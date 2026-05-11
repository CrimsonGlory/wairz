"""Kernel CVE subsystem index powered by kernel.org vulns.git.

Clones or updates https://git.kernel.org/pub/scm/linux/security/vulns.git
into a persistent volume, walks cve/published/YYYY/*.json, and indexes
``programFiles`` -> subsystem -> list of ``{cve_id, min_version,
max_version_excl, severity, description}`` into Redis.

The matcher (:mod:`cve_matcher`, Tier 5) reads from Redis; if the index
is not populated, it returns an empty list gracefully.  The arq worker
runs :func:`sync` on a daily cron so the first CVE match never waits on
a cold-cache 100 MB clone.

Design contract: *fail-soft at every step*.  Missing git, no network,
Redis down, malformed JSON -> log and return empty / a status dict.  The
hardware-firmware pipeline must never fail because of a Tier-5 hiccup.

Keys written to Redis:

* ``kernel_vulns:subsystem:<path>`` -> JSON list of CVE entry dicts.
  ``<path>`` is a subsystem directory *with* trailing slash
  (e.g. ``net/bluetooth/``, ``drivers/gpu/arm/``).
* ``kernel_vulns:last_sync`` -> ISO-8601 timestamp of the last successful
  sync.

Subsystem keys carry a 24-hour TTL so stale data expires gracefully if
sync fails for multiple consecutive days.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from packaging.version import InvalidVersion, Version

from app.config import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUBSYSTEM_KEY_PREFIX = "kernel_vulns:subsystem:"
_LAST_SYNC_KEY = "kernel_vulns:last_sync"
_SUBSYSTEM_TTL_SECONDS = 24 * 60 * 60  # 24h

# Redis pipeline chunk size (avoid pushing 50k SET ops in one round-trip).
_PIPELINE_CHUNK = 500


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

async def _redis_client() -> aioredis.Redis | None:
    """Create an async Redis client.  Returns ``None`` on connection error."""
    settings = get_settings()
    try:
        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
        return client
    except Exception as exc:  # noqa: BLE001
        logger.warning("kernel_vulns_index: redis unavailable (%s)", exc)
        return None


# ---------------------------------------------------------------------------
# CVE JSON walker
# ---------------------------------------------------------------------------

def _subsystem_from_programfile(program_file: str) -> str | None:
    """Return the parent directory (with trailing ``/``) of a source-file path.

    ``net/bluetooth/smp.c`` -> ``net/bluetooth/``
    ``drivers/gpu/arm/midgard/mali_kbase.c`` -> ``drivers/gpu/arm/midgard/``
    Returns ``None`` for top-level files (no slash) or empty input.
    """
    if not program_file or not isinstance(program_file, str):
        return None
    # Normalise Windows-style or redundant separators.
    cleaned = program_file.replace("\\", "/").strip().lstrip("./")
    if "/" not in cleaned:
        return None
    parent = cleaned.rsplit("/", 1)[0]
    return parent + "/"


def _extract_entries(cve_json: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Project a single CVE JSON file into a list of ``(subsystem, entry)`` pairs.

    Linux kernel CNA schema (simplified)::

        {
          "cveMetadata": {"cveId": "CVE-YYYY-NNNNN"},
          "containers": {
            "cna": {
              "affected": [
                {
                  "programFiles": ["net/bluetooth/smp.c", ...],
                  "versions": [
                    {"version": "6.5", "lessThan": "6.6.70",
                     "status": "affected", "versionType": "semver"}
                  ]
                }
              ],
              "descriptions": [{"lang": "en", "value": "..."}],
              "metrics": [...]
            }
          }
        }
    """
    metadata = cve_json.get("cveMetadata") or {}
    # Both ``cveID`` (real kernel.org CNA output) and the spec-standard
    # ``cveId`` appear in the wild; accept either.
    cve_id = metadata.get("cveID") or metadata.get("cveId") or metadata.get("cve_id")
    if not cve_id:
        return []

    containers = cve_json.get("containers") or {}
    cna = containers.get("cna") or {}

    # Description (first English one wins).
    description = ""
    for desc in cna.get("descriptions") or []:
        if (desc.get("lang") or "").lower().startswith("en"):
            description = (desc.get("value") or "").strip()
            break

    # Severity from CVSS metrics, best-effort.
    severity = "unknown"
    for metric in cna.get("metrics") or []:
        for vx_key in ("cvssV3_1", "cvssV3_0", "cvssV3", "cvssV4_0"):
            v = metric.get(vx_key)
            if isinstance(v, dict) and v.get("baseSeverity"):
                severity = str(v["baseSeverity"]).lower()
                break
        if severity != "unknown":
            break

    results: list[tuple[str, dict[str, Any]]] = []
    for affected in cna.get("affected") or []:
        program_files = affected.get("programFiles") or []
        if not program_files:
            continue

        # Derive (min_version, max_version_excl) ranges from the ``versions``
        # blocks.  The kernel CNA uses several idioms that all map onto the
        # same conceptual range:
        #
        #   status="affected",   version="6.11" (no lessThan) -> exactly 6.11
        #   status="affected",   version="6.5", lessThan="6.6.70" -> [6.5, 6.6.70)
        #   status="unaffected", version="6.6.133", lessThanOrEqual="6.6.*"
        #       -> this range is *fixed*; the IMPLIED affected range is
        #          [start_of_series, 6.6.133) — i.e. the ``version`` field of
        #          an unaffected block is an exclusive upper bound on the
        #          affected versions within that series.
        #
        # We collect one open interval per version block.  ``None`` on either
        # side means unbounded in that direction.  All inputs are semver
        # triples (or dotted semver); git-SHA / original_commit_for_fix
        # entries are ignored because we can't compare them numerically.
        version_blocks: list[tuple[str | None, str | None]] = []
        for v in affected.get("versions") or []:
            status = (v.get("status") or "").lower()
            vtype = (v.get("versionType") or "").lower()
            if vtype and vtype not in ("semver", "custom", ""):
                continue
            raw_version = v.get("version")
            version_str = str(raw_version).strip() if raw_version is not None else ""
            less_than = v.get("lessThan") or v.get("lessThanOrEqual")

            if status == "affected":
                # [version, lessThan) — if lessThan missing, treat as the
                # exact point.  ``0`` means from the very beginning.
                if version_str in ("0", ""):
                    min_v: str | None = None
                else:
                    min_v = version_str
                max_v: str | None = less_than or (
                    _next_patch(version_str) if version_str else None
                )
                version_blocks.append((min_v, max_v))
            elif status == "unaffected":
                # Versions STARTING at ``version`` (and the rest of the series)
                # are fixed.  Implied affected range is [None, version).
                if version_str and version_str != "0":
                    version_blocks.append((None, version_str))
                # "0..lessThan unaffected" is noise (no kernel <0 exists);
                # skip.  No other cases contribute.
            # Any other status is skipped.

        # If nothing survived filtering, record an open-ended entry so the
        # matcher can still surface CVEs with no structured version data.
        if not version_blocks:
            version_blocks = [(None, None)]

        for program_file in program_files:
            subsystem = _subsystem_from_programfile(program_file)
            if not subsystem:
                continue
            for min_version, max_version_excl in version_blocks:
                entry = {
                    "cve_id": cve_id,
                    "min_version": min_version,
                    "max_version_excl": max_version_excl,
                    "severity": severity,
                    "description": description,
                }
                results.append((subsystem, entry))
    return results


def _next_patch(version_str: str) -> str | None:
    """Return the version immediately after ``version_str`` for an exclusive bound.

    ``"6.11"``   -> ``"6.11.1"``  (bump patch)
    ``"6.11.5"`` -> ``"6.11.6"``
    Invalid input -> ``None``
    """
    try:
        parts = [int(p) for p in version_str.split(".") if p.isdigit()]
    except ValueError:
        return None
    if not parts:
        return None
    if len(parts) == 1:
        parts.extend([0, 1])
    elif len(parts) == 2:
        parts.append(1)
    else:
        parts[-1] += 1
    return ".".join(str(p) for p in parts)


# ---------------------------------------------------------------------------
# Git clone / pull
# ---------------------------------------------------------------------------

async def _git_available() -> bool:
    return shutil.which("git") is not None


async def _run_git(args: list[str], *, cwd: str | None = None, timeout: int) -> tuple[int, str, str]:  # noqa: ASYNC109 — caller-supplied timeout per Rule #29 contract (forwarded to asyncio.wait_for)
    """Run ``git`` with ``asyncio.create_subprocess_exec`` — never ``shell=True``.

    The ``timeout`` kwarg is a cap on the subprocess call, not an async
    cancellation deadline — keep the explicit parameter for readability.
    """
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"git {' '.join(args)} timed out after {timeout}s"
    return proc.returncode or 0, stdout_b.decode("utf-8", "replace"), stderr_b.decode("utf-8", "replace")


async def _clone_or_pull(cache_dir: str, git_url: str, timeout: int) -> tuple[bool, str]:  # noqa: ASYNC109 — caller-supplied timeout per Rule #29 contract (threaded to _run_git)
    """Clone into ``cache_dir`` or ``git pull`` if the repo already exists."""
    os.makedirs(os.path.dirname(cache_dir) or ".", exist_ok=True)
    git_dir = Path(cache_dir) / ".git"
    if git_dir.is_dir():
        # Existing clone -> pull.
        rc, _out, err = await _run_git(
            ["pull", "--ff-only", "--quiet"],
            cwd=cache_dir,
            timeout=timeout,
        )
        if rc != 0:
            return False, f"git pull failed: {err.strip()}"
        return True, "pulled"
    # Fresh clone (shallow, blobless — keeps the clone ~10x smaller).
    rc, _out, err = await _run_git(
        [
            "clone",
            "--depth=1",
            "--filter=blob:none",
            "--quiet",
            git_url,
            cache_dir,
        ],
        timeout=timeout,
    )
    if rc != 0:
        return False, f"git clone failed: {err.strip()}"
    return True, "cloned"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def sync() -> dict[str, Any]:
    """Sync ``vulns.git`` and rebuild the Redis subsystem index.

    Return a dict describing the outcome::

        {"status": "ok", "cve_count": 1234, "subsystem_count": 456,
         "duration_seconds": 12.3}

    Fail-soft return codes:

    * ``{"status": "no_git"}`` — git binary missing.
    * ``{"status": "clone_failed", "error": "..."}`` — network / repo issue.
    * ``{"status": "no_redis"}`` — Redis unreachable.
    * ``{"status": "error", "error": "..."}`` — anything else unexpected.
    """
    start = time.monotonic()
    settings = get_settings()

    if not await _git_available():
        logger.warning("kernel_vulns_index.sync: git binary not available")
        return {"status": "no_git"}

    cache_dir = settings.kernel_vulns_cache_dir
    timeout = settings.kernel_vulns_sync_timeout
    git_url = settings.kernel_vulns_git_url

    ok, msg = await _clone_or_pull(cache_dir, git_url, timeout)
    if not ok:
        logger.warning("kernel_vulns_index.sync: %s", msg)
        return {"status": "clone_failed", "error": msg}
    logger.info("kernel_vulns_index.sync: %s into %s", msg, cache_dir)

    client = await _redis_client()
    if client is None:
        return {"status": "no_redis"}

    try:
        published_root = Path(cache_dir) / "cve" / "published"
        if not published_root.is_dir():
            return {
                "status": "error",
                "error": f"no cve/published/ under {cache_dir}",
            }

        subsystem_map: dict[str, list[dict[str, Any]]] = {}
        cve_count = 0

        # Walk every YYYY/*.json.  The filesystem walk is sync I/O so we run it
        # on the default executor to keep the event loop unblocked.
        loop = asyncio.get_running_loop()

        def _walk() -> list[Path]:
            out: list[Path] = []
            for year_dir in sorted(published_root.iterdir()):
                if not year_dir.is_dir():
                    continue
                for json_file in year_dir.glob("*.json"):
                    out.append(json_file)
            return out

        files = await loop.run_in_executor(None, _walk)
        logger.info("kernel_vulns_index.sync: walking %d CVE files", len(files))

        def _read_and_extract(path: Path) -> list[tuple[str, dict[str, Any]]]:
            try:
                with open(path, "rb") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug("skipping malformed %s: %s", path, exc)
                return []
            return _extract_entries(data)

        for json_file in files:
            pairs = await loop.run_in_executor(None, _read_and_extract, json_file)
            if pairs:
                cve_count += 1
            for subsystem, entry in pairs:
                subsystem_map.setdefault(subsystem, []).append(entry)

        # Write to Redis in chunked pipelines.  Each key is the JSON-encoded
        # list of entries for that subsystem; 24h TTL.
        keys_written = 0
        pipe = client.pipeline(transaction=False)
        for i, (subsystem, entries) in enumerate(subsystem_map.items(), start=1):
            key = _SUBSYSTEM_KEY_PREFIX + subsystem
            pipe.set(key, json.dumps(entries), ex=_SUBSYSTEM_TTL_SECONDS)
            keys_written += 1
            if i % _PIPELINE_CHUNK == 0:
                await pipe.execute()
                pipe = client.pipeline(transaction=False)
        # Flush any remainder, plus the last_sync marker.
        pipe.set(
            _LAST_SYNC_KEY,
            datetime.now(UTC).isoformat(),
        )
        await pipe.execute()

        duration = time.monotonic() - start
        logger.info(
            "kernel_vulns_index.sync: wrote %d subsystem keys from %d CVEs in %.1fs",
            keys_written,
            cve_count,
            duration,
        )
        return {
            "status": "ok",
            "cve_count": cve_count,
            "subsystem_count": keys_written,
            "duration_seconds": round(duration, 2),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("kernel_vulns_index.sync: unexpected error: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001, S110 — cleanup path; connection may already be closed
            pass


async def _filter_by_version(
    entries: list[dict[str, Any]],
    kernel_version: str,
) -> list[dict[str, Any]]:
    """Filter a subsystem's CVE entries against a concrete kernel version."""
    try:
        target = Version(kernel_version)
    except InvalidVersion:
        logger.debug("kernel_vulns_index.lookup: invalid kernel version %r", kernel_version)
        return []

    out: list[dict[str, Any]] = []
    for entry in entries:
        min_v_raw = entry.get("min_version")
        max_v_raw = entry.get("max_version_excl")

        if min_v_raw is not None:
            try:
                min_v = Version(str(min_v_raw))
            except InvalidVersion:
                min_v = None
            if min_v is not None and target < min_v:
                continue

        if max_v_raw is not None:
            try:
                max_v = Version(str(max_v_raw))
            except InvalidVersion:
                max_v = None
            if max_v is not None and target >= max_v:
                continue

        out.append(entry)
    return out


async def lookup(subsystem_path: str, kernel_version: str) -> list[dict[str, Any]]:
    """Return CVEs affecting ``subsystem_path`` that apply to ``kernel_version``.

    ``subsystem_path`` must be the canonical parent directory with a trailing
    slash (e.g. ``net/bluetooth/``).  ``kernel_version`` must be a semver
    triple like ``6.6.102``.  Returns ``[]`` on any error — callers treat this
    as "no Tier-5 hits", never as "sky is falling".
    """
    if not subsystem_path or not kernel_version:
        return []
    client = await _redis_client()
    if client is None:
        return []
    try:
        raw = await client.get(_SUBSYSTEM_KEY_PREFIX + subsystem_path)
        if not raw:
            return []
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(
                "kernel_vulns_index.lookup: corrupt JSON for subsystem %s",
                subsystem_path,
            )
            return []
        if not isinstance(entries, list):
            return []
        return await _filter_by_version(entries, kernel_version)
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001, S110 — cleanup path; connection may already be closed
            pass


async def last_sync() -> datetime | None:
    """Return the ISO-8601 timestamp of the last successful sync, or ``None``."""
    client = await _redis_client()
    if client is None:
        return None
    try:
        raw = await client.get(_LAST_SYNC_KEY)
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001, S110 — cleanup path; connection may already be closed
            pass


async def is_populated() -> bool:
    """``True`` iff at least one subsystem key exists in Redis."""
    client = await _redis_client()
    if client is None:
        return False
    try:
        # SCAN with a MATCH pattern returns early on the first key; cheaper
        # than KEYS on a populated index.
        async for _key in client.scan_iter(
            match=_SUBSYSTEM_KEY_PREFIX + "*", count=1
        ):
            return True
        return False
    except Exception as exc:  # noqa: BLE001
        logger.debug("kernel_vulns_index.is_populated: %s", exc)
        return False
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001, S110 — cleanup path; connection may already be closed
            pass
