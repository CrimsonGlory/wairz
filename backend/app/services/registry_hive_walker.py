"""Phase γ.4 — Windows registry hive walker.

Reads Windows registry hives via :mod:`regipy` (a pure-Python read-only
library binding) and writes canonical ``parsed_tree`` JSONB to
:class:`WindowsRegistryExtract` rows. Detects hive files in a firmware's
extracted tree via filename + ``regf`` magic bytes heuristic, creates
:class:`HardwareFirmwareBlob` rows with ``category="registry_hive"``
for them, and persists per-hive walk results.

The pure walker (:func:`walk_hive_path`) is decoupled from the
orchestrator (:func:`auto_walk_firmware`) so unit tests can drive the
walker against synthetic / mocked hive fixtures without a DB session.

**Auto-walk-on-unpack integration** (Rule #16): the orchestrator calls
:func:`get_detection_roots` to find every detection root (Linux rootfs,
Android scatter directories, multi-archive roots). Hive scanning
happens uniformly across roots so scatter-zip + multi-partition
firmware get walked in one pass without needing per-format hooks.

**Rule #36 no-execute discipline**: regipy parses the hive AS DATA;
nothing in this module invokes ``regedit``, ``.reg`` apply, ``rundll32``,
or any scriptable registry-modification action. Hive paths are surfaced
to the operator via :class:`WindowsRegistryExtract` rows; the walker
NEVER passes a hive path to a process-spawn primitive.

**Rule #5 sync-I/O discipline**: regipy's ``RegistryHive.recurse_subkeys``
is sync I/O (file reads + parsing). The orchestrator wraps every walk
call in :func:`asyncio.get_running_loop().run_in_executor` so a
multi-MB SOFTWARE.hive walk doesn't block the event loop.

**Rule #33 .d in-process dispatch rationale**: registry walks are
in-process (no Docker spawn, no long subprocess), incrementally persist
via per-hive ``WindowsRegistryExtract`` row INSERTs, and "fire and
observe via row-status" is sufficient for restart recovery (the extract
table's ``(blob, hive_path)`` UniqueConstraint dedups re-runs).
``asyncio.create_task`` is the correct dispatch — see γ.6 router for
the captured pattern.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_registry_extract import WindowsRegistryExtract
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_registry_hive_walk_result,
    _stamp_windows_registry_extracts_parsed_tree,
)


logger = logging.getLogger(__name__)


# ── Hive-detection heuristic ─────────────────────────────────────────────────

# Canonical Windows registry hive filenames. NTUSER.DAT and UsrClass.dat
# are user-profile hives; SOFTWARE/SYSTEM/SAM/SECURITY/DEFAULT are the
# C:/Windows/System32/config set; AmCache.hve indexes executed binaries
# (forensic timeline relevance per Persona-E #13); BBI / COMPONENTS /
# DRIVERS / SCHEMA round out the System32/config slot. ELAM stores Early
# Launch Anti-Malware data; BCD is the boot configuration database.
#
# Match is case-insensitive (Windows filesystems are case-preserving but
# case-insensitive); the heuristic compares against the upper-cased
# basename.
_HIVE_FILENAME_PATTERNS: frozenset[str] = frozenset(
    {
        "SOFTWARE",
        "SYSTEM",
        "SAM",
        "SECURITY",
        "DEFAULT",
        "NTUSER.DAT",
        "USRCLASS.DAT",
        "AMCACHE.HVE",
        "BBI",
        "COMPONENTS",
        "DRIVERS",
        "SCHEMA.DAT",
        "ELAM",
        "BCD",
    }
)

# Windows registry hive file format magic — all real hives start with
# the four-byte ``regf`` literal at offset 0. Filename match alone would
# false-positive on coincidental names; magic match alone would
# over-collect (some firmware tooling produces .hve files of unknown
# vintage). Both must agree before the file is processed.
_REGF_MAGIC: bytes = b"regf"

# Hive-type classifier — lookup from upper-cased basename to canonical
# hive_type column value. Falls back to "unknown" for files that pass
# the magic check but aren't on the canonical name list (caller can
# still walk them; just no flavor discriminator).
_HIVE_TYPE_BY_BASENAME: dict[str, str] = {
    "SOFTWARE": "SOFTWARE",
    "SYSTEM": "SYSTEM",
    "SAM": "SAM",
    "SECURITY": "SECURITY",
    "DEFAULT": "DEFAULT",
    "NTUSER.DAT": "NTUSER",
    "USRCLASS.DAT": "UsrClass",
    "AMCACHE.HVE": "AmCache",
    "BBI": "BBI",
    "COMPONENTS": "COMPONENTS",
    "DRIVERS": "DRIVERS",
    "SCHEMA.DAT": "SCHEMA",
    "ELAM": "ELAM",
    "BCD": "BCD",
}


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum subkey-path depth retained in the parsed_tree. A real
# SOFTWARE.hive has paths 8-15 levels deep; capping at 5 keeps the JSONB
# row size manageable while still covering the persistence-relevant
# subkeys (Run / RunOnce / Services / Image File Execution Options all
# sit at depth ≤4 from the root).
_DEFAULT_MAX_DEPTH: int = 5

# Maximum total subkeys retained per hive walk. A real SOFTWARE.hive
# can have 100K+ keys; capping at 50K keeps the row size proportional
# (each subkey averages ~200 bytes JSON-serialised → ~10 MB JSONB).
_DEFAULT_MAX_KEYS: int = 50000

# Maximum bytes retained per value's data. A REG_BINARY blob can be
# arbitrarily large (e.g. cached graphics tables); capping at 8KiB
# protects row size while still preserving value identity for scan
# purposes. Values exceeding the cap are truncated and tagged.
_DEFAULT_MAX_VALUE_BYTES: int = 8192

# Maximum walk wall-clock per hive. A pathological hive could send the
# walker into a regipy parsing loop; capping at 60 s ensures the
# orchestrator can always make progress on the next hive. Currently a
# soft-cap (the per-hive elapsed time is checked between yields).
_DEFAULT_PER_HIVE_TIMEOUT_SECONDS: float = 60.0


# ── Pure helpers (sync, executor-safe) ───────────────────────────────────────


def _hive_type_from_path(path: str) -> str:
    """Return the canonical ``hive_type`` value for a hive at ``path``.

    Lookup is case-insensitive against the basename. Unknown filenames
    that nonetheless carry the regf magic produce ``"unknown"`` — the
    walk still runs; just no flavor discriminator.
    """
    return _HIVE_TYPE_BY_BASENAME.get(os.path.basename(path).upper(), "unknown")


def _is_hive_file(path: str) -> bool:
    """Return ``True`` when ``path`` is a regular file whose basename
    matches a canonical hive name AND whose first 4 bytes are ``regf``.

    Both checks are required: filename match alone false-positives on
    coincidental names; magic match alone over-collects on unknown
    .hve files. Sync I/O — caller is responsible for offloading to a
    thread executor when invoked from an async context (Rule #5).
    Defensive against missing files, permission errors, short reads.
    """
    try:
        if not os.path.isfile(path):
            return False
        basename = os.path.basename(path).upper()
        if basename not in _HIVE_FILENAME_PATTERNS:
            return False
        with open(path, "rb") as fh:
            return fh.read(4) == _REGF_MAGIC
    except OSError:
        return False


def scan_for_hives(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return a list of hive file paths
    (filename + magic both match). Sync I/O — wrap in
    ``run_in_executor`` for async callers.

    Skips symlinks pointing outside the root (the unpacker may have
    legitimate symlinks within the rootfs but escape symlinks are a
    sandbox concern; we read FILES inside the rootfs only).
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                if name.upper() not in _HIVE_FILENAME_PATTERNS:
                    continue
                full = os.path.join(dirpath, name)
                # Sandbox check: never read a file whose realpath
                # escapes the root tree (Rule #1 spirit).
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if _is_hive_file(real_full):
                    hits.append(real_full)
    return hits


def _coerce_value_data(value: Any, max_bytes: int) -> Any:
    """Truncate / hex-encode a value's data so it fits the JSONB row.

    Bytes-shaped values get hex-encoded (so the JSONB column carries a
    JSON-safe string); long string values get truncated with a marker
    suffix; other shapes pass through unchanged.
    """
    if isinstance(value, (bytes, bytearray)):
        if len(value) > max_bytes:
            return bytes(value[:max_bytes]).hex() + "...[truncated]"
        return bytes(value).hex()
    if isinstance(value, str) and len(value) > max_bytes:
        return value[:max_bytes] + "...[truncated]"
    return value


def walk_hive_path(
    hive_path: str,
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_keys: int = _DEFAULT_MAX_KEYS,
    max_value_bytes: int = _DEFAULT_MAX_VALUE_BYTES,
    per_hive_timeout_seconds: float = _DEFAULT_PER_HIVE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Walk a registry hive and return the canonical ``parsed_tree`` dict.

    Pure / sync — caller MUST wrap in ``run_in_executor`` (Rule #5).
    Defensive against every regipy exception type — a malformed hive
    produces a partial parsed_tree with the error captured in the
    ``errors`` list and ``walk_complete=False``, never a raised
    exception. ``schema_version`` is NOT stamped here — caller passes
    the dict through ``_stamp_windows_registry_extracts_parsed_tree``
    before persisting (Rule #35c separation of pure walker from writer).
    """
    # Lazy import — regipy's cold import is non-trivial (~200 ms) and
    # the walker module imports get pulled into mcp_server bootstrap.
    # Function-local import keeps that cost off the bootstrap path.
    from regipy.exceptions import RegipyException
    from regipy.registry import RegistryHive

    parsed_tree: dict[str, Any] = {
        "hive_type": _hive_type_from_path(hive_path),
        "walk_complete": True,
        "depth_limit": max_depth,
        "key_count": 0,
        "value_count": 0,
        "truncated": False,
        "errors": [],
        "subkeys": [],
    }

    try:
        hive = RegistryHive(hive_path)
    except RegipyException as exc:
        parsed_tree["walk_complete"] = False
        parsed_tree["errors"].append(
            f"open: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return parsed_tree
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        # regipy occasionally raises non-Regipy errors on malformed input
        # (struct unpack failures, IndexError on truncated cells). The
        # walker boundary is defensive — capture and return partial.
        parsed_tree["walk_complete"] = False
        parsed_tree["errors"].append(
            f"open: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return parsed_tree

    started = time.monotonic()

    try:
        for entry in hive.recurse_subkeys(as_json=True, fetch_values=True):
            # Per-hive wall-clock cap — protects against pathological
            # hives that send the parser into a long traversal.
            if time.monotonic() - started > per_hive_timeout_seconds:
                parsed_tree["truncated"] = True
                parsed_tree["walk_complete"] = False
                parsed_tree["errors"].append(
                    f"timeout: per-hive cap {per_hive_timeout_seconds}s exceeded"
                )
                break

            # Depth cap — paths are backslash-separated from the hive
            # root (e.g. "\\Microsoft\\Windows\\CurrentVersion\\Run").
            # ``count("\\")`` over-counts the leading backslash by 1, so
            # depth = backslash_count.
            depth = entry.path.count("\\")
            if depth > max_depth:
                parsed_tree["truncated"] = True
                continue

            # Key-count cap — protects row size on hives with 100K+
            # subkeys. Once hit, we stop the walk entirely (don't keep
            # iterating — we'd just discard everything past the cap).
            if parsed_tree["key_count"] >= max_keys:
                parsed_tree["truncated"] = True
                parsed_tree["walk_complete"] = False
                break
            parsed_tree["key_count"] += 1

            values: list[dict[str, Any]] = []
            for v in entry.values or []:
                # ``v`` is a dict from ``attr.asdict(Value)`` per regipy
                # ``recurse_subkeys(as_json=True)`` — fields: name,
                # value, value_type, is_corrupted.
                values.append(
                    {
                        "name": v.get("name") or "(default)",
                        "type": v.get("value_type") or "unknown",
                        "data": _coerce_value_data(v.get("value"), max_value_bytes),
                    }
                )
                parsed_tree["value_count"] += 1

            parsed_tree["subkeys"].append(
                {
                    "path": entry.path,
                    "values": values,
                }
            )
    except RegipyException as exc:
        parsed_tree["walk_complete"] = False
        parsed_tree["errors"].append(
            f"walk: {type(exc).__name__}: {str(exc)[:200]}"
        )
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        parsed_tree["walk_complete"] = False
        parsed_tree["errors"].append(
            f"walk: {type(exc).__name__}: {str(exc)[:200]}"
        )

    return parsed_tree


# ── Async orchestrator (calls into pure helpers via run_in_executor) ─────────


async def _scan_for_hives_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`scan_for_hives` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scan_for_hives, roots)


async def _walk_hive_path_async(hive_path: str) -> dict[str, Any]:
    """Async wrapper around :func:`walk_hive_path` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_hive_path, hive_path)


def _bytes_per_hive(path: str) -> int:
    """Best-effort file size for the HardwareFirmwareBlob row. Returns
    0 on missing/permission errors."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _sha256_hex(path: str) -> str:
    """Compute a sha256 of the hive file. Returns the hex digest, or an
    empty string on read failure (the FK + UniqueConstraint shape uses
    blob_path / hive_path as the dedup key, so an empty sha256 only
    affects the rollup view rather than correctness)."""
    import hashlib

    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


async def _ensure_hardware_firmware_blob(
    db: AsyncSession,
    *,
    firmware_id: uuid.UUID,
    hive_path: str,
    relative_path: str,
) -> HardwareFirmwareBlob:
    """Get-or-create the HardwareFirmwareBlob row for a detected hive.

    Uses (firmware_id, blob_sha256) as the upsert key (matches the
    existing UniqueConstraint on hardware_firmware_blobs). Sets
    category="registry_hive" so the matrix view + driver-graph
    builders can filter on it.
    """
    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(None, _sha256_hex, hive_path)
    file_size = await loop.run_in_executor(None, _bytes_per_hive, hive_path)

    # Look for an existing row keyed by (firmware_id, blob_sha256). If
    # present, update category in case a previous detection pass set it
    # to something else (e.g. "raw_bin"). If absent, create.
    if sha256:
        existing = (
            await db.execute(
                select(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id,
                    HardwareFirmwareBlob.blob_sha256 == sha256,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            # Promote category to registry_hive (don't downgrade if
            # it's already "registry_hive" — idempotent).
            if existing.category != "registry_hive":
                existing.category = "registry_hive"
                existing.format = "regf_hive"
                existing.detection_source = "registry_hive_walker"
            return existing

    blob = HardwareFirmwareBlob(
        firmware_id=firmware_id,
        blob_path=relative_path,
        blob_sha256=sha256 or "",
        file_size=file_size,
        category="registry_hive",
        format="regf_hive",
        detection_source="registry_hive_walker",
        detection_confidence="high",
    )
    db.add(blob)
    await db.flush()
    return blob


async def _ensure_registry_extract(
    db: AsyncSession,
    *,
    blob_id: uuid.UUID,
    hive_path: str,
    parsed_tree: dict[str, Any],
) -> WindowsRegistryExtract:
    """Get-or-create a WindowsRegistryExtract row for ``(blob_id,
    hive_path)``; UPDATE the parsed_tree + summary counts in place."""
    existing = (
        await db.execute(
            select(WindowsRegistryExtract).where(
                WindowsRegistryExtract.blob_id == blob_id,
                WindowsRegistryExtract.hive_path == hive_path,
            )
        )
    ).scalar_one_or_none()

    walk_status = "completed"
    if not parsed_tree.get("walk_complete", False):
        walk_status = "partial" if parsed_tree.get("subkeys") else "failed"
    walk_error = "; ".join(parsed_tree.get("errors") or []) or None

    if existing is not None:
        existing.parsed_tree = _stamp_windows_registry_extracts_parsed_tree(
            dict(parsed_tree)
        )
        existing.hive_type = parsed_tree.get("hive_type", "unknown")
        existing.key_count = int(parsed_tree.get("key_count", 0))
        existing.value_count = int(parsed_tree.get("value_count", 0))
        existing.walk_status = walk_status
        existing.walk_error = walk_error
        return existing

    extract = WindowsRegistryExtract(
        blob_id=blob_id,
        hive_path=hive_path,
        hive_type=parsed_tree.get("hive_type", "unknown"),
        key_count=int(parsed_tree.get("key_count", 0)),
        value_count=int(parsed_tree.get("value_count", 0)),
        walk_status=walk_status,
        walk_error=walk_error,
        parsed_tree=_stamp_windows_registry_extracts_parsed_tree(dict(parsed_tree)),
    )
    db.add(extract)
    await db.flush()
    return extract


async def auto_walk_firmware(firmware_id: uuid.UUID, db: AsyncSession) -> dict[str, Any]:
    """Walk every registry hive in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via ``get_detection_roots`` (Rule #16).
    2. Scan filesystem for hive files (filename + regf magic).
    3. For each hive: get/create HardwareFirmwareBlob (category=
       "registry_hive"), walk the hive (run_in_executor for Rule #5),
       get/create WindowsRegistryExtract row.
    4. Compute aggregate result; caller stamps it onto firmware row.

    Returns the aggregate dict (UNSTAMPED — caller stamps via
    ``_stamp_firmware_registry_hive_walk_result`` before assigning).
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    hive_paths = await _scan_for_hives_async(roots)
    if not hive_paths:
        return _empty_walk_result(time.monotonic() - started)

    # ── Per-hive walk + persist ──
    by_hive_type: dict[str, int] = {}
    by_walk_status: dict[str, int] = {
        "completed": 0,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
    }
    total_keys = 0
    total_values = 0
    errors: list[str] = []

    for hive_path in hive_paths:
        try:
            parsed_tree = await _walk_hive_path_async(hive_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"walk failed for {hive_path}: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            )
            by_walk_status["failed"] += 1
            continue

        # Compute relative path for the blob row (under any detection
        # root). Fall back to absolute if no root prefix matches.
        relative_path = hive_path
        for r in roots:
            try:
                rp = os.path.realpath(r)
                if hive_path.startswith(rp + "/"):
                    relative_path = hive_path[len(rp) + 1 :]
                    break
            except OSError:
                continue

        try:
            blob = await _ensure_hardware_firmware_blob(
                db,
                firmware_id=firmware_id,
                hive_path=hive_path,
                relative_path=relative_path,
            )
            await _ensure_registry_extract(
                db,
                blob_id=blob.id,
                hive_path=relative_path,
                parsed_tree=parsed_tree,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"persist failed for {hive_path}: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            )
            by_walk_status["failed"] += 1
            continue

        hive_type = parsed_tree.get("hive_type", "unknown")
        by_hive_type[hive_type] = by_hive_type.get(hive_type, 0) + 1

        walk_status_for_hive = "completed"
        if not parsed_tree.get("walk_complete", False):
            walk_status_for_hive = (
                "partial" if parsed_tree.get("subkeys") else "failed"
            )
        by_walk_status[walk_status_for_hive] = (
            by_walk_status.get(walk_status_for_hive, 0) + 1
        )
        total_keys += int(parsed_tree.get("key_count", 0))
        total_values += int(parsed_tree.get("value_count", 0))

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "hive_count": len(hive_paths),
        "by_hive_type": by_hive_type,
        "by_walk_status": by_walk_status,
        "total_keys": total_keys,
        "total_values": total_values,
        "errors": errors,
    }


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    """Aggregate shape for "no hives found" or "no detection roots"."""
    return {
        "run_seconds": round(run_seconds, 3),
        "hive_count": 0,
        "by_hive_type": {},
        "by_walk_status": {
            "completed": 0,
            "partial": 0,
            "failed": 0,
            "skipped": 0,
        },
        "total_keys": 0,
        "total_values": 0,
        "errors": [],
    }


async def _run_registry_hive_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner. Owns its own AsyncSession via
    :func:`async_session_factory`; outer guard catches any escape;
    failure persistence on a fresh session because the inner one
    rolled back. Mirrors the β.4 ``_run_authenticode_chain_background``
    shape (Rule #33 reference recipe).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "registry_hive_walk: firmware %s not found", firmware_id
                )
                return

            row.registry_hive_walk_status = "running"
            row.registry_hive_walk_started_at = datetime.utcnow()
            await db.commit()

            try:
                result = await auto_walk_firmware(firmware_id, db)
                row.registry_hive_walk_status = "completed"
                row.registry_hive_walk_finished_at = datetime.utcnow()
                row.registry_hive_walk_result = (
                    _stamp_firmware_registry_hive_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "registry_hive_walk: firmware %s completed in %.2fs (%d hives)",
                    firmware_id,
                    result["run_seconds"],
                    result["hive_count"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.registry_hive_walk_status = "failed"
                        fail_row.registry_hive_walk_finished_at = (
                            datetime.utcnow()
                        )
                        fail_row.registry_hive_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "registry_hive_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception("registry_hive_walk: unrecoverable for %s", firmware_id)


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by
    :func:`unpack._run_hardware_firmware_detection_safe` after detection
    completes. Same shape as the existing
    :func:`_run_hardware_firmware_detection_safe` in unpack.py — owns
    sessions, swallows exceptions, logs.

    Distinct from :func:`_run_registry_hive_walk_background`: the
    background runner (a) transitions the firmware status column
    through queued → running → completed/failed, and (b) is intended
    for explicit operator-triggered walks via the 202+polling
    endpoint (γ.6 hands the trigger). The auto-walk-on-unpack flow
    runs the SAME orchestrator (auto_walk_firmware) but DOES NOT
    transition the status column — it stays ``idle`` until an operator
    explicitly triggers a re-walk via the endpoint, which resets and
    runs again. This matches the existing detect_hardware_firmware
    pattern: detection runs automatically on unpack, but a manual
    re-detect endpoint also exists.
    """
    try:
        async with async_session_factory() as db:
            result = await auto_walk_firmware(firmware_id, db)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                # Stamp the result aggregate so the operator can see
                # the walk happened, but leave status at idle so a
                # manual re-trigger via the endpoint still works
                # without 409 conflict (status='running' would block).
                row.registry_hive_walk_result = (
                    _stamp_firmware_registry_hive_walk_result(result)
                )
                await db.commit()
            logger.info(
                "registry_hive_walk auto: firmware %s walked %d hives in %.2fs",
                firmware_id,
                result["hive_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "registry_hive_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )
