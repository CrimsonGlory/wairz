"""C2 generic module/driver REACHABILITY-EVIDENCE collector.

This walker enumerates, per firmware, the THREE module sets that the
cve-assessment-framework L4 kill-chain classifier needs to discriminate an
immutable-build-state driver from a mutable-not-loaded one:

  * **LOADED** — the lsmod-equivalent runtime set. A STATIC firmware image
    carries NO loaded set (``lsmod`` is a live-device query); the walker
    surfaces ``loaded: null`` so the framework does NOT mistake "no runtime
    data" for "nothing loaded".
  * **AVAILABLE** — every ``*.ko`` / ``.ko.gz`` / ``.ko.xz`` / ``.ko.zst``
    under ``/lib/modules/<ver>/`` (and Android ``vendor_dlkm``) on disk.
    Per-``.ko`` the existing :mod:`kmod` parser supplies vermagic + appended-
    signature + SHA. These are the modular-AVAILABLE drivers — present but
    (for a static image) not provably loaded.
  * **BUILTIN** — the depmod ``modules.builtin`` set (drivers compiled
    ``=y`` into vmlinux) PLUS the ``=y`` driver symbols read from C1's
    back-filled ``metadata.kernel_config``. A built-in driver IS in the
    running kernel and cannot be unloaded — the immutable axis.

The **3-way diff** (loaded vs available vs builtin) is the C2 output. Its
load-bearing special case is the **static-builtin posture** (R49-A §C2 / the
phone case): when there are 0 ``.ko`` on disk AND drivers are ``=y``, the
BUILTIN set IS the reachability axis — there is no module diff to compute
because nothing is modular. C2 emits ``static_builtin_posture: true`` +
``kernel_posture: "static_builtin"`` so the framework's
``get_loadable_modules()`` knows to read ``builtin_modules.json`` rather than
expecting a (non-existent) loaded-vs-available delta. This is what lets the
classifier route a statically-built FullMAC WiFi driver (bcmdhd present,
mac80211 absent-from-builtin) to ``not_reachable`` — the named KRACK /
FragAttacks compound-immutable correction.

Cross-platform: Linux rootfs (``/lib/modules``) + Android (monolithic
boot.img kernel with 0 ``.ko`` → static_builtin; ``vendor_dlkm`` ``.ko`` set
→ modular). RTOS / bare-metal → ``kernel_posture: "not_applicable"`` (no
loadable-module concept) — guilty-safe no-op.

Three functions per CLAUDE.md Rule #39 (inner/outer/safe triplet):

  - :func:`_do_module_reachability_run` — INNER pure-logic orchestrator.
    Caller owns the session + transaction. Resolves detection roots via
    ``get_detection_roots`` (Rule #16). Walks the AVAILABLE / BUILTIN /
    configured-to-load sets, reads C1's kernel_config from the firmware's
    blobs, computes the static-builtin posture. Returns the result aggregate
    UNSTAMPED (caller stamps via
    ``_stamp_firmware_module_reachability_walk_result``). Clears stale
    ``module_reachability_walk_result`` at entry.

  - :func:`run_module_reachability_walk_background` — OUTER Rule #33 .a state
    machine. Owns its own ``async_session_factory()``. Cycles
    ``queued → running → completed | failed``. Failure persistence on a FRESH
    session (the inner session rolled back).

  - :func:`auto_module_reachability_walk_firmware_safe` — SAFE
    unpack-post-detection hook. Owns own session. Stamps the result so
    operators see the last-known result. Does NOT mutate
    ``module_reachability_walk_status`` (leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_module_reachability_walk`` MCP
    tool works without a 409 conflict).

**Rule #36 + Rule #45 PARSE-ONLY contract.** The walker reads ``.ko``
modinfo (via :class:`KmodParser`, which reads the ELF ``.modinfo`` section as
DATA) and the depmod text files (``modules.builtin`` / ``modules.dep``) AS
DATA. It NEVER passes any module to a spawn primitive
(``insmod`` / ``modprobe`` / ``subprocess`` / ``os.system`` / ``exec`` /
``runpy`` / etc.) and NEVER decrypts anything. Test gate
``test_module_reachability_walker.py::test_walker_no_execute_no_decrypt``
enforces via tokenize-walk; Rule #46 paired META-CANARY confirms the gate
fires.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import logging
import os
import re
import traceback
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.firmware_paths import get_detection_roots
from app.services.hardware_firmware.parsers.kmod import KmodParser
from app.services.jsonb_normalizers import (
    _normalize_hardware_firmware_blobs_metadata,
    _stamp_firmware_module_reachability_walk_result,
)

logger = logging.getLogger(__name__)


# ── Bounds (Rule #5 + the C1 Wave-2 attack-D precedent). ────────────────────
# Per-walk hard cap on the number of .ko files parsed — a pathological
# firmware with 10K+ modules must not blow the wall-clock budget; the
# remaining count is surfaced in ``errors``.
_MAX_MODULES_PER_WALK = 4000
# Per-walk hard cap on candidate files scanned (the os.walk envelope) so a
# huge tree doesn't stall even when few are .ko.
_MAX_CANDIDATES_PER_WALK = 200_000
# A .ko larger than this is not hashed in full (kept bounded) — kmod reads
# only the ELF .modinfo section + the 256-byte signature tail, so the full
# read here is purely for the content SHA used by the Rule #44 cross-firmware
# supply-chain query. 64 MB comfortably holds any real .ko.
_MAX_KO_BYTES = 64 * 1024 * 1024
# modules.builtin / modules.dep text files are small; cap the read defensively.
_MAX_DEPMOD_TEXT_BYTES = 8 * 1024 * 1024
# A configured-to-load source file (init.rc / modules-load.d) is small.
_MAX_CONFIG_TEXT_BYTES = 4 * 1024 * 1024
# A real .config from C1 has hundreds of =y driver symbols; surface a bounded
# sample so the JSONB stays under the 30 KB MCP truncation ceiling.
_MAX_BUILTIN_Y_SAMPLE = 2000

# .ko file suffixes (the AVAILABLE set), longest-first so ``.ko.gz`` wins
# over a bare ``.ko`` substring check.
_KO_SUFFIXES = (".ko.zst", ".ko.xz", ".ko.gz", ".ko.lz4", ".ko")

# init*.rc ``insmod /path/to/foo.ko`` stanza (Android configured-to-load).
_INSMOD_RE = re.compile(
    r"\binsmod\s+(\S+\.ko(?:\.\w+)?)", re.IGNORECASE
)


def _module_name_from_path(path: str) -> str:
    """Strip directory + every .ko* suffix → the canonical module name.

    ``kernel/fs/ext4/ext4.ko`` → ``ext4``; ``bcmdhd.ko.xz`` → ``bcmdhd``.
    The depmod files + the on-disk .ko share this naming, so the same
    normaliser keys both the BUILTIN and AVAILABLE sets.
    """
    base = os.path.basename(path)
    for suf in _KO_SUFFIXES:
        if base.endswith(suf):
            return base[: -len(suf)]
    # Defensive — a path with no .ko suffix (shouldn't reach here): drop the
    # single trailing extension.
    return os.path.splitext(base)[0]


# ── Sync filesystem helpers (Rule #5 — wrapped in run_in_executor). ─────────


def _iter_module_files_sync(
    root_path: str, remaining_candidates: int, remaining_modules: int
) -> tuple[list[tuple[str, int]], list[str], int, int]:
    """Walk one detection root for the module artefacts (sync, bounded).

    Returns ``(ko_files, depmod_builtin_paths, candidates_scanned,
    modules_found)`` where ``ko_files`` is ``[(path, size), ...]`` of every
    ``.ko*`` (capped at ``remaining_modules``) and ``depmod_builtin_paths``
    is every ``modules.builtin`` file found. Symlinks are skipped (a .ko
    symlink would double-count the same module).
    """
    ko_files: list[tuple[str, int]] = []
    builtin_paths: list[str] = []
    candidates_scanned = 0
    modules_found = 0
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            if candidates_scanned >= remaining_candidates:
                return ko_files, builtin_paths, candidates_scanned, modules_found
            candidates_scanned += 1
            lower = filename.lower()
            if lower == "modules.builtin":
                builtin_paths.append(os.path.join(dirpath, filename))
                continue
            if not any(lower.endswith(suf) for suf in _KO_SUFFIXES):
                continue
            if modules_found >= remaining_modules:
                # Don't break the os.walk — keep scanning for builtin files,
                # but stop collecting .ko once the per-walk module cap is hit.
                continue
            full = os.path.join(dirpath, filename)
            try:
                if os.path.islink(full):
                    continue
                size = os.path.getsize(full)
            except OSError:
                continue
            ko_files.append((full, size))
            modules_found += 1
    return ko_files, builtin_paths, candidates_scanned, modules_found


def _read_text_file_sync(path: str, cap: int) -> str | None:
    """Read up to ``cap`` bytes of a text file (sync), decode best-effort."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _sha256_file_sync(path: str, cap: int) -> str | None:
    """Compute the SHA-256 of up to ``cap`` bytes of a file (sync, bounded)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            read = 0
            while read < cap:
                chunk = fh.read(min(1024 * 1024, cap - read))
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _parse_modules_builtin_sync(text: str) -> list[str]:
    """Parse a ``modules.builtin`` text body → canonical module names.

    Each line is a kernel-relative module path
    (``kernel/fs/ext4/ext4.ko``). PURE — no I/O.
    """
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        names.append(_module_name_from_path(line))
    return names


def _find_configured_to_load_sync(root_path: str) -> list[str]:
    """Find static configured-to-load module names under one detection root.

    Sources (PARSE-ONLY, read as DATA):
      * ``/etc/modules`` — one bare module name per line.
      * ``/etc/modules-load.d/*.conf`` — one bare module name per line.
      * Android ``init*.rc`` — ``insmod /path/to/foo.ko`` stanzas.

    Returns the de-duplicated module-name list. Bounded — only the well-known
    relative locations are probed (not a full-tree grep).
    """
    found: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            found.append(name)

    # /etc/modules (bare names, '#' comments).
    etc_modules = os.path.join(root_path, "etc", "modules")
    if os.path.isfile(etc_modules):
        text = _read_text_file_sync(etc_modules, _MAX_CONFIG_TEXT_BYTES)
        if text:
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    _add(line.split()[0])

    # /etc/modules-load.d/*.conf
    modules_load_d = os.path.join(root_path, "etc", "modules-load.d")
    if os.path.isdir(modules_load_d):
        try:
            entries = sorted(os.listdir(modules_load_d))
        except OSError:
            entries = []
        for entry in entries:
            if not entry.endswith(".conf"):
                continue
            text = _read_text_file_sync(
                os.path.join(modules_load_d, entry), _MAX_CONFIG_TEXT_BYTES
            )
            if not text:
                continue
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    _add(line.split()[0])

    # Android init*.rc insmod stanzas (top-level only — bounded).
    try:
        top_entries = sorted(os.listdir(root_path))
    except OSError:
        top_entries = []
    for entry in top_entries:
        lower = entry.lower()
        if not (lower.startswith("init") and lower.endswith(".rc")):
            continue
        full = os.path.join(root_path, entry)
        if not os.path.isfile(full):
            continue
        text = _read_text_file_sync(full, _MAX_CONFIG_TEXT_BYTES)
        if not text:
            continue
        for m in _INSMOD_RE.finditer(text):
            _add(_module_name_from_path(m.group(1)))

    return found


# ── Pure-logic posture classifier. ─────────────────────────────────────────


def _classify_posture(
    available_count: int, builtin_count: int, builtin_y_count: int
) -> tuple[str, bool]:
    """Derive ``(kernel_posture, static_builtin_posture)`` from the set sizes.

    The static-builtin posture (R49-A §C2, the phone case) is the key cross-
    platform signal: 0 ``.ko`` on disk AND at least one built-in driver
    (from ``modules.builtin`` OR C1's ``=y`` config) means the BUILTIN set IS
    the reachability axis — there is no modular diff to compute.

      * 0 available + (builtin OR =y) → ``static_builtin`` / True.
      * 0 available + 0 builtin + 0 =y → ``not_applicable`` / False
        (no loadable-module concept; RTOS / bare-metal / non-Linux blob —
        guilty-safe no-op).
      * >0 available + 0 builtin → ``modular`` / False.
      * >0 available + >0 builtin → ``mixed`` / False.
    """
    has_builtin = builtin_count > 0 or builtin_y_count > 0
    if available_count == 0:
        if has_builtin:
            return "static_builtin", True
        return "not_applicable", False
    if builtin_count > 0:
        return "mixed", False
    return "modular", False


def _builtin_y_from_config(config_map: dict[str, str]) -> list[str]:
    """Extract the ``CONFIG_*=y`` driver symbols from a C1 kernel_config map.

    Every symbol set to ``y`` is a candidate built-in driver. PURE — no I/O.
    Bounded sample so the JSONB stays small.
    """
    out = [k for k, v in config_map.items() if v == "y"]
    out.sort()
    return out[:_MAX_BUILTIN_Y_SAMPLE]


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_module_reachability_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER pure-logic orchestrator.

    Caller owns the session + transaction. Resolves detection roots
    (Rule #16). Walks the AVAILABLE ``.ko`` set, parses ``modules.builtin``
    (BUILTIN set), finds the configured-to-load set, reads C1's
    ``metadata.kernel_config`` from the firmware's blobs for the
    ``builtin_y_from_config`` axis, and computes the static-builtin posture.
    Returns the result aggregate UNSTAMPED. Clears stale
    ``module_reachability_walk_result`` at entry.
    """
    walked_at = dt.datetime.now(dt.UTC).isoformat()

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_aggregate(walked_at, [f"firmware {firmware_id} not found"])

    # Clear stale JSONB at entry (mirrors C1 + the ICS δ-mitigation).
    firmware.module_reachability_walk_result = None

    detection_roots = await get_detection_roots(firmware, db=db)
    if not detection_roots:
        return _empty_aggregate(
            walked_at,
            ["no detection_roots for firmware (extraction may have failed)"],
        )

    loop = asyncio.get_running_loop()
    errors: list[str] = []

    # ── AVAILABLE set + BUILTIN (modules.builtin) — per detection root. ────
    kmod_parser = KmodParser()
    available: list[dict] = []
    available_seen: set[str] = set()  # dedup on (name, sha256)
    builtin_set: set[str] = set()
    configured_to_load: set[str] = set()
    candidates_total = 0
    modules_total = 0
    roots_with_ko = 0

    for root_path in detection_roots:
        remaining_cands = _MAX_CANDIDATES_PER_WALK - candidates_total
        remaining_mods = _MAX_MODULES_PER_WALK - modules_total
        if remaining_cands <= 0:
            errors.append(
                f"reached _MAX_CANDIDATES_PER_WALK={_MAX_CANDIDATES_PER_WALK}; "
                f"later roots skipped"
            )
            break
        (
            ko_files,
            builtin_paths,
            scanned,
            found,
        ) = await loop.run_in_executor(
            None,
            _iter_module_files_sync,
            root_path,
            remaining_cands,
            max(remaining_mods, 0),
        )
        candidates_total += scanned
        if ko_files:
            roots_with_ko += 1

        # Parse each .ko via the existing kmod parser (PARSE-ONLY: reads the
        # ELF .modinfo section as DATA). Compute the content SHA for the
        # Rule #44 cross-firmware supply-chain query.
        for ko_path, ko_size in ko_files:
            modules_total += 1
            name = _module_name_from_path(ko_path)
            sha256 = await loop.run_in_executor(
                None, _sha256_file_sync, ko_path, _MAX_KO_BYTES
            )
            try:
                head = await loop.run_in_executor(
                    None, _read_head_sync, ko_path
                )
                parsed = await loop.run_in_executor(
                    None, kmod_parser.parse, ko_path, head or b"", ko_size
                )
            except Exception as exc:  # noqa: BLE001 — per-module boundary
                errors.append(f"kmod parse failed for {ko_path}: {exc}")
                parsed = None

            dedup_key = f"{name}|{sha256}"
            if dedup_key in available_seen:
                continue
            available_seen.add(dedup_key)

            vermagic = None
            signed = "unknown"
            if parsed is not None:
                vermagic = (parsed.metadata or {}).get("vermagic")
                signed = parsed.signed or "unknown"
            available.append(
                {
                    "name": name,
                    "sha256": sha256,
                    "vermagic": vermagic,
                    "signed": signed == "signed",
                    "path": ko_path,
                }
            )

        if modules_total >= _MAX_MODULES_PER_WALK and remaining_mods <= 0:
            errors.append(
                f"reached _MAX_MODULES_PER_WALK={_MAX_MODULES_PER_WALK}; "
                f"some .ko not parsed (available_count is a lower bound)"
            )

        # modules.builtin → BUILTIN set.
        for bpath in builtin_paths:
            text = await loop.run_in_executor(
                None, _read_text_file_sync, bpath, _MAX_DEPMOD_TEXT_BYTES
            )
            if text:
                for n in _parse_modules_builtin_sync(text):
                    builtin_set.add(n)

        # Configured-to-load (static proxy for the live loaded set).
        for n in await loop.run_in_executor(
            None, _find_configured_to_load_sync, root_path
        ):
            configured_to_load.add(n)

    # ── BUILTIN (=y) from C1's back-filled kernel_config. ──────────────────
    builtin_y: list[str] = []
    blob_rows = (
        await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
    ).scalars().all()
    merged_config: dict[str, str] = {}
    for blob in blob_rows:
        meta = _normalize_hardware_firmware_blobs_metadata(blob.metadata_)
        cfg = meta.get("kernel_config")
        if isinstance(cfg, dict):
            merged_config.update(cfg)
    if merged_config:
        builtin_y = _builtin_y_from_config(merged_config)

    available.sort(key=lambda m: (m["name"], m.get("sha256") or ""))
    builtin_sorted = sorted(builtin_set)
    configured_sorted = sorted(configured_to_load)

    kernel_posture, static_builtin_posture = _classify_posture(
        len(available), len(builtin_sorted), len(builtin_y)
    )

    return {
        "walked_at": walked_at,
        "kernel_posture": kernel_posture,
        "static_builtin_posture": static_builtin_posture,
        # LOADED is a LIVE-only annotation — a static image has none. null
        # (not []) so the framework distinguishes "no runtime data" from
        # "nothing loaded" (R51.1 C2 hop-1 + R49-A §C2).
        "loaded": None,
        "available": available,
        "available_count": len(available),
        "builtin": builtin_sorted,
        "builtin_count": len(builtin_sorted),
        "builtin_y_from_config": builtin_y,
        "builtin_y_count": len(builtin_y),
        "configured_to_load": configured_sorted,
        "modules_kos_root_count": roots_with_ko,
        "candidates_scanned": candidates_total,
        "errors": errors,
    }


def _read_head_sync(path: str) -> bytes | None:
    """Read the first 64 bytes of a file (sync) — the kmod parser's ``magic``
    arg. kmod reopens the path itself for the ELF parse; this head is only
    the contract's ``magic`` parameter."""
    try:
        with open(path, "rb") as fh:
            return fh.read(64)
    except OSError:
        return None


def _empty_aggregate(walked_at: str, errors: list[str]) -> dict:
    """Stable empty-result shape (firmware missing / no detection roots)."""
    return {
        "walked_at": walked_at,
        "kernel_posture": "not_applicable",
        "static_builtin_posture": False,
        "loaded": None,
        "available": [],
        "available_count": 0,
        "builtin": [],
        "builtin_count": 0,
        "builtin_y_from_config": [],
        "builtin_y_count": 0,
        "configured_to_load": [],
        "modules_kos_root_count": 0,
        "candidates_scanned": 0,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_module_reachability_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.module_reachability_walk_status``:
        queued (set by caller via MCP trigger)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Failure persistence on a FRESH session (the inner session rolled back on
    the exception). On failure, ``module_reachability_walk_result`` is
    cleared.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "module_reachability_walk: firmware %s not found", firmware_id,
                )
                return
            firmware.module_reachability_walk_status = "running"
            firmware.module_reachability_walk_started_at = dt.datetime.now(dt.UTC)
            firmware.module_reachability_walk_error = None
            await db.commit()
            try:
                result = await _do_module_reachability_run(db, firmware_id)
                firmware.module_reachability_walk_status = "completed"
                firmware.module_reachability_walk_finished_at = dt.datetime.now(
                    dt.UTC
                )
                firmware.module_reachability_walk_result = (
                    _stamp_firmware_module_reachability_walk_result(result)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.module_reachability_walk_status = "failed"
                        fail_row.module_reachability_walk_finished_at = (
                            dt.datetime.now(dt.UTC)
                        )
                        fail_row.module_reachability_walk_error = err
                        fail_row.module_reachability_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "module_reachability_walk: inner runner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "module_reachability_walk: unrecoverable outer failure for %s",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_module_reachability_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to populate the
    ``module_reachability_walk_result`` JSONB so operators see the last-known
    result even on the first upload. DOES NOT mutate
    ``module_reachability_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_module_reachability_walk`` MCP
    tool works without a 409 conflict.

    ORDERING (Rule #47): registered in walker_registry.WALKER_AUTO_TRIGGERS
    AFTER ``auto_kernel_config_walk_firmware_safe`` so C1 back-fills
    ``metadata.kernel_config`` BEFORE this walker reads it for the
    ``builtin_y_from_config`` axis (sequential dispatch).

    Swallows exceptions silently with structured ``logger.exception``.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_module_reachability_run(db, firmware_id)
                firmware.module_reachability_walk_result = (
                    _stamp_firmware_module_reachability_walk_result(result)
                )
                # No status flip per Rule #39 .safe.
                await db.commit()
            except Exception:
                await db.rollback()
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.module_reachability_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_module_reachability_walk_firmware_safe: inner failed "
                    "for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_module_reachability_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_module_reachability_run",
    "auto_module_reachability_walk_firmware_safe",
    "run_module_reachability_walk_background",
]
