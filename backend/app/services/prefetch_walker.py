"""Phase ζ.2 — Windows Prefetch (.pf) walker.

Reads on-disk ``.pf`` Prefetch files from extracted Windows installations
and surfaces application-execution history (last run times, run counts,
files referenced) as ``WindowsPrefetchRecord`` rows for downstream
finding-emit hooks (ζ.2.D).

**Mirrors γ.4 / δ.5 / ε.1.b.3 precedent shape.** Per the Rule #39
inner/outer/safe runner triplet codified in CLAUDE.md and
``.mex/patterns/inner-outer-safe-runner.md``:

- :func:`_do_prefetch_walk_run` — INNER orchestrator. Accepts
  caller-owned ``db``. Walks every ``.pf`` in the firmware's detection
  roots, parses each via ``windowsprefetch.Prefetch``, persists per-row
  ``WindowsPrefetchRecord`` and returns aggregate dict UNSTAMPED.
- :func:`run_prefetch_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running → completed |
  failed) via ``async_session_factory()``. Outer guard catches escapes;
  failure persistence on a fresh session.
- :func:`auto_walk_firmware_safe` — UNPACK-POST-DETECTION hook. Runs
  the inner orchestrator but does NOT mutate ``prefetch_walk_status``
  (leaves ``idle`` so manual re-trigger works without 409).

**Rule #36 no-execute discipline.** ``windowsprefetch.Prefetch`` PARSES
``.pf`` AS DATA — read-only file open + ``struct.unpack``. wairz does
NOT invoke pftriage / Get-CimInstance Win32_PrefetchedApp / scriptable
replay. Future workers that shell out to additional Prefetch tools
MUST extend ``FORBIDDEN_ARGV0_TOKENS`` in the same shape as δ.4.

**Rule #19 evidence-first probe.** :func:`is_windowsprefetch_available`
exposes a graceful-degrade probe so consumers can surface a clear
"library not installed" message rather than an opaque ImportError.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_prefetch_record import WindowsPrefetchRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_prefetch_walk_result,
    _stamp_windows_prefetch_records_all_run_times,
    _stamp_windows_prefetch_records_filenames_referenced,
    _stamp_windows_prefetch_records_volumes,
)

logger = logging.getLogger(__name__)


# ── Runner tunables ──────────────────────────────────────────────────────────

# Maximum filename strings persisted PER prefetch record. Real Win10
# Prefetch files can carry 200-500 filename references; the per-record
# JSONB caps at this many so the row size stays bounded. Operators
# wanting full inspection can re-walk via the MCP tool against a
# specific path.
_DEFAULT_FILENAMES_CAP_PER_RECORD: int = 256

# Maximum volume entries per record (Win10 typically 1-2; harmless to
# raise the cap, but bound for safety against malformed files).
_DEFAULT_VOLUMES_CAP_PER_RECORD: int = 16

# Maximum walk wall-clock per .pf file. windowsprefetch is fast but a
# multi-MB MAM-compressed .pf in a degraded image could send the parser
# into a long iteration. Soft-cap (checked between files, not per-byte).
_DEFAULT_PER_FILE_TIMEOUT_SECONDS: float = 30.0


# ── Walker constants ────────────────────────────────────────────────────────

_PREFETCH_EXTENSION: str = ".pf"


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_windowsprefetch_available() -> bool:
    """Return True iff ``windowsprefetch`` is importable in this process.

    Mirrors the regipy / python-evtx graceful-degrade probes used by γ.4
    and ε.1.b. The probe runs in <1 ms after first call (Python's
    import cache).
    """
    try:
        import windowsprefetch  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Parser ──────────────────────────────────────────────────────────────────


WINDOWSPREFETCH_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "windowsprefetch not installed — see backend/pyproject.toml ζ.2 block",
    "data": None,
}


def _filetime_to_datetime(ts: int) -> _dt.datetime | None:
    """Convert a Windows FILETIME value (100ns ticks since 1601-01-01) to
    a timezone-aware UTC datetime. Returns None on overflow / 0 / invalid."""
    if not ts or ts <= 0:
        return None
    try:
        # FILETIME is 100ns ticks; convert to microseconds for timedelta.
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)
        delta = _dt.timedelta(microseconds=ts / 10.0)
        return epoch + delta
    except (OverflowError, ValueError):
        return None


def _extract_volumes(pf_obj: Any) -> list[dict[str, Any]]:
    """Extract volume entries from a parsed Prefetch object.

    The windowsprefetch library populates ``volumesInformationArray``
    after volumeInformation*() runs. Each entry is a dict with various
    keys depending on parser version; we normalise to the canonical
    ``{"device_path", "serial_number", "creation_time"}`` shape.
    """
    volumes: list[dict[str, Any]] = []
    raw = getattr(pf_obj, "volumesInformationArray", None)
    if not raw:
        return volumes
    for v in raw[:_DEFAULT_VOLUMES_CAP_PER_RECORD]:
        if not isinstance(v, dict):
            continue
        # windowsprefetch uses "Volume Path" / "Volume Serial Number" /
        # "Volume Creation Date" keys (with spaces) or sometimes the
        # raw attribute names; tolerate both.
        device_path = (
            v.get("Volume Path")
            or v.get("volPath")
            or v.get("device_path")
            or ""
        )
        serial = v.get("Volume Serial Number") or v.get("volSerialNumber")
        creation = (
            v.get("Volume Creation Date")
            or v.get("volCreationTime")
            or v.get("creation_time")
        )
        if isinstance(creation, int):
            dt = _filetime_to_datetime(creation)
            creation = dt.isoformat() if dt else None
        elif creation is not None:
            creation = str(creation)
        volumes.append(
            {
                "device_path": str(device_path) if device_path else "",
                "serial_number": str(serial) if serial else None,
                "creation_time": creation,
            }
        )
    return volumes


def parse_prefetch_file(path: str | Path) -> dict[str, Any]:
    """Parse a single ``.pf`` file and return a structured summary.

    Returns a dict with keys:
    - ``status``: "ok" | "unavailable" | "error".
    - ``data``: parsed Prefetch fields when status="ok"; None otherwise.
    - ``error``: present only when status="error" (truncated to 500 chars).

    **Defensive against missing dep** — returns
    :data:`WINDOWSPREFETCH_UNAVAILABLE` shape if the library isn't
    importable. Callers MUST check ``status`` before accessing ``data``.

    **Defensive against malformed input** — wraps the parse in a
    try/except. Truncated / corrupted .pf files surface a structured
    error instead of crashing the caller.

    Rule #36 reminder: ``path`` is read AS DATA (windowsprefetch uses
    ``open(infile, "rb")`` + struct.unpack — no process spawn).
    """
    if not is_windowsprefetch_available():
        return WINDOWSPREFETCH_UNAVAILABLE

    # Lazy import per Rule #30 — keeps cold-import fast for non-ζ
    # code paths.
    from windowsprefetch.windowsprefetch import Prefetch

    try:
        pf = Prefetch(str(path))
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {"status": "error", "data": None, "error": msg}

    # Extract structured fields.
    timestamps_raw = list(getattr(pf, "timestamps", []) or [])
    # timestamps from windowsprefetch's getTimeStamps are ALREADY
    # human-readable strings (str(datetime + timedelta)); we re-parse
    # to ISO format for canonical persistence.
    timestamps_iso: list[str] = []
    for ts in timestamps_raw:
        try:
            # The library returns "1601-01-01 00:00:00.000000" naive form.
            parsed = _dt.datetime.fromisoformat(str(ts))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=_dt.UTC)
            timestamps_iso.append(parsed.isoformat())
        except (ValueError, TypeError):
            # Pass through as-is if parse fails (defensive).
            timestamps_iso.append(str(ts))

    last_run_dt: _dt.datetime | None = None
    if timestamps_iso:
        try:
            last_run_dt = _dt.datetime.fromisoformat(timestamps_iso[0])
        except (ValueError, TypeError):
            last_run_dt = None

    resources = list(getattr(pf, "resources", []) or [])[
        :_DEFAULT_FILENAMES_CAP_PER_RECORD
    ]
    # Filter out empty strings that the UTF-16 decode tail-trim leaves.
    resources = [r for r in resources if r and r.strip()]

    return {
        "status": "ok",
        "data": {
            "executable_name": str(getattr(pf, "executableName", "") or "")[:256],
            "prefetch_hash": str(getattr(pf, "hash", "") or "")[:16],
            "version": int(getattr(pf, "version", 0) or 0) or None,
            "run_count": int(getattr(pf, "runCount", 0) or 0) or None,
            "last_run_time": last_run_dt,
            "all_run_times": timestamps_iso,
            "filenames_referenced": resources,
            "volumes": _extract_volumes(pf),
        },
    }


# ── Walker ──────────────────────────────────────────────────────────────────


def walk_prefetch_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return a list of ``.pf`` file paths.

    Mirrors the EVTX walker / registry hive walker shape: case-insensitive
    extension match + sandbox check that rejects symlinks pointing
    outside the root tree (Rule #1 spirit).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors, short reads —
    every error path is swallowed at the per-root / per-file level so
    one corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path`` alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                if not name.lower().endswith(_PREFETCH_EXTENSION):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


async def _walk_prefetch_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_prefetch_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_prefetch_files, roots)


async def _parse_prefetch_file_async(path: str) -> dict[str, Any]:
    """Async wrapper around :func:`parse_prefetch_file` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, parse_prefetch_file, path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "prefetch_count": 0,
        "by_status": {"ok": 0, "error": 0, "unavailable": 0},
        "executable_count": 0,
        "total_runs_recorded": 0,
        "errors": [],
        "per_file": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it.
    Matches the WindowsPrefetchRecord.prefetch_file_path discipline."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return real_full[len(real_root) + 1 :] if real_full != real_root else "."
    return os.path.basename(full_path)


def _build_record(
    firmware_id: uuid.UUID,
    prefetch_file_path: str,
    parsed_data: dict[str, Any],
) -> WindowsPrefetchRecord | None:
    """Construct a WindowsPrefetchRecord from a parse result. Returns None
    if the minimum-required fields are missing."""
    exe_name = parsed_data.get("executable_name") or ""
    if not exe_name:
        return None
    return WindowsPrefetchRecord(
        firmware_id=firmware_id,
        prefetch_file_path=prefetch_file_path[:1024],
        executable_name=exe_name,
        prefetch_hash=parsed_data.get("prefetch_hash"),
        version=parsed_data.get("version"),
        run_count=parsed_data.get("run_count"),
        last_run_time=parsed_data.get("last_run_time"),
        all_run_times=_stamp_windows_prefetch_records_all_run_times(
            parsed_data.get("all_run_times") or []
        ),
        filenames_referenced=_stamp_windows_prefetch_records_filenames_referenced(
            parsed_data.get("filenames_referenced") or []
        ),
        volumes=_stamp_windows_prefetch_records_volumes(
            parsed_data.get("volumes") or []
        ),
    )


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_prefetch_walk_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict[str, Any]:
    """Walk every ``.pf`` file in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for ``.pf`` files.
    3. For each file: parse via windowsprefetch (run_in_executor for
       Rule #5 sync I/O), bulk-insert WindowsPrefetchRecord rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.
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

    pf_paths = await _walk_prefetch_files_async(roots)
    if not pf_paths:
        return _empty_walk_result(time.monotonic() - started)

    by_status: dict[str, int] = {"ok": 0, "error": 0, "unavailable": 0}
    executables: set[str] = set()
    total_runs = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    for pf_path in pf_paths:
        relpath = _relativize_path(pf_path, roots)
        try:
            parsed = await _parse_prefetch_file_async(pf_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = f"parse failed for {pf_path}: {type(exc).__name__}: {str(exc)[:200]}"
            errors.append(err)
            by_status["error"] += 1
            per_file.append(
                {
                    "path": relpath,
                    "status": "error",
                    "executable_name": None,
                    "run_count": None,
                    "error": err,
                }
            )
            continue

        status = parsed.get("status", "error")
        by_status[status] = by_status.get(status, 0) + 1

        if status == "ok":
            data = parsed.get("data") or {}
            record = _build_record(firmware_id, relpath, data)
            if record is not None:
                db.add(record)
                await db.flush()
                if record.executable_name:
                    executables.add(record.executable_name)
                if record.run_count:
                    total_runs += record.run_count
            per_file.append(
                {
                    "path": relpath,
                    "status": "ok",
                    "executable_name": data.get("executable_name"),
                    "run_count": data.get("run_count"),
                    "error": None,
                }
            )
        else:
            per_file.append(
                {
                    "path": relpath,
                    "status": status,
                    "executable_name": None,
                    "run_count": None,
                    "error": parsed.get("error") or parsed.get("reason"),
                }
            )

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "prefetch_count": len(pf_paths),
        "by_status": by_status,
        "executable_count": len(executables),
        "total_runs_recorded": total_runs,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_prefetch_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the Prefetch walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the γ.4
    registry_hive_walker / ε.1.b.3 evtx_service shape.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
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
                    "prefetch_walk: firmware %s not found", firmware_id
                )
                return

            row.prefetch_walk_status = "running"
            row.prefetch_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_prefetch_walk_run(db, firmware_id)
                row.prefetch_walk_status = "completed"
                row.prefetch_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.prefetch_walk_result = _stamp_firmware_prefetch_walk_result(
                    result
                )
                await db.commit()
                logger.info(
                    "prefetch_walk: firmware %s completed in %.2fs "
                    "(%d .pf files, %d unique executables, %d total runs)",
                    firmware_id,
                    result["run_seconds"],
                    result["prefetch_count"],
                    result["executable_count"],
                    result["total_runs_recorded"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.prefetch_walk_status = "failed"
                        fail_row.prefetch_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.prefetch_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "prefetch_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "prefetch_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as
    :func:`evtx_service.auto_walk_firmware_safe` (Rule #39 precedent).

    Distinct from :func:`run_prefetch_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_prefetch_walk_run``) but DOES NOT transition the status
    column — it stays ``idle`` until an operator explicitly triggers
    a re-walk via the trigger MCP tool, which resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_prefetch_walk_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.prefetch_walk_result = _stamp_firmware_prefetch_walk_result(
                    result
                )
                await db.commit()
            logger.info(
                "prefetch_walk auto: firmware %s walked %d .pf files in %.2fs",
                firmware_id,
                result["prefetch_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "prefetch_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "WINDOWSPREFETCH_UNAVAILABLE",
    "_do_prefetch_walk_run",
    "auto_walk_firmware_safe",
    "is_windowsprefetch_available",
    "parse_prefetch_file",
    "run_prefetch_walk_background",
    "walk_prefetch_files",
]
