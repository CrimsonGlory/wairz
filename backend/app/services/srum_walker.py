"""Phase ζ.3 — Windows SRUM (System Resource Usage Monitor) walker.

Reads on-disk ``SRUDB.dat`` ESEDB files from extracted Windows
installations and surfaces per-app + per-user resource usage records
(~30-60 days of network bytes / CPU time / push notifications / energy
usage) as ``WindowsSrumRecord`` rows for downstream analysis.

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B = Rule-of-Five):

- :func:`_do_srum_walk_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every ``SRUDB.dat`` in detection roots, parses each
  via ``pyesedb.open()``, persists per-record ``WindowsSrumRecord``
  rows, returns aggregate dict UNSTAMPED.
- :func:`run_srum_walk_background` — OUTER state-machine wrapper.
  Owns Rule #33 .a status transitions via ``async_session_factory()``.
- :func:`auto_walk_firmware_safe` — UNPACK-POST-DETECTION hook. Runs
  the inner orchestrator but does NOT mutate ``srum_walk_status``.

**Rule #36 no-execute discipline.** ``pyesedb.open()`` PARSES SRUDB.dat
AS DATA — read-only ESEDB binding (libesedb C library). wairz does
NOT invoke esedbutil / Get-CimInstance SRUMState / scriptable replay.

**SRUM table layout.** SRUDB.dat carries 5 GUID-named tables + a
SruDbIdMapTable for app/user identifier resolution:

- ``{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`` — application_resource_usage
- ``{973F5D5C-1D90-4944-BE8E-24B94231A174}`` — network_data_usage
- ``{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}`` — network_connectivity
- ``{DD6636C4-8929-4683-974E-22C046A43763}`` — push_notification
- ``{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`` — energy_usage

The walker resolves AppId/UserId integer columns via SruDbIdMapTable
to surface human-readable strings (e.g. chrome.exe path, SID).
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
from app.models.windows_srum_record import WindowsSrumRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_srum_walk_result,
    _stamp_windows_srum_records_extra_metadata,
)

logger = logging.getLogger(__name__)


# ── SRUM table GUID → record_type mapping ────────────────────────────────────

_GUID_APPLICATION_RESOURCE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
_GUID_NETWORK_DATA = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
_GUID_NETWORK_CONNECTIVITY = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
_GUID_PUSH_NOTIFICATION = "{DD6636C4-8929-4683-974E-22C046A43763}"
_GUID_ENERGY_USAGE = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"

_GUID_TO_RECORD_TYPE: dict[str, str] = {
    _GUID_APPLICATION_RESOURCE: "application_resource_usage",
    _GUID_NETWORK_DATA: "network_data_usage",
    _GUID_NETWORK_CONNECTIVITY: "network_connectivity",
    _GUID_PUSH_NOTIFICATION: "push_notification",
    _GUID_ENERGY_USAGE: "energy_usage",
}

_ID_MAP_TABLE_NAME = "SruDbIdMapTable"


# ── Runner tunables ──────────────────────────────────────────────────────────

# Cap on records persisted per file. Real Win11 SRUDB.dat carries 10K-50K
# records across the 5 GUID tables; cap at 50K so a degraded image
# doesn't blow up DB row count. Operators wanting more re-walk via the
# MCP tool against a specific path.
_DEFAULT_MAX_RECORDS_PER_FILE: int = 50_000

# Per-file wall-clock soft cap. libesedb is fast on healthy SRUDBs but
# a corrupted file could send the parser into long iteration.
_DEFAULT_PER_FILE_TIMEOUT_SECONDS: float = 120.0

# Canonical SRUDB filename. Walker scans for this case-insensitively.
_SRUDB_FILENAME: str = "srudb.dat"


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_pyesedb_available() -> bool:
    """Return True iff ``pyesedb`` (libesedb-python binding) is importable."""
    try:
        import pyesedb  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Walker filesystem scan ───────────────────────────────────────────────────


def walk_srudb_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return every ``SRUDB.dat`` path.

    Mirrors the EVTX / Prefetch walker shape: case-insensitive filename
    match + sandbox check that rejects symlinks pointing outside the
    root tree (Rule #1 spirit).

    Sync I/O — wrap in run_in_executor for async callers (Rule #5).
    Defensive against missing roots / permission errors.
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
                if name.lower() != _SRUDB_FILENAME:
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


async def _walk_srudb_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_srudb_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_srudb_files, roots)


# ── Parser helpers ──────────────────────────────────────────────────────────


def _filetime_to_datetime(ts: int) -> _dt.datetime | None:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to UTC."""
    if not ts or ts <= 0:
        return None
    try:
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)
        delta = _dt.timedelta(microseconds=ts / 10.0)
        return epoch + delta
    except (OverflowError, ValueError):
        return None


def _safe_get_value(record: Any, idx: int) -> Any:
    """Safely extract a value from a pyesedb record column at idx.

    libesedb-python's record API returns None for NULL, but raises on
    invalid indices or unusable column types. We swallow every exception
    at the row boundary so one bad column doesn't abort the walk.
    """
    try:
        # Try the typed-int accessor first (most SRUM columns are ints).
        return record.get_value_data_as_integer(idx)
    except Exception:
        pass
    try:
        return record.get_value_data_as_string(idx)
    except Exception:
        pass
    try:
        return record.get_value_data(idx)  # raw bytes
    except Exception:
        return None


def _build_id_map(table: Any) -> dict[int, str]:
    """Build the {IdIndex → IdBlob-decoded-string} map from SruDbIdMapTable.

    SruDbIdMapTable carries IdType (int), IdIndex (int), IdBlob (bytes).
    For SRUM we care about IdType=3 (app/path strings) — the IdBlob
    decodes as UTF-16-LE for app paths. IdType=2 is user SIDs (binary).

    Defensive against malformed rows — skips silently per row.
    """
    id_map: dict[int, str] = {}
    try:
        n = table.get_number_of_records()
    except Exception:
        return id_map

    # Find column indices for IdType / IdIndex / IdBlob.
    try:
        col_count = table.get_number_of_columns()
        col_names = {}
        for ci in range(col_count):
            try:
                col_names[table.get_column(ci).name] = ci
            except Exception:
                pass
    except Exception:
        return id_map

    idx_id_index = col_names.get("IdIndex")
    idx_id_blob = col_names.get("IdBlob")
    idx_id_type = col_names.get("IdType")
    if idx_id_index is None or idx_id_blob is None:
        return id_map

    for ri in range(min(n, 200_000)):  # SruDbIdMapTable can be large
        try:
            rec = table.get_record(ri)
        except Exception:
            continue
        try:
            id_index = rec.get_value_data_as_integer(idx_id_index)
            id_blob_bytes = rec.get_value_data(idx_id_blob)
            id_type = (
                rec.get_value_data_as_integer(idx_id_type)
                if idx_id_type is not None
                else None
            )
        except Exception:
            continue
        if id_index is None or id_blob_bytes is None:
            continue
        # IdType=3: app/path string (UTF-16-LE).
        # IdType=2: user SID (binary). We render as hex for now.
        # IdType=1: AppId (combined w/ AppGuid; rare).
        decoded: str
        if id_type == 3:
            try:
                decoded = id_blob_bytes.decode(
                    "utf-16-le", errors="replace"
                ).rstrip("\x00")
            except (AttributeError, UnicodeDecodeError):
                decoded = f"id:{id_index}"
        else:
            # SID or unknown — render bytes as hex for traceability.
            try:
                decoded = id_blob_bytes.hex() if id_blob_bytes else f"id:{id_index}"
            except Exception:
                decoded = f"id:{id_index}"
        id_map[id_index] = decoded
    return id_map


def _column_index_map(table: Any) -> dict[str, int]:
    """Return {column_name → index} for a pyesedb table."""
    out: dict[str, int] = {}
    try:
        n = table.get_number_of_columns()
    except Exception:
        return out
    for ci in range(n):
        try:
            out[table.get_column(ci).name] = ci
        except Exception:
            pass
    return out


def _build_record_for_table(
    *,
    firmware_id: uuid.UUID,
    record_type: str,
    source_path: str,
    table: Any,
    record: Any,
    col_idx: dict[str, int],
    id_map: dict[int, str],
    table_guid: str,
) -> WindowsSrumRecord | None:
    """Construct a WindowsSrumRecord from one pyesedb record. Returns
    None if the row can't be decoded reliably (defensive boundary)."""

    def _resolve_id(col_name: str) -> str | None:
        idx = col_idx.get(col_name)
        if idx is None:
            return None
        try:
            id_int = record.get_value_data_as_integer(idx)
        except Exception:
            return None
        if id_int is None:
            return None
        return id_map.get(id_int) or f"id:{id_int}"

    def _int_col(col_name: str) -> int | None:
        idx = col_idx.get(col_name)
        if idx is None:
            return None
        try:
            return record.get_value_data_as_integer(idx)
        except Exception:
            return None

    def _filetime_col(col_name: str) -> _dt.datetime | None:
        idx = col_idx.get(col_name)
        if idx is None:
            return None
        try:
            ts_int = record.get_value_data_as_integer(idx)
        except Exception:
            return None
        if ts_int is None:
            return None
        return _filetime_to_datetime(ts_int)

    app_identifier = _resolve_id("AppId")
    user_identifier = _resolve_id("UserId")
    recorded_at = _filetime_col("TimeStamp")

    kwargs: dict[str, Any] = {
        "firmware_id": firmware_id,
        "record_type": record_type,
        "source_path": source_path,
        "app_identifier": app_identifier,
        "user_identifier": user_identifier,
        "recorded_at": recorded_at,
    }

    # Per-record-type metric columns.
    if record_type == "network_data_usage":
        kwargs["bytes_sent"] = _int_col("BytesSent")
        kwargs["bytes_received"] = _int_col("BytesRecvd")
        kwargs["interface_luid"] = _int_col("InterfaceLuid")
    elif record_type == "network_connectivity":
        kwargs["interface_luid"] = _int_col("InterfaceLuid")
        kwargs["duration_seconds"] = _int_col("ConnectedTime")
    elif record_type == "application_resource_usage":
        kwargs["cpu_foreground_seconds"] = _int_col("ForegroundCycleTime")
        kwargs["cpu_background_seconds"] = _int_col("BackgroundCycleTime")
        kwargs["bytes_read"] = _int_col("ForegroundBytesRead") or _int_col(
            "BackgroundBytesRead"
        )
        kwargs["bytes_written"] = _int_col(
            "ForegroundBytesWritten"
        ) or _int_col("BackgroundBytesWritten")
    elif record_type == "push_notification":
        kwargs["push_count"] = _int_col("NotificationCount")
    elif record_type == "energy_usage":
        kwargs["energy_charge"] = _int_col("EventTimestamp")
        kwargs["energy_capacity"] = _int_col("DesignedCapacity")

    # extra_metadata: stamp the source GUID for forensic traceability.
    kwargs["extra_metadata"] = _stamp_windows_srum_records_extra_metadata(
        {"guid_table": table_guid}
    )

    return WindowsSrumRecord(**kwargs)


def _parse_srudb_file(path: str) -> dict[str, Any]:
    """Parse one SRUDB.dat file. Sync — wrap in run_in_executor.

    Returns:
        {
            "status": "ok" | "unavailable" | "error",
            "tables": dict[record_type, list[(table, col_idx)]],
            "id_map": dict[int, str],
            "table_guid_map": dict[record_type, str],
            "error": str (if status == "error"),
        }
    """
    if not is_pyesedb_available():
        return {
            "status": "unavailable",
            "reason": "pyesedb (libesedb-python) not installed",
        }
    import pyesedb

    try:
        f = pyesedb.open(path)
    except Exception as exc:
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {"status": "error", "error": msg}

    return {
        "status": "ok",
        "file": f,
    }


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_srum_walk_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_records_per_file: int = _DEFAULT_MAX_RECORDS_PER_FILE,
) -> dict[str, Any]:
    """Walk every ``SRUDB.dat`` in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for SRUDB.dat files.
    3. For each file: open with pyesedb, build SruDbIdMapTable lookup,
       iterate the 5 GUID-named tables, persist per-record rows via
       db.add_all + flush. (Sync libesedb work runs via run_in_executor.)
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) drive the FULL walk against a real test
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

    srudb_paths = await _walk_srudb_files_async(roots)
    if not srudb_paths:
        return _empty_walk_result(time.monotonic() - started)

    by_record_type: dict[str, int] = {rt: 0 for rt in _GUID_TO_RECORD_TYPE.values()}
    by_status: dict[str, int] = {"ok": 0, "error": 0, "unavailable": 0}
    unique_apps: set[str] = set()
    total_records = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    if not is_pyesedb_available():
        # Surface the missing-dep state as a structured aggregate.
        for srudb_path in srudb_paths:
            relpath = _relativize_path(srudb_path, roots)
            per_file.append(
                {
                    "path": relpath,
                    "status": "unavailable",
                    "record_count": 0,
                    "error": "pyesedb (libesedb-python) not installed",
                }
            )
            by_status["unavailable"] += 1
        return {
            "run_seconds": round(time.monotonic() - started, 3),
            "srudb_count": len(srudb_paths),
            "by_record_type": by_record_type,
            "by_status": by_status,
            "total_records": 0,
            "unique_apps": 0,
            "errors": ["pyesedb not available — install libesedb-python"],
            "per_file": per_file,
        }

    import pyesedb

    for srudb_path in srudb_paths:
        relpath = _relativize_path(srudb_path, roots)
        try:
            # Open + walk in an executor (libesedb is sync C-extension).
            file_records, file_errors = await asyncio.get_running_loop().run_in_executor(
                None,
                _walk_one_srudb_sync,
                pyesedb,
                srudb_path,
                relpath,
                firmware_id,
                max_records_per_file,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = f"parse failed for {srudb_path}: {type(exc).__name__}: {str(exc)[:200]}"
            errors.append(err)
            by_status["error"] += 1
            per_file.append(
                {
                    "path": relpath,
                    "status": "error",
                    "record_count": 0,
                    "error": err,
                }
            )
            continue

        # file_records is a list of (record_type, WindowsSrumRecord).
        # If the parser returned errors AND no records, treat as a
        # per-file error (corrupted SRUDB / open failure / row-decode-
        # only-errors). If records WERE extracted alongside errors,
        # treat as "ok with warnings" — the parser succeeded enough to
        # surface SOME data.
        if not file_records:
            by_status["error"] += 1
            err_msg = (
                file_errors[0]
                if file_errors
                else "no records extracted (empty SRUDB or all rows skipped)"
            )
            errors.extend(file_errors)
            per_file.append(
                {
                    "path": relpath,
                    "status": "error",
                    "record_count": 0,
                    "error": err_msg,
                }
            )
            continue

        # Bulk-insert the records. flush per-file keeps session memory bounded.
        batch_count = 0
        for rt, rec in file_records:
            db.add(rec)
            by_record_type[rt] = by_record_type.get(rt, 0) + 1
            if rec.app_identifier:
                unique_apps.add(rec.app_identifier)
            batch_count += 1
        if batch_count:
            await db.flush()

        total_records += batch_count
        by_status["ok"] += 1
        errors.extend(file_errors)
        per_file.append(
            {
                "path": relpath,
                "status": "ok",
                "record_count": batch_count,
                "error": None,
            }
        )

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "srudb_count": len(srudb_paths),
        "by_record_type": by_record_type,
        "by_status": by_status,
        "total_records": total_records,
        "unique_apps": len(unique_apps),
        "errors": errors,
        "per_file": per_file,
    }


def _walk_one_srudb_sync(
    pyesedb: Any,
    srudb_path: str,
    relpath: str,
    firmware_id: uuid.UUID,
    max_records: int,
) -> tuple[list[tuple[str, WindowsSrumRecord]], list[str]]:
    """Sync helper that opens one SRUDB.dat and yields all WindowsSrumRecord
    rows. Runs in a thread pool via run_in_executor (Rule #5)."""
    out_records: list[tuple[str, WindowsSrumRecord]] = []
    out_errors: list[str] = []

    try:
        f = pyesedb.open(srudb_path)
    except Exception as exc:
        out_errors.append(f"open failed: {type(exc).__name__}: {str(exc)[:200]}")
        return out_records, out_errors

    try:
        # Build SruDbIdMapTable lookup first.
        id_map: dict[int, str] = {}
        n_tables = f.get_number_of_tables()
        for ti in range(n_tables):
            try:
                tbl = f.get_table(ti)
                if tbl.name == _ID_MAP_TABLE_NAME:
                    id_map = _build_id_map(tbl)
                    break
            except Exception:
                continue

        # Walk the 5 GUID-named tables.
        records_so_far = 0
        for ti in range(n_tables):
            if records_so_far >= max_records:
                break
            try:
                tbl = f.get_table(ti)
                tbl_name = tbl.name
            except Exception:
                continue
            record_type = _GUID_TO_RECORD_TYPE.get(tbl_name)
            if record_type is None:
                continue

            col_idx = _column_index_map(tbl)
            try:
                n_records = tbl.get_number_of_records()
            except Exception:
                continue

            for ri in range(n_records):
                if records_so_far >= max_records:
                    break
                try:
                    rec = tbl.get_record(ri)
                except Exception:
                    continue
                try:
                    obj = _build_record_for_table(
                        firmware_id=firmware_id,
                        record_type=record_type,
                        source_path=relpath,
                        table=tbl,
                        record=rec,
                        col_idx=col_idx,
                        id_map=id_map,
                        table_guid=tbl_name,
                    )
                    if obj is not None:
                        out_records.append((record_type, obj))
                        records_so_far += 1
                except Exception as exc:
                    out_errors.append(
                        f"row decode failed (table={tbl_name}, ri={ri}): {type(exc).__name__}: {str(exc)[:100]}"
                    )
                    if len(out_errors) > 100:
                        # Cap error log to keep aggregate size bounded.
                        break
    finally:
        try:
            f.close()
        except Exception:
            pass

    return out_records, out_errors


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "srudb_count": 0,
        "by_record_type": {rt: 0 for rt in _GUID_TO_RECORD_TYPE.values()},
        "by_status": {"ok": 0, "error": 0, "unavailable": 0},
        "total_records": 0,
        "unique_apps": 0,
        "errors": [],
        "per_file": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
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


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_srum_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the SRUM walk.

    Owns AsyncSession via :func:`async_session_factory`; outer guard
    catches escapes; failure persistence on a fresh session. Mirrors
    γ.4 / ε.1.b.3 / ζ.2.B shape exactly.
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
                    "srum_walk: firmware %s not found", firmware_id
                )
                return

            row.srum_walk_status = "running"
            row.srum_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_srum_walk_run(db, firmware_id)
                row.srum_walk_status = "completed"
                row.srum_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.srum_walk_result = _stamp_firmware_srum_walk_result(result)
                await db.commit()
                logger.info(
                    "srum_walk: firmware %s completed in %.2fs "
                    "(%d SRUDB files, %d records, %d unique apps)",
                    firmware_id,
                    result["run_seconds"],
                    result["srudb_count"],
                    result["total_records"],
                    result["unique_apps"],
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
                        fail_row.srum_walk_status = "failed"
                        fail_row.srum_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.srum_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "srum_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "srum_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as ζ.2.B."""
    try:
        async with async_session_factory() as db:
            result = await _do_srum_walk_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.srum_walk_result = _stamp_firmware_srum_walk_result(result)
                await db.commit()
            logger.info(
                "srum_walk auto: firmware %s walked %d SRUDB files in %.2fs",
                firmware_id,
                result["srudb_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "srum_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_srum_walk_run",
    "auto_walk_firmware_safe",
    "is_pyesedb_available",
    "run_srum_walk_background",
    "walk_srudb_files",
]
