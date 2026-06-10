"""MOVE 2 reachability-export durability walker (wairz↔framework bridge, binary axis).

Persists the per-ELF-blob symbol-presence facts the bridge producer
(:mod:`app.services.reachability_export`) extracts, so the bridge data is durable + queryable:

  * PER-BLOB rows into ``reachability_export_records`` (GIN-indexed ``defined_symbols``) — the
    landing zone the Rule #44 ``lookup_reachable_symbol_across_firmwares`` MCP tool queries with a
    JSONB-containment filter ("which firmwares DEFINE symbol X").
  * A small AGGREGATE (blob/elf/stripped counts + total_defined_symbols) onto
    ``firmware.reachability_export_walk_result`` so operators see the last-known result without
    loading hundreds of thousands of symbol strings.

It reuses the already-detected ``HardwareFirmwareBlob`` rows (their path + sha256), so there is no
second tree walk — :func:`extract_elf_symbols` self-gates on the ELF magic, so non-ELF blobs
(mbn / dtb / raw_bin / ...) are silently skipped. PARSE-ONLY (Rule #36 / #45): symbols are read
from the ELF symbol table AS DATA via pyelftools; no binary is ever executed. The Iron Law —
symbol absence is valid ONLY on a NON-STRIPPED, sha256-matched binary — is enforced at the bridge
producer/consumer; the per-blob completeness flags (stripped / has_symtab / has_dynsym) travel
WITH each persisted row so a consumer re-checks trustworthiness.

Three functions per CLAUDE.md Rule #39 (inner / outer / safe triplet):

  - :func:`_do_reachability_export_run` — INNER pure-logic orchestrator. Caller owns the session +
    transaction. Clears stale aggregate + per-blob rows at entry, iterates the firmware's blobs,
    persists a row per ELF blob, returns the aggregate UNSTAMPED (caller stamps via
    ``_stamp_firmware_reachability_export_walk_result``).
  - :func:`run_reachability_export_walk_background` — OUTER Rule #33 .a state machine
    (queued → running → completed | failed). Owns its own ``async_session_factory()``.
  - :func:`auto_reachability_export_walk_firmware_safe` — SAFE unpack-post-detection hook. Stamps
    the aggregate so operators see the last-known result; does NOT mutate
    ``reachability_export_walk_status`` (leaves it ``idle`` so an operator re-trigger via the
    ``trigger_reachability_export_walk`` MCP tool succeeds without a 409 conflict).

ORDERING (Rule #47): registered in WALKER_AUTO_TRIGGERS AFTER the hardware-firmware blob detection
that creates the ``HardwareFirmwareBlob`` rows this walker reads (the legacy
``auto_extract_drivers_safe`` / detection hook precedes the walker list).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import traceback
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.reachability_export import ReachabilityExportRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _coerce_symbol_list,
    _stamp_firmware_reachability_export_walk_result,
)
from app.services.reachability_export import _rel_path, extract_elf_symbols

logger = logging.getLogger(__name__)


def _empty_aggregate(walked_at: str, errors: list[str]) -> dict:
    """Stable empty-result shape (firmware missing / no blobs)."""
    return {
        "walked_at": walked_at,
        "blob_count": 0,
        "elf_count": 0,
        "stripped_count": 0,
        "total_defined_symbols": 0,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_reachability_export_run(
    db: AsyncSession, firmware_id: uuid.UUID
) -> dict:
    """INNER pure-logic orchestrator. Caller owns the session + transaction.

    Clears the stale aggregate + the firmware's stale per-blob rows at entry, iterates the
    firmware's ``HardwareFirmwareBlob`` rows, extracts each ELF blob's symbol sets (parse-only),
    persists a ``ReachabilityExportRecord`` per ELF blob, and returns the aggregate UNSTAMPED.
    Non-ELF blobs are skipped (``extract_elf_symbols`` returns ``None``). Symbol reads run in an
    executor (Rule #5).
    """
    walked_at = dt.datetime.now(dt.UTC).isoformat()

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_aggregate(walked_at, [f"firmware {firmware_id} not found"])

    # Clear stale aggregate + per-blob rows at entry (re-populate fresh each run; the uq on
    # (firmware_id, blob_sha256) is satisfied because the DELETE flushes before the INSERTs).
    firmware.reachability_export_walk_result = None
    await db.execute(
        delete(ReachabilityExportRecord).where(
            ReachabilityExportRecord.firmware_id == firmware_id
        )
    )

    # Detection roots for path relativisation (Rule #16 — handles scatter-zip / container roots).
    detection_roots = await get_detection_roots(firmware, db=db)

    blobs = (
        await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
    ).scalars().all()

    loop = asyncio.get_running_loop()
    errors: list[str] = []
    elf_count = 0
    stripped_count = 0
    total_defined = 0
    seen_sha: set[str] = set()  # defensive vs the (firmware_id, blob_sha256) uq

    for blob in blobs:
        if blob.blob_sha256 in seen_sha:
            continue
        try:
            syms = await loop.run_in_executor(
                None, extract_elf_symbols, blob.blob_path
            )
        except Exception as exc:  # noqa: BLE001 — per-blob boundary; never fail the whole walk
            errors.append(f"symbol extraction failed for {blob.blob_path}: {exc}")
            continue
        if syms is None:
            continue  # non-ELF -> skip (never fabricate a record)

        seen_sha.add(blob.blob_sha256)
        elf_count += 1
        stripped = bool(syms.get("stripped", True))
        if stripped:
            stripped_count += 1
        defined = _coerce_symbol_list(syms.get("defined_symbols"))
        imported = _coerce_symbol_list(syms.get("imported_symbols"))
        total_defined += len(defined)

        db.add(
            ReachabilityExportRecord(
                firmware_id=firmware_id,
                blob_id=blob.id,
                blob_path=_rel_path(blob.blob_path, detection_roots),
                blob_sha256=blob.blob_sha256,
                defined_symbols=defined,
                imported_symbols=imported,
                stripped=stripped,
                has_symtab=bool(syms.get("has_symtab", False)),
                has_dynsym=bool(syms.get("has_dynsym", False)),
                arch=syms.get("arch"),
            )
        )

    return {
        "walked_at": walked_at,
        "blob_count": len(blobs),
        "elf_count": elf_count,
        "stripped_count": stripped_count,
        "total_defined_symbols": total_defined,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_reachability_export_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.reachability_export_walk_status``: queued (set by the MCP trigger) →
    running (this fn, on entry) → completed | failed (this fn, on exit). Failure persistence on a
    FRESH session (the inner session rolled back on the exception).
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "reachability_export_walk: firmware %s not found", firmware_id
                )
                return
            firmware.reachability_export_walk_status = "running"
            firmware.reachability_export_walk_started_at = dt.datetime.now(dt.UTC)
            firmware.reachability_export_walk_error = None
            await db.commit()
            try:
                result = await _do_reachability_export_run(db, firmware_id)
                firmware.reachability_export_walk_status = "completed"
                firmware.reachability_export_walk_finished_at = dt.datetime.now(dt.UTC)
                firmware.reachability_export_walk_result = (
                    _stamp_firmware_reachability_export_walk_result(result)
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
                        fail_row.reachability_export_walk_status = "failed"
                        fail_row.reachability_export_walk_finished_at = dt.datetime.now(
                            dt.UTC
                        )
                        fail_row.reachability_export_walk_error = err
                        fail_row.reachability_export_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "reachability_export_walk: inner runner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "reachability_export_walk: unrecoverable outer failure for %s",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_reachability_export_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to persist the per-blob rows + stamp the aggregate so
    operators see the last-known result on the first upload. DOES NOT mutate
    ``reachability_export_walk_status`` — leaves it ``idle`` so an operator-triggered re-walk via
    ``trigger_reachability_export_walk`` works without a 409. Swallows exceptions silently.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_reachability_export_run(db, firmware_id)
                firmware.reachability_export_walk_result = (
                    _stamp_firmware_reachability_export_walk_result(result)
                )
                # No status flip per Rule #39 .safe.
                await db.commit()
            except Exception:
                await db.rollback()
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.reachability_export_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_reachability_export_walk_firmware_safe: inner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_reachability_export_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_reachability_export_run",
    "auto_reachability_export_walk_firmware_safe",
    "run_reachability_export_walk_background",
]
