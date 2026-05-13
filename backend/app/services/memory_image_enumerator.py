"""Memory-dump-image enumerator (Phase λ.α.B — Rule #39 triplet).

Walks the firmware's detection roots, finds memory-image candidates
matching the extension + size + magic criteria in
:mod:`app.services.memory_image_paths`, and persists per-image rows
into ``memory_dump_image`` (table from λ.α.A). Stamps a per-firmware
aggregate JSONB onto ``firmware.memory_dump_walk_result``.

**This enumerator does NOT invoke Volatility 3.** Its job is metadata
surfacing — "which memory images exist?" That information powers the
operator UI ("you have a 4 GB Windows minidump in this firmware") AND
provides the input set for λ.α.D's vol3_runner. The split lets the
enumerator run independently of the ``INCLUDE_VOL3=1`` Dockerfile
gate (λ.α.C); even on builds without Vol3, operators see which
images exist and could be analysed elsewhere.

Per CLAUDE.md Rule #39, three runners in the canonical shape:

- :func:`_do_memory_image_enumeration` — INNER pure-logic orchestrator.
  Accepts caller-owned ``db``. Resolves detection roots via
  ``get_detection_roots(firmware)`` (Rule #16). Drops any prior
  ``memory_dump_image`` rows for this firmware and re-inserts from
  the current walk (so re-runs reflect current disk state). Returns
  aggregate dict UNSTAMPED — caller is responsible for stamping +
  status mutation.
- :func:`run_memory_image_enumeration_background` — OUTER state-machine
  wrapper. Owns the Rule #33 .a transitions
  ``idle → queued → running → completed | failed`` via
  ``async_session_factory()``. Outer guard catches anything escaping
  the inner; failure persistence on a fresh session (the inner's
  session rolled back on the exception).
- :func:`auto_memory_image_enumeration_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator but does NOT mutate
  ``memory_dump_walk_status`` (leaves ``idle`` so an operator-driven
  re-trigger via ``trigger_memory_dump_walk`` (future MCP tool) works
  without 409 conflict).

Per CLAUDE.md Rule #36 no-execute: the enumerator opens candidate
files READ-ONLY (only the first 16 bytes per file, for magic-byte
detection). NEVER invokes any binary inside a memory image, NEVER
mounts the image as a VM, NEVER passes the image to a process-spawn
primitive. The same Rule #36 invariant carries forward to λ.α.D's
vol3_runner, which spawns the trusted ``vol`` binary with the image
as a DATA argument (-f).

Per CLAUDE.md Rule #16 detection_roots: the enumerator iterates
``get_detection_roots(firmware)`` — never bare ``firmware.extracted_path``.
Scatter-zip extractions, multi-archive medical firmware, and nested
unblob outputs all surface multiple roots; the enumerator visits each.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import time
import traceback
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage
from app.services.firmware_paths import get_detection_roots
from app.services.memory_image_paths import enumerate_memory_image_candidates

logger = logging.getLogger(__name__)


# Result-aggregate schema version. Bumped if/when the dict shape changes
# in a way that breaks downstream consumers (per Rule #35c JSONB discipline).
_MEMORY_DUMP_WALK_RESULT_SCHEMA_VERSION: int = 1


def _empty_aggregate() -> dict:
    """Default aggregate when no images were found (or walker no-op'd)."""
    return {
        "schema_version": _MEMORY_DUMP_WALK_RESULT_SCHEMA_VERSION,
        "image_count": 0,
        "total_bytes": 0,
        "by_os_family": {
            "windows": 0,
            "linux": 0,
            "mac": 0,
            "unknown": 0,
        },
        "elapsed_s": 0.0,
    }


async def _do_memory_image_enumeration(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER orchestrator — enumerate + persist memory_dump_image rows.

    Returns the aggregate dict. Does NOT mutate ``firmware.memory_dump_walk_status``;
    that's the OUTER wrapper's responsibility. Does NOT commit; the
    caller controls the transaction.
    """
    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        logger.warning(
            "memory_image_enumeration: firmware %s vanished pre-walk", firmware_id
        )
        return _empty_aggregate()

    aggregate = _empty_aggregate()
    t0 = time.monotonic()

    detection_roots = await get_detection_roots(firmware, db=db, use_cache=True)
    if not detection_roots:
        aggregate["elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    # Drop prior rows for this firmware so the re-walk reflects current
    # disk state (e.g. if an /unpack call removed images, or if a vendor
    # added them post-upload via /firmware/<id>/files). Cascading FK
    # handles the cleanup; we just issue the DELETE.
    await db.execute(
        delete(MemoryDumpImage).where(MemoryDumpImage.firmware_id == firmware_id)
    )

    # The enumerator's sync helper walks the filesystem; run in the
    # default thread pool so the async loop stays responsive on
    # multi-GB firmware trees.
    loop = asyncio.get_running_loop()
    candidates = await loop.run_in_executor(
        None,
        _materialise_candidates,
        detection_roots,
    )

    for cand in candidates:
        db.add(
            MemoryDumpImage(
                firmware_id=firmware_id,
                image_path=cand.image_path,
                image_filename=cand.image_filename,
                file_size=cand.file_size,
                magic_detected=cand.magic_detected,
                os_family=cand.os_family,
            )
        )
        aggregate["image_count"] += 1
        aggregate["total_bytes"] += cand.file_size
        bucket = cand.os_family if cand.os_family in aggregate["by_os_family"] else "unknown"
        aggregate["by_os_family"][bucket] += 1

    await db.flush()
    aggregate["elapsed_s"] = round(time.monotonic() - t0, 3)
    logger.info(
        "memory_image_enumeration: firmware %s found %d images / %d bytes in %.2fs",
        firmware_id,
        aggregate["image_count"],
        aggregate["total_bytes"],
        aggregate["elapsed_s"],
    )
    return aggregate


def _materialise_candidates(detection_roots: list[str]) -> list:
    """Drain the enumeration iterator into a list (sync; runs in executor).

    The iterator is the cheap part; collecting up-front lets the async
    INSERT loop above stay simple. For firmwares with thousands of
    memory-image candidates (unusual but possible — Hyper-V VM bundles)
    the list grows linearly in candidate count, not in tree-size, so
    materialising is safe.
    """
    return list(enumerate_memory_image_candidates(detection_roots))


async def run_memory_image_enumeration_background(firmware_id: uuid.UUID) -> None:
    """OUTER state-machine wrapper.

    Owns the Rule #33 .a state transitions and stamps the aggregate
    onto ``firmware.memory_dump_walk_result``. Failure persistence on
    a fresh session because the inner session rolled back on the
    exception.
    """
    try:
        async with async_session_factory() as db:
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.memory_dump_walk_status = "running"
            firmware.memory_dump_walk_started_at = _dt.datetime.now(_dt.UTC)
            firmware.memory_dump_walk_error = None
            await db.commit()

            try:
                aggregate = await _do_memory_image_enumeration(db, firmware_id)
            except Exception as exc:  # noqa: BLE001 — outer guard captures all
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
                        fail_row.memory_dump_walk_status = "failed"
                        fail_row.memory_dump_walk_finished_at = _dt.datetime.now(_dt.UTC)
                        fail_row.memory_dump_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "memory_image_enumeration failed for firmware %s",
                    firmware_id,
                )
                return

            firmware.memory_dump_walk_status = "completed"
            firmware.memory_dump_walk_finished_at = _dt.datetime.now(_dt.UTC)
            firmware.memory_dump_walk_result = aggregate
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard; never crash the worker
        logger.exception(
            "unrecoverable error in run_memory_image_enumeration_background"
        )


async def auto_memory_image_enumeration_safe(firmware_id: uuid.UUID) -> None:
    """UNPACK-POST-DETECTION hook — fire-and-forget enumerator.

    Owns its own session. Stamps the aggregate but does NOT mutate
    ``memory_dump_walk_status`` — leaves ``idle`` so an operator-driven
    re-trigger via the future ``trigger_memory_dump_walk`` MCP tool
    succeeds without a 409 conflict (Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            try:
                aggregate = await _do_memory_image_enumeration(db, firmware_id)
            except Exception:  # noqa: BLE001 — safe-runner swallows per Rule #39
                logger.exception(
                    "auto memory_image_enumeration failed for firmware %s",
                    firmware_id,
                )
                return
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.memory_dump_walk_result = aggregate
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard
        logger.exception(
            "unrecoverable error in auto_memory_image_enumeration_safe"
        )
