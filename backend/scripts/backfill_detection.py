#!/usr/bin/env python3
"""One-off backfill: re-run hardware-firmware detection on every Firmware row.

Phase 4 of the ``feature-extraction-integrity`` campaign.  Invalidates the
cached detection_roots, recomputes them from disk, re-runs the detector
and the multi-tier CVE matcher, and records per-firmware audit deltas
into ``firmware.device_metadata['detection_audit']``.

Usage::

    # Dry-run — recompute roots only, no detector / CVE writes.
    docker compose exec -T backend /app/.venv/bin/python \
        scripts/backfill_detection.py --dry-run

    # Real run — full pipeline on every row.
    docker compose exec -T backend /app/.venv/bin/python \
        scripts/backfill_detection.py

    # Scope to one firmware or a small batch.
    docker compose exec -T backend /app/.venv/bin/python \
        scripts/backfill_detection.py --firmware-id 3712e5ad-...
    docker compose exec -T backend /app/.venv/bin/python \
        scripts/backfill_detection.py --limit 2

The script owns its transaction — it ``await db.commit()``s per firmware,
so a later failure never clobbers an already-backfilled row.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.services.firmware_paths import (
    get_detection_roots,
    invalidate_detection_roots,
)
from app.services.hardware_firmware.cve_matcher import match_firmware_cves
from app.services.hardware_firmware.detector import detect_hardware_firmware

logger = logging.getLogger("backfill_detection")


@dataclass
class FirmwareResult:
    """Per-firmware backfill outcome."""

    firmware_id: uuid.UUID
    filename: str | None
    roots_count: int
    blobs_before: int
    blobs_after: int
    cve_matches: int
    status: str  # ok | skipped | error
    note: str = ""

    @property
    def blobs_delta(self) -> int:
        return self.blobs_after - self.blobs_before


@dataclass
class BackfillSummary:
    """Aggregate numbers for end-of-run logging."""

    processed: int = 0
    skipped: int = 0
    errored: int = 0
    total_delta_blobs: int = 0
    total_cve_matches: int = 0
    results: list[FirmwareResult] = field(default_factory=list)


async def _count_blobs(db: AsyncSession, firmware_id: uuid.UUID) -> int:
    stmt = select(func.count(HardwareFirmwareBlob.id)).where(
        HardwareFirmwareBlob.firmware_id == firmware_id,
    )
    return int((await db.execute(stmt)).scalar_one() or 0)


async def _count_blob_cves(db: AsyncSession, firmware_id: uuid.UUID) -> int:
    stmt = select(func.count(SbomVulnerability.id)).where(
        SbomVulnerability.firmware_id == firmware_id,
        SbomVulnerability.blob_id.is_not(None),
    )
    return int((await db.execute(stmt)).scalar_one() or 0)


def _stamp_audit(firmware: Firmware, result: FirmwareResult) -> None:
    """Write Phase 5 seed audit info into ``device_metadata['detection_audit']``.

    Preserves every other key in ``device_metadata``.  Kept simple — the full
    audit table is Phase 5 work.
    """
    existing = dict(firmware.device_metadata or {})
    audit = dict(existing.get("detection_audit") or {})
    audit.update(
        {
            "last_backfill_at": datetime.now(UTC).isoformat(),
            "blobs_detected": result.blobs_after,
            "orphans_pre_backfill": max(0, result.blobs_after - result.blobs_before),
            "roots_count": result.roots_count,
        }
    )
    existing["detection_audit"] = audit
    firmware.device_metadata = existing


async def backfill_one(
    firmware: Firmware,
    db: AsyncSession,
    *,
    dry_run: bool = False,
) -> FirmwareResult:
    """Run the backfill pipeline for one firmware row.

    Safe to call in a loop — any exception is caught by :func:`run_backfill`,
    not here.  On ``dry_run``, no writes leave this function: we invalidate
    the cache, recompute roots (cache write is suppressed below), and skip
    the detector + CVE matcher.
    """
    filename = firmware.original_filename
    firmware_id = firmware.id
    extracted = firmware.extracted_path

    if not extracted:
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            roots_count=0,
            blobs_before=0,
            blobs_after=0,
            cve_matches=0,
            status="skipped",
            note="no extraction",
        )

    if not os.path.isdir(extracted):
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            roots_count=0,
            blobs_before=0,
            blobs_after=0,
            cve_matches=0,
            status="skipped",
            note="extraction missing on disk",
        )

    blobs_before = await _count_blobs(db, firmware_id)

    # Invalidate + recompute roots. On dry-run we don't persist.
    if dry_run:
        # Recompute without persisting: call with db=None so the helper
        # skips the JSONB write + flush.
        roots = await get_detection_roots(firmware, db=None, use_cache=False)
    else:
        await invalidate_detection_roots(firmware, db)
        roots = await get_detection_roots(firmware, db=db, use_cache=False)

    if not roots:
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            roots_count=0,
            blobs_before=blobs_before,
            blobs_after=blobs_before,
            cve_matches=0,
            status="skipped",
            note="no detection roots",
        )

    if dry_run:
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            roots_count=len(roots),
            blobs_before=blobs_before,
            blobs_after=blobs_before,
            cve_matches=0,
            status="ok",
            note="dry-run (no detector / cve write)",
        )

    # Live path: detector + CVE matcher.  Failures in either must NOT
    # abort the whole batch — individual errors are captured per row.
    try:
        await detect_hardware_firmware(firmware_id, db, walk_roots=roots)
    except Exception as exc:  # noqa: BLE001
        logger.exception("detector failed for firmware_id=%s", firmware_id)
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            roots_count=len(roots),
            blobs_before=blobs_before,
            blobs_after=blobs_before,
            cve_matches=0,
            status="error",
            note=f"detector raised: {type(exc).__name__}: {exc}"[:240],
        )

    blobs_after = await _count_blobs(db, firmware_id)
    cve_count_before = await _count_blob_cves(db, firmware_id)

    try:
        await match_firmware_cves(firmware_id, db, force_rescan=False)
    except Exception as exc:  # noqa: BLE001
        logger.exception("cve matcher failed for firmware_id=%s", firmware_id)
        cve_after = cve_count_before
        note = f"cve matcher raised: {type(exc).__name__}: {exc}"[:240]
        status = "error"
    else:
        cve_after = await _count_blob_cves(db, firmware_id)
        note = ""
        status = "ok"

    result = FirmwareResult(
        firmware_id=firmware_id,
        filename=filename,
        roots_count=len(roots),
        blobs_before=blobs_before,
        blobs_after=blobs_after,
        cve_matches=max(0, cve_after - cve_count_before),
        status=status,
        note=note,
    )
    _stamp_audit(firmware, result)
    await db.flush()
    return result


def _emit_row(r: FirmwareResult) -> None:
    """Print one per-firmware result line."""
    display_name = (r.filename or "(unknown)")[:56]
    print(
        f"  {str(r.firmware_id)[:8]}  {display_name:<56} "
        f"roots={r.roots_count:>2}  "
        f"blobs {r.blobs_before:>4} -> {r.blobs_after:>4}  "
        f"delta {r.blobs_delta:+5d}  "
        f"cves={r.cve_matches:>3}  "
        f"[{r.status}]  {r.note}"
    )


async def run_backfill(
    *,
    dry_run: bool = False,
    firmware_id: uuid.UUID | None = None,
    limit: int | None = None,
) -> BackfillSummary:
    """Walk every Firmware row (respecting filters) and run the backfill."""
    summary = BackfillSummary()

    async with async_session_factory() as outer_db:
        stmt = select(Firmware).order_by(Firmware.created_at.asc())
        if firmware_id is not None:
            stmt = stmt.where(Firmware.id == firmware_id)
        if limit is not None:
            stmt = stmt.limit(limit)

        firmware_rows = (await outer_db.execute(stmt)).scalars().all()

    if not firmware_rows:
        print("no firmware in DB")
        return summary

    if dry_run:
        print("=== DRY RUN — no writes ===")
    print(f"processing {len(firmware_rows)} firmware row(s)")
    print(
        f"  {'id':<8}  {'filename':<56} "
        f"{'roots':>5}  {'blobs before -> after':<22}  "
        f"{'delta':>5}  {'cves':<6}  status"
    )

    for fw in firmware_rows:
        # Per-firmware session — the detector + matcher own independent
        # transactions so a crash on firmware N doesn't poison N+1.
        async with async_session_factory() as db:
            # Re-fetch inside this session so SQLAlchemy tracks mutations.
            fresh = (
                await db.execute(
                    select(Firmware).where(Firmware.id == fw.id)
                )
            ).scalar_one_or_none()
            if fresh is None:
                logger.warning("firmware %s vanished mid-backfill", fw.id)
                continue
            try:
                result = await backfill_one(fresh, db, dry_run=dry_run)
            except Exception as exc:  # noqa: BLE001
                logger.exception("unexpected error on firmware_id=%s", fw.id)
                await db.rollback()
                result = FirmwareResult(
                    firmware_id=fw.id,
                    filename=fw.original_filename,
                    roots_count=0,
                    blobs_before=0,
                    blobs_after=0,
                    cve_matches=0,
                    status="error",
                    note=f"unexpected: {type(exc).__name__}: {exc}"[:240],
                )
            else:
                if not dry_run:
                    await db.commit()

        summary.results.append(result)
        if result.status == "ok":
            summary.processed += 1
            summary.total_delta_blobs += result.blobs_delta
            summary.total_cve_matches += result.cve_matches
        elif result.status == "skipped":
            summary.skipped += 1
        elif result.status == "error":
            summary.errored += 1
        _emit_row(result)

    return summary


def _emit_summary(summary: BackfillSummary, dry_run: bool) -> None:
    print()
    marker = "DRY RUN" if dry_run else "backfill"
    print(
        f"{marker} complete: "
        f"{summary.processed} processed, "
        f"{summary.skipped} skipped, "
        f"{summary.errored} errored, "
        f"+{summary.total_delta_blobs} total blobs, "
        f"+{summary.total_cve_matches} CVE matches"
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Recompute detection_roots but do not run detector / CVE matcher.",
    )
    parser.add_argument(
        "--firmware-id",
        type=str,
        default=None,
        help="Process only this firmware UUID.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N firmware rows (useful for smoke tests).",
    )
    return parser.parse_args(argv)


async def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
    )
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    firmware_id: uuid.UUID | None = None
    if args.firmware_id:
        try:
            firmware_id = uuid.UUID(args.firmware_id)
        except ValueError:
            print(f"invalid firmware UUID: {args.firmware_id}", file=sys.stderr)
            return 2

    summary = await run_backfill(
        dry_run=args.dry_run,
        firmware_id=firmware_id,
        limit=args.limit,
    )
    _emit_summary(summary, args.dry_run)
    return 0 if summary.errored == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
