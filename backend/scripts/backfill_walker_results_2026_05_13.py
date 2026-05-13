#!/usr/bin/env python3
"""One-off backfill: re-fire Rule #47 walker auto-triggers on pre-bridge firmware rows.

Closes the Rule #47 walker-bridge gap for rows that landed in ``upload_stage='ready'``
BEFORE commit ``5f3d195`` wired ``_fire_walker_auto_triggers`` into
``_post_process_pipeline``. Those rows have populated ``extracted_path`` +
``device_metadata['detection_roots']`` but every ``*_walk_result`` JSONB column
is NULL — no walker ever fired against the extraction. New uploads (post-5f3d195)
auto-fire the 22-walker chain via the bridge; this script back-fills the existing
ones.

Per Rule #39, each safe-runner owns its own ``async_session_factory()`` session,
swallows exceptions silently, and does NOT mutate ``firmware.<op>_walk_status`` —
the JSONB ``*_walk_result`` column is the truthful signal of walker completion.

Usage::

    # Default — back-fill every row that has registry_hive_walk_result NULL.
    docker compose exec -T worker /app/.venv/bin/python \\
        scripts/backfill_walker_results_2026_05_13.py

    # Dry-run — enumerate candidates without firing walkers.
    docker compose exec -T worker /app/.venv/bin/python \\
        scripts/backfill_walker_results_2026_05_13.py --dry-run

    # Target one specific firmware (ignores the default filter).
    docker compose exec -T worker /app/.venv/bin/python \\
        scripts/backfill_walker_results_2026_05_13.py \\
        --firmware-id 640cda1f-fd00-422b-9bea-24fc7b5c7a37

    # Smoke a small batch first before unleashing on everything.
    docker compose exec -T worker /app/.venv/bin/python \\
        scripts/backfill_walker_results_2026_05_13.py --limit 3

Idempotent — safe to re-run. The default filter excludes rows whose
``registry_hive_walk_result`` is already populated; ``--firmware-id`` bypasses
the filter for explicit re-walks.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_service import _fire_walker_auto_triggers

logger = logging.getLogger("backfill_walker_results")

# Every JSONB result column the 22-walker chain stamps. Matches
# WALKER_AUTO_TRIGGERS in app.workers.walker_registry; used to count
# before/after coverage per row.
WALKER_RESULT_COLUMNS = (
    "registry_hive_walk_result",
    "evtx_walk_result",
    "appcompat_walk_result",
    "bcd_walk_result",
    "dpapi_walk_result",
    "efs_walk_result",
    "esp_walk_result",
    "etl_walk_result",
    "lnk_walk_result",
    "mbr_vbr_walk_result",
    "mft_walk_result",
    "prefetch_walk_result",
    "scheduled_task_walk_result",
    "sdb_walk_result",
    "srum_walk_result",
    "usnjrnl_walk_result",
    "wmi_walk_result",
    "container_walk_result",
    "journald_walk_result",
    "persistence_walk_result",
    "systemd_walk_result",
)


@dataclass
class FirmwareResult:
    """Per-firmware backfill outcome."""

    firmware_id: uuid.UUID
    filename: str | None
    results_before: int
    results_after: int
    elapsed_s: float
    status: str  # ok | skipped | error
    note: str = ""

    @property
    def delta(self) -> int:
        return self.results_after - self.results_before


@dataclass
class BackfillSummary:
    """Aggregate numbers for end-of-run logging."""

    processed: int = 0
    skipped: int = 0
    errored: int = 0
    total_new_results: int = 0
    results: list[FirmwareResult] = field(default_factory=list)


def _count_results(firmware: Firmware) -> int:
    """Count how many walker JSONB result columns are populated on this row."""
    return sum(
        1
        for col in WALKER_RESULT_COLUMNS
        if getattr(firmware, col, None) is not None
    )


async def backfill_one(
    firmware: Firmware,
    db: AsyncSession,
    *,
    dry_run: bool = False,
) -> FirmwareResult:
    """Fire every walker safe-runner for one firmware row.

    Each safe-runner owns its own session per Rule #39, so we do NOT pass
    ``db`` into ``_fire_walker_auto_triggers``. The outer ``db`` here is
    used to re-fetch the row after walkers complete so we can count the
    fresh JSONB result columns.
    """
    filename = firmware.original_filename
    firmware_id = firmware.id
    extracted = firmware.extracted_path

    if not extracted:
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            results_before=0,
            results_after=0,
            elapsed_s=0.0,
            status="skipped",
            note="no extraction",
        )

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isdir, extracted):
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            results_before=0,
            results_after=0,
            elapsed_s=0.0,
            status="skipped",
            note="extraction missing on disk",
        )

    results_before = _count_results(firmware)

    if dry_run:
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            results_before=results_before,
            results_after=results_before,
            elapsed_s=0.0,
            status="ok",
            note="dry-run (no walkers fired)",
        )

    t0 = time.monotonic()
    try:
        await _fire_walker_auto_triggers(firmware_id)
    except Exception as exc:  # noqa: BLE001 — outer guard mirrors Rule #39 shape
        logger.exception("walker-bridge failed for firmware_id=%s", firmware_id)
        return FirmwareResult(
            firmware_id=firmware_id,
            filename=filename,
            results_before=results_before,
            results_after=results_before,
            elapsed_s=time.monotonic() - t0,
            status="error",
            note=f"bridge raised: {type(exc).__name__}: {exc}"[:240],
        )
    elapsed = time.monotonic() - t0

    # Walkers wrote to fresh sessions; our copy is stale. Per Rule #32,
    # prefer an explicit re-SELECT over db.refresh() — this is the rare
    # case where refresh() is NOT a no-op (different process / session
    # updated the row), and the explicit query documents intent.
    # MUST expire the row first or SQLAlchemy's identity map returns the
    # cached pre-walk instance.
    db.expire(firmware)
    reloaded = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one()
    results_after = _count_results(reloaded)

    return FirmwareResult(
        firmware_id=firmware_id,
        filename=filename,
        results_before=results_before,
        results_after=results_after,
        elapsed_s=elapsed,
        status="ok",
    )


def _emit_row(r: FirmwareResult) -> None:
    display_name = (r.filename or "(unknown)")[:48]
    print(
        f"  {str(r.firmware_id)[:8]}  {display_name:<48}  "
        f"results {r.results_before:>2} -> {r.results_after:>2}  "
        f"delta {r.delta:+3d}  "
        f"{r.elapsed_s:>6.1f}s  "
        f"[{r.status}]  {r.note}",
        flush=True,
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
        stmt = (
            select(Firmware)
            .where(Firmware.upload_stage == "ready")
            .order_by(Firmware.created_at.asc())
        )
        if firmware_id is not None:
            # Explicit firmware target — bypass the default filter so
            # operator-driven re-walks work even on rows that already
            # have results stamped.
            stmt = select(Firmware).where(Firmware.id == firmware_id)
        else:
            # Default filter: rows that have never had their registry
            # walker fire. registry_hive_walk_result is a representative
            # marker because it's the first walker registered AND it's
            # cheap (one disk scan + a regipy probe per detection root).
            stmt = stmt.where(Firmware.registry_hive_walk_result.is_(None))
            stmt = stmt.where(Firmware.extracted_path.is_not(None))
        if limit is not None:
            stmt = stmt.limit(limit)

        firmware_rows = (await outer_db.execute(stmt)).scalars().all()

    if not firmware_rows:
        print("no firmware rows match the backfill filter")
        return summary

    if dry_run:
        print("=== DRY RUN — no walkers fired ===")
    print(
        f"processing {len(firmware_rows)} firmware row(s) at "
        f"{datetime.now(UTC).isoformat()}"
    )
    print(
        f"  {'id':<8}  {'filename':<48}  "
        f"{'results':<12}  "
        f"{'delta':<5}  "
        f"{'elapsed':>7}  status"
    )

    for fw in firmware_rows:
        async with async_session_factory() as db:
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
            except Exception as exc:  # noqa: BLE001 — outer guard
                logger.exception("unexpected error on firmware_id=%s", fw.id)
                await db.rollback()
                result = FirmwareResult(
                    firmware_id=fw.id,
                    filename=fw.original_filename,
                    results_before=0,
                    results_after=0,
                    elapsed_s=0.0,
                    status="error",
                    note=f"unexpected: {type(exc).__name__}: {exc}"[:240],
                )

        summary.results.append(result)
        if result.status == "ok":
            summary.processed += 1
            summary.total_new_results += max(0, result.delta)
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
        f"{marker} complete at {datetime.now(UTC).isoformat()}: "
        f"{summary.processed} processed, "
        f"{summary.skipped} skipped, "
        f"{summary.errored} errored, "
        f"+{summary.total_new_results} walker result stamps",
        flush=True,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Enumerate candidates without firing walkers.",
    )
    parser.add_argument(
        "--firmware-id",
        type=str,
        default=None,
        help="Process only this firmware UUID (bypasses default filter).",
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
