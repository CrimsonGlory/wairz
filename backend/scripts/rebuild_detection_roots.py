"""Rebuild ``device_metadata['detection_roots']`` for one or more firmware rows.

Usage (inside the worker container):
    /app/.venv/bin/python /app/scripts/rebuild_detection_roots.py <firmware_uuid> [<firmware_uuid>...]

Use cases:
    * Issue #20 (2026-05-13): the ``_compute_roots_sync`` heuristic was
      extended to collect all rootfs candidates from unblob's nested
      ``_extract`` chain. Existing Moto firmware rows have a stale
      single-entry ``detection_roots`` JSONB — running this script
      replaces it with the freshly-computed multi-candidate list.
    * Any future ``firmware_paths`` heuristic change that warrants a
      backfill without re-extraction.

No file movement happens — the on-disk extraction is unchanged. Only the
JSONB cache column is recomputed and committed.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import uuid

from sqlalchemy import select

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import (
    get_detection_roots,
    invalidate_detection_roots,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("rebuild-detection-roots")


async def _rebuild_one(firmware_id: uuid.UUID) -> None:
    async with async_session_factory() as db:
        row = (
            await db.execute(select(Firmware).where(Firmware.id == firmware_id))
        ).scalar_one_or_none()
        if row is None:
            log.warning("firmware %s not found in DB", firmware_id)
            return
        if not row.extracted_path:
            log.warning(
                "firmware %s has no extracted_path; skipping",
                firmware_id,
            )
            return

        # Invalidate stale cache + recompute from disk.
        await invalidate_detection_roots(row, db)
        roots = await get_detection_roots(row, db=db, use_cache=False)
        await db.commit()

        log.info(
            "firmware %s (%s): %d roots",
            firmware_id,
            row.original_filename,
            len(roots),
        )
        for r in roots[:5]:
            log.info("    %s", r)
        if len(roots) > 5:
            log.info("    ... +%d more", len(roots) - 5)


async def _main(args: list[str]) -> int:
    if not args:
        log.error(
            "usage: rebuild_detection_roots.py <firmware_uuid> [<firmware_uuid>...]"
        )
        return 2
    for arg in args:
        try:
            fid = uuid.UUID(arg)
        except ValueError:
            log.error("not a valid UUID: %s", arg)
            continue
        await _rebuild_one(fid)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
