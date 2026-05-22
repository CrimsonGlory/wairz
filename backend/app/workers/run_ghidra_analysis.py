"""Detached worker that runs a single Ghidra analysis to completion.

Spawned by the start_binary_analysis MCP tool with start_new_session=True
so the analysis is decoupled from the wairz-mcp process lifetime. The
wairz-mcp process returns immediately after kicking us off; we keep
running until Ghidra finishes and the cache rows are persisted, even if
the MCP client disconnects.

Invocation:
    python -m app.workers.run_ghidra_analysis \\
        --firmware-id <uuid> --binary-path <path> --sha256 <hex>

Exits 0 on success, 1 on failure; status is also written to the
ghidra_analysis_run cache row so check_binary_analysis_status can read
it.
"""

import argparse
import asyncio
import logging
import sys
import uuid

from app.database import async_session_factory
from app.services.ghidra_service import (
    _cross_process_analysis_lock,
    get_analysis_cache,
)

logger = logging.getLogger(__name__)


async def _run(
    firmware_id: uuid.UUID, binary_path: str, binary_sha256: str,
) -> int:
    cache = get_analysis_cache()

    try:
        async with _cross_process_analysis_lock(binary_sha256):
            # Re-check under lock — a sibling worker (or a synchronous
            # ensure_analysis call) may have finished while we waited.
            async with async_session_factory() as recheck_db:
                if await cache._is_analysis_complete(
                    firmware_id, binary_sha256, recheck_db,
                ):
                    await cache.mark_run_complete(
                        firmware_id, binary_path, binary_sha256, recheck_db,
                    )
                    await recheck_db.commit()
                    return 0

            async with async_session_factory() as analysis_db:
                await cache._run_full_analysis(
                    binary_path, firmware_id, binary_sha256, analysis_db,
                )
                await cache.mark_run_complete(
                    firmware_id, binary_path, binary_sha256, analysis_db,
                )
                await analysis_db.commit()
        return 0
    except Exception as exc:
        logger.exception("Ghidra analysis failed for %s", binary_path)
        async with async_session_factory() as db:
            await cache.mark_run_failed(
                firmware_id, binary_path, binary_sha256, str(exc), db,
            )
            await db.commit()
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--firmware-id", required=True)
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    rc = asyncio.run(_run(
        uuid.UUID(args.firmware_id), args.binary_path, args.sha256,
    ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
