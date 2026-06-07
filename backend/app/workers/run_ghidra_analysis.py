"""Detached worker that runs a single Ghidra analysis to completion.

Spawned by the start_binary_analysis MCP tool with start_new_session=True
so the analysis is decoupled from the wairz-mcp process lifetime. The
wairz-mcp process returns immediately after kicking us off; we keep
running until Ghidra finishes and the cache rows are persisted, even if
the MCP client disconnects.

Invocation:
    python -m app.workers.run_ghidra_analysis \\
        --firmware-id <uuid> --binary-path <path> --sha256 <hex> \\
        [--import-params '{"processor":"MIPS:LE:32:default","loader":"BinaryLoader","base_addr":2148007936}']

Exits 0 on success, 1 on failure; status is also written to the
ghidra_analysis_run cache row so check_binary_analysis_status can read
it.
"""

import argparse
import asyncio
import json
import logging
import sys
import uuid

from app.config import get_settings
from app.database import async_session_factory
from app.services.ghidra_service import (
    _cross_process_analysis_lock,
    _is_analysis_complete,
    _is_known_format,
    _read_file_magic,
    _run_full_analysis,
    mark_run_complete,
    mark_run_failed,
    resolve_binary_import_params,
)

logger = logging.getLogger(__name__)


async def _resolve_import_params(
    binary_path: str,
    firmware_id: uuid.UUID,
    explicit_params: dict | None,
) -> dict | None:
    """Resolve Ghidra import params for a raw binary.

    Explicit params (from --import-params CLI arg) take priority over the
    rtos_flavor defaults. Returns None when the binary has a known ELF/PE/
    Mach-O header that Ghidra can auto-detect.
    """
    loop = asyncio.get_running_loop()
    magic = await loop.run_in_executor(None, _read_file_magic, binary_path)
    if _is_known_format(magic):
        return None

    # Resolve flavor defaults first — they carry setup_script and other
    # keys the user typically doesn't pass explicitly.
    flavor_params = await resolve_binary_import_params(binary_path, firmware_id)

    if explicit_params:
        # Merge: explicit params override processor/loader/base_addr, but the
        # flavor provides setup_script (and any future ISA-setup keys) as a
        # fallback.  Without this merge, passing explicit params causes the
        # setup_script to be silently dropped and Mips16eSetup.java never runs.
        return {**(flavor_params or {}), **explicit_params}

    return flavor_params


async def _run(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    import_params: dict | None,
) -> int:
    try:
        async with _cross_process_analysis_lock(binary_sha256):
            # Re-check under the cross-process lock — a sibling worker or a
            # synchronous ensure_analysis call may have finished while we waited.
            async with async_session_factory() as recheck_db:
                if await _is_analysis_complete(firmware_id, binary_sha256, recheck_db):
                    async with async_session_factory() as mark_db:
                        await mark_run_complete(
                            firmware_id, binary_path, binary_sha256, mark_db,
                        )
                        await mark_db.commit()
                    return 0

            resolved_params = await _resolve_import_params(
                binary_path, firmware_id, import_params,
            )

            async with async_session_factory() as analysis_db:
                await _run_full_analysis(
                    binary_path, firmware_id, binary_sha256, analysis_db,
                    timeout=get_settings().ghidra_background_analysis_timeout,
                    ghidra_import_params=resolved_params,
                )
                await mark_run_complete(
                    firmware_id, binary_path, binary_sha256, analysis_db,
                )
                await analysis_db.commit()
        return 0
    except Exception as exc:
        logger.exception("Ghidra analysis failed for %s", binary_path)
        async with async_session_factory() as db:
            await mark_run_failed(
                firmware_id, binary_path, binary_sha256, str(exc), db,
            )
            await db.commit()
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--firmware-id", required=True)
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--import-params",
        default=None,
        help=(
            "JSON-encoded Ghidra import params for raw binaries "
            "(processor/loader/base_addr). Overrides rtos_flavor defaults."
        ),
    )
    args = parser.parse_args()

    import_params: dict | None = None
    if args.import_params:
        try:
            import_params = json.loads(args.import_params)
        except json.JSONDecodeError as exc:
            print(f"ERROR: invalid --import-params JSON: {exc}", file=sys.stderr)
            sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    rc = asyncio.run(_run(
        uuid.UUID(args.firmware_id), args.binary_path, args.sha256, import_params,
    ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
