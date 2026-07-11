"""Detached worker that decompiles a single function to completion.

Spawned by the start_function_decompile MCP tool with start_new_session=
True so the decompile is decoupled from the wairz-mcp process lifetime.
Big handler functions in real-world daemons routinely exceed the
synchronous 580s budget; this worker gets 30 minutes, which is enough
for any single function that's still worth waiting on.

Invocation:
    python -m app.workers.run_function_decompile \
        --firmware-id <uuid> --binary-path <path> \
        --sha256 <hex> --function-name <name>

Exits 0 on success, 1 on failure; status is written to the
function_decompile_run:<name> cache row so check_function_decompile_status
can read it. The decompiled code itself is written to the existing
decompile:<name> cache row, so a follow-up decompile_function MCP call
returns instantly.
"""

import argparse
import asyncio
import hashlib
import logging
import sys
import uuid

from app.config import get_settings
from app.database import async_session_factory
from app.services import ghidra_service
from app.services.ghidra_service import (
    _cross_process_analysis_lock,
    _parse_decompile_output,
    _run_ghidra_local,
)

logger = logging.getLogger(__name__)


def get_analysis_cache():
    """Return the cache object used for decompile result storage.

    Tests monkeypatch this to inject a fake cache; production returns the
    ghidra_service module (which exposes _get_cached / _store_cached /
    mark_function_run_* at module scope).
    """
    return ghidra_service


def _lock_key(binary_sha256: str, function_name: str) -> str:
    """Stable, path-safe lock key per (binary, function).

    Function names can contain characters illegal in filenames (e.g.
    'operator()', mangled C++ names), so hash them rather than embed.
    """
    h = hashlib.sha1(
        f"{binary_sha256}:{function_name}".encode(),
    ).hexdigest()
    return f"decompile-{h}"


async def _run(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    function_name: str,
) -> int:
    cache_op = f"decompile:{function_name}"
    cache = get_analysis_cache()

    try:
        async with _cross_process_analysis_lock(
            _lock_key(binary_sha256, function_name),
        ):
            # Re-check under lock — a sibling worker may have finished
            # while we waited.
            async with async_session_factory() as recheck_db:
                cached = await cache._get_cached(
                    firmware_id, binary_sha256, cache_op, recheck_db,
                )
                if cached and cached.get("decompiled_code"):
                    await cache.mark_function_run_complete(
                        firmware_id, binary_path, binary_sha256,
                        function_name, recheck_db,
                    )
                    await recheck_db.commit()
                    return 0

            # Run Ghidra in-process on this host. Do NOT call
            # run_ghidra_subprocess — in cloud mode that re-dispatches to
            # Batch, and this worker is already ON the compute box.
            raw_output = await _run_ghidra_local(
                binary_path,
                "DecompileFunction.java",
                [function_name],
                get_settings().ghidra_background_decompile_timeout,
                binary_sha256,
            )
            decompiled = _parse_decompile_output(raw_output)

            async with async_session_factory() as result_db:
                if decompiled is None:
                    # Distinguish "function not found" from "no output"
                    if "ERROR: Function" in raw_output and "not found" in raw_output:
                        msg = f"Function '{function_name}' not found in binary"
                    else:
                        msg = (
                            "DecompileFunction.java produced no parseable "
                            "output (function may be a thunk or too small)"
                        )
                    await cache.mark_function_run_failed(
                        firmware_id, binary_path, binary_sha256,
                        function_name, msg, result_db,
                    )
                    await result_db.commit()
                    return 1

                await cache._store_cached(
                    firmware_id, binary_path, binary_sha256, cache_op,
                    {"decompiled_code": decompiled}, result_db,
                )
                await cache.mark_function_run_complete(
                    firmware_id, binary_path, binary_sha256,
                    function_name, result_db,
                )
                await result_db.commit()
        return 0
    except Exception as exc:
        logger.exception(
            "Function decompile failed for %s:%s", binary_path, function_name,
        )
        async with async_session_factory() as db:
            await cache.mark_function_run_failed(
                firmware_id, binary_path, binary_sha256, function_name,
                str(exc), db,
            )
            await db.commit()
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--firmware-id", required=True)
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--function-name", required=True)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    rc = asyncio.run(_run(
        uuid.UUID(args.firmware_id),
        args.binary_path,
        args.sha256,
        args.function_name,
    ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
