"""Ghidra-based binary analysis service with full-binary caching.

Runs Ghidra once per binary via AnalyzeBinary.java to extract all data
(functions, imports, exports, xrefs, disassembly, decompilation, binary_info),
stores everything in PostgreSQL analysis_cache, and serves subsequent queries
instantly from the DB.

Falls back to DecompileFunction.java for single-function decompilation requests
on functions not covered in the initial batch (top 200 by size).

Module-level API replaced the previous ``GhidraAnalysisCache`` singleton
(Q4, 2026-04-19) — callers use ``ghidra_service.get_functions(...)`` etc.
directly. Module-scope ``_analysis_locks`` + ``_lock`` preserve the
concurrency guard so only one Ghidra process runs per binary SHA.
"""

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import pathlib
import tempfile
import time
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.services import _cache
from app.utils.hashing import compute_file_sha256

logger = logging.getLogger(__name__)

# Markers used by both AnalyzeBinary.java and DecompileFunction.java
_START_MARKER = "===ANALYSIS_START==="
_END_MARKER = "===ANALYSIS_END==="
_DECOMPILE_START = "===DECOMPILE_START==="
_DECOMPILE_END = "===DECOMPILE_END==="

# Architecture mapping: Ghidra processor names → common short names
_ARCH_MAP = {
    "ARM": "arm",
    "AARCH64": "aarch64",
    "MIPS": "mips",
    "x86": "x86",
    "x86-64": "x86",
    "PowerPC": "ppc",
    "sparc": "sparc",
}


_ANALYSIS_LOCK_DIR = pathlib.Path(tempfile.gettempdir()) / "wairz-analysis-locks"


def _acquire_analysis_flock(lock_path: str) -> int:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _release_analysis_flock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.asynccontextmanager
async def _cross_process_analysis_lock(binary_sha256: str):
    """Host-wide exclusive lock keyed by binary sha256.

    The asyncio.Event guard only dedupes coroutines within a single Python
    process. Each MCP client connection spawns its own wairz-mcp process, so
    concurrent connections can otherwise each decide "no cache yet, I'll run
    Ghidra" and spawn duplicate analyses against the same binary — observed
    in the wild as 7 parallel Ghidras on a 7 MB binary, none finishing.
    fcntl.flock serializes them at the OS level and is released automatically
    if a process crashes, so failed analyses don't leave the binary blocked.
    """
    _ANALYSIS_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = str(_ANALYSIS_LOCK_DIR / f"{binary_sha256}.lock")
    fd = await asyncio.to_thread(_acquire_analysis_flock, lock_path)
    try:
        yield
    finally:
        await asyncio.to_thread(_release_analysis_flock, fd)


def _map_architecture(ghidra_arch: str) -> str:
    """Map Ghidra architecture string to common short name."""
    for key, val in _ARCH_MAP.items():
        if key.lower() in ghidra_arch.lower():
            return val
    return ghidra_arch.lower()


def _parse_analysis_output(raw_output: str) -> dict | None:
    """Extract JSON from Ghidra AnalyzeBinary.java output between markers.

    Ghidra wraps println() output with log prefixes like:
      INFO  AnalyzeBinary.java> {json...} (GhidraScript)
    So we extract the outermost { ... } between the markers.
    """
    start = raw_output.find(_START_MARKER)
    end = raw_output.find(_END_MARKER)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_START_MARKER):end].strip()
    if not content:
        return None

    # Find the outermost JSON object braces within the content
    json_start = content.find("{")
    json_end = content.rfind("}")
    if json_start == -1 or json_end == -1 or json_end <= json_start:
        logger.error("No JSON object found between analysis markers")
        return None

    json_str = content[json_start:json_end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Ghidra analysis JSON: %s", exc)
        return None


def _parse_decompile_output(raw_output: str) -> str | None:
    """Extract decompiled code from DecompileFunction.java output between markers."""
    start = raw_output.find(_DECOMPILE_START)
    end = raw_output.find(_DECOMPILE_END)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_DECOMPILE_START):end].strip()
    return content if content else None


def _build_analyze_command(
    binary_path: str,
    script_name: str,
    project_dir: str,
    script_args: list[str] | None = None,
    *,
    ghidra_import_params: dict | None = None,
) -> list[str]:
    """Build a Ghidra analyzeHeadless command.

    ``ghidra_import_params`` (CLAUDE.md Rule #52 — dormant infrastructure
    unlock 2026-05-19) optionally pins the loader / processor / base
    address for raw bare-metal binaries that Ghidra's auto-detect can't
    handle. Mirrors the dict shape declared in chip_family YAML manifests
    + the half-built outputs of parsers/{mediatek_tinysys,atf,geniezone}.

    Recognised keys:
      - ``processor``: Ghidra processor string (e.g. ``ARM:LE:32:Cortex``)
      - ``loader``: typically ``BinaryLoader`` for raw .bin
      - ``base_addr``: integer load address
      - ``load_offset_in_file`` / ``load_length``: optional sub-region load
      - ``cspec``: optional calling-convention selector

    Unknown keys are silently ignored so future schema additions don't
    break the build path.
    """
    settings = get_settings()
    ghidra_path = settings.ghidra_path
    scripts_path = settings.ghidra_scripts_path

    analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    project_name = f"wairz_{uuid.uuid4().hex[:8]}"

    cmd = [
        analyze_headless,
        project_dir,
        project_name,
        "-import",
        binary_path,
        "-scriptPath",
        scripts_path,
        "-postScript",
        script_name,
    ]

    if ghidra_import_params:
        if (proc := ghidra_import_params.get("processor")):
            cmd.extend(["-processor", str(proc)])
        if (loader := ghidra_import_params.get("loader")):
            cmd.extend(["-loader", str(loader)])
        if (base := ghidra_import_params.get("base_addr")) is not None:
            cmd.extend(["-loader-baseAddr", f"0x{int(base):X}"])
        if (offset := ghidra_import_params.get("load_offset_in_file")) is not None:
            cmd.extend(["-loader-fileOffset", str(int(offset))])
        if (length := ghidra_import_params.get("load_length")) is not None:
            cmd.extend(["-loader-length", str(int(length))])
        if (cspec := ghidra_import_params.get("cspec")):
            cmd.extend(["-cspec", str(cspec)])

    if script_args:
        cmd.extend(script_args)

    cmd.append("-deleteProject")
    return cmd


async def run_ghidra_subprocess(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None = None,
) -> str:
    """Run a Ghidra headless script and return the raw stdout."""
    settings = get_settings()

    with tempfile.TemporaryDirectory(prefix="ghidra_") as project_dir:
        cmd = _build_analyze_command(binary_path, script_name, project_dir, script_args)

        logger.info(
            "Running Ghidra %s on %s",
            script_name,
            os.path.basename(binary_path),
        )

        # Capture stdout/stderr to tempfiles rather than asyncio PIPEs.
        # AnalyzeBinary.java for a multi-MB binary can emit hundreds of MB
        # of println output (per-function decompiles, status logs); with
        # PIPE + communicate(), the kernel 64 KB pipe buffer fills before
        # asyncio drains it on this workload and Ghidra deadlocks blocked
        # in a FileOutputStream.write syscall. Tempfiles let the kernel
        # buffer arbitrary output with no possibility of deadlock; we
        # read them once Ghidra has exited.
        with tempfile.TemporaryFile(prefix="ghidra-stdout-") as stdout_f, \
             tempfile.TemporaryFile(prefix="ghidra-stderr-") as stderr_f:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=stdout_f,
                    stderr=stderr_f,
                )
            except FileNotFoundError:
                raise RuntimeError(
                    f"Ghidra not found at {cmd[0]}. "
                    "Install Ghidra or set GHIDRA_PATH in .env."
                )

            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=settings.ghidra_timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(
                    f"Ghidra analysis timed out after {settings.ghidra_timeout}s"
                )

            stdout_f.seek(0)
            stderr_f.seek(0)
            stdout = stdout_f.read()
            stderr = stderr_f.read()

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if process.returncode != 0:
            # Ghidra often returns non-zero but still produces output.
            # Check for any known output marker before declaring failure.
            known_markers = (
                _START_MARKER, _DECOMPILE_START,
                "===STRING_REFS_START===", "===TAINT_START===",
                "===STACK_LAYOUT_START===", "===GLOBAL_LAYOUT_START===",
            )
            has_output = any(m in stdout_text for m in known_markers)
            if not has_output:
                logger.error(
                    "Ghidra failed (rc=%d): %s",
                    process.returncode,
                    stderr_text[-500:],
                )
                raise RuntimeError(
                    f"Ghidra analysis failed (exit code {process.returncode})"
                )

        return stdout_text


# ---------------------------------------------------------------------------
# Concurrency guard: one Ghidra full-analysis per (binary_sha256) at a time.
# Locks are created lazily (on first use) so module import does not require
# a running event loop.
# ---------------------------------------------------------------------------

_analysis_locks: dict[str, asyncio.Event] = {}
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Lazily construct the module-level asyncio.Lock on first call."""
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


# ---------------------------------------------------------------------------
# Low-level cache + SHA helpers
# ---------------------------------------------------------------------------


async def _get_binary_sha256(binary_path: str) -> str:
    """Compute SHA256 in a thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, compute_file_sha256, binary_path)


async def get_binary_sha256(binary_path: str) -> str:
    """Public wrapper: compute SHA256 in a thread."""
    return await _get_binary_sha256(binary_path)


async def _is_analysis_complete(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> bool:
    """Check if full analysis has been completed for this binary."""
    return await _cache.exists_cached(
        db,
        firmware_id,
        "ghidra_full_analysis",
        binary_sha256=binary_sha256,
    )


async def get_cached(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    operation: str,
    db: AsyncSession,
) -> dict | None:
    """Get a cached result by operation key (public API)."""
    return await _get_cached(firmware_id, binary_sha256, operation, db)


async def _get_cached(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    operation: str,
    db: AsyncSession,
) -> dict | None:
    """Get a cached result by operation key."""
    return await _cache.get_cached(
        db, firmware_id, operation, binary_sha256=binary_sha256,
    )


async def store_cached(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    result_data: dict,
    db: AsyncSession,
) -> None:
    """Store a result in the cache (public API)."""
    await _store_cached(
        firmware_id, binary_path, binary_sha256, operation, result_data, db,
    )


async def _store_cached(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    result_data: dict,
    db: AsyncSession,
) -> None:
    """Store a result in the cache (delete-then-insert upsert)."""
    await _cache.store_cached(
        db,
        firmware_id,
        operation,
        result_data,
        binary_sha256=binary_sha256,
        binary_path=binary_path,
    )


async def _run_full_analysis(
    binary_path: str,
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> None:
    """Run AnalyzeBinary.java and store all results in DB."""
    raw_output = await run_ghidra_subprocess(binary_path, "AnalyzeBinary.java")

    data = _parse_analysis_output(raw_output)
    if data is None:
        raise RuntimeError(
            "Ghidra full analysis produced no parseable output. "
            "Check Ghidra installation and binary compatibility."
        )

    # Store each section as a separate cache entry
    sections = [
        ("functions", "functions"),
        ("imports", "imports"),
        ("exports", "exports"),
        ("binary_info", "binary_info"),
        ("xrefs", "xrefs"),
        ("main_detection", "main_detection"),
    ]

    for key, operation in sections:
        if key in data:
            await _store_cached(
                firmware_id, binary_path, binary_sha256,
                operation, {key: data[key]}, db,
            )

    # Store disassembly per function
    disassembly = data.get("disassembly", {})
    for func_name, disasm_text in disassembly.items():
        await _store_cached(
            firmware_id, binary_path, binary_sha256,
            f"disasm:{func_name}",
            {"disassembly": disasm_text},
            db,
        )

    # Store decompilation per function
    decompilation = data.get("decompilation", {})
    for func_name, code in decompilation.items():
        await _store_cached(
            firmware_id, binary_path, binary_sha256,
            f"decompile:{func_name}",
            {"decompiled_code": code},
            db,
        )

    # Store sentinel marking analysis as complete
    function_count = len(data.get("functions", []))
    decompile_count = len(decompilation)
    await _store_cached(
        firmware_id, binary_path, binary_sha256,
        "ghidra_full_analysis",
        {
            "status": "complete",
            "function_count": function_count,
            "decompiled_count": decompile_count,
        },
        db,
    )

    logger.info(
        "Ghidra full analysis complete for %s: %d functions, %d decompiled",
        os.path.basename(binary_path),
        function_count,
        decompile_count,
    )


async def ensure_analysis(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Ensure full analysis has been run for this binary. Returns binary_sha256.

    Uses a concurrency guard so only one Ghidra process runs per binary.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    binary_sha256 = await _get_binary_sha256(binary_path)

    # Fast path: already analyzed
    if await _is_analysis_complete(firmware_id, binary_sha256, db):
        return binary_sha256

    # Within-process concurrency guard: dedupe parallel coroutines
    should_analyze = False
    lock = _get_lock()
    async with lock:
        event = _analysis_locks.get(binary_sha256)
        if event is not None:
            # Another coroutine is already analyzing this binary — wait for it
            pass
        else:
            # We're the leader — create the event and do the analysis
            event = asyncio.Event()
            _analysis_locks[binary_sha256] = event
            should_analyze = True

    if not should_analyze:
        # Wait for the leader coroutine to finish
        await event.wait()
        return binary_sha256

    # We're responsible for running the analysis. Wrap in an OS-level flock
    # to dedupe across multiple wairz-mcp processes (each MCP connection is
    # a separate process; asyncio.Event only guards within one process).
    try:
        async with _cross_process_analysis_lock(binary_sha256):
            # Re-check under the cross-process lock with a fresh session so
            # we see rows committed by a sibling process that just finished.
            async with async_session_factory() as recheck_db:
                if not await _is_analysis_complete(firmware_id, binary_sha256, recheck_db):
                    async with async_session_factory() as analysis_db:
                        await _run_full_analysis(
                            binary_path, firmware_id, binary_sha256, analysis_db,
                        )
                        await analysis_db.commit()
    finally:
        async with lock:
            _analysis_locks.pop(binary_sha256, None)
        event.set()

    return binary_sha256


# ---------------------------------------------------------------------------
# Public per-binary query API (all cache-backed)
# ---------------------------------------------------------------------------


async def get_functions_if_cached(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Like get_functions but never triggers Ghidra analysis.

    Use this when function metadata is a nice-to-have annotation (e.g.
    mapping byte-scan offsets to enclosing functions) rather than the
    primary product of the call. Returns [] if the binary has not been
    analyzed yet.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        return []
    binary_sha256 = await _get_binary_sha256(binary_path)
    if not await _is_analysis_complete(firmware_id, binary_sha256, db):
        return []
    cached = await _get_cached(firmware_id, binary_sha256, "functions", db)
    return cached.get("functions", []) if cached else []


async def get_run_status(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> dict | None:
    """Read the most recent background-analysis run row.

    Returned dict has keys: status ("running"|"complete"|"failed"),
    started_at (epoch seconds), optional finished_at, optional pid,
    optional error. None means no run has been kicked off via
    start_binary_analysis.
    """
    return await _get_cached(firmware_id, binary_sha256, "ghidra_analysis_run", db)


async def mark_run_started(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    pid: int,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "running", "started_at": time.time(), "pid": pid},
        db,
    )


async def mark_run_complete(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "complete", "finished_at": time.time()},
        db,
    )


async def mark_run_failed(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    error: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "failed", "finished_at": time.time(), "error": error[:2000]},
        db,
    )


async def get_functions(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get function list for a binary (sorted by size desc)."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "functions", db)
    if cached:
        functions = cached.get("functions", [])
        # Apply main detection: if main was detected, update the list
        main_cached = await _get_cached(
            firmware_id, binary_sha256, "main_detection", db,
        )
        if main_cached:
            main_info = main_cached.get("main_detection", {})
            if main_info.get("found") and main_info.get("method") == "libc_start_main_arg":
                main_addr = main_info.get("address")
                for func in functions:
                    if func.get("address") == main_addr and func["name"].startswith("FUN_"):
                        func["name"] = "main"
                        break
        return functions
    return []


async def get_disassembly(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
    max_instructions: int = 200,
) -> str:
    """Get disassembly for a function."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(
        firmware_id, binary_sha256, f"disasm:{function_name}", db,
    )
    if cached:
        disasm = cached.get("disassembly", "")
        # Apply max_instructions limit
        lines = disasm.split("\n")
        if len(lines) > max_instructions:
            lines = lines[:max_instructions]
            lines.append(f"... (truncated at {max_instructions} instructions)")
        return "\n".join(lines)

    return f"No disassembly found for function '{function_name}'. Use list_functions to see available function names."


async def get_imports(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get import list for a binary."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "imports", db)
    if cached:
        return cached.get("imports", [])
    return []


async def get_exports(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get export list for a binary."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "exports", db)
    if cached:
        return cached.get("exports", [])
    return []


async def get_xrefs_to(
    binary_path: str,
    target: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get cross-references to a function/symbol.

    First checks for direct 'to' xrefs under the target name. If none
    found (common for imported symbols like doSystemCmd, system, etc.),
    performs a reverse scan of all functions' outgoing ('from') xrefs to
    find callers whose 'to_func' matches the target.
    """
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "xrefs", db)
    if not cached:
        return []

    xrefs = cached.get("xrefs", {})

    # Direct lookup
    func_xrefs = xrefs.get(target, {})
    direct_results = func_xrefs.get("to", [])
    if direct_results:
        return direct_results

    # Reverse scan: check all functions' outgoing xrefs for calls to target
    reverse_results: list[dict] = []
    for func_name, func_data in xrefs.items():
        for ref in func_data.get("from", []):
            if ref.get("to_func") == target:
                reverse_results.append({
                    "from": ref.get("from", ref.get("address", "unknown")),
                    "type": ref.get("type", "CALL"),
                    "from_func": func_name,
                })
    return reverse_results


async def get_xrefs_from(
    binary_path: str,
    target: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get cross-references from a function/symbol."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "xrefs", db)
    if cached:
        xrefs = cached.get("xrefs", {})
        func_xrefs = xrefs.get(target, {})
        return func_xrefs.get("from", [])
    return []


async def get_binary_info(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict:
    """Get binary metadata in r2-compatible shape for frontend compatibility.

    Returns a dict shaped like: {"core": {}, "bin": {"arch": ..., "libs": [...]}}
    """
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "binary_info", db)
    if not cached:
        return {}

    info = cached.get("binary_info", {})

    # Map to r2-compatible shape
    arch = _map_architecture(info.get("arch", "unknown"))
    bits = info.get("bits", 0)
    endian = info.get("endian", "unknown")
    fmt = info.get("format", "unknown")
    libs = info.get("libraries", [])
    entry = info.get("entry_point", "unknown")
    compiler = info.get("compiler", "unknown")
    image_base = info.get("image_base", "unknown")

    return {
        "core": {
            "format": fmt,
            "file": binary_path,
        },
        "bin": {
            "file": binary_path,
            "bintype": "elf" if "elf" in fmt.lower() else fmt.lower(),
            "arch": arch,
            "bits": bits,
            "endian": endian,
            "os": "linux",
            "machine": info.get("arch", "unknown"),
            "class": f"ELF{bits}" if "elf" in fmt.lower() else fmt,
            "lang": compiler if compiler != "unknown" else "c",
            "stripped": False,  # Ghidra doesn't report this directly; pyelftools handles it
            "static": len(libs) == 0,
            "libs": libs,
            "entry_point": entry,
            "image_base": image_base,
        },
    }


async def decompile_function(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Decompile a function, using cached results or falling back to single-function Ghidra.

    First tries the full-analysis cache. If the function wasn't in the top 200
    decompiled, falls back to running DecompileFunction.java for that specific function.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    binary_sha256 = await _get_binary_sha256(binary_path)
    operation = f"decompile:{function_name}"

    # Check cache (works for both full-analysis and single-function cache entries)
    cached = await _get_cached(firmware_id, binary_sha256, operation, db)
    if cached:
        code = cached.get("decompiled_code")
        if code:
            logger.info(
                "Cache hit for %s:%s",
                os.path.basename(binary_path),
                function_name,
            )
            return code

    # If full analysis was done but this function wasn't decompiled,
    # fall back to single-function decompilation
    raw_output = await run_ghidra_subprocess(
        binary_path,
        "DecompileFunction.java",
        script_args=[function_name],
    )

    decompiled = _parse_decompile_output(raw_output)
    if decompiled is None:
        if "ERROR: Function" in raw_output and "not found" in raw_output:
            lines = raw_output.split("\n")
            func_lines = [
                line.strip()
                for line in lines
                if line.strip().startswith("  ") and "@" in line
            ]
            suggestion = ""
            if func_lines:
                suggestion = "\n\nAvailable functions:\n" + "\n".join(func_lines[:20])
            return f"Function '{function_name}' not found in binary.{suggestion}"
        return "Decompilation produced no output. The function may be too small or a thunk."

    # Store in cache for future use
    await _store_cached(
        firmware_id, binary_path, binary_sha256, operation,
        {"decompiled_code": decompiled}, db,
    )

    return decompiled
