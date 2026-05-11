"""Binary analysis AI tools using Ghidra and pyelftools."""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services import ghidra_service
from app.services.analysis_service import check_binary_protections
from app.services.ghidra_service import decompile_function, run_ghidra_subprocess
from app.utils.sandbox import safe_walk

logger = logging.getLogger(__name__)

# Standard library search paths in firmware filesystems
_STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib32", "/usr/lib32"]

# Markers for FindStringRefs.java output
_STRING_REFS_START = "===STRING_REFS_START==="
_STRING_REFS_END = "===STRING_REFS_END==="

# Markers for TaintAnalysis.java output
_TAINT_START = "===TAINT_START==="
_TAINT_END = "===TAINT_END==="

# Markers for StackLayout.java output
_STACK_LAYOUT_START = "===STACK_LAYOUT_START==="
_STACK_LAYOUT_END = "===STACK_LAYOUT_END==="

# Markers for GlobalLayout.java output
_GLOBAL_LAYOUT_START = "===GLOBAL_LAYOUT_START==="
_GLOBAL_LAYOUT_END = "===GLOBAL_LAYOUT_END==="


def _read_magic_sync(path: str, n: int = 4) -> bytes | None:
    """Read the first `n` bytes of a file. Returns None on OSError.

    Used inside async tool handlers via run_in_executor (Rule #5) for cheap
    one-shot file-magic probes (ELF / PE / etc.).
    """
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return None

# IPC function pairs for cross-binary dataflow analysis
_IPC_PAIRS = {
    "nvram": {
        "writers": ["nvram_set", "nvram_commit", "nvram_bufset"],
        "readers": ["nvram_get", "nvram_safe_get", "nvram_bufget"],
    },
    "config": {
        "writers": ["SetValue", "cfg_set", "config_set", "set_config"],
        "readers": ["GetValue", "cfg_get", "config_get", "get_config"],
    },
    "file": {
        "writers": ["fwrite", "fprintf"],
        "readers": ["fread", "fgets", "fopen"],
    },
}

# Default source/sink functions for taint analysis
_DEFAULT_SOURCES = [
    "websGetVar", "httpGetEnv", "getenv", "recv", "read", "fgets",
    "nvram_get", "nvram_safe_get", "nvram_bufget", "gets",
    "scanf", "fscanf", "sscanf", "recvfrom", "recvmsg",
    "CGI_get_field", "get_cgi", "websGetFormString",
]

_DEFAULT_SINKS = [
    "system", "popen", "execve", "execl", "execlp", "execle",
    "execv", "execvp", "sprintf", "strcpy", "strcat", "strncpy",
    "doSystemCmd", "twsystem", "CsteSystem", "do_system",
    "vsprintf", "fprintf", "printf", "snprintf",
]


def _extract_ghidra_error(raw_output: str, script_name: str) -> str:
    """Extract diagnostic info from Ghidra output when expected markers are missing.

    Looks for ERROR, Exception, Usage, and other diagnostic lines to provide
    actionable error info instead of a generic 'no parseable output' message.
    """
    diagnostic_lines: list[str] = []
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(kw in lower for kw in (
            "error", "exception", "usage:", "not found",
            "invalid", "failed", "timeout", "unable",
        )):
            # Remove Ghidra log prefix if present (e.g. "INFO  Script> ...")
            cleaned = stripped
            for prefix in ("INFO  ", "WARN  ", "ERROR "):
                if cleaned.startswith(prefix):
                    cleaned = cleaned[len(prefix):]
                    break
            if cleaned not in diagnostic_lines:
                diagnostic_lines.append(cleaned)

    if not diagnostic_lines:
        return (
            f"Ghidra {script_name} produced no parseable output. "
            "Possible causes: binary too large (timeout), unsupported format, "
            "or incomplete Ghidra analysis. Try running on a smaller binary first."
        )

    # Cap at 10 lines
    shown = diagnostic_lines[:30]
    result = f"Ghidra {script_name} failed. Diagnostic output:\n\n"
    result += "\n".join(f"  {line}" for line in shown)
    if len(diagnostic_lines) > 30:
        result += f"\n  ... ({len(diagnostic_lines) - 30} more diagnostic lines)"
    return result


async def _handle_list_functions(input: dict, context: ToolContext) -> str:
    """List functions found in a binary, sorted by size (largest first)."""
    path = context.resolve_path(input["binary_path"])
    limit = min(input.get("limit", 100), 500)

    functions = await ghidra_service.get_functions(path, context.firmware_id, context.db)

    if not functions:
        return "No functions found in binary."

    total = len(functions)
    shown = functions[:limit]

    lines = [f"Found {total} function(s) (sorted by size, largest first):", ""]
    for fn in shown:
        name = fn.get("name", "unknown")
        size = fn.get("size", 0)
        address = fn.get("address", "0")
        lines.append(f"  {address}  {size:>6} bytes  {name}")

    if total > limit:
        lines.append("")
        lines.append(
            f"  ... ({total - limit} more functions omitted. "
            f"Use limit={min(total, 500)} to see more.)"
        )

    return "\n".join(lines)


async def _handle_disassemble_function(input: dict, context: ToolContext) -> str:
    """Disassemble a function by name."""
    path = context.resolve_path(input["binary_path"])
    function_name = input["function_name"]
    max_insn = input.get("num_instructions", 100)

    disasm = await ghidra_service.get_disassembly(
        path, function_name, context.firmware_id, context.db, max_insn,
    )

    return f"Disassembly of {function_name}:\n\n{disasm}"


async def _handle_list_imports(input: dict, context: ToolContext) -> str:
    """List imported symbols, grouped by library."""
    path = context.resolve_path(input["binary_path"])

    imports = await ghidra_service.get_imports(path, context.firmware_id, context.db)

    if not imports:
        return "No imports found."

    # Group by library
    by_lib: dict[str, list[str]] = {}
    for imp in imports:
        lib = imp.get("library") or "unknown"
        name = imp.get("name", "unknown")
        by_lib.setdefault(lib, []).append(name)

    lines = [f"Found {len(imports)} import(s):", ""]
    for lib, symbols in sorted(by_lib.items()):
        lines.append(f"  [{lib}]")
        for sym in sorted(symbols):
            lines.append(f"    {sym}")
        lines.append("")

    return "\n".join(lines)


async def _handle_list_exports(input: dict, context: ToolContext) -> str:
    """List exported symbols."""
    path = context.resolve_path(input["binary_path"])

    exports = await ghidra_service.get_exports(path, context.firmware_id, context.db)

    if not exports:
        return "No exports found."

    lines = [f"Found {len(exports)} export(s):", ""]
    for exp in exports:
        name = exp.get("name", "unknown")
        address = exp.get("address", "0")
        lines.append(f"  {address}  {name}")

    return "\n".join(lines)


async def _handle_xrefs_to(input: dict, context: ToolContext) -> str:
    """Get cross-references to an address or symbol."""
    path = context.resolve_path(input["binary_path"])
    target = input["address_or_symbol"]

    xrefs = await ghidra_service.get_xrefs_to(path, target, context.firmware_id, context.db)

    if not xrefs:
        return f"No cross-references to '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) to '{target}':", ""]
    for xref in xrefs:
        from_addr = xref.get("from", "unknown")
        ref_type = xref.get("type", "unknown")
        from_func = xref.get("from_func", "")
        func_info = f"  ({from_func})" if from_func else ""
        lines.append(f"  {from_addr}  [{ref_type}]{func_info}")

    return "\n".join(lines)


async def _handle_xrefs_from(input: dict, context: ToolContext) -> str:
    """Get cross-references from an address or symbol."""
    path = context.resolve_path(input["binary_path"])
    target = input["address_or_symbol"]

    xrefs = await ghidra_service.get_xrefs_from(path, target, context.firmware_id, context.db)

    if not xrefs:
        return f"No cross-references from '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) from '{target}':", ""]
    for xref in xrefs:
        to_addr = xref.get("to", "unknown")
        ref_type = xref.get("type", "unknown")
        to_func = xref.get("to_func", "")
        func_info = f"  ({to_func})" if to_func else ""
        lines.append(f"  {to_addr}  [{ref_type}]{func_info}")

    return "\n".join(lines)


async def _handle_analyze_binary_format(input: dict, context: ToolContext) -> str:
    """Analyze binary format, architecture, linking type, and dependencies using LIEF."""
    path = context.resolve_path(input["binary_path"])

    import asyncio

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: File not found: {input['binary_path']}"

    from app.services.binary_analysis_service import analyze_binary

    info = await loop.run_in_executor(None, analyze_binary, path)

    fmt = info.get("format", "unknown").upper()
    arch = info.get("architecture", "unknown")
    endian = info.get("endianness", "unknown")
    bits = info.get("bits", "unknown")
    is_static = info.get("is_static", False)
    is_pie = info.get("is_pie", False)
    interpreter = info.get("interpreter")
    deps = info.get("dependencies", [])
    entry = info.get("entry_point")
    file_size = info.get("file_size", 0)

    lines = [
        "Binary Format Analysis (LIEF):",
        "",
        f"  Format:       {fmt}",
        f"  Architecture: {arch}",
        f"  Endianness:   {endian}",
        f"  Bits:         {bits}",
        f"  Linking:      {'static' if is_static else 'dynamic'}",
        f"  PIE:          {'yes' if is_pie else 'no'}",
        f"  Entry Point:  {hex(entry) if entry else 'N/A'}",
        f"  File Size:    {file_size:,} bytes",
    ]

    if interpreter:
        lines.append(f"  Interpreter:  {interpreter}")

    if deps:
        lines.append(f"  Dependencies ({len(deps)}):")
        for dep in deps:
            lines.append(f"    - {dep}")

        # Check sysroot availability for standalone emulation (ELF only)
        if fmt == "ELF":
            from app.services.sysroot_service import check_dependencies
            dep_check = check_dependencies(arch or "", deps)
            if dep_check.get("missing"):
                lines.append("")
                lines.append(f"  Sysroot ({dep_check.get('sysroot_path', 'N/A')}):")
                lines.append(f"    Available: {', '.join(dep_check['available']) or 'none'}")
                lines.append(f"    Missing:   {', '.join(dep_check['missing'])}")
            elif dep_check.get("sysroot_path"):
                lines.append("")
                lines.append(f"  Sysroot: All dependencies available at {dep_check['sysroot_path']}")
    elif is_static:
        lines.append("  No shared library dependencies (static binary)")
        lines.append("  Can be emulated directly without a sysroot")

    # PE-specific details via pefile
    if fmt == "PE":
        from app.services.binary_analysis_service import check_pe_protections

        pe_info = await loop.run_in_executor(None, check_pe_protections, path)
        if "error" not in pe_info:
            def _yn(val: object) -> str:
                return "enabled" if val is True else "disabled"

            lines.append("")
            lines.append("  PE Security Characteristics:")
            lines.append(f"    DEP/NX:           {_yn(pe_info.get('dep_nx'))}")
            lines.append(f"    ASLR:             {_yn(pe_info.get('aslr'))}")
            lines.append(f"    SEH:              {_yn(pe_info.get('seh'))}")
            lines.append(f"    CFG:              {_yn(pe_info.get('cfg'))}")
            lines.append(f"    High Entropy VA:  {_yn(pe_info.get('high_entropy_va'))}")
            lines.append(f"    Authenticode:     {_yn(pe_info.get('authenticode'))}")

            sections = pe_info.get("sections", [])
            if sections:
                lines.append("")
                lines.append(f"  Sections ({len(sections)}):")
                for sec in sections:
                    flags = ", ".join(sec.get("flags", []))
                    entropy = sec.get("entropy", 0)
                    lines.append(
                        f"    {sec['name']:<10} vsize={sec['virtual_size']:>8}  "
                        f"raw={sec['raw_size']:>8}  entropy={entropy}  [{flags}]"
                    )

            imports_by_dll = pe_info.get("imports_by_dll", {})
            if imports_by_dll:
                total_funcs = sum(len(v) for v in imports_by_dll.values())
                lines.append("")
                lines.append(f"  Imports ({total_funcs} functions from {len(imports_by_dll)} DLLs):")
                for dll, funcs in sorted(imports_by_dll.items()):
                    lines.append(f"    [{dll}] ({len(funcs)} functions)")
                    for func in funcs[:30]:
                        lines.append(f"      {func}")
                    if len(funcs) > 30:
                        lines.append(f"      ... ({len(funcs) - 30} more)")

            exports = pe_info.get("exports", [])
            if exports:
                lines.append("")
                lines.append(f"  Exports ({len(exports)}):")
                for exp in exports[:50]:
                    lines.append(f"    {exp}")
                if len(exports) > 50:
                    lines.append(f"    ... ({len(exports) - 50} more)")

    return "\n".join(lines)


async def _handle_get_binary_info(input: dict, context: ToolContext) -> str:
    """Get binary metadata: architecture, format, entry point, etc."""
    path = context.resolve_path(input["binary_path"])

    info = None
    try:
        info = await ghidra_service.get_binary_info(path, context.firmware_id, context.db)
    except Exception:
        pass  # Fall through to LIEF/raw analysis

    if info:
        bin_info = info.get("bin", {})
        lines = [
            "Binary Information:",
            "",
            f"  File:         {bin_info.get('file', 'unknown')}",
            f"  Format:       {bin_info.get('bintype', 'unknown')}",
            f"  Architecture: {bin_info.get('arch', 'unknown')}",
            f"  Bits:         {bin_info.get('bits', 'unknown')}",
            f"  Endianness:   {bin_info.get('endian', 'unknown')}",
            f"  OS:           {bin_info.get('os', 'unknown')}",
            f"  Machine:      {bin_info.get('machine', 'unknown')}",
            f"  Class:        {bin_info.get('class', 'unknown')}",
            f"  Language:     {bin_info.get('lang', 'unknown')}",
            f"  Stripped:     {bin_info.get('stripped', 'unknown')}",
            f"  Static:       {bin_info.get('static', 'unknown')}",
            f"  Linked libs:  {', '.join(bin_info.get('libs', [])) or 'none'}",
        ]
        return "\n".join(lines)

    # Fallback: use LIEF/pefile for PE or non-ELF binaries where radare2 failed
    loop = asyncio.get_running_loop()
    magic = await loop.run_in_executor(None, _read_magic_sync, path, 4)
    is_pe = bool(magic and magic[:2] == b"MZ")

    if is_pe:
        from app.services.binary_analysis_service import analyze_binary, check_pe_protections

        lief_info = await loop.run_in_executor(None, analyze_binary, path)
        pe_info = await loop.run_in_executor(None, check_pe_protections, path)

        deps = lief_info.get("dependencies", [])
        lines = [
            "Binary Information (PE via LIEF + pefile):",
            "",
            f"  File:         {os.path.basename(path)}",
            "  Format:       PE",
            f"  Architecture: {lief_info.get('architecture', 'unknown')}",
            f"  Bits:         {lief_info.get('bits', 'unknown')}",
            f"  Endianness:   {lief_info.get('endianness', 'little')}",
            f"  Entry Point:  {hex(lief_info['entry_point']) if lief_info.get('entry_point') else 'N/A'}",
            f"  Static:       {'yes' if lief_info.get('is_static') else 'no'}",
            f"  Linked DLLs:  {', '.join(deps) or 'none'}",
        ]

        if "error" not in pe_info:
            def _yn(v: object) -> str:
                return "yes" if v is True else "no"

            lines.extend([
                "",
                "  Security:",
                f"    DEP/NX:     {_yn(pe_info.get('dep_nx'))}",
                f"    ASLR:       {_yn(pe_info.get('aslr'))}",
                f"    SEH:        {_yn(pe_info.get('seh'))}",
                f"    CFG:        {_yn(pe_info.get('cfg'))}",
                f"    Signed:     {_yn(pe_info.get('authenticode'))}",
            ])

        return "\n".join(lines)

    # Non-PE, non-ELF — try LIEF generic analysis
    from app.services.binary_analysis_service import analyze_binary

    loop = asyncio.get_running_loop()
    lief_info = await loop.run_in_executor(None, analyze_binary, path)
    if lief_info.get("format") != "unknown":
        lines = [
            f"Binary Information ({lief_info['format'].upper()} via LIEF):",
            "",
            f"  File:         {os.path.basename(path)}",
            f"  Format:       {lief_info['format'].upper()}",
            f"  Architecture: {lief_info.get('architecture', 'unknown')}",
            f"  Bits:         {lief_info.get('bits', 'unknown')}",
            f"  Endianness:   {lief_info.get('endianness', 'unknown')}",
            f"  Entry Point:  {hex(lief_info['entry_point']) if lief_info.get('entry_point') else 'N/A'}",
            f"  Static:       {'yes' if lief_info.get('is_static') else 'no'}",
            f"  Dependencies: {', '.join(lief_info.get('dependencies', [])) or 'none'}",
        ]
        return "\n".join(lines)

    # Raw binary fallback — provide basic file metadata
    def _read_raw_binary_metadata_sync(p: str) -> tuple[int, bytes, int, int] | None:
        """Read size + first 16 bytes + (sp, reset) words. Returns None on OSError."""
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                hdr = f.read(16)
            if size > 0x100:
                with open(p, "rb") as f:
                    sp_word = int.from_bytes(f.read(4), "little")
                    reset_word = int.from_bytes(f.read(4), "little")
            else:
                sp_word = 0
                reset_word = 0
            return size, hdr, sp_word, reset_word
        except OSError:
            return None

    meta = await loop.run_in_executor(None, _read_raw_binary_metadata_sync, path)
    if meta is None:
        return "Could not read binary file."
    file_size, header, sp, reset = meta
    magic_hex = " ".join(f"{b:02x}" for b in header[:16])

    lines = [
        "Binary Information (raw binary):",
        "",
        f"  File:         {os.path.basename(path)}",
        "  Format:       Raw binary (no ELF/PE/Mach-O header)",
        f"  Size:         {file_size:,} bytes ({file_size / 1024:.1f} KB)",
        f"  Magic bytes:  {magic_hex}",
    ]

    if file_size > 0x100:
        if 0x20000000 <= sp <= 0x20100000 and 0x08000000 <= reset <= 0x08100000:
            lines.append("  Architecture: ARM Cortex-M (vector table detected)")
            lines.append(f"  Initial SP:   {hex(sp)}")
            lines.append(f"  Reset vector: {hex(reset)}")
        elif sp == 0 or reset == 0:
            pass  # Not a vector table
        else:
            lines.append(f"  Word 0 (SP?): {hex(sp)}")
            lines.append(f"  Word 1 (PC?): {hex(reset)}")

    lines.append("")
    lines.append("  Note: Use extract_strings or detect_rtos for deeper analysis of raw binaries.")
    return "\n".join(lines)


async def _handle_check_binary_protections(
    input: dict, context: ToolContext
) -> str:
    """Check binary security protections (NX, RELRO, canary, PIE, Fortify for ELF; DEP, ASLR, SEH, CFG for PE)."""
    path = context.resolve_path(input["binary_path"])

    # Detect format to choose the right checker
    loop = asyncio.get_running_loop()
    magic = await loop.run_in_executor(None, _read_magic_sync, path, 4)
    is_pe = bool(magic and magic[:2] == b"MZ")

    if is_pe:
        # PE protection check via pefile
        from app.services.binary_analysis_service import check_pe_protections

        pe_info = await loop.run_in_executor(None, check_pe_protections, path)

        if "error" in pe_info:
            return f"Error: {pe_info['error']}"

        def _pe_status(val: object) -> str:
            if isinstance(val, bool):
                return "enabled" if val else "disabled"
            return str(val)

        lines = [
            "PE Binary Protection Status:",
            "",
            f"  DEP/NX:             {_pe_status(pe_info.get('dep_nx'))}",
            f"  ASLR:               {_pe_status(pe_info.get('aslr'))}",
            f"  SEH:                {_pe_status(pe_info.get('seh'))}",
            f"  CFG (Control Flow): {_pe_status(pe_info.get('cfg'))}",
            f"  High Entropy VA:    {_pe_status(pe_info.get('high_entropy_va'))}",
            f"  Force Integrity:    {_pe_status(pe_info.get('force_integrity'))}",
            f"  Authenticode:       {_pe_status(pe_info.get('authenticode'))}",
        ]

        # Summary score
        enabled = sum(
            1
            for k in ("dep_nx", "aslr", "seh", "cfg", "authenticode")
            if pe_info.get(k) is True
        )
        total = 5
        lines.append("")
        lines.append(f"  Protection score: {enabled}/{total}")

        return "\n".join(lines)

    # ELF protection check (existing logic)
    protections = check_binary_protections(path)

    if "error" in protections:
        return f"Error: {protections['error']}"

    def _status(val: object) -> str:
        if isinstance(val, bool):
            return "enabled" if val else "disabled"
        return str(val)

    lines = [
        "Binary Protection Status:",
        "",
        f"  NX (No-Execute):    {_status(protections['nx'])}",
        f"  RELRO:              {protections['relro']}",
        f"  Stack Canary:       {_status(protections['canary'])}",
        f"  PIE:                {_status(protections['pie'])}",
        f"  Fortify Source:     {_status(protections['fortify'])}",
        f"  Stripped:           {_status(protections['stripped'])}",
    ]

    # Summary
    enabled = sum(
        1
        for k in ("nx", "canary", "pie", "fortify")
        if protections.get(k) is True
    )
    if protections.get("relro") == "full":
        enabled += 1
    elif protections.get("relro") == "partial":
        enabled += 0.5

    total = 5
    lines.append("")
    lines.append(f"  Protection score: {enabled}/{total}")

    return "\n".join(lines)


async def _handle_decompile_function(input: dict, context: ToolContext) -> str:
    """Decompile a function using Ghidra headless, returning pseudo-C output."""
    path = context.resolve_path(input["binary_path"])
    function_name = input["function_name"]

    try:
        result = await decompile_function(
            binary_path=path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except FileNotFoundError:
        return f"Error: Binary not found at '{input['binary_path']}'."
    except TimeoutError as exc:
        return f"Error: {exc}"
    except RuntimeError as exc:
        return f"Error: {exc}"

    return f"Decompiled output for {function_name}:\n\n{result}"


async def _handle_find_string_refs(input: dict, context: ToolContext) -> str:
    """Find functions referencing strings matching a pattern."""
    path = context.resolve_path(input["binary_path"])
    pattern = input["pattern"]

    binary_sha256 = await ghidra_service.get_binary_sha256(path)
    cache_key = f"string_refs:{hashlib.md5(pattern.encode()).hexdigest()[:12]}"

    # Check cache
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        results = cached.get("results", [])
    else:
        # Run Ghidra FindStringRefs script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "FindStringRefs.java", script_args=[pattern],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        # Parse output
        start = raw_output.find(_STRING_REFS_START)
        end = raw_output.find(_STRING_REFS_END)
        if start == -1 or end == -1:
            return _extract_ghidra_error(raw_output, "FindStringRefs")

        json_str = raw_output[start + len(_STRING_REFS_START):end].strip()
        # Extract JSON array
        json_start = json_str.find("[")
        json_end = json_str.rfind("]")
        if json_start == -1 or json_end == -1:
            return "No results found for pattern."

        try:
            results = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse FindStringRefs JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache results
        await ghidra_service.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            {"results": results}, context.db,
        )

    if not results:
        return f"No strings matching '{pattern}' with code references found."

    total_refs = sum(len(r.get("references", [])) for r in results)
    lines = [
        f"Found {len(results)} string(s) matching '{pattern}' "
        f"with {total_refs} code reference(s):",
        "",
    ]

    for entry in results:
        str_val = entry.get("string_value", "")
        str_addr = entry.get("string_address", "")
        refs = entry.get("references", [])
        # Truncate long strings for display
        display_str = str_val[:100] + "..." if len(str_val) > 100 else str_val
        lines.append(f"  \"{display_str}\" @ {str_addr}")
        for ref in refs:
            func = ref.get("function", "unknown")
            func_addr = ref.get("function_address", "")
            ref_addr = ref.get("ref_address", "")
            insn = ref.get("instruction", "")
            lines.append(f"    -> {func} @ {func_addr}  (ref {ref_addr}: {insn})")
        lines.append("")

    return "\n".join(lines)


def _resolve_import_sync(
    target_path: str, function_name: str, real_root: str
) -> dict:
    """Synchronous DT_NEEDED parse + library symbol search.

    Two-phase ELF inspection: (1) parse the target binary's DT_NEEDED
    entries, (2) walk each candidate library file in `_STANDARD_LIB_PATHS`
    looking for an exported `function_name`. All filesystem + ELF I/O
    lives here so the async handler can offload this whole phase via
    run_in_executor (Rule #5).

    Returns a dict with one of three statuses:
      {"status": "read_error", "error": "<str>"}
      {"status": "static",      "needed_libs": []}
      {"status": "not_found",   "needed_libs": [...]}
      {"status": "found",       "needed_libs": [...], "lib_path": "<abs>"}
    """
    # Step 1: Parse DT_NEEDED from the target binary
    try:
        with open(target_path, "rb") as f:
            elf = ELFFile(f)
            needed_libs: list[str] = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed_libs.append(tag.needed)
                    break
    except Exception as exc:
        return {"status": "read_error", "error": str(exc)}

    if not needed_libs:
        return {"status": "static", "needed_libs": []}

    # Step 2: Search each library's exports for the function
    found_lib_path: str | None = None

    for lib_name in needed_libs:
        for lib_dir in _STANDARD_LIB_PATHS:
            candidate = os.path.join(real_root, lib_dir.lstrip("/"), lib_name)
            if not os.path.isfile(candidate):
                continue
            try:
                with open(candidate, "rb") as f:
                    lib_elf = ELFFile(f)
                    dynsym = lib_elf.get_section_by_name(".dynsym")
                    if dynsym and isinstance(dynsym, SymbolTableSection):
                        for sym in dynsym.iter_symbols():
                            if (sym.name == function_name
                                    and sym.entry.st_shndx != "SHN_UNDEF"
                                    and sym.entry.st_info.type in (
                                        "STT_FUNC", "STT_GNU_IFUNC")):
                                found_lib_path = candidate
                                break
                if found_lib_path:
                    break
            except Exception:
                continue
        if found_lib_path:
            break

    if not found_lib_path:
        return {"status": "not_found", "needed_libs": needed_libs}

    return {
        "status": "found",
        "needed_libs": needed_libs,
        "lib_path": found_lib_path,
    }


async def _handle_resolve_import(input: dict, context: ToolContext) -> str:
    """Find the library implementing a function and decompile it."""
    path = context.resolve_path(input["binary_path"])
    function_name = input["function_name"]
    real_root = context.real_root_for(input["binary_path"])

    # Rule #5 — DT_NEEDED parse + per-library symbol-table walks are sync
    # ELF I/O; offload Steps 1+2 in a single executor hop. Step 3
    # (decompile_function) is genuinely async (Ghidra subprocess) and
    # stays on the loop.
    loop = asyncio.get_running_loop()
    resolution = await loop.run_in_executor(
        None, _resolve_import_sync, path, function_name, real_root
    )

    status = resolution["status"]
    if status == "read_error":
        return f"Error reading binary: {resolution['error']}"
    if status == "static":
        return "Binary has no DT_NEEDED entries (statically linked?)."
    if status == "not_found":
        needed_libs = resolution["needed_libs"]
        return (
            f"Function '{function_name}' not found in any linked library.\n"
            f"Searched libraries: {', '.join(needed_libs)}\n"
            f"Search paths: {', '.join(_STANDARD_LIB_PATHS)}"
        )

    # status == "found"
    found_lib_path = resolution["lib_path"]

    # Compute firmware-relative path for display
    rel_lib_path = "/" + os.path.relpath(found_lib_path, real_root)  # noqa: ASYNC240 — pure-string path op; no I/O

    # Step 3: Decompile the function from the library
    try:
        decompiled = await decompile_function(
            binary_path=found_lib_path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except (FileNotFoundError, TimeoutError, RuntimeError) as exc:
        return (
            f"Found '{function_name}' in {rel_lib_path}, "
            f"but decompilation failed: {exc}"
        )

    return (
        f"Resolved: '{function_name}' is implemented in {rel_lib_path}\n\n"
        f"{decompiled}"
    )


def _scan_all_binary_protections(search_path: str, real_root: str) -> list[dict]:
    """Synchronous scan of all ELF binaries for security protections."""
    ELF_MAGIC = b"\x7fELF"
    results: list[dict] = []

    for dirpath, _dirs, files in safe_walk(search_path):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            if os.path.islink(abs_path):
                continue
            try:
                with open(abs_path, "rb") as f:
                    magic = f.read(4)
                if magic != ELF_MAGIC:
                    continue
            except (OSError, PermissionError):
                continue
            if name.endswith(".ko") or ".ko." in name:
                continue
            rel_path = "/" + os.path.relpath(abs_path, real_root)
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                size = 0
            elf_type = "unknown"
            try:
                with open(abs_path, "rb") as f:
                    elf = ELFFile(f)
                    if elf.header.e_type == "ET_EXEC":
                        elf_type = "exe"
                    elif elf.header.e_type == "ET_DYN":
                        elf_type = "lib" if ".so" in name else "exe"
            except Exception:
                pass
            protections = check_binary_protections(abs_path)
            if "error" in protections:
                continue
            score = 0.0
            if protections.get("nx") is True:
                score += 1
            if protections.get("canary") is True:
                score += 1
            if protections.get("pie") is True:
                score += 1
            if protections.get("fortify") is True:
                score += 1
            relro = protections.get("relro", "none")
            if relro == "full":
                score += 1
            elif relro == "partial":
                score += 0.5
            results.append({
                "path": rel_path,
                "type": elf_type,
                "size": size,
                "nx": protections.get("nx", False),
                "relro": relro,
                "canary": protections.get("canary", False),
                "pie": protections.get("pie", False),
                "fortify": protections.get("fortify", False),
                "score": score,
            })

    return results


async def _handle_check_all_binary_protections(
    input: dict, context: ToolContext,
) -> str:
    """Scan all ELF binaries and report their security protections."""
    import asyncio

    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)

    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(
        None, _scan_all_binary_protections, search_path, real_root
    )

    if not results:
        return "No ELF binaries found."

    # Sort by protection score ascending (least protected first)
    results.sort(key=lambda r: (r["score"], r["path"]))

    # Build output table
    def _yn(val: object) -> str:
        return "Y" if val is True else "N"

    lines = [
        f"Found {len(results)} ELF binary(ies), sorted by protection score "
        f"(least protected first):",
        "",
        f"  {'Path':<45} {'Type':<5} {'Size':>8} {'NX':>3} {'RELRO':>8} "
        f"{'Can':>4} {'PIE':>4} {'Fort':>5} {'Score':>6}",
        f"  {'─'*45} {'─'*5} {'─'*8} {'─'*3} {'─'*8} {'─'*4} {'─'*4} {'─'*5} {'─'*6}",
    ]

    # Show up to 50 least-protected binaries in table
    display_limit = 50
    for r in results[:display_limit]:
        size_str = f"{r['size'] // 1024}K" if r['size'] >= 1024 else f"{r['size']}B"
        path_display = r["path"]
        if len(path_display) > 44:
            path_display = "..." + path_display[-41:]
        lines.append(
            f"  {path_display:<45} {r['type']:<5} {size_str:>8} "
            f"{_yn(r['nx']):>3} {r['relro']:>8} {_yn(r['canary']):>4} "
            f"{_yn(r['pie']):>4} {_yn(r['fortify']):>5} {r['score']:>5.1f}/5"
        )

    if len(results) > display_limit:
        lines.append(
            f"\n  ... {len(results) - display_limit} more binaries not shown "
            f"(all scored ≥ {results[display_limit]['score']:.1f}/5)"
        )

    # Summary
    no_nx = sum(1 for r in results if not r["nx"])
    no_canary = sum(1 for r in results if not r["canary"])
    no_pie = sum(1 for r in results if not r["pie"])
    lines.append("")
    lines.append(
        f"Summary: {no_nx} without NX, {no_canary} without canary, "
        f"{no_pie} without PIE"
    )

    return "\n".join(lines)


async def _handle_trace_dataflow(input: dict, context: ToolContext) -> str:
    """Trace source-to-sink dataflow paths in a binary."""
    path = context.resolve_path(input["binary_path"])
    sources = input.get("sources", _DEFAULT_SOURCES)
    sinks = input.get("sinks", _DEFAULT_SINKS)

    sources_csv = ",".join(sources)
    sinks_csv = ",".join(sinks)

    binary_sha256 = await ghidra_service.get_binary_sha256(path)
    cache_key = (
        f"taint_analysis:"
        f"{hashlib.md5((sources_csv + '|' + sinks_csv).encode()).hexdigest()[:12]}"
    )

    # Check cache
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        paths = cached.get("paths", [])
    else:
        # Run Ghidra TaintAnalysis script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "TaintAnalysis.java",
                script_args=[sources_csv, sinks_csv],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        # Parse output
        start = raw_output.find(_TAINT_START)
        end = raw_output.find(_TAINT_END)
        if start == -1 or end == -1:
            return _extract_ghidra_error(raw_output, "TaintAnalysis")

        json_str = raw_output[start + len(_TAINT_START):end].strip()
        json_start = json_str.find("[")
        json_end = json_str.rfind("]")
        if json_start == -1 or json_end == -1:
            return "No dataflow paths found."

        try:
            paths = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse TaintAnalysis JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache results
        await ghidra_service.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            {"paths": paths}, context.db,
        )

    if not paths:
        return "No source-to-sink dataflow paths found."

    # Separate by confidence
    high_paths = [p for p in paths if not p.get("interprocedural", False)]
    medium_paths = [p for p in paths if p.get("interprocedural", False)]

    lines = [
        f"Found {len(paths)} potential dataflow path(s) "
        f"({len(high_paths)} high confidence, {len(medium_paths)} medium):",
        "",
    ]

    if high_paths:
        lines.append("## High Confidence (intraprocedural — same function)")
        lines.append("")
        for p in high_paths:
            func = p.get("function", "unknown")
            src = p.get("source_func", "?")
            sink = p.get("sink_func", "?")
            src_addr = p.get("source_call_site", "")
            sink_addr = p.get("sink_call_site", "")
            lines.append(f"  {func}:")
            lines.append(f"    {src}() @ {src_addr}  -->  {sink}() @ {sink_addr}")
        lines.append("")

    if medium_paths:
        lines.append("## Medium Confidence (interprocedural — across functions)")
        lines.append("")
        for p in medium_paths:
            func = p.get("function", "unknown")
            src = p.get("source_func", "?")
            sink = p.get("sink_func", "?")
            sink_func = p.get("sink_function", "?")
            lines.append(f"  {func}:")
            lines.append(f"    {src}()  -->  {sink_func}()  -->  {sink}()")
        lines.append("")

    lines.append(
        "Note: These are heuristic paths based on call ordering. "
        "Decompile the flagged functions to verify data actually flows "
        "from source to sink."
    )

    return "\n".join(lines)


async def _handle_find_callers(input: dict, context: ToolContext) -> str:
    """Find all functions that call the target function."""
    path = context.resolve_path(input["binary_path"])
    target = input["function_name"]
    include_aliases = input.get("include_aliases", True)

    binary_sha256 = await ghidra_service.ensure_analysis(path, context.firmware_id, context.db)

    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, "xrefs", context.db,
    )
    if not cached:
        return "No xref data available for this binary. Run list_functions first."

    xrefs = cached.get("xrefs", {})

    # Build alias set for the target (e.g. doSystemCmd -> _doSystemCmd, PLT thunks)
    targets = {target}
    if include_aliases:
        targets.add(f"_{target}")
        targets.add(f"__{target}")
        targets.add(f"{target}_plt")
        # Also check if target starts with underscore — add base name
        if target.startswith("_") and not target.startswith("__"):
            targets.add(target[1:])

    callers: list[dict] = []
    seen: set[str] = set()

    # Strategy 1: Check the target's own "to" (incoming) xrefs
    for t in targets:
        func_xrefs = xrefs.get(t, {})
        for ref in func_xrefs.get("to", []):
            from_func = ref.get("from_func", "")
            key = f"{from_func}:{ref.get('from', '')}"
            if key not in seen:
                seen.add(key)
                callers.append({
                    "caller": from_func or "unknown",
                    "address": ref.get("from", "unknown"),
                    "type": ref.get("type", "CALL"),
                })

    # Strategy 2: Reverse scan all functions' outgoing "from" xrefs
    for func_name, func_data in xrefs.items():
        for ref in func_data.get("from", []):
            to_func = ref.get("to_func", "")
            if to_func in targets:
                key = f"{func_name}:{ref.get('from', ref.get('address', ''))}"
                if key not in seen:
                    seen.add(key)
                    callers.append({
                        "caller": func_name,
                        "address": ref.get("from", ref.get("address", "unknown")),
                        "type": ref.get("type", "CALL"),
                    })

    if not callers:
        return f"No callers found for '{target}' (also checked aliases: {targets})."

    # Sort by caller name
    callers.sort(key=lambda c: c["caller"])

    lines = [
        f"Found {len(callers)} call site(s) of '{target}':",
        "",
    ]
    for c in callers:
        lines.append(f"  {c['caller']}  @ {c['address']}  [{c['type']}]")

    return "\n".join(lines)


async def _handle_search_binary_content(input: dict, context: ToolContext) -> str:
    """Search for byte patterns, strings, or disassembly patterns in a binary."""
    path = context.resolve_path(input["binary_path"])
    mode = input.get("mode", "string")
    pattern = input["pattern"]
    max_results = input.get("max_results", 50)
    if max_results <= 0:
        max_results = 100000


    if mode == "disasm":
        # Search cached disassembly text with a regex
        binary_sha256 = await ghidra_service.ensure_analysis(
            path, context.firmware_id, context.db,
        )
        functions = await ghidra_service.get_functions(path, context.firmware_id, context.db)
        if not functions:
            return "No functions found (binary not analyzed)."

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return f"Invalid regex pattern: {exc}"

        matches: list[dict] = []
        for fn in functions:
            fn_name = fn.get("name", "unknown")
            disasm_cached = await ghidra_service.get_cached(
                context.firmware_id, binary_sha256,
                f"disasm:{fn_name}", context.db,
            )
            if not disasm_cached:
                continue
            disasm_text = disasm_cached.get("disassembly", "")
            for line in disasm_text.splitlines():
                if regex.search(line):
                    matches.append({"function": fn_name, "line": line.strip()})
                    if len(matches) >= max_results:
                        break
            if len(matches) >= max_results:
                break

        if not matches:
            return f"No disassembly lines matching '{pattern}' found."

        lines = [f"Found {len(matches)} disassembly match(es) for '{pattern}':", ""]
        for m in matches:
            lines.append(f"  [{m['function']}] {m['line']}")
        return "\n".join(lines)

    # Hex or string mode — scan the binary file directly
    if mode == "hex":
        # Parse hex pattern: "48 8b 45 f8" or "488b45f8"
        hex_clean = pattern.replace(" ", "").replace("\\x", "")
        try:
            search_bytes = bytes.fromhex(hex_clean)
        except ValueError:
            return f"Invalid hex pattern: '{pattern}'. Use format like '48 8b 45 f8'."
    else:
        # String mode
        search_bytes = pattern.encode("utf-8", errors="replace")

    if not search_bytes:
        return "Empty search pattern."

    loop = asyncio.get_running_loop()
    file_size = await loop.run_in_executor(None, os.path.getsize, path)
    chunk_size = 65536
    overlap = len(search_bytes) - 1

    # Get function address ranges for mapping offsets to functions
    func_ranges: list[tuple[int, int, str]] = []
    try:
        functions = await ghidra_service.get_functions(path, context.firmware_id, context.db)
        for fn in functions:
            addr_str = fn.get("address", "0")
            size = fn.get("size", 0)
            try:
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                func_ranges.append((addr, addr + size, fn.get("name", "unknown")))
            except (ValueError, TypeError):
                pass
        func_ranges.sort(key=lambda r: r[0])
    except Exception:
        pass

    def _find_function(offset: int) -> str:
        """Binary search for containing function."""
        lo, hi = 0, len(func_ranges) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, name = func_ranges[mid]
            if offset < start:
                hi = mid - 1
            elif offset >= end:
                lo = mid + 1
            else:
                return name
        return ""

    def _scan_binary_chunks_sync() -> list[dict]:
        """Chunked binary scan with cross-boundary match support."""
        local_matches: list[dict] = []
        with open(path, "rb") as f:
            pos = 0
            prev_tail = b""
            while pos < file_size and len(local_matches) < max_results:
                f.seek(pos)
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                # Prepend overlap from previous chunk to catch cross-boundary matches
                search_buf = prev_tail + chunk
                offset_base = pos - len(prev_tail)

                idx = 0
                while idx < len(search_buf) and len(local_matches) < max_results:
                    found = search_buf.find(search_bytes, idx)
                    if found == -1:
                        break
                    abs_offset = offset_base + found
                    # Get context bytes (16 bytes before and after)
                    ctx_start = max(0, found - 16)
                    ctx_end = min(len(search_buf), found + len(search_bytes) + 16)
                    ctx_hex = search_buf[ctx_start:ctx_end].hex()
                    func_name = _find_function(abs_offset)
                    local_matches.append({
                        "offset": abs_offset,
                        "context": ctx_hex,
                        "function": func_name,
                    })
                    idx = found + 1

                prev_tail = chunk[-overlap:] if overlap > 0 else b""
                pos += len(chunk)
        return local_matches

    matches: list[dict] = await loop.run_in_executor(None, _scan_binary_chunks_sync)

    if not matches:
        mode_desc = "hex bytes" if mode == "hex" else "string"
        return f"No matches for {mode_desc} '{pattern}' in binary."

    lines = [f"Found {len(matches)} match(es):", ""]
    for m in matches:
        func_info = f"  in {m['function']}" if m["function"] else ""
        lines.append(f"  offset 0x{m['offset']:08x}{func_info}")
        lines.append(f"    hex: {m['context']}")
    if len(matches) >= max_results:
        lines.append(f"\n  (limited to {max_results} results)")

    return "\n".join(lines)


async def _handle_get_stack_layout(input: dict, context: ToolContext) -> str:
    """Get annotated stack frame layout for a function."""
    path = context.resolve_path(input["binary_path"])
    function_name = input["function_name"]

    binary_sha256 = await ghidra_service.get_binary_sha256(path)
    cache_key = f"stack_layout:{function_name}"

    # Check cache
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        result = cached
    else:
        # Run Ghidra StackLayout script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "StackLayout.java", script_args=[function_name],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        start = raw_output.find(_STACK_LAYOUT_START)
        end = raw_output.find(_STACK_LAYOUT_END)
        if start == -1 or end == -1:
            return _extract_ghidra_error(raw_output, "StackLayout")

        json_str = raw_output[start + len(_STACK_LAYOUT_START):end].strip()
        json_start = json_str.find("{")
        json_end = json_str.rfind("}")
        if json_start == -1 or json_end == -1:
            return "No stack layout data found."

        try:
            result = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse StackLayout JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache
        await ghidra_service.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            result, context.db,
        )

    # Format output
    func_name = result.get("function", function_name)
    frame_size = result.get("frame_size", 0)
    variables = result.get("variables", [])
    saved_regs = result.get("saved_registers", [])
    overflows = result.get("overflow_distances", [])

    lines = [
        f"Stack Layout for {func_name} (frame size: {frame_size} bytes):",
        "",
        f"  {'Offset':<10} {'Size':<8} {'Type':<20} {'Name'}",
        f"  {'─' * 10} {'─' * 8} {'─' * 20} {'─' * 20}",
    ]
    for v in variables:
        offset = v.get("offset", 0)
        size = v.get("size", 0)
        vtype = v.get("type", "unknown")[:20]
        name = v.get("name", "?")
        marker = " <-- return addr" if v.get("is_return_addr") else ""
        lines.append(f"  {offset:<10} {size:<8} {vtype:<20} {name}{marker}")

    if saved_regs:
        lines.append("")
        lines.append("Saved Registers:")
        for sr in saved_regs:
            reg = sr.get("register", "?")
            offset = sr.get("offset", 0)
            lines.append(f"  offset {offset}: {reg}")

    if overflows:
        lines.append("")
        lines.append("Buffer Overflow Distances:")
        for od in overflows:
            buf = od.get("buffer", "?")
            dist = od.get("distance", 0)
            lines.append(
                f"  {buf} (offset {od.get('buffer_offset', '?')}) → "
                f"return addr (offset {od.get('return_addr_offset', '?')}): "
                f"{dist} bytes"
            )

    return "\n".join(lines)


async def _handle_get_global_layout(input: dict, context: ToolContext) -> str:
    """Get global variable layout around a target symbol."""
    path = context.resolve_path(input["binary_path"])
    symbol_name = input["symbol_name"]

    binary_sha256 = await ghidra_service.get_binary_sha256(path)
    cache_key = f"global_layout:{symbol_name}"

    # Check cache
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        result = cached
    else:
        # Run Ghidra GlobalLayout script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "GlobalLayout.java", script_args=[symbol_name],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        start = raw_output.find(_GLOBAL_LAYOUT_START)
        end = raw_output.find(_GLOBAL_LAYOUT_END)
        if start == -1 or end == -1:
            return _extract_ghidra_error(raw_output, "GlobalLayout")

        json_str = raw_output[start + len(_GLOBAL_LAYOUT_START):end].strip()
        json_start = json_str.find("{")
        json_end = json_str.rfind("}")
        if json_start == -1 or json_end == -1:
            return "No global layout data found."

        try:
            result = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse GlobalLayout JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache
        await ghidra_service.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            result, context.db,
        )

    # Format output
    target_sym = result.get("target_symbol", symbol_name)
    target_addr = result.get("target_address", "?")
    section = result.get("section", "?")
    section_range = result.get("section_range", [])
    neighbors = result.get("neighbors", [])

    lines = [
        f"Global Layout around '{target_sym}' @ {target_addr}",
        f"Section: {section}",
    ]
    if section_range:
        lines.append(f"Section range: {section_range[0]} - {section_range[1]}")
    lines.append("")
    lines.append(f"  {'Address':<14} {'Size':<8} {'Type':<24} {'Name'}")
    lines.append(f"  {'─' * 14} {'─' * 8} {'─' * 24} {'─' * 20}")

    for n in neighbors:
        addr = n.get("address", "?")
        size = n.get("size", 0)
        ntype = n.get("type", "unknown")[:24]
        name = n.get("name", "?")
        marker = "  <-- TARGET" if n.get("is_target") else ""
        lines.append(f"  {addr:<14} {size:<8} {ntype:<24} {name}{marker}")

    return "\n".join(lines)


async def _handle_cross_binary_dataflow(input: dict, context: ToolContext) -> str:
    """Trace data flows across binaries via IPC mechanisms (nvram, config, files)."""
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    mechanisms = input.get("mechanisms")  # Optional filter

    ELF_MAGIC = b"\x7fELF"

    def _walk_elf_candidates_sync(root: str, rroot: str) -> list[tuple[str, str]]:
        """Walk `root` and return list of (abs_path, rel_path) for ELF candidates."""
        out: list[tuple[str, str]] = []
        for dirpath, _dirs, files in safe_walk(root):
            for name in files:
                abs_path = os.path.join(dirpath, name)
                if os.path.islink(abs_path):
                    continue
                try:
                    with open(abs_path, "rb") as f:
                        if f.read(4) != ELF_MAGIC:
                            continue
                except (OSError, PermissionError):
                    continue
                # Skip kernel modules — not user-space binaries
                if name.endswith(".ko") or ".ko." in name:
                    continue
                rel_path = "/" + os.path.relpath(abs_path, rroot)
                out.append((abs_path, rel_path))
        return out

    # Step 1: Find all analyzed ELF binaries
    loop = asyncio.get_running_loop()
    elf_candidates = await loop.run_in_executor(
        None, _walk_elf_candidates_sync, search_path, real_root,
    )

    analyzed_binaries: list[tuple[str, str]] = []  # (abs_path, rel_path)
    for abs_path, rel_path in elf_candidates:
        # Check if this binary has been Ghidra-analyzed
        try:
            sha = await ghidra_service.get_binary_sha256(abs_path)
            is_analyzed = await ghidra_service.get_cached(
                context.firmware_id, sha, "ghidra_full_analysis", context.db,
            )
            if is_analyzed:
                analyzed_binaries.append((abs_path, rel_path))
        except Exception:
            continue

    if not analyzed_binaries:
        return (
            "No Ghidra-analyzed binaries found. Run list_functions on key "
            "binaries first to trigger analysis, then re-run this tool."
        )

    # Step 2: For each analyzed binary, get imports and check for IPC functions
    # Map: {mechanism: {key_or_func: [{binary, function, role, call_site}]}}
    ipc_map: dict[str, dict[str, list[dict]]] = {}

    pairs_to_check = _IPC_PAIRS
    if mechanisms:
        pairs_to_check = {
            k: v for k, v in _IPC_PAIRS.items()
            if k in mechanisms
        }

    for abs_path, rel_path in analyzed_binaries:
        sha = await ghidra_service.get_binary_sha256(abs_path)

        # Get imports
        imports_cached = await ghidra_service.get_cached(
            context.firmware_id, sha, "imports", context.db,
        )
        if not imports_cached:
            continue
        import_names = {
            imp.get("name", "") for imp in imports_cached.get("imports", [])
        }

        # Get xrefs
        xrefs_cached = await ghidra_service.get_cached(
            context.firmware_id, sha, "xrefs", context.db,
        )
        xrefs_data = xrefs_cached.get("xrefs", {}) if xrefs_cached else {}

        for mechanism, pair in pairs_to_check.items():
            all_funcs = pair["writers"] + pair["readers"]
            relevant_imports = import_names & set(all_funcs)
            if not relevant_imports:
                continue

            for ipc_func in relevant_imports:
                role = "writer" if ipc_func in pair["writers"] else "reader"

                # Find callers of this IPC function via xrefs
                callers: list[dict] = []
                for func_name, func_data in xrefs_data.items():
                    for ref in func_data.get("from", []):
                        if ref.get("to_func") == ipc_func:
                            callers.append({
                                "binary": rel_path,
                                "function": func_name,
                                "role": role,
                                "ipc_func": ipc_func,
                                "call_site": ref.get("from", ref.get("address", "?")),
                            })

                if callers:
                    ipc_map.setdefault(mechanism, {}).setdefault(ipc_func, []).extend(callers)

    if not ipc_map:
        return (
            f"No IPC dataflow found across {len(analyzed_binaries)} analyzed binaries.\n"
            "This may mean the binaries don't use standard IPC functions, or "
            "the relevant binaries haven't been analyzed yet."
        )

    # Step 3: Correlate cross-binary flows
    cross_flows: list[dict] = []

    for mechanism, func_map in ipc_map.items():
        pair = pairs_to_check[mechanism]
        writers: list[dict] = []
        readers: list[dict] = []

        for ipc_func, entries in func_map.items():
            for entry in entries:
                if entry["role"] == "writer":
                    writers.append(entry)
                else:
                    readers.append(entry)

        # Find cross-binary pairs (writer in binary A, reader in binary B)
        for w in writers:
            for r in readers:
                if w["binary"] != r["binary"]:
                    cross_flows.append({
                        "mechanism": mechanism,
                        "writer_binary": w["binary"],
                        "writer_function": w["function"],
                        "writer_ipc": w["ipc_func"],
                        "reader_binary": r["binary"],
                        "reader_function": r["function"],
                        "reader_ipc": r["ipc_func"],
                    })

    # Format output
    lines = [
        "Cross-Binary Dataflow Analysis",
        f"Analyzed binaries: {len(analyzed_binaries)}",
        "",
    ]

    # Show per-mechanism summary
    for mechanism, func_map in ipc_map.items():
        all_entries = [e for entries in func_map.values() for e in entries]
        writers = [e for e in all_entries if e["role"] == "writer"]
        readers = [e for e in all_entries if e["role"] == "reader"]
        unique_binaries = {e["binary"] for e in all_entries}

        lines.append(f"## {mechanism.upper()} IPC")
        lines.append(f"  {len(writers)} writer(s), {len(readers)} reader(s) "
                      f"across {len(unique_binaries)} binary(ies)")

        for ipc_func, entries in func_map.items():
            lines.append(f"  {ipc_func}():")
            for e in entries[:30]:
                lines.append(
                    f"    [{e['role']}] {e['binary']}:{e['function']} "
                    f"@ {e['call_site']}"
                )
            if len(entries) > 30:
                lines.append(f"    ... and {len(entries) - 30} more")
        lines.append("")

    if cross_flows:
        lines.append(f"## Cross-Binary Flows ({len(cross_flows)})")
        lines.append("")
        shown = cross_flows[:30]
        for cf in shown:
            lines.append(
                f"  [{cf['mechanism']}] "
                f"{cf['writer_binary']}:{cf['writer_function']}() "
                f"--{cf['writer_ipc']}()--> "
                f"{cf['reader_binary']}:{cf['reader_function']}() "
                f"via {cf['reader_ipc']}()"
            )
        if len(cross_flows) > 30:
            lines.append(f"  ... and {len(cross_flows) - 30} more")
    else:
        lines.append(
            "No cross-binary flows detected (all IPC calls are within "
            "the same binary). Try analyzing more binaries with list_functions."
        )

    return "\n".join(lines)


def _detect_elf_machine_sync(path: str) -> str | None:
    """Read the ELF e_machine field. Returns None if not an ELF or unreadable."""
    try:
        with open(path, "rb") as f:
            return ELFFile(f).header.e_machine
    except Exception:
        return None


async def _handle_detect_capabilities(
    input: dict, context: ToolContext
) -> str:
    """Detect binary capabilities using FLARE capa."""
    path = context.resolve_path(input.get("binary_path") or input.get("path", "/"))

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: file not found: {input['path']}"

    # Check capa availability
    capa_bin = shutil.which("capa")
    if not capa_bin:
        return (
            "Error: capa is not installed or not on PATH. "
            "Install it with: pip install flare-capa  (or download from "
            "https://github.com/mandiant/capa/releases)"
        )

    # Detect architecture to warn about MIPS limitations
    arch_warning = ""
    machine = await loop.run_in_executor(None, _detect_elf_machine_sync, path)
    if machine in ("EM_MIPS", "EM_MIPS_RS3_LE"):
        arch_warning = (
            "\n\nWARNING: This binary targets MIPS architecture. "
            "Capa has limited MIPS support — results may be incomplete "
            "or inaccurate. ARM, AArch64, and x86/x64 binaries yield "
            "the best results."
        )

    # Run capa with JSON output
    try:
        proc = await asyncio.create_subprocess_exec(
            capa_bin, path, "-j",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return (
                "Error: capa timed out after 120 seconds. "
                "This binary may be too large for analysis. "
                "Try a smaller binary or a specific shared library instead."
            )
    except Exception as exc:
        return f"Error running capa: {exc}"

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if proc.returncode != 0:
        # Check for common error conditions
        stderr_lower = stderr.lower()
        if "unsupported" in stderr_lower or "not a supported" in stderr_lower:
            return (
                f"Capa does not support this binary format or architecture.\n"
                f"Details: {stderr.strip()}"
            )
        if "no capabilities" in stderr_lower:
            return f"No capabilities detected in this binary.{arch_warning}"
        return f"Capa failed (exit code {proc.returncode}):\n{stderr.strip()}"

    # Parse JSON output
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return (
            "Error: could not parse capa JSON output. "
            f"stderr: {stderr.strip()[:500]}"
        )

    # Extract rules grouped by namespace
    rules = data.get("rules", {})
    if not rules:
        return f"No capabilities detected in this binary.{arch_warning}"

    # Group capabilities by namespace
    by_namespace: dict[str, list[str]] = {}
    attack_techniques: list[str] = []
    mbc_behaviors: list[str] = []

    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})

        # Determine namespace/category
        namespace = meta.get("namespace", "uncategorized")
        # Use top-level namespace for grouping
        top_ns = namespace.split("/")[0] if namespace else "uncategorized"
        by_namespace.setdefault(top_ns, []).append(rule_name)

        # Collect ATT&CK mappings
        for attack in meta.get("attack", []):
            technique = attack.get("technique", "")
            tactic = attack.get("tactic", "")
            tid = attack.get("id", "")
            if technique:
                entry = f"{technique} ({tid})" if tid else technique
                if tactic:
                    entry = f"[{tactic}] {entry}"
                if entry not in attack_techniques:
                    attack_techniques.append(entry)

        # Collect MBC behaviors
        for mbc in meta.get("mbc", []):
            behavior = mbc.get("behavior", "")
            objective = mbc.get("objective", "")
            mid = mbc.get("id", "")
            if behavior:
                entry = f"{behavior} ({mid})" if mid else behavior
                if objective:
                    entry = f"[{objective}] {entry}"
                if entry not in mbc_behaviors:
                    mbc_behaviors.append(entry)

    total = sum(len(caps) for caps in by_namespace.values())

    # Format output
    lines = [
        f"CAPA Capability Detection: {total} capabilities found",
        f"Binary: {input['path']}",
        "",
    ]

    # Capabilities by namespace
    lines.append("=== Capabilities by Category ===")
    for ns in sorted(by_namespace.keys()):
        caps = sorted(by_namespace[ns])
        lines.append(f"\n{ns} ({len(caps)}):")
        for cap in caps:
            lines.append(f"  - {cap}")

    # ATT&CK mappings
    if attack_techniques:
        lines.append("\n=== MITRE ATT&CK Techniques ===")
        for tech in sorted(attack_techniques):
            lines.append(f"  - {tech}")

    # MBC behaviors
    if mbc_behaviors:
        lines.append("\n=== Malware Behavior Catalog ===")
        for beh in sorted(mbc_behaviors):
            lines.append(f"  - {beh}")

    if arch_warning:
        lines.append(arch_warning)

    return "\n".join(lines)


async def _handle_list_binary_capabilities(
    input: dict, context: ToolContext
) -> str:
    """List capability categories found in a binary (lightweight summary)."""
    path = context.resolve_path(input.get("binary_path") or input.get("path", "/"))

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: file not found: {input.get('binary_path', input.get('path', ''))}"

    capa_bin = shutil.which("capa")
    if not capa_bin:
        return (
            "Error: capa is not installed or not on PATH. "
            "Install it with: pip install flare-capa"
        )

    # Run capa with JSON output
    try:
        proc = await asyncio.create_subprocess_exec(
            capa_bin, path, "-j",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=60
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return (
                "Error: capa timed out after 60 seconds. "
                "Try detect_capabilities with the full 120s timeout, "
                "or use a smaller binary."
            )
    except Exception as exc:
        return f"Error running capa: {exc}"

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if proc.returncode != 0:
        stderr_lower = stderr.lower()
        if "unsupported" in stderr_lower or "not a supported" in stderr_lower:
            return f"Capa does not support this binary format or architecture.\nDetails: {stderr.strip()}"
        if "no capabilities" in stderr_lower:
            return "No capabilities detected in this binary."
        return f"Capa failed (exit code {proc.returncode}):\n{stderr.strip()}"

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return f"Error: could not parse capa JSON output. stderr: {stderr.strip()[:500]}"

    rules = data.get("rules", {})
    if not rules:
        return "No capabilities detected in this binary."

    # Group by top-level namespace and count
    by_namespace: dict[str, int] = {}
    attack_count = 0
    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})
        namespace = meta.get("namespace", "uncategorized")
        top_ns = namespace.split("/")[0] if namespace else "uncategorized"
        by_namespace[top_ns] = by_namespace.get(top_ns, 0) + 1
        if meta.get("attack"):
            attack_count += 1

    total = sum(by_namespace.values())
    bin_name = input.get("binary_path", input.get("path", ""))

    lines = [
        f"CAPA Summary: {total} capabilities in {bin_name}",
        "",
    ]

    # Sort by count descending
    for ns, count in sorted(by_namespace.items(), key=lambda x: -x[1]):
        lines.append(f"  {ns}: {count}")

    if attack_count:
        lines.append(f"\n{attack_count} capabilities have MITRE ATT&CK mappings.")
        lines.append("Use detect_capabilities for full details and ATT&CK technique IDs.")

    return "\n".join(lines)


async def _handle_analyze_raw_binary(input: dict, context: ToolContext) -> str:
    """Detect CPU architecture from a raw binary with no recognized headers."""
    path = context.resolve_path(input["binary_path"])

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: File not found: {input['binary_path']}"

    file_size = await loop.run_in_executor(None, os.path.getsize, path)
    if file_size < 64:
        return "Error: File too small for meaningful architecture detection (< 64 bytes)."

    # First check if it actually has headers (might just be misidentified)
    from app.services.binary_analysis_service import analyze_binary, detect_raw_architecture
    info = await loop.run_in_executor(None, analyze_binary, path)

    if info.get("format") != "unknown":
        return (
            f"This file has recognized headers ({info['format'].upper()}). "
            f"Use analyze_binary_format or get_binary_info instead.\n"
            f"Architecture: {info.get('architecture', 'unknown')}"
        )

    # Run statistical architecture detection
    chunk_size = int(input.get("chunk_size", 0))
    candidates = await loop.run_in_executor(
        None, detect_raw_architecture, path, chunk_size
    )

    if not candidates:
        return (
            "Could not detect architecture. The file may be:\n"
            "  - Encrypted or compressed data\n"
            "  - A non-code binary (filesystem image, certificate, etc.)\n"
            "  - An architecture not in the training corpus"
        )

    lines = [
        f"Raw Binary Architecture Analysis ({file_size:,} bytes):",
        "",
    ]

    for i, candidate in enumerate(candidates):
        prefix = ">>>" if i == 0 else "   "
        arch = candidate["architecture"]
        raw = candidate["raw_name"]
        endian = candidate.get("endianness", "unknown")
        confidence = candidate.get("confidence", "unknown")
        lines.append(
            f"  {prefix} {raw:<20} -> {arch} ({endian}-endian)  "
            f"[{confidence} confidence]"
        )

    if candidates:
        top = candidates[0]
        lines.extend([
            "",
            f"Best match: {top['architecture']} ({top.get('endianness', 'unknown')}-endian)",
            "",
            "Note: Statistical detection works best on code sections. If the binary",
            "contains mixed data (code + filesystem + headers), results may vary.",
            "Use chunk_size parameter to scan sub-regions independently.",
        ])

    return "\n".join(lines)


async def _handle_detect_rtos(input: dict, context: ToolContext) -> str:
    """Detect RTOS and companion components from a firmware binary."""
    from app.services.rtos_detection_service import detect_rtos, extract_companion_components

    path_input = input.get("path", "/")
    path = context.resolve_path(path_input)

    import asyncio
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Not a file: {path_input}"

    rtos = await loop.run_in_executor(None, detect_rtos, path)
    companions = await loop.run_in_executor(None, extract_companion_components, path)

    lines = [f"RTOS Detection: {os.path.basename(path)}", ""]

    if rtos:
        lines.append(f"RTOS: {rtos['rtos_display_name']}")
        if rtos.get("version"):
            lines.append(f"Version: {rtos['version']}")
        lines.append(f"Confidence: {rtos['confidence']}")
        lines.append(f"Detection methods: {', '.join(rtos['detection_methods'])}")
        if rtos.get("architecture"):
            lines.append(f"Architecture: {rtos['architecture']}")
        if rtos.get("endianness"):
            lines.append(f"Endianness: {rtos['endianness']}")
        meta = rtos.get("metadata", {})
        if meta.get("heap_variant"):
            lines.append(f"FreeRTOS heap: {meta['heap_variant']}")
        if meta.get("mcuboot_version"):
            lines.append(f"MCUboot version: {meta['mcuboot_version']}")
    else:
        lines.append("No RTOS detected.")

    if companions:
        lines.extend(["", "Companion Components:"])
        for comp in companions:
            ver = f" {comp['version']}" if comp.get("version") else ""
            lines.append(
                f"  - {comp['name']}{ver} ({comp['category']}, "
                f"{comp['confidence']} confidence via {comp['detection_method']})"
            )

    return "\n".join(lines)


def register_binary_tools(registry: ToolRegistry) -> None:
    """Register all binary analysis tools with the given registry."""

    registry.register(
        name="list_functions",
        description=(
            "List all functions found in an ELF binary, sorted by size "
            "(largest first). Large custom functions are often the most "
            "interesting for security analysis. Max 500 functions. "
            "First call for a binary triggers Ghidra analysis (1-3 minutes); "
            "subsequent calls are instant from ghidra_service."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Maximum number of functions to return (default: 100, max: 500). "
                        "Functions are sorted by size descending, so the top 100 captures "
                        "the most interesting ones."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_functions,
    )

    registry.register(
        name="disassemble_function",
        description=(
            "Disassemble a function from an ELF binary. Shows the assembly "
            "instructions with addresses. Use list_functions first to find "
            "function names. Results come from Ghidra analysis ghidra_service."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to disassemble (e.g. 'main', 'auth_check')",
                },
                "num_instructions": {
                    "type": "integer",
                    "description": "Maximum number of instructions to show (default: 100, max: 200)",
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_disassemble_function,
    )

    registry.register(
        name="decompile_function",
        description=(
            "Decompile a function from an ELF binary into pseudo-C code using "
            "Ghidra. This produces high-level C-like output that is much easier "
            "to read than assembly. Use list_functions first to find function "
            "names. Results are cached — first call for a binary may take 1-3 "
            "minutes, subsequent calls are instant. Best for understanding "
            "complex logic, finding vulnerabilities, and analyzing "
            "authentication/crypto routines."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to decompile (e.g. 'main', 'auth_check'). Use list_functions to find available names.",
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_decompile_function,
    )

    registry.register(
        name="list_imports",
        description=(
            "List imported symbols from an ELF binary, grouped by library. "
            "Useful for identifying dangerous functions (system, strcpy, "
            "gets) and external dependencies. Uses Ghidra analysis ghidra_service."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_imports,
    )

    registry.register(
        name="list_exports",
        description=(
            "List exported symbols from an ELF binary. Shows symbol names "
            "and addresses. Uses Ghidra analysis ghidra_service."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_exports,
    )

    registry.register(
        name="xrefs_to",
        description=(
            "Find all cross-references TO a given function or symbol in a "
            "binary. Shows where in the code this function is called or "
            "referenced from, including the caller function name."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "address_or_symbol": {
                    "type": "string",
                    "description": "Target function name or address (0x...)",
                },
            },
            "required": ["binary_path", "address_or_symbol"],
        },
        handler=_handle_xrefs_to,
    )

    registry.register(
        name="xrefs_from",
        description=(
            "Find all cross-references FROM a given function or symbol in a "
            "binary. Shows what functions are called or referenced by the "
            "target, including the callee function name."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "address_or_symbol": {
                    "type": "string",
                    "description": "Source function name or address (0x...)",
                },
            },
            "required": ["binary_path", "address_or_symbol"],
        },
        handler=_handle_xrefs_from,
    )

    registry.register(
        name="get_binary_info",
        description=(
            "Get detailed metadata about a binary: architecture, "
            "endianness, format, linked libraries, entry point, and more. "
            "Works with ELF (via Ghidra cache), PE (via pefile), and "
            "Mach-O (via LIEF). For PE binaries, also shows security "
            "characteristics (DEP, ASLR, SEH, CFG, Authenticode)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary (ELF, PE, or Mach-O)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_get_binary_info,
    )

    registry.register(
        name="analyze_binary_format",
        description=(
            "Analyze a binary file's format, architecture, linking type, and "
            "shared library dependencies using LIEF. Works for ELF, PE, and "
            "Mach-O formats. For standalone binaries, also checks sysroot "
            "availability for emulation. Instant (no Ghidra required)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": (
                        "Path to the binary file (ELF, PE, or Mach-O). "
                        "For standalone binary uploads, use the filename directly."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_analyze_binary_format,
    )

    registry.register(
        name="check_binary_protections",
        description=(
            "Check security protections of a binary. For ELF: NX, RELRO, "
            "stack canaries, PIE, Fortify Source, stripped status. For PE: "
            "DEP/NX, ASLR, SEH, Control Flow Guard, Authenticode. "
            "Automatically detects format. Equivalent to checksec."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary (ELF or PE)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_check_binary_protections,
    )

    # --- Phase 12 tools ---

    registry.register(
        name="find_string_refs",
        description=(
            "Find all functions that reference strings matching a regex pattern. "
            "Critical for tracing interesting strings (URLs like '/goform/telnet', "
            "format strings like 'password=%s', dangerous calls like 'doSystemCmd') "
            "back to the functions that use them. Uses Ghidra analysis — first call "
            "for a binary may take 1-3 minutes. Results are cached."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "pattern": {
                    "type": "string",
                    "description": (
                        "Regex pattern to match against strings in the binary "
                        "(case-insensitive). Examples: 'password', 'goform', "
                        "'system.*cmd', '/cgi-bin/'"
                    ),
                },
            },
            "required": ["binary_path", "pattern"],
        },
        handler=_handle_find_string_refs,
    )

    registry.register(
        name="resolve_import",
        description=(
            "Find which shared library implements a given imported function and "
            "decompile it in one step. Eliminates the manual multi-step workflow: "
            "'find import -> guess which .so -> search exports -> decompile'. "
            "Parses DT_NEEDED from the target binary, searches each library's "
            "exports, and returns the decompiled pseudo-C source."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary that imports the function",
                },
                "function_name": {
                    "type": "string",
                    "description": (
                        "Name of the imported function to resolve and decompile "
                        "(e.g. 'doSystemCmd', 'websGetVar', 'twsystem')"
                    ),
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_resolve_import,
    )

    registry.register(
        name="check_all_binary_protections",
        description=(
            "Scan ALL ELF binaries in the firmware filesystem and report their "
            "security protections in a summary table. Sorted by protection score "
            "(least protected first) to quickly identify the most vulnerable "
            "targets. Shows NX, RELRO, canary, PIE, Fortify for each binary."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan (default: entire firmware filesystem). "
                        "Use a subdirectory like '/usr/bin' to narrow scope."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_check_all_binary_protections,
    )

    registry.register(
        name="trace_dataflow",
        description=(
            "Trace dataflow from user-controlled sources to dangerous sinks in a "
            "binary. Identifies potential command injection and buffer overflow "
            "paths. Sources include: websGetVar, getenv, recv, read, nvram_get, "
            "fgets. Sinks include: system, popen, exec*, sprintf, strcpy. "
            "Uses Ghidra for intraprocedural analysis (same function) and "
            "interprocedural heuristics (across function calls). "
            "First call triggers Ghidra analysis (1-3 minutes); cached thereafter. "
            "HIGHEST-IMPACT tool for finding vulnerabilities in embedded web "
            "interfaces (e.g., router httpd binaries with goform handlers)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary to analyze",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Custom source function names (user-controlled input). "
                        "Default: websGetVar, getenv, recv, read, fgets, nvram_get, etc."
                    ),
                },
                "sinks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Custom sink function names (dangerous operations). "
                        "Default: system, popen, exec*, sprintf, strcpy, etc."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_trace_dataflow,
    )

    # --- Wishlist tools ---

    registry.register(
        name="find_callers",
        description=(
            "Find all call sites of a function across the binary. Scans cached "
            "cross-reference data to find every function that calls the target. "
            "Automatically checks common aliases (e.g., _doSystemCmd, __system, "
            "PLT thunks). Requires the binary to have been analyzed first "
            "(run list_functions if needed)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "function_name": {
                    "type": "string",
                    "description": (
                        "Name of the target function to find callers for "
                        "(e.g. 'doSystemCmd', 'system', 'strcpy')"
                    ),
                },
                "include_aliases": {
                    "type": "boolean",
                    "description": (
                        "Also search for common aliases like _func, __func, "
                        "func_plt (default: true)"
                    ),
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_find_callers,
    )

    registry.register(
        name="search_binary_content",
        description=(
            "Search for byte patterns, strings, or disassembly patterns in a "
            "binary. Three search modes:\n"
            "- 'hex': Search for hex byte patterns (e.g., '48 8b 45 f8')\n"
            "- 'string': Search for string patterns (e.g., '%s%s%s', 'password')\n"
            "- 'disasm': Search cached disassembly with regex (e.g., 'sprintf.*%s')\n\n"
            "For hex/string modes, returns file offsets and hex context. "
            "For disasm mode, returns matching instruction lines with function names."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "pattern": {
                    "type": "string",
                    "description": (
                        "Pattern to search for. Hex mode: '48 8b 45 f8' or '488b45f8'. "
                        "String mode: any text like '%s%s%s'. "
                        "Disasm mode: regex like 'sprintf.*%s'."
                    ),
                },
                "mode": {
                    "type": "string",
                    "enum": ["hex", "string", "disasm"],
                    "description": "Search mode (default: 'string')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 50, max: 100)",
                },
            },
            "required": ["binary_path", "pattern"],
        },
        handler=_handle_search_binary_content,
    )

    registry.register(
        name="get_stack_layout",
        description=(
            "Get the annotated stack frame layout for a function. Shows local "
            "variables, their offsets, sizes, and types. Identifies saved "
            "registers (including the return address) and calculates buffer-to-"
            "return-address overflow distances — critical for assessing buffer "
            "overflow exploitability. Uses Ghidra analysis — first call for a "
            "binary may take 1-3 minutes. Results are cached."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "function_name": {
                    "type": "string",
                    "description": (
                        "Function name to analyze stack layout for "
                        "(e.g. 'formSetSysToolChangePwd')"
                    ),
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_get_stack_layout,
    )

    registry.register(
        name="get_global_layout",
        description=(
            "Map global variables in BSS/data sections around a target symbol. "
            "Shows neighboring global variables with their addresses, sizes, and "
            "types. Useful for understanding global buffer overflow impact — what "
            "data gets corrupted when a global buffer overflows. Uses Ghidra "
            "analysis — first call for a binary may take 1-3 minutes. Results "
            "are cached."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "symbol_name": {
                    "type": "string",
                    "description": (
                        "Name of the target global variable/symbol "
                        "(e.g. 'g_Pass', 'config_buf')"
                    ),
                },
            },
            "required": ["binary_path", "symbol_name"],
        },
        handler=_handle_get_global_layout,
    )

    registry.register(
        name="cross_binary_dataflow",
        description=(
            "Trace data flows across multiple firmware binaries via IPC "
            "mechanisms (nvram_get/set, config get/set, file I/O). Identifies "
            "where data written by one binary (e.g., httpd setting an nvram "
            "value) is read by another binary (e.g., cfmd reading it). "
            "Only works on binaries that have been previously analyzed with "
            "Ghidra (run list_functions on key binaries first). Scans all "
            "analyzed binaries for IPC function imports and correlates "
            "cross-binary data flows."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan for analyzed binaries "
                        "(default: entire firmware filesystem)"
                    ),
                },
                "mechanisms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional filter: only check specific IPC mechanisms. "
                        "Available: 'nvram', 'config', 'file'. "
                        "Default: check all."
                    ),
                },
            },
        },
        handler=_handle_cross_binary_dataflow,
    )

    # --- capa capability detection ---

    registry.register(
        name="detect_capabilities",
        description=(
            "Detect capabilities of an ELF binary using FLARE capa. "
            "Identifies what a binary can DO (e.g., communicate over HTTP, "
            "manipulate files, use cryptography, parse PE headers) by matching "
            "against hundreds of behavioral rules. Results are grouped by "
            "category with MITRE ATT&CK technique mappings where applicable. "
            "Supports ELF binaries on ARM, AArch64, and x86/x64. MIPS support "
            "is limited. Analysis may take 30-120 seconds for large binaries."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": (
                        "Path to the ELF binary in the firmware filesystem "
                        "(e.g., '/usr/bin/httpd', '/bin/busybox')"
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_detect_capabilities,
    )

    registry.register(
        name="list_binary_capabilities",
        description=(
            "Quick summary of capability categories found in an ELF binary "
            "using FLARE capa. Returns only category names and counts — much "
            "faster to scan than full detect_capabilities output. Use this to "
            "triage multiple binaries, then call detect_capabilities on the "
            "interesting ones for full details and ATT&CK mappings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": (
                        "Path to the ELF binary in the firmware filesystem "
                        "(e.g., '/usr/bin/httpd', '/bin/busybox')"
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_binary_capabilities,
    )

    registry.register(
        name="analyze_raw_binary",
        description=(
            "Detect CPU architecture from a raw binary with no recognized "
            "ELF/PE/Mach-O headers. Uses statistical analysis (cpu_rec by "
            "Airbus, 70+ architectures) to identify the instruction set. "
            "Ideal for bare-metal firmware dumps, ROM images, bootloader "
            "extracts, and encrypted firmware where headers are stripped. "
            "Returns top architecture candidates with confidence levels."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": (
                        "Path to the raw binary file (no ELF/PE/Mach-O headers). "
                        "For firmware with recognized headers, use analyze_binary_format instead."
                    ),
                },
                "chunk_size": {
                    "type": "integer",
                    "description": (
                        "Optional: analyze the binary in chunks of this size (bytes) "
                        "to detect multiple architectures in a composite binary. "
                        "Default: 0 (analyze the whole file as one unit). "
                        "Suggested: 65536 for mixed firmware images."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_analyze_raw_binary,
    )

    registry.register(
        name="detect_rtos",
        description=(
            "Detect RTOS (Real-Time Operating System) and companion components "
            "from a firmware binary. Identifies FreeRTOS, Zephyr, VxWorks, "
            "ThreadX/Azure RTOS, QNX, SafeRTOS, and uC/OS (II & III). Also "
            "detects companion libraries: network stacks (lwIP, FreeRTOS+TCP, "
            "NetX Duo), filesystems (LittleFS, FatFS, SPIFFS), and crypto "
            "(wolfSSL, mbedTLS, tinycrypt, BearSSL). Uses 5-tier detection: "
            "magic bytes, string patterns, symbol analysis, ELF sections, and "
            "VxWorks symbol table heuristics."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to the binary file to analyze. Can be any "
                        "firmware binary (ELF, PE, raw/flat binary). "
                        "Defaults to the firmware root if omitted."
                    ),
                },
            },
        },
        handler=_handle_detect_rtos,
    )
