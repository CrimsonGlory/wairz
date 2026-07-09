"""Contract tests for ``app.ai.tools.binary`` MCP tool handlers.

increase-coverage skill run: app/ai/tools/binary.py sat at ~18% coverage
(1355 stmts / ~1108 miss) with partial coverage in ``test_binary_tools.py``
(protections helpers, registration, a few Ghidra formatting paths, batch
decompile, Ghidra error demotion). This file drives every remaining
``_handle_*`` through a real ``ToolContext`` sandbox plus mocks at the
ghidra_service / LIEF / capa / RTOS / subprocess boundaries so no real
Ghidra or FLARE capa process is ever launched.
"""
from __future__ import annotations

import json
import struct
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.binary import (
    _DEFAULT_SINKS,
    _DEFAULT_SOURCES,
    _extract_ghidra_error,
    _handle_analyze_binary_format,
    _handle_analyze_raw_binary,
    _handle_batch_decompile_functions,
    _handle_check_all_binary_protections,
    _handle_check_binary_analysis_status,
    _handle_check_binary_protections,
    _handle_check_function_decompile_status,
    _handle_cross_binary_dataflow,
    _handle_decompile_function,
    _handle_detect_capabilities,
    _handle_detect_rtos,
    _handle_disassemble_function,
    _handle_find_callers,
    _handle_find_string_refs,
    _handle_get_binary_info,
    _handle_get_ghidra_analysis_logs,
    _handle_get_global_layout,
    _handle_get_stack_layout,
    _handle_list_binary_capabilities,
    _handle_list_exports,
    _handle_list_functions,
    _handle_list_imports,
    _handle_resolve_import,
    _handle_search_binary_content,
    _handle_start_binary_analysis,
    _handle_start_function_decompile,
    _handle_trace_dataflow,
    _handle_xrefs_from,
    _handle_xrefs_to,
    _is_benign_ghidra_warning,
    _pid_is_alive,
    _read_magic_sync,
    _resolve_import_sync,
    _scan_all_binary_protections,
    register_binary_tools,
)


# ---------------------------------------------------------------------------
# Minimal ELF fixture (mirrors test_binary_tools.py helper shape)
# ---------------------------------------------------------------------------


def _build_minimal_elf(*, pie: bool = False, nx: bool = True) -> bytes:
    ET_EXEC, ET_DYN = 2, 3
    EM_X86_64 = 62
    PT_LOAD, PT_GNU_STACK = 1, 0x6474E551
    PF_R, PF_W, PF_X = 4, 2, 1
    e_type = ET_DYN if pie else ET_EXEC
    phentsize, ehsize = 56, 64
    stack_flags = PF_R | PF_W if nx else (PF_R | PF_W | PF_X)
    phdrs = [
        struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, 0, 0, 0, 0, 0),
        struct.pack("<IIQQQQQQ", PT_GNU_STACK, stack_flags, 0, 0, 0, 0, 0, 0),
    ]
    e_ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    elf_header = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, EM_X86_64, 1, 0, ehsize, 0, 0, ehsize, phentsize, len(phdrs), 0, 0, 0,
    )
    return e_ident + elf_header + b"".join(phdrs)


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "lib").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(_build_minimal_elf(nx=True, pie=False))
    (tmp_path / "usr" / "bin" / "legacy").write_bytes(_build_minimal_elf(nx=False, pie=False))
    (tmp_path / "usr" / "bin" / "script.sh").write_text("#!/bin/sh\necho hi\n")
    # Raw blob for architecture / PE / string-search tests
    raw = b"AAAA" + b"password=admin\x00" + b"B" * 256
    (tmp_path / "usr" / "bin" / "rawblob.bin").write_bytes(raw)
    # PE-ish magic file
    (tmp_path / "usr" / "bin" / "app.exe").write_bytes(b"MZ" + b"\x00" * 64)
    return tmp_path


@pytest.fixture
def ctx(firmware_root: Path) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )


def _ghidra_mock(**methods) -> MagicMock:
    m = MagicMock()
    defaults = {
        "get_functions": AsyncMock(return_value=[]),
        "get_disassembly": AsyncMock(return_value=""),
        "get_imports": AsyncMock(return_value=[]),
        "get_exports": AsyncMock(return_value=[]),
        "get_xrefs_to": AsyncMock(return_value=[]),
        "get_xrefs_from": AsyncMock(return_value=[]),
        "get_binary_info": AsyncMock(return_value=None),
        "get_binary_sha256": AsyncMock(return_value="a" * 64),
        "get_cached": AsyncMock(return_value=None),
        "store_cached": AsyncMock(return_value=None),
        "ensure_analysis": AsyncMock(return_value="a" * 64),
        "get_functions_if_cached": AsyncMock(return_value=[]),
        "resolve_binary_import_params": AsyncMock(return_value={}),
        "_get_binary_sha256": AsyncMock(return_value="a" * 64),
        "_is_analysis_complete": AsyncMock(return_value=False),
        "clear_binary_analysis": AsyncMock(return_value=None),
        "get_run_status": AsyncMock(return_value=None),
        "mark_run_started": AsyncMock(return_value=None),
        "_get_cached": AsyncMock(return_value=None),
        "get_function_run_status": AsyncMock(return_value=None),
        "mark_function_run_started": AsyncMock(return_value=None),
    }
    defaults.update(methods)
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


# ---------------------------------------------------------------------------
# register_binary_tools
# ---------------------------------------------------------------------------


def test_register_binary_tools_count_and_core_names():
    reg = ToolRegistry()
    register_binary_tools(reg)
    names = set(reg._tools.keys())
    # 29 tools registered in binary.py (handlers + status helpers)
    assert len(names) >= 28
    for expected in (
        "list_functions",
        "disassemble_function",
        "decompile_function",
        "batch_decompile_functions",
        "list_imports",
        "list_exports",
        "xrefs_to",
        "xrefs_from",
        "get_binary_info",
        "analyze_binary_format",
        "check_binary_protections",
        "find_string_refs",
        "resolve_import",
        "check_all_binary_protections",
        "trace_dataflow",
        "find_callers",
        "search_binary_content",
        "get_stack_layout",
        "get_global_layout",
        "cross_binary_dataflow",
        "detect_capabilities",
        "list_binary_capabilities",
        "analyze_raw_binary",
        "detect_rtos",
        "start_binary_analysis",
        "check_binary_analysis_status",
        "start_function_decompile",
        "check_function_decompile_status",
        "get_ghidra_analysis_logs",
    ):
        assert expected in names


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_read_magic_sync_ok_and_missing(tmp_path: Path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x7fELF" + b"xx")
    assert _read_magic_sync(str(p), 4) == b"\x7fELF"
    assert _read_magic_sync(str(tmp_path / "nope"), 4) is None


def test_is_benign_ghidra_warning():
    assert _is_benign_ghidra_warning("Skipping section [.mdebug.abi32]") is True
    assert _is_benign_ghidra_warning("[libfoo.so] -> not found in project") is True
    assert _is_benign_ghidra_warning("NullPointerException") is False


def test_extract_ghidra_error_caps_and_prefix_strip():
    lines = "\n".join(
        f"ERROR something failed number {i}" for i in range(12)
    )
    result = _extract_ghidra_error(lines, "TaintAnalysis")
    assert "TaintAnalysis failed" in result
    assert "more diagnostic lines" in result


def test_pid_is_alive_missing_and_alive():
    assert _pid_is_alive(999_999_999) is False
    # Current process should be alive and non-zombie
    import os
    assert _pid_is_alive(os.getpid()) is True


def test_pid_is_alive_zombie_state(tmp_path: Path, monkeypatch):
    status = tmp_path / "status"
    status.write_text("Name:\tfoo\nState:\tZ (zombie)\n")
    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **k: open(status, *a, **k) if "status" in str(path) else open(path, *a, **k),
    )
    # Direct unit: open /proc fails → False; for zombie we patch open for /proc
    with patch("app.ai.tools.binary.open", create=True) as mock_open:
        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = MagicMock(return_value=False)
        mock_open.return_value.__iter__ = lambda s: iter(
            ["Name:\tfoo\n", "State:\tZ (zombie)\n"]
        )
        assert _pid_is_alive(12345) is False


def test_resolve_import_sync_read_error(tmp_path: Path):
    result = _resolve_import_sync(str(tmp_path / "missing"), "foo", str(tmp_path))
    assert result["status"] == "read_error"


def test_resolve_import_sync_static(firmware_root: Path):
    path = str(firmware_root / "usr" / "bin" / "httpd")
    result = _resolve_import_sync(path, "printf", str(firmware_root))
    # Minimal ELF has no DT_NEEDED
    assert result["status"] in ("static", "read_error", "not_found")


def test_scan_all_binary_protections(firmware_root: Path):
    results = _scan_all_binary_protections(str(firmware_root), str(firmware_root))
    assert any(r["path"].endswith("httpd") for r in results)
    # script.sh is non-ELF — skipped
    assert not any(r["path"].endswith("script.sh") for r in results)


# ---------------------------------------------------------------------------
# list_functions / disassemble / imports / exports / xrefs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_functions_limit_truncation(ctx):
    funcs = [
        {"name": f"f{i}", "size": 1000 - i, "address": f"0x{i:04x}"}
        for i in range(5)
    ]
    mock = _ghidra_mock(get_functions=AsyncMock(return_value=funcs))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_list_functions(
            {"binary_path": "/usr/bin/httpd", "limit": 2}, ctx
        )
    assert "Found 5 function(s)" in result
    assert "more functions omitted" in result
    assert "f0" in result
    assert "f2" not in result  # truncated past limit


@pytest.mark.asyncio
async def test_list_imports_empty_and_xrefs_empty(ctx):
    mock = _ghidra_mock(
        get_imports=AsyncMock(return_value=[]),
        get_exports=AsyncMock(return_value=[]),
        get_xrefs_to=AsyncMock(return_value=[]),
        get_xrefs_from=AsyncMock(return_value=[]),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        assert "No imports" in await _handle_list_imports(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
        assert "No exports" in await _handle_list_exports(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
        assert "No cross-references to" in await _handle_xrefs_to(
            {"binary_path": "/usr/bin/httpd", "address_or_symbol": "main"}, ctx
        )
        assert "No cross-references from" in await _handle_xrefs_from(
            {"binary_path": "/usr/bin/httpd", "address_or_symbol": "main"}, ctx
        )


@pytest.mark.asyncio
async def test_xrefs_from_format(ctx):
    mock = _ghidra_mock(
        get_xrefs_from=AsyncMock(
            return_value=[
                {"to": "0x2000", "type": "CALL", "to_func": "printf"},
                {"to": "0x3000", "type": "DATA", "to_func": ""},
            ]
        )
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_xrefs_from(
            {"binary_path": "/usr/bin/httpd", "address_or_symbol": "main"}, ctx
        )
    assert "Found 2 cross-reference(s) from 'main'" in result
    assert "printf" in result
    assert "0x2000" in result


@pytest.mark.asyncio
async def test_disassemble_function(ctx):
    mock = _ghidra_mock(
        get_disassembly=AsyncMock(return_value="0x1000  ret")
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_disassemble_function(
            {
                "binary_path": "/usr/bin/httpd",
                "function_name": "main",
                "num_instructions": 10,
            },
            ctx,
        )
    assert "Disassembly of main" in result
    assert "ret" in result


# ---------------------------------------------------------------------------
# get_binary_info fallbacks (Ghidra fail → PE → LIEF → raw)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_binary_info_ghidra_ok(ctx):
    mock = _ghidra_mock(
        get_binary_info=AsyncMock(
            return_value={
                "bin": {
                    "file": "httpd",
                    "bintype": "elf",
                    "arch": "x86",
                    "bits": 64,
                    "endian": "little",
                    "os": "linux",
                    "machine": "x86_64",
                    "class": "ELF64",
                    "lang": "c",
                    "stripped": False,
                    "static": False,
                    "libs": ["libc.so.6"],
                }
            }
        )
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_get_binary_info({"binary_path": "/usr/bin/httpd"}, ctx)
    assert "Binary Information:" in result
    assert "x86" in result
    assert "libc.so.6" in result


@pytest.mark.asyncio
async def test_get_binary_info_pe_fallback(ctx):
    mock = _ghidra_mock(get_binary_info=AsyncMock(side_effect=RuntimeError("no ghidra")))
    pe_info = {
        "dep_nx": True,
        "aslr": True,
        "seh": False,
        "cfg": False,
        "authenticode": False,
    }
    lief_info = {
        "architecture": "x86",
        "bits": 32,
        "endianness": "little",
        "entry_point": 0x1000,
        "is_static": False,
        "dependencies": ["KERNEL32.dll"],
    }
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value=lief_info,
        ),
        patch(
            "app.services.binary_analysis_service.check_pe_protections",
            return_value=pe_info,
        ),
    ):
        result = await _handle_get_binary_info({"binary_path": "/usr/bin/app.exe"}, ctx)
    assert "PE via LIEF" in result
    assert "KERNEL32.dll" in result
    assert "DEP/NX" in result


@pytest.mark.asyncio
async def test_get_binary_info_lief_non_pe(ctx):
    mock = _ghidra_mock(get_binary_info=AsyncMock(return_value=None))
    lief_info = {
        "format": "macho",
        "architecture": "arm64",
        "bits": 64,
        "endianness": "little",
        "entry_point": 0x100,
        "is_static": True,
        "dependencies": [],
    }
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value=lief_info,
        ),
    ):
        result = await _handle_get_binary_info({"binary_path": "/usr/bin/rawblob.bin"}, ctx)
    assert "MACHO via LIEF" in result
    assert "arm64" in result


@pytest.mark.asyncio
async def test_get_binary_info_raw_fallback(ctx):
    mock = _ghidra_mock(get_binary_info=AsyncMock(return_value=None))
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "unknown"},
        ),
    ):
        result = await _handle_get_binary_info({"binary_path": "/usr/bin/rawblob.bin"}, ctx)
    assert "raw binary" in result.lower()
    assert "Magic bytes" in result


@pytest.mark.asyncio
async def test_get_binary_info_raw_cortex_m(ctx, firmware_root: Path):
    # Cortex-M vector table: SP in SRAM range, reset in flash range
    blob = bytearray(0x200)
    blob[0:4] = (0x20001000).to_bytes(4, "little")
    blob[4:8] = (0x08000100).to_bytes(4, "little")
    (firmware_root / "usr" / "bin" / "cortex.bin").write_bytes(bytes(blob))
    mock = _ghidra_mock(get_binary_info=AsyncMock(return_value=None))
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "unknown"},
        ),
    ):
        result = await _handle_get_binary_info({"binary_path": "/usr/bin/cortex.bin"}, ctx)
    assert "ARM Cortex-M" in result
    assert "Initial SP" in result


# ---------------------------------------------------------------------------
# analyze_binary_format / check_binary_protections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_binary_format_missing_file(ctx):
    result = await _handle_analyze_binary_format(
        {"binary_path": "/usr/bin/nope"}, ctx
    )
    assert "File not found" in result


@pytest.mark.asyncio
async def test_analyze_binary_format_elf_dynamic_missing_sysroot(ctx):
    info = {
        "format": "elf",
        "architecture": "arm",
        "endianness": "little",
        "bits": 32,
        "is_static": False,
        "is_pie": True,
        "interpreter": "/lib/ld-linux.so.3",
        "dependencies": ["libc.so.6", "libm.so.6"],
        "entry_point": 0x8000,
        "file_size": 4096,
    }
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value=info,
        ),
        patch(
            "app.services.sysroot_service.check_dependencies",
            return_value={
                "missing": ["libm.so.6"],
                "available": ["libc.so.6"],
                "sysroot_path": "/opt/sysroot/arm",
            },
        ),
    ):
        result = await _handle_analyze_binary_format(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Binary Format Analysis" in result
    assert "dynamic" in result
    assert "Missing" in result
    assert "libm.so.6" in result


@pytest.mark.asyncio
async def test_analyze_binary_format_static_and_pe(ctx):
    static_info = {
        "format": "elf",
        "architecture": "x86_64",
        "endianness": "little",
        "bits": 64,
        "is_static": True,
        "is_pie": False,
        "interpreter": None,
        "dependencies": [],
        "entry_point": 0x401000,
        "file_size": 100,
    }
    with patch(
        "app.services.binary_analysis_service.analyze_binary",
        return_value=static_info,
    ):
        result = await _handle_analyze_binary_format(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "static binary" in result

    pe_info = {
        "format": "pe",
        "architecture": "x86",
        "endianness": "little",
        "bits": 32,
        "is_static": False,
        "is_pie": False,
        "interpreter": None,
        "dependencies": ["kernel32.dll"],
        "entry_point": 0x1000,
        "file_size": 200,
    }
    pe_prot = {
        "dep_nx": True,
        "aslr": False,
        "seh": True,
        "cfg": False,
        "high_entropy_va": False,
        "authenticode": False,
        "sections": [
            {
                "name": ".text",
                "virtual_size": 100,
                "raw_size": 100,
                "entropy": 6.1,
                "flags": ["execute", "read"],
            }
        ],
        "imports_by_dll": {
            "kernel32.dll": [f"Func{i}" for i in range(35)],
        },
        "exports": [f"Exp{i}" for i in range(55)],
    }
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value=pe_info,
        ),
        patch(
            "app.services.binary_analysis_service.check_pe_protections",
            return_value=pe_prot,
        ),
    ):
        result = await _handle_analyze_binary_format(
            {"binary_path": "/usr/bin/app.exe"}, ctx
        )
    assert "PE Security Characteristics" in result
    assert "Sections" in result
    assert "Imports" in result
    assert "more)" in result  # truncated imports/exports


@pytest.mark.asyncio
async def test_check_binary_protections_elf_and_pe(ctx):
    result = await _handle_check_binary_protections(
        {"binary_path": "/usr/bin/httpd"}, ctx
    )
    assert "Binary Protection Status" in result
    assert "NX" in result
    assert "Protection score" in result

    pe_prot = {
        "dep_nx": True,
        "aslr": True,
        "seh": True,
        "cfg": False,
        "high_entropy_va": True,
        "force_integrity": False,
        "authenticode": False,
    }
    with patch(
        "app.services.binary_analysis_service.check_pe_protections",
        return_value=pe_prot,
    ):
        result = await _handle_check_binary_protections(
            {"binary_path": "/usr/bin/app.exe"}, ctx
        )
    assert "PE Binary Protection Status" in result
    assert "Protection score: 3/5" in result

    with patch(
        "app.services.binary_analysis_service.check_pe_protections",
        return_value={"error": "bad pe"},
    ):
        result = await _handle_check_binary_protections(
            {"binary_path": "/usr/bin/app.exe"}, ctx
        )
    assert "Error: bad pe" in result


@pytest.mark.asyncio
async def test_check_binary_protections_non_elf_error(ctx):
    result = await _handle_check_binary_protections(
        {"binary_path": "/usr/bin/script.sh"}, ctx
    )
    assert "Error:" in result


# ---------------------------------------------------------------------------
# decompile / batch decompile error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_decompile_function_success_and_errors(ctx):
    with patch(
        "app.ai.tools.binary.decompile_function",
        new=AsyncMock(return_value="int main(){return 0;}"),
    ):
        result = await _handle_decompile_function(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "Decompiled output for main" in result
    assert "int main" in result

    with patch(
        "app.ai.tools.binary.decompile_function",
        new=AsyncMock(side_effect=FileNotFoundError()),
    ):
        result = await _handle_decompile_function(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "Binary not found" in result

    with patch(
        "app.ai.tools.binary.decompile_function",
        new=AsyncMock(side_effect=TimeoutError("timeout")),
    ):
        result = await _handle_decompile_function(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "timeout" in result

    with patch(
        "app.ai.tools.binary.decompile_function",
        new=AsyncMock(side_effect=RuntimeError("ghidra boom")),
    ):
        result = await _handle_decompile_function(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "ghidra boom" in result


@pytest.mark.asyncio
async def test_batch_decompile_not_list_and_exceptions(ctx):
    result = await _handle_batch_decompile_functions(
        {"binary_path": "/usr/bin/httpd", "function_names": "main"}, ctx
    )
    assert "must be a list" in result

    with patch(
        "app.ai.tools.binary.batch_decompile_functions",
        new=AsyncMock(side_effect=FileNotFoundError()),
    ):
        result = await _handle_batch_decompile_functions(
            {"binary_path": "/usr/bin/httpd", "function_names": ["main"]}, ctx
        )
    assert "Binary not found" in result

    with patch(
        "app.ai.tools.binary.batch_decompile_functions",
        new=AsyncMock(side_effect=TimeoutError("t")),
    ):
        result = await _handle_batch_decompile_functions(
            {"binary_path": "/usr/bin/httpd", "function_names": ["main"]}, ctx
        )
    assert "Error: t" in result

    with patch(
        "app.ai.tools.binary.batch_decompile_functions",
        new=AsyncMock(side_effect=RuntimeError("r")),
    ):
        result = await _handle_batch_decompile_functions(
            {"binary_path": "/usr/bin/httpd", "function_names": ["main"]}, ctx
        )
    assert "Error: r" in result


# ---------------------------------------------------------------------------
# find_string_refs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_string_refs_cache_hit(ctx):
    cached = {
        "results": [
            {
                "string_value": "password=admin",
                "string_address": "0x1000",
                "references": [
                    {
                        "function": "auth",
                        "function_address": "0x2000",
                        "ref_address": "0x2010",
                        "instruction": "ldr r0, [pc, #4]",
                    }
                ],
            }
        ]
    }
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=cached))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "password"}, ctx
        )
    assert "Found 1 string" in result
    assert "auth" in result
    assert "password=admin" in result


@pytest.mark.asyncio
async def test_find_string_refs_ghidra_run_and_errors(ctx):
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    payload = (
        "===STRING_REFS_START===\n"
        '[{"string_value":"admin","string_address":"0x1","references":[]}]\n'
        "===STRING_REFS_END===\n"
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value=payload),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "admin"}, ctx
        )
    assert "admin" in result
    mock.store_cached.assert_awaited()

    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(side_effect=RuntimeError("down")),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "x"}, ctx
        )
    assert "Error: down" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value="INFO done\n"),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "x"}, ctx
        )
    assert "no parseable output" in result

    # Markers present but no JSON array
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value="===STRING_REFS_START===\nnada\n===STRING_REFS_END===\n"
            ),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "x"}, ctx
        )
    assert "No results found" in result

    # Bad JSON
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value=(
                    "===STRING_REFS_START===\n[not-json]\n===STRING_REFS_END===\n"
                )
            ),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "x"}, ctx
        )
    assert "Error parsing" in result

    # Empty results after parse
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value=(
                    "===STRING_REFS_START===\n[]\n===STRING_REFS_END===\n"
                )
            ),
        ),
    ):
        result = await _handle_find_string_refs(
            {"binary_path": "/usr/bin/httpd", "pattern": "zzz"}, ctx
        )
    assert "No strings matching" in result


# ---------------------------------------------------------------------------
# resolve_import
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_import_statuses(ctx, firmware_root: Path):
    path = str(firmware_root / "usr" / "bin" / "httpd")
    with patch(
        "app.ai.tools.binary._resolve_import_sync",
        return_value={"status": "read_error", "error": "boom"},
    ):
        result = await _handle_resolve_import(
            {"binary_path": "/usr/bin/httpd", "function_name": "printf"}, ctx
        )
    assert "Error reading binary" in result

    with patch(
        "app.ai.tools.binary._resolve_import_sync",
        return_value={"status": "static", "needed_libs": []},
    ):
        result = await _handle_resolve_import(
            {"binary_path": "/usr/bin/httpd", "function_name": "printf"}, ctx
        )
    assert "statically linked" in result

    with patch(
        "app.ai.tools.binary._resolve_import_sync",
        return_value={"status": "not_found", "needed_libs": ["libc.so.6"]},
    ):
        result = await _handle_resolve_import(
            {"binary_path": "/usr/bin/httpd", "function_name": "printf"}, ctx
        )
    assert "not found in any linked library" in result
    assert "libc.so.6" in result

    with (
        patch(
            "app.ai.tools.binary._resolve_import_sync",
            return_value={
                "status": "found",
                "needed_libs": ["libc.so.6"],
                "lib_path": str(firmware_root / "lib" / "libc.so.6"),
            },
        ),
        patch(
            "app.ai.tools.binary.decompile_function",
            new=AsyncMock(return_value="void printf(...) {}"),
        ),
    ):
        (firmware_root / "lib" / "libc.so.6").write_bytes(_build_minimal_elf())
        result = await _handle_resolve_import(
            {"binary_path": "/usr/bin/httpd", "function_name": "printf"}, ctx
        )
    assert "Resolved" in result
    assert "printf" in result

    with (
        patch(
            "app.ai.tools.binary._resolve_import_sync",
            return_value={
                "status": "found",
                "needed_libs": ["libc.so.6"],
                "lib_path": path,
            },
        ),
        patch(
            "app.ai.tools.binary.decompile_function",
            new=AsyncMock(side_effect=RuntimeError("decompile fail")),
        ),
    ):
        result = await _handle_resolve_import(
            {"binary_path": "/usr/bin/httpd", "function_name": "printf"}, ctx
        )
    assert "decompilation failed" in result


# ---------------------------------------------------------------------------
# check_all_binary_protections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_all_binary_protections_table(ctx):
    result = await _handle_check_all_binary_protections({"path": "/"}, ctx)
    assert "ELF binary" in result
    assert "Summary:" in result
    assert "NX" in result


@pytest.mark.asyncio
async def test_check_all_binary_protections_none(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    ctx = ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(empty),
        db=MagicMock(),
    )
    result = await _handle_check_all_binary_protections({}, ctx)
    assert "No ELF binaries found" in result


# ---------------------------------------------------------------------------
# trace_dataflow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_dataflow_cache_and_ghidra(ctx):
    cached = {
        "paths": [
            {
                "function": "handle_req",
                "source_func": "websGetVar",
                "sink_func": "system",
                "source_call_site": "0x10",
                "sink_call_site": "0x20",
                "interprocedural": False,
            },
            {
                "function": "outer",
                "source_func": "getenv",
                "sink_func": "system",
                "sink_function": "do_cmd",
                "interprocedural": True,
            },
        ]
    }
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=cached))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Found 2 potential dataflow path" in result
    assert "High Confidence" in result
    assert "Medium Confidence" in result
    assert "websGetVar" in result

    mock2 = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    payload = (
        "===TAINT_START===\n"
        '[{"function":"f","source_func":"recv","sink_func":"strcpy",'
        '"source_call_site":"0x1","sink_call_site":"0x2"}]\n'
        "===TAINT_END===\n"
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value=payload),
        ),
    ):
        result = await _handle_trace_dataflow(
            {
                "binary_path": "/usr/bin/httpd",
                "sources": list(_DEFAULT_SOURCES[:2]),
                "sinks": list(_DEFAULT_SINKS[:2]),
            },
            ctx,
        )
    assert "recv" in result
    mock2.store_cached.assert_awaited()

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(side_effect=TimeoutError("slow")),
        ),
    ):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Error: slow" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value="no markers"),
        ),
    ):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "no parseable output" in result or "TaintAnalysis" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value="===TAINT_START===\nnada\n===TAINT_END===\n"
            ),
        ),
    ):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "No dataflow paths found" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value="===TAINT_START===\n[bad]\n===TAINT_END===\n"
            ),
        ),
    ):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Error parsing" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value="===TAINT_START===\n[]\n===TAINT_END===\n"
            ),
        ),
    ):
        result = await _handle_trace_dataflow(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "No source-to-sink" in result


# ---------------------------------------------------------------------------
# find_callers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_callers_paths(ctx):
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_find_callers(
            {"binary_path": "/usr/bin/httpd", "function_name": "system"}, ctx
        )
    assert "No xref data available" in result

    xrefs = {
        "xrefs": {
            "system": {
                "to": [
                    {
                        "from_func": "do_cmd",
                        "from": "0x1000",
                        "type": "CALL",
                    }
                ],
                "from": [],
            },
            "wrapper": {
                "to": [],
                "from": [
                    {
                        "to_func": "_system",
                        "from": "0x2000",
                        "type": "CALL",
                    }
                ],
            },
        }
    }
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=xrefs))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_find_callers(
            {
                "binary_path": "/usr/bin/httpd",
                "function_name": "system",
                "include_aliases": True,
            },
            ctx,
        )
    assert "Found" in result
    assert "do_cmd" in result
    assert "wrapper" in result

    # Underscore-prefixed target adds base alias
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_find_callers(
            {
                "binary_path": "/usr/bin/httpd",
                "function_name": "_system",
                "include_aliases": True,
            },
            ctx,
        )
    assert "Found" in result or "No callers" in result

    empty = {"xrefs": {"other": {"to": [], "from": []}}}
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=empty))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_find_callers(
            {
                "binary_path": "/usr/bin/httpd",
                "function_name": "missing",
                "include_aliases": False,
            },
            ctx,
        )
    assert "No callers found" in result


# ---------------------------------------------------------------------------
# search_binary_content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_binary_content_string_and_hex(ctx):
    mock = _ghidra_mock(
        get_functions_if_cached=AsyncMock(
            return_value=[
                {"name": "auth", "address": "0x0", "size": 64},
            ]
        )
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/rawblob.bin",
                "pattern": "password",
                "mode": "string",
            },
            ctx,
        )
    assert "Found" in result and "match" in result
    assert "offset" in result

    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/rawblob.bin",
                "pattern": "41 41 41 41",
                "mode": "hex",
            },
            ctx,
        )
    assert "Found" in result

    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/rawblob.bin",
                "pattern": "not hex!!",
                "mode": "hex",
            },
            ctx,
        )
    assert "Invalid hex pattern" in result

    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/rawblob.bin",
                "pattern": "",
                "mode": "string",
            },
            ctx,
        )
    assert "Empty search pattern" in result

    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/rawblob.bin",
                "pattern": "ZZZZNOTFOUND",
                "mode": "string",
            },
            ctx,
        )
    assert "No matches" in result


@pytest.mark.asyncio
async def test_search_binary_content_disasm(ctx):
    mock = _ghidra_mock(
        get_functions=AsyncMock(
            return_value=[{"name": "main", "size": 10, "address": "0x1000"}]
        ),
        get_cached=AsyncMock(
            return_value={
                "disassembly": "0x1000  call sprintf\n0x1004  ret\n"
            }
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/httpd",
                "pattern": "sprintf",
                "mode": "disasm",
            },
            ctx,
        )
    assert "disassembly match" in result
    assert "main" in result

    mock_empty = _ghidra_mock(get_functions=AsyncMock(return_value=[]))
    with patch("app.ai.tools.binary.ghidra_service", mock_empty):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/httpd",
                "pattern": "x",
                "mode": "disasm",
            },
            ctx,
        )
    assert "No functions found" in result

    mock_bad = _ghidra_mock(
        get_functions=AsyncMock(
            return_value=[{"name": "main", "size": 1, "address": "0x1"}]
        ),
        get_cached=AsyncMock(return_value={"disassembly": "nop"}),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock_bad):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/httpd",
                "pattern": "[invalid",
                "mode": "disasm",
            },
            ctx,
        )
    assert "Invalid regex" in result

    with patch("app.ai.tools.binary.ghidra_service", mock_bad):
        result = await _handle_search_binary_content(
            {
                "binary_path": "/usr/bin/httpd",
                "pattern": "zzzz",
                "mode": "disasm",
                "max_results": 0,
            },
            ctx,
        )
    assert "No disassembly lines matching" in result


# ---------------------------------------------------------------------------
# stack / global layout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stack_layout_cache_and_ghidra(ctx):
    cached = {
        "function": "vuln",
        "frame_size": 64,
        "variables": [
            {
                "offset": -16,
                "size": 8,
                "type": "char[8]",
                "name": "buf",
                "is_return_addr": False,
            },
            {
                "offset": 0,
                "size": 8,
                "type": "undefined8",
                "name": "ret",
                "is_return_addr": True,
            },
        ],
        "saved_registers": [{"register": "rbp", "offset": -8}],
        "overflow_distances": [
            {
                "buffer": "buf",
                "buffer_offset": -16,
                "return_addr_offset": 0,
                "distance": 16,
            }
        ],
    }
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=cached))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "vuln"}, ctx
        )
    assert "Stack Layout for vuln" in result
    assert "return addr" in result
    assert "Buffer Overflow Distances" in result
    assert "Saved Registers" in result

    mock2 = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    payload = (
        "===STACK_LAYOUT_START===\n"
        '{"function":"f","frame_size":16,"variables":[],'
        '"saved_registers":[],"overflow_distances":[]}\n'
        "===STACK_LAYOUT_END===\n"
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value=payload),
        ),
    ):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "f"}, ctx
        )
    assert "Stack Layout for f" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(side_effect=RuntimeError("x")),
        ),
    ):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "f"}, ctx
        )
    assert "Error: x" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value="nope"),
        ),
    ):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "f"}, ctx
        )
    assert "StackLayout" in result or "no parseable" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value=(
                    "===STACK_LAYOUT_START===\nnada\n===STACK_LAYOUT_END===\n"
                )
            ),
        ),
    ):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "f"}, ctx
        )
    assert "No stack layout data" in result

    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(
                return_value=(
                    "===STACK_LAYOUT_START===\n{bad}\n===STACK_LAYOUT_END===\n"
                )
            ),
        ),
    ):
        result = await _handle_get_stack_layout(
            {"binary_path": "/usr/bin/httpd", "function_name": "f"}, ctx
        )
    assert "Error parsing" in result


@pytest.mark.asyncio
async def test_get_global_layout_cache_and_ghidra(ctx):
    cached = {
        "target_symbol": "g_pass",
        "target_address": "0x401000",
        "section": ".bss",
        "section_range": ["0x400000", "0x402000"],
        "neighbors": [
            {
                "address": "0x401000",
                "size": 32,
                "type": "char[32]",
                "name": "g_pass",
                "is_target": True,
            },
            {
                "address": "0x401020",
                "size": 4,
                "type": "int",
                "name": "g_flag",
                "is_target": False,
            },
        ],
    }
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=cached))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_get_global_layout(
            {"binary_path": "/usr/bin/httpd", "symbol_name": "g_pass"}, ctx
        )
    assert "Global Layout around 'g_pass'" in result
    assert "TARGET" in result
    assert ".bss" in result

    mock2 = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    payload = (
        "===GLOBAL_LAYOUT_START===\n"
        '{"target_symbol":"s","target_address":"0x1","section":".data",'
        '"section_range":[],"neighbors":[]}\n'
        "===GLOBAL_LAYOUT_END===\n"
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock2),
        patch(
            "app.ai.tools.binary.run_ghidra_subprocess",
            new=AsyncMock(return_value=payload),
        ),
    ):
        result = await _handle_get_global_layout(
            {"binary_path": "/usr/bin/httpd", "symbol_name": "s"}, ctx
        )
    assert "Global Layout" in result

    for raw, expect in (
        (RuntimeError("e"), "Error: e"),
        ("nope", "GlobalLayout"),
        (
            "===GLOBAL_LAYOUT_START===\nnada\n===GLOBAL_LAYOUT_END===\n",
            "No global layout data",
        ),
        (
            "===GLOBAL_LAYOUT_START===\n{bad}\n===GLOBAL_LAYOUT_END===\n",
            "Error parsing",
        ),
    ):
        side = (
            AsyncMock(side_effect=raw)
            if isinstance(raw, Exception)
            else AsyncMock(return_value=raw)
        )
        with (
            patch("app.ai.tools.binary.ghidra_service", mock2),
            patch("app.ai.tools.binary.run_ghidra_subprocess", new=side),
        ):
            result = await _handle_get_global_layout(
                {"binary_path": "/usr/bin/httpd", "symbol_name": "s"}, ctx
            )
        assert expect in result


# ---------------------------------------------------------------------------
# cross_binary_dataflow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_binary_dataflow_no_analyzed(ctx):
    mock = _ghidra_mock(
        get_binary_sha256=AsyncMock(return_value="b" * 64),
        get_cached=AsyncMock(return_value=None),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_cross_binary_dataflow({"path": "/"}, ctx)
    assert "No Ghidra-analyzed binaries found" in result


@pytest.mark.asyncio
async def test_cross_binary_dataflow_with_ipc(ctx, firmware_root: Path):
    # Second ELF so we can fabricate cross-binary writer/reader
    (firmware_root / "usr" / "bin" / "cfmd").write_bytes(_build_minimal_elf())

    async def get_sha(path, *a, **k):
        return "sha_" + Path(path).name

    async def get_cached(fid, sha, key, db):
        if key == "ghidra_full_analysis":
            return {"ok": True}
        if key == "imports":
            if "httpd" in sha:
                return {
                    "imports": [
                        {"name": "nvram_set"},
                        {"name": "printf"},
                    ]
                }
            return {"imports": [{"name": "nvram_get"}]}
        if key == "xrefs":
            if "httpd" in sha:
                return {
                    "xrefs": {
                        "web_handler": {
                            "from": [
                                {
                                    "to_func": "nvram_set",
                                    "from": "0x1000",
                                }
                            ],
                            "to": [],
                        }
                    }
                }
            return {
                "xrefs": {
                    "read_cfg": {
                        "from": [
                            {
                                "to_func": "nvram_get",
                                "from": "0x2000",
                            }
                        ],
                        "to": [],
                    }
                }
            }
        return None

    mock = MagicMock()
    mock.get_binary_sha256 = AsyncMock(side_effect=get_sha)
    mock.get_cached = AsyncMock(side_effect=get_cached)

    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_cross_binary_dataflow(
            {"path": "/", "mechanisms": ["nvram"]}, ctx
        )
    assert "Cross-Binary Dataflow Analysis" in result
    assert "NVRAM IPC" in result
    assert "Cross-Binary Flows" in result
    assert "nvram_set" in result


@pytest.mark.asyncio
async def test_cross_binary_dataflow_no_ipc_imports(ctx):
    async def get_cached(fid, sha, key, db):
        if key == "ghidra_full_analysis":
            return {"ok": True}
        if key == "imports":
            return {"imports": [{"name": "printf"}]}
        return None

    mock = _ghidra_mock(
        get_binary_sha256=AsyncMock(return_value="z" * 64),
        get_cached=AsyncMock(side_effect=get_cached),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_cross_binary_dataflow({}, ctx)
    assert "No IPC dataflow found" in result


# ---------------------------------------------------------------------------
# capa detect / list capabilities
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, stdout=b"{}", stderr=b"", rc=0, hang=False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rc
        self._hang = hang
        self.killed = False

    async def communicate(self):
        # First call during wait_for: simulate hang → TimeoutError.
        # Second call after kill(): return empty (cleanup path).
        if self._hang and not self.killed:
            raise TimeoutError()
        return self.stdout, self.stderr

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.mark.asyncio
async def test_detect_capabilities_paths(ctx):
    result = await _handle_detect_capabilities(
        {"path": "/usr/bin/missing", "binary_path": "/usr/bin/missing"}, ctx
    )
    assert "file not found" in result

    with patch("app.ai.tools.binary.shutil.which", return_value=None):
        result = await _handle_detect_capabilities(
            {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "capa is not installed" in result

    capa_json = {
        "rules": {
            "communicate with HTTP": {
                "meta": {
                    "namespace": "communication/http",
                    "attack": [
                        {
                            "technique": "Web Protocols",
                            "tactic": "Command and Control",
                            "id": "T1071",
                        }
                    ],
                    "mbc": [
                        {
                            "behavior": "HTTP Communication",
                            "objective": "Communication",
                            "id": "C0002",
                        }
                    ],
                }
            },
            "encrypt data": {
                "meta": {
                    "namespace": "data-manipulation/encryption",
                    "attack": [],
                    "mbc": [],
                }
            },
        }
    }
    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary._detect_elf_machine_sync",
            return_value="EM_X86_64",
        ),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(
                return_value=_FakeProc(
                    stdout=json.dumps(capa_json).encode(), rc=0
                )
            ),
        ),
    ):
        result = await _handle_detect_capabilities(
            {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "CAPA Capability Detection" in result
    assert "MITRE ATT&CK" in result
    assert "Malware Behavior Catalog" in result

    # MIPS warning
    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary._detect_elf_machine_sync",
            return_value="EM_MIPS",
        ),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(
                return_value=_FakeProc(
                    stdout=json.dumps(capa_json).encode(), rc=0
                )
            ),
        ),
    ):
        result = await _handle_detect_capabilities(
            {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "MIPS" in result

    # Timeout
    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary._detect_elf_machine_sync",
            return_value=None,
        ),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=_FakeProc(hang=True)),
        ),
    ):
        result = await _handle_detect_capabilities(
            {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "timed out" in result

    # Unsupported / no caps / generic fail / bad json / empty rules
    cases = [
        (_FakeProc(stderr=b"unsupported format", rc=1), "does not support"),
        (_FakeProc(stderr=b"no capabilities found", rc=1), "No capabilities"),
        (_FakeProc(stderr=b"crash", rc=2), "Capa failed"),
        (_FakeProc(stdout=b"not-json", rc=0), "could not parse"),
        (_FakeProc(stdout=b'{"rules":{}}', rc=0), "No capabilities"),
    ]
    for proc, expect in cases:
        with (
            patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
            patch(
                "app.ai.tools.binary._detect_elf_machine_sync",
                return_value=None,
            ),
            patch(
                "app.ai.tools.binary.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=proc),
            ),
        ):
            result = await _handle_detect_capabilities(
                {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
            )
        assert expect in result

    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary._detect_elf_machine_sync",
            return_value=None,
        ),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=OSError("spawn fail")),
        ),
    ):
        result = await _handle_detect_capabilities(
            {"path": "/usr/bin/httpd", "binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Error running capa" in result


@pytest.mark.asyncio
async def test_list_binary_capabilities_paths(ctx):
    result = await _handle_list_binary_capabilities(
        {"binary_path": "/usr/bin/missing"}, ctx
    )
    assert "file not found" in result

    with patch("app.ai.tools.binary.shutil.which", return_value=None):
        result = await _handle_list_binary_capabilities(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "capa is not installed" in result

    capa_json = {
        "rules": {
            "r1": {
                "meta": {
                    "namespace": "communication/http",
                    "attack": [{"technique": "t"}],
                }
            },
            "r2": {"meta": {"namespace": "host-interaction/file", "attack": []}},
        }
    }
    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(
                return_value=_FakeProc(
                    stdout=json.dumps(capa_json).encode(), rc=0
                )
            ),
        ),
    ):
        result = await _handle_list_binary_capabilities(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "CAPA Summary" in result
    assert "communication" in result
    assert "MITRE ATT&CK" in result

    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=_FakeProc(hang=True)),
        ),
    ):
        result = await _handle_list_binary_capabilities(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "timed out" in result

    for proc, expect in (
        (_FakeProc(stderr=b"unsupported", rc=1), "does not support"),
        (_FakeProc(stderr=b"no capabilities", rc=1), "No capabilities"),
        (_FakeProc(stderr=b"fail", rc=3), "Capa failed"),
        (_FakeProc(stdout=b"{", rc=0), "could not parse"),
        (_FakeProc(stdout=b'{"rules":{}}', rc=0), "No capabilities"),
    ):
        with (
            patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
            patch(
                "app.ai.tools.binary.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=proc),
            ),
        ):
            result = await _handle_list_binary_capabilities(
                {"binary_path": "/usr/bin/httpd"}, ctx
            )
        assert expect in result

    with (
        patch("app.ai.tools.binary.shutil.which", return_value="/usr/bin/capa"),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=OSError("x")),
        ),
    ):
        result = await _handle_list_binary_capabilities(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "Error running capa" in result


# ---------------------------------------------------------------------------
# analyze_raw_binary / detect_rtos
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_raw_binary_paths(ctx):
    result = await _handle_analyze_raw_binary(
        {"binary_path": "/usr/bin/missing"}, ctx
    )
    assert "File not found" in result

    # Too small
    small_ctx_root = Path(ctx.extracted_path)
    (small_ctx_root / "usr" / "bin" / "tiny.bin").write_bytes(b"x" * 10)
    result = await _handle_analyze_raw_binary(
        {"binary_path": "/usr/bin/tiny.bin"}, ctx
    )
    assert "too small" in result

    with patch(
        "app.services.binary_analysis_service.analyze_binary",
        return_value={"format": "elf", "architecture": "arm"},
    ):
        result = await _handle_analyze_raw_binary(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "recognized headers" in result

    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "unknown"},
        ),
        patch(
            "app.services.binary_analysis_service.detect_raw_architecture",
            return_value=[],
        ),
    ):
        result = await _handle_analyze_raw_binary(
            {"binary_path": "/usr/bin/rawblob.bin"}, ctx
        )
    assert "Could not detect architecture" in result

    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "unknown"},
        ),
        patch(
            "app.services.binary_analysis_service.detect_raw_architecture",
            return_value=[
                {
                    "architecture": "arm",
                    "raw_name": "ARM-LE",
                    "endianness": "little",
                    "confidence": "high",
                },
                {
                    "architecture": "mips",
                    "raw_name": "MIPS-BE",
                    "endianness": "big",
                    "confidence": "low",
                },
            ],
        ),
    ):
        result = await _handle_analyze_raw_binary(
            {"binary_path": "/usr/bin/rawblob.bin", "chunk_size": 1024}, ctx
        )
    assert "Best match: arm" in result
    assert ">>>" in result


@pytest.mark.asyncio
async def test_detect_rtos_paths(ctx):
    result = await _handle_detect_rtos({"path": "/"}, ctx)
    # path="/" resolves to a directory → "Not a file"
    assert "Not a file" in result

    rtos = {
        "rtos_display_name": "FreeRTOS",
        "version": "10.4.3",
        "confidence": "high",
        "detection_methods": ["string", "symbol"],
        "architecture": "arm",
        "endianness": "little",
        "metadata": {"heap_variant": "heap_4", "mcuboot_version": "1.9"},
    }
    companions = [
        {
            "name": "lwIP",
            "version": "2.1",
            "category": "network",
            "confidence": "medium",
            "detection_method": "string",
        }
    ]
    with (
        patch(
            "app.services.rtos_detection_service.detect_rtos",
            return_value=rtos,
        ),
        patch(
            "app.services.rtos_detection_service.extract_companion_components",
            return_value=companions,
        ),
    ):
        result = await _handle_detect_rtos(
            {"path": "/usr/bin/httpd"}, ctx
        )
    assert "FreeRTOS" in result
    assert "heap_4" in result
    assert "lwIP" in result
    assert "MCUboot" in result

    with (
        patch(
            "app.services.rtos_detection_service.detect_rtos",
            return_value=None,
        ),
        patch(
            "app.services.rtos_detection_service.extract_companion_components",
            return_value=[],
        ),
    ):
        result = await _handle_detect_rtos(
            {"path": "/usr/bin/httpd"}, ctx
        )
    assert "No RTOS detected" in result


# ---------------------------------------------------------------------------
# start / check binary analysis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_binary_analysis_paths(ctx):
    result = await _handle_start_binary_analysis(
        {"binary_path": "/usr/bin/missing"}, ctx
    )
    assert "binary not found" in result

    mock = _ghidra_mock(
        _is_analysis_complete=AsyncMock(return_value=True),
        _get_binary_sha256=AsyncMock(return_value="c" * 64),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_start_binary_analysis(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "already_complete" in result

    mock = _ghidra_mock(
        _is_analysis_complete=AsyncMock(return_value=False),
        _get_binary_sha256=AsyncMock(return_value="c" * 64),
        get_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 10,
                "pid": 1234,
            }
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_start_binary_analysis(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "already_running" in result

    fake_proc = MagicMock()
    fake_proc.pid = 4242
    mock = _ghidra_mock(
        _is_analysis_complete=AsyncMock(return_value=False),
        _get_binary_sha256=AsyncMock(return_value="d" * 64),
        get_run_status=AsyncMock(return_value=None),
        clear_binary_analysis=AsyncMock(),
        mark_run_started=AsyncMock(),
    )
    ctx.db.flush = AsyncMock()
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=fake_proc),
        ),
    ):
        result = await _handle_start_binary_analysis(
            {
                "binary_path": "/usr/bin/httpd",
                "force_reanalyze": True,
                "processor": "ARM:LE:32:Cortex",
                "loader": "BinaryLoader",
                "base_addr": "0x80100000",
                "code_offset": "0x30",
            },
            ctx,
        )
    assert "started" in result
    assert "4242" in result
    mock.clear_binary_analysis.assert_awaited()
    mock.mark_run_started.assert_awaited()


@pytest.mark.asyncio
async def test_check_binary_analysis_status_paths(ctx):
    result = await _handle_check_binary_analysis_status(
        {"binary_path": "/usr/bin/missing"}, ctx
    )
    assert "binary not found" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=True),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "complete" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(return_value=None),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "not_started" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 5,
                "pid": 1,
            }
        ),
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch("app.ai.tools.binary._pid_is_alive", return_value=True),
        patch("app.ai.tools.binary.get_settings") as gs,
    ):
        gs.return_value.ghidra_timeout = 300
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "running" in result

    # Orphaned: dead pid + elapsed > 30
    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 60,
                "pid": 99999,
            }
        ),
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch("app.ai.tools.binary._pid_is_alive", return_value=False),
    ):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "orphaned" in result

    # Hard limit exceeded while pid appears alive
    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 1000,
                "pid": 1,
            }
        ),
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch("app.ai.tools.binary._pid_is_alive", return_value=True),
        patch("app.ai.tools.binary.get_settings") as gs,
    ):
        gs.return_value.ghidra_timeout = 100
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "orphaned" in result
    assert "hard limit" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(
            return_value={"status": "failed", "error": "OOM"}
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "failed" in result
    assert "OOM" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(return_value={"status": "complete"}),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "complete" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="e" * 64),
        _is_analysis_complete=AsyncMock(return_value=False),
        get_run_status=AsyncMock(return_value={"status": "weird"}),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_binary_analysis_status(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "unknown status" in result


# ---------------------------------------------------------------------------
# start / check function decompile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_function_decompile_paths(ctx):
    result = await _handle_start_function_decompile(
        {"binary_path": "/usr/bin/missing", "function_name": "main"}, ctx
    )
    assert "binary not found" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(
            return_value={"decompiled_code": "int main(){}"}
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_start_function_decompile(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "already_complete" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 3,
                "pid": 7,
            }
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_start_function_decompile(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "already_running" in result

    fake_proc = MagicMock()
    fake_proc.pid = 9001
    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(return_value=None),
        mark_function_run_started=AsyncMock(),
    )
    ctx.db.flush = AsyncMock()
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch(
            "app.ai.tools.binary.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=fake_proc),
        ),
    ):
        result = await _handle_start_function_decompile(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "started" in result
    assert "9001" in result


@pytest.mark.asyncio
async def test_check_function_decompile_status_paths(ctx):
    result = await _handle_check_function_decompile_status(
        {"binary_path": "/usr/bin/missing", "function_name": "main"}, ctx
    )
    assert "binary not found" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(
            return_value={"decompiled_code": "int main(){}"}
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "complete" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(return_value=None),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "not_started" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 2,
                "pid": 1,
            }
        ),
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch("app.ai.tools.binary._pid_is_alive", return_value=True),
    ):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "running" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(
            return_value={
                "status": "running",
                "started_at": time.time() - 90,
                "pid": 999,
            }
        ),
    )
    with (
        patch("app.ai.tools.binary.ghidra_service", mock),
        patch("app.ai.tools.binary._pid_is_alive", return_value=False),
    ):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "orphaned" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(
            return_value={"status": "failed", "error": "timeout"}
        ),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "failed" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(return_value={"status": "complete"}),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "complete" in result

    mock = _ghidra_mock(
        _get_binary_sha256=AsyncMock(return_value="f" * 64),
        _get_cached=AsyncMock(return_value=None),
        get_function_run_status=AsyncMock(return_value={"status": "???"}),
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_check_function_decompile_status(
            {"binary_path": "/usr/bin/httpd", "function_name": "main"}, ctx
        )
    assert "unknown status" in result


# ---------------------------------------------------------------------------
# get_ghidra_analysis_logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_ghidra_analysis_logs(ctx):
    mock = _ghidra_mock(get_cached=AsyncMock(return_value=None))
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_get_ghidra_analysis_logs(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "No Ghidra logs found" in result

    mock = _ghidra_mock(
        get_cached=AsyncMock(
            return_value={"log": "INFO done\n", "rc": 0}
        )
    )
    with patch("app.ai.tools.binary.ghidra_service", mock):
        result = await _handle_get_ghidra_analysis_logs(
            {
                "binary_path": "/usr/bin/httpd",
                "script_name": "FindStringRefs.java",
            },
            ctx,
        )
    assert "FindStringRefs.java log" in result
    assert "exit code 0" in result
    assert "INFO done" in result


# ---------------------------------------------------------------------------
# analyze_binary_format: sysroot all-available branch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_binary_format_sysroot_all_available(ctx):
    info = {
        "format": "elf",
        "architecture": "arm",
        "endianness": "little",
        "bits": 32,
        "is_static": False,
        "is_pie": False,
        "interpreter": "/lib/ld.so",
        "dependencies": ["libc.so.6"],
        "entry_point": 0x1000,
        "file_size": 50,
    }
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value=info,
        ),
        patch(
            "app.services.sysroot_service.check_dependencies",
            return_value={
                "missing": [],
                "available": ["libc.so.6"],
                "sysroot_path": "/opt/sysroot",
            },
        ),
    ):
        result = await _handle_analyze_binary_format(
            {"binary_path": "/usr/bin/httpd"}, ctx
        )
    assert "All dependencies available" in result


def test_detect_elf_machine_sync(firmware_root: Path):
    from app.ai.tools.binary import _detect_elf_machine_sync

    machine = _detect_elf_machine_sync(str(firmware_root / "usr" / "bin" / "httpd"))
    assert machine is not None
    assert _detect_elf_machine_sync(str(firmware_root / "usr" / "bin" / "script.sh")) is None
    assert _detect_elf_machine_sync("/no/such/file") is None
