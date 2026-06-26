"""Tests for the binary analysis AI tools and analysis service."""

import struct
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.binary import _resolve_binary_path, register_binary_tools
from app.models.ghidra_research import GhidraResearchFile
from app.models.project import Project
from app.services.analysis_service import check_binary_protections
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Helpers: Build a minimal valid ELF binary in memory
# ---------------------------------------------------------------------------


def _build_minimal_elf(
    *,
    arch: str = "x86_64",
    pie: bool = False,
    nx: bool = True,
    has_relro: bool = False,
    has_bind_now: bool = False,
) -> bytes:
    """Build a minimal valid ELF binary for testing pyelftools-based checks.

    This produces a valid ELF header + program headers. Not executable,
    but enough for pyelftools to parse protections.
    """
    # ELF header constants
    EI_NIDENT = 16
    ET_EXEC = 2
    ET_DYN = 3
    EM_X86_64 = 62
    PT_LOAD = 1
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PT_DYNAMIC = 2
    PF_R = 4
    PF_W = 2
    PF_X = 1
    DT_BIND_NOW = 24
    DT_NULL = 0

    e_type = ET_DYN if pie else ET_EXEC
    phentsize = 56  # 64-bit program header size
    ehsize = 64  # 64-bit ELF header size

    # Build program headers
    phdrs = []

    # PT_LOAD (text segment)
    phdrs.append(struct.pack(
        "<IIQQQQQQ",
        PT_LOAD, PF_R | PF_X, 0, 0, 0, 0, 0, 0,
    ))

    # PT_GNU_STACK
    stack_flags = PF_R | PF_W  # No PF_X = NX enabled
    if not nx:
        stack_flags |= PF_X
    phdrs.append(struct.pack(
        "<IIQQQQQQ",
        PT_GNU_STACK, stack_flags, 0, 0, 0, 0, 0, 0,
    ))

    if has_relro:
        phdrs.append(struct.pack(
            "<IIQQQQQQ",
            PT_GNU_RELRO, PF_R, 0, 0, 0, 0, 0, 0,
        ))

    if has_bind_now:
        # PT_DYNAMIC with DT_BIND_NOW entry
        # We'll place the dynamic section data after all headers
        dyn_offset = ehsize + len(phdrs) * phentsize + phentsize  # after this phdr
        dyn_data = struct.pack("<qQ", DT_BIND_NOW, 0)
        dyn_data += struct.pack("<qQ", DT_NULL, 0)
        dyn_size = len(dyn_data)

        phdrs.append(struct.pack(
            "<IIQQQQQQ",
            PT_DYNAMIC, PF_R | PF_W,
            dyn_offset, 0, 0,
            dyn_size, dyn_size, 0,
        ))
    else:
        dyn_data = b""

    phnum = len(phdrs)

    # ELF header (64-bit little-endian)
    e_ident = (
        b"\x7fELF"  # magic
        + b"\x02"    # EI_CLASS: ELFCLASS64
        + b"\x01"    # EI_DATA: ELFDATA2LSB
        + b"\x01"    # EI_VERSION: EV_CURRENT
        + b"\x00"    # EI_OSABI
        + b"\x00" * 8  # EI_ABIVERSION + padding
    )

    elf_header = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,       # e_type
        EM_X86_64,    # e_machine
        1,            # e_version
        0,            # e_entry
        ehsize,       # e_phoff (program headers right after ELF header)
        0,            # e_shoff (no section headers)
        0,            # e_flags
        ehsize,       # e_ehsize
        phentsize,    # e_phentsize
        phnum,        # e_phnum
        0,            # e_shentsize
        0,            # e_shnum
        0,            # e_shstrndx
    )

    binary = e_ident + elf_header
    for ph in phdrs:
        binary += ph
    binary += dyn_data

    return binary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a fake firmware filesystem with ELF binaries."""
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "sbin").mkdir(parents=True)

    # Standard ELF with NX enabled, no PIE
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(
        _build_minimal_elf(nx=True, pie=False)
    )

    # PIE binary with full RELRO
    (tmp_path / "usr" / "sbin" / "daemon").write_bytes(
        _build_minimal_elf(nx=True, pie=True, has_relro=True, has_bind_now=True)
    )

    # No NX (executable stack)
    (tmp_path / "usr" / "bin" / "legacy").write_bytes(
        _build_minimal_elf(nx=False, pie=False)
    )

    # Non-ELF file
    (tmp_path / "usr" / "bin" / "script.sh").write_text("#!/bin/sh\necho hello\n")

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    register_binary_tools(reg)
    return reg


# ---------------------------------------------------------------------------
# check_binary_protections tests (pyelftools, no external tools needed)
# ---------------------------------------------------------------------------


class TestCheckBinaryProtections:
    def test_nx_enabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["nx"] is True

    def test_nx_disabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "legacy")
        result = check_binary_protections(path)
        assert result["nx"] is False

    def test_pie_enabled(self, firmware_root):
        path = str(firmware_root / "usr" / "sbin" / "daemon")
        result = check_binary_protections(path)
        assert result["pie"] is True

    def test_pie_disabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["pie"] is False

    def test_partial_relro(self, firmware_root):
        """Minimal ELF with PT_GNU_RELRO produces at least partial RELRO."""
        path = str(firmware_root / "usr" / "sbin" / "daemon")
        result = check_binary_protections(path)
        assert result["relro"] in ("partial", "full")

    def test_no_relro(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["relro"] == "none"

    def test_not_elf(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "script.sh")
        result = check_binary_protections(path)
        assert "error" in result

    def test_nonexistent_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            check_binary_protections(str(tmp_path / "nonexistent"))


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestRegistration:
    # Core tools that must always be present — new tools are allowed.
    _REQUIRED_TOOLS = {
        "list_functions",
        "disassemble_function",
        "decompile_function",
        "list_imports",
        "list_exports",
        "xrefs_to",
        "xrefs_from",
        "get_binary_info",
        "check_binary_protections",
    }

    def test_core_tools_registered(self, registry):
        names = {t["name"] for t in registry.get_anthropic_tools()}
        missing = self._REQUIRED_TOOLS - names
        assert not missing, f"Missing core binary tools: {missing}"

    def test_tool_schemas_valid(self, registry):
        for tool in registry.get_anthropic_tools():
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert tool["input_schema"]["type"] == "object"
            assert "properties" in tool["input_schema"]

    def test_disassemble_has_optional_param(self, registry):
        tools = registry.get_anthropic_tools()
        disasm = next(t for t in tools if t["name"] == "disassemble_function")
        props = disasm["input_schema"]["properties"]
        assert "num_instructions" in props
        assert "num_instructions" not in disasm["input_schema"].get("required", [])

    def test_core_tools_require_binary_path(self, registry):
        """Core single-binary tools must require binary_path."""
        tools = {t["name"]: t for t in registry.get_anthropic_tools()}
        for name in self._REQUIRED_TOOLS:
            tool = tools[name]
            assert "binary_path" in tool["input_schema"]["properties"], (
                f"{name} missing binary_path"
            )
            assert "binary_path" in tool["input_schema"].get("required", []), (
                f"{name} should require binary_path"
            )


# ---------------------------------------------------------------------------
# check_binary_protections tool handler tests
# ---------------------------------------------------------------------------


class TestCheckBinaryProtectionsTool:
    @pytest.mark.asyncio
    async def test_returns_protection_info(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/httpd"},
            tool_context,
        )
        assert "Binary Protection Status" in result
        assert "NX" in result
        assert "RELRO" in result
        assert "Stack Canary" in result
        assert "PIE" in result
        assert "Fortify" in result

    @pytest.mark.asyncio
    async def test_nx_enabled_in_output(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/httpd"},
            tool_context,
        )
        assert "enabled" in result  # NX should be enabled

    @pytest.mark.asyncio
    async def test_not_elf_error(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/script.sh"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_protection_score(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/sbin/daemon"},
            tool_context,
        )
        assert "Protection score" in result


# ---------------------------------------------------------------------------
# Path traversal tests
# ---------------------------------------------------------------------------


class TestPathTraversal:
    @pytest.mark.asyncio
    async def test_list_functions_traversal(self, registry, tool_context):
        result = await registry.execute(
            "list_functions",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_disassemble_traversal(self, registry, tool_context):
        result = await registry.execute(
            "disassemble_function",
            {"binary_path": "/../../../etc/passwd", "function_name": "main"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_check_protections_traversal(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_imports_traversal(self, registry, tool_context):
        result = await registry.execute(
            "list_imports",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result


# ---------------------------------------------------------------------------
# _resolve_binary_path — .gzf query support (GhidraResearchService routing)
#
# GhidraResearchFile archives live under storage_root/.../ghidra_research/,
# outside the firmware sandbox tree that context.resolve_path() validates
# against — so every binary.py handler routes binary_path arguments through
# _resolve_binary_path first, which detects the .gzf extension and queries
# GhidraResearchService instead of the sandbox. Non-.gzf inputs are
# unaffected (the existing sandbox path is preserved exactly).
# ---------------------------------------------------------------------------


class TestResolveBinaryPathGzfRouting:
    @pytest.mark.asyncio
    async def test_non_gzf_path_uses_normal_sandbox_resolution(self, tool_context, firmware_root):
        path = await _resolve_binary_path("/usr/bin/httpd", tool_context)
        assert path == str(firmware_root / "usr" / "bin" / "httpd")

    @pytest.mark.asyncio
    async def test_gzf_path_resolves_via_ghidra_research_service(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid4()
            project = Project(id=pid, name="gzf-routing", status="ready")
            db.add(project)
            await db.flush()

            gzf_path = tmp_path / "saved.gzf"
            gzf_path.write_bytes(b"PK\x03\x04")  # ZIP magic

            record = GhidraResearchFile(
                id=uuid4(),
                project_id=pid,
                original_filename="saved.gzf",
                file_category="ghidra_archive",
                content_type="application/octet-stream",
                file_size=4,
                sha256="d" * 64,
                storage_path=str(gzf_path),
            )
            db.add(record)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=pid, firmware_id=uuid4(),
                extracted_path=str(tmp_path), db=db,
            )

            # Real SELECT-backed round trip, not a mock — proves the lookup
            # actually matches the persisted row by basename.
            resolved = await _resolve_binary_path("saved.gzf", context)
            assert resolved == str(gzf_path)

    @pytest.mark.asyncio
    async def test_gzf_path_case_insensitive_extension_match(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid4()
            project = Project(id=pid, name="gzf-routing-case", status="ready")
            db.add(project)
            await db.flush()

            gzf_path = tmp_path / "SAVED.GZF"
            gzf_path.write_bytes(b"PK\x03\x04")

            record = GhidraResearchFile(
                id=uuid4(),
                project_id=pid,
                original_filename="SAVED.GZF",
                file_category="ghidra_archive",
                content_type="application/octet-stream",
                file_size=4,
                sha256="f" * 64,
                storage_path=str(gzf_path),
            )
            db.add(record)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=pid, firmware_id=uuid4(),
                extracted_path=str(tmp_path), db=db,
            )

            resolved = await _resolve_binary_path("SAVED.GZF", context)
            assert resolved == str(gzf_path)

    @pytest.mark.asyncio
    async def test_gzf_path_no_match_raises_file_not_found(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid4()
            project = Project(id=pid, name="gzf-routing-missing", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=pid, firmware_id=uuid4(),
                extracted_path=str(tmp_path), db=db,
            )

            with pytest.raises(FileNotFoundError, match="No .gzf archive"):
                await _resolve_binary_path("missing.gzf", context)

    @pytest.mark.asyncio
    async def test_list_functions_tool_routes_gzf_through_registry(self, tmp_path: Path):
        """End-to-end value-flow check (Rule #35b): registry.execute() ->
        _handle_list_functions -> _resolve_binary_path -> resolve_gzf_path,
        with ghidra_service.get_functions mocked to capture exactly which
        path the handler passed downstream — proving the RESOLVED storage
        path reaches Ghidra, not the raw .gzf basename."""
        async with make_live_db() as db:
            pid = uuid4()
            project = Project(id=pid, name="gzf-e2e", status="ready")
            db.add(project)
            await db.flush()

            gzf_path = tmp_path / "saved2.gzf"
            gzf_path.write_bytes(b"PK\x03\x04")

            record = GhidraResearchFile(
                id=uuid4(),
                project_id=pid,
                original_filename="saved2.gzf",
                file_category="ghidra_archive",
                content_type="application/octet-stream",
                file_size=4,
                sha256="e" * 64,
                storage_path=str(gzf_path),
            )
            db.add(record)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=pid, firmware_id=uuid4(),
                extracted_path=str(tmp_path), db=db,
            )

            reg = ToolRegistry()
            register_binary_tools(reg)

            captured: dict = {}

            async def fake_get_functions(path, firmware_id, db_arg):
                captured["path"] = path
                return []

            with patch(
                "app.services.ghidra_service.get_functions",
                new=fake_get_functions,
            ):
                result = await reg.execute(
                    "list_functions", {"binary_path": "saved2.gzf"}, context,
                )

            assert captured["path"] == str(gzf_path)
            assert "Error" not in result

    @pytest.mark.asyncio
    async def test_list_functions_tool_gzf_not_found_is_clean_error(self, tmp_path: Path):
        """The original bug report: a .gzf binary_path with no matching
        GhidraResearchFile row must surface a clean error string (via
        ToolRegistry.execute()'s generic exception handler), not a raw
        traceback or a misleading 'Binary not found' sandbox message."""
        async with make_live_db() as db:
            pid = uuid4()
            project = Project(id=pid, name="gzf-not-found", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=pid, firmware_id=uuid4(),
                extracted_path=str(tmp_path), db=db,
            )

            reg = ToolRegistry()
            register_binary_tools(reg)

            result = await reg.execute(
                "list_functions", {"binary_path": "nonexistent.gzf"}, context,
            )
            assert "Error" in result
            assert "nonexistent.gzf" in result


# ---------------------------------------------------------------------------
# Handler formatting tests (mock GhidraAnalysisCache)
# ---------------------------------------------------------------------------


class TestHandlerFormatting:
    @pytest.mark.asyncio
    async def test_list_functions_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_functions = AsyncMock(return_value=[
            {"name": "main", "size": 200, "address": "00001000"},
            {"name": "auth_check", "size": 150, "address": "00002000"},
        ])

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "list_functions",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 2 function(s)" in result
        assert "main" in result
        assert "auth_check" in result
        assert "00001000" in result

    @pytest.mark.asyncio
    async def test_get_binary_info_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_binary_info = AsyncMock(return_value={
            "core": {},
            "bin": {
                "file": "/usr/bin/httpd",
                "bintype": "elf",
                "arch": "arm",
                "bits": 32,
                "endian": "little",
                "os": "linux",
                "machine": "ARM",
                "class": "ELF32",
                "lang": "c",
                "stripped": True,
                "static": False,
                "libs": ["libc.so.6", "libpthread.so.0"],
            },
        })

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "get_binary_info",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Binary Information" in result
        assert "arm" in result
        assert "little" in result
        assert "libc.so.6" in result

    @pytest.mark.asyncio
    async def test_list_imports_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_imports = AsyncMock(return_value=[
            {"name": "system", "library": "libc.so.6"},
            {"name": "printf", "library": "libc.so.6"},
            {"name": "pthread_create", "library": "libpthread.so.0"},
        ])

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "list_imports",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 3 import(s)" in result
        assert "[libc.so.6]" in result
        assert "system" in result
        assert "[libpthread.so.0]" in result

    @pytest.mark.asyncio
    async def test_list_exports_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_exports = AsyncMock(return_value=[
            {"name": "main", "address": "00001000"},
            {"name": "init", "address": "00002000"},
        ])

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "list_exports",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 2 export(s)" in result
        assert "main" in result
        assert "00001000" in result

    @pytest.mark.asyncio
    async def test_xrefs_to_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_xrefs_to = AsyncMock(return_value=[
            {"from": "00003000", "type": "UNCONDITIONAL_CALL", "from_func": "entry"},
        ])

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "xrefs_to",
                {"binary_path": "/usr/bin/httpd", "address_or_symbol": "main"},
                tool_context,
            )

        assert "Found 1 cross-reference(s) to 'main'" in result
        assert "00003000" in result
        assert "UNCONDITIONAL_CALL" in result

    @pytest.mark.asyncio
    async def test_no_functions_message(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_functions = AsyncMock(return_value=[])

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "list_functions",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "No functions found" in result

    @pytest.mark.asyncio
    async def test_disassembly_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_disassembly = AsyncMock(
            return_value="00001000  push rbp\n00001001  mov rbp, rsp"
        )

        with patch(
            "app.ai.tools.binary.ghidra_service",
            mock_cache,
        ):
            result = await registry.execute(
                "disassemble_function",
                {"binary_path": "/usr/bin/httpd", "function_name": "main"},
                tool_context,
            )

        assert "Disassembly of main" in result
        assert "push rbp" in result


# ---------------------------------------------------------------------------
# Integration: full registry includes binary tools
# ---------------------------------------------------------------------------


class TestFullRegistration:
    def test_create_tool_registry_includes_binary(self):
        from app.ai import create_tool_registry

        registry = create_tool_registry()
        tools = registry.get_anthropic_tools()
        names = {t["name"] for t in tools}
        assert "list_functions" in names
        assert "check_binary_protections" in names
        assert "disassemble_function" in names


class TestBatchDecompileFunctions:
    """Tests for batch_decompile_functions service and tool."""

    def test_parse_batch_decompile_output_single_function(self):
        """Parse batch output with a single function."""
        from app.services.ghidra_service import _parse_batch_decompile_output

        raw_output = (
            "===DECOMPILE_START===\n"
            "// Function: my_func\n"
            "// Address:  0x08048000\n"
            "// Size:     256 bytes\n"
            "\n"
            "void my_func(void) {\n"
            "  printf(\"hello\");\n"
            "}\n"
            "===DECOMPILE_END===\n"
        )

        results = _parse_batch_decompile_output(raw_output)
        assert "my_func" in results
        assert "void my_func(void)" in results["my_func"]
        assert "printf" in results["my_func"]

    def test_parse_batch_decompile_output_multiple_functions(self):
        """Parse batch output with multiple functions."""
        from app.services.ghidra_service import _parse_batch_decompile_output

        raw_output = (
            "===DECOMPILE_START===\n"
            "// Function: func_a\n"
            "// Address:  0x08048000\n"
            "// Size:     100 bytes\n"
            "\n"
            "void func_a(void) { return; }\n"
            "===DECOMPILE_END===\n"
            "===DECOMPILE_START===\n"
            "// Function: func_b\n"
            "// Address:  0x08048100\n"
            "// Size:     200 bytes\n"
            "\n"
            "int func_b(int x) { return x * 2; }\n"
            "===DECOMPILE_END===\n"
        )

        results = _parse_batch_decompile_output(raw_output)
        assert len(results) == 2
        assert "func_a" in results
        assert "func_b" in results
        assert "func_a" in results["func_a"]
        assert "func_b" in results["func_b"]

    def test_parse_batch_decompile_output_failed_decompilation(self):
        """Parse output when a function fails to decompile."""
        from app.services.ghidra_service import _parse_batch_decompile_output

        raw_output = (
            "===DECOMPILE_START===\n"
            "// Function: good_func\n"
            "// Address:  0x08048000\n"
            "\n"
            "void good_func(void) { return; }\n"
            "===DECOMPILE_END===\n"
            "===DECOMPILE_START===\n"
            "// Function: bad_func\n"
            "// Address:  0x08048100\n"
            "\n"
            "// Decompilation failed\n"
            "===DECOMPILE_END===\n"
        )

        results = _parse_batch_decompile_output(raw_output)
        assert "good_func" in results
        assert results["good_func"] is not None
        # bad_func has no code after the metadata, so it should be None or empty
        assert "bad_func" in results
        assert not results["bad_func"] or "Decompilation failed" not in results.get("bad_func", "")

    @pytest.mark.asyncio
    async def test_batch_decompile_functions_with_handler(self, registry, tool_context):
        """Test the batch_decompile_functions MCP tool handler."""
        from app.ai.tools.binary import _handle_batch_decompile_functions

        # Mock input
        input_data = {
            "binary_path": "/bin/busybox",
            "function_names": ["main", "usage"],
        }

        # Mock the batch_decompile_functions service
        with patch("app.ai.tools.binary.batch_decompile_functions") as mock_batch:
            mock_batch.return_value = {
                "main": "int main(void) { return 0; }",
                "usage": "void usage(void) { printf(\"usage\"); }",
            }

            result = await _handle_batch_decompile_functions(input_data, tool_context)

            # Check the handler formats the output correctly
            assert "Batch decompilation results for 2 function(s)" in result
            assert "Function: main" in result
            assert "Function: usage" in result
            assert "2/2 functions decompiled successfully" in result

    @pytest.mark.asyncio
    async def test_batch_decompile_functions_empty_list_error(self, registry, tool_context):
        """Test that empty function_names list returns an error."""
        from app.ai.tools.binary import _handle_batch_decompile_functions

        input_data = {
            "binary_path": "/bin/busybox",
            "function_names": [],
        }

        result = await _handle_batch_decompile_functions(input_data, tool_context)
        assert "function_names list is empty" in result

    @pytest.mark.asyncio
    async def test_batch_decompile_functions_limit_check(self, registry, tool_context):
        """Test that batch size is limited to 10 functions."""
        from app.ai.tools.binary import _handle_batch_decompile_functions

        input_data = {
            "binary_path": "/bin/busybox",
            "function_names": [f"func_{i}" for i in range(15)],
        }

        result = await _handle_batch_decompile_functions(input_data, tool_context)
        assert "Batch size limited to 10" in result
        assert "Requested 15" in result

    @pytest.mark.asyncio
    async def test_batch_decompile_functions_partial_success(self, registry, tool_context):
        """Test handling of partial success (some functions found, some not)."""
        from app.ai.tools.binary import _handle_batch_decompile_functions

        input_data = {
            "binary_path": "/bin/busybox",
            "function_names": ["found_func", "missing_func"],
        }

        with patch("app.ai.tools.binary.batch_decompile_functions") as mock_batch:
            mock_batch.return_value = {
                "found_func": "void found_func(void) { return; }",
                "missing_func": None,
            }

            result = await _handle_batch_decompile_functions(input_data, tool_context)

            assert "2 function(s)" in result
            assert "Function: found_func" in result
            assert "missing_func: (not found or decompilation failed)" in result
            assert "1/2 functions decompiled successfully" in result


class TestGhidraErrorExtractionBenignWarnings:
    """Bug 7: Ghidra warnings about empty .mdebug.abi32 sections and missing
    library symbols should not be presented to the user as the cause of a
    Ghidra script failure — they're informational and don't break analysis.
    """

    def test_pure_benign_warnings_get_demoted(self):
        from app.ai.tools.binary import _extract_ghidra_error

        # Output with only benign warnings (no real error). Should not look
        # like the warnings caused the failure.
        raw = (
            "INFO  Loading...\n"
            "WARN  Skipping section [.mdebug.abi32] with invalid size 0x0\n"
            "WARN  [libdl.so.0] -> not found in project\n"
            "WARN  [libmbedtls.so.17] -> not found in project\n"
            "INFO  Done.\n"
        )
        result = _extract_ghidra_error(raw, "FindStringRefs")

        # The headline should be neutral, not "FindStringRefs failed".
        assert "produced no parseable output" in result
        assert "not the cause" in result
        # The warnings should be visible but presented as non-fatal.
        assert "mdebug" in result.lower()
        assert "not found in project" in result.lower()

    def test_real_error_takes_precedence(self):
        from app.ai.tools.binary import _extract_ghidra_error

        # Mix of real error + benign warnings.
        raw = (
            "INFO  Loading...\n"
            "WARN  Skipping section [.mdebug.abi32] with invalid size 0x0\n"
            "ERROR Script execution failed: NullPointerException at line 42\n"
            "WARN  [libdl.so.0] -> not found in project\n"
        )
        result = _extract_ghidra_error(raw, "FindStringRefs")

        # The real error should headline; warnings should be summarised.
        assert "FindStringRefs failed" in result
        assert "NullPointerException" in result
        assert "Suppressed 2 non-fatal warning" in result

    def test_no_diagnostic_at_all(self):
        from app.ai.tools.binary import _extract_ghidra_error

        result = _extract_ghidra_error("INFO  Loading...\nINFO  Done.\n", "Foo")
        assert "no parseable output" in result
