"""Tests for the firmware comparison service.

Covers filesystem diffing, text diffing, binary diffing (LIEF function hashing,
section hashing, import/export extraction, basic block hashing), and Capstone
instruction-level diffing.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.services.comparison_service import (
    BinaryDiff,
    FileDiffEntry,
    FirmwareDiff,
    FunctionDiffEntry,
    _extract_basic_blocks,
    _extract_binary_info,
    _extract_exports,
    _extract_function_hashes,
    _extract_imports,
    _extract_section_hashes,
    diff_binary,
    diff_filesystems,
    diff_function_instructions,
    diff_text_file,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_GCC = shutil.which("gcc")
needs_gcc = pytest.mark.skipif(not _GCC, reason="gcc required for ELF binary tests")


def _compile(src: str, out: Path, extra_flags: list[str] | None = None):
    """Compile a C source string into an ELF binary."""
    src_file = out.with_suffix(".c")
    src_file.write_text(src)
    cmd = ["gcc", "-o", str(out), str(src_file), "-no-pie"]
    if extra_flags:
        cmd.extend(extra_flags)
    subprocess.run(cmd, check=True, capture_output=True)


@pytest.fixture
def fw_trees(tmp_path: Path):
    """Create two firmware filesystem trees (A and B) with known differences."""
    root_a = tmp_path / "fw_a"
    root_b = tmp_path / "fw_b"
    root_a.mkdir()
    root_b.mkdir()

    # Shared structure
    for root in (root_a, root_b):
        (root / "etc").mkdir()
        (root / "bin").mkdir()
        (root / "lib").mkdir()

    # Identical files
    (root_a / "etc" / "hostname").write_text("router")
    (root_b / "etc" / "hostname").write_text("router")

    # Modified file (different content)
    (root_a / "etc" / "config.conf").write_text("version=1.0\n")
    (root_b / "etc" / "config.conf").write_text("version=2.0\n")

    # Permissions changed only
    (root_a / "bin" / "tool").write_bytes(b"\x7fELF")
    (root_b / "bin" / "tool").write_bytes(b"\x7fELF")
    os.chmod(root_a / "bin" / "tool", 0o755)
    os.chmod(root_b / "bin" / "tool", 0o700)

    # Removed file (in A only)
    (root_a / "etc" / "old.conf").write_text("deprecated")

    # Added file (in B only)
    (root_b / "lib" / "libnew.so").write_bytes(b"\x7fELF\x00")

    return root_a, root_b


SRC_A = """\
#include <stdio.h>
int add(int x, int y) { return x + y; }
int mul(int x, int y) { return x * y; }
int shared_unchanged(int x) { return x * 2; }
int main(void) { printf("%d\\n", add(1, mul(2, 3))); return 0; }
"""

SRC_B = """\
#include <stdio.h>
int add(int x, int y) { return x + y + 1; }
int sub(int x, int y) { return x - y; }
int shared_unchanged(int x) { return x * 2; }
int main(void) { printf("%d\\n", add(1, sub(5, 3))); return 0; }
"""


@pytest.fixture
def elf_pair(tmp_path: Path):
    """Compile two related ELF binaries with symbol-level differences.

    Binary A: has add, mul, shared_unchanged, main
    Binary B: has add (modified), sub (new), shared_unchanged, main (modified)
    Difference: mul removed, sub added, add body changed
    """
    bin_a = tmp_path / "binary_a"
    bin_b = tmp_path / "binary_b"
    _compile(SRC_A, bin_a)
    _compile(SRC_B, bin_b)
    return bin_a, bin_b


SRC_STRIPPED = """\
int helper(int x) { return x + 42; }
int main(void) { return helper(0); }
"""


@pytest.fixture
def stripped_elf(tmp_path: Path):
    """Compile and strip an ELF binary (no .symtab)."""
    out = tmp_path / "stripped"
    _compile(SRC_STRIPPED, out)
    subprocess.run(["strip", str(out)], check=True, capture_output=True)
    return out


# ---------------------------------------------------------------------------
# Filesystem diff tests
# ---------------------------------------------------------------------------

class TestDiffFilesystems:

    def test_detects_added_files(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        added_paths = [e.path for e in result.added]
        assert "/lib/libnew.so" in added_paths

    def test_detects_removed_files(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        removed_paths = [e.path for e in result.removed]
        assert "/etc/old.conf" in removed_paths

    def test_detects_modified_files(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        modified_paths = [e.path for e in result.modified]
        assert "/etc/config.conf" in modified_paths

    def test_detects_permission_changes(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        perm_paths = [e.path for e in result.permissions_changed]
        assert "/bin/tool" in perm_paths

    def test_unchanged_files_not_reported(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        all_paths = (
            [e.path for e in result.added]
            + [e.path for e in result.removed]
            + [e.path for e in result.modified]
            + [e.path for e in result.permissions_changed]
        )
        assert "/etc/hostname" not in all_paths

    def test_total_file_counts(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        assert result.total_files_a == 4  # hostname, config.conf, tool, old.conf
        assert result.total_files_b == 4  # hostname, config.conf, tool, libnew.so

    def test_identical_trees_produce_empty_diff(self, tmp_path: Path):
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        (root_a / "file.txt").write_text("same")
        (root_b / "file.txt").write_text("same")
        result = diff_filesystems(str(root_a), str(root_b))
        assert len(result.added) == 0
        assert len(result.removed) == 0
        assert len(result.modified) == 0
        assert len(result.permissions_changed) == 0

    def test_empty_trees(self, tmp_path: Path):
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        result = diff_filesystems(str(root_a), str(root_b))
        assert result.total_files_a == 0
        assert result.total_files_b == 0

    def test_result_types(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        assert isinstance(result, FirmwareDiff)
        for entry in result.added + result.removed + result.modified:
            assert isinstance(entry, FileDiffEntry)

    def test_size_fields_populated(self, fw_trees):
        root_a, root_b = fw_trees
        result = diff_filesystems(str(root_a), str(root_b))
        for entry in result.added:
            assert entry.size_b is not None and entry.size_b >= 0
        for entry in result.removed:
            assert entry.size_a is not None and entry.size_a >= 0
        for entry in result.modified:
            assert entry.size_a is not None
            assert entry.size_b is not None


# ---------------------------------------------------------------------------
# Text diff tests
# ---------------------------------------------------------------------------

class TestDiffTextFile:

    def test_basic_diff(self, tmp_path: Path):
        a = tmp_path / "a.conf"
        b = tmp_path / "b.conf"
        a.write_text("line1\nline2\nline3\n")
        b.write_text("line1\nmodified\nline3\nnew_line\n")
        result = diff_text_file(str(a), str(b), "/etc/test.conf")
        assert result["lines_added"] == 2  # "modified" and "new_line"
        assert result["lines_removed"] == 1  # "line2"
        assert result["error"] is None
        assert "/etc/test.conf" in result["path"]

    def test_identical_files_produce_empty_diff(self, tmp_path: Path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("same content\n")
        b.write_text("same content\n")
        result = diff_text_file(str(a), str(b), "/etc/same.txt")
        assert result["diff"] == ""
        assert result["lines_added"] == 0
        assert result["lines_removed"] == 0

    def test_file_added(self, tmp_path: Path):
        """Diff where file A doesn't exist (new file in B)."""
        b = tmp_path / "b.txt"
        b.write_text("new content\n")
        fake_a = tmp_path / "nonexistent"
        result = diff_text_file(str(fake_a), str(b), "/etc/new.conf")
        assert result["lines_added"] >= 1
        assert result["error"] is None

    def test_file_removed(self, tmp_path: Path):
        """Diff where file B doesn't exist (removed in B)."""
        a = tmp_path / "a.txt"
        a.write_text("old content\n")
        fake_b = tmp_path / "nonexistent"
        result = diff_text_file(str(a), str(fake_b), "/etc/removed.conf")
        assert result["lines_removed"] >= 1
        assert result["error"] is None

    def test_large_file_rejected(self, tmp_path: Path):
        """Files exceeding MAX_TEXT_DIFF_SIZE produce an error, not a diff."""
        a = tmp_path / "big_a.txt"
        b = tmp_path / "big_b.txt"
        # 512 KB + 1 byte
        a.write_bytes(b"x" * (512 * 1024 + 1))
        b.write_text("small")
        result = diff_text_file(str(a), str(b), "/big")
        assert result["error"] is not None
        assert "too large" in result["error"].lower()

    def test_truncation_on_large_diff(self, tmp_path: Path):
        """Diffs exceeding 500 lines are truncated."""
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("".join(f"line_a_{i}\n" for i in range(600)))
        b.write_text("".join(f"line_b_{i}\n" for i in range(600)))
        result = diff_text_file(str(a), str(b), "/big_diff")
        assert result["truncated"] is True
        assert "truncated" in result["diff"]



# ---------------------------------------------------------------------------
# LIEF-based binary extraction tests
# ---------------------------------------------------------------------------

@needs_gcc
class TestExtractFunctionHashes:

    def test_extracts_named_functions(self, elf_pair):
        bin_a, _ = elf_pair
        funcs = _extract_function_hashes(str(bin_a))
        assert funcs is not None
        assert "add" in funcs
        assert "mul" in funcs
        assert "main" in funcs

    def test_function_has_required_fields(self, elf_pair):
        bin_a, _ = elf_pair
        funcs = _extract_function_hashes(str(bin_a))
        for name, info in funcs.items():
            assert "size" in info and info["size"] > 0
            assert "hash" in info and len(info["hash"]) == 64  # SHA-256 hex
            assert "addr" in info and info["addr"] > 0

    def test_modified_function_has_different_hash(self, elf_pair):
        bin_a, bin_b = elf_pair
        funcs_a = _extract_function_hashes(str(bin_a))
        funcs_b = _extract_function_hashes(str(bin_b))
        assert funcs_a["add"]["hash"] != funcs_b["add"]["hash"]

    def test_unchanged_function_has_same_hash(self, elf_pair):
        bin_a, bin_b = elf_pair
        funcs_a = _extract_function_hashes(str(bin_a))
        funcs_b = _extract_function_hashes(str(bin_b))
        assert funcs_a["shared_unchanged"]["hash"] == funcs_b["shared_unchanged"]["hash"]

    def test_returns_none_for_non_elf(self, tmp_path: Path):
        f = tmp_path / "not_elf"
        f.write_bytes(b"This is not an ELF file")
        assert _extract_function_hashes(str(f)) is None

    def test_returns_none_for_stripped_binary(self, stripped_elf):
        result = _extract_function_hashes(str(stripped_elf))
        # Stripped binary has no .symtab; may have empty .dynsym
        assert result is None


@needs_gcc
class TestExtractSectionHashes:

    def test_extracts_text_section(self, elf_pair):
        bin_a, _ = elf_pair
        sections = _extract_section_hashes(str(bin_a))
        assert sections is not None
        names = [s["name"] for s in sections]
        assert ".text" in names

    def test_section_has_required_fields(self, elf_pair):
        bin_a, _ = elf_pair
        sections = _extract_section_hashes(str(bin_a))
        for sec in sections:
            assert "name" in sec
            assert "size" in sec and sec["size"] > 0
            assert "hash" in sec and len(sec["hash"]) == 64

    def test_modified_binary_has_different_text_hash(self, elf_pair):
        bin_a, bin_b = elf_pair
        secs_a = _extract_section_hashes(str(bin_a))
        secs_b = _extract_section_hashes(str(bin_b))
        text_a = next(s for s in secs_a if s["name"] == ".text")
        text_b = next(s for s in secs_b if s["name"] == ".text")
        assert text_a["hash"] != text_b["hash"]

    def test_returns_none_for_non_elf(self, tmp_path: Path):
        f = tmp_path / "garbage"
        f.write_bytes(b"not elf")
        assert _extract_section_hashes(str(f)) is None


SRC_SHARED_LIB = """\
int exported_add(int x, int y) { return x + y; }
int exported_mul(int x, int y) { return x * y; }
"""


@pytest.fixture
def shared_lib(tmp_path: Path):
    """Compile a shared library with exported functions."""
    out = tmp_path / "libtest.so"
    src = tmp_path / "lib.c"
    src.write_text(SRC_SHARED_LIB)
    subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", str(out), str(src)],
        check=True,
        capture_output=True,
    )
    return out


@needs_gcc
class TestExtractImports:

    def test_extracts_libc_imports(self, elf_pair):
        bin_a, _ = elf_pair
        imports = _extract_imports(str(bin_a))
        assert imports is not None
        assert isinstance(imports, set)
        # Both source files call printf — should be imported from libc
        assert "printf" in imports

    def test_returns_none_for_non_elf(self, tmp_path: Path):
        f = tmp_path / "bad"
        f.write_bytes(b"nope")
        assert _extract_imports(str(f)) is None


@needs_gcc
class TestExtractExports:

    def test_returns_set(self, elf_pair):
        bin_a, _ = elf_pair
        exports = _extract_exports(str(bin_a))
        # Dynamically linked executables may or may not export symbols
        assert exports is None or isinstance(exports, set)

    def test_shared_lib_exports_functions(self, shared_lib):
        exports = _extract_exports(str(shared_lib))
        assert exports is not None
        assert "exported_add" in exports
        assert "exported_mul" in exports

    def test_returns_none_for_non_elf(self, tmp_path: Path):
        f = tmp_path / "bad"
        f.write_bytes(b"nope")
        assert _extract_exports(str(f)) is None


@needs_gcc
class TestExtractBinaryInfo:

    def test_has_file_size(self, elf_pair):
        bin_a, _ = elf_pair
        info = _extract_binary_info(str(bin_a))
        assert info["file_size"] > 0

    def test_has_arch_and_bits(self, elf_pair):
        bin_a, _ = elf_pair
        info = _extract_binary_info(str(bin_a))
        assert info["arch"] == "X86_64"
        assert info["bits"] == 64
        assert info["endian"] == "little"

    def test_non_elf_returns_size_only(self, tmp_path: Path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"12345")
        info = _extract_binary_info(str(f))
        assert info["file_size"] == 5


@needs_gcc
class TestExtractBasicBlocks:

    def test_extracts_blocks(self, elf_pair):
        bin_a, _ = elf_pair
        result = _extract_basic_blocks(str(bin_a))
        assert result is not None
        assert result["block_count"] > 0
        assert len(result["unique_hashes"]) > 0
        assert len(result["blocks"]) == result["block_count"]

    def test_block_has_required_fields(self, elf_pair):
        bin_a, _ = elf_pair
        result = _extract_basic_blocks(str(bin_a))
        for block in result["blocks"]:
            assert "offset" in block
            assert "size" in block and block["size"] > 0
            assert "hash" in block and len(block["hash"]) == 64

    def test_different_binaries_share_some_blocks(self, elf_pair):
        bin_a, bin_b = elf_pair
        bb_a = _extract_basic_blocks(str(bin_a))
        bb_b = _extract_basic_blocks(str(bin_b))
        hashes_a = set(bb_a["unique_hashes"])
        hashes_b = set(bb_b["unique_hashes"])
        # Both share libc init code, so there should be SOME overlap
        assert len(hashes_a & hashes_b) > 0
        # But not identical (code differs)
        assert hashes_a != hashes_b

    def test_returns_none_for_non_elf(self, tmp_path: Path):
        f = tmp_path / "bad"
        f.write_bytes(b"not elf")
        assert _extract_basic_blocks(str(f)) is None


# ---------------------------------------------------------------------------
# Binary diff tests (integration of LIEF extraction + diff logic)
# ---------------------------------------------------------------------------

@needs_gcc
class TestDiffBinary:

    def test_detects_function_changes(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_binary(str(bin_a), str(bin_b), "/usr/bin/prog")
        assert isinstance(result, BinaryDiff)
        assert result.binary_path == "/usr/bin/prog"

        added_names = [f.name for f in result.functions_added]
        removed_names = [f.name for f in result.functions_removed]
        modified_names = [f.name for f in result.functions_modified]

        assert "sub" in added_names
        assert "mul" in removed_names
        assert "add" in modified_names

    def test_info_populated(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_binary(str(bin_a), str(bin_b), "/usr/bin/prog")
        assert result.info_a["file_size"] > 0
        assert result.info_b["file_size"] > 0
        assert "sha256" in result.info_a
        assert "sha256" in result.info_b
        assert result.info_a["identical"] is False

    def test_identical_binaries(self, elf_pair):
        bin_a, _ = elf_pair
        result = diff_binary(str(bin_a), str(bin_a), "/usr/bin/same")
        assert len(result.functions_added) == 0
        assert len(result.functions_removed) == 0
        assert len(result.functions_modified) == 0
        assert result.info_a["identical"] is True

    def test_import_diff(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_binary(str(bin_a), str(bin_b), "/usr/bin/prog")
        # Both use printf, so imports should be largely the same
        assert isinstance(result.imports_added, list)
        assert isinstance(result.imports_removed, list)

    def test_function_diff_entries_have_correct_status(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_binary(str(bin_a), str(bin_b), "/usr/bin/prog")
        for f in result.functions_added:
            assert isinstance(f, FunctionDiffEntry)
            assert f.status == "added"
        for f in result.functions_removed:
            assert f.status == "removed"
        for f in result.functions_modified:
            assert f.status == "modified"

    def test_stripped_binary_falls_back_to_sections(self, stripped_elf, tmp_path: Path):
        """When symbols are unavailable, diff_binary falls back to section hashing."""
        bin_b = tmp_path / "stripped_b"
        # Compile a different program and strip it
        _compile(
            "int main(void) { return 42; }",
            bin_b,
        )
        subprocess.run(["strip", str(bin_b)], check=True, capture_output=True)

        result = diff_binary(str(stripped_elf), str(bin_b), "/bin/prog")
        # Should have section-level comparison instead of function-level
        assert len(result.functions_added) == 0
        assert len(result.functions_removed) == 0
        # Should have basic_block_stats or sections_changed
        has_section_data = (
            len(result.sections_a) > 0
            or len(result.sections_b) > 0
            or result.basic_block_stats is not None
        )
        assert has_section_data


# ---------------------------------------------------------------------------
# Instruction-level diff tests (Capstone)
# ---------------------------------------------------------------------------

@needs_gcc
class TestDiffFunctionInstructions:

    def test_produces_diff_for_modified_function(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_function_instructions(str(bin_a), str(bin_b), "add")
        assert result["error"] is None
        assert result["arch"] == "x86_64"
        assert result["function_name"] == "add"
        # add was modified, so there should be a diff
        assert result["lines_added"] > 0 or result["lines_removed"] > 0
        assert len(result["diff_text"]) > 0

    def test_unchanged_function_produces_empty_diff(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_function_instructions(str(bin_a), str(bin_b), "shared_unchanged")
        assert result["error"] is None
        assert result["lines_added"] == 0
        assert result["lines_removed"] == 0

    def test_missing_function_returns_error(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_function_instructions(str(bin_a), str(bin_b), "nonexistent_func")
        assert result["error"] is not None
        assert "not found" in result["error"].lower()

    def test_non_elf_returns_error(self, tmp_path: Path):
        f = tmp_path / "bad"
        f.write_bytes(b"not an elf")
        result = diff_function_instructions(str(f), str(f), "main")
        assert result["error"] is not None

    def test_diff_text_contains_instruction_offsets(self, elf_pair):
        bin_a, bin_b = elf_pair
        result = diff_function_instructions(str(bin_a), str(bin_b), "add")
        if result["diff_text"]:
            # Instructions should contain offset notation like +0x0000:
            assert "+0x" in result["diff_text"] or "0x" in result["diff_text"]
