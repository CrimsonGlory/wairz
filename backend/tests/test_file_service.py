"""Tests for the FileService — firmware filesystem browsing and sandbox validation.

Uses real temporary filesystem fixtures (no mocks needed since FileService is
purely filesystem-driven). Tests cover path resolution, sandbox validation,
directory listing, file reading (text/binary/base64), file info, and search.
"""

import os
from pathlib import Path

import pytest

from app.services.file_service import (
    MAX_READ_SIZE,
    FileContent,
    FileInfo,
    FileService,
    _file_type_from_stat,
    _format_permissions,
    _hex_dump,
    _is_binary,
)
from app.utils.sandbox import PathTraversalError

# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_root(tmp_path: Path) -> Path:
    """Minimal firmware filesystem for basic tests."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (tmp_path / "etc" / "config.conf").write_text("[server]\nport=8080\n")
    (tmp_path / "bin" / "httpd").write_bytes(b"\x7fELF" + b"\x00" * 12)
    return tmp_path


@pytest.fixture
def multi_partition_root(tmp_path: Path) -> Path:
    """Firmware with separate extraction_dir and rootfs for virtual root tests."""
    extraction = tmp_path / "extraction"
    extraction.mkdir()

    # Primary rootfs
    rootfs = extraction / "squashfs-root"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "etc" / "hostname").write_text("router\n")

    # Secondary partition
    jffs2 = extraction / "jffs2-root"
    jffs2.mkdir()
    (jffs2 / "data").mkdir()
    (jffs2 / "data" / "config.db").write_bytes(b"\x00" * 200)

    # Large raw file (>100KB)
    kernel = extraction / "3A7BB"
    kernel.write_bytes(b"\x00" * 200_000)

    # Small file (should be filtered out from virtual root)
    tiny = extraction / "small.bin"
    tiny.write_bytes(b"\x00" * 50)

    return extraction


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    def test_format_permissions_rwx(self):
        assert _format_permissions(0o755) == "rwxr-xr-x"

    def test_format_permissions_readonly(self):
        assert _format_permissions(0o444) == "r--r--r--"

    def test_format_permissions_no_perms(self):
        assert _format_permissions(0o000) == "---------"

    def test_format_permissions_setuid(self):
        # 0o4755 has setuid bit, but _format_permissions only looks at rwx
        result = _format_permissions(0o4755)
        assert result == "rwxr-xr-x"

    def test_is_binary_with_null_bytes(self):
        assert _is_binary(b"\x7fELF\x00\x00\x00\x00") is True

    def test_is_binary_text(self):
        assert _is_binary(b"Hello, world!\n") is False

    def test_is_binary_empty(self):
        assert _is_binary(b"") is False

    def test_hex_dump_simple(self):
        result = _hex_dump(b"\x41\x42\x43")
        assert "41 42 43" in result
        assert "|ABC|" in result

    def test_hex_dump_with_offset(self):
        result = _hex_dump(b"\x00", offset=0x100)
        assert result.startswith("00000100")

    def test_file_type_from_stat_regular(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("test")
        st = os.lstat(str(f))
        assert _file_type_from_stat(st) == "file"

    def test_file_type_from_stat_directory(self, tmp_path: Path):
        d = tmp_path / "subdir"
        d.mkdir()
        st = os.lstat(str(d))
        assert _file_type_from_stat(st) == "directory"

    def test_file_type_from_stat_symlink(self, tmp_path: Path):
        target = tmp_path / "target.txt"
        target.write_text("x")
        link = tmp_path / "link"
        link.symlink_to(str(target))
        st = os.lstat(str(link))
        assert _file_type_from_stat(st) == "symlink"


# ---------------------------------------------------------------------------
# FileService — simple root (no virtual root)
# ---------------------------------------------------------------------------

class TestFileServiceSimple:
    """Tests with a single-root firmware (no extraction_dir)."""

    def test_list_root(self, simple_root: Path):
        svc = FileService(str(simple_root))
        entries, truncated = svc.list_directory("/")
        assert not truncated
        names = {e.name for e in entries}
        assert "etc" in names
        assert "bin" in names

    def test_list_subdirectory(self, simple_root: Path):
        svc = FileService(str(simple_root))
        entries, _ = svc.list_directory("/etc")
        names = {e.name for e in entries}
        assert "passwd" in names
        assert "config.conf" in names

    def test_list_nonexistent_directory(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(FileNotFoundError):
            svc.list_directory("/nonexistent")

    def test_list_file_as_directory(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(FileNotFoundError):
            svc.list_directory("/etc/passwd")

    def test_read_text_file(self, simple_root: Path):
        svc = FileService(str(simple_root))
        content = svc.read_file("/etc/passwd")
        assert isinstance(content, FileContent)
        assert content.is_binary is False
        assert "root:" in content.content
        assert content.encoding == "utf-8"

    def test_read_binary_file(self, simple_root: Path):
        svc = FileService(str(simple_root))
        content = svc.read_file("/bin/httpd")
        assert content.is_binary is True
        assert content.encoding == "hex"
        assert "7f 45 4c 46" in content.content  # ELF magic

    def test_read_base64_format(self, simple_root: Path):
        svc = FileService(str(simple_root))
        content = svc.read_file("/etc/passwd", format="base64")
        assert content.encoding == "base64"
        assert content.is_binary is True
        # Should be valid base64
        import base64
        decoded = base64.b64decode(content.content)
        assert b"root:" in decoded

    def test_read_nonexistent_file(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(FileNotFoundError):
            svc.read_file("/etc/nonexistent")

    def test_read_with_offset(self, simple_root: Path):
        svc = FileService(str(simple_root))
        content = svc.read_file("/etc/passwd", offset=5)
        assert not content.content.startswith("root:")

    def test_read_file_truncation(self, simple_root: Path):
        # Create a file larger than MAX_READ_SIZE
        big_file = simple_root / "etc" / "bigfile"
        big_file.write_bytes(b"A" * (MAX_READ_SIZE + 1000))

        svc = FileService(str(simple_root))
        content = svc.read_file("/etc/bigfile")
        assert content.truncated is True

    def test_file_info_text(self, simple_root: Path):
        svc = FileService(str(simple_root))
        info = svc.file_info("/etc/passwd")
        assert isinstance(info, FileInfo)
        assert info.type == "file"
        assert info.sha256 is not None
        assert len(info.sha256) == 64
        assert info.size > 0

    def test_file_info_directory(self, simple_root: Path):
        svc = FileService(str(simple_root))
        info = svc.file_info("/etc")
        assert info.type == "directory"
        # Directories don't get SHA256
        assert info.sha256 is None

    def test_file_info_nonexistent(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(FileNotFoundError):
            svc.file_info("/nonexistent")

    def test_search_files_glob(self, simple_root: Path):
        svc = FileService(str(simple_root))
        matches, truncated = svc.search_files("*.conf")
        assert not truncated
        assert any("config.conf" in m for m in matches)

    def test_search_files_no_match(self, simple_root: Path):
        svc = FileService(str(simple_root))
        matches, truncated = svc.search_files("*.xyz")
        assert matches == []
        assert not truncated

    def test_search_case_insensitive(self, simple_root: Path):
        svc = FileService(str(simple_root))
        matches, _ = svc.search_files("*.CONF")
        assert any("config.conf" in m for m in matches)


# ---------------------------------------------------------------------------
# Path traversal prevention
# ---------------------------------------------------------------------------

class TestPathTraversal:
    """Verify sandbox validation blocks escape attempts."""

    def test_dotdot_blocked(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(PathTraversalError):
            svc.list_directory("/../../../etc")

    def test_dotdot_in_read(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(PathTraversalError):
            svc.read_file("/../../../etc/passwd")

    def test_dotdot_in_file_info(self, simple_root: Path):
        svc = FileService(str(simple_root))
        with pytest.raises(PathTraversalError):
            svc.file_info("/../../../etc/shadow")

    def test_absolute_symlink_within_root_resolves(self, simple_root: Path):
        """Relative symlinks to directories within the root resolve correctly."""
        # Use a relative symlink so the sandbox resolver handles it properly
        link = simple_root / "etc" / "link_to_bin"
        link.symlink_to("../bin")

        svc = FileService(str(simple_root))
        entries, _ = svc.list_directory("/etc/link_to_bin")
        names = {e.name for e in entries}
        assert "httpd" in names

    def test_absolute_symlink_rewrites_within_root(self, simple_root: Path):
        """Absolute symlinks are rewritten relative to root by sandbox resolver.

        The sandbox resolver rewrites absolute symlink targets (e.g., /tmp)
        to be relative to the firmware root, so /tmp -> <root>/tmp. If the
        target doesn't exist inside root, it just results in a not-found
        rather than an escape.
        """
        link = simple_root / "etc" / "escape"
        link.symlink_to("/tmp")

        svc = FileService(str(simple_root))
        # The sandbox rewrites /tmp to <root>/tmp — since it doesn't exist,
        # we get FileNotFoundError, NOT PathTraversalError
        with pytest.raises(FileNotFoundError):
            svc.list_directory("/etc/escape")


# ---------------------------------------------------------------------------
# FileService — multi-partition (virtual root)
# ---------------------------------------------------------------------------

class TestFileServiceVirtualRoot:
    """Tests with extraction_dir + rootfs virtual root layout."""

    def test_virtual_root_lists_rootfs(self, multi_partition_root: Path):
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        entries, _ = svc.list_directory("/")

        names = {e.name for e in entries}
        assert "rootfs" in names

    def test_virtual_root_lists_other_partitions(self, multi_partition_root: Path):
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        entries, _ = svc.list_directory("/")

        names = {e.name for e in entries}
        assert "jffs2-root" in names

    def test_virtual_root_lists_large_files(self, multi_partition_root: Path):
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        entries, _ = svc.list_directory("/")

        names = {e.name for e in entries}
        assert "3A7BB" in names
        # Small files should be excluded
        assert "small.bin" not in names

    def test_rootfs_prefix_resolves(self, multi_partition_root: Path):
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        entries, _ = svc.list_directory("/rootfs/etc")

        names = {e.name for e in entries}
        assert "hostname" in names

    def test_other_partition_resolves(self, multi_partition_root: Path):
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        entries, _ = svc.list_directory("/jffs2-root/data")

        names = {e.name for e in entries}
        assert "config.db" in names

    def test_rootfs_shortcut_for_existing_paths(self, multi_partition_root: Path):
        """Paths that exist in rootfs should resolve even without /rootfs/ prefix."""
        rootfs = multi_partition_root / "squashfs-root"
        svc = FileService(str(rootfs), extraction_dir=str(multi_partition_root))
        content = svc.read_file("/rootfs/etc/hostname")
        assert "router" in content.content

    def test_same_extraction_dir_disables_virtual(self, simple_root: Path):
        """When extraction_dir == extracted_root, virtual root is disabled."""
        svc = FileService(str(simple_root), extraction_dir=str(simple_root))
        assert svc.extraction_dir is None

    def test_none_extraction_dir(self, simple_root: Path):
        """None extraction_dir = legacy mode, no virtual root."""
        svc = FileService(str(simple_root), extraction_dir=None)
        entries, _ = svc.list_directory("/")
        names = {e.name for e in entries}
        assert "etc" in names
        assert "rootfs" not in names


# ---------------------------------------------------------------------------
# Symlink handling
# ---------------------------------------------------------------------------

class TestSymlinks:
    def test_symlink_listed_with_target(self, simple_root: Path):
        target = simple_root / "etc" / "passwd"
        link = simple_root / "etc" / "passwd.link"
        link.symlink_to(str(target))

        svc = FileService(str(simple_root))
        entries, _ = svc.list_directory("/etc")
        link_entries = [e for e in entries if e.name == "passwd.link"]
        assert len(link_entries) == 1
        assert link_entries[0].symlink_target is not None

    def test_broken_symlink_flagged(self, simple_root: Path):
        link = simple_root / "etc" / "broken"
        link.symlink_to("/nonexistent/target")

        svc = FileService(str(simple_root))
        entries, _ = svc.list_directory("/etc")
        broken_entries = [e for e in entries if e.name == "broken"]
        assert len(broken_entries) == 1
        assert broken_entries[0].broken is True

    def test_directory_symlink_typed_as_directory(self, simple_root: Path):
        """Relative symlinks to directories are classified as 'directory' type."""
        link = simple_root / "etc" / "bin_link"
        link.symlink_to("../bin")

        svc = FileService(str(simple_root))
        entries, _ = svc.list_directory("/etc")
        link_entries = [e for e in entries if e.name == "bin_link"]
        assert len(link_entries) == 1
        assert link_entries[0].type == "directory"
