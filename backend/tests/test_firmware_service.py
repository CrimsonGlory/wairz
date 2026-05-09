"""Tests for the FirmwareService and its helper functions.

Helper functions (_sanitize_filename, _zip_contains_rootfs, etc.) are tested
with real filesystem operations. The FirmwareService class methods that need
a DB session use mocks.
"""

import os
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.firmware_service import (
    FirmwareService,
    _extract_firmware_from_zip,
    _firmware_tar_filter,
    _is_android_firmware_zip,
    _sanitize_filename,
    _zip_contains_rootfs,
)

# ---------------------------------------------------------------------------
# _sanitize_filename
# ---------------------------------------------------------------------------

class TestSanitizeFilename:
    def test_normal_filename(self):
        assert _sanitize_filename("firmware.bin") == "firmware.bin"

    def test_strips_path_components(self):
        assert _sanitize_filename("/etc/passwd") == "passwd"

    def test_strips_traversal(self):
        assert _sanitize_filename("../../../etc/shadow") == "shadow"

    def test_replaces_special_chars(self):
        result = _sanitize_filename("firmware (v2) [test].bin")
        assert "(" not in result
        assert "[" not in result
        assert result.endswith(".bin")

    def test_strips_leading_dots(self):
        result = _sanitize_filename(".hidden_firmware")
        assert not result.startswith(".")

    def test_strips_leading_underscores(self):
        result = _sanitize_filename("___firmware.bin")
        assert result == "firmware.bin"

    def test_truncates_long_filename(self):
        result = _sanitize_filename("a" * 300 + ".bin")
        assert len(result) <= 200

    def test_empty_becomes_default(self):
        assert _sanitize_filename("") == "firmware.bin"

    def test_dots_only_becomes_default(self):
        assert _sanitize_filename("...") == "firmware.bin"

    def test_windows_path(self):
        result = _sanitize_filename("C:\\Users\\admin\\firmware.bin")
        # os.path.basename handles this correctly on Linux
        assert "firmware" in result

    def test_collapses_consecutive_underscores(self):
        result = _sanitize_filename("firm   ware.bin")
        assert "___" not in result


# ---------------------------------------------------------------------------
# _zip_contains_rootfs
# ---------------------------------------------------------------------------

class TestZipContainsRootfs:
    def test_rootfs_at_top_level(self, tmp_path: Path):
        zp = tmp_path / "rootfs.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("etc/passwd", "root:x:0:0::/root:/bin/sh")
            zf.writestr("usr/bin/foo", "")
            zf.writestr("bin/sh", "")
            zf.writestr("lib/libc.so", "")
        assert _zip_contains_rootfs(str(zp)) is True

    def test_rootfs_in_wrapper_dir(self, tmp_path: Path):
        zp = tmp_path / "rootfs.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("rootfs/etc/passwd", "root:x:0:0::/root:/bin/sh")
            zf.writestr("rootfs/usr/bin/foo", "")
            zf.writestr("rootfs/bin/sh", "")
            zf.writestr("rootfs/lib/libc.so", "")
        assert _zip_contains_rootfs(str(zp)) is True

    def test_non_rootfs_zip(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "Hello")
            zf.writestr("data/config.json", "{}")
        assert _zip_contains_rootfs(str(zp)) is False

    def test_partial_markers_not_enough(self, tmp_path: Path):
        """Need 3+ Linux root directories to classify as rootfs."""
        zp = tmp_path / "partial.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("etc/passwd", "root")
            zf.writestr("bin/sh", "")
        assert _zip_contains_rootfs(str(zp)) is False


# ---------------------------------------------------------------------------
# _is_android_firmware_zip
# ---------------------------------------------------------------------------

class TestIsAndroidFirmwareZip:
    def test_payload_bin_detected(self, tmp_path: Path):
        zp = tmp_path / "ota.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("payload.bin", b"\x00" * 16)
        assert _is_android_firmware_zip(str(zp)) is True

    def test_meta_inf_android(self, tmp_path: Path):
        zp = tmp_path / "ota.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("META-INF/com/google/android/updater-script", "")
        assert _is_android_firmware_zip(str(zp)) is True

    def test_multiple_partitions(self, tmp_path: Path):
        zp = tmp_path / "factory.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("boot.img", b"\x00" * 16)
        assert _is_android_firmware_zip(str(zp)) is True

    def test_single_partition_not_android(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("readme.txt", "Not Android")
        assert _is_android_firmware_zip(str(zp)) is False

    def test_generic_zip_not_android(self, tmp_path: Path):
        zp = tmp_path / "generic.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "Hello")
        assert _is_android_firmware_zip(str(zp)) is False


# ---------------------------------------------------------------------------
# _extract_firmware_from_zip
# ---------------------------------------------------------------------------

class TestExtractFirmwareFromZip:
    def test_extracts_largest_file(self, tmp_path: Path):
        zp = tmp_path / "firmware.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("readme.txt", "small")
            zf.writestr("firmware.bin", b"\x7fELF" + b"\x00" * 1000)
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        assert os.path.isfile(result)
        assert os.path.basename(result) == "firmware.bin"

    def test_empty_zip_returns_none(self, tmp_path: Path):
        zp = tmp_path / "empty.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            pass  # no files
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is None

    def test_hidden_files_skipped(self, tmp_path: Path):
        zp = tmp_path / "macos.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr(".DS_Store", "")
            zf.writestr("__MACOSX/resource", "")
            zf.writestr("firmware.bin", b"\x00" * 100)
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        assert "firmware.bin" in result

    def test_zip_slip_prevention(self, tmp_path: Path):
        """Entries with path traversal should be skipped silently."""
        zp = tmp_path / "malicious.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            # Normal file
            zf.writestr("firmware.bin", b"\x00" * 100)
            # Malicious entry (path traversal)
            zf.writestr("../../etc/passwd", "hacked")
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        # The traversal target should NOT exist outside output
        assert not os.path.exists(tmp_path / "etc" / "passwd")

    def test_preserves_directory_structure(self, tmp_path: Path):
        zp = tmp_path / "structured.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("subdir/firmware.bin", b"\x00" * 100)
            zf.writestr("subdir/config.txt", "test")
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = _extract_firmware_from_zip(str(zp), str(out_dir))
        assert result is not None
        # Both files should be extracted
        zip_contents = out_dir / "zip_contents"
        assert os.path.isfile(zip_contents / "subdir" / "config.txt")


# ---------------------------------------------------------------------------
# _firmware_tar_filter
# ---------------------------------------------------------------------------

class TestFirmwareTarFilter:
    def test_allows_regular_file(self, tmp_path: Path):
        member = tarfile.TarInfo(name="etc/passwd")
        member.type = tarfile.REGTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_allows_directory(self, tmp_path: Path):
        member = tarfile.TarInfo(name="etc/")
        member.type = tarfile.DIRTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_allows_symlink(self, tmp_path: Path):
        member = tarfile.TarInfo(name="bin/sh")
        member.type = tarfile.SYMTYPE
        member.linkname = "/usr/bin/bash"
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None

    def test_rejects_device_node(self, tmp_path: Path):
        member = tarfile.TarInfo(name="dev/sda")
        member.type = tarfile.BLKTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is None

    def test_strips_leading_slash(self, tmp_path: Path):
        member = tarfile.TarInfo(name="/etc/passwd")
        member.type = tarfile.REGTYPE
        result = _firmware_tar_filter(member, str(tmp_path))
        assert result is not None
        assert not result.name.startswith("/")

    def test_rejects_path_traversal(self, tmp_path: Path):
        member = tarfile.TarInfo(name="../../etc/shadow")
        member.type = tarfile.REGTYPE
        with pytest.raises(ValueError, match="traversal"):
            _firmware_tar_filter(member, str(tmp_path))


# ---------------------------------------------------------------------------
# FirmwareService DB methods (mocked)
# ---------------------------------------------------------------------------

class TestFirmwareServiceDBMethods:

    @pytest.mark.asyncio
    async def test_get_by_id_found(self):
        db = AsyncMock()
        fw = MagicMock()
        fw.id = "test-id"
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_id("test-id")
        assert result is fw

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_id("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_by_project(self):
        db = AsyncMock()
        fw_list = [MagicMock(), MagicMock()]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = fw_list
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.list_by_project("project-id")
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_by_project_returns_first(self):
        db = AsyncMock()
        fw = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_project("project-id")
        assert result is fw

    @pytest.mark.asyncio
    async def test_get_by_project_empty(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FirmwareService(db)
        result = await svc.get_by_project("project-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_removes_directory(self, tmp_path: Path):
        db = AsyncMock()
        db.delete = AsyncMock()
        db.flush = AsyncMock()

        # Create a fake firmware directory
        fw_dir = tmp_path / "firmware_dir"
        fw_dir.mkdir()
        storage = fw_dir / "firmware.bin"
        storage.write_bytes(b"\x00")

        fw = MagicMock()
        fw.storage_path = str(storage)
        fw.extracted_path = None

        svc = FirmwareService(db)
        await svc.delete(fw)

        db.delete.assert_awaited_once_with(fw)
        db.flush.assert_awaited_once()
        assert not fw_dir.exists()

    @pytest.mark.asyncio
    async def test_delete_with_extracted_path_fallback(self, tmp_path: Path):
        db = AsyncMock()
        db.delete = AsyncMock()
        db.flush = AsyncMock()

        # Create a fake extracted directory
        extracted = tmp_path / "extracted"
        extracted.mkdir()
        (extracted / "etc").mkdir()

        fw = MagicMock()
        fw.storage_path = None
        fw.extracted_path = str(extracted)

        svc = FirmwareService(db)
        await svc.delete(fw)

        db.delete.assert_awaited_once()
        # Parent of extracted_path should be removed
        assert not extracted.exists()
