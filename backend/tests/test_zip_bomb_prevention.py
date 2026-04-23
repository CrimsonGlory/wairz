"""Tests for zip bomb / extraction bomb prevention in the unpack pipeline."""

import io
import os
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.workers.unpack_common import check_extraction_limits, cleanup_unblob_artifacts
from app.workers.unpack_linux import check_tar_bomb


def _make_settings(
    max_extraction_size_mb=10240,
    max_extraction_files=500000,
    max_compression_ratio=200,
):
    """Create a mock settings object for testing."""
    return SimpleNamespace(
        max_extraction_size_mb=max_extraction_size_mb,
        max_extraction_files=max_extraction_files,
        max_compression_ratio=max_compression_ratio,
    )


# --- check_extraction_limits ---


class TestCheckExtractionLimits:
    """Tests for post-extraction bomb detection."""

    def test_small_extraction_passes(self, tmp_path: Path):
        """Normal extraction with few small files passes."""
        for i in range(10):
            (tmp_path / f"file_{i}.txt").write_bytes(b"x" * 100)
        settings = _make_settings()
        assert check_extraction_limits(str(tmp_path), 1000, settings) is None

    def test_file_count_exceeded(self, tmp_path: Path):
        """Extraction with too many files is rejected."""
        settings = _make_settings(max_extraction_files=5)
        for i in range(10):
            (tmp_path / f"file_{i}.txt").write_bytes(b"x")
        error = check_extraction_limits(str(tmp_path), 100, settings)
        assert error is not None
        assert "file count" in error.lower()

    def test_total_size_exceeded(self, tmp_path: Path):
        """Extraction with total size over limit is rejected."""
        settings = _make_settings(max_extraction_size_mb=1)  # 1MB
        # Write 2MB of data
        (tmp_path / "big.bin").write_bytes(b"\x00" * (2 * 1024 * 1024))
        error = check_extraction_limits(str(tmp_path), 1000, settings)
        assert error is not None
        assert "total size" in error.lower()

    def test_compression_ratio_exceeded(self, tmp_path: Path):
        """Extraction with high compression ratio is rejected."""
        settings = _make_settings(max_compression_ratio=10)
        # 1MB extracted from 100 bytes = 10240:1 ratio
        (tmp_path / "expanded.bin").write_bytes(b"\x00" * (1024 * 1024))
        error = check_extraction_limits(str(tmp_path), 100, settings)
        assert error is not None
        assert "compression ratio" in error.lower()

    def test_compression_ratio_ok(self, tmp_path: Path):
        """Normal compression ratio passes."""
        settings = _make_settings(max_compression_ratio=200)
        # 1KB extracted from 100 bytes = 10:1 ratio
        (tmp_path / "normal.bin").write_bytes(b"\x00" * 1024)
        assert check_extraction_limits(str(tmp_path), 100, settings) is None

    def test_nested_directories_counted(self, tmp_path: Path):
        """Files in nested directories are counted."""
        settings = _make_settings(max_extraction_files=5)
        subdir = tmp_path / "a" / "b" / "c"
        subdir.mkdir(parents=True)
        for i in range(8):
            (subdir / f"file_{i}.txt").write_bytes(b"x")
        error = check_extraction_limits(str(tmp_path), 100, settings)
        assert error is not None
        assert "file count" in error.lower()

    def test_empty_directory_passes(self, tmp_path: Path):
        """Empty extraction directory passes."""
        settings = _make_settings()
        assert check_extraction_limits(str(tmp_path), 1000, settings) is None

    def test_zero_firmware_size_skips_ratio(self, tmp_path: Path):
        """Zero firmware size doesn't divide by zero."""
        settings = _make_settings(max_compression_ratio=10)
        (tmp_path / "file.bin").write_bytes(b"\x00" * 1024)
        # firmware_size=0 should skip ratio check
        assert check_extraction_limits(str(tmp_path), 0, settings) is None


# --- check_tar_bomb ---


class TestCheckTarBomb:
    """Tests for pre-extraction tar bomb detection."""

    def test_normal_tar_passes(self, tmp_path: Path):
        """A normal tar with small files passes."""
        tar_path = tmp_path / "normal.tar"
        with tarfile.open(tar_path, "w") as tf:
            for i in range(5):
                data = b"x" * 100
                info = tarfile.TarInfo(name=f"file_{i}.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        result = check_tar_bomb(str(tar_path), 10 * 1024 * 1024, 100, 200)
        assert result is None

    def test_tar_file_count_exceeded(self, tmp_path: Path):
        """Tar with too many entries is detected."""
        tar_path = tmp_path / "many_files.tar"
        with tarfile.open(tar_path, "w") as tf:
            for i in range(20):
                info = tarfile.TarInfo(name=f"file_{i}.txt")
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
        result = check_tar_bomb(str(tar_path), 1024 * 1024, 10, 200)
        assert result is not None
        assert "file count" in result.lower()

    def test_tar_size_exceeded(self, tmp_path: Path):
        """Tar with declared sizes exceeding limit is detected."""
        tar_path = tmp_path / "big.tar"
        with tarfile.open(tar_path, "w") as tf:
            # Declare a 10MB file
            data = b"\x00" * (10 * 1024 * 1024)
            info = tarfile.TarInfo(name="big.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        # Limit: 5MB
        result = check_tar_bomb(str(tar_path), 5 * 1024 * 1024, 100, 200)
        assert result is not None
        assert "declared size" in result.lower()

    def test_tar_compression_ratio_exceeded(self, tmp_path: Path):
        """Tar.gz with high compression ratio is detected."""
        tar_path = tmp_path / "bomb.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            # Highly compressible data (all zeros)
            data = b"\x00" * (5 * 1024 * 1024)
            info = tarfile.TarInfo(name="zeros.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        archive_size = os.path.getsize(tar_path)
        # Ratio limit of 2 — this should fail since zeros compress extremely well
        result = check_tar_bomb(str(tar_path), 1024 * 1024 * 1024, 100, 2)
        assert result is not None
        assert "compression ratio" in result.lower()

    def test_tar_with_directories_only(self, tmp_path: Path):
        """Tar with only directory entries passes (no size concern)."""
        tar_path = tmp_path / "dirs.tar"
        with tarfile.open(tar_path, "w") as tf:
            for i in range(5):
                info = tarfile.TarInfo(name=f"dir_{i}/")
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
        result = check_tar_bomb(str(tar_path), 10 * 1024 * 1024, 100, 200)
        assert result is None

    def test_corrupt_tar_passes(self, tmp_path: Path):
        """Corrupt/unreadable tar gracefully returns None (no false block)."""
        corrupt_path = tmp_path / "corrupt.tar"
        corrupt_path.write_bytes(b"\x00" * 512)
        result = check_tar_bomb(str(corrupt_path), 10 * 1024 * 1024, 100, 200)
        assert result is None


# --- ZIP bomb prevention in _extract_archive ---


class TestZipBombPrevention:
    """Tests for pre-extraction ZIP bomb detection in firmware_service."""

    def test_normal_zip_extracts(self, tmp_path: Path):
        """Normal ZIP extraction works."""
        from app.services.firmware_service import _extract_archive

        zip_path = tmp_path / "normal.zip"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file.txt", "hello world")
        _extract_archive(str(zip_path), str(output_dir))
        assert (output_dir / "file.txt").exists()

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "safe_extract_zip only enforces declared-size (max_size), not "
            "entry count. max_extraction_files is enforced post-extraction by "
            "check_extraction_limits (see test_file_count_exceeded above), "
            "not pre-extraction. If pre-flight entry-count checking is ever "
            "added to safe_extract_zip, flip this to a normal test."
        ),
    )
    def test_zip_with_many_entries_rejected(self, tmp_path: Path, monkeypatch):
        """ZIP with entry count exceeding limit is rejected (aspirational)."""
        from app.services.firmware_service import _extract_archive

        # Override settings to have a low file limit
        mock_settings = _make_settings(max_extraction_files=5)
        monkeypatch.setattr(
            "app.services.firmware_service.get_settings", lambda: mock_settings
        )

        zip_path = tmp_path / "many.zip"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(20):
                zf.writestr(f"file_{i}.txt", "x")
        with pytest.raises(ValueError, match="entry count"):
            _extract_archive(str(zip_path), str(output_dir))

    def test_zip_with_large_declared_size_rejected(self, tmp_path: Path, monkeypatch):
        """ZIP with large declared uncompressed size is rejected."""
        from app.services.firmware_service import _extract_archive

        mock_settings = _make_settings(max_extraction_size_mb=1)  # 1MB limit
        monkeypatch.setattr(
            "app.services.firmware_service.get_settings", lambda: mock_settings
        )

        zip_path = tmp_path / "big.zip"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 2MB of zeros compresses well but declared size is 2MB
            zf.writestr("big.bin", b"\x00" * (2 * 1024 * 1024))
        with pytest.raises(ValueError, match="declared uncompressed size"):
            _extract_archive(str(zip_path), str(output_dir))

    def test_zip_path_traversal_still_blocked(self, tmp_path: Path):
        """Path traversal prevention still works alongside bomb checks.

        safe_extract_zip raises ValueError with "Path escape detected (zipslip)"
        — this is the canonical message for zip-level traversal attempts.
        """
        from app.services.firmware_service import _extract_archive

        zip_path = tmp_path / "traversal.zip"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../../etc/passwd", "malicious")
        with pytest.raises(ValueError, match="[Pp]ath (traversal|escape).*zipslip"):
            _extract_archive(str(zip_path), str(output_dir))


# --- Unblob artifact cleanup ---


class TestCleanupUnblobArtifacts:
    """Tests for post-extraction artifact cleanup."""

    def test_removes_unknown_files(self, tmp_path: Path):
        """Empty ``.unknown`` files are removed; non-empty chunks are kept.

        cleanup_unblob_artifacts was updated to preserve non-empty ``.unknown``
        chunks because hw-firmware parsers (GFH / HMBN / Qualcomm MBN, etc.)
        can often identify them downstream. Only zero-byte ``.unknown``
        chunks are safe to drop. See the docstring in unpack_common.py.
        """
        # Two zero-byte .unknown files — removable.
        (tmp_path / "0-0.unknown").write_bytes(b"")
        (tmp_path / "1-1.unknown").write_bytes(b"")
        # Non-empty .unknown — kept for hw-firmware parsers.
        (tmp_path / "2-100.unknown").write_bytes(b"\x00" * 100)
        (tmp_path / "real_dir").mkdir()
        removed = cleanup_unblob_artifacts(str(tmp_path))
        assert removed == 2
        assert not (tmp_path / "0-0.unknown").exists()
        assert not (tmp_path / "1-1.unknown").exists()
        assert (tmp_path / "2-100.unknown").exists()
        assert (tmp_path / "real_dir").exists()

    def test_removes_raw_chunks_with_extract_dirs(self, tmp_path: Path):
        """Raw chunk files are removed when a corresponding _extract dir exists."""
        (tmp_path / "123-456.squashfs_v4_le").write_bytes(b"\x00" * 100)
        (tmp_path / "123-456.squashfs_v4_le_extract").mkdir()
        (tmp_path / "123-456.squashfs_v4_le_extract" / "file.txt").write_bytes(b"x")
        removed = cleanup_unblob_artifacts(str(tmp_path))
        assert removed == 1
        assert not (tmp_path / "123-456.squashfs_v4_le").exists()
        assert (tmp_path / "123-456.squashfs_v4_le_extract" / "file.txt").exists()

    def test_keeps_files_without_extract_dir(self, tmp_path: Path):
        """Files without a corresponding _extract dir are kept."""
        (tmp_path / "important.bin").write_bytes(b"\x00" * 100)
        removed = cleanup_unblob_artifacts(str(tmp_path))
        assert removed == 0
        assert (tmp_path / "important.bin").exists()

    def test_keeps_directories(self, tmp_path: Path):
        """Directories are never removed (even if named .unknown)."""
        (tmp_path / "some.unknown").mkdir()
        removed = cleanup_unblob_artifacts(str(tmp_path))
        assert removed == 0
        assert (tmp_path / "some.unknown").exists()

    def test_empty_directory(self, tmp_path: Path):
        """Empty directory returns 0 removed."""
        assert cleanup_unblob_artifacts(str(tmp_path)) == 0

    def test_nonexistent_directory(self, tmp_path: Path):
        """Nonexistent directory returns 0 without error."""
        assert cleanup_unblob_artifacts(str(tmp_path / "nope")) == 0
