"""Tests for 7-Zip wrapper detection and unwrap in firmware uploads.

Covers the helpers that run before binwalk, so the unpack pipeline sees a
raw firmware image instead of the 7z container that some vendor OTAs ship.

These tests shell out to the real `7z` binary (already installed in the
backend container via p7zip-full). Skipped when 7z is unavailable on the
test runner.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.services.firmware_service import (
    _7Z_MAGIC,
    _extract_firmware_from_7z,
    _is_7z_archive,
)

pytestmark = pytest.mark.skipif(
    shutil.which("7z") is None,
    reason="7z binary not available on this system",
)


# ---------------------------------------------------------------------------
# Magic-byte detection
# ---------------------------------------------------------------------------

class TestIs7zArchive:
    def test_valid_magic(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        # Real 7z file needs more than just magic; we only probe the first
        # 6 bytes, so padding with zeros is enough for this check.
        path.write_bytes(_7Z_MAGIC + b"\x00" * 100)
        assert _is_7z_archive(str(path)) is True

    def test_wrong_magic(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"MZ\x00\x00\x00\x00" + b"\x00" * 100)
        assert _is_7z_archive(str(path)) is False

    def test_too_short(self, tmp_path: Path):
        """Files shorter than 6 bytes cannot match the magic signature."""
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x37\x7a")
        assert _is_7z_archive(str(path)) is False

    def test_missing_file(self, tmp_path: Path):
        assert _is_7z_archive(str(tmp_path / "does-not-exist.bin")) is False


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _make_unencrypted_7z(workdir: Path) -> tuple[Path, Path]:
    """Build an unencrypted 7z containing a small inner 'firmware.bin'.

    Returns (archive_path, inner_content_bytes_length).
    """
    inner = workdir / "firmware.bin"
    # A recognizable payload so we can sanity-check extraction round-tripped.
    payload = b"FIRMWARE_MARKER_" + b"x" * 2048
    inner.write_bytes(payload)

    archive = workdir / "wrapped.7z"
    result = subprocess.run(
        ["7z", "a", "-bso0", "-bsp0", str(archive), str(inner)],
        check=True,
        capture_output=True,
    )
    assert result.returncode == 0
    inner.unlink()  # leave only the archive
    return archive, payload


def _make_encrypted_7z(workdir: Path, password: str) -> Path:
    """Build a password-protected 7z (header-encrypted with -mhe=on)."""
    inner = workdir / "secret.bin"
    inner.write_bytes(b"ENCRYPTED_PAYLOAD" + b"x" * 1024)

    archive = workdir / "encrypted.7z"
    result = subprocess.run(
        [
            "7z", "a",
            "-bso0", "-bsp0",
            f"-p{password}",
            "-mhe=on",  # header encryption — mirrors the Creality OTA setup
            str(archive), str(inner),
        ],
        check=True,
        capture_output=True,
    )
    assert result.returncode == 0
    inner.unlink()
    return archive


async def test_extract_unencrypted_picks_largest(tmp_path: Path):
    archive, payload = _make_unencrypted_7z(tmp_path)
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    # The archive has to live inside output_dir's siblings, not output_dir
    # itself, to match how firmware_service lays things out.
    result = await _extract_firmware_from_7z(str(archive), str(output_dir))
    assert result is not None
    assert os.path.isfile(result)
    assert Path(result).read_bytes() == payload


async def test_extract_encrypted_raises_value_error(tmp_path: Path):
    archive = _make_encrypted_7z(tmp_path, password="correcthorse")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    with pytest.raises(ValueError, match="password-protected"):
        await _extract_firmware_from_7z(str(archive), str(output_dir))


async def test_extract_corrupt_raises_runtime_error(tmp_path: Path):
    # A file with correct magic but no real 7z structure after it.
    archive = tmp_path / "corrupt.7z"
    archive.write_bytes(_7Z_MAGIC + b"\x00" * 200)
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    with pytest.raises(RuntimeError, match="7z extraction failed"):
        await _extract_firmware_from_7z(str(archive), str(output_dir))


async def test_extract_cleans_up_temp_dir_on_failure(tmp_path: Path):
    """Extraction failures must not leave temp directories behind."""
    archive = _make_encrypted_7z(tmp_path, password="secret")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with pytest.raises(ValueError):
        await _extract_firmware_from_7z(str(archive), str(output_dir))

    # No 7z_extract_* directory should remain in output_dir
    remaining = [p for p in output_dir.iterdir() if p.name.startswith("7z_extract_")]
    assert remaining == []
