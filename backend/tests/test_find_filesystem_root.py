"""Regression tests for find_filesystem_root's raw-image fallback gate.

Guards the Eaton Network M3 bug: a vendor firmware tar containing
``{EULA, manifest.json, .data_img(FAT16)}`` was classified as a valid
rootfs by the "best-entry-count" fallback of ``find_filesystem_root``,
short-circuiting the recursive unpacker and leaving the FAT16 payload
un-extracted. The fix teaches the fallback to recognise filesystem
images by magic bytes and return ``None`` instead, forcing the caller
to fall through to the unblob/binwalk chain that can actually extract
the nested filesystem.

Scenarios:
    Magic-byte probe (``_file_looks_like_fs_image``):
        - FAT12 / FAT16 / FAT32 images detected via BPB at offset 54/82.
        - ext2/3/4 detected via magic 0x53EF at offset 0x438.
        - squashfs LE ("hsqs") and BE ("sqsh") at offset 0.
        - UBI ("UBI!"), CramFS (0x28cd3d45 LE), JFFS2 (0x1985 or 0x8519).
        - Negative: plain text, zero bytes, ELF, tar, zip all return False.

    Directory probe (``_dir_has_filesystem_image``):
        - Dir with a FAT image among text files returns True.
        - Dir with only text/metadata returns False.
        - Dir with a symlink to a FAT image is NOT followed (False).

    Fallback behaviour (``find_filesystem_root``):
        - Eaton shape (FAT + EULA + manifest.json, no Linux markers)
          returns None — the defect being fixed.
        - Pure Linux rootfs (etc/ + usr/ + bin/) returns the dir
          (primary Linux-marker path unaffected by the new gate).
        - Hybrid (etc/ + usr/ + bin/ + stray .img) returns the rootfs
          (primary path still wins over the new gate).
        - Harmless fallback (dir with a single text file, no markers,
          no images) still returns the dir (benign fallback preserved).
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

from app.workers.unpack_common import (
    _dir_has_filesystem_image,
    _file_looks_like_fs_image,
    find_filesystem_root,
)


def _make_fat16_stub(path: Path, size_kb: int = 8) -> None:
    """Minimal FAT16-looking blob: MBR signature + BPB fs_type string."""
    buf = bytearray(size_kb * 1024)
    # BPB fs_type at offset 54 for FAT12/16
    buf[54:62] = b"FAT16   "
    # MBR boot signature at offset 510
    buf[510:512] = b"\x55\xaa"
    path.write_bytes(bytes(buf))


def _make_fat32_stub(path: Path, size_kb: int = 8) -> None:
    buf = bytearray(size_kb * 1024)
    # FAT32 fs_type lives at offset 82 (different BPB layout)
    buf[82:90] = b"FAT32   "
    buf[510:512] = b"\x55\xaa"
    path.write_bytes(bytes(buf))


def _make_ext4_stub(path: Path) -> None:
    # ext superblock magic 0x53EF at offset 0x438 (little-endian on disk)
    buf = bytearray(0x438 + 4)
    struct.pack_into("<H", buf, 0x438, 0xEF53)
    path.write_bytes(bytes(buf))


class TestFileMagicProbe:
    def test_fat16_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "part.img"
        _make_fat16_stub(f)
        assert _file_looks_like_fs_image(str(f))

    def test_fat32_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "part.img"
        _make_fat32_stub(f)
        assert _file_looks_like_fs_image(str(f))

    def test_ext4_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "rootfs.ext4"
        _make_ext4_stub(f)
        assert _file_looks_like_fs_image(str(f))

    def test_squashfs_le_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "root.squashfs"
        f.write_bytes(b"hsqs" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_squashfs_be_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "root.sqfs"
        f.write_bytes(b"sqsh" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_ubi_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "ubi.img"
        f.write_bytes(b"UBI!" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_cramfs_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "cramfs.bin"
        f.write_bytes(b"\x45\x3d\xcd\x28" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_jffs2_le_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "jffs.bin"
        f.write_bytes(b"\x19\x85" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_jffs2_be_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "jffs.bin"
        f.write_bytes(b"\x85\x19" + b"\x00" * 60)
        assert _file_looks_like_fs_image(str(f))

    def test_plain_text_not_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "EULA"
        f.write_text("This is a plain text end-user licence agreement." * 20)
        assert not _file_looks_like_fs_image(str(f))

    def test_zero_length_not_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert not _file_looks_like_fs_image(str(f))

    def test_json_not_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "manifest.json"
        f.write_text('{"vendor": "Eaton", "version": "2.2.0"}')
        assert not _file_looks_like_fs_image(str(f))

    def test_tar_not_detected(self, tmp_path: Path) -> None:
        # A real tar header starts with "ustar" at offset 257, not a FS magic.
        f = tmp_path / "rootfs.tar"
        buf = bytearray(1024)
        buf[257:263] = b"ustar\x00"
        f.write_bytes(bytes(buf))
        assert not _file_looks_like_fs_image(str(f))


class TestDirHasFilesystemImage:
    def test_eaton_shape_detected(self, tmp_path: Path) -> None:
        # Exact Eaton Network M3 shape: EULA + manifest.json + .data_img
        (tmp_path / "EULA").write_text("licence text")
        (tmp_path / "manifest.json").write_text('{"vendor": "Eaton"}')
        _make_fat16_stub(tmp_path / ".data_img")
        assert _dir_has_filesystem_image(str(tmp_path))

    def test_text_only_dir_not_detected(self, tmp_path: Path) -> None:
        (tmp_path / "README").write_text("readme")
        (tmp_path / "manifest.json").write_text("{}")
        assert not _dir_has_filesystem_image(str(tmp_path))

    def test_symlink_to_fs_image_not_followed(self, tmp_path: Path) -> None:
        # The helper must be symlink-safe — a symlink pointing at an
        # outside-the-dir image must NOT count as an image in the dir.
        outside = tmp_path.parent / "outside.img"
        _make_fat16_stub(outside)
        try:
            (tmp_path / "link_to_img").symlink_to(outside)
            assert not _dir_has_filesystem_image(str(tmp_path))
        finally:
            outside.unlink(missing_ok=True)

    def test_missing_dir_returns_false(self, tmp_path: Path) -> None:
        assert not _dir_has_filesystem_image(str(tmp_path / "nonexistent"))


class TestFindFilesystemRoot:
    def test_eaton_shape_returns_none(self, tmp_path: Path) -> None:
        """The Eaton defect case: FS image at top level, no Linux markers.

        Previously returned ``tmp_path`` via the "most entries" fallback.
        After the fix, returns None to force fallthrough to unblob.
        """
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "EULA").write_text("x" * 512)
        (extraction / "manifest.json").write_text('{"vendor": "Eaton"}')
        _make_fat16_stub(extraction / ".data_img")

        assert find_filesystem_root(str(extraction)) is None

    def test_pure_rootfs_tar_still_classifies(self, tmp_path: Path) -> None:
        """ADB device dump shape: etc/ + usr/ + bin/ — Linux markers present.

        Must still classify (primary path, unrelated to the new gate).
        """
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "etc").mkdir()
        (extraction / "etc" / "passwd").write_text("root:x:0:0::/:/bin/sh\n")
        (extraction / "usr").mkdir()
        (extraction / "bin").mkdir()

        result = find_filesystem_root(str(extraction))
        assert result is not None
        assert os.path.realpath(result) == os.path.realpath(str(extraction))

    def test_hybrid_rootfs_with_stray_image(self, tmp_path: Path) -> None:
        """Hybrid shape: Linux markers + stray .img. Primary wins.

        The Linux-marker path precedes the fallback, so the image alone
        cannot demote a legitimate rootfs.
        """
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "etc").mkdir()
        (extraction / "usr").mkdir()
        (extraction / "bin").mkdir()
        _make_fat16_stub(extraction / "stray.img")

        result = find_filesystem_root(str(extraction))
        assert result is not None
        assert os.path.realpath(result) == os.path.realpath(str(extraction))

    def test_benign_fallback_preserved(self, tmp_path: Path) -> None:
        """Non-rootfs non-image dir: the "most entries" fallback still runs.

        A tar with just a script + a readme — no Linux markers, no
        filesystem images — should still surface the extraction dir so
        the user sees the content.
        """
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "install.sh").write_text("#!/bin/sh\necho hi\n")
        (extraction / "README").write_text("readme")

        result = find_filesystem_root(str(extraction))
        assert result is not None
        assert _dir_has_filesystem_image(result) is False
