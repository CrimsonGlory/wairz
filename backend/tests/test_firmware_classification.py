"""Tests for firmware classification in the unpack worker."""

import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.workers.unpack import classify_firmware
from app.workers.unpack_android import _extract_boot_img


class TestAndroidOtaDetection:
    """Test classify_firmware() recognises Android OTA ZIP files."""

    def test_zip_with_payload_bin(self, tmp_path: Path):
        """A ZIP containing payload.bin is classified as android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("payload.bin", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_system_and_boot_img(self, tmp_path: Path):
        """A ZIP containing system.img + boot.img (>= 2 markers) is android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
            zf.writestr("boot.img", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_system_img_only(self, tmp_path: Path):
        """A ZIP containing only system.img still counts as android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"\x00" * 16)
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_with_meta_inf_android(self, tmp_path: Path):
        """A ZIP with updater-script + update-binary (OTA metadata) is android_ota."""
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("META-INF/com/google/android/updater-script", "")
            zf.writestr("META-INF/com/google/android/update-binary", b"\x00")
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_zip_without_android_markers_not_ota(self, tmp_path: Path):
        """A generic ZIP without Android markers is NOT classified as android_ota."""
        zip_path = tmp_path / "generic.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("readme.txt", "Hello")
            zf.writestr("data.bin", b"\x00" * 16)
        result = classify_firmware(str(zip_path))
        assert result != "android_ota"

    def test_motorola_factory_flash_via_sparsechunks(self, tmp_path: Path):
        """Moto-G32 / Moto-G30 factory flash packages don't include
        payload.bin, system.img, or META-INF markers — but they DO ship
        ``super.img_sparsechunk.0..10``. Issue #20b (2026-05-13): the
        sparsechunk pattern alone is a strong Android-OTA signal and
        must classify as android_ota so Stage 1 ``_extract_android_ota``
        runs the sparsechunk-reassembly path from commit 6538735.
        """
        zip_path = tmp_path / "moto_flash.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(11):
                zf.writestr(f"super.img_sparsechunk.{i}", b"\xff" * 64)
            zf.writestr("flashfile.xml", b"<?xml version='1.0'?>")
        assert classify_firmware(str(zip_path)) == "android_ota"

    def test_motorola_factory_flash_via_broader_partition_set(self, tmp_path: Path):
        """The Moto-G32 namelist contains boot.img + vbmeta.img + dtbo.img
        + vendor_boot.img. Under the OLD narrow {system,boot,vendor}.img
        set only boot.img matched (1, < 2 → fallthrough → linux_blob).
        Issue #20b widens the partition set to include vbmeta.img +
        dtbo.img + vendor_boot.img + init_boot.img + vbmeta_system.img +
        modem.img so the ≥2 condition fires cleanly."""
        zip_path = tmp_path / "moto_partitions.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("boot.img", b"\x00" * 64)
            zf.writestr("vendor_boot.img", b"\x00" * 64)
            zf.writestr("dtbo.img", b"\x00" * 64)
            zf.writestr("vbmeta.img", b"\x00" * 64)
            # No sparsechunks; relies on the partition-set check only.
        assert classify_firmware(str(zip_path)) == "android_ota"


class TestAndroidSparseImageDetection:
    """Test classify_firmware() recognises Android sparse images."""

    def test_sparse_magic_bytes(self, tmp_path: Path):
        """A file starting with 0x3AFF26ED (little-endian) is android_sparse."""
        sparse_path = tmp_path / "system.img"
        sparse_path.write_bytes(b"\x3a\xff\x26\xed" + b"\x00" * 64)
        assert classify_firmware(str(sparse_path)) == "android_sparse"

    def test_wrong_magic_not_sparse(self, tmp_path: Path):
        """A file with similar but wrong magic bytes is NOT android_sparse."""
        path = tmp_path / "not_sparse.img"
        path.write_bytes(b"\x3a\xff\x26\xee" + b"\x00" * 64)
        assert classify_firmware(str(path)) != "android_sparse"


class TestLinuxRootfsTarDetection:
    """Test classify_firmware() recognises Linux rootfs tar archives."""

    def test_tar_with_linux_dirs(self, tmp_path: Path):
        """A tar containing standard Linux dirs is classified as linux_rootfs_tar."""
        tar_path = tmp_path / "rootfs.tar"
        with tarfile.open(tar_path, "w") as tf:
            for dirname in ("etc", "usr", "bin", "lib"):
                info = tarfile.TarInfo(name=dirname)
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
        assert classify_firmware(str(tar_path)) == "linux_rootfs_tar"


class TestElfBinaryDetection:
    """Test classify_firmware() recognises ELF binaries."""

    def test_elf_magic(self, tmp_path: Path):
        """A file with ELF magic \\x7fELF is classified as elf_binary."""
        elf_path = tmp_path / "firmware.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
        assert classify_firmware(str(elf_path)) == "elf_binary"


class TestAndroidBootImageDetection:
    """Test classify_firmware() recognises Android boot images."""

    def test_boot_img_magic(self, tmp_path: Path):
        """A file starting with ANDROID! magic is classified as android_boot."""
        boot_path = tmp_path / "boot.img"
        boot_path.write_bytes(b"ANDROID!" + b"\x00" * 1640)
        assert classify_firmware(str(boot_path)) == "android_boot"

    def test_wrong_magic_not_boot(self, tmp_path: Path):
        """A file starting with similar but wrong bytes is NOT android_boot."""
        path = tmp_path / "not_boot.img"
        path.write_bytes(b"ANDROID?" + b"\x00" * 1640)
        assert classify_firmware(str(path)) != "android_boot"


class TestUnknownAndEdgeCases:
    """Test fallback and edge-case handling."""

    def test_unknown_format_returns_linux_blob(self, tmp_path: Path):
        """An unrecognised binary blob returns linux_blob (for binwalk)."""
        blob_path = tmp_path / "mystery.bin"
        blob_path.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 64)
        assert classify_firmware(str(blob_path)) == "linux_blob"

    def test_empty_file(self, tmp_path: Path):
        """An empty file does not crash and returns a valid classification."""
        empty_path = tmp_path / "empty"
        empty_path.write_bytes(b"")
        result = classify_firmware(str(empty_path))
        assert result in (
            "android_ota", "android_sparse", "android_boot",
            "linux_rootfs_tar", "linux_blob", "elf_binary",
            "intel_hex", "pe_binary", "unknown",
        )

    def test_pe_binary_detection(self, tmp_path: Path):
        """A file starting with MZ is classified as pe_binary."""
        pe_path = tmp_path / "firmware.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 64)
        assert classify_firmware(str(pe_path)) == "pe_binary"


class TestPartitionDumpTarDetection:
    """Test classify_firmware() recognises partition dump tarballs."""

    def test_tar_with_qualcomm_partitions(self, tmp_path: Path):
        """A tarball with Qualcomm partition images is partition_dump_tar."""
        tar_path = tmp_path / "edl_dump.tar"
        with tarfile.open(tar_path, "w") as tf:
            for name in ["boot.img", "system.img", "vendor.img", "modem.img", "tz.img"]:
                data = b"\x00" * 64
                import io
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        assert classify_firmware(str(tar_path)) == "partition_dump_tar"

    def test_tar_with_mtk_partitions(self, tmp_path: Path):
        """A tarball with MTK partition images is partition_dump_tar."""
        tar_path = tmp_path / "mtk_dump.tar"
        with tarfile.open(tar_path, "w") as tf:
            for name in ["boot.img", "recovery.img", "super.img", "lk.img"]:
                data = b"\x00" * 64
                import io
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        assert classify_firmware(str(tar_path)) == "partition_dump_tar"

    def test_tar_with_random_imgs_not_partition_dump(self, tmp_path: Path):
        """A tarball with non-partition .img files is NOT partition_dump_tar."""
        tar_path = tmp_path / "random.tar"
        with tarfile.open(tar_path, "w") as tf:
            for name in ["photo1.img", "photo2.img", "photo3.img"]:
                data = b"\x00" * 64
                import io
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        # 3 .img files but 0 match known partition names
        assert classify_firmware(str(tar_path)) != "partition_dump_tar"


def _make_boot_img(
    tmp_path: Path,
    kernel_data: bytes = b"\x00" * 4096,
    ramdisk_data: bytes = b"",
    second_data: bytes = b"",
    page_size: int = 2048,
    header_version: int = 0,
) -> Path:
    """Build a minimal Android boot image for testing."""
    # Build the v0 header (1648 bytes total but only first ~48 bytes matter)
    header = bytearray(page_size)
    header[0:8] = b"ANDROID!"
    struct.pack_into("<10I", header, 8,
        len(kernel_data), 0x10008000,  # kernel_size, kernel_addr
        len(ramdisk_data), 0x11000000,  # ramdisk_size, ramdisk_addr
        len(second_data), 0x10F00000,   # second_size, second_addr
        0x10000100,                      # tags_addr
        page_size,                       # page_size
        header_version,                  # header_version
        0,                               # os_version
    )

    boot_path = tmp_path / "boot.img"
    with open(boot_path, "wb") as f:
        f.write(header)
        # Page-align each component
        def write_padded(data: bytes):
            f.write(data)
            pad = (page_size - (len(data) % page_size)) % page_size
            f.write(b"\x00" * pad)
        write_padded(kernel_data)
        if ramdisk_data:
            write_padded(ramdisk_data)
        if second_data:
            write_padded(second_data)
    return boot_path


class TestBootImgExtraction:
    """Test _extract_boot_img() extracts kernel and ramdisk."""

    @pytest.mark.asyncio
    async def test_extracts_kernel(self, tmp_path: Path):
        """Kernel is extracted from a well-formed boot.img."""
        kernel_content = b"\x7fELF" + b"\xab" * 8188
        boot_path = _make_boot_img(tmp_path, kernel_data=kernel_content)

        output_dir = tmp_path / "output"
        log: list[str] = []
        result = await _extract_boot_img(str(boot_path), str(output_dir), log)

        assert result is True
        kernel_file = output_dir / "kernel"
        assert kernel_file.exists()
        assert kernel_file.read_bytes() == kernel_content

    @pytest.mark.asyncio
    async def test_extracts_ramdisk_raw(self, tmp_path: Path):
        """Ramdisk image file is saved even if decompression fails."""
        ramdisk_content = b"\xde\xad" * 2048  # Not valid gzip/cpio
        boot_path = _make_boot_img(
            tmp_path, kernel_data=b"\x00" * 4096, ramdisk_data=ramdisk_content,
        )

        output_dir = tmp_path / "output"
        log: list[str] = []
        await _extract_boot_img(str(boot_path), str(output_dir), log)

        ramdisk_file = output_dir / "ramdisk.img"
        assert ramdisk_file.exists()
        assert ramdisk_file.read_bytes() == ramdisk_content

    @pytest.mark.asyncio
    async def test_rejects_bad_magic(self, tmp_path: Path):
        """Files without ANDROID! magic are rejected."""
        bad_path = tmp_path / "bad.img"
        bad_path.write_bytes(b"NOTANDROID" + b"\x00" * 1640)

        output_dir = tmp_path / "output"
        log: list[str] = []
        result = await _extract_boot_img(str(bad_path), str(output_dir), log)

        assert result is False
        assert any("bad magic" in line for line in log)

    @pytest.mark.asyncio
    async def test_header_version_logged(self, tmp_path: Path):
        """Header version is reported in the log."""
        boot_path = _make_boot_img(tmp_path, header_version=2)

        output_dir = tmp_path / "output"
        log: list[str] = []
        await _extract_boot_img(str(boot_path), str(output_dir), log)

        assert any("header v2" in line for line in log)
