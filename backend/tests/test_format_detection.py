"""Magic-byte coverage for ``app.services.format_detection.detect_format``.

Covers each ``DetectedFormat`` value via a synthetic-header fixture
matching the documented magic bytes. For formats where Wairz can
produce a real fixture cheaply (tar, ZIP, APK-shaped ZIP, Android OTA
ZIP), we use the standard library's tarfile / zipfile modules. For
formats whose only public signature is the magic-byte sequence
(squashfs, cramfs, U-Boot uImage, JFFS2, FIT/DTB, ext, ELF, WIM, ISO
9660, QNX IFS, PE), we write the documented bytes at the right offset.

Acronis .tibx / .tib has no published magic-byte signature
(KB 63498); the detection code falls back to extension-based
classification — the test exercises that fallback explicitly per the
Rule #19 evidence-first discipline.
"""
from __future__ import annotations

import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.services.format_detection import (
    CAPABILITY_NOTES,
    EXTRACTION_CAPABILITY,
    DetectedFormat,
    ExtractionCapability,
    detect_format,
)


# ---------------------------------------------------------------------------
# Linux firmware-blob magic bytes (offset 0)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "header,expected",
    [
        # squashfs little-endian
        (b"hsqs" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # squashfs big-endian
        (b"sqsh" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # cramfs (LE 0x28cd3d45)
        (b"\x45\x3d\xcd\x28" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # U-Boot legacy uImage (BE 0x27051956)
        (b"\x27\x05\x19\x56" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # FIT / DTB (BE 0xd00dfeed)
        (b"\xd0\x0d\xfe\xed" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # JFFS2 dirent (LE 0x1985)
        (b"\x85\x19\x03\x20" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
        # ELF
        (b"\x7fELF" + b"\x00" * 60, DetectedFormat.LINUX_FIRMWARE_BLOB),
    ],
)
def test_detects_linux_firmware_blob(tmp_path: Path, header: bytes, expected: DetectedFormat):
    p = tmp_path / "blob.bin"
    p.write_bytes(header)
    assert detect_format(p) == expected


def test_detects_ext_filesystem_via_superblock(tmp_path: Path):
    """ext2/3/4 superblock magic 0x53ef sits at offset 1080 (block 1 + 56)."""
    p = tmp_path / "rootfs.ext"
    payload = bytearray(2048)
    # First 1024 bytes are reserved (boot block); ext superblock starts at 1024.
    # s_magic is at offset 56 within the superblock = file offset 1080.
    payload[1080:1082] = b"\x53\xef"
    p.write_bytes(bytes(payload))
    assert detect_format(p) == DetectedFormat.LINUX_FIRMWARE_BLOB


# ---------------------------------------------------------------------------
# WIM, QNX IFS, ISO 9660, PE, tar
# ---------------------------------------------------------------------------

def test_detects_wim_archive(tmp_path: Path):
    p = tmp_path / "boot.wim"
    p.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 64)
    assert detect_format(p) == DetectedFormat.WIM_ARCHIVE


@pytest.mark.parametrize(
    "magic",
    [
        # Documented QNX IFS signatures (mount_ifs docs).
        b"\xeb\x7e\xff\x7e",
        b"\x00\xff\x7e\xeb",
    ],
)
def test_detects_qnx_ifs(tmp_path: Path, magic: bytes):
    p = tmp_path / "qnx.ifs"
    p.write_bytes(magic + b"\x00" * 64)
    assert detect_format(p) == DetectedFormat.QNX_IFS


def test_detects_iso_9660(tmp_path: Path):
    """CD001 at offset 0x8001 is the ISO 9660 primary volume descriptor."""
    p = tmp_path / "image.iso"
    payload = bytearray(0x8100)
    payload[0x8001:0x8006] = b"CD001"
    p.write_bytes(bytes(payload))
    assert detect_format(p) == DetectedFormat.ISO_9660


def test_detects_windows_installer_iso(tmp_path: Path):
    """ISO 9660 + bootmgr signature → WINDOWS_INSTALLER_ISO upgrade."""
    p = tmp_path / "win.iso"
    payload = bytearray(0x8100)
    payload[0x8001:0x8006] = b"CD001"
    # Plant the bootmgr string somewhere in the head zone — detection
    # searches the whole 512 KB head buffer.
    payload[0x100:0x110] = b"bootmgr.efi xxxx"
    p.write_bytes(bytes(payload))
    assert detect_format(p) == DetectedFormat.WINDOWS_INSTALLER_ISO


def test_detects_pe_executable(tmp_path: Path):
    """MZ at 0 + e_lfanew → PE\\0\\0 → PE executable."""
    p = tmp_path / "win.exe"
    e_lfanew = 0x80
    payload = bytearray(0x100)
    payload[0:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3c, e_lfanew)
    payload[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    p.write_bytes(bytes(payload))
    assert detect_format(p) == DetectedFormat.PE_EXECUTABLE


def test_detects_tar_archive_via_ustar_marker(tmp_path: Path):
    """POSIX 'ustar' marker at offset 0x101 indicates a tar archive."""
    p = tmp_path / "rootfs.tar"
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "etc").mkdir()
    (inner / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    with tarfile.open(p, "w") as tf:
        tf.add(inner, arcname=".")
    assert detect_format(p) == DetectedFormat.TAR_ARCHIVE


def test_detects_tar_archive_by_extension_when_gzipped(tmp_path: Path):
    """gzip-compressed tar lacks the ustar marker in head — extension path catches it."""
    p = tmp_path / "rootfs.tar.gz"
    # Real gzip magic 0x1f8b at offset 0; the test verifies our
    # extension-fallback fires for .tar.gz when the head doesn't carry
    # the inner ustar marker.
    p.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 64)
    assert detect_format(p) == DetectedFormat.TAR_ARCHIVE


# ---------------------------------------------------------------------------
# ZIP-family classification (APK / Android OTA / generic)
# ---------------------------------------------------------------------------

def test_detects_android_apk(tmp_path: Path):
    """ZIP + AndroidManifest.xml + classes.dex → APK."""
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex", b"dex\n035\x00")
    assert detect_format(p) == DetectedFormat.ANDROID_APK


def test_detects_android_ota_via_payload_bin(tmp_path: Path):
    """A/B OTA ZIPs always contain payload.bin at the root."""
    p = tmp_path / "ota.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("payload.bin", b"CrAU")  # OTA payload header magic
        zf.writestr("payload_properties.txt", b"")
    assert detect_format(p) == DetectedFormat.ANDROID_OTA


def test_detects_android_ota_via_partition_images(tmp_path: Path):
    """≥2 partition .img files inside the ZIP → Android OTA factory image."""
    p = tmp_path / "factory.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("system.img", b"\x00" * 64)
        zf.writestr("boot.img", b"\x00" * 64)
        zf.writestr("vbmeta.img", b"\x00" * 64)
    assert detect_format(p) == DetectedFormat.ANDROID_OTA


def test_detects_generic_zip(tmp_path: Path):
    """ZIP without APK/OTA markers → generic ZIP_ARCHIVE."""
    p = tmp_path / "generic.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", b"hello")
        zf.writestr("data.bin", b"\x00" * 32)
    assert detect_format(p) == DetectedFormat.ZIP_ARCHIVE


# ---------------------------------------------------------------------------
# Acronis (extension-only fallback per Rule #19)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ext", [".tibx", ".tib"])
def test_detects_acronis_backup_via_extension(tmp_path: Path, ext: str):
    """No public magic bytes — falls back to canonical extension."""
    p = tmp_path / f"backup{ext}"
    # Random non-matching bytes — extension drives the verdict.
    p.write_bytes(b"\xff" * 256)
    assert detect_format(p) == DetectedFormat.ACRONIS_BACKUP


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

def test_unknown_when_no_signature_matches(tmp_path: Path):
    p = tmp_path / "blob"
    p.write_bytes(b"\xfe" * 256)
    assert detect_format(p) == DetectedFormat.UNKNOWN


def test_unknown_when_path_does_not_exist(tmp_path: Path):
    assert detect_format(tmp_path / "does-not-exist.bin") == DetectedFormat.UNKNOWN


# ---------------------------------------------------------------------------
# Capability mapping invariants
# ---------------------------------------------------------------------------

def test_every_detected_format_has_capability_mapping():
    """EXTRACTION_CAPABILITY must cover every DetectedFormat enum value."""
    missing = [f for f in DetectedFormat if f not in EXTRACTION_CAPABILITY]
    assert not missing, f"missing capability mapping for: {missing}"


def test_capability_notes_only_for_partial_or_none():
    """CAPABILITY_NOTES should only carry copy for partial / none formats.

    'full' formats run the standard flow without a banner — surfacing a
    note for them would clutter the upload UI.
    """
    for fmt, cap in EXTRACTION_CAPABILITY.items():
        if fmt in CAPABILITY_NOTES:
            assert cap in (
                ExtractionCapability.PARTIAL,
                ExtractionCapability.NONE,
            ), (
                f"{fmt} has a capability note but capability={cap}; "
                "notes should be reserved for partial/none formats"
            )
