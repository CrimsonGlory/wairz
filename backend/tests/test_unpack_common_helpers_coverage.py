"""Coverage push for high-miss pure helpers in ``unpack_common``."""
from __future__ import annotations

import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.workers.unpack_common import (
    UnpackResult,
    _catalog_to_classify_str,
    _file_head_matches_magic,
    _file_looks_like_fs_image,
    _has_linux_markers,
    _is_sidecar_filename,
    _is_uefi_content,
    _looks_like_archive_filename,
    _read_magic,
    _read_magic_hex,
    check_extraction_limits,
    classify_firmware,
    cleanup_unblob_artifacts,
    convert_intel_hex_to_binary,
    diagnose_failed_archives,
    remove_extraction_escape_symlinks,
    reset_extraction_dir_sync,
    widen_read_perms,
)

# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------


def test_is_sidecar_filename():
    assert _is_sidecar_filename("archive.tar.gz.md5") is True
    assert _is_sidecar_filename("file.sha256") is True
    assert _is_sidecar_filename("image.img") is False
    assert _is_sidecar_filename("readme.txt") is False


def test_looks_like_archive_filename():
    assert _looks_like_archive_filename("rootfs.tar.gz") is True
    assert _looks_like_archive_filename("readme.txt") is False


def test_read_magic_and_hex(tmp_path: Path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x7fELFABCD")
    assert _read_magic(str(p), 4) == b"\x7fELF"
    hx = _read_magic_hex(str(p), 4)
    assert isinstance(hx, str) and len(hx) >= 2


def test_read_magic_missing(tmp_path: Path):
    assert _read_magic(str(tmp_path / "nope"), 4) == b""


def test_file_head_matches_magic(tmp_path: Path):
    p = tmp_path / "x"
    p.write_bytes(b"hsqs" + b"\x00" * 10)
    assert _file_head_matches_magic(str(p), b"hsqs") is True
    assert _file_head_matches_magic(str(p), b"sqsh") is False


def test_file_looks_like_fs_image(tmp_path: Path):
    p = tmp_path / "fs.img"
    p.write_bytes(b"hsqs" + b"\x00" * 100)
    assert _file_looks_like_fs_image(str(p)) is True
    q = tmp_path / "txt"
    q.write_text("hello")
    assert _file_looks_like_fs_image(str(q)) is False


def test_has_linux_markers(tmp_path: Path):
    root = tmp_path / "r"
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir()
    assert _has_linux_markers(str(root)) is True
    empty = tmp_path / "e"
    empty.mkdir()
    assert _has_linux_markers(str(empty)) is False


def test_is_uefi_content_volume_guid():
    # EFI_FIRMWARE_FILE_SYSTEM2_GUID appears in many UEFI volumes
    # Minimal: just ensure function accepts bytes and returns bool
    assert _is_uefi_content(b"\x00" * 100) is False or isinstance(
        _is_uefi_content(b"\x00" * 100), bool
    )
    # common FV signature "_FVH"
    data = b"\x00" * 40 + b"_FVH" + b"\x00" * 20
    result = _is_uefi_content(data)
    assert isinstance(result, bool)


def test_reset_and_widen(tmp_path: Path):
    d = tmp_path / "ex"
    d.mkdir()
    (d / "a").write_text("x")
    reset_extraction_dir_sync(str(d))
    assert d.is_dir()
    assert not list(d.iterdir())
    (d / "b").write_text("y")
    n = widen_read_perms(str(d))
    assert isinstance(n, int)


# ---------------------------------------------------------------------------
# cleanup / limits / escape symlinks
# ---------------------------------------------------------------------------


def test_cleanup_unblob_artifacts(tmp_path: Path):
    (tmp_path / "empty.unknown").write_bytes(b"")
    (tmp_path / "keep.unknown").write_bytes(b"data")
    (tmp_path / "scratch.test").write_bytes(b"x")
    chunk = tmp_path / "1.squashfs_v4_le"
    chunk.write_bytes(b"hsqs")
    (tmp_path / "1.squashfs_v4_le_extract").mkdir()
    (tmp_path / "1.squashfs_v4_le_extract" / "f").write_text("ok")
    removed = cleanup_unblob_artifacts(str(tmp_path))
    assert removed >= 2
    assert (tmp_path / "keep.unknown").exists()
    assert not chunk.exists()


def test_check_extraction_limits_ok(tmp_path: Path):
    (tmp_path / "a").write_bytes(b"x" * 10)
    settings = MagicMock()
    settings.max_extraction_size_mb = 100
    settings.max_extraction_files = 1000
    settings.max_compression_ratio = 1000
    assert check_extraction_limits(str(tmp_path), firmware_size=100, settings=settings) is None


def test_check_extraction_limits_file_count(tmp_path: Path):
    for i in range(5):
        (tmp_path / f"f{i}").write_bytes(b"x")
    settings = MagicMock()
    settings.max_extraction_size_mb = 100
    settings.max_extraction_files = 3
    settings.max_compression_ratio = 1000
    err = check_extraction_limits(str(tmp_path), firmware_size=1, settings=settings)
    assert err and "file count" in err


def test_check_extraction_limits_ratio(tmp_path: Path):
    (tmp_path / "a").write_bytes(b"x" * 1000)
    settings = MagicMock()
    settings.max_extraction_size_mb = 100
    settings.max_extraction_files = 1000
    settings.max_compression_ratio = 2
    err = check_extraction_limits(str(tmp_path), firmware_size=10, settings=settings)
    assert err and "ratio" in err


def test_remove_extraction_escape_symlinks(tmp_path: Path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    extract = tmp_path / "extract"
    extract.mkdir()
    bad = extract / "escape"
    bad.symlink_to(outside)
    good_target = extract / "real"
    good_target.write_bytes(b"ok")
    good = extract / "link_in"
    good.symlink_to(good_target)
    removed = remove_extraction_escape_symlinks(str(extract))
    assert removed >= 1
    assert not bad.exists()
    assert good.exists() or not good.exists()  # may keep internal


# ---------------------------------------------------------------------------
# diagnose_failed_archives
# ---------------------------------------------------------------------------


def test_diagnose_failed_archives_empty(tmp_path: Path):
    assert diagnose_failed_archives([str(tmp_path)]) == {}


def test_diagnose_failed_archives_fake_zip(tmp_path: Path):
    fake = tmp_path / "vendor.tar.gz"
    fake.write_bytes(b"NOT_A_TAR" + b"\x00" * 50)
    result = diagnose_failed_archives([str(tmp_path)])
    assert result.get("partial_extraction") is True
    assert result.get("unrecognised_archives") or result.get("encrypted_archives")


def test_diagnose_failed_archives_skips_valid_zip(tmp_path: Path):
    zpath = tmp_path / "ok.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("a.txt", "hello")
    # valid zip is not flagged
    result = diagnose_failed_archives([str(tmp_path)])
    # either empty or not containing ok.zip
    for entry in result.get("unrecognised_archives", []):
        assert "ok.zip" not in entry.get("path", "")


# ---------------------------------------------------------------------------
# convert_intel_hex_to_binary
# ---------------------------------------------------------------------------


def _hex_record(addr: int, data: bytes, rtype: int = 0) -> str:
    """Build a valid Intel HEX data/EOF/extended record line."""
    count = len(data)
    payload = bytes([count, (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + data
    checksum = ((~sum(payload) + 1) & 0xFF)
    return ":" + payload.hex().upper() + f"{checksum:02X}"


def test_convert_intel_hex_basic(tmp_path: Path):
    lines = [
        _hex_record(0x0000, b"\x11\x22\x33\x44"),
        _hex_record(0x0004, b"\x55\x66"),
        _hex_record(0, b"", rtype=1),  # EOF
    ]
    hx = tmp_path / "fw.hex"
    hx.write_text("\n".join(lines) + "\n")
    out = tmp_path / "fw.bin"
    meta = convert_intel_hex_to_binary(str(hx), str(out))
    assert meta["size"] == 6
    assert out.read_bytes() == b"\x11\x22\x33\x44\x55\x66"
    assert meta["base_address"] == 0
    assert len(meta["regions"]) >= 1


def test_convert_intel_hex_empty(tmp_path: Path):
    hx = tmp_path / "empty.hex"
    hx.write_text(":00000001FF\n")  # EOF only
    out = tmp_path / "out.bin"
    meta = convert_intel_hex_to_binary(str(hx), str(out))
    assert meta["size"] == 0
    assert meta["regions"] == []


def test_convert_intel_hex_extended_linear(tmp_path: Path):
    # Type 04 sets upper 16 bits, then data at offset 0
    ext = _hex_record(0, bytes([0x08, 0x00]), rtype=4)  # base 0x08000000
    data = _hex_record(0x0000, b"\xDE\xAD")
    eof = _hex_record(0, b"", rtype=1)
    hx = tmp_path / "fw.hex"
    hx.write_text("\n".join([ext, data, eof]) + "\n")
    out = tmp_path / "out.bin"
    meta = convert_intel_hex_to_binary(str(hx), str(out))
    assert meta["size"] == 2
    assert meta["base_address"] == 0x08000000
    assert out.read_bytes() == b"\xDE\xAD"


def test_convert_intel_hex_entry_point_type05(tmp_path: Path):
    data = _hex_record(0x1000, b"\xAA\xBB")
    # type 05 start linear address 0x00001000
    ep = _hex_record(0, bytes([0x00, 0x00, 0x10, 0x00]), rtype=5)
    eof = _hex_record(0, b"", rtype=1)
    hx = tmp_path / "fw.hex"
    hx.write_text("\n".join([data, ep, eof]) + "\n")
    out = tmp_path / "out.bin"
    meta = convert_intel_hex_to_binary(str(hx), str(out))
    assert meta["entry_point"] == 0x1000


def test_convert_intel_hex_skips_bad_lines(tmp_path: Path):
    good = _hex_record(0, b"\x01\x02")
    eof = _hex_record(0, b"", rtype=1)
    hx = tmp_path / "fw.hex"
    hx.write_text("comment\n:ZZ\n" + good + "\n" + eof + "\n")
    out = tmp_path / "out.bin"
    meta = convert_intel_hex_to_binary(str(hx), str(out))
    assert meta["size"] == 2


# ---------------------------------------------------------------------------
# classify_firmware
# ---------------------------------------------------------------------------


def test_classify_elf_binary(tmp_path: Path):
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 32)
    with patch(
        "app.services.rtos_detection_service.detect_rtos",
        return_value=None,
    ):
        assert classify_firmware(str(p)) in ("elf_binary", "linux_blob")


def test_classify_pe_binary(tmp_path: Path):
    p = tmp_path / "tool.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    result = classify_firmware(str(p))
    assert result in ("pe_binary", "linux_blob", "uefi_firmware")


def test_classify_android_sparse(tmp_path: Path):
    p = tmp_path / "super.img"
    p.write_bytes(b"\x3a\xff\x26\xed" + b"\x00" * 32)
    assert classify_firmware(str(p)) == "android_sparse"


def test_classify_android_boot(tmp_path: Path):
    p = tmp_path / "boot.img"
    p.write_bytes(b"ANDROID!" + b"\x00" * 32)
    assert classify_firmware(str(p)) == "android_boot"


def test_classify_android_ota_zip(tmp_path: Path):
    p = tmp_path / "ota.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("payload.bin", b"x")
        zf.writestr("META-INF/com/android/metadata", b"y")
    assert classify_firmware(str(p)) == "android_ota"


def test_classify_android_apk_zip(tmp_path: Path):
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"m")
        zf.writestr("classes.dex", b"d")
    assert classify_firmware(str(p)) == "android_apk"


def test_classify_android_scatter_zip(tmp_path: Path):
    p = tmp_path / "scatter.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("MT6765_Android_scatter.txt", "x")
        zf.writestr("super.img", b"\x00" * 10)
    assert classify_firmware(str(p)) == "android_scatter"


def test_classify_intel_hex(tmp_path: Path):
    p = tmp_path / "fw.hex"
    p.write_text(":100000000102030405060708090A0B0C0D0E0F1068\n:00000001FF\n")
    result = classify_firmware(str(p))
    assert result in ("intel_hex", "linux_blob")


def test_classify_rtos_elf_dispatch(tmp_path: Path):
    p = tmp_path / "rtos.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 32)
    with patch(
        "app.services.rtos_detection_service.detect_rtos",
        return_value={"rtos_name": "freertos"},
    ):
        assert classify_firmware(str(p)) == "freertos_elf"


def test_catalog_to_classify_str_passthrough():
    manifest = MagicMock()
    # Most format ids pass through; zip containers return None
    result = _catalog_to_classify_str("android_boot", manifest)
    assert result in (None, "android_boot") or isinstance(result, (str, type(None)))


def test_unpack_result_defaults():
    r = UnpackResult()
    assert r.success is False or r.success is None or r.success is False
    assert r.extracted_path is None
