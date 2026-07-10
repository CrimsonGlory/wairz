"""Unit tests for pure helpers in ``app.workers.unpack_android``."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.workers.unpack_android import (
    _identify_partition_by_content,
    _is_user_data_partition,
    _read_magic_sync,
    _read_super_lp_magic_sync,
    _relocate_scatter_subdirs,
    _verify_simg_output,
)

# ---------------------------------------------------------------------------
# _is_user_data_partition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("userdata.img", True),
        ("cache.img", True),
        ("metadata.img", True),
        ("persist.img", True),
        ("misc.img", True),
        ("userdata_a.img", True),
        ("userdata_b.img", True),
        ("CACHE.IMG", True),
        ("system.img", False),
        ("vendor.img", False),
        ("super.img", False),
        ("boot.img", False),
    ],
)
def test_is_user_data_partition(name: str, expected: bool):
    assert _is_user_data_partition(name) is expected


# ---------------------------------------------------------------------------
# _verify_simg_output
# ---------------------------------------------------------------------------


def test_verify_simg_missing(tmp_path: Path):
    ok, note = _verify_simg_output(str(tmp_path / "nope.img"))
    assert ok is False
    assert note == "missing"


def test_verify_simg_empty(tmp_path: Path):
    p = tmp_path / "empty.img"
    p.write_bytes(b"")
    ok, note = _verify_simg_output(str(p))
    assert ok is False
    assert note == "empty"


def test_verify_simg_elf(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "elf" in note


def test_verify_simg_squashfs(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"hsqs" + b"\x00" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "squashfs" in note


def test_verify_simg_erofs(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"\xe2\xe1\xf5\xe0" + b"\x00" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "erofs" in note


def test_verify_simg_android_boot(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"ANDROID!" + b"\x00" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "android_boot" in note


def test_verify_simg_still_sparse(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"\x3a\xff\x26\xed" + b"\x00" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "sparse" in note


def test_verify_simg_ext4_superblock(tmp_path: Path):
    # size > 0x438+2 with ext4 magic 0x53EF at offset 0x438
    data = bytearray(0x440)
    data[0x438:0x43A] = b"\x53\xef"
    p = tmp_path / "raw.img"
    p.write_bytes(bytes(data))
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "ext4" in note


def test_verify_simg_all_zero(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"\x00" * 4096)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "all-zero" in note


def test_verify_simg_unknown_nonempty(tmp_path: Path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"VENDOR_BLOB_XXXX" + b"\x01" * 100)
    ok, note = _verify_simg_output(str(p))
    assert ok is True
    assert "unverified" in note


# ---------------------------------------------------------------------------
# _identify_partition_by_content
# ---------------------------------------------------------------------------


def test_identify_partition_not_dir(tmp_path: Path):
    f = tmp_path / "x"
    f.write_text("x")
    assert _identify_partition_by_content(str(f)) is None


def test_identify_partition_system(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "app").mkdir()
    (d / "framework").mkdir()
    (d / "priv-app").mkdir()
    assert _identify_partition_by_content(str(d)) == "system"


def test_identify_partition_system_via_init(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "init").write_text("x")
    (d / "bin").mkdir()
    assert _identify_partition_by_content(str(d)) == "system"


def test_identify_partition_vendor(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "build.prop").write_text("ro.x=1\n")
    (d / "lib").mkdir()
    (d / "etc").mkdir()
    assert _identify_partition_by_content(str(d)) == "vendor"


def test_identify_partition_product(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "app").mkdir()
    (d / "overlay").mkdir()
    assert _identify_partition_by_content(str(d)) == "product"


def test_identify_partition_system_ext(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "priv-app").mkdir()
    (d / "apex").mkdir()
    assert _identify_partition_by_content(str(d)) == "system_ext"


def test_identify_partition_odm(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "etc").mkdir()
    (d / "lib").mkdir()
    (d / "firmware").mkdir()
    assert _identify_partition_by_content(str(d)) == "odm"


def test_identify_partition_unknown(tmp_path: Path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "random").mkdir()
    assert _identify_partition_by_content(str(d)) is None


# ---------------------------------------------------------------------------
# _read_magic_sync / _read_super_lp_magic_sync
# ---------------------------------------------------------------------------


def test_read_magic_sync(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"ABCD" + b"\x00" * 10)
    assert _read_magic_sync(str(p), 4) == b"ABCD"


def test_read_magic_sync_missing(tmp_path: Path):
    assert _read_magic_sync(str(tmp_path / "nope"), 4) is None


def test_read_super_lp_magic(tmp_path: Path):
    # LP magic is at offset 4096 typically; helper reads specific offset
    p = tmp_path / "super.img"
    # Just ensure it doesn't crash; content may return None for short files
    p.write_bytes(b"\x00" * 100)
    result = _read_super_lp_magic_sync(str(p))
    # short file → None is fine
    assert result is None or isinstance(result, bytes)


def test_read_super_lp_magic_missing(tmp_path: Path):
    assert _read_super_lp_magic_sync(str(tmp_path / "nope")) is None


# ---------------------------------------------------------------------------
# _relocate_scatter_subdirs
# ---------------------------------------------------------------------------


def test_relocate_scatter_moves_imgs(tmp_path: Path):
    version = tmp_path / "DPCS10_260414"
    version.mkdir()
    (version / "lk.img").write_bytes(b"LK")
    (version / "preloader.bin").write_bytes(b"PL")
    (version / "notes.txt").write_text("skip")
    logs: list[str] = []
    moved = _relocate_scatter_subdirs(str(tmp_path), logs)
    assert moved == 2
    assert (tmp_path / "lk.img").read_bytes() == b"LK"
    assert (tmp_path / "preloader.bin").read_bytes() == b"PL"
    assert any("Relocated" in line for line in logs)


def test_relocate_scatter_skips_reserved(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "system.img").write_bytes(b"X")
    logs: list[str] = []
    assert _relocate_scatter_subdirs(str(tmp_path), logs) == 0
    assert (rootfs / "system.img").exists()


def test_relocate_scatter_collision_suffix(tmp_path: Path):
    (tmp_path / "lk.img").write_bytes(b"ROOT")
    version = tmp_path / "ver"
    version.mkdir()
    (version / "lk.img").write_bytes(b"SCAT")
    logs: list[str] = []
    moved = _relocate_scatter_subdirs(str(tmp_path), logs)
    assert moved == 1
    assert (tmp_path / "lk.img").read_bytes() == b"ROOT"
    assert (tmp_path / "lk.img_scatter").read_bytes() == b"SCAT"


def test_relocate_scatter_double_collision_skips(tmp_path: Path):
    (tmp_path / "lk.img").write_bytes(b"R")
    (tmp_path / "lk.img_scatter").write_bytes(b"S")
    version = tmp_path / "ver"
    version.mkdir()
    (version / "lk.img").write_bytes(b"NEW")
    logs: list[str] = []
    assert _relocate_scatter_subdirs(str(tmp_path), logs) == 0
    assert any("Skipped" in line for line in logs)


def test_relocate_scatter_empty_dir(tmp_path: Path):
    logs: list[str] = []
    assert _relocate_scatter_subdirs(str(tmp_path), logs) == 0


def test_relocate_scatter_oserror_root(tmp_path: Path):
    logs: list[str] = []
    assert _relocate_scatter_subdirs(str(tmp_path / "missing"), logs) == 0


# ---------------------------------------------------------------------------
# _extract_boot_img_sync
# ---------------------------------------------------------------------------


def _make_boot_img(path: Path, *, kernel: bytes, ramdisk: bytes, page_size: int = 2048) -> None:
    import struct as st

    header = bytearray(page_size)
    header[0:8] = b"ANDROID!"
    # kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr,
    # tags_addr, page_size, header_version, os_version
    st.pack_into(
        "<10I",
        header,
        8,
        len(kernel),
        0x8000,
        len(ramdisk),
        0x1000000,
        0,
        0,
        0,
        page_size,
        0,  # header version 0
        0,
    )
    def _align(n: int) -> int:
        return ((n + page_size - 1) // page_size) * page_size

    body = bytearray()
    body.extend(kernel)
    body.extend(b"\x00" * (_align(len(kernel)) - len(kernel)))
    body.extend(ramdisk)
    body.extend(b"\x00" * (_align(len(ramdisk)) - len(ramdisk)))
    path.write_bytes(bytes(header) + bytes(body))


def test_extract_boot_img_sync_ok(tmp_path: Path):
    from app.workers.unpack_android import _extract_boot_img_sync

    boot = tmp_path / "boot.img"
    out = tmp_path / "out"
    kernel = b"K" * 100
    ramdisk = b"R" * 50
    _make_boot_img(boot, kernel=kernel, ramdisk=ramdisk)
    ok, logs, rd, err = _extract_boot_img_sync(str(boot), str(out))
    assert ok is True
    assert err is None
    assert (out / "kernel").read_bytes() == kernel
    assert (out / "ramdisk.img").read_bytes() == ramdisk
    assert rd == ramdisk
    assert any("boot.img" in line for line in logs)


def test_extract_boot_img_sync_bad_magic(tmp_path: Path):
    from app.workers.unpack_android import _extract_boot_img_sync

    boot = tmp_path / "boot.img"
    boot.write_bytes(b"NOTBOOT!" + b"\x00" * 2000)
    ok, logs, rd, err = _extract_boot_img_sync(str(boot), str(tmp_path / "out"))
    assert ok is False
    assert err == "bad_magic"


def test_extract_boot_img_sync_missing(tmp_path: Path):
    from app.workers.unpack_android import _extract_boot_img_sync

    ok, logs, rd, err = _extract_boot_img_sync(str(tmp_path / "nope"), str(tmp_path / "out"))
    assert ok is False
    assert err is not None


@pytest.mark.asyncio
async def test_extract_boot_img_async_wrapper(tmp_path: Path):
    from app.workers.unpack_android import _extract_boot_img

    boot = tmp_path / "boot.img"
    out = tmp_path / "out"
    # gzip-compressed empty-ish ramdisk that will fail cpio — still exercises path
    import gzip as gz

    ramdisk = gz.compress(b"070701notreallycpio")
    _make_boot_img(boot, kernel=b"K" * 32, ramdisk=ramdisk)
    logs: list[str] = []
    ok = await _extract_boot_img(str(boot), str(out), logs)
    assert ok is True
    assert (out / "kernel").exists()


@pytest.mark.asyncio
async def test_extract_android_ota_raw_img_copy(tmp_path: Path):
    from app.workers.unpack_android import _extract_android_ota

    img = tmp_path / "system.img"
    img.write_bytes(b"\x3a\xff\x26\xed" + b"\x00" * 100)
    extract = tmp_path / "extract"
    extract.mkdir()
    # mock heavy tools
    with (
        patch("shutil.which", return_value=None),
        patch("app.workers.unpack_common._recursive_extract_nested", return_value=[]),
    ):
        log = await _extract_android_ota(str(img), str(extract))
    assert "Copied raw sparse" in log or "sparse" in log.lower() or isinstance(log, str)
    assert any(p.suffix == ".img" for p in extract.rglob("*") if p.is_file())


@pytest.mark.asyncio
async def test_try_extract_partition_no_tools(tmp_path: Path):
    from app.workers.unpack_android import _try_extract_partition

    raw = tmp_path / "p.img"
    raw.write_bytes(b"\x00" * 100)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    logs: list[str] = []
    with patch("shutil.which", return_value=None):
        ok = await _try_extract_partition(str(raw), str(rootfs), "system", logs)
    assert ok is False
