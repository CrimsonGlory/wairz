"""Coverage-oriented unit tests for ``app.workers.unpack`` pure helpers + branches.

Honest production-function calls with filesystem fixtures and mocked
subprocess/detection dependencies — no live Docker extraction.
"""
from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.workers.unpack import (
    _analyze_filesystem,
    _analyze_uefi_extraction,
    _detect_uefi_architecture,
    _pick_detection_root,
    _run_hardware_firmware_detection_safe,
    unpack_firmware,
)
from app.workers.unpack_common import UnpackResult

# ---------------------------------------------------------------------------
# _pick_detection_root
# ---------------------------------------------------------------------------


def test_pick_detection_root_single_partition(tmp_path: Path):
    root = tmp_path / "extracted" / "rootfs"
    root.mkdir(parents=True)
    assert _pick_detection_root(str(root)) == str(root)


def test_pick_detection_root_android_siblings(tmp_path: Path):
    container = tmp_path / "container"
    (container / "system").mkdir(parents=True)
    (container / "vendor").mkdir()
    (container / "product").mkdir()
    extracted = container / "system"
    assert _pick_detection_root(str(extracted)) == str(container)


def test_pick_detection_root_partition_star_dirs(tmp_path: Path):
    container = tmp_path / "container"
    (container / "partition_0_erofs").mkdir(parents=True)
    (container / "partition_1_erofs").mkdir()
    extracted = container / "partition_0_erofs"
    assert _pick_detection_root(str(extracted)) == str(container)


def test_pick_detection_root_oserror_returns_input(tmp_path: Path):
    missing = tmp_path / "nope" / "child"
    # parent doesn't exist → scandir OSError → return input
    assert _pick_detection_root(str(missing)) == str(missing)


def test_pick_detection_root_root_path_no_parent():
    # dirname of "/" is "/" or "" depending on platform; should not crash
    result = _pick_detection_root("/")
    assert result == "/"


# ---------------------------------------------------------------------------
# _detect_uefi_architecture
# ---------------------------------------------------------------------------


def _write_pe_body(path: Path, machine: int) -> None:
    """Minimal MZ + PE header with a given MACHINE type."""
    pe_offset = 0x80
    data = bytearray(pe_offset + 8)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_offset + 4, machine)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(data))


def test_detect_uefi_arch_x86_64(tmp_path: Path):
    _write_pe_body(tmp_path / "DXE" / "body.bin", 0x8664)
    arch, endian = _detect_uefi_architecture(str(tmp_path))
    assert arch == "x86_64"
    assert endian == "little"


def test_detect_uefi_arch_aarch64(tmp_path: Path):
    _write_pe_body(tmp_path / "a" / "body.bin", 0xAA64)
    arch, endian = _detect_uefi_architecture(str(tmp_path))
    assert arch == "aarch64"
    assert endian == "little"


def test_detect_uefi_arch_x86(tmp_path: Path):
    _write_pe_body(tmp_path / "b" / "body.bin", 0x014C)
    arch, endian = _detect_uefi_architecture(str(tmp_path))
    assert arch == "x86"


def test_detect_uefi_arch_arm(tmp_path: Path):
    _write_pe_body(tmp_path / "c" / "body.bin", 0x01C0)
    arch, endian = _detect_uefi_architecture(str(tmp_path))
    assert arch == "arm"


def test_detect_uefi_arch_skips_non_mz(tmp_path: Path):
    p = tmp_path / "body.bin"
    p.write_bytes(b"\x00" * 200)
    assert _detect_uefi_architecture(str(tmp_path)) == (None, None)


def test_detect_uefi_arch_skips_bad_pe_sig(tmp_path: Path):
    pe_offset = 0x80
    data = bytearray(pe_offset + 8)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"XX\x00\x00"
    (tmp_path / "body.bin").write_bytes(bytes(data))
    assert _detect_uefi_architecture(str(tmp_path)) == (None, None)


def test_detect_uefi_arch_empty_dir(tmp_path: Path):
    assert _detect_uefi_architecture(str(tmp_path)) == (None, None)


# ---------------------------------------------------------------------------
# _analyze_uefi_extraction
# ---------------------------------------------------------------------------


def test_analyze_uefi_no_dump_dir(tmp_path: Path):
    result = UnpackResult()
    _analyze_uefi_extraction(result, str(tmp_path))
    assert result.success is not True
    assert result.error and "no output" in result.error.lower()


def test_analyze_uefi_success(tmp_path: Path):
    dump = tmp_path / "bios.dump"
    dump.mkdir()
    _write_pe_body(dump / "module" / "body.bin", 0x8664)
    (dump / "readme.txt").write_text("x")
    result = UnpackResult()
    _analyze_uefi_extraction(result, str(tmp_path))
    assert result.success is True
    assert result.extracted_path == str(dump)
    assert result.architecture == "x86_64"
    assert "UEFI" in (result.os_info or "")


# ---------------------------------------------------------------------------
# _analyze_filesystem
# ---------------------------------------------------------------------------


def test_analyze_filesystem_with_rootfs(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    (rootfs / "etc" / "hostname").write_text("dev\n")
    (rootfs / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 20)

    result = UnpackResult()
    with (
        patch("app.workers.unpack.find_filesystem_root", return_value=str(rootfs)),
        patch(
            "app.services.rtos_detection_service.detect_firmware_kind",
            return_value=MagicMock(kind="linux", flavor=None, notes="rootfs"),
        ),
        patch("app.workers.unpack.detect_architecture", return_value=("mips", "big")),
        patch("app.workers.unpack.detect_os_info", return_value="OpenWrt"),
        patch("app.workers.unpack.detect_kernel", return_value=None),
        patch("app.workers.unpack._find_binwalk_output_dir", return_value=None),
    ):
        _analyze_filesystem(result, str(tmp_path), firmware_path=str(tmp_path / "fw.bin"))

    assert result.success is True
    assert result.extracted_path == str(rootfs)
    assert result.architecture == "mips"
    assert result.endianness == "big"
    assert result.os_info == "OpenWrt"
    assert result.firmware_kind == "linux"


def test_analyze_filesystem_no_root_unknown(tmp_path: Path):
    result = UnpackResult()
    with (
        patch("app.workers.unpack.find_filesystem_root", return_value=None),
        patch(
            "app.services.rtos_detection_service.detect_firmware_kind",
            return_value=MagicMock(kind="unknown", flavor=None, notes="nada"),
        ),
    ):
        _analyze_filesystem(result, str(tmp_path))
    assert result.success is not True
    assert result.error and "filesystem root" in result.error.lower()


def test_analyze_filesystem_no_root_rtos(tmp_path: Path):
    result = UnpackResult()
    with (
        patch("app.workers.unpack.find_filesystem_root", return_value=None),
        patch(
            "app.services.rtos_detection_service.detect_firmware_kind",
            return_value=MagicMock(kind="rtos", flavor="freertos", notes="fr"),
        ),
    ):
        _analyze_filesystem(result, str(tmp_path))
    assert result.success is True
    assert result.firmware_kind == "rtos"
    assert result.rtos_flavor == "freertos"


def test_analyze_filesystem_arch_kernel_fallback(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    result = UnpackResult()
    with (
        patch("app.workers.unpack.find_filesystem_root", return_value=str(rootfs)),
        patch(
            "app.services.rtos_detection_service.detect_firmware_kind",
            return_value=MagicMock(kind="linux", flavor=None, notes="ok"),
        ),
        patch("app.workers.unpack.detect_architecture", return_value=(None, None)),
        patch(
            "app.workers.unpack.detect_architecture_from_kernel",
            return_value=("arm", "little"),
        ) as ker,
        patch("app.workers.unpack.detect_os_info", return_value=None),
        patch("app.workers.unpack.detect_kernel", return_value="/boot/zImage"),
        patch("app.workers.unpack._find_binwalk_output_dir", return_value=None),
    ):
        _analyze_filesystem(result, str(tmp_path / "extract"))
    assert result.architecture == "arm"
    assert result.kernel_path == "/boot/zImage"
    ker.assert_called_once()


# ---------------------------------------------------------------------------
# _run_hardware_firmware_detection_safe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hw_detection_safe_zero_blobs_still_runs_walkers():
    fid = uuid.uuid4()
    walkers = [AsyncMock(), AsyncMock()]

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.commit = AsyncMock()

    with (
        patch(
            "app.database.async_session_factory",
            return_value=mock_session,
        ),
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(return_value=0),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=walkers,
        ),
    ):
        await _run_hardware_firmware_detection_safe(fid, "/tmp/extracted")

    for w in walkers:
        w.assert_awaited_once_with(fid)


@pytest.mark.asyncio
async def test_hw_detection_safe_with_blobs_builds_graph():
    fid = uuid.uuid4()
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.commit = AsyncMock()

    graph = MagicMock(edges=[1, 2], unresolved_count=0)
    walker = AsyncMock()

    with (
        patch("app.database.async_session_factory", return_value=mock_session),
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(return_value=3),
        ),
        patch(
            "app.services.hardware_firmware.graph.build_driver_firmware_graph",
            new=AsyncMock(return_value=graph),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[walker],
        ),
    ):
        await _run_hardware_firmware_detection_safe(fid, "/data/x")

    walker.assert_awaited_once_with(fid)


@pytest.mark.asyncio
async def test_hw_detection_safe_detection_failure_still_walks():
    fid = uuid.uuid4()
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    walker = AsyncMock()
    with (
        patch("app.database.async_session_factory", return_value=mock_session),
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(side_effect=RuntimeError("db down")),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[walker],
        ),
    ):
        await _run_hardware_firmware_detection_safe(fid, "/x")
    walker.assert_awaited_once()


@pytest.mark.asyncio
async def test_hw_detection_safe_walker_exception_swallowed():
    fid = uuid.uuid4()
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    bad = AsyncMock(side_effect=RuntimeError("walker boom"))
    good = AsyncMock()

    with (
        patch("app.database.async_session_factory", return_value=mock_session),
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(return_value=0),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[bad, good],
        ),
    ):
        await _run_hardware_firmware_detection_safe(fid, "/x")
    good.assert_awaited_once()


# ---------------------------------------------------------------------------
# unpack_firmware / _unpack_firmware_inner fast paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_firmware_missing_file(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    result = await unpack_firmware(str(tmp_path / "missing.bin"), str(out))
    assert result.success is not True
    assert result.error and "Cannot stat" in result.error


@pytest.mark.asyncio
async def test_unpack_firmware_apk_fast_path(tmp_path: Path):
    fw = tmp_path / "app.apk"
    # minimal zip as apk
    import zipfile

    with zipfile.ZipFile(fw, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00manifest")
        zf.writestr("classes.dex", b"dex\n")
    out = tmp_path / "out"
    out.mkdir()

    with patch("app.workers.unpack.classify_firmware", return_value="android_apk"):
        result = await unpack_firmware(str(fw), str(out))

    assert result.success is True
    assert (out / "extracted" / "app.apk").is_file() or any(
        p.suffix == ".apk" for p in (out / "extracted").rglob("*") if p.is_file()
    )


@pytest.mark.asyncio
async def test_unpack_firmware_elf_binary_fast_path(tmp_path: Path):
    fw = tmp_path / "busybox"
    fw.write_bytes(b"\x7fELF" + b"\x00" * 64)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="elf_binary"),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={
                "format": "elf",
                "architecture": "x86_64",
                "endianness": "little",
                "is_static": True,
                "dependencies": [],
            },
        ),
    ):
        result = await unpack_firmware(str(fw), str(out))

    assert result.success is True
    assert result.architecture == "x86_64"
    assert result.binary_info is not None


@pytest.mark.asyncio
async def test_unpack_firmware_pe_binary_fast_path(tmp_path: Path):
    fw = tmp_path / "tool.exe"
    fw.write_bytes(b"MZ" + b"\x00" * 64)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="pe_binary"),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={
                "format": "pe",
                "architecture": "x86",
                "endianness": "little",
                "is_static": False,
                "dependencies": ["kernel32.dll"],
            },
        ),
    ):
        result = await unpack_firmware(str(fw), str(out))

    assert result.success is True
    assert "PE" in (result.unpack_log or "") or result.architecture == "x86"


@pytest.mark.asyncio
async def test_unpack_firmware_rtos_blob_path(tmp_path: Path):
    fw = tmp_path / "rtos.bin"
    fw.write_bytes(b"\x00" * 128)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="rtos_blob"),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"architecture": "arm", "endianness": "little"},
        ),
        patch(
            "app.services.rtos_detection_service.detect_rtos",
            return_value={
                "rtos_name": "freertos",
                "rtos_display_name": "FreeRTOS",
                "version": "10.4.3",
                "confidence": "high",
                "architecture": "arm",
                "endianness": "little",
            },
        ),
        patch(
            "app.services.rtos_detection_service.extract_companion_components",
            return_value=[{"name": "lwIP", "version": "2.1.2"}],
        ),
    ):
        result = await unpack_firmware(str(fw), str(out))

    assert result.success is True
    assert result.architecture == "arm"
    assert "FreeRTOS" in (result.unpack_log or "")


@pytest.mark.asyncio
async def test_unpack_firmware_progress_callback_errors_swallowed(tmp_path: Path):
    fw = tmp_path / "x.bin"
    fw.write_bytes(b"\x7fELF" + b"\x00" * 32)
    out = tmp_path / "out"
    out.mkdir()

    async def bad_cb(stage, progress):
        raise RuntimeError("progress boom")

    with (
        patch("app.workers.unpack.classify_firmware", return_value="elf_binary"),
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"architecture": "x86_64", "endianness": "little", "is_static": True, "dependencies": []},
        ),
    ):
        result = await unpack_firmware(str(fw), str(out), progress_callback=bad_cb)
    assert result.success is True


@pytest.mark.asyncio
async def test_unpack_firmware_insufficient_disk(tmp_path: Path):
    fw = tmp_path / "big.bin"
    fw.write_bytes(b"\x00" * 100)
    out = tmp_path / "out"
    out.mkdir()

    # Force disk_usage free << 2x firmware size
    fake_usage = MagicMock()
    fake_usage.free = 10  # bytes

    with patch("shutil.disk_usage", return_value=fake_usage):
        # classify may not be reached if we return early
        result = await unpack_firmware(str(fw), str(out))
    assert result.success is not True
    assert result.error and "disk space" in result.error.lower()


@pytest.mark.asyncio
async def test_unpack_android_boot_path(tmp_path: Path):
    fw = tmp_path / "boot.img"
    fw.write_bytes(b"ANDROID!" + b"\x00" * 2000)
    out = tmp_path / "out"
    out.mkdir()

    async def fake_boot(path, boot_dir, logs):
        Path(boot_dir).mkdir(parents=True, exist_ok=True)
        (Path(boot_dir) / "kernel").write_bytes(b"K")
        logs.append("fake boot extract")
        return True

    with (
        patch("app.workers.unpack.classify_firmware", return_value="android_boot"),
        patch("app.workers.unpack._extract_boot_img", side_effect=fake_boot),
    ):
        result = await unpack_firmware(str(fw), str(out))
    assert result.success is True
    assert result.extracted_path is not None


@pytest.mark.asyncio
async def test_unpack_android_ota_success_path(tmp_path: Path):
    fw = tmp_path / "ota.zip"
    fw.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="android_ota"),
        patch(
            "app.workers.unpack._extract_android_ota",
            new=AsyncMock(return_value="android ota log\n"),
        ),
        patch("app.workers.unpack.check_extraction_limits", return_value=None),
        patch("app.workers.unpack._analyze_filesystem") as analyze,
    ):
        def _set_success(result, *a, **k):
            result.success = True
            result.extracted_path = str(out / "extracted" / "rootfs")

        analyze.side_effect = _set_success
        result = await unpack_firmware(str(fw), str(out))
    assert result.success is True


@pytest.mark.asyncio
async def test_unpack_linux_rootfs_tar_path(tmp_path: Path):
    import tarfile

    rootfs = tmp_path / "root"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    (rootfs / "etc" / "hostname").write_text("r\n")
    (rootfs / "bin" / "sh").write_bytes(b"\x7fELF")
    tar_path = tmp_path / "rootfs.tar"
    with tarfile.open(tar_path, "w") as tf:
        tf.add(rootfs / "etc", arcname="etc")
        tf.add(rootfs / "bin", arcname="bin")
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="linux_rootfs_tar"),
        patch("app.workers.unpack.check_tar_bomb", return_value=None),
        patch(
            "app.workers.unpack_common._recursive_extract_nested",
            return_value=[],
        ),
        patch("app.workers.unpack.check_extraction_limits", return_value=None),
        patch("app.workers.unpack._analyze_filesystem") as analyze,
    ):
        def _ok(result, *a, **k):
            result.success = True
            result.extracted_path = str(out / "extracted")

        analyze.side_effect = _ok
        result = await unpack_firmware(str(tar_path), str(out))
    assert result.success is True


@pytest.mark.asyncio
async def test_unpack_fallback_unblob_success(tmp_path: Path):
    fw = tmp_path / "blob.bin"
    fw.write_bytes(b"\x00" * 64)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="linux_blob"),
        patch(
            "app.workers.unpack.run_unblob_extraction",
            new=AsyncMock(return_value="unblob ok\n"),
        ),
        patch("app.workers.unpack.cleanup_unblob_artifacts", return_value=0),
        patch("app.workers.unpack.remove_extraction_escape_symlinks", return_value=0),
        patch(
            "app.workers.unpack_common._recursive_extract_nested",
            return_value=[],
        ),
        patch("app.workers.unpack.check_extraction_limits", return_value=None),
        patch("app.workers.unpack._analyze_filesystem") as analyze,
    ):
        def _ok(result, *a, **k):
            result.success = True
            result.extracted_path = str(out / "extracted")

        analyze.side_effect = _ok
        result = await unpack_firmware(str(fw), str(out))
    assert result.success is True
    assert "unblob" in (result.unpack_log or "").lower()


@pytest.mark.asyncio
async def test_unpack_uefi_path(tmp_path: Path):
    fw = tmp_path / "bios.bin"
    fw.write_bytes(b"\x00" * 100)
    out = tmp_path / "out"
    out.mkdir()

    with (
        patch("app.workers.unpack.classify_firmware", return_value="uefi_firmware"),
        patch(
            "app.workers.unpack.run_uefi_extraction",
            new=AsyncMock(return_value="uefi extract log\n"),
        ),
        patch("app.workers.unpack._analyze_uefi_extraction") as analyze,
        # fall through after uefi fails then hit generic with failure
        patch(
            "app.workers.unpack.run_unblob_extraction",
            new=AsyncMock(return_value="fail\n"),
        ),
        patch(
            "app.workers.unpack.run_binwalk_extraction",
            new=AsyncMock(return_value="fail\n"),
        ),
        patch("app.workers.unpack.cleanup_unblob_artifacts", return_value=0),
        patch("app.workers.unpack.remove_extraction_escape_symlinks", return_value=0),
        patch(
            "app.workers.unpack_common._recursive_extract_nested",
            return_value=[],
        ),
        patch("app.workers.unpack.check_extraction_limits", return_value=None),
        patch("app.workers.unpack._analyze_filesystem"),
    ):
        def _uefi_ok(result, ed):
            result.success = True
            result.extracted_path = str(out / "extracted" / "x.dump")

        analyze.side_effect = _uefi_ok
        result = await unpack_firmware(str(fw), str(out))
    assert result.success is True
