"""Unit tests for the manual unpack-control service."""
from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from app.models.firmware import Firmware
from app.services.unpack_control_service import (
    UnpackControlError,
    UnpackControlService,
)


def _elf32_arm(little: bool = True) -> bytes:
    """Minimal parseable 52-byte ELF32 ARM header (e_machine=40)."""
    ei_data = 1 if little else 2
    e_ident = b"\x7fELF" + bytes([1, ei_data, 1, 0]) + b"\x00" * 8
    endian = "<" if little else ">"
    rest = struct.pack(
        endian + "HHIIIIIHHHHHH",
        3, 40, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    )
    return e_ident + rest


class _FakeDB:
    """Stand-in for an AsyncSession — the service only awaits flush()."""

    async def flush(self) -> None:
        return None


def _make_firmware(tmp_path: Path) -> Firmware:
    """Build a firmware tree and an in-memory Firmware pointing at it.

    Layout::

        tmp/firmware.bin                    <- storage_path
        tmp/carved/myroot/                  <- promotable dir
        tmp/carved/note.txt                 <- a file (not a dir)
        tmp/extracted/squashfs-root/bin/busybox  (ARM ELF)
    """
    blob = tmp_path / "firmware.bin"
    blob.write_bytes(b"\x27\x05\x19\x56" + b"\x00" * 1024)

    carved = tmp_path / "carved"
    (carved / "myroot" / "bin").mkdir(parents=True)
    (carved / "note.txt").write_text("hi")

    sqfs = tmp_path / "extracted" / "squashfs-root"
    (sqfs / "bin").mkdir(parents=True)
    (sqfs / "lib").mkdir()
    (sqfs / "bin" / "busybox").write_bytes(_elf32_arm())

    fw = Firmware()
    fw.storage_path = str(blob)
    fw.extracted_path = str(sqfs)
    fw.extraction_dir = str(tmp_path / "extracted")
    fw.architecture = None
    fw.endianness = None
    fw.kernel_path = None
    return fw


@pytest.fixture
def svc() -> UnpackControlService:
    return UnpackControlService(_FakeDB())


# ── set_architecture ───────────────────────────────────────────────────────


class TestSetArchitecture:
    async def test_basic(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        await svc.set_architecture(fw, "arm", "little")
        assert (fw.architecture, fw.endianness) == ("arm", "little")

    async def test_alias_normalised(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        await svc.set_architecture(fw, "arm64")
        assert fw.architecture == "aarch64"

    async def test_mipsel_infers_little(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        await svc.set_architecture(fw, "mipsel")
        assert (fw.architecture, fw.endianness) == ("mipsel", "little")

    async def test_invalid_arch_rejected(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.set_architecture(fw, "potato")

    async def test_invalid_endian_rejected(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.set_architecture(fw, "arm", "sideways")


# ── set_rootfs ─────────────────────────────────────────────────────────────


class TestSetRootfs:
    async def test_promote_carved_dir(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        await svc.set_rootfs(fw, "/_carved/myroot")
        assert fw.extracted_path == os.path.realpath(tmp_path / "carved" / "myroot")
        # Promoting drops the binwalk virtual top-level.
        assert fw.extraction_dir is None

    async def test_rejects_file(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.set_rootfs(fw, "/_carved/note.txt")

    async def test_rejects_traversal(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.set_rootfs(fw, "/rootfs/../../../../etc")

    async def test_existing_extracted_dir(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        await svc.set_rootfs(fw, "/rootfs")
        assert fw.extracted_path == os.path.realpath(
            tmp_path / "extracted" / "squashfs-root"
        )


# ── set_kernel ─────────────────────────────────────────────────────────────


class TestSetKernel:
    async def test_set_file(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        # The firmware blob is reachable at /firmware/<basename>.
        await svc.set_kernel(fw, "/firmware/firmware.bin")
        assert fw.kernel_path == os.path.realpath(tmp_path / "firmware.bin")

    async def test_rejects_dir(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.set_kernel(fw, "/rootfs")


# ── redetect ───────────────────────────────────────────────────────────────


class TestRedetect:
    async def test_full_redetect(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        fw.architecture = None
        _fw, report = await svc.redetect(fw)
        assert fw.architecture == "arm"
        assert os.path.basename(fw.extracted_path) == "squashfs-root"
        assert report["arch"] == "arm/little"
        assert report["rootfs"] is not None
        assert report["kernel"] is None  # no kernel image in the tree

    async def test_targets_filter(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        fw.extracted_path = "/sentinel/unchanged"
        await svc.redetect(fw, targets=["arch"])
        assert fw.architecture == "arm"
        # rootfs was not a target, so it must be untouched.
        assert fw.extracted_path == "/sentinel/unchanged"

    async def test_bad_target_rejected(self, svc, tmp_path):
        fw = _make_firmware(tmp_path)
        with pytest.raises(UnpackControlError):
            await svc.redetect(fw, targets=["bogus"])
