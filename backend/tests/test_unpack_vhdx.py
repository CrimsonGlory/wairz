"""Phase α handler 7 contract tests: :func:`unpack_vhdx`."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_vhdx import (
    _QEMU_IMG_CONVERT_TIMEOUT_SECONDS,
    _VHDX_MAGIC,
    unpack_vhdx,
)


def _make_proc_stub(returncode, stdout=b"", stderr=b""):
    class _Proc:
        def __init__(self):
            self.returncode = returncode

        async def communicate(self):
            return stdout, stderr

        def kill(self):
            pass

    return _Proc()


def _make_two_phase_subprocess(info_proc, convert_factory):
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return info_proc
        return convert_factory(*args, **kwargs)

    return _side_effect


@pytest.mark.asyncio
async def test_unpack_vhdx_rejects_invalid_magic(tmp_path: Path):
    bad = tmp_path / "not.vhdx"
    bad.write_bytes(b"\x00" * 64)

    result = await unpack_vhdx(
        firmware_path=str(bad),
        output_base_dir=str(tmp_path),
    )

    assert result.success is False
    assert result.error is not None
    assert "Not a VHDX" in result.error


@pytest.mark.asyncio
async def test_unpack_vhdx_reports_missing_qemu_img(tmp_path: Path):
    vhdx = tmp_path / "fake.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)

    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "qemu-img binary missing" in (result.error or "")
    assert "qemu-utils" in result.unpack_log
    assert "Phase α.6" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_vhdx_reports_info_failure(tmp_path: Path):
    vhdx = tmp_path / "broken.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)

    info_stub = _make_proc_stub(
        returncode=1,
        stderr=b"qemu-img: Could not parse VHDX header\n",
    )
    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        AsyncMock(return_value=info_stub),
    ):
        result = await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "VHDX unreadable" in (result.error or "")
    assert "Could not parse VHDX header" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_vhdx_reports_convert_failure(tmp_path: Path):
    vhdx = tmp_path / "bad.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b'{"virtual-size": 1073741824, "format": "vhdx"}\n',
    )
    convert_stub = _make_proc_stub(
        returncode=1, stderr=b"qemu-img: error reading sector 1234\n",
    )

    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, lambda *_a, **_kw: convert_stub,
        )),
    ):
        result = await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "qemu-img convert failed" in (result.error or "")
    assert "exit=1" in (result.error or "")
    assert "error reading sector" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_vhdx_reports_convert_timeout(tmp_path: Path):
    vhdx = tmp_path / "huge.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)

    info_stub = _make_proc_stub(returncode=0, stdout=b'{}')
    convert_stub = _make_proc_stub(returncode=0)

    state = {"calls": 0}
    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        state["calls"] += 1
        if state["calls"] == 1:
            return await real_wait_for(coro, timeout=timeout)
        coro.close()
        raise TimeoutError

    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, lambda *_a, **_kw: convert_stub,
        )),
    ), patch(
        "app.workers.unpack_vhdx.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert (
        f"timed out after {_QEMU_IMG_CONVERT_TIMEOUT_SECONDS}s" in (result.error or "")
    )


@pytest.mark.asyncio
async def test_unpack_vhdx_succeeds_and_emits_raw_disk(tmp_path: Path):
    vhdx = tmp_path / "vendor.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b'{"virtual-size": 1073741824, "format": "vhdx", "cluster-size": 1048576}\n',
    )

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        # The conversion produces extraction_dir/disk.raw; mock writes a
        # tiny stub so the post-conversion size check has something to read.
        (extraction_dir / "disk.raw").write_bytes(b"\x00" * 4096)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate,
        )),
    ):
        result = await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"got error={result.error!r}"
    assert "VHDX extraction complete via qemu-img convert" in result.unpack_log
    assert (extraction_dir / "disk.raw").exists()
    # Operator guidance must point at windows_storage MCP tools (Phase α.4).
    assert "windows_storage MCP tools" in result.unpack_log
    assert "mount_vhdx_readonly" in result.unpack_log
    # Persona-E #29 reparse-point sandbox discipline must be referenced.
    assert "reparse-point" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_vhdx_invokes_progress_callback(tmp_path: Path):
    vhdx = tmp_path / "small.vhdx"
    vhdx.write_bytes(_VHDX_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(returncode=0, stdout=b'{}')

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "disk.raw").write_bytes(b"\x00" * 1024)
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_vhdx.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate,
        )),
    ):
        await unpack_vhdx(
            firmware_path=str(vhdx),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100
