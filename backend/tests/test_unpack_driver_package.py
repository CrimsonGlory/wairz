"""Phase α handler 6 contract tests: :func:`unpack_driver_package`.

Driver packages are CABs containing INF + SYS + CAT (+ optional DLL/EXE).
The worker classifies the subtype based on file presence.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_driver_package import unpack_driver_package


def _make_proc_stub(returncode, stdout=b"", stderr=b""):
    class _Proc:
        def __init__(self):
            self.returncode = returncode

        async def communicate(self):
            return stdout, stderr

        def kill(self):
            pass

    return _Proc()


@pytest.mark.asyncio
async def test_unpack_driver_package_reports_missing_cabextract(tmp_path: Path):
    pkg = tmp_path / "driver.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)

    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "cabextract binary missing" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_driver_package_reports_extract_failure(tmp_path: Path):
    pkg = tmp_path / "broken.cab"
    pkg.write_bytes(b"\x00" * 64)

    extract_stub = _make_proc_stub(
        returncode=1, stderr=b"corrupted CAB header\n",
    )
    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(return_value=extract_stub),
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "exit=1" in (result.error or "")
    assert "corrupted" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_driver_package_classifies_canonical_subtype(tmp_path: Path):
    """The 4-file driver-package canonical layout: INF + SYS + CAT (+ DLL).
    Must classify subtype=cab_inf_sys_cat and surface kernel-API guidance."""
    pkg = tmp_path / "vendor_storage.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    extract_stub = _make_proc_stub(returncode=0)

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "vendor_storage.inf").write_text(
            "[Version]\nSignature=\"$Windows NT$\"\nClass=Storage\n"
            "ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}\n",
        )
        (extraction_dir / "vendor_storage.sys").write_bytes(
            b"\x4d\x5a" + b"\x00" * 200,
        )
        (extraction_dir / "vendor_storage.cat").write_bytes(
            b"\x30\x82" + b"\x00" * 100,
        )
        (extraction_dir / "vendor_coinst.dll").write_bytes(
            b"\x4d\x5a" + b"\x00" * 100,
        )
        return extract_stub

    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"got error={result.error!r}"
    assert "subtype: cab_inf_sys_cat" in result.unpack_log
    # Component counts must be surfaced.
    assert "*.inf files (1):" in result.unpack_log
    assert "*.sys files (1):" in result.unpack_log
    assert "*.cat files (1):" in result.unpack_log
    assert "*.dll files (1):" in result.unpack_log
    # Phase γ guidance must point at windows_driver MCP tools.
    assert "windows_driver MCP tools" in result.unpack_log
    assert "Authenticode roots" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_driver_package_classifies_dch_subtype(tmp_path: Path):
    """DCH driver — INFs include an extension INF (ext_*.inf or *extension*.inf)."""
    pkg = tmp_path / "dch_audio.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    extract_stub = _make_proc_stub(returncode=0)

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "vendor_audio.inf").write_text("[Version]\n")
        (extraction_dir / "ext_vendor_audio.inf").write_text("[Version]\n")
        (extraction_dir / "vendor_audio.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 200)
        (extraction_dir / "vendor_audio.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)
        return extract_stub

    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"got error={result.error!r}"
    assert "subtype: dch" in result.unpack_log
    assert "Declarative-Componentized-Hardware" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_driver_package_classifies_inf_only(tmp_path: Path):
    """INF-only package — vendor metadata without binary."""
    pkg = tmp_path / "metadata.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    extract_stub = _make_proc_stub(returncode=0)

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "vendor_meta.inf").write_text("[Version]\n")
        return extract_stub

    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "subtype: cab_inf_only" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_driver_package_classifies_unknown(tmp_path: Path):
    """No INF / SYS / DriverStore markers → subtype=unknown."""
    pkg = tmp_path / "weird.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    extract_stub = _make_proc_stub(returncode=0)

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "readme.txt").write_text("Just a readme\n")
        return extract_stub

    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        result = await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "subtype: unknown" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_driver_package_invokes_progress_callback(tmp_path: Path):
    pkg = tmp_path / "small.cab"
    pkg.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    extract_stub = _make_proc_stub(returncode=0)

    def _populate(*_a, **_kw):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "x.inf").write_text("[Version]\n")
        return extract_stub

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_driver_package.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        await unpack_driver_package(
            firmware_path=str(pkg),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100
