"""Phase α handler 2 contract tests: :func:`unpack_msi`.

Mirrors the test_unpack_cab.py / test_unpack_wim.py shape. The MSI
toolchain is two-phase: ``msiinfo suminfo`` for the validity probe,
then ``msiextract`` for the file payload extraction.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import struct
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_msi import (
    _MSIEXTRACT_TIMEOUT_SECONDS,
    unpack_msi,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proc_stub(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> object:
    class _Proc:
        def __init__(self) -> None:
            self.returncode = returncode

        async def communicate(self) -> tuple[bytes, bytes]:
            return stdout, stderr

        def kill(self) -> None:
            pass

    return _Proc()


def _make_two_phase_subprocess(suminfo_proc: object, extract_factory):
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return suminfo_proc
        return extract_factory(*args, **kwargs)

    return _side_effect


# OLE2 compound document magic header — used to make tmp_path / "*.msi"
# files at least look superficially valid for the in-process worker
# logic (the actual MSI parser is mocked).
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


# ---------------------------------------------------------------------------
# 1. msiinfo binary missing → clear failure with install hint.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_reports_missing_msiinfo(tmp_path: Path):
    msi = tmp_path / "fake.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "msiinfo binary missing" in result.error
    assert "msitools" in result.unpack_log
    assert "rebuild" in result.unpack_log.lower()


# ---------------------------------------------------------------------------
# 2. suminfo fails (corrupt MSI) → "MSI archive unreadable".
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_reports_unreadable_archive(tmp_path: Path):
    msi = tmp_path / "broken.msi"
    msi.write_bytes(b"\x00" * 64)

    suminfo_stub = _make_proc_stub(
        returncode=1,
        stderr=b"libmsi-CRITICAL: failed to open compound document\n",
    )

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(return_value=suminfo_stub),
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "MSI archive unreadable" in result.error
    assert "msiinfo suminfo exit=1" in result.unpack_log
    assert "compound document" in result.unpack_log


# ---------------------------------------------------------------------------
# 3. suminfo OK + msiextract timeout → result.error names the timeout ceiling.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_reports_extract_timeout(tmp_path: Path):
    msi = tmp_path / "huge.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)

    suminfo_stub = _make_proc_stub(
        returncode=0,
        stdout=b"Title: VendorDeviceManager\nSubject: Setup\n",
    )
    extract_stub = _make_proc_stub(returncode=0)

    state = {"calls": 0}
    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        state["calls"] += 1
        if state["calls"] == 1:
            return await real_wait_for(coro, timeout=timeout)
        coro.close()
        raise asyncio.TimeoutError

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, lambda *_a, **_kw: extract_stub,
        )),
    ), patch(
        "app.workers.unpack_msi.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_MSIEXTRACT_TIMEOUT_SECONDS}s" in result.error


# ---------------------------------------------------------------------------
# 4. suminfo OK + msiextract non-zero exit → failure with truncated stderr.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_reports_extract_nonzero_exit(tmp_path: Path):
    msi = tmp_path / "bad-payload.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)

    suminfo_stub = _make_proc_stub(
        returncode=0,
        stdout=b"Title: Vendor\n",
    )
    extract_stub = _make_proc_stub(
        returncode=1,
        stderr=b"libmsi: failed to read media table\n",
    )

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, lambda *_a, **_kw: extract_stub,
        )),
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "exit=1" in result.error
    assert "media table" in result.error
    assert "msiextract exit=1" in result.unpack_log


# ---------------------------------------------------------------------------
# 5. suminfo OK + msiextract OK + Windows-style payload → success.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_succeeds_with_program_files_payload(tmp_path: Path):
    msi = tmp_path / "VendorDeviceManager.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    suminfo_stub = _make_proc_stub(
        returncode=0,
        stdout=b"Title: VendorDeviceManager\nSubject: Vendor IoT Device Manager\n",
    )

    def _populate(*_a, **_kw):
        # Typical MSI extraction layout: ProgramFiles64Folder/<vendor>/...
        prog_files = extraction_dir / "Program Files" / "Vendor" / "DeviceManager"
        prog_files.mkdir(parents=True)
        (prog_files / "DeviceManager.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        (prog_files / "DeviceManager.exe.config").write_text(
            "<?xml version=\"1.0\" ?><configuration></configuration>\n",
        )
        (prog_files / "Vendor.Driver.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 200)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, _populate,
        )),
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    assert "MSI extraction complete via msiextract" in result.unpack_log
    # Summary info must land in the log.
    assert "VendorDeviceManager" in result.unpack_log
    # The extracted payload must actually exist on disk.
    prog_files = extraction_dir / "Program Files" / "Vendor" / "DeviceManager"
    assert (prog_files / "DeviceManager.exe").exists()
    assert (prog_files / "Vendor.Driver.dll").exists()


# ---------------------------------------------------------------------------
# 6. Empty MSI (no File table rows — pure-action / pure-registry installer)
#    → still succeeds. The summary log explains how to inspect tables.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_succeeds_with_empty_payload(tmp_path: Path):
    msi = tmp_path / "registry-only.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    suminfo_stub = _make_proc_stub(
        returncode=0,
        stdout=b"Title: RegistryOnlyInstaller\n",
    )

    def _populate(*_a, **_kw):
        # No files extracted — empty extraction_dir.
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, _populate,
        )),
    ):
        result = await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    # Operator guidance must point at MCP tools for table introspection.
    assert "windows_archive MCP tools" in result.unpack_log
    assert "custom actions" in result.unpack_log


# ---------------------------------------------------------------------------
# 7. Progress-callback contract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_invokes_progress_callback(tmp_path: Path):
    msi = tmp_path / "small.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    suminfo_stub = _make_proc_stub(returncode=0, stdout=b"Title: Tiny\n")

    def _populate(*_a, **_kw):
        (extraction_dir / "tiny.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 50)
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, _populate,
        )),
    ):
        await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 8. Custom-action discipline assertion — the worker calls msiextract
#    (file-extractor only), NEVER msiexec or any "execute custom action"
#    path. This is a documentation-level contract check using the
#    captured args (no real MSI engine is invoked under any code path).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_msi_never_executes_custom_actions(tmp_path: Path):
    """Persona-E anti-pattern #3 / Phase β CLAUDE.md Rule #36 candidate:
    MSI custom actions are dump-only, NEVER executed. This test verifies
    the worker only invokes msiinfo + msiextract — no msiexec, no Windows
    Installer engine, no "evaluate condition expression" path.
    """
    msi = tmp_path / "with-ca.msi"
    msi.write_bytes(_OLE2_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    suminfo_stub = _make_proc_stub(returncode=0, stdout=b"Title: HasCustomActions\n")

    captured_cmds: list[tuple] = []

    def _capture_then_stub(*args, **_kw):
        captured_cmds.append(args)
        (extraction_dir / "payload.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 50)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_msi.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            suminfo_stub, _capture_then_stub,
        )),
    ):
        await unpack_msi(
            firmware_path=str(msi),
            output_base_dir=str(tmp_path),
        )

    # Exactly one extract subprocess (msiextract). Plus the suminfo probe
    # (captured externally; not in captured_cmds).
    assert len(captured_cmds) == 1
    extract_args = captured_cmds[0]
    # The binary invoked MUST be msiextract — never msiexec or anything
    # that could trigger custom-action execution.
    assert extract_args[0] == "msiextract"
    # Defence-in-depth: scan all extract command tokens for forbidden names.
    forbidden = {"msiexec", "wine", "winetricks"}
    for tok in extract_args:
        assert not any(f in str(tok) for f in forbidden), (
            f"forbidden token {tok} in msiextract command — "
            "Persona-E anti-pattern #3 / future Rule #36 violation"
        )


# ---------------------------------------------------------------------------
# 9. Rule #35b live canary — build a real MSI with msibuild (msitools)
#    or a vendor-shipped tiny.msi fixture, and extract via the actual
#    msiextract CLI. Auto-skips when msiextract is not on PATH.
# ---------------------------------------------------------------------------


_TINY_MSI_FIXTURE = (
    Path(__file__).parent / "fixtures" / "windows" / "tiny.msi"
)


@pytest.mark.asyncio
async def test_unpack_msi_live_canary_real_msi(tmp_path: Path):
    if not shutil.which("msiextract") or not shutil.which("msiinfo"):
        pytest.skip("msitools not on PATH — Phase α.6 Dockerfile pending")
    if not _TINY_MSI_FIXTURE.exists():
        pytest.skip(f"fixture {_TINY_MSI_FIXTURE} not committed yet")

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_msi(
        firmware_path=str(_TINY_MSI_FIXTURE),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    extract_root = result.extraction_dir or result.extracted_path
    # The fixture is a synthesised tiny MSI containing at least 1 file.
    found = any(
        os.path.isfile(os.path.join(root, name))
        for root, _dirs, files in os.walk(extract_root)
        for name in files
    )
    assert found, (
        f"expected at least one extracted file under {extract_root}, "
        f"unpack_log was: {result.unpack_log[:500]}"
    )
    assert "msiinfo suminfo exit=0" in result.unpack_log
    assert "msiextract exit=0" in result.unpack_log
