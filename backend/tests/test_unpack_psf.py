"""Phase α handler 5 contract tests: :func:`unpack_psf`.

PSF is a stub in Phase α — magic validation + gating-aware operator
message. Full reconstruction is gated behind Phase α.6
``ARG INCLUDE_PSF=1`` and the windows_update MCP tools (Phase β).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.workers.unpack_psf import (
    _PSF_MAGICS,
    unpack_psf,
)


@pytest.mark.asyncio
async def test_unpack_psf_rejects_invalid_magic(tmp_path: Path):
    bad = tmp_path / "not.psf"
    bad.write_bytes(b"\x00\x00\x00\x00" + b"\x00" * 100)

    result = await unpack_psf(
        firmware_path=str(bad),
        output_base_dir=str(tmp_path),
    )

    assert result.success is False
    assert result.error is not None
    assert "Not a valid PSF" in result.error


@pytest.mark.asyncio
async def test_unpack_psf_accepts_pa30_magic(tmp_path: Path):
    """PA30 — Win10/11 cumulative Express install delta."""
    psf = tmp_path / "express.psf"
    psf.write_bytes(b"PA30" + b"\x00" * 100)

    result = await unpack_psf(
        firmware_path=str(psf),
        output_base_dir=str(tmp_path),
    )

    assert result.success is True, f"got error={result.error!r}"
    assert result.extracted_path is not None
    assert "magic=PA30" in result.unpack_log
    # The gating message MUST point operators at both prerequisites.
    assert "BASELINE file" in result.unpack_log
    assert "INCLUDE_PSF=1" in result.unpack_log
    assert "identify_psf_baseline" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_psf_accepts_pa19_magic(tmp_path: Path):
    """PA19 — older Win7/8-era variant."""
    psf = tmp_path / "legacy.psf"
    psf.write_bytes(b"PA19" + b"\x00" * 100)

    result = await unpack_psf(
        firmware_path=str(psf),
        output_base_dir=str(tmp_path),
    )

    assert result.success is True, f"got error={result.error!r}"
    assert "magic=PA19" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_psf_accepts_pa17_magic(tmp_path: Path):
    """PA17 — earliest documented variant."""
    psf = tmp_path / "earliest.psf"
    psf.write_bytes(b"PA17" + b"\x00" * 100)

    result = await unpack_psf(
        firmware_path=str(psf),
        output_base_dir=str(tmp_path),
    )

    assert result.success is True, f"got error={result.error!r}"
    assert "magic=PA17" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_psf_handles_unreadable_file(tmp_path: Path):
    nonexistent = tmp_path / "missing.psf"
    # Don't create the file — open() will raise FileNotFoundError → OSError.

    result = await unpack_psf(
        firmware_path=str(nonexistent),
        output_base_dir=str(tmp_path),
    )

    assert result.success is False
    assert result.error is not None
    assert "PSF read failed" in result.error


@pytest.mark.asyncio
async def test_unpack_psf_invokes_progress_callback(tmp_path: Path):
    psf = tmp_path / "tiny.psf"
    psf.write_bytes(b"PA30" + b"\x00" * 100)

    progress = AsyncMock()
    await unpack_psf(
        firmware_path=str(psf),
        output_base_dir=str(tmp_path),
        progress_callback=progress,
    )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


def test_unpack_psf_magic_constants_are_exhaustive():
    """Documents the magic-byte set; if Microsoft adds a new PSF
    variant the constant must grow before this test passes again."""
    # As of 2026-05, three documented variants. PA30 is current; PA19/17
    # cover legacy Win7/8 / earliest paths (Persona-E #1 reference).
    assert _PSF_MAGICS == (b"PA30", b"PA19", b"PA17")
