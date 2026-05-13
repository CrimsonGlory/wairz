"""Tests for the Phase λ.μ Acronis .tibx unpack worker.

Focused subset of the unit-test surface — covers the pure-logic helpers
(_is_master_slice, _parse_first_recovery_point) + the magic-byte
rejection branch of unpack_tibx that doesn't require Docker SDK mocks.

Heavy mock-Docker-SDK tests for the spawn / wait / log-capture / copy
branches are a follow-up — they need ~150 LOC of AsyncMock plumbing
mirroring test_unpack_vhdx.py's two-phase subprocess shape. Deferred
to keep this initial commit small.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.workers.unpack_tibx import (
    _is_master_slice,
    _parse_first_recovery_point,
    unpack_tibx,
)

# ---------------------------------------------------------------------------
# _is_master_slice — pure-logic shape verification
# ---------------------------------------------------------------------------

def test_is_master_slice_accepts_arch_magic_plain_filename():
    """Master slice: ARCH at offset 8 + non-continuation basename."""
    head = b"\x41\x01\x00\x00\x02\x4c\x52\xea" + b"ARCH" + b"\x00\x00\x00\x00"
    assert _is_master_slice(head, "Archive(1).tibx") is True
    assert _is_master_slice(head, "backup.tibx") is True


def test_is_master_slice_rejects_continuation_naming_even_with_magic():
    """Continuation -NNNN.tibx is rejected even if ARCH magic is present.

    The strict check catches the case where an operator renamed a
    continuation but didn't actually have a master file — the magic
    might have been copied via cargo-cult but the slice index in the
    filename says otherwise.
    """
    head = b"\x41\x01\x00\x00\x02\x4c\x52\xea" + b"ARCH" + b"\x00\x00\x00\x00"
    assert _is_master_slice(head, "Archive(1)-0001.tibx") is False
    assert _is_master_slice(head, "Archive(1)-0042.tibx") is False
    assert _is_master_slice(head, "Archive(1)-9999.tibx") is False


def test_is_master_slice_rejects_no_magic():
    """No ARCH magic → not a master regardless of filename."""
    head = b"\xff" * 16
    assert _is_master_slice(head, "Archive(1).tibx") is False
    assert _is_master_slice(head, "backup.tibx") is False


def test_is_master_slice_rejects_short_head():
    """Head buffer shorter than offset+magic length → False."""
    assert _is_master_slice(b"ARCH", "backup.tibx") is False
    assert _is_master_slice(b"", "backup.tibx") is False


def test_is_master_slice_rejects_continuation_pattern_without_master_count_digit():
    """``-001a.tibx`` is NOT a continuation (non-digit) → would be master."""
    head = b"\x41\x01\x00\x00\x02\x4c\x52\xea" + b"ARCH" + b"\x00\x00\x00\x00"
    # The 4 chars before ".tibx" are "001a" — NOT all digits → not a continuation.
    assert _is_master_slice(head, "Archive(1)-001a.tibx") is True


# ---------------------------------------------------------------------------
# _parse_first_recovery_point — JSON / list / empty handling
# ---------------------------------------------------------------------------

def test_parse_recovery_point_from_object_with_backups_array():
    """tibxread 'list backups' JSON: top-level dict with backups[] entries."""
    raw = '{"backups": [{"id": "rp-1", "date": "..."}, {"id": "rp-2"}]}'
    assert _parse_first_recovery_point(raw) == "rp-1"


def test_parse_recovery_point_from_object_with_recovery_points_alias():
    """Some Acronis releases use 'recovery_points' instead of 'backups'."""
    raw = '{"recovery_points": [{"id": "rp-7"}]}'
    assert _parse_first_recovery_point(raw) == "rp-7"


def test_parse_recovery_point_from_top_level_array():
    """Some releases emit a top-level JSON array directly."""
    raw = '[{"id": "rp-3"}, {"id": "rp-4"}]'
    assert _parse_first_recovery_point(raw) == "rp-3"


def test_parse_recovery_point_from_array_of_strings():
    """Defensive: array of bare strings — first non-empty wins."""
    raw = '["", "rp-bare-1", "rp-bare-2"]'
    assert _parse_first_recovery_point(raw) == "rp-bare-1"


def test_parse_recovery_point_returns_none_on_empty():
    assert _parse_first_recovery_point("") is None
    assert _parse_first_recovery_point("   ") is None


def test_parse_recovery_point_returns_none_on_malformed_json():
    assert _parse_first_recovery_point("not-json") is None
    assert _parse_first_recovery_point("{unterminated") is None


def test_parse_recovery_point_returns_none_on_empty_array():
    assert _parse_first_recovery_point("[]") is None
    assert _parse_first_recovery_point('{"backups": []}') is None


# ---------------------------------------------------------------------------
# unpack_tibx — magic-byte rejection branch (no Docker SDK needed)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_tibx_rejects_continuation_slice(tmp_path: Path):
    """Continuation slice (-NNNN.tibx) rejects with operator guidance.

    No Docker SDK call — the master-slice gate fires before any
    side-container interaction.
    """
    cont = tmp_path / "Archive(1)-0001.tibx"
    # Bytes mimic the observed continuation shape: 41 ff 00 00 prefix + no ARCH.
    cont.write_bytes(b"\x41\xff\x00\x00" + b"\x00" * 64)
    result = await unpack_tibx(
        firmware_path=str(cont),
        output_base_dir=str(tmp_path),
    )
    assert result.success is False
    assert result.error is not None
    assert "continuation" in result.error.lower() or "master" in result.error.lower()
    assert "Archive(1)-0001.tibx" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_tibx_rejects_no_magic(tmp_path: Path):
    """File without ARCH magic at offset 8 rejects cleanly."""
    bad = tmp_path / "backup.tibx"
    bad.write_bytes(b"\xff" * 64)  # no ARCH anywhere
    result = await unpack_tibx(
        firmware_path=str(bad),
        output_base_dir=str(tmp_path),
    )
    assert result.success is False
    assert result.error is not None
    assert "master" in result.error.lower()


@pytest.mark.asyncio
async def test_unpack_tibx_rejects_short_file(tmp_path: Path):
    """File shorter than the magic-probe window rejects cleanly."""
    small = tmp_path / "tiny.tibx"
    small.write_bytes(b"AB")  # 2 bytes, less than _TIBX_HEAD_PROBE_BYTES
    result = await unpack_tibx(
        firmware_path=str(small),
        output_base_dir=str(tmp_path),
    )
    assert result.success is False
    assert result.error is not None
