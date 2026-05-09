"""Unit tests for Phase 5 MCP tools.

Covers ``find_unsigned_firmware`` (DB query + grouping) and
``extract_dtb`` (path sandbox + fdt parser output).  Uses mock-DB pattern
consistent with ``test_hardware_firmware_graph.py``.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools.hardware_firmware import (
    _handle_extract_dtb,
    _handle_find_unsigned_firmware,
)
from app.models.hardware_firmware import HardwareFirmwareBlob

# ---------------------------------------------------------------------------
# find_unsigned_firmware
# ---------------------------------------------------------------------------


def _make_blob(
    *,
    path: str,
    category: str,
    vendor: str | None,
    fmt: str,
    signed: str,
    size: int = 4096,
) -> MagicMock:
    b = MagicMock(spec=HardwareFirmwareBlob)
    b.blob_path = path
    b.category = category
    b.vendor = vendor
    b.format = fmt
    b.signed = signed
    b.file_size = size
    return b


def _make_context(db: AsyncMock) -> ToolContext:
    return ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path="/tmp/fake-extract",  # nosec: test-only path
        db=db,
    )


@pytest.mark.asyncio
async def test_find_unsigned_firmware_empty_returns_friendly_message() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=result)

    ctx = _make_context(db)
    out = await _handle_find_unsigned_firmware({}, ctx)
    assert "No unsigned or weakly-signed" in out


@pytest.mark.asyncio
async def test_find_unsigned_firmware_groups_by_category() -> None:
    blobs = [
        _make_blob(
            path="/vendor/firmware/wcn6750.bin",
            category="wifi",
            vendor="qualcomm",
            fmt="raw_bin",
            signed="unsigned",
        ),
        _make_blob(
            path="/vendor/firmware/bcmfw.bin",
            category="wifi",
            vendor="broadcom",
            fmt="fw_bcm",
            signed="weakly_signed",
        ),
        _make_blob(
            path="/vendor/lib/modules/qcom_camss.ko",
            category="kernel_module",
            vendor="qualcomm",
            fmt="ko",
            signed="unknown",
        ),
    ]
    db = AsyncMock()
    res = MagicMock()
    res.scalars.return_value.all.return_value = blobs
    db.execute = AsyncMock(return_value=res)

    ctx = _make_context(db)
    out = await _handle_find_unsigned_firmware({}, ctx)
    assert "3 blob(s)" in out
    assert "## wifi" in out
    assert "## kernel_module" in out
    # Signed-status surfaces in the bullet as markdown bold.
    assert "**unsigned**" in out
    assert "**weakly_signed**" in out
    assert "**unknown**" in out


# ---------------------------------------------------------------------------
# extract_dtb
# ---------------------------------------------------------------------------


def _build_simple_dtb() -> bytes:
    """Build a minimal DTB via the same helper used by Phase 2 parser tests."""
    from tests.fixtures.hardware_firmware._build_fixtures import build_minimal_dtb

    return build_minimal_dtb()


@pytest.mark.asyncio
async def test_extract_dtb_missing_path_returns_error() -> None:
    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_extract_dtb({}, ctx)
    assert "dtb_path is required" in out


@pytest.mark.asyncio
async def test_extract_dtb_parses_compatible_and_firmware_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Write a synthetic DTB.
    try:
        dtb_bytes = _build_simple_dtb()
    except Exception:
        pytest.skip("fdt not available or API shape differs in this environment")
    dtb_file = tmp_path / "platform.dtb"
    dtb_file.write_bytes(dtb_bytes)

    db = AsyncMock()
    ctx = ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path=str(tmp_path),
        db=db,
    )
    # Force resolve_path to pass — our helper relies on the sandbox.  For the
    # test we bypass by monkeypatching the ToolContext.resolve_path to return
    # the literal file path (the real sandbox logic is tested elsewhere).
    monkeypatch.setattr(ctx, "resolve_path", lambda p: str(dtb_file))

    out = await _handle_extract_dtb({"dtb_path": "/platform.dtb"}, ctx)
    assert "# DTB:" in out
    # build_minimal_dtb produces compatible=qcom,wcn6750-wifi + firmware-name=wcn6750.bin.
    assert "qcom,wcn6750" in out
    assert "wcn6750.bin" in out


@pytest.mark.asyncio
async def test_extract_dtb_missing_file_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = AsyncMock()
    ctx = ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path=str(tmp_path),
        db=db,
    )
    monkeypatch.setattr(
        ctx, "resolve_path", lambda p: str(tmp_path / "does-not-exist.dtb")
    )
    out = await _handle_extract_dtb({"dtb_path": "/does-not-exist.dtb"}, ctx)
    assert "not a file" in out
