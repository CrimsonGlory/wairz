"""MCP handler tests for ``app.ai.tools.android_sast`` (was ~21% / 41 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.android_sast import _handle_scan_apk_sast, register_android_sast_tools


@dataclass
class _StubContext:
    db: object
    firmware_id: uuid.UUID
    project_id: uuid.UUID
    extracted_path: str | None = "/tmp/extract"


def test_register_android_sast():
    reg = ToolRegistry()
    register_android_sast_tools(reg)
    assert "scan_apk_sast" in reg._tools


@pytest.mark.asyncio
async def test_scan_apk_sast_not_installed():
    ctx = _StubContext(db=MagicMock(), firmware_id=uuid.uuid4(), project_id=uuid.uuid4())
    with patch("app.services.mobsfscan.mobsfscan_available", return_value=False):
        out = await _handle_scan_apk_sast({}, ctx)
    assert "not installed" in out.lower()


@pytest.mark.asyncio
async def test_scan_apk_sast_find_apk_error():
    ctx = _StubContext(db=MagicMock(), firmware_id=uuid.uuid4(), project_id=uuid.uuid4())
    with (
        patch("app.services.mobsfscan.mobsfscan_available", return_value=True),
        patch("app.ai.tools.android_sast.find_apk", side_effect=ValueError("no apk")),
    ):
        out = await _handle_scan_apk_sast({"path": "/app.apk"}, ctx)
    assert "no apk" in out


@pytest.mark.asyncio
async def test_scan_apk_sast_success_and_errors():
    ctx = _StubContext(db=MagicMock(), firmware_id=uuid.uuid4(), project_id=uuid.uuid4())
    pipeline = MagicMock()
    result = SimpleNamespace(
        text_output="SAST findings: 2 issues",
        cached=False,
    )
    pipeline.scan_apk = AsyncMock(return_value=result)
    fw_ctx = SimpleNamespace(is_empty=False, summary_line=lambda: "vendor=test")

    with (
        patch("app.services.mobsfscan.mobsfscan_available", return_value=True),
        patch("app.services.mobsfscan.get_mobsfscan_pipeline", return_value=pipeline),
        patch("app.ai.tools.android_sast.find_apk", return_value="/tmp/extract/app.apk"),
        patch("app.ai.tools.android_sast._get_apk_rel_path", return_value="/app.apk"),
        patch("app.utils.firmware_context.get_firmware_context", new=AsyncMock(return_value=fw_ctx)),
    ):
        out = await _handle_scan_apk_sast({}, ctx)
    assert "SAST findings" in out
    assert "vendor=test" in out or "Firmware" in out

    result.cached = True
    pipeline.scan_apk = AsyncMock(return_value=result)
    with (
        patch("app.services.mobsfscan.mobsfscan_available", return_value=True),
        patch("app.services.mobsfscan.get_mobsfscan_pipeline", return_value=pipeline),
        patch("app.ai.tools.android_sast.find_apk", return_value="/tmp/extract/app.apk"),
        patch("app.ai.tools.android_sast._get_apk_rel_path", return_value="/app.apk"),
        patch("app.utils.firmware_context.get_firmware_context", new=AsyncMock(side_effect=RuntimeError("ctx"))),
    ):
        out = await _handle_scan_apk_sast({}, ctx)
    assert "CACHED" in out or "SAST" in out

    for exc, needle in (
        (FileNotFoundError("gone"), "not found"),
        (TimeoutError("slow"), "timed out"),
        (RuntimeError("boom"), "Pipeline error"),
        (Exception("weird"), "Unexpected"),
    ):
        pipeline.scan_apk = AsyncMock(side_effect=exc)
        with (
            patch("app.services.mobsfscan.mobsfscan_available", return_value=True),
            patch("app.services.mobsfscan.get_mobsfscan_pipeline", return_value=pipeline),
            patch("app.ai.tools.android_sast.find_apk", return_value="/tmp/extract/app.apk"),
            patch("app.ai.tools.android_sast._get_apk_rel_path", return_value="/app.apk"),
            patch("app.utils.firmware_context.get_firmware_context", new=AsyncMock(return_value=None)),
        ):
            out = await _handle_scan_apk_sast({}, ctx)
        assert needle.lower() in out.lower()
