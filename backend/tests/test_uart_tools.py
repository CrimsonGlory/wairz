"""MCP handler tests for ``app.ai.tools.uart`` (was ~14% / 116 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.uart import (
    _handle_uart_connect,
    _handle_uart_disconnect,
    _handle_uart_get_transcript,
    _handle_uart_read,
    _handle_uart_send_break,
    _handle_uart_send_command,
    _handle_uart_send_raw,
    _handle_uart_status,
    register_uart_tools,
)


@dataclass
class _StubContext:
    db: object
    firmware_id: uuid.UUID
    project_id: uuid.UUID
    extracted_path: str | None = "/tmp/extract"


def _ctx():
    db = MagicMock()
    db.flush = AsyncMock()
    return _StubContext(db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4())


def test_register_uart_tools():
    reg = ToolRegistry()
    register_uart_tools(reg)
    assert len(reg._tools) == 8


@pytest.mark.asyncio
async def test_uart_connect_branches():
    ctx = _ctx()
    assert "device_path is required" in await _handle_uart_connect({}, ctx)

    session = SimpleNamespace(
        id=uuid.uuid4(), device_path="/dev/ttyUSB0", baudrate=115200, status="connected",
    )
    mock_svc = MagicMock()
    mock_svc.connect = AsyncMock(return_value=session)
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        out = await _handle_uart_connect({"device_path": "/dev/ttyUSB0"}, ctx)
    assert "connected successfully" in out.lower()

    mock_svc.connect = AsyncMock(side_effect=ConnectionError("down"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_connect({"device_path": "/dev/ttyUSB0"}, ctx)

    mock_svc.connect = AsyncMock(side_effect=ValueError("bad baud"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "bad baud" in await _handle_uart_connect({"device_path": "/dev/ttyUSB0"}, ctx)


@pytest.mark.asyncio
async def test_uart_send_command_and_read():
    ctx = _ctx()
    assert "command is required" in await _handle_uart_send_command({}, ctx)

    mock_svc = MagicMock()
    mock_svc.send_command = AsyncMock(return_value={"output": "ok\n# "})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "ok" in await _handle_uart_send_command({"command": "help"}, ctx)

    mock_svc.send_command = AsyncMock(return_value={"output": "  "})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "no output" in (await _handle_uart_send_command({"command": "x"}, ctx)).lower()

    mock_svc.send_command = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Bridge unreachable" in await _handle_uart_send_command({"command": "x"}, ctx)

    mock_svc.send_command = AsyncMock(side_effect=ValueError("no session"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "no session" in await _handle_uart_send_command({"command": "x"}, ctx)

    mock_svc.read_buffer = AsyncMock(return_value={"output": "boot\n", "bytes": 5})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        out = await _handle_uart_read({}, ctx)
        assert "boot" in out and "5 bytes" in out

    mock_svc.read_buffer = AsyncMock(return_value={"output": "", "bytes": 0})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "empty" in (await _handle_uart_read({}, ctx)).lower()

    mock_svc.read_buffer = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Bridge" in await _handle_uart_read({}, ctx)

    mock_svc.read_buffer = AsyncMock(side_effect=ValueError("y"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_read({}, ctx)


@pytest.mark.asyncio
async def test_uart_break_raw_disconnect_status_transcript():
    ctx = _ctx()
    mock_svc = MagicMock()
    mock_svc.send_break = AsyncMock()
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "BREAK" in await _handle_uart_send_break({}, ctx)
    mock_svc.send_break = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Bridge" in await _handle_uart_send_break({}, ctx)
    mock_svc.send_break = AsyncMock(side_effect=ValueError("v"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_send_break({}, ctx)

    assert "data is required" in await _handle_uart_send_raw({}, ctx)
    mock_svc.send_raw = AsyncMock(return_value={"bytes_sent": 4})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Sent 4" in await _handle_uart_send_raw({"data": "AAAA", "hex": True}, ctx)
    mock_svc.send_raw = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Bridge" in await _handle_uart_send_raw({"data": "x"}, ctx)
    mock_svc.send_raw = AsyncMock(side_effect=ValueError("v"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_send_raw({"data": "x"}, ctx)

    session = SimpleNamespace(
        id=uuid.uuid4(), device_path="/dev/ttyUSB0",
        connected_at=datetime.now(UTC), closed_at=datetime.now(UTC),
    )
    mock_svc.disconnect = AsyncMock(return_value=session)
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "disconnected" in (await _handle_uart_disconnect({}, ctx)).lower()
    mock_svc.disconnect = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_disconnect({}, ctx)
    mock_svc.disconnect = AsyncMock(side_effect=ValueError("v"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_disconnect({}, ctx)

    mock_svc.get_status = AsyncMock(return_value={
        "connected": True, "device": "/dev/ttyUSB0", "baudrate": 115200,
        "buffer_bytes": 10, "transcript_path": "/tmp/t.log",
        "session": {"id": str(uuid.uuid4()), "status": "connected"},
        "bridge_error": None,
    })
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        st = await _handle_uart_status({}, ctx)
        assert "Connected" in st and "ttyUSB0" in st

    mock_svc.get_status = AsyncMock(return_value={
        "connected": False, "bridge_error": "timeout",
    })
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        st = await _handle_uart_status({}, ctx)
        assert "Not connected" in st and "timeout" in st

    mock_svc.get_transcript = AsyncMock(return_value={"entries": [], "count": 0})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "No transcript" in await _handle_uart_get_transcript({}, ctx)

    entries = [
        {"ts": "2024-01-01T12:00:00Z", "dir": "cmd", "command": "help", "prompt": "# ", "data": ""},
        {"ts": "2024-01-01T12:00:01Z", "dir": "tx", "data": "x" * 250},
        {"ts": "2024-01-01T12:00:02Z", "dir": "rx", "data": "y" * 250},
        {"ts": "2024-01-01T12:00:03Z", "dir": "evt", "data": "boot"},
    ]
    mock_svc.get_transcript = AsyncMock(return_value={"entries": entries, "count": 4})
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        tr = await _handle_uart_get_transcript({}, ctx)
        assert "CMD:" in tr and "TX:" in tr and "RX:" in tr

    mock_svc.get_transcript = AsyncMock(side_effect=ConnectionError("x"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Bridge" in await _handle_uart_get_transcript({}, ctx)
    mock_svc.get_transcript = AsyncMock(side_effect=ValueError("v"))
    with patch("app.ai.tools.uart.UARTService", return_value=mock_svc):
        assert "Error" in await _handle_uart_get_transcript({}, ctx)
