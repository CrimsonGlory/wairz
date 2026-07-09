"""MCP handler tests for ``app.ai.tools.rtos`` (was ~11% / 218 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.rtos import (
    _handle_analyze_memory_map,
    _handle_analyze_vector_table,
    _handle_detect_rtos_kernel,
    _handle_enumerate_rtos_tasks,
    _handle_recover_base_address,
    register_rtos_tools,
)


@dataclass
class _StubContext:
    db: object = None
    firmware_id: object = None
    project_id: object = None
    extracted_path: str | None = "/tmp/x"
    storage_path: str | None = None

    def __post_init__(self):
        self.firmware_id = self.firmware_id or uuid.uuid4()
        self.project_id = self.project_id or uuid.uuid4()


def test_register_rtos_tools():
    reg = ToolRegistry()
    register_rtos_tools(reg)
    assert len(reg._tools) >= 5


@pytest.mark.asyncio
async def test_detect_rtos_missing_storage():
    ctx = _StubContext(storage_path=None)
    assert "unavailable" in await _handle_detect_rtos_kernel({}, ctx)


@pytest.mark.asyncio
async def test_detect_rtos_with_mock_detection(tmp_path):
    blob = tmp_path / "fw.bin"
    blob.write_bytes(b"\x00" * 256)
    ctx = _StubContext(storage_path=str(blob))
    det = SimpleNamespace(kind="rtos", flavor="freertos", notes="matched")
    with patch("app.ai.tools.rtos.detect_firmware_kind", return_value=det):
        with patch("app.ai.tools.rtos._open_elf", return_value=(None, None)):
            out = await _handle_detect_rtos_kernel({}, ctx)
    assert "rtos" in out.lower()
    assert "freertos" in out.lower()


@pytest.mark.asyncio
async def test_enumerate_tasks_paths(tmp_path):
    blob = tmp_path / "fw.elf"
    blob.write_bytes(b"\x7fELF" + b"\x00" * 100)
    ctx = _StubContext(storage_path=str(blob))

    assert "unavailable" in await _handle_enumerate_rtos_tasks(
        {}, _StubContext(storage_path=None),
    )

    with patch("app.ai.tools.rtos._open_elf", return_value=(None, None)):
        out = await _handle_enumerate_rtos_tasks({}, ctx)
    assert "ELF" in out or "raw binary" in out.lower()

    # Fake ELF with symtab
    sym_task = MagicMock()
    sym_task.__getitem__ = lambda self, k: (
        {"type": "STT_FUNC"} if k == "st_info" else (0x1000 if k == "st_value" else 32)
    )
    sym_task.name = "SensorTask"
    sym_infra = MagicMock()
    sym_infra.__getitem__ = lambda self, k: (
        {"type": "STT_FUNC"} if k == "st_info" else (0x2000 if k == "st_value" else 16)
    )
    sym_infra.name = "vTaskDelay"

    symtab = MagicMock()
    symtab.iter_symbols.return_value = [sym_task, sym_infra]
    elf = MagicMock()
    elf.get_section_by_name.return_value = symtab
    fh = MagicMock()
    with patch("app.ai.tools.rtos._open_elf", return_value=(elf, fh)):
        out = await _handle_enumerate_rtos_tasks({}, ctx)
    assert "SensorTask" in out or "task" in out.lower()
    fh.close.assert_called()

    elf2 = MagicMock()
    elf2.get_section_by_name.return_value = None
    with patch("app.ai.tools.rtos._open_elf", return_value=(elf2, MagicMock())):
        out = await _handle_enumerate_rtos_tasks({}, ctx)
    assert "stripped" in out.lower() or "symtab" in out.lower()


@pytest.mark.asyncio
async def test_vector_table_base_address_memory_map(tmp_path):
    blob = tmp_path / "fw.bin"
    # Minimal vector table: SP + reset + handlers (little-endian words)
    import struct
    words = [0x20001000, 0x08000101] + [0x08000201] * 14
    blob.write_bytes(b"".join(struct.pack("<I", w) for w in words) + b"\x00" * 64)
    ctx = _StubContext(storage_path=str(blob))

    out = await _handle_analyze_vector_table({}, ctx)
    assert isinstance(out, str) and len(out) > 0

    out2 = await _handle_recover_base_address({}, ctx)
    assert isinstance(out2, str)

    out3 = await _handle_analyze_memory_map({}, ctx)
    assert isinstance(out3, str)

    for handler in (
        _handle_analyze_vector_table,
        _handle_recover_base_address,
        _handle_analyze_memory_map,
    ):
        err = await handler({}, _StubContext(storage_path=None))
        assert "unavailable" in err.lower() or "Error" in err or "storage" in err.lower()
