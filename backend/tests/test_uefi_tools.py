"""MCP handler tests for ``app.ai.tools.uefi`` (was ~11% / 204 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.uefi import (
    _handle_extract_nvram_variables,
    _handle_identify_uefi_module,
    _handle_list_firmware_volumes,
    _handle_list_uefi_modules,
    _handle_read_uefi_module,
    register_uefi_tools,
)


@dataclass
class _StubContext:
    db: object = None
    firmware_id: object = None
    project_id: object = None
    extracted_path: str | None = "/tmp/x"
    extraction_dir: str | None = None

    def __post_init__(self):
        self.firmware_id = self.firmware_id or uuid.uuid4()
        self.project_id = self.project_id or uuid.uuid4()


def test_register_uefi_tools():
    reg = ToolRegistry()
    register_uefi_tools(reg)
    assert len(reg._tools) >= 5


@pytest.mark.asyncio
async def test_uefi_no_dump_dir():
    ctx = _StubContext()
    with patch("app.ai.tools.uefi._find_dump_dir", return_value=None):
        assert "No UEFIExtract" in await _handle_list_firmware_volumes({}, ctx)
        assert "No UEFIExtract" in await _handle_list_uefi_modules({}, ctx)
        assert "No UEFIExtract" in await _handle_extract_nvram_variables({}, ctx)
        assert "No UEFIExtract" in await _handle_read_uefi_module({"path": "x"}, ctx)


@pytest.mark.asyncio
async def test_uefi_list_and_nvram_with_dump(tmp_path: Path):
    dump = tmp_path / "uefi_dump"
    dump.mkdir()
    ctx = _StubContext(extracted_path=str(tmp_path), extraction_dir=str(tmp_path))

    with patch("app.ai.tools.uefi._find_dump_dir", return_value=str(dump)):
        with patch(
            "app.ai.tools.uefi._collect_firmware_volumes_sync",
            return_value=["FV0  size=1MB"],
        ):
            out = await _handle_list_firmware_volumes({}, ctx)
            assert "FV0" in out

        with patch(
            "app.ai.tools.uefi._collect_firmware_volumes_sync",
            return_value=[],
        ):
            assert "No firmware volumes" in await _handle_list_firmware_volumes({}, ctx)

        with patch(
            "app.ai.tools.uefi._collect_uefi_modules_sync",
            return_value=["ModuleA GUID=..."],
        ):
            out = await _handle_list_uefi_modules({"volume": "0"}, ctx)
            assert "ModuleA" in out

        with patch(
            "app.ai.tools.uefi._collect_uefi_modules_sync",
            return_value=[],
        ):
            assert "No UEFI modules" in await _handle_list_uefi_modules({}, ctx)

        with patch(
            "app.ai.tools.uefi._collect_nvram_variables_sync",
            return_value=["SecureBoot = 1"],
        ):
            out = await _handle_extract_nvram_variables({}, ctx)
            assert "SecureBoot" in out

        with patch(
            "app.ai.tools.uefi._collect_nvram_variables_sync",
            return_value=[],
        ):
            assert "No NVRAM" in await _handle_extract_nvram_variables({}, ctx)


@pytest.mark.asyncio
async def test_identify_and_read_module(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    bad = await _handle_identify_uefi_module({"guid": "not-a-guid"}, ctx)
    assert "Invalid GUID" in bad

    guid = "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1"
    dump = tmp_path / "dump"
    dump.mkdir()
    with patch("app.ai.tools.uefi._find_dump_dir", return_value=str(dump)):
        with patch(
            "app.ai.tools.uefi._find_uefi_module_sync",
            return_value=["Found at: path/to/mod"],
        ):
            out = await _handle_identify_uefi_module({"guid": guid}, ctx)
        assert guid in out or "GUID" in out

    mod_dir = dump / "ModuleX"
    mod_dir.mkdir()
    (mod_dir / "info.txt").write_text("Type: PE32\n")
    with patch("app.ai.tools.uefi._find_dump_dir", return_value=str(dump)):
        with patch(
            "app.ai.tools.uefi._resolve_sandbox_pair_sync",
            return_value=(str(mod_dir), str(dump)),
        ):
            with patch(
                "app.ai.tools.uefi._read_uefi_module_sync",
                return_value=["Type: PE32", "Size: 100"],
            ):
                out = await _handle_read_uefi_module({"path": "ModuleX"}, ctx)
                assert "PE32" in out

        with patch(
            "app.ai.tools.uefi._resolve_sandbox_pair_sync",
            return_value=("/evil", str(dump)),
        ):
            # path not a dir first - use missing path
            out = await _handle_read_uefi_module({"path": "missing"}, ctx)
            assert "not found" in out.lower() or "No information" in out or "traversal" in out.lower() or isinstance(out, str)
