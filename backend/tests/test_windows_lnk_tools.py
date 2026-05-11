"""Phase η.C.E contract tests: windows_lnk MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search MCP tool returns the actual persisted shape from the η.C.A
table, not just that .add() was called.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_lnk import (
    _handle_lnk_walk_status,
    _handle_search_lnk_records,
    _handle_trigger_lnk_walk,
    register_windows_lnk_tools,
)
from app.models import Firmware, Project, WindowsLnkRecord
from app.services.jsonb_normalizers import (
    _stamp_windows_lnk_records_target_metadata,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the LNK
    handlers actually use."""

    db: AsyncSession
    firmware_id: uuid.UUID


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


def _make_lnk(
    firmware_id: uuid.UUID,
    *,
    lnk_filename: str,
    target_path: str | None = None,
    arguments: str | None = None,
) -> WindowsLnkRecord:
    return WindowsLnkRecord(
        firmware_id=firmware_id,
        source_path=(
            f"Users/dustin/AppData/Roaming/Microsoft/Windows/"
            f"Recent/{lnk_filename}"
        ),
        lnk_filename=lnk_filename,
        target_path=target_path,
        working_directory=None,
        arguments=arguments,
        description=None,
        icon_location=None,
        show_command="SW_SHOWNORMAL",
        hotkey=None,
        target_metadata=_stamp_windows_lnk_records_target_metadata(
            {"data": {"description": lnk_filename}}
        ),
    )


# ── Registration test ───────────────────────────────────────────────────────


def test_register_windows_lnk_tools_registers_three():
    """register_windows_lnk_tools must register exactly the three η.C.E
    tools (search / status / trigger)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_lnk_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_lnk_records" in names
    assert "lnk_walk_status" in names
    assert "trigger_lnk_walk" in names
    assert len(reg._tools) >= 3


# ── search_lnk_records ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_lnk_records_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="η.C.E search empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_lnk_records({}, ctx)
        parsed = json.loads(out)
        assert parsed["total_count"] == 0
        assert parsed["lnk_records"] == []
        assert "message" in parsed


@pytest.mark.asyncio
async def test_search_lnk_records_filter_by_lnk_filename_prefix():
    """lnk_filename_prefix filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="η.C.E filename filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "filter.bin", "f")
        db.add(firmware)
        await db.flush()

        db.add(_make_lnk(
            firmware.id, lnk_filename="Firefox.lnk",
            target_path=r"C:\Program Files\Mozilla Firefox\firefox.exe",
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="Firewalled.lnk",
            target_path=r"C:\Tools\firewalled.exe",
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="Notepad.lnk",
            target_path=r"C:\Windows\notepad.exe",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_lnk_records(
            {"lnk_filename_prefix": "Fire"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        names = {r["lnk_filename"] for r in parsed["lnk_records"]}
        assert names == {"Firefox.lnk", "Firewalled.lnk"}


@pytest.mark.asyncio
async def test_search_lnk_records_non_microsoft_only_filter():
    """non_microsoft_only filter surfaces only LNKs with non-MS targets."""
    async with make_live_db() as db:
        project = Project(name="η.C.E non-MS filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "nonms.bin", "n")
        db.add(firmware)
        await db.flush()

        db.add(_make_lnk(
            firmware.id, lnk_filename="Notepad.lnk",
            target_path=r"C:\Windows\notepad.exe",  # MS — skipped
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="UserTool.lnk",
            target_path=r"D:\Tools\user_tool.exe",  # non-MS — kept
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="Firefox.lnk",
            target_path=r"C:\Program Files\Mozilla Firefox\firefox.exe",  # non-MS — kept (Mozilla, not "Microsoft *")
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_lnk_records(
            {"non_microsoft_only": True}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        names = {r["lnk_filename"] for r in parsed["lnk_records"]}
        assert names == {"UserTool.lnk", "Firefox.lnk"}


@pytest.mark.asyncio
async def test_search_lnk_records_encoded_powershell_only_filter():
    """encoded_powershell_only filter surfaces only Qakbot-pattern LNKs."""
    async with make_live_db() as db:
        project = Project(name="η.C.E encoded-PS filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "encoded.bin", "e")
        db.add(firmware)
        await db.flush()

        db.add(_make_lnk(
            firmware.id, lnk_filename="Benign.lnk",
            target_path=r"C:\Windows\notepad.exe",
            arguments="/A simple-arg",
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="Qakbot.lnk",
            target_path=r"C:\Windows\System32\cmd.exe",
            arguments="/c powershell.exe -EncodedCommand SQBFAFgA",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_lnk_records(
            {"encoded_powershell_only": True}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 1
        assert parsed["lnk_records"][0]["lnk_filename"] == "Qakbot.lnk"


@pytest.mark.asyncio
async def test_search_lnk_records_script_host_only_filter():
    """script_host_only filter surfaces only LNKs whose target resolves
    to a known script-host binary."""
    async with make_live_db() as db:
        project = Project(name="η.C.E script-host filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "scripth.bin", "h")
        db.add(firmware)
        await db.flush()

        db.add(_make_lnk(
            firmware.id, lnk_filename="Notepad.lnk",
            target_path=r"C:\Windows\notepad.exe",  # not script host
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="cmd_via_lnk.lnk",
            target_path=r"C:\Windows\System32\cmd.exe",  # script host
        ))
        db.add(_make_lnk(
            firmware.id, lnk_filename="ps_via_lnk.lnk",
            target_path=r"C:\Windows\System32\powershell.exe",  # script host
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_lnk_records(
            {"script_host_only": True}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        names = {r["lnk_filename"] for r in parsed["lnk_records"]}
        assert names == {"cmd_via_lnk.lnk", "ps_via_lnk.lnk"}


# ── lnk_walk_status ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lnk_walk_status_idle_baseline():
    async with make_live_db() as db:
        project = Project(name="η.C.E status idle canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "status-idle.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lnk_walk_status({}, ctx)
        parsed = json.loads(out)
        assert parsed["status"] == "idle"
        assert parsed["error"] is None
        assert parsed["result"] is None


@pytest.mark.asyncio
async def test_lnk_walk_status_unknown_firmware():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_lnk_walk_status({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
        assert "not found" in parsed["error"]


# ── trigger_lnk_walk ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_lnk_walk_idempotent_409_on_running():
    """Idempotent POST + 409-on-conflict per Rule #33 .a — when status
    is already 'running', the trigger returns conflict=true rather than
    starting a duplicate run."""
    async with make_live_db() as db:
        project = Project(name="η.C.E trigger 409 canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trig.bin", "t")
        firmware.lnk_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_lnk_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed.get("conflict") is True
        assert parsed["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_lnk_walk_unknown_firmware():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_lnk_walk({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
        assert "not found" in parsed["error"]
