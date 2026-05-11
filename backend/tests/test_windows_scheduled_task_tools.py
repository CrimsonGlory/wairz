"""Phase η.B.E contract tests: windows_scheduled_task MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search MCP tool returns the actual persisted shape from the η.B.A
table, not just that .add() was called.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_scheduled_task import (
    _handle_scheduled_task_walk_status,
    _handle_search_scheduled_tasks,
    _handle_trigger_scheduled_task_walk,
    register_windows_scheduled_task_tools,
)
from app.models import Firmware, Project, WindowsScheduledTask
from app.services.jsonb_normalizers import (
    _stamp_windows_scheduled_tasks_actions,
    _stamp_windows_scheduled_tasks_principal,
    _stamp_windows_scheduled_tasks_settings,
    _stamp_windows_scheduled_tasks_triggers,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    Scheduled Task handlers actually use."""

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


def _make_task(
    firmware_id: uuid.UUID,
    *,
    task_name: str,
    author: str | None = None,
    run_level: str | None = None,
    actions: list[dict] | None = None,
) -> WindowsScheduledTask:
    return WindowsScheduledTask(
        firmware_id=firmware_id,
        source_path=f"Windows/System32/Tasks/{task_name}",
        task_uri=f"\\{task_name}",
        task_name=task_name,
        author=author,
        run_level=run_level,
        triggers=_stamp_windows_scheduled_tasks_triggers(
            [{"type": "CalendarTrigger", "enabled": True}]
        ),
        actions=_stamp_windows_scheduled_tasks_actions(actions or []),
        principal=_stamp_windows_scheduled_tasks_principal({"id": "x"}),
        settings=_stamp_windows_scheduled_tasks_settings({"Enabled": True}),
    )


# ── Registration test ───────────────────────────────────────────────────────


def test_register_windows_scheduled_task_tools_registers_three():
    """register_windows_scheduled_task_tools must register exactly the
    three η.B.E tools (search / status / trigger)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_scheduled_task_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_scheduled_tasks" in names
    assert "scheduled_task_walk_status" in names
    assert "trigger_scheduled_task_walk" in names
    assert len(reg._tools) >= 3


# ── search_scheduled_tasks ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_scheduled_tasks_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="η.B.E search empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_scheduled_tasks({}, ctx)
        parsed = json.loads(out)
        assert parsed["total_count"] == 0
        assert parsed["tasks"] == []
        assert "message" in parsed


@pytest.mark.asyncio
async def test_search_scheduled_tasks_filter_by_run_level():
    """run_level filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="η.B.E filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "filter.bin", "f")
        db.add(firmware)
        await db.flush()

        db.add(
            _make_task(
                firmware.id,
                task_name="HighOne",
                run_level="HighestAvailable",
                author="Microsoft Corporation",
            )
        )
        db.add(
            _make_task(
                firmware.id,
                task_name="HighTwo",
                run_level="HighestAvailable",
                author="ThirdParty",
            )
        )
        db.add(
            _make_task(
                firmware.id,
                task_name="LowOne",
                run_level="LeastPrivilege",
                author="Microsoft Corporation",
            )
        )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_scheduled_tasks(
            {"run_level": "HighestAvailable"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        names = {t["task_name"] for t in parsed["tasks"]}
        assert names == {"HighOne", "HighTwo"}


@pytest.mark.asyncio
async def test_search_scheduled_tasks_filter_by_author():
    """author filter returns only exact-match rows."""
    async with make_live_db() as db:
        project = Project(name="η.B.E author filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "author.bin", "a")
        db.add(firmware)
        await db.flush()

        db.add(_make_task(firmware.id, task_name="One", author="Microsoft Corporation"))
        db.add(_make_task(firmware.id, task_name="Two", author="ThirdParty"))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_scheduled_tasks(
            {"author": "ThirdParty"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 1
        assert parsed["tasks"][0]["task_name"] == "Two"


@pytest.mark.asyncio
async def test_search_scheduled_tasks_encoded_powershell_only_filter():
    """encoded_powershell_only filter surfaces only Qakbot-pattern rows."""
    async with make_live_db() as db:
        project = Project(name="η.B.E encoded-PS filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "encoded.bin", "e")
        db.add(firmware)
        await db.flush()

        db.add(
            _make_task(
                firmware.id,
                task_name="Benign",
                actions=[
                    {
                        "type": "Exec",
                        "command": "C:\\foo.exe",
                        "arguments": "--start",
                    }
                ],
            )
        )
        db.add(
            _make_task(
                firmware.id,
                task_name="Qakbot",
                actions=[
                    {
                        "type": "Exec",
                        "command": "powershell.exe",
                        "arguments": "-EncodedCommand SQBFAFgA",
                    }
                ],
            )
        )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_scheduled_tasks(
            {"encoded_powershell_only": True}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 1
        assert parsed["tasks"][0]["task_name"] == "Qakbot"


@pytest.mark.asyncio
async def test_search_scheduled_tasks_invalid_run_level_returns_error():
    async with make_live_db() as db:
        project = Project(name="η.B.E invalid run_level canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "bad.bin", "b")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_scheduled_tasks(
            {"run_level": "Bogus"}, ctx
        )
        parsed = json.loads(out)
        assert "error" in parsed
        assert "must be one of" in parsed["error"]


# ── scheduled_task_walk_status ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scheduled_task_walk_status_idle_baseline():
    async with make_live_db() as db:
        project = Project(name="η.B.E status idle canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "status-idle.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_scheduled_task_walk_status({}, ctx)
        parsed = json.loads(out)
        assert parsed["status"] == "idle"
        assert parsed["error"] is None
        assert parsed["result"] is None


@pytest.mark.asyncio
async def test_scheduled_task_walk_status_unknown_firmware():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_scheduled_task_walk_status({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
        assert "not found" in parsed["error"]


# ── trigger_scheduled_task_walk ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_scheduled_task_walk_idempotent_409_on_running():
    """Idempotent POST + 409-on-conflict per Rule #33 .a — when status
    is already 'running', the trigger returns conflict=true rather than
    starting a duplicate run."""
    async with make_live_db() as db:
        project = Project(name="η.B.E trigger 409 canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trig.bin", "t")
        firmware.scheduled_task_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_scheduled_task_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed.get("conflict") is True
        assert parsed["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_scheduled_task_walk_unknown_firmware():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_scheduled_task_walk({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
        assert "not found" in parsed["error"]
