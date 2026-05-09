"""Phase ζ.3.E contract tests: windows_srum MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search MCP tool returns the actual persisted shape from the ζ.3.A
table, not just that .add() was called.
"""
from __future__ import annotations

import datetime
import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_srum import (
    _handle_search_srum_records,
    _handle_srum_walk_status,
    _handle_trigger_srum_walk,
    register_windows_srum_tools,
)
from app.models import Firmware, Project, WindowsSrumRecord
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    SRUM handlers actually use."""

    db: AsyncSession
    firmware_id: uuid.UUID


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Registration test ───────────────────────────────────────────────────────


def test_register_windows_srum_tools_registers_three():
    """register_windows_srum_tools must register exactly the three
    ζ.3.E tools (search / status / trigger)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_srum_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_srum_records" in names
    assert "srum_walk_status" in names
    assert "trigger_srum_walk" in names
    # Lower-bound — exactly 3 in this category, future additions are a
    # separate sub-phase.
    assert len(reg._tools) >= 3


# ── search_srum_records ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_srum_records_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="ζ.3.E search empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_srum_records({}, ctx)
        parsed = json.loads(out)
        assert parsed["total_count"] == 0
        assert parsed["records"] == []
        assert "message" in parsed


@pytest.mark.asyncio
async def test_search_srum_records_filter_by_record_type():
    """record_type filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.E filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "filter.bin", "f")
        db.add(firmware)
        await db.flush()

        types = [
            "network_data_usage",
            "network_data_usage",
            "application_resource_usage",
            "push_notification",
        ]
        for rt in types:
            db.add(
                WindowsSrumRecord(
                    firmware_id=firmware.id,
                    record_type=rt,
                    source_path="Windows/System32/sru/SRUDB.dat",
                    app_identifier="some-app.exe",
                )
            )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_srum_records(
            {"record_type": "network_data_usage"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2


@pytest.mark.asyncio
async def test_search_srum_records_invalid_record_type():
    """Unknown record_type surfaces a structured error."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.E invalid type canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "invalid-type.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_srum_records(
            {"record_type": "totally-bogus"}, ctx
        )
        parsed = json.loads(out)
        assert "error" in parsed
        assert "invalid record_type" in parsed["error"]


@pytest.mark.asyncio
async def test_search_srum_records_filter_by_app_identifier():
    """app_identifier filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.E filter app canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "filter-app.bin", "g")
        db.add(firmware)
        await db.flush()

        for app in ("chrome.exe", "cmd.exe", "chrome.exe", "powershell.exe"):
            db.add(
                WindowsSrumRecord(
                    firmware_id=firmware.id,
                    record_type="application_resource_usage",
                    source_path="Windows/System32/sru/SRUDB.dat",
                    app_identifier=app,
                )
            )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_srum_records(
            {"app_identifier": "chrome.exe"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        assert all(
            r["app_identifier"] == "chrome.exe" for r in parsed["records"]
        )


# ── srum_walk_status ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_srum_walk_status_default_idle():
    async with make_live_db() as db:
        project = Project(name="ζ.3.E status canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "status.bin", "d")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_srum_walk_status({}, ctx)
        parsed = json.loads(out)
        assert parsed["status"] == "idle"


@pytest.mark.asyncio
async def test_srum_walk_status_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_srum_walk_status({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed


# ── trigger_srum_walk ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_srum_walk_409_on_running():
    async with make_live_db() as db:
        project = Project(name="ζ.3.E trigger conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trigger-conflict.bin", "c")
        firmware.srum_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_srum_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed["conflict"] is True
        assert parsed["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_srum_walk_resets_on_idle(monkeypatch):
    """From idle: mutates state → 'queued' AND schedules background runner.
    Rule #35b: SELECT the row to verify the mutation."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.E trigger reset canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trigger-reset.bin", "r")
        firmware.srum_walk_status = "failed"
        firmware.srum_walk_error = "stale error"
        firmware.srum_walk_finished_at = datetime.datetime(
            2026, 1, 1, tzinfo=datetime.UTC
        )
        db.add(firmware)
        await db.commit()

        scheduled: list = []

        async def _noop_runner(firmware_id):
            scheduled.append(firmware_id)

        import app.services.srum_walker as walker_mod

        monkeypatch.setattr(
            walker_mod, "run_srum_walk_background", _noop_runner
        )

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_srum_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed["scheduled"] is True
        assert parsed["status"] == "queued"

        import asyncio as _asyncio
        await _asyncio.sleep(0)
        assert len(scheduled) == 1

        # Live canary: SELECT the row, verify the reset stuck.
        await db.commit()
        persisted = (
            await db.execute(
                select(Firmware).where(Firmware.id == firmware.id)
            )
        ).scalar_one()
        assert persisted.srum_walk_status == "queued"
        assert persisted.srum_walk_started_at is None
        assert persisted.srum_walk_finished_at is None
        assert persisted.srum_walk_error is None


@pytest.mark.asyncio
async def test_trigger_srum_walk_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_srum_walk({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
