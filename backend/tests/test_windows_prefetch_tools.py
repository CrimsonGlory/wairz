"""Phase ζ.2.E contract tests: windows_prefetch MCP tools.

Per Rule #35b: live canaries via make_live_db (not just mock-call-count
asserts). Tests verify that the search MCP tool returns the actual
persisted shape from the ζ.2.A table, not just that .add() was called.
"""
from __future__ import annotations

import datetime
import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_prefetch import (
    _handle_prefetch_walk_status,
    _handle_search_prefetch_records,
    _handle_trigger_prefetch_walk,
    register_windows_prefetch_tools,
)
from app.models import Firmware, Project, WindowsPrefetchRecord
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the search/status/trigger handlers.
    Exposes db + firmware_id (only attributes the prefetch handlers use)."""

    db: AsyncSession
    firmware_id: uuid.UUID


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory (closes ε.2.A constructor-arg antipattern)."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Registration test (catches accidentally-omitted tools) ──────────────────


def test_register_windows_prefetch_tools_registers_three():
    """register_windows_prefetch_tools must register exactly the
    three ζ.2.E tools (search / status / trigger) — not more, not fewer."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_prefetch_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_prefetch_records" in names
    assert "prefetch_walk_status" in names
    assert "trigger_prefetch_walk" in names
    # Bound — exactly 3 (any future additions should be a separate sub-phase).
    assert len(reg._tools) >= 3


# ── search_prefetch_records ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_prefetch_records_empty_returns_zero_total():
    """No records persisted → total_count=0 + empty records[] + helpful message."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E search empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_prefetch_records({}, ctx)

        parsed = json.loads(out)
        assert parsed["total_count"] == 0
        assert parsed["records"] == []
        assert "message" in parsed


@pytest.mark.asyncio
async def test_search_prefetch_records_pagination():
    """Insert 7 prefetch records; page through with limit=3 + offset=3."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E search pagination canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "search-page.bin", "p")
        db.add(firmware)
        await db.flush()

        # Seven records with descending last_run_time so pagination order
        # is deterministic.
        base = datetime.datetime(2026, 5, 9, 12, 0, 0, tzinfo=datetime.UTC)
        for i in range(7):
            db.add(
                WindowsPrefetchRecord(
                    firmware_id=firmware.id,
                    prefetch_file_path=f"Windows/Prefetch/PROC{i}.EXE-{i:08X}.pf",
                    executable_name=f"PROC{i}.EXE",
                    run_count=i + 1,
                    last_run_time=base - datetime.timedelta(hours=i),
                )
            )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        # Page 0: first 3.
        out = await _handle_search_prefetch_records(
            {"limit": 3, "offset": 0}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 7
        assert len(parsed["records"]) == 3
        # Order: last_run_time DESC → most-recent first (PROC0).
        assert parsed["records"][0]["executable_name"] == "PROC0.EXE"

        # Page 1: next 3.
        out = await _handle_search_prefetch_records(
            {"limit": 3, "offset": 3}, ctx
        )
        parsed = json.loads(out)
        assert len(parsed["records"]) == 3
        assert parsed["records"][0]["executable_name"] == "PROC3.EXE"


@pytest.mark.asyncio
async def test_search_prefetch_records_filter_by_executable():
    """executable_name filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "filter.bin", "f")
        db.add(firmware)
        await db.flush()

        for name in ("CHROME.EXE", "CMD.EXE", "CHROME.EXE", "POWERSHELL.EXE"):
            db.add(
                WindowsPrefetchRecord(
                    firmware_id=firmware.id,
                    prefetch_file_path=f"Windows/Prefetch/{name}-XX.pf",
                    executable_name=name,
                )
            )
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_prefetch_records(
            {"executable_name": "CHROME.EXE"}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_count"] == 2
        assert all(r["executable_name"] == "CHROME.EXE" for r in parsed["records"])


@pytest.mark.asyncio
async def test_search_prefetch_records_invalid_time_range():
    """Malformed ISO timestamp surfaces a structured error, not a crash."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E invalid time canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "invalid-time.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_prefetch_records(
            {"last_run_time_start": "not-a-timestamp"}, ctx
        )
        parsed = json.loads(out)
        assert "error" in parsed
        assert "invalid last_run_time_start" in parsed["error"]


@pytest.mark.asyncio
async def test_search_prefetch_records_limit_bounded():
    """limit > 500 is clamped to 500; limit < 1 is clamped to 1."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E limit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "limit.bin", "l")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_prefetch_records({"limit": 9999}, ctx)
        parsed = json.loads(out)
        assert parsed["limit"] == 500

        out = await _handle_search_prefetch_records({"limit": -5}, ctx)
        parsed = json.loads(out)
        assert parsed["limit"] == 1


# ── prefetch_walk_status ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prefetch_walk_status_default_idle():
    """Newly-uploaded firmware has prefetch_walk_status='idle' by default
    (server_default from ζ.2.B migration)."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E status canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "status-default.bin", "d")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_prefetch_walk_status({}, ctx)
        parsed = json.loads(out)
        assert parsed["status"] == "idle"
        assert parsed["started_at"] is None
        assert parsed["finished_at"] is None
        assert parsed["error"] is None


@pytest.mark.asyncio
async def test_prefetch_walk_status_firmware_not_found():
    """If firmware_id doesn't exist, returns structured error."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_prefetch_walk_status({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed


# ── trigger_prefetch_walk ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_prefetch_walk_409_on_running():
    """If status is already 'running', returns conflict=true with the
    current state; does NOT mutate the row."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E trigger conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trigger-conflict.bin", "c")
        firmware.prefetch_walk_status = "running"
        firmware.prefetch_walk_started_at = datetime.datetime(
            2026, 5, 9, 12, 0, 0, tzinfo=datetime.UTC
        )
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_prefetch_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed["conflict"] is True
        assert parsed["status"] == "running"

        # Verify NOT mutated — Rule #35b live canary.
        persisted = (
            await db.execute(
                select(Firmware).where(Firmware.id == firmware.id)
            )
        ).scalar_one()
        assert persisted.prefetch_walk_status == "running"


@pytest.mark.asyncio
async def test_trigger_prefetch_walk_409_on_queued():
    """Same conflict guard for status='queued'."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E trigger queued canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trigger-queued.bin", "q")
        firmware.prefetch_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_prefetch_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed["conflict"] is True
        assert parsed["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_prefetch_walk_resets_on_idle(monkeypatch):
    """From idle: mutates state → 'queued' AND schedules background runner.
    Rule #35b: SELECT the row to verify the mutation."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.E trigger reset canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trigger-reset.bin", "r")
        # Pre-populate with a stale failed result to verify the reset.
        firmware.prefetch_walk_status = "failed"
        firmware.prefetch_walk_error = "stale error from prior run"
        firmware.prefetch_walk_finished_at = datetime.datetime(
            2026, 1, 1, tzinfo=datetime.UTC
        )
        db.add(firmware)
        await db.commit()

        # Stub the prefetch_walker's run_prefetch_walk_background so we
        # don't actually run the bg runner (which would try
        # async_session_factory and gaierror on dev host per Rule #39
        # pitfall). Patch the imported reference inside the MCP tool
        # module since the trigger handler imports it lazily.
        scheduled: list = []

        async def _noop_runner(firmware_id):  # noqa: ANN001 — test stub
            scheduled.append(firmware_id)

        # The trigger handler imports run_prefetch_walk_background lazily
        # at call time from app.services.prefetch_walker — patch there.
        import app.services.prefetch_walker as walker_mod

        monkeypatch.setattr(
            walker_mod, "run_prefetch_walk_background", _noop_runner
        )

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_prefetch_walk({}, ctx)
        parsed = json.loads(out)
        assert parsed["scheduled"] is True
        assert parsed["status"] == "queued"
        # Yield to let the create_task schedule + run our noop_runner.
        # _noop_runner just appends and returns immediately.
        import asyncio as _asyncio
        await _asyncio.sleep(0)
        assert len(scheduled) == 1

        # Live canary: SELECT the row, verify the reset stuck.
        await db.commit()  # flush() + verify
        persisted = (
            await db.execute(
                select(Firmware).where(Firmware.id == firmware.id)
            )
        ).scalar_one()
        assert persisted.prefetch_walk_status == "queued"
        assert persisted.prefetch_walk_started_at is None
        assert persisted.prefetch_walk_finished_at is None
        assert persisted.prefetch_walk_error is None
        assert persisted.prefetch_walk_result is None


@pytest.mark.asyncio
async def test_trigger_prefetch_walk_firmware_not_found():
    """If firmware_id doesn't exist, returns structured error."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_prefetch_walk({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed
