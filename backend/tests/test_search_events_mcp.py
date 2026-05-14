"""Phase ε.2.C — tier-1 live canary for the search_events MCP tool.

Inserts WindowsEventRecord rows with realistic Sysmon / Security shapes,
then drives _handle_search_events through filter combinations: provider
match, EID match, time range, pagination, empty-result message.
"""
from __future__ import annotations

import datetime
import json
import uuid

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools.windows_event_log import (
    _handle_search_events,
    register_windows_event_log_tools,
)
from app.models import Firmware, Project, WindowsEventRecord
from tests._live_db import make_live_db


def test_register_windows_event_log_tools_includes_cross_firmware_lookup():
    """Rule #44 acceptance — register_windows_event_log_tools registers
    lookup_event_record_across_firmwares alongside the per-firmware tools.
    Issue #15 backfill for ε.1.b walker."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_event_log_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "lookup_event_record_across_firmwares" in names


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


def _ctx(db, firmware_id: uuid.UUID) -> ToolContext:
    """Construct a minimal ToolContext for handler invocation."""
    return ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=firmware_id,
        extracted_path=None,
        db=db,
    )


async def _seed_events(db, firmware_id: uuid.UUID) -> int:
    """Insert 5 events: 2 Sysmon-1, 2 Security-4624, 1 Security-4625.
    Returns count inserted."""
    events = [
        WindowsEventRecord(
            firmware_id=firmware_id,
            evtx_file_path="Sysmon.evtx",
            provider="Microsoft-Windows-Sysmon",
            event_id=1,
            level=4,
            recorded_at=datetime.datetime(2025, 12, 25, 10, 0, 0, tzinfo=datetime.UTC),
            record_number=100,
        ),
        WindowsEventRecord(
            firmware_id=firmware_id,
            evtx_file_path="Sysmon.evtx",
            provider="Microsoft-Windows-Sysmon",
            event_id=1,
            level=4,
            recorded_at=datetime.datetime(2025, 12, 25, 11, 0, 0, tzinfo=datetime.UTC),
            record_number=101,
        ),
        WindowsEventRecord(
            firmware_id=firmware_id,
            evtx_file_path="Security.evtx",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4624,
            level=0,
            recorded_at=datetime.datetime(2025, 12, 25, 12, 0, 0, tzinfo=datetime.UTC),
            record_number=200,
        ),
        WindowsEventRecord(
            firmware_id=firmware_id,
            evtx_file_path="Security.evtx",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4624,
            level=0,
            recorded_at=datetime.datetime(2025, 12, 26, 8, 0, 0, tzinfo=datetime.UTC),
            record_number=201,
        ),
        WindowsEventRecord(
            firmware_id=firmware_id,
            evtx_file_path="Security.evtx",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4625,
            level=0,
            recorded_at=datetime.datetime(2025, 12, 26, 9, 0, 0, tzinfo=datetime.UTC),
            record_number=300,
        ),
    ]
    for e in events:
        db.add(e)
    await db.commit()
    return len(events)


@pytest.mark.asyncio
async def test_search_events_no_filter_returns_all_paginated():
    async with make_live_db() as db:
        project = Project(name="ε.2.C nofilter")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "a")
        db.add(firmware)
        await db.flush()
        await _seed_events(db, firmware.id)

        out = await _handle_search_events({}, _ctx(db, firmware.id))
        data = json.loads(out)

        assert data["total_count"] == 5
        assert len(data["events"]) == 5
        assert data["limit"] == 50
        assert data["offset"] == 0
        # ORDER BY recorded_at DESC — most recent first
        assert data["events"][0]["record_number"] == 300
        assert data["events"][-1]["record_number"] == 100


@pytest.mark.asyncio
async def test_search_events_filter_by_provider_and_eid():
    async with make_live_db() as db:
        project = Project(name="ε.2.C provider+eid")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "b")
        db.add(firmware)
        await db.flush()
        await _seed_events(db, firmware.id)

        out = await _handle_search_events(
            {"provider": "Microsoft-Windows-Sysmon", "event_id": 1},
            _ctx(db, firmware.id),
        )
        data = json.loads(out)

        assert data["total_count"] == 2
        assert all(e["provider"] == "Microsoft-Windows-Sysmon" for e in data["events"])
        assert all(e["event_id"] == 1 for e in data["events"])


@pytest.mark.asyncio
async def test_search_events_time_range_inclusive():
    async with make_live_db() as db:
        project = Project(name="ε.2.C timerange")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "c")
        db.add(firmware)
        await db.flush()
        await _seed_events(db, firmware.id)

        # Window: 2025-12-25 11:00 to 2025-12-26 08:00 inclusive — covers
        # records 101 (11:00), 200 (12:00), 201 (next day 08:00).
        out = await _handle_search_events(
            {
                "time_range_start": "2025-12-25T11:00:00Z",
                "time_range_end": "2025-12-26T08:00:00Z",
            },
            _ctx(db, firmware.id),
        )
        data = json.loads(out)

        assert data["total_count"] == 3
        record_nums = {e["record_number"] for e in data["events"]}
        assert record_nums == {101, 200, 201}


@pytest.mark.asyncio
async def test_search_events_pagination():
    async with make_live_db() as db:
        project = Project(name="ε.2.C pagination")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "d")
        db.add(firmware)
        await db.flush()
        await _seed_events(db, firmware.id)

        # Page 1: limit=2, offset=0
        out1 = await _handle_search_events({"limit": 2, "offset": 0}, _ctx(db, firmware.id))
        data1 = json.loads(out1)
        assert data1["total_count"] == 5
        assert len(data1["events"]) == 2

        # Page 2: limit=2, offset=2
        out2 = await _handle_search_events({"limit": 2, "offset": 2}, _ctx(db, firmware.id))
        data2 = json.loads(out2)
        assert data2["total_count"] == 5
        assert len(data2["events"]) == 2

        # Page 3 (last): limit=2, offset=4
        out3 = await _handle_search_events({"limit": 2, "offset": 4}, _ctx(db, firmware.id))
        data3 = json.loads(out3)
        assert data3["total_count"] == 5
        assert len(data3["events"]) == 1

        # No overlap between pages — set of returned record_numbers covers all 5
        all_nums = (
            {e["record_number"] for e in data1["events"]}
            | {e["record_number"] for e in data2["events"]}
            | {e["record_number"] for e in data3["events"]}
        )
        assert all_nums == {100, 101, 200, 201, 300}


@pytest.mark.asyncio
async def test_search_events_empty_returns_helpful_message():
    async with make_live_db() as db:
        project = Project(name="ε.2.C empty")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "e")
        db.add(firmware)
        await db.flush()
        # Don't seed events — empty result expected.

        out = await _handle_search_events({}, _ctx(db, firmware.id))
        data = json.loads(out)

        assert data["total_count"] == 0
        assert data["events"] == []
        assert "message" in data
        assert "trigger_evtx_walk" in data["message"]


@pytest.mark.asyncio
async def test_search_events_invalid_time_range_returns_error():
    async with make_live_db() as db:
        project = Project(name="ε.2.C invalid time")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "f")
        db.add(firmware)
        await db.flush()

        out = await _handle_search_events(
            {"time_range_start": "not-a-date"}, _ctx(db, firmware.id)
        )
        data = json.loads(out)
        assert "error" in data
        assert "time_range_start" in data["error"]


@pytest.mark.asyncio
async def test_search_events_limit_bounds():
    async with make_live_db() as db:
        project = Project(name="ε.2.C limit bounds")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "canary.bin", "g")
        db.add(firmware)
        await db.flush()
        await _seed_events(db, firmware.id)

        # limit=0 should be coerced to 1
        out_low = await _handle_search_events({"limit": 0}, _ctx(db, firmware.id))
        data_low = json.loads(out_low)
        assert data_low["limit"] == 1

        # limit=99999 should be coerced to 500
        out_high = await _handle_search_events({"limit": 99999}, _ctx(db, firmware.id))
        data_high = json.loads(out_high)
        assert data_high["limit"] == 500
