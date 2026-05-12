"""Phase ι.C.E contract tests: windows_etl MCP tools (FIRST ι WINDOWS MCP).

Per Rule #35b: live canaries via make_live_db. Tests verify that the
MCP tools return the actual persisted shape from the ι.C.A table, not
just that .add() was called.

Mirrors test_linux_systemd_tools.py shape — 5 per-firmware tools
(list / lookup / search / status / trigger) + 1 cross-firmware
aggregation tool with contract assertions across happy-path + 404 +
409 + filter shapes + supply-chain signal aggregation.

Includes coverage for the SECOND application of the cross-firmware
aggregation pattern at walker-stream time (ι.B precedent → ι.C
Rule-of-Two): lookup_etl_provider_across_firmwares within a project
AND globally; supply_chain_signal emission on match_count >= 2.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_etl import (
    _handle_etl_walk_status,
    _handle_list_etl_events,
    _handle_lookup_etl_event,
    _handle_lookup_etl_provider_across_firmwares,
    _handle_search_etl_events,
    _handle_trigger_etl_walk,
    register_windows_etl_tools,
)
from app.models import Firmware, Project, WindowsEtlEvent
from app.services.jsonb_normalizers import (
    _stamp_windows_etl_events_anomaly_flags,
    _stamp_windows_etl_events_payload,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the ETL MCP handlers."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None


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


def _make_etl_event(
    firmware_id: uuid.UUID,
    *,
    provider_guid: str = "9e814aad-3204-11d2-9a82-006008a86939",
    provider_name: str = "NT Kernel Logger",
    etl_session_name: str = "AutoLogger-Diagtrack-Listener",
    etl_file_path: str = "Windows/System32/WDI/LogFiles/BootCKCL.etl",
    event_id: int = 1,
    event_opcode: int = 1,
    timestamp_ft: int = 132000000000000000,
    process_id: int | None = 1234,
    thread_id: int | None = 5678,
    payload_extra: dict | None = None,
    anomaly_flags_override: dict | None = None,
) -> WindowsEtlEvent:
    default_flags = {
        "kernel_proc_after_evtx_clear": False,
        "provider_disable_evidence": False,
        "unusual_provider": False,
        "non_microsoft_in_diagtrack": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    payload = {"ProcessId": process_id or 0}
    if payload_extra:
        payload.update(payload_extra)
    return WindowsEtlEvent(
        firmware_id=firmware_id,
        etl_file_path=etl_file_path,
        etl_session_name=etl_session_name,
        provider_guid=provider_guid,
        provider_name=provider_name,
        event_id=event_id,
        event_version=0,
        event_channel=None,
        event_level=4,
        event_opcode=event_opcode,
        event_keywords=0,
        event_task=0,
        timestamp_ft=timestamp_ft,
        process_id=process_id,
        thread_id=thread_id,
        processor_id=None,
        kernel_time_us=None,
        user_time_us=None,
        payload=_stamp_windows_etl_events_payload(payload),
        anomaly_flags=_stamp_windows_etl_events_anomaly_flags(default_flags),
        raw_record_size=128,
    )


# ── Registration smoke ────────────────────────────────────────────────────────


def test_register_windows_etl_tools_registers_6_tools():
    from app.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()
    register_windows_etl_tools(registry)
    tool_names = sorted(registry._tools.keys())
    assert tool_names == [
        "etl_walk_status",
        "list_etl_events",
        "lookup_etl_event",
        "lookup_etl_provider_across_firmwares",
        "search_etl_events",
        "trigger_etl_walk",
    ]


# ── list_etl_events ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_etl_events_returns_per_firmware_rows():
    async with make_live_db() as db:
        project = Project(name="iota-c-test", description="ι.C.E test")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "a")
        db.add(firmware)
        await db.flush()

        db.add(_make_etl_event(firmware.id, event_id=1))
        db.add(_make_etl_event(firmware.id, event_id=2))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events({"limit": 10}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 2
        assert len(out["etl_events"]) == 2


@pytest.mark.asyncio
async def test_list_etl_events_filter_by_provider_guid():
    async with make_live_db() as db:
        project = Project(name="iota-c-test2", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "b")
        db.add(firmware)
        await db.flush()

        db.add(_make_etl_event(
            firmware.id,
            provider_guid="9e814aad-3204-11d2-9a82-006008a86939",
            event_id=1,
        ))
        db.add(_make_etl_event(
            firmware.id,
            provider_guid="12345678-1234-1234-1234-123456789abc",
            event_id=99,
            provider_name="ThirdParty",
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events(
            {
                "provider_guid": "9e814aad-3204-11d2-9a82-006008a86939",
                "limit": 10,
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["etl_events"][0]["event_id"] == 1


@pytest.mark.asyncio
async def test_list_etl_events_anomaly_only_filter():
    async with make_live_db() as db:
        project = Project(name="iota-c-test3", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "c")
        db.add(firmware)
        await db.flush()

        # Normal event.
        db.add(_make_etl_event(firmware.id, event_id=1))
        # Anomalous event.
        db.add(_make_etl_event(
            firmware.id,
            event_id=2,
            anomaly_flags_override={"unusual_provider": True},
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events(
            {"anomaly_only": True, "limit": 10},
            ctx,
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["etl_events"][0]["event_id"] == 2


@pytest.mark.asyncio
async def test_list_etl_events_no_results_message():
    async with make_live_db() as db:
        project = Project(name="iota-c-empty", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "d")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert "message" in out


# ── lookup_etl_event ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_etl_event_happy_path():
    async with make_live_db() as db:
        project = Project(name="lookup-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "e")
        db.add(firmware)
        await db.flush()

        evt = _make_etl_event(firmware.id, event_id=42)
        db.add(evt)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_lookup_etl_event(
            {"event_row_id": str(evt.id)}, ctx
        )
        out = json.loads(out_str)
        assert out["id"] == str(evt.id)
        assert out["event_id"] == 42
        assert "payload" in out


@pytest.mark.asyncio
async def test_lookup_etl_event_missing_id():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_etl_event({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_etl_event_invalid_uuid():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_etl_event(
            {"event_row_id": "not-a-uuid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_etl_event_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_etl_event(
            {"event_row_id": str(uuid.uuid4())}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── search_etl_events ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_etl_events_finds_by_provider_name():
    async with make_live_db() as db:
        project = Project(name="search-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "f")
        db.add(firmware)
        await db.flush()

        db.add(_make_etl_event(
            firmware.id,
            provider_name="Microsoft-Windows-Kernel-Process",
            event_id=1,
        ))
        db.add(_make_etl_event(
            firmware.id,
            provider_guid="22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
            provider_name="Microsoft-Windows-Diagtrack",
            event_id=2,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_etl_events(
            {"query": "Kernel-Process"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["matches"][0]["provider_name"] == "Microsoft-Windows-Kernel-Process"


@pytest.mark.asyncio
async def test_search_etl_events_missing_query():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_search_etl_events({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── etl_walk_status ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_etl_walk_status_returns_state():
    async with make_live_db() as db:
        project = Project(name="status-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "g")
        firmware.etl_walk_status = "completed"
        firmware.etl_walk_result = {
            "schema_version": 1,
            "files_scanned": 3,
            "events_walked": 100,
            "events_persisted": 100,
            "anomaly_total": 5,
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_etl_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["status"] == "completed"
        assert out["result"]["files_scanned"] == 3


@pytest.mark.asyncio
async def test_etl_walk_status_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_etl_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── trigger_etl_walk ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_etl_walk_schedules(monkeypatch):
    """trigger_etl_walk transitions status idle → queued + schedules
    the background runner."""
    scheduled = []

    # Use a mock that swallows the coro so we don't actually launch
    # the background task (which would try to connect to the real
    # async_session_factory()).
    from unittest.mock import patch as _patch

    async def _noop():
        return None

    def _fake_create_task(coro):
        # Close the coroutine so it doesn't trigger a "coroutine never
        # awaited" warning, then return a dummy future-like.
        coro.close()
        scheduled.append(True)
        # Return a real Task wrapping a no-op to satisfy any caller
        # that calls .add_done_callback() on the result.
        import asyncio as _asyncio
        return _asyncio.ensure_future(_noop())

    with _patch("app.ai.tools.windows_etl.asyncio.create_task", side_effect=_fake_create_task):
        async with make_live_db() as db:
            project = Project(name="trigger-test", description="x")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "win10.bin", "h")
            db.add(firmware)
            await db.flush()

            ctx = _StubContext(db=db, firmware_id=firmware.id)
            out_str = await _handle_trigger_etl_walk({}, ctx)
            out = json.loads(out_str)
            assert out["scheduled"] is True
            assert out["status"] == "queued"
            assert scheduled


@pytest.mark.asyncio
async def test_trigger_etl_walk_conflict_when_running():
    """trigger_etl_walk returns 409-style conflict if already running.
    No need to mock create_task — handler returns early before
    scheduling."""
    async with make_live_db() as db:
        project = Project(name="conflict-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "i")
        firmware.etl_walk_status = "running"
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_etl_walk({}, ctx)
        out = json.loads(out_str)
        assert out.get("conflict") is True
        assert out["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_etl_walk_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_trigger_etl_walk({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── lookup_etl_provider_across_firmwares — CROSS-FIRMWARE AGG ─────────────────


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_project_scope():
    """Provider GUID present in 2 firmwares of same project → both
    matches return + supply_chain_signal."""
    async with make_live_db() as db:
        project = Project(name="cross-test", description="x")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        target_guid = "12345678-1234-1234-1234-123456789abc"
        db.add(_make_etl_event(
            fw1.id,
            provider_guid=target_guid,
            provider_name="ThirdPartyEDR",
            event_id=1,
        ))
        db.add(_make_etl_event(
            fw2.id,
            provider_guid=target_guid,
            provider_name="ThirdPartyEDR",
            event_id=2,
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=project.id
        )
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {"provider_guid": target_guid, "scope": "project"},
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_count"] == 2
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_no_match():
    """Provider GUID not present → empty + message."""
    async with make_live_db() as db:
        project = Project(name="empty-cross", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "3")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {
                "provider_guid": "12345678-1234-1234-1234-123456789abc",
                "scope": "project",
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_count"] == 0
        assert "message" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_global_scope():
    """scope=global crosses projects."""
    async with make_live_db() as db:
        project1 = Project(name="proj1", description="x")
        project2 = Project(name="proj2", description="y")
        db.add(project1)
        db.add(project2)
        await db.flush()

        fw1 = _make_firmware(project1.id, "fw1.bin", "4")
        fw2 = _make_firmware(project2.id, "fw2.bin", "5")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        target_guid = "abcdef00-0000-0000-0000-000000000001"
        db.add(_make_etl_event(
            fw1.id, provider_guid=target_guid, event_id=1
        ))
        db.add(_make_etl_event(
            fw2.id, provider_guid=target_guid, event_id=1
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=project1.id
        )
        # Project-scoped → only 1 match.
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {"provider_guid": target_guid, "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1

        # Global → both.
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {"provider_guid": target_guid, "scope": "global"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 2
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_missing_provider_guid():
    async with make_live_db() as db:
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4()
        )
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_invalid_guid():
    async with make_live_db() as db:
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4()
        )
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {"provider_guid": "not-a-guid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out
        assert "valid GUID" in out["error"]


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_event_id_filter():
    """event_id filter restricts to a specific provider+event_id pair."""
    async with make_live_db() as db:
        project = Project(name="event-filter", description="x")
        db.add(project)
        await db.flush()

        fw = _make_firmware(project.id, "fw.bin", "6")
        db.add(fw)
        await db.flush()

        target_guid = "abcdef00-0000-0000-0000-000000000002"
        db.add(_make_etl_event(fw.id, provider_guid=target_guid, event_id=1))
        db.add(_make_etl_event(fw.id, provider_guid=target_guid, event_id=99))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw.id, project_id=project.id
        )
        out_str = await _handle_lookup_etl_provider_across_firmwares(
            {"provider_guid": target_guid, "event_id": 1, "scope": "project"},
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1
        # 1 firmware row; match_count is per-firmware
        assert out["matches"][0]["match_count"] == 1


# ── Boundary + truncation ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_etl_events_caps_limit_at_500():
    async with make_live_db() as db:
        project = Project(name="cap-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "7")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        # Request limit=10000 → should cap at 500.
        out_str = await _handle_list_etl_events({"limit": 10000}, ctx)
        out = json.loads(out_str)
        assert out["limit"] == 500


@pytest.mark.asyncio
async def test_list_etl_events_offset_negative_normalised_to_zero():
    async with make_live_db() as db:
        project = Project(name="neg-offset", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "8")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events({"offset": -10}, ctx)
        out = json.loads(out_str)
        assert out["offset"] == 0


# ── Row summary shape ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_etl_events_row_summary_includes_all_fields():
    async with make_live_db() as db:
        project = Project(name="shape-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "9")
        db.add(firmware)
        await db.flush()

        db.add(_make_etl_event(
            firmware.id,
            anomaly_flags_override={
                "kernel_proc_after_evtx_clear": True,
            },
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_etl_events({}, ctx)
        out = json.loads(out_str)
        evt = out["etl_events"][0]
        # Key fields must surface.
        for field in (
            "id",
            "etl_file_path",
            "etl_session_name",
            "provider_guid",
            "provider_name",
            "event_id",
            "timestamp_ft",
            "process_id",
            "thread_id",
            "anomaly_flags",
            "has_anomaly",
        ):
            assert field in evt
        assert evt["has_anomaly"] is True
        assert evt["anomaly_flags"]["kernel_proc_after_evtx_clear"] is True
