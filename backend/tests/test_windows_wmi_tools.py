"""Phase θ.B.G contract tests: windows_wmi MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search/status/trigger/lookup MCP tools return the actual persisted
shape from the θ.B.B table, not just that .add() was called.

Mirrors test_windows_bcd_tools.py shape — 4 MCP tools (search /
status / trigger / lookup) with contract assertions across happy-
path + 404 + 409 + filter shapes + cross-firmware aggregation.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_wmi import (
    _handle_lookup_wmi_persistence,
    _handle_search_wmi_events,
    _handle_trigger_wmi_walk,
    _handle_wmi_walk_status,
    register_windows_wmi_tools,
)
from app.models import Firmware, Project, WindowsWmiEvent
from app.services.jsonb_normalizers import (
    _stamp_windows_wmi_events_anomaly_flags,
    _stamp_windows_wmi_events_consumer_payload,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    WMI handlers actually use."""

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


def _make_wmi_event(
    firmware_id: uuid.UUID,
    *,
    binding_id: str,
    consumer_name: str | None = None,
    filter_name: str | None = None,
    consumer_type: str = "CommandLineEventConsumer",
    probably_benign: bool = False,
    fingerprint_sha256: str | None = None,
    consumer_arguments: str | None = None,
    anomaly_overrides: dict | None = None,
) -> WindowsWmiEvent:
    # Derive consumer + filter names from binding_id if not given.
    if consumer_name is None and "-" in binding_id:
        consumer_name = binding_id.split("-")[0]
    if filter_name is None and "-" in binding_id:
        filter_name = binding_id.split("-", 1)[1]
    consumer_name = consumer_name or binding_id
    filter_name = filter_name or binding_id

    default_flags = {
        "encoded_powershell": False,
        "script_host_invocation": False,
        "active_script_consumer": (
            consumer_type == "ActiveScriptEventConsumer"
        ),
        "non_benign_binding": not probably_benign,
        "high_severity": False,
    }
    if anomaly_overrides:
        default_flags.update(anomaly_overrides)

    payload: list | None = None
    if consumer_arguments:
        payload = _stamp_windows_wmi_events_consumer_payload([
            {
                "consumer_type": consumer_type,
                "arguments": consumer_arguments,
                "other": "",
            },
        ])

    return WindowsWmiEvent(
        firmware_id=firmware_id,
        source_path="Windows/System32/wbem/Repository/OBJECTS.DATA",
        binding_id=binding_id,
        filter_name=filter_name,
        consumer_name=consumer_name,
        consumer_type=consumer_type,
        consumer_payload=payload,
        anomaly_flags=_stamp_windows_wmi_events_anomaly_flags(default_flags),
        fingerprint_sha256=fingerprint_sha256,
        probably_benign=probably_benign,
    )


# ── Registration test ───────────────────────────────────────────────────────


def test_register_windows_wmi_tools_registers_four():
    """register_windows_wmi_tools must register exactly the four
    θ.B.G tools (search / status / trigger / lookup)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_wmi_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_wmi_events" in names
    assert "wmi_walk_status" in names
    assert "trigger_wmi_walk" in names
    assert "lookup_wmi_persistence" in names
    assert len(reg._tools) >= 4


# ── search_wmi_events ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_wmi_events_empty_returns_zero_total():
    """No persisted rows → total_count=0, helpful message."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search empty")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert out["wmi_events"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_search_wmi_events_returns_all_when_no_filters():
    """No filters → all persisted rows returned (default pagination)."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search all")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-all.bin", "a")
        db.add(firmware)
        await db.flush()

        for i in range(3):
            db.add(_make_wmi_event(
                firmware.id,
                binding_id=f"Consumer{i}-Filter{i}",
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 3
        assert len(out["wmi_events"]) == 3


@pytest.mark.asyncio
async def test_search_wmi_events_filters_by_active_script_only():
    """active_script_only=True → only ActiveScriptEventConsumer rows."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search active_script")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-as.bin", "x")
        db.add(firmware)
        await db.flush()

        db.add(_make_wmi_event(
            firmware.id,
            binding_id="A-Filter",
            consumer_type="CommandLineEventConsumer",
        ))
        db.add(_make_wmi_event(
            firmware.id,
            binding_id="B-Filter",
            consumer_type="ActiveScriptEventConsumer",
        ))
        db.add(_make_wmi_event(
            firmware.id,
            binding_id="C-Filter",
            consumer_type="LogFileEventConsumer",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events(
            {"active_script_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["wmi_events"][0]["consumer_type"] == (
            "ActiveScriptEventConsumer"
        )


@pytest.mark.asyncio
async def test_search_wmi_events_filters_by_non_benign_only():
    """non_benign_only=True → exclude probably_benign rows."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search non_benign")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-nb.bin", "b")
        db.add(firmware)
        await db.flush()

        db.add(_make_wmi_event(
            firmware.id,
            binding_id="BVTConsumer-BVTFilter",
            probably_benign=True,
        ))
        db.add(_make_wmi_event(
            firmware.id,
            binding_id="Malware-Filter",
            probably_benign=False,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events(
            {"non_benign_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["wmi_events"][0]["binding_id"] == "Malware-Filter"


@pytest.mark.asyncio
async def test_search_wmi_events_filters_by_anomaly_only():
    """anomaly_only=True → only rows with at least one anomaly flag."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search anomaly")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-ano.bin", "n")
        db.add(firmware)
        await db.flush()

        db.add(_make_wmi_event(
            firmware.id,
            binding_id="Clean-Filter",
            consumer_type="CommandLineEventConsumer",
        ))
        db.add(_make_wmi_event(
            firmware.id,
            binding_id="Suspicious-Filter",
            consumer_type="ActiveScriptEventConsumer",
            anomaly_overrides={"active_script_consumer": True, "high_severity": True},
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["wmi_events"][0]["binding_id"] == "Suspicious-Filter"


@pytest.mark.asyncio
async def test_search_wmi_events_binding_substring_filter():
    """binding_substring matches partial binding IDs."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G search substring")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-sub.bin", "u")
        db.add(firmware)
        await db.flush()

        db.add(_make_wmi_event(
            firmware.id, binding_id="QakbotConsumer-Filter"
        ))
        db.add(_make_wmi_event(
            firmware.id, binding_id="Other-Filter"
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events(
            {"binding_substring": "Qakbot"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert "Qakbot" in out["wmi_events"][0]["binding_id"]


@pytest.mark.asyncio
async def test_search_wmi_events_includes_data_only_disclaimer():
    """Output MUST include the Rule #36 data-only disclaimer."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G disclaimer")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-dd.bin", "d")
        db.add(firmware)
        await db.flush()

        db.add(_make_wmi_event(
            firmware.id,
            binding_id="Foo-Bar",
            consumer_arguments="powershell -enc QQ==",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_wmi_events({}, ctx)
        out = json.loads(out_str)
        assert "data_only_disclaimer" in out
        assert "Rule #36" in out["data_only_disclaimer"]


# ── wmi_walk_status ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wmi_walk_status_returns_idle_baseline():
    """Default firmware row → wmi_walk_status='idle' baseline."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G status idle")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "status.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_wmi_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["status"] == "idle"
        assert out["error"] is None
        assert out["result"] is None


@pytest.mark.asyncio
async def test_wmi_walk_status_returns_404_for_missing_firmware():
    """Non-existent firmware_id → error response."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_wmi_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── trigger_wmi_walk ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_wmi_walk_schedules_when_idle():
    """Idle firmware → status flips to queued, scheduled=True."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G trigger idle")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger.bin", "t")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_wmi_walk({}, ctx)
        out = json.loads(out_str)
        assert out["scheduled"] is True
        assert out["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_wmi_walk_409_when_running():
    """If wmi_walk_status is already 'running' → conflict=True
    response with the in-flight status."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G trigger conflict")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-c.bin", "c")
        firmware.wmi_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_wmi_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "running"
        assert "already" in out["message"]


@pytest.mark.asyncio
async def test_trigger_wmi_walk_404_for_missing_firmware():
    """Non-existent firmware_id → error response."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_trigger_wmi_walk({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── lookup_wmi_persistence ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_wmi_persistence_requires_at_least_one_filter():
    """Calling without fingerprint AND without binding_substring →
    error response."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_wmi_persistence({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "fingerprint" in out["error"].lower() or "binding" in out["error"].lower()


@pytest.mark.asyncio
async def test_lookup_wmi_persistence_by_fingerprint_aggregates_across_firmware():
    """Two firmware images carry the same fingerprint → lookup
    returns 2 distinct_firmware_count, both matches."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G lookup fp")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        fw3 = _make_firmware(project.id, "fw3.bin", "3")
        db.add(fw1)
        db.add(fw2)
        db.add(fw3)
        await db.flush()

        fp = "deadbeef" * 8

        # Same fingerprint on fw1 + fw2
        for fw in (fw1, fw2):
            db.add(_make_wmi_event(
                fw.id,
                binding_id="APT29-Filter",
                fingerprint_sha256=fp,
            ))
        # Different fingerprint on fw3
        db.add(_make_wmi_event(
            fw3.id,
            binding_id="Other-Filter",
            fingerprint_sha256="cafe" * 16,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=fw1.id)
        out_str = await _handle_lookup_wmi_persistence(
            {"fingerprint_sha256": fp}, ctx
        )
        out = json.loads(out_str)
        assert out["total_matches"] == 2
        assert out["distinct_firmware_count"] == 2


@pytest.mark.asyncio
async def test_lookup_wmi_persistence_by_binding_substring():
    """binding_substring → matches across firmware corpus."""
    async with make_live_db() as db:
        project = Project(name="θ.B.G lookup sub")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        db.add(_make_wmi_event(
            fw1.id,
            binding_id="ASECConsumer-ASECFilter",
            fingerprint_sha256="11" * 32,
        ))
        db.add(_make_wmi_event(
            fw2.id,
            binding_id="ASECConsumer-DifferentFilter",
            fingerprint_sha256="22" * 32,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=fw1.id)
        out_str = await _handle_lookup_wmi_persistence(
            {"binding_substring": "ASEC"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_matches"] == 2
        assert out["distinct_firmware_count"] == 2


@pytest.mark.asyncio
async def test_lookup_wmi_persistence_no_matches_returns_helpful_message():
    """No matches → helpful message + empty matches list."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_wmi_persistence(
            {"fingerprint_sha256": "nope" * 16}, ctx
        )
        out = json.loads(out_str)
        assert out["total_matches"] == 0
        assert out["matches"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_lookup_wmi_persistence_includes_data_only_disclaimer():
    """The Rule #36 disclaimer surfaces in lookup output too."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_wmi_persistence(
            {"binding_substring": "anything"}, ctx
        )
        out = json.loads(out_str)
        assert "data_only_disclaimer" in out
        assert "Rule #36" in out["data_only_disclaimer"]
