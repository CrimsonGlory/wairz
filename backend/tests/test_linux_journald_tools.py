"""Phase ι.A.E contract tests: linux_journald MCP tools (FIRST LINUX).

Per Rule #35b: live canaries via make_live_db. Tests verify that the
MCP tools return the actual persisted shape from the ι.A.A table,
not just that .add() was called.

Mirrors test_windows_bcd_tools.py shape — 5 MCP tools (list / lookup /
search / status / trigger) with contract assertions across happy-path
+ 404 + 409 + filter shapes.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.linux_journald import (
    _handle_journald_walk_status,
    _handle_list_journald_entries,
    _handle_lookup_journald_entry,
    _handle_search_journald_messages,
    _handle_trigger_journald_walk,
    register_linux_journald_tools,
)
from app.models import Firmware, LinuxJournaldEntry, Project
from app.services.jsonb_normalizers import (
    _stamp_linux_journald_entries_anomaly_flags,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    journald MCP handlers actually use."""

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


def _make_journald_entry(
    firmware_id: uuid.UUID,
    *,
    realtime_us: int = 1_700_000_000_000_000,
    priority: int = 6,
    transport: str = "journal",
    unit: str | None = "sshd.service",
    message: str = "test message",
    machine_id: str = "abcd" * 8,
    boot_id: str | None = None,
    anomaly_flags_override: dict | None = None,
) -> LinuxJournaldEntry:
    default_flags = {
        "priority_critical": priority <= 2,
        "oom_killer": False,
        "audit_failure": False,
        "selinux_denied": False,
        "segfault": False,
        "suspicious_unit": False,
        "log_clear_marker": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    return LinuxJournaldEntry(
        firmware_id=firmware_id,
        journal_file_path="var/log/journal/abc/system.journal",
        machine_id=machine_id,
        boot_id=boot_id or ("0" * 32),
        realtime_timestamp_us=realtime_us,
        monotonic_timestamp_us=123456,
        priority=priority,
        facility=3,
        transport=transport,
        unit=unit,
        pid=1234,
        uid=0,
        gid=0,
        comm="sshd",
        exe_path="/usr/sbin/sshd",
        cmdline="/usr/sbin/sshd -D",
        hostname="test-host",
        message=message,
        anomaly_flags=_stamp_linux_journald_entries_anomaly_flags(default_flags),
    )


# ── Registration test ────────────────────────────────────────────────────────


def test_register_linux_journald_tools_registers_five():
    """register_linux_journald_tools must register exactly the five
    ι.A.E tools."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_linux_journald_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "list_journald_entries" in names
    assert "lookup_journald_entry" in names
    assert "search_journald_messages" in names
    assert "journald_walk_status" in names
    assert "trigger_journald_walk" in names
    assert len(reg._tools) >= 5


# ── list_journald_entries ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_journald_entries_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="ι.A.E list empty")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "list-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_journald_entries({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert out["journald_entries"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_list_journald_entries_returns_all_when_no_filters():
    async with make_live_db() as db:
        project = Project(name="ι.A.E list all")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "list-all.bin", "a")
        db.add(firmware)
        await db.flush()

        for i in range(3):
            db.add(_make_journald_entry(
                firmware.id,
                realtime_us=1_700_000_000_000_000 + i,
                message=f"entry {i}",
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_journald_entries({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 3
        assert len(out["journald_entries"]) == 3


@pytest.mark.asyncio
async def test_list_journald_entries_filters_by_unit():
    async with make_live_db() as db:
        project = Project(name="ι.A.E list unit")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "list-unit.bin", "u")
        db.add(firmware)
        await db.flush()

        db.add(_make_journald_entry(
            firmware.id, unit="sshd.service", message="ssh starting"
        ))
        db.add(_make_journald_entry(
            firmware.id, unit="cron.service", message="cron starting"
        ))
        db.add(_make_journald_entry(
            firmware.id, unit="nginx.service", message="nginx starting"
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_journald_entries(
            {"unit": "ssh"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["journald_entries"][0]["unit"] == "sshd.service"


@pytest.mark.asyncio
async def test_list_journald_entries_filters_by_priority_at_most():
    async with make_live_db() as db:
        project = Project(name="ι.A.E list prio")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "list-p.bin", "p")
        db.add(firmware)
        await db.flush()

        # Priorities 1, 4, 6
        db.add(_make_journald_entry(
            firmware.id, priority=1, message="alert"
        ))
        db.add(_make_journald_entry(
            firmware.id, priority=4, message="warning"
        ))
        db.add(_make_journald_entry(
            firmware.id, priority=6, message="info"
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_journald_entries(
            {"priority_at_most": 3}, ctx
        )
        out = json.loads(out_str)
        # Only priority 1 (<=3) matches.
        assert out["total_count"] == 1
        assert out["journald_entries"][0]["priority"] == 1


@pytest.mark.asyncio
async def test_list_journald_entries_filters_by_anomaly_only():
    async with make_live_db() as db:
        project = Project(name="ι.A.E list anomaly")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "list-a.bin", "x")
        db.add(firmware)
        await db.flush()

        # Clean entry (no anomaly bits)
        db.add(_make_journald_entry(
            firmware.id, message="normal log"
        ))
        # OOM-killer (substantive anomaly)
        db.add(_make_journald_entry(
            firmware.id,
            message="oom kill",
            anomaly_flags_override={"oom_killer": True},
        ))
        # priority_critical alone is NOT substantive — excluded.
        db.add(_make_journald_entry(
            firmware.id,
            priority=1,
            message="alert",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_journald_entries(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(out_str)
        # Only the oom_killer entry should match — priority_critical
        # alone is NOT in the substantive-anomaly set.
        assert out["total_count"] == 1
        assert out["journald_entries"][0]["message"] == "oom kill"


# ── lookup_journald_entry ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_journald_entry_requires_id():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_journald_entry({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "entry_id" in out["error"]


@pytest.mark.asyncio
async def test_lookup_journald_entry_invalid_uuid_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_journald_entry(
            {"entry_id": "not-a-uuid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_journald_entry_returns_persisted_row():
    async with make_live_db() as db:
        project = Project(name="ι.A.E lookup")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "lookup.bin", "l")
        db.add(firmware)
        await db.flush()

        entry = _make_journald_entry(
            firmware.id, message="lookup target", unit="cron.service"
        )
        db.add(entry)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_lookup_journald_entry(
            {"entry_id": str(entry.id)}, ctx
        )
        out = json.loads(out_str)
        assert out["id"] == str(entry.id)
        assert out["message"] == "lookup target"
        assert out["unit"] == "cron.service"


# ── search_journald_messages ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_journald_messages_requires_query():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_search_journald_messages({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_search_journald_messages_finds_substring_match():
    async with make_live_db() as db:
        project = Project(name="ι.A.E search")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search.bin", "q")
        db.add(firmware)
        await db.flush()

        db.add(_make_journald_entry(
            firmware.id, message="failed to start something"
        ))
        db.add(_make_journald_entry(
            firmware.id, message="cron startup complete"
        ))
        db.add(_make_journald_entry(
            firmware.id, message="login session opened"
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_journald_messages(
            {"query": "start"}, ctx
        )
        out = json.loads(out_str)
        # "failed to start" + "cron startup" both match (case-insensitive)
        assert out["total_count"] == 2


# ── journald_walk_status ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_journald_walk_status_idle_initial_state():
    async with make_live_db() as db:
        project = Project(name="ι.A.E status idle")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "status.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_journald_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["status"] == "idle"
        assert out["started_at"] is None
        assert out["finished_at"] is None
        assert out["error"] is None
        assert out["result"] is None


@pytest.mark.asyncio
async def test_journald_walk_status_404_for_nonexistent_firmware():
    async with make_live_db() as db:
        project = Project(name="ι.A.E status 404")
        db.add(project)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_journald_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── trigger_journald_walk ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_journald_walk_queues_when_idle():
    async with make_live_db() as db:
        project = Project(name="ι.A.E trigger queue")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-q.bin", "u")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        from unittest.mock import patch

        # Patch asyncio.create_task to prevent the background task
        # actually spawning (would try to open an async_session_factory
        # connection to a non-existent test DB).
        with patch("asyncio.create_task") as mock_task:
            out_str = await _handle_trigger_journald_walk({}, ctx)
            out = json.loads(out_str)
            assert out["scheduled"] is True
            assert out["status"] == "queued"
            mock_task.assert_called_once()


@pytest.mark.asyncio
async def test_trigger_journald_walk_409_when_running():
    async with make_live_db() as db:
        project = Project(name="ι.A.E trigger conflict")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-c.bin", "v")
        firmware.journald_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_journald_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_journald_walk_409_when_queued():
    async with make_live_db() as db:
        project = Project(name="ι.A.E trigger queued")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-qc.bin", "w")
        firmware.journald_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_journald_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "queued"
