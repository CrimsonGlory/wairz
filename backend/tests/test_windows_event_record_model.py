"""Tests for the WindowsEventRecord ORM model (Phase ε.2.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEventRecord
from tests._live_db import make_live_db


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Helper — Firmware requires project_id + sha256; the rest are nullable."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_windows_event_record_round_trip():
    """Insert a WindowsEventRecord with realistic Sysmon EID 1 fields,
    SELECT it back, and verify every column reflects the constructor
    args (Rule #35b live-canary pattern)."""
    async with make_live_db() as db:
        # FK chain: project → firmware → event record.
        project = Project(name="ε.2.A canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-roundtrip.bin", "a")
        db.add(firmware)
        await db.flush()

        recorded = datetime.datetime(2026, 5, 10, 14, 23, 45, tzinfo=datetime.UTC)
        event = WindowsEventRecord(
            firmware_id=firmware.id,
            evtx_file_path="Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
            provider="Microsoft-Windows-Sysmon",
            event_id=1,
            level=4,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer="WORKSTATION-01",
            task=1,
            recorded_at=recorded,
            message_xml={
                "schema_version": 1,
                "EventData": {
                    "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                    "CommandLine": "notepad.exe foo.txt",
                    "Image": "C:\\Windows\\System32\\notepad.exe",
                    "User": "WORKSTATION-01\\alice",
                },
            },
            raw_xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>...</Event>",
            record_number=12345,
        )
        db.add(event)
        await db.commit()

        # Live canary: SELECT it back and verify EVERY field the constructor
        # set is correctly persisted. Mocks would not catch a constructor
        # bug here — only a real round-trip does (Rule #35b).
        persisted = (
            await db.execute(
                select(WindowsEventRecord).where(WindowsEventRecord.id == event.id)
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert (
            persisted.evtx_file_path
            == "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
        )
        assert persisted.provider == "Microsoft-Windows-Sysmon"
        assert persisted.event_id == 1
        assert persisted.level == 4
        assert persisted.channel == "Microsoft-Windows-Sysmon/Operational"
        assert persisted.computer == "WORKSTATION-01"
        assert persisted.task == 1
        assert persisted.recorded_at == recorded
        assert persisted.message_xml["schema_version"] == 1
        assert (
            persisted.message_xml["EventData"]["ProcessName"]
            == "C:\\Windows\\System32\\notepad.exe"
        )
        assert persisted.raw_xml.startswith("<Event")
        assert persisted.record_number == 12345
        assert persisted.created_at is not None  # server_default fired


@pytest.mark.asyncio
async def test_windows_event_record_nullable_fields():
    """Confirm level / channel / computer / task / message_xml / raw_xml /
    record_number are all nullable per the model definition."""
    async with make_live_db() as db:
        project = Project(name="ε.2.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-nullable.bin", "b")
        db.add(firmware)
        await db.flush()

        recorded = datetime.datetime(2026, 5, 10, tzinfo=datetime.UTC)
        # Minimal event — only the NOT NULL columns populated.
        event = WindowsEventRecord(
            firmware_id=firmware.id,
            evtx_file_path="Windows/System32/winevt/Logs/Application.evtx",
            provider="Application",
            event_id=1000,
            recorded_at=recorded,
        )
        db.add(event)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsEventRecord).where(WindowsEventRecord.id == event.id)
            )
        ).scalar_one()

        assert persisted.level is None
        assert persisted.channel is None
        assert persisted.computer is None
        assert persisted.task is None
        assert persisted.message_xml is None
        assert persisted.raw_xml is None
        assert persisted.record_number is None


@pytest.mark.asyncio
async def test_windows_event_record_multiple_per_firmware():
    """A single firmware can carry many event records (no UNIQUE constraint
    on firmware_id alone — operators expect millions of events per firmware)."""
    async with make_live_db() as db:
        project = Project(name="ε.2.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "c")
        db.add(firmware)
        await db.flush()

        for i in range(5):
            db.add(
                WindowsEventRecord(
                    firmware_id=firmware.id,
                    evtx_file_path=f"path/{i}.evtx",
                    provider="Test",
                    event_id=i,
                    recorded_at=datetime.datetime(2026, 5, 10, tzinfo=datetime.UTC),
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsEventRecord).where(
                    WindowsEventRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 5
        assert {r.event_id for r in rows} == {0, 1, 2, 3, 4}
