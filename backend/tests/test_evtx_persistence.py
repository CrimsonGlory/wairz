"""Phase ε.2.B — tier-1 live canary for per-event persistence wire-up.

Tests `_build_event_record` + `_extract_event_fields` (regex extractors).
Live canary against `_do_evtx_walk_run` is harder (needs python-evtx mocked
or a real .evtx fixture) — covered by ε.1.b's existing
`test_evtx_real_firmware.py` tier-1 tests + the new tier-1 test here for
the ORM round-trip.

Per Rule #39 — tier-1 tests call the INNER runner only; never the outer.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEventRecord
from app.services.evtx_service import (
    _build_event_record,
    _extract_event_fields,
    _relativize_evtx_path,
)
from tests._live_db import make_live_db


# Synthetic EVTX event XML covering the canonical Windows EventLog schema.
_SYSMON_1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2025-12-25T13:47:21.1234567Z"/>
    <EventRecordID>4242</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WORKSTATION-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{abc-123}</Data>
    <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
    <Data Name="CommandLine">notepad.exe foo.txt</Data>
  </EventData>
</Event>"""

_SECURITY_4624_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <TimeCreated SystemTime="2025-12-25T14:00:00Z"/>
    <EventRecordID>4243</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="LogonType">2</Data>
  </EventData>
</Event>"""


def test_extract_event_fields_sysmon():
    f = _extract_event_fields(_SYSMON_1_XML)
    assert f["provider"] == "Microsoft-Windows-Sysmon"
    assert f["event_id"] == 1
    assert f["level"] == 4
    assert f["task"] == 1
    assert f["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert f["computer"] == "WORKSTATION-01"
    assert f["recorded_at"].year == 2025
    assert f["recorded_at"].month == 12
    assert f["recorded_at"].day == 25
    assert f["recorded_at"].tzinfo is not None


def test_extract_event_fields_security_4624():
    f = _extract_event_fields(_SECURITY_4624_XML)
    assert f["provider"] == "Microsoft-Windows-Security-Auditing"
    assert f["event_id"] == 4624
    assert f["level"] == 0
    assert f["channel"] == "Security"
    assert f["recorded_at"].year == 2025


def test_extract_event_fields_malformed_returns_partial():
    # No Provider name → returns dict missing 'provider'
    f = _extract_event_fields("<Event><System><EventID>4625</EventID></System></Event>")
    assert "provider" not in f
    assert f["event_id"] == 4625


def test_extract_event_fields_completely_malformed():
    f = _extract_event_fields("not xml at all")
    assert f == {}


def test_relativize_evtx_path_under_root(tmp_path):
    root = str(tmp_path)
    full = str(tmp_path / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx")
    assert (
        _relativize_evtx_path(full, [root])
        == "Windows/System32/winevt/Logs/Security.evtx"
    )


def test_relativize_evtx_path_outside_root_falls_back():
    # Path doesn't match any root → basename fallback
    out = _relativize_evtx_path("/some/orphan/path/foo.evtx", ["/different/root"])
    assert out == "foo.evtx"


def test_build_event_record_returns_none_when_minimum_fields_missing():
    # Missing TimeCreated → can't construct a record (recorded_at is NOT NULL)
    rec = {"raw_xml": "<Event><System><Provider Name=\"X\"/><EventID>1</EventID></System></Event>", "record_num": 1}
    assert _build_event_record(uuid.uuid4(), "test.evtx", rec) is None


def test_build_event_record_constructs_full_row():
    rec = {"raw_xml": _SYSMON_1_XML, "record_num": 4242}
    fwid = uuid.uuid4()
    obj = _build_event_record(fwid, "Logs/Sysmon.evtx", rec)
    assert obj is not None
    assert obj.firmware_id == fwid
    assert obj.evtx_file_path == "Logs/Sysmon.evtx"
    assert obj.provider == "Microsoft-Windows-Sysmon"
    assert obj.event_id == 1
    assert obj.level == 4
    assert obj.task == 1
    assert obj.channel == "Microsoft-Windows-Sysmon/Operational"
    assert obj.computer == "WORKSTATION-01"
    assert obj.record_number == 4242
    assert obj.message_xml["schema_version"] == 1
    assert "raw_xml_preview" in obj.message_xml
    assert obj.raw_xml == _SYSMON_1_XML


@pytest.mark.asyncio
async def test_build_event_record_persists_via_orm():
    """Rule #35b live canary — _build_event_record's output round-trips
    through the ORM cleanly. Tier-1 only (no _do_evtx_walk_run; that needs
    python-evtx, covered by ε.1.b real-firmware tier-1 tests)."""
    async with make_live_db() as db:
        project = Project(name="ε.2.B canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id,
            original_filename="canary.bin",
            storage_path="/tmp/canary.bin",
            sha256="d" * 64,
            file_size=1024,
        )
        db.add(firmware)
        await db.flush()

        # Build + persist 2 events from synthetic XML.
        for rec in [
            {"raw_xml": _SYSMON_1_XML, "record_num": 4242},
            {"raw_xml": _SECURITY_4624_XML, "record_num": 4243},
        ]:
            obj = _build_event_record(firmware.id, "Logs/Test.evtx", rec)
            assert obj is not None
            db.add(obj)
        await db.commit()

        # SELECT back and verify provider/EID extracted correctly.
        rows = (
            await db.execute(
                select(WindowsEventRecord)
                .where(WindowsEventRecord.firmware_id == firmware.id)
                .order_by(WindowsEventRecord.event_id)
            )
        ).scalars().all()
        assert len(rows) == 2
        assert rows[0].provider == "Microsoft-Windows-Sysmon"
        assert rows[0].event_id == 1
        assert rows[1].provider == "Microsoft-Windows-Security-Auditing"
        assert rows[1].event_id == 4624
        assert rows[0].message_xml["schema_version"] == 1
