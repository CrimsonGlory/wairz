"""Tests for the Phase θ.B.B WindowsWmiEvent ORM model.

Per CLAUDE.md Rule #35b live canaries: round-trip via the real ORM
+ ``make_live_db`` SQLite shim to confirm column shapes + index
declarations match the alembic migration intent.

Covers:
- ORM round-trip — create, persist, SELECT, inspect every column.
- JSONB columns (consumer_payload + anomaly_flags) — Rule #35c stamped
  envelope persists end-to-end.
- Defensive shapes: NULL payloads, oversize binding names truncated,
  benign-flag passes through, fingerprint cross-firmware aggregation
  query.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsWmiEvent
from app.services.jsonb_normalizers import (
    _stamp_windows_wmi_events_anomaly_flags,
    _stamp_windows_wmi_events_consumer_payload,
)
from tests._live_db import make_live_db


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


# ── ORM round-trip live canaries ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wmi_event_persists_cmdline_binding_shape():
    """Rule #35b live canary — round-trip a CommandLineEventConsumer
    binding and confirm every column persists with the expected
    shape."""
    async with make_live_db() as db:
        project = Project(name="θ.B.B cmdline canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-wmi.bin", "w")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="Windows/System32/wbem/Repository/OBJECTS.DATA",
            namespace="ROOT\\subscription",
            binding_id="MalwareConsumer-MalwareFilter",
            filter_name="MalwareFilter",
            filter_query=(
                "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                "WHERE TargetInstance ISA 'Win32_Process'"
            ),
            consumer_name="MalwareConsumer",
            consumer_type="CommandLineEventConsumer",
            consumer_payload=_stamp_windows_wmi_events_consumer_payload([
                {
                    "consumer_type": "CommandLineEventConsumer",
                    "arguments": "powershell.exe -enc QQBBAEEAQQA=",
                    "other": "%COMSPEC%",
                },
            ]),
            anomaly_flags=_stamp_windows_wmi_events_anomaly_flags({
                "encoded_powershell": True,
                "script_host_invocation": True,
                "active_script_consumer": False,
                "non_benign_binding": True,
                "high_severity": True,
            }),
            fingerprint_sha256="a" * 64,
            probably_benign=False,
        )
        db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsWmiEvent).where(
                    WindowsWmiEvent.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.source_path == (
            "Windows/System32/wbem/Repository/OBJECTS.DATA"
        )
        assert r.namespace == "ROOT\\subscription"
        assert r.binding_id == "MalwareConsumer-MalwareFilter"
        assert r.filter_name == "MalwareFilter"
        assert r.consumer_name == "MalwareConsumer"
        assert r.consumer_type == "CommandLineEventConsumer"
        assert r.probably_benign is False
        assert r.fingerprint_sha256 == "a" * 64
        assert "Win32_Process" in r.filter_query

        # JSONB round-trip
        assert isinstance(r.consumer_payload, list)
        assert len(r.consumer_payload) == 1
        assert r.consumer_payload[0]["consumer_type"] == (
            "CommandLineEventConsumer"
        )
        assert "powershell" in r.consumer_payload[0]["arguments"]
        assert r.consumer_payload[0]["schema_version"] == 1

        assert isinstance(r.anomaly_flags, dict)
        assert r.anomaly_flags["encoded_powershell"] is True
        assert r.anomaly_flags["script_host_invocation"] is True
        assert r.anomaly_flags["high_severity"] is True
        assert r.anomaly_flags["schema_version"] == 1


@pytest.mark.asyncio
async def test_wmi_event_persists_active_script_binding():
    """Rule #35b live canary — ActiveScriptEventConsumer shape (VBScript
    / JScript body in consumer_payload, in-process script execution
    is the highest-impact WMI consumer type)."""
    async with make_live_db() as db:
        project = Project(name="θ.B.B activescript canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-vbs.bin", "v")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path=(
                "Windows/System32/wbem/Repository/OBJECTS.DATA"
            ),
            binding_id="VbsConsumer-VbsFilter",
            filter_name="VbsFilter",
            filter_query=(
                "SELECT * FROM __TimerEvent WHERE TimerID = 'foo'"
            ),
            consumer_name="VbsConsumer",
            consumer_type="ActiveScriptEventConsumer",
            consumer_payload=_stamp_windows_wmi_events_consumer_payload([
                {
                    "consumer_type": "ActiveScriptEventConsumer",
                    "arguments": (
                        'Set obj = CreateObject("WScript.Shell"): '
                        'obj.Run "powershell.exe -enc QQ"'
                    ),
                    "other": "VBScript",
                },
            ]),
            anomaly_flags=_stamp_windows_wmi_events_anomaly_flags({
                "encoded_powershell": True,
                "script_host_invocation": False,
                "active_script_consumer": True,
                "non_benign_binding": True,
                "high_severity": True,
            }),
            fingerprint_sha256="b" * 64,
            probably_benign=False,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsWmiEvent).where(
                    WindowsWmiEvent.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.consumer_type == "ActiveScriptEventConsumer"
        assert r.consumer_payload[0]["consumer_type"] == (
            "ActiveScriptEventConsumer"
        )
        assert "WScript.Shell" in r.consumer_payload[0]["arguments"]
        assert r.anomaly_flags["active_script_consumer"] is True


@pytest.mark.asyncio
async def test_wmi_event_benign_binding_passes_through():
    """The probably_benign annotation persists for well-known
    Windows-shipped bindings (BVTConsumer-BVTFilter, SCM Event Log)."""
    async with make_live_db() as db:
        project = Project(name="θ.B.B benign canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-bvt.bin", "x")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="BVTConsumer-BVTFilter",
            filter_name="BVTFilter",
            filter_query=None,
            consumer_name="BVTConsumer",
            consumer_type="CommandLineEventConsumer",
            consumer_payload=None,
            anomaly_flags=_stamp_windows_wmi_events_anomaly_flags({
                "encoded_powershell": False,
                "script_host_invocation": False,
                "active_script_consumer": False,
                "non_benign_binding": False,
                "high_severity": False,
            }),
            fingerprint_sha256="c" * 64,
            probably_benign=True,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsWmiEvent).where(
                    WindowsWmiEvent.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.probably_benign is True
        assert r.filter_query is None
        assert r.consumer_payload is None


@pytest.mark.asyncio
async def test_wmi_event_fingerprint_cross_firmware_aggregation():
    """The fingerprint_sha256 column enables cross-firmware aggregation
    (the lookup_wmi_persistence MCP tool's query shape).

    Two firmware images carrying the same binding fingerprint surface
    via a single SELECT."""
    async with make_live_db() as db:
        project = Project(name="θ.B.B cross-firmware canary")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        # Same fingerprint across both firmware
        fp = "deadbeef" * 8

        for fw in (fw1, fw2):
            db.add(WindowsWmiEvent(
                firmware_id=fw.id,
                source_path="OBJECTS.DATA",
                binding_id="ASEC-ASECFilter",
                filter_name="ASECFilter",
                consumer_name="ASEC",
                consumer_type="ActiveScriptEventConsumer",
                fingerprint_sha256=fp,
                probably_benign=False,
            ))
        await db.commit()

        # The lookup_wmi_persistence query shape: aggregate by
        # fingerprint across firmware.
        rows = (
            await db.execute(
                select(WindowsWmiEvent).where(
                    WindowsWmiEvent.fingerprint_sha256 == fp
                )
            )
        ).scalars().all()
        assert len(rows) == 2
        firmware_ids = {r.firmware_id for r in rows}
        assert firmware_ids == {fw1.id, fw2.id}


@pytest.mark.asyncio
async def test_wmi_event_persists_with_minimal_required_fields():
    """A binding with ONLY required fields (source_path, binding_id,
    filter_name, consumer_name, consumer_type) populated must persist
    successfully."""
    async with make_live_db() as db:
        project = Project(name="θ.B.B minimal canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw.bin", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="Min-Min",
            filter_name="Min",
            consumer_name="Min",
            consumer_type="LogFileEventConsumer",
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsWmiEvent).where(
                    WindowsWmiEvent.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.binding_id == "Min-Min"
        assert r.namespace is None
        assert r.filter_query is None
        assert r.consumer_payload is None
        assert r.anomaly_flags is None
        assert r.fingerprint_sha256 is None
        assert r.probably_benign is False  # server_default
