"""Phase θ.B.E — tier-1 tests for the WMI persistence classifier and
the FindingService emit hook.

Mirrors test_finding_service_bcd_emit.py shape — pure-classifier unit
tests + a make_live_db()-backed live canary (Rule #35b) verifying the
emit hook persists Finding rows with the correct heuristic-driven
confidence tier:

- HIGH — ActiveScriptEventConsumer OR encoded-PowerShell pattern
  (Qakbot signature). Severity: high.
- MEDIUM — CommandLineEventConsumer + script-host invocation.
  LOLBin-via-WMI shape. Severity: medium.
- LOW — baseline non-benign FilterToConsumerBinding. Severity: low.
- 0 drafts — benign bindings (BVTConsumer-BVTFilter, SCM Event Log).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    Finding,
    Firmware,
    Project,
    WindowsWmiEvent,
)
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_wmi_findings,
)
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


# ── Pure classifier tests ───────────────────────────────────────────────────


def test_classify_wmi_benign_emits_zero_drafts():
    """Benign BVTConsumer-BVTFilter binding → 0 drafts (skipped from
    Finding emission)."""
    drafts = classify_wmi_findings(
        binding_id="BVTConsumer-BVTFilter",
        filter_name="BVTFilter",
        filter_query=None,
        consumer_name="BVTConsumer",
        consumer_type="CommandLineEventConsumer",
        consumer_payload=None,
        source_path="OBJECTS.DATA",
        probably_benign=True,
    )
    assert drafts == []


def test_classify_wmi_active_script_high_severity():
    """ActiveScriptEventConsumer → HIGH severity finding regardless
    of payload content (in-process VBScript/JScript = max impact)."""
    drafts = classify_wmi_findings(
        binding_id="Malware-MaliciousTimer",
        filter_name="MaliciousTimer",
        filter_query=(
            "SELECT * FROM __InstanceModificationEvent WITHIN 60"
        ),
        consumer_name="Malware",
        consumer_type="ActiveScriptEventConsumer",
        consumer_payload=[{
            "consumer_type": "ActiveScriptEventConsumer",
            "arguments": 'Set obj = CreateObject("WScript.Shell")',
            "other": "VBScript",
        }],
        source_path="Windows/System32/wbem/Repository/OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert "ActiveScriptEventConsumer" in draft.evidence
    assert "T1546.003" in draft.description


def test_classify_wmi_encoded_powershell_high_severity():
    """CommandLineEventConsumer + encoded-PowerShell → HIGH (the
    Qakbot tradecraft shape)."""
    drafts = classify_wmi_findings(
        binding_id="Qakbot-PeriodicTimer",
        filter_name="PeriodicTimer",
        filter_query="SELECT * FROM __TimerEvent",
        consumer_name="Qakbot",
        consumer_type="CommandLineEventConsumer",
        consumer_payload=[{
            "consumer_type": "CommandLineEventConsumer",
            "arguments": "powershell.exe -EncodedCommand QQBBAEEA=",
            "other": "",
        }],
        source_path="Windows/System32/wbem/Repository/OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert "encoded-PowerShell" in draft.evidence


def test_classify_wmi_active_script_plus_encoded_ps_maximum_high():
    """ActiveScript AND encoded-PS → still HIGH, evidence reflects
    both signals."""
    drafts = classify_wmi_findings(
        binding_id="MaxImpact-Filter",
        filter_name="Filter",
        filter_query=None,
        consumer_name="MaxImpact",
        consumer_type="ActiveScriptEventConsumer",
        consumer_payload=[{
            "consumer_type": "ActiveScriptEventConsumer",
            "arguments": (
                'eval("powershell.exe -enc QQBB")'
            ),
            "other": "",
        }],
        source_path="OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    # Evidence should mention BOTH signals.
    assert "ActiveScript" in draft.evidence
    assert "maximum" in draft.evidence.lower() or "encoded" in draft.evidence.lower()


def test_classify_wmi_cmdline_script_host_medium_severity():
    """CommandLineEventConsumer + script-host invocation but no
    encoded-PS → MEDIUM (LOLBin-via-WMI shape)."""
    drafts = classify_wmi_findings(
        binding_id="LolBin-Filter",
        filter_name="Filter",
        filter_query="SELECT * FROM __TimerEvent",
        consumer_name="LolBin",
        consumer_type="CommandLineEventConsumer",
        consumer_payload=[{
            "consumer_type": "CommandLineEventConsumer",
            "arguments": "wscript.exe c:\\malware.vbs",
            "other": "",
        }],
        source_path="OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.medium
    assert draft.severity == Severity.medium
    assert "LOLBin" in draft.evidence or "script-host" in draft.evidence.lower()


def test_classify_wmi_baseline_low_severity():
    """Non-benign CommandLineEventConsumer without script-host and
    without encoded-PS → LOW baseline."""
    drafts = classify_wmi_findings(
        binding_id="Custom-Filter",
        filter_name="Filter",
        filter_query=None,
        consumer_name="Custom",
        consumer_type="CommandLineEventConsumer",
        consumer_payload=[{
            "consumer_type": "CommandLineEventConsumer",
            "arguments": "c:\\custom-app.exe",  # not a script-host
            "other": "",
        }],
        source_path="OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.low
    assert draft.severity == Severity.low
    assert "baseline" in draft.evidence.lower()


def test_classify_wmi_log_file_consumer_low_severity():
    """LogFileEventConsumer (non-script consumer type) → LOW
    baseline."""
    drafts = classify_wmi_findings(
        binding_id="LogFile-Filter",
        filter_name="Filter",
        filter_query=None,
        consumer_name="LogFile",
        consumer_type="LogFileEventConsumer",
        consumer_payload=[{
            "consumer_type": "LogFileEventConsumer",
            "arguments": "c:\\audit.log",
            "other": "Event occurred",
        }],
        source_path="OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    assert drafts[0].confidence == Confidence.low


def test_classify_wmi_empty_payload_low_severity():
    """Non-benign binding with no consumer payload extracted → LOW
    baseline."""
    drafts = classify_wmi_findings(
        binding_id="Mystery-Filter",
        filter_name="Filter",
        filter_query=None,
        consumer_name="Mystery",
        consumer_type="Unknown",
        consumer_payload=None,
        source_path="OBJECTS.DATA",
        probably_benign=False,
    )
    assert len(drafts) == 1
    assert drafts[0].confidence == Confidence.low


# ── FindingService.emit_wmi_findings_from_walk live canary ──────────────────


@pytest.mark.asyncio
async def test_emit_wmi_findings_from_walk_persists_high_tier():
    """Rule #35b live canary — round-trip a HIGH-tier WMI binding
    through the emit hook and confirm Finding row carries
    confidence=high + source=windows_wmi_persistence."""
    async with make_live_db() as db:
        project = Project(name="θ.B.E HIGH canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-high.bin", "h")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path=(
                "Windows/System32/wbem/Repository/OBJECTS.DATA"
            ),
            binding_id="Malware-MaliciousTimer",
            filter_name="MaliciousTimer",
            filter_query=(
                "SELECT * FROM __InstanceModificationEvent WITHIN 60"
            ),
            consumer_name="Malware",
            consumer_type="ActiveScriptEventConsumer",
            consumer_payload=_stamp_windows_wmi_events_consumer_payload([
                {
                    "consumer_type": "ActiveScriptEventConsumer",
                    "arguments": (
                        'Set obj = CreateObject("WScript.Shell")'
                    ),
                    "other": "VBScript",
                },
            ]),
            anomaly_flags=_stamp_windows_wmi_events_anomaly_flags({
                "encoded_powershell": False,
                "script_host_invocation": False,
                "active_script_consumer": True,
                "non_benign_binding": True,
                "high_severity": True,
            }),
            fingerprint_sha256="a" * 64,
            probably_benign=False,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_wmi_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1

        # Round-trip — confirm Finding row persists correctly.
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.source == "windows_wmi_persistence"
        assert f.confidence == Confidence.high
        assert f.severity == Severity.high
        assert "ActiveScript" in f.evidence


@pytest.mark.asyncio
async def test_emit_wmi_findings_from_walk_skips_benign():
    """Benign BVT binding → 0 Finding rows emitted."""
    async with make_live_db() as db:
        project = Project(name="θ.B.E benign canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-bvt.bin", "b")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="BVTConsumer-BVTFilter",
            filter_name="BVTFilter",
            consumer_name="BVTConsumer",
            consumer_type="CommandLineEventConsumer",
            probably_benign=True,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_wmi_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert emitted == []

        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_emit_wmi_findings_from_walk_medium_tier():
    """CommandLineEventConsumer + script-host → MEDIUM finding."""
    async with make_live_db() as db:
        project = Project(name="θ.B.E MEDIUM canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-med.bin", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="LolBin-Filter",
            filter_name="Filter",
            consumer_name="LolBin",
            consumer_type="CommandLineEventConsumer",
            consumer_payload=_stamp_windows_wmi_events_consumer_payload([
                {
                    "consumer_type": "CommandLineEventConsumer",
                    "arguments": "cscript.exe c:\\malware.vbs",
                    "other": "",
                },
            ]),
            probably_benign=False,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_wmi_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1

        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.confidence == Confidence.medium
        assert f.severity == Severity.medium


@pytest.mark.asyncio
async def test_emit_wmi_findings_from_walk_mixed_bindings():
    """A firmware with 3 bindings (HIGH ActiveScript + MEDIUM cmdline
    + LOW baseline + 1 benign) → 3 Finding rows emitted, benign
    skipped. Confirms the emit hook iterates correctly."""
    async with make_live_db() as db:
        project = Project(name="θ.B.E mixed canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-mixed.bin", "x")
        db.add(firmware)
        await db.flush()

        # HIGH
        db.add(WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="ActiveScript-High",
            filter_name="High",
            consumer_name="AS",
            consumer_type="ActiveScriptEventConsumer",
            probably_benign=False,
        ))
        # MEDIUM
        db.add(WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="CmdLine-Med",
            filter_name="Med",
            consumer_name="CL",
            consumer_type="CommandLineEventConsumer",
            consumer_payload=_stamp_windows_wmi_events_consumer_payload([
                {
                    "consumer_type": "CommandLineEventConsumer",
                    "arguments": "wscript.exe foo.vbs",
                    "other": "",
                },
            ]),
            probably_benign=False,
        ))
        # LOW
        db.add(WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="Custom-Low",
            filter_name="Low",
            consumer_name="C",
            consumer_type="LogFileEventConsumer",
            probably_benign=False,
        ))
        # BENIGN — skipped
        db.add(WindowsWmiEvent(
            firmware_id=firmware.id,
            source_path="OBJECTS.DATA",
            binding_id="BVTConsumer-BVTFilter",
            filter_name="BVTFilter",
            consumer_name="BVTConsumer",
            consumer_type="CommandLineEventConsumer",
            probably_benign=True,
        ))
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_wmi_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        # 3 emitted; 1 benign skipped.
        assert len(emitted) == 3

        # Confirm tier distribution.
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        confidences = sorted(r.confidence for r in rows)
        assert confidences == [
            Confidence.high,
            Confidence.low,
            Confidence.medium,
        ]
