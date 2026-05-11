"""Phase η.B.D — tier-1 tests for the Scheduled Task persistence
classifier and the FindingService emit hook.

Mirrors test_finding_service_powershell_emit.py shape — pure-classifier
unit tests + a make_live_db()-backed live canary verifying the emit
hook persists Finding rows with the correct heuristic-driven
confidence tier (HIGH on encoded-PS / MEDIUM on HighestAvailable +
non-system Author / LOW baseline).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    Finding,
    Firmware,
    Project,
    WindowsScheduledTask,
)
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_scheduled_task_persistence_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_scheduled_tasks_actions,
    _stamp_windows_scheduled_tasks_principal,
    _stamp_windows_scheduled_tasks_settings,
    _stamp_windows_scheduled_tasks_triggers,
)
from tests._live_db import make_live_db

# ── Pure classifier tests (no DB) ────────────────────────────────────────────


def test_classify_high_tier_encoded_powershell_qakbot_pattern():
    """Action with encoded-PowerShell pattern → HIGH confidence + high
    severity (Qakbot pattern)."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="PerformUpdate",
        task_uri="\\Updater\\PerformUpdate",
        author="SuspiciousVendor",
        run_level="HighestAvailable",
        run_as_user="S-1-5-18",
        triggers=[{"type": "CalendarTrigger", "enabled": True}],
        actions=[
            {
                "type": "Exec",
                "command": "powershell.exe",
                "arguments": "-NoProfile -EncodedCommand SQBFAFgA",
            }
        ],
        source_path="Windows/System32/Tasks/Updater/PerformUpdate",
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert draft.source == "windows_scheduled_task_persistence"
    assert "Qakbot pattern" in draft.description
    assert "Encoded-PS" in draft.evidence
    assert "HIGH" in draft.evidence


def test_classify_medium_tier_highest_available_plus_non_system_author():
    """HighestAvailable + non-system Author → MEDIUM confidence + medium
    severity."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="MyVendorService",
        task_uri="\\MyVendor\\MyVendorService",
        author="MyVendor Inc",
        run_level="HighestAvailable",
        run_as_user="S-1-5-18",
        triggers=[{"type": "BootTrigger", "enabled": True}],
        actions=[
            {
                "type": "Exec",
                "command": "C:\\Program Files\\MyVendor\\service.exe",
                "arguments": "--start",
            }
        ],
        source_path="Windows/System32/Tasks/MyVendor/MyVendorService",
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.medium
    assert draft.severity == Severity.medium
    assert "RunLevel=HighestAvailable" in draft.description
    assert "non-Microsoft Author" in draft.description


def test_classify_low_tier_microsoft_author_baseline():
    """Microsoft Corporation Author + HighestAvailable → LOW (system
    task, not privilege-escalation candidate). Severity: info."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="WinSAT",
        task_uri="\\Microsoft\\Windows\\Maintenance\\WinSAT",
        author="Microsoft Corporation",
        run_level="HighestAvailable",
        run_as_user="S-1-5-19",
        triggers=[{"type": "CalendarTrigger", "enabled": True}],
        actions=[
            {
                "type": "Exec",
                "command": "%windir%\\system32\\WinSAT.exe",
                "arguments": "formal",
            }
        ],
        source_path="Windows/System32/Tasks/Microsoft/Windows/Maintenance/WinSAT",
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.low
    assert draft.severity == Severity.info
    assert "baseline" in draft.description.lower()


def test_classify_low_tier_least_privilege_third_party_baseline():
    """Non-system Author but LeastPrivilege RunLevel → LOW (no
    privilege-escalation indicator)."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="OneDriveSync",
        task_uri="\\OneDriveSync",
        author="\\\\HOSTNAME\\enduser",
        run_level=None,  # LeastPrivilege default
        run_as_user="S-1-5-21-...",
        triggers=[{"type": "LogonTrigger", "enabled": True}],
        actions=[
            {
                "type": "Exec",
                "command": "C:\\Users\\enduser\\AppData\\Local\\OneDrive.exe",
                "arguments": None,
            }
        ],
        source_path="Windows/System32/Tasks/Microsoft/Windows/OneDriveSync",
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.low
    assert draft.severity == Severity.info


def test_classify_empty_task_name_yields_no_drafts():
    """Defensive boundary — empty task_name → empty list."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="",
        task_uri=None,
        author=None,
        run_level=None,
        run_as_user=None,
        triggers=[],
        actions=[],
        source_path="x",
    )
    assert drafts == []


def test_classify_encoded_ps_in_second_action_still_detected():
    """First action is benign, second action has encoded-PS → HIGH tier
    (any-action-match wins)."""
    drafts = classify_scheduled_task_persistence_findings(
        task_name="Multi",
        task_uri="\\Multi",
        author="ThirdParty",
        run_level="LeastPrivilege",
        run_as_user=None,
        triggers=[{"type": "TimeTrigger"}],
        actions=[
            {"type": "Exec", "command": "notepad.exe", "arguments": None},
            {
                "type": "Exec",
                "command": "powershell.exe",
                "arguments": "-enc YQBhAA==",
            },
        ],
        source_path="x",
    )
    assert len(drafts) == 1
    assert drafts[0].confidence == Confidence.high


# ── Live canary — emit method through real ORM (Rule #35b) ───────────────────


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


@pytest.mark.asyncio
async def test_emit_scheduled_task_findings_three_tiers_persisted():
    """Live canary: 3 tasks (HIGH / MEDIUM / LOW tier) → 3 Finding rows
    with the correct confidence tier preserved through the emit hook
    (NOT collapsed to Confidence.low like emit_srum / emit_prefetch)."""
    async with make_live_db() as db:
        project = Project(name="η.B.D emit canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "emit-canary.bin", "e")
        db.add(firmware)
        await db.flush()

        # HIGH tier — encoded-PS Qakbot pattern.
        db.add(
            WindowsScheduledTask(
                firmware_id=firmware.id,
                source_path="Windows/System32/Tasks/Updater/PerformUpdate",
                task_uri="\\Updater\\PerformUpdate",
                task_name="PerformUpdate",
                author="SuspiciousVendor",
                run_level="HighestAvailable",
                run_as_user="S-1-5-18",
                triggers=_stamp_windows_scheduled_tasks_triggers(
                    [{"type": "CalendarTrigger"}]
                ),
                actions=_stamp_windows_scheduled_tasks_actions(
                    [
                        {
                            "type": "Exec",
                            "command": "powershell.exe",
                            "arguments": "-EncodedCommand SQBFAFgA",
                        }
                    ]
                ),
                principal=_stamp_windows_scheduled_tasks_principal(
                    {"id": "Author"}
                ),
                settings=_stamp_windows_scheduled_tasks_settings(
                    {"Enabled": True}
                ),
            )
        )

        # MEDIUM tier — HighestAvailable + non-system Author.
        db.add(
            WindowsScheduledTask(
                firmware_id=firmware.id,
                source_path="Windows/System32/Tasks/MyVendor/Service",
                task_uri="\\MyVendor\\Service",
                task_name="Service",
                author="MyVendor Inc",
                run_level="HighestAvailable",
                run_as_user="S-1-5-18",
                triggers=_stamp_windows_scheduled_tasks_triggers(
                    [{"type": "BootTrigger"}]
                ),
                actions=_stamp_windows_scheduled_tasks_actions(
                    [
                        {
                            "type": "Exec",
                            "command": "C:\\Program Files\\MyVendor\\svc.exe",
                            "arguments": None,
                        }
                    ]
                ),
                principal=_stamp_windows_scheduled_tasks_principal(
                    {"id": "Author"}
                ),
                settings=_stamp_windows_scheduled_tasks_settings(
                    {"Enabled": True}
                ),
            )
        )

        # LOW tier — Microsoft system task baseline.
        db.add(
            WindowsScheduledTask(
                firmware_id=firmware.id,
                source_path="Windows/System32/Tasks/Microsoft/WinSAT",
                task_uri="\\Microsoft\\Windows\\Maintenance\\WinSAT",
                task_name="WinSAT",
                author="Microsoft Corporation",
                run_level="HighestAvailable",
                run_as_user="S-1-5-19",
                triggers=_stamp_windows_scheduled_tasks_triggers(
                    [{"type": "CalendarTrigger"}]
                ),
                actions=_stamp_windows_scheduled_tasks_actions(
                    [
                        {
                            "type": "Exec",
                            "command": "%windir%\\system32\\WinSAT.exe",
                            "arguments": "formal",
                        }
                    ]
                ),
                principal=_stamp_windows_scheduled_tasks_principal(
                    {"id": "S-1-5-19"}
                ),
                settings=_stamp_windows_scheduled_tasks_settings(
                    {"Enabled": True}
                ),
            )
        )
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_scheduled_task_findings_from_walk(
            project_id=project.id, firmware_id=firmware.id
        )
        await db.commit()

        assert len(emitted) == 3

        # Live canary: SELECT the persisted Finding rows and verify the
        # 3-tier confidence preserved (Rule #35b).
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(rows) == 3
        assert all(
            r.source == "windows_scheduled_task_persistence" for r in rows
        )

        confidences = {r.title: r.confidence for r in rows}
        assert (
            confidences["Scheduled Task: PerformUpdate"] == "high"
        )
        assert confidences["Scheduled Task: Service"] == "medium"
        assert confidences["Scheduled Task: WinSAT"] == "low"

        # Severity mirrors the tier per the classifier.
        severities = {r.title: r.severity for r in rows}
        assert severities["Scheduled Task: PerformUpdate"] == "high"
        assert severities["Scheduled Task: Service"] == "medium"
        assert severities["Scheduled Task: WinSAT"] == "info"
