"""Phase η.C.D — tier-1 tests for the LNK abnormal-target classifier
and the FindingService emit hook.

Mirrors test_finding_service_scheduled_task_emit.py shape — pure-
classifier unit tests + a make_live_db()-backed live canary verifying
the emit hook persists Finding rows with the correct heuristic-driven
confidence tier (HIGH on script-host + encoded-PS / MEDIUM on
non-Microsoft target / LOW baseline).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    Finding,
    Firmware,
    Project,
    WindowsLnkRecord,
)
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_lnk_abnormal_target_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_lnk_records_target_metadata,
)
from tests._live_db import make_live_db

# ── Pure classifier tests (no DB) ────────────────────────────────────────────


def test_classify_high_tier_script_host_plus_encoded_powershell_qakbot_pattern():
    """target_path = cmd.exe + arguments contain -EncodedCommand →
    HIGH confidence + high severity (Qakbot pattern)."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="malicious_update.lnk",
        source_path=(
            "Users/dustin/AppData/Roaming/Microsoft/Windows/Recent/"
            "malicious_update.lnk"
        ),
        target_path=r"C:\Windows\System32\cmd.exe",
        working_directory=r"%TEMP%",
        arguments=(
            "/c powershell.exe -NoProfile -WindowStyle Hidden "
            "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        ),
        description="Critical System Update",
        show_command="SW_HIDE",
        hotkey=None,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert draft.source == "windows_lnk_abnormal_target"
    assert "Qakbot" in draft.description or "cobalt-strike" in draft.description
    assert "T1547.009" in draft.description
    assert "HIGH" in draft.evidence


def test_classify_high_tier_powershell_target_with_iex():
    """target_path = powershell.exe + arguments contain IEX → HIGH tier."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="hidden.lnk",
        source_path=r"Users/dustin/Desktop/hidden.lnk",
        target_path=r"C:\Windows\System32\powershell.exe",
        working_directory=None,
        arguments="-NoProfile -c IEX (Get-Content C:\\Users\\Public\\stage.ps1)",
        description=None,
        show_command="SW_HIDE",
        hotkey=None,
    )
    assert len(drafts) == 1
    assert drafts[0].confidence == Confidence.high


def test_classify_medium_tier_non_microsoft_target():
    """Non-Microsoft target_path → MEDIUM confidence + medium severity.
    Pure benign target with no encoded-PS args."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="user_tool.lnk",
        source_path=(
            "Users/dustin/AppData/Roaming/Microsoft/Windows/Start Menu/"
            "Programs/user_tool.lnk"
        ),
        target_path=r"D:\Tools\user_tool.exe",
        working_directory=r"D:\Tools",
        arguments=None,
        description="User Custom Tool",
        show_command="SW_SHOWNORMAL",
        hotkey=None,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.medium
    assert draft.severity == Severity.medium
    assert "non-Microsoft target" in draft.description


def test_classify_low_tier_microsoft_explorer_baseline():
    """Microsoft-prefixed target_path + no encoded-PS args → LOW
    (baseline review-candidate). Severity: info."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="Windows Explorer.lnk",
        source_path=(
            "Users/dustin/AppData/Roaming/Microsoft/Windows/Start Menu/"
            "Programs/Windows Explorer.lnk"
        ),
        target_path=r"C:\Windows\explorer.exe",
        working_directory=r"C:\Windows",
        arguments=None,
        description="Windows Explorer",
        show_command="SW_SHOWNORMAL",
        hotkey=None,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.low
    assert draft.severity == Severity.info
    assert "baseline" in draft.description.lower()


def test_classify_low_tier_no_target_path_baseline():
    """Missing target_path falls into LOW (baseline) tier — non-MS
    classifier requires a target_path for MEDIUM."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="empty.lnk",
        source_path=r"Users/dustin/Desktop/empty.lnk",
        target_path=None,
        working_directory=None,
        arguments=None,
        description=None,
        show_command=None,
        hotkey=None,
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.confidence == Confidence.low
    assert draft.severity == Severity.info


def test_classify_empty_lnk_filename_yields_no_drafts():
    """Defensive boundary — empty lnk_filename → empty list."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="",
        source_path="x",
        target_path=None,
        working_directory=None,
        arguments=None,
        description=None,
        show_command=None,
        hotkey=None,
    )
    assert drafts == []


def test_classify_microsoft_cmd_with_encoded_ps_still_high():
    """Microsoft-prefixed cmd.exe target + encoded-PS args → HIGH tier
    (script-host check uses BASENAME, not is_microsoft_target)."""
    drafts = classify_lnk_abnormal_target_findings(
        lnk_filename="trojan.lnk",
        source_path=r"Users/dustin/Recent/trojan.lnk",
        target_path=r"C:\Windows\System32\cmd.exe",  # MS-prefixed
        working_directory=None,
        arguments=(
            "/c powershell.exe -EncodedCommand SQBFAFgA"
        ),
        description=None,
        show_command="SW_HIDE",
        hotkey=None,
    )
    assert len(drafts) == 1
    assert drafts[0].confidence == Confidence.high
    assert drafts[0].severity == Severity.high


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
async def test_emit_lnk_findings_three_tiers_persisted():
    """Live canary: 3 LNKs (HIGH / MEDIUM / LOW tier) → 3 Finding rows
    with the correct confidence tier preserved through the emit hook
    (NOT collapsed to Confidence.low like emit_srum / emit_prefetch)."""
    async with make_live_db() as db:
        project = Project(name="η.C.D emit canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "lnk-emit-canary.bin", "L")
        db.add(firmware)
        await db.flush()

        # HIGH tier — script-host target + encoded-PS Qakbot pattern.
        db.add(
            WindowsLnkRecord(
                firmware_id=firmware.id,
                source_path=(
                    "Users/dustin/AppData/Roaming/Microsoft/Windows/Recent/"
                    "malicious_update.lnk"
                ),
                lnk_filename="malicious_update.lnk",
                target_path=r"C:\Windows\System32\cmd.exe",
                working_directory=r"%TEMP%",
                arguments=(
                    "/c powershell.exe -EncodedCommand "
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
                ),
                description="Critical System Update",
                show_command="SW_HIDE",
                hotkey=None,
                target_metadata=_stamp_windows_lnk_records_target_metadata(
                    {"data": {"description": "Critical System Update"}}
                ),
            )
        )

        # MEDIUM tier — non-Microsoft target.
        db.add(
            WindowsLnkRecord(
                firmware_id=firmware.id,
                source_path=(
                    "Users/dustin/AppData/Roaming/Microsoft/Windows/"
                    "Start Menu/Programs/user_tool.lnk"
                ),
                lnk_filename="user_tool.lnk",
                target_path=r"D:\Tools\user_tool.exe",
                working_directory=r"D:\Tools",
                arguments=None,
                description="User Custom Tool",
                show_command="SW_SHOWNORMAL",
                hotkey=None,
                target_metadata=_stamp_windows_lnk_records_target_metadata(
                    {"data": {"description": "User Custom Tool"}}
                ),
            )
        )

        # LOW tier — Microsoft Explorer baseline.
        db.add(
            WindowsLnkRecord(
                firmware_id=firmware.id,
                source_path=(
                    "Users/dustin/AppData/Roaming/Microsoft/Windows/"
                    "Start Menu/Programs/Windows Explorer.lnk"
                ),
                lnk_filename="Windows Explorer.lnk",
                target_path=r"C:\Windows\explorer.exe",
                working_directory=r"C:\Windows",
                arguments=None,
                description="Windows Explorer",
                show_command="SW_SHOWNORMAL",
                hotkey=None,
                target_metadata=_stamp_windows_lnk_records_target_metadata(
                    {"data": {"description": "Windows Explorer"}}
                ),
            )
        )
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_lnk_findings_from_walk(
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
            r.source == "windows_lnk_abnormal_target" for r in rows
        )

        confidences = {r.title: r.confidence for r in rows}
        assert confidences["LNK: malicious_update.lnk"] == "high"
        assert confidences["LNK: user_tool.lnk"] == "medium"
        assert confidences["LNK: Windows Explorer.lnk"] == "low"

        # Severity mirrors the tier per the classifier.
        severities = {r.title: r.severity for r in rows}
        assert severities["LNK: malicious_update.lnk"] == "high"
        assert severities["LNK: user_tool.lnk"] == "medium"
        assert severities["LNK: Windows Explorer.lnk"] == "info"
