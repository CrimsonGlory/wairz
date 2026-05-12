"""Phase θ.A.D — tier-1 tests for the BCD suspicious-path + testsigning
classifier and the FindingService emit hook.

Mirrors test_finding_service_mft_emit.py shape — pure-classifier unit
tests + a make_live_db()-backed live canary verifying the emit hook
persists Finding rows with the correct heuristic-driven confidence
tier:

Suspicious path:
- HIGH: suspicious_path AND (non_microsoft_description OR
  testsigning_enabled). Strong bootkit signal.
- MEDIUM: suspicious_path alone (could be legitimate non-Microsoft OS).

TestSigning:
- HIGH: testsigning_enabled AND (no_integrity_checks OR nx_disabled).
  Multiple security-policy bits flipped — BYOVD precursor.
- MEDIUM: testsigning_enabled alone (could be developer / driver-debug).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    Finding,
    Firmware,
    Project,
    WindowsBcdEntry,
)
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_bcd_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_bcd_entries_anomaly_flags,
    _stamp_windows_bcd_entries_custom_elements,
)
from tests._live_db import make_live_db


def _clean_anomaly_flags() -> dict:
    """Return anomaly flags where no anomaly is raised (healthy boot entry)."""
    return {
        "suspicious_path": False,
        "non_microsoft_description": False,
        "testsigning_enabled": False,
        "no_integrity_checks": False,
        "nx_disabled": False,
        "is_default_boot": True,
    }


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Pure classifier tests (no DB) ────────────────────────────────────────────


def test_classify_no_signal_healthy_entry_emits_nothing():
    """Healthy boot entry (all flags False) → 0 drafts."""
    drafts = classify_bcd_findings(
        object_guid="{12345678-1234-1234-1234-123456789abc}",
        source_path="Boot/BCD",
        description="Windows 10",
        image_path="\\Windows\\System32\\winload.efi",
        anomaly_flags=_clean_anomaly_flags(),
    )
    assert drafts == []


def test_classify_medium_tier_suspicious_path_alone():
    """suspicious_path=True, no other flags → 1 MEDIUM
    windows_bcd_suspicious_path draft."""
    flags = _clean_anomaly_flags()
    flags["suspicious_path"] = True
    drafts = classify_bcd_findings(
        object_guid="{ubuntu-1234-1234-1234-123456789abc}",
        source_path="EFI/Microsoft/Boot/BCD",
        description="Ubuntu",
        image_path="\\EFI\\Ubuntu\\grubx64.efi",
        anomaly_flags=flags,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_bcd_suspicious_path"
    assert d.confidence == Confidence.medium
    assert d.severity == Severity.medium
    assert "MEDIUM" in d.evidence
    assert "T1542.003" in d.description


def test_classify_high_tier_suspicious_path_plus_non_microsoft_description():
    """suspicious_path + non_microsoft_description → HIGH."""
    flags = _clean_anomaly_flags()
    flags["suspicious_path"] = True
    flags["non_microsoft_description"] = True
    drafts = classify_bcd_findings(
        object_guid="{deadbeef-1234-5678-9abc-def012345678}",
        source_path="EFI/Microsoft/Boot/BCD",
        description="Adversary Bootkit",
        image_path="\\Users\\Public\\evil.efi",
        anomaly_flags=flags,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_bcd_suspicious_path"
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "HIGH" in d.evidence


def test_classify_high_tier_suspicious_path_plus_testsigning():
    """suspicious_path + testsigning_enabled (without non-MS desc) → HIGH."""
    flags = _clean_anomaly_flags()
    flags["suspicious_path"] = True
    flags["testsigning_enabled"] = True
    drafts = classify_bcd_findings(
        object_guid="{guid}",
        source_path="Boot/BCD",
        description=None,  # no description at all
        image_path="\\Foo\\bar.efi",
        anomaly_flags=flags,
    )
    # 2 drafts: suspicious_path HIGH + testsigning_enabled MEDIUM
    sources = {d.source for d in drafts}
    assert sources == {
        "windows_bcd_suspicious_path",
        "windows_bcd_testsigning_enabled",
    }
    sp_draft = next(
        d for d in drafts if d.source == "windows_bcd_suspicious_path"
    )
    assert sp_draft.confidence == Confidence.high


def test_classify_medium_tier_testsigning_alone():
    """testsigning_enabled=True only → MEDIUM
    windows_bcd_testsigning_enabled draft."""
    flags = _clean_anomaly_flags()
    flags["testsigning_enabled"] = True
    drafts = classify_bcd_findings(
        object_guid="{dev-1234-1234-1234-123456789abc}",
        source_path="Boot/BCD",
        description="Windows 10 (Driver Debug)",
        image_path="\\Windows\\System32\\winload.efi",
        anomaly_flags=flags,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_bcd_testsigning_enabled"
    assert d.confidence == Confidence.medium
    assert d.severity == Severity.medium
    assert "MEDIUM" in d.evidence


def test_classify_high_tier_testsigning_plus_no_integrity():
    """testsigning_enabled + no_integrity_checks → HIGH."""
    flags = _clean_anomaly_flags()
    flags["testsigning_enabled"] = True
    flags["no_integrity_checks"] = True
    drafts = classify_bcd_findings(
        object_guid="{byovd-1234-1234-1234-123456789abc}",
        source_path="Boot/BCD",
        description="Windows 10",
        image_path="\\Windows\\System32\\winload.efi",
        anomaly_flags=flags,
    )
    # 1 draft: testsigning_enabled HIGH (suspicious_path is False)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_bcd_testsigning_enabled"
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "HIGH" in d.evidence


def test_classify_high_tier_testsigning_plus_nx_disabled():
    """testsigning_enabled + nx_disabled → HIGH."""
    flags = _clean_anomaly_flags()
    flags["testsigning_enabled"] = True
    flags["nx_disabled"] = True
    drafts = classify_bcd_findings(
        object_guid="{guid}",
        source_path="Boot/BCD",
        description="Windows 10",
        image_path="\\Windows\\System32\\winload.efi",
        anomaly_flags=flags,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_bcd_testsigning_enabled"
    assert d.confidence == Confidence.high


def test_classify_combined_suspicious_path_plus_testsigning_emits_both():
    """A row with BOTH suspicious_path AND testsigning_enabled (and
    cross-flags) emits 2 drafts (one of each source)."""
    flags = {
        "suspicious_path": True,
        "non_microsoft_description": True,
        "testsigning_enabled": True,
        "no_integrity_checks": True,
        "nx_disabled": True,
        "is_default_boot": False,
    }
    drafts = classify_bcd_findings(
        object_guid="{deadbeef}",
        source_path="EFI/Microsoft/Boot/BCD",
        description="Bootkit",
        image_path="\\Users\\evil.efi",
        anomaly_flags=flags,
    )
    sources = {d.source for d in drafts}
    assert sources == {
        "windows_bcd_suspicious_path",
        "windows_bcd_testsigning_enabled",
    }
    # Both should be HIGH (the cross-flags trigger HIGH on both classifiers)
    for d in drafts:
        assert d.confidence == Confidence.high


def test_classify_handles_orphan_with_no_description():
    """Entry with no description / image_path still emits drafts when
    flags are raised."""
    flags = _clean_anomaly_flags()
    flags["testsigning_enabled"] = True
    drafts = classify_bcd_findings(
        object_guid="{orphan-guid}",
        source_path="Boot/BCD",
        description=None,
        image_path=None,
        anomaly_flags=flags,
    )
    assert len(drafts) == 1
    assert "(unset)" in drafts[0].evidence


# ── Live canary: FindingService.emit_bcd_findings_from_walk ──────────────────


@pytest.mark.asyncio
async def test_emit_bcd_findings_persists_confidence_tier_live_canary():
    """Rule #35b live canary — round-trip a high-tier bootkit-shaped
    entry through the emit hook, then SELECT to confirm confidence
    persists on the Finding row."""
    async with make_live_db() as db:
        project = Project(name="θ.A.D emit canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-emit.bin", "e")
        db.add(firmware)
        await db.flush()

        # Build a bootkit-shaped entry with ALL anomaly flags raised.
        entry = WindowsBcdEntry(
            firmware_id=firmware.id,
            source_path="EFI/Microsoft/Boot/BCD",
            object_guid="{deadbeef-1234-5678-9abc-def012345678}",
            object_type=0x10200003,
            description="Adversary Bootkit",
            image_path="\\Users\\Public\\evil.efi",
            gpt_partition_guid=None,
            gpt_disk_guid=None,
            testsigning=True,
            no_integrity_checks=True,
            nx_policy=2,
            custom_elements=_stamp_windows_bcd_entries_custom_elements([]),
            anomaly_flags=_stamp_windows_bcd_entries_anomaly_flags({
                "suspicious_path": True,
                "non_microsoft_description": True,
                "testsigning_enabled": True,
                "no_integrity_checks": True,
                "nx_disabled": True,
                "is_default_boot": False,
            }),
            last_modified_ns=None,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_bcd_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        # 2 drafts emitted: suspicious_path HIGH + testsigning HIGH.
        assert len(emitted) == 2
        sources = {f.source for f in emitted}
        assert sources == {
            "windows_bcd_suspicious_path",
            "windows_bcd_testsigning_enabled",
        }

        # Rule #35b: SELECT persisted findings + inspect confidence.
        persisted = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(persisted) == 2

        for f in persisted:
            assert f.confidence == "high", (
                f"finding {f.source} should be HIGH confidence, got {f.confidence}"
            )
            assert f.severity == "high"


@pytest.mark.asyncio
async def test_emit_bcd_findings_skips_clean_entry():
    """A healthy entry (no anomaly flags) → 0 emits."""
    async with make_live_db() as db:
        project = Project(name="θ.A.D clean")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-clean.bin", "c")
        db.add(firmware)
        await db.flush()

        entry = WindowsBcdEntry(
            firmware_id=firmware.id,
            source_path="Boot/BCD",
            object_guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            object_type=0x10100002,
            description="Windows Boot Manager",
            image_path="\\bootmgr",
            testsigning=False,
            no_integrity_checks=False,
            nx_policy=0,
            custom_elements=_stamp_windows_bcd_entries_custom_elements([]),
            anomaly_flags=_stamp_windows_bcd_entries_anomaly_flags(
                _clean_anomaly_flags()
            ),
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_bcd_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []


@pytest.mark.asyncio
async def test_emit_bcd_findings_medium_tier_alone_persists():
    """Entry with ONLY suspicious_path → 1 MEDIUM emit."""
    async with make_live_db() as db:
        project = Project(name="θ.A.D medium-only")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-medium.bin", "m")
        db.add(firmware)
        await db.flush()

        # Ubuntu-shaped entry — suspicious path but Microsoft-naming
        # absent (which sets non_microsoft_description=True ALSO — but
        # the operator may legitimately have Ubuntu installed).
        # To test pure MEDIUM, we set only suspicious_path=True.
        flags = _clean_anomaly_flags()
        flags["suspicious_path"] = True
        entry = WindowsBcdEntry(
            firmware_id=firmware.id,
            source_path="EFI/Microsoft/Boot/BCD",
            object_guid="{ubuntu-1234-1234-1234-123456789abc}",
            object_type=0x10200003,
            description="Ubuntu Linux (recognised by description)",
            image_path="\\EFI\\Ubuntu\\grubx64.efi",
            custom_elements=_stamp_windows_bcd_entries_custom_elements([]),
            anomaly_flags=_stamp_windows_bcd_entries_anomaly_flags(flags),
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_bcd_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1
        assert emitted[0].source == "windows_bcd_suspicious_path"

        persisted = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(persisted) == 1
        assert persisted[0].confidence == "medium"


@pytest.mark.asyncio
async def test_emit_bcd_findings_no_walk_rows_emits_nothing():
    """Firmware with NO WindowsBcdEntry rows → 0 emits."""
    async with make_live_db() as db:
        project = Project(name="θ.A.D no rows")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-norows.bin", "n")
        db.add(firmware)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_bcd_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []
