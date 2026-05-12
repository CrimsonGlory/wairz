"""Tests for the Phase θ.E.D MBR/VBR boot-sector finding-emit
classifier + ``FindingService.emit_mbr_vbr_findings_from_walk``.

Covers:
- ``classify_mbr_vbr_findings`` — pure classifier returns 0 or 1
  drafts per row with the expected tier mapping (HIGH/MEDIUM) per
  the rule below.
- ``emit_mbr_vbr_findings_from_walk`` — Rule #35b live canaries via
  make_live_db: walk-state-machine round-trip persists Finding rows
  with the correct source / confidence / severity / file_path.

Tier mapping:
- HIGH — windows_mbr_bootkit (MBR with known_bootkit_match
  populated — TDL4 / Petya / Mebroot / etc., always HIGH).
- HIGH — windows_vbr_anomaly with known_bootkit_match populated
  (named VBR bootkit variant).
- MEDIUM — windows_vbr_anomaly with bootcode_signature_match=NULL
  AND >=2 anomaly flags raised (modified VBR without a named
  bootkit; supply-chain compromise candidate).
- (Skipped) — clean MBR/VBR (known-good signature match, no
  bootkit, no anomalies).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, Project, WindowsMbrVbrSector
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    _SOURCE_MBR_BOOTKIT,
    _SOURCE_VBR_ANOMALY,
    FindingService,
    classify_mbr_vbr_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_mbr_vbr_sectors_anomaly_flags,
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


def _clean_anomaly_flags() -> dict:
    return {
        "non_zero_padding": False,
        "unexpected_partition_table": False,
        "non_standard_jmp": False,
        "non_zero_disk_signature": True,
        "is_mbr": True,
        "is_vbr": False,
    }


def _dirty_vbr_anomaly_flags() -> dict:
    """Anomaly flags with 2 raised — meets the MEDIUM threshold."""
    return {
        "non_zero_padding": True,
        "unexpected_partition_table": False,
        "non_standard_jmp": True,
        "non_zero_disk_signature": False,
        "is_mbr": False,
        "is_vbr": True,
    }


# ── classify_mbr_vbr_findings — pure classifier tests ──────────────────────


def test_classify_clean_mbr_emits_zero():
    """Clean MBR with known-good signature, no bootkit → 0 drafts."""
    drafts = classify_mbr_vbr_findings(
        file_path="windows.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="a" * 64,
        sector_size=512,
        bootcode_signature_match="windows_10_mbr",
        known_bootkit_match=None,
        anomaly_flags=_clean_anomaly_flags(),
    )
    assert drafts == []


def test_classify_mbr_bootkit_emits_high():
    """MBR with known_bootkit_match → 1 HIGH windows_mbr_bootkit draft."""
    drafts = classify_mbr_vbr_findings(
        file_path="infected.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="b" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match="petya_mbr",
        anomaly_flags={
            "non_zero_padding": True,
            "non_standard_jmp": True,
            "is_mbr": True,
        },
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.source == _SOURCE_MBR_BOOTKIT
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert "petya_mbr" in draft.title
    assert "petya_mbr" in draft.evidence


def test_classify_vbr_bootkit_emits_high():
    """VBR with known_bootkit_match → 1 HIGH windows_vbr_anomaly draft."""
    drafts = classify_mbr_vbr_findings(
        file_path="infected.img",
        sector_offset=1_048_576,
        sector_kind="vbr_ntfs",
        sector_sha256="c" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match="mebroot_vbr",
        anomaly_flags={
            "non_standard_jmp": True,
            "is_vbr": True,
        },
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.source == _SOURCE_VBR_ANOMALY
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high
    assert "mebroot_vbr" in draft.evidence


def test_classify_vbr_modified_emits_medium():
    """VBR with bootcode_signature_match=NULL AND 2+ anomaly flags →
    1 MEDIUM windows_vbr_anomaly draft."""
    drafts = classify_mbr_vbr_findings(
        file_path="suspect.img",
        sector_offset=1_048_576,
        sector_kind="vbr_fat32",
        sector_sha256="d" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match=None,
        anomaly_flags=_dirty_vbr_anomaly_flags(),
    )
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.source == _SOURCE_VBR_ANOMALY
    assert draft.confidence == Confidence.medium
    assert draft.severity == Severity.medium


def test_classify_vbr_only_one_anomaly_emits_zero():
    """VBR with bootcode_signature_match=NULL but only 1 anomaly flag
    → 0 drafts (below MEDIUM threshold)."""
    drafts = classify_mbr_vbr_findings(
        file_path="suspect.img",
        sector_offset=1_048_576,
        sector_kind="vbr_fat32",
        sector_sha256="e" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match=None,
        anomaly_flags={
            "non_zero_padding": True,
            "is_vbr": True,
        },
    )
    assert drafts == []


def test_classify_vbr_with_known_good_signature_emits_zero():
    """VBR with known-good signature match → 0 drafts (clean VBR)."""
    drafts = classify_mbr_vbr_findings(
        file_path="windows.img",
        sector_offset=1_048_576,
        sector_kind="vbr_ntfs",
        sector_sha256="f" * 64,
        sector_size=512,
        bootcode_signature_match="windows_7_vbr_ntfs",
        known_bootkit_match=None,
        anomaly_flags={"is_vbr": True},
    )
    assert drafts == []


def test_classify_unknown_sector_kind_emits_zero():
    """Unknown sector kind → 0 drafts (no classifier applies)."""
    drafts = classify_mbr_vbr_findings(
        file_path="weird.img",
        sector_offset=512,
        sector_kind="unknown",
        sector_sha256="1" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match=None,
        anomaly_flags={
            "non_zero_padding": True,
            "non_standard_jmp": True,
        },
    )
    assert drafts == []


def test_classify_mbr_clean_with_anomalies_emits_zero():
    """MBR with no bootkit but with anomalies → 0 drafts (the
    mbr_bootkit classifier requires a named bootkit hit; anomalies
    alone aren't enough for MBR — only for VBR)."""
    drafts = classify_mbr_vbr_findings(
        file_path="suspect.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="2" * 64,
        sector_size=512,
        bootcode_signature_match=None,
        known_bootkit_match=None,
        anomaly_flags={
            "non_zero_padding": True,
            "non_standard_jmp": True,
            "unexpected_partition_table": True,
            "is_mbr": True,
        },
    )
    assert drafts == []


# ── emit_mbr_vbr_findings_from_walk — Rule #35b live canaries ──────────────


@pytest.mark.asyncio
async def test_emit_mbr_bootkit_persists_high():
    """Live canary: persist a TDL4 MBR sector + call the emit hook;
    verify a HIGH-confidence windows_mbr_bootkit Finding row lands."""
    async with make_live_db() as db:
        project = Project(name="θ.E.D mbr-bootkit emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "infected.img", "i")
        db.add(firmware)
        await db.flush()

        sector = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="infected.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="3" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match="tdl4_mbr",
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": True,
                "non_standard_jmp": True,
                "is_mbr": True,
            }),
            fingerprint_sha256="4" * 64,
        )
        db.add(sector)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_mbr_vbr_findings_from_walk(
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
        r = rows[0]
        assert r.source == "windows_mbr_bootkit"
        assert r.confidence == "high"
        assert r.severity == "high"
        assert r.file_path == "infected.img"
        assert "tdl4_mbr" in r.evidence


@pytest.mark.asyncio
async def test_emit_vbr_anomaly_medium_persists():
    """Live canary: persist a modified-VBR sector (no bootcode match,
    multiple anomalies) + call the emit hook; verify a MEDIUM-
    confidence windows_vbr_anomaly Finding row lands."""
    async with make_live_db() as db:
        project = Project(name="θ.E.D vbr-medium emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "suspect.img", "s")
        db.add(firmware)
        await db.flush()

        sector = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="suspect.img",
            sector_offset=1_048_576,
            sector_kind="vbr_fat32",
            sector_sha256="5" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": True,
                "non_standard_jmp": True,
                "is_vbr": True,
            }),
            fingerprint_sha256="6" * 64,
        )
        db.add(sector)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_mbr_vbr_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        r = rows[0]
        assert r.source == "windows_vbr_anomaly"
        assert r.confidence == "medium"
        assert r.severity == "medium"


@pytest.mark.asyncio
async def test_emit_clean_mbr_vbr_emits_zero():
    """Live canary: a clean MBR + VBR pair → 0 Finding rows emitted."""
    async with make_live_db() as db:
        project = Project(name="θ.E.D clean emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.img", "w")
        db.add(firmware)
        await db.flush()

        mbr_row = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="windows.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="7" * 64,
            sector_size=512,
            bootcode_signature_match="windows_10_mbr",
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags(
                _clean_anomaly_flags()
            ),
            fingerprint_sha256="8" * 64,
        )
        vbr_row = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="windows.img",
            sector_offset=1_048_576,
            sector_kind="vbr_ntfs",
            sector_sha256="9" * 64,
            sector_size=512,
            bootcode_signature_match="windows_7_vbr_ntfs",
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "is_vbr": True,
            }),
            fingerprint_sha256="a" * 64,
        )
        db.add_all([mbr_row, vbr_row])
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_mbr_vbr_findings_from_walk(
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
async def test_emit_mixed_state_persists_subset():
    """Live canary: 1 clean MBR + 1 bootkit MBR + 1 modified VBR
    → 2 Finding rows (the clean one is skipped)."""
    async with make_live_db() as db:
        project = Project(name="θ.E.D mixed emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "multi.img", "m")
        db.add(firmware)
        await db.flush()

        clean_mbr = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="clean.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="b" * 64,
            sector_size=512,
            bootcode_signature_match="windows_10_mbr",
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags(
                _clean_anomaly_flags()
            ),
            fingerprint_sha256="c" * 64,
        )
        bootkit_mbr = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="infected.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="d" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match="petya_mbr",
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": True,
                "is_mbr": True,
            }),
            fingerprint_sha256="e" * 64,
        )
        modified_vbr = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="suspect.img",
            sector_offset=1_048_576,
            sector_kind="vbr_ntfs",
            sector_sha256="0" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags(
                _dirty_vbr_anomaly_flags()
            ),
            fingerprint_sha256="f" * 64,
        )
        db.add_all([clean_mbr, bootkit_mbr, modified_vbr])
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_mbr_vbr_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 2
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        sources = {r.source for r in rows}
        assert sources == {
            "windows_mbr_bootkit", "windows_vbr_anomaly"
        }
        # Verify HIGH + MEDIUM tier preserved.
        confidences = {r.source: r.confidence for r in rows}
        assert confidences["windows_mbr_bootkit"] == "high"
        assert confidences["windows_vbr_anomaly"] == "medium"
