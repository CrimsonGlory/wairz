"""Phase η.A.D — tier-1 tests for the MFT hidden-content + timestomp
classifier and the FindingService emit hook.

Mirrors test_finding_service_lnk_emit.py shape — pure-classifier unit
tests + a make_live_db()-backed live canary verifying the emit hook
persists Finding rows with the correct heuristic-driven confidence
tier:

ADS-hidden:
- HIGH: ADS size > 16 KB (ProcessHollower / Pegasus / AV-evasion)
- MEDIUM: ADS size 1 KB – 16 KB

Timestomp ($SI mtime < $FN mtime):
- HIGH: all four $SI/$FN pairs inverted (timestomp.exe full rewrite)
- MEDIUM: single-pair inversion
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    Finding,
    Firmware,
    Project,
    WindowsMftRecord,
)
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_mft_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_mft_records_ads_streams,
    _stamp_windows_mft_records_target_metadata,
)
from tests._live_db import make_live_db


# ── Pure classifier tests (no DB) ────────────────────────────────────────────


def _healthy_timestamps() -> dict:
    """Return $SI/$FN timestamps with $SI ≥ $FN (healthy file shape)."""
    return {
        "si_creation_ns": 132_000_000_000_000_000,
        "si_last_modification_ns": 132_500_000_000_000_000,
        "si_last_change_ns": 132_500_000_000_000_000,
        "si_last_access_ns": 133_000_000_000_000_000,
        "fn_creation_ns": 132_000_000_000_000_000,
        "fn_last_modification_ns": 132_000_000_000_000_000,
        "fn_last_change_ns": 132_000_000_000_000_000,
        "fn_last_access_ns": 132_000_000_000_000_000,
    }


def test_classify_no_signal_healthy_file_emits_nothing():
    """Healthy file (no ADS, $SI ≥ $FN) → 0 drafts."""
    drafts = classify_mft_findings(
        filename="cmd.exe",
        source_path="images/disk.raw",
        full_path="Windows\\System32\\cmd.exe",
        ads_streams=[],
        **_healthy_timestamps(),
    )
    assert drafts == []


def test_classify_zone_identifier_below_threshold_emits_nothing():
    """Zone.Identifier ~130 bytes is below the 1 KB benign-tag
    threshold → no ADS-hidden draft."""
    drafts = classify_mft_findings(
        filename="installer.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Downloads\\installer.exe",
        ads_streams=[{"name": "Zone.Identifier", "size": 130, "data_size": 130}],
        **_healthy_timestamps(),
    )
    assert drafts == []


def test_classify_medium_tier_ads_payload_1k_to_16k():
    """ADS size 8 KB → MEDIUM windows_mft_ads_hidden_content draft."""
    drafts = classify_mft_findings(
        filename="installer.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Downloads\\installer.exe",
        ads_streams=[{"name": "hidden", "size": 8192, "data_size": 8192}],
        **_healthy_timestamps(),
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_mft_ads_hidden_content"
    assert d.confidence == Confidence.medium
    assert d.severity == Severity.medium
    assert "MEDIUM" in d.evidence
    assert "T1564.004" in d.description


def test_classify_high_tier_ads_payload_above_16k():
    """ADS size 64 KB → HIGH windows_mft_ads_hidden_content draft
    (ProcessHollower / Pegasus / generic AV-evasion drop pattern)."""
    drafts = classify_mft_findings(
        filename="installer.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Downloads\\installer.exe",
        ads_streams=[{"name": "hidden", "size": 64 * 1024, "data_size": 64 * 1024}],
        **_healthy_timestamps(),
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_mft_ads_hidden_content"
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "HIGH" in d.evidence


def test_classify_multiple_ads_each_emits_separately():
    """A record with both Zone.Identifier (tag) and a hidden payload
    → 1 draft (only the >1 KB stream emits)."""
    drafts = classify_mft_findings(
        filename="installer.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Downloads\\installer.exe",
        ads_streams=[
            {"name": "Zone.Identifier", "size": 130, "data_size": 130},
            {"name": "hidden", "size": 32 * 1024, "data_size": 32 * 1024},
        ],
        **_healthy_timestamps(),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_mft_ads_hidden_content"
    assert drafts[0].confidence == Confidence.high


def test_classify_medium_tier_timestomp_single_pair_inversion():
    """$SI mtime < $FN mtime but creation/change/access matching →
    MEDIUM windows_mft_timestomping draft."""
    drafts = classify_mft_findings(
        filename="dropper.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Temp\\dropper.exe",
        ads_streams=[],
        si_creation_ns=132_000_000_000_000_000,
        si_last_modification_ns=131_900_000_000_000_000,  # SI mtime older
        si_last_change_ns=132_000_000_000_000_000,
        si_last_access_ns=132_000_000_000_000_000,
        fn_creation_ns=132_000_000_000_000_000,
        fn_last_modification_ns=132_500_000_000_000_000,  # FN mtime newer
        fn_last_change_ns=132_000_000_000_000_000,
        fn_last_access_ns=132_000_000_000_000_000,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_mft_timestomping"
    assert d.confidence == Confidence.medium
    assert d.severity == Severity.medium
    assert "single-pair" in d.evidence
    assert "T1070.006" in d.description


def test_classify_high_tier_timestomp_full_tuple_rewrite():
    """All four $SI timestamps strictly older than all four $FN →
    HIGH windows_mft_timestomping draft (timestomp.exe-style rewrite)."""
    drafts = classify_mft_findings(
        filename="dropper.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Temp\\dropper.exe",
        ads_streams=[],
        si_creation_ns=131_500_000_000_000_000,
        si_last_modification_ns=131_500_000_000_000_000,
        si_last_change_ns=131_500_000_000_000_000,
        si_last_access_ns=131_500_000_000_000_000,
        fn_creation_ns=132_900_000_000_000_000,
        fn_last_modification_ns=132_900_000_000_000_000,
        fn_last_change_ns=132_900_000_000_000_000,
        fn_last_access_ns=132_900_000_000_000_000,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_mft_timestomping"
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "ALL FOUR" in d.evidence


def test_classify_timestomp_missing_si_emits_nothing():
    """Partial timestamp tuple (SI mtime is None) → no timestomp draft."""
    drafts = classify_mft_findings(
        filename="cmd.exe",
        source_path="images/disk.raw",
        full_path="Windows\\System32\\cmd.exe",
        ads_streams=[],
        si_creation_ns=None,
        si_last_modification_ns=None,  # missing
        si_last_change_ns=None,
        si_last_access_ns=None,
        fn_creation_ns=132_000_000_000_000_000,
        fn_last_modification_ns=132_000_000_000_000_000,
        fn_last_change_ns=132_000_000_000_000_000,
        fn_last_access_ns=132_000_000_000_000_000,
    )
    assert drafts == []


def test_classify_combined_ads_plus_timestomp_emits_both():
    """A record with BOTH a hidden ADS and a timestomp signal →
    2 drafts (one of each source)."""
    drafts = classify_mft_findings(
        filename="evil.exe",
        source_path="images/disk.raw",
        full_path="Users\\victim\\Downloads\\evil.exe",
        ads_streams=[{"name": "hidden", "size": 32 * 1024, "data_size": 32 * 1024}],
        si_creation_ns=131_500_000_000_000_000,
        si_last_modification_ns=131_500_000_000_000_000,
        si_last_change_ns=131_500_000_000_000_000,
        si_last_access_ns=131_500_000_000_000_000,
        fn_creation_ns=132_900_000_000_000_000,
        fn_last_modification_ns=132_900_000_000_000_000,
        fn_last_change_ns=132_900_000_000_000_000,
        fn_last_access_ns=132_900_000_000_000_000,
    )
    sources = {d.source for d in drafts}
    assert sources == {
        "windows_mft_ads_hidden_content",
        "windows_mft_timestomping",
    }


def test_classify_handles_orphan_with_no_full_path():
    """Orphan record (full_path is None) still emits drafts with
    '(orphan)' substitution in the evidence."""
    drafts = classify_mft_findings(
        filename="orphan.exe",
        source_path="images/disk.raw",
        full_path=None,
        ads_streams=[{"name": "hidden", "size": 4096, "data_size": 4096}],
        **_healthy_timestamps(),
    )
    assert len(drafts) == 1
    assert "(orphan)" in drafts[0].evidence


# ── Live canary: FindingService.emit_mft_findings_from_walk ──────────────────


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_emit_mft_findings_persists_confidence_tier_live_canary():
    """Rule #35b live canary — round-trip a high-tier timestomp +
    hidden ADS record through the emit hook, then SELECT to confirm
    confidence persists on the Finding row."""
    async with make_live_db() as db:
        project = Project(name="η.A.D emit canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-emit.bin", "e")
        db.add(firmware)
        await db.flush()

        # Build a single record with BOTH a hidden ADS payload and
        # timestomp inversion across all four pairs (HIGH on both).
        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/disk.raw",
            segment_number=200,
            in_use=True,
            is_directory=False,
            full_path="Users\\victim\\Downloads\\evil.exe",
            filename="evil.exe",
            file_size=51200,
            si_creation_ns=131_500_000_000_000_000,
            si_last_modification_ns=131_500_000_000_000_000,
            si_last_change_ns=131_500_000_000_000_000,
            si_last_access_ns=131_500_000_000_000_000,
            fn_creation_ns=132_900_000_000_000_000,
            fn_last_modification_ns=132_900_000_000_000_000,
            fn_last_change_ns=132_900_000_000_000_000,
            fn_last_access_ns=132_900_000_000_000_000,
            ads_streams=_stamp_windows_mft_records_ads_streams([
                {"name": "hidden", "size": 64 * 1024, "data_size": 64 * 1024},
            ]),
            target_metadata=_stamp_windows_mft_records_target_metadata({}),
        )
        db.add(record)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_mft_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        # 2 drafts emitted: ADS-hidden HIGH + timestomp HIGH.
        assert len(emitted) == 2
        sources = {f.source for f in emitted}
        assert sources == {
            "windows_mft_ads_hidden_content",
            "windows_mft_timestomping",
        }

        # Rule #35b: SELECT persisted findings + inspect confidence.
        persisted = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(persisted) == 2

        for f in persisted:
            # Both should be HIGH confidence per the tier classifier.
            assert f.confidence == "high", (
                f"finding {f.source} should be HIGH confidence, got {f.confidence}"
            )
            assert f.severity == "high"


@pytest.mark.asyncio
async def test_emit_mft_findings_skips_healthy_record():
    """Healthy file (no ADS, $SI ≥ $FN) → 0 emits."""
    async with make_live_db() as db:
        project = Project(name="η.A.D healthy")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-healthy.bin", "h")
        db.add(firmware)
        await db.flush()

        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/disk.raw",
            segment_number=100,
            in_use=True,
            is_directory=False,
            full_path="Windows\\System32\\cmd.exe",
            filename="cmd.exe",
            file_size=289_792,
            si_creation_ns=132_000_000_000_000_000,
            si_last_modification_ns=132_500_000_000_000_000,
            si_last_change_ns=132_500_000_000_000_000,
            si_last_access_ns=133_000_000_000_000_000,
            fn_creation_ns=132_000_000_000_000_000,
            fn_last_modification_ns=132_000_000_000_000_000,
            fn_last_change_ns=132_000_000_000_000_000,
            fn_last_access_ns=132_000_000_000_000_000,
            ads_streams=[],
            target_metadata=_stamp_windows_mft_records_target_metadata({}),
        )
        db.add(record)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_mft_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []


@pytest.mark.asyncio
async def test_emit_mft_findings_zone_identifier_only_emits_nothing():
    """A file with ONLY Zone.Identifier (MOTW tag) → 0 emits."""
    async with make_live_db() as db:
        project = Project(name="η.A.D zone-id only")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-zone.bin", "z")
        db.add(firmware)
        await db.flush()

        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/disk.raw",
            segment_number=101,
            in_use=True,
            is_directory=False,
            full_path="Users\\victim\\Downloads\\legit_install.exe",
            filename="legit_install.exe",
            file_size=2_048_000,
            si_creation_ns=132_700_000_000_000_000,
            si_last_modification_ns=132_700_000_000_000_000,
            si_last_change_ns=132_700_000_000_000_000,
            si_last_access_ns=132_700_000_000_000_000,
            fn_creation_ns=132_700_000_000_000_000,
            fn_last_modification_ns=132_700_000_000_000_000,
            fn_last_change_ns=132_700_000_000_000_000,
            fn_last_access_ns=132_700_000_000_000_000,
            ads_streams=_stamp_windows_mft_records_ads_streams([
                {"name": "Zone.Identifier", "size": 130, "data_size": 130},
            ]),
            target_metadata=_stamp_windows_mft_records_target_metadata({}),
        )
        db.add(record)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_mft_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []


@pytest.mark.asyncio
async def test_emit_mft_findings_no_walk_rows_emits_nothing():
    """Firmware with NO WindowsMftRecord rows → 0 emits."""
    async with make_live_db() as db:
        project = Project(name="η.A.D no rows")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-norows.bin", "n")
        db.add(firmware)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_mft_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []
