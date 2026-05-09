"""Phase ζ.1 — tier-1 live canary for Amcache install-history Finding emission.

Tests `classify_amcache_install_findings` (pure function) + the full
`emit_amcache_findings_from_walk` round-trip through the ORM. Mirrors
γ.8's test_finding_service_pe_emit shape.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, Project, WindowsRegistryExtract
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.schemas.finding import Severity
from app.services.finding_service import (
    FindingService,
    classify_amcache_install_findings,
)
from tests._live_db import make_live_db

_AMCACHE_PARSED_TREE = {
    "schema_version": 1,
    "hive_type": "AmCache",
    "subkeys": [
        {
            "path": "Root\\InventoryApplicationFile\\notepad.exe|0123456789abcdef",
            "values": [
                {"name": "LowerCaseLongPath", "value": "c:\\windows\\system32\\notepad.exe"},
                {"name": "FileId", "value": "00000123456789abcdef0123456789abcdef0123"},
                {"name": "ProductName", "value": "Microsoft® Windows® Operating System"},
                {"name": "Publisher", "value": "Microsoft Corporation"},
                {"name": "Size", "value": 245760},
            ],
        },
        {
            "path": "Root\\InventoryApplicationFile\\suspicious.exe|deadbeef",
            "values": [
                {"name": "LowerCaseLongPath", "value": "c:\\users\\victim\\appdata\\local\\temp\\suspicious.exe"},
                {"name": "FileId", "value": "0000deadbeefdeadbeefdeadbeefdeadbeefdead"},
                {"name": "Publisher", "value": "(unknown)"},
                {"name": "Size", "value": 4096},
            ],
        },
        # Non-InventoryApplicationFile subkey — should be skipped
        {
            "path": "Root\\InventoryDeviceContainer\\foo",
            "values": [{"name": "DeviceId", "value": "ROOT_HUB"}],
        },
    ],
}


def test_classify_amcache_install_findings_extracts_two_entries():
    drafts = classify_amcache_install_findings(
        hive_path="Windows/AppCompat/Programs/Amcache.hve",
        hive_type="AmCache",
        parsed_tree=_AMCACHE_PARSED_TREE,
    )
    assert len(drafts) == 2
    titles = [d.title for d in drafts]
    assert "AmCache install record: notepad.exe" in titles
    assert "AmCache install record: suspicious.exe" in titles
    # All drafts are LOW severity (info per the helper's choice)
    for d in drafts:
        assert d.severity == Severity.info
        assert d.source == "windows_amcache_install"


def test_classify_amcache_install_findings_skips_non_amcache_hive():
    """Defensive: non-AmCache hives should produce zero drafts even if
    they happen to contain InventoryApplicationFile-shaped subkeys."""
    drafts = classify_amcache_install_findings(
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        parsed_tree=_AMCACHE_PARSED_TREE,
    )
    assert drafts == []


def test_classify_amcache_install_findings_handles_none_parsed_tree():
    drafts = classify_amcache_install_findings(
        hive_path="x",
        hive_type="AmCache",
        parsed_tree=None,
    )
    assert drafts == []


def test_classify_amcache_install_findings_handles_wrong_type():
    drafts = classify_amcache_install_findings(
        hive_path="x",
        hive_type="AmCache",
        parsed_tree="not a dict",
    )
    assert drafts == []


def test_classify_amcache_install_findings_extracts_sha1_strips_padding():
    """FileId in AmCache is 4-zero-padded SHA1 — helper should strip."""
    drafts = classify_amcache_install_findings(
        hive_path="x",
        hive_type="AmCache",
        parsed_tree=_AMCACHE_PARSED_TREE,
    )
    notepad_draft = next(d for d in drafts if "notepad.exe" in d.title)
    # Padding stripped: "0000<40-char-sha1>" → "<40-char-sha1>"
    assert "0123456789abcdef0123456789abcdef0123" in notepad_draft.evidence
    # Padding not present in evidence
    assert "00000123" not in notepad_draft.evidence


@pytest.mark.asyncio
async def test_emit_amcache_findings_from_walk_round_trip():
    """Rule #35b live canary — emit_amcache_findings_from_walk persists
    Finding rows with source=windows_amcache_install via the real ORM."""
    async with make_live_db() as db:
        project = Project(name="ζ.1 amcache canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id,
            original_filename="canary.bin",
            storage_path="/tmp/canary.bin",
            sha256="z" * 64,
            file_size=1024,
        )
        db.add(firmware)
        await db.flush()
        blob = HardwareFirmwareBlob(
            firmware_id=firmware.id,
            blob_path="amcache_blob",
            blob_sha256="b" * 64,
            file_size=4096,
            category="windows",
            format="hive",
            detection_source="manual",
        )
        db.add(blob)
        await db.flush()
        # Two registry extracts: one AmCache (should emit 2 findings),
        # one SOFTWARE (should be skipped).
        amcache = WindowsRegistryExtract(
            blob_id=blob.id,
            hive_path="Windows/AppCompat/Programs/Amcache.hve",
            hive_type="AmCache",
            walk_status="completed",
            parsed_tree=_AMCACHE_PARSED_TREE,
        )
        software = WindowsRegistryExtract(
            blob_id=blob.id,
            hive_path="Windows/System32/config/SOFTWARE",
            hive_type="SOFTWARE",
            walk_status="completed",
            parsed_tree={"subkeys": [{"path": "Root\\InventoryApplicationFile\\x", "values": [{"name": "x", "value": "x"}]}]},
        )
        db.add(amcache)
        db.add(software)
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_amcache_findings_from_walk(
            project_id=project.id,
            firmware_id=firmware.id,
        )
        assert len(emitted) == 2
        for f in emitted:
            assert f.source == "windows_amcache_install"

        # Live canary: SELECT back and verify persistence.
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(rows) == 2
        # All persisted with low confidence baseline (ζ.1 LOW tier)
        for f in rows:
            assert f.confidence == "low"
            assert f.source == "windows_amcache_install"


@pytest.mark.asyncio
async def test_emit_amcache_findings_from_walk_empty_when_no_amcache_hives():
    """When no AmCache hives are present, emit returns empty list."""
    async with make_live_db() as db:
        project = Project(name="ζ.1 empty canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id,
            original_filename="canary.bin",
            storage_path="/tmp/canary.bin",
            sha256="y" * 64,
            file_size=1024,
        )
        db.add(firmware)
        await db.flush()
        # No registry extracts at all — emit returns []

        service = FindingService(db)
        emitted = await service.emit_amcache_findings_from_walk(
            project_id=project.id,
            firmware_id=firmware.id,
        )
        assert emitted == []
