"""Tier-1 tests for the η.D.D BYOVD finding emit pipeline.

Covers the cross-stack alignment surfaces (DB CHECK ↔ Pydantic Literal ↔
finding_service classifier ↔ emit method) and confidence tier mapping:

- classify_byovd_finding (pure function — no DB)
- emit_byovd_findings_from_driver (FindingService method — live canary
  via tests._live_db.make_live_db)

Per CLAUDE.md Rule #35b: at least one test round-trips through the real
ORM + SELECTs the persisted row, inspecting confidence + cve_ids fields
the emit method explicitly sets.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    _SOURCE_BYOVD_DRIVER,
    FindingService,
    _BYOVDFindingDraft,
    classify_byovd_finding,
)
from app.services.loldrivers_lookup_service import BYOVDVerdict
from tests._live_db import make_live_db

# ── classify_byovd_finding — confidence tier mapping ────────────────────────


def _verdict_kwargs(**overrides) -> dict:
    """Build a baseline classify_byovd_finding kwargs dict."""
    base = {
        "driver_path": "C:/Windows/System32/drivers/amp.sys",
        "blob_sha256": "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        "category": "vulnerable driver",
        "cve_ids": [],
        "mitre_id": "T1068",
        "filename": "amp.sys",
        "loldrivers_id": "00000000-0000-0000-0000-000000000001",
        "loads_despite_hvci": False,
        "sha256_match_kind": "file",
        "reference_url": "https://www.loldrivers.io/drivers/00000000-0000-0000-0000-000000000001/",
    }
    base.update(overrides)
    return base


def test_malicious_category_yields_high_confidence():
    """category=malicious → HIGH confidence + high severity."""
    draft = classify_byovd_finding(**_verdict_kwargs(category="malicious"))
    assert isinstance(draft, _BYOVDFindingDraft)
    assert draft.source == _SOURCE_BYOVD_DRIVER
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high


def test_vulnerable_with_cve_yields_high_confidence():
    """category=vulnerable driver + CVE → HIGH confidence + high severity."""
    draft = classify_byovd_finding(
        **_verdict_kwargs(
            category="vulnerable driver",
            cve_ids=["CVE-2026-00001"],
        )
    )
    assert draft.confidence == Confidence.high
    assert draft.severity == Severity.high


def test_vulnerable_without_cve_yields_medium_confidence():
    """category=vulnerable driver + no CVE → MEDIUM confidence + medium severity."""
    draft = classify_byovd_finding(
        **_verdict_kwargs(category="vulnerable driver", cve_ids=[])
    )
    assert draft.confidence == Confidence.medium
    assert draft.severity == Severity.medium


def test_hvci_bypass_bumps_severity_to_critical():
    """loads_despite_hvci=True bumps severity to critical regardless of
    base confidence."""
    draft = classify_byovd_finding(
        **_verdict_kwargs(
            category="vulnerable driver",
            cve_ids=[],
            loads_despite_hvci=True,
        )
    )
    assert draft.severity == Severity.critical


def test_evidence_includes_reference_url():
    """The LOLDrivers /drivers/{id}/ URL is in the evidence text."""
    draft = classify_byovd_finding(**_verdict_kwargs())
    assert "https://www.loldrivers.io/drivers/00000000-0000-0000-0000-000000000001/" in draft.evidence


def test_evidence_includes_match_kind():
    """Match-kind discriminator surfaces in evidence for audit trail."""
    draft = classify_byovd_finding(**_verdict_kwargs(sha256_match_kind="authentihash"))
    assert "Match kind: authentihash" in draft.evidence


def test_title_uses_filename_when_available():
    """Title prefers the filename label over the driver_path."""
    draft = classify_byovd_finding(**_verdict_kwargs(filename="rotten.sys"))
    assert draft.title == "BYOVD driver: rotten.sys"


def test_title_falls_back_to_driver_path():
    """When filename is None, title falls back to driver_path."""
    draft = classify_byovd_finding(
        **_verdict_kwargs(filename=None, driver_path="C:/x/y.sys")
    )
    assert draft.title == "BYOVD driver: C:/x/y.sys"


# ── emit_byovd_findings_from_driver — Rule #35b live canary ─────────────────


@pytest.mark.asyncio
async def test_emit_persists_finding_with_full_value_flow():
    """Live canary: round-trip emit → persist → SELECT and inspect the
    fields the emit method explicitly sets.
    """
    async with make_live_db() as db:
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        service = FindingService(db)

        verdict = BYOVDVerdict(
            sha256="cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
            authentihash_sha256=None,
            filename="amp.sys",
            category="malicious",
            cve_ids=["CVE-2026-00001", "CVE-2026-00002"],
            mitre_id="T1068",
            loldrivers_id="00000000-0000-0000-0000-000000000001",
            loads_despite_hvci=False,
            sha256_match_kind="file",
        )

        persisted = await service.emit_byovd_findings_from_driver(
            project_id=project_id,
            firmware_id=firmware_id,
            driver_path="C:/Windows/System32/drivers/amp.sys",
            blob_sha256="cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
            verdict=verdict,
        )
        assert persisted is not None
        await db.commit()

        # Inspect the persisted row directly (Rule #35b).
        row = (
            await db.execute(
                select(Finding).where(Finding.id == persisted.id)
            )
        ).scalar_one()

        assert row.source == "windows_byovd_driver"
        assert row.confidence == "high"  # malicious → HIGH
        assert row.severity == "high"
        assert row.firmware_id == firmware_id
        assert row.project_id == project_id
        assert row.file_path == "C:/Windows/System32/drivers/amp.sys"
        assert row.cve_ids == ["CVE-2026-00001", "CVE-2026-00002"]
        assert "windows_byovd_driver" not in row.title
        assert "BYOVD driver" in row.title
        assert "amp.sys" in row.title
        assert "loldrivers.io/drivers/00000000-0000-0000-0000-000000000001" in (row.evidence or "")


@pytest.mark.asyncio
async def test_emit_with_none_verdict_returns_none():
    """Defensive — None verdict short-circuits without emitting."""
    async with make_live_db() as db:
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        service = FindingService(db)

        result = await service.emit_byovd_findings_from_driver(
            project_id=project_id,
            firmware_id=firmware_id,
            driver_path="C:/x/y.sys",
            blob_sha256="0" * 64,
            verdict=None,  # type: ignore[arg-type]
        )
        assert result is None
        rows = (await db.execute(select(Finding))).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_emit_hvci_bypass_persists_critical_severity():
    """HVCI bypass → severity=critical, persisted on the row."""
    async with make_live_db() as db:
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        service = FindingService(db)

        verdict = BYOVDVerdict(
            sha256="9" * 64,
            authentihash_sha256="9" * 64,
            filename="rotten.sys",
            category="vulnerable driver",
            cve_ids=[],
            mitre_id="T1068",
            loldrivers_id="00000000-0000-0000-0000-000000000002",
            loads_despite_hvci=True,
            sha256_match_kind="authentihash",
        )
        persisted = await service.emit_byovd_findings_from_driver(
            project_id=project_id,
            firmware_id=firmware_id,
            driver_path="C:/Windows/System32/drivers/rotten.sys",
            blob_sha256="9" * 64,
            verdict=verdict,
        )
        await db.commit()
        assert persisted is not None

        row = (
            await db.execute(
                select(Finding).where(Finding.id == persisted.id)
            )
        ).scalar_one()
        assert row.severity == "critical"
        assert row.source == "windows_byovd_driver"
