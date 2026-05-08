"""Phase β.12b contract tests: ``FindingService.emit_pe_signature_findings``.

Three layers:

1. **Pure-classifier tests** for :func:`classify_pe_verdict_findings` —
   the verdict-tuple → Finding-draft matrix. No DB; exhaustive over the
   7 ``chain_status`` × ``signed`` × ``dbx_revoked`` corners that
   produce or don't produce drafts.
2. **Mock unit tests** for ``FindingService.emit_pe_signature_findings``
   verifying construction shape (number of drafts, correct severity /
   source / file_path) without paying the SQLite round-trip.
3. **Rule #35b live canary** — real ORM round-trip via
   ``tests._live_db.make_live_db``: seed Project + Firmware, run the
   emit helper, SELECT the persisted Finding rows, inspect every
   column the helper explicitly sets (severity / source / description /
   evidence / file_path / confidence / firmware_id / project_id).

Mocks alone would verify call-shape only; the live canary verifies
value-flow end-to-end (audit-2026-05-04 F-A-06 confidence-bypass +
every β-phase postmortem since).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, Project
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    _SOURCE_AUTHENTICODE,
    _SOURCE_DBX_REVOKED,
    classify_pe_verdict_findings,
)
from tests._live_db import make_live_db


# ── classify_pe_verdict_findings — verdict-tuple → draft matrix ───────────────


def test_classify_valid_now_emits_no_drafts():
    """A cleanly-validated chain produces no Finding (good case)."""
    drafts = classify_pe_verdict_findings(
        blob_path="/tmp/clean.exe",
        signed=True,
        chain_status="valid_now",
        dbx_revoked=False,
    )
    assert drafts == []


def test_classify_valid_at_signing_emits_no_drafts():
    """A chain that was valid at the signing timestamp (even if the cert
    has since expired) is the most common good case for older firmware."""
    drafts = classify_pe_verdict_findings(
        blob_path="/tmp/old-but-trusted.exe",
        signed=True,
        chain_status="valid_at_signing",
        dbx_revoked=False,
    )
    assert drafts == []


def test_classify_unsigned_unknown_emits_no_drafts():
    """An unsigned PE with chain_status=unknown does NOT get a Finding —
    the signature absence is captured in
    firmware.authenticode_chain_result.signed_pct, not as a per-PE
    triage row. The medium-severity windows_authenticode emission is
    GATED on signed=True per the β.12 design constraints."""
    drafts = classify_pe_verdict_findings(
        blob_path="/tmp/unsigned.dll",
        signed=False,
        chain_status="unknown",
        dbx_revoked=False,
    )
    assert drafts == []


def test_classify_revoked_emits_high_authenticode_draft():
    """chain_status=revoked → 1 windows_authenticode draft, high severity."""
    drafts = classify_pe_verdict_findings(
        blob_path="/firmware/system32/legacy.exe",
        signed=True,
        chain_status="revoked",
        dbx_revoked=False,
        leaf_serial="0123abcd",
        signer_subject="CN=Acme Co",
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_AUTHENTICODE
    assert d.severity == Severity.high
    assert "revoked" in d.title
    assert "legacy.exe" in d.title
    assert "leaf_serial=0123abcd" in d.evidence
    assert "signer_subject=CN=Acme Co" in d.evidence
    assert "chain_status=revoked" in d.evidence


def test_classify_never_valid_emits_high_authenticode_draft():
    """chain_status=never_valid → 1 windows_authenticode draft, high
    severity. ``signed`` may be True or False — the never_valid verdict
    indicates a parseable signature whose chain doesn't reach a trusted
    root, which is high-severity regardless of the signed flag's value."""
    drafts = classify_pe_verdict_findings(
        blob_path="/firmware/drivers/selfsigned.sys",
        signed=True,
        chain_status="never_valid",
        dbx_revoked=False,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_AUTHENTICODE
    assert d.severity == Severity.high


def test_classify_unknown_signed_emits_medium_authenticode_draft():
    """chain_status=unknown for a signed PE → 1 windows_authenticode
    draft, medium severity. Captures the "signature exists but
    verification is incomplete" middle ground."""
    drafts = classify_pe_verdict_findings(
        blob_path="/firmware/system32/cert-missing.exe",
        signed=True,
        chain_status="unknown",
        dbx_revoked=False,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_AUTHENTICODE
    assert d.severity == Severity.medium


def test_classify_dbx_revoked_emits_critical_dbx_draft():
    """dbx_revoked=True with an otherwise-clean chain → 1
    windows_dbx_revoked draft, critical severity. Independent of
    chain_status: a bypassed-revocation PE that signify happens to
    chain successfully is precisely the case the offline DBX bundle is
    meant to catch."""
    drafts = classify_pe_verdict_findings(
        blob_path="/firmware/drivers/badboot.efi",
        signed=True,
        chain_status="valid_now",
        dbx_revoked=True,
        leaf_serial="cafef00d",
        dbx_revocation_kb="KB5012170",
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_DBX_REVOKED
    assert d.severity == Severity.critical
    assert "leaf_serial=cafef00d" in d.evidence
    assert "dbx_revocation_kb=KB5012170" in d.evidence


def test_classify_chain_revoked_AND_dbx_revoked_emits_two_drafts():
    """A PE that's both chain-revoked AND DBX-revoked produces TWO
    Finding rows — different sources, different severities. The
    operator may want to triage them separately by source filter on
    the FindingsList page."""
    drafts = classify_pe_verdict_findings(
        blob_path="/firmware/system32/doublebad.exe",
        signed=True,
        chain_status="revoked",
        dbx_revoked=True,
        leaf_serial="deadbeef",
    )
    assert len(drafts) == 2
    sources = {d.source for d in drafts}
    assert sources == {_SOURCE_AUTHENTICODE, _SOURCE_DBX_REVOKED}
    severities = {d.severity for d in drafts}
    assert severities == {Severity.high, Severity.critical}


def test_classify_evidence_omits_missing_fields_cleanly():
    """When leaf_serial / signer_subject are absent, the evidence string
    must NOT contain bare ``leaf_serial=`` (empty value) — only the
    fields that have non-None / non-empty values surface."""
    drafts = classify_pe_verdict_findings(
        blob_path="/tmp/x.exe",
        signed=True,
        chain_status="revoked",
        dbx_revoked=False,
    )
    assert len(drafts) == 1
    assert "leaf_serial=" not in drafts[0].evidence
    assert "signer_subject=" not in drafts[0].evidence
    # The fields that ARE always present:
    assert "signed=True" in drafts[0].evidence
    assert "chain_status=revoked" in drafts[0].evidence


def test_classify_blob_path_uses_basename_in_title():
    """The Finding title carries the basename, not the absolute path —
    operators triaging a list view want short, scannable titles."""
    drafts = classify_pe_verdict_findings(
        blob_path="/very/long/extracted/path/to/the/firmware/system32/short.exe",
        signed=True,
        chain_status="never_valid",
        dbx_revoked=False,
    )
    assert "short.exe" in drafts[0].title
    assert "/very/long/extracted/path" not in drafts[0].title


# ── Rule #35b live canary — full ORM round-trip ─────────────────────────────


async def _seed_project_and_firmware(db) -> tuple[Project, Firmware]:
    """Reusable seed: one Project + one Firmware, both flushed."""
    project = Project(
        name="beta12b-emit-test",
        description="Phase β.12b emit-from-verdict live canary",
    )
    db.add(project)
    await db.flush()

    fw = Firmware(
        project_id=project.id,
        original_filename="windows-installer.iso",
        file_size=1024 * 1024 * 32,
        sha256="0" * 64,
    )
    db.add(fw)
    await db.flush()
    return project, fw


@pytest.mark.asyncio
async def test_emit_persists_authenticode_finding_with_full_columns():
    """Live canary: a chain-revoked verdict produces a persisted Finding
    row whose every helper-set column round-trips through the real ORM."""
    async with make_live_db() as db:
        project, fw = await _seed_project_and_firmware(db)

        svc = FindingService(db)
        emitted = await svc.emit_pe_signature_findings(
            project_id=project.id,
            firmware_id=fw.id,
            blob_path="/firmware/system32/oldsigner.exe",
            signed=True,
            chain_status="revoked",
            dbx_revoked=False,
            leaf_serial="abc123",
            signer_subject="CN=Old Vendor Co",
        )
        await db.commit()

        # The helper returned exactly one Finding (chain_status=revoked,
        # not dbx_revoked).
        assert len(emitted) == 1

        # Real SELECT against the live DB — not mock_db.add.call_args.
        row = (
            await db.execute(
                select(Finding).where(Finding.project_id == project.id)
            )
        ).scalar_one()

        # Every column the helper explicitly sets must round-trip cleanly.
        # This is the value-flow assertion that mocks structurally cannot
        # provide (audit-2026-05-04 F-A-06 worked example).
        assert row.source == "windows_authenticode"
        assert row.severity == "high"
        assert row.confidence == "high"
        assert row.file_path == "/firmware/system32/oldsigner.exe"
        assert row.firmware_id == fw.id
        assert row.project_id == project.id
        assert "oldsigner.exe" in row.title
        assert "revoked" in row.title
        assert "leaf_serial=abc123" in row.evidence
        assert "signer_subject=CN=Old Vendor Co" in row.evidence
        # Status defaults to 'open' via Finding.status server_default.
        assert row.status == "open"


@pytest.mark.asyncio
async def test_emit_persists_two_findings_for_double_bad_pe():
    """Live canary: a PE that's BOTH chain-revoked AND DBX-revoked
    produces TWO persisted Finding rows. Confirms the helper's per-draft
    create() loop (not just the classifier) emits both branches."""
    async with make_live_db() as db:
        project, fw = await _seed_project_and_firmware(db)

        svc = FindingService(db)
        emitted = await svc.emit_pe_signature_findings(
            project_id=project.id,
            firmware_id=fw.id,
            blob_path="/firmware/drivers/doublebad.efi",
            signed=True,
            chain_status="revoked",
            dbx_revoked=True,
            leaf_serial="deadbeef",
            dbx_revocation_kb="KB5012170",
        )
        await db.commit()

        assert len(emitted) == 2

        rows = (
            await db.execute(
                select(Finding)
                .where(Finding.project_id == project.id)
                .order_by(Finding.source)
            )
        ).scalars().all()
        assert len(rows) == 2

        by_source = {r.source: r for r in rows}
        assert "windows_authenticode" in by_source
        assert "windows_dbx_revoked" in by_source

        ac = by_source["windows_authenticode"]
        assert ac.severity == "high"
        assert ac.file_path == "/firmware/drivers/doublebad.efi"

        dbx = by_source["windows_dbx_revoked"]
        assert dbx.severity == "critical"
        assert dbx.confidence == "high"
        assert dbx.firmware_id == fw.id
        assert "leaf_serial=deadbeef" in dbx.evidence
        assert "dbx_revocation_kb=KB5012170" in dbx.evidence


@pytest.mark.asyncio
async def test_emit_persists_zero_rows_for_clean_pe():
    """Live canary: a cleanly-validated PE produces NO Finding rows.
    Confirms the classifier's empty-list path doesn't accidentally fire
    a create() with empty data."""
    async with make_live_db() as db:
        project, fw = await _seed_project_and_firmware(db)

        svc = FindingService(db)
        emitted = await svc.emit_pe_signature_findings(
            project_id=project.id,
            firmware_id=fw.id,
            blob_path="/firmware/system32/clean.exe",
            signed=True,
            chain_status="valid_now",
            dbx_revoked=False,
        )
        await db.commit()

        assert emitted == []

        rows = (
            await db.execute(
                select(Finding).where(Finding.project_id == project.id)
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_emit_with_unknown_signed_persists_medium_authenticode_finding():
    """Live canary: chain_status=unknown for signed=True PE persists
    a windows_authenticode Finding at MEDIUM severity (not high).
    Distinguishes the medium-tier branch end-to-end."""
    async with make_live_db() as db:
        project, fw = await _seed_project_and_firmware(db)

        svc = FindingService(db)
        emitted = await svc.emit_pe_signature_findings(
            project_id=project.id,
            firmware_id=fw.id,
            blob_path="/firmware/system32/missing-intermediate.exe",
            signed=True,
            chain_status="unknown",
            dbx_revoked=False,
        )
        await db.commit()

        assert len(emitted) == 1
        row = (
            await db.execute(
                select(Finding).where(Finding.project_id == project.id)
            )
        ).scalar_one()
        assert row.source == "windows_authenticode"
        assert row.severity == "medium"
