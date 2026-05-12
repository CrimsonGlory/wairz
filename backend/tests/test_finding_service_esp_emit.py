"""Tests for the Phase θ.C.D ESP `.efi` finding-emit classifier +
``FindingService.emit_esp_findings_from_walk``.

Covers:
- ``classify_esp_findings`` — pure classifier returns 0/1/2 drafts
  with the expected tier mapping (HIGH/MEDIUM) per the rule below.
- ``emit_esp_findings_from_walk`` — Rule #35b live canaries via
  make_live_db: walk-state-machine round-trip persists Finding rows
  with the correct source / confidence / severity / file_path.

Tier mapping:
- HIGH — unsigned `.efi` AND is_known_bootloader_path
  (BlackLotus / Bootkitty canonical bootkit shape); OR
  signed_revoked (DBX-revoked, authoritative).
- MEDIUM — unsigned `.efi` AND is_vendor_path.
- (Skipped) — signed_valid `.efi` files, unsigned `.efi` in
  non-bootloader / non-vendor paths.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, Project, WindowsEspEntry
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    _SOURCE_ESP_DBX_REVOKED,
    _SOURCE_ESP_UNSIGNED,
    FindingService,
    classify_esp_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_esp_entries_anomaly_flags,
    _stamp_windows_esp_entries_authenticode_chain,
    _stamp_windows_esp_entries_dbx_revocation_match,
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


# ── classify_esp_findings — pure classifier tests ───────────────────────────


def test_classify_signed_valid_emits_zero():
    """A signed_valid `.efi` is not a bootkit signal — 0 drafts."""
    drafts = classify_esp_findings(
        file_path="EFI/Microsoft/Boot/bootmgfw.efi",
        file_sha256="d" * 64,
        file_size=2_000_000,
        authenticode_state="signed_valid",
        anomaly_flags={
            "is_unsigned": False,
            "is_known_bootloader_path": True,
            "is_vendor_path": True,
        },
        chain_dict={
            "signed": True,
            "chain_status": "valid_now",
            "signer_subject": "CN=Microsoft Corporation UEFI CA 2011",
        },
        dbx_match_dict=None,
    )
    assert drafts == []


def test_classify_unsigned_known_bootloader_emits_high():
    """Unsigned `.efi` in canonical OS-bootloader path → HIGH."""
    drafts = classify_esp_findings(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="a" * 64,
        file_size=512,
        authenticode_state="unsigned",
        anomaly_flags={
            "is_unsigned": True,
            "is_known_bootloader_path": True,
            "is_vendor_path": False,
            "is_suspiciously_small": True,
        },
        chain_dict=None,
        dbx_match_dict=None,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_ESP_UNSIGNED
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "BlackLotus" in d.description or "Bootkitty" in d.description
    assert "bootx64.efi" in d.title


def test_classify_unsigned_vendor_path_emits_medium():
    """Unsigned `.efi` in vendor EFI/<vendor>/ path → MEDIUM."""
    drafts = classify_esp_findings(
        file_path="EFI/Acme/utility.efi",
        file_sha256="b" * 64,
        file_size=200_000,
        authenticode_state="unsigned",
        anomaly_flags={
            "is_unsigned": True,
            "is_known_bootloader_path": False,
            "is_vendor_path": True,
        },
        chain_dict=None,
        dbx_match_dict=None,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_ESP_UNSIGNED
    assert d.confidence == Confidence.medium
    assert d.severity == Severity.medium


def test_classify_unsigned_neither_bootloader_nor_vendor_emits_zero():
    """An unsigned `.efi` that lives outside both canonical bootloader
    paths AND vendor paths is NOT a strong bootkit signal — 0 drafts."""
    drafts = classify_esp_findings(
        file_path="EFI/randomapp/random.efi",
        file_sha256="c" * 64,
        file_size=100_000,
        authenticode_state="unsigned",
        anomaly_flags={
            "is_unsigned": True,
            "is_known_bootloader_path": False,
            "is_vendor_path": False,
        },
        chain_dict=None,
        dbx_match_dict=None,
    )
    assert drafts == []


def test_classify_dbx_revoked_emits_high():
    """DBX-revoked → HIGH always (authoritative revocation)."""
    drafts = classify_esp_findings(
        file_path="EFI/Microsoft/Boot/bootmgfw.efi",
        file_sha256="d" * 64,
        file_size=2_000_000,
        authenticode_state="signed_revoked",
        anomaly_flags={
            "is_unsigned": False,
            "is_revoked": True,
            "is_known_bootloader_path": True,
            "is_vendor_path": True,
        },
        chain_dict={
            "signed": True,
            "chain_status": "valid_now",
            "signer_subject": "CN=Microsoft Windows Production PCA 2011",
            "leaf_serial": "DEADBEEFCAFEBABE",
        },
        dbx_match_dict={
            "revoked": True,
            "match_kind": "x509_serial",
            "leaf_serial_normalized": "DEADBEEFCAFEBABE",
        },
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_ESP_DBX_REVOKED
    assert d.confidence == Confidence.high
    assert d.severity == Severity.high
    assert "DBX" in d.description or "revoked" in d.description.lower()
    assert "DEADBEEFCAFEBABE" in d.evidence


def test_classify_parse_failed_emits_zero():
    """parse_failed `.efi` files — no actionable signal — 0 drafts."""
    drafts = classify_esp_findings(
        file_path="EFI/Boot/malformed.efi",
        file_sha256="e" * 64,
        file_size=100,
        authenticode_state="parse_failed",
        anomaly_flags={
            "is_unsigned": False,
            "is_known_bootloader_path": True,
            "is_vendor_path": False,
        },
        chain_dict={"error": "PE parse failed"},
        dbx_match_dict=None,
    )
    assert drafts == []


# ── emit_esp_findings_from_walk — Rule #35b live canaries ──────────────────


@pytest.mark.asyncio
async def test_emit_esp_unsigned_known_bootloader_persists_high():
    """Live canary — emit hook persists the HIGH-tier unsigned
    bootloader finding with the correct columns set."""
    async with make_live_db() as db:
        project = Project(name="θ.C.D emit-unsigned canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-unsigned.bin", "u")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="a" * 64,
            file_size=512,
            authenticode_state="unsigned",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": False,
                    "chain_status": "unknown",
                    "signatures_count": 0,
                })
            ),
            dbx_revocation_match=None,
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": True,
                "is_known_bootloader_path": True,
                "is_vendor_path": False,
                "is_suspiciously_small": True,
            }),
            fingerprint_sha256="f" * 64,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_esp_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1

        # Live SELECT — verify the persisted columns.
        rows = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.source == "windows_esp_unsigned"
        assert f.confidence == Confidence.high
        assert f.severity == Severity.high
        assert f.file_path == "EFI/Boot/bootx64.efi"


@pytest.mark.asyncio
async def test_emit_esp_dbx_revoked_persists_high():
    """Live canary — emit hook persists DBX-revoked finding."""
    async with make_live_db() as db:
        project = Project(name="θ.C.D emit-revoked canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-revoked.bin", "r")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="d" * 64,
            file_size=2_000_000,
            authenticode_state="signed_revoked",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": True,
                    "chain_status": "valid_now",
                    "signer_subject": (
                        "CN=Microsoft Windows Production PCA 2011"
                    ),
                    "leaf_serial": "DEADBEEFCAFEBABE",
                    "signatures_count": 1,
                })
            ),
            dbx_revocation_match=(
                _stamp_windows_esp_entries_dbx_revocation_match({
                    "revoked": True,
                    "match_kind": "x509_serial",
                    "leaf_serial_normalized": "DEADBEEFCAFEBABE",
                    "bundle_entries": 5000,
                    "bundle_path": "/opt/wairz/dbxupdate.bin",
                })
            ),
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_revoked": True,
                "is_known_bootloader_path": True,
                "is_vendor_path": True,
            }),
            fingerprint_sha256="e" * 64,
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_esp_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1

        rows = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.source == "windows_esp_dbx_revoked"
        assert f.confidence == Confidence.high
        assert f.severity == Severity.high
        assert "DEADBEEFCAFEBABE" in f.evidence


@pytest.mark.asyncio
async def test_emit_esp_signed_valid_emits_zero():
    """Live canary — signed_valid Microsoft `.efi` files produce
    NO Finding rows (no anomaly to surface)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.D emit-signed-valid canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-valid.bin", "v")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="d" * 64,
            file_size=2_000_000,
            authenticode_state="signed_valid",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": True,
                    "chain_status": "valid_now",
                    "signer_subject": (
                        "CN=Microsoft Corporation UEFI CA 2011"
                    ),
                    "signatures_count": 1,
                })
            ),
            dbx_revocation_match=None,
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_revoked": False,
                "is_known_bootloader_path": True,
                "is_vendor_path": True,
            }),
        )
        db.add(entry)
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_esp_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert emitted == []
        rows = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_emit_esp_mixed_state_persists_subset():
    """Live canary — walk produces 4 entries (signed_valid + unsigned
    bootloader + unsigned vendor + parse_failed); emit hook produces
    2 Finding rows (HIGH unsigned-bootloader + MEDIUM unsigned-vendor)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.D emit-mixed canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-mixed.bin", "m")
        db.add(firmware)
        await db.flush()

        # Signed-valid — 0 drafts
        db.add(WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="0" * 64,
            file_size=2_000_000,
            authenticode_state="signed_valid",
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_revoked": False,
                "is_known_bootloader_path": True,
                "is_vendor_path": True,
            }),
        ))
        # Unsigned bootloader — HIGH
        db.add(WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="1" * 64,
            file_size=512,
            authenticode_state="unsigned",
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": True,
                "is_known_bootloader_path": True,
                "is_vendor_path": False,
                "is_suspiciously_small": True,
            }),
        ))
        # Unsigned vendor — MEDIUM
        db.add(WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Acme/util.efi",
            file_sha256="2" * 64,
            file_size=200_000,
            authenticode_state="unsigned",
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": True,
                "is_known_bootloader_path": False,
                "is_vendor_path": True,
            }),
        ))
        # Parse-failed — 0 drafts
        db.add(WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/malformed.efi",
            file_sha256="3" * 64,
            file_size=100,
            authenticode_state="parse_failed",
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_known_bootloader_path": True,
            }),
        ))
        await db.commit()

        service = FindingService(db=db)
        emitted = await service.emit_esp_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()
        assert len(emitted) == 2

        rows = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 2
        sources = {r.source for r in rows}
        assert sources == {"windows_esp_unsigned"}
        confidences = {r.confidence for r in rows}
        assert Confidence.high in confidences
        assert Confidence.medium in confidences
