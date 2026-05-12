"""Tests for the Phase θ.C.A WindowsEspEntry ORM model.

Per CLAUDE.md Rule #35b live canaries: round-trip via the real ORM
+ ``make_live_db`` SQLite shim to confirm column shapes + index
declarations match the alembic migration intent.

Covers:
- ORM round-trip — create, persist, SELECT, inspect every column.
- JSONB columns (authenticode_chain, dbx_revocation_match,
  anomaly_flags) — Rule #35c stamped envelope persists end-to-end.
- Defensive shapes: NULL dbx match, parse_failed state,
  signed_valid Microsoft-CA shape, fingerprint cross-firmware
  aggregation query.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEspEntry
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


# ── ORM round-trip live canaries ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_esp_entry_persists_signed_valid_microsoft_shape():
    """Rule #35b live canary — round-trip a signed-valid Microsoft
    bootmgfw.efi entry and confirm every column persists with the
    expected shape."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A signed-valid canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-esp.bin", "e")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="d" * 64,
            file_size=1_234_567,
            authenticode_state="signed_valid",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": True,
                    "chain_status": "valid_now",
                    "signer_subject": (
                        "CN=Microsoft Corporation UEFI CA 2011"
                    ),
                    "signer_issuer": (
                        "CN=Microsoft Corporation Third Party Marketplace Root"
                    ),
                    "leaf_serial": "61077656000000000008",
                    "sig_hash_algo": "sha256",
                    "signed_at": "2023-06-14T12:00:00",
                    "signatures_count": 1,
                    "error": None,
                })
            ),
            dbx_revocation_match=None,
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_expired": False,
                "is_revoked": False,
                "is_non_microsoft_signer": False,
                "is_known_bootloader_path": True,
                "is_vendor_path": False,
                "is_suspiciously_small": False,
            }),
            fingerprint_sha256="f" * 64,
        )
        db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.file_path == "EFI/Microsoft/Boot/bootmgfw.efi"
        assert r.file_sha256 == "d" * 64
        assert r.file_size == 1_234_567
        assert r.authenticode_state == "signed_valid"
        assert r.fingerprint_sha256 == "f" * 64
        assert r.dbx_revocation_match is None

        assert isinstance(r.authenticode_chain, dict)
        assert r.authenticode_chain["signed"] is True
        assert r.authenticode_chain["chain_status"] == "valid_now"
        assert "Microsoft" in r.authenticode_chain["signer_subject"]
        assert r.authenticode_chain["schema_version"] == 1

        assert isinstance(r.anomaly_flags, dict)
        assert r.anomaly_flags["is_known_bootloader_path"] is True
        assert r.anomaly_flags["is_unsigned"] is False
        assert r.anomaly_flags["schema_version"] == 1


@pytest.mark.asyncio
async def test_esp_entry_persists_unsigned_bootloader_shape():
    """Rule #35b live canary — unsigned `.efi` in canonical bootloader
    path (BlackLotus / Bootkitty canonical shape)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A unsigned canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-unsigned.bin", "u")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="0" * 64,
            file_size=512,  # < 4 KB — suspiciously small
            authenticode_state="unsigned",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": False,
                    "chain_status": "unknown",
                    "signatures_count": 0,
                    "error": None,
                })
            ),
            dbx_revocation_match=None,
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": True,
                "is_expired": False,
                "is_revoked": False,
                "is_non_microsoft_signer": False,
                "is_known_bootloader_path": True,
                "is_vendor_path": False,
                "is_suspiciously_small": True,
            }),
            fingerprint_sha256="a" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.authenticode_state == "unsigned"
        assert r.anomaly_flags["is_unsigned"] is True
        assert r.anomaly_flags["is_suspiciously_small"] is True
        assert r.anomaly_flags["is_known_bootloader_path"] is True


@pytest.mark.asyncio
async def test_esp_entry_persists_dbx_revoked_shape():
    """Rule #35b live canary — DBX-revoked `.efi` (BlackLotus
    revocation, or GRUB2 BootHole revocation)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A dbx-revoked canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-revoked.bin", "r")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="1" * 64,
            file_size=2_000_000,
            authenticode_state="signed_revoked",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": True,
                    "chain_status": "revoked",
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
                    "revocation_kb": None,
                    "leaf_serial_normalized": "DEADBEEFCAFEBABE",
                    "match_kind": "x509_serial",
                    "bundle_entries": 5000,
                    "bundle_path": "/opt/wairz/dbxupdate.bin",
                })
            ),
            anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
                "is_unsigned": False,
                "is_expired": False,
                "is_revoked": True,
                "is_non_microsoft_signer": False,
                "is_known_bootloader_path": True,
                "is_vendor_path": False,
                "is_suspiciously_small": False,
            }),
            fingerprint_sha256="b" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.authenticode_state == "signed_revoked"
        assert isinstance(r.dbx_revocation_match, dict)
        assert r.dbx_revocation_match["revoked"] is True
        assert r.dbx_revocation_match["match_kind"] == "x509_serial"
        assert r.dbx_revocation_match["schema_version"] == 1
        assert r.anomaly_flags["is_revoked"] is True


@pytest.mark.asyncio
async def test_esp_entry_persists_parse_failed_shape():
    """Rule #35b live canary — parse_failed shape (signify / pefile
    raised on a malformed .efi)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A parse-failed canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw-malformed.bin", "p")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/badly-malformed.efi",
            file_sha256="2" * 64,
            file_size=100,
            authenticode_state="parse_failed",
            authenticode_chain=(
                _stamp_windows_esp_entries_authenticode_chain({
                    "signed": False,
                    "chain_status": "unknown",
                    "signatures_count": 0,
                    "error": "PE parse failed: PEFormatError: Invalid e_lfanew",
                })
            ),
            dbx_revocation_match=None,
            anomaly_flags=None,
            fingerprint_sha256=None,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.authenticode_state == "parse_failed"
        assert r.anomaly_flags is None
        assert r.fingerprint_sha256 is None
        assert "PE parse failed" in r.authenticode_chain["error"]


@pytest.mark.asyncio
async def test_esp_entry_fingerprint_cross_firmware_aggregation():
    """The fingerprint_sha256 column enables cross-firmware aggregation
    (the lookup_esp_chain MCP tool's query shape).

    Two firmware images carrying the same `.efi` fingerprint surface
    via a single SELECT."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A cross-firmware canary")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        # Same fingerprint across both firmware ⇒ same .efi shape
        # was planted (BlackLotus / Bootkitty cross-corpus surface).
        fp = "deadbeef" * 8

        for fw in (fw1, fw2):
            db.add(WindowsEspEntry(
                firmware_id=fw.id,
                file_path="EFI/Boot/bootx64.efi",
                file_sha256="9" * 64,
                file_size=512,
                authenticode_state="unsigned",
                fingerprint_sha256=fp,
            ))
        await db.commit()

        # The lookup_esp_chain query shape: aggregate by fingerprint
        # across firmware.
        rows = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.fingerprint_sha256 == fp
                )
            )
        ).scalars().all()
        assert len(rows) == 2
        firmware_ids = {r.firmware_id for r in rows}
        assert firmware_ids == {fw1.id, fw2.id}


@pytest.mark.asyncio
async def test_esp_entry_persists_with_minimal_required_fields():
    """An entry with ONLY required fields populated must persist
    successfully (defensive parse-failure path)."""
    async with make_live_db() as db:
        project = Project(name="θ.C.A minimal canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw.bin", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsEspEntry(
            firmware_id=firmware.id,
            file_path="EFI/Boot/some.efi",
            file_sha256="3" * 64,
            file_size=4096,
            authenticode_state="unsigned",
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsEspEntry).where(
                    WindowsEspEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.file_path == "EFI/Boot/some.efi"
        assert r.authenticode_state == "unsigned"
        assert r.authenticode_chain is None
        assert r.dbx_revocation_match is None
        assert r.anomaly_flags is None
        assert r.fingerprint_sha256 is None
