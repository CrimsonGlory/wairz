"""Phase β.2 contract test: WindowsPESignature ORM round-trip.

Per Rule #35b, every new table gets an ORM round-trip + SELECT test.
This test seeds a Project + Firmware + HardwareFirmwareBlob → inserts
a WindowsPESignature → SELECTs the row → asserts all fields persisted.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsPESignature,
)
from tests._live_db import make_live_db


async def _seed_blob(db) -> HardwareFirmwareBlob:
    """Seed a Project + Firmware + HardwareFirmwareBlob fixture chain."""
    project = Project(
        name="windows-pe-test-project",
        description="Phase β.2 ORM round-trip fixture",
    )
    db.add(project)
    await db.flush()

    firmware = Firmware(
        project_id=project.id,
        original_filename="vendor.cab",
        file_size=1024,
        sha256="a" * 64,
    )
    db.add(firmware)
    await db.flush()

    blob = HardwareFirmwareBlob(
        firmware_id=firmware.id,
        blob_path="vendor.sys",
        blob_sha256="b" * 64,
        file_size=2048,
        category="other",
        format="raw_bin",
        detection_source="test",
    )
    db.add(blob)
    await db.flush()
    return blob


@pytest.mark.asyncio
async def test_windows_pe_signature_round_trip():
    """Insert a fully-populated WindowsPESignature, SELECT it back, verify
    every field. Rule #35b value-flow check — a mock `db.add` assertion
    would not catch a missing column-write."""
    async with make_live_db() as live_db:
        blob = await _seed_blob(live_db)

        sig = WindowsPESignature(
            blob_id=blob.id,
            signed=True,
            signer_subject="CN=Microsoft Windows, O=Microsoft Corporation",
            signer_issuer="CN=Microsoft Code Signing PCA 2011",
            leaf_serial="3300000266BD1580E08DD24300000000000266",
            sig_hash_algo="sha256",
            tsa_authority="CN=Microsoft Time-Stamp PCA 2010",
            signed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
            chain_status="valid_at_signing",
            chain_json={
                "root": {"cn": "Microsoft Root Certificate Authority 2010"},
                "leaf": {"cn": "Microsoft Windows", "serial": "33...266"},
            },
            dbx_revoked=False,
            dbx_revocation_kb=None,
            rich_header_json={"compid_count": 12, "linker_version": "14.31"},
            arch_view={"primary": "amd64", "secondary": None, "divergence_score": 0},
        )
        live_db.add(sig)
        await live_db.flush()

        row = (
            await live_db.execute(
                select(WindowsPESignature).where(
                    WindowsPESignature.blob_id == blob.id
                )
            )
        ).scalar_one()

        assert row.blob_id == blob.id
        assert row.signed is True
        assert row.signer_subject == "CN=Microsoft Windows, O=Microsoft Corporation"
        assert row.signer_issuer == "CN=Microsoft Code Signing PCA 2011"
        assert row.leaf_serial == "3300000266BD1580E08DD24300000000000266"
        assert row.sig_hash_algo == "sha256"
        assert row.tsa_authority == "CN=Microsoft Time-Stamp PCA 2010"
        assert row.signed_at == datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
        assert row.chain_status == "valid_at_signing"
        assert row.chain_json == {
            "root": {"cn": "Microsoft Root Certificate Authority 2010"},
            "leaf": {"cn": "Microsoft Windows", "serial": "33...266"},
        }
        assert row.dbx_revoked is False
        assert row.dbx_revocation_kb is None
        assert row.rich_header_json == {
            "compid_count": 12,
            "linker_version": "14.31",
        }
        assert row.arch_view == {
            "primary": "amd64",
            "secondary": None,
            "divergence_score": 0,
        }
        assert row.created_at is not None
        assert row.updated_at is not None


@pytest.mark.asyncio
async def test_windows_pe_signature_defaults():
    """Minimal-insert: only blob_id required; all other fields default."""
    async with make_live_db() as live_db:
        blob = await _seed_blob(live_db)

        sig = WindowsPESignature(blob_id=blob.id)
        live_db.add(sig)
        await live_db.flush()

        row = (
            await live_db.execute(
                select(WindowsPESignature).where(
                    WindowsPESignature.blob_id == blob.id
                )
            )
        ).scalar_one()

        assert row.signed is False
        assert row.dbx_revoked is False
        assert row.chain_status == "unknown"
        assert row.signer_subject is None
        assert row.leaf_serial is None
        assert row.signed_at is None
        assert row.chain_json is None


@pytest.mark.asyncio
async def test_windows_pe_signature_chain_status_documented_values():
    """All 5 documented chain_status values must persist. The CHECK
    constraint at the PostgreSQL layer (migration b1a2c3d4e5f6) catches
    rejected values; SQLite ignores CHECKs by default, so this is a
    positive-case assertion — every documented value rounds-trips.
    """
    async with make_live_db() as live_db:
        blob = await _seed_blob(live_db)

        for status in (
            "valid_at_signing",
            "valid_now",
            "revoked",
            "never_valid",
            "unknown",
        ):
            sig = WindowsPESignature(
                blob_id=blob.id,
                chain_status=status,
            )
            live_db.add(sig)
            await live_db.flush()

            row = (
                await live_db.execute(
                    select(WindowsPESignature)
                    .where(WindowsPESignature.blob_id == blob.id)
                    .where(WindowsPESignature.chain_status == status)
                )
            ).scalar_one()
            assert row.chain_status == status
