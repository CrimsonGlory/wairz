"""Tests for the Phase θ.A.A WindowsBcdEntry ORM model.

Per CLAUDE.md Rule #35b live canaries: round-trip via the real ORM
+ ``make_live_db`` SQLite shim to confirm column shapes + index
declarations match the alembic migration intent.

Covers:
- ORM round-trip — create, persist, SELECT, inspect every column.
- JSONB columns (custom_elements + anomaly_flags) — Rule #35c stamped
  envelope persists end-to-end.
- Index declarations match the alembic migration shape.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsBcdEntry
from app.services.jsonb_normalizers import (
    _stamp_windows_bcd_entries_anomaly_flags,
    _stamp_windows_bcd_entries_custom_elements,
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
async def test_bcd_entry_persists_well_known_bootmgr_shape():
    """Rule #35b live canary — round-trip a well-known {bootmgr} BCD
    entry and confirm every column persists with the expected shape."""
    async with make_live_db() as db:
        project = Project(name="θ.A.A bootmgr canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-bootmgr.bin", "b")
        db.add(firmware)
        await db.flush()

        # Well-known {bootmgr} GUID with full element complement.
        entry = WindowsBcdEntry(
            firmware_id=firmware.id,
            source_path="Boot/BCD",
            object_guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            object_type=0x10100002,  # Boot manager image type
            description="Windows Boot Manager",
            image_path="\\Windows\\System32\\winload.efi",
            gpt_partition_guid="{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}",
            gpt_disk_guid="{1b1de4d3-9ec8-4f00-86f3-d2e5e2e0e4f1}",
            testsigning=False,
            no_integrity_checks=False,
            nx_policy=0,
            custom_elements=_stamp_windows_bcd_entries_custom_elements([
                {
                    "element_type": "0x14000006",
                    "element_value": [
                        "{2afaa8e8-7f8b-11ec-bc6b-e0d4e8ed0d68}"
                    ],
                },
                {
                    "element_type": "0x23000003",
                    "element_value": (
                        "{2afaa8e8-7f8b-11ec-bc6b-e0d4e8ed0d68}"
                    ),
                },
            ]),
            anomaly_flags=_stamp_windows_bcd_entries_anomaly_flags({
                "suspicious_path": False,
                "non_microsoft_description": False,
                "testsigning_enabled": False,
                "no_integrity_checks": False,
                "nx_disabled": False,
                "is_default_boot": True,
            }),
            last_modified_ns="132950000000000000",
        )
        db.add(entry)
        await db.commit()

        # Round-trip SELECT
        rows = (
            await db.execute(
                select(WindowsBcdEntry).where(
                    WindowsBcdEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1

        persisted = rows[0]
        assert persisted.source_path == "Boot/BCD"
        assert persisted.object_guid == (
            "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
        )
        assert persisted.object_type == 0x10100002
        assert persisted.description == "Windows Boot Manager"
        assert persisted.image_path == "\\Windows\\System32\\winload.efi"
        assert persisted.gpt_partition_guid == (
            "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
        )
        assert persisted.testsigning is False
        assert persisted.no_integrity_checks is False
        assert persisted.nx_policy == 0
        assert persisted.last_modified_ns == "132950000000000000"

        # JSONB round-trip (Rule #35c stamped envelope persists end-to-end)
        assert persisted.custom_elements is not None
        assert len(persisted.custom_elements) == 2
        for entry_dict in persisted.custom_elements:
            assert "schema_version" in entry_dict
            assert "element_type" in entry_dict

        assert persisted.anomaly_flags is not None
        assert persisted.anomaly_flags["schema_version"] == 1
        assert persisted.anomaly_flags["suspicious_path"] is False
        assert persisted.anomaly_flags["is_default_boot"] is True


@pytest.mark.asyncio
async def test_bcd_entry_persists_suspicious_anomaly_shape():
    """Rule #35b live canary — round-trip a suspicious-path entry with
    testsigning enabled (θ.A.D HIGH-tier candidate) and confirm the
    anomaly flag aggregate persists end-to-end."""
    async with make_live_db() as db:
        project = Project(name="θ.A.A suspicious canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-sus.bin", "s")
        db.add(firmware)
        await db.flush()

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
            nx_policy=2,  # AlwaysOff
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

        rows = (
            await db.execute(
                select(WindowsBcdEntry).where(
                    WindowsBcdEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1

        persisted = rows[0]
        assert persisted.testsigning is True
        assert persisted.no_integrity_checks is True
        assert persisted.nx_policy == 2
        assert persisted.gpt_partition_guid is None

        # Anomaly flags persist with all signals raised.
        flags = persisted.anomaly_flags
        assert flags is not None
        assert flags["suspicious_path"] is True
        assert flags["non_microsoft_description"] is True
        assert flags["testsigning_enabled"] is True
        assert flags["no_integrity_checks"] is True
        assert flags["nx_disabled"] is True
        assert flags["is_default_boot"] is False


@pytest.mark.asyncio
async def test_bcd_entry_minimal_shape_persists():
    """A BCD entry with only the required columns (firmware_id,
    source_path, object_guid) persists with all other columns NULL."""
    async with make_live_db() as db:
        project = Project(name="θ.A.A minimal canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-min.bin", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsBcdEntry(
            firmware_id=firmware.id,
            source_path="Boot/BCD",
            object_guid="{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}",
        )
        db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsBcdEntry).where(
                    WindowsBcdEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        persisted = rows[0]
        assert persisted.object_type is None
        assert persisted.description is None
        assert persisted.image_path is None
        assert persisted.testsigning is None
        assert persisted.custom_elements is None
        assert persisted.anomaly_flags is None


# ── Index declarations match the alembic migration shape ────────────────────


def test_bcd_entries_indexes_present():
    """Confirm the three indexes from the alembic migration are
    declared on the ORM model so SQLAlchemy + alembic stay aligned."""
    index_names = {idx.name for idx in WindowsBcdEntry.__table__.indexes}
    assert "ix_windows_bcd_entries_firmware" in index_names
    assert "ix_windows_bcd_entries_firmware_guid" in index_names
    assert "ix_windows_bcd_entries_firmware_testsigning" in index_names


def test_bcd_entries_required_columns_not_nullable():
    """firmware_id + source_path + object_guid must be NOT NULL —
    they're the natural-key triple for the table."""
    columns = {c.name: c for c in WindowsBcdEntry.__table__.columns}
    assert columns["firmware_id"].nullable is False
    assert columns["source_path"].nullable is False
    assert columns["object_guid"].nullable is False
    # All other columns are nullable per the alembic migration.
    assert columns["description"].nullable is True
    assert columns["image_path"].nullable is True
    assert columns["testsigning"].nullable is True
