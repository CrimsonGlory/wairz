"""Tests for the WindowsMftRecord ORM model (Phase η.A.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.

Rule #35c JSONB normalizer pass-through verified via the
ads_streams + target_metadata columns; defensive coercion + idempotency
also covered.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsMftRecord
from app.services.jsonb_normalizers import (
    _normalize_windows_mft_records_ads_streams,
    _normalize_windows_mft_records_target_metadata,
    _stamp_windows_mft_records_ads_streams,
    _stamp_windows_mft_records_target_metadata,
)
from tests._live_db import make_live_db


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_windows_mft_record_round_trip_full_columns():
    """Insert a realistic NTFS file segment with all columns populated,
    SELECT it back, and verify every field round-trips. Rule #35b
    live-canary pattern."""
    async with make_live_db() as db:
        project = Project(name="η.A.A canary full")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-full.bin", "f")
        db.add(firmware)
        await db.flush()

        ads_streams = _stamp_windows_mft_records_ads_streams([
            {"name": "Zone.Identifier", "size": 130, "data_size": 130},
            {"name": "hidden", "size": 4096, "data_size": 4096},
        ])
        target_metadata = _stamp_windows_mft_records_target_metadata({
            "parent_segment_ref": 5,
            "reparse_point": False,
            "attribute_flags": 1,
            "hard_link_count": 1,
            "sequence_number": 4,
        })

        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/disk0.raw",
            segment_number=42,
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
            ads_streams=ads_streams,
            target_metadata=target_metadata,
            image_segment_count=200_000,
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.id == record.id
                )
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert persisted.source_path == "images/disk0.raw"
        assert persisted.segment_number == 42
        assert persisted.in_use is True
        assert persisted.is_directory is False
        assert persisted.full_path == "Windows\\System32\\cmd.exe"
        assert persisted.filename == "cmd.exe"
        assert persisted.file_size == 289_792
        assert persisted.si_creation_ns == 132_000_000_000_000_000
        assert persisted.si_last_modification_ns == 132_500_000_000_000_000
        assert persisted.fn_creation_ns == 132_000_000_000_000_000
        assert persisted.fn_last_modification_ns == 132_000_000_000_000_000
        assert persisted.image_segment_count == 200_000

        # JSONB columns round-trip through the normalizers at the read
        # boundary (Rule #35c).
        ads = _normalize_windows_mft_records_ads_streams(
            persisted.ads_streams
        )
        assert len(ads) == 2
        assert {a["name"] for a in ads} == {"Zone.Identifier", "hidden"}
        for entry in ads:
            assert entry["schema_version"] == 1

        meta = _normalize_windows_mft_records_target_metadata(
            persisted.target_metadata
        )
        assert meta["schema_version"] == 1
        assert meta["parent_segment_ref"] == 5
        assert meta["reparse_point"] is False

        assert persisted.created_at is not None


@pytest.mark.asyncio
async def test_windows_mft_record_minimal_required_columns_only():
    """Confirm every column EXCEPT firmware_id / source_path /
    segment_number / in_use / is_directory is nullable per the model."""
    async with make_live_db() as db:
        project = Project(name="η.A.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-min.bin", "n")
        db.add(firmware)
        await db.flush()

        # Minimal record — only NOT NULL columns populated. Orphaned
        # deleted segment.
        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/orphan.raw",
            segment_number=0,
            in_use=False,
            is_directory=False,
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.id == record.id
                )
            )
        ).scalar_one()

        for field in (
            "full_path",
            "filename",
            "file_size",
            "si_creation_ns",
            "si_last_modification_ns",
            "si_last_change_ns",
            "si_last_access_ns",
            "fn_creation_ns",
            "fn_last_modification_ns",
            "fn_last_change_ns",
            "fn_last_access_ns",
            "ads_streams",
            "target_metadata",
            "image_segment_count",
        ):
            assert getattr(persisted, field) is None, f"{field} should be null"


@pytest.mark.asyncio
async def test_windows_mft_record_deleted_segment_round_trips():
    """A deleted-but-unreaped MFT segment is still surfaced
    (FILE_RECORD_SEGMENT_IN_USE flag clear)."""
    async with make_live_db() as db:
        project = Project(name="η.A.A deleted canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-del.bin", "d")
        db.add(firmware)
        await db.flush()

        # An attacker-removed file whose metadata is still recoverable
        # from the unreaped MFT slot.
        record = WindowsMftRecord(
            firmware_id=firmware.id,
            source_path="images/disk0.raw",
            segment_number=900_000,
            in_use=False,
            is_directory=False,
            full_path="Users\\victim\\AppData\\Local\\Temp\\dropper.exe",
            filename="dropper.exe",
            file_size=204_800,
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.id == record.id
                )
            )
        ).scalar_one()
        assert persisted.in_use is False
        assert persisted.filename == "dropper.exe"


@pytest.mark.asyncio
async def test_windows_mft_record_multiple_per_firmware():
    """A single firmware can carry many MFT records (Win10 install
    runs to ~150k segments)."""
    async with make_live_db() as db:
        project = Project(name="η.A.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "m")
        db.add(firmware)
        await db.flush()

        names = ["cmd.exe", "notepad.exe", "powershell.exe", "rundll32.exe"]
        for idx, n in enumerate(names):
            db.add(
                WindowsMftRecord(
                    firmware_id=firmware.id,
                    source_path="images/disk0.raw",
                    segment_number=100 + idx,
                    in_use=True,
                    is_directory=False,
                    full_path=f"Windows\\System32\\{n}",
                    filename=n,
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 4
        assert {r.filename for r in rows} == set(names)


def test_windows_mft_records_normalizer_handles_legacy_and_none():
    """Defensive: normalizer accepts None / wrong-typed shapes
    idempotently (Rule #35c)."""
    # ads_streams — list-shaped column.
    assert _normalize_windows_mft_records_ads_streams(None) == []
    assert _normalize_windows_mft_records_ads_streams("garbage") == []
    assert _normalize_windows_mft_records_ads_streams(42) == []
    canonical = [{"name": "Zone.Identifier", "size": 130, "data_size": None}]
    assert _normalize_windows_mft_records_ads_streams(canonical) == canonical

    # target_metadata — dict-shaped column.
    assert _normalize_windows_mft_records_target_metadata(None) == {}
    assert _normalize_windows_mft_records_target_metadata("garbage") == {}
    assert _normalize_windows_mft_records_target_metadata([{"a": 1}]) == {}
    raw = {"parent_segment_ref": 5, "reparse_point": False}
    assert _normalize_windows_mft_records_target_metadata(raw) == raw


def test_firmware_mft_walk_result_normalizer_handles_none_and_wrong_type():
    """firmware.mft_walk_result accepts dict OR None; wrong-typed → None."""
    from app.services.jsonb_normalizers import (
        _normalize_firmware_mft_walk_result,
        _stamp_firmware_mft_walk_result,
    )

    assert _normalize_firmware_mft_walk_result(None) is None
    assert _normalize_firmware_mft_walk_result("string") is None
    assert _normalize_firmware_mft_walk_result(["list"]) is None
    raw = {"records_walked": 5000, "run_seconds": 1.2}
    assert _normalize_firmware_mft_walk_result(raw) == raw

    once = _stamp_firmware_mft_walk_result(dict(raw))
    twice = _stamp_firmware_mft_walk_result(once.copy())
    assert once["schema_version"] == twice["schema_version"] == 1
