"""Tests for the Phase θ.E.A WindowsMbrVbrSector ORM model.

Per CLAUDE.md Rule #35b live canaries: round-trip via the real ORM
+ ``make_live_db`` SQLite shim to confirm column shapes + index
declarations match the alembic migration intent.

Covers:
- ORM round-trip — create, persist, SELECT, inspect every column.
- JSONB column (anomaly_flags) — Rule #35c stamped envelope persists
  end-to-end.
- Defensive shapes: NULL bootcode_signature_match, NULL known_bootkit_
  match, MBR vs VBR variant fingerprints, cross-firmware aggregation
  query.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsMbrVbrSector
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


# ── ORM round-trip live canaries ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mbr_sector_persists_clean_windows_10_mbr_shape():
    """Rule #35b live canary — round-trip a clean Windows 10 MBR
    entry and confirm every column persists with the expected shape."""
    async with make_live_db() as db:
        project = Project(name="θ.E.A clean-MBR canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows10.img", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="windows10.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="a" * 64,
            sector_size=512,
            bootcode_signature_match="windows_10_mbr",
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": False,
                "unexpected_partition_table": False,
                "non_standard_jmp": False,
                "non_zero_disk_signature": True,
                "is_mbr": True,
                "is_vbr": False,
            }),
            fingerprint_sha256="b" * 64,
        )
        db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsMbrVbrSector).where(
                    WindowsMbrVbrSector.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.file_path == "windows10.img"
        assert r.sector_offset == 0
        assert r.sector_kind == "mbr"
        assert r.sector_sha256 == "a" * 64
        assert r.sector_size == 512
        assert r.bootcode_signature_match == "windows_10_mbr"
        assert r.known_bootkit_match is None
        assert r.fingerprint_sha256 == "b" * 64

        assert isinstance(r.anomaly_flags, dict)
        assert r.anomaly_flags["is_mbr"] is True
        assert r.anomaly_flags["is_vbr"] is False
        assert r.anomaly_flags["non_zero_disk_signature"] is True
        assert r.anomaly_flags["schema_version"] == 1


@pytest.mark.asyncio
async def test_mbr_sector_persists_tdl4_bootkit_shape():
    """Rule #35b live canary — TDL4 bootkit MBR with known_bootkit_match
    populated. Verifies the bootkit-match column accepts the canonical
    string AND the anomaly_flags shape persists alongside."""
    async with make_live_db() as db:
        project = Project(name="θ.E.A TDL4-bootkit canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "infected.img", "t")
        db.add(firmware)
        await db.flush()

        entry = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="infected.img",
            sector_offset=0,
            sector_kind="mbr",
            sector_sha256="c" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match="tdl4_mbr",
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": True,
                "unexpected_partition_table": False,
                "non_standard_jmp": True,
                "non_zero_disk_signature": True,
                "is_mbr": True,
                "is_vbr": False,
            }),
            fingerprint_sha256="d" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsMbrVbrSector).where(
                    WindowsMbrVbrSector.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.known_bootkit_match == "tdl4_mbr"
        assert r.bootcode_signature_match is None
        assert r.anomaly_flags["non_standard_jmp"] is True


@pytest.mark.asyncio
async def test_vbr_ntfs_sector_at_partition_offset():
    """Rule #35b live canary — VBR NTFS sector at a non-zero offset
    (partition 1 starting at 1 MiB)."""
    async with make_live_db() as db:
        project = Project(name="θ.E.A NTFS-VBR canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "win.img", "n")
        db.add(firmware)
        await db.flush()

        entry = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="win.img",
            sector_offset=1_048_576,  # 1 MiB partition start
            sector_kind="vbr_ntfs",
            sector_sha256="e" * 64,
            sector_size=512,
            bootcode_signature_match="windows_7_vbr_ntfs",
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": False,
                "unexpected_partition_table": False,
                "non_standard_jmp": False,
                "non_zero_disk_signature": False,
                "is_mbr": False,
                "is_vbr": True,
            }),
            fingerprint_sha256="f" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsMbrVbrSector).where(
                    WindowsMbrVbrSector.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.sector_kind == "vbr_ntfs"
        assert r.sector_offset == 1_048_576
        assert r.bootcode_signature_match == "windows_7_vbr_ntfs"


@pytest.mark.asyncio
async def test_mbr_sector_cross_firmware_fingerprint_aggregation():
    """Rule #35b live canary — two firmware with the same fingerprint
    (same bootkit planted across both). Verify the cross-firmware
    aggregation query returns both rows."""
    async with make_live_db() as db:
        project = Project(name="θ.E.A cross-firmware canary")
        db.add(project)
        await db.flush()

        firmware_a = _make_firmware(project.id, "infected_a.img", "a")
        firmware_b = _make_firmware(project.id, "infected_b.img", "b")
        db.add_all([firmware_a, firmware_b])
        await db.flush()

        shared_fp = "deadbeef" * 8  # 64 hex
        for fw in (firmware_a, firmware_b):
            entry = WindowsMbrVbrSector(
                firmware_id=fw.id,
                file_path=fw.original_filename,
                sector_offset=0,
                sector_kind="mbr",
                sector_sha256="cafe" * 16,  # same hash both
                sector_size=512,
                bootcode_signature_match=None,
                known_bootkit_match="petya_mbr",
                anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                    "non_zero_padding": True,
                    "unexpected_partition_table": True,
                    "non_standard_jmp": True,
                    "non_zero_disk_signature": False,
                    "is_mbr": True,
                    "is_vbr": False,
                }),
                fingerprint_sha256=shared_fp,
            )
            db.add(entry)
        await db.commit()

        # Cross-firmware aggregation by fingerprint.
        rows = (
            await db.execute(
                select(WindowsMbrVbrSector).where(
                    WindowsMbrVbrSector.fingerprint_sha256 == shared_fp
                )
            )
        ).scalars().all()
        assert len(rows) == 2
        firmware_ids = {r.firmware_id for r in rows}
        assert firmware_ids == {firmware_a.id, firmware_b.id}
        # All rows share the bootkit match.
        assert all(r.known_bootkit_match == "petya_mbr" for r in rows)


@pytest.mark.asyncio
async def test_mbr_sector_unknown_kind_persists():
    """Rule #35b live canary — unknown sector_kind (has magic but no
    FS signature) persists cleanly. CHECK constraint allows 'unknown'."""
    async with make_live_db() as db:
        project = Project(name="θ.E.A unknown-sector canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "weird.img", "u")
        db.add(firmware)
        await db.flush()

        entry = WindowsMbrVbrSector(
            firmware_id=firmware.id,
            file_path="weird.img",
            sector_offset=512,
            sector_kind="unknown",
            sector_sha256="1" * 64,
            sector_size=512,
            bootcode_signature_match=None,
            known_bootkit_match=None,
            anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
                "non_zero_padding": True,
                "unexpected_partition_table": False,
                "non_standard_jmp": False,
                "non_zero_disk_signature": False,
                "is_mbr": False,
                "is_vbr": False,
            }),
            fingerprint_sha256=None,  # parse-fail case
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsMbrVbrSector).where(
                    WindowsMbrVbrSector.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.sector_kind == "unknown"
        assert r.fingerprint_sha256 is None
