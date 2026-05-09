"""Tests for the WindowsPrefetchRecord ORM model (Phase ζ.2.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsPrefetchRecord
from tests._live_db import make_live_db


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Helper — Firmware requires project_id + sha256; the rest are nullable.

    Centralised per ε.2.A's `_make_firmware` shape (closed antipattern from
    that phase's initial test failures: wrong constructor args).
    """
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_windows_prefetch_record_round_trip():
    """Insert a WindowsPrefetchRecord with realistic Win10 fields,
    SELECT it back, and verify every column reflects the constructor
    args (Rule #35b live-canary pattern)."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.A canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-roundtrip.bin", "p")
        db.add(firmware)
        await db.flush()

        last_run = datetime.datetime(2026, 5, 9, 14, 23, 45, tzinfo=datetime.UTC)
        record = WindowsPrefetchRecord(
            firmware_id=firmware.id,
            prefetch_file_path="Windows/Prefetch/CHROME.EXE-AB1234CD.pf",
            executable_name="CHROME.EXE",
            prefetch_hash="ab1234cd",
            version=30,
            run_count=42,
            last_run_time=last_run,
            all_run_times={
                "schema_version": 1,
                "items": [
                    "2026-05-09T14:23:45+00:00",
                    "2026-05-09T13:00:00+00:00",
                    "2026-05-08T09:30:15+00:00",
                ],
            },
            filenames_referenced={
                "schema_version": 1,
                "items": [
                    "\\VOLUME{...}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                    "\\VOLUME{...}\\WINDOWS\\SYSTEM32\\KERNELBASE.DLL",
                    "\\VOLUME{...}\\PROGRAM FILES\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE",
                ],
            },
            volumes={
                "schema_version": 1,
                "items": [
                    {
                        "device_path": "\\DEVICE\\HARDDISKVOLUME3",
                        "serial_number": "12345678",
                        "creation_time": "2025-09-01T08:00:00+00:00",
                    }
                ],
            },
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsPrefetchRecord).where(
                    WindowsPrefetchRecord.id == record.id
                )
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert (
            persisted.prefetch_file_path
            == "Windows/Prefetch/CHROME.EXE-AB1234CD.pf"
        )
        assert persisted.executable_name == "CHROME.EXE"
        assert persisted.prefetch_hash == "ab1234cd"
        assert persisted.version == 30
        assert persisted.run_count == 42
        assert persisted.last_run_time == last_run
        assert persisted.all_run_times["schema_version"] == 1
        assert len(persisted.all_run_times["items"]) == 3
        assert persisted.filenames_referenced["schema_version"] == 1
        assert (
            persisted.filenames_referenced["items"][2].endswith("CHROME.EXE")
        )
        assert persisted.volumes["schema_version"] == 1
        assert (
            persisted.volumes["items"][0]["device_path"]
            == "\\DEVICE\\HARDDISKVOLUME3"
        )
        assert persisted.created_at is not None  # server_default fired


@pytest.mark.asyncio
async def test_windows_prefetch_record_nullable_fields():
    """Confirm prefetch_hash / version / run_count / last_run_time /
    all_run_times / filenames_referenced / volumes are all nullable per
    the model definition. Only firmware_id / prefetch_file_path /
    executable_name are NOT NULL."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-nullable.bin", "q")
        db.add(firmware)
        await db.flush()

        # Minimal record — only the NOT NULL columns populated.
        record = WindowsPrefetchRecord(
            firmware_id=firmware.id,
            prefetch_file_path="Windows/Prefetch/UNKNOWN.pf",
            executable_name="UNKNOWN.EXE",
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsPrefetchRecord).where(
                    WindowsPrefetchRecord.id == record.id
                )
            )
        ).scalar_one()

        assert persisted.prefetch_hash is None
        assert persisted.version is None
        assert persisted.run_count is None
        assert persisted.last_run_time is None
        assert persisted.all_run_times is None
        assert persisted.filenames_referenced is None
        assert persisted.volumes is None


@pytest.mark.asyncio
async def test_windows_prefetch_record_multiple_per_firmware():
    """A single firmware can carry many prefetch records (no UNIQUE
    constraint on firmware_id alone — operators expect 100s of .pf files
    per Win10 install)."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "r")
        db.add(firmware)
        await db.flush()

        names = [
            "CHROME.EXE",
            "CMD.EXE",
            "POWERSHELL.EXE",
            "RUNDLL32.EXE",
            "SVCHOST.EXE",
        ]
        for i, name in enumerate(names):
            db.add(
                WindowsPrefetchRecord(
                    firmware_id=firmware.id,
                    prefetch_file_path=f"Windows/Prefetch/{name}-{i:08X}.pf",
                    executable_name=name,
                    run_count=i + 1,
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsPrefetchRecord).where(
                    WindowsPrefetchRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 5
        assert {r.executable_name for r in rows} == set(names)
