"""Tests for the WindowsSrumRecord ORM model (Phase ζ.3.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsSrumRecord
from tests._live_db import make_live_db


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory (closes ε.2.A constructor-arg antipattern)."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_windows_srum_record_round_trip_network_data_usage():
    """Insert a SRUM network_data_usage record with realistic Win11
    fields, SELECT it back, and verify every column reflects the
    constructor args (Rule #35b live-canary pattern)."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.A canary network")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-net.bin", "n")
        db.add(firmware)
        await db.flush()

        recorded = datetime.datetime(2026, 5, 9, 14, 23, 45, tzinfo=datetime.UTC)
        record = WindowsSrumRecord(
            firmware_id=firmware.id,
            record_type="network_data_usage",
            source_path="Windows/System32/sru/SRUDB.dat",
            app_identifier="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            user_identifier="S-1-5-21-1234567890-...-1001",
            recorded_at=recorded,
            bytes_sent=1024 * 1024 * 50,
            bytes_received=1024 * 1024 * 200,
            interface_luid=0x0123456789ABCDEF,
            extra_metadata={
                "schema_version": 1,
                "guid_table": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            },
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsSrumRecord).where(
                    WindowsSrumRecord.id == record.id
                )
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert persisted.record_type == "network_data_usage"
        assert persisted.source_path == "Windows/System32/sru/SRUDB.dat"
        assert persisted.app_identifier.endswith("chrome.exe")
        assert persisted.user_identifier.startswith("S-1-5-21-")
        assert persisted.recorded_at == recorded
        assert persisted.bytes_sent == 1024 * 1024 * 50
        assert persisted.bytes_received == 1024 * 1024 * 200
        assert persisted.interface_luid == 0x0123456789ABCDEF
        assert persisted.extra_metadata["schema_version"] == 1
        assert persisted.extra_metadata["guid_table"].startswith("{973F5D5C")
        assert persisted.created_at is not None


@pytest.mark.asyncio
async def test_windows_srum_record_application_resource_usage_typed_columns():
    """application_resource_usage record populates CPU + bytes_read/written
    columns; network columns left null."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.A canary cpu")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-cpu.bin", "c")
        db.add(firmware)
        await db.flush()

        record = WindowsSrumRecord(
            firmware_id=firmware.id,
            record_type="application_resource_usage",
            source_path="Windows/System32/sru/SRUDB.dat",
            app_identifier="cmd.exe",
            cpu_foreground_seconds=120,
            cpu_background_seconds=45,
            bytes_read=1024 * 1024,
            bytes_written=512 * 1024,
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsSrumRecord).where(
                    WindowsSrumRecord.id == record.id
                )
            )
        ).scalar_one()
        assert persisted.cpu_foreground_seconds == 120
        assert persisted.cpu_background_seconds == 45
        assert persisted.bytes_read == 1024 * 1024
        assert persisted.bytes_written == 512 * 1024
        # Cross-type fields nullable.
        assert persisted.bytes_sent is None
        assert persisted.bytes_received is None
        assert persisted.push_count is None
        assert persisted.energy_charge is None


@pytest.mark.asyncio
async def test_windows_srum_record_multiple_per_firmware():
    """A single firmware can carry many SRUM records (Win11 SRUDB.dat
    typically contains 10K+ rows across the 5 record types)."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "m")
        db.add(firmware)
        await db.flush()

        types = [
            "network_data_usage",
            "network_connectivity",
            "application_resource_usage",
            "push_notification",
            "energy_usage",
        ]
        for i, rt in enumerate(types):
            db.add(
                WindowsSrumRecord(
                    firmware_id=firmware.id,
                    record_type=rt,
                    source_path="Windows/System32/sru/SRUDB.dat",
                    app_identifier=f"app{i}.exe",
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsSrumRecord).where(
                    WindowsSrumRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 5
        assert {r.record_type for r in rows} == set(types)


@pytest.mark.asyncio
async def test_windows_srum_record_nullable_fields():
    """Confirm app_identifier / user_identifier / recorded_at / all
    typed metric columns / extra_metadata are nullable per the model."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-nullable.bin", "u")
        db.add(firmware)
        await db.flush()

        # Minimal record — only NOT NULL columns populated.
        record = WindowsSrumRecord(
            firmware_id=firmware.id,
            record_type="push_notification",
            source_path="Windows/System32/sru/SRUDB.dat",
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsSrumRecord).where(
                    WindowsSrumRecord.id == record.id
                )
            )
        ).scalar_one()

        for field in (
            "app_identifier",
            "user_identifier",
            "recorded_at",
            "bytes_sent",
            "bytes_received",
            "bytes_read",
            "bytes_written",
            "interface_luid",
            "duration_seconds",
            "cpu_foreground_seconds",
            "cpu_background_seconds",
            "push_count",
            "energy_charge",
            "energy_capacity",
            "extra_metadata",
        ):
            assert getattr(persisted, field) is None, f"{field} should be null"
