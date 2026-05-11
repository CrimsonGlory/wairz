"""Tests for the WindowsLnkRecord ORM model (Phase η.C.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsLnkRecord
from app.services.jsonb_normalizers import (
    _normalize_windows_lnk_records_target_metadata,
    _stamp_windows_lnk_records_target_metadata,
)
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
async def test_windows_lnk_record_round_trip_realistic_firefox():
    """Insert a realistic Firefox-shape Shell Link record with all flat
    columns + JSONB populated, SELECT it back, and verify every column
    reflects the constructor args (Rule #35b live-canary pattern)."""
    async with make_live_db() as db:
        project = Project(name="η.C.A canary firefox")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-firefox.bin", "f")
        db.add(firmware)
        await db.flush()

        creation = datetime.datetime(
            2024, 1, 15, 10, 30, 0, tzinfo=datetime.UTC
        )
        accessed = datetime.datetime(
            2024, 6, 20, 15, 45, 30, tzinfo=datetime.UTC
        )
        modified = datetime.datetime(
            2024, 6, 20, 15, 45, 30, tzinfo=datetime.UTC
        )

        target_metadata = _stamp_windows_lnk_records_target_metadata(
            {
                "size": 1234,
                "header": {
                    "guid": "00021401-0000-0000-c000-000000000046",
                    "creation_time": creation.isoformat(),
                    "accessed_time": accessed.isoformat(),
                    "modified_time": modified.isoformat(),
                    "windowstyle": "SW_SHOWNORMAL",
                    "hotkey": "UNSET - UNSET {0x0000}",
                    "icon_index": 0,
                    "file_size": 0,
                    "link_flags": [
                        "HasName",
                        "HasLinkInfo",
                        "HasRelativePath",
                        "HasWorkingDir",
                        "HasIconLocation",
                        "IsUnicode",
                    ],
                    "file_flags": ["FILE_ATTRIBUTE_ARCHIVE"],
                },
                "link_info": {
                    "local_base_path": (
                        "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
                    ),
                },
                "data": {
                    "description": "Mozilla Firefox",
                    "relative_path": "..\\..\\..\\Program Files\\Mozilla Firefox\\firefox.exe",
                    "working_directory": "C:\\Program Files\\Mozilla Firefox",
                    "command_line_arguments": "",
                    "icon_location": (
                        "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
                    ),
                },
                "extra": {},
            }
        )

        record = WindowsLnkRecord(
            firmware_id=firmware.id,
            source_path=(
                "Users/dustin/AppData/Roaming/Microsoft/Windows/"
                "Start Menu/Programs/Firefox.lnk"
            ),
            lnk_filename="Firefox.lnk",
            target_path="C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            working_directory="C:\\Program Files\\Mozilla Firefox",
            arguments="",
            description="Mozilla Firefox",
            icon_location=(
                "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
            ),
            show_command="SW_SHOWNORMAL",
            hotkey="UNSET - UNSET {0x0000}",
            creation_time=creation,
            accessed_time=accessed,
            modified_time=modified,
            target_metadata=target_metadata,
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsLnkRecord).where(
                    WindowsLnkRecord.id == record.id
                )
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert persisted.source_path.endswith("Firefox.lnk")
        assert persisted.lnk_filename == "Firefox.lnk"
        assert (
            persisted.target_path
            == "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
        )
        assert (
            persisted.working_directory
            == "C:\\Program Files\\Mozilla Firefox"
        )
        assert persisted.arguments == ""
        assert persisted.description == "Mozilla Firefox"
        assert persisted.show_command == "SW_SHOWNORMAL"
        assert persisted.hotkey == "UNSET - UNSET {0x0000}"
        assert persisted.creation_time == creation
        assert persisted.accessed_time == accessed
        assert persisted.modified_time == modified

        # JSONB column round-trips through the normalizer at the read
        # boundary (Rule #35c).
        meta = _normalize_windows_lnk_records_target_metadata(
            persisted.target_metadata
        )
        assert meta["schema_version"] == 1
        assert meta["data"]["description"] == "Mozilla Firefox"
        assert (
            meta["link_info"]["local_base_path"]
            == "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
        )

        assert persisted.created_at is not None


@pytest.mark.asyncio
async def test_windows_lnk_record_minimal_required_columns_only():
    """Confirm target_path / working_directory / arguments / description /
    icon_location / show_command / hotkey / MAC times / target_metadata
    are nullable per the model."""
    async with make_live_db() as db:
        project = Project(name="η.C.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-nullable.bin", "n")
        db.add(firmware)
        await db.flush()

        # Minimal LNK — only NOT NULL columns populated.
        record = WindowsLnkRecord(
            firmware_id=firmware.id,
            source_path="Users/dustin/Desktop/empty.lnk",
            lnk_filename="empty.lnk",
        )
        db.add(record)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsLnkRecord).where(
                    WindowsLnkRecord.id == record.id
                )
            )
        ).scalar_one()

        for field in (
            "target_path",
            "working_directory",
            "arguments",
            "description",
            "icon_location",
            "show_command",
            "hotkey",
            "creation_time",
            "accessed_time",
            "modified_time",
            "target_metadata",
        ):
            assert getattr(persisted, field) is None, f"{field} should be null"


@pytest.mark.asyncio
async def test_windows_lnk_record_multiple_per_firmware():
    """A single firmware can carry many LNK records (Recent docs alone
    averages 30-100 LNKs in a healthy Win10/11 user profile)."""
    async with make_live_db() as db:
        project = Project(name="η.C.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "m")
        db.add(firmware)
        await db.flush()

        names = ["Firefox.lnk", "Excel.lnk", "Notepad.lnk", "cmd.lnk"]
        for n in names:
            db.add(
                WindowsLnkRecord(
                    firmware_id=firmware.id,
                    source_path=(
                        f"Users/dustin/AppData/Roaming/Microsoft/Windows/"
                        f"Start Menu/Programs/{n}"
                    ),
                    lnk_filename=n,
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsLnkRecord).where(
                    WindowsLnkRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 4
        assert {r.lnk_filename for r in rows} == set(names)


@pytest.mark.asyncio
async def test_windows_lnk_records_jsonb_normalizer_idempotent():
    """Rule #35c: stamping a payload that's already stamped is a no-op."""
    raw = {
        "header": {"guid": "00021401-..."},
        "data": {"description": "Foo"},
    }
    once = _stamp_windows_lnk_records_target_metadata(dict(raw))
    twice = _stamp_windows_lnk_records_target_metadata(once.copy())
    assert once["schema_version"] == twice["schema_version"] == 1
    assert (
        _normalize_windows_lnk_records_target_metadata(once)
        == _normalize_windows_lnk_records_target_metadata(twice)
    )


def test_windows_lnk_records_normalizer_handles_legacy_and_none():
    """Defensive: normalizer accepts None / wrong-typed shapes
    idempotently (Rule #35c)."""
    assert _normalize_windows_lnk_records_target_metadata(None) == {}
    assert _normalize_windows_lnk_records_target_metadata("garbage") == {}
    assert _normalize_windows_lnk_records_target_metadata(["bad"]) == {}
    raw = {"header": {"guid": "x"}, "data": {"description": "y"}}
    assert _normalize_windows_lnk_records_target_metadata(raw) == raw


def test_firmware_lnk_walk_result_normalizer_handles_none_and_wrong_type():
    """firmware.lnk_walk_result accepts dict OR None; wrong-typed → None."""
    from app.services.jsonb_normalizers import (
        _normalize_firmware_lnk_walk_result,
        _stamp_firmware_lnk_walk_result,
    )

    assert _normalize_firmware_lnk_walk_result(None) is None
    assert _normalize_firmware_lnk_walk_result("string") is None
    assert _normalize_firmware_lnk_walk_result(["list"]) is None
    raw = {"lnk_count": 5, "run_seconds": 1.2}
    assert _normalize_firmware_lnk_walk_result(raw) == raw

    once = _stamp_firmware_lnk_walk_result(dict(raw))
    twice = _stamp_firmware_lnk_walk_result(once.copy())
    assert once["schema_version"] == twice["schema_version"] == 1
