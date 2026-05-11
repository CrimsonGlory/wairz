"""Tests for the WindowsScheduledTask ORM model (Phase η.B.A).

Rule #35b live canary — ORM round-trip + SELECT verifies that the
constructor args land on the persisted row exactly. Not a mock unit test.
"""
from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsScheduledTask
from app.services.jsonb_normalizers import (
    _normalize_windows_scheduled_tasks_actions,
    _normalize_windows_scheduled_tasks_principal,
    _normalize_windows_scheduled_tasks_settings,
    _normalize_windows_scheduled_tasks_triggers,
    _stamp_windows_scheduled_tasks_actions,
    _stamp_windows_scheduled_tasks_principal,
    _stamp_windows_scheduled_tasks_settings,
    _stamp_windows_scheduled_tasks_triggers,
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
async def test_windows_scheduled_task_round_trip_realistic_winsat():
    """Insert a realistic WinSAT-shape Scheduled Task with all 4 JSONB
    columns populated, SELECT it back, and verify every column reflects
    the constructor args (Rule #35b live-canary pattern)."""
    async with make_live_db() as db:
        project = Project(name="η.B.A canary winsat")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-winsat.bin", "w")
        db.add(firmware)
        await db.flush()

        registered = datetime.datetime(
            2019, 9, 15, 22, 35, 8, tzinfo=datetime.UTC
        )
        triggers = _stamp_windows_scheduled_tasks_triggers(
            [
                {
                    "type": "CalendarTrigger",
                    "enabled": True,
                    "start_boundary": "2009-04-08T19:30:00",
                    "end_boundary": None,
                    "details": {"schedule_type": "ScheduleByWeek"},
                }
            ]
        )
        actions = _stamp_windows_scheduled_tasks_actions(
            [
                {
                    "type": "Exec",
                    "command": "%windir%\\system32\\WinSAT.exe",
                    "arguments": "formal",
                    "working_directory": None,
                    "class_id": None,
                    "details": {},
                }
            ]
        )
        principal = _stamp_windows_scheduled_tasks_principal(
            {
                "id": "S-1-5-19",
                "user_id": "S-1-5-19",
                "run_level": "HighestAvailable",
                "logon_type": None,
                "process_token_sid_type": None,
            }
        )
        settings = _stamp_windows_scheduled_tasks_settings(
            {
                "Enabled": True,
                "Hidden": True,
                "AllowDemandStart": True,
                "DisallowStartIfOnBatteries": False,
            }
        )

        task = WindowsScheduledTask(
            firmware_id=firmware.id,
            source_path="Windows/System32/Tasks/Microsoft/Windows/Maintenance/WinSAT",
            task_uri="\\Microsoft\\Windows\\Maintenance\\WinSAT",
            task_name="WinSAT",
            author="Microsoft Corporation",
            registration_date=registered,
            run_level="HighestAvailable",
            run_as_user="S-1-5-19",
            triggers=triggers,
            actions=actions,
            principal=principal,
            settings=settings,
        )
        db.add(task)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsScheduledTask).where(
                    WindowsScheduledTask.id == task.id
                )
            )
        ).scalar_one()

        assert persisted.firmware_id == firmware.id
        assert persisted.source_path.endswith("Maintenance/WinSAT")
        assert persisted.task_uri == "\\Microsoft\\Windows\\Maintenance\\WinSAT"
        assert persisted.task_name == "WinSAT"
        assert persisted.author == "Microsoft Corporation"
        assert persisted.registration_date == registered
        assert persisted.run_level == "HighestAvailable"
        assert persisted.run_as_user == "S-1-5-19"

        # JSONB columns round-trip through the normalizer at the read
        # boundary (Rule #35c).
        actions_read = _normalize_windows_scheduled_tasks_actions(
            persisted.actions
        )
        assert len(actions_read) == 1
        assert actions_read[0]["command"] == "%windir%\\system32\\WinSAT.exe"
        assert actions_read[0]["arguments"] == "formal"

        triggers_read = _normalize_windows_scheduled_tasks_triggers(
            persisted.triggers
        )
        assert len(triggers_read) == 1
        assert triggers_read[0]["type"] == "CalendarTrigger"
        assert triggers_read[0]["enabled"] is True

        principal_read = _normalize_windows_scheduled_tasks_principal(
            persisted.principal
        )
        assert principal_read["id"] == "S-1-5-19"
        assert principal_read["run_level"] == "HighestAvailable"
        assert principal_read["schema_version"] == 1

        settings_read = _normalize_windows_scheduled_tasks_settings(
            persisted.settings
        )
        assert settings_read["Enabled"] is True
        assert settings_read["Hidden"] is True

        assert persisted.created_at is not None


@pytest.mark.asyncio
async def test_windows_scheduled_task_minimal_required_columns_only():
    """Confirm task_uri / author / registration_date / run_level /
    run_as_user / all 4 JSONB columns are nullable per the model."""
    async with make_live_db() as db:
        project = Project(name="η.B.A nullable canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-nullable.bin", "n")
        db.add(firmware)
        await db.flush()

        # Minimal task — only NOT NULL columns populated.
        task = WindowsScheduledTask(
            firmware_id=firmware.id,
            source_path="Windows/System32/Tasks/Foo",
            task_name="Foo",
        )
        db.add(task)
        await db.commit()

        persisted = (
            await db.execute(
                select(WindowsScheduledTask).where(
                    WindowsScheduledTask.id == task.id
                )
            )
        ).scalar_one()

        for field in (
            "task_uri",
            "author",
            "registration_date",
            "run_level",
            "run_as_user",
            "triggers",
            "actions",
            "principal",
            "settings",
        ):
            assert getattr(persisted, field) is None, f"{field} should be null"


@pytest.mark.asyncio
async def test_windows_scheduled_task_multiple_per_firmware():
    """A single firmware can carry many scheduled tasks (Win11 ships
    ~150-200 task XMLs under \\Microsoft\\Windows\\)."""
    async with make_live_db() as db:
        project = Project(name="η.B.A multi canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-multi.bin", "m")
        db.add(firmware)
        await db.flush()

        names = ["WinSAT", "ScheduledStart", "OneDriveSync"]
        for n in names:
            db.add(
                WindowsScheduledTask(
                    firmware_id=firmware.id,
                    source_path=f"Windows/System32/Tasks/{n}",
                    task_name=n,
                )
            )
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsScheduledTask).where(
                    WindowsScheduledTask.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert {r.task_name for r in rows} == set(names)


@pytest.mark.asyncio
async def test_windows_scheduled_tasks_jsonb_normalizers_idempotent():
    """Rule #35c: stamping a payload that's already stamped is a no-op."""
    raw_triggers = [{"type": "CalendarTrigger", "enabled": True}]
    once = _stamp_windows_scheduled_tasks_triggers(raw_triggers)
    twice = _stamp_windows_scheduled_tasks_triggers(once)
    assert once == twice
    assert (
        _normalize_windows_scheduled_tasks_triggers(once)
        == _normalize_windows_scheduled_tasks_triggers(twice)
    )

    raw_actions = [{"type": "Exec", "command": "C:\\foo.exe"}]
    once_a = _stamp_windows_scheduled_tasks_actions(raw_actions)
    twice_a = _stamp_windows_scheduled_tasks_actions(once_a)
    assert once_a == twice_a

    raw_principal = {"id": "S-1-5-18", "user_id": "S-1-5-18"}
    once_p = _stamp_windows_scheduled_tasks_principal(raw_principal)
    twice_p = _stamp_windows_scheduled_tasks_principal(once_p.copy())
    assert once_p["schema_version"] == twice_p["schema_version"] == 1

    raw_settings = {"Enabled": True}
    once_s = _stamp_windows_scheduled_tasks_settings(raw_settings)
    twice_s = _stamp_windows_scheduled_tasks_settings(once_s.copy())
    assert once_s["schema_version"] == twice_s["schema_version"] == 1


def test_windows_scheduled_tasks_normalizers_handle_legacy_and_none():
    """Defensive: normalizer accepts None / wrong-typed / bare-list legacy
    shapes idempotently (Rule #35c)."""
    # triggers / actions: list-shaped, accept envelope OR bare list OR None.
    assert _normalize_windows_scheduled_tasks_triggers(None) == []
    assert _normalize_windows_scheduled_tasks_triggers("garbage") == []
    bare_list = [{"type": "CalendarTrigger"}]
    assert _normalize_windows_scheduled_tasks_triggers(bare_list) == bare_list
    enveloped = {"schema_version": 1, "items": bare_list}
    assert _normalize_windows_scheduled_tasks_triggers(enveloped) == bare_list

    assert _normalize_windows_scheduled_tasks_actions(None) == []
    assert _normalize_windows_scheduled_tasks_actions(["not-dict"]) == []

    # principal / settings: dict-shaped, accept dict OR None.
    assert _normalize_windows_scheduled_tasks_principal(None) == {}
    assert _normalize_windows_scheduled_tasks_principal("garbage") == {}
    raw_p = {"id": "S-1-5-18"}
    assert _normalize_windows_scheduled_tasks_principal(raw_p) == raw_p

    assert _normalize_windows_scheduled_tasks_settings(None) == {}
    assert _normalize_windows_scheduled_tasks_settings(["bad"]) == {}
    raw_s = {"Enabled": True}
    assert _normalize_windows_scheduled_tasks_settings(raw_s) == raw_s
