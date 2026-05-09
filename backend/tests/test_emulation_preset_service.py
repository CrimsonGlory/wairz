"""Service-layer tests for ``app.services.emulation_preset_service``.

Phase 2 Wave 10 file 2 of 2 — backfills service-layer tests for the
EmulationPreset CRUD service (88 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Triage shape (Rule #19 evidence-first):

* ORM persistence — every method writes to ``emulation_presets``.
  Strong canary candidate: mock-only tests would verify "db.add was
  called" but NOT "the persisted EmulationPreset row reflects the
  right project_id/mode/port_forwards/stub_profile".
* No lazy imports — ORM model + ``select`` are top-level.
* No external boundary — pure DB.

Rule #30 distribution: ``EmulationPreset`` ORM model + ``select`` are
TOP-LEVEL imported on lines 8 + 11. Inverse-Rule-30 shape applies.

Coverage targets:

* ``create_preset`` — minimal happy path: required fields persisted,
  optional fields defaulted; SELECT round-trip confirms shape.
* ``create_preset`` — full kwarg payload round-trips through
  port_forwards (JSONB list[dict]) + stub_profile + pre_init_script.
* ``create_preset`` — port_forwards=None defaults to empty list.
* ``list_presets`` — empty project returns [].
* ``list_presets`` — DESC ordering by created_at across multiple
  rows (with explicit timestamps to avoid SQLite resolution races).
* ``list_presets`` — filtering by project_id (other projects' rows
  excluded).
* ``get_preset`` — happy path returns the right row.
* ``get_preset`` — unknown id raises ValueError("Preset not found").
* ``update_preset`` — partial update only mutates supplied fields;
  None values skipped (per the ``if value is not None`` guard).
* ``update_preset`` — port_forwards JSONB updated correctly.
* ``update_preset`` — unknown attribute silently ignored
  (the ``hasattr`` guard).
* ``update_preset`` — unknown id raises ValueError.
* ``delete_preset`` — happy path: row gone after flush.
* ``delete_preset`` — unknown id raises ValueError.
* **Rule #35b live canary** — full create → list → get → update →
  delete lifecycle SELECTing each stage's persisted state.
* **Rule #30 inverse-consumer-patch sentinels** — EmulationPreset
  + select are bound on the consumer module.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.emulation_preset import EmulationPreset
from app.models.project import Project
from app.services import emulation_preset_service as preset_mod
from app.services.emulation_preset_service import EmulationPresetService
from tests._live_db import make_live_db

# ===========================================================================
# Helpers
# ===========================================================================


async def _seed_project(db) -> Project:
    pid = uuid.uuid4()
    project = Project(id=pid, name="preset-test", status="ready")
    db.add(project)
    await db.flush()
    return project


# ===========================================================================
# create_preset
# ===========================================================================


class TestCreatePreset:
    @pytest.mark.asyncio
    async def test_minimal_required_fields_persist(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id,
                name="hello",
                mode="user",
            )
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.project_id == project.id
            assert row.name == "hello"
            assert row.mode == "user"
            # Defaults
            assert row.description is None
            assert row.binary_path is None
            assert row.arguments is None
            assert row.architecture is None
            assert row.port_forwards == []
            assert row.kernel_name is None
            assert row.init_path is None
            assert row.pre_init_script is None
            assert row.stub_profile == "none"

    @pytest.mark.asyncio
    async def test_full_kwarg_payload_round_trips(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            port_forwards = [
                {"host": 8080, "guest": 80},
                {"host": 2222, "guest": 22},
            ]
            preset = await svc.create_preset(
                project_id=project.id,
                name="full",
                mode="system",
                description="full preset",
                binary_path="/firmware/httpd",
                arguments="-d /etc",
                architecture="armv7",
                port_forwards=port_forwards,
                kernel_name="vmlinux-arm",
                init_path="/sbin/init",
                pre_init_script="echo hi",
                stub_profile="aggressive",
            )
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.description == "full preset"
            assert row.binary_path == "/firmware/httpd"
            assert row.arguments == "-d /etc"
            assert row.architecture == "armv7"
            assert row.port_forwards == port_forwards
            assert row.kernel_name == "vmlinux-arm"
            assert row.init_path == "/sbin/init"
            assert row.pre_init_script == "echo hi"
            assert row.stub_profile == "aggressive"

    @pytest.mark.asyncio
    async def test_port_forwards_none_defaults_to_empty_list(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id,
                name="np",
                mode="user",
                port_forwards=None,
            )
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.port_forwards == []


# ===========================================================================
# list_presets
# ===========================================================================


class TestListPresets:
    @pytest.mark.asyncio
    async def test_empty_project_returns_empty_list(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            assert await svc.list_presets(project.id) == []

    @pytest.mark.asyncio
    async def test_descending_by_created_at(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            base = datetime.now(UTC)
            for i, name in enumerate(("first", "second", "third")):
                db.add(EmulationPreset(
                    project_id=project.id,
                    name=name,
                    mode="user",
                    port_forwards=[],
                    stub_profile="none",
                    created_at=base + timedelta(seconds=i),
                ))
                await db.flush()

            svc = EmulationPresetService(db)
            presets = await svc.list_presets(project.id)
            assert [p.name for p in presets] == ["third", "second", "first"]

    @pytest.mark.asyncio
    async def test_filters_by_project_id(self):
        async with make_live_db() as db:
            p1 = await _seed_project(db)
            p2_id = uuid.uuid4()
            db.add(Project(id=p2_id, name="other", status="ready"))
            await db.flush()

            db.add(EmulationPreset(
                project_id=p1.id, name="a", mode="user",
                port_forwards=[], stub_profile="none",
            ))
            db.add(EmulationPreset(
                project_id=p2_id, name="b", mode="user",
                port_forwards=[], stub_profile="none",
            ))
            await db.flush()

            svc = EmulationPresetService(db)
            results = await svc.list_presets(p1.id)
            assert len(results) == 1
            assert results[0].name == "a"


# ===========================================================================
# get_preset
# ===========================================================================


class TestGetPreset:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            created = await svc.create_preset(
                project_id=project.id, name="x", mode="user",
            )
            await db.flush()

            fetched = await svc.get_preset(created.id)
            assert fetched.id == created.id
            assert fetched.name == "x"

    @pytest.mark.asyncio
    async def test_unknown_id_raises_value_error(self):
        async with make_live_db() as db:
            svc = EmulationPresetService(db)
            with pytest.raises(ValueError) as exc:
                await svc.get_preset(uuid.uuid4())
            assert "Preset not found" in str(exc.value)


# ===========================================================================
# update_preset
# ===========================================================================


class TestUpdatePreset:
    @pytest.mark.asyncio
    async def test_partial_update_skips_none_values(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id, name="orig", mode="user",
                description="initial",
            )
            await db.flush()

            # Only change name; description=None should NOT clear the field.
            updated = await svc.update_preset(preset.id, {
                "name": "renamed",
                "description": None,
            })
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.name == "renamed"
            assert row.description == "initial"  # None skipped per service guard
            assert updated.name == "renamed"

    @pytest.mark.asyncio
    async def test_port_forwards_jsonb_update(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id, name="pf", mode="system",
                port_forwards=[{"host": 80, "guest": 80}],
            )
            await db.flush()

            new_pf = [{"host": 8443, "guest": 443}, {"host": 2222, "guest": 22}]
            await svc.update_preset(preset.id, {"port_forwards": new_pf})
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.port_forwards == new_pf

    @pytest.mark.asyncio
    async def test_unknown_attribute_silently_ignored(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id, name="x", mode="user",
            )
            await db.flush()

            # `nonsense_field` is not on the ORM model — service's
            # `hasattr(preset, key)` guard drops it without error.
            await svc.update_preset(preset.id, {
                "nonsense_field": "ignored",
                "name": "ok",
            })
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.name == "ok"
            assert not hasattr(row, "nonsense_field")

    @pytest.mark.asyncio
    async def test_unknown_id_raises_value_error(self):
        async with make_live_db() as db:
            svc = EmulationPresetService(db)
            with pytest.raises(ValueError):
                await svc.update_preset(uuid.uuid4(), {"name": "x"})


# ===========================================================================
# delete_preset
# ===========================================================================


class TestDeletePreset:
    @pytest.mark.asyncio
    async def test_delete_happy_path(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)
            preset = await svc.create_preset(
                project_id=project.id, name="del", mode="user",
            )
            await db.flush()
            preset_id = preset.id

            await svc.delete_preset(preset_id)
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset_id)
            )).scalar_one_or_none()
            assert row is None

    @pytest.mark.asyncio
    async def test_delete_unknown_id_raises(self):
        async with make_live_db() as db:
            svc = EmulationPresetService(db)
            with pytest.raises(ValueError):
                await svc.delete_preset(uuid.uuid4())


# ===========================================================================
# Rule #35b multi-stage live-canary lifecycle
# ===========================================================================


class TestFullLifecycleLiveCanary:
    @pytest.mark.asyncio
    async def test_create_list_get_update_delete(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = EmulationPresetService(db)

            # Stage 1: create.
            preset = await svc.create_preset(
                project_id=project.id,
                name="lifecycle",
                mode="user",
                port_forwards=[{"host": 80, "guest": 80}],
                stub_profile="standard",
            )
            await db.commit()

            row = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row.name == "lifecycle"
            assert row.stub_profile == "standard"
            assert row.port_forwards == [{"host": 80, "guest": 80}]

            # Stage 2: list — preset appears.
            listed = await svc.list_presets(project.id)
            assert len(listed) == 1
            assert listed[0].id == preset.id

            # Stage 3: get — same row.
            got = await svc.get_preset(preset.id)
            assert got.id == preset.id

            # Stage 4: update — name + port_forwards changed, mode preserved.
            await svc.update_preset(preset.id, {
                "name": "lifecycle-renamed",
                "port_forwards": [{"host": 8080, "guest": 80}],
                "mode": None,  # None must be skipped
            })
            await db.commit()

            row2 = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one()
            assert row2.name == "lifecycle-renamed"
            assert row2.mode == "user"  # unchanged because update value was None
            assert row2.port_forwards == [{"host": 8080, "guest": 80}]

            # Stage 5: delete — gone.
            await svc.delete_preset(preset.id)
            await db.commit()

            row3 = (await db.execute(
                select(EmulationPreset).where(EmulationPreset.id == preset.id)
            )).scalar_one_or_none()
            assert row3 is None
            assert await svc.list_presets(project.id) == []


# ===========================================================================
# Rule #30 inverse-consumer-patch sentinels
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Document that emulation_preset_service binds EmulationPreset + select
    at module scope; future patches MUST hit the consumer module if a
    refactor flips to lazy imports.
    """

    def test_consumer_module_binds_emulation_preset_orm(self):
        # `from app.models.emulation_preset import EmulationPreset` line 11.
        assert hasattr(preset_mod, "EmulationPreset")

    def test_consumer_module_binds_select(self):
        # `from sqlalchemy import select` line 8.
        assert hasattr(preset_mod, "select")
