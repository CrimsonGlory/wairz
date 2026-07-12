"""MCP tool tests for the MOVE 2 reachability-export walker (trigger / get / export / lookup).

trigger / get / export are tested via make_live_db (SQLite). The Rule #44 lookup uses a JSONB
``@>`` containment query (postgres-only — SQLite has no @>), so its happy-path is a container live
canary (Phase 4); here we cover its input-validation + structural-raise-only contract paths that
return before the SQL.
"""
from __future__ import annotations

import dataclasses
import json
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools import reachability_export as tools
from app.models.firmware import Firmware
from app.models.project import Project
from tests._live_db import make_live_db


@dataclasses.dataclass
class _StubContext:
    db: AsyncSession
    firmware_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None


async def _noop_bg(_fid):
    """No-op stand-in for the background runner so the trigger handler's asyncio.create_task gets
    a real (harmless) coroutine without spinning up async_session_factory in the test env."""
    return None


def _make_firmware(project_id: uuid.UUID, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=f"fw-{sha_seed[:8]}.bin",
        storage_path=f"/tmp/{sha_seed[:8]}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── trigger ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_trigger_queues_on_idle(monkeypatch):
    # Stub the background runner so create_task wraps a harmless no-op coroutine (don't patch
    # asyncio.create_task itself — tools.asyncio is the global module; patching it breaks the loop).
    monkeypatch.setattr(tools, "run_reachability_export_walk_background", _noop_bg)
    async with make_live_db() as db:
        project = Project(name="trig canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "a")
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_trigger_reachability_export_walk({}, ctx))
        assert out["status"] == "queued"
        refreshed = await db.get(Firmware, firmware.id)
        assert refreshed.reachability_export_walk_status == "queued"


@pytest.mark.asyncio
async def test_trigger_conflict_on_running():
    # Returns at the conflict path before any create_task spawn.
    async with make_live_db() as db:
        project = Project(name="conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "b")
        firmware.reachability_export_walk_status = "running"
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_trigger_reachability_export_walk({}, ctx))
        assert out["status"] == "conflict"


@pytest.mark.asyncio
async def test_trigger_requires_active_project():
    async with make_live_db() as db:
        project = Project(name="scope canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "c")
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=None)
        out = json.loads(await tools._handle_trigger_reachability_export_walk({}, ctx))
        assert "no active project" in out["error"]


@pytest.mark.asyncio
async def test_trigger_tenancy_guard_rejects_cross_project():
    # Returns at the not-found/tenancy path before any create_task spawn.
    async with make_live_db() as db:
        proj_a = Project(name="A")
        proj_b = Project(name="B")
        db.add_all([proj_a, proj_b])
        await db.flush()
        firmware = _make_firmware(proj_a.id, "d")  # belongs to A
        db.add(firmware)
        await db.commit()
        # active project is B — must not be able to trigger A's firmware
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=proj_b.id)
        out = json.loads(await tools._handle_trigger_reachability_export_walk({}, ctx))
        assert "not found in active project" in out["error"]


# ── get ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_hint_when_no_result():
    async with make_live_db() as db:
        project = Project(name="get-hint canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "e")
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_get_reachability_export({}, ctx))
        assert out["result"] is None and "no reachability-export walk result yet" in out["hint"]


@pytest.mark.asyncio
async def test_get_provenance_gate_rejects_unstamped():
    async with make_live_db() as db:
        project = Project(name="get-gate canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "f")
        # Unstamped result (no schema_version/provenance) — the gate must reject it.
        firmware.reachability_export_walk_result = {"blob_count": 5}
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_get_reachability_export({}, ctx))
        assert "consumer_warning" in out


@pytest.mark.asyncio
async def test_get_returns_stamped_aggregate():
    async with make_live_db() as db:
        project = Project(name="get-ok canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "1")
        firmware.reachability_export_walk_result = {
            "blob_count": 3, "elf_count": 2, "schema_version": 1, "provenance": "walker",
        }
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_get_reachability_export({}, ctx))
        assert out["result"]["elf_count"] == 2 and "consumer_warning" not in out


# ── export ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_writes_jsonl_and_returns_sample(monkeypatch, tmp_path):
    fixture_records = [
        {"schema_version": 1, "binary_path": "usr/sbin/dnsmasq", "defined_symbols": ["main"]},
        {"schema_version": 1, "binary_path": "lib/libfoo.so", "defined_symbols": ["foo"]},
    ]

    async def fake_export(firmware_id, db):
        return fixture_records

    monkeypatch.setattr(tools, "export_reachability_records", fake_export)
    async with make_live_db() as db:
        project = Project(name="export canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id, original_filename="fw.bin",
            storage_path=str(tmp_path / "upload.bin"), sha256=("2" * 64)[:64], file_size=1024,
        )
        db.add(firmware)
        await db.commit()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(await tools._handle_export_reachability_jsonl({}, ctx))
        assert out["record_count"] == 2
        assert out["jsonl_path"].endswith(f"wairz_reachability_{firmware.id}.jsonl")
        assert len(out["sample"]) == 2
        # the file actually exists with 2 lines
        with open(out["jsonl_path"], encoding="utf-8") as fh:
            assert sum(1 for _ in fh) == 2


# ── lookup: input-validation + structural-raise-only (pre-SQL paths) ──────────

@pytest.mark.asyncio
async def test_lookup_requires_symbol():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, project_id=uuid.uuid4())
        out = json.loads(await tools._handle_lookup_reachable_symbol_across_firmwares({}, ctx))
        assert "symbol" in out["error"]


@pytest.mark.asyncio
async def test_lookup_rejects_bad_scope():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, project_id=uuid.uuid4())
        out = json.loads(await tools._handle_lookup_reachable_symbol_across_firmwares(
            {"symbol": "x", "scope": "everywhere"}, ctx))
        assert "scope must be" in out["error"]


@pytest.mark.asyncio
async def test_lookup_project_scope_requires_active_project():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, project_id=None)
        out = json.loads(await tools._handle_lookup_reachable_symbol_across_firmwares(
            {"symbol": "x", "scope": "project"}, ctx))
        assert "requires an active project" in out["error"]
