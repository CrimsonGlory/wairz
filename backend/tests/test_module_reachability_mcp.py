"""Tests for the C2 module-reachability walker MCP tools + the
registry-uniqueness META-CANARY (R51.2 SHOULD-FIX S1).

C2's tools live in a NEW file ai/tools/module_reachability.py (distinct
namespace; NOT the crowded linux_kernel_hardening.py) per the critique's
silent-overwrite lesson. ToolRegistry.register SILENTLY OVERWRITES — the
registry-uniqueness canary below + the extended assertion list in
test_kernel_config_mcp.py close the Rule #10-class MCP-layer gap.

Coverage axes:

* **Registry-uniqueness + C2-names-coexist canary (R51.2 S1)** — assert the
  FULL assembled registry has NO duplicate names AND the 3 distinct C2 tool
  names all coexist (no shadow of the C1 / python_ast tools).
* **trigger_module_reachability_walk** — Rule #33 .a 409-on-conflict +
  project-scope guard + happy-path queue.
* **get_module_reachability** — provenance-gate rejection.
* **lookup_module_across_firmwares** — Rule #44 cross-firmware aggregation +
  supply_chain_signal (≥2 firmware share the SAME .ko SHA).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.module_reachability import (
    _handle_get_module_reachability,
    _handle_lookup_module_across_firmwares,
    _handle_trigger_module_reachability_walk,
)
from app.models import Firmware, Project
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    db: AsyncSession
    firmware_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None


def _make_firmware(project_id: uuid.UUID, sha_seed: str, **kwargs) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=kwargs.pop("original_filename", f"fw-{sha_seed[:8]}.bin"),
        storage_path=f"/tmp/{sha_seed[:8]}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
        **kwargs,
    )


# ───────────────────────────────────────────────────────────────────────
# Registry-uniqueness + C2-names-coexist META-CANARY (R51.2 S1).
# ───────────────────────────────────────────────────────────────────────


def test_full_registry_has_no_duplicate_tool_names_with_c2():
    """The FULL assembled MCP registry MUST have NO duplicate tool names
    (ToolRegistry.register silently overwrites). The 3 DISTINCT C2 names
    coexist with the C1 + python_ast tools (no shadow)."""
    from app.ai import create_tool_registry

    registry = create_tool_registry()
    names = [t.name for t in registry._tools.values()]
    assert len(names) == len(set(names)), (
        f"DUPLICATE MCP tool names in the assembled registry: "
        f"{sorted(n for n in names if names.count(n) > 1)!r}. C2 added its "
        f"tools in a NEW file ai/tools/module_reachability.py to avoid the "
        f"silent-overwrite gap (R51.2 S1)."
    )
    name_set = set(names)
    # The 3 DISTINCT C2 tool names.
    assert "trigger_module_reachability_walk" in name_set
    assert "get_module_reachability" in name_set
    assert "lookup_module_across_firmwares" in name_set
    # No shadow of the C1 extraction / audit tools.
    assert "trigger_kernel_config_walk" in name_set
    assert "lookup_kernel_config_across_firmwares" in name_set


# ───────────────────────────────────────────────────────────────────────
# trigger_module_reachability_walk — Rule #33 .a + project-scope guard.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_409_on_in_flight():
    async with make_live_db() as db:
        project = Project(name="trigger-409")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "a")
        firmware.module_reachability_walk_status = "running"
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_trigger_module_reachability_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert out["status"] == "conflict"
        assert out["module_reachability_walk_status"] == "running"


@pytest.mark.asyncio
async def test_trigger_rejects_cross_project():
    async with make_live_db() as db:
        project_a = Project(name="proj-a")
        project_b = Project(name="proj-b")
        db.add_all([project_a, project_b])
        await db.flush()
        firmware = _make_firmware(project_b.id, "b")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project_a.id)
        out = json.loads(
            await _handle_trigger_module_reachability_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "error" in out
        assert "different project" in out["error"] or "not found" in out["error"]


@pytest.mark.asyncio
async def test_trigger_queues_idle_firmware():
    async with make_live_db() as db:
        project = Project(name="trigger-ok")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "c")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        with patch(
            "app.ai.tools.module_reachability.run_module_reachability_walk_background"
        ) as mock_bg:
            async def _noop(_fid):
                return None

            mock_bg.side_effect = _noop
            out = json.loads(
                await _handle_trigger_module_reachability_walk(
                    {"firmware_id": str(firmware.id)}, ctx
                )
            )
        assert out["status"] == "queued"
        from sqlalchemy import select

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        assert reread.module_reachability_walk_status == "queued"


@pytest.mark.asyncio
async def test_trigger_requires_active_project():
    async with make_live_db() as db:
        project = Project(name="no-scope")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "d")
        db.add(firmware)
        await db.flush()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=None)
        out = json.loads(
            await _handle_trigger_module_reachability_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "error" in out
        assert "no active project" in out["error"]


# ───────────────────────────────────────────────────────────────────────
# get_module_reachability — provenance gate.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_returns_walker_result():
    async with make_live_db() as db:
        project = Project(name="get-ok")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "e")
        firmware.module_reachability_walk_status = "completed"
        firmware.module_reachability_walk_result = {
            "schema_version": 1,
            "provenance": "walker",
            "kernel_posture": "static_builtin",
            "static_builtin_posture": True,
            "loaded": None,
            "available": [],
            "builtin": ["bcmdhd", "ext4"],
            "available_count": 0,
            "builtin_count": 2,
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_module_reachability(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "consumer_warning" not in out
        assert out["result"]["static_builtin_posture"] is True
        assert "bcmdhd" in out["result"]["builtin"]


@pytest.mark.asyncio
async def test_get_rejects_non_walker_provenance():
    async with make_live_db() as db:
        project = Project(name="get-hostile")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "f")
        firmware.module_reachability_walk_status = "completed"
        firmware.module_reachability_walk_result = {
            "schema_version": 1,
            "provenance": "descriptor",  # NOT walker — hostile pre-seed
            "available": [],
            "builtin": [],
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_module_reachability(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "consumer_warning" in out
        assert "provenance gate" in out["consumer_warning"]


@pytest.mark.asyncio
async def test_get_no_result_yet():
    async with make_live_db() as db:
        project = Project(name="get-idle")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "0")
        db.add(firmware)
        await db.flush()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_module_reachability(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert out["result"] is None
        assert "hint" in out


# ───────────────────────────────────────────────────────────────────────
# lookup_module_across_firmwares — Rule #44 + supply_chain_signal.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_shared_ko_sha_is_supply_chain_signal():
    """Two firmware in the project ship the SAME bcmdhd.ko SHA → the lookup
    flags supply_chain_signal=True + lists the shared SHA (the round-48 BTFM
    'identical binary across the fleet' query)."""
    shared_sha = "f" * 64
    async with make_live_db() as db:
        project = Project(name="supply-chain")
        db.add(project)
        await db.flush()

        for seed in ("1", "2"):
            fw = _make_firmware(project.id, seed)
            fw.module_reachability_walk_status = "completed"
            fw.module_reachability_walk_result = {
                "schema_version": 1,
                "provenance": "walker",
                "kernel_posture": "modular",
                "static_builtin_posture": False,
                "available": [
                    {
                        "name": "bcmdhd",
                        "sha256": shared_sha,
                        "vermagic": "5.4.0",
                        "signed": False,
                    }
                ],
                "builtin": [],
            }
            db.add(fw)
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_module_across_firmwares(
                {"module_name": "bcmdhd", "scope": "project"}, ctx
            )
        )
        assert out["match_firmware_count"] == 2
        assert out["supply_chain_signal"] is True
        assert shared_sha in out["shared_ko_sha256"]
        assert all(m["found_in"] == "available" for m in out["matches"])


@pytest.mark.asyncio
async def test_lookup_builtin_match_by_name():
    """A static-builtin firmware where bcmdhd is in the BUILTIN set is matched
    via found_in='builtin' (the phone case — no .ko, driver compiled in)."""
    async with make_live_db() as db:
        project = Project(name="builtin-match")
        db.add(project)
        await db.flush()
        fw = _make_firmware(project.id, "9")
        fw.module_reachability_walk_status = "completed"
        fw.module_reachability_walk_result = {
            "schema_version": 1,
            "provenance": "walker",
            "kernel_posture": "static_builtin",
            "static_builtin_posture": True,
            "available": [],
            "builtin": ["bcmdhd", "ext4"],
        }
        db.add(fw)
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_module_across_firmwares(
                {"module_name": "bcmdhd", "scope": "project"}, ctx
            )
        )
        assert out["match_firmware_count"] == 1
        assert out["matches"][0]["found_in"] == "builtin"
        assert out["matches"][0]["static_builtin_posture"] is True


@pytest.mark.asyncio
async def test_lookup_requires_module_name_or_sha():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, project_id=uuid.uuid4())
        out = json.loads(
            await _handle_lookup_module_across_firmwares({}, ctx)
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_skips_non_completed_and_legacy_schema():
    """Only status='completed' + schema_version==1 rows are considered."""
    async with make_live_db() as db:
        project = Project(name="skip-incomplete")
        db.add(project)
        await db.flush()
        # running → skipped
        fw1 = _make_firmware(project.id, "7")
        fw1.module_reachability_walk_status = "running"
        # completed but schema_version 2 → skipped
        fw2 = _make_firmware(project.id, "8")
        fw2.module_reachability_walk_status = "completed"
        fw2.module_reachability_walk_result = {
            "schema_version": 2,
            "provenance": "walker",
            "available": [{"name": "bcmdhd", "sha256": "a" * 64}],
            "builtin": [],
        }
        db.add_all([fw1, fw2])
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_module_across_firmwares(
                {"module_name": "bcmdhd", "scope": "project"}, ctx
            )
        )
        assert out["match_firmware_count"] == 0
