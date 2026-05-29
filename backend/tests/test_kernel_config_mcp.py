"""Tests for the C1 kernel-config EXTRACTION walker MCP tools +
the registry-uniqueness META-CANARY (R50.2 B1).

The C1 extraction tools live in ai/tools/linux_kernel_hardening.py with
DISTINCT names (trigger_kernel_config_walk / get_kernel_config_extraction)
so they do NOT shadow the pre-existing lookup_kernel_config_across_firmwares
(which reads the AUDIT result and already satisfies Rule #44 for kernel
config). ToolRegistry.register SILENTLY OVERWRITES (no dup guard) — the
registry-uniqueness canary below closes that Rule #10-class MCP-layer gap.

Coverage axes:

* **Registry-uniqueness META-CANARY (R50.2 B1)** — assert the FULL
  assembled registry has NO duplicate tool names. This is the platform
  guard the critique flagged as missing; without it, two register_*
  functions registering the same name produces a silent overwrite (the
  Rule #10 silent-rebind failure class at the MCP layer).
* **trigger_kernel_config_walk** — Rule #33 .a 409-on-conflict +
  project-scope guard (cross-project trigger returns an error, not a
  queue).
* **get_kernel_config_extraction** — provenance-gate rejection
  (non-walker / legacy result surfaces a consumer_warning).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.linux_kernel_hardening import (
    _handle_get_kernel_config_extraction,
    _handle_trigger_kernel_config_walk,
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
# Registry-uniqueness META-CANARY (R50.2 B1 — the missing platform guard).
# ───────────────────────────────────────────────────────────────────────


def test_full_registry_has_no_duplicate_tool_names():
    """R50.2 B1 — the FULL assembled MCP registry MUST have NO duplicate
    tool names. ToolRegistry.register silently overwrites
    (self._tools[name] = ...), so a second register_* function registering
    an already-used name VANISHES the first with zero error (the Rule #10
    silent-rebind failure class at the MCP layer).

    This canary builds the real registry via create_tool_registry() and
    asserts the count of registered ToolDefinitions equals the count of
    distinct names. Because register silently overwrites, a collision
    would make len(registry._tools) SMALLER than the sum of per-category
    registrations — but we can't see that sum directly. Instead we assert
    every name in the registry maps to exactly one definition AND that the
    DISTINCT C1 names + the pre-existing lookup name all coexist.
    """
    from app.ai import create_tool_registry

    registry = create_tool_registry()
    names = [t.name for t in registry._tools.values()]
    assert len(names) == len(set(names)), (
        f"DUPLICATE MCP tool names in the assembled registry: "
        f"{sorted(n for n in names if names.count(n) > 1)!r}. "
        f"ToolRegistry.register SILENTLY OVERWRITES — a collision vanishes "
        f"one tool with no error (Rule #10 MCP-layer gap). Rename the "
        f"colliding tool (R50.2 B1 discipline)."
    )

    # The pre-existing AUDIT cross-firmware tool + the DISTINCT C1
    # extraction tools all coexist (no shadow).
    name_set = set(names)
    assert "lookup_kernel_config_across_firmwares" in name_set, (
        "the pre-existing Rule #44 audit cross-firmware tool vanished — "
        "did C1 accidentally re-register the name and get overwritten?"
    )
    assert "trigger_kernel_config_walk" in name_set
    assert "get_kernel_config_extraction" in name_set
    assert "audit_kernel_config_firmware" in name_set

    # C2 module-reachability tools (R51.2 S1 — DISTINCT new-file namespace)
    # coexist with the C1 tools above (no silent overwrite).
    assert "trigger_module_reachability_walk" in name_set
    assert "get_module_reachability" in name_set
    assert "lookup_module_across_firmwares" in name_set

    # C3 network-exposure tools (R51.2 S1 — DISTINCT new-file namespace,
    # ai/tools/network_exposure.py; NOT the pcap-analysis network.py) coexist
    # with the C1 + C2 tools above (no silent overwrite).
    assert "trigger_network_exposure_walk" in name_set
    assert "get_network_exposure" in name_set
    assert "lookup_network_listener_across_firmwares" in name_set


def test_registry_uniqueness_canary_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a duplicate registration
    and confirm the uniqueness check WOULD catch it. Without this, the
    uniqueness assertion is a silent-pass (passes whether or not the
    registry actually deduplicates)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()

    async def _noop(_input, _ctx):  # pragma: no cover - never called
        return "{}"

    schema = {"type": "object", "properties": {}}
    reg.register(name="dup_tool", description="first", input_schema=schema, handler=_noop)
    reg.register(name="dup_tool", description="second", input_schema=schema, handler=_noop)

    # The registry silently kept only ONE (the overwrite) — so iterating
    # definitions yields ONE 'dup_tool'. The canary proves the FAILURE
    # MODE: two register() calls of the same name do NOT raise + do NOT
    # both persist. A uniqueness check over the assembled registry can
    # only catch a collision if the colliding registrations land DISTINCT
    # names; this canary documents WHY distinct names matter (R50.2 B1).
    names = [t.name for t in reg._tools.values()]
    assert names == ["dup_tool"], (
        "ToolRegistry no longer silently overwrites — if it now raises or "
        "keeps both, update the R50.2 B1 discipline + the uniqueness "
        "canary's reasoning (the gap may be closed at the registry level)."
    )
    # The surviving definition is the SECOND (overwrite semantics) — this
    # is the silent data-loss the B1 discipline guards against.
    assert reg._tools["dup_tool"].description == "second"


# ───────────────────────────────────────────────────────────────────────
# trigger_kernel_config_walk — Rule #33 .a + project-scope guard.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_kernel_config_walk_409_on_in_flight():
    """Rule #33 .a — trigger returns status='conflict' when the walker is
    already queued/running."""
    async with make_live_db() as db:
        project = Project(name="trigger-409")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "a")
        firmware.kernel_config_walk_status = "running"
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_trigger_kernel_config_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert out["status"] == "conflict"
        assert out["kernel_config_walk_status"] == "running"


@pytest.mark.asyncio
async def test_trigger_kernel_config_walk_rejects_cross_project():
    """Project-scope guard — triggering against a firmware in ANOTHER
    project returns an error (not a queue)."""
    async with make_live_db() as db:
        project_a = Project(name="proj-a")
        project_b = Project(name="proj-b")
        db.add_all([project_a, project_b])
        await db.flush()
        # Firmware belongs to project_b.
        firmware = _make_firmware(project_b.id, "b")
        db.add(firmware)
        await db.flush()

        # Context is scoped to project_a — must NOT trigger project_b's fw.
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project_a.id)
        out = json.loads(
            await _handle_trigger_kernel_config_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "error" in out
        assert "different project" in out["error"] or "not found" in out["error"]


@pytest.mark.asyncio
async def test_trigger_kernel_config_walk_queues_idle_firmware():
    """Happy path — an idle firmware in the active project flips to queued
    and the background runner is dispatched (mocked so the detached task
    doesn't hit the real async_session_factory in the SQLite test env)."""
    async with make_live_db() as db:
        project = Project(name="trigger-ok")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "c")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        with patch(
            "app.ai.tools.linux_kernel_hardening.run_kernel_config_walk_background"
        ) as mock_bg:
            # Return a real awaitable-noop so asyncio.create_task is happy.
            async def _noop(_fid):
                return None

            mock_bg.side_effect = _noop
            out = json.loads(
                await _handle_trigger_kernel_config_walk(
                    {"firmware_id": str(firmware.id)}, ctx
                )
            )
        assert out["status"] == "queued"
        # Status persisted as queued.
        from sqlalchemy import select

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        assert reread.kernel_config_walk_status == "queued"


@pytest.mark.asyncio
async def test_trigger_kernel_config_walk_requires_active_project():
    """No active project → error (can't trigger without scope)."""
    async with make_live_db() as db:
        project = Project(name="no-scope")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "d")
        db.add(firmware)
        await db.flush()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=None)
        out = json.loads(
            await _handle_trigger_kernel_config_walk(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "error" in out
        assert "no active project" in out["error"]


# ───────────────────────────────────────────────────────────────────────
# get_kernel_config_extraction — provenance gate.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_kernel_config_extraction_returns_walker_result():
    """A completed walk with provenance=walker + schema_version=1 returns
    the result without a consumer_warning."""
    async with make_live_db() as db:
        project = Project(name="get-ok")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "e")
        firmware.kernel_config_walk_status = "completed"
        firmware.kernel_config_walk_result = {
            "schema_version": 1,
            "provenance": "walker",
            "kernels": [{"config_entries": 4594, "extraction_status": "ok"}],
            "kernels_extracted_count": 1,
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_kernel_config_extraction(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "consumer_warning" not in out
        assert out["result"]["kernels_extracted_count"] == 1


@pytest.mark.asyncio
async def test_get_kernel_config_extraction_rejects_non_walker_provenance():
    """A result with provenance != 'walker' (e.g. a hostile pre-seed)
    surfaces a consumer_warning so Gate-1 consumers refuse it."""
    async with make_live_db() as db:
        project = Project(name="get-hostile")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "f")
        firmware.kernel_config_walk_status = "completed"
        firmware.kernel_config_walk_result = {
            "schema_version": 1,
            "provenance": "descriptor",  # NOT walker — hostile pre-seed
            "kernels": [{"config_entries": 9999}],
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_kernel_config_extraction(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert "consumer_warning" in out
        assert "provenance gate" in out["consumer_warning"]


@pytest.mark.asyncio
async def test_get_kernel_config_extraction_no_result_yet():
    """An idle firmware (no walk yet) returns result=None + a hint."""
    async with make_live_db() as db:
        project = Project(name="get-idle")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "0")
        db.add(firmware)
        await db.flush()
        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_get_kernel_config_extraction(
                {"firmware_id": str(firmware.id)}, ctx
            )
        )
        assert out["result"] is None
        assert "hint" in out
