"""Tests for the C4 android-posture walker MCP tools + the
registry-uniqueness META-CANARY (R51.2 SHOULD-FIX S1 + S2).

C4's tools live in a NEW file ai/tools/android_posture.py (distinct
namespace; NOT the per-APK android.py) per the critique's silent-overwrite
lesson. ToolRegistry.register SILENTLY OVERWRITES — the registry-uniqueness
canary below + the extended assertion list in test_kernel_config_mcp.py close
the Rule #10-class MCP-layer gap.

Coverage axes:

* **Registry-uniqueness + C4-names-coexist canary (R51.2 S1)** — assert the
  FULL assembled registry has NO duplicate names AND the 3 distinct C4 tool
  names all coexist (no shadow of the C1/C2/C3/per-APK-android tools).
* **trigger_android_posture_walk** — Rule #33 .a 409-on-conflict +
  project-scope guard + happy-path queue.
* **get_android_posture** — provenance-gate rejection + THE HONEST GATING
  note surfaced on runtime_confirmed=false.
* **lookup_android_posture_across_firmwares** — Rule #44 cross-firmware
  aggregation + supply_chain_signal (≥2 firmware share the SAME DPC app).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.android_posture import (
    _handle_get_android_posture,
    _handle_lookup_android_posture_across_firmwares,
    _handle_trigger_android_posture_walk,
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
        original_filename=kwargs.pop("original_filename", f"fw-{sha_seed[:8]}.zip"),
        storage_path=f"/tmp/{sha_seed[:8]}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
        **kwargs,
    )


def _posture(
    *,
    kiosk: bool = False,
    cellular: bool = True,
    sideload: bool = True,
    dpc_apps: list[str] | None = None,
    build_type: str = "user",
    build_tags: str = "release-keys",
    runtime_confirmed: bool = False,
) -> dict:
    """Build a stamped image-inferred posture aggregate."""
    return {
        "schema_version": 1,
        "provenance": "walker",
        "walked_at": "2026-05-29T09:00:00+00:00",
        "platform": "android",
        "gates_open": {
            "cellular_active": cellular,
            "sideloading_allowed": sideload,
            "kiosk": kiosk,
        },
        "runtime_confirmed": runtime_confirmed,
        "posture_confidence": "config_inferred",
        "evidence": {
            "dpc_apps": dpc_apps or [],
            "telephony_present": cellular,
            "telephony_evidence": ["lib/libril.so"] if cellular else [],
            "sideload_default": "unknown",
            "build_type": build_type,
            "build_tags": build_tags,
            "device_owner_xml_present": bool(dpc_apps),
        },
        "settling_command": (
            "adb shell dumpsys device_policy; adb shell dpm list-owners; "
            "adb shell getprop | grep -E 'sim|radio'"
        ),
        "errors": [],
    }


# ───────────────────────────────────────────────────────────────────────
# Registry-uniqueness + C4-names-coexist META-CANARY (R51.2 S1).
# ───────────────────────────────────────────────────────────────────────


def test_full_registry_has_no_duplicate_tool_names_with_c4():
    """The FULL assembled MCP registry MUST have NO duplicate tool names
    (ToolRegistry.register silently overwrites). The 3 DISTINCT C4 names
    coexist with the C1 + C2 + C3 + per-APK-android tools (no shadow)."""
    from app.ai import create_tool_registry

    registry = create_tool_registry()
    names = [t.name for t in registry._tools.values()]
    assert len(names) == len(set(names)), (
        f"DUPLICATE MCP tool names in the assembled registry: "
        f"{sorted(n for n in names if names.count(n) > 1)!r}. C4 added its "
        f"tools in a NEW file ai/tools/android_posture.py to avoid the "
        f"silent-overwrite gap (R51.2 S1)."
    )
    name_set = set(names)
    # The 3 DISTINCT C4 tool names.
    assert "trigger_android_posture_walk" in name_set
    assert "get_android_posture" in name_set
    assert "lookup_android_posture_across_firmwares" in name_set
    # No shadow of the per-APK android.py tools.
    assert "analyze_apk" in name_set
    # No shadow of the C3 tools.
    assert "get_network_exposure" in name_set


# ───────────────────────────────────────────────────────────────────────
# trigger_android_posture_walk — Rule #33 .a + project-scope guard.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_409_on_in_flight():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        fw = _make_firmware(proj.id, "a", android_posture_walk_status="running")
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        with patch(
            "app.ai.tools.android_posture.asyncio.create_task"
        ) as mock_task:
            out = json.loads(
                await _handle_trigger_android_posture_walk(
                    {"firmware_id": str(fw.id)}, ctx
                )
            )
        assert out["status"] == "conflict"
        assert out["android_posture_walk_status"] == "running"
        mock_task.assert_not_called()


@pytest.mark.asyncio
async def test_trigger_rejects_cross_project():
    async with make_live_db() as db:
        proj_a = Project(name="a")
        proj_b = Project(name="b")
        db.add_all([proj_a, proj_b])
        await db.flush()
        fw = _make_firmware(proj_b.id, "b")
        db.add(fw)
        await db.flush()
        # Active project is A; firmware belongs to B.
        ctx = _StubContext(db=db, project_id=proj_a.id)
        out = json.loads(
            await _handle_trigger_android_posture_walk(
                {"firmware_id": str(fw.id)}, ctx
            )
        )
        assert "error" in out
        assert "different project" in out["error"] or "not found" in out["error"]


@pytest.mark.asyncio
async def test_trigger_queues_idle_firmware():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        fw = _make_firmware(proj.id, "c", android_posture_walk_status="idle")
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        with patch(
            "app.ai.tools.android_posture.asyncio.create_task"
        ) as mock_task:
            out = json.loads(
                await _handle_trigger_android_posture_walk(
                    {"firmware_id": str(fw.id)}, ctx
                )
            )
        assert out["status"] == "queued"
        await db.refresh(fw)
        assert fw.android_posture_walk_status == "queued"
        mock_task.assert_called_once()


@pytest.mark.asyncio
async def test_trigger_requires_active_project():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        fw = _make_firmware(proj.id, "d")
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=None)  # no active project
        out = json.loads(
            await _handle_trigger_android_posture_walk(
                {"firmware_id": str(fw.id)}, ctx
            )
        )
        assert "error" in out
        assert "no active project" in out["error"]


# ───────────────────────────────────────────────────────────────────────
# get_android_posture — provenance gate + THE HONEST GATING note.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_returns_posture_with_honest_gating_note():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        fw = _make_firmware(
            proj.id,
            "e",
            android_posture_walk_status="completed",
            android_posture_walk_result=_posture(kiosk=False, cellular=True),
        )
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        out = json.loads(
            await _handle_get_android_posture({"firmware_id": str(fw.id)}, ctx)
        )
        assert out["result"]["gates_open"]["cellular_active"] is True
        assert out["result"]["runtime_confirmed"] is False
        # THE HONEST GATING note is surfaced on the image-inferred posture.
        assert "gating_note" in out
        assert "HOLDS THE GATE OPEN" in out["gating_note"]
        assert "settling_command" in out["result"]


@pytest.mark.asyncio
async def test_get_rejects_non_walker_provenance():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        bad = _posture()
        bad["provenance"] = "hand-edited"  # not 'walker'
        fw = _make_firmware(
            proj.id,
            "f",
            android_posture_walk_status="completed",
            android_posture_walk_result=bad,
        )
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        out = json.loads(
            await _handle_get_android_posture({"firmware_id": str(fw.id)}, ctx)
        )
        assert "consumer_warning" in out
        assert "provenance gate" in out["consumer_warning"]


@pytest.mark.asyncio
async def test_get_no_result_yet():
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        fw = _make_firmware(proj.id, "0", android_posture_walk_status="idle")
        db.add(fw)
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        out = json.loads(
            await _handle_get_android_posture({"firmware_id": str(fw.id)}, ctx)
        )
        assert out["result"] is None
        assert "hint" in out


# ───────────────────────────────────────────────────────────────────────
# lookup_android_posture_across_firmwares — Rule #44 + supply_chain_signal.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_shared_dpc_is_supply_chain_signal():
    """≥2 firmware shipping the SAME DPC app → supply_chain_signal=True (the
    same managed-fleet / same-OEM-image posture across the fleet)."""
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        # Two firmware both ship WorkspaceONE → shared DPC → supply-chain.
        fw1 = _make_firmware(
            proj.id,
            "1",
            android_posture_walk_status="completed",
            android_posture_walk_result=_posture(
                kiosk=True, dpc_apps=["com.airwatch.androidagent"]
            ),
        )
        fw2 = _make_firmware(
            proj.id,
            "2",
            android_posture_walk_status="completed",
            android_posture_walk_result=_posture(
                kiosk=True, dpc_apps=["com.airwatch.androidagent"]
            ),
        )
        db.add_all([fw1, fw2])
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        out = json.loads(
            await _handle_lookup_android_posture_across_firmwares(
                {"dpc_app": "airwatch", "scope": "project"}, ctx
            )
        )
        assert out["match_firmware_count"] == 2
        assert out["supply_chain_signal"] is True
        assert "com.airwatch.androidagent" in out["shared_dpc_apps"]
        # Every matched row honestly reports runtime_confirmed=false.
        for m in out["matches"]:
            assert m["runtime_confirmed"] is False


@pytest.mark.asyncio
async def test_lookup_gate_filter_kiosk():
    """A gate filter returns only firmware whose named gate is OPEN."""
    async with make_live_db() as db:
        proj = Project(name="p")
        db.add(proj)
        await db.flush()
        kiosk_fw = _make_firmware(
            proj.id,
            "3",
            android_posture_walk_status="completed",
            android_posture_walk_result=_posture(
                kiosk=True, dpc_apps=["com.example.dpc"]
            ),
        )
        stock_fw = _make_firmware(
            proj.id,
            "4",
            android_posture_walk_status="completed",
            android_posture_walk_result=_posture(kiosk=False),
        )
        db.add_all([kiosk_fw, stock_fw])
        await db.flush()
        ctx = _StubContext(db=db, project_id=proj.id)
        out = json.loads(
            await _handle_lookup_android_posture_across_firmwares(
                {"gate": "kiosk", "scope": "project"}, ctx
            )
        )
        ids = {m["firmware_id"] for m in out["matches"]}
        assert str(kiosk_fw.id) in ids
        assert str(stock_fw.id) not in ids


@pytest.mark.asyncio
async def test_lookup_rejects_bad_gate():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, project_id=uuid.uuid4())
        out = json.loads(
            await _handle_lookup_android_posture_across_firmwares(
                {"gate": "not_a_gate"}, ctx
            )
        )
        assert "error" in out
        assert "gate must be one of" in out["error"]
