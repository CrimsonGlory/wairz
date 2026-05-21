"""Tests for the ICS protocol catalog MCP tools (Phase 3 — Rule #52
instance #3, Session 2 2026-05-22).

Coverage axes:

* **Registration sanity** — register_ics_protocol_tools registers
  exactly the 4 declared tools.

* **W2-β §SC5-NEW-ICS-S2-ε (I35) project-scope guard** —
  trigger_ics_protocol_walk MUST filter by ``context.project_id`` so a
  switch_project-routed call against another project's firmware
  returns 404 (not 202).

* **W2-β §SC5-NEW-ICS-S2-3 / γ (I27) cross-firmware status filter** —
  lookup_ics_protocol_across_firmwares MUST filter at the SQL layer
  on ``ics_protocol_walk_status = 'completed'``; failed/idle rows
  excluded from cross-firmware aggregation.

* **W2-β §SC5-NEW-ICS-S2-ι (I39) legacy-rows schema_version filter** —
  in-Python filter on ``result['schema_version'] == 1``.

* **W2-β §SC5-NEW-ICS-S2-1 (I14) sister-provenance gate** — list /
  describe surfaces a ``consumer_warning`` / ``anomaly`` when
  ``result['provenance'] != 'walker'``.

* **W2-β §SC5-NEW-ICS-S2-γ (I30) supply_chain_signal curated-only** —
  the flag MUST require at least one matching firmware's
  ``manifest_sources_seen`` to contain ``_system`` or ``core``;
  operator-tier-only matches do NOT trigger the flag.

* **W2-β §SC5-NEW-ICS-S2-β (I32) consistency_warning surfacing** —
  describe_ics_protocol_anomalies flags mid-walk catalog drift.

* **Rule #33 .a 409 conflict** — trigger_ics_protocol_walk returns
  ``conflict: true`` when the walker is already queued/running.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.ics_protocol import (
    _handle_describe_ics_protocol_anomalies,
    _handle_list_ics_protocols,
    _handle_lookup_ics_protocol_across_firmwares,
    _handle_trigger_ics_protocol_walk,
    register_ics_protocol_tools,
)
from app.models import Firmware, Project
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the ICS MCP handlers."""

    db: AsyncSession
    firmware_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None


def _make_firmware(project_id: uuid.UUID, sha_seed: str, **kwargs) -> Firmware:
    """Helper — bare-minimum Firmware row for MCP-tool tests."""
    return Firmware(
        project_id=project_id,
        original_filename=kwargs.pop("original_filename", f"fw-{sha_seed[:8]}.bin"),
        storage_path=f"/tmp/{sha_seed[:8]}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
        **kwargs,
    )


def _walker_result(
    *,
    schema_version: int = 1,
    provenance: str = "walker",
    consistency_warning: str | None = None,
    protocol_family_counts: dict | None = None,
    manifest_sources_seen: list[str] | None = None,
    manifest_ids_seen: list[str] | None = None,
) -> dict:
    """Helper — canonical walker_result dict for fixture rows."""
    return {
        "schema_version": schema_version,
        "provenance": provenance,
        "walked_at": "2026-05-22T10:00:00+00:00",
        "snapshot_id_at_entry": "abc" * 21 + "d",  # 64 char
        "snapshot_id_at_exit": "abc" * 21 + "d",
        "consistency_warning": consistency_warning,
        "binaries_scanned_count": 1,
        "binaries_total_count": 1,
        "per_binary": [],
        "protocol_family_counts": protocol_family_counts or {},
        "manifest_ids_seen": manifest_ids_seen or [],
        "manifest_sources_seen": manifest_sources_seen or [],
        "findings_emitted_count": 0,
        "errors": [],
    }


# ───────────────────────────────────────────────────────────────────────
# Registration sanity.
# ───────────────────────────────────────────────────────────────────────


def test_register_ics_protocol_tools_registers_four():
    """register_ics_protocol_tools registers exactly the 4 Session 2
    Phase 3 tools — trigger / list / lookup_across_firmwares /
    describe_anomalies."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_ics_protocol_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "trigger_ics_protocol_walk" in names
    assert "list_ics_protocols" in names
    assert "lookup_ics_protocol_across_firmwares" in names
    assert "describe_ics_protocol_anomalies" in names
    assert len(reg._tools) == 4, (
        f"Expected exactly 4 ICS MCP tools; got {len(reg._tools)}. "
        f"Registry: {sorted(names)!r}"
    )


# ───────────────────────────────────────────────────────────────────────
# trigger_ics_protocol_walk — Rule #33 .a + W2-β §SC5-NEW-ICS-S2-ε.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_ics_protocol_walk_409_on_in_flight():
    """Rule #33 .a contract — trigger returns conflict=true when walker
    status is already queued/running."""
    async with make_live_db() as db:
        project = Project(name="trigger-409")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "a")
        firmware.ics_protocol_walk_status = "running"
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_trigger_ics_protocol_walk({}, ctx)
        )
        assert out.get("conflict") is True, (
            f"Rule #33 .a — expected conflict=true on in-flight; got: {out!r}"
        )
        assert out.get("status") == "running"


@pytest.mark.asyncio
async def test_trigger_ics_protocol_walk_project_scope_filter():
    """W2-β §SC5-NEW-ICS-S2-ε I35 — trigger MUST filter by
    context.project_id. Operator in P1 calling trigger against a
    firmware in P2 (via switch_project) gets 404 (not 202)."""
    async with make_live_db() as db:
        project_a = Project(name="project-a")
        project_b = Project(name="project-b")
        db.add_all([project_a, project_b])
        await db.flush()
        firmware_b = _make_firmware(project_b.id, "b")
        db.add(firmware_b)
        await db.flush()

        # Context says P1 (project_a); attempt to trigger firmware in P2.
        ctx = _StubContext(
            db=db, firmware_id=firmware_b.id, project_id=project_a.id,
        )
        out = json.loads(
            await _handle_trigger_ics_protocol_walk({}, ctx)
        )
        assert "error" in out, (
            f"W2-β §SC5-NEW-ICS-S2-ε — trigger SHOULD have returned an "
            f"error for cross-project firmware; got: {out!r}. Without "
            f"this gate, operator-A in P1 could trigger walker against "
            f"operator-B's firmware in P2 via switch_project."
        )
        assert "tenancy" in out["error"].lower() or "not found" in out["error"].lower()


@pytest.mark.asyncio
async def test_trigger_ics_protocol_walk_requires_active_project():
    """A trigger call with no active project (context.project_id is None)
    MUST fail rather than implicitly scoping globally — defensive."""
    async with make_live_db() as db:
        project = Project(name="trigger-no-project")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "c")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=None)
        out = json.loads(
            await _handle_trigger_ics_protocol_walk({}, ctx)
        )
        assert "error" in out, (
            f"trigger without active project MUST fail; got: {out!r}"
        )
        assert "active project" in out["error"].lower()


# ───────────────────────────────────────────────────────────────────────
# list_ics_protocols — W2-β §SC5-NEW-ICS-S2-1 sister-provenance.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_ics_protocols_consumer_warning_on_provenance_fail():
    """W2-β §SC5-NEW-ICS-S2-1 I14 — list_ics_protocols surfaces
    consumer_warning when ``result.provenance != 'walker'`` (e.g.
    descriptor route pre-seed bypass)."""
    async with make_live_db() as db:
        project = Project(name="provenance-warn")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "d")
        firmware.ics_protocol_walk_status = "completed"
        firmware.ics_protocol_walk_result = _walker_result(
            provenance="descriptor",  # hostile pre-seed
            protocol_family_counts={"s7comm": 1},
            manifest_sources_seen=["_system"],
        )
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_list_ics_protocols({}, ctx)
        )
        assert "consumer_warning" in out, (
            f"W2-β §SC5-NEW-ICS-S2-1 — list_ics_protocols MUST surface a "
            f"consumer_warning when provenance != 'walker'. Without this, "
            f"downstream consumers can attribute Siemens CVEs to non-"
            f"Siemens firmwares based on a descriptor-pre-seeded JSONB. "
            f"Got: {out!r}"
        )
        assert "provenance" in out["consumer_warning"].lower()


@pytest.mark.asyncio
async def test_list_ics_protocols_handles_non_completed_status():
    """list_ics_protocols returns hint when walker hasn't completed."""
    async with make_live_db() as db:
        project = Project(name="not-completed")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "e")
        # default status='idle'
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_list_ics_protocols({}, ctx)
        )
        assert out["status"] == "idle"
        assert out["result"] is None
        assert "hint" in out


# ───────────────────────────────────────────────────────────────────────
# lookup_ics_protocol_across_firmwares — Rule #44 + W2-β multi-gate.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_across_firmwares_filters_failed_rows():
    """W2-β §SC5-NEW-ICS-S2-3 I27 — lookup MUST filter at SQL by
    ics_protocol_walk_status='completed'. Failed rows excluded from
    cross-firmware aggregation."""
    async with make_live_db() as db:
        project = Project(name="filter-failed")
        db.add(project)
        await db.flush()
        # F1 completed with s7comm match
        f1 = _make_firmware(project.id, "1")
        f1.ics_protocol_walk_status = "completed"
        f1.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"s7comm": 1},
            manifest_sources_seen=["_system"],
        )
        # F2 failed with partial s7comm JSONB (shouldn't happen per Rule #33 .b
        # but defensive testing — the gate must hold even if walker is buggy).
        f2 = _make_firmware(project.id, "2")
        f2.ics_protocol_walk_status = "failed"
        f2.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"s7comm": 5},
            manifest_sources_seen=["_system"],
        )
        # F3 idle — never ran.
        f3 = _make_firmware(project.id, "3")
        db.add_all([f1, f2, f3])
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_ics_protocol_across_firmwares(
                {"protocol_family": "s7comm", "scope": "project"}, ctx,
            )
        )
        assert out["match_count"] == 1, (
            f"W2-β §SC5-NEW-ICS-S2-3 — only F1 (completed) should match; "
            f"F2 (failed) and F3 (idle) excluded. Got: {out!r}"
        )
        match_fw_ids = {m["firmware_id"] for m in out["matches"]}
        assert str(f1.id) in match_fw_ids


@pytest.mark.asyncio
async def test_lookup_across_firmwares_filters_legacy_schema_version():
    """W2-β §SC5-NEW-ICS-S2-ι I39 — lookup MUST filter
    ``result.schema_version == 1``; legacy rows with no schema_version
    field are silently excluded."""
    async with make_live_db() as db:
        project = Project(name="filter-legacy")
        db.add(project)
        await db.flush()
        # F1 v1 schema — included
        f1 = _make_firmware(project.id, "5")
        f1.ics_protocol_walk_status = "completed"
        f1.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"dnp3": 1},
            manifest_sources_seen=["_system"],
        )
        # F2 legacy (no schema_version) — excluded
        f2 = _make_firmware(project.id, "6")
        f2.ics_protocol_walk_status = "completed"
        f2.ics_protocol_walk_result = {
            # Pre-Rule-#35c legacy shape — no schema_version, no provenance
            "matches": [{"protocol_family": "dnp3"}],
            "protocol_family_counts": {"dnp3": 99},  # would over-count
        }
        db.add_all([f1, f2])
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_ics_protocol_across_firmwares(
                {"protocol_family": "dnp3", "scope": "project"}, ctx,
            )
        )
        assert out["match_count"] == 1, (
            f"W2-β §SC5-NEW-ICS-S2-ι — legacy row F2 (no schema_version) "
            f"MUST be excluded; only F1 should match. Got: {out!r}"
        )
        assert out["excluded_provenance_count"] == 1, (
            f"excluded_provenance_count MUST surface the silent skip "
            f"so operators see the legacy-row gap. Got: {out!r}"
        )


@pytest.mark.asyncio
async def test_lookup_across_firmwares_supply_chain_signal_requires_curated():
    """W2-β §SC5-NEW-ICS-S2-γ I30 — supply_chain_signal MUST require
    at least one matching firmware's manifest_sources_seen to contain
    a curated tier (_system or core). Operator-tier-only matches do
    NOT trigger the flag.

    Synthesizes 2 firmwares both matching modbus_tcp but with
    operator-tier-only manifest_sources_seen. Asserts match_count=2
    but supply_chain_signal=False.
    """
    async with make_live_db() as db:
        project = Project(name="curated-signal")
        db.add(project)
        await db.flush()
        for i, seed in enumerate(["7", "8"]):
            fw = _make_firmware(project.id, seed)
            fw.ics_protocol_walk_status = "completed"
            fw.ics_protocol_walk_result = _walker_result(
                protocol_family_counts={"modbus_tcp": 1},
                manifest_sources_seen=["operator"],  # NOT curated
            )
            db.add(fw)
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_ics_protocol_across_firmwares(
                {"protocol_family": "modbus_tcp", "scope": "project"}, ctx,
            )
        )
        assert out["match_count"] == 2, (
            f"Both firmwares should match the family. Got: {out!r}"
        )
        assert out["supply_chain_signal"] is False, (
            f"W2-β §SC5-NEW-ICS-S2-γ — supply_chain_signal MUST be False "
            f"when no matching firmware has a curated-tier manifest_source. "
            f"Operator-tier-only matches do NOT trigger the flag — "
            f"otherwise the cross-firmware tool becomes a noise generator "
            f"on operator-supplied YAMLs. Got: {out!r}"
        )


@pytest.mark.asyncio
async def test_lookup_across_firmwares_supply_chain_signal_fires_when_curated():
    """Pair canary — when a curated-tier match IS present AND
    match_count >= 2, supply_chain_signal fires."""
    async with make_live_db() as db:
        project = Project(name="curated-fires")
        db.add(project)
        await db.flush()
        fw1 = _make_firmware(project.id, "9")
        fw1.ics_protocol_walk_status = "completed"
        fw1.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"modbus_tcp": 1},
            manifest_sources_seen=["_system"],  # curated
        )
        fw2 = _make_firmware(project.id, "0")
        fw2.ics_protocol_walk_status = "completed"
        fw2.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"modbus_tcp": 1},
            manifest_sources_seen=["_system"],  # curated
        )
        db.add_all([fw1, fw2])
        await db.flush()

        ctx = _StubContext(db=db, project_id=project.id)
        out = json.loads(
            await _handle_lookup_ics_protocol_across_firmwares(
                {"protocol_family": "modbus_tcp", "scope": "project"}, ctx,
            )
        )
        assert out["match_count"] == 2
        assert out["supply_chain_signal"] is True, (
            f"supply_chain_signal MUST fire when match_count >= 2 AND a "
            f"curated-tier match is present. Got: {out!r}"
        )
        assert "supply_chain_signal_reason" in out


# ───────────────────────────────────────────────────────────────────────
# describe_ics_protocol_anomalies — W2-β §SC5-NEW-ICS-S2-β surfacing.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_describe_anomalies_surfaces_consistency_warning():
    """W2-β §SC5-NEW-ICS-S2-β I32 — describe_ics_protocol_anomalies MUST
    surface ``consistency_warning`` as an anomaly so operators see when
    mid-walk catalog drift poisoned the JSONB."""
    async with make_live_db() as db:
        project = Project(name="anomaly-drift")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "a")
        firmware.ics_protocol_walk_status = "completed"
        firmware.ics_protocol_walk_result = _walker_result(
            consistency_warning="catalog snapshot changed mid-walk (abc -> def)",
        )
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_describe_ics_protocol_anomalies({}, ctx)
        )
        assert out["anomaly_count"] >= 1, (
            f"W2-β §SC5-NEW-ICS-S2-β — describe MUST surface "
            f"consistency_warning as an anomaly. Got: {out!r}"
        )
        anomaly_types = {a["anomaly"] for a in out["anomalies"]}
        assert "mid_walk_catalog_drift" in anomaly_types


@pytest.mark.asyncio
async def test_describe_anomalies_multi_protocol_threshold():
    """describe surfaces multi_protocol anomaly when 3+ protocol families
    detected (rare outside multi-vendor HMI gateways)."""
    async with make_live_db() as db:
        project = Project(name="multi-proto")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "b")
        firmware.ics_protocol_walk_status = "completed"
        firmware.ics_protocol_walk_result = _walker_result(
            protocol_family_counts={"modbus_tcp": 1, "dnp3": 1, "s7comm": 1},
            manifest_sources_seen=["_system"],
        )
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)
        out = json.loads(
            await _handle_describe_ics_protocol_anomalies({}, ctx)
        )
        anomaly_types = {a["anomaly"] for a in out["anomalies"]}
        assert "multi_protocol" in anomaly_types, (
            f"3+ protocol families MUST surface multi_protocol anomaly. "
            f"Got: {out!r}"
        )
