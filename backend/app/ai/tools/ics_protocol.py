"""ICS protocol catalog MCP tools (CLAUDE.md Rule #52 instance #3, Session 2 Phase 3).

Four tools surfacing the Phase 1 walker's output to MCP consumers:

- ``trigger_ics_protocol_walk(firmware_id)`` — operator-trigger entry to the
  Rule #33 .a state machine; flips ``idle → queued`` and fires
  ``run_ics_protocol_walk_background`` via ``asyncio.create_task``. Filters
  by ``context.project_id`` per W2-β §SC5-NEW-ICS-S2-ε (I35) to prevent
  cross-project trigger via ``switch_project``. Rule #33 .a 409-on-conflict.

- ``list_ics_protocols(firmware_id)`` — reads
  ``firmware.ics_protocol_walk_result`` for a single firmware and returns
  the per-binary match aggregate. Respects the W2-β §SC5-NEW-ICS-S2-β
  ``consistency_warning`` field — downstream consumers MUST refuse to
  attribute curated CVEs when set.

- ``lookup_ics_protocol_across_firmwares(query)`` — CLAUDE.md Rule #44
  mandatory cross-firmware aggregation tool. Filters at the SQL layer
  by ``ics_protocol_walk_status = 'completed'`` (W2-β §SC5-NEW-ICS-S2-3
  I27 + §SC5-NEW-ICS-S2-γ filter); filters in-Python by
  ``schema_version=1`` (W2-β §SC5-NEW-ICS-S2-ι I39 legacy-rows gate),
  ``provenance='walker'`` (W2-β §SC5-NEW-ICS-S2-1 I14 sister-provenance
  gate), and absence of ``consistency_warning`` (W2-β §SC5-NEW-ICS-S2-β).
  ``supply_chain_signal`` flag fires only when match_count ≥ 2 AND the
  matching firmwares' ``manifest_sources_seen`` contain at least one
  ``_system`` or ``core`` entry (W2-β §SC5-NEW-ICS-S2-γ I30 curated-only
  signal-source filter).

- ``describe_ics_protocol_anomalies(firmware_id)`` — operator-UX surface
  for unusual matches. Flags multi-protocol firmwares (3+ protocol
  families) and ``consistency_warning`` rows. Tier-1 helper; not
  load-bearing for cross-firmware lookup.

Tenancy contract (W2-β §SC5-NEW-ICS-S2-ε): single-tenant deployment today,
so ``scope='global'`` is operator-owned cross-project introspection (not
exfil); when wairz becomes multi-tenant, the docstring direction is to
acquire ``context.permitted_project_ids`` and filter the WHERE clause in
all 10 ``lookup_*_across_firmwares`` tools (Rule #44 Rule-of-Nine).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.utils.truncation import truncate_output

logger = logging.getLogger(__name__)


# Limits for the cross-firmware lookup tool — bounded to avoid pathological
# query/result load. Mirrors linux_systemd.py:460-464 conventions.
_LOOKUP_LIMIT_MAX = 500
_LOOKUP_LIMIT_DEFAULT = 100

# Supply-chain signal threshold — when ≥ N firmwares match AND at least
# one matching firmware's manifest_sources_seen contains a curated tier
# (``_system`` or ``core``), the flag fires. Per W2-β §SC5-NEW-ICS-S2-γ
# I30 — operator-tier-only matches do NOT trigger the signal.
_SUPPLY_CHAIN_SIGNAL_MIN_MATCHES = 2
_CURATED_MANIFEST_SOURCES: frozenset[str] = frozenset({"_system", "core"})

# Per-anomalies tool: a firmware speaking N+ protocol families is unusual
# (most ICS firmwares speak 1, occasionally 2). 3+ is the threshold for
# operator review.
_MULTI_PROTOCOL_ANOMALY_THRESHOLD = 3


def _truncate(payload: str) -> str:
    """Truncate to the canonical MCP output budget."""
    return truncate_output(payload)


def _result_passes_provenance_gates(result: dict) -> tuple[bool, str | None]:
    """Apply the W2-β §SC5-NEW-ICS-S2-{1,β,ι} consumer-side gates.

    Returns ``(passes, reason_if_rejected)``. A walker-result that
    fails ANY gate is excluded from cross-firmware aggregation.
    """
    if result.get("schema_version") != 1:
        return False, "schema_version != 1 (legacy or unstamped)"
    if result.get("provenance") != "walker":
        return False, (
            f"provenance != 'walker' "
            f"(got {result.get('provenance')!r}) — possible descriptor "
            f"pre-seed; refuse attribution"
        )
    if result.get("consistency_warning"):
        return False, "consistency_warning set — refuse attribution"
    return True, None


# ── trigger_ics_protocol_walk (Rule #33 .a + Rule #44 ε project scope) ────


async def _handle_trigger_ics_protocol_walk(
    input: dict, context: ToolContext,
) -> str:
    """Operator-trigger the ICS protocol catalog walker (Rule #33 .a).

    Flips ``ics_protocol_walk_status`` ``idle → queued`` and fires the
    OUTER background runner via ``asyncio.create_task``. Returns 409 if
    a walk is already in flight.

    W2-β §SC5-NEW-ICS-S2-ε (I35) — filters by ``context.project_id`` so
    operator-A in P1 cannot trigger a walker against operator-B's
    firmware in P2 via the ``switch_project`` MCP path.
    """
    firmware_id_raw = input.get("firmware_id") or context.firmware_id
    if firmware_id_raw is None:
        return json.dumps({"error": "firmware_id is required"})
    firmware_id = (
        uuid.UUID(firmware_id_raw)
        if isinstance(firmware_id_raw, str)
        else firmware_id_raw
    )

    # W2-β §SC5-NEW-ICS-S2-ε project-scope guard. The handler MUST scope
    # the SELECT against context.project_id; missing-row → 404 even if
    # the firmware exists in a different project.
    if not context.project_id:
        return json.dumps({
            "error": (
                "no active project — call switch_project before "
                "trigger_ics_protocol_walk"
            ),
        })
    project_id = (
        uuid.UUID(context.project_id)
        if isinstance(context.project_id, str)
        else context.project_id
    )
    row = (
        await context.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({
            "error": (
                f"firmware {firmware_id} not found in active project "
                f"{project_id} — either the id is wrong OR the firmware "
                f"belongs to a different project (tenancy scope guard)"
            ),
        })

    if row.ics_protocol_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.ics_protocol_walk_status,
            "started_at": (
                row.ics_protocol_walk_started_at.isoformat()
                if row.ics_protocol_walk_started_at
                else None
            ),
            "message": (
                f"ICS walk already {row.ics_protocol_walk_status} "
                f"for firmware {firmware_id}. Poll "
                "ics_protocol_walk_status."
            ),
        })

    row.ics_protocol_walk_status = "queued"
    row.ics_protocol_walk_started_at = None
    row.ics_protocol_walk_finished_at = None
    row.ics_protocol_walk_error = None
    row.ics_protocol_walk_result = None
    await context.db.flush()

    from app.services.ics_protocol_walker import (
        run_ics_protocol_walk_background,
    )

    asyncio.create_task(run_ics_protocol_walk_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "ICS protocol walk scheduled. Poll ics_protocol_walk_status "
            "until status=='completed' to harvest the result via "
            "list_ics_protocols."
        ),
    })


# ── list_ics_protocols (read JSONB for one firmware) ──────────────────────


async def _handle_list_ics_protocols(
    input: dict, context: ToolContext,
) -> str:
    """Return the ICS protocol catalog walker aggregate for one firmware.

    Reads ``firmware.ics_protocol_walk_result`` JSONB; surfaces the
    canonical shape per ``_stamp_firmware_ics_protocol_walk_result``.
    Includes the W2-β §SC5-NEW-ICS-S2-β ``consistency_warning`` field so
    operators see when a walker ran against a torn catalog snapshot.
    """
    firmware_id_raw = input.get("firmware_id") or context.firmware_id
    if firmware_id_raw is None:
        return json.dumps({"error": "firmware_id is required"})
    firmware_id = (
        uuid.UUID(firmware_id_raw)
        if isinstance(firmware_id_raw, str)
        else firmware_id_raw
    )

    row = await context.db.get(Firmware, firmware_id)
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    if row.ics_protocol_walk_status != "completed":
        return json.dumps({
            "firmware_id": str(firmware_id),
            "status": row.ics_protocol_walk_status,
            "result": None,
            "hint": (
                f"walker is {row.ics_protocol_walk_status}; trigger via "
                f"trigger_ics_protocol_walk and poll until completed."
            ),
        })

    result = row.ics_protocol_walk_result or {}
    passes, reject_reason = _result_passes_provenance_gates(result)
    out: dict = {
        "firmware_id": str(firmware_id),
        "status": row.ics_protocol_walk_status,
        "result": result,
    }
    if not passes:
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate: {reject_reason}. "
            f"Downstream CVE-attribution consumers MUST refuse to apply "
            f"protocol-family-derived findings."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── lookup_ics_protocol_across_firmwares (Rule #44 MANDATORY) ─────────────


async def _handle_lookup_ics_protocol_across_firmwares(
    input: dict, context: ToolContext,
) -> str:
    """CROSS-FIRMWARE AGGREGATION — Rule #44 mandatory tool.

    Given a ``protocol_family`` (one of the IcsProtocolFamily Literal
    values), return ALL firmware images in the active project (or
    globally) whose walker matched the given family on at least one
    binary.

    Applies the W2-β §SC5-NEW-ICS-S2 provenance gates:
    - Rule-of-defense-in-depth filter at SQL layer:
      ``ics_protocol_walk_status = 'completed'`` AND
      ``ics_protocol_walk_result IS NOT NULL`` (W2-β §SC5-NEW-ICS-S2-3
      I27 + §SC5-NEW-ICS-S2-γ).
    - Per-row Python filter via ``_result_passes_provenance_gates``:
      ``schema_version == 1`` (W2-β §SC5-NEW-ICS-S2-ι I39 legacy-rows),
      ``provenance == "walker"`` (W2-β §SC5-NEW-ICS-S2-1 I14
      sister-provenance), absence of ``consistency_warning``
      (W2-β §SC5-NEW-ICS-S2-β I32 mid-walk drift).

    ``supply_chain_signal`` flag fires when match_count ≥ 2 AND at
    least one matching firmware's ``manifest_sources_seen`` contains
    a curated-tier source (``_system`` or ``core``). Operator-tier-only
    matches do NOT trigger the signal (W2-β §SC5-NEW-ICS-S2-γ I30).
    """
    protocol_family = input.get("protocol_family")
    if not protocol_family:
        return json.dumps({"error": "protocol_family is required"})
    scope = input.get("scope", "project")
    limit = int(input.get("limit", _LOOKUP_LIMIT_DEFAULT))
    limit = max(1, min(limit, _LOOKUP_LIMIT_MAX))

    where_clauses = [
        Firmware.ics_protocol_walk_status == "completed",
        Firmware.ics_protocol_walk_result.isnot(None),
    ]

    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — call "
                    "switch_project first or use scope='global'."
                )
            })
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )
    else:
        stmt = (
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    excluded_provenance: int = 0
    excluded_no_family: int = 0
    curated_match_seen = False
    for firmware, project in rows:
        result = firmware.ics_protocol_walk_result or {}
        passes, _ = _result_passes_provenance_gates(result)
        if not passes:
            excluded_provenance += 1
            continue
        family_counts = result.get("protocol_family_counts", {})
        if protocol_family not in family_counts:
            excluded_no_family += 1
            continue
        manifest_sources = result.get("manifest_sources_seen", []) or []
        family_match_count = int(family_counts.get(protocol_family, 0))
        is_curated = any(
            src in _CURATED_MANIFEST_SOURCES for src in manifest_sources
        )
        if is_curated:
            curated_match_seen = True
        matches.append({
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "match_count": family_match_count,
            "manifest_ids_seen": result.get("manifest_ids_seen", []),
            "manifest_sources_seen": manifest_sources,
            "is_curated_match": is_curated,
            "walked_at": result.get("walked_at"),
        })

    out: dict = {
        "protocol_family": protocol_family,
        "scope": scope,
        "match_count": len(matches),
        "excluded_provenance_count": excluded_provenance,
        "excluded_no_family_count": excluded_no_family,
        "matches": matches,
    }

    # W2-β §SC5-NEW-ICS-S2-γ I30 — supply_chain_signal flag fires only
    # when threshold met AND curated tier present in the match set.
    supply_chain_signal = (
        len(matches) >= _SUPPLY_CHAIN_SIGNAL_MIN_MATCHES
        and curated_match_seen
    )
    out["supply_chain_signal"] = supply_chain_signal
    if supply_chain_signal:
        out["supply_chain_signal_reason"] = (
            f"Protocol family {protocol_family!r} present in "
            f"{len(matches)} firmware images with at least one curated-"
            f"tier (_system or core) manifest_source match — possible "
            f"vendor-pushed protocol stack OR shared supply-chain "
            f"propagation. Compare manifest_ids_seen + walked_at across "
            f"matches to distinguish."
        )

    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has detected the ICS "
            f"protocol family {protocol_family!r}. Run "
            f"trigger_ics_protocol_walk on more firmwares, then re-query."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── describe_ics_protocol_anomalies (operator-UX) ─────────────────────────


async def _handle_describe_ics_protocol_anomalies(
    input: dict, context: ToolContext,
) -> str:
    """Surface unusual ICS protocol-detection outcomes for one firmware.

    Anomalies surfaced:
    - Multi-protocol firmware (3+ distinct families) — unusual outside
      multi-vendor HMI gateways
    - ``consistency_warning`` set — mid-walk catalog drift; finding
      attribution suspect
    - Failed walker run with partial JSONB (defensive — Rule #33 .b
      contract should clear, but operators see if a regression occurred)
    """
    firmware_id_raw = input.get("firmware_id") or context.firmware_id
    if firmware_id_raw is None:
        return json.dumps({"error": "firmware_id is required"})
    firmware_id = (
        uuid.UUID(firmware_id_raw)
        if isinstance(firmware_id_raw, str)
        else firmware_id_raw
    )
    row = await context.db.get(Firmware, firmware_id)
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    if row.ics_protocol_walk_status != "completed":
        return json.dumps({
            "firmware_id": str(firmware_id),
            "status": row.ics_protocol_walk_status,
            "anomalies": [],
            "hint": "walker has not completed; nothing to describe yet.",
        })

    result = row.ics_protocol_walk_result or {}
    anomalies: list[dict] = []

    family_counts = result.get("protocol_family_counts", {}) or {}
    if len(family_counts) >= _MULTI_PROTOCOL_ANOMALY_THRESHOLD:
        anomalies.append({
            "anomaly": "multi_protocol",
            "severity": "info",
            "detail": (
                f"firmware speaks {len(family_counts)} distinct ICS "
                f"protocol families: {sorted(family_counts.keys())!r}; "
                f"unusual outside multi-vendor HMI gateways"
            ),
        })

    cw = result.get("consistency_warning")
    if cw:
        anomalies.append({
            "anomaly": "mid_walk_catalog_drift",
            "severity": "high",
            "detail": (
                f"catalog snapshot changed mid-walk: {cw!r}. Downstream "
                f"CVE matcher / cross-firmware lookup MUST refuse "
                f"attribution. Re-trigger via trigger_ics_protocol_walk."
            ),
        })

    if result.get("provenance") != "walker":
        anomalies.append({
            "anomaly": "non_walker_provenance",
            "severity": "high",
            "detail": (
                f"JSONB provenance={result.get('provenance')!r} — possible "
                f"descriptor pre-seed bypassing the walker sister-key "
                f"gate (W2-β §SC5-NEW-ICS-S2-1)"
            ),
        })

    if result.get("errors"):
        anomalies.append({
            "anomaly": "walker_errors",
            "severity": "low",
            "detail": (
                f"walker emitted {len(result['errors'])} per-binary error(s); "
                f"see ics_protocol_walk_result.errors via list_ics_protocols"
            ),
        })

    return _truncate(json.dumps({
        "firmware_id": str(firmware_id),
        "status": row.ics_protocol_walk_status,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────


def register_ics_protocol_tools(registry: ToolRegistry) -> None:
    """Register the ICS protocol catalog MCP tool category.

    CLAUDE.md Rule #52 instance #3 / Phase 3. Adds 4 tools to the
    registry. The cross-firmware lookup is the Rule #44 MANDATORY
    addition (Rule-of-Nine durable beyond debate).
    """
    registry.register(
        name="trigger_ics_protocol_walk",
        description=(
            "Rule #52 instance #3 / Rule #33 .a — operator-trigger the "
            "ICS protocol catalog walker against the active firmware. "
            "Flips ics_protocol_walk_status idle → queued and dispatches "
            "the background runner. Returns 409 if a walk is already "
            "queued/running. Polling shape: trigger → poll "
            "ics_protocol_walk_status until 'completed' → harvest via "
            "list_ics_protocols."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware to walk; defaults to "
                        "context.firmware_id"
                    ),
                },
            },
        },
        handler=_handle_trigger_ics_protocol_walk,
    )
    registry.register(
        name="list_ics_protocols",
        description=(
            "Read ics_protocol_walk_result JSONB for one firmware. "
            "Returns the canonical aggregate: per-binary matches, "
            "protocol_family_counts, manifest_ids_seen, snapshot "
            "pinning fields, consistency_warning. The walker MUST "
            "have completed first — call trigger_ics_protocol_walk."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware; defaults to "
                        "context.firmware_id"
                    ),
                },
            },
        },
        handler=_handle_list_ics_protocols,
    )
    registry.register(
        name="lookup_ics_protocol_across_firmwares",
        description=(
            "Rule #44 MANDATORY cross-firmware aggregation tool — "
            "given a protocol_family (modbus_tcp / modbus_rtu / dnp3 "
            "/ s7comm / unknown_ics), return every firmware in the "
            "active project (or globally) whose walker matched the "
            "family on at least one binary. Sets supply_chain_signal "
            "when match_count >= 2 AND at least one matching firmware "
            "has a curated-tier (_system/core) manifest_source — "
            "indicates possible vendor-pushed protocol stack or shared "
            "supply-chain propagation."
        ),
        input_schema={
            "type": "object",
            "required": ["protocol_family"],
            "properties": {
                "protocol_family": {
                    "type": "string",
                    "enum": [
                        "modbus_tcp",
                        "modbus_rtu",
                        "dnp3",
                        "s7comm",
                        "unknown_ics",
                    ],
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "'project' restricts to the active project; "
                        "'global' searches all projects (admin-only "
                        "introspection in single-tenant; future "
                        "multi-tenant deploy MUST gate)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _LOOKUP_LIMIT_MAX,
                },
            },
        },
        handler=_handle_lookup_ics_protocol_across_firmwares,
    )
    registry.register(
        name="describe_ics_protocol_anomalies",
        description=(
            "Surface unusual outcomes for one firmware's ICS walker "
            "result — multi-protocol firmwares (3+ families), "
            "mid-walk catalog drift consistency_warning, non-walker "
            "JSONB provenance (sister-key gate trip), and per-binary "
            "errors. Tier-1 operator-UX helper; consult list_ics_protocols "
            "for the full result aggregate."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware; defaults to "
                        "context.firmware_id"
                    ),
                },
            },
        },
        handler=_handle_describe_ics_protocol_anomalies,
    )


__all__ = [
    "_handle_describe_ics_protocol_anomalies",
    "_handle_list_ics_protocols",
    "_handle_lookup_ics_protocol_across_firmwares",
    "_handle_trigger_ics_protocol_walk",
    "register_ics_protocol_tools",
]
