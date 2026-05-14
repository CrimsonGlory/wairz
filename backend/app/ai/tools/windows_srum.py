"""Windows SRUM MCP tools — Phase ζ.3.E.

Surfaces the Phase ζ.3.B SRUM-walk results to the MCP layer:

- ``search_srum_records`` — paginate the windows_srum_records table for
  the active firmware by record_type / app_identifier / time range.
- ``srum_walk_status`` — Rule #33 status reader for the firmware-row
  srum_walk_* state machine.
- ``trigger_srum_walk`` — trigger the 202+polling SRUM-walk background
  runner (Rule #33 .a idempotent POST + 409-on-conflict).

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.windows_srum_record import WindowsSrumRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_srum_walk_result,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Canonical record_type values — matches the ck_windows_srum_records_record_type
# CHECK constraint exactly (ζ.3.A migration).
_VALID_RECORD_TYPES = frozenset(
    {
        "network_data_usage",
        "network_connectivity",
        "application_resource_usage",
        "push_notification",
        "energy_usage",
    }
)


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text.encode("utf-8")) <= cap:
        return text
    encoded = text.encode("utf-8")[: cap - 200]
    truncated = encoded.decode("utf-8", errors="ignore")
    return (
        truncated
        + "\n\n[output truncated to 30KB — narrow filters or use offset+limit "
        "to paginate]"
    )


# ── search_srum_records ─────────────────────────────────────────────────────


async def _handle_search_srum_records(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_srum_records by record_type / app_identifier /
    time range. Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    record_type = input.get("record_type")
    app_identifier = input.get("app_identifier")
    time_range_start = input.get("recorded_at_start")
    time_range_end = input.get("recorded_at_end")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if record_type and record_type not in _VALID_RECORD_TYPES:
        return json.dumps(
            {
                "error": (
                    f"invalid record_type {record_type!r} — must be one of: "
                    f"{sorted(_VALID_RECORD_TYPES)}"
                )
            }
        )

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsSrumRecord.firmware_id == firmware_id]
    if record_type:
        base_where.append(WindowsSrumRecord.record_type == record_type)
    if app_identifier:
        base_where.append(WindowsSrumRecord.app_identifier == app_identifier)
    if time_range_start:
        try:
            ts = _dt.datetime.fromisoformat(
                time_range_start.replace("Z", "+00:00")
            )
            base_where.append(WindowsSrumRecord.recorded_at >= ts)
        except ValueError:
            return json.dumps(
                {"error": f"invalid recorded_at_start: {time_range_start[:100]}"}
            )
    if time_range_end:
        try:
            ts = _dt.datetime.fromisoformat(
                time_range_end.replace("Z", "+00:00")
            )
            base_where.append(WindowsSrumRecord.recorded_at <= ts)
        except ValueError:
            return json.dumps(
                {"error": f"invalid recorded_at_end: {time_range_end[:100]}"}
            )

    total_q = select(sa_func.count(WindowsSrumRecord.id)).where(*base_where)
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(WindowsSrumRecord)
        .where(*base_where)
        .order_by(WindowsSrumRecord.recorded_at.desc().nulls_last())
        .limit(limit)
        .offset(offset)
    )
    rows = (await context.db.execute(page_q)).scalars().all()

    records = [
        {
            "id": str(r.id),
            "record_type": r.record_type,
            "source_path": r.source_path,
            "app_identifier": r.app_identifier,
            "user_identifier": r.user_identifier,
            "recorded_at": (
                r.recorded_at.isoformat() if r.recorded_at else None
            ),
            "bytes_sent": r.bytes_sent,
            "bytes_received": r.bytes_received,
            "bytes_read": r.bytes_read,
            "bytes_written": r.bytes_written,
            "interface_luid": r.interface_luid,
            "duration_seconds": r.duration_seconds,
            "cpu_foreground_seconds": r.cpu_foreground_seconds,
            "cpu_background_seconds": r.cpu_background_seconds,
            "push_count": r.push_count,
            "energy_charge": r.energy_charge,
            "energy_capacity": r.energy_capacity,
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "records": records,
        "filters": {
            "record_type": record_type,
            "app_identifier": app_identifier,
            "recorded_at_start": time_range_start,
            "recorded_at_end": time_range_end,
        },
    }
    if total == 0:
        out["message"] = (
            "No SRUM records match. The walker may not have run yet "
            "(call trigger_srum_walk and poll srum_walk_status), or your "
            "filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── srum_walk_status ────────────────────────────────────────────────────────


async def _handle_srum_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.srum_walk_* state machine."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )
    row = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    out = {
        "firmware_id": str(firmware_id),
        "status": row.srum_walk_status,
        "started_at": (
            row.srum_walk_started_at.isoformat()
            if row.srum_walk_started_at
            else None
        ),
        "finished_at": (
            row.srum_walk_finished_at.isoformat()
            if row.srum_walk_finished_at
            else None
        ),
        "error": row.srum_walk_error,
        "result": _normalize_firmware_srum_walk_result(
            row.srum_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_srum_walk ───────────────────────────────────────────────────────


async def _handle_trigger_srum_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling SRUM walk background runner.
    Rule #33 .a idempotent POST + 409-on-conflict."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )
    row = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    if row.srum_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.srum_walk_status,
                "started_at": (
                    row.srum_walk_started_at.isoformat()
                    if row.srum_walk_started_at
                    else None
                ),
                "message": (
                    f"SRUM walk already {row.srum_walk_status} for "
                    f"firmware {firmware_id}. Poll srum_walk_status."
                ),
            }
        )

    row.srum_walk_status = "queued"
    row.srum_walk_started_at = None
    row.srum_walk_finished_at = None
    row.srum_walk_error = None
    row.srum_walk_result = None
    await context.db.flush()

    from app.services.srum_walker import run_srum_walk_background

    asyncio.create_task(run_srum_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "SRUM walk scheduled. Poll srum_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_srum_record_across_firmwares (Rule #44) ──────────────────────────


async def _handle_lookup_srum_record_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given an app_identifier (and
    optional record_type), return ALL firmware images in the active
    project (or globally) with a matching SRUM record.

    Rule #44 — same application's resource usage logged across multiple
    captures is a strong supply-chain / persistence signal. The SRUM
    app_identifier IS typically a full Windows path, so identity is
    naturally path-aware (a LotL attacker relocating the binary lands
    under a different app_identifier).

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (matching SRUM rows in that firmware)
    - sample_record (first matching record's summary)
    - total_bytes_sent / total_bytes_received aggregates
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    app_identifier = input.get("app_identifier")
    if not app_identifier:
        return json.dumps({"error": "app_identifier is required"})

    record_type = input.get("record_type")
    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [WindowsSrumRecord.app_identifier == app_identifier]
    if record_type is not None:
        where.append(WindowsSrumRecord.record_type == record_type)

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
            select(WindowsSrumRecord, Firmware, Project)
            .join(Firmware, WindowsSrumRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsSrumRecord, Firmware, Project)
            .join(Firmware, WindowsSrumRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    by_firmware: dict[uuid.UUID, dict] = {}
    for rec, firmware, project in rows:
        slot = by_firmware.get(firmware.id)
        if slot is None:
            slot = {
                "firmware_id": str(firmware.id),
                "project_id": str(project.id),
                "project_name": project.name,
                "original_filename": firmware.original_filename,
                "sha256": firmware.sha256,
                "match_count": 0,
                "sample_record": None,
                "total_bytes_sent": 0,
                "total_bytes_received": 0,
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        slot["total_bytes_sent"] += int(rec.bytes_sent or 0)
        slot["total_bytes_received"] += int(rec.bytes_received or 0)
        if slot["sample_record"] is None:
            slot["sample_record"] = {
                "id": str(rec.id),
                "record_type": rec.record_type,
                "source_path": rec.source_path,
                "app_identifier": rec.app_identifier,
                "user_identifier": rec.user_identifier,
                "recorded_at": (
                    rec.recorded_at.isoformat() if rec.recorded_at else None
                ),
                "bytes_sent": rec.bytes_sent,
                "bytes_received": rec.bytes_received,
            }

    matches: list[dict] = []
    for slot in by_firmware.values():
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "app_identifier": app_identifier,
        "record_type": record_type,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching SRUM records found. Ensure the walker has run "
            "on the relevant firmwares (trigger_srum_walk + poll). "
            "SRUM app_identifier is typically a FULL Windows path; "
            "double-check the value."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_srum_tools(registry: ToolRegistry) -> None:
    """Register all Phase ζ.3.E Windows SRUM MCP tools."""

    registry.register(
        name="search_srum_records",
        description=(
            "Phase ζ.3.E — paginate the per-record windows_srum_records "
            "table for the active firmware by record_type (one of: "
            "network_data_usage, network_connectivity, "
            "application_resource_usage, push_notification, energy_usage), "
            "app_identifier (exact match — typically a full Windows path "
            "like 'C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe'), "
            "and ISO-8601 recorded_at range. Returns up to `limit` rows "
            "per page (default 50, max 500) with total_count for "
            "navigation. Reads the ζ.3.A landing zone populated by ζ.3.B's "
            "walker. Order: recorded_at DESC (forensic-timeline UX). "
            "Indexes (firmware_id, record_type, recorded_at) + "
            "(firmware_id, app_identifier) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "record_type": {
                    "type": "string",
                    "enum": [
                        "network_data_usage",
                        "network_connectivity",
                        "application_resource_usage",
                        "push_notification",
                        "energy_usage",
                    ],
                    "description": (
                        "Discriminator filter — which SRUM GUID-table "
                        "the row came from."
                    ),
                },
                "app_identifier": {
                    "type": "string",
                    "description": (
                        "Exact app_identifier match (typically a full "
                        "Windows executable path)."
                    ),
                },
                "recorded_at_start": {
                    "type": "string",
                    "description": (
                        "ISO-8601 timestamp (inclusive lower bound). "
                        "Example: '2025-12-25T00:00:00Z'."
                    ),
                },
                "recorded_at_end": {
                    "type": "string",
                    "description": "ISO-8601 timestamp (inclusive upper bound).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Page size (default 50, min 1, max 500).",
                    "minimum": 1,
                    "maximum": 500,
                },
                "offset": {
                    "type": "integer",
                    "description": "Page offset for pagination (default 0).",
                    "minimum": 0,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_search_srum_records,
    )

    registry.register(
        name="srum_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row srum_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and "
            "the last-known-result aggregate (counts by record_type, "
            "unique_apps, total_records)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_srum_walk_status,
    )

    registry.register(
        name="trigger_srum_walk",
        description=(
            "Trigger the 202+polling SRUM walk background runner. "
            "Idempotent (Rule #33 .a) — returns conflict=true with the "
            "in-flight status if a run is already queued or running. "
            "Schedules run_srum_walk_background via asyncio.create_task. "
            "Poll srum_walk_status until status=='completed' to harvest "
            "the result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_srum_walk,
    )

    registry.register(
        name="lookup_srum_record_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given an "
            "app_identifier (and optional record_type), return ALL "
            "firmware images in the active project (or globally, with "
            "scope='global') that contain a matching SRUM record. "
            "Identity key is (app_identifier, record_type). SRUM "
            "app_identifier IS typically a full Windows path, so a "
            "LotL attacker who relocates the binary lands under a "
            "different identifier. Returns one entry per matching "
            "firmware with match_count, sample_record, "
            "total_bytes_sent / total_bytes_received aggregates, and "
            "supply_chain_signal=True when match_count >= 2 firmwares "
            "(application's resource usage logged across captures)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_identifier": {
                    "type": "string",
                    "description": (
                        "Required. Exact app identifier as stored in "
                        "the SRUM table (typically a full path like "
                        "'C:\\\\Program Files\\\\Google\\\\Chrome"
                        "\\\\Application\\\\chrome.exe')."
                    ),
                },
                "record_type": {
                    "type": "string",
                    "enum": [
                        "network_data_usage",
                        "network_connectivity",
                        "application_resource_usage",
                        "push_notification",
                        "energy_usage",
                    ],
                    "description": (
                        "Optional. Filter to one SRUM provider's "
                        "records."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "Search scope. 'project' (default) restricts to "
                        "firmwares in the active project; 'global' "
                        "searches across all projects."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": (
                        "Maximum number of distinct firmwares to return "
                        "(default 100, max 500)."
                    ),
                },
            },
            "required": ["app_identifier"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_srum_record_across_firmwares,
    )
