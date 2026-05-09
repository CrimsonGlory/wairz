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
