"""Windows Prefetch MCP tools — Phase ζ.2.E.

Surfaces the Phase ζ.2.B Prefetch-walk results to the MCP layer:

- ``search_prefetch_records`` — paginate the windows_prefetch_records
  table for the active firmware by executable_name (exact match) and/or
  last_run_time range. Returns up to ``limit`` rows per page (default
  50, max 500) with total_count for pagination.
- ``prefetch_walk_status`` — Rule #33 status reader for the firmware-row
  prefetch_walk_* state machine.
- ``trigger_prefetch_walk`` — trigger the 202+polling Prefetch-walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).

Sandbox discipline (Rule #1): no path inputs (the walker resolves paths
itself via get_detection_roots; this MCP layer only reads the persisted
rows).

Rule #36 no-execute discipline: tools read .pf files AS DATA via
windowsprefetch (struct unpack); nothing in this module invokes
pftriage / Get-CimInstance Win32_PrefetchedApp / scriptable replay.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps emit
a tail-truncation marker.
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
from app.models.windows_prefetch_record import WindowsPrefetchRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_prefetch_walk_result,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text.encode("utf-8")) <= cap:
        return text
    # Truncate to cap-200 to leave room for the marker.
    encoded = text.encode("utf-8")[: cap - 200]
    truncated = encoded.decode("utf-8", errors="ignore")
    return (
        truncated
        + "\n\n[output truncated to 30KB — narrow filters or use offset+limit "
        "to paginate]"
    )


# ── search_prefetch_records ─────────────────────────────────────────────────


async def _handle_search_prefetch_records(
    input: dict, context: ToolContext
) -> str:
    """Paginate the windows_prefetch_records table for the active firmware.

    Filters: executable_name (exact match — names are upper-case .EXE
    forms), last_run_time_start, last_run_time_end. Pagination via
    limit + offset. Order: last_run_time DESC for forensic-timeline UX.
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    executable_name = input.get("executable_name")
    time_range_start = input.get("last_run_time_start")
    time_range_end = input.get("last_run_time_end")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    # Bound limit defensively.
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsPrefetchRecord.firmware_id == firmware_id]
    if executable_name:
        base_where.append(WindowsPrefetchRecord.executable_name == executable_name)
    if time_range_start:
        try:
            ts = _dt.datetime.fromisoformat(
                time_range_start.replace("Z", "+00:00")
            )
            base_where.append(WindowsPrefetchRecord.last_run_time >= ts)
        except ValueError:
            return json.dumps(
                {
                    "error": (
                        f"invalid last_run_time_start: {time_range_start[:100]}"
                    )
                }
            )
    if time_range_end:
        try:
            ts = _dt.datetime.fromisoformat(
                time_range_end.replace("Z", "+00:00")
            )
            base_where.append(WindowsPrefetchRecord.last_run_time <= ts)
        except ValueError:
            return json.dumps(
                {"error": f"invalid last_run_time_end: {time_range_end[:100]}"}
            )

    # Total count (uses the same indexes as the page query).
    total_q = select(sa_func.count(WindowsPrefetchRecord.id)).where(*base_where)
    total = (await context.db.execute(total_q)).scalar_one()

    # Page query — order by last_run_time DESC.
    page_q = (
        select(WindowsPrefetchRecord)
        .where(*base_where)
        .order_by(WindowsPrefetchRecord.last_run_time.desc().nulls_last())
        .limit(limit)
        .offset(offset)
    )
    rows = (await context.db.execute(page_q)).scalars().all()

    records = [
        {
            "id": str(r.id),
            "prefetch_file_path": r.prefetch_file_path,
            "executable_name": r.executable_name,
            "prefetch_hash": r.prefetch_hash,
            "version": r.version,
            "run_count": r.run_count,
            "last_run_time": (
                r.last_run_time.isoformat() if r.last_run_time else None
            ),
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
            "executable_name": executable_name,
            "last_run_time_start": time_range_start,
            "last_run_time_end": time_range_end,
        },
    }
    if total == 0:
        out["message"] = (
            "No prefetch records match. The walker may not have run yet "
            "(call trigger_prefetch_walk and poll prefetch_walk_status), "
            "or your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── prefetch_walk_status ────────────────────────────────────────────────────


async def _handle_prefetch_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for the firmware.prefetch_walk_* state machine."""
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
        "status": row.prefetch_walk_status,
        "started_at": (
            row.prefetch_walk_started_at.isoformat()
            if row.prefetch_walk_started_at
            else None
        ),
        "finished_at": (
            row.prefetch_walk_finished_at.isoformat()
            if row.prefetch_walk_finished_at
            else None
        ),
        "error": row.prefetch_walk_error,
        "result": _normalize_firmware_prefetch_walk_result(
            row.prefetch_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_prefetch_walk ───────────────────────────────────────────────────


async def _handle_trigger_prefetch_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling Prefetch walk background runner.

    Rule #33 .a idempotent POST + 409-on-conflict. Returns conflict=true
    with the in-flight status if a run is already queued or running.
    """
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

    # Rule #33 .a — 409-on-conflict idempotency.
    if row.prefetch_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.prefetch_walk_status,
                "started_at": (
                    row.prefetch_walk_started_at.isoformat()
                    if row.prefetch_walk_started_at
                    else None
                ),
                "message": (
                    f"Prefetch walk already {row.prefetch_walk_status} for "
                    f"firmware {firmware_id}. Poll prefetch_walk_status."
                ),
            }
        )

    # Reset state for a fresh run.
    row.prefetch_walk_status = "queued"
    row.prefetch_walk_started_at = None
    row.prefetch_walk_finished_at = None
    row.prefetch_walk_error = None
    row.prefetch_walk_result = None
    await context.db.flush()  # Rule #3 — flush() not commit() in MCP handlers.

    # Schedule the background runner. Rule #33 .d — asyncio.create_task
    # for in-process pure-Python work (matches evtx_service / γ.4).
    # Lazy-imported to avoid a hard top-level dep on windowsprefetch.
    from app.services.prefetch_walker import run_prefetch_walk_background

    asyncio.create_task(run_prefetch_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "Prefetch walk scheduled. Poll prefetch_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_prefetch_tools(registry: ToolRegistry) -> None:
    """Register all Phase ζ.2.E Windows Prefetch MCP tools."""

    registry.register(
        name="search_prefetch_records",
        description=(
            "Phase ζ.2.E — paginate the per-execution "
            "windows_prefetch_records table for the active firmware by "
            "executable_name (exact, e.g. 'CHROME.EXE' / 'CMD.EXE') and "
            "ISO-8601 last_run_time range. Returns up to `limit` rows "
            "per page (default 50, max 500) with total_count so the "
            "operator can navigate large walks. Reads the ζ.2.A landing "
            "zone populated by ζ.2.B's walker. Order: last_run_time DESC "
            "(forensic-timeline UX, NULL last_run_time entries last). "
            "Indexes (firmware_id, executable_name) + (firmware_id, "
            "last_run_time) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "executable_name": {
                    "type": "string",
                    "description": (
                        "Exact executable name match (e.g. 'CHROME.EXE'). "
                        "Names from .pf headers are upper-case with .EXE "
                        "suffix."
                    ),
                },
                "last_run_time_start": {
                    "type": "string",
                    "description": (
                        "ISO-8601 timestamp (inclusive lower bound). "
                        "Example: '2025-12-25T00:00:00Z'."
                    ),
                },
                "last_run_time_end": {
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
        handler=_handle_search_prefetch_records,
    )

    registry.register(
        name="prefetch_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row prefetch_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and the "
            "last-known-result aggregate (counts by status, executable_count, "
            "total_runs_recorded)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_prefetch_walk_status,
    )

    registry.register(
        name="trigger_prefetch_walk",
        description=(
            "Trigger the 202+polling Prefetch walk background runner. "
            "Idempotent (Rule #33 .a) — returns conflict=true with the "
            "in-flight status if a run is already queued or running. On "
            "fresh runs, resets the firmware-row state and schedules "
            "run_prefetch_walk_background via asyncio.create_task. Poll "
            "prefetch_walk_status until status=='completed' to harvest "
            "the result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_prefetch_walk,
    )
