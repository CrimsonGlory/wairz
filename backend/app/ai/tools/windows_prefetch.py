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
from app.models.project import Project
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


# ── lookup_prefetch_record_across_firmwares (Rule #44) ──────────────────────


async def _handle_lookup_prefetch_record_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given an executable_name (and
    optional prefetch_hash), return ALL firmware images in the active
    project (or globally) with a matching Prefetch record.

    Rule #44 — same executable observed running across multiple captures
    is a strong signal. The Windows prefetch_hash bakes in the executable
    PATH at execution time, so (executable_name, prefetch_hash)
    distinguishes "the same exe ran from the same path" from "an exe
    with the same name ran from different paths" — the latter is the
    LotL-relocation indicator (attackers copy cmd.exe to a new location
    so its prefetch hash changes).

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (matching prefetch rows in that firmware)
    - sample_record (first matching record's summary)
    - max_run_count (highest run_count across matching rows — frequently-
      run binaries score higher)
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    executable_name = input.get("executable_name")
    if not executable_name:
        return json.dumps({"error": "executable_name is required"})

    prefetch_hash = input.get("prefetch_hash")
    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [WindowsPrefetchRecord.executable_name == executable_name]
    if prefetch_hash is not None:
        where.append(WindowsPrefetchRecord.prefetch_hash == prefetch_hash)

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
            select(WindowsPrefetchRecord, Firmware, Project)
            .join(Firmware, WindowsPrefetchRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsPrefetchRecord, Firmware, Project)
            .join(Firmware, WindowsPrefetchRecord.firmware_id == Firmware.id)
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
                "max_run_count": 0,
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        rc = rec.run_count or 0
        if rc > slot["max_run_count"]:
            slot["max_run_count"] = rc
        if slot["sample_record"] is None:
            slot["sample_record"] = {
                "id": str(rec.id),
                "prefetch_file_path": rec.prefetch_file_path,
                "executable_name": rec.executable_name,
                "prefetch_hash": rec.prefetch_hash,
                "version": rec.version,
                "run_count": rec.run_count,
                "last_run_time": (
                    rec.last_run_time.isoformat()
                    if rec.last_run_time
                    else None
                ),
            }

    matches: list[dict] = []
    for slot in by_firmware.values():
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "executable_name": executable_name,
        "prefetch_hash": prefetch_hash,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching prefetch records found. Ensure the walker has "
            "run on the relevant firmwares (trigger_prefetch_walk + "
            "poll). Prefetch file names are upper-cased on disk; the "
            "executable_name stored here is the uppercase form (e.g. "
            "'CMD.EXE')."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


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

    registry.register(
        name="lookup_prefetch_record_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given an "
            "executable_name (and optional prefetch_hash), return ALL "
            "firmware images in the active project (or globally, with "
            "scope='global') that contain a matching Windows Prefetch "
            "record. Identity key is the natural tuple "
            "(executable_name, prefetch_hash). The prefetch_hash bakes "
            "in the EXE path at execution time — including it "
            "distinguishes 'same exe from same path' from 'LotL "
            "relocation'. Returns one entry per matching firmware with "
            "match_count, sample_record, max_run_count, and "
            "supply_chain_signal=True when match_count >= 2 firmwares."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "executable_name": {
                    "type": "string",
                    "description": (
                        "Required. Uppercase executable name as stored "
                        "on disk in the prefetch (.pf) filename (e.g. "
                        "'CMD.EXE', 'POWERSHELL.EXE')."
                    ),
                },
                "prefetch_hash": {
                    "type": "string",
                    "description": (
                        "Optional. Exact prefetch hash (path-fingerprint "
                        "hex string). Omit to match every prefetch row "
                        "with the given executable_name regardless of "
                        "path."
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
            "required": ["executable_name"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_prefetch_record_across_firmwares,
    )
