"""Windows Scheduled Task MCP tools — Phase η.B.E.

Surfaces the Phase η.B.C Scheduled Task XML walk results to the MCP layer:

- ``search_scheduled_tasks`` — paginate the windows_scheduled_tasks
  table for the active firmware by author / run_level / task_name
  prefix / encoded-PowerShell filter.
- ``scheduled_task_walk_status`` — Rule #33 status reader for the
  firmware-row scheduled_task_walk_* state machine.
- ``trigger_scheduled_task_walk`` — trigger the 202+polling
  Scheduled Task walk background runner (Rule #33 .a idempotent POST
  + 409-on-conflict).

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.windows_scheduled_task import WindowsScheduledTask
from app.services.jsonb_normalizers import (
    _normalize_firmware_scheduled_task_walk_result,
    _normalize_windows_scheduled_tasks_actions,
    _normalize_windows_scheduled_tasks_principal,
    _normalize_windows_scheduled_tasks_settings,
    _normalize_windows_scheduled_tasks_triggers,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Canonical run_level values surfaced by the η.B.C walker.
_VALID_RUN_LEVELS = frozenset({"LeastPrivilege", "HighestAvailable"})


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


def _row_has_encoded_ps_action(actions: list[dict]) -> bool:
    """Return True iff any action's command + arguments concatenated
    contains a known encoded-PowerShell pattern. Mirrors the walker's
    is_action_encoded_powershell heuristic without the regex import
    cost (we use lowercase substring checks here for the search-time
    filter)."""
    needles = (
        "-encodedcommand",
        "-enc ",
        "-enc\t",
        "frombase64string",
        "invoke-expression",
        "[char[]]",
        "downloadstring(",
        " iex ",
    )
    for act in actions or []:
        if not isinstance(act, dict):
            continue
        blob = " ".join(
            filter(None, (act.get("command"), act.get("arguments")))
        ).lower()
        if any(n in blob for n in needles):
            return True
    return False


# ── search_scheduled_tasks ──────────────────────────────────────────────────


async def _handle_search_scheduled_tasks(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_scheduled_tasks by author / run_level /
    task_name prefix / encoded-PowerShell filter.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    author = input.get("author")
    run_level = input.get("run_level")
    task_name_prefix = input.get("task_name_prefix")
    encoded_powershell_only = bool(input.get("encoded_powershell_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if run_level and run_level not in _VALID_RUN_LEVELS:
        return json.dumps(
            {
                "error": (
                    f"invalid run_level {run_level!r} — must be one of: "
                    f"{sorted(_VALID_RUN_LEVELS)}"
                )
            }
        )

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsScheduledTask.firmware_id == firmware_id]
    if author:
        base_where.append(WindowsScheduledTask.author == author)
    if run_level:
        base_where.append(WindowsScheduledTask.run_level == run_level)
    if task_name_prefix:
        base_where.append(
            WindowsScheduledTask.task_name.like(f"{task_name_prefix}%")
        )

    # Note: encoded_powershell_only requires an in-Python filter on the
    # JSONB actions column. We DON'T predicate this via SQL — JSONB
    # path filtering across regex-shaped keywords is not portable AND
    # the caller can also use a tighter author/run_level pre-filter.
    # Fetch the candidates, filter, then re-paginate.
    if encoded_powershell_only:
        # Pull matching rows fully (no offset/limit yet) and post-filter.
        page_q = (
            select(WindowsScheduledTask)
            .where(*base_where)
            .order_by(
                WindowsScheduledTask.registration_date.desc().nulls_last()
            )
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        filtered = [
            r
            for r in rows
            if _row_has_encoded_ps_action(
                _normalize_windows_scheduled_tasks_actions(r.actions)
            )
        ]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsScheduledTask.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsScheduledTask)
            .where(*base_where)
            .order_by(
                WindowsScheduledTask.registration_date.desc().nulls_last()
            )
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    records = [
        {
            "id": str(r.id),
            "task_name": r.task_name,
            "task_uri": r.task_uri,
            "source_path": r.source_path,
            "author": r.author,
            "registration_date": (
                r.registration_date.isoformat()
                if r.registration_date
                else None
            ),
            "run_level": r.run_level,
            "run_as_user": r.run_as_user,
            "triggers": _normalize_windows_scheduled_tasks_triggers(
                r.triggers
            ),
            "actions": _normalize_windows_scheduled_tasks_actions(
                r.actions
            ),
            "principal": _normalize_windows_scheduled_tasks_principal(
                r.principal
            ),
            "settings": _normalize_windows_scheduled_tasks_settings(
                r.settings
            ),
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "tasks": records,
        "filters": {
            "author": author,
            "run_level": run_level,
            "task_name_prefix": task_name_prefix,
            "encoded_powershell_only": encoded_powershell_only,
        },
    }
    if total == 0:
        out["message"] = (
            "No Scheduled Tasks match. The walker may not have run yet "
            "(call trigger_scheduled_task_walk and poll "
            "scheduled_task_walk_status), or your filters may be too "
            "narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── scheduled_task_walk_status ──────────────────────────────────────────────


async def _handle_scheduled_task_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.scheduled_task_walk_* state
    machine."""
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
        "status": row.scheduled_task_walk_status,
        "started_at": (
            row.scheduled_task_walk_started_at.isoformat()
            if row.scheduled_task_walk_started_at
            else None
        ),
        "finished_at": (
            row.scheduled_task_walk_finished_at.isoformat()
            if row.scheduled_task_walk_finished_at
            else None
        ),
        "error": row.scheduled_task_walk_error,
        "result": _normalize_firmware_scheduled_task_walk_result(
            row.scheduled_task_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_scheduled_task_walk ─────────────────────────────────────────────


async def _handle_trigger_scheduled_task_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling Scheduled Task XML walk background runner.
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

    if row.scheduled_task_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.scheduled_task_walk_status,
                "started_at": (
                    row.scheduled_task_walk_started_at.isoformat()
                    if row.scheduled_task_walk_started_at
                    else None
                ),
                "message": (
                    f"Scheduled Task walk already "
                    f"{row.scheduled_task_walk_status} for firmware "
                    f"{firmware_id}. Poll scheduled_task_walk_status."
                ),
            }
        )

    row.scheduled_task_walk_status = "queued"
    row.scheduled_task_walk_started_at = None
    row.scheduled_task_walk_finished_at = None
    row.scheduled_task_walk_error = None
    row.scheduled_task_walk_result = None
    await context.db.flush()

    from app.services.scheduled_task_walker import (
        run_scheduled_task_walk_background,
    )

    asyncio.create_task(run_scheduled_task_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "Scheduled Task walk scheduled. Poll "
                "scheduled_task_walk_status until status=='completed' "
                "to harvest the result."
            ),
        }
    )


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_scheduled_task_tools(registry: ToolRegistry) -> None:
    """Register all Phase η.B.E Windows Scheduled Task MCP tools."""

    registry.register(
        name="search_scheduled_tasks",
        description=(
            "Phase η.B.E — paginate the per-task windows_scheduled_tasks "
            "table for the active firmware by author (exact match — "
            "typically 'Microsoft Corporation' or '\\\\HOSTNAME\\user'), "
            "run_level (one of: LeastPrivilege, HighestAvailable), "
            "task_name_prefix (case-sensitive prefix match — e.g. "
            "'Win' for WinSAT), and encoded_powershell_only (filters to "
            "tasks whose Action contains -EncodedCommand / -enc / "
            "FromBase64String / Invoke-Expression / [char[]] / "
            "DownloadString / IEX patterns — Qakbot signature). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "with total_count for navigation. Reads the η.B.A landing "
            "zone populated by η.B.C's walker. Order: registration_date "
            "DESC (forensic-timeline UX). Indexes (firmware_id, "
            "registration_date) + (firmware_id, author) + (firmware_id, "
            "task_uri) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "author": {
                    "type": "string",
                    "description": (
                        "Exact author match (typically 'Microsoft "
                        "Corporation' or '\\\\HOSTNAME\\user')."
                    ),
                },
                "run_level": {
                    "type": "string",
                    "enum": ["LeastPrivilege", "HighestAvailable"],
                    "description": (
                        "Filter by privilege level — "
                        "HighestAvailable is the privilege-escalation "
                        "marker."
                    ),
                },
                "task_name_prefix": {
                    "type": "string",
                    "description": (
                        "Case-sensitive prefix match on task_name "
                        "(e.g. 'Win' for WinSAT)."
                    ),
                },
                "encoded_powershell_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only tasks whose Action "
                        "contains an encoded-PowerShell pattern "
                        "(Qakbot signature)."
                    ),
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
        handler=_handle_search_scheduled_tasks,
    )

    registry.register(
        name="scheduled_task_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "scheduled_task_walk_* state machine. Returns status "
            "(idle / queued / running / completed / failed), "
            "started_at, finished_at, error, and the last-known-result "
            "aggregate (task_count, by_status, unique_authors, "
            "highest_available_count, encoded_powershell_count, errors, "
            "per_file)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_scheduled_task_walk_status,
    )

    registry.register(
        name="trigger_scheduled_task_walk",
        description=(
            "Trigger the 202+polling Scheduled Task XML walk background "
            "runner. Idempotent (Rule #33 .a) — returns conflict=true "
            "with the in-flight status if a run is already queued or "
            "running. Schedules run_scheduled_task_walk_background via "
            "asyncio.create_task. Poll scheduled_task_walk_status until "
            "status=='completed' to harvest the result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_scheduled_task_walk,
    )
