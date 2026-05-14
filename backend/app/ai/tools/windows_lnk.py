"""Windows Shell Link (.lnk) MCP tools — Phase η.C.E.

Surfaces the Phase η.C.C LNK walk results to the MCP layer:

- ``search_lnk_records`` — paginate the windows_lnk_records table
  for the active firmware by lnk_filename prefix / target_path
  prefix / non-Microsoft target / encoded-PowerShell argument
  filter / script-host target filter.
- ``lnk_walk_status`` — Rule #33 status reader for the firmware-row
  lnk_walk_* state machine.
- ``trigger_lnk_walk`` — trigger the 202+polling LNK walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).

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
from app.models.project import Project
from app.models.windows_lnk_record import WindowsLnkRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_lnk_walk_result,
    _normalize_windows_lnk_records_target_metadata,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024


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


def _row_arguments_have_encoded_ps(arguments: str | None) -> bool:
    """Return True iff arguments contain a known encoded-PowerShell
    pattern. Mirrors the walker's is_arguments_encoded_powershell
    heuristic without the regex import cost (we use lowercase
    substring checks here for the search-time filter)."""
    if not arguments:
        return False
    needles = (
        "-encodedcommand",
        "-enc ",
        "-enc\t",
        "frombase64string",
        "invoke-expression",
        "[char[]]",
        "downloadstring(",
        " iex ",
        " iex\t",
    )
    blob = arguments.lower()
    return any(n in blob for n in needles)


def _row_target_is_microsoft(target_path: str | None) -> bool:
    """Mirror walker's is_microsoft_target heuristic for the search
    filter. Case-insensitive prefix match against canonical Microsoft
    target locations."""
    if not target_path:
        return False
    lower = target_path.lower().replace("/", "\\")
    prefixes = (
        "c:\\windows\\",
        "%windir%\\",
        "%systemroot%\\",
        "c:\\program files\\windows ",
        "c:\\program files (x86)\\windows ",
        "c:\\program files\\common files\\microsoft ",
        "c:\\program files (x86)\\common files\\microsoft ",
        "c:\\program files\\microsoft ",
        "c:\\program files (x86)\\microsoft ",
        "c:\\programdata\\microsoft\\",
    )
    return any(lower.startswith(p) for p in prefixes)


_SCRIPT_HOST_BASENAMES = frozenset({
    "cmd.exe", "cscript.exe", "wscript.exe", "powershell.exe",
    "pwsh.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
})


def _row_target_is_script_host(target_path: str | None) -> bool:
    """Mirror walker's is_script_host_target heuristic for the
    search filter."""
    if not target_path:
        return False
    base = target_path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return base in _SCRIPT_HOST_BASENAMES


# ── search_lnk_records ──────────────────────────────────────────────────────


async def _handle_search_lnk_records(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_lnk_records by lnk_filename prefix /
    target_path prefix / non-Microsoft target / encoded-PowerShell
    argument filter / script-host target filter.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    lnk_filename_prefix = input.get("lnk_filename_prefix")
    target_path_prefix = input.get("target_path_prefix")
    non_microsoft_only = bool(input.get("non_microsoft_only", False))
    encoded_powershell_only = bool(
        input.get("encoded_powershell_only", False)
    )
    script_host_only = bool(input.get("script_host_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsLnkRecord.firmware_id == firmware_id]
    if lnk_filename_prefix:
        base_where.append(
            WindowsLnkRecord.lnk_filename.like(f"{lnk_filename_prefix}%")
        )
    if target_path_prefix:
        base_where.append(
            WindowsLnkRecord.target_path.like(f"{target_path_prefix}%")
        )

    needs_python_filter = (
        non_microsoft_only or encoded_powershell_only or script_host_only
    )

    if needs_python_filter:
        # Pull matching rows fully (no offset/limit yet) and post-filter
        # the heuristic checks in Python. SQL-side LIKE-prefix filters
        # already narrowed the candidate set.
        page_q = (
            select(WindowsLnkRecord)
            .where(*base_where)
            .order_by(
                WindowsLnkRecord.modified_time.desc().nulls_last()
            )
        )
        rows = (await context.db.execute(page_q)).scalars().all()

        def _matches(r: WindowsLnkRecord) -> bool:
            if non_microsoft_only:
                # Non-Microsoft target — must have a target_path AND
                # NOT match Microsoft prefixes.
                if r.target_path is None:
                    return False
                if _row_target_is_microsoft(r.target_path):
                    return False
            if encoded_powershell_only and not _row_arguments_have_encoded_ps(
                r.arguments
            ):
                return False
            if script_host_only and not _row_target_is_script_host(
                r.target_path
            ):
                return False
            return True

        filtered = [r for r in rows if _matches(r)]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsLnkRecord.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsLnkRecord)
            .where(*base_where)
            .order_by(
                WindowsLnkRecord.modified_time.desc().nulls_last()
            )
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    records = [
        {
            "id": str(r.id),
            "lnk_filename": r.lnk_filename,
            "source_path": r.source_path,
            "target_path": r.target_path,
            "working_directory": r.working_directory,
            "arguments": r.arguments,
            "description": r.description,
            "icon_location": r.icon_location,
            "show_command": r.show_command,
            "hotkey": r.hotkey,
            "creation_time": (
                r.creation_time.isoformat() if r.creation_time else None
            ),
            "accessed_time": (
                r.accessed_time.isoformat() if r.accessed_time else None
            ),
            "modified_time": (
                r.modified_time.isoformat() if r.modified_time else None
            ),
            "target_metadata": _normalize_windows_lnk_records_target_metadata(
                r.target_metadata
            ),
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "lnk_records": records,
        "filters": {
            "lnk_filename_prefix": lnk_filename_prefix,
            "target_path_prefix": target_path_prefix,
            "non_microsoft_only": non_microsoft_only,
            "encoded_powershell_only": encoded_powershell_only,
            "script_host_only": script_host_only,
        },
    }
    if total == 0:
        out["message"] = (
            "No LNK records match. The walker may not have run yet "
            "(call trigger_lnk_walk and poll lnk_walk_status), or "
            "your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lnk_walk_status ─────────────────────────────────────────────────────────


async def _handle_lnk_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.lnk_walk_* state machine."""
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
        "status": row.lnk_walk_status,
        "started_at": (
            row.lnk_walk_started_at.isoformat()
            if row.lnk_walk_started_at
            else None
        ),
        "finished_at": (
            row.lnk_walk_finished_at.isoformat()
            if row.lnk_walk_finished_at
            else None
        ),
        "error": row.lnk_walk_error,
        "result": _normalize_firmware_lnk_walk_result(
            row.lnk_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_lnk_walk ────────────────────────────────────────────────────────


async def _handle_trigger_lnk_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling LNK walk background runner.
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

    if row.lnk_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.lnk_walk_status,
                "started_at": (
                    row.lnk_walk_started_at.isoformat()
                    if row.lnk_walk_started_at
                    else None
                ),
                "message": (
                    f"LNK walk already {row.lnk_walk_status} for "
                    f"firmware {firmware_id}. Poll lnk_walk_status."
                ),
            }
        )

    row.lnk_walk_status = "queued"
    row.lnk_walk_started_at = None
    row.lnk_walk_finished_at = None
    row.lnk_walk_error = None
    row.lnk_walk_result = None
    await context.db.flush()

    from app.services.lnk_walker import run_lnk_walk_background

    asyncio.create_task(run_lnk_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "LNK walk scheduled. Poll lnk_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_lnk_record_across_firmwares (Rule #44) ───────────────────────────


async def _handle_lookup_lnk_record_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a target_path (and optional
    exact arguments), return ALL firmware images in the active project
    (or globally) with a matching LNK record.

    Rule #44 — same shortcut launching the same target across multiple
    customer captures indicates a campaign / persistence mechanism that
    survived imaging. Identity key is the natural tuple
    (target_path, arguments). Omitting arguments matches every LNK
    launching the given target.

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (total LNK rows matching the filter)
    - sample_record (first matching LNK's summary)
    - any_encoded_powershell / any_script_host flags across matches
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    target_path = input.get("target_path")
    if not target_path:
        return json.dumps({"error": "target_path is required"})

    arguments = input.get("arguments")
    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [WindowsLnkRecord.target_path == target_path]
    if arguments is not None:
        where.append(WindowsLnkRecord.arguments == arguments)

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
            select(WindowsLnkRecord, Firmware, Project)
            .join(Firmware, WindowsLnkRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsLnkRecord, Firmware, Project)
            .join(Firmware, WindowsLnkRecord.firmware_id == Firmware.id)
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
                "any_encoded_powershell": False,
                "any_script_host_target": False,
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        if _row_arguments_have_encoded_ps(rec.arguments):
            slot["any_encoded_powershell"] = True
        if _row_target_is_script_host(rec.target_path):
            slot["any_script_host_target"] = True
        if slot["sample_record"] is None:
            slot["sample_record"] = {
                "id": str(rec.id),
                "source_path": rec.source_path,
                "lnk_filename": rec.lnk_filename,
                "target_path": rec.target_path,
                "working_directory": rec.working_directory,
                "arguments": rec.arguments,
                "icon_location": rec.icon_location,
                "show_command": rec.show_command,
            }

    matches: list[dict] = []
    for slot in by_firmware.values():
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "target_path": target_path,
        "arguments": arguments,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching LNK records found. Ensure the walker has run "
            "on the relevant firmwares (trigger_lnk_walk + poll), and "
            "double-check target_path casing (Windows paths are "
            "case-preserving)."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_lnk_tools(registry: ToolRegistry) -> None:
    """Register all Phase η.C.E Windows Shell Link MCP tools."""

    registry.register(
        name="search_lnk_records",
        description=(
            "Phase η.C.E — paginate the per-LNK windows_lnk_records "
            "table for the active firmware by lnk_filename prefix "
            "(case-sensitive — e.g. 'Firefox' for Firefox.lnk), "
            "target_path prefix (case-sensitive — e.g. 'C:\\\\Windows\\\\' "
            "for Microsoft-targeted LNKs), non_microsoft_only (filters "
            "to LNKs whose target_path is NOT under \\\\Windows\\\\, "
            "%SystemRoot%, %windir%, C:\\\\Program Files\\\\Microsoft *, "
            "C:\\\\ProgramData\\\\Microsoft\\\\ — atypical for "
            "legitimate Start Menu / Recent docs entries), "
            "encoded_powershell_only (filters to LNKs whose arguments "
            "contain -EncodedCommand / -enc / FromBase64String / "
            "Invoke-Expression / [char[]] / DownloadString / IEX — "
            "Qakbot / cobalt-strike signature), and script_host_only "
            "(filters to LNKs whose target resolves to cmd.exe / "
            "cscript.exe / wscript.exe / powershell.exe / pwsh.exe / "
            "mshta.exe / regsvr32.exe / rundll32.exe). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "with total_count for navigation. Reads the η.C.A landing "
            "zone populated by η.C.C's walker. Order: modified_time "
            "DESC (forensic-timeline UX). Indexes (firmware_id, "
            "modified_time) + (firmware_id, target_path) + "
            "(firmware_id, lnk_filename) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "lnk_filename_prefix": {
                    "type": "string",
                    "description": (
                        "Case-sensitive prefix match on lnk_filename "
                        "(e.g. 'Firefox' for Firefox.lnk)."
                    ),
                },
                "target_path_prefix": {
                    "type": "string",
                    "description": (
                        "Case-sensitive prefix match on target_path "
                        "(e.g. 'C:\\\\Windows\\\\' for Microsoft-"
                        "targeted LNKs)."
                    ),
                },
                "non_microsoft_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only LNKs whose target_path "
                        "is NOT under known Microsoft binary "
                        "locations."
                    ),
                },
                "encoded_powershell_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only LNKs whose arguments "
                        "contain an encoded-PowerShell pattern "
                        "(Qakbot signature)."
                    ),
                },
                "script_host_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only LNKs whose target "
                        "resolves to a known script-host binary "
                        "(cmd / cscript / wscript / powershell / "
                        "pwsh / mshta / regsvr32 / rundll32)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Page size (default 50, min 1, max 500)."
                    ),
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
        handler=_handle_search_lnk_records,
    )

    registry.register(
        name="lnk_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "lnk_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(lnk_count, by_status, unique_targets, "
            "non_microsoft_target_count, encoded_powershell_count, "
            "errors, per_file)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_lnk_walk_status,
    )

    registry.register(
        name="trigger_lnk_walk",
        description=(
            "Trigger the 202+polling Windows Shell Link (.lnk) walk "
            "background runner. Idempotent (Rule #33 .a) — returns "
            "conflict=true with the in-flight status if a run is "
            "already queued or running. Schedules "
            "run_lnk_walk_background via asyncio.create_task. Poll "
            "lnk_walk_status until status=='completed' to harvest "
            "the result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_lnk_walk,
    )

    registry.register(
        name="lookup_lnk_record_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a target_path "
            "(and optional arguments), return ALL firmware images in the "
            "active project (or globally, with scope='global') that "
            "contain a matching Windows Shell Link (LNK) record. Identity "
            "key is the natural tuple (target_path, arguments). Returns "
            "one entry per matching firmware with match_count, "
            "sample_record, any_encoded_powershell / any_script_host_target "
            "flags, and supply_chain_signal=True when match_count >= 2 "
            "firmwares (campaign / persistence pattern across captures)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": (
                        "Required. Exact target path the LNK launches "
                        "(e.g. 'C:\\\\Windows\\\\System32\\\\cmd.exe', "
                        "'C:\\\\Windows\\\\System32\\\\WindowsPowerShell"
                        "\\\\v1.0\\\\powershell.exe')."
                    ),
                },
                "arguments": {
                    "type": "string",
                    "description": (
                        "Optional. Exact command-line arguments. Omit "
                        "to match every LNK launching the given target."
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
            "required": ["target_path"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_lnk_record_across_firmwares,
    )
