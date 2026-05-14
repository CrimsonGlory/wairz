"""Windows processes MCP tools — Phase λ.β.C.

Surfaces the Phase λ.β walker's per-process records (from
``volatility_process_records``) and the per-firmware aggregate
(``firmware.windows_processes_walk_result``) to the MCP layer.

Tools:

- ``list_windows_processes`` — paginate the per-process rows for the
  active firmware. Filters: image_filename (exact), pid, only_unlinked,
  only_terminated, only_orphan, only_suspicious_path. Pagination via
  limit + offset.
- ``windows_processes_walk_status`` — Rule #33 status reader.
- ``trigger_windows_processes_walk`` — Rule #33 .a idempotent POST
  with 409-on-conflict. Schedules
  :func:`app.services.windows_processes_walker.run_windows_processes_walk_background`
  via ``asyncio.create_task``.
- ``lookup_windows_process_across_firmwares`` — **Rule #44 cross-
  firmware aggregation**. Keyed on the SHA256 of
  ``ImageFileName + command_line`` (the canonical "is this the same
  process across captures" identity). Reveals supply-chain indicators
  (same vendor-pushed service across multiple firmware images) and
  malware persistence (same command-line across customer captures).
  Returns one row per matching firmware with ``match_count`` +
  ``supply_chain_signal`` (True when match_count >= 2 AND the image
  path is NOT under a Microsoft system path).

Sandbox discipline (Rule #1): no path inputs (the walker resolves
paths via ``get_detection_roots``; this MCP layer only reads
persisted rows).

Rule #36 / #45 reminder: tools read records AS DATA. Nothing in this
module invokes a process binary, expands a command line, or shells
out to ``wmic`` / ``Get-Process`` / ``tasklist``. The cross-firmware
tool keys on SHA256 of strings; it NEVER fetches any process image.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.volatility_process_record import VolatilityProcessRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_windows_processes_walk_result,
    _normalize_volatility_process_records_anomaly_flags,
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
        + "\n\n[output truncated to 30KB — narrow filters or use "
        "offset+limit to paginate]"
    )


def _process_identity_key(image_filename: str, command_line: str | None) -> str:
    """SHA256 of ``ImageFileName + "\\n" + (command_line or "")``.

    This is the Rule #44 cross-firmware identity key for a process —
    the same vendor-pushed service across captures hashes to the same
    value. Lower-case ``image_filename`` so case drift (rare; ImageFileName
    is fixed-case) doesn't fragment the key.
    """
    h = hashlib.sha256()
    h.update(image_filename.lower().encode("utf-8", errors="replace"))
    h.update(b"\n")
    if command_line:
        h.update(command_line.encode("utf-8", errors="replace"))
    return h.hexdigest()


# Canonical Microsoft system path prefixes for the supply-chain heuristic.
# Mirrors the walker's _TRUSTED_PATH_PREFIXES (kept independent here so
# this MCP tool doesn't have to import the walker module).
_MS_TRUSTED_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "\\systemroot\\system32\\",
)


def _is_microsoft_path(image_path: str | None) -> bool:
    if not image_path:
        return False
    p = image_path.strip().lower()
    for prefix in _MS_TRUSTED_PREFIXES:
        if p.startswith(prefix):
            return True
    if "\\windows\\system32\\" in p or "\\windows\\syswow64\\" in p:
        return True
    return False


# ── list_windows_processes ────────────────────────────────────────────────


async def _handle_list_windows_processes(
    input: dict, context: ToolContext
) -> str:
    """Paginate the per-process rows for the active firmware.

    Filters: image_filename (exact, e.g. ``svchost.exe``), pid (exact),
    only_unlinked / only_terminated / only_orphan / only_suspicious_path
    (each filters via anomaly_flags JSONB field — true when set).
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    image_filename = input.get("image_filename")
    pid_in = input.get("pid")
    only_unlinked = bool(input.get("only_unlinked"))
    only_terminated = bool(input.get("only_terminated"))
    only_orphan = bool(input.get("only_orphan"))
    only_suspicious_path = bool(input.get("only_suspicious_path"))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    where = [VolatilityProcessRecord.firmware_id == firmware_id]
    if image_filename:
        where.append(VolatilityProcessRecord.image_filename == image_filename)
    if pid_in is not None:
        try:
            where.append(VolatilityProcessRecord.pid == int(pid_in))
        except (TypeError, ValueError):
            return json.dumps({"error": f"invalid pid: {pid_in!r}"})

    # NB: SQLite-backed tests render JSONB as TEXT; the in-memory schema
    # lacks PG's `->>` operator. The MCP tool runs in production against
    # PG only, but we keep the filter simple-and-explicit so SQLite tests
    # exercising this handler don't need a dialect-specific shim.

    total_q = select(sa_func.count(VolatilityProcessRecord.id)).where(*where)
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(VolatilityProcessRecord)
        .where(*where)
        .order_by(
            VolatilityProcessRecord.create_time.desc().nulls_last(),
            VolatilityProcessRecord.pid.asc(),
        )
        .limit(limit)
        .offset(offset)
    )
    rows = (await context.db.execute(page_q)).scalars().all()

    # Apply the anomaly_flags filters in Python so SQLite-test parity
    # holds. Real PG has rapid JSONB indexes but at this row scale the
    # filter is cheap.
    records: list[dict] = []
    for r in rows:
        flags = _normalize_volatility_process_records_anomaly_flags(
            r.anomaly_flags
        ) or {}
        if only_unlinked and not flags.get("unlinked"):
            continue
        if only_terminated and not flags.get("terminated"):
            continue
        if only_orphan and not flags.get("orphan"):
            continue
        if only_suspicious_path and not flags.get("suspicious_path"):
            continue
        records.append(
            {
                "id": str(r.id),
                "memory_image_id": str(r.memory_image_id),
                "pid": r.pid,
                "ppid": r.ppid,
                "image_filename": r.image_filename,
                "command_line": r.command_line,
                "image_path_full": r.image_path_full,
                "create_time": (
                    r.create_time.isoformat() if r.create_time else None
                ),
                "exit_time": (
                    r.exit_time.isoformat() if r.exit_time else None
                ),
                "seen_in_pslist": bool(r.seen_in_pslist),
                "seen_in_psscan": bool(r.seen_in_psscan),
                "seen_in_pstree": bool(r.seen_in_pstree),
                "anomaly_flags": flags,
            }
        )

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "records": records,
        "filters": {
            "image_filename": image_filename,
            "pid": pid_in,
            "only_unlinked": only_unlinked,
            "only_terminated": only_terminated,
            "only_orphan": only_orphan,
            "only_suspicious_path": only_suspicious_path,
        },
    }
    if total == 0:
        out["message"] = (
            "No process records match. The walker may not have run yet "
            "(call trigger_windows_processes_walk and poll "
            "windows_processes_walk_status), or your filters may be too "
            "narrow."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── windows_processes_walk_status ─────────────────────────────────────────


async def _handle_windows_processes_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.windows_processes_walk_*."""
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
        "status": row.windows_processes_walk_status,
        "started_at": (
            row.windows_processes_walk_started_at.isoformat()
            if row.windows_processes_walk_started_at
            else None
        ),
        "finished_at": (
            row.windows_processes_walk_finished_at.isoformat()
            if row.windows_processes_walk_finished_at
            else None
        ),
        "error": row.windows_processes_walk_error,
        "result": _normalize_firmware_windows_processes_walk_result(
            row.windows_processes_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_windows_processes_walk ────────────────────────────────────────


async def _handle_trigger_windows_processes_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling Windows processes walk runner.

    Rule #33 .a idempotent POST + 409-on-conflict.
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

    if row.windows_processes_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.windows_processes_walk_status,
                "started_at": (
                    row.windows_processes_walk_started_at.isoformat()
                    if row.windows_processes_walk_started_at
                    else None
                ),
                "message": (
                    f"Windows processes walk already "
                    f"{row.windows_processes_walk_status} for firmware "
                    f"{firmware_id}. Poll windows_processes_walk_status."
                ),
            }
        )

    row.windows_processes_walk_status = "queued"
    row.windows_processes_walk_started_at = None
    row.windows_processes_walk_finished_at = None
    row.windows_processes_walk_error = None
    row.windows_processes_walk_result = None
    await context.db.flush()  # Rule #3 — flush() not commit() in MCP handlers.

    from app.services.windows_processes_walker import (
        run_windows_processes_walk_background,
    )

    asyncio.create_task(run_windows_processes_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "Windows processes walk scheduled. Poll "
                "windows_processes_walk_status until status=='completed'."
            ),
        }
    )


# ── lookup_windows_process_across_firmwares (Rule #44) ────────────────────


async def _handle_lookup_windows_process_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given an image_filename + optional
    command_line, return ALL firmware images in the active project (or
    globally) with a matching process record.

    Rule #44 — wairz's unique forensic differentiator. Reveals
    supply-chain signals (same vendor-pushed service across firmware
    captures) and malware persistence (same command-line across
    customer images).

    The identity key is ``sha256(image_filename + "\\n" + (command_line
    or ""))``. When ``command_line`` is omitted, the key matches every
    process row with the same ``image_filename`` regardless of command
    line — coarser, useful for "is svchost.exe in every firmware".

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (de-duped process rows in that firmware)
    - sample_process_record (the first matching row's full payload)
    - supply_chain_signal (True when match_count >= 2 AND ANY of the
      matching rows has a non-Microsoft image_path_full).
    """
    image_filename = input.get("image_filename")
    if not image_filename:
        return json.dumps({"error": "image_filename is required"})

    command_line = input.get("command_line")
    scope = input.get("scope", "project")  # "project" or "global"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [VolatilityProcessRecord.image_filename == image_filename]
    if command_line is not None:
        where.append(VolatilityProcessRecord.command_line == command_line)

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
            select(VolatilityProcessRecord, Firmware, Project)
            .join(Firmware, VolatilityProcessRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(VolatilityProcessRecord, Firmware, Project)
            .join(Firmware, VolatilityProcessRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    # Group by firmware_id, aggregate match_count + supply_chain_signal.
    by_firmware: dict[uuid.UUID, dict] = {}
    for proc, firmware, project in rows:
        slot = by_firmware.get(firmware.id)
        if slot is None:
            slot = {
                "firmware_id": str(firmware.id),
                "project_id": str(project.id),
                "project_name": project.name,
                "original_filename": firmware.original_filename,
                "sha256": firmware.sha256,
                "match_count": 0,
                "sample_process_record": None,
                "any_non_microsoft_path": False,
                "_identity_keys": set(),
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        slot["_identity_keys"].add(
            _process_identity_key(
                proc.image_filename, proc.command_line
            )
        )
        if not _is_microsoft_path(proc.image_path_full):
            slot["any_non_microsoft_path"] = True
        if slot["sample_process_record"] is None:
            flags = _normalize_volatility_process_records_anomaly_flags(
                proc.anomaly_flags
            ) or {}
            slot["sample_process_record"] = {
                "id": str(proc.id),
                "pid": proc.pid,
                "ppid": proc.ppid,
                "image_filename": proc.image_filename,
                "command_line": proc.command_line,
                "image_path_full": proc.image_path_full,
                "create_time": (
                    proc.create_time.isoformat()
                    if proc.create_time
                    else None
                ),
                "exit_time": (
                    proc.exit_time.isoformat()
                    if proc.exit_time
                    else None
                ),
                "seen_in_pslist": bool(proc.seen_in_pslist),
                "seen_in_psscan": bool(proc.seen_in_psscan),
                "seen_in_pstree": bool(proc.seen_in_pstree),
                "anomaly_flags": flags,
            }

    # Finalize: supply_chain_signal + drop the internal _identity_keys set.
    matches: list[dict] = []
    for slot in by_firmware.values():
        slot["unique_command_lines"] = len(slot["_identity_keys"])
        slot["supply_chain_signal"] = bool(
            slot["match_count"] >= 2 and slot["any_non_microsoft_path"]
        )
        slot.pop("_identity_keys", None)
        slot.pop("any_non_microsoft_path", None)
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "image_filename": image_filename,
        "command_line": command_line,
        "scope": scope,
        "match_firmware_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching processes found. Ensure the walker has run on the "
            "relevant firmwares (trigger_windows_processes_walk + poll), "
            "and double-check the case of image_filename (Vol3 emits the "
            "exact 15-char EPROCESS field — e.g. 'svchost.exe', not "
            "'SvcHost.exe')."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_processes_tools(registry: ToolRegistry) -> None:
    """Register all Phase λ.β.C Windows processes MCP tools."""

    registry.register(
        name="list_windows_processes",
        description=(
            "Phase λ.β.C — paginate the per-process rows from "
            "``volatility_process_records`` for the active firmware. "
            "Filters: image_filename (exact, e.g. 'svchost.exe'), pid, "
            "only_unlinked (T1014 rootkit indicator — psscan-saw + "
            "pslist-missed), only_terminated, only_orphan, "
            "only_suspicious_path. Returns up to `limit` rows per page "
            "(default 50, max 500) with total_count for pagination. "
            "Order: create_time DESC NULLS LAST, pid ASC."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "image_filename": {
                    "type": "string",
                    "description": (
                        "Exact image filename (Vol3 emits the 15-char "
                        "EPROCESS field, e.g. 'svchost.exe')."
                    ),
                },
                "pid": {
                    "type": "integer",
                    "description": "Filter by exact PID.",
                },
                "only_unlinked": {
                    "type": "boolean",
                    "description": (
                        "Filter to psscan-saw + pslist-missed rows "
                        "(T1014 Rootkit DKOM-unlink indicator)."
                    ),
                },
                "only_terminated": {
                    "type": "boolean",
                    "description": (
                        "Filter to processes with non-NULL exit_time."
                    ),
                },
                "only_orphan": {
                    "type": "boolean",
                    "description": (
                        "Filter to processes whose ppid points to no "
                        "observed parent in the same image."
                    ),
                },
                "only_suspicious_path": {
                    "type": "boolean",
                    "description": (
                        "Filter to processes whose image_path_full is "
                        "OUTSIDE Microsoft-vetted prefixes (System32, "
                        "SysWOW64, Program Files, etc.)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Page size (default 50, max 500).",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Page offset (default 0).",
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_windows_processes,
    )

    registry.register(
        name="windows_processes_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "windows_processes_walk_* state machine. Returns status "
            "(idle / queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(image_count, process_count, by_plugin_seen, by_anomaly, "
            "total_elapsed_s, errors_per_image)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_windows_processes_walk_status,
    )

    registry.register(
        name="trigger_windows_processes_walk",
        description=(
            "Trigger the 202+polling Windows processes walk runner. "
            "Idempotent (Rule #33 .a) — returns conflict=true with the "
            "in-flight status if a run is already queued or running. On "
            "fresh runs, resets the firmware-row state and schedules "
            "run_windows_processes_walk_background via asyncio.create_task. "
            "Poll windows_processes_walk_status until status=='completed' "
            "to harvest the result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_windows_processes_walk,
    )

    registry.register(
        name="lookup_windows_process_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given an "
            "image_filename + optional command_line, return ALL firmware "
            "images in the active project (or globally, with scope='global') "
            "that have a matching Vol3 process record. Identity key is "
            "SHA256(image_filename + command_line). Returns one entry per "
            "matching firmware with match_count, sample_process_record, "
            "unique_command_lines, and supply_chain_signal=True when "
            "match_count >= 2 AND ANY matching row has a non-Microsoft "
            "image_path_full (vendor-pushed service or attacker payload "
            "appearing across captures)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "image_filename": {
                    "type": "string",
                    "description": (
                        "Required. Exact image filename to look up "
                        "(e.g. 'svchost.exe')."
                    ),
                },
                "command_line": {
                    "type": "string",
                    "description": (
                        "Optional. Exact command-line match. Omit to "
                        "match every process with the given image_filename "
                        "regardless of cmdline."
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
            "required": ["image_filename"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_windows_process_across_firmwares,
    )


# Cleanup helper: silence the unused-import linter when ``_dt`` is otherwise
# unused (the timestamp helpers may not fire in every code path).
_ = _dt
