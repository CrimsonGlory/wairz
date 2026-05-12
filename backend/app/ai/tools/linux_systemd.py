"""Linux systemd unit-file MCP tools — Phase ι.B.E (SECOND LINUX MCP).

Surfaces the Phase ι.B.C systemd unit-file walk results to the MCP
layer:

- ``list_systemd_units`` — paginate the linux_systemd_units table
  for the active firmware with filters (unit_type, enabled,
  anomaly_only).
- ``lookup_systemd_unit`` — fetch one unit row by ID with full
  detail (exec_start, working_directory, wanted_by, anomaly_flags).
- ``search_systemd_units`` — substring search across unit_name /
  description / exec_start.
- ``trigger_systemd_walk`` — trigger the 202+polling systemd walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``systemd_walk_status`` — Rule #33 status reader for the firmware-
  row systemd_walk_* state machine.
- ``lookup_systemd_unit_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (wairz competitive differentiator). Given a
  unit_name + optional exec_start substring, return all firmware
  images that have a matching unit. Supply-chain indicator —
  identifies the same vendor-pushed unit across multiple firmware
  captures.

SECOND LINUX MCP tool category in wairz's portfolio. The cross-
firmware aggregation tool is FIRST-of-kind for any Linux walker
(ι.A deferred it).

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
from app.models.linux_systemd_units import LinuxSystemdUnit
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_systemd_walk_result,
    _normalize_linux_systemd_units_after,
    _normalize_linux_systemd_units_anomaly_flags,
    _normalize_linux_systemd_units_before,
    _normalize_linux_systemd_units_required_by,
    _normalize_linux_systemd_units_requires,
    _normalize_linux_systemd_units_socket_listen,
    _normalize_linux_systemd_units_triggers,
    _normalize_linux_systemd_units_wanted_by,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (excludes disabled_but_present which is
# the LOW baseline review-candidate signal — including it would
# over-saturate the anomaly_only filter on healthy systems).
_SUBSTANTIVE_ANOMALY_BITS = (
    "suspicious_path",
    "suspicious_unit_name",
    "socket_unusual_port",
    "root_minimal_deps",
    "enabled_outside_standard",
    "obfuscated_exec",
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


def _row_has_substantive_anomaly(record: LinuxSystemdUnit) -> bool:
    """True iff at least one of the 6 substantive anomaly bits is True
    (excludes disabled_but_present which is the LOW baseline)."""
    flags = _normalize_linux_systemd_units_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: LinuxSystemdUnit) -> dict:
    """Construct the per-row summary dict surfaced by list / search /
    lookup tools."""
    return {
        "id": str(record.id),
        "unit_path": record.unit_path,
        "unit_type": record.unit_type,
        "unit_name": record.unit_name,
        "description": record.description,
        "exec_start": record.exec_start,
        "exec_start_pre": record.exec_start_pre,
        "exec_stop": record.exec_stop,
        "user": record.user,
        "working_directory": record.working_directory,
        "wanted_by": _normalize_linux_systemd_units_wanted_by(
            record.wanted_by
        ),
        "required_by": _normalize_linux_systemd_units_required_by(
            record.required_by
        ),
        "requires": _normalize_linux_systemd_units_requires(
            record.requires
        ),
        "after": _normalize_linux_systemd_units_after(record.after),
        "before": _normalize_linux_systemd_units_before(record.before),
        "enabled": bool(record.enabled),
        "triggers": _normalize_linux_systemd_units_triggers(
            record.triggers
        ),
        "socket_listen": _normalize_linux_systemd_units_socket_listen(
            record.socket_listen
        ),
        "anomaly_flags": _normalize_linux_systemd_units_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
    }


def _row_detail(record: LinuxSystemdUnit) -> dict:
    """Like _row_summary but also includes unit_raw (full INI text)."""
    out = _row_summary(record)
    out["unit_raw"] = record.unit_raw
    return out


# ── list_systemd_units ───────────────────────────────────────────────────────


async def _handle_list_systemd_units(
    input: dict, context: ToolContext
) -> str:
    """Paginate linux_systemd_units by unit_type / enabled /
    anomaly_only filters.

    Returns up to ``limit`` rows per page (default 50, max 500).
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    unit_type_filter = input.get("unit_type")
    enabled_filter = input.get("enabled")
    anomaly_only = bool(input.get("anomaly_only", False))
    anomaly_bit = input.get("anomaly_bit")  # optional specific bit
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [LinuxSystemdUnit.firmware_id == firmware_id]
    if unit_type_filter:
        base_where.append(LinuxSystemdUnit.unit_type == unit_type_filter)
    if enabled_filter is not None:
        base_where.append(LinuxSystemdUnit.enabled == bool(enabled_filter))

    if anomaly_only or anomaly_bit:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(LinuxSystemdUnit)
            .where(*base_where)
            .order_by(LinuxSystemdUnit.unit_name)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_linux_systemd_units_anomaly_flags(
                        r.anomaly_flags
                    ).get(anomaly_bit)
                )
            ]
        elif anomaly_only:
            filtered = [
                r for r in rows if _row_has_substantive_anomaly(r)
            ]
        else:
            filtered = list(rows)
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(LinuxSystemdUnit.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(LinuxSystemdUnit)
            .where(*base_where)
            .order_by(LinuxSystemdUnit.unit_name)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    units = [_row_summary(r) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "systemd_units": units,
        "filters": {
            "unit_type": unit_type_filter,
            "enabled": enabled_filter,
            "anomaly_only": anomaly_only,
            "anomaly_bit": anomaly_bit,
        },
    }
    if total == 0:
        out["message"] = (
            "No systemd units match. The walker may not have run yet "
            "(call trigger_systemd_walk and poll systemd_walk_status), "
            "or your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_systemd_unit ──────────────────────────────────────────────────────


async def _handle_lookup_systemd_unit(
    input: dict, context: ToolContext
) -> str:
    """Fetch one systemd unit by ID with full detail (incl. unit_raw)."""
    unit_id_raw = input.get("unit_id")
    if not unit_id_raw:
        return json.dumps({"error": "unit_id is required"})
    try:
        unit_id = uuid.UUID(str(unit_id_raw))
    except (TypeError, ValueError):
        return json.dumps(
            {"error": f"unit_id {unit_id_raw!r} is not a valid UUID"}
        )

    row = (
        await context.db.execute(
            select(LinuxSystemdUnit).where(LinuxSystemdUnit.id == unit_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"systemd unit {unit_id} not found"})

    return _truncate(json.dumps(_row_detail(row), indent=2))


# ── search_systemd_units ─────────────────────────────────────────────────────


async def _handle_search_systemd_units(
    input: dict, context: ToolContext
) -> str:
    """Substring search across unit_name / description / exec_start."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    query = input.get("query")
    if not query:
        return json.dumps({"error": "query (substring) is required"})

    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    pattern = f"%{query}%"
    where_clauses = [
        LinuxSystemdUnit.firmware_id == firmware_id,
        (
            LinuxSystemdUnit.unit_name.ilike(pattern)
            | LinuxSystemdUnit.description.ilike(pattern)
            | LinuxSystemdUnit.exec_start.ilike(pattern)
        ),
    ]

    total_q = select(sa_func.count(LinuxSystemdUnit.id)).where(
        *where_clauses
    )
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(LinuxSystemdUnit)
        .where(*where_clauses)
        .order_by(LinuxSystemdUnit.unit_name)
        .limit(limit)
        .offset(offset)
    )
    rows = (await context.db.execute(page_q)).scalars().all()

    out = {
        "firmware_id": str(firmware_id),
        "query": query,
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "matches": [_row_summary(r) for r in rows],
    }
    return _truncate(json.dumps(out, indent=2))


# ── systemd_walk_status ──────────────────────────────────────────────────────


async def _handle_systemd_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.systemd_walk_* state
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
        "status": row.systemd_walk_status,
        "started_at": (
            row.systemd_walk_started_at.isoformat()
            if row.systemd_walk_started_at
            else None
        ),
        "finished_at": (
            row.systemd_walk_finished_at.isoformat()
            if row.systemd_walk_finished_at
            else None
        ),
        "error": row.systemd_walk_error,
        "result": _normalize_firmware_systemd_walk_result(
            row.systemd_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_systemd_walk ─────────────────────────────────────────────────────


async def _handle_trigger_systemd_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling systemd walk background runner.
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

    if row.systemd_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.systemd_walk_status,
                "started_at": (
                    row.systemd_walk_started_at.isoformat()
                    if row.systemd_walk_started_at
                    else None
                ),
                "message": (
                    f"systemd walk already {row.systemd_walk_status} "
                    f"for firmware {firmware_id}. Poll "
                    "systemd_walk_status."
                ),
            }
        )

    row.systemd_walk_status = "queued"
    row.systemd_walk_started_at = None
    row.systemd_walk_finished_at = None
    row.systemd_walk_error = None
    row.systemd_walk_result = None
    await context.db.flush()

    from app.services.systemd_walker import run_systemd_walk_background

    asyncio.create_task(run_systemd_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "systemd walk scheduled. Poll systemd_walk_status "
                "until status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_systemd_unit_across_firmwares (CROSS-FIRMWARE AGG) ─────────────────


async def _handle_lookup_systemd_unit_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a unit_name + optional
    exec_start substring, return ALL firmware images in the active
    project (or globally, if requested) that have a matching unit.

    First-of-kind for any Linux walker (ι.A deferred this). The
    wairz competitive differentiator — supply-chain indicator
    identifying the same vendor-pushed unit across firmware captures.

    Returns one row per matching unit, with project + firmware
    metadata + the unit's own anomaly_flags. Up to ``limit`` rows.
    """
    unit_name = input.get("unit_name")
    if not unit_name:
        return json.dumps({"error": "unit_name is required"})

    exec_substring = input.get("exec_substring")
    scope = input.get("scope", "project")  # "project" or "global"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where_clauses = [
        LinuxSystemdUnit.unit_name == unit_name,
    ]
    if exec_substring:
        where_clauses.append(
            LinuxSystemdUnit.exec_start.ilike(f"%{exec_substring}%")
        )

    if scope == "project":
        # Restrict to firmwares within the active project.
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(LinuxSystemdUnit, Firmware, Project)
            .join(Firmware, LinuxSystemdUnit.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )
    else:
        # Global scope — no project restriction.
        stmt = (
            select(LinuxSystemdUnit, Firmware, Project)
            .join(Firmware, LinuxSystemdUnit.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    for unit, firmware, project in rows:
        flags = _normalize_linux_systemd_units_anomaly_flags(
            unit.anomaly_flags
        )
        matches.append({
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "unit_id": str(unit.id),
            "unit_path": unit.unit_path,
            "unit_type": unit.unit_type,
            "unit_name": unit.unit_name,
            "exec_start": unit.exec_start,
            "user": unit.user,
            "enabled": bool(unit.enabled),
            "anomaly_flags": flags,
            "has_anomaly": _row_has_substantive_anomaly(unit),
        })

    out = {
        "unit_name": unit_name,
        "exec_substring": exec_substring,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a systemd unit named "
            f"{unit_name!r}. Run the walker against more firmwares "
            "(call trigger_systemd_walk on each), then re-query."
        )
    elif len(matches) >= 2:
        out["supply_chain_signal"] = (
            f"Unit '{unit_name}' present in {len(matches)} firmware "
            "images — possible vendor-pushed unit OR shared infection. "
            "Compare exec_start + user + anomaly_flags across matches "
            "to distinguish."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ─────────────────────────────────────────────────────────────


def register_linux_systemd_tools(registry: ToolRegistry) -> None:
    """Register all Phase ι.B.E Linux systemd MCP tools. SECOND LINUX
    MCP tool category in wairz (ι.A.E shipped journald). Brings MCP
    tool count 257 → 263.

    Includes the FIRST-of-kind cross-firmware aggregation tool for any
    Linux walker (``lookup_systemd_unit_across_firmwares``) — wairz
    competitive differentiator surfacing supply-chain signal across
    firmware captures.
    """

    registry.register(
        name="list_systemd_units",
        description=(
            "Phase ι.B.E — paginate the per-unit linux_systemd_units "
            "table for the active firmware. Surfaces parsed systemd "
            "unit files (.service / .timer / .socket / .target / .path "
            "/ .mount / .swap) extracted from Linux firmware captures. "
            "SECOND LINUX MCP tool category in wairz (ι.A.E shipped "
            "journald). Filters: "
            "unit_type (exact match — service / timer / socket / "
            "target / etc), "
            "enabled (filter to units with at least one enabled-symlink "
            "in *.wants/ or *.requires/ directories — the canonical "
            "'this unit starts on boot' signal), "
            "anomaly_only (filter to units with at least one substantive "
            "anomaly bit raised: suspicious_path / suspicious_unit_name "
            "/ socket_unusual_port / root_minimal_deps / "
            "enabled_outside_standard / obfuscated_exec — EXCLUDES "
            "disabled_but_present which is LOW baseline), "
            "anomaly_bit (specific bit name to filter on — e.g. "
            "'suspicious_path' or 'obfuscated_exec'). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "ordered by unit_name. Reads the ι.B.A landing zone "
            "populated by ι.B.C's walker. Indexes (firmware_id, "
            "unit_type) + (firmware_id, unit_name) + (firmware_id, "
            "enabled) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "unit_type": {
                    "type": "string",
                    "description": (
                        "Exact match on unit_type (service / timer / "
                        "socket / target / path / mount / swap / etc)."
                    ),
                },
                "enabled": {
                    "type": "boolean",
                    "description": (
                        "Filter to units that are boot-time-active "
                        "(at least one enabled-symlink found)."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only units with at least one "
                        "substantive anomaly flag raised."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to units with this specific anomaly "
                        "bit set (suspicious_path / "
                        "suspicious_unit_name / socket_unusual_port / "
                        "root_minimal_deps / disabled_but_present / "
                        "enabled_outside_standard / obfuscated_exec)."
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
                    "description": (
                        "Page offset for pagination (default 0)."
                    ),
                    "minimum": 0,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_systemd_units,
    )

    registry.register(
        name="lookup_systemd_unit",
        description=(
            "Phase ι.B.E — fetch one systemd unit by its UUID with "
            "full detail (incl. full unit_raw INI text). Use the "
            "unit_id returned by list_systemd_units or "
            "search_systemd_units."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "unit_id": {
                    "type": "string",
                    "description": (
                        "UUID of the LinuxSystemdUnit row. Get from "
                        "list_systemd_units or search_systemd_units."
                    ),
                },
            },
            "required": ["unit_id"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_systemd_unit,
    )

    registry.register(
        name="search_systemd_units",
        description=(
            "Phase ι.B.E — case-insensitive substring search across "
            "unit_name / description / exec_start for the active "
            "firmware. Use this to find units by partial name "
            "('ssh' / 'cron'), description keyword, or ExecStart "
            "path/binary. Returns up to `limit` matching rows per "
            "page (default 50, max 500) ordered by unit_name."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring to search for in unit_name / "
                        "description / exec_start (case-insensitive)."
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
                    "description": "Page offset (default 0).",
                    "minimum": 0,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_search_systemd_units,
    )

    registry.register(
        name="systemd_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "systemd_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(units_scanned, units_persisted, service_count, "
            "timer_count, socket_count, target_count, other_count, "
            "enabled_count, suspicious_path_count, "
            "suspicious_unit_name_count, socket_unusual_port_count, "
            "root_minimal_deps_count, disabled_but_present_count, "
            "enabled_outside_standard_count, obfuscated_exec_count, "
            "anomaly_total, errors, per_root)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_systemd_walk_status,
    )

    registry.register(
        name="trigger_systemd_walk",
        description=(
            "Trigger the 202+polling Linux systemd unit-file walk "
            "background runner. Walks every detection root (etc/"
            "systemd/system/ + usr/lib/systemd/system/ + lib/systemd/"
            "system/ + run/systemd/system/ + etc/systemd/user/ per "
            "Rule #16), parses every .service / .timer / .socket / "
            ".target / .path / .mount / .swap file via Python's "
            "stdlib configparser (NO new dependency — INI text), "
            "merges drop-in overrides (<unit>.<type>.d/*.conf), "
            "detects enabled-symlinks (*.wants/ and *.requires/ "
            "directories), iterates every unit, persists per-unit "
            "rows into linux_systemd_units (Description, ExecStart, "
            "ExecStartPre, ExecStop, User, WorkingDirectory, "
            "WantedBy, RequiredBy, Requires, After, Before, enabled, "
            "Timer triggers, Socket listen ports, anomaly_flags, "
            "full INI text). Idempotent (Rule #33 .a) — returns "
            "conflict=true if a run is already queued or running. "
            "Schedules run_systemd_walk_background via "
            "asyncio.create_task. Poll systemd_walk_status until "
            "status=='completed' to harvest the result. Anomaly "
            "classifier covers Persona-E Linux TTPs: T1543.002 "
            "(suspicious_path: systemd-service-from-writable — APT36 "
            "/ FIRESTARTER / Quasar QLNX), T1027 (obfuscated_exec: "
            "base64/eval/curl|sh patterns), T1571 (socket_unusual_"
            "port: non-standard port binding), rootkit shape "
            "(root_minimal_deps), custom-target staging "
            "(enabled_outside_standard). SECOND LINUX walker in "
            "wairz's portfolio."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_systemd_walk,
    )

    registry.register(
        name="lookup_systemd_unit_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION** — given a unit_name (+ "
            "optional exec_start substring), return ALL firmware "
            "images in the active project (default) OR globally that "
            "have a systemd unit matching the name + exec_start "
            "substring. FIRST-of-kind cross-firmware aggregation MCP "
            "tool for any Linux walker in wairz's portfolio (ι.A "
            "journald deferred this). Wairz competitive "
            "differentiator — surfaces supply-chain signal: a unit "
            "present across multiple firmware images is likely "
            "vendor-pushed (legitimate) OR an in-the-wild infection "
            "across the same vendor's product line. Compare "
            "exec_start + user + anomaly_flags across matches to "
            "distinguish. Anomaly-flag agreement across matches is "
            "a strong adversary-signal indicator. The match_count "
            ">=2 case is flagged with supply_chain_signal in the "
            "output. scope='project' (default) restricts to the "
            "active project's firmwares; scope='global' searches "
            "every project in the database."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "unit_name": {
                    "type": "string",
                    "description": (
                        "Unit basename (no extension) to match "
                        "exactly. E.g. 'sshd' to find sshd.service "
                        "across firmwares."
                    ),
                },
                "exec_substring": {
                    "type": "string",
                    "description": (
                        "Optional substring to further filter on "
                        "ExecStart= (case-insensitive). E.g. "
                        "'/tmp/' to only match suspicious-path "
                        "matches across firmwares."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "'project' (default) restricts to the active "
                        "project's firmwares; 'global' searches every "
                        "project."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Max matches to return (default 100, min 1, "
                        "max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["unit_name"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_systemd_unit_across_firmwares,
    )
