"""Linux systemd journald MCP tools — Phase ι.A.E + κ.A backfill.

Surfaces the Phase ι.A.C journald walk results to the MCP layer:

- ``list_journald_entries`` — paginate the linux_journald_entries
  table for the active firmware with filters (unit, priority,
  transport, anomaly_only).
- ``lookup_journald_entry`` — fetch one journald entry row by ID
  with full detail (cmdline, full message, anomaly_flags).
- ``search_journald_messages`` — full-text substring search across
  the message body.
- ``journald_walk_status`` — Rule #33 status reader for the firmware-
  row journald_walk_* state machine.
- ``trigger_journald_walk`` — trigger the 202+polling journald walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``lookup_journald_entry_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (κ.A backfill — closes the ι.A.E gap; ι.B/C/D/E
  shipped their cross-firmware tool in the .E commits, journald
  deferred). Given a message substring (+ optional unit / transport
  / priority filters), return all firmware images that have matching
  journald entries. Adversary lens — T1070.002 (Clear Linux/Mac
  System Logs) and T1543.002 (Systemd Service) markers recurring
  across firmware captures surface supply-chain or threat-actor
  cohort indicators.

FIRST LINUX MCP tool category in wairz's portfolio (Phases η + θ
shipped 16 MCP tools across 6 Windows categories; this is the first
non-Windows one). κ.A matures Rule #44 cross-firmware-aggregation to
Rule-of-Five (systemd / ETL / EFS / container / journald).

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
from app.models.linux_journald_entry import LinuxJournaldEntry
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_journald_walk_result,
    _normalize_linux_journald_entries_anomaly_flags,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (excludes priority_critical, which is the
# LOW baseline and would over-saturate the anomaly_only filter).
_SUBSTANTIVE_ANOMALY_BITS = (
    "oom_killer",
    "audit_failure",
    "selinux_denied",
    "segfault",
    "suspicious_unit",
    "log_clear_marker",
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


def _row_has_substantive_anomaly(record: LinuxJournaldEntry) -> bool:
    """Return True iff at least one of the 6 substantive anomaly bits
    is True (excludes priority_critical, which is the LOW baseline
    review-candidate signal — including it would over-saturate the
    anomaly_only filter on healthy systems with critical kernel
    boot messages)."""
    flags = _normalize_linux_journald_entries_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: LinuxJournaldEntry) -> dict:
    """Construct the per-row summary dict surfaced by list /
    search / lookup tools."""
    return {
        "id": str(record.id),
        "journal_file_path": record.journal_file_path,
        "machine_id": record.machine_id,
        "boot_id": record.boot_id,
        "realtime_timestamp_us": record.realtime_timestamp_us,
        "monotonic_timestamp_us": record.monotonic_timestamp_us,
        "priority": record.priority,
        "facility": record.facility,
        "transport": record.transport,
        "unit": record.unit,
        "pid": record.pid,
        "uid": record.uid,
        "gid": record.gid,
        "comm": record.comm,
        "exe_path": record.exe_path,
        "cmdline": record.cmdline,
        "hostname": record.hostname,
        "message": record.message,
        "anomaly_flags": _normalize_linux_journald_entries_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
    }


# ── list_journald_entries ────────────────────────────────────────────────────


async def _handle_list_journald_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate linux_journald_entries by unit / priority_at_most /
    transport / anomaly_only filters.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    unit_filter = input.get("unit")
    priority_at_most = input.get("priority_at_most")
    transport_filter = input.get("transport")
    anomaly_only = bool(input.get("anomaly_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [LinuxJournaldEntry.firmware_id == firmware_id]
    if unit_filter:
        base_where.append(
            LinuxJournaldEntry.unit.like(f"%{unit_filter}%")
        )
    if priority_at_most is not None:
        try:
            base_where.append(
                LinuxJournaldEntry.priority <= int(priority_at_most)
            )
        except (TypeError, ValueError):
            pass
    if transport_filter:
        base_where.append(LinuxJournaldEntry.transport == transport_filter)

    if anomaly_only:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(LinuxJournaldEntry)
            .where(*base_where)
            .order_by(LinuxJournaldEntry.realtime_timestamp_us)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        filtered = [r for r in rows if _row_has_substantive_anomaly(r)]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(LinuxJournaldEntry.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(LinuxJournaldEntry)
            .where(*base_where)
            .order_by(LinuxJournaldEntry.realtime_timestamp_us)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    entries = [_row_summary(r) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "journald_entries": entries,
        "filters": {
            "unit": unit_filter,
            "priority_at_most": priority_at_most,
            "transport": transport_filter,
            "anomaly_only": anomaly_only,
        },
    }
    if total == 0:
        out["message"] = (
            "No journald entries match. The walker may not have run "
            "yet (call trigger_journald_walk and poll "
            "journald_walk_status), or your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_journald_entry ────────────────────────────────────────────────────


async def _handle_lookup_journald_entry(
    input: dict, context: ToolContext
) -> str:
    """Fetch one journald entry by ID with full detail."""
    entry_id_raw = input.get("entry_id")
    if not entry_id_raw:
        return json.dumps({"error": "entry_id is required"})
    try:
        entry_id = uuid.UUID(str(entry_id_raw))
    except (TypeError, ValueError):
        return json.dumps(
            {"error": f"entry_id {entry_id_raw!r} is not a valid UUID"}
        )

    row = (
        await context.db.execute(
            select(LinuxJournaldEntry).where(
                LinuxJournaldEntry.id == entry_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"journald entry {entry_id} not found"})

    return _truncate(json.dumps(_row_summary(row), indent=2))


# ── search_journald_messages ─────────────────────────────────────────────────


async def _handle_search_journald_messages(
    input: dict, context: ToolContext
) -> str:
    """Substring search across the journald MESSAGE body."""
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

    where_clauses = [
        LinuxJournaldEntry.firmware_id == firmware_id,
        LinuxJournaldEntry.message.ilike(f"%{query}%"),
    ]

    total_q = select(sa_func.count(LinuxJournaldEntry.id)).where(
        *where_clauses
    )
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(LinuxJournaldEntry)
        .where(*where_clauses)
        .order_by(LinuxJournaldEntry.realtime_timestamp_us)
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


# ── journald_walk_status ─────────────────────────────────────────────────────


async def _handle_journald_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.journald_walk_* state
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
        "status": row.journald_walk_status,
        "started_at": (
            row.journald_walk_started_at.isoformat()
            if row.journald_walk_started_at
            else None
        ),
        "finished_at": (
            row.journald_walk_finished_at.isoformat()
            if row.journald_walk_finished_at
            else None
        ),
        "error": row.journald_walk_error,
        "result": _normalize_firmware_journald_walk_result(
            row.journald_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_journald_walk ────────────────────────────────────────────────────


async def _handle_trigger_journald_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling journald walk background runner.
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

    if row.journald_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.journald_walk_status,
                "started_at": (
                    row.journald_walk_started_at.isoformat()
                    if row.journald_walk_started_at
                    else None
                ),
                "message": (
                    f"journald walk already {row.journald_walk_status} "
                    f"for firmware {firmware_id}. Poll "
                    "journald_walk_status."
                ),
            }
        )

    row.journald_walk_status = "queued"
    row.journald_walk_started_at = None
    row.journald_walk_finished_at = None
    row.journald_walk_error = None
    row.journald_walk_result = None
    await context.db.flush()

    from app.services.journald_walker import run_journald_walk_background

    asyncio.create_task(run_journald_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "journald walk scheduled. Poll journald_walk_status "
                "until status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_journald_entry_across_firmwares (CROSS-FIRMWARE AGG) ──────────────


async def _handle_lookup_journald_entry_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a message substring
    (+ optional unit / transport / priority_at_most filters), return
    ALL firmware images in the active project (or globally, if
    requested) that have matching journald entries.

    κ.A backfill — closes the ι.A.E gap (journald shipped the
    per-firmware MCP tools but deferred the cross-firmware
    aggregation that ι.B/C/D/E added at their .E commits). Brings
    Rule #44 cross-firmware-aggregation to Rule-of-Five (systemd /
    ETL / EFS / container / journald).

    Adversary lens: T1070.002 (Clear Linux/Mac System Logs) — same
    journalctl-vacuum marker phrase across firmware corpus is a
    strong supply-chain or threat-actor cohort indicator.
    T1543.002 (Systemd Service) — same suspicious-unit message
    across firmwares hints at vendor-pushed unit OR shared infection.
    T1562.001 (SELinux denial) / T1562.012 (audit-system failure) —
    same denial/failure phrase across firmwares may indicate
    common-control-bypass tooling.

    Returns one row per matching firmware (deduplicated by
    firmware_id), with project + firmware metadata + sample entry
    detail + per-firmware match count. Anomaly-flag agreement across
    matches is a strong adversary-signal indicator.
    """
    query = input.get("query")
    if not query:
        return json.dumps(
            {"error": "query (message substring) is required"}
        )

    unit_filter = input.get("unit")
    transport_filter = input.get("transport")
    priority_at_most = input.get("priority_at_most")
    anomaly_only = bool(input.get("anomaly_only", False))

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where_clauses = [LinuxJournaldEntry.message.ilike(f"%{query}%")]
    if unit_filter:
        where_clauses.append(
            LinuxJournaldEntry.unit.like(f"%{unit_filter}%")
        )
    if transport_filter:
        where_clauses.append(
            LinuxJournaldEntry.transport == transport_filter
        )
    if priority_at_most is not None:
        try:
            where_clauses.append(
                LinuxJournaldEntry.priority <= int(priority_at_most)
            )
        except (TypeError, ValueError):
            pass

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
            select(LinuxJournaldEntry, Firmware, Project)
            .join(Firmware, LinuxJournaldEntry.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(LinuxJournaldEntry, Firmware, Project)
            .join(Firmware, LinuxJournaldEntry.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    # Group matches by firmware_id (dedupe — the same message phrase
    # may appear in many entries per firmware, and we want a
    # one-row-per-firmware summary).
    per_firmware: dict[uuid.UUID, dict] = {}

    for entry, firmware, project in rows:
        if anomaly_only and not _row_has_substantive_anomaly(entry):
            continue
        bucket = per_firmware.setdefault(
            firmware.id,
            {
                "project_id": str(project.id),
                "project_name": project.name,
                "firmware_id": str(firmware.id),
                "firmware_sha256": firmware.sha256,
                "firmware_original_filename": firmware.original_filename,
                "firmware_version_label": firmware.version_label,
                "match_count": 0,
                "sample_entry": {
                    "entry_id": str(entry.id),
                    "journal_file_path": entry.journal_file_path,
                    "realtime_timestamp_us": entry.realtime_timestamp_us,
                    "priority": entry.priority,
                    "transport": entry.transport,
                    "unit": entry.unit,
                    "comm": entry.comm,
                    "exe_path": entry.exe_path,
                    "hostname": entry.hostname,
                    "message": entry.message,
                    "anomaly_flags": (
                        _normalize_linux_journald_entries_anomaly_flags(
                            entry.anomaly_flags
                        )
                    ),
                    "has_anomaly": _row_has_substantive_anomaly(entry),
                },
            },
        )
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]

    out: dict = {
        "query": query,
        "unit": unit_filter,
        "transport": transport_filter,
        "priority_at_most": priority_at_most,
        "anomaly_only": anomaly_only,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a journald entry "
            f"matching query {query!r}. Run the walker against more "
            "firmwares (call trigger_journald_walk on each), then "
            "re-query — or widen the filters."
        )
    elif len(matches) >= 2:
        out["supply_chain_signal"] = (
            f"Message substring {query!r} present in "
            f"{len(matches)} firmware images — possible "
            "vendor-pushed log marker (legitimate) OR shared "
            "infection / common-tooling indicator. Compare unit + "
            "transport + anomaly_flags across matches to "
            "distinguish. Anomaly-flag agreement across matches is "
            "a strong adversary-signal indicator (e.g. "
            "log_clear_marker recurring across firmwares = "
            "T1070.002 cohort)."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ─────────────────────────────────────────────────────────────


def register_linux_journald_tools(registry: ToolRegistry) -> None:
    """Register all Phase ι.A.E Linux journald MCP tools (+ κ.A
    cross-firmware backfill). FIRST LINUX MCP tool category in wairz.

    κ.A adds ``lookup_journald_entry_across_firmwares`` — the
    cross-firmware aggregation tool that ι.A.E originally deferred
    while ι.B/C/D/E shipped their cross-firmware variant in the .E
    commits. Matures Rule #44 cross-firmware-aggregation pattern to
    Rule-of-Five.
    """

    registry.register(
        name="list_journald_entries",
        description=(
            "Phase ι.A.E — paginate the per-entry "
            "linux_journald_entries table for the active firmware. "
            "Surfaces parsed entries from Linux systemd .journal "
            "binary log files extracted from firmware captures. "
            "FIRST LINUX MCP tool in wairz's portfolio. "
            "Filters: "
            "unit (substring match on _SYSTEMD_UNIT — e.g. 'ssh' or "
            "'systemd-journald'), "
            "priority_at_most (filter to entries with priority <= N "
            "where 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, "
            "5=notice, 6=info, 7=debug), "
            "transport (exact match on _TRANSPORT — typically "
            "'kernel', 'journal', 'audit', 'stdout', 'syslog', "
            "'driver'), "
            "anomaly_only (filter to entries with at least one "
            "substantive anomaly bit raised: oom_killer / "
            "audit_failure / selinux_denied / segfault / "
            "suspicious_unit / log_clear_marker — EXCLUDES "
            "priority_critical baseline to avoid over-saturation on "
            "healthy systems with normal kernel boot messages). "
            "Returns up to `limit` rows per page (default 50, max "
            "500) ordered by realtime_timestamp_us ascending. Reads "
            "the ι.A.A landing zone populated by ι.A.C's walker. "
            "Indexes (firmware_id, realtime_timestamp_us) + "
            "(firmware_id, unit) + (firmware_id, priority) + "
            "(firmware_id, transport) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "unit": {
                    "type": "string",
                    "description": (
                        "Substring match on _SYSTEMD_UNIT (e.g. "
                        "'ssh' or 'systemd-')."
                    ),
                },
                "priority_at_most": {
                    "type": "integer",
                    "description": (
                        "Filter to entries with syslog priority <= N "
                        "(0=emerg, 7=debug)."
                    ),
                    "minimum": 0,
                    "maximum": 7,
                },
                "transport": {
                    "type": "string",
                    "description": (
                        "Exact match on _TRANSPORT ('kernel' / "
                        "'journal' / 'audit' / 'stdout' / 'syslog' / "
                        "'driver')."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least "
                        "one substantive anomaly flag raised "
                        "(oom_killer / audit_failure / "
                        "selinux_denied / segfault / suspicious_unit "
                        "/ log_clear_marker)."
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
        handler=_handle_list_journald_entries,
    )

    registry.register(
        name="lookup_journald_entry",
        description=(
            "Phase ι.A.E — fetch one journald entry by its UUID with "
            "full detail (message body, cmdline, hostname, anomaly "
            "flags). Use the entry_id returned by list_journald_entries "
            "or search_journald_messages."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "entry_id": {
                    "type": "string",
                    "description": (
                        "UUID of the LinuxJournaldEntry row. Get from "
                        "list_journald_entries or "
                        "search_journald_messages."
                    ),
                },
            },
            "required": ["entry_id"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_journald_entry,
    )

    registry.register(
        name="search_journald_messages",
        description=(
            "Phase ι.A.E — case-insensitive substring search across "
            "the journald MESSAGE body for the active firmware. Use "
            "this to find audit-related entries ('audit:'), kernel "
            "anomalies ('segfault'), failed services ('Failed to "
            "start'), or operator-specific keywords (process names, "
            "IP addresses, etc). Returns up to `limit` matching rows "
            "per page (default 50, max 500) ordered by "
            "realtime_timestamp_us ascending."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring to search for in the journald "
                        "MESSAGE body (case-insensitive)."
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
        handler=_handle_search_journald_messages,
    )

    registry.register(
        name="journald_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "journald_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(files_scanned, entries_walked, entries_persisted, "
            "priority_critical_count, oom_killer_count, "
            "audit_failure_count, selinux_denied_count, "
            "suspicious_unit_count, log_clear_marker_count, "
            "anomaly_total, oversize_skipped, compressed_skipped, "
            "errors, per_file)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_journald_walk_status,
    )

    registry.register(
        name="trigger_journald_walk",
        description=(
            "Trigger the 202+polling Linux journald walk background "
            "runner. Walks for files matching *.journal under each "
            "detection root (typically "
            "var/log/journal/<machine-id>/system.journal and "
            "run/log/journal/<machine-id>/*.journal under Linux "
            "firmware rootfs extracts), parses each via a clean-room "
            "pure-Python parser implementing the upstream "
            "systemd/sd-journal binary format, iterates every entry "
            "object, persists per-entry rows into "
            "linux_journald_entries (priority, transport, unit, "
            "pid/uid/gid/comm/exe/cmdline, hostname, message, "
            "anomaly_flags), and stamps an aggregate JSONB result "
            "onto journald_walk_result. Idempotent (Rule #33 .a) — "
            "returns conflict=true with the in-flight status if a "
            "run is already queued or running. Schedules "
            "run_journald_walk_background via asyncio.create_task. "
            "Poll journald_walk_status until status=='completed' to "
            "harvest the result. Anomaly classifier covers Persona-E "
            "Linux TTPs: T1543.002 (systemd-unit-from-writable — "
            "suspicious_unit), T1070.002 (journalctl vacuum/rotate "
            "residue — log_clear_marker), T1562.001 (SELinux AVC "
            "denials — selinux_denied), T1562.012 (audit-system "
            "failures — audit_failure), T1499 collateral (oom_killer "
            "/ segfault). FIRST LINUX walker in wairz's portfolio."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_journald_walk,
    )

    registry.register(
        name="lookup_journald_entry_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION** — given a message "
            "substring (+ optional unit / transport / "
            "priority_at_most / anomaly_only filters), return ALL "
            "firmware images in the active project (default) OR "
            "globally that have a journald entry matching the "
            "filters. κ.A backfill closes the ι.A.E gap (journald "
            "deferred this; ι.B systemd / ι.C ETL / ι.D EFS / ι.E "
            "container all shipped their cross-firmware tool at .E). "
            "Matures Rule #44 cross-firmware-aggregation to "
            "Rule-of-Five. Wairz competitive differentiator — "
            "surfaces supply-chain signal: the same log marker "
            "phrase recurring across multiple firmware images is "
            "either a vendor-pushed log line (legitimate baseline) "
            "OR a shared-tooling / shared-infection indicator. "
            "Adversary lens: T1070.002 (Clear Linux/Mac System Logs) "
            "— same journalctl-vacuum marker across firmwares is a "
            "strong cohort indicator. T1543.002 (Systemd Service) — "
            "same suspicious-unit message hints at vendor-pushed unit "
            "OR shared infection. T1562.001 / T1562.012 — same "
            "SELinux-denial / audit-failure phrase indicates "
            "common control-bypass tooling. Anomaly-flag agreement "
            "across matches is a strong adversary-signal indicator. "
            "The match_count >=2 case is flagged with "
            "supply_chain_signal in the output. scope='project' "
            "(default) restricts to the active project's firmwares; "
            "scope='global' searches every project in the database."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring to match against "
                        "the journald MESSAGE body. E.g. "
                        "'journalctl --vacuum' to find log-clear "
                        "markers across the corpus, or 'avc: denied' "
                        "to surface SELinux denials."
                    ),
                },
                "unit": {
                    "type": "string",
                    "description": (
                        "Optional substring match on _SYSTEMD_UNIT "
                        "(e.g. 'ssh' or 'cron') to scope to a "
                        "particular service across firmwares."
                    ),
                },
                "transport": {
                    "type": "string",
                    "description": (
                        "Optional exact match on _TRANSPORT "
                        "('kernel' / 'journal' / 'audit' / 'stdout' / "
                        "'syslog' / 'driver')."
                    ),
                },
                "priority_at_most": {
                    "type": "integer",
                    "description": (
                        "Optional filter to entries with syslog "
                        "priority <= N (0=emerg, 7=debug). Use "
                        "priority_at_most=2 to scope to crit-and-"
                        "above across the corpus."
                    ),
                    "minimum": 0,
                    "maximum": 7,
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, only count entries with at least "
                        "one substantive anomaly flag raised "
                        "(oom_killer / audit_failure / "
                        "selinux_denied / segfault / "
                        "suspicious_unit / log_clear_marker)."
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
                        "Max per-firmware buckets to return (default "
                        "100, min 1, max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_journald_entry_across_firmwares,
    )
