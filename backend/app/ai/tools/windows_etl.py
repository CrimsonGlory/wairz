"""Windows ETL trace-event MCP tools — Phase ι.C.E (FIRST ι WINDOWS MCP).

Surfaces the Phase ι.C.C ETL trace-log walk results to the MCP layer:

- ``list_etl_events`` — paginate the windows_etl_events table for the
  active firmware with filters (provider_guid, event_id, session_name,
  anomaly_only).
- ``lookup_etl_event`` — fetch one event row by ID with full detail
  (provider, event descriptor, payload, anomaly_flags).
- ``search_etl_events`` — substring search across provider_name /
  etl_session_name / payload values.
- ``trigger_etl_walk`` — trigger the 202+polling ETL walk background
  runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``etl_walk_status`` — Rule #33 status reader for the firmware-row
  etl_walk_* state machine.
- ``lookup_etl_provider_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (wairz competitive differentiator). Given a
  provider_guid (and optional event_id), return all firmware images
  that have ETL events from that provider. Supply-chain / vendor-
  fingerprint indicator. SECOND application of the cross-firmware
  aggregation pattern at walker-stream time (ι.B precedent).

FIRST ι Windows MCP tool category. The cross-firmware aggregation
tool reinforces the ι.B pattern (Rule-of-One → Rule-of-Two).

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import Text, cast, select
from sqlalchemy import func as sa_func

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.windows_etl_events import WindowsEtlEvent
from app.services.jsonb_normalizers import (
    _normalize_firmware_etl_walk_result,
    _normalize_windows_etl_events_anomaly_flags,
    _normalize_windows_etl_events_payload,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (the 4 ETL bits ALL warrant operator review;
# we include them all in the anomaly_only filter — unlike ι.A's
# priority_critical-excluded and ι.B's disabled_but_present-excluded).
_SUBSTANTIVE_ANOMALY_BITS = (
    "kernel_proc_after_evtx_clear",
    "provider_disable_evidence",
    "unusual_provider",
    "non_microsoft_in_diagtrack",
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


def _row_has_substantive_anomaly(record: WindowsEtlEvent) -> bool:
    """True iff at least one of the 4 substantive anomaly bits is True."""
    flags = _normalize_windows_etl_events_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: WindowsEtlEvent) -> dict:
    """Construct the per-row summary dict surfaced by list / search /
    lookup tools."""
    return {
        "id": str(record.id),
        "etl_file_path": record.etl_file_path,
        "etl_session_name": record.etl_session_name,
        "provider_guid": record.provider_guid,
        "provider_name": record.provider_name,
        "event_id": record.event_id,
        "event_version": record.event_version,
        "event_channel": record.event_channel,
        "event_level": record.event_level,
        "event_opcode": record.event_opcode,
        "event_keywords": record.event_keywords,
        "event_task": record.event_task,
        "timestamp_ft": record.timestamp_ft,
        "process_id": record.process_id,
        "thread_id": record.thread_id,
        "processor_id": record.processor_id,
        "kernel_time_us": record.kernel_time_us,
        "user_time_us": record.user_time_us,
        "raw_record_size": record.raw_record_size,
        "anomaly_flags": _normalize_windows_etl_events_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
    }


def _row_detail(record: WindowsEtlEvent) -> dict:
    """Like _row_summary but also includes payload."""
    out = _row_summary(record)
    out["payload"] = _normalize_windows_etl_events_payload(record.payload)
    return out


# ── list_etl_events ──────────────────────────────────────────────────────────


async def _handle_list_etl_events(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_etl_events by provider_guid / event_id /
    session_name / anomaly_only filters.

    Returns up to ``limit`` rows per page (default 50, max 500).
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    provider_guid_filter = input.get("provider_guid")
    event_id_filter = input.get("event_id")
    session_name_filter = input.get("session_name")
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

    base_where = [WindowsEtlEvent.firmware_id == firmware_id]
    if provider_guid_filter:
        base_where.append(
            WindowsEtlEvent.provider_guid == provider_guid_filter.lower()
        )
    if event_id_filter is not None:
        base_where.append(WindowsEtlEvent.event_id == int(event_id_filter))
    if session_name_filter:
        base_where.append(
            WindowsEtlEvent.etl_session_name == session_name_filter
        )

    if anomaly_only or anomaly_bit:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(WindowsEtlEvent)
            .where(*base_where)
            .order_by(WindowsEtlEvent.timestamp_ft)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_windows_etl_events_anomaly_flags(
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
        total_q = select(sa_func.count(WindowsEtlEvent.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsEtlEvent)
            .where(*base_where)
            .order_by(WindowsEtlEvent.timestamp_ft)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    events = [_row_summary(r) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "etl_events": events,
        "filters": {
            "provider_guid": provider_guid_filter,
            "event_id": event_id_filter,
            "session_name": session_name_filter,
            "anomaly_only": anomaly_only,
            "anomaly_bit": anomaly_bit,
        },
    }
    if total == 0:
        out["message"] = (
            "No ETL events match. The walker may not have run yet "
            "(call trigger_etl_walk and poll etl_walk_status), or the "
            "firmware may not contain any .etl files, or your filters "
            "may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_etl_event ─────────────────────────────────────────────────────────


async def _handle_lookup_etl_event(
    input: dict, context: ToolContext
) -> str:
    """Fetch one ETL event by ID with full detail (incl. payload)."""
    event_id_raw = input.get("event_row_id")
    if not event_id_raw:
        return json.dumps({"error": "event_row_id is required"})
    try:
        event_id = uuid.UUID(str(event_id_raw))
    except (TypeError, ValueError):
        return json.dumps(
            {"error": f"event_row_id {event_id_raw!r} is not a valid UUID"}
        )

    row = (
        await context.db.execute(
            select(WindowsEtlEvent).where(WindowsEtlEvent.id == event_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"etl event {event_id} not found"})

    return _truncate(json.dumps(_row_detail(row), indent=2, default=str))


# ── search_etl_events ────────────────────────────────────────────────────────


async def _handle_search_etl_events(
    input: dict, context: ToolContext
) -> str:
    """Substring search across provider_name / etl_session_name /
    payload values for the active firmware."""
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
    # PostgreSQL JSONB ::text cast for substring match across all
    # payload values.
    where_clauses = [
        WindowsEtlEvent.firmware_id == firmware_id,
        (
            WindowsEtlEvent.provider_name.ilike(pattern)
            | WindowsEtlEvent.etl_session_name.ilike(pattern)
            | cast(WindowsEtlEvent.payload, Text).ilike(pattern)
        ),
    ]

    total_q = select(sa_func.count(WindowsEtlEvent.id)).where(
        *where_clauses
    )
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(WindowsEtlEvent)
        .where(*where_clauses)
        .order_by(WindowsEtlEvent.timestamp_ft)
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


# ── etl_walk_status ──────────────────────────────────────────────────────────


async def _handle_etl_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.etl_walk_* state machine."""
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
        "status": row.etl_walk_status,
        "started_at": (
            row.etl_walk_started_at.isoformat()
            if row.etl_walk_started_at
            else None
        ),
        "finished_at": (
            row.etl_walk_finished_at.isoformat()
            if row.etl_walk_finished_at
            else None
        ),
        "error": row.etl_walk_error,
        "result": _normalize_firmware_etl_walk_result(row.etl_walk_result),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_etl_walk ─────────────────────────────────────────────────────────


async def _handle_trigger_etl_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling ETL walk background runner.
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

    if row.etl_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.etl_walk_status,
                "started_at": (
                    row.etl_walk_started_at.isoformat()
                    if row.etl_walk_started_at
                    else None
                ),
                "message": (
                    f"etl walk already {row.etl_walk_status} for "
                    f"firmware {firmware_id}. Poll etl_walk_status."
                ),
            }
        )

    row.etl_walk_status = "queued"
    row.etl_walk_started_at = None
    row.etl_walk_finished_at = None
    row.etl_walk_error = None
    row.etl_walk_result = None
    await context.db.flush()

    from app.services.etl_walker import run_etl_walk_background

    asyncio.create_task(run_etl_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "etl walk scheduled. Poll etl_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_etl_provider_across_firmwares (CROSS-FIRMWARE AGG) ────────────────


async def _handle_lookup_etl_provider_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a provider_guid (+ optional
    event_id), return ALL firmware images in the active project (or
    globally, if requested) that have ETL events from that provider.

    SECOND application of the cross-firmware aggregation pattern at
    walker-stream time (ι.B precedent — Rule-of-One → Rule-of-Two).
    Surfaces supply-chain / vendor-fingerprint signal: a third-party
    provider GUID present across multiple firmware images is likely
    a vendor-shipped EDR / endpoint protection driver (legitimate)
    OR an in-the-wild ETW provider planted by an adversary across
    the same vendor's product line. Compare event_id distribution +
    anomaly_flags across matches to distinguish.

    Returns one row per matching firmware (deduplicated by firmware_id),
    with project + firmware metadata + match counts + sample anomaly
    flags. Up to ``limit`` firmware rows.
    """
    provider_guid = input.get("provider_guid")
    if not provider_guid:
        return json.dumps({"error": "provider_guid is required"})
    provider_guid_norm = provider_guid.strip().lower()
    # Validate as UUID.
    try:
        uuid.UUID(provider_guid_norm)
    except (TypeError, ValueError):
        return json.dumps({
            "error": (
                f"provider_guid {provider_guid!r} is not a valid GUID "
                "(expected canonical 8-4-4-4-12 hyphenated form)"
            )
        })

    event_id_filter = input.get("event_id")
    scope = input.get("scope", "project")  # "project" or "global"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where_clauses = [
        WindowsEtlEvent.provider_guid == provider_guid_norm,
    ]
    if event_id_filter is not None:
        where_clauses.append(WindowsEtlEvent.event_id == int(event_id_filter))

    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(
                Firmware,
                Project,
                sa_func.count(WindowsEtlEvent.id).label("match_count"),
            )
            .join(
                WindowsEtlEvent, WindowsEtlEvent.firmware_id == Firmware.id
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .group_by(Firmware.id, Project.id)
            .order_by(Firmware.created_at)
            .limit(limit)
        )
    else:
        stmt = (
            select(
                Firmware,
                Project,
                sa_func.count(WindowsEtlEvent.id).label("match_count"),
            )
            .join(
                WindowsEtlEvent, WindowsEtlEvent.firmware_id == Firmware.id
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .group_by(Firmware.id, Project.id)
            .order_by(Firmware.created_at)
            .limit(limit)
        )

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    for firmware, project, match_count in rows:
        # Pull a single example row to inspect anomaly flags.
        example = (
            await context.db.execute(
                select(WindowsEtlEvent)
                .where(
                    WindowsEtlEvent.firmware_id == firmware.id,
                    WindowsEtlEvent.provider_guid == provider_guid_norm,
                )
                .order_by(WindowsEtlEvent.timestamp_ft)
                .limit(1)
            )
        ).scalar_one_or_none()
        example_flags: dict = {}
        example_session: str | None = None
        example_provider_name: str | None = None
        if example is not None:
            example_flags = _normalize_windows_etl_events_anomaly_flags(
                example.anomaly_flags
            )
            example_session = example.etl_session_name
            example_provider_name = example.provider_name
        matches.append({
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "match_count": int(match_count),
            "example_provider_name": example_provider_name,
            "example_session": example_session,
            "example_anomaly_flags": example_flags,
            "example_has_anomaly": (
                example is not None
                and _row_has_substantive_anomaly(example)
            ),
        })

    out = {
        "provider_guid": provider_guid_norm,
        "event_id": event_id_filter,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has ETL events from "
            f"provider GUID {provider_guid_norm!r}. Run the walker "
            "against more firmwares (call trigger_etl_walk on each), "
            "then re-query."
        )
    elif len(matches) >= 2:
        out["supply_chain_signal"] = (
            f"Provider GUID {provider_guid_norm!r} appears across "
            f"{len(matches)} firmware images — possible vendor-pushed "
            "EDR / endpoint-protection driver (legitimate) OR shared "
            "ETW-provider infection across the same vendor's product "
            "line. Compare example_provider_name + example_session + "
            "anomaly_flags across matches to distinguish."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_etl_tools(registry: ToolRegistry) -> None:
    """Register all Phase ι.C.E Windows ETL MCP tools. FIRST ι Windows-
    side MCP tool category in wairz (ι.A.E shipped Linux journald;
    ι.B.E shipped Linux systemd). Brings MCP tool count 263 → 269.

    Includes the SECOND application of the cross-firmware aggregation
    pattern at walker-stream time (``lookup_etl_provider_across_
    firmwares``) — wairz competitive differentiator surfacing supply-
    chain signal across firmware captures. Rule-of-One (ι.B) → Rule-
    of-Two (this stream).
    """

    registry.register(
        name="list_etl_events",
        description=(
            "Phase ι.C.E — paginate the per-event windows_etl_events "
            "table for the active firmware. Surfaces parsed Windows "
            "Event Tracing for Windows (ETW) trace records extracted "
            "from .etl binary log files (typically under Windows/"
            "System32/WDI/LogFiles/, winevt/Logs/, Windows/Logs/CBS/, "
            "WMI/) via Fox-IT dissect.etl. FIRST ι Windows MCP tool "
            "category in wairz (ι.A + ι.B shipped Linux walkers). "
            "Persona-E ETW relevance: kernel ETL often survives EVTX "
            "clear (FortiGuard 2024 IR — AutoLogger-Diagtrack-"
            "Listener.etl retained the post-clear process tree). "
            "Filters: provider_guid (exact 8-4-4-4-12 lowercase "
            "hyphenated GUID), event_id (exact int), session_name "
            "(exact match — e.g. 'AutoLogger-Diagtrack-Listener'), "
            "anomaly_only (filter to events with at least one of the 4 "
            "substantive anomaly bits: kernel_proc_after_evtx_clear / "
            "provider_disable_evidence / unusual_provider / "
            "non_microsoft_in_diagtrack), anomaly_bit (specific bit). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "ordered by timestamp_ft ASC. Reads the ι.C.A landing zone "
            "populated by ι.C.C's walker. Indexes (firmware_id, "
            "provider_guid) + (firmware_id, event_id) + (firmware_id, "
            "timestamp_ft) + (firmware_id, etl_session_name) cover the "
            "common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "provider_guid": {
                    "type": "string",
                    "description": (
                        "Exact match on provider_guid (canonical "
                        "8-4-4-4-12 lowercase hyphenated form)."
                    ),
                },
                "event_id": {
                    "type": "integer",
                    "description": (
                        "Exact match on event_id (provider-scoped "
                        "integer)."
                    ),
                },
                "session_name": {
                    "type": "string",
                    "description": (
                        "Exact match on etl_session_name (e.g. "
                        "'AutoLogger-Diagtrack-Listener', "
                        "'Eventlog-Security')."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only events with at least one "
                        "substantive anomaly flag raised."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to events with this specific anomaly "
                        "bit set (kernel_proc_after_evtx_clear / "
                        "provider_disable_evidence / unusual_provider "
                        "/ non_microsoft_in_diagtrack)."
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
        handler=_handle_list_etl_events,
    )

    registry.register(
        name="lookup_etl_event",
        description=(
            "Phase ι.C.E — fetch one ETL event row by its UUID with "
            "full detail (incl. full payload JSONB — decoded manifest "
            "key/value pairs OR raw-bytes b64 preview when no manifest "
            "match). Use the event_row_id returned by list_etl_events "
            "or search_etl_events."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "event_row_id": {
                    "type": "string",
                    "description": (
                        "UUID of the WindowsEtlEvent row. Get from "
                        "list_etl_events or search_etl_events."
                    ),
                },
            },
            "required": ["event_row_id"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_etl_event,
    )

    registry.register(
        name="search_etl_events",
        description=(
            "Phase ι.C.E — case-insensitive substring search across "
            "provider_name / etl_session_name / payload values for the "
            "active firmware. Use this to find events by partial "
            "provider name ('Diagtrack' / 'Kernel'), session name, or "
            "payload field substring (process names like 'lsass.exe', "
            "file paths, etc). Returns up to `limit` matching rows per "
            "page (default 50, max 500) ordered by timestamp_ft ASC."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring to search for in provider_name / "
                        "etl_session_name / payload (case-insensitive)."
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
        handler=_handle_search_etl_events,
    )

    registry.register(
        name="etl_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row etl_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and "
            "the last-known-result aggregate (files_scanned, "
            "events_walked, events_persisted, events_capped, "
            "oversize_skipped, kernel_proc_after_evtx_clear_count, "
            "provider_disable_evidence_count, unusual_provider_count, "
            "non_microsoft_in_diagtrack_count, anomaly_total, errors, "
            "per_file)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_etl_walk_status,
    )

    registry.register(
        name="trigger_etl_walk",
        description=(
            "Trigger the 202+polling Windows ETW .etl trace-log walk "
            "background runner. Walks every detection root for *.etl "
            "files (typically Windows/System32/WDI/LogFiles/, winevt/"
            "Logs/, Windows/Logs/CBS/, NetSetup/, WindowsBackup/, "
            "WindowsUpdate/, Windows/System32/LogFiles/WMI/, plus "
            "defensive fallback scan), parses each .etl file via Fox-IT "
            "dissect.etl (AGPL-3.0, v3.14 released 2025-11-20), iterates "
            "every EventRecord, persists per-event rows into "
            "windows_etl_events (provider_guid, provider_name, event_id, "
            "event_version, event_level, event_opcode, event_keywords, "
            "event_task, timestamp_ft (FILETIME 100ns since 1601), "
            "process_id, thread_id, payload, anomaly_flags). Idempotent "
            "(Rule #33 .a) — returns conflict=true if a run is already "
            "queued or running. Schedules run_etl_walk_background via "
            "asyncio.create_task. Poll etl_walk_status until "
            "status=='completed' to harvest the result. Anomaly "
            "classifier covers 4 Persona-E ETW TTPs: T1070.001 "
            "(kernel_proc_after_evtx_clear: kernel process events "
            "retained in ETL after Security.evtx clear — FortiGuard "
            "2024 canonical tradecraft), T1562.002 "
            "(provider_disable_evidence: logger-session-end event from "
            "session-control provider), T1574 (unusual_provider: "
            "non-Microsoft GUID; non_microsoft_in_diagtrack: third-"
            "party provider in Microsoft-only Diagtrack-Listener — "
            "strong adversary signal). FIRST ι Windows walker in "
            "wairz's portfolio."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_etl_walk,
    )

    registry.register(
        name="lookup_etl_provider_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION** — given a provider_guid "
            "(+ optional event_id), return ALL firmware images in the "
            "active project (default) OR globally that have ETL events "
            "from that provider. SECOND application of the cross-"
            "firmware aggregation pattern at walker-stream time (ι.B "
            "lookup_systemd_unit_across_firmwares precedent — Rule-of-"
            "One → Rule-of-Two). Wairz competitive differentiator — "
            "surfaces supply-chain / vendor-fingerprint signal: a "
            "third-party provider GUID present across multiple firmware "
            "images is likely a vendor-shipped EDR / endpoint-"
            "protection driver (legitimate) OR an in-the-wild ETW "
            "provider planted by an adversary across the same vendor's "
            "product line. Compare event_id distribution + "
            "example_anomaly_flags + example_session across matches to "
            "distinguish. The match_count >=2 case is flagged with "
            "supply_chain_signal in the output. scope='project' "
            "(default) restricts to the active project's firmwares; "
            "scope='global' searches every project in the database."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "provider_guid": {
                    "type": "string",
                    "description": (
                        "Provider GUID to match exactly (canonical "
                        "8-4-4-4-12 lowercase hyphenated form, e.g. "
                        "'9e814aad-3204-11d2-9a82-006008a86939')."
                    ),
                },
                "event_id": {
                    "type": "integer",
                    "description": (
                        "Optional exact match on event_id (provider-"
                        "scoped integer)."
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
                        "Max firmware matches to return (default 100, "
                        "min 1, max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["provider_guid"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_etl_provider_across_firmwares,
    )
