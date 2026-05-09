"""Windows Event Log (EVTX) MCP tools — Phase ε.1.b.4.

Surfaces the Phase ε.1.b EVTX-walk verdicts to the MCP layer:

- ``list_evtx_files`` — list every ``.evtx`` file walked for the
  active firmware, with per-file status (ok / error / unavailable)
  + record_count + provider distribution.
- ``parse_evtx_file`` — parse one ``.evtx`` on demand via python-evtx
  and return a record summary (record_num + raw_xml). Useful when
  the persisted aggregate sample doesn't contain the specific record
  the operator wants to inspect.
- ``query_evtx_events`` — filter walked events by EID + provider +
  raw_xml substring across every walked .evtx of the active firmware.
- ``evtx_walk_status`` — Rule #33 status reader for the firmware-row
  evtx_walk_* state machine (idle / queued / running / completed /
  failed) + last-known-result aggregate.
- ``trigger_evtx_walk`` — trigger the 202+polling EVTX-walk background
  runner (Rule #33 .a idempotent POST + 409-on-conflict). Schedules
  ``run_evtx_walk_background`` via asyncio.create_task.
- ``evtx_walk_summary`` — return the firmware's evtx_walk_result
  aggregate (counts by provider, by status, total records, errors).

Sandbox discipline (Rule #1): every input ``path`` referencing an
.evtx file is resolved via ``context.resolve_path()`` before any read.

Rule #36 no-execute discipline: every tool reads .evtx files AS DATA
via python-evtx (mmap-based read-only record stream); nothing in this
module invokes wevtutil / Get-WinEvent or any scriptable event-replay
primitive.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps emit
a tail-truncation marker.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.services.jsonb_normalizers import (
    _normalize_firmware_evtx_walk_result,
)

logger = logging.getLogger(__name__)


# ── 30 KB output cap (Rule #29) ─────────────────────────────────────────────
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text) <= cap:
        return text
    return text[: cap - 50] + "\n...[truncated to 30KB output cap]"


# ── EID extraction helper ───────────────────────────────────────────────────


_EID_RE = re.compile(r"<EventID(?:\s+[^>]*)?>(\d+)</EventID>")
_PROVIDER_RE = re.compile(r"<Provider\b[^>]*\bName=['\"]([^'\"]+)['\"]")


def _eid_from_xml(xml: str) -> int | None:
    m = _EID_RE.search(xml or "")
    return int(m.group(1)) if m else None


def _provider_from_xml(xml: str) -> str | None:
    m = _PROVIDER_RE.search(xml or "")
    return m.group(1) if m else None


# ── Tool handlers ───────────────────────────────────────────────────────────


async def _handle_list_evtx_files(input: dict, context: ToolContext) -> str:
    """List every .evtx walked for the active firmware (per-file shape)."""
    firmware_id = uuid.UUID(context.firmware_id) if isinstance(context.firmware_id, str) else context.firmware_id
    fw = (
        await context.db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if fw is None:
        return json.dumps({"error": "active firmware not found"})

    aggregate = _normalize_firmware_evtx_walk_result(fw.evtx_walk_result) or {}
    per_file = aggregate.get("per_file") or []
    if not per_file:
        return json.dumps({
            "evtx_count": 0,
            "files": [],
            "message": "No EVTX walk has run for this firmware yet — call trigger_evtx_walk to start one.",
        })

    return _truncate(json.dumps({
        "evtx_count": aggregate.get("evtx_count", 0),
        "total_records": aggregate.get("total_records", 0),
        "files": per_file,
    }, indent=2))


async def _handle_parse_evtx_file(input: dict, context: ToolContext) -> str:
    """Parse one .evtx on demand via python-evtx."""
    rel = input.get("path", "")
    if not rel:
        return json.dumps({"error": "missing 'path' input"})

    try:
        full = context.resolve_path(rel)
    except Exception as exc:  # noqa: BLE001 — sandbox check failure
        return json.dumps({"error": f"sandbox check failed: {type(exc).__name__}: {str(exc)[:200]}"})

    # Cap records returned per call so the 30KB output cap doesn't
    # truncate mid-record. python-evtx parses lazily so an early-exit
    # via a small cap doesn't penalise large files.
    cap = int(input.get("max_records", 50))

    from app.services.evtx_service import parse_evtx_file
    loop = asyncio.get_running_loop()
    parsed = await loop.run_in_executor(None, parse_evtx_file, full)

    if parsed.get("status") != "ok":
        return _truncate(json.dumps(parsed))

    records = parsed.get("records") or []
    sliced = records[:cap]
    out = {
        "status": "ok",
        "path": rel,
        "record_count": len(records),
        "returned_count": len(sliced),
        "records": sliced,
    }
    return _truncate(json.dumps(out))


async def _handle_query_evtx_events(input: dict, context: ToolContext) -> str:
    """Filter walked events by EID + provider + raw_xml substring."""
    firmware_id = uuid.UUID(context.firmware_id) if isinstance(context.firmware_id, str) else context.firmware_id
    fw = (
        await context.db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if fw is None:
        return json.dumps({"error": "active firmware not found"})

    aggregate = _normalize_firmware_evtx_walk_result(fw.evtx_walk_result) or {}
    per_file = aggregate.get("per_file") or []
    if not per_file:
        return json.dumps({"matches": [], "message": "No EVTX walk results to query."})

    target_eid = input.get("eid")  # int | None
    target_provider = input.get("provider")  # str | None (substring match)
    target_substring = input.get("substring")  # str | None
    cap = int(input.get("max_results", 100))

    # Re-parse the per_file entries to get records (the aggregate
    # shape doesn't carry them; ε.1.b campaign Decision #1 deferred
    # per-event row persistence). For each file marked status='ok',
    # parse + filter by EID / provider / substring. Cap globally.
    from app.services.evtx_service import parse_evtx_file
    loop = asyncio.get_running_loop()

    matches: list[dict[str, Any]] = []
    for entry in per_file:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "ok":
            continue
        path = entry.get("path") or ""
        try:
            parsed = await loop.run_in_executor(None, parse_evtx_file, path)
        except Exception:  # noqa: BLE001
            continue
        for rec in parsed.get("records") or []:
            xml = rec.get("raw_xml") or ""
            if target_eid is not None:
                rec_eid = _eid_from_xml(xml)
                if rec_eid != int(target_eid):
                    continue
            if target_provider:
                provider = _provider_from_xml(xml) or ""
                if target_provider not in provider:
                    continue
            if target_substring and target_substring not in xml:
                continue
            matches.append({
                "path": path,
                "record_num": rec.get("record_num"),
                "eid": _eid_from_xml(xml),
                "provider": _provider_from_xml(xml),
                "raw_xml": xml[:1000],
            })
            if len(matches) >= cap:
                break
        if len(matches) >= cap:
            break

    return _truncate(json.dumps({
        "match_count": len(matches),
        "matches": matches,
    }))


async def _handle_evtx_walk_status(input: dict, context: ToolContext) -> str:
    """Rule #33 status reader for firmware.evtx_walk_*."""
    firmware_id = uuid.UUID(context.firmware_id) if isinstance(context.firmware_id, str) else context.firmware_id
    fw = (
        await context.db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if fw is None:
        return json.dumps({"error": "active firmware not found"})

    return json.dumps({
        "firmware_id": str(fw.id),
        "status": fw.evtx_walk_status,
        "started_at": fw.evtx_walk_started_at.isoformat() if fw.evtx_walk_started_at else None,
        "finished_at": fw.evtx_walk_finished_at.isoformat() if fw.evtx_walk_finished_at else None,
        "error": fw.evtx_walk_error,
    })


async def _handle_trigger_evtx_walk(input: dict, context: ToolContext) -> str:
    """Trigger the 202+polling EVTX-walk runner (Rule #33 .a idempotent)."""
    firmware_id = uuid.UUID(context.firmware_id) if isinstance(context.firmware_id, str) else context.firmware_id
    fw = (
        await context.db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if fw is None:
        return json.dumps({"error": "active firmware not found"})

    # Rule #33 .a — idempotent + 409-on-conflict. If a run is in flight,
    # don't double-schedule; just report the in-flight state.
    if fw.evtx_walk_status in ("queued", "running"):
        return json.dumps({
            "status": fw.evtx_walk_status,
            "message": (
                f"EVTX walk already {fw.evtx_walk_status} — call evtx_walk_status to "
                "poll until complete."
            ),
            "conflict": True,
        })

    # Reset prior run state and schedule background runner.
    fw.evtx_walk_status = "queued"
    fw.evtx_walk_started_at = None
    fw.evtx_walk_finished_at = None
    fw.evtx_walk_error = None
    fw.evtx_walk_result = None
    await context.db.flush()

    from app.services.evtx_service import run_evtx_walk_background
    asyncio.create_task(run_evtx_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(fw.id),
        "message": "EVTX walk queued; poll evtx_walk_status until status=='completed'",
    })


async def _handle_evtx_walk_summary(input: dict, context: ToolContext) -> str:
    """Return the firmware's evtx_walk_result aggregate."""
    firmware_id = uuid.UUID(context.firmware_id) if isinstance(context.firmware_id, str) else context.firmware_id
    fw = (
        await context.db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if fw is None:
        return json.dumps({"error": "active firmware not found"})

    aggregate = _normalize_firmware_evtx_walk_result(fw.evtx_walk_result)
    if aggregate is None:
        return json.dumps({
            "result": None,
            "message": "No EVTX walk result yet — call trigger_evtx_walk and poll evtx_walk_status.",
        })

    # Drop the per_file array from the summary view — it can be large;
    # operators get the per-file shape via list_evtx_files.
    summary = {k: v for k, v in aggregate.items() if k != "per_file"}
    summary["per_file_count"] = len(aggregate.get("per_file") or [])
    return _truncate(json.dumps(summary, indent=2))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_event_log_tools(registry: ToolRegistry) -> None:
    """Register all Phase ε.1.b.4 Windows Event Log MCP tools."""

    registry.register(
        name="list_evtx_files",
        description=(
            "List every .evtx file walked for the active firmware. "
            "Returns one entry per file with path, status (ok | error | "
            "unavailable), record_count, and any per-file error. Read-"
            "only; does not trigger a re-walk (use trigger_evtx_walk)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_list_evtx_files,
    )

    registry.register(
        name="parse_evtx_file",
        description=(
            "Parse one .evtx file on demand via python-evtx and return "
            "a record summary (record_num + raw_xml). Useful when the "
            "persisted aggregate sample doesn't contain the specific "
            "record the operator wants to inspect. Path must be inside "
            "the active firmware's extraction root (Rule #1 sandbox)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to the .evtx file inside the firmware "
                        "extraction tree (e.g. 'Windows/System32/winevt/Logs/Security.evtx')."
                    ),
                },
                "max_records": {
                    "type": "integer",
                    "description": "Cap on records returned (default 50; protects the 30KB output cap).",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        handler=_handle_parse_evtx_file,
    )

    registry.register(
        name="query_evtx_events",
        description=(
            "Filter walked events across every .evtx of the active "
            "firmware by Event ID, provider name (substring), and/or "
            "raw_xml substring. Returns up to max_results matches with "
            "path + record_num + EID + provider + truncated raw_xml. "
            "Useful for forensic-timeline pivots (e.g. all Sysmon EID=1 "
            "matching a specific commandline pattern)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "eid": {
                    "type": "integer",
                    "description": "Event ID filter (e.g. 1 for Sysmon process-create, 4624 for logon success).",
                },
                "provider": {
                    "type": "string",
                    "description": "Provider name substring filter (e.g. 'Sysmon' matches 'Microsoft-Windows-Sysmon').",
                },
                "substring": {
                    "type": "string",
                    "description": "Raw XML substring filter (case-sensitive).",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Cap on matches returned (default 100).",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_query_evtx_events,
    )

    registry.register(
        name="evtx_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row evtx_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, and error."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_evtx_walk_status,
    )

    registry.register(
        name="trigger_evtx_walk",
        description=(
            "Trigger the 202+polling EVTX walk background runner. "
            "Idempotent (Rule #33 .a) — returns conflict=true with the "
            "in-flight status if a run is already queued or running. On "
            "fresh runs, resets the firmware-row state and schedules "
            "run_evtx_walk_background via asyncio.create_task. Poll "
            "evtx_walk_status until status=='completed' to harvest the "
            "result."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_evtx_walk,
    )

    registry.register(
        name="evtx_walk_summary",
        description=(
            "Return the firmware's evtx_walk_result aggregate (counts "
            "by provider, by status, total records, errors). Drops the "
            "per_file array — use list_evtx_files for the file-level "
            "view. Returns null when no walk has completed."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_evtx_walk_summary,
    )
