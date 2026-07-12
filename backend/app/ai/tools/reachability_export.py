"""MCP tools for the MOVE 2 reachability-export durability walker (wairz↔framework bridge).

A NEW, DISTINCT tool namespace (mirrors the module_reachability namespace separation). Tool
surface:

  - ``trigger_reachability_export_walk`` — operator-trigger the walker (Rule #33 .a; project-scope
    guarded; 409-shaped conflict on in-flight rerun). Flips
    ``reachability_export_walk_status`` idle → queued + dispatches the background runner.
  - ``get_reachability_export`` — reads the firmware-level AGGREGATE
    (``firmware.reachability_export_walk_result`` — blob/elf/stripped counts), provenance-gated
    (schema_version==1 + provenance=="walker").
  - ``export_reachability_jsonl`` — generate the ``wairz_reachability.jsonl`` wire records ON
    DEMAND (the bridge artifact the framework consumer reads) and write them next to the firmware
    upload; returns the path + count + a small sample.
  - ``lookup_reachable_symbol_across_firmwares`` — **Rule #44 mandatory cross-firmware aggregator**.
    "Which firmwares DEFINE symbol X?" — a GIN-indexed JSONB-containment query over the per-blob
    ``reachability_export_records`` table, grouped by firmware, with a ``supply_chain_signal`` flag.

THE STRUCTURAL RAISE-ONLY CONTRACT (Rule #45 / #53). The lookup is a symbol-PRESENCE /
supply-chain query — it returns firmwares that DEFINE the symbol (candidates to investigate). It
carries NO clear-bearing field, a typed ``suggested_action: "raise_only"``, and an explicit caveat
that ABSENCE FROM THE RESULTS IS NOT PROOF OF ABSENCE (a firmware may not have been walked, or its
blobs may be stripped). Only nm-proven absence on a NON-STRIPPED, sha256-matched binary clears a
CVE — and that determination lives at the framework bridge consumer, NEVER here.

Per Rule #36/#45 the walker neither decrypts nor executes; these tools surface parse-only artefacts.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.reachability_export import ReachabilityExportRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_reachability_export_walk_result,
)
from app.services.reachability_export import (
    export_reachability_records,
    write_reachability_jsonl,
)
from app.services.reachability_export_walker import (
    run_reachability_export_walk_background,
)

logger = logging.getLogger(__name__)

_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text) <= cap:
        return text
    return text[: cap - 80] + "\n... [truncated — narrow the query/scope] ..."


def _coerce_firmware_id(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(value) if isinstance(value, str) else value
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_trigger_reachability_export_walk(
    input: dict, context: ToolContext
) -> str:
    """Operator-trigger the reachability-export walker (Rule #33 .a). Project-scope guarded;
    409-shaped conflict on in-flight rerun."""
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    firmware_id = _coerce_firmware_id(firmware_id_str)
    if firmware_id is None:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    if not context.project_id:
        return json.dumps({
            "error": (
                "no active project — call switch_project before "
                "trigger_reachability_export_walk"
            ),
        })
    project_id = _coerce_firmware_id(context.project_id)
    firmware = (
        await context.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
    ).scalar_one_or_none()
    if firmware is None:
        return json.dumps({
            "error": (
                f"firmware {firmware_id} not found in active project {project_id} "
                f"(wrong id OR belongs to a different project — tenancy scope guard)"
            ),
        })

    if firmware.reachability_export_walk_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "reachability_export_walk_status": firmware.reachability_export_walk_status,
            "message": (
                f"reachability_export_walk is already "
                f"{firmware.reachability_export_walk_status} — wait for completion "
                f"before re-triggering."
            ),
        })

    firmware.reachability_export_walk_status = "queued"
    firmware.reachability_export_walk_started_at = None
    firmware.reachability_export_walk_finished_at = None
    firmware.reachability_export_walk_error = None
    firmware.reachability_export_walk_result = None
    await context.db.flush()  # Rule #3 — flush, not commit, in MCP handlers.
    await context.db.commit()  # background runner opens its own session; commit so it sees `queued`.
    asyncio.create_task(run_reachability_export_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "reachability-export walker enqueued. Poll "
            "firmware.reachability_export_walk_status through running → "
            "completed | failed; harvest the aggregate via get_reachability_export, "
            "the per-symbol fleet view via lookup_reachable_symbol_across_firmwares, "
            "and the bridge JSONL via export_reachability_jsonl."
        ),
    })


async def _handle_get_reachability_export(input: dict, context: ToolContext) -> str:
    """Read the firmware-level reachability-export AGGREGATE (counts only). Provenance-gated."""
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    firmware_id = _coerce_firmware_id(firmware_id_str)
    if firmware_id is None:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    result = _normalize_firmware_reachability_export_walk_result(
        firmware.reachability_export_walk_result
    )
    out: dict = {
        "firmware_id": str(firmware_id),
        "reachability_export_walk_status": firmware.reachability_export_walk_status,
    }
    if result is None:
        out["result"] = None
        out["hint"] = (
            f"no reachability-export walk result yet (status="
            f"{firmware.reachability_export_walk_status}); trigger via "
            f"trigger_reachability_export_walk and poll until completed."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    if result.get("schema_version") != 1 or result.get("provenance") != "walker":
        out["result"] = result
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate "
            f"(schema_version={result.get('schema_version')!r}, "
            f"provenance={result.get('provenance')!r}) — re-trigger via "
            f"trigger_reachability_export_walk."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    out["result"] = result
    out["note"] = (
        "Aggregate counts only — the full per-blob symbol sets live in the "
        "reachability_export_records table; query them via "
        "lookup_reachable_symbol_across_firmwares."
    )
    return _truncate(json.dumps(out, indent=2, default=str))


async def _handle_export_reachability_jsonl(input: dict, context: ToolContext) -> str:
    """Generate the wairz_reachability.jsonl wire records on demand + write them next to the
    firmware upload. Returns the path + count + a small sample (the records can be large)."""
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    firmware_id = _coerce_firmware_id(firmware_id_str)
    if firmware_id is None:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    records = await export_reachability_records(firmware_id, context.db)
    # Write next to the firmware upload (the firmware's own storage dir — a writable, durable
    # location). The JSONL is a DERIVED artefact (Rule #45: our own output, not firmware content).
    out_dir = os.path.dirname(firmware.storage_path or "") or "/tmp"
    out_path = os.path.join(out_dir, f"wairz_reachability_{firmware_id}.jsonl")
    try:
        count = await asyncio.get_event_loop().run_in_executor(
            None, write_reachability_jsonl, records, out_path
        )
    except OSError as exc:
        return json.dumps({
            "error": f"failed to write JSONL to {out_path}: {exc}",
            "record_count": len(records),
        })

    out = {
        "firmware_id": str(firmware_id),
        "jsonl_path": out_path,
        "record_count": count,
        "sample": records[:2],
        "note": (
            "Bridge wire records (binary axis). Deferred reachability axes are explicitly NULL "
            "(link_b_reachable / indirect_calls / confidence_score). The framework consumer "
            "intersects its per-CVE sink set against defined_symbols; symbol absence clears a CVE "
            "ONLY on a non-stripped, sha256-matched binary (the consumer enforces the Iron Law)."
        ),
    }
    return _truncate(json.dumps(out, indent=2, default=str))


async def _handle_lookup_reachable_symbol_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """Rule #44 cross-firmware aggregator — which firmwares DEFINE symbol X?

    A GIN-indexed JSONB-containment query (``defined_symbols @> '["X"]'``) over the per-blob
    reachability_export_records table, grouped by firmware. STRUCTURAL RAISE-ONLY: returns
    PRESENCE matches (candidates to investigate) with NO clear-bearing field, a typed
    ``suggested_action: "raise_only"``, and a caveat that absence-from-results is NOT proof of
    absence. Only nm-proven absence on a non-stripped, sha256-matched binary clears — at the
    framework consumer, never here.
    """
    symbol = input.get("symbol")
    if not symbol or not isinstance(symbol, str):
        return json.dumps({"error": "symbol (a function name string) is required."})
    symbol = symbol.strip()
    if not symbol:
        return json.dumps({"error": "symbol must be non-empty."})

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        return json.dumps({"error": f"scope must be 'project' or 'global', got {scope!r}"})
    limit = max(1, min(int(input.get("limit", 100)), 500))

    stmt = (
        select(ReachabilityExportRecord, Firmware, Project)
        .join(Firmware, ReachabilityExportRecord.firmware_id == Firmware.id)
        .join(Project, Firmware.project_id == Project.id)
        # GIN-backed containment: the symbol is in this blob's DEFINED set.
        .where(ReachabilityExportRecord.defined_symbols.contains([symbol]))
        .order_by(Firmware.created_at)
    )
    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — call switch_project "
                    "first or use scope='global'."
                ),
            })
        stmt = stmt.where(Firmware.project_id == _coerce_firmware_id(context.project_id))

    rows = (await context.db.execute(stmt)).all()

    # Group by firmware (a firmware may define the symbol in >1 blob — report the first blob hit).
    by_firmware: dict[str, dict] = {}
    for record, firmware, project in rows:
        fid = str(firmware.id)
        if fid in by_firmware:
            by_firmware[fid]["defining_blob_count"] += 1
            continue
        by_firmware[fid] = {
            "firmware_id": fid,
            "project_id": str(project.id),
            "project_name": project.name,
            "original_filename": firmware.original_filename,
            "reachability_export_walk_status": firmware.reachability_export_walk_status,
            "sample_blob_path": record.blob_path,
            "sample_blob_sha256": record.blob_sha256,
            "sample_blob_stripped": record.stripped,
            "sample_blob_arch": record.arch,
            "defining_blob_count": 1,
        }
        if len(by_firmware) >= limit:
            break

    matches = list(by_firmware.values())
    # supply_chain_signal: the SAME symbol is DEFINED across ≥2 firmwares — a fleet-wide
    # presence signal (the vulnerable function ships in multiple devices → broaden investigation).
    supply_chain_signal = len(matches) >= 2

    out = {
        "symbol": symbol,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": supply_chain_signal,
        "matches": matches,
        # STRUCTURAL raise-only contract (Rule #45/#53):
        "suggested_action": "raise_only",
        "caveat": (
            "PRESENCE query: these firmwares DEFINE the symbol (investigate them). Absence from "
            "this list is NOT proof of absence — a firmware may not have been walked, or its blobs "
            "may be stripped (symbol absence on a stripped binary is absence-of-evidence). NEVER "
            "clear a CVE on absence-from-results; only nm-proven absence on a non-stripped, "
            "sha256-matched binary clears, and that determination lives at the framework bridge "
            "consumer, not here."
        ),
    }
    if not matches:
        out["message"] = (
            "No firmwares define this symbol in the walked corpus. This is NOT a clear — "
            "ensure the reachability-export walker has run (trigger_reachability_export_walk) "
            "on the relevant firmwares; rows are only present for walked, non-stripped ELF blobs."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_reachability_export_tools(registry: ToolRegistry) -> None:
    """Register the MOVE 2 reachability-export MCP tools (DISTINCT namespace)."""
    registry.register(
        name="trigger_reachability_export_walk",
        description=(
            "Trigger the reachability-export durability walker on one firmware. Extracts per-ELF-"
            "blob symbol-presence facts (DEFINED / IMPORTED sets) PARSE-ONLY via pyelftools, "
            "persists them per-blob into reachability_export_records (GIN-queryable), and stamps a "
            "counts-only aggregate. Idempotent — 409-shaped conflict if already running. Poll "
            "firmware.reachability_export_walk_status; harvest via get_reachability_export / "
            "lookup_reachable_symbol_across_firmwares / export_reachability_jsonl. PARSE-ONLY "
            "(Rule #45) — reads the ELF symbol table AS DATA; never executes a binary."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": "UUID of the firmware to walk; defaults to context.firmware_id.",
                },
            },
        },
        handler=_handle_trigger_reachability_export_walk,
    )
    registry.register(
        name="get_reachability_export",
        description=(
            "Read the firmware-level reachability-export AGGREGATE "
            "(firmware.reachability_export_walk_result): blob_count / elf_count / stripped_count / "
            "total_defined_symbols. Counts only — the full per-blob symbol sets live in the "
            "reachability_export_records table (query via lookup_reachable_symbol_across_firmwares). "
            "Provenance-gated (schema_version==1 + provenance=='walker')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": "UUID of the firmware; defaults to context.firmware_id.",
                },
            },
        },
        handler=_handle_get_reachability_export,
    )
    registry.register(
        name="export_reachability_jsonl",
        description=(
            "Generate the wairz_reachability.jsonl bridge wire records ON DEMAND for one firmware "
            "(the artefact the cve-assessment-framework consumer reads) and write them next to the "
            "firmware upload. Returns the path + record count + a small sample. Deferred "
            "reachability axes (link_b_reachable / indirect_calls / confidence_score) are "
            "explicitly NULL — symbol absence clears a CVE ONLY on a non-stripped, sha256-matched "
            "binary, enforced at the consumer."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": "UUID of the firmware; defaults to context.firmware_id.",
                },
            },
        },
        handler=_handle_export_reachability_jsonl,
    )
    registry.register(
        name="lookup_reachable_symbol_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a function-symbol NAME, return every "
            "firmware that DEFINES it (a GIN-indexed JSONB-containment query over the per-blob "
            "reachability_export_records table). The supply-chain query: 'which devices ship the "
            "vulnerable function?'. supply_chain_signal=True when >=2 firmwares define it. "
            "STRUCTURAL RAISE-ONLY: this is a PRESENCE query (candidates to investigate) carrying "
            "suggested_action='raise_only' and NO clear-bearing field — absence from the results "
            "is NOT proof of absence (the firmware may be unwalked or its blobs stripped). NEVER "
            "clear a CVE on absence-from-results. scope='global' searches all projects."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": (
                        "Exact function-symbol name to look up across the fleet "
                        "(e.g. 'dhcp6_reply', 'png_handle_iCCP'). Required."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "Search scope. 'project' (default) restricts to the active project; "
                        "'global' searches all projects."
                    ),
                    "default": "project",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Max distinct firmwares to return (default 100, max 500).",
                },
            },
            "required": ["symbol"],
        },
        handler=_handle_lookup_reachable_symbol_across_firmwares,
    )


__all__ = ["register_reachability_export_tools"]
