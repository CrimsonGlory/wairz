"""Q2 — ds1qrsetup binary call-graph PARSE-ONLY MCP tools.

Surfaces the Q2 ds1qrsetup call-graph walk results to the MCP layer:

- ``ds1qrsetup_callgraph_walk_status`` — Rule #33 status reader for
  the firmware-row ``ds1qrsetup_callgraph_walk_*`` state machine.
- ``trigger_ds1qrsetup_callgraph_walk`` — 202+poll start of the
  walker via
  ``asyncio.create_task(run_callgraph_background(firmware_id))``.
- ``lookup_ds1qrsetup_callgraph_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (Rule #44 — wairz competitive differentiator). Given a
  symbol query OR compile-flag substring, return every firmware whose
  ds1qrsetup walk result references that symbol / flag — answers
  questions like "which firmware images compile FFmpeg with
  ``--enable-libtensorflow``?" without per-firmware MCP round-trips.

**PARSE-ONLY DISCIPLINE REMINDER (Rule #36 + Rule #45).** The Q2 walker
analyses the ds1qrsetup binary AS DATA via Ghidra headless / radare2.
NEITHER tool invokes the extracted binary. These MCP tools surface
METADATA only — symbol catalogue + reachability classification +
compile-flag fingerprints. Operators triage as DATA.

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_ds1qrsetup_callgraph_walk_result,
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
        + "\n\n[output truncated to 30KB — narrow filters or page]"
    )


# ── ds1qrsetup_callgraph_walk_status ────────────────────────────────────────


async def _handle_ds1qrsetup_callgraph_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.ds1qrsetup_callgraph_walk_*."""
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
        "status": row.ds1qrsetup_callgraph_walk_status,
        "started_at": (
            row.ds1qrsetup_callgraph_walk_started_at.isoformat()
            if row.ds1qrsetup_callgraph_walk_started_at
            else None
        ),
        "finished_at": (
            row.ds1qrsetup_callgraph_walk_finished_at.isoformat()
            if row.ds1qrsetup_callgraph_walk_finished_at
            else None
        ),
        "error": row.ds1qrsetup_callgraph_walk_error,
        "result": _normalize_firmware_ds1qrsetup_callgraph_walk_result(
            row.ds1qrsetup_callgraph_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_ds1qrsetup_callgraph_walk ───────────────────────────────────────


async def _handle_trigger_ds1qrsetup_callgraph_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling ds1qrsetup call-graph walk background
    runner. Rule #33 .a idempotent POST + 409-on-conflict.
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

    if row.ds1qrsetup_callgraph_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.ds1qrsetup_callgraph_walk_status,
            "started_at": (
                row.ds1qrsetup_callgraph_walk_started_at.isoformat()
                if row.ds1qrsetup_callgraph_walk_started_at
                else None
            ),
            "message": (
                f"ds1qrsetup_callgraph walk already "
                f"{row.ds1qrsetup_callgraph_walk_status} for firmware "
                f"{firmware_id}. Poll "
                "ds1qrsetup_callgraph_walk_status."
            ),
        })

    row.ds1qrsetup_callgraph_walk_status = "queued"
    row.ds1qrsetup_callgraph_walk_started_at = None
    row.ds1qrsetup_callgraph_walk_finished_at = None
    row.ds1qrsetup_callgraph_walk_error = None
    row.ds1qrsetup_callgraph_walk_result = None
    await context.db.flush()

    from app.services.ds1qrsetup_callgraph_walker import (
        run_callgraph_background,
    )

    asyncio.create_task(run_callgraph_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "ds1qrsetup call-graph walk scheduled. Poll "
            "ds1qrsetup_callgraph_walk_status until "
            "status=='completed' to harvest the result. PARSE-ONLY: "
            "wairz analyses the ds1qrsetup binary AS DATA via Ghidra "
            "headless (preferred; cached per-binary-SHA in "
            "analysis_cache) or radare2 fallback; the binary is "
            "NEVER invoked via subprocess / exec / runpy. "
            "Aggregate surfaces FFmpeg / Pillow compile-flag "
            "fingerprints + reachable-from-main symbol set."
        ),
    })


# ── lookup_ds1qrsetup_callgraph_across_firmwares (Rule #44) ─────────────────


def _result_matches_query(
    result: dict, *, query: str, query_lower: str,
) -> dict | None:
    """Check whether a per-firmware aggregate matches a substring query
    against compile flags / reachable symbols / unreachable symbols.

    Returns a dict describing the matched dimension (and a sample hit),
    or None if no match.
    """
    flags = result.get("compile_flags_detected") or {}

    # Compile-flag dimension first — operator's most common query.
    for key in ("ffmpeg", "ffmpeg_disabled"):
        for flag in flags.get(key) or []:
            if query_lower in flag.lower():
                return {
                    "match_dimension": f"compile_flag.{key}",
                    "match_sample": flag,
                }
    for key in ("pillow_decoders", "pillow_decoders_absent"):
        for decoder in flags.get(key) or []:
            if query_lower in decoder.lower():
                return {
                    "match_dimension": f"compile_flag.{key}",
                    "match_sample": decoder,
                }

    # Reachable / unreachable symbol dimension.
    for sym in result.get("reachable_symbols") or []:
        if query_lower in sym.lower():
            return {
                "match_dimension": "reachable_symbol",
                "match_sample": sym,
            }
    for sym in result.get("unreachable_symbols") or []:
        if query_lower in sym.lower():
            return {
                "match_dimension": "unreachable_symbol",
                "match_sample": sym,
            }

    return None


async def _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a substring query, return
    every firmware in scope whose ds1qrsetup call-graph aggregate
    references the query (compile flag OR reachable/unreachable symbol).

    **FORENSIC VALUE** — answer questions like:

    (a) "Which firmware images compile FFmpeg with
        ``--enable-libtensorflow``?" — narrows DNN-backend CVE
        applicability across a fleet.
    (b) "Which firmware images have the Pillow JPEG decoder reachable
        from main?" — narrows Pillow long-tail CVE applicability.
    (c) "Which firmware images have ``av_dump_format`` UNREACHABLE
        from main?" — identifies fleets where a specific FFmpeg
        symbol's CVE doesn't apply because the reachable surface
        excludes it.

    Wairz competitive differentiator per Rule #44 (cross-firmware
    aggregation surface).

    PARSE-ONLY DISCIPLINE REMINDER: wairz NEVER invokes the
    ds1qrsetup binary; surfaces static-analysis METADATA only.
    """
    query = input.get("query")
    if not query or not isinstance(query, str):
        return json.dumps({
            "error": (
                "A query string is required. Matches substring against "
                "compile flags + reachable/unreachable symbols across "
                "all firmwares in scope (case-insensitive)."
            )
        })

    query_lower = query.lower()

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    # Pull every firmware row in scope (the call-graph result lives in
    # the firmware JSONB column — no separate table to JOIN to).
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
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(
                Project.id == project_id,
                Firmware.ds1qrsetup_callgraph_walk_status == "completed",
            )
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(
                Firmware.ds1qrsetup_callgraph_walk_status == "completed",
            )
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    for firmware, project in rows:
        result = _normalize_firmware_ds1qrsetup_callgraph_walk_result(
            firmware.ds1qrsetup_callgraph_walk_result
        )
        if result is None:
            continue
        # Rule #44 §SC5-NEW-ICS-S2-ι I39 — schema_version gate. Legacy
        # rows without schema_version are silently skipped.
        if result.get("schema_version") != 1:
            continue

        match_info = _result_matches_query(
            result, query=query, query_lower=query_lower,
        )
        if match_info is None:
            continue

        matches.append({
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "binary_analyzed": result.get("binary_analyzed"),
            "analyzer": result.get("analyzer"),
            "match_dimension": match_info["match_dimension"],
            "match_sample": match_info["match_sample"],
            "total_symbols_in_binary": (result.get("summary") or {}).get(
                "total_symbols_in_binary"
            ),
            "reachable_from_main": (result.get("summary") or {}).get(
                "reachable_from_main"
            ),
        })
        if len(matches) >= limit:
            break

    out: dict = {
        "query": query,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a completed "
            f"ds1qrsetup call-graph aggregate matching {query!r}. "
            "Run the walker against more firmwares (call "
            "trigger_ds1qrsetup_callgraph_walk on each), then "
            "re-query. PARSE-ONLY: wairz surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["cross_firmware_signal"] = (
            f"ds1qrsetup call-graph references matching {query!r} "
            f"appear in {len(matches)} firmware images. Possible "
            "interpretations: (a) shared Yocto recipe — the same "
            "compile-flag configuration across a fleet; (b) consistent "
            "static-link footprint — the same Python interpreter + "
            "C-module set; (c) per-firmware reachability divergence "
            "(check match_dimension values). PARSE-ONLY: wairz "
            "analyses the binary AS DATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ────────────────────────────────────────────────────────────


def register_ds1qrsetup_callgraph_tools(registry: ToolRegistry) -> None:
    """Register all Q2 ds1qrsetup call-graph MCP tools.

    3 tools registered:
      - ds1qrsetup_callgraph_walk_status (Rule #33 status reader)
      - trigger_ds1qrsetup_callgraph_walk (202+poll start)
      - lookup_ds1qrsetup_callgraph_across_firmwares (Rule #44
        cross-firmware aggregation — wairz competitive differentiator)

    PARSE-ONLY DISCIPLINE REMINDER (Rule #36 + Rule #45): the Q2 walker
    analyses the ds1qrsetup binary AS DATA via Ghidra headless /
    radare2; NEITHER tool invokes the binary. These tools surface
    METADATA only.
    """

    registry.register(
        name="ds1qrsetup_callgraph_walk_status",
        description=(
            "Q2 ds1qrsetup call-graph — Rule #33 status reader for the "
            "firmware-row ds1qrsetup_callgraph_walk_* state machine. "
            "Returns status (idle / queued / running / completed / "
            "failed), started_at, finished_at, error, and the "
            "last-known-result aggregate. The aggregate includes "
            "binary_analyzed, analyzer (ghidra / radare2 / "
            "unavailable), compile_flags_detected (ffmpeg + "
            "ffmpeg_disabled + pillow_decoders + "
            "pillow_decoders_absent), reachable_symbols, "
            "unreachable_symbols, summary (total / reachable / "
            "unreachable counts + run_seconds), errors, and "
            "axiom_self_audit. The cve-assessment-framework consumes "
            "this aggregate to narrow FFmpeg DNN-backend + Pillow "
            "decoder reachability for ~42 FFmpeg EXPL CVEs + Pillow "
            "long-tail. PARSE-ONLY: wairz NEVER invokes the binary."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_ds1qrsetup_callgraph_walk_status,
    )

    registry.register(
        name="trigger_ds1qrsetup_callgraph_walk",
        description=(
            "Trigger the 202+polling Q2 ds1qrsetup call-graph "
            "PARSE-ONLY walk background runner. Locates the "
            "ds1qrsetup binary via detection roots (Rule #16) under "
            "opt/ds1qrsetup/ / usr/bin/ / usr/local/bin/ / bin/, "
            "verifies ELF magic, picks the largest candidate, runs "
            "Ghidra headless (cached per-binary-SHA in analysis_cache; "
            "30-120s first run, sub-second cached) — falls back to "
            "radare2 + r2pipe if Ghidra is unavailable / fails. "
            "String-scans the binary for FFmpeg / Pillow compile-flag "
            "fingerprints (--enable-libtensorflow, JPEG / PNG / etc.). "
            "Computes reachability from main() via xrefs BFS. Stamps "
            "the canonical aggregate onto "
            "ds1qrsetup_callgraph_walk_result. Idempotent (Rule #33 "
            ".a) — returns conflict=true if a run is already queued "
            "or running. Schedules run_callgraph_background via "
            "asyncio.create_task. Poll "
            "ds1qrsetup_callgraph_walk_status until "
            "status=='completed'. PARSE-ONLY: ds1qrsetup binary is "
            "analysed AS DATA; NEVER invoked. If neither Ghidra nor "
            "radare2 is available, the aggregate carries "
            "analyzer=='unavailable' (INSUFFICIENT_EVIDENCE per "
            "cve-assessment-framework Q2 contract)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_ds1qrsetup_callgraph_walk,
    )

    registry.register(
        name="lookup_ds1qrsetup_callgraph_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION (Rule #44)** — given a "
            "substring query, return every firmware in scope whose "
            "ds1qrsetup call-graph aggregate references the query "
            "(compile flag OR reachable/unreachable symbol). "
            "**FORENSIC VALUE** — answer questions like: (a) 'Which "
            "firmware images compile FFmpeg with "
            "--enable-libtensorflow?' (narrows DNN-backend CVE "
            "applicability across a fleet); (b) 'Which firmware "
            "images have the Pillow JPEG decoder reachable from "
            "main?' (narrows Pillow long-tail CVE applicability); "
            "(c) 'Which firmware images have av_dump_format "
            "UNREACHABLE from main?' (identifies fleets where a "
            "specific FFmpeg symbol's CVE doesn't apply because the "
            "reachable surface excludes it). Wairz competitive "
            "differentiator per Rule #44. PARSE-ONLY: wairz NEVER "
            "invokes the binary. match_count >= 2 triggers "
            "cross_firmware_signal in the output. scope='project' "
            "(default) restricts to the active project; "
            "scope='global' searches every project. The query "
            "substring is case-insensitive; matches compile flags "
            "(ffmpeg + ffmpeg_disabled + pillow_decoders + "
            "pillow_decoders_absent dimensions) AND reachable / "
            "unreachable symbol names."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring match (case-insensitive) against "
                        "compile flags + reachable/unreachable symbol "
                        "names across firmwares in scope. E.g. "
                        "'libtensorflow', 'JPEG', 'av_dump_format', "
                        "'PIL_ExrDecode'."
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
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_ds1qrsetup_callgraph_across_firmwares,
    )
