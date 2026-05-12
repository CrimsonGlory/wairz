"""Linux persistence-triplet MCP tools — Phase κ.C.E.

Surfaces the Phase κ.C.C Linux persistence walk results (bash_history +
crontab + ld.so.preload) to the MCP layer:

- ``list_linux_persistence_entries`` — paginate one of the 3 κ.C.A
  landing-zone tables for the active firmware (artefact_type discriminator
  selects bash_history / cron / ld_preload). Supports suspicious-only +
  per-bit filters + path substring.
- ``lookup_linux_persistence_entry`` — substring match against the
  artefact-specific text field (command / library_path).
- ``lookup_linux_persistence_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (Rule #44 — wairz competitive differentiator). Given a
  substring, return all firmware images that have a matching entry in
  the named artefact family.
- ``linux_persistence_walk_status`` — Rule #33 status reader for the
  firmware-row persistence_walk_* state machine.
- ``trigger_linux_persistence_walk`` — 202+poll start of the walker via
  ``asyncio.create_task(run_linux_persistence_walk_background(firmware_id))``.

**PARSE-ONLY discipline reminder (Rule #36).** The κ.C.C walker is a
pure-Python text-line parser over 3 artefact families. The walker
NEVER invokes ``bash`` / ``crontab`` / ``ldconfig`` against parsed
content. These MCP tools surface persistence METADATA only — commands,
schedules, library paths, suspicious flags. Operators triage as DATA.

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
from app.models.linux_bash_history_entries import LinuxBashHistoryEntry
from app.models.linux_cron_jobs import LinuxCronJob
from app.models.linux_ld_preload_entries import LinuxLdPreloadEntry
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_persistence_walk_result,
    _normalize_linux_bash_history_suspicious_flags,
    _normalize_linux_cron_suspicious_flags,
    _normalize_linux_ld_preload_suspicious_flags,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024


_ARTEFACT_TYPES = ("bash_history", "cron", "ld_preload")


# Per-artefact configuration.
# Keys: model, text_column, normalizer, suspicious_bits.
def _artefact_config(artefact_type: str) -> dict:
    if artefact_type == "bash_history":
        return {
            "model": LinuxBashHistoryEntry,
            "text_column": LinuxBashHistoryEntry.command,
            "normalize_flags": _normalize_linux_bash_history_suspicious_flags,
            "suspicious_bits": (
                "clear_marker",
                "download_pattern",
                "priv_esc_pattern",
            ),
        }
    if artefact_type == "cron":
        return {
            "model": LinuxCronJob,
            "text_column": LinuxCronJob.command,
            "normalize_flags": _normalize_linux_cron_suspicious_flags,
            "suspicious_bits": (
                "temp_path_command",
                "reboot_persistence",
                "network_egress_pattern",
            ),
        }
    if artefact_type == "ld_preload":
        return {
            "model": LinuxLdPreloadEntry,
            "text_column": LinuxLdPreloadEntry.library_path,
            "normalize_flags": _normalize_linux_ld_preload_suspicious_flags,
            "suspicious_bits": (
                "temp_path_library",
                "unusual_extension",
                "world_writable_dir",
            ),
        }
    return {}


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


def _row_has_suspicious(
    record: object, bits: tuple[str, ...], normalize_flags
) -> bool:
    flags = normalize_flags(getattr(record, "suspicious_flags", None))
    return any(bool(flags.get(b)) for b in bits)


def _row_summary(record: object, artefact_type: str) -> dict:
    """Construct per-row summary for the artefact_type."""
    config = _artefact_config(artefact_type)
    normalize_flags = config["normalize_flags"]
    flags = normalize_flags(getattr(record, "suspicious_flags", None))

    base = {
        "id": str(record.id),
        "source_file": record.source_file,
        "line_number": record.line_number,
        "suspicious_flags": flags,
        "has_suspicious": _row_has_suspicious(
            record, config["suspicious_bits"], normalize_flags
        ),
    }
    if artefact_type == "bash_history":
        base["command"] = record.command
    elif artefact_type == "cron":
        base["schedule_spec"] = record.schedule_spec
        base["user"] = record.user
        base["command"] = record.command
    elif artefact_type == "ld_preload":
        base["library_path"] = record.library_path
    return base


# ── list_linux_persistence_entries ──────────────────────────────────────────


async def _handle_list_linux_persistence_entries(
    input: dict, context: ToolContext
) -> str:
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    artefact_type = input.get("artefact_type")
    if artefact_type not in _ARTEFACT_TYPES:
        return json.dumps({
            "error": (
                f"artefact_type must be one of {_ARTEFACT_TYPES}; "
                f"got {artefact_type!r}"
            )
        })

    suspicious_only = bool(input.get("suspicious_only", False))
    suspicious_bit = input.get("suspicious_bit")
    path_substring = input.get("path_substring")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    config = _artefact_config(artefact_type)
    Model = config["model"]
    text_col = config["text_column"]
    normalize_flags = config["normalize_flags"]
    bits = config["suspicious_bits"]

    base_where = [Model.firmware_id == firmware_id]
    if path_substring:
        base_where.append(text_col.ilike(f"%{path_substring}%"))

    if suspicious_only or suspicious_bit:
        # Python-side filter since JSONB.
        page_q = (
            select(Model)
            .where(*base_where)
            .order_by(Model.source_file, Model.line_number)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if suspicious_bit:
            filtered = [
                r for r in rows
                if normalize_flags(
                    getattr(r, "suspicious_flags", None)
                ).get(suspicious_bit)
            ]
        elif suspicious_only:
            filtered = [
                r for r in rows
                if _row_has_suspicious(r, bits, normalize_flags)
            ]
        else:
            filtered = list(rows)
        total = len(filtered)
        rows = filtered[offset:offset + limit]
    else:
        total_q = select(sa_func.count(Model.id)).where(*base_where)
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(Model)
            .where(*base_where)
            .order_by(Model.source_file, Model.line_number)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    entries = [_row_summary(r, artefact_type) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "artefact_type": artefact_type,
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "entries": entries,
        "filters": {
            "suspicious_only": suspicious_only,
            "suspicious_bit": suspicious_bit,
            "path_substring": path_substring,
        },
    }
    if total == 0:
        out["message"] = (
            f"No {artefact_type} entries match. The walker may not have "
            "run yet (call trigger_linux_persistence_walk and poll "
            "linux_persistence_walk_status), the firmware may not "
            "contain a Linux rootfs, or your filters may be too narrow. "
            "PARSE-ONLY: the walker NEVER invokes parsed commands / "
            "libraries; surfaces persistence METADATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_linux_persistence_entry ──────────────────────────────────────────


async def _handle_lookup_linux_persistence_entry(
    input: dict, context: ToolContext
) -> str:
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    artefact_type = input.get("artefact_type")
    if artefact_type not in _ARTEFACT_TYPES:
        return json.dumps({
            "error": (
                f"artefact_type must be one of {_ARTEFACT_TYPES}; "
                f"got {artefact_type!r}"
            )
        })

    query = input.get("query")
    if not query:
        return json.dumps({"error": "query (substring) is required"})

    config = _artefact_config(artefact_type)
    Model = config["model"]
    text_col = config["text_column"]

    stmt = (
        select(Model)
        .where(
            Model.firmware_id == firmware_id,
            text_col.ilike(f"%{query}%"),
        )
        .order_by(Model.source_file, Model.line_number)
        .limit(50)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    if not rows:
        return json.dumps({
            "firmware_id": str(firmware_id),
            "artefact_type": artefact_type,
            "query": query,
            "match_count": 0,
            "message": (
                f"No {artefact_type} entries matched substring {query!r}. "
                "Run trigger_linux_persistence_walk first OR verify the "
                "spelling."
            ),
        })

    return _truncate(json.dumps({
        "firmware_id": str(firmware_id),
        "artefact_type": artefact_type,
        "query": query,
        "match_count": len(rows),
        "matches": [_row_summary(r, artefact_type) for r in rows],
    }, indent=2))


# ── lookup_linux_persistence_across_firmwares (Rule #44 cross-firmware) ─────


async def _handle_lookup_linux_persistence_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a substring against the
    artefact's primary text column, return ALL firmware images in the
    active project (or globally) that have matching entries.

    **FORENSIC VALUE** — Cross-firmware presence of the same
    bash_history command / cron command / ld.so.preload library across
    supposedly-independent firmware captures = strong supply-chain or
    cross-firmware adversary signal. Wairz competitive differentiator
    per Rule #44.
    """
    artefact_type = input.get("artefact_type")
    if artefact_type not in _ARTEFACT_TYPES:
        return json.dumps({
            "error": (
                f"artefact_type must be one of {_ARTEFACT_TYPES}; "
                f"got {artefact_type!r}"
            )
        })

    query = input.get("query")
    if not query:
        return json.dumps({"error": "query (substring) is required"})

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    config = _artefact_config(artefact_type)
    Model = config["model"]
    text_col = config["text_column"]

    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(Model, Firmware, Project)
            .join(Firmware, Model.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(
                Project.id == project_id,
                text_col.ilike(f"%{query}%"),
            )
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(Model, Firmware, Project)
            .join(Firmware, Model.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(text_col.ilike(f"%{query}%"))
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    per_firmware: dict[uuid.UUID, dict] = {}
    for entry_row, firmware, project in rows:
        bucket = per_firmware.setdefault(firmware.id, {
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "match_count": 0,
            "sample_entry": _row_summary(entry_row, artefact_type),
        })
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]
    out: dict = {
        "artefact_type": artefact_type,
        "query": query,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a {artefact_type} "
            f"entry matching {query!r}. Run the walker against more "
            "firmwares (call trigger_linux_persistence_walk on each), "
            "then re-query. PARSE-ONLY: wairz surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["cross_firmware_signal"] = (
            f"{artefact_type} entries matching {query!r} appear in "
            f"{len(matches)} firmware images. Possible signals: (a) "
            "shared vendor build / installer leaving the same "
            f"{artefact_type} trace (baseline — verify against vendor "
            "docs); (b) compromised supply chain (same artefact across "
            "supposedly-independent firmware); (c) cross-firmware "
            "adversary persistence (rare but documented for APT34 / "
            "APT36 / FIRESTARTER). Compare sample_entry across matches "
            "and review suspicious_flags."
        )
    return _truncate(json.dumps(out, indent=2))


# ── linux_persistence_walk_status ───────────────────────────────────────────


async def _handle_linux_persistence_walk_status(
    input: dict, context: ToolContext
) -> str:
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
        "status": row.persistence_walk_status,
        "started_at": (
            row.persistence_walk_started_at.isoformat()
            if row.persistence_walk_started_at
            else None
        ),
        "finished_at": (
            row.persistence_walk_finished_at.isoformat()
            if row.persistence_walk_finished_at
            else None
        ),
        "error": row.persistence_walk_error,
        "result": _normalize_firmware_persistence_walk_result(
            row.persistence_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_linux_persistence_walk ──────────────────────────────────────────


async def _handle_trigger_linux_persistence_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling Linux persistence-triplet walk.
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

    if row.persistence_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.persistence_walk_status,
            "started_at": (
                row.persistence_walk_started_at.isoformat()
                if row.persistence_walk_started_at
                else None
            ),
            "message": (
                f"linux persistence walk already "
                f"{row.persistence_walk_status} for firmware "
                f"{firmware_id}. Poll linux_persistence_walk_status."
            ),
        })

    row.persistence_walk_status = "queued"
    row.persistence_walk_started_at = None
    row.persistence_walk_finished_at = None
    row.persistence_walk_error = None
    row.persistence_walk_result = None
    await context.db.flush()

    from app.services.linux_persistence_walker import (
        run_linux_persistence_walk_background,
    )

    asyncio.create_task(run_linux_persistence_walk_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Linux persistence walk scheduled (walks bash_history + "
            "crontab + ld.so.preload under detection roots). Poll "
            "linux_persistence_walk_status until status=='completed' to "
            "harvest the result. PARSE-ONLY: walker NEVER invokes parsed "
            "commands / libraries; surfaces persistence METADATA only."
        ),
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_linux_persistence_tools(registry: ToolRegistry) -> None:
    """Register all Phase κ.C.E Linux persistence-triplet MCP tools.

    5 tools registered:
      - list_linux_persistence_entries
      - lookup_linux_persistence_entry
      - lookup_linux_persistence_across_firmwares (Rule #44 cross-
        firmware aggregation)
      - linux_persistence_walk_status
      - trigger_linux_persistence_walk

    PARSE-ONLY discipline reminder: the κ.C.C walker reads each artefact
    file AS TEXT (bash_history + crontab + ld.so.preload). The walker
    NEVER invokes ``bash`` / ``crontab`` / ``ldconfig`` against parsed
    content; these tools surface persistence METADATA only.
    """

    registry.register(
        name="list_linux_persistence_entries",
        description=(
            "Phase κ.C.E — paginate one of the 3 Linux persistence "
            "landing-zone tables for the active firmware. The "
            "artefact_type discriminator selects bash_history / cron / "
            "ld_preload. Surfaces persistence METADATA extracted from "
            "Linux text-format artefacts: bash_history (T1059 + T1070.003), "
            "crontab (T1053.003 + T1547 + T1105), and ld.so.preload "
            "(T1574.006). **PARSE-ONLY** — wairz NEVER invokes parsed "
            "commands or libraries. Filters: suspicious_only (true → only "
            "rows with at least one suspicious_flags bit set), "
            "suspicious_bit (filter to a specific bit — see schema for "
            "valid per-artefact bit names), path_substring (case-"
            "insensitive ILIKE against command / library_path). Returns "
            "up to `limit` rows per page (default 50, max 500) ordered "
            "by source_file then line_number."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "artefact_type": {
                    "type": "string",
                    "enum": list(_ARTEFACT_TYPES),
                    "description": (
                        "Artefact family: bash_history (per-line bash "
                        "history), cron (per-line crontab), or ld_preload "
                        "(per-line ld.so.preload)."
                    ),
                },
                "suspicious_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only rows with at least one "
                        "suspicious_flags bit set."
                    ),
                },
                "suspicious_bit": {
                    "type": "string",
                    "description": (
                        "Filter to rows with this specific bit set. "
                        "Valid bits per artefact_type — "
                        "bash_history: clear_marker / download_pattern / "
                        "priv_esc_pattern; "
                        "cron: temp_path_command / reboot_persistence / "
                        "network_egress_pattern; "
                        "ld_preload: temp_path_library / unusual_extension "
                        "/ world_writable_dir."
                    ),
                },
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring filter on the "
                        "artefact's primary text column (command for "
                        "bash_history + cron; library_path for "
                        "ld_preload). SQL ILIKE %substring%."
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
                    "description": "Page offset (default 0).",
                    "minimum": 0,
                },
            },
            "required": ["artefact_type"],
            "additionalProperties": False,
        },
        handler=_handle_list_linux_persistence_entries,
    )

    registry.register(
        name="lookup_linux_persistence_entry",
        description=(
            "Phase κ.C.E — find Linux persistence entries by substring "
            "against the artefact's primary text column. Returns up to "
            "50 matching entries for the active firmware. Use this "
            "when hunting for a specific command / library across "
            "bash_history / cron / ld.so.preload. PARSE-ONLY — wairz "
            "NEVER invokes parsed content; surfaces METADATA only."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "artefact_type": {
                    "type": "string",
                    "enum": list(_ARTEFACT_TYPES),
                    "description": (
                        "Artefact family: bash_history / cron / ld_preload."
                    ),
                },
                "query": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring match (SQL ILIKE "
                        "%substring%) against the artefact's primary "
                        "text column."
                    ),
                },
            },
            "required": ["artefact_type", "query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_linux_persistence_entry,
    )

    registry.register(
        name="lookup_linux_persistence_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION (Rule #44)** — given a "
            "substring against the artefact's primary text column, "
            "return ALL firmware images in the active project (default) "
            "OR globally that have matching entries. **FORENSIC VALUE** "
            "— cross-firmware presence of the same bash_history "
            "command / cron command / ld.so.preload library across "
            "supposedly-independent firmware captures is a strong "
            "supply-chain or cross-firmware adversary signal. Wairz "
            "competitive differentiator. PARSE-ONLY: walker surfaces "
            "METADATA only. match_count >= 2 triggers "
            "cross_firmware_signal in the output."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "artefact_type": {
                    "type": "string",
                    "enum": list(_ARTEFACT_TYPES),
                    "description": (
                        "Artefact family: bash_history / cron / ld_preload."
                    ),
                },
                "query": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring match against the "
                        "artefact's primary text column."
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
            "required": ["artefact_type", "query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_linux_persistence_across_firmwares,
    )

    registry.register(
        name="linux_persistence_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "persistence_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(bash_history_files_scanned, bash_history_lines_persisted, "
            "cron_files_scanned, cron_lines_persisted, "
            "ld_preload_files_scanned, ld_preload_lines_persisted, "
            "per-anomaly counts, errors, per_artefact list)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_linux_persistence_walk_status,
    )

    registry.register(
        name="trigger_linux_persistence_walk",
        description=(
            "Trigger the 202+polling Linux persistence-triplet walk "
            "(bash_history + crontab + ld.so.preload). Walks every "
            "detection root (per Rule #16), locates each artefact "
            "family, decodes each file as TEXT (errors='replace' for "
            "non-UTF8 robustness), splits into lines, classifies each "
            "line, persists per-line rows across 3 sibling ORM tables. "
            "Idempotent (Rule #33 .a) — returns conflict=true if a run "
            "is already queued or running. Schedules "
            "run_linux_persistence_walk_background via "
            "asyncio.create_task. Poll linux_persistence_walk_status "
            "until status=='completed' to harvest the result. Anomaly "
            "classifier covers 9 bits total (3 per artefact): "
            "bash_history (clear_marker T1070.003, download_pattern "
            "T1105, priv_esc_pattern T1548.003), cron (temp_path_command "
            "T1543.002, reboot_persistence T1547, network_egress_pattern "
            "T1105+T1071), ld.so.preload (temp_path_library T1574.006, "
            "unusual_extension T1036, world_writable_dir). **PARSE-ONLY "
            "(Rule #36)** — walker NEVER invokes bash / crontab / "
            "ldconfig against parsed content."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_linux_persistence_walk,
    )
