"""Windows AppCompat / Shimcache execution-evidence MCP tools — Phase κ.B.E.

Surfaces the Phase κ.B.C AppCompat walk results to the MCP layer:

- ``list_appcompat_entries`` — paginate the windows_appcompat_entries
  table for the active firmware with filters (anomaly_only, anomaly_bit,
  control_set, path_substring).
- ``lookup_appcompat_entry`` — fetch one AppCompat entry row by exact
  file_path or by substring match for the active firmware.
- ``lookup_appcompat_entry_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (Rule #44 — wairz competitive differentiator). Given a
  file_path (exact or substring), return all firmware images that have
  that path in AppCompat. Forensic value: "is this binary present in
  AppCompat across multiple firmware captures from the same vendor?"
- ``appcompat_walk_status`` — Rule #33 status reader for the firmware-
  row appcompat_walk_* state machine.
- ``trigger_appcompat_walk`` — 202+poll start of the walker via
  ``asyncio.create_task(run_appcompat_walk_background(firmware_id))``.

**PARSE-ONLY discipline reminder (Rule #36).** The κ.B.C walker is a
pure-Python ``struct`` parser over the SYSTEM hive's AppCompatCache
REG_BINARY value. The walker NEVER invokes any extracted binary,
NEVER spawns subprocesses, NEVER calls Windows APIs. These MCP tools
surface execution-evidence METADATA only — file paths + FILETIME +
anomaly flags. Operators triage paths as DATA.

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
from app.models.windows_appcompat_entries import WindowsAppCompatEntry
from app.services.jsonb_normalizers import (
    _normalize_firmware_appcompat_walk_result,
    _normalize_windows_appcompat_entries_anomaly_flags,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (the 3 AppCompat bits that warrant operator
# review; parse_error is INFORMATIONAL only — excluded from anomaly_only
# filter).
_SUBSTANTIVE_ANOMALY_BITS = (
    "suspicious_path",
    "temp_execution",
    "unusual_extension",
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


def _row_has_substantive_anomaly(record: WindowsAppCompatEntry) -> bool:
    """True iff at least one of the substantive anomaly bits is True."""
    flags = _normalize_windows_appcompat_entries_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: WindowsAppCompatEntry) -> dict:
    """Construct the per-row summary dict surfaced by list / lookup tools."""
    return {
        "id": str(record.id),
        "file_path": record.file_path,
        "insertion_position": record.insertion_position,
        "last_modified_ts": (
            record.last_modified_ts.isoformat()
            if record.last_modified_ts is not None
            else None
        ),
        "anomaly_flags": _normalize_windows_appcompat_entries_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
        "source_hive_path": record.source_hive_path,
        "control_set": record.control_set,
        "parse_error": record.parse_error,
        "entry_size_bytes": record.entry_size_bytes,
    }


# ── list_appcompat_entries ──────────────────────────────────────────────────


async def _handle_list_appcompat_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_appcompat_entries by anomaly / control_set / path
    substring filters."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    anomaly_only = bool(input.get("anomaly_only", False))
    anomaly_bit = input.get("anomaly_bit")  # optional specific bit
    control_set = input.get("control_set")  # optional int
    path_substring = input.get("path_substring")  # optional str
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsAppCompatEntry.firmware_id == firmware_id]
    if control_set is not None:
        base_where.append(
            WindowsAppCompatEntry.control_set == int(control_set)
        )
    if path_substring:
        base_where.append(
            WindowsAppCompatEntry.file_path.ilike(f"%{path_substring}%")
        )

    if anomaly_only or anomaly_bit:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(WindowsAppCompatEntry)
            .where(*base_where)
            .order_by(WindowsAppCompatEntry.insertion_position)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_windows_appcompat_entries_anomaly_flags(
                        r.anomaly_flags
                    ).get(anomaly_bit)
                )
            ]
        elif anomaly_only:
            filtered = [r for r in rows if _row_has_substantive_anomaly(r)]
        else:
            filtered = list(rows)
        total = len(filtered)
        rows = filtered[offset:offset + limit]
    else:
        total_q = select(sa_func.count(WindowsAppCompatEntry.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsAppCompatEntry)
            .where(*base_where)
            .order_by(WindowsAppCompatEntry.insertion_position)
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
        "entries": entries,
        "filters": {
            "anomaly_only": anomaly_only,
            "anomaly_bit": anomaly_bit,
            "control_set": control_set,
            "path_substring": path_substring,
        },
    }
    if total == 0:
        out["message"] = (
            "No AppCompat entries match. The walker may not have run yet "
            "(call trigger_appcompat_walk and poll appcompat_walk_status), "
            "or the firmware may not contain a Windows SYSTEM hive (only "
            "Windows firmware will have AppCompat data), or your filters "
            "may be too narrow. Note: PARSE-ONLY discipline — the walker "
            "NEVER invokes any extracted binary; surfaces execution-"
            "evidence METADATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_appcompat_entry ──────────────────────────────────────────────────


async def _handle_lookup_appcompat_entry(
    input: dict, context: ToolContext
) -> str:
    """Fetch one AppCompat entry by exact file_path OR by substring."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    file_path = input.get("file_path")
    path_substring = input.get("path_substring")
    if not file_path and not path_substring:
        return json.dumps({
            "error": "Either file_path (exact) OR path_substring is required."
        })

    where_clauses = [WindowsAppCompatEntry.firmware_id == firmware_id]
    if file_path:
        where_clauses.append(WindowsAppCompatEntry.file_path == file_path)
    else:
        where_clauses.append(
            WindowsAppCompatEntry.file_path.ilike(f"%{path_substring}%")
        )

    stmt = (
        select(WindowsAppCompatEntry)
        .where(*where_clauses)
        .order_by(WindowsAppCompatEntry.insertion_position)
        .limit(50)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    if not rows:
        return json.dumps({
            "firmware_id": str(firmware_id),
            "file_path": file_path,
            "path_substring": path_substring,
            "match_count": 0,
            "message": (
                f"No AppCompat entries matched "
                f"{'exact path' if file_path else 'substring'} "
                f"{file_path or path_substring!r}. Run trigger_appcompat_walk "
                "first OR verify the path spelling (paths use backslashes "
                "and may include the \\??\\ device prefix)."
            ),
        })

    return _truncate(json.dumps({
        "firmware_id": str(firmware_id),
        "file_path": file_path,
        "path_substring": path_substring,
        "match_count": len(rows),
        "matches": [_row_summary(r) for r in rows],
    }, indent=2))


# ── lookup_appcompat_entry_across_firmwares (Rule #44 cross-firmware) ───────


async def _handle_lookup_appcompat_entry_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a file_path (exact or
    substring), return ALL firmware images in the active project (or
    globally) that have AppCompat entries matching.

    **FORENSIC VALUE** — "is this binary present in AppCompat across
    multiple firmware captures from the same vendor?" Answers:

    (a) Supply-chain consistency — if a vendor-specific binary appears
        in AppCompat across all-and-only-vendor-X firmware, baseline.
        If it suddenly appears in a vendor-X firmware that PREVIOUSLY
        didn't have it, possible compromise.
    (b) Adversary persistence — a binary at ``\\Users\\Public\\``
        appearing in AppCompat across multiple supposedly-independent
        firmware captures = strong cross-firmware compromise signal.
    (c) Build-system fingerprint — vendor build tools / installer
        helpers can legitimately appear across firmwares; cross-
        firmware presence is NOT automatically suspicious, but the
        signal is worth surfacing.

    Wairz competitive differentiator per Rule #44 (cross-firmware
    aggregation surface).

    Returns one row per matching firmware (deduplicated by firmware_id),
    with project + firmware metadata + match count + sample.
    """
    file_path = input.get("file_path")
    path_substring = input.get("path_substring")
    if not file_path and not path_substring:
        return json.dumps({
            "error": (
                "Either file_path (exact match) OR path_substring is "
                "required."
            )
        })

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where_clauses = []
    if file_path:
        where_clauses.append(WindowsAppCompatEntry.file_path == file_path)
    else:
        where_clauses.append(
            WindowsAppCompatEntry.file_path.ilike(f"%{path_substring}%")
        )

    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(WindowsAppCompatEntry, Firmware, Project)
            .join(
                Firmware,
                WindowsAppCompatEntry.firmware_id == Firmware.id,
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsAppCompatEntry, Firmware, Project)
            .join(
                Firmware,
                WindowsAppCompatEntry.firmware_id == Firmware.id,
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    # Group matches by firmware_id.
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
            "sample_entry": _row_summary(entry_row),
        })
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]

    out: dict = {
        "file_path": file_path,
        "path_substring": path_substring,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        filter_desc = []
        if file_path:
            filter_desc.append(f"file_path={file_path!r}")
        if path_substring:
            filter_desc.append(f"path_substring={path_substring!r}")
        out["message"] = (
            f"No firmware in scope '{scope}' has an AppCompat entry "
            f"matching {' AND '.join(filter_desc)}. Run the walker against "
            "more firmwares (call trigger_appcompat_walk on each), then "
            "re-query. PARSE-ONLY: wairz surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["cross_firmware_signal"] = (
            f"AppCompat entries matching the path appear in {len(matches)} "
            "firmware images. Possible signals: (a) shared vendor "
            "build/installer (baseline — verify against vendor docs); "
            "(b) compromised supply chain (single binary across "
            "supposedly-independent firmware); (c) cross-firmware "
            "adversary persistence. Compare sample_entry across matches "
            "and check anomaly_flags for suspicious-path / temp-execution "
            "indicators."
        )
    return _truncate(json.dumps(out, indent=2))


# ── appcompat_walk_status ───────────────────────────────────────────────────


async def _handle_appcompat_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.appcompat_walk_* state machine."""
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
        "status": row.appcompat_walk_status,
        "started_at": (
            row.appcompat_walk_started_at.isoformat()
            if row.appcompat_walk_started_at
            else None
        ),
        "finished_at": (
            row.appcompat_walk_finished_at.isoformat()
            if row.appcompat_walk_finished_at
            else None
        ),
        "error": row.appcompat_walk_error,
        "result": _normalize_firmware_appcompat_walk_result(
            row.appcompat_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_appcompat_walk ──────────────────────────────────────────────────


async def _handle_trigger_appcompat_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling AppCompat walk background runner.
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

    if row.appcompat_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.appcompat_walk_status,
            "started_at": (
                row.appcompat_walk_started_at.isoformat()
                if row.appcompat_walk_started_at
                else None
            ),
            "message": (
                f"appcompat walk already {row.appcompat_walk_status} for "
                f"firmware {firmware_id}. Poll appcompat_walk_status."
            ),
        })

    row.appcompat_walk_status = "queued"
    row.appcompat_walk_started_at = None
    row.appcompat_walk_finished_at = None
    row.appcompat_walk_error = None
    row.appcompat_walk_result = None
    await context.db.flush()

    from app.services.appcompat_walker import run_appcompat_walk_background

    asyncio.create_task(run_appcompat_walk_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "AppCompat walk scheduled. Poll appcompat_walk_status until "
            "status=='completed' to harvest the result. PARSE-ONLY: wairz "
            "NEVER invokes any extracted binary; surfaces execution-"
            "evidence METADATA only (file_path + last_modified FILETIME + "
            "anomaly flags)."
        ),
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_appcompat_tools(registry: ToolRegistry) -> None:
    """Register all Phase κ.B.E Windows AppCompat / Shimcache MCP tools.

    5 tools registered:
      - list_appcompat_entries
      - lookup_appcompat_entry
      - lookup_appcompat_entry_across_firmwares (Rule #44 cross-firmware
        aggregation — wairz competitive differentiator)
      - appcompat_walk_status
      - trigger_appcompat_walk

    PARSE-ONLY discipline reminder: the κ.B.C walker is a pure-Python
    ``struct`` parser over the SYSTEM hive's AppCompatCache REG_BINARY
    value. The walker NEVER invokes any extracted binary; these tools
    surface execution-evidence METADATA only.
    """

    registry.register(
        name="list_appcompat_entries",
        description=(
            "Phase κ.B.E — paginate the per-entry windows_appcompat_entries "
            "table for the active firmware. Surfaces Windows AppCompat / "
            "Shimcache EXECUTION-EVIDENCE metadata extracted from the "
            "SYSTEM hive's "
            "ControlSet00X\\Control\\Session Manager\\AppCompatCache "
            "REG_BINARY value. AppCompat captures EVERY executable the OS "
            "has seen, regardless of whether it ran — forensic gold for "
            "T1106 / T1059 / LotL hunts. **PARSE-ONLY** — wairz NEVER "
            "invokes any extracted binary; surfaces file_path + "
            "last_modified FILETIME + anomaly flags only. Filters: "
            "anomaly_only (3 substantive bits: suspicious_path / "
            "temp_execution / unusual_extension), anomaly_bit (specific "
            "bit), control_set (filter to one ControlSetNNN ordinal), "
            "path_substring (case-insensitive SQL ILIKE). Returns up to "
            "`limit` rows per page (default 50, max 500) ordered by "
            "insertion_position (0 = MRU). Reads the κ.B.A landing zone "
            "populated by κ.B.C's walker."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least one "
                        "substantive anomaly flag (suspicious_path / "
                        "temp_execution / unusual_extension; parse_error "
                        "is INFORMATIONAL only and excluded)."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to entries with this specific anomaly "
                        "bit set (suspicious_path / temp_execution / "
                        "unusual_extension / parse_error)."
                    ),
                },
                "control_set": {
                    "type": "integer",
                    "description": (
                        "Filter to entries from this ControlSetNNN "
                        "ordinal (e.g. 1 for ControlSet001). Default: "
                        "no filter."
                    ),
                    "minimum": 0,
                },
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring filter on file_path "
                        "(SQL ILIKE %substring%). Useful for hunting "
                        "e.g. all entries under \\Users\\Public\\ or "
                        "matching a specific binary name."
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
        handler=_handle_list_appcompat_entries,
    )

    registry.register(
        name="lookup_appcompat_entry",
        description=(
            "Phase κ.B.E — find AppCompat entries by exact file_path OR "
            "substring (case-insensitive SQL ILIKE). Returns up to 50 "
            "matching entries for the active firmware. Use this when you "
            "know the path of an executable and want to confirm whether "
            "the OS has seen it (T1106 / T1059 hunt: 'did the adversary "
            "drop this binary?'). PARSE-ONLY — wairz NEVER invokes any "
            "extracted binary; surfaces METADATA only. Either file_path "
            "(exact match) OR path_substring is required."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": (
                        "Exact file_path to match. Use canonical "
                        "Windows path form (e.g. "
                        "'C:\\Windows\\System32\\cmd.exe' or "
                        "'\\??\\C:\\Users\\Public\\evil.exe')."
                    ),
                },
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring match (SQL ILIKE "
                        "%substring%). Use when exact path is unknown."
                    ),
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_lookup_appcompat_entry,
    )

    registry.register(
        name="lookup_appcompat_entry_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION (Rule #44)** — given a "
            "file_path (exact OR substring), return ALL firmware images "
            "in the active project (default) OR globally that have "
            "AppCompat entries matching. **FORENSIC VALUE** — answer "
            "'is this binary present in AppCompat across multiple "
            "firmware captures from the same vendor?' Possible signals: "
            "(a) shared vendor build/installer (baseline — verify "
            "against vendor docs); (b) compromised supply chain (single "
            "binary across supposedly-independent firmware); (c) cross-"
            "firmware adversary persistence. Wairz competitive "
            "differentiator. PARSE-ONLY: walker surfaces METADATA only. "
            "match_count >= 2 triggers cross_firmware_signal in the "
            "output. scope='project' (default) restricts to the active "
            "project's firmwares; scope='global' searches every project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": (
                        "Exact file_path to match across firmwares. Use "
                        "canonical Windows path form. Either file_path "
                        "OR path_substring is required."
                    ),
                },
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring match. Either "
                        "file_path OR path_substring is required."
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
            "additionalProperties": False,
        },
        handler=_handle_lookup_appcompat_entry_across_firmwares,
    )

    registry.register(
        name="appcompat_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row appcompat_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and "
            "the last-known-result aggregate (hives_scanned, "
            "entries_persisted, entries_capped, parse_errors, "
            "suspicious_path_count, temp_execution_count, "
            "unusual_extension_count, anomaly_total, errors, per_hive)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_appcompat_walk_status,
    )

    registry.register(
        name="trigger_appcompat_walk",
        description=(
            "Trigger the 202+polling Windows AppCompat / Shimcache "
            "execution-evidence walk background runner. Walks every "
            "Windows SYSTEM hive candidate under detection roots (per "
            "Rule #16), opens each via regipy, reads the "
            "ControlSet00X\\Control\\Session Manager\\AppCompatCache\\"
            "AppCompatCache REG_BINARY value, parses it via a "
            "clean-room pure-Python struct-based parser targeting "
            "Win10/11 + Server 2016+ format (older formats degrade-no-"
            "emit), classifies per-entry anomalies, persists per-entry "
            "rows into windows_appcompat_entries (file_path, "
            "insertion_position, last_modified_ts, anomaly_flags, "
            "source_hive_path, control_set, parse_error). Idempotent "
            "(Rule #33 .a) — returns conflict=true if a run is already "
            "queued or running. Schedules run_appcompat_walk_background "
            "via asyncio.create_task. Poll appcompat_walk_status until "
            "status=='completed' to harvest the result. Anomaly "
            "classifier covers 4 bits: suspicious_path (T1106 / T1059 "
            "— executable under \\Users\\Public\\ / \\Windows\\Temp\\ "
            "/ etc), temp_execution (T1036 Masquerading — .tmp/.dat "
            "extension), unusual_extension (T1036.005 — extension "
            "outside {exe,dll,bat,cmd,ps1,vbs,js,scr,com,msi,cpl}), "
            "parse_error (INFORMATIONAL only). **PARSE-ONLY (Rule #36)** "
            "— walker reads SYSTEM hive bytes, unpacks structs, emits "
            "rows; NEVER invokes any extracted binary, NEVER spawns "
            "subprocesses."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_appcompat_walk,
    )
