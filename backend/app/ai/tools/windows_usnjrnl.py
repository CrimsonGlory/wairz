"""Windows NTFS $UsnJrnl:$J change-log MCP tools — Phase κ.E.E.

Surfaces the Phase κ.E.C $UsnJrnl:$J walk results to the MCP layer:

- ``list_usnjrnl_entries`` — paginate the windows_usnjrnl_entries
  table for the active firmware with filters (reason_flag_filter,
  parent_ref, file_name_substring).
- ``lookup_usnjrnl_entry`` — substring against file_name.
- ``lookup_usnjrnl_entry_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (Rule #44 — wairz competitive differentiator). Given
  a file_name substring, return all firmware images that have that
  artefact name in their windows_usnjrnl_entries table.
- ``usnjrnl_walk_status`` — Rule #33 status reader for the firmware-
  row usnjrnl_walk_* state machine.
- ``trigger_usnjrnl_walk`` — 202+poll start of the walker via
  ``asyncio.create_task(run_usnjrnl_walk_background(firmware_id))``.

**Rule #36 NO-EXECUTE REMINDER.** The κ.E.C walker is a pure-Python
``dissect.ntfs`` parser over $UsnJrnl:$J ADS bytes. The walker NEVER
invokes any binary referenced by the journal entries, NEVER mounts
the image, NEVER shells out to ntfs-3g / mount / losetup. These MCP
tools surface file-system change METADATA only — file_name +
reason_flags + timestamp + MFT references + USN identifier.

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
from app.models.windows_usnjrnl_entries import WindowsUsnJrnlEntry
from app.services.jsonb_normalizers import (
    _normalize_firmware_usnjrnl_walk_result,
    _normalize_windows_usnjrnl_reason_flags,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Reason flag names a caller may filter against. These match the
# canonical USN_REASON_* dictionary produced by the walker's bit decoder.
_REASON_FLAG_NAMES: tuple[str, ...] = (
    "data_overwrite",
    "data_extend",
    "data_truncation",
    "named_data_overwrite",
    "named_data_extend",
    "named_data_truncation",
    "file_create",
    "file_delete",
    "ea_change",
    "security_change",
    "rename_old_name",
    "rename_new_name",
    "indexable_change",
    "basic_info_change",
    "hard_link_change",
    "compression_change",
    "encryption_change",
    "object_id_change",
    "reparse_point_change",
    "stream_change",
    "transacted_change",
    "integrity_change",
    "close",
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


def _row_summary(record: WindowsUsnJrnlEntry) -> dict:
    """Construct the per-row summary dict surfaced by list / lookup tools.

    Rule #36: surfaces METADATA columns only. No binary execution; the
    filename / parent_ref / reason flags are operator triage data.
    """
    return {
        "id": str(record.id),
        "usn": record.usn,
        "file_name": record.file_name,
        "file_reference_number": record.file_reference_number,
        "parent_file_reference_number": record.parent_file_reference_number,
        "source_file_path": record.source_file_path,
        "reason_flags": _normalize_windows_usnjrnl_reason_flags(
            record.reason_flags
        ),
        "source_info": record.source_info,
        "security_id": record.security_id,
        "timestamp": (
            record.timestamp.isoformat()
            if record.timestamp is not None
            else None
        ),
        "parse_error": record.parse_error,
        "schema_version": record.schema_version,
    }


# ── list_usnjrnl_entries ────────────────────────────────────────────────────


async def _handle_list_usnjrnl_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_usnjrnl_entries with reason / filename filters."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    reason_flag_filter = input.get("reason_flag_filter")
    parent_ref = input.get("parent_file_reference_number")
    file_name_substring = input.get("file_name_substring")
    limit = int(input.get("limit", 100))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsUsnJrnlEntry.firmware_id == firmware_id]
    if parent_ref is not None:
        try:
            base_where.append(
                WindowsUsnJrnlEntry.parent_file_reference_number
                == int(parent_ref)
            )
        except (TypeError, ValueError):
            return json.dumps({
                "error": "parent_file_reference_number must be an integer"
            })
    if file_name_substring:
        base_where.append(
            WindowsUsnJrnlEntry.file_name.ilike(f"%{file_name_substring}%")
        )

    if reason_flag_filter:
        if reason_flag_filter not in _REASON_FLAG_NAMES:
            return json.dumps({
                "error": (
                    f"reason_flag_filter {reason_flag_filter!r} is not a "
                    f"recognised bit; valid names: {list(_REASON_FLAG_NAMES)}"
                )
            })
        # JSONB filter — Python-side after SQL pre-filter.
        page_q = (
            select(WindowsUsnJrnlEntry)
            .where(*base_where)
            .order_by(WindowsUsnJrnlEntry.usn)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        filtered = [
            r for r in rows
            if (
                _normalize_windows_usnjrnl_reason_flags(
                    r.reason_flags
                ).get(reason_flag_filter)
            )
        ]
        total = len(filtered)
        rows = filtered[offset:offset + limit]
    else:
        total_q = select(sa_func.count(WindowsUsnJrnlEntry.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsUsnJrnlEntry)
            .where(*base_where)
            .order_by(WindowsUsnJrnlEntry.usn)
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
            "reason_flag_filter": reason_flag_filter,
            "parent_file_reference_number": parent_ref,
            "file_name_substring": file_name_substring,
        },
    }
    if total == 0:
        out["message"] = (
            "No USN journal entries match. The walker may not have run "
            "yet (call trigger_usnjrnl_walk and poll usnjrnl_walk_status), "
            "or the firmware may not contain a Windows NTFS volume with "
            "USN journaling enabled, or your filters may be too narrow. "
            "Note: Rule #36 — the walker NEVER invokes any binary "
            "referenced by the journal; surfaces METADATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_usnjrnl_entry ────────────────────────────────────────────────────


async def _handle_lookup_usnjrnl_entry(
    input: dict, context: ToolContext
) -> str:
    """Fetch USN entries by substring match against file_name."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    query = input.get("query")
    if not query:
        return json.dumps({
            "error": (
                "A query string is required. Matches substring against "
                "file_name (case-insensitive)."
            )
        })

    stmt = (
        select(WindowsUsnJrnlEntry)
        .where(
            WindowsUsnJrnlEntry.firmware_id == firmware_id,
            WindowsUsnJrnlEntry.file_name.ilike(f"%{query}%"),
        )
        .order_by(WindowsUsnJrnlEntry.usn)
        .limit(100)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    if not rows:
        return json.dumps({
            "firmware_id": str(firmware_id),
            "query": query,
            "match_count": 0,
            "message": (
                f"No USN journal entries matched {query!r}. Run "
                "trigger_usnjrnl_walk first OR check the filename "
                "(case-insensitive substring match)."
            ),
        })

    return _truncate(json.dumps({
        "firmware_id": str(firmware_id),
        "query": query,
        "match_count": len(rows),
        "matches": [_row_summary(r) for r in rows],
    }, indent=2))


# ── lookup_usnjrnl_entry_across_firmwares (Rule #44 cross-firmware) ─────────


async def _handle_lookup_usnjrnl_entry_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a file_name substring,
    return ALL firmware images in the active project (default) or
    globally that have USN journal entries with that filename.

    **FORENSIC VALUE** — answers "did this filename get created or
    deleted across multiple firmware captures?" Possible signals:

    (a) Cross-firmware adversary tooling — same payload filename (e.g.
        ``mimikatz.exe``, ``stage.dll``) appearing in multiple firmwares
        suggests shared TTPs or a campaign-level toolkit.
    (b) Wide-deployment artefact — a filename present across many vendor
        firmwares may be either legitimate (shared OEM artefact) OR a
        supply-chain compromise indicator.
    (c) Persistence-evidence — confirming the same artefact deletion
        timestamp across two firmware captures may suggest coordinated
        action.

    Wairz competitive differentiator per Rule #44 (cross-firmware
    aggregation surface).

    Returns one row per matching firmware (deduplicated by firmware_id),
    with project + firmware metadata + match count + sample entry.

    Rule #36 reminder: wairz NEVER invokes any referenced binary;
    surfaces METADATA only.
    """
    query = input.get("query")
    if not query:
        return json.dumps({
            "error": (
                "A query string is required. Matches substring against "
                "file_name (case-insensitive)."
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

    where_clauses = [WindowsUsnJrnlEntry.file_name.ilike(f"%{query}%")]

    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(WindowsUsnJrnlEntry, Firmware, Project)
            .join(Firmware, WindowsUsnJrnlEntry.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsUsnJrnlEntry, Firmware, Project)
            .join(Firmware, WindowsUsnJrnlEntry.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
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
            "sample_entry": _row_summary(entry_row),
        })
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]

    out: dict = {
        "query": query,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a USN journal entry "
            f"matching {query!r}. Run the walker against more firmwares "
            "(call trigger_usnjrnl_walk on each), then re-query. Rule "
            "#36: wairz surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["cross_firmware_signal"] = (
            f"USN journal entries matching {query!r} appear in "
            f"{len(matches)} firmware images. Possible signals: "
            "(a) cross-firmware adversary tooling — same payload "
            "filename across multiple firmwares suggests campaign-level "
            "TTPs or shared toolkit; (b) supply-chain artefact — "
            "wide-deployment filename across vendor firmwares; (c) "
            "persistence evidence — coordinated artefact create/delete "
            "across captures. Compare sample_entry across matches + "
            "correlate with windows_mft_records (η.A) and "
            "windows_appcompat_entries (κ.B) for cross-walker "
            "confirmation. Rule #36: wairz NEVER invokes any binary."
        )
    return _truncate(json.dumps(out, indent=2))


# ── usnjrnl_walk_status ─────────────────────────────────────────────────────


async def _handle_usnjrnl_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.usnjrnl_walk_* state machine."""
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
        "status": row.usnjrnl_walk_status,
        "started_at": (
            row.usnjrnl_walk_started_at.isoformat()
            if row.usnjrnl_walk_started_at
            else None
        ),
        "finished_at": (
            row.usnjrnl_walk_finished_at.isoformat()
            if row.usnjrnl_walk_finished_at
            else None
        ),
        "error": row.usnjrnl_walk_error,
        "result": _normalize_firmware_usnjrnl_walk_result(
            row.usnjrnl_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_usnjrnl_walk ────────────────────────────────────────────────────


async def _handle_trigger_usnjrnl_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling $UsnJrnl:$J walk background runner.
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

    if row.usnjrnl_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.usnjrnl_walk_status,
            "started_at": (
                row.usnjrnl_walk_started_at.isoformat()
                if row.usnjrnl_walk_started_at
                else None
            ),
            "message": (
                f"usnjrnl walk already {row.usnjrnl_walk_status} for "
                f"firmware {firmware_id}. Poll usnjrnl_walk_status."
            ),
        })

    row.usnjrnl_walk_status = "queued"
    row.usnjrnl_walk_started_at = None
    row.usnjrnl_walk_finished_at = None
    row.usnjrnl_walk_error = None
    row.usnjrnl_walk_result = None
    await context.db.flush()

    from app.services.usnjrnl_walker import run_usnjrnl_walk_background

    asyncio.create_task(run_usnjrnl_walk_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "USN journal walk scheduled. Poll usnjrnl_walk_status until "
            "status=='completed' to harvest the result. Rule #36: "
            "walker is a pure-Python dissect.ntfs parser over "
            "$Extend/$UsnJrnl:$J ADS bytes. NEVER invokes any binary "
            "referenced by the journal entries, NEVER mounts the image. "
            "Anomaly classifier covers 3 sources: "
            "windows_usnjrnl_file_deletion (MEDIUM — FILE_DELETE on "
            "executable extension), "
            "windows_usnjrnl_temp_create_delete_pair (HIGH — same file "
            "CREATE+DELETE within 5 min under a temp/staging dir), "
            "windows_usnjrnl_renamed_executable (MEDIUM — rename pair "
            "with extension change)."
        ),
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_usnjrnl_tools(registry: ToolRegistry) -> None:
    """Register all Phase κ.E.E Windows USN journal MCP tools.

    5 tools registered:
      - list_usnjrnl_entries
      - lookup_usnjrnl_entry
      - lookup_usnjrnl_entry_across_firmwares (Rule #44 cross-firmware
        aggregation — wairz competitive differentiator)
      - usnjrnl_walk_status
      - trigger_usnjrnl_walk

    Rule #36 REMINDER: the κ.E.C walker is a pure-Python ``dissect.ntfs``
    parser over $UsnJrnl:$J ADS bytes. The walker NEVER invokes any
    binary referenced by the journal entries; these tools surface
    METADATA only.
    """

    registry.register(
        name="list_usnjrnl_entries",
        description=(
            "Phase κ.E.E — paginate the per-record "
            "windows_usnjrnl_entries table for the active firmware. "
            "Surfaces Windows NTFS USN Journal (\\$UsnJrnl:\\$J) "
            "change-log records extracted from the $Extend/$UsnJrnl "
            "alternate data stream of NTFS volumes. USN journal "
            "records every file-system change (create / delete / "
            "rename / modify) — forensic gold for T1070.004 (File "
            "Deletion) anti-forensics evidence. **Rule #36** — wairz "
            "NEVER invokes any binary referenced by the journal, "
            "NEVER mounts the image. Filters: reason_flag_filter "
            "(canonical USN_REASON_* bit name — e.g. 'file_delete' / "
            "'file_create' / 'rename_old_name'), parent_file_reference_"
            "number (MFT parent ref — join target for 'all events "
            "under this directory'), file_name_substring (SQL ILIKE). "
            "Returns up to `limit` rows per page (default 100, max 500). "
            "Reads the κ.E.A landing zone populated by κ.E.C's walker."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "reason_flag_filter": {
                    "type": "string",
                    "description": (
                        "Filter to entries with this specific USN_REASON_* "
                        "bit set. Valid: file_create, file_delete, "
                        "rename_old_name, rename_new_name, data_overwrite, "
                        "data_extend, data_truncation, "
                        "named_data_overwrite, named_data_extend, "
                        "named_data_truncation, ea_change, "
                        "security_change, indexable_change, "
                        "basic_info_change, hard_link_change, "
                        "compression_change, encryption_change, "
                        "object_id_change, reparse_point_change, "
                        "stream_change, transacted_change, "
                        "integrity_change, close."
                    ),
                },
                "parent_file_reference_number": {
                    "type": "integer",
                    "description": (
                        "Filter to entries whose parent MFT reference "
                        "matches. Useful for 'show me all events under "
                        "this directory' queries."
                    ),
                },
                "file_name_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring filter on file_name "
                        "(SQL ILIKE %substring%)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Page size (default 100, min 1, max 500)."
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
        handler=_handle_list_usnjrnl_entries,
    )

    registry.register(
        name="lookup_usnjrnl_entry",
        description=(
            "Phase κ.E.E — find USN journal entries by substring match "
            "against file_name (case-insensitive SQL ILIKE). Returns up "
            "to 100 matching entries for the active firmware. Use this "
            "when you know an artefact filename (e.g. 'mimikatz.exe', "
            "'stage.dll') and want to surface the corresponding "
            "change-log records. Rule #36 — wairz NEVER invokes any "
            "referenced binary; surfaces METADATA only. The query "
            "parameter is required."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring match (case-insensitive) against "
                        "file_name. E.g. 'mimikatz' returns all "
                        "$J events for any filename containing 'mimikatz'."
                    ),
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_usnjrnl_entry,
    )

    registry.register(
        name="lookup_usnjrnl_entry_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION (Rule #44)** — given a "
            "file_name substring, return ALL firmware images in the "
            "active project (default) OR globally that have USN journal "
            "entries with that filename. **FORENSIC VALUE** — answer "
            "'did this artefact appear across multiple firmware "
            "captures?' Possible signals: (a) cross-firmware adversary "
            "tooling (same payload filename across firmwares suggests "
            "campaign-level TTPs); (b) supply-chain artefact "
            "(wide-deployment filename across vendor firmwares); (c) "
            "persistence evidence (coordinated create/delete across "
            "captures). Wairz competitive differentiator. Rule #36: "
            "wairz NEVER invokes any binary; surfaces METADATA only. "
            "match_count >= 2 triggers cross_firmware_signal in the "
            "output. scope='project' (default) restricts to the active "
            "project's firmwares; scope='global' searches every project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring match (case-insensitive) against "
                        "file_name across firmwares."
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
        handler=_handle_lookup_usnjrnl_entry_across_firmwares,
    )

    registry.register(
        name="usnjrnl_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row usnjrnl_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and "
            "the last-known-result aggregate (images_scanned, "
            "records_walked, records_persisted, records_capped, "
            "parse_errors, file_deletion_count, "
            "temp_create_delete_pair_count, renamed_executable_count, "
            "anomaly_total, errors, per_image)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_usnjrnl_walk_status,
    )

    registry.register(
        name="trigger_usnjrnl_walk",
        description=(
            "Trigger the 202+polling Windows NTFS \\$UsnJrnl:\\$J "
            "change-log walk background runner. Walks every detection "
            "root (per Rule #16), locates raw NTFS image candidates "
            "via the η.A MFT-walker precedent (boot-sector magic "
            "check), opens each via dissect.ntfs.NTFS, reads the "
            "\\$Extend/\\$UsnJrnl:\\$J ADS via "
            "dissect.ntfs.usnjrnl.UsnJrnl.records(), decodes per-record "
            "USN_REASON_* bitmask, persists per-record rows into "
            "windows_usnjrnl_entries (usn + MFT references + file_name "
            "+ reason_flags + source_info + security_id + timestamp). "
            "Idempotent (Rule #33 .a) — returns conflict=true if a run "
            "is already queued or running. Schedules "
            "run_usnjrnl_walk_background via asyncio.create_task. Poll "
            "usnjrnl_walk_status until status=='completed' to harvest "
            "the result. Anomaly classifier covers 3 sources: "
            "windows_usnjrnl_file_deletion (MEDIUM — T1070.004 — "
            "FILE_DELETE on executable extension), "
            "windows_usnjrnl_temp_create_delete_pair (HIGH — T1059 + "
            "T1070.004 chained — same file CREATE+DELETE within 5 min "
            "under temp / AppData\\\\Local\\\\Temp / ProgramData / "
            "Public\\\\Downloads), windows_usnjrnl_renamed_executable "
            "(MEDIUM — T1036 Masquerading — rename pair with extension "
            "change). **Rule #36** — walker reads NTFS bytes, decodes "
            "records, emits rows; NEVER invokes any binary referenced "
            "by the journal entries, NEVER mounts the image, NEVER "
            "shells out to ntfs-3g / mount / losetup."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_usnjrnl_walk,
    )
