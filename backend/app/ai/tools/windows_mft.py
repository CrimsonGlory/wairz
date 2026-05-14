"""Windows NTFS $MFT MCP tools — Phase η.A.F.

Surfaces the Phase η.A.C MFT walk results to the MCP layer:

- ``search_mft_records`` — paginate the windows_mft_records table
  for the active firmware by filename prefix, has_ads filter,
  has_timestomp filter, in_use filter, segment range.
- ``mft_walk_status`` — Rule #33 status reader for the firmware-row
  mft_walk_* state machine.
- ``trigger_mft_walk`` — trigger the 202+polling MFT walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).

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
from app.models.windows_mft_record import WindowsMftRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_mft_walk_result,
    _normalize_windows_mft_records_ads_streams,
    _normalize_windows_mft_records_target_metadata,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# ADS-hidden detection threshold — mirrors finding_service
# _MFT_ADS_MEDIUM_CONFIDENCE_BYTES (1 KB excludes Zone.Identifier).
_ADS_BENIGN_TAG_SIZE = 1024


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


def _row_has_hidden_ads(record: WindowsMftRecord) -> bool:
    """Return True iff the record carries at least one named ADS
    stream with size > _ADS_BENIGN_TAG_SIZE (matches the η.A.D
    classifier's ADS-hidden tier-MEDIUM threshold)."""
    ads = _normalize_windows_mft_records_ads_streams(record.ads_streams)
    for stream in ads:
        if not isinstance(stream, dict):
            continue
        try:
            size = int(stream.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if size > _ADS_BENIGN_TAG_SIZE:
            return True
    return False


def _row_has_timestomp(record: WindowsMftRecord) -> bool:
    """Return True iff the record's $SI mtime < $FN mtime (the
    classic single-pair timestomp signal). Both must be non-None."""
    if (
        record.si_last_modification_ns is None
        or record.fn_last_modification_ns is None
    ):
        return False
    return record.si_last_modification_ns < record.fn_last_modification_ns


# ── search_mft_records ───────────────────────────────────────────────────────


async def _handle_search_mft_records(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_mft_records by filename prefix / has_ads /
    has_timestomp / in_use filter / segment range.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    filename_prefix = input.get("filename_prefix")
    has_ads_only = bool(input.get("has_ads_only", False))
    has_timestomp_only = bool(input.get("has_timestomp_only", False))
    in_use_only = bool(input.get("in_use_only", False))
    deleted_only = bool(input.get("deleted_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsMftRecord.firmware_id == firmware_id]
    if filename_prefix:
        base_where.append(
            WindowsMftRecord.filename.like(f"{filename_prefix}%")
        )
    if in_use_only:
        base_where.append(WindowsMftRecord.in_use.is_(True))
    elif deleted_only:
        base_where.append(WindowsMftRecord.in_use.is_(False))

    needs_python_filter = has_ads_only or has_timestomp_only

    if needs_python_filter:
        # Pull SQL-matching rows fully (no offset/limit yet) and
        # post-filter the JSONB / cross-column heuristics in Python.
        page_q = (
            select(WindowsMftRecord)
            .where(*base_where)
            .order_by(
                WindowsMftRecord.fn_creation_ns.desc().nulls_last()
            )
        )
        rows = (await context.db.execute(page_q)).scalars().all()

        def _matches(r: WindowsMftRecord) -> bool:
            if has_ads_only and not _row_has_hidden_ads(r):
                return False
            if has_timestomp_only and not _row_has_timestomp(r):
                return False
            return True

        filtered = [r for r in rows if _matches(r)]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsMftRecord.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsMftRecord)
            .where(*base_where)
            .order_by(
                WindowsMftRecord.fn_creation_ns.desc().nulls_last()
            )
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    records = [
        {
            "id": str(r.id),
            "source_path": r.source_path,
            "segment_number": r.segment_number,
            "in_use": r.in_use,
            "is_directory": r.is_directory,
            "full_path": r.full_path,
            "filename": r.filename,
            "file_size": r.file_size,
            "si_creation_ns": r.si_creation_ns,
            "si_last_modification_ns": r.si_last_modification_ns,
            "si_last_change_ns": r.si_last_change_ns,
            "si_last_access_ns": r.si_last_access_ns,
            "fn_creation_ns": r.fn_creation_ns,
            "fn_last_modification_ns": r.fn_last_modification_ns,
            "fn_last_change_ns": r.fn_last_change_ns,
            "fn_last_access_ns": r.fn_last_access_ns,
            "ads_streams": _normalize_windows_mft_records_ads_streams(
                r.ads_streams
            ),
            "target_metadata": _normalize_windows_mft_records_target_metadata(
                r.target_metadata
            ),
            "image_segment_count": r.image_segment_count,
            "has_hidden_ads": _row_has_hidden_ads(r),
            "has_timestomp": _row_has_timestomp(r),
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "mft_records": records,
        "filters": {
            "filename_prefix": filename_prefix,
            "has_ads_only": has_ads_only,
            "has_timestomp_only": has_timestomp_only,
            "in_use_only": in_use_only,
            "deleted_only": deleted_only,
        },
    }
    if total == 0:
        out["message"] = (
            "No MFT records match. The walker may not have run yet "
            "(call trigger_mft_walk and poll mft_walk_status), or "
            "your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── mft_walk_status ──────────────────────────────────────────────────────────


async def _handle_mft_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.mft_walk_* state machine."""
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
        "status": row.mft_walk_status,
        "started_at": (
            row.mft_walk_started_at.isoformat()
            if row.mft_walk_started_at
            else None
        ),
        "finished_at": (
            row.mft_walk_finished_at.isoformat()
            if row.mft_walk_finished_at
            else None
        ),
        "error": row.mft_walk_error,
        "result": _normalize_firmware_mft_walk_result(
            row.mft_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_mft_walk ─────────────────────────────────────────────────────────


async def _handle_trigger_mft_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling MFT walk background runner.
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

    if row.mft_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.mft_walk_status,
                "started_at": (
                    row.mft_walk_started_at.isoformat()
                    if row.mft_walk_started_at
                    else None
                ),
                "message": (
                    f"MFT walk already {row.mft_walk_status} for "
                    f"firmware {firmware_id}. Poll mft_walk_status."
                ),
            }
        )

    row.mft_walk_status = "queued"
    row.mft_walk_started_at = None
    row.mft_walk_finished_at = None
    row.mft_walk_error = None
    row.mft_walk_result = None
    await context.db.flush()

    from app.services.mft_walker import run_mft_walk_background

    asyncio.create_task(run_mft_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "MFT walk scheduled. Poll mft_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── Registration ─────────────────────────────────────────────────────────────


async def _handle_lookup_mft_record_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a filename (and optional
    full_path), return ALL firmware images in the active project (or
    globally) with a matching $MFT record.

    Rule #44 — same suspicious file or planted artifact appearing across
    multiple captures is the strongest cross-firmware $MFT signal.
    Identity key is the natural tuple (filename, full_path). Omitting
    full_path widens to "every record with this basename" — useful for
    detecting attackers who relocate binaries.

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (total MFT rows matching the filter in that firmware)
    - sample_record (first matching record's summary)
    - any_ads_hidden / any_timestomp flags across the firmware's matches
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    filename = input.get("filename")
    if not filename:
        return json.dumps({"error": "filename is required"})

    full_path = input.get("full_path")
    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [WindowsMftRecord.filename == filename]
    if full_path:
        where.append(WindowsMftRecord.full_path == full_path)

    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(WindowsMftRecord, Firmware, Project)
            .join(Firmware, WindowsMftRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsMftRecord, Firmware, Project)
            .join(Firmware, WindowsMftRecord.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    by_firmware: dict[uuid.UUID, dict] = {}
    for rec, firmware, project in rows:
        slot = by_firmware.get(firmware.id)
        if slot is None:
            slot = {
                "firmware_id": str(firmware.id),
                "project_id": str(project.id),
                "project_name": project.name,
                "original_filename": firmware.original_filename,
                "sha256": firmware.sha256,
                "match_count": 0,
                "sample_record": None,
                "any_ads_hidden": False,
                "any_timestomp": False,
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        if _row_has_hidden_ads(rec):
            slot["any_ads_hidden"] = True
        if _row_has_timestomp(rec):
            slot["any_timestomp"] = True
        if slot["sample_record"] is None:
            slot["sample_record"] = {
                "id": str(rec.id),
                "source_path": rec.source_path,
                "segment_number": rec.segment_number,
                "filename": rec.filename,
                "full_path": rec.full_path,
                "file_size": rec.file_size,
                "is_directory": bool(rec.is_directory),
                "in_use": bool(rec.in_use),
            }

    matches: list[dict] = []
    for slot in by_firmware.values():
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "filename": filename,
        "full_path": full_path,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching MFT records found. Ensure the walker has run on "
            "the relevant firmwares (trigger_mft_walk + poll), and "
            "double-check the filename case (NTFS preserves case)."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


def register_windows_mft_tools(registry: ToolRegistry) -> None:
    """Register all Phase η.A.F Windows NTFS $MFT MCP tools."""

    registry.register(
        name="search_mft_records",
        description=(
            "Phase η.A.F — paginate the per-MFT-segment "
            "windows_mft_records table for the active firmware. Filters: "
            "filename_prefix (case-sensitive — e.g. 'cmd' for cmd.exe), "
            "has_ads_only (filters to records carrying named ADS streams "
            "larger than 1 KB — excludes benign Zone.Identifier MOTW tags; "
            "captures T1564.004 NTFS-attribute hidden content), "
            "has_timestomp_only (filters to records whose $SI mtime is "
            "older than $FN mtime — T1070.006 anti-forensics signal), "
            "in_use_only / deleted_only (filter by FILE_RECORD_SEGMENT_IN_USE "
            "flag — deleted records hold recovered metadata for files an "
            "attacker tried to wipe). Returns up to `limit` rows per page "
            "(default 50, max 500) with total_count for navigation. Reads "
            "the η.A.A landing zone populated by η.A.C's walker. Order: "
            "fn_creation_ns DESC (forensic-timeline UX). Indexes "
            "(firmware_id, fn_creation_ns) + (firmware_id, filename) + "
            "(firmware_id, source_path, segment_number) cover the common "
            "filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filename_prefix": {
                    "type": "string",
                    "description": (
                        "Case-sensitive prefix match on filename "
                        "(e.g. 'cmd' for cmd.exe)."
                    ),
                },
                "has_ads_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only records carrying at "
                        "least one named ADS stream larger than 1 KB "
                        "(excludes benign Zone.Identifier MOTW tags)."
                    ),
                },
                "has_timestomp_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only records whose $SI mtime "
                        "is older than $FN mtime "
                        "(T1070.006 timestomp signal)."
                    ),
                },
                "in_use_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only allocated records "
                        "(FILE_RECORD_SEGMENT_IN_USE flag set)."
                    ),
                },
                "deleted_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only deleted records "
                        "(FILE_RECORD_SEGMENT_IN_USE flag clear)."
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
                    "description": "Page offset for pagination (default 0).",
                    "minimum": 0,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_search_mft_records,
    )

    registry.register(
        name="mft_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "mft_walk_* state machine. Returns status (idle / queued / "
            "running / completed / failed), started_at, finished_at, "
            "error, and the last-known-result aggregate "
            "(images_scanned, records_walked, records_persisted, "
            "ads_streams_seen, timestomp_candidates, "
            "ads_hidden_candidates, errors, per_image)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_mft_walk_status,
    )

    registry.register(
        name="lookup_mft_record_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a filename (and "
            "optional exact full_path), return ALL firmware images in the "
            "active project (or globally, with scope='global') that "
            "contain a matching MFT record. Identity key is the natural "
            "tuple (filename, full_path). Returns one entry per matching "
            "firmware with match_count, sample_record, "
            "any_ads_hidden / any_timestomp flags across the firmware's "
            "matches, and supply_chain_signal=True when match_count >= 2 "
            "firmwares (same suspicious file or planted artifact across "
            "captures — the strongest cross-firmware $MFT signal)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": (
                        "Required. Exact filename (basename) to look up "
                        "(e.g. 'cmd.exe', 'mimikatz.exe', "
                        "'svchost.exe')."
                    ),
                },
                "full_path": {
                    "type": "string",
                    "description": (
                        "Optional. Exact full path within the volume "
                        "(e.g. 'Windows\\\\System32\\\\cmd.exe'). Omit "
                        "to match every record with the given filename "
                        "regardless of path — useful for planted-file "
                        "detection where attackers relocate binaries."
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
            "required": ["filename"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_mft_record_across_firmwares,
    )

    registry.register(
        name="trigger_mft_walk",
        description=(
            "Trigger the 202+polling Windows NTFS $MFT walk background "
            "runner. Walks raw NTFS image candidates (.dd / .raw / .ntfs "
            "/ .img / .bin) under each detection root, iterates every "
            "MFT segment via dissect.ntfs.NTFS(fh).mft.segments() "
            "(yielding both allocated and deleted-but-unreaped records), "
            "persists per-record metadata + named ADS roster into "
            "windows_mft_records, and stamps an aggregate JSONB result "
            "onto mft_walk_result. Idempotent (Rule #33 .a) — returns "
            "conflict=true with the in-flight status if a run is "
            "already queued or running. Schedules "
            "run_mft_walk_background via asyncio.create_task. Poll "
            "mft_walk_status until status=='completed' to harvest the "
            "result. Auto-emits windows_mft_ads_hidden_content + "
            "windows_mft_timestomping Finding rows for records matching "
            "the η.A.D classifier thresholds."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_mft_walk,
    )
