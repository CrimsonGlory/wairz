"""Windows Boot Configuration Data (BCD) MCP tools — Phase θ.A.F.

Surfaces the Phase θ.A.C BCD walk results to the MCP layer:

- ``search_bcd_entries`` — paginate the windows_bcd_entries table
  for the active firmware by GUID prefix / description filter /
  testsigning filter / suspicious-path filter.
- ``bcd_walk_status`` — Rule #33 status reader for the firmware-row
  bcd_walk_* state machine.
- ``trigger_bcd_walk`` — trigger the 202+polling BCD walk
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
from app.models.windows_bcd_entry import WindowsBcdEntry
from app.services.jsonb_normalizers import (
    _normalize_firmware_bcd_walk_result,
    _normalize_windows_bcd_entries_anomaly_flags,
    _normalize_windows_bcd_entries_custom_elements,
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
        + "\n\n[output truncated to 30KB — narrow filters or use offset+limit "
        "to paginate]"
    )


def _row_has_anomaly(record: WindowsBcdEntry) -> bool:
    """Return True iff any of the 5 substantive anomaly flags is True
    (excludes is_default_boot, which is forensic context not a
    suspicion signal)."""
    flags = _normalize_windows_bcd_entries_anomaly_flags(record.anomaly_flags)
    return any(
        bool(flags.get(k))
        for k in (
            "suspicious_path",
            "non_microsoft_description",
            "testsigning_enabled",
            "no_integrity_checks",
            "nx_disabled",
        )
    )


# ── search_bcd_entries ───────────────────────────────────────────────────────


async def _handle_search_bcd_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_bcd_entries by GUID prefix / description /
    testsigning_only / anomaly_only filters.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    guid_prefix = input.get("guid_prefix")
    description_substring = input.get("description_substring")
    testsigning_only = bool(input.get("testsigning_only", False))
    suspicious_path_only = bool(input.get("suspicious_path_only", False))
    anomaly_only = bool(input.get("anomaly_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsBcdEntry.firmware_id == firmware_id]
    if guid_prefix:
        base_where.append(
            WindowsBcdEntry.object_guid.like(f"{guid_prefix}%")
        )
    if description_substring:
        base_where.append(
            WindowsBcdEntry.description.like(f"%{description_substring}%")
        )
    if testsigning_only:
        base_where.append(WindowsBcdEntry.testsigning.is_(True))

    needs_python_filter = suspicious_path_only or anomaly_only

    if needs_python_filter:
        # Pull SQL-matching rows fully (no offset/limit yet) and
        # post-filter the JSONB shape in Python.
        page_q = (
            select(WindowsBcdEntry)
            .where(*base_where)
            .order_by(WindowsBcdEntry.object_guid)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

        def _matches(r: WindowsBcdEntry) -> bool:
            flags = _normalize_windows_bcd_entries_anomaly_flags(
                r.anomaly_flags
            )
            if suspicious_path_only and not bool(
                flags.get("suspicious_path")
            ):
                return False
            if anomaly_only and not _row_has_anomaly(r):
                return False
            return True

        filtered = [r for r in rows if _matches(r)]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsBcdEntry.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsBcdEntry)
            .where(*base_where)
            .order_by(WindowsBcdEntry.object_guid)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    entries = [
        {
            "id": str(r.id),
            "source_path": r.source_path,
            "object_guid": r.object_guid,
            "object_type": r.object_type,
            "description": r.description,
            "image_path": r.image_path,
            "gpt_partition_guid": r.gpt_partition_guid,
            "gpt_disk_guid": r.gpt_disk_guid,
            "testsigning": r.testsigning,
            "no_integrity_checks": r.no_integrity_checks,
            "nx_policy": r.nx_policy,
            "anomaly_flags": _normalize_windows_bcd_entries_anomaly_flags(
                r.anomaly_flags
            ),
            "custom_elements": _normalize_windows_bcd_entries_custom_elements(
                r.custom_elements
            ),
            "last_modified_ns": r.last_modified_ns,
            "has_anomaly": _row_has_anomaly(r),
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "bcd_entries": entries,
        "filters": {
            "guid_prefix": guid_prefix,
            "description_substring": description_substring,
            "testsigning_only": testsigning_only,
            "suspicious_path_only": suspicious_path_only,
            "anomaly_only": anomaly_only,
        },
    }
    if total == 0:
        out["message"] = (
            "No BCD entries match. The walker may not have run yet "
            "(call trigger_bcd_walk and poll bcd_walk_status), or "
            "your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── bcd_walk_status ──────────────────────────────────────────────────────────


async def _handle_bcd_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.bcd_walk_* state machine."""
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
        "status": row.bcd_walk_status,
        "started_at": (
            row.bcd_walk_started_at.isoformat()
            if row.bcd_walk_started_at
            else None
        ),
        "finished_at": (
            row.bcd_walk_finished_at.isoformat()
            if row.bcd_walk_finished_at
            else None
        ),
        "error": row.bcd_walk_error,
        "result": _normalize_firmware_bcd_walk_result(
            row.bcd_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_bcd_walk ─────────────────────────────────────────────────────────


async def _handle_trigger_bcd_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling BCD walk background runner.
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

    if row.bcd_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.bcd_walk_status,
                "started_at": (
                    row.bcd_walk_started_at.isoformat()
                    if row.bcd_walk_started_at
                    else None
                ),
                "message": (
                    f"BCD walk already {row.bcd_walk_status} for "
                    f"firmware {firmware_id}. Poll bcd_walk_status."
                ),
            }
        )

    row.bcd_walk_status = "queued"
    row.bcd_walk_started_at = None
    row.bcd_walk_finished_at = None
    row.bcd_walk_error = None
    row.bcd_walk_result = None
    await context.db.flush()

    from app.services.bcd_walker import run_bcd_walk_background

    asyncio.create_task(run_bcd_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "BCD walk scheduled. Poll bcd_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_bcd_entry_across_firmwares (Rule #44) ────────────────────────────


async def _handle_lookup_bcd_entry_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given an object_guid, return ALL
    firmware images in the active project (or globally) with a matching
    BCD entry.

    Rule #44 — BCD object GUIDs are STABLE across normal Windows
    installs ({bootmgr} = {9dea862c-...}, {bootloader} = {466f5a88-...},
    etc.), so common-GUID matches are baseline. The signal is stronger
    when an UNUSUAL GUID (a campaign-specific or planted entry)
    surfaces across multiple firmwares OR when testsigning /
    no_integrity_checks anomaly flags propagate across captures.

    Identity key is object_guid. Returns one row per matching firmware
    with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - match_count (matching BCD rows in that firmware)
    - sample_entry (first matching entry's summary)
    - any_testsigning / any_no_integrity_checks flags across matches
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    object_guid = input.get("object_guid")
    if not object_guid:
        return json.dumps({"error": "object_guid is required"})

    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [WindowsBcdEntry.object_guid == object_guid]

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
            select(WindowsBcdEntry, Firmware, Project)
            .join(Firmware, WindowsBcdEntry.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsBcdEntry, Firmware, Project)
            .join(Firmware, WindowsBcdEntry.firmware_id == Firmware.id)
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
                "sample_entry": None,
                "any_testsigning": False,
                "any_no_integrity_checks": False,
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        if rec.testsigning:
            slot["any_testsigning"] = True
        if rec.no_integrity_checks:
            slot["any_no_integrity_checks"] = True
        if slot["sample_entry"] is None:
            slot["sample_entry"] = {
                "id": str(rec.id),
                "source_path": rec.source_path,
                "object_guid": rec.object_guid,
                "object_type": rec.object_type,
                "description": rec.description,
                "image_path": rec.image_path,
                "testsigning": rec.testsigning,
                "no_integrity_checks": rec.no_integrity_checks,
            }

    matches: list[dict] = []
    for slot in by_firmware.values():
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "object_guid": object_guid,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching BCD entries found. Ensure the walker has run "
            "on the relevant firmwares (trigger_bcd_walk + poll). BCD "
            "GUIDs include the braces (e.g. '{9dea862c-5cdd-4e70-acc1-"
            "f32b344d4795}' for {bootmgr})."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_bcd_tools(registry: ToolRegistry) -> None:
    """Register all Phase θ.A.F Windows BCD MCP tools."""

    registry.register(
        name="search_bcd_entries",
        description=(
            "Phase θ.A.F — paginate the per-BCD-object "
            "windows_bcd_entries table for the active firmware. Filters: "
            "guid_prefix (case-insensitive substring match on object_guid — "
            "well-known prefixes like '{9dea862c-' for {bootmgr}, "
            "'{a5a30fa2-' for {globalsettings}), "
            "description_substring (substring match — e.g. 'Bootkit' or "
            "'Ubuntu'), "
            "testsigning_only (filters to entries with TestSigning=True "
            "via BCD element 0x16000010 — the canonical bootkit-precursor "
            "and BYOVD-enabler signal), "
            "suspicious_path_only (filters to entries whose image_path "
            "lies outside Microsoft-vetted prefixes Windows\\\\, Boot\\\\, "
            "EFI\\\\Microsoft\\\\ — the T1542.003 Pre-OS Boot: Bootkit "
            "signal), "
            "anomaly_only (filters to entries with at least one of: "
            "suspicious_path, non_microsoft_description, testsigning_enabled, "
            "no_integrity_checks, nx_disabled). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "with total_count for navigation. Reads the θ.A.A landing "
            "zone populated by θ.A.C's walker. Order: object_guid "
            "ASC (stable per-store triage UX). Indexes "
            "(firmware_id,) + (firmware_id, object_guid) + "
            "(firmware_id, testsigning) cover the common filter shapes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "guid_prefix": {
                    "type": "string",
                    "description": (
                        "Case-insensitive prefix match on object_guid "
                        "(e.g. '{9dea862c-' for {bootmgr})."
                    ),
                },
                "description_substring": {
                    "type": "string",
                    "description": (
                        "Substring match on description (e.g. 'Bootkit' "
                        "or 'Ubuntu')."
                    ),
                },
                "testsigning_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with "
                        "TestSigning=True (BCD element 0x16000010)."
                    ),
                },
                "suspicious_path_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries whose image_path "
                        "lies outside Microsoft-vetted prefixes "
                        "(T1542.003 Pre-OS Boot: Bootkit signal)."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least "
                        "one anomaly_flag raised (suspicious_path / "
                        "non_microsoft_description / testsigning_enabled "
                        "/ no_integrity_checks / nx_disabled)."
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
        handler=_handle_search_bcd_entries,
    )

    registry.register(
        name="bcd_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "bcd_walk_* state machine. Returns status (idle / queued / "
            "running / completed / failed), started_at, finished_at, "
            "error, and the last-known-result aggregate "
            "(stores_scanned, entries_walked, entries_persisted, "
            "testsigning_count, suspicious_path_count, "
            "non_microsoft_description_count, anomaly_total, errors, "
            "per_store)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_bcd_walk_status,
    )

    registry.register(
        name="trigger_bcd_walk",
        description=(
            "Trigger the 202+polling Windows BCD store walk background "
            "runner. Walks for files named 'BCD' (case-insensitive) "
            "under each detection root, iterates every \\Objects\\{guid} "
            "subkey via regipy's RegistryHive with BCD_HIVE_TYPE, "
            "persists per-entry metadata + GPT device GUIDs + security "
            "policy flags + custom elements roster + anomaly flag "
            "aggregate into windows_bcd_entries, and stamps an aggregate "
            "JSONB result onto bcd_walk_result. Idempotent (Rule #33 "
            ".a) — returns conflict=true with the in-flight status if "
            "a run is already queued or running. Schedules "
            "run_bcd_walk_background via asyncio.create_task. Poll "
            "bcd_walk_status until status=='completed' to harvest the "
            "result. Auto-emits windows_bcd_suspicious_path + "
            "windows_bcd_testsigning_enabled Finding rows for entries "
            "matching the θ.A.D classifier thresholds (T1542.003 "
            "Pre-OS Boot: Bootkit + BYOVD-precursor detection)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_bcd_walk,
    )

    registry.register(
        name="lookup_bcd_entry_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given an object_guid, "
            "return ALL firmware images in the active project (or "
            "globally, with scope='global') that contain a matching BCD "
            "entry. Identity key is object_guid. BCD GUIDs are STABLE "
            "across normal Windows installs ({bootmgr} = {9dea862c-...}), "
            "so common-GUID matches are baseline; unusual / "
            "campaign-specific GUIDs surfacing across captures are the "
            "strong signal. Returns one entry per matching firmware "
            "with match_count, sample_entry, "
            "any_testsigning / any_no_integrity_checks flags, and "
            "supply_chain_signal=True when match_count >= 2 firmwares."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "object_guid": {
                    "type": "string",
                    "description": (
                        "Required. BCD object GUID with braces (e.g. "
                        "'{9dea862c-5cdd-4e70-acc1-f32b344d4795}' for "
                        "{bootmgr}, '{466f5a88-0af2-4f76-9038-095b170dc"
                        "21c}' for {bootloader})."
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
            "required": ["object_guid"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_bcd_entry_across_firmwares,
    )
