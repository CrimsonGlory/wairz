"""Windows EFS DDF/DRF metadata MCP tools — Phase ι.D.E (SECOND ι WINDOWS MCP).

Surfaces the Phase ι.D.C EFS walk results to the MCP layer:

- ``list_efs_encrypted_files`` — paginate the windows_efs_encrypted_files
  table for the active firmware with filters (anomaly_only, anomaly_bit,
  ddf_user_count, drf_recovery_agent_count).
- ``lookup_efs_encrypted_file`` — fetch one EFS file row by ID with full
  DDF user list + DRF recovery agent list + anomaly_flags.
- ``search_efs_by_sid`` — find every encrypted file where a given SID
  appears in DDF or DRF (insider-threat hunt — "what does user X have
  access to decrypt?").
- ``trigger_efs_walk`` — trigger the 202+polling EFS walk background
  runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``efs_walk_status`` — Rule #33 status reader for the firmware-row
  efs_walk_* state machine.
- ``lookup_efs_recovery_agent_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (wairz competitive differentiator). Given a recovery
  agent SID OR cert thumbprint, return all firmware images that have
  that recovery agent in any encrypted file's DRF. **Strong supply-chain
  / insider-threat indicator** — if the SAME recovery agent thumbprint
  appears across multiple supposedly-independent customer firmware
  images, that's a forensic alarm. THIRD application of the cross-
  firmware aggregation pattern at walker-stream time (ι.B precedent
  Rule-of-One; ι.C Rule-of-Two; this Rule-of-Three).

PARSE-ONLY discipline reminder (Rule #36 + Rule #36 EXTENSION): the
walker that populates this table NEVER decrypts the FEK, NEVER invokes
DPAPI. These MCP tools surface METADATA only — SID + cert thumbprint +
friendly name. Operators triage as DATA.

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select, func as sa_func

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.windows_efs_encrypted_files import WindowsEfsEncryptedFile
from app.services.jsonb_normalizers import (
    _normalize_firmware_efs_walk_result,
    _normalize_windows_efs_encrypted_files_anomaly_flags,
    _normalize_windows_efs_encrypted_files_ddf_users,
    _normalize_windows_efs_encrypted_files_drf_recovery_agents,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (the 4 EFS bits that warrant operator review;
# cert_thumbprint_anomaly + parse_error are INFORMATIONAL only — excluded
# from the anomaly_only filter to match the ι.C precedent of excluding
# non-actionable bits).
_SUBSTANTIVE_ANOMALY_BITS = (
    "orphaned_drf",
    "unusual_recovery_agent",
    "multiple_ddf_users",
    "large_drf",
    "domain_admin_in_ddf",
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


def _row_has_substantive_anomaly(record: WindowsEfsEncryptedFile) -> bool:
    """True iff at least one of the substantive anomaly bits is True."""
    flags = _normalize_windows_efs_encrypted_files_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _strip_schema_sentinel(items: list[dict]) -> list[dict]:
    """Filter out the schema_version sentinel dict from list-typed JSONB."""
    return [
        item for item in items
        if isinstance(item, dict) and "schema_version" not in item
    ]


def _row_summary(record: WindowsEfsEncryptedFile) -> dict:
    """Construct the per-row summary dict surfaced by list / search /
    lookup tools."""
    return {
        "id": str(record.id),
        "file_path": record.file_path,
        "file_size": record.file_size,
        "mft_record_number": record.mft_record_number,
        "efs_attribute_size": record.efs_attribute_size,
        "ddf_user_count": record.ddf_user_count,
        "drf_recovery_agent_count": record.drf_recovery_agent_count,
        "anomaly_flags": _normalize_windows_efs_encrypted_files_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
        "parse_error": record.parse_error,
    }


def _row_detail(record: WindowsEfsEncryptedFile) -> dict:
    """Like _row_summary but also includes full DDF/DRF lists."""
    out = _row_summary(record)
    ddf_raw = _normalize_windows_efs_encrypted_files_ddf_users(
        record.ddf_users
    )
    drf_raw = _normalize_windows_efs_encrypted_files_drf_recovery_agents(
        record.drf_recovery_agents
    )
    out["ddf_users"] = _strip_schema_sentinel(ddf_raw)
    out["drf_recovery_agents"] = _strip_schema_sentinel(drf_raw)
    return out


# ── list_efs_encrypted_files ────────────────────────────────────────────────


async def _handle_list_efs_encrypted_files(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_efs_encrypted_files by anomaly / count filters."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    anomaly_only = bool(input.get("anomaly_only", False))
    anomaly_bit = input.get("anomaly_bit")  # optional specific bit
    min_ddf_users = input.get("min_ddf_users")
    min_drf_agents = input.get("min_drf_agents")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsEfsEncryptedFile.firmware_id == firmware_id]
    if min_ddf_users is not None:
        base_where.append(
            WindowsEfsEncryptedFile.ddf_user_count >= int(min_ddf_users)
        )
    if min_drf_agents is not None:
        base_where.append(
            WindowsEfsEncryptedFile.drf_recovery_agent_count
            >= int(min_drf_agents)
        )

    if anomaly_only or anomaly_bit:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(WindowsEfsEncryptedFile)
            .where(*base_where)
            .order_by(WindowsEfsEncryptedFile.mft_record_number)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_windows_efs_encrypted_files_anomaly_flags(
                        r.anomaly_flags
                    ).get(anomaly_bit)
                )
            ]
        elif anomaly_only:
            filtered = [r for r in rows if _row_has_substantive_anomaly(r)]
        else:
            filtered = list(rows)
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsEfsEncryptedFile.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsEfsEncryptedFile)
            .where(*base_where)
            .order_by(WindowsEfsEncryptedFile.mft_record_number)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    efs_files = [_row_summary(r) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "efs_files": efs_files,
        "filters": {
            "anomaly_only": anomaly_only,
            "anomaly_bit": anomaly_bit,
            "min_ddf_users": min_ddf_users,
            "min_drf_agents": min_drf_agents,
        },
    }
    if total == 0:
        out["message"] = (
            "No EFS-encrypted files match. The walker may not have run yet "
            "(call trigger_efs_walk and poll efs_walk_status), or the "
            "firmware may not contain any EFS-encrypted files (EFS is "
            "rarely used outside corporate domains), or your filters may "
            "be too narrow. Note: PARSE-ONLY discipline — wairz NEVER "
            "decrypts the FEK; this surface is METADATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_efs_encrypted_file ───────────────────────────────────────────────


async def _handle_lookup_efs_encrypted_file(
    input: dict, context: ToolContext
) -> str:
    """Fetch one EFS file by ID with full DDF/DRF detail."""
    file_id_raw = input.get("efs_row_id")
    if not file_id_raw:
        return json.dumps({"error": "efs_row_id is required"})
    try:
        file_id = uuid.UUID(str(file_id_raw))
    except (TypeError, ValueError):
        return json.dumps(
            {"error": f"efs_row_id {file_id_raw!r} is not a valid UUID"}
        )

    row = (
        await context.db.execute(
            select(WindowsEfsEncryptedFile).where(
                WindowsEfsEncryptedFile.id == file_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"efs file {file_id} not found"})

    return _truncate(json.dumps(_row_detail(row), indent=2, default=str))


# ── search_efs_by_sid ───────────────────────────────────────────────────────


async def _handle_search_efs_by_sid(
    input: dict, context: ToolContext
) -> str:
    """Find every EFS file where a given SID appears in DDF or DRF.

    Insider-threat hunt: "what does user X have access to decrypt?"
    "what recovery agent has access to file Y?"
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    sid = input.get("sid")
    if not sid:
        return json.dumps({"error": "sid is required"})

    sid_trim = sid.strip()
    if not sid_trim.startswith("S-"):
        return json.dumps({
            "error": (
                f"sid {sid!r} doesn't look like a Windows SID "
                "(expected canonical S-R-IA-SA1-SA2-... form)"
            )
        })

    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))
    location_filter = input.get("location", "any")  # ddf | drf | any
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0
    if location_filter not in ("ddf", "drf", "any"):
        location_filter = "any"

    # Read all rows for the firmware, then Python-side filter (the SID
    # lookup requires JSONB containment which is awkward in async SA
    # cross-dialect; bounded by per-firmware EFS file count, typically
    # 0-100).
    base_q = (
        select(WindowsEfsEncryptedFile)
        .where(WindowsEfsEncryptedFile.firmware_id == firmware_id)
        .order_by(WindowsEfsEncryptedFile.mft_record_number)
    )
    rows = (await context.db.execute(base_q)).scalars().all()

    matches: list[dict] = []
    for row in rows:
        ddf_users = _strip_schema_sentinel(
            _normalize_windows_efs_encrypted_files_ddf_users(row.ddf_users)
        )
        drf_agents = _strip_schema_sentinel(
            _normalize_windows_efs_encrypted_files_drf_recovery_agents(
                row.drf_recovery_agents
            )
        )

        match_locations: list[str] = []
        if location_filter in ("ddf", "any"):
            for user in ddf_users:
                if user.get("sid") == sid_trim:
                    match_locations.append("ddf")
                    break
        if location_filter in ("drf", "any"):
            for agent in drf_agents:
                if agent.get("sid") == sid_trim:
                    match_locations.append("drf")
                    break

        if match_locations:
            summary = _row_summary(row)
            summary["match_locations"] = match_locations
            matches.append(summary)

    total = len(matches)
    page = matches[offset : offset + limit]

    out = {
        "firmware_id": str(firmware_id),
        "sid": sid_trim,
        "location_filter": location_filter,
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "matches": page,
    }
    if total == 0:
        out["message"] = (
            f"No EFS files have SID {sid_trim!r} in their "
            f"{location_filter} list. Either the walker hasn't run "
            "(call trigger_efs_walk), the SID isn't present in any "
            "EFS file on the firmware, or the SID format doesn't match "
            "exactly (case-sensitive, canonical S-R-IA-SA1-SA2-... form)."
        )
    return _truncate(json.dumps(out, indent=2))


# ── efs_walk_status ─────────────────────────────────────────────────────────


async def _handle_efs_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.efs_walk_* state machine."""
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
        "status": row.efs_walk_status,
        "started_at": (
            row.efs_walk_started_at.isoformat()
            if row.efs_walk_started_at
            else None
        ),
        "finished_at": (
            row.efs_walk_finished_at.isoformat()
            if row.efs_walk_finished_at
            else None
        ),
        "error": row.efs_walk_error,
        "result": _normalize_firmware_efs_walk_result(row.efs_walk_result),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_efs_walk ────────────────────────────────────────────────────────


async def _handle_trigger_efs_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling EFS walk background runner.
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

    if row.efs_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.efs_walk_status,
                "started_at": (
                    row.efs_walk_started_at.isoformat()
                    if row.efs_walk_started_at
                    else None
                ),
                "message": (
                    f"efs walk already {row.efs_walk_status} for "
                    f"firmware {firmware_id}. Poll efs_walk_status."
                ),
            }
        )

    row.efs_walk_status = "queued"
    row.efs_walk_started_at = None
    row.efs_walk_finished_at = None
    row.efs_walk_error = None
    row.efs_walk_result = None
    await context.db.flush()

    from app.services.efs_walker import run_efs_walk_background

    asyncio.create_task(run_efs_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "efs walk scheduled. Poll efs_walk_status until "
                "status=='completed' to harvest the result. PARSE-ONLY "
                "discipline: wairz NEVER decrypts the FEK; surfaces "
                "METADATA only (DDF SID + cert thumbprint + friendly "
                "name + DRF same)."
            ),
        }
    )


# ── lookup_efs_recovery_agent_across_firmwares (CROSS-FIRMWARE AGG) ─────────


async def _handle_lookup_efs_recovery_agent_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a recovery agent SID OR
    cert thumbprint, return ALL firmware images in the active project
    (or globally, if requested) that have that recovery agent in any
    encrypted file's DRF.

    **STRONG SUPPLY-CHAIN / INSIDER-THREAT INDICATOR** — if the SAME
    recovery agent thumbprint appears across multiple supposedly-
    independent customer firmware images, the implication is either:

    (a) A shared backdoor recovery key — adversary or vendor-with-
        privileged-access has the SAME EFS recovery agent across the
        product line, can decrypt files on every shipped device.
    (b) A vendor-default recovery agent that was never re-keyed —
        misconfiguration risk (every device with this default recovery
        is interchangeable from an EFS-trust perspective).
    (c) Legitimate corporate IT pre-staging — the operator's IT
        department deploys a uniform EFS recovery policy across all
        managed devices (legitimate, but worth verifying).

    THIRD application of the cross-firmware aggregation pattern at
    walker-stream time (ι.B precedent → ι.C → THIS ι.D — Rule-of-Three).
    Wairz competitive differentiator.

    Filters by either SID OR cert thumbprint (at least one is required).
    Returns one row per matching firmware (deduplicated by firmware_id),
    with project + firmware metadata + match count + sample.
    """
    sid_filter = input.get("sid")
    thumbprint_filter = input.get("cert_thumbprint")
    if not sid_filter and not thumbprint_filter:
        return json.dumps({
            "error": (
                "Either sid OR cert_thumbprint is required (or both — "
                "they're AND-combined when both are present)."
            )
        })

    if sid_filter:
        sid_filter = sid_filter.strip()
        if not sid_filter.startswith("S-"):
            return json.dumps({
                "error": (
                    f"sid {sid_filter!r} doesn't look like a Windows SID "
                    "(expected S-R-IA-SA1-SA2-... form)"
                )
            })
    if thumbprint_filter:
        thumbprint_filter = thumbprint_filter.strip().lower()

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    # Read all rows in scope, then Python-side filter on DRF (since
    # JSONB containment is dialect-specific and the DRF list is small
    # per row).
    if scope == "project":
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(WindowsEfsEncryptedFile, Firmware, Project)
            .join(Firmware, WindowsEfsEncryptedFile.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsEfsEncryptedFile, Firmware, Project)
            .join(Firmware, WindowsEfsEncryptedFile.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    # Group matches by firmware_id.
    per_firmware: dict[uuid.UUID, dict] = {}

    for efs_row, firmware, project in rows:
        drf_agents = _strip_schema_sentinel(
            _normalize_windows_efs_encrypted_files_drf_recovery_agents(
                efs_row.drf_recovery_agents
            )
        )
        match_in_this_row = False
        sample_agent = None
        for agent in drf_agents:
            sid_match = (
                sid_filter is None or agent.get("sid") == sid_filter
            )
            thumb_match = (
                thumbprint_filter is None
                or (agent.get("cert_thumbprint") or "").lower()
                == thumbprint_filter
            )
            if sid_match and thumb_match and (
                sid_filter or thumbprint_filter
            ):
                match_in_this_row = True
                sample_agent = agent
                break

        if not match_in_this_row:
            continue

        bucket = per_firmware.setdefault(firmware.id, {
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "match_count": 0,
            "sample_recovery_agent": sample_agent,
            "sample_file_path": efs_row.file_path,
        })
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]

    out = {
        "sid": sid_filter,
        "cert_thumbprint": thumbprint_filter,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        filter_desc = []
        if sid_filter:
            filter_desc.append(f"sid={sid_filter!r}")
        if thumbprint_filter:
            filter_desc.append(f"cert_thumbprint={thumbprint_filter!r}")
        out["message"] = (
            f"No firmware in scope '{scope}' has a recovery agent matching "
            + " AND ".join(filter_desc)
            + ". Run the walker against more firmwares (call "
            "trigger_efs_walk on each), then re-query. PARSE-ONLY: wairz "
            "surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["supply_chain_signal"] = (
            f"Recovery agent matching "
            + (
                f"SID {sid_filter!r}" if sid_filter else ""
            )
            + (
                " AND " if sid_filter and thumbprint_filter else ""
            )
            + (
                f"cert_thumbprint {thumbprint_filter!r}"
                if thumbprint_filter
                else ""
            )
            + f" appears across {len(matches)} firmware images — possible "
            "shared backdoor recovery key (HIGH), un-rekeyed vendor "
            "default (MEDIUM), or legitimate corporate IT pre-staging "
            "(verify with operator's documented EFS recovery policy). "
            "Compare sample_recovery_agent + sample_file_path across "
            "matches to characterise."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_efs_tools(registry: ToolRegistry) -> None:
    """Register all Phase ι.D.E Windows EFS DDF/DRF MCP tools. SECOND ι
    Windows-side MCP tool category in wairz (ι.A.E + ι.B.E Linux walkers;
    ι.C.E ETW — FIRST ι Windows). Brings MCP tool count 269 → 275.

    Includes the THIRD application of the cross-firmware aggregation
    pattern at walker-stream time
    (``lookup_efs_recovery_agent_across_firmwares``) — wairz competitive
    differentiator surfacing supply-chain / insider-threat signal across
    firmware captures. Rule-of-One (ι.B) → Rule-of-Two (ι.C) → Rule-of-
    Three (this stream — pattern is durable beyond debate).

    PARSE-ONLY discipline reminder: all tools surface METADATA only;
    the walker NEVER decrypts the FEK, NEVER invokes DPAPI.
    """

    registry.register(
        name="list_efs_encrypted_files",
        description=(
            "Phase ι.D.E — paginate the per-file windows_efs_encrypted_files "
            "table for the active firmware. Surfaces Windows EFS DDF/DRF "
            "metadata extracted from $EFS LOGGED_UTILITY_STREAM attribute "
            "(type 0x100) on MFT records with the FILE_ATTRIBUTE_ENCRYPTED "
            "bit (0x4000) set. SECOND ι Windows MCP tool category (ι.A + "
            "ι.B Linux; ι.C ETW). **PARSE-ONLY DISCIPLINE** — wairz NEVER "
            "decrypts the FEK, NEVER invokes Windows DPAPI; this table "
            "surfaces METADATA only (DDF user SID + cert thumbprint + "
            "friendly name; DRF recovery agent SID + cert thumbprint + "
            "friendly name). Persona-E EFS relevance: SafeBreach 2020 PoC "
            "abused EFS for ransomware-like behaviour (encrypt victim "
            "files with attacker-controlled DDF — T1486); insider-stealth "
            "patterns via unauthorized SID in DDF (T1564.001); recovery-"
            "agent supply-chain signal when SAME thumbprint appears across "
            "multiple firmwares. Filters: anomaly_only (4 substantive "
            "bits: orphaned_drf / unusual_recovery_agent / "
            "multiple_ddf_users / large_drf / domain_admin_in_ddf), "
            "anomaly_bit (specific bit), min_ddf_users / min_drf_agents "
            "(count thresholds). Returns up to `limit` rows per page "
            "(default 50, max 500) ordered by MFT record number. Reads "
            "the ι.D.A landing zone populated by ι.D.C's walker."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only files with at least one "
                        "substantive anomaly flag raised (excludes "
                        "informational-only cert_thumbprint_anomaly + "
                        "parse_error bits)."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to files with this specific anomaly bit "
                        "set (orphaned_drf / unusual_recovery_agent / "
                        "multiple_ddf_users / large_drf / "
                        "domain_admin_in_ddf / cert_thumbprint_anomaly "
                        "/ parse_error)."
                    ),
                },
                "min_ddf_users": {
                    "type": "integer",
                    "description": (
                        "Filter to files with DDF user count >= this "
                        "value (shared-decryption candidate threshold)."
                    ),
                    "minimum": 0,
                },
                "min_drf_agents": {
                    "type": "integer",
                    "description": (
                        "Filter to files with DRF recovery agent count "
                        ">= this value (unusual-DRF-configuration "
                        "threshold)."
                    ),
                    "minimum": 0,
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
        handler=_handle_list_efs_encrypted_files,
    )

    registry.register(
        name="lookup_efs_encrypted_file",
        description=(
            "Phase ι.D.E — fetch one EFS-encrypted file row by its UUID "
            "with full detail (incl. full DDF user list + DRF recovery "
            "agent list — each entry has SID + cert thumbprint + "
            "friendly name; PARSE-ONLY discipline — wairz NEVER decrypts "
            "the FEK). Use the efs_row_id returned by "
            "list_efs_encrypted_files or search_efs_by_sid."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "efs_row_id": {
                    "type": "string",
                    "description": (
                        "UUID of the WindowsEfsEncryptedFile row. Get "
                        "from list_efs_encrypted_files or search_efs_by_sid."
                    ),
                },
            },
            "required": ["efs_row_id"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_efs_encrypted_file,
    )

    registry.register(
        name="search_efs_by_sid",
        description=(
            "Phase ι.D.E — find every EFS-encrypted file where a given "
            "Windows SID appears in DDF or DRF. **Insider-threat hunt**: "
            "'what does user X have access to decrypt?' OR 'which files "
            "does recovery agent Y have authority over?'. Filters by "
            "location='ddf' (only files where SID is in the DDF user "
            "list), location='drf' (only files where SID is in the DRF "
            "recovery agent list), OR location='any' (default — match "
            "either list). SID must be canonical 'S-R-IA-SA1-SA2-...' "
            "form (case-sensitive exact match). Returns up to `limit` "
            "matching rows per page (default 50, max 500), each row "
            "carries match_locations array indicating which list(s) "
            "matched. PARSE-ONLY discipline — surfaces METADATA only."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sid": {
                    "type": "string",
                    "description": (
                        "Windows SID to search for (canonical S-R-IA-"
                        "SA1-SA2-... form, e.g. "
                        "'S-1-5-21-1234567890-9876543210-1111111111-1001')."
                    ),
                },
                "location": {
                    "type": "string",
                    "enum": ["ddf", "drf", "any"],
                    "description": (
                        "Where to look for the SID: 'ddf' (file owners / "
                        "shared decryption), 'drf' (recovery agents), or "
                        "'any' (default — both lists)."
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
            "required": ["sid"],
            "additionalProperties": False,
        },
        handler=_handle_search_efs_by_sid,
    )

    registry.register(
        name="efs_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row efs_walk_* state "
            "machine. Returns status (idle / queued / running / completed "
            "/ failed), started_at, finished_at, error, and the last-known-"
            "result aggregate (images_scanned, files_walked, "
            "encrypted_files_found, encrypted_files_persisted, files_capped, "
            "parse_errors, orphaned_drf_count, unusual_recovery_agent_count, "
            "multiple_ddf_users_count, large_drf_count, "
            "domain_admin_in_ddf_count, anomaly_total, errors, per_image)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_efs_walk_status,
    )

    registry.register(
        name="trigger_efs_walk",
        description=(
            "Trigger the 202+polling Windows EFS DDF/DRF metadata walk "
            "background runner. Walks every raw NTFS image candidate "
            "under detection roots (reuses η.A's walk_raw_ntfs_images "
            "plumbing), iterates the MFT for files with "
            "FILE_ATTRIBUTE_ENCRYPTED (0x4000) on $STANDARD_INFORMATION, "
            "reads the file's $EFS LOGGED_UTILITY_STREAM attribute "
            "(type 0x100), parses the DDF (Data Decryption Field) + DRF "
            "(Data Recovery Field) entries via a custom MS-EFSR-compliant "
            "parser (PARSE-ONLY — wairz NEVER decrypts the RSA-encrypted "
            "FEK, NEVER invokes Windows DPAPI). Persists per-file rows "
            "into windows_efs_encrypted_files (file_path, file_size, "
            "mft_record_number, efs_attribute_size, ddf_user_count, "
            "drf_recovery_agent_count, ddf_users JSONB, "
            "drf_recovery_agents JSONB, anomaly_flags). Idempotent (Rule "
            "#33 .a) — returns conflict=true if a run is already queued "
            "or running. Schedules run_efs_walk_background via "
            "asyncio.create_task. Poll efs_walk_status until "
            "status=='completed' to harvest the result. Anomaly classifier "
            "covers 7 bits: orphaned_drf (T1486 ransomware-via-EFS / "
            "T1564.001 insider stealth), unusual_recovery_agent (T1564.001 "
            "supporting — non-standard recovery SID), multiple_ddf_users "
            "(shared decryption), large_drf (>2 recovery agents — unusual "
            "config), cert_thumbprint_anomaly (informational), "
            "domain_admin_in_ddf (T1078.002 — admin RID in DDF), "
            "parse_error (informational). SECOND ι Windows walker in "
            "wairz's portfolio (ι.C was ETW)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_efs_walk,
    )

    registry.register(
        name="lookup_efs_recovery_agent_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION** — given a recovery agent SID "
            "OR cert thumbprint (or both — AND-combined), return ALL "
            "firmware images in the active project (default) OR globally "
            "that have that recovery agent in any encrypted file's DRF. "
            "**STRONG SUPPLY-CHAIN / INSIDER-THREAT INDICATOR** — if the "
            "same recovery agent thumbprint appears across multiple "
            "supposedly-independent customer firmware images, that's a "
            "forensic alarm: (a) shared backdoor recovery key — adversary "
            "or privileged vendor has same EFS recovery agent across the "
            "product line; (b) un-rekeyed vendor default — every device "
            "is interchangeable from an EFS-trust perspective; (c) "
            "legitimate corporate IT pre-staging — uniform EFS recovery "
            "policy across managed devices (verify with operator). THIRD "
            "application of the cross-firmware aggregation pattern at "
            "walker-stream time (ι.B systemd → ι.C ETL → THIS ι.D EFS — "
            "Rule-of-One → Rule-of-Two → Rule-of-Three; pattern is "
            "durable). Wairz competitive differentiator — no other "
            "forensic tool surfaces this signal. PARSE-ONLY discipline — "
            "wairz NEVER decrypts the FEK; surfaces METADATA only. "
            "match_count >= 2 triggers supply_chain_signal in the output. "
            "scope='project' (default) restricts to the active project's "
            "firmwares; scope='global' searches every project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sid": {
                    "type": "string",
                    "description": (
                        "Recovery agent SID to match (canonical "
                        "S-R-IA-SA1-SA2-... form). Either sid OR "
                        "cert_thumbprint is required."
                    ),
                },
                "cert_thumbprint": {
                    "type": "string",
                    "description": (
                        "Recovery agent cert thumbprint to match "
                        "(40-char lowercase SHA-1 hex). Either sid OR "
                        "cert_thumbprint is required. Both can be "
                        "supplied to AND-combine."
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
        handler=_handle_lookup_efs_recovery_agent_across_firmwares,
    )
