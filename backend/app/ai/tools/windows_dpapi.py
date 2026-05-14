"""Windows DPAPI master-key PARSE-ONLY METADATA MCP tools — Phase κ.D.E.

Surfaces the Phase κ.D.C DPAPI master-key walk results to the MCP layer:

- ``list_dpapi_master_keys`` — paginate the windows_dpapi_master_keys
  table for the active firmware with filters (anomaly_only, anomaly_bit,
  creator_sid, master_key_guid).
- ``lookup_dpapi_master_key`` — fetch one row by exact GUID match OR
  substring against master_key_guid / creator_sid.
- ``lookup_dpapi_master_key_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (Rule #44 — wairz competitive differentiator). Given a
  GUID or creator_sid substring, return all firmware images that have
  that master-key in their windows_dpapi_master_keys table.
- ``dpapi_walk_status`` — Rule #33 status reader for the firmware-row
  dpapi_walk_* state machine.
- ``trigger_dpapi_walk`` — 202+poll start of the walker via
  ``asyncio.create_task(run_dpapi_walk_background(firmware_id))``.

**PARSE-ONLY DISCIPLINE REMINDER (Rule #36 + Rule #45 — Rule-of-Two
DURABLE BEYOND DEBATE).** The κ.D.C walker is a pure-Python ``struct``
parser over DPAPI master-key files' headers + body preambles. The
walker NEVER decrypts master keys, NEVER invokes ``CryptUnprotectData``,
NEVER imports cryptographic decryption modules, NEVER records the salt
bytes (only the salt SIZE constant). These MCP tools surface METADATA
only — master_key_guid + creator_sid + flags + iteration counts +
per-section sizes + last_modified_ts + anomaly_flags. Operators triage
as DATA.

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
from app.models.windows_dpapi_master_keys import WindowsDpapiMasterKey
from app.services.jsonb_normalizers import (
    _normalize_firmware_dpapi_walk_result,
    _normalize_windows_dpapi_anomaly_flags,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (the 3 DPAPI bits that warrant operator
# review; parse_error is INFORMATIONAL only — excluded from anomaly_only
# filter).
_SUBSTANTIVE_ANOMALY_BITS = (
    "orphaned_masterkey",
    "admin_creator_sid",
    "large_masterkey",
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


def _row_has_substantive_anomaly(record: WindowsDpapiMasterKey) -> bool:
    """True iff at least one of the substantive anomaly bits is True."""
    flags = _normalize_windows_dpapi_anomaly_flags(record.anomaly_flags)
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: WindowsDpapiMasterKey) -> dict:
    """Construct the per-row summary dict surfaced by list / lookup tools.

    PARSE-ONLY: only METADATA columns are surfaced. No salt bytes,
    no decrypted payload — those don't even exist in the ORM.
    """
    return {
        "id": str(record.id),
        "master_key_guid": record.master_key_guid,
        "creator_sid": record.creator_sid,
        "source_file_path": record.source_file_path,
        "flags": record.flags,
        "hmac_iterations": record.hmac_iterations,
        "salt_size": record.salt_size,
        "master_key_size": record.master_key_size,
        "backup_key_size": record.backup_key_size,
        "cred_hist_size": record.cred_hist_size,
        "domain_key_size": record.domain_key_size,
        "file_size_bytes": record.file_size_bytes,
        "last_modified_ts": (
            record.last_modified_ts.isoformat()
            if record.last_modified_ts is not None
            else None
        ),
        "anomaly_flags": _normalize_windows_dpapi_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
        "parse_error": record.parse_error,
        "schema_version": record.schema_version,
    }


# ── list_dpapi_master_keys ──────────────────────────────────────────────────


async def _handle_list_dpapi_master_keys(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_dpapi_master_keys by anomaly / SID / GUID filters."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    anomaly_only = bool(input.get("anomaly_only", False))
    anomaly_bit = input.get("anomaly_bit")  # optional specific bit
    creator_sid = input.get("creator_sid")  # optional SID filter
    guid_substring = input.get("guid_substring")  # optional GUID substring
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsDpapiMasterKey.firmware_id == firmware_id]
    if creator_sid:
        base_where.append(
            WindowsDpapiMasterKey.creator_sid == creator_sid
        )
    if guid_substring:
        base_where.append(
            WindowsDpapiMasterKey.master_key_guid.ilike(
                f"%{guid_substring}%"
            )
        )

    if anomaly_only or anomaly_bit:
        # Python-side filtering after SQL since anomaly_flags is JSONB.
        page_q = (
            select(WindowsDpapiMasterKey)
            .where(*base_where)
            .order_by(WindowsDpapiMasterKey.created_at)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_windows_dpapi_anomaly_flags(
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
        total_q = select(sa_func.count(WindowsDpapiMasterKey.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsDpapiMasterKey)
            .where(*base_where)
            .order_by(WindowsDpapiMasterKey.created_at)
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
            "creator_sid": creator_sid,
            "guid_substring": guid_substring,
        },
    }
    if total == 0:
        out["message"] = (
            "No DPAPI master-key entries match. The walker may not "
            "have run yet (call trigger_dpapi_walk and poll "
            "dpapi_walk_status), or the firmware may not contain a "
            "Windows installation with DPAPI artifacts (only Windows "
            "firmware with Users/<user>/AppData/Roaming/Microsoft/"
            "Protect/<sid>/<guid> paths populated), or your filters "
            "may be too narrow. Note: PARSE-ONLY discipline — the "
            "walker NEVER decrypts master keys; surfaces METADATA only."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_dpapi_master_key ──────────────────────────────────────────────────


async def _handle_lookup_dpapi_master_key(
    input: dict, context: ToolContext
) -> str:
    """Fetch DPAPI master-key entries by substring match against
    master_key_guid OR creator_sid."""
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
                "master_key_guid OR creator_sid (case-insensitive)."
            )
        })

    where_clauses = [
        WindowsDpapiMasterKey.firmware_id == firmware_id,
    ]
    # Match either GUID OR creator SID substring.
    from sqlalchemy import or_
    where_clauses.append(
        or_(
            WindowsDpapiMasterKey.master_key_guid.ilike(f"%{query}%"),
            WindowsDpapiMasterKey.creator_sid.ilike(f"%{query}%"),
        )
    )

    stmt = (
        select(WindowsDpapiMasterKey)
        .where(*where_clauses)
        .order_by(WindowsDpapiMasterKey.created_at)
        .limit(50)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    if not rows:
        return json.dumps({
            "firmware_id": str(firmware_id),
            "query": query,
            "match_count": 0,
            "message": (
                f"No DPAPI master-key entries matched query "
                f"{query!r}. Run trigger_dpapi_walk first OR verify "
                "the query (GUIDs use lowercase hex with dashes; "
                "SIDs use canonical S-1-5-21-... form)."
            ),
        })

    return _truncate(json.dumps({
        "firmware_id": str(firmware_id),
        "query": query,
        "match_count": len(rows),
        "matches": [_row_summary(r) for r in rows],
    }, indent=2))


# ── lookup_dpapi_master_key_across_firmwares (Rule #44 cross-firmware) ──────


async def _handle_lookup_dpapi_master_key_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a master_key_guid OR
    creator_sid substring, return ALL firmware images in the active
    project (or globally) that have DPAPI master-key entries matching.

    **FORENSIC VALUE** — "does this master-key GUID OR creator SID
    appear across multiple firmware captures?" Answers:

    (a) Cross-firmware key reuse — the SAME master_key_guid appearing
        in multiple firmwares is a strong baseline-deviation signal.
        Master-key GUIDs are randomly generated; collisions are
        cryptographically improbable. Reuse implies either firmware
        clone (legitimate — same image deployed multiple times) or
        attacker-replicated key stash across compromised hosts.
    (b) Insider-threat user fingerprint — a creator_sid appearing
        across supposedly-independent vendor firmwares may indicate
        the same insider operator OR a shared service account.
    (c) Backdoor key supply-chain — orphaned + admin-creator keys
        present in multiple firmwares from the same vendor may
        indicate a backdoor pre-staging pipeline.

    Wairz competitive differentiator per Rule #44 (cross-firmware
    aggregation surface).

    Returns one row per matching firmware (deduplicated by firmware_id),
    with project + firmware metadata + match count + sample entry.

    PARSE-ONLY DISCIPLINE REMINDER: wairz NEVER decrypts master keys
    OR uses them to access protected data. Surfaces METADATA only.
    """
    query = input.get("query")
    if not query:
        return json.dumps({
            "error": (
                "A query string is required. Matches substring against "
                "master_key_guid OR creator_sid (case-insensitive)."
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

    from sqlalchemy import or_

    where_clauses = [
        or_(
            WindowsDpapiMasterKey.master_key_guid.ilike(f"%{query}%"),
            WindowsDpapiMasterKey.creator_sid.ilike(f"%{query}%"),
        )
    ]

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
            select(WindowsDpapiMasterKey, Firmware, Project)
            .join(
                Firmware,
                WindowsDpapiMasterKey.firmware_id == Firmware.id,
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(WindowsDpapiMasterKey, Firmware, Project)
            .join(
                Firmware,
                WindowsDpapiMasterKey.firmware_id == Firmware.id,
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
        "query": query,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            f"No firmware in scope '{scope}' has a DPAPI master-key "
            f"matching {query!r}. Run the walker against more firmwares "
            "(call trigger_dpapi_walk on each), then re-query. "
            "PARSE-ONLY: wairz surfaces METADATA only."
        )
    elif len(matches) >= 2:
        out["cross_firmware_signal"] = (
            f"DPAPI master-keys matching {query!r} appear in "
            f"{len(matches)} firmware images. Possible signals: "
            "(a) firmware clone (same image deployed multiple times — "
            "baseline); (b) attacker-replicated key stash across "
            "compromised hosts; (c) insider-threat user fingerprint "
            "(creator_sid appears across supposedly-independent "
            "firmwares); (d) backdoor key supply-chain (orphaned + "
            "admin-creator keys across multiple vendor firmwares). "
            "Master-key GUIDs are randomly generated — cross-firmware "
            "reuse is cryptographically improbable absent firmware "
            "duplication. Compare sample_entry across matches and "
            "check anomaly_flags for orphaned / admin-creator "
            "indicators. PARSE-ONLY: wairz NEVER decrypts."
        )
    return _truncate(json.dumps(out, indent=2))


# ── dpapi_walk_status ───────────────────────────────────────────────────────


async def _handle_dpapi_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.dpapi_walk_* state machine."""
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
        "status": row.dpapi_walk_status,
        "started_at": (
            row.dpapi_walk_started_at.isoformat()
            if row.dpapi_walk_started_at
            else None
        ),
        "finished_at": (
            row.dpapi_walk_finished_at.isoformat()
            if row.dpapi_walk_finished_at
            else None
        ),
        "error": row.dpapi_walk_error,
        "result": _normalize_firmware_dpapi_walk_result(
            row.dpapi_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_dpapi_walk ──────────────────────────────────────────────────────


async def _handle_trigger_dpapi_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling DPAPI master-key METADATA walk background
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

    if row.dpapi_walk_status in ("queued", "running"):
        return json.dumps({
            "conflict": True,
            "status": row.dpapi_walk_status,
            "started_at": (
                row.dpapi_walk_started_at.isoformat()
                if row.dpapi_walk_started_at
                else None
            ),
            "message": (
                f"dpapi walk already {row.dpapi_walk_status} for "
                f"firmware {firmware_id}. Poll dpapi_walk_status."
            ),
        })

    row.dpapi_walk_status = "queued"
    row.dpapi_walk_started_at = None
    row.dpapi_walk_finished_at = None
    row.dpapi_walk_error = None
    row.dpapi_walk_result = None
    await context.db.flush()

    from app.services.dpapi_walker import run_dpapi_walk_background

    asyncio.create_task(run_dpapi_walk_background(firmware_id))

    return json.dumps({
        "scheduled": True,
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "DPAPI master-key METADATA walk scheduled. Poll "
            "dpapi_walk_status until status=='completed' to harvest "
            "the result. PARSE-ONLY: wairz NEVER decrypts master "
            "keys, NEVER invokes CryptUnprotectData, NEVER records "
            "the salt bytes (only the salt_size constant). Surfaces "
            "METADATA only — master_key_guid + creator_sid + per-"
            "section sizes + hmac_iterations + anomaly flags."
        ),
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_dpapi_tools(registry: ToolRegistry) -> None:
    """Register all Phase κ.D.E Windows DPAPI master-key MCP tools.

    5 tools registered:
      - list_dpapi_master_keys
      - lookup_dpapi_master_key
      - lookup_dpapi_master_key_across_firmwares (Rule #44 cross-firmware
        aggregation — wairz competitive differentiator)
      - dpapi_walk_status
      - trigger_dpapi_walk

    PARSE-ONLY DISCIPLINE REMINDER (Rule #36 + Rule #45 — Rule-of-Two
    DURABLE BEYOND DEBATE): the κ.D.C walker is a pure-Python ``struct``
    parser over DPAPI master-key files' headers + body preambles. The
    walker NEVER decrypts master keys; these tools surface METADATA
    only.
    """

    registry.register(
        name="list_dpapi_master_keys",
        description=(
            "Phase κ.D.E — paginate the per-file "
            "windows_dpapi_master_keys table for the active firmware. "
            "Surfaces Windows DPAPI master-key PARSE-ONLY METADATA "
            "extracted from "
            "Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\"
            "<sid>\\<guid> files. DPAPI master-keys are the gateway to "
            "Windows credential vaults (Outlook profiles, browser "
            "passwords, certificate private keys, WinSCP profiles, "
            "Wi-Fi credentials). **PARSE-ONLY (Rule #36 + Rule #45)** "
            "— wairz NEVER decrypts master keys, NEVER invokes "
            "CryptUnprotectData, NEVER records the salt bytes (only "
            "the salt_size constant). Surfaces master_key_guid + "
            "creator_sid (from path) + flags + hmac_iterations + "
            "per-section sizes + anomaly flags only. Filters: "
            "anomaly_only (3 substantive bits: orphaned_masterkey / "
            "admin_creator_sid / large_masterkey), anomaly_bit "
            "(specific bit), creator_sid (exact SID match), "
            "guid_substring (case-insensitive SQL ILIKE). Returns up "
            "to `limit` rows per page (default 50, max 500). Reads "
            "the κ.D.A landing zone populated by κ.D.C's walker."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least "
                        "one substantive anomaly flag "
                        "(orphaned_masterkey / admin_creator_sid / "
                        "large_masterkey; parse_error is "
                        "INFORMATIONAL only and excluded)."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to entries with this specific anomaly "
                        "bit set (orphaned_masterkey / "
                        "admin_creator_sid / large_masterkey / "
                        "parse_error)."
                    ),
                },
                "creator_sid": {
                    "type": "string",
                    "description": (
                        "Exact creator_sid match (canonical "
                        "S-1-5-21-... form). Useful for hunting all "
                        "master-keys created by a specific user."
                    ),
                },
                "guid_substring": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring filter on "
                        "master_key_guid (SQL ILIKE %substring%)."
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
        handler=_handle_list_dpapi_master_keys,
    )

    registry.register(
        name="lookup_dpapi_master_key",
        description=(
            "Phase κ.D.E — find DPAPI master-key entries by substring "
            "match against master_key_guid OR creator_sid (case-"
            "insensitive SQL ILIKE). Returns up to 50 matching entries "
            "for the active firmware. Use this when you know a GUID "
            "or SID and want to surface the corresponding master-key "
            "metadata. PARSE-ONLY (Rule #36 + Rule #45) — wairz NEVER "
            "decrypts master keys; surfaces METADATA only. The query "
            "parameter is required."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring match (case-insensitive) against "
                        "master_key_guid OR creator_sid. E.g. "
                        "'S-1-5-21-' returns all keys; "
                        "'deadbeef' returns keys with that GUID prefix."
                    ),
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_dpapi_master_key,
    )

    registry.register(
        name="lookup_dpapi_master_key_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION (Rule #44)** — given a "
            "master_key_guid OR creator_sid substring, return ALL "
            "firmware images in the active project (default) OR "
            "globally that have DPAPI master-key entries matching. "
            "**FORENSIC VALUE** — answer 'does this master-key GUID "
            "OR creator SID appear across multiple firmware captures?' "
            "Possible signals: (a) firmware clone (same image "
            "deployed multiple times — baseline); (b) attacker-"
            "replicated key stash across compromised hosts; (c) "
            "insider-threat user fingerprint; (d) backdoor key "
            "supply-chain (orphaned + admin-creator keys across "
            "vendor firmwares). Master-key GUIDs are randomly "
            "generated — cross-firmware reuse is cryptographically "
            "improbable absent firmware duplication. Wairz competitive "
            "differentiator. PARSE-ONLY: walker surfaces METADATA "
            "only. match_count >= 2 triggers cross_firmware_signal in "
            "the output. scope='project' (default) restricts to the "
            "active project's firmwares; scope='global' searches "
            "every project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring match (case-insensitive) against "
                        "master_key_guid OR creator_sid across "
                        "firmwares."
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
        handler=_handle_lookup_dpapi_master_key_across_firmwares,
    )

    registry.register(
        name="dpapi_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row dpapi_walk_* "
            "state machine. Returns status (idle / queued / running / "
            "completed / failed), started_at, finished_at, error, and "
            "the last-known-result aggregate (files_scanned, "
            "files_persisted, files_capped, parse_errors, "
            "orphaned_masterkey_count, admin_creator_sid_count, "
            "large_masterkey_count, anomaly_total, errors, per_file)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_dpapi_walk_status,
    )

    registry.register(
        name="trigger_dpapi_walk",
        description=(
            "Trigger the 202+polling Windows DPAPI master-key "
            "PARSE-ONLY METADATA walk background runner. Walks every "
            "detection root (per Rule #16), locates DPAPI master-key "
            "files via the canonical path pattern "
            "Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\"
            "<sid>\\<guid>, parses each file's HEADER + body PREAMBLE "
            "via a pure-Python struct-based parser, classifies "
            "per-file anomalies, persists per-file rows into "
            "windows_dpapi_master_keys (master_key_guid + creator_sid "
            "+ flags + hmac_iterations + salt_size CONSTANT (NOT "
            "bytes) + per-section sizes + last_modified_ts + "
            "anomaly_flags). Idempotent (Rule #33 .a) — returns "
            "conflict=true if a run is already queued or running. "
            "Schedules run_dpapi_walk_background via "
            "asyncio.create_task. Poll dpapi_walk_status until "
            "status=='completed' to harvest the result. Anomaly "
            "classifier covers 4 bits: orphaned_masterkey (creator_sid "
            "no match in firmware user list — backdoor key stash "
            "indicator), admin_creator_sid (RID 500/512/519 or Local "
            "System), large_masterkey (file_size > 2048 bytes), "
            "parse_error (INFORMATIONAL only). **PARSE-ONLY (Rule #36 "
            "+ Rule #45 — Rule-of-Two DURABLE BEYOND DEBATE)** — "
            "walker reads file bytes, unpacks structs, emits rows; "
            "NEVER decrypts master keys, NEVER invokes "
            "CryptUnprotectData, NEVER records salt bytes (only the "
            "salt_size constant)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_dpapi_walk,
    )
