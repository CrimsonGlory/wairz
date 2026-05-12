"""Windows EFI System Partition (ESP) `.efi` PE chain MCP tools —
Phase θ.C.F.

Surfaces the Phase θ.C.C ESP walk results to the MCP layer:

- ``search_esp_entries`` — paginate the windows_esp_entries table for
  the active firmware by file-path / state filter / unsigned-only /
  revoked-only / known-bootloader-only filters.
- ``esp_walk_status`` — Rule #33 status reader for the firmware-row
  esp_walk_* state machine.
- ``trigger_esp_walk`` — trigger the 202+polling ESP walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``lookup_esp_chain`` — cross-firmware aggregation by
  fingerprint_sha256 OR file_sha256 (boot-chain hunt across the
  corpus — same `.efi` shape planted across firmware ⇒ same
  bootkit / supply-chain compromise).

Output truncation (Rule #29): tool outputs ≤ 30 KB.

Per CLAUDE.md Rule #36: this module exposes `.efi` PE chain
metadata as DATA only. The Authenticode chain summary +
authenticode_state + DBX revocation match are surfaced for operator
review; wairz NEVER invokes the `.efi` PE binary referenced by these
rows.
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
from app.models.windows_esp_entry import WindowsEspEntry
from app.services.jsonb_normalizers import (
    _normalize_firmware_esp_walk_result,
    _normalize_windows_esp_entries_anomaly_flags,
    _normalize_windows_esp_entries_authenticode_chain,
    _normalize_windows_esp_entries_dbx_revocation_match,
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


def _row_has_anomaly(record: WindowsEspEntry) -> bool:
    """Return True iff the entry carries any substantive anomaly
    flag: unsigned, revoked, non_microsoft_signer, or
    is_known_bootloader_path-with-unsigned-or-revoked."""
    flags = _normalize_windows_esp_entries_anomaly_flags(
        record.anomaly_flags
    )
    return bool(
        flags.get("is_unsigned")
        or flags.get("is_revoked")
        or flags.get("is_non_microsoft_signer")
        or flags.get("is_expired")
    )


# ── search_esp_entries ──────────────────────────────────────────────────────


async def _handle_search_esp_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_esp_entries by file-path-substring / state /
    unsigned_only / revoked_only / known_bootloader_only filters.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    path_substring = input.get("path_substring")
    state_filter = input.get("authenticode_state")
    unsigned_only = bool(input.get("unsigned_only", False))
    revoked_only = bool(input.get("revoked_only", False))
    known_bootloader_only = bool(input.get("known_bootloader_only", False))
    anomaly_only = bool(input.get("anomaly_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [WindowsEspEntry.firmware_id == firmware_id]
    if path_substring:
        base_where.append(
            WindowsEspEntry.file_path.like(f"%{path_substring}%")
        )
    if state_filter:
        base_where.append(
            WindowsEspEntry.authenticode_state == state_filter
        )
    if unsigned_only:
        base_where.append(
            WindowsEspEntry.authenticode_state == "unsigned"
        )
    if revoked_only:
        base_where.append(
            WindowsEspEntry.authenticode_state == "signed_revoked"
        )

    needs_python_filter = anomaly_only or known_bootloader_only

    if needs_python_filter:
        # Pull SQL-matching rows fully (no offset/limit yet) and
        # post-filter the JSONB shape in Python.
        page_q = (
            select(WindowsEspEntry)
            .where(*base_where)
            .order_by(WindowsEspEntry.file_path)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

        def _matches(r):
            flags = _normalize_windows_esp_entries_anomaly_flags(
                r.anomaly_flags
            )
            if known_bootloader_only and not flags.get(
                "is_known_bootloader_path"
            ):
                return False
            if anomaly_only and not _row_has_anomaly(r):
                return False
            return True

        filtered = [r for r in rows if _matches(r)]
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(WindowsEspEntry.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(WindowsEspEntry)
            .where(*base_where)
            .order_by(WindowsEspEntry.file_path)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    entries = [
        {
            "id": str(r.id),
            "file_path": r.file_path,
            "file_sha256": r.file_sha256,
            "file_size": r.file_size,
            "authenticode_state": r.authenticode_state,
            "authenticode_chain": (
                _normalize_windows_esp_entries_authenticode_chain(
                    r.authenticode_chain
                )
                if r.authenticode_chain is not None
                else None
            ),
            "dbx_revocation_match": (
                _normalize_windows_esp_entries_dbx_revocation_match(
                    r.dbx_revocation_match
                )
            ),
            "anomaly_flags": _normalize_windows_esp_entries_anomaly_flags(
                r.anomaly_flags
            ),
            "fingerprint_sha256": r.fingerprint_sha256,
            "has_anomaly": _row_has_anomaly(r),
        }
        for r in rows
    ]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "esp_entries": entries,
        "filters": {
            "path_substring": path_substring,
            "authenticode_state": state_filter,
            "unsigned_only": unsigned_only,
            "revoked_only": revoked_only,
            "known_bootloader_only": known_bootloader_only,
            "anomaly_only": anomaly_only,
        },
        "data_only_disclaimer": (
            "authenticode_chain + dbx_revocation_match describe the "
            ".efi PE's signing state. Per CLAUDE.md Rule #36, the "
            ".efi binary itself is DATA — never invoke."
        ),
    }
    if total == 0:
        out["message"] = (
            "No ESP entries match. The walker may not have run yet "
            "(call trigger_esp_walk and poll esp_walk_status), the "
            "firmware may not contain an EFI System Partition, or "
            "your filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── esp_walk_status ─────────────────────────────────────────────────────────


async def _handle_esp_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.esp_walk_* state machine."""
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
        "status": row.esp_walk_status,
        "started_at": (
            row.esp_walk_started_at.isoformat()
            if row.esp_walk_started_at
            else None
        ),
        "finished_at": (
            row.esp_walk_finished_at.isoformat()
            if row.esp_walk_finished_at
            else None
        ),
        "error": row.esp_walk_error,
        "result": _normalize_firmware_esp_walk_result(
            row.esp_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_esp_walk ────────────────────────────────────────────────────────


async def _handle_trigger_esp_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling ESP walk background runner.
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

    if row.esp_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.esp_walk_status,
                "started_at": (
                    row.esp_walk_started_at.isoformat()
                    if row.esp_walk_started_at
                    else None
                ),
                "message": (
                    f"ESP walk already {row.esp_walk_status} for "
                    f"firmware {firmware_id}. Poll esp_walk_status."
                ),
            }
        )

    row.esp_walk_status = "queued"
    row.esp_walk_started_at = None
    row.esp_walk_finished_at = None
    row.esp_walk_error = None
    row.esp_walk_result = None
    await context.db.flush()

    from app.services.esp_walker import run_esp_walk_background

    asyncio.create_task(run_esp_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "ESP walk scheduled. Poll esp_walk_status until "
                "status=='completed' to harvest the result."
            ),
        }
    )


# ── lookup_esp_chain ────────────────────────────────────────────────────────


async def _handle_lookup_esp_chain(
    input: dict, context: ToolContext
) -> str:
    """Cross-firmware aggregation by fingerprint_sha256 OR file_sha256.

    Same fingerprint / file hash across firmware ⇒ same `.efi`
    shape was planted (BlackLotus / Bootkitty / supply-chain hunt
    across the wairz corpus). Returns matching rows grouped by
    (firmware_id, file_path) with occurrence counts + distinct
    firmware count.

    Use case: cross-corpus threat hunt — 'this exact unsigned
    bootmgfw.efi fingerprint appears in N firmware images,
    correlating with known BlackLotus / Bootkitty deployment.'
    """
    fingerprint = input.get("fingerprint_sha256")
    file_sha = input.get("file_sha256")
    path_substring = input.get("path_substring")
    limit = int(input.get("limit", 100))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    if not fingerprint and not file_sha and not path_substring:
        return json.dumps({
            "error": (
                "Must provide at least one of: fingerprint_sha256, "
                "file_sha256, or path_substring."
            )
        })

    where_clauses = []
    if fingerprint:
        where_clauses.append(
            WindowsEspEntry.fingerprint_sha256 == fingerprint
        )
    if file_sha:
        where_clauses.append(
            WindowsEspEntry.file_sha256 == file_sha
        )
    if path_substring:
        where_clauses.append(
            WindowsEspEntry.file_path.like(f"%{path_substring}%")
        )

    stmt = (
        select(WindowsEspEntry)
        .where(*where_clauses)
        .order_by(WindowsEspEntry.firmware_id)
        .limit(limit)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    # Group by (firmware_id, file_path) for cross-firmware view.
    aggregated: dict[str, dict] = {}
    for r in rows:
        key = f"{r.firmware_id}|{r.file_path}"
        if key not in aggregated:
            aggregated[key] = {
                "firmware_id": str(r.firmware_id),
                "file_path": r.file_path,
                "file_sha256": r.file_sha256,
                "file_size": r.file_size,
                "authenticode_state": r.authenticode_state,
                "fingerprint_sha256": r.fingerprint_sha256,
                "has_anomaly": _row_has_anomaly(r),
                "occurrences": 0,
            }
        aggregated[key]["occurrences"] += 1

    matches = list(aggregated.values())
    firmware_count = len({m["firmware_id"] for m in matches})

    out = {
        "total_matches": len(matches),
        "distinct_firmware_count": firmware_count,
        "matches": matches,
        "filters": {
            "fingerprint_sha256": fingerprint,
            "file_sha256": file_sha,
            "path_substring": path_substring,
        },
        "data_only_disclaimer": (
            "The `.efi` PEs referenced by these matches are DATA. "
            "Per CLAUDE.md Rule #36, treat as untrusted — never "
            "invoke."
        ),
    }
    if not matches:
        out["message"] = (
            "No matches. The fingerprint may not appear in the wairz "
            "corpus yet, or the filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_esp_tools(registry: ToolRegistry) -> None:
    """Register all Phase θ.C.F Windows ESP MCP tools."""

    registry.register(
        name="search_esp_entries",
        description=(
            "Phase θ.C.F — paginate the per-`.efi` "
            "windows_esp_entries table for the active firmware. "
            "Filters: path_substring (substring match on file_path), "
            "authenticode_state (signed_valid / signed_expired / "
            "signed_revoked / unsigned / parse_failed), "
            "unsigned_only / revoked_only (state shortcuts), "
            "known_bootloader_only (filters to .efi files in "
            "canonical OS-bootloader paths: EFI/Boot/bootx64.efi, "
            "EFI/Microsoft/Boot/bootmgfw.efi, EFI/<linux-vendor>/"
            "{shimx64,grubx64}.efi), "
            "anomaly_only (filters to entries with at least one "
            "anomaly flag raised: is_unsigned / is_revoked / "
            "is_non_microsoft_signer / is_expired). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "with total_count for navigation. Reads the θ.C.A landing "
            "zone populated by θ.C.C's walker. Order: file_path ASC. "
            "Indexes (firmware_id,) + (firmware_id, file_sha256) + "
            "(firmware_id, authenticode_state) cover the common "
            "filter shapes. "
            "PER RULE #36: the `.efi` PE referenced by each row is "
            "DATA — operators reviewing the output MUST NOT invoke "
            "any binary at the returned file_path."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Substring match on file_path (e.g. "
                        "'bootmgfw' or 'EFI/Boot')."
                    ),
                },
                "authenticode_state": {
                    "type": "string",
                    "enum": [
                        "signed_valid",
                        "signed_expired",
                        "signed_revoked",
                        "unsigned",
                        "parse_failed",
                    ],
                    "description": (
                        "Filter to one authenticode_state value."
                    ),
                },
                "unsigned_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only authenticode_state="
                        "unsigned entries."
                    ),
                },
                "revoked_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only authenticode_state="
                        "signed_revoked entries."
                    ),
                },
                "known_bootloader_only": {
                    "type": "boolean",
                    "description": (
                        "If true, filter to .efi files in canonical "
                        "OS-bootloader paths (highest-impact triage)."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least "
                        "one anomaly flag raised (is_unsigned / "
                        "is_revoked / is_non_microsoft_signer / "
                        "is_expired)."
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
        handler=_handle_search_esp_entries,
    )

    registry.register(
        name="esp_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "esp_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result "
            "aggregate (efi_files_scanned, efi_files_persisted, "
            "signed_valid_count, signed_expired_count, "
            "signed_revoked_count, unsigned_count, "
            "parse_failed_count, dbx_revoked_count, "
            "non_microsoft_signer_count, "
            "known_bootloader_anomaly_count, errors, per_root)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_esp_walk_status,
    )

    registry.register(
        name="trigger_esp_walk",
        description=(
            "Trigger the 202+polling Windows EFI System Partition "
            "(ESP) `.efi` PE chain correlation walk background "
            "runner. Walks for `.efi` files under EFI/ subdirectories "
            "(case-insensitive) of each detection root (typical "
            "layouts: FAT32 mount under /boot/efi, raw partition "
            "image, or EFI/ directory at the root of an extracted "
            "UEFI capsule), validates each via the β.4 signify "
            "Authenticode chain + β.10 DBX revocation list + "
            "pefile COFF metadata (all pure-Python parsers treating "
            "the .efi PE as DATA per Rule #36 — never invoked via "
            "wine / mono / qemu-system / chainloader), persists "
            "per-`.efi` metadata + chain summary + DBX match + "
            "anomaly flag aggregate into windows_esp_entries, and "
            "stamps an aggregate JSONB result onto esp_walk_result. "
            "Idempotent (Rule #33 .a) — returns conflict=true with "
            "the in-flight status if a run is already queued or "
            "running. Schedules run_esp_walk_background via "
            "asyncio.create_task. Poll esp_walk_status until "
            "status=='completed' to harvest the result. Auto-emits "
            "windows_esp_unsigned + windows_esp_dbx_revoked Finding "
            "rows for anomaly entries (T1542.003 Pre-OS Boot: "
            "Bootkit — BlackLotus, MoonBounce, CosmicStrand, "
            "Bootkitty)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_esp_walk,
    )

    registry.register(
        name="lookup_esp_chain",
        description=(
            "Phase θ.C.F — cross-firmware aggregation for `.efi` "
            "boot-chain entries (UNIQUE to wairz). Query by "
            "fingerprint_sha256 (SHA256 of file_path_lower + "
            "file_sha256 + authenticode_state — same fingerprint "
            "across firmware ⇒ same .efi shape was planted), OR "
            "file_sha256 (raw file-content match), OR "
            "path_substring (substring match on file_path across "
            "ALL firmware). Returns matching rows grouped by "
            "(firmware_id, file_path) with occurrence counts + "
            "distinct firmware count. "
            "Use case: cross-corpus boot-chain hunt — 'this exact "
            "unsigned bootmgfw.efi fingerprint appears in N "
            "firmware images, correlating with known BlackLotus / "
            "Bootkitty / supply-chain compromise.' Indexes "
            "(fingerprint_sha256,) + (firmware_id, file_sha256) "
            "cover the canonical query shapes. "
            "PER RULE #36: the `.efi` PEs referenced by these "
            "matches are DATA — treat as untrusted, never invoke."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 hex string (64 chars) of the "
                        "canonical entry tuple."
                    ),
                },
                "file_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 hex string (64 chars) of the raw "
                        ".efi file contents."
                    ),
                },
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Substring match on file_path across all "
                        "firmware (e.g. 'bootmgfw.efi' to find "
                        "every Windows boot manager across the "
                        "corpus)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Max matches returned (default 100, max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_lookup_esp_chain,
    )
