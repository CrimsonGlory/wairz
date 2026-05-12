"""Windows MBR/VBR boot-sector MCP tools — Phase θ.E.F.

Surfaces the Phase θ.E.C MBR/VBR walk results to the MCP layer:

- ``list_mbr_vbr_sectors`` — paginate the windows_mbr_vbr_sectors
  table for the active firmware by file-path / sector-kind /
  bootkit-only / anomaly-only filters.
- ``lookup_mbr_vbr_sector`` — cross-firmware aggregation by
  fingerprint_sha256 OR sector_sha256 (boot-sector hunt across the
  corpus — same MBR/VBR shape planted across firmware ⇒ same
  bootkit / supply-chain compromise).

Output truncation (Rule #29): tool outputs ≤ 30 KB.

Per CLAUDE.md Rule #36: this module exposes MBR/VBR sector
metadata as DATA only. The boot code is surfaced via
``sector_sha256`` + ``known_bootkit_match`` + ``anomaly_flags``;
wairz NEVER invokes the boot sector code at the referenced
``file_path`` (Rule #36 no-execute discipline).
"""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.windows_mbr_vbr_sector import WindowsMbrVbrSector
from app.services.jsonb_normalizers import (
    _normalize_windows_mbr_vbr_sectors_anomaly_flags,
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
        + "\n\n[output truncated to 30KB — narrow filters or use "
        "offset+limit to paginate]"
    )


def _anomaly_count(record: WindowsMbrVbrSector) -> int:
    """Count substantive anomaly flags (excludes is_mbr/is_vbr
    convenience booleans)."""
    flags = _normalize_windows_mbr_vbr_sectors_anomaly_flags(
        record.anomaly_flags
    )
    return sum(
        1
        for key in (
            "non_zero_padding",
            "unexpected_partition_table",
            "non_standard_jmp",
        )
        if bool(flags.get(key))
    )


def _row_has_anomaly(record: WindowsMbrVbrSector) -> bool:
    """Return True iff the entry carries any substantive anomaly flag
    OR a bootkit match."""
    return bool(record.known_bootkit_match) or _anomaly_count(record) > 0


def _row_to_dict(record: WindowsMbrVbrSector) -> dict:
    """Project a WindowsMbrVbrSector row to a JSON-safe dict."""
    return {
        "id": str(record.id),
        "firmware_id": str(record.firmware_id),
        "file_path": record.file_path,
        "sector_offset": record.sector_offset,
        "sector_kind": record.sector_kind,
        "sector_sha256": record.sector_sha256,
        "sector_size": record.sector_size,
        "bootcode_signature_match": record.bootcode_signature_match,
        "known_bootkit_match": record.known_bootkit_match,
        "anomaly_flags": _normalize_windows_mbr_vbr_sectors_anomaly_flags(
            record.anomaly_flags
        ),
        "fingerprint_sha256": record.fingerprint_sha256,
        "created_at": (
            record.created_at.isoformat() if record.created_at else None
        ),
    }


# ── list_mbr_vbr_sectors ────────────────────────────────────────────────────


async def _handle_list_mbr_vbr_sectors(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_mbr_vbr_sectors by path-substring / sector-kind
    / bootkit-only / anomaly-only filters.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    path_substring = input.get("path_substring")
    sector_kind_filter = input.get("sector_kind")
    bootkit_only = bool(input.get("bootkit_only", False))
    anomaly_only = bool(input.get("anomaly_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_filters = [WindowsMbrVbrSector.firmware_id == firmware_id]
    if path_substring:
        base_filters.append(
            WindowsMbrVbrSector.file_path.like(f"%{path_substring}%")
        )
    if sector_kind_filter:
        base_filters.append(
            WindowsMbrVbrSector.sector_kind == sector_kind_filter
        )
    if bootkit_only:
        base_filters.append(
            WindowsMbrVbrSector.known_bootkit_match.isnot(None)
        )

    count_stmt = (
        select(sa_func.count())
        .select_from(WindowsMbrVbrSector)
        .where(*base_filters)
    )
    total_count = (await context.db.execute(count_stmt)).scalar_one()

    stmt = (
        select(WindowsMbrVbrSector)
        .where(*base_filters)
        .order_by(
            WindowsMbrVbrSector.file_path.asc(),
            WindowsMbrVbrSector.sector_offset.asc(),
        )
        .offset(offset)
        .limit(limit)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    if anomaly_only:
        rows = [r for r in rows if _row_has_anomaly(r)]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "returned": len(rows),
        "entries": [_row_to_dict(r) for r in rows],
        "filters": {
            "path_substring": path_substring,
            "sector_kind": sector_kind_filter,
            "bootkit_only": bootkit_only,
            "anomaly_only": anomaly_only,
        },
        "data_only_disclaimer": (
            "MBR/VBR sectors are 512 bytes of x86 boot code that runs "
            "at Ring -2 BEFORE any OS code. The rows surface as DATA "
            "for triage only. Per CLAUDE.md Rule #36, NEVER invoke "
            "the boot sector code at the referenced file_path."
        ),
    }
    if total_count == 0:
        out["message"] = (
            "No MBR/VBR sectors persisted for this firmware. Run the "
            "θ.E.C walker (when the trigger MCP tool is wired up in a "
            "follow-up commit) OR check that the firmware extraction "
            "actually contains disk image files (.img / .raw / .vhd "
            "/ .vhdx / .bin / .dd / .001)."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_mbr_vbr_sector ───────────────────────────────────────────────────


async def _handle_lookup_mbr_vbr_sector(
    input: dict, context: ToolContext
) -> str:
    """Cross-firmware aggregation by fingerprint_sha256 OR
    sector_sha256.

    Same fingerprint / sector hash across firmware ⇒ same boot
    sector was planted (TDL4 / Petya / Mebroot / supply-chain
    correlation across the wairz corpus). Returns matching rows
    grouped by (firmware_id, file_path, sector_offset) with
    occurrence counts + distinct firmware count.

    Use case: cross-corpus threat hunt — 'this exact Petya MBR
    fingerprint appears in N firmware images, correlating with
    the same ransomware campaign across the fleet.'
    """
    fingerprint = input.get("fingerprint_sha256")
    sector_sha = input.get("sector_sha256")
    bootkit_match = input.get("known_bootkit_match")
    limit = int(input.get("limit", 100))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    if not fingerprint and not sector_sha and not bootkit_match:
        return json.dumps({
            "error": (
                "Must provide at least one of: fingerprint_sha256, "
                "sector_sha256, or known_bootkit_match."
            )
        })

    where_clauses = []
    if fingerprint:
        where_clauses.append(
            WindowsMbrVbrSector.fingerprint_sha256 == fingerprint
        )
    if sector_sha:
        where_clauses.append(
            WindowsMbrVbrSector.sector_sha256 == sector_sha
        )
    if bootkit_match:
        where_clauses.append(
            WindowsMbrVbrSector.known_bootkit_match == bootkit_match
        )

    stmt = (
        select(WindowsMbrVbrSector)
        .where(*where_clauses)
        .order_by(WindowsMbrVbrSector.firmware_id)
        .limit(limit)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    # Group by (firmware_id, file_path, sector_offset) for
    # cross-firmware view.
    aggregated: dict[str, dict] = {}
    for r in rows:
        key = f"{r.firmware_id}|{r.file_path}|{r.sector_offset}"
        if key not in aggregated:
            aggregated[key] = {
                "firmware_id": str(r.firmware_id),
                "file_path": r.file_path,
                "sector_offset": r.sector_offset,
                "sector_kind": r.sector_kind,
                "sector_sha256": r.sector_sha256,
                "fingerprint_sha256": r.fingerprint_sha256,
                "bootcode_signature_match": r.bootcode_signature_match,
                "known_bootkit_match": r.known_bootkit_match,
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
            "sector_sha256": sector_sha,
            "known_bootkit_match": bootkit_match,
        },
        "data_only_disclaimer": (
            "The boot sectors referenced by these matches are DATA. "
            "Per CLAUDE.md Rule #36, treat as untrusted — never "
            "invoke the boot sector code."
        ),
    }
    if not matches:
        out["message"] = (
            "No matches. The fingerprint may not appear in the wairz "
            "corpus yet, or the filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_mbr_vbr_tools(registry: ToolRegistry) -> None:
    """Register all Phase θ.E.F Windows MBR/VBR MCP tools."""

    registry.register(
        name="list_mbr_vbr_sectors",
        description=(
            "Phase θ.E.F — paginate the per-boot-sector "
            "windows_mbr_vbr_sectors table for the active firmware. "
            "Filters: path_substring (substring match on file_path), "
            "sector_kind (mbr / vbr_fat32 / vbr_ntfs / vbr_fat16 / "
            "vbr_exfat / unknown), bootkit_only (filter to entries "
            "with known_bootkit_match populated — TDL4 / Petya / "
            "Mebroot / Olmasco / BlackEnergy), anomaly_only (filter "
            "to entries with at least one anomaly flag raised: "
            "non_zero_padding / unexpected_partition_table / "
            "non_standard_jmp). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "with total_count for navigation. Reads the θ.E.A landing "
            "zone populated by θ.E.C's walker. Order: file_path ASC + "
            "sector_offset ASC. Indexes (firmware_id,) + "
            "(firmware_id, sector_sha256) + (firmware_id, "
            "known_bootkit_match) cover the common filter shapes. "
            "PER RULE #36: the MBR/VBR boot sector referenced by each "
            "row is DATA — operators reviewing the output MUST NOT "
            "invoke any boot code at the returned file_path. The "
            "sectors are 512 bytes of x86 boot code that runs at "
            "Ring -2 BEFORE any OS code; surfaced for triage only."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Substring match on file_path (e.g. "
                        "'windows.img' or 'partition_0')."
                    ),
                },
                "sector_kind": {
                    "type": "string",
                    "enum": [
                        "mbr",
                        "vbr_fat32",
                        "vbr_ntfs",
                        "vbr_fat16",
                        "vbr_exfat",
                        "unknown",
                    ],
                    "description": (
                        "Filter to one sector_kind value."
                    ),
                },
                "bootkit_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with "
                        "known_bootkit_match populated (highest-impact "
                        "triage)."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with at least "
                        "one anomaly flag raised."
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
                    "description": (
                        "Page offset for pagination (default 0)."
                    ),
                    "minimum": 0,
                },
            },
        },
        handler=_handle_list_mbr_vbr_sectors,
    )

    registry.register(
        name="lookup_mbr_vbr_sector",
        description=(
            "Phase θ.E.F — cross-firmware boot-sector hunt by "
            "fingerprint_sha256 OR sector_sha256 OR known_bootkit_"
            "match. Same fingerprint / sector hash across firmware ⇒ "
            "same boot sector was planted (TDL4 / Petya / Mebroot / "
            "supply-chain correlation across the wairz corpus). "
            "Returns matching rows grouped by (firmware_id, "
            "file_path, sector_offset) with occurrence counts + "
            "distinct firmware count. Pairs with θ.A's lookup_bcd_"
            "chain + θ.B's lookup_wmi_persistence + θ.C's "
            "lookup_esp_chain to give 4-way cross-firmware boot-"
            "chain correlation (BCD + WMI + ESP + MBR/VBR). "
            "Use case: 'this exact Petya MBR fingerprint appears in "
            "N firmware images, correlating with the same ransomware "
            "campaign across the fleet.' "
            "PER RULE #36: the matched boot sectors are DATA. Never "
            "invoke."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 fingerprint (64 hex chars) — same "
                        "fingerprint across firmware ⇒ same boot "
                        "sector shape was planted."
                    ),
                },
                "sector_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 of the 512-byte sector contents (64 "
                        "hex chars) — raw byte match."
                    ),
                },
                "known_bootkit_match": {
                    "type": "string",
                    "description": (
                        "Filter to a specific bootkit name (e.g. "
                        "'petya_mbr', 'tdl4_mbr', 'mebroot_mbr')."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Max rows to return (default 100, max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
        },
        handler=_handle_lookup_mbr_vbr_sector,
    )
