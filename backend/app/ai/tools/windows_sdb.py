"""Windows SDB shim MCP tools — Phase θ.D.F.

Surfaces the Phase θ.D.D SDB shim walk results to the MCP layer:

- ``list_sdb_entries`` — paginate the windows_sdb_entries table for
  the active firmware by file-path / sdb-kind / shim-class /
  custom-only / anomaly-only filters.
- ``lookup_sdb_shim`` — cross-firmware aggregation by
  fingerprint_sha256 OR file_sha256 OR shim_class (shim hunt across
  the corpus — same .sdb shape planted across firmware ⇒ same
  T1546.011 Application Shimming campaign).
- ``summarize_sdb_anomalies`` — aggregate counts of attacker-shape
  signals (InjectDll / RedirectEXE / GetCommandLineW / etc.) per
  firmware for fast triage overview.

Output truncation (Rule #29): tool outputs ≤ 30 KB.

Per CLAUDE.md Rule #36: this module exposes SDB shim metadata as
DATA only. The shim instructions are surfaced via ``shim_payload``
+ ``anomaly_flags``; wairz NEVER invokes any shim infrastructure at
the referenced ``file_path`` (Rule #36 no-execute discipline).

Closes the θ campaign at 5-of-5 walker streams (θ.A BCD + θ.B WMI +
θ.C ESP + θ.E MBR/VBR + θ.D SDB) — and adds the 5th cross-firmware
fingerprint aggregation MCP tool (Rule-of-Five for Pattern P6:
lookup_bcd_chain + lookup_wmi_persistence + lookup_esp_chain +
lookup_mbr_vbr_sector + lookup_sdb_shim).
"""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.windows_sdb_entry import WindowsSdbEntry
from app.services.jsonb_normalizers import (
    _normalize_windows_sdb_entries_anomaly_flags,
    _normalize_windows_sdb_entries_shim_payload,
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


def _anomaly_count(record: WindowsSdbEntry) -> int:
    """Count substantive anomaly flags (excludes informational ones)."""
    flags = _normalize_windows_sdb_entries_anomaly_flags(
        record.anomaly_flags
    )
    return sum(
        1
        for key in (
            "is_custom_path",
            "has_inject_dll",
            "has_redirect_exe",
            "has_get_command_line",
            "has_redirect_shortcut",
            "has_dll_outside_appdir",
        )
        if bool(flags.get(key))
    )


def _row_has_anomaly(record: WindowsSdbEntry) -> bool:
    """Return True iff the entry carries any substantive anomaly flag."""
    return _anomaly_count(record) > 0


def _row_to_dict(record: WindowsSdbEntry) -> dict:
    """Project a WindowsSdbEntry row to a JSON-safe dict."""
    return {
        "id": str(record.id),
        "firmware_id": str(record.firmware_id),
        "file_path": record.file_path,
        "file_sha256": record.file_sha256,
        "sdb_kind": record.sdb_kind,
        "app_name": record.app_name,
        "app_exe": record.app_exe,
        "shim_class": record.shim_class,
        "shim_payload": _normalize_windows_sdb_entries_shim_payload(
            record.shim_payload
        ),
        "anomaly_flags": _normalize_windows_sdb_entries_anomaly_flags(
            record.anomaly_flags
        ),
        "fingerprint_sha256": record.fingerprint_sha256,
        "created_at": (
            record.created_at.isoformat() if record.created_at else None
        ),
    }


# ── list_sdb_entries ────────────────────────────────────────────────────────


async def _handle_list_sdb_entries(
    input: dict, context: ToolContext
) -> str:
    """Paginate windows_sdb_entries by path-substring / sdb-kind /
    shim-class / custom-only / anomaly-only filters.

    Returns up to ``limit`` rows per page (default 50, max 500)."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    path_substring = input.get("path_substring")
    sdb_kind_filter = input.get("sdb_kind")
    shim_class_filter = input.get("shim_class")
    custom_only = bool(input.get("custom_only", False))
    anomaly_only = bool(input.get("anomaly_only", False))
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_filters = [WindowsSdbEntry.firmware_id == firmware_id]
    if path_substring:
        base_filters.append(
            WindowsSdbEntry.file_path.like(f"%{path_substring}%")
        )
    if sdb_kind_filter:
        base_filters.append(
            WindowsSdbEntry.sdb_kind == sdb_kind_filter
        )
    if shim_class_filter:
        base_filters.append(
            WindowsSdbEntry.shim_class == shim_class_filter
        )
    if custom_only:
        base_filters.append(WindowsSdbEntry.sdb_kind == "custom")

    count_stmt = (
        select(sa_func.count())
        .select_from(WindowsSdbEntry)
        .where(*base_filters)
    )
    total_count = (await context.db.execute(count_stmt)).scalar_one()

    stmt = (
        select(WindowsSdbEntry)
        .where(*base_filters)
        .order_by(
            WindowsSdbEntry.file_path.asc(),
            WindowsSdbEntry.shim_class.asc(),
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
            "sdb_kind": sdb_kind_filter,
            "shim_class": shim_class_filter,
            "custom_only": custom_only,
            "anomaly_only": anomaly_only,
        },
        "data_only_disclaimer": (
            "SDB shim entries describe instructions Windows loads + "
            "executes via AppHelp on every application launch. The "
            "rows surface as DATA for triage only. Per CLAUDE.md "
            "Rule #36, NEVER invoke parsed shims via sdbinst / "
            "AppHelp / Mscoree at the referenced file_path."
        ),
    }
    if total_count == 0:
        out["message"] = (
            "No SDB entries persisted for this firmware. Run the "
            "θ.D.D walker (when the trigger MCP tool is wired up in "
            "a follow-up commit) OR check that the firmware "
            "extraction actually contains .sdb files (typically "
            "under Windows/AppPatch/ or Windows/AppPatch/Custom/)."
        )
    return _truncate(json.dumps(out, indent=2))


# ── lookup_sdb_shim ─────────────────────────────────────────────────────────


async def _handle_lookup_sdb_shim(
    input: dict, context: ToolContext
) -> str:
    """Cross-firmware aggregation by fingerprint_sha256 OR
    file_sha256 OR shim_class.

    Same fingerprint / file hash across firmware ⇒ same shim was
    planted (T1546.011 campaign correlation across the wairz
    corpus). Returns matching rows grouped by (firmware_id, file_path,
    shim_class) with occurrence counts + distinct firmware count.

    Use case: cross-corpus threat hunt — 'this exact attacker
    .sdb fingerprint appears in N firmware images, correlating with
    the same shim-persistence campaign across the fleet.'
    """
    fingerprint = input.get("fingerprint_sha256")
    file_sha = input.get("file_sha256")
    shim_class_filter = input.get("shim_class")
    limit = int(input.get("limit", 100))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    if not fingerprint and not file_sha and not shim_class_filter:
        return json.dumps({
            "error": (
                "Must provide at least one of: fingerprint_sha256, "
                "file_sha256, or shim_class."
            )
        })

    where_clauses = []
    if fingerprint:
        where_clauses.append(
            WindowsSdbEntry.fingerprint_sha256 == fingerprint
        )
    if file_sha:
        where_clauses.append(
            WindowsSdbEntry.file_sha256 == file_sha
        )
    if shim_class_filter:
        where_clauses.append(
            WindowsSdbEntry.shim_class == shim_class_filter
        )

    stmt = (
        select(WindowsSdbEntry)
        .where(*where_clauses)
        .order_by(WindowsSdbEntry.firmware_id)
        .limit(limit)
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    # Group by (firmware_id, file_path, shim_class) for
    # cross-firmware view.
    aggregated: dict[str, dict] = {}
    for r in rows:
        key = f"{r.firmware_id}|{r.file_path}|{r.shim_class}"
        if key not in aggregated:
            aggregated[key] = {
                "firmware_id": str(r.firmware_id),
                "file_path": r.file_path,
                "file_sha256": r.file_sha256,
                "sdb_kind": r.sdb_kind,
                "app_name": r.app_name,
                "app_exe": r.app_exe,
                "shim_class": r.shim_class,
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
            "shim_class": shim_class_filter,
        },
        "data_only_disclaimer": (
            "The shim entries referenced by these matches are DATA. "
            "Per CLAUDE.md Rule #36, treat as untrusted — never "
            "invoke parsed shims via sdbinst / AppHelp / Mscoree."
        ),
    }
    if not matches:
        out["message"] = (
            "No matches. The fingerprint may not appear in the wairz "
            "corpus yet, or the filters may be too narrow."
        )
    return _truncate(json.dumps(out, indent=2))


# ── summarize_sdb_anomalies ────────────────────────────────────────────────


async def _handle_summarize_sdb_anomalies(
    input: dict, context: ToolContext
) -> str:
    """Aggregate counts of attacker-shape signals per firmware for
    fast triage overview.

    Returns the per-shim-class counts + custom-path count +
    distinct-app count for the active firmware. Use to answer
    'how many T1546.011 candidates exist here?' in one round-trip
    before drilling into list_sdb_entries."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    stmt = select(WindowsSdbEntry).where(
        WindowsSdbEntry.firmware_id == firmware_id
    )
    rows = (await context.db.execute(stmt)).scalars().all()

    total = len(rows)
    custom = sum(1 for r in rows if r.sdb_kind == "custom")
    microsoft = sum(1 for r in rows if r.sdb_kind == "microsoft")
    unknown = sum(1 for r in rows if r.sdb_kind == "unknown")

    inject_dll = sum(1 for r in rows if r.shim_class == "InjectDll")
    redirect_exe = sum(1 for r in rows if r.shim_class == "RedirectEXE")
    get_command_line = sum(
        1 for r in rows if r.shim_class == "GetCommandLineW"
    )
    redirect_shortcut = sum(
        1 for r in rows if r.shim_class == "RedirectShortcut"
    )
    custom_class = sum(1 for r in rows if r.shim_class == "Custom")
    patch_class = sum(1 for r in rows if r.shim_class == "Patch")
    other_class = sum(1 for r in rows if r.shim_class == "Other")

    anomaly_count = sum(1 for r in rows if _row_has_anomaly(r))
    distinct_files = len({r.file_path for r in rows})
    distinct_apps = len(
        {r.app_exe for r in rows if r.app_exe}
    )

    high_signal_custom = sum(
        1
        for r in rows
        if r.sdb_kind == "custom"
        and r.shim_class in ("InjectDll", "RedirectEXE")
    )

    out = {
        "firmware_id": str(firmware_id),
        "total_entries": total,
        "by_sdb_kind": {
            "microsoft": microsoft,
            "custom": custom,
            "unknown": unknown,
        },
        "by_shim_class": {
            "InjectDll": inject_dll,
            "RedirectEXE": redirect_exe,
            "GetCommandLineW": get_command_line,
            "RedirectShortcut": redirect_shortcut,
            "Custom": custom_class,
            "Patch": patch_class,
            "Other": other_class,
        },
        "anomaly_entries": anomaly_count,
        "distinct_files": distinct_files,
        "distinct_apps": distinct_apps,
        "high_signal_custom_attackers": high_signal_custom,
        "triage_hint": (
            "high_signal_custom_attackers = count of (custom-path "
            ".sdb AND shim_class in InjectDll/RedirectEXE) — direct "
            "T1546.011 Application Shimming candidates. Run "
            "list_sdb_entries with custom_only=true + anomaly_only=true "
            "for the per-row detail."
        ),
        "data_only_disclaimer": (
            "Per CLAUDE.md Rule #36, treat as untrusted — never "
            "invoke parsed shims at the referenced file_path."
        ),
    }
    if total == 0:
        out["message"] = (
            "No SDB entries persisted for this firmware. Run the "
            "θ.D.D walker OR check that the firmware extraction "
            "actually contains .sdb files."
        )
    return _truncate(json.dumps(out, indent=2))


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_sdb_tools(registry: ToolRegistry) -> None:
    """Register all Phase θ.D.F Windows SDB MCP tools."""

    registry.register(
        name="list_sdb_entries",
        description=(
            "Phase θ.D.F — paginate the per-shim-entry "
            "windows_sdb_entries table for the active firmware. "
            "Filters: path_substring (substring match on file_path), "
            "sdb_kind (microsoft / custom / unknown), shim_class "
            "(RedirectEXE / InjectDll / GetCommandLineW / "
            "RedirectShortcut / Custom / Patch / Other), custom_only "
            "(filter to sdb_kind=custom entries — attacker-shape "
            "Windows/AppPatch/Custom/<exe>.sdb T1546.011 candidates), "
            "anomaly_only (filter to entries with at least one "
            "anomaly flag raised: is_custom_path / has_inject_dll / "
            "has_redirect_exe / has_get_command_line / "
            "has_redirect_shortcut / has_dll_outside_appdir). "
            "Returns up to `limit` rows per page (default 50, max "
            "500) with total_count for navigation. Reads the θ.D.B "
            "landing zone populated by θ.D.D's walker. Order: "
            "file_path ASC + shim_class ASC. Indexes (firmware_id,) "
            "+ (firmware_id, file_sha256) + (firmware_id, sdb_kind) "
            "cover the common filter shapes. "
            "PER RULE #36: the shim entries referenced by each row "
            "describe instructions Windows AppHelp loads + executes. "
            "Operators reviewing the output MUST NOT invoke any "
            "shim via sdbinst.exe / AppHelp.dll / Mscoree.dll at "
            "the returned file_path. The entries are surfaced for "
            "triage only."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path_substring": {
                    "type": "string",
                    "description": (
                        "Substring match on file_path (e.g. "
                        "'Custom/' or 'myapp.sdb')."
                    ),
                },
                "sdb_kind": {
                    "type": "string",
                    "enum": ["microsoft", "custom", "unknown"],
                    "description": (
                        "Filter to one sdb_kind value."
                    ),
                },
                "shim_class": {
                    "type": "string",
                    "enum": [
                        "RedirectEXE",
                        "InjectDll",
                        "GetCommandLineW",
                        "RedirectShortcut",
                        "Custom",
                        "Patch",
                        "Other",
                    ],
                    "description": (
                        "Filter to one shim_class value."
                    ),
                },
                "custom_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only entries with "
                        "sdb_kind=custom (highest-impact triage — "
                        "Windows/AppPatch/Custom/ is the attacker-"
                        "controlled path for T1546.011)."
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
        handler=_handle_list_sdb_entries,
    )

    registry.register(
        name="lookup_sdb_shim",
        description=(
            "Phase θ.D.F — cross-firmware shim hunt by "
            "fingerprint_sha256 OR file_sha256 OR shim_class. Same "
            "fingerprint / file hash across firmware ⇒ same shim "
            "was planted (T1546.011 Application Shimming campaign "
            "correlation across the wairz corpus). Returns matching "
            "rows grouped by (firmware_id, file_path, shim_class) "
            "with occurrence counts + distinct firmware count. "
            "Pairs with θ.A's lookup_bcd_chain + θ.B's "
            "lookup_wmi_persistence + θ.C's lookup_esp_chain + "
            "θ.E's lookup_mbr_vbr_sector to give 5-way "
            "cross-firmware Windows-persistence correlation (BCD + "
            "WMI + ESP + MBR/VBR + SDB). "
            "Use case: 'this exact attacker .sdb fingerprint appears "
            "in N firmware images, correlating with the same shim-"
            "persistence campaign across the fleet.' "
            "PER RULE #36: the matched shim entries are DATA. Never "
            "invoke."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 fingerprint (64 hex chars) — same "
                        "fingerprint across firmware ⇒ same shim "
                        "entry shape was planted."
                    ),
                },
                "file_sha256": {
                    "type": "string",
                    "description": (
                        "SHA256 of the `.sdb` file contents (64 hex "
                        "chars) — raw byte match."
                    ),
                },
                "shim_class": {
                    "type": "string",
                    "enum": [
                        "RedirectEXE",
                        "InjectDll",
                        "GetCommandLineW",
                        "RedirectShortcut",
                        "Custom",
                        "Patch",
                        "Other",
                    ],
                    "description": (
                        "Filter to one shim_class value (e.g. "
                        "'InjectDll' to find every InjectDll shim "
                        "in the corpus)."
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
        handler=_handle_lookup_sdb_shim,
    )

    registry.register(
        name="summarize_sdb_anomalies",
        description=(
            "Phase θ.D.F — aggregate-counts overview of attacker-"
            "shape signals per firmware. Returns per-shim-class "
            "counts (InjectDll / RedirectEXE / GetCommandLineW / "
            "RedirectShortcut / Custom / Patch / Other) + per-"
            "sdb-kind counts (microsoft / custom / unknown) + "
            "distinct file + app counts + high_signal_custom_"
            "attackers (custom-path + InjectDll/RedirectEXE — "
            "direct T1546.011 candidates). Use for fast triage "
            "overview before drilling into list_sdb_entries / "
            "lookup_sdb_shim. "
            "PER RULE #36: triage only; never invoke parsed shims."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_summarize_sdb_anomalies,
    )
