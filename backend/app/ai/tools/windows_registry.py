"""Windows registry MCP tools — Phase γ.6.

Surfaces the Phase γ.4 registry-walk verdicts to the MCP layer:

- ``list_hives`` — list every WindowsRegistryExtract row for the active
  firmware (each row = one walked hive).
- ``walk_hive`` — re-walk one hive on demand and return the parsed_tree
  shape (delegates to ``registry_hive_walker.walk_hive_path``).
- ``get_run_keys`` — extract the persistence-relevant Run / RunOnce
  / IFEO keys from a hive.
- ``scan_persistence`` — surface every persistence-related subkey
  across every hive in the firmware (operator's persistence-rollup
  view per Persona-E #13).
- ``dump_subkey`` — return the subkey + values at a specific path
  inside a hive.
- ``diff_hives`` — diff two hives by subkey-set difference (lhs only,
  rhs only, both — values).
- ``trigger_walk`` — trigger the 202+polling registry-hive-walk
  background runner for the active firmware (γ.3 status set;
  Rule #33 .a 409-on-conflict idempotency).

Sandbox discipline (Rule #1): every input ``path`` referencing a hive
on disk is resolved via ``context.resolve_path()`` before any read.

Rule #36 no-execute discipline: every tool reads the hive AS DATA via
regipy or via persisted parsed_tree JSONB; nothing in this module
invokes regedit / .reg apply / scriptable action paths.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps emit
a tail-truncation marker.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_registry_extract import WindowsRegistryExtract
from app.services.jsonb_normalizers import (
    _normalize_windows_registry_extracts_parsed_tree,
)


logger = logging.getLogger(__name__)


# ── 30 KB output cap (Rule #29) ─────────────────────────────────────────────
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text) <= cap:
        return text
    keep = cap - 80
    return text[:keep] + f"\n... [truncated; {len(text) - keep} more bytes]\n"


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    return str(obj)


def _dump_json(payload: Any) -> str:
    return _truncate(json.dumps(payload, indent=2, default=_json_default))


# ── Persistence-relevant subkey-path patterns ────────────────────────────────
#
# Persona-E #13 ranks the registry persistence vectors that operators
# triage first. The list below is the canonical set the scan_persistence
# / get_run_keys tools surface; case-insensitive substring match against
# the parsed subkey path.
_PERSISTENCE_PATH_PATTERNS: tuple[str, ...] = (
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\runservices",
    "currentversion\\runservicesonce",
    "currentversion\\windows\\appinit_dlls",
    "image file execution options",
    "currentversion\\winlogon",
    "currentversion\\explorer\\shellexecutehooks",
    "session manager\\bootexecute",
    "currentversion\\policies\\explorer\\run",
    "active setup\\installed components",
    "currentcontrolset\\services",
)


# ── Helpers ──────────────────────────────────────────────────────────────────


async def _load_firmware_extracts(
    context: ToolContext,
) -> list[tuple[WindowsRegistryExtract, HardwareFirmwareBlob]]:
    """Load every (extract, blob) pair for the active firmware."""
    stmt = (
        select(WindowsRegistryExtract, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsRegistryExtract.blob_id == HardwareFirmwareBlob.id,
        )
        .where(HardwareFirmwareBlob.firmware_id == context.firmware_id)
        .order_by(WindowsRegistryExtract.hive_path)
    )
    rows = (await context.db.execute(stmt)).all()
    return [(extract, blob) for extract, blob in rows]


async def _load_extract_by_hive_path(
    context: ToolContext, hive_path: str,
) -> tuple[WindowsRegistryExtract, HardwareFirmwareBlob] | None:
    stmt = (
        select(WindowsRegistryExtract, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsRegistryExtract.blob_id == HardwareFirmwareBlob.id,
        )
        .where(
            HardwareFirmwareBlob.firmware_id == context.firmware_id,
            WindowsRegistryExtract.hive_path == hive_path,
        )
    )
    row = (await context.db.execute(stmt)).first()
    if row is None:
        return None
    return row[0], row[1]


def _extract_persistence_entries(parsed_tree: dict[str, Any]) -> list[dict[str, Any]]:
    """Return subkeys whose path matches a persistence pattern.

    Case-insensitive substring match; iterates the canonical
    parsed_tree subkey list.
    """
    out: list[dict[str, Any]] = []
    for sk in parsed_tree.get("subkeys", []) or []:
        path_lower = (sk.get("path") or "").lower()
        if any(p in path_lower for p in _PERSISTENCE_PATH_PATTERNS):
            out.append(sk)
    return out


def _extract_subkey_at_path(
    parsed_tree: dict[str, Any], target_path: str,
) -> dict[str, Any] | None:
    """Return the subkey entry whose normalised path matches ``target_path``.

    Both inputs are normalised: leading backslash trimmed,
    case-folded, and backslash-only delimiter so caller can pass either
    ``"Microsoft\\Windows\\CurrentVersion\\Run"`` or
    ``"\\Microsoft\\Windows\\CurrentVersion\\Run"`` and get a match.
    """
    def _norm(s: str) -> str:
        return s.lstrip("\\").lower()

    target_norm = _norm(target_path)
    for sk in parsed_tree.get("subkeys", []) or []:
        if _norm(sk.get("path") or "") == target_norm:
            return sk
    return None


# ── Handlers ─────────────────────────────────────────────────────────────────


async def _handle_list_hives(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """List every persisted registry hive walked for the active firmware."""
    rows = await _load_firmware_extracts(context)
    payload = []
    for extract, blob in rows:
        payload.append(
            {
                "hive_path": extract.hive_path,
                "hive_type": extract.hive_type,
                "blob_path": blob.blob_path,
                "key_count": extract.key_count,
                "value_count": extract.value_count,
                "walk_status": extract.walk_status,
                "walk_error": extract.walk_error,
                "extract_id": extract.id,
            }
        )
    return _dump_json({"firmware_id": context.firmware_id, "hives": payload})


async def _handle_walk_hive(input: dict, context: ToolContext) -> str:
    """Re-walk a hive on demand and return the parsed_tree.

    The walker re-reads the hive from disk via the existing detection
    root; useful when the operator wants the raw walker output without
    consulting the persisted row, OR when the persisted row is from
    an older walker version.
    """
    hive_disk_path_input = input.get("path")
    if not hive_disk_path_input:
        return "Error: 'path' parameter required (path to hive within firmware tree)"
    # Sandbox the path through the firmware extraction root.
    resolved = context.resolve_path(hive_disk_path_input)

    # Lazy import — registry_hive_walker pulls regipy.
    from app.services.registry_hive_walker import walk_hive_path

    loop = asyncio.get_running_loop()
    parsed = await loop.run_in_executor(None, walk_hive_path, resolved)
    return _dump_json(parsed)


async def _handle_get_run_keys(input: dict, context: ToolContext) -> str:
    """Return the Run / RunOnce / IFEO subkey set across all hives, OR
    just one hive if ``hive_path`` is given."""
    hive_path_filter = input.get("hive_path")

    if hive_path_filter:
        loaded = await _load_extract_by_hive_path(context, hive_path_filter)
        if loaded is None:
            return f"Error: no walked hive at hive_path={hive_path_filter!r} for active firmware"
        rows = [loaded]
    else:
        rows = await _load_firmware_extracts(context)

    payload = []
    for extract, _blob in rows:
        parsed = _normalize_windows_registry_extracts_parsed_tree(extract.parsed_tree)
        if parsed is None:
            continue
        run_keys = [
            sk for sk in parsed.get("subkeys", []) or []
            if "currentversion\\run" in (sk.get("path") or "").lower()
        ]
        if run_keys:
            payload.append(
                {
                    "hive_path": extract.hive_path,
                    "hive_type": extract.hive_type,
                    "run_keys": run_keys,
                }
            )
    return _dump_json({"firmware_id": context.firmware_id, "hives": payload})


async def _handle_scan_persistence(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """Surface every persistence-related subkey across every hive.

    Returns one entry per (hive, persistent-subkey) pair so the
    operator sees the full persistence surface in one view.
    """
    rows = await _load_firmware_extracts(context)
    payload: list[dict[str, Any]] = []
    for extract, _blob in rows:
        parsed = _normalize_windows_registry_extracts_parsed_tree(extract.parsed_tree)
        if parsed is None:
            continue
        entries = _extract_persistence_entries(parsed)
        for entry in entries:
            payload.append(
                {
                    "hive_path": extract.hive_path,
                    "hive_type": extract.hive_type,
                    "subkey_path": entry.get("path"),
                    "values": entry.get("values"),
                }
            )
    return _dump_json(
        {
            "firmware_id": context.firmware_id,
            "persistence_entries": payload,
            "entry_count": len(payload),
        }
    )


async def _handle_dump_subkey(input: dict, context: ToolContext) -> str:
    """Return the values at a specific subkey path inside one hive."""
    hive_path = input.get("hive_path")
    subkey_path = input.get("subkey_path")
    if not hive_path or not subkey_path:
        return (
            "Error: both 'hive_path' (which hive) and 'subkey_path' "
            "(which subkey within the hive) are required"
        )

    loaded = await _load_extract_by_hive_path(context, hive_path)
    if loaded is None:
        return f"Error: no walked hive at hive_path={hive_path!r} for active firmware"
    extract, _blob = loaded
    parsed = _normalize_windows_registry_extracts_parsed_tree(extract.parsed_tree)
    if parsed is None:
        return _dump_json(
            {"hive_path": hive_path, "subkey_path": subkey_path, "values": None}
        )

    sk = _extract_subkey_at_path(parsed, subkey_path)
    if sk is None:
        return _dump_json(
            {
                "hive_path": hive_path,
                "subkey_path": subkey_path,
                "values": None,
                "note": "subkey not present in parsed_tree (depth/key cap may have excluded it)",
            }
        )
    return _dump_json(
        {
            "hive_path": hive_path,
            "subkey_path": sk.get("path"),
            "values": sk.get("values"),
        }
    )


async def _handle_diff_hives(input: dict, context: ToolContext) -> str:
    """Diff two hives by subkey-set difference.

    Returns three keys:
    - ``lhs_only``: subkeys present in ``lhs_hive_path`` but not ``rhs_hive_path``
    - ``rhs_only``: subkeys present in ``rhs_hive_path`` but not ``lhs_hive_path``
    - ``both_changed``: subkeys present in both with DIFFERENT value sets
    """
    lhs = input.get("lhs_hive_path")
    rhs = input.get("rhs_hive_path")
    if not lhs or not rhs:
        return (
            "Error: both 'lhs_hive_path' and 'rhs_hive_path' are required "
            "(the two hives to compare; both must already be walked for "
            "the active firmware)"
        )

    lhs_loaded = await _load_extract_by_hive_path(context, lhs)
    rhs_loaded = await _load_extract_by_hive_path(context, rhs)
    if lhs_loaded is None:
        return f"Error: no walked hive at lhs_hive_path={lhs!r}"
    if rhs_loaded is None:
        return f"Error: no walked hive at rhs_hive_path={rhs!r}"

    lhs_extract = lhs_loaded[0]
    rhs_extract = rhs_loaded[0]
    lhs_parsed = _normalize_windows_registry_extracts_parsed_tree(
        lhs_extract.parsed_tree
    ) or {"subkeys": []}
    rhs_parsed = _normalize_windows_registry_extracts_parsed_tree(
        rhs_extract.parsed_tree
    ) or {"subkeys": []}

    lhs_by_path = {
        sk["path"]: sk for sk in lhs_parsed.get("subkeys", []) or []
        if sk.get("path")
    }
    rhs_by_path = {
        sk["path"]: sk for sk in rhs_parsed.get("subkeys", []) or []
        if sk.get("path")
    }

    lhs_only = sorted(set(lhs_by_path) - set(rhs_by_path))
    rhs_only = sorted(set(rhs_by_path) - set(lhs_by_path))
    common_paths = set(lhs_by_path) & set(rhs_by_path)
    both_changed = []
    for path in sorted(common_paths):
        lhs_values = lhs_by_path[path].get("values") or []
        rhs_values = rhs_by_path[path].get("values") or []
        if lhs_values != rhs_values:
            both_changed.append(
                {"path": path, "lhs_values": lhs_values, "rhs_values": rhs_values}
            )

    return _dump_json(
        {
            "lhs_hive_path": lhs,
            "rhs_hive_path": rhs,
            "lhs_only": lhs_only,
            "rhs_only": rhs_only,
            "both_changed": both_changed,
            "summary": {
                "lhs_only_count": len(lhs_only),
                "rhs_only_count": len(rhs_only),
                "both_changed_count": len(both_changed),
            },
        }
    )


async def _handle_trigger_walk(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """Trigger the registry-hive-walk 202+polling background runner
    (Rule #33 contract) for the active firmware.

    Returns immediately with the current status. The background runner
    walks every hive in the firmware's detection roots, persists per-
    hive WindowsRegistryExtract rows + the aggregate result on
    firmware.registry_hive_walk_result.

    Per Rule #33 .a — idempotent: if a walk is already queued or
    running, returns 409-shape error rather than spawning a duplicate.
    """
    firmware = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == context.firmware_id)
        )
    ).scalar_one_or_none()
    if firmware is None:
        return f"Error: firmware_id={context.firmware_id} not found"

    if firmware.registry_hive_walk_status in ("queued", "running"):
        return _dump_json(
            {
                "status": firmware.registry_hive_walk_status,
                "message": (
                    f"Registry hive walk already {firmware.registry_hive_walk_status} "
                    f"for firmware {context.firmware_id}; not re-queueing "
                    f"(Rule #33 .a idempotency)"
                ),
                "started_at": firmware.registry_hive_walk_started_at,
            }
        )

    firmware.registry_hive_walk_status = "queued"
    firmware.registry_hive_walk_started_at = None
    firmware.registry_hive_walk_finished_at = None
    firmware.registry_hive_walk_error = None
    firmware.registry_hive_walk_result = None
    await context.db.flush()

    # Lazy import + create_task per Rule #33 .d (in-process dispatch).
    from app.services.registry_hive_walker import _run_registry_hive_walk_background

    asyncio.create_task(_run_registry_hive_walk_background(context.firmware_id))
    return _dump_json(
        {
            "status": "queued",
            "firmware_id": context.firmware_id,
            "message": "Registry hive walk queued; poll list_hives until walk_status=='completed'",
        }
    )


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_registry_tools(registry: ToolRegistry) -> None:
    """Register all Phase γ.6 Windows registry MCP tools."""

    registry.register(
        name="list_hives",
        description=(
            "List every Windows registry hive walked for the active "
            "firmware. Returns one row per hive with hive_path, "
            "hive_type (SOFTWARE/SYSTEM/SAM/SECURITY/NTUSER/etc.), "
            "key_count, value_count, walk_status (completed | partial "
            "| failed | skipped), walk_error. Read-only; does not "
            "trigger a re-walk (use trigger_walk for that)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_list_hives,
    )

    registry.register(
        name="walk_hive",
        description=(
            "Re-walk a Windows registry hive on demand via regipy and "
            "return the parsed_tree (key/value tree under the canonical "
            "Phase γ.4 schema). Useful when the persisted row is from "
            "an older walker version OR you want the raw walker output "
            "without consulting the DB. Path must be inside the active "
            "firmware's extraction root (Rule #1 sandbox)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to the hive file inside the firmware "
                        "extraction tree (e.g. 'Windows/System32/config/SOFTWARE')."
                    ),
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        handler=_handle_walk_hive,
    )

    registry.register(
        name="get_run_keys",
        description=(
            "Return the Run / RunOnce / RunServices / IFEO subkey set "
            "for one hive (when hive_path is provided) OR every walked "
            "hive of the active firmware. Surfaces the persistence-"
            "relevant subkeys operators triage first per Persona-E #13."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hive_path": {
                    "type": "string",
                    "description": (
                        "Optional: filter to one hive (e.g. "
                        "'Windows/System32/config/SOFTWARE'). Omit to "
                        "scan every walked hive of the active firmware."
                    ),
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_get_run_keys,
    )

    registry.register(
        name="scan_persistence",
        description=(
            "Surface every persistence-related subkey across every "
            "walked hive of the active firmware. Returns one entry "
            "per (hive, subkey) pair covering Run/RunOnce/RunServices, "
            "AppInit_DLLs, Image File Execution Options, Winlogon "
            "shellexecute hooks, Session Manager BootExecute, Active "
            "Setup Installed Components, and CurrentControlSet\\Services. "
            "Per Persona-E #13 persistence-rollup workflow."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_scan_persistence,
    )

    registry.register(
        name="dump_subkey",
        description=(
            "Return the values at a specific subkey path inside one "
            "hive. Useful when you've identified a key of interest via "
            "scan_persistence / get_run_keys and want the full value "
            "set without re-paging through list_hives → walk_hive."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hive_path": {
                    "type": "string",
                    "description": "Which hive (e.g. 'Windows/System32/config/SOFTWARE')",
                },
                "subkey_path": {
                    "type": "string",
                    "description": (
                        "Subkey path within the hive, backslash-separated "
                        "(e.g. 'Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'). "
                        "Leading backslash optional; case-insensitive."
                    ),
                },
            },
            "required": ["hive_path", "subkey_path"],
            "additionalProperties": False,
        },
        handler=_handle_dump_subkey,
    )

    registry.register(
        name="diff_hives",
        description=(
            "Diff two walked hives by subkey-set difference + value "
            "comparison. Returns lhs_only, rhs_only, and both_changed "
            "(subkeys present in both with different value sets). "
            "Useful for comparing pre/post-update SYSTEM hives or "
            "detecting drift across firmware revisions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "lhs_hive_path": {
                    "type": "string",
                    "description": "First hive to compare (left side of the diff)",
                },
                "rhs_hive_path": {
                    "type": "string",
                    "description": "Second hive to compare (right side of the diff)",
                },
            },
            "required": ["lhs_hive_path", "rhs_hive_path"],
            "additionalProperties": False,
        },
        handler=_handle_diff_hives,
    )

    registry.register(
        name="trigger_registry_hive_walk",
        description=(
            "Trigger the Phase γ.3 batch registry-hive-walk 202+polling "
            "background runner for the active firmware. Returns immediately "
            "with status='queued' (Rule #33 .a 409-shape conflict if a "
            "walk is already queued/running). The background runner walks "
            "every hive in the firmware's detection roots, persists per-"
            "hive WindowsRegistryExtract rows + the aggregate result. "
            "Poll list_hives until walk_status=='completed'."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_walk,
    )
