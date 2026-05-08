"""Windows-Update MCP tools — Phase δ.7.

Surfaces the Phase δ.1 windows_update_packages records + the δ.5 per-DLL
diff rows + the δ.3 firmware.windows_update_diff_* status set to the MCP
layer.

Five tools:

- ``list_packages`` — list every WindowsUpdatePackage row for the active
  firmware (compact summary: kb_id + package_type + supersedence + path).
- ``get_package_metadata`` — full per-package record (parsed manifest +
  supersedence chain + applicability + file BOM via the Rule #35c
  normaliser).
- ``get_supersedence_chain`` — supersedence chain for one KB, traversing
  forward (what supersedes this) AND backward (what does this supersede).
- ``list_kb_files`` — flatten the package's file BOM filtered to PE
  artefacts (.dll / .exe / .sys) — the operator's "what binaries are in
  this KB" view.
- ``diff_kb_packages`` — diff two KB packages' file lists by SHA256.
  Returns added / removed / modified / unchanged categories plus the
  per-DLL row count from windows_update_dll_diffs (δ.5).

Sandbox discipline (Rule #1): tools that read disk paths resolve via
``context.resolve_path()``.

Rule #36 no-execute discipline: every tool reads persisted DB rows or
parsed metadata. Nothing in this module invokes setup.exe / wusa.exe /
dism.exe.

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_update_dll_diff import WindowsUpdateDllDiff
from app.models.windows_update_package import WindowsUpdatePackage
from app.services.jsonb_normalizers import (
    _normalize_windows_update_packages_update_metadata,
)


logger = logging.getLogger(__name__)


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


# ── Helpers ─────────────────────────────────────────────────────────────────


async def _load_firmware_packages(
    context: ToolContext,
) -> list[tuple[WindowsUpdatePackage, HardwareFirmwareBlob]]:
    """Load every (package, blob) pair for the active firmware."""
    stmt = (
        select(WindowsUpdatePackage, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsUpdatePackage.blob_id == HardwareFirmwareBlob.id,
        )
        .where(HardwareFirmwareBlob.firmware_id == context.firmware_id)
        .order_by(WindowsUpdatePackage.release_date.desc().nullslast())
    )
    rows = (await context.db.execute(stmt)).all()
    return [(pkg, blob) for pkg, blob in rows]


def _package_summary(pkg: WindowsUpdatePackage) -> dict[str, Any]:
    """Compact per-package shape for list_packages."""
    return {
        "id": pkg.id,
        "package_path": pkg.package_path,
        "package_type": pkg.package_type,
        "kb_id": pkg.kb_id,
        "superseded_by_kb": pkg.superseded_by_kb,
        "release_date": pkg.release_date,
    }


# ── Handlers ────────────────────────────────────────────────────────────────


async def _handle_list_packages(input: dict, context: ToolContext) -> str:
    pkgs = await _load_firmware_packages(context)
    package_filter = input.get("package_type_filter")
    kb_filter = input.get("kb_id_filter")
    rows = []
    for pkg, _blob in pkgs:
        if package_filter and pkg.package_type != package_filter:
            continue
        if kb_filter and pkg.kb_id != kb_filter:
            continue
        rows.append(_package_summary(pkg))
    return _dump_json({"firmware_id": str(context.firmware_id), "count": len(rows), "packages": rows})


async def _handle_get_package_metadata(input: dict, context: ToolContext) -> str:
    package_path = input["package_path"]
    stmt = (
        select(WindowsUpdatePackage, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsUpdatePackage.blob_id == HardwareFirmwareBlob.id,
        )
        .where(
            HardwareFirmwareBlob.firmware_id == context.firmware_id,
            WindowsUpdatePackage.package_path == package_path,
        )
    )
    row = (await context.db.execute(stmt)).first()
    if row is None:
        return _dump_json({"error": "package not found", "package_path": package_path})
    pkg, _blob = row
    metadata = _normalize_windows_update_packages_update_metadata(pkg.update_metadata)
    return _dump_json({
        "package_path": pkg.package_path,
        "package_type": pkg.package_type,
        "kb_id": pkg.kb_id,
        "superseded_by_kb": pkg.superseded_by_kb,
        "release_date": pkg.release_date,
        "update_metadata": metadata,
    })


async def _handle_get_supersedence_chain(input: dict, context: ToolContext) -> str:
    kb_id = input["kb_id"]
    pkgs = await _load_firmware_packages(context)
    by_kb: dict[str, WindowsUpdatePackage] = {p.kb_id: p for p, _b in pkgs if p.kb_id}
    if kb_id not in by_kb:
        return _dump_json({"error": "kb_id not found in firmware packages", "kb_id": kb_id})
    target = by_kb[kb_id]
    meta = _normalize_windows_update_packages_update_metadata(target.update_metadata) or {}
    sup = meta.get("supersedence") if isinstance(meta, dict) else None
    sup = sup if isinstance(sup, dict) else {"supersedes": [], "superseded_by": []}
    return _dump_json({
        "kb_id": kb_id,
        "package_path": target.package_path,
        "supersedes": sup.get("supersedes", []),
        "superseded_by": sup.get("superseded_by", []),
        "release_date": target.release_date,
    })


async def _handle_list_kb_files(input: dict, context: ToolContext) -> str:
    package_path = input["package_path"]
    stmt = (
        select(WindowsUpdatePackage)
        .join(
            HardwareFirmwareBlob,
            WindowsUpdatePackage.blob_id == HardwareFirmwareBlob.id,
        )
        .where(
            HardwareFirmwareBlob.firmware_id == context.firmware_id,
            WindowsUpdatePackage.package_path == package_path,
        )
    )
    pkg = (await context.db.execute(stmt)).scalar_one_or_none()
    if pkg is None:
        return _dump_json({"error": "package not found", "package_path": package_path})
    meta = _normalize_windows_update_packages_update_metadata(pkg.update_metadata) or {}
    files = meta.get("files") if isinstance(meta, dict) else None
    if not isinstance(files, list):
        files = []
    pe_only = [
        f for f in files
        if isinstance(f, dict) and isinstance(f.get("path"), str)
        and f["path"].lower().endswith((".dll", ".exe", ".sys"))
    ]
    return _dump_json({
        "package_path": pkg.package_path,
        "kb_id": pkg.kb_id,
        "pe_count": len(pe_only),
        "files": pe_only,
    })


async def _handle_diff_kb_packages(input: dict, context: ToolContext) -> str:
    older_kb = input["older_kb"]
    newer_kb = input["newer_kb"]
    # Pull rows for both KBs.
    pkgs = await _load_firmware_packages(context)
    by_kb: dict[str, WindowsUpdatePackage] = {p.kb_id: p for p, _b in pkgs if p.kb_id}
    if older_kb not in by_kb or newer_kb not in by_kb:
        return _dump_json({
            "error": "one or both KB IDs not found in firmware",
            "older_kb": older_kb,
            "newer_kb": newer_kb,
        })

    # Surface the persisted per-DLL rows from δ.5 (windows_update_dll_diffs)
    # for the firmware. The δ.5 runner produces (firmware-wide) diffs;
    # we filter to the requested pair via the older_kb / newer_kb columns.
    diff_stmt = select(WindowsUpdateDllDiff).where(
        WindowsUpdateDllDiff.firmware_id == context.firmware_id,
        WindowsUpdateDllDiff.older_kb == older_kb,
        WindowsUpdateDllDiff.newer_kb == newer_kb,
    )
    diff_rows = (await context.db.execute(diff_stmt)).scalars().all()
    by_type: dict[str, int] = {"added": 0, "removed": 0, "modified": 0, "unchanged": 0}
    sample_rows: list[dict[str, Any]] = []
    for row in diff_rows:
        by_type[row.diff_type] = by_type.get(row.diff_type, 0) + 1
        if len(sample_rows) < 50:
            sample_rows.append({
                "dll_path": row.dll_path,
                "diff_type": row.diff_type,
                "older_sha256": row.older_sha256,
                "newer_sha256": row.newer_sha256,
                "file_size_delta": row.file_size_delta,
            })
    return _dump_json({
        "older_kb": older_kb,
        "newer_kb": newer_kb,
        "total_dlls": sum(by_type.values()),
        "by_type": by_type,
        "sample_rows": sample_rows,
        "note": (
            "DLL rows persist from the most-recent δ.5 update-diff run. "
            "Trigger a new run via firmware.windows_update_diff_* (Rule "
            "#33 .a 202+poll trigger) when packages change."
        ) if not diff_rows else None,
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_update_tools(registry: ToolRegistry) -> None:
    """Register all 5 windows_update.* tools (δ.7)."""

    registry.register(
        name="list_update_packages",
        description=(
            "List every detected Windows-Update package in the active "
            "firmware's hardware-firmware blobs. Returns compact summaries "
            "with kb_id + package_type + supersedence + path. Optional "
            "filters by package_type and kb_id."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "package_type_filter": {
                    "type": "string",
                    "description": "Optional: filter to one package_type "
                    "(msu / cab_cumulative / cab_security / cab_sru / "
                    "cab_lcu / cab_dotnet / msi / msix / unknown)",
                },
                "kb_id_filter": {
                    "type": "string",
                    "description": "Optional: filter to one KB ID (e.g. 'KB5036893')",
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_packages,
    )

    registry.register(
        name="get_package_metadata",
        description=(
            "Return the full WindowsUpdatePackage record for one package "
            "by its package_path: parsed manifest (title / description / "
            "support_url) + supersedence chain (both directions) + "
            "applicability (products / architectures / release_channels) "
            "+ file BOM with per-file SHA256."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "package_path": {
                    "type": "string",
                    "description": "Path within the blob's extracted tree (matches WindowsUpdatePackage.package_path)",
                },
            },
            "required": ["package_path"],
            "additionalProperties": False,
        },
        handler=_handle_get_package_metadata,
    )

    registry.register(
        name="get_supersedence_chain",
        description=(
            "Return the supersedence chain for one KB ID across both "
            "directions: ``supersedes`` (KB IDs this package replaces) "
            "and ``superseded_by`` (KB IDs that replace this package). "
            "Useful for the operator's 'is this KB still effective?' "
            "filter and for tracing the upgrade lineage of a specific "
            "binary across multiple firmwares."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "kb_id": {
                    "type": "string",
                    "description": "KB ID to look up (e.g. 'KB5036893')",
                },
            },
            "required": ["kb_id"],
            "additionalProperties": False,
        },
        handler=_handle_get_supersedence_chain,
    )

    registry.register(
        name="list_kb_files",
        description=(
            "Return the file BOM for one Windows-Update package, "
            "filtered to PE artefacts (.dll / .exe / .sys). Each "
            "entry carries path / size / sha256 / is_pe / kind so "
            "the operator can pick a target binary to drill into "
            "without re-walking the package."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "package_path": {
                    "type": "string",
                    "description": "Path within the blob's extracted tree (matches WindowsUpdatePackage.package_path)",
                },
            },
            "required": ["package_path"],
            "additionalProperties": False,
        },
        handler=_handle_list_kb_files,
    )

    registry.register(
        name="diff_kb_packages",
        description=(
            "Diff two KB packages within the active firmware. Returns "
            "the by-type histogram (added / removed / modified / "
            "unchanged) + up to 50 sample per-DLL rows from the "
            "windows_update_dll_diffs table (δ.5 runner output). If "
            "the persisted rows don't exist, prompts the operator to "
            "trigger a new windows_update_diff run via the Rule #33 "
            ".a 202+poll trigger."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "older_kb": {
                    "type": "string",
                    "description": "KB ID for the older side of the diff",
                },
                "newer_kb": {
                    "type": "string",
                    "description": "KB ID for the newer side of the diff",
                },
            },
            "required": ["older_kb", "newer_kb"],
            "additionalProperties": False,
        },
        handler=_handle_diff_kb_packages,
    )
