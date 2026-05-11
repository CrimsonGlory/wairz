"""Windows .NET MCP tools — Phase δ.7.

Surfaces the Phase δ.4 .NET decompile workflow + δ.6 R2R-stomping
detection to the MCP layer.

Six tools:

- ``list_dotnet_bundles`` — list bundles from the most-recent δ.4
  decompile run (firmware.dotnet_decompile_result.bundles).
- ``get_bundle_metadata`` — full per-bundle record including the
  ilspycmd output dir + per-bundle errors.
- ``list_extracted_assemblies`` — list .NET assemblies extracted to
  disk under one bundle's decompile_target_dir.
- ``get_assembly_il`` — read ONE assembly's IL output file (truncated
  to 30 KB per Rule #29).
- ``scan_r2r_stomping`` — run the δ.6 R2R-stomping classifier across
  every .NET PE in the firmware. Emits draft findings (NOT persisted
  yet — δ.8 wires the FindingService.emit hook).
- ``trigger_dotnet_decompile`` — Rule #33 .a 202+poll trigger.
  Idempotent + 409-on-conflict at the active state machine. Enqueues
  the δ.4 ``decompile_dotnet_bundle_job`` arq job and returns the
  current status.

Sandbox discipline (Rule #1): tools that read disk paths resolve via
``context.resolve_path()``.

Rule #36 no-execute discipline: every tool reads .NET artefacts AS DATA
via persisted DB rows or filesystem reads. The trigger tool enqueues an
arq job; the worker enforces argv discipline via ``assert_no_execute_argv``.

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.services.jsonb_normalizers import (
    _normalize_firmware_dotnet_decompile_result,
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


# ── Sync I/O helpers (call via run_in_executor) ────────────────────────────


def _walk_assemblies_sync(target_dir: str) -> tuple[bool, list[dict[str, Any]]]:
    """Sync: enumerate IL/CS decompile outputs under ``target_dir``.

    Returns ``(exists, assemblies)``. ``exists`` is False when the
    directory is missing (caller surfaces an error); ``assemblies``
    is the same shape ``_handle_list_extracted_assemblies`` emits.
    """
    if not os.path.isdir(target_dir):
        return False, []
    assemblies: list[dict[str, Any]] = []
    for dirpath, _dirs, filenames in os.walk(target_dir):
        for fn in filenames:
            if fn.endswith((".il", ".cs", ".decompiled.cs")):
                full = os.path.join(dirpath, fn)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                assemblies.append({
                    "path": os.path.relpath(full, target_dir),  # pure-string after walk
                    "size": st.st_size,
                    "kind": "il" if fn.endswith(".il") else "cs",
                })
    return True, assemblies


def _read_assembly_sync(safe_path: str, cap: int) -> tuple[bool, str]:
    """Sync: existence check + capped read of a decompiled assembly.

    Returns ``(exists, content)``. ``exists`` is False when the file is
    missing; ``content`` may be empty when read fails after the existence
    check (caller distinguishes via the boolean).
    """
    if not os.path.isfile(safe_path):
        return False, ""
    with open(safe_path, encoding="utf-8", errors="replace") as fh:
        return True, fh.read(cap + 1024)


# ── Helpers ─────────────────────────────────────────────────────────────────


async def _load_firmware(context: ToolContext) -> Firmware | None:
    if context.firmware_id is None:
        return None
    return (
        await context.db.execute(
            select(Firmware).where(Firmware.id == context.firmware_id)
        )
    ).scalar_one_or_none()


# ── Handlers ────────────────────────────────────────────────────────────────


async def _handle_list_bundles(input: dict, context: ToolContext) -> str:
    fw = await _load_firmware(context)
    if fw is None:
        return _dump_json({"error": "no active firmware"})
    aggregate = _normalize_firmware_dotnet_decompile_result(fw.dotnet_decompile_result) or {}
    bundles = aggregate.get("bundles") if isinstance(aggregate, dict) else None
    bundles = bundles if isinstance(bundles, list) else []
    summary_rows = [
        {
            "bundle_path": b.get("bundle_path"),
            "bundle_sha256": b.get("bundle_sha256"),
            "extracted_count": b.get("extracted_count", 0),
            "decompile_target_dir": b.get("decompile_target_dir"),
            "error_count": len(b.get("errors") or []),
        }
        for b in bundles if isinstance(b, dict)
    ]
    return _dump_json({
        "firmware_id": str(context.firmware_id),
        "decompile_status": fw.dotnet_decompile_status,
        "decompile_started_at": fw.dotnet_decompile_started_at,
        "decompile_finished_at": fw.dotnet_decompile_finished_at,
        "bundle_count": len(summary_rows),
        "bundles_decompiled": aggregate.get("bundles_decompiled", 0),
        "bundles_failed": aggregate.get("bundles_failed", 0),
        "bundles": summary_rows,
    })


async def _handle_get_bundle_metadata(input: dict, context: ToolContext) -> str:
    bundle_path = input["bundle_path"]
    fw = await _load_firmware(context)
    if fw is None:
        return _dump_json({"error": "no active firmware"})
    aggregate = _normalize_firmware_dotnet_decompile_result(fw.dotnet_decompile_result) or {}
    bundles = aggregate.get("bundles") or []
    for b in bundles:
        if isinstance(b, dict) and b.get("bundle_path") == bundle_path:
            return _dump_json(b)
    return _dump_json({"error": "bundle not found", "bundle_path": bundle_path})


async def _handle_list_extracted_assemblies(input: dict, context: ToolContext) -> str:
    bundle_path = input["bundle_path"]
    fw = await _load_firmware(context)
    if fw is None:
        return _dump_json({"error": "no active firmware"})
    aggregate = _normalize_firmware_dotnet_decompile_result(fw.dotnet_decompile_result) or {}
    bundles = aggregate.get("bundles") or []
    target_dir = None
    for b in bundles:
        if isinstance(b, dict) and b.get("bundle_path") == bundle_path:
            target_dir = b.get("decompile_target_dir")
            break
    if target_dir is None:
        return _dump_json({"error": "bundle not found", "bundle_path": bundle_path})
    loop = asyncio.get_running_loop()
    exists, assemblies = await loop.run_in_executor(
        None, _walk_assemblies_sync, target_dir,
    )
    if not exists:
        return _dump_json({
            "error": "decompile output directory does not exist (rebuild "
            "with INCLUDE_DOTNET=1 + re-run decompile)",
            "decompile_target_dir": target_dir,
        })
    return _dump_json({
        "bundle_path": bundle_path,
        "decompile_target_dir": target_dir,
        "assembly_count": len(assemblies),
        "assemblies": assemblies,
    })


async def _handle_get_assembly_il(input: dict, context: ToolContext) -> str:
    assembly_path = input["assembly_path"]
    safe_path = context.resolve_path(assembly_path)
    loop = asyncio.get_running_loop()
    try:
        exists, content = await loop.run_in_executor(
            None, _read_assembly_sync, safe_path, _OUTPUT_CAP_BYTES,
        )
    except Exception as exc:
        return _dump_json({"error": f"read failed: {exc}", "assembly_path": assembly_path})
    if not exists:
        return _dump_json({"error": "assembly file not found", "assembly_path": assembly_path})
    return _truncate(content)


async def _handle_scan_r2r_stomping(input: dict, context: ToolContext) -> str:
    """Run the δ.6 R2R-stomping classifier across every .NET bundle in
    the firmware's most-recent δ.4 decompile run.

    Returns the draft list (NOT persisted as Findings yet — δ.8 wires
    FindingService.emit_r2r_stomp_findings_from_decompile + extends
    ck_findings_source). Operators see the same shape they'd see post-
    persistence, scaled to today's available data.
    """
    from app.services.r2r_stomping import classify_r2r_stomp_findings

    fw = await _load_firmware(context)
    if fw is None:
        return _dump_json({"error": "no active firmware"})
    aggregate = _normalize_firmware_dotnet_decompile_result(fw.dotnet_decompile_result) or {}
    bundles = aggregate.get("bundles") or []
    drafts: list[dict[str, Any]] = []
    by_tier: dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 0}
    for b in bundles:
        if not isinstance(b, dict):
            continue
        bundle_path = b.get("bundle_path")
        decompile_root = b.get("decompile_target_dir")
        if not bundle_path:
            continue
        for d in classify_r2r_stomp_findings(bundle_path, decompile_root):
            by_tier[d.confidence_tier] = by_tier.get(d.confidence_tier, 0) + 1
            drafts.append({
                "source": d.source,
                "severity": d.severity,
                "title": d.title,
                "description": d.description,
                "evidence": d.evidence,
                "pe_path": d.pe_path,
                "confidence_tier": d.confidence_tier,
            })
    return _dump_json({
        "firmware_id": str(context.firmware_id),
        "draft_count": len(drafts),
        "by_tier": by_tier,
        "drafts": drafts,
        "note": (
            "δ.6 produces drafts only. Finding-row persistence + "
            "ck_findings_source extension lands in δ.8 (cross-stack "
            "alignment slice — Rule #25 single-slice exception #2)."
        ),
    })


async def _handle_trigger_dotnet_decompile(input: dict, context: ToolContext) -> str:
    """Rule #33 .a 202+poll trigger — idempotent + 409-on-conflict.

    If the firmware's dotnet_decompile_status is already 'queued' or
    'running', returns 409 in JSON shape. Otherwise sets status to
    'queued', clears prior result/error, and enqueues the δ.4 arq job.
    """

    fw = await _load_firmware(context)
    if fw is None:
        return _dump_json({"error": "no active firmware"})

    if fw.dotnet_decompile_status in ("queued", "running"):
        return _dump_json({
            "status_code": 409,
            "error": f"dotnet_decompile already {fw.dotnet_decompile_status}",
            "current_status": fw.dotnet_decompile_status,
            "started_at": fw.dotnet_decompile_started_at,
        })

    fw.dotnet_decompile_status = "queued"
    fw.dotnet_decompile_started_at = None
    fw.dotnet_decompile_finished_at = None
    fw.dotnet_decompile_error = None
    fw.dotnet_decompile_result = None
    await context.db.flush()

    # Enqueue via arq if available; fall back to asyncio.create_task per
    # the spawn_emulation_session_job fallback shape.
    enqueued = False
    try:
        from arq import create_pool

        from app.workers.arq_worker import get_redis_settings

        pool = await create_pool(get_redis_settings())
        await pool.enqueue_job(
            "decompile_dotnet_bundle_job",
            firmware_id=str(fw.id),
        )
        await pool.close()
        enqueued = True
    except Exception as exc:
        logger.warning("arq enqueue failed; falling back to asyncio.create_task: %s", exc)
        import asyncio

        from app.services.dotnet_decompile_service import (
            decompile_firmware_background,
        )
        asyncio.create_task(decompile_firmware_background(fw.id))

    return _dump_json({
        "status_code": 202,
        "current_status": fw.dotnet_decompile_status,
        "enqueued_via": "arq" if enqueued else "asyncio.create_task",
        "firmware_id": str(fw.id),
        "note": (
            "Poll firmware.dotnet_decompile_status for completion. "
            "Worker requires INCLUDE_DOTNET=1 at build time; without "
            "it, the run will fail with a clear error."
        ),
    })


# ── Registration ────────────────────────────────────────────────────────────


def register_windows_dotnet_tools(registry: ToolRegistry) -> None:
    """Register all 6 windows_dotnet.* tools (δ.7)."""

    registry.register(
        name="list_dotnet_bundles",
        description=(
            "List .NET single-file bundles detected in the active "
            "firmware's most-recent δ.4 decompile run. Returns the "
            "current decompile_status + bundle summaries with paths "
            "+ extracted_count + decompile_target_dir."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_list_bundles,
    )

    registry.register(
        name="get_bundle_metadata",
        description=(
            "Return the full per-bundle record from the most-recent "
            "δ.4 decompile run by bundle_path: extracted_count + "
            "decompile_target_dir + per-bundle errors."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "bundle_path": {
                    "type": "string",
                    "description": "Path of the bundle within the firmware tree (matches the bundle_path key in dotnet_decompile_result.bundles[].bundle_path)",
                },
            },
            "required": ["bundle_path"],
            "additionalProperties": False,
        },
        handler=_handle_get_bundle_metadata,
    )

    registry.register(
        name="list_extracted_assemblies",
        description=(
            "List .NET assemblies extracted to disk under one bundle's "
            "decompile_target_dir. Each entry carries path + size + "
            "kind (.il / .cs). Operator's drill-down view from "
            "list_dotnet_bundles."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "bundle_path": {
                    "type": "string",
                    "description": "Path of the bundle (matches bundle_path in dotnet_decompile_result.bundles[].bundle_path)",
                },
            },
            "required": ["bundle_path"],
            "additionalProperties": False,
        },
        handler=_handle_list_extracted_assemblies,
    )

    registry.register(
        name="get_assembly_il",
        description=(
            "Read ONE assembly's IL output file (decompile artefact). "
            "Path is resolved via the sandbox helper (Rule #1) and "
            "must live under the firmware's extraction root. Output "
            "is truncated to 30 KB per Rule #29; very large IL files "
            "show a tail-truncation marker."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "assembly_path": {
                    "type": "string",
                    "description": "Path to the .il / .cs file within the firmware extraction root",
                },
            },
            "required": ["assembly_path"],
            "additionalProperties": False,
        },
        handler=_handle_get_assembly_il,
    )

    registry.register(
        name="scan_r2r_stomping",
        description=(
            "Run the δ.6 R2R-stomping classifier across every .NET "
            "bundle in the firmware's most-recent δ.4 decompile run. "
            "Returns draft findings (NOT yet persisted — δ.8 wires "
            "FindingService.emit + extends ck_findings_source) with "
            "the by-tier histogram. Tier 1 = R2R-eligible review "
            "candidate (LOW); Tier 2 = capa/IL divergence (MEDIUM); "
            "Tier 3/4 reserved for future deeper detection."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_scan_r2r_stomping,
    )

    registry.register(
        name="trigger_dotnet_decompile",
        description=(
            "Rule #33 .a 202+poll trigger: enqueue the δ.4 arq job to "
            "decompile every .NET single-file bundle in the active "
            "firmware. Idempotent + 409-on-conflict — if "
            "dotnet_decompile_status is already 'queued' or 'running', "
            "the trigger is rejected with HTTP 409 semantics in JSON. "
            "Otherwise sets status to 'queued', clears prior result/"
            "error, and enqueues the arq job. Worker requires "
            "INCLUDE_DOTNET=1 at build time."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_dotnet_decompile,
    )
