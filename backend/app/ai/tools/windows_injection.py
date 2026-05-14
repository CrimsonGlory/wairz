"""Windows injection MCP tools — Phase λ.γ.C.

Surfaces the Phase λ.γ walker's per-detection records and the
per-firmware aggregate to the MCP layer.

Tools:

- ``list_windows_injection_detections`` — paginate the per-detection
  rows for the active firmware. Filters: detection_kind, pid,
  image_filename (exact), hexdump_sha256 (exact, for "find the same
  injection in this firmware").
- ``windows_injection_walk_status`` — Rule #33 status reader.
- ``trigger_windows_injection_walk`` — Rule #33 .a idempotent POST
  with 409-on-conflict.
- ``lookup_volatility_injection_across_firmwares`` — **Rule #44 cross-
  firmware aggregation** keyed on ``hexdump_sha256`` (SHA256 of the
  first 64 bytes of malfind's hexdump). The strongest cross-firmware
  signal of any λ-stream walker: an injection appearing in multiple
  firmware captures with the same first-64-bytes-hash is the canonical
  threat-actor TTP-reuse signal. ``supply_chain_signal=True`` when
  match_count >= 2.

Sandbox discipline (Rule #1): no path inputs. The walker resolves
paths via get_detection_roots; this MCP layer reads persisted rows.

Rule #36 / #45 reminder: tools read records AS DATA. The cross-firmware
tool keys on a SHA256 of a hex string; it NEVER fetches any binary,
NEVER attempts to deobfuscate injected code, NEVER invokes a region
for execution.
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
from app.models.volatility_injection_record import VolatilityInjectionRecord
from app.services.jsonb_normalizers import (
    _normalize_firmware_windows_injection_walk_result,
    _normalize_volatility_injection_records_evidence,
)

logger = logging.getLogger(__name__)


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


_VALID_DETECTION_KINDS: frozenset[str] = frozenset(
    {
        "injected_code_region",
        "hollow_process",
        "unlinked_module",
        "peb_masquerade",
        "ghosted_process",
    }
)


def _row_to_dict(row: VolatilityInjectionRecord) -> dict:
    evidence = _normalize_volatility_injection_records_evidence(row.evidence)
    return {
        "id": str(row.id),
        "memory_image_id": str(row.memory_image_id),
        "detection_kind": row.detection_kind,
        "detected_by_plugin": row.detected_by_plugin,
        "pid": row.pid,
        "image_filename": row.image_filename,
        "region_address": row.region_address,
        "region_size": row.region_size,
        "region_protection": row.region_protection,
        "hexdump_first_64_bytes": row.hexdump_first_64_bytes,
        "hexdump_sha256": row.hexdump_sha256,
        "masquerade_path": row.masquerade_path,
        "actual_path": row.actual_path,
        "module_name": row.module_name,
        "ghosted_path": row.ghosted_path,
        "evidence": evidence,
    }


# ── list_windows_injection_detections ─────────────────────────────────────


async def _handle_list_windows_injection_detections(
    input: dict, context: ToolContext
) -> str:
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    detection_kind = input.get("detection_kind")
    pid_in = input.get("pid")
    image_filename = input.get("image_filename")
    hexdump_sha256 = input.get("hexdump_sha256")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if detection_kind is not None and detection_kind not in _VALID_DETECTION_KINDS:
        return json.dumps(
            {
                "error": (
                    f"invalid detection_kind {detection_kind!r}; allowed: "
                    f"{sorted(_VALID_DETECTION_KINDS)}"
                )
            }
        )

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    where = [VolatilityInjectionRecord.firmware_id == firmware_id]
    if detection_kind:
        where.append(VolatilityInjectionRecord.detection_kind == detection_kind)
    if pid_in is not None:
        try:
            where.append(VolatilityInjectionRecord.pid == int(pid_in))
        except (TypeError, ValueError):
            return json.dumps({"error": f"invalid pid: {pid_in!r}"})
    if image_filename:
        where.append(
            VolatilityInjectionRecord.image_filename == image_filename
        )
    if hexdump_sha256:
        where.append(
            VolatilityInjectionRecord.hexdump_sha256 == hexdump_sha256
        )

    total = (
        await context.db.execute(
            select(sa_func.count(VolatilityInjectionRecord.id)).where(*where)
        )
    ).scalar_one()

    rows = (
        (
            await context.db.execute(
                select(VolatilityInjectionRecord)
                .where(*where)
                .order_by(
                    VolatilityInjectionRecord.detection_kind.asc(),
                    VolatilityInjectionRecord.pid.asc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "records": [_row_to_dict(r) for r in rows],
        "filters": {
            "detection_kind": detection_kind,
            "pid": pid_in,
            "image_filename": image_filename,
            "hexdump_sha256": hexdump_sha256,
        },
    }
    if total == 0:
        out["message"] = (
            "No injection detections match. The walker may not have run yet "
            "(call trigger_windows_injection_walk and poll "
            "windows_injection_walk_status), or your filters may be too "
            "narrow."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── windows_injection_walk_status ─────────────────────────────────────────


async def _handle_windows_injection_walk_status(
    input: dict, context: ToolContext
) -> str:
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
        "status": row.windows_injection_walk_status,
        "started_at": (
            row.windows_injection_walk_started_at.isoformat()
            if row.windows_injection_walk_started_at
            else None
        ),
        "finished_at": (
            row.windows_injection_walk_finished_at.isoformat()
            if row.windows_injection_walk_finished_at
            else None
        ),
        "error": row.windows_injection_walk_error,
        "result": _normalize_firmware_windows_injection_walk_result(
            row.windows_injection_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_windows_injection_walk ────────────────────────────────────────


async def _handle_trigger_windows_injection_walk(
    input: dict, context: ToolContext
) -> str:
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

    if row.windows_injection_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.windows_injection_walk_status,
                "started_at": (
                    row.windows_injection_walk_started_at.isoformat()
                    if row.windows_injection_walk_started_at
                    else None
                ),
                "message": (
                    f"Windows injection walk already "
                    f"{row.windows_injection_walk_status} for firmware "
                    f"{firmware_id}. Poll windows_injection_walk_status."
                ),
            }
        )

    row.windows_injection_walk_status = "queued"
    row.windows_injection_walk_started_at = None
    row.windows_injection_walk_finished_at = None
    row.windows_injection_walk_error = None
    row.windows_injection_walk_result = None
    await context.db.flush()  # Rule #3 — flush() not commit() in MCP handlers.

    from app.services.windows_injection_walker import (
        run_windows_injection_walk_background,
    )

    asyncio.create_task(run_windows_injection_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "Windows injection walk scheduled. Poll "
                "windows_injection_walk_status until status=='completed'."
            ),
        }
    )


# ── lookup_volatility_injection_across_firmwares (Rule #44) ────────────────


async def _handle_lookup_volatility_injection_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION (Rule #44)** — keyed on
    ``hexdump_sha256``. Returns ALL firmware images in the active
    project (or globally) that contain a matching injection record.

    The strongest forensic signal in the λ chain: an injected code
    region appearing across multiple firmware captures with the same
    first-64-bytes SHA256 is canonical threat-actor TTP-reuse evidence.
    A vendor-pushed legitimate hook code-region appearing in many
    customer captures is a supply-chain signal. ``supply_chain_signal``
    fires when match_count >= 2.

    Optional ``detection_kind`` filter scopes the search to one of the
    5 kinds; default surfaces all kinds (most operators want
    injected_code_region — that's the kind that produces a hexdump_sha256).
    """
    hexdump_sha256 = input.get("hexdump_sha256")
    detection_kind = input.get("detection_kind")
    if not hexdump_sha256:
        return json.dumps({"error": "hexdump_sha256 is required"})
    if detection_kind is not None and detection_kind not in _VALID_DETECTION_KINDS:
        return json.dumps(
            {
                "error": (
                    f"invalid detection_kind {detection_kind!r}; allowed: "
                    f"{sorted(_VALID_DETECTION_KINDS)}"
                )
            }
        )

    scope = input.get("scope", "project")
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where = [VolatilityInjectionRecord.hexdump_sha256 == hexdump_sha256]
    if detection_kind:
        where.append(VolatilityInjectionRecord.detection_kind == detection_kind)

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
            select(VolatilityInjectionRecord, Firmware, Project)
            .join(
                Firmware,
                VolatilityInjectionRecord.firmware_id == Firmware.id,
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(VolatilityInjectionRecord, Firmware, Project)
            .join(
                Firmware,
                VolatilityInjectionRecord.firmware_id == Firmware.id,
            )
            .join(Project, Firmware.project_id == Project.id)
            .where(*where)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    by_firmware: dict[uuid.UUID, dict] = {}
    for record, firmware, project in rows:
        slot = by_firmware.get(firmware.id)
        if slot is None:
            slot = {
                "firmware_id": str(firmware.id),
                "project_id": str(project.id),
                "project_name": project.name,
                "original_filename": firmware.original_filename,
                "sha256": firmware.sha256,
                "match_count": 0,
                "sample_detection": None,
                "detection_kinds": set(),
            }
            by_firmware[firmware.id] = slot
        slot["match_count"] += 1
        slot["detection_kinds"].add(record.detection_kind)
        if slot["sample_detection"] is None:
            slot["sample_detection"] = _row_to_dict(record)

    matches: list[dict] = []
    for slot in by_firmware.values():
        slot["detection_kinds"] = sorted(slot["detection_kinds"])
        slot["supply_chain_signal"] = bool(slot["match_count"] >= 2)
        matches.append(slot)
        if len(matches) >= limit:
            break

    out: dict = {
        "hexdump_sha256": hexdump_sha256,
        "detection_kind": detection_kind,
        "scope": scope,
        "match_firmware_count": len(matches),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching injection records found. Ensure the walker has "
            "run on the relevant firmwares (trigger_windows_injection_walk "
            "+ poll), and double-check that hexdump_sha256 is a 64-char "
            "lower-case hex digest (the canonical form produced by the "
            "walker's _hexdump_sha256 helper)."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_injection_tools(registry: ToolRegistry) -> None:
    """Register all Phase λ.γ.C Windows injection MCP tools."""

    registry.register(
        name="list_windows_injection_detections",
        description=(
            "Phase λ.γ.C — paginate per-detection rows from "
            "``volatility_injection_records`` for the active firmware. "
            "Filters: detection_kind (one of: injected_code_region / "
            "hollow_process / unlinked_module / peb_masquerade / "
            "ghosted_process), pid, image_filename (exact), "
            "hexdump_sha256 (exact — find the same malfind region in "
            "this firmware). Returns up to `limit` rows per page "
            "(default 50, max 500) with total_count. Order: "
            "detection_kind ASC, pid ASC."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "detection_kind": {
                    "type": "string",
                    "enum": [
                        "injected_code_region",
                        "hollow_process",
                        "unlinked_module",
                        "peb_masquerade",
                        "ghosted_process",
                    ],
                    "description": "Filter by detection kind.",
                },
                "pid": {
                    "type": "integer",
                    "description": "Filter by exact PID.",
                },
                "image_filename": {
                    "type": "string",
                    "description": "Exact image filename match.",
                },
                "hexdump_sha256": {
                    "type": "string",
                    "description": (
                        "64-char lower-case hex SHA256 of malfind's "
                        "first-64-bytes hexdump. Find every detection "
                        "in this firmware with the same hash."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Page size (default 50, max 500).",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Page offset (default 0).",
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_windows_injection_detections,
    )

    registry.register(
        name="windows_injection_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "windows_injection_walk_* state machine. Returns status "
            "(idle / queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(image_count, detection_count, by_kind, "
            "unique_hexdump_sha256_count, total_elapsed_s, "
            "errors_per_image)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_windows_injection_walk_status,
    )

    registry.register(
        name="trigger_windows_injection_walk",
        description=(
            "Trigger the 202+polling Windows injection walk runner. "
            "Idempotent (Rule #33 .a) — returns conflict=true with the "
            "in-flight status if a run is already queued or running. On "
            "fresh runs, resets the firmware-row state and schedules "
            "run_windows_injection_walk_background via "
            "asyncio.create_task. Poll windows_injection_walk_status "
            "until status=='completed' to harvest the result. The walker "
            "wires EXCLUSIVELY to the ``windows.malware.<X>`` namespace "
            "per the 2026-06-07 deprecation deadline."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_windows_injection_walk,
    )

    registry.register(
        name="lookup_volatility_injection_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — keyed on "
            "hexdump_sha256 (SHA256 of malfind's first-64-bytes hexdump). "
            "Returns ALL firmware images in the active project (or "
            "globally, with scope='global') that contain a matching "
            "injection record. The strongest cross-firmware signal in "
            "the λ chain: an injected code region appearing across "
            "captures with the same first-64-bytes hash is canonical "
            "threat-actor TTP-reuse evidence. supply_chain_signal=True "
            "when match_count >= 2."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hexdump_sha256": {
                    "type": "string",
                    "description": (
                        "Required. 64-char lower-case hex SHA256 of "
                        "the canonicalised first-64-bytes hexdump."
                    ),
                },
                "detection_kind": {
                    "type": "string",
                    "enum": [
                        "injected_code_region",
                        "hollow_process",
                        "unlinked_module",
                        "peb_masquerade",
                        "ghosted_process",
                    ],
                    "description": (
                        "Optional. Scope to one detection_kind. Default "
                        "surfaces all kinds (most useful: "
                        "injected_code_region — the kind that produces "
                        "a hexdump_sha256)."
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
                        "Maximum distinct firmwares to return (default "
                        "100, max 500)."
                    ),
                },
            },
            "required": ["hexdump_sha256"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_volatility_injection_across_firmwares,
    )
