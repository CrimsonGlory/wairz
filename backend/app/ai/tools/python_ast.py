"""Q1 Python AST walker MCP tools.

Surfaces the :mod:`app.services.python_ast_walker` walk-result aggregate
to the MCP layer:

- ``python_ast_walk_status`` — Rule #33 status reader for the
  firmware-row python_ast_walk_* state machine.
- ``trigger_python_ast_walk`` — trigger the 202+polling background
  runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``get_python_ast_summary`` — pre-summarised aggregate for the active
  firmware (modules + callables + entry-points + summary counts;
  raw graph available via ``get_python_ast_full`` paged).
- ``lookup_python_ast_across_firmwares`` — Rule #44 mandatory
  cross-firmware aggregation. Given a module name (e.g. "tarfile"),
  returns every firmware in the project (or globally) that imports
  it AND whether the module is reachable from an entry-point.

Output truncation (Rule #29): tool outputs <= 30 KB.

**Downstream consumer.** ``cve-assessment-framework`` (Round-9.1 §12
EG-8A.3-5) consumes ``lookup_python_ast_across_firmwares`` to narrow
Python CVE applicability — e.g. ``plistlib`` / ``tarfile`` /
``multiprocessing.forkserver`` reach-or-not flags filter false
positives.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_python_ast_walk_result,
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


# ── python_ast_walk_status ──────────────────────────────────────────────────


async def _handle_python_ast_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.python_ast_walk_* state machine."""
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

    result = _normalize_firmware_python_ast_walk_result(
        row.python_ast_walk_result
    )
    # Strip the (potentially large) modules + callables maps from the
    # status response — operators reach for ``get_python_ast_summary``
    # for the aggregate data. The status payload stays cheap.
    summary_only: dict | None = None
    if result is not None:
        summary_only = {
            "schema_version": result.get("schema_version"),
            "walker": result.get("walker"),
            "summary": result.get("summary"),
            "python_version_detected": result.get("python_version_detected"),
            "extracted_root_paths_scanned": result.get(
                "extracted_root_paths_scanned"
            ),
            "entry_points_sample": (result.get("entry_points") or [])[:5],
        }

    out = {
        "firmware_id": str(firmware_id),
        "status": row.python_ast_walk_status,
        "started_at": (
            row.python_ast_walk_started_at.isoformat()
            if row.python_ast_walk_started_at
            else None
        ),
        "finished_at": (
            row.python_ast_walk_finished_at.isoformat()
            if row.python_ast_walk_finished_at
            else None
        ),
        "error": row.python_ast_walk_error,
        "summary": summary_only,
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_python_ast_walk ─────────────────────────────────────────────────


async def _handle_trigger_python_ast_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling Python AST walk background runner.
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

    if row.python_ast_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.python_ast_walk_status,
                "started_at": (
                    row.python_ast_walk_started_at.isoformat()
                    if row.python_ast_walk_started_at
                    else None
                ),
                "message": (
                    f"Python AST walk already {row.python_ast_walk_status} "
                    f"for firmware {firmware_id}. Poll "
                    "python_ast_walk_status."
                ),
            }
        )

    row.python_ast_walk_status = "queued"
    row.python_ast_walk_started_at = None
    row.python_ast_walk_finished_at = None
    row.python_ast_walk_error = None
    row.python_ast_walk_result = None
    await context.db.flush()

    from app.services.python_ast_walker import (
        run_python_ast_walk_background,
    )

    asyncio.create_task(run_python_ast_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "Python AST walk scheduled. Poll python_ast_walk_status "
                "until status=='completed' to harvest the result."
            ),
        }
    )


# ── get_python_ast_summary ──────────────────────────────────────────────────


async def _handle_get_python_ast_summary(
    input: dict, context: ToolContext
) -> str:
    """Return the full Python AST walk result for the active firmware.

    Caller MAY filter by module-name prefix (``module_prefix``) and/or
    by reachability (``reachable_only=True``) to keep the output under
    the 30 KB cap.
    """
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )
    module_prefix = input.get("module_prefix")
    reachable_only = bool(input.get("reachable_only", False))
    include_callables = bool(input.get("include_callables", False))

    row = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    result = _normalize_firmware_python_ast_walk_result(
        row.python_ast_walk_result
    )
    if result is None:
        return json.dumps(
            {
                "firmware_id": str(firmware_id),
                "status": row.python_ast_walk_status,
                "message": (
                    "Python AST walk has not produced a result yet. "
                    "Call trigger_python_ast_walk and poll "
                    "python_ast_walk_status."
                ),
            }
        )

    modules_imported = result.get("modules_imported") or {}
    callables_referenced = result.get("callables_referenced") or {}

    # Apply prefix filter.
    if module_prefix:
        modules_imported = {
            k: v for k, v in modules_imported.items()
            if k.startswith(module_prefix)
        }
        callables_referenced = {
            k: v for k, v in callables_referenced.items()
            if k.startswith(module_prefix)
        }

    # Apply reachability filter.
    if reachable_only:
        modules_imported = {
            k: v for k, v in modules_imported.items()
            if v.get("reachable_from_entry")
        }
        callables_referenced = {
            k: v for k, v in callables_referenced.items()
            if v.get("reachable_from_entry")
        }

    out = {
        "firmware_id": str(firmware_id),
        "walker": result.get("walker"),
        "schema_version": result.get("schema_version"),
        "python_version_detected": result.get("python_version_detected"),
        "extracted_root_paths_scanned": result.get(
            "extracted_root_paths_scanned"
        ),
        "entry_points": result.get("entry_points"),
        "modules_imported": modules_imported,
        "unreachable_modules": result.get("unreachable_modules"),
        "summary": result.get("summary"),
        "axiom_self_audit": result.get("axiom_self_audit"),
        "filters_applied": {
            "module_prefix": module_prefix,
            "reachable_only": reachable_only,
            "include_callables": include_callables,
        },
    }
    if include_callables:
        out["callables_referenced"] = callables_referenced

    return _truncate(json.dumps(out, indent=2, default=str))


# ── lookup_python_ast_across_firmwares (Rule #44) ───────────────────────────


async def _handle_lookup_python_ast_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given a Python module name (e.g.
    ``tarfile``, ``plistlib``, ``multiprocessing.forkserver``), return
    ALL firmware images in the active project (or globally) where the
    module is imported, along with reachability flags.

    Rule #44 — the same vulnerable callable / module appearing across
    multiple firmwares is a supply-chain signal. Designed for
    cve-assessment-framework consumption (Round-9.1 §12 EG-8A.3-5):
    given a Python CVE that affects ``plistlib.loads``, this tool
    surfaces every firmware in the corpus that imports plistlib AND
    flags whether the import is reachable from a network-facing entry
    point.

    Returns one row per matching firmware with:
    - firmware_id, project_id, project_name, original_filename, sha256
    - module_imported (bool) + module_reachable_from_entry (bool)
    - callable_referenced (bool, if ``callable_name`` provided)
    - callable_reachable_from_entry (bool, if ``callable_name`` provided)
    - imported_from sample (first 5 source positions)
    - supply_chain_signal (True when match_count >= 2 firmwares).
    """
    module_name = input.get("module_name")
    callable_name = input.get("callable_name")
    if not module_name and not callable_name:
        return json.dumps({
            "error": (
                "At least one of module_name or callable_name is required."
            )
        })

    scope = input.get("scope", "project")
    require_reachable = bool(input.get("require_reachable", False))
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

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
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(
                Project.id == project_id,
                # Only consider firmwares with a completed walk; otherwise
                # the JSONB column is NULL and the match is meaningless.
                Firmware.python_ast_walk_status == "completed",
            )
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(Firmware, Project)
            .join(Project, Firmware.project_id == Project.id)
            .where(Firmware.python_ast_walk_status == "completed")
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    for firmware, project in rows:
        result = _normalize_firmware_python_ast_walk_result(
            firmware.python_ast_walk_result
        )
        if result is None:
            continue
        # Schema-version gate (W2-β §SC5-NEW-ICS-S2-ι I39 analogue):
        # require schema_version=1 so legacy rows from a future
        # incompatible walker output don't get false-positive matches.
        if result.get("schema_version") != 1:
            continue

        modules_imported = result.get("modules_imported") or {}
        callables_referenced = result.get("callables_referenced") or {}

        module_slot = (
            modules_imported.get(module_name) if module_name else None
        )
        callable_slot = (
            callables_referenced.get(callable_name) if callable_name else None
        )

        module_imported = module_slot is not None
        module_reachable = bool(
            module_slot and module_slot.get("reachable_from_entry")
        )
        callable_referenced = callable_slot is not None
        callable_reachable = bool(
            callable_slot and callable_slot.get("reachable_from_entry")
        )

        # Did this firmware "match"?
        if module_name and callable_name:
            matched = module_imported or callable_referenced
        elif module_name:
            matched = module_imported
        else:
            matched = callable_referenced

        if not matched:
            continue

        if require_reachable:
            if module_name and callable_name:
                if not (module_reachable or callable_reachable):
                    continue
            elif module_name:
                if not module_reachable:
                    continue
            else:
                if not callable_reachable:
                    continue

        match_entry: dict = {
            "firmware_id": str(firmware.id),
            "project_id": str(project.id),
            "project_name": project.name,
            "original_filename": firmware.original_filename,
            "sha256": firmware.sha256,
            "python_version_detected": result.get("python_version_detected"),
        }
        if module_name:
            match_entry["module_imported"] = module_imported
            match_entry["module_reachable_from_entry"] = module_reachable
            if module_slot:
                match_entry["imported_from_sample"] = (
                    module_slot.get("imported_from") or []
                )[:5]
        if callable_name:
            match_entry["callable_referenced"] = callable_referenced
            match_entry["callable_reachable_from_entry"] = callable_reachable
            if callable_slot:
                match_entry["called_from_sample"] = (
                    callable_slot.get("called_from") or []
                )[:5]

        matches.append(match_entry)
        if len(matches) >= limit:
            break

    out: dict = {
        "module_name": module_name,
        "callable_name": callable_name,
        "scope": scope,
        "require_reachable": require_reachable,
        "match_firmware_count": len(matches),
        "supply_chain_signal": len(matches) >= 2,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching firmwares found. Ensure the walker has run on "
            "the relevant firmwares (trigger_python_ast_walk + poll). "
            "schema_version must equal 1; rows with NULL "
            "python_ast_walk_result or schema_version != 1 are skipped."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ─────────────────────────────────────────────────────────────


def register_python_ast_tools(registry: ToolRegistry) -> None:
    """Register all Q1 Python AST walker MCP tools."""

    registry.register(
        name="python_ast_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "python_ast_walk_* state machine. Returns status "
            "(idle / queued / running / completed / failed), "
            "started_at, finished_at, error, and the last-known-result "
            "summary (files_scanned, modules_imported_count, "
            "callables_referenced_count, entry_reachable_modules_count, "
            "python_version_detected). The full graph is available "
            "via get_python_ast_summary."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_python_ast_walk_status,
    )

    registry.register(
        name="trigger_python_ast_walk",
        description=(
            "Trigger the 202+polling Python AST walk background "
            "runner. Idempotent (Rule #33 .a) — returns conflict=true "
            "with the in-flight status if a walk is already queued or "
            "running. Schedules run_python_ast_walk_background via "
            "asyncio.create_task. Poll python_ast_walk_status until "
            "status=='completed' to harvest the result. The walker "
            "performs static AST + import-graph + call-graph "
            "reachability analysis of every .py / .pyw / .pyi file "
            "across the firmware's detection roots. PARSE-ONLY "
            "discipline (Rule #45 + Rule #36) — ast.parse only; the "
            "walker NEVER invokes compile/exec/runpy/importlib on "
            "firmware-extracted source."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_python_ast_walk,
    )

    registry.register(
        name="get_python_ast_summary",
        description=(
            "Return the Python AST walk aggregate for the active "
            "firmware. Optional filters: module_prefix (e.g. "
            "'ds1qrsetup' or 'tarfile') narrows to qualnames starting "
            "with the prefix; reachable_only=true narrows to modules / "
            "callables reachable from the rooted entry-point set "
            "(Flask app factory / FastAPI route handler / __main__ "
            "block); include_callables=true adds the per-callable "
            "reachability map to the response (off by default to keep "
            "output small). Output is truncated to 30 KB; narrow "
            "filters if needed."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "module_prefix": {
                    "type": "string",
                    "description": (
                        "Narrow the result to modules and callable "
                        "qualnames starting with this prefix. Example: "
                        "'tarfile' returns just tarfile + its "
                        "callables; 'ds1qrsetup' returns the local "
                        "code graph."
                    ),
                },
                "reachable_only": {
                    "type": "boolean",
                    "description": (
                        "Drop modules / callables that aren't "
                        "reachable from any entry-point. Useful for "
                        "CVE-narrowing workflows."
                    ),
                },
                "include_callables": {
                    "type": "boolean",
                    "description": (
                        "Include the full callables_referenced map "
                        "in the response (off by default — the map "
                        "can be large for vendored ML stacks)."
                    ),
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_get_python_ast_summary,
    )

    registry.register(
        name="lookup_python_ast_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a Python "
            "module name (e.g. 'tarfile', 'plistlib', "
            "'multiprocessing.forkserver') and/or a callable qualified "
            "name (e.g. 'tarfile.open', 'plistlib.loads'), return ALL "
            "firmware images in the active project (or globally with "
            "scope='global') that import the module or reference the "
            "callable, along with reachability flags from the "
            "entry-point set. Designed for cve-assessment-framework "
            "consumption — narrows Python CVE applicability via "
            "deployed-script grep precedent (Round-9.1 §12 EG-8A.3-5). "
            "require_reachable=true narrows further to only firmwares "
            "where the module/callable is REACHABLE from an "
            "entry-point. supply_chain_signal=True when match_count "
            ">= 2 firmwares (same library / callable observed across "
            "multiple captures)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "module_name": {
                    "type": "string",
                    "description": (
                        "Python module qualified name to look up. "
                        "Either this or callable_name is required. "
                        "Example: 'tarfile', 'plistlib', "
                        "'multiprocessing.forkserver'."
                    ),
                },
                "callable_name": {
                    "type": "string",
                    "description": (
                        "Python callable qualified name to look up. "
                        "Example: 'tarfile.open', 'plistlib.loads', "
                        "'multiprocessing.forkserver.connect'."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "Search scope. 'project' (default) restricts "
                        "to firmwares in the active project; 'global' "
                        "searches across all projects."
                    ),
                },
                "require_reachable": {
                    "type": "boolean",
                    "description": (
                        "When true, only return firmwares where the "
                        "module/callable is reachable from an "
                        "entry-point (useful for CVE-narrowing)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": (
                        "Maximum number of distinct firmwares to "
                        "return (default 100, max 500)."
                    ),
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_lookup_python_ast_across_firmwares,
    )


# Silence unused-import warnings while keeping the dialect type
# available for future query-shape work (e.g. JSONB key-existence
# operators in PostgreSQL-native filters).
_ = JSONB
