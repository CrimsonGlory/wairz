"""MCP tools for the C2 module/driver REACHABILITY-EVIDENCE walker.

This is a NEW, DISTINCT tool namespace (R51.2 SHOULD-FIX S1) — C2's tools
live HERE, NOT in the already-crowded ``linux_kernel_hardening.py`` (which
holds the C1 extraction + KSPP audit tools). ``ToolRegistry.register``
SILENTLY OVERWRITES (no dup guard, the Rule #10-class MCP-layer gap), so a
clean separate file lowers the collision risk; the registry-uniqueness
META-CANARY in ``test_kernel_config_mcp.py`` + the C2 canary in
``test_module_reachability_mcp.py`` close the gap.

Tool surface:

  - ``trigger_module_reachability_walk`` — operator-trigger the C2 walker
    (Rule #33 .a; project-scope guarded; 409-shaped conflict on in-flight
    rerun). Flips ``module_reachability_walk_status`` idle → queued +
    dispatches the background runner.
  - ``get_module_reachability`` — reads ``firmware.module_reachability_walk_result``
    (the loaded/available/builtin 3-way diff + static_builtin_posture the
    cve-assessment-framework L4 kill-chain classifier consumes via
    ``ModuleEntry.builtin`` + ``kernel/builtin_modules.json``).
    Provenance-gated (schema_version==1 + provenance=="walker").
  - ``lookup_module_across_firmwares`` — **Rule #44 mandatory cross-firmware
    aggregator**. "Which firmware ship the same vulnerable ``.ko`` (by SHA or
    vermagic)?" / "Which firmware built ``bcmdhd`` in vs as a module?" —
    grouped-by-firmware with ``supply_chain_signal`` flag (true when ≥2
    firmware share a ``.ko`` SHA — the round-48 unsigned BTFM supply-chain
    query shape).

Per Rule #36/#45 the walker neither decrypts nor executes; these MCP tools
only surface parse-only artefacts (the walk-result JSONB aggregate).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_module_reachability_walk_result,
)
from app.services.module_reachability_walker import (
    run_module_reachability_walk_background,
)

logger = logging.getLogger(__name__)

_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    """Truncate an MCP tool payload to the 30 KB ceiling (Rule: tool outputs
    must stay small or MCP clients break)."""
    if len(text) <= cap:
        return text
    return text[: cap - 80] + '\n... [truncated — narrow the query/scope] ...'


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_trigger_module_reachability_walk(
    input: dict, context: ToolContext
) -> str:
    """Operator-trigger the C2 module-reachability walker (Rule #33 .a).

    Enumerates the loaded/available/builtin module sets across the firmware's
    detection roots so the cve-assessment-framework L4 classifier can tell an
    immutable built-in / =n driver (clearable) from a =m-not-loaded driver
    (mutable → guilty). Project-scope guarded (W2-β §SC5-NEW-ICS-S2-ε
    analog); 409-shaped conflict on in-flight rerun.
    """
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = (
            uuid.UUID(firmware_id_str)
            if isinstance(firmware_id_str, str)
            else firmware_id_str
        )
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    # Project-scope guard — operator-A in P1 cannot trigger against
    # operator-B's firmware in P2 via switch_project.
    if not context.project_id:
        return json.dumps({
            "error": (
                "no active project — call switch_project before "
                "trigger_module_reachability_walk"
            ),
        })
    project_id = (
        uuid.UUID(context.project_id)
        if isinstance(context.project_id, str)
        else context.project_id
    )
    firmware = (
        await context.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
    ).scalar_one_or_none()
    if firmware is None:
        return json.dumps({
            "error": (
                f"firmware {firmware_id} not found in active project "
                f"{project_id} (either wrong id OR belongs to a different "
                f"project — tenancy scope guard)"
            ),
        })

    if firmware.module_reachability_walk_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "module_reachability_walk_status": (
                firmware.module_reachability_walk_status
            ),
            "message": (
                f"module_reachability_walk is already "
                f"{firmware.module_reachability_walk_status} — wait for "
                f"completion before re-triggering."
            ),
        })

    firmware.module_reachability_walk_status = "queued"
    firmware.module_reachability_walk_started_at = None
    firmware.module_reachability_walk_finished_at = None
    firmware.module_reachability_walk_error = None
    firmware.module_reachability_walk_result = None
    await context.db.flush()  # Rule #3 — flush, not commit, in MCP handlers.
    # Background runner opens its own session; commit BEFORE spawning so it
    # sees `queued`.
    await context.db.commit()
    asyncio.create_task(run_module_reachability_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Module-reachability walker enqueued. Poll "
            "firmware.module_reachability_walk_status through running → "
            "completed | failed; harvest via get_module_reachability. The "
            "result carries the loaded/available/builtin 3-way diff + "
            "static_builtin_posture the cve-assessment-framework L4 "
            "kill-chain classifier consumes."
        ),
    })


async def _handle_get_module_reachability(
    input: dict, context: ToolContext
) -> str:
    """Read the C2 module-reachability walk aggregate for one firmware.

    Returns firmware.module_reachability_walk_result — the loaded (null for a
    static image) / available[] / builtin[] 3-way diff +
    static_builtin_posture + kernel_posture + builtin_y_from_config. This is
    the evidence shape the cve-assessment-framework reads
    (ModuleEntry.builtin + kernel/builtin_modules.json). Provenance-gated:
    schema_version==1 + provenance=="walker" before trusting the evidence.
    """
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = (
            uuid.UUID(firmware_id_str)
            if isinstance(firmware_id_str, str)
            else firmware_id_str
        )
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    result = _normalize_firmware_module_reachability_walk_result(
        firmware.module_reachability_walk_result
    )
    out: dict = {
        "firmware_id": str(firmware_id),
        "module_reachability_walk_status": (
            firmware.module_reachability_walk_status
        ),
    }
    if result is None:
        out["result"] = None
        out["hint"] = (
            f"no module-reachability walk result yet (status="
            f"{firmware.module_reachability_walk_status}); trigger via "
            f"trigger_module_reachability_walk and poll until completed."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    # Provenance gate — refuse to surface a non-walker / legacy result.
    if result.get("schema_version") != 1 or result.get("provenance") != "walker":
        out["result"] = result
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate "
            f"(schema_version={result.get('schema_version')!r}, "
            f"provenance={result.get('provenance')!r}). Downstream L4 "
            f"consumers MUST NOT trust the module evidence — re-trigger via "
            f"trigger_module_reachability_walk."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    out["result"] = result
    return _truncate(json.dumps(out, indent=2, default=str))


async def _handle_lookup_module_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """Rule #44 mandatory cross-firmware aggregator for module reachability.

    Given a module NAME (e.g. ``bcmdhd``, ``ath9k``, ``wlan``), and/or a
    ``.ko`` SHA-256, return every firmware whose module-reachability walk
    found the module — in its AVAILABLE set, BUILTIN set, or both. The
    headline supply-chain query: "which firmware ship the SAME ``.ko`` by
    SHA?" (the round-48 unsigned BTFM ``CI_BTFM.CHE.2.0.0`` case).

    Returns one row per matching firmware with:
      - firmware_id, project_id, project_name, original_filename
      - found_in: "available" | "builtin" | "both"
      - kernel_posture + static_builtin_posture
      - sample available entry (name/sha256/vermagic/signed) when matched
    plus a top-level ``supply_chain_signal`` (True when ≥2 firmware share the
    SAME ``.ko`` SHA — the strongest "same binary across the fleet" signal).
    """
    module_name = input.get("module_name")
    sha256 = input.get("sha256")
    if not module_name and not sha256:
        return json.dumps({
            "error": "At least one of module_name or sha256 is required.",
        })
    if isinstance(module_name, str):
        module_name = module_name.strip().lower()
    if isinstance(sha256, str):
        sha256 = sha256.strip().lower()

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        return json.dumps({
            "error": f"scope must be 'project' or 'global', got {scope!r}",
        })
    limit = int(input.get("limit", 100))
    limit = max(1, min(limit, 500))

    stmt = (
        select(Firmware, Project)
        .join(Project, Firmware.project_id == Project.id)
        .where(Firmware.module_reachability_walk_status == "completed")
        .order_by(Firmware.created_at)
    )
    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — call "
                    "switch_project first or use scope='global'."
                ),
            })
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = stmt.where(Firmware.project_id == project_id)

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    sha_owners: dict[str, list[str]] = {}  # sha256 -> [firmware_id, ...]
    for firmware, project in rows:
        result = _normalize_firmware_module_reachability_walk_result(
            firmware.module_reachability_walk_result
        )
        if result is None or result.get("schema_version") != 1:
            continue

        available = result.get("available") or []
        builtin = result.get("builtin") or []

        avail_hit = None
        for entry in available:
            if not isinstance(entry, dict):
                continue
            ename = (entry.get("name") or "").lower()
            esha = (entry.get("sha256") or "").lower()
            name_match = bool(module_name) and module_name in ename
            sha_match = bool(sha256) and esha == sha256
            if name_match or sha_match:
                avail_hit = entry
                if esha:
                    sha_owners.setdefault(esha, []).append(str(firmware.id))
                break

        builtin_hit = bool(module_name) and any(
            isinstance(b, str) and module_name in b.lower() for b in builtin
        )

        if not avail_hit and not builtin_hit:
            continue

        if avail_hit and builtin_hit:
            found_in = "both"
        elif avail_hit:
            found_in = "available"
        else:
            found_in = "builtin"

        match_entry: dict = {
            "firmware_id": str(firmware.id),
            "project_id": str(project.id),
            "project_name": project.name,
            "original_filename": firmware.original_filename,
            "found_in": found_in,
            "kernel_posture": result.get("kernel_posture"),
            "static_builtin_posture": result.get("static_builtin_posture"),
        }
        if avail_hit:
            match_entry["sample_available"] = {
                "name": avail_hit.get("name"),
                "sha256": avail_hit.get("sha256"),
                "vermagic": avail_hit.get("vermagic"),
                "signed": avail_hit.get("signed"),
            }
        matches.append(match_entry)
        if len(matches) >= limit:
            break

    # supply_chain_signal: the SAME .ko SHA appears in ≥2 firmware (the
    # strongest "identical binary across the fleet" signal). Falls back to
    # "≥2 firmware matched the name" when no SHA was supplied/found.
    shared_sha = {s: fws for s, fws in sha_owners.items() if len(set(fws)) >= 2}
    supply_chain_signal = bool(shared_sha) or len(matches) >= 2

    out: dict = {
        "module_name": module_name,
        "sha256": sha256,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": supply_chain_signal,
        "shared_ko_sha256": sorted(shared_sha.keys()),
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching firmwares found. Ensure the C2 walker has run on "
            "the relevant firmwares (trigger_module_reachability_walk + "
            "poll). schema_version must equal 1; rows with a NULL "
            "module_reachability_walk_result or status != 'completed' are "
            "skipped."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_module_reachability_tools(registry: ToolRegistry) -> None:
    """Register the C2 module-reachability MCP tools (DISTINCT namespace)."""
    registry.register(
        name="trigger_module_reachability_walk",
        description=(
            "Trigger the C2 module/driver REACHABILITY-EVIDENCE walker on "
            "one firmware. Enumerates the LOADED (null for a static image) "
            "/ AVAILABLE (/lib/modules *.ko on disk) / BUILTIN (depmod "
            "modules.builtin + CONFIG_*=y) module sets — the 3-way diff the "
            "cve-assessment-framework L4 kill-chain classifier consumes to "
            "tell an immutable built-in / =n driver (clearable) from a "
            "=m-not-loaded driver (mutable → guilty). Detects the "
            "static-builtin posture (0 .ko on disk + drivers =y, the phone "
            "case) where the BUILTIN set IS the reachability axis. "
            "Idempotent — 409-shaped conflict if already running. Poll "
            "firmware.module_reachability_walk_status; harvest via "
            "get_module_reachability. PARSE-ONLY (Rule #45) — reads modinfo "
            "+ depmod files AS DATA; never insmod/modprobe/spawns."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware to walk; defaults to "
                        "context.firmware_id."
                    ),
                },
            },
        },
        handler=_handle_trigger_module_reachability_walk,
    )
    registry.register(
        name="get_module_reachability",
        description=(
            "Read the C2 module-reachability walk aggregate for one "
            "firmware (firmware.module_reachability_walk_result). Returns "
            "the loaded/available/builtin 3-way diff: loaded (null — "
            "live-device only), available[] (each {name, sha256, vermagic, "
            "signed}), builtin[] (depmod modules.builtin names), "
            "builtin_y_from_config (CONFIG_*=y driver symbols from C1's "
            "kernel_config), configured_to_load, kernel_posture "
            "(static_builtin / modular / mixed / not_applicable), and "
            "static_builtin_posture (true when 0 .ko on disk + drivers =y). "
            "This is the evidence the cve-assessment-framework reads for "
            "the L4 kill-chain discriminator (ModuleEntry.builtin + "
            "kernel/builtin_modules.json). Provenance-gated "
            "(schema_version==1 + provenance=='walker')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware; defaults to "
                        "context.firmware_id."
                    ),
                },
            },
        },
        handler=_handle_get_module_reachability,
    )
    registry.register(
        name="lookup_module_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a module name "
            "(e.g. 'bcmdhd', 'ath9k', 'wlan') and/or a .ko SHA-256, return "
            "every firmware whose module-reachability walk found the module "
            "in its AVAILABLE set, BUILTIN set, or both. The headline "
            "supply-chain query: 'which firmware ship the SAME .ko by SHA?' "
            "(the round-48 unsigned BTFM CI_BTFM.CHE.2.0.0 case). Returns "
            "one row per matching firmware with found_in / kernel_posture / "
            "static_builtin_posture + a sample available entry; "
            "supply_chain_signal=True when >=2 firmware share the SAME .ko "
            "SHA (or, with no SHA, when >=2 firmware match the name). "
            "scope='global' searches all projects."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "module_name": {
                    "type": "string",
                    "description": (
                        "Module name substring to look up (case-insensitive; "
                        "matches available + builtin names). Either this or "
                        "sha256 is required. Example: 'bcmdhd', 'ath9k', "
                        "'wlan'."
                    ),
                },
                "sha256": {
                    "type": "string",
                    "description": (
                        "Exact .ko content SHA-256 to look up across the "
                        "fleet (the strongest 'same binary' supply-chain "
                        "signal). Either this or module_name is required."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "Search scope. 'project' (default) restricts to "
                        "firmwares in the active project; 'global' searches "
                        "across all projects."
                    ),
                    "default": "project",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": (
                        "Maximum number of distinct firmwares to return "
                        "(default 100, max 500)."
                    ),
                },
            },
        },
        handler=_handle_lookup_module_across_firmwares,
    )


__all__ = ["register_module_reachability_tools"]
