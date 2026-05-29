"""MCP tools for the C4 Android DEPLOYMENT-POSTURE walker.

This is a NEW, DISTINCT tool namespace (R51.2 SHOULD-FIX S1 + S2) — C4's tools
live HERE, NOT in the existing per-APK ``android.py`` (which holds
``analyze_apk`` / ``list_apk_permissions`` / ``check_apk_signatures`` /
``scan_apk_manifest``). ``ToolRegistry.register`` SILENTLY OVERWRITES (no dup
guard, the Rule #10-class MCP-layer gap), so a clean separate file lowers the
collision risk; the registry-uniqueness META-CANARY in ``test_kernel_config_
mcp.py`` + the C4 canary in ``test_android_posture_mcp.py`` close the gap.

Tool surface:

  - ``trigger_android_posture_walk`` — operator-trigger the C4 walker
    (Rule #33 .a; project-scope guarded; 409-shaped conflict on in-flight
    rerun). Flips ``android_posture_walk_status`` idle → queued + dispatches
    the background runner.
  - ``get_android_posture`` — reads ``firmware.android_posture_walk_result``
    (the gates_open deployment posture the cve-assessment-framework L4
    kill-chain LockdownGate consumes via AndroidAdapter.get_security_posture +
    get_entry_surfaces). Provenance-gated (schema_version==1 +
    provenance=="walker"). Surfaces THE HONEST GATING — gates_open +
    runtime_confirmed (always false for an image walk) + the named
    settling_command.
  - ``lookup_android_posture_across_firmwares`` — **Rule #44 mandatory
    cross-firmware aggregator**. "Which firmware ship the same DPC / the same
    stock build / a telephony stack?" — grouped-by-firmware with a
    ``supply_chain_signal`` flag (true when ≥2 firmware share the SAME DPC app
    OR the SAME build fingerprint — the fleet-wide same-OEM-image / same-MDM
    query).

Per Rule #36/#45 the walker neither decrypts nor executes dex / invokes any
APK; these MCP tools only surface parse-only artefacts (the walk-result JSONB
aggregate).
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
from app.services.android_posture_walker import (
    run_android_posture_walk_background,
)
from app.services.jsonb_normalizers import (
    _normalize_firmware_android_posture_walk_result,
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


async def _handle_trigger_android_posture_walk(
    input: dict, context: ToolContext
) -> str:
    """Operator-trigger the C4 android-posture walker (Rule #33 .a).

    Synthesizes the gates_open deployment posture across the firmware's
    detection roots so the cve-assessment-framework L4 kill-chain LockdownGate
    can decide gate state. THE HONEST GATING: the result carries
    runtime_confirmed=false for image-inferred posture (an image SUPPORTS a
    lockdown but cannot CONFIRM enrollment) → the consumer holds the gate
    OPEN. Project-scope guarded; 409-shaped conflict on in-flight rerun.
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
                "trigger_android_posture_walk"
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

    if firmware.android_posture_walk_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "android_posture_walk_status": (
                firmware.android_posture_walk_status
            ),
            "message": (
                f"android_posture_walk is already "
                f"{firmware.android_posture_walk_status} — wait for "
                f"completion before re-triggering."
            ),
        })

    firmware.android_posture_walk_status = "queued"
    firmware.android_posture_walk_started_at = None
    firmware.android_posture_walk_finished_at = None
    firmware.android_posture_walk_error = None
    firmware.android_posture_walk_result = None
    await context.db.flush()  # Rule #3 — flush, not commit, in MCP handlers.
    # Background runner opens its own session; commit BEFORE spawning so it
    # sees `queued`.
    await context.db.commit()
    asyncio.create_task(run_android_posture_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Android-posture walker enqueued. Poll "
            "firmware.android_posture_walk_status through running → "
            "completed | failed; harvest via get_android_posture. The result "
            "carries the gates_open deployment posture the cve-assessment-"
            "framework L4 kill-chain LockdownGate consumes — with "
            "runtime_confirmed=false for image-inferred posture (the consumer "
            "holds the gate OPEN, guilty) + the named settling_command."
        ),
    })


async def _handle_get_android_posture(
    input: dict, context: ToolContext
) -> str:
    """Read the C4 android-posture walk aggregate for one firmware.

    Returns firmware.android_posture_walk_result — gates_open
    ({cellular_active, sideloading_allowed, kiosk}) + runtime_confirmed
    (always false for an image walk) + posture_confidence + the supporting
    evidence + the named settling_command. This is the evidence shape the
    cve-assessment-framework reads for the L4 LockdownGate
    (AndroidAdapter.get_security_posture + get_entry_surfaces).
    Provenance-gated: schema_version==1 + provenance=="walker" before trusting
    the posture.

    THE HONEST GATING is surfaced explicitly: an image-inferred posture
    (runtime_confirmed=false) means the consumer MUST hold the gate OPEN
    (guilty, no reduction) and run the settling_command to confirm.
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

    result = _normalize_firmware_android_posture_walk_result(
        firmware.android_posture_walk_result
    )
    out: dict = {
        "firmware_id": str(firmware_id),
        "android_posture_walk_status": (
            firmware.android_posture_walk_status
        ),
    }
    if result is None:
        out["result"] = None
        out["hint"] = (
            f"no android-posture walk result yet (status="
            f"{firmware.android_posture_walk_status}); trigger via "
            f"trigger_android_posture_walk and poll until completed."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    # Provenance gate — refuse to surface a non-walker / legacy result.
    if result.get("schema_version") != 1 or result.get("provenance") != "walker":
        out["result"] = result
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate "
            f"(schema_version={result.get('schema_version')!r}, "
            f"provenance={result.get('provenance')!r}). Downstream L4 "
            f"consumers MUST NOT trust the gates_open posture — "
            f"re-trigger via trigger_android_posture_walk."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    out["result"] = result
    # Surface THE HONEST GATING for the operator/consumer when this is an
    # image-inferred posture (runtime_confirmed=false).
    if result.get("runtime_confirmed") is False:
        out["gating_note"] = (
            "runtime_confirmed=false: this posture is INFERRED from the static "
            "image, which can SUPPORT a lockdown but CANNOT confirm THIS unit "
            "is enrolled / active / SIM-provisioned. The L4 consumer HOLDS THE "
            "GATE OPEN (guilty, no reduction). Run the settling_command to "
            "produce a runtime-confirmed capture that can close the gate."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


async def _handle_lookup_android_posture_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """Rule #44 mandatory cross-firmware aggregator for Android posture.

    Given an OPTIONAL filter (``dpc_app`` substring, ``build_fingerprint``
    substring, or ``gate`` name ∈ {cellular_active, sideloading_allowed,
    kiosk}), return every firmware whose android-posture walk matched. The
    headline fleet query: "which firmware ship the SAME DPC / the SAME stock
    build / a telephony stack?"

    Returns one row per matching firmware with:
      - firmware_id, project_id, project_name, original_filename
      - posture summary (gates_open, runtime_confirmed, posture_confidence,
        dpc_apps, build_type/tags)
    plus a top-level ``supply_chain_signal`` (True when ≥2 firmware share the
    SAME DPC app OR the SAME build fingerprint — the strongest "same OEM image
    / same managed-fleet posture across the fleet" signal).

    Honours the schema_version==1 + status=='completed' gate (rows with a NULL
    result or a non-walker provenance are skipped).
    """
    dpc_app = input.get("dpc_app")
    build_fingerprint = input.get("build_fingerprint")
    gate = input.get("gate")
    if isinstance(dpc_app, str):
        dpc_app = dpc_app.strip().lower()
    if isinstance(build_fingerprint, str):
        build_fingerprint = build_fingerprint.strip().lower()
    if gate is not None and gate not in (
        "cellular_active",
        "sideloading_allowed",
        "kiosk",
    ):
        return json.dumps({
            "error": (
                f"gate must be one of cellular_active / sideloading_allowed / "
                f"kiosk, got {gate!r}"
            ),
        })

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
        .where(Firmware.android_posture_walk_status == "completed")
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
    # dpc_app token -> set of firmware ids that ship it.
    shared_dpc_owners: dict[str, set[str]] = {}
    # build fingerprint -> set of firmware ids that ship it.
    shared_build_owners: dict[str, set[str]] = {}
    for firmware, project in rows:
        result = _normalize_firmware_android_posture_walk_result(
            firmware.android_posture_walk_result
        )
        if (
            result is None
            or result.get("schema_version") != 1
            or result.get("provenance") != "walker"
            or result.get("platform") != "android"
        ):
            continue

        gates = result.get("gates_open") or {}
        evidence = result.get("evidence") or {}
        dpc_apps = [str(a) for a in (evidence.get("dpc_apps") or [])]
        fingerprint = (evidence.get("build_type") or "") + "/" + (
            evidence.get("build_tags") or ""
        )

        # Apply filters (when supplied, ALL must match).
        if dpc_app:
            if not any(dpc_app in a.lower() for a in dpc_apps):
                continue
        if build_fingerprint:
            if build_fingerprint not in fingerprint.lower():
                continue
        if gate is not None:
            if not gates.get(gate):
                continue

        matches.append({
            "firmware_id": str(firmware.id),
            "project_id": str(project.id),
            "project_name": project.name,
            "original_filename": firmware.original_filename,
            "gates_open": gates,
            "runtime_confirmed": result.get("runtime_confirmed"),
            "posture_confidence": result.get("posture_confidence"),
            "dpc_apps": dpc_apps,
            "build_type": evidence.get("build_type"),
            "build_tags": evidence.get("build_tags"),
            "telephony_present": evidence.get("telephony_present"),
        })
        for a in dpc_apps:
            shared_dpc_owners.setdefault(a.lower(), set()).add(str(firmware.id))
        if fingerprint.strip("/"):
            shared_build_owners.setdefault(
                fingerprint.lower(), set()
            ).add(str(firmware.id))
        if len(matches) >= limit:
            break

    # supply_chain_signal: the SAME DPC app OR the SAME build fingerprint is
    # shipped in ≥2 firmware (the strongest "identical managed-fleet / OEM
    # image posture across the fleet" signal).
    shared_dpc = {
        d: sorted(fws)
        for d, fws in shared_dpc_owners.items()
        if len(fws) >= 2
    }
    shared_builds = {
        b: sorted(fws)
        for b, fws in shared_build_owners.items()
        if len(fws) >= 2
    }
    supply_chain_signal = bool(shared_dpc) or bool(shared_builds)

    out: dict = {
        "dpc_app": dpc_app,
        "build_fingerprint": build_fingerprint,
        "gate": gate,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": supply_chain_signal,
        "shared_dpc_apps": shared_dpc,
        "shared_build_fingerprints": shared_builds,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching firmwares found. Ensure the C4 walker has run on the "
            "relevant firmwares (trigger_android_posture_walk + poll). "
            "schema_version must equal 1 + provenance=='walker' + "
            "platform=='android'; rows with a NULL android_posture_walk_result "
            "or status != 'completed' are skipped."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_android_posture_tools(registry: ToolRegistry) -> None:
    """Register the C4 android-posture MCP tools (DISTINCT namespace)."""
    registry.register(
        name="trigger_android_posture_walk",
        description=(
            "Trigger the C4 Android DEPLOYMENT-POSTURE REACHABILITY-EVIDENCE "
            "walker on one firmware. Synthesizes the gates_open deployment "
            "posture ({cellular_active, sideloading_allowed, kiosk}) across "
            "build.prop + the APK inventory + RIL/telephony libs + "
            "device_owner.xml + settings + (optionally) APK manifest "
            "device-admin components — the evidence the cve-assessment-"
            "framework L4 kill-chain LockdownGate consumes. THE HONEST GATING: "
            "a static image can SUPPORT a lockdown (a DPC/kiosk/launcher app "
            "present, a telephony stack present) but CANNOT confirm THIS unit "
            "is enrolled/active/SIM-provisioned — so the result carries "
            "runtime_confirmed=false (the consumer HOLDS THE GATE OPEN, guilty, "
            "no reduction) + a named settling_command (the live adb capture). "
            "Idempotent — 409-shaped conflict if already running. Poll "
            "firmware.android_posture_walk_status; harvest via "
            "get_android_posture. PARSE-ONLY (Rule #45) — reads manifests / "
            "props / XML AS DATA; never executes dex / invokes an APK / spawns."
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
        handler=_handle_trigger_android_posture_walk,
    )
    registry.register(
        name="get_android_posture",
        description=(
            "Read the C4 android-posture walk aggregate for one firmware "
            "(firmware.android_posture_walk_result). Returns gates_open "
            "({cellular_active, sideloading_allowed, kiosk}) + "
            "runtime_confirmed (ALWAYS false for an image walk — an image can "
            "SUPPORT a lockdown but cannot CONFIRM enrollment) + "
            "posture_confidence (config_inferred for image-inferred) + the "
            "supporting evidence (dpc_apps, telephony_present, "
            "sideload_default, build_type/tags, device_owner_xml_present) + "
            "the named settling_command (dumpsys device_policy / dpm "
            "list-owners / getprop — the live capture that can set "
            "runtime_confirmed=true). This is the evidence the cve-assessment-"
            "framework reads for the L4 LockdownGate "
            "(AndroidAdapter.get_security_posture + get_entry_surfaces). "
            "Provenance-gated (schema_version==1 + provenance=='walker'). When "
            "runtime_confirmed=false the consumer MUST hold the gate OPEN "
            "(guilty)."
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
        handler=_handle_get_android_posture,
    )
    registry.register(
        name="lookup_android_posture_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given an OPTIONAL filter "
            "(dpc_app substring, build_fingerprint substring, or a gate name "
            "∈ {cellular_active, sideloading_allowed, kiosk}), return every "
            "firmware whose android-posture walk matched. The headline fleet "
            "query: 'which firmware ship the SAME DPC / the SAME stock build / "
            "a telephony stack?' Returns one row per matching firmware with "
            "its gates_open + runtime_confirmed + dpc_apps + build_type/tags; "
            "supply_chain_signal=True when >=2 firmware share the SAME DPC app "
            "OR the SAME build fingerprint (the same-OEM-image / same-managed-"
            "fleet posture signal). scope='global' searches all projects."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dpc_app": {
                    "type": "string",
                    "description": (
                        "DPC / device-admin app-name substring to look up "
                        "(case-insensitive). Example: 'workspaceone', "
                        "'intune', 'knox'."
                    ),
                },
                "build_fingerprint": {
                    "type": "string",
                    "description": (
                        "Build type/tags fingerprint substring to look up "
                        "(case-insensitive). Example: 'user/release-keys', "
                        "'userdebug'."
                    ),
                },
                "gate": {
                    "type": "string",
                    "enum": [
                        "cellular_active",
                        "sideloading_allowed",
                        "kiosk",
                    ],
                    "description": (
                        "Filter to firmware whose named gate is OPEN "
                        "(inferred-true). Omit to match all postures."
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
        handler=_handle_lookup_android_posture_across_firmwares,
    )


__all__ = ["register_android_posture_tools"]
