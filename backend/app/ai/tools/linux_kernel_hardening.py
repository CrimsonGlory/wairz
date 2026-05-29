"""MCP tools for the Linux kernel hardening (KSPP) walker + the C1
generic kernel-config EXTRACTION walker.

Tool surface:

  Downstream KSPP hardening AUDIT (linux_kernel_hardening_walker):
  - ``audit_kernel_config_firmware`` — operator-trigger the AUDIT walker
    on one firmware (idempotent — Rule #33 .a 409 on in-flight rerun).
  - ``lookup_kernel_config_across_firmwares`` — **Rule #44 mandatory
    cross-firmware aggregator** (ALREADY satisfies Rule #44 for kernel
    config) — answers "which firmware in the corpus have CONFIG_DEVMEM=y?"
    / "which devices ship without dm-verity?" / "which firmware share the
    same KSPP hardening miss?" via grouped-by-firmware aggregation with
    ``supply_chain_signal`` flag (true when ≥2 firmware share the finding).
    Reads firmware.kernel_config_audit_result.

  Upstream EXTRACTION walker (kernel_config_walker — C1, 2026-05-29):
  - ``trigger_kernel_config_walk`` — operator-trigger the EXTRACTION
    walker (Rule #33 .a; project-scope guarded; 409 on in-flight rerun).
    Flips kernel_config_walk_status idle → queued + dispatches the
    background runner.
  - ``get_kernel_config_extraction`` — reads
    firmware.kernel_config_walk_result (the per-kernel extraction
    aggregate; the config.json shape the cve-assessment-framework
    consumes for Gate-1). Provenance-gated (schema_version==1 +
    provenance=="walker").

  DISTINCT-NAME discipline (R50.2 B1): C1 does NOT re-register
  ``lookup_kernel_config_across_firmwares`` — that name already exists
  here (reads the AUDIT result) and ToolRegistry.register SILENTLY
  OVERWRITES (no dup guard). Rule #44 is already satisfied for kernel
  config; C1's obligation is "don't shadow the existing tool". The
  registry-uniqueness META-CANARY in test_kernel_config_mcp.py closes
  the Rule #10-class MCP-layer gap (assert len(names)==len(set(names))
  over the assembled registry).

Per Rule #36/#45 neither walker decrypts or executes; these MCP tools
only surface parse-only artefacts (Finding rows + the audit-result /
walk-result JSONB aggregates).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models import Finding, Firmware
from app.services.kernel_config_walker import (
    run_kernel_config_walk_background,
)
from app.services.linux_kernel_hardening_walker import (
    _KSPP_RULES,
    _LSM_FINDING,
    run_kernel_config_audit_background,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_audit_kernel_config_firmware(input: dict, context: ToolContext) -> str:
    """Operator-trigger the kernel-config audit walker on one firmware.

    Rule #33 .a — if status is already ``queued`` or ``running``, returns
    a 409-shaped JSON response (informational; MCP can't actually return
    HTTP statuses). Otherwise transitions ``idle → queued`` and spawns
    the background runner.
    """
    firmware_id_str = input.get("firmware_id")
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = uuid.UUID(firmware_id_str)
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})
    if firmware.kernel_config_audit_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "kernel_config_audit_status": firmware.kernel_config_audit_status,
            "message": (
                f"kernel_config_audit is already {firmware.kernel_config_audit_status} "
                f"— wait for completion before re-triggering."
            ),
        })

    firmware.kernel_config_audit_status = "queued"
    firmware.kernel_config_audit_started_at = None
    firmware.kernel_config_audit_finished_at = None
    firmware.kernel_config_audit_error = None
    await context.db.flush()  # MCP-handler discipline per Rule #3 — flush, not commit.

    # The background runner opens its own session; commit BEFORE spawning so
    # the new session sees `queued`.
    await context.db.commit()
    asyncio.create_task(run_kernel_config_audit_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Kernel-config audit walker enqueued. Poll firmware.kernel_config_audit_status "
            "for transition through running → completed | failed. Findings emit during "
            "the running phase; firmware.kernel_config_audit_result holds the aggregate."
        ),
    })


async def _handle_lookup_kernel_config_across_firmwares(
    input: dict,
    context: ToolContext,
) -> str:
    """Rule #44 mandatory cross-firmware aggregator for kernel-config findings.

    Filters by ``finding_source`` (one of the 10 ``kernel_config_*``
    values; see ``schemas/finding.py::KernelConfigFindingSource``).
    Returns matches grouped by firmware with ``match_count`` +
    ``supply_chain_signal`` flag when ≥2 firmware carry the same finding.

    Use cases:
      * "Which firmware in this project ship a kernel with KASLR off?"
        → finding_source='kernel_config_no_kaslr'
      * "Which firmware are missing module signing across all projects?"
        → finding_source='kernel_config_no_module_sig', scope='global'
      * "Which devices have /dev/mem exposed?"
        → finding_source='kernel_config_devmem_enabled'

    Scope defaults to 'project' (current context); pass scope='global' to
    search the entire corpus.
    """
    finding_source = input.get("finding_source")
    if not finding_source:
        return json.dumps({
            "error": (
                "finding_source required. Valid values: " +
                ", ".join(sorted(
                    [r.finding_source for r in _KSPP_RULES] + [_LSM_FINDING.finding_source]
                ))
            ),
        })
    valid_sources = {r.finding_source for r in _KSPP_RULES} | {_LSM_FINDING.finding_source}
    if finding_source not in valid_sources:
        return json.dumps({
            "error": f"unknown finding_source {finding_source!r}. Valid: {sorted(valid_sources)}",
        })
    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        return json.dumps({"error": f"scope must be 'project' or 'global', got {scope!r}"})

    stmt = (
        select(Finding, Firmware)
        .join(Firmware, Finding.firmware_id == Firmware.id)
        .where(Finding.source == finding_source)
    )
    if scope == "project" and context.project_id:
        stmt = stmt.where(Finding.project_id == context.project_id)

    result = await context.db.execute(stmt)
    rows = result.all()

    # Group by firmware.
    by_firmware: dict[str, dict] = {}
    for finding, firmware in rows:
        fw_id = str(firmware.id)
        audit_result = firmware.kernel_config_audit_result or {}
        if fw_id not in by_firmware:
            by_firmware[fw_id] = {
                "firmware_id": fw_id,
                "project_id": str(firmware.project_id),
                "original_filename": firmware.original_filename,
                "match_count": 0,
                "audit_status": firmware.kernel_config_audit_status,
                "kernel_semver": None,
                "sample_finding": None,
            }
            # Try to pluck the kernel_semver from the per-blob audit
            # result so operators see WHICH kernel version triggered the
            # finding (lets them correlate with CVE matcher output).
            per_blob = (audit_result.get("per_blob") if isinstance(audit_result, dict) else None) or []
            if per_blob and isinstance(per_blob, list):
                first = per_blob[0]
                if isinstance(first, dict):
                    by_firmware[fw_id]["kernel_semver"] = first.get("kernel_semver")
        by_firmware[fw_id]["match_count"] += 1
        if by_firmware[fw_id]["sample_finding"] is None:
            by_firmware[fw_id]["sample_finding"] = {
                "title": finding.title,
                "severity": finding.severity,
                "cwe_ids": finding.cwe_ids,
            }

    matches = sorted(by_firmware.values(), key=lambda x: x["match_count"], reverse=True)

    return json.dumps({
        "finding_source": finding_source,
        "scope": scope,
        "matches": matches,
        "total_firmwares": len(matches),
        "supply_chain_signal": len(matches) >= 2,
    }, indent=2)


# ---------------------------------------------------------------------------
# C1 EXTRACTION walker tools (distinct names — R50.2 B1).
# ---------------------------------------------------------------------------


async def _handle_trigger_kernel_config_walk(input: dict, context: ToolContext) -> str:
    """Operator-trigger the C1 kernel-config EXTRACTION walker (Rule #33 .a).

    The UPSTREAM extraction walker — guarantees metadata.kernel_config is
    populated cross-packaging (boot.img / payload.bin / 6-codec) so the
    downstream audit walker fires. Project-scope guarded (W2-β
    §SC5-NEW-ICS-S2-ε analog); 409 on in-flight rerun.
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
                "trigger_kernel_config_walk"
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

    if firmware.kernel_config_walk_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "kernel_config_walk_status": firmware.kernel_config_walk_status,
            "message": (
                f"kernel_config_walk is already {firmware.kernel_config_walk_status} "
                f"— wait for completion before re-triggering."
            ),
        })

    firmware.kernel_config_walk_status = "queued"
    firmware.kernel_config_walk_started_at = None
    firmware.kernel_config_walk_finished_at = None
    firmware.kernel_config_walk_error = None
    firmware.kernel_config_walk_result = None
    await context.db.flush()  # Rule #3 — flush, not commit, in MCP handlers.
    # Background runner opens its own session; commit BEFORE spawning so it
    # sees `queued`.
    await context.db.commit()
    asyncio.create_task(run_kernel_config_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Kernel-config EXTRACTION walker enqueued. Poll "
            "firmware.kernel_config_walk_status through running → "
            "completed | failed; harvest via get_kernel_config_extraction. "
            "On completion, metadata.kernel_config is back-filled so the "
            "downstream audit walker (audit_kernel_config_firmware) fires."
        ),
    })


async def _handle_get_kernel_config_extraction(input: dict, context: ToolContext) -> str:
    """Read the C1 extraction-walk aggregate for one firmware.

    Returns firmware.kernel_config_walk_result (the per-kernel
    extraction records — the config.json shape the cve-assessment-framework
    consumes for Gate-1). Provenance-gated: schema_version==1 +
    provenance=="walker" before trusting the kernel_config dict.
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

    result = firmware.kernel_config_walk_result
    out: dict = {
        "firmware_id": str(firmware_id),
        "kernel_config_walk_status": firmware.kernel_config_walk_status,
    }
    if not isinstance(result, dict):
        out["result"] = None
        out["hint"] = (
            f"no extraction-walk result yet (status="
            f"{firmware.kernel_config_walk_status}); trigger via "
            f"trigger_kernel_config_walk and poll until completed."
        )
        return json.dumps(out, indent=2, default=str)

    # Provenance gate — refuse to surface a non-walker / legacy result for
    # Gate-1 consumption.
    if result.get("schema_version") != 1 or result.get("provenance") != "walker":
        out["result"] = result
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate "
            f"(schema_version={result.get('schema_version')!r}, "
            f"provenance={result.get('provenance')!r}). Downstream Gate-1 "
            f"consumers MUST NOT trust the kernel_config dict — re-trigger "
            f"via trigger_kernel_config_walk."
        )
        return json.dumps(out, indent=2, default=str)

    out["result"] = result
    return json.dumps(out, indent=2, default=str)


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_linux_kernel_hardening_tools(registry: ToolRegistry) -> None:
    """Register the Linux kernel hardening MCP tools."""
    valid_sources = sorted(
        [r.finding_source for r in _KSPP_RULES] + [_LSM_FINDING.finding_source]
    )

    registry.register(
        name="audit_kernel_config_firmware",
        description=(
            "Trigger the Linux kernel-config audit walker on one firmware. "
            "Reads HardwareFirmwareBlob.metadata.kernel_config populated by "
            "the kernel_image parser (extracts IKCFG-embedded .config from "
            "vmlinux / Image / zImage / uImage), runs the KSPP-aligned rule "
            "catalogue (10 hardening checks: KASLR, /dev/mem, MODULE_SIG, "
            "LSM, STACKPROTECTOR, HARDENED_USERCOPY, FORTIFY_SOURCE, "
            "io_uring, DM_VERITY), and emits Findings. Idempotent — returns "
            "409-shaped conflict response if already running."
        ),
        input_schema={
            "type": "object",
            "required": ["firmware_id"],
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": "UUID of the firmware to audit.",
                },
            },
        },
        handler=_handle_audit_kernel_config_firmware,
    )

    registry.register(
        name="lookup_kernel_config_across_firmwares",
        description=(
            "Rule #44 mandatory cross-firmware aggregator. Query which "
            "firmware in the project (or global corpus) share the same "
            "Linux kernel-config hardening miss. Filters by finding_source "
            "(e.g. 'kernel_config_devmem_enabled'); returns matches grouped "
            "by firmware with match_count + supply_chain_signal flag (true "
            "when >=2 firmware carry the finding). Use this to answer: "
            "'which devices in our fleet ship with /dev/mem exposed?' / "
            "'which kernels are missing module signing?'"
        ),
        input_schema={
            "type": "object",
            "required": ["finding_source"],
            "properties": {
                "finding_source": {
                    "type": "string",
                    "description": (
                        "One of the 10 kernel_config_* finding sources. Valid: "
                        + ", ".join(valid_sources)
                    ),
                    "enum": valid_sources,
                },
                "scope": {
                    "type": "string",
                    "description": (
                        "'project' (default — search current project only) "
                        "or 'global' (search across the entire corpus)."
                    ),
                    "enum": ["project", "global"],
                    "default": "project",
                },
            },
        },
        handler=_handle_lookup_kernel_config_across_firmwares,
    )

    # ── C1 EXTRACTION walker tools (distinct names — R50.2 B1) ─────────────
    registry.register(
        name="trigger_kernel_config_walk",
        description=(
            "Trigger the C1 generic kernel-config EXTRACTION walker on one "
            "firmware. This is the UPSTREAM extraction layer — it guarantees "
            "HardwareFirmwareBlob.metadata.kernel_config is populated "
            "cross-packaging (Android boot.img v0-v4, A/B OTA payload.bin "
            "CrAU, 6-codec outer-envelope decompress, content-rescan of "
            "carved chunks, original-upload-archive re-extraction) so the "
            "DOWNSTREAM audit_kernel_config_firmware walker fires even on "
            "kernels the filename-bound parser missed (e.g. Android boot.img "
            "kernels carved by unblob). Idempotent — 409-shaped conflict if "
            "already running. Poll firmware.kernel_config_walk_status; "
            "harvest via get_kernel_config_extraction. DISTINCT from "
            "audit_kernel_config_firmware (the downstream KSPP audit)."
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
        handler=_handle_trigger_kernel_config_walk,
    )
    registry.register(
        name="get_kernel_config_extraction",
        description=(
            "Read the C1 kernel-config EXTRACTION walk aggregate for one "
            "firmware (firmware.kernel_config_walk_result). Returns the "
            "per-kernel records: banner, kernel_semver, arch, compression, "
            "ikconfig_present, config_entries, config_stats, the kernel_config "
            "dict (the config.json shape the cve-assessment-framework consumes "
            "for Gate-1 config_disabled), module_mode, extraction_status "
            "(ok / blocked / fallback_banner_only / live_device_recommended), "
            "and blocked_reason for the ff12d941 case. Provenance-gated "
            "(schema_version==1 + provenance=='walker'). DISTINCT from "
            "the audit result — this is the raw extracted config, not the "
            "KSPP findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware; defaults to context.firmware_id."
                    ),
                },
            },
        },
        handler=_handle_get_kernel_config_extraction,
    )


__all__ = ["register_linux_kernel_hardening_tools"]
