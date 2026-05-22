"""MCP tools for the Linux kernel hardening (KSPP) walker.

Tool surface (Phase 6 of the kernel_image campaign):

  - ``audit_kernel_config_firmware`` — operator-trigger walker run on
    one firmware (idempotent — Rule #33 .a 409 on in-flight rerun).
  - ``lookup_kernel_config_across_firmwares`` — **Rule #44 mandatory
    cross-firmware aggregator** — answers "which firmware in the
    corpus have CONFIG_DEVMEM=y?" / "which devices ship without
    dm-verity?" / "which firmware share the same KSPP hardening
    miss?" via grouped-by-firmware aggregation with
    ``supply_chain_signal`` flag (true when ≥2 firmware share the
    finding).

Per Rule #36/#45 the walker NEVER decrypts; these MCP tools only
surface parse-only artefacts (Finding rows + audit-result JSONB
aggregates from firmware.kernel_config_audit_result).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models import Finding, Firmware
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


__all__ = ["register_linux_kernel_hardening_tools"]
