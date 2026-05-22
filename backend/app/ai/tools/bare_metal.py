"""MCP tools for the schema-driven bare-metal MCU/DSP audit walker (Rule #52).

Tool surface (Phase 1):
  - ``list_chip_families`` — enumerate the catalog
  - ``audit_bare_metal_firmware`` — trigger walker for one firmware
  - ``submit_bare_metal_descriptor`` — operator-supplied chip hint
  - ``lookup_bare_metal_findings_across_firmwares`` — Rule #44 mandatory
    cross-firmware MCP tool

Per Rule #36/#45 the walker NEVER decrypts; these MCP tools only surface
parse-only artefacts (metadata aggregates, finding rows, catalog entries).
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timezone

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models import BareMetalDescriptor, Finding, Firmware
from app.services.bare_metal_walker import run_bare_metal_audit_background
from app.services.hardware_firmware.chip_catalog import get_chip_catalog
from app.services.jsonb_normalizers import _stamp_bare_metal_descriptor_payload

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_list_chip_families(input: dict, context: ToolContext) -> str:
    """Enumerate the chip catalog. Vendor filter optional."""
    vendor_filter = (input.get("vendor") or "").strip().lower()
    catalog = get_chip_catalog()
    rows = []
    for fid, manifest in sorted(catalog.items()):
        if vendor_filter and manifest.vendor != vendor_filter:
            continue
        rows.append({
            "family_id": fid,
            "display_name": manifest.display_name,
            "vendor": manifest.vendor,
            "domains": [
                {
                    "name": d.name,
                    "arch": d.arch,
                    "endianness": d.endianness,
                    "instruction_word_bits": d.instruction_word_bits,
                    "data_word_bits": d.data_word_bits,
                    "packing": d.packing,
                    "address_regions": [r.name for r in d.address_regions],
                    "policy_count": sum(len(r.policy) for r in d.address_regions),
                }
                for d in manifest.domains
            ],
            "source_path": manifest.source_path,
        })
    return json.dumps({"chip_families": rows, "total": len(rows)}, indent=2)


async def _handle_audit_bare_metal_firmware(input: dict, context: ToolContext) -> str:
    """Trigger walker for one firmware. Returns job-status ack.

    Rule #33 .a state machine — sets status to ``queued`` synchronously,
    then dispatches the background runner. Operators poll via the result
    column or check status via ``get_bare_metal_audit_status``.
    """
    firmware_id_str = input.get("firmware_id") or str(context.firmware_id) if context.firmware_id else None
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required (or context.firmware_id must be set)"})
    try:
        firmware_id = uuid.UUID(firmware_id_str)
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    if firmware.bare_metal_audit_status in ("queued", "running"):
        return json.dumps({
            "status": "already_in_flight",
            "current_status": firmware.bare_metal_audit_status,
            "firmware_id": str(firmware_id),
            "hint": "wait for current run to complete; check bare_metal_audit_result",
        })
    firmware.bare_metal_audit_status = "queued"
    firmware.bare_metal_audit_started_at = None
    firmware.bare_metal_audit_finished_at = None
    firmware.bare_metal_audit_error = None
    await context.db.flush()

    import asyncio
    blob_path = input.get("blob_path")
    chip_target_hint = input.get("chip_target")
    asyncio.create_task(
        run_bare_metal_audit_background(
            firmware_id,
            blob_path=__import__("pathlib").Path(blob_path) if blob_path else None,
            chip_target_hint=chip_target_hint,
        )
    )
    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "hint": "audit running in background; poll firmware.bare_metal_audit_result",
    })


async def _handle_submit_bare_metal_descriptor(input: dict, context: ToolContext) -> str:
    """Operator-supplied chip family hint for a firmware (Rule #33 .a idempotent)."""
    firmware_id_str = input.get("firmware_id") or (str(context.firmware_id) if context.firmware_id else None)
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = uuid.UUID(firmware_id_str)
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})
    chip_family_hint = input.get("chip_family_hint")
    if not chip_family_hint or "/" not in chip_family_hint:
        return json.dumps({"error": "chip_family_hint required (format: 'vendor/family')"})
    catalog = get_chip_catalog()
    if chip_family_hint not in catalog:
        return json.dumps({
            "error": f"chip_family_hint {chip_family_hint!r} not in catalog",
            "known_families": sorted(catalog.keys()),
            "hint": "drop a YAML at data/chip_families/<vendor>/<family>.yaml — or use inline_chip_family (Phase 2)",
        })
    domain_hint = input.get("domain_hint") or catalog[chip_family_hint].domains[0].name
    ingestor_id = input.get("ingestor_id") or "mcp-operator"
    payload_dict = _stamp_bare_metal_descriptor_payload({
        "firmware_id": str(firmware_id),
        "descriptor_source": "operator",
        "chip_family_hint": chip_family_hint,
        "domain_hint": domain_hint,
        "evidence": input.get("evidence") or {},
        "received_at": datetime.now(UTC).isoformat(),
    })
    descriptor_hash = hashlib.sha256(
        json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    ).hexdigest()[:32]
    # Idempotency: check for existing descriptor with same (firmware, ingestor, hash)
    existing = await context.db.execute(
        select(BareMetalDescriptor).where(
            BareMetalDescriptor.firmware_id == firmware_id,
            BareMetalDescriptor.ingestor_id == ingestor_id,
            BareMetalDescriptor.descriptor_hash == descriptor_hash,
        )
    )
    prior = existing.scalar_one_or_none()
    if prior is not None:
        return json.dumps({
            "status": "idempotent_replay",
            "descriptor_id": str(prior.id),
            "chip_family_hint": chip_family_hint,
        })
    desc = BareMetalDescriptor(
        firmware_id=firmware_id,
        descriptor_source="operator",
        ingestor_id=ingestor_id,
        descriptor_hash=descriptor_hash,
        payload=payload_dict,
    )
    context.db.add(desc)
    await context.db.flush()
    return json.dumps({
        "status": "created",
        "descriptor_id": str(desc.id),
        "chip_family_hint": chip_family_hint,
        "domain_hint": domain_hint,
        "hint": "run audit_bare_metal_firmware to fire the walker",
    })


async def _handle_lookup_bare_metal_findings_across_firmwares(input: dict, context: ToolContext) -> str:
    """Rule #44 — supply-chain audit: which firmwares share the same bare-metal finding?

    Filters by ``finding_source`` (e.g. 'c28x_unsecure_csm') and optionally
    ``chip_family``. Groups results by firmware. Returns match_count +
    supply_chain_signal flag (match_count >= 2 means cross-firmware drift).
    """
    finding_source = input.get("finding_source")
    if not finding_source:
        return json.dumps({"error": "finding_source required (e.g. 'c28x_unsecure_csm')"})
    scope = input.get("scope", "project")
    chip_family_filter = input.get("chip_family")
    stmt = (
        select(Finding, Firmware)
        .join(Firmware, Finding.firmware_id == Firmware.id)
        .where(Finding.source == finding_source)
    )
    if scope == "project" and context.project_id:
        stmt = stmt.where(Finding.project_id == context.project_id)
    result = await context.db.execute(stmt)
    rows = result.all()
    if chip_family_filter:
        rows = [
            (f, fw) for (f, fw) in rows
            if (fw.bare_metal_audit_result or {}).get("chip_match", {}).get("family_id") == chip_family_filter
        ]
    # Group by firmware
    by_firmware: dict = {}
    for finding, firmware in rows:
        fw_id = str(firmware.id)
        if fw_id not in by_firmware:
            by_firmware[fw_id] = {
                "firmware_id": fw_id,
                "project_id": str(firmware.project_id),
                "original_filename": firmware.original_filename,
                "match_count": 0,
                "chip_family": (firmware.bare_metal_audit_result or {})
                    .get("chip_match", {}).get("family_id"),
                "sample_finding": None,
            }
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
        "chip_family_filter": chip_family_filter,
        "matches": matches,
        "total_firmwares": len(matches),
        "supply_chain_signal": len(matches) >= 2,
    }, indent=2)


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_bare_metal_tools(registry: ToolRegistry) -> None:
    """Register the bare-metal MCU/DSP MCP tools."""
    registry.register(
        name="list_chip_families",
        description=(
            "List all chip families in the bare-metal catalog "
            "(data/chip_families/**/*.yaml). Optional vendor filter."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vendor": {"type": "string", "description": "Optional vendor filter (e.g. 'ti', 'nxp', 'st')"},
            },
        },
        handler=_handle_list_chip_families,
    )
    registry.register(
        name="audit_bare_metal_firmware",
        description=(
            "Trigger the bare-metal MCU/DSP audit walker against a firmware. "
            "Walker resolves chip via operator descriptor or auto-detect, "
            "evaluates address-region policies (CSM PWL audit, etc.), and "
            "emits CWE-tagged findings. Returns 'queued' status — poll "
            "firmware.bare_metal_audit_result for completion."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {"type": "string", "description": "Firmware UUID; defaults to current context"},
                "blob_path": {"type": "string", "description": "Optional path to bare-metal blob; required when no hardware_firmware_blobs row exists yet"},
                "chip_target": {"type": "string", "description": "Optional vendor/family/domain to skip auto-detect"},
            },
        },
        handler=_handle_audit_bare_metal_firmware,
    )
    registry.register(
        name="submit_bare_metal_descriptor",
        description=(
            "Submit an operator-supplied chip family hint for a bare-metal "
            "firmware. Rule #33 .a idempotent on (firmware_id, ingestor_id, "
            "descriptor_hash). The walker reads the most-recent non-superseded "
            "descriptor + applies provenance precedence "
            "(operator > attested_external > unauthenticated_external > auto)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {"type": "string", "description": "Firmware UUID"},
                "chip_family_hint": {"type": "string", "description": "vendor/family from catalog (e.g. 'ti/tms320f28066')"},
                "domain_hint": {"type": "string", "description": "Optional domain name; defaults to first declared"},
                "ingestor_id": {"type": "string", "description": "Optional ingestor identifier; defaults to 'mcp-operator'"},
                "evidence": {"type": "object", "description": "Optional free-form evidence (JTAG session log, CLASSID, etc.)"},
            },
            "required": ["chip_family_hint"],
        },
        handler=_handle_submit_bare_metal_descriptor,
    )
    # ── Rule #44 mandatory cross-firmware lookup ─────────────────────
    registry.register(
        name="lookup_bare_metal_findings_across_firmwares",
        description=(
            "Supply-chain audit — find every firmware that shares a specific "
            "bare-metal finding (e.g. 'c28x_unsecure_csm'). Optional "
            "chip_family filter narrows to one chip; scope=project|global "
            "controls project vs corpus-wide. Returns match_count per "
            "firmware + supply_chain_signal flag when 2+ firmwares match — "
            "the canonical 'multiple Eaton UPS firmwares ship with the same "
            "unprogrammed CSM' detection query."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_source": {"type": "string", "description": "Finding source tag (e.g. 'c28x_unsecure_csm', 'c28x_csm_perma_lock')"},
                "chip_family": {"type": "string", "description": "Optional chip family (e.g. 'ti/tms320f28066')"},
                "scope": {"type": "string", "enum": ["project", "global"], "description": "project (default) or global"},
            },
            "required": ["finding_source"],
        },
        handler=_handle_lookup_bare_metal_findings_across_firmwares,
    )


__all__ = ["register_bare_metal_tools"]
