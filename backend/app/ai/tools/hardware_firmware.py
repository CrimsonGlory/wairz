"""Hardware firmware MCP tools.

Tools for inspecting detected modem / TEE / Wi-Fi / BT / GPU / DSP / kernel
firmware blobs from the current firmware.  Detection runs automatically
after extraction; Phase 2 adds per-format parsers that fill in version,
signing, chipset, and format-specific metadata.
"""

from __future__ import annotations

import asyncio
import json
import os

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.hardware_firmware.cve_matcher import CveMatch
from app.services.jsonb_normalizers import _normalize_hardware_firmware_blobs_metadata


def _read_dtb_sync(real_path: str) -> bytes:
    """Synchronous helper: read up to 16 MiB of a DTB blob."""
    with open(real_path, "rb") as f:
        return f.read(16 * 1024 * 1024)


async def _handle_list_hardware_firmware(input: dict, context: ToolContext) -> str:
    """List detected hardware firmware blobs for the current firmware."""
    category = input.get("category")
    vendor = input.get("vendor")
    signed_only = bool(input.get("signed_only", False))

    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == context.firmware_id,
    )
    if category:
        stmt = stmt.where(HardwareFirmwareBlob.category == category)
    if vendor:
        stmt = stmt.where(HardwareFirmwareBlob.vendor == vendor)
    if signed_only:
        stmt = stmt.where(HardwareFirmwareBlob.signed == "signed")

    stmt = stmt.order_by(HardwareFirmwareBlob.category, HardwareFirmwareBlob.blob_path)
    result = await context.db.execute(stmt)
    blobs = result.scalars().all()

    if not blobs:
        return (
            "No hardware firmware detected for this firmware. "
            "If detection hasn't run yet, wait for the post-unpack detection task to complete."
        )

    lines = [f"# Hardware firmware blobs ({len(blobs)} total)"]
    by_category: dict[str, list[HardwareFirmwareBlob]] = {}
    for b in blobs:
        by_category.setdefault(b.category, []).append(b)

    for cat in sorted(by_category.keys()):
        group = by_category[cat]
        lines.append(f"\n## {cat} ({len(group)})")
        for b in group:
            size_kb = b.file_size // 1024
            v = b.vendor or "unknown"
            ver = f" v{b.version}" if b.version else ""
            lines.append(
                f"- `{b.blob_path}` - {v}/{b.format}{ver} - {size_kb} KB - {b.signed}"
            )
    return "\n".join(lines)


async def _handle_analyze_hardware_firmware(input: dict, context: ToolContext) -> str:
    """Return detailed per-blob analysis for a single detected hardware firmware path."""
    blob_path = input.get("blob_path")
    if not blob_path:
        return "Error: blob_path is required."

    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == context.firmware_id,
        HardwareFirmwareBlob.blob_path == blob_path,
    )
    result = await context.db.execute(stmt)
    blob = result.scalars().first()
    if blob is None:
        return f"No hardware firmware blob found at path: {blob_path}"

    lines = [
        f"# Hardware firmware: {blob.blob_path}",
        "",
        f"- **Category:** {blob.category}",
        f"- **Vendor:** {blob.vendor or 'unknown'}",
        f"- **Format:** {blob.format}",
        f"- **Size:** {blob.file_size:,} bytes",
        f"- **SHA-256:** `{blob.blob_sha256}`",
        f"- **Partition:** {blob.partition or '-'}",
    ]
    if blob.version:
        lines.append(f"- **Version:** {blob.version}")
    lines.append(f"- **Signed:** {blob.signed}")
    if blob.signature_algorithm:
        lines.append(f"- **Signature algorithm:** {blob.signature_algorithm}")
    if blob.cert_subject:
        lines.append(f"- **Signing cert subject:** `{blob.cert_subject}`")
    if blob.chipset_target:
        lines.append(f"- **Chipset target:** {blob.chipset_target}")

    lines.append(f"- **Detection source:** {blob.detection_source}")
    lines.append(f"- **Detection confidence:** {blob.detection_confidence}")

    md = _normalize_hardware_firmware_blobs_metadata(blob.metadata_)
    if md:
        lines.append("")
        lines.append("## Parser metadata")
        lines.append("")
        lines.append("```json")
        try:
            lines.append(json.dumps(md, indent=2, default=str, sort_keys=True))
        except (TypeError, ValueError):
            lines.append(str(md))
        lines.append("```")

    return "\n".join(lines)


async def _handle_list_firmware_drivers(input: dict, context: ToolContext) -> str:
    """Return the driver <-> firmware graph for the current firmware."""
    from app.services.hardware_firmware.graph import build_driver_firmware_graph

    pattern = input.get("module_pattern")
    result = await build_driver_firmware_graph(context.firmware_id, context.db)

    by_driver: dict[str, dict] = {}
    for e in result.edges:
        rec = by_driver.setdefault(
            e.driver_path,
            {
                "driver_path": e.driver_path,
                "fw_deps": [],
                "resolved": [],
                "unresolved": [],
            },
        )
        if e.firmware_blob_path:
            if e.firmware_name not in rec["fw_deps"]:
                rec["fw_deps"].append(e.firmware_name)
            if e.firmware_blob_path not in rec["resolved"]:
                rec["resolved"].append(e.firmware_blob_path)
        else:
            if e.firmware_name not in rec["unresolved"]:
                rec["unresolved"].append(e.firmware_name)

    if pattern:
        pat = pattern.lower()
        by_driver = {k: v for k, v in by_driver.items() if pat in k.lower()}

    if not by_driver:
        return (
            "No driver-firmware relationships detected. Either hardware "
            "firmware detection hasn't run, no kmod/DTB blobs were parsed, "
            "or no firmware_deps entries were found in .modinfo sections."
        )

    lines = [
        "# Driver -> Firmware Graph",
        "",
        f"- **Drivers:** {len(by_driver)}",
        f"- **Kmod drivers:** {result.kmod_drivers}",
        f"- **DTB sources:** {result.dtb_sources}",
        f"- **Unresolved firmware refs:** {result.unresolved_count}",
        "",
    ]
    for driver, rec in sorted(by_driver.items()):
        lines.append(f"## `{driver}`")
        if rec["resolved"]:
            lines.append("")
            lines.append("**Resolved:**")
            for r in rec["resolved"][:20]:
                lines.append(f"- `{r}`")
            if len(rec["resolved"]) > 20:
                lines.append(f"- _(+{len(rec['resolved']) - 20} more)_")
        if rec["unresolved"]:
            lines.append("")
            lines.append("**Unresolved (missing in image):**")
            for r in rec["unresolved"][:20]:
                lines.append(f"- {r}")
            if len(rec["unresolved"]) > 20:
                lines.append(f"- _(+{len(rec['unresolved']) - 20} more)_")
        lines.append("")
    return "\n".join(lines)


async def _handle_find_unsigned_firmware(input: dict, context: ToolContext) -> str:
    """List unsigned / weakly-signed / unknown-signed firmware blobs grouped by category."""
    stmt = (
        select(HardwareFirmwareBlob)
        .where(
            HardwareFirmwareBlob.firmware_id == context.firmware_id,
            HardwareFirmwareBlob.signed.in_(["unsigned", "unknown", "weakly_signed"]),
        )
        .order_by(HardwareFirmwareBlob.category, HardwareFirmwareBlob.blob_path)
    )
    blobs = (await context.db.execute(stmt)).scalars().all()
    if not blobs:
        return "No unsigned or weakly-signed hardware firmware blobs detected."

    by_cat: dict[str, list[HardwareFirmwareBlob]] = {}
    for b in blobs:
        by_cat.setdefault(b.category, []).append(b)

    lines = [f"# Unsigned / weakly-signed firmware ({len(blobs)} blob(s))"]
    for cat in sorted(by_cat.keys()):
        group = by_cat[cat]
        lines.append(f"\n## {cat} ({len(group)})")
        for b in group:
            size_kb = b.file_size // 1024
            v = b.vendor or "unknown"
            lines.append(
                f"- `{b.blob_path}` - {v}/{b.format} - {size_kb} KB - **{b.signed}**"
            )
    return "\n".join(lines)


async def _handle_extract_dtb(input: dict, context: ToolContext) -> str:
    """Parse a DTB and emit the compatible -> firmware-name mapping per node."""
    dtb_path = input.get("dtb_path")
    if not dtb_path:
        return "Error: dtb_path is required."

    # Validate against the sandbox
    try:
        real_path = context.resolve_path(dtb_path)
    except Exception as exc:
        return f"Error: path resolution failed: {exc}"

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, real_path):
        return f"Error: not a file: {dtb_path}"

    try:
        import fdt  # type: ignore[import-untyped]
    except ImportError:
        return "Error: fdt library not installed (pip install fdt)."

    try:
        data = await loop.run_in_executor(None, _read_dtb_sync, real_path)
    except OSError as exc:
        return f"Error reading {dtb_path}: {exc}"

    try:
        dt = fdt.parse_dtb(data)
    except Exception as exc:
        return f"Error parsing DTB: {exc}"

    compat_map: list[dict] = []

    def _prop_strings(prop) -> list[str]:
        """Extract strings from a prop — tries both .data and .value shapes."""
        out: list[str] = []
        data = getattr(prop, "data", None)
        if isinstance(data, list):
            for v in data:
                if isinstance(v, str) and v:
                    out.append(v.rstrip("\x00"))
            if out:
                return out
        if isinstance(data, (bytes, bytearray)):
            for chunk in bytes(data).split(b"\x00"):
                if chunk:
                    try:
                        out.append(chunk.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
            if out:
                return out
        val = getattr(prop, "value", None)
        if isinstance(val, list):
            for v in val:
                if isinstance(v, str) and v:
                    out.append(v.rstrip("\x00"))
        elif isinstance(val, str):
            out.append(val.rstrip("\x00"))
        return out

    def _walk(node, parent_path: str = "") -> None:
        node_name = getattr(node, "name", "")
        node_path = (
            f"{parent_path}/{node_name}" if node_name and node_name != "/" else "/"
        )
        compat_prop = None
        fwname_prop = None
        for prop in getattr(node, "props", []):
            pname = getattr(prop, "name", "")
            if pname == "compatible":
                compat_prop = prop
            elif pname == "firmware-name":
                fwname_prop = prop
        if compat_prop is not None:
            compat_strings = _prop_strings(compat_prop)
            fw_names = _prop_strings(fwname_prop) if fwname_prop is not None else []
            compat_map.append(
                {
                    "path": node_path,
                    "compatible": compat_strings,
                    "firmware_name": fw_names,
                }
            )
        for child in getattr(node, "nodes", []):
            _walk(child, node_path)

    _walk(dt.root)

    if not compat_map:
        return f"No compatible nodes found in {dtb_path}."

    lines = [
        f"# DTB: {dtb_path}",
        "",
        f"{len(compat_map)} nodes with `compatible` props:",
    ]
    for entry in compat_map[:100]:
        compat = ", ".join(entry["compatible"][:3]) if entry["compatible"] else "-"
        fw = ", ".join(entry["firmware_name"]) if entry["firmware_name"] else "-"
        lines.append(
            f"- `{entry['path']}` -> compatible=`{compat}` - firmware-name=`{fw}`"
        )
    if len(compat_map) > 100:
        lines.append(f"\n_(+{len(compat_map) - 100} more nodes truncated)_")
    return "\n".join(lines)


async def _handle_export_hardware_firmware_hbom(
    input: dict, context: ToolContext,
) -> str:
    """Export a CycloneDX v1.6 HBOM for the current firmware (JSON string)."""
    from app.services.hardware_firmware.hbom_export import build_hbom

    hbom = await build_hbom(context.firmware_id, context.db)
    return json.dumps(hbom, indent=2, default=str)


async def _handle_list_extension_points(input: dict, context: ToolContext) -> str:
    """List operator-extension points (YAML surfaces + parser/family maps).

    Returns one entry per loader currently registered with the global
    ``yaml_cache.register_loader`` registry — load timestamp, entry
    summary, reload count, and last_warning (queryable so operators
    can confirm their YAML edits landed without shelling into the
    container to grep WARN logs).

    Plus two top-level maps:
    - parser_format_map — which parser handles which classifier format
      string (walked from the PARSER_REGISTRY at call time, so a new
      parser self-registering surfaces here without any tool change).
    - bt_parser_families — the BT-specific dispatch table (qca_rome /
      broadcom_hcd / mediatek_bt / realtek_bt) verbatim from
      ``parsers/bt_firmware_banner.BT_PARSER_FAMILIES``.

    Operators use this tool to:
    - Discover the 6+ YAML extension surfaces without reading docs.
    - Verify their YAML edit was actually loaded (vs silently falling
      back to in-tree defaults).
    - See the latest YAML parse error (`last_warning`) so they can fix
      a typo without context-switching to the container shell.
    """
    from app.services.hardware_firmware.cve_matcher import (
        get_known_firmware_load_rejections,
    )
    from app.services.hardware_firmware.parsers import PARSER_REGISTRY
    from app.services.hardware_firmware.parsers.bt_firmware_banner import (
        BT_PARSER_FAMILIES,
    )
    from app.utils.yaml_cache import (
        list_registered_loaders,
        surface_state_payload,
    )

    surface_filter = input.get("surface_filter")
    loaders = list_registered_loaders()

    if surface_filter:
        import re as _re
        try:
            rx = _re.compile(surface_filter, _re.IGNORECASE)
        except _re.error as exc:
            return f"Error: invalid surface_filter regex: {exc}"
        loaders = {
            name: ld for name, ld in loaders.items() if rx.search(name)
        }

    extension_surfaces = [
        surface_state_payload(name, ld)
        for name, ld in sorted(loaders.items())
    ]

    parser_format_map = {
        fmt: parser.__class__.__name__
        for fmt, parser in sorted(PARSER_REGISTRY.items())
    }

    # F-FORENSIC-10 rejection counts per layer (backlog evening:RvwC-C10).
    # Operators see "how many entries each gate rejected on last load" without
    # grepping WARN logs. Today: curated tier (cve_matcher.py) counters; future
    # P3.x may add BT-pin counters from patterns_loader.
    load_rejections = {
        "curated_known_firmware": get_known_firmware_load_rejections(),
    }

    payload = {
        "extension_surfaces": extension_surfaces,
        "parser_format_map": parser_format_map,
        "bt_parser_families": list(BT_PARSER_FAMILIES),
        "load_rejections": load_rejections,
    }
    return json.dumps(payload, indent=2, default=str, sort_keys=False)


async def _handle_verify_cve_attribution(input: dict, context: ToolContext) -> str:
    """Walk the matcher's attribution chain for a (cve_id, blob_id) tuple.

    Operators triaging "why does this blob have CVE-X?" walk YAML by hand
    today; the matcher already produces this chain internally — surfacing
    it as an MCP tool closes the operator loop. Backlog evening:RvwC-C11.

    Returns:
      * the sbom_vulnerabilities row (match_tier + match_confidence +
        adjusted CVSS) for the (firmware_id, blob_id, cve_id) tuple,
      * the blob's classification context (vendor, category, format,
        chipset_target, detected_version),
      * for curated/advisory-tier matches: the known_firmware.yaml entry
        that fired (name + narrowing fields + notes),
      * the diagnostic explanation of WHICH narrowing field matched the
        blob's data.
    """
    import uuid as _uuid

    from sqlalchemy import select

    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.models.sbom import SbomVulnerability
    from app.services.hardware_firmware.cve_matcher import _load_known_firmware

    cve_id = (input.get("cve_id") or "").strip()
    blob_id_raw = (input.get("blob_id") or "").strip()
    if not cve_id or not blob_id_raw:
        return json.dumps({
            "error": "Both cve_id and blob_id are required",
        }, indent=2)
    try:
        blob_id = _uuid.UUID(blob_id_raw)
    except ValueError:
        return json.dumps({
            "error": f"blob_id {blob_id_raw!r} is not a valid UUID",
        }, indent=2)

    # 1. Look up the persistence row
    vuln_row = (await context.db.execute(
        select(SbomVulnerability)
        .where(SbomVulnerability.firmware_id == context.firmware_id)
        .where(SbomVulnerability.blob_id == blob_id)
        .where(SbomVulnerability.cve_id == cve_id)
        .limit(1)
    )).scalar_one_or_none()
    if vuln_row is None:
        return json.dumps({
            "cve_id": cve_id,
            "blob_id": str(blob_id),
            "firmware_id": str(context.firmware_id),
            "matched": False,
            "hint": (
                "No sbom_vulnerabilities row found for this (firmware, "
                "blob, cve) tuple. Either cve-match hasn't run, or this "
                "tuple doesn't have a matcher hit. Run check_firmware_cves "
                "to populate the table."
            ),
        }, indent=2)

    # 2. Blob context
    blob_row = (await context.db.execute(
        select(HardwareFirmwareBlob)
        .where(HardwareFirmwareBlob.id == blob_id)
        .limit(1)
    )).scalar_one_or_none()
    blob_context = None
    if blob_row is not None:
        blob_context = {
            "path": blob_row.blob_path,
            "vendor": blob_row.vendor,
            "category": blob_row.category,
            "format": blob_row.format,
            "chipset_target": getattr(blob_row, "chipset_target", None),
            "detected_version": getattr(blob_row, "detected_version", None),
            "detection_confidence": getattr(
                blob_row, "detection_confidence", None,
            ),
        }

    # 3. YAML reverse-lookup for curated/advisory tier
    matching_yaml_entry: dict | None = None
    if vuln_row.match_tier in ("curated_yaml", "advisory_yaml"):
        families = _load_known_firmware()
        for fam in families:
            fam_cves = fam.get("cves") or []
            adv_id = fam.get("advisory_id")
            if cve_id in fam_cves or cve_id == adv_id:
                matching_yaml_entry = {
                    "name": fam.get("name"),
                    "advisory_id": adv_id,
                    "shared_advisory_id": bool(
                        fam.get("shared_advisory_id", False),
                    ),
                    "vendor": fam.get("vendor"),
                    "vendor_regex": fam.get("vendor_regex"),
                    "category": fam.get("category"),
                    "category_regex": fam.get("category_regex"),
                    "chipset_regex": fam.get("chipset_regex"),
                    "version_regex": fam.get("version_regex"),
                    "cves": list(fam_cves),
                    "severity": fam.get("severity"),
                    "cvss_score": fam.get("cvss_score"),
                    "notes": fam.get("notes"),
                }
                break

    return json.dumps({
        "cve_id": cve_id,
        "blob_id": str(blob_id),
        "firmware_id": str(context.firmware_id),
        "matched": True,
        "match_tier": vuln_row.match_tier,
        "match_confidence": vuln_row.match_confidence,
        "severity": vuln_row.severity,
        "cvss_score": (
            float(vuln_row.cvss_score) if vuln_row.cvss_score is not None
            else None
        ),
        "adjusted_severity": vuln_row.adjusted_severity,
        "adjusted_cvss_score": (
            float(vuln_row.adjusted_cvss_score)
            if vuln_row.adjusted_cvss_score is not None else None
        ),
        "adjustment_rationale": vuln_row.adjustment_rationale,
        "resolution_status": vuln_row.resolution_status,
        "blob_context": blob_context,
        "matching_yaml_entry": matching_yaml_entry,
    }, indent=2, default=str)


async def _handle_describe_advisory(input: dict, context: ToolContext) -> str:
    """Describe an `ADVISORY-*` ID from known_firmware.yaml.

    Operators triaging a `cve_id` that starts with `ADVISORY-` (advisory-tier
    matches like ADVISORY-FRAGATTACK / ADVISORY-BT-KNOB / etc.) walk YAML by
    hand today. This tool returns the YAML entries that declared the
    advisory_id — name, vendor, category, severity, cvss_score, notes, and
    the `shared_advisory_id` flag indicating intentional SPEC-level
    convergence across vendor entries.

    Backlog evening:RvwC-C4 — closes the operator-visibility loop on
    advisory-tier CVE attribution.
    """
    from app.services.hardware_firmware.cve_matcher import _load_known_firmware

    advisory_id = (input.get("advisory_id") or "").strip()
    if not advisory_id:
        return json.dumps({
            "error": "advisory_id is required (e.g. 'ADVISORY-FRAGATTACK')",
        }, indent=2)

    families = _load_known_firmware()
    matches = [
        {
            "name": fam.get("name"),
            "advisory_id": fam.get("advisory_id"),
            "shared_advisory_id": bool(fam.get("shared_advisory_id", False)),
            "vendor": fam.get("vendor"),
            "vendor_regex": fam.get("vendor_regex"),
            "category": fam.get("category"),
            "category_regex": fam.get("category_regex"),
            "chipset_regex": fam.get("chipset_regex"),
            "version_regex": fam.get("version_regex"),
            "severity": fam.get("severity"),
            "cvss_score": fam.get("cvss_score"),
            "cves": fam.get("cves") or [],
            "notes": fam.get("notes"),
        }
        for fam in families
        if fam.get("advisory_id") == advisory_id
    ]
    if not matches:
        return json.dumps({
            "advisory_id": advisory_id,
            "matches": [],
            "hint": (
                "No known_firmware.yaml entries match this advisory_id. "
                "Check the spelling or run `list_extension_points` to "
                "verify the YAML loaded."
            ),
        }, indent=2)
    return json.dumps({
        "advisory_id": advisory_id,
        "match_count": len(matches),
        "is_shared": all(m["shared_advisory_id"] for m in matches),
        "matches": matches,
    }, indent=2, default=str)


async def _handle_check_firmware_cves(input: dict, context: ToolContext) -> str:
    """Run the three-tier CVE matcher against all detected hw-firmware blobs."""
    from app.services.hardware_firmware.cve_matcher import match_firmware_cves

    force_rescan = bool(input.get("force_rescan", False))
    result = await match_firmware_cves(
        context.firmware_id, context.db, force_rescan=force_rescan
    )

    if not result:
        return (
            "No hardware firmware CVE matches. Either detection hasn't run, "
            "no blobs were classified/parsed, or none of them match curated "
            "CVE families.  Tier 3 (curated YAML) covers ~15 famous CVE "
            "families — modem, TEE, Wi-Fi, GPU, DSP, bootloader."
        )

    # Group non-tier-4 matches by blob.  Tier 4 (kernel CPE cartesian) is
    # streamed-persisted inside the matcher and is summarised at the top
    # rather than rendered per-blob, since it can reach 2.65 M rows on
    # Yocto-style firmware and would blow the MCP 30 KB output budget.
    by_blob: dict[str, list[CveMatch]] = {}
    for m in result.matches:
        by_blob.setdefault(str(m.blob_id), []).append(m)

    total_rendered = len(result.matches)
    header = (
        f"# Hardware firmware CVE matches "
        f"({total_rendered} non-tier-4 across {len(by_blob)} blob(s)"
    )
    if result.tier4_rows:
        header += (
            f"; tier-4 kernel-CPE: {result.tier4_rows} cartesian rows "
            f"({result.tier4_inserted} newly persisted, "
            f"{len(result.tier4_distinct_cves)} distinct kernel CVEs) — "
            f"query individual kernel_module blobs for detail"
        )
    header += ")"
    lines = [header, ""]
    for blob_id, group in by_blob.items():
        lines.append(f"## Blob `{blob_id}`")
        lines.append("")
        for m in group:
            sev = f"**{m.severity.upper()}**"
            cvss = f" (CVSS {m.cvss_score})" if m.cvss_score else ""
            tier = f"_{m.tier}_"
            conf = f"confidence={m.confidence}"
            lines.append(
                f"- {m.cve_id} · {sev}{cvss} · {tier} · {conf}"
            )
            lines.append(f"  {m.description.strip()[:200]}")
        lines.append("")
    return "\n".join(lines)


def register_hardware_firmware_tools(registry: ToolRegistry) -> None:
    """Register hardware firmware MCP tools with the given registry."""
    registry.register(
        name="list_hardware_firmware",
        description=(
            "List all detected hardware firmware blobs for the current firmware. "
            "Filter by category (modem/tee/wifi/bluetooth/gpu/dsp/camera/audio/sensor/"
            "touchpad/nfc/usb/display/fingerprint/dtb/kernel_module/bootloader/other), "
            "vendor (qualcomm/mediatek/samsung/broadcom/nvidia/imagination/arm/apple/"
            "cypress/unisoc/hisilicon/intel/realtek/unknown), or filter to only signed blobs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category, e.g. 'modem' or 'tee'.",
                },
                "vendor": {
                    "type": "string",
                    "description": "Filter by vendor, e.g. 'qualcomm'.",
                },
                "signed_only": {
                    "type": "boolean",
                    "description": "Only include blobs with signed=signed.",
                },
            },
        },
        handler=_handle_list_hardware_firmware,
    )

    registry.register(
        name="analyze_hardware_firmware",
        description=(
            "Deep analysis of a single detected hardware firmware blob: parsed "
            "headers, version, signature algorithm, signing-cert subject, chipset "
            "target, and parser-specific metadata (MBN segments, DTB compatibles, "
            ".modinfo, etc.).  Use the blob_path returned by list_hardware_firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "blob_path": {
                    "type": "string",
                    "description": (
                        "Absolute path to the blob inside the extracted firmware "
                        "(as reported by list_hardware_firmware)."
                    ),
                },
            },
            "required": ["blob_path"],
        },
        handler=_handle_analyze_hardware_firmware,
    )

    registry.register(
        name="list_firmware_drivers",
        description=(
            "Return the driver-firmware graph: kernel modules and device-tree "
            "sources with the firmware blobs they request via request_firmware(). "
            "Driver metadata comes from the .modinfo section (firmware= entries), "
            "DTB firmware-name properties, and vmlinux string scans. Unresolved "
            "references indicate missing firmware or incomplete extraction "
            "(also surface as 'Missing firmware' findings)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "module_pattern": {
                    "type": "string",
                    "description": (
                        "Optional substring filter on the driver path "
                        "(case-insensitive)."
                    ),
                },
            },
        },
        handler=_handle_list_firmware_drivers,
    )

    registry.register(
        name="check_firmware_cves",
        description=(
            "Run the three-tier CVE matcher against all detected hardware firmware "
            "blobs and return CVE matches. Results also persist to sbom_vulnerabilities "
            "with blob_id, match_tier (chipset_cpe|nvd_freetext|curated_yaml), and "
            "match_confidence (high|medium|low)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "force_rescan": {
                    "type": "boolean",
                    "description": (
                        "If true, re-run matching even for blobs that already "
                        "have persisted CVEs."
                    ),
                },
            },
        },
        handler=_handle_check_firmware_cves,
    )

    registry.register(
        name="find_unsigned_firmware",
        description=(
            "Fast triage: list all hardware firmware blobs whose signed status "
            "is 'unsigned', 'unknown', or 'weakly_signed'. Grouped by category "
            "(modem/tee/wifi/gpu/dsp/etc.).  Useful for spotting unvalidated "
            "binaries in an Android image at a glance."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=_handle_find_unsigned_firmware,
    )

    registry.register(
        name="export_hardware_firmware_hbom",
        description=(
            "Export a CycloneDX v1.6 HBOM (Hardware Bill of Materials) for "
            "the current firmware.  Emits one hardware + one firmware "
            "component per detected blob, linked via dependencies.provides, "
            "with SHA-256 hashes, supplier/manufacturer metadata, and any "
            "CVE matches attached to the firmware components.  Useful for "
            "export to external SBOM tooling (dependency-track, grype, "
            "etc.) and for compliance documentation."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=_handle_export_hardware_firmware_hbom,
    )

    registry.register(
        name="extract_dtb",
        description=(
            "Parse a Device Tree Blob (DTB or DTBO) at the given path and emit "
            "the compatible_string -> firmware_name mapping per node. Useful "
            "for understanding which drivers the kernel will bind to and which "
            "firmware files they request.  The path is validated against the "
            "firmware sandbox."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dtb_path": {
                    "type": "string",
                    "description": (
                        "Firmware-relative path to a .dtb or .dtbo file "
                        "(e.g. /dtbs/qcom/sm8450.dtb)."
                    ),
                },
            },
            "required": ["dtb_path"],
        },
        handler=_handle_extract_dtb,
    )

    registry.register(
        name="verify_cve_attribution",
        description=(
            "Walk the matcher's attribution chain for a (cve_id, blob_id) "
            "tuple. Returns the sbom_vulnerabilities row (match_tier + "
            "match_confidence), the blob's classification context "
            "(vendor / category / format / chipset_target / "
            "detected_version), and — for curated/advisory tier matches — "
            "the known_firmware.yaml entry that fired (name, narrowing "
            "fields, notes). Operators triaging 'why does this blob have "
            "CVE-X?' get the full chain in one MCP call instead of "
            "walking YAML by hand."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": (
                        "The CVE ID (e.g. 'CVE-2017-9417') or advisory ID "
                        "(e.g. 'ADVISORY-FRAGATTACK') as it appears in "
                        "sbom_vulnerabilities.cve_id."
                    ),
                },
                "blob_id": {
                    "type": "string",
                    "description": (
                        "The hardware_firmware_blobs.id UUID (string form)."
                    ),
                },
            },
            "required": ["cve_id", "blob_id"],
        },
        handler=_handle_verify_cve_attribution,
    )

    registry.register(
        name="describe_advisory",
        description=(
            "Describe an `ADVISORY-*` ID from known_firmware.yaml. "
            "Operators triaging an advisory-tier CVE match (cve_id starts "
            "with `ADVISORY-`) get the YAML entries that declared the "
            "advisory_id — name, vendor, category, severity, cvss_score, "
            "notes, and the `shared_advisory_id` flag indicating intentional "
            "SPEC-level convergence across vendor entries. Returns "
            "`is_shared: true` when ALL matching entries declare the opt-in "
            "flag (Rule #50)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "advisory_id": {
                    "type": "string",
                    "description": (
                        "The advisory ID (e.g. 'ADVISORY-FRAGATTACK', "
                        "'ADVISORY-BT-KNOB'). Case-sensitive — matches the "
                        "string in known_firmware.yaml exactly."
                    ),
                },
            },
            "required": ["advisory_id"],
        },
        handler=_handle_describe_advisory,
    )

    registry.register(
        name="list_extension_points",
        description=(
            "List all operator-extension points the wairz hardware-firmware "
            "classifier respects: YAML surfaces (vendor_prefixes, firmware_"
            "patterns, bt_qca_codenames, bt_banner_cve_pins, bt_realtek_project_"
            "ids, known_firmware, …) plus the parser-format → handler map and "
            "the BT family dispatch table. Per-surface state includes path, "
            "load timestamp, entry summary, reload count, AND last_warning "
            "(the most recent malformed-YAML message — non-null means your "
            "YAML edit silently fell back to the prior valid state). Use "
            "this to verify your YAML edits actually loaded without shelling "
            "into the container."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "surface_filter": {
                    "type": "string",
                    "description": (
                        "Optional case-insensitive regex to filter surfaces "
                        "by name (e.g. 'bt_' for BT-only surfaces)."
                    ),
                },
            },
        },
        handler=_handle_list_extension_points,
    )
