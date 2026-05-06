"""Hardware firmware MCP tools.

Tools for inspecting detected modem / TEE / Wi-Fi / BT / GPU / DSP / kernel
firmware blobs from the current firmware.  Detection runs automatically
after extraction; Phase 2 adds per-format parsers that fill in version,
signing, chipset, and format-specific metadata.
"""

from __future__ import annotations

import json
import os

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.hardware_firmware.cve_matcher import CveMatch
from app.services.jsonb_normalizers import _normalize_hardware_firmware_blobs_metadata


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

    if not os.path.isfile(real_path):
        return f"Error: not a file: {dtb_path}"

    try:
        import fdt  # type: ignore[import-untyped]
    except ImportError:
        return "Error: fdt library not installed (pip install fdt)."

    try:
        with open(real_path, "rb") as f:
            data = f.read(16 * 1024 * 1024)
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
