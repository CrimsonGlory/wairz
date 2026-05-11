"""Windows-archive MCP tools — Phase α.4.

Surfaces extracted Windows archive contents to the MCP layer:
- ``list_cab_contents`` — cabextract --list of any CAB inside the
  firmware tree.
- ``read_msix_manifest`` — parsed AppxManifest.xml capabilities + entry
  points + identity.
- ``dump_msi_custom_actions`` — MSI Binary table contents (raw bytes)
  via ``msidump --binary``. **Custom actions are extracted, NEVER
  executed** (Persona-E anti-pattern #3 / Rule #36 candidate).
- ``parse_inf_basic`` — INF section parser (Version / Manufacturer /
  Models / Strings) for driver packages.
- ``identify_psf_baseline`` — reads a PSF header to identify the
  target binary's RSDS GUID, which the operator can use to locate
  the baseline file for full reconstruction (Phase β).
- ``classify_driver_package_subtype`` — re-walks an extracted CAB tree
  to surface the driver-package subtype (cab_inf_sys_cat / dch /
  driver_store_dir / unknown).

Sandbox discipline (Rule #1): every input ``path`` is resolved via
``context.resolve_path()`` before any read; the helper ``realpath``-
walks against the firmware extraction root and raises if the target
escapes. Custom-action dumping NEVER runs the dumped bytes — the MCP
``dump_msi_custom_actions`` tool emits the bytes for the operator's
inspection, full stop.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps
include offset/limit pagination params. INF files >100 KB get
section-tail truncation.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

# defusedxml hardens against XXE / billion-laughs / external-entity attacks
# on untrusted XML (Phase Lint.B.3, 2026-05-10). MSIX AppxManifest.xml
# comes from extracted firmware archives — untrusted source. defusedxml
# exposes `fromstring` that wraps the stdlib parser with attack-rejecting
# policies; the resulting Element tree uses the stdlib's
# `xml.etree.ElementTree.Element` type (defusedxml does not re-export it),
# so type annotations and ParseError handling continue to come from the
# stdlib module.
import xml.etree.ElementTree as ET  # type-only: ET.ParseError, traversal helpers

from defusedxml.ElementTree import fromstring as _safe_fromstring

from app.ai.tool_registry import ToolContext, ToolRegistry

logger = logging.getLogger(__name__)


# ── 30 KB output cap (Rule #29) ────────────────────────────────────────────
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    """Truncate to MCP byte cap, preserving the head and noting the cut."""
    if len(text) <= cap:
        return text
    keep = cap - 64
    return text[:keep] + f"\n... [truncated; {len(text) - keep} more bytes]\n"


# ── PSF magic bytes (mirrors unpack_psf._PSF_MAGICS) ──────────────────────
_PSF_MAGICS: tuple[bytes, ...] = (b"PA30", b"PA19", b"PA17")


def register_windows_archive_tools(registry: ToolRegistry) -> None:
    """Register all Phase α.4 Windows archive MCP tools."""

    registry.register(
        name="list_cab_contents",
        description=(
            "List the file index of a CAB cabinet without extracting. Runs "
            "`cabextract --list` against a CAB inside the firmware tree. "
            "Useful for MSU update packages (lists inner CABs), driver "
            "packages (surfaces INF/SYS/CAT triplet), and any ad-hoc CAB. "
            "Output is the cabextract listing plus filename count summary; "
            "truncated at 30KB."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to a .cab file.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_list_cab_contents,
    )

    registry.register(
        name="read_msix_manifest",
        description=(
            "Parse an extracted MSIX/AppX/MSIXBundle's AppxManifest.xml or "
            "AppxBundleManifest.xml. Surfaces package identity (Name, "
            "Version, Publisher, Architecture), declared Capabilities, "
            "Entry points (Application/Executable + StartPage), Dependencies "
            "(TargetDeviceFamily MinVersion / MaxVersion). Phase β "
            "windows_pe_signature tools cover signature verification; "
            "Phase β verify_msix_blockmap covers integrity hashing."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path inside the firmware tree to AppxManifest.xml "
                        "or AppxBundleManifest.xml."
                    ),
                },
            },
            "required": ["path"],
        },
        handler=_handle_read_msix_manifest,
    )

    registry.register(
        name="dump_msi_custom_actions",
        description=(
            "Dump the MSI Binary-table contents (custom-action payloads) "
            "via `msidump --binary`. **Custom actions are EXTRACTED, NEVER "
            "EXECUTED** (Rule #36 candidate). Each Binary table row is "
            "written to disk inside the firmware tree as a child blob the "
            "operator can analyse with the existing binary-tools "
            "(decompile_function, analyze_binary_format, etc.). Returns "
            "the dump-target directory path + per-action filename map."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to the .msi file.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_dump_msi_custom_actions,
    )

    registry.register(
        name="parse_inf_basic",
        description=(
            "Parse an INF (driver info file) into structured sections. "
            "Surfaces [Version] (Class, ClassGuid, DriverPackageType, "
            "Provider), [Manufacturer], [Models] (PnP IDs + driver-section "
            "names), and [Strings] tokens. Phase γ windows_driver tools "
            "(parse_inf_directives, infer_driver_capability, "
            "validate_driver_signature) cover the deeper analysis."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to the .inf file.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_parse_inf_basic,
    )

    registry.register(
        name="identify_psf_baseline",
        description=(
            "Read a PSF (Patch Storage File / Express install delta) header "
            "to identify the target binary's RSDS GUID, which the operator "
            "uses to locate the baseline file for full reconstruction. "
            "Phase α ships the magic-validation step; Phase β "
            "apply_psf_to_baseline performs the reconstruction once the "
            "operator provides a baseline."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to the .psf file.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_identify_psf_baseline,
    )

    registry.register(
        name="classify_driver_package_subtype",
        description=(
            "Re-walk an already-extracted Windows driver-package CAB tree "
            "and classify the subtype: cab_inf_sys_cat (canonical 4-file), "
            "dch (Declarative-Componentized-Hardware via ext_*.inf), "
            "cab_inf_only / cab_sys_only (partial), driver_store_dir "
            "(FileRepository nested layout), or unknown. Use after a "
            "WINDOWS_CAB upload to surface driver-package shape without "
            "re-extracting (the unpack_driver_package worker does this "
            "automatically when WINDOWS_DRIVER_PACKAGE is the detected "
            "format; this tool is for the operator-hint reclassification "
            "path)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to the extracted CAB directory.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_classify_driver_package_subtype,
    )


# ── Handlers ───────────────────────────────────────────────────────────────


async def _handle_list_cab_contents(input: dict, context: ToolContext) -> str:
    cab_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, cab_path):
        return f"CAB file not found: {cab_path}"

    try:
        proc = await asyncio.create_subprocess_exec(
            "cabextract", "--list", cab_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return (
            "cabextract binary missing — install via Phase α.6 Dockerfile "
            "(already in the worker apt block; rebuild backend if listing "
            "from the API path)."
        )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=30)
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        return "cabextract --list timed out (>30s — possibly a corrupt CAB)"

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    if rc != 0:
        return f"cabextract --list exit={rc}\nstderr: {stderr[-500:]}"

    file_count = sum(1 for line in stdout.splitlines() if line.strip())
    return _truncate(
        f"CAB contents ({file_count} entries) for {os.path.basename(cab_path)}:\n\n"
        f"{stdout}"
    )


async def _handle_read_msix_manifest(input: dict, context: ToolContext) -> str:
    manifest_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, manifest_path):
        return f"Manifest file not found: {manifest_path}"
    try:
        xml_bytes = await loop.run_in_executor(
            None, lambda: open(manifest_path, "rb").read(),
        )
    except OSError as exc:
        return f"Manifest read failed: {exc}"

    try:
        # MSIX manifests are ASCII-XML; _safe_fromstring (defusedxml) tolerates
        # any encoding the XML declaration specifies, while rejecting XXE /
        # entity-expansion / external-entity attacks.
        root = _safe_fromstring(xml_bytes)
    except ET.ParseError as exc:
        return f"Manifest XML parse failed: {exc}"

    # MSIX namespaces vary by manifest version — collect everything.
    def _local_name(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    lines: list[str] = []
    is_bundle = _local_name(root.tag) == "Bundle"
    lines.append(
        f"Type: {'MSIXBundle (multi-package)' if is_bundle else 'MSIX/AppX (single package)'}"
    )

    # Identity (universal across manifest versions)
    for elem in root.iter():
        if _local_name(elem.tag) == "Identity":
            attrs = elem.attrib
            lines.append("\nIdentity:")
            for k, v in attrs.items():
                lines.append(f"  {k}: {v}")
            break

    # Capabilities (what permissions the package declares)
    caps_block: list[str] = []
    for elem in root.iter():
        if _local_name(elem.tag) == "Capability":
            cap_name = elem.attrib.get("Name", "(unnamed)")
            caps_block.append(f"  - {cap_name}")
        elif _local_name(elem.tag) == "DeviceCapability":
            cap_name = elem.attrib.get("Name", "(unnamed)")
            caps_block.append(f"  - DeviceCapability: {cap_name}")
        elif _local_name(elem.tag) == "RestrictedCapability":
            cap_name = elem.attrib.get("Name", "(unnamed)")
            caps_block.append(f"  - RestrictedCapability: {cap_name}")
    if caps_block:
        lines.append(f"\nCapabilities ({len(caps_block)}):")
        lines.extend(caps_block)

    # Applications / Entry points
    apps_block: list[str] = []
    for elem in root.iter():
        if _local_name(elem.tag) == "Application":
            app_id = elem.attrib.get("Id", "(no Id)")
            executable = elem.attrib.get("Executable", "")
            entry_point = elem.attrib.get("EntryPoint", "")
            apps_block.append(
                f"  - Id={app_id} Executable={executable} EntryPoint={entry_point}"
            )
    if apps_block:
        lines.append(f"\nApplications ({len(apps_block)}):")
        lines.extend(apps_block)

    # Dependencies (TargetDeviceFamily)
    deps_block: list[str] = []
    for elem in root.iter():
        if _local_name(elem.tag) == "TargetDeviceFamily":
            attrs = elem.attrib
            deps_block.append(
                f"  - {attrs.get('Name', 'Unknown')} "
                f"min={attrs.get('MinVersion', '?')} "
                f"max={attrs.get('MaxVersionTested', '?')}"
            )
    if deps_block:
        lines.append(f"\nTarget device families ({len(deps_block)}):")
        lines.extend(deps_block)

    return _truncate("\n".join(lines))


async def _handle_dump_msi_custom_actions(input: dict, context: ToolContext) -> str:
    msi_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, msi_path):
        return f"MSI file not found: {msi_path}"

    # msidump writes to a directory; create a sibling _custom_actions/ dir.
    dump_dir = msi_path + "_custom_actions"
    try:
        os.makedirs(dump_dir, exist_ok=True)
    except OSError as exc:
        return f"Could not create dump dir {dump_dir}: {exc}"

    # msidump --table=Binary <msi> dumps the Binary table (custom-action
    # payloads) as separate files. We do NOT execute any of them.
    try:
        proc = await asyncio.create_subprocess_exec(
            "msidump", "--directory", dump_dir, "--binary", msi_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return (
            "msidump binary missing — install msitools via Phase α.6 "
            "Dockerfile delta (apt: msitools)."
        )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=120)
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        return "msidump timed out (>120s)"

    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode
    if rc != 0:
        return f"msidump exit={rc}\nstderr: {stderr[-500:]}"

    # Inventory the dumped files for the operator. Single executor hop:
    # listdir + per-entry getsize for the first 50 entries, returning
    # ``(names, sizes)`` so the async caller doesn't stall the loop per
    # file (Rule #5).
    def _inventory_dump_dir_sync(directory: str) -> tuple[list[str], dict[str, int]]:
        if not os.path.isdir(directory):
            return [], {}
        names_sync = sorted(os.listdir(directory))
        sizes_sync: dict[str, int] = {}
        for n in names_sync[:50]:
            try:
                sizes_sync[n] = os.path.getsize(os.path.join(directory, n))
            except OSError:
                pass
        return names_sync, sizes_sync

    dumped, sizes = await loop.run_in_executor(
        None, _inventory_dump_dir_sync, dump_dir,
    )

    if not dumped:
        return (
            f"msidump completed (rc=0) but no Binary table entries were "
            f"emitted to {dump_dir}. The MSI may have no custom actions."
        )

    rel = os.path.relpath(  # noqa: ASYNC240 — pure-string path op; no I/O
        dump_dir, context.extracted_path or msi_path,
    )
    out = ["Custom-action dump complete (extract-only, NEVER executed).\n"]
    out.append(f"Dumped to: {rel} ({len(dumped)} entries)")
    out.append("Each entry is a Binary table stream — typically a PE binary, "
               "VBScript, JScript, or DLL fragment that the MSI engine would "
               "have invoked on install. They are dumped as raw bytes for the "
               "operator's analysis via the existing binary tools.\n")
    out.append("Files:")
    for name in dumped[:50]:
        if name in sizes:
            out.append(f"  - {name} ({sizes[name]:,} bytes)")
        else:
            out.append(f"  - {name}")
    if len(dumped) > 50:
        out.append(f"  ... and {len(dumped) - 50} more.")
    return _truncate("\n".join(out))


_INF_SECTION_RE = re.compile(r"^\[([^\]]+)\]\s*$")


async def _handle_parse_inf_basic(input: dict, context: ToolContext) -> str:
    inf_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, inf_path):
        return f"INF file not found: {inf_path}"
    try:
        text = await loop.run_in_executor(
            None,
            lambda: open(inf_path, encoding="utf-16-le", errors="replace").read()
            if open(inf_path, "rb").read(2) == b"\xff\xfe"
            else open(inf_path, encoding="utf-8", errors="replace").read(),
        )
    except OSError as exc:
        return f"INF read failed: {exc}"

    # Truncate input to 200 KB to bound parse cost (real INFs are <50 KB).
    if len(text) > 200_000:
        text = text[:200_000] + "\n; [truncated]\n"

    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        m = _INF_SECTION_RE.match(stripped)
        if m:
            current = m.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(stripped)

    out: list[str] = [
        f"INF file: {os.path.basename(inf_path)}",
        f"Total sections: {len(sections)}",
    ]

    interesting = ("Version", "Manufacturer", "Strings")
    for sec in interesting:
        if sec in sections:
            out.append(f"\n[{sec}] ({len(sections[sec])} entries)")
            for entry in sections[sec][:30]:
                out.append(f"  {entry}")
            if len(sections[sec]) > 30:
                out.append(f"  ... and {len(sections[sec]) - 30} more.")

    # Models section is variable-named (e.g. [Vendor.NTamd64]); enumerate.
    models_secs = [s for s in sections if "Model" in s or s.endswith(".NT") or ".NTamd64" in s or ".NTx86" in s or ".NTarm64" in s]
    if models_secs:
        out.append(f"\nModels-like sections ({len(models_secs)}): {models_secs}")
        for ms in models_secs[:5]:
            out.append(f"\n[{ms}] ({len(sections[ms])} entries)")
            for entry in sections[ms][:15]:
                out.append(f"  {entry}")

    # All other sections (counts only).
    other = [s for s in sections if s not in interesting and s not in models_secs]
    if other:
        out.append(f"\nOther sections ({len(other)}):")
        for s in other[:30]:
            out.append(f"  [{s}] {len(sections[s])} entries")
        if len(other) > 30:
            out.append(f"  ... and {len(other) - 30} more.")

    return _truncate("\n".join(out))


async def _handle_identify_psf_baseline(input: dict, context: ToolContext) -> str:
    psf_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, psf_path):
        return f"PSF file not found: {psf_path}"
    try:
        head = await loop.run_in_executor(
            None, lambda: open(psf_path, "rb").read(4096),
        )
    except OSError as exc:
        return f"PSF read failed: {exc}"

    matched_magic: bytes | None = None
    for magic in _PSF_MAGICS:
        if head[: len(magic)] == magic:
            matched_magic = magic
            break

    if matched_magic is None:
        return (
            f"Not a valid PSF file — expected magic in "
            f"{[m.decode() for m in _PSF_MAGICS]!r}, "
            f"got {head[:4]!r}"
        )

    # Heuristic: search the first 4KB for an RSDS GUID (the PE-debug
    # marker that PSF headers carry to identify the target binary). The
    # full PSF spec is documented but the PE-target-id field varies by
    # PSF variant; surface a best-effort RSDS scan for now.
    rsds_offset = head.find(b"RSDS")
    rsds_info = ""
    if rsds_offset >= 0 and rsds_offset + 24 <= len(head):
        guid_bytes = head[rsds_offset + 4: rsds_offset + 20]
        # Format as standard GUID string (Microsoft mixed-endian).
        d1 = int.from_bytes(guid_bytes[0:4], "little")
        d2 = int.from_bytes(guid_bytes[4:6], "little")
        d3 = int.from_bytes(guid_bytes[6:8], "little")
        d4 = guid_bytes[8:16].hex()
        guid_str = (
            f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4].upper()}-{d4[4:].upper()}"
        )
        # Age (4-byte counter following GUID)
        age = int.from_bytes(head[rsds_offset + 20: rsds_offset + 24], "little")
        rsds_info = (
            f"\nTarget binary RSDS GUID (PE PDB hash): {guid_str}\n"
            f"PDB Age: {age}\n"
            f"\nUse this GUID to locate the baseline binary in another "
            f"firmware upload (or via Microsoft's symbol server, offline "
            f"cache — Phase β). The baseline + this PSF can then be "
            f"reconstructed via the Phase β `apply_psf_to_baseline` tool."
        )

    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, psf_path)
    except OSError:
        pass

    return _truncate(
        f"PSF file: {os.path.basename(psf_path)}\n"
        f"Magic: {matched_magic.decode()} "
        f"({'Win10/11 cumulative' if matched_magic == b'PA30' else 'Win7/8' if matched_magic == b'PA19' else 'earliest'})\n"
        f"Size: {fw_size:,} bytes"
        f"{rsds_info}"
    )


async def _handle_classify_driver_package_subtype(
    input: dict, context: ToolContext,
) -> str:
    pkg_dir = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isdir, pkg_dir):
        return f"Driver-package directory not found: {pkg_dir}"

    def _walk_extensions(root: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {"inf": [], "sys": [], "cat": [], "dll": []}
        for r, _dirs, files in os.walk(root):
            for name in files:
                ext = os.path.splitext(name)[1].lower().lstrip(".")
                if ext in out:
                    out[ext].append(os.path.relpath(os.path.join(r, name), root))
        return out

    components = await loop.run_in_executor(None, _walk_extensions, pkg_dir)

    n_inf = len(components["inf"])
    n_sys = len(components["sys"])
    n_cat = len(components["cat"])
    n_dll = len(components["dll"])

    # Mirror the classification logic from unpack_driver_package.py:
    if n_inf > 0 and n_sys > 0 and n_cat > 0:
        is_dch = any(
            "ext_" in os.path.basename(p).lower()
            or "extension" in os.path.basename(p).lower()
            for p in components["inf"]
        )
        subtype = "dch" if is_dch else "cab_inf_sys_cat"
    elif n_inf > 0 and n_sys == 0:
        subtype = "cab_inf_only"
    elif n_inf == 0 and n_sys > 0:
        subtype = "cab_sys_only"
    else:
        try:
            top_entries = await loop.run_in_executor(
                None, lambda: sorted(os.listdir(pkg_dir)),
            )
            ds_pattern = any(
                "_" in e and (".inf_" in e or "_amd64_" in e or "_x86_" in e)
                for e in top_entries
            )
            subtype = "driver_store_dir" if ds_pattern else "unknown"
        except OSError:
            subtype = "unknown"

    return _truncate(
        f"Driver-package subtype: {subtype}\n\n"
        f"Component file counts:\n"
        f"  *.inf: {n_inf}  ({components['inf'][:5]}{'...' if n_inf > 5 else ''})\n"
        f"  *.sys: {n_sys}  ({components['sys'][:5]}{'...' if n_sys > 5 else ''})\n"
        f"  *.cat: {n_cat}  ({components['cat'][:5]}{'...' if n_cat > 5 else ''})\n"
        f"  *.dll: {n_dll}  ({components['dll'][:5]}{'...' if n_dll > 5 else ''})\n\n"
        "For deeper analysis use Phase γ windows_driver tools "
        "(parse_inf_directives, infer_driver_capability, "
        "validate_driver_signature)."
    )
