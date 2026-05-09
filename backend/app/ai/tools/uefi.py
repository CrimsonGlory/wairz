"""UEFI/BIOS firmware analysis AI tools.

Tools for analyzing UEFI firmware structure: firmware volumes, DXE/PEI/SMM
modules, NVRAM variables, and module identification via GUID databases.
Operates on UEFIExtract output (.dump/ directories).
"""

import asyncio
import os
import re

from app.ai.tool_registry import ToolContext, ToolRegistry

# Well-known EDK2 / AMI / Insyde GUIDs for module identification
_KNOWN_GUIDS: dict[str, str] = {
    "1BA0062E-C779-4582-8566-336AE8F78F09": "DxeCore",
    "52C05B14-0B98-496C-BC3B-04B50211D680": "PeiCore",
    "9E21FD93-9C72-4C15-8C4B-E77F1DB2D792": "SecurityStubDxe",
    "80CF7257-87AB-47F9-A3FE-D50B76D89541": "PcdDxe",
    "B601F8C4-43B7-4784-95B1-F4226CB40CEE": "RuntimeDxe",
    "F099D67F-71AE-4C36-B2A3-DCEB0EB2B7D8": "WatchdogTimerDxe",
    "AD608272-D07F-4964-801E-7BD3B7888652": "MonotonicCounterRuntimeDxe",
    "4B28E4C7-FF36-4E10-93CF-A82159E777C5": "CapsuleRuntimeDxe",
    "42857F0A-13F2-4B21-8A23-53D3F714B840": "ConSplitterDxe",
    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D": "GraphicsConsoleDxe",
    "93B80003-9FB3-11D4-9A3A-0090273FC14D": "DevicePathDxe",
    "9FB1A1F3-3B71-4324-B39A-745CBB015FFF": "FvSimpleFileSystemDxe",
    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F": "Fat",
    "0167CCC4-D0F7-4F21-A3EF-9E64B7CDCE8B": "ScsiBusDxe",
    "0A66E322-3740-4CCE-AD62-BD172CECCA35": "ScsiDiskDxe",
    "69FD8E47-A161-4550-B01A-5594CEB2B2B2": "NvmExpressDxe",
    "B95E9FDA-26DE-48D2-8807-1F9107AC5E3A": "UhciDxe",
    "BDFE430E-8F2A-4DB0-9991-6F856594777E": "EhciDxe",
    "2FB92EFA-2EE0-4BAE-9EB6-7464125E1EF7": "XhciDxe",
    "240612B7-A063-11D4-9A3A-0090273FC14D": "UsbBusDxe",
    "2D2E62CF-9ECF-43B7-8219-94E7FC713DFE": "UsbKbDxe",
    "9FB4B4A7-42C0-4BCD-8540-9BCC6711F83E": "UsbMassStorageDxe",
    "E4F61863-FE2C-4B56-A8F4-08519BC439DF": "Variable (NVRAM)",
    "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60": "VariableRuntimeDxe",
    "378D7B65-8DA9-4773-B6E4-A47826A833E1": "Network/PxeBcDxe",
    "025BBFC7-E6A9-4B8B-82AD-6815A1AEAF4A": "MnpDxe",
    "A210F973-229D-4F4D-AA37-9895E6C9EABA": "DpcDxe",
    "529D3F93-E8E9-4E73-B1E1-BDF6A9D50113": "ArpDxe",
    # NOTE: removed 2026-05-10 (Phase Lint.B.1) — duplicate of line 38.
    # GUID E4F61863-FE2C-4B56-A8F4-08519BC439DF is EFI_VARIABLE_GUID
    # (Variable / NVRAM) per UEFI spec. The previous "FaultTolerantWriteDxe"
    # mapping here was wrong — that protocol uses GUID
    # 0AABDB99-77B6-4E7E-B12C-5CF6D2DC51AB. The ruff F601 suppression
    # picked this up as a "repeated dict key" — fixed at the source.
    "28A03FF4-12B3-4305-A417-BB1A4F94081E": "CpuDxe",
    "222C386D-5ABC-4FB4-B124-FBB82488ACF4": "SmmAccess2Dxe",
    "A0BAD966-B83B-4A78-87AB-A4E2D1E24094": "SmmControl2Dxe",
    "764BED88-DF41-45A8-BC7D-2E1AAC13C0D2": "SmmCorePerformanceLib",
}


def register_uefi_tools(registry: ToolRegistry) -> None:
    """Register all UEFI firmware analysis tools."""

    registry.register(
        name="list_firmware_volumes",
        description=(
            "List all firmware volumes in a UEFI/BIOS firmware image. "
            "Shows volume GUIDs, sizes, types (PEI, DXE, NVRAM), and "
            "the number of modules in each volume. Requires UEFIExtract "
            "output (firmware must be classified as uefi_firmware)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_list_firmware_volumes,
    )

    registry.register(
        name="list_uefi_modules",
        description=(
            "List all DXE drivers, PEI modules, and SMM drivers in the "
            "firmware with their GUIDs and human-readable names (when known). "
            "Identifies module types: SEC, PEI, DXE_CORE, DXE_DRIVER, "
            "DXE_RUNTIME_DRIVER, SMM_CORE, SMM, APPLICATION."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "volume": {
                    "type": "string",
                    "description": "Optional: filter to a specific volume directory name",
                },
            },
        },
        handler=_handle_list_uefi_modules,
    )

    registry.register(
        name="extract_nvram_variables",
        description=(
            "Extract UEFI NVRAM variables from the firmware. Shows variable "
            "names, GUIDs, attributes (runtime, boot-service, non-volatile), "
            "and data sizes. Identifies Secure Boot variables (PK, KEK, db, dbx) "
            "and other security-relevant settings."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_extract_nvram_variables,
    )

    registry.register(
        name="identify_uefi_module",
        description=(
            "Identify a UEFI module by its GUID. Cross-references against "
            "the EDK2 GUID database to provide human-readable names and "
            "module descriptions. Also reads the info.txt metadata from "
            "UEFIExtract output for detailed module information."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "guid": {
                    "type": "string",
                    "description": "UEFI module GUID (e.g. '1BA0062E-C779-4582-8566-336AE8F78F09')",
                },
            },
            "required": ["guid"],
        },
        handler=_handle_identify_uefi_module,
    )

    registry.register(
        name="read_uefi_module",
        description=(
            "Read the metadata and optionally the body of a specific UEFI "
            "module from the UEFIExtract output. Returns the info.txt "
            "contents (type, subtype, size, attributes) and can show the "
            "first N bytes of the body as hex dump."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path within the .dump/ tree (e.g. '0 Flash image/2 BIOS region/1 Volume/0 File')",
                },
                "show_hex": {
                    "type": "boolean",
                    "description": "Include hex dump of body.bin (first 256 bytes)",
                    "default": False,
                },
            },
            "required": ["path"],
        },
        handler=_handle_read_uefi_module,
    )


# ── Handlers ──────────────────────────────────────────────────────────


def _find_dump_dir(context: ToolContext) -> str | None:
    """Find the .dump directory in the extraction output."""
    root = context.extracted_path
    if not root:
        return None
    # If extracted_path IS the .dump dir
    if root.endswith(".dump"):
        return root
    # Search one level for .dump dirs
    try:
        for entry in os.scandir(root):
            if entry.is_dir() and entry.name.endswith(".dump"):
                return entry.path
    except OSError:
        pass
    # Check parent (extraction_dir)
    if context.extraction_dir:
        try:
            for entry in os.scandir(context.extraction_dir):
                if entry.is_dir() and entry.name.endswith(".dump"):
                    return entry.path
        except OSError:
            pass
    return None


def _parse_info_txt(info_path: str) -> dict[str, str]:
    """Parse UEFIExtract's info.txt into a key-value dict."""
    result: dict[str, str] = {}
    try:
        with open(info_path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if ": " in line:
                    key, _, value = line.partition(": ")
                    result[key.strip()] = value.strip()
    except OSError:
        pass
    return result


_GUID_RE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


def _extract_guid_from_dirname(dirname: str) -> str | None:
    """Extract a GUID from a UEFIExtract directory name."""
    m = _GUID_RE.search(dirname)
    return m.group(0).upper() if m else None


# ── Sync collectors (Rule #5 — called via run_in_executor) ────────────


def _collect_firmware_volumes_sync(dump_dir: str) -> list[str]:
    """Walk the .dump tree and return formatted firmware-volume lines."""
    volumes: list[str] = []
    for root, dirs, _files in os.walk(dump_dir):
        # Look for directories containing "Volume" in their name
        info_path = os.path.join(root, "info.txt")
        if not os.path.isfile(info_path):
            continue
        info = _parse_info_txt(info_path)
        ftype = info.get("Type", "")
        if "Volume" in os.path.basename(root) or "volume" in ftype.lower():
            rel = os.path.relpath(root, dump_dir)
            guid = _extract_guid_from_dirname(os.path.basename(root))
            # Count child modules
            child_count = sum(1 for d in dirs if "File" in d)
            size = info.get("Full size", info.get("Size", "unknown"))
            line = f"  {rel}"
            if guid:
                name = _KNOWN_GUIDS.get(guid, "")
                line += f"  GUID={guid}"
                if name:
                    line += f" ({name})"
            line += f"  size={size}  modules={child_count}"
            volumes.append(line)
    return volumes


def _collect_uefi_modules_sync(
    dump_dir: str, volume_filter: str | None
) -> list[str]:
    """Walk the .dump tree and return formatted UEFI module lines."""
    modules: list[str] = []
    for root, _dirs, files in os.walk(dump_dir):
        if "info.txt" not in files:
            continue
        if volume_filter and volume_filter not in root:
            continue

        info = _parse_info_txt(os.path.join(root, "info.txt"))
        subtype = info.get("Subtype", "")

        # FFS files have a "File GUID" field — this is the definitive marker
        dirname = os.path.basename(root)
        file_guid = info.get("File GUID", "")
        is_module = bool(file_guid)

        if not is_module:
            continue

        guid = file_guid.strip().upper()
        name = _KNOWN_GUIDS.get(guid, "")
        size = info.get("Full size", info.get("Size", "?"))

        # Use Subtype for human-readable label, fall back to dirname
        label = subtype or dirname.split(" ", 1)[-1] if " " in dirname else "Unknown"

        line = f"  [{label:20s}] {guid}"
        if name:
            line += f"  {name}"
        line += f"  ({size})"
        modules.append(line)
    return modules


def _collect_nvram_variables_sync(dump_dir: str) -> list[str]:
    """Walk the .dump tree and return formatted NVRAM-variable lines."""
    variables: list[str] = []
    secure_boot_guids = {
        "8BE4DF61-93CA-11D2-AA0D-00E098032B8C": "EFI Global Variable",
        "D719B2CB-3D3A-4596-A3BC-DAD00E67656F": "Secure Boot KEK",
    }
    secure_boot_vars = {"PK", "KEK", "db", "dbx", "dbt", "SecureBoot", "SetupMode"}

    for root, _dirs, files in os.walk(dump_dir):
        if "info.txt" not in files:
            continue
        info = _parse_info_txt(os.path.join(root, "info.txt"))
        # Look for NVRAM-related entries
        ftype = info.get("Type", "")
        if "NVAR" in ftype or "variable" in ftype.lower() or "VSS" in ftype:
            dirname = os.path.basename(root)
            name = info.get("Name", dirname)
            guid = _extract_guid_from_dirname(dirname) or info.get("GUID", "")
            attrs = info.get("Attributes", "")
            size = info.get("Size", info.get("Full size", "?"))

            is_secure_boot = name in secure_boot_vars or (
                guid.upper() in secure_boot_guids
            )
            marker = " [SECURE BOOT]" if is_secure_boot else ""

            line = f"  {name:30s} GUID={guid}  size={size}"
            if attrs:
                line += f"  attrs={attrs}"
            line += marker
            variables.append(line)
    return variables


def _find_uefi_module_sync(dump_dir: str, guid: str) -> list[str]:
    """Walk the .dump tree looking for the directory whose GUID matches.

    Returns the formatted lines for the first match or [] if not found.
    """
    found_info: list[str] = []
    for root, _dirs, files in os.walk(dump_dir):
        dirname = os.path.basename(root)
        dir_guid = _extract_guid_from_dirname(dirname)
        if dir_guid and dir_guid.upper() == guid:
            rel = os.path.relpath(root, dump_dir)
            found_info.append(f"Location: {rel}")
            if "info.txt" in files:
                info = _parse_info_txt(os.path.join(root, "info.txt"))
                for k, v in info.items():
                    found_info.append(f"  {k}: {v}")
            break
    return found_info


def _read_uefi_module_sync(full_path: str, show_hex: bool) -> list[str]:
    """Read the module info.txt + listing + optional hex dump synchronously."""
    lines: list[str] = []

    # Read info.txt
    info_path = os.path.join(full_path, "info.txt")
    if os.path.isfile(info_path):
        try:
            with open(info_path, errors="replace") as f:
                lines.append("=== Module Info ===")
                lines.append(f.read().strip())
        except OSError:
            pass

    # List contents
    try:
        entries = sorted(os.listdir(full_path))
        lines.append(f"\n=== Contents ({len(entries)} items) ===")
        for name in entries:
            entry_path = os.path.join(full_path, name)
            if os.path.isfile(entry_path):
                size = os.path.getsize(entry_path)
                lines.append(f"  [file] {name} ({size} bytes)")
            elif os.path.isdir(entry_path):
                lines.append(f"  [dir]  {name}/")
    except OSError:
        pass

    # Optional hex dump of body.bin
    if show_hex:
        body_path = os.path.join(full_path, "body.bin")
        if os.path.isfile(body_path):
            try:
                with open(body_path, "rb") as f:
                    data = f.read(256)
                lines.append(f"\n=== body.bin hex dump (first {len(data)} bytes) ===")
                for i in range(0, len(data), 16):
                    chunk = data[i:i + 16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    ascii_part = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in chunk
                    )
                    lines.append(f"  {i:04X}: {hex_part:<48s} {ascii_part}")
            except OSError:
                lines.append("  (could not read body.bin)")

    return lines


# ── Async handlers ────────────────────────────────────────────────────


async def _handle_list_firmware_volumes(
    input: dict, context: ToolContext
) -> str:
    dump_dir = _find_dump_dir(context)
    if not dump_dir:
        return (
            "No UEFIExtract output found. This firmware may not be "
            "UEFI/BIOS type, or extraction has not completed."
        )

    # Rule #5 — UEFIExtract dump trees can hold thousands of nested module
    # directories; walking + parsing info.txt is sync I/O. Offload.
    loop = asyncio.get_running_loop()
    volumes = await loop.run_in_executor(
        None, _collect_firmware_volumes_sync, dump_dir
    )

    if not volumes:
        return "No firmware volumes found in UEFIExtract output."

    return f"Firmware Volumes ({len(volumes)}):\n" + "\n".join(volumes)


async def _handle_list_uefi_modules(
    input: dict, context: ToolContext
) -> str:
    dump_dir = _find_dump_dir(context)
    if not dump_dir:
        return "No UEFIExtract output found."

    volume_filter = input.get("volume")

    # Rule #5 — sync walk + per-directory info.txt parse, offload.
    loop = asyncio.get_running_loop()
    modules = await loop.run_in_executor(
        None, _collect_uefi_modules_sync, dump_dir, volume_filter
    )

    if not modules:
        return "No UEFI modules found in the extraction output."

    return f"UEFI Modules ({len(modules)}):\n" + "\n".join(modules[:200])


async def _handle_extract_nvram_variables(
    input: dict, context: ToolContext
) -> str:
    dump_dir = _find_dump_dir(context)
    if not dump_dir:
        return "No UEFIExtract output found."

    # Rule #5 — sync walk + per-directory info.txt parse, offload.
    loop = asyncio.get_running_loop()
    variables = await loop.run_in_executor(
        None, _collect_nvram_variables_sync, dump_dir
    )

    if not variables:
        return (
            "No NVRAM variables found. This firmware may not have an "
            "NVRAM region, or UEFIExtract could not parse it."
        )

    return f"NVRAM Variables ({len(variables)}):\n" + "\n".join(variables[:300])


async def _handle_identify_uefi_module(
    input: dict, context: ToolContext
) -> str:
    guid = input.get("guid", "").strip().upper()
    if not _GUID_RE.match(guid):
        return f"Invalid GUID format: {guid}. Expected: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

    known_name = _KNOWN_GUIDS.get(guid)

    # Search the dump directory for this GUID
    dump_dir = _find_dump_dir(context)
    found_info: list[str] = []
    if dump_dir:
        # Rule #5 — sync walk over the dump tree, offload.
        loop = asyncio.get_running_loop()
        found_info = await loop.run_in_executor(
            None, _find_uefi_module_sync, dump_dir, guid
        )

    lines = [f"GUID: {guid}"]
    if known_name:
        lines.append(f"Known name: {known_name}")
    else:
        lines.append("Not found in built-in GUID database.")

    if found_info:
        lines.append("")
        lines.extend(found_info)

    return "\n".join(lines)


async def _handle_read_uefi_module(
    input: dict, context: ToolContext
) -> str:
    path = input.get("path", "")
    show_hex = input.get("show_hex", False)

    dump_dir = _find_dump_dir(context)
    if not dump_dir:
        return "No UEFIExtract output found."

    full_path = os.path.join(dump_dir, path.lstrip("/"))
    if not os.path.isdir(full_path):
        return f"Module directory not found: {path}"

    # Verify path is within dump_dir (sandbox check)
    real_full = os.path.realpath(full_path)
    real_dump = os.path.realpath(dump_dir)
    if not real_full.startswith(real_dump):
        return "Path traversal detected."

    # Rule #5 — info.txt read + os.listdir + body.bin read are sync I/O; offload.
    loop = asyncio.get_running_loop()
    lines = await loop.run_in_executor(
        None, _read_uefi_module_sync, full_path, show_hex
    )

    return "\n".join(lines) if lines else "No information available for this module."
