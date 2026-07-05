import asyncio
import os
from collections import Counter
from collections.abc import Callable

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services import _cache
from app.services.component_map_service import ComponentMapService
from app.utils.sandbox import safe_walk

MAX_FIND_RESULTS = 100

# Extension-based type mapping (fast first pass)
TYPE_EXTENSIONS: dict[str, set[str]] = {
    "config": {
        ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml", ".toml",
        ".properties", ".env", ".htaccess",
    },
    "certificate": {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx"},
    "python": {".py", ".pyc", ".pyo"},
    "lua": {".lua"},
    "web": {".html", ".htm", ".css", ".js", ".php", ".asp", ".jsp", ".cgi"},
    "database": {".db", ".sqlite", ".sqlite3"},
}

VALID_TYPES = {"elf", "shell_script", "config", "certificate", "python", "lua",
               "library", "database", "web"}


def _check_type_magic(filepath: str, file_type: str) -> bool:
    """Check file type using magic bytes for types that need it."""
    try:
        if file_type == "elf":
            with open(filepath, "rb") as f:
                return f.read(4) == b"\x7fELF"
        if file_type == "shell_script":
            with open(filepath, "rb") as f:
                header = f.read(2)
                return header == b"#!"
        if file_type == "database":
            with open(filepath, "rb") as f:
                return f.read(15) == b"SQLite format 3"
    except (OSError, PermissionError):
        pass
    return False


def _matches_type(filepath: str, name: str, file_type: str) -> bool:
    """Check if a file matches the requested type."""
    _, ext = os.path.splitext(name)
    ext = ext.lower()

    # Extension-based types
    if file_type in TYPE_EXTENSIONS:
        return ext in TYPE_EXTENSIONS[file_type]

    # Library: .so or .so.N patterns
    if file_type == "library":
        if ext == ".so" or ".so." in name or ext == ".a":
            return True
        return False

    # Types needing magic bytes
    if file_type == "elf":
        return _check_type_magic(filepath, "elf")

    if file_type == "shell_script":
        if ext in {".sh", ".bash"}:
            return True
        return _check_type_magic(filepath, "shell_script")

    return False


def _find_files_by_type(
    search_root: str,
    file_type: str,
    to_virtual: Callable[[str], str | None],
) -> str:
    """Walk filesystem and find files matching the requested type.

    *to_virtual* maps each real abs_path to its firmware-virtual path. Using
    this instead of a single ``real_root`` avoids ``..`` segments when the
    walk crosses multiple namespaces (e.g. searching from ``/`` with
    extraction_dir set).
    """
    if file_type not in VALID_TYPES:
        return f"Error: unknown file type '{file_type}'. Valid types: {', '.join(sorted(VALID_TYPES))}"

    matches: list[str] = []
    seen: set[str] = set()

    for dirpath, _dirs, files in safe_walk(search_root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            if not _matches_type(abs_path, name, file_type):
                continue
            vpath = to_virtual(abs_path)
            if vpath is None or vpath in seen:
                continue
            seen.add(vpath)
            matches.append(vpath)
            if len(matches) >= MAX_FIND_RESULTS:
                break
        if len(matches) >= MAX_FIND_RESULTS:
            break

    if not matches:
        return f"No files of type '{file_type}' found."

    header = f"Found {len(matches)} {file_type} file(s)"
    if len(matches) >= MAX_FIND_RESULTS:
        header += f" (showing first {MAX_FIND_RESULTS})"
    header += ":\n"
    return header + "\n".join(matches)


async def _handle_list_directory(input: dict, context: ToolContext) -> str:
    svc = context._file_service()
    entries, truncated = svc.list_directory(input["path"])

    if not entries:
        return "Empty directory."

    lines = []
    for e in entries:
        suffix = ""
        if e.type == "directory":
            suffix = "/"
        elif e.type == "symlink" and e.symlink_target:
            suffix = f" -> {e.symlink_target}"
            if e.broken:
                suffix += " [broken]"
        lines.append(f"{e.permissions}  {e.size:>8}  {e.name}{suffix}")

    result = "\n".join(lines)
    if truncated:
        result += f"\n\n... [truncated: showing first {len(entries)} entries]"
    return result


async def _handle_read_file(input: dict, context: ToolContext) -> str:
    svc = context._file_service()
    content = svc.read_file(
        path=input["path"],
        offset=input.get("offset", 0),
        length=input.get("length"),
    )

    header = f"File size: {content.size} bytes"
    if content.is_binary:
        header += " (binary, showing hex dump)"
    if content.truncated:
        header += " [truncated]"
    return f"{header}\n\n{content.content}"


async def _handle_file_info(input: dict, context: ToolContext) -> str:
    svc = context._file_service()
    info = svc.file_info(input["path"])

    lines = [
        f"Path: {info.path}",
        f"Type: {info.type}",
        f"MIME: {info.mime_type}",
        f"Size: {info.size} bytes",
        f"Permissions: {info.permissions}",
    ]
    if info.sha256:
        lines.append(f"SHA256: {info.sha256}")
    if info.elf_info:
        lines.append("ELF Info:")
        for k, v in info.elf_info.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


async def _handle_search_files(input: dict, context: ToolContext) -> str:
    svc = context._file_service()
    matches, truncated = svc.search_files(
        pattern=input["pattern"],
        path=input.get("path", "/"),
    )

    if not matches:
        return f"No files matching '{input['pattern']}' found."

    header = f"Found {len(matches)} match(es)"
    if truncated:
        header += f" (showing first {len(matches)})"
    header += ":\n"
    return header + "\n".join(matches)


async def _handle_find_files_by_type(input: dict, context: ToolContext) -> str:
    input_path = input.get("path") or "/"
    search_root = context.resolve_path(input_path)
    return _find_files_by_type(
        search_root=search_root,
        file_type=input["file_type"],
        to_virtual=context.to_virtual_path,
    )


async def _handle_get_component_map(input: dict, context: ToolContext) -> str:
    """Return a text summary of the firmware component dependency graph."""
    # Firmware-wide cache entry (binary_sha256 IS NULL)
    cached = await _cache.get_cached(
        context.db, context.firmware_id, "component_map",
    )

    if cached:
        data = cached
    else:
        # Build graph (CPU-bound) — Phase 3b: multi-root
        extra = [
            r for r in context.get_detection_roots()
            if r and r != context.extracted_path
        ]
        service = ComponentMapService(
            context.extracted_path, extra_roots=extra or None,
        )
        loop = asyncio.get_event_loop()
        graph = await loop.run_in_executor(None, service.build_graph)

        data = {
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.type, "path": n.path, "size": n.size}
                for n in graph.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "type": e.type, "details": e.details}
                for e in graph.edges
            ],
            "truncated": graph.truncated,
        }

        # Cache the result (idempotent upsert)
        await _cache.store_cached(
            context.db,
            context.firmware_id,
            "component_map",
            {**data, "nodes": [{**n, "metadata": {}} for n in data["nodes"]]},
        )

    nodes = data["nodes"]
    edges = data["edges"]

    # Build text summary
    lines: list[str] = []
    lines.append(f"Component Map: {len(nodes)} components, {len(edges)} relationships")
    if data.get("truncated"):
        lines.append("(Graph was truncated to 500 nodes)")
    lines.append("")

    # Count by type
    type_counts = Counter(n["type"] for n in nodes)
    lines.append("Component types:")
    for t, c in type_counts.most_common():
        lines.append(f"  {t}: {c}")
    lines.append("")

    # Count edge types
    edge_counts = Counter(e["type"] for e in edges)
    lines.append("Relationship types:")
    for t, c in edge_counts.most_common():
        lines.append(f"  {t}: {c}")
    lines.append("")

    # Highly-connected components (most edges)
    edge_count_per_node: dict[str, int] = {}
    for e in edges:
        edge_count_per_node[e["source"]] = edge_count_per_node.get(e["source"], 0) + 1
        edge_count_per_node[e["target"]] = edge_count_per_node.get(e["target"], 0) + 1

    top_connected = sorted(edge_count_per_node.items(), key=lambda x: x[1], reverse=True)[:15]
    if top_connected:
        lines.append("Most connected components:")
        for node_id, count in top_connected:
            # Find the node type
            node_type = ""
            for n in nodes:
                if n["id"] == node_id:
                    node_type = f" [{n['type']}]"
                    break
            lines.append(f"  {node_id}{node_type}: {count} connections")
        lines.append("")

    # Key binaries (largest by size)
    binaries = sorted(
        [n for n in nodes if n["type"] == "binary"],
        key=lambda n: n.get("size", 0),
        reverse=True,
    )[:10]
    if binaries:
        lines.append("Key binaries (by size):")
        for b in binaries:
            size_kb = b.get("size", 0) / 1024
            lines.append(f"  {b['id']} ({size_kb:.1f}KB)")
        lines.append("")

    # Init scripts and what they start
    starts_service_edges = [e for e in edges if e["type"] == "starts_service"]
    if starts_service_edges:
        lines.append("Service startup map:")
        for e in starts_service_edges:
            lines.append(f"  {e['source']} -> {e['target']}")

    return "\n".join(lines)


async def _handle_get_firmware_metadata(input: dict, context: ToolContext) -> str:
    """Return firmware image metadata (partitions, U-Boot, MTD)."""
    from app.models.firmware import Firmware
    from app.services.firmware_metadata_service import FirmwareMetadataService

    stmt = select(Firmware).where(Firmware.id == context.firmware_id)
    result = await context.db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware record not found."

    has_user_config = bool(firmware.architecture or firmware.endianness)

    if not firmware.storage_path and not has_user_config:
        return "Error: firmware storage path not available."

    lines: list[str] = []

    # User-supplied configuration (architecture, endianness) — always shown when set
    if has_user_config:
        lines.append("User Configuration:")
        if firmware.architecture:
            lines.append(f"  Architecture: {firmware.architecture}")
        if firmware.endianness:
            lines.append(f"  Endianness:   {firmware.endianness}")
        lines.append("")

    if not firmware.storage_path:
        return "\n".join(lines)

    service = FirmwareMetadataService()
    metadata = await service.scan_firmware_image(
        firmware.storage_path, context.firmware_id, context.db,
    )

    lines.append(f"Firmware Image Size: {metadata.file_size:,} bytes ({metadata.file_size / 1024 / 1024:.2f} MB)")
    lines.append("")

    # Sections table
    if metadata.sections:
        lines.append(f"Sections ({len(metadata.sections)}):")
        lines.append(f"  {'Offset':<12} {'Size':<12} {'Type'}")
        lines.append(f"  {'-' * 12} {'-' * 12} {'-' * 40}")
        for s in metadata.sections:
            offset_hex = f"0x{s.offset:08X}"
            if s.size is not None:
                if s.size >= 1024 * 1024:
                    size_str = f"{s.size / 1024 / 1024:.1f} MB"
                elif s.size >= 1024:
                    size_str = f"{s.size / 1024:.1f} KB"
                else:
                    size_str = f"{s.size} B"
            else:
                size_str = "unknown"
            lines.append(f"  {offset_hex:<12} {size_str:<12} {s.type}")
        lines.append("")

    # U-Boot header
    if metadata.uboot_header:
        h = metadata.uboot_header
        lines.append("U-Boot uImage Header:")
        lines.append(f"  Name:         {h.name}")
        lines.append(f"  OS:           {h.os_type}")
        lines.append(f"  Architecture: {h.architecture}")
        lines.append(f"  Image Type:   {h.image_type}")
        lines.append(f"  Compression:  {h.compression}")
        lines.append(f"  Load Address: {h.load_address}")
        lines.append(f"  Entry Point:  {h.entry_point}")
        lines.append(f"  Data Size:    {h.data_size:,} bytes")
        lines.append("")

    # U-Boot environment
    if metadata.uboot_env:
        lines.append(f"U-Boot Environment ({len(metadata.uboot_env)} variables):")
        for key, value in sorted(metadata.uboot_env.items()):
            # Truncate long values
            display_value = value if len(value) <= 120 else value[:117] + "..."
            lines.append(f"  {key}={display_value}")
        lines.append("")

    # MTD partitions
    if metadata.mtd_partitions:
        lines.append(f"MTD Partitions ({len(metadata.mtd_partitions)}):")
        lines.append(f"  {'Name':<20} {'Offset':<12} {'Size'}")
        lines.append(f"  {'-' * 20} {'-' * 12} {'-' * 12}")
        for p in metadata.mtd_partitions:
            offset_str = f"0x{p.offset:08X}" if p.offset is not None else "auto"
            if p.size == 0:
                size_str = "(rest)"
            elif p.size >= 1024 * 1024:
                size_str = f"{p.size / 1024 / 1024:.1f} MB"
            elif p.size >= 1024:
                size_str = f"{p.size / 1024:.1f} KB"
            else:
                size_str = f"{p.size} B"
            lines.append(f"  {p.name:<20} {offset_str:<12} {size_str}")
        lines.append("")

    if not metadata.sections and not metadata.uboot_header and not metadata.mtd_partitions:
        if not has_user_config:
            lines.append("No structural metadata found in firmware image.")

    return "\n".join(lines)


# Plain-text U-Boot env file locations (uEnv.txt-style). U-Boot reads these
# at boot via ``run loadbootenv; env import -t``. They live in the rootfs (or
# /boot partition) rather than as a packed CRC+kv block in flash.
_TEXT_UBOOT_ENV_PATHS = (
    "/uEnv.txt", "/boot/uEnv.txt",
    "/u-boot.env", "/boot/u-boot.env",
    "/etc/u-boot.env", "/etc/uboot.env",
)


def _parse_text_uboot_env(path: str) -> dict[str, str]:
    """Parse a uEnv.txt-style file. Tolerates comments, blank lines, CRLFs."""
    env: dict[str, str] = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key and key.replace("_", "").isalnum():
                    env[key] = value.strip()
    except OSError:
        pass
    return env


async def _handle_extract_bootloader_env(input: dict, context: ToolContext) -> str:
    """Return U-Boot environment variables.

    Tries two locations in order:
      1. The packed CRC+kv block scan against the raw firmware image (covers
         standalone U-Boot env partitions and env embedded in the upgrade .bin).
      2. Plain-text uEnv.txt-style files inside the extracted rootfs (covers
         U-Boot's ``env import -t`` bootflow).

    For vendor *upgrade images* the env may legitimately not be present at
    all — it lives on device flash, separate from the upgrade payload. In
    that case both scans return empty.
    """
    from app.models.firmware import Firmware
    from app.services.firmware_metadata_service import FirmwareMetadataService

    stmt = select(Firmware).where(Firmware.id == context.firmware_id)
    result = await context.db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if not firmware or not firmware.storage_path:
        return "Error: firmware storage path not available."

    # 1. Scan raw firmware image for CRC+kv env block.
    service = FirmwareMetadataService()
    metadata = await service.scan_firmware_image(
        firmware.storage_path, context.firmware_id, context.db,
    )
    binary_env = dict(metadata.uboot_env)

    # 2. Look for plain-text uEnv.txt-style files in the extracted rootfs.
    text_env: dict[str, str] = {}
    text_env_source: str | None = None
    for rel in _TEXT_UBOOT_ENV_PATHS:
        try:
            real = context.resolve_path(rel)
        except Exception:
            continue
        if os.path.isfile(real):  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop
            parsed = _parse_text_uboot_env(real)
            if parsed:
                text_env.update(parsed)
                text_env_source = rel
                break

    if not binary_env and not text_env:
        return (
            "No U-Boot environment variables found.\n\n"
            "Checked:\n"
            "  - CRC+key=value block scan of the firmware image\n"
            "  - Plain-text env files: " + ", ".join(_TEXT_UBOOT_ENV_PATHS) + "\n\n"
            "For vendor upgrade images the bootloader env often isn't present "
            "(it lives on device flash, not in the .bin). Try a full flash dump "
            "if available, or check the device's actual storage layout."
        )

    lines: list[str] = []
    if binary_env:
        lines.append(f"U-Boot Environment from image scan ({len(binary_env)} variables):")
        lines.append("")
        for key, value in sorted(binary_env.items()):
            lines.append(f"{key}={value}")
        lines.append("")

    if text_env:
        lines.append(
            f"U-Boot Environment from {text_env_source} ({len(text_env)} variables):"
        )
        lines.append("")
        for key, value in sorted(text_env.items()):
            lines.append(f"{key}={value}")

    return "\n".join(lines).strip()


def register_filesystem_tools(registry: ToolRegistry) -> None:
    """Register all filesystem tools with the given registry."""

    registry.register(
        name="list_directory",
        description=(
            "List contents of a directory in the firmware filesystem. "
            "Returns file names, types, sizes, and permissions. Max 200 entries."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (e.g. '/' or '/etc')",
                },
            },
            "required": ["path"],
        },
        handler=_handle_list_directory,
    )

    registry.register(
        name="read_file",
        description=(
            "Read contents of a file. Text files return UTF-8 content, "
            "binary files return a hex dump. Max 50KB per read. "
            "Use offset and length for partial reads of large files."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to read",
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset to start reading from (default: 0)",
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to read (default: up to 50KB)",
                },
            },
            "required": ["path"],
        },
        handler=_handle_read_file,
    )

    registry.register(
        name="file_info",
        description=(
            "Get detailed metadata for a file: type, MIME type, size, permissions, "
            "SHA256 hash, and ELF headers if applicable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to inspect",
                },
            },
            "required": ["path"],
        },
        handler=_handle_file_info,
    )

    registry.register(
        name="search_files",
        description=(
            "Search for files by glob pattern (e.g. '*.conf', 'passwd'). "
            "Returns matching file paths. Max 100 results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match file names against",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": ["pattern"],
        },
        handler=_handle_search_files,
    )

    registry.register(
        name="find_files_by_type",
        description=(
            "Find files of a specific type in the firmware filesystem. "
            "Types: elf, shell_script, config, certificate, python, lua, "
            "library, database, web."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_type": {
                    "type": "string",
                    "description": "Type of files to find",
                    "enum": sorted(VALID_TYPES),
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": ["file_type"],
        },
        handler=_handle_find_files_by_type,
    )

    registry.register(
        name="get_component_map",
        description=(
            "Get a summary of the firmware's component dependency graph. "
            "Shows component types (binaries, libraries, scripts, configs), "
            "their relationships (library linking, function imports, script execution, "
            "service startup), most connected components, and key binaries. "
            "Use this to understand the firmware architecture at a high level "
            "before diving into specific files."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_get_component_map,
        applies_to=("linux",),
    )

    registry.register(
        name="get_firmware_metadata",
        description=(
            "Get structural metadata from the raw firmware image. "
            "Returns: partition/section map (offsets, sizes, types from binwalk scan), "
            "U-Boot uImage header (OS, arch, compression, load/entry addresses), "
            "U-Boot environment variables (bootcmd, bootargs, mtdparts, etc.), "
            "and MTD partition table if present. "
            "Use this to understand the firmware image layout before diving into files."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_get_firmware_metadata,
    )

    registry.register(
        name="extract_bootloader_env",
        description=(
            "Extract U-Boot bootloader environment variables from the firmware image. "
            "Returns key=value pairs like bootcmd, bootargs, ethaddr, mtdparts, etc. "
            "Quick way to check boot configuration without scanning the full image."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_extract_bootloader_env,
    )
