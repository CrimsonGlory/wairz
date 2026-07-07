import asyncio
import logging
import os
import re
import shutil
import tempfile
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.models.ghidra_research import GhidraResearchFile
from app.services.ghidra_research_service import (
    GhidraResearchService,
    run_ghidra_import_background,
)
from app.services.ghidra_service import run_ghidra_subprocess
from app.utils.sandbox import PathTraversalError, validate_path
from app.utils.truncation import truncate_output

logger = logging.getLogger(__name__)

# Ghidra runs can produce verbose analysis output; give them a higher
# truncation ceiling than the 30KB MCP default so operators can see enough
# of a failing run to diagnose it without needing host/container filesystem
# access (see read_ghidra_log / list_ghidra_logs below for the sanctioned
# path to the untruncated content).
GHIDRA_OUTPUT_MAX_KB = 100


def _ghidra_logs_dir(project_id: uuid.UUID) -> str:
    settings = get_settings()
    logs_dir = os.path.join(settings.storage_root, "projects", str(project_id), "ghidra_logs")
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


def _persist_ghidra_log(project_id: uuid.UUID, label: str, content: str) -> str:
    """Write full Ghidra stdout/stderr to a durable per-project log file.

    Returns the log's filename (empty string on write failure) so callers
    can point the operator at read_ghidra_log instead of leaving the only
    untruncated copy of the output unreachable once the MCP response is
    truncated.
    """
    logs_dir = _ghidra_logs_dir(project_id)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:80]
    filename = f"{timestamp}_{uuid.uuid4().hex[:8]}_{safe_label}.log"
    full_path = os.path.join(logs_dir, filename)
    try:
        with open(full_path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except OSError:
        logger.exception("Failed to persist Ghidra log for project %s", project_id)
        return ""
    return filename


def register_ghidra_research_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="list_ghidra_research_files",
        description=(
            "List Ghidra research files uploaded to the current project. "
            "These include .gzf Ghidra archive exports (with pre-existing analysis, "
            "renamed functions, custom types, and researcher comments) and .py/.java "
            "analysis scripts. Use this to discover what prior research is available "
            "before using import_ghidra_archive or read_ghidra_script. "
            "Projects can hold hundreds of files: pass name_contains to find a "
            "specific script by name regardless of list position, or use "
            "limit/offset to page through the full set."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name_contains": {
                    "type": "string",
                    "description": (
                        "Case-insensitive substring filter over filename and "
                        "description, applied to the FULL file set before paging. "
                        "Use this to retrieve a specific script's ID even when the "
                        "project has more files than one page can show."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Max files to return after filtering (default 100).",
                    "default": 100,
                    "minimum": 1,
                },
                "offset": {
                    "type": "integer",
                    "description": "Files to skip after filtering, for paging (default 0).",
                    "default": 0,
                    "minimum": 0,
                },
            },
        },
        handler=_handle_list_ghidra_research_files,
    )

    registry.register(
        name="read_ghidra_script",
        description=(
            "Read the text content of a Ghidra research script (.py or .java) by its file ID. "
            "Use list_ghidra_research_files first to find available scripts and their IDs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "UUID of the .py or .java script to read",
                },
            },
            "required": ["file_id"],
        },
        handler=_handle_read_ghidra_script,
    )

    registry.register(
        name="save_ghidra_script",
        description=(
            "Create or update a Ghidra analysis script in the current project. "
            "Use this to save Python or Java scripts for Ghidra analysis. "
            "If a file with the same name already exists it will be updated. "
            "Allowed extensions: .py, .java, .jy."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Filename with extension, e.g. 'analyze_firmware.py'",
                },
                "content": {
                    "type": "string",
                    "description": "The text content of the script",
                },
                "description": {
                    "type": "string",
                    "description": "Optional description of the script's purpose",
                },
            },
            "required": ["filename", "content"],
        },
        handler=_handle_save_ghidra_script,
    )

    registry.register(
        name="import_ghidra_archive",
        description=(
            "Trigger Ghidra headless to import a .gzf archive file. "
            "Ghidra will load the pre-existing project (with researcher annotations, "
            "renamed functions, custom data types, and bookmarks) and run AnalyzeBinary.java "
            "to extract the annotated analysis. The import runs in the background — "
            "use get_ghidra_import_status to poll until status is 'completed' or 'failed'. "
            "Returns 409 if an import is already running."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "UUID of the .gzf archive file to import",
                },
            },
            "required": ["file_id"],
        },
        handler=_handle_import_ghidra_archive,
    )

    registry.register(
        name="get_ghidra_import_status",
        description=(
            "Check the import status and result of a Ghidra archive import job. "
            "Poll this after calling import_ghidra_archive until status is 'completed' or 'failed'. "
            "On completion, import_result contains the functions, decompilations, "
            "and researcher annotations extracted from the archive."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "UUID of the .gzf archive file",
                },
            },
            "required": ["file_id"],
        },
        handler=_handle_get_ghidra_import_status,
    )

    registry.register(
        name="resolve_firmware_path",
        description=(
            "Resolve a firmware binary path or GZF filename to its actual filesystem location(s). "
            "Accepts the same binary_path strings as run_ghidra_headless: logical name, relative path, "
            "full firmware store path, or GZF original filename. "
            "Returns raw_binary_path (the absolute path to the raw .bin file), "
            "gzf_path (the absolute path to an associated .gzf Ghidra archive, if any), "
            "and ghidra_project_dir (always null — Ghidra projects are created fresh per run). "
            "Does NOT import, analyse, or create any project. "
            "Use this to locate files for manual inspection (hexdump, unzip, etc.) "
            "or to confirm which file a script will operate on before running it."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": (
                        "Path to resolve. Accepted forms: bare filename ('rtl8761bu_fw.bin'), "
                        "virtual firmware path ('/firmware/rtl8761bu_fw.bin'), "
                        "GZF original filename ('2026-04-25_rtl8761buv_USB_fw-and-ROM.bin.gzf'), "
                        "or full absolute path."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_resolve_firmware_path,
    )

    registry.register(
        name="run_ghidra_headless",
        description=(
            "Run Ghidra analyzeHeadless directly. Two modes:\n\n"
            "INFO mode — pass flags=[\"--version\"] or flags=[\"-help\"] to query Ghidra without "
            "loading any binary. No binary_path needed.\n\n"
            "SCRIPT mode — run any Ghidra script against a binary in the current project. "
            "Specify binary_path plus either script_name (a .java/.py in the Ghidra scripts dir) "
            "or script_file_id (UUID of a research script — written to a temp dir and executed). "
            "For raw bare-metal binaries use processor/loader/base_addr/setup_script/code_offset "
            "to control how Ghidra imports the binary. If omitted, wairz auto-detects from the "
            "firmware's rtos_flavor (e.g. baremetal-mips16e → MIPS:LE:32:default + BinaryLoader). "
            "For RTOS blob-only projects binary_path can be just the filename or /firmware/<name>.\n\n"
            "GZF PROCESS mode — set use_saved_project=True and binary_path to a .gzf filename "
            "(as listed by list_ghidra_research_files). Ghidra restores the full project from the "
            "GZF on first use (all memory blocks, saved annotations, renamed functions) and then "
            "runs the script in -process mode. The restored project is cached on disk so subsequent "
            "calls skip the import step. Use this when the GZF contains multiple memory blocks "
            "(patch / data / ROM) that are lost in plain -import mode."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "flags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "INFO mode: flags to pass directly to analyzeHeadless with no project, "
                        "e.g. [\"--version\"] or [\"-help\"]."
                    ),
                },
                "binary_path": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: path to the binary. For RTOS blob-only projects use the "
                        "filename (e.g. 'rtl8761bu_fw.bin') or '/firmware/<name>'. "
                        "For Linux firmware use the path relative to the firmware root."
                    ),
                },
                "script_name": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: name of a .java or .py script already present in the "
                        "Ghidra scripts directory (e.g. 'ExtractAnnotations.java')."
                    ),
                },
                "script_file_id": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: UUID of a research script saved via save_ghidra_script. "
                        "The script will be written to a temp directory and executed. "
                        "Use list_ghidra_research_files to find available script IDs."
                    ),
                },
                "script_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "SCRIPT mode: arguments passed to the script after the script name.",
                },
                "processor": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: Ghidra language/processor ID for raw binaries, "
                        "e.g. 'MIPS:LE:32:default', 'ARM:LE:32:Cortex'. "
                        "Auto-detected from rtos_flavor when omitted."
                    ),
                },
                "loader": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: Ghidra loader name, e.g. 'BinaryLoader' for raw .bin. "
                        "Auto-detected from rtos_flavor when omitted."
                    ),
                },
                "base_addr": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: Hex or decimal load base address, e.g. '0x80100000'. "
                        "Auto-detected from rtos_flavor when omitted."
                    ),
                },
                "setup_script": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: name of a Ghidra script to run as -preScript (ISA setup), "
                        "e.g. 'Mips16eSetup.java'. Runs before auto-analysis AND before the main "
                        "script. Auto-detected from rtos_flavor when omitted."
                    ),
                },
                "code_offset": {
                    "type": "string",
                    "description": (
                        "SCRIPT mode: hex byte offset from base_addr to the first instruction, "
                        "passed as first arg to setup_script, e.g. '0x30' to skip a 48-byte "
                        "Realtek header."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": (
                        "SCRIPT mode: timeout in seconds. Defaults to ghidra_timeout setting "
                        "(300 s). Increase for long-running scripts. "
                        "For GZF process mode the same timeout covers both the import step "
                        "and the script step independently."
                    ),
                },
                "use_saved_project": {
                    "type": "boolean",
                    "description": (
                        "GZF PROCESS mode: when True and binary_path is a .gzf filename, "
                        "restore the GZF into a persistent Ghidra project (first run only, "
                        "cached by content hash) then run the script in -process mode. "
                        "Preserves all memory blocks and saved annotations from the archive."
                    ),
                },
            },
        },
        handler=_handle_run_ghidra_headless,
    )

    registry.register(
        name="export_ghidra_archive",
        description=(
            "Export the LIVE persistent Ghidra project for a .gzf archive back out "
            "as a new downloadable .gzf file — the reverse of import_ghidra_archive. "
            "Requires run_ghidra_headless(use_saved_project=True) to have been run at "
            "least once against this archive (so a persistent project exists on disk); "
            "packages that project's CURRENT state (including any renames, retyping, "
            "or comments applied by prior script runs) via Ghidra's own project-archive "
            "API. The export is registered as a NEW Ghidra research file — it does not "
            "overwrite the source archive. Download it via the ghidra-research download "
            "endpoint or a fresh list_ghidra_research_files call."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": (
                        "UUID of the source .gzf archive whose persistent project "
                        "should be exported."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": (
                        "Timeout in seconds for the export run. Defaults to the "
                        "ghidra_timeout setting (300 s)."
                    ),
                },
            },
            "required": ["file_id"],
        },
        handler=_handle_export_ghidra_archive,
    )

    registry.register(
        name="list_ghidra_logs",
        description=(
            "List Ghidra run logs persisted for the current project. Every "
            "run_ghidra_headless call writes its full (untruncated) stdout/stderr "
            "to a durable log file — use this to find one, then read_ghidra_log "
            "to retrieve its content. This is the sanctioned way to see output "
            "beyond the truncated run_ghidra_headless response; do not attempt "
            "to read Ghidra logs via host or container filesystem access."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max logs to list, most recent first. Defaults to 50.",
                },
            },
        },
        handler=_handle_list_ghidra_logs,
    )

    registry.register(
        name="read_ghidra_log",
        description=(
            "Read the content of a persisted Ghidra run log by filename "
            "(from list_ghidra_logs). Content is truncated to "
            f"{GHIDRA_OUTPUT_MAX_KB}KB by default; pass tail=true to see the "
            "end of the log instead of the start, which is usually more useful "
            "for diagnosing a failed or timed-out run."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Log filename as returned by list_ghidra_logs.",
                },
                "tail": {
                    "type": "boolean",
                    "description": "Return the last ~100KB instead of the first ~100KB.",
                },
            },
            "required": ["filename"],
        },
        handler=_handle_read_ghidra_log,
    )


async def _handle_list_ghidra_logs(input: dict, context: ToolContext) -> str:
    logs_dir = _ghidra_logs_dir(context.project_id)
    try:
        entries = [e for e in os.listdir(logs_dir) if e.endswith(".log")]
    except OSError:
        entries = []

    if not entries:
        return (
            "No Ghidra logs persisted yet for this project. "
            "Logs are written automatically after each run_ghidra_headless call."
        )

    rows: list[tuple[float, str, int]] = []
    for name in entries:
        full = os.path.join(logs_dir, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        rows.append((st.st_mtime, name, st.st_size))
    rows.sort(reverse=True)

    limit = input.get("limit")
    limit = limit if isinstance(limit, int) and limit > 0 else 50
    shown = rows[:limit]

    lines = [f"Found {len(rows)} Ghidra log(s) (showing {len(shown)}):\n"]
    for mtime, name, size in shown:
        ts = datetime.fromtimestamp(mtime, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(f"- {name}  ({size / 1024:.1f} KB, {ts})")
    lines.append("\nUse read_ghidra_log with a filename to retrieve full content.")
    return "\n".join(lines)


async def _handle_read_ghidra_log(input: dict, context: ToolContext) -> str:
    filename = (input.get("filename") or "").strip()
    if not filename:
        return "Error: filename is required. Use list_ghidra_logs to find available log filenames."

    logs_dir = _ghidra_logs_dir(context.project_id)
    try:
        full_path = validate_path(logs_dir, filename)
    except PathTraversalError:
        return f"Error: Invalid filename '{filename}'."

    if not os.path.isfile(full_path):  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop
        return f"Error: Log file '{filename}' not found in this project's Ghidra logs."

    try:
        with open(full_path, encoding="utf-8", errors="replace") as fh:  # noqa: ASYNC230 -- single bounded stat/open call, not a hot loop
            content = fh.read()
    except OSError as exc:
        return f"Error reading log file: {exc}"

    if not input.get("tail"):
        return truncate_output(content, max_kb=GHIDRA_OUTPUT_MAX_KB)

    max_bytes = GHIDRA_OUTPUT_MAX_KB * 1024
    encoded = content.encode("utf-8")
    if len(encoded) <= max_bytes:
        return content

    tail_bytes = encoded[-max_bytes:]
    first_newline = tail_bytes.find(b"\n")
    if first_newline > 0:
        tail_bytes = tail_bytes[first_newline + 1:]
    return (
        f"... [truncated: showing last ~{len(tail_bytes) / 1024:.0f}KB of "
        f"{len(encoded) / 1024:.0f}KB] ...\n\n"
        + tail_bytes.decode("utf-8", errors="replace")
    )


async def _handle_list_ghidra_research_files(input: dict, context: ToolContext) -> str:
    name_contains = input.get("name_contains") or None

    try:
        limit = int(input.get("limit", 100))
    except (TypeError, ValueError):
        return "Error: 'limit' must be an integer."
    if limit < 1:
        return "Error: 'limit' must be >= 1."

    try:
        offset = int(input.get("offset", 0))
    except (TypeError, ValueError):
        return "Error: 'offset' must be an integer."
    if offset < 0:
        return "Error: 'offset' must be >= 0."

    svc = GhidraResearchService(context.db)
    total = await svc.count_by_project(context.project_id, name_contains=name_contains)
    files = await svc.list_by_project(
        context.project_id, limit=limit, offset=offset, name_contains=name_contains,
    )
    if not files:
        if name_contains:
            return (
                f"No Ghidra research files match name_contains={name_contains!r} "
                "in this project."
            )
        return (
            "No Ghidra research files have been uploaded to this project. "
            "Upload .gzf archives or .py/.java scripts via the Ghidra Research tab in the UI."
        )

    archives = [f for f in files if f.file_category == "ghidra_archive"]
    scripts = [f for f in files if f.file_category != "ghidra_archive"]

    filter_note = f" matching name_contains={name_contains!r}" if name_contains else ""
    lines = [
        f"Found {len(files)} of {total} research file(s){filter_note} "
        f"(offset={offset}, limit={limit}):\n"
    ]

    if archives:
        lines.append("=== Ghidra Archives (.gzf) ===")
        for f in archives:
            desc = f" — {f.description}" if f.description else ""
            size_mb = f.file_size / (1024 * 1024)
            lines.append(
                f"- {f.original_filename}{desc} "
                f"({size_mb:.1f} MB) "
                f"import_status={f.import_status} "
                f"(ID: {f.id})"
            )

    if scripts:
        lines.append("\n=== Analysis Scripts ===")
        for f in scripts:
            desc = f" — {f.description}" if f.description else ""
            size_kb = f.file_size / 1024
            lines.append(
                f"- {f.original_filename}{desc} "
                f"({size_kb:.1f} KB, {f.file_category}) "
                f"(ID: {f.id})"
            )

    return "\n".join(lines)


async def _handle_read_ghidra_script(input: dict, context: ToolContext) -> str:
    file_id_str = input.get("file_id", "")
    try:
        file_id = uuid.UUID(file_id_str)
    except (ValueError, AttributeError):
        return f"Error: Invalid file ID: {file_id_str}"

    svc = GhidraResearchService(context.db)
    record = await svc.get(file_id)
    if not record or record.project_id != context.project_id:
        return f"Error: File {file_id_str} not found in this project."

    ext = os.path.splitext(record.original_filename)[1].lower()
    from app.schemas.ghidra_research import TEXT_EXTENSIONS
    if ext not in TEXT_EXTENSIONS:
        return f"Error: Cannot read binary file '{record.original_filename}'. Only .py/.java/.jy scripts are readable as text."

    content = GhidraResearchService.read_text_content(record)
    header = (
        f"Script: {record.original_filename}\n"
        f"Type: {record.content_type}\n"
        f"Size: {record.file_size} bytes\n"
    )
    if record.description:
        header += f"Description: {record.description}\n"
    header += "---\n"
    return header + content


async def _handle_save_ghidra_script(input: dict, context: ToolContext) -> str:
    filename = input.get("filename", "").strip()
    content = input.get("content", "")
    description = input.get("description")

    if not filename:
        return "Error: filename is required."
    if not content:
        return "Error: content is required and cannot be empty."

    ext = os.path.splitext(filename)[1].lower()
    from app.schemas.ghidra_research import TEXT_EXTENSIONS
    if ext not in TEXT_EXTENSIONS:
        return f"Error: '{ext}' not allowed for save_ghidra_script. Use .py, .java, or .jy."

    # Check if exists to report create vs update
    existing_result = await context.db.execute(
        select(GhidraResearchFile).where(
            GhidraResearchFile.project_id == context.project_id,
            GhidraResearchFile.original_filename == filename,
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing is not None:
        svc = GhidraResearchService(context.db)
        try:
            record = await svc.update_script_content(existing.id, content)
        except ValueError as exc:
            return f"Error: {exc}"
        size_kb = record.file_size / 1024
        return (
            f"Script updated successfully.\n"
            f"  Filename: {record.original_filename}\n"
            f"  Size: {size_kb:.1f} KB\n"
            f"  ID: {record.id}"
        )

    # Create via a fake UploadFile — use the service's upload path
    import io

    from fastapi import UploadFile as FastAPIUploadFile

    content_bytes = content.encode("utf-8")
    fake_file = FastAPIUploadFile(
        filename=filename,
        file=io.BytesIO(content_bytes),
        size=len(content_bytes),
    )

    svc = GhidraResearchService(context.db)
    try:
        record = await svc.upload(context.project_id, fake_file, description)
    except ValueError as exc:
        return f"Error: {exc}"

    size_kb = record.file_size / 1024
    return (
        f"Script created successfully.\n"
        f"  Filename: {record.original_filename}\n"
        f"  Size: {size_kb:.1f} KB\n"
        f"  ID: {record.id}"
    )


async def _handle_import_ghidra_archive(input: dict, context: ToolContext) -> str:
    file_id_str = input.get("file_id", "")
    try:
        file_id = uuid.UUID(file_id_str)
    except (ValueError, AttributeError):
        return f"Error: Invalid file ID: {file_id_str}"

    svc = GhidraResearchService(context.db)
    record = await svc.get(file_id)
    if not record or record.project_id != context.project_id:
        return f"Error: File {file_id_str} not found in this project."

    ext = os.path.splitext(record.original_filename)[1].lower()
    if ext != ".gzf":
        return f"Error: Only .gzf archives can be imported. '{record.original_filename}' is not a .gzf file."

    if record.import_status in ("queued", "running"):
        return f"Import already {record.import_status}. Use get_ghidra_import_status to check progress."

    record.import_status = "queued"
    record.import_result = None
    record.import_error = None
    await context.db.flush()

    asyncio.create_task(run_ghidra_import_background(file_id))

    return (
        f"Ghidra archive import started for '{record.original_filename}'.\n"
        f"  File ID: {file_id}\n"
        f"  Status: queued\n"
        f"Use get_ghidra_import_status with this file ID to poll for completion."
    )


async def _handle_get_ghidra_import_status(input: dict, context: ToolContext) -> str:
    file_id_str = input.get("file_id", "")
    try:
        file_id = uuid.UUID(file_id_str)
    except (ValueError, AttributeError):
        return f"Error: Invalid file ID: {file_id_str}"

    svc = GhidraResearchService(context.db)
    record = await svc.get(file_id)
    if not record or record.project_id != context.project_id:
        return f"Error: File {file_id_str} not found in this project."

    lines = [
        f"Archive: {record.original_filename}",
        f"Import status: {record.import_status}",
    ]

    if record.import_status == "failed":
        lines.append(f"Error: {record.import_error or 'Unknown error'}")
    elif record.import_status == "completed" and record.import_result:
        result = record.import_result
        func_count = len(result.get("functions", []))
        lines.append(f"Functions extracted: {func_count}")
        binary_info = result.get("binary_info", {})
        if binary_info:
            lines.append(f"Architecture: {binary_info.get('architecture', 'unknown')}")
            lines.append(f"Entry point: {binary_info.get('entry_point', 'unknown')}")
        lines.append("\nUse the binary analysis tools to query decompiled functions from this import.")
    elif record.import_status in ("queued", "running"):
        lines.append("Import is in progress. Poll again in a few seconds.")

    return "\n".join(lines)


async def _handle_export_ghidra_archive(input: dict, context: ToolContext) -> str:
    file_id_str = input.get("file_id", "")
    try:
        file_id = uuid.UUID(file_id_str)
    except (ValueError, AttributeError):
        return f"Error: Invalid file ID: {file_id_str}"

    svc = GhidraResearchService(context.db)
    record = await svc.get(file_id)
    if not record or record.project_id != context.project_id:
        return f"Error: File {file_id_str} not found in this project."

    ext = os.path.splitext(record.original_filename)[1].lower()
    if ext != ".gzf":
        return f"Error: Only .gzf archives can be exported. '{record.original_filename}' is not a .gzf file."

    if not os.path.exists(record.storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
        return f"Error: Archive file not found on disk: {record.storage_path}"

    from app.services.ghidra_service import (  # noqa: PLC0415
        _cross_process_analysis_lock,
        _format_ghidra_diag,
        _make_ghidra_preexec_fn,
        gzf_project_paths,
    )
    from app.utils.hashing import compute_file_sha256  # noqa: PLC0415

    loop = asyncio.get_running_loop()
    gzf_sha = await loop.run_in_executor(None, compute_file_sha256, record.storage_path)
    proj_base, proj_name, rep_dir = gzf_project_paths(gzf_sha)

    if not await loop.run_in_executor(None, os.path.isdir, rep_dir):
        return (
            f"Error: No persistent Ghidra project found for '{record.original_filename}'. "
            "Run run_ghidra_headless with use_saved_project=True against this archive at "
            "least once before exporting — export_ghidra_archive packages the LIVE "
            "persistent project (with any renames/retyping applied), not the pristine "
            "uploaded archive."
        )

    settings = get_settings()
    analyze_headless = os.path.join(settings.ghidra_path, "support", "analyzeHeadless")
    scripts_path = settings.ghidra_scripts_path

    timeout_override = input.get("timeout")
    timeout = timeout_override if isinstance(timeout_override, int) else settings.ghidra_timeout

    export_dir = tempfile.mkdtemp(prefix="ghidra-export-")
    export_stem = os.path.splitext(record.original_filename)[0]
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    output_filename = f"{export_stem}_export_{timestamp}.gzf"
    output_path = os.path.join(export_dir, output_filename)

    process_cmd = [
        analyze_headless,
        proj_base,
        proj_name,
        "-process", "*",
        "-noanalysis",
        "-scriptPath", scripts_path,
        "-postScript", "ExportProjectArchive.java",
        output_path,
    ]

    try:
        async with _cross_process_analysis_lock(f"gzf_{gzf_sha[:16]}"):
            with (
                tempfile.TemporaryFile(prefix="ghidra-export-out-") as out_f,
                tempfile.TemporaryFile(prefix="ghidra-export-err-") as err_f,
            ):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *process_cmd,
                        stdout=out_f,
                        stderr=err_f,
                        preexec_fn=_make_ghidra_preexec_fn(),
                    )
                except FileNotFoundError:
                    return f"Error: Ghidra not found at {analyze_headless}. Set GHIDRA_PATH in .env."

                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return f"Error: Ghidra export timed out after {timeout} s."

                out_f.seek(0)
                err_f.seek(0)
                stdout_text = out_f.read().decode("utf-8", errors="replace")
                stderr_text = err_f.read().decode("utf-8", errors="replace")

            output_exists = await loop.run_in_executor(None, os.path.isfile, output_path)
            if proc.returncode != 0 or not output_exists:
                diag = _format_ghidra_diag(stdout_text, stderr_text)
                return (
                    f"Error: Ghidra export failed (exit code {proc.returncode}) — "
                    f"'{output_filename}' not produced.\n\n"
                    f"Ghidra diagnostics:\n{diag}"
                )

        exported = await svc.register_local_file(
            context.project_id,
            output_path,
            output_filename,
            description=(
                f"Exported from the persistent project of '{record.original_filename}' "
                "via export_ghidra_archive"
            ),
        )
    finally:
        shutil.rmtree(export_dir, ignore_errors=True)

    size_mb = exported.file_size / (1024 * 1024)
    return (
        "Ghidra archive exported successfully.\n"
        f"  Source archive: {record.original_filename}\n"
        f"  Exported file:  {exported.original_filename}\n"
        f"  Size:           {size_mb:.1f} MB\n"
        f"  File ID:        {exported.id}\n"
        "Use list_ghidra_research_files to confirm it's registered, or download it via "
        f"GET /api/v1/projects/{context.project_id}/ghidra-research/{exported.id}/download"
    )


# ---------------------------------------------------------------------------
# resolve_firmware_path handler
# ---------------------------------------------------------------------------

async def _handle_resolve_firmware_path(input: dict, context: ToolContext) -> str:
    binary_path_input = (input.get("binary_path") or "").strip()
    if not binary_path_input:
        return "Error: binary_path is required."

    settings = get_settings()

    basename = os.path.basename(binary_path_input)

    raw_binary_path: str | None = None
    gzf_path: str | None = None
    logical_name: str | None = None

    # Check if the input matches a GhidraResearchFile (by original_filename or storage_path).
    # This match runs over the COMPLETE research-file set: the default 100-row
    # cap on list_by_project would make any file past the first 100 unmatchable
    # here (both the direct-name match below and the .gzf-association loop in the
    # else-branch). name_contains can't substitute — it filters original_filename
    # only, missing the storage_path-based match and the gzf-association loop's
    # basename-substring search — so size the fetch by the true count instead.
    svc = GhidraResearchService(context.db)
    total_research_files = await svc.count_by_project(context.project_id)
    research_files = await svc.list_by_project(
        context.project_id, limit=max(total_research_files, 1),
    )

    matched_research: GhidraResearchFile | None = None
    for rf in research_files:
        if (
            rf.original_filename == basename
            or rf.original_filename == binary_path_input
            or rf.storage_path == binary_path_input
            or os.path.basename(rf.storage_path) == basename
        ):
            matched_research = rf
            break

    if matched_research:
        rf_ext = os.path.splitext(matched_research.original_filename)[1].lower()
        logical_name = matched_research.original_filename
        if rf_ext == ".gzf":
            sp = matched_research.storage_path
            gzf_path = sp if os.path.exists(sp) else None  # noqa: ASYNC240 — pre-flight stat, no walk
            # For a GZF input, the raw binary is the project's firmware blob
            if context.storage_path and os.path.isfile(context.storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
                raw_binary_path = context.storage_path
        else:
            return (
                f"Note: '{matched_research.original_filename}' is a script/non-binary research file "
                f"(category: {matched_research.file_category}), not a firmware binary or GZF archive.\n"
                f"Storage path: {matched_research.storage_path}"
            )
    else:
        # Resolve as a firmware tree path — same fallback chain as run_ghidra_headless
        try:
            resolved = context.resolve_path(binary_path_input)
        except Exception:
            resolved = ""

        if not os.path.isfile(resolved) and context.storage_path and os.path.isfile(context.storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
            resolved = context.storage_path

        if not os.path.isfile(resolved):  # noqa: ASYNC240 — pre-flight stat, no walk
            return (
                f"Error: Cannot resolve '{binary_path_input}'. "
                "No matching file found in the firmware tree or Ghidra research files for this project."
            )

        raw_binary_path = resolved
        logical_name = os.path.basename(resolved)

        # Look for an associated .gzf by checking if the binary name appears in any archive filename
        binary_base = os.path.splitext(logical_name)[0].lower()
        for rf in research_files:
            if rf.file_category == "ghidra_archive":
                gzf_name_lower = rf.original_filename.lower()
                if logical_name.lower() in gzf_name_lower or binary_base in gzf_name_lower:
                    if os.path.exists(rf.storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
                        gzf_path = rf.storage_path
                        break

    # Derive stable project dir for this GZF (single source of truth:
    # ghidra_service.gzf_project_paths, shared with _run_gzf_process_mode
    # and the read-path .gzf process-mode routing in ensure_analysis).
    ghidra_project_dir: str | None = None
    if gzf_path and os.path.isfile(gzf_path):  # noqa: ASYNC240 — pre-flight stat, no walk
        from app.services.ghidra_service import gzf_project_paths  # noqa: PLC0415
        from app.utils.hashing import compute_file_sha256  # noqa: PLC0415
        loop = asyncio.get_running_loop()
        gzf_sha = await loop.run_in_executor(None, compute_file_sha256, gzf_path)
        candidate, _, rep_candidate = gzf_project_paths(gzf_sha)
        if os.path.isdir(rep_candidate):  # noqa: ASYNC240 — pre-flight stat, no walk
            ghidra_project_dir = candidate

    lines = [
        "Resolved firmware path:",
        f"  logical_name:       {logical_name}",
        f"  raw_binary_path:    {raw_binary_path}",
        f"  gzf_path:           {gzf_path}",
        f"  ghidra_project_dir: {ghidra_project_dir or 'null  (project not yet restored — run with use_saved_project=True)'}",
    ]

    if gzf_path:
        lines += [
            "",
            "The .gzf is a standard ZIP archive.",
            "List its members:  unzip -l '" + gzf_path + "'",
            "Extract a block:   unzip -p '" + gzf_path + "' '<member>' > /tmp/block.bin",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GZF process-mode helper
# ---------------------------------------------------------------------------

async def _run_gzf_process_mode(
    gzf_path: str,
    script_name: str,
    script_args: list[str],
    extra_script_path: str | None,
    timeout: int,  # noqa: ASYNC109 -- caller-supplied timeout per Rule #29 contract
    project_id: uuid.UUID,
    context: ToolContext,
) -> str:
    """Restore a GZF into a persistent Ghidra project and run script_name in
    -process mode against it, KEEPING the project on disk.

    The project directory is keyed by the first 16 hex chars of the GZF
    content SHA256, so the same archive always maps to the same directory.
    An OS-level flock on that key ensures only one process runs the -import
    step even when multiple wairz-mcp connections hit the same GZF simultaneously.

    After a successful script run, the persistent project is the golden copy of
    the renamed/retyped state — it is NOT exported back to the .gzf file and is
    NOT deleted. Two things make subsequent reads observe the changes:

      1. The persistent project's monotonic rev counter is bumped
         (bump_gzf_project_rev_sync). ensure_analysis compares this rev against
         the rev stamped in the cached ghidra_full_analysis sentinel and
         rebuilds the cache whenever they diverge, so list_functions /
         find_callers / get_xrefs see the renames durably (not just once).
      2. The analysis cache for this GZF is cleared eagerly here so the very
         next read (even in another process) re-analyzes against the renamed
         project rather than serving stale pre-rename names — including
         orphaned single-function decompile:<old_name> entries.

    Returns the combined output string (same shape as import-mode).
    """
    settings = get_settings()
    analyze_headless = os.path.join(settings.ghidra_path, "support", "analyzeHeadless")

    from app.database import async_session_factory  # noqa: PLC0415
    from app.services.ghidra_service import (  # noqa: PLC0415
        _cross_process_analysis_lock,
        _format_ghidra_diag,
        _make_ghidra_preexec_fn,
        bump_gzf_project_rev_sync,
        clear_binary_analysis,
        gzf_project_paths,
    )
    from app.utils.hashing import compute_file_sha256  # noqa: PLC0415

    loop = asyncio.get_running_loop()
    gzf_sha = await loop.run_in_executor(None, compute_file_sha256, gzf_path)

    proj_base, proj_name, rep_dir = gzf_project_paths(gzf_sha)

    # Serialise the import step across all processes for this GZF.
    # The flock is released before the process step so concurrent script
    # runs against the same already-imported project are allowed.
    async with _cross_process_analysis_lock(f"gzf_{gzf_sha[:16]}"):
        rep_exists = await loop.run_in_executor(None, os.path.isdir, rep_dir)

        if not rep_exists:
            await loop.run_in_executor(None, lambda: os.makedirs(proj_base, exist_ok=True))

            import_cmd = [
                analyze_headless,
                proj_base,
                proj_name,
                "-import", gzf_path,
                "-noanalysis",
                "-overwrite",
            ]
            logger.info(
                "GZF process-mode: importing %s → %s",
                os.path.basename(gzf_path), proj_base,
            )

            with (
                tempfile.TemporaryFile(prefix="ghidra-gzf-import-out-") as out_f,
                tempfile.TemporaryFile(prefix="ghidra-gzf-import-err-") as err_f,
            ):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *import_cmd,
                        stdout=out_f,
                        stderr=err_f,
                        preexec_fn=_make_ghidra_preexec_fn(),
                    )
                except FileNotFoundError:
                    return f"Error: Ghidra not found at {analyze_headless}. Set GHIDRA_PATH in .env."

                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return f"Error: GZF import timed out after {timeout} s."

                out_f.seek(0)
                err_f.seek(0)
                import_stdout = out_f.read().decode("utf-8", errors="replace")
                import_stderr = err_f.read().decode("utf-8", errors="replace")

            if not await loop.run_in_executor(None, os.path.isdir, rep_dir):
                diag = _format_ghidra_diag(import_stdout, import_stderr)
                return (
                    f"Error: GZF import failed (exit code {proc.returncode}) — "
                    f"{proj_name}.rep not created.\n\n"
                    f"Ghidra diagnostics:\n{diag}\n\n"
                    f"=== import stdout ===\n{import_stdout[:3000]}\n"
                    f"=== import stderr ===\n{import_stderr[:3000]}"
                )

            logger.info("GZF process-mode: import complete at %s", rep_dir)

    # --- process step (outside the lock: concurrent script runs are fine) ---
    scripts_path = settings.ghidra_scripts_path

    process_cmd = [
        analyze_headless,
        proj_base,
        proj_name,
        "-process", "*",
        "-noanalysis",
    ]
    if extra_script_path:
        # Single combined -scriptPath flag, and an ABSOLUTE -postScript
        # path — see _build_analyze_command's extra_script_path docstring
        # in ghidra_service.py for the empirically-verified reasons: two
        # separate -scriptPath flags drop the first one entirely, and
        # bare-name collision resolution across directories is
        # alphabetical-last-wins, not first-match.
        process_cmd.extend(["-scriptPath", f"{extra_script_path};{scripts_path}"])
        postscript_target = os.path.join(extra_script_path, script_name)
    else:
        process_cmd.extend(["-scriptPath", scripts_path])
        postscript_target = script_name
    process_cmd.extend(["-postScript", postscript_target])
    if script_args:
        process_cmd.extend(script_args)

    logger.info(
        "GZF process-mode: running %s on project %s", script_name, proj_base,
    )

    with (
        tempfile.TemporaryFile(prefix="ghidra-gzf-proc-out-") as out_f,
        tempfile.TemporaryFile(prefix="ghidra-gzf-proc-err-") as err_f,
    ):
        try:
            proc = await asyncio.create_subprocess_exec(
                *process_cmd,
                stdout=out_f,
                stderr=err_f,
                preexec_fn=_make_ghidra_preexec_fn(),
            )
        except FileNotFoundError:
            return f"Error: Ghidra not found at {analyze_headless}. Set GHIDRA_PATH in .env."

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Error: GZF process-mode script timed out after {timeout} s."

        out_f.seek(0)
        err_f.seek(0)
        stdout_text = out_f.read().decode("utf-8", errors="replace")
        stderr_text = err_f.read().decode("utf-8", errors="replace")

    # Keep the persistent project on disk with all renames/retypes baked in.
    # On a successful run, durably invalidate the analysis cache so every read
    # tool observes the new project state:
    #   (1) bump the monotonic rev — ensure_analysis rebuilds on rev mismatch,
    #       so the invalidation survives any number of future renames AND any
    #       force_reanalyze that might otherwise rebuild from a stale source
    #       (the consume-once "_wairz_renamed" dirty flag this replaces could
    #       only fire ONCE, leaving later renames permanently invisible);
    #   (2) clear the cache eagerly on a fresh committed session so the next
    #       read — even from a different process — re-analyzes immediately and
    #       orphaned decompile:<old_name> entries are dropped.
    if proc.returncode == 0:
        try:
            new_rev = await loop.run_in_executor(
                None, bump_gzf_project_rev_sync, proj_base,
            )
            async with async_session_factory() as clear_db:
                await clear_binary_analysis(context.firmware_id, gzf_sha, clear_db)
                await clear_db.commit()
            logger.info(
                "GZF process-mode: persistent project retained at %s; rev bumped "
                "to %d and analysis cache cleared for %s",
                rep_dir, new_rev, gzf_sha[:12],
            )
        except Exception as exc:
            logger.warning(
                "GZF process-mode: failed to bump rev / clear cache: %s", exc,
            )
    else:
        logger.warning(
            "GZF process-mode: script exited %s — leaving analysis cache intact "
            "(no rev bump)", proc.returncode,
        )

    combined = (
        f"Script: {script_name}\n"
        f"GZF: {os.path.basename(gzf_path)}\n"
        f"Project: {proj_base}\n"
        f"Exit code: {proc.returncode}\n"
        f"\n=== STDOUT ===\n{stdout_text}"
        f"\n=== STDERR ===\n{stderr_text}"
    )
    log_filename = _persist_ghidra_log(project_id, f"gzf_{script_name}", combined)
    if log_filename:
        combined += (
            f"\n\nFull log persisted as '{log_filename}' — use read_ghidra_log "
            "to retrieve it if this output was truncated."
        )
    return truncate_output(combined, max_kb=GHIDRA_OUTPUT_MAX_KB)


# ---------------------------------------------------------------------------
# run_ghidra_headless handler
# ---------------------------------------------------------------------------

async def _handle_run_ghidra_headless(input: dict, context: ToolContext) -> str:
    flags = input.get("flags")
    binary_path_rel = input.get("binary_path")
    script_name = input.get("script_name", "").strip()
    script_file_id_str = input.get("script_file_id", "")
    script_args = input.get("script_args") or []
    timeout_override = input.get("timeout")
    use_saved_project = bool(input.get("use_saved_project", False))

    settings = get_settings()
    analyze_headless = os.path.join(settings.ghidra_path, "support", "analyzeHeadless")

    # --- INFO mode ---
    if flags is not None:
        try:
            proc = await asyncio.create_subprocess_exec(
                analyze_headless,
                *flags,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return (
                f"Error: Ghidra not found at {analyze_headless}. "
                "Set GHIDRA_PATH in .env."
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=30)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return "Error: Ghidra info query timed out after 30 s."

        output = (stdout_b + stderr_b).decode("utf-8", errors="replace").strip()
        return truncate_output(
            f"$ analyzeHeadless {' '.join(flags)}\n"
            f"exit code: {proc.returncode}\n\n"
            f"{output}"
        )

    # --- SCRIPT mode ---
    if not binary_path_rel and not script_name and not script_file_id_str:
        return (
            "Error: Provide either flags (info mode) or binary_path + script_name / "
            "script_file_id (script mode)."
        )

    if not binary_path_rel:
        return "Error: binary_path is required in script mode."

    # --- GZF process-mode: resolve GZF path before the normal firmware-tree lookup ---
    gzf_storage_path: str | None = None
    if use_saved_project:
        if os.path.splitext(binary_path_rel)[1].lower() != ".gzf":
            return "Error: use_saved_project=True requires binary_path to be a .gzf filename."
        svc_gzf = GhidraResearchService(context.db)
        try:
            gzf_storage_path = await svc_gzf.resolve_gzf_path(context.project_id, binary_path_rel)
        except FileNotFoundError as exc:
            return f"Error: {exc}"

    # GZF process mode never touches the firmware sandbox tree — binary_path_rel
    # is a research-archive filename, not a sandboxed firmware path, so the
    # normal resolve_path/isfile gate below must be skipped entirely (it would
    # otherwise return a "Binary not found" error before _run_gzf_process_mode
    # is ever reached, since gzf archives live outside extracted_path).
    resolved_binary = ""
    if gzf_storage_path is None:
        resolved_binary = context.resolve_path(binary_path_rel)
        # For RTOS blob-only projects resolve_path returns the parent directory for bare
        # basenames. Fall back to context.storage_path when the resolved path isn't a file.
        if not os.path.isfile(resolved_binary) and context.storage_path and os.path.isfile(context.storage_path):  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop
            resolved_binary = context.storage_path
        if not os.path.isfile(resolved_binary):  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop
            return f"Error: Binary not found at path '{binary_path_rel}'."

    # Build ghidra_import_params from explicit inputs; auto-detect from rtos_flavor if absent.
    _processor = input.get("processor", "").strip()
    _loader = input.get("loader", "").strip()
    _base_addr_str = input.get("base_addr", "").strip()
    _setup_script = input.get("setup_script", "").strip()
    _code_offset_str = input.get("code_offset", "").strip()

    if _processor or _loader or _base_addr_str or _setup_script:
        ghidra_import_params: dict | None = {}
        if _processor:
            ghidra_import_params["processor"] = _processor
        if _loader:
            ghidra_import_params["loader"] = _loader
        if _base_addr_str:
            try:
                ghidra_import_params["base_addr"] = int(_base_addr_str, 0)
            except ValueError:
                return f"Error: Invalid base_addr '{_base_addr_str}' — use hex (0x...) or decimal."
        if _setup_script:
            ghidra_import_params["setup_script"] = _setup_script
        if _code_offset_str:
            try:
                ghidra_import_params["code_offset"] = int(_code_offset_str, 0)
            except ValueError:
                return f"Error: Invalid code_offset '{_code_offset_str}' — use hex (0x...) or decimal."
    else:
        # Auto-detect from firmware rtos_flavor (e.g. baremetal-mips16e → MIPS:LE:32:default)
        ghidra_import_params = None
        if context.firmware_id:
            from sqlalchemy import select as _select  # noqa: PLC0415

            from app.models.firmware import Firmware as _FirmwareModel  # noqa: PLC0415
            _row = await context.db.execute(
                _select(_FirmwareModel.rtos_flavor).where(
                    _FirmwareModel.id == context.firmware_id
                )
            )
            _flavor = _row.scalar_one_or_none()
            if _flavor:
                import app.services.ghidra_service as _gs  # noqa: PLC0415
                ghidra_import_params = _gs._FLAVOR_GHIDRA_PARAMS.get(_flavor)  # noqa: SLF001

    # Resolve script: research file takes precedence over script_name
    _tmp_script_dir = None
    effective_script_name = script_name

    if script_file_id_str:
        try:
            script_file_id = uuid.UUID(script_file_id_str)
        except (ValueError, AttributeError):
            return f"Error: Invalid script_file_id: {script_file_id_str!r}"

        svc = GhidraResearchService(context.db)
        record = await svc.get(script_file_id)
        if not record or record.project_id != context.project_id:
            return f"Error: Script file {script_file_id_str} not found in this project."

        ext = os.path.splitext(record.original_filename)[1].lower()
        from app.schemas.ghidra_research import TEXT_EXTENSIONS  # noqa: PLC0415
        if ext not in TEXT_EXTENSIONS:
            return (
                f"Error: '{record.original_filename}' is not a text script. "
                "Only .py/.java/.jy scripts can be run."
            )

        content = GhidraResearchService.read_text_content(record)
        _tmp_script_dir = tempfile.mkdtemp(prefix="ghidra_script_")
        script_dest = os.path.join(_tmp_script_dir, record.original_filename)
        with open(script_dest, "w", encoding="utf-8") as fh:  # noqa: ASYNC230 -- single bounded stat/open call, not a hot loop
            fh.write(content)
        # mkdtemp() creates the dir 0o700 owned by the calling UID. In the
        # worker/root container the GZF process-mode step drops to the 'wairz'
        # user via _make_ghidra_preexec_fn (so persistent-project ownership
        # stays consistent), and that de-privileged Ghidra process then cannot
        # traverse the 0o700 root-owned temp dir — analyzeHeadless reports
        # "Script not found: <tmp>/<name>.java" even though the file exists.
        # Widen to world-traversable dir + world-readable script so the dropped
        # user can read it. These are the operator's own research scripts in a
        # short-lived per-run temp dir (rmtree'd in the finally), not secrets.
        os.chmod(_tmp_script_dir, 0o755)  # noqa: S103 -- world-traversable temp dir, short-lived, no secrets, see comment above  # nosec B103
        os.chmod(script_dest, 0o644)  # noqa: S103 -- world-readable script, required for de-privileged Ghidra user to traverse  # nosec B103
        effective_script_name = record.original_filename

    if not effective_script_name:
        return "Error: Provide script_name or script_file_id in script mode."

    timeout = timeout_override if isinstance(timeout_override, int) else None

    try:
        effective_timeout = timeout if timeout is not None else settings.ghidra_timeout

        # --- GZF process mode: delegate entirely, skip the import-mode path ---
        if gzf_storage_path is not None:
            return await _run_gzf_process_mode(
                gzf_storage_path,
                effective_script_name,
                script_args if script_args else [],
                _tmp_script_dir,
                effective_timeout,
                context.project_id,
                context,
            )

        import importlib  # noqa: PLC0415
        svc_mod = importlib.import_module("app.services.ghidra_service")
        _build_cmd = svc_mod._build_analyze_command  # noqa: SLF001

        with tempfile.TemporaryDirectory(prefix="ghidra_run_") as project_dir:
            import shlex  # noqa: PLC0415
            cmd = _build_cmd(
                resolved_binary,
                effective_script_name,
                project_dir,
                script_args if script_args else None,
                ghidra_import_params=ghidra_import_params,
                extra_script_path=_tmp_script_dir,
            )

            logger.info("run_ghidra_headless: %s", shlex.join(cmd))

            with (
                tempfile.TemporaryFile(prefix="ghidra-out-") as stdout_f,
                tempfile.TemporaryFile(prefix="ghidra-err-") as stderr_f,
            ):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=stdout_f,
                        stderr=stderr_f,
                    )
                except FileNotFoundError:
                    return (
                        f"Error: Ghidra not found at {cmd[0]}. "
                        "Set GHIDRA_PATH in .env."
                    )

                try:
                    await asyncio.wait_for(proc.wait(), timeout=effective_timeout)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return f"Error: Ghidra script timed out after {effective_timeout} s."

                stdout_f.seek(0)
                stderr_f.seek(0)
                stdout_text = stdout_f.read().decode("utf-8", errors="replace")
                stderr_text = stderr_f.read().decode("utf-8", errors="replace")

        combined = (
            f"Script: {effective_script_name}\n"
            f"Binary: {binary_path_rel}\n"
            f"Exit code: {proc.returncode}\n"
            f"\n=== STDOUT ===\n{stdout_text}"
            f"\n=== STDERR ===\n{stderr_text}"
        )
        log_filename = _persist_ghidra_log(
            context.project_id, f"run_{effective_script_name}", combined
        )
        if log_filename:
            combined += (
                f"\n\nFull log persisted as '{log_filename}' — use read_ghidra_log "
                "to retrieve it if this output was truncated."
            )
        return truncate_output(combined, max_kb=GHIDRA_OUTPUT_MAX_KB)

    finally:
        if _tmp_script_dir and os.path.isdir(_tmp_script_dir):  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop
            # shutil is imported module-level (line 5). A function-local
            # `import shutil` here would rebind it as a local for this whole
            # function body and raise UnboundLocalError on any earlier
            # reference (Rule #40).
            shutil.rmtree(_tmp_script_dir, ignore_errors=True)
