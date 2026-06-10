import asyncio
import logging
import os
import tempfile
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.models.ghidra_research import GhidraResearchFile
from app.services.ghidra_research_service import (
    GhidraResearchService,
    run_ghidra_import_background,
)
from app.services.ghidra_service import run_ghidra_subprocess
from app.utils.truncation import truncate_output

logger = logging.getLogger(__name__)


def register_ghidra_research_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="list_ghidra_research_files",
        description=(
            "List all Ghidra research files uploaded to the current project. "
            "These include .gzf Ghidra archive exports (with pre-existing analysis, "
            "renamed functions, custom types, and researcher comments) and .py/.java "
            "analysis scripts. Use this to discover what prior research is available "
            "before using import_ghidra_archive or read_ghidra_script."
        ),
        input_schema={"type": "object", "properties": {}},
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


async def _handle_list_ghidra_research_files(input: dict, context: ToolContext) -> str:
    svc = GhidraResearchService(context.db)
    files = await svc.list_by_project(context.project_id)
    if not files:
        return (
            "No Ghidra research files have been uploaded to this project. "
            "Upload .gzf archives or .py/.java scripts via the Ghidra Research tab in the UI."
        )

    archives = [f for f in files if f.file_category == "ghidra_archive"]
    scripts = [f for f in files if f.file_category != "ghidra_archive"]

    lines = [f"Found {len(files)} Ghidra research file(s):\n"]

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

    # Check if the input matches a GhidraResearchFile (by original_filename or storage_path)
    svc = GhidraResearchService(context.db)
    research_files = await svc.list_by_project(context.project_id)

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

    # Derive stable project dir for this GZF (mirrors _run_gzf_process_mode).
    ghidra_project_dir: str | None = None
    if gzf_path and os.path.isfile(gzf_path):  # noqa: ASYNC240 — pre-flight stat, no walk
        from app.utils.hashing import compute_file_sha256  # noqa: PLC0415
        loop = asyncio.get_running_loop()
        gzf_sha = await loop.run_in_executor(None, compute_file_sha256, gzf_path)
        candidate = os.path.join(settings.ghidra_projects_dir, gzf_sha[:16])
        rep_candidate = os.path.join(candidate, "gzf_project.rep")
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
    timeout: int,
) -> str:
    """Restore a GZF into a persistent Ghidra project (first run only) then run
    script_name in -process mode against all programs in that project.

    The project directory is keyed by the first 16 hex chars of the GZF
    content SHA256, so the same archive always maps to the same directory.
    An OS-level flock on that key ensures only one process runs the -import
    step even when multiple wairz-mcp connections hit the same GZF
    simultaneously.

    Returns the combined output string (same shape as import-mode).
    """
    settings = get_settings()
    analyze_headless = os.path.join(settings.ghidra_path, "support", "analyzeHeadless")

    from app.utils.hashing import compute_file_sha256  # noqa: PLC0415
    from app.services.ghidra_service import (  # noqa: PLC0415
        _cross_process_analysis_lock,
        _format_ghidra_diag,
    )

    loop = asyncio.get_running_loop()
    gzf_sha = await loop.run_in_executor(None, compute_file_sha256, gzf_path)

    proj_base = os.path.join(settings.ghidra_projects_dir, gzf_sha[:16])
    proj_name = "gzf_project"
    rep_dir = os.path.join(proj_base, f"{proj_name}.rep")

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
                    )
                except FileNotFoundError:
                    return f"Error: Ghidra not found at {analyze_headless}. Set GHIDRA_PATH in .env."

                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout)
                except asyncio.TimeoutError:
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
        "-scriptPath", scripts_path,
    ]
    if extra_script_path:
        process_cmd.extend(["-scriptPath", extra_script_path])
    process_cmd.extend(["-postScript", script_name])
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
            )
        except FileNotFoundError:
            return f"Error: Ghidra not found at {analyze_headless}. Set GHIDRA_PATH in .env."

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Error: GZF process-mode script timed out after {timeout} s."

        out_f.seek(0)
        err_f.seek(0)
        stdout_text = out_f.read().decode("utf-8", errors="replace")
        stderr_text = err_f.read().decode("utf-8", errors="replace")

    return truncate_output(
        f"Script: {script_name}\n"
        f"GZF: {os.path.basename(gzf_path)}\n"
        f"Project: {proj_base}\n"
        f"Exit code: {proc.returncode}\n"
        f"\n=== STDOUT ===\n{stdout_text}"
        f"\n=== STDERR ===\n{stderr_text}"
    )


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
        except asyncio.TimeoutError:
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
        basename_gzf = os.path.basename(binary_path_rel)
        svc_gzf = GhidraResearchService(context.db)
        research_files_gzf = await svc_gzf.list_by_project(context.project_id)
        for _rf in research_files_gzf:
            if (
                _rf.original_filename == basename_gzf
                or _rf.original_filename == binary_path_rel
                or _rf.storage_path == binary_path_rel
                or os.path.basename(_rf.storage_path) == basename_gzf
            ):
                if os.path.splitext(_rf.original_filename)[1].lower() == ".gzf":
                    gzf_storage_path = _rf.storage_path
                    break
        if gzf_storage_path is None:
            return (
                f"Error: GZF '{binary_path_rel}' not found in this project's research files. "
                "Use list_ghidra_research_files to see available archives."
            )
        if not os.path.exists(gzf_storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
            return f"Error: GZF file not on disk: {gzf_storage_path}"

    resolved_binary = context.resolve_path(binary_path_rel)
    # For RTOS blob-only projects resolve_path returns the parent directory for bare
    # basenames. Fall back to context.storage_path when the resolved path isn't a file.
    if not os.path.isfile(resolved_binary) and context.storage_path and os.path.isfile(context.storage_path):
        resolved_binary = context.storage_path
    if not os.path.isfile(resolved_binary):
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
            from app.models.firmware import Firmware as _FirmwareModel  # noqa: PLC0415
            from sqlalchemy import select as _select                      # noqa: PLC0415
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
        with open(script_dest, "w", encoding="utf-8") as fh:
            fh.write(content)
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
            )
            if _tmp_script_dir:
                # Inject extra -scriptPath so analyzeHeadless finds the temp script
                cmd.extend(["-scriptPath", _tmp_script_dir])

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
                except asyncio.TimeoutError:
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
        return truncate_output(combined)

    finally:
        if _tmp_script_dir and os.path.isdir(_tmp_script_dir):
            import shutil  # noqa: PLC0415
            shutil.rmtree(_tmp_script_dir, ignore_errors=True)
