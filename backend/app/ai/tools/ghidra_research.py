import asyncio
import os
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.ghidra_research import GhidraResearchFile
from app.services.ghidra_research_service import (
    GhidraResearchService,
    run_ghidra_import_background,
)


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
    import mimetypes
    fake_file.content_type = mimetypes.guess_type(filename)[0] or "text/plain"

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
