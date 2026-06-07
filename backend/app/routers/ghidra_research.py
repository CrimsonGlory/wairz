import asyncio
import os
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.schemas.ghidra_research import (
    ALLOWED_EXTENSIONS,
    TEXT_EXTENSIONS,
    GhidraResearchFileResponse,
    GhidraResearchFileUpdate,
    GhidraResearchScriptUpdate,
)
from app.services.ghidra_research_service import (
    GhidraResearchService,
    run_ghidra_import_background,
)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/ghidra-research",
    tags=["ghidra-research"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


def _validate_extension_endpoint(filename: str) -> None:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            f"File type '{ext}' not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )


@router.post("", response_model=GhidraResearchFileResponse, status_code=201)
async def upload_ghidra_research_file_endpoint(
    project_id: uuid.UUID,
    file: UploadFile,
    description: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    _validate_extension_endpoint(file.filename or "")
    svc = GhidraResearchService(db)
    try:
        record = await svc.upload(project_id, file, description)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return record


@router.get("", response_model=list[GhidraResearchFileResponse])
async def list_ghidra_research_files_endpoint(
    project_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    return await svc.list_by_project(project_id, limit=limit, offset=offset)


@router.get("/{file_id}", response_model=GhidraResearchFileResponse)
async def get_ghidra_research_file_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    return record


@router.get("/{file_id}/content")
async def read_ghidra_research_file_content_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    ext = os.path.splitext(record.original_filename)[1].lower()
    if ext not in TEXT_EXTENSIONS:
        raise HTTPException(400, f"Cannot read content of binary file '{record.original_filename}'")
    content = GhidraResearchService.read_text_content(record)
    return {
        "content": content,
        "content_type": record.content_type,
        "filename": record.original_filename,
        "size": record.file_size,
    }


@router.put("/{file_id}/content", response_model=GhidraResearchFileResponse)
async def update_ghidra_research_script_content_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    body: GhidraResearchScriptUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    try:
        updated = await svc.update_script_content(file_id, body.content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return updated


@router.get("/{file_id}/download")
async def download_ghidra_research_file_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    if not os.path.exists(record.storage_path):  # noqa: ASYNC240 — pre-flight stat before FileResponse; single check, no walk
        raise HTTPException(404, "File not found on disk")
    return FileResponse(
        path=record.storage_path,
        filename=record.original_filename,
        media_type=record.content_type,
    )


@router.patch("/{file_id}", response_model=GhidraResearchFileResponse)
async def update_ghidra_research_file_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    data: GhidraResearchFileUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    updated = await svc.update_description(file_id, data.description)
    return updated


@router.delete("/{file_id}", status_code=204)
async def delete_ghidra_research_file_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    await svc.delete(file_id)


@router.post("/{file_id}/import", response_model=GhidraResearchFileResponse, status_code=202)
async def trigger_ghidra_archive_import_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Trigger Ghidra headless to import a .gzf archive (202 + polling per Rule #33)."""
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")

    ext = os.path.splitext(record.original_filename)[1].lower()
    if ext != ".gzf":
        raise HTTPException(400, "Only .gzf Ghidra archive files can be imported")

    if record.import_status in ("queued", "running"):
        raise HTTPException(409, f"Import already {record.import_status}")

    record.import_status = "queued"
    record.import_result = None
    record.import_error = None
    await db.commit()

    asyncio.create_task(run_ghidra_import_background(file_id))
    return record


@router.get("/{file_id}/import-status", response_model=GhidraResearchFileResponse)
async def get_ghidra_archive_import_status_endpoint(
    project_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = GhidraResearchService(db)
    record = await svc.get(file_id)
    if not record or record.project_id != project_id:
        raise HTTPException(404, "Ghidra research file not found")
    return record
