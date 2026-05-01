import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.project import Project
from app.schemas.pagination import Page
from app.schemas.project import (
    ProjectCreate,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdate,
)
from app.services.document_service import DocumentService
from app.utils.pagination import paginate_query

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])

SCRATCHPAD_MD_TEMPLATE = """\
# Agent Scratchpad

This document is used by AI agents to persist analysis notes, progress, and context across sessions.
Agents will read this at the start of each session and update it as they work.

---

*No notes yet.*
"""

WAIRZ_MD_TEMPLATE = """\
# WAIRZ.md — Project Instructions

Add custom instructions, notes, or context here for the AI assistant.
The AI will read this file automatically at the start of each conversation.

## Examples of what to put here

- Project-specific analysis focus areas
- Known components or versions to investigate
- Custom credentials or default passwords to check
- Architecture notes or device information
- Links to related documentation or datasheets
"""


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(name=data.name, description=data.description)
    db.add(project)
    await db.flush()

    # Create default WAIRZ.md note
    doc_svc = DocumentService(db)
    await doc_svc.create_note(
        project_id=project.id,
        title="WAIRZ",
        content=WAIRZ_MD_TEMPLATE,
    )

    # Create default SCRATCHPAD.md note
    await doc_svc.create_note(
        project_id=project.id,
        title="SCRATCHPAD",
        content=SCRATCHPAD_MD_TEMPLATE,
    )

    # Load firmware relationship (empty for new project)
    await db.refresh(project, ["firmware"])
    return project


@router.get("", response_model=Page[ProjectListResponse])
async def list_projects(
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db),
):
    # Eager-load firmware so we can surface the active firmware's kind
    # without extra round-trips per project.
    stmt = (
        select(Project)
        .options(selectinload(Project.firmware))
        .order_by(Project.created_at.desc())
    )
    items, total = await paginate_query(db, stmt, offset=offset, limit=limit)
    out = []
    for p in items:
        # Use the most recently uploaded firmware as the "active" one —
        # matches the MCP server's default-firmware selection.
        active_fw = max(p.firmware, key=lambda f: f.created_at) if p.firmware else None
        out.append(
            ProjectListResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                status=p.status,
                created_at=p.created_at,
                updated_at=p.updated_at,
                firmware_kind=active_fw.firmware_kind if active_fw else None,
                rtos_flavor=active_fw.rtos_flavor if active_fw else None,
            )
        )
    return Page[ProjectListResponse](items=out, total=total, offset=offset, limit=limit)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)
    await db.flush()
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
