import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.finding import FindingCreate, FindingResponse, FindingUpdate
from app.schemas.pagination import Page
from app.services.finding_service import FindingService
from app.services.report_service import generate_markdown_report, generate_pdf_report
from app.utils.firmware_selection import pick_active_firmware
from app.utils.pagination import paginate_query

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/findings",
    tags=["findings"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(
    project_id: uuid.UUID,
    data: FindingCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.create(project_id, data)
    return finding


@router.get("", response_model=Page[FindingResponse])
async def list_findings(
    project_id: uuid.UUID,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    source: str | None = Query(None),
    firmware_id: uuid.UUID | None = Query(None, description="Filter by firmware version"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a project (paged)."""
    await _get_project_or_404(project_id, db)
    stmt = select(Finding).where(Finding.project_id == project_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    if source:
        stmt = stmt.where(Finding.source == source)
    if firmware_id:
        stmt = stmt.where(Finding.firmware_id == firmware_id)
    stmt = stmt.order_by(Finding.created_at.desc())
    items, total = await paginate_query(db, stmt, offset=offset, limit=limit)
    return Page[FindingResponse](
        items=[FindingResponse.model_validate(f) for f in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    # Verify finding belongs to this project
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    finding = await svc.update(finding_id, data)
    return finding


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    await svc.delete(finding_id)


@router.post("/export")
async def export_findings(
    project_id: uuid.UUID,
    format: str = Query("markdown", pattern="^(markdown|pdf)$"),
    firmware_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    project = await _get_project_or_404(project_id, db)

    # Load firmware for the report header: the selected version, else the newest
    # loadable one (a project may have several versions).
    fw_result = await db.execute(
        select(Firmware).where(Firmware.project_id == project_id)
    )
    firmware_list = list(fw_result.scalars().all())
    if firmware_id is not None:
        firmware = next((f for f in firmware_list if f.id == firmware_id), None)
    else:
        firmware = pick_active_firmware(firmware_list)

    # Load findings
    svc = FindingService(db)
    findings = await svc.list_by_project(project_id)

    safe_name = re.sub(r'[^\w.-]', '_', project.name)

    if format == "pdf":
        pdf_bytes = generate_pdf_report(project, firmware, findings)
        filename = f"{safe_name}_security_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    md = generate_markdown_report(project, firmware, findings)
    filename = f"{safe_name}_security_report.md"
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
