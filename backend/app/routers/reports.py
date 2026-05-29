"""Report authoring + rendering REST API.

Routes are project-scoped to mirror the rest of the codebase. Auth is
inherited from the same origin/host guard that gates every other endpoint.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.report import ReportRender
from app.schemas.finding import FindingResponse
from app.schemas.report import (
    FindingInclusionUpdate,
    RenderRequest,
    RenderResult,
    ReportCreate,
    ReportFindingResponse,
    ReportRename,
    ReportRenderResponse,
    ReportResponse,
    ReportSectionResponse,
    ReportSummary,
    ReportTemplateResponse,
    SectionUpsert,
    TemplateSectionResponse,
)
from app.services.finding_service import FindingService
from app.services.report_authoring_service import (
    ReportAuthoringError,
    ReportAuthoringService,
    TemplateMismatchError,
)
from app.services.report_render_service import (
    artifact_path,
    compute_content_hash,
    render_pdf_bytes,
    report_storage_dir,
    write_artifact,
)
from app.services.report_template_service import (
    TemplateNotFoundError,
    get_template,
    list_templates,
)
from app.utils.sandbox import PathTraversalError, validate_path

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/reports",
    tags=["reports"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if project is None:
        raise HTTPException(404, "Project not found")
    return project


async def _load_firmware(project_id: uuid.UUID, db: AsyncSession) -> Firmware | None:
    # Projects can have multiple firmware versions; pick the earliest-created
    # one to mirror the MCP _select_firmware default and stay deterministic
    # across renders.
    result = await db.execute(
        select(Firmware)
        .where(Firmware.project_id == project_id)
        .order_by(Firmware.created_at)
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _to_report_response(
    report,
    db: AsyncSession,
) -> ReportResponse:
    """Hydrate a Report ORM object into the public schema."""
    finding_svc = FindingService(db)
    sections = sorted(report.sections, key=lambda s: s.order_index)

    inclusion_by_finding: dict[uuid.UUID, bool] = {
        link.finding_id: link.included for link in report.findings
    }
    finding_ids = list(inclusion_by_finding.keys())
    findings: list[ReportFindingResponse] = []
    for fid in finding_ids:
        finding = await finding_svc.get(fid)
        if finding is None:
            continue  # finding deleted out from under us; skip
        findings.append(
            ReportFindingResponse(
                finding=FindingResponse.model_validate(finding),
                included=inclusion_by_finding[fid],
            )
        )
    findings.sort(
        key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            x.finding.severity, 99
        ), x.finding.title)
    )

    renders = sorted(report.renders, key=lambda r: r.created_at, reverse=True)

    return ReportResponse(
        id=report.id,
        project_id=report.project_id,
        template_id=report.template_id,
        status=report.status,
        title=report.title,
        created_at=report.created_at,
        finalized_at=report.finalized_at,
        sections=[ReportSectionResponse.model_validate(s) for s in sections],
        findings=findings,
        renders=[ReportRenderResponse.model_validate(r) for r in renders],
    )


def _template_to_response(template) -> ReportTemplateResponse:
    return ReportTemplateResponse(
        id=template.id,
        name=template.name,
        version=template.version,
        language=template.language,
        findings_order=template.findings_order,
        sections=[TemplateSectionResponse(**s.model_dump()) for s in template.sections],
    )


def _resolve_updated_by(request: Request) -> str:
    """Identify the editor. The MCP path sets X-Wairz-Agent: 1; everything
    else is treated as a human user."""
    if request.headers.get("x-wairz-agent") == "1":
        return "agent"
    return "user"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

@router.get("/templates", response_model=list[ReportTemplateResponse])
async def list_report_templates(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    return [_template_to_response(t) for t in list_templates()]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(
    project_id: uuid.UUID,
    payload: ReportCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    try:
        report = await svc.create(
            project_id=project_id,
            template_id=payload.template_id,
            title=payload.title,
        )
    except ReportAuthoringError as exc:
        raise HTTPException(400, str(exc))
    return await _to_report_response(report, db)


@router.get("", response_model=list[ReportSummary])
async def list_reports(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    reports = await svc.list_by_project(project_id)
    out: list[ReportSummary] = []
    for r in reports:
        section_updated = [s.updated_at for s in r.sections if s.updated_at]
        last_modified = max([r.created_at, *section_updated, r.finalized_at or r.created_at])
        filled = sum(1 for s in r.sections if (s.content_md or "").strip())
        out.append(ReportSummary(
            id=r.id,
            project_id=r.project_id,
            template_id=r.template_id,
            status=r.status,
            title=r.title,
            created_at=r.created_at,
            finalized_at=r.finalized_at,
            last_modified_at=last_modified,
            filled_section_count=filled,
            total_section_count=len(r.sections),
        ))
    return out


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")
    return await _to_report_response(report, db)


@router.get("/{report_id}/template", response_model=ReportTemplateResponse)
async def get_report_template(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")
    try:
        template = get_template(report.template_id)
    except TemplateNotFoundError:
        raise HTTPException(500, f"template {report.template_id} not found on disk")
    return _template_to_response(template)


@router.put(
    "/{report_id}/sections/{slug}",
    response_model=ReportSectionResponse,
)
async def upsert_section(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    slug: str,
    payload: SectionUpsert,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")

    try:
        section = await svc.upsert_section(
            report_id=report_id,
            slug=slug,
            content_md=payload.content_md,
            updated_by=_resolve_updated_by(request),
        )
    except TemplateMismatchError as exc:
        raise HTTPException(404, str(exc))
    except ReportAuthoringError as exc:
        raise HTTPException(409, str(exc))

    return ReportSectionResponse.model_validate(section)


@router.put(
    "/{report_id}/findings/{finding_id}",
    response_model=ReportFindingResponse,
)
async def set_finding_inclusion(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingInclusionUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")

    try:
        link = await svc.set_finding_included(
            report_id=report_id,
            finding_id=finding_id,
            included=payload.included,
        )
    except ReportAuthoringError as exc:
        raise HTTPException(404, str(exc))

    finding_svc = FindingService(db)
    finding = await finding_svc.get(finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return ReportFindingResponse(
        finding=FindingResponse.model_validate(finding),
        included=link.included,
    )


@router.patch("/{report_id}", response_model=ReportResponse)
async def rename_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    payload: ReportRename,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")
    try:
        report = await svc.rename(report_id, payload.title)
    except ReportAuthoringError as exc:
        raise HTTPException(400, str(exc))
    return await _to_report_response(report, db)


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")
    # Best-effort artifact cleanup. We don't fail the API call if the
    # filesystem is in an unexpected state — the DB cascade is what matters.
    storage_dir = report_storage_dir(project_id, report_id)
    if storage_dir.is_dir():
        for child in storage_dir.iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        try:
            storage_dir.rmdir()
        except OSError:
            pass
    await db.delete(report)


# ---------------------------------------------------------------------------
# Render + download
# ---------------------------------------------------------------------------

@router.post("/{report_id}/render", response_model=RenderResult)
async def render_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    payload: RenderRequest,
    db: AsyncSession = Depends(get_db),
):
    project = await _get_project_or_404(project_id, db)
    svc = ReportAuthoringService(db)
    report = await svc.get(report_id)
    if report is None or report.project_id != project_id:
        raise HTTPException(404, "Report not found")

    if payload.format != "pdf":
        # HTML format reserved for future use; only PDF is implemented.
        raise HTTPException(400, "only pdf format is implemented")

    template = get_template(report.template_id)
    sections = sorted(report.sections, key=lambda s: s.order_index)

    # Use the authoring helper so we honor the included flag.
    findings = await svc.included_findings(report_id)

    content_hash = compute_content_hash(
        report=report,
        sections=sections,
        findings=findings,
        template=template,
        fmt=payload.format,
    )

    # Cache hit: return the existing artifact if we have it.
    cache_result = await db.execute(
        select(ReportRender).where(
            ReportRender.report_id == report_id,
            ReportRender.content_hash == content_hash,
            ReportRender.format == payload.format,
        )
    )
    cached = cache_result.scalar_one_or_none()
    if cached is not None and os.path.exists(cached.storage_path):
        return RenderResult(
            content_hash=content_hash,
            format=payload.format,
            byte_size=cached.byte_size,
            download_url=(
                f"/api/v1/projects/{project_id}/reports/{report_id}/renders/{content_hash}"
                f"?format={payload.format}"
            ),
            cached=True,
        )

    firmware = await _load_firmware(project_id, db)
    pdf_bytes = render_pdf_bytes(
        report=report,
        sections=sections,
        findings=findings,
        project=project,
        firmware=firmware,
        template=template,
    )

    path = artifact_path(project_id, report_id, content_hash, payload.format)
    write_artifact(path, pdf_bytes)

    if cached is not None:
        # Stale row from a deleted file — refresh in place.
        cached.storage_path = str(path)
        cached.byte_size = len(pdf_bytes)
        cached.created_at = datetime.now(timezone.utc)
    else:
        db.add(
            ReportRender(
                report_id=report_id,
                content_hash=content_hash,
                format=payload.format,
                storage_path=str(path),
                byte_size=len(pdf_bytes),
            )
        )
    await db.flush()

    return RenderResult(
        content_hash=content_hash,
        format=payload.format,
        byte_size=len(pdf_bytes),
        download_url=(
            f"/api/v1/projects/{project_id}/reports/{report_id}/renders/{content_hash}"
            f"?format={payload.format}"
        ),
        cached=False,
    )


@router.get("/{report_id}/renders/{content_hash}")
async def download_render(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    content_hash: str,
    format: str = "pdf",
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    if format not in {"pdf", "html"}:
        raise HTTPException(400, "unknown format")
    if not all(c in "0123456789abcdef" for c in content_hash) or len(content_hash) != 64:
        # Cheap sanity check before we touch the filesystem.
        raise HTTPException(400, "invalid content_hash")

    result = await db.execute(
        select(ReportRender).where(
            ReportRender.report_id == report_id,
            ReportRender.content_hash == content_hash,
            ReportRender.format == format,
        )
    )
    render = result.scalar_one_or_none()
    if render is None:
        raise HTTPException(404, "render not found")

    # Validate the artifact path stays inside the project's report dir.
    expected_dir = report_storage_dir(project_id, report_id)
    try:
        validate_path(str(expected_dir), os.path.basename(render.storage_path))
    except PathTraversalError:
        raise HTTPException(403, "render path escapes report dir")

    if not os.path.exists(render.storage_path):
        raise HTTPException(404, "artifact missing on disk")

    media_type = "application/pdf" if format == "pdf" else "text/html"
    return FileResponse(
        render.storage_path,
        media_type=media_type,
        filename=f"report-{content_hash[:12]}.{format}",
    )
