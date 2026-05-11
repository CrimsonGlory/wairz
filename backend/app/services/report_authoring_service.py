"""Authoring service for structured reports.

Owns the create/get/upsert-section/toggle-finding lifecycle. The render
path lives next to it in :mod:`report_render_service` so that the
authoring concerns stay separable from the WeasyPrint pipeline.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.finding import Finding
from app.models.project import Project
from app.models.report import (
    Report,
    ReportFinding,
    ReportRender,
    ReportSection,
)
from app.services.report_template_service import (
    ReportTemplate,
    TemplateNotFoundError,
    default_template_id,
    get_template,
)


class ReportAuthoringError(ValueError):
    """Raised for caller-visible authoring errors (404/409/422-class)."""


class TemplateMismatchError(ReportAuthoringError):
    """Raised when an upsert targets a slug not in the template."""


class ReportAuthoringService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def create(
        self,
        project_id: uuid.UUID,
        template_id: str | None = None,
        title: str | None = None,
    ) -> Report:
        tid = template_id or default_template_id()
        try:
            template = get_template(tid)
        except TemplateNotFoundError as exc:
            raise ReportAuthoringError(f"unknown template: {tid}") from exc

        resolved_title = (title or "").strip() or await self._default_title(
            project_id, template
        )
        report = Report(
            project_id=project_id,
            template_id=tid,
            status="draft",
            title=resolved_title,
        )
        self.db.add(report)
        await self.db.flush()

        # Pre-populate one row per template section.
        for section in template.sections:
            self.db.add(
                ReportSection(
                    report_id=report.id,
                    slug=section.slug,
                    title=section.title,
                    content_md="",
                    order_index=section.order,
                    updated_by="system",
                )
            )

        # Attach all current project findings, included by default.
        finding_ids = await self.db.execute(
            select(Finding.id).where(Finding.project_id == project_id)
        )
        for (fid,) in finding_ids.all():
            self.db.add(
                ReportFinding(report_id=report.id, finding_id=fid, included=True)
            )

        await self.db.flush()
        return await self._reload(report.id)

    async def get(self, report_id: uuid.UUID) -> Report | None:
        result = await self.db.execute(
            select(Report)
            .where(Report.id == report_id)
            .options(
                selectinload(Report.sections),
                selectinload(Report.findings),
                selectinload(Report.renders),
            )
        )
        return result.scalar_one_or_none()

    async def list_by_project(self, project_id: uuid.UUID) -> list[Report]:
        result = await self.db.execute(
            select(Report)
            .where(Report.project_id == project_id)
            .options(selectinload(Report.sections))
            .order_by(Report.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_or_create_active_draft(
        self,
        project_id: uuid.UUID,
        template_id: str | None = None,
    ) -> Report:
        """Return the most recent draft report, or create one if none exists.

        Used by the MCP entrypoint so the agent doesn't have to juggle
        report ids across calls.
        """
        result = await self.db.execute(
            select(Report)
            .where(
                Report.project_id == project_id,
                Report.status == "draft",
            )
            .order_by(Report.created_at.desc())
            .limit(1)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return await self._reload(existing.id)
        return await self.create(project_id, template_id=template_id)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    async def upsert_section(
        self,
        report_id: uuid.UUID,
        slug: str,
        content_md: str,
        updated_by: str,
    ) -> ReportSection:
        report = await self._require_report(report_id)
        template = get_template(report.template_id)
        template_section = template.section_for_slug(slug)
        if template_section is None:
            raise TemplateMismatchError(
                f"slug {slug!r} not in template {report.template_id!r}"
            )

        result = await self.db.execute(
            select(ReportSection).where(
                ReportSection.report_id == report_id,
                ReportSection.slug == slug,
            )
        )
        section = result.scalar_one_or_none()
        if section is None:
            section = ReportSection(
                report_id=report_id,
                slug=slug,
                title=template_section.title,
                content_md=content_md,
                order_index=template_section.order,
                updated_by=updated_by,
            )
            self.db.add(section)
        else:
            section.content_md = content_md
            section.title = template_section.title
            section.order_index = template_section.order
            section.updated_by = updated_by

        await self.db.flush()
        # Pull updated_at back from the DB (server-side onupdate=func.now()).
        await self.db.refresh(section)
        return section

    # ------------------------------------------------------------------
    # Finding inclusion
    # ------------------------------------------------------------------

    async def set_finding_included(
        self,
        report_id: uuid.UUID,
        finding_id: uuid.UUID,
        included: bool,
    ) -> ReportFinding:
        report = await self._require_report(report_id)
        result = await self.db.execute(
            select(ReportFinding).where(
                ReportFinding.report_id == report_id,
                ReportFinding.finding_id == finding_id,
            )
        )
        link = result.scalar_one_or_none()
        if link is None:
            # Validate the finding belongs to the same project before linking.
            f_result = await self.db.execute(
                select(Finding).where(
                    Finding.id == finding_id,
                    Finding.project_id == report.project_id,
                )
            )
            if f_result.scalar_one_or_none() is None:
                raise ReportAuthoringError(
                    "finding not found in this project"
                )
            link = ReportFinding(
                report_id=report_id,
                finding_id=finding_id,
                included=included,
            )
            self.db.add(link)
        else:
            link.included = included

        await self.db.flush()
        return link

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def included_findings(self, report_id: uuid.UUID) -> list[Finding]:
        """Return Finding rows for the report, in severity order, included only."""
        result = await self.db.execute(
            select(Finding, ReportFinding.included)
            .join(
                ReportFinding,
                ReportFinding.finding_id == Finding.id,
            )
            .where(
                ReportFinding.report_id == report_id,
                ReportFinding.included.is_(True),
            )
        )
        return [row[0] for row in result.all()]

    async def template_for(self, report: Report) -> ReportTemplate:
        return get_template(report.template_id)

    async def rename(self, report_id: uuid.UUID, title: str) -> Report:
        new_title = (title or "").strip()
        if not new_title:
            raise ReportAuthoringError("title cannot be empty")
        if len(new_title) > 255:
            raise ReportAuthoringError("title must be 255 characters or fewer")
        report = await self._require_report(report_id)
        report.title = new_title
        await self.db.flush()
        return report

    async def _default_title(
        self, project_id: uuid.UUID, template: ReportTemplate
    ) -> str:
        """Build the auto-title from the project name when available."""
        result = await self.db.execute(
            select(Project.name).where(Project.id == project_id)
        )
        project_name = result.scalar_one_or_none()
        if project_name:
            return f"{project_name} Pentest Report"
        return template.name

    async def _require_report(self, report_id: uuid.UUID) -> Report:
        report = await self.get(report_id)
        if report is None:
            raise ReportAuthoringError(f"report {report_id} not found")
        return report

    async def _reload(self, report_id: uuid.UUID) -> Report:
        report = await self.get(report_id)
        assert report is not None  # we just created/loaded it
        return report
