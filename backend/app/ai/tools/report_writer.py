"""MCP tools for the structured-report flow.

Three thin wrappers around the REST authoring service so the agent can
draft, write, and render a report without leaving the MCP transport.
The REST API remains the source of truth — these tools share the same
service layer.
"""

from __future__ import annotations

import json

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.report_authoring_service import (
    ReportAuthoringError,
    ReportAuthoringService,
    TemplateMismatchError,
)
from app.services.report_render_service import (
    artifact_path,
    compute_content_hash,
    render_pdf_bytes,
    write_artifact,
)
from app.services.report_template_service import (
    TemplateNotFoundError,
    get_template,
    list_templates,
)
from sqlalchemy import select


def register_report_writer_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="report_start",
        description=(
            "Start (or reopen) a structured report draft for the current project. "
            "Returns the active draft along with the template schema (section "
            "slugs, titles, guidance, and word limits) so you know what to write. "
            "Call this once at the beginning of a report-authoring session — if a "
            "draft already exists, it will be returned unchanged. "
            "Use the optional template_id argument to pick a non-default template."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "template_id": {
                    "type": "string",
                    "description": (
                        "Optional template id, e.g. 'standard_iot_pentest_v1'. "
                        "If omitted, the default template is used."
                    ),
                },
            },
        },
        handler=_handle_report_start,
    )

    registry.register(
        name="report_write_section",
        description=(
            "Write or rewrite a single section of the active draft report by slug. "
            "The slug must come from the template returned by report_start. "
            "Content is markdown — use headings, lists, and tables. Do NOT write "
            "finding cards yourself; they are rendered automatically from the "
            "structured findings list."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "slug": {
                    "type": "string",
                    "description": (
                        "Section slug from the template (e.g. 'executive_summary')."
                    ),
                },
                "content_md": {
                    "type": "string",
                    "description": "Markdown content for this section.",
                },
            },
            "required": ["slug", "content_md"],
        },
        handler=_handle_report_write_section,
    )

    registry.register(
        name="report_render",
        description=(
            "Render the active draft report to PDF. Returns the download path "
            "and the content hash that identifies the cached PDF. The user "
            "can re-render at any time after editing sections."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_report_render,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _handle_report_start(input: dict, context: ToolContext) -> str:
    template_id = input.get("template_id") or None

    try:
        if template_id is not None:
            get_template(template_id)  # validate up-front for a clean error
    except TemplateNotFoundError:
        available = ", ".join(t.id for t in list_templates()) or "(none)"
        return f"Error: unknown template_id {template_id!r}. Available: {available}"

    svc = ReportAuthoringService(context.db)
    try:
        report = await svc.get_or_create_active_draft(
            context.project_id, template_id=template_id
        )
    except ReportAuthoringError as exc:
        return f"Error: {exc}"
    await context.db.commit()

    template = get_template(report.template_id)
    sections_payload = []
    for ts in template.sections:
        existing = next(
            (s for s in report.sections if s.slug == ts.slug),
            None,
        )
        sections_payload.append({
            "slug": ts.slug,
            "title": ts.title,
            "required": ts.required,
            "order": ts.order,
            "max_words": ts.max_words,
            "guidance": ts.guidance,
            "filled": bool(existing and existing.content_md.strip()),
            "current_word_count": (
                len((existing.content_md or "").split()) if existing else 0
            ),
        })

    payload = {
        "report_id": str(report.id),
        "status": report.status,
        "template_id": template.id,
        "template_name": template.name,
        "title": report.title,
        "findings_attached": len(report.findings),
        "sections": sections_payload,
        "instructions": (
            "Write each section by calling report_write_section(slug, content_md). "
            "Findings are rendered automatically; describe them in risk_summary "
            "and conclusion but do NOT write finding cards yourself. "
            "Call report_render to produce the PDF — the user can re-render "
            "after edits at any time."
        ),
    }
    return json.dumps(payload, indent=2)


async def _handle_report_write_section(input: dict, context: ToolContext) -> str:
    slug = (input.get("slug") or "").strip()
    content_md = input.get("content_md") or ""
    if not slug:
        return "Error: slug is required."

    svc = ReportAuthoringService(context.db)
    try:
        report = await svc.get_or_create_active_draft(context.project_id)
    except ReportAuthoringError as exc:
        return f"Error: {exc}"

    try:
        section = await svc.upsert_section(
            report_id=report.id,
            slug=slug,
            content_md=content_md,
            updated_by="agent",
        )
    except TemplateMismatchError as exc:
        return f"Error: {exc}"
    except ReportAuthoringError as exc:
        return f"Error: {exc}"
    await context.db.commit()

    word_count = len(content_md.split())
    return (
        f"Section {section.slug!r} updated ({word_count} words, "
        f"{len(content_md)} chars). report_id={report.id}"
    )


async def _handle_report_render(
    input: dict, context: ToolContext
) -> str:
    svc = ReportAuthoringService(context.db)
    try:
        report = await svc.get_or_create_active_draft(context.project_id)
    except ReportAuthoringError as exc:
        return f"Error: {exc}"

    # Reload with sections + findings populated for the renderer.
    report = await svc.get(report.id)
    template = get_template(report.template_id)
    sections = sorted(report.sections, key=lambda s: s.order_index)
    findings = await svc.included_findings(report.id)

    project = (
        await context.db.execute(
            select(Project).where(Project.id == context.project_id)
        )
    ).scalar_one()
    firmware = (
        await context.db.execute(
            select(Firmware).where(Firmware.project_id == context.project_id)
        )
    ).scalar_one_or_none()

    fmt = "pdf"
    content_hash = compute_content_hash(
        report=report,
        sections=sections,
        findings=findings,
        template=template,
        fmt=fmt,
    )

    from app.models.report import ReportRender
    cache_result = await context.db.execute(
        select(ReportRender).where(
            ReportRender.report_id == report.id,
            ReportRender.content_hash == content_hash,
            ReportRender.format == fmt,
        )
    )
    cached = cache_result.scalar_one_or_none()

    import os
    if cached is not None and os.path.exists(cached.storage_path):
        path = cached.storage_path
        size = cached.byte_size
        was_cached = True
    else:
        pdf_bytes = render_pdf_bytes(
            report=report,
            sections=sections,
            findings=findings,
            project=project,
            firmware=firmware,
            template=template,
        )
        path_obj = artifact_path(context.project_id, report.id, content_hash, fmt)
        write_artifact(path_obj, pdf_bytes)
        path = str(path_obj)
        size = len(pdf_bytes)
        if cached is not None:
            cached.storage_path = path
            cached.byte_size = size
        else:
            context.db.add(
                ReportRender(
                    report_id=report.id,
                    content_hash=content_hash,
                    format=fmt,
                    storage_path=path,
                    byte_size=size,
                )
            )
        await context.db.commit()
        was_cached = False

    download_url = (
        f"/api/v1/projects/{context.project_id}/reports/{report.id}"
        f"/renders/{content_hash}?format={fmt}"
    )
    return json.dumps({
        "report_id": str(report.id),
        "format": fmt,
        "content_hash": content_hash,
        "byte_size": size,
        "cached": was_cached,
        "storage_path": path,
        "download_url": download_url,
        "ui_path": f"/projects/{context.project_id}/report/{report.id}",
    }, indent=2)
