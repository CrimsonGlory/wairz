"""Renders structured reports to HTML/PDF.

Pipeline: section markdown → HTML (markdown lib) → bleach.clean() →
Jinja base template → WeasyPrint PDF.

Findings are *never* rendered from agent-authored markdown; they are
emitted from the structured Finding rows through the dedicated
``_findings.html`` / ``_finding_card.html`` partials.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bleach
import markdown as md_lib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import get_settings
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.report import Report, ReportSection
from app.services.report_template_service import ReportTemplate, get_template

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ALLOWED_TAGS = {
    "p", "br", "strong", "em", "code", "pre", "blockquote",
    "ul", "ol", "li", "a", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td", "hr", "span", "div",
}
ALLOWED_ATTRS = {
    "a": ["href", "title"],
    "code": ["class"],
    "span": ["class"],
    "div": ["class"],
    "th": ["align"],
    "td": ["align"],
}

RENDER_DIR = Path(__file__).resolve().parent.parent.parent / "report_templates" / "render"
TEMPLATE_VERSION = "1.3"  # bumped when partials/css change in a way that affects output


def _markdown_to_safe_html(text: str) -> str:
    if not text:
        return ""
    raw = md_lib.markdown(
        text,
        extensions=["extra", "sane_lists", "tables", "fenced_code"],
        output_format="html5",
    )
    return bleach.clean(
        raw,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True,
        strip_comments=True,
    )


def _make_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(RENDER_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["markdown_safe"] = _markdown_to_safe_html
    return env


def _build_slots(
    template: ReportTemplate,
    sections: list[ReportSection],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """Interleave template sections and the auto-injected findings slot,
    in template order.
    """
    sections_by_slug = {s.slug: s for s in sections}
    template_sections = sorted(template.sections, key=lambda s: s.order)

    section_slots: list[dict[str, Any]] = []
    for ts in template_sections:
        section = sections_by_slug.get(ts.slug)
        content_md = section.content_md if section else ""
        section_slots.append({
            "kind": "section",
            "order": ts.order,
            "slug": ts.slug,
            "title": ts.title,
            "content_md": content_md,
            "content_html": _markdown_to_safe_html(content_md),
        })

    findings_slot = {
        "kind": "findings",
        "order": template.findings_order,
        "title": "Findings",
        "findings": findings,
        "groups": _group_findings_by_severity(findings),
    }

    return sorted(section_slots + [findings_slot], key=lambda s: s["order"])


def _group_findings_by_severity(findings: list[Finding]) -> list[dict[str, Any]]:
    by_sev: dict[str, list[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    groups: list[dict[str, Any]] = []
    for sev in sorted(by_sev.keys(), key=lambda s: SEVERITY_ORDER.get(s, 99)):
        items = sorted(by_sev[sev], key=lambda f: f.title or "")
        groups.append({"severity": sev, "findings": items})
    return groups


def _read_css() -> str:
    return (RENDER_DIR / "report.css").read_text(encoding="utf-8")


def render_html(
    *,
    report: Report,
    sections: list[ReportSection],
    findings: list[Finding],
    project: Project,
    firmware: Firmware | None,
    template: ReportTemplate | None = None,
    generated_at: datetime | None = None,
) -> str:
    template = template or get_template(report.template_id)
    env = _make_env()
    base = env.get_template("base.html")
    slots = _build_slots(template, sections, findings)
    return base.render(
        report=report,
        project=project,
        firmware=firmware,
        template=template,
        language=template.language or "en",
        slots=slots,
        css=_read_css(),
        generated_at=(generated_at or datetime.now(timezone.utc)).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),
    )


def render_pdf_bytes(
    *,
    report: Report,
    sections: list[ReportSection],
    findings: list[Finding],
    project: Project,
    firmware: Firmware | None,
    template: ReportTemplate | None = None,
    generated_at: datetime | None = None,
) -> bytes:
    """HTML → WeasyPrint → PDF bytes. Imported lazily for test friendliness."""
    import weasyprint

    html = render_html(
        report=report,
        sections=sections,
        findings=findings,
        project=project,
        firmware=firmware,
        template=template,
        generated_at=generated_at,
    )
    return weasyprint.HTML(string=html, base_url=str(RENDER_DIR)).write_pdf()


# ----------------------------------------------------------------------------
# Caching: deterministic content hash + on-disk artifact storage
# ----------------------------------------------------------------------------


def compute_content_hash(
    *,
    report: Report,
    sections: list[ReportSection],
    findings: list[Finding],
    template: ReportTemplate,
    fmt: str,
) -> str:
    """A hash of the rendered surface so identical inputs reuse cached files."""
    payload = {
        "template_id": template.id,
        "template_version": template.version,
        "renderer_version": TEMPLATE_VERSION,
        "format": fmt,
        "report": {
            "title": report.title,
        },
        "sections": [
            {
                "slug": s.slug,
                "title": s.title,
                "content_md": s.content_md,
                "order_index": s.order_index,
            }
            for s in sorted(sections, key=lambda x: x.order_index)
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "description": f.description,
                "evidence": f.evidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cve_ids": f.cve_ids,
                "cwe_ids": f.cwe_ids,
            }
            for f in sorted(findings, key=lambda x: str(x.id))
        ],
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def report_storage_dir(project_id: uuid.UUID, report_id: uuid.UUID) -> Path:
    settings = get_settings()
    return Path(settings.storage_root) / "projects" / str(project_id) / "reports" / str(report_id)


def artifact_path(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    content_hash: str,
    fmt: str,
) -> Path:
    return report_storage_dir(project_id, report_id) / f"{content_hash}.{fmt}"


def write_artifact(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fp:
        fp.write(content)
    os.replace(tmp, path)
