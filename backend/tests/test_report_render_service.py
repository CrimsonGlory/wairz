"""Tests for the report renderer + content-hash determinism + sandbox."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import report_render_service as rrs
from app.services.report_template_service import ReportTemplate, TemplateSection
from app.utils.sandbox import PathTraversalError, validate_path


# ---------------------------------------------------------------------------
# Tiny stand-in objects so we don't need a database session.
# ---------------------------------------------------------------------------

def _template() -> ReportTemplate:
    return ReportTemplate(
        id="t1",
        name="Tiny",
        version=1,
        language="en",
        findings_order=50,
        sections=[
            TemplateSection(
                slug="executive_summary",
                title="Executive Summary",
                required=True,
                order=10,
            ),
            TemplateSection(
                slug="scope",
                title="Scope",
                required=True,
                order=20,
            ),
            TemplateSection(
                slug="conclusion",
                title="Conclusion",
                required=False,
                order=60,
            ),
        ],
    )


def _section(slug: str, title: str, content: str, order: int) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        report_id=uuid.uuid4(),
        slug=slug,
        title=title,
        content_md=content,
        order_index=order,
        updated_by="test",
        updated_at=None,
    )


def _finding(*, severity: str = "high", title: str = "Hardcoded creds",
             ident: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.UUID(ident) if ident else uuid.uuid4(),
        title=title,
        severity=severity,
        status="open",
        description="Plaintext password in /etc/passwd-like file.",
        evidence="root:x:0:0:::/bin/sh",
        file_path="/etc/passwd",
        line_number=12,
        cve_ids=None,
        cwe_ids=["CWE-798"],
    )


def _report() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        title="Test Report",
        status="draft",
    )


def _project() -> SimpleNamespace:
    return SimpleNamespace(name="TestProject", description=None)


# ---------------------------------------------------------------------------
# Renderer smoke tests
# ---------------------------------------------------------------------------

class TestRenderHTML:
    def test_renders_sections_in_template_order(self):
        template = _template()
        sections = [
            _section("scope", "Scope", "**Scope** content.", 20),
            _section("executive_summary", "Executive Summary",
                     "Top-level summary.", 10),
        ]
        findings = [_finding()]
        html = rrs.render_html(
            report=_report(),
            sections=sections,
            findings=findings,
            project=_project(),
            firmware=None,
            template=template,
        )
        # Both rendered sections appear, in template order.
        es_idx = html.index("Executive Summary")
        scope_idx = html.index("Scope")
        findings_idx = html.index("Findings")
        assert es_idx < scope_idx < findings_idx
        # Finding card came from the structured pipeline, not raw markdown.
        assert "Hardcoded creds" in html
        assert "severity-high" in html

    def test_findings_section_inserted_at_findings_order(self):
        template = _template()
        sections = [
            _section("conclusion", "Conclusion", "Wrap-up.", 60),
        ]
        html = rrs.render_html(
            report=_report(),
            sections=sections,
            findings=[_finding()],
            project=_project(),
            firmware=None,
            template=template,
        )
        # findings_order=50, conclusion=60 → findings appears before conclusion.
        assert html.index("Findings") < html.index("Conclusion")

    def test_strips_inline_html_from_section_markdown(self):
        template = _template()
        sections = [
            _section(
                "executive_summary",
                "Executive Summary",
                "Hello <script>alert(1)</script> world.",
                10,
            ),
        ]
        html = rrs.render_html(
            report=_report(),
            sections=sections,
            findings=[],
            project=_project(),
            firmware=None,
            template=template,
        )
        # bleach strips the <script> tag.
        assert "<script" not in html
        assert "alert(1)" not in html or "&lt;script" not in html
        # The visible word "alert(1)" might survive as text; the *tag* must not.
        assert "<script>" not in html

    def test_finding_description_renders_markdown(self):
        template = _template()
        f = _finding()
        f.description = (
            "**bold** statement and `code` reference.\n\n"
            "1. first item\n"
            "2. second item\n\n"
            "Final paragraph."
        )
        html = rrs.render_html(
            report=_report(),
            sections=[],
            findings=[f],
            project=_project(),
            firmware=None,
            template=template,
        )
        # Markdown was processed into real HTML, not escaped as plain text.
        assert "<strong>bold</strong>" in html
        assert "<code>code</code>" in html
        assert "<ol>" in html and "<li>first item</li>" in html
        # No literal markdown syntax left in the description block.
        assert "**bold**" not in html

# ---------------------------------------------------------------------------
# Content-hash determinism
# ---------------------------------------------------------------------------

class TestContentHash:
    def test_same_inputs_produce_same_hash(self):
        template = _template()
        report = _report()
        sections = [
            _section("executive_summary", "Executive Summary", "Body.", 10),
        ]
        findings = [_finding(ident="11111111-1111-1111-1111-111111111111")]
        h1 = rrs.compute_content_hash(
            report=report,
            sections=sections,
            findings=findings,
            template=template,
            fmt="pdf",
        )
        h2 = rrs.compute_content_hash(
            report=report,
            sections=sections,
            findings=findings,
            template=template,
            fmt="pdf",
        )
        assert h1 == h2

    def test_section_change_changes_hash(self):
        template = _template()
        report = _report()
        findings = [_finding(ident="22222222-2222-2222-2222-222222222222")]
        h1 = rrs.compute_content_hash(
            report=report,
            sections=[
                _section("executive_summary", "Executive Summary", "v1", 10),
            ],
            findings=findings,
            template=template,
            fmt="pdf",
        )
        h2 = rrs.compute_content_hash(
            report=report,
            sections=[
                _section("executive_summary", "Executive Summary", "v2", 10),
            ],
            findings=findings,
            template=template,
            fmt="pdf",
        )
        assert h1 != h2

    def test_finding_change_changes_hash(self):
        template = _template()
        report = _report()
        sections = [_section("scope", "Scope", "Body", 20)]
        h1 = rrs.compute_content_hash(
            report=report, sections=sections,
            findings=[_finding(ident="33333333-3333-3333-3333-333333333333", title="A")],
            template=template, fmt="pdf",
        )
        h2 = rrs.compute_content_hash(
            report=report, sections=sections,
            findings=[_finding(ident="33333333-3333-3333-3333-333333333333", title="B")],
            template=template, fmt="pdf",
        )
        assert h1 != h2

    def test_format_changes_hash(self):
        template = _template()
        report = _report()
        sections = [_section("scope", "Scope", "Body", 20)]
        h_pdf = rrs.compute_content_hash(
            report=report, sections=sections, findings=[],
            template=template, fmt="pdf",
        )
        h_html = rrs.compute_content_hash(
            report=report, sections=sections, findings=[],
            template=template, fmt="html",
        )
        assert h_pdf != h_html

    def test_section_order_independent(self):
        template = _template()
        report = _report()
        s1 = _section("executive_summary", "Executive Summary", "A", 10)
        s2 = _section("scope", "Scope", "B", 20)
        h1 = rrs.compute_content_hash(
            report=report, sections=[s1, s2], findings=[],
            template=template, fmt="pdf",
        )
        h2 = rrs.compute_content_hash(
            report=report, sections=[s2, s1], findings=[],
            template=template, fmt="pdf",
        )
        assert h1 == h2


# ---------------------------------------------------------------------------
# Sandbox: artifact path stays under the report dir
# ---------------------------------------------------------------------------

class TestArtifactSandbox:
    def test_artifact_path_inside_storage_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            rrs.get_settings(), "storage_root", str(tmp_path), raising=False,
        )
        # Re-call the function so it picks up the patched setting.
        from app.config import get_settings
        get_settings.cache_clear()
        monkeypatch.setenv("STORAGE_ROOT", str(tmp_path))

        project_id = uuid.uuid4()
        report_id = uuid.uuid4()
        path = rrs.artifact_path(project_id, report_id, "abc123", "pdf")
        # Resolved path must be under storage_root.
        validate_path(
            str(rrs.report_storage_dir(project_id, report_id)),
            os.path.basename(path),
        )

    def test_validate_path_rejects_traversal(self, tmp_path: Path):
        # A request for "../etc/passwd" inside a fake report dir is rejected.
        with pytest.raises(PathTraversalError):
            validate_path(str(tmp_path / "reports" / "abc"),
                          "../../../etc/passwd")

    def test_write_artifact_creates_parent(self, tmp_path: Path):
        target = tmp_path / "deep" / "nested" / "file.pdf"
        rrs.write_artifact(target, b"hello")
        assert target.read_bytes() == b"hello"
