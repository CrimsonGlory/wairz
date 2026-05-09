"""Service-layer tests for ``app.services.report_service``.

Phase 2 Wave 7 file 4 of 5 — backfills service-layer tests for the
security-assessment report generator (365 LOC) per intake
audit-test-coverage-routers-services-2026-05-04. Pure-formatter
service: takes Project + Firmware + Findings and returns
markdown / HTML / PDF (the PDF path lazy-imports ``weasyprint``).

Rule #30 distribution: the only third-party heavy dependency
(``weasyprint``) is lazy-imported INSIDE ``generate_pdf_report``
at line 362. Per Rule #30, the test SOURCE-patches ``weasyprint.HTML``,
NOT ``app.services.report_service.weasyprint`` (which would be a
silent no-op — the symbol isn't bound on the consumer module). All
other dependencies (datetime, html.escape, ORM models) are
module-scope and not heavy enough to warrant patching.

Coverage targets:

* ``SEVERITY_ORDER`` / ``SEVERITY_EMOJI`` / ``SEVERITY_COLORS``
  constants — sanity (5 tiers, sorted critical→info, color tuples
  3-element).
* ``_severity_badge_html`` — escapes HTML; uses correct color tuple;
  unknown severity falls back to ``info`` colors.
* ``generate_markdown_report``:
  * Title / generated / project metadata header;
  * No-firmware branch (no Firmware Information section);
  * Firmware section all 6 properties (original_filename, sha256,
    file_size, architecture, endianness, os_info);
  * Empty findings → "No security findings" copy;
  * Severity table counts by tier;
  * Findings sorted by SEVERITY_ORDER then title;
  * file_path with line_number formatted ``path:N``; without
    line_number formatted ``path``;
  * CVE / CWE joined with commas;
  * description + evidence code-block both rendered.
* ``generate_html_report``:
  * HTML escaping for project.name (XSS canary — ``<script>``);
  * No-firmware branch;
  * Severity sections opened/closed in order;
  * Severity badge inline-styled with the right color tuple;
  * Empty findings — exec-summary line + no severity sections;
  * file_path with line_number rendered as ``path:N``.
* ``generate_pdf_report`` — Rule #30 SOURCE-patch on
  ``weasyprint.HTML``; verifies ``string=<html>`` keyword arg AND
  ``.write_pdf()`` chained call.
* **Rule #35b live canary** — real Project + Firmware + 4 Findings
  on PostgreSQL-shimmed SQLite. Markdown and HTML output both contain
  the persisted field VALUES (project.name, firmware.sha256, every
  finding.title). Mock-only tests cannot fail on:
  * a regression that drops ``firmware.original_filename`` from the
    table when the property exists (silent loss of provenance);
  * a regression that uses ``finding.severity`` for sorting BUT
    rendering uses ``finding.status`` (would still pass mock tests
    asserting ``f.severity`` was accessed);
  * the severity sort + grouping discipline (a real chain of
    persisted findings exercises both the sort key AND the
    section-grouping branch).
"""
from __future__ import annotations

import re
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.report_service import (
    SEVERITY_COLORS,
    SEVERITY_EMOJI,
    SEVERITY_ORDER,
    _severity_badge_html,
    generate_html_report,
    generate_markdown_report,
    generate_pdf_report,
)
from tests._live_db import make_live_db

# ===========================================================================
# Module constants
# ===========================================================================


class TestSeverityConstants:
    def test_severity_order_five_tiers_critical_to_info(self):
        # Lower number = higher severity (sort ascending = most severe first).
        assert SEVERITY_ORDER == {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
        }

    def test_severity_emoji_present_for_all_tiers(self):
        for tier in ("critical", "high", "medium", "low", "info"):
            assert tier in SEVERITY_EMOJI
            assert SEVERITY_EMOJI[tier]  # non-empty

    def test_severity_colors_three_element_tuples(self):
        for tier, colors in SEVERITY_COLORS.items():
            assert len(colors) == 3, f"{tier} colors must be (text, bg, accent)"
            for c in colors:
                assert c.startswith("#"), f"{tier} color {c!r} not a hex literal"


# ===========================================================================
# _severity_badge_html
# ===========================================================================


class TestSeverityBadgeHtml:
    def test_known_severity_uses_color_tuple(self):
        html = _severity_badge_html("critical")
        crit_text, _, crit_bg = SEVERITY_COLORS["critical"]
        assert crit_text in html
        assert crit_bg in html
        assert "Critical" in html  # capitalised label

    def test_unknown_severity_falls_back_to_info(self):
        html = _severity_badge_html("unknown-tier")
        info_text, _, info_bg = SEVERITY_COLORS["info"]
        assert info_text in html
        assert info_bg in html

    def test_html_special_chars_escaped_in_label(self):
        # The capitalize() of e.g. "<script>" is "<script>"; escape() wraps
        # the < and >.
        html = _severity_badge_html("<script>")
        assert "&lt;script&gt;" in html
        # The only raw `<` should be the surrounding span tags
        # (opening `<span` and closing `</span>`); the label content is
        # fully escaped.
        assert html.count("<") == 2  # <span ...> and </span>
        assert "<script>" not in html  # raw label NEVER leaks


# ===========================================================================
# Helpers for building stand-in models
# ===========================================================================


def _make_project(
    *,
    name: str = "Test Project",
    description: str | None = None,
    project_id: uuid.UUID | None = None,
) -> Project:
    return Project(
        id=project_id or uuid.uuid4(),
        name=name,
        description=description,
        status="ready",
    )


def _make_firmware(
    *,
    project_id: uuid.UUID | None = None,
    original_filename: str | None = "fw.bin",
    sha256: str = "deadbeef" * 8,
    file_size: int | None = 4194304,
    architecture: str | None = "arm",
    endianness: str | None = "little",
    os_info: str | None = "Linux 4.9",
) -> Firmware:
    return Firmware(
        id=uuid.uuid4(),
        project_id=project_id or uuid.uuid4(),
        original_filename=original_filename,
        sha256=sha256,
        file_size=file_size,
        architecture=architecture,
        endianness=endianness,
        os_info=os_info,
    )


def _make_finding(
    *,
    title: str = "Generic finding",
    severity: str = "medium",
    status: str = "open",
    description: str | None = None,
    evidence: str | None = None,
    file_path: str | None = None,
    line_number: int | None = None,
    cve_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    project_id: uuid.UUID | None = None,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        project_id=project_id or uuid.uuid4(),
        title=title,
        severity=severity,
        status=status,
        description=description,
        evidence=evidence,
        file_path=file_path,
        line_number=line_number,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        source="manual",
    )


# ===========================================================================
# generate_markdown_report
# ===========================================================================


class TestGenerateMarkdownReport:
    def test_title_and_project_header(self):
        project = _make_project(name="DPCS10", description="Camera FW")
        md = generate_markdown_report(project, None, [])
        assert "# Security Assessment Report: DPCS10" in md
        assert "**Project:** DPCS10" in md
        assert "**Description:** Camera FW" in md

    def test_no_description_omits_description_line(self):
        project = _make_project(name="P", description=None)
        md = generate_markdown_report(project, None, [])
        assert "**Description:**" not in md

    def test_no_firmware_omits_firmware_section(self):
        md = generate_markdown_report(_make_project(), None, [])
        assert "## Firmware Information" not in md

    def test_firmware_section_includes_all_properties(self):
        firmware = _make_firmware()
        md = generate_markdown_report(_make_project(), firmware, [])
        assert "## Firmware Information" in md
        assert "fw.bin" in md
        assert firmware.sha256 in md
        # 4 MB == 4194304 bytes; expect "4.0 MB (4,194,304 bytes)"
        assert "4.0 MB (4,194,304 bytes)" in md
        assert "arm" in md
        assert "little" in md
        assert "Linux 4.9" in md

    def test_firmware_section_skips_missing_properties(self):
        firmware = _make_firmware(
            original_filename=None, file_size=None,
            architecture=None, endianness=None, os_info=None,
        )
        md = generate_markdown_report(_make_project(), firmware, [])
        # SHA256 still present; nothing else.
        assert firmware.sha256 in md
        assert "Filename" not in md
        assert "Architecture" not in md

    def test_empty_findings_renders_no_findings_copy(self):
        md = generate_markdown_report(_make_project(), None, [])
        assert "No security findings were recorded" in md
        # Findings header MUST NOT appear when findings list is empty.
        assert "## Findings" not in md

    def test_severity_table_counts_findings(self):
        findings = [
            _make_finding(severity="critical", title="C1"),
            _make_finding(severity="high", title="H1"),
            _make_finding(severity="high", title="H2"),
            _make_finding(severity="low", title="L1"),
        ]
        md = generate_markdown_report(_make_project(), None, findings)
        assert "**4** finding(s) were identified" in md
        # Summary table.
        assert "| Critical | 1 |" in md
        assert "| High | 2 |" in md
        assert "| Low | 1 |" in md
        # No medium / info.
        assert "| Medium |" not in md

    def test_findings_sorted_critical_first_then_title(self):
        findings = [
            _make_finding(severity="medium", title="M-Beta"),
            _make_finding(severity="high", title="H-Alpha"),
            _make_finding(severity="critical", title="C-Bravo"),
            _make_finding(severity="medium", title="M-Alpha"),
        ]
        md = generate_markdown_report(_make_project(), None, findings)
        # Each finding header starts with "#### <title>".
        # Find indices in document order.
        positions = [(re.search(rf"#### {re.escape(t)}", md).start(), t)
                     for t in ("C-Bravo", "H-Alpha", "M-Alpha", "M-Beta")]
        # Document order should be the input order to ``positions``.
        for i in range(1, len(positions)):
            assert positions[i][0] > positions[i - 1][0], (
                f"{positions[i][1]!r} appeared before {positions[i - 1][1]!r}"
            )

    def test_file_path_with_line_number(self):
        f = _make_finding(file_path="/usr/bin/x", line_number=42, severity="medium")
        md = generate_markdown_report(_make_project(), None, [f])
        assert "**File:** `/usr/bin/x:42`" in md

    def test_file_path_without_line_number(self):
        f = _make_finding(file_path="/usr/bin/x", line_number=None, severity="medium")
        md = generate_markdown_report(_make_project(), None, [f])
        assert "**File:** `/usr/bin/x`" in md
        # Make sure no spurious ":None" or ":0".
        assert "/usr/bin/x:None" not in md
        assert "/usr/bin/x:0" not in md

    def test_cve_and_cwe_lists_joined(self):
        f = _make_finding(
            severity="high",
            cve_ids=["CVE-2023-0001", "CVE-2023-0002"],
            cwe_ids=["CWE-78", "CWE-89"],
        )
        md = generate_markdown_report(_make_project(), None, [f])
        assert "**CVEs:** CVE-2023-0001, CVE-2023-0002" in md
        assert "**CWEs:** CWE-78, CWE-89" in md

    def test_description_and_evidence_blocks(self):
        f = _make_finding(
            severity="medium",
            description="Some prose explaining the issue.",
            evidence="strings(1) showed 'admin:admin'",
        )
        md = generate_markdown_report(_make_project(), None, [f])
        assert "Some prose explaining the issue." in md
        assert "**Evidence:**" in md
        assert "```\nstrings(1) showed 'admin:admin'\n```" in md


# ===========================================================================
# generate_html_report
# ===========================================================================


class TestGenerateHtmlReport:
    def test_xss_in_project_name_escaped(self):
        project = _make_project(name="<script>alert('xss')</script>")
        html = generate_html_report(project, None, [])
        # The literal <script> must NOT appear; the escaped form must.
        assert "<script>alert('xss')</script>" not in html.replace(
            "&lt;script&gt;alert('xss')&lt;/script&gt;", "[ESCAPED]",
        )
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html

    def test_no_firmware_branch_omits_firmware_section(self):
        html = generate_html_report(_make_project(), None, [])
        assert "Firmware Information" not in html

    def test_firmware_xss_in_filename_escaped(self):
        firmware = _make_firmware(original_filename="<img onerror=evil>.bin")
        html = generate_html_report(_make_project(), firmware, [])
        # The escaped <img> must appear.
        assert "&lt;img onerror=evil&gt;.bin" in html

    def test_severity_sections_in_order(self):
        findings = [
            _make_finding(severity="low", title="L"),
            _make_finding(severity="critical", title="C"),
            _make_finding(severity="high", title="H"),
        ]
        html = generate_html_report(_make_project(), None, findings)
        crit_at = html.find("Critical Severity")
        high_at = html.find("High Severity")
        low_at = html.find("Low Severity")
        assert 0 <= crit_at < high_at < low_at, (
            f"severity sections out of order: critical@{crit_at} "
            f"high@{high_at} low@{low_at}"
        )

    def test_empty_findings_renders_no_findings_copy(self):
        html = generate_html_report(_make_project(), None, [])
        assert "No security findings were recorded" in html
        assert "Severity</h2>" not in html  # no severity sections opened

    def test_file_path_with_line_number(self):
        f = _make_finding(severity="medium", file_path="x.c", line_number=10)
        html = generate_html_report(_make_project(), None, [f])
        assert "x.c:10" in html

    def test_file_path_without_line_number(self):
        f = _make_finding(severity="medium", file_path="x.c", line_number=None)
        html = generate_html_report(_make_project(), None, [f])
        assert "<code>x.c</code>" in html
        assert "x.c:None" not in html

    def test_cves_and_cwes_rendered(self):
        f = _make_finding(
            severity="high",
            cve_ids=["CVE-2024-0001"], cwe_ids=["CWE-78", "CWE-79"],
        )
        html = generate_html_report(_make_project(), None, [f])
        assert "CVE-2024-0001" in html
        assert "CWE-78, CWE-79" in html


# ===========================================================================
# generate_pdf_report — Rule #30 SOURCE patch on lazy weasyprint
# ===========================================================================


class TestGeneratePdfReport:
    def test_source_patch_on_weasyprint_html(self):
        """``weasyprint`` is lazy-imported inside ``generate_pdf_report``
        at line 362. Per Rule #30, the patch target is ``weasyprint.HTML``
        (the SOURCE module) — patching ``rs_mod.weasyprint`` would be a
        silent no-op because the consumer module has no module-scope
        ``weasyprint`` binding."""
        # Build a fake `weasyprint` module replacement.
        fake_html_instance = MagicMock()
        fake_html_instance.write_pdf.return_value = b"%PDF-1.4 fake bytes"

        fake_weasyprint = MagicMock()
        fake_weasyprint.HTML = MagicMock(return_value=fake_html_instance)

        # Inject as if `import weasyprint` resolved to fake_weasyprint.
        with patch.dict("sys.modules", {"weasyprint": fake_weasyprint}):
            project = _make_project(name="canary")
            findings = [
                _make_finding(severity="high", title="High issue"),
            ]
            pdf_bytes = generate_pdf_report(project, None, findings)

        # Verify the call shape.
        assert pdf_bytes == b"%PDF-1.4 fake bytes"
        # weasyprint.HTML(string=<rendered html>)
        fake_weasyprint.HTML.assert_called_once()
        call_kwargs = fake_weasyprint.HTML.call_args.kwargs
        assert "string" in call_kwargs
        # The rendered HTML must reference the project name (verifies the
        # PDF function actually called generate_html_report rather than
        # passing an empty string).
        assert "canary" in call_kwargs["string"]
        assert "High issue" in call_kwargs["string"]
        # And then .write_pdf() chained.
        fake_html_instance.write_pdf.assert_called_once()


# ===========================================================================
# Rule #35b LIVE-CANARY — real ORM + value-flow contract
# ===========================================================================


class TestReportRenderingLiveCanary:
    """Rule #35b live canary: real Project + Firmware + Findings on the
    SQLite-shimmed live DB. Both markdown and HTML reports include the
    persisted field VALUES end-to-end.

    Mock-only tests of ``mock.assert_called_with(project, firmware,
    findings)`` cannot fail on:
    * a regression that silently drops ``firmware.original_filename``
      in production rows when the schema migration adds NULL-default;
    * a regression where ``finding.severity`` becomes None for some
      sources (the sort key ``SEVERITY_ORDER.get(f.severity, 99)``
      would still work but the section header would render
      ``None Severity``);
    * a regression dropping the line_number from the rendered file
      path while still passing assertion-shape mock tests.
    """

    @pytest.mark.asyncio
    async def test_markdown_and_html_round_trip_persisted_values(self):
        async with make_live_db() as db:
            project = Project(
                id=uuid.uuid4(), name="canary-report-project",
                description="canary description",
                status="ready",
            )
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=project.id,
                original_filename="canary.bin",
                sha256="canary" + "0" * 58,
                file_size=8 * 1024 * 1024,
                architecture="aarch64",
                endianness="little",
                os_info="Linux 5.10 (canary)",
            )
            db.add(firmware)
            await db.flush()

            f1 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                title="Hardcoded admin password",
                severity="critical", status="open", source="manual",
                file_path="/etc/shadow", line_number=12,
                cve_ids=["CVE-2024-9999"], cwe_ids=["CWE-798"],
                description="Plaintext credentials present.",
                evidence="root:x:0:0:root:/root:/bin/bash",
            )
            f2 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                title="Telnet daemon enabled",
                severity="high", status="open", source="manual",
                file_path="/etc/init.d/telnetd",
            )
            f3 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                title="World-writable /tmp",
                severity="low", status="false_positive", source="manual",
            )
            f4 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                title="Banner discloses version",
                severity="info", status="open", source="manual",
            )
            db.add_all([f1, f2, f3, f4])
            await db.flush()
            await db.commit()

            from sqlalchemy import select
            stmt = select(Project).where(Project.id == project.id)
            persisted_project = (await db.execute(stmt)).scalar_one()
            persisted_firmware = (await db.execute(
                select(Firmware).where(Firmware.id == firmware.id)
            )).scalar_one()
            persisted_findings = list(
                (await db.execute(
                    select(Finding).where(Finding.project_id == project.id)
                )).scalars().all()
            )

            assert persisted_project.name == "canary-report-project"
            assert persisted_firmware.sha256 == "canary" + "0" * 58
            assert len(persisted_findings) == 4

            md = generate_markdown_report(
                persisted_project, persisted_firmware, persisted_findings,
            )
            html = generate_html_report(
                persisted_project, persisted_firmware, persisted_findings,
            )

            # Markdown — value-flow assertions.
            assert "canary-report-project" in md
            assert "canary description" in md
            assert "canary.bin" in md
            assert ("canary" + "0" * 58) in md
            assert "8.0 MB (8,388,608 bytes)" in md
            assert "aarch64" in md
            assert "little" in md
            assert "Linux 5.10 (canary)" in md
            assert "Hardcoded admin password" in md
            assert "Telnet daemon enabled" in md
            assert "World-writable /tmp" in md
            assert "Banner discloses version" in md
            assert "/etc/shadow:12" in md
            assert "CVE-2024-9999" in md
            assert "CWE-798" in md
            assert "Plaintext credentials present." in md
            assert "root:x:0:0:root:/root:/bin/bash" in md

            # Severity headings ordered correctly.
            crit_idx = md.find("### Critical Severity")
            high_idx = md.find("### High Severity")
            low_idx = md.find("### Low Severity")
            info_idx = md.find("### Info Severity")
            assert 0 <= crit_idx < high_idx < low_idx < info_idx

            # HTML — value-flow assertions (escape() leaves alphanumeric
            # alone but applies to angle brackets).
            assert "canary-report-project" in html
            assert "canary.bin" in html
            assert ("canary" + "0" * 58) in html
            assert "/etc/shadow:12" in html
            assert "CVE-2024-9999" in html
            assert "CWE-798" in html
            # No XSS-shaped text leaked unescaped.
            assert "<script>" not in html

    @pytest.mark.asyncio
    async def test_pdf_report_round_trips_via_html(self):
        """End-to-end: persist real rows; generate_pdf_report composes the
        HTML from those rows AND passes it through (mocked) weasyprint.
        Rule #30 SOURCE-patch on weasyprint."""
        async with make_live_db() as db:
            project = Project(
                id=uuid.uuid4(), name="pdf-canary",
                description=None, status="ready",
            )
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=project.id, sha256="p" * 64,
            )
            db.add(firmware)
            await db.flush()

            f = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                title="PDF Canary Finding",
                severity="medium", status="open", source="manual",
            )
            db.add(f)
            await db.flush()
            await db.commit()

            captured = {}

            class _FakeHTML:
                def __init__(self, *, string: str):
                    captured["string"] = string

                def write_pdf(self) -> bytes:
                    return b"%PDF-1.4 mocked"

            fake_weasyprint = MagicMock()
            fake_weasyprint.HTML = _FakeHTML

            with patch.dict("sys.modules", {"weasyprint": fake_weasyprint}):
                pdf = generate_pdf_report(project, firmware, [f])

            assert pdf == b"%PDF-1.4 mocked"
            # The HTML passed to weasyprint includes the persisted finding
            # title — verifies the PDF path is wired correctly.
            assert "pdf-canary" in captured["string"]
            assert "PDF Canary Finding" in captured["string"]
