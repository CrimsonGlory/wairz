"""Service-layer tests for ``app.services.compliance_service``.

Phase 2 Wave 7 file 2 of 5 — backfills service-layer tests for the
ETSI EN 303 645 compliance assessment service (481 LOC) per intake
audit-test-coverage-routers-services-2026-05-04. Pairs with Wave 5
``test_compliance_router.py`` (cross-project boundary canary on the
HTTP surface; this file canaries the value-flow of the underlying
report generator).

The service maps existing firmware Finding rows to the 13 ETSI
provisions via three pattern types — title regex, source-tool name,
CWE-ID set intersection. Reports are generated on-demand and NOT
persisted (no JSONB cache table); the value-flow contract is "Finding
rows in DB → report dict matched to the right provisions with the right
status".

Rule #30 distribution: every dependency is module-scope (sqlalchemy,
Finding model). No third-party heavy imports — patches not needed for
this service's tests, EXCEPT the inverse-Rule-30 reminder that
``ETSI_PROVISIONS`` is a module-scope dict used by all matcher methods;
tests that need to mutate it must `monkeypatch.setattr(comp_mod,
"ETSI_PROVISIONS", ...)` against the consumer module.

Coverage targets:

* ``ETSI_PROVISIONS`` — sanity: all 13 provisions present; clauses
  5.1–5.13; the 4 not_automatable provisions (9/10/11/12) flagged.
* ``_finding_matches`` (the inner matcher) — title regex
  case-insensitive; source-tool exact-set membership; CWE set
  intersection; empty title doesn't crash; None title doesn't crash;
  cwe_ids is None doesn't crash.
* ``_match_findings`` — multiple findings against one provision; same
  finding matched twice (once via title, once via source) returns it
  ONCE (no dupes).
* ``_determine_status`` — exhaustive truth table:
  * not_automatable + no findings → ``not_tested``;
  * not_automatable + open findings → ``fail``;
  * not_automatable + only resolved → ``partial``;
  * has_patterns + no matches → ``pass`` (we looked, found nothing);
  * matches all resolved → ``pass``;
  * mix of open+resolved → ``partial``;
  * all open → ``fail``;
  * empty patterns + no matches → ``not_tested`` (no patterns means we
    didn't have a way to look).
* ``format_report_text`` — header structure; status icons; truncation
  at 10-finding cap with "and N more" continuation; "No issues found"
  vs "No relevant analysis"; not_automatable note rendered.
* **Rule #35b live canary** — real Project + 4 Finding rows on
  PostgreSQL-shimmed SQLite. ``generate_report`` walks the actual ORM
  query path and produces a report whose provisions reference real
  finding IDs round-tripped from DB. Cross-project canary: a Finding
  in project B does NOT appear in project A's report (security
  boundary — same shape as Wave 3 cross-project canaries).
* **firmware_id filter canary** — when ``firmware_id`` is supplied, the
  report only counts findings on that firmware (a regression where
  ``firmware_id`` was applied as `==None` would silently leak all
  rows; canary catches it).
"""
from __future__ import annotations

import re
import uuid

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.services import compliance_service as comp_mod
from app.services.compliance_service import (
    ETSI_PROVISIONS,
    ETSIComplianceService,
)

from tests._live_db import make_live_db


# ===========================================================================
# ETSI_PROVISIONS sanity
# ===========================================================================


class TestEtsiProvisionsConstants:
    def test_all_thirteen_provisions_present(self):
        assert set(ETSI_PROVISIONS.keys()) == set(range(1, 14))

    def test_clauses_match_specification(self):
        """ETSI EN 303 645 V2.1.1 numbers the provisions 5.1 through 5.13."""
        for n in range(1, 14):
            assert ETSI_PROVISIONS[n]["id"] == f"5.{n}"

    def test_four_not_automatable_provisions(self):
        """Provisions 9 (resilience), 10 (telemetry), 11 (delete user data),
        12 (installation) are runtime/manual concerns and not_automatable."""
        not_auto = {
            n for n, d in ETSI_PROVISIONS.items() if d.get("not_automatable")
        }
        assert not_auto == {9, 10, 11, 12}

    def test_each_provision_has_required_keys(self):
        required = {"id", "name", "description", "title_patterns", "source_patterns", "cwe_ids"}
        for n, prov in ETSI_PROVISIONS.items():
            assert required.issubset(prov.keys()), (
                f"provision {n} missing keys: {required - prov.keys()}"
            )


# ===========================================================================
# _finding_matches — the inner matcher
# ===========================================================================


def _make_finding(
    *,
    title: str = "Generic finding",
    source: str = "manual",
    cwe_ids: list[str] | None = None,
    status: str = "open",
    severity: str = "medium",
    project_id: uuid.UUID | None = None,
    firmware_id: uuid.UUID | None = None,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        project_id=project_id or uuid.uuid4(),
        firmware_id=firmware_id,
        title=title,
        severity=severity,
        status=status,
        source=source,
        cwe_ids=cwe_ids,
    )


class TestFindingMatches:
    def setup_method(self):
        # Minimal AsyncSession-shaped service surface for the unit-level methods.
        self.service = ETSIComplianceService(db=None)  # type: ignore[arg-type]

    def test_title_regex_match_case_insensitive(self):
        prov = {
            "title_patterns": [r"hardcoded.*password"],
            "source_patterns": [],
            "cwe_ids": [],
        }
        title_pats = [re.compile(p, re.IGNORECASE) for p in prov["title_patterns"]]
        finding = _make_finding(title="Hardcoded ROOT password in /etc/shadow")
        assert self.service._finding_matches(
            finding, title_pats, set(prov["source_patterns"]), set(prov["cwe_ids"]),
        )

    def test_source_exact_match_short_circuits(self):
        prov = {
            "title_patterns": [r"absolutely-not-going-to-match"],
            "source_patterns": ["find_hardcoded_credentials"],
            "cwe_ids": [],
        }
        title_pats = [re.compile(p, re.IGNORECASE) for p in prov["title_patterns"]]
        finding = _make_finding(
            title="something completely unrelated",
            source="find_hardcoded_credentials",
        )
        assert self.service._finding_matches(
            finding, title_pats, set(prov["source_patterns"]), set(prov["cwe_ids"]),
        )

    def test_cwe_intersection_match(self):
        prov = {
            "title_patterns": [],
            "source_patterns": [],
            "cwe_ids": ["CWE-798", "CWE-259"],
        }
        finding = _make_finding(cwe_ids=["CWE-798", "CWE-1"])
        assert self.service._finding_matches(
            finding, [], set(prov["source_patterns"]), set(prov["cwe_ids"]),
        )

    def test_no_match_returns_false(self):
        prov = {
            "title_patterns": [r"xyz"],
            "source_patterns": ["other_source"],
            "cwe_ids": ["CWE-1"],
        }
        title_pats = [re.compile(p, re.IGNORECASE) for p in prov["title_patterns"]]
        finding = _make_finding(title="abc", source="manual", cwe_ids=["CWE-99"])
        assert not self.service._finding_matches(
            finding, title_pats, set(prov["source_patterns"]), set(prov["cwe_ids"]),
        )

    def test_empty_title_does_not_crash(self):
        finding = _make_finding(title="")
        # Treat title as empty string; no regex should match.
        title_pats = [re.compile(r"buffer", re.IGNORECASE)]
        assert not self.service._finding_matches(finding, title_pats, set(), set())

    def test_none_title_does_not_crash(self):
        """Finding.title is non-null in the model but the matcher's
        ``title or ""`` guard means a defensively-None value still works."""
        finding = _make_finding()
        finding.title = None  # type: ignore[assignment]
        title_pats = [re.compile(r"buffer", re.IGNORECASE)]
        assert not self.service._finding_matches(finding, title_pats, set(), set())

    def test_none_cwe_ids_does_not_crash(self):
        finding = _make_finding(cwe_ids=None)
        # Non-empty cwe_set but None on the finding side — no intersection,
        # no crash.
        assert not self.service._finding_matches(finding, [], set(), {"CWE-1"})


# ===========================================================================
# _match_findings — collects matches across multiple findings
# ===========================================================================


class TestMatchFindings:
    def setup_method(self):
        self.service = ETSIComplianceService(db=None)  # type: ignore[arg-type]

    def test_collects_multiple_matches(self):
        prov = ETSI_PROVISIONS[1]  # default-passwords; "hardcoded.*password"
        findings = [
            _make_finding(title="Hardcoded admin password", source="manual"),
            _make_finding(title="Default password in firmware",
                          source="find_hardcoded_credentials"),
            _make_finding(title="Buffer overflow in parser", source="manual"),  # no match
        ]
        matched = self.service._match_findings(findings, prov)
        # First two should match (one via title, one via source).
        assert len(matched) == 2
        assert findings[0] in matched
        assert findings[1] in matched
        assert findings[2] not in matched

    def test_finding_matching_multiple_axes_appears_once(self):
        """A single finding that matches BOTH a title pattern AND a source
        pattern is still returned exactly ONCE — _finding_matches
        short-circuits on the first hit."""
        prov = ETSI_PROVISIONS[1]
        # Matches both source_patterns AND title regex.
        f = _make_finding(
            title="Hardcoded password leak",
            source="find_hardcoded_credentials",
        )
        matched = self.service._match_findings([f], prov)
        assert matched == [f]


# ===========================================================================
# _determine_status — full truth table
# ===========================================================================


class TestDetermineStatus:
    def setup_method(self):
        self.service = ETSIComplianceService(db=None)  # type: ignore[arg-type]

    # --- not_automatable branch ---

    def test_not_automatable_no_findings_returns_not_tested(self):
        prov = {"not_automatable": True, "title_patterns": [], "source_patterns": [], "cwe_ids": []}
        assert self.service._determine_status(prov, []) == "not_tested"

    def test_not_automatable_open_finding_returns_fail(self):
        prov = {"not_automatable": True, "title_patterns": [], "source_patterns": [], "cwe_ids": []}
        f = _make_finding(status="open")
        assert self.service._determine_status(prov, [f]) == "fail"

    def test_not_automatable_only_resolved_findings_returns_partial(self):
        prov = {"not_automatable": True, "title_patterns": [], "source_patterns": [], "cwe_ids": []}
        f = _make_finding(status="fixed")
        assert self.service._determine_status(prov, [f]) == "partial"

    # --- has_patterns branch ---

    def test_has_patterns_no_matches_returns_pass(self):
        """The 'we looked and found nothing' branch — has_patterns truthy
        AND matched_findings empty → pass."""
        prov = {"title_patterns": [r"foo"], "source_patterns": [], "cwe_ids": []}
        assert self.service._determine_status(prov, []) == "pass"

    def test_no_patterns_no_matches_returns_not_tested(self):
        prov = {"title_patterns": [], "source_patterns": [], "cwe_ids": []}
        assert self.service._determine_status(prov, []) == "not_tested"

    # --- matched_findings branch ---

    def test_all_resolved_returns_pass(self):
        prov = {"title_patterns": [r"x"], "source_patterns": [], "cwe_ids": []}
        findings = [_make_finding(status="fixed"), _make_finding(status="false_positive")]
        assert self.service._determine_status(prov, findings) == "pass"

    def test_mixed_open_and_resolved_returns_partial(self):
        prov = {"title_patterns": [r"x"], "source_patterns": [], "cwe_ids": []}
        findings = [_make_finding(status="open"), _make_finding(status="fixed")]
        assert self.service._determine_status(prov, findings) == "partial"

    def test_all_open_returns_fail(self):
        prov = {"title_patterns": [r"x"], "source_patterns": [], "cwe_ids": []}
        findings = [_make_finding(status="open"), _make_finding(status="open")]
        assert self.service._determine_status(prov, findings) == "fail"


# ===========================================================================
# format_report_text — output formatter
# ===========================================================================


class TestFormatReportText:
    def setup_method(self):
        self.service = ETSIComplianceService(db=None)  # type: ignore[arg-type]

    def _make_report(
        self,
        provisions: list[dict] | None = None,
        summary: dict | None = None,
    ) -> dict:
        return {
            "standard": "ETSI EN 303 645",
            "standard_version": "V2.1.1 (2020-06)",
            "generated_at": "2026-05-06T12:00:00+00:00",
            "provisions": provisions or [],
            "summary": summary or {"total": 13, "pass": 13, "fail": 0, "partial": 0, "not_tested": 0},
        }

    def test_header_and_summary_lines(self):
        report = self._make_report()
        text = self.service.format_report_text(report)
        assert "# ETSI EN 303 645 Compliance Report" in text
        assert "Version: V2.1.1 (2020-06)" in text
        assert "Generated: 2026-05-06T12:00:00+00:00" in text
        assert "Total provisions: 13" in text
        assert "Pass:       13" in text

    def test_status_icons_per_provision(self):
        report = self._make_report(provisions=[
            {"clause": "5.1", "name": "p1", "description": "d1",
             "status": "pass", "finding_count": 0, "findings": []},
            {"clause": "5.2", "name": "p2", "description": "d2",
             "status": "fail", "finding_count": 1, "findings": [
                 {"severity": "high", "title": "T", "status": "open", "source": "s"}
             ]},
            {"clause": "5.3", "name": "p3", "description": "d3",
             "status": "partial", "finding_count": 1, "findings": [
                 {"severity": "low", "title": "TT", "status": "open", "source": "x"}
             ]},
            {"clause": "5.4", "name": "p4", "description": "d4",
             "status": "not_tested", "finding_count": 0, "findings": []},
        ])
        text = self.service.format_report_text(report)
        assert "[PASS] 5.1" in text
        assert "[FAIL] 5.2" in text
        assert "[PARTIAL] 5.3" in text
        assert "[NOT TESTED] 5.4" in text

    def test_truncation_at_ten_findings_shows_continuation(self):
        finds = [
            {"severity": "low", "title": f"T{i}", "status": "open", "source": "x"}
            for i in range(15)
        ]
        report = self._make_report(provisions=[{
            "clause": "5.5", "name": "n", "description": "d",
            "status": "fail", "finding_count": 15, "findings": finds,
        }])
        text = self.service.format_report_text(report)
        # Capped at 10 visible.
        assert "T0" in text
        assert "T9" in text
        assert "T10" not in text  # the 11th title (index 10) is truncated
        assert "and 5 more" in text

    def test_no_findings_pass_shows_no_issues_line(self):
        report = self._make_report(provisions=[{
            "clause": "5.6", "name": "n", "description": "d",
            "status": "pass", "finding_count": 0, "findings": [],
        }])
        text = self.service.format_report_text(report)
        assert "No issues found." in text

    def test_no_findings_not_tested_shows_no_analysis_line(self):
        report = self._make_report(provisions=[{
            "clause": "5.9", "name": "n", "description": "d",
            "status": "not_tested", "finding_count": 0, "findings": [],
        }])
        text = self.service.format_report_text(report)
        assert "No relevant analysis has been performed." in text

    def test_not_automatable_note_rendered(self):
        report = self._make_report(provisions=[{
            "clause": "5.9", "name": "Resilience", "description": "d",
            "status": "not_tested", "finding_count": 0, "findings": [],
            "note": "This provision requires runtime or manual assessment.",
        }])
        text = self.service.format_report_text(report)
        assert "Note: This provision requires runtime or manual assessment." in text


# ===========================================================================
# Rule #35b LIVE-CANARY — real ORM round-trip + cross-project boundary
# ===========================================================================


class TestGenerateReportLiveCanary:
    """Rule #35b live canary: real Project + Finding rows + the
    full ``generate_report`` value-flow contract.

    The service does NOT persist (no JSONB cache table); the
    contract is "rows in DB → matched provisions in returned dict".
    Mock-only tests of ``mock_db.execute.assert_called`` cannot fail
    on:
    * a regression where the matcher silently drops a CWE ID
      (e.g. case-mismatch on CWE-798 vs cwe-798);
    * a comparison-operator flip on the cross-project filter;
    * a status transition where ``open`` findings stop being counted
      as ``fail``.
    """

    @pytest.mark.asyncio
    async def test_generates_provisions_with_correct_status_counts(self):
        async with make_live_db() as db:
            project_a = Project(id=uuid.uuid4(), name="canary-a", status="ready")
            project_b = Project(id=uuid.uuid4(), name="canary-b", status="ready")
            db.add_all([project_a, project_b])
            await db.flush()

            firmware_a = Firmware(
                id=uuid.uuid4(), project_id=project_a.id, sha256="a" * 64,
            )
            firmware_b_in_a = Firmware(
                id=uuid.uuid4(), project_id=project_a.id, sha256="b" * 64,
            )
            firmware_other_project = Firmware(
                id=uuid.uuid4(), project_id=project_b.id, sha256="c" * 64,
            )
            db.add_all([firmware_a, firmware_b_in_a, firmware_other_project])
            await db.flush()

            # Finding 1: matches provision 1 (default-passwords) via title.
            f1 = Finding(
                id=uuid.uuid4(), project_id=project_a.id, firmware_id=firmware_a.id,
                title="Hardcoded admin password in /etc/shadow",
                severity="high", status="open", source="manual",
                cwe_ids=["CWE-798"],
            )
            # Finding 2: matches provision 2 (vulns) via source-tool name.
            f2 = Finding(
                id=uuid.uuid4(), project_id=project_a.id, firmware_id=firmware_a.id,
                title="Unrelated text",
                severity="medium", status="fixed", source="run_vulnerability_scan",
            )
            # Finding 3: matches provision 5 (communicate securely) via CWE-319.
            f3 = Finding(
                id=uuid.uuid4(), project_id=project_a.id, firmware_id=firmware_b_in_a.id,
                title="Telnet enabled on boot", severity="high", status="open",
                source="manual", cwe_ids=["CWE-319"],
            )
            # Finding 4: cross-project leak canary — belongs to project B,
            # MUST NOT appear in project A's report.
            f4 = Finding(
                id=uuid.uuid4(), project_id=project_b.id,
                firmware_id=firmware_other_project.id,
                title="Hardcoded password — different project",
                severity="high", status="open", source="manual",
                cwe_ids=["CWE-798"],
            )
            db.add_all([f1, f2, f3, f4])
            await db.flush()
            await db.commit()

            service = ETSIComplianceService(db=db)
            report = await service.generate_report(project_id=project_a.id)

            # Top-level shape.
            assert report["standard"] == "ETSI EN 303 645"
            assert report["standard_version"] == "V2.1.1 (2020-06)"
            assert report["summary"]["total"] == 13
            # 13 provisions covered = pass + fail + partial + not_tested.
            assert (
                report["summary"]["pass"]
                + report["summary"]["fail"]
                + report["summary"]["partial"]
                + report["summary"]["not_tested"]
            ) == 13

            # Provisions list has 13 entries in order 1..13.
            assert len(report["provisions"]) == 13
            assert [p["provision"] for p in report["provisions"]] == list(range(1, 14))

            by_provision = {p["provision"]: p for p in report["provisions"]}

            # Provision 1: f1 matched (open) → fail.
            p1 = by_provision[1]
            assert p1["status"] == "fail"
            assert p1["finding_count"] == 1
            assert str(f1.id) in {x["id"] for x in p1["findings"]}
            # Cross-project canary: f4 is NOT in project A's provision 1.
            assert str(f4.id) not in {x["id"] for x in p1["findings"]}

            # Provision 2: f2 matched (fixed) → pass (all findings resolved).
            p2 = by_provision[2]
            assert p2["finding_count"] == 1
            assert p2["status"] == "pass"
            assert str(f2.id) in {x["id"] for x in p2["findings"]}

            # Provision 5: f3 matched via CWE-319 (open) → fail.
            p5 = by_provision[5]
            assert p5["finding_count"] == 1
            assert p5["status"] == "fail"
            assert str(f3.id) in {x["id"] for x in p5["findings"]}

            # Not-automatable provisions (9, 10, 11, 12) report not_tested
            # since none of the four findings can match an empty pattern set.
            for n in (9, 10, 11, 12):
                prov = by_provision[n]
                assert prov["status"] == "not_tested"
                assert "note" in prov
                assert "runtime or manual assessment" in prov["note"]

    @pytest.mark.asyncio
    async def test_firmware_id_filter_restricts_findings(self):
        """When ``firmware_id`` is supplied, the report only counts
        findings on that firmware. Regression where the filter compared
        ``firmware_id is None`` would silently leak ALL of project's
        findings — canary catches it."""
        async with make_live_db() as db:
            project = Project(id=uuid.uuid4(), name="firmware-filter-canary", status="ready")
            db.add(project)
            await db.flush()

            fw1 = Firmware(id=uuid.uuid4(), project_id=project.id, sha256="1" * 64)
            fw2 = Firmware(id=uuid.uuid4(), project_id=project.id, sha256="2" * 64)
            db.add_all([fw1, fw2])
            await db.flush()

            f1 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=fw1.id,
                title="Hardcoded password in fw1", severity="high",
                status="open", source="manual", cwe_ids=["CWE-798"],
            )
            f2 = Finding(
                id=uuid.uuid4(), project_id=project.id, firmware_id=fw2.id,
                title="Hardcoded password in fw2", severity="high",
                status="open", source="manual", cwe_ids=["CWE-798"],
            )
            db.add_all([f1, f2])
            await db.flush()
            await db.commit()

            # Without filter: both findings match provision 1.
            service = ETSIComplianceService(db=db)
            full_report = await service.generate_report(project_id=project.id)
            full_p1 = next(p for p in full_report["provisions"] if p["provision"] == 1)
            assert full_p1["finding_count"] == 2
            assert {x["id"] for x in full_p1["findings"]} == {str(f1.id), str(f2.id)}

            # With firmware_id=fw1: only f1 should appear.
            filtered_report = await service.generate_report(
                project_id=project.id, firmware_id=fw1.id,
            )
            filtered_p1 = next(
                p for p in filtered_report["provisions"] if p["provision"] == 1
            )
            assert filtered_p1["finding_count"] == 1
            assert {x["id"] for x in filtered_p1["findings"]} == {str(f1.id)}

    @pytest.mark.asyncio
    async def test_empty_project_yields_pass_for_pattern_provisions(self):
        """A project with NO findings yields ``pass`` for every provision
        that has patterns (we looked, found nothing) and ``not_tested``
        for the four not_automatable provisions."""
        async with make_live_db() as db:
            project = Project(id=uuid.uuid4(), name="empty-canary", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            service = ETSIComplianceService(db=db)
            report = await service.generate_report(project_id=project.id)

            assert report["summary"]["pass"] == 9  # provisions 1-8 + 13
            assert report["summary"]["not_tested"] == 4  # 9/10/11/12
            assert report["summary"]["fail"] == 0
            assert report["summary"]["partial"] == 0

            for prov in report["provisions"]:
                assert prov["finding_count"] == 0
                assert prov["findings"] == []

    @pytest.mark.asyncio
    async def test_findings_ordered_by_created_at_desc(self):
        """The query orders findings by created_at DESC; the most recent
        match is first in the returned list."""
        async with make_live_db() as db:
            project = Project(id=uuid.uuid4(), name="order-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(id=uuid.uuid4(), project_id=project.id, sha256="o" * 64)
            db.add(firmware)
            await db.flush()

            from datetime import datetime, timezone, timedelta
            t0 = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

            # Add 3 findings, oldest first; created_at increases.
            for i, t in enumerate([t0, t0 + timedelta(hours=1), t0 + timedelta(hours=2)]):
                f = Finding(
                    id=uuid.uuid4(), project_id=project.id, firmware_id=firmware.id,
                    title=f"Hardcoded password #{i}", severity="medium",
                    status="open", source="manual", cwe_ids=["CWE-798"],
                    created_at=t,
                )
                db.add(f)
            await db.flush()
            await db.commit()

            service = ETSIComplianceService(db=db)
            report = await service.generate_report(project_id=project.id)
            p1 = next(p for p in report["provisions"] if p["provision"] == 1)
            titles = [x["title"] for x in p1["findings"]]
            # Order DESC by created_at: #2 first, then #1, then #0.
            assert titles == [
                "Hardcoded password #2",
                "Hardcoded password #1",
                "Hardcoded password #0",
            ]
