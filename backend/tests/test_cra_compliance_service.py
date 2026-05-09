"""Service-layer tests for ``app.services.cra_compliance_service``.

Phase 2 Wave 1 file 3 of 5 — backfills service-layer tests for the CRA
(EU Cyber Resilience Act) compliance assessment surface (839 LOC, 7
public methods + 7 internal helpers). The service is heavily stateful
— assessments persist 21 rows (1 CraAssessment + 20 CraRequirementResult
per the CRA_REQUIREMENTS list), auto-population mutates them in place,
manual updates recalculate summary counts, and exports walk the eager-
loaded relationship.

This test file uses ``tests._live_db.make_live_db`` for ALL tests rather
than only the canary — every method touches DB state, so a real SQLite
session catches value-flow regressions across the entire service. The
``CRAComplianceService.create_assessment`` constructor maps ``status``,
``finding_ids``, ``tool_sources``, ``related_cwes``, ``related_cves`` etc.
on each CraRequirementResult; ``auto_populate`` then maps ``status``,
``auto_populated``, ``evidence_summary``, ``finding_ids``, ``tool_sources``,
``related_cves``, ``assessed_at``. Mock-only tests would assert
``db.add.call_count == 21`` and pass while a constructor silently dropped
``annex_part`` (the F-A-06 confidence-bypass shape this file backstops).

Coverage targets:

* ``create_assessment``       — 1 + 20 row creation; auto_pass_count=0;
  not_tested_count=20; finding_ids/tool_sources init as empty lists.
* ``get_assessment``          — None for missing; eager-loaded results.
* ``list_assessments``        — order_by(created_at desc); empty list path.
* ``auto_populate``           — high-severity → fail; low-severity → partial;
  no findings → pass; not_automatable → not_tested; unknown assessment raises.
* ``update_requirement``      — status update + recalculation; unknown raises.
* ``export_checklist``        — splits part1 (13) / part2 (7); includes
  metadata + product fields.
* ``export_article14_notification`` — CVE metadata + affected_components +
  related_findings populated.
* ``_match_findings`` / ``_finding_matches`` — match-by-source, match-by-
  title-pattern, match-by-cwe-intersection, no-match path.
* ``_determine_status``       — high→fail; low→partial; empty+patterns→pass;
  not_automatable→not_tested; empty+no-patterns→not_tested.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

# Importing the model registers the cra_assessments + cra_requirement_results
# tables on Base.metadata so make_live_db's create_all picks them up.
from app.models.cra_compliance import CraAssessment, CraRequirementResult  # noqa: F401
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.cra_compliance_service import (
    CRA_REQUIREMENTS,
    CRAComplianceService,
)
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_project(db, name: str = "cra-test") -> Project:
    pid = uuid.uuid4()
    project = Project(id=pid, name=name, status="ready")
    db.add(project)
    await db.flush()
    return project


async def _seed_firmware(db, project: Project) -> Firmware:
    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="f" * 64,
        extracted_path="/tmp/x",
        extraction_dir="/tmp/x",
    )
    db.add(firmware)
    await db.flush()
    return firmware


def _make_finding(
    project_id: uuid.UUID,
    *,
    title: str,
    severity: str = "high",
    source: str = "security_audit",
    cwe_ids: list[str] | None = None,
    firmware_id: uuid.UUID | None = None,
) -> Finding:
    return Finding(
        project_id=project_id,
        firmware_id=firmware_id,
        title=title,
        severity=severity,
        source=source,
        confidence="high",
        cwe_ids=cwe_ids or [],
    )


# ===========================================================================
# create_assessment — 21-row initial state
# ===========================================================================


class TestCreateAssessment:
    @pytest.mark.asyncio
    async def test_creates_one_assessment_and_twenty_requirement_rows(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)

            assessment = await svc.create_assessment(
                project_id=project.id,
                product_name="Wairz Test Product",
                product_version="1.0",
                assessor_name="Engineering Team",
            )

            # The assessment row landed.
            assert assessment is not None
            assert assessment.project_id == project.id
            assert assessment.product_name == "Wairz Test Product"
            assert assessment.product_version == "1.0"
            assert assessment.assessor_name == "Engineering Team"
            assert assessment.not_tested_count == len(CRA_REQUIREMENTS) == 20
            assert assessment.auto_pass_count == 0
            assert assessment.auto_fail_count == 0

            # Real SELECT: 20 CraRequirementResult rows persisted.
            persisted_results = (
                await db.execute(
                    select(CraRequirementResult)
                    .where(CraRequirementResult.assessment_id == assessment.id)
                )
            ).scalars().all()
            assert len(persisted_results) == 20, (
                f"Rule #35b: expected 20 requirement rows, got {len(persisted_results)}"
            )

            # Every row has the canonical initial state.
            for row in persisted_results:
                assert row.status == "not_tested"
                assert row.auto_populated is False
                assert row.finding_ids == []
                assert row.tool_sources == []
                assert row.related_cves == []
                assert row.annex_part in (1, 2)

            # Annex split mirrors CRA_REQUIREMENTS exactly: 13 part-1 + 7 part-2.
            part1 = sum(1 for r in persisted_results if r.annex_part == 1)
            part2 = sum(1 for r in persisted_results if r.annex_part == 2)
            assert part1 == 13
            assert part2 == 7


# ===========================================================================
# get_assessment + list_assessments
# ===========================================================================


class TestReadOps:
    @pytest.mark.asyncio
    async def test_get_assessment_returns_none_for_unknown(self):
        async with make_live_db() as db:
            svc = CRAComplianceService(db)
            assert await svc.get_assessment(uuid.uuid4()) is None

    @pytest.mark.asyncio
    async def test_get_assessment_eager_loads_results(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            created = await svc.create_assessment(project_id=project.id)

            fetched = await svc.get_assessment(created.id)
            assert fetched is not None
            # Eager-loaded relationship is accessible without a fresh query.
            assert len(fetched.requirement_results) == 20

    @pytest.mark.asyncio
    async def test_list_assessments_returns_empty_for_unknown_project(self):
        async with make_live_db() as db:
            svc = CRAComplianceService(db)
            result = await svc.list_assessments(uuid.uuid4())
            assert result == []

    @pytest.mark.asyncio
    async def test_list_assessments_orders_by_created_at_desc(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)

            first = await svc.create_assessment(
                project_id=project.id, product_name="first",
            )
            second = await svc.create_assessment(
                project_id=project.id, product_name="second",
            )

            # SQLite's server_default=func.now() resolves to the same value
            # when both INSERTs land in the same microsecond. Force a
            # deterministic spread so order_by(created_at desc) has
            # something to actually order on.
            first.created_at = datetime(2026, 1, 1, tzinfo=UTC)
            second.created_at = datetime(2026, 6, 1, tzinfo=UTC)
            await db.flush()

            results = await svc.list_assessments(project.id)
            assert len(results) == 2
            # desc order — second comes first.
            assert results[0].id == second.id
            assert results[1].id == first.id


# ===========================================================================
# auto_populate — match findings → mutate requirement statuses
# ===========================================================================


class TestAutoPopulate:
    @pytest.mark.asyncio
    async def test_high_severity_finding_marks_requirement_fail(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            # CWE-798 is in annex1_part1_1.1's cwe_ids — match by intersection.
            critical_finding = _make_finding(
                project.id,
                title="Hardcoded credential in /etc/init.d/login",
                severity="critical",
                cwe_ids=["CWE-798"],
            )
            db.add(critical_finding)
            await db.flush()

            updated = await svc.auto_populate(assessment.id)

            req_111 = next(
                r for r in updated.requirement_results
                if r.requirement_id == "annex1_part1_1.1"
            )
            assert req_111.status == "fail", (
                "critical finding matching CWE-798 must mark req 1.1 as fail"
            )
            assert req_111.auto_populated is True
            assert req_111.evidence_summary is not None
            assert "Hardcoded credential" in req_111.evidence_summary
            assert str(critical_finding.id) in req_111.finding_ids
            assert updated.auto_fail_count >= 1

    @pytest.mark.asyncio
    async def test_low_severity_finding_marks_requirement_partial(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            low_finding = _make_finding(
                project.id,
                title="Default password considered weak",
                severity="low",
                cwe_ids=["CWE-798"],
            )
            db.add(low_finding)
            await db.flush()

            updated = await svc.auto_populate(assessment.id)

            req_111 = next(
                r for r in updated.requirement_results
                if r.requirement_id == "annex1_part1_1.1"
            )
            assert req_111.status == "partial"

    @pytest.mark.asyncio
    async def test_no_findings_with_patterns_marks_pass(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            # No findings at all. Requirements with title_patterns/tool_sources
            # → "pass". Requirements without any patterns → "not_tested".
            updated = await svc.auto_populate(assessment.id)

            req_111 = next(
                r for r in updated.requirement_results
                if r.requirement_id == "annex1_part1_1.1"
            )
            # 1.1 has patterns AND tool_sources AND cwe_ids → would search → pass.
            assert req_111.status == "pass"
            assert req_111.auto_populated is True
            assert updated.auto_pass_count >= 1

    @pytest.mark.asyncio
    async def test_not_automatable_requirement_stays_not_tested(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            updated = await svc.auto_populate(assessment.id)

            # 1.3 is "Security risk assessment documentation" — not_automatable.
            req_113 = next(
                r for r in updated.requirement_results
                if r.requirement_id == "annex1_part1_1.3"
            )
            assert req_113.status == "not_tested"
            # auto_populated stays False because the not_automatable branch
            # short-circuits BEFORE the auto_populated = True assignment.
            assert req_113.auto_populated is False

    @pytest.mark.asyncio
    async def test_raises_for_missing_assessment(self):
        async with make_live_db() as db:
            svc = CRAComplianceService(db)
            with pytest.raises(ValueError, match="not found"):
                await svc.auto_populate(uuid.uuid4())


# ===========================================================================
# update_requirement — manual entry path
# ===========================================================================


class TestUpdateRequirement:
    @pytest.mark.asyncio
    async def test_updates_status_and_recalculates_summary(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            # Set the not_automatable 1.3 to "pass" manually with notes.
            updated_req = await svc.update_requirement(
                assessment_id=assessment.id,
                requirement_id="annex1_part1_1.3",
                status="pass",
                manual_notes="Risk assessment doc completed 2026-Q2",
                manual_evidence="See ./docs/cra-risk-assessment.pdf",
            )

            assert updated_req.status == "pass"
            assert updated_req.manual_notes == "Risk assessment doc completed 2026-Q2"
            assert updated_req.manual_evidence == "See ./docs/cra-risk-assessment.pdf"
            assert updated_req.assessed_at is not None

            # Summary counts recalculated: 1 pass, 19 not_tested.
            refreshed = await svc.get_assessment(assessment.id)
            assert refreshed.auto_pass_count == 1
            assert refreshed.not_tested_count == 19

    @pytest.mark.asyncio
    async def test_raises_for_unknown_requirement(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(project_id=project.id)

            with pytest.raises(ValueError, match="not found in assessment"):
                await svc.update_requirement(
                    assessment_id=assessment.id,
                    requirement_id="annex1_partX_99",
                    status="pass",
                )


# ===========================================================================
# export_checklist — full structured JSON
# ===========================================================================


class TestExportChecklist:
    @pytest.mark.asyncio
    async def test_includes_part1_part2_split_and_metadata(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(
                project_id=project.id,
                product_name="Test Router",
                product_version="2.5.0",
                assessor_name="Compliance Team",
            )

            doc = await svc.export_checklist(assessment.id)

            assert doc["standard"] == "EU Cyber Resilience Act (CRA)"
            assert doc["regulation"] == "Regulation (EU) 2024/2847"
            assert doc["product"]["name"] == "Test Router"
            assert doc["product"]["version"] == "2.5.0"
            assert doc["assessor"] == "Compliance Team"
            assert doc["summary"]["total_requirements"] == 20

            # Part 1: 13 security requirements.
            assert doc["part1_security_requirements"]["deadline"] == "2027-12-11"
            assert len(doc["part1_security_requirements"]["requirements"]) == 13

            # Part 2: 7 vulnerability handling requirements.
            assert doc["part2_vulnerability_handling"]["deadline"] == "2026-09-11"
            assert len(doc["part2_vulnerability_handling"]["requirements"]) == 7

            # Each entry has the canonical export shape.
            sample = doc["part1_security_requirements"]["requirements"][0]
            assert {
                "requirement_id", "requirement_title", "status",
                "auto_populated", "evidence_summary", "finding_count",
                "finding_ids", "tool_sources", "manual_notes",
                "manual_evidence", "related_cwes", "related_cves",
                "not_automatable", "assessed_at",
            } <= sample.keys()

    @pytest.mark.asyncio
    async def test_raises_for_missing_assessment(self):
        async with make_live_db() as db:
            svc = CRAComplianceService(db)
            with pytest.raises(ValueError, match="not found"):
                await svc.export_checklist(uuid.uuid4())


# ===========================================================================
# export_article14_notification — ENISA notification builder
# ===========================================================================


class TestExportArticle14Notification:
    @pytest.mark.asyncio
    async def test_includes_cve_metadata_and_finding_summaries(self):
        async with make_live_db() as db:
            project = await _seed_project(db)
            firmware = await _seed_firmware(db, project)
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(
                project_id=project.id,
                firmware_id=firmware.id,
                product_name="Test Device",
                product_version="3.1",
                assessor_name="Security Team",
            )

            # Seed a finding referencing the CVE.
            finding = _make_finding(
                project.id,
                title="OpenSSL CVE-2024-0727 found in libcrypto",
                severity="high",
                cwe_ids=["CWE-787"],
                firmware_id=firmware.id,
            )
            finding.cve_ids = ["CVE-2024-0727"]
            finding.file_path = "usr/lib/libcrypto.so.3"
            db.add(finding)
            await db.flush()

            doc = await svc.export_article14_notification(
                assessment_id=assessment.id,
                cve_id="CVE-2024-0727",
            )

            assert doc["notification_type"] == "actively_exploited_vulnerability"
            assert doc["product"]["name"] == "Test Device"
            assert doc["product"]["version"] == "3.1"
            assert doc["vulnerability"]["cve_id"] == "CVE-2024-0727"
            assert len(doc["vulnerability"]["related_findings"]) == 1
            assert doc["vulnerability"]["related_findings"][0]["title"].startswith(
                "OpenSSL CVE-2024-0727"
            )
            assert doc["vulnerability"]["related_findings"][0]["file_path"] == "usr/lib/libcrypto.so.3"

    @pytest.mark.asyncio
    async def test_raises_for_missing_assessment(self):
        async with make_live_db() as db:
            svc = CRAComplianceService(db)
            with pytest.raises(ValueError, match="not found"):
                await svc.export_article14_notification(uuid.uuid4(), "CVE-2024-0001")


# ===========================================================================
# Internal helpers — pure-ish functions (no DB needed for matching logic)
# ===========================================================================


class TestMatchingInternals:
    """``_match_findings`` / ``_finding_matches`` route findings to requirements
    via three independent signals — title regex, source-tool name, CWE
    intersection. Each one needs its own coverage to catch a regression on
    one signal that doesn't break the other two."""

    def _svc(self):
        # No DB needed for these purely-logical helpers; the service stores
        # ``self.db`` but ``_finding_matches`` doesn't touch it.
        return CRAComplianceService(db=None)  # type: ignore[arg-type]

    def test_matches_by_source(self):
        svc = self._svc()
        f = Finding(
            project_id=uuid.uuid4(),
            title="some title",
            severity="medium",
            source="find_hardcoded_credentials",
            confidence="high",
            cwe_ids=[],
        )
        title_patterns = [re.compile(r"unrelated", re.IGNORECASE)]
        source_set = {"find_hardcoded_credentials"}
        cwe_set: set[str] = set()
        assert svc._finding_matches(f, title_patterns, source_set, cwe_set) is True

    def test_matches_by_title_pattern_case_insensitive(self):
        svc = self._svc()
        f = Finding(
            project_id=uuid.uuid4(),
            title="Default Password Detected",
            severity="medium",
            source="some_other_tool",
            confidence="high",
            cwe_ids=[],
        )
        title_patterns = [re.compile(r"default.*password", re.IGNORECASE)]
        source_set: set[str] = set()
        cwe_set: set[str] = set()
        assert svc._finding_matches(f, title_patterns, source_set, cwe_set) is True

    def test_matches_by_cwe_intersection(self):
        svc = self._svc()
        f = Finding(
            project_id=uuid.uuid4(),
            title="some title",
            severity="medium",
            source="some_tool",
            confidence="high",
            cwe_ids=["CWE-798", "CWE-1188"],
        )
        title_patterns: list[re.Pattern] = []
        source_set: set[str] = set()
        cwe_set = {"CWE-798"}
        assert svc._finding_matches(f, title_patterns, source_set, cwe_set) is True

    def test_no_match_returns_false(self):
        svc = self._svc()
        f = Finding(
            project_id=uuid.uuid4(),
            title="totally unrelated finding",
            severity="medium",
            source="some_tool",
            confidence="high",
            cwe_ids=["CWE-999"],
        )
        title_patterns = [re.compile(r"another.*thing", re.IGNORECASE)]
        source_set = {"different_tool"}
        cwe_set = {"CWE-100"}
        assert svc._finding_matches(f, title_patterns, source_set, cwe_set) is False


class TestDetermineStatusInternals:
    def _svc(self):
        return CRAComplianceService(db=None)  # type: ignore[arg-type]

    def test_high_severity_returns_fail(self):
        svc = self._svc()
        finding = Finding(
            project_id=uuid.uuid4(), title="x", severity="critical",
            source="t", confidence="high", cwe_ids=[],
        )
        assert svc._determine_status({}, [finding]) == "fail"

    def test_low_severity_returns_partial(self):
        svc = self._svc()
        finding = Finding(
            project_id=uuid.uuid4(), title="x", severity="low",
            source="t", confidence="high", cwe_ids=[],
        )
        assert svc._determine_status({}, [finding]) == "partial"

    def test_empty_with_patterns_returns_pass(self):
        svc = self._svc()
        req_def = {"title_patterns": [r"x"]}
        assert svc._determine_status(req_def, []) == "pass"

    def test_empty_with_tool_sources_returns_pass(self):
        svc = self._svc()
        req_def = {"tool_sources": ["some_tool"]}
        assert svc._determine_status(req_def, []) == "pass"

    def test_not_automatable_returns_not_tested_even_with_findings(self):
        svc = self._svc()
        finding = Finding(
            project_id=uuid.uuid4(), title="x", severity="critical",
            source="t", confidence="high", cwe_ids=[],
        )
        req_def = {"not_automatable": True}
        assert svc._determine_status(req_def, [finding]) == "not_tested"

    def test_empty_with_no_patterns_returns_not_tested(self):
        svc = self._svc()
        assert svc._determine_status({}, []) == "not_tested"
