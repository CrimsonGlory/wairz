"""EU Cyber Resilience Act (CRA) compliance assessment service.

Maps existing firmware security findings to the 20 CRA Annex I requirements
(13 Part 1 security + 7 Part 2 vulnerability handling) and generates
structured compliance assessments with auto-population from tool findings.
"""

import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.cra_compliance import CraAssessment, CraRequirementResult
from app.models.finding import Finding
from app.models.sbom import SbomVulnerability
from app.services.jsonb_normalizers import (
    _normalize_cra_requirement_results_finding_ids,
    _normalize_cra_requirement_results_related_cves,
    _normalize_cra_requirement_results_related_cwes,
    _normalize_cra_requirement_results_tool_sources,
)

# ---------------------------------------------------------------------------
# CRA Annex I Requirement Definitions
# ---------------------------------------------------------------------------
# Each requirement maps to finding title patterns, tool sources, and CWE IDs.
# "not_automatable" requirements need manual assessment.

CRA_REQUIREMENTS: list[dict] = [
    # --- Part 1: Security Requirements (Dec 2027 deadline) ---
    {
        "requirement_id": "annex1_part1_1.1",
        "requirement_title": "Secure by design, delivered with secure defaults",
        "annex_part": 1,
        "title_patterns": [
            r"default.*password",
            r"hardcoded.*(password|credential)",
            r"debug.*(enabled|interface)",
            r"insecure.*default",
        ],
        "tool_sources": [
            "find_hardcoded_credentials",
            "analyze_config_security",
        ],
        "cwe_ids": ["CWE-798", "CWE-1188", "CWE-1394"],
    },
    {
        "requirement_id": "annex1_part1_1.2",
        "requirement_title": "No known exploitable vulnerabilities",
        "annex_part": 1,
        "title_patterns": [
            r"known.*cve",
            r"vulnerability",
            r"unpatched",
            r"cwe.*checker",
        ],
        "tool_sources": [
            "run_vulnerability_scan",
            "check_known_cves",
            "cwe_check_binary",
        ],
        "cwe_ids": ["CWE-1104", "CWE-937"],
    },
    {
        "requirement_id": "annex1_part1_1.3",
        "requirement_title": "Security risk assessment documentation",
        "annex_part": 1,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part1_1.4",
        "requirement_title": "SBOM (machine-readable)",
        "annex_part": 1,
        "title_patterns": [
            r"sbom",
            r"software.*bill",
            r"component.*inventory",
        ],
        "tool_sources": [
            "generate_sbom",
            "get_sbom_components",
        ],
        "cwe_ids": [],
    },
    {
        "requirement_id": "annex1_part1_1.5",
        "requirement_title": "Address vulnerabilities without delay",
        "annex_part": 1,
        "title_patterns": [
            r"vulnerability.*disclosure",
            r"vex",
            r"triage",
        ],
        "tool_sources": [
            "run_vulnerability_scan",
        ],
        "cwe_ids": [],
    },
    {
        "requirement_id": "annex1_part1_1.6",
        "requirement_title": "Secure update mechanism",
        "annex_part": 1,
        "title_patterns": [
            r"update.*mechanism",
            r"firmware.*update",
            r"no.*update",
            r"http.*update",
            r"insecure.*update",
            r"no.*rollback",
        ],
        "tool_sources": [
            "detect_update_mechanisms",
            "check_secure_boot",
        ],
        "cwe_ids": ["CWE-494", "CWE-319", "CWE-1277"],
    },
    {
        "requirement_id": "annex1_part1_1.7",
        "requirement_title": "Data confidentiality",
        "annex_part": 1,
        "title_patterns": [
            r"certificate",
            r"crypto",
            r"encryption",
            r"plaintext.*protocol",
            r"private.*key",
        ],
        "tool_sources": [
            "analyze_certificate",
            "find_crypto_material",
        ],
        "cwe_ids": ["CWE-312", "CWE-319", "CWE-326"],
    },
    {
        "requirement_id": "annex1_part1_1.8",
        "requirement_title": "Data integrity",
        "annex_part": 1,
        "title_patterns": [
            r"secure.*boot",
            r"unsigned",
            r"integrity",
            r"code.*signing",
        ],
        "tool_sources": [
            "check_secure_boot",
            "check_binary_protections",
        ],
        "cwe_ids": ["CWE-345", "CWE-353"],
    },
    {
        "requirement_id": "annex1_part1_1.9",
        "requirement_title": "Minimize data processing",
        "annex_part": 1,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part1_1.10",
        "requirement_title": "Availability and resilience",
        "annex_part": 1,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part1_1.11",
        "requirement_title": "Minimize attack surface",
        "annex_part": 1,
        "title_patterns": [
            r"attack.*surface",
            r"setuid",
            r"world.*writable",
            r"unnecessary.*service",
            r"open.*port",
        ],
        "tool_sources": [
            "check_setuid_binaries",
            "check_filesystem_permissions",
            "analyze_attack_surface",
        ],
        "cwe_ids": ["CWE-250", "CWE-732"],
    },
    {
        "requirement_id": "annex1_part1_1.12",
        "requirement_title": "Mitigate impact of incidents",
        "annex_part": 1,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part1_1.13",
        "requirement_title": "Logging and monitoring",
        "annex_part": 1,
        "title_patterns": [
            r"syslog",
            r"logging",
            r"audit.*log",
        ],
        "tool_sources": [
            "analyze_init_scripts",
        ],
        "cwe_ids": [],
    },
    # --- Part 2: Vulnerability Handling (Sep 2026 deadline) ---
    {
        "requirement_id": "annex1_part2_2.1",
        "requirement_title": "Identify and document vulnerabilities",
        "annex_part": 2,
        "title_patterns": [
            r"known.*cve",
            r"vulnerability",
            r"unpatched",
            r"cwe.*checker",
        ],
        "tool_sources": [
            "run_vulnerability_scan",
            "check_known_cves",
        ],
        "cwe_ids": ["CWE-1104"],
    },
    {
        "requirement_id": "annex1_part2_2.2",
        "requirement_title": "Address vulnerabilities timely",
        "annex_part": 2,
        "title_patterns": [
            r"vulnerability.*disclosure",
            r"unpatched",
            r"outdated",
        ],
        "tool_sources": [
            "run_vulnerability_scan",
        ],
        "cwe_ids": [],
    },
    {
        "requirement_id": "annex1_part2_2.3",
        "requirement_title": "Effective security testing",
        "annex_part": 2,
        "title_patterns": [
            r"sast",
            r"shellcheck",
            r"bandit",
            r"fuzzing",
            r"static.*analysis",
        ],
        "tool_sources": [
            "scan_scripts",
            "run_shellcheck",
            "run_bandit",
        ],
        "cwe_ids": [],
    },
    {
        "requirement_id": "annex1_part2_2.4",
        "requirement_title": "Vulnerability disclosure policy",
        "annex_part": 2,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part2_2.5",
        "requirement_title": "Share info about vulnerabilities",
        "annex_part": 2,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part2_2.6",
        "requirement_title": "Vulnerability notification to authorities",
        "annex_part": 2,
        "title_patterns": [],
        "tool_sources": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    {
        "requirement_id": "annex1_part2_2.7",
        "requirement_title": "SBOM available to authorities",
        "annex_part": 2,
        "title_patterns": [
            r"sbom",
            r"software.*bill",
            r"component.*inventory",
        ],
        "tool_sources": [
            "generate_sbom",
            "get_sbom_components",
        ],
        "cwe_ids": [],
    },
]


class CRAComplianceService:
    """Generate and manage CRA Annex I compliance assessments.

    Assessments are persistent (DB-backed) and support both automatic
    population from existing findings and manual entry for requirements
    that cannot be automated.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_assessment(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID | None = None,
        product_name: str | None = None,
        product_version: str | None = None,
        assessor_name: str | None = None,
    ) -> CraAssessment:
        """Create a new CRA assessment and initialize all 20 requirement rows."""
        assessment = CraAssessment(
            project_id=project_id,
            firmware_id=firmware_id,
            product_name=product_name,
            product_version=product_version,
            assessor_name=assessor_name,
            not_tested_count=len(CRA_REQUIREMENTS),
        )
        self.db.add(assessment)
        await self.db.flush()  # get the assessment.id

        # Create one result row per requirement
        for req_def in CRA_REQUIREMENTS:
            result = CraRequirementResult(
                assessment_id=assessment.id,
                requirement_id=req_def["requirement_id"],
                requirement_title=req_def["requirement_title"],
                annex_part=req_def["annex_part"],
                status="not_tested",
                auto_populated=False,
                finding_ids=[],
                tool_sources=[],
                related_cwes=req_def.get("cwe_ids", []),
                related_cves=[],
            )
            self.db.add(result)

        await self.db.flush()
        await self.db.refresh(assessment)

        # Re-fetch with eager-loaded results
        return await self.get_assessment(assessment.id)  # type: ignore[return-value]

    async def get_assessment(self, assessment_id: uuid.UUID) -> CraAssessment | None:
        """Get an assessment with all requirement results eagerly loaded."""
        stmt = (
            select(CraAssessment)
            .where(CraAssessment.id == assessment_id)
            .options(selectinload(CraAssessment.requirement_results))
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_assessments(self, project_id: uuid.UUID) -> list[CraAssessment]:
        """List assessments for a project (without requirement details)."""
        stmt = (
            select(CraAssessment)
            .where(CraAssessment.project_id == project_id)
            .order_by(CraAssessment.created_at.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Auto-population
    # ------------------------------------------------------------------

    async def auto_populate(self, assessment_id: uuid.UUID) -> CraAssessment:
        """Run auto-population by matching project findings to CRA requirements.

        For each requirement with defined patterns:
        1. Query findings matching title_patterns, cwe_ids, or tool_sources
        2. Determine status based on finding severity:
           - Matching findings with severity >= high: "fail"
           - Matching findings with severity < high: "partial"
           - No matching findings but tool_sources exist: "pass"
           - not_automatable: left as "not_tested"
        3. Update evidence, finding_ids, tool_sources, counts
        """
        assessment = await self.get_assessment(assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment {assessment_id} not found")

        # Load all findings for the project
        stmt = select(Finding).where(Finding.project_id == assessment.project_id)
        if assessment.firmware_id:
            stmt = stmt.where(Finding.firmware_id == assessment.firmware_id)
        stmt = stmt.order_by(Finding.created_at.desc())

        result = await self.db.execute(stmt)
        findings = list(result.scalars().all())

        # Build a lookup from requirement_id -> definition
        req_defs = {r["requirement_id"]: r for r in CRA_REQUIREMENTS}

        # Counters for the summary
        pass_count = 0
        fail_count = 0
        manual_count = 0
        not_tested_count = 0

        for req_result in assessment.requirement_results:
            req_def = req_defs.get(req_result.requirement_id)
            if req_def is None:
                not_tested_count += 1
                continue

            is_not_automatable = req_def.get("not_automatable", False)

            if is_not_automatable:
                # Don't overwrite manual entries
                if req_result.status not in ("not_tested",):
                    # User already set something manually — count appropriately
                    if req_result.status == "pass":
                        pass_count += 1
                    elif req_result.status == "fail":
                        fail_count += 1
                    elif req_result.status in ("partial", "not_applicable"):
                        manual_count += 1
                    else:
                        not_tested_count += 1
                else:
                    not_tested_count += 1
                continue

            # Match findings to this requirement
            matched = self._match_findings(findings, req_def)
            matched_ids = [str(f.id) for f in matched]
            matched_sources = self._extract_sources(matched, req_def)
            matched_cves = self._extract_cves(matched)

            # Determine status
            status = self._determine_status(req_def, matched)

            # Build evidence summary
            evidence = self._build_evidence_summary(matched)

            # Update the requirement result
            req_result.status = status
            req_result.auto_populated = True
            req_result.evidence_summary = evidence
            req_result.finding_ids = _normalize_cra_requirement_results_finding_ids(matched_ids)
            req_result.tool_sources = _normalize_cra_requirement_results_tool_sources(matched_sources)
            req_result.related_cves = _normalize_cra_requirement_results_related_cves(matched_cves)
            req_result.assessed_at = datetime.now(timezone.utc)

            # Count
            if status == "pass":
                pass_count += 1
            elif status == "fail":
                fail_count += 1
            elif status == "partial":
                manual_count += 1
            else:
                not_tested_count += 1

        # Update assessment summary
        assessment.auto_pass_count = pass_count
        assessment.auto_fail_count = fail_count
        assessment.manual_count = manual_count
        assessment.not_tested_count = not_tested_count

        await self.db.flush()
        return await self.get_assessment(assessment_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Manual requirement update
    # ------------------------------------------------------------------

    async def update_requirement(
        self,
        assessment_id: uuid.UUID,
        requirement_id: str,
        status: str | None = None,
        manual_notes: str | None = None,
        manual_evidence: str | None = None,
    ) -> CraRequirementResult:
        """Update a single requirement result (manual entry)."""
        stmt = (
            select(CraRequirementResult)
            .where(CraRequirementResult.assessment_id == assessment_id)
            .where(CraRequirementResult.requirement_id == requirement_id)
        )
        result = await self.db.execute(stmt)
        req_result = result.scalar_one_or_none()
        if req_result is None:
            raise ValueError(
                f"Requirement {requirement_id} not found in assessment {assessment_id}"
            )

        if status is not None:
            req_result.status = status
        if manual_notes is not None:
            req_result.manual_notes = manual_notes
        if manual_evidence is not None:
            req_result.manual_evidence = manual_evidence
        req_result.assessed_at = datetime.now(timezone.utc)

        await self.db.flush()
        await self.db.refresh(req_result)

        # Recalculate assessment summary counts
        await self._recalculate_counts(assessment_id)

        return req_result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    async def export_checklist(self, assessment_id: uuid.UUID) -> dict:
        """Export the full CRA checklist as structured JSON."""
        assessment = await self.get_assessment(assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment {assessment_id} not found")

        req_defs = {r["requirement_id"]: r for r in CRA_REQUIREMENTS}

        part1_results = []
        part2_results = []

        for req_result in assessment.requirement_results:
            req_def = req_defs.get(req_result.requirement_id, {})
            entry = {
                "requirement_id": req_result.requirement_id,
                "requirement_title": req_result.requirement_title,
                "status": req_result.status,
                "auto_populated": req_result.auto_populated,
                "evidence_summary": req_result.evidence_summary,
                "finding_count": len(_normalize_cra_requirement_results_finding_ids(req_result.finding_ids)),
                "finding_ids": _normalize_cra_requirement_results_finding_ids(req_result.finding_ids),
                "tool_sources": _normalize_cra_requirement_results_tool_sources(req_result.tool_sources),
                "manual_notes": req_result.manual_notes,
                "manual_evidence": req_result.manual_evidence,
                "related_cwes": _normalize_cra_requirement_results_related_cwes(req_result.related_cwes),
                "related_cves": _normalize_cra_requirement_results_related_cves(req_result.related_cves),
                "not_automatable": req_def.get("not_automatable", False),
                "assessed_at": (
                    req_result.assessed_at.isoformat()
                    if req_result.assessed_at
                    else None
                ),
            }
            if req_result.annex_part == 1:
                part1_results.append(entry)
            else:
                part2_results.append(entry)

        return {
            "standard": "EU Cyber Resilience Act (CRA)",
            "regulation": "Regulation (EU) 2024/2847",
            "annex": "Annex I — Essential Cybersecurity Requirements",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessment_id": str(assessment.id),
            "product": {
                "name": assessment.product_name,
                "version": assessment.product_version,
            },
            "assessor": assessment.assessor_name,
            "overall_status": assessment.overall_status,
            "summary": {
                "total_requirements": len(CRA_REQUIREMENTS),
                "pass": assessment.auto_pass_count,
                "fail": assessment.auto_fail_count,
                "manual_review": assessment.manual_count,
                "not_tested": assessment.not_tested_count,
            },
            "part1_security_requirements": {
                "title": "Part I — Security Requirements for Products with Digital Elements",
                "deadline": "2027-12-11",
                "requirements": part1_results,
            },
            "part2_vulnerability_handling": {
                "title": "Part II — Vulnerability Handling Requirements",
                "deadline": "2026-09-11",
                "requirements": part2_results,
            },
        }

    async def export_article14_notification(
        self,
        assessment_id: uuid.UUID,
        cve_id: str,
    ) -> dict:
        """Generate an Article 14 ENISA notification for a specific CVE.

        Article 14 requires manufacturers to notify ENISA within 24 hours
        of becoming aware of an actively exploited vulnerability.

        Queries SBOM vulnerabilities and findings for the given CVE and
        returns a structured notification document.
        """
        assessment = await self.get_assessment(assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment {assessment_id} not found")

        # Find SBOM vulnerabilities matching this CVE
        vuln_stmt = select(SbomVulnerability).where(
            SbomVulnerability.cve_id == cve_id
        )
        if assessment.firmware_id:
            vuln_stmt = vuln_stmt.where(
                SbomVulnerability.firmware_id == assessment.firmware_id
            )
        vuln_result = await self.db.execute(vuln_stmt)
        vulns = list(vuln_result.scalars().all())

        # Find related findings
        finding_stmt = select(Finding).where(
            Finding.project_id == assessment.project_id
        )
        finding_result = await self.db.execute(finding_stmt)
        all_findings = list(finding_result.scalars().all())

        # Filter findings that reference this CVE
        cve_findings = [
            f for f in all_findings
            if f.cve_ids and cve_id in f.cve_ids
        ]

        # Build affected components list
        affected_components = []
        severity = "unknown"
        description = f"Vulnerability {cve_id}"

        for vuln in vulns:
            if vuln.severity:
                severity = vuln.severity
            if vuln.description:
                description = vuln.description
            affected_components.append({
                "component_id": str(vuln.component_id),
                "cvss_score": float(vuln.cvss_score) if vuln.cvss_score else None,
                "cvss_vector": vuln.cvss_vector,
            })

        # Build finding summaries
        finding_summaries = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
            }
            for f in cve_findings
        ]

        now = datetime.now(timezone.utc)

        return {
            "notification_type": "actively_exploited_vulnerability",
            "article": "Article 14 — Reporting obligations of manufacturers",
            "regulation": "Regulation (EU) 2024/2847",
            "product": {
                "name": assessment.product_name or "Unknown Product",
                "version": assessment.product_version or "Unknown Version",
                "sbom_ref": f"assessment:{assessment.id}",
            },
            "vulnerability": {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "affected_components": affected_components,
                "related_findings": finding_summaries,
            },
            "timeline": {
                "discovered_at": now.isoformat(),
                "notification_deadline": "24h from discovery",
                "full_notification_deadline": "72h from discovery",
                "remediation_eta": None,
            },
            "mitigation": {
                "temporary": None,
                "planned_fix": None,
            },
            "contact": {
                "csirt": "ENISA (eu-cert@cert.europa.eu)",
                "manufacturer": assessment.assessor_name,
            },
            "generated_at": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_findings(
        self, findings: list[Finding], req_def: dict
    ) -> list[Finding]:
        """Find all findings that match a requirement's patterns."""
        title_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in req_def.get("title_patterns", [])
        ]
        source_set = set(req_def.get("tool_sources", []))
        cwe_set = set(req_def.get("cwe_ids", []))

        matched: list[Finding] = []
        for finding in findings:
            if self._finding_matches(finding, title_patterns, source_set, cwe_set):
                matched.append(finding)
        return matched

    def _finding_matches(
        self,
        finding: Finding,
        title_patterns: list[re.Pattern],
        source_set: set[str],
        cwe_set: set[str],
    ) -> bool:
        """Check if a single finding matches any requirement patterns."""
        # Match by source tool name
        if finding.source and finding.source in source_set:
            return True

        # Match by title pattern
        title = finding.title or ""
        for pattern in title_patterns:
            if pattern.search(title):
                return True

        # Match by CWE ID intersection
        if finding.cwe_ids and cwe_set:
            if cwe_set.intersection(finding.cwe_ids):
                return True

        return False

    def _determine_status(
        self, req_def: dict, matched_findings: list[Finding]
    ) -> str:
        """Determine requirement status based on matched findings.

        - Matching findings with severity >= high: "fail"
        - Matching findings with severity < high: "partial"
        - No matching findings and tool_sources exist: "pass"
        - not_automatable: "not_tested"
        """
        if req_def.get("not_automatable"):
            return "not_tested"

        if not matched_findings:
            # No issues found — if we had patterns to search with, that's a pass
            has_patterns = (
                req_def.get("title_patterns")
                or req_def.get("tool_sources")
                or req_def.get("cwe_ids")
            )
            return "pass" if has_patterns else "not_tested"

        # Check severity of matched findings
        high_sev = {"critical", "high"}
        has_high = any(
            (f.severity or "").lower() in high_sev
            for f in matched_findings
        )
        return "fail" if has_high else "partial"

    def _extract_sources(
        self, matched_findings: list[Finding], req_def: dict
    ) -> list[str]:
        """Extract unique tool sources from matched findings."""
        tool_sources = set(req_def.get("tool_sources", []))
        found_sources: set[str] = set()
        for finding in matched_findings:
            if finding.source and finding.source in tool_sources:
                found_sources.add(finding.source)
        return sorted(found_sources)

    def _extract_cves(self, matched_findings: list[Finding]) -> list[str]:
        """Extract unique CVE IDs from matched findings."""
        cves: set[str] = set()
        for finding in matched_findings:
            if finding.cve_ids:
                cves.update(finding.cve_ids)
        return sorted(cves)

    def _build_evidence_summary(self, matched_findings: list[Finding]) -> str:
        """Build a human-readable evidence summary from matched findings."""
        if not matched_findings:
            return "No relevant findings detected by automated tools."

        lines = [f"Found {len(matched_findings)} relevant finding(s):"]
        for f in matched_findings[:15]:  # Cap at 15 per requirement
            severity = (f.severity or "unknown").upper()
            lines.append(f"  - [{severity}] {f.title}")
        if len(matched_findings) > 15:
            lines.append(f"  ... and {len(matched_findings) - 15} more")
        return "\n".join(lines)

    async def _recalculate_counts(self, assessment_id: uuid.UUID) -> None:
        """Recalculate and update assessment summary counts."""
        assessment = await self.get_assessment(assessment_id)
        if assessment is None:
            return

        pass_count = 0
        fail_count = 0
        manual_count = 0
        not_tested_count = 0

        for req in assessment.requirement_results:
            if req.status == "pass":
                pass_count += 1
            elif req.status == "fail":
                fail_count += 1
            elif req.status in ("partial", "not_applicable"):
                manual_count += 1
            else:
                not_tested_count += 1

        assessment.auto_pass_count = pass_count
        assessment.auto_fail_count = fail_count
        assessment.manual_count = manual_count
        assessment.not_tested_count = not_tested_count

        await self.db.flush()
