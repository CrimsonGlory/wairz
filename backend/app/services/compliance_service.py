"""ETSI EN 303 645 compliance assessment service.

Maps existing firmware security findings to the 13 ETSI provisions for
consumer IoT cybersecurity and generates a structured compliance report.
"""

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding

# ---------------------------------------------------------------------------
# ETSI EN 303 645 provision definitions and finding-matching patterns
# ---------------------------------------------------------------------------

# Each provision maps to patterns that match finding titles, sources, and
# CWE IDs.  A finding that matches any pattern is linked to that provision.

ETSI_PROVISIONS: dict[int, dict] = {
    1: {
        "id": "5.1",
        "name": "No universal default passwords",
        "description": (
            "Where passwords are used and in any state other than the "
            "factory default, all consumer IoT device passwords shall be "
            "unique per device or defined by the user."
        ),
        "title_patterns": [
            r"default.password",
            r"hardcoded.*(password|credential|secret)",
            r"weak.password",
            r"empty.password",
            r"universal.password",
            r"factory.default",
        ],
        "source_patterns": [
            "find_hardcoded_credentials",
            "analyze_config_security",
        ],
        "cwe_ids": ["CWE-798", "CWE-259", "CWE-521", "CWE-1392"],
    },
    2: {
        "id": "5.2",
        "name": "Implement a means to manage reports of vulnerabilities",
        "description": (
            "The manufacturer shall make a vulnerability disclosure policy "
            "publicly available and act on vulnerabilities in a timely manner."
        ),
        "title_patterns": [
            r"known.cve",
            r"vulnerability",
            r"unpatched",
            r"outdated.*(component|software|library|version)",
            r"end.of.life",
        ],
        "source_patterns": [
            "run_vulnerability_scan",
            "check_known_cves",
            "check_component_cves",
        ],
        "cwe_ids": ["CWE-1104", "CWE-937"],
    },
    3: {
        "id": "5.3",
        "name": "Keep software updated",
        "description": (
            "Software components in consumer IoT devices should be "
            "securely updateable."
        ),
        "title_patterns": [
            r"update.mechanism",
            r"firmware.update",
            r"ota.update",
            r"software.update",
            r"insecure.update",
            r"unsigned.update",
        ],
        "source_patterns": [
            "generate_sbom",
            "scan_with_yara",
        ],
        "cwe_ids": ["CWE-494"],
    },
    4: {
        "id": "5.4",
        "name": "Securely store sensitive security parameters",
        "description": (
            "Sensitive security parameters in persistent storage shall "
            "be stored securely by the device."
        ),
        "title_patterns": [
            r"hardcoded.*(key|credential|secret|token|password)",
            r"plaintext.*(key|credential|secret|token|password)",
            r"exposed.*(key|credential|secret|token)",
            r"private.key",
            r"crypto.material",
            r"embedded.*(key|secret)",
            r"insecure.*storage",
        ],
        "source_patterns": [
            "find_hardcoded_credentials",
            "find_crypto_material",
            "analyze_certificate",
        ],
        "cwe_ids": ["CWE-312", "CWE-321", "CWE-798", "CWE-922"],
    },
    5: {
        "id": "5.5",
        "name": "Communicate securely",
        "description": (
            "The consumer IoT device shall use best practice cryptography "
            "to communicate securely."
        ),
        "title_patterns": [
            r"(weak|expired|self.signed).cert",
            r"(weak|insecure).*(cipher|crypto|tls|ssl|encryption|algorithm)",
            r"plaintext.*(protocol|communication|http|ftp|telnet)",
            r"telnet",
            r"unencrypted",
            r"md5|sha.?1",
            r"missing.tls",
        ],
        "source_patterns": [
            "analyze_certificate",
            "analyze_init_scripts",
        ],
        "cwe_ids": ["CWE-319", "CWE-326", "CWE-327", "CWE-295"],
    },
    6: {
        "id": "5.6",
        "name": "Minimise exposed attack surfaces",
        "description": (
            "All unused network and logical interfaces shall be disabled. "
            "Software shall run with least necessary privileges."
        ),
        "title_patterns": [
            r"setuid",
            r"setgid",
            r"world.writable",
            r"excessive.permission",
            r"unnecessary.service",
            r"open.port",
            r"debug.*(enabled|interface|port|service)",
            r"(telnet|ftp|tftp|snmp|upnp).*(enabled|running|service)",
            r"attack.surface",
        ],
        "source_patterns": [
            "check_setuid_binaries",
            "check_filesystem_permissions",
            "analyze_init_scripts",
        ],
        "cwe_ids": ["CWE-250", "CWE-269", "CWE-732", "CWE-1188"],
    },
    7: {
        "id": "5.7",
        "name": "Ensure software integrity",
        "description": (
            "The consumer IoT device shall verify its software using "
            "secure boot mechanisms, or similar."
        ),
        "title_patterns": [
            r"(no|missing|disabled).*(secure.boot|code.signing|integrity)",
            r"binary.protection",
            r"(no|missing).*(stack.canary|nx|pie|relro|aslr|fortify)",
            r"insecure.boot",
            r"unsigned.firmware",
        ],
        "source_patterns": [
            "check_binary_protections",
            "check_all_binary_protections",
            "check_kernel_config",
            "check_kernel_hardening",
        ],
        "cwe_ids": ["CWE-345", "CWE-353", "CWE-693"],
    },
    8: {
        "id": "5.8",
        "name": "Ensure that personal data is secure",
        "description": (
            "The device shall protect the confidentiality of personal "
            "data transiting between the device and a service."
        ),
        "title_patterns": [
            r"personal.data",
            r"privacy",
            r"sensitive.*(file|data).*(permission|access|exposed)",
            r"world.readable.*(log|config|database|credential)",
        ],
        "source_patterns": [
            "check_filesystem_permissions",
        ],
        "cwe_ids": ["CWE-359", "CWE-532"],
    },
    9: {
        "id": "5.9",
        "name": "Make systems resilient to outages",
        "description": (
            "Consumer IoT devices should remain operating and locally "
            "functional in the case of a loss of network access."
        ),
        "title_patterns": [],
        "source_patterns": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    10: {
        "id": "5.10",
        "name": "Examine system telemetry data",
        "description": (
            "If telemetry data is collected, it shall be examined for "
            "security anomalies."
        ),
        "title_patterns": [],
        "source_patterns": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    11: {
        "id": "5.11",
        "name": "Make it easy for users to delete user data",
        "description": (
            "The consumer shall be provided with functionality to "
            "delete personal data from the device."
        ),
        "title_patterns": [],
        "source_patterns": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    12: {
        "id": "5.12",
        "name": "Make installation and maintenance of devices easy",
        "description": (
            "Installation and maintenance should involve minimal "
            "decisions by the user and follow security best practices."
        ),
        "title_patterns": [],
        "source_patterns": [],
        "cwe_ids": [],
        "not_automatable": True,
    },
    13: {
        "id": "5.13",
        "name": "Validate input data",
        "description": (
            "The consumer IoT device software shall validate data "
            "input via user interfaces and transferred via APIs or "
            "between networks."
        ),
        "title_patterns": [
            r"(command|sql|os|code).injection",
            r"buffer.overflow",
            r"format.string",
            r"input.validation",
            r"stack.overflow",
            r"heap.overflow",
            r"memory.corruption",
            r"fuzzing.crash",
        ],
        "source_patterns": [
            "scan_with_yara",
            "triage_fuzzing_crash",
            "start_fuzzing_campaign",
        ],
        "cwe_ids": ["CWE-20", "CWE-77", "CWE-78", "CWE-89", "CWE-120", "CWE-134"],
    },
}


class ETSIComplianceService:
    """Generate ETSI EN 303 645 compliance reports from existing findings."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_report(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID | None = None,
    ) -> dict:
        """Generate a compliance report mapping findings to ETSI provisions.

        Returns a dict with:
          - standard: str
          - generated_at: str (ISO timestamp)
          - provisions: list of provision dicts with status and matched findings
          - summary: { total, pass, fail, partial, not_tested }
        """
        # Load all findings for this project (optionally filtered by firmware)
        stmt = select(Finding).where(Finding.project_id == project_id)
        if firmware_id:
            stmt = stmt.where(Finding.firmware_id == firmware_id)
        stmt = stmt.order_by(Finding.created_at.desc())

        result = await self.db.execute(stmt)
        findings = list(result.scalars().all())

        # Map findings to provisions
        provisions = []
        counts = {"total": 13, "pass": 0, "fail": 0, "partial": 0, "not_tested": 0}

        for provision_num in sorted(ETSI_PROVISIONS.keys()):
            prov_def = ETSI_PROVISIONS[provision_num]
            matched = self._match_findings(findings, prov_def)

            status = self._determine_status(prov_def, matched)
            counts[status] += 1

            provision_entry = {
                "provision": provision_num,
                "clause": prov_def["id"],
                "name": prov_def["name"],
                "description": prov_def["description"],
                "status": status,
                "finding_count": len(matched),
                "findings": [
                    {
                        "id": str(f.id),
                        "title": f.title,
                        "severity": f.severity,
                        "status": f.status,
                        "source": f.source,
                    }
                    for f in matched
                ],
            }
            if prov_def.get("not_automatable"):
                provision_entry["note"] = (
                    "This provision requires runtime or manual assessment "
                    "and cannot be fully evaluated through static firmware analysis."
                )
            provisions.append(provision_entry)

        return {
            "standard": "ETSI EN 303 645",
            "standard_version": "V2.1.1 (2020-06)",
            "generated_at": datetime.now(UTC).isoformat(),
            "provisions": provisions,
            "summary": counts,
        }

    def _match_findings(
        self, findings: list[Finding], prov_def: dict
    ) -> list[Finding]:
        """Find all findings that match a provision's patterns."""
        matched: list[Finding] = []
        title_patterns = [
            re.compile(p, re.IGNORECASE) for p in prov_def.get("title_patterns", [])
        ]
        source_patterns = set(prov_def.get("source_patterns", []))
        cwe_set = set(prov_def.get("cwe_ids", []))

        for finding in findings:
            if self._finding_matches(finding, title_patterns, source_patterns, cwe_set):
                matched.append(finding)

        return matched

    def _finding_matches(
        self,
        finding: Finding,
        title_patterns: list[re.Pattern],
        source_patterns: set[str],
        cwe_set: set[str],
    ) -> bool:
        """Check if a single finding matches any of the provision patterns."""
        # Match by source tool name
        if finding.source and finding.source in source_patterns:
            return True

        # Match by title pattern
        title = finding.title or ""
        for pattern in title_patterns:
            if pattern.search(title):
                return True

        # Match by CWE ID
        if finding.cwe_ids and cwe_set:
            if cwe_set.intersection(finding.cwe_ids):
                return True

        return False

    def _determine_status(
        self, prov_def: dict, matched_findings: list[Finding]
    ) -> str:
        """Determine compliance status for a provision.

        Returns one of: "pass", "fail", "partial", "not_tested"
        """
        if prov_def.get("not_automatable"):
            # If there happen to be relevant findings, report them
            if matched_findings:
                has_open = any(f.status == "open" for f in matched_findings)
                return "fail" if has_open else "partial"
            return "not_tested"

        if not matched_findings:
            # No matching findings found - could mean not tested or passing
            # If the provision has patterns defined, it means we looked but
            # found nothing — that's a pass.
            has_patterns = (
                prov_def.get("title_patterns")
                or prov_def.get("source_patterns")
                or prov_def.get("cwe_ids")
            )
            return "pass" if has_patterns else "not_tested"

        # We have matched findings — check their statuses
        open_findings = [f for f in matched_findings if f.status == "open"]
        resolved_findings = [f for f in matched_findings if f.status != "open"]

        if not open_findings:
            # All findings resolved
            return "pass"
        if resolved_findings:
            # Mix of open and resolved
            return "partial"
        # All findings still open
        return "fail"

    def format_report_text(self, report: dict) -> str:
        """Format a compliance report as readable text for MCP output."""
        lines: list[str] = []
        lines.append(f"# {report['standard']} Compliance Report")
        lines.append(f"Version: {report['standard_version']}")
        lines.append(f"Generated: {report['generated_at']}")
        lines.append("")

        summary = report["summary"]
        lines.append("## Summary")
        lines.append(f"  Total provisions: {summary['total']}")
        lines.append(f"  Pass:       {summary['pass']}")
        lines.append(f"  Fail:       {summary['fail']}")
        lines.append(f"  Partial:    {summary['partial']}")
        lines.append(f"  Not tested: {summary['not_tested']}")
        lines.append("")

        STATUS_ICON = {
            "pass": "[PASS]",
            "fail": "[FAIL]",
            "partial": "[PARTIAL]",
            "not_tested": "[NOT TESTED]",
        }

        lines.append("## Provisions")
        lines.append("")
        for prov in report["provisions"]:
            icon = STATUS_ICON.get(prov["status"], "[ ? ]")
            lines.append(
                f"{icon} {prov['clause']} - {prov['name']}"
            )
            lines.append(f"  {prov['description']}")

            if prov.get("note"):
                lines.append(f"  Note: {prov['note']}")

            if prov["findings"]:
                lines.append(f"  Matched findings ({prov['finding_count']}):")
                for f in prov["findings"][:10]:  # Cap at 10 per provision
                    lines.append(
                        f"    - [{f['severity'].upper()}] {f['title']} "
                        f"(status: {f['status']}, source: {f['source']})"
                    )
                if prov["finding_count"] > 10:
                    lines.append(
                        f"    ... and {prov['finding_count'] - 10} more"
                    )
            else:
                if prov["status"] == "pass":
                    lines.append("  No issues found.")
                elif prov["status"] == "not_tested":
                    lines.append("  No relevant analysis has been performed.")

            lines.append("")

        return "\n".join(lines)
