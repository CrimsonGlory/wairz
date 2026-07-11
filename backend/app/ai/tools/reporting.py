import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.schemas.finding import FindingCreate, FindingStatus, FindingUpdate, Severity
from app.services.document_service import DocumentService
from app.services.finding_service import FindingService
from app.services.report_service import generate_html_report, generate_markdown_report


async def _resolve_firmware_refs(
    context: ToolContext, refs: list[str]
) -> list[uuid.UUID]:
    """Map firmware references (UUIDs or version labels) to firmware UUIDs.

    References are resolved against the active project's firmware. Labels match
    case-insensitively; entries that resolve to nothing are skipped.
    """
    result = await context.db.execute(
        select(Firmware).where(Firmware.project_id == context.project_id)
    )
    firmware = list(result.scalars().all())
    by_id = {str(fw.id): fw.id for fw in firmware}
    by_label = {
        (fw.version_label or "").strip().lower(): fw.id
        for fw in firmware
        if fw.version_label
    }
    resolved: list[uuid.UUID] = []
    for ref in refs:
        key = str(ref).strip()
        if key in by_id:
            resolved.append(by_id[key])
        elif key.lower() in by_label:
            resolved.append(by_label[key.lower()])
    # De-duplicate while preserving order.
    seen: set[uuid.UUID] = set()
    return [fid for fid in resolved if not (fid in seen or seen.add(fid))]


def register_reporting_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="add_finding",
        description=(
            "Record a security finding for the current firmware project. "
            "Use this whenever you identify a security issue, vulnerability, or notable concern. "
            "Severity levels: critical, high, medium, low, info."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short descriptive title for the finding",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level of the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the finding, including why it matters and potential impact",
                },
                "evidence": {
                    "type": "string",
                    "description": "Supporting evidence: command output, file contents, code snippets, etc.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Filesystem path of the affected file (relative to firmware root)",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number in the affected file, if applicable",
                },
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CVE identifiers, e.g. ['CVE-2023-1234']",
                },
                "cwe_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CWE identifiers, e.g. ['CWE-798', 'CWE-259'] for hardcoded credentials",
                },
                "source": {
                    "type": "string",
                    "enum": ["ai_discovered", "manual", "sbom_scan", "fuzzing", "security_review"],
                    "description": "How this finding was discovered (default: ai_discovered)",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                    "description": (
                        "Matcher certainty (independent of severity). "
                        "Use 'high' when the finding is verified against a "
                        "deterministic gate (CVE matches, magic-byte gates, "
                        "decoded-key extraction); 'medium' for static-"
                        "analysis or pattern matchers (regex/AST/BAP); "
                        "'low' for heuristic guesses or single-indicator "
                        "fingerprints.  Defaults to NULL when omitted."
                    ),
                },
            },
            "required": ["title", "severity", "description"],
        },
        handler=_handle_add_finding,
    )

    registry.register(
        name="list_findings",
        description=(
            "List all security findings recorded for the current project. "
            "Optionally filter by severity or status."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity level",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "Filter by finding status",
                },
            },
        },
        handler=_handle_list_findings,
    )

    registry.register(
        name="get_finding",
        description=(
            "Read the full details of a single recorded finding by its ID, including "
            "description, evidence, affected file/line, CVE/CWE identifiers, status, "
            "source, and timestamps. Use this to review the complete record of a past "
            "finding (list_findings only returns one-line summaries)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "UUID of the finding to read",
                },
            },
            "required": ["finding_id"],
        },
        handler=_handle_get_finding,
    )

    registry.register(
        name="update_finding",
        description=(
            "Update an existing finding's severity, status, details, or the firmware "
            "version(s) it affects. Use this to re-rate severity after further analysis, "
            "mark findings as confirmed/false_positive/fixed, refine the "
            "description/evidence, or tag additional firmware versions when a "
            "vulnerability is still present in a newer release."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "UUID of the finding to update",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "New severity level for the finding",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "New status for the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Updated description",
                },
                "evidence": {
                    "type": "string",
                    "description": "Updated or additional evidence",
                },
                "firmware_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Replaces the set of firmware version(s) this finding affects. "
                        "Each entry may be a firmware UUID or version label (e.g. 'V2'). "
                        "To add a newly-released version while keeping existing tags, "
                        "pass the full desired set (old + new). Use list_firmware_versions "
                        "to see available versions."
                    ),
                },
            },
            "required": ["finding_id"],
        },
        handler=_handle_update_finding,
    )

    registry.register(
        name="generate_assessment_report",
        description=(
            "Generate a full security assessment report from all recorded findings "
            "and save it as a project document. The report includes firmware info, "
            "executive summary, and all findings grouped by severity. "
            "The generated document can be downloaded from the web UI."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["markdown", "html"],
                    "description": "Report format (default: markdown)",
                },
                "title": {
                    "type": "string",
                    "description": "Custom report title (default: 'Security Assessment Report')",
                },
            },
        },
        handler=_handle_generate_assessment_report,
    )

    registry.register(
        name="generate_executive_summary",
        description=(
            "Generate a concise executive summary of the current assessment state. "
            "Returns finding counts by severity, top critical/high issues, SBOM stats, "
            "and overall risk posture. Does NOT save a document — returns text directly "
            "for use in conversation."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_generate_executive_summary,
    )

    registry.register(
        name="run_full_assessment",
        description=(
            "Run a comprehensive automated security assessment of the current firmware. "
            "Executes 7 phases sequentially: (1) credential & crypto scan, "
            "(2) SBOM generation & vulnerability lookup, (3) config & filesystem checks, "
            "(4) YARA malware detection & Semgrep analysis, (5) binary protection audit, "
            "(6) Android-specific checks (if applicable), (7) ETSI compliance mapping. "
            "Each phase creates findings automatically. Failures in one phase do not "
            "block others. This is a long-running operation (may take several minutes). "
            "Returns a summary of all phases with finding counts and durations."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "skip_phases": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "credential_crypto",
                            "sbom_vulnerability",
                            "config_filesystem",
                            "malware_detection",
                            "binary_protections",
                            "android",
                            "compliance",
                        ],
                    },
                    "description": (
                        "Phases to skip. Valid names: credential_crypto, "
                        "sbom_vulnerability, config_filesystem, malware_detection, "
                        "binary_protections, android, compliance"
                    ),
                },
            },
        },
        handler=_handle_run_full_assessment,
    )


async def _handle_add_finding(input: dict, context: ToolContext) -> str:
    # Rule #35b / audit-2026-05-04 F-D-03: pre-fix this handler dropped
    # firmware_id (no scoping to the active firmware) and confidence (no
    # input schema field).  Both now propagate explicitly through
    # FindingCreate → FindingService.create() → Finding(...).
    from app.schemas.finding import Confidence

    svc = FindingService(context.db)
    confidence_in = input.get("confidence")
    data = FindingCreate(
        title=input["title"],
        severity=Severity(input["severity"]),
        description=input.get("description"),
        evidence=input.get("evidence"),
        file_path=input.get("file_path"),
        line_number=input.get("line_number"),
        cve_ids=input.get("cve_ids"),
        cwe_ids=input.get("cwe_ids"),
        source=input.get("source", "ai_discovered"),
        firmware_id=context.firmware_id,
        confidence=Confidence(confidence_in) if confidence_in else None,
    )
    finding = await svc.create(context.project_id, data)
    await context.db.flush()
    versions = ", ".join(
        fw.version_label or str(fw.id)[:8] for fw in finding.firmware_versions
    )
    version_str = f" — version(s): {versions}" if versions else ""
    return (
        f"Finding recorded: {finding.title} [{finding.severity}] "
        f"(ID: {finding.id}){version_str}"
    )


async def _handle_list_findings(input: dict, context: ToolContext) -> str:
    svc = FindingService(context.db)
    findings = await svc.list_by_project(
        context.project_id,
        severity=input.get("severity"),
        status=input.get("status"),
    )
    if not findings:
        return "No findings recorded for this project."

    lines = [f"Found {len(findings)} finding(s):\n"]
    for f in findings:
        status_badge = f"[{f.status}]" if f.status != "open" else ""
        file_info = f" in {f.file_path}" if f.file_path else ""
        versions = ", ".join(
            fw.version_label or str(fw.id)[:8] for fw in f.firmware_versions
        )
        version_info = f" {{{versions}}}" if versions else ""
        lines.append(
            f"- [{f.severity.upper()}] {f.title}{file_info}{version_info} {status_badge} (ID: {f.id})"
        )
    return "\n".join(lines)


async def _handle_get_finding(input: dict, context: ToolContext) -> str:
    import uuid

    svc = FindingService(context.db)
    try:
        finding_id = uuid.UUID(input["finding_id"])
    except (ValueError, KeyError):
        return f"Error: '{input.get('finding_id')}' is not a valid finding ID."

    finding = await svc.get(finding_id)
    if not finding or finding.project_id != context.project_id:
        return f"Error: Finding {input['finding_id']} not found in this project."

    lines = [
        f"# {finding.title}",
        f"- ID: {finding.id}",
        f"- Severity: {finding.severity}",
        f"- Status: {finding.status}",
        f"- Source: {finding.source}",
    ]
    if finding.file_path:
        loc = finding.file_path
        if finding.line_number is not None:
            loc += f":{finding.line_number}"
        lines.append(f"- Location: {loc}")
    if finding.cve_ids:
        lines.append(f"- CVEs: {', '.join(finding.cve_ids)}")
    if finding.cwe_ids:
        lines.append(f"- CWEs: {', '.join(finding.cwe_ids)}")
    if finding.firmware_versions:
        versions = ", ".join(
            f"{fw.version_label or 'unlabeled'} ({str(fw.id)[:8]})"
            for fw in finding.firmware_versions
        )
        lines.append(f"- Affected version(s): {versions}")
    lines.append(f"- Created: {finding.created_at}")
    lines.append(f"- Updated: {finding.updated_at}")
    lines.append("")
    lines.append("## Description")
    lines.append(finding.description or "(none)")
    lines.append("")
    lines.append("## Evidence")
    lines.append(finding.evidence or "(none)")

    return "\n".join(lines)


async def _handle_update_finding(input: dict, context: ToolContext) -> str:
    import uuid

    svc = FindingService(context.db)
    finding_id = uuid.UUID(input["finding_id"])
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != context.project_id:
        return f"Error: Finding {input['finding_id']} not found in this project."

    update_fields = {}
    if "severity" in input:
        update_fields["severity"] = Severity(input["severity"])
    if "status" in input:
        update_fields["status"] = FindingStatus(input["status"])
    if "description" in input:
        update_fields["description"] = input["description"]
    if "evidence" in input:
        update_fields["evidence"] = input["evidence"]
    if "firmware_ids" in input:
        update_fields["firmware_ids"] = await _resolve_firmware_refs(
            context, input["firmware_ids"]
        )

    if not update_fields:
        return "No fields to update."

    data = FindingUpdate(**update_fields)
    updated = await svc.update(finding_id, data)
    await context.db.flush()
    return f"Finding updated: {updated.title} [{updated.severity}] — status: {updated.status}"


async def _handle_generate_assessment_report(input: dict, context: ToolContext) -> str:
    fmt = input.get("format", "markdown").lower()
    custom_title = input.get("title")

    # Load project
    result = await context.db.execute(
        select(Project).where(Project.id == context.project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        return "Error: Current project not found."

    # Load firmware (may be None for projects without firmware)
    firmware = None
    if context.firmware_id:
        result = await context.db.execute(
            select(Firmware).where(Firmware.id == context.firmware_id)
        )
        firmware = result.scalar_one_or_none()

    # Load all findings for this project
    finding_svc = FindingService(context.db)
    findings = await finding_svc.list_by_project(context.project_id)

    # Generate report
    if fmt == "html":
        report_content = generate_html_report(project, firmware, findings)
        ext = "html"
    else:
        report_content = generate_markdown_report(project, firmware, findings)
        ext = "md"

    # Build filename
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    if custom_title:
        safe_title = custom_title.strip().replace("/", "_").replace("\\", "_").replace(" ", "-")
        filename = f"{safe_title}.{ext}"
    else:
        filename = f"security-assessment-{timestamp}.{ext}"

    # Save as project document
    doc_svc = DocumentService(context.db)
    try:
        document = await doc_svc.create_document(
            project_id=context.project_id,
            filename=filename,
            content=report_content,
            description=f"Security assessment report ({fmt.upper()}) — {len(findings)} findings",
        )
    except ValueError as exc:
        return f"Error saving report: {exc}"

    return (
        f"Report generated with {len(findings)} finding(s), saved as {filename}\n"
        f"  Format: {fmt.upper()}\n"
        f"  Size: {document.file_size / 1024:.1f} KB\n"
        f"  Document ID: {document.id}"
    )


async def _handle_generate_executive_summary(input: dict, context: ToolContext) -> str:
    # Load project
    result = await context.db.execute(
        select(Project).where(Project.id == context.project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        return "Error: Current project not found."

    # Load firmware
    firmware = None
    if context.firmware_id:
        result = await context.db.execute(
            select(Firmware).where(Firmware.id == context.firmware_id)
        )
        firmware = result.scalar_one_or_none()

    # Load findings
    finding_svc = FindingService(context.db)
    findings = await finding_svc.list_by_project(context.project_id)

    # Severity breakdown
    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    lines: list[str] = []
    lines.append(f"=== Executive Summary: {project.name} ===\n")

    if firmware:
        fw_info = firmware.original_filename or firmware.sha256[:16]
        arch = firmware.architecture or "unknown"
        lines.append(f"Firmware: {fw_info} ({arch})")

    # Finding counts
    lines.append(f"\n--- Findings ({len(findings)} total) ---")
    if not findings:
        lines.append("No findings recorded.")
    else:
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_severity.get(sev, []))
            if count:
                lines.append(f"  {sev.capitalize()}: {count}")

        # Status breakdown
        by_status: dict[str, int] = {}
        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
        status_parts = [f"{status}: {count}" for status, count in sorted(by_status.items())]
        lines.append(f"  Status: {', '.join(status_parts)}")

    # Top critical/high issues
    top_issues = [
        f for f in findings if f.severity in ("critical", "high")
    ]
    if top_issues:
        lines.append("\n--- Top Critical/High Issues ---")
        for f in top_issues[:20]:
            file_info = f" in {f.file_path}" if f.file_path else ""
            cves = f" ({', '.join(f.cve_ids)})" if f.cve_ids else ""
            lines.append(f"  [{f.severity.upper()}] {f.title}{file_info}{cves}")

    # SBOM stats
    comp_count_result = await context.db.execute(
        select(func.count()).select_from(SbomComponent).where(
            SbomComponent.firmware_id == context.firmware_id
        )
    )
    comp_count = comp_count_result.scalar_one()

    vuln_count_result = await context.db.execute(
        select(func.count()).select_from(SbomVulnerability).where(
            SbomVulnerability.firmware_id == context.firmware_id
        )
    )
    vuln_count = vuln_count_result.scalar_one()

    if comp_count > 0 or vuln_count > 0:
        lines.append("\n--- SBOM ---")
        lines.append(f"  Components: {comp_count}")
        lines.append(f"  Known vulnerabilities: {vuln_count}")

    # Risk posture
    lines.append("\n--- Risk Posture ---")
    critical_count = len(by_severity.get("critical", []))
    high_count = len(by_severity.get("high", []))
    if critical_count > 0:
        lines.append("  Overall: CRITICAL — immediate remediation required")
    elif high_count > 0:
        lines.append("  Overall: HIGH — significant issues require attention")
    elif len(by_severity.get("medium", [])) > 0:
        lines.append("  Overall: MEDIUM — moderate issues identified")
    elif len(findings) > 0:
        lines.append("  Overall: LOW — minor issues only")
    else:
        lines.append("  Overall: No findings recorded yet")

    return "\n".join(lines)


async def _handle_run_full_assessment(input: dict, context: ToolContext) -> str:
    """Run a full multi-phase security assessment."""
    from app.services.assessment_service import AssessmentService

    skip_phases = input.get("skip_phases")

    svc = AssessmentService(
        project_id=context.project_id,
        firmware_id=context.firmware_id,
        extracted_path=context.extracted_path,
        db=context.db,
    )

    result = await svc.run_full_assessment(skip_phases=skip_phases)

    # Format output
    lines: list[str] = [
        "=== Full Security Assessment Complete ===",
        f"Total findings created: {result['total_findings_created']}",
        f"Total duration: {result['total_duration_s']}s",
        "",
        "--- Phase Results ---",
    ]

    for phase in result["phases"]:
        status_icon = {
            "completed": "OK",
            "skipped": "SKIP",
            "error": "FAIL",
        }.get(phase["status"], phase["status"])

        line = (
            f"  [{status_icon}] {phase['phase']}: "
            f"{phase['findings_created']} finding(s), "
            f"{phase['duration_s']}s"
        )
        if phase["errors"]:
            line += f" — errors: {'; '.join(phase['errors'])}"
        lines.append(line)

    lines.append("")
    lines.append(
        "Use list_findings to review all findings, or "
        "generate_assessment_report to create a downloadable report."
    )

    return "\n".join(lines)
