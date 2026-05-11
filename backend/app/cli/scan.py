"""Standalone CLI for stateless firmware security scanning.

Wraps AssessmentService to run against a firmware image or extracted
directory without requiring PostgreSQL or Redis. Uses a temporary
SQLite database via aiosqlite for the assessment lifecycle.

Usage:
    wairz-scan /path/to/firmware.bin
    wairz-scan /path/to/extracted/ --format=markdown --fail-on high
    wairz-scan firmware.bin --format=sarif --fail-on cvss:7.0
    wairz-scan firmware.bin --skip-phases=sbom_vulnerability,compliance

Exit codes:
    0  Pass — no findings exceed the threshold
    1  Fail — one or more findings exceed the threshold
    2  Error — scan error, timeout, extraction failure, etc.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import uuid
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# Patch pydantic-settings so ``app.config.get_settings()`` never reaches for
# a real .env / DATABASE_URL during import. The CLI provides its own DB
# engine, so these values are throwaway.
# ---------------------------------------------------------------------------
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///unused.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

logger = logging.getLogger("wairz.scan")

ALL_PHASES = [
    "credential_crypto",
    "sbom_vulnerability",
    "config_filesystem",
    "malware_detection",
    "binary_protections",
    "android",
    "compliance",
]

# Severity levels ordered from highest to lowest
_SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


def _parse_fail_on(value: str) -> dict:
    """Parse --fail-on value into a threshold descriptor.

    Returns dict with either:
      {"mode": "severity", "level": "critical"|"high"|"medium"|"none"}
      {"mode": "cvss", "score": float}
    """
    if value == "none":
        return {"mode": "none"}

    # cvss:N.N pattern
    m = re.match(r"^cvss:(\d+(?:\.\d+)?)$", value, re.IGNORECASE)
    if m:
        score = float(m.group(1))
        if score < 0.0 or score > 10.0:
            raise argparse.ArgumentTypeError(
                f"CVSS score must be 0.0-10.0, got {score}"
            )
        return {"mode": "cvss", "score": score}

    if value in ("critical", "high", "medium"):
        return {"mode": "severity", "level": value}

    raise argparse.ArgumentTypeError(
        f"Invalid --fail-on value: {value!r}. "
        "Use: critical, high, medium, cvss:N.N, or none"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wairz-scan",
        description="Scan firmware for security vulnerabilities.",
        epilog=(
            "Exit codes:\n"
            "  0  Pass — no findings exceed the threshold\n"
            "  1  Fail — one or more findings exceed the threshold\n"
            "  2  Error — scan error, timeout, extraction failure, etc.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "firmware_path",
        help="Path to a firmware file or an already-extracted directory.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "vex"],
        default="json",
        dest="output_format",
        help="Output format (default: json). sarif=SARIF 2.1.0, vex=CycloneDX VEX.",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        dest="fail_on",
        help=(
            "Fail threshold: critical, high, medium, cvss:N.N, or none. "
            "Exit 1 if any finding meets or exceeds the threshold."
        ),
    )
    # Backward compat: --fail-on-critical is an alias for --fail-on critical
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=False,
        help="Alias for --fail-on critical (backward compatibility).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Scan timeout in seconds (default: 600). Exit code 2 on timeout.",
    )
    parser.add_argument(
        "--skip-phases",
        default="",
        help=f"Comma-separated phases to skip. Available: {', '.join(ALL_PHASES)}",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write report to this file instead of stdout.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# Temporary SQLite engine
# ---------------------------------------------------------------------------

async def _create_temp_db(db_path: str):
    """Create a temporary async SQLite engine and initialize all tables.

    SQLAlchemy models in this project use PostgreSQL-specific column types
    (JSONB, ARRAY, gen_random_uuid).  We register DDL-level compilation
    hooks so those types render as SQLite-compatible equivalents (TEXT/JSON).
    This is safe because the CLI never reads the data back through complex
    ORM queries -- it only collects the in-memory assessment result dict
    and reads simple Finding rows.
    """
    from sqlalchemy import ARRAY as SA_ARRAY
    from sqlalchemy import event
    from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.ext.compiler import compiles

    # Teach SQLite how to render PostgreSQL-specific types
    @compiles(JSONB, "sqlite")
    def _compile_jsonb(type_, compiler, **kw):
        return "TEXT"

    @compiles(PG_ARRAY, "sqlite")
    def _compile_pg_array(type_, compiler, **kw):
        return "TEXT"

    @compiles(SA_ARRAY, "sqlite")
    def _compile_sa_array(type_, compiler, **kw):
        return "TEXT"

    url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(url, echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _rec):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Import Base *after* env vars are set so config doesn't explode
    # Force all models to be registered on Base.metadata
    import app.models  # noqa: F401, E402
    from app.database import Base  # noqa: E402

    # SQLite cannot execute server_default=func.gen_random_uuid() or
    # other PG-specific server defaults. Strip them all before
    # create_all -- the Python-side ``default=uuid.uuid4`` still fires
    # and supplies the value.
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            if col.server_default is not None:
                col.server_default = None

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    return engine, session_factory


# ---------------------------------------------------------------------------
# Extract firmware if needed
# ---------------------------------------------------------------------------

def _extract_firmware(firmware_path: str, work_dir: str) -> str:
    """Extract a firmware file into *work_dir* using binwalk or unblob.

    If *firmware_path* is already a directory, return it as-is.
    Returns the path to the extraction root.
    """
    if os.path.isdir(firmware_path):
        return os.path.realpath(firmware_path)

    if not os.path.isfile(firmware_path):
        print(f"Error: {firmware_path} does not exist", file=sys.stderr)
        sys.exit(2)

    extract_dir = os.path.join(work_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    # Try unblob first (handles more formats), fall back to binwalk
    if shutil.which("unblob"):
        logger.info("Extracting with unblob: %s", firmware_path)
        import subprocess
        result = subprocess.run(
            ["unblob", "--extract-dir", extract_dir, firmware_path],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning("unblob failed (rc=%d): %s", result.returncode, result.stderr[:500])
        else:
            return extract_dir
    elif shutil.which("binwalk3") or shutil.which("binwalk"):
        bw = shutil.which("binwalk3") or shutil.which("binwalk")
        logger.info("Extracting with %s: %s", os.path.basename(bw), firmware_path)
        import subprocess
        result = subprocess.run(
            [bw, "-e", "-C", extract_dir, firmware_path],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning("binwalk failed (rc=%d): %s", result.returncode, result.stderr[:500])
        else:
            return extract_dir

    # If no extractor available or extraction failed, treat the file's
    # parent directory as the "extracted" root -- some phases will still
    # run (binary protections on the raw file, etc.).
    logger.warning(
        "No firmware extractor available (install unblob or binwalk). "
        "Scanning the file as-is."
    )
    # Copy the raw file into extract_dir so it has something to scan
    shutil.copy2(firmware_path, extract_dir)
    return extract_dir


# ---------------------------------------------------------------------------
# Collect findings from DB
# ---------------------------------------------------------------------------

async def _collect_findings(session_factory, project_id: uuid.UUID) -> list[dict]:
    """Read all findings back from the temp DB as plain dicts."""
    from sqlalchemy import select

    from app.models.finding import Finding

    async with session_factory() as session:
        result = await session.execute(
            select(Finding).where(Finding.project_id == project_id)
        )
        findings = []
        for f in result.scalars().all():
            findings.append({
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cve_ids": f.cve_ids,
                "cwe_ids": f.cwe_ids,
                "source": f.source,
            })
        return findings


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _format_json(summary: dict, findings: list[dict]) -> str:
    output = {
        "summary": summary,
        "findings": findings,
    }
    return json.dumps(output, indent=2, default=str)


def _format_markdown(summary: dict, findings: list[dict]) -> str:
    lines = [
        "# Wairz Firmware Security Scan Report",
        "",
        "## Summary",
        "",
        f"- **Status:** {summary.get('status', 'unknown')}",
        f"- **Total findings:** {summary.get('total_findings_created', 0)}",
        f"- **Duration:** {summary.get('total_duration_s', 0)}s",
        "",
        "### Phases",
        "",
        "| Phase | Status | Findings | Duration |",
        "|-------|--------|----------|----------|",
    ]
    for phase in summary.get("phases", []):
        lines.append(
            f"| {phase['phase']} | {phase['status']} | "
            f"{phase['findings_created']} | {phase['duration_s']}s |"
        )
    lines.append("")

    # Group findings by severity
    sev_order = ["critical", "high", "medium", "low", "info"]
    by_severity: dict[str, list[dict]] = {s: [] for s in sev_order}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    lines.append("## Findings")
    lines.append("")
    for sev in sev_order:
        group = by_severity.get(sev, [])
        if not group:
            continue
        lines.append(f"### {sev.upper()} ({len(group)})")
        lines.append("")
        for f in group:
            lines.append(f"#### {f['title']}")
            if f.get("description"):
                lines.append(f"\n{f['description']}")
            if f.get("file_path"):
                loc = f["file_path"]
                if f.get("line_number"):
                    loc += f":{f['line_number']}"
                lines.append(f"\n**Location:** `{loc}`")
            if f.get("evidence"):
                lines.append(f"\n<details><summary>Evidence</summary>\n\n```\n{f['evidence']}\n```\n</details>")
            if f.get("cve_ids"):
                lines.append(f"\n**CVEs:** {', '.join(f['cve_ids'])}")
            if f.get("cwe_ids"):
                lines.append(f"\n**CWEs:** {', '.join(f['cwe_ids'])}")
            lines.append("")

    return "\n".join(lines)


def _severity_to_sarif_level(severity: str) -> str:
    """Map finding severity to SARIF level."""
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _format_sarif(summary: dict, findings: list[dict]) -> str:
    """Produce a SARIF 2.1.0 JSON document from findings."""
    rules = []
    results = []
    seen_rule_ids: dict[str, int] = {}  # rule_id -> index in rules list

    for f in findings:
        # Determine rule ID: prefer CVE, then CWE, then title-based slug
        cve_ids = f.get("cve_ids") or []
        cwe_ids = f.get("cwe_ids") or []
        if cve_ids:
            rule_id = cve_ids[0]
        elif cwe_ids:
            rule_id = cwe_ids[0]
        else:
            # Slug from title
            rule_id = re.sub(r"[^a-zA-Z0-9_-]", "-", f.get("title", "unknown"))

        # Register rule if new
        if rule_id not in seen_rule_ids:
            rule_entry: dict = {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", rule_id)},
            }
            if f.get("description"):
                rule_entry["fullDescription"] = {"text": f["description"]}
            # Properties: severity and CWE tags
            properties: dict = {}
            if f.get("severity"):
                properties["security-severity"] = f["severity"]
            tags = []
            for cwe in cwe_ids:
                tags.append(f"external/cwe/{cwe}")
            if tags:
                properties["tags"] = tags
            if properties:
                rule_entry["properties"] = properties
            seen_rule_ids[rule_id] = len(rules)
            rules.append(rule_entry)

        rule_index = seen_rule_ids[rule_id]

        # Build result
        result_entry: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": _severity_to_sarif_level(f.get("severity", "info")),
            "message": {
                "text": f.get("description") or f.get("title", "Finding"),
            },
        }

        # Location
        if f.get("file_path"):
            location: dict = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f["file_path"],
                    },
                },
            }
            if f.get("line_number"):
                location["physicalLocation"]["region"] = {
                    "startLine": f["line_number"],
                }
            result_entry["locations"] = [location]

        results.append(result_entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wairz-scan",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/wairz/wairz",
                        "rules": rules,
                    },
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


def _format_vex(summary: dict, findings: list[dict], firmware_name: str) -> str:
    """Produce a CycloneDX VEX JSON document from findings."""
    now = datetime.now(UTC).isoformat()

    cdx_vulns = []
    for f in findings:
        cve_ids = f.get("cve_ids") or []
        vuln_id = cve_ids[0] if cve_ids else f.get("title", "unknown")

        severity = f.get("severity", "info")

        # Map severity to CycloneDX VEX analysis state
        if severity in ("critical", "high"):
            state = "exploitable"
        elif severity == "medium":
            state = "in_triage"
        else:
            state = "in_triage"

        vuln_entry: dict = {
            "id": vuln_id,
            "source": {"name": "wairz-scan", "url": "https://github.com/wairz/wairz"},
        }

        # Ratings
        ratings = []
        rating: dict = {"severity": severity, "method": "other"}
        ratings.append(rating)
        vuln_entry["ratings"] = ratings

        if f.get("description"):
            vuln_entry["description"] = f["description"]

        # Affects — use file_path as component ref
        if f.get("file_path"):
            vuln_entry["affects"] = [
                {"ref": f"comp-{f['file_path']}"}
            ]

        # CWE references
        cwe_ids = f.get("cwe_ids") or []
        if cwe_ids:
            cwes = []
            for cwe in cwe_ids:
                # Extract numeric part from "CWE-123" format
                m = re.match(r"CWE-(\d+)", cwe, re.IGNORECASE)
                if m:
                    cwes.append(int(m.group(1)))
            if cwes:
                vuln_entry["cwes"] = cwes

        vuln_entry["analysis"] = {"state": state}
        cdx_vulns.append(vuln_entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "wairz-scan",
                        "version": "1.0.0",
                        "publisher": "wairz",
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": firmware_name,
                "version": "1.0",
            },
        },
        "vulnerabilities": cdx_vulns,
    }
    return json.dumps(bom, indent=2, default=str)


# ---------------------------------------------------------------------------
# Threshold checking
# ---------------------------------------------------------------------------

def _extract_cvss_from_finding(finding: dict) -> float | None:
    """Try to extract a CVSS score from a finding's evidence or description.

    Looks for patterns like "CVSS: 9.8" or "cvss_score: 7.5" in the
    evidence text. Returns None if no score found.
    """
    for field in ("evidence", "description"):
        text = finding.get(field)
        if not text:
            continue
        # Match common CVSS patterns
        m = re.search(r"(?:cvss[_ ]?(?:score)?[:\s]+)(\d+(?:\.\d+)?)", str(text), re.IGNORECASE)
        if m:
            return float(m.group(1))
    return None


def _check_threshold(findings: list[dict], threshold: dict) -> bool:
    """Return True if any finding exceeds the threshold (should fail)."""
    mode = threshold["mode"]

    if mode == "none":
        return False

    if mode == "cvss":
        target_score = threshold["score"]
        for f in findings:
            cvss = _extract_cvss_from_finding(f)
            if cvss is not None and cvss >= target_score:
                return True
        return False

    if mode == "severity":
        level = threshold["level"]
        # All severities at or above the threshold level
        level_idx = _SEVERITY_LEVELS.index(level)
        failing_severities = set(_SEVERITY_LEVELS[: level_idx + 1])
        for f in findings:
            if f.get("severity") in failing_severities:
                return True
        return False

    return False


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_LEVELS}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace) -> int:
    """Run the assessment and return the exit code."""
    work_dir = tempfile.mkdtemp(prefix="wairz-scan-")
    db_path = os.path.join(work_dir, "scan.db")

    try:
        # Extract firmware
        extracted_path = _extract_firmware(args.firmware_path, work_dir)
        logger.info("Extracted firmware root: %s", extracted_path)

        # Create temporary database
        engine, session_factory = await _create_temp_db(db_path)

        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()

        # Seed the temp DB with a project and firmware row so FK
        # constraints are satisfied.
        import hashlib

        from app.models.firmware import Firmware
        from app.models.project import Project

        # Compute a basic sha256 for the firmware record
        fw_path = args.firmware_path

        def _compute_fw_record_sync() -> tuple[str, bool]:
            """Sync: return ``(sha256, is_file_on_disk)`` for the firmware
            row seed. The hash falls back to a hash of the path string when
            ``fw_path`` is not a regular file (e.g. an extracted dir).
            """
            if os.path.isfile(fw_path):
                hh = hashlib.sha256()
                with open(fw_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        hh.update(chunk)
                return hh.hexdigest(), True
            return hashlib.sha256(fw_path.encode()).hexdigest(), False

        loop = asyncio.get_running_loop()
        sha256, fw_is_file = await loop.run_in_executor(None, _compute_fw_record_sync)

        async with session_factory() as session:
            session.add(Project(
                id=project_id,
                name="ci-scan",
                status="created",
            ))
            session.add(Firmware(
                id=firmware_id,
                project_id=project_id,
                sha256=sha256,
                original_filename=os.path.basename(fw_path),  # noqa: ASYNC240 — pure-string path op; no I/O
                extracted_path=extracted_path,
                storage_path=fw_path if fw_is_file else None,
            ))
            await session.commit()

        # Parse skip phases
        skip_phases = [
            s.strip() for s in args.skip_phases.split(",") if s.strip()
        ]

        # Run assessment
        async with session_factory() as session:
            from app.services.assessment_service import AssessmentService

            svc = AssessmentService(
                project_id=project_id,
                firmware_id=firmware_id,
                extracted_path=extracted_path,
                db=session,
            )
            summary = await svc.run_full_assessment(skip_phases=skip_phases)
            await session.commit()

        # Collect findings
        findings = await _collect_findings(session_factory, project_id)

        # Format output
        firmware_name = os.path.basename(fw_path)  # noqa: ASYNC240 — pure-string path op; no I/O
        if args.output_format == "markdown":
            report = _format_markdown(summary, findings)
        elif args.output_format == "sarif":
            report = _format_sarif(summary, findings)
        elif args.output_format == "vex":
            report = _format_vex(summary, findings, firmware_name)
        else:
            report = _format_json(summary, findings)

        # Write output
        if args.output:
            def _write_report_sync() -> None:
                with open(args.output, "w") as f:
                    f.write(report)

            await loop.run_in_executor(None, _write_report_sync)
            logger.info("Report written to %s", args.output)
        else:
            print(report)

        # Determine exit code based on threshold
        if _check_threshold(findings, args.fail_threshold):
            counts = _count_by_severity(findings)
            logger.info(
                "Exiting with code 1: threshold exceeded "
                "(critical=%d, high=%d, medium=%d, low=%d)",
                counts["critical"], counts["high"],
                counts["medium"], counts["low"],
            )
            await engine.dispose()
            return 1

        await engine.dispose()
        return 0

    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


def main():
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    # Resolve --fail-on / --fail-on-critical into a unified threshold
    if args.fail_on is not None:
        try:
            args.fail_threshold = _parse_fail_on(args.fail_on)
        except argparse.ArgumentTypeError as e:
            parser.error(str(e))
    elif args.fail_on_critical:
        # Backward compat
        args.fail_threshold = {"mode": "severity", "level": "critical"}
    else:
        # Default: no threshold (never fail on findings)
        args.fail_threshold = {"mode": "none"}

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        exit_code = asyncio.run(
            asyncio.wait_for(_run(args), timeout=args.timeout)
        )
    except TimeoutError:
        print(
            f"Error: scan timed out after {args.timeout} seconds",
            file=sys.stderr,
        )
        exit_code = 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        exit_code = 130
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
