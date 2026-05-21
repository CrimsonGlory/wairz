"""Grype-based vulnerability scanner — local, fast, offline-capable.

Replaces the NVD API approach (rate-limited to 0.6 req/s) with Grype
which runs locally against a cached vulnerability database. Scans
complete in seconds instead of minutes.

Grype DB is downloaded on first use (~150-200MB) and auto-updated.
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
from shutil import which

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.finding import Finding
from app.models.sbom import SbomComponent, SbomVulnerability

logger = logging.getLogger(__name__)


def _extract_cpe_vendor(cpe: str | None) -> str | None:
    """Extract vendor from a CPE 2.3 string (e.g. cpe:2.3:a:VENDOR:PRODUCT:...)."""
    if not cpe:
        return None
    parts = cpe.split(":")
    if len(parts) > 3 and parts[3] not in ("*", ""):
        return parts[3].lower()
    return None


def _extract_grype_vendor(match: dict) -> str | None:
    """Extract vendor from Grype match details — walks CPEs in matchDetails."""
    for detail in match.get("matchDetails", []):
        for key in ("found", "searchedBy"):
            obj = detail.get(key, {})
            for cpe_str in obj.get("cpes", []):
                vendor = _extract_cpe_vendor(cpe_str)
                if vendor:
                    return vendor
    for rv in match.get("relatedVulnerabilities", []):
        for cpe_str in rv.get("cpes", []):
            vendor = _extract_cpe_vendor(cpe_str)
            if vendor:
                return vendor
    return None


def grype_available() -> bool:
    """Check if grype binary is installed."""
    return which("grype") is not None


async def scan_with_grype(
    firmware_id: uuid.UUID,
    project_id: uuid.UUID,
    db: AsyncSession,
    force_rescan: bool = False,
) -> dict:
    """Run Grype vulnerability scan on SBOM components.

    1. Export existing SBOM components as CycloneDX JSON to a temp file
    2. Run `grype sbom:<tempfile> -o json` to scan for vulnerabilities
    3. Parse results and store in the database
    4. Create grouped findings for critical/high vulnerabilities

    Returns dict with scan summary.

    force_rescan semantics (Session 2a Fix #6 of the 2026-05-21
    SBOM/vuln-scan regression sweep). Per Session 1 W2-β
    §SC5-NEW-SBOM-μ, when force_rescan=False AND the firmware already
    has persisted SbomVulnerability rows, the cached path returns the
    existing counts WITHOUT re-running the Grype subprocess. When
    force_rescan=True OR no vulns are persisted yet, the scan runs and
    the DELETE+INSERT discipline of the matches-loop runs INSIDE the
    caller's transaction — the outer `_run_vuln_scan_background`
    runner's rollback (in `routers/sbom.py:_run_vuln_scan_background`)
    reverts BOTH the DELETE and any partial INSERTs if the matches loop
    raises. Pre-Fix #6 the function ignored `force_rescan` entirely,
    unconditionally re-running the scan + DELETEing existing vulns on
    every invocation (~30-60 s of wasted CPU + operator-visible
    "scanning…" spinner on every poll-induced trigger).
    """
    settings = get_settings()

    # Step 1: Load SBOM components
    result = await db.execute(
        select(SbomComponent).where(SbomComponent.firmware_id == firmware_id)
    )
    components = list(result.scalars().all())
    if not components:
        return {
            "status": "no_components",
            "total_components_scanned": 0,
            "total_vulnerabilities_found": 0,
            "findings_created": 0,
            "vulns_by_severity": {},
        }

    # force_rescan=False short-circuit: if vulns are already persisted
    # for this firmware, return the existing summary instead of re-running
    # the Grype subprocess. Mirrors VulnerabilityService.scan_components's
    # cached path. Per W2-β §SC5-NEW-SBOM-μ the cached path's count query
    # is bounded + cheap (single COUNT + GROUP BY severity).
    if not force_rescan:
        existing_count = await db.scalar(
            select(func.count(SbomVulnerability.id)).where(
                SbomVulnerability.firmware_id == firmware_id
            )
        )
        if existing_count and existing_count > 0:
            findings_existing = await db.scalar(
                select(func.count(SbomVulnerability.id)).where(
                    SbomVulnerability.firmware_id == firmware_id,
                    SbomVulnerability.finding_id.is_not(None),
                )
            ) or 0
            severity_rows = (await db.execute(
                select(SbomVulnerability.severity, func.count(SbomVulnerability.id))
                .where(SbomVulnerability.firmware_id == firmware_id)
                .group_by(SbomVulnerability.severity)
            )).all()
            vulns_by_severity = {(sev or "unknown").lower(): cnt for sev, cnt in severity_rows}
            return {
                "status": "cached",
                "total_components_scanned": len(components),
                "total_vulnerabilities_found": int(existing_count),
                "findings_created": int(findings_existing),
                "vulns_by_severity": vulns_by_severity,
            }

    # Step 2: Build CycloneDX SBOM for Grype input
    cdx_components = []
    for comp in components:
        cdx_comp = {
            "type": "library",
            "name": comp.name,
        }
        if comp.version:
            cdx_comp["version"] = comp.version
        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe
        if comp.purl:
            cdx_comp["purl"] = comp.purl
        cdx_components.append(cdx_comp)

    # Use specVersion 1.5 for Grype input — Grype 0.87 doesn't support 1.7.
    # User-facing exports use 1.7, but the internal scan SBOM must be
    # compatible with the installed Grype version.
    cdx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": cdx_components,
    }

    # Step 3: Write to temp file and run Grype
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cdx.json", delete=False
    ) as f:
        json.dump(cdx_sbom, f)
        sbom_path = f.name

    try:
        env = os.environ.copy()
        env["GRYPE_DB_CACHE_DIR"] = settings.grype_db_cache_dir
        os.makedirs(settings.grype_db_cache_dir, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "grype",
            f"sbom:{sbom_path}",
            "-o", "json",
            "--quiet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=settings.grype_timeout
        )

        if proc.returncode not in (0, 1):
            # returncode 1 = vulnerabilities found (not an error)
            error_msg = stderr.decode(errors="replace")[:500]
            logger.error("Grype failed: %s", error_msg)
            raise RuntimeError(f"Grype scan failed: {error_msg}")

        grype_output = json.loads(stdout.decode(errors="replace"))

    except TimeoutError:
        logger.error("Grype scan timed out after %ds", settings.grype_timeout)
        raise RuntimeError(f"Grype scan timed out after {settings.grype_timeout}s")
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Grype output: %s", e)
        raise RuntimeError(f"Failed to parse Grype output: {e}")
    finally:
        os.unlink(sbom_path)

    # Step 4: Parse Grype results and store vulnerabilities
    matches = grype_output.get("matches", [])

    # Clear existing vulnerabilities for this firmware
    await db.execute(
        delete(SbomVulnerability).where(
            SbomVulnerability.firmware_id == firmware_id
        )
    )

    vuln_count = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve_id = vuln.get("id", "")
        severity = vuln.get("severity", "Unknown").lower()
        description = vuln.get("description", "")
        fix_versions = vuln.get("fix", {}).get("versions", [])
        data_source = vuln.get("dataSource", "")

        # Map CVSS score
        cvss_score = None
        for cvss in vuln.get("cvss", []):
            if cvss.get("version", "").startswith("3"):
                cvss_score = cvss.get("metrics", {}).get("baseScore")
                break
        if cvss_score is None:
            for cvss in vuln.get("cvss", []):
                cvss_score = cvss.get("metrics", {}).get("baseScore")
                if cvss_score is not None:
                    break

        # Find matching component
        comp_name = artifact.get("name", "").lower()
        comp_version = artifact.get("version")
        matching_comp = None
        for comp in components:
            if comp.name.lower() == comp_name:
                matching_comp = comp
                break

        if not matching_comp:
            continue

        grype_vendor = _extract_grype_vendor(match)
        comp_vendor = _extract_cpe_vendor(matching_comp.cpe)
        if grype_vendor and comp_vendor and grype_vendor != comp_vendor:
            logger.debug(
                "Skipping %s for %s: vendor mismatch (grype=%s, component=%s)",
                cve_id, matching_comp.name, grype_vendor, comp_vendor,
            )
            continue

        vuln_record = SbomVulnerability(
            component_id=matching_comp.id,
            firmware_id=firmware_id,
            cve_id=cve_id,
            severity=severity,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            description=description[:2000] if description else None,
        )
        db.add(vuln_record)
        vuln_count += 1
        if severity in severity_counts:
            severity_counts[severity] += 1

    await db.flush()

    # Step 5: Create findings for critical/high vulns
    if severity_counts["critical"] + severity_counts["high"] > 0:
        # Rule #35b / audit-2026-05-04 F-A-06: confidence + firmware_id
        # MUST be explicit on every Finding() construction outside
        # FindingService.create() to prevent silent NULL persistence.
        # Confidence: Grype matches via SBOM components are name+version
        # against the Grype DB; "high" reflects matcher certainty (the
        # impact severity is in the `severity` field).
        finding = Finding(
            project_id=project_id,
            firmware_id=firmware_id,
            confidence="high",
            title="Vulnerability scan results",
            description=(
                f"Found {vuln_count} vulnerabilities: "
                f"{severity_counts['critical']} critical, "
                f"{severity_counts['high']} high, "
                f"{severity_counts['medium']} medium, "
                f"{severity_counts['low']} low"
            ),
            severity="critical" if severity_counts["critical"] > 0 else "high",
            source="sbom_scan",
            status="open",
        )
        db.add(finding)
        await db.flush()

    findings_created = 1 if severity_counts["critical"] + severity_counts["high"] > 0 else 0

    return {
        "status": "success",
        "total_components_scanned": len(components),
        "total_vulnerabilities_found": vuln_count,
        "findings_created": findings_created,
        "vulns_by_severity": severity_counts,
        "backend": "grype",
    }
