"""REST endpoints for SBOM generation, component listing, vulnerability scanning, and export."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.database import get_db
from app.models.sbom import SbomComponent, SbomVulnerability
from app.rate_limit import TIER_A_HEAVY, limiter
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.pagination import Page
from app.schemas.sbom import (
    SbomComponentResponse,
    SbomGenerateResponse,
    SbomSummaryResponse,
    SbomVulnerabilityResponse,
    VulnerabilityResolutionStatus,
    VulnerabilityScanResponse,
    VulnerabilityUpdateRequest,
)
from app.services.sbom import SbomService
from app.services.vulnerability_service import VulnerabilityService
from app.utils.pagination import paginate_query_rows

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/sbom",
    tags=["sbom"],
)


def _components_with_vuln_counts_stmt(
    firmware_id: uuid.UUID,
    type_filter: str | None = None,
    name_filter: str | None = None,
):
    """Build the composite SELECT for components + per-component vuln count."""
    vuln_count_sq = (
        select(
            SbomVulnerability.component_id,
            func.count(SbomVulnerability.id).label("vuln_count"),
        )
        .group_by(SbomVulnerability.component_id)
        .subquery()
    )

    stmt = (
        select(SbomComponent, vuln_count_sq.c.vuln_count)
        .outerjoin(vuln_count_sq, SbomComponent.id == vuln_count_sq.c.component_id)
        .where(SbomComponent.firmware_id == firmware_id)
        .order_by(SbomComponent.name)
    )

    if type_filter:
        stmt = stmt.where(SbomComponent.type == type_filter)
    if name_filter:
        stmt = stmt.where(SbomComponent.name.ilike(f"%{name_filter}%"))

    return stmt


def _rows_to_component_responses(rows) -> list[SbomComponentResponse]:
    responses = []
    for row in rows:
        comp = row[0]
        vuln_count = row[1] or 0
        resp = SbomComponentResponse.model_validate(comp)
        resp.vulnerability_count = vuln_count
        responses.append(resp)
    return responses


async def _get_components_with_vuln_counts(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    type_filter: str | None = None,
    name_filter: str | None = None,
) -> list[SbomComponentResponse]:
    """Load SBOM components with vulnerability counts (full set).

    Used by the /generate and /export code paths that legitimately need
    every component to build a complete SBOM document.
    """
    stmt = _components_with_vuln_counts_stmt(firmware_id, type_filter, name_filter)
    result = await db.execute(stmt)
    rows = result.all()  # bounded: full SBOM required for generate/export doc
    return _rows_to_component_responses(rows)


@router.post("/generate", response_model=SbomGenerateResponse)
@limiter.limit(TIER_A_HEAVY)
async def generate_sbom(
    request: Request,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Generate SBOM from extracted firmware filesystem.

    Returns cached results unless force_rescan=True.
    """
    # Check if SBOM already exists
    if not force_rescan:
        stmt = select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware.id
        )
        result = await db.execute(stmt)
        count = result.scalar()
        if count and count > 0:
            components = await _get_components_with_vuln_counts(db, firmware.id)
            return SbomGenerateResponse(
                components=components,
                total=len(components),
                cached=True,
            )

    # Clear existing components if force_rescan
    if force_rescan:
        await db.execute(
            delete(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
        await db.flush()

    # Run SBOM generation (CPU-bound, run in thread).
    # Populate detection_roots cache first so SbomService sees every
    # sibling partition (rootfs + scatter dirs + raw-image dirs).
    from app.services.firmware_paths import get_detection_roots
    await get_detection_roots(firmware, db=db)
    service = SbomService(firmware=firmware)
    loop = asyncio.get_running_loop()
    try:
        component_dicts = await loop.run_in_executor(None, service.generate_sbom)
    except Exception as e:
        raise HTTPException(500, f"Failed to generate SBOM: {e}")

    # Inject detected RTOS and companion components from os_info
    import logging as _logging
    _log = _logging.getLogger(__name__)
    _log.info("SBOM: component_dicts=%d, firmware.os_info=%s", len(component_dicts), bool(firmware.os_info))
    if firmware.os_info:
        import json as _json
        try:
            os_info = _json.loads(firmware.os_info) if isinstance(firmware.os_info, str) else firmware.os_info
            rtos = os_info.get("rtos")
            if rtos and rtos.get("name"):
                rtos_name = rtos["name"].lower().replace("/", "-").replace(" ", "-")
                component_dicts.append({
                    "name": rtos["name"],
                    "version": rtos.get("version"),
                    "type": "operating-system",
                    "cpe": f"cpe:2.3:o:{rtos_name}:{rtos_name}:{rtos.get('version', '*')}:*:*:*:*:*:*:*",
                    "purl": None,
                    "supplier": "Micrium" if "ucos" in rtos_name.lower() or "uc-os" in rtos_name.lower() else None,
                    "detection_source": "rtos_detection",
                    "detection_confidence": rtos.get("confidence", "medium"),
                    "file_paths": None,
                    "metadata": {"format": os_info.get("format", "unknown")},
                })
            for comp in os_info.get("companion_components", []):
                component_dicts.append({
                    "name": comp["name"],
                    "version": comp.get("version"),
                    "type": "library",
                    "cpe": None,
                    "purl": None,
                    "supplier": None,
                    "detection_source": "rtos_detection",
                    "detection_confidence": comp.get("confidence", "medium"),
                    "file_paths": None,
                    "metadata": {},
                })
        except Exception:
            pass  # os_info parsing failure is non-fatal

    # Persist to database
    for comp_dict in component_dicts:
        db_comp = SbomComponent(
            firmware_id=firmware.id,
            name=comp_dict["name"],
            version=comp_dict["version"],
            type=comp_dict["type"],
            cpe=comp_dict["cpe"],
            purl=comp_dict["purl"],
            supplier=comp_dict["supplier"],
            detection_source=comp_dict["detection_source"],
            detection_confidence=comp_dict["detection_confidence"],
            file_paths=comp_dict["file_paths"],
            metadata_=comp_dict["metadata"],
        )
        db.add(db_comp)

    await db.flush()

    # Return with vuln counts
    components = await _get_components_with_vuln_counts(db, firmware.id)
    return SbomGenerateResponse(
        components=components,
        total=len(components),
        cached=False,
    )


@router.get("", response_model=Page[SbomComponentResponse])
async def list_sbom_components(
    type: str | None = Query(None, description="Filter by component type"),
    name: str | None = Query(None, description="Filter by component name (partial match)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List SBOM components for a project's firmware (paged)."""
    stmt = _components_with_vuln_counts_stmt(firmware.id, type, name)
    rows, total = await paginate_query_rows(db, stmt, offset=offset, limit=limit)
    return Page[SbomComponentResponse](
        items=_rows_to_component_responses(rows),
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/export")
async def export_sbom(
    format: str = Query("cyclonedx-json", pattern="^(cyclonedx-json|spdx-json|cyclonedx-vex-json)$"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Export SBOM in CycloneDX JSON, SPDX 2.3 JSON, or CycloneDX VEX JSON format."""
    stmt = select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
    result = await db.execute(stmt)
    components = result.scalars().all()  # bounded: full SBOM required to build export doc

    if not components:
        raise HTTPException(404, "No SBOM generated yet. Run POST /generate first.")

    if format == "cyclonedx-vex-json":
        # Load vulnerabilities joined with components
        vuln_stmt = (
            select(SbomVulnerability, SbomComponent)
            .join(SbomComponent, SbomVulnerability.component_id == SbomComponent.id)
            .where(SbomVulnerability.firmware_id == firmware.id)
            .order_by(SbomVulnerability.cvss_score.desc().nullslast())
        )
        vuln_result = await db.execute(vuln_stmt)
        vuln_rows = vuln_result.all()
        return _build_vex_response(components, vuln_rows, firmware)

    if format == "spdx-json":
        return _build_spdx_response(components, firmware)

    # Build CycloneDX 1.7 (ECMA-424) JSON
    main_component: dict = {
        "type": "firmware",
        "name": firmware.original_filename or "unknown",
        "version": "1.0",
    }

    # HBOM: embed device metadata when available
    if firmware.device_metadata:
        dm = firmware.device_metadata
        if dm.get("manufacturer"):
            main_component["manufacturer"] = {"name": dm["manufacturer"]}
        if dm.get("model"):
            main_component["description"] = dm.get("description", dm["model"])
        props = []
        for key in ("serial", "sku", "model", "architecture"):
            if dm.get(key):
                props.append({"name": f"device:{key}", "value": str(dm[key])})
        if props:
            main_component["properties"] = props

    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "wairz-sbom",
                        "version": "0.1.0",
                        "publisher": "wairz",
                    }
                ]
            },
            "component": main_component,
        },
        "components": [],
    }

    for comp in components:
        cdx_comp: dict = {
            "type": _map_type_to_cyclonedx(comp.type),
            "name": comp.name,
        }
        if comp.version:
            cdx_comp["version"] = comp.version
        if comp.purl:
            cdx_comp["purl"] = comp.purl
        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe
        if comp.supplier:
            cdx_comp["supplier"] = {"name": comp.supplier}

        bom["components"].append(cdx_comp)

    content = json.dumps(bom, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{firmware.id}.cdx.json"'
        },
    )


# ---------------------------------------------------------------------------
# Vulnerability Scanning Endpoints
# ---------------------------------------------------------------------------


@router.post("/vulnerabilities/scan", response_model=VulnerabilityScanResponse)
@limiter.limit(TIER_A_HEAVY)
async def scan_vulnerabilities(
    request: Request,
    project_id: uuid.UUID,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a vulnerability scan for all SBOM components.

    Uses Grype (local, fast) by default. Falls back to NVD API if Grype
    is unavailable. Configure via VULNERABILITY_BACKEND=grype|nvd.
    """
    from app.config import get_settings
    from app.services.grype_service import grype_available, scan_with_grype

    # Ensure SBOM exists
    comp_count = await db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware.id
        )
    )
    if not comp_count:
        raise HTTPException(
            400, "No SBOM generated yet. Run POST /generate first."
        )

    settings = get_settings()
    use_grype = settings.vulnerability_backend == "grype" and grype_available()

    try:
        if use_grype:
            summary = await scan_with_grype(
                firmware_id=firmware.id,
                project_id=project_id,
                db=db,
            )
        else:
            vuln_svc = VulnerabilityService(db)
            summary = await vuln_svc.scan_components(
                firmware_id=firmware.id,
                project_id=project_id,
                force_rescan=force_rescan,
            )
    except Exception as e:
        raise HTTPException(500, f"Vulnerability scan failed: {e}")

    return VulnerabilityScanResponse(**summary)


@router.get(
    "/vulnerabilities", response_model=Page[SbomVulnerabilityResponse]
)
async def list_vulnerabilities(
    severity: str | None = Query(None, description="Filter by severity"),
    component_id: uuid.UUID | None = Query(
        None, description="Filter by component ID"
    ),
    cve_id: str | None = Query(None, description="Filter by CVE ID"),
    resolution_status: str | None = Query(
        None, description="Filter by resolution status (open, resolved, ignored, false_positive)"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerability matches for this firmware's SBOM (paged)."""
    stmt = (
        select(SbomVulnerability, SbomComponent.name, SbomComponent.version)
        .join(
            SbomComponent,
            SbomVulnerability.component_id == SbomComponent.id,
        )
        .where(SbomVulnerability.firmware_id == firmware.id)
        .order_by(SbomVulnerability.cvss_score.desc().nullslast())
    )

    if severity:
        stmt = stmt.where(SbomVulnerability.severity == severity)
    if component_id:
        stmt = stmt.where(SbomVulnerability.component_id == component_id)
    if cve_id:
        stmt = stmt.where(SbomVulnerability.cve_id == cve_id)
    if resolution_status:
        stmt = stmt.where(
            SbomVulnerability.resolution_status == resolution_status
        )

    rows, total = await paginate_query_rows(db, stmt, offset=offset, limit=limit)

    responses = []
    for vuln, comp_name, comp_version in rows:
        resp = SbomVulnerabilityResponse.model_validate(vuln)
        resp.component_name = comp_name
        resp.component_version = comp_version
        responses.append(resp)

    return Page[SbomVulnerabilityResponse](
        items=responses,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.patch(
    "/vulnerabilities/{vulnerability_id}",
    response_model=SbomVulnerabilityResponse,
)
async def update_vulnerability(
    vulnerability_id: uuid.UUID,
    body: VulnerabilityUpdateRequest,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Update vulnerability resolution status (ignore, false positive, reopen)."""
    stmt = select(SbomVulnerability).where(
        SbomVulnerability.id == vulnerability_id,
        SbomVulnerability.firmware_id == firmware.id,
    )
    result = await db.execute(stmt)
    vuln = result.scalars().first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")

    if body.resolution_status is not None:
        new_status = body.resolution_status.value
        vuln.resolution_status = new_status

        if new_status in ("resolved", "ignored", "false_positive"):
            vuln.resolved_by = "user"
            vuln.resolved_at = datetime.now(timezone.utc)
        elif new_status == "open":
            # Reopening — clear resolution metadata
            vuln.resolved_by = None
            vuln.resolved_at = None

    if body.resolution_justification is not None:
        vuln.resolution_justification = body.resolution_justification

    await db.flush()
    await db.refresh(vuln)

    # Build response with component info
    comp_stmt = select(SbomComponent.name, SbomComponent.version).where(
        SbomComponent.id == vuln.component_id
    )
    comp_result = await db.execute(comp_stmt)
    comp_row = comp_result.first()

    resp = SbomVulnerabilityResponse.model_validate(vuln)
    if comp_row:
        resp.component_name = comp_row[0]
        resp.component_version = comp_row[1]

    return resp


@router.get("/vulnerabilities/summary", response_model=SbomSummaryResponse)
async def vulnerability_summary(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated vulnerability and SBOM statistics."""
    vuln_svc = VulnerabilityService(db)
    summary = await vuln_svc.get_vulnerability_summary(firmware.id)
    return SbomSummaryResponse(**summary)


@router.post("/push-to-dependency-track")
async def push_to_dependency_track(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Push the current CycloneDX SBOM to a Dependency-Track instance."""
    from app.services.dependency_track_service import DependencyTrackService

    svc = DependencyTrackService()
    if not svc.is_configured:
        raise HTTPException(
            400,
            "Dependency-Track not configured. "
            "Set DEPENDENCY_TRACK_URL and DEPENDENCY_TRACK_API_KEY environment variables.",
        )

    # Build CycloneDX JSON from components
    stmt = select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
    result = await db.execute(stmt)
    components = result.scalars().all()  # bounded: full SBOM required for Dependency-Track push

    if not components:
        raise HTTPException(404, "No SBOM generated yet. Run POST /generate first.")

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "wairz-sbom",
                        "version": "0.1.0",
                        "publisher": "wairz",
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": firmware.original_filename or "unknown",
                "version": "1.0",
            },
        },
        "components": [
            {
                "type": _map_type_to_cyclonedx(c.type),
                "name": c.name,
                **({"version": c.version} if c.version else {}),
                **({"purl": c.purl} if c.purl else {}),
                **({"cpe": c.cpe} if c.cpe else {}),
                **({"supplier": {"name": c.supplier}} if c.supplier else {}),
            }
            for c in components
        ],
    }

    try:
        dt_result = await svc.push_sbom(
            sbom_json=bom,
            project_name=firmware.original_filename or "wairz-firmware",
            project_version="1.0",
        )
    except Exception as e:
        raise HTTPException(502, f"Failed to push to Dependency-Track: {e}")

    return {"status": "pushed", "dependency_track_response": dt_result}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _map_type_to_cyclonedx(comp_type: str) -> str:
    """Map our component type to CycloneDX component type."""
    mapping = {
        "application": "application",
        "library": "library",
        "operating-system": "operating-system",
        "firmware": "firmware",
    }
    return mapping.get(comp_type, "application")


def _map_resolution_to_vex_state(vuln) -> str:
    """Map internal resolution_status to CycloneDX VEX analysis state."""
    status = vuln.resolution_status or "open"
    if status == "resolved":
        return "resolved"
    if status in ("ignored", "false_positive"):
        return "not_affected"
    # status == "open"
    if vuln.adjusted_severity:
        return "exploitable"
    return "in_triage"


def _map_resolution_to_vex_response(vuln) -> list[str] | None:
    """Map internal resolution_status to CycloneDX VEX analysis response."""
    status = vuln.resolution_status or "open"
    if status == "resolved":
        return ["update"]
    if status == "ignored":
        return ["will_not_fix"]
    return None


def _map_justification_to_vex(vuln) -> str | None:
    """Map internal resolution_justification to CycloneDX VEX justification.

    CycloneDX VEX justification values:
      code_not_present, code_not_reachable, requires_configuration,
      requires_dependency, requires_environment, protected_by_compiler,
      protected_by_mitigating_control, protected_at_runtime,
      protected_at_perimeter, protected_by_policy
    """
    justification = vuln.resolution_justification
    if not justification:
        return None
    # If the justification already matches a CycloneDX value, use it directly
    valid_values = {
        "code_not_present", "code_not_reachable", "requires_configuration",
        "requires_dependency", "requires_environment", "protected_by_compiler",
        "protected_by_mitigating_control", "protected_at_runtime",
        "protected_at_perimeter", "protected_by_policy",
    }
    normalized = justification.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized in valid_values:
        return normalized
    return None


def _build_vex_response(
    components: list, vuln_rows: list, firmware
) -> Response:
    """Build a CycloneDX 1.7 VEX document with vulnerability analysis."""
    now = datetime.now(timezone.utc).isoformat()

    # Build component bom-refs keyed by component ID
    comp_bom_refs: dict[str, str] = {}
    cdx_components = []
    for comp in components:
        bom_ref = f"comp-{comp.id}"
        comp_bom_refs[str(comp.id)] = bom_ref
        cdx_comp: dict = {
            "type": _map_type_to_cyclonedx(comp.type),
            "bom-ref": bom_ref,
            "name": comp.name,
        }
        if comp.version:
            cdx_comp["version"] = comp.version
        if comp.purl:
            cdx_comp["purl"] = comp.purl
        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe
        if comp.supplier:
            cdx_comp["supplier"] = {"name": comp.supplier}
        cdx_components.append(cdx_comp)

    # Build vulnerability entries
    cdx_vulns = []
    for vuln, comp in vuln_rows:
        vex_state = _map_resolution_to_vex_state(vuln)

        # Ratings: use adjusted values if available, else original
        effective_score = (
            float(vuln.adjusted_cvss_score)
            if vuln.adjusted_cvss_score is not None
            else (float(vuln.cvss_score) if vuln.cvss_score is not None else None)
        )
        effective_severity = vuln.adjusted_severity or vuln.severity

        ratings = []
        if effective_score is not None:
            rating: dict = {
                "score": effective_score,
                "severity": effective_severity,
                "method": "CVSSv31",
            }
            if vuln.cvss_vector:
                rating["vector"] = vuln.cvss_vector
            ratings.append(rating)

        vuln_entry: dict = {
            "id": vuln.cve_id,
            "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
        }
        if ratings:
            vuln_entry["ratings"] = ratings
        if vuln.description:
            vuln_entry["description"] = vuln.description

        # Affects
        comp_ref = comp_bom_refs.get(str(comp.id))
        if comp_ref:
            vuln_entry["affects"] = [{"ref": comp_ref}]

        # Analysis
        analysis: dict = {"state": vex_state}

        justification = _map_justification_to_vex(vuln)
        if justification and vex_state == "not_affected":
            analysis["justification"] = justification

        detail = vuln.resolution_justification or vuln.adjustment_rationale
        if detail:
            analysis["detail"] = detail

        response = _map_resolution_to_vex_response(vuln)
        if response:
            analysis["response"] = response

        vuln_entry["analysis"] = analysis
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
                        "name": "wairz-sbom",
                        "version": "0.1.0",
                        "publisher": "wairz",
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": firmware.original_filename or "unknown",
                "version": "1.0",
            },
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulns,
    }

    content = json.dumps(bom, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="vex-{firmware.id}.cdx.json"'
        },
    )


def _build_spdx_response(components: list, firmware) -> Response:
    """Build an SPDX 2.3 JSON document from SBOM components."""
    now = datetime.now(timezone.utc).isoformat()

    packages = []
    relationships = []

    for idx, comp in enumerate(components):
        spdx_id = f"SPDXRef-Package-{idx}"

        pkg: dict = {
            "SPDXID": spdx_id,
            "name": comp.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }

        if comp.version:
            pkg["versionInfo"] = comp.version
        if comp.supplier:
            pkg["supplier"] = f"Organization: {comp.supplier}"

        external_refs = []
        if comp.cpe:
            external_refs.append({
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": comp.cpe,
            })
        if comp.purl:
            external_refs.append({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp.purl,
            })
        if external_refs:
            pkg["externalRefs"] = external_refs

        if comp.detection_source:
            pkg["comment"] = f"Detected by: {comp.detection_source} ({comp.detection_confidence or 'unknown'})"

        packages.append(pkg)
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES",
        })

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"wairz-sbom-{firmware.original_filename or 'firmware'}",
        "documentNamespace": f"https://wairz.local/spdx/{firmware.id}",
        "creationInfo": {
            "created": now,
            "creators": [
                "Tool: wairz-sbom-0.1.0",
                "Organization: wairz",
            ],
        },
        "packages": packages,
        "relationships": relationships,
    }

    content = json.dumps(doc, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{firmware.id}.spdx.json"'
        },
    )


@router.get("/cpe-dictionary/status")
async def get_cpe_dictionary_status(project_id: uuid.UUID):
    """Return the CPE dictionary loading status."""
    from app.services.cpe_dictionary_service import get_cpe_dictionary_service

    svc = get_cpe_dictionary_service()
    return await svc.get_status()


@router.post("/cpe-dictionary/reload")
async def reload_cpe_dictionary(project_id: uuid.UUID):
    """Force reload the CPE dictionary from NVD."""
    from app.services.cpe_dictionary_service import get_cpe_dictionary_service

    svc = get_cpe_dictionary_service()
    svc._index = None
    svc._product_names = None
    svc._loading = False
    loaded = await svc.ensure_loaded()
    return {"status": "loading" if not loaded else "loaded"}
# SBOM RTOS injection: 1775525996
