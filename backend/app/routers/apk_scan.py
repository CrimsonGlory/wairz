"""REST endpoints for APK security scanning.

Phase 1: Manifest security checks (18 MobSF-equivalent checks)
Phase 2a: Bytecode analysis (insecure API pattern detection)
Phase 2b: SAST (jadx + mobsfscan pipeline)
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.rate_limit import TIER_A_HEAVY, limiter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools._android_helpers import is_priv_app_path
from app.database import get_db
from app.models.firmware import Firmware
from app.schemas.apk_scan import (
    BytecodeFindingResponse,
    BytecodeScanResponse,
    BytecodeScanSummary,
    ConfidenceSummary,
    FirmwareContextResponse,
    ManifestFindingResponse,
    ManifestScanResponse,
    ManifestScanSummary,
    SastFindingResponse,
    SastScanResponse,
    SastScanSummary,
    SastScanTimingResponse,
    SourceFileListResponse,
    SourceFileResponse,
)

if TYPE_CHECKING:
    from app.utils.firmware_context import FirmwareContext

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan",
    tags=["apk-scan"],
)

# ---------------------------------------------------------------------------
# Severity filtering helper
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]
_SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _filter_by_min_severity(
    findings: list,
    min_severity: str,
    severity_attr: str = "severity",
) -> list:
    """Filter a list of findings/dicts to only those >= *min_severity*.

    Works with both Pydantic models (attribute access) and plain dicts.
    Returns the list unchanged when *min_severity* is ``"info"`` (the
    lowest level, which includes everything).
    """
    threshold = _SEVERITY_RANK.get(min_severity.lower(), 0)
    if threshold == 0:
        return findings  # "info" keeps everything

    filtered = []
    for f in findings:
        sev = (
            f.get(severity_attr, "info")
            if isinstance(f, dict)
            else getattr(f, severity_attr, "info")
        )
        if _SEVERITY_RANK.get(sev.lower(), 0) >= threshold:
            filtered.append(f)
    return filtered


def _recompute_manifest_summary(
    findings: list[ManifestFindingResponse],
) -> ManifestScanSummary:
    """Recompute summary counts from a (possibly filtered) finding list."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower() if isinstance(f, ManifestFindingResponse) else f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return ManifestScanSummary(
        total_findings=len(findings),
        **counts,
    )


def _recompute_bytecode_summary(
    findings: list[BytecodeFindingResponse],
) -> BytecodeScanSummary:
    """Recompute summary counts from a (possibly filtered) bytecode finding list."""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    for f in findings:
        sev = f.severity.lower() if isinstance(f, BytecodeFindingResponse) else f.get("severity", "info").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = f.category if isinstance(f, BytecodeFindingResponse) else f.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        conf = f.confidence if isinstance(f, BytecodeFindingResponse) else f.get("confidence", "high")
        by_confidence[conf] = by_confidence.get(conf, 0) + 1
    return BytecodeScanSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_category=by_category,
        by_confidence=by_confidence,
    )


_CONFIDENCE_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def _filter_bytecode_findings(
    findings: list[BytecodeFindingResponse],
    min_severity: str,
    min_confidence: str,
) -> list[BytecodeFindingResponse]:
    """Filter bytecode findings by both severity and confidence thresholds."""
    sev_threshold = _SEVERITY_RANK.get(min_severity.lower(), 0)
    conf_threshold = _CONFIDENCE_RANK.get(min_confidence.lower(), 0)

    filtered = []
    for f in findings:
        sev = f.severity.lower() if isinstance(f, BytecodeFindingResponse) else f.get("severity", "info").lower()
        if _SEVERITY_RANK.get(sev, 0) < sev_threshold:
            continue
        conf = f.confidence if isinstance(f, BytecodeFindingResponse) else f.get("confidence", "high")
        if _CONFIDENCE_RANK.get(conf.lower(), 0) < conf_threshold:
            continue
        filtered.append(f)
    return filtered


# Schemas imported from app.schemas.apk_scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> Firmware:
    """Get firmware record, raise 404 if not found."""
    stmt = select(Firmware).where(
        Firmware.id == firmware_id,
        Firmware.project_id == project_id,
    )
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if not firmware:
        raise HTTPException(404, "Firmware not found")
    return firmware


def _find_apk_in_firmware(extracted_path: str, apk_path: str) -> str:
    """Resolve an APK path within firmware extraction.

    Uses sandbox-safe path validation.
    """
    from app.utils.sandbox import validate_path

    full_path = os.path.join(extracted_path, apk_path.lstrip("/"))
    validate_path(extracted_path, full_path)

    if os.path.isfile(full_path) and full_path.lower().endswith(".apk"):
        return full_path

    # Try as directory
    if os.path.isdir(full_path):
        for fname in os.listdir(full_path):
            if fname.lower().endswith(".apk"):
                candidate = os.path.join(full_path, fname)
                validate_path(extracted_path, candidate)
                return candidate

    raise HTTPException(404, f"APK not found at: {apk_path}")


# ---------------------------------------------------------------------------
# Phase 1: Manifest scan endpoint
# ---------------------------------------------------------------------------


@router.post("/manifest", response_model=ManifestScanResponse)
@limiter.limit(TIER_A_HEAVY)
async def scan_apk_manifest_endpoint(
    request: Request,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    apk_path: str = Query(
        ...,
        description="Firmware-relative path to the APK (e.g. system/app/Settings/Settings.apk)",
    ),
    persist_findings: bool = Query(
        True,
        description="Whether to persist findings to the project findings database",
    ),
    min_severity: str = Query(
        "info",
        description="Minimum severity threshold to include in results (info, low, medium, high, critical)",
    ),
    db: AsyncSession = Depends(get_db),
) -> ManifestScanResponse:
    """Run Phase 1 manifest-level security scan on an APK.

    Performs 18 MobSF-equivalent manifest security checks including:
    - debuggable, allowBackup, usesCleartextTraffic, testOnly flags
    - Outdated minSdkVersion, exported components without permissions
    - Custom permission issues, StrandHogg v1/v2 vulnerabilities
    - Deep link validation, network security config issues

    Severity is automatically adjusted based on firmware context:
    - priv-app APKs get +1 severity bump for some checks
    - Platform-signed APKs get severity reduction for build artifacts

    Results are cached by APK SHA256. Typically completes under 500ms.
    """
    # Validate min_severity
    if min_severity.lower() not in _SEVERITY_RANK:
        raise HTTPException(
            400,
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(_SEVERITY_ORDER)}",
        )

    firmware = await _get_firmware(project_id, firmware_id, db)
    extracted_path = firmware.extracted_path
    loop = asyncio.get_event_loop()
    if not extracted_path or not await loop.run_in_executor(
        None, os.path.isdir, extracted_path,
    ):
        raise HTTPException(400, "Firmware not yet extracted")

    abs_apk_path = _find_apk_in_firmware(extracted_path, apk_path)

    # Check cache first
    from app.services import _cache

    sha256 = await loop.run_in_executor(None, _compute_sha256, abs_apk_path)

    cached = await _cache.get_cached(
        db, firmware_id, "manifest_scan", binary_sha256=sha256,
    )

    if cached:
        resp = _build_manifest_response(cached)
        resp.from_cache = True
        # Apply severity threshold filtering to cached results too
        if min_severity.lower() != "info":
            resp.findings = _filter_by_min_severity(resp.findings, min_severity)
            resp.summary = _recompute_manifest_summary(resp.findings)
        return resp

    # Detect firmware context
    rel_path = os.path.relpath(abs_apk_path, extracted_path)  # noqa: ASYNC240 — pure-string path op; no I/O
    is_priv_app = is_priv_app_path(abs_apk_path, extracted_path)

    # Detect platform signing via manifest heuristics (declared permissions
    # with signature/signatureOrSystem protectionLevel, requested platform-
    # signature permissions, or system shared UID).
    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    is_platform_signed = False
    try:
        is_platform_signed = await loop.run_in_executor(
            None, svc.check_platform_signed, abs_apk_path
        )
    except Exception:
        pass

    # Run manifest scan
    try:
        result = await loop.run_in_executor(
            None,
            lambda: svc.scan_manifest_security(
                abs_apk_path,
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            ),
        )
    except FileNotFoundError:
        raise HTTPException(404, "APK file not found")
    except ImportError:
        raise HTTPException(
            503, "Androguard not installed — APK manifest scanning unavailable"
        )
    except Exception as exc:
        logger.exception("Manifest scan failed for %s", apk_path)
        raise HTTPException(500, f"Manifest scan failed: {exc}")

    # Enrich result with context flags
    result["is_priv_app"] = is_priv_app
    result["is_platform_signed"] = is_platform_signed

    # Cache result
    try:
        await _cache.store_cached(
            db,
            firmware_id,
            "manifest_scan",
            result,
            binary_sha256=sha256,
            binary_path=rel_path,
        )
        await db.commit()
    except Exception as exc:
        logger.warning("Failed to cache manifest result: %s", exc)

    # Build firmware context for finding enrichment
    fw_ctx = None
    try:
        from app.utils.firmware_context import build_firmware_context_from_firmware
        fw_ctx = build_firmware_context_from_firmware(firmware, apk_path=abs_apk_path)
    except Exception as exc:
        logger.debug("Failed to build firmware context: %s", exc)

    # Persist findings to the project findings database
    if persist_findings and result.get("findings"):
        try:
            await _persist_rest_manifest_findings(
                db, project_id, firmware_id, result, rel_path,
                fw_ctx=fw_ctx,
            )
        except Exception as exc:
            logger.warning("Failed to persist manifest findings: %s", exc)

    resp = _build_manifest_response(result)
    resp.from_cache = False

    # Attach firmware context metadata
    try:
        resp.firmware_context = _build_firmware_context_response(
            firmware, apk_path=abs_apk_path
        )
    except Exception as exc:
        logger.debug("Failed to build firmware context: %s", exc)

    # Apply severity threshold filtering
    if min_severity.lower() != "info":
        resp.findings = _filter_by_min_severity(resp.findings, min_severity)
        resp.summary = _recompute_manifest_summary(resp.findings)

    return resp


def _build_manifest_response(result: dict) -> ManifestScanResponse:
    """Build a ManifestScanResponse from a scan result dict."""
    findings = []
    for f in result.get("findings", []):
        findings.append(
            ManifestFindingResponse(
                check_id=f.get("check_id", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", ""),
                cwe_ids=f.get("cwe_ids") or [],
                confidence=f.get("confidence", "high"),
            )
        )

    summary_raw = result.get("summary", {})
    summary = ManifestScanSummary(
        total_findings=result.get("total_findings", len(findings)),
        critical=summary_raw.get("critical", 0),
        high=summary_raw.get("high", 0),
        medium=summary_raw.get("medium", 0),
        low=summary_raw.get("low", 0),
        info=summary_raw.get("info", 0),
    )

    conf_raw = result.get("confidence_summary", {})
    confidence_summary = ConfidenceSummary(
        high=conf_raw.get("high", 0),
        medium=conf_raw.get("medium", 0),
        low=conf_raw.get("low", 0),
    )

    # Build suppressed findings list for transparency
    suppressed_findings = [
        ManifestFindingResponse(**sf)
        for sf in result.get("suppressed_findings", [])
    ]

    return ManifestScanResponse(
        package=result.get("package", "unknown"),
        findings=findings,
        summary=summary,
        confidence_summary=confidence_summary,
        is_priv_app=result.get("is_priv_app", False),
        is_platform_signed=result.get("is_platform_signed", False),
        is_debug_signed=result.get("is_debug_signed", False),
        severity_reduced=result.get("severity_reduced", False),
        reduced_check_ids=result.get("reduced_check_ids", []),
        suppressed_findings=suppressed_findings,
        suppressed_count=result.get("suppressed_count", 0),
        suppression_reasons=result.get("suppression_reasons", []),
        elapsed_ms=result.get("elapsed_ms"),
    )


async def _persist_rest_manifest_findings(
    db: AsyncSession,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    result: dict,
    rel_path: str,
    *,
    fw_ctx: FirmwareContext | None = None,
) -> None:
    """Write manifest findings to the Finding table from REST endpoint.

    When *fw_ctx* is provided, finding descriptions and evidence are
    enriched with firmware metadata (device model, Android version, etc.).
    """
    from app.models.finding import Finding

    for f in result["findings"]:
        description = f["description"]
        evidence = f.get("evidence", "")

        # Enrich with firmware context when available
        if fw_ctx:
            from app.utils.firmware_context import enrich_description, enrich_evidence
            description = enrich_description(description, fw_ctx)
            evidence = enrich_evidence(evidence, fw_ctx)

        finding = Finding(
            project_id=project_id,
            firmware_id=firmware_id,
            title=f"[{f['check_id']}] {f['title']}",
            severity=f["severity"],
            confidence=f.get("confidence", "high"),
            description=description,
            evidence=evidence,
            file_path=rel_path,
            cwe_ids=f.get("cwe_ids") or None,
            source="apk-manifest-scan",
        )
        db.add(finding)

    await db.commit()


# ---------------------------------------------------------------------------
# Phase 2a: Bytecode scan endpoint
# ---------------------------------------------------------------------------


@router.post("/bytecode", response_model=BytecodeScanResponse)
@limiter.limit(TIER_A_HEAVY)
async def scan_apk_bytecode_endpoint(
    request: Request,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    apk_path: str = Query(
        ...,
        description="Firmware-relative path to the APK (e.g. system/app/Settings/Settings.apk)",
    ),
    min_severity: str = Query(
        "info",
        description="Minimum severity threshold to include in results (info, low, medium, high, critical)",
    ),
    min_confidence: str = Query(
        "low",
        description="Minimum confidence threshold (low, medium, high). Use 'medium' to suppress noisy low-confidence matches.",
    ),
    db: AsyncSession = Depends(get_db),
) -> BytecodeScanResponse:
    """Run Phase 2a bytecode security scan on an APK.

    Scans DEX bytecode for insecure API usage patterns including:
    - Insecure crypto (ECB, DES, static keys/IVs)
    - Cleartext HTTP, disabled TLS validation
    - World-readable/writable storage
    - Runtime.exec, WebView security issues
    - SQL injection vectors, and more

    Results are cached by APK SHA256. Typically completes under 30s.
    Each finding includes a confidence score (high/medium/low) based on
    detection signal quality — use min_confidence to filter noisy results.
    """
    # Validate min_severity
    if min_severity.lower() not in _SEVERITY_RANK:
        raise HTTPException(
            400,
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(_SEVERITY_ORDER)}",
        )

    # Validate min_confidence
    _CONFIDENCE_LEVELS = ("low", "medium", "high")
    if min_confidence.lower() not in _CONFIDENCE_LEVELS:
        raise HTTPException(
            400,
            f"Invalid min_confidence '{min_confidence}'. Must be one of: {', '.join(_CONFIDENCE_LEVELS)}",
        )

    firmware = await _get_firmware(project_id, firmware_id, db)
    extracted_path = firmware.extracted_path
    loop = asyncio.get_event_loop()
    if not extracted_path or not await loop.run_in_executor(
        None, os.path.isdir, extracted_path,
    ):
        raise HTTPException(400, "Firmware not yet extracted")

    abs_apk_path = _find_apk_in_firmware(extracted_path, apk_path)

    # Check cache first
    from app.services import _cache

    sha256 = await loop.run_in_executor(
        None, _compute_sha256, abs_apk_path
    )

    cached = await _cache.get_cached(
        db, firmware_id, "bytecode_scan", binary_sha256=sha256,
    )

    if cached:
        cached["from_cache"] = True
        resp = BytecodeScanResponse(**cached)
        if min_severity.lower() != "info" or min_confidence.lower() != "low":
            resp.findings = _filter_bytecode_findings(
                resp.findings, min_severity, min_confidence
            )
            resp.summary = _recompute_bytecode_summary(resp.findings)
        return resp

    # Run scan
    try:
        from app.services.bytecode_analysis_service import BytecodeAnalysisService

        svc = BytecodeAnalysisService()
        apk_location = "/" + os.path.relpath(abs_apk_path, extracted_path)  # noqa: ASYNC240 — pure-string path op; no I/O

        result = await loop.run_in_executor(
            None,
            lambda: svc.scan_apk(
                abs_apk_path,
                apk_location=apk_location,
                timeout=30.0,
            ),
        )
    except FileNotFoundError:
        raise HTTPException(404, "APK file not found")
    except ImportError:
        raise HTTPException(
            503, "Androguard not installed — APK bytecode scanning unavailable"
        )
    except Exception as exc:
        logger.exception("Bytecode scan failed for %s", apk_path)
        raise HTTPException(500, f"Bytecode scan failed: {exc}")

    # Cache result
    try:
        rel_path = os.path.relpath(abs_apk_path, extracted_path)  # noqa: ASYNC240 — pure-string path op; no I/O
        await _cache.store_cached(
            db,
            firmware_id,
            "bytecode_scan",
            result,
            binary_sha256=sha256,
            binary_path=rel_path,
        )
        await db.commit()
    except Exception as exc:
        logger.warning("Failed to cache bytecode result: %s", exc)

    result["from_cache"] = False
    resp = BytecodeScanResponse(**result)

    # Attach firmware context metadata
    try:
        resp.firmware_context = _build_firmware_context_response(
            firmware, apk_path=abs_apk_path
        )
    except Exception as exc:
        logger.debug("Failed to build firmware context: %s", exc)

    # Apply severity + confidence threshold filtering
    if min_severity.lower() != "info" or min_confidence.lower() != "low":
        resp.findings = _filter_bytecode_findings(
            resp.findings, min_severity, min_confidence
        )
        resp.summary = _recompute_bytecode_summary(resp.findings)

    return resp


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 of a file."""
    import hashlib
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _build_firmware_context_response(
    firmware: Firmware,
    apk_path: str | None = None,
) -> FirmwareContextResponse:
    """Build a FirmwareContextResponse from a Firmware ORM model."""
    from app.utils.firmware_context import build_firmware_context_from_firmware

    ctx = build_firmware_context_from_firmware(firmware, apk_path=apk_path)
    return FirmwareContextResponse(
        device_model=ctx.device_model,
        manufacturer=ctx.manufacturer,
        android_version=ctx.android_version,
        api_level=ctx.api_level,
        security_patch=ctx.security_patch,
        architecture=ctx.architecture,
        partition=ctx.partition,
        firmware_filename=ctx.firmware_filename,
        bootloader_state=ctx.bootloader_state,
        is_priv_app=ctx.is_priv_app,
        is_system_app=ctx.is_system_app,
        is_vendor_app=ctx.is_vendor_app,
    )


# ---------------------------------------------------------------------------
# Phase 2b: mobsfscan SAST scan endpoint
# ---------------------------------------------------------------------------


@router.post("/sast", response_model=SastScanResponse)
@limiter.limit(TIER_A_HEAVY)
async def scan_apk_sast_endpoint(
    request: Request,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    apk_path: str = Query(
        ...,
        description="Firmware-relative path to the APK (e.g. system/app/Settings/Settings.apk)",
    ),
    min_severity: str = Query(
        "info",
        description="Minimum severity to include (info, low, medium, high, critical)",
    ),
    force_rescan: bool = Query(
        False,
        description="Skip cache and force a fresh scan",
    ),
    timeout: int = Query(  # noqa: ASYNC109 — caller-supplied per-request override; flows into pipeline.scan_apk(timeout=...) which uses asyncio.wait_for internally per Rule #29
        600,
        ge=30,
        le=900,
        description="Total pipeline budget in seconds (default: 600, max: 900)",
    ),
    db: AsyncSession = Depends(get_db),
) -> SastScanResponse:
    """Run Phase 2b SAST scan: JADX decompilation + mobsfscan analysis.

    Decompiles the APK to Java/Kotlin source code using JADX, then runs
    mobsfscan for pattern-based static analysis.  The pipeline enforces
    a total timeout budget (default 3 minutes) shared across both phases.

    Results are cached by APK SHA256.  Findings are persisted to the
    project findings table.
    """
    # Validate min_severity
    if min_severity.lower() not in _SEVERITY_RANK:
        raise HTTPException(
            400,
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(_SEVERITY_ORDER)}",
        )

    from app.services.mobsfscan import (
        get_mobsfscan_pipeline,
        mobsfscan_available,
    )

    if not mobsfscan_available():
        raise HTTPException(
            503, "mobsfscan not installed \u2014 SAST scanning unavailable"
        )

    firmware = await _get_firmware(project_id, firmware_id, db)
    extracted_path = firmware.extracted_path
    loop = asyncio.get_event_loop()
    if not extracted_path or not await loop.run_in_executor(
        None, os.path.isdir, extracted_path,
    ):
        raise HTTPException(400, "Firmware not yet extracted")

    abs_apk_path = _find_apk_in_firmware(extracted_path, apk_path)
    apk_rel_path = os.path.relpath(abs_apk_path, extracted_path)  # noqa: ASYNC240 — pure-string path op; no I/O

    pipeline = get_mobsfscan_pipeline()

    # Build firmware context for finding enrichment
    fw_ctx = None
    try:
        from app.utils.firmware_context import build_firmware_context_from_firmware
        fw_ctx = build_firmware_context_from_firmware(firmware, apk_path=abs_apk_path)
    except Exception as exc:
        logger.debug("Failed to build firmware context: %s", exc)

    try:
        result = await pipeline.scan_apk(
            apk_path=abs_apk_path,
            firmware_id=firmware_id,
            project_id=project_id,
            db=db,
            apk_rel_path=apk_rel_path,
            timeout=timeout,
            min_severity=min_severity,
            persist=True,
            use_cache=not force_rescan,
            fw_ctx=fw_ctx,
        )
    except FileNotFoundError:
        raise HTTPException(404, "APK file not found")
    except TimeoutError as exc:
        raise HTTPException(504, f"Pipeline timed out: {exc}")
    except RuntimeError as exc:
        raise HTTPException(500, f"Pipeline error: {exc}")
    except Exception as exc:
        logger.exception("SAST scan failed for %s", apk_path)
        raise HTTPException(500, f"SAST scan failed: {exc}")

    # Build response
    sast_findings = []
    for nf in result.normalized:
        sast_findings.append(
            SastFindingResponse(
                rule_id=nf.rule_id,
                title=nf.title,
                description=nf.description,
                severity=nf.severity,
                file_path=nf.file_path,
                source_file=nf.source_file,
                line_number=nf.line_number,
                cwe_ids=nf.cwe_ids,
                owasp_mobile=nf.owasp_mobile,
                masvs=nf.masvs,
            )
        )

    sev_counts: dict[str, int] = {}
    for nf in result.normalized:
        sev_counts[nf.severity] = sev_counts.get(nf.severity, 0) + 1

    # Build firmware context for response
    fw_context_resp = None
    try:
        fw_context_resp = _build_firmware_context_response(
            firmware, apk_path=abs_apk_path
        )
    except Exception as exc:
        logger.debug("Failed to build firmware context: %s", exc)

    return SastScanResponse(
        success=result.scan_result.success,
        findings=sast_findings,
        summary=SastScanSummary(
            total_findings=len(result.scan_result.findings),
            by_severity=sev_counts,
            files_scanned=result.scan_result.files_scanned,
            normalized_findings=len(result.normalized),
            persisted_count=result.persisted_count,
            suppressed_rule_count=result.scan_result.suppressed_rule_count,
            suppressed_path_count=result.scan_result.suppressed_path_count,
        ),
        timing=SastScanTimingResponse(
            total_elapsed_ms=result.total_elapsed_ms,
            jadx_elapsed_ms=result.jadx_elapsed_ms,
            mobsfscan_elapsed_ms=result.mobsfscan_elapsed_ms,
        ),
        cached=result.cached,
        error=result.scan_result.error,
        firmware_context=fw_context_resp,
    )


# ---------------------------------------------------------------------------
# Decompiled source viewer
# ---------------------------------------------------------------------------


@router.get("/source/list", response_model=SourceFileListResponse)
async def list_decompiled_sources_endpoint(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    apk_path: str = Query(
        ...,
        description="Firmware-relative path to the APK",
    ),
    db: AsyncSession = Depends(get_db),
) -> SourceFileListResponse:
    """List available decompiled source files for an APK.

    Returns the file paths of all Java/Kotlin sources produced by JADX
    decompilation. Only available after a SAST scan has been run on the APK.
    """
    firmware = await _get_firmware(project_id, firmware_id, db)
    extracted_path = firmware.extracted_path
    loop = asyncio.get_event_loop()
    if not extracted_path or not await loop.run_in_executor(
        None, os.path.isdir, extracted_path,
    ):
        raise HTTPException(400, "Firmware not yet extracted")

    abs_apk_path = _find_apk_in_firmware(extracted_path, apk_path)

    from app.services.jadx_service import JadxDecompilationCache

    svc = JadxDecompilationCache()
    try:
        sources = await svc.get_all_sources(abs_apk_path, firmware_id, db)
    except FileNotFoundError:
        raise HTTPException(404, "APK not found")
    except Exception as exc:
        raise HTTPException(500, f"Failed to retrieve sources: {exc}")

    file_list = sorted(sources.keys()) if sources else []
    return SourceFileListResponse(
        apk_path=apk_path,
        files=file_list,
        total=len(file_list),
    )


@router.get("/source", response_model=SourceFileResponse)
async def get_decompiled_source_endpoint(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    apk_path: str = Query(
        ...,
        description="Firmware-relative path to the APK",
    ),
    file_path: str = Query(
        ...,
        description="Java source file path within the APK (e.g. com/android/server/telecom/PhoneAccountRegistrar.java)",
    ),
    db: AsyncSession = Depends(get_db),
) -> SourceFileResponse:
    """Get the decompiled Java/Kotlin source code for a specific file.

    Returns the JADX-decompiled source code for a single class file.
    The source must have been previously decompiled via a SAST scan.
    Use the ``line`` query parameter in the frontend to scroll to a
    specific line (e.g. the line reported in a SAST finding).
    """
    firmware = await _get_firmware(project_id, firmware_id, db)
    extracted_path = firmware.extracted_path
    loop = asyncio.get_event_loop()
    if not extracted_path or not await loop.run_in_executor(
        None, os.path.isdir, extracted_path,
    ):
        raise HTTPException(400, "Firmware not yet extracted")

    abs_apk_path = _find_apk_in_firmware(extracted_path, apk_path)

    from app.services.jadx_service import JadxDecompilationCache

    svc = JadxDecompilationCache()
    try:
        source = await svc.get_source_file(
            abs_apk_path, file_path, firmware_id, db,
        )
    except FileNotFoundError:
        raise HTTPException(404, "APK not found")
    except Exception as exc:
        raise HTTPException(500, f"Failed to retrieve source: {exc}")

    if source is None:
        raise HTTPException(
            404,
            f"Source file '{file_path}' not found in decompiled output. "
            "Run a SAST scan first to decompile the APK.",
        )

    return SourceFileResponse(
        path=file_path,
        source=source,
        apk_path=apk_path,
        line_count=source.count("\n") + 1,
    )
