"""REST endpoints for SBOM generation, component listing, vulnerability scanning, and export."""

import asyncio
import json
import logging
import traceback
import uuid
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


# Session 2a Fix #8-broader: the local `_spawn_background_task` helper +
# `_BACKGROUND_TASKS` set originally lived here (Session 1 Fix #8). They
# have been factored into `app/utils/background.py` and are now imported
# by every router + service that fires detached coroutines (5+ call sites
# across hardware_firmware.py / fuzzing.py / emulation.py / firmware_service.py
# in addition to this file). The local names below are preserved as
# re-export aliases so existing call sites + tests + the Rule #46 paired
# META-CANARIES at `tests/test_sbom_router_background_tasks.py` keep
# working without per-test patching changes.
from app.utils.background import _BACKGROUND_TASKS, spawn_background_task as _spawn_background_task  # noqa: F401

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomComponent, SbomVulnerability
from app.rate_limit import TIER_A_LIGHT_ACK, limiter
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.pagination import Page
from app.schemas.sbom import (
    SbomComponentResponse,
    SbomGenerateResponse,
    SbomGenerateStatusResponse,
    SbomSummaryResponse,
    SbomVulnerabilityResponse,
    VulnerabilityScanResponse,
    VulnerabilityScanStatusResponse,
    VulnerabilityUpdateRequest,
)
from app.services.jsonb_normalizers import _normalize_firmware_device_metadata
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
    """Build the composite SELECT for components + per-component vuln count.

    PERF FIX 2026-05-18: the vuln-count subquery MUST filter by
    firmware_id. Without it the GROUP BY aggregates the entire
    sbom_vulnerabilities table (7.5M+ rows in production), turning
    every SBOM-page render + every vuln-scan-poll into a 7-second
    parallel-seq-scan. The SBOM page polls every 2 s during a scan,
    so after ~4 polls the SQLAlchemy connection pool (size=10 +
    overflow=20 = 30 max) is exhausted and every endpoint returns
    `QueuePool limit ... connection timed out` until the in-flight
    queries drain. The `idx_sbom_vulns_firmware` index makes the
    filtered subquery O(per-firmware-rows) instead of O(full table).
    """
    vuln_count_sq = (
        select(
            SbomVulnerability.component_id,
            func.count(SbomVulnerability.id).label("vuln_count"),
        )
        .where(SbomVulnerability.firmware_id == firmware_id)
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


async def _do_sbom_generate(
    db: AsyncSession,
    firmware: Firmware,
    force_rescan: bool,
) -> dict:
    """Pure-logic SBOM generation orchestrator (Rule #39 INNER runner).

    Accepts ``db`` from the caller; does NOT mutate firmware.sbom_status
    (the OUTER runner owns the state machine). Returns a result-aggregate
    dict with `total_components` + `cached` for the caller to stamp onto
    `firmware.sbom_result`.

    Splits cached-path (no work) from genuine-generation-path. Detection
    roots are populated before the service so sibling partitions are
    walked. Component dicts are persisted as SbomComponent rows; RTOS +
    companion components from os_info are injected per the pre-Session-2a
    contract.
    """
    # Cached-path: no work, return the existing row count.
    if not force_rescan:
        cached_count = await db.scalar(
            select(func.count(SbomComponent.id)).where(
                SbomComponent.firmware_id == firmware.id
            )
        )
        if cached_count and cached_count > 0:
            return {"total_components": int(cached_count), "cached": True}

    # Force-rescan path: clear existing rows.
    if force_rescan:
        await db.execute(
            delete(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
        await db.flush()

    # Populate detection_roots cache so SbomService sees every sibling
    # partition (rootfs + scatter dirs + raw-image dirs).
    from app.services.firmware_paths import get_detection_roots
    await get_detection_roots(firmware, db=db)
    service = SbomService(firmware=firmware)
    loop = asyncio.get_running_loop()
    component_dicts = await loop.run_in_executor(None, service.generate_sbom)

    # Inject detected RTOS and companion components from os_info (unchanged
    # from pre-Session-2a — RTOS injection is part of the contract).
    logger.info(
        "SBOM: component_dicts=%d, firmware.os_info=%s",
        len(component_dicts), bool(firmware.os_info),
    )
    if firmware.os_info:
        try:
            os_info = json.loads(firmware.os_info) if isinstance(firmware.os_info, str) else firmware.os_info
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

    # Bridge hardware_firmware_blobs into the SBOM as components
    # (over-constraint sweep 2026-05-22 follow-up). For HW-shape
    # firmware (L4T BSP, vendor BSPs, MCU firmware), the strategy
    # pipeline finds only software packages (DEBs etc.) — the rich
    # hardware-firmware-blob inventory (bootloader / kernel Image /
    # TEE / DTB / MCU firmware blobs) lives in a parallel table and
    # never appears in the SBOM view. The operator's mental model
    # is unified ("show me ALL my firmware's components"), so bridge
    # blobs into sbom_components here, deduplicated by
    # (vendor, product, version) so multi-file products (23 DTB
    # files, 18 bootloader stages) collapse to one IdentifiedComponent
    # per logical product.
    try:
        blobs = (await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware.id
            )
        )).scalars().all()
        existing_keys = {(c["name"], c.get("version")) for c in component_dicts}
        # Group blobs by (vendor, category, format, version) — HardwareFirmwareBlob
        # has no `product` field; the descriptive product name lives in
        # firmware_patterns.yaml + classifier metadata. Use the available
        # fields to derive a stable component name: "{vendor} {category}
        # ({format})" e.g. "nvidia bootloader (Tegra-MB1)" or
        # "nvidia kernel (Image)". Version pulled from blob.version OR
        # metadata.l4t_release. Multi-file products (23 DTB files, 18
        # bootloader stages of different types) collapse cleanly because
        # the format differs per stage.
        blob_dedup: dict[tuple[str, str, str, str | None], int] = {}
        for blob in blobs:
            vendor = blob.vendor or "unknown"
            category = blob.category or "other"
            blob_format = blob.format or "unknown"
            # Model attribute is `metadata_` (the SQLAlchemy ORM `metadata`
            # name is reserved at the class level; the JSONB column is
            # exposed under the trailing-underscore alias).
            md = blob.metadata_ or {}
            version = blob.version or md.get("l4t_release") or None
            # Qualcomm DSP/audio/modem blobs ship concatenated banners
            # (VARIANT_STRING=... + VERSION_STRING=... + UUID_STRING=...)
            # that can hit 128+ chars. sbom_components.version is
            # VARCHAR(100); cap to 95 to fit + trailing "..." indicator.
            # Rule #15 column-widening migration is queued as a follow-up.
            if version and len(version) > 95:
                version = version[:95] + "..."
            key = (vendor, category, blob_format, version)
            blob_dedup[key] = blob_dedup.get(key, 0) + 1
        for (vendor, category, blob_format, version), instance_count in blob_dedup.items():
            # Special-case kernel blobs: emit as type=operating-system with
            # name=linux-kernel so the SBOM page surfaces them as the OS
            # component operators expect. Pre-2026-05-22 the L4T BSP kernel
            # Image was bridged as type=firmware, leaving the SBOM with
            # zero OS components for Tegra firmware (operator-reported
            # "SBOMs are missing trivial things like linux kernel").
            if category == "kernel":
                comp_name = "linux-kernel"
                comp_type = "operating-system"
                # Universal canonical kernel version extraction — use the
                # shared helper to handle ANY firmware shape:
                # - L4T BSP: blob.metadata.l4t_release="R32.3.1" is non-
                #   canonical. Fall back to sibling nvidia-l4t-kernel
                #   deb component's version field "4.9.140-tegra-..." which
                #   contains the canonical kernel SemVer 4.9.140.
                # - Generic Linux: blob.version "5.15.118-yocto-..." →
                #   "5.15.118".
                # - Android: blob.version "5.4.106-tegra" → "5.4.106".
                # Single source of truth; no per-firmware-shape hand-patching
                # downstream. New shapes add a regex pattern to
                # `app/services/sbom/version_normalize.py`, not here.
                from app.services.sbom.version_normalize import canonical_kernel_version
                sibling_versions = [
                    c["version"] for c in component_dicts
                    if c.get("version") and isinstance(c.get("name"), str)
                    and "kernel" in c["name"].lower()
                ]
                kernel_v = canonical_kernel_version(
                    version, sibling_versions=sibling_versions
                )
                if kernel_v:
                    # Replace the bridged version with the canonical one
                    # so the operator-facing SBOM page also shows it.
                    version = kernel_v
                    cpe = f"cpe:2.3:o:linux:linux_kernel:{kernel_v}:*:*:*:*:*:*:*"
                else:
                    cpe = None
            else:
                comp_name = f"{vendor} {category} ({blob_format})"
                comp_type = "firmware"
                cpe = None
            # Defensive cap on name too — VARCHAR(255).
            if len(comp_name) > 250:
                comp_name = comp_name[:250] + "..."
            if (comp_name, version) in existing_keys:
                continue
            existing_keys.add((comp_name, version))
            slug = "".join(
                ch.lower() if ch.isalnum() or ch in "-_" else "-"
                for ch in f"{category}-{blob_format}"
            ).strip("-")[:80]
            purl = (
                f"pkg:firmware/{vendor.lower()}/{slug}@{version}"
                if version else f"pkg:firmware/{vendor.lower()}/{slug}"
            )
            component_dicts.append({
                "name": comp_name,
                "version": version,
                "type": comp_type,
                "cpe": cpe,
                "purl": purl,
                "supplier": vendor if vendor != "unknown" else None,
                "detection_source": "hardware_firmware_blob",
                "detection_confidence": "high",
                "file_paths": None,
                "metadata": {
                    "instance_count": instance_count,
                    "category": category,
                    "format": blob_format,
                },
            })
    except Exception:
        logger.exception(
            "SBOM hardware-firmware-blob bridge failed for firmware %s "
            "(non-fatal — software components still persisted)",
            firmware.id,
        )

    # Persist to database.
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
    return {"total_components": len(component_dicts), "cached": False}


async def _firmware_to_sbom_generate_status(
    db: AsyncSession, firmware: Firmware
) -> SbomGenerateStatusResponse:
    """Build a SBOM /generate status response from a Firmware row.

    Mirrors ``_firmware_to_vuln_scan_status`` above. The ``result`` JSONB
    payload (stamped by ``_run_sbom_generate_background``) carries the
    last-known component count + cached flag so the polling endpoint's
    response shape survives a page reload without an extra COUNT query.

    The 3 unknown-format fields (detected_format / extraction_capability /
    sbom_supported_for_format) per Scout D + W2-α resolution let the
    frontend render the graceful-degrade affordance. They derive from the
    firmware row's pre-upload classify so they're available BEFORE the
    background runner even fires.
    """
    result_dict = firmware.sbom_result or {}
    total: int | None = result_dict.get("total_components") if isinstance(result_dict, dict) else None
    cached: bool = bool(result_dict.get("cached", False)) if isinstance(result_dict, dict) else False

    # Derive unknown-format fields from the firmware row (set by the
    # upload pipeline's classify_firmware step). Per Scout D + W2-α, these
    # let the frontend render the "format unknown — try generic strategy"
    # affordance without a separate API roundtrip.
    detected_format = getattr(firmware, "detected_format", None)
    extraction_capability: str | None = None
    sbom_supported_for_format: bool | None = None
    # extraction_capability is JSONB on device_metadata for non-Session-3 deployments;
    # avoid a hard requirement so the alembic ordering is independent of Fix #9.
    meta = getattr(firmware, "device_metadata", None) or {}
    if isinstance(meta, dict):
        upload_status = meta.get("upload_status") if isinstance(meta.get("upload_status"), dict) else None
        if upload_status:
            extraction_capability = upload_status.get("extraction_capability")
            sbom_supported_for_format = upload_status.get("sbom_supported_for_format")

    return SbomGenerateStatusResponse(
        firmware_id=firmware.id,
        status=firmware.sbom_status,
        started_at=firmware.sbom_status_started_at,
        finished_at=firmware.sbom_status_finished_at,
        error=firmware.sbom_status_error,
        cached=cached,
        total_components=total,
        detected_format=detected_format,
        extraction_capability=extraction_capability,
        sbom_supported_for_format=sbom_supported_for_format,
    )


async def _run_sbom_generate_background(
    firmware_id: uuid.UUID,
    force_rescan: bool,
) -> None:
    """Detached SBOM /generate runner (Rule #39 OUTER state-machine wrapper).

    Owns its own ``AsyncSession``; mirrors ``_run_vuln_scan_background``
    above. State transitions: ``queued → running → completed | failed``.

    Unknown-format short-circuit per Scout C + W2-α resolution: lands
    INSIDE this runner AFTER the 409 router-level idempotency check has
    already passed. If `firmware.detected_format` is None or the upload
    pipeline marked the format as unsupported, the runner flips to
    ``completed`` with an empty result + an explanatory marker — operator
    sees the polling complete cleanly with `total_components=0` +
    `sbom_supported_for_format=False`, NOT a generic failure toast.
    """
    started = datetime.now(UTC)
    try:
        async with async_session_factory() as db:
            try:
                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    logger.warning(
                        "sbom-generate background: firmware %s vanished before run",
                        firmware_id,
                    )
                    return
                fw.sbom_status = "running"
                fw.sbom_status_started_at = started
                fw.sbom_status_error = None
                await db.commit()

                # Unknown-format graceful-degrade (Scout C + W2-α resolution).
                # If pre-upload classify marked the format as unknown OR
                # extraction-capability is "none", run the generation anyway
                # (RTOS / single-binary firmware may still emit something) BUT
                # if the result is 0 components AND format is unknown, the
                # response carries sbom_supported_for_format=False so the
                # frontend renders the graceful-degrade affordance.
                result_aggregate = await _do_sbom_generate(db, fw, force_rescan)
                await db.commit()

                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    return
                fw.sbom_status = "completed"
                fw.sbom_status_finished_at = datetime.now(UTC)
                fw.sbom_status_error = None
                # Stamp the result aggregate per Rule #33 .b — same row as
                # the status column; survives backend restart + page reload.
                fw.sbom_result = result_aggregate
                await db.commit()
                logger.info(
                    "sbom-generate background: firmware %s completed (components=%d, cached=%s)",
                    firmware_id,
                    result_aggregate.get("total_components", -1),
                    result_aggregate.get("cached", False),
                )
            except Exception as exc:
                await db.rollback()
                err_summary = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_fw = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_fw is not None:
                        fail_fw.sbom_status = "failed"
                        fail_fw.sbom_status_finished_at = datetime.now(UTC)
                        fail_fw.sbom_status_error = err_summary
                        await fail_db.commit()
                logger.exception(
                    "sbom-generate background: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "sbom-generate background: unrecoverable error for firmware %s",
            firmware_id,
        )


@router.post(
    "/generate",
    response_model=SbomGenerateStatusResponse,
    status_code=202,
)
@limiter.limit(TIER_A_LIGHT_ACK)
async def generate_sbom(
    request: Request,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> SbomGenerateStatusResponse:
    """Enqueue SBOM generation for the resolved firmware (Rule #29 + #33).

    Returns 202 Accepted with the firmware row in ``sbom_status='queued'``.
    The frontend polls ``GET /sbom/generate/status`` every 2 s until
    ``status`` flips to ``completed`` (success — read ``total_components``
    + ``cached``) or ``failed`` (read ``error``).

    Why 202 rather than 200: pre-Session-2a /generate ran synchronously
    under the executor for 30-120 s per call. The endpoint was already
    decorated ``@limiter.limit(TIER_A_LIGHT_ACK)`` (30/hour) — a tier
    shape that requires 202+polling semantics per Rule #51 .ii. Session 1
    identified the mismatch; Session 2a Fix #1 closes it.

    Idempotency: a POST while the firmware's status is already
    ``queued`` or ``running`` returns 409 with the in-flight status
    rather than spawning a second run. The frontend should poll
    ``/sbom/generate/status`` to observe the existing run.
    """
    if firmware.sbom_status in ("queued", "running"):
        raise HTTPException(
            409,
            f"sbom-generate already {firmware.sbom_status} for this firmware",
        )

    firmware.sbom_status = "queued"
    firmware.sbom_status_started_at = None
    firmware.sbom_status_finished_at = None
    firmware.sbom_status_error = None
    # Commit before scheduling the background task so its fresh session
    # observes the queued row.
    await db.commit()

    # Rule #33 (d) rubric: in-process Syft / strategy run + DB writes =
    # asyncio.create_task is correct (vuln-scan + cve-match precedent).
    # No worker resource coordination needed; intermediate state is
    # incrementally persisted by _do_sbom_generate via db.flush().
    #
    # _spawn_background_task wraps asyncio.create_task with a strong-
    # reference set per S1 Fix #8 GC-hardening discipline.
    _spawn_background_task(
        _run_sbom_generate_background(firmware.id, force_rescan),
        name=f"sbom_generate_{firmware.id}",
    )
    return await _firmware_to_sbom_generate_status(db, firmware)


@router.get(
    "/generate/status",
    response_model=SbomGenerateStatusResponse,
)
async def get_sbom_generate_status(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> SbomGenerateStatusResponse:
    """Return the current SBOM /generate status snapshot for the resolved firmware.

    The frontend polls this every 2 s after a 202 from POST /sbom/generate
    until ``status`` flips to ``completed`` or ``failed``. Mirrors the
    firmware-unpack + vuln-scan polling shape.
    """
    return await _firmware_to_sbom_generate_status(db, firmware)


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
        # outerjoin per over-constraint-sweep-2026-05-22: blob-pipeline
        # vulns have component_id NULL but blob_id populated; INNER JOIN
        # silently dropped them from VEX exports, undercounting affected
        # components and severity totals. `_build_vex_response` handles
        # the SbomComponent==None case via the same blob-fallback shape
        # the components list uses.
        vuln_stmt = (
            select(SbomVulnerability, SbomComponent)
            .outerjoin(SbomComponent, SbomVulnerability.component_id == SbomComponent.id)
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
    dm = _normalize_firmware_device_metadata(firmware.device_metadata)
    if dm:
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
            "timestamp": datetime.now(UTC).isoformat(),
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


async def _build_vuln_scan_summary(
    db: AsyncSession, firmware_id: uuid.UUID
) -> VulnerabilityScanResponse:
    """Build the last-completed-result summary for a finished vuln scan.

    Aggregated from the persisted ``sbom_vulnerabilities`` rows — those
    rows ARE the result of the scan (Rule #33 (b): persistence on the
    same row used for status, and the rows that ALREADY exist count).

    No separate JSONB ``vuln_scan_result`` column is required because
    the row count + per-severity breakdown is cheap to recompute, and
    the user data (5,104 SbomVulnerability rows for the user's affected
    firmware) round-trips through this helper unchanged.
    """
    total_components = await db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware_id
        )
    ) or 0
    total_vulns = await db.scalar(
        select(func.count(SbomVulnerability.id)).where(
            SbomVulnerability.firmware_id == firmware_id
        )
    ) or 0
    findings_created = await db.scalar(
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
    vulns_by_severity: dict[str, int] = {sev or "unknown": cnt for sev, cnt in severity_rows}
    return VulnerabilityScanResponse(
        status="completed",
        total_components_scanned=total_components,
        total_vulnerabilities_found=total_vulns,
        findings_created=findings_created,
        vulns_by_severity=vulns_by_severity,
    )


async def _firmware_to_vuln_scan_status(
    db: AsyncSession, firmware: Firmware
) -> VulnerabilityScanStatusResponse:
    """Build a status response from a Firmware row.

    Hydrates the ``summary`` field from a count query against
    ``sbom_vulnerabilities`` when status == "completed" so the
    frontend's last-known-result render survives a page reload
    without an extra GET round-trip.
    """
    summary: VulnerabilityScanResponse | None = None
    if firmware.vuln_scan_status == "completed":
        summary = await _build_vuln_scan_summary(db, firmware.id)
    return VulnerabilityScanStatusResponse(
        firmware_id=firmware.id,
        status=firmware.vuln_scan_status,
        started_at=firmware.vuln_scan_started_at,
        finished_at=firmware.vuln_scan_finished_at,
        error=firmware.vuln_scan_error,
        summary=summary,
    )


async def _run_vuln_scan_background(
    firmware_id: uuid.UUID,
    project_id: uuid.UUID,
    force_rescan: bool,
) -> None:
    """Detached vulnerability-scan runner.

    Owns its own ``AsyncSession`` so the FastAPI request that returned
    the 202 can close cleanly. Mirrors ``_run_cve_match_background`` in
    ``routers/hardware_firmware.py`` and ``_run_unpack_background`` in
    ``routers/firmware.py``.

    On entry: flips ``vuln_scan_status`` from ``queued`` → ``running``.
    On clean return: persists the scan summary fields and flips status
    to ``completed``. On exception: flips status to ``failed`` on a
    fresh session and stores a short traceback summary on
    ``vuln_scan_error`` for the UI to surface.
    """
    from app.config import get_settings
    from app.services.grype_service import grype_available, scan_with_grype

    started = datetime.now(UTC)
    try:
        async with async_session_factory() as db:
            try:
                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    logger.warning(
                        "vuln-scan background: firmware %s vanished before run",
                        firmware_id,
                    )
                    return
                fw.vuln_scan_status = "running"
                fw.vuln_scan_started_at = started
                fw.vuln_scan_error = None
                await db.commit()

                settings = get_settings()
                use_grype = (
                    settings.vulnerability_backend == "grype"
                    and grype_available()
                )

                if use_grype:
                    summary = await scan_with_grype(
                        firmware_id=firmware_id,
                        project_id=project_id,
                        db=db,
                        force_rescan=force_rescan,
                    )
                else:
                    vuln_svc = VulnerabilityService(db)
                    summary = await vuln_svc.scan_components(
                        firmware_id=firmware_id,
                        project_id=project_id,
                        force_rescan=force_rescan,
                    )
                await db.commit()

                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    return
                fw.vuln_scan_status = "completed"
                fw.vuln_scan_finished_at = datetime.now(UTC)
                fw.vuln_scan_error = None
                await db.commit()
                logger.info(
                    "vuln-scan background: firmware %s completed (vulns=%d)",
                    firmware_id,
                    summary.get("total_vulnerabilities_found", -1),
                )
            except Exception as exc:
                await db.rollback()
                err_summary = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_fw = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_fw is not None:
                        fail_fw.vuln_scan_status = "failed"
                        fail_fw.vuln_scan_finished_at = datetime.now(UTC)
                        fail_fw.vuln_scan_error = err_summary
                        await fail_db.commit()
                logger.exception(
                    "vuln-scan background: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "vuln-scan background: unrecoverable error for firmware %s",
            firmware_id,
        )


@router.post(
    "/vulnerabilities/scan",
    response_model=VulnerabilityScanStatusResponse,
    status_code=202,
)
@limiter.limit(TIER_A_LIGHT_ACK)
async def scan_vulnerabilities(
    request: Request,
    project_id: uuid.UUID,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityScanStatusResponse:
    """Enqueue a vulnerability scan for the resolved firmware (Rule #29 + #33).

    Returns 202 Accepted with the firmware row in
    ``vuln_scan_status="queued"``. The frontend polls
    ``GET /sbom/vulnerabilities/scan/status`` every 2 s
    (firmware-unpack precedent) until ``status`` flips to ``completed``
    (success — read ``summary``) or ``failed`` (read ``error``).

    Why 202 rather than 200: a single synchronous run on 72 components
    held the TCP connection idle for ~4m10s; with the 16 GB Illumisite
    image incoming the wall-time blows past the SECURITY_SCAN_TIMEOUT
    (600s) ceiling and exceeds Cloudflare's 100s origin timeout in any
    proxied deployment. See CLAUDE.md Rule #29.

    Idempotency: a POST while the firmware's status is already
    ``queued`` or ``running`` returns 409 with the in-flight status
    rather than spawning a second run. The frontend should poll
    ``/sbom/vulnerabilities/scan/status`` to observe the existing run.
    """
    # Ensure SBOM exists — preserves the prior 400 contract.
    comp_count = await db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware.id
        )
    )
    if not comp_count:
        raise HTTPException(
            400, "No SBOM generated yet. Run POST /generate first."
        )

    if firmware.vuln_scan_status in ("queued", "running"):
        raise HTTPException(
            409,
            f"vuln-scan already {firmware.vuln_scan_status} for this firmware",
        )

    firmware.vuln_scan_status = "queued"
    firmware.vuln_scan_started_at = None
    firmware.vuln_scan_finished_at = None
    firmware.vuln_scan_error = None
    # Commit before scheduling the background task so its fresh session
    # observes the queued row.
    await db.commit()

    # Rule #33 (d) rubric: in-process Grype subprocess + DB writes =
    # asyncio.create_task is correct (cve-match precedent). No worker
    # resource coordination needed; intermediate state is incrementally
    # persisted by VulnerabilityService.scan_components / scan_with_grype.
    #
    # `_spawn_background_task` wraps `asyncio.create_task` with a strong-
    # reference set per Rule #51 §SC5-NEW-SBOM Fix #8 (Scout D primary
    # symptom — bare `create_task` returns a task with only a weak ref
    # from the event loop, allowing it to be GC'd mid-run on memory
    # pressure → vuln_scan_status stuck 'running' forever).
    _spawn_background_task(
        _run_vuln_scan_background(firmware.id, project_id, force_rescan),
        name=f"vuln_scan_{firmware.id}",
    )
    return await _firmware_to_vuln_scan_status(db, firmware)


@router.get(
    "/vulnerabilities/scan/status",
    response_model=VulnerabilityScanStatusResponse,
)
async def get_vuln_scan_status(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityScanStatusResponse:
    """Return the current vuln-scan status snapshot for the resolved firmware.

    The frontend polls this every 2 s after a 202 from
    ``POST /sbom/vulnerabilities/scan`` until ``status`` flips to
    ``completed`` or ``failed``. Mirrors the firmware-unpack polling
    shape used by ProjectDetailPage and the cve-match polling shape
    used by the hardware-firmware page.
    """
    return await _firmware_to_vuln_scan_status(db, firmware)


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
    """List vulnerability matches for this firmware (paged).

    Includes both SBOM-component-linked vulns (Tier 1 Grype-based via
    POST /vulnerabilities/scan — populates component_id) AND
    hardware-firmware-blob-linked vulns (Tier 2-5 curated YAML via
    POST /cve-match against hardware_firmware_blobs — populates blob_id).
    Pre-2026-05-22 this endpoint INNER-JOIN'ed on component_id, silently
    dropping all blob-linked rows; operators with HW-shape firmware
    (L4T BSP, Tegra, MCU BSPs) saw "No vulnerabilities found" despite
    populated sbom_vulnerabilities. LEFT JOIN'ed since.
    """
    stmt = (
        select(
            SbomVulnerability,
            SbomComponent.name,
            SbomComponent.version,
            HardwareFirmwareBlob.blob_path,
        )
        .outerjoin(
            SbomComponent,
            SbomVulnerability.component_id == SbomComponent.id,
        )
        .outerjoin(
            HardwareFirmwareBlob,
            SbomVulnerability.blob_id == HardwareFirmwareBlob.id,
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
    for vuln, comp_name, comp_version, blob_path in rows:
        resp = SbomVulnerabilityResponse.model_validate(vuln)
        resp.component_name = comp_name
        resp.component_version = comp_version
        resp.blob_path = blob_path
        # Synthesize display fields when only blob context exists, so the
        # existing frontend's "Component" column shows something useful
        # without UI changes. Format: "<basename> (<category>)" e.g.
        # "Image (kernel)" or "mb1_t194_prod.bin (bootloader)".
        if resp.component_name is None and blob_path:
            import os as _os
            resp.component_name = _os.path.basename(blob_path)
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
            vuln.resolved_at = datetime.now(UTC)
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
            "timestamp": datetime.now(UTC).isoformat(),
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
    now = datetime.now(UTC).isoformat()

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
    now = datetime.now(UTC).isoformat()

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
