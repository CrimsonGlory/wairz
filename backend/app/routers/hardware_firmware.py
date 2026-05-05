"""REST endpoints for the hardware firmware graph.

Endpoints:

* ``GET .../`` — list detected hardware firmware blobs (Phase 5)
* ``GET .../{blob_id}`` — one blob with full metadata (Phase 5)
* ``GET .../{blob_id}/cves`` — CVE matches for one blob (Phase 5)
* ``POST .../cve-match`` — (re-)run the three-tier CVE matcher (Phase 5)
* ``GET .../firmware-edges`` — on-demand driver <-> firmware edges for the
  component-map overlay.  Separate from the cached component_map graph so
  the frontend can toggle the overlay without invalidating heavy caches.
* ``GET .../drivers`` — per-driver summary of requested firmware blobs
  (resolved vs unresolved).
"""

from __future__ import annotations

import asyncio
import logging
import os
import traceback
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import case, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.rate_limit import TIER_A_HEAVY, limiter
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.hardware_firmware import (
    CveMatchRunResult,
    CveMatchStatusResponse,
    FirmwareDriverResponse,
    FirmwareDriversListResponse,
    FirmwareEdgeResponse,
    FirmwareEdgesResponse,
    HardwareFirmwareBlobResponse,
    HardwareFirmwareCveAggregate,
    HardwareFirmwareCveRow,
    HardwareFirmwareCvesResponse,
    HardwareFirmwareListResponse,
)


logger = logging.getLogger(__name__)


# Severity ordering for the per-blob max_severity rollup. Postgres
# numeric MAX() works on the rank, then we map back to the label.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _severity_case():
    """SQL CASE that ranks SbomVulnerability.severity for MAX() aggregation."""
    return case(
        (SbomVulnerability.severity == "critical", 4),
        (SbomVulnerability.severity == "high", 3),
        (SbomVulnerability.severity == "medium", 2),
        (SbomVulnerability.severity == "low", 1),
        else_=0,
    )


# Kernel-tier set must stay in sync with the matcher (cve_matcher.py)
# and with the run_cve_match aggregate split below.
_KERNEL_TIERS = {"kernel_cpe", "kernel_subsystem"}
from app.services.hardware_firmware.cve_matcher import match_firmware_cves
from app.services.hardware_firmware.graph import build_driver_firmware_graph
from app.services.hardware_firmware.hbom_export import build_hbom

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/hardware-firmware",
    tags=["hardware-firmware"],
)


def _blob_to_response(
    blob: HardwareFirmwareBlob,
    cve_count: int = 0,
    advisory_count: int = 0,
    max_severity: str | None = None,
) -> HardwareFirmwareBlobResponse:
    """Build a response model from an ORM row.

    Falls back to explicit dict construction because the
    ``metadata``/``metadata_`` alias via ``validation_alias`` is sensitive
    to ORM attribute name vs column name and has surprised us before.

    ``cve_count`` / ``advisory_count`` / ``max_severity`` are sourced from
    the list endpoint's GROUP BY join against ``sbom_vulnerabilities`` --
    they default to 0/None for callers (single-blob fetch) that don't
    pre-compute them.
    """
    return HardwareFirmwareBlobResponse(
        id=blob.id,
        firmware_id=blob.firmware_id,
        blob_path=blob.blob_path,
        partition=blob.partition,
        blob_sha256=blob.blob_sha256,
        file_size=blob.file_size,
        category=blob.category,
        vendor=blob.vendor,
        format=blob.format,
        version=blob.version,
        signed=blob.signed,
        signature_algorithm=blob.signature_algorithm,
        cert_subject=blob.cert_subject,
        chipset_target=blob.chipset_target,
        driver_references=blob.driver_references,
        sbom_component_id=blob.sbom_component_id,
        metadata=blob.metadata_ or {},
        detection_source=blob.detection_source,
        detection_confidence=blob.detection_confidence,
        created_at=blob.created_at,
        cve_count=cve_count,
        advisory_count=advisory_count,
        max_severity=max_severity,
    )


@router.get("", response_model=HardwareFirmwareListResponse)
async def list_blobs(
    category: str | None = None,
    vendor: str | None = None,
    signed_only: bool = False,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareListResponse:
    """List detected hardware firmware blobs for the resolved firmware.

    Each row is decorated with cve_count / advisory_count / max_severity
    rolled up from sbom_vulnerabilities via a single GROUP BY (no N+1).
    The UI uses these to badge the tree without an extra fetch per blob.
    """
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    if category:
        stmt = stmt.where(HardwareFirmwareBlob.category == category)
    if vendor:
        stmt = stmt.where(HardwareFirmwareBlob.vendor == vendor)
    if signed_only:
        stmt = stmt.where(HardwareFirmwareBlob.signed == "signed")
    stmt = stmt.order_by(HardwareFirmwareBlob.category, HardwareFirmwareBlob.blob_path)
    blobs = (await db.execute(stmt)).scalars().all()  # bounded: per-firmware blobs + envelope (HardwareFirmwareListResponse)

    # Single GROUP BY across all sbom_vulnerabilities for this firmware,
    # split into actual-CVE vs ADVISORY-* presence flags.  We project
    # max_severity via a CASE-rank so the badge color reflects the
    # highest severity across either category.
    rollup_stmt = select(
        SbomVulnerability.blob_id,
        func.sum(
            case((SbomVulnerability.cve_id.like("ADVISORY-%"), 0), else_=1)
        ).label("cve_count"),
        func.sum(
            case((SbomVulnerability.cve_id.like("ADVISORY-%"), 1), else_=0)
        ).label("advisory_count"),
        func.max(_severity_case()).label("max_severity_rank"),
    ).where(
        SbomVulnerability.firmware_id == firmware.id,
        SbomVulnerability.blob_id.is_not(None),
    ).group_by(SbomVulnerability.blob_id)
    rollup = {
        r.blob_id: (
            int(r.cve_count or 0),
            int(r.advisory_count or 0),
            _RANK_TO_SEVERITY.get(int(r.max_severity_rank or 0)),
        )
        for r in (await db.execute(rollup_stmt)).all()
    }

    blob_rows: list[HardwareFirmwareBlobResponse] = []
    for b in blobs:
        cve_n, adv_n, max_sev = rollup.get(b.id, (0, 0, None))
        blob_rows.append(_blob_to_response(b, cve_n, adv_n, max_sev))
    return HardwareFirmwareListResponse(blobs=blob_rows, total=len(blob_rows))


@router.get("/cve-aggregate", response_model=HardwareFirmwareCveAggregate)
async def get_cve_aggregate(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareCveAggregate:
    """Read-only summary of persisted hw-firmware CVEs for this firmware.

    Distinct from POST /cve-match (which RUNS the matcher); this just
    counts what already lives in sbom_vulnerabilities so the UI header
    badge can render on page load without re-running the matcher every
    time the user navigates back to the page.

    Splits kernel-tier CVEs out from hw-firmware CVEs to mirror the
    aggregate semantics of POST /cve-match.
    """
    stmt = select(
        SbomVulnerability.cve_id,
        SbomVulnerability.match_tier,
        SbomVulnerability.severity,
        func.max(SbomVulnerability.created_at).label("seen_at"),
    ).where(
        SbomVulnerability.firmware_id == firmware.id,
        SbomVulnerability.blob_id.is_not(None),
    ).group_by(
        SbomVulnerability.cve_id,
        SbomVulnerability.match_tier,
        SbomVulnerability.severity,
    )
    rows = (await db.execute(stmt)).all()

    hwfw_cves: set[str] = set()
    kernel_cves: set[str] = set()
    advisories: set[str] = set()
    # Severity bucket is chosen once per distinct hw-firmware CVE, using
    # the highest observed severity (critical > high > medium > low >
    # unknown).  Track rank per cve_id so repeated rows with different
    # severities resolve deterministically.
    hw_sev_rank: dict[str, int] = {}
    last_seen = None
    for cve_id, tier, severity, seen in rows:
        if seen is not None and (last_seen is None or seen > last_seen):
            last_seen = seen
        if cve_id.startswith("ADVISORY-"):
            advisories.add(cve_id)
        elif tier in _KERNEL_TIERS:
            kernel_cves.add(cve_id)
        else:
            hwfw_cves.add(cve_id)
            rank = _SEVERITY_RANK.get(severity or "", 0)
            if rank > hw_sev_rank.get(cve_id, 0):
                hw_sev_rank[cve_id] = rank

    crit = sum(1 for r in hw_sev_rank.values() if r == 4)
    high = sum(1 for r in hw_sev_rank.values() if r == 3)
    med = sum(1 for r in hw_sev_rank.values() if r == 2)
    low = sum(1 for r in hw_sev_rank.values() if r == 1)
    return HardwareFirmwareCveAggregate(
        hw_firmware_cves=len(hwfw_cves),
        kernel_cves=len(kernel_cves),
        advisory_count=len(advisories),
        last_match_at=last_seen,
        hw_severity_critical=crit,
        hw_severity_high=high,
        hw_severity_medium=med,
        hw_severity_low=low,
    )


@router.get("/cves", response_model=HardwareFirmwareCvesResponse)
async def list_cves(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareCvesResponse:
    """CVE-centric aggregation for the CVEs tab.

    Returns one row per distinct ``cve_id`` (excluding ADVISORY-* and
    kernel-tier rows) with the list of hw-firmware blobs it affects and
    the distinct formats across those blobs.  Sorted critical → high →
    medium → low → unknown; within-bucket tie-break by affected-blob
    count desc.
    """
    stmt = (
        select(
            SbomVulnerability.cve_id,
            SbomVulnerability.severity,
            SbomVulnerability.cvss_score,
            SbomVulnerability.match_tier,
            SbomVulnerability.match_confidence,
            SbomVulnerability.description,
            SbomVulnerability.blob_id,
            HardwareFirmwareBlob.format,
        )
        .join(
            HardwareFirmwareBlob,
            HardwareFirmwareBlob.id == SbomVulnerability.blob_id,
        )
        .where(
            SbomVulnerability.firmware_id == firmware.id,
            SbomVulnerability.blob_id.is_not(None),
            ~SbomVulnerability.cve_id.like("ADVISORY-%"),
            ~SbomVulnerability.match_tier.in_(list(_KERNEL_TIERS)),
        )
    )
    rows = (await db.execute(stmt)).all()

    by_cve: dict[str, dict] = {}
    for r in rows:
        rec = by_cve.setdefault(
            r.cve_id,
            {
                "cve_id": r.cve_id,
                "severity": r.severity or "unknown",
                "cvss_score": float(r.cvss_score) if r.cvss_score is not None else None,
                "match_tier": r.match_tier,
                "match_confidence": r.match_confidence,
                "description": r.description,
                "blob_ids": set(),
                "formats": set(),
                "sev_rank": 0,
            },
        )
        rec["blob_ids"].add(r.blob_id)
        if r.format:
            rec["formats"].add(r.format)
        rank = _SEVERITY_RANK.get(r.severity or "", 0)
        if rank > rec["sev_rank"]:
            rec["sev_rank"] = rank
            rec["severity"] = r.severity or rec["severity"]

    cves = [
        HardwareFirmwareCveRow(
            cve_id=v["cve_id"],
            severity=v["severity"],
            cvss_score=v["cvss_score"],
            match_tier=v["match_tier"],
            match_confidence=v["match_confidence"],
            description=v["description"],
            affected_blob_count=len(v["blob_ids"]),
            affected_blob_ids=sorted(v["blob_ids"]),
            affected_formats=sorted(v["formats"]),
        )
        for v in by_cve.values()
    ]
    cves.sort(
        key=lambda c: (
            -_SEVERITY_RANK.get(c.severity, 0),
            -c.affected_blob_count,
            c.cve_id,
        ),
    )
    return HardwareFirmwareCvesResponse(cves=cves, total=len(cves))


@router.get("/{blob_id}/download")
async def download_blob(
    blob_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Stream a detected blob's raw bytes as a file attachment.

    Sandbox: resolves the blob's on-disk path with ``os.path.realpath``
    and enforces that it lives under the firmware's extraction_dir (or
    extracted_path when extraction_dir is unset).  Anything else → 403.
    """
    blob_stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.id == blob_id,
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    blob = (await db.execute(blob_stmt)).scalar_one_or_none()
    if blob is None:
        raise HTTPException(404, "Blob not found")

    candidate = os.path.realpath(blob.blob_path or "")
    if not candidate or not os.path.isfile(candidate):
        raise HTTPException(404, "Blob file missing on disk")

    # Sandbox bounds: prefer extraction_dir, fall back to extracted_path.
    # Both columns come off the Firmware row; realpath both sides so
    # symlinked paths resolve consistently before the prefix check.
    sandbox_roots: list[str] = []
    for attr in ("extraction_dir", "extracted_path"):
        v = getattr(firmware, attr, None)
        if v:
            sandbox_roots.append(os.path.realpath(v))
    if not sandbox_roots:
        raise HTTPException(403, "No sandbox root configured for firmware")

    if not any(
        candidate == root or candidate.startswith(root.rstrip("/") + "/")
        for root in sandbox_roots
    ):
        raise HTTPException(403, "Blob path escapes firmware sandbox")

    filename = os.path.basename(candidate) or f"blob-{blob_id}.bin"
    return FileResponse(
        candidate,
        media_type="application/octet-stream",
        filename=filename,
    )


@router.get("/firmware-edges", response_model=FirmwareEdgesResponse)
async def get_firmware_edges(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareEdgesResponse:
    """Return driver <-> firmware edges for the component-map overlay."""
    result = await build_driver_firmware_graph(firmware.id, db)
    return FirmwareEdgesResponse(
        edges=[
            FirmwareEdgeResponse(
                driver_path=e.driver_path,
                firmware_name=e.firmware_name,
                firmware_blob_path=e.firmware_blob_path,
                source=e.source,
            )
            for e in result.edges
        ],
        kmod_drivers=result.kmod_drivers,
        dtb_sources=result.dtb_sources,
        unresolved_count=result.unresolved_count,
    )


@router.get("/drivers", response_model=FirmwareDriversListResponse)
async def list_drivers(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareDriversListResponse:
    """List drivers (kmod + vmlinux + DTB) with the firmware they request."""
    result = await build_driver_firmware_graph(firmware.id, db)
    by_driver: dict[str, dict] = {}
    for e in result.edges:
        rec = by_driver.setdefault(
            e.driver_path,
            {
                "driver_path": e.driver_path,
                "format": _infer_format(e.driver_path, e.source),
                "firmware_deps": [],
                "firmware_blobs": [],
                "total": 0,
            },
        )
        rec["firmware_deps"].append(e.firmware_name)
        if e.firmware_blob_path:
            rec["firmware_blobs"].append(e.firmware_blob_path)
        rec["total"] += 1

    drivers = [FirmwareDriverResponse(**d) for d in by_driver.values()]
    return FirmwareDriversListResponse(drivers=drivers, total=len(drivers))


def _aggregate_match_result(result) -> CveMatchRunResult:
    """Roll a :class:`MatchResult` into the shape the frontend renders.

    Distinct-CVE semantics: tiers 4/5 project every kernel CVE onto
    every kernel_module blob by design (so per-blob CVE queries reflect
    kernel findings), which inflates the persisted row count by
    O(CVEs × modules). The aggregate UI needs distinct-CVE counts.
    """
    tier5_kernel = [m for m in result.matches if m.tier == "kernel_subsystem"]
    hwfw_matches = [m for m in result.matches if m.tier not in _KERNEL_TIERS]
    tier5_kernel_cves = {m.cve_id for m in tier5_kernel}
    hwfw_cves = {m.cve_id for m in hwfw_matches}
    kernel_distinct = result.tier4_distinct_cves | tier5_kernel_cves
    return CveMatchRunResult(
        count=len(hwfw_cves | kernel_distinct),
        rows=len(hwfw_matches) + len(tier5_kernel) + result.tier4_rows,
        hw_firmware_cves=len(hwfw_cves),
        kernel_cves=len(kernel_distinct),
        kernel_module_rows=len(tier5_kernel) + result.tier4_rows,
    )


def _firmware_to_status(firmware: Firmware) -> CveMatchStatusResponse:
    """Build a status response from a Firmware row.

    The persisted ``cve_match_result`` JSONB is hydrated back into a
    :class:`CveMatchRunResult` so the frontend's last-known-result
    render survives a page reload without an extra `/cve-aggregate`
    round-trip.
    """
    raw = firmware.cve_match_result
    return CveMatchStatusResponse(
        firmware_id=firmware.id,
        status=firmware.cve_match_status,
        started_at=firmware.cve_match_started_at,
        finished_at=firmware.cve_match_finished_at,
        error=firmware.cve_match_error,
        result=CveMatchRunResult(**raw) if raw else None,
    )


async def _run_cve_match_background(
    firmware_id: uuid.UUID,
    force_rescan: bool,
) -> None:
    """Detached cve-match runner.

    Owns its own ``AsyncSession`` so the FastAPI request that returned
    the 202 can close cleanly. Mirrors ``_run_unpack_background`` in
    ``routers/firmware.py`` and ``_run_campaign_spawn_background`` in
    ``routers/fuzzing.py``.

    On entry: flips ``cve_match_status`` from ``queued`` → ``running``.
    On clean return: persists the aggregate via :func:`_aggregate_match_result`
    and flips status to ``completed``.
    On exception: flips status to ``failed`` and stores a short
    traceback summary on ``cve_match_error`` for the UI to surface.
    """
    started = datetime.utcnow()
    try:
        async with async_session_factory() as db:
            try:
                # Mark running. Use a fresh select so we don't carry over
                # any stale ORM state from the request session that
                # queued the job.
                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    logger.warning(
                        "cve-match background: firmware %s vanished before run",
                        firmware_id,
                    )
                    return
                fw.cve_match_status = "running"
                fw.cve_match_started_at = started
                fw.cve_match_error = None
                fw.cve_match_result = None
                await db.commit()

                # Heavy work — streaming tier-4 persist (commit 5fddd6d)
                # bounds memory; runtime is governed by the matcher's
                # own logging (cve-match: tier-N done in N.NNs).
                result = await match_firmware_cves(
                    firmware_id, db, force_rescan=force_rescan
                )
                await db.commit()

                aggregate = _aggregate_match_result(result)
                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    return
                fw.cve_match_status = "completed"
                fw.cve_match_finished_at = datetime.utcnow()
                fw.cve_match_result = aggregate.model_dump()
                fw.cve_match_error = None
                await db.commit()
                logger.info(
                    "cve-match background: firmware %s completed (count=%d, rows=%d)",
                    firmware_id,
                    aggregate.count,
                    aggregate.rows,
                )
            except Exception as exc:
                await db.rollback()
                # Best-effort failure persistence on a fresh session —
                # the rolled-back one can't be reused after the rollback
                # invalidates its state and we still want the row to
                # carry the error for the UI poller.
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
                        fail_fw.cve_match_status = "failed"
                        fail_fw.cve_match_finished_at = datetime.utcnow()
                        fail_fw.cve_match_error = err_summary
                        await fail_db.commit()
                logger.exception(
                    "cve-match background: firmware %s failed", firmware_id
                )
    except Exception:
        # Outer guard — never let the event loop crash on a background
        # job. A DB unavailability mid-run lands here.
        logger.exception(
            "cve-match background: unrecoverable error for firmware %s",
            firmware_id,
        )


@router.post("/cve-match", response_model=CveMatchStatusResponse, status_code=202)
@limiter.limit(TIER_A_HEAVY)
async def run_cve_match(
    request: Request,
    force_rescan: bool = False,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> CveMatchStatusResponse:
    """Enqueue a cve-match run for the resolved firmware (Rule #29).

    Returns 202 Accepted with the firmware row in ``cve_match_status="queued"``.
    The frontend polls ``GET /cve-match/status`` every 2 s (firmware-unpack
    precedent) until ``status`` flips to ``completed`` (success — read
    ``result``) or ``failed`` (read ``error``).

    Why 202 rather than 200: the matcher's tier-4 cartesian (kernel CVEs ×
    kernel module blobs) reaches 2.65 M rows on Yocto firmware and runs
    ~7 minutes end-to-end even with the streaming Core insert (commit
    5fddd6d) — past every reasonable reverse-proxy ceiling
    (nginx 60 s, Cloudflare 100 s, ALB 60 s). See CLAUDE.md Rule #29
    and the cve-match-residual-oom-2026-04-25 intake.

    Idempotency: a POST while the firmware's status is already
    ``queued`` or ``running`` returns 409 with the in-flight status
    rather than spawning a second run. The frontend should poll
    ``/cve-match/status`` to observe the existing run.
    """
    if firmware.cve_match_status in ("queued", "running"):
        raise HTTPException(
            409,
            f"cve-match already {firmware.cve_match_status} for this firmware",
        )

    firmware.cve_match_status = "queued"
    firmware.cve_match_started_at = None
    firmware.cve_match_finished_at = None
    firmware.cve_match_error = None
    firmware.cve_match_result = None
    # Commit before scheduling the background task so its fresh session
    # observes the queued row.
    await db.commit()
    await db.refresh(firmware)

    asyncio.create_task(
        _run_cve_match_background(firmware.id, force_rescan)
    )
    return _firmware_to_status(firmware)


@router.get("/cve-match/status", response_model=CveMatchStatusResponse)
async def get_cve_match_status(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> CveMatchStatusResponse:
    """Return the current cve-match status snapshot for the resolved firmware.

    The frontend polls this every 2 s after a 202 from POST /cve-match
    until ``status`` flips to ``completed`` or ``failed``. Mirrors the
    firmware-unpack polling shape used by ProjectDetailPage.
    """
    return _firmware_to_status(firmware)


@router.get("/cdx.json")
async def export_hbom(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Export a CycloneDX v1.6 HBOM for the resolved firmware.

    Emits one ``hardware`` + one ``firmware`` component per detected blob,
    linked via ``dependencies.provides``.  Any ``sbom_vulnerabilities``
    rows with ``blob_id`` set are attached to the corresponding firmware
    component bom-ref.

    The response is served as ``application/json`` (FastAPI default) and
    is structurally JSON rather than matching a Pydantic schema — the
    CycloneDX spec is the contract.
    """
    return await build_hbom(firmware.id, db)


@router.get("/{blob_id}", response_model=HardwareFirmwareBlobResponse)
async def get_blob(
    blob_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareBlobResponse:
    """Fetch a single detected hardware firmware blob by id."""
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.id == blob_id,
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    blob = (await db.execute(stmt)).scalar_one_or_none()
    if blob is None:
        raise HTTPException(404, "Blob not found")
    return _blob_to_response(blob)


@router.get("/{blob_id}/cves")
async def get_blob_cves(
    blob_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return persisted CVE matches for a single hardware firmware blob."""
    # Validate the blob belongs to this firmware before returning CVEs.
    blob_stmt = select(HardwareFirmwareBlob.id).where(
        HardwareFirmwareBlob.id == blob_id,
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    if (await db.execute(blob_stmt)).scalar_one_or_none() is None:
        raise HTTPException(404, "Blob not found")

    stmt = (
        select(SbomVulnerability)
        .where(
            SbomVulnerability.blob_id == blob_id,
            SbomVulnerability.firmware_id == firmware.id,
        )
        .order_by(SbomVulnerability.created_at.desc())
    )
    vulns = (await db.execute(stmt)).scalars().all()  # bounded: CVEs for a single blob_id
    return [
        {
            "id": str(v.id),
            "blob_id": str(v.blob_id) if v.blob_id else None,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "description": v.description,
            "match_confidence": v.match_confidence,
            "match_tier": v.match_tier,
            "resolution_status": v.resolution_status,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in vulns
    ]


def _infer_format(driver_path: str, source: str) -> str:
    if source == "kmod_modinfo":
        return "ko"
    if source == "vmlinux_strings":
        return "vmlinux"
    if source == "dtb_firmware_name":
        return "dtb"
    return "unknown"
