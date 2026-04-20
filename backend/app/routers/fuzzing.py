"""REST endpoints for AFL++ fuzzing campaigns."""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.fuzzing import (
    FuzzingCampaignCreateRequest,
    FuzzingCampaignResponse,
    FuzzingCrashDetailResponse,
    FuzzingCrashResponse,
    FuzzingTargetAnalysis,
)
from app.services.fuzzing_service import FuzzingService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/fuzzing",
    tags=["fuzzing"],
)


async def _run_campaign_spawn_background(campaign_id: uuid.UUID) -> None:
    """Spawn the AFL++ container for a queued campaign in the background.

    Owns its own ``AsyncSession`` so the FastAPI request session that
    returned the 202 can close cleanly. Mirrors
    ``_run_unpack_background`` in ``routers/firmware.py``.

    Errors are caught and logged; the service itself is responsible for
    flipping ``campaign.status`` to ``"error"`` on spawn failure. This
    wrapper's ``except`` is a belt-and-braces guard for unexpected
    exceptions (e.g. DB connection issues) so we never crash the event
    loop for a background job.
    """
    try:
        async with async_session_factory() as db:
            try:
                svc = FuzzingService(db)
                await svc._spawn_campaign_container(campaign_id)
                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception(
            "Background fuzzing-container spawn failed for campaign %s",
            campaign_id,
        )


@router.get("/analyze", response_model=FuzzingTargetAnalysis)
async def analyze_target(
    project_id: uuid.UUID,
    path: str,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Analyze a binary for fuzzing suitability."""
    svc = FuzzingService(db)
    try:
        analysis = await svc.analyze_target(firmware, path)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return analysis


@router.post("/campaigns", response_model=FuzzingCampaignResponse, status_code=201)
async def create_campaign(
    project_id: uuid.UUID,
    request: FuzzingCampaignCreateRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Create a new fuzzing campaign."""
    svc = FuzzingService(db)
    config = {
        "timeout_per_exec": request.timeout_per_exec,
        "memory_limit": request.memory_limit,
        "dictionary": request.dictionary,
        "seed_corpus": request.seed_corpus,
    }
    try:
        campaign = await svc.create_campaign(firmware, request.binary_path, config)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return campaign


@router.post(
    "/campaigns/{campaign_id}/start",
    response_model=FuzzingCampaignResponse,
    status_code=202,
)
async def start_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Enqueue a fuzzing campaign for background start.

    Returns 202 Accepted with the campaign row in ``status="queued"``.
    The frontend should poll ``GET /campaigns/{id}`` every 2 s (matches
    the firmware-unpack pattern) and expect the status to transition to
    ``"running"`` (container spawned successfully) or ``"error"`` (spawn
    failed; ``error_message`` populated).

    Why 202 rather than 200: container spin-up + seed-corpus upload can
    take 30-60 s on a cold docker daemon and the backend synchronous
    ceiling is ``fuzzing_timeout_minutes=120`` (7200 s) — well past any
    reverse-proxy tolerance (nginx 60 s, Cloudflare 100 s, ALB 60 s).
    See CLAUDE.md Rule #29.
    """
    svc = FuzzingService(db)
    try:
        campaign = await svc.start_campaign(campaign_id, project_id)
        await db.flush()
        # The session is committed automatically on a clean return from
        # the FastAPI dependency (via ``get_db``). We commit here
        # explicitly so the background task sees the ``queued`` row
        # when it opens its own session.
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    # Schedule the container spawn outside the HTTP request / response
    # cycle. ``asyncio.create_task`` is acceptable here because the
    # spawn phase is short-lived (typically <30 s) and the arq pool is
    # not currently wired for fuzzing jobs — this matches the firmware
    # unpack fallback path in routers/firmware.py lines 182-184.
    asyncio.create_task(_run_campaign_spawn_background(campaign_id))
    return campaign


@router.post("/campaigns/{campaign_id}/stop", response_model=FuzzingCampaignResponse)
async def stop_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop a running fuzzing campaign."""
    svc = FuzzingService(db)
    try:
        campaign = await svc.stop_campaign(campaign_id, project_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return campaign


@router.get("/campaigns", response_model=list[FuzzingCampaignResponse])
async def list_campaigns(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all fuzzing campaigns for this project."""
    svc = FuzzingService(db)
    campaigns = await svc.list_campaigns(project_id)
    # Update status for running campaigns sequentially
    # (AsyncSession is not safe for concurrent coroutine access)
    for i, campaign in enumerate(campaigns):
        if campaign.status == "running":
            try:
                campaigns[i] = await svc.get_campaign_status(campaign.id)
            except Exception:
                continue

    return campaigns


@router.get("/campaigns/{campaign_id}", response_model=FuzzingCampaignResponse)
async def get_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get campaign details with live stats."""
    svc = FuzzingService(db)
    try:
        campaign = await svc.get_campaign_status(campaign_id, project_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return campaign


@router.get("/campaigns/{campaign_id}/crashes", response_model=list[FuzzingCrashResponse])
async def list_crashes(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all crashes for a campaign."""
    svc = FuzzingService(db)
    crashes = await svc.get_crashes(campaign_id, project_id)
    return crashes


@router.get(
    "/campaigns/{campaign_id}/crashes/{crash_id}",
    response_model=FuzzingCrashDetailResponse,
)
async def get_crash_detail(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    crash_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed crash information including hex-encoded input."""
    svc = FuzzingService(db)
    try:
        crash = await svc.get_crash_detail(campaign_id, crash_id, project_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))

    # Build response with hex-encoded crash input
    resp = FuzzingCrashDetailResponse.model_validate(crash)
    if crash.crash_input:
        resp.crash_input_hex = crash.crash_input.hex()
    return resp


@router.post(
    "/campaigns/{campaign_id}/crashes/{crash_id}/triage",
    response_model=FuzzingCrashResponse,
)
async def triage_crash(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    crash_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Triage a crash: reproduce with GDB and classify exploitability."""
    svc = FuzzingService(db)
    try:
        crash = await svc.triage_crash(campaign_id, crash_id, project_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return crash
