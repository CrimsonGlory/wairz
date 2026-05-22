"""REST endpoints for attack surface analysis."""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.attack_surface import AttackSurfaceEntry
from app.models.finding import Finding
from app.rate_limit import TIER_A_HEAVY, limiter
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.attack_surface import (
    AttackSurfaceEntryResponse,
    AttackSurfaceScanRequest,
    AttackSurfaceScanResponse,
    AttackSurfaceSummary,
)
from app.schemas.pagination import Page
from app.services.jsonb_normalizers import (
    _normalize_attack_surface_entries_dangerous_imports,
    _normalize_attack_surface_entries_input_categories,
    _stamp_attack_surface_entries_score_breakdown,
)
from app.utils.pagination import paginate_query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/attack-surface",
    tags=["attack-surface"],
)


@router.get("", response_model=Page[AttackSurfaceEntryResponse])
async def list_attack_surface_entries(
    project_id: uuid.UUID,
    min_score: int = Query(0, ge=0, le=100, description="Minimum attack surface score"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List attack surface entries sorted by score descending (paged)."""
    stmt = (
        select(AttackSurfaceEntry)
        .where(
            AttackSurfaceEntry.project_id == project_id,
            AttackSurfaceEntry.firmware_id == firmware.id,
            AttackSurfaceEntry.attack_surface_score >= min_score,
        )
        .order_by(AttackSurfaceEntry.attack_surface_score.desc())
    )
    items, total = await paginate_query(db, stmt, offset=offset, limit=limit)
    return Page[AttackSurfaceEntryResponse](
        items=[AttackSurfaceEntryResponse.model_validate(e) for e in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/scan", response_model=AttackSurfaceScanResponse)
@limiter.limit(TIER_A_HEAVY)
async def trigger_attack_surface_scan(
    request: Request,
    project_id: uuid.UUID,
    body: AttackSurfaceScanRequest | None = None,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an attack surface scan of the firmware.

    Returns cached results unless force_rescan=True.
    """
    force_rescan = body.force_rescan if body else False
    path_filter = body.path if body else None

    # Check for cached results
    if not force_rescan:
        count = await db.scalar(
            select(func.count(AttackSurfaceEntry.id)).where(
                AttackSurfaceEntry.project_id == project_id,
                AttackSurfaceEntry.firmware_id == firmware.id,
            )
        )
        if count and count > 0:
            stmt = (
                select(AttackSurfaceEntry)
                .where(
                    AttackSurfaceEntry.project_id == project_id,
                    AttackSurfaceEntry.firmware_id == firmware.id,
                )
                .order_by(AttackSurfaceEntry.attack_surface_score.desc())
            )
            result = await db.execute(stmt)
            entries = result.scalars().all()  # bounded: scan response includes all entries for this firmware
            return AttackSurfaceScanResponse(
                entries=[AttackSurfaceEntryResponse.model_validate(e) for e in entries],
                summary=_build_summary(entries),
                cached=True,
            )

    # Run scan in thread executor (CPU-bound)
    from app.services.attack_surface_service import scan_attack_surface

    loop = asyncio.get_running_loop()
    try:
        scan_results = await loop.run_in_executor(
            None,
            scan_attack_surface,
            firmware.extracted_path,
            path_filter,
        )
    except Exception as e:
        raise HTTPException(500, f"Attack surface scan failed: {e}")

    # Clear old entries
    await db.execute(
        delete(AttackSurfaceEntry).where(
            AttackSurfaceEntry.project_id == project_id,
            AttackSurfaceEntry.firmware_id == firmware.id,
        )
    )

    # Persist
    db_entries = []
    for r in scan_results:
        entry = AttackSurfaceEntry(
            project_id=project_id,
            firmware_id=firmware.id,
            binary_path=r.path,
            binary_name=r.name,
            architecture=r.architecture,
            file_size=r.file_size,
            attack_surface_score=r.score,
            score_breakdown=_stamp_attack_surface_entries_score_breakdown(dict(r.breakdown)),
            is_setuid=r.is_setuid,
            is_network_listener=r.is_network_listener,
            is_cgi_handler=r.is_cgi_handler,
            has_dangerous_imports=r.has_dangerous_imports,
            dangerous_imports=_normalize_attack_surface_entries_dangerous_imports(r.dangerous_imports),
            input_categories=_normalize_attack_surface_entries_input_categories(r.input_categories),
            auto_findings_generated=bool(r.findings),
        )
        db.add(entry)
        db_entries.append(entry)

        # Auto-findings — Rule #35b explicit confidence + firmware_id
        # (audit-2026-05-04 width-canary surfaced this site; the source
        # `r.findings` carries no confidence signal because attack-
        # surface heuristics are environment-shaped — listening port
        # detection + service banner inference; "medium" reflects the
        # heuristic class).
        for finding_data in r.findings:
            finding = Finding(
                project_id=project_id,
                firmware_id=firmware.id,
                confidence="medium",
                title=finding_data["title"],
                severity=finding_data["severity"],
                description=finding_data["description"],
                file_path=finding_data.get("file_path"),
                cwe_ids=finding_data.get("cwe_ids"),
                source="attack_surface",
            )
            db.add(finding)

    await db.flush()

    responses = [AttackSurfaceEntryResponse.model_validate(e) for e in db_entries]
    return AttackSurfaceScanResponse(
        entries=responses,
        summary=_build_summary(db_entries),
        cached=False,
    )


@router.get("/{entry_id}", response_model=AttackSurfaceEntryResponse)
async def get_attack_surface_entry(
    project_id: uuid.UUID,
    entry_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Get a single attack surface entry by ID."""
    stmt = select(AttackSurfaceEntry).where(
        AttackSurfaceEntry.id == entry_id,
        AttackSurfaceEntry.project_id == project_id,
    )
    result = await db.execute(stmt)
    entry = result.scalars().first()
    if not entry:
        raise HTTPException(404, "Attack surface entry not found")
    return entry


def _build_summary(entries: list) -> AttackSurfaceSummary:
    """Build summary statistics from a list of entries."""
    total = len(entries)
    critical = 0
    high = 0
    medium = 0
    low = 0
    all_categories: set[str] = set()

    for e in entries:
        score = e.attack_surface_score
        if score >= 75:
            critical += 1
        elif score >= 50:
            high += 1
        elif score >= 25:
            medium += 1
        else:
            low += 1
        cats = _normalize_attack_surface_entries_input_categories(e.input_categories)
        all_categories.update(cats)

    return AttackSurfaceSummary(
        total_binaries=total,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        top_categories=sorted(all_categories),
    )
