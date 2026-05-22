"""HTTP router for the bare-metal MCU/DSP audit surface (CLAUDE.md Rule #52).

Per-surface endpoint shape per Scout EE §4 recommendation: a focused
``POST /api/v1/projects/{p}/firmware/{f}/bare-metal-hint`` for now;
generic ``POST /external-descriptors`` alias deferred to Rule-of-Two
when the second descriptor type ships (Rule #19 evidence-first — don't
generalize on a single use case).

The endpoint is the external-ingestor protocol Phase 1 deferred to Phase 2:
Velociraptor / dissect / custom pipelines push structured chip hints
into wairz. Operators consume the same surface via the MCP tool
``submit_bare_metal_descriptor`` (same service layer, same idempotency
contract, different transport).

**Rule #33 .a contract:**
  - Idempotent on ``(firmware_id, ingestor_id, descriptor_hash)``.
  - Same hash from same ingestor → 200 idempotent replay.
  - Different hash from same ingestor → 409 conflict.
  - Different ingestor → new row, provenance-arbitrated at walker time
    (Scout GG §SC5 fix at ``bare_metal_walker._most_recent_descriptor``).

**Rule #51 rate-limit:** ``TIER_A_LIGHT_ACK`` (30/hour per IP) — ack is
sub-second (single INSERT + commit); walker auto-trigger fires detached.

**Scout GG §SC4 multi-tenancy:** Phase 1 trust model is "single project
API key → ``unauthenticated_external``". Per-ingestor scoped keys
(Scout EE §5.4) ship in Phase 3 when the second external integration
partner arrives — Rule #19 evidence-first vs over-engineering for one
ingestor.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import BareMetalDescriptor, Firmware, Project
from app.rate_limit import TIER_A_LIGHT_ACK, limiter
from app.services.hardware_firmware.chip_catalog import get_chip_catalog
from app.services.jsonb_normalizers import _stamp_bare_metal_descriptor_payload

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v1/projects/{project_id}/firmware/{firmware_id}",
    tags=["bare-metal"],
)


class BareMetalHintRequest(BaseModel):
    """Operator / external-ingestor body for a bare-metal chip hint.

    Inline ``ChipFamilyManifest`` not exposed via HTTP in Phase 1 — Scout
    CC §SC14 path defers to Phase 2.
    """

    chip_family_hint: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*/[a-z][a-z0-9_]*$",
        description="vendor/family identifier from the catalog (e.g. 'ti/tms320f28066')",
    )
    domain_hint: str | None = Field(
        default=None,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        description="Optional domain name; defaults to the family's first declared domain",
    )
    ingestor_id: str | None = Field(
        default=None,
        max_length=128,
        description="Optional ingestor identifier (Velociraptor instance / operator handle); auto-defaults to 'http-default'",
    )
    evidence: dict | None = Field(
        default=None,
        description="Optional free-form evidence (JTAG session log, CLASSID/REVID, extraction tool, ...)",
    )

    model_config = {"extra": "forbid"}


class BareMetalHintResponse(BaseModel):
    """Response shape — descriptor row carried back to the ingestor."""

    descriptor_id: str
    firmware_id: str
    chip_family_hint: str
    domain_hint: str
    descriptor_source: str
    ingestor_id: str | None
    descriptor_hash: str
    received_at: str
    status: str   # "created" | "idempotent_replay"


@router.post("/bare-metal-hint", response_model=BareMetalHintResponse, status_code=201)
@limiter.limit(TIER_A_LIGHT_ACK)
async def push_bare_metal_hint(
    request: Request,
    response: Response,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    body: BareMetalHintRequest,
    db: AsyncSession = Depends(get_db),
) -> BareMetalHintResponse:
    """Push an external chip-family hint for a bare-metal firmware.

    Idempotent on ``(firmware_id, ingestor_id, descriptor_hash)`` per
    Rule #33 .a. Sub-second ACK + detached walker auto-trigger; rate-
    limited at ``TIER_A_LIGHT_ACK`` per Rule #51.

    Trust model (Phase 1): global API key authenticates the request →
    ``descriptor_source = unauthenticated_external``. Per-ingestor
    scoped keys + ``attested_external`` ship in Phase 3 (Scout EE §5.4).
    """
    # 404 — project must exist
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail=f"project {project_id} not found")

    # 404 — firmware must exist + belong to this project
    firmware = await db.get(Firmware, firmware_id)
    if firmware is None or firmware.project_id != project_id:
        raise HTTPException(status_code=404, detail=f"firmware {firmware_id} not found in project {project_id}")

    # 422 — chip_family_hint must be in the catalog
    catalog = get_chip_catalog()
    if body.chip_family_hint not in catalog:
        raise HTTPException(
            status_code=422,
            detail={
                "error": f"chip_family_hint {body.chip_family_hint!r} not in catalog",
                "known_families": sorted(catalog.keys()),
                "hint": "drop a YAML at data/chip_families/<vendor>/<family>.yaml — operators may extend the catalog without a rebuild",
            },
        )
    manifest = catalog[body.chip_family_hint]
    domain_hint = body.domain_hint or manifest.domains[0].name
    if domain_hint not in {d.name for d in manifest.domains}:
        raise HTTPException(
            status_code=422,
            detail={
                "error": f"domain_hint {domain_hint!r} not declared on family {body.chip_family_hint}",
                "known_domains": [d.name for d in manifest.domains],
            },
        )

    # Build the canonical payload + idempotency hash
    ingestor_id = body.ingestor_id or "http-default"
    payload = _stamp_bare_metal_descriptor_payload({
        "firmware_id": str(firmware_id),
        "descriptor_source": "unauthenticated_external",
        "chip_family_hint": body.chip_family_hint,
        "domain_hint": domain_hint,
        "evidence": body.evidence or {},
        "received_at": datetime.now(UTC).isoformat(),
    })
    # Stable hash excluding the received_at timestamp (replay across days = same descriptor)
    hash_input = {k: v for k, v in payload.items() if k != "received_at"}
    descriptor_hash = hashlib.sha256(
        json.dumps(hash_input, sort_keys=True).encode("utf-8")
    ).hexdigest()[:32]

    # Rule #33 .a: check existing — idempotent or conflict
    existing = await db.execute(
        select(BareMetalDescriptor).where(
            BareMetalDescriptor.firmware_id == firmware_id,
            BareMetalDescriptor.ingestor_id == ingestor_id,
        )
    )
    prior_rows = list(existing.scalars())
    same_hash_row = next((r for r in prior_rows if r.descriptor_hash == descriptor_hash), None)
    if same_hash_row is not None:
        # 200 idempotent replay
        response.status_code = 200
        return BareMetalHintResponse(
            descriptor_id=str(same_hash_row.id),
            firmware_id=str(firmware_id),
            chip_family_hint=body.chip_family_hint,
            domain_hint=domain_hint,
            descriptor_source="unauthenticated_external",
            ingestor_id=ingestor_id,
            descriptor_hash=descriptor_hash,
            received_at=same_hash_row.received_at.isoformat(),
            status="idempotent_replay",
        )
    if prior_rows:
        # 409 conflict — same ingestor previously pushed a different hash;
        # supersedes_id required for explicit update (deferred to Phase 2.5).
        latest = max(prior_rows, key=lambda r: r.received_at)
        raise HTTPException(
            status_code=409,
            detail={
                "error": f"ingestor {ingestor_id!r} previously pushed a different descriptor for this firmware",
                "prior_descriptor_id": str(latest.id),
                "prior_descriptor_hash": latest.descriptor_hash,
                "hint": "explicit supersedes_id required to update — Phase 2.5 feature; use a unique ingestor_id per ingestor in the meantime",
            },
        )

    desc = BareMetalDescriptor(
        firmware_id=firmware_id,
        descriptor_source="unauthenticated_external",
        ingestor_id=ingestor_id,
        descriptor_hash=descriptor_hash,
        payload=payload,
    )
    db.add(desc)
    await db.commit()
    await db.refresh(desc)

    response.headers["X-Descriptor-Id"] = str(desc.id)
    return BareMetalHintResponse(
        descriptor_id=str(desc.id),
        firmware_id=str(firmware_id),
        chip_family_hint=body.chip_family_hint,
        domain_hint=domain_hint,
        descriptor_source="unauthenticated_external",
        ingestor_id=ingestor_id,
        descriptor_hash=descriptor_hash,
        received_at=desc.received_at.isoformat(),
        status="created",
    )
