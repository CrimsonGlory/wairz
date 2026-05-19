"""ORM model for the bare-metal descriptor store (CLAUDE.md Rule #52).

External-ingestor and operator chip-hint records pushed via:

* MCP tool ``submit_bare_metal_descriptor`` (operator-authenticated session)
* HTTP endpoint ``POST /api/v1/projects/{p}/firmware/{f}/bare-metal-hint``
  (Velociraptor / external ingestor with API key)
* Internal autodetect emit (``YamlDrivenMatcher`` writes the auto match)

Rule #33 .a idempotency contract: same ``(firmware_id, ingestor_id,
descriptor_hash)`` triple is a no-op replay; different hash from same
ingestor within a 60s window = 409 conflict; different ingestor IDs
coexist with provenance arbitration (Scout CC §SC11).

The walker (``services/bare_metal_walker.py``) reads the most recent
non-superseded descriptor per firmware AND the auto-detect result; the
descriptor wins by provenance precedence:

    operator > attested_external > unauthenticated_external > auto_detection
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BareMetalDescriptor(Base):
    """One chip-hint descriptor pushed for a firmware row.

    Stored as append-only with ``supersedes_id`` linkage — provides full
    audit trail of operator + external-ingestor decisions over time.
    The walker reads the MOST RECENT NON-SUPERSEDED descriptor per
    firmware, ordered by ``(received_at DESC)``.
    """

    __tablename__ = "bare_metal_descriptors"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Closed Literal mirrored in app/schemas/chip_family.py DescriptorSource
    descriptor_source: Mapped[str] = mapped_column(String(32), nullable=False)
    ingestor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    descriptor_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bare_metal_descriptors.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_bare_metal_descriptors_firmware_received",
            "firmware_id",
            text("received_at DESC"),
        ),
        # Partial unique — Rule #33 .a idempotency at the storage layer.
        # Only enforced when both ingestor_id AND descriptor_hash are present.
        Index(
            "ux_bare_metal_descriptors_idempotency",
            "firmware_id",
            "ingestor_id",
            "descriptor_hash",
            unique=True,
            postgresql_where=text(
                "ingestor_id IS NOT NULL AND descriptor_hash IS NOT NULL"
            ),
        ),
    )


__all__ = ["BareMetalDescriptor"]
