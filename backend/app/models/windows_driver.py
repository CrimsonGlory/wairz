"""Windows driver-package extract table.

One row per INF/CAT/SYS triplet detected in a hardware-firmware blob
(FK→``hardware_firmware_blobs.id``, ON DELETE CASCADE). A single
firmware may carry many drivers (Windows installs commonly ship 100+
inbox drivers in ``C:/Windows/INF`` and ``C:/Windows/System32/
DriverStore``).

The ``signing_tier`` column is the Persona-E #13 capability badge —
``whql`` / ``attestation`` / ``cross_signed`` / ``unsigned`` /
``unknown``. The tier determines which Windows kernel-mode loader
will accept the driver (HVCI requires WHQL + EV; SecureBoot requires
at least cross-signed). DB CHECK enforces the allowlist per Rule #33
.c; the matching Pydantic ``WindowsDriverSigningTier`` Literal at the
writer boundary catches code-side typos at load time.

The ``inf_metadata`` JSONB column carries the parsed [Version] /
[Manufacturer] / [Models] / [Strings] block content under the
canonical schema documented in
``app.services.jsonb_normalizers._normalize_windows_drivers_inf_metadata``.
Schema version is stamped by the writer via the matching ``_stamp_*``
helper (Rule #35c).

Rule #36 no-execute discipline: this table holds DATA only — γ.5
reads INF / CAT files via parsers (no ``rundll32``, no ``.inf``
install, no shell-out) and validates the CAT via the existing
β.4-β.10 signify Authenticode stack. Paths are surfaced to the
operator for triage; nothing in wairz invokes them.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsDriver(Base):
    """Per-driver-package record for a hardware-firmware blob."""

    __tablename__ = "windows_drivers"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the hardware-firmware blob that contained this driver.
    # Cascade DELETE so removing a blob row removes its driver rows.
    blob_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Anchor path — typically the INF path. Used as the dedup key
    # alongside blob_id so re-extracts UPDATE the existing row.
    driver_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Triplet path components. Nullable because some drivers ship
    # INF-only (test/dev signed, no CAT) or SYS-only (preinstalled
    # DriverStore subdir without an associated INF on disk).
    inf_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    cat_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sys_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # INF [Version] block — driver class + class GUID + provider +
    # version. class_guid is indexed for cross-firmware "show every
    # X-class driver" queries.
    inf_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    class_guid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    driver_provider: Mapped[str | None] = mapped_column(String(256), nullable=True)
    driver_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    driver_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # INF [Manufacturer] — primary manufacturer string for operator
    # display. Multi-manufacturer INFs surface secondary entries via
    # inf_metadata JSONB.
    manufacturer: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Plug-and-Play hardware IDs from [Models]. Postgres ARRAY so the
    # driver matrix can answer "which firmware contains a driver for X"
    # via ``WHERE 'PCI\\VEN_1234&DEV_5678' = ANY(pnp_ids)``.
    pnp_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)

    # CAT signature outcome — populated by γ.5 via the existing
    # β.4-β.10 signify stack (no new crypto code in γ).
    catalog_signed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    catalog_signer_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    catalog_signer_issuer: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Persona-E #13 capability badge — durable allowlist below per
    # Rule #33 .c. NULL not allowed; default 'unknown' captures the
    # "tier classifier didn't reach this row" case explicitly.
    signing_tier: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unknown"
    )

    # Parsed INF data. See the matching normaliser for the canonical
    # shape; writers stamp schema_version via
    # ``_stamp_windows_drivers_inf_metadata``.
    inf_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # Rule #33 .c durable gate. Pydantic Literal at writer boundary
        # catches typos at load time; this CHECK catches direct-SQL
        # writes that bypass the Pydantic layer.
        CheckConstraint(
            "signing_tier IN ('whql', 'attestation', 'cross_signed', 'unsigned', 'unknown')",
            name="ck_windows_drivers_signing_tier",
        ),
        # One driver row per (blob, driver_path) — re-extracts UPDATE
        # not INSERT.
        UniqueConstraint(
            "blob_id",
            "driver_path",
            name="uq_windows_drivers_blob_path",
        ),
        Index("ix_windows_drivers_blob_id", "blob_id"),
        # Partial index on class_guid (NULL excluded — most rows
        # populate this, but a partial index keeps the index small for
        # the dominant non-NULL access pattern).
        Index(
            "ix_windows_drivers_class_guid",
            "class_guid",
            postgresql_where=text("class_guid IS NOT NULL"),
        ),
        Index("ix_windows_drivers_signing_tier", "signing_tier"),
    )
