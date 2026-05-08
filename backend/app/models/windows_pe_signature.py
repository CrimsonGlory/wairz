"""Windows PE Authenticode + RICH + ARM-arch signatures table.

One row per PE binary in a hardware-firmware blob (FK→hardware_firmware_blobs.id,
ON DELETE CASCADE). Carries the Authenticode chain verdict, RICH header
fingerprint, DBX revocation cross-reference, ARM64EC/X dual-view metadata,
and signature-freshness time-anchor for Persona-E #2 / #10 / #16.

Per Persona-D #3.b the per-blob structure deserves its own table (not JSONB
on firmware.device_metadata) because:
  (a) The DBX cross-reference workflow needs efficient indexed
      ``WHERE leaf_serial IN (dbx_set)`` SELECTs across firmware.
  (b) The PE-Hardening-Dashboard frontend page sorts/filters per-PE rows.
  (c) Per-blob FK lets cascade DELETE clean up signatures when a firmware
      blob row is removed.

CHECK constraint on ``chain_status`` enforces the Persona-E #2 tri-state:
- ``valid_at_signing``: signature was valid at counter-signature timestamp
- ``valid_now``: signature still validates today (cert + chain + revocation)
- ``revoked``: cert in DBX OR CRL OR OCSP says no
- ``never_valid``: signature never validated (test/dev cert, broken chain)
- ``unknown``: validation skipped (offline data missing, malformed PE)
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
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsPESignature(Base):
    """Per-PE-binary Authenticode + RICH + arch-view signature record."""

    __tablename__ = "windows_pe_signatures"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the hardware-firmware blob this PE belongs to. Cascade
    # DELETE so removing a blob row removes its signature record.
    blob_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
        nullable=False,
        # Index defined explicitly in __table_args__ alongside the
        # other Phase-β query-pattern indexes (dbx, chain_status,
        # leaf_serial). Don't set ``index=True`` here too — the two
        # paths produce duplicate CREATE INDEX statements.
    )

    # ── Authenticode chain ────────────────────────────────────────
    signed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"),
    )
    signer_subject: Mapped[str | None] = mapped_column(Text)
    signer_issuer: Mapped[str | None] = mapped_column(Text)
    leaf_serial: Mapped[str | None] = mapped_column(String(128))
    sig_hash_algo: Mapped[str | None] = mapped_column(String(32))

    # Time-anchor (RFC 3161 counter-signature timestamp + TSA cert).
    tsa_authority: Mapped[str | None] = mapped_column(Text)
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Chain-status tri-state (see module docstring for the contract).
    chain_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unknown",
    )
    chain_json: Mapped[dict | None] = mapped_column(JSONB)

    # ── DBX revocation cross-reference ────────────────────────────
    dbx_revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"),
    )
    dbx_revocation_kb: Mapped[str | None] = mapped_column(String(32))

    # ── RICH header (Persona-E sec.1 line) ────────────────────────
    rich_header_json: Mapped[dict | None] = mapped_column(JSONB)

    # ── ARM64EC / ARM64X bimorphic detection (Persona-E #2 #3) ────
    # arch_view: dict of {primary, secondary, divergence_score}.
    # Single-arch PEs have arch_view=NULL; bimorphic populate.
    arch_view: Mapped[dict | None] = mapped_column(JSONB)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # Persona-E #2 tri-state. The CHECK is the durable gate (Rule
        # #33 .c) — a Pydantic Literal at the API/MCP boundary catches
        # writer-side typos but the CHECK catches direct-SQL writes
        # from cron scripts / manual fixes / partial-failure rollbacks.
        CheckConstraint(
            "chain_status IN ('valid_at_signing', 'valid_now', 'revoked', "
            "'never_valid', 'unknown')",
            name="ck_windows_pe_signatures_chain_status",
        ),
        # Phase β query-pattern indexes:
        # - blob_id: cascade traversal + per-blob lookup.
        # - leaf_serial: Persona-E #10 cross-firmware
        #   ``WHERE leaf_serial IN (dbx_set)`` rollup query.
        # - dbx_revoked: revocation rollup queries.
        # - chain_status: PE-Hardening-Dashboard filter chip queries.
        Index("ix_windows_pe_signatures_blob_id", "blob_id"),
        Index("ix_windows_pe_signatures_leaf_serial", "leaf_serial"),
        Index("ix_windows_pe_signatures_dbx", "dbx_revoked"),
        Index("ix_windows_pe_signatures_chain_status", "chain_status"),
    )
