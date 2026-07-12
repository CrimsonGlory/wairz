"""Per-blob ELF symbol-presence row for the wairz reachability bridge (binary axis).

One row per ELF :class:`HardwareFirmwareBlob`, holding the DEFINED + IMPORTED symbol sets the
bridge producer (:mod:`app.services.reachability_export`) extracts. PERSISTING per-blob — rather
than embedding every symbol string in one firmware-level JSONB — keeps the firmware-level
``reachability_export_walk_result`` aggregate small (an ELF symbol table is 3k-30k strings and a
firmware can carry hundreds of ELF blobs) AND lets the Rule #44
``lookup_reachable_symbol_across_firmwares`` MCP tool answer "which firmwares DEFINE symbol X"
with a GIN-indexed JSONB-containment query (``defined_symbols @> '["X"]'``) instead of a Python
scan of a giant aggregate.

PARSE-ONLY (Rule #36 / #45): rows hold symbol NAMES read from the ELF symbol table AS DATA —
nothing here executes a binary. The Iron Law — symbol absence is valid ONLY on a NON-STRIPPED,
sha256-matched binary — is enforced at the bridge producer/consumer
(:mod:`app.services.reachability_export` / the framework ``src/bridge/symbol_analysis``). The
completeness flags (``stripped`` / ``has_symtab`` / ``has_dynsym``) travel WITH each row so a
downstream consumer re-checks trustworthiness and NEVER infers code-absence from a stripped or
sha-mismatched blob.

Per CLAUDE.md Rule #35c: the two JSONB columns (``defined_symbols`` / ``imported_symbols``) carry
normalisers in :mod:`app.services.jsonb_normalizers`. The firmware-level aggregate (counts) lands
on ``Firmware.reachability_export_walk_result`` with its own SCHEMA_VERSION + stamp.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ReachabilityExportRecord(Base):
    """One ELF blob's symbol-presence facts (per-blob, GIN-queryable ``defined_symbols``)."""

    __tablename__ = "reachability_export_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this blob belongs to. Cascade DELETE so removing a
    # firmware row removes its symbol records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # FK to the source HardwareFirmwareBlob. SET NULL (not CASCADE) so a re-detection that
    # rewrites blob rows does not silently delete symbol records mid-flight; the walker
    # re-populates per firmware. blob_path + blob_sha256 are denormalised so the wire record +
    # the Iron-Law sha256 correspondence re-check need no join.
    blob_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("hardware_firmware_blobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Detection-root-relative path (the wire-format key the framework consumer matches).
    blob_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    blob_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # DEFINED function set (st_shndx != SHN_UNDEF, STT_FUNC/STT_GNU_IFUNC) — the symbol-presence
    # axis the framework intersects its per-CVE sink set against. GIN-indexed for the Rule #44
    # cross-firmware "which firmwares define symbol X" containment query.
    defined_symbols: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # IMPORTED set (SHN_UNDEF) — what this binary calls out to.
    imported_symbols: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Completeness flags — travel WITH the row so a consumer re-checks trustworthiness (Iron Law).
    # A stripped blob's empty defined set is absence-of-EVIDENCE, never proof of code-absence.
    stripped: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    has_symtab: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    has_dynsym: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    arch: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # One symbol record per (firmware, blob content) — mirrors the blob uq.
        UniqueConstraint("firmware_id", "blob_sha256", name="uq_reachexport_firmware_sha256"),
        # Per-firmware fetch (the walker clears + re-populates per firmware; the aggregate read).
        Index("ix_reachexport_firmware", "firmware_id"),
        # The Rule #44 lookup: defined_symbols @> '["X"]' across firmwares (GIN containment).
        Index(
            "ix_reachexport_defined_gin",
            "defined_symbols",
            postgresql_using="gin",
        ),
    )
