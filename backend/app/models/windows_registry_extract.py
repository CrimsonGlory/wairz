"""Windows registry hive extract table.

One row per registry hive parsed out of a hardware-firmware blob
(FK→``hardware_firmware_blobs.id``, ON DELETE CASCADE). A single
firmware may carry multiple hives (SOFTWARE, SYSTEM, SAM, SECURITY,
NTUSER.DAT, UsrClass.dat, AmCache.hve, etc.) — each gets its own row.

The ``parsed_tree`` JSONB column carries the walked key/value tree
under the canonical schema documented in
``app.services.jsonb_normalizers._normalize_windows_registry_extracts_parsed_tree``.
Schema version is stamped by the writer via the matching ``_stamp_*``
helper so future walker shape revisions can be discriminated at the
read boundary (Rule #35c).

CHECK on ``walk_status`` enforces the per-hive parse-status tri-state
plus ``skipped``. The aggregate batch-walk status across ALL hives in
a firmware lives on the firmware row via
``firmware.registry_hive_walk_*`` columns (Phase γ.3, separate
migration).

Rule #36 no-execute discipline: this table holds DATA only — the
γ.4 worker reads hives via regipy (read-only library binding) and
writes the parsed payload here; nothing in wairz invokes ``regedit``,
``.reg`` apply, or any scriptable registry-modification action.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsRegistryExtract(Base):
    """Per-hive registry-walk record for a hardware-firmware blob."""

    __tablename__ = "windows_registry_extracts"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the hardware-firmware blob that contained this hive. Cascade
    # DELETE so removing a blob row removes its registry extracts.
    blob_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path within the blob's extracted tree; e.g.
    # "Windows/System32/config/SOFTWARE" or "Users/<user>/NTUSER.DAT".
    hive_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Hive flavor discriminator. Common values: SOFTWARE, SYSTEM, SAM,
    # SECURITY, NTUSER, UsrClass, AmCache, BBI, DEFAULT, COMPONENTS,
    # DRIVERS, ELAM, BCD, SCHEMA, unknown.
    hive_type: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unknown"
    )

    # Walk summary — operator-visible counts, also mirrored inside
    # parsed_tree so downstream MCP tools that fetch the row without
    # the JSONB column still see summary numbers.
    key_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    value_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Per-hive parse status (the aggregate batch-walk status across all
    # hives lives on firmware row via γ.3). The tri-state-plus-skipped
    # is enforced by both the Pydantic Literal at the writer boundary
    # and the DB CHECK below per Rule #33 .c.
    walk_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="completed"
    )
    walk_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Parsed key/value tree. See the matching normaliser for the
    # canonical shape; writers stamp schema_version via
    # ``_stamp_windows_registry_extracts_parsed_tree``.
    parsed_tree: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # Rule #33 .c — DB-side allowlist. Pydantic Literal at the writer
        # boundary catches code-side typos; this CHECK catches direct-SQL
        # writes that bypass the Pydantic layer.
        CheckConstraint(
            "walk_status IN ('completed', 'partial', 'failed', 'skipped')",
            name="ck_windows_registry_extracts_walk_status",
        ),
        # One extract per (blob, hive_path); re-walks UPDATE-not-INSERT.
        UniqueConstraint(
            "blob_id",
            "hive_path",
            name="uq_windows_registry_extracts_blob_path",
        ),
        Index("ix_windows_registry_extracts_blob_id", "blob_id"),
        Index("ix_windows_registry_extracts_hive_path", "hive_path"),
        Index("ix_windows_registry_extracts_hive_type", "hive_type"),
    )
