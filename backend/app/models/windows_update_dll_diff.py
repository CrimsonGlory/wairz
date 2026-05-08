"""Windows-Update per-DLL diff record table.

One row per DLL across the most-recent KB pair within a firmware.
Backs the Phase δ.5 background runner's per-DLL incremental persistence
(asyncio.create_task dispatch — Rule #33 .d). The
UniqueConstraint on (firmware_id, dll_path) makes the runner idempotent
on restart: a mid-run crash leaves already-completed rows in place;
the next run UPSERTs them rather than INSERTing duplicates.

CHECK on ``diff_type`` enforces the discriminator allowlist (Rule #33
.c gate). Matching Pydantic ``WindowsUpdateDllDiffType`` Literal at the
writer boundary catches code-side typos at load time.

Rule #36 no-execute discipline: this table holds DATA only — the δ.5
runner SHA256s the already-extracted CAB/MSU contents (α-phase unpacker
outputs) and compares; no installer entry-point is invoked at any stage.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsUpdateDllDiff(Base):
    """Per-DLL diff record for a firmware's KB-vs-KB update diff run."""

    __tablename__ = "windows_update_dll_diffs"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose update-diff run produced this row. Cascade
    # DELETE so removing a firmware row removes its per-DLL diff records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path of the DLL within the package's extracted tree.
    dll_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # KB IDs identifying the older / newer side of the diff. Either may
    # be NULL: ``older_kb`` is NULL when the DLL is ``added`` (only in
    # newer KB); ``newer_kb`` is NULL when the DLL is ``removed`` (only
    # in older KB).
    older_kb: Mapped[str | None] = mapped_column(String(32), nullable=True)
    newer_kb: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # SHA256 of each side. Either may be NULL on added/removed.
    older_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    newer_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Discriminator — the matching DB CHECK + Pydantic Literal pair
    # (Rule #33 .c) gate writes at both layers. Allowed values:
    # 'added' | 'removed' | 'modified' | 'unchanged'.
    diff_type: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unchanged"
    )

    # newer_size - older_size. NULL on added/removed where one side is
    # undefined. Surfaces "biggest changes by bytes" cheaply.
    file_size_delta: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # Rule #33 .c — DB-side allowlist matched by the writer-side
        # Pydantic ``WindowsUpdateDllDiffType`` Literal.
        CheckConstraint(
            "diff_type IN ('added', 'removed', 'modified', 'unchanged')",
            name="ck_windows_update_dll_diffs_type",
        ),
        # Restart recovery natural key — the δ.5 runner UPSERTs on
        # this constraint via PG ``ON CONFLICT DO UPDATE``.
        UniqueConstraint(
            "firmware_id",
            "dll_path",
            name="uq_windows_update_dll_diffs_fw_path",
        ),
        Index("ix_windows_update_dll_diffs_firmware_id", "firmware_id"),
        Index("ix_windows_update_dll_diffs_diff_type", "diff_type"),
        Index("ix_windows_update_dll_diffs_dll_path", "dll_path"),
    )
