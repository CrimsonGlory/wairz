"""add usnjrnl_walk_* columns to firmware (Phase κ.E.B — TENTH κ-era walker)

Revision ID: aabbccddee17
Revises: aabbccddee16
Create Date: 2026-05-12 23:50:00.000000

Adds five columns to the ``firmware`` table for the Phase κ.E Windows
NTFS $UsnJrnl:$J change-log walker 202+polling refactor (CLAUDE.md
Rule #33 contract). Mirrors the appcompat_walk_status / dpapi_walk_status
/ persistence_walk_status patterns already on the table.

Phase κ.E.C background runner ``run_usnjrnl_walk_background`` walks each
detection root per Rule #16, locates raw NTFS image candidates via the
η.A MFT-walker precedent (boot-sector magic check on ``.dd`` / ``.raw``
/ ``.ntfs`` / ``.img`` / ``.bin``), opens each via ``dissect.ntfs.NTFS``,
reads the ``$Extend/$UsnJrnl:$J`` ADS via
``dissect.ntfs.usnjrnl.UsnJrnl.records()``, decodes per-record
reason flags, persists per-record rows into ``windows_usnjrnl_entries``
(table from κ.E.A), and stamps an aggregate JSONB result onto
``usnjrnl_walk_result``.

**Rule #36 no-execute discipline.** The walker is a pure-Python parser
over NTFS bytes via ``dissect.ntfs``. NO sub-process invocations, NO
``ntfs-3g`` / ``mount`` / ``losetup`` invocation, NO execution of any
file referenced by the journal. The walker's source is tokenized
against forbidden invocation tokens in
``test_usnjrnl_walker.py::test_walker_no_execute``, plus a canary
test confirms the gate ACTUALLY fires on synthetic violations.

Per Rule #33 .d (asyncio.create_task vs arq rubric): USN walks run
entirely in-process (pure-Python ``dissect.ntfs`` parsing; no Docker
spawn, no subprocess) and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as γ.4
(registry_hive_walker) / η.A (mft_walker) / κ.B (appcompat) /
κ.D (dpapi).

Columns:

- ``usnjrnl_walk_status``: idle / queued / running / completed / failed
- ``usnjrnl_walk_started_at``: when the background task picked up
- ``usnjrnl_walk_finished_at``: when the run terminated
- ``usnjrnl_walk_error``: traceback summary on failure (Text)
- ``usnjrnl_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_usnjrnl_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the appcompat_walk_status / dpapi_walk_status
pattern (Rule #33 .c).

Revision ID ``aabbccddee17`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
κ.E.A head ``aabbccddee16``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee17"
down_revision = "aabbccddee16"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "usnjrnl_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "usnjrnl_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "usnjrnl_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("usnjrnl_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("usnjrnl_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_usnjrnl_walk_status",
        "firmware",
        "usnjrnl_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_usnjrnl_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "usnjrnl_walk_result")
    op.drop_column("firmware", "usnjrnl_walk_error")
    op.drop_column("firmware", "usnjrnl_walk_finished_at")
    op.drop_column("firmware", "usnjrnl_walk_started_at")
    op.drop_column("firmware", "usnjrnl_walk_status")
