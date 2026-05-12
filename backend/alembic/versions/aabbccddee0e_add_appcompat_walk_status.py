"""add appcompat_walk_* columns to firmware (Phase κ.B.B — SEVENTH κ-era walker)

Revision ID: aabbccddee0e
Revises: aabbccddee0d
Create Date: 2026-05-12 21:30:00.000000

Adds five columns to the ``firmware`` table for the Phase κ.B Windows
AppCompat / Shimcache execution-evidence walker 202+polling refactor
(CLAUDE.md Rule #33 contract). Mirrors the etl_walk_status /
efs_walk_status / container_walk_status / journald_walk_status / systemd_walk_status
patterns already on the table.

Phase κ.B.C background runner ``run_appcompat_walk_background`` walks each
detection root per Rule #16 (NOT ``firmware.extracted_path`` alone),
locates Windows SYSTEM hive candidates (typically
``Windows/System32/config/SYSTEM`` paths under detection roots; mirrored
backups via RegBack are also picked up), opens each via ``regipy``,
reads the ``ControlSet00X\\Control\\Session Manager\\AppCompatCache\\
AppCompatCache`` REG_BINARY value, parses it via a pure-Python ``struct``-
based AppCompatCache parser (targeting Win10/11 + Server 2016+ format),
classifies per-entry anomalies, persists per-entry rows into
``windows_appcompat_entries`` (table from κ.B.A), and stamps an aggregate
JSONB result onto ``appcompat_walk_result``.

**PARSE-ONLY DISCIPLINE — Rule #36.** The walker parses the AppCompatCache
REG_BINARY value AS DATA via pure-Python ``struct`` unpacking. NO
sub-process invocations, NO Windows API calls, NO ``rundll32`` /
``cscript`` / ``wmic`` / ``wine`` / ``mono`` — the walker reads bytes,
unpacks structs, emits rows. The walker's source is tokenized against
forbidden invocation tokens in ``test_appcompat_walker_no_execute``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): AppCompat walks
run entirely in-process (regipy + pure-Python ``struct`` parsing; no
Docker spawn, no subprocess) and per-row persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 (registry_hive_walker) / ι.C.B (etl) / ι.D.B (efs) / ι.E.B (container).

Columns:

- ``appcompat_walk_status``: idle / queued / running / completed / failed
- ``appcompat_walk_started_at``: when the background task picked up
- ``appcompat_walk_finished_at``: when the run terminated
- ``appcompat_walk_error``: traceback summary on failure (Text)
- ``appcompat_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_appcompat_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the etl_walk_status / efs_walk_status /
container_walk_status pattern (Rule #33 .c).

Revision ID ``aabbccddee0e`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
κ.B.A head ``aabbccddee0d``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee0e"
down_revision = "aabbccddee0d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "appcompat_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "appcompat_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "appcompat_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("appcompat_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("appcompat_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_appcompat_walk_status",
        "firmware",
        "appcompat_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_appcompat_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "appcompat_walk_result")
    op.drop_column("firmware", "appcompat_walk_error")
    op.drop_column("firmware", "appcompat_walk_finished_at")
    op.drop_column("firmware", "appcompat_walk_started_at")
    op.drop_column("firmware", "appcompat_walk_status")
