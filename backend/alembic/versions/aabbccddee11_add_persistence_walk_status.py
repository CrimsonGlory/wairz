"""add persistence_walk_* columns to firmware (Phase κ.C.B — EIGHTH κ-era walker)

Revision ID: aabbccddee11
Revises: aabbccddee10
Create Date: 2026-05-12 23:30:00.000000

Adds five columns to the ``firmware`` table for the Phase κ.C Linux
persistence-triplet walker (bash_history + crontab + ld.so.preload)
202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors the
appcompat_walk_status / efs_walk_status / container_walk_status /
systemd_walk_status / journald_walk_status patterns already on the
table.

**Single status set for the bundle, not 3 separate sets.** Mirrors γ.4
``registry_walk_*`` covering 5 hive types — when a single walker
emits to multiple sibling ORM tables, one status set covers the
walker overall. Splitting into 3 sets (bash_history_walk_status,
cron_walk_status, ld_preload_walk_status) would force 3 separate
trigger MCP tools + 3 polling loops + 3 sets of Rule #33 .c CHECK
constraints — for what end? Operators would invariably re-trigger
all 3; the work is one-shot under the κ.C.C ``run_linux_persistence_walk_background``.

Phase κ.C.C background runner ``run_linux_persistence_walk_background``
walks each detection root per Rule #16 (NOT ``firmware.extracted_path``
alone), locates each artefact family (bash_history candidates +
crontab candidates + ld.so.preload candidates), decodes each file
with ``errors='replace'`` for robustness against non-UTF8 bytes,
tokenizes into lines, runs the κ.C.D classifier per line, and
persists per-line rows into the three κ.C.A tables.

**PARSE-ONLY DISCIPLINE — Rule #36.** The walker reads each artefact
file AS TEXT via pure-Python ``open()`` + line splitting + regex
matching. NO ``bash`` invocation, NO ``crontab`` CLI, NO ``ldconfig``,
NO subprocess of any kind. Test gate
``test_linux_persistence_walker.py::test_walker_no_execute``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): persistence
walks run entirely in-process (pure-Python text-line parsing + regex)
and per-row persistence is the durable state. ``asyncio.create_task``
is the correct dispatch.

Columns:

- ``persistence_walk_status``: idle / queued / running / completed / failed
- ``persistence_walk_started_at``: when the background task picked up
- ``persistence_walk_finished_at``: when the run terminated
- ``persistence_walk_error``: traceback summary on failure (Text)
- ``persistence_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_persistence_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the appcompat_walk_status / efs_walk_status /
container_walk_status pattern (Rule #33 .c).

Revision ID ``aabbccddee11`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
κ.C.A head ``aabbccddee10``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee11"
down_revision = "aabbccddee10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "persistence_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "persistence_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "persistence_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("persistence_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("persistence_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_persistence_walk_status",
        "firmware",
        "persistence_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_persistence_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "persistence_walk_result")
    op.drop_column("firmware", "persistence_walk_error")
    op.drop_column("firmware", "persistence_walk_finished_at")
    op.drop_column("firmware", "persistence_walk_started_at")
    op.drop_column("firmware", "persistence_walk_status")
