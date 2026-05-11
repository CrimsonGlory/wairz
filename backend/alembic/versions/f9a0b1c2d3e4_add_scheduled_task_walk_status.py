"""add scheduled_task_walk_* columns to firmware (Phase η.B.B)

Revision ID: f9a0b1c2d3e4
Revises: f8a9b0c1d2e3
Create Date: 2026-05-11 22:30:00.000000

Adds five columns to the ``firmware`` table for the Phase η.B
Scheduled Task XML-walk 202+polling refactor (CLAUDE.md Rule #33
contract). Mirrors the prefetch_walk_status / evtx_walk_status /
srum_walk_status / registry_hive_walk_status patterns already on the
table.

Phase η.B.C background runner ``run_scheduled_task_walk_background``
walks every ``\\Windows\\System32\\Tasks\\**\\*`` XML file across the
firmware's detection roots
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via
``defusedxml.ElementTree.fromstring`` (per intake D2 — defusedxml
swap pattern from Phase Lint.B.3 baseline; the parsed XML is
treated as untrusted data per Rule #36 — never invoked), persists
per-task rows into ``windows_scheduled_tasks`` (table created in
η.B.A), and stamps an aggregate JSONB result onto
``scheduled_task_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): Scheduled Task
walks run entirely in-process (defusedxml is pure Python; no Docker
spawn, no subprocess), and per-row persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same
shape as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B.

Columns:

- ``scheduled_task_walk_status``: idle / queued / running / completed / failed
- ``scheduled_task_walk_started_at``: when the background task picked up
- ``scheduled_task_walk_finished_at``: when the run terminated
- ``scheduled_task_walk_error``: traceback summary on failure (Text)
- ``scheduled_task_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_scheduled_task_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the prefetch_walk_status / evtx_walk_status /
srum_walk_status pattern (Rule #33 .c).

Revision ID `f9a0b1c2d3e4` was pre-validated FREE against the
72-revision tree before authoring (Rule #19 evidence-first).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "f9a0b1c2d3e4"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "scheduled_task_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "scheduled_task_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "scheduled_task_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("scheduled_task_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("scheduled_task_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_scheduled_task_walk_status",
        "firmware",
        "scheduled_task_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_scheduled_task_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "scheduled_task_walk_result")
    op.drop_column("firmware", "scheduled_task_walk_error")
    op.drop_column("firmware", "scheduled_task_walk_finished_at")
    op.drop_column("firmware", "scheduled_task_walk_started_at")
    op.drop_column("firmware", "scheduled_task_walk_status")
