"""add lnk_walk_* columns to firmware (Phase η.C.B)

Revision ID: c2e3f4a5b6d7
Revises: b1d2e3f4a5c6
Create Date: 2026-05-11 23:30:00.000000

Adds five columns to the ``firmware`` table for the Phase η.C
Windows Shell Link (.lnk) walk 202+polling refactor (CLAUDE.md
Rule #33 contract). Mirrors the prefetch_walk_status /
evtx_walk_status / srum_walk_status / scheduled_task_walk_status
patterns already on the table.

Phase η.C.C background runner ``run_lnk_walk_background`` walks
every ``*.lnk`` file under user-profile + system shortcut locations
across the firmware's detection roots
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via
``LnkParse3.lnk_file(fhandle=...)`` (the parsed Shell Link is
treated as untrusted DATA per Rule #36 — never invoked), persists
per-LNK rows into ``windows_lnk_records`` (table created in
η.C.A), and stamps an aggregate JSONB result onto
``lnk_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): LNK walks
run entirely in-process (LnkParse3 is pure Python; no Docker
spawn, no subprocess), and per-row persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same
shape as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C.

Columns:

- ``lnk_walk_status``: idle / queued / running / completed / failed
- ``lnk_walk_started_at``: when the background task picked up
- ``lnk_walk_finished_at``: when the run terminated
- ``lnk_walk_error``: traceback summary on failure (Text)
- ``lnk_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_lnk_walk_result``;
  schema_version stamped per Rule #35c (writer added in η.C.A).

CHECK constraint matches the prefetch_walk_status / evtx_walk_status /
srum_walk_status / scheduled_task_walk_status pattern (Rule #33 .c).

Revision ID `c2e3f4a5b6d7` was pre-validated FREE against the
74-revision tree before authoring (Rule #19 evidence-first).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "c2e3f4a5b6d7"
down_revision = "b1d2e3f4a5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "lnk_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "lnk_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "lnk_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("lnk_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("lnk_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_lnk_walk_status",
        "firmware",
        "lnk_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_lnk_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "lnk_walk_result")
    op.drop_column("firmware", "lnk_walk_error")
    op.drop_column("firmware", "lnk_walk_finished_at")
    op.drop_column("firmware", "lnk_walk_started_at")
    op.drop_column("firmware", "lnk_walk_status")
