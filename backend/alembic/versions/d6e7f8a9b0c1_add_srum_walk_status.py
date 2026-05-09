"""add srum_walk_* columns to firmware (Phase ζ.3.B)

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-05-10 16:30:00.000000

Adds five columns to the ``firmware`` table for the Phase ζ.3 SRUM-walk
202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors the
prefetch_walk_status / evtx_walk_status / registry_hive_walk_status
patterns already on the table.

Phase ζ.3.B background runner ``run_srum_walk_background`` walks every
``SRUDB.dat`` across the firmware's detection roots
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), invokes ``pyesedb.open()`` to
decode each (libesedb-python is a read-only ESEDB binding per Rule #36
— DATA only, never invoked via esedbutil / Get-CimInstance SRUMState /
scriptable replay), persists per-record rows into
``windows_srum_records`` (table created in ζ.3.A), and stamps an
aggregate JSONB result onto ``srum_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): SRUM walks run
entirely in-process (libesedb-python is a C-extension binding that
runs in the worker process; no Docker spawn, no subprocess), and
per-row persistence is the durable state. ``asyncio.create_task`` is
the correct dispatch — same shape as γ.4 / ε.1.b.3 / ζ.2.B.

Columns:

- ``srum_walk_status``: idle / queued / running / completed / failed
- ``srum_walk_started_at``: when the background task picked up
- ``srum_walk_finished_at``: when the run terminated
- ``srum_walk_error``: traceback summary on failure (Text)
- ``srum_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_srum_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the prefetch_walk_status / evtx_walk_status
pattern (Rule #33 .c).

Revision ID `d6e7f8a9b0c1` was pre-validated FREE against the
68-revision tree before authoring.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "srum_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "srum_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "srum_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("srum_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("srum_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_srum_walk_status",
        "firmware",
        "srum_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_srum_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "srum_walk_result")
    op.drop_column("firmware", "srum_walk_error")
    op.drop_column("firmware", "srum_walk_finished_at")
    op.drop_column("firmware", "srum_walk_started_at")
    op.drop_column("firmware", "srum_walk_status")
