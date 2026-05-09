"""add prefetch_walk_* columns to firmware (Phase ζ.2.B)

Revision ID: b4c5d6e7f8a9
Revises: f3a4b5c6d7e8
Create Date: 2026-05-10 14:00:00.000000

Adds five columns to the ``firmware`` table for the Phase ζ.2 Prefetch-walk
202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors the
evtx_walk_status / registry_hive_walk_status / windows_update_diff_status
patterns already on the table.

Phase ζ.2.B background runner ``run_prefetch_walk_background`` walks every
``.pf`` file across the firmware's detection roots
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 — NOT
``firmware.extracted_path`` alone), invokes ``windowsprefetch.Prefetch``
to decode each (windowsprefetch is a pure-Python read-only struct-unpack
parser per Rule #36 — DATA only, never invoked via pftriage / Powershell
/ Get-CimInstance Win32_PrefetchedApp), persists per-execution rows into
``windows_prefetch_records`` (table created in ζ.2.A), and stamps an
aggregate JSONB result onto ``prefetch_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): Prefetch walks run
entirely in-process (no Docker spawn, no long subprocess; windowsprefetch
is pure-Python read-only), and the per-row persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 registry_hive_walker.

Columns:

- ``prefetch_walk_status``: idle / queued / running / completed / failed
- ``prefetch_walk_started_at``: when the background task picked up
- ``prefetch_walk_finished_at``: when the run terminated
- ``prefetch_walk_error``: traceback summary on failure (Text)
- ``prefetch_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_prefetch_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the evtx_walk_status pattern (Rule #33 .c).
The matching Pydantic ``PrefetchWalkStatus`` Literal at the writer
boundary catches code-side typos; this CHECK catches direct-SQL writes.

Revision ID `b4c5d6e7f8a9` was pre-validated FREE against the 66-revision
tree before authoring (Pattern #2 evidence-first — grep returned 0 hits).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "b4c5d6e7f8a9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "prefetch_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "prefetch_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "prefetch_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("prefetch_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("prefetch_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_prefetch_walk_status",
        "firmware",
        "prefetch_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_prefetch_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "prefetch_walk_result")
    op.drop_column("firmware", "prefetch_walk_error")
    op.drop_column("firmware", "prefetch_walk_finished_at")
    op.drop_column("firmware", "prefetch_walk_started_at")
    op.drop_column("firmware", "prefetch_walk_status")
