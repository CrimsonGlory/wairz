"""add mft_walk_* columns to firmware (Phase η.A.B)

Revision ID: 2a4b3c5d6e7f
Revises: 1f3a2b4c5d6e
Create Date: 2026-05-11 01:00:00.000000

Adds five columns to the ``firmware`` table for the Phase η.A NTFS
$MFT walk 202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors
the prefetch_walk_status / evtx_walk_status / srum_walk_status /
scheduled_task_walk_status / lnk_walk_status patterns already on the
table.

Phase η.A.C background runner ``run_mft_walk_background`` opens each
raw NTFS image candidate found under any detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via dissect.ntfs
``NTFS(fh)`` (the parsed filesystem is treated as untrusted DATA per
Rule #36 — never mounted via ntfs-3g / mount; never executed via
qemu-system), iterates every MFT segment via ``fs.mft.segments()``,
persists per-record rows into ``windows_mft_records`` (table from
η.A.A), and stamps an aggregate JSONB result onto ``mft_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): MFT walks run
entirely in-process (dissect.ntfs is pure Python; no Docker spawn,
no subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as γ.4
/ ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C.

Columns:

- ``mft_walk_status``: idle / queued / running / completed / failed
- ``mft_walk_started_at``: when the background task picked up
- ``mft_walk_finished_at``: when the run terminated
- ``mft_walk_error``: traceback summary on failure (Text)
- ``mft_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_mft_walk_result``;
  schema_version stamped per Rule #35c (writer added in η.A.A).

CHECK constraint matches the prefetch_walk_status / evtx_walk_status /
srum_walk_status / scheduled_task_walk_status / lnk_walk_status
pattern (Rule #33 .c).

Revision ID `2a4b3c5d6e7f` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from η.A.A head ``1f3a2b4c5d6e``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "2a4b3c5d6e7f"
down_revision = "1f3a2b4c5d6e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "mft_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "mft_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "mft_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("mft_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("mft_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_mft_walk_status",
        "firmware",
        "mft_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_mft_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "mft_walk_result")
    op.drop_column("firmware", "mft_walk_error")
    op.drop_column("firmware", "mft_walk_finished_at")
    op.drop_column("firmware", "mft_walk_started_at")
    op.drop_column("firmware", "mft_walk_status")
