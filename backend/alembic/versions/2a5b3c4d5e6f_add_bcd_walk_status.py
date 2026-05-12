"""add bcd_walk_* columns to firmware (Phase θ.A.B)

Revision ID: 2a5b3c4d5e6f
Revises: 1f4a2b3c4d5e
Create Date: 2026-05-12 02:30:00.000000

Adds five columns to the ``firmware`` table for the Phase θ.A BCD
store walk 202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors
the prefetch_walk_status / evtx_walk_status / srum_walk_status /
scheduled_task_walk_status / lnk_walk_status / mft_walk_status
patterns already on the table.

Phase θ.A.C background runner ``run_bcd_walk_background`` opens each
BCD store candidate found under any detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via regipy
``RegistryHive`` (BCD is REGF format; treated as untrusted DATA per
Rule #36 — never executed via ``bcdedit`` / ``reg.exe`` / boot
manager), iterates every ``\\Objects\\{guid}`` subkey, persists
per-entry rows into ``windows_bcd_entries`` (table from θ.A.A), and
stamps an aggregate JSONB result onto ``bcd_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): BCD walks run
entirely in-process (regipy is pure Python; no Docker spawn, no
subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as γ.4
/ ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B.

Columns:

- ``bcd_walk_status``: idle / queued / running / completed / failed
- ``bcd_walk_started_at``: when the background task picked up
- ``bcd_walk_finished_at``: when the run terminated
- ``bcd_walk_error``: traceback summary on failure (Text)
- ``bcd_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_bcd_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the prefetch_walk_status / evtx_walk_status /
srum_walk_status / scheduled_task_walk_status / lnk_walk_status /
mft_walk_status pattern (Rule #33 .c).

Revision ID `2a5b3c4d5e6f` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.A.A head ``1f4a2b3c4d5e``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "2a5b3c4d5e6f"
down_revision = "1f4a2b3c4d5e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "bcd_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "bcd_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "bcd_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("bcd_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("bcd_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_bcd_walk_status",
        "firmware",
        "bcd_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_bcd_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "bcd_walk_result")
    op.drop_column("firmware", "bcd_walk_error")
    op.drop_column("firmware", "bcd_walk_finished_at")
    op.drop_column("firmware", "bcd_walk_started_at")
    op.drop_column("firmware", "bcd_walk_status")
