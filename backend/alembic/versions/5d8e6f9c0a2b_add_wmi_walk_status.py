"""add wmi_walk_* columns to firmware (Phase θ.B.C)

Revision ID: 5d8e6f9c0a2b
Revises: 4c7d5e6f8b1a
Create Date: 2026-05-12 04:30:00.000000

Adds five columns to the ``firmware`` table for the Phase θ.B WMI
persistence walk 202+polling refactor (CLAUDE.md Rule #33 contract).
Mirrors the bcd_walk_status / mft_walk_status / lnk_walk_status /
scheduled_task_walk_status patterns already on the table.

Phase θ.B.D background runner ``run_wmi_walk_background`` opens each
WMI OBJECTS.DATA candidate found under any detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via the vendored
PyWMIPersistenceFinder (Phase θ.B.A — keyword-search regex parser
that treats OBJECTS.DATA as untrusted text DATA per Rule #36; never
executes wscript / cscript / powershell / mshta / WmiPrvSE / wmiexec
against parsed payloads), iterates every detected
``__FilterToConsumerBinding`` triple, persists per-binding rows into
``windows_wmi_events`` (table from θ.B.B), and stamps an aggregate
JSONB result onto ``wmi_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): WMI walks run
entirely in-process (the vendored parser is pure Python; no Docker
spawn, no subprocess), and per-binding persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same shape
as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B.

Columns:

- ``wmi_walk_status``: idle / queued / running / completed / failed
- ``wmi_walk_started_at``: when the background task picked up
- ``wmi_walk_finished_at``: when the run terminated
- ``wmi_walk_error``: traceback summary on failure (Text)
- ``wmi_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_wmi_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the bcd_walk_status / mft_walk_status /
lnk_walk_status / scheduled_task_walk_status pattern (Rule #33 .c).

Revision ID ``5d8e6f9c0a2b`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.B.B head ``4c7d5e6f8b1a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "5d8e6f9c0a2b"
down_revision = "4c7d5e6f8b1a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "wmi_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "wmi_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "wmi_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("wmi_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("wmi_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_wmi_walk_status",
        "firmware",
        "wmi_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_wmi_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "wmi_walk_result")
    op.drop_column("firmware", "wmi_walk_error")
    op.drop_column("firmware", "wmi_walk_finished_at")
    op.drop_column("firmware", "wmi_walk_started_at")
    op.drop_column("firmware", "wmi_walk_status")
