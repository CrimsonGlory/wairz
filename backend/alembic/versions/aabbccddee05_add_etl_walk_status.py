"""add etl_walk_* columns to firmware (Phase ι.C.B — FIRST ι WINDOWS-SIDE)

Revision ID: aabbccddee05
Revises: aabbccddee04
Create Date: 2026-05-12 18:30:00.000000

Adds five columns to the ``firmware`` table for the Phase ι.C Windows
ETW .etl trace-log walk 202+polling refactor (CLAUDE.md Rule #33
contract). FIRST ι Windows-side walker (ι.A + ι.B shipped Linux —
journald + systemd). Mirrors the systemd_walk_status /
journald_walk_status / bcd_walk_status / wmi_walk_status /
esp_walk_status / mbr_vbr_walk_status / sdb_walk_status patterns
already on the table.

Phase ι.C.C background runner ``run_etl_walk_background`` walks each
detection root (typically ``Windows/System32/WDI/LogFiles/`` /
``Windows/System32/winevt/Logs/`` / ``Windows/Logs/CBS/`` /
``Windows/Logs/NetSetup/`` / ``Windows/Logs/WindowsBackup/`` /
``Windows/Logs/WindowsUpdate/`` / ``Windows/System32/LogFiles/WMI/``
per Rule #16 — NOT ``firmware.extracted_path`` alone), parses every
``.etl`` file via Fox-IT ``dissect.etl`` (AGPL-3.0, v3.14 — Rule #19
evidence-first probe ran 2026-05-12T15:45Z), iterates every
EventRecord instance, persists per-event rows into
``windows_etl_events`` (table from ι.C.A), and stamps an aggregate
JSONB result onto ``etl_walk_result``.

Per Rule #36 no-execute: the .etl binary is parsed as untrusted DATA.
Nothing in wairz starts a kernel trace session, registers an ETW
logger, invokes any process referenced in event payloads, or loads
any embedded provider manifest as code.

Per Rule #33 .d (asyncio.create_task vs arq rubric): ETL walks run
entirely in-process (dissect.etl pure-Python parser; no Docker spawn,
no subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B /
θ.B.C / θ.C.B / θ.D.B / θ.E.B / ι.A.B / ι.B.B.

Columns:

- ``etl_walk_status``: idle / queued / running / completed / failed
- ``etl_walk_started_at``: when the background task picked up
- ``etl_walk_finished_at``: when the run terminated
- ``etl_walk_error``: traceback summary on failure (Text)
- ``etl_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_etl_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the systemd_walk_status / journald_walk_status
/ bcd_walk_status / wmi_walk_status / esp_walk_status /
mbr_vbr_walk_status / sdb_walk_status pattern (Rule #33 .c).

Revision ID ``aabbccddee05`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
ι.C.A head ``aabbccddee04``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee05"
down_revision = "aabbccddee04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "etl_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "etl_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "etl_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("etl_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("etl_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_etl_walk_status",
        "firmware",
        "etl_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_etl_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "etl_walk_result")
    op.drop_column("firmware", "etl_walk_error")
    op.drop_column("firmware", "etl_walk_finished_at")
    op.drop_column("firmware", "etl_walk_started_at")
    op.drop_column("firmware", "etl_walk_status")
