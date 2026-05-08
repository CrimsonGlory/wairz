"""add_authenticode_chain_status to firmware (Phase β.3)

Revision ID: b2a3c4d5e6f7
Revises: b1a2c3d4e5f6
Create Date: 2026-05-07 20:30:00.000000

Adds five columns to the ``firmware`` table for the Phase β
Authenticode batch-validation 202+polling refactor (CLAUDE.md Rule
#33 contract). Mirrors the cve_match_status / vuln_scan_status /
unpack_status patterns already in the table.

Phase β.4 background runner ``_run_authenticode_chain_background``
walks every PE in the firmware's hardware_firmware_blobs, runs the
signify-based validator, and writes a ``WindowsPESignature`` row per
PE. The aggregate result (counts of signed / unsigned / dbx_revoked
/ chain_status by tier) lands in ``authenticode_chain_result`` so
the frontend's last-known-result render survives a session reload.

Columns:
- ``authenticode_chain_status``: idle / queued / running / completed / failed
- ``authenticode_chain_started_at``: when the background task picked the row up
- ``authenticode_chain_finished_at``: when the run terminated
- ``authenticode_chain_error``: traceback summary on failure (Text)
- ``authenticode_chain_result``: JSONB aggregate
  ``{signed_count, signed_pct, unsigned_count, dbx_revoked_count,
    by_chain_status: {valid_at_signing, valid_now, ...}, run_seconds}``

CHECK constraint matches the cve_match / vuln_scan pattern (Rule #33 .c).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "b2a3c4d5e6f7"
down_revision = "b1a2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "authenticode_chain_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "authenticode_chain_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "authenticode_chain_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("authenticode_chain_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("authenticode_chain_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_authenticode_chain_status",
        "firmware",
        "authenticode_chain_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_authenticode_chain_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "authenticode_chain_result")
    op.drop_column("firmware", "authenticode_chain_error")
    op.drop_column("firmware", "authenticode_chain_finished_at")
    op.drop_column("firmware", "authenticode_chain_started_at")
    op.drop_column("firmware", "authenticode_chain_status")
