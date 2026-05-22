r"""add kernel_config_audit walker state machine

Revision ID: 4ecdef506a7c
Revises: 3dcb4e5f6a7b
Create Date: 2026-05-22 21:50:00.000000

DDL infrastructure for the ``linux_kernel_hardening_walker`` per
CLAUDE.md Rule #33 .a 5-state contract.  The walker reads
``HardwareFirmwareBlob.metadata.kernel_config`` populated by the
``kernel_image`` parser (commit 108102b) and emits Findings via
FindingService for each insecure / missing hardening config.

New ``firmware`` columns:

- ``kernel_config_audit_status`` (Literal[idle|queued|running|completed|failed])
  + ``ck_firmware_kernel_config_audit_status`` CHECK
- ``kernel_config_audit_started_at`` / ``kernel_config_audit_finished_at`` timestamps
- ``kernel_config_audit_error`` text (failure trace)
- ``kernel_config_audit_result`` JSONB (per-run audit aggregate;
  Rule #35c normaliser pair lands in the walker commit)

Mirrors ``fc5d6e7f8a9b`` (bare-metal walker state machine).  No new
table — the bare-metal-style descriptor table is not needed here; the
walker reads kernel_config from the existing HardwareFirmwareBlob.metadata_
JSONB column populated by the parser.

Chains from ``3dcb4e5f6a7b`` (cross-stack alignment for the
``kernel_config_*`` finding sources — commit dd8af4e).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "4ecdef506a7c"
down_revision: str | None = "3dcb4e5f6a7b"
branch_labels: str | None = None
depends_on: str | None = None


_VALID_AUDIT_STATUSES = ("idle", "queued", "running", "completed", "failed")


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_audit_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_kernel_config_audit_status",
        "firmware",
        "kernel_config_audit_status IN ('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_audit_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_audit_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("kernel_config_audit_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_audit_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "kernel_config_audit_result")
    op.drop_column("firmware", "kernel_config_audit_error")
    op.drop_column("firmware", "kernel_config_audit_finished_at")
    op.drop_column("firmware", "kernel_config_audit_started_at")
    op.drop_constraint(
        "ck_firmware_kernel_config_audit_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "kernel_config_audit_status")
