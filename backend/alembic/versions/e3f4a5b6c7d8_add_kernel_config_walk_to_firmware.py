r"""add kernel_config_walk extraction walker state machine

Revision ID: e3f4a5b6c7d8
Revises: c1d2e3f4q2a6
Create Date: 2026-05-29 14:00:00.000000

DDL infrastructure for the C1 ``kernel_config_walker`` (the UPSTREAM
generic kernel-config EXTRACTION layer) per CLAUDE.md Rule #33 .a 5-state
contract.

This is DISTINCT from the existing ``kernel_config_audit_*`` family
(migration ``4ecdef506a7c``) owned by ``linux_kernel_hardening_walker``:

- ``kernel_config_audit_*`` — the DOWNSTREAM KSPP hardening AUDIT that
  CONSUMES ``HardwareFirmwareBlob.metadata.kernel_config`` and emits
  Findings.
- ``kernel_config_walk_*`` (this migration) — the UPSTREAM EXTRACTION
  walker that GUARANTEES ``metadata.kernel_config`` is populated
  cross-packaging (Android boot.img v0-v4, payload.bin CrAU, 6-codec
  outer-envelope decompress, content-rescan, original-archive
  re-extraction). C1 back-fills the blob metadata so the audit walker
  fires UNCHANGED on the next pass.

New ``firmware`` columns:

- ``kernel_config_walk_status`` (Literal[idle|queued|running|completed|failed])
  + ``ck_firmware_kernel_config_walk_status`` CHECK
- ``kernel_config_walk_started_at`` / ``kernel_config_walk_finished_at`` timestamps
- ``kernel_config_walk_error`` text (failure trace)
- ``kernel_config_walk_result`` JSONB (per-run extraction aggregate;
  Rule #35c normaliser pair + ``FIRMWARE_KERNEL_CONFIG_WALK_RESULT_SCHEMA_VERSION``
  lands in the jsonb_normalizers commit)

Mirrors ``4ecdef506a7c`` (kernel_config_audit walker state machine).  No
new table — the walker reads kernel candidates from the firmware
extraction tree (Rule #16 detection roots) and writes back onto the
existing ``HardwareFirmwareBlob.metadata_`` JSONB column.

Chains from ``c1d2e3f4q2a6`` (ds1qrsetup callgraph walk status — current
alembic head verified 2026-05-29). Revision ID ``e3f4a5b6c7d8`` chosen
distinct from existing IDs to avoid the collision lesson in commit
``a51b15a`` (the natural ``d2e3f4a5b6c7`` candidate was already taken by
``add_upload_stage_to_firmware``).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "e3f4a5b6c7d8"
down_revision: str | None = "c1d2e3f4q2a6"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_kernel_config_walk_status",
        "firmware",
        "kernel_config_walk_status IN ('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("kernel_config_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "kernel_config_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "kernel_config_walk_result")
    op.drop_column("firmware", "kernel_config_walk_error")
    op.drop_column("firmware", "kernel_config_walk_finished_at")
    op.drop_column("firmware", "kernel_config_walk_started_at")
    op.drop_constraint(
        "ck_firmware_kernel_config_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "kernel_config_walk_status")
