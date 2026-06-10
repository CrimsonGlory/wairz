r"""add reachability_export_walk extraction walker state machine

Revision ID: b8c9d0e1f2a3
Revises: d7e8f9a0b1c2
Create Date: 2026-06-09 22:00:00.000000

DDL infrastructure for the MOVE 2 ``reachability_export_walker`` (the wairz↔framework reachability
bridge durability layer, binary axis) per CLAUDE.md Rule #33 .a 5-state contract.

The walker extracts per-ELF-blob symbol-presence facts (DEFINED / IMPORTED sets) for every
HardwareFirmwareBlob, persists them PER-BLOB into the ``reachability_export_records`` table
(migration ``d7e8f9a0b1c2``; GIN-queryable for the Rule #44
``lookup_reachable_symbol_across_firmwares`` MCP tool), and stamps only an AGGREGATE
(blob/elf/stripped counts + total_defined_symbols) onto ``reachability_export_walk_result``.

New ``firmware`` columns (mirrors ``a6b7c8d9e0f1`` — the C2 module_reachability state machine):

- ``reachability_export_walk_status`` (Literal[idle|queued|running|completed|failed]) +
  ``ck_firmware_reachability_export_walk_status`` CHECK
- ``reachability_export_walk_started_at`` / ``reachability_export_walk_finished_at`` timestamps
- ``reachability_export_walk_error`` text (failure trace)
- ``reachability_export_walk_result`` JSONB (per-run aggregate; Rule #35c normaliser pair +
  ``FIRMWARE_REACHABILITY_EXPORT_WALK_RESULT_SCHEMA_VERSION`` land in the jsonb_normalizers commit)

PARSE-ONLY (Rule #36/#45): the walker reads the ELF symbol table AS DATA via pyelftools; it NEVER
executes a binary. The Iron Law (symbol absence valid ONLY on a non-stripped, sha256-matched
binary) is enforced at the bridge producer/consumer; per-blob completeness flags travel with each
``reachability_export_records`` row.

Per CLAUDE.md Rule #19 evidence-first: revision id ``b8c9d0e1f2a3`` pre-validated FREE before
authoring. Chains from the MOVE 2 Phase 1 head ``d7e8f9a0b1c2``.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b8c9d0e1f2a3"
down_revision: str | None = "d7e8f9a0b1c2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "reachability_export_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_reachability_export_walk_status",
        "firmware",
        "reachability_export_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "reachability_export_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "reachability_export_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("reachability_export_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "reachability_export_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "reachability_export_walk_result")
    op.drop_column("firmware", "reachability_export_walk_error")
    op.drop_column("firmware", "reachability_export_walk_finished_at")
    op.drop_column("firmware", "reachability_export_walk_started_at")
    op.drop_constraint(
        "ck_firmware_reachability_export_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "reachability_export_walk_status")
