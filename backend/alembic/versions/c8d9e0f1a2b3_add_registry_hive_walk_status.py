"""add registry_hive_walk_* columns to firmware (Phase γ.3)

Revision ID: c8d9e0f1a2b3
Revises: c7d8e9f0a1b2
Create Date: 2026-05-09 10:00:00.000000

Adds five columns to the ``firmware`` table for the Phase γ batch
registry-walk 202+polling refactor (CLAUDE.md Rule #33 contract).
Mirrors the cve_match_status / vuln_scan_status /
authenticode_chain_status patterns already on the table.

Phase γ.4 background runner ``_run_registry_hive_walk_background``
walks every hive in the firmware's hardware_firmware_blobs (regipy
read-only binding per Rule #36 — DATA only, no .reg apply / no
scriptable action), and writes a ``WindowsRegistryExtract`` row per
hive (Phase γ.1 table). The aggregate result (counts of hive_type,
walk_status histogram, total keys/values, run_seconds) lands in
``registry_hive_walk_result`` so the frontend's last-known-result
render survives a session reload.

Per Rule #33 .d (asyncio.create_task vs arq rubric): registry walks
run entirely in-process (no Docker spawn, no long subprocess; regipy
is a pure-Python read-only library), incrementally persist via per-
hive ``WindowsRegistryExtract`` row INSERTs, and "fire and observe
via row-status" is sufficient for restart recovery (re-run dedups
via the (blob, hive_path) UniqueConstraint on the extract table).
``asyncio.create_task`` is the correct dispatch — see γ.6 router
implementation for the captured pattern.

Columns:

- ``registry_hive_walk_status``: idle / queued / running / completed / failed
- ``registry_hive_walk_started_at``: when the background task picked the row up
- ``registry_hive_walk_finished_at``: when the run terminated
- ``registry_hive_walk_error``: traceback summary on failure (Text)
- ``registry_hive_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_registry_hive_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the cve_match / vuln_scan / authenticode_chain
pattern (Rule #33 .c). The matching Pydantic
``RegistryHiveWalkStatus`` Literal at the writer boundary catches code-
side typos; this CHECK catches direct-SQL writes.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "c8d9e0f1a2b3"
down_revision = "c7d8e9f0a1b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "registry_hive_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "registry_hive_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "registry_hive_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("registry_hive_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("registry_hive_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_registry_hive_walk_status",
        "firmware",
        "registry_hive_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_registry_hive_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "registry_hive_walk_result")
    op.drop_column("firmware", "registry_hive_walk_error")
    op.drop_column("firmware", "registry_hive_walk_finished_at")
    op.drop_column("firmware", "registry_hive_walk_started_at")
    op.drop_column("firmware", "registry_hive_walk_status")
