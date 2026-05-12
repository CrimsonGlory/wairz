"""add dpapi_walk_* columns to firmware (Phase κ.D.B — NINTH κ-era walker)

Revision ID: aabbccddee14
Revises: aabbccddee13
Create Date: 2026-05-12 23:45:00.000000

Adds five columns to the ``firmware`` table for the Phase κ.D Windows
DPAPI master-key PARSE-ONLY METADATA walker 202+polling refactor
(CLAUDE.md Rule #33 contract). Mirrors the appcompat_walk_status /
efs_walk_status / persistence_walk_status patterns already on the
table.

Phase κ.D.C background runner ``run_dpapi_walk_background`` walks each
detection root per Rule #16 (NOT ``firmware.extracted_path`` alone),
locates Windows DPAPI master-key files via the canonical path pattern
``Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<sid>\\<guid>``,
parses each file's header via a pure-Python ``struct``-based parser,
classifies per-file anomalies (orphaned_masterkey /
admin_creator_sid / large_masterkey / parse_error), persists per-file
rows into ``windows_dpapi_master_keys`` (table from κ.D.A), and stamps
an aggregate JSONB result onto ``dpapi_walk_result``.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #45 (parse-only-metadata
walker, Rule-of-Two — DURABLE BEYOND DEBATE).** The walker parses the
master-key file AS DATA via pure-Python ``struct`` unpacking. NO
sub-process invocations, NO ``CryptUnprotectData`` shim, NO DPAPI
bindings, NO decryption primitives. The walker's source is tokenized
against forbidden invocation + decryption tokens in
``test_dpapi_walker.py::test_walker_no_decrypt``, plus a canary test
confirms the gate ACTUALLY fires on synthetic violations.

Per Rule #33 .d (asyncio.create_task vs arq rubric): DPAPI walks run
entirely in-process (pure-Python ``struct`` parsing; no Docker spawn,
no subprocess) and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 (registry_hive_walker) / ι.D.B (efs) / κ.B.B (appcompat) / κ.C.B
(persistence).

Columns:

- ``dpapi_walk_status``: idle / queued / running / completed / failed
- ``dpapi_walk_started_at``: when the background task picked up
- ``dpapi_walk_finished_at``: when the run terminated
- ``dpapi_walk_error``: traceback summary on failure (Text)
- ``dpapi_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_dpapi_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the appcompat_walk_status / efs_walk_status /
persistence_walk_status pattern (Rule #33 .c).

Revision ID ``aabbccddee14`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
κ.D.A head ``aabbccddee13``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee14"
down_revision = "aabbccddee13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "dpapi_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "dpapi_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "dpapi_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("dpapi_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("dpapi_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_dpapi_walk_status",
        "firmware",
        "dpapi_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_dpapi_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "dpapi_walk_result")
    op.drop_column("firmware", "dpapi_walk_error")
    op.drop_column("firmware", "dpapi_walk_finished_at")
    op.drop_column("firmware", "dpapi_walk_started_at")
    op.drop_column("firmware", "dpapi_walk_status")
