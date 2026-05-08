"""add windows_update_diff_* columns to firmware (Phase δ.3)

Revision ID: d3a4b5c6d7e8
Revises: d1e2f3a4b5c6
Create Date: 2026-05-09 18:00:00.000000

Adds five columns to the ``firmware`` table for the Phase δ KB-vs-KB
update-diff 202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors
the cve_match_status / vuln_scan_status / authenticode_chain_status /
registry_hive_walk_status / dotnet_decompile_status patterns already on
the table.

Phase δ.5 background runner ``_run_windows_update_diff_background`` walks
every (older_kb, newer_kb) pair across the firmware's
``windows_update_packages`` rows (δ.1 table), computes per-DLL changeset
via SHA256 comparison, and persists per-DLL diff rows incrementally to
a dedicated table introduced in δ.5 (with a UniqueConstraint on
(firmware_id, dll_path) for restart recovery via re-run dedup). The
aggregate result (counts of dlls_added / removed / modified / unchanged,
by-KB-pair histogram, run_seconds) lands in ``windows_update_diff_result``
so the frontend's last-known-result render survives a session reload.

Per Rule #33 .d (asyncio.create_task vs arq rubric): update-diff work
runs entirely in-process (no Docker spawn — diff is pure-Python SHA256
+ string comparison over already-extracted CAB/MSU contents), AND
intermediate state IS incrementally persisted to the DB (per-DLL diff
rows INSERT-or-UPDATE on the dedicated table per (firmware_id,
dll_path)), AND "fire and observe via row-status" is sufficient (a
mid-run crash is recoverable by re-running — already-completed per-DLL
rows are idempotent on the UniqueConstraint). All three rubric clauses
favour ``asyncio.create_task`` — distinct from δ.2's dotnet decompile
which uses arq because the work coordinates with worker-only resources.

Columns:

- ``windows_update_diff_status``: idle / queued / running / completed / failed
- ``windows_update_diff_started_at``: when the background task picked the row up
- ``windows_update_diff_finished_at``: when the run terminated
- ``windows_update_diff_error``: traceback summary on failure (Text)
- ``windows_update_diff_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_windows_update_diff_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the cve_match / vuln_scan / authenticode_chain /
registry_hive_walk / dotnet_decompile pattern (Rule #33 .c). The matching
Pydantic ``WindowsUpdateDiffStatus`` Literal at the writer boundary catches
code-side typos; this CHECK catches direct-SQL writes.

Per Rule #36 no-execute discipline: this work computes diffs over already-
extracted package contents (CAB/MSU outputs from α-phase unpackers); no
update-installer entry points are invoked at any stage.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "d3a4b5c6d7e8"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "windows_update_diff_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_update_diff_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_update_diff_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("windows_update_diff_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("windows_update_diff_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_windows_update_diff_status",
        "firmware",
        "windows_update_diff_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_windows_update_diff_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "windows_update_diff_result")
    op.drop_column("firmware", "windows_update_diff_error")
    op.drop_column("firmware", "windows_update_diff_finished_at")
    op.drop_column("firmware", "windows_update_diff_started_at")
    op.drop_column("firmware", "windows_update_diff_status")
