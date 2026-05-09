"""add evtx_walk_* columns to firmware (Phase ε.1.b.2)

Revision ID: e0a1b2c3d4e5
Revises: d5a6b7c8d9e0
Create Date: 2026-05-10 09:00:00.000000

Adds five columns to the ``firmware`` table for the Phase ε.1.b
EVTX-walk 202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors
the cve_match_status / vuln_scan_status / authenticode_chain_status /
registry_hive_walk_status / dotnet_decompile_status /
windows_update_diff_status patterns already on the table.

Phase ε.1.b.3 background runner ``run_evtx_walk_background`` walks
every ``.evtx`` file across the firmware's detection roots
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), invokes
``app.services.evtx_service.parse_evtx_file`` to decode each
(python-evtx read-only PE-format-equivalent record stream per Rule
#36 — DATA only, never invoked via wevtutil / Get-WinEvent), and
aggregates per-EVTX summaries into a JSONB result. The aggregate
result (counts by EID, by provider, time range, sample records,
run_seconds) lands in ``evtx_walk_result`` so the frontend's last-
known-result render survives a session reload.

Per Rule #33 .d (asyncio.create_task vs arq rubric): EVTX walks run
entirely in-process (no Docker spawn, no long subprocess; python-evtx
is a pure-Python read-only library), and the per-firmware aggregate
JSONB stamp is the durable state. ``asyncio.create_task`` is the
correct dispatch — see γ.4 ``registry_hive_walker.py`` precedent for
the captured pattern (same in-process / pure-Python shape).

Per Phase ε.1.b campaign Decision #1: per-event row persistence is
DEFERRED to a future ζ.X phase. ε.1.b's ``evtx_walk_result`` JSONB
is sufficient for the walk-summary aggregate; full per-event search
indexing can layer in later without breaking the schema.

Columns:

- ``evtx_walk_status``: idle / queued / running / completed / failed
- ``evtx_walk_started_at``: when the background task picked the row up
- ``evtx_walk_finished_at``: when the run terminated
- ``evtx_walk_error``: traceback summary on failure (Text)
- ``evtx_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_evtx_walk_result``;
  schema_version stamped per Rule #35c (added in ε.1.b.3 alongside
  the runner).

CHECK constraint matches the cve_match / vuln_scan / authenticode_chain /
registry_hive_walk pattern (Rule #33 .c). The matching Pydantic
``EvtxWalkStatus`` Literal at the writer boundary catches code-side
typos; this CHECK catches direct-SQL writes (cron scripts, manual
fixes, ORM rollbacks under partial-failure paths).

Revision ID `e0a1b2c3d4e5` was pre-validated FREE against the
60-revision tree before authoring per `.mex/patterns/add-alembic-migration.md`
(δ.3 hit two consecutive collisions in the rotating-hex pattern; the
pre-check eliminates that trap).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "e0a1b2c3d4e5"
down_revision = "d5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "evtx_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "evtx_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "evtx_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("evtx_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("evtx_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_evtx_walk_status",
        "firmware",
        "evtx_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_evtx_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "evtx_walk_result")
    op.drop_column("firmware", "evtx_walk_error")
    op.drop_column("firmware", "evtx_walk_finished_at")
    op.drop_column("firmware", "evtx_walk_started_at")
    op.drop_column("firmware", "evtx_walk_status")
