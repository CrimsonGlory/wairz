"""add ds1qrsetup_callgraph_walk_* columns to firmware (Q2 ds1qrsetup callgraph walker)

Revision ID: 7a8b9c0d1e2f
Revises: 6f7a8b9c0d1e
Create Date: 2026-05-27 18:00:00.000000

Adds five columns to the ``firmware`` table for the Q2 ds1qrsetup
callgraph walker 202+polling refactor (CLAUDE.md Rule #33 contract).
Mirrors the python_ast_walk_status / srum_walk_status / prefetch_walk_status
pattern already on the table — same 5-column shape, same DB CHECK.

The walker performs **static binary call-graph analysis** of the
ds1qrsetup network-facing binary (Python interpreter + statically-linked
C modules from the Yocto recipe) on DS1 firmware. It identifies which
native symbols are reachable from main() and enumerates FFmpeg /Pillow
compile-flag fingerprints via string-scan + symbol enumeration. The
cve-assessment-framework consumes the JSON aggregate to narrow
FFmpeg DNN-backend + Pillow decoder reachability for ~42 FFmpeg EXPL
CVEs + the Pillow long-tail.

Per Rule #33 .d (asyncio.create_task vs arq rubric): the call-graph
analysis delegates to ``ghidra_service.ensure_analysis`` which already
owns a per-binary concurrency guard and caches results in
``analysis_cache``. The walker itself is in-process and JSONB-aggregate
persisted — ``asyncio.create_task`` is the correct dispatch (same shape
as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / Q1).

**Rule #36 + Rule #45 PARSE-ONLY discipline.** The ds1qrsetup binary
is analysed AS DATA via Ghidra headless / radare2 — neither tool
INVOKES the binary; both extract static information. wairz does NOT
``exec()`` / ``runpy.run_path()`` / spawn the binary; the walker
NEVER calls ``subprocess.run([binary_path, ...])``. Test gate
``test_walker_no_decrypt_no_exec`` scans the walker source for any
spawn token targeting the extracted binary.

Columns:

- ``ds1qrsetup_callgraph_walk_status``: idle / queued / running /
  completed / failed
- ``ds1qrsetup_callgraph_walk_started_at``: when the background task
  picked up
- ``ds1qrsetup_callgraph_walk_finished_at``: when the run terminated
- ``ds1qrsetup_callgraph_walk_error``: traceback summary on failure (Text)
- ``ds1qrsetup_callgraph_walk_result``: JSONB aggregate. Canonical
  shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_ds1qrsetup_callgraph_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the python_ast_walk_status / srum_walk_status
pattern (Rule #33 .c).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "c1d2e3f4q2a6"
down_revision = "6f7a8b9c0d1e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "ds1qrsetup_callgraph_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ds1qrsetup_callgraph_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ds1qrsetup_callgraph_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ds1qrsetup_callgraph_walk_error", sa.Text, nullable=True
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ds1qrsetup_callgraph_walk_result", JSONB, nullable=True
        ),
    )
    op.create_check_constraint(
        "ck_firmware_ds1qrsetup_callgraph_walk_status",
        "firmware",
        "ds1qrsetup_callgraph_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_ds1qrsetup_callgraph_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "ds1qrsetup_callgraph_walk_result")
    op.drop_column("firmware", "ds1qrsetup_callgraph_walk_error")
    op.drop_column("firmware", "ds1qrsetup_callgraph_walk_finished_at")
    op.drop_column("firmware", "ds1qrsetup_callgraph_walk_started_at")
    op.drop_column("firmware", "ds1qrsetup_callgraph_walk_status")
