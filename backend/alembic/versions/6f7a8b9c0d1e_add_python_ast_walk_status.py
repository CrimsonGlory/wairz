"""add python_ast_walk_* columns to firmware (Q1 Python AST walker)

Revision ID: 6f7a8b9c0d1e
Revises: 5e6f7a8b9c0d
Create Date: 2026-05-27 12:00:00.000000

Adds five columns to the ``firmware`` table for the Q1 Python AST
walker 202+polling refactor (CLAUDE.md Rule #33 contract). Mirrors the
srum_walk_status / prefetch_walk_status / evtx_walk_status patterns
already on the table.

The walker performs static AST + import-graph analysis of Python
source files in a firmware extraction. For each (module, callable)
pair it determines reachability from a "rooted" entry-point set
(typically Flask/FastAPI route handlers). The cve-assessment-framework
consumes the JSON aggregate to narrow Python CVE applicability via
deployed-script grep precedent (Round-9.1 §12 EG-8A.3-5).

Per Rule #33 .d (asyncio.create_task vs arq rubric): Python AST walks
run entirely in-process (``ast.parse`` is pure CPU; no Docker spawn,
no subprocess), and the JSONB aggregate is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B.

**Rule #45 + Rule #36 PARSE-ONLY discipline.** The walker invokes
``ast.parse(source, mode='exec')`` on Python source files but NEVER
executes them — ``ast.parse`` is a syntactic parser that produces an
AST tree without running any code. wairz does NOT invoke ``compile()`` +
``exec()`` / ``runpy.run_path`` / ``importlib.import_module`` on
firmware-extracted source.

Columns:

- ``python_ast_walk_status``: idle / queued / running / completed / failed
- ``python_ast_walk_started_at``: when the background task picked up
- ``python_ast_walk_finished_at``: when the run terminated
- ``python_ast_walk_error``: traceback summary on failure (Text)
- ``python_ast_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_python_ast_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the srum_walk_status / prefetch_walk_status
pattern (Rule #33 .c).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "6f7a8b9c0d1e"
down_revision = "5e6f7a8b9c0d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "python_ast_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "python_ast_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "python_ast_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("python_ast_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("python_ast_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_python_ast_walk_status",
        "firmware",
        "python_ast_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_python_ast_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "python_ast_walk_result")
    op.drop_column("firmware", "python_ast_walk_error")
    op.drop_column("firmware", "python_ast_walk_finished_at")
    op.drop_column("firmware", "python_ast_walk_started_at")
    op.drop_column("firmware", "python_ast_walk_status")
