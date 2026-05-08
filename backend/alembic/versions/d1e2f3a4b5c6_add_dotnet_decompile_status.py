"""add dotnet_decompile_* columns to firmware (Phase δ.2)

Revision ID: d1e2f3a4b5c6
Revises: d0e1f2a3b4c5
Create Date: 2026-05-09 17:30:00.000000

Adds five columns to the ``firmware`` table for the Phase δ batch
.NET single-file bundle decompile 202+polling refactor (CLAUDE.md Rule
#33 contract). Mirrors the cve_match_status / vuln_scan_status /
authenticode_chain_status / registry_hive_walk_status patterns already
on the table.

Phase δ.4 worker ``decompile_dotnet_bundle_job`` walks every detected
.NET single-file bundle in the firmware's hardware_firmware_blobs (PE
table walk via dnfile per Rule #36 — DATA only, no .NET assembly entry
point invocation) and runs ilspycmd inside the gated worker container
(Dockerfile ``ARG INCLUDE_DOTNET=1`` brings in dotnet-runtime-8.0 +
ilspycmd). The aggregate result (counts of bundles_decompiled,
total_assemblies_extracted, run_seconds, per-bundle output paths) lands
in ``dotnet_decompile_result`` so the frontend's last-known-result
render survives a session reload.

Per Rule #33 .d (asyncio.create_task vs arq rubric): .NET decompile
work coordinates with worker-only resources (the gated dotnet-runtime
+ ilspycmd dotnet-tool spawn happens inside the worker container, NOT
the backend). Per the rubric clauses (i) work coordinates with worker-
only resources AND (ii) work survives backend restarts via durable
Redis-queue state, dispatch is **arq** — not asyncio.create_task. δ.4
adds the arq job + worker registration; the trigger-MCP-tool layer
(δ.7) enqueues via arq.

Columns:

- ``dotnet_decompile_status``: idle / queued / running / completed / failed
- ``dotnet_decompile_started_at``: when the arq job picked the row up
- ``dotnet_decompile_finished_at``: when the run terminated
- ``dotnet_decompile_error``: traceback summary on failure (Text)
- ``dotnet_decompile_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_dotnet_decompile_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the cve_match / vuln_scan / authenticode_chain
/ registry_hive_walk pattern (Rule #33 .c). The matching Pydantic
``DotnetDecompileStatus`` Literal at the writer boundary catches code-
side typos; this CHECK catches direct-SQL writes.

Per Rule #36 no-execute discipline: ilspycmd reads the .NET bundle AS
DATA (PE table walking via dnfile, IL extraction via ILSpy's IL
serialiser); nothing in wairz invokes the .NET assembly's entry point.
δ.4 worker ships a forbidden-token scan over the decompile_log + output
tree as the test gate.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "d1e2f3a4b5c6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "dotnet_decompile_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "dotnet_decompile_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "dotnet_decompile_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("dotnet_decompile_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("dotnet_decompile_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_dotnet_decompile_status",
        "firmware",
        "dotnet_decompile_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_dotnet_decompile_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "dotnet_decompile_result")
    op.drop_column("firmware", "dotnet_decompile_error")
    op.drop_column("firmware", "dotnet_decompile_finished_at")
    op.drop_column("firmware", "dotnet_decompile_started_at")
    op.drop_column("firmware", "dotnet_decompile_status")
