r"""add windows_info_walk_* columns to firmware (Phase λ.α.D)

Revision ID: c5f6a7b8c9d0
Revises: bdf2a3b4c5d6
Create Date: 2026-05-13 14:30:00.000000

Adds five columns to the ``firmware`` table for the Phase λ.α.D
windows.info walker — the first Vol3-backed walker to invoke
:mod:`app.services.vol3_runner` against ``memory_dump_image`` rows
enumerated by λ.α.B. Mirrors the existing ``memory_dump_walk_*`` /
``registry_hive_walk_*`` / ``prefetch_walk_*`` / ``evtx_walk_*`` /
``srum_walk_*`` / ``scheduled_task_walk_*`` / ``lnk_walk_*`` /
``mft_walk_*`` / ``bcd_walk_*`` pattern — same 5-column shape, same
Rule #33 .c CHECK constraint.

The λ.α.D walker (``backend/app/services/windows_info_walker.py``):

- Resolves :func:`app.services.firmware_paths.get_detection_roots` per
  Rule #16 (NOT bare ``firmware.extracted_path``).
- Iterates every ``memory_dump_image`` row whose ``os_family`` is
  ``"windows"`` OR ``"unknown"`` (the unknown bucket exists because
  raw acquisitions carry no magic — Vol3's automagic LayerStacker
  classifies them at scan time).
- Invokes :func:`app.services.vol3_runner.run_vol3_plugin` with
  plugin ``"windows.info"`` and the per-image absolute path. Each
  invocation: 1 subprocess + 1 (image, plugin) round-trip + 1 JSONB
  per-image record persistence (``kernel_hint`` + ``isf_profile_guess``
  + ``last_walked_at`` stamped onto the ``memory_dump_image`` row).
- Aggregates per-firmware: image_count, classified_count,
  by_os_kernel_family, total elapsed_s, errors_per_image.

Per Rule #33 .a state machine: ``windows_info_walk_status`` Literal
matches the 5-state pattern; CHECK constraint enforces it. The walker's
202+polling endpoint (λ.δ MCP tool) reads ``windows_info_walk_result``
from this row on every poll for the last-known aggregate.

Per Rule #33 .d (asyncio.create_task vs arq rubric): the walker delegates
to ``vol3_runner.run_vol3_plugin`` which uses
``asyncio.create_subprocess_exec``. The outer walker runs as
``asyncio.create_task`` from the unpack-post-detection hook OR from
the future λ.δ trigger endpoint. Per-image rows are incrementally
persisted within the same outer task; a mid-run crash is recoverable
via re-run dedup on the per-image row's UniqueConstraint. arq isn't
needed — the work is in-process and the per-image state IS the durable
state.

Per Rule #33 .b (result aggregate on the same row): the JSONB
``windows_info_walk_result`` column stores the per-firmware aggregate
(image_count + classified_count + by_os_kernel_family +
total_elapsed_s); per-image kernel_hint + isf_profile_guess go on
``memory_dump_image`` rows directly. Survives backend restart AND page
reload.

Per Rule #33 .c (Literal + DB CHECK): the migration adds the CHECK
constraint ``ck_firmware_windows_info_walk_status``. The corresponding
Pydantic Literal lives in the walker's schema imports.

Columns:

- ``windows_info_walk_status``: idle / queued / running / completed / failed
- ``windows_info_walk_started_at``: when the background task picked up
- ``windows_info_walk_finished_at``: when the run terminated
- ``windows_info_walk_error``: traceback summary on failure (Text)
- ``windows_info_walk_result``: JSONB aggregate ``{schema_version: 1,
  image_count: int, classified_count: int, by_os_kernel_family:
  {windows10: int, windows11: int, windows_server: int, unknown: int},
  total_elapsed_s: float, errors_per_image: list[str]}``.

Revision ID ``c5f6a7b8c9d0`` was pre-validated FREE against the versions
tree before authoring (Rule #19 evidence-first — 125 existing revisions
enumerated; the chosen ID does not collide).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "c5f6a7b8c9d0"
down_revision = "bdf2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "windows_info_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_info_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_info_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("windows_info_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("windows_info_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_windows_info_walk_status",
        "firmware",
        "windows_info_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_windows_info_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "windows_info_walk_result")
    op.drop_column("firmware", "windows_info_walk_error")
    op.drop_column("firmware", "windows_info_walk_finished_at")
    op.drop_column("firmware", "windows_info_walk_started_at")
    op.drop_column("firmware", "windows_info_walk_status")
