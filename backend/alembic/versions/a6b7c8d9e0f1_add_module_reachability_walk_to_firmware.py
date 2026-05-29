r"""add module_reachability_walk extraction walker state machine

Revision ID: a6b7c8d9e0f1
Revises: f4a5b6c7d8e9
Create Date: 2026-05-29 16:00:00.000000

DDL infrastructure for the C2 ``module_reachability_walker`` (the generic
module/driver REACHABILITY-EVIDENCE collector) per CLAUDE.md Rule #33 .a
5-state contract.

C2 produces the loaded-vs-available-vs-BUILTIN module evidence the
cve-assessment-framework L4 kill-chain classifier consumes (the framework
``ModuleEntry.builtin`` discriminator + ``kernel/builtin_modules.json`` was
wired framework-side). The 3-way diff lets the classifier tell an
immutable static-builtin / ``=n`` driver (clearable) from a ``=m``-not-loaded
driver (mutable → guilty), closing the KRACK-style compound-immutable gap
(R51.1 C2 GAP-CLOSED).

C2 is DISTINCT from C1 ``kernel_config_walk_*`` (migration ``e3f4a5b6c7d8``):

- ``kernel_config_walk_*`` — C1 extracts the kernel ``.config`` (the
  ``=y``/``=m``/``=n`` axis) cross-packaging.
- ``module_reachability_walk_*`` (this migration) — C2 enumerates the
  on-disk loadable module set (``/lib/modules`` ``*.ko``), the depmod
  ``modules.builtin`` set, and the configured-to-load set, and READS C1's
  back-filled ``metadata.kernel_config`` for the ``builtin_y_from_config``
  axis. It detects the "static-builtin posture" (0 ``.ko`` on disk + drivers
  ``=y``) where the BUILTIN set IS the reachability axis (the phone case).

New ``firmware`` columns:

- ``module_reachability_walk_status``
  (Literal[idle|queued|running|completed|failed]) +
  ``ck_firmware_module_reachability_walk_status`` CHECK
- ``module_reachability_walk_started_at`` /
  ``module_reachability_walk_finished_at`` timestamps
- ``module_reachability_walk_error`` text (failure trace)
- ``module_reachability_walk_result`` JSONB (per-run reachability aggregate;
  Rule #35c normaliser pair +
  ``FIRMWARE_MODULE_REACHABILITY_WALK_RESULT_SCHEMA_VERSION`` lands in the
  jsonb_normalizers commit)

Mirrors ``e3f4a5b6c7d8`` (C1 kernel_config_walk state machine). No new
table — the walker reads modules from the firmware extraction tree (Rule #16
detection roots) and writes back only onto the existing
``firmware.module_reachability_walk_result`` JSONB column.

Chains from ``f4a5b6c7d8e9`` (extend_findings_source_kernel_config_extraction_blocked
— the single alembic head verified 2026-05-29). Revision ID ``a6b7c8d9e0f1``
chosen distinct from existing IDs to avoid the collision lesson in commit
``a51b15a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "a6b7c8d9e0f1"
down_revision: str | None = "f4a5b6c7d8e9"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "module_reachability_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_module_reachability_walk_status",
        "firmware",
        "module_reachability_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "module_reachability_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "module_reachability_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("module_reachability_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "module_reachability_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "module_reachability_walk_result")
    op.drop_column("firmware", "module_reachability_walk_error")
    op.drop_column("firmware", "module_reachability_walk_finished_at")
    op.drop_column("firmware", "module_reachability_walk_started_at")
    op.drop_constraint(
        "ck_firmware_module_reachability_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "module_reachability_walk_status")
