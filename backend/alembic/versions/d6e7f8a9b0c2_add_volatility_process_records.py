r"""add volatility_process_records table + windows_processes_walk_* cols (Phase λ.β.A)

Revision ID: d6e7f8a9b0c2
Revises: c5f6a7b8c9d0
Create Date: 2026-05-14 09:00:00.000000

Phase λ.β walker — invokes Vol3's ``windows.pslist`` / ``windows.psscan`` /
``windows.pstree`` / ``windows.cmdline`` plugin family against every
``memory_dump_image`` row whose ``os_family`` is ``windows`` OR
``unknown`` for a given firmware. De-dupes process observations across
the four plugins per ``(memory_image_id, pid, image_filename,
create_time)`` and records which plugin(s) saw each process (bitfield
columns ``seen_in_pslist`` / ``seen_in_psscan`` / ``seen_in_pstree``).

The pslist/psscan delta is the highest-value forensic signal — a row
psscan-saw + pslist-missed is the canonical rootkit ``DKOM unlink``
indicator (T1014 Rootkit). ``windows.cmdline`` populates ``command_line``
+ resolves ``image_path_full`` for cross-firmware similarity hashing
(Rule #44).

Per Rule #39 inner/outer/safe runner triplet:
- Inner ``_do_windows_processes_walk`` — accepts caller-owned ``db``, walks
  memory_dump_image rows, invokes vol3_runner per (image, plugin), dedupes,
  persists VolatilityProcessRecord rows, returns aggregate UNSTAMPED.
- Outer ``run_windows_processes_walk_background`` — owns its own
  ``async_session_factory()`` session, transitions
  ``windows_processes_walk_status`` through idle → running → completed |
  failed.
- Safe ``auto_windows_processes_walk_firmware_safe`` — unpack-post-detection
  hook; stamps the aggregate but leaves status idle.

Per Rule #44 cross-firmware MCP discipline: a single migration adds both
the per-record table AND the firmware-level walk_* state-machine columns
because they ship together and create a meaningless intermediate state
if split.

Per Rule #33 .a state machine + .c CHECK constraint: the new
``windows_processes_walk_status`` column is constrained via
``ck_firmware_windows_processes_walk_status`` to the canonical 5-state
machine.

Revision ID ``d6e7f8a9b0c2`` was pre-validated FREE against the versions
tree (126 revs enumerated; chosen ID does not collide). Chains off
``c5f6a7b8c9d0`` (λ.α.D windows_info_walk_status — the single head).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "d6e7f8a9b0c2"
down_revision = "c5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── volatility_process_records table ──────────────────────────────
    op.create_table(
        "volatility_process_records",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "firmware_id",
            UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "memory_image_id",
            UUID(as_uuid=True),
            sa.ForeignKey("memory_dump_image.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("pid", sa.Integer, nullable=False),
        sa.Column("ppid", sa.Integer, nullable=True),
        sa.Column("image_filename", sa.String(256), nullable=False),
        sa.Column("command_line", sa.Text, nullable=True),
        sa.Column("image_path_full", sa.String(1024), nullable=True),
        sa.Column(
            "create_time", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "exit_time", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "seen_in_pslist",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "seen_in_psscan",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "seen_in_pstree",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "anomaly_flags",
            JSONB,
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_volatility_process_records_firmware_pid",
        "volatility_process_records",
        ["firmware_id", "pid"],
    )
    op.create_index(
        "ix_volatility_process_records_firmware_image_filename",
        "volatility_process_records",
        ["firmware_id", "image_filename"],
    )
    op.create_index(
        "ix_volatility_process_records_memory_image_id",
        "volatility_process_records",
        ["memory_image_id"],
    )

    # ── firmware.windows_processes_walk_* state-machine columns ────────
    op.add_column(
        "firmware",
        sa.Column(
            "windows_processes_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_processes_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_processes_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_processes_walk_error", sa.Text, nullable=True
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_processes_walk_result", JSONB, nullable=True
        ),
    )
    op.create_check_constraint(
        "ck_firmware_windows_processes_walk_status",
        "firmware",
        "windows_processes_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_windows_processes_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "windows_processes_walk_result")
    op.drop_column("firmware", "windows_processes_walk_error")
    op.drop_column("firmware", "windows_processes_walk_finished_at")
    op.drop_column("firmware", "windows_processes_walk_started_at")
    op.drop_column("firmware", "windows_processes_walk_status")

    op.drop_index(
        "ix_volatility_process_records_memory_image_id",
        table_name="volatility_process_records",
    )
    op.drop_index(
        "ix_volatility_process_records_firmware_image_filename",
        table_name="volatility_process_records",
    )
    op.drop_index(
        "ix_volatility_process_records_firmware_pid",
        table_name="volatility_process_records",
    )
    op.drop_table("volatility_process_records")
