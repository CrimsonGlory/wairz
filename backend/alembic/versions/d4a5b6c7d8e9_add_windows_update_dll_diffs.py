"""add windows_update_dll_diffs table for Phase δ.5 per-DLL incremental persistence

Revision ID: d4a5b6c7d8e9
Revises: d3a4b5c6d7e8
Create Date: 2026-05-09 18:30:00.000000

Per-DLL diff record table that backs the Phase δ.5 background runner
``_run_windows_update_diff_background`` (asyncio.create_task dispatch
per Rule #33 .d). Each row captures the diff verdict for one DLL across
the most-recent KB pair within a firmware; the UniqueConstraint on
(firmware_id, dll_path) makes the runner idempotent on restart — a
mid-run crash leaves already-completed rows in place, and the next run
UPSERTs them rather than INSERTing duplicates.

Per Rule #33 .d (asyncio.create_task vs arq rubric): the per-DLL table
IS the durable state — the in-process pure-Python diff runs in stages,
flushing each DLL's verdict via ``ON CONFLICT DO UPDATE`` (alembic-modeled
via the UniqueConstraint + service-side ``insert(...).on_conflict_do_update``).
Restart recovery is automatic: the runner re-reads the per-DLL table to
skip already-completed rows (or simply re-computes them — both verdicts
are identical when the bundle SHA256 hasn't changed).

Schema:

- ``id`` UUID PK
- ``firmware_id`` UUID FK firmware(id) ON DELETE CASCADE NOT NULL
- ``dll_path`` VARCHAR(1024) NOT NULL — relative path of the DLL within
  the package's extracted tree (e.g. ``amd64_microsoft-windows-kernel-base/
  ntdll.dll`` or ``Windows10.0-KB5036893-x64.cab/<...>/win32k.sys``).
  The (firmware_id, dll_path) tuple is unique across the firmware's
  diff run.
- ``older_kb`` VARCHAR(32) NULL — KB ID where the DLL was sourced from
  on the older side; NULL if the DLL is "added" (only in newer KB).
- ``newer_kb`` VARCHAR(32) NULL — KB ID for the newer side; NULL if the
  DLL is "removed" (only in older KB).
- ``older_sha256`` VARCHAR(64) NULL — SHA256 of the older copy
- ``newer_sha256`` VARCHAR(64) NULL — SHA256 of the newer copy
- ``diff_type`` VARCHAR(32) NOT NULL — 'added' | 'removed' | 'modified' |
  'unchanged'. CHECK constraint matches Pydantic
  ``WindowsUpdateDllDiffType`` Literal at the writer boundary per Rule
  #33 .c.
- ``file_size_delta`` BigInteger NULL — newer_size - older_size; NULL
  for added/removed where one side is undefined. Surfaces the most-
  changed-by-bytes DLLs without re-walking the file system.
- ``created_at`` / ``updated_at`` TIMESTAMPTZ — runner UPSERT's
  updated_at on re-run.

Indexes:

- ``firmware_id``: cascade traversal + per-firmware navigation (the
  dominant access pattern — δ.7 MCP ``windows_update.list_dll_diffs``
  scopes to a firmware).
- ``diff_type``: filter chip queries on the operator UI ("show me
  every DLL that was MODIFIED across the diff").
- ``dll_path``: cross-firmware filter for "is this DLL ever changed in
  any firmware in this dataset?" — informs Persona-E #5 R2R-stomping
  hot-path detection.

UniqueConstraint on (firmware_id, dll_path): per the kickoff δ.5 spec,
restart recovery via the natural-key uniqueness. Per-DLL UPSERT writes.

Rule #36 no-execute discipline: this table holds DATA only — the δ.5
runner SHA256s the already-extracted CAB/MSU contents (α-phase
unpacker outputs) and compares; no installer entry-point is invoked
at any stage.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "d4a5b6c7d8e9"
down_revision = "d3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_update_dll_diffs",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "firmware_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("dll_path", sa.String(1024), nullable=False),
        sa.Column("older_kb", sa.String(32), nullable=True),
        sa.Column("newer_kb", sa.String(32), nullable=True),
        sa.Column("older_sha256", sa.String(64), nullable=True),
        sa.Column("newer_sha256", sa.String(64), nullable=True),
        sa.Column(
            "diff_type",
            sa.String(32),
            nullable=False,
            server_default="unchanged",
        ),
        sa.Column("file_size_delta", sa.BigInteger, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Rule #33 .c durable gate — Pydantic Literal at the writer
        # boundary catches typos at code-load time; this CHECK catches
        # direct-SQL writes (cron scripts, manual fixes, partial-failure
        # rollbacks) that bypass the Pydantic layer.
        sa.CheckConstraint(
            "diff_type IN ('added', 'removed', 'modified', 'unchanged')",
            name="ck_windows_update_dll_diffs_type",
        ),
        # Restart recovery via UPSERT — the runner re-runs idempotently
        # against this natural key.
        sa.UniqueConstraint(
            "firmware_id",
            "dll_path",
            name="uq_windows_update_dll_diffs_fw_path",
        ),
    )
    op.create_index(
        "ix_windows_update_dll_diffs_firmware_id",
        "windows_update_dll_diffs",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_update_dll_diffs_diff_type",
        "windows_update_dll_diffs",
        ["diff_type"],
    )
    op.create_index(
        "ix_windows_update_dll_diffs_dll_path",
        "windows_update_dll_diffs",
        ["dll_path"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_update_dll_diffs_dll_path",
        table_name="windows_update_dll_diffs",
    )
    op.drop_index(
        "ix_windows_update_dll_diffs_diff_type",
        table_name="windows_update_dll_diffs",
    )
    op.drop_index(
        "ix_windows_update_dll_diffs_firmware_id",
        table_name="windows_update_dll_diffs",
    )
    op.drop_table("windows_update_dll_diffs")
