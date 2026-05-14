r"""add ix_windows_scheduled_tasks_firmware_task_name index

Revision ID: e1f2a3b4c5d6
Revises: e0f1a2b3c4d5
Create Date: 2026-05-14 17:00:00.000000

The Rule #44 ``lookup_scheduled_task_across_firmwares`` MCP tool
(Issue #15.4, commit ``82f41cc``) filters on
``WindowsScheduledTask.task_name == task_name`` joined across all
firmwares in a project (or globally). The SQL-audit 2026-05-14
flagged this as the only walker where the cross-firmware filter
column lacked an index — every other walker has either an explicit
index on its identity column (BCD ``object_guid``, ESP / MBR-VBR /
SDB ``fingerprint_sha256``, prefetch ``executable_name``, SRUM
``app_identifier``) or a composite-prefix that covers it (EVTX
``(provider, event_id)``, MFT ``filename``, LNK ``target_path``).

This migration adds the missing composite index
``(firmware_id, task_name)``. Mirror added to the ORM
``__table_args__`` in the same commit so subsequent ``alembic check``
runs see no drift.
"""
from __future__ import annotations

from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "e0f1a2b3c4d5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_windows_scheduled_tasks_firmware_task_name",
        "windows_scheduled_tasks",
        ["firmware_id", "task_name"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_scheduled_tasks_firmware_task_name",
        table_name="windows_scheduled_tasks",
    )
