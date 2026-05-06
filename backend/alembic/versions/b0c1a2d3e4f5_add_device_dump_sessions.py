"""add device_dump_sessions table

Revision ID: b0c1a2d3e4f5
Revises: a8f3d2c1e9b4
Create Date: 2026-05-06 00:00:00.000000

Replaces ``device_service._dump_state`` module-level global (audit-2026-05-04
finding F-A-01) with a DB-backed row per dump invocation. Standard Rule #33
202+polling shape — status column with CHECK constraint, JSONB
``partitions`` and ``result`` carrying ``schema_version`` per Rule #35c.

Status values mirror the precedent set by ``ck_emulation_sessions_status``,
``ck_fuzzing_campaigns_status``, and ``ck_firmware_cve_match_status``
(per Rule #33c). Device dumps add ``partial`` and ``cancelled`` since the
operation is multi-partition: a run can finish with some partitions OK and
others failed, distinct from a wholesale ``failed``.

This revision is hand-written following the
``c2d3e4f5a6b7_add_emulation_sessions.py`` and
``e6f7a8b9c0d1_add_cve_match_status_to_firmware.py`` precedents (same
shape, different table).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'b0c1a2d3e4f5'
down_revision: Union[str, None] = 'a8f3d2c1e9b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DEVICE_DUMP_STATUS_VALUES = (
    "queued", "running", "completed", "partial", "failed", "cancelled",
)


def upgrade() -> None:
    op.create_table(
        'device_dump_sessions',
        sa.Column(
            'id', sa.Uuid(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('device_id', sa.String(length=64), nullable=False),
        sa.Column(
            'status', sa.String(length=20),
            server_default='queued', nullable=False,
        ),
        sa.Column('dump_dir', sa.String(length=512), nullable=False),
        sa.Column('partitions', JSONB(), nullable=False),
        sa.Column(
            'bytes_written', sa.BigInteger(),
            server_default='0', nullable=False,
        ),
        sa.Column('total_bytes', sa.BigInteger(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('result', JSONB(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ['project_id'], ['projects.id'], ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'idx_device_dump_project', 'device_dump_sessions', ['project_id'],
    )
    op.create_index(
        'idx_device_dump_status', 'device_dump_sessions', ['status'],
    )
    quoted = ", ".join(f"'{v}'" for v in DEVICE_DUMP_STATUS_VALUES)
    op.create_check_constraint(
        'ck_device_dump_sessions_status',
        'device_dump_sessions',
        f"status IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint(
        'ck_device_dump_sessions_status',
        'device_dump_sessions',
        type_='check',
    )
    op.drop_index(
        'idx_device_dump_status', table_name='device_dump_sessions',
    )
    op.drop_index(
        'idx_device_dump_project', table_name='device_dump_sessions',
    )
    op.drop_table('device_dump_sessions')
