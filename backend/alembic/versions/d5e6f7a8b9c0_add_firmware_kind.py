"""add firmware_kind, firmware_kind_source, rtos_flavor

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-05-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "firmware_kind",
            sa.String(20),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("firmware_kind_source", sa.String(20), nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("rtos_flavor", sa.String(40), nullable=True),
    )

    # Backfill: every existing project today is embedded Linux. Tag them as
    # detected=linux so the UI can show the source as auto-detected (and the
    # user can still override). Phase 4's auto-detector will refine these.
    op.execute(
        "UPDATE firmware SET firmware_kind = 'linux', firmware_kind_source = 'detected'"
    )


def downgrade() -> None:
    op.drop_column("firmware", "rtos_flavor")
    op.drop_column("firmware", "firmware_kind_source")
    op.drop_column("firmware", "firmware_kind")
