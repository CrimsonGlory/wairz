"""add finding_firmware association table

Revision ID: g5e6f7a8b9c0
Revises: c0d1e2f3a4b5
Create Date: 2026-06-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "g5e6f7a8b9c0"
down_revision: Union[str, None] = "c0d1e2f3a4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_firmware",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("firmware_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["firmware_id"], ["firmware.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("finding_id", "firmware_id"),
    )
    op.create_index(
        "ix_finding_firmware_firmware_id",
        "finding_firmware",
        ["firmware_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_firmware_firmware_id", table_name="finding_firmware"
    )
    op.drop_table("finding_firmware")
