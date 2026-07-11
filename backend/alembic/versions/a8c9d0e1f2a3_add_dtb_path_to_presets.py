"""Add dtb_path to emulation_presets

Persists the device-tree blob override (start_emulation's `dtb` knob) alongside
the other QEMU/boot overrides so a working DT-kernel bring-up can be replayed.

Revision ID: a8c9d0e1f2a3
Revises: f7b8c9d0e1f2
Create Date: 2026-06-02 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a8c9d0e1f2a3"
down_revision: Union[str, None] = "f7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emulation_presets",
        sa.Column("dtb_path", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("emulation_presets", "dtb_path")
