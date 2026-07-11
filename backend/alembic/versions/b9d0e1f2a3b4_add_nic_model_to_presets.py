"""Add nic_model to emulation_presets

Persists the NIC-model override (start_emulation's `nic_model` knob) alongside
the other QEMU/boot overrides.

Revision ID: b9d0e1f2a3b4
Revises: a8c9d0e1f2a3
Create Date: 2026-06-02 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b9d0e1f2a3b4"
down_revision: Union[str, None] = "a8c9d0e1f2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emulation_presets",
        sa.Column("nic_model", sa.String(50), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("emulation_presets", "nic_model")
