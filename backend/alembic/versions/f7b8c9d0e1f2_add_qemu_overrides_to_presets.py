"""Add QEMU/boot override columns to emulation_presets

Lets the agent persist system-mode bring-up knobs (cpu, machine, mem, smp,
kernel_append, initrd_path, drive_interface, root_dev, qemu_extra_args) so a
working emulation configuration can be saved and replayed.

Revision ID: f7b8c9d0e1f2
Revises: e6f7a8b9c0d1
Create Date: 2026-06-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f7b8c9d0e1f2"
down_revision: Union[str, None] = "e6f7a8b9c0d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_COLUMNS = [
    ("cpu", sa.String(50)),
    ("machine", sa.String(50)),
    ("mem", sa.Integer()),
    ("smp", sa.Integer()),
    ("kernel_append", sa.Text()),
    ("initrd_path", sa.String(512)),
    ("drive_interface", sa.String(20)),
    ("root_dev", sa.String(50)),
    ("qemu_extra_args", sa.Text()),
]


def upgrade() -> None:
    for name, type_ in _COLUMNS:
        op.add_column(
            "emulation_presets",
            sa.Column(name, type_, nullable=True),
        )


def downgrade() -> None:
    for name, _ in reversed(_COLUMNS):
        op.drop_column("emulation_presets", name)
