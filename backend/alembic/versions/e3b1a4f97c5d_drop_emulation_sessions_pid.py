"""drop emulation_sessions.pid (dead column)

Revision ID: e3b1a4f97c5d
Revises: 89007f64cfb0
Create Date: 2026-05-05

Drops ``emulation_sessions.pid`` per audit-2026-05-04 quick-wins M-13
(Stream C F-C-08).  No backend code reads or writes this column — grep
across ``backend/app/`` returns zero hits outside the model definition
and one MagicMock attribute set in ``test_emulation_auth.py`` (also
removed in this commit).  Originally added in revision
``c2d3e4f5a6b7_add_emulation_sessions`` for an OS-level QEMU PID that
was never actually plumbed; the current emulation flow tracks the
running container by ``container_id`` instead, which is sufficient for
``docker stop`` / ``docker logs`` / status polling.

Downgrade restores the column as nullable Integer with no default,
matching the original definition.

Sibling column ``emulation_sessions.kernel_used`` is also unwritten in
production but DOES have a read site
(``backend/app/ai/tools/emulation.py:2763``) plus a schema field
(``app/schemas/emulation.py:148``).  It is intentionally NOT dropped
here — the right close is to plumb the write path
(``system_emulation_service`` should record which kernel image FirmAE
selected), which is a separate intake item.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e3b1a4f97c5d"
down_revision: Union[str, None] = "89007f64cfb0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("emulation_sessions", "pid")


def downgrade() -> None:
    op.add_column(
        "emulation_sessions",
        sa.Column("pid", sa.Integer(), nullable=True),
    )
