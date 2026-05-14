r"""make volatility_*_records.created_at NOT NULL (drift fix)

Revision ID: e0f1a2b3c4d5
Revises: d8e9f0a1b2c4
Create Date: 2026-05-14 16:00:00.000000

The λ.β.A (``d6e7f8a9b0c2``) and λ.γ.A (``d8e9f0a1b2c4``) migrations
created ``created_at`` columns with ``server_default=now()`` but did not
declare ``nullable=False``. SQLAlchemy 2.0's ORM declares the columns
as ``Mapped[datetime]`` (non-Optional ⇒ NOT NULL) so ``alembic check``
on the post-d8 DB reports a ``modify_nullable`` drift on both tables.

This is a NOT-NULL backfill — every row's ``created_at`` is always set
by the server default at INSERT time, so no row can have NULL today.
The ALTER is forward-only; tables are empty in dev (and never accumulate
nullable rows since the default fires unconditionally), so the
``USING created_at`` clause is unnecessary.

Per the audit-models-orm-vs-db-schema-drift-2026-05-05 playbook (the
``alembic check`` gate the test ``test_alembic_autogenerate_is_empty``
backstops): when ORM and DB disagree on nullability, ship the smallest
forward-only migration that aligns them. We do NOT amend the original
λ.β.A / λ.γ.A migrations because they have shipped to main (commits
624556c and 89b6f0f, 2026-05-13/14) and CI has run them.
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e0f1a2b3c4d5"
down_revision = "d8e9f0a1b2c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "volatility_process_records",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_server_default=sa.text("now()"),
        nullable=False,
    )
    op.alter_column(
        "volatility_injection_records",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_server_default=sa.text("now()"),
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "volatility_injection_records",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_server_default=sa.text("now()"),
        nullable=True,
    )
    op.alter_column(
        "volatility_process_records",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_server_default=sa.text("now()"),
        nullable=True,
    )
