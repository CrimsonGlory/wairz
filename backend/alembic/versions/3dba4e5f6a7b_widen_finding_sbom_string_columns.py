"""widen Finding.title + Finding.file_path + sbom_components.purl per Rule #15

Revision ID: 3dba4e5f6a7b
Revises: 2cba3d4e5f6a
Create Date: 2026-05-22 13:30:00.000000

Over-constraint sweep 2026-05-22 commit 5/5. Rule #15 family — three
``String(512)`` columns observed silently truncating legitimate values:

- ``findings.title`` 512 → 1024 — CRA / compliance / windows / ICS finding
  titles include OEM model + CWE list + check description, approaching
  or exceeding 512 chars.
- ``findings.file_path`` 512 → 2048 — Windows long-paths in Win11 ISO
  firmware (``\\Windows\\WinSxS\\amd64_microsoft-windows-...``) routinely
  exceed 512 chars. Compare ``windows_mft_record.full_path`` already at
  ``String(4096)`` and ``windows_lnk_record.target_path`` at ``String(2048)``.
- ``sbom_components.purl`` 512 → 1024 — Nested Maven shaded jars and npm
  scoped-package purls with full classifier metadata can exceed 512 chars.

Rule #15 precedent: ``analysis_cache.operation`` needed VARCHAR(512), was
VARCHAR(100). Same class of bug; same fix shape.

PostgreSQL ``ALTER COLUMN ... TYPE VARCHAR(N)`` with larger N is a
metadata-only operation when the new length >= old length — no table
rewrite, runs in milliseconds even on large ``findings``/
``sbom_components`` tables.

Downgrade is destructive only if rows have grown past the OLD cap during
the new-cap window; the downgrade truncates rather than failing (uses
``USING substring(<col>, 1, N)``) to allow safe rollback.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3dba4e5f6a7b"
down_revision: Union[str, None] = "2cba3d4e5f6a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # findings.title 512 → 1024
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.String(length=512),
        type_=sa.String(length=1024),
        existing_nullable=False,
    )
    # findings.file_path 512 → 2048
    op.alter_column(
        "findings",
        "file_path",
        existing_type=sa.String(length=512),
        type_=sa.String(length=2048),
        existing_nullable=True,
    )
    # sbom_components.purl 512 → 1024
    op.alter_column(
        "sbom_components",
        "purl",
        existing_type=sa.String(length=512),
        type_=sa.String(length=1024),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Downgrade truncates rather than failing on rows that grew past the
    # old cap during the new-cap window. ``USING substring(...)`` ensures
    # the operation succeeds even with longer-than-old-cap rows present.
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.String(length=1024),
        type_=sa.String(length=512),
        existing_nullable=False,
        postgresql_using="substring(title, 1, 512)",
    )
    op.alter_column(
        "findings",
        "file_path",
        existing_type=sa.String(length=2048),
        type_=sa.String(length=512),
        existing_nullable=True,
        postgresql_using="substring(file_path, 1, 512)",
    )
    op.alter_column(
        "sbom_components",
        "purl",
        existing_type=sa.String(length=1024),
        type_=sa.String(length=512),
        existing_nullable=True,
        postgresql_using="substring(purl, 1, 512)",
    )
