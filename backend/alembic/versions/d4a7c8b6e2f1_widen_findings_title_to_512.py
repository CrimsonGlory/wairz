"""widen_findings_title_to_512

Revision ID: d4a7c8b6e2f1
Revises: c3f8a1b9e4d2
Create Date: 2026-04-25 00:00:00.000000

The Finding.title column was created as VARCHAR(255) but the
credentials-detector formats title as
``f"Hardcoded credential in {path}"`` — on deeply-nested firmware
extracts (e.g. ``/zImage-restore.tar.xz_extract/.../etc/.../delegates.xml``)
the path alone reaches ~290 chars. The whole /security/audit pipeline
runs to completion, then the per-finding flush triggers
``StringDataRightTruncationError`` and rolls back the entire transaction
— no findings persist even though every scanner ran successfully.

Widening to 512 matches the existing ``file_path`` column width and is
a metadata-only ALTER in PostgreSQL (no lock storm, non-blocking).

Note: alembic autogenerate is currently blocked by an orthogonal
model-registration gap (``hardware_firmware`` model is referenced via
FK from ``SbomVulnerability`` but not exported via ``app/models/__init__.py``);
this revision was hand-written using the
``1f6c72decc84_widen_analysis_cache_operation_to_512`` precedent.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4a7c8b6e2f1'
down_revision: Union[str, None] = 'c3f8a1b9e4d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.String(length=255),
        type_=sa.String(length=512),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Truncates any rows whose title > 255 chars. Irreversible for
    # those rows (original value not recoverable). Kept for completeness.
    op.execute(
        "UPDATE findings SET title = LEFT(title, 255) "
        "WHERE length(title) > 255"
    )
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.String(length=512),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
