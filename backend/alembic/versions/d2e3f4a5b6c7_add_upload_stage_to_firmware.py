"""add upload_stage + detected_format to firmware

Revision ID: d2e3f4a5b6c7
Revises: 61b147189fcf
Create Date: 2026-05-07 14:00:00.000000

Adds five columns to the ``firmware`` table that back the upload-side
202+polling refactor (CLAUDE.md Rule #29 + Rule #33) AND the format-
detection pre-flight (intake firmware-format-detection-preflight-2026-05-07).

Why now: the synchronous ``POST /api/v1/projects/{pid}/firmware`` endpoint
runs 5+ minutes of CPU-bound work (SHA-256 over the multi-GB body, archive
extraction, filesystem-root detection, arch/endian/OS detection) AFTER the
upload bytes finish streaming. The 16 GB Illumisite recovery image earlier
this session blew past the frontend axios 600s ceiling AND the same
SECURITY_SCAN_TIMEOUT class of reverse-proxy ceilings the vuln-scan
refactor (revision c1d2e3f4a5b6) addressed last week. The frontend showed
a "timeout" toast even though the backend kept running detached and
eventually committed the firmware row — typical Rule #33 failure mode.

Columns:
- ``upload_stage``: uploading / hashing / detecting / extracting /
  analyzing / ready / failed. Default ``ready`` so existing rows are
  correctly classified post-migration (they have ``extracted_path`` /
  ``architecture`` / ``os_info`` populated → fully processed).
- ``upload_stage_started_at``: when the post-write background task
  picked the row up (i.e. when the 202 ack returned and the runner
  flipped status to ``detecting``).
- ``upload_stage_finished_at``: terminal timestamp.
- ``upload_stage_error``: short traceback summary on ``failed``.
- ``detected_format``: VARCHAR(48) populated by
  ``app/services/format_detection.py:detect_format()``. No CHECK
  constraint — the enum evolves as new format handlers ship; treating
  the column as a free-form discriminator that the Pydantic schema
  validates on response keeps migrations cheap as the format catalogue
  grows. This mirrors the precedent set by the per-finding ``source``
  field BEFORE revision 61b147189fcf tightened it (the lesson there
  was: tighten only after the value space stabilises).

A CHECK constraint covers ``upload_stage`` only — the value space is
fixed by the state machine in ``services/firmware_service.py``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd2e3f4a5b6c7'
down_revision: Union[str, None] = '61b147189fcf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


UPLOAD_STAGE_VALUES = (
    "uploading",
    "hashing",
    "detecting",
    "extracting",
    "analyzing",
    "ready",
    "failed",
)


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "upload_stage",
            sa.String(length=16),
            nullable=False,
            server_default="ready",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "upload_stage_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "upload_stage_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "upload_stage_error",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "detected_format",
            sa.String(length=48),
            nullable=True,
        ),
    )
    quoted = ", ".join(f"'{v}'" for v in UPLOAD_STAGE_VALUES)
    op.create_check_constraint(
        "ck_firmware_upload_stage",
        "firmware",
        f"upload_stage IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firmware_upload_stage", "firmware", type_="check")
    op.drop_column("firmware", "detected_format")
    op.drop_column("firmware", "upload_stage_error")
    op.drop_column("firmware", "upload_stage_finished_at")
    op.drop_column("firmware", "upload_stage_started_at")
    op.drop_column("firmware", "upload_stage")
