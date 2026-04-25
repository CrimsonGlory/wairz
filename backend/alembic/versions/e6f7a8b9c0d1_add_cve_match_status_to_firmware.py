"""add_cve_match_status_to_firmware

Revision ID: e6f7a8b9c0d1
Revises: d4a7c8b6e2f1
Create Date: 2026-04-25 22:00:00.000000

Adds five columns to the ``firmware`` table that back the cve-match
202+polling refactor (CLAUDE.md Rule #29 follow-up to the
cve-match-residual-oom-2026-04-25 intake).

The synchronous ``POST /cve-match`` worked at the memory layer after
commit 5fddd6d (streaming tier-4 persist via Core executemany) but
still ran 404 s end-to-end on the Yocto smoke firmware
(2.65 M index updates × 5 b-trees × asyncio await overhead). A 7-minute
synchronous request is past every reasonable reverse-proxy ceiling
(nginx 60 s, Cloudflare 100 s, ALB 60 s). The follow-up converts the
endpoint to the firmware-unpack precedent: 202 ack + ``asyncio.create_task``
+ frontend polling on a status endpoint.

Columns:
- ``cve_match_status``: idle / queued / running / completed / failed
- ``cve_match_started_at``: when the background task picked the row up
- ``cve_match_finished_at``: when the run terminated (success or failure)
- ``cve_match_error``: traceback summary on ``failed`` (Text)
- ``cve_match_result``: JSONB with the count/rows/hw_firmware_cves/
  kernel_cves/kernel_module_rows dict the synchronous endpoint used to
  return — kept on the row so the frontend's last-known-result render
  doesn't need to re-query ``GET /cve-aggregate`` after a successful run.

A CHECK constraint mirrors the emulation/fuzzing status pattern from
revision 54c8864fbe0c so DB-side enforcement matches the Pydantic
``Literal`` enum on ``CveMatchStatusResponse.status``.

Note: alembic autogenerate is currently blocked by the orthogonal
model-registration gap noted in d4a7c8b6e2f1; this revision is
hand-written using the a3b4c5d6e7f8_add_firmware_unpack_progress.py
precedent (same target table, same shape).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, None] = 'd4a7c8b6e2f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


CVE_MATCH_STATUS_VALUES = (
    "idle", "queued", "running", "completed", "failed",
)


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "cve_match_status",
            sa.String(length=20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "cve_match_started_at",
            sa.DateTime(timezone=False),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "cve_match_finished_at",
            sa.DateTime(timezone=False),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "cve_match_error",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "cve_match_result",
            JSONB(),
            nullable=True,
        ),
    )
    quoted = ", ".join(f"'{v}'" for v in CVE_MATCH_STATUS_VALUES)
    op.create_check_constraint(
        "ck_firmware_cve_match_status",
        "firmware",
        f"cve_match_status IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firmware_cve_match_status", "firmware", type_="check")
    op.drop_column("firmware", "cve_match_result")
    op.drop_column("firmware", "cve_match_error")
    op.drop_column("firmware", "cve_match_finished_at")
    op.drop_column("firmware", "cve_match_started_at")
    op.drop_column("firmware", "cve_match_status")
