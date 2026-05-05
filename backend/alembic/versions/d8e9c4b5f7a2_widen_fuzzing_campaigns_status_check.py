"""widen fuzzing_campaigns status CHECK to include 202-polling values

Revision ID: d8e9c4b5f7a2
Revises: a9f4e9cdabe2
Create Date: 2026-05-05

Companion to migration `c3f8a1b9e4d2_widen_emulation_session_status_check`
for the fuzzing 202+polling refactor (Wave-1 Stream β, commit `df30015`,
2026-04-20).  The fuzzing service writes `campaign.status = "queued"`
at `backend/app/services/fuzzing_service.py:393` after the refactor,
but the matching CHECK-constraint widening was missed — every
`POST /fuzzing/campaigns/{id}/start` triggers `CheckViolationError`
on flush.  Audit `audit-2026-05-04` confirmed across streams B+C+F.

Drops and recreates `ck_fuzzing_campaigns_status` to add `queued`.
Mirrors the shape of `c3f8a1b9e4d2` so that future drift between
emulation and fuzzing constraints stays visible at a glance.

Downgrade restores the original 5-value set; rows currently at
`status = "queued"` must be migrated or deleted before downgrade.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'd8e9c4b5f7a2'
down_revision: Union[str, None] = 'a9f4e9cdabe2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Expanded allowlist — adds "queued" (row created before the detached
# spawn task transitions to "running"). Order: created → queued → running
# → stopped/completed/error reflects the lifecycle.
FUZZING_STATUS_VALUES_V2 = (
    "created", "queued", "running", "stopped", "completed", "error",
)
FUZZING_STATUS_VALUES_V1 = (
    "created", "running", "stopped", "completed", "error",
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.drop_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        type_="check",
    )
    op.create_check_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        _in_list_sql("status", FUZZING_STATUS_VALUES_V2),
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        type_="check",
    )
    op.create_check_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        _in_list_sql("status", FUZZING_STATUS_VALUES_V1),
    )
