"""widen emulation_sessions status CHECK to include 202-polling values

Revision ID: c3f8a1b9e4d2
Revises: 123cc2c5463a
Create Date: 2026-04-20 18:15:00.000000

Rule #29 202+polling refactor, Fleet Wave 1 Stream α — the
`POST /emulation/start` endpoint now returns 202 with status="pending"
and transitions the row through `pending → booting → ready` in a
background task (via `asyncio.create_task` / arq job
`spawn_emulation_session_job`). Migration 54c8864fbe0c added a CHECK
constraint on `emulation_sessions.status` that only allows the
pre-202 values ("created", "starting", "running", "stopping",
"stopped", "error"). Any INSERT with the new values fails with
`CheckViolationError: ck_emulation_sessions_status`.

This migration drops and re-creates the constraint with the expanded
set: adds "pending" (row created before background task picks it up),
"booting" (Docker container created, waiting on health probe), and
"ready" (health probe succeeded, terminal WebSocket safe to attach).

Downgrade drops the expanded constraint and re-creates the original
6-value constraint. Existing rows at any of the new three values must
be manually migrated or deleted before downgrade succeeds — pgsql
will reject the ALTER TABLE if live data violates the narrower
constraint.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c3f8a1b9e4d2'
down_revision: Union[str, None] = '123cc2c5463a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Expanded allowlist — the three trailing values are the 202-polling
# lifecycle. Order preserved for readability against the pre-expansion
# set in `54c8864fbe0c_add_enum_check_constraints.py`.
EMULATION_STATUS_VALUES_V2 = (
    "created", "pending", "starting", "booting",
    "running", "ready", "stopping", "stopped", "error",
)
EMULATION_STATUS_VALUES_V1 = (
    "created", "starting", "running", "stopping", "stopped", "error",
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.drop_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        type_="check",
    )
    op.create_check_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        _in_list_sql("status", EMULATION_STATUS_VALUES_V2),
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        type_="check",
    )
    op.create_check_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        _in_list_sql("status", EMULATION_STATUS_VALUES_V1),
    )
