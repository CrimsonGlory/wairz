"""add windows_event_records table (Phase ε.2.A)

Revision ID: f1a2b3c4d5e6
Revises: e1a2b3c4d5e6
Create Date: 2026-05-10 11:00:00.000000

Phase ε.2.A — adds the per-event landing zone for the EVTX walker.
ε.1.b's ``firmware.evtx_walk_result`` JSONB carries the per-firmware
aggregate (counts, providers, sample); ε.2.A introduces the per-event
table so future search-events MCP tools (ε.2.C, deferred to follow-up)
can paginate filtered results without re-walking.

The table FKs to ``firmware.id`` with ON DELETE CASCADE so removing
a firmware row removes all its events. Two composite indexes cover
the operator-visible filters:

- ``ix_windows_event_records_firmware_provider_eid`` — supports
  "find every Sysmon-1 / Security-4624 / Security-4625 event for
  this firmware".
- ``ix_windows_event_records_firmware_recorded_at`` — supports
  forensic-timeline reconstruction (time-bounded queries).

Per Phase ε.2 campaign decision: ε.2.A ships the table only; ε.2.B
(walker persistence wire-up) and ε.2.C (search MCP) are deferred to
follow-up sessions per Rule #25 per-sub-task discipline. The table
ships with the model + JSONB normaliser + alignment so the next
session resumes without schema drift.

Per CLAUDE.md Rule #19 generalised: this migration touches
infrastructure (alembic chain). Rule #8 extended rebuild
(backend + worker + migrator) MUST run before declaring complete.
Pre-validated revision ID: ``f1a2b3c4d5e6`` confirmed FREE in the
versions tree of size 62 (Python regex script per Pattern #2).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "e1a2b3c4d5e6"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_event_records",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "firmware_id",
            UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evtx_file_path", sa.String(1024), nullable=False),
        sa.Column("provider", sa.String(256), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("level", sa.Integer(), nullable=True),
        sa.Column("channel", sa.String(256), nullable=True),
        sa.Column("computer", sa.String(256), nullable=True),
        sa.Column("task", sa.Integer(), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("message_xml", JSONB, nullable=True),
        sa.Column("raw_xml", sa.Text(), nullable=True),
        sa.Column("record_number", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_event_records_firmware_provider_eid",
        "windows_event_records",
        ["firmware_id", "provider", "event_id"],
    )
    op.create_index(
        "ix_windows_event_records_firmware_recorded_at",
        "windows_event_records",
        ["firmware_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_event_records_firmware_recorded_at",
        table_name="windows_event_records",
    )
    op.drop_index(
        "ix_windows_event_records_firmware_provider_eid",
        table_name="windows_event_records",
    )
    op.drop_table("windows_event_records")
