"""add_ics_protocol_walk_to_firmware

Revision ID: 1c52a4b5c6d7
Revises: feab18c9d201
Create Date: 2026-05-22 09:00:00.000000

Adds five columns to the ``firmware`` table that back the ICS protocol
catalog walker — CLAUDE.md Rule #52 instance #3 (Rule-of-Three DURABLE
BEYOND DEBATE when full surface ships) — per the Session 2 plan at
``.planning/research/ics-protocol-session2-2026-05-22/SESSION-2-KICKOFF.md``.

Mirrors ``feab18c9d201_add_sbom_status_to_firmware.py`` shape exactly:
the ICS walker is an operator-triggered + auto-fired Rule #33 .a 5-state
machine; the ``ics_protocol_walk_result`` JSONB carries the aggregate
walker output so the polling endpoint can return last-known-result on
page reload without re-running the scan.

Columns:
- ``ics_protocol_walk_status``: idle / queued / running / completed / failed
  CHECK constraint mirrors ``ck_firmware_bare_metal_audit_status`` from
  revision ``fc5d6e7f8a9b``. ``NOT NULL DEFAULT 'idle'`` per W2-β
  §SC5-NEW-SBOM-α (avoids the orphan-reaper-crashes-on-NULL trap the
  rate-limit-2026-05-18 campaign documented).
- ``ics_protocol_walk_started_at``: when the background task picked up
- ``ics_protocol_walk_finished_at``: when the run terminated
- ``ics_protocol_walk_error``: traceback summary on ``failed`` (Text)
- ``ics_protocol_walk_result`` JSONB: result aggregate (per-binary matches,
  per-protocol counts, snapshot_id_at_entry/_at_exit, consistency_warning
  per W2-β §SC5-NEW-ICS-S2-β, provenance sister-key per W2-β
  §SC5-NEW-ICS-S2-1). Rule #35c normaliser
  ``_normalize_firmware_ics_protocol_walk_result`` +
  ``_stamp_firmware_ics_protocol_walk_result`` +
  ``FIRMWARE_ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION = 1`` in
  ``services/jsonb_normalizers.py`` (Phase 1.B commit).

Does NOT extend ``findings.source`` CHECK — that ships in Phase 2 as a
Rule #25 Shape-1 cross-stack alignment commit alongside the Pydantic
``IcsProtocolFindingSource`` Literal + frontend mirror + Rule #48 5-part
alignment test.

Chains from Session 2a head ``feab18c9d201`` (sbom_status migration).
No backfill needed — every existing firmware row gets
``ics_protocol_walk_status='idle'`` via the server default.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '1c52a4b5c6d7'
down_revision: Union[str, None] = 'feab18c9d201'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


ICS_PROTOCOL_WALK_STATUS_VALUES = (
    "idle", "queued", "running", "completed", "failed",
)


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "ics_protocol_walk_status",
            sa.String(length=20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ics_protocol_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ics_protocol_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ics_protocol_walk_error",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "ics_protocol_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    quoted = ", ".join(f"'{v}'" for v in ICS_PROTOCOL_WALK_STATUS_VALUES)
    op.create_check_constraint(
        "ck_firmware_ics_protocol_walk_status",
        "firmware",
        f"ics_protocol_walk_status IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_ics_protocol_walk_status", "firmware", type_="check"
    )
    op.drop_column("firmware", "ics_protocol_walk_result")
    op.drop_column("firmware", "ics_protocol_walk_error")
    op.drop_column("firmware", "ics_protocol_walk_finished_at")
    op.drop_column("firmware", "ics_protocol_walk_started_at")
    op.drop_column("firmware", "ics_protocol_walk_status")
