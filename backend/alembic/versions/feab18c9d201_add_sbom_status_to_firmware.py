"""add_sbom_status_to_firmware

Revision ID: feab18c9d201
Revises: fd6e7f8a9b0c
Create Date: 2026-05-21 16:00:00.000000

Adds five columns to the ``firmware`` table that back the SBOM
``/generate`` 202+polling refactor (Session 2a of the 2026-05-21
SBOM/vuln-scan regression sweep; CLAUDE.md Rule #29 + Rule #33).

Background: ``POST /sbom/generate`` shipped pre-fix as a synchronous
endpoint that ran Syft / our custom strategies under the executor for
30-120s, holding the TCP connection idle past the axios floor. The
endpoint was already decorated ``@limiter.limit(TIER_A_LIGHT_ACK)``
(30/hour) — a tier shape that requires 202+polling semantics
(Rule #51 .ii — the tier shape was correct, the endpoint was wrong).
Session 1 identified the mismatch; Session 2a fixes it by converting
to the same 202+polling shape ``/sbom/vulnerabilities/scan`` shipped
in commit ``c1d2e3f4a5b6`` (2026-05-07).

Columns:
- ``sbom_status``: idle / queued / running / completed / failed
  CHECK constraint mirrors ``ck_firmware_vuln_scan_status`` from
  revision ``c1d2e3f4a5b6``. ``NOT NULL DEFAULT 'idle'`` per
  W2-β §SC5-NEW-SBOM-α (avoids the orphan-reaper-crashes-on-NULL trap
  the rate-limit-2026-05-18 campaign documented).
- ``sbom_status_started_at``: when the background task picked the row up
- ``sbom_status_finished_at``: when the run terminated (success or failure)
- ``sbom_status_error``: traceback summary on ``failed`` (Text)
- ``sbom_result`` JSONB: the result aggregate (component count, format,
  cached flag) so the polling endpoint can return the last-known-result
  on page reload WITHOUT re-running. Per Rule #33 .b
  "Persist the result aggregate on the same row used for status — not
  Redis, not in-process memory." Note: ``sbom_components`` rows are the
  authoritative result; this JSONB is a lightweight aggregate for the
  status endpoint's response shape only.

Mirrors ``c1d2e3f4a5b6`` (vuln_scan_status) for shape consistency. The
``sbom_result`` JSONB column is added here that vuln_scan does NOT have —
vuln_scan's "result" is the persisted ``sbom_vulnerabilities`` rows so
no separate aggregate column was needed; SBOM /generate's "cached" flag
and component-count summary are useful for the polling endpoint's
response shape to avoid a per-poll COUNT query.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'feab18c9d201'
down_revision: Union[str, None] = 'fd6e7f8a9b0c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SBOM_STATUS_VALUES = (
    "idle", "queued", "running", "completed", "failed",
)


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "sbom_status",
            sa.String(length=20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sbom_status_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sbom_status_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sbom_status_error",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sbom_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    quoted = ", ".join(f"'{v}'" for v in SBOM_STATUS_VALUES)
    op.create_check_constraint(
        "ck_firmware_sbom_status",
        "firmware",
        f"sbom_status IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firmware_sbom_status", "firmware", type_="check")
    op.drop_column("firmware", "sbom_result")
    op.drop_column("firmware", "sbom_status_error")
    op.drop_column("firmware", "sbom_status_finished_at")
    op.drop_column("firmware", "sbom_status_started_at")
    op.drop_column("firmware", "sbom_status")
