"""add_vuln_scan_status_to_firmware

Revision ID: c1d2e3f4a5b6
Revises: b0c1a2d3e4f5
Create Date: 2026-05-07 12:35:08.000000

Adds four columns to the ``firmware`` table that back the SBOM
vulnerability-scan 202+polling refactor (CLAUDE.md Rule #29 + Rule #33).

The synchronous ``POST /sbom/vulnerabilities/scan`` succeeded at the
backend layer (5,104 SbomVulnerability rows persisted in a single
transaction for firmware ``0977b260-…`` / 72 components, ~4m10s of
wall-time) but the frontend's axios floor / network blip / browser
backgrounding tripped before the response landed — surfacing as a
phantom "scan failed" toast even though the rows were intact. With a
16 GB Illumisite image landing next, the synchronous tier blows past
the SECURITY_SCAN_TIMEOUT (600s) ceiling on a cold Grype DB sync.

Columns:
- ``vuln_scan_status``: idle / queued / running / completed / failed
- ``vuln_scan_started_at``: when the background task picked the row up
- ``vuln_scan_finished_at``: when the run terminated (success or failure)
- ``vuln_scan_error``: traceback summary on ``failed`` (Text)

No ``vuln_scan_result`` JSONB column is needed: the persisted
``sbom_vulnerabilities`` rows ARE the result. The status response builds
its ``summary`` field per-request from a count query against those rows.

A CHECK constraint mirrors the cve-match status pattern from revision
e6f7a8b9c0d1 so DB-side enforcement matches the Pydantic ``Literal``
on ``VulnerabilityScanStatusResponse.status``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, None] = 'b0c1a2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


VULN_SCAN_STATUS_VALUES = (
    "idle", "queued", "running", "completed", "failed",
)


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "vuln_scan_status",
            sa.String(length=20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "vuln_scan_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "vuln_scan_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "vuln_scan_error",
            sa.Text(),
            nullable=True,
        ),
    )
    quoted = ", ".join(f"'{v}'" for v in VULN_SCAN_STATUS_VALUES)
    op.create_check_constraint(
        "ck_firmware_vuln_scan_status",
        "firmware",
        f"vuln_scan_status IN ({quoted})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firmware_vuln_scan_status", "firmware", type_="check")
    op.drop_column("firmware", "vuln_scan_error")
    op.drop_column("firmware", "vuln_scan_finished_at")
    op.drop_column("firmware", "vuln_scan_started_at")
    op.drop_column("firmware", "vuln_scan_status")
