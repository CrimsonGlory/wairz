"""add esp_walk_* columns to firmware (Phase θ.C.B)

Revision ID: 8b9c0d1e2f3a
Revises: 7a8b9c0d1e2f
Create Date: 2026-05-12 06:30:00.000000

Adds five columns to the ``firmware`` table for the Phase θ.C ESP
PE chain correlation walk 202+polling refactor (CLAUDE.md Rule #33
contract). Mirrors the bcd_walk_status / wmi_walk_status pattern
already on the table.

Phase θ.C.C background runner ``run_esp_walk_background`` walks for
`.efi` files under each detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), validates each PE against
β.4 signify Authenticode + β.10 DBX revocation, persists per-`.efi`
rows into ``windows_esp_entries`` (table from θ.C.A), and stamps an
aggregate JSONB result onto ``esp_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): ESP walks run
entirely in-process (signify is pure-Python; pefile is pure-Python;
DBX is a byte-compare; no Docker spawn, no subprocess), and
per-`.efi` persistence is the durable state. ``asyncio.create_task``
is the correct dispatch — same shape as γ.4 / ε.1.b.3 / ζ.2.B /
ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B / θ.B.D.

Columns:

- ``esp_walk_status``: idle / queued / running / completed / failed
- ``esp_walk_started_at``: when the background task picked up
- ``esp_walk_finished_at``: when the run terminated
- ``esp_walk_error``: traceback summary on failure (Text)
- ``esp_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_esp_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the bcd_walk_status / wmi_walk_status /
mft_walk_status / lnk_walk_status / scheduled_task_walk_status
pattern (Rule #33 .c).

Revision ID ``8b9c0d1e2f3a`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.C.A head ``7a8b9c0d1e2f``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "8b9c0d1e2f3a"
down_revision = "7a8b9c0d1e2f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "esp_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "esp_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "esp_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("esp_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("esp_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_esp_walk_status",
        "firmware",
        "esp_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_esp_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "esp_walk_result")
    op.drop_column("firmware", "esp_walk_error")
    op.drop_column("firmware", "esp_walk_finished_at")
    op.drop_column("firmware", "esp_walk_started_at")
    op.drop_column("firmware", "esp_walk_status")
