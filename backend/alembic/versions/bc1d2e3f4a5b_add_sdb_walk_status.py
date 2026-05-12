"""add sdb_walk_* columns to firmware (Phase θ.D.C)

Revision ID: bc1d2e3f4a5b
Revises: ab1c2d3e4f5a
Create Date: 2026-05-12 11:30:00.000000

Adds five columns to the ``firmware`` table for the Phase θ.D SDB
shim walker 202+polling refactor (CLAUDE.md Rule #33 contract).
Mirrors the bcd_walk_status / wmi_walk_status / esp_walk_status /
mbr_vbr_walk_status pattern already on the table.

Phase θ.D.D background runner ``run_sdb_walk_background`` walks for
`.sdb` files under each detection root (``app.services.firmware_paths.
get_detection_roots`` per Rule #16 — NOT ``firmware.extracted_path``
alone), parses the binary format via the vendored python_sdb clean-
room parser (θ.D.A), classifies each TAG_SHIM / TAG_PATCH entry by
shim_class (RedirectEXE / InjectDll / GetCommandLineW /
RedirectShortcut / Custom / Patch / Other), and persists per-entry
rows into ``windows_sdb_entries`` (table from θ.D.B), stamping an
aggregate JSONB result onto ``sdb_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): SDB walks run
entirely in-process (pure-Python binary parsing via the vendored
python_sdb; no Docker spawn, no subprocess), and per-entry persistence
is the durable state. ``asyncio.create_task`` is the correct dispatch
— same shape as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B
/ θ.A.B / θ.B.D / θ.C.B / θ.E.B.

Columns:

- ``sdb_walk_status``: idle / queued / running / completed / failed
- ``sdb_walk_started_at``: when the background task picked up
- ``sdb_walk_finished_at``: when the run terminated
- ``sdb_walk_error``: traceback summary on failure (Text)
- ``sdb_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_sdb_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the bcd_walk_status / wmi_walk_status /
mft_walk_status / lnk_walk_status / scheduled_task_walk_status /
esp_walk_status / mbr_vbr_walk_status pattern (Rule #33 .c).

Revision ID ``bc1d2e3f4a5b`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.D.B head ``ab1c2d3e4f5a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "bc1d2e3f4a5b"
down_revision = "ab1c2d3e4f5a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "sdb_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sdb_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "sdb_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("sdb_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("sdb_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_sdb_walk_status",
        "firmware",
        "sdb_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_sdb_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "sdb_walk_result")
    op.drop_column("firmware", "sdb_walk_error")
    op.drop_column("firmware", "sdb_walk_finished_at")
    op.drop_column("firmware", "sdb_walk_started_at")
    op.drop_column("firmware", "sdb_walk_status")
