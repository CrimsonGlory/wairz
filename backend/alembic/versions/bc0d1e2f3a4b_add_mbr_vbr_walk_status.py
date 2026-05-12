"""add mbr_vbr_walk_* columns to firmware (Phase θ.E.B)

Revision ID: bc0d1e2f3a4b
Revises: ab0c1d2e3f4a
Create Date: 2026-05-12 09:30:00.000000

Adds five columns to the ``firmware`` table for the Phase θ.E MBR/VBR
boot-sector walk 202+polling refactor (CLAUDE.md Rule #33 contract).
Mirrors the bcd_walk_status / wmi_walk_status / esp_walk_status
pattern already on the table.

Phase θ.E.C background runner ``run_mbr_vbr_walk_background`` walks
for raw disk image files (.img / .raw / .vhd / .vhdx — possibly
already converted by α.2.7's qemu-img path) AND partition images
under each detection root (``app.services.firmware_paths.
get_detection_roots`` per Rule #16 — NOT ``firmware.extracted_path``
alone), reads the first 512 bytes (MBR), examines the partition
table at offset 446, then reads each partition's first sector
(VBR). SHA256-hashes each sector, classifies by signature, matches
against bundled known-good Windows VBR + known-malicious bootkit
signature tables, and persists per-sector rows into
``windows_mbr_vbr_sectors`` (table from θ.E.A), stamping an
aggregate JSONB result onto ``mbr_vbr_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): MBR/VBR walks
run entirely in-process (pure-Python sector reads + SHA256 + signature
table lookups; no Docker spawn, no subprocess), and per-sector
persistence is the durable state. ``asyncio.create_task`` is the
correct dispatch — same shape as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B /
η.B.C / η.C.C / η.A.B / θ.A.B / θ.B.D / θ.C.B.

Columns:

- ``mbr_vbr_walk_status``: idle / queued / running / completed / failed
- ``mbr_vbr_walk_started_at``: when the background task picked up
- ``mbr_vbr_walk_finished_at``: when the run terminated
- ``mbr_vbr_walk_error``: traceback summary on failure (Text)
- ``mbr_vbr_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_mbr_vbr_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the bcd_walk_status / wmi_walk_status /
mft_walk_status / lnk_walk_status / scheduled_task_walk_status /
esp_walk_status pattern (Rule #33 .c).

Revision ID ``bc0d1e2f3a4b`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.E.A head ``ab0c1d2e3f4a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "bc0d1e2f3a4b"
down_revision = "ab0c1d2e3f4a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "mbr_vbr_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "mbr_vbr_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "mbr_vbr_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("mbr_vbr_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("mbr_vbr_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_mbr_vbr_walk_status",
        "firmware",
        "mbr_vbr_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_mbr_vbr_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "mbr_vbr_walk_result")
    op.drop_column("firmware", "mbr_vbr_walk_error")
    op.drop_column("firmware", "mbr_vbr_walk_finished_at")
    op.drop_column("firmware", "mbr_vbr_walk_started_at")
    op.drop_column("firmware", "mbr_vbr_walk_status")
