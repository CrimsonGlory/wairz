"""add journald_walk_* columns to firmware (Phase ι.A.B — FIRST LINUX)

Revision ID: fb3a4b5c6d7e
Revises: ea2f3a4b5c6d
Create Date: 2026-05-12 15:30:00.000000

Adds five columns to the ``firmware`` table for the Phase ι.A Linux
journald walk 202+polling refactor (CLAUDE.md Rule #33 contract).
FIRST LINUX walker in wairz's portfolio. Mirrors the bcd_walk_status /
wmi_walk_status / esp_walk_status / mbr_vbr_walk_status /
sdb_walk_status patterns already on the table.

Phase ι.A.C background runner ``run_journald_walk_background`` opens
each ``.journal`` file candidate found under any detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), parses each via a clean-room
pure-Python parser implementing the upstream systemd journal-def.h
format (no third-party Python package matched per the Rule #19
evidence-first probe — ``dissect.journal`` does not exist on PyPI;
``kaitaistruct`` is available but would require ~500 LOC of vendor-in
generated code; clean-room is the smaller path). Treated as untrusted
DATA per Rule #36 — never executed via ``journalctl`` / ``systemd-cat``
/ entry-embedded EXEC fields. Iterates every entry object, persists
per-entry rows into ``linux_journald_entries`` (table from ι.A.A), and
stamps an aggregate JSONB result onto ``journald_walk_result``.

Per Rule #33 .d (asyncio.create_task vs arq rubric): journald walks
run entirely in-process (pure-Python clean-room parser; no Docker
spawn, no subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B / θ.B.C
/ θ.C.B / θ.D.B / θ.E.B.

Columns:

- ``journald_walk_status``: idle / queued / running / completed / failed
- ``journald_walk_started_at``: when the background task picked up
- ``journald_walk_finished_at``: when the run terminated
- ``journald_walk_error``: traceback summary on failure (Text)
- ``journald_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_journald_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the bcd_walk_status / wmi_walk_status /
esp_walk_status / mbr_vbr_walk_status / sdb_walk_status pattern (Rule
#33 .c).

Revision ID `fb3a4b5c6d7e` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.A.A head ``ea2f3a4b5c6d``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "fb3a4b5c6d7e"
down_revision = "ea2f3a4b5c6d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "journald_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "journald_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "journald_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("journald_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("journald_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_journald_walk_status",
        "firmware",
        "journald_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_journald_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "journald_walk_result")
    op.drop_column("firmware", "journald_walk_error")
    op.drop_column("firmware", "journald_walk_finished_at")
    op.drop_column("firmware", "journald_walk_started_at")
    op.drop_column("firmware", "journald_walk_status")
