"""add systemd_walk_* columns to firmware (Phase ι.B.B — SECOND LINUX)

Revision ID: aabbccddee02
Revises: aabbccddee01
Create Date: 2026-05-12 17:00:00.000000

Adds five columns to the ``firmware`` table for the Phase ι.B Linux
systemd unit-file walk 202+polling refactor (CLAUDE.md Rule #33
contract). SECOND LINUX walker in wairz's portfolio (ι.A shipped
journald). Mirrors the journald_walk_status / bcd_walk_status /
wmi_walk_status / esp_walk_status / mbr_vbr_walk_status / sdb_walk_status
patterns already on the table.

Phase ι.B.C background runner ``run_systemd_walk_background`` walks
each detection root (``etc/systemd/system/`` / ``usr/lib/systemd/system/``
/ ``lib/systemd/system/`` / ``run/systemd/system/`` /
``etc/systemd/user/`` per Rule #16 — NOT ``firmware.extracted_path``
alone), parses every .service/.timer/.socket/.target/.path/.mount/.swap
file via Python's stdlib ``configparser`` (NO new dependency — systemd
unit files are INI text), merges drop-in overrides (``<unit>.<type>.d/
*.conf``), detects enabled-symlinks (``*.wants/`` and ``*.requires/``
directories), iterates every unit, persists per-unit rows into
``linux_systemd_units`` (table from ι.B.A), and stamps an aggregate
JSONB result onto ``systemd_walk_result``.

Per Rule #36 no-execute: the unit-file INI text is parsed as
untrusted DATA. Nothing in wairz invokes any embedded ExecStart= /
ExecStartPre= / ExecStop= command, mounts any referenced path, or
links any unit into a running systemd via systemctl / runuser /
systemd-run.

Per Rule #33 .d (asyncio.create_task vs arq rubric): systemd walks
run entirely in-process (stdlib configparser; no Docker spawn, no
subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B /
θ.B.C / θ.C.B / θ.D.B / θ.E.B / ι.A.B.

Columns:

- ``systemd_walk_status``: idle / queued / running / completed / failed
- ``systemd_walk_started_at``: when the background task picked up
- ``systemd_walk_finished_at``: when the run terminated
- ``systemd_walk_error``: traceback summary on failure (Text)
- ``systemd_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_systemd_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the journald_walk_status / bcd_walk_status /
wmi_walk_status / esp_walk_status / mbr_vbr_walk_status / sdb_walk_status
pattern (Rule #33 .c).

Revision ID `aabbccddee02` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.B.A head ``aabbccddee01``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee02"
down_revision = "aabbccddee01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "systemd_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "systemd_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "systemd_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("systemd_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("systemd_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_systemd_walk_status",
        "firmware",
        "systemd_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_systemd_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "systemd_walk_result")
    op.drop_column("firmware", "systemd_walk_error")
    op.drop_column("firmware", "systemd_walk_finished_at")
    op.drop_column("firmware", "systemd_walk_started_at")
    op.drop_column("firmware", "systemd_walk_status")
