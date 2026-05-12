"""add linux_bash_history_entries + linux_cron_jobs + linux_ld_preload_entries tables (Phase κ.C.A — EIGHTH κ-era walker)

Revision ID: aabbccddee10
Revises: aabbccddee0f
Create Date: 2026-05-12 23:00:00.000000

Phase κ.C.A — adds three per-line landing-zone tables for the Linux
persistence-triplet walker (bash_history + crontab + ld.so.preload).
EIGHTH κ-era walker. Three artefacts under ONE walker because:

- They cohabit Linux firmware images (the same rootfs typically carries
  all three).
- Adversary TTPs touch them in concert — bash_history shows manual recon,
  crontab shows scheduled re-execution, ld.so.preload shows shared-library
  hijack. A real-world APT campaign (APT36 / FIRESTARTER / Quasar QLNX)
  leaves traces across all three.

- The shape of the work is identical for all three (text-file walker with
  per-line tokenization + heuristic classifier), so a SINGLE walker module
  with three sub-parsers is cleaner than three identical modules.

The Phase κ.C.C walker (``linux_persistence_walker.py``) walks every
detection root (per Rule #16), locates each artefact family, decodes
each file with ``errors='replace'`` for robustness, splits into lines,
parses + classifies, and emits per-line rows. Each artefact has its
own ORM table because the per-line schemas diverge — bash_history has
just `command`, crontab has `schedule_spec` + `user` + `command`, and
ld.so.preload has `library_path`. The artefact tables share the
``source_file`` + ``line_number`` ordering shape.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee10``
pre-validated FREE in the versions tree (grep returned 0 hits) before
authoring. Chains from κ.B.D head ``aabbccddee0f``.

Per CLAUDE.md Rule #25 — single alembic migration adds all 3 tables.
Splitting would force κ.C.B (firmware status columns) to chain from an
arbitrary one of three intermediate revisions.

Per CLAUDE.md Rule #35c JSONB discipline: each ``suspicious_flags``
JSONB column gets a dedicated normalizer + schema_version stamp helper
in ``app.services.jsonb_normalizers``.

Indexes:

- ``ix_linux_bash_history_entries_firmware_source_line`` —
  ``(firmware_id, source_file, line_number)`` covers per-file
  iteration + pagination.
- ``ix_linux_cron_jobs_firmware_source_line`` — same shape.
- ``ix_linux_ld_preload_entries_firmware_source_line`` — same shape.

Per CLAUDE.md Rule #36 — the κ.C.C walker is PARSE-ONLY: text-file
reads, line tokenization, regex match. NO subprocess invocations, NO
``crontab`` CLI, NO ``ldconfig``, NO ``bash`` execution of the parsed
lines. Test gate ``test_linux_persistence_walker.py::test_walker_no_execute``.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee10"
down_revision: str | None = "aabbccddee0f"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── linux_bash_history_entries ────────────────────────────────────
    op.create_table(
        "linux_bash_history_entries",
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
        sa.Column("source_file", sa.String(2048), nullable=False),
        sa.Column(
            "line_number",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column("command", sa.Text, nullable=True),
        sa.Column("suspicious_flags", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_linux_bash_history_entries_firmware_source_line",
        "linux_bash_history_entries",
        ["firmware_id", "source_file", "line_number"],
    )

    # ── linux_cron_jobs ───────────────────────────────────────────────
    op.create_table(
        "linux_cron_jobs",
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
        sa.Column("source_file", sa.String(2048), nullable=False),
        sa.Column(
            "line_number",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column("schedule_spec", sa.String(128), nullable=True),
        sa.Column("user", sa.String(64), nullable=True),
        sa.Column("command", sa.Text, nullable=True),
        sa.Column("suspicious_flags", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_linux_cron_jobs_firmware_source_line",
        "linux_cron_jobs",
        ["firmware_id", "source_file", "line_number"],
    )

    # ── linux_ld_preload_entries ──────────────────────────────────────
    op.create_table(
        "linux_ld_preload_entries",
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
        sa.Column("source_file", sa.String(2048), nullable=False),
        sa.Column(
            "line_number",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column("library_path", sa.String(2048), nullable=True),
        sa.Column("suspicious_flags", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_linux_ld_preload_entries_firmware_source_line",
        "linux_ld_preload_entries",
        ["firmware_id", "source_file", "line_number"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_linux_ld_preload_entries_firmware_source_line",
        table_name="linux_ld_preload_entries",
    )
    op.drop_table("linux_ld_preload_entries")

    op.drop_index(
        "ix_linux_cron_jobs_firmware_source_line",
        table_name="linux_cron_jobs",
    )
    op.drop_table("linux_cron_jobs")

    op.drop_index(
        "ix_linux_bash_history_entries_firmware_source_line",
        table_name="linux_bash_history_entries",
    )
    op.drop_table("linux_bash_history_entries")
