"""add windows_appcompat_entries table (Phase κ.B.A — SEVENTH κ-era walker)

Revision ID: aabbccddee0d
Revises: aabbccddee0c
Create Date: 2026-05-12 21:00:00.000000

Phase κ.B.A — adds the per-entry landing zone for the Windows AppCompat /
Shimcache execution-evidence walker. AppCompatCache is a Windows
registry-resident execution-evidence artefact at SYSTEM hive path
``ControlSet00X\\Control\\Session Manager\\AppCompatCache\\AppCompatCache``
(REG_BINARY value); it tracks "what executed" with file_path + last-
modified FILETIME, high adversary value for T1106 (Native API) / T1059
(Command and Scripting Interpreter) / LotL (Living off the Land)
detection.

**Real-world Persona-E AppCompat relevance (forensic gold):**

- AppCompatCache is execution evidence — the Application Compatibility
  Engine records EVERY executable the system has seen, regardless of
  whether it actually ran. Mandiant's ShimCacheParser predates 2014;
  Eric Zimmerman's AppCompatCacheParser is the modern reference.

- Persona-E patterns surfaced by κ.B.D classifier (4 anomaly bits):
  - ``suspicious_path``: executable under canonical adversary-staging
    directories (\\Users\\Public\\, \\Windows\\Temp\\, \\AppData\\Local\\
    Temp\\, \\ProgramData\\Microsoft\\Windows\\Caches\\, C:\\Temp\\).
    T1106 / T1059 — Persona-E HIGH.
  - ``temp_execution``: .tmp/.dat extension on path that executed
    (extension hiding). T1036 Masquerading — Persona-E MEDIUM.
  - ``unusual_extension``: extension outside the standard set
    {exe, dll, bat, cmd, ps1, vbs, js, scr, com, msi, cpl}. T1036.005 +
    T1027 — Persona-E MEDIUM.
  - ``parse_error``: entry failed structured parse (truncated, malformed).
    INFORMATIONAL only — not a Persona-E finding by itself.

**PARSE-ONLY DISCIPLINE — Rule #36.** The κ.B.C walker parses the
AppCompatCache REG_BINARY value AS DATA via pure-Python ``struct``
unpacking. NO sub-process invocations, NO Windows API calls, NO
``rundll32`` / ``cscript`` / ``wmic`` / ``wine`` / ``mono`` — the
walker reads bytes, unpacks structs, and emits rows. The walker's
source is tokenized against forbidden invocation tokens in
``test_appcompat_walker_no_execute``.

Per CLAUDE.md Rule #16: the κ.B.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system
images) surfaces every SYSTEM hive candidate.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee0d``
pre-validated FREE in the versions tree (grep returned 0 hits) before
authoring. Chains from ι.E.D head ``aabbccddee0c``.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers``.

Indexes:

- ``ix_windows_appcompat_entries_firmware_insertion`` — ``(firmware_id,
  insertion_position)`` covers MRU/LRU timeline reconstruction.
- ``ix_windows_appcompat_entries_firmware_last_modified`` — ``(firmware_id,
  last_modified_ts)`` covers FILETIME-based timeline correlation.
- ``ix_windows_appcompat_entries_firmware_file_path`` — ``(firmware_id,
  file_path)`` covers cross-firmware joins on the same binary path
  (the κ.B.E ``lookup_appcompat_entry_across_firmwares`` MCP tool reads
  this index path).
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee0d"
down_revision: str | None = "aabbccddee0c"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_appcompat_entries",
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
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column(
            "insertion_position",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_modified_ts",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("anomaly_flags", JSONB, nullable=True),
        sa.Column("source_hive_path", sa.String(512), nullable=True),
        sa.Column("control_set", sa.Integer, nullable=True),
        sa.Column(
            "schema_version",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
        sa.Column("parse_error", sa.Text, nullable=True),
        sa.Column("entry_size_bytes", sa.BigInteger, nullable=True),
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
        "ix_windows_appcompat_entries_firmware_insertion",
        "windows_appcompat_entries",
        ["firmware_id", "insertion_position"],
    )
    op.create_index(
        "ix_windows_appcompat_entries_firmware_last_modified",
        "windows_appcompat_entries",
        ["firmware_id", "last_modified_ts"],
    )
    op.create_index(
        "ix_windows_appcompat_entries_firmware_file_path",
        "windows_appcompat_entries",
        ["firmware_id", "file_path"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_appcompat_entries_firmware_file_path",
        table_name="windows_appcompat_entries",
    )
    op.drop_index(
        "ix_windows_appcompat_entries_firmware_last_modified",
        table_name="windows_appcompat_entries",
    )
    op.drop_index(
        "ix_windows_appcompat_entries_firmware_insertion",
        table_name="windows_appcompat_entries",
    )
    op.drop_table("windows_appcompat_entries")
