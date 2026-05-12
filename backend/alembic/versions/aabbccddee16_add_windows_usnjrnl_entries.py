"""add windows_usnjrnl_entries table (Phase κ.E.A — TENTH κ-era walker)

Revision ID: aabbccddee16
Revises: aabbccddee15
Create Date: 2026-05-12 23:45:00.000000

Phase κ.E.A — adds the per-record landing zone for the Windows NTFS
$UsnJrnl:$J change-log walker. The USN journal records every file-
system change (create / delete / rename / modify) on a tracked NTFS
volume, with USN identifier + reason flags + timestamp.

**Real-world Persona-E USN Journal relevance (T1070.004 / anti-
forensics):**

- ``windows_usnjrnl_file_deletion``: reason_flags has ``FILE_DELETE``
  AND filename ends in an executable extension. Adversary deleted an
  executable; the $J record preserves the create+delete pair even
  after the file is gone. Persona-E MEDIUM.

- ``windows_usnjrnl_temp_create_delete_pair``: the SAME file has both
  ``FILE_CREATE`` and ``FILE_DELETE`` records within 5 minutes AND
  the file lives under ``Temp`` / ``AppData\\Local\\Temp`` /
  ``ProgramData`` / ``Public\\Downloads``. Staged-payload anti-
  forensics. Persona-E HIGH.

- ``windows_usnjrnl_renamed_executable``: ``RENAME_OLD_NAME`` +
  ``RENAME_NEW_NAME`` pair with extension change (``.tmp`` → ``.exe``,
  ``.dat`` → ``.dll``, etc.). T1036 Masquerading. Persona-E MEDIUM.

**Rule #36 no-execute discipline.** The κ.E.C walker parses the $J
ADS via ``dissect.ntfs.usnjrnl.UsnJrnl`` (pure-Python parser). NO
sub-process invocations, NO ``ntfs-3g`` / ``mount`` / ``losetup``
invocation, NO execution of any file referenced by the journal — the
walker reads bytes, decodes records, and emits rows. The walker's
source is tokenized against forbidden invocation tokens in
``test_usnjrnl_walker.py::test_walker_no_execute``, plus a canary
test confirms the gate ACTUALLY fires on synthetic violations.

Per CLAUDE.md Rule #16: the κ.E.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Windows firmware surfaces every raw NTFS image
candidate.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee16``
pre-validated FREE in the versions tree (grep returned 0 hits) before
authoring. Chains from κ.D.D head ``aabbccddee15``.

Per CLAUDE.md Rule #35c JSONB discipline: the ``reason_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers``. Two production shapes are
accepted via the normalizer (per Rule #35c): canonical
``{"file_create": True, ...}`` dict AND legacy ``int`` bitmask — the
normalizer accepts both and emits the canonical shape.

Indexes:

- ``ix_windows_usnjrnl_entries_firmware_usn`` — ``(firmware_id, usn)``
  covers monotonic timeline reconstruction.
- ``ix_windows_usnjrnl_entries_firmware_timestamp`` — ``(firmware_id,
  timestamp)`` covers timeline correlation for incident response.
- ``ix_windows_usnjrnl_entries_firmware_file_name`` — ``(firmware_id,
  file_name)`` covers cross-firmware filename joins.
- ``ix_windows_usnjrnl_entries_firmware_parent_ref`` — ``(firmware_id,
  parent_file_reference_number)`` covers "all $J events under this
  directory" queries.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee16"
down_revision: str | None = "aabbccddee15"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_usnjrnl_entries",
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
        sa.Column("source_file_path", sa.String(1024), nullable=False),
        sa.Column("usn", sa.BigInteger, nullable=True),
        sa.Column(
            "file_reference_number", sa.BigInteger, nullable=True
        ),
        sa.Column(
            "parent_file_reference_number", sa.BigInteger, nullable=True
        ),
        sa.Column("file_name", sa.String(512), nullable=True),
        sa.Column("reason_flags", JSONB, nullable=True),
        sa.Column("source_info", sa.Integer, nullable=True),
        sa.Column("security_id", sa.Integer, nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("parse_error", sa.Text, nullable=True),
        sa.Column(
            "schema_version",
            sa.Integer,
            nullable=False,
            server_default="2",
        ),
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
        "ix_windows_usnjrnl_entries_firmware_usn",
        "windows_usnjrnl_entries",
        ["firmware_id", "usn"],
    )
    op.create_index(
        "ix_windows_usnjrnl_entries_firmware_timestamp",
        "windows_usnjrnl_entries",
        ["firmware_id", "timestamp"],
    )
    op.create_index(
        "ix_windows_usnjrnl_entries_firmware_file_name",
        "windows_usnjrnl_entries",
        ["firmware_id", "file_name"],
    )
    op.create_index(
        "ix_windows_usnjrnl_entries_firmware_parent_ref",
        "windows_usnjrnl_entries",
        ["firmware_id", "parent_file_reference_number"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_usnjrnl_entries_firmware_parent_ref",
        table_name="windows_usnjrnl_entries",
    )
    op.drop_index(
        "ix_windows_usnjrnl_entries_firmware_file_name",
        table_name="windows_usnjrnl_entries",
    )
    op.drop_index(
        "ix_windows_usnjrnl_entries_firmware_timestamp",
        table_name="windows_usnjrnl_entries",
    )
    op.drop_index(
        "ix_windows_usnjrnl_entries_firmware_usn",
        table_name="windows_usnjrnl_entries",
    )
    op.drop_table("windows_usnjrnl_entries")
