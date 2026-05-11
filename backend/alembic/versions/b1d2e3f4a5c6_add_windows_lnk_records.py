"""add windows_lnk_records table (Phase η.C.A)

Revision ID: b1d2e3f4a5c6
Revises: a0b1c2d3e4f5
Create Date: 2026-05-11 23:00:00.000000

Phase η.C.A — adds the per-LNK landing zone for the Windows Shell Link
walker (η.C.C). Windows shortcuts (.lnk files in the Microsoft Shell
Link / MS-SHLLINK binary format) live under user profiles and system
shortcut locations, typically:

- ``\\Users\\<profile>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\``
  (Recent docs — lists files the user opened)
- ``\\Users\\<profile>\\AppData\\Roaming\\Microsoft\\Windows\\
  Start Menu\\Programs\\`` (per-user Start Menu shortcuts)
- ``\\Users\\<profile>\\Desktop\\`` (per-user desktop shortcuts)
- ``\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\``
  (machine-wide Start Menu shortcuts)

The Shell Link binary carries persistence-candidate metadata:

- **Header**: MAC times (creation/accessed/modified — the LNK's OWN
  embedded times, distinct from the on-disk .lnk file's filesystem
  mtime), file_attributes, hotkey, show_command (windowstyle),
  icon_index, link_flags.
- **LinkInfo**: ``local_base_path`` (resolved drive-letter target —
  e.g. ``C:\\Windows\\System32\\cmd.exe``), volume_id, network info.
- **StringData**: name (description), relative_path (LNK-relative
  path to target), working_directory, command_line_arguments,
  icon_location.
- **ExtraData**: TrackerDataBlock (machine_id + droid GUIDs —
  forensically valuable for cross-machine tracking),
  EnvironmentVariableDataBlock, etc.

Persistence-finding emit (η.C.D) leverages the parsed data to flag:

- ``cmd.exe /c <encoded-PS>`` action shape — target_path resolves
  to ``cmd.exe`` AND arguments contain encoded-PowerShell pattern
  (-EncodedCommand / FromBase64String / IEX). HIGH confidence.
- Non-Microsoft target binary — target_path NOT under
  ``\\Windows\\``, ``\\Program Files\\``, or
  ``\\Program Files (x86)\\``. MEDIUM confidence.
- Baseline rows → LOW confidence.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker (``LnkParse3.lnk_file(fhandle=...)``) PARSES the
LNK binary; nothing in wairz invokes the resolved target_path or
the LNK itself via cscript / wscript / cmd /c / Start-Process.
LnkParse3 is pure-Python; no shell-out.

Per CLAUDE.md Rule #35c JSONB discipline: ``target_metadata`` JSONB
column gets a dedicated normalizer + schema_version stamp in
``app.services.jsonb_normalizers``. The flat columns (target_path /
working_directory / arguments / etc.) are materialized for fast
indexed lookup; the FULL parsed JSON (LnkParse3 ``.get_json()``
shape) is stamped into ``target_metadata`` for full-fidelity
forensic triage.

Per CLAUDE.md Rule #16: the η.C.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so scatter-zip / multi-archive Windows extracts surface
their user-profile LNK locations.

Per CLAUDE.md Rule #19 generalised: this migration extends
infrastructure (alembic chain). Pre-validated revision ID
``b1d2e3f4a5c6`` confirmed FREE in the versions tree of size 73
before authoring (grep returned 0 hits).

Indexes:

- ``ix_windows_lnk_records_firmware_modified`` —
  ``(firmware_id, modified_time)`` covers "all LNKs for firmware Y,
  newest LNK-modified first" forensic-timeline queries.
- ``ix_windows_lnk_records_firmware_target`` —
  ``(firmware_id, target_path)`` covers "find all LNKs pointing
  at cmd.exe / powershell.exe" T1547.009 emit queries.
- ``ix_windows_lnk_records_firmware_filename`` —
  ``(firmware_id, lnk_filename)`` covers operator UX of "show me
  firefox.lnk" or "show me Recent/foo.lnk".
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1d2e3f4a5c6"
down_revision: str | None = "a0b1c2d3e4f5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_lnk_records",
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
        # Path to the .lnk file within the detection root (Rule #16).
        # Long — Recent docs paths can be 6+ levels deep under
        # \Users\<profile>\AppData\Roaming\Microsoft\Windows\.
        sa.Column("source_path", sa.String(2048), nullable=False),
        # Basename of the .lnk file. Fast operator search column.
        sa.Column("lnk_filename", sa.String(512), nullable=False),
        # Resolved target path: link_info.local_base_path or
        # data.relative_path. NULL when both absent (rare). Indexed
        # jointly with firmware_id for "find all LNKs pointing at X"
        # forensic-emit queries.
        sa.Column("target_path", sa.String(2048), nullable=True),
        # data.working_directory.
        sa.Column("working_directory", sa.String(2048), nullable=True),
        # data.command_line_arguments — Text since encoded-PS args can
        # exceed 8 KB.
        sa.Column("arguments", sa.Text, nullable=True),
        # data.description (NAME_STRING).
        sa.Column("description", sa.String(1024), nullable=True),
        # data.icon_location.
        sa.Column("icon_location", sa.String(2048), nullable=True),
        # header.windowstyle — e.g. "SW_SHOWNORMAL".
        sa.Column("show_command", sa.String(64), nullable=True),
        # header.hotkey — free-form parser string (e.g. "CTRL+SHIFT+F1").
        sa.Column("hotkey", sa.String(128), nullable=True),
        # MAC times from the LNK header (NOT the on-disk .lnk file's
        # filesystem mtime). LnkParse3 surfaces tz-aware UTC datetimes.
        sa.Column(
            "creation_time", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "accessed_time", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "modified_time", sa.DateTime(timezone=True), nullable=True
        ),
        # Full parsed LnkParse3 .get_json() output (header + link_info
        # + data + extra). Rule #35c stamped envelope.
        sa.Column("target_metadata", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_lnk_records_firmware_modified",
        "windows_lnk_records",
        ["firmware_id", "modified_time"],
    )
    op.create_index(
        "ix_windows_lnk_records_firmware_target",
        "windows_lnk_records",
        ["firmware_id", "target_path"],
    )
    op.create_index(
        "ix_windows_lnk_records_firmware_filename",
        "windows_lnk_records",
        ["firmware_id", "lnk_filename"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_lnk_records_firmware_filename",
        table_name="windows_lnk_records",
    )
    op.drop_index(
        "ix_windows_lnk_records_firmware_target",
        table_name="windows_lnk_records",
    )
    op.drop_index(
        "ix_windows_lnk_records_firmware_modified",
        table_name="windows_lnk_records",
    )
    op.drop_table("windows_lnk_records")
