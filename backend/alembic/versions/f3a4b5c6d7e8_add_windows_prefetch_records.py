"""add windows_prefetch_records table (Phase ζ.2.A)

Revision ID: f3a4b5c6d7e8
Revises: f2b3c4d5e6f7
Create Date: 2026-05-10 13:00:00.000000

Phase ζ.2.A — adds the per-execution landing zone for the Prefetch
walker (ζ.2.B). Mirrors ε.2.A's ``windows_event_records`` shape: per-row
forensic record + composite indexes for the operator-MCP filter shapes.

Wairz parses ``%SystemRoot%\\Prefetch\\*.pf`` files for application-
execution history (last run times, run counts, files/directories
referenced, version 17/23/26/30 supported by the windowsprefetch
library — XP through Win11, MAM-compressed Win10+ included).

Indexes:

- ``ix_windows_prefetch_records_firmware_executable`` —
  ``(firmware_id, executable_name)`` covers "find every .pf entry
  for chrome.exe / cmd.exe / powershell.exe" filter.
- ``ix_windows_prefetch_records_firmware_last_run`` —
  ``(firmware_id, last_run_time DESC)`` covers forensic-timeline
  reconstruction (most-recently-executed-first).

Per CLAUDE.md Rule #19 generalised: this migration touches infrastructure
(alembic chain). Rule #8 extended rebuild (backend + worker + migrator)
runs after the cut-over. Pre-validated revision ID: ``f3a4b5c6d7e8``
confirmed FREE in the versions tree of size 65 (grep returned 0 hits).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA only
— Prefetch files are parsed by the windowsprefetch Python library
(read-only file open + struct unpack, never invokes pftriage / Powershell
/ Get-CimInstance Win32_PrefetchedApp).
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a4b5c6d7e8"
down_revision: str | None = "f2b3c4d5e6f7"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_prefetch_records",
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
        # Path to the source .pf file relative to the detection root that
        # contained it (Rule #16 detection_roots discipline).
        sa.Column("prefetch_file_path", sa.String(1024), nullable=False),
        # Executable name from Prefetch header (60-byte UTF-16 field;
        # padded; truncated null at first \\0). Common: "CHROME.EXE",
        # "CMD.EXE", "POWERSHELL.EXE", "RUNDLL32.EXE".
        sa.Column("executable_name", sa.String(256), nullable=False),
        # Prefetch hash (header bytes 76-79; hex-encoded by parser).
        # Combined with executable_name forms the canonical .pf filename:
        # "<NAME>-<HASH>.pf". Helps cross-reference different exec paths
        # of the same binary (e.g. system32 vs syswow64).
        sa.Column("prefetch_hash", sa.String(16), nullable=True),
        # Prefetch format version: 17=WinXP, 23=Win7/Vista, 26=Win8.1,
        # 30=Win10+ (MAM-compressed). Recorded for forensic context.
        sa.Column("version", sa.Integer(), nullable=True),
        # Number of times the executable has been run (32-bit; saturates
        # at MAX_INT for very-active binaries).
        sa.Column("run_count", sa.Integer(), nullable=True),
        # Most-recent run time. Authoritative timestamp for timeline
        # reconstruction. Win10+ stores up to 8 timestamps; we record
        # the LATEST in last_run_time + the full set in all_run_times.
        sa.Column(
            "last_run_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # All recorded run times (up to 8 on Win10+, only 1 on earlier).
        # JSONB array of ISO-8601 strings, newest-first, schema_version
        # stamped per Rule #35c.
        sa.Column("all_run_times", JSONB, nullable=True),
        # Files referenced during exec (full UTF-16 paths from the
        # Filename Strings block; can be 200+ entries for complex apps).
        # JSONB list[str], schema_version-stamped.
        sa.Column("filenames_referenced", JSONB, nullable=True),
        # Volumes referenced during exec (volume serial + path on each).
        # JSONB list[dict] — typically 1-2 entries (boot volume + roaming).
        sa.Column("volumes", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_prefetch_records_firmware_executable",
        "windows_prefetch_records",
        ["firmware_id", "executable_name"],
    )
    op.create_index(
        "ix_windows_prefetch_records_firmware_last_run",
        "windows_prefetch_records",
        ["firmware_id", "last_run_time"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_prefetch_records_firmware_last_run",
        table_name="windows_prefetch_records",
    )
    op.drop_index(
        "ix_windows_prefetch_records_firmware_executable",
        table_name="windows_prefetch_records",
    )
    op.drop_table("windows_prefetch_records")
