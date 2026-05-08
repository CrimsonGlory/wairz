"""add windows_update_packages table for Phase δ KB-vs-KB diff

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-05-09 17:00:00.000000

Per-blob Windows-Update package record. Phase δ.1 of the Windows-coverage
god-mode campaign (.planning/intake/windows-coverage-godmode-2026-05-07.md).

Per Persona-E #5 (R2R-stomping) + Persona-D #14 (KB-vs-KB diff) discussions:

- One row per detected update package in a hardware-firmware blob; a single
  firmware may carry multiple packages (cumulative + security-only +
  servicing-stack + .NET cumulative side-by-side in a captured WIM, or
  successive KBs side-by-side after a pending-reboot install).
- New table (not JSONB on ``firmware.device_metadata``) — efficient indexed
  ``WHERE kb_id = 'KB5036893'`` lookups across firmware boundaries (the
  per-DLL update-diff workflow joins on KB ID), per-blob JOIN navigation
  for the hardware graph, cascade-delete cleanup when a blob row is removed.
- ``update_metadata`` JSONB stamped with ``schema_version`` per Rule #35c.
  See ``app.services.jsonb_normalizers._normalize_windows_update_packages_update_metadata``
  for the canonical shape; consumers route through that boundary so a future
  v2 manifest-parser shape can be discriminated at the read site rather than
  backfilled across the table.

Indexes:

- ``blob_id``: cascade traversal + per-blob join from
  ``HardwareFirmwareBlob`` (the dominant access pattern — δ.7 MCP tools
  start from a project's hardware blobs and scan their update packages).
- ``kb_id``: cross-firmware filter chip queries ("show every KB5036893
  package across the dataset" — informs the δ.5 update-diff workflow's
  cross-firmware lookup of "the same KB applied to this device family").
- ``package_type``: filter chip queries on the operator UI ("show every
  cumulative-update package across this firmware") — Persona-E #5 R2R-
  stomping detection narrows on cab_cumulative + cab_lcu + cab_dotnet
  rows (the package types that bundle .NET DLLs).
- ``superseded_by_kb``: "is this KB still effective?" filter; NULL means
  the package is the latest known KB in the chain. Operators filtering
  for "what's currently effective on this firmware" use ``WHERE
  superseded_by_kb IS NULL``.

UniqueConstraint on (blob_id, package_path): re-detection of the same
package UPDATEs the existing row rather than INSERT a duplicate — keeps
the table size proportional to (firmware × packages), not (firmware ×
packages × scans).

Per Rule #33 .c contract: ``package_type`` carries a DB CHECK constraint
allowlist matched by a Pydantic ``WindowsUpdatePackageType`` Literal at
the writer boundary. The Literal catches code-side typos at load time;
the CHECK catches direct-SQL writes (cron scripts, manual fixes, partial-
failure rollbacks) that bypass the Pydantic layer.

Rule #36 no-execute discipline: this table holds DATA only — δ-phase
workers parse the package manifest (msitools / cabextract / pefile) and
write parsed metadata here; nothing in wairz invokes ``setup.exe``,
``wusa.exe``, ``dism.exe /Add-Package``, or any update-installer entry
point. The package is read AS DATA via cab/msu unpacking; never executed.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_update_packages",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "blob_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Path within the blob's extracted tree, e.g.
        # "Windows/servicing/Packages/Package_for_KB5036893~31bf3856ad364e35~amd64~~22621.3447.1.5.cab"
        # or top-level "windows10.0-kb5036893-x64_<hash>.msu".
        sa.Column("package_path", sa.String(1024), nullable=False),
        # Discriminator. ck constraint enforces the allowlist; matching
        # Pydantic Literal at the writer boundary catches code-side typos.
        # Common values: msu, cab_cumulative (LCU), cab_security,
        # cab_sru (servicing-stack update), cab_lcu, cab_dotnet (.NET CU),
        # msi, msix, unknown.
        sa.Column(
            "package_type",
            sa.String(32),
            nullable=False,
            server_default="unknown",
        ),
        # KB identifier extracted from the manifest (typically
        # "KB5036893"; format is /^KB\d+$/). NULL = manifest didn't
        # surface a KB, e.g. side-loaded vendor cab without a KB stamp.
        sa.Column("kb_id", sa.String(32), nullable=True),
        # Most-recent KB known to supersede this package. NULL = this is
        # the latest in the supersedence chain. The full chain (which can
        # be many) lives in ``update_metadata.supersedence``; this scalar
        # column is the indexed answer to the operator's most-frequent
        # filter ("is this still effective?").
        sa.Column("superseded_by_kb", sa.String(32), nullable=True),
        # Release date from the package manifest (typically the "Last
        # Modified" header on the support article). NULL = manifest didn't
        # carry the release date or parser couldn't extract it.
        sa.Column("release_date", sa.DateTime(timezone=True), nullable=True),
        # Full parsed manifest payload — bill-of-files, supersedence chain
        # (both directions), applicability rules, file SHA256 list.
        # Canonical shape lives in
        # app.services.jsonb_normalizers._normalize_windows_update_packages_update_metadata.
        # Schema version stamped via the matching ``_stamp_*`` helper so
        # future v2 manifest shapes can be discriminated at the read site.
        sa.Column("update_metadata", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Rule #33 .c durable gate — Pydantic Literal at the writer boundary
        # catches typos at code-load time; this CHECK catches direct-SQL
        # writes that bypass the Pydantic layer (cron scripts, manual fixes,
        # partial-failure rollbacks).
        sa.CheckConstraint(
            "package_type IN ("
            "'msu', 'cab_cumulative', 'cab_security', 'cab_sru', "
            "'cab_lcu', 'cab_dotnet', 'msi', 'msix', 'unknown'"
            ")",
            name="ck_windows_update_packages_type",
        ),
        # One package row per (blob, package_path); re-detections UPDATE-
        # not-INSERT. Keeps table size proportional to live data.
        sa.UniqueConstraint(
            "blob_id",
            "package_path",
            name="uq_windows_update_packages_blob_path",
        ),
    )
    op.create_index(
        "ix_windows_update_packages_blob_id",
        "windows_update_packages",
        ["blob_id"],
    )
    op.create_index(
        "ix_windows_update_packages_kb_id",
        "windows_update_packages",
        ["kb_id"],
    )
    op.create_index(
        "ix_windows_update_packages_package_type",
        "windows_update_packages",
        ["package_type"],
    )
    op.create_index(
        "ix_windows_update_packages_superseded_by_kb",
        "windows_update_packages",
        ["superseded_by_kb"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_update_packages_superseded_by_kb",
        table_name="windows_update_packages",
    )
    op.drop_index(
        "ix_windows_update_packages_package_type",
        table_name="windows_update_packages",
    )
    op.drop_index(
        "ix_windows_update_packages_kb_id",
        table_name="windows_update_packages",
    )
    op.drop_index(
        "ix_windows_update_packages_blob_id",
        table_name="windows_update_packages",
    )
    op.drop_table("windows_update_packages")
