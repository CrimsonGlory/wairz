"""add_windows_registry_extracts table for Phase γ registry walking

Revision ID: c6d7e8f9a0b1
Revises: c5b6a7d8e9f0
Create Date: 2026-05-09 09:00:00.000000

Per-blob registry-hive walk record. Phase γ.1 of the Windows-coverage
god-mode campaign (.planning/intake/windows-coverage-godmode-2026-05-07.md).

Per Persona-E #13 (registry persistence + driver matrix) discussion:

- One row per parsed hive in a hardware-firmware blob; a single firmware
  may carry multiple hives (SOFTWARE, SYSTEM, SAM, SECURITY, NTUSER.DAT,
  UsrClass.dat, AmCache.hve, etc.) and each gets its own row.
- New table (not JSONB on ``firmware.device_metadata``) — efficient
  indexed ``WHERE hive_path LIKE 'Windows/System32/config/%'`` lookups
  across firmware boundaries; per-blob JOIN navigation for the hardware
  graph; cascade-delete cleanup when a blob row is removed.
- ``parsed_tree`` JSONB stamped with ``schema_version`` per Rule #35c.
  See ``app.services.jsonb_normalizers._normalize_windows_registry_extracts_parsed_tree``
  for the canonical shape; consumers route through that boundary so a
  future v2 walker shape can be discriminated at the read site rather
  than backfilled across the table.

Per-hive ``walk_status`` is a tri-state-plus-skipped CHECK (Rule #33 .c
gate) — the AGGREGATE batch-walk status across ALL hives in a firmware
lives on the firmware row via ``firmware.registry_hive_walk_*`` columns
(Phase γ.3, separate migration). Per-extract ``walk_status`` lets a
partial walker (caps reached on some hives, others completed cleanly)
record the per-hive verdict without losing aggregate information.

Indexes:

- ``blob_id``: cascade traversal + per-blob join from
  ``HardwareFirmwareBlob`` (the dominant access pattern — all γ.6 MCP
  tools start from a project's hardware blobs and scan their hives).
- ``hive_path``: per-firmware path filter for the operator's
  ``list_hives`` view ("show every SOFTWARE.hive in this firmware").
- ``hive_type``: cross-firmware filter chip queries ("show every SYSTEM
  hive across the dataset" — informs aggregate persistence patterns
  for Persona-E #13's diff_driver_matrix workflow).

UniqueConstraint on (blob_id, hive_path): re-walks of the same hive
UPDATE the existing row rather than INSERT a duplicate — keeps the
table size proportional to (firmware × hives), not (firmware × hives ×
walks).

Rule #36 no-execute discipline: γ.4 reads the hives via regipy
(read-only library binding) and writes parsed data into ``parsed_tree``
— never invokes ``regedit`` / ``.reg`` apply / scriptable action paths.
The table holds DATA only.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "c6d7e8f9a0b1"
down_revision = "c5b6a7d8e9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_registry_extracts",
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
        # "Windows/System32/config/SOFTWARE" or "Users/<user>/NTUSER.DAT".
        sa.Column("hive_path", sa.String(1024), nullable=False),
        # Hive flavor discriminator — convenient operator filter and
        # the parsed_tree dispatch hint. Common values: SOFTWARE, SYSTEM,
        # SAM, SECURITY, NTUSER, UsrClass, AmCache, BBI, DEFAULT,
        # COMPONENTS, DRIVERS, ELAM, BCD, SCHEMA, unknown.
        sa.Column(
            "hive_type",
            sa.String(32),
            nullable=False,
            server_default="unknown",
        ),
        # Walk summary — operator-visible counts, mirrored inside
        # parsed_tree so downstream MCP tools that only fetch the row
        # without the JSONB column still have summary numbers.
        sa.Column("key_count", sa.BigInteger, nullable=True),
        sa.Column("value_count", sa.BigInteger, nullable=True),
        # Per-hive parse status. Aggregate batch-walk status (γ.3) lives
        # on the firmware row; this column captures the per-hive verdict
        # for partial-walker scenarios (depth/key cap on some hives,
        # clean completion on others).
        sa.Column(
            "walk_status",
            sa.String(32),
            nullable=False,
            server_default="completed",
        ),
        sa.Column("walk_error", sa.Text, nullable=True),
        # Parsed key/value tree — JSONB with schema_version stamped per
        # Rule #35c. Canonical shape: see
        # app.services.jsonb_normalizers._normalize_windows_registry_extracts_parsed_tree.
        sa.Column("parsed_tree", JSONB, nullable=True),
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
        # Rule #33 .c durable gate — Pydantic Literal at the writer
        # boundary catches typos at code-load time; this CHECK catches
        # direct-SQL writes (cron scripts, manual fixes, partial-failure
        # rollbacks) that bypass the Pydantic layer.
        sa.CheckConstraint(
            "walk_status IN ('completed', 'partial', 'failed', 'skipped')",
            name="ck_windows_registry_extracts_walk_status",
        ),
        # One extract row per (blob, hive_path); re-walks UPDATE rather
        # than INSERT to keep table size proportional to live data.
        sa.UniqueConstraint(
            "blob_id",
            "hive_path",
            name="uq_windows_registry_extracts_blob_path",
        ),
    )
    op.create_index(
        "ix_windows_registry_extracts_blob_id",
        "windows_registry_extracts",
        ["blob_id"],
    )
    op.create_index(
        "ix_windows_registry_extracts_hive_path",
        "windows_registry_extracts",
        ["hive_path"],
    )
    op.create_index(
        "ix_windows_registry_extracts_hive_type",
        "windows_registry_extracts",
        ["hive_type"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_registry_extracts_hive_type",
        table_name="windows_registry_extracts",
    )
    op.drop_index(
        "ix_windows_registry_extracts_hive_path",
        table_name="windows_registry_extracts",
    )
    op.drop_index(
        "ix_windows_registry_extracts_blob_id",
        table_name="windows_registry_extracts",
    )
    op.drop_table("windows_registry_extracts")
