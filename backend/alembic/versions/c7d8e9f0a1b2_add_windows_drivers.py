"""add_windows_drivers table for Phase γ driver matrix

Revision ID: c7d8e9f0a1b2
Revises: c6d7e8f9a0b1
Create Date: 2026-05-09 09:30:00.000000

Per-blob driver-package extract record. Phase γ.2 of the Windows-coverage
god-mode campaign (.planning/intake/windows-coverage-godmode-2026-05-07.md).

Per Persona-E #13 (driver matrix view) discussion:

- One row per INF/CAT/SYS triplet detected in a hardware-firmware blob;
  a single firmware may carry many drivers (Windows installs commonly
  ship 100+ inbox drivers in C:/Windows/INF and C:/Windows/System32/
  DriverStore).
- New table (not JSONB on ``firmware.device_metadata``) — the driver
  matrix view filters/sorts on ``class_guid`` + ``signing_tier``
  across firmware boundaries; per-blob JOIN navigation for the
  hardware graph; ON DELETE CASCADE so blob removal cleans up driver
  rows.
- ``signing_tier`` is the Persona-E #13 capability badge — ``whql`` /
  ``attestation`` / ``cross_signed`` / ``unsigned`` / ``unknown``. The
  tier determines which Windows kernel-mode loader will accept the
  driver (HVCI requires WHQL + EV; SecureBoot requires at least
  cross-signed). DB CHECK enforces the allowlist (Rule #33 .c) and
  the matching Pydantic ``WindowsDriverSigningTier`` Literal at the
  writer boundary catches code-side typos at load time.
- ``pnp_ids`` is a Postgres ARRAY of Plug-and-Play hardware/compatible
  IDs harvested from the INF ``[Models]`` section; used by the driver
  matrix to answer "which firmware images contain a driver for
  PCI\\VEN_1234&DEV_5678".
- ``inf_metadata`` JSONB stamped with ``schema_version`` per Rule #35c
  carries the full parsed [Version] / [Manufacturer] / [Models] /
  [Strings] structure. See
  ``app.services.jsonb_normalizers._normalize_windows_drivers_inf_metadata``
  for the canonical shape; consumers route through that boundary.

Indexes:

- ``blob_id``: cascade traversal + per-blob JOIN from
  ``HardwareFirmwareBlob`` (the dominant access pattern — γ.6 MCP
  tools start from a project's hardware blobs and enumerate drivers).
- ``class_guid``: cross-firmware filter for the driver matrix view
  ("show every Display class driver across the dataset"). NULL is
  excluded from the index because most rows have a ClassGuid.
- ``signing_tier``: capability-badge filter chip ("show every WHQL
  driver" or "show every unsigned driver across the dataset").

UniqueConstraint on (blob_id, driver_path): re-extracts of the same
driver UPDATE the existing row rather than INSERT a duplicate — keeps
the table size proportional to (firmware × drivers), not (firmware ×
drivers × extracts).

Rule #36 no-execute discipline: γ.5 reads INF/CAT files via parsers
(no shell-out, no rundll32, no .inf install) and validates the CAT
via the existing β.4-β.10 signify Authenticode stack. Nothing in
this table holds executable references that wairz invokes — paths are
DATA only, surfaced to the operator for triage.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB


revision = "c7d8e9f0a1b2"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_drivers",
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
        # Anchor path for the driver — typically the INF path (the
        # parsed/canonical entry point). Used as the dedup key alongside
        # blob_id so re-extracts UPDATE the existing row.
        sa.Column("driver_path", sa.String(1024), nullable=False),
        # Path components when the triplet is co-located. Nullable
        # because some drivers have INF-only (no CAT, e.g. test/dev
        # signed) or SYS-only (preinstalled DriverStore subdir) shapes.
        sa.Column("inf_path", sa.String(1024), nullable=True),
        sa.Column("cat_path", sa.String(1024), nullable=True),
        sa.Column("sys_path", sa.String(1024), nullable=True),
        # INF [Version] block — driver class, ClassGuid, provider,
        # version, catalog file reference. ClassGuid is indexed for
        # cross-firmware "show every X-class driver" queries.
        sa.Column("inf_class", sa.String(64), nullable=True),
        sa.Column("class_guid", sa.String(64), nullable=True),
        sa.Column("driver_provider", sa.String(256), nullable=True),
        sa.Column("driver_version", sa.String(64), nullable=True),
        sa.Column("driver_name", sa.String(256), nullable=True),
        # INF [Manufacturer] — primary manufacturer string for operator
        # display. Multi-manufacturer INFs surface secondary entries via
        # inf_metadata JSONB.
        sa.Column("manufacturer", sa.String(256), nullable=True),
        # Plug-and-Play hardware IDs from [Models] — array so the driver
        # matrix can answer "which firmware contains a driver for X" via
        # ``WHERE 'PCI\\VEN_1234&DEV_5678' = ANY(pnp_ids)``.
        sa.Column("pnp_ids", ARRAY(sa.Text), nullable=True),
        # CAT signature outcome — populated by the β.4-β.10 signify
        # stack via integration in γ.5 (no new crypto code in γ).
        sa.Column(
            "catalog_signed",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("catalog_signer_subject", sa.Text, nullable=True),
        sa.Column("catalog_signer_issuer", sa.Text, nullable=True),
        # Persona-E #13 capability badge. NULL = the tier classifier
        # didn't run (the worker didn't reach the CAT validation step,
        # or the row was created without a CAT). Default 'unknown' on
        # the writer side; explicit allowlist enforced via CHECK below
        # per Rule #33 .c.
        sa.Column(
            "signing_tier",
            sa.String(32),
            nullable=False,
            server_default="unknown",
        ),
        # Parsed INF data per Rule #35c. See the matching normaliser for
        # the canonical shape; writers stamp schema_version via
        # ``_stamp_windows_drivers_inf_metadata``.
        sa.Column("inf_metadata", JSONB, nullable=True),
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
        # Rule #33 .c durable gate. Pydantic
        # ``WindowsDriverSigningTier`` Literal at the writer boundary
        # catches code-side typos at load time; this CHECK catches
        # direct-SQL writes (cron scripts, manual fixes, partial-failure
        # rollbacks) that bypass the Pydantic layer.
        sa.CheckConstraint(
            "signing_tier IN ('whql', 'attestation', 'cross_signed', 'unsigned', 'unknown')",
            name="ck_windows_drivers_signing_tier",
        ),
        # One driver row per (blob, driver_path) — re-extracts UPDATE
        # not INSERT.
        sa.UniqueConstraint(
            "blob_id",
            "driver_path",
            name="uq_windows_drivers_blob_path",
        ),
    )
    op.create_index(
        "ix_windows_drivers_blob_id",
        "windows_drivers",
        ["blob_id"],
    )
    op.create_index(
        "ix_windows_drivers_class_guid",
        "windows_drivers",
        ["class_guid"],
        postgresql_where=sa.text("class_guid IS NOT NULL"),
    )
    op.create_index(
        "ix_windows_drivers_signing_tier",
        "windows_drivers",
        ["signing_tier"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_drivers_signing_tier",
        table_name="windows_drivers",
    )
    op.drop_index(
        "ix_windows_drivers_class_guid",
        table_name="windows_drivers",
    )
    op.drop_index(
        "ix_windows_drivers_blob_id",
        table_name="windows_drivers",
    )
    op.drop_table("windows_drivers")
