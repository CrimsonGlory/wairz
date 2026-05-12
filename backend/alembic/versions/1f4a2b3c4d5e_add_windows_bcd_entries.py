"""add windows_bcd_entries table (Phase θ.A.A)

Revision ID: 1f4a2b3c4d5e
Revises: a8b9c0d1e2f3
Create Date: 2026-05-12 02:00:00.000000

Phase θ.A.A — adds the per-entry landing zone for the Phase θ.A
Windows Boot Configuration Data (BCD) store walker (θ.A.C). BCD
stores extracted from firmware captures (typically files named
``BCD`` without extension under ``Boot/`` or
``EFI/Microsoft/Boot/`` partition prefixes) are walked via regipy's
``RegistryHive`` (BCD is the same REGF format as standard registry
hives — regipy recognises ``BCD_HIVE_TYPE = 'bcd'``) to surface every
``\\Objects\\{guid}`` entry. Each entry becomes one row in this
table.

Surfaces per-BCD-object forensic-triage metadata:

- **Object identifiers** (object_guid + object_type) — the canonical
  triage key. object_guid is the GUID under ``\\Objects\\``;
  well-known GUIDs like ``{9dea862c-5cdd-4e70-acc1-f32b344d4795}``
  (``{bootmgr}``), ``{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}``
  (``{globalsettings}``) carry settings; per-OS-entry GUIDs identify
  bootable OS images. object_type is the Description/Type 32-bit
  discriminator combining object class + image type + app class
  (https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm).
- **Application metadata** (description + image_path) — description
  is BCD element 0x12000004 (e.g. "Windows 10", "Ubuntu");
  image_path is BCD element 0x12000002 (e.g.
  ``\\Windows\\System32\\winload.efi``). Mismatched paths outside
  known-good roots are the θ.A.D suspicious-path signal.
- **GPT device identifiers** (gpt_partition_guid + gpt_disk_guid) —
  parsed from BCD element 0x11000001 (ApplicationDevice raw blob,
  bytes [32:48] for partition GUID and [56:72] for disk GUID).
  NULL on non-GPT encodings or short blobs.
- **Security flags** (testsigning + no_integrity_checks + nx_policy)
  — BCD elements 0x16000010 / 0x16000048 / 0x25000020. TestSigning
  enabled is the common bootkit / BYOVD precursor; NoIntegrityChecks
  disables DSE; NxPolicy=2 (AlwaysOff) disables DEP.
- **custom_elements JSONB** — additional BCD elements not promoted
  to flat columns (DisplayOrder, DefaultObject, vendor-specific or
  attacker-planted elements). Canonical shape
  ``[{"element_type": "0x14000006", "element_value": ..., "schema_version": 1}]``.
- **anomaly_flags JSONB** — heuristic detection summary for the
  θ.A.D classifier. Canonical shape ``{"suspicious_path": bool,
  "non_microsoft_description": bool, "testsigning_enabled": bool,
  "no_integrity_checks": bool, "nx_disabled": bool,
  "is_default_boot": bool, "schema_version": 1}``.
- **last_modified_ns** — FILETIME-string from the NKRecord header.
- **source_path** — relative path to the BCD store within the
  detection root (Rule #16).

Per CLAUDE.md Rule #16: the θ.A.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-archive / scatter-zip firmware extracts surface
every BCD store candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker treats BCD stores as untrusted REGF input via
regipy (a pure-Python parser); nothing in wairz invokes ``bcdedit``
/ ``reg.exe`` / ``bootmgr`` against the parsed entries. The
image_path is surfaced for operator review; the bootloader binary
is NEVER loaded, mapped, or executed.

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns
(``custom_elements`` and ``anomaly_flags``) get dedicated
normalizer + schema_version stamp helpers in
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``1f4a2b3c4d5e``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from η.D.D head ``a8b9c0d1e2f3``.

Indexes:

- ``ix_windows_bcd_entries_firmware`` — ``(firmware_id,)`` covers
  "all BCD entries for firmware Y" canonical triage.
- ``ix_windows_bcd_entries_firmware_guid`` — ``(firmware_id,
  object_guid)`` covers "show me the {bootmgr} entry" natural lookup.
- ``ix_windows_bcd_entries_firmware_testsigning`` — ``(firmware_id,
  testsigning)`` covers θ.A.D anomaly-search and cross-firmware
  bootkit detection sweeps.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1f4a2b3c4d5e"
down_revision: str | None = "a8b9c0d1e2f3"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_bcd_entries",
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
        # Relative path to the BCD store within the detection root.
        sa.Column("source_path", sa.String(2048), nullable=False),
        # The GUID under ``\Objects\``.
        sa.Column("object_guid", sa.String(64), nullable=False),
        # BCD object Description/Type 32-bit discriminator.
        sa.Column("object_type", sa.Integer, nullable=True),
        # Application description (BCD element 0x12000004).
        sa.Column("description", sa.String(512), nullable=True),
        # Application path (BCD element 0x12000002 — bootloader binary).
        sa.Column("image_path", sa.String(2048), nullable=True),
        # GPT partition GUID parsed from BCD element 0x11000001.
        sa.Column("gpt_partition_guid", sa.String(64), nullable=True),
        # GPT disk GUID parsed from BCD element 0x11000001.
        sa.Column("gpt_disk_guid", sa.String(64), nullable=True),
        # TestSigning flag (BCD element 0x16000010).
        sa.Column("testsigning", sa.Boolean, nullable=True),
        # NoIntegrityChecks flag (BCD element 0x16000048).
        sa.Column("no_integrity_checks", sa.Boolean, nullable=True),
        # NX policy (BCD element 0x25000020).
        sa.Column("nx_policy", sa.Integer, nullable=True),
        # Custom element roster (JSONB list-shape).
        sa.Column("custom_elements", JSONB, nullable=True),
        # Anomaly flag aggregate (JSONB dict-shape).
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # Last-modified FILETIME from the NKRecord header (string).
        sa.Column("last_modified_ns", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_bcd_entries_firmware",
        "windows_bcd_entries",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_bcd_entries_firmware_guid",
        "windows_bcd_entries",
        ["firmware_id", "object_guid"],
    )
    op.create_index(
        "ix_windows_bcd_entries_firmware_testsigning",
        "windows_bcd_entries",
        ["firmware_id", "testsigning"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_bcd_entries_firmware_testsigning",
        table_name="windows_bcd_entries",
    )
    op.drop_index(
        "ix_windows_bcd_entries_firmware_guid",
        table_name="windows_bcd_entries",
    )
    op.drop_index(
        "ix_windows_bcd_entries_firmware",
        table_name="windows_bcd_entries",
    )
    op.drop_table("windows_bcd_entries")
