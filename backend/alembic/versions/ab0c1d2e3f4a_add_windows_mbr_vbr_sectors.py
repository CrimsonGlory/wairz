"""add windows_mbr_vbr_sectors table (Phase θ.E.A)

Revision ID: ab0c1d2e3f4a
Revises: 9c0d1e2f3a4b
Create Date: 2026-05-12 09:00:00.000000

Phase θ.E.A — adds the per-boot-sector landing zone for the Phase θ.E
Master Boot Record (MBR) + Volume Boot Record (VBR) boot-sector
correlation walker (θ.E.C). Boot sectors (the 512-byte first sector
of an MBR-partitioned disk image, and the first sector of each
FAT/NTFS/exFAT partition referenced by the MBR's partition table) are
walked by the θ.E.C runner, SHA256-hashed, signature-matched against
the bundled known-good Windows VBR shapes + known malicious bootkit
shapes (TDL4 / Olmasco / Mebroot / Petya / BlackEnergy), and persisted
into this table.

Completes the boot-chain trifecta with θ.A BCD + θ.C ESP:

- θ.A BCD walker: Windows boot-configuration database (the OS-stage
  boot loader config; post-bootmgr).
- θ.C ESP walker: UEFI EFI System Partition (.efi PE32+ files —
  bootmgfw.efi / shimx64.efi / grubx64.efi; pre-bootmgr UEFI stage).
- θ.E MBR/VBR walker (THIS): BIOS / legacy boot path — MBR bytes
  0..445 are 16-bit boot code; VBR first 3 bytes are JMP to bootloader
  in partition. Runs at Ring -2 BEFORE any OS code.

Surfaces per-sector forensic-triage metadata:

- **Source identifier** (file_path + sector_offset) — the relative
  path within the detection root (Rule #16) to the raw disk image
  file the sector was extracted from, plus the byte offset within
  that file (MBR=0; VBRs at partition starts).
- **Sector kind** (sector_kind) — 6-state discriminator: mbr,
  vbr_fat32, vbr_ntfs, vbr_fat16, vbr_exfat, unknown. DB CHECK
  constraint enforces the enum. The Literal mirror in
  ``app/schemas/firmware.py`` type-checks at the API boundary.
- **Sector content identifiers** (sector_sha256 + sector_size) —
  SHA256 of the 512-byte sector is the canonical cross-firmware
  identifier (lookup_mbr_vbr_sector MCP tool aggregates by sha256 +
  fingerprint across the wairz corpus).
- **bootcode_signature_match** — match name from the bundled
  known-good Windows / Linux signature table. NULL on no match.
- **known_bootkit_match** — match name from the bundled known-
  bootkit signature table (TDL4 / Olmasco / Mebroot / Petya /
  BlackEnergy). NULL on no match.
- **anomaly_flags JSONB** — θ.E.D classifier inputs
  (non_zero_padding, unexpected_partition_table, non_standard_jmp,
  non_zero_disk_signature).
- **fingerprint_sha256** — SHA256 of (file_path_lower + sector_offset
  + sector_kind + sector_sha256) for cross-firmware aggregation.

Per CLAUDE.md Rule #16: the θ.E.C walker uses
``get_detection_roots(firmware)`` — multi-archive Windows disk-image
extractions surface differently per unpacker; the multi-root
discipline catches raw .img / .raw / .vhd / .vhdx-already-converted-
by-α.2.7 / individual partition .bin files.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only. MBR + VBR are 512 bytes of x86 boot code that runs at Ring -2
BEFORE any OS code. The walker reads + SHA256-hashes + byte-compares
against signature tables — all of which read the file as DATA without
transferring control to the executable. NO code path in wairz invokes
nasm / objdump / qemu-system / any process-spawn primitive against
the sectors. The test gate
``tests/test_mbr_vbr_walker.py::test_mbr_vbr_no_bootcode_execution``
asserts this discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column gets a dedicated normaliser + schema_version stamp helper in
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``ab0c1d2e3f4a``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from θ.C.D head ``9c0d1e2f3a4b``.

Indexes:

- ``ix_windows_mbr_vbr_sectors_firmware`` — ``(firmware_id,)`` covers
  "all MBR/VBR sectors for firmware Y" canonical triage.
- ``ix_windows_mbr_vbr_sectors_firmware_sha`` — ``(firmware_id,
  sector_sha256)`` covers "show me this exact bootcode hash" lookup.
- ``ix_windows_mbr_vbr_sectors_fingerprint`` — ``(fingerprint_sha256,)``
  covers the cross-firmware aggregation in ``lookup_mbr_vbr_sector``
  MCP tool.
- ``ix_windows_mbr_vbr_sectors_firmware_bootkit`` — ``(firmware_id,
  known_bootkit_match)`` covers the bootkit-focused MCP search filter.

CHECK constraint enforces the 6-state sector_kind enum (Rule #33 .c)
— matches the Pydantic Literal mirror in
``app/schemas/firmware.py`` for boundary type-checking.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ab0c1d2e3f4a"
down_revision: str | None = "9c0d1e2f3a4b"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_mbr_vbr_sectors",
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
        # Relative path to the raw disk / partition image.
        sa.Column("file_path", sa.String(2048), nullable=False),
        # Sector byte offset within the source file (MBR=0).
        sa.Column("sector_offset", sa.BigInteger, nullable=False),
        # Sector kind discriminator (CHECK-enforced 6-state).
        sa.Column("sector_kind", sa.String(32), nullable=False),
        # SHA256 of the 512-byte sector contents (64 hex chars).
        sa.Column("sector_sha256", sa.String(64), nullable=False),
        # Sector size in bytes (always 512 today).
        sa.Column("sector_size", sa.BigInteger, nullable=False),
        # Match name from bundled known-good signature table; NULL on
        # no match.
        sa.Column(
            "bootcode_signature_match", sa.String(128), nullable=True
        ),
        # Match name from bundled known-bootkit signature table; NULL
        # on no match.
        sa.Column(
            "known_bootkit_match", sa.String(128), nullable=True
        ),
        # Heuristic detection summary — JSONB dict-shape.
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # SHA256 of canonical entry tuple for cross-firmware
        # aggregation.
        sa.Column("fingerprint_sha256", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # CHECK constraint enforcing the 6-state sector_kind enum per
    # Rule #33 .c. Mirrored by Pydantic Literal in
    # app/schemas/firmware.py.
    op.create_check_constraint(
        "ck_windows_mbr_vbr_sectors_sector_kind",
        "windows_mbr_vbr_sectors",
        "sector_kind IN "
        "('mbr', 'vbr_fat32', 'vbr_ntfs', 'vbr_fat16', "
        "'vbr_exfat', 'unknown')",
    )
    op.create_index(
        "ix_windows_mbr_vbr_sectors_firmware",
        "windows_mbr_vbr_sectors",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_mbr_vbr_sectors_firmware_sha",
        "windows_mbr_vbr_sectors",
        ["firmware_id", "sector_sha256"],
    )
    op.create_index(
        "ix_windows_mbr_vbr_sectors_fingerprint",
        "windows_mbr_vbr_sectors",
        ["fingerprint_sha256"],
    )
    op.create_index(
        "ix_windows_mbr_vbr_sectors_firmware_bootkit",
        "windows_mbr_vbr_sectors",
        ["firmware_id", "known_bootkit_match"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_mbr_vbr_sectors_firmware_bootkit",
        table_name="windows_mbr_vbr_sectors",
    )
    op.drop_index(
        "ix_windows_mbr_vbr_sectors_fingerprint",
        table_name="windows_mbr_vbr_sectors",
    )
    op.drop_index(
        "ix_windows_mbr_vbr_sectors_firmware_sha",
        table_name="windows_mbr_vbr_sectors",
    )
    op.drop_index(
        "ix_windows_mbr_vbr_sectors_firmware",
        table_name="windows_mbr_vbr_sectors",
    )
    op.drop_constraint(
        "ck_windows_mbr_vbr_sectors_sector_kind",
        "windows_mbr_vbr_sectors",
        type_="check",
    )
    op.drop_table("windows_mbr_vbr_sectors")
