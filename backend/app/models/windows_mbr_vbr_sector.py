"""Per-boot-sector Windows MBR/VBR row (Phase θ.E.A).

One row per 512-byte boot sector parsed from a firmware capture:

- the Master Boot Record (MBR — first 512 bytes of an MBR-partitioned
  disk image), and
- each partition's Volume Boot Record (VBR — first sector of every
  FAT16 / FAT32 / NTFS / exFAT partition referenced by the MBR's
  partition table).

Captures forensic-triage metadata for the boot-chain integrity scan
(θ.E — completes the boot-chain trifecta with θ.A BCD + θ.C ESP):

- The relative file path to the raw disk / partition image within the
  detection root (Rule #16) the sector was extracted from.
- The 512-byte sector offset (MBR is always 0; VBRs surface at the
  first sector of each partition the MBR's table points to).
- The sector kind (mbr, vbr_fat32, vbr_ntfs, vbr_fat16, vbr_exfat,
  unknown) — discriminated by the well-known signature bytes at
  offsets 3 / 82 of the sector (per the FAT12/16/32 + NTFS + exFAT
  format specs; see `mbr_vbr_walker.classify_sector_kind`).
- SHA256 of the 512-byte sector contents (canonical cross-firmware
  identifier — same hash across multiple firmware ⇒ same bootcode
  was planted; see `lookup_mbr_vbr_sector` MCP tool for cross-corpus
  correlation).
- Sector size in bytes (always 512 today; preserved as a column for
  forward-compat with non-512 sectors AND for the canonical
  invariant assertion in the test suite).
- Bootcode signature name (text — when the boot-code region matches
  a known-good Windows / Linux signature in the bundled signature
  table; NULL when no match). The ANSSI bootcode_parser-derived
  reference table lives at module load in
  `app.services.mbr_vbr_walker._KNOWN_BOOTCODE_SIGNATURES` per
  Rule #19 evidence-first inline approach (instead of vendoring the
  GPL-3 ANSSI tool — only the small signature constants are needed).
- Known bootkit name (text — TDL4 / Olmasco / Mebroot / Petya /
  BlackEnergy / etc.; NULL when no match). Same source table.
- Anomaly flags JSONB (heuristic-detection summary: non_zero_padding,
  unexpected_partition_table, non_standard_jmp, etc.).
- Fingerprint sha256 (cross-firmware aggregation surface — same
  fingerprint across firmware ⇒ same boot sector was planted).

**T1542.003 Pre-OS Boot: Bootkit (MBR/VBR sub-pattern)** — adversaries
(TDL4, Olmasco, Mebroot, BlackEnergy, Petya / NotPetya, GoldenSpy)
modify MBR bootcode bytes 0..445 (the first 446 bytes of the 512-byte
MBR are x86 boot code; bytes 446..509 are the 4-entry partition table;
bytes 510..511 are the magic ``\\x55\\xAA``). Modifying VBR bootcode
(first 3 bytes are a JMP / NOP-JMP, then OEM ID at offsets 3..10,
then partition-format BIOS Parameter Block, then bootloader code)
achieves the same persistence below the OS-visible layer. Detection
focus:

- **Bootcode signature mismatch** vs the bundled known-good Windows
  XP/Vista/7/8/10 VBR shapes — strong supply-chain / bootkit signal.
- **Known bootkit fingerprint hit** (TDL4 / Petya / etc.) — direct
  evidence of adversary deployment.
- **Anomaly flag combination** (non-standard JMP at offset 0,
  partition table entries with unexpected types, non-zero padding
  in reserved regions) — suggests modification even without a
  named-bootkit hit.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Disk images surface differently
across firmware unpackers (raw .img, .raw, .vhd, .vhdx-already-
converted-by-α.2.7); the multi-root discipline catches all forms.

**Per CLAUDE.md Rule #36 no-execute discipline**: this table holds
DATA only. MBR + VBR are 512 bytes of x86 boot code that runs at
Ring -2 BEFORE any OS code. The walker reads + SHA256-hashes + byte-
compares against signature tables; NO codepath in wairz invokes
nasm / objdump / qemu-system / any process-spawn primitive against
the sectors. The test gate
``tests/test_mbr_vbr_walker.py::test_mbr_vbr_no_bootcode_execution``
asserts this discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags``
JSONB column carries its own normaliser + schema_version stamp; see
``app.services.jsonb_normalizers``:

- ``_normalize_windows_mbr_vbr_sectors_anomaly_flags`` /
  ``_stamp_windows_mbr_vbr_sectors_anomaly_flags``

The flat columns (file_path / sector_offset / sector_kind /
sector_sha256 / sector_size / bootcode_signature_match /
known_bootkit_match / fingerprint_sha256) are materialized for fast
indexed lookup; the JSONB column carries the per-sector heuristic
detection flag aggregate.

θ.E.D finding emit (``windows_mbr_bootkit`` +
``windows_vbr_anomaly``) leverages the parsed data to flag:

- **windows_mbr_bootkit** — MBR sector with known_bootkit_match
  populated (TDL4 / Olmasco / Mebroot / Petya / etc.). Tier:
  HIGH always — direct named-bootkit fingerprint hit.

- **windows_vbr_anomaly** — VBR sector whose bootcode does NOT match
  any known-good Windows VBR signature AND has anomaly_flags set.
  Tier:

  - HIGH (Confidence.high) — known_bootkit_match populated (named
    VBR bootkit — Mebroot VBR variant, Olmasco VBR variant).
  - MEDIUM (Confidence.medium) — bootcode_signature_match is NULL
    AND >=2 anomaly flags raised (modified VBR without a named
    bootkit match — supply-chain compromise candidate).

Reference for MBR / VBR architecture:
- Intel x86 boot process: BIOS POST → MBR @ 0x7C00 → bootmgr.
- ANSSI bootcode_parser project (GPL-3, reference only — wairz
  embeds the small signature subset inline rather than vendoring):
  https://github.com/ANSSI-FR/bootcode_parser
- TDL4 MBR rootkit (Kaspersky 2011 analysis): MBR + driver hijack.
- Petya / NotPetya (2016/2017): MBR replacement + ransom-note dropper.
- Microsoft NTFS VBR spec:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsMbrVbrSector(Base):
    """Per-boot-sector row from a walked MBR / VBR scan."""

    __tablename__ = "windows_mbr_vbr_sectors"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this sector was parsed from.
    # Cascade DELETE so removing a firmware row removes its sectors.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path to the raw disk / partition image file within the
    # detection root (Rule #16). Stored relative for stable cross-
    # extraction identifiers. E.g. ``firmware.img`` or
    # ``partition_0.bin``.
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # Sector offset within the source file (BigInteger — disk images
    # can reach multiple GB). MBR is always 0; VBRs surface at the
    # first sector of each partition the MBR's table points to. Stored
    # in bytes, not sector index, so the relationship to the source
    # file is unambiguous.
    sector_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Sector kind discriminator. One of:
    # - mbr           — bytes 510..511 == \\x55\\xAA AND offset == 0
    # - vbr_fat32     — "FAT32   " at offset 82, OR Boot signature
    #                   \\x29 at offset 66, AND offset != 0
    # - vbr_ntfs      — "NTFS    " at offset 3
    # - vbr_fat16     — "FAT16   " at offset 54
    # - vbr_exfat     — "EXFAT   " at offset 3
    # - unknown       — has the \\x55\\xAA magic but doesn't match
    #                   any known FS signature (legitimate for some
    #                   embedded / legacy boot loaders)
    # CHECK constraint enforces the 6-state enum in the alembic
    # migration; the Literal mirror in app/schemas/firmware.py
    # type-checks at the API boundary.
    sector_kind: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # SHA256 of the 512-byte sector contents (canonical cross-firmware
    # identifier). 64 hex chars.
    sector_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # Sector size in bytes. Always 512 today; preserved as a column for
    # forward-compat with non-512 sectors AND the canonical invariant
    # assertion in the test suite.
    sector_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Match name from the bundled known-good signature table when the
    # boot-code region of the sector matches a known-good Windows /
    # Linux signature. E.g. "windows_10_mbr", "windows_7_vbr_ntfs",
    # "windows_xp_mbr". NULL when no match (modified / unknown
    # bootloader OR genuinely-non-Windows boot sector).
    bootcode_signature_match: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # Match name from the bundled known-bootkit signature table when
    # the boot-code region of the sector matches a known malicious
    # bootkit. E.g. "tdl4_mbr", "olmasco_mbr", "petya_mbr",
    # "mebroot_mbr", "blackenergy_mbr". NULL when no match.
    known_bootkit_match: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # Anomaly flags — heuristic detection summary for the θ.E.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "non_zero_padding": bool,
    #     "unexpected_partition_table": bool,
    #     "non_standard_jmp": bool,
    #     "non_zero_disk_signature": bool,
    #     "is_mbr": bool,
    #     "is_vbr": bool,
    #   }
    # NULL only on defensive parser-failure paths.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # SHA256 fingerprint of the canonical entry tuple
    # (file_path_lower + sector_offset + sector_kind + sector_sha256)
    # for cross-firmware aggregation in ``lookup_mbr_vbr_sector`` MCP
    # tool. Same fingerprint across firmware ⇒ same boot sector was
    # planted (campaign / supply-chain correlation across the wairz
    # corpus). NULL on defensive parser-failure paths.
    fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Walker run timestamp — when this row was inserted.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All MBR/VBR sectors for firmware Y" — canonical triage.
        Index(
            "ix_windows_mbr_vbr_sectors_firmware",
            "firmware_id",
        ),
        # "All MBR/VBR sectors for firmware Y, by sha256" — natural
        # lookup for "show me this exact bootcode hash" triage.
        Index(
            "ix_windows_mbr_vbr_sectors_firmware_sha",
            "firmware_id",
            "sector_sha256",
        ),
        # "All MBR/VBR sectors matching this fingerprint across all
        # firmware" — the lookup_mbr_vbr_sector MCP tool's query
        # shape (cross-firmware aggregation for boot-chain hunt).
        Index(
            "ix_windows_mbr_vbr_sectors_fingerprint",
            "fingerprint_sha256",
        ),
        # "All sectors with a bootkit match for firmware Y" — the
        # anomaly-focused MCP search filter.
        Index(
            "ix_windows_mbr_vbr_sectors_firmware_bootkit",
            "firmware_id",
            "known_bootkit_match",
        ),
    )
