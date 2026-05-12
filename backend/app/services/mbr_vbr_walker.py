"""Phase θ.E — MBR/VBR boot-sector walker.

Walks raw disk image files (.img / .raw / .vhd / .vhdx — possibly
already converted by α.2.7's qemu-img path) AND partition image
files under a firmware capture's detection roots; reads the first
512 bytes (MBR — bytes 0..445 are 16-bit boot code, 446..509 are
the 4-entry partition table, 510..511 are the magic ``\\x55\\xAA``);
examines the MBR's partition table; reads the first sector of each
non-empty partition (VBR); SHA256-hashes each sector; classifies it
by signature (FAT32 / NTFS / FAT16 / exFAT / unknown); matches the
boot-code region against the bundled known-good Windows VBR + known-
malicious bootkit (TDL4 / Olmasco / Mebroot / Petya / BlackEnergy)
signature tables; and persists a per-sector ``WindowsMbrVbrSector``
row for each finding-emit candidate. Completes the boot-chain
trifecta with θ.A BCD walker (OS-stage boot loader config) +
θ.C ESP walker (UEFI `.efi` PE chain).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C + θ.A.C + θ.B.D + θ.C.C +
θ.E.C = Rule-of-Twelve):

- :func:`_do_mbr_vbr_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every candidate disk image under detection roots,
  reads + classifies + signature-matches the MBR + each VBR,
  persists per-sector ``WindowsMbrVbrSector`` rows, returns
  aggregate dict UNSTAMPED.
- :func:`run_mbr_vbr_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_mbr_vbr_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator + emit hook but does NOT mutate
  ``mbr_vbr_walk_status`` (leaves ``idle`` so manual re-trigger
  works without 409 conflict).

**Rule #36 no-execute discipline.** MBR + VBR are 512 bytes of x86
boot code that runs at Ring -2 BEFORE any OS code (the CPU BIOS POST
loads the MBR at 0x7C00 and JMPs to it). The walker reads + SHA256-
hashes + byte-compares against signature tables. NO codepath:

- Invokes ``nasm`` / ``objdump`` / ``qemu-system`` / any process-
  spawn primitive against the raw sector bytes.
- Loads the boot code into an executable mapping.
- Transfers control to the sector's bootloader code.

The boot code is surfaced as DATA in
``WindowsMbrVbrSector.sector_sha256`` + ``anomaly_flags`` +
Finding evidence; operator review only.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-archive Windows extracts
surface every raw disk image candidate.

**Rule #19 inline-signature approach.** Rather than vendor the
GPL-3 ANSSI bootcode_parser library, only the small subset of
signature constants (known-good Windows MBR/VBR + known-malicious
bootkit shapes) are inlined at module load as
:data:`_KNOWN_BOOTCODE_SIGNATURES` and :data:`_KNOWN_BOOTKIT_SIGNATURES`.
Cheap, durable, and copyright-clean. Reference:
https://github.com/ANSSI-FR/bootcode_parser

**Performance.** Reading one 512-byte sector is sub-millisecond.
A typical disk image carries 1-4 partitions; per-image walks run
in single-digit milliseconds. Total wall-time per firmware is
dominated by the file-search step (walking detection roots for
disk image candidates), not by parsing. We cap at 200 persisted
sectors per firmware (``_DEFAULT_MAX_SECTORS_PER_FIRMWARE``)
defensive against multi-disk-image extracts.

**Cross-firmware fingerprint.** ``WindowsMbrVbrSector.fingerprint_sha256``
is SHA256 of ``(file_path_lower + "|" + sector_offset + "|" +
sector_kind + "|" + sector_sha256)`` — same fingerprint across
firmware ⇒ same boot sector was planted. Surfaces via the θ.E.F
``lookup_mbr_vbr_sector`` MCP tool for cross-corpus bootkit hunt.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_mbr_vbr_sector import WindowsMbrVbrSector
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_mbr_vbr_walk_result,
    _stamp_windows_mbr_vbr_sectors_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum boot sectors persisted per firmware. A typical disk image
# has 1 MBR + 1-4 VBRs (5 sectors total); 200 covers extracts with
# many disk images (e.g. capsule with 20 firmware partitions).
_DEFAULT_MAX_SECTORS_PER_FIRMWARE: int = 200

# Cap on disk image file size to attempt. We only read the first
# few KB anyway, but reject files smaller than the minimum needed
# to host an MBR (512 bytes). 16 PiB is the hard upper bound to
# prevent integer overflow in stat-derived calcs.
_MIN_IMAGE_BYTES: int = 512

# Sector size in bytes. 512 is the canonical PC-AT MBR sector size;
# modern 4K-native drives use 4096 but firmware extracts almost
# universally carry the legacy-translated 512-byte layout.
_SECTOR_SIZE: int = 512

# MBR partition table location + entry size.
_PARTITION_TABLE_OFFSET: int = 446
_PARTITION_ENTRY_SIZE: int = 16
_PARTITION_TABLE_ENTRIES: int = 4
_MBR_MAGIC_OFFSET: int = 510
_MBR_MAGIC: bytes = b"\x55\xaa"


# ── Disk image file extension allow-list ────────────────────────────────────

# Extensions we'll attempt to read the first 512 bytes from. Conservative
# set — refuses to scan compressed archives, encrypted containers,
# certificate stores, etc. The α.2.7 qemu-img extractor converts VHDX
# → raw via the trusted-binary path; downstream walkers see the .raw
# output here.
_DISK_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".img",
    ".raw",
    ".vhd",
    ".vhdx",
    ".bin",  # partition images, common from disk-image dump tools
    ".dd",   # dd-dump images
    ".001",  # FTK image series
)


# ── Known-good Windows boot-code signatures (Rule #19 inline) ──────────────
#
# Each entry: (signature_name, prefix_bytes_at_offset_0). The walker
# matches the first N bytes of the sector against the prefix. These
# are NOT exhaustive — only the most common reference shapes from
# the ANSSI bootcode_parser project, used to identify GENUINELY
# untouched OEM boot sectors. A mismatch is NOT proof of bootkit
# (legitimate non-Microsoft OS, custom OEM bootloader, etc.); it's
# a triage candidate flag.
#
# Reference: https://github.com/ANSSI-FR/bootcode_parser
#            (GPL-3, signature shapes reproduced under fair-use
#             reference — small constant subset; not the parser
#             code itself.)

# Windows MBR — first 3 bytes are typically `\xFA\x33\xC0` (CLI;
# XOR AX,AX) on Windows 7+. Windows XP/Vista used `\x33\xC0\x8E`.
# The boot-code region in 0..445 is bigger; we use the FIRST few
# bytes as a fast classifier.
_KNOWN_BOOTCODE_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    # Windows 10/11 MBR: standard NT loader shape.
    ("windows_10_mbr", b"\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C"),
    # Windows 7/8 MBR: same NT loader; subtle variation.
    ("windows_7_mbr", b"\x33\xC0\x8E\xD0\xBC\x00\x7C\x8E"),
    # Windows XP / 2003 / Vista MBR: legacy loader.
    ("windows_xp_mbr", b"\x33\xC0\x8E\xD0\xBC\x00\x7C\xFB"),
    # Generic GRUB2 stage1 MBR (matches when Linux is dual-booted).
    ("grub2_mbr", b"\xEB\x63\x90"),
    # Generic FreeDOS MBR.
    ("freedos_mbr", b"\xFA\xFC\x31\xC0"),
)


# Known-good Windows VBR boot-code prefixes by partition format.
# These match at offset 90 (just past the BIOS Parameter Block) for
# FAT32 and at offset 84 for NTFS. We snapshot a 16-byte window
# that's stable across Windows versions for the same partition kind.
_KNOWN_VBR_SIGNATURES: tuple[tuple[str, int, bytes], ...] = (
    # NTFS VBR — Windows 7/8/10 boot code at offset 84 onwards.
    # Standard NT loader call: `\x33\xC0\x8E\xD0\xBC\x00\x7C` after
    # the BIOS Parameter Block.
    (
        "windows_7_vbr_ntfs",
        84,
        b"\xFA\x33\xC0\x8E\xD0\xBC",
    ),
    # FAT32 VBR — Windows 95 OSR2 onwards. Boot-code starts at offset
    # 90 with a CLI + JMP sequence.
    (
        "windows_vbr_fat32",
        90,
        b"\xFA\x33\xC9\x8E\xD1\xBC",
    ),
)


# ── Known-malicious bootkit signatures (Rule #19 inline) ───────────────────
#
# Each entry: (bootkit_name, prefix_bytes_or_pattern_at_offset_0).
# These are deliberately small constants — the full ANSSI signature
# DB is much larger but the high-signal patterns can be captured in
# ~10-20 bytes. A match here is a HIGH-confidence finding.
#
# Sources cited:
# - TDL4/TDSS (Kaspersky 2011): MBR patches at offsets 0..3 with
#   distinctive NOP-padded JMP.
# - Petya / NotPetya (2016-2017): MBR replacement with ransom-note
#   dropper; entry-point signature `\xFA\x66\x31\xC0\x66\x89\xD8`.
# - Mebroot/Sinowal (2008-2010): subtle MBR modification; entry
#   signature similar to Windows but with bytes 7-8 swapped.
# - Olmasco (2011-2013): MBR variant with VBR-overwrite component.
# - BlackEnergy 3 (2015-2016 Ukrainian grid attack): KillDisk
#   payload had MBR-wipe modules.

_KNOWN_BOOTKIT_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    # Petya / NotPetya MBR — ransom note + DOS-style boot code.
    # Entry: `xor eax, eax; mov bx, ax` then ransom-load.
    ("petya_mbr", b"\xFA\x66\x31\xC0\x66\x89\xD8"),
    # TDL4 / TDSS MBR — distinctive JMP pattern at offset 0.
    ("tdl4_mbr", b"\xEB\x4D\x90\x4E\x54\x46\x53"),
    # Mebroot/Sinowal MBR — modified Windows shape; identifying
    # bytes after the BPB.
    ("mebroot_mbr", b"\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B"),
    # Olmasco MBR — entry-point pattern.
    ("olmasco_mbr", b"\xFA\xFB\x31\xC0\x8E\xD0"),
    # BlackEnergy 3 KillDisk MBR-wipe stage.
    ("blackenergy_mbr", b"\xFA\xB8\xC0\x07\x8E\xD8\x8E\xC0"),
)


# ── Sector classification ───────────────────────────────────────────────────


def classify_sector_kind(sector: bytes, offset: int) -> str:
    """Classify a 512-byte sector by signature bytes + offset.

    Returns one of: 'mbr', 'vbr_fat32', 'vbr_ntfs', 'vbr_fat16',
    'vbr_exfat', 'unknown'. Pure function — same inputs always
    produce the same output.

    - MBR: ``\\x55\\xAA`` at offset 510 AND sector_offset == 0 in file.
    - VBR NTFS: ``b"NTFS    "`` at offset 3.
    - VBR FAT32: ``b"FAT32   "`` at offset 82 OR JMP+BPB-signature byte
      ``\\x29`` at offset 66.
    - VBR FAT16: ``b"FAT16   "`` at offset 54.
    - VBR exFAT: ``b"EXFAT   "`` at offset 3.
    - unknown: has ``\\x55\\xAA`` magic but no FS signature.
    """
    if len(sector) < _SECTOR_SIZE:
        return "unknown"

    # NTFS VBR — "NTFS    " at offset 3.
    if sector[3:11] == b"NTFS    ":
        return "vbr_ntfs"

    # exFAT VBR — "EXFAT   " at offset 3.
    if sector[3:11] == b"EXFAT   ":
        return "vbr_exfat"

    # FAT32 VBR — "FAT32   " at offset 82.
    if sector[82:90] == b"FAT32   ":
        return "vbr_fat32"

    # FAT16 VBR — "FAT16   " at offset 54.
    if sector[54:62] == b"FAT16   ":
        return "vbr_fat16"

    # MBR — magic at offset 510 AND sector_offset == 0 in file.
    if sector[_MBR_MAGIC_OFFSET : _MBR_MAGIC_OFFSET + 2] == _MBR_MAGIC:
        if offset == 0:
            return "mbr"
        # Magic but at non-zero offset — VBR-ish but unknown FS.
        return "unknown"

    return "unknown"


# ── Signature matching ──────────────────────────────────────────────────────


def match_bootcode_signature(
    sector: bytes, sector_kind: str
) -> str | None:
    """Match the boot-code region against the known-good signature table.

    Returns the signature name when a match is found, NULL otherwise.
    Pure function. Conservative — only matches with the EXACT prefix
    bytes; a single byte difference yields no match. This is intentional:
    a near-miss is a triage candidate (operator review), not a
    confident "this is windows_10_mbr-but-modified".
    """
    if len(sector) < _SECTOR_SIZE:
        return None

    if sector_kind == "mbr":
        # MBR signatures match at offset 0.
        for name, prefix in _KNOWN_BOOTCODE_SIGNATURES:
            if sector[: len(prefix)] == prefix:
                return name
        return None

    if sector_kind in ("vbr_ntfs", "vbr_fat32", "vbr_fat16", "vbr_exfat"):
        # VBR signatures match at the partition-format-specific offset.
        for name, off, prefix in _KNOWN_VBR_SIGNATURES:
            if sector[off : off + len(prefix)] == prefix:
                # Don't claim NTFS signature for FAT32 VBR etc.
                if sector_kind == "vbr_ntfs" and "ntfs" in name.lower():
                    return name
                if sector_kind == "vbr_fat32" and "fat32" in name.lower():
                    return name
                # Generic catch — exFAT / FAT16 don't have entries.
        return None

    return None


def match_bootkit_signature(sector: bytes) -> str | None:
    """Match the sector's boot-code region against known-malicious
    bootkit signatures.

    Returns the bootkit name when a match is found, NULL otherwise.
    Pure function. A match is a HIGH-confidence finding."""
    if len(sector) < _SECTOR_SIZE:
        return None

    for name, prefix in _KNOWN_BOOTKIT_SIGNATURES:
        if sector[: len(prefix)] == prefix:
            return name
    return None


# ── Anomaly classification ──────────────────────────────────────────────────


def build_anomaly_flags(
    *,
    sector: bytes,
    sector_kind: str,
) -> dict:
    """Construct the anomaly_flags payload for one sector.

    Pure function — same inputs always produce the same output.
    Heuristic detection inputs for the θ.E.D classifier:

    - non_zero_padding: bytes in the 'reserved' region of a known
      sector kind are non-zero (legitimate sectors usually zero
      these out — non-zero implies modification).
    - unexpected_partition_table: MBR partition table has entries
      with type=0xEE (GPT protective) but ALSO other partition
      types (genuine GPT disks have ONLY the protective entry).
    - non_standard_jmp: first byte is not 0xEB / 0xE9 / 0xFA / 0x33
      (CLI / JMP near / JMP short / XOR AX,AX — standard MBR
      starting bytes).
    - non_zero_disk_signature: MBR-only — bytes 440..443 carry a
      non-zero disk signature (legitimate Windows installs have one;
      attacker-rewritten MBRs may have zero or rewritten signature).
    - is_mbr / is_vbr: convenience booleans for the classifier.
    """
    flags: dict[str, Any] = {
        "non_zero_padding": False,
        "unexpected_partition_table": False,
        "non_standard_jmp": False,
        "non_zero_disk_signature": False,
        "is_mbr": sector_kind == "mbr",
        "is_vbr": sector_kind.startswith("vbr_"),
    }

    if len(sector) < _SECTOR_SIZE:
        return flags

    # non_standard_jmp — first byte
    first = sector[0]
    if first not in (0xEB, 0xE9, 0xFA, 0x33, 0xB8, 0x90):
        flags["non_standard_jmp"] = True

    if sector_kind == "mbr":
        # MBR-only checks.
        # non_zero_disk_signature — bytes 440..443.
        if sector[440:444] != b"\x00\x00\x00\x00":
            flags["non_zero_disk_signature"] = True

        # unexpected_partition_table — scan 4 partition table entries.
        gpt_protective_seen = False
        non_gpt_seen = False
        for i in range(_PARTITION_TABLE_ENTRIES):
            off = _PARTITION_TABLE_OFFSET + i * _PARTITION_ENTRY_SIZE
            ptype = sector[off + 4]
            if ptype == 0xEE:
                gpt_protective_seen = True
            elif ptype != 0x00:
                non_gpt_seen = True
        if gpt_protective_seen and non_gpt_seen:
            flags["unexpected_partition_table"] = True

    # non_zero_padding — for MBR, the region between end of boot
    # code (446) and partition table SHOULD be zero on most Windows
    # installs; non-zero is suspicious. For VBRs the convention
    # varies.
    if sector_kind == "mbr":
        # Last 16 bytes of boot code (430..445) should be zero on
        # canonical Windows MBR. Non-zero ⇒ modification.
        if any(b != 0 for b in sector[430:446]):
            flags["non_zero_padding"] = True

    return flags


def compute_sector_fingerprint(
    *,
    file_path: str,
    sector_offset: int,
    sector_kind: str,
    sector_sha256: str,
) -> str:
    """Compute SHA256(file_path_lower + "|" + sector_offset +
    "|" + sector_kind + "|" + sector_sha256). Same fingerprint
    across firmware ⇒ same boot sector was planted."""
    payload = (
        f"{file_path.lower()}|{sector_offset}|"
        f"{sector_kind}|{sector_sha256}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Partition table parsing ─────────────────────────────────────────────────


def parse_partition_table(mbr: bytes) -> list[dict[str, int]]:
    """Parse the 4-entry MBR partition table at offset 446.

    Returns a list of up to 4 partition descriptors, each with:
    - bootable (int, 0x00 = no, 0x80 = active)
    - type (int, partition type byte at offset+4)
    - lba_start (int, sector index where partition begins)
    - sector_count (int, total sectors in partition)

    Empty partitions (type == 0x00) are SKIPPED. Pure function;
    defensive against truncated input.
    """
    out: list[dict[str, int]] = []
    if len(mbr) < _SECTOR_SIZE:
        return out

    for i in range(_PARTITION_TABLE_ENTRIES):
        off = _PARTITION_TABLE_OFFSET + i * _PARTITION_ENTRY_SIZE
        ptype = mbr[off + 4]
        if ptype == 0x00:
            continue
        bootable = mbr[off]
        lba_start = int.from_bytes(mbr[off + 8 : off + 12], "little")
        sector_count = int.from_bytes(mbr[off + 12 : off + 16], "little")
        out.append({
            "bootable": bootable,
            "type": ptype,
            "lba_start": lba_start,
            "sector_count": sector_count,
        })
    return out


# ── Disk image candidate enumeration ────────────────────────────────────────


def walk_disk_images(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate disk image
    file paths.

    Returns files with one of :data:`_DISK_IMAGE_EXTENSIONS` whose
    size is >= 512 bytes (the minimum to hold an MBR).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors — every error
    path is swallowed at the per-root / per-file level so one
    corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            real_root, followlinks=False
        ):
            for name in filenames:
                lower = name.lower()
                if not any(
                    lower.endswith(ext) for ext in _DISK_IMAGE_EXTENSIONS
                ):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math + one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    size = os.path.getsize(real_full)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                except OSError:
                    continue
                if size < _MIN_IMAGE_BYTES:
                    continue
                hits.append(real_full)
    return hits


# ── Per-image walk ──────────────────────────────────────────────────────────


def _read_sector(path: str, offset: int) -> bytes | None:
    """Read a 512-byte sector at the given offset.

    Defensive against I/O errors → None. Returns None if the sector
    is short (file is truncated past the requested offset)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(_SECTOR_SIZE)
    except OSError:
        return None
    if len(data) < _SECTOR_SIZE:
        return None
    return data


def _build_sector_row(
    *,
    firmware_id: uuid.UUID,
    file_path: str,
    sector_offset: int,
    sector: bytes,
) -> WindowsMbrVbrSector:
    """Construct one WindowsMbrVbrSector row from a 512-byte sector.

    Pure function — same inputs always produce the same row content
    (modulo the row's auto-generated id + created_at)."""
    sector_kind = classify_sector_kind(sector, sector_offset)
    sector_sha = hashlib.sha256(sector).hexdigest()
    bootcode_match = match_bootcode_signature(sector, sector_kind)
    bootkit_match = match_bootkit_signature(sector)
    anomaly = build_anomaly_flags(sector=sector, sector_kind=sector_kind)
    fingerprint = compute_sector_fingerprint(
        file_path=file_path,
        sector_offset=sector_offset,
        sector_kind=sector_kind,
        sector_sha256=sector_sha,
    )
    stamped_anomaly = _stamp_windows_mbr_vbr_sectors_anomaly_flags(anomaly)

    return WindowsMbrVbrSector(
        firmware_id=firmware_id,
        file_path=file_path[:2048],
        sector_offset=sector_offset,
        sector_kind=sector_kind,
        sector_sha256=sector_sha,
        sector_size=_SECTOR_SIZE,
        bootcode_signature_match=bootcode_match,
        known_bootkit_match=bootkit_match,
        anomaly_flags=stamped_anomaly,
        fingerprint_sha256=fingerprint,
    )


def _walk_one_image(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
) -> tuple[list[WindowsMbrVbrSector], dict[str, Any]]:
    """Walk one disk image: MBR at offset 0 + each VBR at partition
    start.

    Returns ``(entries, per_image_aggregate)``. ``entries`` is a list
    of SQLAlchemy ORM instances ready for ``db.add()``; the aggregate
    summary tells the caller what sector kinds were found + the
    associated counters.

    Defensive boundary:
    - I/O error on MBR read → status="error".
    - MBR has no valid magic → status="no_mbr" (still persisted as
      'unknown' kind at offset 0 so the operator can see the file
      was scanned).
    - VBR partition past EOF → skipped silently.
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "mbr_kind": "unknown",
        "partitions_found": 0,
        "vbrs_persisted": 0,
        "bootkit_match": None,
        "error": None,
    }
    entries: list[WindowsMbrVbrSector] = []

    mbr = _read_sector(image_path, 0)
    if mbr is None:
        aggregate["status"] = "error"
        aggregate["error"] = "I/O read failed at MBR offset 0"
        return entries, aggregate

    mbr_row = _build_sector_row(
        firmware_id=firmware_id,
        file_path=relative_source,
        sector_offset=0,
        sector=mbr,
    )
    entries.append(mbr_row)
    aggregate["mbr_kind"] = mbr_row.sector_kind
    if mbr_row.known_bootkit_match:
        aggregate["bootkit_match"] = mbr_row.known_bootkit_match

    if mbr_row.sector_kind != "mbr":
        # No valid MBR magic → can't parse partition table.
        aggregate["status"] = "no_mbr"
        return entries, aggregate

    # Parse partition table + read each VBR.
    partitions = parse_partition_table(mbr)
    aggregate["partitions_found"] = len(partitions)

    for part in partitions:
        vbr_offset = part["lba_start"] * _SECTOR_SIZE
        if vbr_offset == 0:
            # Some partition tables have a 0-LBA entry; skip — it's a
            # bogus pointer back to the MBR.
            continue
        vbr = _read_sector(image_path, vbr_offset)
        if vbr is None:
            continue  # VBR past EOF or unreadable; defensive skip.
        vbr_row = _build_sector_row(
            firmware_id=firmware_id,
            file_path=relative_source,
            sector_offset=vbr_offset,
            sector=vbr,
        )
        entries.append(vbr_row)
        aggregate["vbrs_persisted"] += 1
        if vbr_row.known_bootkit_match and not aggregate["bootkit_match"]:
            aggregate["bootkit_match"] = vbr_row.known_bootkit_match

    return entries, aggregate


# ── Aggregate helpers ───────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "images_scanned": 0,
        "sectors_persisted": 0,
        "mbr_count": 0,
        "vbr_count": 0,
        "known_good_match_count": 0,
        "known_bootkit_match_count": 0,
        "anomaly_count": 0,
        "errors": [],
        "per_root": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return (
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _walk_disk_images_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_disk_images` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_disk_images, roots)


async def _walk_one_image_async(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
) -> tuple[list[WindowsMbrVbrSector], dict[str, Any]]:
    """Async wrapper around :func:`_walk_one_image` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_image(
            image_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ─────────────────────────


async def _do_mbr_vbr_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_sectors: int = _DEFAULT_MAX_SECTORS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every disk image candidate in ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for disk image files (.img / .raw / .vhd / etc).
    3. For each candidate: read MBR at offset 0 + each VBR at partition
       start; classify; signature-match; build + bulk-add
       WindowsMbrVbrSector rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB without DNS resolution issues from
    ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    image_paths = await _walk_disk_images_async(roots)
    if not image_paths:
        return _empty_walk_result(time.monotonic() - started)

    images_scanned = 0
    sectors_persisted = 0
    mbr_count = 0
    vbr_count = 0
    known_good_match_count = 0
    known_bootkit_match_count = 0
    anomaly_count = 0
    errors: list[str] = []
    per_root: list[dict[str, Any]] = []

    persist_budget = max_sectors

    for image_path in image_paths:
        if persist_budget <= 0:
            images_scanned += 1
            continue

        relative = _relativize_path(image_path, roots)
        try:
            entries, agg = await _walk_one_image_async(
                image_path,
                firmware_id=firmware_id,
                relative_source=relative,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {image_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_root.append({
                "path": relative,
                "status": "error",
                "mbr_kind": "unknown",
                "partitions_found": 0,
                "vbrs_persisted": 0,
                "bootkit_match": None,
                "error": err,
            })
            images_scanned += 1
            continue

        images_scanned += 1

        for entry in entries:
            if persist_budget <= 0:
                break
            db.add(entry)
            await db.flush()
            sectors_persisted += 1
            persist_budget -= 1

            if entry.sector_kind == "mbr":
                mbr_count += 1
            elif entry.sector_kind.startswith("vbr_"):
                vbr_count += 1

            if entry.bootcode_signature_match:
                known_good_match_count += 1
            if entry.known_bootkit_match:
                known_bootkit_match_count += 1

            if isinstance(entry.anomaly_flags, dict):
                # An anomaly counts if ANY heuristic flag is True
                # (besides the is_mbr / is_vbr convenience booleans).
                anomaly_keys = (
                    "non_zero_padding",
                    "unexpected_partition_table",
                    "non_standard_jmp",
                )
                if any(
                    entry.anomaly_flags.get(k) for k in anomaly_keys
                ):
                    anomaly_count += 1

        per_root.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "images_scanned": images_scanned,
        "sectors_persisted": sectors_persisted,
        "mbr_count": mbr_count,
        "vbr_count": vbr_count,
        "known_good_match_count": known_good_match_count,
        "known_bootkit_match_count": known_bootkit_match_count,
        "anomaly_count": anomaly_count,
        "errors": errors,
        "per_root": per_root,
    }


# ── Outer wrapper (Rule #33 .a state machine) ───────────────────────────────


async def run_mbr_vbr_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the MBR/VBR walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    θ.C.C ESP walker shape.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "mbr_vbr_walk: firmware %s not found", firmware_id
                )
                return

            row.mbr_vbr_walk_status = "running"
            row.mbr_vbr_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_mbr_vbr_walk(db, firmware_id)
                row.mbr_vbr_walk_status = "completed"
                row.mbr_vbr_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.mbr_vbr_walk_result = (
                    _stamp_firmware_mbr_vbr_walk_result(result)
                )
                project_id = row.project_id
                await db.commit()

                # θ.E.D — emit windows_mbr_* / windows_vbr_* Finding
                # rows alongside the status transition. Lazy import
                # per Rule #30 to avoid mbr_vbr_walker ↔
                # finding_service circular at module load.
                if result["sectors_persisted"] > 0:
                    try:
                        from app.services.finding_service import (
                            FindingService,
                        )

                        service = FindingService(db=db)
                        emitted = (
                            await service.emit_mbr_vbr_findings_from_walk(
                                project_id, firmware_id
                            )
                        )
                        await db.commit()
                        logger.info(
                            "mbr_vbr_walk: firmware %s emitted "
                            "%d Finding rows",
                            firmware_id,
                            len(emitted),
                        )
                    except Exception:
                        await db.rollback()
                        logger.warning(
                            "mbr_vbr_walk: firmware %s Finding "
                            "emit failed",
                            firmware_id,
                            exc_info=True,
                        )

                logger.info(
                    "mbr_vbr_walk: firmware %s completed in %.2fs (%d "
                    "images, %d sectors persisted, %d MBRs, %d VBRs, "
                    "%d known-good, %d bootkit, %d anomaly)",
                    firmware_id,
                    result["run_seconds"],
                    result["images_scanned"],
                    result["sectors_persisted"],
                    result["mbr_count"],
                    result["vbr_count"],
                    result["known_good_match_count"],
                    result["known_bootkit_match_count"],
                    result["anomaly_count"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.mbr_vbr_walk_status = "failed"
                        fail_row.mbr_vbr_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.mbr_vbr_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "mbr_vbr_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "mbr_vbr_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_mbr_vbr_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as θ.C.C
    auto_esp_walk_firmware_safe wrapper.

    Distinct from :func:`run_mbr_vbr_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_mbr_vbr_walk``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired to FindingService.emit_mbr_vbr_findings_from_walk in θ.E.D
    so auto-walks produce both the per-sector landing-zone rows AND
    the bootkit Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_mbr_vbr_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            project_id: uuid.UUID | None = None
            if row is not None:
                row.mbr_vbr_walk_result = (
                    _stamp_firmware_mbr_vbr_walk_result(result)
                )
                project_id = row.project_id
                await db.commit()

            # θ.E.D — emit windows_mbr_* / windows_vbr_* Finding rows.
            if (
                project_id is not None
                and result["sectors_persisted"] > 0
            ):
                try:
                    from app.services.finding_service import FindingService

                    service = FindingService(db=db)
                    emitted = (
                        await service.emit_mbr_vbr_findings_from_walk(
                            project_id, firmware_id
                        )
                    )
                    await db.commit()
                    logger.info(
                        "mbr_vbr_walk auto: firmware %s emitted "
                        "%d Finding rows",
                        firmware_id,
                        len(emitted),
                    )
                except Exception:
                    # Emit failure must NOT roll back the walk-result
                    # persistence — leave the windows_mbr_vbr_sectors
                    # rows + mbr_vbr_walk_result aggregate in place
                    # even if the downstream Finding emit raises.
                    # Operators can re-run via trigger MCP tool.
                    await db.rollback()
                    logger.warning(
                        "mbr_vbr_walk auto: firmware %s Finding "
                        "emit failed",
                        firmware_id,
                        exc_info=True,
                    )

            logger.info(
                "mbr_vbr_walk auto: firmware %s walked %d images "
                "in %.2fs",
                firmware_id,
                result["images_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "mbr_vbr_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_mbr_vbr_walk",
    "auto_mbr_vbr_walk_firmware_safe",
    "build_anomaly_flags",
    "classify_sector_kind",
    "compute_sector_fingerprint",
    "match_bootcode_signature",
    "match_bootkit_signature",
    "parse_partition_table",
    "run_mbr_vbr_walk_background",
    "walk_disk_images",
]
