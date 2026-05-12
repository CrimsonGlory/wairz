"""Tests for the Phase θ.E.C MBR/VBR boot-sector walker.

Critical test: ``test_mbr_vbr_no_bootcode_execution`` — the Rule #36
no-execute gate. The MBR/VBR walker module MUST contain ZERO process-
spawn primitives. MBR + VBR are 512 bytes of x86 boot code that
runs at Ring -2 BEFORE any OS code. The walker treats them as DATA
via SHA256 hashing + byte-comparison against signature tables. NO
codepath in this walker may invoke nasm / objdump / qemu-system /
chainloader against the sectors.

Test coverage:
- Pure helpers (sector classification, signature matching,
  anomaly classification, fingerprint compute).
- ``walk_disk_images`` — extension-allow-list + min-size gate
  + path-traversal-resistance across detection roots.
- ``parse_partition_table`` — 4-entry partition table decoder.
- Inner orchestrator ``_do_mbr_vbr_walk`` — Rule #35b live canaries
  via make_live_db: no-roots, no-images, successful walk with mixed
  states.
- **Rule #36 no-execute test gate** — ``test_mbr_vbr_no_bootcode_execution``
  asserts the walker module surfaces sectors as DATA only.
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsMbrVbrSector
from app.services.mbr_vbr_walker import (
    _do_mbr_vbr_walk,
    build_anomaly_flags,
    classify_sector_kind,
    compute_sector_fingerprint,
    match_bootcode_signature,
    match_bootkit_signature,
    parse_partition_table,
    walk_disk_images,
)
from tests._live_db import make_live_db


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Rule #36 no-execute test gate ───────────────────────────────────────────


_WALKER_MODULE = (
    Path(__file__).parent.parent
    / "app"
    / "services"
    / "mbr_vbr_walker.py"
)


# Forbidden execution primitives — patterns the walker MUST NOT
# contain. We scrub string literals + comments before matching so
# documentation / examples don't false-positive.
_FORBIDDEN_EXEC_PATTERNS: list[str] = [
    r"\bsubprocess\.\w+\(",
    r"\bos\.system\(",
    r"\bos\.execvp\(",
    r"\bos\.execve\(",
    r"\bos\.spawnvp\(",
    r"\basyncio\.create_subprocess_(exec|shell)\(",
    r"\brunpy\.\w+\(",
    r"(?:^|[^a-zA-Z_])eval\s*\(",
    r"(?:^|[^a-zA-Z_])exec\s*\(",
    # Boot code execution wrappers — even via subprocess.
    r"\bnasm\s+",
    r"\bobjdump\s+",
    r"\bqemu-system",
    r"\bchainloader",
    r"\brundll32\.exe\s+",
]


def _strip_string_literals_and_comments(source: str) -> str:
    """Strip Python string literals + comments from source so the
    forbidden-pattern gate doesn't fire on documentation / examples."""
    source = re.sub(r'"""[\s\S]*?"""', '""', source)
    source = re.sub(r"'''[\s\S]*?'''", "''", source)
    source = re.sub(r'"[^"\n]*"', '""', source)
    source = re.sub(r"'[^'\n]*'", "''", source)
    source = re.sub(r"#[^\n]*", "", source)
    return source


def test_mbr_vbr_no_bootcode_execution():
    """**Rule #36 central gate** — the MBR/VBR walker module MUST NOT
    contain ANY process-spawn primitive that could execute the parsed
    boot-sector x86 boot code.

    Scrubs string literals + comments first so documentation examples
    don't fire the gate. The actual CODE must contain ZERO matches
    for every forbidden pattern: subprocess.*, asyncio.create_subprocess_*,
    os.system / execvp / spawnvp, runpy, eval/exec function calls, OR
    boot-code execution wrappers (nasm / objdump / qemu-system /
    chainloader / rundll32).

    MBR + VBR are 512 bytes of x86 boot code that runs at Ring -2
    BEFORE any OS code. The walker treats sectors as DATA via SHA256
    hashing + byte-compares against signature tables — none of which
    transfer control to the boot code. The sectors surface as DATA in
    WindowsMbrVbrSector.sector_sha256 + Finding evidence; the walker
    never INVOKES them.
    """
    walker_source = _WALKER_MODULE.read_text()
    scrubbed = _strip_string_literals_and_comments(walker_source)

    for pattern in _FORBIDDEN_EXEC_PATTERNS:
        match = re.search(pattern, scrubbed)
        assert match is None, (
            f"mbr_vbr_walker.py contains forbidden pattern {pattern!r} "
            f"at offset {match.start()}: "
            f"{scrubbed[max(0, match.start()-30):match.end()+30]!r}. "
            "Rule #36 no-execute discipline violated — MBR/VBR are "
            "attacker-controlled x86 boot code and must NEVER be invoked."
        )


# ── Sector classification ──────────────────────────────────────────────────


def _make_mbr(boot_code: bytes = b"\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C") -> bytes:
    """Synthetic 512-byte MBR with canonical Windows 10 prefix + magic."""
    sector = bytearray(512)
    sector[0:len(boot_code)] = boot_code
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


def _make_ntfs_vbr() -> bytes:
    """Synthetic 512-byte NTFS VBR — JMP + NTFS at offset 3."""
    sector = bytearray(512)
    sector[0] = 0xEB
    sector[1] = 0x52
    sector[2] = 0x90
    sector[3:11] = b"NTFS    "
    # Boot code at offset 84.
    sector[84:90] = b"\xFA\x33\xC0\x8E\xD0\xBC"
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


def _make_fat32_vbr() -> bytes:
    """Synthetic 512-byte FAT32 VBR — JMP + FAT32 at offset 82."""
    sector = bytearray(512)
    sector[0] = 0xEB
    sector[1] = 0x58
    sector[2] = 0x90
    sector[82:90] = b"FAT32   "
    # Boot code at offset 90.
    sector[90:96] = b"\xFA\x33\xC9\x8E\xD1\xBC"
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


def _make_petya_mbr() -> bytes:
    """Synthetic Petya bootkit MBR — first bytes match Petya signature."""
    sector = bytearray(512)
    sector[0:7] = b"\xFA\x66\x31\xC0\x66\x89\xD8"
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


def test_classify_sector_kind_mbr():
    """MBR magic at 510 + offset 0 → 'mbr'."""
    assert classify_sector_kind(_make_mbr(), 0) == "mbr"


def test_classify_sector_kind_ntfs_vbr():
    """NTFS signature at offset 3 → 'vbr_ntfs'."""
    assert classify_sector_kind(_make_ntfs_vbr(), 1_048_576) == "vbr_ntfs"


def test_classify_sector_kind_fat32_vbr():
    """FAT32 signature at offset 82 → 'vbr_fat32'."""
    assert classify_sector_kind(_make_fat32_vbr(), 1_048_576) == "vbr_fat32"


def test_classify_sector_kind_short_sector():
    """Sector < 512 bytes → 'unknown'."""
    assert classify_sector_kind(b"\xEB\x90", 0) == "unknown"


def test_classify_sector_kind_no_magic_at_zero():
    """Magic absent at offset 510 with offset 0 → 'unknown'."""
    sector = bytearray(512)
    sector[0] = 0x90  # NOP, no recognizable signature
    assert classify_sector_kind(bytes(sector), 0) == "unknown"


def test_classify_sector_kind_magic_at_nonzero_offset():
    """Magic at offset 510 but offset != 0 + no FS signature → 'unknown'."""
    sector = bytearray(512)
    sector[510] = 0x55
    sector[511] = 0xAA
    sector[3:11] = b"WEIRDFS!"
    assert classify_sector_kind(bytes(sector), 1024) == "unknown"


def test_classify_sector_kind_exfat():
    """exFAT signature at offset 3 → 'vbr_exfat'."""
    sector = bytearray(512)
    sector[3:11] = b"EXFAT   "
    sector[510] = 0x55
    sector[511] = 0xAA
    assert classify_sector_kind(bytes(sector), 1024) == "vbr_exfat"


def test_classify_sector_kind_fat16():
    """FAT16 signature at offset 54 → 'vbr_fat16'."""
    sector = bytearray(512)
    sector[54:62] = b"FAT16   "
    sector[510] = 0x55
    sector[511] = 0xAA
    assert classify_sector_kind(bytes(sector), 1024) == "vbr_fat16"


# ── Bootcode signature matching ────────────────────────────────────────────


def test_match_bootcode_signature_windows_10_mbr():
    """Canonical Windows 10 MBR boot code → 'windows_10_mbr'."""
    assert match_bootcode_signature(_make_mbr(), "mbr") == "windows_10_mbr"


def test_match_bootcode_signature_unknown_kind():
    """Unknown sector kind → None (no signature to match)."""
    assert match_bootcode_signature(_make_mbr(), "unknown") is None


def test_match_bootcode_signature_grub2():
    """GRUB2 stage1 prefix → 'grub2_mbr'."""
    grub_mbr = bytearray(512)
    grub_mbr[0:3] = b"\xEB\x63\x90"
    grub_mbr[510] = 0x55
    grub_mbr[511] = 0xAA
    assert match_bootcode_signature(bytes(grub_mbr), "mbr") == "grub2_mbr"


def test_match_bootcode_signature_no_match():
    """Sector with no known prefix → None."""
    custom_mbr = bytearray(512)
    custom_mbr[0] = 0x42  # not a known starting byte
    custom_mbr[510] = 0x55
    custom_mbr[511] = 0xAA
    assert match_bootcode_signature(bytes(custom_mbr), "mbr") is None


def test_match_bootcode_signature_short_sector():
    """Short sector → None (defensive)."""
    assert match_bootcode_signature(b"\xFA\x33\xC0", "mbr") is None


# ── Bootkit signature matching ─────────────────────────────────────────────


def test_match_bootkit_signature_petya():
    """Petya bootkit prefix → 'petya_mbr'."""
    assert match_bootkit_signature(_make_petya_mbr()) == "petya_mbr"


def test_match_bootkit_signature_clean():
    """Clean Windows MBR → None (no bootkit match)."""
    assert match_bootkit_signature(_make_mbr()) is None


def test_match_bootkit_signature_tdl4():
    """TDL4 bootkit prefix → 'tdl4_mbr'."""
    tdl4 = bytearray(512)
    tdl4[0:7] = b"\xEB\x4D\x90\x4E\x54\x46\x53"
    tdl4[510] = 0x55
    tdl4[511] = 0xAA
    assert match_bootkit_signature(bytes(tdl4)) == "tdl4_mbr"


# ── Partition table parsing ────────────────────────────────────────────────


def test_parse_partition_table_single_ntfs_partition():
    """MBR with one NTFS partition at LBA 2048."""
    sector = bytearray(_make_mbr())
    # Partition 0: bootable, NTFS (0x07), LBA 2048, 1M sectors.
    sector[446] = 0x80  # bootable
    sector[446 + 4] = 0x07  # NTFS type
    sector[446 + 8 : 446 + 12] = (2048).to_bytes(4, "little")
    sector[446 + 12 : 446 + 16] = (1_000_000).to_bytes(4, "little")
    parts = parse_partition_table(bytes(sector))
    assert len(parts) == 1
    assert parts[0]["bootable"] == 0x80
    assert parts[0]["type"] == 0x07
    assert parts[0]["lba_start"] == 2048
    assert parts[0]["sector_count"] == 1_000_000


def test_parse_partition_table_empty():
    """MBR with all-zero partition table → empty list."""
    parts = parse_partition_table(_make_mbr())
    assert parts == []


def test_parse_partition_table_skips_zero_type():
    """Entries with type=0x00 are skipped (empty partitions)."""
    sector = bytearray(_make_mbr())
    # Partition 0: empty (type=0)
    # Partition 1: NTFS at LBA 1024
    off = 446 + 16
    sector[off + 4] = 0x07
    sector[off + 8 : off + 12] = (1024).to_bytes(4, "little")
    parts = parse_partition_table(bytes(sector))
    assert len(parts) == 1
    assert parts[0]["lba_start"] == 1024


def test_parse_partition_table_short_input():
    """Sector < 512 bytes → empty list."""
    assert parse_partition_table(b"\x00" * 100) == []


# ── Anomaly flags ──────────────────────────────────────────────────────────


def test_build_anomaly_flags_clean_windows_mbr():
    """Canonical Windows MBR → all anomaly flags False."""
    flags = build_anomaly_flags(sector=_make_mbr(), sector_kind="mbr")
    assert flags["is_mbr"] is True
    assert flags["is_vbr"] is False
    assert flags["non_standard_jmp"] is False  # 0xFA is CLI
    assert flags["non_zero_padding"] is False


def test_build_anomaly_flags_modified_mbr_padding():
    """MBR with non-zero bytes in 430..445 → non_zero_padding=True."""
    sector = bytearray(_make_mbr())
    sector[440] = 0x42  # Inject byte into trailing boot-code region.
    flags = build_anomaly_flags(sector=bytes(sector), sector_kind="mbr")
    assert flags["non_zero_padding"] is True


def test_build_anomaly_flags_non_standard_jmp():
    """MBR with unusual first byte → non_standard_jmp=True."""
    sector = bytearray(_make_mbr())
    sector[0] = 0x42  # Not 0xEB/0xE9/0xFA/0x33/0xB8/0x90.
    flags = build_anomaly_flags(sector=bytes(sector), sector_kind="mbr")
    assert flags["non_standard_jmp"] is True


def test_build_anomaly_flags_disk_signature_set():
    """MBR with non-zero disk signature → non_zero_disk_signature=True."""
    sector = bytearray(_make_mbr())
    sector[440:444] = b"\xDE\xAD\xBE\xEF"
    flags = build_anomaly_flags(sector=bytes(sector), sector_kind="mbr")
    assert flags["non_zero_disk_signature"] is True


def test_build_anomaly_flags_vbr_kind():
    """VBR sector → is_vbr=True, is_mbr=False."""
    flags = build_anomaly_flags(
        sector=_make_ntfs_vbr(), sector_kind="vbr_ntfs"
    )
    assert flags["is_mbr"] is False
    assert flags["is_vbr"] is True


def test_build_anomaly_flags_unexpected_partition_table():
    """MBR with both GPT-protective AND non-GPT entries →
    unexpected_partition_table=True."""
    sector = bytearray(_make_mbr())
    # Partition 0: GPT protective (0xEE)
    sector[446 + 4] = 0xEE
    # Partition 1: NTFS (0x07) — mixing is suspicious.
    sector[446 + 16 + 4] = 0x07
    flags = build_anomaly_flags(sector=bytes(sector), sector_kind="mbr")
    assert flags["unexpected_partition_table"] is True


# ── Fingerprint computation ────────────────────────────────────────────────


def test_compute_sector_fingerprint_deterministic():
    """Same inputs → same fingerprint."""
    fp1 = compute_sector_fingerprint(
        file_path="windows.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="a" * 64,
    )
    fp2 = compute_sector_fingerprint(
        file_path="windows.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="a" * 64,
    )
    assert fp1 == fp2
    assert len(fp1) == 64


def test_compute_sector_fingerprint_path_case_insensitive():
    """file_path differs in case → same fingerprint (lowercase
    normalisation)."""
    fp_upper = compute_sector_fingerprint(
        file_path="WINDOWS.IMG",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="b" * 64,
    )
    fp_lower = compute_sector_fingerprint(
        file_path="windows.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="b" * 64,
    )
    assert fp_upper == fp_lower


def test_compute_sector_fingerprint_changes_on_offset():
    """Different sector_offset → different fingerprint."""
    fp_mbr = compute_sector_fingerprint(
        file_path="x.img",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="c" * 64,
    )
    fp_vbr = compute_sector_fingerprint(
        file_path="x.img",
        sector_offset=1_048_576,
        sector_kind="mbr",
        sector_sha256="c" * 64,
    )
    assert fp_mbr != fp_vbr


# ── walk_disk_images ───────────────────────────────────────────────────────


def test_walk_disk_images_finds_img_extension():
    """Files with .img extension >= 512 bytes are found."""
    with tempfile.TemporaryDirectory() as td:
        img = Path(td) / "windows.img"
        img.write_bytes(_make_mbr())
        results = walk_disk_images([td])
        assert len(results) == 1
        assert results[0].endswith("windows.img")


def test_walk_disk_images_rejects_too_small():
    """Files < 512 bytes are rejected (can't host an MBR)."""
    with tempfile.TemporaryDirectory() as td:
        small = Path(td) / "tiny.img"
        small.write_bytes(b"X" * 100)
        results = walk_disk_images([td])
        assert results == []


def test_walk_disk_images_skips_unknown_extension():
    """Files without .img/.raw/.vhd/etc extension are skipped."""
    with tempfile.TemporaryDirectory() as td:
        random = Path(td) / "ignore.txt"
        random.write_bytes(b"X" * 1024)
        results = walk_disk_images([td])
        assert results == []


def test_walk_disk_images_multiple_extensions():
    """Multiple disk image files across extensions all found."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "a.img").write_bytes(b"X" * 1024)
        (Path(td) / "b.raw").write_bytes(b"X" * 1024)
        (Path(td) / "c.vhd").write_bytes(b"X" * 1024)
        results = walk_disk_images([td])
        assert len(results) == 3


def test_walk_disk_images_nonexistent_root():
    """Nonexistent root → empty list (defensive)."""
    assert walk_disk_images(["/nonexistent/path"]) == []


# ── Inner orchestrator (_do_mbr_vbr_walk) — Rule #35b live canaries ────────


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_no_firmware():
    """firmware_id that doesn't exist → empty result."""
    async with make_live_db() as db:
        result = await _do_mbr_vbr_walk(db, uuid.uuid4())
        assert result["images_scanned"] == 0
        assert result["sectors_persisted"] == 0
        assert result["per_root"] == []


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_no_roots():
    """Firmware with no extracted_path → empty result."""
    async with make_live_db() as db:
        project = Project(name="θ.E.C no-roots canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "n")
        db.add(firmware)
        await db.flush()

        result = await _do_mbr_vbr_walk(db, firmware.id)
        assert result["images_scanned"] == 0


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_no_disk_images():
    """Detection root with no disk image files → empty result.

    Per θ.C postmortem #1: ``get_detection_roots`` returns ``[td,
    '/tmp']`` for tempdir-based firmware fixtures (multi-root), which
    would pick up unrelated disk images under /tmp. Force a
    single-root layout via patch."""
    with tempfile.TemporaryDirectory() as td:
        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.E.C no-images canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "z")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.mbr_vbr_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_mbr_vbr_walk(db, firmware.id)
            assert result["images_scanned"] == 0


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_clean_windows_mbr():
    """Live canary — walk a real disk image with a clean Windows MBR
    + one NTFS VBR. Verify the walker produces a 2-row
    WindowsMbrVbrSector aggregate (MBR + VBR)."""
    with tempfile.TemporaryDirectory() as td:
        # Build a synthetic disk: MBR at offset 0 + NTFS VBR at LBA 2048.
        mbr = bytearray(_make_mbr())
        mbr[446] = 0x80
        mbr[446 + 4] = 0x07  # NTFS type
        mbr[446 + 8 : 446 + 12] = (2048).to_bytes(4, "little")
        mbr[446 + 12 : 446 + 16] = (1_000_000).to_bytes(4, "little")

        # Disk file: MBR + zeros to LBA 2048 + NTFS VBR.
        vbr_offset = 2048 * 512
        disk = bytearray(vbr_offset + 512)
        disk[0:512] = bytes(mbr)
        disk[vbr_offset : vbr_offset + 512] = _make_ntfs_vbr()

        img_path = Path(td) / "windows.img"
        img_path.write_bytes(bytes(disk))

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.E.C clean-MBR canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "w")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.mbr_vbr_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_mbr_vbr_walk(db, firmware.id)
            assert result["images_scanned"] == 1
            assert result["sectors_persisted"] == 2  # MBR + 1 VBR
            assert result["mbr_count"] == 1
            assert result["vbr_count"] == 1
            assert result["known_good_match_count"] >= 1  # Windows 10 MBR
            assert result["known_bootkit_match_count"] == 0

            rows = (
                await db.execute(
                    select(WindowsMbrVbrSector).where(
                        WindowsMbrVbrSector.firmware_id == firmware.id
                    )
                )
            ).scalars().all()
            assert len(rows) == 2
            mbr_row = next(r for r in rows if r.sector_kind == "mbr")
            vbr_row = next(
                r for r in rows if r.sector_kind == "vbr_ntfs"
            )
            assert mbr_row.sector_offset == 0
            assert mbr_row.bootcode_signature_match == "windows_10_mbr"
            assert mbr_row.known_bootkit_match is None
            assert vbr_row.sector_offset == vbr_offset
            assert vbr_row.known_bootkit_match is None
            assert mbr_row.fingerprint_sha256 is not None
            assert vbr_row.fingerprint_sha256 is not None


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_petya_bootkit():
    """Live canary — walk a disk image with the Petya bootkit MBR.
    Verify the walker flags known_bootkit_match='petya_mbr'."""
    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "infected.img"
        img_path.write_bytes(_make_petya_mbr())

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.E.C petya-bootkit canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "p")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.mbr_vbr_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_mbr_vbr_walk(db, firmware.id)
            assert result["sectors_persisted"] == 1  # Just MBR
            assert result["known_bootkit_match_count"] == 1

            r = (
                await db.execute(
                    select(WindowsMbrVbrSector).where(
                        WindowsMbrVbrSector.firmware_id == firmware.id
                    )
                )
            ).scalar_one()
            assert r.sector_kind == "mbr"
            assert r.known_bootkit_match == "petya_mbr"
            assert r.bootcode_signature_match is None


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_unreadable_image():
    """Live canary — image file that's exactly 0 bytes is skipped via
    the min-size gate, so no row is persisted."""
    with tempfile.TemporaryDirectory() as td:
        small = Path(td) / "broken.img"
        small.write_bytes(b"")  # 0-byte file → rejected by min-size gate

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.E.C broken-image canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "b")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.mbr_vbr_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_mbr_vbr_walk(db, firmware.id)
            # 0-byte image rejected at walk_disk_images
            # (min-size 512 bytes); no rows persisted.
            assert result["images_scanned"] == 0
            assert result["sectors_persisted"] == 0


@pytest.mark.asyncio
async def test_do_mbr_vbr_walk_no_mbr_magic():
    """Live canary — image file with no valid MBR magic. Walker still
    persists 1 'unknown' row at offset 0 (so operators see the file
    was scanned)."""
    with tempfile.TemporaryDirectory() as td:
        # Build a 512-byte sector with no MBR magic.
        broken = bytearray(512)
        broken[0:4] = b"GARB"  # Not a known MBR shape.
        # No magic at 510/511.

        img_path = Path(td) / "nonbootable.img"
        img_path.write_bytes(bytes(broken))

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.E.C no-magic canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "u")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.mbr_vbr_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_mbr_vbr_walk(db, firmware.id)
            assert result["images_scanned"] == 1
            # Unknown sector still persisted for operator visibility.
            assert result["sectors_persisted"] == 1
            assert result["mbr_count"] == 0  # Not classified as MBR

            r = (
                await db.execute(
                    select(WindowsMbrVbrSector).where(
                        WindowsMbrVbrSector.firmware_id == firmware.id
                    )
                )
            ).scalar_one()
            assert r.sector_kind == "unknown"
            assert r.sector_offset == 0
