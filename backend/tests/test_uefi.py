"""Tests for UEFI firmware classification and PE32+ security scanning."""

import struct
from pathlib import Path

from app.workers.unpack import classify_firmware
from app.workers.unpack_common import (
    _EFI_CAPSULE_GUID,
    _FVH_MAGIC,
    _IFD_SIGNATURE,
    _is_uefi_content,
    _is_uefi_firmware,
)

# ---------------------------------------------------------------------------
# classify_firmware() — UEFI detection
# ---------------------------------------------------------------------------


class TestClassifyFirmwareUefi:
    """Test classify_firmware() recognises UEFI/BIOS firmware images."""

    def test_ifd_signature_at_offset_0x10(self, tmp_path: Path):
        """A file with Intel Flash Descriptor (0x5AA5F00F) at offset 0x10 is uefi_firmware."""
        data = bytearray(256)
        data[0x10:0x14] = _IFD_SIGNATURE
        fw = tmp_path / "bios.bin"
        fw.write_bytes(bytes(data))
        assert classify_firmware(str(fw)) == "uefi_firmware"

    def test_fvh_magic_in_first_64kb(self, tmp_path: Path):
        """A file with _FVH magic within the first 64KB is uefi_firmware."""
        # Place _FVH at offset 0x8000 (well within 64KB)
        data = bytearray(0x8010)
        data[0x8000:0x8004] = _FVH_MAGIC
        fw = tmp_path / "bios.fd"
        fw.write_bytes(bytes(data))
        assert classify_firmware(str(fw)) == "uefi_firmware"

    def test_rom_file_in_size_range(self, tmp_path: Path):
        """A .ROM file between 4MB and 32MB classifies as uefi_firmware."""
        fw = tmp_path / "bios.rom"
        # 4MB of zeros — no magic bytes, but extension + size triggers detection
        fw.write_bytes(b"\x00" * (4 * 1024 * 1024))
        assert classify_firmware(str(fw)) == "uefi_firmware"

    def test_cap_file_in_size_range(self, tmp_path: Path):
        """A .CAP file in the valid size range classifies as uefi_firmware."""
        fw = tmp_path / "update.cap"
        fw.write_bytes(b"\x00" * (8 * 1024 * 1024))
        assert classify_firmware(str(fw)) == "uefi_firmware"

    def test_small_txt_not_uefi(self, tmp_path: Path):
        """A small .txt file does NOT classify as uefi_firmware."""
        txt = tmp_path / "readme.txt"
        txt.write_bytes(b"Hello, world!\n")
        assert classify_firmware(str(txt)) != "uefi_firmware"

    def test_elf_binary_not_uefi(self, tmp_path: Path):
        """An ELF binary classifies as elf_binary, not uefi_firmware."""
        elf = tmp_path / "program"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 128)
        assert classify_firmware(str(elf)) == "elf_binary"

    def test_efi_capsule_guid_at_offset_0(self, tmp_path: Path):
        """A file starting with the EFI capsule GUID classifies as uefi_firmware."""
        data = _EFI_CAPSULE_GUID + b"\x00" * 240
        fw = tmp_path / "capsule.bin"
        fw.write_bytes(data)
        assert classify_firmware(str(fw)) == "uefi_firmware"

    def test_rom_too_small_not_uefi(self, tmp_path: Path):
        """A tiny .ROM file (under 2MB) without UEFI signatures is not uefi_firmware."""
        fw = tmp_path / "tiny.rom"
        fw.write_bytes(b"\x00" * 1024)
        assert classify_firmware(str(fw)) != "uefi_firmware"


# ---------------------------------------------------------------------------
# _is_uefi_content() — raw bytes detection
# ---------------------------------------------------------------------------


class TestIsUefiContent:
    """Test _is_uefi_content() identifies UEFI signatures in raw data."""

    def test_efi_capsule_guid(self):
        """EFI capsule GUID at offset 0 is detected."""
        data = _EFI_CAPSULE_GUID + b"\x00" * 64
        assert _is_uefi_content(data) is True

    def test_ifd_signature_at_offset_0x10(self):
        """Intel Flash Descriptor at offset 0x10 is detected."""
        data = bytearray(64)
        data[0x10:0x14] = _IFD_SIGNATURE
        assert _is_uefi_content(bytes(data)) is True

    def test_fvh_magic_in_first_4kb(self):
        """_FVH magic within the first 4KB is detected."""
        data = bytearray(4096)
        data[2048:2052] = _FVH_MAGIC
        assert _is_uefi_content(bytes(data)) is True

    def test_random_data_not_uefi(self):
        """Random data without any UEFI signatures returns False."""
        import os as _os
        data = _os.urandom(4096)
        # Ensure we didn't randomly generate a match (astronomically unlikely)
        assert _is_uefi_content(data) is False or _FVH_MAGIC in data[:4096]

    def test_too_short_data(self):
        """Data shorter than 32 bytes returns False."""
        assert _is_uefi_content(b"\x00" * 16) is False
        assert _is_uefi_content(b"") is False


# ---------------------------------------------------------------------------
# _is_uefi_firmware() — file-level detection
# ---------------------------------------------------------------------------


class TestIsUefiFirmware:
    """Test _is_uefi_firmware() with actual files."""

    def test_ifd_signature(self, tmp_path: Path):
        """File with IFD at offset 0x10 is detected."""
        data = bytearray(256)
        data[0x10:0x14] = _IFD_SIGNATURE
        fw = tmp_path / "ifd.bin"
        fw.write_bytes(bytes(data))
        magic = bytes(data[:16])
        assert _is_uefi_firmware(str(fw), magic) is True

    def test_fvh_in_first_64kb(self, tmp_path: Path):
        """File with _FVH in first 64KB is detected."""
        data = bytearray(65536)
        data[32768:32772] = _FVH_MAGIC
        fw = tmp_path / "fvh.bin"
        fw.write_bytes(bytes(data))
        magic = bytes(data[:16])
        assert _is_uefi_firmware(str(fw), magic) is True

    def test_fd_extension_correct_size(self, tmp_path: Path):
        """A .fd file in the 2-64MB range is detected by extension heuristic."""
        fw = tmp_path / "bios.fd"
        fw.write_bytes(b"\x00" * (4 * 1024 * 1024))
        magic = b"\x00" * 16
        assert _is_uefi_firmware(str(fw), magic) is True

    def test_bin_extension_wrong_size_no_magic(self, tmp_path: Path):
        """A .bin file outside size range without UEFI magic is not detected."""
        fw = tmp_path / "data.bin"
        fw.write_bytes(b"\x00" * 128)
        magic = b"\x00" * 16
        assert _is_uefi_firmware(str(fw), magic) is False


# ---------------------------------------------------------------------------
# PE32+ header parsing — inline security checks
# ---------------------------------------------------------------------------


def _build_pe32plus(
    dll_characteristics: int = 0,
    sections: list[tuple[str, int]] | None = None,
    machine: int = 0x8664,  # x86_64 by default
) -> bytes:
    """Build a minimal PE32+ binary with the given DllCharacteristics and sections.

    Parameters
    ----------
    dll_characteristics : int
        Value of DllCharacteristics in the optional header.
    sections : list of (name, characteristics) tuples
        Section headers to include.  Each entry is (section_name, section_flags).
    machine : int
        COFF machine type (default 0x8664 for AMD64).

    Returns
    -------
    bytes
        A minimal PE32+ image (just headers, no actual code/data).
    """
    if sections is None:
        sections = [(".text", 0x60000020)]  # readable + executable + code

    num_sections = len(sections)
    pe_offset = 0x80  # Standard PE offset for small files

    # DOS header (64 bytes minimum)
    dos = bytearray(pe_offset)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    size_of_optional = 0x70  # Minimum PE32+ optional header size (112 bytes)
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, machine)           # Machine
    struct.pack_into("<H", coff, 2, num_sections)      # NumberOfSections
    struct.pack_into("<H", coff, 16, size_of_optional)  # SizeOfOptionalHeader

    # Optional header — PE32+ (magic 0x020B)
    opt = bytearray(size_of_optional)
    struct.pack_into("<H", opt, 0, 0x020B)  # Magic = PE32+

    # DllCharacteristics is at offset 0x46 from start of optional header for PE32+
    struct.pack_into("<H", opt, 0x46, dll_characteristics)

    # Section headers (40 bytes each)
    sec_data = bytearray()
    for name, chars in sections:
        sec = bytearray(40)
        name_bytes = name.encode("ascii")[:8]
        sec[0:len(name_bytes)] = name_bytes
        struct.pack_into("<I", sec, 36, chars)  # Characteristics
        sec_data.extend(sec)

    return bytes(dos + pe_sig + coff + opt + sec_data)


# DllCharacteristics flag constants (matching the endpoint code)
DYNAMIC_BASE = 0x0040
HIGH_ENTROPY_VA = 0x0020
NX_COMPAT = 0x0100

# Section characteristic flags
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_WRITE = 0x80000000
SCN_MEM_READ = 0x40000000


def _analyze_pe_findings(data: bytes) -> list[str]:
    """Replicate the PE32+ security scanning logic from the uefi-scan endpoint.

    Returns a list of finding tags like "missing_aslr", "missing_dep",
    "wxn_violation", "missing_high_entropy".
    """
    findings: list[str] = []

    if len(data) < 64:
        return findings

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 0x70 > len(data):
        return findings
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return findings

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    is_64bit = machine in (0x8664, 0xAA64)

    opt_offset = pe_offset + 0x18
    opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_pe32plus = opt_magic == 0x020B

    dll_char_offset = opt_offset + (0x46 if is_pe32plus else 0x42)
    if dll_char_offset + 2 > len(data):
        return findings
    dll_chars = struct.unpack_from("<H", data, dll_char_offset)[0]

    if not (dll_chars & DYNAMIC_BASE):
        findings.append("missing_aslr")
    if not (dll_chars & NX_COMPAT):
        findings.append("missing_dep")
    if is_64bit and not (dll_chars & HIGH_ENTROPY_VA):
        findings.append("missing_high_entropy")

    # W^X check on sections
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    size_opt = struct.unpack_from("<H", data, pe_offset + 0x14)[0]
    section_start = pe_offset + 0x18 + size_opt

    for i in range(min(num_sections, 20)):
        sec_offset = section_start + i * 40
        if sec_offset + 40 > len(data):
            break
        sec_chars = struct.unpack_from("<I", data, sec_offset + 36)[0]
        if (sec_chars & SCN_MEM_EXECUTE) and (sec_chars & SCN_MEM_WRITE):
            findings.append("wxn_violation")
            break  # One is enough

    return findings


class TestPe32PlusSecurityScanning:
    """Test PE32+ header parsing and security flag detection."""

    def test_detect_missing_aslr(self):
        """PE32+ without DYNAMIC_BASE flag triggers ASLR finding."""
        pe = _build_pe32plus(dll_characteristics=NX_COMPAT | HIGH_ENTROPY_VA)
        findings = _analyze_pe_findings(pe)
        assert "missing_aslr" in findings
        assert "missing_dep" not in findings

    def test_detect_missing_dep(self):
        """PE32+ without NX_COMPAT flag triggers DEP finding."""
        pe = _build_pe32plus(dll_characteristics=DYNAMIC_BASE | HIGH_ENTROPY_VA)
        findings = _analyze_pe_findings(pe)
        assert "missing_dep" in findings
        assert "missing_aslr" not in findings

    def test_detect_wxn_violation(self):
        """PE32+ with a writable+executable section triggers W^X finding."""
        pe = _build_pe32plus(
            dll_characteristics=DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA,
            sections=[
                (".text", SCN_MEM_READ | SCN_MEM_EXECUTE),
                (".rwx", SCN_MEM_READ | SCN_MEM_WRITE | SCN_MEM_EXECUTE),
            ],
        )
        findings = _analyze_pe_findings(pe)
        assert "wxn_violation" in findings
        assert "missing_aslr" not in findings
        assert "missing_dep" not in findings

    def test_all_flags_set_no_findings(self):
        """PE32+ with all security flags and clean sections produces no findings."""
        pe = _build_pe32plus(
            dll_characteristics=DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA,
            sections=[
                (".text", SCN_MEM_READ | SCN_MEM_EXECUTE),
                (".data", SCN_MEM_READ | SCN_MEM_WRITE),
                (".rdata", SCN_MEM_READ),
            ],
        )
        findings = _analyze_pe_findings(pe)
        assert findings == []

    def test_no_flags_set_all_findings(self):
        """PE32+ with zero DllCharacteristics triggers all applicable findings."""
        pe = _build_pe32plus(dll_characteristics=0, machine=0x8664)
        findings = _analyze_pe_findings(pe)
        assert "missing_aslr" in findings
        assert "missing_dep" in findings
        assert "missing_high_entropy" in findings

    def test_high_entropy_only_for_64bit(self):
        """HIGH_ENTROPY_VA check applies only to 64-bit (x86_64, AArch64)."""
        # 32-bit i386 — no high entropy finding even without the flag
        pe32 = _build_pe32plus(
            dll_characteristics=DYNAMIC_BASE | NX_COMPAT,
            machine=0x014C,  # i386
        )
        findings = _analyze_pe_findings(pe32)
        assert "missing_high_entropy" not in findings

        # 64-bit AArch64 — high entropy finding expected
        pe64 = _build_pe32plus(
            dll_characteristics=DYNAMIC_BASE | NX_COMPAT,
            machine=0xAA64,  # AArch64
        )
        findings = _analyze_pe_findings(pe64)
        assert "missing_high_entropy" in findings

    def test_truncated_header_no_crash(self):
        """Truncated data does not crash the parser — returns empty findings."""
        assert _analyze_pe_findings(b"MZ" + b"\x00" * 10) == []
        assert _analyze_pe_findings(b"") == []

    def test_invalid_pe_signature_no_crash(self):
        """Data with valid DOS header but bad PE signature returns no findings."""
        data = bytearray(256)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"XX\x00\x00"  # Not PE\x00\x00
        assert _analyze_pe_findings(bytes(data)) == []

    def test_clean_sections_no_wxn(self):
        """Sections that are only writable OR only executable do not trigger W^X."""
        pe = _build_pe32plus(
            dll_characteristics=DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA,
            sections=[
                (".text", SCN_MEM_READ | SCN_MEM_EXECUTE),
                (".data", SCN_MEM_READ | SCN_MEM_WRITE),
            ],
        )
        findings = _analyze_pe_findings(pe)
        assert "wxn_violation" not in findings
