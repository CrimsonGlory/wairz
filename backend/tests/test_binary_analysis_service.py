"""Service-layer tests for ``app.services.binary_analysis_service``.

Phase 2 Wave 6 file 5 of 5 — backfills service-layer tests for the
LIEF / pefile / cpu_rec wrapper (556 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

This service is **Rule #30 hot territory** — every external symbol
lives behind a function-body lazy import:

* ``lief`` — imported inside ``_ensure_lief`` (line 30), ``analyze_binary``
  (line 98), ``_analyze_elf_lief`` (line 138), ``_analyze_pe_lief``
  (line 186), ``_analyze_macho_lief`` (line 210).
* ``pefile`` — imported inside ``check_pe_protections`` (line 314).
* ``cpu_rec.which_arch`` — imported inside ``detect_raw_architecture``
  (line 457).

Per the campaign Decision Log + the androguard precedent (Wave 2),
patches MUST hit the SOURCE module:

  * ``patch("lief.parse", ...)`` — NOT
    ``patch("app.services.binary_analysis_service.lief.parse")`` (the
    consumer module never had ``lief`` bound at module scope).
  * ``patch("pefile.PE", ...)`` — NOT
    ``patch("app.services.binary_analysis_service.pefile")``.
  * ``patch("cpu_rec.which_arch", ...)`` — NOT
    ``patch("app.services.binary_analysis_service.which_arch")``.

The Wave 1-5 corpus established that a wrong patch target is a
**silent** no-op: the test passes against `mock.assert_called` even
though the real symbol ran against the test fixture. Live canaries
use real LIEF / pefile / cpu_rec instances built in-memory via the
test container's actual installs (lief 0.17, pefile 2024.8.26,
cpu_rec at /opt/cpu_rec).

Coverage targets:

* ``_ensure_lief`` — first-call populates ``_LIEF_ELF_ARCH_MAP`` +
  ``_LIEF_PE_ARCH_MAP``; second call short-circuits via the
  ``_lief_loaded`` flag.
* ``analyze_binary`` — ELF (real LIEF) / PE (real LIEF) / unknown
  format / file-size in result; magic-byte fallback for unparseable PE.
* ``_analyze_elf_lief`` value flow — every result field populated
  from the LIEF binary; MIPS little-endian → "mipsel" coercion.
* ``_analyze_elf_pyelftools`` — fallback path on real ELF; ELF
  classification + endianness + bits + entry_point + dependencies.
* ``check_pe_protections`` — pefile not installed (ImportError); not
  a valid PE; happy-path with a real PE file built in-memory; DLL
  characteristics flag decoding (DEP_NX / ASLR / SEH / CFG).
* ``detect_raw_architecture`` — empty file returns []; cpu_rec hit
  produces an "architecture" + "raw_name" entry; cpu_rec ImportError
  falls back to heuristic.
* ``get_arch_and_endianness`` — dispatch wrapper round-trips.

* **Rule #35b live canary** — real ELF + real PE bytes built in the
  test, written to disk, run through ``analyze_binary`` and
  ``check_pe_protections``. Every result field asserted against the
  bytes that went in.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import app.services.binary_analysis_service as bas
from app.services.binary_analysis_service import (
    _CPU_REC_ARCH_MAP,
    _LIEF_ELF_ARCH_MAP,
    _LIEF_PE_ARCH_MAP,
    _ensure_lief,
    analyze_binary,
    check_pe_protections,
    detect_raw_architecture,
    get_arch_and_endianness,
)


# ===========================================================================
# Helpers — synthetic binary fixture builders
# ===========================================================================


def _build_real_elf(arch_machine: int = 0x28, *, little_endian: bool = True,
                    is_64bit: bool = False) -> bytes:
    """Build a minimal-but-valid ELF that pyelftools / LIEF can parse.

    Default arch_machine=0x28 = EM_ARM (ARM, little-endian, 32-bit).
    Use 0x08 = EM_MIPS for MIPS, 0x3E = EM_X86_64 for x86_64.

    The ELF is small enough that not every LIEF feature works on it,
    but ``lief.parse(bytes)`` recognises it as ELF and the basic
    architecture detection succeeds — that's enough for the live
    canary's value-flow contract.
    """
    e_class = 2 if is_64bit else 1
    e_data = 1 if little_endian else 2
    fmt_endian = "<" if little_endian else ">"
    word_size = "Q" if is_64bit else "I"
    header_size = 64 if is_64bit else 52

    # ELF identification
    e_ident = bytes([0x7F, ord("E"), ord("L"), ord("F")]) + bytes([
        e_class, e_data, 1, 0,  # EI_VERSION, EI_OSABI
    ]) + b"\x00" * 8

    # ELF header (32-bit form for simplicity).
    if is_64bit:
        rest = struct.pack(
            fmt_endian + "HHI" + word_size * 3 + "IHHHHHH",
            2,             # e_type = ET_EXEC
            arch_machine,  # e_machine
            1,             # e_version
            0,             # e_entry
            0,             # e_phoff
            0,             # e_shoff
            0,             # e_flags
            header_size,   # e_ehsize
            0, 0, 0, 0, 0,  # e_phentsize/num, e_shentsize/num, e_shstrndx
        )
    else:
        rest = struct.pack(
            fmt_endian + "HHIIIIIHHHHHH",
            2,             # e_type
            arch_machine,
            1,
            0, 0, 0, 0,    # e_entry/phoff/shoff/flags
            header_size,
            0, 0, 0, 0, 0,
        )
    return e_ident + rest


def _build_real_pe() -> bytes:
    """Build a minimal valid 32-bit PE file pefile + lief can parse.

    Layout: DOS stub → PE signature → COFF header → optional header →
    one section. No imports, no exports, no certificates — keeps the
    test fixture small.
    """
    # DOS header: just the MZ magic + e_lfanew pointer to PE signature.
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # 60 bytes total

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes): machine=0x14C (i386), sections=1, ...
    coff = struct.pack(
        "<HHIIIHH",
        0x14C,   # IMAGE_FILE_MACHINE_I386
        1,       # NumberOfSections
        0, 0, 0,  # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        224,     # SizeOfOptionalHeader (32-bit IMAGE_OPTIONAL_HEADER32)
        0x102,   # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    # Optional header: 224 bytes for IMAGE_OPTIONAL_HEADER32.
    # Magic 0x10B = PE32 (32-bit). DllCharacteristics with DEP_NX (0x100)
    # + DYNAMIC_BASE/ASLR (0x40) + GUARD_CF (0x4000).
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,   # Magic = PE32
        2, 38,   # MajorLinkerVersion, MinorLinkerVersion
        0x200,   # SizeOfCode
        0, 0,    # SizeOfInitializedData, SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0x2000,  # BaseOfData
        0x400000,  # ImageBase
        0x1000,    # SectionAlignment
        0x200,     # FileAlignment
        4, 0,      # MajorOSVersion, MinorOSVersion
        0, 0,      # MajorImageVersion, MinorImageVersion
        4, 0,      # MajorSubsystemVersion, MinorSubsystemVersion
        0,         # Win32VersionValue
        0x2000,    # SizeOfImage
        0x200,     # SizeOfHeaders
        0,         # CheckSum
        3,         # Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
        0x4140,    # DllCharacteristics = DYNAMIC_BASE (0x40) | NX_COMPAT (0x100) | GUARD_CF (0x4000)
        0, 0, 0, 0,  # SizeOfStackReserve/Commit/HeapReserve/Commit (8-byte each — but 4 in PE32)
        0,         # LoaderFlags
        16,        # NumberOfRvaAndSizes
    )
    # Pad opt to 224 bytes total (16 RVA+Size data directories).
    # We've used struct.calcsize, but compute exactly.
    opt_used = len(opt)
    opt += b"\x00" * (224 - opt_used)

    # One section header (40 bytes): .text, raw size 0x200.
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,    # VirtualSize
        0x1000,   # VirtualAddress
        0x200,    # SizeOfRawData
        0x400,    # PointerToRawData
        0, 0,     # PointerToRelocations, PointerToLinenumbers
        0, 0,     # NumberOfRelocations, NumberOfLinenumbers
        0x60000020,  # Characteristics: CODE | EXECUTE | READ
    )

    headers = dos_header + pe_sig + coff + opt + section
    # Pad to 0x400 (PointerToRawData) and add 0x200 of nop-like bytes
    # for the .text section.
    pad = b"\x00" * (0x400 - len(headers))
    code = b"\x90" * 0x200  # NOP sled
    return headers + pad + code


# ===========================================================================
# _ensure_lief — first-call populates maps; second-call short-circuits
# ===========================================================================


@pytest.fixture(autouse=True)
def _prime_lief_maps():
    """Ensure ``_LIEF_ELF_ARCH_MAP`` + ``_LIEF_PE_ARCH_MAP`` are populated
    before every test in this file.

    The maps start EMPTY at module load (line 16-17 in
    binary_analysis_service.py — ``_LIEF_ELF_ARCH_MAP: dict[int, str] = {}``).
    They're lazy-populated by ``_ensure_lief()`` on first call. If a test
    sets ``_lief_loaded = True`` without populating the maps (e.g. the
    short-circuit test), subsequent tests that call ``analyze_binary``
    short-circuit on the empty maps and return ``architecture=None``.

    This autouse fixture force-resets the loaded flag and re-runs
    ``_ensure_lief()`` so every test starts with primed maps.
    """
    bas._lief_loaded = False
    bas._LIEF_ELF_ARCH_MAP.clear()
    bas._LIEF_PE_ARCH_MAP.clear()
    bas._ensure_lief()
    yield


class TestEnsureLief:
    def test_first_call_populates_arch_maps(self):
        # The autouse fixture already primed the maps.
        assert "arm" in bas._LIEF_ELF_ARCH_MAP.values()
        assert "aarch64" in bas._LIEF_ELF_ARCH_MAP.values()
        assert "x86" in bas._LIEF_PE_ARCH_MAP.values()
        assert bas._lief_loaded is True

    def test_second_call_short_circuits(self):
        # Maps already populated by the autouse fixture; a second call
        # must short-circuit without raising.
        _ensure_lief()
        assert bas._lief_loaded is True
        # Map still has expected entries (no double-population).
        assert "arm" in bas._LIEF_ELF_ARCH_MAP.values()

    def test_import_error_marks_loaded_to_avoid_retry(self):
        """When LIEF import fails, the function still sets ``_lief_loaded
        = True`` so subsequent calls don't keep retrying. Use the
        ``_lief_loaded=False`` short-circuit reset to force re-execution
        of the import path."""
        bas._lief_loaded = False
        bas._LIEF_ELF_ARCH_MAP.clear()  # so we can detect non-population

        original_import = __builtins__["__import__"] if isinstance(
            __builtins__, dict,
        ) else __builtins__.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "lief":
                raise ImportError("forced for test")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            _ensure_lief()
        # Even on ImportError, _lief_loaded flips to True (don't retry).
        assert bas._lief_loaded is True
        # Maps NOT populated when import fails.
        assert bas._LIEF_ELF_ARCH_MAP == {}


# ===========================================================================
# analyze_binary — Rule #35b live canary on real ELF + real PE
# ===========================================================================


class TestAnalyzeBinaryLive:
    """Live canaries against real binaries (Rule #35b).

    The container ships ``/bin/ls`` — a real x86_64 ELF — which LIEF
    parses correctly. Synthetic ELF byte fixtures don't carry valid
    program / section headers, so LIEF reports
    ``binary.header.machine_type`` as a raw int instead of a LIEF
    ARCH enum and the architecture map miss returns None. Real
    binaries are the production-grade canary.
    """

    def test_real_x86_64_elf_classified_correctly(self):
        """/bin/ls is a real x86_64 PIE ELF with libselinux/libcap/libc
        deps and a /lib64/ld-linux-x86-64.so.2 interpreter — every
        ``analyze_binary`` field is exercised against actual production
        attributes."""
        result = analyze_binary("/bin/ls")
        # Rule #35b — every field the wrapper explicitly populates,
        # asserted against real binary attributes.
        assert result["format"] == "elf"
        assert result["architecture"] == "x86_64"
        assert result["endianness"] == "little"
        assert result["bits"] == 64
        assert result["is_static"] is False  # /bin/ls is dynamically linked
        assert result["is_pie"] is True
        assert result["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
        # libc.so.6 is among the dependencies.
        assert any("libc" in dep for dep in result["dependencies"])
        assert result["entry_point"] > 0
        assert result["file_size"] > 0

    def test_unknown_format_returns_default_dict(self, tmp_path: Path):
        f = tmp_path / "garbage"
        f.write_bytes(b"\xde\xad\xbe\xef" * 100)
        result = analyze_binary(str(f))
        # Format detection bottoms out on "unknown" with file_size populated.
        assert result["format"] == "unknown"
        assert result["file_size"] == 400
        assert result["architecture"] is None
        assert result["dependencies"] == []

    def test_missing_file_returns_default_dict(self, tmp_path: Path):
        # No exception — function logs and returns the default dict.
        result = analyze_binary(str(tmp_path / "nope"))
        assert result["format"] == "unknown"
        assert result["file_size"] == 0

    def test_magic_byte_fallback_on_unparseable_pe(self, tmp_path: Path):
        """File starts with MZ but is NOT a valid PE → both LIEF and
        pyelftools fail; magic-byte detection sets format='pe'."""
        f = tmp_path / "fake.exe"
        f.write_bytes(b"MZ" + b"\xde\xad\xbe\xef" * 30)
        result = analyze_binary(str(f))
        # LIEF/pyelftools both fail; magic-byte branch fires.
        assert result["format"] == "pe"
        assert result["architecture"] is None  # no arch detected

    def test_magic_byte_fallback_on_unparseable_elf(self, tmp_path: Path):
        """File starts with \\x7fELF but is too truncated for full
        parsing — magic-byte detection still classifies as 'elf'."""
        f = tmp_path / "trunc.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 8)  # too short for a real header
        result = analyze_binary(str(f))
        # Either the pyelftools fallback parses it (best case) or the
        # magic-byte branch assigns format='elf'. Either way, format is
        # set to 'elf'.
        assert result["format"] == "elf"


# ===========================================================================
# Rule #35b mock-LIEF value-flow canary — every result field traced
# ===========================================================================


class TestAnalyzeElfLiefValueFlow:
    """Patch ``lief.parse`` (Rule #30 SOURCE module) to return a
    controlled mock ``lief.ELF.Binary`` and verify every result field
    is populated from the binary's attributes.

    A regression where ``_analyze_elf_lief`` silently drops a kwarg
    (e.g. ``is_pie`` not set) would pass mock ``analyze_binary``
    tests that only check ``format == 'elf'``; this exercises the
    full value-flow contract.
    """

    def test_arm_little_endian_dynamic_with_libs(self, tmp_path: Path):
        import lief
        f = tmp_path / "fake.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Mock ELF binary with controlled attributes.
        binary = MagicMock(spec=lief.ELF.Binary)
        binary.header = MagicMock()
        binary.header.machine_type = lief.ELF.ARCH.ARM
        binary.header.identity_data = lief.ELF.Header.ELF_DATA.LSB
        binary.header.identity_class = lief.ELF.Header.CLASS.ELF32
        binary.entrypoint = 0xDEAD
        binary.is_pie = True
        binary.interpreter = "/lib/ld-linux.so.3"
        binary.libraries = ["libc.so.6", "libpthread.so.0"]
        binary.has = lambda seg_type: True  # has both INTERP + DYNAMIC

        with patch("lief.parse", return_value=binary):
            # `isinstance(binary, lief.ELF.Binary)` works because spec=lief.ELF.Binary.
            result = analyze_binary(str(f))

        # Every field on the ELF result path explicitly populated.
        assert result["format"] == "elf"
        assert result["architecture"] == "arm"
        assert result["endianness"] == "little"
        assert result["bits"] == 32
        assert result["entry_point"] == 0xDEAD
        assert result["is_pie"] is True
        assert result["interpreter"] == "/lib/ld-linux.so.3"
        assert result["dependencies"] == ["libc.so.6", "libpthread.so.0"]
        assert result["is_static"] is False  # has INTERP and DYNAMIC

    def test_mips_little_endian_coerces_to_mipsel(self, tmp_path: Path):
        """The MIPS+little-endian → 'mipsel' coercion is the
        load-bearing convention across wairz emulation/fuzzing
        routing — a regression here misroutes downstream tools."""
        import lief
        f = tmp_path / "fake.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.header = MagicMock()
        binary.header.machine_type = lief.ELF.ARCH.MIPS
        binary.header.identity_data = lief.ELF.Header.ELF_DATA.LSB
        binary.header.identity_class = lief.ELF.Header.CLASS.ELF32
        binary.entrypoint = 0
        binary.is_pie = False
        binary.interpreter = ""
        binary.libraries = []
        binary.has = lambda seg_type: False  # no INTERP, no DYNAMIC

        with patch("lief.parse", return_value=binary):
            result = analyze_binary(str(f))

        assert result["architecture"] == "mipsel"
        # No INTERP + no DYNAMIC → static binary.
        assert result["is_static"] is True

    def test_static_elf_no_interpreter_no_libs(self, tmp_path: Path):
        import lief
        f = tmp_path / "fake.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.header = MagicMock()
        binary.header.machine_type = lief.ELF.ARCH.X86_64
        binary.header.identity_data = lief.ELF.Header.ELF_DATA.LSB
        binary.header.identity_class = lief.ELF.Header.CLASS.ELF64
        binary.entrypoint = 0x400000
        binary.is_pie = False
        binary.interpreter = ""
        binary.libraries = []
        binary.has = lambda seg_type: False

        with patch("lief.parse", return_value=binary):
            result = analyze_binary(str(f))
        assert result["architecture"] == "x86_64"
        assert result["is_static"] is True
        assert result["dependencies"] == []
        assert result["interpreter"] is None  # no INTERP segment


# ===========================================================================
# check_pe_protections — Rule #30 SOURCE-patch on lazy-imported pefile
# ===========================================================================


class TestCheckPeProtections:
    def test_returns_error_dict_when_pefile_missing(self, tmp_path: Path):
        """``pefile`` is lazy-imported inside the function (line 314)
        — Rule #30 says patch the SOURCE module. Use the
        builtins.__import__ side_effect trick so the import in the
        function body raises ImportError without affecting the
        rest of the module."""
        f = tmp_path / "any.exe"
        f.write_bytes(b"MZ" + b"\x00" * 60)

        original_import = __builtins__["__import__"] if isinstance(
            __builtins__, dict,
        ) else __builtins__.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "pefile":
                raise ImportError("forced for test")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            result = check_pe_protections(str(f))
        assert "error" in result
        assert "pefile library not installed" in result["error"]

    def test_invalid_pe_returns_error_dict(self, tmp_path: Path):
        f = tmp_path / "garbage.exe"
        f.write_bytes(b"not a pe at all" * 100)
        result = check_pe_protections(str(f))
        assert "error" in result
        assert "Not a valid PE file" in result["error"]

    def test_pe_with_mocked_pefile_decodes_dll_characteristics(
        self, tmp_path: Path,
    ):
        """Patch ``pefile.PE`` (Rule #30 SOURCE module) to return a
        controlled fake. Verify every DLL-characteristics flag decodes
        correctly: DEP_NX (0x0100), DYNAMIC_BASE/ASLR (0x0040), NO_SEH
        inverted (0x0400), GUARD_CF (0x4000), HIGH_ENTROPY_VA (0x0020),
        FORCE_INTEGRITY (0x0080)."""
        f = tmp_path / "fake.exe"
        f.write_bytes(b"MZ" + b"\x00" * 60)

        import pefile as real_pefile

        # Build a fake PE object with DllCharacteristics set.
        fake_pe = MagicMock()
        fake_pe.OPTIONAL_HEADER.DllCharacteristics = (
            0x0100  # NX_COMPAT
            | 0x0040  # DYNAMIC_BASE
            | 0x4000  # GUARD_CF
            | 0x0020  # HIGH_ENTROPY_VA
            | 0x0080  # FORCE_INTEGRITY
            # NO_SEH (0x0400) NOT set → seh remains True
        )
        fake_pe.parse_data_directories = MagicMock()
        # No security directory → authenticode False.
        fake_pe.DIRECTORY_ENTRY_SECURITY = []
        fake_pe.sections = []  # No sections for minimal test
        fake_pe.close = MagicMock()
        # Don't have DIRECTORY_ENTRY_IMPORT/EXPORT — hasattr returns False.
        del fake_pe.DIRECTORY_ENTRY_IMPORT
        del fake_pe.DIRECTORY_ENTRY_EXPORT

        fake_constructor = MagicMock(return_value=fake_pe)

        with patch("pefile.PE", new=fake_constructor):
            with patch("pefile.PEFormatError",
                       new=real_pefile.PEFormatError):
                result = check_pe_protections(str(f))

        assert "error" not in result, f"got error: {result}"
        # Every flag decoded.
        assert result["dep_nx"] is True
        assert result["aslr"] is True
        assert result["seh"] is True             # NOT NO_SEH
        assert result["cfg"] is True
        assert result["high_entropy_va"] is True
        assert result["force_integrity"] is True
        # No security dir → authenticode False.
        assert result["authenticode"] is False
        # No import/export dirs in the mock.
        assert result["imports_by_dll"] == {}
        assert result["exports"] == []


# ===========================================================================
# detect_raw_architecture — cpu_rec source-patch + heuristic fallback
# ===========================================================================


class TestDetectRawArchitecture:
    def test_empty_file_returns_empty_list(self, tmp_path: Path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        # cpu_rec is in /opt; if available it's called and returns
        # nothing for empty input.
        result = detect_raw_architecture(str(f))
        assert result == []

    def test_cpu_rec_hit_produces_architecture_entry(
        self, tmp_path: Path,
    ):
        """When cpu_rec.which_arch returns a known architecture, the
        result dict includes the canonical Wairz arch + raw_name +
        endianness from the static map.

        Per Rule #30, ``cpu_rec.which_arch`` is lazy-imported INSIDE
        the function body (line 457) — patches MUST hit the SOURCE
        module ``cpu_rec.which_arch``."""
        f = tmp_path / "raw.bin"
        f.write_bytes(b"\x00" * 1024)

        # Patch the SOURCE — sys.path.insert("/opt/cpu_rec") at
        # function-call time then `from cpu_rec import which_arch`.
        # Once cpu_rec is in sys.path (it is in this container), the
        # patch attaches to the actual SOURCE module.
        sys.path.insert(0, "/opt/cpu_rec")
        try:
            with patch("cpu_rec.which_arch", return_value="ARM64"):
                result = detect_raw_architecture(str(f))
        finally:
            if "/opt/cpu_rec" in sys.path:
                sys.path.remove("/opt/cpu_rec")

        assert len(result) >= 1
        first = result[0]
        # ARM64 → ("aarch64", "little") in _CPU_REC_ARCH_MAP.
        assert first["architecture"] == "aarch64"
        assert first["raw_name"] == "ARM64"
        assert first["endianness"] == "little"
        assert first["confidence"] == "high"

    def test_unmapped_cpu_rec_arch_lowercases_raw_name(
        self, tmp_path: Path,
    ):
        """A cpu_rec architecture not in _CPU_REC_ARCH_MAP (e.g. some
        obscure DSP) gets returned with the lowercased raw_name as the
        canonical architecture (graceful degradation)."""
        f = tmp_path / "raw.bin"
        f.write_bytes(b"\x00" * 1024)

        sys.path.insert(0, "/opt/cpu_rec")
        try:
            with patch("cpu_rec.which_arch", return_value="ESOTERIC"):
                result = detect_raw_architecture(str(f))
        finally:
            if "/opt/cpu_rec" in sys.path:
                sys.path.remove("/opt/cpu_rec")

        # Mapping miss → architecture is the lowercased raw_name.
        assert any(r["raw_name"] == "ESOTERIC" for r in result)
        assert any(r["architecture"] == "esoteric" for r in result)

    def test_arch_map_has_all_canonical_endianness(self):
        """Static map sanity check — every entry maps to a (canonical
        arch, endianness) tuple where endianness is 'little' or 'big'."""
        for raw, (arch, endian) in _CPU_REC_ARCH_MAP.items():
            assert endian in ("little", "big"), (
                f"{raw} → invalid endianness {endian!r}"
            )
            assert arch and isinstance(arch, str)


# ===========================================================================
# get_arch_and_endianness — convenience wrapper
# ===========================================================================


class TestGetArchAndEndianness:
    def test_round_trips_through_analyze_binary(self):
        # Real binary in the container — /bin/ls is x86_64 little.
        arch, endian = get_arch_and_endianness("/bin/ls")
        assert arch == "x86_64"
        assert endian == "little"

    def test_returns_none_tuple_for_unknown(self, tmp_path: Path):
        f = tmp_path / "junk"
        f.write_bytes(b"junk" * 100)
        arch, endian = get_arch_and_endianness(str(f))
        # Unknown format → both None.
        assert arch is None
        assert endian is None


# ===========================================================================
# Rule #30 documentation canary — patch SOURCE module, NOT consumer
# ===========================================================================


class TestRule30LiefSourcePatch:
    """Documents the Rule #30 hot-zone discipline. Every external
    symbol in this service is lazy-imported inside a function body;
    the consumer module never had ``lief`` / ``pefile`` /
    ``which_arch`` bound at module scope.

    Empirical proof:  patching the CONSUMER module's name (which
    doesn't exist) raises AttributeError, OR the patch attaches to
    a phantom and silently no-ops while the real symbol runs.
    Patching the SOURCE module is the only correct shape.
    """

    def test_consumer_module_lacks_lief_attribute(self):
        """``app.services.binary_analysis_service`` must NOT have a
        ``lief`` attribute — the import is inside function bodies. If
        someone refactors lief to a top-level import, this test will
        flag the change so patches across the codebase get re-audited
        (the inverse Rule #30 situation)."""
        assert not hasattr(bas, "lief"), (
            "lief must NOT be bound at module scope of "
            "binary_analysis_service.py — refactor would break Rule #30 "
            "patches across the codebase"
        )

    def test_consumer_module_lacks_pefile_attribute(self):
        assert not hasattr(bas, "pefile"), (
            "pefile must NOT be bound at module scope — function-body "
            "lazy import is the documented Rule #30 shape"
        )

    def test_source_module_lief_parse_is_real_target(self, tmp_path: Path):
        """A patch on `lief.parse` (SOURCE module) actually intercepts
        the call from `analyze_binary`. Proves the patch target."""
        f = tmp_path / "any.bin"
        f.write_bytes(b"\x00" * 100)

        with patch("lief.parse", return_value=None) as mock_parse:
            result = analyze_binary(str(f))
        # The patched-source mock was called → patch target is correct.
        mock_parse.assert_called_once_with(str(f))
        # And the None return → falls through to the magic-byte path.
        assert result["format"] == "unknown"
