"""Service for analyzing standalone binaries — format, architecture, linking, dependencies.

Uses LIEF for unified ELF/PE/Mach-O parsing with pyelftools as fallback for ELF.
Designed to run synchronously (called from executor in async contexts) since
LIEF and pyelftools do file I/O.
"""

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Canonical architecture names matching the rest of Wairz (emulation, fuzzing, etc.)
_LIEF_ELF_ARCH_MAP: dict[int, str] = {}
_LIEF_PE_ARCH_MAP: dict[int, str] = {}

# Lazy-init flag — LIEF is imported on first use to avoid import-time cost
_lief_loaded = False


def _ensure_lief() -> None:
    """Import LIEF and populate architecture maps on first use."""
    global _lief_loaded
    if _lief_loaded:
        return

    try:
        import lief  # noqa: F401

        # ELF machine types → canonical Wairz architecture names
        _LIEF_ELF_ARCH_MAP.update({
            lief.ELF.ARCH.ARM: "arm",
            lief.ELF.ARCH.AARCH64: "aarch64",
            lief.ELF.ARCH.MIPS: "mips",
            lief.ELF.ARCH.I386: "x86",
            lief.ELF.ARCH.X86_64: "x86_64",
            lief.ELF.ARCH.PPC: "ppc",
            lief.ELF.ARCH.PPC64: "ppc64",
            lief.ELF.ARCH.SH: "sh",
            lief.ELF.ARCH.SPARC: "sparc",
        })

        # PE machine types → canonical Wairz architecture names
        _LIEF_PE_ARCH_MAP.update({
            lief.PE.Header.MACHINE_TYPES.I386: "x86",
            lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
            lief.PE.Header.MACHINE_TYPES.ARM: "arm",
            lief.PE.Header.MACHINE_TYPES.ARM64: "aarch64",
        })

        _lief_loaded = True
    except ImportError:
        logger.warning("LIEF library not installed — binary analysis will use pyelftools fallback")
        _lief_loaded = True  # Don't retry


def analyze_binary(file_path: str) -> dict[str, Any]:
    """Analyze a binary file and return structured metadata.

    Returns a dict with:
        format: "elf" | "pe" | "macho" | "unknown"
        architecture: canonical arch name (arm, aarch64, mips, mipsel, x86, x86_64, ...)
        endianness: "little" | "big" | None
        bits: 32 | 64 | None
        is_static: bool
        is_pie: bool
        interpreter: str | None (dynamic linker path for ELF)
        dependencies: list[str] (DT_NEEDED for ELF, DLL imports for PE, dylibs for Mach-O)
        entry_point: int | None
        file_size: int

    This function is synchronous — call via loop.run_in_executor() in async code.
    """
    _ensure_lief()

    result: dict[str, Any] = {
        "format": "unknown",
        "architecture": None,
        "endianness": None,
        "bits": None,
        "is_static": False,
        "is_pie": False,
        "interpreter": None,
        "dependencies": [],
        "entry_point": None,
        "file_size": 0,
    }

    try:
        result["file_size"] = os.path.getsize(file_path)
    except OSError:
        pass

    # Try LIEF first (unified parser)
    try:
        import lief

        binary = lief.parse(file_path)
        if binary is not None:
            if isinstance(binary, lief.ELF.Binary):
                return _analyze_elf_lief(binary, result)
            elif isinstance(binary, lief.PE.Binary):
                return _analyze_pe_lief(binary, result)
            elif isinstance(binary, lief.MachO.FatBinary):
                # lief.parse() returns FatBinary for Mach-O; extract first slice
                return _analyze_macho_lief(binary.at(0), result)
            elif isinstance(binary, lief.MachO.Binary):
                return _analyze_macho_lief(binary, result)
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("LIEF parse failed for %s: %s", file_path, exc)

    # Fallback to pyelftools for ELF
    try:
        return _analyze_elf_pyelftools(file_path, result)
    except Exception:
        pass

    # Try basic magic-byte detection
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"MZ":
            result["format"] = "pe"
        elif magic[:4] == b"\x7fELF":
            result["format"] = "elf"
    except OSError:
        pass

    return result


def _analyze_elf_lief(binary: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata from an ELF binary using LIEF."""
    import lief

    result["format"] = "elf"

    # Architecture
    arch = _LIEF_ELF_ARCH_MAP.get(binary.header.machine_type)
    endianness = "little" if binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"

    # Handle MIPS endianness: mips (big) vs mipsel (little)
    if arch == "mips" and endianness == "little":
        arch = "mipsel"

    result["architecture"] = arch
    result["endianness"] = endianness
    result["bits"] = 64 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
    result["entry_point"] = binary.entrypoint

    # Static vs dynamic detection
    has_interp = binary.has(lief.ELF.Segment.TYPE.INTERP)
    has_dynamic = binary.has(lief.ELF.Segment.TYPE.DYNAMIC)
    result["is_static"] = not has_interp and not has_dynamic

    # Interpreter (dynamic linker)
    if has_interp:
        result["interpreter"] = binary.interpreter

    # PIE detection
    result["is_pie"] = binary.is_pie

    # Dependencies (DT_NEEDED)
    if has_dynamic:
        result["dependencies"] = list(binary.libraries)

    return result


def _analyze_pe_lief(binary: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata from a PE binary using LIEF."""
    result["format"] = "pe"

    # Architecture
    arch = _LIEF_PE_ARCH_MAP.get(binary.header.machine)
    result["architecture"] = arch
    result["endianness"] = "little"  # PE is always little-endian
    result["bits"] = 64 if binary.header.sizeof_optional_header > 100 else 32

    # More precise bits detection
    try:
        import lief
        if binary.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS:
            result["bits"] = 64
        else:
            result["bits"] = 32
    except Exception:
        pass

    result["entry_point"] = binary.entrypoint
    result["is_static"] = len(binary.imports) == 0

    # DLL dependencies
    deps = []
    for imp in binary.imports:
        dll_name = imp.name
        if dll_name and dll_name not in deps:
            deps.append(dll_name)
    result["dependencies"] = deps

    return result


def _analyze_macho_lief(binary: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata from a Mach-O binary using LIEF."""
    import lief

    result["format"] = "macho"

    # Architecture from CPU type
    cpu_type = binary.header.cpu_type
    arch_map = {
        lief.MachO.Header.CPU_TYPE.ARM: "arm",
        lief.MachO.Header.CPU_TYPE.ARM64: "aarch64",
        lief.MachO.Header.CPU_TYPE.X86: "x86",
        lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
    }
    result["architecture"] = arch_map.get(cpu_type)
    result["endianness"] = "little"  # Modern Mach-O is always LE
    result["bits"] = 64 if cpu_type in (
        lief.MachO.Header.CPU_TYPE.ARM64,
        lief.MachO.Header.CPU_TYPE.X86_64,
    ) else 32

    result["entry_point"] = binary.entrypoint

    # Dependencies (LC_LOAD_DYLIB) — libraries returns DylibCommand objects
    result["dependencies"] = [lib.name for lib in binary.libraries]
    result["is_static"] = len(result["dependencies"]) == 0

    return result


def _analyze_elf_pyelftools(file_path: str, result: dict[str, Any]) -> dict[str, Any]:
    """Fallback ELF analysis using pyelftools (already a Wairz dependency)."""
    from elftools.elf.elffile import ELFFile

    from app.workers.unpack_common import _ELF_ARCH_MAP

    # Keep file open throughout — pyelftools lazy-reads segments and sections
    f = open(file_path, "rb")
    try:
        magic = f.read(4)
        if magic != b"\x7fELF":
            raise ValueError("Not an ELF file")
        f.seek(0)
        elf = ELFFile(f)

        result["format"] = "elf"

        # Architecture
        machine = elf.header.e_machine
        arch = _ELF_ARCH_MAP.get(machine)
        endianness = "little" if elf.little_endian else "big"
        if arch == "mips" and endianness == "little":
            arch = "mipsel"

        result["architecture"] = arch
        result["endianness"] = endianness
        result["bits"] = elf.elfclass
        result["entry_point"] = elf.header.e_entry

        # Static vs dynamic: check for PT_INTERP and PT_DYNAMIC segments
        has_interp = False
        has_dynamic = False
        for segment in elf.iter_segments():
            seg_type = segment.header.p_type
            if seg_type == "PT_INTERP":
                has_interp = True
                result["interpreter"] = segment.get_interp_name()
            elif seg_type == "PT_DYNAMIC":
                has_dynamic = True

        result["is_static"] = not has_interp and not has_dynamic

        # PIE detection: ET_DYN type can indicate PIE
        result["is_pie"] = elf.header.e_type == "ET_DYN"

        # Dependencies (DT_NEEDED from .dynamic section)
        deps = []
        if has_dynamic:
            for section in elf.iter_sections():
                if hasattr(section, "iter_tags"):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            deps.append(tag.needed)
        result["dependencies"] = deps
    finally:
        f.close()

    return result


def check_pe_protections(file_path: str) -> dict[str, object]:
    """Check PE binary security protections using pefile.

    Returns a dict with:
      - dep_nx: bool (DEP/NX via IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
      - aslr: bool (ASLR via IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
      - seh: bool (Structured Exception Handling — True unless NO_SEH is set)
      - cfg: bool (Control Flow Guard via IMAGE_DLLCHARACTERISTICS_GUARD_CF)
      - authenticode: bool (Has Authenticode signature)
      - high_entropy_va: bool (High-entropy ASLR for 64-bit)
      - force_integrity: bool (Mandatory integrity checking)
      - sections: list[dict] (section details: name, virtual_size, characteristics)
      - imports_by_dll: dict[str, list[str]] (imported functions grouped by DLL)
      - exports: list[str] (exported function names)
    """
    try:
        import pefile
    except ImportError:
        return {"error": "pefile library not installed"}

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
    except pefile.PEFormatError:
        return {"error": "Not a valid PE file"}
    except Exception as exc:
        return {"error": f"Failed to parse PE: {exc}"}

    result: dict[str, object] = {}

    # DLL characteristics flags
    dll_chars = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0) or 0

    result["dep_nx"] = bool(dll_chars & 0x0100)       # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    result["aslr"] = bool(dll_chars & 0x0040)          # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    result["seh"] = not bool(dll_chars & 0x0400)       # NOT IMAGE_DLLCHARACTERISTICS_NO_SEH
    result["cfg"] = bool(dll_chars & 0x4000)           # IMAGE_DLLCHARACTERISTICS_GUARD_CF
    result["high_entropy_va"] = bool(dll_chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    result["force_integrity"] = bool(dll_chars & 0x0080)  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

    # Authenticode signature presence (DIRECTORY_ENTRY_SECURITY)
    result["authenticode"] = (
        hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
        and pe.DIRECTORY_ENTRY_SECURITY is not None
        and len(pe.DIRECTORY_ENTRY_SECURITY) > 0
    )

    # Sections
    sections = []
    for section in pe.sections:
        sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        chars = section.Characteristics
        flags = []
        if chars & 0x20000000:
            flags.append("EXECUTE")
        if chars & 0x40000000:
            flags.append("READ")
        if chars & 0x80000000:
            flags.append("WRITE")
        sections.append({
            "name": sec_name,
            "virtual_size": section.Misc_VirtualSize,
            "virtual_address": hex(section.VirtualAddress),
            "raw_size": section.SizeOfRawData,
            "entropy": round(section.get_entropy(), 2),
            "flags": flags,
        })
    result["sections"] = sections

    # Imports by DLL
    imports_by_dll: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="replace") if entry.dll else "unknown"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", errors="replace"))
                elif imp.ordinal is not None:
                    funcs.append(f"ordinal_{imp.ordinal}")
            imports_by_dll[dll_name] = funcs
    result["imports_by_dll"] = imports_by_dll

    # Exports
    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("ascii", errors="replace"))
            elif exp.ordinal is not None:
                exports.append(f"ordinal_{exp.ordinal}")
    result["exports"] = exports

    pe.close()
    return result


# Map cpu_rec architecture names → Wairz canonical names
_CPU_REC_ARCH_MAP: dict[str, tuple[str, str]] = {
    "ARM64": ("aarch64", "little"),
    "ARMel": ("arm", "little"),
    "ARMeb": ("arm", "big"),
    "ARMhf": ("arm", "little"),
    "ARM": ("arm", "little"),
    "MIPS32el": ("mipsel", "little"),
    "MIPS32eb": ("mips", "big"),
    "MIPS64el": ("mipsel", "little"),
    "MIPS64eb": ("mips", "big"),
    "MIPSel": ("mipsel", "little"),
    "MIPS": ("mips", "big"),
    "PPC32": ("ppc", "big"),
    "PPC64": ("ppc64", "big"),
    "PPC64el": ("ppc64", "little"),
    "SPARC": ("sparc", "big"),
    "X86": ("x86", "little"),
    "X86-64": ("x86_64", "little"),
    "SH4": ("sh", "little"),
    "SH4eb": ("sh", "big"),
    "RISC-V": ("riscv", "little"),
}


def detect_raw_architecture(file_path: str, chunk_size: int = 0) -> list[dict[str, Any]]:
    """Detect CPU architecture from a raw binary using cpu_rec statistical analysis.

    Designed for binaries with no ELF/PE/Mach-O headers (bare-metal firmware,
    ROM dumps, bootloaders). Uses Airbus cpu_rec tool which applies Multinomial
    Naive Bayes on n-grams from a pre-trained corpus of 70+ architectures.

    Args:
        file_path: Path to the raw binary file.
        chunk_size: If >0, analyze in chunks of this size to find different
                    architecture regions within the binary. Default 0 = whole file.

    Returns:
        List of architecture candidates, each a dict with:
          - architecture: Wairz canonical name (arm, mips, x86, etc.) or raw cpu_rec name
          - raw_name: Original cpu_rec architecture name
          - endianness: "little" | "big" | None
          - confidence: "high" | "medium" | "low" (based on score)
          - score: float (log-probability ratio from cpu_rec, if available)

    This function is synchronous -- call via run_in_executor() in async code.
    """
    results: list[dict[str, Any]] = []

    # Try cpu_rec first
    try:
        import sys
        cpu_rec_path = "/opt/cpu_rec"
        if cpu_rec_path not in sys.path:
            sys.path.insert(0, cpu_rec_path)

        from cpu_rec import which_arch  # type: ignore[import-untyped]

        # Preload training data on first call
        which_arch()

        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return results

        raw_arch = which_arch(data)
        if raw_arch:
            mapped = _CPU_REC_ARCH_MAP.get(raw_arch)
            arch = mapped[0] if mapped else raw_arch.lower()
            endian = mapped[1] if mapped else None
            results.append({
                "architecture": arch,
                "raw_name": raw_arch,
                "endianness": endian,
                "confidence": "high",
            })

        # Also check sub-chunks for architecture boundaries in composite binaries
        if chunk_size > 0 and len(data) > chunk_size * 2:
            seen_archs = {raw_arch} if raw_arch else set()
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset:offset + chunk_size]
                if len(chunk) < 1024:  # Too small for meaningful detection
                    continue
                chunk_arch = which_arch(chunk)
                if chunk_arch and chunk_arch not in seen_archs:
                    seen_archs.add(chunk_arch)
                    mapped = _CPU_REC_ARCH_MAP.get(chunk_arch)
                    arch = mapped[0] if mapped else chunk_arch.lower()
                    endian = mapped[1] if mapped else None
                    results.append({
                        "architecture": arch,
                        "raw_name": chunk_arch,
                        "endianness": endian,
                        "confidence": "medium",
                    })

        return results

    except ImportError:
        logger.debug("cpu_rec not available, falling back to heuristic detection")
    except Exception as exc:
        logger.warning("cpu_rec failed for %s: %s", file_path, exc)

    # Fallback: basic heuristic detection using common instruction patterns
    try:
        with open(file_path, "rb") as f:
            data = f.read(min(os.path.getsize(file_path), 65536))

        if not data:
            return results

        # ARM: look for common ARM instruction patterns
        # BL instructions: 0xEB...... (ARM mode), 0xF?..F?.. (Thumb BL)
        arm_bl_count = sum(1 for i in range(0, len(data) - 3, 4) if data[i + 3] == 0xEB)
        # MIPS: common lui/addiu pattern (0x3C = lui upper byte big-endian)
        mips_be_count = sum(1 for i in range(0, len(data) - 3, 4) if data[i] == 0x3C)
        mips_le_count = sum(1 for i in range(0, len(data) - 3, 4) if data[i + 3] == 0x3C)
        # x86: common REX prefixes (0x48-0x4F for 64-bit), MOV (0x89, 0x8B)
        x86_count = sum(1 for b in data if b in (0x48, 0x49, 0x89, 0x8B, 0xE8, 0xC3))

        total = len(data)
        scores = [
            ("arm", "little", arm_bl_count / (total / 4)),
            ("mips", "big", mips_be_count / (total / 4)),
            ("mipsel", "little", mips_le_count / (total / 4)),
            ("x86_64", "little", x86_count / total),
        ]
        scores.sort(key=lambda x: x[2], reverse=True)

        for arch, endian, score in scores[:3]:
            if score > 0.01:  # At least 1% match
                confidence = "medium" if score > 0.05 else "low"
                results.append({
                    "architecture": arch,
                    "raw_name": f"heuristic:{arch}",
                    "endianness": endian,
                    "confidence": confidence,
                })

    except Exception as exc:
        logger.warning("Heuristic architecture detection failed for %s: %s", file_path, exc)

    return results


def get_arch_and_endianness(file_path: str) -> tuple[str | None, str | None]:
    """Quick architecture + endianness detection for a single binary.

    Convenience wrapper around analyze_binary() for the firmware upload pipeline.
    Returns (architecture, endianness) matching existing Wairz conventions.
    """
    info = analyze_binary(file_path)
    return info.get("architecture"), info.get("endianness")
