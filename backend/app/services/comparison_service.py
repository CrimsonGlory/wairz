"""Service for comparing firmware versions — filesystem and binary diffing."""

import hashlib
import os
from dataclasses import dataclass, field

import lief

from app.utils.hashing import compute_file_sha256
from app.utils.sandbox import safe_walk

MAX_DIFF_ENTRIES = 2000


@dataclass
class FileDiffEntry:
    """A single file difference between two firmware versions."""

    path: str
    status: str  # "added", "removed", "modified", "permissions_changed"
    size_a: int | None = None
    size_b: int | None = None
    perms_a: str | None = None
    perms_b: str | None = None
    hash_a: str | None = None
    hash_b: str | None = None


@dataclass
class FirmwareDiff:
    """Result of comparing two firmware filesystem trees."""

    added: list[FileDiffEntry] = field(default_factory=list)
    removed: list[FileDiffEntry] = field(default_factory=list)
    modified: list[FileDiffEntry] = field(default_factory=list)
    permissions_changed: list[FileDiffEntry] = field(default_factory=list)
    total_files_a: int = 0
    total_files_b: int = 0
    truncated: bool = False


@dataclass
class FunctionDiffEntry:
    """A function-level difference between two binaries."""

    name: str
    status: str  # "added", "removed", "modified"
    size_a: int | None = None
    size_b: int | None = None
    hash_a: str | None = None
    hash_b: str | None = None
    addr_a: int | None = None
    addr_b: int | None = None


@dataclass
class BinaryDiff:
    """Result of comparing two versions of a binary."""

    binary_path: str
    functions_added: list[FunctionDiffEntry] = field(default_factory=list)
    functions_removed: list[FunctionDiffEntry] = field(default_factory=list)
    functions_modified: list[FunctionDiffEntry] = field(default_factory=list)
    info_a: dict = field(default_factory=dict)
    info_b: dict = field(default_factory=dict)
    sections_a: list[dict] = field(default_factory=list)
    sections_b: list[dict] = field(default_factory=list)
    sections_changed: list[dict] = field(default_factory=list)
    imports_added: list[str] = field(default_factory=list)
    imports_removed: list[str] = field(default_factory=list)
    exports_added: list[str] = field(default_factory=list)
    exports_removed: list[str] = field(default_factory=list)
    basic_block_stats: dict | None = None


def _file_sha256(path: str) -> str | None:
    """Compute SHA256 hash of a file, returning None on error."""
    try:
        return compute_file_sha256(path)
    except (OSError, PermissionError):
        return None


def _get_perms(path: str) -> str:
    """Get file permissions as octal string."""
    try:
        return oct(os.stat(path).st_mode)[-4:]
    except OSError:
        return "????"


def _scan_tree(root: str) -> dict[str, tuple[str | None, int, str]]:
    """Walk a filesystem tree and return {rel_path: (sha256, size, perms)} for files."""
    real_root = os.path.realpath(root)
    result: dict[str, tuple[str | None, int, str]] = {}

    for dirpath, _dirs, files in safe_walk(root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            rel_path = "/" + os.path.relpath(abs_path, real_root)

            try:
                stat = os.stat(abs_path)
                size = stat.st_size
            except OSError:
                continue

            sha = _file_sha256(abs_path)
            perms = _get_perms(abs_path)
            result[rel_path] = (sha, size, perms)

    return result


def diff_filesystems(root_a: str, root_b: str) -> FirmwareDiff:
    """Compare two extracted firmware filesystem trees.

    Returns categorized differences: added, removed, modified, permissions_changed.
    """
    tree_a = _scan_tree(root_a)
    tree_b = _scan_tree(root_b)

    paths_a = set(tree_a.keys())
    paths_b = set(tree_b.keys())

    result = FirmwareDiff(
        total_files_a=len(tree_a),
        total_files_b=len(tree_b),
    )

    # Truncate per category so one large category doesn't starve the others
    # Added files (in B but not in A)
    for path in sorted(paths_b - paths_a):
        if len(result.added) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_b, size_b, perms_b = tree_b[path]
        result.added.append(FileDiffEntry(
            path=path, status="added", size_b=size_b, perms_b=perms_b, hash_b=sha_b,
        ))

    # Removed files (in A but not in B)
    for path in sorted(paths_a - paths_b):
        if len(result.removed) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_a, size_a, perms_a = tree_a[path]
        result.removed.append(FileDiffEntry(
            path=path, status="removed", size_a=size_a, perms_a=perms_a, hash_a=sha_a,
        ))

    # Common files — check for modifications
    for path in sorted(paths_a & paths_b):
        if len(result.modified) >= MAX_DIFF_ENTRIES and len(result.permissions_changed) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_a, size_a, perms_a = tree_a[path]
        sha_b, size_b, perms_b = tree_b[path]

        content_changed = (sha_a != sha_b) and sha_a is not None and sha_b is not None
        perm_changed = perms_a != perms_b

        if content_changed and len(result.modified) < MAX_DIFF_ENTRIES:
            result.modified.append(FileDiffEntry(
                path=path, status="modified",
                size_a=size_a, size_b=size_b,
                perms_a=perms_a, perms_b=perms_b,
                hash_a=sha_a, hash_b=sha_b,
            ))
        elif perm_changed and len(result.permissions_changed) < MAX_DIFF_ENTRIES:
            result.permissions_changed.append(FileDiffEntry(
                path=path, status="permissions_changed",
                size_a=size_a, size_b=size_b,
                perms_a=perms_a, perms_b=perms_b,
                hash_a=sha_a, hash_b=sha_b,
            ))

    return result


def diff_binary(binary_a_path: str, binary_b_path: str, binary_rel_path: str) -> BinaryDiff:
    """Compare two versions of the same ELF binary at the function level.

    Uses LIEF to extract function symbols with body hashes, detecting same-size
    code changes that pure size comparison misses.  Falls back to section-level
    hashing for stripped binaries.
    """
    result = BinaryDiff(binary_path=binary_rel_path)

    # Always extract basic info (file size, arch, etc.)
    result.info_a = _extract_binary_info(binary_a_path)
    result.info_b = _extract_binary_info(binary_b_path)

    # Compute file hashes for comparison
    sha_a = _file_sha256(binary_a_path)
    sha_b = _file_sha256(binary_b_path)
    result.info_a["sha256"] = sha_a
    result.info_b["sha256"] = sha_b
    result.info_a["identical"] = sha_a == sha_b

    # Extract import/export sets using LIEF and compare them
    imports_a = _extract_imports(binary_a_path)
    imports_b = _extract_imports(binary_b_path)
    if imports_a is not None and imports_b is not None:
        result.imports_added = sorted(imports_b - imports_a)
        result.imports_removed = sorted(imports_a - imports_b)

    exports_a = _extract_exports(binary_a_path)
    exports_b = _extract_exports(binary_b_path)
    if exports_a is not None and exports_b is not None:
        result.exports_added = sorted(exports_b - exports_a)
        result.exports_removed = sorted(exports_a - exports_b)

    # Function-level diff using body hashes
    funcs_a = _extract_function_hashes(binary_a_path)
    funcs_b = _extract_function_hashes(binary_b_path)

    if funcs_a is None or funcs_b is None:
        result.info_a["stripped"] = funcs_a is None or (funcs_a is not None and len(funcs_a) == 0)
        result.info_b["stripped"] = funcs_b is None or (funcs_b is not None and len(funcs_b) == 0)

        # Fall back to section-level hashing for stripped binaries
        secs_a = _extract_section_hashes(binary_a_path)
        secs_b = _extract_section_hashes(binary_b_path)
        if secs_a is not None:
            result.sections_a = secs_a
        if secs_b is not None:
            result.sections_b = secs_b
        if secs_a and secs_b:
            map_a = {s["name"]: s for s in secs_a}
            map_b = {s["name"]: s for s in secs_b}
            for name in sorted(set(map_a) | set(map_b)):
                sa = map_a.get(name)
                sb = map_b.get(name)
                if sa and sb and sa["hash"] != sb["hash"]:
                    result.sections_changed.append({
                        "name": name,
                        "size_a": sa["size"],
                        "size_b": sb["size"],
                        "hash_a": sa["hash"],
                        "hash_b": sb["hash"],
                    })
                elif sa and not sb:
                    result.sections_changed.append({
                        "name": name,
                        "status": "removed",
                        "size_a": sa["size"],
                        "hash_a": sa["hash"],
                    })
                elif sb and not sa:
                    result.sections_changed.append({
                        "name": name,
                        "status": "added",
                        "size_b": sb["size"],
                        "hash_b": sb["hash"],
                    })

        # Basic block hashing for deeper stripped binary comparison
        bb_a = _extract_basic_blocks(binary_a_path)
        bb_b = _extract_basic_blocks(binary_b_path)
        if bb_a is not None and bb_b is not None:
            hashes_a = set(bb_a["unique_hashes"])
            hashes_b = set(bb_b["unique_hashes"])
            common = hashes_a & hashes_b
            added = hashes_b - hashes_a
            removed = hashes_a - hashes_b
            total_unique = len(hashes_a | hashes_b)
            unchanged_pct = round(len(common) / total_unique * 100, 1) if total_unique > 0 else 100.0
            result.basic_block_stats = {
                "blocks_a": bb_a["block_count"],
                "blocks_b": bb_b["block_count"],
                "common_count": len(common),
                "added_count": len(added),
                "removed_count": len(removed),
                "unchanged_pct": unchanged_pct,
            }

        return result

    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())

    # Added functions
    for name in sorted(names_b - names_a):
        fb = funcs_b[name]
        result.functions_added.append(FunctionDiffEntry(
            name=name, status="added",
            size_b=fb["size"], hash_b=fb["hash"], addr_b=fb["addr"],
        ))

    # Removed functions
    for name in sorted(names_a - names_b):
        fa = funcs_a[name]
        result.functions_removed.append(FunctionDiffEntry(
            name=name, status="removed",
            size_a=fa["size"], hash_a=fa["hash"], addr_a=fa["addr"],
        ))

    # Modified functions (different hash — catches same-size code changes)
    for name in sorted(names_a & names_b):
        fa = funcs_a[name]
        fb = funcs_b[name]
        if fa["hash"] != fb["hash"]:
            result.functions_modified.append(FunctionDiffEntry(
                name=name, status="modified",
                size_a=fa["size"], size_b=fb["size"],
                hash_a=fa["hash"], hash_b=fb["hash"],
                addr_a=fa["addr"], addr_b=fb["addr"],
            ))

    return result


MAX_TEXT_DIFF_SIZE = 512 * 1024  # 512 KB per file for text diffing

# Extensions commonly containing readable/diffable content in firmware
_TEXT_EXTENSIONS = frozenset({
    ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".sh", ".ash", ".bash", ".csh", ".lua", ".py", ".pl", ".rb",
    ".html", ".htm", ".css", ".js", ".php", ".cgi",
    ".txt", ".log", ".md", ".csv", ".tsv",
    ".service", ".timer", ".mount", ".socket", ".target",
    ".rules", ".pem", ".crt", ".key",
})

# Paths that are always interesting for firmware comparison
_TEXT_PATH_PATTERNS = (
    "/etc/", "/usr/share/", "/www/", "/opt/",
    "init.d/", "rc.d/", "crontab",
)


def is_diffable_text(path: str, abs_path: str) -> bool:
    """Check if a file is likely a text file worth diffing."""
    _, ext = os.path.splitext(path.lower())
    if ext in _TEXT_EXTENSIONS:
        return True
    if any(p in path for p in _TEXT_PATH_PATTERNS):
        # Check if it's actually text by reading first bytes
        try:
            with open(abs_path, "rb") as f:
                chunk = f.read(512)
                if b"\x00" in chunk:
                    return False
                return True
        except OSError:
            return False
    return False


def diff_text_file(path_a: str, path_b: str, rel_path: str) -> dict:
    """Generate a unified diff between two text files.

    Returns a dict with the diff lines and metadata.
    """
    import difflib

    result: dict = {
        "path": rel_path,
        "diff": "",
        "lines_added": 0,
        "lines_removed": 0,
        "truncated": False,
        "error": None,
    }

    try:
        size_a = os.path.getsize(path_a) if os.path.exists(path_a) else 0
        size_b = os.path.getsize(path_b) if os.path.exists(path_b) else 0

        if size_a > MAX_TEXT_DIFF_SIZE or size_b > MAX_TEXT_DIFF_SIZE:
            result["error"] = f"File too large for text diff ({max(size_a, size_b)} bytes)"
            return result

        lines_a: list[str] = []
        lines_b: list[str] = []

        if os.path.exists(path_a):
            with open(path_a, errors="replace") as f:
                lines_a = f.readlines()

        if os.path.exists(path_b):
            with open(path_b, errors="replace") as f:
                lines_b = f.readlines()

        diff_lines = list(difflib.unified_diff(
            lines_a, lines_b,
            fromfile=f"a{rel_path}",
            tofile=f"b{rel_path}",
            lineterm="",
        ))

        # Count additions and removals (skip header lines)
        for line in diff_lines[2:]:
            if line.startswith("+") and not line.startswith("+++"):
                result["lines_added"] += 1
            elif line.startswith("-") and not line.startswith("---"):
                result["lines_removed"] += 1

        # Truncate if diff is very large
        if len(diff_lines) > 500:
            diff_lines = diff_lines[:500]
            diff_lines.append("\n... diff truncated (500 lines shown) ...")
            result["truncated"] = True

        result["diff"] = "\n".join(diff_lines)

    except Exception as e:
        result["error"] = str(e)

    return result


def _extract_function_hashes(binary_path: str) -> dict[str, dict] | None:
    """Extract function names, sizes, addresses, and body hashes from ELF binary.

    Tries .symtab first (all functions), falls back to .dynsym (exports only).
    Returns {name: {size, hash, addr}} or None if parsing fails.
    """
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return None

        functions: dict[str, dict] = {}

        # Try all symbols first (.symtab + .dynsym), fall back to dynamic only
        # LIEF exposes .symbols (all) and .dynamic_symbols; .static_symbols
        # doesn't exist in all versions.
        symbol_sources = [binary.symbols]
        if hasattr(binary, "dynamic_symbols"):
            symbol_sources.append(binary.dynamic_symbols)

        for symbols in symbol_sources:
            for sym in symbols:
                if (sym.is_function
                        and sym.name and sym.size > 0 and sym.value > 0
                        and sym.name not in functions):
                    content = binary.get_content_from_virtual_address(sym.value, sym.size)
                    if content and len(content) == sym.size:
                        h = hashlib.sha256(bytes(content)).hexdigest()
                        functions[sym.name] = {
                            "size": sym.size,
                            "hash": h,
                            "addr": sym.value,
                        }
            if functions:
                break  # Got functions, don't try next source

        return functions if functions else None
    except Exception:
        return None


def _extract_section_hashes(binary_path: str) -> list[dict] | None:
    """Extract hashes for key sections — fallback for stripped binaries."""
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return None

        sections: list[dict] = []
        for name in (".text", ".rodata", ".data", ".init", ".fini", ".plt"):
            section = binary.get_section(name)
            if section and section.size > 0:
                content = bytes(section.content)
                sections.append({
                    "name": name,
                    "size": section.size,
                    "hash": hashlib.sha256(content).hexdigest(),
                })
        return sections if sections else None
    except Exception:
        return None


def _extract_imports(binary_path: str) -> set[str] | None:
    """Extract imported function names from an ELF binary using LIEF."""
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return None
        imports: set[str] = set()
        for sym in binary.dynamic_symbols:
            if sym.is_function and sym.name and sym.imported:
                imports.add(sym.name)
        return imports
    except Exception:
        return None


def _extract_exports(binary_path: str) -> set[str] | None:
    """Extract exported function names from an ELF binary using LIEF."""
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return None
        exports: set[str] = set()
        for sym in binary.dynamic_symbols:
            if sym.is_function and sym.name and sym.exported:
                exports.add(sym.name)
        return exports
    except Exception:
        return None


def diff_function_instructions(
    binary_a_path: str,
    binary_b_path: str,
    function_name: str,
) -> dict:
    """Disassemble a function from both binaries and produce a unified diff.

    Uses LIEF to locate the function symbol and read its bytes, then Capstone
    to disassemble.  Returns a dict with function_name, arch, diff_text,
    lines_added, lines_removed, and error.
    """
    import difflib

    import capstone

    result: dict = {
        "function_name": function_name,
        "arch": "",
        "diff_text": "",
        "lines_added": 0,
        "lines_removed": 0,
        "error": None,
    }

    # Architecture mapping from LIEF ELF machine type to Capstone
    _ARCH_MAP = {
        lief.ELF.ARCH.AARCH64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "aarch64"),
        lief.ELF.ARCH.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, "arm"),
        lief.ELF.ARCH.MIPS: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, "mips"),
        lief.ELF.ARCH.I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86"),
        lief.ELF.ARCH.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86_64"),
    }

    def _parse_and_disassemble(binary_path: str, label: str):
        """Parse a binary, find the function, and disassemble it.

        Returns (lines, arch_info, error_string).
        """
        binary = lief.ELF.parse(binary_path)
        if binary is None:
            return None, None, f"Failed to parse {label} as ELF"

        # Find the function symbol (iterates both .symtab and .dynsym)
        sym = None
        for s in binary.symbols:
            if (
                s.name == function_name
                and s.is_function
                and s.value > 0
            ):
                sym = s
                break

        if sym is None:
            return None, None, f"Function '{function_name}' not found in {label}"

        if sym.size == 0:
            return None, None, f"Function '{function_name}' has size 0 in {label}"

        # Determine architecture
        machine = binary.header.machine_type
        if machine not in _ARCH_MAP:
            return None, None, f"Unsupported architecture in {label}: {machine}"

        cs_arch, cs_mode, arch_name = _ARCH_MAP[machine]

        # Handle endianness for MIPS
        if machine == lief.ELF.ARCH.MIPS:
            if binary.header.identity_data == lief.ELF.Header.ELF_DATA.MSB:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        # Read function bytes
        try:
            func_bytes = bytes(binary.get_content_from_virtual_address(
                sym.value, sym.size,
            ))
        except Exception as e:
            return None, None, f"Failed to read function bytes in {label}: {e}"

        if not func_bytes:
            return None, None, f"Empty function body in {label}"

        # Disassemble
        try:
            md = capstone.Cs(cs_arch, cs_mode)
            instructions = list(md.disasm(func_bytes, sym.value))
        except capstone.CsError as e:
            return None, None, f"Capstone disassembly failed for {label}: {e}"

        # Format as lines with offset relative to function start
        base = sym.value
        lines = []
        for insn in instructions:
            offset = insn.address - base
            lines.append(f"+{offset:#06x}: {insn.mnemonic} {insn.op_str}")

        return lines, (machine, arch_name), None

    # Disassemble both binaries
    lines_a, arch_a, err_a = _parse_and_disassemble(binary_a_path, "firmware A")
    if err_a and lines_a is None:
        result["error"] = err_a
        return result

    lines_b, arch_b, err_b = _parse_and_disassemble(binary_b_path, "firmware B")
    if err_b and lines_b is None:
        result["error"] = err_b
        return result

    # Check architecture match
    if arch_a[0] != arch_b[0]:
        result["error"] = (
            f"Architecture mismatch: firmware A is {arch_a[1]}, "
            f"firmware B is {arch_b[1]}"
        )
        return result

    result["arch"] = arch_a[1]

    # Produce unified diff
    diff_lines = list(difflib.unified_diff(
        lines_a,
        lines_b,
        fromfile=f"a/{function_name}",
        tofile=f"b/{function_name}",
        lineterm="",
    ))

    # Count additions and removals (skip header lines)
    for line in diff_lines[2:]:
        if line.startswith("+") and not line.startswith("+++"):
            result["lines_added"] += 1
        elif line.startswith("-") and not line.startswith("---"):
            result["lines_removed"] += 1

    result["diff_text"] = "\n".join(diff_lines)

    return result


def _extract_functions(binary_path: str) -> dict[str, int] | None:
    """Extract function names and sizes from an ELF binary (legacy, pyelftools).

    Kept for backward compatibility. Use _extract_function_hashes() instead.
    Returns {function_name: size} or None if parsing fails.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            functions: dict[str, int] = {}

            for section_name in (".symtab", ".dynsym"):
                section = elf.get_section_by_name(section_name)
                if section and isinstance(section, SymbolTableSection):
                    for sym in section.iter_symbols():
                        if (sym.entry.st_info.type == "STT_FUNC"
                                and sym.name
                                and sym.entry.st_shndx != "SHN_UNDEF"
                                and sym.entry.st_size > 0):
                            functions[sym.name] = sym.entry.st_size

            return functions
    except Exception:
        return None


def _extract_binary_info(binary_path: str) -> dict:
    """Extract basic binary metadata using LIEF."""
    try:
        info: dict = {}
        stat = os.stat(binary_path)
        info["file_size"] = stat.st_size

        binary = lief.parse(binary_path)
        if binary is not None:
            header = binary.header
            info["arch"] = str(header.machine_type).split(".")[-1]
            info["bits"] = 64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
            info["endian"] = (
                "little" if header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"
            )

        return info
    except Exception:
        return {"file_size": os.path.getsize(binary_path) if os.path.exists(binary_path) else 0}


def _extract_basic_blocks(binary_path: str) -> dict | None:
    """Extract basic block hashes from .text section for stripped binary comparison.

    Splits .text section at branch/jump/return instructions to identify basic blocks,
    then hashes each block's normalized instruction sequence.
    Returns {block_count, unique_hashes: list, blocks: list[{offset, size, hash}]} or None.
    """
    import capstone

    try:
        binary = lief.ELF.parse(binary_path)
        if binary is None:
            return None

        text_section = binary.get_section(".text")
        if text_section is None or text_section.size == 0:
            return None

        text_bytes = bytes(text_section.content)
        base_addr = text_section.virtual_address

        # Architecture mapping (same as diff_function_instructions)
        _ARCH_MAP = {
            lief.ELF.ARCH.AARCH64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            lief.ELF.ARCH.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            lief.ELF.ARCH.MIPS: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
            lief.ELF.ARCH.I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            lief.ELF.ARCH.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        }

        machine = binary.header.machine_type
        if machine not in _ARCH_MAP:
            return None

        cs_arch, cs_mode = _ARCH_MAP[machine]

        # Handle endianness for MIPS
        if machine == lief.ELF.ARCH.MIPS:
            if binary.header.identity_data == lief.ELF.Header.ELF_DATA.MSB:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True
        instructions = list(md.disasm(text_bytes, base_addr))

        if not instructions:
            return None

        # Branch/jump/return instruction sets by architecture
        _BRANCH_MNEMONICS: set[str] = set()
        if cs_arch == capstone.CS_ARCH_ARM64:
            _BRANCH_MNEMONICS = {"b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"}
        elif cs_arch == capstone.CS_ARCH_ARM:
            _BRANCH_MNEMONICS = {
                "b", "bl", "bx", "blx", "bxj",
                "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
                "bhi", "bls", "bge", "blt", "bgt", "ble",
            }
        elif cs_arch == capstone.CS_ARCH_MIPS:
            _BRANCH_MNEMONICS = {
                "j", "jr", "jal", "jalr",
                "beq", "bne", "bgtz", "blez", "bltz", "bgez",
                "beqz", "bnez",
            }
        elif cs_arch == capstone.CS_ARCH_X86:
            _BRANCH_MNEMONICS = {
                "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp",
                "call", "ret", "retf", "retn", "iret",
                "loop", "loope", "loopne",
            }

        # Split into basic blocks at branch instructions
        blocks: list[dict] = []
        current_block_insns: list[str] = []
        block_start_offset = 0

        for insn in instructions:
            # Normalize: mnemonic + operand types (strip absolute addresses)
            # Replace hex addresses with a placeholder to ignore relocation differences
            op_str = insn.op_str
            # Normalize absolute addresses (hex values) to a placeholder
            normalized_ops = []
            for part in op_str.replace(",", " ").split():
                if part.startswith("0x") or part.startswith("#0x"):
                    normalized_ops.append("ADDR")
                else:
                    normalized_ops.append(part)
            normalized = f"{insn.mnemonic} {' '.join(normalized_ops)}".strip()
            current_block_insns.append(normalized)

            if insn.mnemonic.lower() in _BRANCH_MNEMONICS:
                # End of basic block
                if current_block_insns:
                    block_text = "\n".join(current_block_insns)
                    block_hash = hashlib.sha256(block_text.encode()).hexdigest()
                    block_offset = insn.address - base_addr
                    blocks.append({
                        "offset": block_start_offset,
                        "size": int(block_offset - block_start_offset + insn.size),
                        "hash": block_hash,
                    })
                    current_block_insns = []
                    block_start_offset = int(block_offset + insn.size)

        # Handle trailing instructions (final block without a branch at the end)
        if current_block_insns:
            block_text = "\n".join(current_block_insns)
            block_hash = hashlib.sha256(block_text.encode()).hexdigest()
            last_insn = instructions[-1]
            end_offset = last_insn.address - base_addr + last_insn.size
            blocks.append({
                "offset": block_start_offset,
                "size": int(end_offset - block_start_offset),
                "hash": block_hash,
            })

        unique_hashes = list(set(b["hash"] for b in blocks))
        return {
            "block_count": len(blocks),
            "unique_hashes": unique_hashes,
            "blocks": blocks,
        }
    except Exception:
        return None


async def diff_decompilation(
    path_a: str,
    path_b: str,
    binary_path: str,
    function_name: str,
    firmware_a_id,
    firmware_b_id,
    db,
    context_lines: int = 5,
) -> dict:
    """Decompile a function from both binaries and produce a unified diff.

    Uses the Ghidra analysis cache for decompilation (results are cached by
    binary hash + function name).  Returns a dict with source_a, source_b,
    diff_text, lines_added, lines_removed, and error.
    """
    import difflib

    from app.services import ghidra_service

    result: dict = {
        "function_name": function_name,
        "binary_path": binary_path,
        "source_a": "",
        "source_b": "",
        "diff_text": "",
        "lines_added": 0,
        "lines_removed": 0,
        "error": None,
    }


    try:
        code_a = await ghidra_service.decompile_function(path_a, function_name, firmware_a_id, db)
    except Exception as exc:
        result["error"] = f"Error decompiling from firmware A: {exc}"
        return result

    try:
        code_b = await ghidra_service.decompile_function(path_b, function_name, firmware_b_id, db)
    except Exception as exc:
        result["error"] = f"Error decompiling from firmware B: {exc}"
        return result

    result["source_a"] = code_a
    result["source_b"] = code_b

    lines_a = code_a.splitlines(keepends=True)
    lines_b = code_b.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile=f"a/{binary_path}:{function_name}",
        tofile=f"b/{binary_path}:{function_name}",
        n=context_lines,
    ))

    for line in diff_lines[2:]:
        if line.startswith("+") and not line.startswith("+++"):
            result["lines_added"] += 1
        elif line.startswith("-") and not line.startswith("---"):
            result["lines_removed"] += 1

    result["diff_text"] = "".join(diff_lines)

    return result
