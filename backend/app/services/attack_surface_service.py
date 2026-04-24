"""Attack surface analysis service.

Scans extracted firmware for ELF binaries and scores each one by how
exposed it is to attack, based on imported symbols, file permissions,
path location, and init script presence.
"""

import logging
import os
import re
import stat
from dataclasses import dataclass, field

from app.services.analysis_service import check_binary_protections
from app.services.binary_analysis_service import _LIEF_ELF_ARCH_MAP
from app.utils.sandbox import safe_walk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal detection constants
# ---------------------------------------------------------------------------

DANGEROUS_FUNCTIONS = {
    "system", "popen", "execve", "execl", "execvp", "execle",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "fscanf", "sscanf",
    "dlopen", "dlsym",
}

NETWORK_FUNCTIONS = {
    "socket", "bind", "listen", "accept", "select", "poll",
    "epoll_create", "epoll_wait", "recvfrom", "recvmsg",
}

KNOWN_NETWORK_DAEMONS = {
    "uhttpd", "lighttpd", "nginx", "httpd", "mini_httpd", "thttpd",
    "dropbear", "sshd", "telnetd", "ftpd", "vsftpd", "proftpd",
    "dnsmasq", "named", "unbound",
    "mosquitto", "emqx",
    "ubusd", "netifd", "odhcpd", "hostapd", "wpad",
    "miniupnpd", "upnpd",
    "snmpd", "lldpd",
    "crond", "xinetd", "inetd",
}

CGI_PATH_PATTERNS = ["/www/cgi-bin/", "/tmp/www/", "/www/", "/usr/lib/cgi-bin/"]

# Normalization: max reasonable raw_score * multiplier ~ 150
NORMALIZATION_FACTOR = 0.67

# Pre-computed list for rapidfuzz matching
_DAEMON_NAMES_LIST = sorted(KNOWN_NETWORK_DAEMONS)


def _fuzzy_daemon_match(name: str, threshold: float = 0.80) -> bool:
    """Check if a binary name fuzzy-matches a known network daemon.

    Catches version-suffixed names (lighttpd-1.4.45), variant names
    (dropbear_ssh, sshd-v2), and init script names (S50dropbear).
    """
    import re

    # Strip common prefixes/suffixes before fuzzy matching
    cleaned = re.sub(r"^[SK]\d{2}", "", name)         # init script prefixes (S50, K20)
    cleaned = re.sub(r"[-_]?v?\d[\d.]*$", "", cleaned)  # version suffixes
    cleaned = cleaned.strip("-_")

    if not cleaned:
        return False

    # Quick exact check on cleaned name
    if cleaned in KNOWN_NETWORK_DAEMONS:
        return True

    try:
        from rapidfuzz import fuzz, process
        result = process.extractOne(
            cleaned,
            _DAEMON_NAMES_LIST,
            scorer=fuzz.token_sort_ratio,
            score_cutoff=threshold * 100,
        )
        return result is not None
    except ImportError:
        return False


@dataclass
class BinarySignals:
    """Collected signals for a single binary."""
    path: str
    name: str
    architecture: str | None = None
    file_size: int | None = None
    imported_symbols: set[str] = field(default_factory=set)
    is_setuid: bool = False
    is_setgid: bool = False
    is_cgi: bool = False
    is_known_daemon: bool = False
    in_init_scripts: bool = False
    has_debug_info: bool = False
    # Protection status (from pyelftools)
    nx: bool = False
    canary: bool = False
    pie: bool = False
    relro: str = "none"


def _rel(abs_path: str, root: str) -> str:
    """Return firmware-relative path."""
    return "/" + os.path.relpath(abs_path, os.path.realpath(root))


def _is_elf(path: str) -> bool:
    """Quick check if a file starts with ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _get_elf_imports_lief(path: str) -> tuple[set[str], str | None, bool]:
    """Extract imported symbol names using LIEF.

    Returns (imports_set, architecture_string, has_debug_info).
    """
    import lief

    binary = lief.parse(path)
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        return set(), None, False

    imports = set()
    # Iterate over dynamic symbols — imported symbols have no value
    for sym in binary.dynamic_symbols:
        if sym.imported:
            imports.add(sym.name)

    # Architecture
    arch = _LIEF_ELF_ARCH_MAP.get(binary.header.machine_type)

    # Debug info
    has_debug = binary.has_section(".debug_info")

    return imports, arch, has_debug


def _get_elf_imports_pyelftools(path: str) -> tuple[set[str], str | None, bool]:
    """Fallback: extract imported symbols using pyelftools."""
    from elftools.elf.elffile import ELFFile

    imports = set()
    arch = None
    has_debug = False

    with open(path, "rb") as f:
        try:
            elf = ELFFile(f)
        except Exception:
            return imports, arch, has_debug

        arch = elf.header.e_machine
        has_debug = elf.get_section_by_name(".debug_info") is not None

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            for sym in dynsym.iter_symbols():
                if sym.name and sym.entry.st_shndx == "SHN_UNDEF":
                    imports.add(sym.name)

    return imports, arch, has_debug


def _get_elf_imports(path: str) -> tuple[set[str], str | None, bool]:
    """Get imports using LIEF, falling back to pyelftools."""
    try:
        return _get_elf_imports_lief(path)
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("LIEF import extraction failed for %s: %s", path, exc)
    try:
        return _get_elf_imports_pyelftools(path)
    except Exception as exc:
        logger.debug("pyelftools import extraction failed for %s: %s", path, exc)
    return set(), None, False


def _get_binary_protections(path: str) -> dict:
    """Get binary protections using pyelftools."""
    try:
        return check_binary_protections(path)
    except Exception:
        return {}


def _collect_init_script_binaries(root: str) -> set[str]:
    """Scan /etc/init.d/* and /etc/inittab for referenced binary names."""
    referenced = set()
    init_dirs = [
        os.path.join(root, "etc", "init.d"),
        os.path.join(root, "etc", "rc.d"),
    ]
    inittab = os.path.join(root, "etc", "inittab")

    scripts: list[str] = []
    for d in init_dirs:
        if os.path.isdir(d):
            try:
                scripts.extend(
                    os.path.join(d, f) for f in os.listdir(d)
                    if os.path.isfile(os.path.join(d, f))
                )
            except OSError:
                continue
    if os.path.isfile(inittab):
        scripts.append(inittab)

    for script_path in scripts:
        try:
            with open(script_path, "r", errors="replace") as f:
                content = f.read(64_000)
        except OSError:
            continue
        # Extract words that look like binary names (alphanumeric + _ + -)
        for word in re.findall(r"\b[a-zA-Z][\w.-]+\b", content):
            referenced.add(word)

    return referenced


def _score_binary(signals: BinarySignals) -> tuple[int, dict]:
    """Compute attack surface score and breakdown for a binary.

    Returns (final_score, breakdown_dict).
    """
    net_imports = signals.imported_symbols & NETWORK_FUNCTIONS
    dangerous_imports = signals.imported_symbols & DANGEROUS_FUNCTIONS

    # Component scores
    network_score = 5 * min(len(net_imports), 5)
    cgi_score = 4 if signals.is_cgi else 0
    setuid_score = 3 if (signals.is_setuid or signals.is_setgid) else 0
    dangerous_score = 2 * min(len(dangerous_imports), 10)
    known_daemon_bonus = 5 if signals.is_known_daemon else 0

    raw_score = network_score + cgi_score + setuid_score + dangerous_score + known_daemon_bonus

    # Privilege multiplier
    if signals.is_setuid or signals.is_setgid:
        privilege_multiplier = 3.0
    elif signals.in_init_scripts:
        privilege_multiplier = 2.0
    else:
        privilege_multiplier = 1.0

    final_score = min(100, int(raw_score * privilege_multiplier * NORMALIZATION_FACTOR))

    breakdown = {
        "network_score": network_score,
        "cgi_score": cgi_score,
        "setuid_score": setuid_score,
        "dangerous_score": dangerous_score,
        "known_daemon_bonus": known_daemon_bonus,
        "raw_score": raw_score,
        "privilege_multiplier": privilege_multiplier,
        "normalization_factor": NORMALIZATION_FACTOR,
        "network_imports": sorted(net_imports),
        "dangerous_imports_found": sorted(dangerous_imports),
        "protections": {
            "nx": signals.nx,
            "canary": signals.canary,
            "pie": signals.pie,
            "relro": signals.relro,
        },
        "has_debug_info": signals.has_debug_info,
    }

    return final_score, breakdown


def _classify_categories(signals: BinarySignals) -> list[str]:
    """Classify the binary into input categories."""
    cats = []
    if signals.is_known_daemon or (signals.imported_symbols & NETWORK_FUNCTIONS):
        cats.append("network")
    if signals.is_cgi:
        cats.append("cgi")
    if signals.is_setuid or signals.is_setgid:
        cats.append("setuid")
    if signals.imported_symbols & {"dlopen", "dlsym"}:
        cats.append("dynamic_loading")
    if signals.imported_symbols & {"system", "popen", "execve", "execl", "execvp", "execle"}:
        cats.append("command_injection")
    if signals.imported_symbols & {"strcpy", "strcat", "sprintf", "vsprintf", "gets"}:
        cats.append("unsafe_memory")
    if signals.imported_symbols & {"scanf", "fscanf", "sscanf"}:
        cats.append("format_string")
    if signals.in_init_scripts:
        cats.append("boot_service")
    if signals.has_debug_info:
        cats.append("debug_symbols")
    return cats


@dataclass
class AttackSurfaceResult:
    """Result of a single binary analysis."""
    path: str
    name: str
    architecture: str | None
    file_size: int | None
    score: int
    breakdown: dict
    is_setuid: bool
    is_network_listener: bool
    is_cgi_handler: bool
    has_dangerous_imports: bool
    dangerous_imports: list[str]
    input_categories: list[str]
    # Auto-finding data
    findings: list[dict] = field(default_factory=list)


def _generate_auto_findings(
    signals: BinarySignals,
    score: int,
    breakdown: dict,
    rel_path: str,
) -> list[dict]:
    """Generate automatic security findings based on attack surface signals."""
    findings = []
    protections = breakdown.get("protections", {})
    net_imports = signals.imported_symbols & NETWORK_FUNCTIONS
    dangerous = signals.imported_symbols & DANGEROUS_FUNCTIONS

    # Rule 1: Network listener + no ASLR + no stack canary
    if net_imports and not protections.get("pie") and not protections.get("canary"):
        findings.append({
            "title": f"Network listener without ASLR/canary: {signals.name}",
            "severity": "high",
            "description": (
                f"Binary {rel_path} listens on the network (imports: "
                f"{', '.join(sorted(net_imports)[:5])}) but lacks PIE (ASLR) "
                f"and stack canary protections, making it vulnerable to "
                f"memory corruption exploits."
            ),
            "file_path": rel_path,
            "cwe_ids": ["CWE-119"],
        })

    # Rule 2: Setuid + imports system()/popen()
    cmd_injection = signals.imported_symbols & {"system", "popen"}
    if (signals.is_setuid or signals.is_setgid) and cmd_injection:
        findings.append({
            "title": f"Setuid binary with command injection risk: {signals.name}",
            "severity": "high",
            "description": (
                f"Binary {rel_path} is setuid and imports "
                f"{', '.join(sorted(cmd_injection))}. If user input reaches "
                f"these functions, privilege escalation via command injection is possible."
            ),
            "file_path": rel_path,
            "cwe_ids": ["CWE-78"],
        })

    # Rule 3: CGI handler + no input validation imports
    input_validation = {"getopt", "optarg", "strtol", "strtoul", "atoi", "getenv"}
    if signals.is_cgi and not (signals.imported_symbols & input_validation):
        findings.append({
            "title": f"CGI handler without input validation: {signals.name}",
            "severity": "medium",
            "description": (
                f"Binary {rel_path} is a CGI handler but does not import "
                f"common input parsing functions, suggesting missing input validation."
            ),
            "file_path": rel_path,
            "cwe_ids": ["CWE-20"],
        })

    # Rule 4: Network listener + setuid + imports strcpy()
    buffer_overflow = signals.imported_symbols & {"strcpy", "strcat", "gets"}
    if net_imports and (signals.is_setuid or signals.is_setgid) and buffer_overflow:
        findings.append({
            "title": f"Critical: privileged network service with buffer overflow risk: {signals.name}",
            "severity": "critical",
            "description": (
                f"Binary {rel_path} is a setuid network listener that imports "
                f"unsafe functions ({', '.join(sorted(buffer_overflow))}). "
                f"This combination enables remote privilege escalation."
            ),
            "file_path": rel_path,
            "cwe_ids": ["CWE-120"],
        })

    # Rule 5: Debug symbols in production
    if signals.has_debug_info:
        findings.append({
            "title": f"Debug symbols in production binary: {signals.name}",
            "severity": "low",
            "description": (
                f"Binary {rel_path} contains .debug_info section. "
                f"Debug symbols aid reverse engineering and may leak "
                f"source file paths and internal structure."
            ),
            "file_path": rel_path,
            "cwe_ids": ["CWE-215"],
        })

    return findings


def scan_attack_surface(
    extracted_root: str,
    path_filter: str | None = None,
) -> list[AttackSurfaceResult]:
    """Scan firmware filesystem for ELF binaries and compute attack surface scores.

    This is a sync function -- call from a thread executor for async contexts.

    Args:
        extracted_root: Path to the extracted firmware root filesystem.
        path_filter: Optional sub-path to limit scanning to.

    Returns:
        List of AttackSurfaceResult sorted by score descending.
    """
    real_root = os.path.realpath(extracted_root)
    scan_root = real_root
    if path_filter:
        candidate = os.path.realpath(os.path.join(real_root, path_filter.lstrip("/")))
        if candidate.startswith(real_root):
            scan_root = candidate

    # Phase 1: Collect init script references
    init_binaries = _collect_init_script_binaries(real_root)

    # Phase 2: Walk filesystem for ELF binaries
    results: list[AttackSurfaceResult] = []
    elf_count = 0

    for dirpath, _dirs, files in safe_walk(scan_root):
        for name in files:
            abs_path = os.path.join(dirpath, name)

            # Skip symlinks to avoid duplicates
            if os.path.islink(abs_path):
                continue
            if not os.path.isfile(abs_path):
                continue
            if not _is_elf(abs_path):
                continue

            elf_count += 1
            if elf_count > 5000:
                logger.warning("Attack surface scan: hit 5000 ELF limit, stopping")
                break

            rel_path = _rel(abs_path, real_root)
            signals = BinarySignals(path=rel_path, name=name)

            # File size
            try:
                st = os.stat(abs_path)
                signals.file_size = st.st_size
                # Setuid/setgid check
                signals.is_setuid = bool(st.st_mode & stat.S_ISUID)
                signals.is_setgid = bool(st.st_mode & stat.S_ISGID)
            except OSError:
                pass

            # ELF imports
            imports, arch, has_debug = _get_elf_imports(abs_path)
            signals.imported_symbols = imports
            signals.architecture = arch
            signals.has_debug_info = has_debug

            # CGI path check
            for pattern in CGI_PATH_PATTERNS:
                if pattern in rel_path:
                    signals.is_cgi = True
                    break

            # Known daemon check — exact first, then fuzzy for version-suffixed
            # or variant names (e.g., lighttpd-1.4.45, dropbear_ssh, sshd-v2)
            if name in KNOWN_NETWORK_DAEMONS:
                signals.is_known_daemon = True
            else:
                signals.is_known_daemon = _fuzzy_daemon_match(name)

            # Init script check
            if name in init_binaries:
                signals.in_init_scripts = True

            # Binary protections
            prots = _get_binary_protections(abs_path)
            if "error" not in prots:
                signals.nx = bool(prots.get("nx", False))
                signals.canary = bool(prots.get("canary", False))
                signals.pie = bool(prots.get("pie", False))
                signals.relro = str(prots.get("relro", "none"))

            # Score
            score, breakdown = _score_binary(signals)
            categories = _classify_categories(signals)

            net_imports = signals.imported_symbols & NETWORK_FUNCTIONS
            dangerous = signals.imported_symbols & DANGEROUS_FUNCTIONS

            # Auto-findings
            auto_findings = _generate_auto_findings(signals, score, breakdown, rel_path)

            results.append(AttackSurfaceResult(
                path=rel_path,
                name=name,
                architecture=signals.architecture,
                file_size=signals.file_size,
                score=score,
                breakdown=breakdown,
                is_setuid=signals.is_setuid or signals.is_setgid,
                is_network_listener=bool(net_imports) or signals.is_known_daemon,
                is_cgi_handler=signals.is_cgi,
                has_dangerous_imports=bool(dangerous),
                dangerous_imports=sorted(dangerous),
                input_categories=categories,
                findings=auto_findings,
            ))

        if elf_count > 5000:
            break

    # Sort by score descending
    results.sort(key=lambda r: r.score, reverse=True)
    return results
