"""String analysis AI tools for firmware reverse engineering."""

import asyncio
import logging
import math
import os
import re
from collections import Counter

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.utils.sandbox import safe_walk, validate_path

logger = logging.getLogger(__name__)

MAX_STRINGS = 200
MAX_GREP_RESULTS = 100
MAX_CRED_RESULTS = 100

# Hash type identification for /etc/shadow analysis
_HASH_TYPES = {
    "$1$": ("MD5", "WEAK"),
    "$2a$": ("Blowfish", "OK"),
    "$2b$": ("Blowfish", "OK"),
    "$2y$": ("Blowfish", "OK"),
    "$5$": ("SHA-256", "OK"),
    "$6$": ("SHA-512", "OK"),
    "$y$": ("yescrypt", "OK"),
}

# Common default passwords found in embedded firmware
_COMMON_PASSWORDS = [
    "admin", "root", "password", "1234", "12345", "123456",
    "default", "changeme", "toor", "pass", "guest", "user",
    "test", "administrator", "support",
]

# Patterns for string categorisation
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
# Validated IP regex — each octet 0-255 (replaces weak \d{1,3} pattern)
_IP_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_FILEPATH_RE = re.compile(r"(?:/[\w._-]+){2,}")
_CRED_RE = re.compile(
    r"(?:password|passwd|secret|api_key|token|credential)\s*[=:]\s*\S+",
    re.IGNORECASE,
)

# Crypto file extensions
_CRYPTO_EXTENSIONS = {
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".pub",
}

# SSH key filenames
_SSH_KEY_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
}

# PEM header patterns
_PEM_HEADER_RE = re.compile(
    r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?(PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----"
)

# Credential and API key patterns — shared with security audit service
from app.utils.credential_patterns import (
    API_KEY_PATTERNS as _API_KEY_PATTERNS,
    CREDENTIAL_PATTERNS as _CREDENTIAL_PATTERNS,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


async def _run_subprocess(
    args: list[str], cwd: str, timeout: int = 30
) -> tuple[str, str]:
    """Run a subprocess asynchronously with timeout.

    Returns (stdout, stderr) as strings.
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"Command timed out after {timeout}s: {args[0]}")
    return stdout.decode("utf-8", errors="replace"), stderr.decode(
        "utf-8", errors="replace"
    )


def _categorize_strings(lines: list[str]) -> dict[str, list[str]]:
    """Categorize extracted strings into meaningful groups."""
    categories: dict[str, list[str]] = {
        "urls": [],
        "ip_addresses": [],
        "email_addresses": [],
        "file_paths": [],
        "potential_credentials": [],
        "other": [],
    }
    seen: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)

        categorized = False
        if _URL_RE.search(line):
            categories["urls"].append(line)
            categorized = True
        if _IP_RE.search(line):
            categories["ip_addresses"].append(line)
            categorized = True
        if _EMAIL_RE.search(line):
            categories["email_addresses"].append(line)
            categorized = True
        if _CRED_RE.search(line):
            categories["potential_credentials"].append(line)
            categorized = True
        if _FILEPATH_RE.search(line) and not categorized:
            categories["file_paths"].append(line)
            categorized = True
        if not categorized:
            categories["other"].append(line)

    return categories


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_text_file(path: str) -> bool:
    """Check if a file is likely text by scanning for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" not in chunk
    except (OSError, PermissionError):
        return False


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_extract_strings(input: dict, context: ToolContext) -> str:
    """Extract and categorize interesting strings from a file."""
    path = context.resolve_path(input["path"])
    min_length = input.get("min_length", 6)
    max_results = input.get("max_results", MAX_STRINGS)
    if max_results <= 0:
        max_results = None  # unlimited

    if not os.path.isfile(path):
        return f"Error: '{input['path']}' is not a file."

    stdout, _ = await _run_subprocess(
        ["strings", "-n", str(min_length), path],
        cwd=context.extracted_path,
    )

    lines = stdout.splitlines()
    total_count = len(lines)
    categories = _categorize_strings(lines)

    # Build output
    parts: list[str] = [
        f"Extracted strings from {input['path']} ({total_count} total, min length {min_length}):",
        "",
    ]

    shown = 0
    for cat_name, cat_items in categories.items():
        if not cat_items:
            continue
        label = cat_name.replace("_", " ").title()
        parts.append(f"## {label} ({len(cat_items)} found)")
        for item in cat_items:
            if max_results is not None and shown >= max_results:
                break
            parts.append(f"  {item}")
            shown += 1
        parts.append("")
        if max_results is not None and shown >= max_results:
            parts.append(f"... [truncated: showing {max_results} of {total_count} strings]")
            break

    return "\n".join(parts)


async def _handle_search_strings(input: dict, context: ToolContext) -> str:
    """Search for a regex pattern across firmware filesystem files."""
    pattern = input["pattern"]
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    max_results = input.get("max_results", MAX_GREP_RESULTS)
    if max_results <= 0:
        max_results = 100000  # effectively unlimited

    try:
        stdout, _ = await _run_subprocess(
            [
                "grep", "-rn",
                "--binary-files=without-match",
                f"--max-count={max_results}",
                "-E", pattern,
                search_path,
            ],
            cwd=context.extracted_path,
            timeout=30,
        )
    except TimeoutError:
        return f"Search timed out after 30s. Try a more specific pattern or path."

    if not stdout.strip():
        return f"No matches found for pattern '{pattern}'."

    lines = stdout.strip().splitlines()

    # Convert absolute paths to firmware-relative paths
    results: list[str] = []
    for line in lines[:max_results]:
        if line.startswith(real_root):
            line = line[len(real_root):]
            if not line.startswith("/"):
                line = "/" + line
        results.append(line)

    header = f"Found {len(results)} match(es) for '{pattern}'"
    if len(lines) > max_results:
        header += f" (showing first {max_results})"
    header += ":\n"

    return header + "\n".join(results)


def _find_crypto_material_sync(
    search_path: str, real_root: str,
) -> dict[str, list[str]]:
    """Synchronous filesystem walk for cryptographic material.

    Walks ``search_path`` and classifies files by SSH key name, PEM header
    contents, or crypto-related extension. Returns the findings dict; the
    async caller wraps this via ``run_in_executor`` (Rule #5).
    """
    findings: dict[str, list[str]] = {
        "private_keys": [],
        "certificates": [],
        "public_keys": [],
        "ssh_keys": [],
        "crypto_files": [],
    }

    for dirpath, _dirs, files in safe_walk(search_path):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            rel_path = "/" + os.path.relpath(abs_path, real_root)

            _, ext = os.path.splitext(name)
            ext = ext.lower()

            # Check SSH key filenames
            if name in _SSH_KEY_NAMES:
                findings["ssh_keys"].append(rel_path)
                continue

            # Try PEM header detection for text files
            pem_matched = False
            if os.path.isfile(abs_path) and os.path.getsize(abs_path) <= 1_000_000:
                if _is_text_file(abs_path):
                    try:
                        with open(abs_path, "r", errors="replace") as f:
                            header = f.read(4096)
                        match = _PEM_HEADER_RE.search(header)
                        if match:
                            pem_matched = True
                            kind = match.group(2)
                            if "PRIVATE" in kind:
                                findings["private_keys"].append(rel_path)
                            elif "CERTIFICATE" in kind:
                                findings["certificates"].append(rel_path)
                            elif "PUBLIC" in kind:
                                findings["public_keys"].append(rel_path)
                    except (OSError, PermissionError):
                        pass

            # Fall back to extension-based detection
            if not pem_matched and ext in _CRYPTO_EXTENSIONS:
                findings["crypto_files"].append(f"{rel_path} ({ext})")

    return findings


async def _handle_find_crypto_material(input: dict, context: ToolContext) -> str:
    """Find cryptographic keys, certificates, and related files."""
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)

    loop = asyncio.get_running_loop()
    findings = await loop.run_in_executor(
        None, _find_crypto_material_sync, search_path, real_root,
    )

    # Build output
    total = sum(len(v) for v in findings.values())
    if total == 0:
        return "No cryptographic material found."

    parts: list[str] = [f"Found {total} crypto-related file(s):", ""]
    display_limit = 30
    for cat_name, items in findings.items():
        if not items:
            continue
        label = cat_name.replace("_", " ").title()
        parts.append(f"## {label} ({len(items)})")
        for item in items[:display_limit]:
            parts.append(f"  {item}")
        if len(items) > display_limit:
            parts.append(f"  ... and {len(items) - display_limit} more")
        parts.append("")

    return "\n".join(parts)


def _identify_hash_type(pw_hash: str) -> tuple[str, str]:
    """Identify password hash type and strength. Returns (type_name, strength)."""
    if not pw_hash or pw_hash in ("!", "*", "!!", "x", "NP", "LK"):
        return ("locked/disabled", "N/A")
    for prefix, (name, strength) in _HASH_TYPES.items():
        if pw_hash.startswith(prefix):
            return (name, strength)
    # No known prefix — likely DES (traditional crypt, 13 chars)
    if len(pw_hash) == 13 and pw_hash.isascii():
        return ("DES", "WEAK")
    return ("unknown", "UNKNOWN")


def _try_common_passwords(pw_hash: str) -> str | None:
    """Try cracking a hash against common default passwords."""
    try:
        import crypt
    except ImportError:
        return None

    for password in _COMMON_PASSWORDS:
        try:
            if crypt.crypt(password, pw_hash) == pw_hash:
                return password
        except Exception:
            continue
    return None


def _analyze_shadow_file(
    shadow_path: str, display_path: str, results: list[dict[str, str]],
) -> list[str]:
    """Analyze a shadow file for password security issues. Returns issue lines."""
    issues: list[str] = []
    try:
        with open(shadow_path, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                user = parts[0]
                pw_hash = parts[1]

                if not pw_hash or pw_hash in ("", "!"):
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}' has empty/disabled password hash: '{pw_hash}'",
                        "entropy": "n/a",
                        "category": "shadow",
                    })
                    if pw_hash == "":
                        issues.append(
                            f"  [CRITICAL] {display_path}:{line_num}: "
                            f"User '{user}' has NO password (empty hash)"
                        )
                    continue

                if pw_hash in ("*", "!!", "x", "NP", "LK"):
                    continue  # Properly locked account

                hash_type, strength = _identify_hash_type(pw_hash)

                if strength == "WEAK":
                    issues.append(
                        f"  [HIGH] {display_path}:{line_num}: "
                        f"User '{user}' uses weak {hash_type} password hash"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}': weak {hash_type} hash",
                        "entropy": "n/a",
                        "category": "shadow_weak_hash",
                    })

                # Try common passwords
                cracked = _try_common_passwords(pw_hash)
                if cracked:
                    issues.append(
                        f"  [CRITICAL] {display_path}:{line_num}: "
                        f"User '{user}' has default password: '{cracked}' "
                        f"(hash type: {hash_type})"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}': default password '{cracked}' ({hash_type})",
                        "entropy": "n/a",
                        "category": "shadow_cracked",
                    })
    except (OSError, PermissionError):
        pass
    return issues


def _analyze_passwd_file(
    passwd_path: str, display_path: str, results: list[dict[str, str]],
) -> list[str]:
    """Analyze a passwd file for security issues. Returns issue lines."""
    issues: list[str] = []
    try:
        with open(passwd_path, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user = parts[0]
                pw_field = parts[1]
                uid = parts[2]
                shell = parts[6]

                # Flag uid=0 non-root accounts
                if uid == "0" and user != "root":
                    issues.append(
                        f"  [HIGH] {display_path}:{line_num}: "
                        f"Non-root account '{user}' has UID 0 (root-equivalent)"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"UID 0 non-root account: {user}",
                        "entropy": "n/a",
                        "category": "passwd_uid0",
                    })

                # Flag empty password field with login shell
                no_login_shells = {
                    "/bin/false", "/usr/bin/false", "/sbin/nologin",
                    "/usr/sbin/nologin", "/bin/sync",
                }
                if pw_field == "" and shell.strip() not in no_login_shells:
                    issues.append(
                        f"  [CRITICAL] {display_path}:{line_num}: "
                        f"User '{user}' has empty password field with login shell '{shell.strip()}'"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"Empty password with shell: {user} ({shell.strip()})",
                        "entropy": "n/a",
                        "category": "passwd_empty",
                    })
    except (OSError, PermissionError):
        pass
    return issues


async def _handle_find_hardcoded_credentials(
    input: dict, context: ToolContext
) -> str:
    """Find hardcoded passwords, API keys, tokens, and other credentials."""
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    max_results = input.get("max_results", MAX_CRED_RESULTS)
    if max_results <= 0:
        max_results = 100000

    results: list[dict[str, str]] = []
    auth_issues: list[str] = []

    # Check /etc/shadow and /etc_ro/shadow for password security
    for shadow_rel in ["etc/shadow", "etc_ro/shadow"]:
        try:
            shadow_path = validate_path(real_root, shadow_rel)
        except ValueError:
            continue
        if os.path.isfile(shadow_path):
            issues = _analyze_shadow_file(shadow_path, f"/{shadow_rel}", results)
            auth_issues.extend(issues)

    # Check /etc/passwd and /etc_ro/passwd for account issues
    for passwd_rel in ["etc/passwd", "etc_ro/passwd"]:
        try:
            passwd_path = validate_path(real_root, passwd_rel)
        except ValueError:
            continue
        if os.path.isfile(passwd_path):
            issues = _analyze_passwd_file(passwd_path, f"/{passwd_rel}", results)
            auth_issues.extend(issues)

    # Walk filesystem for credential patterns
    for dirpath, _dirs, files in safe_walk(search_path):
        if len(results) >= max_results:
            break
        for name in files:
            if len(results) >= max_results:
                break

            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            if os.path.getsize(abs_path) > 1_000_000:
                continue
            if not _is_text_file(abs_path):
                continue

            rel_path = "/" + os.path.relpath(abs_path, real_root)

            try:
                with open(abs_path, "r", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if len(results) >= max_results:
                            break
                        matched = False
                        # Check cloud/service API key patterns first (higher value)
                        for pat, category, severity in _API_KEY_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(0)
                                results.append({
                                    "file": rel_path,
                                    "line": str(line_num),
                                    "match": line.strip()[:200],
                                    "entropy": f"{_shannon_entropy(value):.2f}",
                                    "category": category,
                                    "severity": severity,
                                })
                                matched = True
                                break
                        if matched:
                            continue
                        # Fallback to generic credential patterns
                        for pat in _CREDENTIAL_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(1)
                                entropy = _shannon_entropy(value)
                                results.append({
                                    "file": rel_path,
                                    "line": str(line_num),
                                    "match": line.strip()[:200],
                                    "entropy": f"{entropy:.2f}",
                                    "category": "credential_pattern",
                                })
                                break  # one match per line
            except (OSError, PermissionError):
                continue

    if not results and not auth_issues:
        return "No hardcoded credentials found."

    # Build output
    parts: list[str] = [f"Found {len(results)} potential credential(s):", ""]

    # Authentication issues section (shadow/passwd analysis)
    if auth_issues:
        parts.append(f"## Authentication Issues ({len(auth_issues)})")
        parts.extend(auth_issues)
        parts.append("")

    # API key findings (cloud/service tokens) — show first, highest priority
    api_key_results = [r for r in results if r.get("severity")]
    if api_key_results:
        parts.append(f"## API Keys & Service Tokens ({len(api_key_results)})")
        for r in api_key_results:
            parts.append(f"  [{r['severity'].upper()}] {r['category']}")
            parts.append(f"    {r['file']}:{r['line']}")
            parts.append(f"    {r['match']}")
        parts.append("")

    # Separate remaining results by entropy
    pattern_results = [r for r in results if r.get("category") == "credential_pattern"]

    high_entropy: list[dict[str, str]] = []
    low_entropy: list[dict[str, str]] = []
    for r in pattern_results:
        if r["entropy"] == "n/a" or float(r["entropy"]) > 4.0:
            high_entropy.append(r)
        else:
            low_entropy.append(r)

    if high_entropy:
        parts.append(f"## Likely Real Secrets (high entropy >4.0 bits) — {len(high_entropy)}")
        for r in high_entropy[:30]:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        if len(high_entropy) > 30:
            parts.append(f"  ... and {len(high_entropy) - 30} more")
        parts.append("")

    if low_entropy:
        parts.append(f"## Possible Credentials (lower entropy) — {len(low_entropy)}")
        for r in low_entropy[:20]:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        if len(low_entropy) > 20:
            parts.append(f"  ... and {len(low_entropy) - 20} more")
        parts.append("")

    if len(results) >= max_results:
        parts.append(f"... [truncated: showing first {max_results} results]")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Hardcoded IP detection
# ---------------------------------------------------------------------------

import ipaddress as _ipaddress

# Well-known IPs — label instead of flagging as unknown
_WELL_KNOWN_IPS: dict[str, str] = {
    "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "77.88.8.8": "Yandex DNS", "77.88.8.1": "Yandex DNS",
    "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS",
    "76.76.2.0": "Control D DNS",
    "129.6.15.28": "NIST NTP", "132.163.97.1": "NIST NTP",
    "128.138.140.44": "NIST NTP",
    "128.105.39.11": "Netgear hardcoded NTP (known issue)",
    "17.253.34.253": "Apple NTP (time.apple.com)",
}

# Subnet masks to exclude
_SUBNET_MASKS = frozenset({
    "255.255.255.0", "255.255.0.0", "255.0.0.0",
    "255.255.255.128", "255.255.255.192", "255.255.255.224",
    "255.255.255.240", "255.255.255.248", "255.255.255.252",
    "255.255.128.0", "255.255.192.0", "255.255.224.0",
    "255.255.240.0", "255.255.248.0", "255.255.252.0",
    "255.255.254.0", "255.255.255.255",
})

# Context patterns that suggest version strings (look-behind window)
_VERSION_CONTEXT_RE = re.compile(
    r"(?:version|ver|v|release|build|fw|rev|patch|sdk)\s*[:=]?\s*$",
    re.IGNORECASE,
)

# High-risk context patterns (raise severity)
_HIGH_RISK_CONTEXT_RE = re.compile(
    r"(?:wget|curl|nc|netcat|tftp|ftp|ssh|scp|rsync)\b", re.IGNORECASE,
)


def _classify_ip(ip_str: str) -> tuple[str, str]:
    """Classify an IP address. Returns (category, severity)."""
    try:
        addr = _ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid", "info"

    if ip_str in _SUBNET_MASKS:
        return "subnet_mask", "skip"
    if ip_str in ("0.0.0.0", "255.255.255.255"):
        return "broadcast", "skip"
    if ip_str in _WELL_KNOWN_IPS:
        return f"well_known:{_WELL_KNOWN_IPS[ip_str]}", "info"
    if addr.is_loopback:
        return "loopback", "info"
    if addr.is_link_local:
        return "link_local", "info"
    if addr.is_multicast:
        return "multicast", "skip"
    if addr.is_private:
        return "private_rfc1918", "low"
    # RFC 5737 documentation ranges
    if ip_str.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return "documentation", "skip"
    return "public", "medium"


def _is_version_context(text: str, match_start: int) -> bool:
    """Check if the IP match looks like a version string."""
    prefix = text[max(0, match_start - 30):match_start]
    return bool(_VERSION_CONTEXT_RE.search(prefix))


def _is_oid_context(text: str, match_start: int) -> bool:
    """Check if the IP match is part of an ASN.1 OID (e.g., 1.3.6.1.x)."""
    prefix = text[max(0, match_start - 10):match_start]
    return bool(re.search(r"\d+\.\d+\.$", prefix))


async def _handle_find_hardcoded_ips(input: dict, context: ToolContext) -> str:
    """Scan firmware for hardcoded IP addresses with classification.

    Phase 3b: when no explicit ``path`` is supplied the scan walks every
    detection root so scatter-zip siblings / raw-image dirs are covered
    alongside the rootfs. Relative paths are computed against whichever
    detection root owns the file.
    """
    from app.utils.truncation import truncate_output

    input_path = input.get("path")
    include_private = input.get("include_private", True)
    include_binaries = input.get("include_binaries", True)
    max_results = input.get("max_results", 200)

    # Collect scan roots: either the explicit path, or every detection
    # root. The real-root list is used downstream for relative-path
    # resolution so a file in ``/DPCS10_fixture/boot/ramdisk`` shows as
    # ``/boot/ramdisk`` under its own partition instead of getting a
    # ``..`` relpath.
    if input_path and input_path not in ("/", ""):
        scan_roots = [context.resolve_path(input_path)]
    else:
        scan_roots = list(context.get_detection_roots() or [context.extracted_path])
    real_roots = [os.path.realpath(r) for r in scan_roots if r]

    findings: list[dict] = []
    files_scanned = 0
    ips_found: Counter = Counter()
    # Track resolved real paths to avoid re-scanning hardlinks/symlinks
    scanned_realpaths: set[str] = set()

    def _relpath_for(fpath: str) -> str:
        for rr in real_roots:
            if fpath.startswith(rr + os.sep) or fpath == rr:
                return "/" + os.path.relpath(fpath, rr)
        fallback = context.extracted_path or (real_roots[0] if real_roots else fpath)
        return "/" + os.path.relpath(fpath, fallback)

    for scan_root in scan_roots:
      for dirpath, _dirnames, filenames in safe_walk(scan_root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = _relpath_for(fpath)

            try:
                real = os.path.realpath(fpath)
                fstat = os.stat(fpath)
            except OSError:
                continue
            if fstat.st_size > 10 * 1024 * 1024:  # 10MB max
                continue

            # Determine if text or binary
            is_binary = False
            try:
                with open(fpath, "rb") as f:
                    chunk = f.read(512)
                if b"\x00" in chunk:
                    is_binary = True
            except OSError:
                continue

            if is_binary and not include_binaries:
                continue

            # Skip binaries we've already scanned (symlinks/hardlinks to same file)
            if is_binary and real in scanned_realpaths:
                files_scanned += 1
                continue
            if is_binary:
                scanned_realpaths.add(real)

            files_scanned += 1

            # For text files, read content directly
            # For binary files, use strings extraction
            if is_binary:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "strings", "-n", "7", fpath,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                    content = stdout.decode("utf-8", errors="replace")
                except (asyncio.TimeoutError, OSError):
                    continue
            else:
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                except OSError:
                    continue

            for match in _IP_RE.finditer(content):
                ip_str = match.group()
                category, severity = _classify_ip(ip_str)

                if severity == "skip":
                    continue
                if not include_private and category == "private_rfc1918":
                    continue

                # False positive filters
                if _is_version_context(content, match.start()):
                    continue
                if _is_oid_context(content, match.start()):
                    continue

                ips_found[ip_str] += 1

                # Context-based severity adjustment
                ctx_start = max(0, match.start() - 60)
                ctx_end = min(len(content), match.end() + 60)
                context_str = content[ctx_start:ctx_end].strip()

                if _HIGH_RISK_CONTEXT_RE.search(context_str):
                    if severity == "medium":
                        severity = "high"
                    elif severity == "low":
                        severity = "medium"

                findings.append({
                    "ip": ip_str,
                    "file": rel,
                    "category": category,
                    "severity": severity,
                    "context": context_str[:120],
                    "binary": is_binary,
                })

                if len(findings) >= max_results:
                    break
            if len(findings) >= max_results:
                break
        if len(findings) >= max_results:
            break

    # Format output — group by IP, not by file occurrence
    lines = [f"Scanned {files_scanned} files, found {len(findings)} IP references ({len(ips_found)} unique IPs)\n"]

    # Build per-IP grouped data with highest severity
    ip_data: dict[str, dict] = {}
    for f in findings:
        ip = f["ip"]
        if ip not in ip_data:
            ip_data[ip] = {
                "category": f["category"],
                "severity": f["severity"],
                "files": [],
                "contexts": [],
            }
        entry = ip_data[ip]
        # Keep highest severity
        sev_order = {"high": 3, "medium": 2, "low": 1, "info": 0}
        if sev_order.get(f["severity"], 0) > sev_order.get(entry["severity"], 0):
            entry["severity"] = f["severity"]
        if f["file"] not in [x[0] for x in entry["files"]]:
            entry["files"].append((f["file"], f["binary"]))
        if f["context"] and len(entry["contexts"]) < 3:
            entry["contexts"].append(f["context"][:100])

    # Sort IPs by severity (high first), then by file count
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_ips = sorted(
        ip_data.items(),
        key=lambda x: (sev_order.get(x[1]["severity"], 9), -len(x[1]["files"])),
    )

    for sev in ["high", "medium", "low", "info"]:
        sev_ips = [(ip, d) for ip, d in sorted_ips if d["severity"] == sev]
        if not sev_ips:
            continue
        lines.append(f"\n## {sev.upper()} ({len(sev_ips)} IPs)")
        for ip, data in sev_ips:
            cat_tag = f" [{data['category']}]" if ":" in data["category"] else ""
            file_count = len(data["files"])
            lines.append(f"  {ip}{cat_tag} — found in {file_count} file(s)")
            # Show up to 5 files, summarize the rest
            for fpath, is_bin in data["files"][:20]:
                bin_tag = " (binary)" if is_bin else ""
                lines.append(f"    {fpath}{bin_tag}")
            if file_count > 20:
                lines.append(f"    ... and {file_count - 20} more files")
            # Show context for high/medium
            if sev in ("high", "medium") and data["contexts"]:
                lines.append(f"    context: {data['contexts'][0]}")

    # Summary of unique IPs
    if ips_found:
        lines.append(f"\n## Top IPs (by occurrence)")
        for ip, count in ips_found.most_common(20):
            cat, _ = _classify_ip(ip)
            lines.append(f"  {ip} ({count}x) [{cat}]")

    return truncate_output("\n".join(lines))


def register_string_tools(registry: ToolRegistry) -> None:
    """Register all string analysis tools with the given registry."""

    registry.register(
        name="extract_strings",
        description=(
            "Extract and categorize interesting strings from a file (binary or text). "
            "Strings are categorized into: URLs, IP addresses, email addresses, "
            "file paths, potential credentials, and other."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to extract strings from",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length (default: 6)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum strings to return (default: 200, set to 0 for all)",
                },
            },
            "required": ["path"],
        },
        handler=_handle_extract_strings,
    )

    registry.register(
        name="search_strings",
        description=(
            "Search for a regex pattern across all text files in the firmware filesystem "
            "(like grep -rn). Returns matching lines with file paths and line numbers. "
            "Timeout: 30 seconds."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (extended regex syntax)",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": ["pattern"],
        },
        handler=_handle_search_strings,
    )

    registry.register(
        name="find_crypto_material",
        description=(
            "Scan the firmware filesystem for cryptographic material: "
            "private keys, certificates, public keys, SSH keys, "
            "and files with crypto-related extensions (.pem, .key, .crt, etc.). "
            "Also checks file contents for PEM headers."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": [],
        },
        handler=_handle_find_crypto_material,
    )

    registry.register(
        name="find_hardcoded_credentials",
        description=(
            "Search firmware filesystem for hardcoded passwords, API keys, tokens, "
            "and other credentials. Enhanced analysis includes:\n"
            "- /etc/shadow & /etc_ro/shadow: hash type identification (DES, MD5, "
            "SHA-256, SHA-512), weak hash flagging, and cracking against 15 common "
            "default passwords (admin, root, password, 1234, etc.)\n"
            "- /etc/passwd & /etc_ro/passwd: UID-0 non-root accounts, empty password "
            "fields with login shells\n"
            "- Filesystem scan: password/secret/token assignments in text files\n"
            "Results ranked by Shannon entropy."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": [],
        },
        handler=_handle_find_hardcoded_credentials,
    )

    registry.register(
        name="find_hardcoded_ips",
        description=(
            "Scan firmware filesystem for hardcoded IP addresses. Classifies each IP as "
            "public (medium-high severity), private/RFC1918 (low), well-known (Google DNS, "
            "Cloudflare, NTP servers — info), loopback, or link-local. Filters false positives: "
            "version strings, subnet masks, ASN.1 OIDs, documentation ranges. "
            "Severity is elevated when IPs appear near wget/curl/nc commands."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (default: entire firmware root)",
                },
                "include_private": {
                    "type": "boolean",
                    "description": "Include private/RFC1918 IPs in results (default: true)",
                    "default": True,
                },
                "include_binaries": {
                    "type": "boolean",
                    "description": "Scan ELF/binary files via strings extraction (default: true)",
                    "default": True,
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum IP references to return (default: 200)",
                    "default": 200,
                },
            },
            "required": [],
        },
        handler=_handle_find_hardcoded_ips,
    )
