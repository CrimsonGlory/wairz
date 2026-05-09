"""Security assessment AI tools for firmware analysis.

Tools for evaluating the security posture of an extracted firmware filesystem:
config file auditing, setuid detection, init script analysis, filesystem
permissions, CVE lookups, certificate analysis, YARA malware scanning,
and kernel configuration extraction and hardening analysis.
"""

import asyncio
import gzip
import json
import logging
import os
import re
import shutil
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.utils.sandbox import safe_walk, validate_path
from app.utils.truncation import truncate_output

logger = logging.getLogger(__name__)

MAX_RESULTS = 100  # default for MCP; overridable via max_results input param


def _get_limit(input: dict) -> int:
    """Read max_results from tool input, defaulting to MAX_RESULTS."""
    val = input.get("max_results", MAX_RESULTS)
    return val if val > 0 else 100000

# Certificate file extensions to scan for
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}

# Directories commonly containing certificates in firmware
_CERT_SEARCH_DIRS = [
    "etc/ssl", "etc/ssl/certs", "etc/ssl/private",
    "etc/pki", "etc/pki/tls", "etc/pki/tls/certs",
    "etc/certificates", "etc/https", "etc/lighttpd",
    "usr/share/ca-certificates", "etc/ca-certificates",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _walk_firmware(extracted_root: str, path: str | None) -> str:
    """Return the validated starting path for a filesystem walk."""
    return validate_path(extracted_root, path or "/")


def _rel(abs_path: str, extracted_root: str) -> str:
    """Return a firmware-relative path for display."""
    return "/" + os.path.relpath(abs_path, os.path.realpath(extracted_root))


# ---------------------------------------------------------------------------
# check_known_cves
# ---------------------------------------------------------------------------


async def _handle_check_known_cves(input: dict, context: ToolContext) -> str:
    """Look up known CVEs for a given component and version.

    Uses a local pattern database of commonly-vulnerable embedded Linux
    components.  This is intentionally offline — no external API calls — so
    results are best-effort.  The AI should cross-reference with its own
    knowledge for more complete coverage.
    """
    component = input["component"].strip().lower()
    version = input["version"].strip()

    # Lightweight offline CVE knowledge base for common embedded components.
    # Each entry: (component_pattern, version_check, cve_id, severity, summary)
    cve_db: list[tuple[str, str, str, str, str]] = [
        # BusyBox
        ("busybox", "<1.36.0", "CVE-2022-48174", "critical",
         "Stack overflow in BusyBox ash (awk applet) allows code execution"),
        ("busybox", "<1.35.0", "CVE-2022-28391", "high",
         "BusyBox DNS resolution use-after-free"),
        ("busybox", "<1.34.0", "CVE-2021-42386", "high",
         "BusyBox awk heap-use-after-free"),
        ("busybox", "<1.34.0", "CVE-2021-42385", "high",
         "BusyBox awk divide-by-zero"),
        ("busybox", "<1.34.0", "CVE-2021-42384", "high",
         "BusyBox awk use-after-free in evaluate"),
        # OpenSSL
        ("openssl", "<1.1.1w", "CVE-2023-5678", "medium",
         "OpenSSL DH key generation excessive time (DoS)"),
        ("openssl", "<3.0.12", "CVE-2023-5363", "medium",
         "OpenSSL incorrect cipher key/IV length processing"),
        ("openssl", "<1.1.1u", "CVE-2023-2650", "medium",
         "OpenSSL ASN1 object identifier DoS"),
        ("openssl", "<1.0.2", "CVE-2014-0160", "critical",
         "Heartbleed: TLS heartbeat buffer over-read"),
        # Dropbear SSH
        ("dropbear", "<2022.83", "CVE-2021-36369", "high",
         "Dropbear trivial authentication bypass via empty password"),
        ("dropbear", "<2020.81", "CVE-2020-36254", "high",
         "Dropbear MITM attack due to algorithm negotiation issue"),
        # dnsmasq
        ("dnsmasq", "<2.86", "CVE-2021-3448", "medium",
         "dnsmasq DNS rebinding protection bypass"),
        ("dnsmasq", "<2.83", "CVE-2020-25681", "critical",
         "dnsmasq DNSpooq heap buffer overflow in DNSSEC"),
        # lighttpd
        ("lighttpd", "<1.4.72", "CVE-2023-3447", "medium",
         "lighttpd use-after-free in h2 connection handling"),
        # curl
        ("curl", "<8.4.0", "CVE-2023-38545", "critical",
         "SOCKS5 heap buffer overflow in curl"),
        ("curl", "<7.87.0", "CVE-2022-43551", "high",
         "curl HSTS bypass via IDN encoding"),
        # uClibc / uClibc-ng
        ("uclibc", "<1.0.43", "CVE-2022-30295", "high",
         "uClibc-ng DNS transaction ID predictability"),
        # Linux kernel (common embedded versions)
        ("linux", "<5.15.0", "CVE-2022-0847", "critical",
         "DirtyPipe: arbitrary file overwrite via splice"),
        ("linux", "<5.4.0", "CVE-2021-22555", "high",
         "Netfilter heap-out-of-bounds write for privilege escalation"),
    ]

    def _version_tuple(v: str) -> tuple[int, ...]:
        """Parse a version string to a comparable tuple."""
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts) if parts else (0,)

    ver = _version_tuple(version)
    matches: list[str] = []

    for comp_pat, ver_check, cve_id, severity, summary in cve_db:
        if comp_pat not in component:
            continue
        # Parse the version check (only supports "<X.Y.Z" for simplicity)
        m = re.match(r"<(.+)", ver_check)
        if m:
            threshold = _version_tuple(m.group(1))
            if ver < threshold:
                matches.append(
                    f"  [{severity.upper()}] {cve_id}\n"
                    f"    {summary}\n"
                    f"    Affected: {comp_pat} {ver_check}, your version: {version}"
                )

    if not matches:
        return (
            f"No known CVEs found for {component} {version} in the local database.\n"
            "Note: This database covers common embedded components only. "
            "Cross-reference with NVD or other sources for comprehensive results."
        )

    header = f"Found {len(matches)} potential CVE(s) for {component} {version}:\n"
    return header + "\n\n".join(matches)


# ---------------------------------------------------------------------------
# analyze_config_security
# ---------------------------------------------------------------------------

# Patterns for common insecure config settings
_CONFIG_CHECKS: list[tuple[str, str, re.Pattern, str, str]] = [
    # (filename_pattern, check_name, regex, severity, description)
    ("shadow", "empty_password",
     re.compile(r"^([^:]+)::"), "critical",
     "Account '{match}' has an empty password hash — no password required for login"),
    ("shadow", "weak_hash_des",
     re.compile(r"^([^:]+):[^$!*x]"), "high",
     "Account '{match}' uses DES password hash (trivially crackable)"),
    ("passwd", "uid0_extra",
     re.compile(r"^(?!root:)([^:]+):[^:]*:0:"), "high",
     "Non-root account '{match}' has UID 0 (root-equivalent)"),
    ("passwd", "no_password_field",
     re.compile(r"^([^:]+)::"), "medium",
     "Account '{match}' has empty password field in passwd"),
    ("sshd_config", "root_login",
     re.compile(r"^\s*PermitRootLogin\s+(yes|without-password)", re.IGNORECASE), "high",
     "SSH allows root login (PermitRootLogin {match})"),
    ("sshd_config", "password_auth",
     re.compile(r"^\s*PasswordAuthentication\s+yes", re.IGNORECASE), "medium",
     "SSH allows password authentication (prefer key-based auth)"),
    ("sshd_config", "empty_passwords",
     re.compile(r"^\s*PermitEmptyPasswords\s+yes", re.IGNORECASE), "critical",
     "SSH allows empty passwords"),
    ("httpd.conf", "dir_listing",
     re.compile(r"^\s*Options\s+.*Indexes", re.IGNORECASE), "medium",
     "Apache directory listing enabled (Options Indexes)"),
    ("lighttpd.conf", "dir_listing",
     re.compile(r'^\s*dir-listing\.activate\s*=\s*"enable"', re.IGNORECASE), "medium",
     "Lighttpd directory listing enabled"),
    ("telnetd", "telnet_enabled",
     re.compile(r"telnetd", re.IGNORECASE), "high",
     "Telnet daemon enabled — sends credentials in plaintext"),
]


async def _handle_analyze_config_security(input: dict, context: ToolContext) -> str:
    """Analyze a specific config file for common insecure settings."""
    path = input["path"]
    full_path = context.resolve_path(path)

    if not os.path.isfile(full_path):
        return f"Error: '{path}' is not a file."

    try:
        with open(full_path, errors="replace") as f:
            content = f.read(256_000)  # 256KB limit
    except PermissionError:
        return f"Error: Cannot read '{path}' — permission denied."

    basename = os.path.basename(full_path).lower()
    findings: list[str] = []

    for fname_pattern, check_name, regex, severity, desc_template in _CONFIG_CHECKS:
        if fname_pattern not in basename and fname_pattern not in path.lower():
            continue
        for line_num, line in enumerate(content.splitlines(), 1):
            m = regex.search(line)
            if m:
                match_val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                desc = desc_template.format(match=match_val)
                findings.append(
                    f"  [{severity.upper()}] Line {line_num}: {desc}\n"
                    f"    {line.rstrip()}"
                )

    # Generic checks applicable to any config file
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip().lower()
        # Debug mode flags
        if re.search(r"\bdebug\s*[=:]\s*(true|1|on|yes)\b", stripped, re.IGNORECASE):
            findings.append(
                f"  [LOW] Line {line_num}: Debug mode appears to be enabled\n"
                f"    {line.rstrip()}"
            )
        # Default/common passwords in config values
        for pwd in ("admin", "password", "1234", "default", "root", "toor", "changeme"):
            if re.search(rf"\b(password|passwd|pass|pwd|secret)\s*[=:]\s*['\"]?{pwd}\b",
                         stripped, re.IGNORECASE):
                findings.append(
                    f"  [HIGH] Line {line_num}: Possible default/weak password\n"
                    f"    {line.rstrip()}"
                )
                break  # one match per line

    if not findings:
        return f"No obvious security issues found in '{path}'."

    limit = _get_limit(input)
    header = f"Found {len(findings)} potential issue(s) in '{path}':\n\n"
    return header + "\n\n".join(findings[:limit])


# ---------------------------------------------------------------------------
# check_setuid_binaries
# ---------------------------------------------------------------------------


def _check_setuid_binaries_sync(
    search_root: str, real_root: str, limit: int,
) -> tuple[list[str], list[str]]:
    """Synchronous walk for setuid/setgid binary detection.

    Returns (setuid_files, setgid_files). The async caller wraps this via
    ``run_in_executor`` (Rule #5).
    """
    setuid_files: list[str] = []
    setgid_files: list[str] = []

    for dirpath, _dirs, files in safe_walk(search_root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            rel = _rel(abs_path, real_root)
            mode = st.st_mode

            if mode & stat.S_ISUID:
                owner = f"uid={st.st_uid}"
                setuid_files.append(f"  SETUID  {oct(mode)[-4:]}  {owner}  {rel}")
            if mode & stat.S_ISGID:
                owner = f"gid={st.st_gid}"
                setgid_files.append(f"  SETGID  {oct(mode)[-4:]}  {owner}  {rel}")

            if len(setuid_files) + len(setgid_files) >= limit:
                break
        if len(setuid_files) + len(setgid_files) >= limit:
            break

    return setuid_files, setgid_files


async def _handle_check_setuid_binaries(input: dict, context: ToolContext) -> str:
    """Find all setuid/setgid files in the firmware filesystem."""
    input_path = input.get("path") or "/"
    search_root = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    limit = _get_limit(input)

    loop = asyncio.get_running_loop()
    setuid_files, setgid_files = await loop.run_in_executor(
        None, _check_setuid_binaries_sync, search_root, real_root, limit,
    )

    lines: list[str] = []

    if setuid_files:
        lines.append(f"Setuid binaries ({len(setuid_files)}):")
        lines.append("  These run with the file owner's privileges regardless of who executes them.")
        lines.append("")
        lines.extend(setuid_files)
        lines.append("")

    if setgid_files:
        lines.append(f"Setgid binaries ({len(setgid_files)}):")
        lines.append("  These run with the file group's privileges.")
        lines.append("")
        lines.extend(setgid_files)
        lines.append("")

    if not lines:
        return "No setuid or setgid binaries found."

    # Security note
    lines.append(
        "Note: Setuid-root binaries are common attack targets. "
        "Check each for known vulnerabilities and unnecessary permissions."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_init_scripts
# ---------------------------------------------------------------------------

# Known network-facing services that are security-relevant
_KNOWN_SERVICES = {
    "telnetd": ("high", "Telnet daemon — plaintext credential transmission"),
    "ftpd": ("high", "FTP daemon — plaintext credential transmission"),
    "vsftpd": ("medium", "FTP daemon (vsftpd)"),
    "tftpd": ("high", "TFTP daemon — unauthenticated file access"),
    "httpd": ("info", "HTTP server"),
    "lighttpd": ("info", "Lighttpd HTTP server"),
    "nginx": ("info", "Nginx HTTP/reverse proxy"),
    "uhttpd": ("info", "uHTTPd (OpenWrt web server)"),
    "sshd": ("info", "SSH daemon"),
    "dropbear": ("info", "Dropbear SSH daemon"),
    "dnsmasq": ("info", "DNS/DHCP server"),
    "miniupnpd": ("medium", "UPnP daemon — may expose internal services"),
    "snmpd": ("medium", "SNMP daemon — check community strings"),
    "mosquitto": ("info", "MQTT broker"),
    "upnpd": ("medium", "UPnP daemon"),
    "smbd": ("medium", "Samba file sharing"),
    "nmbd": ("medium", "NetBIOS name service"),
}


async def _handle_analyze_init_scripts(input: dict, context: ToolContext) -> str:
    """Parse init scripts and inittab to identify services started at boot."""
    input_path = input.get("path") or "/"
    real_root = context.real_root_for(input_path)
    search_root = context.resolve_path(input_path)

    services: list[str] = []
    raw_entries: list[str] = []

    # 1. Check /etc/inittab
    inittab_path = validate_path(real_root, "etc/inittab")
    if os.path.isfile(inittab_path):
        try:
            with open(inittab_path, errors="replace") as f:
                for line_num, line in enumerate(f.readlines()[:200], 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw_entries.append(f"  inittab:{line_num}: {line}")
                    # Check for respawn entries and service names
                    for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                        if svc_name in line.lower():
                            services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                            services.append(f"    Source: /etc/inittab:{line_num}")
                            break
        except (PermissionError, OSError):
            pass

    # 2. Check /etc/init.d/ scripts
    initd_path = validate_path(real_root, "etc/init.d")
    if os.path.isdir(initd_path):
        for script_name in sorted(os.listdir(initd_path)):
            script_path = os.path.join(initd_path, script_name)
            if not os.path.isfile(script_path):
                continue
            raw_entries.append(f"  /etc/init.d/{script_name}")

            try:
                with open(script_path, errors="replace") as f:
                    content = f.read(8192).lower()
            except (PermissionError, OSError):
                continue

            for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                if svc_name in content:
                    services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                    services.append(f"    Source: /etc/init.d/{script_name}")

    # 3. Check /etc/rc.d/ (common in OpenWrt)
    rcd_path = validate_path(real_root, "etc/rc.d")
    if os.path.isdir(rcd_path):
        for link_name in sorted(os.listdir(rcd_path)):
            raw_entries.append(f"  /etc/rc.d/{link_name}")

    # 4. Check systemd units
    for systemd_dir in ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"):
        sd_path = validate_path(real_root, systemd_dir)
        if not os.path.isdir(sd_path):
            continue
        for unit_name in sorted(os.listdir(sd_path)):
            if not unit_name.endswith(".service"):
                continue
            raw_entries.append(f"  {systemd_dir}/{unit_name}")
            unit_path = os.path.join(sd_path, unit_name)
            try:
                with open(unit_path, errors="replace") as f:
                    content = f.read(4096).lower()
            except (PermissionError, OSError):
                continue

            for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                if svc_name in content:
                    services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                    services.append(f"    Source: {systemd_dir}/{unit_name}")

    lines: list[str] = []

    # Deduplicate services
    seen = set()
    unique_services: list[str] = []
    for s in services:
        if s not in seen:
            seen.add(s)
            unique_services.append(s)

    if unique_services:
        lines.append(f"Network/security-relevant services ({len(unique_services) // 2}):")
        lines.append("")
        lines.extend(unique_services)
        lines.append("")

    if raw_entries:
        lines.append(f"All init entries found ({len(raw_entries)}):")
        lines.append("")
        init_limit = _get_limit(input)
        lines.extend(raw_entries[:init_limit])
    else:
        lines.append("No init scripts, inittab, or systemd units found.")

    return "\n".join(lines) if lines else "No init system configuration found."


# ---------------------------------------------------------------------------
# check_filesystem_permissions
# ---------------------------------------------------------------------------

# Sensitive paths where weak permissions matter most
_SENSITIVE_PATHS = {
    "etc/shadow", "etc/shadow-", "etc/gshadow",
    "etc/passwd", "etc/group",
    "etc/ssh", "etc/dropbear",
}

_SENSITIVE_PATTERNS = re.compile(
    r"(\.pem|\.key|\.crt|id_rsa|id_dsa|id_ecdsa|id_ed25519|"
    r"authorized_keys|\.htpasswd|\.env|credentials|secrets)"
)


def _check_filesystem_permissions_sync(
    search_root: str, real_root: str, limit: int,
) -> tuple[list[str], list[str]]:
    """Synchronous walk to detect world-writable files and weak perms.

    Returns (world_writable, sensitive_weak). The async caller wraps this via
    ``run_in_executor`` (Rule #5).
    """
    world_writable: list[str] = []
    sensitive_weak: list[str] = []

    for dirpath, dirs, files in safe_walk(search_root):
        for name in files + dirs:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue

            mode = st.st_mode
            rel = _rel(abs_path, real_root)
            perm_str = oct(mode)[-4:]

            # World-writable files (not symlinks)
            if stat.S_ISREG(mode) and (mode & stat.S_IWOTH):
                world_writable.append(f"  {perm_str}  {rel}")

            # World-writable directories without sticky bit
            if stat.S_ISDIR(mode) and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                world_writable.append(f"  {perm_str}  {rel}/  (no sticky bit)")

            # Sensitive files with loose permissions
            rel_stripped = rel.lstrip("/")
            is_sensitive = (
                rel_stripped in _SENSITIVE_PATHS
                or _SENSITIVE_PATTERNS.search(name)
            )
            if is_sensitive and stat.S_ISREG(mode):
                # Sensitive files should not be world-readable
                if mode & stat.S_IROTH:
                    sensitive_weak.append(
                        f"  {perm_str}  {rel}  (world-readable sensitive file)"
                    )
                # Private keys should be owner-only
                if name.endswith((".key", ".pem")) or name.startswith("id_"):
                    if (mode & 0o077) != 0:
                        sensitive_weak.append(
                            f"  {perm_str}  {rel}  (private key accessible by group/others)"
                        )

            total = len(world_writable) + len(sensitive_weak)
            if total >= limit:
                break
        if len(world_writable) + len(sensitive_weak) >= limit:
            break

    return world_writable, sensitive_weak


async def _handle_check_filesystem_permissions(input: dict, context: ToolContext) -> str:
    """Check for world-writable files and weak permissions on sensitive files."""
    input_path = input.get("path") or "/"
    search_root = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    limit = _get_limit(input)

    loop = asyncio.get_running_loop()
    world_writable, sensitive_weak = await loop.run_in_executor(
        None, _check_filesystem_permissions_sync, search_root, real_root, limit,
    )

    lines: list[str] = []

    if world_writable:
        lines.append(f"World-writable files/directories ({len(world_writable)}):")
        lines.append("  These can be modified by any user on the system.")
        lines.append("")
        lines.extend(world_writable[:50])
        lines.append("")

    if sensitive_weak:
        lines.append(f"Sensitive files with weak permissions ({len(sensitive_weak)}):")
        lines.append("")
        lines.extend(sensitive_weak[:50])
        lines.append("")

    if not lines:
        return "No obvious filesystem permission issues found."

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_certificate
# ---------------------------------------------------------------------------


def _find_cert_files(extracted_root: str, search_path: str | None) -> list[str]:
    """Find certificate files in the firmware filesystem."""
    real_root = os.path.realpath(extracted_root)
    cert_files: list[str] = []

    if search_path:
        # Scan a specific file or directory — validate against sandbox
        full_path = validate_path(real_root, search_path)
        if os.path.isfile(full_path):
            return [full_path]
        if os.path.isdir(full_path):
            for dirpath, _dirs, files in safe_walk(full_path):
                for name in files:
                    _, ext = os.path.splitext(name)
                    if ext.lower() in _CERT_EXTENSIONS:
                        cert_files.append(os.path.join(dirpath, name))
                    elif _is_pem_file(os.path.join(dirpath, name)):
                        cert_files.append(os.path.join(dirpath, name))
            return cert_files

    # Scan known certificate directories
    for cert_dir in _CERT_SEARCH_DIRS:
        full_dir = validate_path(real_root, cert_dir)
        if not os.path.isdir(full_dir):
            continue
        for dirpath, _dirs, files in safe_walk(full_dir):
            for name in files:
                abs_path = os.path.join(dirpath, name)
                _, ext = os.path.splitext(name)
                if ext.lower() in _CERT_EXTENSIONS:
                    cert_files.append(abs_path)
                elif _is_pem_file(abs_path):
                    cert_files.append(abs_path)

    # Also scan entire filesystem for cert extensions if nothing found yet
    if not cert_files:
        for dirpath, _dirs, files in safe_walk(real_root):
            for name in files:
                _, ext = os.path.splitext(name)
                if ext.lower() in _CERT_EXTENSIONS:
                    cert_files.append(os.path.join(dirpath, name))
                if len(cert_files) >= 10000:
                    break
            if len(cert_files) >= 10000:
                break

    return cert_files


def _is_pem_file(path: str) -> bool:
    """Quick check if a file looks like PEM format."""
    try:
        with open(path, "rb") as f:
            header = f.read(64)
        return b"-----BEGIN" in header
    except (OSError, PermissionError):
        return False


def _audit_certificate(cert_data: bytes, file_path: str, real_root: str) -> dict:
    """Parse and audit a single certificate. Returns a dict with info and issues."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except ImportError:
        return {"error": "cryptography library not installed"}

    cert = None
    parse_error = None

    # Try PEM first, then DER
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception as exc:
            parse_error = str(exc)

    if cert is None:
        return {"error": f"Failed to parse certificate: {parse_error}"}

    rel_path = "/" + os.path.relpath(file_path, real_root)
    now = datetime.now(UTC)

    # Extract info
    info: dict = {
        "path": rel_path,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
    }

    # Key info
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        info["key_type"] = "RSA"
        info["key_size"] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        info["key_type"] = "EC"
        info["key_size"] = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        info["key_type"] = "DSA"
        info["key_size"] = pub_key.key_size
    else:
        info["key_type"] = type(pub_key).__name__
        info["key_size"] = 0

    # Signature algorithm
    info["signature_algorithm"] = cert.signature_algorithm_oid._name

    # Self-signed check
    info["self_signed"] = cert.issuer == cert.subject

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        info["sans"] = [str(n) for n in san_ext.value]
    except x509.ExtensionNotFound:
        info["sans"] = []

    # Wildcard check
    cn_values = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    info["wildcard"] = any("*" in attr.value for attr in cn_values)

    # Security issues
    issues: list[dict] = []

    # Expired
    if now > cert.not_valid_after_utc:
        issues.append({
            "severity": "HIGH",
            "issue": f"Certificate expired on {cert.not_valid_after_utc.date()}",
        })

    # Not yet valid
    if now < cert.not_valid_before_utc:
        issues.append({
            "severity": "MEDIUM",
            "issue": f"Certificate not valid until {cert.not_valid_before_utc.date()}",
        })

    # Weak key size
    if info["key_type"] == "RSA" and info["key_size"] < 2048:
        issues.append({
            "severity": "HIGH",
            "issue": f"Weak RSA key size: {info['key_size']} bits (minimum 2048)",
        })

    # Weak signature algorithm
    sig_algo = info["signature_algorithm"].lower()
    if "md5" in sig_algo:
        issues.append({
            "severity": "CRITICAL",
            "issue": "MD5 signature algorithm (broken, trivially forgeable)",
        })
    elif "sha1" in sig_algo:
        issues.append({
            "severity": "HIGH",
            "issue": "SHA-1 signature algorithm (deprecated, collision attacks exist)",
        })

    # Self-signed
    if info["self_signed"]:
        issues.append({
            "severity": "MEDIUM",
            "issue": "Self-signed certificate (no third-party trust chain)",
        })

    # Wildcard
    if info["wildcard"]:
        issues.append({
            "severity": "LOW",
            "issue": "Wildcard certificate",
        })

    info["issues"] = issues
    return info


def _analyze_certificate_sync(
    resolved_root: str, real_root: str, search_path: str | None,
) -> tuple[list[str], list[dict]]:
    """Synchronous certificate discovery + parse + audit.

    Returns (cert_files, results). The async caller wraps this via
    ``run_in_executor`` (Rule #5).
    """
    cert_files = _find_cert_files(resolved_root, search_path)

    results: list[dict] = []
    for cert_file in cert_files:
        try:
            with open(cert_file, "rb") as f:
                cert_data = f.read(100_000)  # 100KB limit per cert
        except (OSError, PermissionError):
            continue

        result = _audit_certificate(cert_data, cert_file, real_root)
        if "error" not in result:
            results.append(result)

    return cert_files, results


async def _handle_analyze_certificate(input: dict, context: ToolContext) -> str:
    """Parse and audit X.509 certificates found in the firmware."""
    input_path = input.get("path") or "/"
    real_root = context.real_root_for(input_path)
    search_path = input.get("path")

    # Resolve the extracted root for cert file searching
    resolved_root = context.resolve_path("/")

    loop = asyncio.get_running_loop()
    cert_files, results = await loop.run_in_executor(
        None, _analyze_certificate_sync, resolved_root, real_root, search_path,
    )

    if not cert_files:
        return "No certificate files found in the firmware filesystem."

    if not results:
        return (
            f"Found {len(cert_files)} certificate file(s) but none could be parsed. "
            "Files may be in an unsupported format or corrupted."
        )

    # Build output
    total_issues = sum(len(r.get("issues", [])) for r in results)
    lines = [
        f"Analyzed {len(results)} certificate(s), {total_issues} issue(s) found:",
        "",
    ]

    for r in results:
        issues = r.get("issues", [])
        issue_summary = f"  [{len(issues)} issue(s)]" if issues else "  [OK]"
        lines.append(f"## {r['path']}{issue_summary}")
        lines.append(f"  Subject:    {r['subject']}")
        lines.append(f"  Issuer:     {r['issuer']}")
        lines.append(f"  Valid:      {r['not_before'][:10]} to {r['not_after'][:10]}")
        lines.append(f"  Key:        {r['key_type']} {r['key_size']} bits")
        lines.append(f"  Signature:  {r['signature_algorithm']}")
        if r.get("self_signed"):
            lines.append("  Self-signed: yes")
        if r.get("sans"):
            lines.append(f"  SANs:       {', '.join(r['sans'][:10])}")

        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['issue']}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Kernel sysctl hardening
# ---------------------------------------------------------------------------

# (parameter, secure_value, default_value, severity, description)
_SYSCTL_CHECKS: list[tuple[str, str, str, str, str]] = [
    # Kernel security
    ("kernel.randomize_va_space", "2", "2", "critical", "ASLR — 0=off, 1=partial, 2=full"),
    ("kernel.kptr_restrict", "1", "0", "high", "Hide kernel pointers from /proc/kallsyms"),
    ("kernel.dmesg_restrict", "1", "0", "medium", "Restrict dmesg to root only"),
    ("kernel.unprivileged_bpf_disabled", "1", "0", "high", "Block unprivileged BPF programs"),
    ("kernel.perf_event_paranoid", "3", "2", "medium", "Restrict perf to root only"),
    ("kernel.yama.ptrace_scope", "1", "0", "medium", "Restrict ptrace to parent process"),
    ("kernel.modules_disabled", "1", "0", "high", "Prevent runtime kernel module loading"),
    ("kernel.core_pattern", "|/bin/false", "core", "medium", "Disable core dumps to writable paths"),
    # Network hardening
    ("net.ipv4.tcp_syncookies", "1", "0", "high", "SYN flood protection"),
    ("net.ipv4.conf.all.accept_redirects", "0", "1", "medium", "Reject ICMP redirects (MITM)"),
    ("net.ipv6.conf.all.accept_redirects", "0", "1", "medium", "Reject IPv6 ICMP redirects"),
    ("net.ipv4.conf.all.accept_source_route", "0", "0", "high", "Reject source-routed packets"),
    ("net.ipv6.conf.all.accept_source_route", "0", "0", "high", "Reject IPv6 source-routed packets"),
    ("net.ipv4.conf.all.rp_filter", "1", "0", "medium", "Reverse path filtering (anti-spoof)"),
    ("net.ipv4.conf.default.rp_filter", "1", "0", "medium", "Default reverse path filtering"),
    ("net.ipv4.conf.all.send_redirects", "0", "1", "low", "Don't send ICMP redirects"),
    ("net.ipv4.conf.all.log_martians", "1", "0", "low", "Log packets with impossible addresses"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "0", "medium", "Ignore broadcast pings (Smurf)"),
]


def _parse_sysctl_files(real_root: str) -> dict[str, str]:
    """Parse sysctl.conf and sysctl.d/*.conf to extract effective parameters."""
    params: dict[str, str] = {}

    # Check main sysctl.conf and common variants
    for conf_path in [
        os.path.join(real_root, "etc", "sysctl.conf"),
        os.path.join(real_root, "etc_ro", "sysctl.conf"),
    ]:
        if os.path.isfile(conf_path):
            _parse_single_sysctl(conf_path, params)

    # Check sysctl.d drop-ins (alphabetical order, later overrides earlier)
    sysctl_d = os.path.join(real_root, "etc", "sysctl.d")
    if os.path.isdir(sysctl_d):
        for name in sorted(os.listdir(sysctl_d)):
            if name.endswith(".conf"):
                _parse_single_sysctl(os.path.join(sysctl_d, name), params)

    # Also check init scripts for runtime sysctl -w calls
    for init_dir in ["etc/init.d", "etc/rc.d"]:
        init_path = os.path.join(real_root, init_dir)
        if os.path.isdir(init_path):
            for name in os.listdir(init_path):
                script_path = os.path.join(init_path, name)
                if os.path.isfile(script_path):
                    try:
                        with open(script_path, errors="replace") as f:
                            for line in f:
                                m = re.match(
                                    r'\s*sysctl\s+-w\s+([^=]+)=(\S+)', line
                                )
                                if m:
                                    params[m.group(1).strip()] = m.group(2).strip()
                    except (OSError, PermissionError):
                        continue

    return params


def _parse_single_sysctl(path: str, params: dict[str, str]) -> None:
    """Parse a single sysctl.conf file."""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    params[key.strip()] = val.strip()
    except (OSError, PermissionError):
        pass


async def _handle_check_kernel_hardening(
    input: dict, context: ToolContext
) -> str:
    """Check kernel sysctl hardening parameters in the firmware."""
    real_root = context.real_root_for(input.get("path", "/"))

    params = _parse_sysctl_files(real_root)

    # Check if firmware is a router (ip_forward=1 is expected)
    is_router = False
    for daemon in ["zebra", "quagga", "bird", "dnsmasq", "hostapd"]:
        for check_dir in ["usr/sbin", "usr/bin", "sbin"]:
            if os.path.exists(os.path.join(real_root, check_dir, daemon)):
                is_router = True
                break

    findings: list[dict] = []
    secure_count = 0
    total = len(_SYSCTL_CHECKS)

    for param, secure_val, default_val, severity, desc in _SYSCTL_CHECKS:
        actual = params.get(param)

        # Skip ip_forward check on routers
        if param == "net.ipv4.ip_forward" and is_router:
            continue

        if actual is None:
            # Parameter not explicitly set — using kernel default
            if default_val != secure_val:
                findings.append({
                    "param": param,
                    "value": f"(default: {default_val})",
                    "expected": secure_val,
                    "severity": severity,
                    "desc": desc,
                    "status": "default_insecure",
                })
            else:
                secure_count += 1
        elif actual == secure_val:
            secure_count += 1
        else:
            findings.append({
                "param": param,
                "value": actual,
                "expected": secure_val,
                "severity": severity,
                "desc": desc,
                "status": "misconfigured",
            })

    if not findings:
        return f"All {total} kernel hardening parameters are secure."

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

    lines = [
        f"Kernel hardening: {secure_count}/{total} parameters secure, "
        f"{len(findings)} issue(s) found",
    ]
    if is_router:
        lines.append("(Router firmware detected — ip_forward check skipped)")
    lines.append("")

    for f in findings:
        status = "NOT SET" if f["status"] == "default_insecure" else f"= {f['value']}"
        lines.append(f"[{f['severity'].upper()}] {f['param']} {status}")
        lines.append(f"  Expected: {f['expected']} — {f['desc']}")

    lines.append("")
    lines.append("Checked files: /etc/sysctl.conf, /etc/sysctl.d/*.conf, init scripts")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# scan_with_yara
# ---------------------------------------------------------------------------


async def _handle_scan_with_yara(input: dict, context: ToolContext) -> str:
    """Scan firmware with YARA rules for malware and suspicious patterns.

    Phase 3b: multi-root — walks every detection root so scatter-zip
    siblings and raw-image dirs are scanned alongside the primary rootfs.
    When ``path_filter`` is supplied the call degrades to the legacy
    single-root path scoped to that subdirectory (shim preserved).
    """
    from app.services.yara_service import scan_firmware, scan_firmware_multi

    path_filter = input.get("path")

    loop = asyncio.get_running_loop()
    if path_filter:
        # Scoped scan — legacy shim handles sub-directory filtering.
        result = await loop.run_in_executor(
            None, scan_firmware, context.extracted_path, None, path_filter,
        )
    else:
        roots = context.get_detection_roots() or [context.extracted_path]
        result = await loop.run_in_executor(
            None, scan_firmware_multi, roots,
        )

    lines: list[str] = []

    if result.errors:
        for err in result.errors[:5]:
            lines.append(f"⚠ {err}")
        lines.append("")

    lines.append("YARA scan complete:")
    lines.append(f"  Rules loaded: {result.rules_loaded}")
    lines.append(f"  Files scanned: {result.files_scanned}")
    lines.append(f"  Files with matches: {result.files_matched}")
    lines.append(f"  Total findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("No malware or suspicious patterns detected.")
        return "\n".join(lines)

    # Group by severity
    by_severity: dict[str, list] = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in ["critical", "high", "medium", "low", "info"]:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        lines.append(f"[{sev.upper()}] ({len(findings)} finding(s)):")
        for f in findings[:50]:
            lines.append(f"  • {f.title}")
            if f.file_path:
                lines.append(f"    File: {f.file_path}")
            if f.evidence:
                # Show first 2 lines of evidence
                ev_lines = f.evidence.split("\n")[:2]
                for ev in ev_lines:
                    lines.append(f"    {ev}")
        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# extract_kernel_config
# ---------------------------------------------------------------------------

# Magic bytes marking the start of an embedded kernel config (IKCONFIG)
_IKCFG_ST = b"IKCFG_ST"
_IKCFG_ED = b"IKCFG_ED"

# Common locations for kernel images in firmware
_KERNEL_IMAGE_NAMES = [
    "vmlinuz", "vmlinux", "zImage", "Image", "uImage", "bzImage",
    "vmlinuz.bin", "kernel.bin", "kernel.img",
]

# Common locations for pre-extracted kernel configs
_CONFIG_SEARCH_PATHS = [
    "proc/config.gz",
    "boot/config-*",
    "lib/modules/*/build/.config",
    "etc/kernel/config",
]


def _extract_ikconfig(data: bytes) -> str | None:
    """Extract kernel config from a binary image containing IKCFG_ST magic."""
    offset = 0
    while True:
        idx = data.find(_IKCFG_ST, offset)
        if idx == -1:
            return None
        # The gzip data starts immediately after the IKCFG_ST marker
        gz_start = idx + len(_IKCFG_ST)
        # Find the end marker to know the extent
        end_idx = data.find(_IKCFG_ED, gz_start)
        if end_idx == -1:
            # Try to decompress anyway from gz_start
            gz_blob = data[gz_start:]
        else:
            gz_blob = data[gz_start:end_idx]

        try:
            config_text = gzip.decompress(gz_blob).decode("utf-8", errors="replace")
            if "CONFIG_" in config_text:
                return config_text
        except Exception:
            pass

        # Try next occurrence
        offset = idx + 1

    return None


def _extract_kernel_config_from_path_sync(full_path: str, path: str) -> str:
    """Synchronously try to extract a kernel config from a single file path.

    Returns the result string for the async handler to return as-is.
    Mirrors the original three-attempt sequence (gzip / text / IKCONFIG).
    """
    # Check if it's a gzip file (e.g. /proc/config.gz)
    if path.endswith(".gz"):
        try:
            with open(full_path, "rb") as f:
                config_text = gzip.decompress(f.read()).decode(
                    "utf-8", errors="replace"
                )
            if "CONFIG_" in config_text:
                lines = config_text.splitlines()
                return (
                    f"Extracted kernel config from {path} "
                    f"({len(lines)} lines):\n\n{config_text}"
                )
        except Exception as e:
            return f"Error decompressing '{path}': {e}"

    # Check if it's already a text config file
    try:
        with open(full_path, errors="replace") as f:
            head = f.read(4096)
        if "CONFIG_" in head:
            with open(full_path, errors="replace") as f:
                config_text = f.read(512_000)
            lines = config_text.splitlines()
            return (
                f"Kernel config from {path} "
                f"({len(lines)} lines):\n\n{config_text}"
            )
    except Exception:
        pass

    # Try IKCONFIG extraction from binary
    try:
        with open(full_path, "rb") as f:
            data = f.read()
        config_text = _extract_ikconfig(data)
        if config_text:
            lines = config_text.splitlines()
            return (
                f"Extracted IKCONFIG from {path} "
                f"({len(lines)} lines):\n\n{config_text}"
            )
        return (
            f"No embedded kernel config (IKCFG_ST) found in '{path}'. "
            "The kernel may not have been compiled with CONFIG_IKCONFIG."
        )
    except Exception as e:
        return f"Error reading '{path}': {e}"


def _extract_kernel_config_auto_sync(extracted_root: str) -> str:
    """Synchronous auto-search for kernel config files + kernel images.

    Returns the result string for the async handler to return as-is.
    Performs glob over _CONFIG_SEARCH_PATHS and a safe_walk over
    extracted_root for kernel images.
    """
    import glob as globmod

    results: list[str] = []

    # 1. Check pre-extracted config files
    for pattern in _CONFIG_SEARCH_PATHS:
        full_pattern = os.path.join(extracted_root, pattern)
        for match_path in globmod.glob(full_pattern):
            real = os.path.realpath(match_path)
            if not real.startswith(extracted_root):
                continue
            rel = "/" + os.path.relpath(real, extracted_root)

            if match_path.endswith(".gz"):
                try:
                    with open(match_path, "rb") as f:
                        config_text = gzip.decompress(f.read()).decode(
                            "utf-8", errors="replace"
                        )
                    if "CONFIG_" in config_text:
                        lines = config_text.splitlines()
                        return (
                            f"Extracted kernel config from {rel} "
                            f"({len(lines)} lines):\n\n{config_text}"
                        )
                except Exception:
                    results.append(f"Found {rel} but failed to decompress")
            else:
                try:
                    with open(match_path, errors="replace") as f:
                        config_text = f.read(512_000)
                    if "CONFIG_" in config_text:
                        lines = config_text.splitlines()
                        return (
                            f"Kernel config from {rel} "
                            f"({len(lines)} lines):\n\n{config_text}"
                        )
                except Exception:
                    results.append(f"Found {rel} but failed to read")

    # 2. Search for kernel image files and try IKCONFIG extraction
    kernel_files: list[str] = []
    for dirpath, _dirnames, filenames in safe_walk(extracted_root):
        for fname in filenames:
            if fname in _KERNEL_IMAGE_NAMES or fname.startswith("vmlinuz"):
                fpath = os.path.join(dirpath, fname)
                kernel_files.append(fpath)
        if len(kernel_files) >= 10:
            break

    for kpath in kernel_files:
        rel = "/" + os.path.relpath(kpath, extracted_root)
        try:
            with open(kpath, "rb") as f:
                data = f.read()
            config_text = _extract_ikconfig(data)
            if config_text:
                lines = config_text.splitlines()
                return (
                    f"Extracted IKCONFIG from {rel} "
                    f"({len(lines)} lines):\n\n{config_text}"
                )
            results.append(f"Checked {rel} — no IKCFG_ST magic found")
        except Exception as e:
            results.append(f"Checked {rel} — error: {e}")

    if results:
        return (
            "No kernel config found. Searched locations:\n"
            + "\n".join(f"  • {r}" for r in results)
            + "\n\nThe kernel may not have CONFIG_IKCONFIG enabled."
        )
    return (
        "No kernel config found. No config files or kernel images "
        "were found in the firmware filesystem.\n"
        "Hint: If you have a vmlinuz path, pass it explicitly via "
        "the 'path' parameter."
    )


async def _handle_extract_kernel_config(
    input: dict, context: ToolContext
) -> str:
    """Extract kernel .config from firmware — either from a kernel binary
    (IKCONFIG) or from pre-extracted config files."""
    extracted_root = os.path.realpath(context.extracted_path)
    path = input.get("path")
    loop = asyncio.get_running_loop()

    # If a specific path is provided, try to extract from that binary
    if path:
        full_path = context.resolve_path(path)
        if not os.path.isfile(full_path):
            return f"Error: '{path}' is not a file."

        return await loop.run_in_executor(
            None, _extract_kernel_config_from_path_sync, full_path, path,
        )

    # Auto-search mode: look in common locations
    return await loop.run_in_executor(
        None, _extract_kernel_config_auto_sync, extracted_root,
    )


# ---------------------------------------------------------------------------
# check_kernel_config
# ---------------------------------------------------------------------------


async def _handle_check_kernel_config(
    input: dict, context: ToolContext
) -> str:
    """Run kconfig-hardened-check against a kernel .config to identify
    security hardening gaps."""
    config_text = input.get("config_text")
    path = input.get("path")

    # Resolve the config content
    if config_text:
        # Config text provided directly
        pass
    elif path:
        full_path = context.resolve_path(path)
        if not os.path.isfile(full_path):
            return f"Error: '{path}' is not a file."
        # If .gz, decompress first
        if path.endswith(".gz"):
            try:
                with open(full_path, "rb") as f:
                    config_text = gzip.decompress(f.read()).decode(
                        "utf-8", errors="replace"
                    )
            except Exception as e:
                return f"Error decompressing '{path}': {e}"
        else:
            try:
                with open(full_path, errors="replace") as f:
                    config_text = f.read(512_000)
            except Exception as e:
                return f"Error reading '{path}': {e}"
    else:
        # Try auto-extraction
        auto_result = await _handle_extract_kernel_config(
            {}, context
        )
        if "lines):\n\n" in auto_result:
            # Successfully extracted — pull out the config text
            config_text = auto_result.split("lines):\n\n", 1)[1]
        else:
            return (
                "No kernel config provided and auto-extraction failed.\n"
                + auto_result
                + "\n\nProvide config_text or path to a kernel config file."
            )

    if not config_text or "CONFIG_" not in config_text:
        return (
            "The provided content does not appear to be a valid kernel "
            "config (no CONFIG_* entries found)."
        )

    # Write config to a temp file for kconfig-hardened-check
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".config", prefix="wairz_kconf_")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(config_text)

        # Try running kconfig-hardened-check
        try:
            proc = await asyncio.create_subprocess_exec(
                "kconfig-hardened-check", "-c", tmp_path, "-m", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=60
            )
        except FileNotFoundError:
            return await _fallback_kernel_config_check(config_text)
        except TimeoutError:
            return "Error: kconfig-hardened-check timed out after 60 seconds."

        # kconfig-hardened-check may return non-zero if there are FAIL results
        # — that's expected. Only treat it as error if no stdout at all.
        output = stdout.decode("utf-8", errors="replace").strip()
        if not output:
            err = stderr.decode("utf-8", errors="replace").strip()
            if err:
                # Might be a version that doesn't support JSON mode
                return await _fallback_kernel_config_check(config_text)
            return (
                "kconfig-hardened-check produced no output.\n"
                f"stderr: {err}"
            )

        # Parse JSON output
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Not JSON — maybe older version, use raw output
            lines = output.splitlines()
            return (
                f"kconfig-hardened-check results ({len(lines)} lines):\n\n"
                + output
            )

        return _format_kconfig_results(data)

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _format_kconfig_results(data: list | dict) -> str:
    """Format kconfig-hardened-check JSON output into a readable summary."""
    # The JSON output is a list of check results
    if isinstance(data, dict):
        # Some versions wrap in a dict
        checks = data.get("checks", data.get("results", []))
    elif isinstance(data, list):
        checks = data
    else:
        return f"Unexpected output format: {type(data)}"

    if not checks:
        return "kconfig-hardened-check returned no check results."

    # Group by result
    ok_checks: list[dict] = []
    fail_checks: list[dict] = []
    notfound_checks: list[dict] = []

    for check in checks:
        result = check.get("result", "").upper() if isinstance(check, dict) else ""
        if "OK" in result:
            ok_checks.append(check)
        elif "FAIL" in result:
            fail_checks.append(check)
        else:
            notfound_checks.append(check)

    lines: list[str] = []
    lines.append("Kernel Config Hardening Check Results")
    lines.append("=" * 40)
    lines.append(
        f"  PASS: {len(ok_checks)}  |  FAIL: {len(fail_checks)}  "
        f"|  OTHER: {len(notfound_checks)}"
    )
    lines.append("")

    if fail_checks:
        lines.append(f"FAILED CHECKS ({len(fail_checks)}):")
        lines.append("-" * 40)
        for check in fail_checks:
            name = check.get("option", check.get("name", "?"))
            desired = check.get("desired", check.get("expected", "?"))
            actual = check.get("actual", check.get("value", "?"))
            decision = check.get("decision", check.get("reason", ""))
            line = f"  [FAIL] {name}: {actual} (expected: {desired})"
            if decision:
                line += f" — {decision}"
            lines.append(line)
        lines.append("")

    if notfound_checks:
        lines.append(f"NOT FOUND / OTHER ({len(notfound_checks)}):")
        lines.append("-" * 40)
        for check in notfound_checks[:30]:
            name = check.get("option", check.get("name", "?"))
            result = check.get("result", "?")
            lines.append(f"  [{result}] {name}")
        if len(notfound_checks) > 30:
            lines.append(f"  ... and {len(notfound_checks) - 30} more")
        lines.append("")

    lines.append(f"PASSED CHECKS: {len(ok_checks)} (not shown)")
    lines.append("")
    lines.append(
        "Tip: Focus on FAIL items. Many are defense-in-depth options — "
        "prioritize those relevant to the firmware's threat model."
    )

    return "\n".join(lines)


async def _fallback_kernel_config_check(config_text: str) -> str:
    """Basic kernel config hardening check when kconfig-hardened-check is
    not installed. Checks a curated set of critical security options."""

    # (option, secure_value, severity, description)
    checks: list[tuple[str, str, str, str]] = [
        # Memory protection
        ("CONFIG_STACKPROTECTOR_STRONG", "y", "high",
         "Stack buffer overflow protection (strong)"),
        ("CONFIG_STACKPROTECTOR", "y", "high",
         "Stack buffer overflow protection"),
        ("CONFIG_VMAP_STACK", "y", "medium",
         "Virtually-mapped kernel stacks (guard pages)"),
        ("CONFIG_RANDOMIZE_BASE", "y", "high",
         "Kernel ASLR (KASLR)"),
        ("CONFIG_RANDOMIZE_MEMORY", "y", "medium",
         "Randomize kernel memory sections"),
        # Hardened usercopy
        ("CONFIG_HARDENED_USERCOPY", "y", "high",
         "Bounds-check user/kernel memory copies"),
        # Slab hardening
        ("CONFIG_SLAB_FREELIST_RANDOM", "y", "medium",
         "Randomize slab freelist"),
        ("CONFIG_SLAB_FREELIST_HARDENED", "y", "medium",
         "Harden slab freelist metadata"),
        # Read-only data
        ("CONFIG_STRICT_KERNEL_RWX", "y", "high",
         "Read-only kernel code and data"),
        ("CONFIG_STRICT_MODULE_RWX", "y", "high",
         "Read-only module code and data"),
        # Dangerous features that should be disabled
        ("CONFIG_DEVMEM", "n", "high",
         "/dev/mem access (should be disabled)"),
        ("CONFIG_DEVKMEM", "n", "high",
         "/dev/kmem access (should be disabled)"),
        ("CONFIG_KEXEC", "n", "medium",
         "kexec (can bypass secure boot)"),
        ("CONFIG_HIBERNATION", "n", "low",
         "Hibernation (exposes memory image)"),
        ("CONFIG_ACPI_CUSTOM_METHOD", "n", "high",
         "Custom ACPI methods (arbitrary code execution)"),
        # Module signing
        ("CONFIG_MODULE_SIG", "y", "high",
         "Module signature verification"),
        ("CONFIG_MODULE_SIG_FORCE", "y", "medium",
         "Require valid module signatures"),
        # Debug / info leak
        ("CONFIG_KALLSYMS", "n", "medium",
         "Kernel symbol table (information leak)"),
        ("CONFIG_DEBUG_FS", "n", "medium",
         "debugfs (information leak / attack surface)"),
        ("CONFIG_KPROBES", "n", "low",
         "Kprobes (kernel probing infrastructure)"),
        # Security modules
        ("CONFIG_SECURITY", "y", "medium",
         "Security frameworks enabled"),
        ("CONFIG_SECCOMP", "y", "high",
         "seccomp syscall filtering"),
        ("CONFIG_SECCOMP_FILTER", "y", "high",
         "seccomp BPF filter"),
        # Integrity
        ("CONFIG_BUG_ON_DATA_CORRUPTION", "y", "medium",
         "Panic on detected data corruption"),
        ("CONFIG_FORTIFY_SOURCE", "y", "high",
         "Compile-time buffer overflow detection"),
        ("CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "y", "medium",
         "Zero memory on allocation"),
    ]

    # Parse config into a dict
    config_map: dict[str, str] = {}
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("#") and "is not set" in line:
            # # CONFIG_FOO is not set
            m = re.match(r"#\s*(CONFIG_\w+)\s+is not set", line)
            if m:
                config_map[m.group(1)] = "n"
        elif line.startswith("CONFIG_"):
            m = re.match(r"(CONFIG_\w+)=(.+)", line)
            if m:
                config_map[m.group(1)] = m.group(2)

    pass_count = 0
    fail_items: list[str] = []
    notfound_items: list[str] = []

    for option, secure_val, severity, desc in checks:
        actual = config_map.get(option)
        if actual is None:
            notfound_items.append(f"  [NOTFOUND] {option} — {desc}")
        elif actual == secure_val:
            pass_count += 1
        else:
            fail_items.append(
                f"  [{severity.upper()}] {option}={actual} "
                f"(expected: {secure_val}) — {desc}"
            )

    lines: list[str] = []
    lines.append(
        "Kernel Config Hardening Check (built-in fallback)"
    )
    lines.append(
        "Note: kconfig-hardened-check is not installed. "
        "Using a reduced set of 26 critical checks."
    )
    lines.append("=" * 50)
    lines.append(
        f"  PASS: {pass_count}  |  FAIL: {len(fail_items)}  "
        f"|  NOT FOUND: {len(notfound_items)}"
    )
    lines.append("")

    if fail_items:
        lines.append(f"FAILED CHECKS ({len(fail_items)}):")
        lines.append("-" * 40)
        lines.extend(fail_items)
        lines.append("")

    if notfound_items:
        lines.append(f"NOT FOUND ({len(notfound_items)}):")
        lines.append("-" * 40)
        lines.extend(notfound_items)
        lines.append("")

    lines.append(f"PASSED CHECKS: {pass_count}")
    lines.append("")
    lines.append(
        "Install kconfig-hardened-check for a comprehensive analysis "
        "(400+ checks): pip install kconfig-hardened-check"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_selinux_policy / check_selinux_enforcement
# ---------------------------------------------------------------------------


async def _handle_analyze_selinux_policy(
    input: dict, context: ToolContext
) -> str:
    """Full SELinux policy analysis for Android firmware."""
    from app.services.selinux_service import SELinuxService

    loop = asyncio.get_running_loop()
    svc = SELinuxService(context.extracted_path)
    result = await loop.run_in_executor(None, svc.analyze_policy)

    if not result["has_selinux"]:
        return (
            "No SELinux policy found in firmware. "
            "SELinux analysis is only available for Android firmware with "
            "policy files in /system/etc/selinux/ or similar locations."
        )

    lines: list[str] = ["# SELinux Policy Analysis", ""]

    # Enforcement status
    enf = result["enforcement"]
    if enf.get("enforcing") is True:
        lines.append("Enforcement: ENFORCING")
    elif enf.get("enforcing") is False:
        lines.append("Enforcement: PERMISSIVE / DISABLED (security risk)")
    else:
        lines.append("Enforcement: UNKNOWN")
    if enf.get("source"):
        lines.append(f"  Source: {enf['source']}")
    if enf.get("details"):
        for k, v in enf["details"].items():
            lines.append(f"  {k} = {v}")
    lines.append("")

    # Policy files
    lines.append(f"Policy files found: {len(result['policy_files'])}")
    for pf in result["policy_files"][:30]:
        lines.append(f"  {pf}")
    if len(result["policy_files"]) > 30:
        lines.append(f"  ... and {len(result['policy_files']) - 30} more")
    lines.append("")

    # CIL stats
    cs = result.get("cil_stats", {})
    if cs.get("total_cil_files", 0) > 0:
        lines.append("CIL policy statistics:")
        lines.append(f"  CIL files: {cs.get('total_cil_files', 0)}")
        lines.append(f"  Type declarations: {cs.get('type_declarations', 0)}")
        lines.append(f"  Allow rules: {cs.get('allow_rules', 0)}")
        lines.append(f"  Neverallow rules: {cs.get('neverallow_rules', 0)}")
        lines.append(f"  Type transitions: {cs.get('type_transitions', 0)}")
        lines.append(f"  Permissive declarations: {cs.get('typepermissive', 0)}")
        lines.append("")

    # Permissive domains
    perm = result["permissive_domains"]
    if perm:
        lines.append(f"PERMISSIVE DOMAINS ({len(perm)}) — security risk:")
        for d in perm[:50]:
            lines.append(f"  - {d}")
        if len(perm) > 50:
            lines.append(f"  ... and {len(perm) - 50} more")
        lines.append("")
        lines.append(
            "Permissive domains bypass SELinux enforcement. Processes running "
            "in these domains can perform any action — SELinux logs violations "
            "but does not block them. This is a significant security weakness."
        )
    else:
        lines.append("No permissive domains found (good).")

    return "\n".join(lines)


async def _handle_check_selinux_enforcement(
    input: dict, context: ToolContext
) -> str:
    """Quick SELinux enforcement status check."""
    from app.services.selinux_service import SELinuxService

    loop = asyncio.get_running_loop()
    svc = SELinuxService(context.extracted_path)

    # Check if there are any policy files at all
    policy_files = await loop.run_in_executor(None, svc._find_policy_files)
    if not policy_files:
        return (
            "No SELinux policy found in firmware. "
            "SELinux analysis is only available for Android firmware."
        )

    enforcement = await loop.run_in_executor(None, svc.check_enforcement)

    lines: list[str] = []

    # Enforcement
    if enforcement.get("enforcing") is True:
        lines.append("SELinux: ENFORCING")
    elif enforcement.get("enforcing") is False:
        lines.append("SELinux: NOT ENFORCING (security risk)")
    else:
        lines.append("SELinux: UNKNOWN enforcement status")
    lines.append(f"Source: {enforcement.get('source', 'unknown')}")

    if enforcement.get("details"):
        for k, v in enforcement["details"].items():
            lines.append(f"  {k} = {v}")
    lines.append("")

    # Quick permissive domain check
    permissive = await loop.run_in_executor(
        None, svc._find_permissive_domains_all, policy_files
    )
    unique = sorted(set(permissive))
    if unique:
        lines.append(f"Permissive domains: {len(unique)}")
        for d in unique[:20]:
            lines.append(f"  - {d}")
        if len(unique) > 20:
            lines.append(f"  ... and {len(unique) - 20} more")
        lines.append("")
        lines.append("These domains weaken SELinux protection.")
    else:
        lines.append("No permissive domains found.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# check_compliance (ETSI EN 303 645)
# ---------------------------------------------------------------------------


async def _handle_check_compliance(input: dict, context: ToolContext) -> str:
    """Generate a compliance report against a security standard."""
    standard = input.get("standard", "etsi-en-303-645")

    if standard != "etsi-en-303-645":
        return f"Unsupported standard: {standard}. Currently supported: etsi-en-303-645"

    from app.services.compliance_service import ETSIComplianceService

    service = ETSIComplianceService(context.db)
    report = await service.generate_report(
        project_id=context.project_id,
        firmware_id=context.firmware_id,
    )
    return service.format_report_text(report)


# ---------------------------------------------------------------------------
# scan_scripts (Semgrep)
# ---------------------------------------------------------------------------

_SEMGREP_RULES_PATH = Path(__file__).parent / "semgrep_rules" / "firmware.yaml"

# Map language filter names to file extensions for pre-filtering
_LANG_EXTENSIONS: dict[str, set[str]] = {
    "bash": {".sh", ".bash", ".ash"},
    "php": {".php", ".cgi", ".inc"},
    "lua": {".lua"},
    "python": {".py"},
}


async def _handle_scan_scripts(input: dict, context: ToolContext) -> str:
    """Scan firmware scripts with Semgrep for security issues."""

    if not shutil.which("semgrep"):
        return (
            "Error: semgrep is not installed. "
            "Install it with: pip install semgrep  "
            "(or see https://semgrep.dev/docs/getting-started/)"
        )

    if not _SEMGREP_RULES_PATH.is_file():
        return f"Error: Semgrep rules file not found at {_SEMGREP_RULES_PATH}"

    # Resolve target path
    target_rel = input.get("path") or "/"
    target_path = context.resolve_path(target_rel)

    if not os.path.isdir(target_path):
        return (
            f"Error: path '{target_rel}' is not a directory "
            "in the firmware filesystem."
        )

    # Build language filter args
    languages = input.get("languages")
    if languages:
        if isinstance(languages, str):
            languages = [lang.strip() for lang in languages.split(",")]
        valid = set(_LANG_EXTENSIONS.keys())
        invalid = [lang for lang in languages if lang not in valid]
        if invalid:
            return (
                f"Error: unsupported language(s): {', '.join(invalid)}. "
                f"Supported: {', '.join(sorted(valid))}"
            )

    cmd = [
        "semgrep", "scan",
        "--config", str(_SEMGREP_RULES_PATH),
        "--json",
        "--no-git-ignore",
        "--quiet",
        target_path,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=120
        )
    except TimeoutError:
        return (
            "Error: Semgrep scan timed out after 120 seconds. "
            "Try scanning a smaller directory."
        )
    except Exception as exc:
        return f"Error running semgrep: {exc}"

    # Parse JSON output
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        err_msg = (
            stderr.decode(errors="replace").strip()
            if stderr else "unknown error"
        )
        if proc.returncode != 0 and not stdout:
            return (
                f"Semgrep exited with code {proc.returncode}: {err_msg}"
            )
        return f"Error: could not parse Semgrep output. stderr: {err_msg}"

    results = data.get("results", [])
    errors = data.get("errors", [])

    # Apply language filter if specified
    if languages:
        allowed_exts: set[str] = set()
        for lang in languages:
            allowed_exts.update(_LANG_EXTENSIONS[lang])
        results = [
            r for r in results
            if any(
                r.get("path", "").endswith(ext) for ext in allowed_exts
            )
        ]

    lines: list[str] = []

    if errors:
        for err in errors[:5]:
            msg = (
                err.get("message", str(err))
                if isinstance(err, dict) else str(err)
            )
            lines.append(f"Warning: {msg}")
        lines.append("")

    lines.append(f"Semgrep scan complete: {len(results)} finding(s)")
    lines.append("")

    if not results:
        lines.append("No issues detected in scanned scripts.")
        return "\n".join(lines)

    # Group by category
    by_category: dict[str, list] = {}
    extracted_root = context.extracted_path
    for r in results:
        meta = r.get("extra", {}).get("metadata", {})
        category = meta.get("category", "other")
        by_category.setdefault(category, []).append(r)

    for category, findings in sorted(by_category.items()):
        label = category.replace("_", " ").upper()
        lines.append(f"== {label} ({len(findings)}) ==")
        for f in findings[:50]:
            severity = f.get("extra", {}).get("severity", "WARNING")
            rule_id = f.get("check_id", "unknown")
            file_path = _rel(f.get("path", ""), extracted_root)
            line_start = f.get("start", {}).get("line", "?")
            line_end = f.get("end", {}).get("line", "?")
            message = f.get("extra", {}).get("message", "")
            matched = f.get("extra", {}).get("lines", "").strip()

            lines.append(f"  [{severity}] {rule_id}")
            lines.append(f"    File: {file_path}:{line_start}-{line_end}")
            if matched:
                match_lines = matched.split("\n")[:2]
                for ml in match_lines:
                    lines.append(f"    > {ml}")
            if message:
                lines.append(f"    {message}")
            lines.append("")
        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# shellcheck_scan (ShellCheck)
# ---------------------------------------------------------------------------

# Map security-relevant ShellCheck codes to CWEs
_SC_CWE_MAP: dict[int, tuple[str, str]] = {
    2086: ("CWE-78", "Unquoted variable — word splitting → command injection risk"),
    2091: ("CWE-78", "Quoting command substitution used as condition"),
    2046: ("CWE-78", "Unquoted $(…) — word splitting → command injection risk"),
    2059: ("CWE-134", "printf format string from variable"),
    2155: ("CWE-252", "local var=$(cmd) masks return code"),
}


def _discover_shell_scripts(
    target_path: str, max_files: int
) -> list[str]:
    """Discover shell scripts by extension, shebang, and well-known paths.

    Synchronous helper — wrap the call in ``run_in_executor`` from any
    async handler (Rule #5).
    """
    scripts: list[str] = []
    seen: set[str] = set()

    shell_extensions = {".sh", ".ash"}
    shebang_patterns = {b"/bin/sh", b"/bin/bash", b"/bin/ash", b"/usr/bin/env sh", b"/usr/bin/env bash"}
    # Directories where ALL files are likely scripts
    script_dirs = {"etc/init.d", "www/cgi-bin"}

    for dirpath, _dirs, files in safe_walk(target_path):
        if len(scripts) >= max_files:
            break
        rel_dir = os.path.relpath(dirpath, target_path)
        in_script_dir = any(
            rel_dir == sd or rel_dir.startswith(sd + os.sep) for sd in script_dirs
        )

        for name in files:
            if len(scripts) >= max_files:
                break
            abs_path = os.path.join(dirpath, name)
            if abs_path in seen or not os.path.isfile(abs_path):
                continue

            # Check extension
            _, ext = os.path.splitext(name.lower())
            if ext in shell_extensions or in_script_dir:
                seen.add(abs_path)
                scripts.append(abs_path)
                continue

            # Check shebang
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            seen.add(abs_path)
                            scripts.append(abs_path)
            except OSError:
                continue

    return scripts


async def _handle_shellcheck_scan(input: dict, context: ToolContext) -> str:
    """Run ShellCheck static analysis on shell scripts."""

    if not shutil.which("shellcheck"):
        return (
            "Error: shellcheck is not installed. "
            "Install it with: apt-get install -y shellcheck  "
            "(or download the static binary from https://github.com/koalaman/shellcheck)"
        )

    # Resolve target path
    target_rel = input.get("path") or "/"
    target_path = context.resolve_path(target_rel)

    if not os.path.isdir(target_path):
        return (
            f"Error: path '{target_rel}' is not a directory "
            "in the firmware filesystem."
        )

    severity = input.get("severity", "warning")
    shell = input.get("shell", "sh")
    max_files = input.get("max_files", 100)

    # Discover shell scripts (sync — wrap via executor per Rule #5)
    loop = asyncio.get_running_loop()
    scripts = await loop.run_in_executor(
        None, _discover_shell_scripts, target_path, max_files,
    )
    if not scripts:
        return "No shell scripts found in the target path."

    # Run ShellCheck on each script
    all_results: list[dict] = []
    errors: list[str] = []
    extracted_root = context.extracted_path

    for script_path in scripts:
        cmd = [
            "shellcheck", "-f", "json1",
            "-S", severity,
            "-s", shell,
            script_path,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
        except TimeoutError:
            rel = _rel(script_path, extracted_root)
            errors.append(f"Timeout scanning {rel}")
            continue
        except Exception as exc:
            rel = _rel(script_path, extracted_root)
            errors.append(f"Error scanning {rel}: {exc}")
            continue

        if not stdout:
            continue

        try:
            data = json.loads(stdout)
            comments = data.get("comments", [])
            for c in comments:
                c["file"] = script_path
            all_results.extend(comments)
        except json.JSONDecodeError:
            continue

    # Format output
    lines: list[str] = []

    if errors:
        for err in errors[:5]:
            lines.append(f"Warning: {err}")
        if len(errors) > 5:
            lines.append(f"  ... and {len(errors) - 5} more warnings")
        lines.append("")

    lines.append(f"ShellCheck scan complete: {len(all_results)} finding(s) in {len(scripts)} script(s)")
    lines.append("")

    if not all_results:
        lines.append("No issues detected in scanned scripts.")
        return "\n".join(lines)

    # Group by severity, then by SC code
    by_severity: dict[str, dict[int, list[dict]]] = {}
    for r in all_results:
        level = r.get("level", "warning")
        code = r.get("code", 0)
        by_severity.setdefault(level, {}).setdefault(code, []).append(r)

    severity_order = ["error", "warning", "info", "style"]
    for sev in severity_order:
        if sev not in by_severity:
            continue
        by_code = by_severity[sev]
        total = sum(len(v) for v in by_code.values())
        lines.append(f"== {sev.upper()} ({total}) ==")

        for code, findings in sorted(by_code.items()):
            cwe_info = _SC_CWE_MAP.get(code)
            cwe_label = f" [{cwe_info[0]}]" if cwe_info else ""
            lines.append(f"  SC{code}{cwe_label} ({len(findings)} occurrence(s))")
            if cwe_info:
                lines.append(f"    Security: {cwe_info[1]}")

            for f in findings[:30]:
                file_path = _rel(f.get("file", ""), extracted_root)
                line_num = f.get("line", "?")
                end_line = f.get("endLine", "?")
                message = f.get("message", "")
                lines.append(f"    {file_path}:{line_num}-{end_line}")
                if message:
                    lines.append(f"      {message}")
            if len(findings) > 30:
                lines.append(f"    ... and {len(findings) - 30} more")
            lines.append("")

    return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# bandit_scan (Bandit)
# ---------------------------------------------------------------------------

# Key Bandit test IDs for firmware security
_BANDIT_HIGHLIGHT: dict[str, tuple[str, str]] = {
    "B102": ("CWE-78", "exec_used"),
    "B103": ("CWE-732", "set_bad_file_permissions"),
    "B104": ("CWE-200", "hardcoded_bind_all_interfaces"),
    "B105": ("CWE-259", "hardcoded_password_string"),
    "B106": ("CWE-259", "hardcoded_password_funcarg"),
    "B107": ("CWE-259", "hardcoded_password_default"),
    "B301": ("CWE-502", "pickle"),
    "B602": ("CWE-78", "subprocess_popen_with_shell_equals_true"),
    "B501": ("CWE-295", "ssl_no_verify"),
}


def _discover_python_scripts(
    target_path: str, max_files: int
) -> list[str]:
    """Discover Python scripts by extension and shebang.

    Synchronous helper — wrap the call in ``run_in_executor`` from any
    async handler (Rule #5).
    """
    scripts: list[str] = []
    seen: set[str] = set()
    py_extensions = {".py", ".pyw"}
    shebang_patterns = {b"/usr/bin/python", b"/usr/bin/env python", b"/usr/bin/python3", b"/usr/bin/env python3"}

    for dirpath, _dirs, files in safe_walk(target_path):
        if len(scripts) >= max_files:
            break
        for name in files:
            if len(scripts) >= max_files:
                break
            abs_path = os.path.join(dirpath, name)
            if abs_path in seen or not os.path.isfile(abs_path):
                continue

            _, ext = os.path.splitext(name.lower())
            if ext in py_extensions:
                seen.add(abs_path)
                scripts.append(abs_path)
                continue

            # Check shebang
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            seen.add(abs_path)
                            scripts.append(abs_path)
            except OSError:
                continue

    return scripts


async def _handle_bandit_scan(input: dict, context: ToolContext) -> str:
    """Run Bandit Python security linter on Python scripts in firmware."""

    bandit_bin = shutil.which("bandit") or shutil.which("bandit", path="/app/.venv/bin")
    if not bandit_bin:
        return (
            "Error: bandit is not installed. "
            "Install it with: pip install bandit  "
            "(or add bandit>=1.7 to pyproject.toml dependencies)"
        )

    # Resolve target path
    target_rel = input.get("path") or "/"
    target_path = context.resolve_path(target_rel)

    if not os.path.isdir(target_path):
        return (
            f"Error: path '{target_rel}' is not a directory "
            "in the firmware filesystem."
        )

    severity = input.get("severity", "low")
    confidence = input.get("confidence", "medium")
    max_files = input.get("max_files", 100)

    # Discover Python scripts (sync — wrap via executor per Rule #5)
    loop = asyncio.get_running_loop()
    scripts = await loop.run_in_executor(
        None, _discover_python_scripts, target_path, max_files,
    )
    if not scripts:
        return "No Python scripts found in the target path."

    # Map severity to bandit -l flags
    severity_flag = {"low": "-l", "medium": "-ll", "high": "-lll"}.get(severity, "-l")
    confidence_flag = {"low": "-i", "medium": "-ii", "high": "-iii"}.get(confidence, "-ii")

    # Run Bandit on the target path (it handles recursion itself)
    # Feed it the list of discovered files to avoid scanning non-Python files
    cmd = [
        bandit_bin,
        "-f", "json",
        severity_flag,
        confidence_flag,
    ] + scripts

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=60
        )
    except TimeoutError:
        return (
            "Error: Bandit scan timed out after 60 seconds. "
            "Try scanning a smaller directory or fewer files."
        )
    except Exception as exc:
        return f"Error running bandit: {exc}"

    # Parse JSON output
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        err_msg = (
            stderr.decode(errors="replace").strip()
            if stderr else "unknown error"
        )
        # Bandit exits non-zero when it finds issues — that's normal
        if not stdout:
            return f"Bandit produced no output. stderr: {err_msg}"
        return f"Error: could not parse Bandit output. stderr: {err_msg}"

    results = data.get("results", [])
    metrics = data.get("metrics", {})
    extracted_root = context.extracted_path

    # Format output
    lines: list[str] = []

    # Summary from metrics
    total_metrics = metrics.get("_totals", {})
    loc = total_metrics.get("loc", 0)
    lines.append(f"Bandit scan complete: {len(results)} finding(s) in {len(scripts)} script(s) ({loc} lines of code)")
    lines.append("")

    if not results:
        lines.append("No issues detected in scanned Python scripts.")
        return "\n".join(lines)

    # Group by severity
    by_severity: dict[str, list[dict]] = {}
    for r in results:
        sev = r.get("issue_severity", "LOW")
        by_severity.setdefault(sev, []).append(r)

    severity_order = ["HIGH", "MEDIUM", "LOW"]
    for sev in severity_order:
        if sev not in by_severity:
            continue
        findings = by_severity[sev]
        lines.append(f"== {sev} SEVERITY ({len(findings)}) ==")

        for f in findings[:50]:
            test_id = f.get("test_id", "?")
            test_name = f.get("test_name", "unknown")
            issue_text = f.get("issue_text", "")
            file_path = f.get("filename", "")
            line_num = f.get("line_number", "?")
            conf = f.get("issue_confidence", "?")
            issue_cwe = f.get("issue_cwe", {})
            cwe_id = f"CWE-{issue_cwe.get('id', '')}" if issue_cwe.get("id") else ""

            # Use known CWE mapping if bandit didn't provide one
            if not cwe_id and test_id in _BANDIT_HIGHLIGHT:
                cwe_id = _BANDIT_HIGHLIGHT[test_id][0]

            # Make path relative to firmware root
            if file_path.startswith(os.path.realpath(extracted_root)):
                file_path = _rel(file_path, extracted_root)

            cwe_label = f" [{cwe_id}]" if cwe_id else ""
            lines.append(f"  [{test_id}] {test_name}{cwe_label} (confidence: {conf})")
            lines.append(f"    File: {file_path}:{line_num}")
            if issue_text:
                lines.append(f"    {issue_text}")

            # Add firmware-specific context for highlighted tests
            if test_id in _BANDIT_HIGHLIGHT:
                _, desc = _BANDIT_HIGHLIGHT[test_id]
                lines.append(f"    Firmware risk: {desc}")
            lines.append("")

        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")
            lines.append("")

    return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# check_secure_boot
# ---------------------------------------------------------------------------

# Weak key indicators in certificate CN/issuer fields
_WEAK_KEY_INDICATORS = [
    "test", "debug", "sample", "example", "do not trust", "do not ship",
    "insecure", "unsigned", "placeholder",
]


def _check_weak_cert_cn(cert_data: bytes, file_path: str, real_root: str) -> list[dict]:
    """Check a certificate for weak key indicators. Returns list of warnings."""
    try:
        from cryptography import x509
    except ImportError:
        return []

    cert = None
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception:
            return []

    if cert is None:
        return []

    warnings: list[dict] = []
    rel_path = "/" + os.path.relpath(file_path, real_root)

    # Check subject CN and issuer for weak indicators
    for attr_source, label in [
        (cert.subject, "subject"),
        (cert.issuer, "issuer"),
    ]:
        cn_attrs = attr_source.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        for attr in cn_attrs:
            cn_lower = attr.value.lower()
            for indicator in _WEAK_KEY_INDICATORS:
                if indicator in cn_lower:
                    warnings.append({
                        "severity": "CRITICAL",
                        "file": rel_path,
                        "detail": (
                            f"Certificate {label} CN contains '{indicator}': "
                            f"{attr.value}"
                        ),
                    })

    # Self-signed in production context
    if cert.issuer == cert.subject:
        warnings.append({
            "severity": "HIGH",
            "file": rel_path,
            "detail": (
                f"Self-signed certificate used in secure boot context: "
                f"{cert.subject.rfc4514_string()}"
            ),
        })

    return warnings


def _check_secure_boot_sync(
    extracted_root: str, real_root: str,
) -> tuple[list[dict], list[dict]]:
    """Synchronously inspect the firmware for secure-boot mechanisms.

    Performs all 10 safe_walk passes plus per-file reads (FIT/.dtb,
    kernel config, fstab, build.prop, EFI certs). Returns
    ``(mechanisms, weak_key_warnings)``. The async caller wraps this via
    ``run_in_executor`` (Rule #5).
    """
    mechanisms: list[dict] = []
    weak_key_warnings: list[dict] = []

    # -----------------------------------------------------------------------
    # A. U-Boot Verified Boot
    # -----------------------------------------------------------------------
    uboot: dict = {
        "name": "U-Boot Verified Boot",
        "detected": False,
        "status": "not_detected",
        "evidence": [],
    }

    # Search for U-Boot environment files
    uboot_env_files = ["fw_env.config", "u-boot.env", "uboot.env"]
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname in uboot_env_files:
                rel = _rel(os.path.join(dirpath, fname), extracted_root)
                uboot["evidence"].append(f"U-Boot env file: {rel}")
                uboot["detected"] = True

    # Look for FIT image indicators in device tree files
    fit_signature_found = False
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname.endswith((".dtb", ".dts", ".its", ".itb")):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, errors="replace") as f:
                        content = f.read(256_000)
                    if "signature" in content.lower() or "hash" in content.lower():
                        rel = _rel(fpath, extracted_root)
                        uboot["evidence"].append(
                            f"FIT signature/hash in device tree: {rel}"
                        )
                        fit_signature_found = True
                        uboot["detected"] = True
                except (OSError, PermissionError):
                    continue

    # Check for verified boot CONFIG in kernel config
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname in (".config", "config.gz") or fname.startswith("config-"):
                fpath = os.path.join(dirpath, fname)
                try:
                    if fname.endswith(".gz"):
                        with open(fpath, "rb") as f:
                            content = gzip.decompress(f.read()).decode(
                                "utf-8", errors="replace"
                            )
                    else:
                        with open(fpath, errors="replace") as f:
                            content = f.read(512_000)
                    if "CONFIG_FIT_SIGNATURE" in content:
                        rel = _rel(fpath, extracted_root)
                        uboot["evidence"].append(
                            f"CONFIG_FIT_SIGNATURE found in: {rel}"
                        )
                        uboot["detected"] = True
                        fit_signature_found = True
                except (OSError, PermissionError):
                    continue

    # Check for public key files in /etc/ used for U-Boot verification
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname.endswith((".dtb",)) and "key" in fname.lower():
                fpath = os.path.join(dirpath, fname)
                rel = _rel(fpath, extracted_root)
                uboot["evidence"].append(f"Possible signing key DTB: {rel}")
                uboot["detected"] = True

    # Check for uImage magic bytes in binary files (0x27051956)
    uimage_magic = b"\x27\x05\x19\x56"
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname.lower() in (
                "uimage", "firmware.bin", "kernel.bin", "image.bin",
            ):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "rb") as f:
                        header = f.read(4)
                    if header == uimage_magic:
                        rel = _rel(fpath, extracted_root)
                        uboot["evidence"].append(f"uImage format binary: {rel}")
                        uboot["detected"] = True
                except (OSError, PermissionError):
                    continue

    if uboot["detected"]:
        if fit_signature_found:
            uboot["status"] = "enabled"
        else:
            uboot["status"] = "partial"
            uboot["evidence"].append(
                "WARNING: U-Boot environment found but no FIT signature "
                "verification detected — boot may not be verified"
            )

    mechanisms.append(uboot)

    # -----------------------------------------------------------------------
    # B. dm-verity (Android)
    # -----------------------------------------------------------------------
    dmverity: dict = {
        "name": "dm-verity / Android Verified Boot",
        "detected": False,
        "status": "not_detected",
        "evidence": [],
    }

    # Search for verity_key files
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if "verity_key" in fname.lower():
                fpath = os.path.join(dirpath, fname)
                rel = _rel(fpath, extracted_root)
                dmverity["evidence"].append(f"Verity key file: {rel}")
                dmverity["detected"] = True

                # Check cert for weak keys
                try:
                    with open(fpath, "rb") as f:
                        cert_data = f.read(100_000)
                    warnings = _check_weak_cert_cn(
                        cert_data, fpath, real_root
                    )
                    weak_key_warnings.extend(warnings)
                except (OSError, PermissionError):
                    pass

    # Parse fstab files for verify or avb flags
    fstab_verify_found = False
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname.startswith("fstab") or fname == "fstab":
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            # Android fstab: src mnt_point type mnt_flags fs_mgr_flags
                            if len(parts) >= 5:
                                fs_mgr = parts[4]
                                if "verify" in fs_mgr or "avb" in fs_mgr:
                                    rel = _rel(fpath, extracted_root)
                                    flag = (
                                        "avb" if "avb" in fs_mgr else "verify"
                                    )
                                    dmverity["evidence"].append(
                                        f"fstab {flag} flag for {parts[1]}: "
                                        f"{rel}"
                                    )
                                    dmverity["detected"] = True
                                    fstab_verify_found = True
                except (OSError, PermissionError):
                    continue

    # Look for vbmeta partition indicators
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if "vbmeta" in fname.lower():
                fpath = os.path.join(dirpath, fname)
                rel = _rel(fpath, extracted_root)
                dmverity["evidence"].append(f"vbmeta partition image: {rel}")
                dmverity["detected"] = True

    # Check build.prop for verified boot state
    for dirpath, _dirs, files in safe_walk(extracted_root):
        for fname in files:
            if fname in ("build.prop", "default.prop"):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, errors="replace") as f:
                        for line in f:
                            if "ro.boot.verifiedbootstate" in line:
                                rel = _rel(fpath, extracted_root)
                                dmverity["evidence"].append(
                                    f"Verified boot state: {line.strip()} "
                                    f"({rel})"
                                )
                                dmverity["detected"] = True
                            elif "ro.boot.veritymode" in line:
                                rel = _rel(fpath, extracted_root)
                                dmverity["evidence"].append(
                                    f"Verity mode: {line.strip()} ({rel})"
                                )
                                dmverity["detected"] = True
                except (OSError, PermissionError):
                    continue

    if dmverity["detected"]:
        if fstab_verify_found:
            dmverity["status"] = "enabled"
        else:
            dmverity["status"] = "partial"

    mechanisms.append(dmverity)

    # -----------------------------------------------------------------------
    # C. UEFI Secure Boot
    # -----------------------------------------------------------------------
    uefi: dict = {
        "name": "UEFI Secure Boot",
        "detected": False,
        "status": "not_detected",
        "evidence": [],
    }

    # Search for EFI directories and certificate files
    efi_cert_files: list[str] = []
    uefi_key_names = {"pk", "kek", "db", "dbx", "pk.cer", "kek.cer",
                      "db.cer", "dbx.cer", "pk.auth", "kek.auth",
                      "db.auth", "dbx.auth"}

    for dirpath, _dirs, files in safe_walk(extracted_root):
        # Detect EFI directory structures
        dir_lower = os.path.basename(dirpath).lower()
        if dir_lower == "efi" or "/efi/" in dirpath.lower():
            rel = _rel(dirpath, extracted_root)
            if not any("EFI directory" in e for e in uefi["evidence"]):
                uefi["evidence"].append(f"EFI directory found: {rel}")
            uefi["detected"] = True

        for fname in files:
            fname_lower = fname.lower()

            # Check for PK/KEK/db/dbx files
            if fname_lower in uefi_key_names:
                fpath = os.path.join(dirpath, fname)
                rel = _rel(fpath, extracted_root)
                uefi["evidence"].append(
                    f"UEFI key database file: {rel}"
                )
                uefi["detected"] = True
                efi_cert_files.append(fpath)

            # Check for .cer/.auth files in EFI paths
            elif (
                fname_lower.endswith((".cer", ".auth"))
                and "/efi/" in dirpath.lower()
            ):
                fpath = os.path.join(dirpath, fname)
                rel = _rel(fpath, extracted_root)
                uefi["evidence"].append(f"EFI certificate: {rel}")
                uefi["detected"] = True
                efi_cert_files.append(fpath)

    # Parse any found EFI certificates for weak keys
    for cert_path in efi_cert_files:
        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read(100_000)
            warnings = _check_weak_cert_cn(cert_data, cert_path, real_root)
            weak_key_warnings.extend(warnings)
        except (OSError, PermissionError):
            continue

    if uefi["detected"]:
        has_pk = any(
            "pk" in e.lower() and "key database" in e.lower()
            for e in uefi["evidence"]
        )
        if has_pk:
            uefi["status"] = "enabled"
        else:
            uefi["status"] = "partial"
            uefi["evidence"].append(
                "WARNING: EFI structure found but no Platform Key (PK) "
                "detected — Secure Boot may not be fully configured"
            )

    mechanisms.append(uefi)

    return mechanisms, weak_key_warnings


async def _handle_check_secure_boot(input: dict, context: ToolContext) -> str:
    """Detect and assess secure boot mechanisms in firmware.

    Checks for U-Boot verified boot, dm-verity (Android), and UEFI Secure Boot.
    Analyzes certificate chains and flags weak/test keys.
    """
    extracted_root = os.path.realpath(context.extracted_path)
    real_root = context.real_root_for(input.get("path", "/"))

    loop = asyncio.get_running_loop()
    mechanisms, weak_key_warnings = await loop.run_in_executor(
        None, _check_secure_boot_sync, extracted_root, real_root,
    )

    # -----------------------------------------------------------------------
    # D. Build report
    # -----------------------------------------------------------------------
    detected = [m for m in mechanisms if m["detected"]]
    lines: list[str] = []

    if not detected:
        lines.append("## Secure Boot Assessment: NO MECHANISMS DETECTED")
        lines.append("")
        lines.append(
            "No secure boot mechanisms (U-Boot verified boot, dm-verity, "
            "UEFI Secure Boot) were found in this firmware image."
        )
        lines.append("")
        lines.append(
            "This means the firmware may be vulnerable to boot-level "
            "tampering, rootkit installation, and firmware replacement attacks."
        )
        return "\n".join(lines)

    # Overall posture
    all_enabled = all(m["status"] == "enabled" for m in detected)
    any_partial = any(m["status"] == "partial" for m in detected)

    if all_enabled and not weak_key_warnings:
        posture = "STRONG"
    elif all_enabled and weak_key_warnings:
        posture = "WEAKENED (weak keys detected)"
    elif any_partial:
        posture = "PARTIAL"
    else:
        posture = "PRESENT"

    lines.append(f"## Secure Boot Assessment: {posture}")
    lines.append(f"Mechanisms detected: {len(detected)}/{len(mechanisms)}")
    lines.append("")

    for m in mechanisms:
        status_label = {
            "enabled": "ENABLED",
            "partial": "PARTIAL",
            "not_detected": "NOT DETECTED",
        }.get(m["status"], m["status"].upper())

        lines.append(f"### {m['name']}: {status_label}")
        if m["evidence"]:
            for ev in m["evidence"]:
                prefix = "  ! " if ev.startswith("WARNING") else "  - "
                lines.append(f"{prefix}{ev}")
        else:
            lines.append("  (no evidence found)")
        lines.append("")

    # Weak key warnings
    if weak_key_warnings:
        lines.append("### WEAK KEY WARNINGS")
        for w in weak_key_warnings:
            lines.append(f"  [{w['severity']}] {w['file']}: {w['detail']}")
        lines.append("")

    # Summary
    lines.append("### Summary")
    for m in detected:
        lines.append(f"  - {m['name']}: {m['status'].upper()}")
    if weak_key_warnings:
        lines.append(
            f"  - {len(weak_key_warnings)} weak key warning(s) — "
            "review certificates for test/debug keys"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# detect_network_dependencies
# ---------------------------------------------------------------------------

# Binary extensions to skip during text file scanning
_NET_DEP_BINARY_EXTENSIONS = frozenset({
    ".bin", ".img", ".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma",
    ".zip", ".tar", ".elf", ".so", ".o", ".a", ".ko", ".dtb",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".pyc", ".pyo", ".class", ".wasm",
})

# Regex patterns grouped by category
_NET_DEP_PATTERNS: dict[str, list[tuple[re.Pattern, str, str, str | None]]] = {
    # (pattern, description, severity, cwe)
    "NFS": [
        (re.compile(r"\bnfs://\S+", re.IGNORECASE), "NFS URL", "medium", "CWE-1051"),
        (re.compile(r"^\s*[^#]\S+\s+\S+\s+nfs[4 ,\t]", re.MULTILINE), "NFS mount in fstab", "medium", "CWE-1051"),
        (re.compile(r"\bmount\b.*\s+-t\s+nfs[4 ]", re.IGNORECASE), "NFS mount command", "medium", "CWE-1051"),
        (re.compile(r"no_root_squash", re.IGNORECASE), "NFS no_root_squash export", "high", "CWE-269"),
    ],
    "SMB/CIFS": [
        (re.compile(r"(?<!:)//\w[\w.-]+/\w[\w./$-]+"), "SMB/CIFS share path", "medium", "CWE-1051"),
        (re.compile(r"\bmount\b.*\s+-t\s+cifs\b", re.IGNORECASE), "CIFS mount command", "medium", "CWE-1051"),
        (re.compile(r"(?:cifs|smbfs|mount).*\bpassword=\S+", re.IGNORECASE), "CIFS mount with inline password", "critical", "CWE-798"),
        (re.compile(r"(?:cifs|smbfs|mount).*\busername=\S+", re.IGNORECASE), "CIFS mount with inline username", "high", "CWE-256"),
    ],
    "Cloud Storage": [
        (re.compile(r"\bs3://[\w./-]+", re.IGNORECASE), "AWS S3 bucket URL", "high", "CWE-200"),
        (re.compile(r"[\w.-]+\.s3\.amazonaws\.com"), "AWS S3 endpoint", "high", "CWE-200"),
        (re.compile(r"[\w.-]+\.blob\.core\.windows\.net"), "Azure Blob endpoint", "high", "CWE-200"),
        (re.compile(r"\bgs://[\w./-]+"), "Google Cloud Storage URL", "high", "CWE-200"),
        (re.compile(r"storage\.googleapis\.com"), "GCS endpoint", "high", "CWE-200"),
    ],
    "Database": [
        (re.compile(r"\bmongodb://\S+", re.IGNORECASE), "MongoDB connection string", "high", "CWE-200"),
        (re.compile(r"\bmysql://\S+", re.IGNORECASE), "MySQL connection string", "high", "CWE-200"),
        (re.compile(r"\bpostgres(ql)?://\S+", re.IGNORECASE), "PostgreSQL connection string", "high", "CWE-200"),
        (re.compile(r"\bredis://\S+", re.IGNORECASE), "Redis connection string", "high", "CWE-200"),
        (re.compile(r"\binfluxdb://\S+", re.IGNORECASE), "InfluxDB connection string", "high", "CWE-200"),
        (re.compile(r"\bamqps?://\S+", re.IGNORECASE), "AMQP connection string", "high", "CWE-200"),
        (re.compile(r"(?:mysql|redis-cli|psql|mongo)\b.*(?:-h|--host)\s+\S+", re.IGNORECASE),
         "Database CLI with remote host", "medium", "CWE-200"),
        (re.compile(r"\b(?:3306|5432|6379|27017|5672|9092|2181)\b"),
         "Well-known database/broker port", "info", None),
    ],
    "MQTT/AMQP": [
        (re.compile(r"\bmqtts?://\S+", re.IGNORECASE), "MQTT broker URL", "high", "CWE-200"),
        (re.compile(r"\bmosquitto_(?:pub|sub)\b.*-h\s+\S+", re.IGNORECASE),
         "Mosquitto client with remote host", "high", "CWE-200"),
        (re.compile(r"^\s*(?:listener|port)\s+1883\b", re.MULTILINE),
         "MQTT plaintext listener (port 1883)", "high", "CWE-319"),
        (re.compile(r"^\s*(?:listener|port)\s+8883\b", re.MULTILINE),
         "MQTT TLS listener (port 8883)", "medium", "CWE-200"),
    ],
    "FTP/TFTP": [
        (re.compile(r"\bftps?://\S+", re.IGNORECASE), "FTP URL", "high", "CWE-494"),
        (re.compile(r"\btftp://\S+", re.IGNORECASE), "TFTP URL", "high", "CWE-494"),
        (re.compile(r"\b(?:ftpget|ftpput|wget|curl)\b.*\bftp://", re.IGNORECASE),
         "FTP download command", "high", "CWE-494"),
    ],
    "Remote Syslog": [
        (re.compile(r"^\s*@@?\S+", re.MULTILINE),
         "rsyslog remote forwarding (@host or @@host)", "medium", "CWE-319"),
        (re.compile(r"destination\s*\{[^}]*host\s*\(\s*\"[^\"]+\"", re.DOTALL),
         "syslog-ng remote destination", "medium", "CWE-319"),
    ],
    "iSCSI": [
        (re.compile(r"\biqn\.\d{4}-\d{2}\.\S+", re.IGNORECASE),
         "iSCSI target IQN", "high", "CWE-200"),
    ],
}

# Config files to scan first (high confidence)
_NET_DEP_CONFIG_FILES = [
    "etc/fstab",
    "etc/exports",
    "etc/samba/smb.conf",
    "etc/mosquitto/mosquitto.conf",
    "etc/rsyslog.conf",
    "etc/syslog-ng/syslog-ng.conf",
    "etc/iscsi/initiatorname.iscsi",
]

# Config file globs for auto-mount configs
_NET_DEP_CONFIG_GLOBS = [
    "etc/auto.*",
]


def _is_net_dep_text_file(path: str) -> bool:
    """Check if a file is a text file suitable for scanning."""
    _, ext = os.path.splitext(path.lower())
    if ext in _NET_DEP_BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
            if b"\x00" in chunk:
                return False
    except OSError:
        return False
    return True


def _detect_network_dependencies_sync(
    search_root: str, real_root: str, limit: int,
) -> list:
    """Synchronously scan firmware for network mount/cloud/DB indicators.

    Returns a list of NetDepFinding dataclass instances. The async caller
    wraps this via ``run_in_executor`` (Rule #5).
    """
    from dataclasses import dataclass

    @dataclass
    class NetDepFinding:
        category: str
        severity: str
        description: str
        file_path: str
        line_number: int
        evidence: str
        cwe: str | None

    findings: list[NetDepFinding] = []

    def _scan_file(abs_path: str, content: str | None = None):
        """Scan a single file against all network dependency patterns."""
        if content is None:
            try:
                if os.path.getsize(abs_path) > 1_000_000:
                    return
            except OSError:
                return
            if not _is_net_dep_text_file(abs_path):
                return
            try:
                with open(abs_path, errors="replace") as f:
                    content = f.read(256_000)
            except (OSError, PermissionError):
                return

        rel_path = _rel(abs_path, real_root)
        basename = os.path.basename(abs_path).lower()

        for category, patterns in _NET_DEP_PATTERNS.items():
            for pat, desc, severity, cwe in patterns:
                # Scope rsyslog @host pattern to rsyslog config files only
                if "rsyslog" in desc.lower() and "rsyslog" not in basename and "syslog" not in basename:
                    continue
                # Scope syslog-ng pattern to syslog-ng configs only
                if "syslog-ng" in desc.lower() and "syslog-ng" not in basename and "syslog" not in basename:
                    continue
                # Scope MQTT listener patterns to mosquitto config files
                if "listener" in desc.lower() and "mosquitto" not in basename:
                    continue
                # Well-known port pattern only matches in config-like files
                if "Well-known" in desc and not any(
                    ext in basename for ext in (".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".env")
                ):
                    continue

                for line_num, line in enumerate(content.splitlines(), 1):
                    if len(findings) >= limit:
                        return
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    m = pat.search(line)
                    if not m:
                        continue

                    # Elevate severity for credential exposure in connection strings
                    actual_severity = severity
                    actual_cwe = cwe
                    match_text = m.group(0)
                    if category == "Database" and re.search(r"://[^/]*:[^@/]+@", match_text):
                        actual_severity = "critical"
                        actual_cwe = "CWE-798"
                        desc_final = f"{desc} (contains credentials)"
                    elif category == "SMB/CIFS" and "password=" in line.lower():
                        actual_severity = "critical"
                        actual_cwe = "CWE-798"
                        desc_final = f"{desc} (inline password exposed)"
                    else:
                        desc_final = desc

                    findings.append(NetDepFinding(
                        category=category,
                        severity=actual_severity,
                        description=desc_final,
                        file_path=rel_path,
                        line_number=line_num,
                        evidence=stripped[:200],
                        cwe=actual_cwe,
                    ))

    # Phase 1: Scan specific config files (high confidence)
    for rel_conf in _NET_DEP_CONFIG_FILES:
        conf_path = os.path.join(real_root, rel_conf)
        if os.path.isfile(conf_path):
            _scan_file(conf_path)

    # Scan auto.* mount configs
    auto_dir = os.path.join(real_root, "etc")
    if os.path.isdir(auto_dir):
        try:
            for name in os.listdir(auto_dir):
                if name.startswith("auto.") and os.path.isfile(os.path.join(auto_dir, name)):
                    _scan_file(os.path.join(auto_dir, name))
        except OSError:
            pass

    # Phase 2: Scan init scripts and crontabs (medium confidence)
    for rel_dir in ("etc/init.d", "etc/rc.d", "etc/cron.d", "var/spool/cron"):
        dir_path = os.path.join(real_root, rel_dir)
        if not os.path.isdir(dir_path):
            continue
        try:
            for name in os.listdir(dir_path):
                if len(findings) >= limit:
                    break
                abs_path = os.path.join(dir_path, name)
                if os.path.isfile(abs_path):
                    _scan_file(abs_path)
        except OSError:
            continue

    # Phase 3: Broad sweep across all text files (if we haven't hit limit)
    if len(findings) < limit:
        # Track already-scanned files to avoid duplicates
        scanned = set()
        for f in findings:
            scanned.add(f.file_path)

        for dirpath, _dirs, files in safe_walk(search_root):
            if len(findings) >= limit:
                break
            for name in files:
                if len(findings) >= limit:
                    break
                abs_path = os.path.join(dirpath, name)
                rel_path = _rel(abs_path, real_root)
                if rel_path in scanned:
                    continue
                scanned.add(rel_path)
                _scan_file(abs_path)

    return findings


async def _handle_detect_network_dependencies(input: dict, context: ToolContext) -> str:
    """Scan firmware for network mounts, cloud endpoints, brokers, and DB connections."""
    input_path = input.get("path") or "/"
    search_root = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)
    limit = _get_limit(input)

    loop = asyncio.get_running_loop()
    findings = await loop.run_in_executor(
        None, _detect_network_dependencies_sync, search_root, real_root, limit,
    )

    if not findings:
        return "No network dependencies detected in the firmware filesystem."

    # Deduplicate by (category, file_path, line_number)
    seen = set()
    unique: list[NetDepFinding] = []
    for f in findings:
        key = (f.category, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique[:limit]

    # Sort by severity order, then category
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # Group by category
    by_category: dict[str, list[NetDepFinding]] = {}
    for f in sorted(findings, key=lambda x: (sev_order.get(x.severity, 5), x.category)):
        by_category.setdefault(f.category, []).append(f)

    # Build output
    lines: list[str] = []
    lines.append(f"Network Dependency Scan: {len(findings)} finding(s)\n")

    # Summary counts by severity
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            summary_parts.append(f"{sev_counts[sev]} {sev}")
    lines.append(f"Severity: {', '.join(summary_parts)}\n")

    for category, cat_findings in by_category.items():
        lines.append(f"--- {category} ({len(cat_findings)}) ---\n")
        for f in cat_findings:
            cwe_str = f" [{f.cwe}]" if f.cwe else ""
            lines.append(f"  [{f.severity.upper()}]{cwe_str} {f.description}")
            lines.append(f"    File: {f.file_path}:{f.line_number}")
            lines.append(f"    Evidence: {f.evidence}")
            lines.append("")

    return truncate_output("\n".join(lines))


async def _handle_update_yara_rules(input: dict, context: ToolContext) -> str:
    """Download or update YARA Forge community rules."""
    from app.config import get_settings

    forge_dir = get_settings().yara_forge_dir
    os.makedirs(forge_dir, exist_ok=True)
    dest = os.path.join(forge_dir, "yara-rules-core.yar")

    # YARA Forge distributes rules as a zip file
    script = (
        "set -e; "
        "URL=$(curl -s https://api.github.com/repos/YARAHQ/yara-forge/releases/latest "
        "| grep -o 'https://[^\"]*yara-forge-rules-core.zip' | head -1); "
        "curl -fsSL --max-time 60 -o /tmp/yara-forge.zip \"$URL\"; "
        f"unzip -o /tmp/yara-forge.zip -d /tmp/yara-forge-extract > /dev/null; "
        f"mv /tmp/yara-forge-extract/packages/core/yara-rules-core.yar {dest}; "
        "rm -rf /tmp/yara-forge.zip /tmp/yara-forge-extract"
    )

    proc = await asyncio.create_subprocess_exec(
        "sh", "-c", script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except TimeoutError:
        return "Error: download timed out after 120s"

    if proc.returncode != 0:
        err = stderr.decode("utf-8", errors="replace")[:300]
        return f"Error: YARA Forge download failed: {err}"

    # Count rules
    try:
        with open(dest) as f:
            content = f.read()
        rule_count = content.count("\nrule ")
    except Exception:
        rule_count = "unknown"

    return (
        f"YARA Forge community rules updated: {rule_count} rules downloaded to {forge_dir}.\n"
        f"These will be automatically loaded alongside built-in rules on the next scan."
    )


async def _handle_detect_update_mechanisms(input: dict, context: ToolContext) -> str:
    """Scan firmware for update mechanisms and report findings.

    Phase 3b: walks every detection root when no ``path`` filter is
    supplied. With a ``path`` filter, scope falls back to the single
    sub-directory (shim preserved).
    """
    from app.services.update_mechanism_service import (
        detect_update_mechanisms,
        format_mechanisms_report,
    )

    extracted_root = context.extracted_path
    input_path = input.get("path")
    if input_path:
        search_root = context.resolve_path(input_path)
        mechanisms = detect_update_mechanisms(search_root)
    else:
        roots = context.get_detection_roots() or [extracted_root]
        search_root = os.path.realpath(roots[0])
        extras = [r for r in roots[1:] if r] or None
        mechanisms = detect_update_mechanisms(search_root, extra_roots=extras)
    report = format_mechanisms_report(mechanisms)
    return truncate_output(report)


async def _handle_analyze_update_config(input: dict, context: ToolContext) -> str:
    """Deep-dive analysis of a specific update system's config."""
    from app.services.update_mechanism_service import analyze_update_config_detail

    extracted_root = context.extracted_path
    system = input["system"].strip().lower()
    config_path = input.get("path")

    if config_path:
        # Validate path within sandbox
        context.resolve_path(config_path)

    report = analyze_update_config_detail(extracted_root, system, config_path)
    return truncate_output(report)


# ---------------------------------------------------------------------------
# CRA (EU Cyber Resilience Act) Compliance Tools
# ---------------------------------------------------------------------------


async def _handle_create_cra_assessment(input: dict, context: ToolContext) -> str:
    """Create a CRA compliance assessment for the current firmware."""

    from app.services.cra_compliance_service import CRAComplianceService

    service = CRAComplianceService(context.db)
    assessment = await service.create_assessment(
        project_id=context.project_id,
        firmware_id=context.firmware_id,
        product_name=input.get("product_name"),
        product_version=input.get("product_version"),
        assessor_name=input.get("assessor_name"),
    )
    total = (
        assessment.auto_pass_count
        + assessment.auto_fail_count
        + assessment.manual_count
        + assessment.not_tested_count
    )
    return (
        f"CRA assessment created: {assessment.id}\n"
        f"{total} requirements initialized.\n"
        f"Use auto_populate_cra to map existing findings to requirements."
    )


async def _handle_auto_populate_cra(input: dict, context: ToolContext) -> str:
    """Auto-populate CRA assessment from existing tool findings."""
    import uuid as _uuid

    from app.services.cra_compliance_service import CRAComplianceService

    assessment_id = input.get("assessment_id")
    if not assessment_id:
        return "Error: assessment_id is required"

    service = CRAComplianceService(context.db)
    try:
        assessment = await service.auto_populate(_uuid.UUID(assessment_id))
    except ValueError as e:
        return f"Error: {e}"

    return (
        f"Auto-populated CRA assessment {assessment.id}:\n"
        f"  Pass: {assessment.auto_pass_count}\n"
        f"  Fail: {assessment.auto_fail_count}\n"
        f"  Manual review: {assessment.manual_count}\n"
        f"  Not tested: {assessment.not_tested_count}\n\n"
        f"Use update_cra_requirement to manually assess 'not_tested' requirements."
    )


async def _handle_update_cra_requirement(input: dict, context: ToolContext) -> str:
    """Manually update a CRA requirement status/notes."""
    import uuid as _uuid

    from app.services.cra_compliance_service import CRAComplianceService

    assessment_id = input.get("assessment_id")
    requirement_id = input.get("requirement_id")
    if not assessment_id:
        return "Error: assessment_id is required"
    if not requirement_id:
        return "Error: requirement_id is required"

    status = input.get("status")
    manual_notes = input.get("manual_notes")
    manual_evidence = input.get("manual_evidence")

    service = CRAComplianceService(context.db)
    try:
        req_result = await service.update_requirement(
            assessment_id=_uuid.UUID(assessment_id),
            requirement_id=requirement_id,
            status=status,
            manual_notes=manual_notes,
            manual_evidence=manual_evidence,
        )
    except ValueError as e:
        return f"Error: {e}"

    return (
        f"Updated requirement {req_result.requirement_id}: "
        f"{req_result.requirement_title}\n"
        f"  Status: {req_result.status}\n"
        f"  Notes: {req_result.manual_notes or '(none)'}"
    )


async def _handle_export_cra_checklist(input: dict, context: ToolContext) -> str:
    """Export CRA checklist as structured JSON."""
    import uuid as _uuid

    from app.services.cra_compliance_service import CRAComplianceService

    assessment_id = input.get("assessment_id")
    if not assessment_id:
        return "Error: assessment_id is required"

    service = CRAComplianceService(context.db)
    try:
        checklist = await service.export_checklist(_uuid.UUID(assessment_id))
    except ValueError as e:
        return f"Error: {e}"

    return truncate_output(json.dumps(checklist, indent=2, default=str))


async def _handle_generate_article14_notification(
    input: dict, context: ToolContext
) -> str:
    """Generate Article 14 ENISA notification for a CVE."""
    import uuid as _uuid

    from app.services.cra_compliance_service import CRAComplianceService

    assessment_id = input.get("assessment_id")
    cve_id = input.get("cve_id")
    if not assessment_id:
        return "Error: assessment_id is required"
    if not cve_id:
        return "Error: cve_id is required"

    service = CRAComplianceService(context.db)
    try:
        notification = await service.export_article14_notification(
            _uuid.UUID(assessment_id), cve_id
        )
    except ValueError as e:
        return f"Error: {e}"

    return truncate_output(json.dumps(notification, indent=2, default=str))


# ---------------------------------------------------------------------------
# ClamAV scanning
# ---------------------------------------------------------------------------


async def _handle_scan_with_clamav(input: dict, context: ToolContext) -> str:
    """Scan a file or directory with ClamAV antivirus."""
    from app.services import clamav_service

    available = await clamav_service.check_available()
    if not available:
        return "ClamAV is not available. The clamd service may not be running or is unreachable."

    path = context.resolve_path(input.get("path", "/"))

    if os.path.isfile(path):
        result = await clamav_service.scan_file(path)
        if result.error:
            return f"Error scanning {_rel(path, context.extracted_path)}: {result.error}"
        if result.infected:
            return (
                f"INFECTED: {_rel(path, context.extracted_path)}\n"
                f"Signature: {result.signature}"
            )
        return f"Clean: {_rel(path, context.extracted_path)} — no threats detected."

    elif os.path.isdir(path):
        max_files = input.get("max_files", 500)
        results = await clamav_service.scan_directory(path, max_files=max_files)
        infected = [r for r in results if r.infected]
        errors = [r for r in results if r.error]

        lines = [f"ClamAV scan of {_rel(path, context.extracted_path)}:"]
        lines.append(f"Files scanned: {len(results)}")
        lines.append(f"Infected: {len(infected)}")
        if errors:
            lines.append(f"Errors: {len(errors)}")

        if infected:
            lines.append("\n--- Infected files ---")
            for r in infected[:50]:
                rel = _rel(r.file_path, context.extracted_path)
                lines.append(f"  {rel}: {r.signature}")

        if errors:
            lines.append("\n--- Scan errors ---")
            for r in errors[:10]:
                rel = _rel(r.file_path, context.extracted_path)
                lines.append(f"  {rel}: {r.error}")

        return truncate_output("\n".join(lines))
    else:
        return f"Path not found: {input.get('path', '/')}"


async def _handle_scan_firmware_clamav(input: dict, context: ToolContext) -> str:
    """Batch scan all extracted firmware files with ClamAV.

    Phase 3b: the 500-file cap is distributed across every detection root
    so scatter-zip siblings / raw-image dirs aren't starved. Roots
    covered count appears in the output for transparency.
    """
    from app.services import clamav_service

    available = await clamav_service.check_available()
    if not available:
        return "ClamAV is not available. The clamd service may not be running or is unreachable."

    if not context.extracted_path:
        return "No extracted firmware available. Unpack firmware first."

    roots = context.get_detection_roots() or [context.extracted_path]
    # Distribute the 500-file cap evenly with a small floor per root.
    per_root_cap = max(100, 500 // max(1, len(roots)))
    results: list = []
    for root in roots:
        part = await clamav_service.scan_directory(root, max_files=per_root_cap)
        results.extend(part)
    infected = [r for r in results if r.infected]
    errors = [r for r in results if r.error]

    lines = ["ClamAV firmware scan results:"]
    lines.append(f"Files scanned: {len(results)}")
    lines.append(f"Infected: {len(infected)}")
    lines.append(f"Clean: {len(results) - len(infected) - len(errors)}")
    if errors:
        lines.append(f"Errors: {len(errors)}")

    if infected:
        lines.append("\n--- Infected files ---")
        for r in infected[:50]:
            rel = _rel(r.file_path, context.extracted_path)
            lines.append(f"  MALWARE: {rel}")
            lines.append(f"    Signature: {r.signature}")
    else:
        lines.append("\nNo malware detected.")

    if errors:
        lines.append("\n--- Scan errors ---")
        for r in errors[:10]:
            lines.append(f"  {r.error}")

    return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# VirusTotal hash-only lookups
# ---------------------------------------------------------------------------


async def _handle_check_virustotal(input: dict, context: ToolContext) -> str:
    """Check a single file's hash against VirusTotal."""
    from app.services import virustotal_service

    path = context.resolve_path(input.get("path", "/"))
    if not os.path.isfile(path):
        return f"Not a file: {input.get('path', '/')}"

    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(
        None, virustotal_service._compute_sha256, path
    )

    result = await virustotal_service.check_hash(sha256)
    if result is None:
        return (
            "VirusTotal API key not configured. Set VT_API_KEY in .env "
            "to enable hash-only lookups. No file data is ever uploaded."
        )

    rel = _rel(path, context.extracted_path)
    lines = [f"VirusTotal lookup for {rel}:", f"SHA-256: {sha256}"]

    if not result.found:
        lines.append("Status: Not found in VirusTotal corpus")
        lines.append("(File hash not previously submitted to VT)")
    else:
        ratio = f"{result.detection_count}/{result.total_engines}"
        if result.detection_count == 0:
            lines.append(f"Status: Clean ({ratio} engines)")
        else:
            lines.append(f"Status: DETECTED ({ratio} engines)")
            lines.append("\nDetections:")
            for d in result.detections[:15]:
                lines.append(f"  {d}")
        lines.append(f"\nPermalink: {result.permalink}")

    return truncate_output("\n".join(lines))


async def _handle_scan_firmware_virustotal(input: dict, context: ToolContext) -> str:
    """Batch hash-check all ELF/PE binaries in firmware against VirusTotal."""
    from app.services import virustotal_service

    api_key = virustotal_service._get_api_key()
    if not api_key:
        return (
            "VirusTotal API key not configured. Set VT_API_KEY in .env "
            "to enable hash-only lookups. No file data is ever uploaded."
        )

    if not context.extracted_path:
        return "No extracted firmware available. Unpack firmware first."

    # Phase 3b: collect binaries from every detection root, dedupe by
    # SHA-256 across roots so a blob in two partitions isn't counted
    # twice against the API cap.
    loop = asyncio.get_running_loop()
    max_files = input.get("max_files", 50)
    roots = context.get_detection_roots() or [context.extracted_path]
    per_root_cap = max(25, max_files // max(1, len(roots)))
    hashes: list[tuple[str, str]] = []
    seen_sha: set[str] = set()
    for root in roots:
        partial = await loop.run_in_executor(
            None, virustotal_service.collect_binary_hashes,
            root, per_root_cap,
        )
        for sha, rel in partial:
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            hashes.append((sha, rel))
            if len(hashes) >= max_files:
                break
        if len(hashes) >= max_files:
            break

    if not hashes:
        return "No ELF or PE binaries found in extracted firmware."

    lines = [
        f"VirusTotal batch scan: {len(hashes)} binaries across {len(roots)} detection root(s)",
        f"Rate limit: {virustotal_service.FREE_TIER_BATCH} lookups/min (free tier)",
        f"Estimated time: ~{(len(hashes) // virustotal_service.FREE_TIER_BATCH) * 15}s",
        "",
    ]

    results = await virustotal_service.batch_check_hashes(hashes)

    detected = [r for r in results if r.found and r.detection_count > 0]
    clean = [r for r in results if r.found and r.detection_count == 0]
    not_found = [r for r in results if not r.found]

    lines.append("--- Summary ---")
    lines.append(f"Detected (malicious/suspicious): {len(detected)}")
    lines.append(f"Clean: {len(clean)}")
    lines.append(f"Not in VT corpus: {len(not_found)}")

    if detected:
        lines.append("\n--- Detected files ---")
        for r in detected:
            lines.append(f"  {r.file_path}: {r.detection_count}/{r.total_engines}")
            for d in r.detections[:5]:
                lines.append(f"    {d}")
            lines.append(f"    {r.permalink}")

    return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# abuse.ch threat intelligence (MalwareBazaar, ThreatFox, URLhaus, YARAify)
# ---------------------------------------------------------------------------


async def _handle_check_malwarebazaar_hash(input: dict, context: ToolContext) -> str:
    """Check a file's hash against MalwareBazaar for known malware."""
    from app.services import abusech_service, virustotal_service

    path = context.resolve_path(input.get("path", "/"))
    if not os.path.isfile(path):
        return f"Not a file: {input.get('path', '/')}"

    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(
        None, virustotal_service._compute_sha256, path
    )

    result = await abusech_service.check_malwarebazaar(sha256)
    rel = _rel(path, context.extracted_path)
    lines = [f"MalwareBazaar lookup for {rel}:", f"SHA-256: {sha256}"]

    if not result.found:
        lines.append("Status: Not found in MalwareBazaar")
        lines.append("(Hash not associated with any known malware sample)")
    else:
        lines.append("Status: KNOWN MALWARE")
        if result.signature:
            lines.append(f"Signature: {result.signature}")
        if result.file_type:
            lines.append(f"File type: {result.file_type}")
        if result.tags:
            lines.append(f"Tags: {', '.join(result.tags[:10])}")
        if result.first_seen:
            lines.append(f"First seen: {result.first_seen}")
        if result.reporter:
            lines.append(f"Reporter: {result.reporter}")

    return truncate_output("\n".join(lines))


async def _handle_check_threatfox_ioc(input: dict, context: ToolContext) -> str:
    """Check an IOC (hash, IP, domain) against ThreatFox."""
    from app.services import abusech_service

    ioc = input.get("ioc", "")
    if not ioc:
        return "Error: 'ioc' parameter is required (hash, IP, or domain)"

    ioc_type = input.get("ioc_type", "sha256_hash")

    results = await abusech_service.check_threatfox(ioc, ioc_type)
    lines = [f"ThreatFox lookup for {ioc} (type: {ioc_type}):"]

    if not results:
        lines.append("Status: Not found in ThreatFox IOC database")
    else:
        lines.append(f"Status: FOUND — {len(results)} IOC record(s)")
        for r in results[:10]:
            lines.append(f"\n  Threat: {r.threat_type}")
            lines.append(f"  Malware: {r.malware}")
            lines.append(f"  Confidence: {r.confidence_level}%")
            if r.tags:
                lines.append(f"  Tags: {', '.join(r.tags[:5])}")
            if r.reference:
                lines.append(f"  Reference: {r.reference}")

    return truncate_output("\n".join(lines))


async def _handle_check_urlhaus_url(input: dict, context: ToolContext) -> str:
    """Check a URL against URLhaus for known malware distribution."""
    from app.services import abusech_service

    url = input.get("url", "")
    if not url:
        return "Error: 'url' parameter is required"

    result = await abusech_service.check_urlhaus(url)
    lines = [f"URLhaus lookup for: {url}"]

    if not result.found:
        lines.append("Status: Not found in URLhaus")
    else:
        lines.append("Status: KNOWN MALICIOUS URL")
        if result.threat:
            lines.append(f"Threat: {result.threat}")
        lines.append(f"URL status: {result.status}")
        if result.tags:
            lines.append(f"Tags: {', '.join(result.tags[:10])}")
        if result.date_added:
            lines.append(f"Date added: {result.date_added}")

    return truncate_output("\n".join(lines))


async def _handle_enrich_firmware_threat_intel(input: dict, context: ToolContext) -> str:
    """Batch-check firmware IOCs against all abuse.ch services."""
    from app.services import abusech_service, virustotal_service

    if not context.extracted_path:
        return "No extracted firmware available. Unpack firmware first."

    # Phase 3b: collect across every detection root, SHA-dedupe.
    loop = asyncio.get_running_loop()
    max_hashes = input.get("max_hashes", 30)
    roots = context.get_detection_roots() or [context.extracted_path]
    per_root_cap = max(15, max_hashes // max(1, len(roots)))
    hashes: list[tuple[str, str]] = []
    seen_sha: set[str] = set()
    for root in roots:
        partial = await loop.run_in_executor(
            None, virustotal_service.collect_binary_hashes,
            root, per_root_cap,
        )
        for sha, rel in partial:
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            hashes.append((sha, rel))
            if len(hashes) >= max_hashes:
                break
        if len(hashes) >= max_hashes:
            break

    if not hashes:
        return "No ELF or PE binaries found in extracted firmware."

    # Collect IPs from hardcoded IP findings if available
    ips: list[str] = []
    urls: list[str] = []

    lines = [
        f"abuse.ch threat intel enrichment: {len(hashes)} binaries across {len(roots)} detection root(s)",
        "Services: MalwareBazaar, ThreatFox, URLhaus, YARAify",
        "",
    ]

    summary = await abusech_service.enrich_iocs(
        hashes=hashes,
        ips=ips,
        urls=urls,
        max_hashes=max_hashes,
    )

    # MalwareBazaar results
    mb_hits = summary["malwarebazaar"]
    lines.append(f"--- MalwareBazaar: {len(mb_hits)} known malware samples ---")
    if mb_hits:
        for r in mb_hits[:20]:
            lines.append(f"  {r.file_path}: {r.signature or 'unknown'}")
            if r.tags:
                lines.append(f"    Tags: {', '.join(r.tags[:5])}")
    else:
        lines.append("  No known malware samples found.")

    # ThreatFox results
    tf_hits = summary["threatfox"]
    lines.append(f"\n--- ThreatFox: {len(tf_hits)} IOC matches ---")
    if tf_hits:
        for r in tf_hits[:20]:
            lines.append(f"  {r.ioc}: {r.malware} ({r.threat_type})")
    else:
        lines.append("  No IOC matches found.")

    # URLhaus results
    uh_hits = summary["urlhaus"]
    lines.append(f"\n--- URLhaus: {len(uh_hits)} malicious URLs ---")
    if uh_hits:
        for r in uh_hits[:20]:
            lines.append(f"  {r.url}: {r.threat} ({r.status})")
    else:
        lines.append("  No malicious URLs found.")

    # YARAify results
    yf_hits = summary["yaraify"]
    lines.append(f"\n--- YARAify: {len(yf_hits)} community YARA matches ---")
    if yf_hits:
        for r in yf_hits[:20]:
            rules = ", ".join(r.rule_matches[:5])
            lines.append(f"  {r.file_path}: {rules}")
    else:
        lines.append("  No community YARA matches found.")

    total = len(mb_hits) + len(tf_hits) + len(uh_hits) + len(yf_hits)
    lines.append(f"\n--- Total threat intel hits: {total} ---")

    return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# CIRCL Hashlookup (known-good identification)
# ---------------------------------------------------------------------------


async def _handle_check_known_good_hash(input: dict, context: ToolContext) -> str:
    """Check if a file is a known-good binary via CIRCL hashlookup."""
    from app.services import hashlookup_service, virustotal_service

    path = context.resolve_path(input.get("path", "/"))
    if not os.path.isfile(path):
        return f"Not a file: {input.get('path', '/')}"

    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(
        None, virustotal_service._compute_sha256, path
    )

    result = await hashlookup_service.check_known_good(sha256)
    rel = _rel(path, context.extracted_path)
    lines = [f"CIRCL Hashlookup for {rel}:", f"SHA-256: {sha256}"]

    if not result.known:
        lines.append("Status: Not found in known-good databases")
        lines.append("(This doesn't mean the file is malicious — it may simply be custom/proprietary)")
    else:
        lines.append("Status: KNOWN GOOD")
        lines.append(f"Source: {result.source}")
        if result.product_name:
            lines.append(f"Product: {result.product_name}")
        if result.vendor:
            lines.append(f"Vendor: {result.vendor}")
        if result.file_name:
            lines.append(f"Original filename: {result.file_name}")

    return truncate_output("\n".join(lines))


async def _handle_scan_firmware_known_good(input: dict, context: ToolContext) -> str:
    """Batch-check firmware binaries against CIRCL known-good database.

    Phase 3b: binaries harvested across every detection root, SHA-deduped
    so each distinct hash counts against the cap exactly once.
    """
    from app.services import hashlookup_service, virustotal_service

    if not context.extracted_path:
        return "No extracted firmware available. Unpack firmware first."

    loop = asyncio.get_running_loop()
    max_files = input.get("max_files", 100)
    roots = context.get_detection_roots() or [context.extracted_path]
    per_root_cap = max(50, max_files // max(1, len(roots)))
    hashes: list[tuple[str, str]] = []
    seen_sha: set[str] = set()
    for root in roots:
        partial = await loop.run_in_executor(
            None, virustotal_service.collect_binary_hashes,
            root, per_root_cap,
        )
        for sha, rel in partial:
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            hashes.append((sha, rel))
            if len(hashes) >= max_files:
                break
        if len(hashes) >= max_files:
            break

    if not hashes:
        return "No ELF or PE binaries found in extracted firmware."

    results = await hashlookup_service.batch_check_known_good(hashes, max_files=max_files)

    known = [r for r in results if r.known]
    unknown = [r for r in results if not r.known]

    lines = [
        f"CIRCL Hashlookup: {len(hashes)} binaries checked",
        f"Known-good: {len(known)}",
        f"Unknown/custom: {len(unknown)}",
        "",
    ]

    if known:
        lines.append("--- Known-good files (safe to deprioritize) ---")
        for r in known[:50]:
            product = f" ({r.product_name})" if r.product_name else ""
            vendor = f" by {r.vendor}" if r.vendor else ""
            lines.append(f"  {r.file_path}: {r.source}{product}{vendor}")

    if unknown:
        lines.append(f"\n--- Unknown/custom binaries ({len(unknown)}) ---")
        lines.append("These require manual analysis — not in any known-good database.")
        for r in unknown[:50]:
            lines.append(f"  {r.file_path}")

    return truncate_output("\n".join(lines))


def register_security_tools(registry: ToolRegistry) -> None:
    """Register all security assessment tools with the given registry."""

    registry.register(
        name="check_known_cves",
        description=(
            "Look up known CVEs for a given software component and version. "
            "Covers common embedded Linux components: BusyBox, OpenSSL, "
            "Dropbear, dnsmasq, lighttpd, curl, uClibc, Linux kernel. "
            "Uses a local database — results are best-effort. "
            "Cross-reference with your own knowledge for completeness."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "component": {
                    "type": "string",
                    "description": "Software component name (e.g. 'busybox', 'openssl', 'dropbear')",
                },
                "version": {
                    "type": "string",
                    "description": "Version string (e.g. '1.33.0', '1.1.1k')",
                },
            },
            "required": ["component", "version"],
        },
        handler=_handle_check_known_cves,
    )

    registry.register(
        name="analyze_config_security",
        description=(
            "Analyze a configuration file for security issues. Checks for: "
            "empty passwords in /etc/shadow, extra UID-0 accounts in /etc/passwd, "
            "insecure SSH settings (root login, password auth, empty passwords), "
            "web server directory listing, debug mode flags, and default/weak "
            "passwords in config values. Works on any text config file."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the configuration file to analyze (e.g. '/etc/shadow', '/etc/ssh/sshd_config')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": ["path"],
        },
        handler=_handle_analyze_config_security,
    )

    registry.register(
        name="check_setuid_binaries",
        description=(
            "Find all setuid and setgid binaries in the firmware filesystem. "
            "Setuid-root binaries are common privilege escalation targets. "
            "Returns file permissions, owner info, and paths."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (default: entire filesystem)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": [],
        },
        handler=_handle_check_setuid_binaries,
    )

    registry.register(
        name="analyze_init_scripts",
        description=(
            "Analyze init scripts, inittab, and systemd units to identify "
            "services started at boot. Flags security-relevant services: "
            "telnet (plaintext), FTP, TFTP (unauthenticated), UPnP, SNMP. "
            "Covers /etc/inittab, /etc/init.d/, /etc/rc.d/, and systemd units."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory to scan (default: entire filesystem)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": [],
        },
        handler=_handle_analyze_init_scripts,
    )

    registry.register(
        name="check_filesystem_permissions",
        description=(
            "Check for filesystem permission issues: world-writable files "
            "and directories (without sticky bit), sensitive files with "
            "overly permissive access (shadow, private keys, credentials, "
            "SSH configs). Helps identify privilege escalation opportunities."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (default: entire filesystem)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100, set to 0 for all)",
                },
            },
            "required": [],
        },
        handler=_handle_check_filesystem_permissions,
    )

    registry.register(
        name="analyze_certificate",
        description=(
            "Parse and audit X.509 certificates (PEM and DER format) found in "
            "the firmware. Reports subject, issuer, validity dates, key type and "
            "size, signature algorithm, SANs, and self-signed status. Flags "
            "security issues: expired certs, weak keys (<2048 RSA), weak "
            "signatures (MD5, SHA-1), self-signed certs, and wildcards. "
            "If no path given, scans /etc/ssl/, /etc/pki/, and common cert "
            "directories. Pass a file path to analyze a specific certificate."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to a certificate file or directory to scan. "
                        "If omitted, scans common certificate directories "
                        "(/etc/ssl/, /etc/pki/, etc.) and falls back to "
                        "scanning the entire filesystem by extension."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_analyze_certificate,
    )

    registry.register(
        name="check_kernel_hardening",
        description=(
            "Check kernel sysctl security parameters in the firmware. "
            "Analyzes /etc/sysctl.conf and init scripts for 18 hardening "
            "parameters: ASLR, kptr_restrict, SYN cookies, reverse path "
            "filtering, ICMP redirects, BPF restrictions, ptrace scope, etc. "
            "Router-aware: adjusts severity for ip_forward on routing firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root path to scan (default: '/')",
                },
            },
            "required": [],
        },
        handler=_handle_check_kernel_hardening,
    )

    registry.register(
        name="scan_with_yara",
        description=(
            "Scan firmware files with YARA rules to detect malware, backdoors, "
            "and suspicious patterns. Uses 30+ built-in rules covering: "
            "IoT botnets (Mirai, VPNFilter, BotenaGo), reverse shells, "
            "hardcoded backdoors, crypto miners, web shells, data exfiltration, "
            "embedded private keys, weak crypto, insecure update mechanisms, "
            "and command injection vectors. Optionally filter to a subdirectory."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Subdirectory within the firmware to scan "
                        "(default: scan entire filesystem)"
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_scan_with_yara,
    )

    registry.register(
        name="extract_kernel_config",
        description=(
            "Extract the kernel .config from firmware. Searches for embedded "
            "IKCONFIG in kernel images (vmlinuz, zImage, uImage) using the "
            "IKCFG_ST magic marker, and checks common locations like "
            "/proc/config.gz, /boot/config-*, /lib/modules/*/build/.config. "
            "Pass a specific kernel image path, or omit to auto-search."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to a kernel image (vmlinuz, zImage, etc.), "
                        "config.gz, or .config file. If omitted, searches "
                        "common firmware locations automatically."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_extract_kernel_config,
    )

    registry.register(
        name="check_kernel_config",
        description=(
            "Analyze a kernel .config for security hardening gaps. Uses "
            "kconfig-hardened-check if installed (400+ checks), otherwise "
            "falls back to a built-in set of 26 critical checks covering "
            "stack protection, KASLR, FORTIFY_SOURCE, seccomp, /dev/mem, "
            "module signing, and more. Provide config_text directly, a "
            "path to a config file, or omit both to auto-extract."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "config_text": {
                    "type": "string",
                    "description": (
                        "Raw kernel config text (from extract_kernel_config). "
                        "If omitted, uses 'path' or auto-extracts."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Path to a kernel .config file or config.gz. "
                        "If omitted and no config_text, auto-extracts."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_check_kernel_config,
    )

    # ----- SELinux policy analysis -----

    registry.register(
        name="analyze_selinux_policy",
        description=(
            "Analyze SELinux policy in Android firmware. Finds policy files "
            "(CIL, binary sepolicy) in /system/etc/selinux/ and related "
            "directories, identifies permissive domains, counts allow/neverallow "
            "rules, and checks enforcement status. Works offline using CIL text "
            "parsing with optional setools/seinfo fallback for binary policies. "
            "Only applicable to Android firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_analyze_selinux_policy,
    )

    registry.register(
        name="check_selinux_enforcement",
        description=(
            "Quick check of SELinux enforcement status and permissive domains "
            "in Android firmware. Reads build.prop for ro.boot.selinux and "
            "related properties, and lists any permissive domains that weaken "
            "the security posture. Only applicable to Android firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_check_selinux_enforcement,
    )

    registry.register(
        name="check_compliance",
        description=(
            "Generate a compliance report against a security standard. "
            "Maps all existing findings to the standard's provisions and "
            "returns a compliance matrix with pass/fail/partial/not_tested "
            "status for each provision. Currently supports ETSI EN 303 645 "
            "(Cyber Security for Consumer IoT), which covers 13 provisions: "
            "default passwords, vulnerability management, software updates, "
            "credential storage, secure communication, attack surface, "
            "software integrity, data security, resilience, telemetry, "
            "data deletion, installation, and input validation. "
            "Run security analysis tools first for best coverage."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "standard": {
                    "type": "string",
                    "description": (
                        "The compliance standard to check against. "
                        "Currently supported: 'etsi-en-303-645' (default)."
                    ),
                    "default": "etsi-en-303-645",
                },
            },
            "required": [],
        },
        handler=_handle_check_compliance,
    )

    registry.register(
        name="scan_scripts",
        description=(
            "Scan firmware shell scripts, PHP, Lua, and Python files for "
            "security issues using Semgrep with firmware-specific rules. "
            "Detects: command injection (eval, system, exec, popen), "
            "insecure downloads (HTTP without TLS, disabled cert checks), "
            "hardcoded credentials (passwords, API keys), insecure "
            "permissions (chmod 777/666/o+w), dangerous dynamic execution "
            "(loadstring, eval, assert), and debug artifacts (set -x). "
            "Requires semgrep CLI to be installed."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan within the firmware filesystem "
                        "(e.g. '/etc/init.d', '/usr/lib/lua'). "
                        "Defaults to the entire firmware root."
                    ),
                },
                "languages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Filter results to specific languages: "
                        "'bash', 'php', 'lua', 'python'. "
                        "Omit to scan all supported languages."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_scan_scripts,
    )

    # ----- ShellCheck static analysis -----

    registry.register(
        name="shellcheck_scan",
        description=(
            "Run ShellCheck static analysis on shell scripts to find command "
            "injection via unquoted variables, unsafe patterns, and quoting "
            "bugs. Complementary to scan_scripts (Semgrep). Discovers scripts "
            "by extension (.sh, .ash), shebang (#!), and well-known paths "
            "(/etc/init.d/, /www/cgi-bin/). Maps security-relevant SC codes "
            "to CWEs (SC2086 → CWE-78, etc.). Requires shellcheck CLI."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan within the firmware filesystem "
                        "(e.g. '/etc/init.d', '/usr/bin'). "
                        "Defaults to the entire firmware root."
                    ),
                },
                "severity": {
                    "type": "string",
                    "enum": ["error", "warning", "info", "style"],
                    "description": (
                        "Minimum severity level to report. "
                        "Default: 'warning'."
                    ),
                },
                "shell": {
                    "type": "string",
                    "enum": ["sh", "bash", "dash", "ksh"],
                    "description": (
                        "Shell dialect to assume. Most firmware uses "
                        "POSIX sh/ash, so default is 'sh'."
                    ),
                },
                "max_files": {
                    "type": "integer",
                    "description": (
                        "Maximum number of scripts to scan. Default: 100."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_shellcheck_scan,
    )

    # ----- Bandit Python security linter -----

    registry.register(
        name="bandit_scan",
        description=(
            "Run Bandit Python security linter on Python scripts in firmware. "
            "Detects command injection (subprocess shell=True, exec, eval), "
            "hardcoded credentials, insecure crypto, pickle deserialization, "
            "insecure TLS. Discovers Python scripts by extension (.py, .pyw) "
            "and shebang. Returns findings with CWE mappings and severity. "
            "Requires bandit CLI."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan within the firmware filesystem "
                        "(e.g. '/usr/lib/python3'). "
                        "Defaults to the entire firmware root."
                    ),
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": (
                        "Minimum severity level to report. "
                        "Default: 'low' (report all)."
                    ),
                },
                "confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": (
                        "Minimum confidence level to report. "
                        "Default: 'medium'."
                    ),
                },
                "max_files": {
                    "type": "integer",
                    "description": (
                        "Maximum number of scripts to scan. Default: 100."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_bandit_scan,
    )

    # ----- Secure boot chain analysis -----

    registry.register(
        name="check_secure_boot",
        description=(
            "Detect and assess secure boot mechanisms in firmware. "
            "Checks for U-Boot verified boot (FIT signatures, CONFIG_FIT_SIGNATURE, "
            "signing key DTBs), dm-verity / Android Verified Boot (verity_key files, "
            "fstab verify/avb flags, vbmeta partitions, build.prop boot state), and "
            "UEFI Secure Boot (EFI directories, PK/KEK/db/dbx key databases, "
            ".cer/.auth certificate files). Also performs weak key detection across "
            "all mechanisms — flags certificates with test/debug/sample CNs and "
            "self-signed certs in boot verification contexts. Returns a posture "
            "assessment: STRONG, WEAKENED, PARTIAL, or NOT DETECTED."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Optional path within the firmware filesystem to "
                        "restrict the search. Defaults to scanning the "
                        "entire firmware root."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_check_secure_boot,
    )

    registry.register(
        name="update_yara_rules",
        description=(
            "Download or update YARA Forge community rules. Fetches the latest "
            "yara-forge-rules-core.yar from GitHub, adding thousands of community "
            "detection rules alongside the built-in Wairz rules. Safe to re-run."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_update_yara_rules,
    )

    registry.register(
        name="detect_network_dependencies",
        description=(
            "Scan firmware for network dependencies: NFS/CIFS mounts, cloud storage "
            "endpoints (S3, Azure Blob, GCS), database connections (MongoDB, MySQL, "
            "PostgreSQL, Redis, InfluxDB), MQTT/AMQP brokers, FTP/TFTP URLs, remote "
            "syslog forwarding, and iSCSI targets. Classifies findings by severity "
            "and CWE. Flags credential exposure in mount options and connection strings. "
            "Scans config files first (fstab, exports, smb.conf, mosquitto.conf), "
            "then init scripts and crontabs, then all text files."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory within the firmware to scan. "
                        "Defaults to the entire firmware root."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum findings to return (default: 100, set to 0 for all)",
                },
            },
            "required": [],
        },
        handler=_handle_detect_network_dependencies,
    )

    # ----- Firmware update mechanism detection -----

    registry.register(
        name="detect_update_mechanisms",
        description=(
            "Scan firmware for update mechanisms: SWUpdate, RAUC, Mender, "
            "opkg/sysupgrade, U-Boot env, Android OTA, package managers "
            "(dpkg/apt/yum), and custom wget+flash OTA scripts. For each "
            "detected system, reports binaries, config files, update URLs "
            "(HTTP vs HTTPS), A/B partition scheme, and security findings. "
            "Flags: no update mechanism (CWE-1277), HTTP-only URLs (CWE-319), "
            "no rollback (CWE-1277), custom OTA scripts (CWE-494)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Root path within firmware to scan. "
                        "Defaults to the entire firmware filesystem."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_detect_update_mechanisms,
    )

    registry.register(
        name="analyze_update_config",
        description=(
            "Deep-dive analysis of a specific update system's configuration. "
            "Reads and parses the config files for the named update system, "
            "extracting server URLs, feed definitions, slot layouts, signing "
            "settings, and poll intervals. Systems: swupdate, rauc, mender, "
            "opkg, uboot_env, android_ota, package_manager."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "system": {
                    "type": "string",
                    "description": (
                        "Update system to analyze. One of: swupdate, rauc, "
                        "mender, opkg, uboot_env, android_ota, package_manager."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Optional path to a specific config file to analyze. "
                        "If omitted, auto-discovers config files for the system."
                    ),
                },
            },
            "required": ["system"],
        },
        handler=_handle_analyze_update_config,
    )

    # ----- CRA (EU Cyber Resilience Act) compliance -----

    registry.register(
        name="create_cra_assessment",
        description=(
            "Create a new CRA (EU Cyber Resilience Act) compliance assessment "
            "for the current firmware. Initializes all 20 Annex I requirements "
            "(13 Part 1 security + 7 Part 2 vulnerability handling) with status "
            "'not_tested'. Optionally provide product metadata and assessor name."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "product_name": {
                    "type": "string",
                    "description": "Product name for the assessment (e.g. 'Router X200')",
                },
                "product_version": {
                    "type": "string",
                    "description": "Product firmware version (e.g. '2.1.0')",
                },
                "assessor_name": {
                    "type": "string",
                    "description": "Name of the person or team performing the assessment",
                },
            },
            "required": [],
        },
        handler=_handle_create_cra_assessment,
    )

    registry.register(
        name="auto_populate_cra",
        description=(
            "Auto-populate a CRA assessment from existing tool findings. "
            "Maps findings to the 20 CRA Annex I requirements based on title "
            "patterns, CWE IDs, and tool sources. High/critical severity findings "
            "cause 'fail', lower severity causes 'partial', no findings means "
            "'pass'. Non-automatable requirements are left for manual assessment. "
            "Run security analysis tools first for best coverage."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "assessment_id": {
                    "type": "string",
                    "description": "UUID of the CRA assessment to auto-populate",
                },
            },
            "required": ["assessment_id"],
        },
        handler=_handle_auto_populate_cra,
    )

    registry.register(
        name="update_cra_requirement",
        description=(
            "Manually update a single CRA requirement's status and/or notes. "
            "Use for requirements that cannot be auto-populated (e.g. risk "
            "assessment documentation, vulnerability disclosure policy) or to "
            "override auto-populated results with manual findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "assessment_id": {
                    "type": "string",
                    "description": "UUID of the CRA assessment",
                },
                "requirement_id": {
                    "type": "string",
                    "description": (
                        "CRA requirement ID (e.g. 'annex1_part1_1.3', "
                        "'annex1_part2_2.4')"
                    ),
                },
                "status": {
                    "type": "string",
                    "enum": ["pass", "fail", "partial", "not_tested", "not_applicable"],
                    "description": "New status for the requirement",
                },
                "manual_notes": {
                    "type": "string",
                    "description": "Manual assessment notes (e.g. justification for status)",
                },
                "manual_evidence": {
                    "type": "string",
                    "description": "Manual evidence text (e.g. document references, test results)",
                },
            },
            "required": ["assessment_id", "requirement_id"],
        },
        handler=_handle_update_cra_requirement,
    )

    registry.register(
        name="export_cra_checklist",
        description=(
            "Export a CRA compliance checklist as structured JSON. Returns the "
            "full assessment with all 20 requirements grouped by Annex I Part 1 "
            "(security) and Part 2 (vulnerability handling), including evidence, "
            "finding IDs, deadlines, and compliance summary."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "assessment_id": {
                    "type": "string",
                    "description": "UUID of the CRA assessment to export",
                },
            },
            "required": ["assessment_id"],
        },
        handler=_handle_export_cra_checklist,
    )

    registry.register(
        name="generate_article14_notification",
        description=(
            "Generate an Article 14 ENISA vulnerability notification document "
            "for a specific CVE. Article 14 of the CRA requires manufacturers "
            "to notify ENISA within 24 hours of becoming aware of an actively "
            "exploited vulnerability. Produces a structured notification with "
            "product info, vulnerability details, affected components, timeline, "
            "and mitigation status."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "assessment_id": {
                    "type": "string",
                    "description": "UUID of the CRA assessment",
                },
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (e.g. 'CVE-2024-1234')",
                },
            },
            "required": ["assessment_id", "cve_id"],
        },
        handler=_handle_generate_article14_notification,
    )

    # ----- ClamAV antivirus scanning -----

    registry.register(
        name="scan_with_clamav",
        description=(
            "Scan a specific file or directory with ClamAV antivirus. "
            "Detects malware, trojans, backdoors, and other threats using "
            "the ClamAV signature database (updated daily). The ClamAV "
            "daemon runs as a Docker sidecar. Returns infection status and "
            "signature names for detected threats. Gracefully reports if "
            "ClamAV is unavailable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path within the firmware to scan. Can be a file "
                        "or directory. Defaults to the firmware root."
                    ),
                },
                "max_files": {
                    "type": "integer",
                    "description": (
                        "Maximum files to scan in directory mode. Default: 500."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_scan_with_clamav,
    )

    registry.register(
        name="scan_firmware_clamav",
        description=(
            "Batch scan all extracted firmware files with ClamAV antivirus. "
            "Scans up to 500 regular files (skipping symlinks, devices, and "
            "files >100MB). Returns a summary with infected file list and "
            "malware signature names. The ClamAV daemon runs as a Docker "
            "sidecar with daily signature updates."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_scan_firmware_clamav,
    )

    # ----- VirusTotal hash-only lookups -----

    registry.register(
        name="check_virustotal",
        description=(
            "Check a file's SHA-256 hash against VirusTotal. Privacy-first: "
            "only the hash is sent, never the file contents. Returns detection "
            "count, engine names, and a permalink. Requires VT_API_KEY in .env. "
            "Gracefully reports if API key not configured."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to check",
                },
            },
            "required": ["path"],
        },
        handler=_handle_check_virustotal,
    )

    registry.register(
        name="scan_firmware_virustotal",
        description=(
            "Batch hash-check all ELF and PE binaries in extracted firmware "
            "against VirusTotal. Privacy-first: only SHA-256 hashes are sent, "
            "never file contents. Prioritizes shared libraries, then "
            "executables. Rate-limited to 4 req/min (VT free tier). "
            "Requires VT_API_KEY in .env."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_files": {
                    "type": "integer",
                    "description": (
                        "Maximum binaries to check. Default: 50. "
                        "Higher values take longer due to rate limiting."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_scan_firmware_virustotal,
    )

    # ----- abuse.ch threat intelligence -----

    registry.register(
        name="check_malwarebazaar_hash",
        description=(
            "Check a file's SHA-256 hash against MalwareBazaar to see if it "
            "is a known malware sample. Returns malware signature, tags, and "
            "first-seen date if found. Only the hash is sent — no file data "
            "is uploaded. Works without an API key (ABUSECH_AUTH_KEY optional "
            "for higher rate limits)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to check",
                },
            },
            "required": ["path"],
        },
        handler=_handle_check_malwarebazaar_hash,
    )

    registry.register(
        name="check_threatfox_ioc",
        description=(
            "Check an IOC (indicator of compromise) against ThreatFox. "
            "Supports hash, IP address, domain, and URL lookups. Returns "
            "associated malware family, threat type, and confidence level. "
            "Useful for checking hardcoded IPs and extracted URLs against "
            "known C2 infrastructure."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ioc": {
                    "type": "string",
                    "description": (
                        "The IOC to look up: a SHA-256 hash, IP address "
                        "(with optional port, e.g. '1.2.3.4:443'), domain, "
                        "or URL"
                    ),
                },
                "ioc_type": {
                    "type": "string",
                    "enum": ["sha256_hash", "ip:port", "domain", "url"],
                    "description": (
                        "Type of IOC. Default: sha256_hash"
                    ),
                },
            },
            "required": ["ioc"],
        },
        handler=_handle_check_threatfox_ioc,
    )

    registry.register(
        name="check_urlhaus_url",
        description=(
            "Check a URL against URLhaus to see if it is a known malware "
            "distribution point. Returns threat classification, current "
            "status (online/offline), and tags. Useful for checking URLs "
            "extracted from firmware configuration files and scripts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to check against URLhaus",
                },
            },
            "required": ["url"],
        },
        handler=_handle_check_urlhaus_url,
    )

    registry.register(
        name="enrich_firmware_threat_intel",
        description=(
            "Batch-check all extracted firmware binaries against the full "
            "abuse.ch threat intelligence suite: MalwareBazaar (known malware), "
            "ThreatFox (IOC database), URLhaus (malicious URLs), and YARAify "
            "(community YARA matches). Only hashes are sent — no file data. "
            "Takes several minutes due to polite rate limiting."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_hashes": {
                    "type": "integer",
                    "description": (
                        "Maximum binaries to check. Default: 30. "
                        "Higher values take proportionally longer."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_enrich_firmware_threat_intel,
    )

    # ----- CIRCL Hashlookup (known-good identification) -----

    registry.register(
        name="check_known_good_hash",
        description=(
            "Check if a file is a known-good binary using CIRCL's hashlookup "
            "service (NSRL database). Identifies legitimate files like BusyBox, "
            "OpenSSL, or glibc to reduce false positives in threat analysis. "
            "No API key required. A 'not found' result does NOT mean the file "
            "is malicious — it may be custom or proprietary firmware."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to check",
                },
            },
            "required": ["path"],
        },
        handler=_handle_check_known_good_hash,
    )

    registry.register(
        name="scan_firmware_known_good",
        description=(
            "Batch-check all firmware binaries against CIRCL's known-good "
            "database (NSRL). Identifies legitimate open-source and vendor "
            "files to help prioritize manual analysis on truly unknown "
            "binaries. No API key required."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_files": {
                    "type": "integer",
                    "description": (
                        "Maximum binaries to check. Default: 100."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_scan_firmware_known_good,
    )
