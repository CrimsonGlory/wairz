"""Firmware update mechanism static detection service.

Scans extracted firmware filesystems for update mechanisms (SWUpdate, RAUC,
Mender, opkg/sysupgrade, U-Boot env, Android OTA, custom scripts, package
managers) and classifies findings by type and severity.
"""

import logging
import os
import re
from dataclasses import dataclass, field

from app.utils.sandbox import safe_walk, validate_path

logger = logging.getLogger(__name__)

# Max bytes to read from any single config/script file
_MAX_FILE_SIZE = 512_000

# Binary extensions to skip during text scanning
_BINARY_EXTENSIONS = frozenset({
    ".bin", ".img", ".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma",
    ".zip", ".tar", ".elf", ".so", ".o", ".a", ".ko", ".dtb",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".pyc", ".pyo", ".class", ".wasm",
})

# Regex for URLs in config files
_URL_PATTERN = re.compile(
    r'(https?://[^\s\'"<>}{)\]]+)', re.IGNORECASE
)

# Patterns that suggest custom OTA logic
_CUSTOM_OTA_DOWNLOAD = re.compile(
    r'\b(wget|curl|fetch)\b', re.IGNORECASE
)
_CUSTOM_OTA_FLASH = re.compile(
    r'\b(mtd\s+write|mtd_write|flash_eraseall|flashcp|dd\s+.*of=/dev/mtd|'
    r'nandwrite|fw_setenv|flash_erase|sysupgrade)\b',
    re.IGNORECASE,
)

# U-Boot env variables that indicate update/rollback support
_UBOOT_UPDATE_VARS = {
    "bootcmd", "altbootcmd", "upgrade_available", "bootcount",
    "bootlimit", "boot_part", "boot_slot",
}


@dataclass
class UpdateMechanism:
    """A detected firmware update mechanism."""
    system: str           # e.g., "swupdate", "rauc", "opkg", "custom_ota"
    confidence: str       # "high", "medium", "low"
    binaries: list[str] = field(default_factory=list)
    configs: list[str] = field(default_factory=list)
    update_urls: list[str] = field(default_factory=list)
    uses_https: bool | None = None
    has_ab_scheme: bool | None = None
    findings: list[dict] = field(default_factory=list)


def _rel(abs_path: str, root: str) -> str:
    """Return a firmware-relative path for display."""
    return "/" + os.path.relpath(abs_path, root)


def _is_text_file(path: str) -> bool:
    """Quick check if a file is likely text (not binary)."""
    _, ext = os.path.splitext(path.lower())
    if ext in _BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
            if b"\x00" in chunk:
                return False
    except OSError:
        return False
    return True


def _read_text(path: str, max_size: int = _MAX_FILE_SIZE) -> str | None:
    """Read a text file safely, returning None on failure."""
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return None
        with open(path, errors="replace") as f:
            return f.read(max_size)
    except OSError:
        return None


def _extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""
    return list(set(_URL_PATTERN.findall(text)))


def _classify_urls(urls: list[str]) -> bool | None:
    """Return True if all update URLs use HTTPS, False if any HTTP, None if no URLs."""
    if not urls:
        return None
    has_http = any(u.startswith("http://") for u in urls)
    return not has_http


def _find_binary(root: str, name: str) -> str | None:
    """Find a binary by name in common PATH directories."""
    search_dirs = [
        "bin", "sbin", "usr/bin", "usr/sbin",
        "usr/local/bin", "usr/local/sbin",
        "system/bin", "system/xbin",
    ]
    for d in search_dirs:
        candidate = os.path.join(root, d, name)
        if os.path.isfile(candidate):
            return candidate
        # Check if it's a symlink that resolves within root
        if os.path.islink(candidate):
            try:
                validate_path(root, os.path.join("/", d, name))
                return candidate
            except Exception:
                pass
    return None


def _find_file(root: str, rel_path: str) -> str | None:
    """Check if a file exists at a specific relative path."""
    candidate = os.path.join(root, rel_path.lstrip("/"))
    if os.path.isfile(candidate):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Per-system detectors
# ---------------------------------------------------------------------------


def _detect_swupdate(root: str) -> UpdateMechanism | None:
    """Detect SWUpdate OTA framework."""
    binary = _find_binary(root, "swupdate")
    config = _find_file(root, "etc/swupdate.cfg")
    config_dir = os.path.join(root, "etc", "swupdate")
    has_config_dir = os.path.isdir(config_dir)

    if not binary and not config and not has_config_dir:
        return None

    mech = UpdateMechanism(
        system="swupdate",
        confidence="high" if binary else "medium",
    )

    if binary:
        mech.binaries.append(_rel(binary, root))
    if config:
        mech.configs.append(_rel(config, root))
        content = _read_text(config)
        if content:
            mech.update_urls.extend(_extract_urls(content))
            # A/B detection: SWUpdate uses sw-description with "installed-directly"
            if "installed-directly" in content or "dual_copy" in content.lower():
                mech.has_ab_scheme = True
    if has_config_dir:
        mech.configs.append(_rel(config_dir, root))
        # Scan config dir for additional configs
        try:
            for f in os.listdir(config_dir):
                fp = os.path.join(config_dir, f)
                if os.path.isfile(fp):
                    content = _read_text(fp)
                    if content:
                        mech.update_urls.extend(_extract_urls(content))
        except OSError:
            pass

    # Check for .swu files (update packages)
    for dirpath, _dirs, files in safe_walk(root):
        for name in files:
            if name.endswith(".swu"):
                mech.configs.append(_rel(os.path.join(dirpath, name), root))
                break
        if len(mech.configs) > 10:
            break

    mech.uses_https = _classify_urls(mech.update_urls)

    # Findings
    if mech.update_urls and mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "SWUpdate configured with HTTP-only update URL — updates can be intercepted",
            "cwe": "CWE-319",
        })
    if mech.update_urls and mech.uses_https is True:
        mech.findings.append({
            "severity": "info",
            "description": "SWUpdate configured with HTTPS update URL",
        })

    return mech


def _detect_rauc(root: str) -> UpdateMechanism | None:
    """Detect RAUC update framework."""
    binary = _find_binary(root, "rauc")
    config = _find_file(root, "etc/rauc/system.conf")

    if not binary and not config:
        return None

    mech = UpdateMechanism(
        system="rauc",
        confidence="high" if binary and config else "medium",
    )

    if binary:
        mech.binaries.append(_rel(binary, root))
    if config:
        mech.configs.append(_rel(config, root))
        content = _read_text(config)
        if content:
            mech.update_urls.extend(_extract_urls(content))
            # RAUC uses slot definitions — multiple slots indicate A/B
            slots = re.findall(r'\[slot\.\w+\.\d+\]', content)
            if len(slots) >= 2:
                mech.has_ab_scheme = True

    # Check for RAUC bundles
    for dirpath, _dirs, files in safe_walk(root):
        for name in files:
            if name.endswith(".raucb"):
                mech.configs.append(_rel(os.path.join(dirpath, name), root))
                break
        if len(mech.configs) > 10:
            break

    mech.uses_https = _classify_urls(mech.update_urls)

    if mech.update_urls and mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "RAUC configured with HTTP-only update URL",
            "cwe": "CWE-319",
        })
    if mech.update_urls and mech.uses_https is True:
        mech.findings.append({
            "severity": "info",
            "description": "RAUC configured with HTTPS update URL",
        })
    if mech.has_ab_scheme:
        mech.findings.append({
            "severity": "info",
            "description": "RAUC A/B partition scheme detected — supports rollback",
        })

    return mech


def _detect_mender(root: str) -> UpdateMechanism | None:
    """Detect Mender OTA client."""
    binary = _find_binary(root, "mender") or _find_binary(root, "mender-client")
    config = _find_file(root, "etc/mender/mender.conf")
    data_dir = os.path.join(root, "var", "lib", "mender")
    has_data_dir = os.path.isdir(data_dir)

    if not binary and not config and not has_data_dir:
        return None

    mech = UpdateMechanism(
        system="mender",
        confidence="high" if binary else "medium",
    )

    if binary:
        mech.binaries.append(_rel(binary, root))
    if config:
        mech.configs.append(_rel(config, root))
        content = _read_text(config)
        if content:
            mech.update_urls.extend(_extract_urls(content))
            # Mender always uses rootfs A/B by design
            mech.has_ab_scheme = True
    if has_data_dir:
        mech.configs.append(_rel(data_dir, root))

    mech.uses_https = _classify_urls(mech.update_urls)

    if mech.update_urls and mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "Mender configured with HTTP-only server URL",
            "cwe": "CWE-319",
        })
    if mech.update_urls and mech.uses_https is True:
        mech.findings.append({
            "severity": "info",
            "description": "Mender configured with HTTPS server URL",
        })
    if mech.has_ab_scheme:
        mech.findings.append({
            "severity": "info",
            "description": "Mender uses A/B rootfs partition scheme — supports rollback",
        })

    return mech


def _detect_opkg(root: str) -> UpdateMechanism | None:
    """Detect opkg package manager and sysupgrade."""
    binary = _find_binary(root, "opkg")
    sysupgrade = _find_binary(root, "sysupgrade") or _find_file(root, "sbin/sysupgrade")
    config = _find_file(root, "etc/opkg.conf")
    config_dir = os.path.join(root, "etc", "opkg")
    has_config_dir = os.path.isdir(config_dir)

    if not binary and not sysupgrade and not config:
        return None

    mech = UpdateMechanism(
        system="opkg",
        confidence="high" if binary else "medium",
    )

    if binary:
        mech.binaries.append(_rel(binary, root))
    if sysupgrade:
        mech.binaries.append(_rel(sysupgrade, root))
    if config:
        mech.configs.append(_rel(config, root))
        content = _read_text(config)
        if content:
            mech.update_urls.extend(_extract_urls(content))
    if has_config_dir:
        mech.configs.append(_rel(config_dir, root))
        try:
            for f in os.listdir(config_dir):
                fp = os.path.join(config_dir, f)
                if os.path.isfile(fp):
                    content = _read_text(fp)
                    if content:
                        mech.update_urls.extend(_extract_urls(content))
        except OSError:
            pass

    mech.uses_https = _classify_urls(mech.update_urls)
    # opkg/sysupgrade typically does NOT have A/B — it's a full flash
    mech.has_ab_scheme = False

    if mech.update_urls and mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "opkg repositories use HTTP-only URLs — package downloads can be intercepted",
            "cwe": "CWE-319",
        })
    if not sysupgrade and binary:
        mech.findings.append({
            "severity": "info",
            "description": "opkg package manager present without sysupgrade — partial update only",
        })
    if mech.has_ab_scheme is False:
        mech.findings.append({
            "severity": "medium",
            "description": "opkg/sysupgrade has no A/B rollback — failed update may brick device",
            "cwe": "CWE-1277",
        })

    return mech


def _detect_uboot_env(root: str) -> UpdateMechanism | None:
    """Detect U-Boot environment update support."""
    fw_setenv = _find_binary(root, "fw_setenv")
    fw_printenv = _find_binary(root, "fw_printenv")
    env_config = _find_file(root, "etc/fw_env.config")

    if not fw_setenv and not fw_printenv and not env_config:
        return None

    mech = UpdateMechanism(
        system="uboot_env",
        confidence="high" if env_config else "medium",
    )

    if fw_setenv:
        mech.binaries.append(_rel(fw_setenv, root))
    if fw_printenv:
        mech.binaries.append(_rel(fw_printenv, root))
    if env_config:
        mech.configs.append(_rel(env_config, root))
        content = _read_text(env_config)
        if content:
            # Parse env config: device offset size
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    mech.findings.append({
                        "severity": "info",
                        "description": f"U-Boot env location: {line.strip()}",
                    })

    # Look for env vars in default env or scripts referencing upgrade
    init_scripts = _collect_init_scripts(root)
    has_altbootcmd = False
    has_bootcount = False
    for script_path in init_scripts:
        content = _read_text(script_path)
        if not content:
            continue
        for var in _UBOOT_UPDATE_VARS:
            if var in content:
                if var == "altbootcmd":
                    has_altbootcmd = True
                if var in ("bootcount", "bootlimit"):
                    has_bootcount = True

    if has_altbootcmd:
        mech.has_ab_scheme = True
        mech.findings.append({
            "severity": "info",
            "description": "U-Boot altbootcmd detected — A/B boot support present",
        })
    if has_bootcount:
        mech.findings.append({
            "severity": "info",
            "description": "U-Boot bootcount mechanism detected — automatic rollback on boot failure",
        })

    return mech


def _detect_android_ota(root: str) -> UpdateMechanism | None:
    """Detect Android OTA update mechanisms."""
    update_engine = _find_file(root, "system/bin/update_engine")
    update_engine_client = _find_file(root, "system/bin/update_engine_client")
    recovery_dir = os.path.join(root, "cache", "recovery")
    has_recovery = os.path.isdir(recovery_dir)
    meta_inf = os.path.join(root, "META-INF", "com", "google", "android")
    has_meta_inf = os.path.isdir(meta_inf)

    if not update_engine and not update_engine_client and not has_recovery and not has_meta_inf:
        return None

    mech = UpdateMechanism(
        system="android_ota",
        confidence="high" if update_engine else "medium",
    )

    if update_engine:
        mech.binaries.append(_rel(update_engine, root))
    if update_engine_client:
        mech.binaries.append(_rel(update_engine_client, root))
    if has_recovery:
        mech.configs.append(_rel(recovery_dir, root))
    if has_meta_inf:
        mech.configs.append(_rel(meta_inf, root))

    # Check build.prop for OTA URL
    for prop_path in ["system/build.prop", "build.prop", "vendor/build.prop"]:
        prop_file = _find_file(root, prop_path)
        if prop_file:
            content = _read_text(prop_file)
            if content:
                urls = _extract_urls(content)
                mech.update_urls.extend(urls)

    # Android A/B: check for update_engine + boot_control HAL
    boot_control = _find_file(root, "system/lib/hw/boot_control.default.so") or \
                   _find_file(root, "system/lib64/hw/boot_control.default.so") or \
                   _find_file(root, "vendor/lib/hw/boot_control.default.so") or \
                   _find_file(root, "vendor/lib64/hw/boot_control.default.so")
    if update_engine and boot_control:
        mech.has_ab_scheme = True
        mech.findings.append({
            "severity": "info",
            "description": "Android A/B update system with boot_control HAL",
        })
    elif update_engine:
        mech.has_ab_scheme = True
        mech.findings.append({
            "severity": "info",
            "description": "Android A/B update system (update_engine present)",
        })

    mech.uses_https = _classify_urls(mech.update_urls)

    return mech


def _detect_package_managers(root: str) -> UpdateMechanism | None:
    """Detect standard Linux package managers (dpkg, apt, yum, rpm)."""
    detections: list[tuple[str, str | None, str | None]] = []

    # dpkg/apt
    dpkg = _find_binary(root, "dpkg")
    apt = _find_binary(root, "apt-get") or _find_binary(root, "apt")
    sources_list = _find_file(root, "etc/apt/sources.list")
    if dpkg or apt:
        detections.append(("dpkg/apt", dpkg or apt, sources_list))

    # yum/dnf
    yum = _find_binary(root, "yum") or _find_binary(root, "dnf")
    yum_dir = os.path.join(root, "etc", "yum.repos.d")
    yum_conf = _find_file(root, "etc/yum.conf")
    if yum:
        detections.append(("yum/dnf", yum, yum_conf if yum_conf else (
            _rel(yum_dir, root) if os.path.isdir(yum_dir) else None
        )))

    # rpm
    rpm = _find_binary(root, "rpm")
    if rpm and not yum:
        detections.append(("rpm", rpm, None))

    if not detections:
        return None

    mech = UpdateMechanism(
        system="package_manager",
        confidence="medium",
    )

    for pkg_name, binary_path, config_path in detections:
        if binary_path:
            mech.binaries.append(_rel(binary_path, root))
        if config_path:
            if config_path.startswith("/"):
                mech.configs.append(config_path)
            else:
                mech.configs.append(_rel(config_path, root))

    # Extract URLs from sources.list
    if sources_list:
        content = _read_text(sources_list)
        if content:
            mech.update_urls.extend(_extract_urls(content))

    # Extract URLs from yum repos
    if os.path.isdir(yum_dir):
        try:
            for f in os.listdir(yum_dir):
                fp = os.path.join(yum_dir, f)
                if os.path.isfile(fp):
                    content = _read_text(fp)
                    if content:
                        mech.update_urls.extend(_extract_urls(content))
        except OSError:
            pass

    mech.uses_https = _classify_urls(mech.update_urls)

    if mech.update_urls and mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "Package manager repositories use HTTP-only URLs",
            "cwe": "CWE-319",
        })

    return mech


def _collect_init_scripts(root: str) -> list[str]:
    """Collect init scripts, cron jobs, and other startup scripts."""
    scripts: list[str] = []

    # init.d scripts
    for init_dir in ["etc/init.d", "etc/rc.d", "etc/rc.d/init.d"]:
        d = os.path.join(root, init_dir)
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp):
                        scripts.append(fp)
            except OSError:
                continue

    # Cron jobs
    for cron_dir in ["etc/cron.d", "etc/cron.daily", "etc/cron.hourly",
                     "var/spool/cron", "var/spool/cron/crontabs"]:
        d = os.path.join(root, cron_dir)
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp):
                        scripts.append(fp)
            except OSError:
                continue

    # Crontab
    crontab = os.path.join(root, "etc", "crontab")
    if os.path.isfile(crontab):
        scripts.append(crontab)

    # inittab
    inittab = os.path.join(root, "etc", "inittab")
    if os.path.isfile(inittab):
        scripts.append(inittab)

    return scripts


def _detect_custom_ota(root: str) -> UpdateMechanism | None:
    """Detect custom OTA scripts (wget/curl + flash/mtd/dd patterns).

    NOTE: The YARA rule 'Suspicious_Firmware_Modification_Tools' also catches
    some of these patterns. This detector does deeper analysis — extracting
    URLs, classifying severity, and identifying the specific scripts involved.
    """
    scripts = _collect_init_scripts(root)

    # Also scan cgi-bin and www scripts
    for web_dir in ["www", "www/cgi-bin", "usr/lib/cgi-bin"]:
        d = os.path.join(root, web_dir)
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp) and _is_text_file(fp):
                        scripts.append(fp)
            except OSError:
                continue

    custom_scripts: list[tuple[str, str]] = []  # (script_path, matched_line)
    all_urls: list[str] = []

    for script_path in scripts:
        content = _read_text(script_path)
        if not content:
            continue

        has_download = bool(_CUSTOM_OTA_DOWNLOAD.search(content))
        has_flash = bool(_CUSTOM_OTA_FLASH.search(content))

        if has_download and has_flash:
            # Find the most relevant line
            for line in content.splitlines():
                if _CUSTOM_OTA_DOWNLOAD.search(line) or _CUSTOM_OTA_FLASH.search(line):
                    custom_scripts.append((script_path, line.strip()[:200]))
                    break
            urls = _extract_urls(content)
            all_urls.extend(urls)

    if not custom_scripts:
        return None

    mech = UpdateMechanism(
        system="custom_ota",
        confidence="medium",
    )

    for script_path, _matched_line in custom_scripts:
        mech.binaries.append(_rel(script_path, root))

    mech.update_urls = list(set(all_urls))
    mech.uses_https = _classify_urls(mech.update_urls)
    mech.has_ab_scheme = False  # custom scripts rarely implement rollback

    for script_path, matched_line in custom_scripts:
        mech.findings.append({
            "severity": "medium",
            "description": (
                f"Custom OTA script at {_rel(script_path, root)}: "
                f"downloads and flashes firmware via shell commands"
            ),
            "cwe": "CWE-494",
            "evidence": matched_line,
        })

    if mech.uses_https is False:
        mech.findings.append({
            "severity": "high",
            "description": "Custom OTA downloads firmware over HTTP — no transport encryption",
            "cwe": "CWE-319",
        })

    return mech


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def detect_update_mechanisms(
    extracted_root: str,
    *,
    extra_roots: list[str] | None = None,
) -> list[UpdateMechanism]:
    """Scan an extracted firmware filesystem for update mechanisms.

    Returns a list of detected UpdateMechanism objects, each describing
    a specific update system found in the firmware with its binaries,
    configs, URLs, and security findings.

    Phase 3b: accepts ``extra_roots`` so scatter-zip siblings and raw
    image dirs are scanned too. When an update system is found in
    multiple roots, the first hit's metadata is kept and later roots'
    unique findings (binaries, configs, URLs) are merged.

    This is a sync function — call from a thread executor for async contexts.
    """
    real_root = os.path.realpath(extracted_root)
    all_roots: list[str] = [real_root]
    if extra_roots:
        seen = {real_root}
        for r in extra_roots:
            if not r:
                continue
            real = os.path.realpath(r)
            if real in seen or not os.path.isdir(real):
                continue
            seen.add(real)
            all_roots.append(real)

    detectors = [
        _detect_swupdate,
        _detect_rauc,
        _detect_mender,
        _detect_opkg,
        _detect_uboot_env,
        _detect_android_ota,
        _detect_package_managers,
        _detect_custom_ota,
    ]

    mechanisms: list[UpdateMechanism] = []
    # System → first mechanism found, for merging subsequent roots.
    by_system: dict[str, UpdateMechanism] = {}

    for detector in detectors:
        for root in all_roots:
            try:
                result = detector(root)
            except Exception as e:
                logger.warning(
                    "Update mechanism detector %s failed on %s: %s",
                    detector.__name__, root, e,
                )
                continue
            if result is None:
                continue
            existing = by_system.get(result.system)
            if existing is None:
                by_system[result.system] = result
                mechanisms.append(result)
            else:
                # Merge unique entries so a split partition layout
                # doesn't drop binaries/configs found only in a sibling.
                for b in result.binaries:
                    if b not in existing.binaries:
                        existing.binaries.append(b)
                for c in result.configs:
                    if c not in existing.configs:
                        existing.configs.append(c)
                for u in result.update_urls:
                    if u not in existing.update_urls:
                        existing.update_urls.append(u)
                for f in result.findings:
                    if f not in existing.findings:
                        existing.findings.append(f)

    # If no mechanisms found at all, that's a finding itself
    if not mechanisms:
        no_update = UpdateMechanism(
            system="none",
            confidence="high",
        )
        no_update.findings.append({
            "severity": "high",
            "description": (
                "No firmware update mechanism detected. Device may lack the ability "
                "to receive security patches, leaving known vulnerabilities unpatched."
            ),
            "cwe": "CWE-1277",
        })
        mechanisms.append(no_update)
    else:
        # Check if any mechanism has rollback support
        has_rollback = any(m.has_ab_scheme for m in mechanisms)
        if not has_rollback:
            # Add a finding to the first real mechanism
            for m in mechanisms:
                if m.system != "none":
                    m.findings.append({
                        "severity": "medium",
                        "description": (
                            "No A/B partition or rollback mechanism detected. "
                            "A failed update could leave the device inoperable."
                        ),
                        "cwe": "CWE-1277",
                    })
                    break

    return mechanisms


def format_mechanisms_report(mechanisms: list[UpdateMechanism]) -> str:
    """Format detected update mechanisms as a human-readable report."""
    if not mechanisms:
        return "No update mechanisms detected."

    lines: list[str] = []
    lines.append("# Firmware Update Mechanism Detection\n")

    # Summary
    real_mechs = [m for m in mechanisms if m.system != "none"]
    if real_mechs:
        lines.append(f"**Detected {len(real_mechs)} update system(s):**\n")
        for m in real_mechs:
            https_status = ""
            if m.uses_https is True:
                https_status = " (HTTPS)"
            elif m.uses_https is False:
                https_status = " (HTTP ONLY - INSECURE)"
            ab_status = ""
            if m.has_ab_scheme is True:
                ab_status = " [A/B]"
            elif m.has_ab_scheme is False:
                ab_status = " [no rollback]"
            lines.append(
                f"- **{m.system}** ({m.confidence} confidence)"
                f"{https_status}{ab_status}"
            )
        lines.append("")
    else:
        lines.append("**No update mechanism found.**\n")

    # Details per mechanism
    for m in mechanisms:
        lines.append(f"## {m.system.upper()}")
        lines.append(f"Confidence: {m.confidence}")

        if m.binaries:
            lines.append("\n### Binaries")
            for b in m.binaries:
                lines.append(f"  - {b}")

        if m.configs:
            lines.append("\n### Configs")
            for c in m.configs:
                lines.append(f"  - {c}")

        if m.update_urls:
            lines.append("\n### Update URLs")
            for u in m.update_urls:
                protocol = "HTTPS" if u.startswith("https://") else "HTTP"
                lines.append(f"  - [{protocol}] {u}")

        if m.findings:
            lines.append("\n### Findings")
            for f in m.findings:
                sev = f["severity"].upper()
                desc = f["description"]
                cwe = f.get("cwe", "")
                cwe_str = f" ({cwe})" if cwe else ""
                evidence = f.get("evidence", "")
                lines.append(f"  - [{sev}]{cwe_str} {desc}")
                if evidence:
                    lines.append(f"    Evidence: `{evidence}`")

        lines.append("")

    return "\n".join(lines)


def analyze_update_config_detail(
    extracted_root: str, system: str, config_path: str | None = None
) -> str:
    """Deep-dive analysis of a specific update system's configuration.

    Returns a detailed text report of the configuration for the given
    update system.
    """
    real_root = os.path.realpath(extracted_root)
    lines: list[str] = []

    # Map system to its default config locations
    system_configs: dict[str, list[str]] = {
        "swupdate": ["etc/swupdate.cfg", "etc/swupdate/"],
        "rauc": ["etc/rauc/system.conf"],
        "mender": ["etc/mender/mender.conf"],
        "opkg": ["etc/opkg.conf", "etc/opkg/"],
        "uboot_env": ["etc/fw_env.config"],
        "android_ota": ["system/build.prop"],
        "package_manager": ["etc/apt/sources.list", "etc/yum.conf"],
    }

    if config_path:
        # Analyze a specific file
        resolved = validate_path(real_root, config_path)
        content = _read_text(resolved)
        if not content:
            return f"Error: Cannot read config file at {config_path}"
        lines.append(f"# {system.upper()} Config Analysis: {config_path}\n")
        lines.append(f"```\n{content[:8000]}\n```\n")
        _analyze_config_content(system, content, config_path, lines)
    else:
        # Auto-find configs for the system
        paths = system_configs.get(system, [])
        if not paths:
            return f"Unknown update system: {system}. Known systems: {', '.join(system_configs.keys())}"

        lines.append(f"# {system.upper()} Configuration Analysis\n")

        found_any = False
        for rel_path in paths:
            abs_path = os.path.join(real_root, rel_path)
            if os.path.isfile(abs_path):
                found_any = True
                content = _read_text(abs_path)
                if content:
                    lines.append(f"## {_rel(abs_path, real_root)}\n")
                    lines.append(f"```\n{content[:4000]}\n```\n")
                    _analyze_config_content(system, content, _rel(abs_path, real_root), lines)
            elif os.path.isdir(abs_path):
                found_any = True
                lines.append(f"## Directory: {_rel(abs_path, real_root)}\n")
                try:
                    for f in sorted(os.listdir(abs_path)):
                        fp = os.path.join(abs_path, f)
                        if os.path.isfile(fp):
                            content = _read_text(fp)
                            if content:
                                lines.append(f"### {f}\n")
                                lines.append(f"```\n{content[:2000]}\n```\n")
                                _analyze_config_content(
                                    system, content, _rel(fp, real_root), lines
                                )
                except OSError:
                    lines.append("  (cannot read directory)\n")

        if not found_any:
            lines.append(f"No configuration files found for {system}.")
            lines.append(f"Searched: {', '.join(paths)}")

    return "\n".join(lines)


def _analyze_config_content(
    system: str, content: str, file_path: str, lines: list[str]
) -> None:
    """Analyze config content and append findings to lines."""
    urls = _extract_urls(content)
    if urls:
        lines.append("**URLs found:**")
        for u in urls:
            protocol = "HTTPS" if u.startswith("https://") else "HTTP (INSECURE)"
            lines.append(f"  - [{protocol}] {u}")
        lines.append("")

    # System-specific analysis
    if system == "swupdate":
        if "suricatta" in content.lower():
            lines.append("- SWUpdate Suricatta (hawkBit) backend integration detected")
        if "ssl" in content.lower() or "cert" in content.lower():
            lines.append("- TLS/certificate configuration present")
        if "gpgme" in content.lower() or "signed" in content.lower():
            lines.append("- GPG signature verification configured")
        else:
            lines.append("- WARNING: No GPG signature verification detected")

    elif system == "rauc":
        slots = re.findall(r'\[slot\.(\w+)\.(\d+)\]', content)
        if slots:
            lines.append(f"- Slot layout: {', '.join(f'{n}.{i}' for n, i in slots)}")
            slot_names = set(n for n, _ in slots)
            if len(slots) > len(slot_names):
                lines.append("- A/B scheme confirmed (multiple instances per slot class)")
        if "keyring" in content.lower():
            lines.append("- Keyring for bundle verification configured")
        else:
            lines.append("- WARNING: No keyring configured — bundles may not be verified")

    elif system == "mender":
        import json as json_mod
        try:
            conf = json_mod.loads(content)
            server = conf.get("ServerURL", conf.get("Servers", [{}]))
            if server:
                lines.append(f"- Mender server: {server}")
            tenant = conf.get("TenantToken")
            if tenant:
                lines.append(f"- Tenant token: {tenant[:20]}...")
            poll_interval = conf.get("UpdatePollIntervalSeconds")
            if poll_interval:
                lines.append(f"- Update poll interval: {poll_interval}s")
        except (json_mod.JSONDecodeError, TypeError):
            pass

    elif system == "opkg":
        feeds = re.findall(r'^src/gz\s+(\S+)\s+(.+)$', content, re.MULTILINE)
        if feeds:
            lines.append("**Package feeds:**")
            for name, url in feeds:
                protocol = "HTTPS" if url.strip().startswith("https://") else "HTTP"
                lines.append(f"  - {name}: [{protocol}] {url.strip()}")
            lines.append("")

    elif system == "uboot_env":
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 3:
                    lines.append(f"- Environment at device={parts[0]}, offset={parts[1]}, size={parts[2]}")

    lines.append("")
