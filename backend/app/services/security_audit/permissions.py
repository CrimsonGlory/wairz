"""Filesystem permission + boot-service scanners.

Extracted from security_audit_service.py as step 3/8 of the Phase 5 split.
Contains three checks that care about filesystem metadata or init scripts:

- ``_scan_setuid``: setuid-root binaries (privilege escalation targets).
- ``_scan_world_writable``: world-writable files in sensitive directories
  (``etc``, ``bin``, ``sbin``, ``usr/bin``, ``usr/sbin``, ``lib``).
- ``_scan_init_services``: insecure services started at boot via ``init.d``,
  ``rc.d``, or ``inittab`` (telnetd, ftpd, tftpd, UPnP, SNMP).
"""

import os
import re
import stat

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    SecurityFinding,
    _rel,
)

_KNOWN_SERVICES = {
    "telnetd": ("high", "Telnet daemon — plaintext credential transmission"),
    "ftpd": ("high", "FTP daemon — plaintext credential transmission"),
    "tftpd": ("high", "TFTP daemon — unauthenticated file access"),
    "miniupnpd": ("medium", "UPnP daemon — may expose internal services"),
    "snmpd": ("medium", "SNMP daemon — check community strings"),
}


def _scan_setuid(root: str, findings: list[SecurityFinding]) -> None:
    """Find setuid-root binaries."""
    count = 0
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        for name in files:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & stat.S_ISUID and st.st_uid == 0:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Setuid-root binary: {name}",
                    severity="medium",
                    description=f"Binary {rel} is setuid-root (mode {oct(st.st_mode)[-4:]}). "
                                "Setuid-root binaries are common privilege escalation targets.",
                    file_path=rel,
                    cwe_ids=["CWE-250"],
                ))
                count += 1


def _scan_init_services(root: str, findings: list[SecurityFinding]) -> None:
    """Check init scripts for insecure services started at boot."""
    init_dirs = [
        os.path.join(root, "etc", "init.d"),
        os.path.join(root, "etc", "rc.d"),
    ]
    inittab = os.path.join(root, "etc", "inittab")

    scripts_to_scan: list[str] = []
    for d in init_dirs:
        if os.path.isdir(d):
            try:
                scripts_to_scan.extend(
                    os.path.join(d, f) for f in os.listdir(d)
                    if os.path.isfile(os.path.join(d, f))
                )
            except OSError:
                continue
    if os.path.isfile(inittab):
        scripts_to_scan.append(inittab)

    for script_path in scripts_to_scan:
        try:
            with open(script_path, errors="replace") as f:
                content = f.read(64_000)
        except OSError:
            continue
        rel = _rel(script_path, root)
        for service, (severity, desc) in _KNOWN_SERVICES.items():
            if re.search(rf"\b{re.escape(service)}\b", content):
                findings.append(SecurityFinding(
                    title=f"Insecure service at boot: {service}",
                    severity=severity,
                    description=f"{desc}. Started from {rel}.",
                    file_path=rel,
                    cwe_ids=["CWE-319"] if "plaintext" in desc.lower() else None,
                ))


def _scan_world_writable(root: str, findings: list[SecurityFinding]) -> None:
    """Find world-writable files in sensitive directories."""
    sensitive_dirs = ["etc", "bin", "sbin", "usr/bin", "usr/sbin", "lib"]
    count = 0
    for d in sensitive_dirs:
        dir_path = os.path.join(root, d)
        if not os.path.isdir(dir_path):
            continue
        for dirpath, _dirs, files in os.walk(dir_path):
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            for name in files:
                abs_path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(abs_path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & stat.S_IWOTH:
                    rel = _rel(abs_path, root)
                    findings.append(SecurityFinding(
                        title=f"World-writable file: {name}",
                        severity="medium",
                        description=f"{rel} is world-writable (mode {oct(st.st_mode)[-4:]}). "
                                    "Any process can modify this file.",
                        file_path=rel,
                        cwe_ids=["CWE-732"],
                    ))
                    count += 1
