"""Network / update-mechanism scanners.

Extracted from security_audit_service.py as step 4/8 of the Phase 5 split.

- ``_scan_network_dependencies``: /etc/fstab CIFS credentials, NFS
  ``no_root_squash`` exports, cloud storage endpoints, plaintext
  FTP/TFTP/MQTT URLs, DB connection strings with embedded credentials.
- ``_scan_update_mechanisms``: delegates to update_mechanism_service to
  identify OTA / update systems and promotes high/medium severity
  findings into the audit report.
"""

import os
import re

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    SecurityFinding,
    _is_text_file,
    _rel,
)

_NET_DEP_CIFS_CRED_RE = re.compile(r"\bpassword=\S+", re.IGNORECASE)
_NET_DEP_NO_ROOT_SQUASH_RE = re.compile(r"no_root_squash", re.IGNORECASE)
_NET_DEP_CLOUD_RE = re.compile(
    r"(?:\bs3://[\w./-]+|[\w.-]+\.s3\.amazonaws\.com|"
    r"[\w.-]+\.blob\.core\.windows\.net|"
    r"\bgs://[\w./-]+|storage\.googleapis\.com)",
    re.IGNORECASE,
)
_NET_DEP_PLAINTEXT_RE = re.compile(
    r"(?:\bftps?://\S+|\btftp://\S+|\bmqtts?://\S+|"
    r"\b(?:ftpget|ftpput|wget|curl)\b.*\bftp://)",
    re.IGNORECASE,
)
_NET_DEP_DB_CRED_RE = re.compile(
    r"\b(?:mongodb|mysql|postgres(?:ql)?|redis|amqps?|influxdb)://[^/]*:[^@/]+@",
    re.IGNORECASE,
)


def _scan_network_dependencies(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for network mounts, cloud endpoints, and plaintext protocols."""
    count = 0

    # 1. Scan /etc/fstab for CIFS credential exposure
    fstab_path = os.path.join(root, "etc", "fstab")
    if os.path.isfile(fstab_path):
        try:
            with open(fstab_path, errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    if count >= MAX_FINDINGS_PER_CHECK:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _NET_DEP_CIFS_CRED_RE.search(stripped) and "cifs" in stripped.lower():
                        findings.append(SecurityFinding(
                            title="CIFS mount with inline credentials in /etc/fstab",
                            severity="critical",
                            description="CIFS mount options contain plaintext password. "
                                        "Credentials should use a credentials file instead.",
                            evidence=stripped[:200],
                            file_path="/etc/fstab",
                            line_number=line_num,
                            cwe_ids=["CWE-798"],
                        ))
                        count += 1
        except OSError:
            pass

    # 2. Scan /etc/exports for no_root_squash
    exports_path = os.path.join(root, "etc", "exports")
    if os.path.isfile(exports_path):
        try:
            with open(exports_path, errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    if count >= MAX_FINDINGS_PER_CHECK:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _NET_DEP_NO_ROOT_SQUASH_RE.search(stripped):
                        findings.append(SecurityFinding(
                            title="NFS export with no_root_squash",
                            severity="high",
                            description="NFS export uses no_root_squash, allowing remote root "
                                        "to have root privileges on the exported filesystem.",
                            evidence=stripped[:200],
                            file_path="/etc/exports",
                            line_number=line_num,
                            cwe_ids=["CWE-269"],
                        ))
                        count += 1
        except OSError:
            pass

    # 3. Broad sweep: cloud storage, plaintext protocols, DB credentials
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        for name in files:
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            try:
                if os.path.getsize(abs_path) > 1_000_000:
                    continue
            except OSError:
                continue
            if not _is_text_file(abs_path):
                continue
            rel_path = _rel(abs_path, root)
            try:
                with open(abs_path, errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if count >= MAX_FINDINGS_PER_CHECK:
                            break
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue

                        # Cloud storage endpoints
                        m = _NET_DEP_CLOUD_RE.search(stripped)
                        if m:
                            findings.append(SecurityFinding(
                                title=f"Cloud storage endpoint in {rel_path}",
                                severity="high",
                                description=f"Firmware references cloud storage: {m.group(0)[:80]}",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-200"],
                            ))
                            count += 1
                            continue

                        # DB connection strings with embedded credentials
                        m = _NET_DEP_DB_CRED_RE.search(stripped)
                        if m:
                            findings.append(SecurityFinding(
                                title=f"Database connection with credentials in {rel_path}",
                                severity="critical",
                                description="Database connection string contains embedded credentials.",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-798"],
                            ))
                            count += 1
                            continue

                        # Plaintext FTP/TFTP/MQTT URLs
                        m = _NET_DEP_PLAINTEXT_RE.search(stripped)
                        if m:
                            match_text = m.group(0).lower()
                            if "tftp" in match_text:
                                title = f"TFTP URL in {rel_path}"
                            elif "ftp" in match_text:
                                title = f"FTP URL in {rel_path}"
                            else:
                                title = f"MQTT broker reference in {rel_path}"
                            findings.append(SecurityFinding(
                                title=title,
                                severity="high",
                                description="Plaintext protocol used for file transfer or messaging. "
                                            "Data transmitted without encryption.",
                                evidence=stripped[:200],
                                file_path=rel_path,
                                line_number=line_num,
                                cwe_ids=["CWE-319"],
                            ))
                            count += 1
                            continue
            except (OSError, PermissionError):
                continue


def _scan_update_mechanisms(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for firmware update mechanisms and flag insecure patterns.

    Calls the update_mechanism_service and converts important findings
    to SecurityFinding objects for the audit report.
    """
    from app.services.update_mechanism_service import detect_update_mechanisms

    mechanisms = detect_update_mechanisms(root)
    count = 0

    for mech in mechanisms:
        for f in mech.findings:
            if count >= MAX_FINDINGS_PER_CHECK:
                return
            severity = f.get("severity", "info")
            # Only promote high/medium findings to the audit report
            if severity not in ("high", "medium"):
                continue
            description = f.get("description", "")
            cwe = f.get("cwe")
            evidence = f.get("evidence")

            title_prefix = mech.system.upper()
            if mech.system == "none":
                title_prefix = "Update Mechanism"
            elif mech.system == "custom_ota":
                title_prefix = "Custom OTA"

            findings.append(SecurityFinding(
                title=f"[{title_prefix}] {description[:80]}",
                severity=severity,
                description=description,
                evidence=evidence,
                cwe_ids=[cwe] if cwe else None,
            ))
            count += 1
