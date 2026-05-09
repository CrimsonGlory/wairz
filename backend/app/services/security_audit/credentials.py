"""Credential + crypto-material scanners.

Extracted from security_audit_service.py as step 2/8 of the Phase 5 split.
Contains three checks:

- ``_scan_credentials``: hardcoded API keys + generic credential patterns
  (entropy-gated to reduce false positives).
- ``_scan_shadow``: weak / empty / legacy-DES password hashes in
  ``/etc/shadow`` or ``/etc_ro/shadow``.
- ``_scan_crypto_material``: embedded private keys + device certificates
  (skipping system CA bundles to avoid noise).
"""

import os

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    SecurityFinding,
    _is_text_file,
    _rel,
    _shannon_entropy,
)
from app.utils.credential_patterns import (
    API_KEY_PATTERNS as _API_KEY_PATTERNS,
)
from app.utils.credential_patterns import (
    CREDENTIAL_PATTERNS as _CREDENTIAL_PATTERNS,
)
from app.utils.credential_patterns import (
    HASH_TYPES as _HASH_TYPES,
)


def _scan_credentials(root: str, findings: list[SecurityFinding]) -> None:
    """Scan for hardcoded credentials and API keys."""
    count = 0
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
                        # Cloud/service API keys (high value)
                        matched = False
                        for pat, category, severity in _API_KEY_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(0)
                                entropy = _shannon_entropy(value)
                                if entropy < 2.0:
                                    continue  # Skip low-entropy matches
                                findings.append(SecurityFinding(
                                    title=f"{category.replace('_', ' ').title()} found in {rel_path}",
                                    severity=severity,
                                    description=f"Detected {category} pattern (entropy: {entropy:.1f})",
                                    evidence=line.strip()[:200],
                                    file_path=rel_path,
                                    line_number=line_num,
                                    cwe_ids=["CWE-798"],
                                ))
                                count += 1
                                matched = True
                                break
                        if matched:
                            continue
                        # Generic credential patterns
                        for pat in _CREDENTIAL_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(1)
                                entropy = _shannon_entropy(value)
                                if entropy < 2.5 or len(value) < 4:
                                    continue  # Skip trivial matches
                                findings.append(SecurityFinding(
                                    title=f"Hardcoded credential in {rel_path}",
                                    severity="medium",
                                    description=f"Possible hardcoded credential (entropy: {entropy:.1f})",
                                    evidence=line.strip()[:200],
                                    file_path=rel_path,
                                    line_number=line_num,
                                    cwe_ids=["CWE-798"],
                                ))
                                count += 1
                                break
            except (OSError, PermissionError):
                continue


def _scan_shadow(root: str, findings: list[SecurityFinding]) -> None:
    """Check /etc/shadow for weak or empty passwords."""
    for shadow_rel in ("etc/shadow", "etc_ro/shadow"):
        shadow_path = os.path.join(root, shadow_rel)
        if not os.path.isfile(shadow_path):
            continue
        try:
            with open(shadow_path) as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 2:
                        continue
                    user, hash_field = parts[0], parts[1]
                    if not hash_field or hash_field in ("*", "!", "!!", "x"):
                        continue
                    if hash_field == "":
                        findings.append(SecurityFinding(
                            title=f"Empty password for user '{user}'",
                            severity="critical",
                            description=f"User '{user}' has no password set in /{shadow_rel}",
                            file_path=f"/{shadow_rel}",
                            cwe_ids=["CWE-258"],
                        ))
                        continue
                    # Check hash strength
                    for prefix, (algo, strength) in _HASH_TYPES.items():
                        if hash_field.startswith(prefix):
                            if strength == "weak":
                                findings.append(SecurityFinding(
                                    title=f"Weak password hash for user '{user}'",
                                    severity="medium",
                                    description=f"User '{user}' uses {algo} hash in /{shadow_rel} — consider stronger algorithm",
                                    file_path=f"/{shadow_rel}",
                                    cwe_ids=["CWE-916"],
                                ))
                            break
                    else:
                        # DES or unknown — likely weak
                        if not hash_field.startswith("$"):
                            findings.append(SecurityFinding(
                                title=f"Legacy DES password hash for user '{user}'",
                                severity="high",
                                description=f"User '{user}' uses DES crypt in /{shadow_rel} — trivially crackable",
                                file_path=f"/{shadow_rel}",
                                cwe_ids=["CWE-916"],
                            ))
        except OSError:
            continue


def _scan_crypto_material(root: str, findings: list[SecurityFinding]) -> None:
    """Find private keys and certificates."""
    count = 0
    crypto_extensions = {".pem", ".key", ".p12", ".pfx"}
    # Skip system CA certificate bundles — these are standard and not findings
    ca_dirs = {"ssl/certs", "ssl/ca-certificates", "pki/tls/certs", "ca-certificates"}
    for dirpath, _dirs, files in os.walk(root):
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        # Skip system CA bundle directories
        rel_dir = os.path.relpath(dirpath, root)
        if any(ca in rel_dir for ca in ca_dirs):
            continue
        for name in files:
            _, ext = os.path.splitext(name.lower())
            if ext not in crypto_extensions:
                continue
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(256)
            except OSError:
                continue
            if b"PRIVATE KEY" in header:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Private key found: {name}",
                    severity="high",
                    description=f"Private key file at {rel}. Embedded private keys can be extracted and used to impersonate the device.",
                    file_path=rel,
                    cwe_ids=["CWE-321"],
                ))
                count += 1
            elif b"CERTIFICATE" in header:
                rel = _rel(abs_path, root)
                findings.append(SecurityFinding(
                    title=f"Device certificate: {name}",
                    severity="info",
                    description=f"Non-CA certificate at {rel}. May contain device identity or service credentials.",
                    file_path=rel,
                ))
                count += 1
