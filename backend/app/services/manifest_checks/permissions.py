"""Permission-related manifest security checks.

Covers:

- MANIFEST-007 _check_custom_permissions: custom ``<permission>``
  declarations with weak ``protectionLevel`` (normal/dangerous instead
  of signature).
- MANIFEST-016 _check_dangerous_permissions: requested permissions that
  represent significant privacy / security risk (SMS, phone, camera,
  location, etc.).
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.manifest_checks._base import (
    _NS_ANDROID,
    ManifestFinding,
)

logger = logging.getLogger(__name__)


class PermissionChecks:
    """Topic module for permission-declaration and -request checks."""

    # Protection levels that provide meaningful access control
    _STRONG_PROTECTION_LEVELS: set[str] = {
        "signature",
        "signatureorsystem",
        "signature|privileged",
        # Numeric value 0x02 = signature, 0x03 = signatureOrSystem
        "0x2", "0x02", "2",
        "0x3", "0x03", "3",
    }

    # High-risk permission groups for targeted findings
    _HIGH_RISK_PERMISSION_GROUPS: dict[str, tuple[str, str, str]] = {
        # permission -> (category, risk_description, cwe)
        "android.permission.SEND_SMS": (
            "SMS", "Can send SMS messages (potential toll fraud)", "CWE-284"
        ),
        "android.permission.RECEIVE_SMS": (
            "SMS", "Can intercept incoming SMS (OTP theft risk)", "CWE-284"
        ),
        "android.permission.READ_SMS": (
            "SMS", "Can read SMS messages (privacy/OTP theft)", "CWE-284"
        ),
        "android.permission.CALL_PHONE": (
            "Phone", "Can make calls without user interaction", "CWE-284"
        ),
        "android.permission.READ_CALL_LOG": (
            "Phone", "Can read call history (privacy risk)", "CWE-284"
        ),
        "android.permission.PROCESS_OUTGOING_CALLS": (
            "Phone", "Can intercept/redirect outgoing calls", "CWE-284"
        ),
        "android.permission.RECORD_AUDIO": (
            "Surveillance", "Can record audio from microphone", "CWE-284"
        ),
        "android.permission.CAMERA": (
            "Surveillance", "Can access camera for photos/video", "CWE-284"
        ),
        "android.permission.ACCESS_FINE_LOCATION": (
            "Location", "Can access precise GPS location", "CWE-284"
        ),
        "android.permission.ACCESS_BACKGROUND_LOCATION": (
            "Location", "Can access location in background", "CWE-284"
        ),
        "android.permission.READ_CONTACTS": (
            "PII", "Can read user contacts (data exfiltration)", "CWE-284"
        ),
        "android.permission.WRITE_CONTACTS": (
            "PII", "Can modify user contacts", "CWE-284"
        ),
        "android.permission.READ_CALENDAR": (
            "PII", "Can read calendar events (privacy risk)", "CWE-284"
        ),
        "android.permission.MANAGE_EXTERNAL_STORAGE": (
            "Storage", "Full access to shared storage (all files)", "CWE-284"
        ),
        "android.permission.REQUEST_INSTALL_PACKAGES": (
            "Install", "Can request to install other APKs", "CWE-284"
        ),
        "android.permission.SYSTEM_ALERT_WINDOW": (
            "Overlay", "Can draw over other apps (tapjacking)", "CWE-1021"
        ),
        "android.permission.BIND_ACCESSIBILITY_SERVICE": (
            "Accessibility", "Can observe and control UI (keylogging risk)", "CWE-284"
        ),
        "android.permission.BIND_DEVICE_ADMIN": (
            "Admin", "Can act as device administrator", "CWE-284"
        ),
        "android.permission.WRITE_SETTINGS": (
            "Settings", "Can modify system settings", "CWE-284"
        ),
        "android.permission.READ_PHONE_STATE": (
            "Phone", "Can read phone identity (IMEI, phone number)", "CWE-284"
        ),
    }

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def _check_custom_permissions(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-007: Custom permissions with weak protectionLevel.

        Apps that define custom ``<permission>`` elements with
        ``protectionLevel="normal"`` (default) or ``"dangerous"``
        provide weaker access control than ``"signature"`` or
        ``"signatureOrSystem"``.  Normal permissions are auto-granted;
        dangerous permissions only require user approval.  Only
        signature-level permissions ensure that the calling app is
        signed with the same key.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID
        weak_perms: list[dict[str, str]] = []

        permission_elements = manifest_xml.findall(".//permission")
        for elem in permission_elements:
            perm_name = (
                elem.get(f"{{{ns}}}name")
                or elem.get("name")
                or "unknown"
            )

            protection_level = (
                elem.get(f"{{{ns}}}protectionLevel")
                or elem.get("protectionLevel")
            )

            # Default protectionLevel is "normal" (0x0) if not specified
            effective_level = (protection_level or "normal").strip().lower()

            if effective_level not in self._STRONG_PROTECTION_LEVELS:
                weak_perms.append({
                    "permission": perm_name,
                    "protectionLevel": protection_level or "(not set, defaults to normal)",
                })

        if not weak_perms:
            return findings

        evidence_lines = [
            f"  {wp['permission']} — protectionLevel={wp['protectionLevel']}"
            for wp in weak_perms
        ]
        evidence = (
            f"{len(weak_perms)} custom permission(s) with weak "
            f"protectionLevel:\n" + "\n".join(evidence_lines)
        )

        # Severity scales with count
        if len(weak_perms) >= 3:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-007",
                title="Custom permissions with weak protectionLevel",
                severity=severity,
                description=(
                    "The application defines custom permissions with a "
                    "protectionLevel of 'normal' or 'dangerous' instead of "
                    "'signature'. Normal permissions are auto-granted to any "
                    "requesting app. Dangerous permissions only require user "
                    "consent. Only signature-level permissions ensure that "
                    "the calling app is signed with the same developer key, "
                    "providing meaningful access control. Third-party apps "
                    "could declare and obtain these permissions to access "
                    "protected components."
                ),
                evidence=evidence,
                cwe_ids=["CWE-732"],
                confidence="medium",
            )
        )

        return findings

    def _check_dangerous_permissions(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-016: High-risk and dangerous permissions usage.

        Flags permissions that represent significant privacy or security
        risks.  Rather than listing every dangerous permission (which
        would be noisy), this focuses on high-risk categories: SMS/phone
        abuse, surveillance (camera/mic), location tracking, overlay
        attacks, device admin, and accessibility abuse.
        """
        findings: list[ManifestFinding] = []

        try:
            permissions = apk_obj.get_permissions()
        except Exception:
            return findings

        if not permissions:
            return findings

        requested = set(permissions)

        # Group high-risk permissions by category
        by_category: dict[str, list[tuple[str, str, str]]] = {}
        for perm in requested:
            if perm in self._HIGH_RISK_PERMISSION_GROUPS:
                cat, desc, cwe = self._HIGH_RISK_PERMISSION_GROUPS[perm]
                by_category.setdefault(cat, []).append((perm, desc, cwe))

        for category, perms in sorted(by_category.items()):
            perm_names = [p[0].split(".")[-1] for p in perms]
            cwe_ids = list({p[2] for p in perms})

            severity = "medium"
            # Escalate for surveillance + SMS categories
            if category in ("Surveillance", "SMS", "Overlay", "Accessibility", "Admin"):
                severity = "high"

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-016",
                    title=f"High-risk {category} permissions requested",
                    severity=severity,
                    description=(
                        f"The app requests {len(perms)} high-risk "
                        f"{category.lower()}-related permission(s): "
                        + "; ".join(f"{p[0].split('.')[-1]} — {p[1]}" for p in perms)
                        + ". Verify these permissions are essential for "
                        "the app's core functionality and that sensitive "
                        "data access is properly justified."
                    ),
                    evidence=f"Permissions: {', '.join(perm_names)}",
                    cwe_ids=cwe_ids,
                    confidence="medium",
                )
            )

        return findings
