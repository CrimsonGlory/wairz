"""Signing-related manifest security checks.

Covers:

- MANIFEST-014 _check_signing_scheme: APK signing scheme version
  (v1/v2/v3) coverage, flagging Janus-vulnerable v1-only signing.
- MANIFEST-018 _check_shared_user_id: android:sharedUserId deprecation
  and cross-app data-directory exposure.

Also provides ``_has_signature_or_system_protection``, the manifest
heuristic used to detect platform-signed APKs.  Its result is consumed
by ``AndroguardService.scan_manifest_security`` to decide whether to
reduce severity on findings that represent expected-system-app
behaviour.  This helper is kept in ``signing.py`` because it is
conceptually about signing-tier gating.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.manifest_checks._base import (
    _NS_ANDROID,
    ManifestFinding,
)

logger = logging.getLogger(__name__)


class SigningChecks:
    """Topic module for APK signing and sharedUserId checks."""

    # Protection levels that imply platform-level trust.  An APK that
    # *declares* permissions at these levels is enforcing platform-key
    # gating on its own components — a strong signal that it is a
    # legitimate system component rather than a third-party app that
    # happened to land in /system/priv-app/.
    _SIGNATURE_SYSTEM_LEVELS: set[str] = {
        "signature",
        "signatureorsystem",
        "signature|privileged",
        # Numeric values: 0x02 = signature, 0x03 = signatureOrSystem
        "0x2", "0x02", "2",
        "0x3", "0x03", "3",
    }

    # Well-known AOSP/OEM uses-permissions that require platform signing.
    # If an APK *requests* any of these, it was designed to run as a
    # platform-signed component.
    _PLATFORM_SIGNATURE_PERMISSIONS: set[str] = {
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.STATUS_BAR",
        "android.permission.STATUS_BAR_SERVICE",
        "android.permission.MANAGE_USERS",
        "android.permission.INTERACT_ACROSS_USERS",
        "android.permission.INTERACT_ACROSS_USERS_FULL",
        "android.permission.MANAGE_DEVICE_ADMINS",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.MASTER_CLEAR",
        "android.permission.REBOOT",
        "android.permission.SHUTDOWN",
        "android.permission.SET_TIME",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.CONNECTIVITY_INTERNAL",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.MANAGE_USB",
        "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        "android.permission.GRANT_RUNTIME_PERMISSIONS",
        "android.permission.REVOKE_RUNTIME_PERMISSIONS",
        "android.permission.MANAGE_APP_OPS_MODES",
    }

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def _has_signature_or_system_protection(
        self, apk_obj: Any
    ) -> bool:
        """Detect whether APK has signatureOrSystem-level protection.

        An APK is considered to have signatureOrSystem protection when
        **any** of these conditions is met:

        1. It **declares** one or more ``<permission>`` elements with a
           ``protectionLevel`` of ``signature``, ``signatureOrSystem``,
           or ``signature|privileged``.
        2. It **requests** (via ``<uses-permission>``) a well-known
           platform-signature permission that only platform-signed apps
           can hold (e.g., ``INSTALL_PACKAGES``, ``WRITE_SECURE_SETTINGS``).
        3. It has ``android:sharedUserId="android.uid.system"`` or
           ``android:sharedUserId="android.uid.phone"`` — explicit system
           UID sharing requires platform signing.

        These heuristics are lightweight (manifest-only, no crypto
        verification) and designed to have **high precision / low recall**:
        if any signal fires, the APK is almost certainly a genuine system
        component, justifying severity reduction.
        """
        # --- Check 1: declared permissions with signature protection -----
        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return False

        if manifest_xml is None:
            return False

        ns = _NS_ANDROID

        for elem in manifest_xml.findall(".//permission"):
            protection = (
                elem.get(f"{{{ns}}}protectionLevel")
                or elem.get("protectionLevel")
            )
            if protection and protection.strip().lower() in self._SIGNATURE_SYSTEM_LEVELS:
                return True

        # --- Check 2: uses well-known platform-signature permissions -----
        requested_perms: set[str] = set()
        try:
            perms = apk_obj.get_permissions()
            if perms:
                requested_perms = set(perms)
        except Exception:
            pass

        if requested_perms & self._PLATFORM_SIGNATURE_PERMISSIONS:
            return True

        # --- Check 3: sharedUserId = android.uid.system / phone ----------
        shared_uid = None
        try:
            shared_uid = (
                manifest_xml.get(f"{{{ns}}}sharedUserId")
                or manifest_xml.get("sharedUserId")
            )
        except Exception:
            pass

        if shared_uid and shared_uid in (
            "android.uid.system",
            "android.uid.phone",
            "android.uid.bluetooth",
            "android.uid.nfc",
        ):
            return True

        return False

    def _check_signing_scheme(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-014: Check APK signing scheme version.

        APK Signature Scheme v1 (JAR signing) is vulnerable to the
        Janus vulnerability (CVE-2017-13156) on Android < 7.0 and
        doesn't protect all APK contents.  v2/v3 schemes provide
        whole-APK integrity verification and are required for modern
        Android versions (CWE-347).
        """
        findings: list[ManifestFinding] = []

        try:
            # Androguard can detect which signing schemes are present
            is_signed_v1 = False
            is_signed_v2 = False
            is_signed_v3 = False

            try:
                is_signed_v1 = apk_obj.is_signed_v1()
            except Exception:
                pass
            try:
                is_signed_v2 = apk_obj.is_signed_v2()
            except Exception:
                pass
            try:
                is_signed_v3 = apk_obj.is_signed_v3()
            except Exception:
                pass

            if not is_signed_v1 and not is_signed_v2 and not is_signed_v3:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK is not signed",
                        severity="critical",
                        description=(
                            "The APK does not have any valid signature. "
                            "Unsigned APKs cannot be installed on Android "
                            "devices and indicate a development or tampered "
                            "build."
                        ),
                        evidence="No v1, v2, or v3 signature detected",
                        cwe_ids=["CWE-347"],
                        confidence="high",
                    )
                )
            elif is_signed_v1 and not is_signed_v2 and not is_signed_v3:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK uses only v1 (JAR) signing scheme",
                        severity="medium",
                        description=(
                            "The APK is signed with only the v1 (JAR) "
                            "signing scheme. v1 signatures are vulnerable "
                            "to the Janus attack (CVE-2017-13156) on "
                            "Android < 7.0 and do not protect all APK "
                            "contents. APK Signature Scheme v2 or v3 "
                            "should be used for whole-file integrity."
                        ),
                        evidence="Signing: v1=true, v2=false, v3=false",
                        cwe_ids=["CWE-347"],
                        confidence="high",
                    )
                )
            elif is_signed_v1 and is_signed_v2 and not is_signed_v3:
                # v1+v2 is acceptable but v3 adds key rotation support
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK lacks v3 signing (no key rotation support)",
                        severity="info",
                        description=(
                            "The APK is signed with v1+v2 schemes but not "
                            "v3. APK Signature Scheme v3 adds key rotation "
                            "support, allowing certificates to be updated "
                            "without requiring a new package name. Consider "
                            "adding v3 signing for future-proofing."
                        ),
                        evidence="Signing: v1=true, v2=true, v3=false",
                        cwe_ids=["CWE-347"],
                        confidence="low",
                    )
                )
        except Exception as e:
            logger.debug("Signing scheme check failed: %s", e)

        return findings

    def _check_shared_user_id(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-018: android:sharedUserId usage.

        The ``android:sharedUserId`` attribute is deprecated since
        API 29 (Android 10) and allows multiple apps signed with the
        same certificate to share a Linux UID, giving them access to
        each other's data directories.  This widens the attack surface:
        if *any* app sharing the UID is compromised, all other apps in
        the group are also exposed (CWE-250).

        System UIDs (``android.uid.system``, ``android.uid.phone``, etc.)
        are flagged at info level since they are expected for platform
        components.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID

        shared_uid = (
            manifest_xml.get(f"{{{ns}}}sharedUserId")
            or manifest_xml.get("sharedUserId")
        )

        if not shared_uid:
            return findings

        # Well-known system UIDs — expected for platform components
        system_uids = {
            "android.uid.system",
            "android.uid.phone",
            "android.uid.bluetooth",
            "android.uid.nfc",
            "android.uid.log",
            "android.uid.shell",
        }

        if shared_uid in system_uids:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-018",
                    title=f"System sharedUserId: {shared_uid}",
                    severity="info",
                    description=(
                        f"The application uses sharedUserId=\"{shared_uid}\", "
                        f"a well-known system UID. This is expected for "
                        f"platform components but means the app runs with "
                        f"elevated system privileges. The sharedUserId "
                        f"attribute is deprecated since Android 10 (API 29)."
                    ),
                    evidence=f'android:sharedUserId="{shared_uid}"',
                    cwe_ids=["CWE-250"],
                    confidence="high",
                )
            )
        else:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-018",
                    title=f"Custom sharedUserId: {shared_uid}",
                    severity="medium",
                    description=(
                        f"The application uses a custom "
                        f"sharedUserId=\"{shared_uid}\". Apps sharing this "
                        f"UID (and signed with the same certificate) can "
                        f"access each other's private data directories. "
                        f"If any app in the shared UID group is compromised, "
                        f"all others are also exposed. The sharedUserId "
                        f"attribute is deprecated since Android 10 (API 29) "
                        f"due to these security implications."
                    ),
                    evidence=f'android:sharedUserId="{shared_uid}"',
                    cwe_ids=["CWE-250"],
                    confidence="high",
                )
            )

        return findings
