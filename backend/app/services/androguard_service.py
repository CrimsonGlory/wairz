"""Androguard-based APK analysis service.

Provides deep static analysis of Android APK files: permissions,
components, signature verification, manifest parsing, and manifest
security scanning.  All methods are synchronous (CPU-bound) and
should be called via ``loop.run_in_executor()`` from async handlers.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from app.services.manifest_checks import ManifestChecker, ManifestFinding

logger = logging.getLogger(__name__)

# Re-export ManifestFinding so existing imports still work
__all__ = ["AndroguardService", "ManifestFinding", "classify_permission"]

# ---------------------------------------------------------------------------
# Manifest security finding data structure
# ---------------------------------------------------------------------------

# SDK thresholds defined in manifest_checks.py (used by _check_min_sdk)

# ---------------------------------------------------------------------------
# Severity hierarchy and firmware-context bumping
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]


def _bump_severity(severity: str) -> str:
    """Bump severity up by one level (info→low→medium→high→critical).

    Used to automatically escalate findings for APKs in privileged
    firmware locations (``/system/priv-app/``) or platform-signed APKs,
    which have wider blast radius when compromised.
    """
    try:
        idx = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def _reduce_severity(severity: str) -> str:
    """Reduce severity down by one level (critical→high→medium→low→info).

    Used to automatically de-escalate findings for platform-signed
    system components where certain security findings represent
    expected system behaviour rather than genuine vulnerabilities.
    """
    try:
        idx = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[max(idx - 1, 0)]


# Check IDs eligible for severity reduction on platform-signed system
# components.  These findings represent expected behaviour for system apps
# with signatureOrSystem protection and should be reduced by one severity
# level.  Checks NOT on this list (debuggable, cleartext traffic, testOnly,
# minSdk, network security config) remain dangerous even for system apps.
_PLATFORM_SIGNED_REDUCIBLE_CHECKS: set[str] = {
    # MANIFEST-002: allowBackup — system backup is platform-managed;
    # the platform controls which system apps participate in backup.
    "MANIFEST-002",
    # MANIFEST-006: exported components — system apps intentionally
    # export activities/services/receivers for platform IPC; protected
    # by platform-level signature checks at runtime.
    "MANIFEST-006",
    # MANIFEST-007: custom permissions with weak protectionLevel —
    # platform-signed apps can safely use normal/dangerous for APIs
    # consumed by other system components that share the platform key.
    "MANIFEST-007",
    # MANIFEST-008: StrandHogg v1 — task affinity hijacking is far
    # less relevant for platform-signed apps that run in the system
    # process or protected task stacks.
    "MANIFEST-008",
    # MANIFEST-009: StrandHogg v2 — same reasoning as v1; platform
    # components are not realistic targets for task embedding attacks.
    "MANIFEST-009",
    # MANIFEST-010: app link verification — system apps typically
    # handle intents via platform-level intent routing, not deep links.
    "MANIFEST-010",
    # MANIFEST-012: allowTaskReparenting — system apps have protected
    # task stacks managed by the platform; reparenting is benign.
    "MANIFEST-012",
    # MANIFEST-013: implicit intent hijacking — system components
    # intentionally expose services/receivers for platform IPC;
    # protected by platform-level signature checks.
    "MANIFEST-013",
    # MANIFEST-016: dangerous permissions — system apps often require
    # elevated permissions as part of their platform role.
    "MANIFEST-016",
    # MANIFEST-018: sharedUserId — system apps commonly use shared UIDs
    # as part of the platform architecture.
    "MANIFEST-018",
}


# ManifestFinding imported from manifest_checks.py (canonical definition)

# ---------------------------------------------------------------------------
# Permission risk classification
# ---------------------------------------------------------------------------

_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
}

_SIGNATURE_PERMISSIONS: set[str] = {
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.READ_LOGS",
    "android.permission.DUMP",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.GRANT_RUNTIME_PERMISSIONS",
    "android.permission.REVOKE_RUNTIME_PERMISSIONS",
    "android.permission.MANAGE_USERS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.MASTER_CLEAR",
}


def classify_permission(perm: str) -> str:
    """Classify an Android permission as 'dangerous', 'signature', or 'normal'."""
    if perm in _DANGEROUS_PERMISSIONS:
        return "dangerous"
    if perm in _SIGNATURE_PERMISSIONS:
        return "signature"
    return "normal"


# ---------------------------------------------------------------------------
# Permission-combination allowlisting (false-positive suppression)
# ---------------------------------------------------------------------------
# Known-safe permission groups that commonly appear together and should NOT
# trigger false-positive findings.  Each entry maps a frozenset of permission
# suffixes (without the ``android.permission.`` prefix) to metadata about
# the safe combination:
#   - ``reason``: human-readable explanation of why this group is safe
#   - ``suppress_check_ids``: set of check IDs whose findings are suppressed
#     when the APK's requested permissions are a *subset* of the allowlisted
#     combination (i.e., the APK only requests permissions in the safe group
#     and nothing else that's dangerous/signature)
#   - ``reduce_confidence``: if True and the finding is not fully suppressed,
#     reduce the confidence to "low" instead (softer suppression)
#
# The matching logic is: for a given APK, collect all its requested
# permissions.  For each allowlist entry, if the APK's "interesting"
# permissions (dangerous + signature) are a subset of the entry's permission
# set, all findings whose check_id is in ``suppress_check_ids`` are
# suppressed.

@dataclass
class _PermissionAllowlistEntry:
    """A known-safe permission combination that suppresses false positives."""

    permissions: frozenset[str]  # full permission names
    reason: str
    suppress_check_ids: set[str] = field(default_factory=set)
    reduce_confidence: bool = False


def _full_perms(*suffixes: str) -> frozenset[str]:
    """Build frozenset of full ``android.permission.*`` names from suffixes."""
    return frozenset(f"android.permission.{s}" for s in suffixes)


_SAFE_PERMISSION_GROUPS: list[_PermissionAllowlistEntry] = [
    # --- Networking basics ---
    # Almost every app that accesses the internet requests both.
    # INTERNET allows socket creation; ACCESS_NETWORK_STATE lets the
    # app check if the device is online before making requests.
    _PermissionAllowlistEntry(
        permissions=_full_perms("INTERNET", "ACCESS_NETWORK_STATE"),
        reason=(
            "Standard networking pair — required by virtually all apps "
            "that make HTTP requests"
        ),
        suppress_check_ids={"MANIFEST-006"},  # exported components
        reduce_confidence=True,
    ),
    # Extended networking: INTERNET + ACCESS_NETWORK_STATE +
    # ACCESS_WIFI_STATE — common for apps needing Wi-Fi detection
    _PermissionAllowlistEntry(
        permissions=_full_perms(
            "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
        ),
        reason=(
            "Standard networking triple — INTERNET + network/Wi-Fi state "
            "detection is common for connectivity-aware apps"
        ),
        suppress_check_ids={"MANIFEST-006"},
        reduce_confidence=True,
    ),
    # --- Location pair ---
    # Fine + coarse location together is the standard pattern since
    # ACCESS_COARSE_LOCATION is auto-granted alongside ACCESS_FINE_LOCATION.
    _PermissionAllowlistEntry(
        permissions=_full_perms(
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        ),
        reason=(
            "Standard location pair — coarse location is automatically "
            "granted alongside fine location"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Storage read pair (pre-Android 13) ---
    # READ_EXTERNAL_STORAGE + WRITE_EXTERNAL_STORAGE was the standard
    # pattern before scoped storage made these mostly obsolete.
    _PermissionAllowlistEntry(
        permissions=_full_perms(
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        ),
        reason=(
            "Standard storage pair (pre-Android 13) — both were required "
            "for file access before scoped storage"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Media access triple (Android 13+) ---
    # READ_MEDIA_IMAGES + READ_MEDIA_VIDEO + READ_MEDIA_AUDIO replaced
    # the old storage permissions starting with Android 13.
    _PermissionAllowlistEntry(
        permissions=_full_perms(
            "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
        ),
        reason=(
            "Standard media access triple (Android 13+) — granular "
            "replacements for READ_EXTERNAL_STORAGE"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Bluetooth pair (Android 12+) ---
    # BLUETOOTH_CONNECT + BLUETOOTH_SCAN are the new runtime permissions
    # replacing the deprecated BLUETOOTH and BLUETOOTH_ADMIN.
    _PermissionAllowlistEntry(
        permissions=_full_perms("BLUETOOTH_CONNECT", "BLUETOOTH_SCAN"),
        reason=(
            "Standard Bluetooth pair (Android 12+) — required for BLE "
            "scanning and connecting to devices"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Contacts read/write pair ---
    # Apps that manage contacts always request both.
    _PermissionAllowlistEntry(
        permissions=_full_perms("READ_CONTACTS", "WRITE_CONTACTS"),
        reason="Standard contacts pair — read + write access together",
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Calendar read/write pair ---
    _PermissionAllowlistEntry(
        permissions=_full_perms("READ_CALENDAR", "WRITE_CALENDAR"),
        reason="Standard calendar pair — read + write access together",
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Call log read/write pair ---
    _PermissionAllowlistEntry(
        permissions=_full_perms("READ_CALL_LOG", "WRITE_CALL_LOG"),
        reason="Standard call log pair — read + write access together",
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- SMS pair ---
    _PermissionAllowlistEntry(
        permissions=_full_perms("READ_SMS", "RECEIVE_SMS"),
        reason=(
            "Standard SMS receive pair — apps verifying SMS codes need both"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Foreground service + wake lock ---
    # Very common combination for apps with background tasks that need
    # to keep the CPU awake.
    _PermissionAllowlistEntry(
        permissions=_full_perms("FOREGROUND_SERVICE", "WAKE_LOCK"),
        reason=(
            "Standard background task pair — foreground service with "
            "wake lock to prevent CPU sleep"
        ),
        suppress_check_ids=set(),
        reduce_confidence=True,
    ),
    # --- Boot completed + receive boot (common for services) ---
    _PermissionAllowlistEntry(
        permissions=_full_perms(
            "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE",
        ),
        reason=(
            "Standard auto-start service pair — start foreground service "
            "after device boot"
        ),
        suppress_check_ids={"MANIFEST-006"},
        reduce_confidence=True,
    ),
]


def _apply_permission_allowlisting(
    findings: list[ManifestFinding],
    apk_permissions: set[str],
) -> tuple[list[ManifestFinding], int, list[str]]:
    """Apply permission-combination allowlisting to suppress false positives.

    For each safe permission group, if the APK's dangerous+signature
    permissions are a *subset* of the group's permissions, matching
    findings are either suppressed entirely (check_id in
    ``suppress_check_ids``) or have their confidence reduced to "low"
    (when ``reduce_confidence`` is True).

    Parameters
    ----------
    findings:
        Mutable list of findings from the manifest checks.
    apk_permissions:
        Full set of permissions requested by the APK.

    Returns
    -------
    tuple:
        (filtered_findings, suppressed_count, suppression_reasons)
        ``filtered_findings`` is the same list with suppressed findings
        marked.  ``suppressed_count`` and ``suppression_reasons`` are
        for summary reporting.
    """
    if not apk_permissions:
        return findings, 0, []

    # Build the set of "notable" permissions — those that are dangerous,
    # signature-level, or explicitly listed in any allowlist group.
    # Normal permissions not in any group (e.g., VIBRATE, WAKE_LOCK) are
    # ignored for matching purposes — they don't affect safety assessment.
    allowlisted_perms: set[str] = set()
    for entry in _SAFE_PERMISSION_GROUPS:
        allowlisted_perms |= entry.permissions

    notable_perms = {
        p for p in apk_permissions
        if (
            p in _DANGEROUS_PERMISSIONS
            or p in _SIGNATURE_PERMISSIONS
            or p in allowlisted_perms
        )
    }

    if not notable_perms:
        # Only trivial normal permissions — nothing to check
        return findings, 0, []

    suppressed_count = 0
    suppression_reasons: list[str] = []

    for entry in _SAFE_PERMISSION_GROUPS:
        # Check if the APK has any overlap with this safe group.
        matching_perms = notable_perms & entry.permissions
        if not matching_perms:
            continue

        # Require that ALL the APK's notable permissions are covered
        # by this safe group.  If the APK has extra dangerous/signature
        # permissions beyond the safe group, the combination is not
        # "known safe" — skip this entry entirely.
        if not notable_perms.issubset(entry.permissions):
            continue

        # This safe group is applicable.  Apply suppression.
        for finding in findings:
            if finding.suppressed:
                continue

            if finding.check_id in entry.suppress_check_ids:
                finding.suppressed = True
                finding.suppression_reason = (
                    f"Allowlisted permission group: {entry.reason}"
                )
                suppressed_count += 1
                if entry.reason not in suppression_reasons:
                    suppression_reasons.append(entry.reason)

            elif entry.reduce_confidence and finding.confidence != "low":
                # Softer suppression: don't remove the finding, but
                # reduce confidence to indicate it's likely benign
                # given the safe permission combination.
                original = finding.confidence
                finding.confidence = "low"
                if finding.suppression_reason:
                    finding.suppression_reason += (
                        f"; confidence reduced ({original}→low): "
                        f"{entry.reason}"
                    )
                else:
                    finding.suppression_reason = (
                        f"Confidence reduced ({original}→low) due to "
                        f"allowlisted permission group: {entry.reason}"
                    )

    return findings, suppressed_count, suppression_reasons


class AndroguardService:
    """Wraps Androguard to analyse individual APK files.

    Composes ``ManifestChecker`` (from ``app.services.manifest_checks``)
    instead of inheriting a monolithic mixin.  ``ManifestChecker`` in
    turn aggregates six topic modules (backup/debug, network, component,
    permission, signing, misc).  Thin ``_check_*`` forwarders below
    preserve the existing ``self._check_<name>(...)`` call sites in
    ``scan_manifest_security`` so the composition change stayed local.
    """

    def __init__(self) -> None:
        self.manifest_checker = ManifestChecker(self)

        # Thin forwarders so ``self._check_<name>(...)`` inside
        # ``scan_manifest_security`` continues to work with the same
        # method-name surface the legacy Mixin provided.  Binding the
        # already-bound methods from ``self.manifest_checker`` preserves
        # correct ``self`` semantics on each topic module.
        self._check_debuggable = self.manifest_checker._check_debuggable
        self._check_allow_backup = self.manifest_checker._check_allow_backup
        self._check_cleartext_traffic = (
            self.manifest_checker._check_cleartext_traffic
        )
        self._check_test_only = self.manifest_checker._check_test_only
        self._check_min_sdk = self.manifest_checker._check_min_sdk
        self._check_exported_components = (
            self.manifest_checker._check_exported_components
        )
        self._check_custom_permissions = (
            self.manifest_checker._check_custom_permissions
        )
        self._check_strandhogg_v1 = self.manifest_checker._check_strandhogg_v1
        self._check_strandhogg_v2 = self.manifest_checker._check_strandhogg_v2
        self._check_app_links = self.manifest_checker._check_app_links
        self._check_network_security_config = (
            self.manifest_checker._check_network_security_config
        )
        self._check_allow_task_reparenting = (
            self.manifest_checker._check_allow_task_reparenting
        )
        self._check_implicit_intent_hijacking = (
            self.manifest_checker._check_implicit_intent_hijacking
        )
        self._check_signing_scheme = self.manifest_checker._check_signing_scheme
        self._check_backup_agent = self.manifest_checker._check_backup_agent
        self._check_dangerous_permissions = (
            self.manifest_checker._check_dangerous_permissions
        )
        self._check_intent_scheme_hijacking = (
            self.manifest_checker._check_intent_scheme_hijacking
        )
        self._check_shared_user_id = self.manifest_checker._check_shared_user_id
        self._has_signature_or_system_protection = (
            self.manifest_checker._has_signature_or_system_protection
        )

    @staticmethod
    def is_available() -> bool:
        """Return True if androguard is importable."""
        try:
            import androguard  # noqa: F401
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze_apk(self, apk_path: str) -> dict[str, Any]:
        """Analyse an APK and return structured metadata.

        Raises ``ImportError`` if androguard is not installed, or
        ``FileNotFoundError`` / ``ValueError`` on bad input.
        """
        from androguard.misc import AnalyzeAPK

        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        apk_obj, dex_list, analysis = AnalyzeAPK(apk_path)

        result: dict[str, Any] = {
            "package": apk_obj.get_package() or "unknown",
            "version_code": apk_obj.get_androidversion_code(),
            "version_name": apk_obj.get_androidversion_name(),
            "min_sdk": apk_obj.get_min_sdk_version(),
            "target_sdk": apk_obj.get_target_sdk_version(),
            "permissions": sorted(apk_obj.get_permissions()),
            "activities": sorted(apk_obj.get_activities()),
            "services": sorted(apk_obj.get_services()),
            "receivers": sorted(apk_obj.get_receivers()),
            "providers": sorted(apk_obj.get_providers()),
            "main_activity": apk_obj.get_main_activity(),
            "is_signed": apk_obj.is_signed(),
            "signatures": [],
        }

        # Certificate info
        try:
            certs = apk_obj.get_certificates()
            for cert in certs:
                sig_info: dict[str, Any] = {}
                try:
                    sig_info["issuer"] = str(cert.issuer.human_friendly) if hasattr(cert.issuer, "human_friendly") else str(cert.issuer)
                except Exception:
                    sig_info["issuer"] = "unknown"
                try:
                    sig_info["subject"] = str(cert.subject.human_friendly) if hasattr(cert.subject, "human_friendly") else str(cert.subject)
                except Exception:
                    sig_info["subject"] = "unknown"
                try:
                    sig_info["serial"] = str(cert.serial_number)
                except Exception:
                    sig_info["serial"] = "unknown"
                try:
                    sig_info["algorithm"] = cert.signature_algo or "unknown"
                except Exception:
                    sig_info["algorithm"] = "unknown"
                try:
                    sig_info["not_before"] = str(cert["tbs_certificate"]["validity"]["not_before"].native)
                    sig_info["not_after"] = str(cert["tbs_certificate"]["validity"]["not_after"].native)
                except Exception:
                    pass

                # Debug/test certificate detection
                sig_info["is_debug"] = self._is_debug_cert(sig_info)
                result["signatures"].append(sig_info)
        except Exception as exc:
            logger.warning("Failed to extract certificate info from %s: %s", apk_path, exc)

        return result

    # ------------------------------------------------------------------
    # Manifest security scanning
    # ------------------------------------------------------------------

    def scan_manifest_security(
        self,
        apk_path: str,
        *,
        is_priv_app: bool = False,
        is_platform_signed: bool = False,
    ) -> dict[str, Any]:
        """Run manifest-level security checks on an APK.

        Each check assigns a **static base severity** matching MobSF's
        classification.  When the APK is in a privileged firmware
        location (``/system/priv-app/``) or is signed with the platform
        key, **all findings are automatically bumped +1 severity level**
        (info→low→medium→high→critical) to reflect the wider blast
        radius of privileged system components.

        **Severity reduction for platform-signed system components:**
        After the bump, if the APK is platform-signed AND has
        signatureOrSystem-level protection (detected via declared
        permissions, requested platform-signature permissions, or
        system shared UID), findings for *expected system behaviour*
        checks are automatically **reduced by 1 severity level**.
        This prevents noisy false-positive-grade findings on legitimate
        OEM/AOSP system apps.  See ``_PLATFORM_SIGNED_REDUCIBLE_CHECKS``
        for the eligible check IDs.

        **Permission-combination allowlisting:**
        Before firmware-context adjustments, known-safe permission
        combinations (e.g., INTERNET + ACCESS_NETWORK_STATE) are checked
        against the APK's requested permissions.  Findings matching
        ``suppress_check_ids`` for applicable safe groups are suppressed
        entirely; other findings have their confidence reduced to "low".
        See ``_SAFE_PERMISSION_GROUPS`` for the full allowlist.

        Returns a dict with ``package``, ``findings`` (list of finding
        dicts), ``summary`` counts by severity, ``total_findings``,
        ``suppressed_findings``, ``suppressed_count``, ``suppression_reasons``,
        ``severity_bumped`` (bool), ``severity_reduced`` (bool), and
        ``reduced_check_ids`` (list of check IDs that were reduced).

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file.
        is_priv_app:
            Whether the APK resides in a ``/system/priv-app/`` directory.
            Triggers automatic +1 severity bump on all findings.
        is_platform_signed:
            Whether the APK is signed with the platform key.  Triggers
            automatic +1 severity bump on all findings.  Also triggers
            severity reduction for eligible checks if the APK has
            signatureOrSystem protection.
        """
        import time

        from androguard.core.apk import APK

        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        t0 = time.monotonic()

        # Use APK() instead of AnalyzeAPK() — manifest checks only need
        # the APK manifest/resources, not DEX parsing or analysis.
        # This reduces scan time from seconds to well under 500ms.
        apk_obj = APK(apk_path)

        t_parse = time.monotonic()

        # Detect debug signing for context-aware checks (lightweight,
        # uses APK() internally so adds <10ms).
        is_debug_signed = False
        try:
            certs = apk_obj.get_certificates()
            for cert in certs:
                sig_info: dict[str, Any] = {}
                try:
                    sig_info["subject"] = (
                        str(cert.subject.human_friendly)
                        if hasattr(cert.subject, "human_friendly")
                        else str(cert.subject)
                    )
                except Exception:
                    sig_info["subject"] = "unknown"
                if self._is_debug_cert(sig_info):
                    is_debug_signed = True
                    break
        except Exception:
            pass

        findings: list[ManifestFinding] = []

        # Run each check — context-aware checks receive signing/location
        # information for severity and confidence adjustments.
        findings.extend(self._check_debuggable(
            apk_obj,
            is_platform_signed=is_platform_signed,
            is_debug_signed=is_debug_signed,
        ))
        findings.extend(self._check_allow_backup(
            apk_obj,
            is_platform_signed=is_platform_signed,
            is_priv_app=is_priv_app,
        ))
        findings.extend(self._check_cleartext_traffic(apk_obj))
        findings.extend(self._check_test_only(apk_obj))
        findings.extend(self._check_min_sdk(apk_obj))
        findings.extend(self._check_exported_components(apk_obj))
        findings.extend(self._check_custom_permissions(apk_obj))
        findings.extend(self._check_strandhogg_v1(apk_obj))
        findings.extend(self._check_strandhogg_v2(apk_obj))
        findings.extend(self._check_app_links(apk_obj))
        findings.extend(self._check_network_security_config(apk_obj))
        findings.extend(self._check_allow_task_reparenting(apk_obj))
        findings.extend(self._check_implicit_intent_hijacking(apk_obj))
        findings.extend(self._check_signing_scheme(apk_obj))
        findings.extend(self._check_backup_agent(apk_obj))
        findings.extend(self._check_dangerous_permissions(apk_obj))
        findings.extend(self._check_intent_scheme_hijacking(apk_obj))
        findings.extend(self._check_shared_user_id(apk_obj))

        # --- Permission-combination allowlisting -------------------------
        # Suppress false positives for known-safe permission groups.
        # Applied before firmware-context adjustments so that suppressed
        # findings aren't subsequently bumped/reduced (they're already
        # marked as benign).
        try:
            apk_permissions = set(apk_obj.get_permissions())
        except Exception:
            apk_permissions = set()

        findings, suppressed_count, suppression_reasons = (
            _apply_permission_allowlisting(findings, apk_permissions)
        )

        # Remove fully suppressed findings from the active list but keep
        # them available for transparency/audit.
        suppressed_findings = [f for f in findings if f.suppressed]
        active_findings = [f for f in findings if not f.suppressed]

        # --- Firmware context: automatic +1 severity bump ----------------
        # APKs in /system/priv-app/ or signed with the platform key have
        # elevated privileges and wider blast radius — bump every finding
        # up one severity level (info→low, low→medium, medium→high,
        # high→critical).  This matches the MobSF risk-adjustment model.
        # Only active (non-suppressed) findings are bumped.
        severity_bumped = is_priv_app or is_platform_signed
        if severity_bumped:
            for f in active_findings:
                f.severity = _bump_severity(f.severity)

        # --- Platform-signed system component: automatic -1 reduction -----
        # Platform-signed APKs with signatureOrSystem protection are
        # trusted system components.  Certain findings (exported
        # components, backup, weak custom permissions, StrandHogg,
        # app links) represent *expected* system behaviour and should
        # be de-escalated by one severity level.  This prevents noisy
        # false-positive-grade findings on OEM/AOSP system apps while
        # keeping genuinely dangerous findings (debuggable, cleartext,
        # testOnly, minSdk, NSC) at full severity.
        severity_reduced = False
        reduced_check_ids: list[str] = []
        if is_platform_signed:
            has_sig_or_system = self._has_signature_or_system_protection(
                apk_obj,
            )
            if has_sig_or_system:
                for f in active_findings:
                    if f.check_id in _PLATFORM_SIGNED_REDUCIBLE_CHECKS:
                        original = f.severity
                        f.severity = _reduce_severity(f.severity)
                        if f.severity != original:
                            severity_reduced = True
                            reduced_check_ids.append(f.check_id)

        t_checks = time.monotonic()

        # Summarize by severity and confidence (active findings only)
        summary: dict[str, int] = {}
        confidence_summary: dict[str, int] = {}
        for f in active_findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
            confidence_summary[f.confidence] = (
                confidence_summary.get(f.confidence, 0) + 1
            )

        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        parse_ms = round((t_parse - t0) * 1000, 1)
        checks_ms = round((t_checks - t_parse) * 1000, 1)

        logger.info(
            "Manifest scan for %s completed in %.1fms "
            "(parse=%.1fms, checks=%.1fms, %d findings, "
            "%d suppressed, bumped=%s, reduced=%s)",
            apk_path, elapsed_ms, parse_ms, checks_ms,
            len(active_findings), suppressed_count,
            severity_bumped, severity_reduced,
        )

        return {
            "package": apk_obj.get_package() or "unknown",
            "findings": [f.to_dict() for f in active_findings],
            "summary": summary,
            "confidence_summary": confidence_summary,
            "total_findings": len(active_findings),
            "suppressed_findings": [f.to_dict() for f in suppressed_findings],
            "suppressed_count": suppressed_count,
            "suppression_reasons": suppression_reasons,
            "severity_bumped": severity_bumped,
            "severity_reduced": severity_reduced,
            "reduced_check_ids": reduced_check_ids,
            "is_debug_signed": is_debug_signed,
            "elapsed_ms": elapsed_ms,
            "parse_ms": parse_ms,
            "checks_ms": checks_ms,
        }


    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_debug_cert(sig_info: dict[str, Any]) -> bool:
        """Heuristic check for debug/test signing certificates."""
        for cert_field in ("issuer", "subject"):
            val = sig_info.get(cert_field, "").lower()
            if any(kw in val for kw in ("android debug", "debug", "test", "cn=android debug")):
                return True
        return False

    def get_permissions_with_risk(self, apk_path: str) -> list[dict[str, str]]:
        """Return permissions with risk classification.

        Lightweight wrapper that only extracts permissions (still uses
        full ``AnalyzeAPK`` under the hood — Androguard has no lighter API).
        """
        info = self.analyze_apk(apk_path)
        return [
            {"permission": p, "risk": classify_permission(p)}
            for p in info["permissions"]
        ]

    def check_signatures(self, apk_path: str) -> dict[str, Any]:
        """Verify APK signatures and check for debug/test certs."""
        info = self.analyze_apk(apk_path)
        warnings: list[str] = []

        if not info["is_signed"]:
            warnings.append("APK is NOT signed")

        for sig in info["signatures"]:
            if sig.get("is_debug"):
                warnings.append(
                    f"Debug/test certificate detected: {sig.get('subject', 'unknown')}"
                )
            algo = sig.get("algorithm", "").lower()
            if "md5" in algo or "sha1" in algo:
                warnings.append(
                    f"Weak signature algorithm: {sig.get('algorithm')}"
                )

        return {
            "package": info["package"],
            "is_signed": info["is_signed"],
            "signatures": info["signatures"],
            "warnings": warnings,
        }

    def check_is_debug_signed(self, apk_path: str) -> bool:
        """Lightweight check: is the APK signed with a debug certificate?

        Uses ``APK()`` (no DEX parsing) so it completes in milliseconds
        instead of seconds.  Suitable for the platform-signing heuristic
        in manifest scan workflows where full signature analysis is overkill.
        """
        from androguard.core.apk import APK

        try:
            apk_obj = APK(apk_path)
            certs = apk_obj.get_certificates()
            for cert in certs:
                sig_info: dict[str, Any] = {}
                try:
                    sig_info["subject"] = (
                        str(cert.subject.human_friendly)
                        if hasattr(cert.subject, "human_friendly")
                        else str(cert.subject)
                    )
                except Exception:
                    sig_info["subject"] = "unknown"
                if self._is_debug_cert(sig_info):
                    return True
        except Exception:
            pass
        return False

    def check_platform_signed(self, apk_path: str) -> bool:
        """Detect whether an APK is likely platform-signed.

        Uses manifest heuristics (declared signatureOrSystem permissions,
        requested platform-signature permissions, system shared UIDs)
        rather than the less accurate "not debug-signed" negation.

        Uses ``APK()`` (no DEX parsing) so it completes in milliseconds.
        """
        from androguard.core.apk import APK

        try:
            apk_obj = APK(apk_path)
            return self._has_signature_or_system_protection(apk_obj)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
