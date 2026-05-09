"""Miscellaneous manifest security checks.

Currently covers MANIFEST-005 _check_min_sdk (outdated ``minSdkVersion``).
Additional stand-alone checks that don't fit the backup/network/
component/permission/signing categorisation land here.
"""

from __future__ import annotations

from typing import Any

from app.services.manifest_checks._base import (
    _MIN_SDK_CRITICAL_THRESHOLD,
    _MIN_SDK_SECURE_THRESHOLD,
    ManifestFinding,
    _sdk_to_android_version,
)


class MiscChecks:
    """Topic module for miscellaneous manifest checks."""

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def _check_min_sdk(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-005: minSdkVersion too low check.

        MobSF base severity: **high** for critically outdated (<19),
        **medium** for outdated (<24), **info** when absent.
        """
        min_sdk_str = apk_obj.get_min_sdk_version()
        try:
            min_sdk = int(min_sdk_str) if min_sdk_str else None
        except (ValueError, TypeError):
            min_sdk = None

        if min_sdk is None:
            return [
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title="minSdkVersion not specified",
                    severity="info",
                    description=(
                        "The minSdkVersion is not set in the manifest. "
                        "Without a minimum SDK constraint the app may run "
                        "on very old Android versions lacking critical "
                        "security patches."
                    ),
                    evidence="minSdkVersion not set",
                    cwe_ids=["CWE-1104"],
                    confidence="low",
                )
            ]

        findings: list[ManifestFinding] = []

        if min_sdk < _MIN_SDK_CRITICAL_THRESHOLD:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title=f"Critically outdated minSdkVersion ({min_sdk})",
                    severity="high",
                    description=(
                        f"minSdkVersion is {min_sdk} (Android "
                        f"{_sdk_to_android_version(min_sdk)}), which is below "
                        f"API {_MIN_SDK_CRITICAL_THRESHOLD} (Android 4.4 KitKat). "
                        "This ancient API level lacks TLS 1.2 by default, "
                        "modern certificate pinning support, and many "
                        "security hardening features introduced in later "
                        "Android releases."
                    ),
                    evidence=f"minSdkVersion={min_sdk}",
                    cwe_ids=["CWE-1104"],
                )
            )
        elif min_sdk < _MIN_SDK_SECURE_THRESHOLD:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title=f"Outdated minSdkVersion ({min_sdk})",
                    severity="low",
                    description=(
                        f"minSdkVersion is {min_sdk} (Android "
                        f"{_sdk_to_android_version(min_sdk)}), below "
                        f"API {_MIN_SDK_SECURE_THRESHOLD} (Android 7.0 Nougat). "
                        "This means the app supports devices that lack "
                        "file-based encryption, network security config "
                        "enforcement, and other modern security features."
                    ),
                    evidence=f"minSdkVersion={min_sdk}",
                    cwe_ids=["CWE-1104"],
                )
            )

        return findings
