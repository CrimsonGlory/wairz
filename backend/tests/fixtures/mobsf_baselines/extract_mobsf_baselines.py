#!/usr/bin/env python3
"""MobSF manifest baseline extraction utility.

Runs Wairz's manifest scanner (AndroguardService) against each well-known test
APK using mock Androguard APK objects, then exports normalised findings to JSON
fixture files alongside the known MobSF baselines for comparison.

Usage (from backend/ directory):
    python -m tests.fixtures.mobsf_baselines.extract_mobsf_baselines

    # Or directly:
    python tests/fixtures/mobsf_baselines/extract_mobsf_baselines.py

    # With --update flag to overwrite existing fixture files:
    python -m tests.fixtures.mobsf_baselines.extract_mobsf_baselines --update

Outputs:
    tests/fixtures/mobsf_baselines/diva_wairz_scan.json
    tests/fixtures/mobsf_baselines/insecurebankv2_wairz_scan.json
    tests/fixtures/mobsf_baselines/ovaa_wairz_scan.json
    tests/fixtures/mobsf_baselines/comparison_report.json  (side-by-side diff)

Each *_wairz_scan.json file contains the normalised output from our scanner,
and comparison_report.json shows matched/missing/extra findings vs the MobSF
baselines.
"""

from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure imports resolve when run as a script from backend/
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _THIS_DIR.parent.parent.parent  # backend/
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.services.androguard_service import AndroguardService  # noqa: E402

NS_ANDROID = "http://schemas.android.com/apk/res/android"


# ============================================================================
# APK mock builders (extracted from existing test files for reuse)
# ============================================================================


@dataclass
class TestAPKSpec:
    """Specification for a test APK mock."""

    name: str
    package: str
    min_sdk: str
    target_sdk: str
    manifest_xml: str
    permissions: list[str]
    baseline_file: str
    output_file: str
    # Optional component lists (for APKs that need explicit lists)
    activities: list[str] | None = None
    services: list[str] | None = None
    receivers: list[str] | None = None
    providers: list[str] | None = None
    # Extra attribute overrides
    extra_attrs: dict[tuple[str, str], str | None] | None = None


# ---- DIVA manifest XML ---------------------------------------------------

DIVA_MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="jakhar.aseem.diva"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="24" />

    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">

        <activity android:name="jakhar.aseem.diva.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name="jakhar.aseem.diva.LogActivity" />
        <activity android:name="jakhar.aseem.diva.HardcodeActivity" />

        <activity android:name="jakhar.aseem.diva.InsecureDataStorage1Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.InsecureDataStorage2Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.InsecureDataStorage3Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.InsecureDataStorage4Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.InputValidation2URISchemeActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.AccessControl1Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.AccessControl2Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.AccessControl3Activity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity android:name="jakhar.aseem.diva.APICreds1Activity" />
        <activity android:name="jakhar.aseem.diva.APICreds2Activity" />

        <provider
            android:name="jakhar.aseem.diva.NotesProvider"
            android:authorities="jakhar.aseem.diva.provider.notesprovider" />
        <provider
            android:name="jakhar.aseem.diva.NotesProvider2"
            android:authorities="jakhar.aseem.diva.provider.notesprovider2" />
    </application>
</manifest>
"""

# ---- InsecureBankv2 manifest XML ------------------------------------------

INSECUREBANKV2_MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.android.insecurebankv2"
    android:versionCode="1"
    android:versionName="2.0">

    <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="15"/>

    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.GET_ACCOUNTS"/>
    <uses-permission android:name="android.permission.USE_CREDENTIALS"/>

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">

        <activity
            android:name="com.android.insecurebankv2.LoginActivity"
            android:exported="true"
            android:label="@string/app_name">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <activity
            android:name="com.android.insecurebankv2.PostLogin"
            android:exported="true"
            android:label="@string/title_activity_post_login"/>

        <activity
            android:name="com.android.insecurebankv2.DoTransfer"
            android:exported="true"
            android:label="@string/title_activity_do_transfer"/>

        <activity
            android:name="com.android.insecurebankv2.ViewStatement"
            android:exported="true"
            android:label="@string/title_activity_view_statement">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="http"
                      android:host="mybank.com"/>
            </intent-filter>
        </activity>

        <activity
            android:name="com.android.insecurebankv2.ChangePassword"
            android:exported="true"
            android:label="@string/title_activity_change_password"/>

        <activity
            android:name="com.android.insecurebankv2.DoLogin"
            android:exported="true"
            android:label="@string/title_activity_do_login"/>

        <activity
            android:name="com.android.insecurebankv2.FilePrefActivity"
            android:exported="true"
            android:label="@string/title_activity_file_pref"/>

        <activity
            android:name="com.android.insecurebankv2.WebViewActivity"
            android:exported="true"
            android:label="@string/title_activity_web_view"/>

        <service
            android:name="com.android.insecurebankv2.MyBroadCastReceiver"
            android:exported="true"/>

        <receiver
            android:name="com.android.insecurebankv2.MyBroadCastReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="theBroadcast"/>
            </intent-filter>
        </receiver>

    </application>
</manifest>
"""

# ---- OVAA manifest XML ---------------------------------------------------

OVAA_MANIFEST_XML = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.ovaa">

    <uses-sdk android:minSdkVersion="23"
              android:targetSdkVersion="29" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />

    <application
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:name=".OvaaApplication"
        android:label="OVAA">

        <activity android:name="oversecured.ovaa.LoginActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name="oversecured.ovaa.DeeplinkActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="oversecured" android:host="ovaa" />
            </intent-filter>
        </activity>

        <activity android:name="oversecured.ovaa.WebViewActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="oversecured.com" />
            </intent-filter>
        </activity>

        <activity android:name="oversecured.ovaa.activities.EntropyActivity"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.InsecureSharedPrefsActivity"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.InsecureStorageActivity"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.SQLInjectionActivity"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.InsecureLogActivity"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.TheftActivity"
                  android:launchMode="singleTask"
                  android:exported="true" />

        <activity android:name="oversecured.ovaa.activities.InternalActivity"
                  android:exported="false" />

        <provider
            android:name="oversecured.ovaa.providers.TheftOverContentProvider"
            android:authorities="oversecured.ovaa.theftover"
            android:exported="true" />

        <provider
            android:name="oversecured.ovaa.providers.InsecureProvider"
            android:authorities="oversecured.ovaa.insecure"
            android:exported="true" />

        <receiver android:name="oversecured.ovaa.receivers.InsecureReceiver"
                  android:exported="true">
            <intent-filter>
                <action android:name="oversecured.ovaa.INSECURE_ACTION" />
            </intent-filter>
        </receiver>

        <service android:name="oversecured.ovaa.services.InternalService"
                 android:exported="false" />

    </application>
</manifest>
"""


# ============================================================================
# Mock APK builders
# ============================================================================


def _build_mock_apk(spec: TestAPKSpec) -> MagicMock:
    """Build a mock Androguard APK object from a TestAPKSpec."""
    apk = MagicMock()
    manifest_tree = ET.fromstring(spec.manifest_xml)

    apk.get_package.return_value = spec.package
    apk.get_min_sdk_version.return_value = spec.min_sdk
    apk.get_target_sdk_version.return_value = spec.target_sdk
    apk.get_main_activity.return_value = f"{spec.package}.MainActivity"
    apk.get_android_manifest_xml.return_value = manifest_tree
    apk.get_permissions.return_value = spec.permissions

    # No network security config by default
    apk.get_file.return_value = None

    # get_attribute_value: resolve from the actual manifest XML
    def _get_attribute_value(tag: str, attr: str) -> str | None:
        ns = f"{{{NS_ANDROID}}}"
        if tag == "application":
            elem = manifest_tree.find(".//application")
        elif tag == "manifest":
            elem = manifest_tree
        else:
            elem = manifest_tree.find(f".//{tag}")

        if elem is None:
            return None

        # Merge any extra_attrs overrides
        key = (tag, attr)
        if spec.extra_attrs and key in spec.extra_attrs:
            return spec.extra_attrs[key]

        # Try both namespaced and plain attribute names
        for name in (attr, f"{ns}{attr}"):
            val = elem.get(name)
            if val is not None:
                return val
        return None

    apk.get_attribute_value.side_effect = _get_attribute_value

    # Set component lists if provided
    if spec.activities is not None:
        apk.get_activities.return_value = spec.activities
    if spec.services is not None:
        apk.get_services.return_value = spec.services
    if spec.receivers is not None:
        apk.get_receivers.return_value = spec.receivers
    if spec.providers is not None:
        apk.get_providers.return_value = spec.providers

    return apk


# ============================================================================
# APK specifications
# ============================================================================

DIVA_SPEC = TestAPKSpec(
    name="DIVA",
    package="jakhar.aseem.diva",
    min_sdk="15",
    target_sdk="24",
    manifest_xml=DIVA_MANIFEST_XML,
    permissions=[
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.INTERNET",
    ],
    baseline_file="diva_baseline.json",
    output_file="diva_wairz_scan.json",
    activities=[
        "jakhar.aseem.diva.MainActivity",
        "jakhar.aseem.diva.LogActivity",
        "jakhar.aseem.diva.HardcodeActivity",
        "jakhar.aseem.diva.InsecureDataStorage1Activity",
        "jakhar.aseem.diva.InsecureDataStorage2Activity",
        "jakhar.aseem.diva.InsecureDataStorage3Activity",
        "jakhar.aseem.diva.InsecureDataStorage4Activity",
        "jakhar.aseem.diva.InputValidation2URISchemeActivity",
        "jakhar.aseem.diva.AccessControl1Activity",
        "jakhar.aseem.diva.AccessControl2Activity",
        "jakhar.aseem.diva.AccessControl3Activity",
        "jakhar.aseem.diva.APICreds1Activity",
        "jakhar.aseem.diva.APICreds2Activity",
    ],
    services=[],
    receivers=[],
    providers=[
        "jakhar.aseem.diva.NotesProvider",
        "jakhar.aseem.diva.NotesProvider2",
    ],
)

INSECUREBANKV2_SPEC = TestAPKSpec(
    name="InsecureBankv2",
    package="com.android.insecurebankv2",
    min_sdk="15",
    target_sdk="15",
    manifest_xml=INSECUREBANKV2_MANIFEST_XML,
    permissions=[
        "android.permission.INTERNET",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.GET_ACCOUNTS",
        "android.permission.USE_CREDENTIALS",
    ],
    baseline_file="insecurebankv2_baseline.json",
    output_file="insecurebankv2_wairz_scan.json",
    activities=[
        "com.android.insecurebankv2.LoginActivity",
        "com.android.insecurebankv2.PostLogin",
        "com.android.insecurebankv2.DoTransfer",
        "com.android.insecurebankv2.ViewStatement",
        "com.android.insecurebankv2.ChangePassword",
        "com.android.insecurebankv2.DoLogin",
        "com.android.insecurebankv2.FilePrefActivity",
        "com.android.insecurebankv2.WebViewActivity",
    ],
    services=["com.android.insecurebankv2.MyBroadCastReceiver"],
    receivers=["com.android.insecurebankv2.MyBroadCastReceiver"],
    providers=[],
)

OVAA_SPEC = TestAPKSpec(
    name="OVAA",
    package="oversecured.ovaa",
    min_sdk="23",
    target_sdk="29",
    manifest_xml=OVAA_MANIFEST_XML,
    permissions=[
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ],
    baseline_file="ovaa_baseline.json",
    output_file="ovaa_wairz_scan.json",
    activities=[
        "oversecured.ovaa.LoginActivity",
        "oversecured.ovaa.DeeplinkActivity",
        "oversecured.ovaa.WebViewActivity",
        "oversecured.ovaa.activities.EntropyActivity",
        "oversecured.ovaa.activities.InsecureSharedPrefsActivity",
        "oversecured.ovaa.activities.InsecureStorageActivity",
        "oversecured.ovaa.activities.SQLInjectionActivity",
        "oversecured.ovaa.activities.InsecureLogActivity",
        "oversecured.ovaa.activities.TheftActivity",
        "oversecured.ovaa.activities.InternalActivity",
    ],
    services=["oversecured.ovaa.services.InternalService"],
    receivers=["oversecured.ovaa.receivers.InsecureReceiver"],
    providers=[
        "oversecured.ovaa.providers.TheftOverContentProvider",
        "oversecured.ovaa.providers.InsecureProvider",
    ],
)

ALL_SPECS = [DIVA_SPEC, INSECUREBANKV2_SPEC, OVAA_SPEC]


# ============================================================================
# Scanner runner
# ============================================================================


def run_scan(spec: TestAPKSpec) -> dict[str, Any]:
    """Run the Wairz manifest scanner against a mock APK and return results."""
    svc = AndroguardService()
    apk_mock = _build_mock_apk(spec)
    fake_path = f"/fake/{spec.package}.apk"

    # Patch target: scan_manifest_security imports APK lazily via
    # `from androguard.core.apk import APK` at call time. Python's local
    # import reads androguard.core.apk.APK at the moment of call, so we
    # patch the source module, not app.services.androguard_service.
    with patch("androguard.core.apk.APK", return_value=apk_mock):
        with patch("os.path.isfile", return_value=True):
            return svc.scan_manifest_security(fake_path)


def normalise_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalise a scanner finding to the baseline comparison format."""
    return {
        "check_id": finding["check_id"],
        "title": finding["title"],
        "severity": finding["severity"],
        "confidence": finding.get("confidence", "unknown"),
        "cwe_ids": finding.get("cwe_ids", []),
        "has_evidence": bool(finding.get("evidence")),
        "description_excerpt": finding.get("description", "")[:200],
    }


def normalise_to_baseline_schema(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalise a Wairz scanner finding to the same schema as MobSF baselines.

    Produces output matching the ``mobsf_findings`` entries in the baseline
    JSON files (``diva_baseline.json``, etc.), making direct schema-level
    comparison possible.

    MobSF baseline schema fields:
        issue_title, severity, category, wairz_check_id, mobsf_rule,
        cwe_ids, description, evidence_pattern
    """
    # Map Wairz check IDs to MobSF rule names for cross-reference
    _CHECK_TO_MOBSF_RULE: dict[str, str] = {
        "MANIFEST-001": "android_debuggable",
        "MANIFEST-002": "android_allowbackup",
        "MANIFEST-003": "android_cleartext",
        "MANIFEST-004": "android_testonly",
        "MANIFEST-005": "android_minsdk",
        "MANIFEST-006": "android_exported",
        "MANIFEST-007": "android_permission_custom",
        "MANIFEST-008": "android_task_affinity",
        "MANIFEST-009": "android_task_hijacking",
        "MANIFEST-010": "android_browsable",
        "MANIFEST-011": "android_nsc",
        "MANIFEST-012": "android_task_reparenting",
        "MANIFEST-013": "android_intent_scheme",
        "MANIFEST-014": "android_grant_uri",
        "MANIFEST-015": "android_signing",
        "MANIFEST-016": "android_permissions",
        "MANIFEST-017": "android_permission_typo",
        "MANIFEST-018": "android_shared_uid",
    }

    check_id = finding["check_id"]
    return {
        "issue_title": finding["title"],
        "severity": finding["severity"],
        "category": "manifest",
        "wairz_check_id": check_id,
        "mobsf_rule": _CHECK_TO_MOBSF_RULE.get(check_id, f"wairz_{check_id.lower().replace('-', '_')}"),
        "cwe_ids": finding.get("cwe_ids", []),
        "description": finding.get("description", ""),
        "evidence_pattern": finding.get("evidence", ""),
        "confidence": finding.get("confidence", "unknown"),
    }


def export_scan_result(spec: TestAPKSpec, result: dict[str, Any]) -> dict[str, Any]:
    """Export a full scan result as a fixture-ready JSON structure.

    The output includes findings in two formats:
      - ``findings``: Wairz-native normalised format (for internal comparison)
      - ``mobsf_findings``: MobSF baseline-compatible format (same schema as
        the ``mobsf_findings`` entries in ``*_baseline.json`` files), enabling
        direct field-by-field comparison with the MobSF baseline
    """
    normalised_findings = [normalise_finding(f) for f in result["findings"]]
    baseline_schema_findings = [
        normalise_to_baseline_schema(f) for f in result["findings"]
    ]

    # Group by check_id
    by_check: dict[str, list[dict]] = {}
    for f in normalised_findings:
        by_check.setdefault(f["check_id"], []).append(f)

    # Group baseline-schema findings by check_id for side-by-side comparison
    baseline_by_check: dict[str, list[dict]] = {}
    for f in baseline_schema_findings:
        baseline_by_check.setdefault(f["wairz_check_id"], []).append(f)

    return {
        "_meta": {
            "apk_name": spec.name,
            "package": spec.package,
            "min_sdk": int(spec.min_sdk),
            "target_sdk": int(spec.target_sdk),
            "scanner": "wairz-androguard-manifest",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": result.get("elapsed_ms"),
            "parse_ms": result.get("parse_ms"),
            "checks_ms": result.get("checks_ms"),
        },
        "findings": normalised_findings,
        "mobsf_findings": baseline_schema_findings,
        "findings_by_check": by_check,
        "mobsf_findings_by_check": baseline_by_check,
        "summary": result.get("summary", {}),
        "confidence_summary": result.get("confidence_summary", {}),
        "total_findings": result.get("total_findings", len(normalised_findings)),
        "severity_bumped": result.get("severity_bumped", False),
        "severity_reduced": result.get("severity_reduced", False),
        "suppressed_findings": result.get("suppressed_findings", []),
        "suppressed_count": result.get("suppressed_count", 0),
    }


# ============================================================================
# Comparison logic
# ============================================================================


def compare_with_baseline(
    spec: TestAPKSpec,
    scan_export: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """Compare Wairz scan output against a MobSF baseline fixture.

    Uses the ``mobsf_findings_by_check`` from the scan export (which has the
    same schema as the baseline's ``mobsf_findings``) for direct field-level
    comparison.  Falls back to ``findings_by_check`` if the baseline schema
    findings are not available.

    Returns a comparison report with matched, missing, and extra findings.
    """
    # Build lookup from baseline
    baseline_by_check: dict[str, list[dict]] = {}
    for bf in baseline.get("mobsf_findings", []):
        cid = bf["wairz_check_id"]
        baseline_by_check.setdefault(cid, []).append(bf)

    # Prefer mobsf_findings_by_check (same schema) for direct comparison
    scan_by_check = scan_export.get("mobsf_findings_by_check") or scan_export.get("findings_by_check", {})

    # Classify
    matched: list[dict] = []
    missing_from_scan: list[dict] = []
    extra_in_scan: list[dict] = []

    # Check each baseline finding
    for cid, baseline_findings in baseline_by_check.items():
        scan_findings = scan_by_check.get(cid, [])
        if scan_findings:
            for bf in baseline_findings:
                # Resolve scan finding title (works with both schemas)
                sf_title = scan_findings[0].get("issue_title") or scan_findings[0].get("title", "")
                sf_severity = scan_findings[0]["severity"]

                severity_match = any(
                    sf["severity"] == bf["severity"] for sf in scan_findings
                )
                # CWE overlap check
                baseline_cwes = set(bf.get("cwe_ids", []))
                scan_cwes = set(scan_findings[0].get("cwe_ids", []))
                cwe_overlap = bool(baseline_cwes & scan_cwes) if baseline_cwes else True

                matched.append({
                    "check_id": cid,
                    "baseline_title": bf["issue_title"],
                    "baseline_severity": bf["severity"],
                    "scan_title": sf_title,
                    "scan_severity": sf_severity,
                    "severity_match": severity_match,
                    "cwe_overlap": cwe_overlap,
                    "baseline_cwe_ids": sorted(baseline_cwes),
                    "scan_cwe_ids": sorted(scan_cwes),
                    "status": "matched" if severity_match else "severity_mismatch",
                })
        else:
            for bf in baseline_findings:
                missing_from_scan.append({
                    "check_id": cid,
                    "baseline_title": bf["issue_title"],
                    "baseline_severity": bf["severity"],
                    "baseline_cwe_ids": bf.get("cwe_ids", []),
                    "status": "missing",
                })

    # Find extra findings not in baseline
    baseline_check_ids = set(baseline_by_check.keys())
    for cid, scan_findings in scan_by_check.items():
        if cid not in baseline_check_ids:
            for sf in scan_findings:
                sf_title = sf.get("issue_title") or sf.get("title", "")
                extra_in_scan.append({
                    "check_id": cid,
                    "scan_title": sf_title,
                    "scan_severity": sf["severity"],
                    "scan_cwe_ids": sf.get("cwe_ids", []),
                    "status": "extra",
                })

    # Validate expected_absent
    false_positives: list[dict] = []
    for absent in baseline.get("expected_absent", []):
        cid = absent["wairz_check_id"]
        if cid in scan_by_check:
            false_positives.append({
                "check_id": cid,
                "reason_should_be_absent": absent["reason"],
                "scan_severity": scan_by_check[cid][0]["severity"],
                "status": "false_positive",
            })

    # Compute metrics
    total_baseline = sum(len(v) for v in baseline_by_check.values())
    total_scan = scan_export.get("total_findings", 0)
    matched_count = len([m for m in matched if m["status"] == "matched"])
    severity_mismatch_count = len(
        [m for m in matched if m["status"] == "severity_mismatch"]
    )

    detection_rate = matched_count / total_baseline if total_baseline > 0 else 0.0
    fp_tolerance = baseline.get("summary", {}).get("false_positive_tolerance", 2)
    fp_count = len(false_positives) + len(extra_in_scan)
    fp_rate = fp_count / total_scan if total_scan > 0 else 0.0

    return {
        "apk_name": spec.name,
        "package": spec.package,
        "baseline_total": total_baseline,
        "scan_total": total_scan,
        "matched": matched,
        "matched_count": matched_count,
        "severity_mismatches": severity_mismatch_count,
        "missing_from_scan": missing_from_scan,
        "extra_in_scan": extra_in_scan,
        "false_positives": false_positives,
        "metrics": {
            "detection_rate": round(detection_rate, 3),
            "false_positive_count": fp_count,
            "false_positive_rate": round(fp_rate, 3),
            "fp_tolerance": fp_tolerance,
            "fp_within_tolerance": fp_count <= fp_tolerance,
            "severity_match_rate": round(
                matched_count / (matched_count + severity_mismatch_count), 3
            )
            if (matched_count + severity_mismatch_count) > 0
            else 1.0,
        },
        "verdict": (
            "PASS"
            if (
                len(missing_from_scan) == 0
                and fp_count <= fp_tolerance
                and fp_rate < 0.20
            )
            else "FAIL"
        ),
    }


# ============================================================================
# Main
# ============================================================================


def main() -> None:
    update_mode = "--update" in sys.argv

    output_dir = _THIS_DIR
    comparison_results: list[dict[str, Any]] = []

    print("=" * 70)
    print("MobSF Manifest Baseline Extraction Utility")
    print("=" * 70)

    all_pass = True

    for spec in ALL_SPECS:
        print(f"\n--- {spec.name} ({spec.package}) ---")

        # 1. Run the Wairz scanner
        print(f"  Running manifest scan...")
        result = run_scan(spec)
        scan_export = export_scan_result(spec, result)
        print(
            f"  Found {scan_export['total_findings']} findings "
            f"in {result.get('elapsed_ms', '?')}ms"
        )

        # 2. Write scan output
        output_path = output_dir / spec.output_file
        if update_mode or not output_path.exists():
            with open(output_path, "w") as f:
                json.dump(scan_export, f, indent=2, default=str)
            print(f"  Wrote {output_path.name}")
        else:
            print(f"  {output_path.name} already exists (use --update to overwrite)")

        # 3. Load MobSF baseline and compare
        baseline_path = output_dir / spec.baseline_file
        if baseline_path.exists():
            with open(baseline_path) as f:
                baseline = json.load(f)

            comparison = compare_with_baseline(spec, scan_export, baseline)
            comparison_results.append(comparison)

            # Print summary
            m = comparison["metrics"]
            print(f"  Detection rate: {m['detection_rate']*100:.1f}%")
            print(f"  FP rate: {m['false_positive_rate']*100:.1f}% "
                  f"({m['false_positive_count']} extra findings, "
                  f"tolerance={m['fp_tolerance']})")
            print(f"  Severity match rate: {m['severity_match_rate']*100:.1f}%")
            print(f"  Verdict: {comparison['verdict']}")

            if comparison["missing_from_scan"]:
                print(f"  MISSING from scan:")
                for miss in comparison["missing_from_scan"]:
                    print(f"    - {miss['check_id']}: {miss['baseline_title']}")

            if comparison["false_positives"]:
                print(f"  FALSE POSITIVES:")
                for fp in comparison["false_positives"]:
                    print(f"    - {fp['check_id']}: {fp['reason_should_be_absent']}")

            if comparison["verdict"] == "FAIL":
                all_pass = False
        else:
            print(f"  WARNING: Baseline {baseline_path.name} not found, skipping comparison")

    # 4. Write comparison report
    report = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "extract_mobsf_baselines.py",
            "description": "Side-by-side comparison of Wairz manifest scanner vs MobSF baselines",
        },
        "results": comparison_results,
        "overall_verdict": "PASS" if all_pass else "FAIL",
    }

    report_path = output_dir / "comparison_report.json"
    if update_mode or not report_path.exists():
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nWrote comparison report: {report_path.name}")

    print(f"\nOverall verdict: {'PASS' if all_pass else 'FAIL'}")
    print("=" * 70)

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
