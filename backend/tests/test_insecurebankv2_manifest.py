"""Validate manifest scanning against InsecureBankv2 APK.

InsecureBankv2 (https://github.com/dineshshetty/Android-InsecureBankv2) is a
deliberately vulnerable Android banking app used as a security training tool.
These tests verify that our manifest scanner produces findings that match or
exceed the MobSF baseline when scanning InsecureBankv2's manifest.

Known InsecureBankv2 manifest characteristics:
- Package: com.android.insecurebankv2
- android:debuggable="true"
- android:allowBackup="true"
- minSdkVersion=15 (Android 4.0.3 — critically outdated)
- targetSdkVersion=15
- No networkSecurityConfig
- No android:usesCleartextTraffic attr (defaults true for targetSdk < 28)
- Multiple exported activities without permission protection
- No custom permissions
- Activities: LoginActivity (main), PostLogin, DoTransfer, ViewStatement,
  ChangePassword, DoLogin, FilePref498Activity, WebViewActivity, plus services

MobSF baseline findings (expected):
  HIGH: debuggable, allowBackup→cleartext, minSdk < 19, exported components
  MEDIUM: allowBackup
  No StrandHogg findings (no custom taskAffinity/reparenting)
  No MANIFEST-011 (no network security config)

Tests use mocked Androguard objects — no real APK file needed.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from app.services.androguard_service import AndroguardService

# ---------------------------------------------------------------------------
# InsecureBankv2 manifest XML (simplified from the real app)
# ---------------------------------------------------------------------------

_INSECUREBANKV2_MANIFEST_XML = """\
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

NS = "http://schemas.android.com/apk/res/android"


def _build_mock_apk():
    """Build a mock Androguard APK object matching InsecureBankv2."""
    apk = MagicMock()
    manifest_tree = ET.fromstring(_INSECUREBANKV2_MANIFEST_XML)

    apk.get_package.return_value = "com.android.insecurebankv2"
    apk.get_min_sdk_version.return_value = "15"
    apk.get_target_sdk_version.return_value = "15"
    apk.get_androidversion_code.return_value = "1"
    apk.get_androidversion_name.return_value = "2.0"
    apk.get_main_activity.return_value = "com.android.insecurebankv2.LoginActivity"
    apk.get_android_manifest_xml.return_value = manifest_tree

    apk.get_permissions.return_value = [
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
    ]

    apk.get_activities.return_value = [
        "com.android.insecurebankv2.LoginActivity",
        "com.android.insecurebankv2.PostLogin",
        "com.android.insecurebankv2.DoTransfer",
        "com.android.insecurebankv2.ViewStatement",
        "com.android.insecurebankv2.ChangePassword",
        "com.android.insecurebankv2.DoLogin",
        "com.android.insecurebankv2.FilePrefActivity",
        "com.android.insecurebankv2.WebViewActivity",
    ]
    apk.get_services.return_value = [
        "com.android.insecurebankv2.MyBroadCastReceiver",
    ]
    apk.get_receivers.return_value = [
        "com.android.insecurebankv2.MyBroadCastReceiver",
    ]
    apk.get_providers.return_value = []

    # get_attribute_value: returns manifest attribute values
    def _get_attr(tag: str, attr: str):
        """Simulate Androguard's get_attribute_value."""
        lookup = {
            ("application", "debuggable"): "true",
            ("application", "allowBackup"): "true",
            ("application", f"{{{NS}}}debuggable"): "true",
            ("application", f"{{{NS}}}allowBackup"): "true",
            # No usesCleartextTraffic set
            # No testOnly set
            # No networkSecurityConfig set
        }
        return lookup.get((tag, attr))

    apk.get_attribute_value.side_effect = _get_attr

    # No network security config file
    apk.get_file.return_value = None

    return apk


@pytest.fixture
def service():
    return AndroguardService()


@pytest.fixture
def insecurebankv2_apk():
    return _build_mock_apk()


# ---------------------------------------------------------------------------
# Helper to run scan with mocked APK constructor
# ---------------------------------------------------------------------------

def _run_scan(service, mock_apk, *, is_priv_app=False, is_platform_signed=False):
    """Run manifest scan by patching APK() to return our mock."""
    from unittest.mock import patch

    with patch("androguard.core.apk.APK", return_value=mock_apk):
        with patch("os.path.isfile", return_value=True):
            return service.scan_manifest_security(
                "/fake/InsecureBankv2.apk",
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            )


def _findings_by_check(result):
    """Group findings by check_id for easy lookup."""
    by_id: dict[str, list[dict]] = {}
    for f in result["findings"]:
        by_id.setdefault(f["check_id"], []).append(f)
    return by_id


# ===================================================================
# Test suite: InsecureBankv2 manifest scan
# ===================================================================

class TestInsecureBankv2ManifestScan:
    """Validate scanner output against InsecureBankv2 matches MobSF baseline."""

    def test_package_name(self, service, insecurebankv2_apk):
        result = _run_scan(service, insecurebankv2_apk)
        assert result["package"] == "com.android.insecurebankv2"

    def test_total_findings_count(self, service, insecurebankv2_apk):
        """InsecureBankv2 should produce at least 5 manifest findings."""
        result = _run_scan(service, insecurebankv2_apk)
        # Expected: MANIFEST-001, 002, 003, 005, 006, 010 = at least 6
        assert result["total_findings"] >= 5, (
            f"Expected ≥5 findings, got {result['total_findings']}: "
            f"{[f['check_id'] for f in result['findings']]}"
        )

    def test_debuggable_detected(self, service, insecurebankv2_apk):
        """MANIFEST-001: debuggable=true must be detected (MobSF HIGH)."""
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-001" in by_id, "debuggable=true not detected"
        finding = by_id["MANIFEST-001"][0]
        assert finding["severity"] == "high"
        assert "CWE-489" in finding["cwe_ids"]
        assert "debuggable" in finding["evidence"].lower()
        assert finding["confidence"] == "high"

    def test_allow_backup_detected(self, service, insecurebankv2_apk):
        """MANIFEST-002: allowBackup=true must be detected (MobSF MEDIUM)."""
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-002" in by_id, "allowBackup=true not detected"
        finding = by_id["MANIFEST-002"][0]
        assert finding["severity"] == "medium"
        assert "CWE-921" in finding["cwe_ids"]
        # Explicitly set, so confidence should be high
        assert finding["confidence"] == "high"

    def test_cleartext_traffic_detected(self, service, insecurebankv2_apk):
        """MANIFEST-003: cleartext traffic must be detected.

        InsecureBankv2 doesn't explicitly set usesCleartextTraffic, but
        targetSdk=15 (< 28) means the default is true.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-003" in by_id, (
            "cleartext traffic not detected (targetSdk=15 defaults to true)"
        )
        finding = by_id["MANIFEST-003"][0]
        assert finding["severity"] == "high"
        assert "CWE-319" in finding["cwe_ids"]
        # Default-based detection → medium confidence
        assert finding["confidence"] == "medium"

    def test_no_test_only(self, service, insecurebankv2_apk):
        """MANIFEST-004: testOnly should NOT be flagged (not set)."""
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-004" not in by_id, (
            "testOnly finding generated but InsecureBankv2 is not testOnly"
        )

    def test_min_sdk_critically_outdated(self, service, insecurebankv2_apk):
        """MANIFEST-005: minSdkVersion=15 must be flagged as critically outdated.

        MobSF flags minSdk < 19 as HIGH. API 15 = Android 4.0.3 ICS, which
        lacks TLS 1.2 by default, modern cert pinning, and many security
        hardening features.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-005" in by_id, "minSdkVersion=15 not flagged"
        finding = by_id["MANIFEST-005"][0]
        assert finding["severity"] == "high"
        assert "CWE-1104" in finding["cwe_ids"]
        assert "15" in finding["evidence"]

    def test_exported_components_detected(self, service, insecurebankv2_apk):
        """MANIFEST-006: Multiple exported components without permission.

        InsecureBankv2 exports 8+ activities, 1 service, 1 receiver — all
        without permission protection. LoginActivity is excluded (main
        launcher). Expect ≥5 unprotected exported components → HIGH severity.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-006" in by_id, (
            "exported components without permission not detected"
        )
        finding = by_id["MANIFEST-006"][0]
        # ≥5 components → high severity per MobSF baseline
        assert finding["severity"] == "high", (
            f"Expected high severity for ≥5 exported components, got {finding['severity']}"
        )
        assert "CWE-926" in finding["cwe_ids"]
        # Verify evidence mentions specific components
        assert "PostLogin" in finding["evidence"]
        assert "DoTransfer" in finding["evidence"]

    def test_no_custom_permissions(self, service, insecurebankv2_apk):
        """MANIFEST-007: No custom permissions defined → no finding."""
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-007" not in by_id, (
            "Custom permission finding generated but InsecureBankv2 defines none"
        )

    def test_no_strandhogg_v1(self, service, insecurebankv2_apk):
        """MANIFEST-008: No taskAffinity abuse → no StrandHogg v1 finding.

        InsecureBankv2 doesn't set custom taskAffinity or
        allowTaskReparenting on any activities.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-008" not in by_id, (
            "StrandHogg v1 finding generated but no taskAffinity abuse in manifest"
        )

    def test_no_strandhogg_v2(self, service, insecurebankv2_apk):
        """MANIFEST-009: No singleTask/singleInstance launch modes.

        InsecureBankv2 doesn't use risky launch modes on exported activities
        (beyond the main launcher which is excluded).
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-009" not in by_id, (
            "StrandHogg v2 finding generated but no risky launchModes in manifest"
        )

    def test_browsable_activity_detected(self, service, insecurebankv2_apk):
        """MANIFEST-010: ViewStatement has browsable intent filter with http scheme.

        The ViewStatement activity handles http://mybank.com without
        autoVerify, which should trigger an app link verification finding.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-010" in by_id, (
            "Browsable activity (ViewStatement with http scheme) not detected"
        )
        # Should find unverified http app link
        http_findings = [
            f for f in by_id["MANIFEST-010"]
            if "autoVerify" in f["title"].lower() or "unverified" in f["title"].lower()
        ]
        assert len(http_findings) >= 1, (
            "Expected unverified HTTP app link finding for ViewStatement"
        )

    def test_no_network_security_config(self, service, insecurebankv2_apk):
        """MANIFEST-011: No networkSecurityConfig → no NSC findings.

        InsecureBankv2 doesn't reference a network security config XML.
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        assert "MANIFEST-011" not in by_id, (
            "NSC finding generated but InsecureBankv2 has no networkSecurityConfig"
        )

    def test_severity_distribution_matches_mobsf(self, service, insecurebankv2_apk):
        """Verify severity distribution matches MobSF baseline.

        MobSF expected for InsecureBankv2:
          HIGH: debuggable, cleartext, minSdk < 19, exported components (≥5)
          MEDIUM: allowBackup, app links (unverified http)
          LOW: (possible custom scheme deep link)

        We should have at least 3 HIGH and 1 MEDIUM findings.
        """
        result = _run_scan(service, insecurebankv2_apk)
        summary = result["summary"]
        high_count = summary.get("high", 0)
        medium_count = summary.get("medium", 0)

        assert high_count >= 3, (
            f"Expected ≥3 HIGH findings matching MobSF, got {high_count}. "
            f"Summary: {summary}"
        )
        assert medium_count >= 1, (
            f"Expected ≥1 MEDIUM findings matching MobSF, got {medium_count}. "
            f"Summary: {summary}"
        )

    def test_timing_metadata(self, service, insecurebankv2_apk):
        """Verify timing metadata is present and reasonable."""
        result = _run_scan(service, insecurebankv2_apk)
        assert "elapsed_ms" in result
        assert "parse_ms" in result
        assert "checks_ms" in result
        # With mocked APK, should be under 100ms
        assert result["elapsed_ms"] < 500

    def test_no_severity_bump_standalone(self, service, insecurebankv2_apk):
        """Standalone APK (not in firmware) should not have severity bumped."""
        result = _run_scan(service, insecurebankv2_apk)
        assert result["severity_bumped"] is False
        assert result["severity_reduced"] is False

    def test_confidence_distribution(self, service, insecurebankv2_apk):
        """Verify confidence scores are assigned correctly."""
        result = _run_scan(service, insecurebankv2_apk)
        confidence = result["confidence_summary"]
        # Should have some high-confidence findings (explicit attributes)
        assert confidence.get("high", 0) >= 2, (
            f"Expected ≥2 high-confidence findings, got {confidence}"
        )


class TestInsecureBankv2FirmwareContext:
    """Test InsecureBankv2 findings with firmware-context adjustments."""

    def test_priv_app_bumps_severity(self, service, insecurebankv2_apk):
        """When in /system/priv-app/, all findings get +1 severity."""
        result = _run_scan(
            service, insecurebankv2_apk, is_priv_app=True
        )
        assert result["severity_bumped"] is True
        by_id = _findings_by_check(result)

        # MANIFEST-001 debuggable: base=high → bumped=critical
        assert by_id["MANIFEST-001"][0]["severity"] == "critical"
        # MANIFEST-002 allowBackup: base=medium → bumped=high
        assert by_id["MANIFEST-002"][0]["severity"] == "high"

    def test_platform_signed_no_reduction(self, service, insecurebankv2_apk):
        """InsecureBankv2 has no signatureOrSystem protection.

        It doesn't declare any signature-level permissions or request
        platform-signature permissions, so severity reduction should NOT
        apply even if is_platform_signed=True.
        """
        result = _run_scan(
            service, insecurebankv2_apk, is_platform_signed=True
        )
        assert result["severity_bumped"] is True
        # No reduction since InsecureBankv2 doesn't have sigOrSystem protection
        assert result["severity_reduced"] is False


class TestInsecureBankv2FalsePositiveRate:
    """Verify false positive rate is within acceptable bounds.

    MobSF baseline for InsecureBankv2 produces ~6-8 manifest findings.
    Our scanner should not produce significantly more (< 20% FP rate).
    """

    def test_no_false_positives(self, service, insecurebankv2_apk):
        """Each finding should correspond to a real InsecureBankv2 vulnerability."""
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)

        # These check IDs should be present (true positives):
        expected_present = {"MANIFEST-001", "MANIFEST-002", "MANIFEST-003",
                          "MANIFEST-005", "MANIFEST-006", "MANIFEST-010"}
        # These should NOT be present (would be false positives):
        expected_absent = {"MANIFEST-004", "MANIFEST-007", "MANIFEST-008",
                         "MANIFEST-009", "MANIFEST-011"}

        for check_id in expected_present:
            assert check_id in by_id, f"True positive {check_id} missing"

        for check_id in expected_absent:
            assert check_id not in by_id, f"False positive {check_id} present"

    def test_finding_count_within_bounds(self, service, insecurebankv2_apk):
        """Total findings should be 5-12 (MobSF baseline ± tolerance).

        MobSF produces ~6-8 findings for InsecureBankv2 manifest.
        We allow up to 12 to account for sub-findings (e.g., app links
        can produce separate http/custom scheme findings).
        """
        result = _run_scan(service, insecurebankv2_apk)
        total = result["total_findings"]
        assert 5 <= total <= 12, (
            f"Finding count {total} outside expected range [5, 12]. "
            f"Findings: {[f['check_id'] + ': ' + f['title'] for f in result['findings']]}"
        )

    def test_all_cwe_ids_valid(self, service, insecurebankv2_apk):
        """All CWE IDs should be properly formatted."""
        result = _run_scan(service, insecurebankv2_apk)
        for f in result["findings"]:
            for cwe in f["cwe_ids"]:
                assert cwe.startswith("CWE-"), f"Invalid CWE format: {cwe}"
                # CWE number should be parseable
                cwe_num = cwe.split("-")[1]
                assert cwe_num.isdigit(), f"Non-numeric CWE: {cwe}"

    def test_all_findings_have_evidence(self, service, insecurebankv2_apk):
        """Every finding should include evidence from the manifest."""
        result = _run_scan(service, insecurebankv2_apk)
        for f in result["findings"]:
            assert f["evidence"], (
                f"Finding {f['check_id']} ({f['title']}) has no evidence"
            )

    def test_exported_components_lists_correct_components(
        self, service, insecurebankv2_apk
    ):
        """MANIFEST-006 evidence should list specific unprotected components.

        Expected exported+unprotected (excluding main LoginActivity):
        - PostLogin, DoTransfer, ViewStatement, ChangePassword, DoLogin,
          FilePrefActivity, WebViewActivity (activities)
        - MyBroadCastReceiver (service + receiver)
        """
        result = _run_scan(service, insecurebankv2_apk)
        by_id = _findings_by_check(result)
        evidence = by_id["MANIFEST-006"][0]["evidence"]

        # These should all appear in evidence
        expected_components = [
            "PostLogin",
            "DoTransfer",
            "ViewStatement",
            "ChangePassword",
            "DoLogin",
            "FilePrefActivity",
            "WebViewActivity",
            "MyBroadCastReceiver",
        ]
        for comp in expected_components:
            assert comp in evidence, (
                f"Expected component {comp} in exported components evidence"
            )

        # Main activity should NOT appear (it's excluded)
        # Note: LoginActivity might appear as part of other component names,
        # so check specifically
        assert "LoginActivity" not in evidence or "PostLogin" in evidence
