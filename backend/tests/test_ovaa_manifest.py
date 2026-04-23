"""Tests for manifest security scanning against the OVAA (Oversecured Vulnerable Android App).

OVAA is a purposely vulnerable Android application created by Oversecured
for testing mobile security scanners.  Its manifest contains numerous
security issues that a competent scanner must detect.

This test suite validates that our manifest scanner produces findings
matching the MobSF baseline for OVAA's AndroidManifest.xml.

Reference: https://github.com/nickcano/Oversecured-Vulnerable-Android-App
Known OVAA manifest security issues (MobSF baseline):
  - allowBackup enabled
  - Multiple exported activities without permission protection
  - Custom deep link scheme (oversecured://) without verification
  - Browsable HTTP deep links without autoVerify
  - Exported content provider without permission
  - Low minSdkVersion
  - Exported broadcast receivers
  - Multiple activities with singleTask launchMode (StrandHogg v2)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from app.services.androguard_service import AndroguardService, ManifestFinding

# ---------------------------------------------------------------------------
# OVAA AndroidManifest.xml (reconstructed from public source)
# ---------------------------------------------------------------------------

_NS = "http://schemas.android.com/apk/res/android"

# The OVAA manifest declares the following:
#  - package: oversecured.ovaa
#  - minSdkVersion: 23   (Android 6.0 Marshmallow)
#  - targetSdkVersion: 29
#  - android:allowBackup="true"
#  - android:usesCleartextTraffic="true"
#  - NO android:debuggable (release build)
#  - NO android:testOnly
#  - Main activity: oversecured.ovaa.LoginActivity (launcher)
#  - Multiple exported activities with browsable deep links
#  - Exported content provider without permissions
#  - Custom URL scheme "oversecured://"
#  - Activities with singleTask launchMode

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

        <!-- Main launcher activity -->
        <activity android:name="oversecured.ovaa.LoginActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Deep link activity - handles oversecured:// scheme -->
        <activity android:name="oversecured.ovaa.DeeplinkActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="oversecured" android:host="ovaa" />
            </intent-filter>
        </activity>

        <!-- WebView activity - handles http links without autoVerify -->
        <activity android:name="oversecured.ovaa.WebViewActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="oversecured.com" />
            </intent-filter>
        </activity>

        <!-- Exported activities without permission protection -->
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

        <!-- Activity with singleTask launchMode (StrandHogg v2 risk) -->
        <activity android:name="oversecured.ovaa.activities.TheftActivity"
                  android:launchMode="singleTask"
                  android:exported="true" />

        <!-- Non-exported internal activity (should NOT be flagged) -->
        <activity android:name="oversecured.ovaa.activities.InternalActivity"
                  android:exported="false" />

        <!-- Exported content provider without permission -->
        <provider
            android:name="oversecured.ovaa.providers.TheftOverContentProvider"
            android:authorities="oversecured.ovaa.theftover"
            android:exported="true" />

        <!-- Another exported content provider without permission -->
        <provider
            android:name="oversecured.ovaa.providers.InsecureProvider"
            android:authorities="oversecured.ovaa.insecure"
            android:exported="true" />

        <!-- Exported broadcast receiver -->
        <receiver android:name="oversecured.ovaa.receivers.InsecureReceiver"
                  android:exported="true">
            <intent-filter>
                <action android:name="oversecured.ovaa.INSECURE_ACTION" />
            </intent-filter>
        </receiver>

        <!-- Non-exported service (should NOT be flagged) -->
        <service android:name="oversecured.ovaa.services.InternalService"
                 android:exported="false" />

    </application>
</manifest>
"""


def _build_ovaa_manifest_tree() -> ET.Element:
    """Parse the OVAA manifest XML into an Element tree."""
    return ET.fromstring(OVAA_MANIFEST_XML)


def _make_ovaa_apk_mock() -> MagicMock:
    """Build a mock Androguard APK object mimicking OVAA.

    Replicates the APK interface methods used by the manifest scanner
    so that all 11 check methods see a realistic OVAA manifest.
    """
    mock = MagicMock()
    manifest = _build_ovaa_manifest_tree()

    # Package name
    mock.get_package.return_value = "oversecured.ovaa"

    # SDK versions
    mock.get_min_sdk_version.return_value = "23"
    mock.get_target_sdk_version.return_value = "29"

    # Main activity (launcher)
    mock.get_main_activity.return_value = "oversecured.ovaa.LoginActivity"

    # get_android_manifest_xml returns the parsed ET tree
    mock.get_android_manifest_xml.return_value = manifest

    # get_attribute_value for application-level attributes
    def _get_attribute_value(tag: str, attr: str) -> str | None:
        ns_uri = f"{{{_NS}}}"
        if tag == "application":
            app_elem = manifest.find(".//application")
            if app_elem is None:
                return None
            # Try both namespaced and plain
            val = app_elem.get(f"{ns_uri}{attr}") or app_elem.get(attr)
            return val
        return None

    mock.get_attribute_value.side_effect = _get_attribute_value

    return mock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOVAAManifestFindings:
    """Validate that the manifest scanner produces correct findings for OVAA."""

    @pytest.fixture
    def service(self) -> AndroguardService:
        return AndroguardService()

    @pytest.fixture
    def ovaa_mock(self) -> MagicMock:
        return _make_ovaa_apk_mock()

    @pytest.fixture
    def findings(self, service: AndroguardService, ovaa_mock: MagicMock, monkeypatch) -> list[dict]:
        """Run all manifest checks against the OVAA mock and return findings."""
        # Monkeypatch APK constructor to return our mock
        import app.services.androguard_service as ag_mod

        def _fake_apk_init(path):
            return ovaa_mock

        monkeypatch.setattr("androguard.core.apk.APK", _fake_apk_init)

        # Create a dummy file for the file existence check
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04fake")
            tmp_path = f.name

        try:
            result = service.scan_manifest_security(tmp_path)
        finally:
            os.unlink(tmp_path)

        assert result["package"] == "oversecured.ovaa"
        return result["findings"]

    @pytest.fixture
    def finding_by_id(self, findings: list[dict]) -> dict[str, list[dict]]:
        """Group findings by check_id for easy lookup."""
        grouped: dict[str, list[dict]] = {}
        for f in findings:
            grouped.setdefault(f["check_id"], []).append(f)
        return grouped

    # ---------------------------------------------------------------
    # MANIFEST-001: Debuggable — OVAA is NOT debuggable in release
    # ---------------------------------------------------------------
    def test_no_debuggable_finding(self, finding_by_id):
        """OVAA release build is not debuggable — no MANIFEST-001 expected."""
        assert "MANIFEST-001" not in finding_by_id

    # ---------------------------------------------------------------
    # MANIFEST-002: allowBackup=true
    # ---------------------------------------------------------------
    def test_allow_backup_detected(self, finding_by_id):
        """OVAA has android:allowBackup=true — must trigger MANIFEST-002."""
        assert "MANIFEST-002" in finding_by_id
        f = finding_by_id["MANIFEST-002"][0]
        assert f["severity"] == "medium"
        assert "CWE-921" in f["cwe_ids"]
        assert "allowBackup" in f["evidence"]
        assert f["confidence"] == "high"  # explicitly set

    # ---------------------------------------------------------------
    # MANIFEST-003: usesCleartextTraffic=true
    # ---------------------------------------------------------------
    def test_cleartext_traffic_detected(self, finding_by_id):
        """OVAA has android:usesCleartextTraffic=true — must trigger MANIFEST-003."""
        assert "MANIFEST-003" in finding_by_id
        f = finding_by_id["MANIFEST-003"][0]
        assert f["severity"] == "high"
        assert "CWE-319" in f["cwe_ids"]
        assert "usesCleartextTraffic" in f["evidence"]
        assert f["confidence"] == "high"

    # ---------------------------------------------------------------
    # MANIFEST-004: testOnly — OVAA is NOT test-only
    # ---------------------------------------------------------------
    def test_no_test_only_finding(self, finding_by_id):
        """OVAA is not marked testOnly — no MANIFEST-004 expected."""
        assert "MANIFEST-004" not in finding_by_id

    # ---------------------------------------------------------------
    # MANIFEST-005: minSdkVersion=23 (below 24 threshold)
    # ---------------------------------------------------------------
    def test_min_sdk_outdated(self, finding_by_id):
        """OVAA minSdk=23 is below the secure threshold of 24 — triggers MANIFEST-005."""
        assert "MANIFEST-005" in finding_by_id
        f = finding_by_id["MANIFEST-005"][0]
        assert f["severity"] == "low"  # 23 >= 19 but < 24
        assert "CWE-1104" in f["cwe_ids"]
        assert "23" in f["evidence"]

    # ---------------------------------------------------------------
    # MANIFEST-006: Exported components without permission
    # ---------------------------------------------------------------
    def test_exported_components_detected(self, finding_by_id):
        """OVAA has many exported components without permission — must trigger MANIFEST-006.

        Expected unprotected exported components (main launcher excluded):
        - DeeplinkActivity (exported=true, no permission)
        - WebViewActivity (exported=true, no permission)
        - EntropyActivity (exported=true, no permission)
        - InsecureSharedPrefsActivity (exported=true, no permission)
        - InsecureStorageActivity (exported=true, no permission)
        - SQLInjectionActivity (exported=true, no permission)
        - InsecureLogActivity (exported=true, no permission)
        - TheftActivity (exported=true, no permission)
        - TheftOverContentProvider (exported=true, no permission)
        - InsecureProvider (exported=true, no permission)
        - InsecureReceiver (exported=true, no permission)
        = 11 components → severity should be 'high' (≥5)
        """
        assert "MANIFEST-006" in finding_by_id
        f = finding_by_id["MANIFEST-006"][0]
        assert f["severity"] == "high"  # ≥5 unprotected exported components
        assert "CWE-926" in f["cwe_ids"]
        # Verify key components appear in evidence
        assert "DeeplinkActivity" in f["evidence"]
        assert "TheftOverContentProvider" in f["evidence"]
        assert "InsecureReceiver" in f["evidence"]
        assert "InsecureProvider" in f["evidence"]
        # InternalActivity and InternalService should NOT appear
        assert "InternalActivity" not in f["evidence"]
        assert "InternalService" not in f["evidence"]
        # LoginActivity (main launcher) should NOT appear
        assert "LoginActivity" not in f["evidence"]

    def test_exported_component_count(self, finding_by_id):
        """Verify the correct number of unprotected exported components."""
        f = finding_by_id["MANIFEST-006"][0]
        # Count "exported component(s)" from evidence
        assert "11 exported component" in f["evidence"]

    def test_exported_components_all_explicit(self, finding_by_id):
        """All OVAA components are explicitly exported — confidence should be 'high'."""
        f = finding_by_id["MANIFEST-006"][0]
        assert f["confidence"] == "high"

    # ---------------------------------------------------------------
    # MANIFEST-007: Custom permissions — OVAA declares none
    # ---------------------------------------------------------------
    def test_no_custom_permission_finding(self, finding_by_id):
        """OVAA does not declare custom permissions — no MANIFEST-007 expected."""
        assert "MANIFEST-007" not in finding_by_id

    # ---------------------------------------------------------------
    # MANIFEST-008: StrandHogg v1 — OVAA activities don't have
    # non-default taskAffinity, so no v1 finding expected
    # ---------------------------------------------------------------
    def test_no_strandhogg_v1(self, finding_by_id):
        """OVAA activities use default taskAffinity — no MANIFEST-008 expected."""
        assert "MANIFEST-008" not in finding_by_id

    # ---------------------------------------------------------------
    # MANIFEST-009: StrandHogg v2 — TheftActivity has singleTask
    # launchMode and is exported, minSdk=23 < 29
    # ---------------------------------------------------------------
    def test_strandhogg_v2_detected(self, finding_by_id):
        """OVAA TheftActivity has singleTask + exported + minSdk<29 — triggers MANIFEST-009."""
        assert "MANIFEST-009" in finding_by_id
        f = finding_by_id["MANIFEST-009"][0]
        assert f["severity"] == "high"  # minSdk=23 < 29
        assert "CWE-1021" in f["cwe_ids"]
        assert "TheftActivity" in f["evidence"]
        assert "singleTask" in f["evidence"]
        assert f["confidence"] == "medium"

    # ---------------------------------------------------------------
    # MANIFEST-010: Deep links — OVAA has both custom scheme and
    # http/https without autoVerify
    # ---------------------------------------------------------------
    def test_custom_scheme_deep_link_detected(self, finding_by_id):
        """OVAA uses oversecured:// custom scheme — triggers MANIFEST-010 custom scheme finding."""
        assert "MANIFEST-010" in finding_by_id
        # Find the custom-scheme finding
        custom_findings = [
            f for f in finding_by_id["MANIFEST-010"]
            if "custom" in f["title"].lower() or "Custom" in f["title"]
        ]
        assert len(custom_findings) >= 1
        f = custom_findings[0]
        assert f["severity"] == "low"
        assert "CWE-939" in f["cwe_ids"]
        assert "oversecured" in f["evidence"]
        assert "DeeplinkActivity" in f["evidence"]

    def test_unverified_https_link_detected(self, finding_by_id):
        """OVAA WebViewActivity handles https without autoVerify — triggers MANIFEST-010."""
        # Find the unverified http/https finding
        http_findings = [
            f for f in finding_by_id["MANIFEST-010"]
            if "unverified" in f["title"].lower() or "autoVerify" in f["title"]
        ]
        assert len(http_findings) >= 1
        f = http_findings[0]
        assert f["severity"] == "medium"
        assert "CWE-939" in f["cwe_ids"]
        assert "WebViewActivity" in f["evidence"]
        assert "oversecured.com" in f["evidence"]

    # ---------------------------------------------------------------
    # MANIFEST-011: Network security config — OVAA doesn't specify one
    # ---------------------------------------------------------------
    def test_no_network_security_config_finding(self, finding_by_id):
        """OVAA has no networkSecurityConfig — no MANIFEST-011 findings expected."""
        # OVAA relies on usesCleartextTraffic=true instead of NSC
        assert "MANIFEST-011" not in finding_by_id

    # ---------------------------------------------------------------
    # Summary validation
    # ---------------------------------------------------------------
    def test_total_finding_count(self, findings):
        """OVAA should produce findings matching MobSF baseline plus any
        new checks that have landed since the baseline was written.

        Expected core findings (MobSF baseline parity):
        - MANIFEST-002: allowBackup (1)
        - MANIFEST-003: cleartext traffic (1)
        - MANIFEST-005: outdated minSdk (1)
        - MANIFEST-006: exported components (1)
        - MANIFEST-009: StrandHogg v2 (1)
        - MANIFEST-010: custom scheme (1) + unverified https (1)
        = 7 baseline findings

        Additional findings from checks added post-baseline (e.g.
        MANIFEST-013 implicit intent hijacking) are expected and fine.
        The assertion enforces the baseline as a lower bound.
        """
        assert len(findings) >= 7, (
            f"Expected ≥7 findings (MobSF baseline parity), "
            f"got {len(findings)}: {[f['check_id'] for f in findings]}"
        )

    def test_severity_distribution(self, findings):
        """Verify severity distribution matches MobSF baseline expectations."""
        severities = [f["severity"] for f in findings]
        # High: cleartext (MANIFEST-003), exported components (MANIFEST-006), StrandHogg v2 (MANIFEST-009)
        assert severities.count("high") >= 3
        # Medium: allowBackup (MANIFEST-002), unverified https links (MANIFEST-010)
        assert severities.count("medium") >= 1
        # Low: minSdk (MANIFEST-005), custom scheme (MANIFEST-010)
        assert severities.count("low") >= 1

    def test_no_false_positives(self, finding_by_id):
        """Verify no findings are triggered for attributes OVAA does NOT have."""
        # OVAA is not debuggable
        assert "MANIFEST-001" not in finding_by_id
        # OVAA is not test-only
        assert "MANIFEST-004" not in finding_by_id
        # OVAA has no custom permissions
        assert "MANIFEST-007" not in finding_by_id
        # OVAA has no non-default taskAffinity
        assert "MANIFEST-008" not in finding_by_id

    # ---------------------------------------------------------------
    # Performance
    # ---------------------------------------------------------------
    def test_scan_completes_under_500ms(self, service, ovaa_mock, monkeypatch):
        """Manifest scan should complete well under 500ms (target: <100ms for mocked APK)."""
        import tempfile, os, time

        monkeypatch.setattr("androguard.core.apk.APK", lambda path: ovaa_mock)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04fake")
            tmp_path = f.name

        try:
            t0 = time.monotonic()
            result = service.scan_manifest_security(tmp_path)
            elapsed = time.monotonic() - t0
        finally:
            os.unlink(tmp_path)

        assert elapsed < 0.5, f"Scan took {elapsed:.3f}s — exceeds 500ms limit"
        assert result["elapsed_ms"] < 500


class TestOVAAWithFirmwareContext:
    """Test OVAA findings with firmware context adjustments."""

    @pytest.fixture
    def service(self) -> AndroguardService:
        return AndroguardService()

    @pytest.fixture
    def ovaa_mock(self) -> MagicMock:
        return _make_ovaa_apk_mock()

    def _scan(self, service, ovaa_mock, monkeypatch, **kwargs) -> dict:
        import tempfile, os

        monkeypatch.setattr("androguard.core.apk.APK", lambda path: ovaa_mock)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04fake")
            tmp_path = f.name

        try:
            return service.scan_manifest_security(tmp_path, **kwargs)
        finally:
            os.unlink(tmp_path)

    def test_priv_app_severity_bump(self, service, ovaa_mock, monkeypatch):
        """When OVAA is in /system/priv-app/, all severities should be bumped +1."""
        result = self._scan(service, ovaa_mock, monkeypatch, is_priv_app=True)

        assert result["severity_bumped"] is True

        findings_by_id = {}
        for f in result["findings"]:
            findings_by_id.setdefault(f["check_id"], []).append(f)

        # MANIFEST-003 (cleartext) was high → critical
        assert findings_by_id["MANIFEST-003"][0]["severity"] == "critical"
        # MANIFEST-002 (allowBackup) was medium → high
        assert findings_by_id["MANIFEST-002"][0]["severity"] == "high"
        # MANIFEST-005 (minSdk) was low → medium
        assert findings_by_id["MANIFEST-005"][0]["severity"] == "medium"
        # MANIFEST-006 (exported) was high → critical
        assert findings_by_id["MANIFEST-006"][0]["severity"] == "critical"
        # MANIFEST-009 (StrandHogg v2) was high → critical
        assert findings_by_id["MANIFEST-009"][0]["severity"] == "critical"

    def test_standalone_apk_no_bump(self, service, ovaa_mock, monkeypatch):
        """Without firmware context flags, severities remain at base level."""
        result = self._scan(service, ovaa_mock, monkeypatch)

        assert result["severity_bumped"] is False
        assert result["severity_reduced"] is False

        findings_by_id = {}
        for f in result["findings"]:
            findings_by_id.setdefault(f["check_id"], []).append(f)

        # Verify base severities
        assert findings_by_id["MANIFEST-003"][0]["severity"] == "high"
        assert findings_by_id["MANIFEST-002"][0]["severity"] == "medium"
        assert findings_by_id["MANIFEST-005"][0]["severity"] == "low"

    def test_cwe_ids_present_on_all_findings(self, service, ovaa_mock, monkeypatch):
        """Every OVAA finding must have at least one CWE ID."""
        result = self._scan(service, ovaa_mock, monkeypatch)
        for f in result["findings"]:
            assert len(f["cwe_ids"]) > 0, (
                f"Finding {f['check_id']} ({f['title']}) has no CWE IDs"
            )

    def test_confidence_levels_present(self, service, ovaa_mock, monkeypatch):
        """Every OVAA finding must have a valid confidence level."""
        result = self._scan(service, ovaa_mock, monkeypatch)
        valid_levels = {"high", "medium", "low"}
        for f in result["findings"]:
            assert f["confidence"] in valid_levels, (
                f"Finding {f['check_id']} has invalid confidence: {f['confidence']}"
            )


class TestOVAAMobSFBaselineComparison:
    """Compare scanner output against known MobSF findings for OVAA.

    MobSF baseline for OVAA (key manifest-level findings):
    1. Application Data can be Backed up [allowBackup=true]          → medium
    2. Clear Text Traffic Is Enabled [usesCleartextTraffic=true]     → high
    3. App can be installed on older vulnerable Android versions      → low/info
    4. Exported Activities/Providers/Receivers without permissions    → high
    5. Browsable Activities (Deep Link abuse)                        → medium/low
    6. Task Hijacking (StrandHogg variants)                          → high
    """

    @pytest.fixture
    def service(self) -> AndroguardService:
        return AndroguardService()

    @pytest.fixture
    def ovaa_mock(self) -> MagicMock:
        return _make_ovaa_apk_mock()

    @pytest.fixture
    def result(self, service, ovaa_mock, monkeypatch) -> dict:
        import tempfile, os

        monkeypatch.setattr("androguard.core.apk.APK", lambda path: ovaa_mock)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04fake")
            tmp_path = f.name

        try:
            return service.scan_manifest_security(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_mobsf_backup_finding(self, result):
        """MobSF: 'Application Data can be Backed up' → medium severity."""
        backup = [f for f in result["findings"] if f["check_id"] == "MANIFEST-002"]
        assert len(backup) == 1
        assert backup[0]["severity"] == "medium"

    def test_mobsf_cleartext_finding(self, result):
        """MobSF: 'Clear Text Traffic Is Enabled' → high severity."""
        cleartext = [f for f in result["findings"] if f["check_id"] == "MANIFEST-003"]
        assert len(cleartext) == 1
        assert cleartext[0]["severity"] == "high"

    def test_mobsf_min_sdk_finding(self, result):
        """MobSF: 'App can be installed on older vulnerable Android versions' → low."""
        minsdk = [f for f in result["findings"] if f["check_id"] == "MANIFEST-005"]
        assert len(minsdk) == 1
        # minSdk=23 is >= 19 (not critical) but < 24 (outdated) → low
        assert minsdk[0]["severity"] == "low"

    def test_mobsf_exported_components_finding(self, result):
        """MobSF: Multiple exported components without permission → high severity."""
        exported = [f for f in result["findings"] if f["check_id"] == "MANIFEST-006"]
        assert len(exported) == 1
        assert exported[0]["severity"] == "high"

    def test_mobsf_browsable_activities_finding(self, result):
        """MobSF: Browsable activities / deep link abuse → medium + low."""
        links = [f for f in result["findings"] if f["check_id"] == "MANIFEST-010"]
        assert len(links) >= 1
        severities = {f["severity"] for f in links}
        # Custom scheme → low, unverified https → medium
        assert "low" in severities or "medium" in severities

    def test_mobsf_task_hijacking_finding(self, result):
        """MobSF: Task hijacking (StrandHogg 2.0) → high severity."""
        strandhogg = [f for f in result["findings"] if f["check_id"] == "MANIFEST-009"]
        assert len(strandhogg) == 1
        assert strandhogg[0]["severity"] == "high"

    def test_false_positive_rate_under_20pct(self, result):
        """Verify false positive rate is under 20%.

        For OVAA, all findings should be true positives since it's an
        intentionally vulnerable app. FP rate = 0%.
        """
        total = result["total_findings"]
        # All findings for OVAA are legitimate — 0% false positive rate
        # Map each check_id to whether it's expected
        expected_ids = {
            "MANIFEST-002",  # allowBackup=true
            "MANIFEST-003",  # usesCleartextTraffic=true
            "MANIFEST-005",  # minSdk=23
            "MANIFEST-006",  # exported components
            "MANIFEST-009",  # StrandHogg v2
            "MANIFEST-010",  # deep links
        }
        actual_ids = {f["check_id"] for f in result["findings"]}
        unexpected = actual_ids - expected_ids
        fp_rate = len(unexpected) / total if total > 0 else 0
        assert fp_rate < 0.20, (
            f"False positive rate {fp_rate:.0%} exceeds 20% threshold. "
            f"Unexpected findings: {unexpected}"
        )

    def test_result_metadata(self, result):
        """Verify result metadata is complete and correct."""
        assert result["package"] == "oversecured.ovaa"
        assert result["total_findings"] > 0
        assert "summary" in result
        assert "confidence_summary" in result
        assert result["elapsed_ms"] >= 0
        assert result["parse_ms"] >= 0
        assert result["checks_ms"] >= 0
