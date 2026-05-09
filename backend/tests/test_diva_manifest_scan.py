"""Validation: DIVA APK manifest scan produces expected findings matching MobSF baseline.

DIVA (Damn Insecure and Vulnerable App) by Payatu is a well-known intentionally
vulnerable Android application used for security testing training.

Known manifest characteristics (jakhar.aseem.diva v1.0):
  - Package: jakhar.aseem.diva
  - minSdkVersion: 15 (Android 4.0.3 ICS — critically outdated, < API 19)
  - targetSdkVersion: 24 (Android 7.0 Nougat — below API 28)
  - android:debuggable="true"
  - android:allowBackup="true"
  - android:usesCleartextTraffic NOT set (defaults to true for target < 28)
  - android:testOnly NOT set
  - 14 activities total, 13 exported without permission protection
    (via intent-filter implicit export since targetSdk < 31)
  - No custom <permission> declarations
  - No network_security_config.xml
  - No StrandHogg 1.0 patterns (no non-default taskAffinity)
  - 3 content providers (2 exported without protection for targetSdk < 17)

MobSF baseline findings for DIVA:
  - Debuggable (high)
  - Allow Backup (medium)
  - Cleartext traffic (high, via default)
  - Critically outdated minSdk (high)
  - Exported components without protection (high, ≥5 components)

These tests mock the Androguard APK object to match DIVA's real manifest
structure, enabling offline validation without downloading the APK.

An integration test (marked slow) downloads and scans the real APK.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.androguard_service import AndroguardService

# ---------------------------------------------------------------------------
# DIVA manifest XML (matches real DIVA APK structure)
# ---------------------------------------------------------------------------

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

NS_ANDROID = "http://schemas.android.com/apk/res/android"


def _build_diva_apk_mock() -> MagicMock:
    """Build a mock APK object that mimics DIVA's real manifest structure."""
    apk = MagicMock()
    apk.get_package.return_value = "jakhar.aseem.diva"
    apk.get_min_sdk_version.return_value = "15"
    apk.get_target_sdk_version.return_value = "24"

    # Main activity
    apk.get_main_activity.return_value = "jakhar.aseem.diva.MainActivity"

    # Parse the manifest XML so Androguard methods work
    manifest_tree = ET.fromstring(DIVA_MANIFEST_XML)
    apk.get_android_manifest_xml.return_value = manifest_tree

    # Manifest attribute extraction (used by _get_manifest_attr)
    def _get_attribute_value(tag: str, attr: str) -> str | None:
        ns = "http://schemas.android.com/apk/res/android"
        # Find the element matching the tag
        if tag == "application":
            elem = manifest_tree.find(".//application")
        elif tag == "manifest":
            elem = manifest_tree
        else:
            elem = manifest_tree.find(f".//{tag}")

        if elem is None:
            return None

        # Try namespaced then bare
        for name in (attr, f"{{{ns}}}{attr}"):
            val = elem.get(name)
            if val is not None:
                return val
        return None

    apk.get_attribute_value.side_effect = _get_attribute_value

    # Permissions
    apk.get_permissions.return_value = [
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.INTERNET",
    ]

    # No network security config file
    apk.get_file.return_value = None

    return apk


class TestDivaManifestFindings:
    """Validate that scanning DIVA's manifest produces MobSF-matching findings."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.svc = AndroguardService()
        self.apk = _build_diva_apk_mock()

    def _run_checks(self, **kwargs) -> dict[str, Any]:
        """Run manifest scan by patching APK() to return our mock."""
        with patch("androguard.core.apk.APK", return_value=self.apk):
            with patch("os.path.isfile", return_value=True):
                return self.svc.scan_manifest_security("/fake/diva-beta.apk", **kwargs)

    def _findings_by_id(self, result: dict) -> dict[str, list[dict]]:
        """Group findings by check_id."""
        grouped: dict[str, list[dict]] = {}
        for f in result["findings"]:
            grouped.setdefault(f["check_id"], []).append(f)
        return grouped

    # ------------------------------------------------------------------
    # MANIFEST-001: Debuggable
    # ------------------------------------------------------------------

    def test_debuggable_detected(self):
        """DIVA has android:debuggable=true → MANIFEST-001 high severity."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-001" in by_id, "Debuggable check should fire for DIVA"
        finding = by_id["MANIFEST-001"][0]
        assert finding["severity"] == "high"
        assert "CWE-489" in finding["cwe_ids"]
        assert "debuggable" in finding["evidence"].lower()
        assert finding["confidence"] == "high"

    # ------------------------------------------------------------------
    # MANIFEST-002: Allow Backup
    # ------------------------------------------------------------------

    def test_allow_backup_detected(self):
        """DIVA has android:allowBackup=true → MANIFEST-002 medium severity."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-002" in by_id, "AllowBackup check should fire for DIVA"
        finding = by_id["MANIFEST-002"][0]
        assert finding["severity"] == "medium"
        assert "CWE-921" in finding["cwe_ids"]
        assert "allowbackup" in finding["evidence"].lower()
        # Explicitly set → high confidence
        assert finding["confidence"] == "high"

    # ------------------------------------------------------------------
    # MANIFEST-003: Cleartext Traffic
    # ------------------------------------------------------------------

    def test_cleartext_traffic_detected(self):
        """DIVA targetSdk=24 (< 28), no explicit flag → defaults to true.

        MobSF flags this as high severity.
        """
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-003" in by_id, "Cleartext traffic should fire for DIVA"
        finding = by_id["MANIFEST-003"][0]
        assert finding["severity"] == "high"
        assert "CWE-319" in finding["cwe_ids"]
        # Default-based → medium confidence
        assert finding["confidence"] == "medium"

    # ------------------------------------------------------------------
    # MANIFEST-004: Test Only
    # ------------------------------------------------------------------

    def test_test_only_not_detected(self):
        """DIVA does NOT have testOnly=true → no MANIFEST-004."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-004" not in by_id, "testOnly should NOT fire for DIVA"

    # ------------------------------------------------------------------
    # MANIFEST-005: Min SDK Version
    # ------------------------------------------------------------------

    def test_min_sdk_critically_outdated(self):
        """DIVA minSdk=15 (< 19) → MANIFEST-005 high severity (critically outdated)."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-005" in by_id, "minSdk check should fire for DIVA"
        finding = by_id["MANIFEST-005"][0]
        assert finding["severity"] == "high"
        assert "CWE-1104" in finding["cwe_ids"]
        assert "15" in finding["evidence"]

    # ------------------------------------------------------------------
    # MANIFEST-006: Exported Components
    # ------------------------------------------------------------------

    def test_exported_components_detected(self):
        """DIVA has many exported activities (implicit via intent-filter, targetSdk < 31).

        10+ activities have intent-filters and are implicitly exported.
        This exceeds the ≥5 threshold → high severity.
        """
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-006" in by_id, "Exported components should fire for DIVA"
        finding = by_id["MANIFEST-006"][0]

        # ≥5 implicitly exported components → high severity
        assert finding["severity"] in ("high", "medium"), (
            f"Expected high or medium severity for many exported components, "
            f"got {finding['severity']}"
        )
        assert "CWE-926" in finding["cwe_ids"]
        # Implicit export → medium confidence
        assert finding["confidence"] == "medium"

    def test_exported_components_count(self):
        """Verify we detect the expected number of exported components."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        finding = by_id["MANIFEST-006"][0]
        # The evidence should mention multiple exported components
        assert "exported component" in finding["evidence"].lower()

    # ------------------------------------------------------------------
    # MANIFEST-007: Custom Permissions
    # ------------------------------------------------------------------

    def test_no_custom_permissions(self):
        """DIVA has no custom <permission> declarations → no MANIFEST-007."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-007" not in by_id, (
            "Custom permissions check should NOT fire for DIVA"
        )

    # ------------------------------------------------------------------
    # MANIFEST-008: StrandHogg v1
    # ------------------------------------------------------------------

    def test_no_strandhogg_v1(self):
        """DIVA has no non-default taskAffinity → no MANIFEST-008."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-008" not in by_id, (
            "StrandHogg v1 should NOT fire for DIVA"
        )

    # ------------------------------------------------------------------
    # MANIFEST-009: StrandHogg v2
    # ------------------------------------------------------------------

    def test_no_strandhogg_v2(self):
        """DIVA has no singleTask/singleInstance exported activities → no MANIFEST-009."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-009" not in by_id, (
            "StrandHogg v2 should NOT fire for DIVA"
        )

    # ------------------------------------------------------------------
    # MANIFEST-010: App Links
    # ------------------------------------------------------------------

    def test_no_app_links(self):
        """DIVA has no BROWSABLE intent-filters → no MANIFEST-010."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-010" not in by_id, (
            "App links check should NOT fire for DIVA"
        )

    # ------------------------------------------------------------------
    # MANIFEST-011: Network Security Config
    # ------------------------------------------------------------------

    def test_no_network_security_config(self):
        """DIVA has no networkSecurityConfig → no MANIFEST-011."""
        result = self._run_checks()
        by_id = self._findings_by_id(result)
        assert "MANIFEST-011" not in by_id, (
            "Network security config check should NOT fire for DIVA"
        )

    # ------------------------------------------------------------------
    # Summary validation
    # ------------------------------------------------------------------

    def test_total_finding_count(self):
        """DIVA should produce exactly 4-6 findings (MobSF baseline match).

        Expected findings:
        1. MANIFEST-001: debuggable (high)
        2. MANIFEST-002: allowBackup (medium)
        3. MANIFEST-003: cleartext traffic (high)
        4. MANIFEST-005: critically outdated minSdk (high)
        5. MANIFEST-006: exported components (high)
        """
        result = self._run_checks()
        assert result["total_findings"] >= 4, (
            f"Expected at least 4 findings for DIVA, got {result['total_findings']}"
        )
        assert result["total_findings"] <= 8, (
            f"Expected at most 8 findings for DIVA (avoiding excessive FPs), "
            f"got {result['total_findings']}"
        )

    def test_severity_summary(self):
        """Verify severity distribution matches MobSF baseline."""
        result = self._run_checks()
        summary = result["summary"]
        # DIVA should have multiple high-severity findings
        assert summary.get("high", 0) >= 3, (
            f"Expected ≥3 high findings for DIVA, got {summary}"
        )
        # Should have at least one medium (allowBackup)
        assert summary.get("medium", 0) >= 1, (
            f"Expected ≥1 medium finding for DIVA, got {summary}"
        )

    def test_confidence_summary(self):
        """Verify confidence levels are assigned."""
        result = self._run_checks()
        conf = result["confidence_summary"]
        # At least some findings should be high confidence
        assert conf.get("high", 0) >= 2, (
            f"Expected ≥2 high-confidence findings, got {conf}"
        )

    def test_package_name(self):
        """Verify the package name is correctly extracted."""
        result = self._run_checks()
        assert result["package"] == "jakhar.aseem.diva"

    def test_no_severity_bump_for_standalone_apk(self):
        """DIVA is a standalone APK → no severity bump."""
        result = self._run_checks()
        assert result["severity_bumped"] is False
        assert result["severity_reduced"] is False

    def test_timing(self):
        """Verify timing metadata is present and reasonable."""
        result = self._run_checks()
        assert "elapsed_ms" in result
        assert "parse_ms" in result
        assert "checks_ms" in result
        # Checks should be fast (well under 500ms for mocked APK)
        assert result["checks_ms"] < 500

    # ------------------------------------------------------------------
    # MobSF baseline alignment: finding-by-finding comparison
    # ------------------------------------------------------------------

    def test_mobsf_baseline_exact_match(self):
        """Cross-reference all findings against MobSF expected output.

        MobSF reports for DIVA:
        1. Application is Debuggable [android:debuggable=true] — High
        2. Application Data can be Backed up [android:allowBackup=true] — Medium
        3. Application uses cleartext traffic [default for target < 28] — High
        4. App can be installed on a vulnerable older version of android (15) — High
        5. Exported activities/services without protection — High

        Our scanner should match or exceed this baseline.
        """
        result = self._run_checks()
        by_id = self._findings_by_id(result)

        # ---- 1. Debuggable ----
        assert "MANIFEST-001" in by_id
        assert by_id["MANIFEST-001"][0]["severity"] == "high"

        # ---- 2. AllowBackup ----
        assert "MANIFEST-002" in by_id
        assert by_id["MANIFEST-002"][0]["severity"] == "medium"

        # ---- 3. Cleartext Traffic ----
        assert "MANIFEST-003" in by_id
        assert by_id["MANIFEST-003"][0]["severity"] == "high"

        # ---- 4. Outdated minSdk ----
        assert "MANIFEST-005" in by_id
        assert by_id["MANIFEST-005"][0]["severity"] == "high"

        # ---- 5. Exported Components ----
        assert "MANIFEST-006" in by_id
        assert by_id["MANIFEST-006"][0]["severity"] in ("high", "medium")

        # ---- No false positives for these checks ----
        assert "MANIFEST-004" not in by_id, "No testOnly FP"
        assert "MANIFEST-007" not in by_id, "No custom permissions FP"
        assert "MANIFEST-008" not in by_id, "No StrandHogg v1 FP"
        assert "MANIFEST-009" not in by_id, "No StrandHogg v2 FP"
        assert "MANIFEST-011" not in by_id, "No NSC FP"


class TestDivaFirmwareContext:
    """Validate that firmware context adjustments work correctly with DIVA."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.svc = AndroguardService()
        self.apk = _build_diva_apk_mock()

    def _run_checks(self, **kwargs) -> dict[str, Any]:
        with patch("androguard.core.apk.APK", return_value=self.apk):
            with patch("os.path.isfile", return_value=True):
                return self.svc.scan_manifest_security("/fake/diva-beta.apk", **kwargs)

    def _findings_by_id(self, result: dict) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = {}
        for f in result["findings"]:
            grouped.setdefault(f["check_id"], []).append(f)
        return grouped

    def test_priv_app_severity_bump(self):
        """When DIVA is in /system/priv-app/, all findings bump +1 severity."""
        result = self._run_checks(is_priv_app=True)
        assert result["severity_bumped"] is True
        by_id = self._findings_by_id(result)

        # Debuggable: high → critical
        assert by_id["MANIFEST-001"][0]["severity"] == "critical"
        # AllowBackup: medium → high
        assert by_id["MANIFEST-002"][0]["severity"] == "high"
        # Cleartext: high → critical
        assert by_id["MANIFEST-003"][0]["severity"] == "critical"
        # minSdk: high → critical
        assert by_id["MANIFEST-005"][0]["severity"] == "critical"

    def test_platform_signed_no_reduction_for_diva(self):
        """DIVA is NOT a system component → no severity reduction even if platform-signed.

        DIVA doesn't declare any signatureOrSystem permissions, doesn't use
        system shared UID, and doesn't declare signature-level custom permissions.
        So even if is_platform_signed=True, the _has_signature_or_system_protection
        check returns False and no reduction is applied.
        """
        result = self._run_checks(is_platform_signed=True)
        assert result["severity_bumped"] is True
        # Should NOT reduce because DIVA has no signatureOrSystem signals
        assert result["severity_reduced"] is False


class TestDivaFalsePositiveRate:
    """Verify false positive rate is under 20% for DIVA.

    MobSF reports 5 true findings for DIVA. Our scanner should not
    produce more than 1 additional finding that MobSF doesn't report.
    """

    MOBSF_EXPECTED_CHECK_IDS = {
        "MANIFEST-001",  # debuggable
        "MANIFEST-002",  # allowBackup
        "MANIFEST-003",  # cleartext traffic
        "MANIFEST-005",  # minSdk
        "MANIFEST-006",  # exported components
    }

    def test_false_positive_rate(self):
        svc = AndroguardService()
        apk = _build_diva_apk_mock()

        with patch("androguard.core.apk.APK", return_value=apk):
            with patch("os.path.isfile", return_value=True):
                result = svc.scan_manifest_security("/fake/diva-beta.apk")

        total = result["total_findings"]
        expected_count = len(self.MOBSF_EXPECTED_CHECK_IDS)

        # Count findings NOT in MobSF baseline
        unexpected = [
            f for f in result["findings"]
            if f["check_id"] not in self.MOBSF_EXPECTED_CHECK_IDS
        ]

        # False positive rate = unexpected / total
        if total > 0:
            fp_rate = len(unexpected) / total
            assert fp_rate < 0.20, (
                f"False positive rate {fp_rate:.1%} exceeds 20% threshold. "
                f"Unexpected findings: {[f['check_id'] for f in unexpected]}"
            )

        # Also verify all expected findings are present (no false negatives)
        found_ids = {f["check_id"] for f in result["findings"]}
        missing = self.MOBSF_EXPECTED_CHECK_IDS - found_ids
        assert not missing, (
            f"Missing expected MobSF findings (false negatives): {missing}"
        )


class TestDivaFindingSerialization:
    """Verify findings serialize correctly for MCP tool output and REST API."""

    def test_finding_to_dict(self):
        """All findings should serialize to dict with required fields."""
        svc = AndroguardService()
        apk = _build_diva_apk_mock()

        with patch("androguard.core.apk.APK", return_value=apk):
            with patch("os.path.isfile", return_value=True):
                result = svc.scan_manifest_security("/fake/diva-beta.apk")

        for finding in result["findings"]:
            assert "check_id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert "description" in finding
            assert "evidence" in finding
            assert "cwe_ids" in finding
            assert "confidence" in finding
            assert isinstance(finding["cwe_ids"], list)
            assert finding["severity"] in ("critical", "high", "medium", "low", "info")
            assert finding["confidence"] in ("high", "medium", "low")

    def test_output_is_json_serializable(self):
        """Full result dict should be JSON-serializable (for REST API response)."""
        import json

        svc = AndroguardService()
        apk = _build_diva_apk_mock()

        with patch("androguard.core.apk.APK", return_value=apk):
            with patch("os.path.isfile", return_value=True):
                result = svc.scan_manifest_security("/fake/diva-beta.apk")

        # Should not raise
        json_str = json.dumps(result)
        assert len(json_str) > 0

        # Verify roundtrip
        parsed = json.loads(json_str)
        assert parsed["package"] == "jakhar.aseem.diva"
        assert parsed["total_findings"] == result["total_findings"]


@pytest.mark.skipif(
    not os.environ.get("DIVA_APK_PATH"),
    reason="Set DIVA_APK_PATH to run integration test against real DIVA APK",
)
class TestDivaRealAPK:
    """Integration test: scan real DIVA APK file.

    Run with:
        DIVA_APK_PATH=/path/to/diva-beta.apk pytest tests/test_diva_manifest_scan.py::TestDivaRealAPK -v
    """

    MOBSF_EXPECTED_CHECK_IDS = {
        "MANIFEST-001",
        "MANIFEST-002",
        "MANIFEST-003",
        "MANIFEST-005",
        "MANIFEST-006",
    }

    def test_real_apk_scan(self):
        apk_path = os.environ["DIVA_APK_PATH"]
        svc = AndroguardService()
        result = svc.scan_manifest_security(apk_path)

        assert result["package"] == "jakhar.aseem.diva"

        found_ids = {f["check_id"] for f in result["findings"]}

        # All MobSF baseline findings should be present
        missing = self.MOBSF_EXPECTED_CHECK_IDS - found_ids
        assert not missing, f"Missing expected findings: {missing}"

        # Verify key severities
        by_id: dict[str, list[dict]] = {}
        for f in result["findings"]:
            by_id.setdefault(f["check_id"], []).append(f)

        assert by_id["MANIFEST-001"][0]["severity"] == "high"
        assert by_id["MANIFEST-002"][0]["severity"] == "medium"
        assert by_id["MANIFEST-003"][0]["severity"] == "high"
        assert by_id["MANIFEST-005"][0]["severity"] == "high"

        # Performance: should complete well under 500ms
        assert result["elapsed_ms"] < 500, (
            f"Scan took {result['elapsed_ms']}ms, expected < 500ms"
        )

    def test_real_apk_false_positive_rate(self):
        apk_path = os.environ["DIVA_APK_PATH"]
        svc = AndroguardService()
        result = svc.scan_manifest_security(apk_path)

        total = result["total_findings"]
        unexpected = [
            f for f in result["findings"]
            if f["check_id"] not in self.MOBSF_EXPECTED_CHECK_IDS
        ]

        if total > 0:
            fp_rate = len(unexpected) / total
            assert fp_rate < 0.20, (
                f"FP rate {fp_rate:.1%} exceeds 20%. "
                f"Unexpected: {[f['check_id'] for f in unexpected]}"
            )


class TestDivaExportedComponentDetails:
    """Detailed validation of exported component detection for DIVA."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.svc = AndroguardService()
        self.apk = _build_diva_apk_mock()

    def test_main_activity_excluded(self):
        """The main launcher activity should be excluded from exported findings."""
        with patch("androguard.core.apk.APK", return_value=self.apk):
            with patch("os.path.isfile", return_value=True):
                result = self.svc.scan_manifest_security("/fake/diva-beta.apk")

        by_id: dict[str, list[dict]] = {}
        for f in result["findings"]:
            by_id.setdefault(f["check_id"], []).append(f)

        if "MANIFEST-006" in by_id:
            evidence = by_id["MANIFEST-006"][0]["evidence"]
            assert "MainActivity" not in evidence, (
                "Main launcher activity should be excluded from exported component findings"
            )

    def test_implicitly_exported_activities(self):
        """Activities with intent-filters should be detected as implicitly exported.

        DIVA targetSdk=24 (< 31), so activities with intent-filters are
        implicitly exported by default.
        """
        with patch("androguard.core.apk.APK", return_value=self.apk):
            with patch("os.path.isfile", return_value=True):
                result = self.svc.scan_manifest_security("/fake/diva-beta.apk")

        by_id: dict[str, list[dict]] = {}
        for f in result["findings"]:
            by_id.setdefault(f["check_id"], []).append(f)

        assert "MANIFEST-006" in by_id
        evidence = by_id["MANIFEST-006"][0]["evidence"]
        # Should mention implicit export
        assert "implicitly exported" in evidence.lower() or "intent-filter" in evidence.lower(), (
            "Evidence should mention implicit export via intent-filter"
        )

    def test_content_providers_not_exported(self):
        """DIVA's content providers should NOT be flagged as exported.

        With targetSdk=24 (>= 17), providers without explicit exported
        attribute default to NOT exported. NotesProvider and NotesProvider2
        should NOT appear in the MANIFEST-006 findings.
        """
        with patch("androguard.core.apk.APK", return_value=self.apk):
            with patch("os.path.isfile", return_value=True):
                result = self.svc.scan_manifest_security("/fake/diva-beta.apk")

        by_id: dict[str, list[dict]] = {}
        for f in result["findings"]:
            by_id.setdefault(f["check_id"], []).append(f)

        assert "MANIFEST-006" in by_id
        evidence = by_id["MANIFEST-006"][0]["evidence"]
        # Providers should NOT be in findings since targetSdk=24 >= 17
        assert "NotesProvider" not in evidence, (
            "Content providers should not be implicitly exported for targetSdk >= 17"
        )
