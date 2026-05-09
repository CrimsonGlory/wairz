"""Tests for the Wairz manifest scanner runner.

These tests validate that the WairzRunner correctly invokes
AndroguardService.scan_manifest_security() and normalizes findings
into the same structured JSON schema used by the MobSF runner for
direct comparison.

Tests use mocked AndroguardService scan results based on actual
Wairz output for DIVA, InsecureBankv2, and OVAA APKs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.wairz_runner import (
    NormalizedWairzFinding,
    WairzRunner,
    WairzScanResult,
    _normalize_findings,
    batch_scan,
    compare_with_mobsf,
)

# ---------------------------------------------------------------------------
# Fixtures: simulated AndroguardService.scan_manifest_security() output
# ---------------------------------------------------------------------------


def _diva_raw_result() -> dict[str, Any]:
    """Simulated Wairz scan result for DIVA APK."""
    return {
        "package": "jakhar.aseem.diva",
        "findings": [
            {
                "check_id": "MANIFEST-001",
                "title": "Application is debuggable",
                "severity": "high",
                "description": "android:debuggable is set to true in the manifest.",
                "evidence": 'android:debuggable="true"',
                "cwe_ids": ["CWE-489"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-002",
                "title": "Application data can be backed up",
                "severity": "medium",
                "description": "android:allowBackup is true or defaults to true.",
                "evidence": 'android:allowBackup="true"',
                "cwe_ids": ["CWE-921"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-003",
                "title": "Cleartext traffic allowed",
                "severity": "high",
                "description": "usesCleartextTraffic is true or defaults to true for targetSdk < 28.",
                "evidence": "targetSdkVersion=24 (< 28, cleartext default on)",
                "cwe_ids": ["CWE-319"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-005",
                "title": "Minimum SDK version is 15",
                "severity": "low",
                "description": "minSdkVersion 15 is below recommended level 24.",
                "evidence": "android:minSdkVersion=15",
                "cwe_ids": ["CWE-1104"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Activity without permission: jakhar.aseem.diva.MainActivity",
                "severity": "high",
                "description": "Activity is exported without requiring a permission.",
                "evidence": "jakhar.aseem.diva.MainActivity",
                "cwe_ids": ["CWE-926"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Content Provider without permission: jakhar.aseem.diva.NotesProvider",
                "severity": "high",
                "description": "Content Provider is exported without requiring a permission.",
                "evidence": "jakhar.aseem.diva.NotesProvider",
                "cwe_ids": ["CWE-926"],
                "confidence": "high",
            },
        ],
        "summary": {
            "critical": 0,
            "high": 4,
            "medium": 1,
            "low": 1,
            "info": 0,
        },
        "confidence_summary": {"high": 6, "medium": 0, "low": 0},
        "total_findings": 6,
        "suppressed_findings": [],
        "suppressed_count": 0,
        "suppression_reasons": [],
        "severity_bumped": False,
        "severity_reduced": False,
        "reduced_check_ids": [],
        "is_debug_signed": True,
        "elapsed_ms": 42,
        "parse_ms": 15,
        "checks_ms": 27,
    }


def _insecurebankv2_raw_result() -> dict[str, Any]:
    """Simulated Wairz scan result for InsecureBankv2 APK."""
    return {
        "package": "com.android.insecurebankv2",
        "findings": [
            {
                "check_id": "MANIFEST-001",
                "title": "Application is debuggable",
                "severity": "high",
                "description": "android:debuggable is set to true.",
                "evidence": 'android:debuggable="true"',
                "cwe_ids": ["CWE-489"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-002",
                "title": "Application data can be backed up",
                "severity": "medium",
                "description": "android:allowBackup is true.",
                "evidence": 'android:allowBackup="true"',
                "cwe_ids": ["CWE-921"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-003",
                "title": "Cleartext traffic allowed",
                "severity": "high",
                "description": "usesCleartextTraffic defaults to true for targetSdk < 28.",
                "evidence": "targetSdkVersion=15 (< 28, cleartext default on)",
                "cwe_ids": ["CWE-319"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-005",
                "title": "Minimum SDK version is 15",
                "severity": "low",
                "description": "minSdkVersion 15 is critically outdated.",
                "evidence": "android:minSdkVersion=15",
                "cwe_ids": ["CWE-1104"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Activity without permission: com.android.insecurebankv2.PostLogin",
                "severity": "high",
                "description": "Activity is exported without requiring a permission.",
                "evidence": "com.android.insecurebankv2.PostLogin",
                "cwe_ids": ["CWE-926"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Receiver without permission: com.android.insecurebankv2.MyBroadCastReceiver",
                "severity": "medium",
                "description": "Receiver is exported without requiring a permission.",
                "evidence": "com.android.insecurebankv2.MyBroadCastReceiver",
                "cwe_ids": ["CWE-926"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-008",
                "title": "StrandHogg v1: taskAffinity set on Activity",
                "severity": "medium",
                "description": "Activity has taskAffinity set, susceptible to task hijacking.",
                "evidence": "com.android.insecurebankv2.LoginActivity",
                "cwe_ids": ["CWE-1021"],
                "confidence": "medium",
            },
        ],
        "summary": {
            "critical": 0,
            "high": 3,
            "medium": 3,
            "low": 1,
            "info": 0,
        },
        "confidence_summary": {"high": 6, "medium": 1, "low": 0},
        "total_findings": 7,
        "suppressed_findings": [],
        "suppressed_count": 0,
        "suppression_reasons": [],
        "severity_bumped": False,
        "severity_reduced": False,
        "reduced_check_ids": [],
        "is_debug_signed": True,
        "elapsed_ms": 38,
        "parse_ms": 12,
        "checks_ms": 26,
    }


def _ovaa_raw_result() -> dict[str, Any]:
    """Simulated Wairz scan result for OVAA APK."""
    return {
        "package": "oversecured.ovaa",
        "findings": [
            {
                "check_id": "MANIFEST-002",
                "title": "Application data can be backed up",
                "severity": "medium",
                "description": "android:allowBackup is true.",
                "evidence": 'android:allowBackup="true"',
                "cwe_ids": ["CWE-921"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-003",
                "title": "Cleartext traffic allowed",
                "severity": "high",
                "description": "usesCleartextTraffic is true.",
                "evidence": 'android:usesCleartextTraffic="true"',
                "cwe_ids": ["CWE-319"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-005",
                "title": "Minimum SDK version is 23",
                "severity": "low",
                "description": "minSdkVersion 23 is below recommended level 24.",
                "evidence": "android:minSdkVersion=23",
                "cwe_ids": ["CWE-1104"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Activity without permission: oversecured.ovaa.LoginActivity",
                "severity": "high",
                "description": "Activity is exported without requiring a permission.",
                "evidence": "oversecured.ovaa.LoginActivity",
                "cwe_ids": ["CWE-926"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-010",
                "title": "Browsable deep link without autoVerify",
                "severity": "medium",
                "description": "Deep link handler activity lacks autoVerify attribute.",
                "evidence": "oversecured.ovaa.DeeplinkActivity: oversecured://ovaa",
                "cwe_ids": ["CWE-939"],
                "confidence": "medium",
            },
        ],
        "summary": {
            "critical": 0,
            "high": 2,
            "medium": 2,
            "low": 1,
            "info": 0,
        },
        "confidence_summary": {"high": 4, "medium": 1, "low": 0},
        "total_findings": 5,
        "suppressed_findings": [],
        "suppressed_count": 0,
        "suppression_reasons": [],
        "severity_bumped": False,
        "severity_reduced": False,
        "reduced_check_ids": [],
        "is_debug_signed": False,
        "elapsed_ms": 35,
        "parse_ms": 10,
        "checks_ms": 25,
    }


def _priv_app_raw_result() -> dict[str, Any]:
    """Simulated Wairz scan result for a priv-app APK with severity bumping."""
    return {
        "package": "com.example.systemapp",
        "findings": [
            {
                "check_id": "MANIFEST-002",
                "title": "Application data can be backed up",
                "severity": "high",  # bumped from medium
                "description": "android:allowBackup is true.",
                "evidence": 'android:allowBackup="true"',
                "cwe_ids": ["CWE-921"],
                "confidence": "high",
            },
            {
                "check_id": "MANIFEST-003",
                "title": "Cleartext traffic allowed",
                "severity": "critical",  # bumped from high
                "description": "usesCleartextTraffic is true.",
                "evidence": 'android:usesCleartextTraffic="true"',
                "cwe_ids": ["CWE-319"],
                "confidence": "high",
            },
        ],
        "summary": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        "confidence_summary": {"high": 2, "medium": 0, "low": 0},
        "total_findings": 2,
        "suppressed_findings": [
            {
                "check_id": "MANIFEST-006",
                "title": "Exported Activity: com.example.systemapp.SettingsActivity",
                "severity": "medium",
                "description": "Activity exported without permission but suppressed for system app.",
                "evidence": "com.example.systemapp.SettingsActivity",
                "cwe_ids": ["CWE-926"],
                "confidence": "low",
                "suppressed": True,
                "suppression_reason": "System app with signatureOrSystem protection",
            },
        ],
        "suppressed_count": 1,
        "suppression_reasons": ["System app with signatureOrSystem protection"],
        "severity_bumped": True,
        "severity_reduced": True,
        "reduced_check_ids": ["MANIFEST-002"],
        "is_debug_signed": False,
        "elapsed_ms": 50,
        "parse_ms": 18,
        "checks_ms": 32,
    }


# ---------------------------------------------------------------------------
# Tests: NormalizedWairzFinding
# ---------------------------------------------------------------------------


class TestNormalizedWairzFinding:
    """Tests for the NormalizedWairzFinding dataclass."""

    def test_to_dict_basic(self):
        finding = NormalizedWairzFinding(
            check_id="MANIFEST-001",
            title="Application is debuggable",
            severity="high",
            description="Debug flag is set.",
            evidence='android:debuggable="true"',
            cwe_ids=["CWE-489"],
            confidence="high",
        )
        d = finding.to_dict()
        assert d["check_id"] == "MANIFEST-001"
        assert d["severity"] == "high"
        assert d["cwe_ids"] == ["CWE-489"]
        assert d["confidence"] == "high"
        assert "suppressed" not in d

    def test_to_dict_suppressed(self):
        finding = NormalizedWairzFinding(
            check_id="MANIFEST-006",
            title="Exported Activity",
            severity="medium",
            description="Exported without permission.",
            evidence="com.example.Activity",
            cwe_ids=["CWE-926"],
            confidence="low",
            suppressed=True,
            suppression_reason="System app",
        )
        d = finding.to_dict()
        assert d["suppressed"] is True
        assert d["suppression_reason"] == "System app"

    def test_frozen(self):
        finding = NormalizedWairzFinding(
            check_id="MANIFEST-001",
            title="Test",
            severity="high",
            description="Test",
            evidence="",
            cwe_ids=[],
            confidence="high",
        )
        with pytest.raises(AttributeError):
            finding.severity = "low"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tests: WairzScanResult
# ---------------------------------------------------------------------------


class TestWairzScanResult:
    """Tests for the WairzScanResult dataclass."""

    def test_summary_severity_counts(self):
        result = WairzScanResult(
            success=True,
            package_name="test.app",
            manifest_findings=[
                NormalizedWairzFinding(
                    check_id="MANIFEST-001",
                    title="Debug",
                    severity="high",
                    description="",
                    evidence="",
                    cwe_ids=[],
                    confidence="high",
                ),
                NormalizedWairzFinding(
                    check_id="MANIFEST-002",
                    title="Backup",
                    severity="medium",
                    description="",
                    evidence="",
                    cwe_ids=[],
                    confidence="high",
                ),
            ],
        )
        summary = result.summary
        assert summary["total_findings"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["success"] is True

    def test_summary_firmware_context(self):
        result = WairzScanResult(
            success=True,
            is_priv_app=True,
            is_platform_signed=True,
            severity_bumped=True,
            severity_reduced=True,
            reduced_check_ids=["MANIFEST-002"],
        )
        ctx = result.summary["firmware_context"]
        assert ctx["is_priv_app"] is True
        assert ctx["is_platform_signed"] is True
        assert ctx["severity_bumped"] is True
        assert ctx["severity_reduced"] is True
        assert ctx["reduced_check_ids"] == ["MANIFEST-002"]

    def test_to_dict_full(self):
        result = WairzScanResult(
            success=True,
            package_name="test.app",
            manifest_findings=[],
            suppressed_findings=[],
            apk_hash="abc123",
            scan_duration_ms=42,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["package_name"] == "test.app"
        assert d["apk_hash"] == "abc123"
        assert d["scan_duration_ms"] == 42
        assert d["manifest_findings"] == []
        assert d["suppressed_findings"] == []
        assert "firmware_context" in d

    def test_error_result(self):
        result = WairzScanResult(
            success=False,
            error="File not found",
        )
        assert result.success is False
        assert result.error == "File not found"
        assert result.summary["error"] == "File not found"


# ---------------------------------------------------------------------------
# Tests: _normalize_findings
# ---------------------------------------------------------------------------


class TestNormalizeFindings:
    """Tests for the _normalize_findings function."""

    def test_normalize_basic(self):
        raw = [
            {
                "check_id": "MANIFEST-001",
                "title": "Debuggable",
                "severity": "high",
                "description": "Debug flag set.",
                "evidence": 'android:debuggable="true"',
                "cwe_ids": ["CWE-489"],
                "confidence": "high",
            },
        ]
        findings = _normalize_findings(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "MANIFEST-001"
        assert f.severity == "high"
        assert f.confidence == "high"
        assert f.suppressed is False

    def test_normalize_suppressed(self):
        raw = [
            {
                "check_id": "MANIFEST-006",
                "title": "Exported",
                "severity": "medium",
                "description": "Exported without perm.",
                "evidence": "com.example.Activity",
                "cwe_ids": ["CWE-926"],
                "confidence": "low",
                "suppressed": True,
                "suppression_reason": "System app",
            },
        ]
        findings = _normalize_findings(raw, suppressed=True)
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert findings[0].suppression_reason == "System app"

    def test_normalize_defaults(self):
        """Missing fields should get defaults."""
        raw = [{"check_id": "MANIFEST-001"}]
        findings = _normalize_findings(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.title == ""
        assert f.severity == "info"
        assert f.confidence == "high"
        assert f.cwe_ids == []

    def test_normalize_skips_non_dicts(self):
        raw = [{"check_id": "MANIFEST-001"}, "not a dict", 42]
        findings = _normalize_findings(raw)
        assert len(findings) == 1

    def test_normalize_empty(self):
        assert _normalize_findings([]) == []


# ---------------------------------------------------------------------------
# Tests: WairzRunner
# ---------------------------------------------------------------------------


class TestWairzRunner:
    """Tests for the WairzRunner class."""

    def _mock_service(self, raw_result: dict[str, Any]) -> MagicMock:
        mock = MagicMock()
        mock.scan_manifest_security.return_value = raw_result
        return mock

    def test_scan_diva(self, tmp_path):
        """DIVA APK scan returns expected normalized findings."""
        apk = tmp_path / "diva.apk"
        apk.write_bytes(b"fake APK data")

        raw = _diva_raw_result()
        service = self._mock_service(raw)
        runner = WairzRunner(service=service)

        result = runner.scan_apk(str(apk))

        assert result.success is True
        assert result.package_name == "jakhar.aseem.diva"
        assert len(result.manifest_findings) == 6
        assert result.scan_duration_ms >= 0

        # Verify check IDs present
        check_ids = {f.check_id for f in result.manifest_findings}
        assert "MANIFEST-001" in check_ids  # debuggable
        assert "MANIFEST-002" in check_ids  # allowBackup
        assert "MANIFEST-003" in check_ids  # cleartext
        assert "MANIFEST-005" in check_ids  # min SDK
        assert "MANIFEST-006" in check_ids  # exported components

        # Verify severity distribution
        sev = result.summary["by_severity"]
        assert sev.get("high", 0) == 4
        assert sev.get("medium", 0) == 1
        assert sev.get("low", 0) == 1

        service.scan_manifest_security.assert_called_once_with(
            str(apk),
            is_priv_app=False,
            is_platform_signed=False,
        )

    def test_scan_insecurebankv2(self, tmp_path):
        """InsecureBankv2 APK scan returns expected normalized findings."""
        apk = tmp_path / "insecurebankv2.apk"
        apk.write_bytes(b"fake APK data")

        raw = _insecurebankv2_raw_result()
        service = self._mock_service(raw)
        runner = WairzRunner(service=service)

        result = runner.scan_apk(str(apk))

        assert result.success is True
        assert result.package_name == "com.android.insecurebankv2"
        assert len(result.manifest_findings) == 7

        check_ids = {f.check_id for f in result.manifest_findings}
        assert "MANIFEST-001" in check_ids
        assert "MANIFEST-008" in check_ids  # StrandHogg v1

    def test_scan_ovaa(self, tmp_path):
        """OVAA APK scan returns expected normalized findings."""
        apk = tmp_path / "ovaa.apk"
        apk.write_bytes(b"fake APK data")

        raw = _ovaa_raw_result()
        service = self._mock_service(raw)
        runner = WairzRunner(service=service)

        result = runner.scan_apk(str(apk))

        assert result.success is True
        assert result.package_name == "oversecured.ovaa"
        assert len(result.manifest_findings) == 5

        check_ids = {f.check_id for f in result.manifest_findings}
        assert "MANIFEST-010" in check_ids  # deep links

    def test_scan_priv_app_severity_bumping(self, tmp_path):
        """Priv-app scan preserves firmware context metadata."""
        apk = tmp_path / "systemapp.apk"
        apk.write_bytes(b"fake APK data")

        raw = _priv_app_raw_result()
        service = self._mock_service(raw)
        runner = WairzRunner(service=service)

        result = runner.scan_apk(
            str(apk),
            is_priv_app=True,
            is_platform_signed=True,
        )

        assert result.success is True
        assert result.is_priv_app is True
        assert result.is_platform_signed is True
        assert result.severity_bumped is True
        assert result.severity_reduced is True
        assert "MANIFEST-002" in result.reduced_check_ids

        # Verify suppressed findings
        assert len(result.suppressed_findings) == 1
        suppressed = result.suppressed_findings[0]
        assert suppressed.check_id == "MANIFEST-006"
        assert suppressed.suppressed is True

        # Verify bumped severities
        cleartext = [
            f for f in result.manifest_findings
            if f.check_id == "MANIFEST-003"
        ][0]
        assert cleartext.severity == "critical"

        service.scan_manifest_security.assert_called_once_with(
            str(apk),
            is_priv_app=True,
            is_platform_signed=True,
        )

    def test_scan_file_not_found(self):
        runner = WairzRunner()
        result = runner.scan_apk("/nonexistent/path.apk")
        assert result.success is False
        assert "not found" in result.error

    def test_scan_exception_handling(self, tmp_path):
        """Service exceptions are caught and returned as errors."""
        apk = tmp_path / "bad.apk"
        apk.write_bytes(b"fake")

        service = MagicMock()
        service.scan_manifest_security.side_effect = RuntimeError("Parse error")
        runner = WairzRunner(service=service)

        result = runner.scan_apk(str(apk))
        assert result.success is False
        assert "Parse error" in result.error

    def test_lazy_service_creation(self, tmp_path):
        """Runner creates AndroguardService on first scan if none provided."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake")

        with patch(
            "app.services.wairz_runner.WairzRunner._get_service"
        ) as mock_get:
            mock_svc = MagicMock()
            mock_svc.scan_manifest_security.return_value = {
                "package": "test",
                "findings": [],
                "suppressed_findings": [],
                "severity_bumped": False,
                "severity_reduced": False,
                "reduced_check_ids": [],
            }
            mock_get.return_value = mock_svc

            runner = WairzRunner()
            result = runner.scan_apk(str(apk))
            assert result.success is True
            mock_get.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: scan_apk_from_raw
# ---------------------------------------------------------------------------


class TestScanFromRaw:
    """Tests for WairzRunner.scan_apk_from_raw()."""

    def test_from_raw_diva(self):
        runner = WairzRunner()
        raw = _diva_raw_result()

        result = runner.scan_apk_from_raw(raw, apk_hash="abc123")
        assert result.success is True
        assert result.package_name == "jakhar.aseem.diva"
        assert result.apk_hash == "abc123"
        assert len(result.manifest_findings) == 6

    def test_from_raw_preserves_context(self):
        runner = WairzRunner()
        raw = _priv_app_raw_result()

        result = runner.scan_apk_from_raw(
            raw,
            is_priv_app=True,
            is_platform_signed=True,
        )
        assert result.severity_bumped is True
        assert result.severity_reduced is True


# ---------------------------------------------------------------------------
# Tests: batch_scan
# ---------------------------------------------------------------------------


class TestBatchScan:
    """Tests for the batch_scan function."""

    def test_batch_scan_multiple(self, tmp_path):
        apk1 = tmp_path / "diva.apk"
        apk2 = tmp_path / "ovaa.apk"
        apk1.write_bytes(b"fake1")
        apk2.write_bytes(b"fake2")

        call_count = 0

        def mock_scan(path, *, is_priv_app=False, is_platform_signed=False):
            nonlocal call_count
            call_count += 1
            if "diva" in path:
                return _diva_raw_result()
            return _ovaa_raw_result()

        service = MagicMock()
        service.scan_manifest_security.side_effect = mock_scan
        runner = WairzRunner(service=service)

        results = batch_scan([str(apk1), str(apk2)], runner=runner)
        assert len(results) == 2
        assert str(apk1) in results
        assert str(apk2) in results

    def test_batch_scan_empty(self):
        results = batch_scan([])
        assert results == {}


# ---------------------------------------------------------------------------
# Tests: compare_with_mobsf
# ---------------------------------------------------------------------------


class TestCompareWithMobsf:
    """Tests for the compare_with_mobsf convenience wrapper."""

    def test_comparison_basic(self):
        from app.services.mobsf_runner import NormalizedManifestFinding

        wairz_result = WairzScanResult(
            success=True,
            package_name="test.app",
            manifest_findings=[
                NormalizedWairzFinding(
                    check_id="MANIFEST-001",
                    title="Debuggable",
                    severity="high",
                    description="Debug flag.",
                    evidence='android:debuggable="true"',
                    cwe_ids=["CWE-489"],
                    confidence="high",
                ),
                NormalizedWairzFinding(
                    check_id="MANIFEST-002",
                    title="Backup allowed",
                    severity="medium",
                    description="Backup flag.",
                    evidence='android:allowBackup="true"',
                    cwe_ids=["CWE-921"],
                    confidence="high",
                ),
            ],
        )

        mobsf_findings = [
            NormalizedManifestFinding(
                check_id="MANIFEST-001",
                title="Application is debuggable",
                severity="high",
                description="Debug enabled.",
                evidence='android:debuggable="true"',
                cwe_ids=["CWE-489"],
                confidence="high",
                mobsf_key="is_debuggable",
                mobsf_severity="high",
            ),
            NormalizedManifestFinding(
                check_id="MANIFEST-003",
                title="Cleartext traffic",
                severity="high",
                description="HTTP allowed.",
                evidence="usesCleartextTraffic",
                cwe_ids=["CWE-319"],
                confidence="high",
                mobsf_key="is_clear_text_traffic",
                mobsf_severity="high",
            ),
        ]

        comparison = compare_with_mobsf(wairz_result, mobsf_findings)

        assert len(comparison["matched"]) >= 1  # MANIFEST-001
        assert len(comparison["wairz_only"]) >= 1  # MANIFEST-002
        assert len(comparison["mobsf_only"]) >= 1  # MANIFEST-003


# ---------------------------------------------------------------------------
# Tests: to_dict schema compatibility
# ---------------------------------------------------------------------------


class TestSchemaCompatibility:
    """Verify WairzRunner output matches the MobSF runner schema."""

    def test_finding_dict_keys(self):
        """NormalizedWairzFinding.to_dict() has the same core keys as
        ManifestFinding.to_dict()."""
        finding = NormalizedWairzFinding(
            check_id="MANIFEST-001",
            title="Test",
            severity="high",
            description="Test description",
            evidence="test evidence",
            cwe_ids=["CWE-489"],
            confidence="high",
        )
        d = finding.to_dict()
        required_keys = {
            "check_id", "title", "severity", "description",
            "evidence", "cwe_ids", "confidence",
        }
        assert required_keys.issubset(d.keys())

    def test_result_dict_keys(self):
        """WairzScanResult.to_dict() matches MobsfScanResult.to_dict() structure."""
        result = WairzScanResult(
            success=True,
            package_name="test",
            apk_hash="abc",
            scan_duration_ms=42,
        )
        d = result.to_dict()
        required_keys = {
            "success", "package_name", "apk_hash",
            "scan_duration_ms", "manifest_findings", "error",
        }
        assert required_keys.issubset(d.keys())

    def test_summary_keys(self):
        """WairzScanResult.summary matches MobsfScanResult.summary structure."""
        result = WairzScanResult(success=True, package_name="test")
        summary = result.summary
        required_keys = {
            "success", "package_name", "total_findings",
            "by_severity", "scan_duration_ms", "apk_hash", "error",
        }
        assert required_keys.issubset(summary.keys())
        # Extra Wairz-specific keys
        assert "firmware_context" in summary
        assert "by_confidence" in summary
        assert "suppressed_count" in summary
