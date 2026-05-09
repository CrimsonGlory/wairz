"""Tests for the MobSF API runner manifest finding normalization.

These tests validate that the MobSF runner correctly normalizes
MobSF report JSON into the structured NormalizedManifestFinding schema,
matching the Wairz ManifestFinding format for comparison.

Tests use synthetic MobSF report fixtures based on actual MobSF output
for DIVA, InsecureBankv2, and OVAA APKs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.mobsf_runner import (
    MobsfRunner,
    MobsfScanResult,
    NormalizedManifestFinding,
    _extract_manifest_findings,
    _map_rule_to_check,
    _map_severity,
    compare_findings,
)

# ---------------------------------------------------------------------------
# Fixtures: synthetic MobSF report data
# ---------------------------------------------------------------------------


def _diva_report() -> dict[str, Any]:
    """Simulated MobSF report for DIVA APK."""
    return {
        "package_name": "jakhar.aseem.diva",
        "app_name": "DIVA",
        "min_sdk": "15",
        "target_sdk": "24",
        "is_debuggable": True,
        "is_allow_backup": True,
        "is_clear_text_traffic": True,
        "is_test_only": False,
        "manifest_analysis": [
            {
                "rule": "android_debuggable",
                "title": "Debug Enabled For App",
                "severity": "high",
                "description": "Debugging was enabled on the app.",
                "component": [],
            },
            {
                "rule": "android_allowbackup",
                "title": "Application Data can be Backed up",
                "severity": "warning",
                "description": "This flag allows anyone to backup your application data via adb.",
                "component": [],
            },
        ],
        "exported_activities": [
            "jakhar.aseem.diva.MainActivity",
            "jakhar.aseem.diva.LogActivity",
            "jakhar.aseem.diva.HardcodeActivity",
            "jakhar.aseem.diva.InsecureDataStorage1Activity",
            "jakhar.aseem.diva.InsecureDataStorage2Activity",
        ],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [
            "jakhar.aseem.diva.NotesProvider",
        ],
        "browsable_activities": {},
        "network_security": [],
    }


def _insecurebankv2_report() -> dict[str, Any]:
    """Simulated MobSF report for InsecureBankv2 APK."""
    return {
        "package_name": "com.android.insecurebankv2",
        "app_name": "InsecureBankv2",
        "min_sdk": "15",
        "target_sdk": "15",
        "is_debuggable": True,
        "is_allow_backup": True,
        "is_clear_text_traffic": True,
        "is_test_only": False,
        "manifest_analysis": [
            {
                "rule": "android_debuggable",
                "title": "Debug Enabled For App",
                "severity": "high",
                "description": "Debugging was enabled on the app.",
                "component": [],
            },
            {
                "rule": "android_allowbackup",
                "title": "Application Data can be Backed up",
                "severity": "warning",
                "description": "Allows backup via adb.",
                "component": [],
            },
            {
                "rule": "android_task_affinity",
                "title": "TaskAffinity is set for Activity",
                "severity": "warning",
                "description": "Activity susceptible to task hijacking.",
                "component": ["com.android.insecurebankv2.LoginActivity"],
            },
        ],
        "exported_activities": [
            "com.android.insecurebankv2.LoginActivity",
            "com.android.insecurebankv2.PostLogin",
            "com.android.insecurebankv2.DoTransfer",
            "com.android.insecurebankv2.ViewStatement",
            "com.android.insecurebankv2.ChangePassword",
        ],
        "exported_services": [
            "com.android.insecurebankv2.MyBroadCastReceiver",
        ],
        "exported_receivers": [
            "com.android.insecurebankv2.MyBroadCastReceiver",
        ],
        "exported_providers": [],
        "browsable_activities": {},
        "network_security": [],
    }


def _ovaa_report() -> dict[str, Any]:
    """Simulated MobSF report for OVAA (Oversecured Vulnerable Android App)."""
    return {
        "package_name": "oversecured.ovaa",
        "app_name": "OVAA",
        "min_sdk": "23",
        "target_sdk": "30",
        "is_debuggable": False,
        "is_allow_backup": True,
        "is_clear_text_traffic": True,
        "is_test_only": False,
        "manifest_analysis": [
            {
                "rule": "android_allowbackup",
                "title": "Application Data can be Backed up",
                "severity": "warning",
                "description": "Allows backup via adb.",
                "component": [],
            },
            {
                "rule": "android_cleartext",
                "title": "Cleartext Traffic Allowed",
                "severity": "high",
                "description": "App allows cleartext HTTP traffic.",
                "component": [],
            },
            {
                "rule": "android_exported_provider",
                "title": "Content Provider Exported",
                "severity": "warning",
                "description": "Content provider exported without protection.",
                "component": ["oversecured.ovaa.providers.TheftOverwriteProvider"],
            },
            {
                "rule": "android_launch_mode",
                "title": "Activity with singleTask launch mode",
                "severity": "warning",
                "description": "Activity can be used for task hijacking.",
                "component": ["oversecured.ovaa.activities.DeeplinkActivity"],
            },
        ],
        "exported_activities": [
            "oversecured.ovaa.activities.LoginActivity",
            "oversecured.ovaa.activities.DeeplinkActivity",
            "oversecured.ovaa.activities.WebViewActivity",
        ],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [
            "oversecured.ovaa.providers.TheftOverwriteProvider",
        ],
        "browsable_activities": {
            "oversecured.ovaa.activities.DeeplinkActivity": ["ovaa://"],
        },
        "network_security": [
            {
                "title": "No certificate pinning configured",
                "severity": "warning",
                "description": "No certificate pinning in network security config.",
                "scope": "base-config",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Tests: Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Verify MobSF severity strings are correctly mapped to Wairz severity."""

    def test_high_maps_to_high(self) -> None:
        assert _map_severity("high") == "high"

    def test_warning_maps_to_medium(self) -> None:
        assert _map_severity("warning") == "medium"

    def test_info_maps_to_info(self) -> None:
        assert _map_severity("info") == "info"

    def test_secure_maps_to_info(self) -> None:
        assert _map_severity("secure") == "info"

    def test_hotspot_maps_to_low(self) -> None:
        assert _map_severity("hotspot") == "low"

    def test_unknown_maps_to_info(self) -> None:
        assert _map_severity("banana") == "info"

    def test_case_insensitive(self) -> None:
        assert _map_severity("HIGH") == "high"
        assert _map_severity("Warning") == "medium"


# ---------------------------------------------------------------------------
# Tests: Rule-to-check mapping
# ---------------------------------------------------------------------------


class TestRuleToCheckMapping:
    """Verify MobSF rule names map to correct Wairz check IDs."""

    def test_debuggable(self) -> None:
        check_id, cwe = _map_rule_to_check("android_debuggable", "Debug Enabled")
        assert check_id == "MANIFEST-001"
        assert "CWE-489" in cwe

    def test_backup(self) -> None:
        check_id, cwe = _map_rule_to_check("android_allowbackup", "Backup")
        assert check_id == "MANIFEST-002"
        assert "CWE-921" in cwe

    def test_cleartext(self) -> None:
        check_id, cwe = _map_rule_to_check("android_cleartext", "Cleartext")
        assert check_id == "MANIFEST-003"
        assert "CWE-319" in cwe

    def test_task_affinity(self) -> None:
        check_id, _ = _map_rule_to_check("android_task_affinity", "Task Affinity")
        assert check_id == "MANIFEST-008"

    def test_launch_mode(self) -> None:
        check_id, _ = _map_rule_to_check("android_launch_mode", "singleTask")
        assert check_id == "MANIFEST-009"

    def test_exported_provider(self) -> None:
        check_id, cwe = _map_rule_to_check(
            "android_exported_provider", "Content Provider Exported"
        )
        assert check_id == "MANIFEST-006"
        assert "CWE-926" in cwe

    def test_network_security(self) -> None:
        check_id, _ = _map_rule_to_check("android_nsc", "Network Security")
        assert check_id == "MANIFEST-011"

    def test_unknown_rule(self) -> None:
        check_id, _ = _map_rule_to_check("completely_unknown_rule", "Unknown")
        assert check_id == "MANIFEST-UNK"


# ---------------------------------------------------------------------------
# Tests: Finding extraction from MobSF reports
# ---------------------------------------------------------------------------


class TestDIVAExtraction:
    """Verify finding extraction for DIVA APK MobSF report."""

    def setup_method(self) -> None:
        self.report = _diva_report()
        self.findings = _extract_manifest_findings(self.report)

    def test_finds_debuggable(self) -> None:
        debuggable = [f for f in self.findings if f.check_id == "MANIFEST-001"]
        assert len(debuggable) >= 1
        assert debuggable[0].severity == "high"

    def test_finds_allow_backup(self) -> None:
        backup = [f for f in self.findings if f.check_id == "MANIFEST-002"]
        assert len(backup) >= 1

    def test_finds_cleartext(self) -> None:
        cleartext = [f for f in self.findings if f.check_id == "MANIFEST-003"]
        assert len(cleartext) >= 1
        assert cleartext[0].severity == "high"

    def test_finds_min_sdk(self) -> None:
        sdk = [f for f in self.findings if f.check_id == "MANIFEST-005"]
        assert len(sdk) >= 1
        # DIVA min SDK 15 is critically outdated (< 19)
        min_sdk_finding = [f for f in sdk if "15" in f.evidence or "min" in f.title.lower()]
        assert len(min_sdk_finding) >= 1
        assert min_sdk_finding[0].severity == "high"

    def test_finds_exported_activities(self) -> None:
        exported = [
            f
            for f in self.findings
            if f.check_id == "MANIFEST-006" and "Activity" in f.title
        ]
        assert len(exported) >= 1
        # DIVA has 5 exported activities in our fixture
        assert "5" in exported[0].title or "5" in exported[0].evidence

    def test_finds_exported_provider(self) -> None:
        providers = [
            f
            for f in self.findings
            if f.check_id == "MANIFEST-006" and "Provider" in f.title
        ]
        assert len(providers) >= 1

    def test_total_findings_reasonable(self) -> None:
        # DIVA should produce 5-12 findings (MobSF baseline)
        assert 4 <= len(self.findings) <= 15

    def test_all_have_check_id(self) -> None:
        for f in self.findings:
            assert f.check_id, f"Finding missing check_id: {f.title}"

    def test_all_have_valid_severity(self) -> None:
        valid = {"critical", "high", "medium", "low", "info"}
        for f in self.findings:
            assert f.severity in valid, f"Invalid severity {f.severity}: {f.title}"


class TestInsecureBankv2Extraction:
    """Verify finding extraction for InsecureBankv2 MobSF report."""

    def setup_method(self) -> None:
        self.report = _insecurebankv2_report()
        self.findings = _extract_manifest_findings(self.report)

    def test_finds_debuggable(self) -> None:
        debuggable = [f for f in self.findings if f.check_id == "MANIFEST-001"]
        assert len(debuggable) >= 1

    def test_finds_task_affinity(self) -> None:
        """InsecureBankv2 has task affinity issues."""
        ta = [f for f in self.findings if f.check_id == "MANIFEST-008"]
        assert len(ta) >= 1

    def test_finds_exported_services(self) -> None:
        services = [
            f
            for f in self.findings
            if f.check_id == "MANIFEST-006" and "Service" in f.title
        ]
        assert len(services) >= 1

    def test_finds_exported_receivers(self) -> None:
        receivers = [
            f
            for f in self.findings
            if f.check_id == "MANIFEST-006" and "Receiver" in f.title
        ]
        assert len(receivers) >= 1

    def test_critically_outdated_min_sdk(self) -> None:
        """InsecureBankv2 has minSdk=15, critically outdated."""
        sdk = [f for f in self.findings if f.check_id == "MANIFEST-005"]
        assert len(sdk) >= 1
        high_sdk = [f for f in sdk if f.severity == "high"]
        assert len(high_sdk) >= 1

    def test_total_findings_reasonable(self) -> None:
        assert 5 <= len(self.findings) <= 18


class TestOVAAExtraction:
    """Verify finding extraction for OVAA MobSF report."""

    def setup_method(self) -> None:
        self.report = _ovaa_report()
        self.findings = _extract_manifest_findings(self.report)

    def test_no_debuggable(self) -> None:
        """OVAA is not debuggable — should not produce MANIFEST-001."""
        debuggable = [f for f in self.findings if f.check_id == "MANIFEST-001"]
        assert len(debuggable) == 0

    def test_finds_allow_backup(self) -> None:
        backup = [f for f in self.findings if f.check_id == "MANIFEST-002"]
        assert len(backup) >= 1

    def test_finds_cleartext(self) -> None:
        cleartext = [f for f in self.findings if f.check_id == "MANIFEST-003"]
        assert len(cleartext) >= 1

    def test_finds_launch_mode(self) -> None:
        """OVAA has singleTask activity."""
        lm = [f for f in self.findings if f.check_id == "MANIFEST-009"]
        assert len(lm) >= 1

    def test_finds_browsable_activity(self) -> None:
        browsable = [
            f for f in self.findings if "Browsable" in f.title or "deep link" in f.title.lower()
        ]
        assert len(browsable) >= 1

    def test_finds_network_security(self) -> None:
        nsc = [f for f in self.findings if f.check_id == "MANIFEST-011"]
        assert len(nsc) >= 1

    def test_min_sdk_not_critical(self) -> None:
        """OVAA minSdk=23, so below 24 but not critically outdated."""
        sdk = [
            f
            for f in self.findings
            if f.check_id == "MANIFEST-005" and "min" in f.title.lower()
        ]
        if sdk:
            assert sdk[0].severity == "medium"


# ---------------------------------------------------------------------------
# Tests: NormalizedManifestFinding serialization
# ---------------------------------------------------------------------------


class TestFindingSerialization:
    """Verify NormalizedManifestFinding serializes correctly."""

    def test_to_dict_fields(self) -> None:
        finding = NormalizedManifestFinding(
            check_id="MANIFEST-001",
            title="Test finding",
            severity="high",
            description="Test description",
            evidence="test evidence",
            cwe_ids=["CWE-489"],
            confidence="high",
            mobsf_key="is_debuggable",
            mobsf_severity="high",
        )
        d = finding.to_dict()
        assert d["check_id"] == "MANIFEST-001"
        assert d["severity"] == "high"
        assert d["cwe_ids"] == ["CWE-489"]
        assert d["mobsf_key"] == "is_debuggable"

    def test_json_serializable(self) -> None:
        finding = NormalizedManifestFinding(
            check_id="MANIFEST-002",
            title="Test",
            severity="medium",
            description="desc",
            evidence="ev",
            cwe_ids=["CWE-921"],
            confidence="high",
            mobsf_key="is_allow_backup",
            mobsf_severity="warning",
        )
        # Should not raise
        serialized = json.dumps(finding.to_dict())
        assert "MANIFEST-002" in serialized


# ---------------------------------------------------------------------------
# Tests: MobsfScanResult
# ---------------------------------------------------------------------------


class TestMobsfScanResult:
    """Verify MobsfScanResult summary and serialization."""

    def test_empty_result(self) -> None:
        result = MobsfScanResult(success=True)
        assert result.summary["total_findings"] == 0
        assert result.summary["success"] is True

    def test_result_with_findings(self) -> None:
        findings = _extract_manifest_findings(_diva_report())
        result = MobsfScanResult(
            success=True,
            package_name="jakhar.aseem.diva",
            manifest_findings=findings,
            apk_hash="abc123",
            scan_duration_ms=1500,
        )
        assert result.summary["total_findings"] > 0
        assert result.summary["package_name"] == "jakhar.aseem.diva"
        assert result.summary["apk_hash"] == "abc123"

    def test_to_dict(self) -> None:
        findings = _extract_manifest_findings(_diva_report())
        result = MobsfScanResult(
            success=True,
            package_name="jakhar.aseem.diva",
            manifest_findings=findings,
        )
        d = result.to_dict()
        assert "manifest_findings" in d
        assert isinstance(d["manifest_findings"], list)
        assert len(d["manifest_findings"]) > 0

    def test_error_result(self) -> None:
        result = MobsfScanResult(
            success=False,
            error="Connection refused",
        )
        assert result.summary["success"] is False
        assert result.summary["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# Tests: scan_apk_from_report (offline mode)
# ---------------------------------------------------------------------------


class TestScanFromReport:
    """Verify offline report normalization via scan_apk_from_report."""

    @pytest.mark.asyncio
    async def test_from_diva_report(self) -> None:
        runner = MobsfRunner(api_url="http://unused", api_key="unused")
        result = await runner.scan_apk_from_report(
            _diva_report(), apk_hash="deadbeef"
        )
        assert result.success is True
        assert result.package_name == "jakhar.aseem.diva"
        assert len(result.manifest_findings) > 0
        assert result.apk_hash == "deadbeef"

    @pytest.mark.asyncio
    async def test_from_ovaa_report(self) -> None:
        runner = MobsfRunner(api_url="http://unused", api_key="unused")
        result = await runner.scan_apk_from_report(_ovaa_report())
        assert result.success is True
        assert result.package_name == "oversecured.ovaa"
        # OVAA should NOT have debuggable finding
        debuggable = [
            f for f in result.manifest_findings if f.check_id == "MANIFEST-001"
        ]
        assert len(debuggable) == 0


# ---------------------------------------------------------------------------
# Tests: Comparison utility
# ---------------------------------------------------------------------------


class TestCompareFindings:
    """Verify the comparison utility for Wairz vs MobSF findings."""

    def test_all_matched(self) -> None:
        wairz = [
            {"check_id": "MANIFEST-001", "title": "Debuggable", "severity": "high"},
            {"check_id": "MANIFEST-002", "title": "Backup", "severity": "medium"},
        ]
        mobsf = [
            NormalizedManifestFinding(
                check_id="MANIFEST-001",
                title="Debug",
                severity="high",
                description="",
                evidence="",
                cwe_ids=[],
                confidence="high",
                mobsf_key="is_debuggable",
                mobsf_severity="high",
            ),
            NormalizedManifestFinding(
                check_id="MANIFEST-002",
                title="Backup",
                severity="medium",
                description="",
                evidence="",
                cwe_ids=[],
                confidence="high",
                mobsf_key="is_allow_backup",
                mobsf_severity="warning",
            ),
        ]
        result = compare_findings(wairz, mobsf)
        assert result["summary"]["matched_count"] == 2
        assert result["summary"]["wairz_only_count"] == 0
        assert result["summary"]["mobsf_only_count"] == 0
        assert result["summary"]["coverage_pct"] == 100.0
        assert result["summary"]["severity_match_pct"] == 100.0

    def test_wairz_extra_coverage(self) -> None:
        wairz = [
            {"check_id": "MANIFEST-001", "title": "Debuggable", "severity": "high"},
            {"check_id": "MANIFEST-008", "title": "StrandHogg", "severity": "medium"},
        ]
        mobsf = [
            NormalizedManifestFinding(
                check_id="MANIFEST-001",
                title="Debug",
                severity="high",
                description="",
                evidence="",
                cwe_ids=[],
                confidence="high",
                mobsf_key="is_debuggable",
                mobsf_severity="high",
            ),
        ]
        result = compare_findings(wairz, mobsf)
        assert result["summary"]["matched_count"] == 1
        assert result["summary"]["wairz_only_count"] == 1
        assert result["summary"]["mobsf_only_count"] == 0

    def test_mobsf_gap(self) -> None:
        wairz: list[dict[str, Any]] = []
        mobsf = [
            NormalizedManifestFinding(
                check_id="MANIFEST-001",
                title="Debug",
                severity="high",
                description="",
                evidence="",
                cwe_ids=[],
                confidence="high",
                mobsf_key="is_debuggable",
                mobsf_severity="high",
            ),
        ]
        result = compare_findings(wairz, mobsf)
        assert result["summary"]["matched_count"] == 0
        assert result["summary"]["mobsf_only_count"] == 1

    def test_severity_mismatch(self) -> None:
        wairz = [
            {"check_id": "MANIFEST-002", "title": "Backup", "severity": "high"},
        ]
        mobsf = [
            NormalizedManifestFinding(
                check_id="MANIFEST-002",
                title="Backup",
                severity="medium",
                description="",
                evidence="",
                cwe_ids=[],
                confidence="high",
                mobsf_key="is_allow_backup",
                mobsf_severity="warning",
            ),
        ]
        result = compare_findings(wairz, mobsf)
        assert result["summary"]["severity_match_pct"] == 0.0


# ---------------------------------------------------------------------------
# Tests: Edge cases & robustness
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Verify robustness against malformed or empty MobSF reports."""

    def test_empty_report(self) -> None:
        findings = _extract_manifest_findings({})
        assert findings == []

    def test_missing_manifest_analysis(self) -> None:
        report = {"package_name": "test", "is_debuggable": True}
        findings = _extract_manifest_findings(report)
        # Should still find debuggable from top-level
        assert any(f.check_id == "MANIFEST-001" for f in findings)

    def test_manifest_analysis_not_list(self) -> None:
        report = {"manifest_analysis": "not a list"}
        findings = _extract_manifest_findings(report)
        # Should not crash, just return empty or attribute-based findings
        assert isinstance(findings, list)

    def test_null_sdk_values(self) -> None:
        report = {"min_sdk": None, "target_sdk": None}
        findings = _extract_manifest_findings(report)
        sdk = [f for f in findings if f.check_id == "MANIFEST-005"]
        assert len(sdk) == 0  # None should not produce findings

    def test_non_numeric_sdk(self) -> None:
        report = {"min_sdk": "N/A", "target_sdk": "unknown"}
        findings = _extract_manifest_findings(report)
        sdk = [f for f in findings if f.check_id == "MANIFEST-005"]
        assert len(sdk) == 0  # Non-numeric should not crash

    def test_deduplication(self) -> None:
        """Findings from both top-level and manifest_analysis should be deduped."""
        report = {
            "is_debuggable": True,
            "manifest_analysis": [
                {
                    "rule": "android_debuggable",
                    "title": "Application is debuggable",
                    "severity": "high",
                    "description": "debug on",
                    "component": [],
                },
            ],
        }
        findings = _extract_manifest_findings(report)
        debuggable = [f for f in findings if f.check_id == "MANIFEST-001"]
        # Should be deduplicated — 1-2 findings max
        assert 1 <= len(debuggable) <= 2

    def test_exported_components_as_dicts(self) -> None:
        """MobSF sometimes returns exported components as dicts."""
        report = {
            "exported_activities": [
                {"name": "com.test.Activity1", "permission": ""},
                {"name": "com.test.Activity2", "permission": ""},
            ],
        }
        findings = _extract_manifest_findings(report)
        exported = [
            f for f in findings if f.check_id == "MANIFEST-006"
        ]
        assert len(exported) >= 1

    def test_large_component_list_truncation(self) -> None:
        """Evidence should truncate large component lists."""
        report = {
            "exported_activities": [f"com.test.Activity{i}" for i in range(20)],
        }
        findings = _extract_manifest_findings(report)
        exported = [
            f
            for f in findings
            if f.check_id == "MANIFEST-006" and "Activity" in f.title
        ]
        assert len(exported) == 1
        # Should mention 20 found
        assert "20" in exported[0].title or "20" in exported[0].description
        # Evidence should truncate
        assert "+15 more" in exported[0].evidence
