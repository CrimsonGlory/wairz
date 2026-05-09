"""Tests for the comparison harness CLI (wairz-compare-apk).

Validates that the comparison harness correctly:
1. Orchestrates both Wairz and MobSF runners
2. Classifies findings as match/miss/extra
3. Computes aggregate metrics (coverage, severity match, FP rate)
4. Produces correct JSON diff reports
5. Handles edge cases (errors, empty results, batch mode)

Uses mocked runner results based on DIVA, InsecureBankv2, and OVAA APKs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from app.cli.compare_apk import (
    ComparisonReport,
    FindingExtra,
    FindingMatch,
    FindingMiss,
    _compute_aggregate,
    _get_attr,
    _severity_index,
    build_comparison,
    format_json,
    format_summary,
)

# ---------------------------------------------------------------------------
# Minimal mock result dataclasses (avoid importing full runners in tests)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MockFinding:
    check_id: str = ""
    title: str = ""
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    confidence: str = "high"
    mobsf_key: str = ""


@dataclass(slots=True)
class MockWairzResult:
    success: bool = True
    package_name: str = ""
    manifest_findings: list[MockFinding] = field(default_factory=list)
    suppressed_findings: list[MockFinding] = field(default_factory=list)
    error: str | None = None
    scan_duration_ms: int = 0
    apk_hash: str = ""
    is_priv_app: bool = False
    is_platform_signed: bool = False
    severity_bumped: bool = False
    severity_reduced: bool = False
    reduced_check_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MockMobsfResult:
    success: bool = True
    package_name: str = ""
    manifest_findings: list[MockFinding] = field(default_factory=list)
    error: str | None = None
    scan_duration_ms: int = 0
    apk_hash: str = ""


# ---------------------------------------------------------------------------
# Fixtures: simulated scanner outputs for test APKs
# ---------------------------------------------------------------------------


def _diva_wairz() -> MockWairzResult:
    """Wairz findings for DIVA APK."""
    return MockWairzResult(
        success=True,
        package_name="jakhar.aseem.diva",
        apk_hash="aabb1122",
        scan_duration_ms=42,
        manifest_findings=[
            MockFinding(
                check_id="MANIFEST-001",
                title="Application is debuggable",
                severity="high",
                evidence='android:debuggable="true"',
                cwe_ids=["CWE-489"],
            ),
            MockFinding(
                check_id="MANIFEST-002",
                title="Application data can be backed up",
                severity="medium",
                evidence='android:allowBackup="true"',
                cwe_ids=["CWE-921"],
            ),
            MockFinding(
                check_id="MANIFEST-003",
                title="Cleartext traffic allowed",
                severity="high",
                evidence="targetSdkVersion=24",
                cwe_ids=["CWE-319"],
            ),
            MockFinding(
                check_id="MANIFEST-005",
                title="Minimum SDK version is 15",
                severity="low",
                evidence="android:minSdkVersion=15",
                cwe_ids=["CWE-1104"],
            ),
            MockFinding(
                check_id="MANIFEST-006",
                title="Exported Activity without permission: MainActivity",
                severity="high",
                evidence="jakhar.aseem.diva.MainActivity",
                cwe_ids=["CWE-926"],
            ),
            MockFinding(
                check_id="MANIFEST-006",
                title="Exported Content Provider without permission: NotesProvider",
                severity="high",
                evidence="jakhar.aseem.diva.NotesProvider",
                cwe_ids=["CWE-926"],
            ),
        ],
    )


def _diva_mobsf() -> MockMobsfResult:
    """MobSF findings for DIVA APK."""
    return MockMobsfResult(
        success=True,
        package_name="jakhar.aseem.diva",
        apk_hash="aabb1122",
        scan_duration_ms=1500,
        manifest_findings=[
            MockFinding(
                check_id="MANIFEST-001",
                title="Debug Enabled For App",
                severity="high",
                evidence='android:debuggable="true"',
                cwe_ids=["CWE-489"],
                mobsf_key="is_debuggable",
            ),
            MockFinding(
                check_id="MANIFEST-002",
                title="Application Data can be Backed up",
                severity="medium",
                evidence='android:allowBackup="true"',
                cwe_ids=["CWE-921"],
                mobsf_key="is_allow_backup",
            ),
            MockFinding(
                check_id="MANIFEST-003",
                title="Cleartext Traffic Allowed",
                severity="high",
                evidence='android:usesCleartextTraffic="true"',
                cwe_ids=["CWE-319"],
                mobsf_key="is_clear_text_traffic",
            ),
            MockFinding(
                check_id="MANIFEST-005",
                title="Minimum SDK version is 15",
                severity="high",  # MobSF rates min_sdk=15 as high
                evidence='android:minSdkVersion="15"',
                cwe_ids=["CWE-1104"],
                mobsf_key="min_sdk",
            ),
            MockFinding(
                check_id="MANIFEST-006",
                title="Exported Activities without permission (5 found)",
                severity="high",
                evidence="jakhar.aseem.diva.MainActivity, ...",
                cwe_ids=["CWE-926"],
                mobsf_key="exported_activities",
            ),
        ],
    )


def _ovaa_wairz() -> MockWairzResult:
    """Wairz findings for OVAA APK."""
    return MockWairzResult(
        success=True,
        package_name="oversecured.ovaa",
        apk_hash="ccdd3344",
        scan_duration_ms=35,
        manifest_findings=[
            MockFinding(
                check_id="MANIFEST-002",
                title="Application data can be backed up",
                severity="medium",
                cwe_ids=["CWE-921"],
            ),
            MockFinding(
                check_id="MANIFEST-003",
                title="Cleartext traffic allowed",
                severity="high",
                cwe_ids=["CWE-319"],
            ),
            MockFinding(
                check_id="MANIFEST-006",
                title="Exported Activity: LoginActivity",
                severity="high",
                cwe_ids=["CWE-926"],
            ),
            MockFinding(
                check_id="MANIFEST-010",
                title="Browsable deep link without autoVerify",
                severity="medium",
                cwe_ids=["CWE-939"],
                confidence="medium",
            ),
        ],
    )


def _ovaa_mobsf() -> MockMobsfResult:
    """MobSF findings for OVAA APK."""
    return MockMobsfResult(
        success=True,
        package_name="oversecured.ovaa",
        apk_hash="ccdd3344",
        scan_duration_ms=2000,
        manifest_findings=[
            MockFinding(
                check_id="MANIFEST-002",
                title="Application Data can be Backed up",
                severity="medium",
                cwe_ids=["CWE-921"],
                mobsf_key="is_allow_backup",
            ),
            MockFinding(
                check_id="MANIFEST-003",
                title="Cleartext Traffic Allowed",
                severity="high",
                cwe_ids=["CWE-319"],
                mobsf_key="is_clear_text_traffic",
            ),
            MockFinding(
                check_id="MANIFEST-006",
                title="Exported Activities (3 found)",
                severity="high",
                cwe_ids=["CWE-926"],
                mobsf_key="exported_activities",
            ),
            MockFinding(
                check_id="MANIFEST-009",
                title="Activity with singleTask launch mode",
                severity="medium",
                cwe_ids=["CWE-1021"],
                mobsf_key="launch_mode",
            ),
            MockFinding(
                check_id="MANIFEST-011",
                title="No certificate pinning configured",
                severity="medium",
                cwe_ids=["CWE-295"],
                mobsf_key="network_security",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Tests: FindingMatch / FindingMiss / FindingExtra dataclasses
# ---------------------------------------------------------------------------


class TestFindingDataclasses:
    """Verify finding classification dataclasses serialize correctly."""

    def test_match_to_dict(self):
        m = FindingMatch(
            check_id="MANIFEST-001",
            wairz_title="Debuggable",
            wairz_severity="high",
            mobsf_title="Debug Enabled",
            mobsf_severity="high",
            severity_match=True,
            severity_delta=0,
        )
        d = m.to_dict()
        assert d["classification"] == "match"
        assert d["check_id"] == "MANIFEST-001"
        assert d["wairz"]["severity"] == "high"
        assert d["mobsf"]["severity"] == "high"
        assert d["severity_match"] is True

    def test_miss_to_dict(self):
        m = FindingMiss(
            check_id="MANIFEST-009",
            mobsf_title="singleTask launch",
            mobsf_severity="medium",
            mobsf_key="launch_mode",
        )
        d = m.to_dict()
        assert d["classification"] == "miss"
        assert d["check_id"] == "MANIFEST-009"
        assert d["mobsf"]["mobsf_key"] == "launch_mode"

    def test_extra_to_dict(self):
        e = FindingExtra(
            check_id="MANIFEST-010",
            wairz_title="Deep link without verify",
            wairz_severity="medium",
            wairz_confidence="medium",
        )
        d = e.to_dict()
        assert d["classification"] == "extra"
        assert d["wairz"]["confidence"] == "medium"


# ---------------------------------------------------------------------------
# Tests: ComparisonReport
# ---------------------------------------------------------------------------


class TestComparisonReport:
    """Verify ComparisonReport serialization and verdicts."""

    def test_empty_report_to_dict(self):
        r = ComparisonReport(
            apk_path="/test.apk",
            wairz_success=True,
            mobsf_success=True,
        )
        d = r.to_dict()
        assert d["meta"]["apk_path"] == "/test.apk"
        assert d["summary"]["match_count"] == 0
        assert d["summary"]["verdict"] == "PASS: Full coverage match"

    def test_verdict_gaps(self):
        r = ComparisonReport(wairz_success=True, mobsf_success=True)
        r.misses = [
            FindingMiss(check_id="MANIFEST-001", mobsf_title="Debug"),
        ]
        assert "GAPS" in r._verdict()

    def test_verdict_pass_with_extras(self):
        r = ComparisonReport(wairz_success=True, mobsf_success=True)
        r.extras = [
            FindingExtra(check_id="MANIFEST-010", wairz_title="Deep link"),
        ]
        assert "PASS+EXTRA" in r._verdict()

    def test_verdict_wairz_error(self):
        r = ComparisonReport(wairz_success=False, wairz_error="parse error")
        assert "ERROR" in r._verdict()

    def test_full_report_json_serializable(self):
        r = ComparisonReport(
            apk_path="/test.apk",
            wairz_success=True,
            mobsf_success=True,
            wairz_total=3,
            mobsf_total=2,
        )
        r.matches = [
            FindingMatch(check_id="MANIFEST-001", severity_match=True),
        ]
        r.extras = [
            FindingExtra(check_id="MANIFEST-010"),
        ]
        # Should not raise
        serialized = json.dumps(r.to_dict())
        parsed = json.loads(serialized)
        assert parsed["summary"]["match_count"] == 1
        assert parsed["summary"]["extra_count"] == 1


# ---------------------------------------------------------------------------
# Tests: build_comparison (core logic)
# ---------------------------------------------------------------------------


class TestBuildComparison:
    """Verify the core comparison logic with DIVA and OVAA fixtures."""

    def test_diva_comparison(self):
        """DIVA: both scanners find similar issues."""
        report = build_comparison(
            _diva_wairz(),
            _diva_mobsf(),
            apk_path="/diva.apk",
        )

        assert report.wairz_success is True
        assert report.mobsf_success is True
        assert report.package_name == "jakhar.aseem.diva"

        # Both found MANIFEST-001 (debuggable)
        match_ids = {m.check_id for m in report.matches}
        assert "MANIFEST-001" in match_ids
        assert "MANIFEST-002" in match_ids
        assert "MANIFEST-003" in match_ids
        assert "MANIFEST-005" in match_ids
        assert "MANIFEST-006" in match_ids

        # Should have no misses (Wairz covers all MobSF findings for DIVA)
        assert len(report.misses) == 0

        # Coverage should be 100% (no gaps)
        assert report.coverage_pct == 100.0

    def test_diva_severity_mismatch(self):
        """DIVA MANIFEST-005: Wairz=low vs MobSF=high."""
        report = build_comparison(_diva_wairz(), _diva_mobsf())

        sdk_matches = [m for m in report.matches if m.check_id == "MANIFEST-005"]
        assert len(sdk_matches) >= 1
        # Wairz rates minSdk=15 as low, MobSF as high
        sdk = sdk_matches[0]
        assert sdk.severity_match is False
        assert sdk.severity_delta < 0  # Wairz less severe

    def test_ovaa_has_misses(self):
        """OVAA: MobSF finds MANIFEST-009 and MANIFEST-011 that Wairz doesn't."""
        report = build_comparison(
            _ovaa_wairz(),
            _ovaa_mobsf(),
            apk_path="/ovaa.apk",
        )

        miss_ids = {m.check_id for m in report.misses}
        assert "MANIFEST-009" in miss_ids  # singleTask launch mode
        assert "MANIFEST-011" in miss_ids  # network security

    def test_ovaa_has_extras(self):
        """OVAA: Wairz finds MANIFEST-010 (deep links) that MobSF doesn't."""
        report = build_comparison(_ovaa_wairz(), _ovaa_mobsf())

        extra_ids = {e.check_id for e in report.extras}
        assert "MANIFEST-010" in extra_ids

    def test_ovaa_coverage_below_100(self):
        """OVAA: coverage < 100% because of MobSF-only findings."""
        report = build_comparison(_ovaa_wairz(), _ovaa_mobsf())

        # MobSF has 5 findings across 5 check_ids, Wairz matches 3 of those
        # So coverage = matched / (matched + missed)
        assert report.coverage_pct < 100.0
        assert report.coverage_pct > 0.0

    def test_both_failed(self):
        """Both scanners fail — report shows errors, no findings."""
        w = MockWairzResult(success=False, error="parse error")
        m = MockMobsfResult(success=False, error="API timeout")
        report = build_comparison(w, m)

        assert report.wairz_success is False
        assert report.mobsf_success is False
        assert len(report.matches) == 0
        assert len(report.misses) == 0
        assert len(report.extras) == 0
        assert "ERROR" in report._verdict()

    def test_wairz_failed_mobsf_ok(self):
        """Wairz fails, MobSF succeeds — graceful error."""
        w = MockWairzResult(success=False, error="File not found")
        m = _diva_mobsf()
        report = build_comparison(w, m)
        assert report.wairz_success is False
        assert report.mobsf_success is True
        assert len(report.matches) == 0

    def test_empty_findings_both(self):
        """Both scanners produce no findings."""
        w = MockWairzResult(success=True, package_name="clean.app")
        m = MockMobsfResult(success=True, package_name="clean.app")
        report = build_comparison(w, m)

        assert len(report.matches) == 0
        assert len(report.misses) == 0
        assert len(report.extras) == 0
        assert report.coverage_pct == 100.0  # No gaps = 100%

    def test_firmware_context_preserved(self):
        """Firmware context metadata flows through to report."""
        w = MockWairzResult(
            success=True,
            severity_bumped=True,
            severity_reduced=True,
        )
        m = MockMobsfResult(success=True)
        report = build_comparison(
            w, m,
            is_priv_app=True,
            is_platform_signed=True,
        )

        assert report.is_priv_app is True
        assert report.is_platform_signed is True
        assert report.severity_bumped is True
        assert report.severity_reduced is True

        d = report.to_dict()
        assert d["firmware_context"]["is_priv_app"] is True

    def test_manifest_unk_skipped_for_gaps(self):
        """MANIFEST-UNK findings from MobSF are not counted as gaps."""
        w = MockWairzResult(success=True)
        m = MockMobsfResult(
            success=True,
            manifest_findings=[
                MockFinding(
                    check_id="MANIFEST-UNK",
                    title="Unknown MobSF rule",
                    severity="info",
                    mobsf_key="some_unknown_rule",
                ),
            ],
        )
        report = build_comparison(w, m)
        assert len(report.misses) == 0  # MANIFEST-UNK not a gap

    def test_multiple_wairz_findings_same_check(self):
        """Multiple Wairz findings for same check_id all get matched."""
        w = MockWairzResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-006", title="Exported Activity: A"),
                MockFinding(check_id="MANIFEST-006", title="Exported Activity: B"),
                MockFinding(check_id="MANIFEST-006", title="Exported Provider: C"),
            ],
        )
        m = MockMobsfResult(
            success=True,
            manifest_findings=[
                MockFinding(
                    check_id="MANIFEST-006",
                    title="Exported Activities (3)",
                    severity="high",
                ),
            ],
        )
        report = build_comparison(w, m)
        # All 3 Wairz MANIFEST-006 findings should match against MobSF
        assert len(report.matches) == 3
        assert all(m.check_id == "MANIFEST-006" for m in report.matches)


# ---------------------------------------------------------------------------
# Tests: Severity comparison helpers
# ---------------------------------------------------------------------------


class TestSeverityHelpers:
    def test_severity_index_ordering(self):
        assert _severity_index("info") < _severity_index("low")
        assert _severity_index("low") < _severity_index("medium")
        assert _severity_index("medium") < _severity_index("high")
        assert _severity_index("high") < _severity_index("critical")

    def test_severity_index_unknown(self):
        assert _severity_index("banana") == 0

    def test_get_attr_dataclass(self):
        f = MockFinding(check_id="TEST", severity="high")
        assert _get_attr(f, "check_id") == "TEST"
        assert _get_attr(f, "severity") == "high"
        assert _get_attr(f, "nonexistent", "default") == "default"

    def test_get_attr_dict(self):
        d = {"check_id": "TEST", "severity": "high"}
        assert _get_attr(d, "check_id") == "TEST"
        assert _get_attr(d, "missing", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# Tests: Output formatting
# ---------------------------------------------------------------------------


class TestFormatJson:
    """Verify JSON output format."""

    def test_single_report(self):
        report = ComparisonReport(
            apk_path="/test.apk",
            wairz_success=True,
            mobsf_success=True,
        )
        output = format_json([report])
        parsed = json.loads(output)
        assert "meta" in parsed
        assert "diff" in parsed
        assert "summary" in parsed
        # Single report = no "batch" wrapper
        assert "batch" not in parsed

    def test_batch_report(self):
        r1 = ComparisonReport(apk_path="/a.apk", wairz_success=True, mobsf_success=True)
        r2 = ComparisonReport(apk_path="/b.apk", wairz_success=True, mobsf_success=True)
        output = format_json([r1, r2])
        parsed = json.loads(output)
        assert parsed["batch"] is True
        assert parsed["apk_count"] == 2
        assert len(parsed["reports"]) == 2
        assert "aggregate" in parsed


class TestFormatSummary:
    """Verify human-readable summary output."""

    def test_single_report_summary(self):
        report = build_comparison(_diva_wairz(), _diva_mobsf(), apk_path="/diva.apk")
        output = format_summary([report])
        assert "jakhar.aseem.diva" in output
        assert "MATCH" in output or "Coverage" in output
        assert "Verdict:" in output

    def test_summary_shows_firmware_context(self):
        w = MockWairzResult(success=True, severity_bumped=True)
        m = MockMobsfResult(success=True)
        report = build_comparison(w, m, is_priv_app=True)
        output = format_summary([report])
        assert "priv-app" in output

    def test_summary_shows_misses(self):
        report = build_comparison(_ovaa_wairz(), _ovaa_mobsf())
        output = format_summary([report])
        assert "MISS" in output

    def test_batch_summary_aggregate(self):
        r1 = build_comparison(_diva_wairz(), _diva_mobsf())
        r2 = build_comparison(_ovaa_wairz(), _ovaa_mobsf())
        output = format_summary([r1, r2])
        assert "AGGREGATE" in output


# ---------------------------------------------------------------------------
# Tests: Aggregate computation
# ---------------------------------------------------------------------------


class TestComputeAggregate:
    def test_basic_aggregate(self):
        r1 = build_comparison(_diva_wairz(), _diva_mobsf())
        r2 = build_comparison(_ovaa_wairz(), _ovaa_mobsf())
        agg = _compute_aggregate([r1, r2])

        assert agg["apk_count"] == 2
        assert agg["successful_scans"] == 2
        assert agg["total_matches"] > 0
        assert agg["avg_coverage_pct"] > 0

    def test_empty_aggregate(self):
        agg = _compute_aggregate([])
        assert agg["apk_count"] == 0
        assert agg["avg_coverage_pct"] == 0.0


# ---------------------------------------------------------------------------
# Tests: False positive rate
# ---------------------------------------------------------------------------


class TestFalsePositiveRate:
    def test_no_low_confidence_extras_means_zero_fp(self):
        """High-confidence extras are not false positives."""
        w = MockWairzResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-001", confidence="high"),
                MockFinding(check_id="MANIFEST-010", confidence="high"),
            ],
        )
        m = MockMobsfResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-001"),
            ],
        )
        report = build_comparison(w, m)
        assert report.false_positive_rate == 0.0

    def test_low_confidence_extras_counted_as_fp(self):
        """Low-confidence Wairz-only findings contribute to FP rate."""
        w = MockWairzResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-001", confidence="high"),
                MockFinding(check_id="MANIFEST-099", confidence="low"),
            ],
        )
        m = MockMobsfResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-001"),
            ],
        )
        report = build_comparison(w, m)
        # 1 low-confidence extra out of 2 total Wairz findings = 50% FP
        assert report.false_positive_rate == 50.0


# ---------------------------------------------------------------------------
# Tests: CLI argument parser
# ---------------------------------------------------------------------------


class TestCLIParser:
    def test_minimal_args(self):
        from app.cli.compare_apk import build_parser
        parser = build_parser()
        args = parser.parse_args(["test.apk", "--mobsf-report", "report.json"])
        assert args.apk_paths == ["test.apk"]
        assert args.mobsf_report == "report.json"

    def test_batch_args(self):
        from app.cli.compare_apk import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "a.apk", "b.apk",
            "--mobsf-report-dir", "/reports/",
            "--priv-app",
            "--platform-signed",
            "--format", "both",
            "-o", "output.json",
        ])
        assert len(args.apk_paths) == 2
        assert args.priv_app is True
        assert args.platform_signed is True
        assert args.format == "both"
        assert args.output == "output.json"

    def test_live_api_args(self):
        from app.cli.compare_apk import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "test.apk",
            "--mobsf-url", "http://localhost:8000",
            "--mobsf-key", "secret",
        ])
        assert args.mobsf_url == "http://localhost:8000"
        assert args.mobsf_key == "secret"

    def test_verbose_flag(self):
        from app.cli.compare_apk import build_parser
        parser = build_parser()
        args = parser.parse_args(["test.apk", "-v", "--mobsf-report", "r.json"])
        assert args.verbose is True


# ---------------------------------------------------------------------------
# Tests: Integration with real runner dataclasses
# ---------------------------------------------------------------------------


class TestIntegrationWithRunners:
    """Verify comparison works with actual WairzScanResult and MobsfScanResult."""

    def test_with_wairz_runner_types(self):
        """Build comparison using actual NormalizedWairzFinding objects."""
        from app.services.wairz_runner import NormalizedWairzFinding, WairzScanResult

        wairz = WairzScanResult(
            success=True,
            package_name="test.app",
            manifest_findings=[
                NormalizedWairzFinding(
                    check_id="MANIFEST-001",
                    title="Debuggable",
                    severity="high",
                    description="Debug flag set.",
                    evidence='android:debuggable="true"',
                    cwe_ids=["CWE-489"],
                    confidence="high",
                ),
            ],
            apk_hash="abc123",
            scan_duration_ms=42,
        )

        mobsf = MockMobsfResult(
            success=True,
            package_name="test.app",
            manifest_findings=[
                MockFinding(
                    check_id="MANIFEST-001",
                    title="Debug Enabled",
                    severity="high",
                    cwe_ids=["CWE-489"],
                ),
            ],
        )

        report = build_comparison(wairz, mobsf)
        assert len(report.matches) == 1
        assert report.matches[0].check_id == "MANIFEST-001"
        assert report.apk_hash == "abc123"

    def test_with_mobsf_runner_types(self):
        """Build comparison using actual NormalizedManifestFinding objects."""
        from app.services.mobsf_runner import MobsfScanResult, NormalizedManifestFinding

        wairz = MockWairzResult(
            success=True,
            manifest_findings=[
                MockFinding(check_id="MANIFEST-001", severity="high"),
            ],
        )

        mobsf = MobsfScanResult(
            success=True,
            package_name="test.app",
            manifest_findings=[
                NormalizedManifestFinding(
                    check_id="MANIFEST-001",
                    title="Debug Enabled",
                    severity="high",
                    description="Debug on",
                    evidence='android:debuggable="true"',
                    cwe_ids=["CWE-489"],
                    confidence="high",
                    mobsf_key="is_debuggable",
                    mobsf_severity="high",
                ),
            ],
        )

        report = build_comparison(wairz, mobsf)
        assert len(report.matches) == 1
        assert report.matches[0].severity_match is True


# ---------------------------------------------------------------------------
# Tests: Report JSON structure validation
# ---------------------------------------------------------------------------


class TestReportStructure:
    """Validate the JSON report structure matches the expected schema."""

    def test_diva_full_report_structure(self):
        report = build_comparison(
            _diva_wairz(), _diva_mobsf(), apk_path="/diva.apk"
        )
        d = report.to_dict()

        # Top-level keys
        assert set(d.keys()) == {"meta", "runners", "firmware_context", "diff", "summary"}

        # Meta
        assert d["meta"]["apk_path"] == "/diva.apk"
        assert d["meta"]["harness_version"] == "1.0.0"

        # Runners
        assert d["runners"]["wairz"]["success"] is True
        assert d["runners"]["mobsf"]["success"] is True
        assert d["runners"]["wairz"]["duration_ms"] == 42
        assert d["runners"]["mobsf"]["duration_ms"] == 1500

        # Diff
        assert "matches" in d["diff"]
        assert "misses" in d["diff"]
        assert "extras" in d["diff"]

        # All diff entries have classification
        for m in d["diff"]["matches"]:
            assert m["classification"] == "match"
        for m in d["diff"]["misses"]:
            assert m["classification"] == "miss"
        for e in d["diff"]["extras"]:
            assert e["classification"] == "extra"

        # Summary
        summary = d["summary"]
        assert "total_unique_findings" in summary
        assert "match_count" in summary
        assert "miss_count" in summary
        assert "extra_count" in summary
        assert "coverage_pct" in summary
        assert "severity_match_pct" in summary
        assert "false_positive_rate" in summary
        assert "verdict" in summary

    def test_every_match_has_both_sides(self):
        """Every match entry must have both wairz and mobsf details."""
        report = build_comparison(_diva_wairz(), _diva_mobsf())
        for m in report.matches:
            d = m.to_dict()
            assert "wairz" in d
            assert "mobsf" in d
            assert "title" in d["wairz"]
            assert "severity" in d["wairz"]
            assert "title" in d["mobsf"]
            assert "severity" in d["mobsf"]
