"""Tests for the APK security scan test harness framework.

Validates:
  1. APK test fixture discovery (real files, synthetic, well-known)
  2. Multi-phase scan orchestration (manifest, bytecode, SAST)
  3. Per-APK result collection into structured findings report
  4. Report serialization and validation

These tests use synthetic fixtures (mock APK factory) so they run
without real APK files or androguard installed.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.harness.discovery import (
    WELL_KNOWN_APKS,
    APKFixture,
    FixtureSource,
    ScanPhase,
    discover_all,
    discover_real_apks,
    discover_synthetic_fixtures,
)
from tests.harness.orchestrator import (
    APKScanResult,
    ManifestScanner,
    PhaseFinding,
    PhaseResult,
    PhaseStatus,
    ScanConfig,
    ScanOrchestrator,
    ScanReport,
)

# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------


class TestFixtureDiscovery:
    """Test APK fixture discovery from various sources."""

    def test_discover_synthetic_fixtures(self):
        """Synthetic fixtures are discovered from apk_fixture_manifests."""
        fixtures = discover_synthetic_fixtures()
        assert len(fixtures) > 0
        # All should be marked synthetic
        for f in fixtures:
            assert f.source == FixtureSource.SYNTHETIC
            assert "synthetic" in f.tags
            assert f.fixture_def is not None

    def test_synthetic_fixtures_have_package_names(self):
        """Each synthetic fixture has a package name from its manifest."""
        fixtures = discover_synthetic_fixtures()
        for f in fixtures:
            assert f.package_name is not None, f"Fixture {f.name} missing package_name"

    def test_synthetic_fixtures_have_expected_checks(self):
        """Synthetic fixtures with expected_checks have non-empty sets."""
        fixtures = discover_synthetic_fixtures()
        checked = [f for f in fixtures if f.expected_manifest_checks]
        # We should have at least 18 single-check fixtures
        assert len(checked) >= 18, f"Expected ≥18 fixtures with checks, got {len(checked)}"

    def test_discover_real_apks_empty_dir(self, tmp_path):
        """Discovery of real APKs from an empty directory returns empty list."""
        fixtures = discover_real_apks(search_dirs=[str(tmp_path)])
        assert fixtures == []

    def test_discover_real_apks_with_files(self, tmp_path):
        """Real APK files are discovered and classified."""
        (tmp_path / "test1.apk").write_bytes(b"PK\x03\x04fake")
        (tmp_path / "test2.apk").write_bytes(b"PK\x03\x04fake2")
        (tmp_path / "not_an_apk.txt").write_text("hello")

        fixtures = discover_real_apks(search_dirs=[str(tmp_path)])
        assert len(fixtures) == 2
        names = {f.name for f in fixtures}
        assert "test1.apk" in names
        assert "test2.apk" in names

    def test_discover_real_apks_recursive(self, tmp_path):
        """Recursive discovery finds APKs in subdirectories."""
        subdir = tmp_path / "system" / "app" / "MyApp"
        subdir.mkdir(parents=True)
        (subdir / "MyApp.apk").write_bytes(b"PK\x03\x04fake")

        fixtures = discover_real_apks(search_dirs=[str(tmp_path)], recursive=True)
        assert len(fixtures) == 1
        assert fixtures[0].name == "MyApp.apk"

    def test_discover_real_apks_well_known_matching(self, tmp_path):
        """Well-known APK filenames are matched to their definitions."""
        (tmp_path / "diva.apk").write_bytes(b"PK\x03\x04fake")
        fixtures = discover_real_apks(search_dirs=[str(tmp_path)])
        assert len(fixtures) == 1
        assert fixtures[0].source == FixtureSource.WELL_KNOWN
        assert "DIVA" in fixtures[0].name
        assert "MANIFEST-001" in fixtures[0].expected_manifest_checks

    def test_discover_firmware_location_detection(self, tmp_path):
        """APKs in firmware paths get firmware_location set."""
        priv_app = tmp_path / "system" / "priv-app" / "SystemUI"
        priv_app.mkdir(parents=True)
        (priv_app / "SystemUI.apk").write_bytes(b"PK\x03\x04fake")

        fixtures = discover_real_apks(search_dirs=[str(tmp_path)])
        assert len(fixtures) == 1
        assert fixtures[0].firmware_location is not None
        assert "priv-app" in fixtures[0].firmware_location
        assert fixtures[0].is_priv_app

    def test_discover_all_combines_sources(self):
        """discover_all() combines synthetic fixtures."""
        fixtures = discover_all(include_real=False, include_synthetic=True)
        assert len(fixtures) > 0
        sources = {f.source for f in fixtures}
        assert FixtureSource.SYNTHETIC in sources

    def test_discover_all_deduplicates_by_name(self, tmp_path):
        """Fixtures with the same name are deduplicated."""
        # Create a real APK with same name as a synthetic fixture
        (tmp_path / "debuggable.apk").write_bytes(b"PK\x03\x04fake")

        fixtures = discover_all(
            search_dirs=[str(tmp_path)],
            include_real=True,
            include_synthetic=True,
        )
        names = [f.name for f in fixtures]
        assert len(names) == len(set(names)), "Duplicate names found"

    def test_discover_all_tags_filter(self):
        """Tag filtering works on discover_all."""
        # Clean fixtures should have "clean" tag
        clean = discover_all(
            include_real=False,
            include_synthetic=True,
            tags_filter={"clean"},
        )
        for f in clean:
            assert "clean" in f.tags

    def test_well_known_apks_completeness(self):
        """Well-known APK definitions cover expected apps."""
        assert "diva" in WELL_KNOWN_APKS
        assert "insecurebankv2" in WELL_KNOWN_APKS
        assert "ovaa" in WELL_KNOWN_APKS

        for key, defn in WELL_KNOWN_APKS.items():
            assert "name" in defn
            assert "package_name" in defn
            assert "expected_manifest_checks" in defn
            assert len(defn["expected_manifest_checks"]) > 0


class TestAPKFixture:
    """Test APKFixture dataclass methods."""

    def test_compute_sha256(self, tmp_path):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"test content")

        fixture = APKFixture(name="test.apk", path=str(apk))
        sha = fixture.compute_sha256()
        assert sha is not None
        assert len(sha) == 64  # SHA256 hex digest

        # Cached on second call
        assert fixture.compute_sha256() == sha

    def test_compute_sha256_no_file(self):
        fixture = APKFixture(name="missing.apk", path="/nonexistent/path.apk")
        assert fixture.compute_sha256() is None

    def test_compute_sha256_synthetic(self):
        fixture = APKFixture(name="synthetic", source=FixtureSource.SYNTHETIC)
        assert fixture.compute_sha256() is None

    def test_is_real_file(self, tmp_path):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"test")

        fixture_real = APKFixture(name="test.apk", path=str(apk))
        assert fixture_real.is_real_file

        fixture_missing = APKFixture(name="missing", path="/nonexistent")
        assert not fixture_missing.is_real_file

        fixture_none = APKFixture(name="none")
        assert not fixture_none.is_real_file

    def test_is_priv_app(self):
        fixture = APKFixture(name="test", firmware_location="/system/priv-app/Test/")
        assert fixture.is_priv_app

        fixture2 = APKFixture(name="test", firmware_location="/system/app/Test/")
        assert not fixture2.is_priv_app

    def test_is_platform_signed(self):
        fixture = APKFixture(name="test", tags={"platform-signed"})
        assert fixture.is_platform_signed

        fixture2 = APKFixture(name="test", tags=set())
        assert not fixture2.is_platform_signed


# ---------------------------------------------------------------------------
# Phase result tests
# ---------------------------------------------------------------------------


class TestPhaseResult:
    """Test PhaseResult dataclass."""

    def test_finding_count(self):
        pr = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="M-001", title="t", severity="high"),
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="M-002", title="t", severity="low"),
            ],
        )
        assert pr.finding_count == 2

    def test_severity_counts(self):
        pr = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="1", title="t", severity="high"),
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="2", title="t", severity="high"),
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="3", title="t", severity="low"),
            ],
        )
        assert pr.severity_counts == {"high": 2, "low": 1}


class TestAPKScanResult:
    """Test APKScanResult aggregation methods."""

    def _make_result(self) -> APKScanResult:
        fixture = APKFixture(
            name="test.apk",
            expected_manifest_checks={"MANIFEST-001", "MANIFEST-002"},
        )
        result = APKScanResult(fixture=fixture)
        result.phase_results[ScanPhase.MANIFEST] = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-001", title="Debug", severity="high"),
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-002", title="Backup", severity="medium"),
            ],
        )
        result.phase_results[ScanPhase.BYTECODE] = PhaseResult(
            phase=ScanPhase.BYTECODE,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.BYTECODE, check_id="BC-001", title="ECB", severity="high"),
            ],
        )
        return result

    def test_all_findings(self):
        r = self._make_result()
        assert len(r.all_findings) == 3

    def test_total_finding_count(self):
        r = self._make_result()
        assert r.total_finding_count == 3

    def test_has_errors_false(self):
        r = self._make_result()
        assert not r.has_errors

    def test_has_errors_true(self):
        r = self._make_result()
        r.phase_results[ScanPhase.SAST] = PhaseResult(
            phase=ScanPhase.SAST,
            status=PhaseStatus.ERROR,
            error="jadx not found",
        )
        assert r.has_errors

    def test_severity_counts(self):
        r = self._make_result()
        counts = r.severity_counts
        assert counts["high"] == 2
        assert counts["medium"] == 1

    def test_findings_by_phase(self):
        r = self._make_result()
        manifest = r.findings_by_phase(ScanPhase.MANIFEST)
        assert len(manifest) == 2
        bytecode = r.findings_by_phase(ScanPhase.BYTECODE)
        assert len(bytecode) == 1

    def test_check_ids_found(self):
        r = self._make_result()
        ids = r.check_ids_found(ScanPhase.MANIFEST)
        assert ids == {"MANIFEST-001", "MANIFEST-002"}

    def test_validate_expected_manifest_checks_pass(self):
        r = self._make_result()
        val = r.validate_expected_manifest_checks()
        assert val["pass"]
        assert val["missing"] == set()

    def test_validate_expected_manifest_checks_fail(self):
        fixture = APKFixture(
            name="test",
            expected_manifest_checks={"MANIFEST-001", "MANIFEST-003"},
        )
        result = APKScanResult(fixture=fixture)
        result.phase_results[ScanPhase.MANIFEST] = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-001", title="t", severity="high"),
            ],
        )
        val = result.validate_expected_manifest_checks()
        assert not val["pass"]
        assert "MANIFEST-003" in val["missing"]


# ---------------------------------------------------------------------------
# Scan report tests
# ---------------------------------------------------------------------------


class TestScanReport:
    """Test ScanReport aggregation and serialization."""

    def _make_report(self) -> ScanReport:
        config = ScanConfig(phases={ScanPhase.MANIFEST, ScanPhase.BYTECODE})
        report = ScanReport(config=config)

        # APK 1: success
        f1 = APKFixture(
            name="vuln.apk",
            source=FixtureSource.REAL_FILE,
            expected_manifest_checks={"MANIFEST-001"},
            expected_min_findings=1,
            expected_max_findings=10,
        )
        r1 = APKScanResult(fixture=f1, total_elapsed_ms=100)
        r1.phase_results[ScanPhase.MANIFEST] = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-001", title="Debug", severity="high"),
                PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-002", title="Backup", severity="medium"),
            ],
            elapsed_ms=50,
        )
        r1.phase_results[ScanPhase.BYTECODE] = PhaseResult(
            phase=ScanPhase.BYTECODE,
            status=PhaseStatus.SUCCESS,
            findings=[
                PhaseFinding(phase=ScanPhase.BYTECODE, check_id="BC-001", title="ECB", severity="high"),
            ],
            elapsed_ms=50,
        )

        # APK 2: error
        f2 = APKFixture(name="broken.apk", source=FixtureSource.REAL_FILE)
        r2 = APKScanResult(fixture=f2, total_elapsed_ms=10)
        r2.phase_results[ScanPhase.MANIFEST] = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.ERROR,
            error="Parse error",
            elapsed_ms=10,
        )

        report.results = [r1, r2]
        report.total_elapsed_ms = 110
        return report

    def test_apk_count(self):
        report = self._make_report()
        assert report.apk_count == 2

    def test_total_findings(self):
        report = self._make_report()
        assert report.total_findings == 3

    def test_error_count(self):
        report = self._make_report()
        assert report.error_count == 1

    def test_success_count(self):
        report = self._make_report()
        assert report.success_count == 1

    def test_findings_by_severity(self):
        report = self._make_report()
        by_sev = report.findings_by_severity()
        assert by_sev["high"] == 2
        assert by_sev["medium"] == 1

    def test_findings_by_phase(self):
        report = self._make_report()
        by_phase = report.findings_by_phase()
        assert by_phase[ScanPhase.MANIFEST] == 2
        assert by_phase[ScanPhase.BYTECODE] == 1

    def test_validate_all_expected(self):
        report = self._make_report()
        validations = report.validate_all_expected()
        assert len(validations) >= 1

        # Check manifest validation passes
        manifest_val = [v for v in validations if "missing" in v]
        assert len(manifest_val) == 1
        assert manifest_val[0]["pass"]

        # Check count validation passes
        count_val = [v for v in validations if v.get("check") == "total_count_bounds"]
        assert len(count_val) == 1
        assert count_val[0]["pass"]

    def test_summary_output(self):
        report = self._make_report()
        summary = report.summary()
        assert "APK SECURITY SCAN REPORT" in summary
        assert "APKs scanned:   2" in summary
        assert "Total findings: 3" in summary
        assert "vuln.apk" in summary
        assert "broken.apk" in summary

    def test_to_dict_serializable(self):
        report = self._make_report()
        d = report.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert len(json_str) > 0

        # Verify structure
        assert d["summary"]["apk_count"] == 2
        assert d["summary"]["total_findings"] == 3
        assert len(d["results"]) == 2
        assert len(d["results"][0]["findings"]) == 3

    def test_to_dict_includes_validations(self):
        report = self._make_report()
        d = report.to_dict()
        assert "validations" in d
        assert len(d["validations"]) >= 1


# ---------------------------------------------------------------------------
# Scan config tests
# ---------------------------------------------------------------------------


class TestScanConfig:
    """Test ScanConfig defaults and customization."""

    def test_default_config(self):
        config = ScanConfig()
        assert ScanPhase.MANIFEST in config.phases
        assert ScanPhase.BYTECODE in config.phases
        assert ScanPhase.SAST in config.phases
        assert config.manifest_timeout == 5.0
        assert config.bytecode_timeout == 30.0
        assert config.sast_timeout == 180.0
        assert config.min_severity == "info"
        assert not config.fail_fast

    def test_custom_config(self):
        config = ScanConfig(
            phases={ScanPhase.MANIFEST},
            min_severity="high",
            fail_fast=True,
        )
        assert config.phases == {ScanPhase.MANIFEST}
        assert config.min_severity == "high"
        assert config.fail_fast


# ---------------------------------------------------------------------------
# Orchestrator tests (unit tests with mocked scanners)
# ---------------------------------------------------------------------------


class TestScanOrchestrator:
    """Test the scan orchestrator with synthetic fixtures."""

    @pytest.fixture
    def synthetic_fixture(self):
        """A synthetic fixture from apk_fixture_manifests."""
        try:
            from tests.fixtures.apk.apk_fixture_manifests import DEBUGGABLE_APK
        except ImportError:
            pytest.skip("apk_fixture_manifests not available")

        return APKFixture(
            name="debuggable.apk",
            source=FixtureSource.SYNTHETIC,
            package_name="com.test.debuggable",
            expected_manifest_checks={"MANIFEST-001"},
            tags={"synthetic"},
            fixture_def=DEBUGGABLE_APK,
        )

    @pytest.mark.asyncio
    async def test_manifest_only_orchestration(self, synthetic_fixture):
        """Orchestrator runs manifest phase on synthetic fixture."""
        config = ScanConfig(phases={ScanPhase.MANIFEST})
        orchestrator = ScanOrchestrator(config)

        with patch("tests.harness.orchestrator.ManifestScanner.scan") as mock_scan:
            mock_scan.return_value = PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.SUCCESS,
                findings=[
                    PhaseFinding(
                        phase=ScanPhase.MANIFEST,
                        check_id="MANIFEST-001",
                        title="Debuggable",
                        severity="high",
                    ),
                ],
                elapsed_ms=10,
            )

            report = await orchestrator.run([synthetic_fixture])

        assert report.apk_count == 1
        assert report.total_findings == 1
        assert report.error_count == 0

    @pytest.mark.asyncio
    async def test_bytecode_skipped_for_synthetic(self, synthetic_fixture):
        """Bytecode phase is skipped for synthetic fixtures."""
        config = ScanConfig(
            phases={ScanPhase.MANIFEST, ScanPhase.BYTECODE},
            skip_synthetic_for_bytecode=True,
        )
        orchestrator = ScanOrchestrator(config)

        with patch("tests.harness.orchestrator.ManifestScanner.scan") as mock_scan:
            mock_scan.return_value = PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.SUCCESS,
                findings=[],
                elapsed_ms=5,
            )

            report = await orchestrator.run([synthetic_fixture])

        result = report.results[0]
        assert result.phase_status(ScanPhase.BYTECODE) == PhaseStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_sast_skipped_for_synthetic(self, synthetic_fixture):
        """SAST phase is skipped for synthetic fixtures."""
        config = ScanConfig(
            phases={ScanPhase.SAST},
            skip_synthetic_for_sast=True,
        )
        orchestrator = ScanOrchestrator(config)
        report = await orchestrator.run([synthetic_fixture])

        result = report.results[0]
        assert result.phase_status(ScanPhase.SAST) == PhaseStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_fail_fast_stops_on_error(self):
        """fail_fast=True stops after first error."""
        # Synthetic fixtures with empty fixture_def are skipped by the
        # orchestrator (should_skip True), so the ManifestScanner patch
        # would never fire. Give them a non-empty dict so the scanner
        # is actually invoked and the patched failure surfaces.
        fixtures = [
            APKFixture(name="apk1.apk", source=FixtureSource.SYNTHETIC, fixture_def={"package": "c.a"}),
            APKFixture(name="apk2.apk", source=FixtureSource.SYNTHETIC, fixture_def={"package": "c.b"}),
        ]
        config = ScanConfig(phases={ScanPhase.MANIFEST}, fail_fast=True)
        orchestrator = ScanOrchestrator(config)

        call_count = 0

        def failing_scan(fixture, **kwargs):
            nonlocal call_count
            call_count += 1
            return PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.ERROR,
                error="Simulated error",
            )

        with patch("tests.harness.orchestrator.ManifestScanner.scan", side_effect=failing_scan):
            report = await orchestrator.run(fixtures)

        # Should stop after first fixture
        assert report.apk_count == 1
        assert report.error_count == 1

    @pytest.mark.asyncio
    async def test_multi_phase_orchestration(self):
        """All three phases run for a real APK fixture."""
        fixture = APKFixture(
            name="real.apk",
            path="/tmp/real.apk",
            source=FixtureSource.REAL_FILE,
        )

        config = ScanConfig(phases={ScanPhase.MANIFEST, ScanPhase.BYTECODE, ScanPhase.SAST})
        orchestrator = ScanOrchestrator(config)

        manifest_result = PhaseResult(
            phase=ScanPhase.MANIFEST,
            status=PhaseStatus.SUCCESS,
            findings=[PhaseFinding(phase=ScanPhase.MANIFEST, check_id="M-1", title="t", severity="high")],
            elapsed_ms=10,
        )
        bytecode_result = PhaseResult(
            phase=ScanPhase.BYTECODE,
            status=PhaseStatus.SUCCESS,
            findings=[PhaseFinding(phase=ScanPhase.BYTECODE, check_id="B-1", title="t", severity="medium")],
            elapsed_ms=20,
        )
        sast_result = PhaseResult(
            phase=ScanPhase.SAST,
            status=PhaseStatus.SUCCESS,
            findings=[PhaseFinding(phase=ScanPhase.SAST, check_id="S-1", title="t", severity="low")],
            elapsed_ms=100,
        )

        with (
            patch("tests.harness.orchestrator.ManifestScanner.scan", return_value=manifest_result),
            patch("tests.harness.orchestrator.BytecodeScanner.scan", return_value=bytecode_result),
            patch("tests.harness.orchestrator.SASTScanner.scan", new_callable=AsyncMock, return_value=sast_result),
        ):
            report = await orchestrator.run([fixture])

        assert report.apk_count == 1
        result = report.results[0]
        assert result.total_finding_count == 3
        assert result.phase_status(ScanPhase.MANIFEST) == PhaseStatus.SUCCESS
        assert result.phase_status(ScanPhase.BYTECODE) == PhaseStatus.SUCCESS
        assert result.phase_status(ScanPhase.SAST) == PhaseStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_report_timing(self):
        """Report tracks timing correctly."""
        fixture = APKFixture(name="test", source=FixtureSource.SYNTHETIC, fixture_def={})
        config = ScanConfig(phases={ScanPhase.MANIFEST})
        orchestrator = ScanOrchestrator(config)

        with patch("tests.harness.orchestrator.ManifestScanner.scan") as mock_scan:
            mock_scan.return_value = PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.SUCCESS,
                elapsed_ms=5,
            )
            report = await orchestrator.run([fixture])

        assert report.started_at > 0
        assert report.finished_at >= report.started_at
        assert report.total_elapsed_ms >= 0


# ---------------------------------------------------------------------------
# Phase scanner tests (unit tests for normalization)
# ---------------------------------------------------------------------------


class TestManifestScanner:
    """Test ManifestScanner finding normalization."""

    def test_normalize_manifest_findings(self):
        from tests.harness.orchestrator import _normalize_manifest_findings

        raw = [
            {
                "check_id": "MANIFEST-001",
                "title": "Debuggable",
                "severity": "high",
                "confidence": "high",
                "description": "App is debuggable",
                "evidence": "android:debuggable=true",
                "cwe_ids": ["CWE-489"],
            },
        ]
        findings = _normalize_manifest_findings(raw)
        assert len(findings) == 1
        assert findings[0].phase == ScanPhase.MANIFEST
        assert findings[0].check_id == "MANIFEST-001"
        assert findings[0].severity == "high"
        assert findings[0].cwe_ids == ["CWE-489"]

    def test_normalize_bytecode_findings(self):
        from tests.harness.orchestrator import _normalize_bytecode_findings

        raw = [
            {
                "pattern_id": "BYTECODE-001",
                "title": "ECB Mode",
                "severity": "high",
                "confidence": "high",
                "description": "ECB cipher mode",
                "cwe_ids": ["CWE-327"],
                "category": "crypto",
                "count": 3,
                "locations": [
                    {"caller_class": "Lcom/test;", "caller_method": "encrypt"},
                ],
            },
        ]
        findings = _normalize_bytecode_findings(raw)
        assert len(findings) == 1
        assert findings[0].phase == ScanPhase.BYTECODE
        assert findings[0].check_id == "BYTECODE-001"
        assert findings[0].location is not None

    def test_normalize_sast_findings_dataclass(self):
        from tests.harness.orchestrator import _normalize_sast_findings

        # Simulate a NormalizedFinding-like dataclass
        mock_finding = MagicMock()
        mock_finding.rule_id = "android_ssl_pinning_bypass"
        mock_finding.title = "SSL Pinning Bypass"
        mock_finding.severity = "high"
        mock_finding.description = "SSL pinning disabled"
        mock_finding.evidence = "match: TrustManager"
        mock_finding.cwe_ids = ["CWE-295"]
        mock_finding.file_path = "com/test/NetworkUtils.java"
        mock_finding.line_number = 42

        findings = _normalize_sast_findings([mock_finding])
        assert len(findings) == 1
        assert findings[0].phase == ScanPhase.SAST
        assert findings[0].check_id == "android_ssl_pinning_bypass"
        assert findings[0].location["file_path"] == "com/test/NetworkUtils.java"

    def test_normalize_sast_findings_dict(self):
        from tests.harness.orchestrator import _normalize_sast_findings

        raw = [
            {
                "rule_id": "android_logging",
                "title": "Logging",
                "severity": "info",
                "description": "Debug logging",
                "evidence": "Log.d",
                "cwe_ids": ["CWE-532"],
                "file_path": "com/test/Debug.java",
                "line_number": 10,
            },
        ]
        findings = _normalize_sast_findings(raw)
        assert len(findings) == 1
        assert findings[0].check_id == "android_logging"


class TestSeverityFiltering:
    """Test severity filtering in the orchestrator."""

    def test_filter_severity(self):
        from tests.harness.orchestrator import _filter_severity

        findings = [
            PhaseFinding(phase=ScanPhase.MANIFEST, check_id="1", title="t", severity="critical"),
            PhaseFinding(phase=ScanPhase.MANIFEST, check_id="2", title="t", severity="high"),
            PhaseFinding(phase=ScanPhase.MANIFEST, check_id="3", title="t", severity="medium"),
            PhaseFinding(phase=ScanPhase.MANIFEST, check_id="4", title="t", severity="low"),
            PhaseFinding(phase=ScanPhase.MANIFEST, check_id="5", title="t", severity="info"),
        ]

        # All findings pass info threshold
        assert len(_filter_severity(findings, "info")) == 5

        # Only high and critical
        high_plus = _filter_severity(findings, "high")
        assert len(high_plus) == 2
        assert all(f.severity in ("high", "critical") for f in high_plus)

        # Only critical
        critical = _filter_severity(findings, "critical")
        assert len(critical) == 1


# ---------------------------------------------------------------------------
# Integration test: manifest scan with mock APK factory
# ---------------------------------------------------------------------------


class TestManifestScannerWithMockFactory:
    """Integration test: ManifestScanner using mock APK factory and real AndroguardService."""

    @pytest.fixture
    def debuggable_fixture(self):
        try:
            from tests.fixtures.apk.apk_fixture_manifests import DEBUGGABLE_APK
        except ImportError:
            pytest.skip("apk_fixture_manifests not available")

        return APKFixture(
            name="debuggable.apk",
            source=FixtureSource.SYNTHETIC,
            package_name="com.test.debuggable",
            expected_manifest_checks={"MANIFEST-001"},
            tags={"synthetic"},
            fixture_def=DEBUGGABLE_APK,
        )

    def test_manifest_scan_detects_debuggable(self, debuggable_fixture):
        """ManifestScanner correctly detects debuggable flag via mock factory."""
        try:
            from app.services.androguard_service import AndroguardService
        except ImportError:
            pytest.skip("androguard_service not available")

        scanner = ManifestScanner()
        result = scanner.scan(debuggable_fixture, firmware_context=False)

        assert result.status == PhaseStatus.SUCCESS
        check_ids = {f.check_id for f in result.findings}
        assert "MANIFEST-001" in check_ids

    @pytest.fixture
    def kitchen_sink_fixture(self):
        try:
            from tests.fixtures.apk.apk_fixture_manifests import KITCHEN_SINK_APK
        except ImportError:
            pytest.skip("apk_fixture_manifests not available")

        return APKFixture(
            name="kitchen_sink.apk",
            source=FixtureSource.SYNTHETIC,
            package_name="com.test.kitchensink",
            expected_manifest_checks=set(),  # Kitchen sink triggers many checks
            tags={"synthetic", "vulnerable"},
            fixture_def=KITCHEN_SINK_APK,
        )

    def test_manifest_scan_kitchen_sink_finds_many(self, kitchen_sink_fixture):
        """Kitchen sink APK triggers multiple manifest checks."""
        try:
            from app.services.androguard_service import AndroguardService
        except ImportError:
            pytest.skip("androguard_service not available")

        scanner = ManifestScanner()
        result = scanner.scan(kitchen_sink_fixture, firmware_context=False)

        assert result.status == PhaseStatus.SUCCESS
        # Kitchen sink should trigger many checks
        assert result.finding_count >= 5, (
            f"Expected ≥5 findings for kitchen sink, got {result.finding_count}"
        )


# ---------------------------------------------------------------------------
# Full pipeline test with mocked scanners
# ---------------------------------------------------------------------------


class TestFullPipelineReport:
    """Test the full pipeline producing a complete report."""

    @pytest.mark.asyncio
    async def test_full_pipeline_report_structure(self):
        """Full pipeline produces a valid structured report."""
        # Non-empty fixture_def so should_skip is False and the patched
        # ManifestScanner.scan is actually invoked for both fixtures.
        fixtures = [
            APKFixture(
                name="test_vuln.apk",
                source=FixtureSource.SYNTHETIC,
                package_name="com.test.vuln",
                expected_manifest_checks={"MANIFEST-001", "MANIFEST-002"},
                expected_min_findings=2,
                expected_max_findings=20,
                tags={"synthetic", "vulnerable"},
                fixture_def={"package": "com.test.vuln"},
            ),
            APKFixture(
                name="test_clean.apk",
                source=FixtureSource.SYNTHETIC,
                package_name="com.test.clean",
                expected_manifest_checks=set(),
                tags={"synthetic", "clean"},
                fixture_def={"package": "com.test.clean"},
            ),
        ]

        config = ScanConfig(phases={ScanPhase.MANIFEST})
        orchestrator = ScanOrchestrator(config)

        # Mock the scanner to return controlled results
        def mock_manifest_scan(fixture, **kwargs):
            if "vuln" in fixture.name:
                return PhaseResult(
                    phase=ScanPhase.MANIFEST,
                    status=PhaseStatus.SUCCESS,
                    findings=[
                        PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-001",
                                     title="Debug", severity="high", cwe_ids=["CWE-489"]),
                        PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-002",
                                     title="Backup", severity="medium", cwe_ids=["CWE-530"]),
                        PhaseFinding(phase=ScanPhase.MANIFEST, check_id="MANIFEST-003",
                                     title="Cleartext", severity="high", cwe_ids=["CWE-319"]),
                    ],
                    elapsed_ms=15,
                )
            return PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.SUCCESS,
                findings=[],
                elapsed_ms=5,
            )

        with patch("tests.harness.orchestrator.ManifestScanner.scan", side_effect=mock_manifest_scan):
            report = await orchestrator.run(fixtures)

        # Verify report structure
        assert report.apk_count == 2
        assert report.total_findings == 3
        assert report.error_count == 0

        # Verify per-APK results
        vuln_result = report.results[0]
        assert vuln_result.fixture.name == "test_vuln.apk"
        assert vuln_result.total_finding_count == 3

        clean_result = report.results[1]
        assert clean_result.fixture.name == "test_clean.apk"
        assert clean_result.total_finding_count == 0

        # Verify validation
        validations = report.validate_all_expected()
        assert len(validations) >= 1

        # Manifest check validation should pass for vuln APK
        manifest_val = [v for v in validations if v.get("fixture_name") == "test_vuln.apk" and "missing" in v]
        assert len(manifest_val) == 1
        assert manifest_val[0]["pass"]

        # Count bounds validation should pass
        count_val = [v for v in validations if v.get("check") == "total_count_bounds"]
        assert len(count_val) == 1
        assert count_val[0]["pass"]

        # Verify serialization
        d = report.to_dict()
        json_str = json.dumps(d, indent=2)
        assert len(json_str) > 0

        # Verify summary generation
        summary = report.summary()
        assert "APK SECURITY SCAN REPORT" in summary
        assert "PASS" in summary
