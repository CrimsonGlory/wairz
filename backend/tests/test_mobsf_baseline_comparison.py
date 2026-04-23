"""Automated MobSF baseline comparison tests.

Runs Wairz's manifest scanner against each well-known test APK mock and
validates that the findings match the MobSF baseline JSON fixtures stored
in tests/fixtures/mobsf_baselines/.

These tests ensure that:
  1. All MobSF-reported findings are detected (no false negatives)
  2. Severity classifications match the MobSF baseline
  3. False positive rate stays below 20%
  4. Expected-absent checks are not falsely reported
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.mobsf_baselines.extract_mobsf_baselines import (
    ALL_SPECS,
    TestAPKSpec,
    compare_with_baseline,
    export_scan_result,
    normalise_to_baseline_schema,
    run_scan,
)

BASELINES_DIR = Path(__file__).resolve().parent / "fixtures" / "mobsf_baselines"


def _load_baseline(spec: TestAPKSpec) -> dict[str, Any]:
    """Load the MobSF baseline JSON for a given APK spec."""
    path = BASELINES_DIR / spec.baseline_file
    assert path.exists(), f"Baseline fixture missing: {path}"
    with open(path) as f:
        return json.load(f)


def _run_and_compare(spec: TestAPKSpec) -> dict[str, Any]:
    """Run scanner, export, load baseline, and compare."""
    result = run_scan(spec)
    scan_export = export_scan_result(spec, result)
    baseline = _load_baseline(spec)
    return compare_with_baseline(spec, scan_export, baseline)


# ---------------------------------------------------------------------------
# Parametrized test suite — runs against all three test APKs
# ---------------------------------------------------------------------------


@pytest.fixture(params=[s.name for s in ALL_SPECS], ids=[s.name for s in ALL_SPECS])
def spec(request) -> TestAPKSpec:
    """Parametrized fixture returning each TestAPKSpec."""
    return next(s for s in ALL_SPECS if s.name == request.param)


@pytest.fixture
def comparison(spec: TestAPKSpec) -> dict[str, Any]:
    """Run the scanner and return the comparison result."""
    return _run_and_compare(spec)


class TestMobSFBaselineDetection:
    """Verify all MobSF-reported findings are detected by Wairz scanner."""

    def test_no_missing_findings(self, comparison: dict[str, Any]) -> None:
        """Every MobSF baseline finding must be detected by our scanner."""
        missing = comparison["missing_from_scan"]
        assert len(missing) == 0, (
            f"{comparison['apk_name']}: Missing {len(missing)} MobSF findings: "
            + ", ".join(f"{m['check_id']}({m['baseline_title']})" for m in missing)
        )

    def test_detection_rate_100pct(self, comparison: dict[str, Any]) -> None:
        """Every baseline check_id must be detected by the scanner.

        Severity mismatches still count as detections — the check ID is
        found; a severity difference is a separate concern validated by
        ``TestMobSFBaselineSeverity``. This matches the semantics of
        ``missing_from_scan`` (empty ⇒ nothing missing ⇒ full detection).
        """
        missing = comparison["missing_from_scan"]
        assert len(missing) == 0, (
            f"{comparison['apk_name']}: "
            f"Missing {len(missing)} baseline check_ids: "
            + ", ".join(
                f"{m['check_id']}({m.get('baseline_title', '?')})"
                for m in missing
            )
        )


class TestMobSFBaselineSeverity:
    """Verify severity classifications match MobSF baseline."""

    def test_severity_match_rate(self, comparison: dict[str, Any]) -> None:
        """At least 80% of matched findings should have exact severity match.

        Some variance is acceptable (e.g., MobSF may report 'info' where we
        report 'low' for borderline cases).
        """
        rate = comparison["metrics"]["severity_match_rate"]
        assert rate >= 0.8, (
            f"{comparison['apk_name']}: Severity match rate {rate*100:.1f}% < 80%. "
            f"Mismatches: {comparison['severity_mismatches']}"
        )

    def test_no_critical_severity_downgrades(self, comparison: dict[str, Any]) -> None:
        """High-severity baseline findings should not be downgraded to low/info."""
        for m in comparison["matched"]:
            if m["baseline_severity"] in ("high", "critical"):
                assert m["scan_severity"] not in ("low", "info"), (
                    f"{comparison['apk_name']}: {m['check_id']} "
                    f"baseline={m['baseline_severity']} but scan={m['scan_severity']}"
                )


class TestMobSFBaselineFalsePositives:
    """Verify false positive rate is within acceptable bounds."""

    def test_fp_within_tolerance(self, comparison: dict[str, Any]) -> None:
        """False positive count must not exceed the baseline's tolerance."""
        m = comparison["metrics"]
        assert m["fp_within_tolerance"], (
            f"{comparison['apk_name']}: "
            f"{m['false_positive_count']} FPs exceed tolerance {m['fp_tolerance']}"
        )

    def test_fp_rate_under_20pct(self, comparison: dict[str, Any]) -> None:
        """False positive rate must be under 20%."""
        rate = comparison["metrics"]["false_positive_rate"]
        assert rate < 0.20, (
            f"{comparison['apk_name']}: FP rate {rate*100:.1f}% >= 20%"
        )

    def test_expected_absent_not_found(self, comparison: dict[str, Any]) -> None:
        """Checks listed in expected_absent should not appear in scan results."""
        fps = comparison["false_positives"]
        assert len(fps) == 0, (
            f"{comparison['apk_name']}: Found {len(fps)} false positives: "
            + ", ".join(f"{fp['check_id']}" for fp in fps)
        )


class TestMobSFBaselineOverallVerdict:
    """Overall pass/fail verdict."""

    def test_verdict_pass(self, comparison: dict[str, Any]) -> None:
        """Each APK comparison should produce a PASS verdict."""
        assert comparison["verdict"] == "PASS", (
            f"{comparison['apk_name']}: Verdict is {comparison['verdict']}. "
            f"Missing={len(comparison['missing_from_scan'])}, "
            f"FPs={comparison['metrics']['false_positive_count']}"
        )


# ---------------------------------------------------------------------------
# Individual APK fixture export tests (non-parametrized)
# ---------------------------------------------------------------------------


class TestBaselineFixtureIntegrity:
    """Verify the baseline JSON fixtures are well-formed."""

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_baseline_has_required_keys(self, spec: TestAPKSpec) -> None:
        """Each baseline JSON must have _meta, mobsf_findings, expected_absent, summary."""
        baseline = _load_baseline(spec)
        for key in ("_meta", "mobsf_findings", "expected_absent", "summary"):
            assert key in baseline, f"{spec.name}: Missing key '{key}' in baseline"

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_baseline_findings_have_required_fields(self, spec: TestAPKSpec) -> None:
        """Each finding in mobsf_findings must have issue_title, severity, category, wairz_check_id."""
        baseline = _load_baseline(spec)
        for i, finding in enumerate(baseline["mobsf_findings"]):
            for field in ("issue_title", "severity", "category", "wairz_check_id"):
                assert field in finding, (
                    f"{spec.name}: Finding[{i}] missing field '{field}'"
                )
            assert finding["severity"] in (
                "critical", "high", "medium", "low", "info"
            ), f"{spec.name}: Finding[{i}] invalid severity '{finding['severity']}'"

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_baseline_summary_consistency(self, spec: TestAPKSpec) -> None:
        """Summary total_findings should match len(mobsf_findings)."""
        baseline = _load_baseline(spec)
        actual = len(baseline["mobsf_findings"])
        declared = baseline["summary"]["total_findings"]
        assert actual == declared, (
            f"{spec.name}: Summary says {declared} findings but has {actual}"
        )

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_baseline_severity_distribution(self, spec: TestAPKSpec) -> None:
        """Summary severity counts should match actual findings."""
        baseline = _load_baseline(spec)
        actual_counts: dict[str, int] = {}
        for f in baseline["mobsf_findings"]:
            sev = f["severity"]
            actual_counts[sev] = actual_counts.get(sev, 0) + 1

        declared = baseline["summary"]["by_severity"]
        for sev, count in actual_counts.items():
            assert declared.get(sev, 0) == count, (
                f"{spec.name}: Summary says {declared.get(sev, 0)} {sev} but "
                f"found {count}"
            )


# ---------------------------------------------------------------------------
# Schema normalisation tests
# ---------------------------------------------------------------------------


class TestBaselineSchemaNormalization:
    """Verify that normalise_to_baseline_schema produces MobSF-compatible output."""

    _BASELINE_REQUIRED_FIELDS = {
        "issue_title", "severity", "category", "wairz_check_id",
        "mobsf_rule", "cwe_ids", "description", "evidence_pattern",
    }

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_normalised_findings_have_baseline_fields(self, spec: TestAPKSpec) -> None:
        """Each normalised finding must have all MobSF baseline schema fields."""
        result = run_scan(spec)
        for i, finding in enumerate(result["findings"]):
            normalised = normalise_to_baseline_schema(finding)
            missing = self._BASELINE_REQUIRED_FIELDS - set(normalised.keys())
            assert not missing, (
                f"{spec.name}: Finding[{i}] ({finding['check_id']}) normalised "
                f"output missing fields: {missing}"
            )

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_normalised_category_is_manifest(self, spec: TestAPKSpec) -> None:
        """All manifest findings should have category='manifest'."""
        result = run_scan(spec)
        for finding in result["findings"]:
            normalised = normalise_to_baseline_schema(finding)
            assert normalised["category"] == "manifest"

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_normalised_check_id_matches(self, spec: TestAPKSpec) -> None:
        """wairz_check_id in normalised output must match original check_id."""
        result = run_scan(spec)
        for finding in result["findings"]:
            normalised = normalise_to_baseline_schema(finding)
            assert normalised["wairz_check_id"] == finding["check_id"]

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_export_includes_mobsf_findings(self, spec: TestAPKSpec) -> None:
        """export_scan_result must include mobsf_findings in baseline schema."""
        result = run_scan(spec)
        export = export_scan_result(spec, result)
        assert "mobsf_findings" in export, "Export missing 'mobsf_findings' key"
        assert "mobsf_findings_by_check" in export, "Export missing 'mobsf_findings_by_check' key"
        assert len(export["mobsf_findings"]) == export["total_findings"]

    @pytest.mark.parametrize("spec", ALL_SPECS, ids=[s.name for s in ALL_SPECS])
    def test_mobsf_findings_match_internal_findings_count(self, spec: TestAPKSpec) -> None:
        """mobsf_findings and findings should have the same count."""
        result = run_scan(spec)
        export = export_scan_result(spec, result)
        assert len(export["mobsf_findings"]) == len(export["findings"])
