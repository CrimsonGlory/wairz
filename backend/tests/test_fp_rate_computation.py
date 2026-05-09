"""Tests for multi-phase false-positive rate computation.

Validates that the FP rate computation logic correctly:
  1. Classifies findings as TP/FP/FN based on ground-truth annotations
  2. Computes per-phase FP rates and detection rates
  3. Computes aggregate FP rates across phases (weighted by finding count)
  4. Applies pass/fail thresholds correctly
  5. Formats summary tables with correct data
  6. Handles edge cases (empty findings, all FP, all FN, etc.)
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.mobsf_baselines.fp_rate_computation import (
    PHASE_BYTECODE,
    PHASE_MANIFEST,
    PHASE_SAST,
    AggregateResult,
    MultiAPKSummary,
    PhaseResult,
    aggregate_result_to_dict,
    compute_aggregate_fp_rate,
    compute_bytecode_fp_rate,
    compute_manifest_fp_rate,
    compute_multi_apk_summary,
    compute_phase_fp_rate,
    compute_sast_fp_rate,
    format_failure_details,
    format_summary_table,
    load_manifest_baseline,
    load_phase_baseline,
    multi_apk_summary_to_dict,
    phase_result_to_dict,
)

# ---------------------------------------------------------------------------
# Fixtures — minimal ground-truth baselines for unit testing
# ---------------------------------------------------------------------------


@pytest.fixture
def manifest_baseline() -> dict[str, Any]:
    """Minimal manifest baseline for testing."""
    return {
        "_meta": {"apk_name": "TestApp"},
        "mobsf_findings": [
            {
                "issue_title": "Debuggable",
                "severity": "high",
                "category": "manifest",
                "wairz_check_id": "MANIFEST-001",
                "mobsf_rule": "android_debuggable",
                "cwe_ids": ["CWE-215"],
                "description": "Test",
                "evidence_pattern": "test",
            },
            {
                "issue_title": "AllowBackup",
                "severity": "medium",
                "category": "manifest",
                "wairz_check_id": "MANIFEST-002",
                "mobsf_rule": "android_allowbackup",
                "cwe_ids": ["CWE-921"],
                "description": "Test",
                "evidence_pattern": "test",
            },
            {
                "issue_title": "Cleartext",
                "severity": "high",
                "category": "manifest",
                "wairz_check_id": "MANIFEST-003",
                "mobsf_rule": "android_cleartext",
                "cwe_ids": ["CWE-319"],
                "description": "Test",
                "evidence_pattern": "test",
            },
        ],
        "expected_absent": [
            {
                "wairz_check_id": "MANIFEST-004",
                "reason": "App does not set testOnly",
            },
        ],
        "summary": {
            "total_findings": 3,
            "by_severity": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
            "false_positive_tolerance": 1,
            "max_acceptable_total": 4,
            "max_fp_rate": 0.20,
        },
    }


@pytest.fixture
def bytecode_baseline() -> dict[str, Any]:
    """Minimal bytecode baseline for testing."""
    return {
        "_meta": {"apk_name": "TestApp", "phase": "bytecode"},
        "true_positive_pattern_ids": [
            "crypto_ecb_mode",
            "hardcoded_sharedprefs",
            "logging_sensitive_data",
        ],
        "expected_absent_pattern_ids": [
            {
                "pattern_id": "webview_js_enabled",
                "reason": "App has no WebView",
            },
        ],
        "summary": {
            "total_true_positives": 3,
            "false_positive_tolerance": 1,
            "max_fp_rate": 0.20,
        },
    }


@pytest.fixture
def sast_baseline() -> dict[str, Any]:
    """Minimal SAST baseline for testing."""
    return {
        "_meta": {"apk_name": "TestApp", "phase": "sast"},
        "true_positive_rule_ids": [
            "android_sql_injection",
            "android_insecure_sharedprefs",
            "android_logging",
        ],
        "expected_absent_rule_ids": [
            {
                "rule_id": "android_crypto_ecb",
                "reason": "No crypto usage",
            },
        ],
        "summary": {
            "total_true_positives": 3,
            "false_positive_tolerance": 1,
            "max_fp_rate": 0.20,
        },
    }


# ---------------------------------------------------------------------------
# Manifest phase tests
# ---------------------------------------------------------------------------


class TestManifestFPRateComputation:
    """Test manifest-phase FP rate logic."""

    def test_perfect_match_all_tp(self, manifest_baseline: dict) -> None:
        """All baseline findings detected, no extras -> PASS."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        assert result.phase == PHASE_MANIFEST
        assert result.total_findings == 3
        assert result.true_positive_count == 3
        assert result.false_positive_count == 0
        assert result.false_negative_count == 0
        assert result.fp_rate == 0.0
        assert result.detection_rate == 1.0
        assert result.passed is True
        assert result.verdict == "PASS"

    def test_missing_finding_is_fn(self, manifest_baseline: dict) -> None:
        """Missing a baseline finding -> false negative -> FAIL."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            # MANIFEST-003 missing
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        assert result.false_negative_count == 1
        assert "MANIFEST-003" in result.false_negative_ids
        assert result.detection_rate == pytest.approx(2 / 3, abs=0.01)
        assert result.passed is False
        assert "Missing 1 expected finding" in result.failure_reasons[0]

    def test_extra_finding_is_fp(self, manifest_baseline: dict) -> None:
        """Finding not in baseline -> false positive."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
            {"check_id": "MANIFEST-999", "severity": "low"},  # extra
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        assert result.true_positive_count == 3
        assert result.false_positive_count == 1
        assert "MANIFEST-999" in result.false_positive_ids
        assert result.fp_rate == pytest.approx(1 / 4, abs=0.01)
        # 1 FP <= tolerance 1 and rate 25% >= 20% -> FAIL on rate
        assert result.passed is False

    def test_expected_absent_violation(self, manifest_baseline: dict) -> None:
        """Finding in expected_absent -> false positive."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
            {"check_id": "MANIFEST-004", "severity": "info"},  # should be absent
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        assert result.false_positive_count == 1
        assert "MANIFEST-004" in result.false_positive_ids
        assert len(result.expected_absent_violations) == 1
        assert result.expected_absent_violations[0]["check_id"] == "MANIFEST-004"

    def test_within_tolerance_passes(self, manifest_baseline: dict) -> None:
        """1 FP with tolerance=1 and rate < 20% -> PASS.

        Baseline contains MANIFEST-001/002/003 as TPs. To achieve fp_rate
        < 20% with tolerance=1, we need at least 6 findings. Pad the TPs
        with duplicates (deduped via set in the counter) and add exactly
        one extra ID.
        """
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
            # Duplicates still contribute to total_findings but dedup in
            # false_positive_count / true_positive_count via set(...)
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-099", "severity": "low"},  # 1 FP
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        # 1 unique FP out of 6 total findings = 16.7% < 20%; 1 <= tolerance 1
        assert result.false_positive_count == 1
        assert result.fp_rate == pytest.approx(1 / 6, abs=0.01)
        assert result.passed is True

    def test_empty_findings_has_fn(self, manifest_baseline: dict) -> None:
        """No findings at all -> all baseline findings are FN -> FAIL."""
        result = compute_manifest_fp_rate([], manifest_baseline)

        assert result.total_findings == 0
        assert result.false_negative_count == 3
        assert result.fp_rate == 0.0
        assert result.detection_rate == 0.0
        assert result.passed is False

    def test_fp_tolerance_exceeded_fails(self, manifest_baseline: dict) -> None:
        """FP count > tolerance -> FAIL even if rate is low."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
            # 8 more findings to dilute FP rate but exceed count tolerance
            {"check_id": "MANIFEST-005", "severity": "high"},
            {"check_id": "MANIFEST-006", "severity": "high"},
            {"check_id": "MANIFEST-007", "severity": "low"},
            {"check_id": "MANIFEST-008", "severity": "low"},
            {"check_id": "MANIFEST-009", "severity": "low"},
            {"check_id": "MANIFEST-010", "severity": "low"},
            {"check_id": "MANIFEST-011", "severity": "low"},
            {"check_id": "MANIFEST-012", "severity": "low"},
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        # 8 extras are FP, but 1 (MANIFEST-004) expected absent not triggered
        assert result.false_positive_count > manifest_baseline["summary"]["false_positive_tolerance"]
        assert result.passed is False


# ---------------------------------------------------------------------------
# Bytecode phase tests
# ---------------------------------------------------------------------------


class TestBytecodeFPRateComputation:
    """Test bytecode-phase FP rate logic."""

    def test_all_tp_detected(self, bytecode_baseline: dict) -> None:
        """All expected patterns found, no extras -> PASS."""
        findings = [
            {"pattern_id": "crypto_ecb_mode"},
            {"pattern_id": "hardcoded_sharedprefs"},
            {"pattern_id": "logging_sensitive_data"},
        ]
        result = compute_bytecode_fp_rate(findings, bytecode_baseline)

        assert result.true_positive_count == 3
        assert result.false_positive_count == 0
        assert result.false_negative_count == 0
        assert result.passed is True

    def test_extra_pattern_is_fp(self, bytecode_baseline: dict) -> None:
        """Extra pattern not in baseline -> FP."""
        findings = [
            {"pattern_id": "crypto_ecb_mode"},
            {"pattern_id": "hardcoded_sharedprefs"},
            {"pattern_id": "logging_sensitive_data"},
            {"pattern_id": "unknown_pattern"},  # extra
        ]
        result = compute_bytecode_fp_rate(findings, bytecode_baseline)

        assert result.false_positive_count == 1
        assert "unknown_pattern" in result.false_positive_ids

    def test_expected_absent_violation(self, bytecode_baseline: dict) -> None:
        """Pattern in expected_absent found -> FP."""
        findings = [
            {"pattern_id": "crypto_ecb_mode"},
            {"pattern_id": "hardcoded_sharedprefs"},
            {"pattern_id": "logging_sensitive_data"},
            {"pattern_id": "webview_js_enabled"},  # should be absent
        ]
        result = compute_bytecode_fp_rate(findings, bytecode_baseline)

        assert result.false_positive_count == 1
        assert len(result.expected_absent_violations) == 1
        assert result.expected_absent_violations[0]["pattern_id"] == "webview_js_enabled"

    def test_id_field_fallback(self, bytecode_baseline: dict) -> None:
        """Falls back to 'id' field if 'pattern_id' is missing."""
        findings = [
            {"id": "crypto_ecb_mode"},
            {"id": "hardcoded_sharedprefs"},
            {"id": "logging_sensitive_data"},
        ]
        result = compute_bytecode_fp_rate(findings, bytecode_baseline)

        assert result.true_positive_count == 3
        assert result.passed is True


# ---------------------------------------------------------------------------
# SAST phase tests
# ---------------------------------------------------------------------------


class TestSASTFPRateComputation:
    """Test SAST-phase FP rate logic."""

    def test_all_tp_detected(self, sast_baseline: dict) -> None:
        """All expected rules found -> PASS."""
        findings = [
            {"rule_id": "android_sql_injection"},
            {"rule_id": "android_insecure_sharedprefs"},
            {"rule_id": "android_logging"},
        ]
        result = compute_sast_fp_rate(findings, sast_baseline)

        assert result.true_positive_count == 3
        assert result.false_positive_count == 0
        assert result.passed is True

    def test_expected_absent_violation(self, sast_baseline: dict) -> None:
        """Rule in expected_absent found -> FP."""
        findings = [
            {"rule_id": "android_sql_injection"},
            {"rule_id": "android_insecure_sharedprefs"},
            {"rule_id": "android_logging"},
            {"rule_id": "android_crypto_ecb"},  # should be absent
        ]
        result = compute_sast_fp_rate(findings, sast_baseline)

        assert result.false_positive_count == 1
        assert len(result.expected_absent_violations) == 1

    def test_rule_field_fallback(self, sast_baseline: dict) -> None:
        """Falls back to 'rule' field if 'rule_id' is missing."""
        findings = [
            {"rule": "android_sql_injection"},
            {"rule": "android_insecure_sharedprefs"},
            {"rule": "android_logging"},
        ]
        result = compute_sast_fp_rate(findings, sast_baseline)

        assert result.true_positive_count == 3
        assert result.passed is True


# ---------------------------------------------------------------------------
# Phase dispatcher tests
# ---------------------------------------------------------------------------


class TestPhaseDispatcher:
    """Test the compute_phase_fp_rate dispatcher."""

    def test_dispatches_manifest(self, manifest_baseline: dict) -> None:
        findings = [{"check_id": "MANIFEST-001", "severity": "high"}]
        result = compute_phase_fp_rate(PHASE_MANIFEST, findings, manifest_baseline)
        assert result.phase == PHASE_MANIFEST

    def test_dispatches_bytecode(self, bytecode_baseline: dict) -> None:
        findings = [{"pattern_id": "crypto_ecb_mode"}]
        result = compute_phase_fp_rate(PHASE_BYTECODE, findings, bytecode_baseline)
        assert result.phase == PHASE_BYTECODE

    def test_dispatches_sast(self, sast_baseline: dict) -> None:
        findings = [{"rule_id": "android_sql_injection"}]
        result = compute_phase_fp_rate(PHASE_SAST, findings, sast_baseline)
        assert result.phase == PHASE_SAST

    def test_unknown_phase_raises(self, manifest_baseline: dict) -> None:
        with pytest.raises(ValueError, match="Unknown phase"):
            compute_phase_fp_rate("unknown", [], manifest_baseline)


# ---------------------------------------------------------------------------
# Aggregate computation tests
# ---------------------------------------------------------------------------


class TestAggregateFPRate:
    """Test aggregate FP rate computation across phases."""

    def test_all_phases_pass(
        self,
        manifest_baseline: dict,
        bytecode_baseline: dict,
        sast_baseline: dict,
    ) -> None:
        """All phases pass -> aggregate passes."""
        manifest_result = compute_manifest_fp_rate(
            [
                {"check_id": "MANIFEST-001", "severity": "high"},
                {"check_id": "MANIFEST-002", "severity": "medium"},
                {"check_id": "MANIFEST-003", "severity": "high"},
            ],
            manifest_baseline,
        )
        bytecode_result = compute_bytecode_fp_rate(
            [
                {"pattern_id": "crypto_ecb_mode"},
                {"pattern_id": "hardcoded_sharedprefs"},
                {"pattern_id": "logging_sensitive_data"},
            ],
            bytecode_baseline,
        )
        sast_result = compute_sast_fp_rate(
            [
                {"rule_id": "android_sql_injection"},
                {"rule_id": "android_insecure_sharedprefs"},
                {"rule_id": "android_logging"},
            ],
            sast_baseline,
        )

        agg = compute_aggregate_fp_rate(
            "TestApp",
            {
                PHASE_MANIFEST: manifest_result,
                PHASE_BYTECODE: bytecode_result,
                PHASE_SAST: sast_result,
            },
        )

        assert agg.overall_verdict == "PASS"
        assert agg.all_phases_pass is True
        assert agg.aggregate_fp_rate == 0.0
        assert agg.aggregate_detection_rate == 1.0
        assert agg.total_findings_all_phases == 9
        assert agg.total_true_positives == 9
        assert agg.total_false_positives == 0

    def test_one_phase_fails_aggregate_fails(
        self,
        manifest_baseline: dict,
        bytecode_baseline: dict,
    ) -> None:
        """One failing phase -> aggregate fails."""
        manifest_ok = compute_manifest_fp_rate(
            [
                {"check_id": "MANIFEST-001", "severity": "high"},
                {"check_id": "MANIFEST-002", "severity": "medium"},
                {"check_id": "MANIFEST-003", "severity": "high"},
            ],
            manifest_baseline,
        )
        # Bytecode missing all expected -> FAIL
        bytecode_fail = compute_bytecode_fp_rate([], bytecode_baseline)

        agg = compute_aggregate_fp_rate(
            "TestApp",
            {
                PHASE_MANIFEST: manifest_ok,
                PHASE_BYTECODE: bytecode_fail,
            },
        )

        assert agg.overall_verdict == "FAIL"
        assert agg.all_phases_pass is False

    def test_weighted_fp_rate(self) -> None:
        """Aggregate FP rate is weighted by finding count, not averaged."""
        # Phase A: 10 findings, 1 FP (10% FP rate)
        phase_a = PhaseResult(
            phase="a", apk_name="Test",
            total_findings=10, true_positive_count=9,
            false_positive_count=1, false_negative_count=0,
            fp_rate=0.10, detection_rate=1.0,
            passed=True,
        )
        # Phase B: 2 findings, 1 FP (50% FP rate)
        phase_b = PhaseResult(
            phase="b", apk_name="Test",
            total_findings=2, true_positive_count=1,
            false_positive_count=1, false_negative_count=0,
            fp_rate=0.50, detection_rate=1.0,
            passed=True,
        )

        agg = compute_aggregate_fp_rate("Test", {"a": phase_a, "b": phase_b})

        # Weighted: (1+1) / (10+2) = 2/12 = 16.7%, not (10%+50%)/2 = 30%
        assert agg.aggregate_fp_rate == pytest.approx(2 / 12, abs=0.001)
        assert agg.total_findings_all_phases == 12
        assert agg.total_false_positives == 2

    def test_empty_phases(self) -> None:
        """No phases -> aggregate has zero findings, PASS."""
        agg = compute_aggregate_fp_rate("Empty", {})

        assert agg.aggregate_fp_rate == 0.0
        assert agg.aggregate_detection_rate == 1.0
        assert agg.total_findings_all_phases == 0
        # all_phases_pass is True because all() of empty = True
        assert agg.all_phases_pass is True
        assert agg.overall_verdict == "PASS"


# ---------------------------------------------------------------------------
# Multi-APK summary tests
# ---------------------------------------------------------------------------


class TestMultiAPKSummary:
    """Test cross-APK summary computation."""

    def test_two_apks_both_pass(self) -> None:
        """Both APKs pass -> overall PASS."""
        agg1 = AggregateResult(
            apk_name="App1",
            total_findings_all_phases=5,
            total_true_positives=5,
            total_false_positives=0,
            total_false_negatives=0,
            aggregate_fp_rate=0.0,
            aggregate_detection_rate=1.0,
            overall_verdict="PASS",
        )
        agg2 = AggregateResult(
            apk_name="App2",
            total_findings_all_phases=8,
            total_true_positives=7,
            total_false_positives=1,
            total_false_negatives=0,
            aggregate_fp_rate=0.125,
            aggregate_detection_rate=1.0,
            overall_verdict="PASS",
        )

        summary = compute_multi_apk_summary({"app1": agg1, "app2": agg2})

        assert summary.overall_verdict == "PASS"
        # Aggregate: (0+1) / (5+8) = 1/13 ~= 7.7%
        assert summary.overall_fp_rate == pytest.approx(1 / 13, abs=0.01)
        assert summary.overall_detection_rate == pytest.approx(12 / 12, abs=0.01)

    def test_one_apk_fails_overall_fails(self) -> None:
        """One APK fails -> overall FAIL."""
        agg_pass = AggregateResult(
            apk_name="Good",
            total_findings_all_phases=5,
            total_true_positives=5,
            total_false_positives=0,
            total_false_negatives=0,
            overall_verdict="PASS",
        )
        agg_fail = AggregateResult(
            apk_name="Bad",
            total_findings_all_phases=3,
            total_true_positives=1,
            total_false_positives=2,
            total_false_negatives=1,
            overall_verdict="FAIL",
        )

        summary = compute_multi_apk_summary({"good": agg_pass, "bad": agg_fail})
        assert summary.overall_verdict == "FAIL"

    def test_per_phase_aggregate(self) -> None:
        """Per-phase aggregate sums across APKs."""
        manifest_pr = PhaseResult(
            phase=PHASE_MANIFEST, apk_name="App1",
            total_findings=5, true_positive_count=4,
            false_positive_count=1, false_negative_count=0,
            fp_rate=0.20, detection_rate=1.0, passed=True,
        )
        agg = AggregateResult(
            apk_name="App1",
            phase_results={PHASE_MANIFEST: manifest_pr},
            total_findings_all_phases=5,
            total_true_positives=4,
            total_false_positives=1,
            total_false_negatives=0,
            aggregate_fp_rate=0.20,
            overall_verdict="PASS",
        )

        summary = compute_multi_apk_summary({"app1": agg})

        assert PHASE_MANIFEST in summary.per_phase_aggregate
        phase_agg = summary.per_phase_aggregate[PHASE_MANIFEST]
        assert phase_agg["total_findings"] == 5
        assert phase_agg["total_fp"] == 1
        assert phase_agg["fp_rate"] == pytest.approx(0.20, abs=0.01)


# ---------------------------------------------------------------------------
# Summary table formatting tests
# ---------------------------------------------------------------------------


class TestSummaryTableFormatting:
    """Test ASCII table output."""

    def _build_simple_summary(self) -> MultiAPKSummary:
        """Build a simple summary for formatting tests."""
        pr = PhaseResult(
            phase=PHASE_MANIFEST, apk_name="TestApp",
            total_findings=5, true_positive_count=4,
            false_positive_count=1, false_negative_count=0,
            fp_rate=0.20, detection_rate=1.0,
            fp_tolerance=2, max_fp_rate=0.20,
            passed=True,
        )
        agg = AggregateResult(
            apk_name="TestApp",
            phase_results={PHASE_MANIFEST: pr},
            total_findings_all_phases=5,
            total_true_positives=4,
            total_false_positives=1,
            total_false_negatives=0,
            aggregate_fp_rate=0.20,
            aggregate_detection_rate=1.0,
            overall_verdict="PASS",
        )
        return compute_multi_apk_summary({"test": agg})

    def test_table_contains_header(self) -> None:
        summary = self._build_simple_summary()
        table = format_summary_table(summary)

        assert "Phase" in table
        assert "APK" in table
        assert "FP Rate" in table
        assert "Det. Rate" in table
        assert "Result" in table

    def test_table_contains_phase_row(self) -> None:
        summary = self._build_simple_summary()
        table = format_summary_table(summary)

        assert "manifest" in table
        assert "TestApp" in table
        assert "PASS" in table

    def test_table_contains_aggregate_row(self) -> None:
        summary = self._build_simple_summary()
        table = format_summary_table(summary)

        assert "AGGREGATE" in table

    def test_table_contains_overall_verdict(self) -> None:
        summary = self._build_simple_summary()
        table = format_summary_table(summary)

        assert "Overall:" in table
        assert "Verdict=PASS" in table

    def test_table_no_header(self) -> None:
        summary = self._build_simple_summary()
        table_with_header = format_summary_table(summary, include_header=True)
        table = format_summary_table(summary, include_header=False)

        # include_header=False suppresses the top per-APK column header
        # (identified by "| Phase      | APK" with padding).
        # The bottom "Cross-APK Phase Aggregates" section has its own
        # "| Phase" header that is always printed — that's a separate
        # structural section, not gated by this flag.
        assert "| Phase      | APK" not in table
        assert "| Phase      | APK" in table_with_header
        # But should still have data
        assert "manifest" in table


class TestFailureDetails:
    """Test failure detail formatting."""

    def test_no_failures_returns_empty(self) -> None:
        pr = PhaseResult(
            phase=PHASE_MANIFEST, apk_name="OK",
            passed=True,
        )
        agg = AggregateResult(
            apk_name="OK",
            phase_results={PHASE_MANIFEST: pr},
            overall_verdict="PASS",
        )
        summary = compute_multi_apk_summary({"ok": agg})
        details = format_failure_details(summary)
        assert details == ""

    def test_failure_shows_reasons(self) -> None:
        pr = PhaseResult(
            phase=PHASE_MANIFEST, apk_name="Bad",
            passed=False,
            failure_reasons=["FP rate 25.0% >= threshold 20%"],
            false_positive_ids=["MANIFEST-099"],
        )
        agg = AggregateResult(
            apk_name="Bad",
            phase_results={PHASE_MANIFEST: pr},
            overall_verdict="FAIL",
        )
        summary = compute_multi_apk_summary({"bad": agg})
        details = format_failure_details(summary)

        assert "FAILURE: Bad / manifest" in details
        assert "FP rate 25.0%" in details
        assert "MANIFEST-099" in details


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------


class TestSerialization:
    """Test JSON serialization of results."""

    def test_phase_result_roundtrip(self) -> None:
        pr = PhaseResult(
            phase=PHASE_MANIFEST, apk_name="Test",
            total_findings=5, true_positive_count=4,
            false_positive_count=1, false_negative_count=0,
            matched_ids=["MANIFEST-001", "MANIFEST-002"],
            false_positive_ids=["MANIFEST-099"],
            fp_rate=0.20, detection_rate=1.0,
            fp_tolerance=2, max_fp_rate=0.20,
            passed=True,
        )
        d = phase_result_to_dict(pr)

        assert d["phase"] == PHASE_MANIFEST
        assert d["metrics"]["fp_rate"] == 0.20
        assert d["verdict"] == "PASS"
        # Ensure it's JSON-serializable
        json.dumps(d)

    def test_aggregate_result_roundtrip(self) -> None:
        agg = AggregateResult(
            apk_name="Test",
            total_findings_all_phases=10,
            total_true_positives=8,
            total_false_positives=2,
            aggregate_fp_rate=0.20,
            overall_verdict="PASS",
        )
        d = aggregate_result_to_dict(agg)

        assert d["apk_name"] == "Test"
        assert d["aggregate_metrics"]["fp_rate"] == 0.20
        json.dumps(d)

    def test_multi_apk_summary_roundtrip(self) -> None:
        agg = AggregateResult(
            apk_name="Test",
            overall_verdict="PASS",
        )
        summary = compute_multi_apk_summary({"test": agg})
        d = multi_apk_summary_to_dict(summary)

        assert "apk_results" in d
        assert "per_phase_aggregate" in d
        assert "overall_verdict" in d
        json.dumps(d)


# ---------------------------------------------------------------------------
# Baseline loader tests
# ---------------------------------------------------------------------------


class TestBaselineLoaders:
    """Test that ground-truth baseline files load correctly."""

    @pytest.mark.parametrize("apk_key", ["diva", "insecurebankv2", "ovaa"])
    def test_manifest_baseline_loads(self, apk_key: str) -> None:
        baseline = load_manifest_baseline(apk_key)
        assert baseline is not None
        assert "_meta" in baseline
        assert "mobsf_findings" in baseline
        assert "expected_absent" in baseline
        assert "summary" in baseline

    @pytest.mark.parametrize("apk_key", ["diva", "insecurebankv2", "ovaa"])
    def test_bytecode_baseline_loads(self, apk_key: str) -> None:
        baseline = load_phase_baseline(apk_key, PHASE_BYTECODE)
        assert baseline is not None
        assert "true_positive_pattern_ids" in baseline
        assert "expected_absent_pattern_ids" in baseline
        assert "summary" in baseline

    @pytest.mark.parametrize("apk_key", ["diva", "insecurebankv2", "ovaa"])
    def test_sast_baseline_loads(self, apk_key: str) -> None:
        baseline = load_phase_baseline(apk_key, PHASE_SAST)
        assert baseline is not None
        assert "true_positive_rule_ids" in baseline
        assert "expected_absent_rule_ids" in baseline
        assert "summary" in baseline

    def test_unknown_apk_returns_none(self) -> None:
        assert load_manifest_baseline("nonexistent") is None
        assert load_phase_baseline("nonexistent", PHASE_BYTECODE) is None

    @pytest.mark.parametrize("apk_key", ["diva", "insecurebankv2", "ovaa"])
    def test_baseline_summary_tp_count_matches(self, apk_key: str) -> None:
        """Summary total_true_positives matches actual list length."""
        for phase in [PHASE_BYTECODE, PHASE_SAST]:
            baseline = load_phase_baseline(apk_key, phase)
            assert baseline is not None
            if phase == PHASE_BYTECODE:
                actual = len(baseline["true_positive_pattern_ids"])
            else:
                actual = len(baseline["true_positive_rule_ids"])
            declared = baseline["summary"]["total_true_positives"]
            assert actual == declared, (
                f"{apk_key}/{phase}: declared {declared} TPs but has {actual}"
            )


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_duplicate_findings_counted_once(self, manifest_baseline: dict) -> None:
        """Duplicate check IDs in findings — unique set used for counting."""
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-001", "severity": "high"},  # duplicate
            {"check_id": "MANIFEST-002", "severity": "medium"},
            {"check_id": "MANIFEST-003", "severity": "high"},
        ]
        result = compute_manifest_fp_rate(findings, manifest_baseline)

        # total_findings counts raw list length
        assert result.total_findings == 4
        # TP count uses unique set
        assert result.true_positive_count == 3

    def test_zero_fp_tolerance(self) -> None:
        """With fp_tolerance=0, any FP fails."""
        baseline = {
            "_meta": {"apk_name": "Strict"},
            "mobsf_findings": [
                {"wairz_check_id": "MANIFEST-001", "issue_title": "T", "severity": "high",
                 "category": "manifest", "mobsf_rule": "r", "cwe_ids": [], "description": "", "evidence_pattern": ""},
            ],
            "expected_absent": [],
            "summary": {"total_findings": 1, "false_positive_tolerance": 0, "max_fp_rate": 0.20},
        }
        findings = [
            {"check_id": "MANIFEST-001", "severity": "high"},
            {"check_id": "MANIFEST-999", "severity": "low"},
        ]
        result = compute_manifest_fp_rate(findings, baseline)

        assert result.false_positive_count == 1
        assert result.passed is False
        assert any("exceeds tolerance" in r for r in result.failure_reasons)

    def test_100pct_fp_rate(self) -> None:
        """All findings are FP -> rate = 100%."""
        baseline = {
            "_meta": {"apk_name": "AllFP"},
            "mobsf_findings": [
                {"wairz_check_id": "MANIFEST-001", "issue_title": "T", "severity": "high",
                 "category": "manifest", "mobsf_rule": "r", "cwe_ids": [], "description": "", "evidence_pattern": ""},
            ],
            "expected_absent": [],
            "summary": {"total_findings": 1, "false_positive_tolerance": 0, "max_fp_rate": 0.20},
        }
        findings = [
            {"check_id": "MANIFEST-999", "severity": "low"},
            {"check_id": "MANIFEST-998", "severity": "low"},
        ]
        result = compute_manifest_fp_rate(findings, baseline)

        assert result.fp_rate == 1.0
        assert result.false_negative_count == 1
        assert result.passed is False

    def test_aggregate_detection_rate_with_fn(self) -> None:
        """Aggregate detection rate accounts for FN across phases."""
        phase_a = PhaseResult(
            phase="a", apk_name="Test",
            total_findings=3, true_positive_count=2,
            false_positive_count=0, false_negative_count=1,
            passed=False,
        )
        phase_b = PhaseResult(
            phase="b", apk_name="Test",
            total_findings=5, true_positive_count=5,
            false_positive_count=0, false_negative_count=0,
            passed=True,
        )

        agg = compute_aggregate_fp_rate("Test", {"a": phase_a, "b": phase_b})

        # Detection: (2+5) / (2+1+5+0) = 7/8 = 87.5%
        assert agg.aggregate_detection_rate == pytest.approx(7 / 8, abs=0.001)
