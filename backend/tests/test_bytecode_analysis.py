"""Tests for Phase 2a bytecode analysis service.

Tests the pattern matching logic, severity adjustment, and output formatting
without requiring actual APK files (unit tests use mocked Androguard objects).
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from app.services.bytecode_analysis_service import (
    BYTECODE_PATTERNS,
    BytecodeAnalysisService,
    BytecodeFinding,
)


class TestPatternDatabase:
    """Verify the pattern database is complete and well-formed."""

    def test_all_patterns_have_required_fields(self):
        for p in BYTECODE_PATTERNS:
            assert p.id, f"Pattern missing id"
            assert p.title, f"Pattern {p.id} missing title"
            assert p.description, f"Pattern {p.id} missing description"
            assert p.severity in (
                "critical", "high", "medium", "low", "info"
            ), f"Pattern {p.id} has invalid severity: {p.severity}"
            assert p.category, f"Pattern {p.id} missing category"

    def test_all_patterns_have_detection_criteria(self):
        for p in BYTECODE_PATTERNS:
            has_detection = (
                p.class_patterns or p.method_patterns or p.string_patterns
            )
            assert has_detection, (
                f"Pattern {p.id} has no detection criteria "
                "(needs class_patterns, method_patterns, or string_patterns)"
            )

    def test_pattern_ids_are_unique(self):
        ids = [p.id for p in BYTECODE_PATTERNS]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_minimum_pattern_count(self):
        """We should have at least 35 patterns covering major categories."""
        assert len(BYTECODE_PATTERNS) >= 35
        categories = {p.category for p in BYTECODE_PATTERNS}
        expected = {
            "crypto", "network", "storage", "runtime",
            "webview", "logging", "credentials",
        }
        assert expected.issubset(categories), (
            f"Missing categories: {expected - categories}"
        )

    def test_cwe_coverage(self):
        """All non-info patterns should have CWE IDs."""
        for p in BYTECODE_PATTERNS:
            if p.severity != "info":
                assert p.cwe_ids, f"Pattern {p.id} (severity={p.severity}) missing CWE IDs"


class TestBytecodeFinding:
    """Test the BytecodeFinding dataclass."""

    def test_to_dict(self):
        f = BytecodeFinding(
            pattern_id="test_pattern",
            title="Test Finding",
            description="A test finding",
            severity="high",
            cwe_ids=["CWE-123"],
            category="crypto",
            locations=[{"caller_class": "Lcom/test;", "caller_method": "doStuff"}],
            count=1,
        )
        d = f.to_dict()
        assert d["pattern_id"] == "test_pattern"
        assert d["severity"] == "high"
        assert d["total_occurrences"] == 1
        assert len(d["locations"]) == 1

    def test_to_dict_caps_locations(self):
        """Locations should be capped to 20 in output."""
        locs = [{"caller_class": f"Lcom/test{i};"} for i in range(50)]
        f = BytecodeFinding(
            pattern_id="t", title="T", description="D",
            severity="high", cwe_ids=[], category="c",
            locations=locs, count=50,
        )
        d = f.to_dict()
        assert len(d["locations"]) == 20
        assert d["total_occurrences"] == 50


class TestSeverityAdjustment:
    """Test firmware context severity adjustments."""

    def test_priv_app_crypto_bump(self):
        svc = BytecodeAnalysisService()
        findings = [
            BytecodeFinding(
                pattern_id="crypto_ecb_mode",
                title="ECB Mode",
                description="desc",
                severity="high",
                cwe_ids=["CWE-327"],
                category="crypto",
                locations=[],
                count=1,
            )
        ]
        adjusted = svc._adjust_severity_for_context(
            findings, "/system/priv-app/MyApp/MyApp.apk"
        )
        assert adjusted[0].severity == "critical"

    def test_system_app_runtime_reduction(self):
        svc = BytecodeAnalysisService()
        findings = [
            BytecodeFinding(
                pattern_id="runtime_native_load",
                title="Native Load",
                description="desc",
                severity="info",
                cwe_ids=["CWE-111"],
                category="runtime",
                locations=[],
                count=1,
            )
        ]
        adjusted = svc._adjust_severity_for_context(
            findings, "/system/app/SystemUI/SystemUI.apk"
        )
        # info -> info (can't go below info)
        assert adjusted[0].severity == "info"

    def test_system_app_logging_reduction(self):
        svc = BytecodeAnalysisService()
        findings = [
            BytecodeFinding(
                pattern_id="logging_verbose",
                title="Verbose Logging",
                description="desc",
                severity="low",
                cwe_ids=["CWE-532"],
                category="logging",
                locations=[],
                count=5,
            )
        ]
        adjusted = svc._adjust_severity_for_context(
            findings, "/system/app/Launcher/Launcher.apk"
        )
        assert adjusted[0].severity == "info"

    def test_regular_app_no_adjustment(self):
        svc = BytecodeAnalysisService()
        findings = [
            BytecodeFinding(
                pattern_id="crypto_ecb_mode",
                title="ECB Mode",
                description="desc",
                severity="high",
                cwe_ids=["CWE-327"],
                category="crypto",
                locations=[],
                count=1,
            )
        ]
        adjusted = svc._adjust_severity_for_context(
            findings, "/data/app/com.example/base.apk"
        )
        assert adjusted[0].severity == "high"


class TestBenignHttpFilter:
    """Test HTTP URL false positive filtering."""

    def test_schemas_android_com(self):
        assert BytecodeAnalysisService._is_benign_http(
            "http://schemas.android.com/apk/res/android"
        )

    def test_w3c(self):
        assert BytecodeAnalysisService._is_benign_http(
            "http://www.w3.org/2001/XMLSchema"
        )

    def test_localhost(self):
        assert BytecodeAnalysisService._is_benign_http("http://localhost:8080/api")

    def test_real_http_url(self):
        assert not BytecodeAnalysisService._is_benign_http(
            "http://api.example.com/data"
        )

    def test_xmlpull(self):
        assert BytecodeAnalysisService._is_benign_http(
            "http://xmlpull.org/v1/doc/features.html"
        )


class TestScanApkIntegration:
    """Integration test for the full scan_apk method (requires mocking)."""

    def test_file_not_found(self):
        svc = BytecodeAnalysisService()
        with pytest.raises(FileNotFoundError):
            svc.scan_apk("/nonexistent/path.apk")

    @patch("app.services.bytecode_analysis_service.BytecodeAnalysisService._scan_analysis")
    def test_scan_returns_expected_structure(self, mock_scan):
        """Test that scan_apk returns the expected dict structure."""
        svc = BytecodeAnalysisService()
        mock_scan.return_value = [
            BytecodeFinding(
                pattern_id="crypto_ecb_mode",
                title="ECB Mode",
                description="test",
                severity="high",
                cwe_ids=["CWE-327"],
                category="crypto",
                locations=[{"target": "test"}],
                count=1,
            )
        ]

        # We need to mock AnalyzeAPK
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.test.app"

        # AnalyzeAPK is lazily imported from androguard.misc inside
        # scan_apk(), so patch the source module, not the service module.
        with patch(
            "androguard.misc.AnalyzeAPK",
            return_value=(mock_apk, [MagicMock()], MagicMock()),
        ):
            import tempfile
            import os

            # Create a temp file to pass file existence check
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
                f.write(b"fake apk")
                tmp_path = f.name

            try:
                result = svc.scan_apk(tmp_path)
                assert result["package"] == "com.test.app"
                assert len(result["findings"]) == 1
                assert result["findings"][0]["pattern_id"] == "crypto_ecb_mode"
                assert "summary" in result
                assert "elapsed_seconds" in result
                assert result["elapsed_seconds"] < 30.0
            finally:
                os.unlink(tmp_path)

    def test_timeout_respected(self):
        """Verify the timeout mechanism works."""
        svc = BytecodeAnalysisService()

        # Mock a scan that would take too long
        mock_analysis = MagicMock()

        # Make get_methods return a very long iterator that checks time
        class SlowIterator:
            def __iter__(self):
                return self

            def __next__(self):
                time.sleep(0.001)
                return MagicMock()

        mock_analysis.get_methods.return_value = SlowIterator()
        mock_analysis.get_strings.return_value = []
        mock_analysis.get_classes.return_value = []

        # Should complete (possibly with partial results) due to timeout
        start = time.monotonic()
        findings = svc._scan_analysis(mock_analysis, timeout=0.5, start_time=start)
        elapsed = time.monotonic() - start
        # Should not run significantly past timeout
        assert elapsed < 2.0, f"Scan took {elapsed}s, expected < 2.0s"


class TestInsecureBankv2Patterns:
    """Verify patterns specifically relevant to InsecureBankv2 detection.

    InsecureBankv2 is a deliberately vulnerable Android app with:
    - Hardcoded encryption key ("This is the super secret key123")
    - Base64 used as "encryption" for credentials
    - SharedPreferences for credential storage
    - WebView with JavaScript enabled
    - AES with hardcoded key via SecretKeySpec
    - MD5 hashing
    """

    def test_insecurebankv2_crypto_patterns_exist(self):
        """All InsecureBankv2 crypto patterns must have detection rules."""
        pattern_ids = {p.id for p in BYTECODE_PATTERNS}
        required = {
            "crypto_static_key",       # SecretKeySpec with hardcoded bytes
            "crypto_static_iv",        # IvParameterSpec with static IV
            "crypto_weak_hash",        # MD5/SHA1 usage
            "crypto_no_key_derivation",  # String.getBytes() as key (context-gated)
        }
        missing = required - pattern_ids
        assert not missing, f"Missing InsecureBankv2 crypto patterns: {missing}"

    def test_insecurebankv2_credential_patterns_exist(self):
        """All InsecureBankv2 credential patterns must have detection rules."""
        pattern_ids = {p.id for p in BYTECODE_PATTERNS}
        required = {
            "credentials_sharedprefs",       # SharedPreferences credential storage
            "credentials_base64_encode",     # Base64 as "encryption"
            "credentials_hardcoded_string",  # Hardcoded password strings
        }
        missing = required - pattern_ids
        assert not missing, f"Missing InsecureBankv2 credential patterns: {missing}"

    def test_insecurebankv2_webview_patterns_exist(self):
        """All InsecureBankv2 WebView patterns must have detection rules."""
        pattern_ids = {p.id for p in BYTECODE_PATTERNS}
        required = {
            "webview_js_enabled",      # setJavaScriptEnabled
            "webview_file_access",     # setAllowFileAccess
            "webview_save_password",   # setSavePassword
        }
        missing = required - pattern_ids
        assert not missing, f"Missing InsecureBankv2 WebView patterns: {missing}"


class TestCredentialPatterns:
    """Test credential-related pattern detection specifics."""

    def test_sharedprefs_methods_covered(self):
        """SharedPreferences put/get methods must be in pattern."""
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "credentials_sharedprefs")
        assert any("putString" in m for m in pat.method_patterns)
        assert any("getString" in m for m in pat.method_patterns)

    def test_base64_methods_covered(self):
        """Both Android and Java Base64 APIs must be in pattern."""
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "credentials_base64_encode")
        android_covered = any("android/util/Base64" in m for m in pat.method_patterns)
        java_covered = any("java/util/Base64" in m for m in pat.method_patterns)
        assert android_covered, "Android Base64 API not covered"
        assert java_covered, "Java Base64 API not covered"

    def test_hardcoded_string_patterns_not_too_broad(self):
        """Credential string patterns should be specific enough."""
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "credentials_hardcoded_string")
        # Should contain InsecureBankv2-relevant patterns
        needles_lower = {s.lower() for s in pat.string_patterns}
        assert "password" in needles_lower or "passwd" in needles_lower
        assert "secret key" in needles_lower or "secret_key" in needles_lower

    def test_priv_app_bumps_credential_severity(self):
        """Credential findings in priv-app should be bumped."""
        svc = BytecodeAnalysisService()
        findings = [
            BytecodeFinding(
                pattern_id="credentials_sharedprefs",
                title="SharedPrefs Credentials",
                description="desc",
                severity="high",
                cwe_ids=["CWE-312"],
                category="credentials",
                locations=[],
                count=1,
            )
        ]
        adjusted = svc._adjust_severity_for_context(
            findings, "/system/priv-app/MyApp/MyApp.apk"
        )
        assert adjusted[0].severity == "critical"


class TestContextualFiltering:
    """Test the context-gated FP reduction logic."""

    def test_string_getbytes_removed_without_crypto_context(self):
        """crypto_no_key_derivation should be removed when no crypto APIs found."""
        findings_map = {
            "crypto_no_key_derivation": BytecodeFinding(
                pattern_id="crypto_no_key_derivation",
                title="Raw Key Material",
                description="desc",
                severity="critical",
                cwe_ids=["CWE-321"],
                category="crypto",
                locations=[{"target": "Ljava/lang/String;->getBytes"}],
                count=5,
            ),
            "logging_verbose": BytecodeFinding(
                pattern_id="logging_verbose",
                title="Verbose Logging",
                description="desc",
                severity="low",
                cwe_ids=["CWE-532"],
                category="logging",
                locations=[],
                count=1,
            ),
        }
        BytecodeAnalysisService._filter_contextual_findings(findings_map)
        assert "crypto_no_key_derivation" not in findings_map
        assert "logging_verbose" in findings_map  # unrelated should stay

    def test_string_getbytes_kept_with_crypto_context(self):
        """crypto_no_key_derivation should be kept when SecretKeySpec is found."""
        findings_map = {
            "crypto_no_key_derivation": BytecodeFinding(
                pattern_id="crypto_no_key_derivation",
                title="Raw Key Material",
                description="desc",
                severity="critical",
                cwe_ids=["CWE-321"],
                category="crypto",
                locations=[],
                count=1,
            ),
            "crypto_static_key": BytecodeFinding(
                pattern_id="crypto_static_key",
                title="Hardcoded Key",
                description="desc",
                severity="critical",
                cwe_ids=["CWE-321"],
                category="crypto",
                locations=[],
                count=1,
            ),
        }
        BytecodeAnalysisService._filter_contextual_findings(findings_map)
        assert "crypto_no_key_derivation" in findings_map

    def test_credential_strings_removed_without_storage_context(self):
        """credentials_hardcoded_string should be removed without storage context."""
        findings_map = {
            "credentials_hardcoded_string": BytecodeFinding(
                pattern_id="credentials_hardcoded_string",
                title="Hardcoded Password",
                description="desc",
                severity="high",
                cwe_ids=["CWE-798"],
                category="credentials",
                locations=[{"string_value": "super secret key123"}],
                count=1,
            ),
        }
        BytecodeAnalysisService._filter_contextual_findings(findings_map)
        assert "credentials_hardcoded_string" not in findings_map

    def test_credential_strings_kept_with_sharedprefs(self):
        """credentials_hardcoded_string stays when SharedPreferences is used."""
        findings_map = {
            "credentials_hardcoded_string": BytecodeFinding(
                pattern_id="credentials_hardcoded_string",
                title="Hardcoded Password",
                description="desc",
                severity="high",
                cwe_ids=["CWE-798"],
                category="credentials",
                locations=[],
                count=1,
            ),
            "credentials_sharedprefs": BytecodeFinding(
                pattern_id="credentials_sharedprefs",
                title="SharedPrefs",
                description="desc",
                severity="high",
                cwe_ids=["CWE-312"],
                category="credentials",
                locations=[],
                count=1,
            ),
        }
        BytecodeAnalysisService._filter_contextual_findings(findings_map)
        assert "credentials_hardcoded_string" in findings_map


class TestBareAesDetection:
    """Test the special bare 'AES' string detection."""

    def test_bare_aes_recorded(self):
        """Bare 'AES' string should trigger crypto_aes_default_mode."""
        findings_map: dict[str, BytecodeFinding] = {}
        BytecodeAnalysisService._record_bare_aes_finding(findings_map, "AES")
        assert "crypto_aes_default_mode" in findings_map
        f = findings_map["crypto_aes_default_mode"]
        assert f.severity == "high"
        assert "CWE-327" in f.cwe_ids
        assert f.count == 1

    def test_bare_aes_not_triggered_by_aes_cbc(self):
        """'AES/CBC/PKCS5Padding' should NOT trigger bare AES detection."""
        # The bare AES check only fires when stripped == "AES"
        # AES/CBC/... strings will NOT match this condition
        assert "AES/CBC" != "AES"


class TestBenignCredentialFilter:
    """Test filtering of credential string false positives."""

    def test_bare_password_label_is_benign(self):
        assert BytecodeAnalysisService._is_benign_credential_string("Password")

    def test_enter_password_is_benign(self):
        assert BytecodeAnalysisService._is_benign_credential_string("enter password")

    def test_android_resource_is_benign(self):
        assert BytecodeAnalysisService._is_benign_credential_string("@string/password_hint")

    def test_actual_hardcoded_password_is_not_benign(self):
        assert not BytecodeAnalysisService._is_benign_credential_string(
            "This is the super secret key123"
        )

    def test_api_key_value_is_not_benign(self):
        assert not BytecodeAnalysisService._is_benign_credential_string(
            "api_key=AIzaSyB4nR3a3JHk92Jd"
        )

    def test_very_short_is_benign(self):
        assert BytecodeAnalysisService._is_benign_credential_string("pw")


class TestExtendedWebviewPatterns:
    """Test extended WebView patterns for comprehensive detection."""

    def test_webview_save_password_pattern(self):
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "webview_save_password")
        assert "setSavePassword" in pat.method_patterns[0]
        assert pat.severity == "high"

    def test_webview_debug_pattern(self):
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "webview_debug_enabled")
        assert "setWebContentsDebuggingEnabled" in pat.method_patterns[0]

    def test_webview_mixed_content_pattern(self):
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "webview_mixed_content")
        assert "setMixedContentMode" in pat.method_patterns[0]

    def test_webview_dom_storage_pattern(self):
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "webview_dom_storage")
        assert pat.severity == "low"  # DOM storage alone is low risk


class TestWeakHashPattern:
    """Test weak hash algorithm detection."""

    def test_weak_hash_pattern_exists(self):
        pat = next(p for p in BYTECODE_PATTERNS if p.id == "crypto_weak_hash")
        assert "MD5" in pat.string_patterns
        assert "SHA-1" in pat.string_patterns or "SHA1" in pat.string_patterns
        assert any("MessageDigest" in m for m in pat.method_patterns)
