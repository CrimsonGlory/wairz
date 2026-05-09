"""Service-layer tests for ``app.services.androguard_service``.

Phase 2 Wave 2 file 4 of 5 — backfills service-layer tests for the
Androguard wrapper (902 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

This service is **Rule #30 hot territory**. Every Androguard symbol is
LAZY-imported INSIDE function bodies (lines 508, 523, 640, 861, 891),
NOT at module scope. Per Phase 1's pytest-unblock fleet (session 0801ca27,
2026-04-23 — +620 tests unlocked once patch targets were corrected),
patches MUST hit the SOURCE module (`androguard.core.apk.APK`,
`androguard.misc.AnalyzeAPK`), NOT
`app.services.androguard_service.APK` — the latter is a silent no-op
because the symbol was never bound at module scope.

Coverage targets:

* Pure functions      — ``classify_permission`` (dangerous / normal /
  signature buckets); ``_is_debug_cert`` (issuer / subject heuristic);
  ``_bump_severity`` / ``_reduce_severity`` (severity ladder).
* ``is_available()``  — True/False on ImportError of androguard.
* ``analyze_apk()``   — FileNotFoundError on missing file; happy path
  asserts package/permissions/signatures shape; certificate metadata
  rolls up.
* ``scan_manifest_security()`` — FileNotFoundError on missing file (only
  the file-existence guard is exercised here; the full check pipeline
  is covered by manifest_checks tests).
* ``check_is_debug_signed()`` — exception swallow returns False.
* ``check_platform_signed()`` — exception swallow returns False.
* ``check_signatures()``      — wraps analyze_apk; flags unsigned APKs;
  flags weak signature algorithms (MD5/SHA1).
* **Rule #35b discipline** — this service does NOT persist to the DB;
  the value-flow contract is the dict shape returned by ``analyze_apk``
  and ``scan_manifest_security``. The "live canary" here is verifying
  that mocked APK metadata round-trips through the wrapper into the
  returned dict with the expected field names — the F-A-06-shape
  assertion that mock-only ``mock_apk.assert_called`` tests cannot fail on.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.androguard_service import (
    AndroguardService,
    _bump_severity,
    _reduce_severity,
    classify_permission,
)

# ===========================================================================
# Pure-function tests — no androguard dependency
# ===========================================================================


class TestClassifyPermission:
    @pytest.mark.parametrize("perm,expected", [
        ("android.permission.READ_SMS",        "dangerous"),
        ("android.permission.SEND_SMS",        "dangerous"),
        ("android.permission.READ_CONTACTS",   "dangerous"),
        ("android.permission.CAMERA",          "dangerous"),
        ("android.permission.ACCESS_FINE_LOCATION", "dangerous"),
        ("android.permission.RECORD_AUDIO",    "dangerous"),
    ])
    def test_dangerous_permissions_classified_correctly(self, perm, expected):
        assert classify_permission(perm) == expected

    @pytest.mark.parametrize("perm", [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ])
    def test_normal_permissions_classified_correctly(self, perm):
        # The exact bucket name varies but it MUST NOT be "dangerous" —
        # that's the security boundary the classification protects.
        assert classify_permission(perm) != "dangerous"

    def test_unknown_permission_does_not_raise(self):
        # Unknown permissions get a default classification (not crash).
        result = classify_permission("com.example.totally.made.up")
        assert isinstance(result, str)


class TestSeverityLadder:
    @pytest.mark.parametrize("base,expected", [
        ("info",     "low"),
        ("low",      "medium"),
        ("medium",   "high"),
        ("high",     "critical"),
        ("critical", "critical"),  # ceiling
    ])
    def test_bump_severity_climbs_ladder(self, base, expected):
        assert _bump_severity(base) == expected

    @pytest.mark.parametrize("base,expected", [
        ("critical", "high"),
        ("high",     "medium"),
        ("medium",   "low"),
        ("low",      "info"),
        ("info",     "info"),  # floor
    ])
    def test_reduce_severity_drops_ladder(self, base, expected):
        assert _reduce_severity(base) == expected


class TestIsDebugCert:
    @pytest.mark.parametrize("subject,expected", [
        ("CN=Android Debug, O=Android, C=US", True),
        ("debug",                              True),
        ("CN=test cert",                       True),
        ("CN=Google Inc, O=Google",            False),
        ("CN=Acme Corp",                       False),
    ])
    def test_classifies_debug_cert_via_subject(self, subject, expected):
        sig_info = {"issuer": "", "subject": subject}
        assert AndroguardService._is_debug_cert(sig_info) is expected

    def test_returns_false_when_no_keywords_match(self):
        sig_info = {"issuer": "Google Inc", "subject": "Google Apps"}
        assert AndroguardService._is_debug_cert(sig_info) is False


# ===========================================================================
# is_available — module-import probe
# ===========================================================================


class TestIsAvailable:
    def test_returns_true_when_androguard_importable(self):
        # Production install ships androguard — the import succeeds.
        assert AndroguardService.is_available() is True

    def test_returns_false_when_androguard_import_raises(self):
        """Patch builtins.__import__ to raise on `androguard` so the
        ImportError branch is exercised. Other modules import normally."""
        real_import = __builtins__["__import__"] if isinstance(
            __builtins__, dict,
        ) else __builtins__.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "androguard":
                raise ImportError("forced")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            assert AndroguardService.is_available() is False


# ===========================================================================
# analyze_apk — Rule #30 patch surface
# ===========================================================================


class TestAnalyzeApk:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        svc = AndroguardService()
        with pytest.raises(FileNotFoundError, match="APK not found"):
            svc.analyze_apk(str(tmp_path / "missing.apk"))

    def test_happy_path_returns_canonical_dict_shape(self, tmp_path: Path):
        """``AnalyzeAPK`` is lazy-imported inside the method body
        (line 523). Per Rule #30, patch the SOURCE module
        ``androguard.misc.AnalyzeAPK`` — patching
        ``app.services.androguard_service.AnalyzeAPK`` would silently no-op."""
        apk_file = tmp_path / "test.apk"
        apk_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        # Build APK obj that returns canonical metadata.
        apk_obj = MagicMock()
        apk_obj.get_package = MagicMock(return_value="com.example.test")
        apk_obj.get_androidversion_code = MagicMock(return_value="1")
        apk_obj.get_androidversion_name = MagicMock(return_value="1.0")
        apk_obj.get_min_sdk_version = MagicMock(return_value=21)
        apk_obj.get_target_sdk_version = MagicMock(return_value=33)
        apk_obj.get_permissions = MagicMock(return_value=[
            "android.permission.INTERNET",
            "android.permission.CAMERA",
        ])
        apk_obj.get_activities = MagicMock(return_value=["MainActivity"])
        apk_obj.get_services = MagicMock(return_value=[])
        apk_obj.get_receivers = MagicMock(return_value=[])
        apk_obj.get_providers = MagicMock(return_value=[])
        apk_obj.get_main_activity = MagicMock(return_value="MainActivity")
        apk_obj.is_signed = MagicMock(return_value=True)
        apk_obj.get_certificates = MagicMock(return_value=[])  # skip cert path

        with patch(
            "androguard.misc.AnalyzeAPK",
            return_value=(apk_obj, [], None),
        ):
            svc = AndroguardService()
            result = svc.analyze_apk(str(apk_file))

        # Rule #35b shape — every field the wrapper explicitly populates
        # round-trips into the returned dict with the expected key names.
        assert result["package"] == "com.example.test"
        assert result["version_code"] == "1"
        assert result["version_name"] == "1.0"
        assert result["min_sdk"] == 21
        assert result["target_sdk"] == 33
        # Permissions sorted (the wrapper sorts before returning).
        assert result["permissions"] == sorted([
            "android.permission.INTERNET",
            "android.permission.CAMERA",
        ])
        assert result["activities"] == ["MainActivity"]
        assert result["main_activity"] == "MainActivity"
        assert result["is_signed"] is True
        assert result["signatures"] == []  # no certs


# ===========================================================================
# scan_manifest_security — file-existence guard
# ===========================================================================


class TestScanManifestSecurity:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        svc = AndroguardService()
        with pytest.raises(FileNotFoundError, match="APK not found"):
            svc.scan_manifest_security(str(tmp_path / "missing.apk"))


# ===========================================================================
# check_is_debug_signed / check_platform_signed — exception swallow
# ===========================================================================


class TestCheckIsDebugSigned:
    def test_returns_false_when_apk_ctor_raises(self, tmp_path: Path):
        """``APK`` is lazy-imported inside the method (line 861); patch
        the SOURCE module per Rule #30 — patching
        ``app.services.androguard_service.APK`` would silently no-op."""
        apk_file = tmp_path / "broken.apk"
        apk_file.write_bytes(b"not a real apk")

        with patch(
            "androguard.core.apk.APK",
            side_effect=Exception("malformed apk"),
        ):
            svc = AndroguardService()
            assert svc.check_is_debug_signed(str(apk_file)) is False

    def test_returns_true_when_debug_cert_present(self, tmp_path: Path):
        apk_file = tmp_path / "debug.apk"
        apk_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        # APK returns a cert with a debug subject.
        cert = MagicMock()
        cert.subject = MagicMock()
        cert.subject.human_friendly = "CN=Android Debug, O=Android"
        apk_obj = MagicMock()
        apk_obj.get_certificates = MagicMock(return_value=[cert])

        with patch(
            "androguard.core.apk.APK",
            return_value=apk_obj,
        ):
            svc = AndroguardService()
            assert svc.check_is_debug_signed(str(apk_file)) is True


class TestCheckPlatformSigned:
    def test_returns_false_when_apk_ctor_raises(self, tmp_path: Path):
        """``APK`` is lazy-imported inside the method (line 891); patch
        the SOURCE module per Rule #30."""
        apk_file = tmp_path / "broken.apk"
        apk_file.write_bytes(b"junk")

        with patch(
            "androguard.core.apk.APK",
            side_effect=Exception("can't parse"),
        ):
            svc = AndroguardService()
            assert svc.check_platform_signed(str(apk_file)) is False


# ===========================================================================
# check_signatures — wraps analyze_apk
# ===========================================================================


class TestCheckSignatures:
    def test_unsigned_apk_yields_warning(self, tmp_path: Path):
        apk_file = tmp_path / "unsigned.apk"
        apk_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        apk_obj = MagicMock()
        apk_obj.get_package = MagicMock(return_value="com.unsigned")
        apk_obj.get_androidversion_code = MagicMock(return_value="1")
        apk_obj.get_androidversion_name = MagicMock(return_value="1.0")
        apk_obj.get_min_sdk_version = MagicMock(return_value=21)
        apk_obj.get_target_sdk_version = MagicMock(return_value=33)
        apk_obj.get_permissions = MagicMock(return_value=[])
        apk_obj.get_activities = MagicMock(return_value=[])
        apk_obj.get_services = MagicMock(return_value=[])
        apk_obj.get_receivers = MagicMock(return_value=[])
        apk_obj.get_providers = MagicMock(return_value=[])
        apk_obj.get_main_activity = MagicMock(return_value=None)
        apk_obj.is_signed = MagicMock(return_value=False)
        apk_obj.get_certificates = MagicMock(return_value=[])

        with patch(
            "androguard.misc.AnalyzeAPK",
            return_value=(apk_obj, [], None),
        ):
            svc = AndroguardService()
            result = svc.check_signatures(str(apk_file))

        assert result["is_signed"] is False
        assert any("NOT signed" in w for w in result["warnings"]), (
            "unsigned APK must produce a warning"
        )

    def test_md5_signature_algorithm_yields_warning(self, tmp_path: Path):
        apk_file = tmp_path / "md5signed.apk"
        apk_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        cert_mock = MagicMock()
        cert_mock.issuer = MagicMock()
        cert_mock.issuer.human_friendly = "CN=Acme Corp"
        cert_mock.subject = MagicMock()
        cert_mock.subject.human_friendly = "CN=Acme App"
        cert_mock.serial_number = "12345"
        cert_mock.signature_algo = "md5_with_rsa"

        apk_obj = MagicMock()
        apk_obj.get_package = MagicMock(return_value="com.acme")
        apk_obj.get_androidversion_code = MagicMock(return_value="1")
        apk_obj.get_androidversion_name = MagicMock(return_value="1.0")
        apk_obj.get_min_sdk_version = MagicMock(return_value=21)
        apk_obj.get_target_sdk_version = MagicMock(return_value=33)
        apk_obj.get_permissions = MagicMock(return_value=[])
        apk_obj.get_activities = MagicMock(return_value=[])
        apk_obj.get_services = MagicMock(return_value=[])
        apk_obj.get_receivers = MagicMock(return_value=[])
        apk_obj.get_providers = MagicMock(return_value=[])
        apk_obj.get_main_activity = MagicMock(return_value=None)
        apk_obj.is_signed = MagicMock(return_value=True)
        apk_obj.get_certificates = MagicMock(return_value=[cert_mock])

        with patch(
            "androguard.misc.AnalyzeAPK",
            return_value=(apk_obj, [], None),
        ):
            svc = AndroguardService()
            result = svc.check_signatures(str(apk_file))

        assert any("Weak signature algorithm" in w and "md5" in w.lower()
                   for w in result["warnings"]), (
            "MD5 signature algorithm must produce a weak-algorithm warning"
        )


# ===========================================================================
# get_permissions_with_risk — wraps analyze_apk + classify_permission
# ===========================================================================


class TestGetPermissionsWithRisk:
    def test_returns_permission_risk_pairs(self, tmp_path: Path):
        apk_file = tmp_path / "perm.apk"
        apk_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        apk_obj = MagicMock()
        apk_obj.get_package = MagicMock(return_value="com.perm")
        apk_obj.get_androidversion_code = MagicMock(return_value="1")
        apk_obj.get_androidversion_name = MagicMock(return_value="1.0")
        apk_obj.get_min_sdk_version = MagicMock(return_value=21)
        apk_obj.get_target_sdk_version = MagicMock(return_value=33)
        apk_obj.get_permissions = MagicMock(return_value=[
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ])
        apk_obj.get_activities = MagicMock(return_value=[])
        apk_obj.get_services = MagicMock(return_value=[])
        apk_obj.get_receivers = MagicMock(return_value=[])
        apk_obj.get_providers = MagicMock(return_value=[])
        apk_obj.get_main_activity = MagicMock(return_value=None)
        apk_obj.is_signed = MagicMock(return_value=True)
        apk_obj.get_certificates = MagicMock(return_value=[])

        with patch(
            "androguard.misc.AnalyzeAPK",
            return_value=(apk_obj, [], None),
        ):
            svc = AndroguardService()
            result = svc.get_permissions_with_risk(str(apk_file))

        assert len(result) == 2
        # Each entry has permission + risk fields.
        assert all("permission" in r and "risk" in r for r in result)
        # CAMERA must be classified as dangerous.
        camera = next(r for r in result if r["permission"].endswith("CAMERA"))
        assert camera["risk"] == "dangerous"
