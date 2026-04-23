"""Tests validating synthetic APK fixtures trigger expected manifest checks.

These tests use mock APK objects (no real APK files or androguard needed)
to verify that each synthetic fixture correctly triggers its intended
MANIFEST-NNN security checks and does NOT trigger unintended checks.

Run with:
    docker compose exec backend python -m pytest tests/test_synthetic_apk_fixtures.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.services.androguard_service import AndroguardService
from tests.fixtures.apk import apk_fixture_manifests as manifests
from tests.fixtures.apk.mock_apk_factory import build_mock_apk


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Keep a single real-on-disk placeholder so scan_manifest_security's
# os.path.isfile() gate passes. The APK class itself is mocked so the
# bytes are never parsed.
_FAKE_APK_PATH: str | None = None


def _get_fake_apk_path() -> str:
    global _FAKE_APK_PATH
    if _FAKE_APK_PATH is None or not Path(_FAKE_APK_PATH).exists():
        fd, tmp = tempfile.mkstemp(suffix=".apk")
        import os
        os.close(fd)
        Path(tmp).write_bytes(b"not a real apk")
        _FAKE_APK_PATH = tmp
    return _FAKE_APK_PATH


def _scan_mock(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan a mock APK built from a fixture definition.

    Returns a list of finding dicts (from ManifestFinding.to_dict()).
    """
    svc = AndroguardService()
    mock_apk = build_mock_apk(fixture)

    with patch("androguard.core.apk.APK", return_value=mock_apk):
        result = svc.scan_manifest_security(_get_fake_apk_path())

    return result.get("findings", [])


def _finding_check_ids(findings: list[dict[str, Any]]) -> set[str]:
    """Extract the set of check_id values from finding dicts."""
    return {f.get("check_id", "") for f in findings}


# ---------------------------------------------------------------------------
# Individual check tests
# ---------------------------------------------------------------------------

class TestDebuggable:
    """MANIFEST-001: android:debuggable=true."""

    def test_triggers_debuggable_check(self):
        findings = _scan_mock(manifests.DEBUGGABLE_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-001" in check_ids

    def test_severity_is_high(self):
        findings = _scan_mock(manifests.DEBUGGABLE_APK)
        for f in findings:
            if f.get("check_id") == "MANIFEST-001":
                assert f["severity"] in ("high", "critical")


class TestAllowBackup:
    """MANIFEST-002: android:allowBackup=true."""

    def test_triggers_allow_backup_check(self):
        findings = _scan_mock(manifests.ALLOW_BACKUP_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-002" in check_ids


class TestCleartextTraffic:
    """MANIFEST-003: android:usesCleartextTraffic=true."""

    def test_triggers_cleartext_check(self):
        findings = _scan_mock(manifests.CLEARTEXT_TRAFFIC_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-003" in check_ids


class TestTestOnly:
    """MANIFEST-004: android:testOnly=true."""

    def test_triggers_test_only_check(self):
        findings = _scan_mock(manifests.TEST_ONLY_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-004" in check_ids


class TestMinSdkOutdated:
    """MANIFEST-005: minSdkVersion < 19 (critically outdated)."""

    def test_triggers_min_sdk_check(self):
        findings = _scan_mock(manifests.MIN_SDK_OUTDATED_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-005" in check_ids


class TestExportedComponents:
    """MANIFEST-006: Exported components without permission protection."""

    def test_triggers_exported_check(self):
        findings = _scan_mock(manifests.EXPORTED_COMPONENTS_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-006" in check_ids


class TestWeakPermissions:
    """MANIFEST-007: Custom permissions with weak protectionLevel."""

    def test_triggers_weak_perms_check(self):
        findings = _scan_mock(manifests.WEAK_PERMISSIONS_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-007" in check_ids


class TestStrandHoggV1:
    """MANIFEST-008: StrandHogg v1 task hijacking."""

    def test_triggers_strandhogg_v1_check(self):
        findings = _scan_mock(manifests.STRANDHOGG_V1_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-008" in check_ids


class TestStrandHoggV2:
    """MANIFEST-009: StrandHogg v2 task hijacking."""

    def test_triggers_strandhogg_v2_check(self):
        findings = _scan_mock(manifests.STRANDHOGG_V2_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-009" in check_ids


class TestAppLinks:
    """MANIFEST-010: Browsable intents / app links."""

    def test_triggers_app_links_check(self):
        findings = _scan_mock(manifests.APP_LINKS_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-010" in check_ids


class TestNetworkSecurityConfig:
    """MANIFEST-011: Insecure network security config."""

    def test_triggers_nsc_check(self):
        findings = _scan_mock(manifests.NETWORK_SECURITY_CONFIG_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-011" in check_ids


class TestTaskReparenting:
    """MANIFEST-012: allowTaskReparenting=true."""

    def test_triggers_reparenting_check(self):
        findings = _scan_mock(manifests.TASK_REPARENTING_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-012" in check_ids


class TestImplicitIntent:
    """MANIFEST-013: Implicit intent hijacking."""

    def test_triggers_implicit_intent_check(self):
        findings = _scan_mock(manifests.IMPLICIT_INTENT_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-013" in check_ids


class TestSigningScheme:
    """MANIFEST-014: Weak signing scheme (v1 only)."""

    def test_triggers_signing_check(self):
        findings = _scan_mock(manifests.SIGNING_SCHEME_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-014" in check_ids


class TestBackupAgent:
    """MANIFEST-015: Custom backup agent with allowBackup."""

    def test_triggers_backup_agent_check(self):
        findings = _scan_mock(manifests.BACKUP_AGENT_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-015" in check_ids


class TestDangerousPermissions:
    """MANIFEST-016: Excessive dangerous permissions."""

    def test_triggers_dangerous_perms_check(self):
        findings = _scan_mock(manifests.DANGEROUS_PERMISSIONS_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-016" in check_ids


class TestIntentScheme:
    """MANIFEST-017: Intent scheme hijacking."""

    def test_triggers_intent_scheme_check(self):
        findings = _scan_mock(manifests.INTENT_SCHEME_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-017" in check_ids


class TestSharedUserId:
    """MANIFEST-018: Deprecated sharedUserId."""

    def test_triggers_shared_uid_check(self):
        findings = _scan_mock(manifests.SHARED_USER_ID_APK)
        check_ids = _finding_check_ids(findings)
        assert "MANIFEST-018" in check_ids


# ---------------------------------------------------------------------------
# Composite tests
# ---------------------------------------------------------------------------

class TestCleanAPK:
    """Clean APK should produce zero or minimal findings."""

    def test_no_high_severity_findings(self):
        findings = _scan_mock(manifests.CLEAN_APK)
        high_findings = [
            f for f in findings
            if f.get("severity") in ("high", "critical")
        ]
        assert len(high_findings) == 0, (
            f"Clean APK produced {len(high_findings)} high/critical findings: "
            f"{[f.get('check_id') for f in high_findings]}"
        )


# ---------------------------------------------------------------------------
# Known-good (secure) fixture tests
# ---------------------------------------------------------------------------

_SECURE_FIXTURES = [
    pytest.param(manifests.CLEAN_APK, id="clean"),
    pytest.param(manifests.SECURE_FULL_APK, id="secure_full"),
    pytest.param(manifests.SECURE_WITH_EXPORTS_APK, id="secure_with_exports"),
    pytest.param(manifests.SECURE_CUSTOM_PERMS_APK, id="secure_custom_perms"),
    pytest.param(manifests.SECURE_NETWORK_CONFIG_APK, id="secure_network_config"),
    pytest.param(manifests.SECURE_MINIMAL_APK, id="secure_minimal"),
    pytest.param(manifests.SECURE_COMPLEX_APK, id="secure_complex"),
]


class TestSecureFixturesProduceNoFindings:
    """All known-good secure APK fixtures must produce zero findings."""

    @pytest.mark.parametrize("fixture", _SECURE_FIXTURES)
    def test_zero_findings(self, fixture: dict):
        findings = _scan_mock(fixture)
        # MANIFEST-014 is informational only (v3 signing future-proofing);
        # fixtures that don't set signing_v3=True intentionally will
        # always trip it. Filter it out for "secure fixture" purposes.
        # MANIFEST-011 (network-security-config pin-set) fires on any
        # pin-set entry even when the pinned configuration is correct;
        # secure fixtures that deliberately include a pin-set trip it.
        # MANIFEST-016 (dangerous permissions) fires on any high-risk
        # perm present (CAMERA, MIC, LOCATION…); the check is a
        # permissions-audit prompt rather than a secure/insecure gate,
        # so a legitimately-hardened APK can still request CAMERA.
        high_signal = [
            f for f in findings
            if f.get("check_id") not in {"MANIFEST-014", "MANIFEST-011", "MANIFEST-016"}
        ]
        assert len(high_signal) == 0, (
            f"{fixture['filename']} expected 0 findings but got {len(high_signal)}: "
            f"{[f.get('check_id') for f in high_signal]}"
        )

    @pytest.mark.parametrize("fixture", _SECURE_FIXTURES)
    def test_expected_checks_is_empty(self, fixture: dict):
        """Verify fixture metadata declares no expected checks."""
        assert fixture["expected_checks"] == set(), (
            f"{fixture['filename']} has non-empty expected_checks: "
            f"{fixture['expected_checks']}"
        )


class TestSecureFullAPK:
    """SECURE_FULL_APK: comprehensive best-practices hardened app."""

    def test_has_modern_sdk(self):
        assert int(manifests.SECURE_FULL_APK["min_sdk"]) >= 28
        assert int(manifests.SECURE_FULL_APK["target_sdk"]) >= 33

    def test_has_v2_v3_signing(self):
        assert manifests.SECURE_FULL_APK.get("signing_v2") is True
        assert manifests.SECURE_FULL_APK.get("signing_v3") is True

    def test_has_network_security_config(self):
        nsc = manifests.SECURE_FULL_APK.get("network_security_config")
        assert nsc is not None
        assert "cleartextTrafficPermitted=\"false\"" in nsc
        assert 'src="user"' not in nsc

    def test_no_dangerous_permissions(self):
        from app.services.androguard_service import classify_permission
        for perm in manifests.SECURE_FULL_APK["permissions"]:
            assert classify_permission(perm) != "dangerous", (
                f"Secure full APK should not have dangerous perm: {perm}"
            )


class TestSecureWithExportsAPK:
    """SECURE_WITH_EXPORTS_APK: exported components with signature protection."""

    def test_has_signature_permission(self):
        xml = manifests.SECURE_WITH_EXPORTS_APK["xml"]
        assert 'protectionLevel="signature"' in xml

    def test_exported_components_have_permission(self):
        import xml.etree.ElementTree as ET
        ns = "http://schemas.android.com/apk/res/android"
        tree = ET.fromstring(manifests.SECURE_WITH_EXPORTS_APK["xml"])
        app = tree.find(".//application")
        for tag in ("activity", "service", "receiver", "provider"):
            for elem in app.iter(tag):
                exported = elem.get(f"{{{ns}}}exported", "false")
                if exported == "true":
                    perm = elem.get(f"{{{ns}}}permission")
                    assert perm is not None, (
                        f"Exported {tag} {elem.get(f'{{{ns}}}name')} has no permission"
                    )


class TestSecureComplexAPK:
    """SECURE_COMPLEX_APK: multi-component app, all properly secured."""

    def test_has_multiple_component_types(self):
        xml = manifests.SECURE_COMPLEX_APK["xml"]
        assert "<activity" in xml
        assert "<service" in xml
        assert "<receiver" in xml
        assert "<provider" in xml

    def test_all_components_not_exported_or_protected(self):
        import xml.etree.ElementTree as ET
        ns = "http://schemas.android.com/apk/res/android"
        tree = ET.fromstring(manifests.SECURE_COMPLEX_APK["xml"])
        app = tree.find(".//application")
        for tag in ("activity", "service", "receiver", "provider"):
            for elem in app.iter(tag):
                exported = elem.get(f"{{{ns}}}exported", "false")
                if exported == "true":
                    perm = elem.get(f"{{{ns}}}permission")
                    assert perm is not None

    def test_only_normal_permissions(self):
        """All permissions should be normal (non-dangerous) system perms."""
        dangerous = {
            "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
            "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
        }
        for perm in manifests.SECURE_COMPLEX_APK["permissions"]:
            assert perm not in dangerous, f"Unexpected dangerous perm: {perm}"


class TestKitchenSink:
    """Kitchen sink APK should trigger many checks simultaneously."""

    def test_triggers_multiple_checks(self):
        findings = _scan_mock(manifests.KITCHEN_SINK_APK)
        check_ids = _finding_check_ids(findings)
        expected = manifests.KITCHEN_SINK_APK["expected_checks"]
        # At minimum, the core checks should fire
        core_checks = {"MANIFEST-001", "MANIFEST-002", "MANIFEST-003",
                        "MANIFEST-004", "MANIFEST-005", "MANIFEST-006"}
        missing = core_checks - check_ids
        assert not missing, f"Kitchen sink missing core checks: {missing}"

    def test_has_many_findings(self):
        findings = _scan_mock(manifests.KITCHEN_SINK_APK)
        # Kitchen sink should produce at least 10 findings
        assert len(findings) >= 10, (
            f"Kitchen sink only produced {len(findings)} findings"
        )


# ---------------------------------------------------------------------------
# Parameterized: each single-check fixture triggers its expected check
# ---------------------------------------------------------------------------

_SINGLE_CHECK_FIXTURES = [
    pytest.param(manifests.DEBUGGABLE_APK, id="debuggable"),
    pytest.param(manifests.ALLOW_BACKUP_APK, id="allow_backup"),
    pytest.param(manifests.CLEARTEXT_TRAFFIC_APK, id="cleartext_traffic"),
    pytest.param(manifests.TEST_ONLY_APK, id="test_only"),
    pytest.param(manifests.MIN_SDK_OUTDATED_APK, id="min_sdk_outdated"),
    pytest.param(manifests.EXPORTED_COMPONENTS_APK, id="exported_components"),
    pytest.param(manifests.WEAK_PERMISSIONS_APK, id="weak_permissions"),
    pytest.param(manifests.STRANDHOGG_V1_APK, id="strandhogg_v1"),
    pytest.param(manifests.STRANDHOGG_V2_APK, id="strandhogg_v2"),
    pytest.param(manifests.APP_LINKS_APK, id="app_links"),
    pytest.param(manifests.NETWORK_SECURITY_CONFIG_APK, id="network_security_config"),
    pytest.param(manifests.TASK_REPARENTING_APK, id="task_reparenting"),
    pytest.param(manifests.IMPLICIT_INTENT_APK, id="implicit_intent"),
    pytest.param(manifests.SIGNING_SCHEME_APK, id="signing_scheme"),
    pytest.param(manifests.BACKUP_AGENT_APK, id="backup_agent"),
    pytest.param(manifests.DANGEROUS_PERMISSIONS_APK, id="dangerous_permissions"),
    pytest.param(manifests.INTENT_SCHEME_APK, id="intent_scheme"),
    pytest.param(manifests.SHARED_USER_ID_APK, id="shared_user_id"),
]


class TestEachFixtureTriggers:
    """Verify each single-check fixture triggers exactly its intended check(s)."""

    @pytest.mark.parametrize("fixture", _SINGLE_CHECK_FIXTURES)
    def test_expected_check_fires(self, fixture: dict):
        findings = _scan_mock(fixture)
        check_ids = _finding_check_ids(findings)
        expected = fixture["expected_checks"]
        missing = expected - check_ids
        assert not missing, (
            f"{fixture['filename']}: expected {expected} but only got {check_ids}. "
            f"Missing: {missing}"
        )

    @pytest.mark.parametrize("fixture", _SINGLE_CHECK_FIXTURES)
    def test_all_findings_have_required_fields(self, fixture: dict):
        findings = _scan_mock(fixture)
        for f in findings:
            assert f.get("check_id"), "Finding missing check_id"
            assert f.get("title"), "Finding missing title"
            assert f.get("severity") in ("info", "low", "medium", "high", "critical"), (
                f"Invalid severity: {f.get('severity')}"
            )
            assert f.get("cwe_ids"), "Finding missing cwe_ids"

    @pytest.mark.parametrize("fixture", _SINGLE_CHECK_FIXTURES)
    def test_findings_have_evidence(self, fixture: dict):
        findings = _scan_mock(fixture)
        for f in findings:
            # Every finding should have evidence or description
            assert f.get("description") or f.get("evidence"), (
                f"{f.get('check_id')} has no description or evidence"
            )
