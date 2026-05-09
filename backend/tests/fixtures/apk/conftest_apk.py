"""Pytest fixtures for synthetic APK testing.

Import these fixtures in your test's conftest.py or import directly:

    from tests.fixtures.apk.conftest_apk import (
        mock_apk_debuggable,
        mock_apk_kitchen_sink,
        ...
    )

Each fixture returns a MagicMock APK object that can be passed directly
to AndroguardService methods. No real APK files or androguard installation
required.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.fixtures.apk import apk_fixture_manifests as manifests
from tests.fixtures.apk.mock_apk_factory import build_mock_apk

# ---------------------------------------------------------------------------
# Individual check fixtures (one per MANIFEST-NNN)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_apk_debuggable() -> MagicMock:
    """APK triggering MANIFEST-001 (debuggable)."""
    return build_mock_apk(manifests.DEBUGGABLE_APK)


@pytest.fixture
def mock_apk_allow_backup() -> MagicMock:
    """APK triggering MANIFEST-002 (allowBackup)."""
    return build_mock_apk(manifests.ALLOW_BACKUP_APK)


@pytest.fixture
def mock_apk_cleartext_traffic() -> MagicMock:
    """APK triggering MANIFEST-003 (cleartext traffic)."""
    return build_mock_apk(manifests.CLEARTEXT_TRAFFIC_APK)


@pytest.fixture
def mock_apk_test_only() -> MagicMock:
    """APK triggering MANIFEST-004 (testOnly)."""
    return build_mock_apk(manifests.TEST_ONLY_APK)


@pytest.fixture
def mock_apk_min_sdk_outdated() -> MagicMock:
    """APK triggering MANIFEST-005 (outdated minSdk)."""
    return build_mock_apk(manifests.MIN_SDK_OUTDATED_APK)


@pytest.fixture
def mock_apk_exported_components() -> MagicMock:
    """APK triggering MANIFEST-006 (exported components)."""
    return build_mock_apk(manifests.EXPORTED_COMPONENTS_APK)


@pytest.fixture
def mock_apk_weak_permissions() -> MagicMock:
    """APK triggering MANIFEST-007 (weak custom permissions)."""
    return build_mock_apk(manifests.WEAK_PERMISSIONS_APK)


@pytest.fixture
def mock_apk_strandhogg_v1() -> MagicMock:
    """APK triggering MANIFEST-008 (StrandHogg v1)."""
    return build_mock_apk(manifests.STRANDHOGG_V1_APK)


@pytest.fixture
def mock_apk_strandhogg_v2() -> MagicMock:
    """APK triggering MANIFEST-009 (StrandHogg v2)."""
    return build_mock_apk(manifests.STRANDHOGG_V2_APK)


@pytest.fixture
def mock_apk_app_links() -> MagicMock:
    """APK triggering MANIFEST-010 (browsable intents / app links)."""
    return build_mock_apk(manifests.APP_LINKS_APK)


@pytest.fixture
def mock_apk_network_security_config() -> MagicMock:
    """APK triggering MANIFEST-011 (insecure network security config)."""
    return build_mock_apk(manifests.NETWORK_SECURITY_CONFIG_APK)


@pytest.fixture
def mock_apk_task_reparenting() -> MagicMock:
    """APK triggering MANIFEST-012 (allowTaskReparenting)."""
    return build_mock_apk(manifests.TASK_REPARENTING_APK)


@pytest.fixture
def mock_apk_implicit_intent() -> MagicMock:
    """APK triggering MANIFEST-013 (implicit intent hijacking)."""
    return build_mock_apk(manifests.IMPLICIT_INTENT_APK)


@pytest.fixture
def mock_apk_signing_scheme() -> MagicMock:
    """APK triggering MANIFEST-014 (weak signing scheme)."""
    return build_mock_apk(manifests.SIGNING_SCHEME_APK)


@pytest.fixture
def mock_apk_backup_agent() -> MagicMock:
    """APK triggering MANIFEST-015 (backup agent)."""
    return build_mock_apk(manifests.BACKUP_AGENT_APK)


@pytest.fixture
def mock_apk_dangerous_permissions() -> MagicMock:
    """APK triggering MANIFEST-016 (dangerous permissions)."""
    return build_mock_apk(manifests.DANGEROUS_PERMISSIONS_APK)


@pytest.fixture
def mock_apk_intent_scheme() -> MagicMock:
    """APK triggering MANIFEST-017 (intent scheme hijacking)."""
    return build_mock_apk(manifests.INTENT_SCHEME_APK)


@pytest.fixture
def mock_apk_shared_user_id() -> MagicMock:
    """APK triggering MANIFEST-018 (sharedUserId)."""
    return build_mock_apk(manifests.SHARED_USER_ID_APK)


# ---------------------------------------------------------------------------
# Composite fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_apk_kitchen_sink() -> MagicMock:
    """APK triggering ALL manifest checks (maximum vulnerability surface)."""
    return build_mock_apk(manifests.KITCHEN_SINK_APK)


@pytest.fixture
def mock_apk_clean() -> MagicMock:
    """Clean APK that should produce zero findings."""
    return build_mock_apk(manifests.CLEAN_APK)


# ---------------------------------------------------------------------------
# Known-good (secure) fixtures — should produce zero findings
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_apk_secure_full() -> MagicMock:
    """Fully hardened APK with all best practices."""
    return build_mock_apk(manifests.SECURE_FULL_APK)


@pytest.fixture
def mock_apk_secure_with_exports() -> MagicMock:
    """APK with exported components properly protected by signature perms."""
    return build_mock_apk(manifests.SECURE_WITH_EXPORTS_APK)


@pytest.fixture
def mock_apk_secure_custom_perms() -> MagicMock:
    """APK with custom permissions at signature protectionLevel."""
    return build_mock_apk(manifests.SECURE_CUSTOM_PERMS_APK)


@pytest.fixture
def mock_apk_secure_network_config() -> MagicMock:
    """APK with proper network security config (no cleartext, system CAs)."""
    return build_mock_apk(manifests.SECURE_NETWORK_CONFIG_APK)


@pytest.fixture
def mock_apk_secure_minimal() -> MagicMock:
    """Minimal secure APK relying on safe defaults for modern SDK."""
    return build_mock_apk(manifests.SECURE_MINIMAL_APK)


@pytest.fixture
def mock_apk_secure_complex() -> MagicMock:
    """Complex multi-component app, all properly secured."""
    return build_mock_apk(manifests.SECURE_COMPLEX_APK)


# ---------------------------------------------------------------------------
# Parameterized fixture: iterate over all single-check fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(
    params=[
        ("debuggable.apk", manifests.DEBUGGABLE_APK),
        ("allow_backup.apk", manifests.ALLOW_BACKUP_APK),
        ("cleartext_traffic.apk", manifests.CLEARTEXT_TRAFFIC_APK),
        ("test_only.apk", manifests.TEST_ONLY_APK),
        ("min_sdk_outdated.apk", manifests.MIN_SDK_OUTDATED_APK),
        ("exported_components.apk", manifests.EXPORTED_COMPONENTS_APK),
        ("weak_permissions.apk", manifests.WEAK_PERMISSIONS_APK),
        ("strandhogg_v1.apk", manifests.STRANDHOGG_V1_APK),
        ("strandhogg_v2.apk", manifests.STRANDHOGG_V2_APK),
        ("app_links.apk", manifests.APP_LINKS_APK),
        ("network_security_config.apk", manifests.NETWORK_SECURITY_CONFIG_APK),
        ("task_reparenting.apk", manifests.TASK_REPARENTING_APK),
        ("implicit_intent.apk", manifests.IMPLICIT_INTENT_APK),
        ("signing_scheme.apk", manifests.SIGNING_SCHEME_APK),
        ("backup_agent.apk", manifests.BACKUP_AGENT_APK),
        ("dangerous_permissions.apk", manifests.DANGEROUS_PERMISSIONS_APK),
        ("intent_scheme.apk", manifests.INTENT_SCHEME_APK),
        ("shared_user_id.apk", manifests.SHARED_USER_ID_APK),
    ],
    ids=lambda p: p[0],
)
def mock_apk_single_check(request) -> tuple[str, dict[str, Any], MagicMock]:
    """Parameterized fixture yielding (filename, fixture_def, mock_apk) for each single-check APK.

    Use in tests that want to validate each check individually:

        def test_each_check_triggers(mock_apk_single_check):
            filename, fixture_def, apk = mock_apk_single_check
            expected = fixture_def["expected_checks"]
            # ... run scan and validate ...
    """
    filename, fixture_def = request.param
    return filename, fixture_def, build_mock_apk(fixture_def)
