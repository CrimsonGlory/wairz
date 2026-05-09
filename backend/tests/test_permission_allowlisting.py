"""Tests for permission-combination allowlisting in the manifest security checker.

Verifies that known-safe permission groups (e.g., INTERNET + ACCESS_NETWORK_STATE)
correctly suppress or reduce confidence of false-positive findings.
"""


from app.services.androguard_service import (
    _SAFE_PERMISSION_GROUPS,
    ManifestFinding,
    _apply_permission_allowlisting,
)


class TestPermissionAllowlistDataStructure:
    """Verify the allowlist entries are well-formed."""

    def test_all_entries_have_permissions(self):
        for entry in _SAFE_PERMISSION_GROUPS:
            assert len(entry.permissions) >= 2, (
                f"Allowlist entry '{entry.reason}' should have at least 2 permissions"
            )

    def test_all_entries_have_reason(self):
        for entry in _SAFE_PERMISSION_GROUPS:
            assert entry.reason, "Every allowlist entry must have a reason"

    def test_all_permissions_are_fully_qualified(self):
        for entry in _SAFE_PERMISSION_GROUPS:
            for perm in entry.permissions:
                assert perm.startswith("android.permission."), (
                    f"Permission '{perm}' should be fully qualified"
                )

    def test_at_least_ten_safe_groups(self):
        """We should have a reasonable number of known-safe groups."""
        assert len(_SAFE_PERMISSION_GROUPS) >= 10


class TestNetworkingAllowlist:
    """INTERNET + ACCESS_NETWORK_STATE is the most common safe pair."""

    def test_internet_plus_network_state_suppresses_manifest006(self):
        """MANIFEST-006 should be suppressed for basic networking apps."""
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components without permission protection",
                severity="medium",
                description="test",
                evidence="test evidence",
                cwe_ids=["CWE-926"],
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 1
        assert result[0].suppressed is True
        assert "networking" in result[0].suppression_reason.lower()

    def test_internet_plus_network_state_reduces_confidence_for_others(self):
        """Non-suppressible findings should get confidence reduced."""
        findings = [
            ManifestFinding(
                check_id="MANIFEST-001",
                title="Debuggable",
                severity="high",
                description="test",
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 0  # not suppressed
        assert result[0].suppressed is False
        assert result[0].confidence == "low"  # reduced

    def test_networking_triple_also_works(self):
        """INTERNET + NETWORK_STATE + WIFI_STATE also safe."""
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="medium",
                description="test",
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 1
        assert result[0].suppressed is True


class TestNoSuppression:
    """Verify findings are NOT suppressed when they shouldn't be."""

    def test_no_permissions_no_suppression(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-001",
                title="Debuggable",
                severity="high",
                description="test",
                confidence="high",
            ),
        ]
        result, count, reasons = _apply_permission_allowlisting(findings, set())
        assert count == 0
        assert result[0].suppressed is False
        assert result[0].confidence == "high"

    def test_dangerous_permissions_not_in_allowlist(self):
        """Unusual dangerous perms should not trigger suppression."""
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="medium",
                description="test",
                confidence="high",
            ),
        ]
        # SEND_SMS is dangerous and not in a simple safe group
        perms = {
            "android.permission.SEND_SMS",
            "android.permission.CAMERA",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 0
        assert result[0].suppressed is False

    def test_empty_findings_no_crash(self):
        result, count, reasons = _apply_permission_allowlisting(
            [], {"android.permission.INTERNET"}
        )
        assert count == 0
        assert result == []


class TestMultipleFindings:
    """Test with multiple findings - some suppressed, some not."""

    def test_mixed_suppression(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="medium",
                description="test",
                confidence="high",
            ),
            ManifestFinding(
                check_id="MANIFEST-001",
                title="Debuggable",
                severity="high",
                description="test",
                confidence="high",
            ),
            ManifestFinding(
                check_id="MANIFEST-002",
                title="Allow backup",
                severity="medium",
                description="test",
                confidence="medium",
            ),
        ]
        perms = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)

        # MANIFEST-006 should be suppressed
        assert result[0].suppressed is True
        assert count == 1

        # MANIFEST-001 and MANIFEST-002 should have reduced confidence
        assert result[1].suppressed is False
        assert result[1].confidence == "low"
        assert result[2].suppressed is False
        assert result[2].confidence == "low"


class TestManifestFindingToDict:
    """Test that suppression info is included in to_dict()."""

    def test_suppressed_finding_includes_fields(self):
        f = ManifestFinding(
            check_id="MANIFEST-006",
            title="Test",
            severity="medium",
            description="test",
            suppressed=True,
            suppression_reason="Test reason",
        )
        d = f.to_dict()
        assert d["suppressed"] is True
        assert d["suppression_reason"] == "Test reason"

    def test_non_suppressed_finding_excludes_fields(self):
        f = ManifestFinding(
            check_id="MANIFEST-001",
            title="Test",
            severity="high",
            description="test",
        )
        d = f.to_dict()
        assert "suppressed" not in d  # not included when False


class TestLocationPairAllowlist:
    """Test location permission pair allowlisting."""

    def test_fine_plus_coarse_reduces_confidence(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-001",
                title="Debuggable",
                severity="high",
                description="test",
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 0  # no suppression for MANIFEST-001
        assert result[0].confidence == "low"  # but confidence reduced


class TestStoragePairAllowlist:
    """Test storage permission pair allowlisting."""

    def test_read_write_external_reduces_confidence(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-002",
                title="Allow backup",
                severity="medium",
                description="test",
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert result[0].confidence == "low"


class TestBluetoothPairAllowlist:
    """Test Bluetooth permission pair allowlisting."""

    def test_bt_connect_plus_scan_reduces_confidence(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="low",
                description="test",
                confidence="medium",
            ),
        ]
        perms = {
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert result[0].confidence == "low"


class TestBootCompletedAllowlist:
    """Test RECEIVE_BOOT_COMPLETED + FOREGROUND_SERVICE allowlisting."""

    def test_boot_plus_foreground_suppresses_manifest006(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="medium",
                description="test",
                confidence="high",
            ),
        ]
        perms = {
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        assert count == 1
        assert result[0].suppressed is True


class TestAlreadySuppressed:
    """Test that already-suppressed findings aren't double-processed."""

    def test_already_suppressed_not_reprocessed(self):
        findings = [
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components",
                severity="medium",
                description="test",
                confidence="high",
                suppressed=True,
                suppression_reason="Already suppressed",
            ),
        ]
        perms = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        }
        result, count, reasons = _apply_permission_allowlisting(findings, perms)
        # Should not count as newly suppressed
        assert count == 0
        assert result[0].suppression_reason == "Already suppressed"
