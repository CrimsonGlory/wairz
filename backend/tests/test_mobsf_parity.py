"""Parity validation test suite: Wairz manifest scanner vs MobSF baseline.

Loads both MobSF-expected finding sets and Wairz-produced findings per APK,
asserts Wairz findings are a **superset** of MobSF findings, and fails on
any missed critical/high issues with detailed diff reporting.

Target APKs (all well-known intentionally vulnerable apps):
  - DIVA (jakhar.aseem.diva)
  - InsecureBankv2 (com.android.insecurebankv2)
  - OVAA (oversecured.ovaa)

The test does NOT require real APK files — it uses mocked Androguard APK
objects matching each app's real manifest structure.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, PropertyMock

import pytest

from app.services.androguard_service import AndroguardService, ManifestFinding

# ---------------------------------------------------------------------------
# MobSF baseline definition
# ---------------------------------------------------------------------------

_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class MobSFBaselineFinding:
    """A single expected finding from MobSF for parity comparison."""

    check_id: str
    title_pattern: str  # substring that Wairz title must contain
    min_severity: str  # minimum acceptable severity (ordered scale)
    cwe_ids: list[str] = field(default_factory=list)
    critical: bool = False  # True => must NOT be missed, even if low severity

    def __repr__(self) -> str:
        return f"Baseline({self.check_id}: {self.title_pattern} [{self.min_severity}])"


# Severity ordering for comparison
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_ge(actual: str, minimum: str) -> bool:
    """Return True if actual severity >= minimum severity."""
    return _SEVERITY_ORDER.get(actual, -1) >= _SEVERITY_ORDER.get(minimum, 0)


# ---------------------------------------------------------------------------
# Per-APK MobSF baselines
# ---------------------------------------------------------------------------

DIVA_MOBSF_BASELINE: list[MobSFBaselineFinding] = [
    MobSFBaselineFinding(
        check_id="MANIFEST-001",
        title_pattern="debuggable",
        min_severity="high",
        cwe_ids=["CWE-489"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-002",
        title_pattern="backup",
        min_severity="medium",
        cwe_ids=["CWE-921"],
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-003",
        title_pattern="cleartext",
        min_severity="medium",
        cwe_ids=["CWE-319"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-005",
        title_pattern="minSdk",
        min_severity="high",
        cwe_ids=["CWE-1104"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-006",
        title_pattern="exported",
        min_severity="medium",
        cwe_ids=["CWE-926"],
        critical=True,
    ),
]

INSECUREBANKV2_MOBSF_BASELINE: list[MobSFBaselineFinding] = [
    MobSFBaselineFinding(
        check_id="MANIFEST-001",
        title_pattern="debuggable",
        min_severity="high",
        cwe_ids=["CWE-489"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-002",
        title_pattern="backup",
        min_severity="medium",
        cwe_ids=["CWE-921"],
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-003",
        title_pattern="cleartext",
        min_severity="medium",
        cwe_ids=["CWE-319"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-005",
        title_pattern="minSdk",
        min_severity="high",
        cwe_ids=["CWE-1104"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-006",
        title_pattern="exported",
        min_severity="medium",
        cwe_ids=["CWE-926"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-010",
        title_pattern="browsable",
        min_severity="low",
        cwe_ids=["CWE-939"],
    ),
]

OVAA_MOBSF_BASELINE: list[MobSFBaselineFinding] = [
    MobSFBaselineFinding(
        check_id="MANIFEST-002",
        title_pattern="backup",
        min_severity="medium",
        cwe_ids=["CWE-921"],
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-003",
        title_pattern="cleartext",
        min_severity="high",
        cwe_ids=["CWE-319"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-005",
        title_pattern="minSdk",
        min_severity="low",
        cwe_ids=["CWE-1104"],
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-006",
        title_pattern="exported",
        min_severity="medium",
        cwe_ids=["CWE-926"],
        critical=True,
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-009",
        title_pattern="StrandHogg",
        min_severity="low",
        cwe_ids=["CWE-1021"],
    ),
    MobSFBaselineFinding(
        check_id="MANIFEST-010",
        title_pattern="browsable",
        min_severity="low",
        cwe_ids=["CWE-939"],
    ),
]

# ---------------------------------------------------------------------------
# Mocked APK manifests — identical to per-app test files
# ---------------------------------------------------------------------------

DIVA_MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="jakhar.aseem.diva"
    android:versionCode="1"
    android:versionName="1.0">
  <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="24"/>
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
  <application
      android:debuggable="true"
      android:allowBackup="true"
      android:label="@string/app_name"
      android:icon="@mipmap/ic_launcher"
      android:theme="@style/AppTheme">
    <activity android:name=".MainActivity"
              android:label="@string/app_name">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".LogActivity"/>
    <activity android:name=".HardcodeActivity"/>
    <activity android:name=".InsecureDataStorage1Activity"/>
    <activity android:name=".InsecureDataStorage2Activity"/>
    <activity android:name=".InsecureDataStorage3Activity"/>
    <activity android:name=".InsecureDataStorage4Activity"/>
    <activity android:name=".SQLInjectionActivity"/>
    <activity android:name=".InputValidation2URISchemeActivity"/>
    <activity android:name=".AccessControl1Activity">
      <intent-filter>
        <action android:name="jakhar.aseem.diva.action.VIEW_CREDS"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
    </activity>
    <activity android:name=".AccessControl2Activity"/>
    <activity android:name=".AccessControl3Activity">
      <intent-filter>
        <action android:name="jakhar.aseem.diva.action.VIEW_CREDS2"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
    </activity>
    <activity android:name=".APICreds1Activity"/>
    <provider
        android:name=".NotesProvider"
        android:authorities="jakhar.aseem.diva.provider.notesprovider"
        android:exported="true"/>
  </application>
</manifest>
"""

INSECUREBANKV2_MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.android.insecurebankv2"
    android:versionCode="1"
    android:versionName="2.0">
  <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="15"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
  <application
      android:debuggable="true"
      android:allowBackup="true"
      android:label="@string/app_name"
      android:icon="@drawable/ic_launcher"
      android:theme="@style/AppTheme">
    <activity android:name=".LoginActivity"
              android:label="@string/app_name">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".PostLogin"/>
    <activity android:name=".DoTransfer"/>
    <activity android:name=".ViewStatement">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="http" android:host="mybank.com"/>
      </intent-filter>
    </activity>
    <activity android:name=".ChangePassword"/>
    <activity android:name=".DoLogin"/>
    <activity android:name=".FilePrefActivity"/>
    <activity android:name=".WebViewActivity"/>
    <service android:name=".MyBroadCastReceiver"/>
    <receiver android:name=".MyBroadCastReceiver2">
      <intent-filter>
        <action android:name="theBroadcast"/>
      </intent-filter>
    </receiver>
  </application>
</manifest>
"""

OVAA_MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.ovaa"
    android:versionCode="1"
    android:versionName="1.0">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="29"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
  <!-- Additional perms to break the INTERNET+ACCESS_NETWORK_STATE
       _SAFE_PERMISSION_GROUPS allowlist match, which would otherwise
       suppress MANIFEST-006 as "standard networking pair". Real OVAA
       requests READ/WRITE_EXTERNAL_STORAGE — include them here so the
       mock tracks the real app's permission footprint. See
       test_ovaa_manifest.py for the same pattern. -->
  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
  <application
      android:allowBackup="true"
      android:usesCleartextTraffic="true"
      android:label="@string/app_name"
      android:icon="@mipmap/ic_launcher"
      android:theme="@style/AppTheme">
    <activity android:name=".LoginActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".OversecuredActivity"
              android:exported="true"/>
    <activity android:name=".DeeplinkActivity"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="oversecured" android:host="ovaa"/>
      </intent-filter>
    </activity>
    <activity android:name=".WebViewActivity"
              android:exported="true"/>
    <activity android:name=".TheftActivity"
              android:exported="true"
              android:launchMode="singleTask"/>
    <activity android:name=".EntropyActivity"
              android:exported="true"/>
    <activity android:name=".WeakCryptoActivity"
              android:exported="true"/>
    <activity android:name=".WebResourceActivity"
              android:exported="true"/>
    <activity android:name=".InsecureSharedPrefsActivity"
              android:exported="true"/>
    <activity android:name=".RootDetectionActivity"
              android:exported="true"/>
    <activity android:name=".MemoryCorruptionActivity"
              android:exported="true"/>
    <provider
        android:name=".OversecuredProvider"
        android:authorities="oversecured.ovaa.provider"
        android:exported="true"/>
    <receiver android:name=".InsecureReceiver"
              android:exported="true"/>
  </application>
</manifest>
"""


# ---------------------------------------------------------------------------
# Helpers: mock APK builder
# ---------------------------------------------------------------------------


def _build_mock_apk(
    manifest_xml: str,
    package: str,
    *,
    min_sdk: int,
    target_sdk: int,
    debug_signed: bool = True,
) -> MagicMock:
    """Build a mock Androguard APK object from manifest XML."""
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = package
    mock_apk.get_min_sdk_version.return_value = str(min_sdk)
    mock_apk.get_target_sdk_version.return_value = str(target_sdk)
    mock_apk.get_effective_target_sdk_version.return_value = target_sdk
    mock_apk.get_max_sdk_version.return_value = None

    # Parse the XML and return elements
    root = ET.fromstring(manifest_xml)
    mock_apk.get_android_manifest_xml.return_value = root
    mock_apk.get_android_manifest_axml.return_value = MagicMock(
        get_xml=MagicMock(return_value=manifest_xml.encode())
    )

    # Application attributes from XML
    app_el = root.find("application")
    ns = _NS

    debuggable = app_el.get(f"{{{ns}}}debuggable", "false")
    mock_apk.get_attribute_value.side_effect = lambda tag, attr: {
        ("application", "debuggable"): debuggable,
        ("application", "allowBackup"): app_el.get(f"{{{ns}}}allowBackup"),
        ("application", "usesCleartextTraffic"): app_el.get(
            f"{{{ns}}}usesCleartextTraffic"
        ),
        ("application", "testOnly"): app_el.get(f"{{{ns}}}testOnly"),
        ("application", "networkSecurityConfig"): app_el.get(
            f"{{{ns}}}networkSecurityConfig"
        ),
    }.get((tag, attr))

    # Permissions
    perms = [
        el.get(f"{{{ns}}}name")
        for el in root.findall("uses-permission")
        if el.get(f"{{{ns}}}name")
    ]
    mock_apk.get_permissions.return_value = perms

    # Activities
    activities = []
    if app_el is not None:
        for act in app_el.findall("activity"):
            name = act.get(f"{{{ns}}}name", "")
            activities.append(name)
    mock_apk.get_activities.return_value = activities

    # Services
    services = []
    if app_el is not None:
        for svc in app_el.findall("service"):
            name = svc.get(f"{{{ns}}}name", "")
            services.append(name)
    mock_apk.get_services.return_value = services

    # Receivers
    receivers = []
    if app_el is not None:
        for rcv in app_el.findall("receiver"):
            name = rcv.get(f"{{{ns}}}name", "")
            receivers.append(name)
    mock_apk.get_receivers.return_value = receivers

    # Providers
    providers = []
    if app_el is not None:
        for prov in app_el.findall("provider"):
            name = prov.get(f"{{{ns}}}name", "")
            providers.append(name)
    mock_apk.get_providers.return_value = providers

    # Debug signing simulation
    if debug_signed:
        mock_apk.get_certificates_v1.return_value = [MagicMock()]
        mock_apk.get_certificates_v2.return_value = []
        cert_mock = MagicMock()
        cert_mock.issuer = MagicMock()
        cn_attr = MagicMock()
        cn_attr.value = "Android Debug"
        cert_mock.issuer.get_attributes_for_oid.return_value = [cn_attr]
        cert_mock.subject = cert_mock.issuer
        mock_apk.get_certificates_v1.return_value = [cert_mock]
    else:
        mock_apk.get_certificates_v1.return_value = [MagicMock()]
        mock_apk.get_certificates_v2.return_value = []
        cert_mock = MagicMock()
        cert_mock.issuer = MagicMock()
        cn_attr = MagicMock()
        cn_attr.value = "Some Publisher"
        cert_mock.issuer.get_attributes_for_oid.return_value = [cn_attr]
        cert_mock.subject = cert_mock.issuer
        mock_apk.get_certificates_v1.return_value = [cert_mock]

    # Shared user ID
    mock_apk.get_attribute_value.side_effect = _make_attr_side_effect(
        root, app_el, ns
    )

    return mock_apk


def _make_attr_side_effect(root: ET.Element, app_el: ET.Element, ns: str):
    """Build a side_effect function for get_attribute_value mock."""
    lookup: dict[tuple[str, str], str | None] = {
        ("application", "debuggable"): app_el.get(f"{{{ns}}}debuggable")
        if app_el is not None
        else None,
        ("application", "allowBackup"): app_el.get(f"{{{ns}}}allowBackup")
        if app_el is not None
        else None,
        ("application", "usesCleartextTraffic"): app_el.get(
            f"{{{ns}}}usesCleartextTraffic"
        )
        if app_el is not None
        else None,
        ("application", "testOnly"): app_el.get(f"{{{ns}}}testOnly")
        if app_el is not None
        else None,
        ("application", "networkSecurityConfig"): app_el.get(
            f"{{{ns}}}networkSecurityConfig"
        )
        if app_el is not None
        else None,
        ("manifest", "sharedUserId"): root.get(f"{{{ns}}}sharedUserId"),
    }

    def _side_effect(tag: str, attr: str) -> str | None:
        return lookup.get((tag, attr))

    return _side_effect


# ---------------------------------------------------------------------------
# Diff / reporting helpers
# ---------------------------------------------------------------------------


@dataclass
class ParityResult:
    """Result of comparing Wairz findings against MobSF baseline."""

    apk_name: str
    baseline: list[MobSFBaselineFinding]
    wairz_findings: list[dict[str, Any]]
    matched: list[tuple[MobSFBaselineFinding, dict[str, Any]]]
    missed: list[MobSFBaselineFinding]
    extra: list[dict[str, Any]]  # Wairz found but MobSF didn't expect

    @property
    def missed_critical_high(self) -> list[MobSFBaselineFinding]:
        """Baseline findings flagged critical or with min_severity >= high that were missed."""
        return [
            b
            for b in self.missed
            if b.critical or b.min_severity in ("high", "critical")
        ]

    @property
    def is_superset(self) -> bool:
        """True if Wairz found everything MobSF expected."""
        return len(self.missed) == 0

    @property
    def coverage_pct(self) -> float:
        if not self.baseline:
            return 100.0
        return len(self.matched) / len(self.baseline) * 100

    def format_report(self) -> str:
        """Generate a human-readable diff report."""
        lines: list[str] = []
        lines.append(f"=== Parity Report: {self.apk_name} ===")
        lines.append(
            f"Baseline: {len(self.baseline)} expected | "
            f"Wairz: {len(self.wairz_findings)} produced | "
            f"Matched: {len(self.matched)} | "
            f"Missed: {len(self.missed)} | "
            f"Extra: {len(self.extra)}"
        )
        lines.append(f"Coverage: {self.coverage_pct:.0f}%")
        lines.append("")

        if self.matched:
            lines.append("✓ MATCHED findings:")
            for baseline, wairz in self.matched:
                sev = wairz.get("severity", "?")
                lines.append(
                    f"  [{baseline.check_id}] {baseline.title_pattern} "
                    f"— baseline min={baseline.min_severity}, "
                    f"wairz={sev} {'✓' if _sev_ge(sev, baseline.min_severity) else '⚠ BELOW MIN'}"
                )
            lines.append("")

        if self.missed:
            lines.append("✗ MISSED findings (Wairz did NOT produce):")
            for b in self.missed:
                crit = " [CRITICAL/MUST-DETECT]" if b.critical else ""
                lines.append(
                    f"  [{b.check_id}] {b.title_pattern} "
                    f"(min_severity={b.min_severity}, "
                    f"CWEs={b.cwe_ids}){crit}"
                )
            lines.append("")

        if self.extra:
            lines.append("+ EXTRA findings (Wairz found, MobSF baseline lacks):")
            for f in self.extra:
                lines.append(
                    f"  [{f.get('check_id', '?')}] {f.get('title', '?')} "
                    f"severity={f.get('severity', '?')}"
                )
            lines.append("")

        if self.missed_critical_high:
            lines.append(
                f"🚨 {len(self.missed_critical_high)} CRITICAL/HIGH finding(s) MISSED!"
            )
            for b in self.missed_critical_high:
                lines.append(
                    f"  !! [{b.check_id}] {b.title_pattern} — "
                    f"min_severity={b.min_severity}, CWEs={b.cwe_ids}"
                )
        else:
            lines.append("No critical/high findings missed.")

        return "\n".join(lines)


def _run_parity_check(
    apk_name: str,
    baseline: list[MobSFBaselineFinding],
    wairz_result: dict[str, Any],
) -> ParityResult:
    """Compare Wairz scan result against MobSF baseline."""
    findings = wairz_result.get("findings", [])
    # Build lookup by check_id
    wairz_by_id: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        cid = f.get("check_id", "")
        wairz_by_id.setdefault(cid, []).append(f)

    matched: list[tuple[MobSFBaselineFinding, dict[str, Any]]] = []
    missed: list[MobSFBaselineFinding] = []
    matched_check_ids: set[str] = set()

    for b in baseline:
        candidates = wairz_by_id.get(b.check_id, [])
        if candidates:
            # Pick the one with highest severity
            best = max(candidates, key=lambda c: _SEVERITY_ORDER.get(c.get("severity", "info"), 0))
            matched.append((b, best))
            matched_check_ids.add(b.check_id)
        else:
            missed.append(b)

    # Extra = Wairz findings whose check_id isn't in the baseline
    baseline_ids = {b.check_id for b in baseline}
    extra = [f for f in findings if f.get("check_id") not in baseline_ids]

    return ParityResult(
        apk_name=apk_name,
        baseline=baseline,
        wairz_findings=findings,
        matched=matched,
        missed=missed,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def service():
    return AndroguardService()


@pytest.fixture
def diva_apk():
    return _build_mock_apk(
        DIVA_MANIFEST_XML,
        "jakhar.aseem.diva",
        min_sdk=15,
        target_sdk=24,
        debug_signed=True,
    )


@pytest.fixture
def insecurebankv2_apk():
    return _build_mock_apk(
        INSECUREBANKV2_MANIFEST_XML,
        "com.android.insecurebankv2",
        min_sdk=15,
        target_sdk=15,
        debug_signed=True,
    )


@pytest.fixture
def ovaa_apk():
    return _build_mock_apk(
        OVAA_MANIFEST_XML,
        "oversecured.ovaa",
        min_sdk=23,
        target_sdk=29,
        debug_signed=False,
    )


# ---------------------------------------------------------------------------
# Core parity tests
# ---------------------------------------------------------------------------


class TestDivaParity:
    """DIVA: Wairz must be a superset of MobSF baseline."""

    def _scan(self, service: AndroguardService, apk: MagicMock) -> dict[str, Any]:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "androguard.core.apk.APK",
                lambda path, **kw: apk,
            )
            # scan_manifest_security() calls os.path.isfile(apk_path) before
            # APK(). /fake paths don't exist, so stub isfile to True.
            mp.setattr("os.path.isfile", lambda p: True)
            return service.scan_manifest_security("/fake/diva.apk")

    def test_superset(self, service, diva_apk):
        """Wairz findings must be a superset of MobSF DIVA baseline."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)

        if not parity.is_superset:
            pytest.fail(
                f"Wairz is NOT a superset of MobSF for DIVA.\n\n"
                f"{parity.format_report()}"
            )

    def test_no_missed_critical_high(self, service, diva_apk):
        """No critical/high MobSF findings may be missed."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)

        if parity.missed_critical_high:
            details = "\n".join(
                f"  - [{b.check_id}] {b.title_pattern} "
                f"(severity>={b.min_severity}, CWEs={b.cwe_ids})"
                for b in parity.missed_critical_high
            )
            pytest.fail(
                f"DIVA: {len(parity.missed_critical_high)} critical/high "
                f"finding(s) missed:\n{details}\n\n"
                f"Full report:\n{parity.format_report()}"
            )

    def test_severity_meets_minimum(self, service, diva_apk):
        """Each matched finding must meet the MobSF minimum severity."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)

        violations = []
        for baseline, wairz in parity.matched:
            actual_sev = wairz.get("severity", "info")
            if not _sev_ge(actual_sev, baseline.min_severity):
                violations.append(
                    f"  [{baseline.check_id}] {baseline.title_pattern}: "
                    f"expected >={baseline.min_severity}, got {actual_sev}"
                )

        if violations:
            pytest.fail(
                "DIVA severity violations:\n"
                + "\n".join(violations)
                + f"\n\n{parity.format_report()}"
            )

    def test_cwe_coverage(self, service, diva_apk):
        """Each matched finding must include the expected CWE IDs."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)

        violations = []
        for baseline, wairz in parity.matched:
            wairz_cwes = set(wairz.get("cwe_ids", []))
            for expected_cwe in baseline.cwe_ids:
                if expected_cwe not in wairz_cwes:
                    violations.append(
                        f"  [{baseline.check_id}] missing {expected_cwe} "
                        f"(has: {wairz_cwes})"
                    )

        if violations:
            pytest.fail(
                "DIVA CWE coverage gaps:\n" + "\n".join(violations)
            )

    def test_coverage_at_least_100_pct(self, service, diva_apk):
        """Coverage must be 100% (all baseline findings matched)."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)
        assert parity.coverage_pct == 100.0, (
            f"DIVA coverage={parity.coverage_pct:.0f}%, expected 100%\n"
            f"{parity.format_report()}"
        )

    def test_false_positive_rate(self, service, diva_apk):
        """Extra findings (beyond MobSF baseline) must not exceed 20%."""
        result = self._scan(service, diva_apk)
        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)
        total = len(parity.wairz_findings)
        extra = len(parity.extra)
        if total > 0:
            fp_rate = extra / total
            assert fp_rate < 0.20, (
                f"DIVA false positive rate = {fp_rate:.0%} "
                f"({extra} extra / {total} total)\n"
                f"{parity.format_report()}"
            )


class TestInsecureBankv2Parity:
    """InsecureBankv2: Wairz must be a superset of MobSF baseline."""

    def _scan(self, service: AndroguardService, apk: MagicMock) -> dict[str, Any]:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "androguard.core.apk.APK",
                lambda path, **kw: apk,
            )
            mp.setattr("os.path.isfile", lambda p: True)
            return service.scan_manifest_security("/fake/insecurebankv2.apk")

    def test_superset(self, service, insecurebankv2_apk):
        """Wairz findings must be a superset of MobSF InsecureBankv2 baseline."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )

        if not parity.is_superset:
            pytest.fail(
                f"Wairz is NOT a superset of MobSF for InsecureBankv2.\n\n"
                f"{parity.format_report()}"
            )

    def test_no_missed_critical_high(self, service, insecurebankv2_apk):
        """No critical/high MobSF findings may be missed."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )

        if parity.missed_critical_high:
            details = "\n".join(
                f"  - [{b.check_id}] {b.title_pattern} "
                f"(severity>={b.min_severity}, CWEs={b.cwe_ids})"
                for b in parity.missed_critical_high
            )
            pytest.fail(
                f"InsecureBankv2: {len(parity.missed_critical_high)} critical/high "
                f"finding(s) missed:\n{details}\n\n"
                f"Full report:\n{parity.format_report()}"
            )

    def test_severity_meets_minimum(self, service, insecurebankv2_apk):
        """Each matched finding must meet the MobSF minimum severity."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )

        violations = []
        for baseline, wairz in parity.matched:
            actual_sev = wairz.get("severity", "info")
            if not _sev_ge(actual_sev, baseline.min_severity):
                violations.append(
                    f"  [{baseline.check_id}] {baseline.title_pattern}: "
                    f"expected >={baseline.min_severity}, got {actual_sev}"
                )

        if violations:
            pytest.fail(
                "InsecureBankv2 severity violations:\n"
                + "\n".join(violations)
                + f"\n\n{parity.format_report()}"
            )

    def test_cwe_coverage(self, service, insecurebankv2_apk):
        """Each matched finding must include the expected CWE IDs."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )

        violations = []
        for baseline, wairz in parity.matched:
            wairz_cwes = set(wairz.get("cwe_ids", []))
            for expected_cwe in baseline.cwe_ids:
                if expected_cwe not in wairz_cwes:
                    violations.append(
                        f"  [{baseline.check_id}] missing {expected_cwe} "
                        f"(has: {wairz_cwes})"
                    )

        if violations:
            pytest.fail(
                "InsecureBankv2 CWE coverage gaps:\n" + "\n".join(violations)
            )

    def test_coverage_at_least_100_pct(self, service, insecurebankv2_apk):
        """Coverage must be 100%."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )
        assert parity.coverage_pct == 100.0, (
            f"InsecureBankv2 coverage={parity.coverage_pct:.0f}%\n"
            f"{parity.format_report()}"
        )

    def test_false_positive_rate(self, service, insecurebankv2_apk):
        """Extra findings must not exceed 20%."""
        result = self._scan(service, insecurebankv2_apk)
        parity = _run_parity_check(
            "InsecureBankv2", INSECUREBANKV2_MOBSF_BASELINE, result
        )
        total = len(parity.wairz_findings)
        extra = len(parity.extra)
        if total > 0:
            fp_rate = extra / total
            assert fp_rate < 0.20, (
                f"InsecureBankv2 false positive rate = {fp_rate:.0%} "
                f"({extra} extra / {total} total)\n"
                f"{parity.format_report()}"
            )


class TestOVAAParity:
    """OVAA: Wairz must be a superset of MobSF baseline."""

    def _scan(self, service: AndroguardService, apk: MagicMock) -> dict[str, Any]:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "androguard.core.apk.APK",
                lambda path, **kw: apk,
            )
            mp.setattr("os.path.isfile", lambda p: True)
            return service.scan_manifest_security("/fake/ovaa.apk")

    def test_superset(self, service, ovaa_apk):
        """Wairz findings must be a superset of MobSF OVAA baseline."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)

        if not parity.is_superset:
            pytest.fail(
                f"Wairz is NOT a superset of MobSF for OVAA.\n\n"
                f"{parity.format_report()}"
            )

    def test_no_missed_critical_high(self, service, ovaa_apk):
        """No critical/high MobSF findings may be missed."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)

        if parity.missed_critical_high:
            details = "\n".join(
                f"  - [{b.check_id}] {b.title_pattern} "
                f"(severity>={b.min_severity}, CWEs={b.cwe_ids})"
                for b in parity.missed_critical_high
            )
            pytest.fail(
                f"OVAA: {len(parity.missed_critical_high)} critical/high "
                f"finding(s) missed:\n{details}\n\n"
                f"Full report:\n{parity.format_report()}"
            )

    def test_severity_meets_minimum(self, service, ovaa_apk):
        """Each matched finding must meet the MobSF minimum severity."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)

        violations = []
        for baseline, wairz in parity.matched:
            actual_sev = wairz.get("severity", "info")
            if not _sev_ge(actual_sev, baseline.min_severity):
                violations.append(
                    f"  [{baseline.check_id}] {baseline.title_pattern}: "
                    f"expected >={baseline.min_severity}, got {actual_sev}"
                )

        if violations:
            pytest.fail(
                "OVAA severity violations:\n"
                + "\n".join(violations)
                + f"\n\n{parity.format_report()}"
            )

    def test_cwe_coverage(self, service, ovaa_apk):
        """Each matched finding must include the expected CWE IDs."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)

        violations = []
        for baseline, wairz in parity.matched:
            wairz_cwes = set(wairz.get("cwe_ids", []))
            for expected_cwe in baseline.cwe_ids:
                if expected_cwe not in wairz_cwes:
                    violations.append(
                        f"  [{baseline.check_id}] missing {expected_cwe} "
                        f"(has: {wairz_cwes})"
                    )

        if violations:
            pytest.fail(
                "OVAA CWE coverage gaps:\n" + "\n".join(violations)
            )

    def test_coverage_at_least_100_pct(self, service, ovaa_apk):
        """Coverage must be 100%."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)
        assert parity.coverage_pct == 100.0, (
            f"OVAA coverage={parity.coverage_pct:.0f}%\n"
            f"{parity.format_report()}"
        )

    def test_false_positive_rate(self, service, ovaa_apk):
        """Extra findings must not exceed 20%."""
        result = self._scan(service, ovaa_apk)
        parity = _run_parity_check("OVAA", OVAA_MOBSF_BASELINE, result)
        total = len(parity.wairz_findings)
        extra = len(parity.extra)
        if total > 0:
            fp_rate = extra / total
            assert fp_rate < 0.20, (
                f"OVAA false positive rate = {fp_rate:.0%} "
                f"({extra} extra / {total} total)\n"
                f"{parity.format_report()}"
            )

    def test_no_false_debuggable(self, service, ovaa_apk):
        """OVAA is NOT debuggable — scanner must NOT produce MANIFEST-001."""
        result = self._scan(service, ovaa_apk)
        check_ids = {f.get("check_id") for f in result.get("findings", [])}
        assert "MANIFEST-001" not in check_ids, (
            "OVAA: False positive — MANIFEST-001 (debuggable) produced "
            "but OVAA is NOT debuggable"
        )


# ---------------------------------------------------------------------------
# Firmware context parity: priv-app severity bumping
# ---------------------------------------------------------------------------


class TestFirmwareContextParity:
    """Severity adjustments for firmware-embedded APKs must preserve superset property."""

    def _scan_with_context(
        self,
        service: AndroguardService,
        apk: MagicMock,
        *,
        is_priv_app: bool = False,
        is_platform_signed: bool = False,
    ) -> dict[str, Any]:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "androguard.core.apk.APK",
                lambda path, **kw: apk,
            )
            mp.setattr("os.path.isfile", lambda p: True)
            return service.scan_manifest_security(
                "/fake/app.apk",
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            )

    def test_priv_app_still_superset_diva(self, service, diva_apk):
        """priv-app bump must not drop any findings — still a superset of baseline."""
        result = self._scan_with_context(
            service, diva_apk, is_priv_app=True
        )
        parity = _run_parity_check("DIVA (priv-app)", DIVA_MOBSF_BASELINE, result)
        assert parity.is_superset, (
            f"priv-app DIVA lost baseline findings:\n{parity.format_report()}"
        )

    def test_priv_app_severity_bumped(self, service, diva_apk):
        """priv-app findings should have higher severity than standalone."""
        standalone = self._scan_with_context(service, diva_apk)
        privapp = self._scan_with_context(
            service, diva_apk, is_priv_app=True
        )

        standalone_sevs = {
            f["check_id"]: f["severity"]
            for f in standalone.get("findings", [])
        }
        privapp_sevs = {
            f["check_id"]: f["severity"]
            for f in privapp.get("findings", [])
        }

        bumped = 0
        for cid, priv_sev in privapp_sevs.items():
            base_sev = standalone_sevs.get(cid)
            if base_sev and _SEVERITY_ORDER.get(priv_sev, 0) > _SEVERITY_ORDER.get(
                base_sev, 0
            ):
                bumped += 1

        assert bumped > 0, (
            "priv-app context should bump at least one finding's severity"
        )

    def test_platform_signed_still_superset_ovaa(self, service, ovaa_apk):
        """Platform-signed OVAA must still be a superset of MobSF baseline."""
        result = self._scan_with_context(
            service, ovaa_apk, is_platform_signed=True
        )
        parity = _run_parity_check(
            "OVAA (platform-signed)", OVAA_MOBSF_BASELINE, result
        )
        assert parity.is_superset, (
            f"platform-signed OVAA lost baseline findings:\n"
            f"{parity.format_report()}"
        )

    @pytest.mark.skip(
        reason=(
            "OVAA mock lacks signatureOrSystem signals required by Rule #13 "
            "heuristic — no declared signature permissions, no requested "
            "platform-only permissions, no system shared UID. Product "
            "correctly does NOT apply severity reduction for this APK "
            "even when is_platform_signed=True. A proper regression test "
            "would need a distinct 'platform_app' mock with those signals; "
            "see test_manifest_checks_signing.py for the coverage that "
            "already exists at the unit level."
        )
    )
    def test_platform_signed_severity_reduction(self, service, ovaa_apk):
        """Platform-signed findings on eligible checks should be reduced."""
        result = self._scan_with_context(
            service, ovaa_apk, is_platform_signed=True
        )
        assert result.get("severity_reduced") or result.get(
            "reduced_check_ids"
        ), "Platform-signed scan should indicate severity reduction applied"


# ---------------------------------------------------------------------------
# Cross-APK aggregate parity
# ---------------------------------------------------------------------------


class TestCrossAPKParity:
    """Aggregate parity across all three test APKs."""

    def _scan_all(
        self, service, diva_apk, insecurebankv2_apk, ovaa_apk
    ) -> list[ParityResult]:
        results = []
        apks = [
            ("DIVA", diva_apk, DIVA_MOBSF_BASELINE),
            ("InsecureBankv2", insecurebankv2_apk, INSECUREBANKV2_MOBSF_BASELINE),
            ("OVAA", ovaa_apk, OVAA_MOBSF_BASELINE),
        ]
        for name, apk, baseline in apks:
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(
                    "androguard.core.apk.APK",
                    lambda path, a=apk, **kw: a,
                )
                mp.setattr("os.path.isfile", lambda p: True)
                result = service.scan_manifest_security(f"/fake/{name}.apk")
            results.append(_run_parity_check(name, baseline, result))
        return results

    def test_all_superset(self, service, diva_apk, insecurebankv2_apk, ovaa_apk):
        """All three APKs must have Wairz as a superset of MobSF."""
        results = self._scan_all(service, diva_apk, insecurebankv2_apk, ovaa_apk)
        failures = [r for r in results if not r.is_superset]
        if failures:
            reports = "\n\n".join(r.format_report() for r in failures)
            pytest.fail(
                f"{len(failures)}/3 APKs failed superset check:\n\n{reports}"
            )

    def test_zero_missed_critical_high_across_all(
        self, service, diva_apk, insecurebankv2_apk, ovaa_apk
    ):
        """Zero critical/high findings may be missed across all APKs combined."""
        results = self._scan_all(service, diva_apk, insecurebankv2_apk, ovaa_apk)
        all_missed = []
        for r in results:
            for b in r.missed_critical_high:
                all_missed.append(f"  [{r.apk_name}] {b.check_id}: {b.title_pattern}")

        if all_missed:
            reports = "\n\n".join(r.format_report() for r in results)
            pytest.fail(
                f"{len(all_missed)} critical/high finding(s) missed across APKs:\n"
                + "\n".join(all_missed)
                + f"\n\nFull reports:\n{reports}"
            )

    def test_aggregate_coverage_above_threshold(
        self, service, diva_apk, insecurebankv2_apk, ovaa_apk
    ):
        """Aggregate MobSF baseline coverage must be >= 100%."""
        results = self._scan_all(service, diva_apk, insecurebankv2_apk, ovaa_apk)
        total_baseline = sum(len(r.baseline) for r in results)
        total_matched = sum(len(r.matched) for r in results)
        agg_coverage = (total_matched / total_baseline * 100) if total_baseline else 100
        per_apk = ", ".join(
            f"{r.apk_name}={r.coverage_pct:.0f}%" for r in results
        )
        assert agg_coverage == 100.0, (
            f"Aggregate coverage={agg_coverage:.0f}% (per-APK: {per_apk})"
        )

    def test_aggregate_false_positive_rate(
        self, service, diva_apk, insecurebankv2_apk, ovaa_apk
    ):
        """Combined false positive rate across all APKs must be under 20%."""
        results = self._scan_all(service, diva_apk, insecurebankv2_apk, ovaa_apk)
        total_findings = sum(len(r.wairz_findings) for r in results)
        total_extra = sum(len(r.extra) for r in results)
        if total_findings > 0:
            fp_rate = total_extra / total_findings
            assert fp_rate < 0.20, (
                f"Aggregate FP rate = {fp_rate:.0%} "
                f"({total_extra}/{total_findings})"
            )


# ---------------------------------------------------------------------------
# Detailed diff reporting (standalone helper tests)
# ---------------------------------------------------------------------------


class TestParityReportFormat:
    """Verify the diff report formatting is correct and informative."""

    def test_report_contains_sections(self, service, diva_apk):
        """Report should include matched, missed, extra sections."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "androguard.core.apk.APK",
                lambda path, **kw: diva_apk,
            )
            mp.setattr("os.path.isfile", lambda p: True)
            result = service.scan_manifest_security("/fake/diva.apk")

        parity = _run_parity_check("DIVA", DIVA_MOBSF_BASELINE, result)
        report = parity.format_report()

        assert "Parity Report: DIVA" in report
        assert "Coverage:" in report
        assert "Baseline:" in report
        # If all matched, the MATCHED section must be present
        if parity.matched:
            assert "MATCHED" in report

    def test_missed_report_shows_cwe(self):
        """When findings are missed, report shows CWE details."""
        # Construct a synthetic parity result with a missed finding
        missed = MobSFBaselineFinding(
            check_id="MANIFEST-001",
            title_pattern="debuggable",
            min_severity="high",
            cwe_ids=["CWE-489"],
            critical=True,
        )
        parity = ParityResult(
            apk_name="SyntheticAPK",
            baseline=[missed],
            wairz_findings=[],
            matched=[],
            missed=[missed],
            extra=[],
        )
        report = parity.format_report()
        assert "MISSED" in report
        assert "CWE-489" in report
        assert "CRITICAL/HIGH" in report or "MUST-DETECT" in report
        assert parity.coverage_pct == 0.0

    def test_extra_findings_labeled(self):
        """Extra findings (Wairz-only) should appear in report."""
        extra_finding = {
            "check_id": "MANIFEST-099",
            "title": "Some extra check",
            "severity": "low",
        }
        parity = ParityResult(
            apk_name="SyntheticAPK",
            baseline=[],
            wairz_findings=[extra_finding],
            matched=[],
            missed=[],
            extra=[extra_finding],
        )
        report = parity.format_report()
        assert "EXTRA" in report
        assert "MANIFEST-099" in report
