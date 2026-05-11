"""MobSF API runner — invokes MobSF server REST API for APK analysis.

This module provides a client for the Mobile Security Framework (MobSF)
REST API that:

1. Uploads an APK to MobSF for static analysis
2. Retrieves the full scan report
3. Extracts manifest-related security findings
4. Normalizes them into a structured JSON schema compatible with the
   Wairz ManifestFinding format

This is a **validation/benchmarking** tool, not the primary scanning
engine.  It enables comparison of Wairz's built-in Androguard manifest
checks (see :mod:`app.services.androguard_service`) against MobSF's
baseline findings to measure coverage, accuracy, and false-positive
rates.

Usage::

    runner = MobsfRunner(api_url="http://localhost:8000", api_key="...")
    result = await runner.scan_apk("/path/to/app.apk")

    # Access normalized manifest findings
    for f in result.manifest_findings:
        print(f"{f.check_id}: {f.title} [{f.severity}]")

    # Raw MobSF report for full-spectrum analysis
    raw = result.raw_report

All methods are async.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.utils.hashing import compute_file_sha256

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Normalized manifest finding schema
# ---------------------------------------------------------------------------

# MobSF severity strings → Wairz severity
_SEVERITY_MAP: dict[str, str] = {
    "high": "high",
    "warning": "medium",
    "info": "info",
    "secure": "info",
    "hotspot": "low",
    "suppressed": "info",
}

# Canonical mapping: MobSF manifest check key → Wairz check metadata.
# Each entry contains the Wairz check_id, default CWE(s), and severity
# that MobSF would produce.  This table drives the normalization from
# MobSF's free-form JSON into structured ManifestFinding objects.
_MANIFEST_CHECK_MAP: dict[str, dict[str, Any]] = {
    # --- Core app attributes ---
    "is_debuggable": {
        "check_id": "MANIFEST-001",
        "title": "Application is debuggable",
        "cwe_ids": ["CWE-489"],
        "default_severity": "high",
    },
    "is_allow_backup": {
        "check_id": "MANIFEST-002",
        "title": "Application allows backup",
        "cwe_ids": ["CWE-921"],
        "default_severity": "medium",
    },
    "is_clear_text_traffic": {
        "check_id": "MANIFEST-003",
        "title": "Cleartext traffic allowed",
        "cwe_ids": ["CWE-319"],
        "default_severity": "high",
    },
    "is_test_only": {
        "check_id": "MANIFEST-004",
        "title": "Application is test-only",
        "cwe_ids": [],
        "default_severity": "medium",
    },
    # --- SDK version ---
    "min_sdk": {
        "check_id": "MANIFEST-005",
        "title": "Outdated minimum SDK version",
        "cwe_ids": ["CWE-1104"],
        "default_severity": "high",
    },
    "target_sdk": {
        "check_id": "MANIFEST-005",
        "title": "Outdated target SDK version",
        "cwe_ids": ["CWE-1104"],
        "default_severity": "medium",
    },
    # --- Exported components ---
    "exported_activity": {
        "check_id": "MANIFEST-006",
        "title": "Exported Activity without permission protection",
        "cwe_ids": ["CWE-926"],
        "default_severity": "high",
    },
    "exported_service": {
        "check_id": "MANIFEST-006",
        "title": "Exported Service without permission protection",
        "cwe_ids": ["CWE-926"],
        "default_severity": "high",
    },
    "exported_receiver": {
        "check_id": "MANIFEST-006",
        "title": "Exported Receiver without permission protection",
        "cwe_ids": ["CWE-926"],
        "default_severity": "medium",
    },
    "exported_provider": {
        "check_id": "MANIFEST-006",
        "title": "Exported Content Provider without permission protection",
        "cwe_ids": ["CWE-926"],
        "default_severity": "high",
    },
    "browsable_activity": {
        "check_id": "MANIFEST-006",
        "title": "Browsable Activity (deep link handler)",
        "cwe_ids": ["CWE-939"],
        "default_severity": "medium",
    },
    # --- Custom permissions ---
    "custom_permission": {
        "check_id": "MANIFEST-007",
        "title": "Custom permission with weak protection level",
        "cwe_ids": ["CWE-250"],
        "default_severity": "medium",
    },
    # --- Task hijacking ---
    "task_affinity": {
        "check_id": "MANIFEST-008",
        "title": "StrandHogg v1: Task affinity hijacking",
        "cwe_ids": ["CWE-1021"],
        "default_severity": "medium",
    },
    "launch_mode": {
        "check_id": "MANIFEST-009",
        "title": "StrandHogg v2: Exported singleTask/singleInstance",
        "cwe_ids": ["CWE-1021"],
        "default_severity": "medium",
    },
    # --- App links ---
    "app_link_verification": {
        "check_id": "MANIFEST-010",
        "title": "App link without autoVerify",
        "cwe_ids": ["CWE-939"],
        "default_severity": "medium",
    },
    # --- Network security ---
    "network_security_config": {
        "check_id": "MANIFEST-011",
        "title": "Missing or weak network security configuration",
        "cwe_ids": ["CWE-295"],
        "default_severity": "high",
    },
    "certificate_pinning": {
        "check_id": "MANIFEST-011",
        "title": "Missing certificate pinning",
        "cwe_ids": ["CWE-295"],
        "default_severity": "medium",
    },
}


@dataclass(frozen=True, slots=True)
class NormalizedManifestFinding:
    """A single MobSF manifest finding normalized to the Wairz schema.

    Fields align with :class:`~app.services.androguard_service.ManifestFinding`
    for direct comparison.
    """

    check_id: str
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str
    cwe_ids: list[str]
    confidence: str  # "high", "medium", "low"
    mobsf_key: str  # original MobSF finding key for traceability
    mobsf_severity: str  # original MobSF severity string

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict matching ManifestFinding.to_dict() output."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "cwe_ids": self.cwe_ids,
            "confidence": self.confidence,
            "mobsf_key": self.mobsf_key,
            "mobsf_severity": self.mobsf_severity,
        }


@dataclass(slots=True)
class MobsfScanResult:
    """Result of a MobSF API scan with normalized manifest findings."""

    success: bool
    package_name: str = ""
    manifest_findings: list[NormalizedManifestFinding] = field(default_factory=list)
    raw_report: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    scan_duration_ms: int = 0
    apk_hash: str = ""

    @property
    def summary(self) -> dict[str, Any]:
        """Compact summary suitable for logging or MCP output."""
        severity_counts: dict[str, int] = {}
        for f in self.manifest_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        check_ids = sorted({f.check_id for f in self.manifest_findings})
        return {
            "success": self.success,
            "package_name": self.package_name,
            "total_findings": len(self.manifest_findings),
            "by_severity": severity_counts,
            "check_ids": check_ids,
            "scan_duration_ms": self.scan_duration_ms,
            "apk_hash": self.apk_hash,
            "error": self.error,
        }

    def to_dict(self) -> dict[str, Any]:
        """Full serialization for JSON output."""
        return {
            "success": self.success,
            "package_name": self.package_name,
            "apk_hash": self.apk_hash,
            "scan_duration_ms": self.scan_duration_ms,
            "summary": self.summary,
            "manifest_findings": [f.to_dict() for f in self.manifest_findings],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# MobSF API Client
# ---------------------------------------------------------------------------


class MobsfRunner:
    """Async client for MobSF REST API with manifest finding normalization.

    Parameters
    ----------
    api_url:
        Base URL of the MobSF server (e.g. ``http://localhost:8000``).
    api_key:
        MobSF REST API key (shown on the MobSF dashboard).
    timeout:
        Maximum seconds for the full upload+scan cycle.  Default 300.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout: int = 300,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def scan_apk(self, apk_path: str) -> MobsfScanResult:
        """Upload an APK to MobSF, trigger a scan, and return normalized results.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file on disk.

        Returns
        -------
        MobsfScanResult
            Scan result with manifest findings normalized to Wairz schema.
        """
        import aiohttp

        p = Path(apk_path)
        if not p.is_file():  # noqa: ASYNC240 — single Path.is_file() guard at scan entry; bounded to one stat
            return MobsfScanResult(
                success=False,
                error=f"APK file not found: {apk_path}",
            )

        loop = asyncio.get_running_loop()
        apk_hash = await loop.run_in_executor(None, compute_file_sha256, str(p))
        t0 = time.monotonic()

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as session:
                # Step 1: Upload the APK
                upload_resp = await self._upload(session, p)
                if not upload_resp.get("hash"):
                    return MobsfScanResult(
                        success=False,
                        error=f"MobSF upload failed: {json.dumps(upload_resp)[:500]}",
                        apk_hash=apk_hash,
                        scan_duration_ms=_elapsed_ms(t0),
                    )

                mobsf_hash = upload_resp["hash"]
                file_name = upload_resp.get("file_name", p.name)

                # Step 2: Trigger static analysis scan
                scan_resp = await self._scan(session, mobsf_hash, file_name)
                if not scan_resp:
                    return MobsfScanResult(
                        success=False,
                        error="MobSF scan returned empty response",
                        apk_hash=apk_hash,
                        scan_duration_ms=_elapsed_ms(t0),
                    )

                # Step 3: Retrieve the JSON report
                report = await self._report(session, mobsf_hash)
                if not report:
                    return MobsfScanResult(
                        success=False,
                        error="MobSF report retrieval failed",
                        apk_hash=apk_hash,
                        scan_duration_ms=_elapsed_ms(t0),
                    )

                # Step 4: Extract and normalize manifest findings
                pkg = report.get("package_name", "")
                findings = _extract_manifest_findings(report)

                return MobsfScanResult(
                    success=True,
                    package_name=pkg,
                    manifest_findings=findings,
                    raw_report=report,
                    apk_hash=apk_hash,
                    scan_duration_ms=_elapsed_ms(t0),
                )

        except Exception as exc:
            logger.exception("MobSF scan failed for %s", apk_path)
            return MobsfScanResult(
                success=False,
                error=f"MobSF API error: {exc}",
                apk_hash=apk_hash,
                scan_duration_ms=_elapsed_ms(t0),
            )

    async def scan_apk_from_report(
        self,
        report_json: dict[str, Any],
        *,
        apk_hash: str = "",
    ) -> MobsfScanResult:
        """Normalize an existing MobSF report without re-scanning.

        Useful for offline comparison when a pre-exported MobSF JSON
        report is available (e.g., saved from ``/api/v1/report_json``).

        Parameters
        ----------
        report_json:
            A full MobSF static analysis JSON report.
        apk_hash:
            Optional SHA256 hash of the APK for tracking.

        Returns
        -------
        MobsfScanResult
            Scan result with normalized manifest findings.
        """
        pkg = report_json.get("package_name", "")
        findings = _extract_manifest_findings(report_json)
        return MobsfScanResult(
            success=True,
            package_name=pkg,
            manifest_findings=findings,
            raw_report=report_json,
            apk_hash=apk_hash,
        )

    # -----------------------------------------------------------------------
    # Internal API methods
    # -----------------------------------------------------------------------

    async def _upload(
        self,
        session: Any,  # aiohttp.ClientSession
        apk_path: Path,
    ) -> dict[str, Any]:
        """Upload APK to MobSF ``/api/v1/upload``."""
        import aiohttp

        url = f"{self.api_url}/api/v1/upload"
        headers = {"Authorization": self.api_key}

        data = aiohttp.FormData()
        data.add_field(
            "file",
            apk_path.open("rb"),
            filename=apk_path.name,
            content_type="application/vnd.android.package-archive",
        )

        logger.info("Uploading %s to MobSF %s", apk_path.name, url)
        async with session.post(url, headers=headers, data=data) as resp:
            if resp.status != 200:
                body = await resp.text()
                logger.error("MobSF upload failed [%d]: %s", resp.status, body[:500])
                return {"error": body[:500]}
            return await resp.json()

    async def _scan(
        self,
        session: Any,  # aiohttp.ClientSession
        file_hash: str,
        file_name: str,
    ) -> dict[str, Any]:
        """Trigger static scan via ``/api/v1/scan``."""
        url = f"{self.api_url}/api/v1/scan"
        headers = {"Authorization": self.api_key}
        data = {
            "hash": file_hash,
            "file_name": file_name,
            "scan_type": "apk",
            "re_scan": "0",
        }

        logger.info("Triggering MobSF scan for %s", file_name)
        async with session.post(url, headers=headers, data=data) as resp:
            if resp.status != 200:
                body = await resp.text()
                logger.error("MobSF scan failed [%d]: %s", resp.status, body[:500])
                return {}
            return await resp.json()

    async def _report(
        self,
        session: Any,  # aiohttp.ClientSession
        file_hash: str,
    ) -> dict[str, Any]:
        """Retrieve JSON report via ``/api/v1/report_json``."""
        url = f"{self.api_url}/api/v1/report_json"
        headers = {"Authorization": self.api_key}
        data = {"hash": file_hash}

        logger.info("Retrieving MobSF report for %s", file_hash)
        async with session.post(url, headers=headers, data=data) as resp:
            if resp.status != 200:
                body = await resp.text()
                logger.error("MobSF report failed [%d]: %s", resp.status, body[:500])
                return {}
            return await resp.json()


# ---------------------------------------------------------------------------
# Manifest finding extraction & normalization
# ---------------------------------------------------------------------------


def _extract_manifest_findings(
    report: dict[str, Any],
) -> list[NormalizedManifestFinding]:
    """Extract and normalize manifest security findings from a MobSF report.

    MobSF's static analysis JSON report contains manifest findings in
    several locations:

    1. ``manifest_analysis`` — list of dicts with ``rule``, ``title``,
       ``severity``, ``description``
    2. ``exported_activities`` / ``exported_services`` / etc. — component
       lists with export and permission details
    3. ``network_security`` — network security config analysis
    4. ``certificate_analysis`` — signing certificate findings
    5. Top-level fields: ``is_debuggable``, ``is_allow_backup``, etc.

    We parse all of these and normalize into a unified schema.
    """
    findings: list[NormalizedManifestFinding] = []

    # ----- 1. Top-level boolean/attribute checks -----
    findings.extend(_extract_app_attribute_findings(report))

    # ----- 2. manifest_analysis section -----
    findings.extend(_extract_manifest_analysis_findings(report))

    # ----- 3. Exported components -----
    findings.extend(_extract_exported_component_findings(report))

    # ----- 4. Network security configuration -----
    findings.extend(_extract_network_security_findings(report))

    # Deduplicate by check_id + title (keep first occurrence)
    seen: set[str] = set()
    deduped: list[NormalizedManifestFinding] = []
    for f in findings:
        key = f"{f.check_id}|{f.title}|{f.evidence[:100]}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def _extract_app_attribute_findings(
    report: dict[str, Any],
) -> list[NormalizedManifestFinding]:
    """Extract findings from MobSF top-level app attributes."""
    findings: list[NormalizedManifestFinding] = []

    # Debuggable
    if report.get("is_debuggable"):
        meta = _MANIFEST_CHECK_MAP["is_debuggable"]
        findings.append(
            NormalizedManifestFinding(
                check_id=meta["check_id"],
                title=meta["title"],
                severity=meta["default_severity"],
                description=(
                    "The application has android:debuggable=true set in the "
                    "manifest. This allows attackers to attach a debugger, "
                    "inspect memory, and bypass security controls."
                ),
                evidence="android:debuggable=\"true\"",
                cwe_ids=meta["cwe_ids"],
                confidence="high",
                mobsf_key="is_debuggable",
                mobsf_severity="high",
            )
        )

    # Allow backup
    if report.get("is_allow_backup"):
        meta = _MANIFEST_CHECK_MAP["is_allow_backup"]
        findings.append(
            NormalizedManifestFinding(
                check_id=meta["check_id"],
                title=meta["title"],
                severity=meta["default_severity"],
                description=(
                    "The application has android:allowBackup=true (or defaults "
                    "to true). Application data can be extracted via adb backup "
                    "without requiring root."
                ),
                evidence="android:allowBackup=\"true\"",
                cwe_ids=meta["cwe_ids"],
                confidence="high",
                mobsf_key="is_allow_backup",
                mobsf_severity="warning",
            )
        )

    # Cleartext traffic
    cleartext = report.get("is_clear_text_traffic")
    if cleartext is True or cleartext == "true":
        meta = _MANIFEST_CHECK_MAP["is_clear_text_traffic"]
        findings.append(
            NormalizedManifestFinding(
                check_id=meta["check_id"],
                title=meta["title"],
                severity=meta["default_severity"],
                description=(
                    "The application allows cleartext (HTTP) network traffic. "
                    "All network communications could be intercepted by MITM "
                    "attackers."
                ),
                evidence="android:usesCleartextTraffic=\"true\"",
                cwe_ids=meta["cwe_ids"],
                confidence="high",
                mobsf_key="is_clear_text_traffic",
                mobsf_severity="high",
            )
        )

    # Test only
    if report.get("is_test_only"):
        meta = _MANIFEST_CHECK_MAP["is_test_only"]
        findings.append(
            NormalizedManifestFinding(
                check_id=meta["check_id"],
                title=meta["title"],
                severity=meta["default_severity"],
                description=(
                    "The application has android:testOnly=true. This flag is "
                    "meant for development and should never ship to production."
                ),
                evidence="android:testOnly=\"true\"",
                cwe_ids=meta["cwe_ids"],
                confidence="high",
                mobsf_key="is_test_only",
                mobsf_severity="high",
            )
        )

    # Min SDK version
    min_sdk = report.get("min_sdk")
    if min_sdk is not None:
        try:
            sdk_int = int(min_sdk)
        except (ValueError, TypeError):
            sdk_int = None
        if sdk_int is not None and sdk_int < 24:
            meta = _MANIFEST_CHECK_MAP["min_sdk"]
            severity = "high" if sdk_int < 19 else "medium"
            findings.append(
                NormalizedManifestFinding(
                    check_id=meta["check_id"],
                    title=f"Minimum SDK version is {sdk_int} (API level < 24)",
                    severity=severity,
                    description=(
                        f"The application targets a minimum SDK of {sdk_int}. "
                        f"Android API levels below 24 (Nougat) lack important "
                        f"security features like network security config defaults "
                        f"and full-disk encryption."
                    ),
                    evidence=f"android:minSdkVersion=\"{sdk_int}\"",
                    cwe_ids=meta["cwe_ids"],
                    confidence="high",
                    mobsf_key="min_sdk",
                    mobsf_severity="warning" if sdk_int >= 19 else "high",
                )
            )

    # Target SDK version
    target_sdk = report.get("target_sdk")
    if target_sdk is not None:
        try:
            target_int = int(target_sdk)
        except (ValueError, TypeError):
            target_int = None
        if target_int is not None and target_int < 28:
            meta = _MANIFEST_CHECK_MAP["target_sdk"]
            findings.append(
                NormalizedManifestFinding(
                    check_id=meta["check_id"],
                    title=f"Target SDK version is {target_int} (API level < 28)",
                    severity=meta["default_severity"],
                    description=(
                        f"The application targets SDK {target_int}. Target SDK "
                        f"below 28 (Android 9) means the app doesn't benefit "
                        f"from cleartext-traffic-off-by-default and other "
                        f"security defaults."
                    ),
                    evidence=f"android:targetSdkVersion=\"{target_int}\"",
                    cwe_ids=meta["cwe_ids"],
                    confidence="high",
                    mobsf_key="target_sdk",
                    mobsf_severity="info",
                )
            )

    return findings


def _extract_manifest_analysis_findings(
    report: dict[str, Any],
) -> list[NormalizedManifestFinding]:
    """Extract findings from MobSF's ``manifest_analysis`` section.

    MobSF reports manifest findings as a list of dicts::

        "manifest_analysis": [
            {
                "rule": "android_debuggable",
                "title": "Debug Enabled For App",
                "severity": "high",
                "description": "...",
                "name": "...",
                "component": [],
            },
            ...
        ]

    We map these to our check IDs via pattern matching on the rule name.
    """
    findings: list[NormalizedManifestFinding] = []
    manifest_analysis = report.get("manifest_analysis", [])

    if not isinstance(manifest_analysis, list):
        return findings

    for entry in manifest_analysis:
        if not isinstance(entry, dict):
            continue

        rule = entry.get("rule", "")
        title = entry.get("title", "")
        severity_raw = entry.get("severity", "info")
        description = entry.get("description", "")
        components = entry.get("component", [])

        # Map MobSF severity to Wairz severity
        severity = _map_severity(severity_raw)

        # Map rule to check_id
        check_id, cwe_ids = _map_rule_to_check(rule, title)

        # Build evidence from component list
        evidence_parts: list[str] = []
        if isinstance(components, list):
            for comp in components[:10]:
                evidence_parts.append(str(comp))
        evidence = "; ".join(evidence_parts) if evidence_parts else rule

        findings.append(
            NormalizedManifestFinding(
                check_id=check_id,
                title=title or rule,
                severity=severity,
                description=description,
                evidence=evidence[:1000],
                cwe_ids=cwe_ids,
                confidence="high" if severity in ("high", "critical") else "medium",
                mobsf_key=rule,
                mobsf_severity=severity_raw,
            )
        )

    return findings


def _extract_exported_component_findings(
    report: dict[str, Any],
) -> list[NormalizedManifestFinding]:
    """Extract findings from MobSF's exported component lists.

    MobSF lists exported components in separate sections:
    - ``exported_activities``
    - ``exported_services``
    - ``exported_receivers``
    - ``exported_providers``

    Each can be a list of component name strings or dicts with details.
    We generate MANIFEST-006 findings for unprotected exports.
    """
    findings: list[NormalizedManifestFinding] = []

    component_types = {
        "exported_activities": ("Activity", "exported_activity"),
        "exported_services": ("Service", "exported_service"),
        "exported_receivers": ("Receiver", "exported_receiver"),
        "exported_providers": ("Provider", "exported_provider"),
    }

    for key, (comp_type, map_key) in component_types.items():
        components = report.get(key)
        if not components:
            continue

        if not isinstance(components, list):
            continue

        meta = _MANIFEST_CHECK_MAP.get(map_key, {})
        check_id = meta.get("check_id", "MANIFEST-006")
        cwe_ids = meta.get("cwe_ids", ["CWE-926"])
        default_severity = meta.get("default_severity", "medium")

        comp_names: list[str] = []
        for comp in components:
            if isinstance(comp, str):
                comp_names.append(comp)
            elif isinstance(comp, dict):
                name = comp.get("name", comp.get("class", str(comp)))
                comp_names.append(str(name))

        if comp_names:
            # Summarize: list up to 5 components, indicate if more
            displayed = comp_names[:5]
            extra = len(comp_names) - 5
            evidence = ", ".join(displayed)
            if extra > 0:
                evidence += f" (+{extra} more)"

            findings.append(
                NormalizedManifestFinding(
                    check_id=check_id,
                    title=f"Exported {comp_type}{'s' if len(comp_names) > 1 else ''} "
                    f"without permission protection ({len(comp_names)} found)",
                    severity=default_severity,
                    description=(
                        f"{len(comp_names)} {comp_type.lower()} component(s) are "
                        f"exported without requiring a permission. This may allow "
                        f"unauthorized access from other applications."
                    ),
                    evidence=evidence,
                    cwe_ids=cwe_ids,
                    confidence="high",
                    mobsf_key=key,
                    mobsf_severity="warning",
                )
            )

    # Browsable activities
    browsable = report.get("browsable_activities", {})
    if browsable and isinstance(browsable, dict):
        for activity, schemes in browsable.items():
            meta = _MANIFEST_CHECK_MAP.get("browsable_activity", {})
            scheme_str = (
                ", ".join(str(s) for s in schemes[:5])
                if isinstance(schemes, list)
                else str(schemes)
            )
            findings.append(
                NormalizedManifestFinding(
                    check_id=meta.get("check_id", "MANIFEST-006"),
                    title=f"Browsable Activity: {activity}",
                    severity=meta.get("default_severity", "medium"),
                    description=(
                        f"Activity {activity} handles deep link schemes: "
                        f"{scheme_str}. Browsable activities can be triggered "
                        f"by external URLs."
                    ),
                    evidence=f"Schemes: {scheme_str}",
                    cwe_ids=meta.get("cwe_ids", ["CWE-939"]),
                    confidence="medium",
                    mobsf_key="browsable_activities",
                    mobsf_severity="info",
                )
            )

    return findings


def _extract_network_security_findings(
    report: dict[str, Any],
) -> list[NormalizedManifestFinding]:
    """Extract findings from MobSF's network security analysis."""
    findings: list[NormalizedManifestFinding] = []

    # Network security config
    nsc = report.get("network_security")
    if isinstance(nsc, list):
        for entry in nsc:
            if not isinstance(entry, dict):
                continue
            severity_raw = entry.get("severity", "info")
            if severity_raw.lower() in ("high", "warning"):
                meta = _MANIFEST_CHECK_MAP.get("network_security_config", {})
                findings.append(
                    NormalizedManifestFinding(
                        check_id=meta.get("check_id", "MANIFEST-011"),
                        title=entry.get("title", "Network security configuration issue"),
                        severity=_map_severity(severity_raw),
                        description=entry.get("description", ""),
                        evidence=entry.get("scope", ""),
                        cwe_ids=meta.get("cwe_ids", ["CWE-295"]),
                        confidence="high",
                        mobsf_key="network_security",
                        mobsf_severity=severity_raw,
                    )
                )

    # Certificate pinning check
    cert_analysis = report.get("certificate_analysis", {})
    if isinstance(cert_analysis, dict):
        cert_findings = cert_analysis.get("certificate_findings", [])
        if isinstance(cert_findings, list):
            for cf in cert_findings:
                if not isinstance(cf, dict):
                    continue
                severity_raw = cf.get("severity", "info")
                if severity_raw.lower() in ("high", "warning"):
                    meta = _MANIFEST_CHECK_MAP.get("certificate_pinning", {})
                    findings.append(
                        NormalizedManifestFinding(
                            check_id=meta.get("check_id", "MANIFEST-011"),
                            title=cf.get("title", "Certificate analysis issue"),
                            severity=_map_severity(severity_raw),
                            description=cf.get("description", ""),
                            evidence=cf.get("hash", ""),
                            cwe_ids=meta.get("cwe_ids", ["CWE-295"]),
                            confidence="medium",
                            mobsf_key="certificate_analysis",
                            mobsf_severity=severity_raw,
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _map_severity(raw: str) -> str:
    """Map MobSF severity string to Wairz severity."""
    return _SEVERITY_MAP.get(raw.lower(), "info")


def _map_rule_to_check(
    rule: str, title: str
) -> tuple[str, list[str]]:
    """Map a MobSF manifest_analysis rule to a Wairz check_id and CWE list.

    Uses pattern matching on rule name and title to find the best
    mapping from the canonical check map.
    """
    rule_lower = rule.lower()
    title_lower = title.lower()

    # Direct rule mapping patterns
    rule_patterns: list[tuple[str, str]] = [
        ("debuggable", "is_debuggable"),
        ("debug", "is_debuggable"),
        ("backup", "is_allow_backup"),
        ("cleartext", "is_clear_text_traffic"),
        ("clear_text", "is_clear_text_traffic"),
        ("test_only", "is_test_only"),
        ("testonly", "is_test_only"),
        ("min_sdk", "min_sdk"),
        ("minsdk", "min_sdk"),
        ("target_sdk", "target_sdk"),
        ("targetsdk", "target_sdk"),
        ("exported_activity", "exported_activity"),
        ("exported_service", "exported_service"),
        ("exported_receiver", "exported_receiver"),
        ("exported_provider", "exported_provider"),
        ("exported_content", "exported_provider"),
        ("task_affinity", "task_affinity"),
        ("taskaffinity", "task_affinity"),
        ("strandhogg", "task_affinity"),
        ("launch_mode", "launch_mode"),
        ("launchmode", "launch_mode"),
        ("singletask", "launch_mode"),
        ("singleinstance", "launch_mode"),
        ("app_link", "app_link_verification"),
        ("applink", "app_link_verification"),
        ("autoverify", "app_link_verification"),
        ("deep_link", "app_link_verification"),
        ("deeplink", "app_link_verification"),
        ("network_security", "network_security_config"),
        ("nsc", "network_security_config"),
        ("certificate_pin", "certificate_pinning"),
        ("cert_pin", "certificate_pinning"),
        ("custom_permission", "custom_permission"),
        ("permission_level", "custom_permission"),
        ("browsable", "browsable_activity"),
    ]

    combined = f"{rule_lower} {title_lower}"
    for pattern, map_key in rule_patterns:
        if pattern in combined:
            meta = _MANIFEST_CHECK_MAP.get(map_key, {})
            return (
                meta.get("check_id", "MANIFEST-UNK"),
                meta.get("cwe_ids", []),
            )

    # Fallback: unmapped rule
    return "MANIFEST-UNK", []


def _elapsed_ms(t0: float) -> int:
    """Return elapsed milliseconds since ``t0``."""
    return int((time.monotonic() - t0) * 1000)


# ---------------------------------------------------------------------------
# Comparison utility
# ---------------------------------------------------------------------------


def compare_findings(
    wairz_findings: list[dict[str, Any]],
    mobsf_findings: list[NormalizedManifestFinding],
) -> dict[str, Any]:
    """Compare Wairz manifest findings against MobSF baseline.

    Returns a structured comparison report showing:
    - Findings present in both (true positives)
    - Findings only in Wairz (potential false positives or extended coverage)
    - Findings only in MobSF (gaps in Wairz coverage)

    Parameters
    ----------
    wairz_findings:
        List of dicts from ``ManifestFinding.to_dict()``.
    mobsf_findings:
        List of ``NormalizedManifestFinding`` from MobSF scan.

    Returns
    -------
    dict
        Structured comparison with ``matched``, ``wairz_only``,
        ``mobsf_only``, and summary statistics.
    """
    wairz_by_check: dict[str, list[dict[str, Any]]] = {}
    for f in wairz_findings:
        cid = f.get("check_id", "UNKNOWN")
        wairz_by_check.setdefault(cid, []).append(f)

    mobsf_by_check: dict[str, list[NormalizedManifestFinding]] = {}
    for f in mobsf_findings:
        mobsf_by_check.setdefault(f.check_id, []).append(f)

    all_checks = sorted(set(wairz_by_check.keys()) | set(mobsf_by_check.keys()))

    matched: list[dict[str, Any]] = []
    wairz_only: list[dict[str, Any]] = []
    mobsf_only: list[dict[str, Any]] = []

    for check_id in all_checks:
        w_list = wairz_by_check.get(check_id, [])
        m_list = mobsf_by_check.get(check_id, [])

        if w_list and m_list:
            # Both found this check — compare severity
            for w in w_list:
                matched.append({
                    "check_id": check_id,
                    "wairz_title": w.get("title", ""),
                    "wairz_severity": w.get("severity", ""),
                    "mobsf_title": m_list[0].title,
                    "mobsf_severity": m_list[0].severity,
                    "severity_match": w.get("severity", "") == m_list[0].severity,
                })
        elif w_list and not m_list:
            for w in w_list:
                wairz_only.append({
                    "check_id": check_id,
                    "title": w.get("title", ""),
                    "severity": w.get("severity", ""),
                    "classification": "extended_coverage",
                })
        else:
            for m in m_list:
                mobsf_only.append({
                    "check_id": check_id,
                    "title": m.title,
                    "severity": m.severity,
                    "classification": "coverage_gap",
                })

    total = len(matched) + len(wairz_only) + len(mobsf_only)
    return {
        "matched": matched,
        "wairz_only": wairz_only,
        "mobsf_only": mobsf_only,
        "summary": {
            "total_unique_checks": len(all_checks),
            "matched_count": len(matched),
            "wairz_only_count": len(wairz_only),
            "mobsf_only_count": len(mobsf_only),
            "coverage_pct": round(
                (len(matched) / total * 100) if total > 0 else 0, 1
            ),
            "severity_match_pct": round(
                (
                    sum(1 for m in matched if m["severity_match"])
                    / len(matched)
                    * 100
                )
                if matched
                else 0,
                1,
            ),
        },
    }
