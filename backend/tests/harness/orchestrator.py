"""Multi-phase APK scan orchestrator.

Runs manifest, bytecode, and SAST scans against discovered APK fixtures
and collects results into a structured report. Each phase is independently
skippable and has its own timeout.

Usage:
    from tests.harness.orchestrator import ScanOrchestrator, ScanConfig
    from tests.harness.discovery import discover_all

    fixtures = discover_all()
    config = ScanConfig(phases={ScanPhase.MANIFEST, ScanPhase.BYTECODE})
    orchestrator = ScanOrchestrator(config)
    report = await orchestrator.run(fixtures)
    print(report.summary())
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from tests.harness.discovery import APKFixture, FixtureSource, ScanPhase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Configuration for the scan orchestrator.

    Attributes:
        phases: Which scan phases to run. Defaults to all three.
        manifest_timeout: Per-APK timeout for manifest scan (seconds).
        bytecode_timeout: Per-APK timeout for bytecode scan (seconds).
        sast_timeout: Per-APK timeout for SAST scan (seconds).
        min_severity: Minimum severity to include in results.
        fail_fast: Stop on first scan error if True.
        skip_synthetic_for_bytecode: Skip synthetic fixtures for bytecode
            (they lack real DEX — only manifest mocks work).
        skip_synthetic_for_sast: Skip synthetic fixtures for SAST.
        firmware_context: Whether to apply firmware context adjustments.
    """

    phases: set[ScanPhase] = field(
        default_factory=lambda: {ScanPhase.MANIFEST, ScanPhase.BYTECODE, ScanPhase.SAST}
    )
    manifest_timeout: float = 5.0
    bytecode_timeout: float = 30.0
    sast_timeout: float = 180.0
    min_severity: str = "info"
    fail_fast: bool = False
    skip_synthetic_for_bytecode: bool = True
    skip_synthetic_for_sast: bool = True
    firmware_context: bool = True


# ---------------------------------------------------------------------------
# Phase result types
# ---------------------------------------------------------------------------


class PhaseStatus(str, Enum):
    """Status of a single phase scan."""

    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class PhaseFinding:
    """A single finding from any phase, normalized for the report.

    Attributes:
        phase: Which scan phase produced this finding.
        check_id: The check/pattern/rule ID (e.g. MANIFEST-001, BYTECODE-003).
        title: Human-readable title.
        severity: Severity level (critical/high/medium/low/info).
        confidence: Confidence level (high/medium/low).
        description: Description of the finding.
        evidence: Evidence or match details.
        cwe_ids: Associated CWE IDs.
        category: Category grouping.
        location: Optional source location (file, line, class, method).
    """

    phase: ScanPhase
    check_id: str
    title: str
    severity: str
    confidence: str = "high"
    description: str = ""
    evidence: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    category: str = ""
    location: dict[str, Any] | None = None


@dataclass
class PhaseResult:
    """Result of running one scan phase against one APK.

    Attributes:
        phase: Which scan phase was run.
        status: Overall status.
        findings: List of normalized findings.
        elapsed_ms: Wall-clock time in milliseconds.
        error: Error message if status is ERROR or TIMEOUT.
        raw_result: The raw result dict from the scanner (for debugging).
        from_cache: Whether the result was served from cache.
    """

    phase: ScanPhase
    status: PhaseStatus
    findings: list[PhaseFinding] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str | None = None
    raw_result: dict[str, Any] | None = None
    from_cache: bool = False

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Per-APK result
# ---------------------------------------------------------------------------


@dataclass
class APKScanResult:
    """Combined results of all phases for a single APK.

    Attributes:
        fixture: The APK fixture that was scanned.
        phase_results: Results keyed by scan phase.
        total_elapsed_ms: Total time across all phases.
    """

    fixture: APKFixture
    phase_results: dict[ScanPhase, PhaseResult] = field(default_factory=dict)
    total_elapsed_ms: float = 0.0

    @property
    def all_findings(self) -> list[PhaseFinding]:
        """All findings across all phases."""
        findings: list[PhaseFinding] = []
        for pr in self.phase_results.values():
            findings.extend(pr.findings)
        return findings

    @property
    def total_finding_count(self) -> int:
        return sum(pr.finding_count for pr in self.phase_results.values())

    @property
    def has_errors(self) -> bool:
        return any(
            pr.status in (PhaseStatus.ERROR, PhaseStatus.TIMEOUT)
            for pr in self.phase_results.values()
        )

    @property
    def severity_counts(self) -> dict[str, int]:
        """Aggregate severity counts across all phases."""
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def findings_by_phase(self, phase: ScanPhase) -> list[PhaseFinding]:
        pr = self.phase_results.get(phase)
        return pr.findings if pr else []

    def phase_status(self, phase: ScanPhase) -> PhaseStatus:
        pr = self.phase_results.get(phase)
        return pr.status if pr else PhaseStatus.SKIPPED

    def check_ids_found(self, phase: ScanPhase | None = None) -> set[str]:
        """Return the set of check IDs found, optionally filtered by phase."""
        findings = self.findings_by_phase(phase) if phase else self.all_findings
        return {f.check_id for f in findings}

    def validate_expected_manifest_checks(self) -> dict[str, Any]:
        """Validate that expected manifest checks were found.

        Returns:
            Dict with 'expected', 'found', 'missing', 'unexpected', 'pass'.
        """
        expected = self.fixture.expected_manifest_checks
        found = self.check_ids_found(ScanPhase.MANIFEST)
        return {
            "expected": expected,
            "found": found,
            "missing": expected - found,
            "unexpected": found - expected,
            "pass": expected.issubset(found),
        }


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------


@dataclass
class ScanReport:
    """Aggregate report across all APKs and phases.

    Attributes:
        config: The scan configuration used.
        results: Per-APK results.
        total_elapsed_ms: Total wall-clock time.
        started_at: Unix timestamp when the run started.
        finished_at: Unix timestamp when the run finished.
    """

    config: ScanConfig
    results: list[APKScanResult] = field(default_factory=list)
    total_elapsed_ms: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def apk_count(self) -> int:
        return len(self.results)

    @property
    def total_findings(self) -> int:
        return sum(r.total_finding_count for r in self.results)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.has_errors)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if not r.has_errors)

    def findings_by_severity(self) -> dict[str, int]:
        """Aggregate severity counts across all APKs."""
        counts: dict[str, int] = {}
        for r in self.results:
            for sev, cnt in r.severity_counts.items():
                counts[sev] = counts.get(sev, 0) + cnt
        return counts

    def findings_by_phase(self) -> dict[ScanPhase, int]:
        """Total finding count per phase across all APKs."""
        counts: dict[ScanPhase, int] = {}
        for r in self.results:
            for phase, pr in r.phase_results.items():
                counts[phase] = counts.get(phase, 0) + pr.finding_count
        return counts

    def validate_all_expected(self) -> list[dict[str, Any]]:
        """Validate expected findings for all fixtures that have them.

        Returns list of validation results for fixtures with expectations.
        """
        validations: list[dict[str, Any]] = []
        for r in self.results:
            if r.fixture.expected_manifest_checks:
                val = r.validate_expected_manifest_checks()
                val["fixture_name"] = r.fixture.name
                validations.append(val)

            # Check total count bounds
            if r.fixture.expected_min_findings is not None:
                count = r.total_finding_count
                val = {
                    "fixture_name": r.fixture.name,
                    "check": "total_count_bounds",
                    "total": count,
                    "min": r.fixture.expected_min_findings,
                    "max": r.fixture.expected_max_findings,
                    "pass": (
                        count >= r.fixture.expected_min_findings
                        and (
                            r.fixture.expected_max_findings is None
                            or count <= r.fixture.expected_max_findings
                        )
                    ),
                }
                validations.append(val)

        return validations

    def summary(self) -> str:
        """Generate a human-readable summary of the scan report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("APK SECURITY SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"APKs scanned:   {self.apk_count}")
        lines.append(f"Total findings: {self.total_findings}")
        lines.append(f"Total time:     {self.total_elapsed_ms:.0f}ms")
        lines.append(f"Errors:         {self.error_count}")
        lines.append("")

        # Phase breakdown
        by_phase = self.findings_by_phase()
        lines.append("Findings by phase:")
        for phase in ScanPhase:
            count = by_phase.get(phase, 0)
            lines.append(f"  {phase.value:10s}: {count}")

        # Severity breakdown
        by_sev = self.findings_by_severity()
        lines.append("\nFindings by severity:")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(sev, 0)
            lines.append(f"  {sev:10s}: {count}")

        # Per-APK details
        lines.append("\n" + "-" * 70)
        lines.append("PER-APK RESULTS")
        lines.append("-" * 70)

        for r in self.results:
            lines.append(f"\n  {r.fixture.name}")
            lines.append(f"    Source:   {r.fixture.source.value}")
            lines.append(f"    Findings: {r.total_finding_count}")
            lines.append(f"    Time:     {r.total_elapsed_ms:.0f}ms")
            if r.has_errors:
                for phase, pr in r.phase_results.items():
                    if pr.status in (PhaseStatus.ERROR, PhaseStatus.TIMEOUT):
                        lines.append(f"    ERROR [{phase.value}]: {pr.error}")

            for phase, pr in r.phase_results.items():
                if pr.status == PhaseStatus.SKIPPED:
                    continue
                lines.append(
                    f"    [{phase.value:8s}] "
                    f"status={pr.status.value} "
                    f"findings={pr.finding_count} "
                    f"time={pr.elapsed_ms:.0f}ms"
                )

        # Validation
        validations = self.validate_all_expected()
        if validations:
            lines.append("\n" + "-" * 70)
            lines.append("VALIDATION")
            lines.append("-" * 70)
            for v in validations:
                status = "PASS" if v["pass"] else "FAIL"
                lines.append(f"  [{status}] {v['fixture_name']}")
                if "missing" in v:
                    if v["missing"]:
                        lines.append(f"    Missing checks: {v['missing']}")
                    if v["unexpected"]:
                        lines.append(f"    Unexpected checks: {v['unexpected']}")
                if "total" in v:
                    lines.append(
                        f"    Total findings: {v['total']} "
                        f"(expected {v['min']}-{v.get('max', '∞')})"
                    )

        lines.append("\n" + "=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-compatible dict."""
        return {
            "config": {
                "phases": [p.value for p in self.config.phases],
                "min_severity": self.config.min_severity,
            },
            "summary": {
                "apk_count": self.apk_count,
                "total_findings": self.total_findings,
                "total_elapsed_ms": self.total_elapsed_ms,
                "error_count": self.error_count,
                "success_count": self.success_count,
                "by_severity": self.findings_by_severity(),
                "by_phase": {p.value: c for p, c in self.findings_by_phase().items()},
            },
            "results": [
                {
                    "fixture": {
                        "name": r.fixture.name,
                        "source": r.fixture.source.value,
                        "package_name": r.fixture.package_name,
                        "tags": sorted(r.fixture.tags),
                        "firmware_location": r.fixture.firmware_location,
                    },
                    "total_findings": r.total_finding_count,
                    "total_elapsed_ms": r.total_elapsed_ms,
                    "has_errors": r.has_errors,
                    "phases": {
                        phase.value: {
                            "status": pr.status.value,
                            "finding_count": pr.finding_count,
                            "elapsed_ms": pr.elapsed_ms,
                            "error": pr.error,
                            "from_cache": pr.from_cache,
                            "severity_counts": pr.severity_counts,
                        }
                        for phase, pr in r.phase_results.items()
                    },
                    "findings": [
                        {
                            "phase": f.phase.value,
                            "check_id": f.check_id,
                            "title": f.title,
                            "severity": f.severity,
                            "confidence": f.confidence,
                            "cwe_ids": f.cwe_ids,
                            "category": f.category,
                        }
                        for f in r.all_findings
                    ],
                }
                for r in self.results
            ],
            "validations": _serialize_validations(self.validate_all_expected()),
        }


# ---------------------------------------------------------------------------
# Phase scanners (pluggable backends)
# ---------------------------------------------------------------------------


class ManifestScanner:
    """Runs Phase 1 manifest security checks via AndroguardService."""

    def scan(
        self,
        fixture: APKFixture,
        *,
        min_severity: str = "info",
        firmware_context: bool = True,
    ) -> PhaseResult:
        """Run manifest scan synchronously.

        For real APK files, uses AndroguardService.scan_manifest_security().
        For synthetic fixtures, uses the mock APK factory.
        """
        start = time.monotonic()
        try:
            from app.services.androguard_service import AndroguardService

            service = AndroguardService()

            is_priv_app = fixture.is_priv_app if firmware_context else False
            is_platform_signed = fixture.is_platform_signed if firmware_context else False

            if fixture.source == FixtureSource.SYNTHETIC and fixture.fixture_def:
                # Use mock APK factory.
                #
                # androguard_service imports ``APK`` lazily inside
                # scan_manifest_security (`from androguard.core.apk import APK`),
                # so we must patch the source module, not androguard_service.
                # We also short-circuit ``os.path.isfile`` for the "<synthetic>"
                # sentinel path since no real file exists.
                from unittest.mock import patch as _patch

                from tests.fixtures.apk.mock_apk_factory import build_mock_apk

                mock_apk = build_mock_apk(fixture.fixture_def)
                _orig_isfile = os.path.isfile

                def _isfile_or_synthetic(p: str) -> bool:
                    if p == "<synthetic>":
                        return True
                    return _orig_isfile(p)

                with (
                    _patch("androguard.core.apk.APK", return_value=mock_apk),
                    _patch("os.path.isfile", side_effect=_isfile_or_synthetic),
                ):
                    result = service.scan_manifest_security(
                        apk_path="<synthetic>",
                        is_priv_app=is_priv_app,
                        is_platform_signed=is_platform_signed,
                    )
            elif fixture.path and fixture.is_real_file:
                result = service.scan_manifest_security(
                    apk_path=fixture.path,
                    is_priv_app=is_priv_app,
                    is_platform_signed=is_platform_signed,
                )
            else:
                return PhaseResult(
                    phase=ScanPhase.MANIFEST,
                    status=PhaseStatus.SKIPPED,
                    error="No APK file or fixture definition available",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )

            # Normalize findings
            findings = _normalize_manifest_findings(result.get("findings", []))

            # Filter by severity
            findings = _filter_severity(findings, min_severity)

            elapsed = (time.monotonic() - start) * 1000
            return PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.SUCCESS,
                findings=findings,
                elapsed_ms=elapsed,
                raw_result=result,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Manifest scan error for %s: %s", fixture.name, exc)
            return PhaseResult(
                phase=ScanPhase.MANIFEST,
                status=PhaseStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=elapsed,
            )


class BytecodeScanner:
    """Runs Phase 2a bytecode analysis via BytecodeAnalysisService."""

    def scan(
        self,
        fixture: APKFixture,
        *,
        timeout: float = 30.0,
        min_severity: str = "info",
    ) -> PhaseResult:
        """Run bytecode scan synchronously. Requires real APK file."""
        start = time.monotonic()

        if not fixture.is_real_file:
            return PhaseResult(
                phase=ScanPhase.BYTECODE,
                status=PhaseStatus.SKIPPED,
                error="Bytecode scan requires real APK file",
                elapsed_ms=0.0,
            )

        try:
            from app.services.bytecode_analysis_service import BytecodeAnalysisService

            service = BytecodeAnalysisService()
            result = service.scan_apk(
                apk_path=fixture.path,
                apk_location=fixture.firmware_location,
                timeout=timeout,
            )

            findings = _normalize_bytecode_findings(result.get("findings", []))
            findings = _filter_severity(findings, min_severity)

            elapsed = (time.monotonic() - start) * 1000
            return PhaseResult(
                phase=ScanPhase.BYTECODE,
                status=PhaseStatus.SUCCESS,
                findings=findings,
                elapsed_ms=elapsed,
                raw_result=result,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Bytecode scan error for %s: %s", fixture.name, exc)
            return PhaseResult(
                phase=ScanPhase.BYTECODE,
                status=PhaseStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=elapsed,
            )


class SASTScanner:
    """Runs Phase 2b SAST via MobsfScanPipeline (jadx + mobsfscan)."""

    async def scan(
        self,
        fixture: APKFixture,
        *,
        timeout: int = 180,
        min_severity: str = "info",
        db: Any = None,
        firmware_id: Any = None,
        project_id: Any = None,
    ) -> PhaseResult:
        """Run SAST scan asynchronously. Requires real APK file."""
        start = time.monotonic()

        if not fixture.is_real_file:
            return PhaseResult(
                phase=ScanPhase.SAST,
                status=PhaseStatus.SKIPPED,
                error="SAST scan requires real APK file",
                elapsed_ms=0.0,
            )

        try:
            from app.services.mobsfscan import MobsfScanPipeline

            pipeline = MobsfScanPipeline()
            result = await pipeline.scan_apk(
                apk_path=fixture.path,
                firmware_id=firmware_id,
                project_id=project_id,
                db=db,
                apk_rel_path=fixture.firmware_location or "",
                timeout=timeout,
                min_severity=min_severity,
                persist=False,  # Don't persist in test mode
                use_cache=True,
            )

            findings = _normalize_sast_findings(result.normalized)
            findings = _filter_severity(findings, min_severity)

            elapsed = (time.monotonic() - start) * 1000
            return PhaseResult(
                phase=ScanPhase.SAST,
                status=PhaseStatus.SUCCESS,
                findings=findings,
                elapsed_ms=elapsed,
                raw_result={
                    "finding_count": len(findings),
                    "jadx_elapsed_ms": result.jadx_elapsed_ms,
                    "mobsfscan_elapsed_ms": result.mobsfscan_elapsed_ms,
                    "total_elapsed_ms": result.total_elapsed_ms,
                    "cached": result.cached,
                },
                from_cache=result.cached,
            )

        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            return PhaseResult(
                phase=ScanPhase.SAST,
                status=PhaseStatus.TIMEOUT,
                error=f"SAST scan timed out after {timeout}s",
                elapsed_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("SAST scan error for %s: %s", fixture.name, exc)
            return PhaseResult(
                phase=ScanPhase.SAST,
                status=PhaseStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=elapsed,
            )


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------


class ScanOrchestrator:
    """Coordinates multi-phase APK security scanning.

    Example:
        config = ScanConfig(phases={ScanPhase.MANIFEST})
        orchestrator = ScanOrchestrator(config)
        report = await orchestrator.run(fixtures)
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._manifest_scanner = ManifestScanner()
        self._bytecode_scanner = BytecodeScanner()
        self._sast_scanner = SASTScanner()

    async def run(
        self,
        fixtures: list[APKFixture],
        *,
        db: Any = None,
        firmware_id: Any = None,
        project_id: Any = None,
    ) -> ScanReport:
        """Run all configured phases against all fixtures.

        Args:
            fixtures: APK fixtures to scan.
            db: Optional async DB session (required for SAST persistence).
            firmware_id: Optional firmware UUID (for SAST caching).
            project_id: Optional project UUID (for SAST persistence).

        Returns:
            A ScanReport with all results.
        """
        report = ScanReport(config=self.config)
        report.started_at = time.time()
        run_start = time.monotonic()

        for fixture in fixtures:
            try:
                apk_result = await self._scan_single(
                    fixture,
                    db=db,
                    firmware_id=firmware_id,
                    project_id=project_id,
                )
                report.results.append(apk_result)

                if self.config.fail_fast and apk_result.has_errors:
                    logger.warning(
                        "Fail-fast: stopping after error on %s",
                        fixture.name,
                    )
                    break

            except Exception as exc:
                logger.error(
                    "Unexpected error scanning %s: %s\n%s",
                    fixture.name,
                    exc,
                    traceback.format_exc(),
                )
                # Record as an all-phases error
                error_result = APKScanResult(fixture=fixture)
                for phase in self.config.phases:
                    error_result.phase_results[phase] = PhaseResult(
                        phase=phase,
                        status=PhaseStatus.ERROR,
                        error=f"Orchestrator error: {type(exc).__name__}: {exc}",
                    )
                report.results.append(error_result)

                if self.config.fail_fast:
                    break

        report.total_elapsed_ms = (time.monotonic() - run_start) * 1000
        report.finished_at = time.time()
        return report

    async def _scan_single(
        self,
        fixture: APKFixture,
        *,
        db: Any = None,
        firmware_id: Any = None,
        project_id: Any = None,
    ) -> APKScanResult:
        """Run all configured phases for a single APK fixture."""
        apk_start = time.monotonic()
        result = APKScanResult(fixture=fixture)

        # Phase 1: Manifest
        if ScanPhase.MANIFEST in self.config.phases:
            # Synthetic fixtures CAN be manifest-scanned if they have a
            # fixture_def (the mock APK factory handles it).  Only skip
            # synthetics that have no definition at all.
            should_skip = (
                fixture.source == FixtureSource.SYNTHETIC
                and not fixture.fixture_def
            )
            if not should_skip:
                # Manifest scan is sync — run in executor to not block
                loop = asyncio.get_running_loop()
                pr = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: self._manifest_scanner.scan(
                            fixture,
                            min_severity=self.config.min_severity,
                            firmware_context=self.config.firmware_context,
                        ),
                    ),
                    timeout=self.config.manifest_timeout,
                )
                result.phase_results[ScanPhase.MANIFEST] = pr

        # Phase 2a: Bytecode
        if ScanPhase.BYTECODE in self.config.phases:
            should_skip = (
                self.config.skip_synthetic_for_bytecode
                and fixture.source == FixtureSource.SYNTHETIC
            )
            if should_skip:
                result.phase_results[ScanPhase.BYTECODE] = PhaseResult(
                    phase=ScanPhase.BYTECODE,
                    status=PhaseStatus.SKIPPED,
                    error="Synthetic fixture — bytecode scan requires real APK",
                )
            else:
                loop = asyncio.get_running_loop()
                try:
                    pr = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda: self._bytecode_scanner.scan(
                                fixture,
                                timeout=self.config.bytecode_timeout,
                                min_severity=self.config.min_severity,
                            ),
                        ),
                        timeout=self.config.bytecode_timeout + 5,  # margin
                    )
                except asyncio.TimeoutError:
                    pr = PhaseResult(
                        phase=ScanPhase.BYTECODE,
                        status=PhaseStatus.TIMEOUT,
                        error=f"Timed out after {self.config.bytecode_timeout}s",
                    )
                result.phase_results[ScanPhase.BYTECODE] = pr

        # Phase 2b: SAST
        if ScanPhase.SAST in self.config.phases:
            should_skip = (
                self.config.skip_synthetic_for_sast
                and fixture.source == FixtureSource.SYNTHETIC
            )
            if should_skip:
                result.phase_results[ScanPhase.SAST] = PhaseResult(
                    phase=ScanPhase.SAST,
                    status=PhaseStatus.SKIPPED,
                    error="Synthetic fixture — SAST scan requires real APK",
                )
            else:
                try:
                    pr = await asyncio.wait_for(
                        self._sast_scanner.scan(
                            fixture,
                            timeout=int(self.config.sast_timeout),
                            min_severity=self.config.min_severity,
                            db=db,
                            firmware_id=firmware_id,
                            project_id=project_id,
                        ),
                        timeout=self.config.sast_timeout + 10,
                    )
                except asyncio.TimeoutError:
                    pr = PhaseResult(
                        phase=ScanPhase.SAST,
                        status=PhaseStatus.TIMEOUT,
                        error=f"Timed out after {self.config.sast_timeout}s",
                    )
                result.phase_results[ScanPhase.SAST] = pr

        result.total_elapsed_ms = (time.monotonic() - apk_start) * 1000
        return result


# ---------------------------------------------------------------------------
# Finding normalization helpers
# ---------------------------------------------------------------------------

def _serialize_validations(validations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Make validation dicts JSON-serializable (convert sets to sorted lists)."""
    result: list[dict[str, Any]] = []
    for v in validations:
        sv: dict[str, Any] = {}
        for k, val in v.items():
            sv[k] = sorted(val) if isinstance(val, (set, frozenset)) else val
        result.append(sv)
    return result


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _filter_severity(
    findings: list[PhaseFinding], min_severity: str
) -> list[PhaseFinding]:
    """Filter findings below the minimum severity threshold."""
    threshold = _SEVERITY_ORDER.get(min_severity, 0)
    return [
        f
        for f in findings
        if _SEVERITY_ORDER.get(f.severity, 0) >= threshold
    ]


def _normalize_manifest_findings(
    findings: list[dict[str, Any]],
) -> list[PhaseFinding]:
    """Convert manifest scanner output to normalized PhaseFinding list."""
    normalized: list[PhaseFinding] = []
    for f in findings:
        normalized.append(
            PhaseFinding(
                phase=ScanPhase.MANIFEST,
                check_id=f.get("check_id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                confidence=f.get("confidence", "high"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                cwe_ids=f.get("cwe_ids", []),
                category="manifest",
            )
        )
    return normalized


def _normalize_bytecode_findings(
    findings: list[dict[str, Any]],
) -> list[PhaseFinding]:
    """Convert bytecode scanner output to normalized PhaseFinding list."""
    normalized: list[PhaseFinding] = []
    for f in findings:
        locations = f.get("locations", [])
        # Create one PhaseFinding per bytecode finding (may have multiple locations)
        normalized.append(
            PhaseFinding(
                phase=ScanPhase.BYTECODE,
                check_id=f.get("pattern_id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                confidence=f.get("confidence", "high"),
                description=f.get("description", ""),
                evidence=f"Found {f.get('count', 0)} occurrence(s)",
                cwe_ids=f.get("cwe_ids", []),
                category=f.get("category", "bytecode"),
                location=locations[0] if locations else None,
            )
        )
    return normalized


def _normalize_sast_findings(
    findings: list,
) -> list[PhaseFinding]:
    """Convert mobsfscan normalized findings to PhaseFinding list."""
    normalized: list[PhaseFinding] = []
    for f in findings:
        # Handle both dataclass and dict representations
        if hasattr(f, "rule_id"):
            normalized.append(
                PhaseFinding(
                    phase=ScanPhase.SAST,
                    check_id=getattr(f, "rule_id", ""),
                    title=getattr(f, "title", ""),
                    severity=getattr(f, "severity", "info"),
                    confidence="high",
                    description=getattr(f, "description", ""),
                    evidence=getattr(f, "evidence", ""),
                    cwe_ids=getattr(f, "cwe_ids", []),
                    category="sast",
                    location={
                        "file_path": getattr(f, "file_path", None),
                        "line_number": getattr(f, "line_number", None),
                    },
                )
            )
        elif isinstance(f, dict):
            normalized.append(
                PhaseFinding(
                    phase=ScanPhase.SAST,
                    check_id=f.get("rule_id", ""),
                    title=f.get("title", ""),
                    severity=f.get("severity", "info"),
                    confidence="high",
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    cwe_ids=f.get("cwe_ids", []),
                    category="sast",
                    location={
                        "file_path": f.get("file_path"),
                        "line_number": f.get("line_number"),
                    },
                )
            )
    return normalized
