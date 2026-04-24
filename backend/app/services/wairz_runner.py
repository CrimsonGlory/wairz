"""Wairz manifest scanner runner — invokes AndroguardService locally.

This module provides a runner that:

1. Invokes the Wairz built-in manifest scanner (AndroguardService)
   against APK files
2. Normalizes findings into the same structured JSON schema used by
   the MobSF runner (:mod:`app.services.mobsf_runner`) for direct
   comparison
3. Supports both standalone APKs and firmware-embedded APKs with
   firmware context (priv-app, platform-signed)

This is the **Wairz side** of the benchmarking pipeline.  It pairs
with :func:`~app.services.mobsf_runner.compare_findings` to measure
coverage, accuracy, and false-positive rates against MobSF's baseline.

Usage::

    runner = WairzRunner()
    result = runner.scan_apk("/path/to/app.apk")

    # Compare against MobSF
    from app.services.mobsf_runner import compare_findings
    comparison = compare_findings(
        [f.to_dict() for f in result.manifest_findings],
        mobsf_result.manifest_findings,
    )

All scan methods are synchronous (the underlying Androguard service
is CPU-bound) but can be wrapped in ``run_in_executor()`` for async
callers.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.androguard_service import AndroguardService
from app.services.mobsf_runner import compare_findings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normalized finding schema (mirrors mobsf_runner.NormalizedManifestFinding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizedWairzFinding:
    """A single Wairz manifest finding normalized for comparison.

    Fields align with :class:`~app.services.mobsf_runner.NormalizedManifestFinding`
    for direct comparison via :func:`~app.services.mobsf_runner.compare_findings`.
    """

    check_id: str
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str
    cwe_ids: list[str]
    confidence: str  # "high", "medium", "low"
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict matching ManifestFinding.to_dict() output.

        The output is compatible with both the MobSF runner's
        ``compare_findings()`` function and the Wairz Finding model.
        """
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "cwe_ids": self.cwe_ids,
            "confidence": self.confidence,
        }
        if self.suppressed:
            d["suppressed"] = True
            d["suppression_reason"] = self.suppression_reason
        return d


@dataclass(slots=True)
class WairzScanResult:
    """Result of a Wairz manifest scan with normalized findings."""

    success: bool
    package_name: str = ""
    manifest_findings: list[NormalizedWairzFinding] = field(default_factory=list)
    suppressed_findings: list[NormalizedWairzFinding] = field(default_factory=list)
    raw_result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    scan_duration_ms: int = 0
    apk_hash: str = ""
    # Firmware context metadata
    is_priv_app: bool = False
    is_platform_signed: bool = False
    severity_bumped: bool = False
    severity_reduced: bool = False
    reduced_check_ids: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        """Compact summary suitable for logging or comparison reports."""
        severity_counts: dict[str, int] = {}
        for f in self.manifest_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        confidence_counts: dict[str, int] = {}
        for f in self.manifest_findings:
            confidence_counts[f.confidence] = (
                confidence_counts.get(f.confidence, 0) + 1
            )
        check_ids = sorted({f.check_id for f in self.manifest_findings})
        return {
            "success": self.success,
            "package_name": self.package_name,
            "total_findings": len(self.manifest_findings),
            "suppressed_count": len(self.suppressed_findings),
            "by_severity": severity_counts,
            "by_confidence": confidence_counts,
            "check_ids": check_ids,
            "scan_duration_ms": self.scan_duration_ms,
            "apk_hash": self.apk_hash,
            "firmware_context": {
                "is_priv_app": self.is_priv_app,
                "is_platform_signed": self.is_platform_signed,
                "severity_bumped": self.severity_bumped,
                "severity_reduced": self.severity_reduced,
                "reduced_check_ids": self.reduced_check_ids,
            },
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
            "suppressed_findings": [f.to_dict() for f in self.suppressed_findings],
            "firmware_context": {
                "is_priv_app": self.is_priv_app,
                "is_platform_signed": self.is_platform_signed,
                "severity_bumped": self.severity_bumped,
                "severity_reduced": self.severity_reduced,
                "reduced_check_ids": self.reduced_check_ids,
            },
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class WairzRunner:
    """Runner that invokes Wairz's AndroguardService for manifest scanning.

    This provides the Wairz counterpart to :class:`~app.services.mobsf_runner.MobsfRunner`,
    enabling side-by-side comparison of manifest findings.

    Parameters
    ----------
    service:
        Optional pre-configured :class:`~app.services.androguard_service.AndroguardService`
        instance.  If ``None``, a new instance is created on first scan.
    """

    def __init__(
        self,
        service: Any | None = None,
    ) -> None:
        self._service = service

    def _get_service(self) -> Any:
        """Lazy-instantiate the AndroguardService (import is top-level;
        instantiation stays lazy to avoid cold-start cost on non-APK paths)."""
        if self._service is None:
            self._service = AndroguardService()
        return self._service

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def scan_apk(
        self,
        apk_path: str,
        *,
        is_priv_app: bool = False,
        is_platform_signed: bool = False,
    ) -> WairzScanResult:
        """Scan an APK using Wairz's manifest scanner and return normalized results.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file on disk.
        is_priv_app:
            Whether the APK is from a ``/system/priv-app/`` directory.
        is_platform_signed:
            Whether the APK is signed with the platform key.

        Returns
        -------
        WairzScanResult
            Scan result with manifest findings normalized for comparison.
        """
        p = Path(apk_path)
        if not p.is_file():
            return WairzScanResult(
                success=False,
                error=f"APK file not found: {apk_path}",
            )

        apk_hash = _compute_sha256(p)
        t0 = time.monotonic()

        try:
            service = self._get_service()
            raw = service.scan_manifest_security(
                apk_path,
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            )

            # Normalize active findings
            active_findings = _normalize_findings(
                raw.get("findings", []),
                suppressed=False,
            )

            # Normalize suppressed findings
            suppressed_findings = _normalize_findings(
                raw.get("suppressed_findings", []),
                suppressed=True,
            )

            elapsed = _elapsed_ms(t0)

            return WairzScanResult(
                success=True,
                package_name=raw.get("package", ""),
                manifest_findings=active_findings,
                suppressed_findings=suppressed_findings,
                raw_result=raw,
                apk_hash=apk_hash,
                scan_duration_ms=elapsed,
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
                severity_bumped=raw.get("severity_bumped", False),
                severity_reduced=raw.get("severity_reduced", False),
                reduced_check_ids=raw.get("reduced_check_ids", []),
            )

        except FileNotFoundError:
            return WairzScanResult(
                success=False,
                error=f"APK file not found: {apk_path}",
                apk_hash=apk_hash,
                scan_duration_ms=_elapsed_ms(t0),
            )
        except Exception as exc:
            logger.exception("Wairz manifest scan failed for %s", apk_path)
            return WairzScanResult(
                success=False,
                error=f"Wairz scan error: {exc}",
                apk_hash=apk_hash,
                scan_duration_ms=_elapsed_ms(t0),
            )

    async def scan_apk_async(
        self,
        apk_path: str,
        *,
        is_priv_app: bool = False,
        is_platform_signed: bool = False,
    ) -> WairzScanResult:
        """Async wrapper around :meth:`scan_apk` using ``run_in_executor``.

        Androguard manifest parsing is CPU-bound; this wraps the sync
        call to avoid blocking the event loop.

        Parameters match :meth:`scan_apk`.
        """
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.scan_apk(
                apk_path,
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            ),
        )

    def scan_apk_from_raw(
        self,
        raw_result: dict[str, Any],
        *,
        apk_hash: str = "",
        is_priv_app: bool = False,
        is_platform_signed: bool = False,
    ) -> WairzScanResult:
        """Normalize a pre-existing raw scan result without re-scanning.

        Useful for offline comparison when a previously cached scan
        result is available (e.g., from the ``analysis_cache`` table).

        Parameters
        ----------
        raw_result:
            A dict from ``AndroguardService.scan_manifest_security()``.
        apk_hash:
            Optional SHA256 hash of the APK for tracking.
        is_priv_app:
            Whether the APK was from a ``/system/priv-app/`` directory.
        is_platform_signed:
            Whether the APK was platform-signed.

        Returns
        -------
        WairzScanResult
            Normalized scan result for comparison.
        """
        active_findings = _normalize_findings(
            raw_result.get("findings", []),
            suppressed=False,
        )
        suppressed_findings = _normalize_findings(
            raw_result.get("suppressed_findings", []),
            suppressed=True,
        )

        return WairzScanResult(
            success=True,
            package_name=raw_result.get("package", ""),
            manifest_findings=active_findings,
            suppressed_findings=suppressed_findings,
            raw_result=raw_result,
            apk_hash=apk_hash,
            is_priv_app=is_priv_app,
            is_platform_signed=is_platform_signed,
            severity_bumped=raw_result.get("severity_bumped", False),
            severity_reduced=raw_result.get("severity_reduced", False),
            reduced_check_ids=raw_result.get("reduced_check_ids", []),
        )


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _normalize_findings(
    findings: list[dict[str, Any]],
    *,
    suppressed: bool = False,
) -> list[NormalizedWairzFinding]:
    """Convert ManifestFinding dicts into NormalizedWairzFinding objects.

    Parameters
    ----------
    findings:
        List of finding dicts from ``ManifestFinding.to_dict()``.
    suppressed:
        Whether these findings were suppressed by the scanner.

    Returns
    -------
    list[NormalizedWairzFinding]
        Normalized findings ready for comparison.
    """
    normalized: list[NormalizedWairzFinding] = []
    for f in findings:
        if not isinstance(f, dict):
            continue

        is_suppressed = f.get("suppressed", suppressed)
        suppression_reason = f.get("suppression_reason", "")

        normalized.append(
            NormalizedWairzFinding(
                check_id=f.get("check_id", "UNKNOWN"),
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                cwe_ids=f.get("cwe_ids", []),
                confidence=f.get("confidence", "high"),
                suppressed=is_suppressed,
                suppression_reason=suppression_reason,
            )
        )

    return normalized


# ---------------------------------------------------------------------------
# Batch scanning
# ---------------------------------------------------------------------------


def batch_scan(
    apk_paths: list[str],
    *,
    is_priv_app: bool = False,
    is_platform_signed: bool = False,
    runner: WairzRunner | None = None,
) -> dict[str, WairzScanResult]:
    """Scan multiple APKs and return results keyed by path.

    Parameters
    ----------
    apk_paths:
        List of absolute paths to APK files.
    is_priv_app:
        Whether the APKs are from ``/system/priv-app/``.
    is_platform_signed:
        Whether the APKs are platform-signed.
    runner:
        Optional pre-configured runner.  A new one is created if None.

    Returns
    -------
    dict[str, WairzScanResult]
        Results keyed by APK path.
    """
    if runner is None:
        runner = WairzRunner()

    results: dict[str, WairzScanResult] = {}
    for path in apk_paths:
        logger.info("Scanning %s", path)
        results[path] = runner.scan_apk(
            path,
            is_priv_app=is_priv_app,
            is_platform_signed=is_platform_signed,
        )

    return results


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------


def compare_with_mobsf(
    wairz_result: WairzScanResult,
    mobsf_findings: list[Any],
) -> dict[str, Any]:
    """Compare Wairz scan result against MobSF normalized findings.

    This is a convenience wrapper around
    :func:`~app.services.mobsf_runner.compare_findings` that handles
    the conversion from ``WairzScanResult`` to finding dicts.

    Parameters
    ----------
    wairz_result:
        Wairz scan result from :meth:`WairzRunner.scan_apk`.
    mobsf_findings:
        List of ``NormalizedManifestFinding`` from MobSF runner.

    Returns
    -------
    dict
        Structured comparison report (see ``mobsf_runner.compare_findings``).
    """
    wairz_dicts = [f.to_dict() for f in wairz_result.manifest_findings]
    return compare_findings(wairz_dicts, mobsf_findings)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _elapsed_ms(t0: float) -> int:
    """Return elapsed milliseconds since ``t0``."""
    return int((time.monotonic() - t0) * 1000)
