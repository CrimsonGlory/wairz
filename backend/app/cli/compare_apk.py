"""Comparison harness CLI for Wairz vs MobSF APK manifest scanning.

Orchestrates both the Wairz runner (Androguard-based) and the MobSF
runner (MobSF API or offline JSON report), collects findings from
each, and produces a side-by-side JSON diff report classifying each
finding as ``match``, ``miss`` (MobSF-only gap), or ``extra``
(Wairz-only extended coverage).

Usage::

    # Live scan: both runners scan the APK
    wairz-compare-apk /path/to/app.apk --mobsf-url http://localhost:8000 --mobsf-key KEY

    # Offline: Wairz scans live, MobSF from pre-exported JSON report
    wairz-compare-apk /path/to/app.apk --mobsf-report /path/to/mobsf_report.json

    # Batch: multiple APKs
    wairz-compare-apk /path/to/apk1.apk /path/to/apk2.apk --mobsf-report-dir /reports/

    # Firmware-embedded APK with context
    wairz-compare-apk /path/to/app.apk --priv-app --platform-signed

    # Output to file
    wairz-compare-apk /path/to/app.apk --mobsf-report report.json -o comparison.json

Exit codes:
    0  All findings matched (100% coverage, no gaps)
    1  Gaps detected (MobSF found things Wairz missed)
    2  Error (scan failure, file not found, etc.)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Patch pydantic-settings so imports don't fail outside Docker
# ---------------------------------------------------------------------------
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///unused.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

logger = logging.getLogger("wairz.compare-apk")

# Severity ordering for comparison
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Data structures for the comparison report
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FindingMatch:
    """A finding present in both Wairz and MobSF output."""

    classification: str = "match"
    check_id: str = ""
    wairz_title: str = ""
    wairz_severity: str = ""
    wairz_evidence: str = ""
    wairz_cwe_ids: list[str] = field(default_factory=list)
    mobsf_title: str = ""
    mobsf_severity: str = ""
    mobsf_evidence: str = ""
    mobsf_cwe_ids: list[str] = field(default_factory=list)
    severity_match: bool = True
    severity_delta: int = 0  # positive = wairz more severe

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "check_id": self.check_id,
            "wairz": {
                "title": self.wairz_title,
                "severity": self.wairz_severity,
                "evidence": self.wairz_evidence,
                "cwe_ids": self.wairz_cwe_ids,
            },
            "mobsf": {
                "title": self.mobsf_title,
                "severity": self.mobsf_severity,
                "evidence": self.mobsf_evidence,
                "cwe_ids": self.mobsf_cwe_ids,
            },
            "severity_match": self.severity_match,
            "severity_delta": self.severity_delta,
        }


@dataclass(frozen=True, slots=True)
class FindingMiss:
    """A finding present in MobSF but absent from Wairz (coverage gap)."""

    classification: str = "miss"
    check_id: str = ""
    mobsf_title: str = ""
    mobsf_severity: str = ""
    mobsf_evidence: str = ""
    mobsf_cwe_ids: list[str] = field(default_factory=list)
    mobsf_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "check_id": self.check_id,
            "mobsf": {
                "title": self.mobsf_title,
                "severity": self.mobsf_severity,
                "evidence": self.mobsf_evidence,
                "cwe_ids": self.mobsf_cwe_ids,
                "mobsf_key": self.mobsf_key,
            },
        }


@dataclass(frozen=True, slots=True)
class FindingExtra:
    """A finding present in Wairz but absent from MobSF (extended coverage)."""

    classification: str = "extra"
    check_id: str = ""
    wairz_title: str = ""
    wairz_severity: str = ""
    wairz_evidence: str = ""
    wairz_cwe_ids: list[str] = field(default_factory=list)
    wairz_confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "check_id": self.check_id,
            "wairz": {
                "title": self.wairz_title,
                "severity": self.wairz_severity,
                "evidence": self.wairz_evidence,
                "cwe_ids": self.wairz_cwe_ids,
                "confidence": self.wairz_confidence,
            },
        }


@dataclass(slots=True)
class ComparisonReport:
    """Full side-by-side comparison report for one APK."""

    apk_path: str = ""
    apk_hash: str = ""
    package_name: str = ""
    timestamp: str = ""

    # Runner results
    wairz_total: int = 0
    wairz_duration_ms: int = 0
    wairz_success: bool = False
    wairz_error: str | None = None

    mobsf_total: int = 0
    mobsf_duration_ms: int = 0
    mobsf_success: bool = False
    mobsf_error: str | None = None

    # Firmware context
    is_priv_app: bool = False
    is_platform_signed: bool = False
    severity_bumped: bool = False
    severity_reduced: bool = False

    # Classified findings
    matches: list[FindingMatch] = field(default_factory=list)
    misses: list[FindingMiss] = field(default_factory=list)
    extras: list[FindingExtra] = field(default_factory=list)

    # Aggregate metrics
    coverage_pct: float = 0.0
    severity_match_pct: float = 0.0
    false_positive_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Full serialization for JSON output."""
        total_classified = len(self.matches) + len(self.misses) + len(self.extras)
        return {
            "meta": {
                "apk_path": self.apk_path,
                "apk_hash": self.apk_hash,
                "package_name": self.package_name,
                "timestamp": self.timestamp,
                "harness_version": "1.0.0",
            },
            "runners": {
                "wairz": {
                    "success": self.wairz_success,
                    "total_findings": self.wairz_total,
                    "duration_ms": self.wairz_duration_ms,
                    "error": self.wairz_error,
                },
                "mobsf": {
                    "success": self.mobsf_success,
                    "total_findings": self.mobsf_total,
                    "duration_ms": self.mobsf_duration_ms,
                    "error": self.mobsf_error,
                },
            },
            "firmware_context": {
                "is_priv_app": self.is_priv_app,
                "is_platform_signed": self.is_platform_signed,
                "severity_bumped": self.severity_bumped,
                "severity_reduced": self.severity_reduced,
            },
            "diff": {
                "matches": [m.to_dict() for m in self.matches],
                "misses": [m.to_dict() for m in self.misses],
                "extras": [e.to_dict() for e in self.extras],
            },
            "summary": {
                "total_unique_findings": total_classified,
                "match_count": len(self.matches),
                "miss_count": len(self.misses),
                "extra_count": len(self.extras),
                "coverage_pct": self.coverage_pct,
                "severity_match_pct": self.severity_match_pct,
                "false_positive_rate": self.false_positive_rate,
                "verdict": self._verdict(),
            },
        }

    def _verdict(self) -> str:
        """Human-readable verdict string."""
        if not self.wairz_success:
            return "ERROR: Wairz scan failed"
        if not self.mobsf_success:
            return "ERROR: MobSF scan failed"
        if self.misses:
            return f"GAPS: {len(self.misses)} MobSF finding(s) not detected by Wairz"
        if self.extras:
            return f"PASS+EXTRA: All MobSF findings matched, {len(self.extras)} additional Wairz finding(s)"
        return "PASS: Full coverage match"


# ---------------------------------------------------------------------------
# Core comparison logic
# ---------------------------------------------------------------------------


def _severity_index(severity: str) -> int:
    """Return numeric index for severity comparison."""
    try:
        return _SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return 0


def build_comparison(
    wairz_result: Any,
    mobsf_result: Any,
    *,
    apk_path: str = "",
    is_priv_app: bool = False,
    is_platform_signed: bool = False,
) -> ComparisonReport:
    """Build a ComparisonReport from Wairz and MobSF scan results.

    Parameters
    ----------
    wairz_result:
        A ``WairzScanResult`` from the Wairz runner.
    mobsf_result:
        A ``MobsfScanResult`` from the MobSF runner.
    apk_path:
        Path to the APK for metadata.
    is_priv_app:
        Firmware context: privileged app location.
    is_platform_signed:
        Firmware context: platform-signed APK.

    Returns
    -------
    ComparisonReport
        Structured comparison with match/miss/extra classifications.
    """
    report = ComparisonReport(
        apk_path=apk_path,
        apk_hash=wairz_result.apk_hash or mobsf_result.apk_hash,
        package_name=wairz_result.package_name or mobsf_result.package_name,
        timestamp=datetime.now(UTC).isoformat(),
        wairz_total=len(wairz_result.manifest_findings),
        wairz_duration_ms=wairz_result.scan_duration_ms,
        wairz_success=wairz_result.success,
        wairz_error=wairz_result.error,
        mobsf_total=len(mobsf_result.manifest_findings),
        mobsf_duration_ms=mobsf_result.scan_duration_ms,
        mobsf_success=mobsf_result.success,
        mobsf_error=mobsf_result.error,
        is_priv_app=is_priv_app,
        is_platform_signed=is_platform_signed,
        severity_bumped=getattr(wairz_result, "severity_bumped", False),
        severity_reduced=getattr(wairz_result, "severity_reduced", False),
    )

    if not wairz_result.success or not mobsf_result.success:
        return report

    # Group findings by check_id for comparison
    wairz_by_check: dict[str, list[Any]] = {}
    for f in wairz_result.manifest_findings:
        cid = f.check_id if hasattr(f, "check_id") else f.get("check_id", "UNKNOWN")
        wairz_by_check.setdefault(cid, []).append(f)

    mobsf_by_check: dict[str, list[Any]] = {}
    for f in mobsf_result.manifest_findings:
        cid = f.check_id if hasattr(f, "check_id") else f.get("check_id", "UNKNOWN")
        mobsf_by_check.setdefault(cid, []).append(f)

    all_checks = sorted(set(wairz_by_check.keys()) | set(mobsf_by_check.keys()))

    # Skip unmapped MobSF findings (MANIFEST-UNK) for gap analysis
    # since they represent MobSF rules we haven't mapped yet, not real gaps
    skip_for_gaps = {"MANIFEST-UNK"}

    for check_id in all_checks:
        w_list = wairz_by_check.get(check_id, [])
        m_list = mobsf_by_check.get(check_id, [])

        if w_list and m_list:
            # Match: both scanners found this check
            for w in w_list:
                m = m_list[0]  # Compare against first MobSF finding for this check
                w_sev = _get_attr(w, "severity", "info")
                m_sev = _get_attr(m, "severity", "info")
                delta = _severity_index(w_sev) - _severity_index(m_sev)

                report.matches.append(FindingMatch(
                    check_id=check_id,
                    wairz_title=_get_attr(w, "title", ""),
                    wairz_severity=w_sev,
                    wairz_evidence=_get_attr(w, "evidence", ""),
                    wairz_cwe_ids=_get_attr(w, "cwe_ids", []),
                    mobsf_title=_get_attr(m, "title", ""),
                    mobsf_severity=m_sev,
                    mobsf_evidence=_get_attr(m, "evidence", ""),
                    mobsf_cwe_ids=_get_attr(m, "cwe_ids", []),
                    severity_match=(w_sev == m_sev),
                    severity_delta=delta,
                ))
        elif w_list and not m_list:
            # Extra: Wairz found it, MobSF didn't (extended coverage)
            for w in w_list:
                report.extras.append(FindingExtra(
                    check_id=check_id,
                    wairz_title=_get_attr(w, "title", ""),
                    wairz_severity=_get_attr(w, "severity", "info"),
                    wairz_evidence=_get_attr(w, "evidence", ""),
                    wairz_cwe_ids=_get_attr(w, "cwe_ids", []),
                    wairz_confidence=_get_attr(w, "confidence", "high"),
                ))
        elif m_list and check_id not in skip_for_gaps:
            # Miss: MobSF found it, Wairz didn't (coverage gap)
            for m in m_list:
                report.misses.append(FindingMiss(
                    check_id=check_id,
                    mobsf_title=_get_attr(m, "title", ""),
                    mobsf_severity=_get_attr(m, "severity", "info"),
                    mobsf_evidence=_get_attr(m, "evidence", ""),
                    mobsf_cwe_ids=_get_attr(m, "cwe_ids", []),
                    mobsf_key=_get_attr(m, "mobsf_key", ""),
                ))

    # Compute aggregate metrics
    total = len(report.matches) + len(report.misses)
    if total > 0:
        report.coverage_pct = round(len(report.matches) / total * 100, 1)
    else:
        report.coverage_pct = 100.0

    if report.matches:
        sev_matches = sum(1 for m in report.matches if m.severity_match)
        report.severity_match_pct = round(sev_matches / len(report.matches) * 100, 1)

    # False positive rate: extras that are low-confidence relative to total wairz
    if report.wairz_total > 0:
        low_conf_extras = sum(
            1 for e in report.extras
            if e.wairz_confidence == "low"
        )
        report.false_positive_rate = round(
            low_conf_extras / report.wairz_total * 100, 1
        )

    return report


def _get_attr(obj: Any, name: str, default: Any = "") -> Any:
    """Get attribute from either a dataclass or a dict."""
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj.get(name, default)
    return default


# ---------------------------------------------------------------------------
# Runner orchestration
# ---------------------------------------------------------------------------


def run_wairz_scan(
    apk_path: str,
    *,
    is_priv_app: bool = False,
    is_platform_signed: bool = False,
) -> Any:
    """Run the Wairz manifest scanner on an APK.

    Returns a WairzScanResult.
    """
    from app.services.wairz_runner import WairzRunner

    runner = WairzRunner()
    return runner.scan_apk(
        apk_path,
        is_priv_app=is_priv_app,
        is_platform_signed=is_platform_signed,
    )


async def run_mobsf_scan(
    apk_path: str,
    *,
    api_url: str | None = None,
    api_key: str | None = None,
    report_path: str | None = None,
) -> Any:
    """Run MobSF analysis — either live API or from offline JSON report.

    Returns a MobsfScanResult.
    """
    from app.services.mobsf_runner import MobsfRunner, MobsfScanResult

    # Offline mode: load from pre-exported JSON report
    if report_path:
        rp = Path(report_path)
        loop = asyncio.get_event_loop()
        if not await loop.run_in_executor(None, rp.is_file):
            return MobsfScanResult(
                success=False,
                error=f"MobSF report not found: {report_path}",
            )
        try:
            report_text = await loop.run_in_executor(
                None, lambda: rp.read_text(encoding="utf-8"),
            )
            report_json = json.loads(report_text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return MobsfScanResult(
                success=False,
                error=f"Failed to parse MobSF report: {exc}",
            )

        runner = MobsfRunner(api_url="http://unused", api_key="unused")
        return await runner.scan_apk_from_report(report_json)

    # Live API mode
    if not api_url or not api_key:
        return MobsfScanResult(
            success=False,
            error=(
                "MobSF API URL and key required for live scanning. "
                "Use --mobsf-url and --mobsf-key, or provide --mobsf-report "
                "for offline comparison."
            ),
        )

    runner = MobsfRunner(api_url=api_url, api_key=api_key)
    return await runner.scan_apk(apk_path)


async def compare_apk(
    apk_path: str,
    *,
    is_priv_app: bool = False,
    is_platform_signed: bool = False,
    mobsf_url: str | None = None,
    mobsf_key: str | None = None,
    mobsf_report: str | None = None,
) -> ComparisonReport:
    """Orchestrate both runners and build a comparison report.

    Parameters
    ----------
    apk_path:
        Path to the APK file.
    is_priv_app:
        Whether APK is from /system/priv-app/.
    is_platform_signed:
        Whether APK is platform-signed.
    mobsf_url:
        MobSF API base URL for live scanning.
    mobsf_key:
        MobSF API key for live scanning.
    mobsf_report:
        Path to pre-exported MobSF JSON report for offline comparison.

    Returns
    -------
    ComparisonReport
        Side-by-side diff with match/miss/extra classifications.
    """
    p = Path(apk_path)
    loop = asyncio.get_event_loop()
    if not await loop.run_in_executor(None, p.is_file):
        report = ComparisonReport(
            apk_path=apk_path,
            timestamp=datetime.now(UTC).isoformat(),
            wairz_success=False,
            wairz_error=f"APK not found: {apk_path}",
            mobsf_success=False,
            mobsf_error="Skipped (APK not found)",
        )
        return report

    # Run Wairz scanner (synchronous, CPU-bound)
    logger.info("Running Wairz manifest scan on %s", apk_path)
    loop = asyncio.get_running_loop()
    wairz_result = await loop.run_in_executor(
        None,
        lambda: run_wairz_scan(
            apk_path,
            is_priv_app=is_priv_app,
            is_platform_signed=is_platform_signed,
        ),
    )

    # Run MobSF scanner (async)
    logger.info("Running MobSF scan on %s", apk_path)
    mobsf_result = await run_mobsf_scan(
        apk_path,
        api_url=mobsf_url,
        api_key=mobsf_key,
        report_path=mobsf_report,
    )

    # Build comparison
    return build_comparison(
        wairz_result,
        mobsf_result,
        apk_path=apk_path,
        is_priv_app=is_priv_app,
        is_platform_signed=is_platform_signed,
    )


async def compare_batch(
    apk_paths: list[str],
    *,
    is_priv_app: bool = False,
    is_platform_signed: bool = False,
    mobsf_url: str | None = None,
    mobsf_key: str | None = None,
    mobsf_report_dir: str | None = None,
) -> list[ComparisonReport]:
    """Compare multiple APKs sequentially.

    For offline mode with --mobsf-report-dir, looks for
    ``<package_name>.json`` or ``<apk_stem>.json`` in the report directory.

    Returns a list of ComparisonReport objects.
    """
    reports: list[ComparisonReport] = []

    for apk_path in apk_paths:
        # Resolve MobSF report path for this APK
        report_path: str | None = None
        if mobsf_report_dir:
            report_dir = Path(mobsf_report_dir)
            stem = Path(apk_path).stem
            # Try stem.json first, then look for any matching file
            candidates = [
                report_dir / f"{stem}.json",
                report_dir / f"{stem}_report.json",
            ]
            for c in candidates:
                if c.is_file():
                    report_path = str(c)
                    break

        report = await compare_apk(
            apk_path,
            is_priv_app=is_priv_app,
            is_platform_signed=is_platform_signed,
            mobsf_url=mobsf_url,
            mobsf_key=mobsf_key,
            mobsf_report=report_path,
        )
        reports.append(report)

    return reports


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_json(reports: list[ComparisonReport]) -> str:
    """Format comparison reports as pretty-printed JSON."""
    if len(reports) == 1:
        return json.dumps(reports[0].to_dict(), indent=2, ensure_ascii=False)

    batch = {
        "batch": True,
        "apk_count": len(reports),
        "timestamp": datetime.now(UTC).isoformat(),
        "reports": [r.to_dict() for r in reports],
        "aggregate": _compute_aggregate(reports),
    }
    return json.dumps(batch, indent=2, ensure_ascii=False)


def format_summary(reports: list[ComparisonReport]) -> str:
    """Format a human-readable summary table."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("APK Manifest Security Scan Comparison: Wairz vs MobSF")
    lines.append("=" * 72)

    for r in reports:
        lines.append("")
        lines.append(f"APK: {r.apk_path}")
        lines.append(f"Package: {r.package_name}")
        lines.append(f"Hash: {r.apk_hash[:16]}..." if r.apk_hash else "Hash: N/A")
        if r.is_priv_app or r.is_platform_signed:
            ctx_parts: list[str] = []
            if r.is_priv_app:
                ctx_parts.append("priv-app")
            if r.is_platform_signed:
                ctx_parts.append("platform-signed")
            lines.append(f"Firmware context: {', '.join(ctx_parts)}")
        lines.append("-" * 72)

        # Runner status
        w_status = "OK" if r.wairz_success else f"FAIL: {r.wairz_error}"
        m_status = "OK" if r.mobsf_success else f"FAIL: {r.mobsf_error}"
        lines.append(f"  Wairz:  {r.wairz_total} findings in {r.wairz_duration_ms}ms [{w_status}]")
        lines.append(f"  MobSF:  {r.mobsf_total} findings in {r.mobsf_duration_ms}ms [{m_status}]")
        lines.append("")

        # Matches
        if r.matches:
            lines.append(f"  MATCHES ({len(r.matches)}):")
            for m in r.matches:
                sev_note = "" if m.severity_match else f" [severity: wairz={m.wairz_severity} vs mobsf={m.mobsf_severity}]"
                lines.append(f"    {m.check_id}: {m.wairz_title}{sev_note}")

        # Misses (gaps)
        if r.misses:
            lines.append(f"  MISSES ({len(r.misses)}) — MobSF-only gaps:")
            for m in r.misses:
                lines.append(f"    {m.check_id}: {m.mobsf_title} [{m.mobsf_severity}]")

        # Extras (extended coverage)
        if r.extras:
            lines.append(f"  EXTRAS ({len(r.extras)}) — Wairz-only extended coverage:")
            for e in r.extras:
                lines.append(f"    {e.check_id}: {e.wairz_title} [{e.wairz_severity}]")

        lines.append("")
        lines.append(f"  Coverage: {r.coverage_pct}%  |  Severity match: {r.severity_match_pct}%  |  FP rate: {r.false_positive_rate}%")
        lines.append(f"  Verdict: {r._verdict()}")

    if len(reports) > 1:
        agg = _compute_aggregate(reports)
        lines.append("")
        lines.append("=" * 72)
        lines.append("AGGREGATE SUMMARY")
        lines.append(f"  APKs scanned: {agg['apk_count']}")
        lines.append(f"  Total matches: {agg['total_matches']}")
        lines.append(f"  Total misses: {agg['total_misses']}")
        lines.append(f"  Total extras: {agg['total_extras']}")
        lines.append(f"  Avg coverage: {agg['avg_coverage_pct']}%")
        lines.append(f"  Avg severity match: {agg['avg_severity_match_pct']}%")

    lines.append("")
    return "\n".join(lines)


def _compute_aggregate(reports: list[ComparisonReport]) -> dict[str, Any]:
    """Compute aggregate metrics across multiple reports."""
    total_matches = sum(len(r.matches) for r in reports)
    total_misses = sum(len(r.misses) for r in reports)
    total_extras = sum(len(r.extras) for r in reports)

    successful = [r for r in reports if r.wairz_success and r.mobsf_success]
    avg_cov = (
        round(sum(r.coverage_pct for r in successful) / len(successful), 1)
        if successful
        else 0.0
    )
    avg_sev = (
        round(sum(r.severity_match_pct for r in successful) / len(successful), 1)
        if successful
        else 0.0
    )

    return {
        "apk_count": len(reports),
        "successful_scans": len(successful),
        "total_matches": total_matches,
        "total_misses": total_misses,
        "total_extras": total_extras,
        "avg_coverage_pct": avg_cov,
        "avg_severity_match_pct": avg_sev,
    }


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="wairz-compare-apk",
        description=(
            "Compare Wairz APK manifest security scanner against MobSF baseline. "
            "Runs both scanners and produces a side-by-side JSON diff report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Live MobSF comparison\n"
            "  wairz-compare-apk app.apk --mobsf-url http://localhost:8000 --mobsf-key KEY\n"
            "\n"
            "  # Offline comparison from MobSF JSON report\n"
            "  wairz-compare-apk app.apk --mobsf-report mobsf_report.json\n"
            "\n"
            "  # Batch comparison with firmware context\n"
            "  wairz-compare-apk *.apk --mobsf-report-dir ./reports/ --priv-app\n"
        ),
    )

    parser.add_argument(
        "apk_paths",
        nargs="+",
        help="Path(s) to APK file(s) to scan",
    )

    # MobSF source (mutually exclusive: live API or offline report)
    mobsf_group = parser.add_argument_group("MobSF source")
    mobsf_group.add_argument(
        "--mobsf-url",
        help="MobSF REST API base URL (e.g., http://localhost:8000)",
    )
    mobsf_group.add_argument(
        "--mobsf-key",
        help="MobSF REST API key",
    )
    mobsf_group.add_argument(
        "--mobsf-report",
        help="Path to pre-exported MobSF JSON report (single APK mode)",
    )
    mobsf_group.add_argument(
        "--mobsf-report-dir",
        help="Directory of MobSF JSON reports for batch mode (named <stem>.json)",
    )

    # Firmware context
    ctx_group = parser.add_argument_group("firmware context")
    ctx_group.add_argument(
        "--priv-app",
        action="store_true",
        help="APK is from /system/priv-app/ (enables severity bumping)",
    )
    ctx_group.add_argument(
        "--platform-signed",
        action="store_true",
        help="APK is platform-signed (enables severity reduction for eligible checks)",
    )

    # Output
    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--format",
        choices=["json", "summary", "both"],
        default="json",
        help="Output format (default: json)",
    )
    out_group.add_argument(
        "-o", "--output",
        help="Write output to file (default: stdout)",
    )
    out_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point for the comparison harness."""
    # Single APK with explicit --mobsf-report
    if len(args.apk_paths) == 1 and args.mobsf_report:
        reports = [
            await compare_apk(
                args.apk_paths[0],
                is_priv_app=args.priv_app,
                is_platform_signed=args.platform_signed,
                mobsf_url=args.mobsf_url,
                mobsf_key=args.mobsf_key,
                mobsf_report=args.mobsf_report,
            )
        ]
    else:
        reports = await compare_batch(
            args.apk_paths,
            is_priv_app=args.priv_app,
            is_platform_signed=args.platform_signed,
            mobsf_url=args.mobsf_url,
            mobsf_key=args.mobsf_key,
            mobsf_report_dir=args.mobsf_report_dir,
        )

    # Format output
    output_parts: list[str] = []
    if args.format in ("json", "both"):
        output_parts.append(format_json(reports))
    if args.format in ("summary", "both"):
        output_parts.append(format_summary(reports))

    output = "\n".join(output_parts)

    # Write output
    if args.output:
        out_path = Path(args.output)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: out_path.write_text(output, encoding="utf-8"),
        )
        logger.info("Report written to %s", args.output)
    else:
        print(output)

    # Determine exit code
    has_errors = any(not r.wairz_success or not r.mobsf_success for r in reports)
    has_gaps = any(r.misses for r in reports)

    if has_errors:
        return 2
    if has_gaps:
        return 1
    return 0


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        logger.info("Interrupted")
        exit_code = 2
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
