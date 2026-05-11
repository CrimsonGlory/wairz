"""mobsfscan CLI invocation + JSON parsing.

This module is the **low-level runner** layer of the mobsfscan pipeline.
:func:`run_mobsfscan` executes the ``mobsfscan`` CLI against a directory
of decompiled Java/Kotlin sources (typically produced by JADX) and
:func:`_parse_mobsfscan_output` converts the resulting JSON into
:class:`MobsfScanFinding` dataclasses.

Path-level suppression (library/generated code) is applied here during
parse so that raw cached results remain unfiltered — rule-level
suppressions are similarly applied here, and the ``SUPPRESSED_RULES`` /
``SUPPRESSED_PATH_PATTERNS`` sources live in
:mod:`~app.services.mobsfscan.normalization`.

Orchestration (cache lookup, source materialization, persistence) lives
in :mod:`~app.services.mobsfscan.pipeline`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from shutil import which

from app.services.mobsfscan.normalization import (
    SUPPRESSED_RULES,
    _is_suppressed_path,
)

logger = logging.getLogger(__name__)

# Default timeout for mobsfscan execution (seconds).
# Full-app scans typically complete in 30-90s; cap at 180s.
_DEFAULT_TIMEOUT: int = 180


@dataclass(frozen=True, slots=True)
class MobsfScanFinding:
    """A single finding produced by mobsfscan."""

    rule_id: str
    title: str
    description: str
    severity: str  # "ERROR" | "WARNING" | "INFO" from mobsfscan → mapped below
    section: str  # e.g. "code_analysis", "manifest_analysis"
    file_path: str  # relative path within the scanned source tree
    line_number: int  # 1-based; 0 if unavailable
    match_string: str  # the matched code snippet
    cwe: str  # CWE ID string, e.g. "CWE-312"
    owasp_mobile: str  # e.g. "M9: Reverse Engineering"
    masvs: str  # OWASP MASVS reference
    metadata: dict  # raw rule metadata for downstream consumers

    @property
    def normalized_severity(self) -> str:
        """Map mobsfscan severity to Wairz finding severity."""
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "info",
        }
        return mapping.get(self.severity.upper(), "info")


@dataclass(slots=True)
class MobsfScanResult:
    """Aggregated result of a mobsfscan run."""

    success: bool
    findings: list[MobsfScanFinding] = field(default_factory=list)
    raw_json: dict | None = None
    error: str | None = None
    scan_duration_ms: int = 0
    files_scanned: int = 0
    suppressed_rule_count: int = 0
    suppressed_path_count: int = 0

    @property
    def summary(self) -> dict:
        """Return a compact summary suitable for MCP tool output."""
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.normalized_severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "success": self.success,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "files_scanned": self.files_scanned,
            "scan_duration_ms": self.scan_duration_ms,
            "error": self.error,
            "suppressed_rule_count": self.suppressed_rule_count,
            "suppressed_path_count": self.suppressed_path_count,
        }


def _find_mobsfscan() -> str | None:
    """Locate the ``mobsfscan`` binary, checking venv bin path too.

    In Docker with uv/venv, pip-installed CLI tools land in
    ``/app/.venv/bin/`` which may not be on the system PATH.
    """
    return which("mobsfscan") or which("mobsfscan", path="/app/.venv/bin")


def mobsfscan_available() -> bool:
    """Check whether the ``mobsfscan`` binary is available."""
    return _find_mobsfscan() is not None


async def run_mobsfscan(
    source_dir: str,
    *,
    timeout: int | None = None,  # noqa: ASYNC109 — caller-supplied per-scan timeout; falls through to _DEFAULT_TIMEOUT
) -> MobsfScanResult:
    """Execute ``mobsfscan`` against *source_dir* and return parsed results.

    Parameters
    ----------
    source_dir:
        Absolute path to the directory containing decompiled Java/Kotlin
        sources (typically produced by JADX).
    timeout:
        Maximum seconds to wait for the scan to complete.  Defaults to
        ``_DEFAULT_TIMEOUT`` (180 s).

    Returns
    -------
    MobsfScanResult
        Parsed scan results with individual findings and metadata.

    Raises
    ------
    FileNotFoundError
        If *source_dir* does not exist or is not a directory.
    RuntimeError
        If the ``mobsfscan`` binary is not found on PATH.
    """
    effective_timeout = timeout or _DEFAULT_TIMEOUT

    # ------- pre-flight checks -------
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isdir, source_dir):
        raise FileNotFoundError(
            f"Source directory does not exist or is not a directory: {source_dir}"
        )

    mobsfscan_bin = _find_mobsfscan()
    if mobsfscan_bin is None:
        raise RuntimeError(
            "mobsfscan binary not found on PATH. "
            "Install with: pip install mobsfscan"
        )

    # ------- build command -------
    cmd: list[str] = [
        mobsfscan_bin,
        "--json",          # JSON output
        "--no-fail",       # don't exit non-zero when findings are present
        source_dir,
    ]

    logger.info(
        "Running mobsfscan on %s (timeout=%ds)", source_dir, effective_timeout,
    )

    t0 = time.monotonic()

    # Ensure venv bin is on PATH so mobsfscan can find semgrep
    # (mobsfscan spawns semgrep as a subprocess internally)
    env = os.environ.copy()
    venv_bin = "/app/.venv/bin"
    if venv_bin not in env.get("PATH", ""):
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=effective_timeout,
        )
    except TimeoutError:
        # Kill the process tree on timeout
        try:
            process.kill()  # type: ignore[possibly-undefined]
            await process.wait()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mobsfscan timed out after %ds on %s", effective_timeout, source_dir,
        )
        return MobsfScanResult(
            success=False,
            error=f"mobsfscan timed out after {effective_timeout}s",
            scan_duration_ms=elapsed_ms,
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    stdout_text = stdout_bytes.decode(errors="replace")
    stderr_text = stderr_bytes.decode(errors="replace").strip()

    if stderr_text:
        logger.debug("mobsfscan stderr: %s", stderr_text[:1000])

    # mobsfscan --no-fail returns 0 even when findings exist.
    # A non-zero exit with --no-fail indicates a real error.
    if process.returncode != 0:
        error_msg = stderr_text[:500] if stderr_text else f"exit code {process.returncode}"
        logger.error("mobsfscan failed: %s", error_msg)
        return MobsfScanResult(
            success=False,
            error=f"mobsfscan failed: {error_msg}",
            scan_duration_ms=elapsed_ms,
        )

    # ------- parse JSON output -------
    return _parse_mobsfscan_output(stdout_text, elapsed_ms)


def _parse_mobsfscan_output(
    raw_stdout: str,
    elapsed_ms: int,
) -> MobsfScanResult:
    """Parse mobsfscan JSON output into structured findings.

    mobsfscan JSON schema (v0.3+):
    ```json
    {
      "results": {
        "<rule_id>": {
          "metadata": {
            "description": "...",
            "severity": "ERROR|WARNING|INFO",
            "cwe": "CWE-...",
            "masvs": "...",
            "owasp-mobile": "...",
            "ref": "...",
            "input_case": "exact",
          },
          "files": [
            {
              "file_path": "relative/path.java",
              "match_string": "matched code",
              "match_position": [start, end],
              "match_lines": [start_line, end_line],
            }
          ]
        }
      },
      "errors": []
    }
    ```
    """
    try:
        data = json.loads(raw_stdout)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse mobsfscan JSON output: %s", exc)
        return MobsfScanResult(
            success=False,
            error=f"Failed to parse mobsfscan output: {exc}",
            scan_duration_ms=elapsed_ms,
        )

    findings: list[MobsfScanFinding] = []
    results: dict = data.get("results", {})
    errors: list = data.get("errors", [])

    suppressed_rule_count = 0
    suppressed_path_count = 0

    for rule_id, rule_data in results.items():
        # --- Rule-level suppression ---
        if rule_id in SUPPRESSED_RULES:
            suppressed_rule_count += len(rule_data.get("files", []))
            continue

        metadata = rule_data.get("metadata", {})
        title = metadata.get("description", rule_id)
        description = metadata.get("description", "")
        severity = metadata.get("severity", "INFO")
        cwe = metadata.get("cwe", "")
        owasp_mobile = metadata.get("owasp-mobile", "")
        masvs = metadata.get("masvs", "")
        section = metadata.get("input_case", "code_analysis")

        matched_files = rule_data.get("files", [])
        for file_entry in matched_files:
            file_path = file_entry.get("file_path", "")

            # --- Path-level suppression (library/generated code) ---
            if file_path and _is_suppressed_path(file_path):
                suppressed_path_count += 1
                continue

            match_string = file_entry.get("match_string", "")

            # match_lines is [start, end]; use start
            match_lines = file_entry.get("match_lines", [0, 0])
            line_number = match_lines[0] if match_lines else 0

            findings.append(
                MobsfScanFinding(
                    rule_id=rule_id,
                    title=title,
                    description=description,
                    severity=severity,
                    section=section,
                    file_path=file_path,
                    line_number=line_number,
                    match_string=match_string,
                    cwe=cwe,
                    owasp_mobile=owasp_mobile,
                    masvs=masvs,
                    metadata=metadata,
                )
            )

    if suppressed_rule_count or suppressed_path_count:
        logger.info(
            "mobsfscan suppressions: %d findings from suppressed rules, "
            "%d from suppressed paths",
            suppressed_rule_count,
            suppressed_path_count,
        )

    if errors:
        logger.warning("mobsfscan reported %d errors: %s", len(errors), errors[:3])

    return MobsfScanResult(
        success=True,
        findings=findings,
        raw_json=data,
        scan_duration_ms=elapsed_ms,
        files_scanned=_count_source_files(data),
        suppressed_rule_count=suppressed_rule_count,
        suppressed_path_count=suppressed_path_count,
    )


def _count_source_files(data: dict) -> int:
    """Count unique files referenced in scan results."""
    files: set[str] = set()
    for rule_data in data.get("results", {}).values():
        for file_entry in rule_data.get("files", []):
            fp = file_entry.get("file_path", "")
            if fp:
                files.add(fp)
    return len(files)
