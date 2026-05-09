"""Optional third-party scanner integrations.

Extracted from security_audit_service.py as step 5/8 of the Phase 5 split.
Each scanner silently no-ops when its host binary is not installed, so
these can ship on systems without the full toolchain.

- ``_run_external_scanner`` + ``_parse_external_finding``: shared runner
  / JSONL parser used by TruffleHog and Nosey Parker.
- ``_scan_trufflehog``: filesystem secrets scan (TruffleHog v3 CLI).
- ``_scan_noseyparker``: filesystem secrets scan via Nosey Parker's
  two-phase scan + report workflow.
- ``_scan_shellcheck``: shell-script linting focused on command
  injection (SC2086, SC2091, SC2046).
- ``_scan_bandit``: Python static analysis (falls back to
  ``/app/.venv/bin/bandit`` when not on PATH, matching the in-container
  install).
"""

import logging
import os

from app.services.security_audit._base import (
    MAX_FINDINGS_PER_CHECK,
    SecurityFinding,
    _rel,
)

logger = logging.getLogger(__name__)


def _run_external_scanner(
    cmd: list[str],
    scanner_name: str,
    root: str,
    findings: list[SecurityFinding],
) -> None:
    """Run an external secrets scanner and merge JSON results into findings."""
    import json
    import subprocess
    from shutil import which

    binary = cmd[0]
    if not which(binary):
        logger.debug("%s not installed — skipping", scanner_name)
        return

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
            text=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning("%s timed out after 300s on %s", scanner_name, root)
        return
    except OSError as e:
        logger.warning("%s execution failed: %s", scanner_name, e)
        return

    if not proc.stdout.strip():
        return

    # Parse JSON output (each tool has different format)
    for line in proc.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = _parse_external_finding(obj, scanner_name, root)
        if finding:
            findings.append(finding)
            if len(findings) >= MAX_FINDINGS_PER_CHECK:
                break


def _parse_external_finding(
    obj: dict, scanner_name: str, root: str
) -> SecurityFinding | None:
    """Parse a single JSON result from TruffleHog or Nosey Parker."""
    if scanner_name == "trufflehog":
        detector = obj.get("DetectorName", obj.get("detectorName", "unknown"))
        verified = obj.get("Verified", obj.get("verified", False))
        raw = obj.get("Raw", obj.get("raw", ""))
        source_meta = obj.get("SourceMetadata", obj.get("sourceMetadata", {}))
        file_path = None
        line_number = None
        if source_meta:
            data = source_meta.get("Data", source_meta.get("data", {}))
            fs = data.get("Filesystem", data.get("filesystem", {}))
            file_path = fs.get("file", None)
            line_number = fs.get("line", None)
            if file_path and root:
                file_path = "/" + os.path.relpath(file_path, root) if file_path.startswith(root) else file_path
        severity = "critical" if verified else "high"
        return SecurityFinding(
            title=f"[TruffleHog] {detector}" + (" (verified)" if verified else ""),
            severity=severity,
            description=f"Detected by TruffleHog detector: {detector}. "
                        + ("Credential verified as active." if verified else "Unverified match."),
            evidence=raw[:200] if raw else None,
            file_path=file_path,
            line_number=int(line_number) if line_number else None,
            cwe_ids=["CWE-798"],
        )
    elif scanner_name == "noseyparker":
        rule = obj.get("rule_name", "unknown")
        matches = obj.get("matches", [])
        if not matches:
            return None
        match = matches[0]
        snippet = match.get("snippet", {})
        matching = snippet.get("matching", "")
        provenance = match.get("provenance", [{}])
        file_path = provenance[0].get("path") if provenance else None
        if file_path and root:
            file_path = "/" + os.path.relpath(file_path, root) if file_path.startswith(root) else file_path
        location = match.get("location", {}).get("source_span", {})
        line_num = location.get("start", {}).get("line")
        return SecurityFinding(
            title=f"[NoseyParker] {rule}",
            severity="high",
            description=f"Detected by Nosey Parker rule: {rule}",
            evidence=matching[:200] if matching else None,
            file_path=file_path,
            line_number=line_num,
            cwe_ids=["CWE-798"],
        )
    return None


def _scan_trufflehog(root: str, findings: list[SecurityFinding]) -> None:
    """Run TruffleHog filesystem scan if installed."""
    _run_external_scanner(
        ["trufflehog", "filesystem", root, "--json", "--no-update",
         "--force-skip-binaries", "--force-skip-archives"],
        "trufflehog", root, findings,
    )


def _scan_noseyparker(root: str, findings: list[SecurityFinding]) -> None:
    """Run Nosey Parker filesystem scan if installed.

    NP requires two steps: scan (writes to datastore) then report (reads findings).
    """
    import json
    import subprocess
    import tempfile
    from shutil import rmtree, which

    if not which("noseyparker"):
        logger.debug("noseyparker not installed — skipping")
        return

    datastore = tempfile.mkdtemp(prefix="np-")
    try:
        # Step 1: Scan into datastore
        try:
            subprocess.run(
                ["noseyparker", "scan", "--datastore", datastore, root],
                capture_output=True, timeout=300, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("noseyparker scan failed: %s", e)
            return

        # Step 2: Report as JSONL
        try:
            proc = subprocess.run(
                ["noseyparker", "report", "--datastore", datastore,
                 "--format", "jsonl"],
                capture_output=True, timeout=60, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("noseyparker report failed: %s", e)
            return

        if not proc.stdout.strip():
            return

        for line in proc.stdout.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = _parse_external_finding(obj, "noseyparker", root)
            if finding:
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS_PER_CHECK:
                    break
    finally:
        rmtree(datastore, ignore_errors=True)


def _scan_shellcheck(root: str, findings: list[SecurityFinding]) -> None:
    """Run ShellCheck on shell scripts found in the firmware."""
    import json
    import subprocess
    from shutil import which

    if not which("shellcheck"):
        logger.debug("shellcheck not installed — skipping")
        return

    # Discover shell scripts
    shell_extensions = {".sh", ".ash"}
    shebang_patterns = {b"/bin/sh", b"/bin/bash", b"/bin/ash", b"/usr/bin/env sh", b"/usr/bin/env bash"}
    script_dirs = {"etc/init.d", "www/cgi-bin"}

    scripts: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        if len(scripts) >= 100:
            break
        rel_dir = os.path.relpath(dirpath, root)
        in_script_dir = any(
            rel_dir == sd or rel_dir.startswith(sd + os.sep) for sd in script_dirs
        )
        for name in files:
            if len(scripts) >= 100:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            _, ext = os.path.splitext(name.lower())
            if ext in shell_extensions or in_script_dir:
                scripts.append(abs_path)
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            scripts.append(abs_path)
            except OSError:
                continue

    if not scripts:
        return

    # Security-relevant SC codes mapped to CWEs
    sc_cwe_map = {
        2086: ("CWE-78", "Unquoted variable — command injection"),
        2091: ("CWE-78", "Command substitution used as condition"),
        2046: ("CWE-78", "Unquoted $(…) — word splitting"),
    }

    count = 0
    for script_path in scripts:
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        try:
            proc = subprocess.run(
                ["shellcheck", "-f", "json1", "-S", "warning", "-s", "sh", script_path],
                capture_output=True, timeout=30, text=True,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not proc.stdout:
            continue

        try:
            data = json.loads(proc.stdout)
            comments = data.get("comments", [])
        except json.JSONDecodeError:
            continue

        for c in comments:
            sc_code = c.get("code", 0)
            if sc_code not in sc_cwe_map:
                continue
            if count >= MAX_FINDINGS_PER_CHECK:
                break
            cwe_id, desc = sc_cwe_map[sc_code]
            level = c.get("level", "warning")
            severity_map = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
            rel_path = _rel(script_path, root)
            findings.append(SecurityFinding(
                title=f"SC{sc_code}: {desc} in {os.path.basename(script_path)}",
                severity=severity_map.get(level, "medium"),
                description=f"ShellCheck SC{sc_code}: {c.get('message', '')}",
                evidence=None,
                file_path=rel_path,
                line_number=c.get("line"),
                cwe_ids=[cwe_id],
            ))
            count += 1


def _scan_bandit(root: str, findings: list[SecurityFinding]) -> None:
    """Run Bandit on Python scripts found in the firmware."""
    import json
    import subprocess
    from shutil import which

    bandit_bin = which("bandit") or which("bandit", path="/app/.venv/bin")
    if not bandit_bin:
        logger.debug("bandit not installed — skipping")
        return

    # Discover Python scripts
    py_extensions = {".py", ".pyw"}
    shebang_patterns = {b"/usr/bin/python", b"/usr/bin/env python", b"/usr/bin/python3", b"/usr/bin/env python3"}

    scripts: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        if len(scripts) >= 100:
            break
        for name in files:
            if len(scripts) >= 100:
                break
            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            _, ext = os.path.splitext(name.lower())
            if ext in py_extensions:
                scripts.append(abs_path)
                continue
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(2)
                    if header == b"#!":
                        first_line = (header + f.readline(256)).strip()
                        if any(pat in first_line for pat in shebang_patterns):
                            scripts.append(abs_path)
            except OSError:
                continue

    if not scripts:
        return

    try:
        proc = subprocess.run(
            [bandit_bin, "-f", "json", "-ll", "-ii"] + scripts,
            capture_output=True, timeout=60, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("bandit execution failed: %s", e)
        return

    if not proc.stdout:
        return

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return

    results = data.get("results", [])
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    count = 0

    for r in results:
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        test_id = r.get("test_id", "?")
        test_name = r.get("test_name", "unknown")
        issue_text = r.get("issue_text", "")
        file_path = r.get("filename", "")
        line_num = r.get("line_number")
        sev = r.get("issue_severity", "MEDIUM")
        issue_cwe = r.get("issue_cwe", {})
        cwe_id = f"CWE-{issue_cwe['id']}" if issue_cwe.get("id") else None

        if file_path.startswith(root):
            file_path = _rel(file_path, root)

        findings.append(SecurityFinding(
            title=f"[Bandit {test_id}] {test_name}: {issue_text[:80]}",
            severity=severity_map.get(sev, "medium"),
            description=f"Bandit {test_id} ({test_name}): {issue_text}",
            file_path=file_path,
            line_number=line_num,
            cwe_ids=[cwe_id] if cwe_id else None,
        ))
        count += 1
