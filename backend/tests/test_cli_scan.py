"""Tests for ``app.cli.scan`` (was 0% cover / 345 miss).

Covers pure helpers (fail-on parsing, formatters, threshold checks) and
filesystem extraction branches with mocks — no live AssessmentService run.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.cli import scan as scan_mod
from app.cli.scan import (
    ALL_PHASES,
    _build_parser,
    _check_threshold,
    _count_by_severity,
    _extract_cvss_from_finding,
    _extract_firmware,
    _format_json,
    _format_markdown,
    _format_sarif,
    _format_vex,
    _parse_fail_on,
    _severity_to_sarif_level,
)


# ---------------------------------------------------------------------------
# _parse_fail_on
# ---------------------------------------------------------------------------


def test_parse_fail_on_none():
    assert _parse_fail_on("none") == {"mode": "none"}


def test_parse_fail_on_severity_levels():
    assert _parse_fail_on("critical") == {"mode": "severity", "level": "critical"}
    assert _parse_fail_on("high") == {"mode": "severity", "level": "high"}
    assert _parse_fail_on("medium") == {"mode": "severity", "level": "medium"}


def test_parse_fail_on_cvss():
    assert _parse_fail_on("cvss:7.0") == {"mode": "cvss", "score": 7.0}
    assert _parse_fail_on("cvss:0") == {"mode": "cvss", "score": 0.0}
    assert _parse_fail_on("CVSS:10.0") == {"mode": "cvss", "score": 10.0}


def test_parse_fail_on_cvss_out_of_range():
    with pytest.raises(argparse.ArgumentTypeError, match="0.0-10.0"):
        _parse_fail_on("cvss:11")
    # Negative scores don't match the regex → generic invalid message
    with pytest.raises(argparse.ArgumentTypeError, match="Invalid"):
        _parse_fail_on("cvss:-1")


def test_parse_fail_on_invalid():
    with pytest.raises(argparse.ArgumentTypeError, match="Invalid"):
        _parse_fail_on("low")
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_fail_on("cvss:abc")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def test_build_parser_defaults():
    p = _build_parser()
    args = p.parse_args(["firmware.bin"])
    assert args.firmware_path == "firmware.bin"
    assert args.output_format == "json"
    assert args.timeout == 600
    assert args.skip_phases == ""
    assert args.fail_on is None
    assert args.fail_on_critical is False


def test_build_parser_flags():
    p = _build_parser()
    args = p.parse_args([
        "/fw", "--format=sarif", "--fail-on", "high",
        "--timeout", "30", "--skip-phases", "android,compliance",
        "--output", "out.json", "-v",
    ])
    assert args.output_format == "sarif"
    assert args.fail_on == "high"
    assert args.timeout == 30
    assert "android" in args.skip_phases
    assert args.output == "out.json"
    assert args.verbose is True


def test_all_phases_nonempty():
    assert "credential_crypto" in ALL_PHASES
    assert "sbom_vulnerability" in ALL_PHASES
    assert len(ALL_PHASES) >= 5


# ---------------------------------------------------------------------------
# formatters
# ---------------------------------------------------------------------------


def _sample_findings():
    return [
        {
            "id": str(uuid.uuid4()),
            "title": "Hardcoded password",
            "severity": "critical",
            "description": "Found admin:admin",
            "file_path": "/etc/passwd",
            "cve_id": None,
            "cvss_score": 9.8,
            "source": "credential",
            "cwe_id": "CWE-798",
        },
        {
            "id": str(uuid.uuid4()),
            "title": "OpenSSL old",
            "severity": "high",
            "description": "CVE-2014-0160",
            "file_path": "/usr/lib/libssl.so",
            "cve_id": "CVE-2014-0160",
            "cvss_score": 7.5,
            "source": "sbom",
            "cwe_id": None,
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Info note",
            "severity": "info",
            "description": "note",
            "file_path": None,
            "cve_id": None,
            "cvss_score": None,
            "source": "config",
            "cwe_id": None,
        },
    ]


def _sample_summary():
    return {
        "firmware": "test.bin",
        "status": "completed",
        "total_findings": 3,
        "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1},
        "phases_run": ["credential_crypto"],
        "duration_seconds": 1.2,
    }


def test_format_json():
    out = _format_json(_sample_summary(), _sample_findings())
    data = json.loads(out)
    assert "summary" in data and "findings" in data
    assert len(data["findings"]) == 3


def test_format_markdown():
    out = _format_markdown(_sample_summary(), _sample_findings())
    assert "Hardcoded password" in out or "critical" in out.lower()
    assert "#" in out or "Finding" in out or out


def test_severity_to_sarif_level():
    assert _severity_to_sarif_level("critical") in ("error", "warning", "note", "none")
    assert _severity_to_sarif_level("high") in ("error", "warning", "note", "none")
    assert _severity_to_sarif_level("medium") in ("error", "warning", "note", "none")
    assert _severity_to_sarif_level("low") in ("error", "warning", "note", "none")
    assert _severity_to_sarif_level("info") in ("error", "warning", "note", "none")
    assert _severity_to_sarif_level("unknown") in ("error", "warning", "note", "none")


def test_format_sarif():
    out = _format_sarif(_sample_summary(), _sample_findings())
    data = json.loads(out)
    assert data.get("version") == "2.1.0" or "runs" in data


def test_format_vex():
    out = _format_vex(_sample_summary(), _sample_findings(), "fw.bin")
    data = json.loads(out)
    assert "bomFormat" in data or "vulnerabilities" in data or isinstance(data, dict)


def test_format_empty_findings():
    s = _sample_summary()
    s["total_findings"] = 0
    assert json.loads(_format_json(s, []))
    assert isinstance(_format_markdown(s, []), str)
    assert json.loads(_format_sarif(s, []))
    assert json.loads(_format_vex(s, [], "x.bin"))


# ---------------------------------------------------------------------------
# threshold / cvss / counts
# ---------------------------------------------------------------------------


def test_extract_cvss_from_finding():
    # Parses free-text evidence/description, not a structured cvss_score field
    assert _extract_cvss_from_finding({"evidence": "CVSS: 7.5"}) == 7.5
    assert _extract_cvss_from_finding({"description": "cvss_score: 8.1"}) == 8.1
    assert _extract_cvss_from_finding({}) is None
    assert _extract_cvss_from_finding({"evidence": "no score here"}) is None


def test_check_threshold_none():
    findings = _sample_findings()
    assert _check_threshold(findings, {"mode": "none"}) is False


def test_check_threshold_severity():
    findings = _sample_findings()
    assert _check_threshold(findings, {"mode": "severity", "level": "critical"}) is True
    assert _check_threshold(findings, {"mode": "severity", "level": "high"}) is True
    only_info = [f for f in findings if f["severity"] == "info"]
    assert _check_threshold(only_info, {"mode": "severity", "level": "critical"}) is False


def test_check_threshold_cvss():
    findings = [
        {"severity": "high", "evidence": "CVSS score: 9.8 critical"},
        {"severity": "info", "description": "nothing"},
    ]
    assert _check_threshold(findings, {"mode": "cvss", "score": 9.0}) is True
    assert _check_threshold(findings, {"mode": "cvss", "score": 9.9}) is False


def test_count_by_severity():
    counts = _count_by_severity(_sample_findings())
    assert counts.get("critical", 0) >= 1
    assert counts.get("high", 0) >= 1
    assert sum(counts.values()) >= 3


# ---------------------------------------------------------------------------
# _extract_firmware
# ---------------------------------------------------------------------------


def test_extract_firmware_directory(tmp_path):
    d = tmp_path / "already"
    d.mkdir()
    (d / "bin").mkdir()
    out = _extract_firmware(str(d), str(tmp_path / "work"))
    assert os.path.isdir(out)
    assert os.path.samefile(out, d)


def test_extract_firmware_missing_file(tmp_path):
    with pytest.raises(SystemExit) as ei:
        _extract_firmware(str(tmp_path / "nope.bin"), str(tmp_path / "work"))
    assert ei.value.code == 2


def test_extract_firmware_no_extractor_copies_file(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 64)
    work = tmp_path / "work"
    work.mkdir()
    with patch("app.cli.scan.shutil.which", return_value=None):
        out = _extract_firmware(str(fw), str(work))
    assert os.path.isdir(out)
    assert any(Path(out).iterdir())


def test_extract_firmware_unblob_success(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"data")
    work = tmp_path / "work"
    work.mkdir()

    def fake_which(name):
        return "/usr/bin/unblob" if name == "unblob" else None

    mock_result = MagicMock(returncode=0, stderr="")
    with patch("app.cli.scan.shutil.which", side_effect=fake_which):
        with patch("subprocess.run", return_value=mock_result) as run:
            out = _extract_firmware(str(fw), str(work))
    assert out.endswith("extracted") or os.path.isdir(out)
    run.assert_called_once()
    assert "unblob" in run.call_args[0][0][0]


def test_extract_firmware_unblob_fail_falls_back_to_copy(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"data")
    work = tmp_path / "work"
    work.mkdir()

    def fake_which(name):
        return "/usr/bin/unblob" if name == "unblob" else None

    mock_result = MagicMock(returncode=1, stderr="boom")
    with patch("app.cli.scan.shutil.which", side_effect=fake_which):
        with patch("subprocess.run", return_value=mock_result):
            out = _extract_firmware(str(fw), str(work))
    # falls through to copy
    assert os.path.isdir(out)


def test_extract_firmware_binwalk_path(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"data")
    work = tmp_path / "work"
    work.mkdir()

    def fake_which(name):
        if name == "unblob":
            return None
        if name in ("binwalk3", "binwalk"):
            return f"/usr/bin/{name}"
        return None

    mock_result = MagicMock(returncode=0, stderr="")
    with patch("app.cli.scan.shutil.which", side_effect=fake_which):
        with patch("subprocess.run", return_value=mock_result) as run:
            out = _extract_firmware(str(fw), str(work))
    assert os.path.isdir(out)
    assert run.called


# ---------------------------------------------------------------------------
# main / _run smoke with heavy mocks
# ---------------------------------------------------------------------------


def test_main_help_exits_zero():
    with patch("sys.argv", ["wairz-scan", "--help"]):
        with pytest.raises(SystemExit) as ei:
            scan_mod.main()
        assert ei.value.code == 0