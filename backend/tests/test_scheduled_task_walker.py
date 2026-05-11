"""Tier-1 tests for the Scheduled Task XML walker (Phase η.B.C).

Per Rule #39 / Rule #35b: tests target the INNER runner
(_do_scheduled_task_run) with a make_live_db()-provided session — never
the OUTER runner (run_scheduled_task_walk_background) which would
attempt async_session_factory() and fail with socket.gaierror on the
dev host.
"""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsScheduledTask
from app.services.jsonb_normalizers import (
    _normalize_windows_scheduled_tasks_actions,
)
from app.services.scheduled_task_walker import (
    _do_scheduled_task_run,
    is_action_encoded_powershell,
    is_defusedxml_available,
    is_system_author,
    parse_scheduled_task_xml,
    walk_scheduled_task_files,
)
from tests._live_db import make_live_db

# ── Fixtures ─────────────────────────────────────────────────────────────────

# 3-task synthetic XML fixtures per intake D2 (RunOnce / On Logon /
# encoded-PowerShell Qakbot pattern). Inline here so tests are
# self-contained.

_WINSAT_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2019-09-15T22:35:08</Date>
    <Author>Microsoft Corporation</Author>
    <URI>\\Microsoft\\Windows\\Maintenance\\WinSAT</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2009-04-08T19:30:00</StartBoundary>
      <ScheduleByWeek>
        <DaysOfWeek><Sunday/></DaysOfWeek>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="S-1-5-19">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>S-1-5-19</UserId>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="S-1-5-19">
    <Exec>
      <Command>%windir%\\system32\\WinSAT.exe</Command>
      <Arguments>formal</Arguments>
    </Exec>
  </Actions>
</Task>
"""

_LOGON_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-15T10:00:00</Date>
    <Author>\\\\HOSTNAME\\enduser</Author>
    <URI>\\OneDriveSync</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1234567890-1234567890-1234567890-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Users\\enduser\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe</Command>
    </Exec>
  </Actions>
</Task>
"""

# Qakbot pattern — encoded-PowerShell action.
_QAKBOT_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-06-01T03:14:15</Date>
    <Author>SuspiciousVendor</Author>
    <URI>\\Updater\\PerformUpdate</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-06-01T03:14:15</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>S-1-5-18</UserId>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAFsAUwBZAFMAVABFAE0ALgBJAEMATwBOAFYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACkAKQA=</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _write_xml(path: Path, content: str) -> None:
    """Write XML content as UTF-16-LE-with-BOM (the canonical Win10/11
    Tasks XML encoding)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Encode to UTF-16-LE with BOM prefix (matching Windows convention).
    path.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    """Centralised Firmware factory."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Probes ───────────────────────────────────────────────────────────────────


def test_is_defusedxml_available_returns_bool():
    """Probe must return a bool — never raise. In the test env it
    should be True (defusedxml is in pyproject.toml)."""
    available = is_defusedxml_available()
    assert isinstance(available, bool)


def test_is_action_encoded_powershell_qakbot_pattern_detected():
    """Encoded-PowerShell pattern detection (Qakbot pattern)."""
    assert is_action_encoded_powershell(
        "powershell.exe",
        "-NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
    )
    assert is_action_encoded_powershell(
        "powershell.exe", "-enc SQBFAFgA"
    )
    assert is_action_encoded_powershell(
        "pwsh", "[System.Convert]::FromBase64String('blah')"
    )
    assert is_action_encoded_powershell(
        "powershell", "Invoke-Expression $payload"
    )


def test_is_action_encoded_powershell_benign_actions_safe():
    """Benign Action shapes (legitimate WinSAT / OneDrive) must NOT
    trigger the encoded-PS heuristic."""
    assert not is_action_encoded_powershell(
        "%windir%\\system32\\WinSAT.exe", "formal"
    )
    assert not is_action_encoded_powershell(
        "C:\\Program Files\\Microsoft Update\\update.exe", None
    )
    assert not is_action_encoded_powershell(None, None)
    assert not is_action_encoded_powershell("", "")


def test_is_system_author_known_microsoft_prefixes():
    """Microsoft system tasks recognised; third-party authors not."""
    assert is_system_author("Microsoft Corporation")
    assert is_system_author("Microsoft Windows")
    assert is_system_author("Microsoft Corp")
    assert not is_system_author("\\\\HOSTNAME\\enduser")
    assert not is_system_author("SuspiciousVendor")
    assert not is_system_author(None)
    assert not is_system_author("")


# ── Walker (filesystem scan) ─────────────────────────────────────────────────


def test_walk_scheduled_task_files_empty_root(tmp_path: Path):
    """Empty root → empty list, no exceptions."""
    assert walk_scheduled_task_files([str(tmp_path)]) == []


def test_walk_scheduled_task_files_finds_tasks_xml(tmp_path: Path):
    """Creates 3 task XMLs in canonical Tasks subtree; all surfaced."""
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    _write_xml(tasks_dir / "WinSAT", _WINSAT_XML)
    _write_xml(tasks_dir / "Microsoft" / "Windows" / "OneDriveSync", _LOGON_XML)
    _write_xml(tasks_dir / "PerformUpdate", _QAKBOT_XML)

    hits = walk_scheduled_task_files([str(tmp_path)])
    assert len(hits) == 3
    names = {os.path.basename(h) for h in hits}
    assert names == {"WinSAT", "OneDriveSync", "PerformUpdate"}


def test_walk_scheduled_task_files_skips_non_tasks_subtrees(
    tmp_path: Path,
):
    """An XML file outside any \\Tasks\\ subtree must NOT be surfaced
    (Tasks live exclusively under \\Windows\\System32\\Tasks\\)."""
    elsewhere = tmp_path / "Windows" / "Configuration"
    _write_xml(elsewhere / "AppX.xml", _WINSAT_XML)

    hits = walk_scheduled_task_files([str(tmp_path)])
    assert hits == []


def test_walk_scheduled_task_files_rejects_escape_symlinks(
    tmp_path: Path,
):
    """A symlink whose realpath escapes the root must be rejected."""
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}"
    outside.mkdir()
    real_xml = outside / "evil"
    _write_xml(real_xml, _QAKBOT_XML)

    inside = tmp_path / "Windows" / "System32" / "Tasks"
    inside.mkdir(parents=True)
    try:
        os.symlink(str(real_xml), str(inside / "evil"))
    except OSError:
        pytest.skip("symlink creation not supported on this filesystem")

    hits = walk_scheduled_task_files([str(tmp_path)])
    assert hits == []  # escape symlink dropped silently
    shutil.rmtree(outside, ignore_errors=True)


# ── Parser (defensive against missing dep + malformed input) ─────────────────


def test_parse_scheduled_task_xml_realistic_winsat(tmp_path: Path):
    """Parse a realistic WinSAT task; verify all extracted fields."""
    path = tmp_path / "WinSAT"
    _write_xml(path, _WINSAT_XML)

    result = parse_scheduled_task_xml(str(path))
    assert result["status"] == "ok"
    data = result["data"]
    assert data["task_uri"] == "\\Microsoft\\Windows\\Maintenance\\WinSAT"
    assert data["author"] == "Microsoft Corporation"
    assert data["registration_date"] is not None
    assert data["run_level"] == "HighestAvailable"
    assert data["run_as_user"] == "S-1-5-19"
    assert len(data["triggers"]) == 1
    assert data["triggers"][0]["type"] == "CalendarTrigger"
    assert data["triggers"][0]["enabled"] is True
    assert len(data["actions"]) == 1
    assert data["actions"][0]["command"] == "%windir%\\system32\\WinSAT.exe"
    assert data["actions"][0]["arguments"] == "formal"
    assert data["principal"]["run_level"] == "HighestAvailable"
    assert data["settings"]["Enabled"] is True
    assert data["settings"]["Hidden"] is True


def test_parse_scheduled_task_xml_qakbot_encoded_powershell(
    tmp_path: Path,
):
    """Parse the Qakbot-pattern encoded-PowerShell task; verify Action
    fields surface for the η.B.D classifier."""
    path = tmp_path / "PerformUpdate"
    _write_xml(path, _QAKBOT_XML)

    result = parse_scheduled_task_xml(str(path))
    assert result["status"] == "ok"
    data = result["data"]
    assert data["author"] == "SuspiciousVendor"
    assert data["run_level"] == "HighestAvailable"
    assert data["actions"][0]["command"] == "powershell.exe"
    # Verify the encoded-PS detection on the parsed action.
    assert is_action_encoded_powershell(
        data["actions"][0]["command"],
        data["actions"][0]["arguments"],
    )


def test_parse_scheduled_task_xml_corrupted_returns_error(
    tmp_path: Path,
):
    """A corrupted XML file must surface a structured error rather
    than crashing."""
    bad = tmp_path / "broken"
    bad.write_bytes(b"\xff\xfe<not-valid-xml")

    result = parse_scheduled_task_xml(str(bad))
    assert result["status"] == "error"
    assert "error" in result
    assert isinstance(result["error"], str)


def test_parse_scheduled_task_xml_missing_file_returns_error(
    tmp_path: Path,
):
    """A non-existent file must surface a structured error."""
    result = parse_scheduled_task_xml(str(tmp_path / "does-not-exist"))
    assert result["status"] == "error"


def test_parse_scheduled_task_xml_oversize_skipped(tmp_path: Path):
    """A file > max_bytes must be skipped (attacker-DoS protection)."""
    huge = tmp_path / "too-big"
    huge.write_bytes(b"<?xml version='1.0'?><Task/>" + b"\x00" * (10 * 1024))

    # Override max_bytes to a tiny value; the file should be skipped.
    result = parse_scheduled_task_xml(str(huge), max_bytes=100)
    assert result["status"] == "skipped"
    assert "reason" in result


def test_parse_scheduled_task_xml_non_task_root_rejected(
    tmp_path: Path,
):
    """An XML file with a non-Task root tag must be rejected."""
    bad = tmp_path / "wrong-root"
    _write_xml(bad, "<?xml version='1.0'?><NotATask/>")

    result = parse_scheduled_task_xml(str(bad))
    assert result["status"] == "error"
    assert "is not 'Task'" in result["error"]


# ── Inner runner — Rule #39 + Rule #35b live canary ──────────────────────────


@pytest.mark.asyncio
async def test_do_scheduled_task_run_no_firmware_returns_empty():
    """If firmware_id doesn't exist, runner returns the empty-walk shape."""
    async with make_live_db() as db:
        result = await _do_scheduled_task_run(db, uuid.uuid4())
        assert result["task_count"] == 0
        assert result["by_status"]["ok"] == 0


@pytest.mark.asyncio
async def test_do_scheduled_task_run_no_detection_roots_returns_empty():
    """If the firmware has no detection roots, runner returns empty."""
    async with make_live_db() as db:
        project = Project(name="η.B.C no-roots canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "no-roots.bin", "n")
        # No extracted_path → no detection roots.
        db.add(firmware)
        await db.commit()

        result = await _do_scheduled_task_run(db, firmware.id)
        assert result["task_count"] == 0


@pytest.mark.asyncio
async def test_do_scheduled_task_run_no_xml_files(tmp_path: Path):
    """If the root has no task XMLs, runner returns empty walk result."""
    async with make_live_db() as db:
        project = Project(name="η.B.C empty-root canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "empty-root.bin", "e")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        result = await _do_scheduled_task_run(db, firmware.id)
        assert result["task_count"] == 0


@pytest.mark.asyncio
async def test_do_scheduled_task_run_persists_three_realistic_tasks(
    tmp_path: Path,
):
    """Place 3 realistic task XMLs (WinSAT / OneDrive / Qakbot pattern);
    runner walks them, parses each, and persists 3 WindowsScheduledTask
    rows. Live canary: SELECT WindowsScheduledTask + verify the encoded-
    PS task surfaced its Action fields, and the aggregate carries the
    expected highest_available_count + encoded_powershell_count."""
    async with make_live_db() as db:
        project = Project(name="η.B.C three-task canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "three-task.bin", "t")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
        _write_xml(tasks_dir / "WinSAT", _WINSAT_XML)
        _write_xml(
            tasks_dir / "Microsoft" / "Windows" / "OneDriveSync",
            _LOGON_XML,
        )
        _write_xml(tasks_dir / "PerformUpdate", _QAKBOT_XML)

        result = await _do_scheduled_task_run(db, firmware.id)

        assert result["task_count"] == 3
        assert result["by_status"]["ok"] == 3
        assert result["by_status"]["error"] == 0
        assert result["unique_authors"] == 3  # MS, HOSTNAME\enduser, Suspicious
        # Two tasks have RunLevel=HighestAvailable (WinSAT + Qakbot).
        assert result["highest_available_count"] == 2
        # One task has the encoded-PS Action shape (Qakbot).
        assert result["encoded_powershell_count"] == 1

        # Live canary: SELECT WindowsScheduledTask rows and verify
        # the persisted shape. Rule #35b — value-flow contract.
        rows = (
            await db.execute(
                select(WindowsScheduledTask).where(
                    WindowsScheduledTask.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3

        names = {r.task_name for r in rows}
        assert names == {"WinSAT", "OneDriveSync", "PerformUpdate"}

        # Verify the Qakbot row has the encoded-PS action persisted via
        # JSONB read through the normalizer.
        qakbot = next(r for r in rows if r.task_name == "PerformUpdate")
        actions = _normalize_windows_scheduled_tasks_actions(qakbot.actions)
        assert len(actions) == 1
        assert actions[0]["command"] == "powershell.exe"
        assert "EncodedCommand" in (actions[0]["arguments"] or "")
        assert qakbot.run_level == "HighestAvailable"
        assert qakbot.author == "SuspiciousVendor"

        # WinSAT row carries the system author.
        winsat = next(r for r in rows if r.task_name == "WinSAT")
        assert winsat.author == "Microsoft Corporation"
        assert winsat.run_level == "HighestAvailable"

        # OneDriveSync — non-system author + LogonTrigger.
        onedrive = next(
            r for r in rows if r.task_name == "OneDriveSync"
        )
        assert onedrive.author and "enduser" in onedrive.author
        # LogonType in principal carried through.
        assert onedrive.principal.get("logon_type") == "InteractiveToken"


@pytest.mark.asyncio
async def test_do_scheduled_task_run_handles_corrupted_alongside_valid(
    tmp_path: Path,
):
    """Mixed corrupted + valid task XMLs — runner persists the valid
    ones and surfaces the corrupted ones in by_status['error']."""
    async with make_live_db() as db:
        project = Project(name="η.B.C mixed canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "mixed.bin", "x")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
        _write_xml(tasks_dir / "WinSAT", _WINSAT_XML)
        # Need >=5 bytes so the head-read tolerance check sees the BOM
        # but the parse still fails. A truncated XML body gives us that.
        bad = tasks_dir / "broken"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_bytes(b"\xff\xfe<not valid xml")

        result = await _do_scheduled_task_run(db, firmware.id)
        # WinSAT parses; broken doesn't.
        assert result["by_status"]["ok"] == 1
        assert result["by_status"]["error"] == 1
        # Persisted rows: 1 (WinSAT only).
        rows = (
            await db.execute(
                select(WindowsScheduledTask).where(
                    WindowsScheduledTask.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].task_name == "WinSAT"
