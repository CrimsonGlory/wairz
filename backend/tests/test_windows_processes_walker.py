"""Tests for ``app.services.windows_processes_walker`` (Phase λ.β).

Covers:

- Pure helpers — ``_parse_vol3_datetime``, ``_int_or_none``,
  ``_record_key``, ``_is_suspicious_path``, ``_compute_anomaly_flags``.
- ``_do_windows_processes_walk`` live canary (Rule #35b) — seeds a real
  Firmware + MemoryDumpImage row via ``make_live_db``, mocks the runner
  with the 4 plugin shapes (pslist / psscan / pstree / cmdline),
  asserts the persisted VolatilityProcessRecord rows + the per-firmware
  aggregate.
- Rule #39 outer-wrapper state-machine transitions
  (idle → running → completed) via
  ``run_windows_processes_walk_background``.
- Rule #39 safe-runner graceful path —
  ``auto_windows_processes_walk_firmware_safe`` stamps the aggregate
  without mutating the status.
- Rule #36 + #45 source-scan gate over ``windows_processes_walker.py``
  + Rule #46 canary that confirms the gate fires on a synthetic
  violation.
"""
from __future__ import annotations

import datetime as _dt
import io
import pathlib
import re
import tokenize
import uuid
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select

# Importing the per-record + per-image tables registers their metadata
# on Base.metadata so make_live_db's create_all() materialises them.
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage  # noqa: F401  (registers mapper)
from app.models.project import Project
from app.models.volatility_process_record import VolatilityProcessRecord
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3RunResult,
)
from app.services.windows_processes_walker import (
    _PLUGINS_TO_RUN,
    _WALK_OS_FAMILIES,
    _compute_anomaly_flags,
    _do_windows_processes_walk,
    _int_or_none,
    _is_suspicious_path,
    _parse_vol3_datetime,
    _record_key,
    auto_windows_processes_walk_firmware_safe,
    run_windows_processes_walk_background,
)
from tests._live_db import make_live_db

# ── Pure helpers ─────────────────────────────────────────────────────────────


def test_walk_os_families_includes_windows_and_unknown() -> None:
    assert "windows" in _WALK_OS_FAMILIES
    assert "unknown" in _WALK_OS_FAMILIES
    assert "linux" not in _WALK_OS_FAMILIES
    assert "mac" not in _WALK_OS_FAMILIES


def test_plugins_to_run_is_locked_to_metadata_set() -> None:
    """Per Rule #45, the plugin list is HARD-PINNED to the 4 metadata
    plugins. No credential extraction (windows.hashdump etc.) leaks in."""
    assert _PLUGINS_TO_RUN == (
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
    )
    for forbidden in ("windows.hashdump", "windows.lsadump", "windows.cachedump"):
        assert forbidden not in _PLUGINS_TO_RUN


def test_int_or_none_handles_strings_and_invalid() -> None:
    assert _int_or_none(42) == 42
    assert _int_or_none("42") == 42
    assert _int_or_none("0x10") == 16
    assert _int_or_none("N/A") is None
    assert _int_or_none("") is None
    assert _int_or_none(None) is None
    assert _int_or_none("not a number") is None
    assert _int_or_none(True) is None  # bools rejected


def test_parse_vol3_datetime_iso_z_form() -> None:
    dt = _parse_vol3_datetime("2023-10-15T03:42:11Z")
    assert dt is not None
    assert dt.year == 2023 and dt.month == 10 and dt.day == 15
    assert dt.tzinfo is not None


def test_parse_vol3_datetime_handles_unknown_values() -> None:
    assert _parse_vol3_datetime(None) is None
    assert _parse_vol3_datetime("") is None
    assert _parse_vol3_datetime("N/A") is None
    assert _parse_vol3_datetime("garbage") is None


def test_record_key_essential_fields() -> None:
    """PID + ImageFileName required; CreateTime nullable in the key."""
    rec = {"PID": 1234, "ImageFileName": "svchost.exe"}
    key = _record_key(rec)
    assert key is not None
    assert key[0] == 1234
    assert key[1] == "svchost.exe"
    assert key[2] is None  # no CreateTime → None part of key


def test_record_key_returns_none_when_pid_missing() -> None:
    assert _record_key({"ImageFileName": "x.exe"}) is None
    assert _record_key({"PID": 1, "ImageFileName": ""}) is None
    assert _record_key({"PID": 1}) is None


def test_record_key_with_create_time() -> None:
    rec = {
        "PID": 1234,
        "ImageFileName": "svchost.exe",
        "CreateTime": "2023-10-15T03:42:11Z",
    }
    key = _record_key(rec)
    assert key is not None
    assert isinstance(key[2], _dt.datetime)


def test_is_suspicious_path_microsoft_paths_not_suspicious() -> None:
    assert not _is_suspicious_path(r"C:\Windows\System32\svchost.exe")
    assert not _is_suspicious_path(r"C:\Windows\SysWOW64\svchost.exe")
    assert not _is_suspicious_path(r"c:\windows\system32\lsass.exe")
    assert not _is_suspicious_path(r"\??\C:\Windows\System32\smss.exe")
    assert not _is_suspicious_path(r"C:\Program Files\Notepad++\notepad++.exe")


def test_is_suspicious_path_user_temp_is_suspicious() -> None:
    assert _is_suspicious_path(r"C:\Users\admin\AppData\Local\Temp\evil.exe")
    assert _is_suspicious_path(r"C:\Temp\malware.exe")
    assert _is_suspicious_path(r"C:\Users\Public\Downloads\dropper.exe")
    assert _is_suspicious_path("")  is False  # empty path → not suspicious
    assert _is_suspicious_path(None) is False


def test_compute_anomaly_flags_unlinked_indicator() -> None:
    """psscan-saw + pslist-missed → unlinked=True (T1014 rootkit)."""
    flags = _compute_anomaly_flags(
        seen_pslist=False,
        seen_psscan=True,
        exit_time=None,
        image_path=r"C:\Windows\System32\svchost.exe",
        ppid=4,
        observed_pids={4, 1234},
    )
    assert flags["unlinked"] is True
    assert flags["terminated"] is False
    assert flags["suspicious_path"] is False
    assert flags["schema_version"] == 1


def test_compute_anomaly_flags_terminated_when_exit_time_set() -> None:
    flags = _compute_anomaly_flags(
        seen_pslist=True,
        seen_psscan=True,
        exit_time=_dt.datetime.now(_dt.UTC),
        image_path=r"C:\Windows\System32\notepad.exe",
        ppid=1234,
        observed_pids={1234, 5678},
    )
    assert flags["terminated"] is True
    assert flags["unlinked"] is False


def test_compute_anomaly_flags_orphan_when_ppid_absent() -> None:
    flags = _compute_anomaly_flags(
        seen_pslist=True,
        seen_psscan=False,
        exit_time=None,
        image_path=r"C:\Windows\System32\svchost.exe",
        ppid=99999,
        observed_pids={4, 1234},
    )
    assert flags["orphan"] is True


def test_compute_anomaly_flags_idle_process_not_orphan() -> None:
    """PID 0 with PPID=None gets orphan=False (kernel idle process)."""
    flags = _compute_anomaly_flags(
        seen_pslist=True,
        seen_psscan=False,
        exit_time=None,
        image_path=None,
        ppid=None,
        observed_pids={0, 4, 1234},
    )
    assert flags["orphan"] is False


def test_compute_anomaly_flags_suspicious_path_for_user_temp() -> None:
    flags = _compute_anomaly_flags(
        seen_pslist=True,
        seen_psscan=True,
        exit_time=None,
        image_path=r"C:\Users\admin\AppData\Local\Temp\evil.exe",
        ppid=4,
        observed_pids={4},
    )
    assert flags["suspicious_path"] is True


# ── _do_windows_processes_walk live canary (Rule #35b) ──────────────────────


def _vol3_pslist_record(
    pid: int,
    ppid: int | None,
    name: str,
    create_time: str | None = None,
    exit_time: str | None = None,
) -> dict[str, Any]:
    """Build a synthetic Vol3 ``windows.pslist`` record."""
    rec: dict[str, Any] = {"PID": pid, "ImageFileName": name}
    if ppid is not None:
        rec["PPID"] = ppid
    if create_time:
        rec["CreateTime"] = create_time
    if exit_time:
        rec["ExitTime"] = exit_time
    return rec


def _vol3_cmdline_record(
    pid: int,
    name: str,
    args: str,
    create_time: str | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "PID": pid,
        "ImageFileName": name,
        "Args": args,
    }
    if create_time:
        rec["CreateTime"] = create_time
    return rec


def _fake_run_factory(
    pslist_records: list[dict] | None = None,
    psscan_records: list[dict] | None = None,
    pstree_records: list[dict] | None = None,
    cmdline_records: list[dict] | None = None,
):
    """Return a fake run_vol3_plugin that dispatches on plugin name."""
    by_plugin: dict[str, list[dict]] = {
        "windows.pslist": pslist_records or [],
        "windows.psscan": psscan_records or [],
        "windows.pstree": pstree_records or [],
        "windows.cmdline": cmdline_records or [],
    }

    async def fake_run(image_path: str, plugin: str, **_: Any) -> Vol3RunResult:
        return Vol3RunResult(
            plugin=plugin,
            image_path=image_path,
            records=by_plugin.get(plugin, []),
            elapsed_s=1.0,
            exit_code=0,
            stderr_tail="",
        )

    return fake_run


@pytest.mark.asyncio
async def test_do_windows_processes_walk_persists_pslist_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process seen ONLY in pslist gets persisted with seen_in_pslist=True."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="pslist-only")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="img.bin",
            file_size=4096,
            sha256="a" * 64,
        )
        db.add(firmware)
        await db.flush()
        image = MemoryDumpImage(
            firmware_id=firmware.id,
            image_path="/data/mem.raw",
            image_filename="mem.raw",
            file_size=200 * 1024 * 1024,
            magic_detected="MDMP",
            os_family="windows",
        )
        db.add(image)
        await db.flush()

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp/canary"]

        monkeypatch.setattr(
            "app.services.windows_processes_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_processes_walker.run_vol3_plugin",
            _fake_run_factory(
                pslist_records=[
                    _vol3_pslist_record(
                        4, None, "System", "2023-10-15T03:00:00Z"
                    ),
                    _vol3_pslist_record(
                        1234,
                        4,
                        "svchost.exe",
                        "2023-10-15T03:42:11Z",
                    ),
                ],
            ),
        )

        aggregate = await _do_windows_processes_walk(db, firmware.id)
        assert aggregate["image_count"] == 1
        assert aggregate["process_count"] == 2
        assert aggregate["by_plugin_seen"]["pslist"] == 2

        rows = (
            (
                await db.execute(
                    select(VolatilityProcessRecord).where(
                        VolatilityProcessRecord.firmware_id == firmware.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        by_pid = {r.pid: r for r in rows}
        assert by_pid[4].image_filename == "System"
        assert by_pid[4].seen_in_pslist is True
        assert by_pid[4].seen_in_psscan is False
        assert by_pid[1234].image_filename == "svchost.exe"
        assert by_pid[1234].ppid == 4


@pytest.mark.asyncio
async def test_do_windows_processes_walk_detects_unlinked_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """psscan-saw + pslist-missed → row with unlinked=True (T1014)."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="unlinked")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="img.bin",
            file_size=4096,
            sha256="b" * 64,
        )
        db.add(firmware)
        await db.flush()
        image = MemoryDumpImage(
            firmware_id=firmware.id,
            image_path="/data/mem.raw",
            image_filename="mem.raw",
            file_size=200 * 1024 * 1024,
            magic_detected="MDMP",
            os_family="windows",
        )
        db.add(image)
        await db.flush()

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        monkeypatch.setattr(
            "app.services.windows_processes_walker.get_detection_roots",
            fake_roots,
        )

        # Same legitimate process appears in BOTH pslist + psscan;
        # the rootkit-hidden process appears ONLY in psscan.
        ct = "2023-10-15T03:42:11Z"
        monkeypatch.setattr(
            "app.services.windows_processes_walker.run_vol3_plugin",
            _fake_run_factory(
                pslist_records=[
                    _vol3_pslist_record(1234, 4, "svchost.exe", ct),
                ],
                psscan_records=[
                    _vol3_pslist_record(1234, 4, "svchost.exe", ct),
                    _vol3_pslist_record(6666, 4, "rootkit.sys", ct),
                ],
            ),
        )

        aggregate = await _do_windows_processes_walk(db, firmware.id)
        assert aggregate["process_count"] == 2
        # by_anomaly.unlinked counts the de-duped rows that match the
        # T1014 indicator — exactly one (the rootkit.sys row).
        assert aggregate["by_anomaly"]["unlinked"] == 1

        rows = (
            (
                await db.execute(
                    select(VolatilityProcessRecord).where(
                        VolatilityProcessRecord.firmware_id == firmware.id
                    )
                )
            )
            .scalars()
            .all()
        )
        by_pid = {r.pid: r for r in rows}
        assert by_pid[1234].seen_in_pslist is True
        assert by_pid[1234].seen_in_psscan is True
        assert by_pid[6666].seen_in_pslist is False
        assert by_pid[6666].seen_in_psscan is True
        assert by_pid[6666].anomaly_flags["unlinked"] is True


@pytest.mark.asyncio
async def test_do_windows_processes_walk_cmdline_enriches_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """windows.cmdline supplies command_line + image_path_full."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="cmdline")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="img.bin",
            file_size=4096,
            sha256="c" * 64,
        )
        db.add(firmware)
        await db.flush()
        image = MemoryDumpImage(
            firmware_id=firmware.id,
            image_path="/data/mem.raw",
            image_filename="mem.raw",
            file_size=200 * 1024 * 1024,
            magic_detected="MDMP",
            os_family="windows",
        )
        db.add(image)
        await db.flush()

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        monkeypatch.setattr(
            "app.services.windows_processes_walker.get_detection_roots",
            fake_roots,
        )

        ct = "2023-10-15T03:42:11Z"
        monkeypatch.setattr(
            "app.services.windows_processes_walker.run_vol3_plugin",
            _fake_run_factory(
                pslist_records=[
                    _vol3_pslist_record(1234, 4, "svchost.exe", ct),
                ],
                cmdline_records=[
                    _vol3_cmdline_record(
                        1234,
                        "svchost.exe",
                        r'"C:\Windows\System32\svchost.exe" -k netsvcs -p',
                        ct,
                    ),
                ],
            ),
        )

        await _do_windows_processes_walk(db, firmware.id)
        row = (
            (
                await db.execute(
                    select(VolatilityProcessRecord).where(
                        VolatilityProcessRecord.pid == 1234,
                        VolatilityProcessRecord.firmware_id == firmware.id,
                    )
                )
            )
            .scalar_one()
        )
        assert row.command_line is not None
        assert "svchost.exe" in row.command_line
        assert row.image_path_full == r"C:\Windows\System32\svchost.exe"
        assert row.anomaly_flags["suspicious_path"] is False


@pytest.mark.asyncio
async def test_do_windows_processes_walk_aborts_on_vol3_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vol3NotInstalled at the first image aborts and records the gap."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="no-vol3")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="img.bin",
            file_size=4096,
            sha256="d" * 64,
        )
        db.add(firmware)
        await db.flush()
        db.add(
            MemoryDumpImage(
                firmware_id=firmware.id,
                image_path="/data/mem.raw",
                image_filename="mem.raw",
                file_size=200 * 1024 * 1024,
                magic_detected="MDMP",
                os_family="windows",
            )
        )
        await db.flush()

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        call_count = {"n": 0}

        async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
            call_count["n"] += 1
            raise Vol3NotInstalled("INCLUDE_VOL3=1 required")

        monkeypatch.setattr(
            "app.services.windows_processes_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_processes_walker.run_vol3_plugin",
            fake_run,
        )

        aggregate = await _do_windows_processes_walk(db, firmware.id)
        # Only ONE invocation — the loop aborts on Vol3NotInstalled.
        assert call_count["n"] == 1
        assert aggregate["image_count"] == 0
        assert len(aggregate["errors_per_image"]) == 1
        assert "Vol3 not installed" in aggregate["errors_per_image"][0]


@pytest.mark.asyncio
async def test_do_windows_processes_walk_records_per_image_invocation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vol3InvocationFailed on one plugin records the error + continues."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="failure")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="img.bin",
            file_size=4096,
            sha256="e" * 64,
        )
        db.add(firmware)
        await db.flush()
        db.add(
            MemoryDumpImage(
                firmware_id=firmware.id,
                image_path="/data/mem.raw",
                image_filename="mem.raw",
                file_size=200 * 1024 * 1024,
                magic_detected="MDMP",
                os_family="windows",
            )
        )
        await db.flush()

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        async def fake_run(image_path: str, plugin: str, **_: Any) -> Vol3RunResult:
            if plugin == "windows.psscan":
                raise Vol3InvocationFailed("symbol lookup failed")
            return Vol3RunResult(
                plugin=plugin,
                image_path=image_path,
                records=[
                    _vol3_pslist_record(4, None, "System", "2023-10-15T03:00:00Z"),
                ],
                elapsed_s=0.5,
                exit_code=0,
                stderr_tail="",
            )

        monkeypatch.setattr(
            "app.services.windows_processes_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_processes_walker.run_vol3_plugin",
            fake_run,
        )

        aggregate = await _do_windows_processes_walk(db, firmware.id)
        assert aggregate["image_count"] == 1
        # Process count > 0 because the other 3 plugins succeeded.
        assert aggregate["process_count"] >= 1
        # Per-image error recorded for psscan.
        assert any(
            "Vol3InvocationFailed" in err
            for err in aggregate["errors_per_image"]
        )


# ── Rule #39 outer-wrapper state-machine transitions ────────────────────────


@pytest.mark.asyncio
async def test_run_windows_processes_walk_background_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outer wrapper drives idle → running → completed and stamps aggregate."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="outer")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="outer.bin",
            file_size=2048,
            sha256="o" * 64,
        )
        db.add(firmware)
        await db.commit()

        async def fake_inner(db_arg, fw_id):
            return {
                "image_count": 1,
                "process_count": 5,
                "by_plugin_seen": {
                    "pslist": 5,
                    "psscan": 5,
                    "pstree": 5,
                    "cmdline": 5,
                },
                "by_anomaly": {
                    "unlinked": 0,
                    "terminated": 1,
                    "orphan": 0,
                    "suspicious_path": 0,
                },
                "total_elapsed_s": 4.0,
                "errors_per_image": [],
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_processes_walker._do_windows_processes_walk",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.windows_processes_walker.async_session_factory",
            fake_factory,
        )

        await run_windows_processes_walk_background(firmware.id)

        await db.refresh(firmware)
        assert firmware.windows_processes_walk_status == "completed"
        assert firmware.windows_processes_walk_started_at is not None
        assert firmware.windows_processes_walk_finished_at is not None
        assert firmware.windows_processes_walk_error is None
        result = firmware.windows_processes_walk_result
        assert result is not None
        assert result["schema_version"] == 1
        assert result["process_count"] == 5


@pytest.mark.asyncio
async def test_auto_windows_processes_walk_safe_does_not_mutate_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe runner stamps the aggregate but leaves status=idle (Rule #33 .a)."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="safe")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="safe.bin",
            file_size=2048,
            sha256="s" * 64,
        )
        db.add(firmware)
        await db.commit()

        async def fake_inner(db_arg, fw_id):
            return {
                "image_count": 0,
                "process_count": 0,
                "by_plugin_seen": {
                    "pslist": 0, "psscan": 0, "pstree": 0, "cmdline": 0
                },
                "by_anomaly": {
                    "unlinked": 0, "terminated": 0, "orphan": 0,
                    "suspicious_path": 0,
                },
                "total_elapsed_s": 0.0,
                "errors_per_image": [],
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_processes_walker._do_windows_processes_walk",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.windows_processes_walker.async_session_factory",
            fake_factory,
        )

        await auto_windows_processes_walk_firmware_safe(firmware.id)

        await db.refresh(firmware)
        assert firmware.windows_processes_walk_status == "idle"
        assert firmware.windows_processes_walk_result is not None
        assert firmware.windows_processes_walk_result["schema_version"] == 1


# ── Rule #36 + #45 source-scan gate + Rule #46 canary ────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Strip docstrings / comments so the gate scans CODE tokens only."""
    out_tokens: list[str] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return source
    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


_FORBIDDEN_CANARY = "decrypt"

# Whitespace-tolerant per κ.D Rule #46 fix.
_FORBIDDEN_DECRYPT_TOKENS: tuple[str, ...] = (
    r"\.\s*decrypt\s*\(",
    r"\bCryptUnprotectData\b",
    r"\bCryptProtectData\b",
    r"from\s+cryptography\s*\.\s*fernet",
    r"\bpyDes\b",
    r"from\s+Crypto\s*\.\s*Cipher",
)

_FORBIDDEN_SPAWN_TOKENS: tuple[str, ...] = (
    r"subprocess\s*\.\s*\(run\|Popen\|call\|check_output\|check_call\)",
    r"asyncio\s*\.\s*create_subprocess_shell\s*\(",
    r"os\s*\.\s*system\s*\(",
    r"os\s*\.\s*execvp\s*\(",
    r"\beval\s*\(",
)


def _walker_source() -> str:
    return (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "windows_processes_walker.py"
    ).read_text()


def test_walker_no_forbidden_spawn_primitives() -> None:
    """Rule #36 — the walker MUST NOT shell out directly."""
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_SPAWN_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in windows_processes_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must only "
            "invoke Vol3 via the run_vol3_plugin helper."
        )


def test_walker_no_decrypt_invocation() -> None:
    """Rule #45 — the walker MUST contain no decrypt invocation."""
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 violation in windows_processes_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must NEVER decrypt."
        )


def test_walker_source_scan_gate_canary_fires() -> None:
    """Rule #46 — confirm the gate actually fires on a synthetic violation.

    The synthetic source uses CODE-token concatenation (NOT f-string
    interpolation) so the violation survives docstring/comment stripping.
    Mirrors κ.D's whitespace-tolerant regex canary.
    """
    line_a = "def bad_walker():\n"
    line_b = "    obj = SomeClass()\n"
    line_c = "    obj." + _FORBIDDEN_CANARY + '(b"x")\n'
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d
    stripped = _strip_docstrings_and_comments(synthetic_source)

    pattern = r"\.\s*decrypt\s*\("
    assert re.findall(pattern, stripped), (
        f"Rule #46 canary FAILED — synthetic violation "
        f"'{_FORBIDDEN_CANARY}' did NOT match the source-scan regex "
        f"{pattern!r}. stripped={stripped!r}."
    )


def test_walker_source_scan_gate_excludes_docstring_mentions() -> None:
    """Docstring mentions of forbidden tokens DO NOT trigger the gate."""
    synthetic_docstring_source = '''
def safe_walker():
    """This walker NEVER invokes CryptUnprotectData and NEVER tries to
    decrypt anything — pure metadata."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)
    assert not re.findall(r"\bCryptUnprotectData\b", stripped)


# Unused-import suppression for `patch` (kept for parity with siblings).
_ = patch
