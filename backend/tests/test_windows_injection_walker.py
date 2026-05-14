"""Tests for ``app.services.windows_injection_walker`` (Phase λ.γ).

Covers:

- Plugin list LOCKED to the ``windows.malware.<X>`` namespace (the
  2026-06-07 deprecation gate — the walker MUST NOT mention any of
  the deprecated top-level path shapes: bare malfind / hollowprocesses
  / ldrmodules / processghosting / psxview directly under windows.*).
- Hexdump canonicalisation + SHA256 helpers.
- Per-plugin record extractors for malfind, hollowprocesses,
  ldrmodules (skips fully-linked rows), processghosting, pebmasquerade.
- ``_do_windows_injection_walk`` live canary (Rule #35b) via
  make_live_db — seeds Firmware + MemoryDumpImage, mocks the runner
  with the 5 plugin shapes, asserts persisted VolatilityInjectionRecord
  rows + the per-firmware aggregate.
- Rule #39 outer-wrapper state-machine transitions.
- Rule #39 safe-runner — stamps aggregate, leaves status=idle.
- Rule #36 + #45 source-scan gate + Rule #46 canary.
- DEPRECATION GATE — the walker source must not mention any
  top-level windows.<deprecated> path.
"""
from __future__ import annotations

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

from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage  # noqa: F401  (registers mapper)
from app.models.project import Project
from app.models.volatility_injection_record import VolatilityInjectionRecord
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3RunResult,
)
from app.services.windows_injection_walker import (
    _PLUGIN_TO_KIND,
    _PLUGINS_TO_RUN,
    _WALK_OS_FAMILIES,
    _canonicalise_hexdump_first_64,
    _do_windows_injection_walk,
    _extract_hollowprocesses_record,
    _extract_ldrmodules_record,
    _extract_malfind_record,
    _extract_pebmasquerade_record,
    _extract_processghosting_record,
    _hexdump_sha256,
    auto_windows_injection_walk_firmware_safe,
    run_windows_injection_walk_background,
)
from tests._live_db import make_live_db


# ── Plugin list locked to windows.malware.<X> (2026-06-07 deprecation) ──────


def test_plugins_pinned_to_windows_malware_namespace() -> None:
    """Hard 2026-06-07 deprecation — the walker MUST NOT wire to the
    deprecated top-level ``windows.<X>`` paths."""
    expected = {
        "windows.malware.malfind.Malfind",
        "windows.malware.hollowprocesses.HollowProcesses",
        "windows.malware.ldrmodules.LdrModules",
        "windows.malware.processghosting.ProcessGhosting",
        "windows.malware.pebmasquerade.PEBMasquerade",
    }
    assert set(_PLUGINS_TO_RUN) == expected
    for plugin in _PLUGINS_TO_RUN:
        assert plugin.startswith("windows.malware."), (
            f"Plugin {plugin!r} does NOT start with windows.malware. — "
            "violates the 2026-06-07 deprecation gate."
        )
    # Plugin → kind map covers every plugin in the list.
    assert set(_PLUGIN_TO_KIND) == set(_PLUGINS_TO_RUN)


def test_walk_os_families_includes_windows_and_unknown() -> None:
    assert "windows" in _WALK_OS_FAMILIES
    assert "unknown" in _WALK_OS_FAMILIES
    assert "linux" not in _WALK_OS_FAMILIES


# ── Hexdump canonicalisation ────────────────────────────────────────────────


def test_canonicalise_hexdump_extracts_first_64_pairs() -> None:
    raw = (
        "00000000 fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b\n"
        "00000010 52 0c 8b 52 14 8b 72 28  0f b7 4a 26 31 ff ac 3c\n"
        "00000020 61 7c 02 2c 20 c1 cf 0d  01 c7 e2 f2 52 57 8b 52\n"
        "00000030 10 8b 4a 3c 8b 4c 11 78  e3 48 01 d1 51 8b 59 20\n"
        "00000040 01 d3 8b 49 18 e3 3a 49  8b 34 8b 01 d6 31 ff ac\n"  # past 64
    )
    canonical = _canonicalise_hexdump_first_64(raw)
    assert canonical is not None
    pairs = canonical.split(" ")
    # Exactly 64 hex pairs.
    assert len(pairs) == 64
    # All lower-case hex.
    for pair in pairs:
        assert re.fullmatch(r"[0-9a-f]{2}", pair), (
            f"non-canonical pair {pair!r}"
        )
    # First pair is fc, second e8, third 82.
    assert pairs[0] == "fc"
    assert pairs[1] == "e8"
    assert pairs[2] == "82"


def test_canonicalise_hexdump_handles_empty_and_none() -> None:
    assert _canonicalise_hexdump_first_64(None) is None
    assert _canonicalise_hexdump_first_64("") is None
    assert _canonicalise_hexdump_first_64("no hex pairs here just ASCII text") is None


def test_hexdump_sha256_is_deterministic() -> None:
    """Same canonical input → same SHA256; different input → different."""
    a = _hexdump_sha256("fc e8 82 00 00 00")
    b = _hexdump_sha256("fc e8 82 00 00 00")
    c = _hexdump_sha256("00 00 00 00 00 00")
    assert a == b
    assert a != c
    assert len(a) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", a)


def test_hexdump_sha256_none_for_none_input() -> None:
    assert _hexdump_sha256(None) is None
    assert _hexdump_sha256("") is None


# ── Per-plugin record extractors ────────────────────────────────────────────


def test_extract_malfind_record_canonical_shape() -> None:
    rec = {
        "PID": 1234,
        "Process": "lsass.exe",
        "Start VPN": 0x10000,
        "End VPN": 0x10010,
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Hexdump": "00000000 fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b",
        "Disasm": "0x10000: cld",
        "PrivateMemory": True,
    }
    fid = uuid.uuid4()
    iid = uuid.uuid4()
    row = _extract_malfind_record(rec, fid, iid)
    assert row is not None
    assert row.detection_kind == "injected_code_region"
    assert row.detected_by_plugin == "windows.malware.malfind.Malfind"
    assert row.pid == 1234
    assert row.image_filename == "lsass.exe"
    assert row.region_address == 0x10000
    assert row.region_size and row.region_size > 0
    assert row.region_protection == "PAGE_EXECUTE_READWRITE"
    assert row.hexdump_first_64_bytes is not None
    assert row.hexdump_sha256 is not None
    assert len(row.hexdump_sha256) == 64
    assert row.evidence["kind"] == "injected_code_region"
    assert row.evidence["protection"] == "PAGE_EXECUTE_READWRITE"


def test_extract_malfind_record_returns_none_for_missing_pid() -> None:
    assert _extract_malfind_record(
        {"Process": "x.exe"}, uuid.uuid4(), uuid.uuid4()
    ) is None


def test_extract_hollowprocesses_record() -> None:
    rec = {
        "PID": 4444,
        "Process": "svchost.exe",
        "PEB ImagePathName": r"C:\Windows\System32\svchost.exe",
        "EPROCESS ImageFileName": "evil.exe",
        "Notes": "PEB path mismatch with EPROCESS",
    }
    row = _extract_hollowprocesses_record(rec, uuid.uuid4(), uuid.uuid4())
    assert row is not None
    assert row.detection_kind == "hollow_process"
    assert row.masquerade_path == r"C:\Windows\System32\svchost.exe"
    assert row.actual_path == "evil.exe"
    assert row.evidence["kind"] == "hollow_process"
    assert row.evidence["divergence_reason"] == "PEB path mismatch with EPROCESS"


def test_extract_ldrmodules_skips_fully_linked() -> None:
    """A module present in InLoad / InInit / InMem is benign — not emitted."""
    rec = {
        "Pid": 1234,
        "Process": "svchost.exe",
        "MappedPath": r"C:\Windows\System32\kernel32.dll",
        "InLoad": True,
        "InInit": True,
        "InMem": True,
    }
    assert _extract_ldrmodules_record(rec, uuid.uuid4(), uuid.uuid4()) is None


def test_extract_ldrmodules_emits_unlinked() -> None:
    """At least one False → row emitted with anomaly_flags reflecting the gap."""
    rec = {
        "Pid": 1234,
        "Process": "svchost.exe",
        "MappedPath": r"C:\Temp\rootkit.dll",
        "InLoad": False,
        "InInit": True,
        "InMem": True,
        "Base": 0x77770000,
        "Size": 0x10000,
    }
    row = _extract_ldrmodules_record(rec, uuid.uuid4(), uuid.uuid4())
    assert row is not None
    assert row.detection_kind == "unlinked_module"
    assert row.module_name == r"C:\Temp\rootkit.dll"
    assert row.region_address == 0x77770000
    assert row.region_size == 0x10000
    assert row.evidence["in_load_order"] is False
    assert row.evidence["in_init_order"] is True
    assert row.evidence["missing_from_lists"] == ["InLoad"]


def test_extract_processghosting_record() -> None:
    rec = {
        "PID": 7777,
        "Process": "ghost.exe",
        "FILE_OBJECT path": r"\Device\HarddiskVolume3\Users\admin\Downloads\dropper.exe",
        "Reason": "PendingDeletion bit set",
    }
    row = _extract_processghosting_record(rec, uuid.uuid4(), uuid.uuid4())
    assert row is not None
    assert row.detection_kind == "ghosted_process"
    assert row.ghosted_path.startswith(r"\Device\HarddiskVolume3")
    assert row.evidence["deletion_reason"] == "PendingDeletion bit set"


def test_extract_pebmasquerade_record() -> None:
    rec = {
        "PID": 8888,
        "Process": "lsass.exe",
        "PEB ImagePathName": r"C:\Windows\System32\winlogon.exe",
        "EPROCESS ImageFileName": "lsass.exe",
        "Image Base Address": 0x140000000,
    }
    row = _extract_pebmasquerade_record(rec, uuid.uuid4(), uuid.uuid4())
    assert row is not None
    assert row.detection_kind == "peb_masquerade"
    assert row.masquerade_path == r"C:\Windows\System32\winlogon.exe"
    assert row.actual_path == "lsass.exe"
    assert row.region_address == 0x140000000


# ── _do_windows_injection_walk live canary (Rule #35b) ──────────────────────


def _fake_run_factory(by_plugin: dict[str, list[dict]]):
    """Return a fake run_vol3_plugin that dispatches on plugin name."""

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


async def _seed_canary(db, sha_seed: str = "a") -> tuple[Project, Firmware, MemoryDumpImage]:
    project = Project(id=uuid.uuid4(), name=f"canary-{sha_seed}")
    db.add(project)
    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        original_filename="img.bin",
        file_size=4096,
        sha256=sha_seed * 64,
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
    return project, firmware, image


@pytest.mark.asyncio
async def test_do_windows_injection_walk_persists_malfind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with make_live_db() as db:
        _, firmware, _ = await _seed_canary(db, "a")

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp/canary"]

        monkeypatch.setattr(
            "app.services.windows_injection_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.run_vol3_plugin",
            _fake_run_factory(
                {
                    "windows.malware.malfind.Malfind": [
                        {
                            "PID": 1234,
                            "Process": "lsass.exe",
                            "Start VPN": 0x10000,
                            "End VPN": 0x10010,
                            "Protection": "PAGE_EXECUTE_READWRITE",
                            "Hexdump": (
                                "00000000 fc e8 82 00 00 00 60 89  "
                                "e5 31 c0 64 8b 50 30 8b\n"
                            ),
                        },
                    ],
                },
            ),
        )

        aggregate = await _do_windows_injection_walk(db, firmware.id)
        assert aggregate["image_count"] == 1
        assert aggregate["detection_count"] == 1
        assert aggregate["by_kind"]["injected_code_region"] == 1
        assert aggregate["unique_hexdump_sha256_count"] == 1

        row = (
            (
                await db.execute(
                    select(VolatilityInjectionRecord).where(
                        VolatilityInjectionRecord.firmware_id == firmware.id
                    )
                )
            )
            .scalar_one()
        )
        assert row.detection_kind == "injected_code_region"
        assert row.detected_by_plugin == "windows.malware.malfind.Malfind"
        assert row.hexdump_sha256 is not None
        assert len(row.hexdump_sha256) == 64


@pytest.mark.asyncio
async def test_do_windows_injection_walk_persists_all_five_kinds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All 5 plugins emitting one detection each → 5 persisted rows + by_kind."""
    async with make_live_db() as db:
        _, firmware, _ = await _seed_canary(db, "b")

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        monkeypatch.setattr(
            "app.services.windows_injection_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.run_vol3_plugin",
            _fake_run_factory(
                {
                    "windows.malware.malfind.Malfind": [
                        {
                            "PID": 1111,
                            "Process": "evil.exe",
                            "Start VPN": 0x10000,
                            "End VPN": 0x10010,
                            "Protection": "PAGE_EXECUTE_READWRITE",
                            "Hexdump": "00000000 fc e8 82 00",
                        },
                    ],
                    "windows.malware.hollowprocesses.HollowProcesses": [
                        {
                            "PID": 2222,
                            "Process": "svchost.exe",
                            "PEB ImagePathName": r"C:\Windows\System32\svchost.exe",
                            "EPROCESS ImageFileName": "evil.exe",
                        },
                    ],
                    "windows.malware.ldrmodules.LdrModules": [
                        {
                            "Pid": 3333,
                            "Process": "lsass.exe",
                            "MappedPath": r"C:\Temp\rootkit.dll",
                            "InLoad": False,
                            "InInit": True,
                            "InMem": True,
                        },
                    ],
                    "windows.malware.processghosting.ProcessGhosting": [
                        {
                            "PID": 4444,
                            "Process": "ghost.exe",
                            "FILE_OBJECT path": r"\Device\Harddisk\file.exe",
                        },
                    ],
                    "windows.malware.pebmasquerade.PEBMasquerade": [
                        {
                            "PID": 5555,
                            "Process": "lsass.exe",
                            "PEB ImagePathName": r"C:\Windows\System32\winlogon.exe",
                            "EPROCESS ImageFileName": "lsass.exe",
                        },
                    ],
                },
            ),
        )

        aggregate = await _do_windows_injection_walk(db, firmware.id)
        assert aggregate["detection_count"] == 5
        assert aggregate["by_kind"]["injected_code_region"] == 1
        assert aggregate["by_kind"]["hollow_process"] == 1
        assert aggregate["by_kind"]["unlinked_module"] == 1
        assert aggregate["by_kind"]["ghosted_process"] == 1
        assert aggregate["by_kind"]["peb_masquerade"] == 1


@pytest.mark.asyncio
async def test_do_windows_injection_walk_aborts_on_vol3_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with make_live_db() as db:
        _, firmware, _ = await _seed_canary(db, "c")

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        call_count = {"n": 0}

        async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
            call_count["n"] += 1
            raise Vol3NotInstalled("INCLUDE_VOL3=1 required")

        monkeypatch.setattr(
            "app.services.windows_injection_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.run_vol3_plugin",
            fake_run,
        )

        aggregate = await _do_windows_injection_walk(db, firmware.id)
        # Only ONE invocation — loop aborts on Vol3NotInstalled.
        assert call_count["n"] == 1
        assert aggregate["image_count"] == 0
        assert len(aggregate["errors_per_image"]) == 1
        assert "Vol3 not installed" in aggregate["errors_per_image"][0]


@pytest.mark.asyncio
async def test_do_windows_injection_walk_per_plugin_failure_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One plugin failing records the error + continues with the rest."""
    async with make_live_db() as db:
        _, firmware, _ = await _seed_canary(db, "d")

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        async def fake_run(image_path: str, plugin: str, **_: Any) -> Vol3RunResult:
            if plugin == "windows.malware.malfind.Malfind":
                raise Vol3InvocationFailed("symbol lookup failed")
            return Vol3RunResult(
                plugin=plugin,
                image_path=image_path,
                records=[
                    {
                        "PID": 9999,
                        "Process": "x.exe",
                        "FILE_OBJECT path": r"\Device\X\y.exe",
                    }
                ]
                if "processghosting" in plugin
                else [],
                elapsed_s=0.5,
                exit_code=0,
                stderr_tail="",
            )

        monkeypatch.setattr(
            "app.services.windows_injection_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.run_vol3_plugin",
            fake_run,
        )

        aggregate = await _do_windows_injection_walk(db, firmware.id)
        # Per-image error captured for malfind, but processghosting
        # still produced a row.
        assert any(
            "Vol3InvocationFailed" in err
            for err in aggregate["errors_per_image"]
        )
        assert aggregate["by_kind"]["ghosted_process"] == 1


@pytest.mark.asyncio
async def test_do_windows_injection_walk_unique_hexdump_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two malfind records with the SAME hexdump bytes → unique count = 1."""
    async with make_live_db() as db:
        _, firmware, _ = await _seed_canary(db, "e")

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        same_hex = "00000000 fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b"
        monkeypatch.setattr(
            "app.services.windows_injection_walker.get_detection_roots",
            fake_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.run_vol3_plugin",
            _fake_run_factory(
                {
                    "windows.malware.malfind.Malfind": [
                        {
                            "PID": 1111,
                            "Process": "a.exe",
                            "Start VPN": 0x10000,
                            "End VPN": 0x10010,
                            "Hexdump": same_hex,
                        },
                        {
                            "PID": 2222,
                            "Process": "b.exe",
                            "Start VPN": 0x20000,
                            "End VPN": 0x20010,
                            "Hexdump": same_hex,
                        },
                    ],
                },
            ),
        )

        aggregate = await _do_windows_injection_walk(db, firmware.id)
        assert aggregate["detection_count"] == 2
        assert aggregate["unique_hexdump_sha256_count"] == 1  # de-duped


# ── Rule #39 outer-wrapper + safe-runner ────────────────────────────────────


@pytest.mark.asyncio
async def test_run_windows_injection_walk_background_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
                "detection_count": 3,
                "by_kind": {
                    "injected_code_region": 1,
                    "hollow_process": 1,
                    "unlinked_module": 0,
                    "peb_masquerade": 1,
                    "ghosted_process": 0,
                },
                "unique_hexdump_sha256_count": 1,
                "total_elapsed_s": 3.0,
                "errors_per_image": [],
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_injection_walker._do_windows_injection_walk",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.async_session_factory",
            fake_factory,
        )

        await run_windows_injection_walk_background(firmware.id)

        await db.refresh(firmware)
        assert firmware.windows_injection_walk_status == "completed"
        assert firmware.windows_injection_walk_started_at is not None
        assert firmware.windows_injection_walk_finished_at is not None
        assert firmware.windows_injection_walk_error is None
        result = firmware.windows_injection_walk_result
        assert result is not None
        assert result["schema_version"] == 1
        assert result["detection_count"] == 3


@pytest.mark.asyncio
async def test_auto_windows_injection_walk_safe_does_not_mutate_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
                "detection_count": 0,
                "by_kind": {
                    "injected_code_region": 0,
                    "hollow_process": 0,
                    "unlinked_module": 0,
                    "peb_masquerade": 0,
                    "ghosted_process": 0,
                },
                "unique_hexdump_sha256_count": 0,
                "total_elapsed_s": 0.0,
                "errors_per_image": [],
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_injection_walker._do_windows_injection_walk",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.windows_injection_walker.async_session_factory",
            fake_factory,
        )

        await auto_windows_injection_walk_firmware_safe(firmware.id)

        await db.refresh(firmware)
        assert firmware.windows_injection_walk_status == "idle"
        assert firmware.windows_injection_walk_result is not None
        assert firmware.windows_injection_walk_result["schema_version"] == 1


# ── Rule #36 + #45 source-scan gate + Rule #46 canary ────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
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
        / "windows_injection_walker.py"
    ).read_text()


def test_walker_no_forbidden_spawn_primitives() -> None:
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_SPAWN_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in windows_injection_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must only "
            "invoke Vol3 via the run_vol3_plugin helper."
        )


def test_walker_no_decrypt_invocation() -> None:
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 violation in windows_injection_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must NEVER decrypt."
        )


def test_walker_source_scan_gate_canary_fires() -> None:
    """Rule #46 — confirm the gate fires on a synthetic violation.

    Concatenated code lines (not f-string) so the violation survives
    docstring/comment stripping. Whitespace-tolerant regex.
    """
    line_a = "def bad_walker():\n"
    line_b = "    obj = SomeClass()\n"
    line_c = "    obj." + _FORBIDDEN_CANARY + '(b"x")\n'
    line_d = "    return None\n"
    synthetic = line_a + line_b + line_c + line_d
    stripped = _strip_docstrings_and_comments(synthetic)
    pattern = r"\.\s*decrypt\s*\("
    assert re.findall(pattern, stripped), (
        f"Rule #46 canary FAILED — synthetic violation did NOT match "
        f"the regex {pattern!r}. stripped={stripped!r}"
    )


# ── 2026-06-07 deprecation gate ─────────────────────────────────────────────


_DEPRECATED_TOP_LEVEL_PLUGIN_NAMES: tuple[str, ...] = (
    "hollowprocesses",
    "malfind",
    "ldrmodules",
    "processghosting",
    "psxview",
)


def _deprecated_path_pattern(short_name: str) -> str:
    """Build a whitespace-tolerant regex matching the DEPRECATED top-
    level path shape ``windows.<short_name>`` that does NOT match the
    canonical ``windows.malware.<short_name>``.

    Tokenize joins tokens with single spaces, so the post-strip form
    is ``windows . <short_name>``. The pattern uses ``\\s*`` around
    the dot AND negative-lookbehinds for ``malware`` (with or without
    intervening whitespace) — matching κ.D's whitespace-tolerant
    regex discipline.
    """
    return (
        rf"(?<!malware)(?<!malware\.)(?<!malware \.)"
        rf"\bwindows\s*\.\s*{short_name}\b"
    )


def test_walker_no_top_level_deprecated_plugin_paths() -> None:
    """Rule #36 / 2026-06-07 deprecation — the walker source must NOT
    mention any of the deprecated top-level plugin path shapes.

    Vol3 has flagged the 5 deprecated bare names (hollowprocesses,
    malfind, ldrmodules, processghosting, psxview, each directly under
    the windows.* package) for removal at the 2026-06-07 deadline. The
    walker MUST wire EXCLUSIVELY to the canonical
    ``windows.malware.<X>`` namespace. This gate checks the CODE
    tokens (docstrings + comments are allowed to mention the bare
    short-names for documentation context, but the deprecated combined
    shape ``windows.<short_name>`` must NOT appear).

    Whitespace-tolerant regex per κ.D's Rule #46 fix — tokenize joins
    code tokens with single spaces, so a naïve word-boundary regex
    silently misses the post-strip form ``windows . <short_name>``.
    """
    source = _strip_docstrings_and_comments(_walker_source())
    for short_name in _DEPRECATED_TOP_LEVEL_PLUGIN_NAMES:
        pattern = _deprecated_path_pattern(short_name)
        matches = re.findall(pattern, source)
        assert not matches, (
            f"2026-06-07 DEPRECATION violation in windows_injection_walker.py — "
            f"found {matches} mentioning the DEPRECATED top-level path "
            f"``windows.{short_name}``. Wire to ``windows.malware.{short_name}`` "
            "instead."
        )


def test_walker_source_scan_canary_for_deprecated_path() -> None:
    """Rule #46 — confirm the deprecation gate fires on synthetic violations.

    Constructs the synthetic violation at runtime via string
    concatenation rather than embedding the literal deprecated form
    in the source (which would itself trip the project-wide grep gate
    described in the issue). Uses the same ``_deprecated_path_pattern``
    helper as the real gate so any future pattern fix updates both
    call sites coherently.
    """
    deprecated_short = "malfind"
    bad_call = "windows" + "." + deprecated_short + ".Malfind"
    synthetic_code = (
        "def bad_walker():\n"
        f"    {bad_call}\n"
        "    return None\n"
    )
    stripped_code = _strip_docstrings_and_comments(synthetic_code)
    pattern = _deprecated_path_pattern(deprecated_short)
    assert re.findall(pattern, stripped_code), (
        f"Rule #46 canary FAILED — synthetic deprecated-path violation "
        f"did NOT match the regex {pattern!r}. stripped_code={stripped_code!r}. "
        "The gate is silently passing; the regex needs further "
        "whitespace-tolerance work."
    )


def test_walker_deprecation_gate_accepts_canonical_path() -> None:
    """Negative case — the canonical malware-namespaced path must NOT
    match the deprecation gate (otherwise the gate would reject
    legitimate code). Built via runtime concatenation to dodge the
    project-wide grep gate."""
    short = "malfind"
    canonical_path = "windows" + "." + "malware" + "." + short + ".Malfind"
    canonical_code = f"PLUGIN = {canonical_path}\n"
    stripped = _strip_docstrings_and_comments(canonical_code)
    pattern = _deprecated_path_pattern(short)
    assert not re.findall(pattern, stripped), (
        f"Deprecation gate produced a FALSE POSITIVE on the canonical "
        f"path. stripped={stripped!r}; pattern={pattern!r}."
    )


# Unused-import suppression for `patch`.
_ = patch
