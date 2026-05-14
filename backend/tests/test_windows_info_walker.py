"""Tests for ``app.services.windows_info_walker`` (Phase λ.α.D).

Covers:

- Pure helpers — ``_extract_variables`` (Vol3 record → flat dict),
  ``_derive_kernel_hint`` (variables → human kernel string),
  ``_classify_os_kernel_family``, ``_derive_isf_profile_guess``,
  ``_family_from_kernel_hint``.
- ``_walk_one_image`` with mocked ``vol3_runner.run_vol3_plugin`` —
  success + Vol3InvocationFailed per-image error + Vol3NotInstalled
  re-raise.
- ``_do_windows_info_walk`` live canary (Rule #35b) — seeds a real
  Firmware + MemoryDumpImage row via ``make_live_db``, mocks the
  runner, asserts the persisted ``kernel_hint`` / ``isf_profile_guess``
  / ``last_walked_at`` + the per-firmware aggregate.
- Rule #39 outer-wrapper state-machine transitions
  (idle → running → completed) via ``run_windows_info_walk_background``.
- Rule #39 safe-runner graceful Vol3NotInstalled handling —
  ``auto_windows_info_walk_firmware_safe`` aggregates the install gap
  in ``errors_per_image`` without crashing.
- Rule #45 + Rule #46 source-scan gate over ``windows_info_walker.py``
  + canary that confirms the gate fires on a synthetic violation.
"""
from __future__ import annotations

import datetime as _dt
import io
import pathlib
import re
import tokenize
import uuid
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select

# Importing MemoryDumpImage registers its metadata on Base.metadata so
# make_live_db's create_all() materialises the table for the live canary.
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage  # noqa: F401  (registers mapper)
from app.models.project import Project
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3RunResult,
)
from app.services.windows_info_walker import (
    _WALK_OS_FAMILIES,
    _classify_os_kernel_family,
    _derive_isf_profile_guess,
    _derive_kernel_hint,
    _do_windows_info_walk,
    _empty_aggregate,
    _extract_variables,
    _family_from_kernel_hint,
    _walk_one_image,
    auto_windows_info_walk_firmware_safe,
    run_windows_info_walk_background,
)
from tests._live_db import make_live_db

# ── Pure helpers ─────────────────────────────────────────────────────────────


def test_extract_variables_from_canonical_windows_info_output() -> None:
    """Vol3's ``[{Variable, Value, TreeDepth}, ...]`` shape flattens."""
    records = [
        {"TreeDepth": 0, "Variable": "Kernel Base", "Value": "0xfffff80000000000"},
        {"TreeDepth": 0, "Variable": "DTB", "Value": "0x1aa000"},
        {"TreeDepth": 0, "Variable": "Is64Bit", "Value": "True"},
        {"TreeDepth": 0, "Variable": "NtMajorVersion", "Value": "10"},
        {"TreeDepth": 0, "Variable": "NtMinorVersion", "Value": "0"},
    ]
    out = _extract_variables(records)
    assert out["Kernel Base"] == "0xfffff80000000000"
    assert out["DTB"] == "0x1aa000"
    assert out["Is64Bit"] == "True"
    assert out["NtMajorVersion"] == "10"
    assert out["NtMinorVersion"] == "0"


def test_extract_variables_tolerates_malformed_records() -> None:
    """Records missing Variable/Value or with wrong types are skipped."""
    records: list[dict[str, Any]] = [
        {"Variable": "Valid", "Value": "ok"},
        {"NotVariable": "ignored"},
        {"Variable": 42, "Value": "ignored"},  # non-string Variable
        {"Variable": "NullValue", "Value": None},
    ]
    out = _extract_variables(records)
    assert out["Valid"] == "ok"
    assert "NotVariable" not in out
    assert out["NullValue"] == ""


def test_derive_kernel_hint_windows10_with_build_number() -> None:
    """A canonical Win10 19045 image gets the expected hint shape."""
    variables = {
        "NtMajorVersion": "10",
        "NtMinorVersion": "0",
        "NTBuildLab": "19045.1.amd64fre.vb_release.191206-1406",
        "MachineType": "AMD64",
        "NtProductType": "NtProductWinNt",
    }
    hint = _derive_kernel_hint(variables)
    assert hint == "Windows 10 (NT 10.0.19045) AMD64"


def test_derive_kernel_hint_windows11_high_build_number() -> None:
    """Build number >= 22000 classifies as Windows 11."""
    variables = {
        "NtMajorVersion": "10",
        "NtMinorVersion": "0",
        "NTBuildLab": "22631.2861.amd64fre.ni_release.231024-1700",
        "MachineType": "AMD64",
        "NtProductType": "NtProductWinNt",
    }
    hint = _derive_kernel_hint(variables)
    assert hint.startswith("Windows 11")
    assert "22631" in hint


def test_derive_kernel_hint_server() -> None:
    """Server product classifies as Windows Server."""
    variables = {
        "NtMajorVersion": "10",
        "NtMinorVersion": "0",
        "NTBuildLab": "20348.1.amd64fre.fe_release.200118-1820",
        "MachineType": "AMD64",
        "NtProductType": "LanmanNT",
    }
    hint = _derive_kernel_hint(variables)
    assert hint.startswith("Windows Server")


def test_derive_kernel_hint_returns_none_without_essential_fields() -> None:
    """Missing NtMajorVersion or NtMinorVersion → None."""
    assert _derive_kernel_hint({}) is None
    assert _derive_kernel_hint({"NtMajorVersion": "10"}) is None
    assert _derive_kernel_hint({"NtMinorVersion": "0"}) is None


def test_classify_os_kernel_family() -> None:
    """Family classification matches the ``_derive_kernel_hint`` policy."""
    assert _classify_os_kernel_family(
        {"NtMajorVersion": "10", "NtMinorVersion": "0", "NTBuildLab": "19045"}
    ) == "windows10"
    assert _classify_os_kernel_family(
        {"NtMajorVersion": "10", "NtMinorVersion": "0", "NTBuildLab": "22631"}
    ) == "windows11"
    assert _classify_os_kernel_family(
        {
            "NtMajorVersion": "10",
            "NtMinorVersion": "0",
            "NTBuildLab": "20348",
            "NtProductType": "LanmanNT",
        }
    ) == "windows_server"
    assert _classify_os_kernel_family({}) == "unknown"


def test_derive_isf_profile_guess_extracts_bundle_id() -> None:
    """The pre-leaf path segment is the canonical 16-char bundle ID."""
    symbols = (
        "file:///opt/wairz/vol3-symbols/windows/ntkrnlmp.pdb/"
        "a1b2c3d4e5f60a1b/abcdef0123456789.json.xz"
    )
    guess = _derive_isf_profile_guess({"Symbols": symbols})
    assert guess == "a1b2c3d4e5f60a1b"


def test_derive_isf_profile_guess_returns_none_without_symbols() -> None:
    assert _derive_isf_profile_guess({}) is None


def test_derive_isf_profile_guess_truncates_at_column_constraint() -> None:
    """The isf_profile_guess column is String(64); the helper caps the
    result so a future Vol3 schema bump can't overflow the column."""
    # Construct a path whose pre-leaf segment is >64 chars.
    long_segment = "x" * 200
    symbols = f"file:///opt/wairz/vol3-symbols/windows/ntkrnlmp.pdb/{long_segment}/leaf.json.xz"
    guess = _derive_isf_profile_guess({"Symbols": symbols})
    assert guess is not None
    assert len(guess) <= 64


def test_family_from_kernel_hint_round_trip() -> None:
    """Kernel hints derived by ``_derive_kernel_hint`` round-trip back
    to the same family bucket via ``_family_from_kernel_hint``."""
    assert _family_from_kernel_hint("Windows 10 (NT 10.0.19045) AMD64") == "windows10"
    assert _family_from_kernel_hint("Windows 11 (NT 10.0.22631) AMD64") == "windows11"
    assert _family_from_kernel_hint("Windows Server (NT 10.0.20348)") == "windows_server"
    assert _family_from_kernel_hint("Linux 5.15.0") == "unknown"


# ── _walk_one_image (mocked vol3_runner) ────────────────────────────────────


@pytest.mark.asyncio
async def test_walk_one_image_success_stamps_per_image_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful Vol3 invocation stamps kernel_hint + isf_profile_guess
    + last_walked_at on the MemoryDumpImage row."""
    image = MemoryDumpImage(
        id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        image_path="/data/mem.raw",
        image_filename="mem.raw",
        file_size=1024 * 1024 * 200,
        magic_detected="MDMP",
        os_family="windows",
    )

    fake_result = Vol3RunResult(
        plugin="windows.info",
        image_path="/data/mem.raw",
        records=[
            {"Variable": "NtMajorVersion", "Value": "10"},
            {"Variable": "NtMinorVersion", "Value": "0"},
            {"Variable": "NTBuildLab", "Value": "19045.1.amd64fre"},
            {"Variable": "MachineType", "Value": "AMD64"},
            {"Variable": "NtProductType", "Value": "NtProductWinNt"},
            {
                "Variable": "Symbols",
                "Value": "file:///opt/wairz/vol3-symbols/windows/ntkrnlmp.pdb/abc123/sha.json.xz",
            },
        ],
        elapsed_s=2.5,
        exit_code=0,
        stderr_tail="",
    )

    async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
        return fake_result

    monkeypatch.setattr(
        "app.services.windows_info_walker.run_vol3_plugin", fake_run
    )

    classified, elapsed_s, err = await _walk_one_image(db=None, image=image)
    assert classified is True
    assert elapsed_s == 2.5
    assert err is None
    assert image.kernel_hint == "Windows 10 (NT 10.0.19045) AMD64"
    assert image.isf_profile_guess == "abc123"
    assert image.last_walked_at is not None
    assert isinstance(image.last_walked_at, _dt.datetime)


@pytest.mark.asyncio
async def test_walk_one_image_records_per_image_error_on_invocation_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vol3InvocationFailed becomes a per-image error string; classification False."""
    image = MemoryDumpImage(
        id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        image_path="/data/bad.raw",
        image_filename="bad.raw",
        file_size=1024 * 1024 * 200,
        magic_detected="raw",
        os_family="unknown",
    )

    async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
        raise Vol3InvocationFailed("FATAL: unable to find ISF for kernel banner")

    monkeypatch.setattr(
        "app.services.windows_info_walker.run_vol3_plugin", fake_run
    )

    classified, elapsed_s, err = await _walk_one_image(db=None, image=image)
    assert classified is False
    assert elapsed_s == 0.0
    assert err is not None
    assert "bad.raw" in err
    assert "Vol3InvocationFailed" in err
    # No per-image fields were stamped (the row's not classified).
    assert image.kernel_hint is None
    assert image.last_walked_at is None


@pytest.mark.asyncio
async def test_walk_one_image_propagates_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vol3NotInstalled propagates so the inner orchestrator can abort
    the whole walk."""
    image = MemoryDumpImage(
        id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        image_path="/data/mem.raw",
        image_filename="mem.raw",
        file_size=1024 * 1024 * 200,
        magic_detected="MDMP",
        os_family="windows",
    )

    async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
        raise Vol3NotInstalled("rebuild with --build-arg INCLUDE_VOL3=1")

    monkeypatch.setattr(
        "app.services.windows_info_walker.run_vol3_plugin", fake_run
    )

    with pytest.raises(Vol3NotInstalled):
        await _walk_one_image(db=None, image=image)


# ── _do_windows_info_walk live canary (Rule #35b) ───────────────────────────


@pytest.mark.asyncio
async def test_do_windows_info_walk_live_canary_persists_per_image_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule #35b live canary — round-trip through real ORM + SELECT to
    verify kernel_hint + isf_profile_guess + last_walked_at + the
    per-firmware aggregate all persist correctly.
    """
    async with make_live_db() as db:
        # Seed: project + firmware + one Windows image.
        project = Project(id=uuid.uuid4(), name="canary-project")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="image.bin",
            file_size=2048,
            sha256="a" * 64,
        )
        db.add(firmware)
        await db.flush()
        image = MemoryDumpImage(
            firmware_id=firmware.id,
            image_path="/data/canary.raw",
            image_filename="canary.raw",
            file_size=200 * 1024 * 1024,
            magic_detected="MDMP",
            os_family="windows",
        )
        db.add(image)
        await db.flush()

        async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
            return Vol3RunResult(
                plugin="windows.info",
                image_path="/data/canary.raw",
                records=[
                    {"Variable": "NtMajorVersion", "Value": "10"},
                    {"Variable": "NtMinorVersion", "Value": "0"},
                    {"Variable": "NTBuildLab", "Value": "22631"},
                    {"Variable": "MachineType", "Value": "AMD64"},
                    {"Variable": "NtProductType", "Value": "NtProductWinNt"},
                    {
                        "Variable": "Symbols",
                        "Value": "file:///opt/wairz/vol3-symbols/windows/ntkrnlmp.pdb/bundle1/sha.json.xz",
                    },
                ],
                elapsed_s=1.5,
                exit_code=0,
                stderr_tail="",
            )

        # get_detection_roots is invoked early — stub it to return at least one root.
        async def fake_get_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp/canary"]

        monkeypatch.setattr(
            "app.services.windows_info_walker.run_vol3_plugin", fake_run
        )
        monkeypatch.setattr(
            "app.services.windows_info_walker.get_detection_roots",
            fake_get_roots,
        )

        aggregate = await _do_windows_info_walk(db, firmware.id)

        # Aggregate shape: one image walked + classified as windows11.
        assert aggregate["image_count"] == 1
        assert aggregate["classified_count"] == 1
        assert aggregate["by_os_kernel_family"]["windows11"] == 1
        assert aggregate["total_elapsed_s"] > 0
        assert aggregate["errors_per_image"] == []

        # SELECT the persisted image row and inspect — Rule #35b live canary.
        persisted = (
            await db.execute(
                select(MemoryDumpImage).where(
                    MemoryDumpImage.id == image.id
                )
            )
        ).scalar_one()
        assert persisted.kernel_hint is not None
        assert "Windows 11" in persisted.kernel_hint
        assert persisted.isf_profile_guess == "bundle1"
        assert persisted.last_walked_at is not None


@pytest.mark.asyncio
async def test_do_windows_info_walk_handles_no_images_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No Windows / unknown images → empty aggregate, no Vol3 invocation."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="empty-project")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="empty.bin",
            file_size=2048,
            sha256="y" * 64,
        )
        db.add(firmware)
        await db.flush()

        async def fake_get_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp/empty"]

        called = {"count": 0}

        async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
            called["count"] += 1
            raise AssertionError("should not have been invoked")

        monkeypatch.setattr(
            "app.services.windows_info_walker.get_detection_roots",
            fake_get_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_info_walker.run_vol3_plugin", fake_run
        )

        aggregate = await _do_windows_info_walk(db, firmware.id)
        assert aggregate["image_count"] == 0
        assert aggregate["classified_count"] == 0
        assert aggregate["errors_per_image"] == []
        assert called["count"] == 0


@pytest.mark.asyncio
async def test_do_windows_info_walk_aborts_on_vol3_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vol3NotInstalled at the first image aborts the loop and records the gap."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="no-vol3-project")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="image.bin",
            file_size=2048,
            sha256="z" * 64,
        )
        db.add(firmware)
        await db.flush()
        db.add(
            MemoryDumpImage(
                firmware_id=firmware.id,
                image_path="/data/img.raw",
                image_filename="img.raw",
                file_size=200 * 1024 * 1024,
                magic_detected="raw",
                os_family="unknown",
            )
        )
        db.add(
            MemoryDumpImage(
                firmware_id=firmware.id,
                image_path="/data/img2.raw",
                image_filename="img2.raw",
                file_size=200 * 1024 * 1024,
                magic_detected="MDMP",
                os_family="windows",
            )
        )
        await db.flush()

        async def fake_get_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp"]

        call_count = {"n": 0}

        async def fake_run(*args: Any, **kwargs: Any) -> Vol3RunResult:
            call_count["n"] += 1
            raise Vol3NotInstalled("INCLUDE_VOL3=1 required")

        monkeypatch.setattr(
            "app.services.windows_info_walker.get_detection_roots",
            fake_get_roots,
        )
        monkeypatch.setattr(
            "app.services.windows_info_walker.run_vol3_plugin", fake_run
        )

        aggregate = await _do_windows_info_walk(db, firmware.id)
        # Only ONE invocation attempt — the loop aborts on Vol3NotInstalled.
        assert call_count["n"] == 1
        # No images counted (the abort happens before image_count increments).
        assert aggregate["image_count"] == 0
        assert len(aggregate["errors_per_image"]) == 1
        assert "Vol3 not installed" in aggregate["errors_per_image"][0]
        assert "INCLUDE_VOL3=1" in aggregate["errors_per_image"][0]


# ── Outer wrapper state-machine transitions (Rule #33 .a) ────────────────────


@pytest.mark.asyncio
async def test_run_windows_info_walk_background_transitions_to_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The outer wrapper drives idle → running → completed and stamps
    the schema-versioned aggregate."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="outer-project")
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

        # Stub the inner orchestrator to return a deterministic aggregate.
        async def fake_inner(db_arg, fw_id):
            return {
                "schema_version": 1,
                "image_count": 1,
                "classified_count": 1,
                "by_os_kernel_family": {
                    "windows10": 0,
                    "windows11": 1,
                    "windows_server": 0,
                    "unknown": 0,
                },
                "total_elapsed_s": 1.0,
                "errors_per_image": [],
            }

        # Monkeypatch the inner orchestrator AND the session factory so
        # the outer wrapper uses our live DB session.
        monkeypatch.setattr(
            "app.services.windows_info_walker._do_windows_info_walk",
            fake_inner,
        )

        # Replace async_session_factory to yield our live db.
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_info_walker.async_session_factory",
            fake_factory,
        )

        await run_windows_info_walk_background(firmware.id)

        # Re-fetch the firmware row to observe the transitions.
        await db.refresh(firmware)
        assert firmware.windows_info_walk_status == "completed"
        assert firmware.windows_info_walk_started_at is not None
        assert firmware.windows_info_walk_finished_at is not None
        assert firmware.windows_info_walk_error is None
        # Aggregate is stamped with schema_version.
        result = firmware.windows_info_walk_result
        assert result is not None
        assert result["schema_version"] == 1
        assert result["classified_count"] == 1


# ── Safe-runner (Rule #39 unpack-post-detection hook) ────────────────────────


@pytest.mark.asyncio
async def test_auto_windows_info_walk_safe_does_not_mutate_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The safe runner stamps the aggregate but leaves
    ``windows_info_walk_status`` at idle so a future operator-driven
    re-trigger via the trigger MCP tool succeeds without 409 conflict
    (Rule #33 .a)."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="safe-project")
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
                "schema_version": 1,
                "image_count": 0,
                "classified_count": 0,
                "by_os_kernel_family": {
                    "windows10": 0,
                    "windows11": 0,
                    "windows_server": 0,
                    "unknown": 0,
                },
                "total_elapsed_s": 0.0,
                "errors_per_image": [],
            }

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.windows_info_walker._do_windows_info_walk",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.windows_info_walker.async_session_factory",
            fake_factory,
        )

        await auto_windows_info_walk_firmware_safe(firmware.id)

        await db.refresh(firmware)
        # Status stays idle — the safe runner doesn't transition it.
        assert firmware.windows_info_walk_status == "idle"
        # But the aggregate IS stamped.
        assert firmware.windows_info_walk_result is not None
        assert firmware.windows_info_walk_result["schema_version"] == 1


# ── Sanity checks on module configuration ────────────────────────────────────


def test_walk_os_families_includes_windows_and_unknown() -> None:
    """The walker iterates Windows + unknown images (raw acquisitions
    classify as unknown at enumeration time; Vol3 automagic re-classifies
    them at scan time)."""
    assert "windows" in _WALK_OS_FAMILIES
    assert "unknown" in _WALK_OS_FAMILIES
    # Linux + mac are excluded — windows.info doesn't run on them.
    assert "linux" not in _WALK_OS_FAMILIES
    assert "mac" not in _WALK_OS_FAMILIES


def test_empty_aggregate_shape() -> None:
    """The empty aggregate has the right keys + schema version."""
    agg = _empty_aggregate()
    assert agg["schema_version"] == 1
    assert agg["image_count"] == 0
    assert agg["classified_count"] == 0
    assert set(agg["by_os_kernel_family"].keys()) == {
        "windows10", "windows11", "windows_server", "unknown"
    }
    assert agg["total_elapsed_s"] == 0.0
    assert agg["errors_per_image"] == []


# ── Rule #36 + Rule #45 source-scan gate over windows_info_walker.py ────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Strip docstrings / # comments / string literals so the gate
    scans CODE tokens only."""
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


# Synthetic-violation canary constant (used by Rule #46 canary test).
_FORBIDDEN_CANARY = "decrypt"


# Forbidden tokens — whitespace-tolerant per κ.D tokenize-whitespace fix.
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
        / "windows_info_walker.py"
    ).read_text()


def test_walker_no_forbidden_spawn_primitives() -> None:
    """Rule #36 — the walker CODE must NOT shell out via system/exec/eval.

    The walker's only subprocess invocation goes through
    ``vol3_runner.run_vol3_plugin``, which is itself audited under
    its own source-scan gate. The walker module must NOT contain a
    direct ``subprocess.run`` / ``os.system`` / ``eval`` etc.
    """
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_SPAWN_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in windows_info_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must only "
            "invoke Vol3 via the run_vol3_plugin helper."
        )


def test_walker_no_decrypt_invocation() -> None:
    """Rule #45 — the walker CODE must contain no decrypt invocation.

    Vol3's metadata plugins (windows.info, pslist, …) emit pre-parsed
    structured records; the walker should NEVER need to decrypt
    anything itself. A future regression that added inline decrypt
    code would land here.
    """
    source = _strip_docstrings_and_comments(_walker_source())
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 violation in windows_info_walker.py — found "
            f"{matches} matching {pattern!r}; walker CODE must NEVER decrypt."
        )


def test_walker_source_scan_gate_canary_fires() -> None:
    """Rule #46 — confirm the gate actually fires on a synthetic violation.

    The synthetic source uses CODE-token concatenation (not f-string
    interpolation) so the violation survives docstring/comment
    stripping. Mirrors κ.D's whitespace-tolerant regex canary.
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
    """Rule #46 false-positive guard — docstring mentions of forbidden
    tokens DO NOT cause the gate to fire."""
    synthetic_docstring_source = '''
def safe_walker():
    """This walker NEVER invokes CryptUnprotectData and NEVER tries to
    decrypt anything — pure metadata."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)
    assert not re.findall(r"\bCryptUnprotectData\b", stripped)


# ── Unused-import suppression for `patch` ───────────────────────────────────
_ = patch
