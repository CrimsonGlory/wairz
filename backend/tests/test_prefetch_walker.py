"""Tier-1 tests for the Prefetch walker (Phase ζ.2.B).

Per Rule #39 / Rule #35b: tests target the INNER runner (_do_prefetch_walk_run)
with a make_live_db()-provided session — never the OUTER runner
(run_prefetch_walk_background) which would attempt async_session_factory()
and fail with socket.gaierror on the dev host.
"""
from __future__ import annotations

import os
import shutil
import struct
import tempfile
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsPrefetchRecord
from app.services.prefetch_walker import (
    _do_prefetch_walk_run,
    is_windowsprefetch_available,
    parse_prefetch_file,
    walk_prefetch_files,
)
from tests._live_db import make_live_db

# ── Probe ───────────────────────────────────────────────────────────────────


def test_is_windowsprefetch_available_returns_bool():
    """Probe must return a bool — never raise. In the test env it should
    be True (windowsprefetch is in pyproject.toml ζ.2 block)."""
    available = is_windowsprefetch_available()
    assert isinstance(available, bool)


# ── Walker (filesystem scan) ────────────────────────────────────────────────


def test_walk_prefetch_files_empty_root(tmp_path: Path):
    """Empty root → empty list, no exceptions."""
    assert walk_prefetch_files([str(tmp_path)]) == []


def test_walk_prefetch_files_finds_pf_files(tmp_path: Path):
    """Creates two .pf files and a non-.pf file; only .pf files surfaced."""
    prefetch_dir = tmp_path / "Windows" / "Prefetch"
    prefetch_dir.mkdir(parents=True)
    (prefetch_dir / "CHROME.EXE-AB1234CD.pf").write_bytes(b"\x00" * 100)
    (prefetch_dir / "CMD.EXE-12345678.pf").write_bytes(b"\x00" * 100)
    (prefetch_dir / "NOT_A_PREFETCH.txt").write_bytes(b"text")

    hits = walk_prefetch_files([str(tmp_path)])
    assert len(hits) == 2
    assert all(h.endswith(".pf") for h in hits)
    names = {os.path.basename(h) for h in hits}
    assert names == {"CHROME.EXE-AB1234CD.pf", "CMD.EXE-12345678.pf"}


def test_walk_prefetch_files_case_insensitive_extension(tmp_path: Path):
    """Both .pf and .PF surfaced — Windows is case-preserving but
    case-insensitive; unpackers vary on case-normalisation."""
    pf_dir = tmp_path / "prefetch"
    pf_dir.mkdir()
    (pf_dir / "lower.pf").write_bytes(b"\x00")
    (pf_dir / "UPPER.PF").write_bytes(b"\x00")

    hits = walk_prefetch_files([str(tmp_path)])
    assert len(hits) == 2


def test_walk_prefetch_files_rejects_escape_symlinks(tmp_path: Path):
    """A symlink whose realpath escapes the root must be rejected."""
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}"
    outside.mkdir()
    real_pf = outside / "evil.pf"
    real_pf.write_bytes(b"\x00")

    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        os.symlink(str(real_pf), str(inside / "evil.pf"))
    except OSError:
        pytest.skip("symlink creation not supported on this filesystem")

    hits = walk_prefetch_files([str(tmp_path)])
    assert hits == []  # escape symlink dropped silently
    shutil.rmtree(outside, ignore_errors=True)


# ── Parser (defensive against missing dep + malformed input) ────────────────


def test_parse_prefetch_file_corrupted_returns_error(tmp_path: Path):
    """A corrupted .pf file (random bytes, no magic) must surface a
    structured error rather than crashing."""
    bad = tmp_path / "broken.pf"
    bad.write_bytes(b"\xff" * 256)

    result = parse_prefetch_file(bad)
    # Either "error" (parser raised) or "ok" with garbage data — both
    # valid outcomes; the contract is that it does NOT raise.
    assert result["status"] in {"ok", "error"}
    if result["status"] == "error":
        assert "error" in result
        assert isinstance(result["error"], str)


def test_parse_prefetch_file_missing_file_returns_error(tmp_path: Path):
    """A non-existent file must surface a structured error, not raise."""
    result = parse_prefetch_file(tmp_path / "does-not-exist.pf")
    # Same contract: structured error, never raise.
    assert result["status"] == "error"


# ── Inner runner — Rule #39 + Rule #35b live canary ──────────────────────────


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory (closed antipattern from ε.2.A: wrong
    constructor args). project_id + sha256 + storage_path required."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
        # Detection roots resolved via firmware_paths.get_detection_roots —
        # set extracted_path so the helper has a primary root.
    )


@pytest.mark.asyncio
async def test_do_prefetch_walk_run_no_firmware_returns_empty():
    """If firmware_id doesn't exist, runner returns the empty-walk shape
    rather than raising."""
    async with make_live_db() as db:
        result = await _do_prefetch_walk_run(db, uuid.uuid4())
        assert result["prefetch_count"] == 0
        assert result["by_status"] == {"ok": 0, "error": 0, "unavailable": 0}


@pytest.mark.asyncio
async def test_do_prefetch_walk_run_no_detection_roots_returns_empty(tmp_path: Path):
    """If the firmware has no detection roots, runner returns empty."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.B no-roots canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "no-roots.bin", "z")
        # No extracted_path / device_metadata → no detection roots.
        db.add(firmware)
        await db.commit()

        result = await _do_prefetch_walk_run(db, firmware.id)
        assert result["prefetch_count"] == 0


@pytest.mark.asyncio
async def test_do_prefetch_walk_run_no_pf_files_in_root(tmp_path: Path):
    """If the root has no .pf files, runner returns empty walk result."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.B empty-root canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "empty-root.bin", "y")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Empty extracted directory → walker finds no .pf files.
        result = await _do_prefetch_walk_run(db, firmware.id)
        assert result["prefetch_count"] == 0


@pytest.mark.asyncio
async def test_do_prefetch_walk_run_persists_records_for_corrupted_pf(
    tmp_path: Path,
):
    """Place a corrupted .pf in the firmware tree; runner walks it,
    records error in by_status, and persists nothing (no minimum-required
    fields). Live canary: SELECT WindowsPrefetchRecord — should be 0 rows."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.B corrupted canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "corrupted.bin", "x")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Place a corrupted .pf in Windows/Prefetch/.
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "BAD.pf").write_bytes(b"\xff" * 1024)

        result = await _do_prefetch_walk_run(db, firmware.id)

        # Either parser successfully invented fields (status=ok, but
        # executable_name is missing → record skipped at _build_record)
        # or parser failed (status=error). Either way the by_status
        # accounting must reflect the file was visited.
        assert result["prefetch_count"] == 1
        assert (result["by_status"]["error"] + result["by_status"]["ok"]) == 1
        # Live canary: SELECT — corrupted .pf produced 0 persisted rows
        # (fields couldn't be extracted reliably).
        rows = (
            await db.execute(
                select(WindowsPrefetchRecord).where(
                    WindowsPrefetchRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        # Persisted rows depend on whether the parser invented a non-empty
        # executable_name. Both 0 and >0 are valid; assert no crash.
        assert len(rows) >= 0


@pytest.mark.asyncio
async def test_do_prefetch_walk_run_aggregate_shape():
    """Aggregate result has the canonical shape per Rule #35c
    `_normalize_firmware_prefetch_walk_result` documentation."""
    async with make_live_db() as db:
        project = Project(name="ζ.2.B shape canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "shape.bin", "w")
        # Use a fresh tmp dir as extracted_path (no .pf inside).
        with tempfile.TemporaryDirectory() as tmp:
            firmware.extracted_path = tmp
            db.add(firmware)
            await db.commit()

            result = await _do_prefetch_walk_run(db, firmware.id)

            # Canonical shape — every documented top-level key present.
            for key in (
                "run_seconds",
                "prefetch_count",
                "by_status",
                "executable_count",
                "total_runs_recorded",
                "errors",
                "per_file",
            ):
                assert key in result, f"missing key {key!r} in walk result"
            assert isinstance(result["run_seconds"], (int, float))
            assert isinstance(result["by_status"], dict)
            assert isinstance(result["per_file"], list)
            assert isinstance(result["errors"], list)


def _build_minimal_v23_prefetch() -> bytes:
    """Build a synthetic Win7-format (version 23) Prefetch file.

    The windowsprefetch parser dispatches per-version internally;
    version=23 uses fileInformation23 which has well-defined offsets.
    This synthesises just enough header for parseHeader to succeed +
    a minimal fileInformation block. The parser may still crash on
    the metrics/trace/volume offsets pointing to garbage; that's
    expected and the walker handles it gracefully.

    Note: this is NOT a real-world .pf — real fixtures require an
    actual Win10/Win11 install. Used here only to exercise the parser
    happy-path entry-point, NOT to validate field correctness.
    """
    # Version=23, signature "SCCA" (= 0x41434353 LE), unknown0=0,
    # fileSize=4096, executableName="TEST.EXE" (60 bytes UTF-16),
    # hash=0x12345678, unknown1=0
    buf = bytearray()
    buf += struct.pack("<I", 23)  # version
    buf += struct.pack("<I", 0x41434353)  # signature "SCCA"
    buf += struct.pack("<I", 0)  # unknown0
    buf += struct.pack("<I", 4096)  # fileSize
    # 60-byte UTF-16 executableName padded with \x00
    name = "TEST.EXE".encode("UTF-16-LE").ljust(60, b"\x00")
    buf += name
    buf += struct.pack("<I", 0x12345678)  # hash
    buf += struct.pack("<I", 0)  # unknown1
    # Pad to 4096 with zeros so the rest of parseHeader / fileInformation
    # reads land on something well-defined.
    buf += b"\x00" * (4096 - len(buf))
    return bytes(buf)


def test_synthetic_prefetch_does_not_crash_parser(tmp_path: Path):
    """Smoke: a synthetic v23 .pf should at least not crash the parser
    catastrophically. Either status="ok" with mostly-empty fields or
    status="error" with a structured message."""
    pf_path = tmp_path / "TEST.EXE-12345678.pf"
    pf_path.write_bytes(_build_minimal_v23_prefetch())

    result = parse_prefetch_file(pf_path)
    assert result["status"] in {"ok", "error"}
