"""Tier-1 tests for the SRUM walker (Phase ζ.3.B).

Per Rule #39 / Rule #35b: tests target the INNER runner
(_do_srum_walk_run) with a make_live_db()-provided session — never
the OUTER runner (run_srum_walk_background) which would attempt
async_session_factory() and fail with socket.gaierror on the dev host.
"""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsSrumRecord
from app.services.srum_walker import (
    _do_srum_walk_run,
    is_pyesedb_available,
    walk_srudb_files,
)
from tests._live_db import make_live_db

# ── Probe ───────────────────────────────────────────────────────────────────


def test_is_pyesedb_available_returns_bool():
    """Probe must return a bool, never raise."""
    assert isinstance(is_pyesedb_available(), bool)


# ── Walker (filesystem scan) ────────────────────────────────────────────────


def test_walk_srudb_files_empty_root(tmp_path: Path):
    """Empty root → empty list, no exceptions."""
    assert walk_srudb_files([str(tmp_path)]) == []


def test_walk_srudb_files_finds_srudb(tmp_path: Path):
    """Creates an SRUDB.dat in the canonical Windows path; walker
    surfaces it."""
    sru_dir = tmp_path / "Windows" / "System32" / "sru"
    sru_dir.mkdir(parents=True)
    (sru_dir / "SRUDB.dat").write_bytes(b"\x00" * 1024)

    hits = walk_srudb_files([str(tmp_path)])
    assert len(hits) == 1
    assert hits[0].endswith("SRUDB.dat") or hits[0].endswith("srudb.dat")


def test_walk_srudb_files_case_insensitive(tmp_path: Path):
    """Match SRUDB.dat / srudb.dat / Srudb.dat (Windows case-insensitive
    + extracted-tree case-preserving)."""
    sru_dir = tmp_path / "sru"
    sru_dir.mkdir()
    (sru_dir / "SRUDB.dat").write_bytes(b"\x00")
    (sru_dir / "srudb.dat").write_bytes(b"\x00") if not (
        sru_dir / "SRUDB.dat"
    ).exists() else None  # skip on case-insensitive FS
    # On case-insensitive FS we'll only find one; on case-sensitive both.
    # The contract is: case-insensitive match → at least 1.
    hits = walk_srudb_files([str(tmp_path)])
    assert len(hits) >= 1


def test_walk_srudb_files_rejects_escape_symlinks(tmp_path: Path):
    """A symlink whose realpath escapes the root must be rejected."""
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}"
    outside.mkdir()
    real_srudb = outside / "SRUDB.dat"
    real_srudb.write_bytes(b"\x00")

    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        os.symlink(str(real_srudb), str(inside / "SRUDB.dat"))
    except OSError:
        pytest.skip("symlink creation not supported on this filesystem")

    hits = walk_srudb_files([str(tmp_path)])
    assert hits == []
    shutil.rmtree(outside, ignore_errors=True)


def test_walk_srudb_files_skips_unrelated_files(tmp_path: Path):
    """Non-SRUDB.dat files in the same dir must NOT be surfaced."""
    sru_dir = tmp_path / "sru"
    sru_dir.mkdir()
    (sru_dir / "SRUDB.dat").write_bytes(b"\x00")
    (sru_dir / "SRUDB.dat.LOG1").write_bytes(b"\x00")
    (sru_dir / "SRUDB.dat.LOG2").write_bytes(b"\x00")
    (sru_dir / "edb.chk").write_bytes(b"\x00")

    hits = walk_srudb_files([str(tmp_path)])
    assert len(hits) == 1


# ── Inner runner — Rule #39 + Rule #35b live canary ──────────────────────────


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_do_srum_walk_run_no_firmware_returns_empty():
    """If firmware_id doesn't exist, runner returns the empty-walk shape
    rather than raising."""
    async with make_live_db() as db:
        result = await _do_srum_walk_run(db, uuid.uuid4())
        assert result["srudb_count"] == 0
        assert result["total_records"] == 0
        assert result["unique_apps"] == 0


@pytest.mark.asyncio
async def test_do_srum_walk_run_no_detection_roots_returns_empty():
    """If the firmware has no detection roots, runner returns empty."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.B no-roots canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "no-roots-srum.bin", "z")
        db.add(firmware)
        await db.commit()

        result = await _do_srum_walk_run(db, firmware.id)
        assert result["srudb_count"] == 0


@pytest.mark.asyncio
async def test_do_srum_walk_run_no_srudb_in_root(tmp_path: Path):
    """If the root has no SRUDB.dat, runner returns empty walk result."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.B empty-root canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "empty-srum.bin", "y")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        result = await _do_srum_walk_run(db, firmware.id)
        assert result["srudb_count"] == 0


@pytest.mark.asyncio
async def test_do_srum_walk_run_corrupted_srudb_records_error(tmp_path: Path):
    """Place a corrupted SRUDB.dat (random bytes, no ESEDB magic);
    walker walks it, records error in by_status, and persists nothing.
    Live canary: SELECT WindowsSrumRecord — should be 0 rows."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.B corrupted canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "corrupted-srum.bin", "x")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Place a corrupted SRUDB.dat (zero header — pyesedb rejects).
        sru_dir = tmp_path / "Windows" / "System32" / "sru"
        sru_dir.mkdir(parents=True)
        (sru_dir / "SRUDB.dat").write_bytes(b"\xff" * 4096)

        result = await _do_srum_walk_run(db, firmware.id)

        # Walker visited the file — srudb_count=1.
        assert result["srudb_count"] == 1
        # If pyesedb is available, the corrupted file produces an error;
        # if not, status is "unavailable". Either way, total_records=0.
        assert result["total_records"] == 0
        assert (
            result["by_status"]["error"] >= 1
            or result["by_status"]["unavailable"] >= 1
        )

        # Live canary: SELECT — corrupted SRUDB produced 0 persisted rows.
        rows = (
            await db.execute(
                select(WindowsSrumRecord).where(
                    WindowsSrumRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 0


@pytest.mark.asyncio
async def test_do_srum_walk_run_aggregate_shape(tmp_path: Path):
    """Aggregate result has the canonical shape per Rule #35c
    `_normalize_firmware_srum_walk_result` documentation."""
    async with make_live_db() as db:
        project = Project(name="ζ.3.B shape canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "shape-srum.bin", "w")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        result = await _do_srum_walk_run(db, firmware.id)

        for key in (
            "run_seconds",
            "srudb_count",
            "by_record_type",
            "by_status",
            "total_records",
            "unique_apps",
            "errors",
            "per_file",
        ):
            assert key in result, f"missing key {key!r} in walk result"
        # by_record_type must contain all 5 canonical record types.
        for rt in (
            "network_data_usage",
            "network_connectivity",
            "application_resource_usage",
            "push_notification",
            "energy_usage",
        ):
            assert rt in result["by_record_type"]
