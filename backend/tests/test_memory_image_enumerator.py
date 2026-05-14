"""Tests for ``app.services.memory_image_enumerator`` (Phase λ.α.B).

Covers Rule #39 triplet smoke:

- ``_do_memory_image_enumeration`` (INNER) — Rule #35b live canary
  against ``make_live_db``: seed firmware + temp directory with fake
  images, stub get_detection_roots, run inner, assert MemoryDumpImage
  rows + aggregate.
- ``run_memory_image_enumeration_background`` (OUTER) — drives
  idle → running → completed, stamps aggregate. Failure path:
  inner raises → outer rolls back, fail_db transitions to failed,
  error column populated.
- ``auto_memory_image_enumeration_safe`` (UNPACK-POST-DETECTION hook) —
  stamps aggregate but leaves ``memory_dump_walk_status`` at ``idle``
  so a future operator-driven re-trigger succeeds without 409 conflict
  (Rule #33 .a).

Mirrors the test_prefetch_walker.py / test_srum_walker.py /
test_windows_info_walker.py shape that Issue #13 specifies.
"""
from __future__ import annotations

import pathlib
import uuid
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage
from app.models.project import Project
from app.services.memory_image_enumerator import (
    _do_memory_image_enumeration,
    _empty_aggregate,
    auto_memory_image_enumeration_safe,
    run_memory_image_enumeration_background,
)
from app.services.memory_image_paths import MIN_MEMORY_IMAGE_BYTES
from tests._live_db import make_live_db


def _make_image(path: pathlib.Path, *, size: int, magic: bytes = b"") -> None:
    """Write a fake memory image of ``size`` bytes with optional magic prefix."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        if magic:
            fh.write(magic)
        fh.seek(size - 1)
        fh.write(b"\x00")


# ── _empty_aggregate shape ───────────────────────────────────────────────────


def test_empty_aggregate_shape() -> None:
    """The default aggregate carries the right schema + keys."""
    agg = _empty_aggregate()
    assert agg["schema_version"] == 1
    assert agg["image_count"] == 0
    assert agg["total_bytes"] == 0
    assert set(agg["by_os_family"].keys()) == {
        "windows", "linux", "mac", "unknown"
    }
    assert agg["elapsed_s"] == 0.0


# ── _do_memory_image_enumeration live canary (Rule #35b) ────────────────────


@pytest.mark.asyncio
async def test_do_memory_image_enumeration_persists_rows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Inner orchestrator persists MemoryDumpImage rows + populates the
    aggregate from a real filesystem walk."""
    # Create one valid Windows minidump + one Linux LiME + one too-small file.
    _make_image(
        tmp_path / "win.raw",
        size=MIN_MEMORY_IMAGE_BYTES + 512,
        magic=b"MDMP",
    )
    _make_image(
        tmp_path / "linux.lime",
        size=MIN_MEMORY_IMAGE_BYTES + 1024,
        magic=b"LiME",
    )
    _make_image(tmp_path / "small.raw", size=1024)

    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="canary")
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

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return [str(tmp_path)]

        monkeypatch.setattr(
            "app.services.memory_image_enumerator.get_detection_roots",
            fake_roots,
        )

        aggregate = await _do_memory_image_enumeration(db, firmware.id)
        assert aggregate["image_count"] == 2
        assert aggregate["by_os_family"]["windows"] == 1
        assert aggregate["by_os_family"]["linux"] == 1
        assert aggregate["by_os_family"]["unknown"] == 0
        assert aggregate["total_bytes"] >= 2 * MIN_MEMORY_IMAGE_BYTES

        rows = (
            (
                await db.execute(
                    select(MemoryDumpImage).where(
                        MemoryDumpImage.firmware_id == firmware.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        by_name = {r.image_filename: r for r in rows}
        assert by_name["win.raw"].magic_detected == "MDMP"
        assert by_name["win.raw"].os_family == "windows"
        assert by_name["linux.lime"].magic_detected == "LiME"
        assert by_name["linux.lime"].os_family == "linux"


@pytest.mark.asyncio
async def test_do_memory_image_enumeration_replaces_prior_rows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Re-running drops prior MemoryDumpImage rows for the same firmware."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="re-run")
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

        # Stale row from a prior run pointing at a file that no longer exists.
        stale = MemoryDumpImage(
            firmware_id=firmware.id,
            image_path="/data/stale.raw",
            image_filename="stale.raw",
            file_size=4096,
            magic_detected="raw",
            os_family="unknown",
        )
        db.add(stale)
        await db.flush()

        # Current disk state: one new image.
        _make_image(
            tmp_path / "current.raw",
            size=MIN_MEMORY_IMAGE_BYTES + 256,
            magic=b"MDMP",
        )

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return [str(tmp_path)]

        monkeypatch.setattr(
            "app.services.memory_image_enumerator.get_detection_roots",
            fake_roots,
        )

        aggregate = await _do_memory_image_enumeration(db, firmware.id)
        assert aggregate["image_count"] == 1

        rows = (
            (
                await db.execute(
                    select(MemoryDumpImage).where(
                        MemoryDumpImage.firmware_id == firmware.id
                    )
                )
            )
            .scalars()
            .all()
        )
        # Stale row gone; only the current image remains.
        assert len(rows) == 1
        assert rows[0].image_filename == "current.raw"


@pytest.mark.asyncio
async def test_do_memory_image_enumeration_no_detection_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty detection roots → empty aggregate, no DB writes."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="no-roots")
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

        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return []

        monkeypatch.setattr(
            "app.services.memory_image_enumerator.get_detection_roots",
            fake_roots,
        )

        aggregate = await _do_memory_image_enumeration(db, firmware.id)
        assert aggregate["image_count"] == 0

        rows = (
            (
                await db.execute(
                    select(MemoryDumpImage).where(
                        MemoryDumpImage.firmware_id == firmware.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows == []


@pytest.mark.asyncio
async def test_do_memory_image_enumeration_firmware_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Firmware vanished between caller + walker → empty aggregate, no crash."""
    async with make_live_db() as db:
        async def fake_roots(*args: Any, **kwargs: Any) -> list[str]:
            return ["/tmp/should-not-be-reached"]

        monkeypatch.setattr(
            "app.services.memory_image_enumerator.get_detection_roots",
            fake_roots,
        )
        aggregate = await _do_memory_image_enumeration(db, uuid.uuid4())
        assert aggregate["image_count"] == 0
        assert aggregate["schema_version"] == 1


# ── Outer wrapper state-machine transitions ──────────────────────────────────


@pytest.mark.asyncio
async def test_run_memory_image_enumeration_background_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outer wrapper drives idle → running → completed + stamps result."""
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
                "schema_version": 1,
                "image_count": 2,
                "total_bytes": 4 * MIN_MEMORY_IMAGE_BYTES,
                "by_os_family": {
                    "windows": 1, "linux": 1, "mac": 0, "unknown": 0
                },
                "elapsed_s": 1.5,
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.memory_image_enumerator._do_memory_image_enumeration",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.memory_image_enumerator.async_session_factory",
            fake_factory,
        )

        await run_memory_image_enumeration_background(firmware.id)

        await db.refresh(firmware)
        assert firmware.memory_dump_walk_status == "completed"
        assert firmware.memory_dump_walk_started_at is not None
        assert firmware.memory_dump_walk_finished_at is not None
        assert firmware.memory_dump_walk_error is None
        result = firmware.memory_dump_walk_result
        assert result is not None
        assert result["image_count"] == 2
        assert result["schema_version"] == 1


@pytest.mark.asyncio
async def test_run_memory_image_enumeration_background_failure_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inner raises → outer captures, transitions to failed, populates error."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="fail")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="fail.bin",
            file_size=2048,
            sha256="f" * 64,
        )
        db.add(firmware)
        await db.commit()

        async def fake_inner(db_arg, fw_id):
            raise RuntimeError("simulated walker boom")

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.memory_image_enumerator._do_memory_image_enumeration",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.memory_image_enumerator.async_session_factory",
            fake_factory,
        )

        await run_memory_image_enumeration_background(firmware.id)

        await db.refresh(firmware)
        assert firmware.memory_dump_walk_status == "failed"
        assert firmware.memory_dump_walk_finished_at is not None
        assert firmware.memory_dump_walk_error is not None
        assert "simulated walker boom" in firmware.memory_dump_walk_error


# ── Safe-runner — does not mutate status ─────────────────────────────────────


@pytest.mark.asyncio
async def test_auto_memory_image_enumeration_safe_leaves_status_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe runner stamps aggregate but leaves status=idle (Rule #33 .a)."""
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
                "schema_version": 1,
                "image_count": 0,
                "total_bytes": 0,
                "by_os_family": {
                    "windows": 0, "linux": 0, "mac": 0, "unknown": 0
                },
                "elapsed_s": 0.0,
            }

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.memory_image_enumerator._do_memory_image_enumeration",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.memory_image_enumerator.async_session_factory",
            fake_factory,
        )

        await auto_memory_image_enumeration_safe(firmware.id)

        await db.refresh(firmware)
        # Status stays idle — the safe runner doesn't transition it.
        assert firmware.memory_dump_walk_status == "idle"
        # But aggregate IS stamped.
        assert firmware.memory_dump_walk_result is not None
        assert firmware.memory_dump_walk_result["schema_version"] == 1


@pytest.mark.asyncio
async def test_auto_memory_image_enumeration_safe_swallows_inner_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe-runner swallows exceptions silently — never propagates up."""
    async with make_live_db() as db:
        project = Project(id=uuid.uuid4(), name="swallow")
        db.add(project)
        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=project.id,
            original_filename="swallow.bin",
            file_size=2048,
            sha256="x" * 64,
        )
        db.add(firmware)
        await db.commit()

        async def fake_inner(db_arg, fw_id):
            raise RuntimeError("inner boom")

        @asynccontextmanager
        async def fake_factory():
            yield db

        monkeypatch.setattr(
            "app.services.memory_image_enumerator._do_memory_image_enumeration",
            fake_inner,
        )
        monkeypatch.setattr(
            "app.services.memory_image_enumerator.async_session_factory",
            fake_factory,
        )

        # No raise — the safe-runner swallows.
        await auto_memory_image_enumeration_safe(firmware.id)

        await db.refresh(firmware)
        # Status untouched.
        assert firmware.memory_dump_walk_status == "idle"
        # No aggregate stamped (inner raised before producing one).
        # The pre-call value is None (column was never written), so this
        # confirms the safe-runner's exception path is truly silent.
        assert firmware.memory_dump_walk_result is None
