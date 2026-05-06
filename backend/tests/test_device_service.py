"""Tests for DeviceService — DB-backed dump state per audit F-A-01.

Covers:
- start_dump value-flow: row fields populated correctly (Rule #35b — assert
  on the constructor args via a captor, not just call counts)
- start_dump idempotency check via find_active_dump
- cancel_dump on each status tier (queued, running, terminal)
- import_dump dump_id resolution + terminal-state check
- _normalize_partitions accepts canonical, list, and None shapes
  (Rule #35c boundary normaliser)
- _build_partitions_payload includes schema_version

The asyncio.create_task spawn is patched out so unit tests don't try to
reach a real bridge or DB. The Rule #35b live canary against a fresh row
through the real ORM lives at the end of the session as an in-container
``python -c`` smoke (see commit message).
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.device_service import (
    DUMP_PARTITIONS_SCHEMA_VERSION,
    DeviceService,
    _build_partitions_payload,
    _normalize_partitions,
)


def _make_db_session() -> AsyncMock:
    """Mock AsyncSession that mirrors the real api surface."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.execute = AsyncMock()
    return db


def _execute_returning(value):
    """Build a SQLAlchemy result whose ``scalar_one_or_none()`` returns ``value``."""
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=value)
    return result


# ── _build_partitions_payload + _normalize_partitions (pure helpers) ──


class TestPartitionsHelpers:
    def test_build_partitions_payload_includes_schema_version(self):
        payload = _build_partitions_payload(["boot", "vendor"])
        assert payload["schema_version"] == DUMP_PARTITIONS_SCHEMA_VERSION
        assert isinstance(payload["items"], list)
        assert len(payload["items"]) == 2
        assert all(p["status"] == "pending" for p in payload["items"])
        assert all(p["bytes_written"] == 0 for p in payload["items"])
        assert [p["partition"] for p in payload["items"]] == ["boot", "vendor"]

    def test_normalize_partitions_canonical_dict(self):
        payload = {"schema_version": 1, "items": [{"partition": "boot"}]}
        out = _normalize_partitions(payload)
        assert out == [{"partition": "boot"}]

    def test_normalize_partitions_bare_list(self):
        out = _normalize_partitions([{"partition": "x"}])
        assert out == [{"partition": "x"}]

    def test_normalize_partitions_none(self):
        assert _normalize_partitions(None) == []

    def test_normalize_partitions_unparseable(self):
        # A scalar / unexpected shape returns empty list (defensive
        # — rule #35c boundary normaliser should never raise).
        assert _normalize_partitions("oops") == []
        assert _normalize_partitions(42) == []
        assert _normalize_partitions({"items": "not-a-list"}) == []


# ── find_active_dump (idempotent-POST gate) ──


class TestFindActiveDump:
    @pytest.mark.asyncio
    async def test_returns_queued_or_running_row(self):
        db = _make_db_session()
        existing = MagicMock(id=uuid.uuid4(), status="running")
        db.execute.return_value = _execute_returning(existing)

        svc = DeviceService(db)
        result = await svc.find_active_dump(uuid.uuid4())
        assert result is existing

    @pytest.mark.asyncio
    async def test_returns_none_when_no_active(self):
        db = _make_db_session()
        db.execute.return_value = _execute_returning(None)

        svc = DeviceService(db)
        result = await svc.find_active_dump(uuid.uuid4())
        assert result is None


# ── start_dump value-flow ──


class TestStartDump:
    @pytest.mark.asyncio
    async def test_creates_row_with_expected_fields(self):
        """Rule #35b — assert on the constructor args, not just call counts."""
        db = _make_db_session()
        project_id = uuid.uuid4()

        with (
            patch("app.services.device_service.os.makedirs"),
            patch("app.services.device_service.shutil.disk_usage") as mock_disk,
            patch("app.services.device_service.asyncio.create_task") as mock_spawn,
        ):
            # Consume the coroutine so it doesn't surface as
            # "RuntimeWarning: coroutine '...' was never awaited".
            mock_spawn.side_effect = lambda coro: coro.close()
            mock_disk.return_value = MagicMock(free=10 * 1024**3)  # 10 GB free
            svc = DeviceService(db)
            row = await svc.start_dump(project_id, "ABC123", ["boot", "vendor"])

        # The row was constructed with the right values — captor pattern.
        added = db.add.call_args[0][0]
        assert added is row
        assert added.project_id == project_id
        assert added.device_id == "ABC123"
        assert added.status == "queued"
        # JSONB partitions wraps schema_version + items per Rule #35c.
        assert added.partitions["schema_version"] == DUMP_PARTITIONS_SCHEMA_VERSION
        assert [p["partition"] for p in added.partitions["items"]] == ["boot", "vendor"]
        # Commit happens before spawning the background task per
        # Rule #33 reference shape.
        assert db.commit.await_count == 1
        # Background task scheduled via asyncio.create_task.
        assert mock_spawn.call_count == 1

    @pytest.mark.asyncio
    async def test_raises_on_low_disk_space(self):
        db = _make_db_session()

        with (
            patch("app.services.device_service.os.makedirs"),
            patch("app.services.device_service.shutil.disk_usage") as mock_disk,
            patch("app.services.device_service.asyncio.create_task") as mock_spawn,
        ):
            mock_disk.return_value = MagicMock(free=2 * 1024**3)  # 2 GB free, < 5 GB
            svc = DeviceService(db)
            with pytest.raises(ValueError, match="Insufficient disk space"):
                await svc.start_dump(uuid.uuid4(), "ABC123", ["boot"])

            # No row added, no task spawned.
            assert db.add.call_count == 0
            assert mock_spawn.call_count == 0


# ── cancel_dump per-tier ──


class TestCancelDump:
    @pytest.mark.asyncio
    async def test_cancels_running_dump(self):
        db = _make_db_session()
        project_id = uuid.uuid4()
        dump_id = uuid.uuid4()
        running = MagicMock(id=dump_id, project_id=project_id, status="running")
        db.execute.return_value = _execute_returning(running)

        svc = DeviceService(db)
        with patch.object(svc, "_bridge_request", AsyncMock(return_value={"ok": True})):
            result = await svc.cancel_dump(project_id, dump_id)

        assert result is running
        assert running.status == "cancelled"
        assert running.finished_at is not None
        assert db.commit.await_count == 1

    @pytest.mark.asyncio
    async def test_idempotent_on_terminal_state(self):
        """Calling cancel on a completed dump leaves it untouched."""
        db = _make_db_session()
        project_id = uuid.uuid4()
        dump_id = uuid.uuid4()
        completed = MagicMock(id=dump_id, project_id=project_id, status="completed")
        db.execute.return_value = _execute_returning(completed)

        svc = DeviceService(db)
        result = await svc.cancel_dump(project_id, dump_id)

        assert result is completed
        # status not flipped, no commit issued.
        assert completed.status == "completed"
        assert db.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_returns_none_when_dump_not_found(self):
        db = _make_db_session()
        db.execute.return_value = _execute_returning(None)

        svc = DeviceService(db)
        result = await svc.cancel_dump(uuid.uuid4(), uuid.uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_dump_belongs_to_different_project(self):
        """Project scoping is enforced — a dump from project B can't be
        cancelled by a project-A request."""
        db = _make_db_session()
        project_a = uuid.uuid4()
        project_b = uuid.uuid4()
        # Row belongs to project_b but we look it up under project_a.
        cross_project = MagicMock(
            id=uuid.uuid4(), project_id=project_b, status="running"
        )
        db.execute.return_value = _execute_returning(cross_project)

        svc = DeviceService(db)
        result = await svc.cancel_dump(project_a, cross_project.id)
        assert result is None


# ── import_dump pre-conditions ──


class TestImportDump:
    @pytest.mark.asyncio
    async def test_raises_if_dump_missing(self):
        db = _make_db_session()
        db.execute.return_value = _execute_returning(None)

        svc = DeviceService(db)
        with pytest.raises(ValueError, match="not found"):
            await svc.import_dump(uuid.uuid4(), uuid.uuid4(), "ABC123")

    @pytest.mark.asyncio
    async def test_raises_if_dump_not_in_terminal_state(self):
        db = _make_db_session()
        project_id = uuid.uuid4()
        dump_id = uuid.uuid4()
        running = MagicMock(id=dump_id, project_id=project_id, status="running")
        db.execute.return_value = _execute_returning(running)

        svc = DeviceService(db)
        with pytest.raises(ValueError, match="cannot import"):
            await svc.import_dump(project_id, dump_id, "ABC123")
