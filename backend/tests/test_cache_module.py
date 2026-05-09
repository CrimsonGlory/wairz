"""Unit tests for ``app.services._cache``.

Follows the project's AsyncMock+MagicMock convention (see
``test_hardware_firmware_cve_matcher.py``). Tests verify the SQL
statements the helpers build and the callback pattern (flush vs commit
ownership), not end-to-end DB behavior — integration coverage comes
from the call-site tests (``test_binary_tools``,
``test_bytecode_analysis``, ``test_compare_apk``, etc.).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.analysis_cache import AnalysisCache
from app.services import _cache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_session(*, execute_returns: list) -> AsyncMock:
    """Build a mock AsyncSession with queued execute() results.

    Each element of ``execute_returns`` is a pre-built SQLAlchemy
    ``Result`` mock (see helpers below) returned by successive
    ``await db.execute(...)`` calls.
    """
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(side_effect=execute_returns)
    return db


def _result_with_first(row) -> MagicMock:
    """Mock a select().scalars().first() chain that yields ``row``."""
    res = MagicMock()
    res.scalars.return_value.first.return_value = row
    return res


def _result_with_scalar_one_or_none(row) -> MagicMock:
    """Mock a select().scalar_one_or_none() chain that yields ``row``."""
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    return res


def _result_with_rowcount(n: int) -> MagicMock:
    res = MagicMock()
    res.rowcount = n
    return res


# ---------------------------------------------------------------------------
# get_cached
# ---------------------------------------------------------------------------


class TestGetCached:
    @pytest.mark.asyncio
    async def test_returns_dict_when_row_exists(self) -> None:
        db = _mock_session(
            execute_returns=[_result_with_first({"findings": ["hit"]})],
        )
        out = await _cache.get_cached(
            db, uuid.uuid4(), "cwe_checker", binary_sha256="abc",
        )
        assert out == {"findings": ["hit"]}

    @pytest.mark.asyncio
    async def test_returns_none_when_row_missing(self) -> None:
        db = _mock_session(execute_returns=[_result_with_first(None)])
        out = await _cache.get_cached(
            db, uuid.uuid4(), "cwe_checker", binary_sha256="abc",
        )
        assert out is None

    @pytest.mark.asyncio
    async def test_returns_none_when_result_is_not_dict(self) -> None:
        # Defensive: the column is JSONB so PostgreSQL can store any JSON
        # value; if a caller stored a bare string or list, guard returns None.
        db = _mock_session(execute_returns=[_result_with_first("not a dict")])
        out = await _cache.get_cached(
            db, uuid.uuid4(), "cwe_checker", binary_sha256="abc",
        )
        assert out is None

    @pytest.mark.asyncio
    async def test_firmware_wide_key_uses_is_null(self) -> None:
        # When binary_sha256=None, the helper must filter
        # binary_sha256 IS NULL — not "binary_sha256 == None" (which would
        # render as "= NULL" and match zero rows).
        db = _mock_session(execute_returns=[_result_with_first(None)])
        await _cache.get_cached(db, uuid.uuid4(), "firmware_metadata")
        stmt = db.execute.call_args[0][0]
        compiled_sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "IS NULL" in compiled_sql

    @pytest.mark.asyncio
    async def test_per_binary_key_does_not_use_is_null(self) -> None:
        db = _mock_session(execute_returns=[_result_with_first(None)])
        await _cache.get_cached(
            db, uuid.uuid4(), "cwe_checker", binary_sha256="deadbeef",
        )
        stmt = db.execute.call_args[0][0]
        compiled_sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "IS NULL" not in compiled_sql
        assert "deadbeef" in compiled_sql


# ---------------------------------------------------------------------------
# exists_cached
# ---------------------------------------------------------------------------


class TestExistsCached:
    @pytest.mark.asyncio
    async def test_true_when_row_exists(self) -> None:
        db = _mock_session(
            execute_returns=[_result_with_scalar_one_or_none(uuid.uuid4())],
        )
        assert await _cache.exists_cached(
            db, uuid.uuid4(), "ghidra_full_analysis", binary_sha256="abc",
        )

    @pytest.mark.asyncio
    async def test_false_when_row_missing(self) -> None:
        db = _mock_session(
            execute_returns=[_result_with_scalar_one_or_none(None)],
        )
        assert not await _cache.exists_cached(
            db, uuid.uuid4(), "ghidra_full_analysis", binary_sha256="abc",
        )

    @pytest.mark.asyncio
    async def test_selects_id_not_full_row(self) -> None:
        # Cheap probe — selecting ``id`` only avoids pulling the multi-MB
        # JSONB result column for a presence check.
        db = _mock_session(
            execute_returns=[_result_with_scalar_one_or_none(None)],
        )
        await _cache.exists_cached(
            db, uuid.uuid4(), "jadx_decompilation", binary_sha256="abc",
        )
        stmt = db.execute.call_args[0][0]
        compiled_sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "analysis_cache.result" not in compiled_sql
        assert "analysis_cache.id" in compiled_sql


# ---------------------------------------------------------------------------
# store_cached
# ---------------------------------------------------------------------------


class TestStoreCached:
    @pytest.mark.asyncio
    async def test_delete_then_insert_per_binary(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(0)])
        fw_id = uuid.uuid4()
        await _cache.store_cached(
            db,
            fw_id,
            "cwe_checker",
            {"warnings": []},
            binary_sha256="abc",
            binary_path="/bin/foo",
        )
        # One DELETE then add() for INSERT
        assert db.execute.call_count == 1
        delete_stmt = db.execute.call_args[0][0]
        compiled_delete = str(delete_stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "DELETE FROM analysis_cache" in compiled_delete
        assert "abc" in compiled_delete
        # Insert side: db.add(entry) called once, flush once
        assert db.add.call_count == 1
        entry = db.add.call_args[0][0]
        assert isinstance(entry, AnalysisCache)
        assert entry.firmware_id == fw_id
        assert entry.operation == "cwe_checker"
        assert entry.binary_sha256 == "abc"
        assert entry.binary_path == "/bin/foo"
        # store_cached stamps the result with `schema_version` via
        # _stamp_analysis_cache_result (jsonb_normalizers.py:134). Pop
        # the stamp before comparing the writer-supplied payload.
        result = dict(entry.result)
        stamp = result.pop("schema_version", None)
        assert stamp == 1
        assert result == {"warnings": []}
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_firmware_wide_uses_is_null_in_delete(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(0)])
        await _cache.store_cached(
            db, uuid.uuid4(), "firmware_metadata", {"sections": []},
        )
        delete_stmt = db.execute.call_args[0][0]
        compiled_delete = str(delete_stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "IS NULL" in compiled_delete
        # And the inserted row has NULL binary_sha256 / binary_path
        entry = db.add.call_args[0][0]
        assert entry.binary_sha256 is None
        assert entry.binary_path is None

    @pytest.mark.asyncio
    async def test_does_not_commit_only_flushes(self) -> None:
        # Rule #3: MCP handlers and routers own the transaction; helpers flush.
        db = _mock_session(execute_returns=[_result_with_rowcount(0)])
        await _cache.store_cached(
            db, uuid.uuid4(), "op", {"x": 1}, binary_sha256="h",
        )
        db.flush.assert_awaited_once()
        # db is an AsyncMock; hasattr() auto-creates attributes, so use call
        # assertions on the commit attribute instead.
        db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# invalidate_firmware
# ---------------------------------------------------------------------------


class TestInvalidateFirmware:
    @pytest.mark.asyncio
    async def test_deletes_all_rows_for_firmware(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(7)])
        fw_id = uuid.uuid4()
        count = await _cache.invalidate_firmware(db, fw_id)
        assert count == 7
        delete_stmt = db.execute.call_args[0][0]
        compiled = str(delete_stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "DELETE FROM analysis_cache" in compiled
        # SQLAlchemy compiles UUID literals hyphenless (32-char hex).
        assert fw_id.hex in compiled
        # No operation / sha filter — deletes EVERY row for this firmware_id.
        assert "operation" not in compiled.split("WHERE")[-1]
        assert "binary_sha256" not in compiled.split("WHERE")[-1]
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_zero_when_none_matched(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(0)])
        count = await _cache.invalidate_firmware(db, uuid.uuid4())
        assert count == 0


# ---------------------------------------------------------------------------
# cleanup_older_than
# ---------------------------------------------------------------------------


class TestCleanupOlderThan:
    @pytest.mark.asyncio
    async def test_deletes_rows_older_than_cutoff(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(42)])
        count = await _cache.cleanup_older_than(db, days=30)
        assert count == 42
        delete_stmt = db.execute.call_args[0][0]
        compiled = str(delete_stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "DELETE FROM analysis_cache" in compiled
        assert "created_at" in compiled
        # Rough sanity on the cutoff being ~30 days back.
        approx_cutoff = datetime.now(UTC) - timedelta(days=30)
        assert str(approx_cutoff.year) in compiled
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_zero_when_none_expired(self) -> None:
        db = _mock_session(execute_returns=[_result_with_rowcount(0)])
        assert await _cache.cleanup_older_than(db, days=90) == 0
