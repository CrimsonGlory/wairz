"""Shared SQLite-backed live-DB fixture for Rule #35b live-canary tests.

Per CLAUDE.md Rule #35b, every new test file must include at least one
test that does a real ORM round-trip + SELECT — not just `mock.assert_called`
— so the value-flow contract (constructor args → persisted columns) is
verified end-to-end.

This helper builds an in-memory SQLite engine that can serve the production
ORM models. PostgreSQL-only types are shimmed to SQLite-compatible
equivalents:

- ``JSONB`` → ``JSON`` (DDL) + ``json.dumps``/``json.loads`` (bind/result)
- ``ARRAY(...)`` (both ``sqlalchemy.dialects.postgresql.ARRAY`` and the
  generic ``sqlalchemy.types.ARRAY``) → ``JSON`` + json serialization
- ``UUID`` (PG-specific) → ``VARCHAR(36)``

The shim is registered at module-import time, so importing this module
once (typically from a test fixture) is enough to make all subsequent
``Base.metadata.create_all`` calls produce SQLite-compatible DDL. The
production runtime (PostgreSQL) is unaffected because the registered
``@compiles`` decorators only fire when ``dialect.name == 'sqlite'``.

Usage::

    import pytest
    from tests._live_db import make_live_db

    @pytest.fixture
    async def live_db():
        async for db in make_live_db():
            yield db

    @pytest.mark.asyncio
    async def test_persists_confidence(live_db):
        # ... seed rows + run service code ...
        # Then SELECT the persisted row and inspect.
        row = (await live_db.execute(select(Finding))).scalar_one()
        assert row.confidence == "high"
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.dialects.postgresql import ARRAY as PGARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import ARRAY as GenARRAY


# ---------------------------------------------------------------------------
# DDL-time shims: render PG-only types as SQLite-friendly equivalents.
#
# Why TEXT and not JSON for JSONB / ARRAY:
#
# SQLite has a "JSON" column type since 3.45, and SQLAlchemy's SQLite dialect
# applies its OWN ``json_deserializer`` result processor on top of the
# column's bind/result processors when the rendered DDL type is JSON (see
# sqlalchemy/dialects/sqlite/base.py:1045 → sqltypes.py:2820). Combined with
# our explicit JSONB.bind_processor / .result_processor below, that produces
# a double-decode chain that bombs on ``server_default="'{}'"`` round-trips
# at flush time:
#
#     json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
#
# Discovered Wave 1 (EmulationSession.port_forwards), confirmed Wave 2
# (FuzzingCampaign.config + .stats). Bare-string server_defaults
# (``server_default="'{}'"``) trigger this; ``server_default=text("'{}'")``
# avoids it via a different SQLAlchemy code path. Rendering JSONB / ARRAY
# as TEXT removes the SQLite-dialect JSON processor entirely, leaving only
# our shims — single decode, no conflict, ``server_default``s round-trip.
# ---------------------------------------------------------------------------
@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(element, compiler, **kw):  # noqa: ARG001
    return "TEXT"


@compiles(PGARRAY, "sqlite")
def _compile_pg_array_sqlite(element, compiler, **kw):  # noqa: ARG001
    return "TEXT"


@compiles(GenARRAY, "sqlite")
def _compile_generic_array_sqlite(element, compiler, **kw):  # noqa: ARG001
    return "TEXT"


@compiles(PGUUID, "sqlite")
def _compile_uuid_sqlite(element, compiler, **kw):  # noqa: ARG001
    return "VARCHAR(36)"


# ---------------------------------------------------------------------------
# Bind/result shims: serialize Python list/dict ↔ JSON for SQLite.
# Each closure captures ``dialect.name`` once at processor-creation time so
# the per-row hot path is a single isinstance check.
# ---------------------------------------------------------------------------
def _make_bind(self, dialect):
    if dialect.name != "sqlite":
        return None
    return lambda v: None if v is None else json.dumps(v)


def _make_result(self, dialect, coltype):  # noqa: ARG001
    """Result processor that survives the bare-string server_default round-trip.

    When a JSONB column declares ``server_default="'{}'"`` (bare-string SQL
    fragment), the value stored AND read back is the literal string ``'{}'``
    (with single quotes intact — SQLAlchemy doesn't strip the outer SQL
    quoting before passing to result processors). Naïve ``json.loads("'{}'")``
    raises ``JSONDecodeError`` on the unbalanced quotes. Strip the outer
    quotes and retry; final fallback returns the value as-is so the test
    surfaces a useful error rather than masking it.
    """
    if dialect.name != "sqlite":
        return None

    def _process(v):
        if v is None:
            return None
        if isinstance(v, (list, dict)):
            return v
        if isinstance(v, str):
            if v.startswith("'") and v.endswith("'"):
                v = v[1:-1]
            try:
                return json.loads(v)
            except (json.JSONDecodeError, ValueError):
                return v
        return v

    return _process


JSONB.bind_processor = _make_bind  # type: ignore[method-assign]
JSONB.result_processor = _make_result  # type: ignore[method-assign]
PGARRAY.bind_processor = _make_bind  # type: ignore[method-assign]
PGARRAY.result_processor = _make_result  # type: ignore[method-assign]
GenARRAY.bind_processor = _make_bind  # type: ignore[method-assign]
GenARRAY.result_processor = _make_result  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Engine + session factory.
# ---------------------------------------------------------------------------
def _dedup_indexes() -> None:
    """Strip duplicate index entries from ORM table metadata.

    A few wairz models declare a column with ``index=True`` AND repeat the
    same index in ``__table_args__`` (e.g. ``Firmware.project_id``). PG
    silently deduplicates by name; SQLite raises ``index already exists``
    on the second CREATE. Drop the second occurrence here so SQLite-
    backed live-canary tests succeed without changing production models.
    """
    from app.models.firmware import Firmware

    for table in (Firmware.__table__,):
        seen: set[str] = set()
        duplicates = []
        for idx in list(table.indexes):
            if idx.name in seen:
                duplicates.append(idx)
            else:
                seen.add(idx.name)
        for d in duplicates:
            table.indexes.remove(d)


@asynccontextmanager
async def make_live_db() -> AsyncIterator[AsyncSession]:
    """Yield a fresh in-memory SQLite session with production tables created.

    The engine is per-call; the in-memory database is destroyed when the
    session closes, so tests are fully isolated from each other.

    Usage::

        async with make_live_db() as db:
            ...

    Implemented as ``@asynccontextmanager`` (NOT a bare async generator
    consumed via ``async for ... break``). When a consumer ``break``s out
    of an async-generator loop, GeneratorExit fires inside an
    ``async with`` body — and aiosqlite's pool teardown can stall on the
    pending connection-close awaitable, leaving pytest's session-end
    teardown blocked indefinitely (observed mid-suite hang on the
    audit-2026-05-04 Phase 1 backfill sweep). The contextmanager
    discipline guarantees deterministic ``__aexit__`` cleanup.
    """
    # Importing models triggers SQLAlchemy mapper registration on Base.metadata.
    # Every module whose model declares an FK target referenced by another
    # in-test module MUST be in this list — otherwise `create_all` raises
    # NoReferencedTableError. The volatility/memory_dump triple is required
    # because volatility_injection_records.memory_image_id FK targets the
    # memory_dump_image table (see Rule #35b live-canary discipline +
    # 2026-05-21 SBOM/vuln-scan regression investigation Fix #10).
    from app.database import Base
    from app.models import (  # noqa: F401
        analysis_cache,
        finding,
        firmware,
        memory_dump_image,
        project,
        sbom,
        volatility_injection_record,
        volatility_process_record,
    )

    _dedup_indexes()

    # StaticPool: every operation reuses the SAME aiosqlite connection so the
    # `:memory:` database persists across `db.execute()` calls within the
    # session (every connection gets its own in-memory DB otherwise — NullPool
    # would reset the schema on every operation).
    #
    # Why not the default pool: aiosqlite's QueuePool keeps idle connections
    # in a background thread-pool that pytest's session teardown can't reap
    # before the runner exits — observed mid-suite hang on the
    # audit-2026-05-04 Phase 1 backfill where a multi-file sweep would print
    # the first file's dots and then sit in `ep_poll` indefinitely.
    # StaticPool's single-connection model has nothing for dispose() to await.
    from sqlalchemy.pool import StaticPool

    def _tolerant_json_loads(s):
        """Tolerant JSON decoder for SQLite server_default round-trips.

        SQLAlchemy's ``JSON.result_processor`` calls
        ``json_deserializer(value)`` after our shim has already decoded.
        For columns with bare-string ``server_default="'{}'"``, the value
        comes back as the literal string ``'{}'`` (with quotes); naïve
        ``json.loads`` would raise ``JSONDecodeError`` (Wave 1+2 discovery).
        Strip outer single-quotes (the SQL-string-literal artefact) and
        retry; final fallback returns the string unchanged so the test
        surfaces a useful error rather than masking it.
        """
        if isinstance(s, (list, dict)):
            return s
        if isinstance(s, str):
            if s.startswith("'") and s.endswith("'"):
                s = s[1:-1]
            try:
                return json.loads(s)
            except (json.JSONDecodeError, ValueError):
                return s
        return s

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        json_deserializer=_tolerant_json_loads,
    )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as db:
            yield db
    finally:
        await engine.dispose()
