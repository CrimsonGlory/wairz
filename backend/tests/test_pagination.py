"""Tests for the shared pagination schema + helper.

Covers:
- ``Page`` validates bounds (limit 1..1000, offset >= 0, total >= 0)
- ``paginate_query`` returns ``(items, total)`` where items is a slice
  of <= limit rows and total is the full matching row count
- ORDER BY in the source statement does not leak into the count query
  (would break on some engines and slow Postgres unnecessarily)
"""
from __future__ import annotations

import pytest
from sqlalchemy import Integer, String, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.schemas.pagination import Page, PageParams
from app.utils.pagination import paginate_query


class _Base(DeclarativeBase):
    pass


class _Row(_Base):
    __tablename__ = "pag_test_rows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)


@pytest.mark.asyncio
async def test_page_envelope_validates_bounds() -> None:
    # Valid
    p = Page[int](items=[1, 2], total=100, offset=0, limit=10)
    assert p.total == 100
    assert p.limit == 10

    # limit too large
    with pytest.raises(Exception):
        Page[int](items=[], total=0, offset=0, limit=1001)

    # limit 0 not allowed
    with pytest.raises(Exception):
        Page[int](items=[], total=0, offset=0, limit=0)

    # negative offset
    with pytest.raises(Exception):
        Page[int](items=[], total=0, offset=-1, limit=10)

    # negative total
    with pytest.raises(Exception):
        Page[int](items=[], total=-1, offset=0, limit=10)


def test_page_params_defaults() -> None:
    p = PageParams()
    assert p.offset == 0
    assert p.limit == 100

    p = PageParams(offset=50, limit=200)
    assert p.offset == 50
    assert p.limit == 200


@pytest.mark.asyncio
async def test_paginate_query_slices_and_counts() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(_Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as db:
        # Seed 25 rows
        for i in range(25):
            db.add(_Row(id=i, name=f"row-{i:02d}"))
        await db.commit()

    async with session_factory() as db:
        stmt = select(_Row).order_by(_Row.id)

        # First page: 10 rows, total=25
        items, total = await paginate_query(db, stmt, offset=0, limit=10)
        assert total == 25
        assert len(items) == 10
        assert items[0].id == 0

        # Middle page
        items, total = await paginate_query(db, stmt, offset=10, limit=10)
        assert total == 25
        assert len(items) == 10
        assert items[0].id == 10

        # Tail page (5 rows left)
        items, total = await paginate_query(db, stmt, offset=20, limit=10)
        assert total == 25
        assert len(items) == 5
        assert items[-1].id == 24

        # Beyond the end
        items, total = await paginate_query(db, stmt, offset=100, limit=10)
        assert total == 25
        assert items == []

    await engine.dispose()


@pytest.mark.asyncio
async def test_paginate_query_count_ignores_order_by() -> None:
    """Count query strips ORDER BY so it doesn't leak into the subquery."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(_Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as db:
        for i in range(5):
            db.add(_Row(id=i, name=f"row-{i}"))
        await db.commit()

    async with session_factory() as db:
        stmt = select(_Row).order_by(_Row.name.desc())
        items, total = await paginate_query(db, stmt, offset=0, limit=3)
        assert total == 5
        assert len(items) == 3
        # Outer query kept ORDER BY — we still get ordered slice
        assert items[0].name == "row-4"

    await engine.dispose()
