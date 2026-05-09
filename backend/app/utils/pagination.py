"""Helper for pagination against SQLAlchemy async sessions.

Call signature::

    items, total = await paginate_query(db, stmt, offset=0, limit=100)

For ``select(Model)`` style statements, ``items`` is the result of
``.scalars().all()``.  For composite ``select(Model, col, col)`` style
statements (e.g. vulnerabilities joined with component name/version) use
``paginate_query_rows`` which returns ``Row`` objects unchanged — the
caller owns the row-to-response shaping.

The count is built by wrapping the statement in a subquery:
``select(func.count()).select_from(stmt.subquery())``.  This works for
joins, filters, and ``order_by`` because the subquery erases the ORDER
BY cost.  We strip any ORDER BY from the count path for Postgres
efficiency — ``count()`` over an unordered subquery is cheaper.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def paginate_query(
    db: AsyncSession,
    stmt: Select[Any],
    *,
    offset: int,
    limit: int,
) -> tuple[Sequence[Any], int]:
    """Execute ``stmt`` paginated; return ``(items_via_scalars, total)``.

    Use this when ``stmt`` is ``select(Model)`` — i.e. the rows coming
    back are single ORM instances and you want ``.scalars().all()``.
    """
    total = await _count_for(db, stmt)
    paged = stmt.offset(offset).limit(limit)
    result = await db.execute(paged)
    return result.scalars().all(), total


async def paginate_query_rows(
    db: AsyncSession,
    stmt: Select[Any],
    *,
    offset: int,
    limit: int,
) -> tuple[Sequence[Any], int]:
    """Execute ``stmt`` paginated; return ``(row_objects, total)``.

    Use this when ``stmt`` is a composite ``select(Model, col, col)`` —
    the caller needs direct access to the row tuples.
    """
    total = await _count_for(db, stmt)
    paged = stmt.offset(offset).limit(limit)
    result = await db.execute(paged)
    return result.all(), total


async def _count_for(db: AsyncSession, stmt: Select[Any]) -> int:
    """Count rows that ``stmt`` would produce, ignoring ORDER BY."""
    # ``order_by(None)`` clears any ORDER BY clause — Postgres doesn't
    # need it for COUNT, and some engines reject ORDER BY inside a
    # subquery when paired with aggregate functions.
    bare = stmt.order_by(None)
    count_stmt = select(func.count()).select_from(bare.subquery())
    return (await db.execute(count_stmt)).scalar_one()
