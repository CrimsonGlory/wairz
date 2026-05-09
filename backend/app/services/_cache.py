"""Canonical cache access for the ``analysis_cache`` table.

Consolidates the ten parallel inline implementations that previously
reinvented the same "fetch-or-store cached analysis result" query into a
single module. Every service, MCP tool handler, and router that caches
firmware analysis output should use these helpers rather than querying
:class:`~app.models.analysis_cache.AnalysisCache` directly.

## Semantics

- ``binary_sha256=None`` selects/stores the **firmware-wide** cache entry
  (used by ``firmware_metadata_service``, ``component_map``, etc.). In
  PostgreSQL, nulls are distinct in unique indexes, so these entries
  coexist safely with per-binary rows under the ``idx_cache_lookup``
  index.
- ``store_cached`` uses delete-then-insert, which is idempotent under
  both the unique-constraint and constraint-absent cases. Every previous
  inline implementation relied on the unique constraint for idempotency;
  the ``cwe_checker_service`` variant was missing the defensive DELETE
  and would silently accumulate duplicates if the constraint were
  dropped — this module fixes that drift.

## Transaction ownership

Every helper issues ``flush()`` only — the caller owns ``commit()``:
MCP tool handlers rely on the outer dispatch in ``mcp_server.py`` (see
CLAUDE.md rule #3); REST routers and arq workers commit themselves.

## Cron

``cleanup_older_than`` is called from
``app.workers.arq_worker.cleanup_analysis_cache`` on a daily schedule.
The retention window is ``settings.analysis_cache_retention_days``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_cache import AnalysisCache
from app.services.jsonb_normalizers import (
    _normalize_analysis_cache_result,
    _stamp_analysis_cache_result,
)


async def exists_cached(
    db: AsyncSession,
    firmware_id: UUID,
    operation: str,
    *,
    binary_sha256: str | None = None,
) -> bool:
    """Return ``True`` if a cache row exists for this key.

    Cheaper than :func:`get_cached` when the caller only needs a presence
    probe (e.g., "has this binary already been analysed?") — selects
    ``id`` instead of the full JSONB ``result`` blob.
    """
    conditions = [
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.operation == operation,
    ]
    if binary_sha256 is not None:
        conditions.append(AnalysisCache.binary_sha256 == binary_sha256)
    else:
        conditions.append(AnalysisCache.binary_sha256.is_(None))

    stmt = select(AnalysisCache.id).where(*conditions).limit(1)
    return (await db.execute(stmt)).scalar_one_or_none() is not None


async def get_cached(
    db: AsyncSession,
    firmware_id: UUID,
    operation: str,
    *,
    binary_sha256: str | None = None,
) -> dict | None:
    """Fetch a cached result dict or ``None``.

    When ``binary_sha256`` is ``None``, matches the firmware-wide cache
    entry (the ``binary_sha256 IS NULL`` row). When a hex digest is
    supplied, matches the corresponding per-binary row.

    The helper selects only the ``result`` JSONB column to keep the
    round-trip small; it returns ``None`` both for a missing row and
    for a row whose ``result`` is ``NULL``.
    """
    conditions = [
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.operation == operation,
    ]
    if binary_sha256 is not None:
        conditions.append(AnalysisCache.binary_sha256 == binary_sha256)
    else:
        conditions.append(AnalysisCache.binary_sha256.is_(None))

    stmt = select(AnalysisCache.result).where(*conditions).limit(1)
    row = (await db.execute(stmt)).scalars().first()
    return _normalize_analysis_cache_result(row)


async def store_cached(
    db: AsyncSession,
    firmware_id: UUID,
    operation: str,
    result: dict[str, Any],
    *,
    binary_sha256: str | None = None,
    binary_path: str | None = None,
) -> None:
    """Idempotent upsert: delete any existing row, insert new one, flush.

    Handles both per-binary (``binary_sha256``+``binary_path`` supplied)
    and firmware-wide (both ``None``) cache keys. Uses delete-then-insert
    so the result is correct even when the unique constraint is missing
    or temporarily loosened during a migration.
    """
    delete_conditions = [
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.operation == operation,
    ]
    if binary_sha256 is not None:
        delete_conditions.append(AnalysisCache.binary_sha256 == binary_sha256)
    else:
        delete_conditions.append(AnalysisCache.binary_sha256.is_(None))

    await db.execute(delete(AnalysisCache).where(*delete_conditions))
    db.add(
        AnalysisCache(
            firmware_id=firmware_id,
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            operation=operation,
            result=_stamp_analysis_cache_result(result),
        )
    )
    await db.flush()


async def invalidate_firmware(db: AsyncSession, firmware_id: UUID) -> int:
    """Delete all cache entries for a firmware. Returns the row count.

    The ``analysis_cache.firmware_id`` FK already has ``ON DELETE
    CASCADE``, so dropping the firmware itself removes cache rows for
    free. Use this helper for explicit invalidation without removing
    the firmware (e.g., after a re-analysis request).
    """
    result = await db.execute(
        delete(AnalysisCache).where(AnalysisCache.firmware_id == firmware_id)
    )
    await db.flush()
    return result.rowcount or 0


async def cleanup_older_than(db: AsyncSession, *, days: int) -> int:
    """Delete cache rows older than ``days`` days. Returns the row count.

    Called from the ``cleanup_analysis_cache`` arq cron job. The caller
    owns the commit — this helper only flushes.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = await db.execute(
        delete(AnalysisCache).where(AnalysisCache.created_at < cutoff)
    )
    await db.flush()
    return result.rowcount or 0
