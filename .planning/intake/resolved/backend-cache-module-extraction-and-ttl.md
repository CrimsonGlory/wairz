---
title: "Backend: Extract Shared Cache Module + Add TTL Cleanup"
status: completed
priority: high
target: backend/app/services/, backend/app/workers/
completed_at: 2026-04-19
completed_via: "session 93a4948d — commits d100595..618ee09 (10 call sites migrated, cron + tests shipped)"
---

## Status: Completed 2026-04-19 (session 93a4948d)

### What shipped (13 commits `d100595..2a27175`)

| Commit | Scope |
|---|---|
| `d100595` | `backend/app/services/_cache.py` — 5 helpers (get_cached, exists_cached, store_cached, invalidate_firmware, cleanup_older_than); `analysis_cache_retention_days` in Settings |
| `5808555` | ghidra_service.py — 3 sites (existence probe, get, upsert) |
| `b5f2432` | cwe_checker_service.py — 2 sites (fixes missing delete-then-insert bug) |
| `1b84726` | jadx_service.py — 3 sites |
| `909101c` | mobsfscan_service.py — 2 sites |
| `b5212f0` | firmware_metadata_service.py — 2 sites (firmware-wide NULL key) |
| `b5f3a78` | routers/apk_scan.py + ai/tools/android_bytecode.py — 4 sites |
| `404b9c8` | routers/component_map.py + ai/tools/filesystem.py — 4 sites (**scope widening: intake missed these**) |
| `1744fad` | mcp_server.py save_code_cleanup — 1 site (**scope widening: intake missed this**) |
| `618ee09` | arq_worker.py cleanup_analysis_cache_job cron + test_cache_module.py 15 unit tests |
| `835dd70` | mobsfscan.py hoist _cache import to module level |

### Intake scope vs. delivered scope

Intake listed **7 call sites**. Scope-widening grep found **3 additional**: `ai/tools/filesystem.py` (component_map), `routers/component_map.py`, `mcp_server.py` save_code_cleanup — all same pattern. Delivered = **10 sites migrated**.

Two bulk-pattern sites (`services/export_service.py`, `services/import_service.py`) left alone — they iterate/bulk-insert rather than the "fetch-or-store by key" pattern the intake targets. Not an accidental gap.

### Acceptance criteria (audit result)

| Criterion | Status |
|---|---|
| `grep -rn 'AnalysisCache' backend/app/services backend/app/routers backend/app/ai/tools \| grep -v _cache.py` returns only imports & docstrings | ✓ (2 bulk-pattern files in services/ + GhidraAnalysisCache class name are legitimate residuals) |
| All 7 (+ 3 extra) call sites use `get_cached` / `store_cached` | ✓ |
| `backend/tests/test_cache_module.py` covers: set-then-get, idempotent re-store, invalidate_firmware, cleanup_older_than, exists_cached | ✓ (15 test methods across 5 test classes) |
| Cron job runs successfully and deletes old rows | ✓ (live smoke: `{status:ok, retention_days:30, deleted:0}`) |
| Retention config (`analysis_cache_retention_days`) honored | ✓ (default 30, wired through) |

### Related intake note

`data-analysis-cache-operation-varchar-fix` prerequisite: already shipped in session `59045370` (alembic `1f6c72decc84` — VARCHAR(100) → VARCHAR(512) for JADX cache keys). No additional work.

---

## Original specification (preserved for reference)

---

## Problem

**Two connected issues.**

### Issue 1 — Five parallel implementations of analysis_cache access

Each reimplements the same "delete-then-insert" pattern against `AnalysisCache`:
- `backend/app/services/ghidra_service.py:248-310` — `GhidraAnalysisCache` class (canonical pattern)
- `backend/app/services/cwe_checker_service.py:109-154` — `_get_cached_result`, `_save_to_cache` (inline)
- `backend/app/services/jadx_service.py:300-340` — inline
- `backend/app/services/mobsfscan_service.py:1006-1041` — inline
- `backend/app/services/firmware_metadata_service.py:158` — inline
- `backend/app/ai/tools/android_bytecode.py:247` — inline
- `backend/app/routers/apk_scan.py:312, 583` — inline

Only `GhidraAnalysisCache` does the defensive DELETE before INSERT — others rely on the unique constraint. If a migration removes or alters the constraint, the others silently accumulate duplicates.

### Issue 2 — No TTL / cleanup on `analysis_cache`

The model has `created_at` but no cleanup code. Grep confirms zero `DELETE FROM analysis_cache WHERE created_at < ...` anywhere. The JSONB `result` column can be multi-megabyte (Ghidra decompilations, JADX class dumps, mobsfscan reports). A large firmware with tens of thousands of cached operations easily produces a multi-GB table.

## Approach

### Step 1 — Extract canonical cache module

Create `backend/app/services/_cache.py` (underscore to signal internal):

```python
"""Canonical cache access for the analysis_cache table.

All services analyzing firmware content should use these helpers rather
than querying AnalysisCache directly.
"""
from typing import Any
from uuid import UUID
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.analysis_cache import AnalysisCache


async def get_cached(
    db: AsyncSession,
    firmware_id: UUID,
    binary_sha256: str,
    operation: str,
) -> dict | None:
    """Return cached result or None."""
    stmt = select(AnalysisCache).where(
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.binary_sha256 == binary_sha256,
        AnalysisCache.operation == operation,
    ).limit(1)
    row = (await db.execute(stmt)).scalar_one_or_none()
    return row.result if row else None


async def store_cached(
    db: AsyncSession,
    firmware_id: UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    result: dict[str, Any],
) -> None:
    """Idempotent upsert: delete any existing row, insert new one, flush."""
    await db.execute(
        delete(AnalysisCache).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.binary_sha256 == binary_sha256,
            AnalysisCache.operation == operation,
        )
    )
    db.add(AnalysisCache(
        firmware_id=firmware_id,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        operation=operation,
        result=result,
    ))
    await db.flush()


async def invalidate_firmware(db: AsyncSession, firmware_id: UUID) -> int:
    """Delete all cache entries for a firmware. Returns count deleted."""
    result = await db.execute(
        delete(AnalysisCache).where(AnalysisCache.firmware_id == firmware_id)
    )
    await db.flush()
    return result.rowcount


async def cleanup_older_than(
    db: AsyncSession,
    *,
    days: int = 30,
) -> int:
    """Delete cache rows older than N days. Returns count deleted."""
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        delete(AnalysisCache).where(AnalysisCache.created_at < cutoff)
    )
    await db.flush()
    return result.rowcount
```

### Step 2 — Migrate call sites

For each of the 7 call sites listed above, replace inline queries with `get_cached` / `store_cached`. Be careful about operation key length (see `data-analysis-cache-operation-varchar-fix.md` — do that one first).

Example migration for `ghidra_service.py`:
```python
# Before
cache = GhidraAnalysisCache(db)
existing = await cache.get_cached(firmware_id, sha256, op_key)

# After
from app.services._cache import get_cached, store_cached
existing = await get_cached(db, firmware_id, sha256, op_key)
```

Keep `GhidraAnalysisCache` class as a thin wrapper during transition to avoid breaking callers.

### Step 3 — Schedule TTL cleanup

Add a new arq cron job. In `backend/app/workers/arq_worker.py`:

```python
from arq.cron import cron
from app.database import async_session_factory
from app.services._cache import cleanup_older_than

async def cleanup_analysis_cache(ctx: dict) -> dict:
    """Delete analysis_cache rows older than 30 days."""
    async with async_session_factory() as db:
        count = await cleanup_older_than(db, days=30)
        await db.commit()
    return {"rows_deleted": count}

class WorkerSettings:
    # ...existing...
    cron_jobs = [
        cron(cleanup_analysis_cache, hour=3, minute=0),  # daily 03:00
    ]
```

Make the retention window configurable: add `analysis_cache_retention_days: int = 30` to `config.py`.

### Step 4 — Add invalidation on firmware deletion

In `backend/app/services/firmware_service.py` delete path, call `invalidate_firmware(db, firmware_id)` — though with `ON DELETE CASCADE` the rows go away anyway, being explicit documents intent. Skip if redundant.

### Step 5 — Add observability

The cron job logs count deleted. Also expose a Prometheus-compatible metric once observability work lands (`infra-cleanup-migration-and-observability.md`).

## Files

- `backend/app/services/_cache.py` (new)
- `backend/app/services/ghidra_service.py` (replace inline with shared)
- `backend/app/services/cwe_checker_service.py`
- `backend/app/services/jadx_service.py`
- `backend/app/services/mobsfscan_service.py`
- `backend/app/services/firmware_metadata_service.py`
- `backend/app/ai/tools/android_bytecode.py`
- `backend/app/routers/apk_scan.py`
- `backend/app/workers/arq_worker.py` (cron job)
- `backend/app/config.py` (retention days)
- `backend/tests/test_cache_module.py` (new)

## Acceptance Criteria

- [ ] `grep -rn 'AnalysisCache' backend/app/services backend/app/routers backend/app/ai/tools | grep -v _cache.py` returns only import statements — no direct queries
- [ ] All 7 call sites use `get_cached` / `store_cached`
- [ ] `backend/tests/test_cache_module.py` covers: set-then-get, idempotent re-store, invalidate_firmware, cleanup_older_than
- [ ] Cron job runs successfully and deletes old rows
- [ ] Retention config (`analysis_cache_retention_days`) is honored

## Risks

- The `operation` column width issue (see `data-analysis-cache-operation-varchar-fix.md`) must be fixed first — otherwise migrated code will hit the same StringDataRightTruncation
- Cache invalidation during active scans may briefly return cache miss — acceptable since scans are idempotent
- Prevent the cron from running while a cache-writing scan is mid-flight: add `SKIP LOCKED` or a separate cleanup table. For V1, the 30-day window is long enough that concurrent access is not a real concern

## References

- Backend review H6 (parallel cache implementations)
- Data review H4 (unbounded cache growth)
