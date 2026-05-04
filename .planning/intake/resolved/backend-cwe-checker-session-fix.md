---
title: "Backend: Fix cwe_checker AsyncSession Sharing + Add Lint Rule"
status: completed
completed_at: 2026-04-18
completed_in: session 59045370 autopilot wave-2 (commit b9f625a)
priority: critical
target: backend/app/services/cwe_checker_service.py, backend/pyproject.toml
---

## Problem

Direct violation of CLAUDE.md learned rule #7:

> Never `asyncio.gather()` on coroutines sharing a SQLAlchemy `AsyncSession`. Gather'd coroutines that share a session cause state corruption, lost writes, or runtime exceptions.

`backend/app/services/cwe_checker_service.py:289-310` — `run_cwe_checker_batch(..., db: AsyncSession, ...)` fans out N concurrent coroutines via `asyncio.gather`, each calling `run_cwe_checker(..., db, ...)`, which internally does `await db.execute(...)` (line 113) and `db.add(entry); await db.flush()` (lines 153-154). 

The `asyncio.Semaphore` at line 302 limits concurrency to `max_concurrent=2`, but **does NOT serialize session access** — two coroutines actively interleave on the same session. Expected failures under load:
- `sqlalchemy.exc.InvalidRequestError: Session is already flushing`
- State corruption (wrong firmware_id on a cache row)
- Lost writes silently dropped

Additionally: 5 other services have similar coupling risk (`virustotal_service`, `abusech_service`, etc.) — these use `asyncio.gather` but are session-free (pure HTTP calls), so no rule violation. Still, the codebase has no mechanical check.

## Approach

### Fix 1 — Serialize the gather loop

Replace `asyncio.gather` with a sequential await loop. The semaphore was already limiting to 2, so the speedup was minimal for this CPU-heavy workload.

Current (buggy):
```python
async def _check_one(path):
    async with semaphore:
        return await run_cwe_checker(..., db=db, ...)

results = await asyncio.gather(*[_check_one(p) for p in binary_paths], return_exceptions=True)
```

Option A (simple sequential — recommended):
```python
results = []
for path in binary_paths:
    try:
        results.append(await run_cwe_checker(..., db=db, ...))
    except Exception as e:
        results.append(e)
```

Option B (preserve parallelism, isolate sessions):
```python
from app.database import async_session_factory

async def _check_one(path):
    async with semaphore:
        async with async_session_factory() as own_db:
            result = await run_cwe_checker(..., db=own_db, ...)
            await own_db.commit()
            return result

results = await asyncio.gather(*[_check_one(p) for p in binary_paths], return_exceptions=True)
```

Option B preserves concurrency but needs careful transaction boundary thought — the outer caller no longer owns the writes. For the cwe_checker case (idempotent delete-then-insert cache writes), Option B is safe. **Recommend Option A as the minimal correctness fix; revisit with Option B if the speedup matters.**

### Fix 2 — Add a Ruff lint rule for async-subprocess pattern

CLAUDE.md rule #5 says wrap sync subprocess in `run_in_executor`. We can't easily detect gather-over-shared-session mechanically, but we CAN detect blocking subprocess inside `async def`:

Add to `backend/pyproject.toml` or as a custom check in `.github/workflows/lint.yml`:

```bash
# Grep-based CI check (simpler than writing a full Ruff plugin)
if grep -rn --include='*.py' -B5 'subprocess\.\(run\|Popen\|call\|check_call\|check_output\)' backend/app/services backend/app/routers | grep -B5 'async def' | grep 'async def'; then
  echo "ERROR: Found subprocess call inside async def. Use run_in_executor or mark module as sync."
  exit 1
fi
```

### Fix 3 — Add regression test

`backend/tests/test_cwe_checker_async_safety.py`:

```python
import asyncio
import pytest
from app.services.cwe_checker_service import run_cwe_checker_batch

@pytest.mark.asyncio
async def test_batch_does_not_corrupt_session(db):
    """Rule #7: batch operations must not share an AsyncSession via gather."""
    # This is a smoke test — running it many times should never raise
    # InvalidRequestError or produce duplicate rows
    paths = ["/tmp/test1.elf", "/tmp/test2.elf", "/tmp/test3.elf"]
    # Create dummy ELF files, stub cwe_checker subprocess
    # ...
    for _ in range(10):
        results = await run_cwe_checker_batch(paths, db=db, ...)
        assert len(results) == 3
```

## Files

- `backend/app/services/cwe_checker_service.py:289-310`
- `.github/workflows/lint.yml` (add grep-based check)
- `backend/tests/test_cwe_checker_async_safety.py` (new)

## Acceptance Criteria

- [ ] `asyncio.gather` removed from `run_cwe_checker_batch`, replaced with sequential loop OR per-task session factory
- [ ] Running `run_cwe_checker_batch` against 10+ binaries in a row does not raise `InvalidRequestError`
- [ ] CI lint job fails if `subprocess.run` is re-introduced inside an `async def`
- [ ] No regression in the existing `backend/tests/test_binary_tools.py` (if it covers cwe_checker)

## Risks

- Option A loses parallelism in exchange for correctness — cwe_checker is CPU-heavy and already semaphore-limited to 2, so the impact is minimal
- Grep-based lint has false positives if `async def` appears on the same line as a comment — tune regex carefully

## References

- Backend review C1
- CLAUDE.md learned rule #7 (directly violated)
- CLAUDE.md learned rule #5 (subprocess in async — this is the class of bug to prevent)
