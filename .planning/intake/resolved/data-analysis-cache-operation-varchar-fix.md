---
title: "Data: Widen analysis_cache.operation from VARCHAR(100) to VARCHAR(512)"
status: completed
completed_at: 2026-04-18
completed_in: session 59045370 autopilot (commit e3053b6)
priority: critical
target: backend/alembic/versions/
---

## Problem

Live foot-gun matching CLAUDE.md learned rule #15.

- `backend/app/models/analysis_cache.py:26` declares `operation: Mapped[str] = mapped_column(String(512), nullable=False)`
- `backend/alembic/versions/01ac34151ca4_add_analysis_cache_table.py:28` created the column as `sa.String(length=100)`
- No subsequent migration has altered it (grep-verified: `operation` only appears in the two analysis_cache migrations)

Known offending callers that produce operation keys >100 chars:
- `backend/app/services/ghidra_service.py:645` — `operation = f"decompile:{function_name}"` (Java mangled names routinely exceed 100 chars)
- `backend/app/mcp_server.py:165` — `operation = f"code_cleanup:{function_name}"`
- `backend/app/routers/analysis.py:276` — same pattern
- `backend/app/services/jadx_service.py` — JADX class names with inner classes + synthetic lambdas (`$$ExternalSyntheticLambda0`) reach 150+ chars (this is exactly the rule #15 precedent)

Current failure mode: `asyncpg.exceptions.StringDataRightTruncation` raised mid-transaction; tool returns a confusing 500.

## Approach

Single Alembic migration to widen the column.

**Step 1 — Generate migration.**

```bash
docker compose exec backend alembic revision -m "widen_analysis_cache_operation_to_512"
```

**Step 2 — Fill in the migration body.**

```python
def upgrade() -> None:
    op.alter_column(
        "analysis_cache",
        "operation",
        existing_type=sa.String(length=100),
        type_=sa.String(length=512),
        existing_nullable=False,
    )

def downgrade() -> None:
    # NOTE: Truncates existing data > 100 chars. Not reversible for rows with long operation keys.
    op.execute("UPDATE analysis_cache SET operation = LEFT(operation, 100) WHERE length(operation) > 100")
    op.alter_column(
        "analysis_cache",
        "operation",
        existing_type=sa.String(length=512),
        type_=sa.String(length=100),
        existing_nullable=False,
    )
```

**Step 3 — Verify on a running instance.**

```bash
docker compose exec backend alembic upgrade head
docker compose exec postgres psql -U wairz -d wairz -c "\d analysis_cache" | grep operation
# Expect: operation | character varying(512)
```

**Step 4 — Add regression test.**

`backend/tests/test_analysis_cache_schema.py`:
```python
async def test_analysis_cache_accepts_long_operation_key():
    long_op = "decompile:" + "A" * 500  # 510 chars total
    async with async_session_factory() as db:
        cache = AnalysisCache(firmware_id=..., binary_sha256=..., operation=long_op, result={})
        db.add(cache)
        await db.flush()  # Must not raise StringDataRightTruncation
```

## Files

- `backend/alembic/versions/{new_revision}_widen_analysis_cache_operation.py` (new)
- `backend/tests/test_analysis_cache_schema.py` (new)

## Acceptance Criteria

- [ ] `docker compose exec postgres psql -U wairz -d wairz -c "\d analysis_cache"` shows `operation | character varying(512)`
- [ ] JADX scan of a real Android APK with long inner-class names succeeds without `StringDataRightTruncation`
- [ ] Regression test passes in CI
- [ ] Rebuild both backend AND worker (learned rule #8: shared Dockerfile)

## Risks

- Widening a column is a metadata-only operation in PostgreSQL — very fast even on large tables, no lock storm
- Downgrade would truncate — document this explicitly

## References

- Data review C1
- CLAUDE.md learned rule #15 (this is exactly that class of bug, still live)
