---
title: "Data: Add Pagination to Unbounded List Endpoints"
status: completed
priority: high
target: backend/app/routers/
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 435cb5c2 Stream Beta
> across 5 per-endpoint-family commits (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Phase 3 history). Live audit verified:
> - **Step 1** `Page[T]` + `PageParams` schemas: commit `8994dcb` →
>   `backend/app/schemas/pagination.py:25` (`class Page(BaseModel, Generic[T])`) + line 34
>   (`class PageParams(BaseModel)`).
> - **Step 2** `paginate_query_rows` helper adopted in sbom/attack_surface/projects/findings
>   routers (4 router files).
> - **Step 3 migrations** —
>   - projects + findings pagination: commit `6c4d08d`
>   - attack_surface pagination + bounded-scalar annotations: commit `67aaf49`
>   - sbom components + vulns: commit `9aeae31` (see `backend/app/routers/sbom.py:219,418`
>     for the actual `paginate_query_rows(db, stmt, offset=offset, limit=limit)` calls).
> - Frontend `unwrap(data)` companion helper: commit `3063283` + Rule #26 incident note.
> This intake is retained for historical reference; further changes go in new intakes.

## Problem

Several list endpoints call `.scalars().all()` with no pagination:

- `backend/app/routers/projects.py:82` — `list_projects` returns all projects (tenant-global)
- `backend/app/routers/sbom.py:67, 208, 222, 392, 487` — all components / vulns for a firmware
- `backend/app/routers/attack_surface.py:52, 87` — all binaries
- `backend/app/routers/security_audit.py` — 7 `.scalars().all()` calls on firmware sets

Only 4 `.limit(...)` usages total across all routers.

**Scale concern:** A large Android system image SBOM can exceed 50K components with tens of thousands of vulns. A single request returns the full JSON payload — OOM on backend, browser hang on frontend.

## Approach

Standard offset/limit pagination with `total_count` in the response envelope.

### Step 1 — Introduce a reusable pagination schema

`backend/app/schemas/pagination.py`:

```python
from typing import Generic, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")

class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(gt=0, le=500)

class PageParams(BaseModel):
    offset: int = Field(0, ge=0)
    limit: int = Field(100, gt=0, le=500)
```

### Step 2 — Helper for async paginated query

`backend/app/utils/pagination.py`:

```python
async def paginate_query(db, stmt, params: PageParams) -> tuple[list, int]:
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()
    result = await db.execute(stmt.offset(params.offset).limit(params.limit))
    return result.scalars().all(), total
```

### Step 3 — Migrate endpoints

Add `offset: int = 0, limit: int = 100` query params to affected endpoints. Change return type to `Page[ComponentResponse]`. Example for `sbom.py:67`:

```python
@router.get("/components", response_model=Page[SbomComponentResponse])
async def list_components(
    project_id: UUID, firmware_id: UUID,
    offset: int = 0, limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(SbomComponent).where(SbomComponent.firmware_id == firmware_id).order_by(SbomComponent.name)
    items, total = await paginate_query(db, stmt, PageParams(offset=offset, limit=limit))
    return Page(items=[SbomComponentResponse.model_validate(c) for c in items], total=total, offset=offset, limit=limit)
```

### Step 4 — Frontend integration

Update `frontend/src/api/sbom.ts` (and other affected API clients) to accept `offset` / `limit` and return `{ items, total }`. Pages using these need an "Load more" or paged list UI. Start with a default `limit=100` to preserve existing UX for small datasets.

## Files

**Backend:**
- `backend/app/schemas/pagination.py` (new)
- `backend/app/utils/pagination.py` (new)
- `backend/app/routers/projects.py` (1 endpoint)
- `backend/app/routers/sbom.py` (5 endpoints)
- `backend/app/routers/attack_surface.py` (2 endpoints)
- `backend/app/routers/security_audit.py` (7 call sites)
- `backend/app/routers/findings.py` (verify — may already paginate)

**Frontend:**
- `frontend/src/api/sbom.ts`
- `frontend/src/api/findings.ts`
- `frontend/src/api/projects.ts`
- `frontend/src/pages/SbomPage.tsx`
- `frontend/src/pages/AttackSurfaceTab.tsx` (or equivalent)

## Acceptance Criteria

- [ ] `grep -rn '\.scalars()\.all()' backend/app/routers/` returns only paginated-safe call sites (i.e., bounded by `project_id` with known small cardinality, or explicitly commented)
- [ ] `GET /api/v1/projects/{id}/firmware/{fid}/sbom/components?limit=10` returns exactly 10 items and `total >= 10`
- [ ] A large SBOM (50K components) does not OOM the backend when listed
- [ ] Frontend SbomPage displays the first page and shows "N of M" count
- [ ] Existing tests pass; add tests for paged responses

## Risks

- Breaking API change for any external MCP consumer that calls these endpoints directly — document in README + add `total` / `offset` / `limit` to the OpenAPI schema. Consider keeping unpaginated for one release with a deprecation warning
- Count-query overhead: `SELECT COUNT(*)` over 50K rows is fast with an index, but could be slow on `sbom_vulnerabilities` if not indexed — verify indexes exist
- Frontend UX: "load more" vs "numbered pages" vs virtualization — align with `frontend-code-splitting-and-virtualization.md` work

## References

- Data review C5
- Frontend review H12 (no virtualization for large lists)
