---
title: "Data: Fix Schema Drift in Findings, Firmware, CRA"
status: completed
priority: critical
target: backend/app/models/, backend/app/schemas/, backend/alembic/versions/
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 435cb5c2 Phase 2
> Stream Alpha D1/D2/D3 (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Phase 2 history). Live audit verified:
> - **D1** `findings.source` backfilled + enforced NOT NULL: commit `fb10d28`
>   (alembic `bb4acf97d9dd_backfill_and_enforce_findings_source_.py`). ORM
>   `backend/app/models/finding.py:43` now declares
>   `source: Mapped[str] = mapped_column(String(50), default="manual",
>   server_default="manual")`.
> - **D2** `FirmwareDetailResponse` fields restored:
>   `backend/app/schemas/firmware.py:49` exposes `extraction_dir: str | None`,
>   line 56 exposes `device_metadata: dict | None`.
> - **D3** CRA JSONB columns retyped to `Mapped[list[str]]`:
>   `backend/app/models/cra_compliance.py:81-92` (`finding_ids`, `tool_sources`,
>   `related_cwes`, `related_cves`).
> - ORM ↔ Pydantic parity regression test: commit `4cc5354`.
> This intake is retained for historical reference; further changes go in new intakes.

## Problem

Three distinct schema drift issues, each a live bug that will surface as 500s on specific rows.

### D1. `findings.source` nullability drift

- ORM `backend/app/models/finding.py:43` declares `source: Mapped[str]` (non-nullable) with a default
- Migration `backend/alembic/versions/b1c2d3e4f5a6_add_sbom_tables.py:68` created it as `nullable=True`
- Pydantic `FindingResponse.source: str` (`backend/app/schemas/finding.py:76`) will raise `ValidationError` on any legacy NULL row → 500 to client
- Grep finds no backfill — any finding created before `source` was added has NULL

### D2. `FirmwareDetailResponse` drops backend fields

- `backend/app/models/firmware.py:29` has `extraction_dir` — **not present** in `FirmwareDetailResponse` (`backend/app/schemas/firmware.py:37-55`)
- `backend/app/models/firmware.py:39` has `device_metadata: JSONB` — **not present** in response schema either
- Frontend features expecting device metadata on the detail endpoint silently get empty data
- Violates CLAUDE.md rule #4 (Pydantic response must match ORM)

### D3. CRA JSONB columns typed as `dict` but store `list`

`backend/app/models/cra_compliance.py:81-94`:
```python
finding_ids: Mapped[dict] = mapped_column(JSONB, server_default="[]")
tool_sources: Mapped[dict] = mapped_column(JSONB, server_default="[]")
related_cwes: Mapped[dict] = mapped_column(JSONB, server_default="[]")
related_cves: Mapped[dict] = mapped_column(JSONB, server_default="[]")
```

Server default is a JSON array but the Python type is `dict`. Any code doing `entry.finding_ids.keys()` raises `AttributeError`. mypy cannot catch it because the type is a lie.

## Approach

Three independent fixes in one PR.

### Fix D1 — Backfill then enforce NOT NULL

New migration:
```python
def upgrade() -> None:
    op.execute("UPDATE findings SET source = 'manual' WHERE source IS NULL")
    op.alter_column(
        "findings",
        "source",
        existing_type=sa.String(length=50),
        nullable=False,
        server_default="manual",
    )

def downgrade() -> None:
    op.alter_column("findings", "source", nullable=True)
```

### Fix D2 — Add missing fields to `FirmwareDetailResponse`

In `backend/app/schemas/firmware.py`, inside `FirmwareDetailResponse`:

```python
class FirmwareDetailResponse(BaseModel):
    # ...existing fields...
    extraction_dir: str | None = None
    device_metadata: dict | None = None
    
    model_config = ConfigDict(from_attributes=True)
```

Verify with the frontend: `frontend/src/types/index.ts` — add matching fields to `FirmwareDetail`.

### Fix D3 — Retype CRA JSONB columns

Python-only change, no DB migration required:

```python
finding_ids: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
tool_sources: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
related_cwes: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
related_cves: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
```

Verify no existing code calls `.keys()` or `.items()` on these (grep across `backend/app/services/cra_compliance_service.py` and routers).

## Files

- `backend/alembic/versions/{new_revision}_backfill_findings_source.py` (new)
- `backend/app/schemas/firmware.py` (add 2 fields)
- `backend/app/models/cra_compliance.py` (retype 4 columns)
- `frontend/src/types/index.ts` (FirmwareDetail: add 2 fields)
- `backend/tests/test_schemas.py` (new: verify ORM ↔ Pydantic alignment)

## Acceptance Criteria

- [ ] `SELECT COUNT(*) FROM findings WHERE source IS NULL` returns 0 after migration
- [ ] `findings` table has `source NOT NULL DEFAULT 'manual'`
- [ ] `GET /api/v1/projects/{id}/firmware/{fid}` response includes `extraction_dir` and `device_metadata`
- [ ] `grep -rn '\.finding_ids\.\(keys\|items\|get\)\|\.tool_sources\.\(keys\|items\|get\)' backend/app` returns no hits
- [ ] mypy / Pyright on `backend/app/services/cra_compliance_service.py` passes
- [ ] Regression test verifies all 15 models' field sets match their response schemas (see `test_schemas.py` below)

## Test: ORM ↔ Pydantic alignment

Add `backend/tests/test_schemas.py`:

```python
import inspect
from app.models import finding, firmware, project  # etc
from app.schemas import finding as s_finding, firmware as s_firmware, project as s_project

def _orm_fields(model_cls) -> set[str]:
    return set(model_cls.__mapper__.column_attrs.keys())

def _pydantic_fields(schema_cls) -> set[str]:
    return set(schema_cls.model_fields.keys())

def test_firmware_detail_response_matches_orm():
    orm = _orm_fields(firmware.Firmware)
    schema = _pydantic_fields(s_firmware.FirmwareDetailResponse)
    # Schema may be a subset but must not declare fields absent from ORM
    invented = schema - orm
    assert not invented, f"Schema declares fields not in ORM: {invented}"
    # Record dropped fields (warning, not failure)
    dropped = orm - schema - {"id", "created_at"}  # allow id / timestamps filtered
    if dropped:
        print(f"NOTE: Firmware ORM fields not exposed in response: {dropped}")
```

## Risks

- D1 migration is safe (UPDATE then ALTER) but takes time proportional to `findings` count — run in maintenance window if count > 1M
- D2 — existing `FirmwareDetailResponse` consumers might not expect new fields; TypeScript will not complain if field is optional, but verify no strict `Record<...>` lookups on the response shape

## References

- Data review C2, C3, C4
- CLAUDE.md learned rule #4 (Pydantic response schemas must match ORM)
