---
name: add-jsonb-column
description: Add a new JSONB column to any model with the boundary normaliser + schema_version discipline (Rule #35c) so future shape drift is guarded at the read site, not on a recovery night.
triggers:
  - "add jsonb column"
  - "new jsonb"
  - "json column"
  - "metadata column"
  - "rule 35c"
edges:
  - target: context/conventions.md
    condition: for the Verify Checklist that lists Rule #35c
  - target: patterns/docker-rebuild-backend-worker.md
    condition: after the model + migration land, before integration testing
last_updated: 2026-05-06
---

# Add JSONB Column

## Context

CLAUDE.md Rule #35c. Every JSONB column gets EITHER a `schema_version` discriminator (when ≥3 consumer files read it) OR a boundary normaliser (always). The reference shape is `_normalize_vendor_decryption` at `backend/app/services/unpack_audit_service.py:104` and the central module `backend/app/services/jsonb_normalizers.py` hosts every per-column helper.

The rule applies regardless of current shape uniformity — it's forward-looking. Legacy rows accumulate indefinitely; sub-key drift exists even when column-level shape is uniform (the unpack-audit `vendor_decryption` incident, 2026-05-04). The cost is ~15 LOC per column. The cost of not doing it is the next incident replayed.

## Decide: per-column strategy

Count consumer **files** that read the column (writers don't count — they're sources of truth).

- **≥3 consumer files** → schema_version discriminator. Add a `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant, a `_stamp_<table>_<column>(payload)` writer helper, and the normaliser. Writers stamp the version into the dict payload; readers route through the normaliser which can dispatch on `value.get("schema_version", 1)` once a v2 lands.
- **<3 consumer files** → boundary normaliser only. Just `_normalize_<table>_<column>(value)`; no writer-side stamping needed (the marker would be more code-touch than benefit).

For list-shaped columns (`list[str]`, `list[dict]`), the schema_version marker can't live INSIDE the list cleanly — declare the SCHEMA_VERSION constant for forward-discipline but skip the stamp helper.

## Steps

1. Define the column on the model. Mirror existing JSONB columns:
   ```python
   from sqlalchemy.dialects.postgresql import JSONB

   my_field: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
   # or for a list-shaped column with non-null default:
   my_list: Mapped[list[dict]] = mapped_column(JSONB, server_default="'[]'")
   ```

2. Generate the alembic migration:
   ```
   docker compose exec backend alembic revision --autogenerate -m "add <table>.<column>"
   ```

3. Add the boundary normaliser to `backend/app/services/jsonb_normalizers.py`:
   ```python
   # ── <table>.<column> ─────────────────────────────────────────────────────────
   #
   # Canonical shape: <describe>. Server default <{}|[]|None>. <N> consumer
   # files (per <date>'s grep). <strategy>.
   <TABLE>_<COLUMN>_SCHEMA_VERSION = 1


   def _normalize_<table>_<column>(value: Any) -> <canonical>:
       """<describe>. Defensive: None / wrong-type → canonical empty."""
       if isinstance(value, <type>):
           return value
       return <empty>


   # Only when ≥3 consumer files (and not a list-shaped column):
   def _stamp_<table>_<column>(payload: <canonical>) -> <canonical>:
       """Stamp the schema_version onto a writer payload. Idempotent."""
       payload["schema_version"] = <TABLE>_<COLUMN>_SCHEMA_VERSION
       return payload
   ```

4. Update consumers:
   - **Reads:** replace `meta = obj.col or {}` / `obj.col.get(...)` with `meta = _normalize_<table>_<column>(obj.col)`.
   - **Writes (when stamping):** wrap the payload through `_stamp_<table>_<column>(payload)` before assigning.

5. Add tests in `backend/tests/test_jsonb_normalizers.py`:
   - Parameterised cases for canonical pass-through, `None`, wrong-type (`list` when expecting `dict` / `str` / `int`), mixed-list filtering when applicable.
   - `test_*_idempotent` — passing the canonical value back through returns the same value.
   - When stamping: `test_stamp_*_adds_version`, `test_stamp_*_idempotent`, `test_stamp_*_preserves_none` (if column is nullable).

6. Rebuild + smoke + canary per CLAUDE.md Rules #8 / #11 / #35b:
   - `docker compose up -d --build backend worker`
   - Runtime import smoke: `docker compose exec -T backend /app/.venv/bin/python -c "from app.services.jsonb_normalizers import _normalize_<table>_<column>; print('ok')"`
   - Live canary against ≥3 production rows. Run the new normaliser against `await db.execute(select(Model).limit(N))` and inspect output shapes.

## Gotchas

- **Calling the normaliser inside a list-comprehension wraps the same dict twice** — fine for read-side normalisers (idempotent) but if you mutate the result, you mutate the row. Reads should not mutate; clone with `dict(...)` if you need to.
- **Pydantic schemas (`response_model=`) bypass the normaliser** — `from_attributes=True` reads ORM columns directly. If a downstream Pydantic field could fail on a wrong-typed legacy row, validate at the router layer (route `r.col` through the normaliser before constructing the response).
- **Stamping a `dict | None` payload** must preserve the None semantic when the column is nullable. The reference `_stamp_firmware_device_metadata` does this with the `if not payload: return None` guard.
- **The schema_version constant lives at module top-level**, not inside a class. Bump only on backwards-incompatible shape change AND extend the matching normaliser's dispatch.
- **Existing rows lacking `schema_version`** are treated as v1 by convention (the canonical shape today). The normaliser handles their absence transparently.

## Verify

- [ ] Column declared with `JSONB` import + `mapped_column(JSONB, ...)`.
- [ ] Alembic migration generated and committed.
- [ ] `_normalize_<table>_<column>` exists in `backend/app/services/jsonb_normalizers.py`.
- [ ] If ≥3 consumer files (dict-shaped): `_stamp_<table>_<column>` + `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` declared.
- [ ] Every consumer read uses the normaliser.
- [ ] Every consumer write (when stamping) uses the stamp helper.
- [ ] Tests added in `backend/tests/test_jsonb_normalizers.py` covering canonical / None / wrong-type / idempotency.
- [ ] `docker compose up -d --build backend worker` ran (Rule #8).
- [ ] Rule #11 import smoke OK on the touched modules.
- [ ] Rule #35b live canary against ≥3 production rows of the column.

## Debug

- **AttributeError: 'str' object has no attribute 'get'** at consumer site → a legacy row has a different shape than expected. Verify the normaliser is in the read path.
- **TypeError: 'NoneType' object is not iterable** in a `for x in obj.col:` loop → consumer didn't route through the normaliser; the column is `None` at this row.
- **Stamp re-applies on every flush, growing the dict** → not happening (idempotent, single key); but if the stamp logic looks expensive, profile — it shouldn't be.
- **Migration fails: column already exists** → an earlier autogenerate already produced this migration; check `alembic/versions/` and remove duplicates.

## Update Scaffold

- [ ] If the column is on a model that didn't have JSONB before, update `.planning/research/jsonb-shape-inventory-2026-05-04.md` with the new column row.
- [ ] If the consumer count crosses the ≥3 threshold for the first time, update the strategy column in that file.
