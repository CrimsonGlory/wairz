---
title: "alembic autogenerate broken: cra_compliance + hardware_firmware ORM models not exported from app/models/__init__.py"
status: pending
priority: high
target: backend/app/models/__init__.py
---

## Description

`backend/app/models/__init__.py` does not import the ORM models for `cra_compliance` or `hardware_firmware`. Result: `alembic revision --autogenerate` does not see those tables in its metadata reflection, so any schema change to those tables falls back to hand-written migrations. Two recent migrations (`d4a7c8b6e2f1`, `e6f7a8b9c0d1`) explicitly say "hand-written" in their docstrings citing this gap.

This silently degrades the migration UX project-wide — every future change to those tables is manual SQL instead of declarative ORM.

**Evidence:** Stream C (F-C-04). Migrations explicitly call out the gap.

**Companion to CLAUDE.md "Adding a Database Table" section** — autogenerate-friendly imports are part of the standard model-creation workflow; these were skipped.

## Acceptance Criteria

- [ ] Add `from .cra_compliance import *` and `from .hardware_firmware import *` (or explicit class names) to `backend/app/models/__init__.py`.
- [ ] Run `docker compose exec backend alembic revision --autogenerate -m "audit-2026-05-04 metadata sync sanity"` — verify the autogenerate produces an EMPTY migration (i.e. metadata now matches schema). If it produces ops, investigate (drift, not just import gap).
- [ ] Delete the empty sanity migration before commit.
- [ ] Optionally add a pre-commit / CI test that diff-checks the model `__init__.py` exports against the on-disk model file list, so the next added model can't be silently omitted.

## Out of Scope

- Backfilling the two hand-written migrations to be autogenerate-derived (they exist; risk to re-roll them is higher than benefit).

## Cross-step

Single commit `fix(models): export cra_compliance + hardware_firmware so alembic autogenerate sees them`.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-c-models-2026-05-04.md` finding F-C-04.
