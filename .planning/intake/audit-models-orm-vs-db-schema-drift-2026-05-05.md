---
title: "Investigate ORM ↔ DB schema drift surfaced by Wave-1 #6 sanity autogenerate"
status: pending
priority: medium
target: backend/app/models/* + backend/alembic/versions/*
---

## Description

Closing the `audit-models-init-export-cra-hwfirmware-2026-05-04` intake (Wave-1 #6) added `cra_compliance` + `hardware_firmware` to `app/models/__init__.py` so alembic autogenerate now sees them. The acceptance test ran `alembic revision --autogenerate -m "audit-2026-05-04 metadata sync sanity"` — the migration was NOT empty. Two distinct families of drift appeared:

**Family A — type-narrowing drift (4 columns):** DB is `TIMESTAMP(timezone=True)`; ORM model declares `DateTime()` (no tz):
- `hardware_firmware_blobs.created_at`
- `sbom_components.created_at`
- `sbom_vulnerabilities.published_date`
- `sbom_vulnerabilities.created_at`

**Family B — index/unique-constraint drift (multiple sites):**
- `attack_surface_entries.ix_attack_surface_firmware_id` — in DB, not in model
- `emulation_sessions.idx_emulation_project`, `idx_emulation_status`, `ix_emulation_sessions_container_id` — in DB, not in model
- `emulation_sessions.ix_emulation_sessions_project_id` — in model, not in DB (or different naming)
- `findings.idx_findings_source` — in DB, not in model
- `firmware.uq_firmware_project_sha256` — unique constraint in DB, not in model
- `sbom_components.idx_sbom_firmware` — in DB, not in model
- `sbom_components.uq_sbom_components_firmware_name_version_cpe` — unique constraint in DB, not in model
- `sbom_components.ix_sbom_components_firmware_id` — in model, not in DB
- `sbom_vulnerabilities.ix_sbom_vulnerabilities_blob_id` — in model, not in DB
- `uart_sessions.ix_uart_sessions_firmware_id` — in model, not in DB

The drift was masked because `__init__.py` didn't expose the cra/hw models, so autogenerate's reflection-vs-metadata diff only ran against a subset of tables. Per CLAUDE.md "Adding a Database Table" Rule, every model file should be imported in `__init__.py`. The drift in non-cra/non-hw tables is older — likely from hand-written migrations that didn't sync back to ORM, or model edits that didn't ship a migration.

## Acceptance Criteria

- [ ] Family A: pick a direction (model-tracks-DB or DB-tracks-model). Wairz convention via `database.py:24` is `expire_on_commit=False` and `func.now()` server defaults — almost certainly want `TIMESTAMP(timezone=True)` to match production behaviour. Update each of 4 model columns to declare `DateTime(timezone=True)` (or use `TIMESTAMP(timezone=True)` directly). No migration needed if the DB already has tz.
- [ ] Family B (per-line classification):
  - **Index missing-from-model:** add `__table_args__ = (Index('idx_*', ...), ...)` per existing convention
  - **Index missing-from-DB:** ship a migration adding it
  - **Unique constraint missing-from-model:** add `UniqueConstraint(...)` to `__table_args__`
- [ ] Run `alembic revision --autogenerate -m "drift sanity"` — migration MUST be empty.
- [ ] Add CI gate: a pre-commit / scheduled action that runs autogenerate against a fresh DB at HEAD and fails if it produces ops. Companion to Rule #21 mirror sync.

## Out of Scope

- Re-rolling the existing hand-written cra/hw migrations to autogenerate-derived form (low risk, high churn).

## Cross-step

Per Rule #25, ship per-table fixes as separate commits (`fix(models): emulation_sessions index drift`, `fix(models): sbom_* type+index drift`, etc.). The autogenerate-empty assertion runs ONCE at the end of the stream.

## Provenance

Surfaced 2026-05-05 during Wave-1 #6 closure. Discovered by autopilot processing `audit-models-init-export-cra-hwfirmware-2026-05-04.md`. Discovery file: ad-hoc — drift listed in this intake's Description above.
