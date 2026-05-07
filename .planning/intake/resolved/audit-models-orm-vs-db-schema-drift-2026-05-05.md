---
title: "Investigate ORM ↔ DB schema drift surfaced by Wave-1 #6 sanity autogenerate"
status: completed
priority: medium
target: backend/app/models/* + backend/alembic/versions/*
---

## Progress — autopilot 2026-05-05

**Family A (4 timestamp drift columns) — SHIPPED.**

`hardware_firmware_blobs.created_at`, `sbom_components.created_at`,
`sbom_vulnerabilities.created_at`, `sbom_vulnerabilities.published_date`
all updated from `mapped_column(server_default=func.now())` to
`mapped_column(DateTime(timezone=True), server_default=func.now())` to
match the DB which already declares `timestamp with time zone` for all
four.  No migration needed.  Verified via runtime smoke:
`column.type.timezone == True` on all four.

Re-ran `alembic revision --autogenerate -m "drift sanity check"` after
the model edits — autogen output dropped from 4 type-narrowing lines +
many index/UC drift lines to ONLY the index/UC drift (Family B).

**Family B (index/UC drift) — SHIPPED 2026-05-05.**

6 commits, mechanical model edits only, no migrations:

| Commit | Table | Change |
|---|---|---|
| f5c0824 | `emulation_sessions` | drop `index=True` on project_id, add 3 Index() to __table_args__ |
| 04c8be1 | `findings` | add Index("idx_findings_source", "source") to __table_args__ |
| cb83774 | `firmware` | add UniqueConstraint("project_id", "sha256", ...) to __table_args__ |
| 7f65908 | `sbom_components` + `sbom_vulnerabilities` | drop phantom `index=True` on firmware_id/blob_id, add idx_sbom_firmware + UC |
| 8fba6f7 | `attack_surface_entries` | add Index("ix_attack_surface_firmware_id", "firmware_id") to __table_args__ |
| 49d9d8f | `uart_sessions` | drop phantom `index=True` on firmware_id (DB has no such index) |

Final `alembic revision --autogenerate` after `docker compose up -d
--build backend worker` (Rule #8 rebuild) produces `def upgrade(): pass`
and `def downgrade(): pass` — drift is fully closed.

Resolution policy used:
- "DB has, model doesn't" — added Index/UniqueConstraint to model
  __table_args__ with the DB-side name; no migration since the DB already
  has the constraint.
- "Model has, DB doesn't (different name)" — dropped column-level
  `index=True`, declared the existing DB-named Index in __table_args__
  instead. Avoids duplicate-name DDL.
- "Model has, DB doesn't (no DB-side equivalent)" — only `uart_sessions
  .firmware_id`. Dropped `index=True` to match DB; uart_sessions is
  small (per-session, typically <100 rows) so the FK lookup cost is
  negligible.

CI gate (autogen-empty in pre-commit) is out of scope for this intake
closer — filed as a follow-up companion to Rule #21 mirror sync.

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
- [x] Add CI gate: a pre-commit / scheduled action that runs autogenerate against a fresh DB at HEAD and fails if it produces ops. Companion to Rule #21 mirror sync. **Shipped 2026-05-07** as `backend/tests/test_alembic_autogenerate_empty.py` (uses `alembic check` programmatically; raises `AutogenerateDiffsDetected` on drift). Caught one residual drift at delivery time (`device_dump_sessions.project_id` had duplicate `index=True` + named `Index()` — fixed in same commit). Closes BOTH the 2026-05-05 audit's CI-gate followup AND the `audit-db-alembic-chain-drift-2026-05-07` audit's recommended durable backstop in one artifact.

## Out of Scope

- Re-rolling the existing hand-written cra/hw migrations to autogenerate-derived form (low risk, high churn).

## Cross-step

Per Rule #25, ship per-table fixes as separate commits (`fix(models): emulation_sessions index drift`, `fix(models): sbom_* type+index drift`, etc.). The autogenerate-empty assertion runs ONCE at the end of the stream.

## Provenance

Surfaced 2026-05-05 during Wave-1 #6 closure. Discovered by autopilot processing `audit-models-init-export-cra-hwfirmware-2026-05-04.md`. Discovery file: ad-hoc — drift listed in this intake's Description above.
