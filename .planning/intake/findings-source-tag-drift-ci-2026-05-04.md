---
title: "CI check: DB ck_findings_source CHECK ↔ frontend FindingSource union must agree"
status: pending
priority: low
target: backend/tests/test_finding_source_alignment.py (new) OR scripts/check_finding_source_alignment.py (new) + .github/workflows/ if any
---

## Description

The `ck_findings_source` CHECK constraint in `backend/alembic/versions/54c8864fbe0c_add_enum_check_constraints.py:41` (later extended by `a9f4e9cdabe2_add_unpack_audit_source.py` to add `unpack_audit`) lists 17 valid source values. The frontend `FindingSource` union at `frontend/src/types/index.ts:184` lists 13. Differential at 2026-05-04 audit:

- **DB-only (8):** `attack_surface`, `hardware_firmware_graph`, `cwe_checker`, `uefi_scan`, `clamav_scan`, `vt_scan`, `fuzzing_scan`, `fuzzing` (note: `fuzzing` and `fuzzing_scan` both DB-allowed; legacy)
- **Frontend-only (2):** `ai_discovered`, `known_good_scan`

Findings created with a DB-only source render as "Manual" in the UI via the `?? FINDING_SOURCE_CONFIG.manual` fallback at `FindingDetail.tsx:93` and `FindingsList.tsx:232` — graceful but misleading. Operators see findings categorised under the wrong source filter chip. The graceful fallback is precisely what allows the drift to survive — symptoms are functionally invisible.

Surfaced as antipattern #4 in `.planning/knowledge/unpack-audit-findings-2026-05-04-antipatterns.md`. Companion to CLAUDE.md Rule #9 (TypeScript Record exhaustive).

## Acceptance Criteria

- [ ] Pytest test at `backend/tests/test_finding_source_alignment.py` (or standalone script) that:
  - Reads the latest `ck_findings_source` value list from `backend/alembic/versions/*.py` (parse the most recent `_add_*_source.py` migration file's recreate-CHECK call, OR introspect the live DB constraint via `pg_constraint`).
  - Reads `FindingSource` union from `frontend/src/types/index.ts` via regex (`/export type FindingSource = (.+)/`).
  - Reads `FINDING_SOURCE_CONFIG` keys from `frontend/src/constants/statusConfig.ts`.
  - Asserts: every DB value appears in `FindingSource` union AND in `FINDING_SOURCE_CONFIG`. Conversely every union value appears in the DB CHECK list.
  - Fails loud with a diff: "DB-only: [...]; Frontend-only: [...]"
- [ ] Resolution path documented in test failure message — either add the missing source to the other side, OR remove if truly defunct (e.g. `fuzzing` legacy duplicate).
- [ ] Optionally wire into a pre-commit / CI gate.

## Out of Scope

- Actually closing the existing 8-DB-only / 2-frontend-only drift — that's a separate intake (would need per-source classification: keep / rename / remove). This intake adds the GATE; the close is downstream.

## Cross-step

Single commit `test(findings): assert DB CHECK source values agree with frontend FindingSource union`. No DB or frontend changes; pure test addition. Rebuild gate: backend image rebuild ONLY if test depends on a new pip package (likely none — stdlib regex + sqlalchemy text() is enough).
