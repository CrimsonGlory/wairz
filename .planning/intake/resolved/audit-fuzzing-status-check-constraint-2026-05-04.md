---
title: "Fuzzing 202+polling refactor missing CHECK constraint widening — every campaign start hits HTTP 500"
status: pending
priority: critical
target: backend/alembic/versions/<new_revision>.py + backend/app/models/fuzzing.py
---

## Description

The Wave-1 β fuzzing 202+polling refactor (commit `df30015`, 2026-04-20) added `status="queued"` writes in `backend/app/services/fuzzing_service.py:393` but did NOT ship the corresponding migration to widen `ck_fuzzing_campaigns_status`. The CHECK constraint allowlist still reads `('created', 'running', 'stopped', 'completed', 'error')`. Every `POST /fuzzing/campaigns/{id}/start` triggers `CheckViolationError` → HTTP 500 at the first DB flush.

This is a runtime ship-blocker; the feature is in production but every invocation fails. Compare with the emulation 202+polling refactor (Wave-1 α, commit `c5d2f74`) which DID ship a paired widening migration `c3f8a1b9e4d2_add_emulation_queued_status.py`.

**Evidence:**
- Service write: `backend/app/services/fuzzing_service.py:393` — `campaign.status = "queued"`
- Live CHECK: introspect `pg_constraint` on `fuzzing_campaigns` constraint name `ck_fuzzing_campaigns_status`
- Original migration: `backend/alembic/versions/54c8864fbe0c_add_enum_check_constraints.py` (constraint creation, no `queued`)

**Cross-stream confirmation:** Stream B (F-B-04), Stream C (F-C-01), Stream F (F-F-03). Triple confirmation.

**Companion to CLAUDE.md Rule #33c** (status column gets BOTH a Pydantic Literal AND a DB CHECK constraint). The 202+polling design contract was followed for the column-add but the value-set widening for the new "queued" state was missed.

## Acceptance Criteria

- [ ] New alembic migration `<rev>_widen_fuzzing_campaigns_status_queued.py` (single revision, single op) drops + recreates `ck_fuzzing_campaigns_status` to include `queued` (and `error` if not already; reconcile with the model's Literal in `app/schemas/fuzzing.py` so they exactly agree).
- [ ] Pydantic Literal in the schemas package (or wherever `FuzzingCampaignStatus` is declared) lists `queued` as a valid value.
- [ ] Test: `backend/tests/test_fuzzing_status_check_alignment.py` — assert every value the service writes appears in the live DB CHECK list (introspect via SQLAlchemy `text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='ck_fuzzing_campaigns_status'")`).
- [ ] Smoke: `POST /fuzzing/campaigns/{id}/start` against a real campaign row succeeds (status flips to `queued` then `running`).
- [ ] Backend + worker rebuild per Rule #8 after migration ships.

## Out of Scope

- Wider Rule #33c CHECK-coverage gaps on other status columns (filed separately as `audit-status-columns-check-constraints-rule33c-2026-05-04.md`).

## Cross-step

Single commit `fix(fuzzing): widen ck_fuzzing_campaigns_status to allow queued`. Per Rule #20 / #8, requires backend+worker rebuild before the migration auto-runs at boot.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery files: `.planning/discoveries/audit-stream-{b,c,f}-2026-05-04.md`.
