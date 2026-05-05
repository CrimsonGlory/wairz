---
title: "Finding.confidence dropped on 5 bypass paths — sweep + Rule #35b live-canary tests"
status: pending
priority: high
target: backend/app/services/{mobsfscan/normalization.py, vulnerability_service.py, grype_service.py, cwe_checker_service.py} + backend/app/ai/tools/reporting.py + backend/tests/test_finding_service.py
---

## Description

Commit `7dc21fe` (2026-05-04, Rule #35b base case) fixed `FindingService.create()` to forward `data.confidence.value` to the `Finding(...)` constructor. **Five additional code paths bypass `FindingService.create()` and construct `Finding(...)` directly, dropping `confidence` to NULL on persist.** None of them benefited from the fix.

**Bypass paths (5 sites):**
1. `backend/app/services/mobsfscan/normalization.py:481-492` (Stream A F-A-06)
2. `backend/app/services/vulnerability_service.py:366-383` (Stream A F-A-06)
3. `backend/app/services/grype_service.py:231-244` (Stream A F-A-06)
4. `backend/app/services/cwe_checker_service.py::_generate_findings` (Stream D F-D-08, also drops `firmware_id`)
5. `backend/app/ai/tools/reporting.py::_handle_add_finding:213` (Stream D F-D-03 — drops both `firmware_id` and `confidence`; every MCP-created finding NULLs both)

**Test gaps that allowed this to ship:**
- `backend/tests/test_finding_service.py:30-118` — `_make_finding` mocks `confidence="high"` but `test_create_minimal` and `test_create_full_fields` never assert `added.confidence` (Stream G F-G-01). Exact Rule #35b reproduction.
- `backend/tests/test_unpack_audit_service.py:347-368` — only `mock_db.add.call_count == 4`, no `call_args_list` capture (Stream G F-G-02).

**Cross-stream confirmation:** Stream A + Stream D + Stream G — three independent surfaces all flagged the same root cause.

**Companion to CLAUDE.md Rule #35b** (mocks vs live canaries) — the post-incident lesson was about WHY this happened, but the fix only patched the one path. The other 5 sites still carry the original anti-pattern.

## Acceptance Criteria

- [ ] All 5 bypass paths route through `FindingService.create()` (or a shared helper that forwards `confidence` + `firmware_id` correctly), per the `unpack_audit_service.py` precedent. Direct `Finding(...)` construction outside `FindingService` is forbidden going forward.
- [ ] `test_finding_service.py::test_create_full_fields` adds `assert added.confidence == "high"`. Add a dedicated `test_create_propagates_confidence` test that captures `mock_db.add.call_args[0][0].confidence`.
- [ ] `test_unpack_audit_service.py::test_run_persists_findings` switches from `call_count` to `call_args_list`-capture, asserting each persisted Finding has the correct `confidence` and `firmware_id`.
- [ ] Live canary (Rule #35b): run each bypass-path scanner against a real fixture firmware, SELECT the persisted Finding rows, assert `confidence IS NOT NULL` and `firmware_id IS NOT NULL`.
- [ ] Optional but recommended: add a SQLAlchemy event listener on `Finding.before_insert` that asserts `confidence IS NOT NULL` and `firmware_id IS NOT NULL` in dev/test mode (production: log warning + emit metric).

## Out of Scope

- Backfilling existing NULL-confidence rows (separate intake if needed; depends on whether downstream code tolerates NULL).

## Cross-step

Per Rule #25 — split into 6 commits: one per service, one for MCP, one for test additions. Or if the helper centralisation is the cleanest fix, 2 commits: helper + sweep.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery files: `.planning/discoveries/audit-stream-{a,d,g}-2026-05-04.md`.
