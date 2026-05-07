---
title: "test_status_check_constraint_alignment.py — 11 pre-existing failures (sbom_vulnerabilities columns lack CHECK constraints)"
status: pending
priority: low
target: backend/tests/test_status_check_constraint_alignment.py + backend/alembic/versions/<new>.py (CHECK constraints) OR test allowlist update
discovered: 2026-05-07
discovered_by: Wave 9 Phase 2 closure session — full-suite smoke surfaced 11 alignment failures isolated to this single test file
---

## Problem

`backend/tests/test_status_check_constraint_alignment.py` fails 11 of 12 declared tests. Verified pre-existing by running the test against `HEAD~10` — fails identically, so this is NOT a recent regression.

The test walks the alembic chain from head and resolves each `Mapped[str]` "status-like" ORM column to a migration that creates a CHECK constraint on it. Three `sbom_vulnerabilities` columns and the meta-test fail:

```
test_sbom_resolved_by_writes_in_allowlist          — no migration creates ck_sbom_vulns_resolved_by
test_sbom_match_tier_writes_in_allowlist           — no migration creates ck_sbom_vulns_match_tier
test_sbom_match_confidence_writes_in_allowlist     — no migration creates ck_sbom_vulns_match_confidence
test_every_new_constraint_resolves_to_an_allowlist_tuple   — meta-test failing on the same gap
```

Plus 7 others (project_status_writes_in_allowlist, uart_session_status_writes_in_allowlist, emulation_session_mode_writes_in_allowlist, emulation_pydantic_literal_subset_of_check, emulation_stub_profile_pydantic_literal_subset_of_check, cra_status_enum_subset_of_overall_status_check, cra_requirement_status_enum_subset_of_check) — investigate per-test; likely the same root cause (constraint name expected by test but not present in any migration) but need per-test diagnosis.

## Root cause hypothesis

Two possible shapes:

1. **The columns genuinely lack CHECK constraints in production.** Audit columns added without enum CHECKs is a real anti-pattern — values can drift to anything the ORM allows. The right close is a new alembic migration adding the missing constraints (`op.create_check_constraint("ck_sbom_vulns_resolved_by", "sbom_vulnerabilities", "resolved_by IN ('user', 'auto', ...)")`) plus per-column allowlist tuples on the new migration module.

2. **The test's expectations are stale.** The test expects constraint names that were never planned to exist (e.g. `match_confidence` is freeform string from external scanners). The right close is to remove the test rows for those columns + leave a comment noting why they're explicitly NOT constrained.

Determining which shape applies needs per-column inspection of the ORM annotations (is the column genuinely status-like with a small set of valid values, or is it freeform?) AND the audit/intake history for the columns.

## Acceptance Criteria

- [ ] Per-failing-test diagnosis: is the column status-like-with-finite-values OR freeform?
- [ ] For status-like columns lacking CHECK: one alembic migration adding the missing constraints + per-column allowlist tuples on the migration module (so the test resolver passes).
- [ ] For freeform columns the test misclassifies: remove the row from the test's expected-constraints map + add an inline comment citing the rationale.
- [ ] Full-suite goes from 11 failed → 0 failed (in this test file).

## Out of Scope

- Closing the source-tag drift (separate intake `findings-source-tag-drift-ci-2026-05-04.md`, has its own xfail-style baseline).
- Adding NEW status-like columns to other tables.

## Notes

This intake exists to prevent the pre-existing failures from being conflated with future regressions. Wave 9 Phase 2 closure correctly identified them as pre-existing (not Wave 9's responsibility) and the parent session correctly verified by replaying against HEAD~10. The 11 failures should be ignored when measuring full-suite delta in subsequent campaigns until this intake closes.
