---
title: "Backend: Fix 18 Unstable Test Files (Unlock Full CI)"
status: resolved
resolved_at: 2026-04-23
resolved_in: fleet session backend-pytest-unstable-2026-04-23 (α/β/γ streams)
resolved_shas:
  - 01182fc  # merge α — Android/MobSF
  - 50d1bc1  # merge β — Hardware/Firmware + intent:// fix
  - c53800c  # merge γ — Data/Emulation
  - 2fae870  # workflow rename: "Pytest (Backend)"
priority: medium
target: backend/tests/
created_at: 2026-04-19
created_in: session 480666ce — discovered when adding pytest CI workflow
---

## Resolution note (2026-04-23)

Rule #19 re-measure: at dispatch the workflow had **15** `--ignore=` lines (not 18
as the intake title claims — 3 test files had been fixed via unrelated work
between 2026-04-19 and 2026-04-23, confirming Rule #19 hygiene: never trust a
count that's >24 hours old).

Fleet dispatch with 3 disjoint streams:
- α (Android/MobSF, 5 files): 167 tests green, 3 skipped (documented), 0 product changes
- β (Hardware/Firmware, 5 files): 236 tests green, 1 product fix (intent:// scheme in `_SENSITIVE_SCHEMES`), preserved Rule #1 symlink-rejection contract
- γ (Data/Emulation, 5 files): 163 tests green, 1 xfail (aspirational zip-entry-count check not yet implemented), 0 product changes

Zero cross-stream sweeps (Rule #23 worktree discipline). Final full pytest:
**1706 passed, 3 skipped, 1 xfailed** in 57s. Workflow job renamed from
"Pytest (Backend, Stable Subset)" → "Pytest (Backend)".

Pattern note: per-stream `/app/tests-{name}` subdirs failed for files that
cross-import within the `tests` package (e.g. `from tests.harness.orchestrator
import ...`). Fallback canonical `/app/tests/` path + `/tmp/wairz-pytest.lock`
file-lock worked for α and γ. β's files had no cross-package imports, so its
per-stream subdir ran without the lock.

---

## Context

Session 480666ce added `.github/workflows/backend-tests.yml` — CI now runs
backend pytest on a STABLE SUBSET (60 of 78 test files, 1086/1086 passing).
18 test files were excluded via `--ignore=` flags to keep the CI signal
trustworthy on day 1. Those 18 files held ~189 failing tests at measurement
(2026-04-19); the failures are pre-existing (not caused by recent refactors).

This intake is the cleanup pass: walk the 18 files, triage each failure as
**test bug** / **product bug** / **missing fixture** / **deprecated API**,
fix what's cheap, mark intentional skips with `@pytest.mark.skip(reason=...)`,
then remove the corresponding `--ignore=` line from the workflow.

## The 18 files

Grouped by likely failure class (to be confirmed per-file during triage):

### Probably-test-bug (stale fixtures, patch targets)
- `tests/test_cache_module.py` — 2 failures observed: `test_does_not_commit_only_flushes` (asserts AsyncMock lacks `commit_invoked` attribute; MagicMock auto-creates any attr — assertion pattern is wrong); `test_deletes_all_rows_for_firmware` (asserts UUID str in compiled SQL, but SQLAlchemy renders without hyphens in the compiled literal).

### Needs investigation — large numbers of failures
- `tests/test_bytecode_analysis.py`
- `tests/test_diva_manifest_scan.py`
- `tests/test_emulation_auth.py`
- `tests/test_false_positive_rate.py`
- `tests/test_fp_rate_computation.py`
- `tests/test_hardware_firmware_classifier_patterns.py`
- `tests/test_hardware_firmware_parsers.py`
- `tests/test_hardware_firmware_router.py`
- `tests/test_mobsf_baseline_comparison.py` (also has `ERROR` collection failures)
- `tests/test_mobsf_parity.py`
- `tests/test_ovaa_manifest.py`
- `tests/test_scan_harness.py`
- `tests/test_synthetic_apk_fixtures.py`
- `tests/test_zip_bomb_prevention.py`

### Previously-red-now-green (excluded from the workflow but PASSING locally — kept in the ignore list out of caution)
_None as of measurement; re-check during cleanup._

## Approach

Per Rule #22 — grep all sites first. For each file:

1. `docker compose exec -T backend /app/.venv/bin/python -m pytest tests/<file>.py --tb=short` — get the full failure report.
2. Classify:
   - **Test bug** (patch target stale / fixture wrong) → fix test.
   - **Product bug** (real regression) → either fix product code OR mark xfail with linked issue.
   - **Environment-dependent** (needs network, specific binary, etc.) → mark skip with `reason=`.
   - **Deprecated** (tests a removed feature) → delete the test.
3. Commit per-file: `test(<file>): fix/skip/delete N failing cases`.
4. When the file is green, remove its `--ignore=` line from `.github/workflows/backend-tests.yml` in the same commit.

Discipline: one file per commit. When the last `--ignore=` line is removed,
final commit can drop the "stable subset" language in the workflow comment
and in its job name.

## Acceptance

- `grep -c '\-\-ignore=' .github/workflows/backend-tests.yml` → 0.
- `docker compose exec backend /app/.venv/bin/python -m pytest tests/ --tb=no -q` on main → 0 failures, 0 errors.
- Workflow job name in `.github/workflows/backend-tests.yml:21` changed from `"Pytest (Backend, Stable Subset)"` to `"Pytest (Backend)"`.

## Estimated Scope

2-3 sessions. Fleet-parallelizable if domains decompose cleanly (Android/MobSF
cluster vs. hardware_firmware cluster vs. emulation/fuzzing cluster vs. data
schema cluster).

## References

- Workflow: `.github/workflows/backend-tests.yml`
- Baseline measurement: session 480666ce (2026-04-19) — 1086/1086 stable, 199 fail / 36 error in the 18 excluded files.
- Rule #19: measure first. Do not re-ignore files that are now green.
- Rule #25: one commit per independently-verifiable sub-task (one file = one commit).
