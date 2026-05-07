# Patterns: Test Maintenance Triage 2026-05-06

> Extracted: 2026-05-07
> Triage scope: 5 pre-existing test failures uncovered by Wave 6 full-suite smoke
>   (commits 98cc0fd..a607908; 5 fixes, 0 production code changes)
> Companion campaign: phase-2-test-coverage-routers-services-2026-05-06
> Postmortem: none (mid-campaign cleanup, not a standalone campaign)

## Successful Patterns

### 1. Full-suite smoke as a Wave-end gate
- **Description:** After every wave that adds N new test files, run the full
  backend suite (`pytest tests/ --ignore=tests/tests`) and treat any failure
  outside the wave's own files as a triage candidate. Most failures are
  pre-existing drift the wave's tests merely caused to be SEEN; ignoring them
  perpetuates the drift.
- **Evidence:** Wave 6 ran full-suite smoke after the 5 service tests
  shipped; surfaced 9 pre-existing failures (Groups A-E), 5 of which
  were 1-line fixes and 4 of which were already broken before this campaign
  started. Without the smoke gate, all 9 would have remained latent.
- **Applies when:** every wave end of any test-coverage campaign, AND any
  session where ≥3 test files are added/modified.

### 2. Per-group commit discipline for triage cleanup
- **Description:** When triaging N pre-existing failures, group them by
  ROOT CAUSE (not by test file), commit each group as its own bisect-clean
  patch with a commit message that names: (a) the production change that
  caused the drift, (b) the failure mode, (c) the resolution shape.
  Mirror Rule #25's per-feature-commit discipline for fixes.
- **Evidence:** 5 commits this session (98cc0fd / 38eda51 / 6a7f8a2 / a08473f /
  a607908), each closing one root cause: schema_version stamp drift /
  cross-stack path resolution / loose migration matcher / DeviceDump exclusion
  miss / mock setup gap. Each commit independently revertable.
- **Applies when:** any triage cleanup that touches ≥3 test files for ≥2
  distinct root causes.

### 3. Run host-side AND container-side as a verification matrix
- **Description:** When fixing a cross-stack contract test (DB ↔ frontend),
  verify the fix BOTH inside the backend container (where it should skip)
  AND on the host (where it should actually execute the alignment check).
  Pure container-side verification can mask a bug where the skipif
  condition is too aggressive and the test never runs anywhere.
- **Evidence:** Group B fix on `test_finding_source_alignment.py` —
  verified container skip (3 skipped) AND host execution (3 passed in
  0.48s) before committing. Confirmed alignment is actually clean as of
  2026-05-06; the skipif doesn't hide a real drift.
- **Applies when:** any fix that adds `pytest.mark.skipif` with an
  environmental condition, especially path-existence checks.

### 4. Forward-compatible stamp assertion (pop-and-assert)
- **Description:** When a JSONB column is stamped with `schema_version`
  by a normaliser/stamper helper, tests asserting on the persisted dict
  should:
    1. Pop `schema_version` into a local variable.
    2. Assert the popped value equals the current schema constant
       (forward-compatibility: a bump fails the test loudly with a
       clear "stamp version mismatch" rather than a confusing
       dict-equality diff).
    3. Assert remaining-dict equality against the writer-supplied
       payload.
  Refs jsonb_normalizers.py:134 (`payload["schema_version"] =
  ANALYSIS_CACHE_RESULT_SCHEMA_VERSION`).
- **Evidence:** Group A fix on `test_cache_module.py` — pop + assert
  stamp == 1, then assert remaining-dict equality. Forward-compat: when
  the schema bumps to 2, the test fails with a specific stamp-mismatch
  signal, not a confusing structural diff.
- **Applies when:** any test that compares an entry's stamped JSONB
  column against a writer-supplied payload.

### 5. Migration-matcher regex must require quoted constraint name
- **Description:** When a test-time helper walks alembic migrations to
  find "the file that creates `<constraint_name>`", the matcher MUST
  require the constraint name to appear in QUOTED form (single or
  double Python string quotes) AND ideally as the first positional
  argument to `op.create_check_constraint(...)`. Loose substring matches
  (`"<name>" in text` or `f'"{name}"' in text`) silently match docstring
  references that cite the constraint as a precedent — and silently
  return the WRONG migration's allowlist tuple.
- **Evidence:** Group C fix on `test_fuzzing_status_check_alignment.py`
  — matcher loaded `b0c1a2d3e4f5_add_device_dump_sessions.py` (which
  cites `ck_fuzzing_campaigns_status` in a docstring) instead of
  `d8e9c4b5f7a2_widen_fuzzing_campaigns_status_check.py` (the actual
  migration recreating the constraint). The wrong tuple
  (`DEVICE_DUMP_STATUS_VALUES`) was loaded and the service's writes
  failed alignment for 3 unrelated values.
- **Applies when:** any test that parses alembic migrations to extract
  allowlist tuples for CHECK-constraint alignment. The same shape applies
  to ENUM allowlists, TYPE allowlists, etc. wherever migrations are
  walked by name.

### 6. Mock-builder helper for service-evolved guards
- **Description:** When a service adds a new validation guard (e.g.
  same-content-reupload 409 at firmware_service.py:362-381) and existing
  test mocks don't account for it, build a NAMED helper that returns the
  correctly-configured mock with documentation citing the service line.
  Example: `_mock_db_no_duplicates()` returns an AsyncMock whose
  `db.execute(...).scalar_one_or_none()` is None — the shape every
  upload-related test now needs.
- **Evidence:** Group E fix on `test_tar_of_image_integration.py` —
  3 tests went from inline `AsyncMock()` (bare → false-positive 409) to
  shared `_mock_db_no_duplicates()` with inline citation
  ("firmware_service.py:362-381"). Future tests in the same area can
  import + call the helper instead of re-discovering the gap.
- **Applies when:** ≥2 test files mock the same service whose validation
  surface has grown. The helper amortises the documentation cost; the
  citation comment makes the next regression's repro 1 line away.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Triage during this session, NOT defer to a separate campaign | Failures are 1-2 line fixes; campaign overhead exceeds the work itself | 5 commits in ~30 min, 0 regressions, suite now at 0-failure baseline |
| Module-level skipif over per-test skipif | All 3 finding_source_alignment tests share the same prerequisite (frontend/ accessible); module-level marker is more discoverable than 3 inline skips | Single 7-line guard; tests still execute on host; no test logic changes needed |
| Tighten regex matcher rather than rename constraint | The constraint name is correctly stable; the matcher was the bug | One regex change; preserves the docstring discipline of citing related constraints |
| Add `cancelled` to exclusion set rather than make matcher smarter | The grep is intentionally broad to catch all `<X>.status = "lit"` patterns; the exclusion list documents which OTHER models the same files touch | 1-line addition with inline comment naming the source migration |
| Helper function over inline mock setup for db.execute | Shape will recur for every test mocking firmware upload going forward | Single source of truth + service-line citation |

## Quality Rule Candidates

(none promoted — the patterns are discipline-level and don't lend themselves
to clean regex enforcement at the file-write level. The Rule #5 discipline
"migration-matcher regex must require quoted constraint name" is a code-
review pattern, not an automated lint target.)
