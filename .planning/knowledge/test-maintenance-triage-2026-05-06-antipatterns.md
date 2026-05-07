# Anti-patterns: Test Maintenance Triage 2026-05-06

> Extracted: 2026-05-07
> Triage scope: 5 pre-existing test failures uncovered by Wave 6 full-suite smoke
>   (commits 98cc0fd..a607908; 5 fixes, 0 production code changes)
> Companion campaign: phase-2-test-coverage-routers-services-2026-05-06

## Failed Patterns

### 1. Test asserts on a JSONB column without accounting for schema_version stamp
- **What was done:** `test_cache_module.py::TestStoreCached::test_delete_then_insert_per_binary`
  asserted `entry.result == {"warnings": []}` against a payload that
  `_stamp_analysis_cache_result` had decorated with `schema_version=1`.
- **Failure mode:** Equality check fails with a confusing structural diff;
  the test author has to chase down the helper function to discover the
  stamp source.
- **Evidence:** audit-2026-05-04 introduced the boundary-normaliser sweep
  with `_stamp_<column>` helpers (jsonb_normalizers.py); pre-existing tests
  weren't updated. Group A failure surfaced when Wave 6 ran the full suite.
- **How to avoid:** When the audit-2026-05-04 stamp pattern (or any
  similar version stamp) is introduced, grep for tests asserting on the
  affected column's full equality and update them to pop-and-assert per
  pattern #4 in the patterns file. Cheap; prevents the next regression
  from looking the same.

### 2. Cross-stack contract test with hardcoded absolute path
- **What was done:** `test_finding_source_alignment.py` resolved
  `_FRONTEND_TYPES = _REPO_ROOT / "frontend" / ...` where `_REPO_ROOT`
  was `Path(__file__).parent.parent.parent`. In the host repo, that's
  `/home/dustin/code/wairz/frontend/...` — works. Inside the backend
  container with `/app/` mounted from `backend/`, it resolves to
  `/frontend/...` which doesn't exist.
- **Failure mode:** `FileNotFoundError: [Errno 2] No such file or directory:
  '/frontend/src/types/index.ts'` for every container-side test run since
  the test was added.
- **Evidence:** test_finding_source_alignment.py:147; the path computation
  was correct on host but wrong in container. 3 tests failing identically.
- **How to avoid:** Cross-stack contract tests (DB ↔ frontend, backend ↔
  CI scripts, etc.) need an environmental skip when the cross-stack
  artefact isn't accessible. Use module-level `pytest.mark.skipif` on a
  path-existence check, with a reason that explicitly says "running in
  a container with only X mounted".

### 3. Migration-matcher regex matches docstring text
- **What was done:** `_latest_status_check_migration_path` walked alembic
  files and matched any whose text contained the constraint name AND
  `create_check_constraint` ANYWHERE. The constraint name appearing in a
  docstring (markdown backticks) counted as a match, returning the wrong
  migration.
- **Failure mode:** Returned `b0c1a2d3e4f5_add_device_dump_sessions.py`
  (which cites `ck_fuzzing_campaigns_status` in a precedent-naming
  docstring) instead of `d8e9c4b5f7a2_widen_fuzzing_campaigns_status_check.py`
  (the actual migration recreating the constraint). Loaded the wrong
  allowlist tuple (`DEVICE_DUMP_STATUS_VALUES`); flagged 3 unrelated
  status values as illegal.
- **Evidence:** Group C debug session — `_latest_status_check_migration_path()`
  returned `b0c1a2d3e4f5_add_device_dump_sessions.py`; expected
  `d8e9c4b5f7a2_widen_fuzzing_campaigns_status_check.py`.
- **How to avoid:** Migration matchers MUST require the constraint name
  in QUOTED form (single or double Python quotes), and ideally as the
  first positional argument to `create_check_constraint(...)`. Markdown
  backticks in docstrings should NOT match. Pattern #5 in the patterns
  file documents the regex shape.

### 4. Status alignment test exclusion list misses one DeviceDump value
- **What was done:** `test_project_status_writes_in_allowlist` greps
  for `<X>.status = "lit"` in 3 files (firmware router, arq worker,
  device service) and compares hits to the `ck_projects_status` allowlist,
  filtering out hits that belong to other models. The exclusion list
  included `partial` (a DeviceDumpSession status added in
  b0c1a2d3e4f5) but missed `cancelled` (the same migration's other
  new value).
- **Failure mode:** `device_service.py:233` writes
  `row.status = "cancelled"` against a DeviceDumpSession row, but the
  test grepped it as if it were a Project row → flagged as illegal.
- **Evidence:** Group D failure with explicit message
  `unexpected status literals in project-touching files: {'cancelled'}`.
- **How to avoid:** When a migration adds NEW status values to a model
  whose service file is grepped by another model's alignment test, audit
  the alignment test's exclusion lists for ALL the new values (not just
  the ones the migration's first paragraph mentions). The discipline:
  a migration adding N new status values triggers an audit of N+1 tests
  (the new model's alignment test + 1 per cross-cutting alignment test).

### 5. Bare AsyncMock for AsyncSession misses chained mock returns
- **What was done:** `test_tar_of_image_integration.py` used
  `db = AsyncMock()` to mock the AsyncSession. By default, `db.execute()`
  returns an AsyncMock whose `.scalar_one_or_none()` returns ANOTHER
  AsyncMock — not None.
- **Failure mode:** When the service code added a same-content-reupload
  guard at firmware_service.py:362-381 (`SELECT Firmware.id WHERE ... → 409
  if exists`), the bare-AsyncMock chain reads as "duplicate exists" →
  fires the 409. Tests were unrelated to that guard but failed because
  the fixture didn't account for the new SELECT.
- **Evidence:** Group E failure with HTTPException at
  firmware_service.py:373; `existing_id =
  <coroutine object AsyncMockMixin._execute_mock_call ...>` — non-None.
- **How to avoid:** When a service file adds new validation guards
  involving `db.execute(SELECT ...).scalar_one_or_none()` calls, audit
  every test that mocks that service's session and add the matching
  result configuration. Better yet: build a NAMED mock-builder helper
  per pattern #6 in the patterns file that future tests import and reuse.

### 6. Treating "pre-existing" as "skip"
- **What was done:** In an earlier session, the 9 failing tests were
  noted as "pre-existing" and left unfixed. The Wave 6 close commit's
  HANDOFF described "9 pre-existing failures unrelated to Wave 6"
  without flagging them for cleanup.
- **Failure mode:** "Pre-existing failure" is a STATUS, not a
  RESOLUTION. The drift compounds — every wave that doesn't fix the
  drift adds noise to the failure list, until eventually the suite
  becomes too noisy to use as a regression gate.
- **Evidence:** 9 pre-existing failures had been around for an
  unknown number of days/weeks before Wave 6 surfaced them. None had
  open issues; none were tracked as cleanup work.
- **How to avoid:** When "pre-existing failure unrelated to my work"
  is the diagnosis, also: (a) note the failure in the campaign or
  session HANDOFF as a follow-up item, (b) when the wave's blast
  radius is small, fix the failures in-line as a separate commit per
  Rule #25; (c) when too large, file a triage intake. The wave-end
  smoke gate (pattern #1) is the trigger; "pre-existing → triage" is
  the response.
