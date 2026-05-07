# Anti-patterns: Phase 2 — Test Coverage Backfill (21 routers + 26 services)

> Extracted: 2026-05-08
> Campaign: `.planning/campaigns/phase-2-test-coverage-routers-services-2026-05-06.md`

## Failed Patterns

### 1. Trusting session-end "remaining N" memory over the structured triage table

- **What was done:** Wave 9 closeout report claimed "Remaining 3 services for Wave 10 triage." The campaign's structured Triage table (line 191) listed 5 candidates.
- **Failure mode:** Without `git ls-files` reconciliation at Wave 10 kickoff, the wave would have proceeded against 3 of 5 candidates — leaving 2 services silently uncovered and claiming "Phase 2 complete" against an incorrect baseline.
- **Evidence:** Wave 10 dispatch protocol's mandatory `git ls-files` step caught the discrepancy before authoring.
- **How to avoid:** When a campaign log claim and a structured table disagree, the table is more likely correct because it's measurement-derived. Re-run `git ls-files` per candidate at every wave kickoff. Companion to Rule #31 (broadest-reasonable grep canary) and Rule #19 (evidence-first).

### 2. Pure-mock tests for value-flow contracts

- **What was done:** Initial-instinct tests for some services would have used `mock_db.add.call_count == N` style assertions to "verify" persistence behavior.
- **Failure mode:** Mock unit tests verify dispatch shape ("X was called"), not value flow ("X was called with the right args AND the persisted row reflects them"). Wave 9's `grype_service` would have shipped with a F-A-06 confidence-bypass regression invisible to mock-only tests; the live-canary on persisted SbomVulnerability + Finding rows caught it.
- **Evidence:** Rule #35b discipline applied to all 40 substantive files; 0 known value-flow regressions in shipped tests.
- **How to avoid:** Per CLAUDE.md Rule #35b — every new test file must include at least one Rule #35b live-canary that round-trips through the real ORM via `tests._live_db.make_live_db` and SELECTs the persisted row.

### 3. Naive `patch("app.services.X.Y")` for lazy-imported third-party `Y`

- **What was done:** Initial Rule #30 misapplication — patching the consumer module for a symbol that's lazy-imported inside a function body.
- **Failure mode:** Silent no-op. The patch never resolves because the consumer module never bound the symbol at module scope; the real `Y` runs against fake test inputs and produces downstream `FileNotFoundError` or shape mismatches that look like service bugs.
- **Evidence:** Pre-authoring Rule #30 mechanical grep applied to all 40 test files; companion lesson from session 0801ca27's pytest-unblock fleet (+620 tests unlocked when patch targets corrected).
- **How to avoid:** Run `grep -nE "^[[:space:]]+(from|import)" backend/app/services/X.py` BEFORE writing any patch. If indented matches surface, use SOURCE-patch shape: `patch("<lib>.<Symbol>")` for sub-attribute-style, or `patch.dict(sys.modules, {"<libname>": fake_module})` for full-module replacement. Pair every `sys.modules` injection with a `not hasattr(consumer_module, "<libname>")` sentinel.

### 4. Bare-string JSONB `server_default="'[]'"` band-aid

- **What was done:** Wave 1 hit `JSONDecodeError: Expecting value` at flush time on EmulationSession.port_forwards. Initial workaround: every test EmulationSession constructor passes `port_forwards=[]` explicitly.
- **Failure mode:** Wave 2 hit the same shape on FuzzingCampaign.config + .stats. The band-aid would have multiplied across every future bare-string JSONB column. Symptom: SQLite's dialect-level JSON processor double-decodes against `_live_db.py`'s shim because both processors fire when DDL renders as JSON type.
- **Evidence:** Wave 2 commit `080c10d` shim hardening eliminated the gotcha for all current and future cases.
- **How to avoid:** When designing new ORM models with JSONB columns, prefer `server_default=text("'{}'")` (text-expression) over bare-string `server_default="'{}'"`. If bare-string is necessary, the Wave 2 shim handles it. Documented in `tests/_live_db.py:67`.

### 5. Stale nested `/app/tests/tests/` directory from prior `docker cp` invocations

- **What was done:** Across multiple prior sessions, `docker cp host/path/test.py <container>:/app/tests/test_X.py` invocations were run from inside the `backend/` directory, leading to host-relative-path interpretation that landed files at `/app/tests/tests/test_X.py` instead of `/app/tests/test_X.py`.
- **Failure mode:** Wave 8 full-suite smoke initially reported 27 failures from the stale nested directory containing 87 outdated test files. False-alarm investigation cost ~5 minutes.
- **Evidence:** Wave 8 cleanup via `docker compose exec backend rm -rf /app/tests/tests`.
- **How to avoid:** Use host-absolute paths in `docker cp`: `docker cp /home/dustin/code/wairz/backend/tests/test_X.py <container>:/app/tests/test_X.py`. Audit `/app/tests/` periodically during long campaigns.

### 6. Pre-existing failures masquerading as campaign regressions

- **What was done:** Wave 9 full-suite smoke surfaced 12 failures. Initial reaction risk: blame Wave 9's contribution.
- **Failure mode:** The 12 failures predate Wave 9 by 4-10 commits (post-Wave-8 sbom 202+polling refactor + alembic chain repair + new vuln_scan CHECK constraint). Misattributing them to Wave 9 would have triggered unnecessary rework.
- **Evidence:** Verified non-attributability by running ONLY the 4 Wave 9 test files in isolation (111/111 pass cleanly).
- **How to avoid:** When the wave-end full-suite gate surfaces unexpected failures, FIRST run only the wave's own test files in isolation. If those pass, the failures are pre-existing and belong to a separate intake; do NOT close them under the campaign's signoff. Companion to Rule #19 (evidence-first).

### 7. Host-venv pytest invocation when backend container is the canonical environment

- **What was done:** Phase 2 close-out used `cd backend && .venv/bin/pytest tests/` to run the full-suite smoke gate.
- **Failure mode:** Host venv runs Python 3.14 (vs container's 3.12) and lacks tools (`cpu_rec`, `git`, `tar`/`fat` utilities, websocket env) that several tests assume. 7 environmental failures surface at every host-venv run that don't surface in the backend container.
- **Evidence:** Wave 9's container-run smoke showed only the 12 alignment-class failures; host-venv runs add 7 environmental failures on top.
- **How to avoid:** Install pytest into the backend dev image (currently `--no-dev`) and route the campaign full-suite gate through `docker compose exec backend ... pytest`. Filed as a recommendation in the postmortem; separate intake to follow.

### 8. Untested router silently shipping a NameError

- **What was done:** `apk_scan.py` bytecode endpoint referenced `_cache` without importing it. The endpoint had zero router-level test coverage before Phase 2.
- **Failure mode:** NameError shipped silently to production. No test, no canary, no log; only a runtime hit on the bytecode endpoint would have surfaced it.
- **Evidence:** Wave 1 author writing `test_apk_scan_router.py` — first real call against the endpoint surfaced the bug. Fixed in commit `4a6357f`.
- **How to avoid:** Per CLAUDE.md "Every new router gets a router-level test file" — adding a new file under `backend/app/routers/` MUST add a matching `backend/tests/test_<router>.py` in the same PR. Phase 2 backfilled the historical gap; the Wave-5 router-test mandate prevents future recurrences.
