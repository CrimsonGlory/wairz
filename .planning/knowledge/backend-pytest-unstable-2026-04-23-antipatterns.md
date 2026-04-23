# Anti-patterns: backend-pytest-unstable-tests fleet (2026-04-23)

> Extracted: 2026-04-23
> Session: `.planning/fleet/session-backend-pytest-unstable-2026-04-23.md`

## Failed Patterns

### 1. Scout-level "service is broken" hypothesis without reading raw test assertions
- **What was done:** Scout B (session 5321d5a1, 2026-04-20) classified `test_cache_module.py`'s 2 failures as "failures appear to be real product bugs (commit-vs-flush discipline per Rule #3), not test bugs". The seed's Session +2 plan propagated this claim verbatim: "pre-flight re-measure required; likely a Rule #3 violation in the service."
- **Failure mode:** Had Stream γ's sub-agent trusted the scout's diagnosis and edited `_cache.py` to "fix" a commit-vs-flush bug, it would have introduced a real bug into working code (the service IS Rule #3-compliant). The tests' actual assertions — `assert not hasattr(db, "commit_invoked")` against an AsyncMock and `assert str(fw_id) in compiled` against SQLAlchemy's hex-literal rendering — are themselves broken.
- **Evidence:** Pre-flight re-run in session file §Pre-flight Findings #1; γ brief "cache_module diagnosis match: confirmed test-bug exactly as pre-flight stated" (the FLEET caught the scout's error BEFORE dispatching γ).
- **How to avoid:** For any scout / seed / intake claim of the form "test X fails because service Y is broken", re-run the failing test and READ the assertion text before accepting the diagnosis. The pre-flight re-measure (Rule #19) costs ~2 minutes; the alternative is an hour of "fixing" a non-bug + another hour reverting.

### 2. Per-stream test subdir as the default isolation mechanism for concurrent pytest
- **What was done:** The original stream-prompt template instructed each agent to use `/app/tests-{alpha,beta,gamma}/` as an isolated test root to avoid `docker cp` collisions during concurrent pytest runs.
- **Failure mode:** 2 of 3 streams (α, γ) hit `ModuleNotFoundError: No module named 'tests.harness'` or `tests.fixtures.mobsf_baselines.extract_mobsf_baselines`. Python's import system resolves `from tests.X import Y` against `sys.path` → the package named `tests` under `/app/tests/`, not `/app/tests-alpha/`. The `pyproject.toml` at `/app/` anchors the canonical tests package location.
- **Evidence:** α brief "per-stream subdir broke cross-test-package imports"; γ brief same fallback. β's 5 files happened to have no cross-package imports, so β alone succeeded with the per-stream pattern.
- **How to avoid:** Stop offering per-stream subdir as the DEFAULT. Offer it as a "try-first, fall-back-quick" optimization. Canonical `/app/tests/` + `/tmp/wairz-pytest.lock` file-lock is the default-safe pattern. Long-term fix: audit `from tests.X` cross-imports and migrate to absolute `from backend.tests.X` paths OR consolidate shared helpers into `conftest.py`.

### 3. Stale intake line counts trusted without re-measurement
- **What was done:** The intake `backend-pytest-unstable-tests.md` was written on 2026-04-19 and claimed "18 test files with ~189 failing tests". On 2026-04-23 at dispatch time, the workflow had **15** `--ignore=` lines — 3 files had been silently fixed by unrelated work (session-handoff-2026-04-20 extras) in the intervening days.
- **Failure mode:** If the fleet had pre-allocated 18 stream slots or built 18 per-file dispatch prompts based on the intake count, 3 slots would have no target. More subtly: if a sub-agent's prompt listed a file that wasn't in the workflow's ignore list anymore, the agent might assume it still needed fixing (Rule #19 violation) or remove a non-existent ignore line and commit a no-op.
- **Evidence:** `grep -c '\-\-ignore=' .github/workflows/backend-tests.yml` at session start: **15**, not 18. Seed self-reported: "`backend-pytest-unstable-tests` deep-read; re-measure first". The seed recognized the risk but couldn't act on it.
- **How to avoid:** ALWAYS run the intake's own acceptance grep at dispatch time. For this intake it was `grep -c '\-\-ignore=' .github/workflows/backend-tests.yml`. If the count differs from the intake's stated count, adjust the stream decomposition (or dispatch budget) accordingly AND note the drift in the session file for the eventual postmortem.

### 4. Assertion pattern `assert not hasattr(mock, "X_invoked")` against MagicMock/AsyncMock
- **What was done:** `test_cache_module.py:215` — `assert not hasattr(db, "commit_invoked")` where `db` is an `AsyncMock`. The intent seems to have been "verify the code never called `commit()`", but the implementation is unreachable: MagicMock/AsyncMock auto-creates any attribute access at arbitrary depth, so `hasattr(db, "commit_invoked")` ALWAYS returns True.
- **Failure mode:** The test always fails (False; mock always has any attribute) in a way that LOOKS like a product bug. Worse: if the mock is replaced with a real object that doesn't have `commit_invoked`, the assertion passes for the wrong reason (real object genuinely lacks it, not because commit wasn't called).
- **Evidence:** Pre-flight re-run; γ commit `81949b7` fixing this to `db.commit.assert_not_called()` + `db.flush.assert_called_once()`.
- **How to avoid:** **New harness rule (see below).** Use the mock's call assertions (`.assert_not_called()`, `.assert_called_once_with(...)`) — never `hasattr` against a mock for negative assertions. For positive assertions, use `.called` or `.call_args`.

### 5. Assertion pattern `str(uuid) in compiled_sql` without `uuid.hex`
- **What was done:** `test_cache_module.py:233` — `assert str(fw_id) in compiled` where `fw_id` is a `UUID` and `compiled` is the string of a SQLAlchemy-compiled SQL statement. SQLAlchemy renders UUIDs in compiled SQL as **hex literals without dashes** (e.g. `'b6a51a15593d409086406c529308e670'`), but `str(uuid.UUID(...))` produces the dashed form (`'b6a51a15-593d-4090-8640-6c529308e670'`).
- **Failure mode:** Assertion always fails for UUIDs with any non-zero byte — the dashed form is never a substring of the hex form. Diagnostic looks like "SQLAlchemy is rendering UUIDs wrong", but the test assertion is what's wrong.
- **Evidence:** Pre-flight re-run; γ commit `81949b7`. Raw error: `assert 'b6a51a15-593d-4090-8640-6c529308e670' in "DELETE FROM analysis_cache WHERE analysis_cache.firmware_id = 'b6a51a15593d409086406c529308e670'"`.
- **How to avoid:** **New harness rule (see below).** Use `fw_id.hex in compiled` or `str(fw_id).replace('-', '') in compiled`.

### 6. Patching `app.services.X_service.Y` when `Y` is lazy-imported inside a function body
- **What was done:** 3 streams independently hit the same pattern — tests used `patch("app.services.androguard_service.APK")` (α, γ) or `patch("app.services.bytecode_analysis_service.AnalyzeAPK")` (β). In each case, the service module does NOT `import APK` at module scope; it does `from androguard.core.apk import APK` inside `def scan_apk(...)`. The symbol `APK` is never bound at `app.services.androguard_service` module scope, so the patch is a no-op — the real `APK` is used, and the test mock is ignored.
- **Failure mode:** Test appears to run the mock, but actually hits the real androguard code against a fake APK path → `FileNotFoundError` or wrong output. Hard to diagnose because the test LOOKS like it should work (the mock module exists; the attribute APK doesn't exist on it, which is silently accepted by `unittest.mock.patch` with `create=True` default behavior in some paths).
- **Evidence:** α brief "androguard.core.apk.APK is the correct patch target"; β brief "AnalyzeAPK patch at service module but source is androguard.misc"; γ brief "scan_harness orchestrator patches app.services.androguard_service.APK; APK is lazy-imported so patch target should be androguard.core.apk.APK (same defect as α)". Three independent discoveries over 3 streams.
- **How to avoid:** For any mock patch targeting `app.services.X_service.<ThirdPartySymbol>`, first `grep -n "import <ThirdPartySymbol>" backend/app/services/X_service.py`. If the import is function-local, patch the SOURCE module (e.g. `androguard.core.apk.APK`), not the service module. Candidate harness rule (medium confidence, narrow applicability) appended.
