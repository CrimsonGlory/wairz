# Patterns: backend-pytest-unstable-tests fleet (2026-04-23)

> Extracted: 2026-04-23
> Session: `.planning/fleet/session-backend-pytest-unstable-2026-04-23.md`
> Postmortem: none (fleet session, not a campaign)
> Streams: α Android/MobSF, β Hardware/Firmware, γ Data/Emulation — all success

## Successful Patterns

### 1. Pre-flight Rule #19 re-measure before believing any "N failures" claim
- **Description:** Before dispatching streams, run the actually-failing tests and inspect the raw assertion output. In this session, the pre-flight found that (a) the workflow had 15 `--ignore=` lines, not 18 as the intake claimed (3 files had been silently fixed by unrelated work); (b) Scout B's Rule #3 hypothesis on `test_cache_module.py` was wrong — both failures are test-bug shape (MagicMock hasattr auto-creation + SQLAlchemy UUID hex rendering), not service bugs.
- **Evidence:** Session file §Pre-flight Findings; γ brief "cache_module diagnosis match: confirmed test-bug exactly as pre-flight stated"; saved Stream γ from editing `_cache.py` unnecessarily.
- **Applies when:** Any intake, seed, or scout report is >24 h old OR claims a specific count of affected files/failures. Cost is ~2 min; savings can be an entire stream's dispatch budget.

### 2. Worktree discipline via literal `git worktree add` in every sub-agent prompt
- **Description:** Each of the 3 stream prompts contained the verbatim command `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-pytest-2026-04-23 e52f4fc` followed by `cd .worktrees/stream-{name}` BEFORE any file-write instruction. Result: 0 cross-stream sweeps across 19 file-level commits. Confirms Rule #23 evidence (now 5 of 6 consecutive fleet successes under this discipline — session 7e8dd7c3 was the 4th, this is the 5th).
- **Evidence:** Session file §Cross-Stream Sweep Audit (0 sweeps); β's 7 commits + α's 6 commits + γ's 6 commits merged cleanly except for expected workflow-line adjacency conflicts.
- **Applies when:** Any fleet dispatch with ≥2 streams writing to the same repo. `isolation: "worktree"` parameter is still a no-op at working-tree level — the prompt must carry the explicit command.

### 3. Lazy-import patch target = source module, not service module
- **Description:** When a service body contains `from androguard.core.apk import APK` inside a function (lazy import), tests patching `app.services.androguard_service.APK` are useless — the symbol was never bound at `app.services.androguard_service` module scope. Correct patch target is the source module (`androguard.core.apk.APK`). Three streams discovered this independently: α retargeted 6 APK patches; β retargeted 1 AnalyzeAPK patch in bytecode test; γ retargeted the orchestrator's APK patch. Triple-independent discovery = high confidence this is a systemic pattern in the codebase.
- **Evidence:** α brief "androguard.core.apk.APK is the correct patch target"; β brief "AnalyzeAPK patch at service module but source is androguard.misc"; γ brief "same defect as α".
- **Applies when:** Any test using `patch("app.services.X_service.Y")` where Y is a class/function from a third-party library. Verify by grepping the service for `from <lib> import Y` at MODULE scope vs. function-body scope.

### 4. Baseline-parity assertion: `>=N` not `==N` when checks can legitimately grow
- **Description:** When a test asserts against a vulnerable-APK baseline (DIVA, OVAA, InsecureBank) for "this scanner catches at least the known issues", use `assert len(findings) >= expected_count`, not `== expected_count`. Adding new checks (e.g. MANIFEST-013) will tick the count up; the baseline's semantics are "no worse than this", not "exactly this".
- **Evidence:** α commit 822cb28 (`test(ovaa_manifest): loosen finding-count to ≥7 to accommodate new checks`) — test was `assert == 7` at intake, actual count was 8 after MANIFEST-013 added.
- **Applies when:** Parity / regression / coverage tests against any growing baseline (MobSF fixtures, vulnerable-APK suites). Do NOT loosen if the test's purpose is "exact N" (e.g. deduplication tests) — read the test intent first.

### 5. Adjacent-hunk merge conflict resolution: drop both sides when each deletes a different block
- **Description:** When α deletes lines 10-14 of a file and β deletes lines 15-19, git's 3-way merge sees ONE adjacency conflict containing 5 HEAD-side lines (β wants removed) and 5 β-side lines (α wants removed). The resolution is to drop everything between `<<<<<<<` and `>>>>>>>` (both deletions apply). This is NOT "pick one side"; neither branch's CONTENT survives — both branches' DELETIONS survive.
- **Evidence:** Wave 2 merge at commit `50d1bc1` — conflict between α-merged HEAD (still had β's ignores) and β tip (still had α's ignores). Resolution: remove all 6 conflict-bracket lines, leaving only the 5 γ-owned lines that neither α nor β touched. Same pattern at `c53800c` (γ merge): all remaining ignores gone, zero remained.
- **Applies when:** Multi-stream fleet where streams modify different lines in a shared file. Pre-communicate expected conflict shape; resolver should sanity-check "does HEAD's outside-the-conflict content match the union of what SHOULD survive?" before committing.

### 6. Docker-cp iteration loop for backend test fixes (Rule #20 pattern)
- **Description:** Because the backend container bakes code into the image (no `/app` bind mount), test edits need to enter the container via `docker cp`. The 5-second iteration loop:
  ```bash
  docker cp backend/tests/<file>.py wairz-backend-1:/app/tests/<file>.py
  docker compose exec -T -w /app backend /app/.venv/bin/python -m pytest tests/<file>.py --tb=short
  ```
  vs. the 3-5 minute full rebuild per CLAUDE.md Rule #8. For pure test edits (no service-code change), no rebuild needed — the `.venv` has source-linked imports only for `/app/app/`, and tests are loaded from `/app/tests/` directly. For service-code edits, rebuild at stream end.
- **Evidence:** All 3 stream agents used variations of this pattern. β edited `components.py` (service code) and deferred rebuild to stream end (Rule #8); α and γ made test-only edits and needed no rebuild.
- **Applies when:** Any backend Python test-iteration task. Never for frontend (serves compiled bundle — see Rule #26). Class-shape changes on cached singletons still need `docker compose restart backend` (Rule #20 exception).

### 7. Per-stream test subdir `/app/tests-{name}` — works IFF no cross-package imports
- **Description:** To allow 3 streams to run pytest concurrently without `docker cp` collisions at `/app/tests/`, the original plan was per-stream subdirs. Works for pytest files that only `from app.X import Y` (absolute) but FAILS for test files that cross-import within the tests package, e.g. `from tests.harness.orchestrator import ...` or `from tests.fixtures.mobsf_baselines.extract_mobsf_baselines import ...`. Python resolves those against `sys.path` → `/app/tests/`, not `/app/tests-alpha/`. 1 of 3 streams (β) succeeded with the per-stream pattern; 2 of 3 (α, γ) fell back to canonical `/app/tests/` + `/tmp/wairz-pytest.lock` file-lock.
- **Evidence:** α brief "per-stream subdir broke cross-test-package imports"; γ brief same. β brief "no lock fallback needed" (β's 5 files had no cross-package imports).
- **Applies when:** Parallel pytest across streams. Cheap win: try per-stream subdir, fall back to canonical + lock on first `ModuleNotFoundError: No module named 'tests.X'`. Ideal long-term fix: refactor test cross-imports to use absolute `from backend.tests.X` or consolidate shared-helper imports into `conftest.py`.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 3 streams (α/β/γ) instead of 1 sequential pass | 15 test files disjoint by domain (MobSF, HW/firmware, Data/emulation); fleet parallelism validated in 7e8dd7c3 | 30 min wall-clock vs. ~90 min serial; 3× speedup; 0 sweeps |
| β fixes `intent://` scheme (MANIFEST-017) in-flight | Single additive dict-entry; preserving Rule #25 scope (single commit); alternative would be a new intake + another session | β merged cleanly; 1 product fix commit (`de8ed0f`) isolated and revertable |
| γ marks zip-bomb entry-count test `xfail(strict=True)` instead of implementing the feature | Feature was never implemented (aspirational); `xfail(strict=True)` locks the gap so a future impl can "green" the test | Preserved signal without scope-creeping into a new feature |
| Keep merged branches after worktree cleanup | Revert safety — `git revert -m 1 <merge-sha>` per stream still works | 3 branches retained: `feat/stream-{alpha,beta,gamma}-pytest-2026-04-23` |
| Per-stream test subdir attempted first, canonical+lock as fallback | Subdir gives true parallelism when feasible; fall-back is cheap | 1/3 streams used subdir; 2/3 fell back without cost |
| Wave 2 workflow rename as separate commit, not bundled with merges | Rule #25 + bisect-clean; a stale "Stable Subset" comment removal is a distinct concern from un-ignoring files | Final commit `2fae870` isolated the rename; `git log --oneline` tells the story cleanly |

## Metrics

- Baseline → Post: 1086 → **1706** tests passing (+620 tests unlocked)
- Commits: 19 file-level (6+7+6) + 3 merge + 1 rename + 1 campaign-close = **24 total**
- Cross-stream sweeps: **0** (Rule #23 evidence matrix now 5 of 6 successes)
- Product-code edits: **1 file** (β: `components.py` `_SENSITIVE_SCHEMES` += `intent`)
- Wall-clock: ~25 min dispatch + ~10 min merge/verify = ~35 min total
- Rebuild count: 1 (backend+worker after β's components.py edit, before final pytest)
