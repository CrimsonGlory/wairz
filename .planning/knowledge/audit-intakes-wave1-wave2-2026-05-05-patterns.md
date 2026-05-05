# Patterns: Audit-2026-05-04 Intake Execution Sweep (Wave 1 + Wave 2)

> Extracted: 2026-05-05
> Campaign: `.planning/campaigns/completed/audit-2026-05-04.md` (intake-execution phase, not the audit-RUN phase)
> Postmortem: not authored — autopilot session, no postmortem trigger
> Commit range: `1ed34a7..b7250c7` (14 commits)

The audit-RUN's patterns/antipatterns (filed by archon) are in
`audit-2026-05-04-{patterns,antipatterns}.md` — the meta-process of
running 9 parallel research streams. These files capture the
distinct EXECUTION/CLOSURE patterns from autopilot processing the 18
filed intakes, which is a different task shape.

## Successful Patterns

### 1. Wave-based ordering: ship-blocker XS → defect-closure small → bundle items
- **Description:** Process intakes in the audit-summary's recommended order (Wave 1 ship-blockers first, smallest first within wave). Wave 1 of 5 fixes was 4 XS + 1 small (alembic migration). Wave 2 of 7 fixes scaled up to medium (rate-limit decorators, finding-confidence propagation). Quick-wins picked opportunistically AFTER waves close.
- **Evidence:** 14 commits in 4-5 hours wall-clock, no reverts, no cross-stream sweeps. Earliest commits (filesystem.py select import, security.py safe_walk) closed in <3 minutes each. Later commits (rate-limit, finding propagation) took 30+ minutes but built on confidence from earlier wins.
- **Applies when:** Autopilot/archon processing N≥3 filed intakes that are independently revertable. Match per-session granularity to per-intake granularity (Rule #25 in execution mode).
- **Why it works:** XS wins build confidence and surface infrastructure issues (e.g. discovered the `tests/` dir is excluded from the production image during the Wave-1 fuzzing migration test) BEFORE the medium-scope fixes need that infra to work.

### 2. `docker cp` + Rule #11 reload smoke for fast iteration without rebuild
- **Description:** Each backend code change followed the pattern: edit on host → `docker cp <host>:<container>/app/...` → `python -c "importlib.reload(...); assert hasattr(...)"`. Skipped the 3-5 min `docker compose up -d --build backend worker` for every commit; ran the rebuild ONCE at end of batch.
- **Evidence:** 14 commits closed in one session; only ONE `docker compose up -d --build` ran (after Wave 2 closure). Each commit's verification used `docker cp` + reload — total per-commit verification <30 s vs ~3 min/rebuild = ~14 × 3 min = 42 min saved.
- **Applies when:** Backend code changes that are NOT class-shape edits (Rule #20). Pure function-body edits, import additions, decorator additions, single-file fixes.
- **Why it works:** Codifies CLAUDE.md Rule #20's "fast iteration" branch. The end-of-batch rebuild is what makes the migration auto-run at boot for the next session.

### 3. Live test verification via container after each fix
- **Description:** After each fix, copy the test file in (`docker cp ... wairz-backend-1:/app/tests/...`) AND run `docker compose exec backend /app/.venv/bin/python -m pytest tests/<new>.py -v`. Pre-existing tests like `test_finding_source_alignment.py` fail in-container (path issue with `/frontend/src/...`) but those are pre-existing — my new tests run cleanly.
- **Evidence:** Each Wave 1 + Wave 2 commit ran the new test in-container with exit=0 before commit. Pre-existing 38 finding-related tests verified unchanged for the confidence-propagation work.
- **Applies when:** Tests that depend ONLY on backend artefacts (no frontend file paths). For tests that span both, fall back to either fixing them later (CI-only) or running on host with full repo paths.
- **Why it works:** Confirms the test ACTUALLY runs (not skipped, not import-broken) before commit. A pre-commit "tests pass on my host" check is unreliable when host vs container Python versions / package versions diverge.

### 4. Structural test as discipline-locker
- **Description:** When a Wave-2 intake described "5 bypass paths drop confidence", I wrote `test_finding_confidence_propagation.py` that AST-walks every `.py` under `backend/app/`, finds every direct `Finding(...)` call OUTSIDE `finding_service.py`, and asserts `confidence=` AND `firmware_id=` are present in the kwargs set. Treat the structural test as the durable form of the discipline.
- **Evidence:** First test run failed and surfaced 4 ADDITIONAL bypass paths the original audit missed (Rule #31 width canary IRL): `routers/attack_surface.py:146`, `services/import_service.py:295`, `ai/tools/attack_surface.py:92`, `services/hardware_firmware/graph.py:336`. Final count: 9 bypass paths fixed (vs the audit's 5).
- **Applies when:** Any "every X must Y" rule where X is a syntactic shape detectable by AST or regex. Cross-cutting kwargs presence, decorator presence, import presence — all good fits.
- **Why it works:** A structural test surfaces the next bypass site at AUTHOR time, not runtime. Generalises Rule #31's narrow-vs-broad-grep canary to test code: a single `Finding(...)` constructor regex catches every bypass forever, even ones the original audit missed. Companion to live runtime canaries (Rule #35b) — both have a place; structural for "always" properties, runtime for "this specific value got persisted."

### 5. Filing surfaced-but-out-of-scope drift as a follow-up intake
- **Description:** Wave-1 #6 (models __init__.py exports) closure ran `alembic revision --autogenerate` to verify the metadata-sync acceptance criterion. Migration was NOT empty — surfaced 4 timestamp-type drifts + ~10 index/unique-constraint drifts in tables UNRELATED to cra_compliance/hardware_firmware. Rather than silently fix them or silently ignore, filed `audit-models-orm-vs-db-schema-drift-2026-05-05.md` with the full diff, marked the surfaced drift Out of Scope for the closing intake.
- **Evidence:** Commit `45dfdb9` references the follow-up intake. Sanity migration deleted from container, never committed.
- **Applies when:** Closing an intake's acceptance criterion exposes additional defects. Document the discovery, file a follow-up, ship the original closure on its own scope.
- **Why it works:** Rule #19 evidence-first means the intake's ORIGINAL scope was right; the new drift is a different scope. Bundling them risks blowing the original intake's review surface.

### 6. Mark blocked items with explicit blocker, not silently skip
- **Description:** `.env.example` is protected by Citadel's `external-action-gate.js` hook — every read attempt returned a "Blocked" tool error. Rather than skip silently, set the intake's frontmatter `status: blocked`, added a BLOCKED section explaining (a) which hook blocks it, (b) what the hook is correct about (can't distinguish .env from .env.example), (c) what the resume paths are.
- **Evidence:** Commit `d839de1` updates the intake. Future autopilot scans will see `status: blocked` and skip; an operator-driven session can flip to `pending` after resolving the hook.
- **Applies when:** Any intake whose closure path is gated on a system constraint (hook, permission, missing infrastructure) the autopilot can't resolve.
- **Why it works:** Discoverable. The blocker reason is co-located with the intake. Resolution paths are documented. The autopilot's next pass naturally skips it without re-investigating.

### 7. Recognize and skip intake-author-errors with documented reason
- **Description:** Quick-win M-5 said "remove `db.refresh.assert_awaited_once()` — codifies a no-op given `expire_on_commit=False`." But the audit-summary's own counter-finding (line 110) said: "the 3 `db.refresh` calls present are post-`flush()` and load-bearing for `onupdate=func.now()` server defaults — Rule #32's no-op framing should be tightened to 'no-op AFTER commit'; AFTER flush is legitimate." So M-5's premise was wrong: the test asserts a load-bearing call. Skipped M-5; documented the conflict in TaskUpdate.
- **Evidence:** Task #13 marked completed with description "SKIPPED: M-5 conflicts with audit-summary counter-finding". No commit; no test change.
- **Applies when:** A bundle / intake item conflicts with the OWN audit's other findings, OR with a more recent learned-rule revision. Read both sources before fixing.
- **Why it works:** Rule #19 evidence-first applied to intake instructions — the spec describes intent at filing time; the codebase + counter-findings describe truth NOW. When they disagree, prefer current truth.

### 8. End-of-batch rebuild + per-rule verification (Rule #8 + #26 amortized)
- **Description:** Edits ran via `docker cp` per-commit through Wave 1 + Wave 2. ONE `docker compose up -d --build backend worker frontend` ran AFTER all 14 commits. Verification at the end: `alembic current` confirmed migration head (d8e9c4b5f7a2), `python -c 'from app.rate_limit import ...; from app.routers... ; from app.ai.tools.cwe_checker import _generate_findings; from app.models import CraAssessment, ...'` confirmed all touched modules import cleanly in the rebuilt image.
- **Evidence:** Frontend image LastTagTime jumped from `2026-05-04T17:21` → `2026-05-05T05:55` after the rebuild. Backend healthy in 11 s. All imports resolved on first try.
- **Applies when:** Autopilot session that ships ≥3 commits touching backend code. Per-commit rebuilds compound; one end-of-session rebuild + Rule #11 import canary catches everything once.
- **Why it works:** CLAUDE.md Rule #8 requires backend+worker rebuild "before trusting for the next session". Rule #26 requires frontend rebuild after `frontend/src/**` changes. Doing both ONCE at session-end means the next session inherits a coherent image, but mid-session iteration stays fast via `docker cp`.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| D-Auto-1: System-emulation timeout — Path A stop-gap not Path B refactor | Path A is single-commit and intake explicitly listed it as a valid path; Path B (202+polling refactor) is medium-large scope and out-of-band for autopilot single-pass | Single commit `5f9d2db`, frontend tier constant added with derivation comment, intake closed |
| D-Auto-2: Rate-limit per-IP not per-API-key as intake suggested | wairz uses a single global API key; per-API-key would collapse to per-system and starve multi-client deployments | TIER_A/B/C constants in `app/rate_limit.py`, applied to 7 expensive POSTs |
| D-Auto-3: Skip M-5; document conflict | M-5 contradicted audit-summary counter-finding | No code change; Task #13 marked completed with reason |
| D-Auto-4: Mark `env.example/config.py drift` BLOCKED rather than disable hook | Modifying Citadel's secret-file hook is out-of-band for autopilot; an operator-driven session can resolve it | Intake `status: blocked`, commit `d839de1` documents resume paths |
| D-Auto-5: Structural test (AST walk) over runtime canary for Finding propagation | Runtime canary requires invoking 9 different scanners (mobsfscan Docker, grype Docker, NVD HTTP, etc.); structural test catches the discipline at author-time | `test_finding_confidence_propagation.py` 2 cases pass; surfaced 4 additional bypass paths the audit missed |
| D-Auto-6: Per-intake atomic commits per Rule #25, not bundled "feat(audit): wave 1+2" omnibus | Each intake has independent acceptance criteria and is independently revertable | 14 commits, every one with its own intake-archive move and acceptance verification; bisect-clean |
| D-Auto-7: Rename emulation router body params (`request: Request` → `body: <BodyType>`) for slowapi compat | slowapi looks for `Request` typed parameter; rename body to avoid name collision; FastAPI binds bodies by type, not name → no API contract change | rate-limit decorator applied cleanly to /start and /system; tests pass |

## Companion Anti-patterns

See `audit-intakes-wave1-wave2-2026-05-05-antipatterns.md` for the failed approaches and pipe-induced silent failures encountered during this sweep.
