# Patterns: substring_in_head signal kind (P3.x — 2026-05-20)

> Extracted: 2026-05-20
> Campaign: (no campaign file — direct-shipped per Rule #25 per-piece cadence)
> Postmortem: .planning/postmortems/postmortem-substring-in-head-signal-2026-05-20.md
> Commits: dcebd1c..7216d47 (3 commits — schema + SHA pin + postmortem)

## Successful Patterns

### 1. HIGH P3.x deferrals close per the prior session's contract — no scout dispatch when shape + scope are clear (Rule-of-Two)
- **Description:** The P3.2 postmortem Rec #2 described the schema extension shape (`substring_in_head` signal kind closing the windows_installer_iso + iso_9660 bridge), the bridge cleanup target (`_CATALOG_NEEDS_DISAMBIGUATION` + `_legacy_bridge_detect`), AND the commit pattern (Rule #25 Shape-1 single-slice cross-stack alignment). Direct ship per `backlog-sweep-2026-05-19-patterns.md` Pattern #1 — no Wave-1 / Wave-2 scout dispatch needed. Total session time ~3 hours vs the projected ~5-6 hours with scout dispatch.
- **Evidence:** Postmortem Pattern #1; P3.2 postmortem Rec #2; backlog-sweep-2026-05-19 Pattern #1 (Rule-of-One precedent); this session = Rule-of-Two.
- **Applies when:** A HIGH backlog item carries a clear implementation contract from a prior session's review (LOC estimate + reviewer-tag + acceptance criteria + cross-stack alignment shape). Skip scout dispatch; ship directly per Rule #25.

### 2. Sub-model + symmetric-reject + extra='forbid' + Rule #46 paired canary is the durable signal-kind extension shape (Rule-of-Two)
- **Description:** Both P3.2.b's `TextFormatConstraint` and this session's `SubstringInHeadConstraint` follow the identical 4-element pattern:
    1. `extra="forbid"` Pydantic sub-model with closed-Literal sub-fields, model_validator for cross-field invariants.
    2. `DetectionSignal.<kind>_constraint: Constraint | None` field added.
    3. `DetectionSignal._check_kind_fields` validator branch adds BOTH required-when-kind AND symmetric-reject (constraint set on wrong kind = mis-author error).
    4. Evaluator at `_eval_<kind>` in `resolver.py` consumes ONLY the constraint's declared fields; Rule #46 anti-hardcode AST META-CANARY forbids hardcoded byte literals; paired gate-canary synthesises a hostile evaluator + asserts the gate rejects it.
- **Evidence:** P3.2.b `TextFormatConstraint` (commit `b56e9af` in P3.2.b chain) + this session's `SubstringInHeadConstraint` (commit `dcebd1c`).
- **Applies when:** Adding a new signal kind to `DetectionSignalKind` Literal. Promote to `.mex/patterns/add-signal-kind.md` recipe at Rule-of-Three (next signal-kind extension).

### 3. Rule #46 §gate-canary-requirement hygiene fixups cluster around new signal-kind extensions
- **Description:** This session added 4 paired gate-canaries (SIGNAL_EVALUATORS exhaustive + _SIGNAL_COST_CLASS exhaustive + DISPATCH_EVALUATORS exhaustive + the new anti-hardcode AST canary for `_eval_substring_in_head`). It ALSO added the MISSING exhaustive canary for `_SIGNAL_COST_CLASS` — the project was missing this exhaustive entirely. Pre-existing canaries without paired gates cluster; when extending a dispatch table for a new signal kind, sweep adjacent dispatch tables for the same hygiene gaps.
- **Evidence:** 4 new tests in `test_substring_in_head_evaluator.py`: `test_meta_canary_signal_evaluators_exhaustive_gate_actually_fires`, `test_meta_canary_signal_cost_class_exhaustive` + `_gate_actually_fires`, `test_meta_canary_dispatch_evaluators_exhaustive_gate_actually_fires`, `test_meta_canary_substring_in_head_evaluator_anti_hardcode_gate_actually_fires`.
- **Applies when:** Adding a new value to a closed Literal that maps to a dispatch table. Audit the dispatch table's exhaustive META-CANARY for a paired gate-canary; audit adjacent dispatch tables for the same. Add what's missing.

### 4. Rule #25 Shape-1 single-slice exception #2 stays correct for signal-kind extensions (Rule-of-Eleven now)
- **Description:** Splitting schema + resolver + YAML + bridge cleanup + tests across 4-5 commits would leave the exhaustive META-CANARIES RED between commits (schema adds Literal value BEFORE SIGNAL_EVALUATORS gets entry → exhaustive fails). Per Rule #25 single-slice exception #2 (cross-stack alignment commits), multi-surface change ships atomically.
- **Evidence:** This session = Rule-of-Eleven (Rule #25 Rule-of-Nine in CLAUDE.md + P3.2 baseline + this session). The bundled commit `dcebd1c` touched 9 files in one slice; pytest 433/434 green THROUGHOUT the commit (no test fails between hypothetical sub-commits).
- **Applies when:** Adding a new value to a closed-grammar dispatch surface where multiple consumer tables (validator, dispatch, cost-class, tests, YAMLs) must all see the value simultaneously to remain green.

### 5. Direct-push per-piece cadence + 0 reverts continues (32+ commits across 4 sessions)
- **Description:** P3.1 (8 commits) + P3.2 (6 commits) + backlog sweep (7 commits) + this session (3 commits) = 24 commits in the lane plus other cross-session work; 0 reverts; all bisect-clean. The per-piece + per-Rule-#25 cadence is durable.
- **Evidence:** `git log --oneline 34d0689..7216d47` — 24 commits including the current session.
- **Applies when:** Any wairz session shipping schema extensions, MCP tools, or cross-stack alignment changes. The cadence works; don't deviate to bundled commits.

### 6. Test infrastructure executes on host, NOT in production container
- **Description:** `backend/.dockerignore` excludes `tests/`, `alembic/versions/`, `.ruff_cache`, `.planning`, `docs`, `*.md`, `.citadel`, `.claude` per the production-only image policy (commit `b9f438f`, 2026-04-18). Test execution + fixture regeneration ALWAYS uses host-side `cd backend && uv run` — never `docker compose exec`.
- **Evidence:** Postmortem What Broke #2 (in-container `_GENERATE.py` failed with FileNotFoundError); Pattern #6 documented.
- **Applies when:** Running pytest, regenerating fixtures, running ruff, or executing any other dev-only tool. Host-side `cd backend && uv run` is the canonical surface. `docker compose exec backend ...` for tests is opportunistic and may fail.

### 7. docker cp + restart per Rule #20 exception is the right fallback when a parallel rebuild snapshots mid-edit
- **Description:** When the Rule #8 rebuild runs in parallel with source edits, BuildKit's COPY layer may snapshot mid-edit. Some edits land in the image; others don't. Recovery: `docker cp <host>/<file> <container>:<path>` for each missing file, then `docker compose restart backend worker` to bust cached singletons (class-shape changes are Rule #20 exception territory).
- **Evidence:** Postmortem What Broke #1; recovery completed in <3 min total.
- **Applies when:** Parallel rebuild + edits causes some changes to miss the image. Verify with `docker compose exec <svc> grep -c <token> <file>` per file; docker cp the deltas; restart for class-shape changes.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Do NOT dispatch Wave-1/Wave-2 scouts | P3.2 postmortem Rec #2 already described the schema extension shape, the bridge cleanup target, AND the Rule #25 Shape-1 alignment pattern; backlog-sweep Pattern #1 codified this dispatch-skip discipline | 2 commits / 0 reverts / 0 scope expansion / ~3 hours session time (vs projected ~5-6 hours with scouts) |
| Use sub-model (`SubstringInHeadConstraint`) over inline DetectionSignal fields | Mirrors P3.2.b `TextFormatConstraint` exactly; cleaner serialisation; future extensions don't pollute DetectionSignal; `extra='forbid'` discipline scopes per-constraint instead of per-DetectionSignal | 34 tests pass; operator YAML round-trips cleanly; catalog `last_warning` is None |
| Rule #25 Shape-1 single-slice atomic commit (not split into N additive) | Schema + resolver + YAML + bridge cleanup + tests would leave the exhaustive META-CANARIES RED between commits | Bisect-clean; 1 commit (dcebd1c) covers all 9 file changes; 0 between-commit test failures |
| Drop the filename signal from windows_installer_iso.yaml entirely | Preserves legacy extensionless-bootmgr-ISO semantic (legacy bridge upgraded ANY CD001 + bootmgr to windows_installer_iso regardless of extension); filename was belt-and-suspenders before | windows_installer_iso resolves correctly for `WIN10_22H2.bin` (no .iso extension) + bootmgr substring; both `.iso` AND extensionless paths work |
| Use HOST pytest (`cd backend && uv run pytest`) as canonical test surface | `backend/.dockerignore` excludes tests/ from the production image; in-container pytest is opportunistic | 433/434 tests pass on host; no in-container test invocation needed during the session |
| `docker cp` + `restart backend worker` as Rule #20 fallback for missed-by-parallel-rebuild edits | New Pydantic class + new module-level constants are class-shape changes; cached singletons need a restart to bust | Rule #11 import smoke green after restart; backend container healthy in 4 seconds; Rule #35b live canary confirms catalog correctly resolves both ISO variants |

## Followup Recommendations Carried Forward

1. **`Refinement.stem_category_map` schema extension** — P3.2 postmortem Rec #3, deferred. Next-session HIGH priority. Single-session feasible per same Rule #25 Shape-1 pattern; closes the `qcom_mbn` bridge case.
2. **arq worker `on_startup` plugin registration** — P3.2 postmortem Rec #6, deferred. ~30 LOC + restart-survival test.
3. **`.mex/patterns/add-signal-kind.md` recipe** — at Rule-of-Three (next signal-kind extension), promote the sub-model + symmetric-reject + extra='forbid' + Rule #46 paired-canary pattern to a `.mex/patterns/` recipe.
4. **UP037 cleanup via `from __future__ import annotations`** in `app/schemas/file_format.py` — 8 pre-existing + 1 new instance. Single-line change at top of file removes all 9 instances. Low-priority lint hygiene; deferred per Rule #25 minimum-scope.
