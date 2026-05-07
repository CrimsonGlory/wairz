# Anti-patterns: 2026-05-07 multi-OS extraction pipeline campaign

> Extracted: 2026-05-07
> Source: 19 commits between `d9b6c4a` (baseline) and `f2423f3` (HEAD) on
> branch `clean-history`. 4 archon dispatches, 0 reverts, 0 regressions,
> +58 tests.

## Summary: no anti-patterns observed in this campaign

This is a deliberately documented null result. The campaign shipped cleanly
across 4 sequential archon dispatches with no reverts, no regressions, and
no mid-session scope corrections. Documenting WHY is more useful than
fabricating anti-patterns — the structural reasons below are the
reproducible elements that future similar campaigns should preserve.

## Structural reasons the campaign stayed clean

### S1. Phase 1's careful upfront design (D1-D7 in the kickoff prompt) eliminated post-hoc decision drift

The dispatch infrastructure was designed with 7 explicit decision points
(D1-D7 covering registry shape, sentinel-worker behavior, capability map
authorship, progress callback ownership, recursive composition layout,
test invariant choice, error-degradation policy) BEFORE any code was
written. Phase 2 handlers each fit the design without re-litigating the
shape — the 4-commit handler cadence held mechanically because Phase 1
made every decision the handler authors would otherwise have had to make
ad-hoc.

- **Why this prevents anti-patterns:** Decision drift between handlers is
  the dominant source of "second handler refactors first handler" churn.
  Locking the shape in Phase 1 meant Phase 2 was pure execution.
- **Reproduce next time:** When opening any pipeline / dispatcher /
  registry-style intake, demand the kickoff prompt enumerates the
  decision points the FIRST handler implicitly makes — and lock them
  before authoring handler #1.

### S2. Per-handler 4-commit shape applied uniformly, eliminating bundled-commit revert costs

All three Phase 2 handlers used the (worker / registration / capability
bump / test) commit shape. None bundled. A bundled "feat: add WIM
handler" omnibus would have been ~250 LOC across 4 files; if the
registration cut-over went wrong, revert would lose the worker module too.
Per-commit revert kept each component independently rollback-safe.

- **Why this prevents anti-patterns:** Rule #25's bundled-commit failure
  mode (all-or-nothing rollback, scrambled bisect) cannot occur if the
  shape is mechanical and per-handler-uniform.
- **Reproduce next time:** Rule #25 generalizes — any "implement N
  similar handlers" intake should ship N × 4 commits (or N × 5 with
  Dockerfile), not N omnibus commits.

### S3. Sequential (not parallel) dispatch avoided cross-stream sweep risk

The 4 archon dispatches ran sequentially because each dispatch's commits
depend on the previous dispatch's registry state — Phase 2 handler 3
literally calls Phase 2 handler 1's worker. Parallel dispatch under shared-
checkout discipline (Rule #23 anti-pattern #1) would have produced
cross-stream commit sweeps; sequential dispatch trivially avoids the
hazard.

- **Why this prevents anti-patterns:** Rule #23's worktree discipline is
  unnecessary when the work is genuinely sequential. Don't create
  parallelism where dependencies forbid it — false parallelism eats
  sweep-recovery time.
- **Reproduce next time:** When dispatch waves have semantic dependencies
  (registry edits, schema changes), default to sequential. Reserve
  parallelism + worktrees for genuinely independent subtrees.

### S4. Real-tool live canaries caught value-flow bugs that mock-only tests miss

Each handler test rounded a fixture through the real CLI tool. None of the
3 handler test files needed post-merge fixes — the round-trip caught
flag-mismatch / cwd-mismatch / sasquatch-style silent-failure bugs at the
test-authoring stage rather than after deploy. Mock-only tests would
have shipped + blown up against real firmware in a future session.

- **Why this prevents anti-patterns:** Rule #35b's mock-vs-live-canary
  lesson is precisely "mocks pass, runtime fails." Skipping the canary
  step is the structural source of "test passed, prod broke" anti-pattern
  reports in prior sessions.
- **Reproduce next time:** Every subprocess-driven worker test gets a
  real-tool round-trip canary in the same commit as the test file. No
  exceptions; the host-skip path covers dev environments lacking the
  tool.

## Watch-items for future extraction work (NOT failures this session)

Items below are observations that did NOT cause harm this session but
warrant attention if the pipeline grows further.

### W1. The capability-map alignment test relies on test discovery — silent if test file is renamed

`test_capability_notes_only_for_partial_or_none` is the lockstep gate
between the registry and the capability map. If the test file is renamed
or the test is accidentally renamed, the invariant becomes unenforced
without any failure signal — a Rule #17-shaped silent-success risk.

- **Mitigation:** When the registry passes ~10 handlers, consider
  promoting the invariant from a single test to a `pytest_collection`
  hook or a CI smoke that asserts the test exists by name.

### W2. Recursive composition has no max-depth guard

The Windows installer ISO worker invokes the WIM worker. If a future
format nests 5+ levels deep, recursive composition could spiral on a
malicious or malformed input. Currently safe because the registry only
contains 3 handlers and the composition is hard-coded.

- **Mitigation:** When the registry passes ~5 composing handlers, add a
  recursion-depth parameter to `extraction_pipeline.dispatch` (default 3,
  configurable per format) and a test asserting deeper nests degrade
  gracefully.

## Cross-Reference

- Companion patterns: `.planning/knowledge/session-2026-05-07-extraction-pipeline-patterns.md`
- Prior session anti-patterns precedent:
  `.planning/knowledge/session-2026-05-07-multi-fix-illumisite-patterns.md`
  (anti-patterns A1-A3)
- Rule #23 worktree discipline: CLAUDE.md Learned Rules
- Rule #35b mocks-vs-live-canary: CLAUDE.md Learned Rules
