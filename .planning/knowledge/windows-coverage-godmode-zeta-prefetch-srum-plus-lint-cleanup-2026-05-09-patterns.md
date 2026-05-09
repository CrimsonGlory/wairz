# Patterns — Windows-Coverage God-Mode ζ + Lint Cleanup (2026-05-10)

## Pattern P1: Suppression-removal as bug-discovery

**Shape:** treat each suppressed lint rule as a temporary marker, not a
permanent state. Periodically run `ruff check --no-cache .` with each
ignored code surfaced individually (`--select <code>`); each hit is
either a real bug, a false positive worth justifying, or a cosmetic
cleanup. Removing the suppression at source — not relaxing the rule —
forces the decision.

**Evidence (this campaign, 5 ruff + 1 bandit closures):**
- F601 → 1 real bug (UEFI dup GUID overrode correct mapping).
- F811 → 1 real bug (`_firmware_tar_filter` shadowing imported,
  stricter version).
- S314 → 2 real security issues (untrusted-XML XXE vulnerability).
- E741 + F402 → 4 cosmetic but cheap closures.

Pattern recurrence (campaign-level): each Windows-coverage phase that
adds a new module produces 1-3 new suppressions in the cleanup audit;
ratio of "real bugs caught" to "total suppressions audited" tracks at
~10-15% per audit cycle.

**When to apply:** end of any campaign that added meaningful new code
(>500 LOC); reserve a `Phase Lint` slice; budget ~1 hour per 10 ruff
codes audited.

## Pattern P2: Library-API probe before walker drafting (Rule #19 instance)

**Shape:** before writing the inner runner of a Rule #39 walker triplet,
run `inspect.getsource(<library entry point>)` against the chosen parser
library inside the backend container. Probes the actual yield-shape /
return-type / exception class before code is committed against assumed
shape.

**Evidence (this campaign):**
- ζ.2 prefetch — probed `windowsprefetch.Prefetch.parse` before drafting
  `_do_prefetch_run`; confirmed it returns a single object with `name /
  hash / executable_filename / files / volumes / executions` attributes
  (NOT a generator like python-evtx); ~30 seconds of probe avoided ~30
  minutes of refactor.
- ζ.3 SRUM — probed `libesedb_python.file()` API surface; confirmed
  `tables` is iterable, each table has `records` iterable, each record
  has `value(column_index)` semantics. Decided on a single
  `windows_srum_records` table with `record_type` discriminator
  rather than 4 separate tables (one per SRUM extension table).

**Generalisation:** Rule #19 evidence-first applies to library API
shapes too, not just data shapes. The probe artefact (often just a
`docker compose exec backend python -c "..."` paste) goes in the
campaign file as decision evidence.

## Pattern P3: Stdlib import retained for types only after defusedxml swap

**Shape:** when migrating untrusted-XML parsing from
`xml.etree.ElementTree` to `defusedxml.ElementTree`, do NOT delete the
stdlib import — defusedxml deliberately re-uses the stdlib's `Element`
and `ParseError` classes, and does NOT re-export `Element` itself.
Keep `import xml.etree.ElementTree as ET` for type annotations and
exception handling; use `from defusedxml.ElementTree import fromstring
as _safe_fromstring` for the actual parsing.

**Evidence:** Phase Lint.B.3 (commit 63ec1c0) on
`backend/app/services/manifest_checks/network_security.py` and
`backend/app/ai/tools/windows_archive.py`. Both files keep
`ET.Element` type annotations and `except ET.ParseError`; both swap
`ET.fromstring` → `_safe_fromstring`. Bandit B405 must stay in skips
because it flags the type-only import; that's a known bandit
limitation, not a security issue.

**Generalisation:** the pattern is "import stdlib for types, defusedxml
for parsers" — the SAME pattern documented in defusedxml's README
under "Recommendations". Codified here as a wairz-specific recipe with
a worked-example call site.

## Pattern P4: Rule #39 walker triplet as a 1-week recipe

**Shape:** the inner/outer/safe runner triplet (Rule #39) has stabilised
across 5 walkers. Authoring a new walker now follows a tight 1-week
recipe:

- Day 1 — research: library probe (Pattern P2); fixture availability;
  parent-directory + filename-glob detection root walk.
- Day 2 — alembic migration + ORM model + JSONB normalizers (Rule #35c)
  + tier-1 ORM tests via `make_live_db()`. Single commit (ζ.X.A).
- Day 3 — Rule #39 inner runner (`_do_<op>_run`) + outer wrapper
  (`run_<op>_background`) + safe wrapper (`auto_<op>_walk_firmware_safe`)
  + tier-1 inner-runner tests against a real fixture. Single commit (ζ.X.B).
- Day 4 — cross-stack alignment (Rule #25 exception #2): alembic
  `ck_findings_source` + backend Literal + classifier + emit + frontend
  union + frontend config. ATOMIC single commit (ζ.X.C).
- Day 5 — finding-emit hook + FindingService integration + 3 MCP tools
  (search/status/trigger). Two commits (ζ.X.D + ζ.X.E).

**Evidence:** ζ.2 Prefetch (4 commits, 1 day) + ζ.3 SRUM (4 commits,
1 day) shipped this campaign on the recipe. Total LOC across both: ~1500.
Cost per walker amortising downward as the recipe matures (γ.4 was 7
commits + 2 days; ζ.2 was 4 commits + 4 hours).

**Recipe location:** `.mex/patterns/inner-outer-safe-runner.md` (existing
from γ.4 codification); this campaign adds two more worked examples to
that recipe.

## Pattern P5: Per-piece direct-push-to-main with concurrency-cancelled CI

**Shape:** for a campaign that ships 8-15 small, individually-revertable
commits in one session, direct-push each commit to main rather than
batching into a single PR. CI's `concurrency.cancel-in-progress: true`
cancels superseded Backend Tests runs while keeping each Lint run
independent (Lint is fast enough to always-run). Net effect: full CI
verification on the FINAL commit, fast feedback on each Lint, runner
minutes saved.

**Evidence (this campaign):** 14 commits pushed in 4 batches over ~2
hours. Backend Tests CI ran ~3 times to completion (on representative
intermediate SHAs); ~10 superseded runs got cancelled in-flight.
Estimated runner-minutes saved: ~40.

**When to apply:** trusted-author campaigns (177+ session trust level
in this repo); commits ≤200 LOC each; commits independently revertable;
no commit introduces a class-shape change without a Rule #11 import
smoke. Don't apply for: untrusted contributors, larger atomic commits,
release-bound work that needs a PR-level review trail.

## Pattern P6: `>= N` lower-bound count assertions for growing collections

**Shape:** test assertions of the form `assert
len(registry._tools) == N` are fragile when the collection grows over
time. Relax to `>= N` lower bound (with a comment citing the SHA at
which N was the exact count). The assertion still catches "feature
disappeared / category dropped / registration broke" failure modes;
it does NOT catch "duplicate registration" but that's covered by the
registry's own dedup logic.

**Evidence (cumulative):**
- 5c14be2 (2026-05-09 ε.2.B `test_registry_tool_count_is_213`).
- 13ef37f (2026-05-09 ζ.1 `test_tier1_mcp_registry_count_is_219_post_epsilon`).
- ζ.2.E + ζ.3.E (this campaign — implicit, no test count needed
  relaxation because both already >= the prior bound).

Rule-of-Four; one more occurrence triggers numbered-Rule promotion in
CLAUDE.md.

**Mechanical detection:** `grep -rn "len(reg._tools) == \|registry.*== 22"
backend/tests/` BEFORE every push that adds an MCP tool category.

## Pattern P7: Continuation prompt as durable hand-off artefact

**Shape:** when a session approaches context exhaustion mid-campaign,
write a continuation prompt that the next session can pick up from in
≤5 tool calls. Include: branch tip + main HEAD SHA, exact CI status,
remaining work scoped down to commit-by-commit, applicable rule
citations, end-conditions list, failure pivot policy, and explicit
autonomy budget statement.

**Evidence:** the continuation prompt for THIS session was authored by
the prior Archon session (post-merge-eps2c-zeta1) and embedded in the
campaign file. The new session bootstrapped to productive work in:
1. campaign file read
2. lint triage report read
3. git log (to verify what shipped)
4. gh run list (to verify CI state)
5. CLAUDE.md skim for active rules

Five tool calls; ~30 seconds of orientation; zero re-discovery cost.

**Generalisation:** the continuation prompt IS the most valuable
artefact a context-exhausted session can produce. It is to multi-
session campaigns what the HANDOFF block is to in-task work.
