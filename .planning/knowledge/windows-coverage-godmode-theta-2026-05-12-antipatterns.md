# Anti-patterns: Windows-Coverage God-Mode Phase θ (boot-chain + lateral + shim)

> Extracted: 2026-05-12
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-theta-2026-05-12.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-theta-2026-05-12.md`
> Per-stream files (10): `.planning/knowledge/windows-coverage-godmode-theta-{A,B,C,D,E}-*-{patterns,antipatterns}.md`

## Failed Patterns (cross-stream, campaign-level)

### 1. Trusting kickoff-brief claims about CI state without verification (Rule-of-Three with η + α precedents)

- **What was done:** Session-open brief stated `Lint CI: SUCCESS on 8236ff9 (verify before starting)`. Brief was written while the run was still `in_progress`; actual conclusion was `failure` (11 ruff errors: 4× I001 + 7× ASYNC230 latent from η.A NTFS-MFT walker).
- **Failure mode:** A brief authored DURING an in-flight CI run will document the run's state at brief-write time, not at session-open time. Trusting the brief's "SUCCESS" claim without `gh run view <id> --json conclusion` would have shipped lint debt forward into θ.A's first commit, polluting Pattern P5 per-piece direct-push.
- **Evidence:** Run `25706790088` (the brief's referenced run) had `conclusion: "failure"`. Earlier ~30 commits' Lint runs were all `cancelled` per Rule #41 concurrency-cancel.
- **How to avoid:** ALWAYS verify CI state at session-open via `gh run view <id> --json conclusion,status` even when the brief asserts it. The brief's "verify before starting" parenthetical IS the discipline — follow it, don't skip it. Treat brief claims about external state (CI, cron timing, system date) as claims-pending-verification; treat brief claims about file state (commit SHA, alembic head, MCP count) as more trustworthy (those are quasi-immutable).

### 2. Trusting sub-agent self-reported wall time vs `duration_ms` (Rule-of-Five within this campaign)

- **What was done:** Each θ sub-agent reported a "wall time" in its summary: θ.A "2.5h", θ.B "1.5h", θ.C "1h", θ.E "40 min", θ.D "35 min". The actual `duration_ms` from the task-notification was substantially lower in every case: θ.A 38m, θ.B 34m, θ.C 26m, θ.E 25m, θ.D 30m. The ratio drifted from ~4× (θ.A) toward ~1.2× (θ.D) as Pattern P1 speedup compounded.
- **Failure mode:** Sub-agents appear to report a conflated metric (perhaps "if I'd done this without precedent reuse" or "elapsed clock time including idle"), not actual agent-process wall time. Capacity planning based on self-reported wall times would over-budget; capacity planning based on `duration_ms` is accurate.
- **Evidence:** 5 sub-agent returns, 5 instances of inflated self-reported wall time vs `duration_ms` precision. Caught by orchestrator-side cross-check (Pattern P7).
- **How to avoid:** Trust `duration_ms` from the task-notification (millisecond-precise from the harness). Treat sub-agent self-reported "wall time" strings as SOFT signals only — useful for narrative, NOT for capacity planning. Document this in the dispatch prompt for future sub-agents OR ignore the field at orchestrator level.

### 3. System-date drift between Claude sessions causing temporal-relative claims to be stale (Rule-of-One — promotion candidate at Rule-of-Two)

- **What was done:** Brief Item #1 said "2026-05-13 06:00 UTC has now passed" — implying cron empirical re-check was due THIS session. Actual UTC at session-open was 2026-05-12T01:17Z (~29h pre-trigger). The session-context system-date said `Today's date is 2026-05-11` while actual UTC was 2026-05-12 early — a 1-day discrepancy that the brief inherited.
- **Failure mode:** Briefs authored in one session may carry temporal claims ("today is X", "Y has passed", "next session you can run Z") that drift relative to the next session's actual clock. Trusting the brief's temporal framing without `date -u "+%Y-%m-%dT%H:%M:%SZ"` would cause the cron check to be run prematurely (returning 0 schedule runs) and a doc update churned for no reason.
- **Evidence:** `date -u "+%Y-%m-%dT%H:%M:%SZ"` returned `2026-05-12T01:17:00Z`; cron is `0 6 13 5 *` UTC; trigger window 28h43m future. Re-deferred Item #1 cleanly without doc churn.
- **How to avoid:** At session-open, ALWAYS run `date -u "+%Y-%m-%dT%H:%M:%SZ"` and compare against any temporal claim in the brief. Treat the system-context `Today's date is X` as a soft signal that may drift; treat `date -u` as authoritative for cron / scheduled trigger checks.

### 4. Lint debt accumulating latent across concurrency-cancelled CI runs (Rule #41 manifestation — Rule-of-Two with async-cleanup-2026-05-11 precedent)

- **What was done:** η.A NTFS-MFT walker shipped 5 commits (`ad5f0fa..9baefd9`) with 11 ruff errors (I001 + ASYNC230) that ALL prior Lint runs cancelled before reaching ruff's reporting step. Lint stayed apparently-green for ~30 commits until run `25706790088` on `8236ff9` finally completed uncancelled.
- **Failure mode:** Pattern P5 per-piece direct-push + GitHub Actions `concurrency.cancel-in-progress: true` produces a structural latent-defect-detection gap at boundary commits. The next idle window between pushes is the only time CI completes; a sustained ~30-commit push cadence can mask debt for >1 hour. Rule #41 documents this threat and mechanism (a) per-commit must-complete sibling mitigates it.
- **Evidence:** Run `25706790088` failure conclusion; previous ~30 runs ALL cancelled status per `gh run list --workflow=lint.yml`. CLAUDE.md async-cleanup-2026-05-11 Phase E.8 F823 incident was Rule-of-One; this θ session's I001+ASYNC230 incident is Rule-of-Two.
- **How to avoid:** Rule #41 mechanism (a) `lint-backend-must-complete` job (already shipped in `.github/workflows/lint.yml`) catches THIS class. For empirical validation: `gh run view <SHA-of-final-commit-in-a-cadence> --json conclusion` against the must-complete sibling specifically — it's the authoritative signal vs the cancellable sibling. Session-open verification of CI on HEAD (antipattern #1 above) is the second-line backstop.

### 5. Sub-agent campaign-progression Rule-of-N count vs CLAUDE.md canonical text count (Rule-of-One, low-severity)

- **What was done:** θ.B sub-agent reported Rule #39 walker triplet at "Rule-of-Ten" with the chain `γ.4 → ... → θ.B.D` enumerated. CLAUDE.md's existing Rule #39 text only enumerates Rule-of-Five (the 5 worked examples promoted at extraction time). The mismatch is "campaign-progression" (running tally per stream-author) vs "canonical text" (the worked examples cited in the rule).
- **Failure mode:** Reader of either the per-stream postmortem OR CLAUDE.md alone gets a different count of N. Not a defect — the rule shape is what's durable; the count is a footnote — but inconsistent narrative across documents creates reader friction.
- **Evidence:** θ.B sub-agent claim Rule-of-Ten; CLAUDE.md Rule #39 last-updated worked-example count is 5. Same shape for Rule #25 single-slice exception #2 (campaign-progression: Rule-of-Eighteen; CLAUDE.md: Rule-of-Eight).
- **How to avoid:** Either (a) periodically refresh CLAUDE.md Rule-of-N counts to match campaign-progression (manual doc PR every 3-5 campaigns), OR (b) accept the distinction and document it explicitly in CLAUDE.md ("Rule-of-N counts in the text reflect promotion-time evidence; per-campaign postmortems carry the running campaign-progression tally"). Option (b) is cheaper and more honest about the data model. Defer the cleanup either way — zero shipping-impact.

### 6. Naive use of brief's wall-time estimates for capacity planning (Rule-of-Five within this campaign)

- **What was done:** Campaign brief estimated θ.A 4-6h, θ.B 6-8h, θ.C 2-4h, θ.E 2-3h, θ.D 5-7h = 19-28h naive sum for the 5 streams. Initial framing was "3 core + 2 optional with capacity-dependent deferral to ι".
- **Failure mode:** The brief's estimates were authored BEFORE the Pattern P1 speedup pattern was known (the speedup compounds when a stream-shape precedent exists). Trusting the estimate's aggregate naively would have caused premature deferral of θ.D + θ.E to ι.
- **Evidence:** Actual cumulative agent-wall ~153 min (~2.5h); cumulative session-wall ~4h. Brief estimate was 8-12× over actual.
- **How to avoid:** When a stream-shape precedent exists in the same campaign lineage (or prior campaign with same shape — e.g. η.A precedes θ.A's walker stream), discount brief estimates by 50-75% for STREAMS 2+ in the same session. Trust brief estimates as upper bounds for STREAM 1 (precedent-establishing); use Pattern P1 speedup math for streams 2+. Re-evaluate capacity after each stream return based on actual `duration_ms`, not on naive sum.

## Quality Rule Candidates

(No new harness regex rules from this campaign. Candidates considered and skipped:)

1. **Skipped (LOW confidence — false-positive risk):** Regex for `# noqa:[^—]*$` (noqa without em-dash rationale) — applies to `backend/{app,tests}/**/*.py`. SKIP because multi-line comments with rationale on the next line would false-positive; Rule #43 discipline is documented + code-reviewable, regex enforcement would be net-negative.

2. **Skipped (already covered):** All Pattern P1-P7 are process patterns, not code-regex patterns. They live in the patterns file above + CLAUDE.md narrative; harness regex enforcement is wrong shape for them.

3. **Skipped (already covered):** Cross-stack alignment enforcement is already a test gate (`tests/test_finding_source_alignment.py`); ruff ASYNC230 is enforced by ruff itself; Rule #41 mechanism (a) per-commit lint must-complete is already in `.github/workflows/lint.yml`. No regex layer needed.

Net new harness rules added: **0** (all candidates skipped per skill's "Skip vague or low-confidence patterns entirely — a bad rule that fires on innocent code is worse than no rule").
