# Anti-patterns: P3 session 78f772bd — firmware_service execution from pre-audited de-risk

> Extracted: 2026-04-24
> Session: 78f772bd
> Commits: 5e2cb18 (refactor), fd496f3 (intake + ROUTER + seed-resolution)

## Failed Patterns (near-misses; no actual failures this session)

This was a clean execution session — the prior session's audit absorbed the failure modes. The anti-patterns documented below are NEAR-MISSES and CONTINUED-AVOIDANCES (not first-time failures); they record what could have gone wrong if the session had skipped a step.

### 1. Panic-pivoting on the +1 ast.walk delta (15 vs seed's 14) instead of investigating

- **What was done:** Did NOT do this. Pre-measure returned 15, seed predicted 14, +1 delta. Resisted the urge to (a) treat the seed as wrong and re-derive the catalog from scratch, or (b) blindly proceed and discover the discrepancy mid-edit. Instead, ran the per-import enumeration to find the cause: L355 appears twice because `_extract_tar` is nested inside `upload`, both contain it via ast.walk traversal. Single statement, single deletion, count agrees post-edit.
- **Near-miss failure mode:** Treating the seed as wrong would have wasted ~10 minutes re-deriving the catalog (high context cost). Blindly proceeding would have either (a) succeeded but left "+1 unexplained" in the commit message — contaminating the audit trail, or (b) caused an unnecessary debug spiral when post-count showed -1 instead of 0.
- **Evidence:** Per-import enumeration showed `L 355  fn=upload   from app.workers.unpack_linux import _firmware_tar_filter` AND `L 355  fn=_extract_tar  from app.workers.unpack_linux import _firmware_tar_filter` — same lineno, two enclosing functions. Visual read of L353-356 confirmed `def _extract_tar(): ... from ... import _firmware_tar_filter`. One physical line, one logical statement, two ast.walk hits per the predecessor's nested-function classifier.
- **How to avoid:** When a pre-measure count diverges from the seed/spec by ±1-2, ALWAYS run the per-line enumeration before any edit. The investigation cost is ~5 seconds; the benefit is a correct mental model that survives the edit + post-measure cycle. This is Rule #19 (evidence-first) applied to count discrepancies — the divergence describes truth, the prediction describes intent, and you need the evidence to bridge the gap.

### 2. Treating "+15 / -14" diff-stat prediction as a hard contract

- **What was done:** Did NOT do this. Seed predicted "~15 ins / 14 del"; actual was "+15 / -44". The 30-line delta is fully accounted for by parenthesized multi-line imports being expanded into per-line deletions. Wrote the actual numbers in the commit message with an explicit reconciliation note.
- **Near-miss failure mode:** Treating the prediction as a contract would have triggered (a) an unnecessary "stop and verify" loop ("the diff is 3x larger than expected, what went wrong?"), or (b) re-doing the edits to "match" the prediction (impossible, since the deletion count is determined by line-format, not author intent). Either path consumes context for no benefit.
- **Evidence:** Commit `5e2cb18` shows 4 deletions of multi-line parenthesized blocks: `from app.workers.unpack import (\n    detect_architecture,\n    detect_kernel,\n    detect_os_info,\n    find_filesystem_root,\n)` is 6 lines deleted but 1 logical statement. Diff includes 4 such blocks (5+5+6+6=22 deleted lines from 4 statements alone, plus 9 single-line deletions = 31 vs predicted 14 = +17 line delta from multi-line block expansion).
- **How to avoid:** When a seed/spec predicts diff-stat numbers, treat them as ESTIMATES with an explicit calibration note. Predictions of insertions are usually accurate (top-level imports are 1 line each; multi-line top-level imports are author-controlled). Predictions of deletions for multi-line parenthesized blocks should be multiplied by ~5x. Better: in seeds, predict in terms of LOGICAL STATEMENTS, not LINES. The execution session's commit message can then report both (logical: "14 imports promoted"; line: "+15 / -44").

### 3. Chaining a 7th P3 carve-out on momentum despite Rule #19 + explicit user direction

- **What was done:** Did NOT do this. After firmware_service shipped clean in 1 commit, the seed listed `clamav_service.py`(2), `attack_surface_service.py`(2), `hardware_firmware/cve_matcher.py`(2) as next-densest candidates. Same-session momentum: "I just shipped 14 imports, surely 2 more is trivial." Rule #19 + the user's explicit prompt ("Resist chaining a 7th carve-out") + the seed's own STOP recommendation all pointed the other way.
- **Near-miss failure mode:** Each additional carve-out would have required a fresh per-target Rule #30 audit (~5 minutes), edits (~3 minutes), smoke (~30 seconds), commit (~30 seconds) = ~10 minutes per file. After 6 P3 sessions, the marginal LOC delta per session has dropped from ~50 (initial assessment_service) to ~14 (firmware_service, this session) to a projected ~2 (next 3 candidates combined). The same audit overhead applies regardless of payoff. The cost-benefit ratio inverts at this scale.
- **Evidence:** User prompt this session: "Next session: Execute firmware_service from seed-next-session-2026-04-25.md — single commit, ~15 ins / 14 del. Resist chaining a 7th carve-out (Rule #19: no felt pressure)." Seed's own optional-followon section: "Same Rule #30 audit procedure. But Rule #19 applies: no felt cycle pressure. Diminishing returns. Recommend STOP after firmware_service unless user directs further." Both inputs explicitly governed against momentum. Predecessor pattern #6 ("layered lazy-import audit needs 2-grep audit per target") confirms each candidate would still need full audit overhead.
- **How to avoid:** When a session opens with explicit boundary instructions (user prompt, seed STOP recommendation), HONOR them. Momentum is not pressure. The marginal LOC count is not a tiebreaker — the deciding factor is "is there concrete cycle pressure / build issue / runtime problem?" If the answer is no for 6 consecutive carve-outs, the diminishing-returns threshold is real. Rule #19 wins.

### 4. Letting context bleed between the audit phase and execution phase within one session

- **What was done:** Did NOT do this — the audit and execution were two SEPARATE sessions by design (3d9d854e and 78f772bd). The audit's cost (~20 minutes of research, scope-mapping, evidence-gathering) lived in 3d9d854e's context; the execution's cost (~5 minutes of mechanical edits + smoke) lived in 78f772bd's context. Neither session had to fit both.
- **Near-miss failure mode:** Had session 3d9d854e attempted to audit AND execute, total context cost would have been ~25 minutes of focused work + scope-decision rework. Worse: an audit done as a prelude to execution often gets compressed ("we already know it's safe") and skips the deliverable-commit step, which means the audit leaves no durable trace. If session 3d9d854e then ran out of context before execution, session 78f772bd would have to re-derive the audit from scratch.
- **Evidence:** 3d9d854e shipped 6 commits totalling ~3 hours of session activity (per session-costs.jsonl); the audit was the LAST work item. Session 78f772bd ran in ~10 minutes (pre-measure → 14 edits → smoke → 2 commits). Splitting the work cleanly let each session focus.
- **How to avoid:** When a target needs audit, treat audit-phase and execution-phase as separate sessions. Commit the audit as evidence (intake doc), write the execution plan as a seed, end the session. Next session executes from the seed. This is the bipartite pattern documented in the patterns file (#1).

## Quality Rule Candidates

No high- or medium-confidence candidates emerge this session.

- **Nested-function ast.walk double-count:** A counter-implementation issue, not a source-code anti-pattern. The fix is in the counter (use unique-line dedup), not in the codebase. No regex catches this in user code; the codebase isn't supposed to avoid nested functions. Captured as a verification-shape note in the patterns file. (Combined with the predecessor session's docstring + multi-line continuation grep error modes, this is the 4th total bidirectional-error mode catalogued for import counts. Rule #31's "3rd incident" criterion technically met, BUT all 4 error modes are workflow-discipline issues without a single regex that catches them. Promote to Rule #32 only if a 5th distinct error mode surfaces with a unifying lesson.)
- **Multi-line parenthesized import deletion line-count inflation:** A diff-stat prediction calibration issue. Solved by changing how seeds predict diff stats; no regex possible.
- **Bipartite audit + execution session shape:** A multi-session coordination pattern. No regex; documented in patterns file (#1) as a workflow lesson.
- **Rule #19 stop point at diminishing returns:** A strategic-pacing pattern. No regex; documented in patterns file (#5) as a workflow lesson.

No entries added to `.claude/harness.json` qualityRules.custom this session. The P3 carve-out series continues to produce durable workflow knowledge rather than new harness rules — predecessor's anti-patterns file reached the same conclusion.

## Quality Rule Review (existing rules touched this session)

- `auto-fleet-worktree-requires-worktree-add` — not relevant (solo session, no fleet).
- `auto-frontend-long-op-no-explicit-timeout` / `auto-frontend-multipart-no-explicit-timeout` — not relevant (no frontend edits).
- `auto-frontend-rebuild-not-restart` — not relevant (no frontend edits).
- `auto-pytest-mock-patch-androguard-at-service` — not relevant (no test patches edited).

No existing rule caught a false positive; no existing rule missed a true positive.
