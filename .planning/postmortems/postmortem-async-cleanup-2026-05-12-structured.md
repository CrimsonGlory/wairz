# Postmortem: ASYNC family lint cleanup (structured)

> Date: 2026-05-12
> Campaign: `.planning/campaigns/completed/async-cleanup-2026-05-11.md`
> Duration: 2026-05-11 (open) → 2026-05-12 (close); ~36 hours across 2 sessions / 3 archon turns / 1 inline closure
> Outcome: completed
> Companion: `.planning/postmortems/postmortem-async-cleanup-2026-05-12.md` (narrative synthesis; this file is the structured-data complement produced by `/citadel:postmortem`)

## Summary

Three-phase lint tech-debt campaign closed all four ASYNC family ruff codes (240/230/109/221) at source rather than continued suppression. 319 source-level hits closed + 1 latent F823 bug discovered + fixed. Final state: `[tool.ruff.lint] ignore` shrank 30 → 24 entries (exceeded the 30 → 26 target by 2 incidental commented-placeholder cleanups from the parent campaign). 4 new CLAUDE.md rules promoted (#40-43) with Rule-of-N evidence.

## What Broke

### 1. F823 latent bug masked by concurrency-cancel CI

- **What happened:** `app/ai/tools/emulation.py:2627` `_handle_emulate_with_qiling()` had `import asyncio` placed AFTER its first reference to `asyncio.create_subprocess_exec` inside the function body. Python's local-binding rule promoted `asyncio` to a function-scope local for the whole function, so the early use site raised `UnboundLocalError` at runtime — caught by ruff F823 ("local variable used before assignment"). The bug had probably existed in main for weeks.
- **Caught by:** CI Lint workflow on commit `cae7547` (Phase E.8) — the FIRST commit whose Lint run completed past that codepath. Every prior intermediate Lint run had been concurrency-cancelled within 1-3 seconds by the next push (Pattern P5 cadence).
- **Cost:** 1 rework commit `6376d8d` (Phase D.39). ~5 minutes of rework. Lint also failed on `bca4485` (Phase E.8 precursor) due to the same bug — 2 visible failure events surfaced from one latent defect.
- **Fix:** Move `import asyncio` to first statement of the function body. Single-line positional change.
- **Infrastructure created:** Rule #40 promoted ("Function-local imports MUST sit at top of function body") + Rule #41 promoted ("Concurrency-cancel CI delays defect detection; schedule consolidation pauses"). The pair documents both the specific failure (Rule #40) and the masking mechanism (Rule #41).

### 2. Exit-code captured after pipe — Rule #35a slip

- **What happened:** Author's diagnostic command `( uv run ruff check ... | tail -10 ); echo "exit=$?"` reported `tail`'s exit (0), not ruff's actual exit (1, because findings existed). The subshell wrapping the pipe inverted the captured exit code.
- **Caught by:** Author self-inspection on the SECOND ruff run that re-checked the same state with direct exit capture (`cmd; ec=$?` before any pipe).
- **Cost:** Negligible — caught immediately; no commit shipped under the wrong assumption.
- **Fix:** Re-run with `cmd; ec=$?; echo "real exit=$ec"` shape. Then audit the rest of the session's exit-code captures.
- **Infrastructure created:** None new — Rule #35a already covers this exact failure mode. The self-catch validated the rule's already-promoted state.

### 3. Campaign ledger math drift (30 → 24 actual vs 30 → 26 stated)

- **What happened:** Campaign file's stated target was `[tool.ruff.lint] ignore` shrinks 30 → 26 (4 ASYNC removals). Final state is 24 (6 entries removed). The 2-entry discrepancy came from parent-campaign closures (S314, E741, F811, F402, F601) that had remained as commented placeholders in the ignore block; some of those comments were incidentally cleaned up during ASYNC-removal edits.
- **Caught by:** Phase H structured-postmortem author count during numbers-table fill-in.
- **Cost:** None — campaign's stated ASYNC objective was 100% met; the additional cleanup is net positive.
- **Fix:** Documented in the narrative postmortem's "Final state" table and "What Could Have Been Better" section.
- **Infrastructure created:** Recommendation noted (see Recommendations #3 below) — campaign open should record literal-string entry count + named list to catch drift in future.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---:|---|
| CI Lint (ruff F823) | Latent `import asyncio` after first-use site in `emulation.py:2627` (Rule #40 incident) | 1 surfaced (~30+ runs masked it before that) | A production `UnboundLocalError` crash on a user-invoked Qiling emulation path |
| Local ruff `--no-cache` discipline (Antipattern A6) | Stale cache hits that would have misreported zero hits | 0 false positives this campaign | Ruff cache directory ownership issues silently invalidating verification |
| Rule #35a (exit-code-before-pipe) | Self-catch of `tail`-induced exit obfuscation in author's diagnostic command | 1 self-catch | Mis-reporting "ruff exit 0" when ruff had findings |
| Antipattern A2 (fix-before-remove) | Each Phase G commit verified zero hits BEFORE removing the suppression | 3 Phase G commits + 1 from session 1 | A suppression-removal commit landing while latent hits still existed; would have failed Lint instantly and blocked the campaign |
| Rule #25 small-commit principle | 61 commits, every one independently revertable | 0 forced rollbacks | A bundled mega-commit would have blocked all 61 changes on any single regression |
| Rule #21 mirror discipline | Rules #40-43 mirrored into `.mex/context/conventions.md` Verify Checklist in the same commit as the CLAUDE.md additions | 4 mirror entries | Future agents following only `.mex/ROUTER.md` would have missed the newest rules |
| Sub-agent context preservation | Two archon hand-offs (session 1 → session 2 turn 1 → turn 2) survived without rule-context drift | 2 transitions | Re-discovery cost across session boundaries; lost decisions |
| Rule #31 width-canary | Phase G.4 ran `ruff check --select ASYNC` (no narrowing) as the widest possible canary before declaring campaign done | 1 canary | A narrow-grep illusion of completeness; campaign-close on incomplete coverage |

## Scope Analysis

- **Planned:** "Close ASYNC240/230/109/221 suppressions in `backend/pyproject.toml` by fixing source-level violations. Final state: 4 codes hit zero, `[tool.ruff.lint] ignore` shrinks 30 → 26, CI green at every commit."
- **Built:**
  - 4 codes hit zero ✅ (ASYNC240: 226 → 0, ASYNC230: 50 → 0, ASYNC109: 36 → 0, ASYNC221: 7 → 0)
  - F823 also closed (1 latent → 0) — bonus discovery
  - `[tool.ruff.lint] ignore` shrunk 30 → 24 (exceeded target by 2 entries — commented placeholders incidentally cleaned)
  - CI Lint green at every shipped commit except `bca4485` + `cae7547` (the 2 F823 surface events, both immediately fixed in next commits)
  - 4 new CLAUDE.md rules promoted (#40-43) with Rule-of-N evidence — out-of-scope value-add
- **Drift:** minor — final state exceeded stated target by +2 ignore-entry removals and +1 latent bug fix. No scope reduction. No phase skipped. Phase F (ASYNC109 standalone) was folded implicitly into D/E commits since the hit shapes overlapped.

## Patterns

1. **Per-FILE commits beat per-CODE commits for multi-axis cleanups.** Decision D1 was the inflection point — top hot files had hits across multiple codes, so per-code phasing would have touched each 2-3x. 61 commits shipped cleanly with zero cross-code bisect surprises.
2. **Helper extraction during a per-file sweep produces durable code, not just lint-quiet decoration.** The D.34 helper (`reset_extraction_dir_sync`) propagated to 7 reuses (D.35 batched 6 + D.37 +1). Rule-of-Two with the precedent helper extraction from `feature-extraction-integrity` Phase 2 — codified as Rule #42.
3. **Continuation prompts survive cross-session and cross-agent.** Session 1 → session 2 (user invokes `/do continue`) → archon turn 1 → archon turn 2 → inline closure: each transition bootstrapped to productive work in ≤5 tool calls because the campaign file's Pattern P7 continuation block captured all the state.
4. **Pattern P5 per-piece direct-push + concurrency-cancel CI is double-edged.** Saves ~30 Backend Tests runner-minutes per multi-commit session BUT delays defect detection at boundary commits. Codified as Rule #41 with explicit mitigation contract (consolidation pauses + broader local gate).
5. **Decision D4 generalizes from tests to app/.** Per-line noqa with rationale is the right closure for inherently-blocking-but-bounded sync I/O, not just test boilerplate. 4 rationale categories formalized as Rule #43.
6. **Latent bugs accumulate at concurrency-cancel boundaries.** F823 surfaced ONLY because cae7547's Lint run wasn't immediately cancelled. The bug had probably existed for weeks. This generalizes — there are likely other "near-misses" sitting in main today that will surface on the next consolidation pause.

## Recommendations

1. **Implement Rule #41 consolidation pause discipline going forward.** For any multi-commit session > 5 commits, schedule a pause before commit 10 where the next commit waits for CI green on the previous. Cost: 5-10 min idle per pause. Benefit: defects surface within 10 commits rather than accumulating through 60.
2. **Run `ruff check --no-cache .` (FULL ruleset) once per session before any session-end commit.** Catches latent debt that the active campaign isn't actively closing. Would have caught F823 weeks earlier if applied to any prior session.
3. **Campaign-open template should record the literal `ignore` list entry count + named list.** A 30-second `awk` script at open + close catches the kind of math drift this campaign saw (stated 30→26, actual 30→24).
4. **Quarterly audit: walk every `# noqa: ASYNC<code>` in the codebase and verify its rationale fits Rule #43's 4 categories.** Any noqa whose rationale doesn't match a category is a candidate for re-fix (executor wrap or refactor). Cost: ~30 min quarterly. Benefit: prevents rationale-prose drift into tech-debt theatre.
5. **Add a `pre-push` git hook (or CI step) running `ruff check --no-cache --select F823 .` exit-zero gate.** F823 is mechanical, cheap to check, and was the most-recently-promoted Rule #40. Adding the gate prevents the same shape from re-accreting.

## Numbers

| Metric | Value |
|---|---:|
| Phases planned | 8 (A/B/C/D/E/F/G/H) |
| Phases completed | 8 (F implicit, folded into D/E) |
| Total commits | 61 (60 baseline → G.4 + 1 H closure; plus 1 post-closure rule-promotion `a0bb676` = 62 total ahead of `3fc48b3`) |
| Files changed | ~80 unique source files + 3 new docs + 1 campaign-file move + 2 CLAUDE.md/conventions.md updates |
| Sessions | 2 |
| Archon turns | 3 (session 1 single + session 2 turn 1 + session 2 turn 2) + 1 inline closure |
| ASYNC hits closed | 319 |
| F823 hits closed | 1 |
| New CLAUDE.md rules promoted | 4 (#40, #41, #42, #43) |
| Ignore-list reduction | 30 → 24 entries (−6 actual vs −4 planned) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 (gates fired correctly; the cae7547 Lint failure was the gate doing its job, not a block on intended work) |
| Anti-pattern warnings | 0 (none surfaced during this campaign) |
| Rework cycles | 1 (F823 fix in D.39 reactive to cae7547 Lint failure) |
| Cancelled CI runs (concurrency-cancel) | ~30+ Backend Tests + ~25+ Lint runs across 61 commits |
| Sub-agent delegations | 3 (knowledge-extractor + 2 archon turns) |
| Cross-session work-recovery cost | ~5 tool calls per session bootstrap (campaign file read + git log + gh run + working tree + first ruff) |

---HANDOFF---
- Postmortem: async-cleanup-2026-05-11 (structured complement)
- Document: .planning/postmortems/postmortem-async-cleanup-2026-05-12-structured.md
- Failures documented: 3 (F823 latent, exit-code pipe slip, ledger math drift)
- Safety catches: 8 systems documented
- Recommendations: 5 (consolidation pause discipline, full local ruff gate, ledger-math drift fix, quarterly noqa audit, F823 pre-push gate)
- Companion narrative postmortem: .planning/postmortems/postmortem-async-cleanup-2026-05-12.md
---
