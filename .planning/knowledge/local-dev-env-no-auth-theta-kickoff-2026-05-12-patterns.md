# Patterns: local-dev-env-no-auth intake closure + Phase θ kickoff

> Extracted: 2026-05-12
> Campaign: ad-hoc session (intake + brief; no in-flight campaign)
> Postmortem: `.planning/postmortems/postmortem-local-dev-env-no-auth-theta-kickoff-2026-05-12.md`

## Successful Patterns

### 1. 3-scout research-fleet for ≤10-candidate scope decisions

- **Description:** When choosing among 5-10 candidates for a multi-stream campaign scope, dispatch 3 independent scouts in parallel with NON-OVERLAPPING lenses (e.g. OSS library / Persona-E adversary / Competitive parity). Each scout writes its output to a distinct `/.planning/research-fleet/` file. The synthesizer reads ALL outputs after all 3 complete, then picks by cross-scout convergence.
- **Evidence:** Phase η used 3-scout pre-pass for 13-candidate scope → 5 chosen with strong cross-scout signal. Phase θ used the same shape for 8 candidates → BCD scored HIGH 3/3, WMI HIGH 2/3 (Scout 1 flagged vendor-in complexity that became implementation guidance, not a rejection). Outliers (ETL from Scout 2 only, EVT from Scout 1 only) cleanly dropped to deferred.
- **Applies when:** Phase-scope decision among ≥5 candidates where multiple lenses are non-overlapping. Each scout's output should target ~5-15 min wall time; 3 parallel via background `Agent` invocation. Total wall ~10-15 min, total tokens ~200-300K across all 3.
- **Wave discipline:** Scouts MUST NOT read each other's outputs before publishing — confirmed in Phase θ by Scout 2's explicit "did not read scout3" note. The discipline scales beyond η's first validation; it's the durable shape for multi-lens convergence.

### 2. Hot-start avoidance: decompose-then-defer for largest stream

- **Description:** When a session is asked to "kick off campaign X", the right end-state is a campaign brief with phase end conditions + a "Kickoff sequence (next session)" section — NOT to dispatch the first stream in-session. The first stream pairs cleanly with the next session's natural-trigger work (e.g. cron empirical re-check, pending operator action).
- **Evidence:** Phase θ campaign brief stops at "synthesize and decompose into streams" per resume prompt scope. The "Kickoff sequence (next session)" section maps: (1) cron empirical re-check post-2026-05-13T06:00Z, (2) θ.A BCD walker dispatch. Both load with a single tight scope in the next session.
- **Applies when:** Resume prompt scope ends at "decompose into streams" rather than "ship streams"; session has multiple in-flight follow-ups (cron empirical, operator action) that pair more naturally with the next session.
- **Companion:** `feedback_do_them_all_pattern.md` memory — for "do them all + deep research" directives, validated pattern is 3 parallel scouts → synthesize → ship per-piece. This pattern extends that to "synthesize → DEFER ship to next session when scope ends at decompose".

### 3. AI-blocked surface → paste-apply diff in non-blocked path

- **Description:** When a Citadel hook blocks AI from reading/editing a path (e.g. `.env*` blocked by `protect-files.js` + `external-action-gate.js`), the right response is NOT a workaround. Instead, write a SEPARATE markdown file in a non-blocked path that contains the exact paste-apply diff the operator should manually apply, including filenames, find-and-replace strings, and verification commands.
- **Evidence:** `.planning/intake/local-dev-env-no-auth-2026-05-12-OPERATOR-DIFF.md` shipped this session. Contents: File 1 (.env.example) replacement block; File 2 (.env) add-one-of-two-lines; 3-step verification. Operator can apply in <60 seconds; AI never touches a protected file.
- **Applies when:** Any Citadel-protected surface (`.env*`, `.git/`, credentials, secrets, memory files outside project root). Catch-all rule: if the hook blocks 2+ attempts on the same target, stop trying to bypass; document a paste-apply diff instead.

### 4. Per-piece direct-push (Pattern P5) with Rule #25 sub-task discipline

- **Description:** When closing an intake with N (≥3) independently-verifiable sub-tasks, each gets its own commit + immediate direct-push to main. The sub-task count drives the commit count, not arbitrary grouping. The intake's "in scope" / "out of scope" sections define the slice boundaries.
- **Evidence:** `local-dev-env-no-auth-2026-05-12` intake had 5 sub-tasks (Items 1-5); session shipped 5 corresponding commits (`5b52d6f` exit-code, `644bae7` README+install docs, `7989590` post-rebuild pattern + INDEX, `d5cbd26` operator paste-apply diff, `987a6b4` harness rule + counter) plus 3 closure commits for the cron defer + scout outputs + campaign brief. 8 total, all revertable independently, bisect-clean.
- **Applies when:** Any intake / feature with ≥3 sub-tasks. The Rule #25 single-slice exception #2 (cross-stack alignment) still applies — bundle the multi-surface change in one commit when an alignment test enforces pairwise agreement.

### 5. Convergence-first stream ordering — start with lowest-risk pick

- **Description:** When multiple convergent picks emerge from a research-fleet pre-pass, the FIRST stream to ship is NOT the highest-adversary-value pick — it's the lowest-implementation-risk pick (zero new dep, smallest complexity, closest precedent). This is Pattern P5 best-practice: start with the most reproducible build to validate the campaign brief's end conditions before committing to harder streams.
- **Evidence:** Phase θ campaign brief ordered streams: θ.A BCD (HIGH adversary value + ZERO new dep + 3/3 scout convergence) BEFORE θ.B WMI (HIGHEST adversary value but vendor-in complexity). The decision is recorded in the brief's Decision Log entry #3.
- **Applies when:** Campaign brief has 3+ streams with strong cross-scout convergence. First stream ordering becomes a risk-management decision separate from the value ranking.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 3-scout research-fleet pre-pass (OSS / Persona-E / Competitive) | Same shape as η; convergent ranking across 3 lenses gives higher-confidence pick than single-lens | All 3 returned in ~4 min wall; convergence on BCD (3/3) and WMI (2/3 #1) clean |
| θ ships 3 core (θ.A BCD + θ.B WMI + θ.C ESP); 2 optional (θ.D SDB + θ.E MBR/VBR); 5 deferred to ι | Pattern P5 per-piece direct-push works best on convergent picks; Volatility/hiberfil architectural-prereq pair dominates the rest of the deferred list | 3-core / 2-optional / 5-deferred shape matches scout convergence cleanly |
| θ.A BCD FIRST (not WMI) despite WMI's #1 adversary lens | BCD has zero new dep (regipy already in tree) + smallest complexity; lowest-risk first stream per Pattern P5 | θ.A becomes kickoff stream for next session |
| WMI walker via 200-LOC PyWMIPersistenceFinder vendor-in (NOT full python-cim) | python-cim archived 2024; format is bounded to keyword-search persistence detection; 200-LOC vendor under Rule #36 no-execute is right-sized | θ.B uses custom-sized vendor shape, not a heavy archived dep |
| Defer Volatility 3 + hibernate.sys as paired Phase ι campaign | Both share the same architectural prerequisite (memory-dump upload as new top-level data type — ~5-10 streams); pairing in ι gives focused campaign vs half-shipped in θ | Vol3 + hiberfil flagged for ι kickoff |
| Defer θ.A dispatch to next session (hot-start avoidance) | Resume prompt scope ends at "decompose into streams"; cron empirical (Item #1) pairs naturally with the next session's θ.A kickoff; both load with single tight scope | Session ends clean; brief encodes the kickoff sequence |
| `.env.example` paste-apply diff in `.planning/intake/` rather than AI-edited | Citadel `protect-files.js` + `external-action-gate.js` block `.env*` (intentional); paste-apply diff lets operator close the gap without bypass | Operator action item opened; AI ships docs + code path |
| Per-piece direct-push to main (Pattern P5), Trust=trusted | Same as η; Rule #41 must-complete CI mitigations healthy (per-commit lint + nightly backend-tests cron pending empirical 2026-05-13T06:00Z) | 8 commits direct-pushed; no worktree-merge step |
