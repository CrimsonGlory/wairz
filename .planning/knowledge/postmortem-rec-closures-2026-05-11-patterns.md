# Patterns: Postmortem-followup Rec #2/#4/#5 closure session 2026-05-11

> Extracted: 2026-05-11
> Campaign: ad-hoc session (no campaign file; resume directive closing prior postmortem-followup recs)
> Postmortem: `.planning/postmortems/postmortem-rec-closures-2026-05-11.md`
> Parent postmortem: `.planning/postmortems/postmortem-followup-2026-05-12-structured.md`

## Successful Patterns

### 1. Inline `CLOSED YYYY-MM-DD` blocks under each Recommendation

- **Description:** When closing a postmortem-followup recommendation,
  edit the postmortem-followup document IN PLACE to add a
  `**CLOSED YYYY-MM-DD (next session):**` block (or
  `**INVESTIGATED YYYY-MM-DD ...:**` for investigation-only closures)
  immediately AFTER the original recommendation body.  Preserve the
  original framing AND append the findings, mechanism, decision, and
  evidence inline.  A future reader sees what was asked and what was
  found without having to cross-reference a separate closure document.
- **Evidence:** This session's Rec #2 + #5 closures used this shape
  (commit `6b6f4bc`); diff `+90 / −1` lines under the two
  Recommendations.  Replaces the ad-hoc "find the related closure
  doc" navigation pattern that was previously used.
- **Applies when:** Any postmortem recommendation gets closed (or
  investigated, or explicitly deferred with a trigger condition) and
  the closure shape is documentary rather than producing a separate
  artifact (e.g. a campaign file, a new postmortem).
- **Anti-shape to avoid:** Writing a separate "closure of Rec #N"
  document — adds navigation friction; reader has to find both halves
  to understand the cycle.

### 2. Same-file recommendation closures bundled in one commit (Rule #25 nuance)

- **Description:** When N recommendations close in the same edit
  session AND they edit the same file (e.g. two `CLOSED` blocks in
  the same postmortem-followup), bundle them in ONE commit — even
  though Rule #25 generally prefers per-sub-task commits.  Splitting
  same-file closures into two commits forces two interleaved edits
  to the same file with no bisect benefit; the commits would have to
  be carefully ordered to preserve a clean diff, AND the closure shape
  is genuinely one-piece (same file, same workflow, same author intent).
  Closures that touch DIFFERENT files DO get separate commits.
- **Evidence:** This session's Rec #2 + #5 bundled in `6b6f4bc`
  (both edits to `postmortem-followup-2026-05-12-structured.md`),
  while Rec #4 (edit to `next-session-plan.md`, different file)
  shipped as separate commit `fbcb72d`.  Net: 2 commits, not 3.
- **Applies when:** Closing N postmortem-followup recommendations
  in one session and ≥2 of them edit the same file.
- **Cross-reference:** Rule #25 says "per-piece" not "per-rec" — the
  "piece" is the file × workflow tuple, not the recommendation number.
  Reinforces the existing single-slice exception #2 (cross-stack
  alignment tests) under a different shape.

### 3. Deferred-with-explicit-trigger for "wait for X" follow-ups

- **Description:** When a postmortem recommendation prescribes an
  action that genuinely cannot be done now because of an external
  trigger (e.g. "wait for the first nightly cron"), don't close it
  AND don't ignore it.  Instead: (i) verify with a cheap probe that
  the trigger condition has NOT yet been met (e.g. `gh run list` to
  confirm 0 `schedule` events exist), (ii) document the trigger
  condition (specific timestamp; specific diagnostic command) inline
  in the deferral note, (iii) pass the deferred state forward to the
  next session via the resume prompt or session-handoff.  The
  deferred item should be SHORTER to re-pick-up next session than a
  blind re-read of the original recommendation would be.
- **Evidence:** This session deferred Rec #1 with explicit trigger
  "2026-05-13 06:00 UTC" + diagnostic command
  `gh run list --workflow=backend-tests.yml --limit 10 --json
  event,conclusion,createdAt,headSha | jq '.[] |
  select(.event=="schedule")'`.  The next session inherits this
  verbatim and can validate in <60 seconds.
- **Applies when:** Recommendation depends on an external trigger
  (scheduled job firing, scheduled date, third-party event, user
  authorization) that cannot be advanced by the current session.
- **Anti-shape to avoid:** "Defer to next session" without a trigger
  or diagnostic — the next session will have to re-read the original
  recommendation and re-derive the trigger condition.

### 4. Cross-repo fix proposed as diff but NOT applied (cross-repo authorization preserved)

- **Description:** When the right fix for an issue lives in a
  different repository than the current project's working directory
  (e.g. an upstream library, a sister tool, a harness/hook), produce
  the precise patch inline in the postmortem AS code, with file:line
  references and security/scope-bypass justification.  But DO NOT
  apply the patch to the upstream repo without explicit user
  authorization — cross-repo / shared-system changes are higher
  blast-radius than in-tree work.  The inline patch makes the
  closure shape complete (the investigation is genuinely done; the
  user has the answer + the fix in their hand) while preserving the
  cross-repo authorization decision for the user.
- **Evidence:** This session's Rec #5 closure (`6b6f4bc`)
  documented the precise Citadel patch for the memory-directory
  bypass with full code block and security-scope rationale, but
  explicitly stated "NOT applied — cross-repo / shared-system change
  requires explicit authorization."  Same shape applies to any
  upstream fix proposal.
- **Applies when:** Investigation surfaces a fix that lives in a
  repo other than the current working directory; the fix is
  well-scoped enough to express as a patch; and applying it has
  cross-repo blast radius.

### 5. Telemetry as audit trail of safety-system catches

- **Description:** Instead of running additional probes to verify
  "did the hook fire?", read `.planning/telemetry/hook-errors.jsonl`
  (or the equivalent telemetry file) filtered by timestamp range OR
  hook name OR detail-substring.  Telemetry rows ARE the audit log
  of safety-system activity; querying them is free, deterministic,
  and reflects what actually fired during this session.
- **Evidence:** This session's postmortem confirmed the 2
  protect-files Read blocks on Citadel hook sources by reading
  the telemetry JSONL (timestamps `2026-05-11T20:28:16` and
  `2026-05-11T20:28:22`), avoiding a re-probe of the hook.
- **Applies when:** Writing the "What Safety Systems Caught" table
  of a postmortem; debugging whether a hook fired on a specific
  action; verifying safety-system uptime.
- **Tooling:** `tail -N .planning/telemetry/hook-errors.jsonl | grep
  -E "<timestamp-prefix>"` is enough; no JSON parser needed.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Tackle the tractable trio (#2 + #4 + #5) this session; defer #1 (cron empirical) and #3 (archon decomposition) | #1 trigger date (2026-05-13) is 2 days out — measured premature.  #3 is a multi-session campaign that benefits from a fresh-context archon decomposition rather than a hot-start after 11 prior + 2 this-session commits. | 3 closures shipped; 2 deferred with explicit triggers; net 3/5 = 60% closure rate per session.  Matches the parent's "60% per session" chain rate. |
| Bundle Rec #2 + #5 in one commit; separate commit for Rec #4 | Rule #25 "per-piece" applies to file × workflow tuple, not per-rec.  Same-file closures bundle naturally; different-file closures separate. | 2 commits to main (`6b6f4bc` + `fbcb72d`).  Bisect-clean preserved. |
| Propose Citadel patch inline but NOT apply | Cross-repo / shared-system change has higher blast radius; the investigation is complete without applying.  User can decide on cross-repo action separately. | Patch documented in postmortem-followup Rec #5 closure block; ready for PR at `github.com/SethGammon/Citadel` if user authorizes. |
| NOT modify the harness rule's `message` field to document grandfathering | `protect-files.js` allows append-only changes to `qualityRules.custom` — modifying an existing rule's message is not append-shape.  Audit conclusion goes in the postmortem document instead. | Conclusion captured in postmortem-followup Rec #2 closure block; harness.json untouched (apart from session counter bump). |
| Read postmortem audit-trail directly via telemetry JSONL | Faster than re-probing; deterministic; reflects actual session activity. | "What Safety Systems Caught" table populated with real timestamps and detail strings. |
