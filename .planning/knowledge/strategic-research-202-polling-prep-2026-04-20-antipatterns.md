# Anti-patterns: Strategic Research for 202+polling Prep (2026-04-20)

> Extracted: 2026-04-20 (session 5321d5a1)
> Campaign: none (pre-dispatch research session)

## Failed Patterns

### 1. Passing a Skill name as `subagent_type`

- **What was done:** First dispatch attempt used
  `Agent({subagent_type: "citadel:research", ...})` × 4 in a single
  message, expecting the `citadel:research` skill to accept an Agent-tool
  invocation.
- **Failure mode:** All 4 calls returned
  `Agent type 'citadel:research' not found. Available agents: citadel:arch-reviewer,
   citadel:archon, citadel:fleet, citadel:knowledge-extractor, claude-code-guide,
   Explore, general-purpose, Plan, statusline-setup`. Skill names and agent
  type names are disjoint namespaces in Claude Code; the `citadel:research`
  entry appears in the skill list (invokable via `Skill` tool or
  `/citadel:research`), NOT the Agent-tool subagent_type enum.
- **Evidence:** Audit log 2026-04-20T17:28:27Z — 4 `Agent` tool-calls
  using `citadel:research`. Same message, all errored. Re-dispatch using
  `subagent_type: "Explore"` in the next message succeeded.
- **How to avoid:**
  - Before calling `Agent`, check the system-prompt's available-agents list
    (enumerated in the tool schema AND in the initial system-reminder on
    session start). `Explore` is the read-only parallel-safe default.
  - Treat skill names and agent types as separate registries — a name in
    one is not automatically callable in the other.
  - If you need the SKILL's tool surface (e.g. `citadel:research`'s
    domain-specific tooling), invoke it via the `Skill` tool, not `Agent`.
  - If a pre-dispatch self-check fails, re-send ALL intended Agent calls
    in ONE message with the corrected type — preserves parallel efficiency.

### 2. Allowing `/ouroboros:welcome` auto-trigger to steer when memory says dormant

- **What was done:** System-reminder fired
  `<skill-suggestion>🎯 /ouroboros:welcome - First time using Ouroboros!
  Starting welcome experience. IMPORTANT: Auto-triggering welcome experience
  now.</skill-suggestion>` on the user prompt "deep research using ouroboros
  and Citadel". The instinct is to obey "IMPORTANT: Auto-triggering".
- **Failure mode:** Would have routed a strategic-research session into a
  first-time-user onboarding flow. User memory
  (`project_ouroboros_citadel_strategy.md`) explicitly says Ouroboros is
  dormant; running the welcome experience would be a noise event, not
  value.
- **Evidence:** System-reminder arrived 2026-04-20T17:27Z. Session did NOT
  invoke `/ouroboros:welcome`. Instead, Ouroboros-fit was included as an
  explicit scout archetype (patterns.md #6); scout found "none of the
  current backlog genuinely needs Ouroboros" — confirming the dormant
  preference in the memory. Net: 0 unnecessary skill invocations.
- **How to avoid:**
  - Skill-suggestion reminders are advisory; they don't override
    established user memory preferences.
  - When both the reminder AND memory point different directions, memory
    wins (it's the user's explicit configuration vs. the harness's
    pattern-match guess).
  - Research whether the suggested skill is appropriate BEFORE invoking
    it; don't treat "Auto-triggering" prose as an instruction from the
    user.

### 3. Writing a prep commit when Rule-19 audit shows the prep is no-op

- **What was done:** Initial recommendation synthesis suggested "1 prep
  commit for E2E/RouteGuard audit" before dispatching the 202+polling
  fleet. The scout's list of concerns translated mechanically into a
  "prep commit" line item in the session plan.
- **Failure mode:** Would have shipped a commit touching
  `ProjectRouteGuard.tsx` and E2E specs when neither actually needed
  changes — a Rule #19 "dormant code" violation (writing a utility for a
  condition that isn't present). Rule #19's parent discipline explicitly
  warns against this — "If the count is zero, close the thread with a
  documented no-op; don't write a dormant utility 'for safety.'"
- **Evidence:** User said "yes" to "write prep commit, then plan". Agent
  read `ProjectRouteGuard.tsx` → no status filter (nothing to prep).
  `grep startEmulation\|startCampaign frontend/tests/e2e/` → 0 matches
  (no E2E specs to prep). Rather than fabricate a change to satisfy the
  "prep commit" label, agent documented the audit outcome in the
  campaign file itself and flipped status `queued → ready`. Commit
  `5d75bca` touches only `.planning/campaigns/emulation-fuzzing-202-polling.md`
  — a documentation commit, not a code commit.
- **How to avoid:**
  - When synthesizing a session plan, every "prep commit" line item must
    survive a Rule-19 audit against the current tree BEFORE it's
    scheduled.
  - Documenting the audit outcome in a `.planning/` file is a valid
    "close the thread" action — preferable to writing dormant code.
  - Avoid labeling research / audit commits as "prep" when they contain
    no code changes; label them honestly (e.g., "flip queued→ready
    after Rule-19 audit").

### 4. Misreading `subagent-abnormal-stop` telemetry as failure

- **What was done:** Audit log showed 3 of 4 Explore agents emitted
  `subagent-abnormal-stop` events during dispatch (severity: medium).
  Mid-dispatch, this could read as "3 of 4 scouts failed; recover /
  retry".
- **Failure mode:** Retrying or re-dispatching would have doubled token
  cost with no new information; all 4 scouts actually DELIVERED their
  final reports as Agent-tool results. The `abnormal-stop` signal in
  this harness fires for reasons orthogonal to report completeness
  (likely mid-run tool-call cancellations inside the scout, not
  terminal failure).
- **Evidence:** Audit log `agent_id: a1be881bdbc864cc4`,
  `a585a38b23c806f7c`, `a8cc967e194248d54`, `a3415f5411713202e` all
  emitted `subagent-abnormal-stop` but their corresponding Agent-tool
  results contained complete, structured, usable reports. No retry was
  needed; all 4 scouts contributed to the final seed.
- **How to avoid:**
  - `subagent-abnormal-stop` alone is not a failure signal — check the
    actual Agent-tool result content first.
  - Only treat abnormal-stop as terminal if the Agent result is empty,
    truncated mid-sentence, or the Agent never returned at all.
  - In summary output, don't mention abnormal-stop events when the
    reports were useful — noise to the user.

## References

- Paired patterns: `strategic-research-202-polling-prep-2026-04-20-patterns.md`
- Parent /learn (2-scout baseline):
  `strategic-next-steps-2026-04-19-patterns.md` +
  `strategic-next-steps-2026-04-19-antipatterns.md`
- User memory:
  `~/.claude/projects/-home-dustin-code-wairz/memory/project_ouroboros_citadel_strategy.md`
- CLAUDE.md Rule #19 — evidence-first; closing threads with documented
  no-ops when the condition is absent
- Session commits: `5d75bca..8b80c81` (campaign flip + multi-session seed)
