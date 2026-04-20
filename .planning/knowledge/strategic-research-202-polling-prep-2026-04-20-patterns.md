# Patterns: Strategic Research for 202+polling Prep (2026-04-20)

> Extracted: 2026-04-20 (session 5321d5a1)
> Campaign: none (pre-dispatch research + Rule-19 audit for queued `.planning/campaigns/emulation-fuzzing-202-polling.md`)
> Postmortem: none — session commits only (`5d75bca`, `8b80c81`)
> Related /learn outputs:
>   - `strategic-next-steps-2026-04-19-patterns.md` (2-scout baseline)
>   - `wairz-rule29-timeout-alignment-research-2026-04-22-patterns.md`
>   - `wairz-frontend-axios-timeout-sweep-2026-04-22-patterns.md`

## Context

User prompt: "deep research using ouroboros and Citadel how to proceed".
Starting state: daemon `stopped` (no-active-work), 1 pending intake, 2 queued
campaigns, ~25 other intakes. Output: 2 commits + a 271-line multi-session
seed plan with 4-scout-validated recommendations. No code changes, pure
research + readiness-audit.

## Successful Patterns

### 1. 4-scout parallel Explore fleet for "how to proceed" prompts

- **Description:** Expand the 2-scout baseline (strategic + tactical, from
  `strategic-next-steps-2026-04-19`) to **4 orthogonal archetypes** when the
  session's "what's next" decision has >1 dimension:
  - **ROI scan** — rank all pending work items by composite leverage.
  - **Deep triage** — front-load the top candidate's details so the next
    session dispatches cleanly (no re-discovery cost).
  - **Readiness audit** — for each QUEUED campaign, validate it's actually
    dispatchable today (no stale assumptions, no missing prep).
  - **Orchestrator fit** — given the backlog, pick the right tool (Citadel
    autopilot / fleet / archon / Ouroboros hybrid).
- **Evidence:** Session 5321d5a1 dispatched 4 Explore agents in a single
  message (`Agent({subagent_type: "Explore"})` × 4). Wall clock ~3 min.
  All 4 returned structured reports under 500 words each. Synthesis was
  mechanical — each scout answered one question cleanly; the union
  determined session-plan structure (commit `8b80c81`, 271-line seed).
- **Applies when:** The user asks an open-ended strategic question
  ("how to proceed", "what should we do next", "strategic plan"), AND the
  backlog has ≥2 candidate directions, AND at least one candidate is a
  campaign (not just an intake). For narrowly-scoped questions, use
  `citadel:research` skill (single-agent). For 2-candidate decisions,
  stay with the 2-scout baseline.
- **Anti-inclusion:** Don't add a 5th scout unless you can name its
  archetype clearly. "Research more" is not an archetype.

### 2. Subagent type resolution: check the available-agents list first

- **Description:** Before calling `Agent({subagent_type: "X"})`, verify
  `X` is in the available-agents list. Skill names (`citadel:research`,
  `citadel:doc-gen`, etc.) and agent-type names are two disjoint
  namespaces; some plugins expose both. Calling a skill name as a
  subagent type raises
  `Agent type 'X' not found. Available agents: [...]`.
  The fallback for read-only parallel research is always `Explore`.
- **Evidence:** Session 5321d5a1 first attempt dispatched
  `subagent_type: "citadel:research"` × 4 and got 4 errors in one message.
  Re-dispatched with `subagent_type: "Explore"` × 4 in the next message,
  succeeded. Round-trip cost: ~1 extra prompt cycle; no material delay.
- **Applies when:** ANY `Agent` tool call. In Claude Code the list appears
  in the system prompt's tool schema and in the initial system-reminder.
  Grep-audit before dispatch: "does the available-agents list show this
  name?"
- **Recovery:** If you've already dispatched and errored, re-send all
  Agent calls in ONE message with the corrected subagent_type — parallel
  efficiency is preserved.

### 3. Pre-flight Rule #19 on a CAMPAIGN FILE's readiness claims

- **Description:** Rule #19 ("evidence-first") originally applied to
  backfill/cleanup intakes claiming specific DB conditions. Extend the
  discipline to `.planning/campaigns/*.md` files marked `status: queued`:
  before dispatching, audit every "needs prep commit" / "must update
  first" / "blocker risk" claim against the actual in-tree state.
  Concerns that are no-ops get closed in the campaign file with a dated
  audit note; concerns that are real get a prep commit BEFORE the
  fleet dispatch.
- **Evidence:** Session 5321d5a1 202+polling-readiness scout raised 2
  prep concerns:
  1. "`ProjectRouteGuard` may need a status-filter update for `starting`"
     — actual read of `frontend/src/components/ProjectRouteGuard.tsx`
     showed it only resets Zustand stores on projectId change, carries
     no status filter → no-op.
  2. "E2E specs may stall at 30s when POST becomes 202" — grep
     `startEmulation\|startCampaign` in `frontend/tests/e2e/` returned 0
     matches; the existing `emulation-workflow.spec.ts` is UI-smoke
     only; no fuzzing spec exists → no-op.
  Both audited and documented in the campaign file as "Pre-flight audit
  — 2026-04-20" block (commit `5d75bca`). Campaign status flipped
  `queued → ready`. NO prep commit needed. Dispatch-ready.
- **Applies when:** Any campaign approaches dispatch after sitting
  `queued` for ≥1 calendar day. Intervening commits can invalidate
  assumptions silently (see Rule #19 parent).
- **Harness rule candidate (low confidence, NOT added):** Detecting the
  "needs audit" condition mechanically requires parsing campaign-file
  prose — not a regex win. Keep as discipline, not enforcement.

### 4. Intake diagnosis correction as a /learn surface (diff from Rule #19)

- **Description:** Rule #19 asks "is the CONDITION still present?" — a
  state check. This pattern asks "is the intake's ROOT CAUSE DIAGNOSIS
  correct?" — a causation check. When a research scout reads the actual
  failing tests (not just the intake's summary), the scout can catch
  misdiagnosis before scope sets — e.g., "test is structurally correct,
  failure is a real product bug" vs. the intake's "test is the bug".
  The correction gets written into the session seed AS A PRE-FLIGHT for
  the next session, not applied in-session.
- **Evidence:** Session 5321d5a1 CI-triage scout read
  `backend/tests/test_cache_module.py` in full. Intake
  (`.planning/intake/backend-pytest-unstable-tests.md`) claimed 2 failures
  are test-bugs: `test_does_not_commit_only_flushes` (MagicMock
  auto-attr) and `test_deletes_all_rows_for_firmware` (UUID str SQL
  rendering). Scout's read: both tests are structurally correct;
  failures likely indicate the service-under-test calls `db.commit()`
  where it should `db.flush()` (CLAUDE.md Rule #3 violation). Seed
  (commit `8b80c81`) documents this as "Pre-flight Rule #19 re-measure"
  for the next session's stream γ (`test_cache_module.py` → 1 code fix
  + 0 test changes, probably).
- **Applies when:** An intake prescribes "fix the test" for N>1 failing
  cases. Have the pre-dispatch scout actually open at least one of the
  failing tests and cross-read the service-under-test. Catches
  "it's the test" misdiagnoses cheaply.

### 5. Multi-session seed with 3-session forward plan

- **Description:** When pre-dispatch research identifies ≥2 large work
  items (not just "next candidate"), write a single forward seed
  covering **+1, +2, and +3** sessions. Each session-block has: specific
  campaign/intake target, stream decomposition (if fleet-applicable),
  acceptance criteria, commit cadence, and pre-flight discipline. Avoids
  per-session re-planning; preserves scout evidence in a durable place;
  survives context-window compression.
- **Evidence:** Session 5321d5a1 wrote
  `.planning/intake/seed-next-session-2026-04-20.md` (271 lines)
  covering:
  - +1: `/fleet` 202+polling (2 streams α/β, merge order α-first)
  - +2: `/fleet` pytest-unstable-tests (3 clusters α/β/γ)
  - +3+: intake-drain order (cache-extraction → hook-dedup → pagination)
  Plus pre-flight gates, scout telemetry table, and verification
  protocols applied session-wide.
- **Applies when:** A research pass identifies ≥2 high-ROI next
  campaigns + ≥3 residual intakes in a clear ranking. Don't write
  forward plans beyond +3 — backlog changes fast, later sessions
  re-evaluate.
- **Format reuse:** The 2026-04-18 seed (`seed-next-session-2026-04-19.md`)
  used Short/Medium/Large scope options with Scout-deepening. The
  2026-04-20 version moved to session-numbered blocks because the
  decomposition was sequential-over-time, not parallel-over-appetite.
  Both shapes are valid — pick based on whether the user faces
  **appetite choice** (options A/B/C) or **schedule choice** (+1/+2/+3).

### 6. Ouroboros-vs-Citadel decision as an explicit scout archetype

- **Description:** User memory (`project_ouroboros_citadel_strategy.md`)
  says "Ouroboros dormant, Citadel active — use Ouroboros only for new
  major features." When the user invokes both ("deep research using
  ouroboros and Citadel"), DON'T route through
  `/ouroboros:welcome` auto-trigger. Instead, dispatch a scout with the
  explicit charter: "which (if any) backlog items would genuinely
  benefit from Socratic interview / evolutionary loop?" — and let the
  scout honestly say "none" when true. Saves an interview round that
  would produce no new information.
- **Evidence:** Session 5321d5a1 dispatched "Ouroboros fit" scout
  (archetype #4 of the 4-scout fleet). Scout found: no Ouroboros skills
  on disk under `~/.claude/plugins/ouroboros/` (remote MCP only); every
  queued backlog item has a tight spec; 2 feature intakes already shipped.
  Verdict: "Use Citadel for all current backlog. Ouroboros dormant until
  greenfield feature with discovery risk lands." Saved an entire
  `/ouroboros:interview` round.
- **Applies when:** User invokes both orchestrator names, OR when a
  system reminder auto-suggests `/ouroboros:welcome` despite established
  dormancy preference. Run the fit scout; honor the memory.
- **Format:** Scout's output should explicitly say "none of the current
  backlog genuinely needs Ouroboros right now" when that's true. User
  asked for research, not validation — honest null verdicts are
  high-signal.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use `Explore` agents (not `citadel:research` skill) for parallel scouts | `citadel:research` is a Skill (not Agent type); scouts need to be Agents for parallel dispatch. First attempt errored with the skill name. | 4 parallel Explore agents returned structured reports in ~3 min wall clock. |
| Extend Rule #19 to campaign readiness claims | Queued campaigns sitting >1 day develop stale "prep needed" assumptions; intervening commits can resolve them silently. Same evidence-first discipline applies. | Commit `5d75bca`: 2 prep concerns audited → both no-op; campaign flipped `queued → ready`; 0 prep commits shipped. |
| Write 3-session forward plan, not 1-session seed | 4-scout research surfaced 2 campaigns + 3-intake residual; writing them all at once preserves evidence and scout-verified stream decompositions. | Commit `8b80c81`: 271-line seed covering +1/+2/+3 sessions. |
| Keep Ouroboros dormant | Scout confirmed no current backlog item has discovery risk; every intake has a tight spec. User memory preference (dormant) honored without a new interview round. | No `/ouroboros:*` invocation this session. |

## References

- Parent /learn: `strategic-next-steps-2026-04-19-patterns.md` (pattern #1 —
  2-scout baseline that this extraction extends to 4-scout)
- CLAUDE.md Rule #19 — evidence-first on DB conditions (parent); this
  extraction extends the discipline to campaign-file readiness claims
- CLAUDE.md Rule #3 — use `flush()` not `commit()` in MCP handlers (the
  Pattern #4 misdiagnosed-test case)
- Campaign file: `.planning/campaigns/emulation-fuzzing-202-polling.md`
  (contains the inline audit note at line 13-32 per commit `5d75bca`)
- Seed file: `.planning/intake/seed-next-session-2026-04-20.md`
- Commits: `5d75bca..8b80c81` (2 commits this session)
