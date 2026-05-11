---
version: 1
id: "{uuid}"
status: active
started: "{ISO timestamp}"
completed_at: null
direction: "{one-line summary of the original user direction}"
phase_count: 0
current_phase: 1
branch: null
worktree_status: null
---
<!-- FRONTMATTER GUIDE
  version:        Do not change. Schema version for UI compatibility.
  id:             Stable UUID. Set once at creation. Never change — used by UI for entity tracking across renames.
  status:         Keep in sync with the "Status:" line below. Values: active | completed | parked | failed
  started:        Set once at creation. ISO timestamp.
  completed_at:   Set when status changes to completed or failed. ISO timestamp. null while active.
  direction:      Single-line summary of the campaign goal. No newlines.
  phase_count:    Update when adding phases. Count of rows in the Phases table.
  current_phase:  Update as phases advance. Matches the phase number currently in-progress.
  branch:         Git branch this campaign is executing on (e.g. "feat/auth-refactor"). null if working on main.
  worktree_status: State of the campaign's associated worktree. Values: active | merged | archived | null.
                  Set to "active" when campaign starts in a dedicated worktree.
                  Set to "merged" when the branch has been merged to main.
                  Set to "archived" when the branch is preserved but will not be merged (speculative loser).
-->

# Campaign: {Campaign Name}

Status: active
Started: {ISO timestamp, e.g., 2026-03-20T14:30:00Z}
Direction: {The original user direction that created this campaign}

## Claimed Scope
<!-- Directories this campaign will modify. Used by coordination system to prevent collisions. -->
- src/api/auth/
- src/middleware/

## Ledger Math Baseline
<!-- Pre-execution snapshot of any quantitative target the campaign promises to
     move (ignore-list size, hit count, file count, LOC delta, suite count).
     Captures literal COUNT plus named ENTRY LIST so close-time drift is
     detectable.  Origin: postmortem-async-cleanup-2026-05-12 Recommendation
     #3 — that campaign stated `[tool.ruff.lint] ignore` would shrink 30 → 26
     (4 ASYNC removals), but actual was 30 → 24 (2 incidental commented-
     placeholder cleanups also landed).  The +2 drift was only caught at
     structured-postmortem time.  Capturing the named list at OPEN makes
     close-time diff trivial.  Run this at open AND close; diff the two
     snapshots in the postmortem.  Skip this section entirely for campaigns
     with no quantitative target (pure-feature builds, qualitative refactors). -->

**Quantitative target:** {one-line, e.g. "[tool.ruff.lint] ignore shrinks 30 → 26 entries (4 ASYNC removals)"}

**Baseline at open (paste literal output; adapt commands for the campaign's actual metric source):**

```bash
# Example for ruff ignore-list — replace with your campaign's metric source.
( cd backend && awk '/^ignore = \[/,/^\]/' pyproject.toml | grep -E '^\s*"' | wc -l )
( cd backend && awk '/^ignore = \[/,/^\]/' pyproject.toml | grep -oE '"[A-Z]+[0-9]+[A-Z]?[0-9]?"' | sort -u | tr '\n' ',' )
```

- Count: {N}
- Named list: {comma-separated, e.g. "ASYNC109,ASYNC221,ASYNC230,ASYNC240,B007,..."}
- Captured: {YYYY-MM-DD}

## Phases
<!-- 3-8 phases. Mark status as: [pending], [in-progress], [complete], [skipped], [failed] -->
<!-- "Done When" column: machine-verifiable acceptance criteria. Not "auth is implemented." -->
<!-- Instead: "File exists AND typecheck passes AND endpoint returns 200" -->
| # | Status | Type | Phase | Done When |
|---|--------|------|-------|-----------|
| 1 | pending | research | Audit existing auth implementation | Decision Log has auth audit findings |
| 2 | pending | plan | Design token refresh architecture | Architecture decision logged with alternatives evaluated |
| 3 | pending | build | Implement JWT middleware | src/auth/middleware.ts exists AND typecheck passes |
| 4 | pending | build | Add refresh token endpoint | /api/auth/refresh returns 200 with valid token |
| 5 | pending | wire | Connect auth to existing routes | Protected routes return 401 without token, 200 with token |
| 6 | pending | verify | Run full test suite, manual verification | npm test passes with 0 failures |

## Phase End Conditions
<!-- Machine-verifiable criteria. Archon checks these before marking a phase complete. -->
<!-- Format: phase_number | condition_type | check_command_or_description -->
<!-- Condition types: file_exists, command_passes, metric_threshold, visual_verify, manual -->
<!-- Example:
| 1 | command_passes | npx tsc --noEmit (exit 0) |
| 1 | file_exists | src/auth/middleware.ts |
| 2 | visual_verify | /dashboard renders with data (not skeleton/blank) |
| 2 | metric_threshold | npm test -- --coverage | coverage > 60% |
| 3 | manual | User confirms auth flow works end-to-end |
-->

## Feature Ledger
<!-- Track what was actually built. Updated after each phase. -->
| Feature | Status | Phase | Notes |
|---------|--------|-------|-------|

## Decision Log
<!-- Timestamped decisions with reasoning. Prevents re-debating in future sessions. -->
<!-- Example:
- 2026-03-20: Chose jose over jsonwebtoken for JWT handling
  Reason: ESM native, better TypeScript types, actively maintained
-->

## Review Queue
<!-- Items that need human review. Archon adds items here; user reviews them. -->
<!-- Format: - [ ] {Type}: {Description} -->
<!-- Types: Visual, Architecture, UX, Security, Performance -->
<!-- Example:
- [ ] Visual: Check the new dashboard layout looks right on mobile
- [ ] Architecture: Verify the event bus pattern is correct for cross-domain comm
- [ ] UX: Confirm the onboarding flow feels natural
-->

## Circuit Breakers
<!-- Conditions that should trigger parking this campaign. Defined at creation. -->
<!-- Example:
- 3+ consecutive sub-agent failures on the same phase
- Typecheck introduces 5+ new errors
- Direction drift detected (built features don't serve the original goal)
- Fundamental architectural conflict discovered
-->

## Active Context
<!-- Where the campaign is RIGHT NOW. Updated on every session. -->
<!-- When updating Status or advancing phases, keep frontmatter fields in sync:
     - status mirrors the "Status:" line above
     - current_phase mirrors the active phase number
     - phase_count mirrors the row count in the Phases table
-->
Campaign just created. Starting with Phase 1 (Research).

## Continuation State
<!-- Machine-readable state for the next Archon invocation. -->
<!-- Also update frontmatter: status, current_phase when these change. -->
Phase: 1
Sub-step: not started
Files modified: (none yet)
Blocking: none
