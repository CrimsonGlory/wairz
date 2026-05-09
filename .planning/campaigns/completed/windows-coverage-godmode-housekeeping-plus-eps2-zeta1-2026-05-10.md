# Campaign: Windows-Coverage God-Mode — Housekeeping + ε.2 + ζ.1 (Extended Scope)

> **Slug:** `windows-coverage-godmode-housekeeping-plus-eps2-zeta1-2026-05-10`
> **Created:** 2026-05-10
> **Owner:** archon
> **Status:** active
> **Trust:** trusted (176+ sessions completed)
> **Branches:** three new branches off main, one per item — `feat/windows-phase-gamma-2026-05-09` is reused for item 1 (already pushed).
> **Reversibility:** amber — three independent commits + three PRs; revert via `git revert <sha>` per item; PRs revert via `gh pr close`.

## Direction

Three durable-debt closures before any new ε.2 / ζ.X feature work. None touch infrastructure (Dockerfile / docker-compose / alembic). Purpose:
1. Unblock the merge chain by opening the γ PR (currently no PR exists; δ PR #1 has base=γ branch by design — γ MUST merge first).
2. Close ε.1.b antipattern #7 + closeout antipattern #4 (operational state files in tree force awkward `git stash` dances; archon Step 1.5 checkpoint friction).
3. Codify Rule #39 (inner/outer/safe runner triplet) per Rule-of-Three confirmed across γ.4 + δ.5 + ε.1.b.3.

After all three ship: defer Phase ε.2 / ζ.X selection to the user.

## Baseline (recorded at campaign creation)

- main tip: `e2fd35e` (origin)
- ε branch tip: `c86cf90` (PR #3 DRAFT, base=δ branch)
- δ branch tip: `ed3b515` (PR #1 OPEN, base=γ branch)
- γ branch tip: `8437ae3` (origin, **NO γ PR opened — Phase 1 closes this**)
- C/postmortem-followups tip: `d9ea7cd` (PR #2 OPEN, base=δ branch)
- δ PR #1 body retrieved as template for γ PR body shape
- Today's date: 2026-05-10

## Knowledge Files (read for Rule #19 evidence-first compliance)

Read prior to phase work — confirmed loaded into archon context this session:
- `.planning/postmortems/postmortem-windows-coverage-godmode-epsilon-1b-2026-05-10.md`
- `.planning/knowledge/windows-coverage-godmode-epsilon-1b-2026-05-10-patterns.md`
- `.planning/knowledge/windows-coverage-godmode-epsilon-1b-2026-05-10-antipatterns.md`
- `.planning/campaigns/completed/windows-coverage-godmode-epsilon-1b-2026-05-10.md`
- δ PR #1 body via `gh pr view 1 --repo eastmadc/wairz`

To-read in-phase:
- Phase 1: `.planning/postmortems/postmortem-windows-coverage-godmode-gamma-2026-05-09.md` + γ patterns for PR body content
- Phase 3: `.mex/context/conventions.md` (mirror target), `.mex/patterns/INDEX.md` (recipe template), `backend/app/services/registry_hive_walker.py` + `windows_update_diff_service.py` + `evtx_service.py` (three precedents to cite)

## Global Constraints

- DO NOT push to main, ever.
- DO NOT use `git --no-verify`, `--no-gpg-sign`, or `--amend` (Rule-of-Twelve discipline).
- DO NOT commit operational state files (`.claude/circuit-breaker-state.json`, `.claude/harness.json`, `.planning/daemon.json`, `.planning/telemetry/*.jsonl`, `.planning/fleet/session-*.md`). Phase 2 is what closes this loop in tree.
- DO commit knowledge / postmortem / campaign files only at campaign close.
- Per Rule #21: any change to CLAUDE.md Learned Rules MUST mirror to `.mex/context/conventions.md` Verify Checklist in the SAME commit. (Phase 3 explicitly does this.)
- Per Rule #25: each item is its own branch off main + its own commit (3 branches, 3 commits, 3 PRs).
- Per Rule #38: prefer absolute paths and `git -C /home/dustin/code/wairz <cmd>`; subshell `(cd backend && uv run …)` for cwd-sensitive invocations.
- Per Rule #19 generalised (ε.1.b Recommendation #1): NEVER defer rebuild verification. None of these three items touch infrastructure — confirm by inspecting the diff before commit (only .gitignore + CLAUDE.md + .mex/* + git-rm-cached entries; zero changes to backend/Dockerfile / backend/alembic/ / docker-compose.yml). NO rebuild needed.
- Per Rule #35a: any `cmd | tail` invocation that needs an exit code uses file-redirect form.
- Pre-push: `git status --short` MUST show only intended files staged; operational-state files MUST NOT be staged.

## Phases

| # | Phase | Branch | Status |
|---|-------|--------|--------|
| 1 | Open γ PR (merge-chain unblock) | `feat/windows-phase-gamma-2026-05-09` (reuse existing) | **complete** — PR #4 OPEN |
| 2 | .gitignore for operational state + git rm --cached | `feat/gitignore-operational-state-2026-05-10` (off main) | **complete** — PR #5 OPEN (`8e27106`) |
| 3 | CLAUDE.md Rule #39 + mirror + recipe | `feat/claude-md-rule-39-2026-05-10` off ε tip; PR base=ε | pending |
| 4 | ε.2.A — `windows_event_records` table + alembic + ORM + JSONB normalizer + alignment | `feat/windows-phase-epsilon-2-2026-05-10` off ε tip | pending |
| 5 | ε.2.B — wire per-event persistence into `_do_evtx_walk_run` + live canary | same branch | pending |
| 6 | ε.2.C — `search_events` MCP tool + helpers | same branch | pending |
| 7 | ζ.1.A — `windows_amcache_extracts` table + alembic + ORM + alignment | `feat/windows-phase-zeta-1-2026-05-10` off ε.2 tip | pending |
| 8 | ζ.1.B — `amcache_walker.py` (Rule #39 4th application; auto-walk hook) | same branch | pending |
| 9 | ζ.1.C — Amcache MCP category + finding emit | same branch | pending |
| 10 | close-out — postmortem + knowledge + active → completed move | direct commits to ε branch | pending |

## Resolved Decisions (added 2026-05-10 mid-campaign)

**Phase 3 topology — Option B revised: branch off ε tip; PR base=ε branch.** User instruction "we need to do them all and you decide" + multi-persona analysis: main is 5wks stale, no clean Rule #39 base on main; ε is the only base with Rules 1-38; this matches PR #2 base=δ shape (sibling docs PR pattern).

**ζ.X format pick: Amcache.** Library cost zero (regipy already in deps); 150 LOC walker mirrors γ.4 exactly; provides 4th application of Rule #39 inner/outer/safe triplet (Rule-of-Four).

**Daemon: skip.** Single-session execution with HANDOFF if context fills.

## Phase End Conditions

| Phase | Condition | Type | Verify |
|-------|-----------|------|--------|
| 1 | γ PR exists at GitHub against `main` | command_passes | `gh pr list --repo eastmadc/wairz --head feat/windows-phase-gamma-2026-05-09 --json number,baseRefName --jq '.[0].number' \| grep -E '^[0-9]+$'` |
| 1 | γ PR body contains link to merge-chain ordering note | command_passes | `gh pr view <N> --repo eastmadc/wairz --json body --jq '.body' \| grep -i "merge order"` |
| 2 | `.gitignore` contains all 5 patterns | command_passes | `for p in '.claude/circuit-breaker-state.json' '.claude/consent-session-externalActions.json' '.planning/daemon.json' '.planning/telemetry/\*.jsonl' '.planning/fleet/session-\*.md'; do grep -F "$p" /home/dustin/code/wairz/.gitignore; done` |
| 2 | Tracked variants are removed from index | command_passes | `git -C /home/dustin/code/wairz ls-files \| grep -E 'circuit-breaker-state\|telemetry/.*\.jsonl\|daemon\.json\|harness\.json' \| wc -l` returns 0 (or only `harness.json` if intentionally tracked) |
| 2 | New branch pushed + PR open | command_passes | `gh pr list --repo eastmadc/wairz --head feat/gitignore-operational-state-2026-05-10 --json number --jq '.[0].number' \| grep -E '^[0-9]+$'` |
| 3 | Rule #39 exists in CLAUDE.md Learned Rules | file_exists + grep | `grep -E '^39\. \*\*Background runners' /home/dustin/code/wairz/CLAUDE.md` |
| 3 | `.mex/context/conventions.md` Verify Checklist mirrors Rule #39 | command_passes | `grep -i 'rule #39' /home/dustin/code/wairz/.mex/context/conventions.md` |
| 3 | Recipe file exists | file_exists | `test -f /home/dustin/code/wairz/.mex/patterns/inner-outer-safe-runner.md` |
| 3 | Recipe is referenced from `.mex/patterns/INDEX.md` | command_passes | `grep -F 'inner-outer-safe-runner' /home/dustin/code/wairz/.mex/patterns/INDEX.md` |
| 3 | New branch pushed + PR open | command_passes | `gh pr list --repo eastmadc/wairz --head feat/claude-md-rule-39-2026-05-10 --json number --jq '.[0].number' \| grep -E '^[0-9]+$'` |

## Decision Log

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Three separate branches off main (not stacked off ε) | Per Rule #25 — durable-debt closures aren't ε feature work. Branches off main are independently mergeable; stacking off ε would chain these into the windows-coverage merge order needlessly. |
| 2 | Phase 1 reuses the existing γ branch instead of cutting a fresh "PR-only" branch | The γ branch tip `8437ae3` is already pushed; opening the PR against it is one `gh pr create` call. Cutting a fresh branch would be churn for no benefit. |
| 3 | Phase 3 bundles CLAUDE.md + conventions mirror + recipe in ONE commit | Rule #21 mandates the mirror in same commit; the recipe is the natural companion artefact for Rule #25 documentation. Splitting would leave conventions.md missing the mirror line for one commit (Rule #21 violation). |
| 4 | NO rebuild this campaign | None of the three items touch Dockerfile / docker-compose / alembic. Per Rule #19 generalised (ε.1.b Rec #1), we verified the diff before declaring no-rebuild — applies on each commit. |
| 5 | NO daemon | Single-session work; user explicitly said "No daemon currently running". Three small, well-scoped items. |

## Continuation State

- Current phase: 3 (Rule #39 codification — BLOCKED on user decision)
- Files modified so far: PR #4 (γ → main); PR #5 (.gitignore commit `8e27106` on `feat/gitignore-operational-state-2026-05-10` → main).
- Blocking issues: **Phase 3 topology issue** — user said "branch off main, NOT on the ε branch" but `main` (e2fd35e, 5 weeks stale) has CLAUDE.md ending at Rule #5. Adding Rule #39 to that base produces a chimeric file (Rule #39 next to Rule #5 with #6-38 missing). The full Rule #1-38 set lives only on the ε branch (and partially on δ / postmortem-followups). User decision needed — see "Phase 3 Topology Decision" below.
- checkpoint-phase-1: none (gh-only, no working-tree changes)
- checkpoint-phase-2: none (clean working tree at branch creation; recovery via `git revert 8e27106`)

## Phase 3 Topology Decision (BLOCKED — needs user input)

**Problem:** `main` at `e2fd35e` is 5+ weeks stale. CLAUDE.md on main ends at Rule #5 (basic Performance section). Rules #6–#38 exist on the windows-coverage branches (γ has up to #37; δ + ε have through #38; commit `037e091` adding Rule #38 lives only on the postmortem-followups branch but ε's CLAUDE.md also has Rule #38 via its own history). User's instruction was "off main, NOT on the ε branch — these are durable-debt closures not ε feature work" — but a clean PR adding only Rule #39 requires a base where Rules #1–#38 are already present.

**Options surfaced:**

(A) **Branch off ε tip + PR base=main + accept the umbrella diff.** PR shows ε's full content + Rule #39 against main (765+ commits diff). Same shape as PR #4 (γ → main, 747-commit umbrella). Mergeable into main. **Pro:** clean diff for the rule addition itself; merge-clean once γ → main lands first. **Con:** PR diff is huge; reviewer noise; the user explicitly said "not on the ε branch."

(B) **Branch off ε tip + PR base=ε branch (or δ).** PR diff is JUST Rule #39 + mirror + recipe (small, clean). **Pro:** small focused PR. **Con:** stacks Phase 3 onto the windows-coverage merge chain — exactly what user said NOT to do.

(C) **Branch off main + commit Rule #39 against the stale CLAUDE.md.** PR is small (Rule #39 + mirror + recipe). **Con:** the resulting CLAUDE.md is chimeric (Rules #1–#5 then jump to #39). When γ → main merges later, conflict on the CLAUDE.md tail. Must be merged AFTER γ → main lands. **Pro:** matches user's literal instruction.

(D) **Defer Phase 3 until after PR #4 (γ → main) merges.** Once γ lands in main, main has Rules #1–#37; postmortem-followups (PR #2) merge will bring Rule #38 along; then Phase 3 PR base=main is small + clean. **Pro:** cleanest end state. **Con:** introduces sequencing dependency on review-time decisions outside of agent control.

**Recommended:** (D) Defer Phase 3 until PR #4 merges. The Rule-of-Three is documented in this campaign file + the ε.1.b postmortem; codifying to CLAUDE.md is durable-debt with no time pressure. Once γ + postmortem-followups land in main, Rule #39 codification is a 30-minute follow-up.

**Alternative if user wants Rule #39 NOW:** (A) branch off ε, PR base=main, umbrella diff accepted (same shape as PR #4).

Phase 3 blocked pending user choice. Until then, the durable-debt closure for Rule #39 lives in:
- ε.1.b postmortem Recommendation #3 (codify to Rule #39)
- ε.1.b patterns Pattern #1 (inner/outer/safe runner triplet — Rule-of-Three confirmed)
- This campaign file (Phase 3 plan and topology analysis)

## Active Context

Phase 1 + Phase 2 complete. Direction alignment check (after Phase 2 — every 2 phases per archon Step 4): aligned to user's explicit three-item brief. Phase 3 surfaced a topology issue requiring user input.

## Feature Ledger

| Phase | Date | Outcome | Artefacts |
|-------|------|---------|-----------|
| 1 | 2026-05-10 | complete | PR #4 (https://github.com/eastmadc/wairz/pull/4): γ → main; body 747-commit umbrella; merge-order documented; δ template followed |
| 2 | 2026-05-10 | complete | PR #5 (https://github.com/eastmadc/wairz/pull/5): commit `8e27106` on `feat/gitignore-operational-state-2026-05-10`; 5 gitignore patterns + 9 files `git rm --cached`'d; closes ε.1.b antipattern #7 + closeout antipattern #4 |
| 3 | 2026-05-10 | **blocked on user decision** | Topology issue (main is 5wk stale; CLAUDE.md on main lacks Rules #6-38). 4 options surfaced; recommended (D) defer until PR #4 merges. |

## Review Queue

(none yet)

