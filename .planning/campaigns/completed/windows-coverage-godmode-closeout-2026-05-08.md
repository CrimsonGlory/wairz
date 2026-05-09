# Campaign: Windows-Coverage God-Mode — Closeout (δ → durable docs → ε kickoff)

> **Slug:** `windows-coverage-godmode-closeout-2026-05-08`
> **Created:** 2026-05-08
> **Owner:** archon
> **Status:** completed
> **Trust:** trusted (188 sessions completed)

## Direction

Three sequential phases, authorized as a single batch by the user:
- **Phase 1 / Variant A** — Push γ + δ branches, open δ PR (close-out, ~5 min).
- **Phase 2 / Variant C** — Postmortem follow-ups: Rule #8 + #38 extensions, add-alembic-migration recipe, real-firmware-skip-tier-canary recipe (durable docs, ~30 min).
- **Phase 3 / Variant B** — Phase ε kickoff: EVTX parser + ESEDB Dockerfile delta (active campaign, ~50 min).

Estimated total: ~85 minutes single-session.

## Ordering Rationale

A→C→B is the right order:
- A first: lowest-risk close-out of completed δ work; gets the PR up before new branches diverge.
- C second: bakes δ lessons into durable infrastructure BEFORE ε starts using them.
- B third: ε kickoff benefits from C's recipes; specifically Pattern #1 in δ patterns ("real-PE skip-tier canary, Rule-of-Three durable") promotes to a recipe that ε.1's tests will follow.

## Baseline (recorded at campaign creation)

- Current branch: `feat/windows-phase-delta-2026-05-09`
- δ tip: `1f09179` (Phase δ.9)
- δ commit range: `1fbdaab..1f09179` (9 commits, 0 reverts, +5788 LOC, +97 tests)
- γ tip: `8437ae3` (Phase γ.9) — **NOT pushed to origin** (origin only has main + clean-history)
- clean-history tip: `5d9a404` on origin
- main tip: `e2fd35e` on origin
- Today's date: 2026-05-08
- Trust level: trusted (188 sessions completed per harness.json)
- No active campaigns blocking this work
- No coordination claims registered

## Knowledge Files (read for Rule #19 evidence-first compliance)

Read prior to Phase 2/C and Phase 3/B work:
- `.planning/postmortems/postmortem-windows-coverage-godmode-delta-2026-05-09.md`
- `.planning/knowledge/windows-coverage-godmode-delta-2026-05-09-patterns.md`
- `.planning/knowledge/windows-coverage-godmode-delta-2026-05-09-antipatterns.md`

These three files are **untracked on disk** — Phase 1 commits them on the δ branch before pushing.

## Global Constraints

- DO NOT push to main, ever.
- DO NOT use `git --no-verify`, `--no-gpg-sign`, or `--amend` (Rule-of-Twelve discipline; campaign has 44 commits 0 reverts).
- DO NOT commit operational state files (.claude/circuit-breaker-state.json, .claude/harness.json, .planning/daemon.json, .planning/telemetry/*.jsonl, .planning/fleet/session-*.md).
- DO commit knowledge files (`.planning/knowledge/*.md`) and postmortems (`.planning/postmortems/*.md`) when explicitly named in a phase's deliverables.
- Per Rule #21: any change to CLAUDE.md Learned Rules MUST mirror to `.mex/context/conventions.md` Verify Checklist in the SAME commit.
- Per Rule #25: each independently-verifiable sub-task is its own commit.
- Per Rule #38: prefer absolute paths and `git -C /home/dustin/code/wairz <cmd>`.
- Per Rule #8 (post-Phase-2/C extension): rebuild backend + worker + migrator together.
- Per Rule #24: frontend typecheck uses `npx tsc -b --force` with the canary protocol.

## Phases

### Phase 1 — Variant A: Push δ + open PR (status: pending)

**Goal:** Get δ on origin and open a PR with γ as base.

**Steps:**
1. Pre-flight checks (branch state, γ-merge status, working tree clean).
2. Stage + commit δ knowledge files (postmortem + patterns + antipatterns) on δ branch.
3. Push γ branch to origin (no PR — just the branch, since δ PR needs γ as base).
4. Push δ branch with `-u origin`.
5. Open δ PR via gh pr create, base = `feat/windows-phase-gamma-2026-05-09`.
6. Capture PR URL.

**End conditions:**
- `command_passes`: `git -C /home/dustin/code/wairz ls-remote --heads origin feat/windows-phase-gamma-2026-05-09` returns one match.
- `command_passes`: `git -C /home/dustin/code/wairz ls-remote --heads origin feat/windows-phase-delta-2026-05-09` returns one match.
- `command_passes`: `gh pr view <PR-number> --json state,baseRefName | jq -e '.state == "OPEN" and .baseRefName == "feat/windows-phase-gamma-2026-05-09"'`.
- `manual`: PR URL captured + reported to user.

### Phase 2 — Variant C: Postmortem follow-ups (status: pending)

**Goal:** Bake δ lessons into CLAUDE.md + .mex/patterns/ as durable infrastructure.

**Steps:**
1. Cut `feat/postmortem-followups-2026-05-09` branch off δ tip 1f09179.
2. Sub-task C.1 — Rule #8 + Rule #38 extension + .mex/context/conventions.md mirror (one commit).
3. Sub-task C.2 — `.mex/patterns/add-alembic-migration.md` recipe + INDEX.md entry (one commit).
4. Sub-task C.3 — `.mex/patterns/real-firmware-skip-tier-canary.md` recipe + INDEX.md entry (one commit).
5. Push branch + open PR (base = clean-history or δ — pick the simplest at runtime).

**End conditions:**
- `file_exists`: `.mex/patterns/add-alembic-migration.md`.
- `file_exists`: `.mex/patterns/real-firmware-skip-tier-canary.md`.
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline 1f09179..feat/postmortem-followups-2026-05-09 | wc -l` equals 3.
- `command_passes`: `grep -c "Rebuild worker AND migrator" CLAUDE.md` equals 1.
- `command_passes`: `grep -c "Rebuild worker AND migrator" .mex/context/conventions.md` ≥ 1 (mirror).
- `manual`: C PR URL captured.

### Phase 3 — Variant B: ε kickoff (status: pending)

**Goal:** Land ε.1 (EVTX) + ε.2 (ESEDB Dockerfile delta) as the first 2 commits of Phase ε.

**Steps:**
1. Cut `feat/windows-phase-epsilon-2026-05-10` branch off δ tip 1f09179 (NOT off C — keep ε's lineage clean).
2. ε.1 — EVTX parser + auto-walk hook + 3-tier real-firmware canary (one commit).
3. ε.2 — Dockerfile delta + Rule #11 import smoke (one commit).
4. Push branch + open DRAFT PR (active phase, not close-out).

**End conditions:**
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline 1f09179..feat/windows-phase-epsilon-2026-05-10 | wc -l` equals 2 (or more if extra ε.X land).
- `file_exists`: a new evtx_service.py somewhere under backend/app/ (path TBD by phase).
- `command_passes`: docker compose exec backend bash -c "which esedbexport && which pffexport && which regfexport" exits 0 after rebuild.
- `manual`: ε draft PR URL captured.

## Active Context

Campaign COMPLETE (2026-05-08).
- δ PR #1 OPEN at https://github.com/eastmadc/wairz/pull/1 (base=γ branch).
- C PR #2 OPEN at https://github.com/eastmadc/wairz/pull/2 (base=δ branch).
- ε PR #3 DRAFT at https://github.com/eastmadc/wairz/pull/3 (base=δ branch).

## Continuation State

- Phase 1 outputs: γ branch on origin (`8437ae3`), δ branch on origin (`ed3b515` after docs commit), δ PR #1.
- Phase 2 outputs: C branch on origin (`d9ea7cd` tip), C PR #2, 3 commits (`037e091` rule extension, `75c3343` add-alembic-migration, `d9ea7cd` real-firmware-skip-tier-canary).
- Rule #8 + Rule #38 mirror discipline held in C.1 (CLAUDE.md + .mex/context/conventions.md updated atomically).
- Phase 3 next step: cut feat/windows-phase-epsilon-2026-05-10 off δ tip ed3b515 (NOT off C — keep ε's lineage clean).

## Decision Log

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | A→C→B ordering (not A→B→C) | C produces recipes that B's tests follow; doing C first eliminates the "promote pattern as part of ε.1" detour mentioned in the original brief |
| 2 | Push γ branch but not γ PR in Phase 1 | Brief is δ-specific; γ PR would expand scope. γ branch push is the minimum required for δ PR base |
| 3 | δ knowledge files (postmortem + patterns + antipatterns) commit on δ branch (not C branch) | They document δ work; bisect-clean lineage matches the work they describe |
| 4 | C branch base = δ tip 1f09179 | Documents derive from δ work; if C ships before δ merges, C's PR base may need to update — defer that decision to runtime |
| 5 | ε branch base = δ tip 1f09179 (not C tip) | ε is feature work; C is doc work; mixing them complicates revert/bisect. C's recipes are referenced from ε but don't need to be on the same branch |

## Feature Ledger

| Phase | Sub-task | Commit | Result |
|-------|----------|--------|--------|
| 1 (A) | δ knowledge files commit | `ed3b515` | docs(δ): postmortem + patterns + antipatterns committed on δ branch |
| 1 (A) | γ branch push | n/a | feat/windows-phase-gamma-2026-05-09 → origin (8437ae3) |
| 1 (A) | δ branch push | n/a | feat/windows-phase-delta-2026-05-09 → origin (ed3b515) |
| 1 (A) | δ PR open | n/a | PR #1 OPEN, base=γ branch, https://github.com/eastmadc/wairz/pull/1 |
| 2 (C.1) | Rule #8 + #38 extension | `037e091` | docs(rules): worker+migrator + CWD-drift catch-and-correct, mirrored to .mex/context/conventions.md per Rule #21 |
| 2 (C.2) | add-alembic-migration recipe | `75c3343` | 286-LOC recipe + INDEX entry; revision-ID pre-check + per-migration shape (table-creator / column-adder / check-extender) |
| 2 (C.3) | real-firmware-skip-tier-canary recipe | `d9ea7cd` | 281-LOC recipe + INDEX entry; Rule-of-Three (β.14a + γ.9 + δ.9), inner-vs-outer runner discipline, Rule #30 mock patch target |
| 2 (C) | C branch push | n/a | feat/postmortem-followups-2026-05-09 → origin (d9ea7cd) |
| 2 (C) | C PR open | n/a | PR #2 OPEN, base=δ branch, https://github.com/eastmadc/wairz/pull/2 |
| 3 (B.ε.2) | Dockerfile delta | `2724640` | feat(workers): libesedb-utils + libpff-utils + libregf-utils added; activates δ.7 windows_storage deep-extraction tools; rebuild verification deferred to next session |
| 3 (B.ε.1.a) | EVTX parser scaffold | `99f5a73` | feat(services): python-evtx dep + evtx_service.py (parse_evtx_file + is_python_evtx_available probe) + 5 tier-1 tests; auto-walk hook + outer state-machine + ORM persistence deferred to ε.1.b next session |
| 3 (B) | ε branch push | n/a | feat/windows-phase-epsilon-2026-05-10 → origin (99f5a73) |
| 3 (B) | ε draft PR open | n/a | PR #3 DRAFT, base=δ branch, https://github.com/eastmadc/wairz/pull/3 |

## Quality Baseline

- Recent commit count: 9 δ + 9 γ + 14 β + 12 α = 44 windows-coverage commits, 0 reverts.
- Frontend typecheck: assumed clean per δ.9 (Rule #24 canary fired correctly per postmortem).
- Backend pytest host sweep: 3539 pass / 9 pre-existing flakes (per γ.9 postmortem; not re-run in this campaign).
- No new code in Phase 1 or Phase 2 — verification deferred to Phase 3 build phase.

## Phase End Conditions Table

| Phase | Type | End Conditions |
|-------|------|----------------|
| 1 (A) | wire | command_passes (3) + manual (PR URL) |
| 2 (C) | docs | file_exists (2) + command_passes (3) + manual (PR URL) |
| 3 (B) | build | command_passes (2) + file_exists (1) + manual (draft PR URL) |
