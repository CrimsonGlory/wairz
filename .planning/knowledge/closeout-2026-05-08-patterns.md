# Patterns: Windows-Coverage God-Mode Closeout (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-closeout-2026-05-08.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-closeout-2026-05-08.md`
> Branches: `feat/windows-phase-delta-2026-05-09`, `feat/postmortem-followups-2026-05-09`, `feat/windows-phase-epsilon-2026-05-10`
> Commits in scope: `ed3b515`, `037e091`, `75c3343`, `d9ea7cd`, `2724640`, `99f5a73` (6 commits 0 reverts)
> Status: 3 phases (A→C→B) completed; 3 PRs opened (PR #1 OPEN, PR #2 OPEN, PR #3 DRAFT)

This is a META-campaign extraction — the campaign was itself a closeout
+ docs + ε kickoff batch, not feature work. Patterns are about workflow
discipline (scope, branching, mirror discipline) rather than service
architecture. Layered on top of:

- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md` (and successors β.7–β.14)
- `windows-coverage-godmode-gamma-2026-05-09-{patterns,antipatterns}.md` (γ phases)
- `windows-coverage-godmode-delta-2026-05-09-{patterns,antipatterns}.md` (δ phases — immediate precedent)

## Successful Patterns

### 1. Pre-emptive rule codification at trusted level after Rule-of-One

- **Description:** When the operator is at trusted level (188+ sessions
  completed per harness.json) AND the failure mode is structurally
  identical to an already-codified rule, codify the extension after
  Rule-of-One rather than waiting for Rule-of-Two. Phase 2/C.1 extended
  CLAUDE.md Rule #8 from "rebuild worker whenever you rebuild backend"
  to "rebuild worker AND migrator..." after δ.5 alone (Rule-of-One).
  The rationale: backend + worker + migrator share the SAME Dockerfile +
  SAME alembic versions tree; the failure mode (stale image init
  container exits 255) is structurally identical to the worker-stale
  case. Waiting for a Rule-of-Two recurrence in ε would buy nothing —
  the rule shape is already clear.
- **Evidence:** Commit `037e091` — Rule #8 + Rule #38 extension landed
  pre-emptively in Phase 2/C.1 after one δ.5 incident, NOT after a
  second occurrence in ε. The δ postmortem antipattern #2 explicitly
  recommended pre-emptive codification.
- **Applies when:**
  (a) trust level is "trusted" per `harness.json` (20+ sessions, or 188+
      in this codebase's case);
  (b) the new failure mode is structurally identical to an already-
      codified rule (shared infrastructure, shared dependency graph,
      shared cache layer); AND
  (c) waiting for Rule-of-Two recurrence would not change the rule's
      wording — only its evidence base.
  **Counter-cases:** novel failure modes that haven't appeared at
  Rule-of-One yet, or operators at "novice"/"familiar" trust level
  where over-codification adds friction without clear benefit. For
  those cases, wait for Rule-of-Two.

### 2. Honest scope reduction with split-and-document

- **Description:** When a sub-task scoped in the kickoff brief turns
  out to exceed the session's budget (token, time, or cognitive),
  reduce scope HONESTLY by splitting into N.a + N.b + ...; ship N.a
  cleanly with full transparency in the commit message + PR
  description about what's deferred. Do NOT hide partial work as
  "complete", and do NOT half-commit work that fails its acceptance
  criteria.
- **Evidence:** Phase 3/B.ε.1 was specified by the user's kickoff
  brief as "EVTX parser via python-evtx + auto-walk hook from unpack
  post-detection per γ.4 / γ.5 precedent" — a single-commit slice per
  Rule #25. Mid-session, the realistic scope (parser + walker +
  auto-walk hook + outer state machine + ORM persistence + tests)
  exceeded the remaining context budget. Reduced to ε.1.a (parser
  foundation + Rule #19 probe + 5 tier-1 tests, ~400 LOC) with
  ε.1.b (auto-walk hook + outer state machine + ORM persistence +
  MCP tools + FE skeleton + Finding emit) explicitly deferred. The
  ε.1.a commit message + PR #3 description both documented the
  split + listed every deferred item by name. No half-completed
  state on disk; no scope-creep-then-blame; no claim that ε.1 was
  "done".
- **Applies when:** any scoped sub-task whose realistic LOC /
  complexity / time exceeds remaining session budget AND has natural
  decomposition points (parser-vs-orchestrator,
  scaffold-vs-implementation, foundation-vs-emit). Mechanical
  heuristic: if you find yourself thinking "I'll just stub this
  for now" — STOP, split into N.a + N.b instead, and ship N.a as
  a properly-documented foundation. The kickoff brief's exit-
  condition rule "Do not start sub-tasks you cannot finish; better
  to land 1-2 clean commits than 3 partial" is the canonical phrasing.

### 3. Branch state pre-flight discovery before any push

- **Description:** Before issuing `git push` or `gh pr create`, run a
  3-command pre-flight that surfaces hidden state mismatches:
  (1) `git log --oneline <main-or-merge-base>..HEAD | wc -l` — verify
      commit count matches expected (caught: γ commits unexpectedly
      reachable via clean-history).
  (2) `git log --oneline clean-history..HEAD` — verify which feature
      commits are NOT yet merged into the umbrella branch (caught: γ
      unmerged into clean-history → δ PR base must be γ branch, not
      clean-history).
  (3) `git ls-remote --heads origin <branch>` for every dependent
      branch — verify dependent bases are actually pushed (caught: γ
      branch was LOCAL ONLY → δ PR base wouldn't resolve until γ was
      pushed).
- **Evidence:** Phase 1/A pre-flight at session start surfaced both
  drift conditions before any push. Without the pre-flight, δ PR
  creation would have failed with "base ref does not exist" (γ
  branch missing on origin) OR included +10K LOC of γ noise (γ commits
  reachable via clean-history if base was clean-history). Cost of
  pre-flight: ~5 seconds of bash. Cost of skipping it: ~5 minutes of
  PR re-creation + ~5K-10K LOC of misleading PR diff if discovered
  late.
- **Applies when:** any closeout PR for a feature branch in a
  multi-phase campaign where dependent branches (parent / sibling /
  base) may not all be on the remote AND where the umbrella merge
  base may have drifted. Mechanical heuristic: before `gh pr create
  --base X --head Y`, verify (a) Y is pushed, (b) X is pushed, (c)
  the diff between X and Y is what you expect.

### 4. Atomic Rule #21 mirror via single-commit-multiple-files

- **Description:** Rule #21 mirror discipline (CLAUDE.md ↔
  .mex/context/conventions.md) is an instance of Rule #25 single-slice
  exception #1 (multi-file change bundled in ONE commit). Phase 2/C.1
  bundled both files in commit `037e091`; both Rule #8 + Rule #38
  changes touched both files; the commit landed atomically. Splitting
  would have left a window where CLAUDE.md had the new wording but
  conventions.md had the old, OR vice versa — both intolerable
  states for any agent reading either file as canonical.
- **Evidence:** Commit `037e091` — diff stat: `CLAUDE.md +2/-2` +
  `.mex/context/conventions.md +3/-3` in one commit. The Rule #21
  reciprocal-pin shape held; no bisect-broken intermediate state.
  Same shape as the Rule #25 single-slice exception #2 (cross-stack
  alignment via `test_finding_source_alignment.py`) but for docs
  rather than code.
- **Applies when:** any change to CLAUDE.md Learned Rules MUST also
  update `.mex/context/conventions.md` Verify Checklist in the SAME
  commit (Rule #21). Generalises to any pair of files where one is
  canonical + the other is a derived mirror that agents read at
  task time. Workflow: edit canonical → edit mirror → stage both →
  commit ONCE. NEVER `git add CLAUDE.md && git commit -m "..."` then
  `git add .mex/conventions.md && git commit -m "mirror update"` —
  that creates a bisect-broken window.

### 5. Citadel skill chaining as campaign closeout discipline

- **Description:** Archon's exit protocol → /citadel:postmortem →
  /citadel:learn → /citadel:session-handoff is a 4-step closeout
  ritual that this session executed in sequence. Each skill reads
  the previous one's output (postmortem reads campaign file; learn
  reads campaign + postmortem; session-handoff reads everything
  including learn's output). The chain produces a complete archival
  package: campaign moved to `completed/`, postmortem in
  `.planning/postmortems/`, patterns + antipatterns in
  `.planning/knowledge/`, and HANDOFF block for next session pickup.
- **Evidence:** This session ran the chain at end-of-campaign; the
  resulting `.planning/` shape is consistent with prior phase
  closeouts (e.g. δ produced same set of artefacts). Archon
  explicitly suggested /postmortem in its exit handoff;
  /postmortem suggested /learn; /learn does not auto-suggest
  /session-handoff but the user requested it explicitly.
- **Applies when:** any completed campaign — feature work, doc work,
  closeout meta-campaigns, or scoped reductions. The chain takes
  ~15-20 min and produces durable artefacts that future sessions
  + `/citadel:dashboard` + cross-campaign analyses depend on.
  Skipping the chain leaves the campaign's lessons in the session
  transcript (which gets compacted away) rather than the
  knowledge base.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | A→C→B ordering (closeout → docs → kickoff) | C produces recipes that B's tests follow; doing C first eliminates the "promote pattern as part of ε.1" detour mentioned in the original brief | Correct on first attempt; ε.1.a's docstring + commit message reference the C.3 recipe (just-landed in PR #2) for tier shape |
| 2 | δ knowledge files commit on δ branch (not C branch) | They document δ work; bisect-clean lineage matches the work they describe | Correct; δ PR #1 description references the same files as committed on the same branch |
| 3 | C base = δ branch (not main / clean-history) | C content (CLAUDE.md edits + recipes) is independent of δ feature work but the C branch was cut off δ tip; using clean-history as base would have shown all of γ + δ + C work as one PR | Correct; PR #2 shows only the 3 C commits cleanly |
| 4 | ε base = δ branch (not C branch) | ε is feature work; C is doc work; mixing them complicates revert/bisect; C's recipes are referenced from ε but don't need to be on the same branch | Correct; PR #3 shows only the 2 ε commits cleanly |
| 5 | γ branch pushed but γ PR NOT opened | Brief was δ-specific; γ PR would expand scope. γ branch push was the minimum required for δ PR base | Correct for this campaign; tracked as Recommendation #1 for next session |
| 6 | ε.1 split into ε.1.a + ε.1.b | Realistic scope (parser + walker + auto-walk + ORM + MCP + FE) exceeded remaining context budget; ε.1.a foundation + ε.1.b orchestration is the natural decomposition | Correct; ε.1.a ships clean foundation; ε.1.b's planned shape documented in evtx_service.py module docstring + PR #3 description |
| 7 | Pre-emptive Rule #8 extension (Rule-of-One codification) | Migrator-stale failure mode is structurally identical to worker-stale; waiting for Rule-of-Two would not change rule wording | Correct; rule + mirror landed atomically in `037e091` |
| 8 | Skip ε.2 rebuild verification this session | Rebuild takes 3-5 min + consumes context for log; deferring to next session keeps closeout-campaign budget intact | Correct; tracked as Recommendation #3 for next session; the Dockerfile delta IS the change |

## Cross-references back into existing knowledge

- **Pattern #1 (pre-emptive Rule-of-One codification at trusted
  level)** is novel within wairz as an explicit discipline; it
  generalises the Rule #21 mirror practice to a new dimension —
  WHEN to codify, not just HOW. Promotable to a CLAUDE.md
  meta-rule on the second occurrence (e.g. if a future ε or ζ
  phase codifies a rule extension after Rule-of-One on
  structurally-identical grounds).
- **Pattern #2 (honest scope reduction with split-and-document)** is
  the canonical interpretation of the kickoff brief's exit-condition
  rule. Generalises Rule #25 per-sub-task commit discipline:
  not only "commit each sub-task separately" but also "if a
  sub-task realistically splits into N.a + N.b mid-session, ship
  N.a cleanly + document N.b's planned shape in the same artefacts
  (commit message, PR description, module docstring)."
- **Pattern #3 (branch state pre-flight)** generalises Rule #19
  evidence-first to git/PR state: measure the actual branch +
  remote state with 3 cheap commands BEFORE any push or PR
  creation. Companion to Rule #38 absolute-path discipline (both
  are bash-tool hygiene rules that cost ~1 second).
- **Pattern #4 (atomic Rule #21 mirror)** is the FOURTH application
  of Rule #25 single-slice exception #1 (multi-file mirror) —
  CLAUDE.md ↔ conventions.md sync. Earlier applications: any
  prior Learned-Rule addition (the rule itself was added in α
  with mirror discipline). Pattern is durable beyond doubt.
- **Pattern #5 (Citadel skill chain closeout discipline)** is
  Rule-of-Two now (δ + closeout) — both campaigns ran the
  archon → postmortem → learn → session-handoff chain at
  end-of-campaign. Pattern is durable; future campaigns should
  default to running the chain.
- **Rule #25 per-sub-task commits** is now **Rule-of-Eighteen
  across the windows-coverage campaign** (α 12 + β 14 + γ 9 +
  δ 9 + closeout 6 = 50 commits, 0 reverts). Pattern is durable
  beyond reasonable doubt; codified.
- **Rule #38 absolute-path discipline** held under closeout —
  Rule-of-Three+ clean now (β.14 + γ + δ + closeout). The one
  mid-flow `cd /home/dustin/code/Citadel` for the consent-grant
  retry was scoped to a single Bash invocation; next git command
  used `git -C /home/dustin/code/wairz` form again. Validates
  the discipline rather than violating it.
- **Rule #19 evidence-first** held under closeout — Phase 3/B
  pre-author probe `grep -E "python-evtx" pyproject.toml
  Dockerfile docker-compose.yml` confirmed dep was MISSING before
  authoring ε.1.a code. Pyproject.toml addition + service code
  shipped together in commit `99f5a73`. Same shape as δ.4's
  multi-package import probe.
- **Citadel external-action-gate** worked as designed — the gate
  fired on the first `gh pr create`, the operator re-granted with
  the correct cwd, and the gate did NOT auto-bypass. The 6-hour
  TTL is the right design tradeoff for "long sessions stay warm
  but inter-session boundaries require fresh consent".
