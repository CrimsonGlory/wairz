# Anti-Patterns: Windows-Coverage God-Mode Closeout (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-closeout-2026-05-08.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-closeout-2026-05-08.md`
> Branches: `feat/windows-phase-delta-2026-05-09`, `feat/postmortem-followups-2026-05-09`, `feat/windows-phase-epsilon-2026-05-10`
> Commits in scope: `ed3b515`, `037e091`, `75c3343`, `d9ea7cd`, `2724640`, `99f5a73` (6 commits 0 reverts)
> Status: 3 phases (A→C→B) completed; 3 PRs opened

This is an incremental extraction layered on top of α/β/γ/δ-phase
antipatterns files. Patterns already captured there are not re-stated;
this file captures only the closeout-meta-campaign failure modes.

## Anti-Patterns

### 1. Stale session-allow marker + cwd-dependent grant retry

- **What was done:** First `gh pr create` invocation triggered the
  Citadel `external-action-gate.js` PreToolUse hook with `[Citadel]
  New session — external action needs approval`. The wairz
  `.claude/consent-session-externalActions.json` marker EXISTED but
  had a timestamp of `2026-05-07T21:10:18.561Z` — older than the
  6-hour `hasSessionAllow` TTL (current session was at
  `2026-05-09T00:57Z`). The first re-grant attempt ran:
  ```sh
  cd /home/dustin/code/Citadel && node -e "require('./hooks_src/harness-health-util').grantSessionAllow('externalActions')"
  ```
  But `harness-health-util.js` resolves `PROJECT_ROOT` via
  `process.env.CLAUDE_PROJECT_DIR || process.cwd()`. Because the
  cd'd cwd was `/home/dustin/code/Citadel`, the consent file was
  WRITTEN to `/home/dustin/code/Citadel/.claude/consent-session-externalActions.json`
  — NOT to wairz's `.claude/`. The wairz gate kept firing.
- **Failure mode:** Two consecutive `gh pr create` failures with the
  same hook-block message. ~30 seconds of debug to realize the
  consent file was being written to the wrong project root.
- **Evidence:** Bash log showed two consecutive PR-create attempts
  both blocked by the gate; the second attempt's grant ran from
  Citadel cwd (visible in the bash command). The fix used explicit
  `CLAUDE_PROJECT_DIR=/home/dustin/code/wairz` env var prefix to
  override the cwd-derived PROJECT_ROOT.
- **How to avoid:** When granting session-allow for a Citadel hook
  in a different repo than the script lives in, ALWAYS prefix with
  `CLAUDE_PROJECT_DIR=<target-repo-absolute-path>` rather than
  relying on `cd <citadel-path>` + relative require. Fixed
  invocation:
  ```sh
  CLAUDE_PROJECT_DIR=/home/dustin/code/wairz \
    node -e "require('/home/dustin/code/Citadel/hooks_src/harness-health-util').grantSessionAllow('externalActions')"
  ```
  (Note: still requires the absolute require path because Citadel
  scripts aren't on the wairz Node module search path.) Companion
  to CLAUDE.md Rule #38 (absolute-path bash discipline) — both
  rules cover the cwd-dependence trap. **Promotable to a
  Citadel-side fix:** the script could fall back to walking up
  the directory tree to find the nearest `.claude/` (Git-style
  marker resolution); or document the env-var requirement
  prominently in the hook's stderr message ("To grant: cd
  $TARGET_PROJECT && node -e ..." instead of just "node -e ...").

### 2. Untracked δ knowledge files at session start

- **What was done:** Session started with
  `.planning/postmortems/postmortem-windows-coverage-godmode-delta-2026-05-09.md`
  + the 2 δ patterns/antipatterns files in the UNTRACKED set per
  `git status --short`. The user's brief referenced them as PR
  description sources but did NOT explicitly say "commit them
  first". A naive Phase 1 ("just push δ + open PR") would have
  pushed δ branch WITHOUT the knowledge files, then opened a PR
  whose description references files not present in the diff.
- **Failure mode:** No actual incident — caught via pre-flight
  `git status` reading. ~30 seconds for one extra docs commit
  (`ed3b515`) before push. The commit landed cleanly with all 3
  files (filtering out the .planning/telemetry/ + .claude/
  operational state files via specific path arguments).
- **Evidence:** Pre-flight `git status --short` revealed the
  knowledge files in the untracked set; commit `ed3b515` staged
  exactly the 3 δ files via explicit paths (no `git add -A`).
- **How to avoid:** Pre-flight `git status --short` for any phase
  closeout PR — verify (a) every file referenced in the PR
  description is tracked + committed, (b) operational state files
  are NOT staged, (c) the working tree is consistent with what the
  PR claims. **Promotable to a `.mex/patterns/close-out-pr.md`
  recipe:** the closeout shape is consistent across phases (cf.
  γ closeout, δ closeout, ε kickoff close); a recipe would
  formalize the pre-flight checklist + the "commit knowledge files
  on the WORK branch, not the docs branch" decision. Companion
  Rule #19 evidence-first generalisation — measure git state
  before pushing, not after.

### 3. Untracked prior-phase knowledge files accumulating in working tree

- **What was done:** At session start, `.planning/knowledge/` and
  `.planning/postmortems/` had **21 untracked files** from prior
  phases (β5-β14, γ, qnx, fc05) sitting in the working tree.
  Phase 1's commit `ed3b515` only committed the THREE δ files;
  the other 21 remained untracked at session end. They are
  artefacts that document real work but live nowhere on the git
  history.
- **Failure mode:** No immediate incident, but an accumulating
  risk: a `git clean -fdx` (or a machine wipe / project reclone)
  would lose all 21 files. They represent ~10K+ LOC of extracted
  patterns and postmortems — durable institutional knowledge
  with no durable storage.
- **Evidence:** Session-start `git status` showed 13 untracked
  `.planning/knowledge/*.md` + 8 untracked `.planning/postmortems/*.md`
  files; session-end state is unchanged for those 21 files (we
  only touched the 3 δ files + 2 closeout files).
- **How to avoid:** At every campaign closeout, reconcile the
  `.planning/knowledge/` + `.planning/postmortems/` directories
  with git. Either:
  (a) commit each prior-phase artefact retroactively on its
      original branch (if the branch still exists);
  (b) batch-commit all backlog artefacts on a dedicated
      `chore/backfill-knowledge` branch + open a separate PR for
      the umbrella merge target; or
  (c) explicitly document in `.gitignore` that they're
      intentionally untracked (with the durability tradeoff
      acknowledged).
  Tracked as Recommendation #5 in the closeout postmortem.
  **Promotable to a Citadel /citadel:learn extension:** the skill
  could detect untracked .planning artefacts in its target
  campaign's date range + flag them as a closeout chore, OR
  auto-commit them on the campaign's branch as the FINAL step
  of the chain.

### 4. Operational state files in working tree throughout session

- **What was done:** Session started with — and ended with —
  9 modified operational state files: `.claude/circuit-breaker-state.json`,
  `.claude/harness.json`, `.planning/daemon.json`, and
  `.planning/telemetry/{agent-runs,audit,doc-sync-queue,hook-errors,hook-timing,session-costs}.jsonl`.
  These are session-local artefacts that should NEVER be committed
  on a feature branch. Throughout the session, every `git status`
  + `git diff --cached --stat` had to manually filter them out;
  every `git add` used specific paths to avoid them; the closeout
  campaign's PR descriptions show "Warning: 44 uncommitted changes"
  on every `gh pr create` invocation (the warning includes these
  9 files + the 21 untracked prior-phase artefacts + others).
- **Failure mode:** No incident — defensive `git add <specific-paths>`
  discipline held throughout. But: the noise is high, the warning
  is normalised, and a future operator using `git add -A` (or a
  novice agent that defaults to `git commit -a`) would commit
  operational state onto a feature branch. Once committed,
  reverting requires either a force-push (which Rule prohibits
  except by user request) or an explicit revert commit.
- **Evidence:** Every `git push` and `gh pr create` in this
  session printed "Warning: 44 uncommitted changes". The warning
  was IGNORED because the changes were intentional (operational
  state) — but ignoring it normalises the warning, defeating its
  purpose for catching ACTUAL accidental uncommitted work.
- **How to avoid:** Add the operational state files to a project
  `.gitignore` entry. Concretely:
  ```
  # Citadel operational state — session-local, do NOT commit
  .claude/circuit-breaker-state.json
  .claude/harness.json
  .claude/consent-session-*.json
  .planning/daemon.json
  .planning/telemetry/*.jsonl
  .planning/fleet/session-*.md
  ```
  After this change, `git status` will show only the genuinely-
  modified work-product files, and the "Warning: N uncommitted
  changes" message becomes a real signal again. Tracked as
  Recommendation #4 in the closeout postmortem. **Promotable to
  a Citadel /citadel:setup extension:** the setup wizard could
  auto-add these patterns to `.gitignore` on first run; current
  installations don't have the entries.

### 5. Skill suggestion noise (ouroboros:welcome firing on Citadel-only project)

- **What was done:** Throughout the session, every UserPromptSubmit
  surfaced a `<skill-suggestion>` system reminder for
  `/ouroboros:welcome`, even though the project's user memory
  explicitly declares `Ouroboros DORMANT; Citadel ACTIVE`. The
  welcome experience was suppressed by the agent (correctly
  ignoring the suggestion per memory guidance), but the noise
  appeared in 3+ separate user turns.
- **Failure mode:** No incident — the agent correctly ignored
  every suggestion. But: the suggestion's `IMPORTANT: Auto-
  triggering welcome experience now. Use AskUserQuestion to
  confirm or skip.` framing pressures the agent to interrupt
  the user with a confirmation question on every turn. A less
  disciplined agent OR an agent without memory access would
  have spammed AskUserQuestion calls. The user's project memory
  (`Ouroboros dormant, Citadel active`) is the only signal
  preventing the noise.
- **Evidence:** 3+ user turns in this session received the
  ouroboros:welcome suggestion despite the project memory
  state.
- **How to avoid:** Two layers of fix possible:
  (a) **Ouroboros side:** the welcome trigger should check for
      a project-level "Ouroboros dormant" or "Ouroboros disabled"
      marker before firing. Memory-based suppression is
      operator-specific; a project-file marker would be team-
      shareable.
  (b) **Hook side:** the UserPromptSubmit hook could read the
      operator's auto-memory `MEMORY.md` for the
      `Ouroboros dormant` indicator and suppress the suggestion
      before it reaches the agent.
  Both fixes are upstream-Citadel/Ouroboros work, not wairz-
  specific. Tracked as a follow-up note for Citadel/Ouroboros
  maintainers; not blocking for this campaign or future ones.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (cwd-dependent consent grant)** is novel within
  wairz; the underlying class of issue (cwd-dependent script
  resolution) is already in CLAUDE.md Rule #38. The companion fix
  (CLAUDE_PROJECT_DIR env var) generalises Rule #38's "use absolute
  paths" guidance to cross-repo Node script invocations.
  Promotable: when invoking a Node hook script that lives in a
  different repo than the target project, prefix with
  `CLAUDE_PROJECT_DIR=<absolute-target-path>` instead of relying
  on `cd` resolution.
- **Anti-pattern #2 (untracked knowledge files at session start)**
  is novel as an explicit closeout-PR check. Mitigation is the
  pre-flight `git status --short` discipline already used by Phase
  1; promotable to a `.mex/patterns/close-out-pr.md` recipe (the
  closeout-PR shape is consistent across γ + δ + ε kickoff +
  this campaign — Rule-of-Four).
- **Anti-pattern #3 (knowledge backlog accumulating)** is the most
  durable risk identified this session. The 21 untracked
  artefacts represent real work; their loss would erase
  ~10K+ LOC of extracted patterns + postmortems. Mitigation
  options range from retroactive per-branch commits to a
  dedicated backfill PR — depends on whether prior-phase
  branches are still around. Tracked.
- **Anti-pattern #4 (operational state in working tree)** is a
  Citadel installation-hygiene issue, not a wairz-specific
  problem. The .gitignore fix is straightforward; the
  underlying point is that "Warning: N uncommitted changes" on
  every push normalises the warning + blunts its signal value.
  Promotable to a /citadel:setup wizard improvement.
- **Anti-pattern #5 (ouroboros:welcome noise)** is a
  Citadel/Ouroboros-side issue, not a wairz issue. Documented for
  upstream attention; not blocking for next session.

All five anti-patterns share two common shapes:

1. **"Configuration / state in the wrong place"** — #1 (consent
   file in Citadel/.claude instead of wairz/.claude), #3 (knowledge
   files in working tree instead of branch history), #4
   (operational state in working tree instead of .gitignore'd).
   Mitigation is consistent: declare the target location explicitly
   (env var, branch commit, .gitignore entry) rather than relying
   on cwd / default / convention.

2. **"Hook signal noise"** — #4 (44-uncommitted warning fires on
   every push because of operational state, defeating its purpose),
   #5 (ouroboros:welcome fires on every prompt despite project
   memory disabling it). Mitigation: hooks should check for
   suppression conditions (gitignore membership, memory state)
   before firing.

This is the META-campaign counterpart to δ's "bulk-build environments"
theme — closeout shifts the same lesson to **operator-state
environments** (consent files, gitignore, hook suppression rules)
where the contract is the broader system state, not just one
artefact's content.
