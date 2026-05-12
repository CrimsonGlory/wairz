# Anti-patterns: local-dev-env-no-auth intake closure + Phase θ kickoff

> Extracted: 2026-05-12
> Campaign: ad-hoc session
> Postmortem: `.planning/postmortems/postmortem-local-dev-env-no-auth-theta-kickoff-2026-05-12.md`

## Failed Patterns

### 1. `subagent_type: "citadel:research"` (Agent tool)

- **What was done:** Initial parallel-scout dispatch passed `subagent_type: "citadel:research"` to the Agent tool, intending to use the `/citadel:research` skill as a sub-agent.
- **Failure mode:** Agent tool rejected with `Agent type 'citadel:research' not found. Available agents: citadel:arch-reviewer, citadel:archon, citadel:fleet, citadel:knowledge-extractor, claude, claude-code-guide, Explore, general-purpose, Plan, statusline-setup.` Skills (`/citadel:research`) and subagent types are DISJOINT namespaces. `/citadel:research` is invokable via the Skill tool inside the main conversation; it is NOT spawnable as a background Agent.
- **Evidence:** This-session telemetry — 3 simultaneous Agent dispatch rejections at 00:55Z. Re-spawned as `general-purpose` immediately; ~30s cost; no work lost.
- **How to avoid:** Use the Available agents list in the Agent tool docs as the source of truth. For research-style work in background, `general-purpose` is the right pick (it has tool access broad enough to web-search + write files). For Citadel-namespaced agents, only the 4 explicitly registered (`citadel:arch-reviewer`, `citadel:archon`, `citadel:fleet`, `citadel:knowledge-extractor`) are valid. Skills with `citadel:` prefix are invokable via the Skill tool only.
- **No new harness rule needed:** the failure is mechanical and surfaces at dispatch time with a clear error message listing the valid alternatives. A harness rule would add noise without value.

### 2. Edit on `.mex/patterns/INDEX.md` without prior Read

- **What was done:** Inspected `INDEX.md` via Bash `head -50` (sufficient to see the surrounding context for an insert), then immediately issued an Edit.
- **Failure mode:** Edit tool's read-before-write guard rejected with `File has not been read yet. Read it first before writing to it.` Bash grep/head does NOT satisfy the Read-tool's tracking — only the dedicated Read tool counts.
- **Evidence:** Edit tool error at 00:58Z. Recovered by Read'ing the file then re-issuing the same Edit; ~5s cost.
- **How to avoid:** Use the Read tool (not Bash cat/head/tail) when planning to Edit the same file. The Read tool tracks per-session per-file read status; Bash inspections do not register. CLAUDE.md system prompt already calls this out: "use Read (NOT cat/head/tail)" — slip was on my side.
- **No new harness rule needed:** Edit tool already enforces this mechanically.

### 3. (Citadel-level) `protect-files.js` blocks memory file Read/Write

- **What was done:** Attempted to bump validation count in `~/.claude/projects/-home-dustin-code-wairz/memory/feedback_do_them_all_pattern.md` to reflect this session's 8 additional commits / 3rd directive issuance.
- **Failure mode:** `protect-files.js` blocked BOTH Read (`outside project root`) AND Write (`outside project root`). The auto-memory feature is designed for cross-session persistence — agents are expected to maintain memory — but the current rule treats anything outside the project root as restricted unless explicitly allowed.
- **Evidence:** Telemetry entries at 01:04:50Z (Read blocked) and the earlier Write at 01:04:51Z (also blocked). Skipped the memory update; MEMORY.md entry's pre-existing summary remains accurate enough.
- **How to avoid (Citadel-level fix):** Add a positive allowlist entry to `protect-files.js` for `~/.claude/projects/<project-slug>/memory/**`. This is filed as Rec #1 in the postmortem.
- **Note:** This is the only one of the three antipatterns that suggests a Citadel-level rule change. The other two are mechanical and self-correcting.

## What did NOT break (validation positives)

This section is part of the antipatterns file because it documents the
"absence of breakage" that validates discipline-rules from prior sessions:

- **No Rule #38 absolute-path drift.** Every `git -C /home/dustin/code/wairz` invocation resolved against the right tree. The subshell-scoped `( cd <subdir> && ... )` discipline wasn't needed this session (no in-container python work) but the absolute-path patterns held.
- **No Rule #35a pipe-then-exit drift.** No `cmd | tail -N; echo "exit=$?"` patterns introduced. The few Bash invocations that needed both output and exit code used `; ec=$?` BEFORE any pipe.
- **No Rule #25 omnibus bundling.** Each of the 5 intake sub-tasks shipped as its own commit; the 3 Phase θ work products (defer note + scout outputs + brief) each shipped as their own commit.
- **No Rule #11 import-smoke skip.** The `backend/app/main.py` edit was literal-value-only (no class shape change, no new symbol), so Rule #11 smoke was correctly skipped per the commit message rationale.
- **No agent-attribution / cross-stream sweep.** No worktree work this session; main checkout only. Rule #23 worktree discipline N/A.

These validations confirm the operating-rules set holds across this
session's shape. Future sessions should expect the same discipline to
hold.
