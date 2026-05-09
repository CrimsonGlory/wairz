# Anti-patterns: Windows-Coverage God-Mode ε.1.b (2026-05-10)

> Extracted: 2026-05-10
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-epsilon-1b-2026-05-10.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-epsilon-1b-2026-05-10.md`

## Failed Patterns

### 1. Bash CWD drift after `cd backend && uv run …` (Rule #38 sub-incident; Rule-of-Four+ now)

- **What was done:** Used `cd backend && uv run python -c "..."` for the alembic-head pre-check at the start of the session. The Bash tool's cwd persists across calls; subsequent invocations that used relative paths (e.g. `Read backend/alembic/versions/...`) would resolve against the wrong base.
- **Failure mode:** A parallel `Read` call failed with "File does not exist" because pwd had drifted to `/home/dustin/code/wairz/backend/`. The user's parallel batch was cancelled and had to be redone.
- **Evidence:** Mid-session detected via `pwd` check returning `/home/dustin/code/wairz/backend` instead of the repo root.
- **How to avoid:** Use subshell form `( uv run python -c "..." )` — the cd is scoped to the parens and doesn't leak. For git operations, use `git -C /home/dustin/code/wairz <cmd>` per Rule #38. Already codified in CLAUDE.md Rule #38; ε.1.b adds another data point. The discipline is durable now (β.14 + γ + δ + ε.1.b clean across all sessions, with one mid-session catch each in δ and ε.1.b that validates the rule rather than violating it). Future occurrences should be flagged as a regression rather than a fresh discovery.

### 2. Bare-token check in Rule #36 source-scan test false-positives on docstring prose

- **What was done:** First draft of `test_tier1_no_execute_discipline_in_evtx_paths` used `assert "subprocess.run" not in src` — a bare token check across the entire source.
- **Failure mode:** The check matched the docstring text that *explains* what Rule #36 forbids ("Future ε.X workers that shell out... MUST NOT pass an extracted .evtx path as argv[0] to subprocess.run / Popen / asyncio.create_subprocess_*..."). Test failed against legitimate code that was correctly documenting the rule.
- **Evidence:** ε.1.b.5 first pytest run — `1 failed, 4 passed, 2 skipped`. Failure message showed the match was inside the docstring.
- **How to avoid:** Use call-form regex `re.search(r"\bsubprocess\.run\s*\(", src)` — only matches actual call sites with paren, not docstring mentions. Generalisable: when scanning source for forbidden API usage, match the CALL FORM (`X.Y(`) not the bare symbol name. Docstring mentions of forbidden APIs are LEGITIMATE (they explain the rule); only call-form matches count.

### 3. Pipe-induced exit obfuscation in Rule #24 mandatory tsc canary (Rule #35a sub-incident)

- **What was done:** First Rule #24 canary attempt was `npx tsc -b --force 2>&1 | tail -15; echo "exit=$?"`. The `| tail` pipe captured tsc's exit code through tail; `$?` after a pipeline reflects the LAST command (tail), not the first (tsc).
- **Failure mode:** Output showed `exit=0` despite TS2322 error visible in the tail output. The "exit=0 with TS2322 error" combination is impossible in a non-piped invocation — this is the canonical Rule #35a pipe-trap.
- **Evidence:** Output of the first canary run included both the type error and a misleading `exit=0`.
- **How to avoid:** Use file-redirect form for exit-code-checking commands: `cmd > /tmp/log 2>&1; ec=$?; tail /tmp/log`. Companion to Rule #17 (silent CLI exit) and Rule #24 (mandatory tsc canary). Already codified in CLAUDE.md Rule #35a; ε.1.b adds a worked example for the Rule #24 canary specifically.

### 4. Closeout-PR #2 deferred Rule #8 rebuild verification → campaign-blocker for next consumer (Rule #19 generalisation gap)

- **What was done:** Closeout PR #2's ε.2 commit (`2724640`) added `libpff-utils` to the Dockerfile apt-install list. The closeout campaign Feature Ledger explicitly noted "rebuild verification deferred to next session" — the Rule #8 extended rebuild was not run at change-time.
- **Failure mode:** `libpff-utils` does not exist in Debian Trixie (the backend image's base distribution). The Dockerfile-touching commit landed unverified; the bug surfaced as a CAMPAIGN-BLOCKER at ε.1.b cut-over time, when Rule #8 rebuild ran for the first time since ε.2 landed. `apt-get install` failed loudly: `E: Unable to locate package libpff-utils` + `process did not complete successfully: exit code: 100`. The closeout campaign was 2 days old at ε.1.b's cut-over; the deferral was effectively forgotten.
- **Evidence:** `c86cf90` is the housekeeping fix forced into ε.1.b's commit set. The fix was 1 line in the Dockerfile but blocked the ε.1.b verification step until it was applied.
- **How to avoid:** Generalise Rule #19 evidence-first to "verify at change-time, not consumer-session-time". When a campaign explicitly defers a verification step that touches infrastructure (Dockerfile, docker-compose.yml, alembic chain), the deferral creates a latent failure mode for the NEXT consumer. **No more deferrals on infrastructure-touching commits.** Either run the verification before the commit lands OR auto-create a `.planning/intake/verify-<commit>-<step>.md` ticket so the next pre-flight picks it up. ε.1.b postmortem Recommendation #1.

### 5. `gh pr edit --body-file` fails silently due to GraphQL Projects-classic deprecation warning

- **What was done:** Tried `gh pr edit 3 --body "$(cat <<'EOF' ... EOF)"` and `gh pr edit 3 --body-file /tmp/body.md` to update PR #3 description.
- **Failure mode:** Output showed only the GraphQL Projects-classic deprecation warning. No error message. Subsequent `gh pr view 3` showed body length unchanged (still 7110 chars from the original DRAFT) — the edit didn't apply, but `gh` exited with what appeared to be a partial-success state. The deprecation warning seems to abort the GraphQL mutation silently.
- **Evidence:** Two attempts at `gh pr edit --body-file` followed by `gh pr view 3 --json body --jq '.body | length'` both showed the body was still 7110 chars (the old DRAFT content).
- **How to avoid:** Use `gh api -X PATCH /repos/{owner}/{repo}/pulls/{number} --field body=@file --jq '.body | length'` for PR body updates. The REST endpoint succeeded where the GraphQL-backed CLI failed. Always verify via body-length post-edit when using `gh pr edit`.

### 6. Edit tool Read-first guardrail trip on Dockerfile (Rule #21 corollary; Rule-of-Four+ now)

- **What was done:** Tried to Edit `backend/Dockerfile` to fix the libpff-utils bug without first calling Read on the file in this conversation turn.
- **Failure mode:** Edit failed with `File has not been read yet. Read it first before writing to it.` No edit applied.
- **Evidence:** The Edit tool returned the error message; subsequent Read + Edit succeeded.
- **How to avoid:** Always Read before Edit on any file in a session. Edit tool guardrail is the enforcement; instinct is calibrating but still occasionally misses. γ.9 / δ / ε.1.b have all hit this 1-2 times per session. The pattern is: a Bash-tool inspection of the file (e.g. `grep`) does NOT count as Read for Edit's purposes; only the Read tool counts. Cost is trivial (~10 seconds per occurrence); no need for additional infrastructure beyond the existing guardrail.

### 7. `git stash --include-untracked` captures operational state files alongside intentional new files (closeout antipattern #4 sub-incident)

- **What was done:** Archon Step 1.5 protocol called for `git stash push --include-untracked` as a phase checkpoint. The wairz session's `git status` shows ~10 modified-tracked operational state files (`.claude/circuit-breaker-state.json`, `.planning/telemetry/*.jsonl`, `.planning/daemon.json`, etc.) AND any intentional new untracked files (the new campaign markdown).
- **Failure mode:** The stash captured both intended new files AND every operational state file. When attempting to selectively restore the campaign file via `git checkout stash@{0} -- <path>`, it failed because the stash's untracked-file storage doesn't appear in `--name-only` output the same way tracked-modified files do. Required a full `git stash pop` to restore everything, which restored ALL captured files including the operational state ones — but those revert back to the pre-stash unstaged state, which matches the don't-stage discipline anyway.
- **Evidence:** `git stash show stash@{0} --name-only` returned only tracked-modified files; the campaign markdown was missing from disk after the stash but was restored by `git stash pop`.
- **How to avoid:** **Add operational state files to `.gitignore`** (closeout antipattern #4 closure). Specifically: `.claude/circuit-breaker-state.json`, `.planning/telemetry/*.jsonl`, `.planning/daemon.json`, `.claude/consent-session-externalActions.json`, `.planning/fleet/session-*.md`, `.claude/harness.json` (if it's mutated by the harness), and any other auto-mutated files in the tree. Then `git stash --include-untracked` captures only intentional new files. ε.1.b postmortem Recommendation #2.

## Cross-references

- Antipattern #1 is durable now (Rule-of-Four+) — Rule #38 codified, all post-Rule-codification sessions clean with one mid-session catch each in δ and ε.1.b.
- Antipattern #2 is a NEW codification — first occurrence in ε.1.b. Promotable to a Rule-of-Three on second occurrence in another phase that runs the same source-scan test.
- Antipattern #3 is a worked example of Rule #35a; Rule already codified.
- Antipattern #4 is a NEW lesson — Rule #19 generalisation gap. Promotable to Rule-of-Two if it recurs; current state Rule-of-One.
- Antipattern #5 is a `gh` CLI workaround; documentation-only (no rule needed). Promotable to a CLAUDE.md note or `.mex/patterns/` callout when authoring PR-update flows.
- Antipattern #6 is durable now (Rule-of-Four+) — Edit guardrail enforcement is sufficient.
- Antipattern #7 is a wairz-specific friction surfaced by the Archon checkpoint protocol against the operational-state-files-in-tree state. Recommendation #2 closes it via `.gitignore` additions.
