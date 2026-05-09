# Postmortem: Windows-Coverage God-Mode — Phase ε.1.b (EVTX Orchestration Layer)

> Date: 2026-05-10
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-epsilon-1b-2026-05-10.md`
> Branch: `feat/windows-phase-epsilon-2026-05-10` (from ε.1.a tip `99f5a73`)
> Commits: 6 (`9e839a1..c86cf90`) on top of `99f5a73`
> Outcome: completed

## Summary

Phase ε.1.b shipped the EVTX orchestration layer that ε.1.a's `evtx_service.py` docstring described — `walk_evtx_files` walker + alembic `firmware.evtx_walk_*` 5-col 202+poll status set + inner/outer/safe runner triplet + auto-walk hook in `unpack.py` + 6 MCP tools in new `windows_event_log` category (registry 213→219) + frontend `EvtxWalkPage` skeleton + `FindingService.emit_evtx_findings_from_walk` hook for the Sysmon-1 / 4624 / 4625 forensic-timeline trio + 3-tier real-firmware canary (Rule-of-Four) + Dockerfile fix for `libpff-utils` (closeout PR #2 deferred-verification bug). 6 commits, 0 reverts, +2401 LOC across 19 files, all green; container rebuild + Rule #11 import smoke clean against alembic head `e1a2b3c4d5e6`.

## What Broke

### 1. Bash CWD drift after `cd backend && uv run ...` (Rule #38 sub-incident)

- **What happened:** Used `cd backend && uv run python -c "..."` early in the session for the alembic-head pre-check. The Bash tool's cwd persists across calls, so the next invocation `git -C /home/dustin/code/wairz log` (absolute path) worked, but a subsequent `Read` of `c8d9e0f1a2b3_add_registry_hive_walk_status.py` would have hit `backend/backend/...` if I'd used a relative path. Detected when a parallel `Read` failed mid-batch ("File does not exist") because pwd was `/home/dustin/code/wairz/backend`.
- **Caught by:** **Self-inspection** mid-flow — the failed Read tool result triggered an immediate `pwd` check.
- **Cost:** ~30 seconds (one cwd reset; the parallel `Read` of the .NET migration was cancelled by the user, so I had to retry it).
- **Fix:** Switched to subshell `( uv run ... )` for the rest of the session — the cd is scoped to the parens and doesn't leak.
- **Infrastructure created:** None — Rule #38 already documents this; ε.1.b adds another data point to the Rule-of-Three+ count (β.10 / β.12 incidents → β.14 / γ / δ / ε.1.b clean sessions, with one mid-session catch each in δ and ε.1.b that validates rather than violates the rule).

### 2. Rule #36 test false positive on docstring "subprocess.run" mention

- **What happened:** First draft of `test_tier1_no_execute_discipline_in_evtx_paths` used `assert "subprocess.run" not in src` — the bare-token check matched the *docstring* prose explaining what Rule #36 forbids ("Future ε.X workers that shell out to additional EVTX tools..."). Test FAILED on legitimate code.
- **Caught by:** **pytest** — failed loudly on first run (1 failed + 4 passed + 2 skipped).
- **Cost:** ~2 minutes (recognise the false positive, switch to a regex that matches the call form `subprocess.run(` with paren).
- **Fix:** Changed bare-token check to `re.search(r"\bsubprocess\.run\s*\(", src)` — only matches actual call sites, not docstring text. Same change for all 10 forbidden tokens.
- **Infrastructure created:** None — the regex shape is now documented in `test_evtx_real_firmware.py` and can be lifted as a recipe if a third application needs it. Pattern: docstring mentions of forbidden tokens are LEGITIMATE (they explain the rule); only call-form matches count.

### 3. Pipe-induced exit obfuscation in first Rule #24 canary attempt (Rule #35a)

- **What happened:** First Rule #24 canary attempt was `npx tsc -b --force 2>&1 | tail -15`. The pipe captured tsc's exit code through `tail`, which is the canonical Rule #35a pipe-trap — `$?` after a pipeline reflects the LAST command (tail), not the first (tsc). Output showed `exit=0` despite tsc producing a TS2322 error (canary file deliberately bad).
- **Caught by:** **Rule #35a discipline** — the rule itself says "use file-redirect form, not pipe form". I noticed the impossible "exit=0 with TS2322 error visible" combination and re-ran without the pipe.
- **Cost:** ~30 seconds (one re-run with `> /tmp/canary-tsc.log 2>&1 ; ec=$?`).
- **Fix:** Switched to file-redirect form: `cmd > /tmp/log 2>&1; ec=$?; tail /tmp/log`. The shell pipeline is gone; `$?` reflects `cmd` directly. Canary correctly produced `exit=2` with TS2322 visible.
- **Infrastructure created:** None — Rule #35a already codified this. The fix is the worked example for Rule #24's mandatory canary protocol; future Rule-of-Three would lift this to a `.mex/patterns/` recipe.

### 4. Closeout PR #2 ε.2 Dockerfile change broke `docker compose build`

- **What happened:** Phase ε.2 (commit `2724640` from the closeout campaign) added `libpff-utils` to the Dockerfile apt-install list. The package does NOT exist in Debian Trixie (the backend image's base distribution). The closeout campaign's Phase 3 ε.2 ledger entry explicitly said "rebuild verification deferred to next session" — so the bug landed unverified, and surfaced at ε.1.b cut-over time when Rule #8 rebuild ran for the first time since ε.2 landed.
- **Caught by:** **Docker compose build** — `apt-get install` failed loudly: `E: Unable to locate package libpff-utils` + `process did not complete successfully: exit code: 100`.
- **Cost:** ~5 minutes (probe Trixie's apt cache for `libpff` family, identify that only `libpff-dev` / `libpff1t64` / `python3-pypff` exist; verify `python3-pypff` is the right replacement; commit the fix).
- **Fix:** `c86cf90` replaces `libpff-utils` with `python3-pypff` (the Python bindings, which is the actual delivery shape for libpff CLI usage in libyal's toolchain on Trixie). `libesedb-utils` and `libregf-utils` remain (both available in Trixie).
- **Infrastructure created:** **None enforced**, but the postmortem flags the Rule #19 generalisation in Recommendation #1.

### 5. `gh pr edit --body` failed silently due to GraphQL deprecation warning

- **What happened:** Tried `gh pr edit 3 --body "$(cat <<'EOF' ... EOF)"` to update PR #3 description. Output showed only the GraphQL Projects-classic deprecation warning, no error message. Subsequent `gh pr view 3` showed body length unchanged — the edit didn't apply, but `gh` exited with what appeared to be a partial-success state.
- **Caught by:** **Self-inspection** — checked PR body length post-edit (still 7110 chars; my new body was ~5500 chars). The mismatch triggered investigation.
- **Cost:** ~3 minutes (try `--body-file`; that also failed with the same GraphQL warning; fall back to `gh api -X PATCH /repos/.../pulls/3 --field body=@file` which DID work).
- **Fix:** Switched from `gh pr edit --body-file` to `gh api -X PATCH .../pulls/3 --field body=@file --jq '.body | length'`. The REST endpoint succeeded where the GraphQL-backed CLI failed silently.
- **Infrastructure created:** None — workaround documented in this postmortem. Future PR-body updates should prefer `gh api` over `gh pr edit` when GraphQL deprecation warnings appear, OR check body length post-edit to verify the change applied.

### 6. Edit-tool Read-first guardrail on Dockerfile (Rule #21 corollary)

- **What happened:** Tried to Edit `backend/Dockerfile` to fix the libpff-utils bug without first calling Read on the file in this conversation turn. Edit failed: `File has not been read yet. Read it first before writing to it.`
- **Caught by:** **Edit tool guardrail** — returned the error message immediately; no edit applied.
- **Cost:** ~10 seconds (one Read call).
- **Fix:** Read then Edit on retry.
- **Infrastructure created:** None — Edit tool guardrail is the enforcement. Rule-of-Three+ across γ.9 / δ / ε.1.b (with one catch in this session, matching δ's count of two).

### 7. `git stash --include-untracked` captured operational state files alongside campaign file

- **What happened:** Archon Step 1.5 protocol calls for `git stash push --include-untracked` as a phase checkpoint. The stash captured both intended targets (the new campaign file in `.planning/campaigns/`) AND every operational state file (`.claude/circuit-breaker-state.json`, `.planning/telemetry/*.jsonl`, `.planning/daemon.json`). When `git stash pop` ran, those files reappeared as modified — but they're already in the explicit-don't-stage discipline, so this didn't cause harm. The cost was an attempted `git checkout stash@{0} -- <campaign-file>` which failed because the stash's untracked-file storage doesn't appear in `--name-only` output the same way tracked-modified files do.
- **Caught by:** **Self-inspection** — noticed `git stash show stash@{0} --name-only` listed only tracked-modified files, then a follow-up `ls` confirmed the campaign file was missing from disk.
- **Cost:** ~1 minute (one `git stash pop` to restore everything; the campaign file came back along with the operational state files I had to ignore again).
- **Fix:** `git stash pop` restored everything; the operational state files reverted to the pre-stash unstaged state, which matches the global-constraint "don't stage operational state" discipline anyway. Stash dropped at end of session.
- **Infrastructure created:** None — the archon checkpoint protocol is fine for tracked changes; the wairz session's operational-state-files-in-the-tree problem (closeout antipattern #4) is what makes the protocol awkward. Recommendation #2 below proposes the durable fix.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Rule #24 mandatory tsc canary | Confirmed TS2322 + exit=2 on the canary file (canary works); real typecheck of FE source then exited 0 cleanly | 2 fired (one mid-session for ε.1.b.4, one final) | Trusting a "0 errors" output that was actually masking a TS2322 in the new ε.1.b.4 FE pages — canary verified the tool was actually checking |
| Rule #35a pipe-trap detection | Caught the first canary attempt's `\| tail` pipe-induced exit obfuscation | 1 catch + correction | Reporting a "passed" canary that actually masked the real exit code; would have undermined the Rule #24 discipline at its first application this session |
| Rule #19 evidence-first probes | (a) δ patterns + postmortem read before drafting ε.1.b.1; (b) γ.4 `registry_hive_walker.py` precedent read before ε.1.b.3 runner triplet design; (c) alembic head pre-validated via Python regex script BEFORE authoring migrations; (d) `e0a1b2c3d4e5` + `e1a2b3c4d5e6` revision IDs pre-checked FREE against 60-revision tree; (e) Trixie apt cache probed for `libpff` family BEFORE picking the replacement package | 5 | Multi-iteration design churn; alembic revision-ID collisions (δ.3 hit two consecutive); arbitrary picking of a wrong replacement package for libpff |
| Rule #36 forbidden-call regex gate | Confirmed zero subprocess / asyncio.create_subprocess_* / os.system call sites in evtx_service.py at test time | 10 forbidden patterns × 1 source file scan | A future contributor adding a "convenience" subprocess invocation against an .evtx file would be caught at pytest time |
| Rule #25 single-slice exception #2 (cross-stack alignment) | ε.1.b.4 bundled alembic + Pydantic Literal + `_SOURCE_*` constants + emit method + 6 MCP tools + auto-walk hook + FE union + FE config + FE page + route registration in ONE commit | 0 actual catches (designed in alignment from the start) | `test_finding_source_alignment.py` would have been RED between commits if ε.1.b.4 had been split. Saved a bisect-broken state. **Rule-of-Five now** — `7079b4d` + β.12a `ee2abd9` + γ.7 `f70c2e1` + δ.8 `20ea228` + ε.1.b.4 `5466644`. Pattern is durable beyond reasonable doubt. |
| `test_finding_source_alignment.py` (3 tests) | Confirmed DB CHECK (28 sources at ε end) ↔ FE union ↔ FE config aligned post-ε.1.b.4 | 3 / 3 pass | Cross-stack drift between DB allowlist and frontend rendering would have shipped silently — operators would see "Manual" badges for new ε sources via the `?? FINDING_SOURCE_CONFIG.manual` fallback |
| Rule #35b live canaries | Forced ORM round-trip + SELECT verification on `_do_evtx_walk_run` (3 tier-1 canaries) and `emit_evtx_findings_from_walk` (1 emit-end-to-end canary in test_evtx_real_firmware.py) | 4 live canaries shipped in ε.1.b | Constructor-args-vs-persisted-fields class of bugs (audit-2026-05-04 F-A-06 confidence-bypass shape). The emit hook's three-source dispatch was verified end-to-end; the runner's per-provider aggregation was verified to match the synthetic input |
| Rule #35c JSONB normalizer + stamp + schema_version | New `firmware.evtx_walk_result` JSONB column shipped with normalizer + stamp + 11 dedicated tests covering canonical / None / wrong-type / idempotency | 11 normalizer tests | Producer-consumer JSONB shape drift — the audit-2026-05-04 F-G-04 finding's class of bug |
| Edit tool Read-first guardrail | Edit attempt on Dockerfile without prior Read | 1 | Silent edit against assumed file contents (Bash output is stale relative to prior Edit calls) |
| Rule #38 absolute-path discipline | `git -C /home/dustin/code/wairz` for every git invocation; subshell `( uv run ... )` for cwd-sensitive Python calls | ~50+ Bash invocations clean (1 mid-session catch-and-correct vs the prior pattern) | CWD drift after `cd backend && ...` (the β.10 / β.12 incident pair). Rule-of-Four+ clean now (γ + δ + ε.1.b continue β.14's clean streak) |
| Rule #8 extended rebuild + Rule #11 post-rebuild import smoke | (a) rebuild backend + worker + migrator together caught the `libpff-utils` Trixie packaging bug at apt-install time, BEFORE any tests ran against a stale image; (b) post-rebuild smoke confirmed 6 evtx exports + 3 source constants + 219 MCP tools + 10-value WindowsFindingSource + JSONB schema_version=1 in the rebuilt container | 1 build-time catch + 6 import-smoke confirmations | Stale image runtime drift — the running backend would have continued serving the OLD code (no bind mount); tests against host would have passed but container behavior would have diverged |

## Scope Analysis

- **Planned (ε.1.b kickoff prompt):** 5 sub-tasks ε.1.b.1..ε.1.b.5 — walker (.1), alembic status set + windows_event_records table OR just status set decide-at-runtime (.2), inner/outer/safe runner triplet (.3), auto-walk hook + 6-8 MCP tools + FE skeleton + finding emit + cross-stack alignment slice in ONE commit (.4), 3-tier real-firmware canary (.5).
- **Built:** All 5 sub-tasks shipped as 5 commits + 1 housekeeping commit (Dockerfile fix). Decision #1 in the campaign file: per-event `windows_event_records` table DEFERRED to a future ζ.X phase — `firmware.evtx_walk_result` JSONB aggregate is sufficient for the walk-summary; per-event search indexing layers on top later without breaking the schema. ε.1.b.4's "6-8 MCP tools" landed as 6 tools (the lower bound; covers the trigger / status / list / parse / query / summary surface; ζ.X may add 2 more for full search if needed).
- **Drift:** None on the build axis. One scope-clarification at start (defer per-event table to ζ.X) resolved before drafting code. One out-of-scope housekeeping commit (Dockerfile fix) added because Rule #8 rebuild surfaced the closeout-PR #2 deferred bug; necessary to declare ε.1.b complete. No commit-level rework.

## Patterns

- **Rule #25 per-sub-task commits held under ε.1.b** — 6 commits, each independently revertable, no `--no-verify`, no `--amend`. **Rule-of-Thirteen now across the campaign** (α 12 + β 14 + γ 9 + δ 9 + ε.1.b 6 = 50 commits, 0 reverts).
- **Rule #25 single-slice exception #2 (cross-stack alignment)** is **Rule-of-Five now**: `7079b4d` (2026-05-06) + `ee2abd9` β.12a + `f70c2e1` γ.7 + `20ea228` δ.8 + `5466644` ε.1.b.4. The alignment test is RED between commits if split, GREEN under the bundled commit shape. Pattern is durable beyond reasonable doubt — should be promoted to a CLAUDE.md Rule-of-Five citation.
- **Real-PE skip-tier canary discipline** — Rule-of-Four now: β.14a + γ.9 + δ.9 + ε.1.b.5. The 5p+2s on dev host shape is durable; tier-2/3 fixture provisioning graduates to 7p with no test edits. The recipe at `.mex/patterns/real-firmware-skip-tier-canary.md` (PR #2) is the canonical template.
- **Inner-vs-outer runner split (δ Pattern #2)** is now Rule-of-Three: γ.4 implicit precedent + δ.5 first explicit codification + ε.1.b.3 second explicit codification. The shape — `_do_<op>_run(db, firmware_id)` for tier-1 live canaries, `run_<op>_background(firmware_id)` for production via `async_session_factory()`, `auto_walk_firmware_safe(firmware_id)` for unpack hook — is mature beyond doubt. Promotable to CLAUDE.md rule on third occurrence (this is the third) — propose Rule #39 in the recommendations.
- **Rule #38 absolute-path bash discipline held under ε.1.b** — Rule-of-Four+ clean now (β.14 first clean session + γ + δ + ε.1.b). One mid-session catch-and-correct each in δ and ε.1.b validates the discipline rather than violating it.
- **Rule #19 evidence-first generalises across new library surfaces and infrastructure layers** — applied to alembic head pre-check (1-second Python regex script avoided a δ.3-style collision), revision ID candidates pre-validation (8 candidates checked FREE in one batch), Trixie apt cache for `libpff` family (caught the wrong replacement). Same shape every time: probe in seconds; design against actual contract; save iteration cycles.
- **Rule #33 .a/.c/.d 202+polling contract held under ε.1.b.2 + ε.1.b.3 + ε.1.b.4-trigger** — new firmware-row status set has Pydantic Literal + DB CHECK (.c), the `trigger_evtx_walk` MCP tool is idempotent with 409-on-conflict (.a), and the dispatch (.d) correctly chose `asyncio.create_task` (in-process pure-Python parser; per-firmware JSONB aggregate is durable state).
- **Rule #36 no-execute discipline + automated regex test** — ε.1.b extends the test-gate codification from δ.4's `assert_no_execute_argv` (subprocess argv-token check) to ε.1.b.5's source-file regex scan (`re.search` for `subprocess.X(` form). Different shape (source-scan vs argv-scan), same rule. Future ε.X / ζ.X workers can adopt either pattern depending on whether the worker spawns subprocesses or not.

## Recommendations

1. **Generalise Rule #19 evidence-first to "rebuild verification at change-time, not consumer-session-time".** ε.1.b's housekeeping commit (`c86cf90`) was forced because closeout PR #2's ε.2 commit deferred Rule #8 rebuild verification to "next session" — the next session was ε.1.b's, and the bug surfaced as a campaign-blocker rather than a closeout follow-up. Cheap mitigation: when a campaign explicitly defers a verification step, the deferral note in the Feature Ledger should auto-create a `.planning/intake/verify-<commit>-<step>.md` ticket so the next pre-flight check picks it up without manual handoff. Or: simpler — refuse to ship a Dockerfile-touching commit without the rebuild verification, no exception. Cost: minor process change. Benefit: eliminates the deferred-verification trap class.

2. **Add operational state files to `.gitignore` (closeout antipattern #4 closure).** The campaign-file restoration dance during Archon Step 1.5 was awkward because `.claude/circuit-breaker-state.json`, `.planning/telemetry/*.jsonl`, `.planning/daemon.json`, etc. all show up as modified-tracked files in `git status`. Adding them to `.gitignore` (or an `.gitignore.local` that the harness manages) would make `git stash --include-untracked` capture only intentional new files (campaign markdown, source files), eliminating the "did the campaign file survive the stash?" worry. Cost: 5 lines in `.gitignore` + one cleanup commit to `git rm --cached` the affected files. Benefit: cleaner archon checkpoints; less cognitive load during Bash ops.

3. **Promote the inner/outer/safe runner triplet to CLAUDE.md Rule #39.** δ's Pattern #2 codified inner-vs-outer split; ε.1.b is the third independent application (γ.4 precedent + δ.5 explicit + ε.1.b.3 explicit). The pattern is durable: `_do_<op>_run(db, firmware_id)` (inner — accepts db, pure logic, tier-1 testable via make_live_db()) + `run_<op>_background(firmware_id)` (outer — owns Rule #33 .a state machine via async_session_factory) + `auto_walk_firmware_safe(firmware_id)` (unpack hook — owns own session, never mutates status, fire-and-forget). Three applications in three independent Phase-X slices = Rule-of-Three. CLAUDE.md Rule #39 should codify the contract + cite the three precedents. Companion to Rule #33 .a (state machine ownership) and Rule #35b (live canaries against the inner runner). Cost: ~30 lines of CLAUDE.md prose + .mex/context/conventions.md mirror per Rule #21.

4. **Promote `.mex/patterns/inner-outer-safe-runner.md` recipe.** Same Rule-of-Three argument as #3 — three applications across three phases is enough evidence. Recipe shape: when to use (any Rule #33 202+poll background work that needs tier-1 testability), how to write the three functions, idiomatic test scaffold via `make_live_db()`, common pitfalls (don't call the outer wrapper from tier-1 — `socket.gaierror` from Docker DNS). Cost: ~250 LOC of doc; benefit: future agents avoid the δ.5-style "first canary attempt fails with gaierror" detour.

5. **Document the `gh api -X PATCH` workaround for `gh pr edit --body-file` failures.** The GraphQL deprecation warning that broke `gh pr edit --body` is documented as a `gh` open issue but isn't called out anywhere in wairz docs. Add a one-paragraph callout to the harness `add-router-test.md` recipe (or wherever gh is first mentioned) noting the workaround. Cost: 5-line doc note. Benefit: future PR-body-update sessions don't waste 3 minutes on this.

6. **Tier-2/3 real-firmware canary fixture provisioning.** ε.1.b.5 ships 5p+2s; tier-2 needs a real Win11 `Security.evtx` at `WAIRZ_TEST_REAL_EVTX_FILE`, tier-3 needs a paired before/after Sysmon log directory at `WAIRZ_TEST_REAL_EVTX_PAIRED`. Fixture extraction is a one-time operator setup (any modern Windows install has these natively). Once provisioned, the canary set graduates from 5p+2s to 7p with no test edits. Mirrors β.14a + γ.9 + δ.9 deferred-fixture-provisioning shape.

7. **Extend `_normalize_firmware_evtx_walk_result` + `_stamp_firmware_evtx_walk_result` once ζ.X per-event persistence lands.** Current schema_version is 1 (just the aggregate). When ζ.X adds the `windows_event_records` table for per-event search, the aggregate shape may evolve (e.g. add `by_eid` histogram for top-N event IDs). Bump `FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION` to 2 + extend dispatch in the normalizer per Rule #35c forward-discipline.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 5 (ε.1.b.1..ε.1.b.5) |
| Phases completed | 5 (100%) + 1 housekeeping commit |
| Commits | 6 (`9e839a1..c86cf90`) |
| Files changed | 19 (8 new, 11 modified) |
| Lines added | 2,429 |
| Lines deleted | 28 |
| Reverts | 0 |
| Amends | 0 |
| `--no-verify` invocations | 0 |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Rule #24 mandatory canary | 2 fired (correctly produced TS2322 + exit=2 via file-redirect form; real typecheck exited 0) |
| Rule #35a pipe-trap catches | 1 (caught + corrected mid-canary, no impact) |
| Edit-tool Read-first catches | 1 (Dockerfile, no impact) |
| Alembic revision-ID collisions | 0 (pre-validation eliminated the trap) |
| Closeout-deferred-verification catches | 1 (Dockerfile libpff-utils; surfaced at first ε.1.b rebuild) |
| Tests added | +28 (5 walker + 11 jsonb normalizer + 5 inner-runner + 7 real-firmware canary) |
| Targeted pytest pass | 307 pass + 2 skip (tier-2/3 fixture-pending, expected) |
| New MCP tools | +6 (213 → 219 total registry size) |
| New JSONB normalizers | +1 (`firmware.evtx_walk_result`) |
| New Pydantic Literals | +1 (`EvtxWalkStatus`) |
| New finding sources | +3 (`windows_sysmon_proc_create`, `windows_logon_success`, `windows_logon_failure`) — registry now 28 sources |
| New ORM models | 0 (per-event table deferred to ζ.X per Decision #1) |
| New alembic migrations | +2 (ε.1.b.2 status set, ε.1.b.4 ck_findings_source extension) |
| Per-table alignment test pairs | 4 (γ.1 + γ.2 + δ.1 + δ.5 — unchanged; ε.1.b adds firmware-status Literal which lives outside the `_PAIRS` tuple) |
| Wall-clock duration | ~50 minutes |

---HANDOFF---
- Postmortem: windows-coverage-godmode-epsilon-1b-2026-05-10
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-epsilon-1b-2026-05-10.md
- Failures documented: 7 (CWD drift, Rule #36 test false-positive, Rule #35a pipe-trap, libpff-utils Dockerfile, gh pr edit silent fail, Edit Read-first guard, git stash include-untracked friction)
- Safety catches: 11 (Rule #24 canary × 2, Rule #35a pipe-trap detect, Rule #19 probes × 5, Rule #36 forbidden-call regex × 10 patterns, Rule #25 alignment Rule-of-Five, alignment-test-pair × 3, Rule #35b live canaries × 4, Rule #35c normalizer × 11 tests, Edit guardrail × 1, Rule #38 ~50+ clean invocations, Rule #8+#11 rebuild + smoke)
- Recommendations: 7 (Rule #19 generalise to "rebuild at change-time", .gitignore operational state, promote inner/outer/safe to Rule #39, write inner-outer-safe.md recipe, document gh api workaround, tier-2/3 EVTX fixture provisioning, ζ.X normalizer schema bump)
---

Run `/learn windows-coverage-godmode-epsilon-1b-2026-05-10` to extract patterns into the knowledge base.
