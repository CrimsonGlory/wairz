# Anti-patterns: P3 session aa8b4a17 — triple-close at the structural floor

> Extracted: 2026-04-24
> Session: aa8b4a17
> Commits: `8f9d261`, `4bd491b`, `9a26c1a`, `78669d3`, `e84f02e`

## Failed Patterns

### 1. Initial `docker cp` used host-tree path instead of container path

- **What was done:** First `docker cp` call used `/app/backend/app/services/clamav_service.py` (mirroring the host tree layout `backend/app/services/`). Container layout is different: `/app/app/services/clamav_service.py` (the `backend/` prefix is stripped at container build time because the container's WORKDIR is `/app` and the image is built from `backend/`).
- **Failure mode:** `docker cp` returned `Error response from daemon: Could not find the file /app/backend/app/services in container wairz-backend-1`. Cost: one wasted cp call + one diagnostic call (`docker compose exec -T backend ls /app && find /app -maxdepth 3 -name '<file>'`) before recovery. Total ~20-30s wasted plus context-window noise.
- **Evidence:** Session telemetry `audit.jsonl` shows the 22:51:01.469Z cp with the host-layout path, immediately followed at 22:51:05.708Z by the diagnostic `docker compose exec ... ls /app && find` probe, then at 22:51:11.255Z the corrected cp.
- **How to avoid:** Before the FIRST `docker cp` of a session, run one cheap discovery call: `docker compose exec -T backend find /app -maxdepth 3 -name '<any known file>'`. Cache the container-path prefix for the rest of the session. Alternatively, the prior P3 session's knowledge file (`firmware-service-p3-execution-2026-04-24-patterns.md` STEP 6) could have embedded the exact command with `/app/app/services/` — but it used a placeholder `<file>`. Recommend amending that file OR adding a `.mex/patterns/docker-cp-rule20.md` pattern that hardcodes the container-layout path.

### 2. Bash call cancellation in the opening parallel batch

- **What was done:** The opening context-gather message issued a single batch with 5 bash calls + 3 reads + 1 tool-search + 1 task update. Three of the five bash calls returned output; the remaining two (`=== top-level imports of each promotion target ===` and `=== full app.* import graph for each target ===`) returned `Cancelled: parallel tool call Bash(...) errored` plus the ToolSearch was cancelled as a cascade. No harness error message indicated the cause; no retry was triggered automatically.
- **Failure mode:** Silent parallel-count cap (or similar harness constraint). Because the cancellations weren't announced as an error, the agent had to notice via output inspection and resubmit the cancelled calls sequentially. One extra tool round-trip before the audit could complete.
- **Evidence:** Session telemetry `audit.jsonl` at 22:47:43.058Z (first batch) shows the cycle-check grep landing; at 22:47:44.975Z the top-level-imports grep launched; then in the next message at 22:48:43.121Z the re-issued version of the cancelled call landed. No explicit cancellation event in the telemetry (only in the tool output).
- **How to avoid:** Keep the opening parallel batch at ≤3 bash calls + ≤3 reads. If more is needed, issue a second batch in the immediately following message. For critical context-gathering (path discovery, cycle-check), prefer sequential or small-parallel shape over a single mega-batch — the time cost of 2-3 smaller batches is dwarfed by the recovery cost of one cancelled call. (This does NOT apply to trivially-parallel work like file reads — those rarely cancel. The constraint appears to be bash-specific.)

### 3. Temptation to bundle cve_matcher into the attack_surface commit

- **What was done:** After clamav (commit `8f9d261`) and attack_surface (commit `4bd491b`) both passed Rule #11 smoke cleanly, the mechanical nature of the remaining cve_matcher work suggested: "just fold L251/L481 into the attack_surface commit and save the second commit overhead."
- **Failure mode:** Would have violated Rule #25 (one commit per independently-verifiable sub-task). The 3 files share the same refactor SHAPE but are independently revertable refactors — a regression in any ONE should not require reverting the other 2. `git bisect` clarity also requires per-file commits.
- **Evidence:** The temptation was felt but not acted on — commit `9a26c1a` for cve_matcher shipped separately. Historical evidence: Rule #25 was codified in CLAUDE.md at session 435cb5c2 after a bundled-sub-task commit caused painful bisect work; every subsequent P3 session has held to per-file commits. This session's 3-file chain continued the precedent.
- **How to avoid:** Cite Rule #25 in the self-check at the moment the temptation arises. The rule is not "one commit per file no matter what" — it's "one commit per independently-verifiable sub-task." For P3 carve-outs, the FILE is the unit of verification (each has its own Rule #11 smoke + identity check + Rule #30 audit). Even if 3 files' diffs are all `+2 -2`, they're 3 sub-tasks. The cost of an extra commit is negligible; the cost of an undoable bundled revert is large.

### 4. (Near-miss) Edits to cve_matcher's Tier-1 try/except could have mis-classified the failure mode

- **What was done:** cve_matcher L251 `from app.services.cpe_dictionary_service import CpeDictionaryService` lives INSIDE a `try/except Exception` block that wraps the import + instantiation + `await svc.ensure_loaded()`. An impatient promotion could have: (a) kept the try/except unchanged (still wrapping a now-gone import statement — harmless but misleading), (b) removed the try/except entirely (dangerous — the `await ensure_loaded()` can fail on Redis/network issues), or (c) mis-described the semantics in the commit message.
- **Failure mode:** Option (b) would have broken Tier 1 fail-soft — any Redis outage would propagate as an unhandled exception up the Tier cascade, potentially crashing the full cve_match pipeline. Option (a) is cosmetic but reduces code clarity. Option (c) creates a documentation drift that future sessions might act on incorrectly.
- **Evidence:** The session read the full try/except block including lines 248-263 BEFORE editing, classified the except as "network-bound fail-soft for ensure_loaded()" (not "import-time fail-soft"), and executed option (d): remove only the import line; leave the except wrapping `svc = CpeDictionaryService(); await svc.ensure_loaded()`. Commit `9a26c1a` documents this explicitly in the "Fail-soft semantics preserved" paragraph.
- **How to avoid:** For every function-body import inside try/except, READ THE ENTIRE TRY BLOCK before deciding the edit shape. Classify the except's purpose: import-time fail-soft, call-time fail-soft, or both. If the target module's top-level is reliable (no fragile deps) AND the except still protects a runtime call → option (d) is correct. Document the classification in the commit message so future sessions reading the diff understand WHY the try/except shape looks the way it does post-promotion.

## Quality Rule Candidates

None. All patterns from this session are procedural (session-shape, audit-sequence discipline) rather than code-level regexes. Existing harness rules already cover the enforceable patterns (`auto-pytest-mock-patch-androguard-at-service`, `auto-fleet-worktree-requires-worktree-add`, `auto-frontend-rebuild-not-restart`, etc.). A new rule would be vague or overlap with existing coverage — filing none per the /learn quality gate ("never write a quality rule with confidence < medium").
