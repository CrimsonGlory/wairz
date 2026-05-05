# Anti-patterns: Audit-2026-05-04 Intake Execution Sweep (Wave 1 + Wave 2)

> Extracted: 2026-05-05
> Campaign: `.planning/campaigns/completed/audit-2026-05-04.md` (intake-execution phase)
> Commit range: `1ed34a7..b7250c7` (14 commits)

## Failed Patterns

### 1. Bash heredoc inside YAML run-block (initial parse-step rewrite)
- **What was done:** First draft of the firmware-scan parse-step used `python3 - <<EOF ... EOF` heredocs nested inside a YAML `run: |` block scalar. Each python invocation read OUTFILE/FORMAT from environment via heredoc body.
- **Failure mode:** YAML's `|` block strips a CONSTANT amount of leading whitespace based on the first non-whitespace line. The `EOF` token MUST appear unindented relative to the heredoc-opening line — but YAML couldn't preserve that exact indentation because the `EOF` line had to be indented to remain valid YAML.
- **Evidence:** First-pass yaml.safe_load passed (YAML is valid), but rendering the run-script showed the heredoc content was misaligned — Python would have raised IndentationError at runtime.
- **How to avoid:** Use `out=$(python3 -c '...')` with single-quoted python source. Pass shell vars to python via `env:` block on the step, NOT via heredoc interpolation. Single-quote python preserves indentation cleanly because no shell expansion happens inside it.

### 2. Process substitution `< <(...)` for python output capture under `set -e`
- **What was done:** First draft of the parse-step used `read CRITICAL HIGH TOTAL < <(python3 -c '...')` to capture three space-separated counts.
- **Failure mode:** Process substitution disconnects the inner command's exit code from the outer shell. With `set -e`, a python failure inside `<()` does NOT abort the parent script reliably across all bash versions — `read` returns non-zero (no input), but whether `set -e` triggers depends on the bash version and whether `read` is in a compound command. Sandbox test confirmed: malformed JSON produced a python traceback to stderr but the outer script CONTINUED past the failure.
- **Evidence:** Sandbox test in `/tmp/test-parse-step.sh` showed "malformed OK: read failed (no values to assign)" — read returned non-zero but the script proceeded. Rule #35a in action: "verification artefacts can lie."
- **How to avoid:** Prefer `out=$(python3 -c '...')` then `read -r X Y Z <<< "$out"`. The `$()` form propagates the inner exit code under `set -e` reliably across bash versions. Process substitution for output capture is a Rule-#17-shape silent-success risk.

### 3. Slowapi `request: Request` parameter colliding with existing pydantic body params
- **What was done:** Adding `@limiter.limit(TIER_B_DOCKER)` to `start_emulation` and `start_system_emulation` first attempted to add `request: Request` as a positional arg, but BOTH endpoints already had `request: EmulationStartRequest` (pydantic body model).
- **Failure mode:** Two parameters can't share the name `request`. slowapi inspects the function signature looking for a `Request` type, but FastAPI binds body params by NAME-irrelevant type matching, so the `request: EmulationStartRequest` was masking slowapi's lookup.
- **Evidence:** First import smoke after `docker cp` would have raised on conflicting `request` names; caught at edit time before commit.
- **How to avoid:** Rename the body param to `body: <BodyType>` when adding slowapi rate limits to handlers that already have a body. FastAPI binds bodies by type annotation, not parameter name — no API contract change. Update every `request.<field>` reference inside the handler to `body.<field>` (8 sites in /start, 3 sites in /system).

### 4. Initial Rule #24 canary attempt with pipe-induced exit obfuscation (Rule #35a sub-case)
- **What was done:** The first attempt to verify the typecheck Rule-#17 canary was `npx tsc -b --force 2>&1 | tail -5; echo "exit=$?"`.
- **Failure mode:** `$?` after a pipeline reflects the LAST command (`tail`), not the first (`tsc`). Output showed "tail" exit=0 even when tsc actually failed with exit=2. Rule #35a generalisation in practice: pipes implicitly subshell; bash does NOT enable `set -o pipefail` by default.
- **Evidence:** Caught immediately by reading the canary output — type error printed AND `exit=0`, which is impossible if tsc actually exited non-zero. Rule #35a (CLAUDE.md, this codebase) explicitly documents this exact case.
- **How to avoid:** When capturing exit codes, run the command directly without a pipe (`cmd; ec=$?`). If you must pipe for output, either `set -o pipefail` explicitly OR use `${PIPESTATUS[0]}` after the pipeline OR split into `cmd > /tmp/out; ec=$?; tail -5 /tmp/out`. CLAUDE.md Rule #35a (a) is the canonical reference.

### 5. Initial assumption that intake's claimed scope is exhaustive
- **What was done:** Wave-2 #7 (Finding.confidence bypass paths) intake listed 5 sites. First-pass plan was to fix those 5 and ship.
- **Failure mode:** The structural test surfaced 4 ADDITIONAL bypass paths the audit missed. If I'd shipped only the 5 listed, the structural test would have failed in CI on the next push and the discipline would have been broken from day one.
- **Evidence:** Test failure output:
  - `app/routers/attack_surface.py:146` — missing confidence
  - `app/services/import_service.py:295` — missing confidence + firmware_id
  - `app/ai/tools/attack_surface.py:92` — missing confidence
  - `app/services/hardware_firmware/graph.py:336` — missing confidence
- **How to avoid:** When the intake's scope is "every X must Y" or "all sites that do Z", treat the intake's count as a LOWER BOUND, not a definitive list. Run the structural check (regex / AST grep) FIRST and reconcile any divergence before designing the fix. Rule #31 width-canary applied to intake-scope claims, not just grep counts.

### 6. Initial autogenerate sanity migration assumed it would be empty
- **What was done:** Wave-1 #6 (models __init__.py exports) intake's acceptance criterion said: "Run autogenerate; verify it produces an EMPTY migration. If it produces ops, investigate."
- **Failure mode:** It DID produce ops. The intake's "empty migration" expectation was based on the assumption that the only drift was the import gap. The actual drift was wider: 4 timestamp-type columns + ~10 index/unique-constraint sites. Without the diversion, my closing commit would have either (a) silently shipped the unrelated drift fixes or (b) shipped the closure without acknowledging the surfaced drift.
- **Evidence:** Auto-generated `b503093bcead` migration listed `op.alter_column('hardware_firmware_blobs', 'created_at', ...)`, `op.drop_index('ix_attack_surface_firmware_id', ...)`, etc. — operations entirely unrelated to the imports being fixed.
- **How to avoid:** When an intake's acceptance criterion says "verify X produces empty/clean output", BUILD IN a follow-up-intake path. If the output isn't clean, file the discovered drift as a new intake (`audit-models-orm-vs-db-schema-drift-2026-05-05.md`), delete the auto-generated artifact, ship the original closure on its own scope. Don't bundle the surfaced drift into the closing commit.

### 7. Citadel hook silently blocked .env.example edits with no actionable suggestion
- **What was done:** Attempted to read `.env.example` to close Wave-2 #17 (.env.example/config.py drift).
- **Failure mode:** Hook returned "Blocked — secrets access" and the autopilot couldn't proceed. The hook is correct (can't distinguish .env from .env.example by filename pattern alone), but offered no alternative path within the session.
- **Evidence:** Two consecutive Read + Bash attempts both blocked.
- **How to avoid:** When a Citadel hook blocks a clearly-intended-public file (`.env.example`, `*.example`, `*.template`), either (a) propose a hook regex update to whitelist the example variant family, or (b) document the blocker in the intake and mark `status: blocked`. This was Path B; the hook update would be Path A and is a separate scope. The intake's "BLOCKED" annotation is now discoverable for the next operator session.

## Recurring Lesson

Five of these seven anti-patterns are instances of CLAUDE.md Rule #35a's
generalised lesson: **verification artefacts can lie**. The verification
mechanism (pipe exit code, process substitution exit, autogenerate empty
migration, intake's claimed scope, structural assumption that hooks
gracefully escape) reported "looks good" while the underlying contract
was broken. The discipline is: when a verification mechanism reports
success, ASK WHICH CONTRACT IT ACTUALLY CHECKED — and probe with a
deliberate canary if the contract is weaker than assumed.

The structural-test pattern (Pattern #4 in the companion file) is a
durable instantiation of this discipline: instead of trusting "all
sites updated" or "the intake's count is correct", write the test that
would fail if a single site were missed.
