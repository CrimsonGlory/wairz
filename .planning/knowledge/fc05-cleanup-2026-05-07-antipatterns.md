# Anti-patterns: post-F-C-05 cleanup session 2026-05-07

> Extracted: 2026-05-07
> Campaign: `.planning/fleet/session-post-fc05-cleanup-2026-05-07.md` + 6 commits f2f0906..5d9a404

## Failed Patterns

### 1. Pipe contamination of exit codes (Rule #35a, second variant)
- **What was done:** Captured the result of `alembic check` via `cmd 2>&1 | tail -5; echo "exit=$?"`. The `$?` reports `tail`'s exit, not `alembic check`'s.
- **Failure mode:** alembic check returned exit 255 (drift detected) but the prompt printed `exit=0` because it captured `tail`'s exit. Misled into thinking the test had passed when it had failed.
- **Evidence:** First few `alembic check` invocations this session reported `exit=0` despite stderr showing `FAILED:` messages. Re-run with `cmd > /tmp/x.txt 2>&1; ec=$?; cat /tmp/x.txt; echo "ec=$ec"` showed real_ec=255.
- **How to avoid:** Always redirect-then-cat AND capture exit code BEFORE any pipe (`set -o pipefail` works too, but the redirect-then-cat shape is what Rule #35a already documents). Generalises Rule #35a's "no piped pytest" to any exit-code-bearing command.

### 2. Rule #20 class-shape exception bites under no-bind-mount
- **Description:** Edited `backend/app/models/device_dump.py` to drop `index=True`. Ran `alembic check` — still showed drift. The backend container has no bind mount on `/app/app/`, so the running container kept reading the OLD `index=True` from its baked-in COPY layer.
- **Failure mode:** False-positive drift signal; ~10 minutes spent diagnosing what looked like a phantom index in metadata.
- **Evidence:** `docker compose config --format json | python3 -c "..."` showed no bind mount on app/. `md5sum` host-vs-container disagreed until rebuild. After rebuild, `alembic check` returned 0.
- **How to avoid:** When editing under `backend/app/models/`, check first whether the running container has a bind mount on `app/`. If not, full Rule #8 rebuild required (NOT just `docker compose restart`). Mechanical detection: `docker compose config --format json | grep -A1 '"target".*"/app/app"'`. If empty, plan for a full rebuild before any test that depends on the model state.

### 3. Rebuild strips dev test infrastructure
- **What was done:** Ran `docker compose up -d --build backend worker` after a model edit. Re-ran pytest — failed with `/app/.venv/bin/pytest: no such file or directory` AND `tests/` not present in container.
- **Failure mode:** The production image excludes `tests/` via `backend/.dockerignore` (commit b9f438f) AND strips dev deps via `uv sync --no-dev` in the Dockerfile. Every Rule #8 rebuild breaks the local test workflow until the contributor manually restores both.
- **Evidence:** This session's troubleshooting sequence at the autogen-empty test stage. Required `docker compose exec -T -w /app backend uv sync` + `docker cp backend/tests wairz-backend-1:/app/tests/` to recover.
- **How to avoid:** When you do a Rule #8 rebuild, immediately run the CI-workflow-equivalent post-rebuild restore: `uv sync` (no `--no-dev`) + `docker cp backend/tests wairz-backend-1:/app/tests`. Captured as Pattern #6 above. Future improvement candidate (deferred): add a `backend/scripts/post-rebuild-test-setup.sh` wrapper that automates this.

### 4. Intake premise can be wrong; verify before acting
- **What was done:** Stream γ followed the intake's "Sourcing options" priority list, starting with option 4: "OpenQNX archives — `vocho/openqnx` ships a small selftest corpus under `trunk/utils/m/mkxfs/dumpifs/test/`."
- **Failure mode:** That directory does not exist in `vocho/openqnx`. The intake author wrote the suggestion from memory or a third-hand reference, not verified inspection.
- **Evidence:** Stream γ's findings note in `.planning/intake/qnx-ifs-test-corpus-2026-05-07.md` (post-update at commit e96e6aa).
- **How to avoid:** When following a sourcing/path suggestion in an intake, verify the path exists with WebFetch FIRST before any download/legal-review work. Generalises Rule #19 "evidence-first" to intake-suggested paths: the intake describes intent, the upstream describes reality.

### 5. Sub-agent prompt without explicit "no `git add -A`" wording would have swept (Rule #23)
- **Description:** Three-agent Wave 1 ran without worktrees on the same checkout. If any of the three had used `git add -A` or `git add .`, they would have committed unstaged changes from sibling streams.
- **Failure mode (counterfactual — did NOT occur):** Each agent's commit would contain its own changes plus whatever the other two streams had unstaged. Cross-stream sweep, exactly the failure mode Rule #23 anti-pattern #1 documented in `wairz-intake-sweep-wave12-antipatterns.md`.
- **Evidence:** All three sub-agent prompts (this session, transcript) explicitly said `git add <specific-paths>` and `Do NOT use git add -A`. All three commits are clean per `git show <sha> --stat`.
- **How to avoid:** When dispatching parallel agents WITHOUT worktree isolation, the "no `git add -A`" wording is non-negotiable. It's the ONE phrase keeping the wave clean. Worth a Fleet-skill template enhancement.

### 6. Backend pytest needs `-w /app -e PYTHONPATH=/app`
- **What was done:** Ran `docker compose exec -T backend /app/.venv/bin/alembic check`. Failed with `ModuleNotFoundError: No module named 'app'`.
- **Failure mode:** WORKDIR is /app but Python's default sys.path doesn't include CWD when invoked via absolute path. Without `PYTHONPATH=/app`, `from app.database import Base` (in `alembic/env.py`) fails.
- **Evidence:** This session's first attempt at `alembic check` post-restart produced the ModuleNotFoundError. Adding `-w /app -e PYTHONPATH=/app` fixed it.
- **How to avoid:** ANY `docker compose exec` that targets `app.*` imports needs `-w /app -e PYTHONPATH=/app`. Same shape as the F-C-05 migration application earlier in the same session. Codify in the post-rebuild restore wrapper script.

### 7. (Counterfactual) Treating γ's external blocker as a failure
- **What was done:** Stream γ couldn't source a license-clean QNX IFS fixture. The intake stayed unresolved.
- **Failure mode (counterfactual):** Treating "couldn't ship the deliverable" as a stream failure would have led to either committing an unlicensed blob OR scope-creeping into a 2-hour QNX SDP install.
- **Evidence:** Stream γ's report explicitly framed the outcome as "blocked on license, intake updated with concrete next-action and 8-path attempt log" — a high-quality "documented blocker" outcome, not a failure.
- **How to avoid:** Sub-agent prompts should explicitly call out "a high-quality 'I couldn't source this, here's why and here's what to try next' outcome is acceptable." This session's γ prompt did. Pattern is replicable.
