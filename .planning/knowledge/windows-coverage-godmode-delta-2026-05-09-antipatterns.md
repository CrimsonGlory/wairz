# Anti-Patterns: Windows-Coverage God-Mode δ (2026-05-09)

> Extracted: 2026-05-09
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase δ section)
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-delta-2026-05-09.md`
> Branch: `feat/windows-phase-delta-2026-05-09`
> Commits in scope: `1fbdaab..1f09179` (δ.1 through δ.9)
> Status: 9 sub-tasks completed; campaign Phase δ CLOSED (Phase ε deferred per PRD)

This is an incremental extraction layered on top of the previous
α/β/γ-X antipatterns files. Patterns already captured there are not
re-stated; this file captures only the δ-delta failure modes.

## Anti-Patterns

### 1. Alembic revision-ID rotating-hex pattern collides with orphan migrations

- **What was done:** Authored δ.3's revision ID as `d2e3f4a5b6c7`
  following the rotating-hex pattern from γ (c6 → c7 → c8 → c9 → d0
  → d1 → d2 → d3 ...). The pattern collided with an orphan migration
  `d2e3f4a5b6c7_add_upload_stage_to_firmware.py` from a prior unmerged
  branch sitting in the alembic versions directory. After renaming to
  `d3e4f5a6b7c8`, hit a SECOND collision with
  `d3e4f5a6b7c8_add_kernel_path_to_firmware.py`.
- **Failure mode:** Alembic refused with "Revision is present more
  than once" + "Cycle is detected". The chain failed to load AT ALL —
  not just the new migration; the entire alembic head resolution broke
  until the collision was resolved.
- **Evidence:** δ.3 first apply attempt — `alembic upgrade head`
  failed with the cycle error. Second attempt with `d3e4f5a6b7c8` ALSO
  failed. Third attempt with `d3a4b5c6d7e8` (validated against the
  full 57-revision-ID set) succeeded.
- **How to avoid:** Before authoring a migration, run a one-liner
  to check the candidate revision ID against the full versions tree:
  ```sh
  cd backend && uv run python -c "
  import re, glob
  ids = set()
  for p in glob.glob('alembic/versions/*.py'):
      txt = open(p).read()
      m = re.search(r'(?m)^revision[: \w]*=\s*[\"\\']?([a-f0-9]+)', txt)
      if m: ids.add(m.group(1))
  cand = 'd3a4b5c6d7e8'
  print('TAKEN' if cand in ids else 'FREE', cand, '/', len(ids), 'total')
  "
  ```
  Cost: 1 second; benefit: eliminates the collision retry loop.
  **Promotable to a `.mex/patterns/add-alembic-migration.md` recipe
  step.** The wairz repo has 57 IDs in the versions tree (more than
  the 35-ish in the active chain) due to orphaned migrations from
  unmerged branches — any rotating-hex pattern is statistically
  likely to collide.

### 2. Migrator image NOT rebuilt alongside backend+worker (Rule #8 gap)

- **What was done:** Ran `docker compose build --pull backend worker`
  for the δ.9 cut-over, then `docker compose up -d backend worker`
  expecting the new images to take effect. The migrator init container
  started first (compose dependency) using its OLD image (from before
  the δ migrations were authored), couldn't find revision
  `d5a6b7c8d9e0` in its versions tree, and exited 255. Backend +
  worker stayed in `Stopped` state because of the failed init
  dependency.
- **Failure mode:** "Service migrator didn't complete successfully:
  exit 255" + alembic log "Can't locate revision identified by
  'd5a6b7c8d9e0'". Backend + worker NEVER STARTED — the user-facing
  effect was a cluster-down state until the migrator image was rebuilt
  too.
- **Evidence:** δ.9 first up-d attempt — migrator exit 255 + backend
  + worker not running. Second attempt after `docker compose build
  migrator` — clean.
- **How to avoid:** **Extend CLAUDE.md Rule #8 wording** from
  "Rebuild worker whenever you rebuild backend" to "Rebuild worker
  AND migrator whenever you rebuild backend". All three share the
  Dockerfile + alembic versions tree; rebuilding only two leaves the
  third stale. Mechanical mitigation: when running
  `docker compose build backend`, always include `worker migrator` in
  the same command. **Rule-of-One within δ; codify pre-emptively in
  the rule wording rather than waiting for a recurrence in ε.**

### 3. Background runner tested via outer wrapper (DNS resolution failure)

- **What was done:** First draft of
  `test_tier1_synthetic_update_diff_persists_dll_rows` called
  `await run_windows_update_diff_background(fw.id)` directly. The
  outer runner uses `async_session_factory()` which resolves
  `DATABASE_URL` (containing hostname `postgres`) — host pytest can't
  resolve it, only the Docker network can.
- **Failure mode:** `socket.gaierror: [Errno -2] Name or service not
  known`. Test failed loudly at runner-execution time.
- **Evidence:** δ.9 canary first run — 4 passed + 2 skipped + 1 failed
  with the gaierror. Refactored to call inner `_do_diff_run(db, fw.id)`
  with the live test db; canary then 5 passed + 2 skipped.
- **How to avoid:** When authoring a Rule #35b live canary against a
  service that uses `async_session_factory()`, prefer the INNER
  runner (which accepts a `db` param) over the OUTER state-machine
  wrapper. If no inner runner exists, the service was structured for
  production dispatch only — refactor to expose one (single-line
  addition; no caller changes). γ.4 `auto_walk_firmware(fw.id, db)`
  precedent. Mechanical heuristic: **if the runner takes only
  `firmware_id`, factor out an inner function that takes `(db,
  firmware_id)`.** Outer wrapper is exercised in the running
  container's runtime smoke; inner runner is exercised in the host
  pytest sweep.

### 4. Edit tool Read-first guardrail re-discovered (Rule-of-Three)

- **What was done:** Twice during the session (Dockerfile insertion
  for INCLUDE_DOTNET=1 + `frontend/src/types/index.ts` FindingSource
  extension), invoked the Edit tool against a file that hadn't been
  Read in the conversation turn. Edit failed with `File has not been
  read yet. Read it first before writing to it.`
- **Failure mode:** Edit tool guardrail returned the error
  immediately; no edit applied. ~10 seconds per occurrence.
- **Evidence:** δ.4 + δ.8 — two Edit-tool refusals, each resolved by
  Read-then-Edit on retry. γ.9 antipattern #5 documented this with 2
  catches. δ adds 2 more catches → **Rule-of-Three (γ + δ) confirms
  the pattern's persistence**; instinct still calibrating.
- **How to avoid:** Internalize the rule "**Read before any first
  Edit on a file in a session — Bash `cat` output does NOT satisfy
  the Edit-tool's Read-first contract.**" Cheap mitigation: if you're
  about to Edit a file you haven't Read this turn, prefix the Edit
  with a Read. Cost: ~5 seconds per file; benefit: eliminates the
  refusal-and-retry loop. Not a harness rule (the Edit tool itself is
  the enforcement).

### 5. CWD drift after `cd backend && uv run` (caught mid-flow)

- **What was done:** Earlier in the session ran a Bash invocation
  beginning with `cd /home/dustin/code/wairz/backend && uv run
  python -c "..."`. The Bash tool's cwd persists across calls; later
  pytest invocations executed from `/backend` (correct for relative
  test paths) but a future `git status backend/...` would have
  resolved against `/backend/backend/...`.
- **Failure mode:** **No actual incident** — the antipattern was
  caught via self-inspection (`pwd` returned the drifted directory)
  and corrected with `cd /home/dustin/code/wairz` before any git
  invocation could trip on it. Net cost: ~30 seconds of one cwd reset.
- **Evidence:** Session bash log — one `cd /home/dustin/code/wairz`
  command issued mid-session after the drift detection; subsequent
  git invocations all used `git -C /home/dustin/code/wairz` form.
- **How to avoid:** **Already codified in CLAUDE.md Rule #38** —
  prefer `git -C <repo>` over `cd <repo> && git ...`; use subshell
  `(cd backend && uv run ...)` form for cwd-sensitive tools so the
  cd is scoped to the parens. δ.9 validates the rule rather than
  violating it (the discipline catches the drift). Continued
  observance keeps the streak (β.14 + γ + δ all clean).

### 6. Frontend container exited during multi-service compose recreate

- **What was done:** When the failing migrator caused
  `docker compose up -d backend worker` to abort partway, the frontend
  container (which had been running on a prior image) was either taken
  down by compose's dependency-graph cascade or stopped responding
  during the failure. After fixing the migrator and re-running
  `up -d frontend`, it started fresh on the new image.
- **Failure mode:** `docker compose ps` showed no frontend service in
  the running list. ~10 seconds to recover.
- **Evidence:** δ.9 cut-over — first `docker compose ps` post-migrator-
  failure showed 7 services running; frontend was missing. One
  `docker compose up -d frontend` restored it.
- **How to avoid:** After ANY `docker compose` error during multi-
  service recreate (especially when an init container fails), run
  `docker compose ps` to confirm all expected services are running
  before declaring the cut-over complete. Don't assume "compose up
  succeeded for service X" means "service Y stayed running" — the
  dependency graph can cascade the failure.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (alembic revision-ID collision)** is novel within
  this codebase as a documented incident (γ never collided because the
  c6→c9 sequence happened to miss orphans; δ's d0→d5 sequence hit two
  collisions). Mitigation is a `.mex/patterns/add-alembic-migration.md`
  recipe step (postmortem rec #7) — documentation-only, not a harness
  rule. Promotable to a CLAUDE.md rule if it recurs in ε.
- **Anti-pattern #2 (migrator stale image)** is novel within this
  codebase as a documented incident. Mitigation is a CLAUDE.md Rule
  #8 wording extension (postmortem rec #2) — pre-emptive update
  rather than waiting for a recurrence.
- **Anti-pattern #3 (outer-wrapper-vs-inner-runner)** is novel as an
  explicit antipattern; γ.4's `auto_walk_firmware` was the implicit
  precedent. The MITIGATION (inner-runner discipline) is durable
  enough to PROMOTE to a Pattern (#2 in patterns file) rather than
  just tracked here as a one-off. The antipattern shape is the
  authoring shortcut that reaches for the outer wrapper first.
- **Anti-pattern #4 (Edit tool Read-first)** is Rule-of-Three now
  (γ.9 + δ × 2). Tool-contract reminder; not a harness rule.
- **Anti-pattern #5 (CWD drift after cd backend &&)** is documented
  in CLAUDE.md Rule #38; γ.9 reported clean discipline. δ caught one
  drift incident MID-FLOW + corrected before any git command tripped
  — net 0 incidents in commits. Validates the rule.
- **Anti-pattern #6 (frontend container exited during compose
  recreate)** is novel within this codebase. Mitigation is a
  procedural reminder ("`docker compose ps` after any compose
  failure"); not a harness rule. Promotable if it recurs.

All six anti-patterns share two common shapes:

1. **"Authoring shortcut that doesn't survive the long tail"** —
   #1 (rotating-hex picks the obvious next ID, hits an orphan), #3
   (outer wrapper is the obvious entry point but doesn't take a db).
   Mitigation: a 1-second probe before committing to the shortcut.

2. **"Rebuild discipline incomplete"** — #2 (worker rebuilt but
   migrator wasn't), #6 (frontend silently exited during failed
   recreate). Mitigation: extend Rule #8 wording + run `docker
   compose ps` after every `up -d`.

This is the test-authoring + cut-over counterpart to γ.9's "assuming
a contract without verifying it in the current scope" theme — δ
shifts the same lesson to **bulk-build environments** (alembic
versions tree, docker compose dependency graph) where the contract
is the broader system state, not just one tool's API.
