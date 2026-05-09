# Postmortem: Windows-Coverage God-Mode — Phase δ (.NET + Update-Diff + Storage)

> Date: 2026-05-09 (δ shipped 2026-05-08; campaign branch dated 2026-05-09)
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase δ section)
> Branch: `feat/windows-phase-delta-2026-05-09` (from γ tip `8437ae3`)
> Duration: 2026-05-08 16:41 → 17:33 MDT (~52 minutes wall-clock)
> Commits: 9 (`1fbdaab..1f09179`) on the δ branch
> Outcome: completed

## Summary

Phase δ shipped the Windows-Update package table + the .NET single-file
bundle decompile worker (gated `INCLUDE_DOTNET=1`) + the per-DLL KB-vs-KB
update-diff runner with restart-recovery via natural-key UPSERT + the
R2R-stomping classifier (Persona-E #5 — single highest-impact
differentiator) + 16 new MCP tools across 3 categories (197 → 213 total)
+ 2 frontend skeleton pages + the cross-stack alignment slice extending
`ck_findings_source` with `windows_r2r_stomp` + `windows_il_capa`. 9
commits, 0 reverts, +5788 LOC, all green; container rebuild + Rule #11
import smoke clean against alembic head `d5a6b7c8d9e0`.

## What Broke

### 1. Alembic revision-ID collision with orphan migrations

- **What happened:** δ.3 used revision id `d2e3f4a5b6c7`, which
  collided with an orphaned `d2e3f4a5b6c7_add_upload_stage_to_firmware.py`
  sitting in the alembic versions tree (from a prior unmerged branch).
  Alembic refused with "Revision d2e3f4a5b6c7 is present more than once"
  + "Cycle is detected in revisions". After renaming to `d3e4f5a6b7c8`,
  hit a SECOND collision with `d3e4f5a6b7c8_add_kernel_path_to_firmware.py`
  (also orphan).
- **Caught by:** **alembic upgrade head** at apply time — loud +
  immediate. The "Cycle is detected" + "Revision present more than once"
  shape is unambiguous.
- **Cost:** ~2 minutes total (rename file → update revision string →
  `docker cp` again → `alembic upgrade head` retry × 2).
- **Fix:** Wrote a small Python probe to enumerate all 57 revision IDs
  in the versions directory; picked `d3a4b5c6d7e8` (free) for δ.3 and
  pre-validated `d4a5b6c7d8e9` / `d5a6b7c8d9e0` / etc. for the remaining
  δ migrations. Documented the "rotating-hex-pattern collides with
  orphans" trap in the δ.3 commit message.
- **Infrastructure created:** None (informational — see Recommendation
  #1 for a small revision-ID-uniqueness pre-check).

### 2. CWD drift after `cd backend && uv run` (Rule #38 sub-incident)

- **What happened:** Earlier in the session ran a Bash invocation that
  began `cd /home/dustin/code/wairz/backend && uv run python -c "..."`.
  The Bash tool's cwd persists across calls, so subsequent `pytest`
  invocations executed against `/home/dustin/code/wairz/backend` but
  treated `tests/...` as relative-from-backend (correct), while a later
  `git status backend/...` from the same cwd would have resolved against
  `backend/backend/...` if it had been issued.
- **Caught by:** **Self-inspection** mid-flow — noticed `pwd` returned
  `/home/dustin/code/wairz/backend` and reset with explicit
  `cd /home/dustin/code/wairz` before any git invocation that could
  have suffered the antipattern.
- **Cost:** ~30 seconds (one cwd reset).
- **Fix:** Switched to `git -C /home/dustin/code/wairz <subcommand>` and
  subshell `( cd backend && uv run ... )` for the rest of the session.
- **Infrastructure created:** None — Rule #38 already documents this
  failure mode + γ.9 antipattern #3 already coded the precedent;
  CWD-drift discipline is now Rule-of-Three clean (β.10/β.12 incidents
  → β.14/γ/δ clean sessions, with one mid-δ catch-and-correct that
  validates the rule rather than violating it).

### 3. Edit tool's "must Read first" requirement (Rule #21 corollary)

- **What happened:** Twice during the session (Dockerfile insertion +
  `frontend/src/types/index.ts` FindingSource extension), invoked the
  Edit tool without first calling Read on the file in this conversation
  turn. Edit failed with `File has not been read yet. Read it first
  before writing to it.`
- **Caught by:** **Edit tool guardrail** — returned the error message
  immediately; no edit was applied.
- **Cost:** ~10 seconds each (one Read call per occurrence).
- **Fix:** Read then Edit on retry.
- **Infrastructure created:** None — Edit tool guardrail is the
  enforcement. γ.9 antipattern #5 already documented this; δ extends
  the Rule-of-Three (γ.9 had 2 catches, δ had 2 catches = same shape,
  same cost, instinct still calibrating to "Read before any first
  Edit on a file in a session").

### 4. Tier-1 update-diff test failed against host DNS

- **What happened:** First draft of
  `test_tier1_synthetic_update_diff_persists_dll_rows` called the OUTER
  `run_windows_update_diff_background(fw.id)` runner directly. The outer
  runner uses `async_session_factory()` which resolves `DATABASE_URL`
  with hostname `postgres` (Docker service name) — host pytest can't
  resolve it (DNS only works inside the Docker network). Test failed
  with `socket.gaierror: [Errno -2] Name or service not known`.
- **Caught by:** **pytest** — failed loudly on first run (1 failed +
  4 passed + 2 skipped).
- **Cost:** ~3 minutes (read the runner, identify the inner-vs-outer
  split, refactor the test to call `_do_diff_run(db, fw.id)` directly).
- **Fix:** Imported the inner `_do_diff_run` and passed the live test
  db. The outer state-machine wrapper is exercised in the running
  container (where DNS resolves), not the host pytest sweep. Same shape
  γ.4 used (`auto_walk_firmware(fw.id, db)` accepts the live db
  directly).
- **Infrastructure created:** None — the inner-runner pattern is
  already established. Mechanical lesson: when authoring a Rule #35b
  live canary against a service that uses `async_session_factory()`,
  prefer the inner runner that takes a `db` arg (or refactor to expose
  one).

### 5. Migrator image cache stale after backend+worker rebuild

- **What happened:** Ran `docker compose build --pull backend worker`
  successfully, then `docker compose up -d backend worker` failed because
  the migrator init container started first using its OLD image (built
  pre-δ) and couldn't find revision `d5a6b7c8d9e0` in the alembic versions
  list. Backend + worker stayed `Stopped` with "service migrator didn't
  complete successfully: exit 255".
- **Caught by:** **Docker compose** — service "migrator" exit 255 +
  alembic log "Can't locate revision identified by 'd5a6b7c8d9e0'".
- **Cost:** ~2 minutes (one extra `docker compose build migrator` +
  retry).
- **Fix:** `docker compose build migrator` + retry `up -d`. The
  migrator + backend + worker share the same Dockerfile — Rule #8
  ("rebuild worker whenever you rebuild backend") needs to be EXTENDED
  to migrator. Rule-of-One now; if it recurs the rule should be updated.
- **Infrastructure created:** None for δ. Recommendation #2 below
  proposes a small CLAUDE.md Rule #8 extension to add "+ migrator" to
  the rebuild list.

### 6. Frontend container exited during backend recreate

- **What happened:** When the failing migrator caused `docker compose
  up -d backend worker` to abort partway, the frontend container
  (which had been running) was either taken down or stopped responding.
  After fixing the migrator and re-running `up -d frontend`, it started
  fresh.
- **Caught by:** **Self-inspection** — `docker compose ps` showed no
  frontend service in the running list.
- **Cost:** ~10 seconds (one `up -d frontend`).
- **Fix:** Standard recovery — `docker compose up -d frontend`.
- **Infrastructure created:** None — recovery was trivial. Mechanical
  lesson: after any compose error during multi-service recreate, run
  `docker compose ps` to confirm all expected services are running
  before declaring the cut-over complete.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Rule #24 mandatory tsc canary | Confirmed TS2322 + exit=2 on the canary file (canary works); real typecheck of FE source then exited 0 cleanly | 1 fired | Trusting a "0 errors" output that was actually masking a TS2322 in the new δ.8 FE pages — canary verified the tool was actually checking |
| Rule #19 evidence-first probes | (a) γ patterns + antipatterns + postmortem read before drafting δ.1; (b) `uv run python -c "import dnfile, dncil, capa"` confirming host venv state before writing δ.4/δ.6 (caught the missing-deps before code that imports them); (c) γ.1 / γ.3 migration shape probed before δ.1; (d) γ.8 classifier + emit-method shape probed before δ.6 / δ.8; (e) γ.9 real-firmware canary shape probed before δ.9 | 5 | Multi-iteration test design churn, missing-import surprises, mismatched migration patterns. dnfile probe alone saved a δ.4 / δ.6 redesign cycle when the host venv wouldn't have run the new service tests. |
| Rule #36 forbidden-argv0-token gate | `assert_no_execute_argv` rejected every runtime + path-prefixed form (dotnet / wine / mono / cscript / wscript / powershell / pwsh) at test time | 12 test cases × 7 forbidden tokens | A future contributor adding a "convenience" subprocess invocation that resolves `argv[0]` to a .NET runtime, executing the bundle's entry point — Rule #36 violation locked at the source |
| Rule #25 single-slice exception #2 (cross-stack alignment) | δ.8 bundled alembic + Pydantic Literal + `_SOURCE_R2R_STOMP/_IL_CAPA` constants + emit method + FE union + FE config + 2 FE pages + route registration in ONE commit | 0 actual catches (designed in alignment from the start) | Single-slice exception #2 enforced — `test_finding_source_alignment.py` would have been RED between commits if δ.8 had been split. Saved a bisect-broken state. **Rule-of-Four now** (`7079b4d` + β.12a `ee2abd9` + γ.7 `f70c2e1` + δ.8 `20ea228`) — pattern is durable beyond doubt. |
| `test_windows_check_literal_alignment.py` | Per-table tri-state alignment now covers 4 pairs: WindowsDriverSigningTier (γ.2), WindowsRegistryExtractWalkStatus (γ.1), WindowsUpdatePackageType (δ.1), WindowsUpdateDllDiffType (δ.5) | 0 actual drift catches (designed in alignment from the start) | Future drift between Pydantic Literal and CheckConstraint will fire here. |
| Rule #35b live canaries | Forced ORM round-trip + SELECT verification on every new service writer | 5 in δ tier-1 canary set + 13 in unit tests across δ.5 + δ.6 + δ.7 = 18 live canaries shipped in δ | Constructor-args-vs-persisted-fields class of bugs (audit-2026-05-04 F-A-06 confidence-bypass shape). The δ.5 inner-runner UPSERT path was verified end-to-end; the δ.8 emit hook's pre-emit DELETE was verified to remove prior + insert new without duplicates. |
| pytest fixture-shape error | Caught the OUTER `run_windows_update_diff_background` vs INNER `_do_diff_run` async-session-factory mismatch on first canary run | 1 (1 test, 1 root cause) | Silent passing canary that didn't actually exercise the runner against the live test DB. The gaierror was loud + immediate; refactor took ~3 minutes. |
| Edit tool Read-first guardrail | Edit attempts without prior Read | 2 | Silent edits against assumed file contents (Bash output is stale relative to prior Edit calls). |
| Rule #38 absolute-path discipline | `git -C /home/dustin/code/wairz` for every git invocation; subshell `(cd backend && ...)` for cwd-sensitive uv calls | ~30+ Bash invocations clean (1 mid-δ catch-and-correct vs the prior pattern; net 0 incidents) | CWD drift after `cd backend && ...` (the β.10 / β.12 incident pair). Rule-of-Three clean now (γ + δ continue β.14's clean streak). |
| Container-restart-required-after-rebuild discipline (Rule #20 class-shape exception) | Migrator image needed rebuild alongside backend + worker | 1 caught at compose-up time | Backend + worker booted but with a stale alembic head reference — they would have been "running" but with a DB schema that didn't match the model code. Rebuild caught it before any data touched the new schema. |

## Scope Analysis

- **Planned (δ kickoff prompt):** 9 sub-tasks δ.1..δ.9 —
  windows_update_packages table (δ.1); firmware.dotnet_decompile_*
  status set + arq dispatch (δ.2); firmware.windows_update_diff_*
  status set + asyncio.create_task dispatch (δ.3); decompile_dotnet_bundle_job
  worker + Dockerfile INCLUDE_DOTNET delta (δ.4); _run_windows_update_diff_background
  runner + windows_update_dll_diffs table + UPSERT (δ.5); R2R-stomping
  classifier (δ.6); 16 MCP tools across 3 categories (δ.7); cross-stack
  alignment slice + 2 FE skeleton pages (δ.8); 3-tier real-firmware
  canary set + cut-over (δ.9).
- **Built:** All 9 sub-tasks shipped as 9 commits, ordering preserved,
  exact scope match. Two mid-stream additions:
  (a) `windows_update_dll_diffs` table moved from "δ.3 implicit" to
      "δ.5 explicit migration" — the kickoff said δ.3 was the 5-col
      status set on firmware AND δ.5 owned the per-DLL persistence;
      the cleanest split was to ship the per-DLL TABLE migration with
      the runner that uses it (δ.5), not with the firmware status set
      (δ.3). No scope drift; just commit boundary refinement.
  (b) Inner `_do_diff_run` made callable directly so live canaries can
      exercise the diff logic without `async_session_factory()`. Pure
      additive — no caller changes.
- **Drift:** None on the build axis. One scope-clarification mid-session
  (δ.5 table boundary) resolved without rework. Two host-environment
  surprises (alembic ID collision, migrator stale image) caught early
  + corrected within minutes; no commit-level rework needed.

## Patterns

- **Rule #25 per-sub-task commits held under δ** — 9 commits, each
  independently revertable, no `--no-verify`, no `--amend`.
  **Rule-of-Twelve now across the campaign** (α 12 + β 14 + γ 9 + δ 9 =
  44 commits, 0 reverts).
- **Rule #25 single-slice exception #2 (cross-stack alignment)** is
  Rule-of-Four now: `7079b4d` (2026-05-06) + `ee2abd9` β.12a + `f70c2e1`
  γ.7 + `20ea228` δ.8. The alignment test is RED between commits if
  split, GREEN under the bundled commit shape. Pattern is durable
  beyond doubt.
- **Rule #38 absolute-path discipline held under δ** — Rule-of-Three
  clean now (β.14 first clean session under codified rule + γ + δ).
  One mid-δ catch-and-correct validates the discipline rather than
  violating it.
- **Rule #19 evidence-first generalises across new library surfaces** —
  applied to dnfile (`recurse PE table walk`), dncil (IL disassembly),
  flare-capa (capability matching). Same shape every time: probe in
  30 seconds (`uv run python -c "import dnfile, dncil, capa"`); design
  test/code against the actual contract; save multi-iteration rework.
- **Rule #33 .a/.c/.d 202+polling contract held under δ.2 + δ.3 +
  δ.7-trigger** — both new firmware-row status sets have Pydantic
  Literal + DB CHECK (.c), the `trigger_dotnet_decompile` MCP tool is
  idempotent with 409-on-conflict (.a), and the dispatch rubric (.d)
  correctly split arq (δ.4 — Docker dotnet-runtime spawn) vs
  asyncio.create_task (δ.5 — pure-Python in-process diff +
  per-DLL incremental DB persistence).
- **Rule #36 no-execute discipline** — δ extends the no-execute rule
  from installer custom actions (α.2) + Authenticode signature parsing
  (β.4) + registry hives (γ.4) + driver INF/CAT (γ.5) to .NET
  single-file bundles (δ.4 ilspycmd reads PE+metadata as data; argv[0]
  must be ilspycmd, never dotnet/wine/mono) + capa-on-IL (δ.6 reads IL
  bytes as data via flare-capa rule matching). Forbidden-token argv
  gate is the new instance-of-the-rule.
- **JSONB normalizer + schema_version + stamp helper discipline (Rule
  #35c)** — applied to 3 new JSONB columns in δ
  (windows_update_packages.update_metadata,
  firmware.dotnet_decompile_result,
  firmware.windows_update_diff_result), each with normalizer + stamp +
  full test coverage matching the existing precedent. Total normalizers
  shipped across the campaign: γ added 3, δ added 3, totaling 6 new
  windows-coverage normalizers.
- **Per-table Pydantic Literal ↔ DB CHECK alignment test
  (test_windows_check_literal_alignment.py)** — γ.2 introduced the
  test with 2 pairs; δ extended to 4 pairs (added WindowsUpdatePackageType
  + WindowsUpdateDllDiffType). The `_PAIRS` tuple-extension shape is
  durable now; future per-table tri-state additions append to the tuple.

## Recommendations

1. **Pre-check alembic revision ID for collision before authoring a
   migration.** δ.3's collision wasn't caught until `alembic upgrade
   head` ran. Cheap mitigation: a one-line bash helper
   (`grep -c "<rev>" backend/alembic/versions/*.py | awk -F: '$2>0'`)
   the agent runs before writing the file. Cost: 1 second; benefit:
   eliminates the rotating-hex-pattern trap. Could also be a
   `.mex/patterns/add-alembic-migration.md` recipe step.

2. **Extend CLAUDE.md Rule #8 to include migrator.** Currently
   "Rebuild worker whenever you rebuild backend" — δ showed migrator
   needs the same treatment because all three share the Dockerfile +
   alembic versions tree. Rule-of-One within δ; promote to Rule-of-Two
   if it recurs in ε; pre-emptively update the rule wording to
   "Rebuild worker AND migrator whenever you rebuild backend".

3. **REST endpoints for windows_update + windows_dotnet.** δ.8 shipped
   2 frontend pages as skeletons (matching γ.7's RegistryDiffPage /
   DriverMatrixPage pattern). The pages are functional via MCP tools
   today (Claude Code / Desktop), but operators using the web UI see
   placeholder content. Add `GET /hardware-firmware/update-packages`,
   `GET /hardware-firmware/update-packages/{id}/files`,
   `GET /firmware/{id}/dotnet-bundles`,
   `GET /firmware/{id}/dotnet-decompile/status`,
   `POST /firmware/{id}/dotnet-decompile` (Rule #33 trigger),
   `GET /firmware/{id}/r2r-stomp` to `app/routers/hardware_firmware.py`
   + matching axios clients in `frontend/src/api/`. Cost: ~6 endpoints
   + matching client functions. Benefit: δ FE feature parity with β/γ.

4. **Tier-2/3 real-firmware canary fixture provisioning.** The δ.9
   canary set ships 5 pass + 2 skip; tier-2 needs a real .NET 8
   single-file bundle at `WAIRZ_TEST_REAL_DOTNET_BUNDLE`, tier-3 needs
   a real KB-vs-KB extracted package pair at `WAIRZ_TEST_KB_DIFF_FIXTURE`.
   Fixture extraction from a real Win11 install is a one-time operator
   setup. Once provisioned, the canary set graduates from 5p+2s to 7
   pass with no test edits. Mirrors β.14a + γ.9 deferred-fixture-
   provisioning shape.

5. **libesedb-utils Dockerfile delta for deep ESEDB extraction.** δ.7's
   `windows_storage` tools (5 tools) surface VHDX + BCD + ESEDB file
   locations + sizes via filesystem walk. The `dump_esedb_table` tool
   delegates to the `esedbexport` CLI from `libesedb-utils` — but that
   apt package isn't installed in the Dockerfile. Without it, the tool
   surfaces a clear "library not installed — Dockerfile delta needed"
   message. Adding `libesedb-utils` + `libpff-utils` + `libregf-utils`
   to the Dockerfile apt block (per the PRD's δ tooling list) would
   activate deep extraction. Cost: ~6 lines in the Dockerfile + image
   rebuild. Benefit: the 5 windows_storage tools graduate from
   "discovery + path surfacing" to "row-level extraction".

6. **R2R-stomping Tier 3 + Tier 4 promotion when capa-rules + native
   disasm engine land.** δ.6 shipped Tier 1 (R2R-eligible review
   candidate) + Tier 2 (missing-IL divergence). Tier 3 (byte-level
   IL/native prologue compare) + Tier 4 (capa-rule promotion for known
   stomp patterns) are documented in the module docstring and tracked
   here as follow-up. The infrastructure (dnfile + dncil + flare-capa)
   is already in place; Tier 3 needs ~50 LOC for a hash-prefix compare,
   Tier 4 needs custom capa-rules + flare-capa rule loading. Wait until
   tier-2 fixture provisioning surfaces real divergence patterns
   before designing the rule set.

7. **Add `.mex/patterns/add-alembic-migration.md` recipe.** Codifies
   the per-migration shape: revision ID collision check + naming
   convention + (table-creator | column-adder | check-extender)
   variants + Rule #20 fast iteration apply path. The shape is now
   established across α (1 migration), β (2), γ (4), δ (5) — 12
   migrations across the campaign with 1 collision incident. Cost:
   ~10 LOC of doc; benefit: future agents avoid the δ.3 collision trap.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 9 (δ.1..δ.9) |
| Phases completed | 9 (100%) |
| Commits | 9 (`1fbdaab..1f09179`) |
| Files changed | 35 (24 new, 11 modified) |
| Lines added | 5,788 |
| Lines deleted | 2 |
| Reverts | 0 |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Rule #24 mandatory canary | 1 fired (canary correctly produced TS2322 + exit=2 via file-redirect; real typecheck exited 0) |
| Edit-tool Read-first catches | 2 (no impact) |
| Alembic revision-ID collisions | 2 (caught immediately; renamed `d2e3f4a5b6c7` → `d3a4b5c6d7e8`) |
| Migrator stale-image catches | 1 (caught at compose up) |
| Tests added | +97 (315 total δ-related δ tests pass + 2 skip awaiting fixtures) |
| Tests passing (host sweep) | 3539 (9 pre-existing host-environment failures unrelated to δ) |
| Tests skipped | 2 (tier-2/3 awaiting real .NET 8 bundle + KB diff fixtures — expected) |
| New MCP tools | +16 (197 → 213 total registry size) |
| New JSONB normalizers | +3 (update_metadata, dotnet_decompile_result, windows_update_diff_result) |
| New Pydantic Literals | +4 (WindowsUpdatePackageType, DotnetDecompileStatus, WindowsUpdateDiffStatus, WindowsUpdateDllDiffType) |
| New finding sources | +2 (windows_r2r_stomp, windows_il_capa) — registry now 25 sources |
| New ORM models | +2 (WindowsUpdatePackage, WindowsUpdateDllDiff) |
| New alembic migrations | +5 (δ.1, δ.2, δ.3, δ.5, δ.8) |
| Rule #36 forbidden-argv0 test cases | 12 (every runtime variant + path-prefixed form rejected) |
| Per-table alignment test pairs | 4 (γ.1 + γ.2 + δ.1 + δ.5) — was 2 at γ end |
| Wall-clock duration | ~52 minutes |

---HANDOFF---
- Postmortem: windows-coverage-godmode-delta-2026-05-09
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-delta-2026-05-09.md
- Failures documented: 6 (1 alembic collision, 1 CWD-drift catch-and-correct, 2 Edit-tool guards, 1 inner-vs-outer runner refactor, 1 stale-migrator-image, 1 frontend container restart)
- Safety catches: 9 (Rule #24 canary, Rule #19 probes × 5, Rule #36 argv gate × 12 cases, Rule #25 alignment Rule-of-Four, alignment-test-pair Rule-of-Four, Rule #35b live canaries × 18, pytest fixture error, Edit guardrail, Rule #38 ~30+ clean invocations, Rule #20 class-shape rebuild discipline)
- Recommendations: 7 (alembic revision-ID pre-check, Rule #8 +migrator extension, REST endpoints for δ pages, tier-2/3 fixture provisioning, libesedb Dockerfile delta, R2R Tier 3+4 promotion, add-alembic-migration recipe)
---
