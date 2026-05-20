# Anti-patterns: SBOM/vuln-scan regression investigation Session 1 (2026-05-21)

> Extracted: 2026-05-21
> Postmortem: `.planning/postmortems/postmortem-sbom-vuln-scan-regression-session1-2026-05-21.md`

## Failed Patterns

### 1. Trusting operator-supplied pytest spec paths without verifying file existence
- **What was done:** The user's prompt spec'd `pytest tests/test_sbom_router.py tests/test_sbom_service.py tests/test_hardware_firmware_cve_matcher.py tests/test_hardware_firmware_router.py tests/test_finding_service_pe_emit.py`. Pytest was invoked verbatim against the backend container.
- **Failure mode:** `test_sbom_service.py` doesn't exist — it was absorbed by the Phase 5 SBOM split (Rule #27, session 7e8dd7c3 2026-04-22). Pytest exited 0 silently with "no tests ran" — exactly the Rule #17 / Rule #35a-pipe silent-success pattern. The bash background-task notification reported "exit code 0" reinforcing the false signal.
- **Evidence:** Opening baseline document `What Broke` notes. Pytest output: `ERROR: file or directory not found: tests/test_sbom_router.py / no tests ran in 0.00s`.
- **How to avoid:** Before running any operator-supplied pytest command, verify each spec'd file path exists. Either via `ls` or via a `pytest --collect-only` dry run that asserts collected-test count > 0. Cost ~1 sec; catches Rule #17 silent-exit instances.

### 2. `docker compose restart backend worker` after a sibling-service rebuild
- **What was done:** Initial `docker compose up -d --build backend worker migrator` succeeded; backend was healthy. `docker compose up -d --build frontend` then recreated backend as a dependency. Subsequent `docker compose restart backend worker` to pick up Fix #4 code change caused backend to crash on `api_key is required` (lifespan gate at `app/main.py:70`).
- **Failure mode:** Backend stuck in crash loop. Persisted through `down + up -d --build`. The .env file IS present (1557 bytes, 19 Apr) but env_file propagation appears to be lost. Hook blocks agent read of .env so root cause isolated to operator inspection.
- **Evidence:** Session 1 "What Broke" #1 in postmortem. Container logs show: `ERROR: api_key is required. Set API_KEY in .env or WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.`
- **How to avoid:** When a multi-fix sweep needs many backend restart cycles, prefer batching all code edits + ONE `docker compose up -d --build backend worker migrator` at end, rather than per-fix restarts. Saves both wall-clock AND env-propagation risk. Workaround for in-session validation: `docker run --rm --network=wairz_default -e WAIRZ_ALLOW_NO_AUTH=true --volume=...` ephemeral container.

### 3. Mock with too-narrow signature breaks when production signature widens
- **What was done:** Fix #8 added `name=` kwarg to `asyncio.create_task` via `_spawn_background_task(coro, name=name)`. The pre-existing test `TestVulnerabilityScanRule33::test_post_returns_202_and_queues_when_idle` mocked `asyncio.create_task` with `def fake_create_task(coro)` — no `name` kwarg.
- **Failure mode:** TypeError on test execution: `fake_create_task() got an unexpected keyword argument 'name'`. Caught at Session 1 close combined-sweep pytest run (1 failed, 205 passed).
- **Evidence:** Final pytest sweep error. Mock widened to `def fake_create_task(coro, *, name=None)` in commit `4b949d4`.
- **How to avoid:** When widening a function's public signature (adding a kwarg with a default), grep for every mock that patches the function AND verify each mock's shim accepts the new param. Rule #30 sibling discipline. Cost ~10 sec; carries zero risk. Even better: mock shims should default to `**kwargs`-tolerant signatures from the start, so future widening doesn't break them.

### 4. `if count <= 0: return` placed BEFORE walker fan-out
- **What was done:** `app/workers/unpack.py:106` (pre-fix) had `if count <= 0: return` after HW-blob detection, intended to skip the driver-firmware graph build for firmware without HW blobs. The early-return ALSO short-circuited 25+ walker safe-runners below it.
- **Failure mode:** Every firmware whose HW-blob detection returned zero (bare-metal MCU/DSP, intel_hex, .bin without known headers, generic ZIP archives) silently skipped 27 walker safe-runners. Scout C's live-DB probe documented cluster-wide zero walker output since 2026-05-12. Pre-fix age: pre-dates the 30-day investigation window.
- **Evidence:** Scout C report lines 16, 87-89, 138-140, 162-166. Postmortem "Summary" root-cause #1.
- **How to avoid:** Rule #16 principle — each downstream consumer should decide its own work via `get_detection_roots()`, NOT a central gate. When N downstream consumers all consume from the same upstream signal, the gate belongs in each consumer (cheap no-op when no work), not in the dispatch.

### 5. Naive gate removal without concurrency bound
- **What was done:** Scout C's recommendation: "Removing it (or restructuring to `if count > 0: build_driver_firmware_graph()` then ALWAYS proceed to walker fan-out)". A naive single-line fix.
- **Failure mode (avoided pre-shipping by W2-β):** §SC5-NEW-SBOM-θ — 5 firmware × 27 walkers = 135 simultaneous walker tasks against DB pool=40. ~95 walker tasks would timeout on `pool.acquire(timeout=10)`. Operator-visible: silently broken walkers; `*_walk_status` columns stay `idle` (Rule #39 .safe contract). Worse than the original failure mode.
- **Evidence:** W2-β §SC5-NEW-SBOM-θ — full attack walkthrough.
- **How to avoid:** When removing a defensive gate that was protective beyond its stated purpose (gate's removal would expose downstream work to a different failure mode), the replacement protection MUST ship in the SAME atomic commit. Rule #25 single-slice exception #2 — gate + concurrency bound + safe-runner discipline + tests in one bundle. Recipe shape: module-level `asyncio.Semaphore(N)` sized at ~10% of DB pool, wrapped around the fan-out loop via `async with`.

### 6. Bare `asyncio.create_task(coro)` for detached background work
- **What was done:** `routers/sbom.py:583` (pre-fix) called `asyncio.create_task(_run_vuln_scan_background(firmware.id, project_id, force_rescan))` without keeping any reference to the returned task.
- **Failure mode:** Python's asyncio scheduler keeps only a WEAK reference to tasks via `asyncio.all_tasks()`. Under memory pressure or GC, a task with no strong reference can be collected mid-run. The firmware row stays in `vuln_scan_status='running'` forever; frontend polls indefinitely; operator sees a stuck-spinner. Documented at https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task — "Important: Save a reference to the result of this function, to avoid a task disappearing mid-execution."
- **Evidence:** Scout D primary finding. Postmortem root-cause #5.
- **How to avoid:** Module-level `_BACKGROUND_TASKS: set[asyncio.Task] = set()` + helper `_spawn_background_task(coro, *, name=None)` that adds the new task to the set AND registers `add_done_callback(_BACKGROUND_TASKS.discard)` so the set self-trims on completion. Use the helper at every detached-task spawn site. Same pattern applies to **4 other bare `asyncio.create_task` sites surfaced by Rule #47 enumeration**: `routers/hardware_firmware.py:654`, `routers/hardware_firmware.py:750`, `routers/fuzzing.py:143`, `routers/emulation.py:165`. Each has the same GC-vanish risk; queued for Session 2 sweep.

### 7. State-machine column added without orphan reaper in same commit chain
- **What was done:** Two instances this campaign:
  (a) `upload_stage` state machine introduced in `847eae9` (2026-05-07) — Rule #33 sync→202+polling conversion of `POST /firmware/upload`. No orphan reaper companion shipped.
  (b) `bare_metal_audit_status` state machine introduced 2026-05-19 with the bare-metal walker (Rule #52 first instance). No orphan reaper companion shipped.
- **Failure mode:** Under any backend crash or restart mid-execution, the row stays in `IN ('detecting','extracting','analyzing')` for upload_stage or `IN ('queued','running')` for bare_metal_audit_status indefinitely. Scout C found one TMS320 row stuck `bare_metal_audit_status='queued'` for 6 DAYS. Operator's frontend renders a stuck-spinner; next attempt 409s on the dedup check.
- **Evidence:** Scout C lines 67-73, 134, 219-232. Scout B suspect commit #1 (`847eae9`). Postmortem root-causes #2 + #3.
- **How to avoid:** **Rule #51 .i companion-failure discipline:** every Rule #33 sync→202+polling conversion (or any new state-machine column with in-progress states) ships its orphan reaper in `main.py` lifespan in the SAME Rule #25 atomic commit chain. The reaper template lives at `main.py:120-242` (vuln_scan / cve_match / device_dump precedents). For state machines whose work runs detached via `asyncio.create_task` (susceptible to fresh-row-mid-startup races), add a `started_at < NOW() - INTERVAL '15 minutes'` grace clause per W2-β §SC5-NEW-SBOM-ε.

### 8. `.dockerignore` excludes `tests/` so production-image-based pytest can't work
- **What was done:** Operator-supplied spec said "docker compose exec -T -w /app backend uv run pytest tests/test_*.py" against the running backend container. Backend image is built from a Dockerfile that consumes `.dockerignore` — and `.dockerignore` excludes `tests/`.
- **Failure mode:** Production image has no `/app/tests/` directory. Pytest exits 0 with "no tests ran". Second-order Rule #17 instance (also failure pattern #1 above).
- **Evidence:** Opening baseline document — `.dockerignore` contents include `tests/` line with the comment "Tests are dev-only; not exercised by the production image."
- **How to avoid:** Either (a) `docker cp backend/tests <container>:/app/tests` before running pytest against the production image (Rule #20 fast iteration); (b) `docker run --rm --volume=$(pwd)/backend/tests:/app/tests:ro` bind-mount at run time; (c) use a separate `Dockerfile.ci` test target if shipped. Wairz already uses (a) in the operator's documented workflow.
