# Wave-2 β — Cross-Feature Blow-It-Up (BETA persona)

> Investigation date: 2026-05-21
> Synthesizes: 5 Wave-1 reports + (anticipated) W2-α convergence
> Branch tip read: `4ecaa5b` (main, post-baseline rebuild)
> Methodology: Rule #52 W2-β cross-feature attack stage; combine pairs of Wave-1-validated-safe fixes at their seam, hunt §SC5-analog attacks at the new boundary

## Executive Summary

The proposed seven-fix sweep — adding `sbom_status`, wiring upload_stage reaper, registering `auto_bare_metal_audit_firmware_safe`, removing the `unpack.py:106 if count <= 0: return` gate, frontend rebuild + Rule #29 alignment, fixing grype `force_rescan`, and unblocking the `make_live_db()` FK — opens **at least eleven new cross-feature attack surfaces** that Wave-1 saw individually but did not blow up at the seams. The highest-severity new attack is **§SC5-NEW-SBOM-θ (CRITICAL): Removing the `count<=0` gate without an in-walker bound triggers a DB connection-pool detonation** — 26 walker safe-runners each open their own `async_session_factory()` (`walker_registry.py:11-13`), an upload firestorm against 5 firmware in the same minute (operator-typical for bare-metal triage with f28066_*.bin variants) would request 130 simultaneous connections against a pool of 40 (pre-58a6f54 it was 30), starving the polling endpoints that just became 30/hour. **The fix-as-proposed is FRAGILE and needs hardening BEFORE shipping** — specifically (a) the gate-removal needs a per-firmware walker-fan-out concurrency bound (semaphore N=4), (b) the `sbom_status` Pydantic Literal needs a paired migration with `DEFAULT 'idle'` for existing rows (the orphan reaper crashes on NULL otherwise per §SC5-NEW-SBOM-α), and (c) the proposed dual 202+polling of generate + scan opens a Rule #51 cascade where vuln-scan polls block on SBOM generate's row-level lock at `sbom_components` (§SC5-NEW-SBOM-γ). Twelve new attacks catalogued; confidence HIGH.

## NEW §SC5-NEW-SBOM Attack Catalog

### §SC5-NEW-SBOM-α: Orphan reaper crashes on NULL sbom_status

- **Setup:** Proposal A lands a `sbom_status` Mapped[str] column on Firmware with `server_default="idle"`. Existing 25 firmware rows already in the table are migrated via `op.add_column(...)` with a server-side default — but if the migration uses `nullable=True` first (the safer Alembic pattern that avoids `ALTER TABLE ... SET DEFAULT 'idle' WHERE sbom_status IS NULL` blocking on a 25-row table) and the lifespan reaper at `main.py:200-242` (analogous to vuln-scan) is added in the same commit, the reaper executes BEFORE the backfill commit lands.
- **Trigger:** Backend restart after migration ships but BEFORE the deferred backfill closes.
- **Outcome (un-mitigated):** `UPDATE firmware SET sbom_status='failed' WHERE sbom_status IN ('queued','running')` does NOT match NULLs (per SQL `IN ()` semantics, NULL ≠ NULL); the reaper succeeds with rowcount=0. However, on the NEXT POST `/sbom/generate`, the 409 check `if firmware.sbom_status in ('queued', 'running')` evaluates `None in (...)` = `False`, so the POST proceeds — but then `firmware.sbom_status = 'queued'` writes to a column whose CHECK constraint may or may not allow NULL-to-string transition depending on how `op.create_check_constraint("ck_firmware_sbom_status", "sbom_status IN (...)")` was authored. **If the CHECK was written as `sbom_status IN (...)` without `OR sbom_status IS NULL`**, the very first POST after migration ships an UPDATE that triggers IntegrityError. The 500 surfaces as "Failed to generate SBOM" toast on the frontend.
- **Severity:** **HIGH** (operator-visible 500 on the first new-feature use)
- **Maps to Rule:** Rule #51 .i (orphan reaper completeness) + Rule #47 (consumer enumeration of CHECK semantics)
- **Mitigation:** (a) Migration uses `nullable=False, server_default="idle"` from the start (Alembic auto-runs `ALTER TABLE ... ADD COLUMN ... DEFAULT 'idle' NOT NULL` which on PostgreSQL 11+ avoids a full rewrite via the metadata-only default). (b) CHECK constraint written as `sbom_status IN ('idle', 'queued', 'running', 'completed', 'failed')` matching the canonical Rule #33 .c shape; (c) Lifespan reaper at `main.py:200-242` analog updates `WHERE sbom_status IN ('queued','running')` — works correctly on a NOT NULL column with defaulted backfill.
- **Gate-canary test (Rule #46):**
  ```python
  def test_sbom_status_reaper_handles_default_idle(db_session):
      # Synthesize: create a Firmware row WITHOUT explicitly setting sbom_status.
      # The DB default must populate 'idle'. The reaper must not flip 'idle' rows.
      fw = Firmware(project_id=p.id, original_filename="x.bin", ...)
      db_session.add(fw); db_session.commit()
      assert fw.sbom_status == "idle"  # default applied
      reap_orphans()  # lifespan analog
      db_session.refresh(fw)
      assert fw.sbom_status == "idle"  # reaper did not touch idle rows
  ```

### §SC5-NEW-SBOM-β: Rule #7 violation during the SBOM cut-over commit

- **Setup:** Proposal A converts `/sbom/generate` to 202+polling per Rule #33. The cut-over commit ships the new `_run_sbom_generate_background(firmware_id)` (its own `async_session_factory()` session) alongside the OLD synchronous body — temporarily during atomicity. If a developer mistakenly uses `asyncio.gather(generate_background(...), update_detection_roots(db, fw))` to "parallelise the post-generate update" where both coroutines share the OUTER request `db` session (passed in via Depends), Rule #7 fires.
- **Trigger:** Code-review pass misses the `asyncio.gather` because both coros LOOK independent — one's a background fire-and-forget, the other's a refresh.
- **Outcome (un-mitigated):** `AsyncSession` is NOT safe for concurrent coroutine access. State corruption: the `detection_roots` JSONB cache write races with `firmware.sbom_status="queued"` write; either a lost write OR a `sqlalchemy.exc.InvalidRequestError: Session is closed` runtime exception. Symptom: the polling endpoint reads `sbom_status='running'` but no work is happening (race lost the queued flip).
- **Severity:** **MEDIUM** (depends on whether the implementer falls into this trap; the existing pattern at `routers/sbom.py:583` is correctly `asyncio.create_task` not `gather`)
- **Maps to Rule:** Rule #7 (no gather on shared AsyncSession) + Rule #51 (Rule #33 conversion invariant sweep)
- **Mitigation:** Cut-over commit MUST use `asyncio.create_task(_run_sbom_generate_background(firmware.id))` exactly mirroring `routers/sbom.py:583`. Refresh-after-commit is unnecessary per Rule #32. Static AST canary: `tests/test_rule7_no_gather_shared_session.py` walks every router file and asserts no `asyncio.gather(...)` call sees the same `db: AsyncSession` param.
- **Gate-canary test (Rule #46):**
  ```python
  def test_sbom_generate_background_owns_own_session():
      src = open("backend/app/routers/sbom.py").read()
      # Synthesize: assert the new runner uses async_session_factory(), not the outer db
      assert "_run_sbom_generate_background" in src
      # Assert NO asyncio.gather with shared db
      assert not re.search(r"asyncio\.gather\([^)]*\bdb\b", src)
  ```

### §SC5-NEW-SBOM-γ: Dual 202+polling triggers Rule #51 polling cascade

- **Setup:** Proposal A converts `/sbom/generate` AND `/sbom/vulnerabilities/scan` BOTH to 202+polling under `TIER_A_LIGHT_ACK=30/hour`. An operator clicks "Generate SBOM" then immediately "Scan for Vulnerabilities" (the SbomPage UI allows this; there's no gate). The frontend now polls TWO status endpoints every 2s: `/sbom/generate/status` AND `/sbom/vulnerabilities/scan/status`.
- **Trigger:** Operator workflow: generate (in progress) → click scan (which 400s on "No SBOM generated yet" at `routers/sbom.py:560-563` because the queued-not-completed sbom_components are still missing) → operator re-clicks scan after generate completes → both polls now firing in lockstep.
- **Outcome (un-mitigated):** Per Rule #51 .iv "DB pool headroom," the post-58a6f54 pool is sized 15+25=40 (per CLAUDE.md Rule #51 worked example). Each poll opens a connection via `Depends(get_db)`. Two polls × 2 endpoints × 4-poll-window = 16 connections per single operator. **The 30/hour tier was math'd assuming SINGLE-stream polling**; dual-stream halves the effective budget. A 3-operator concurrent triage session (typical for the Eaton TMS320 case: one Wairz user reading the 5 f28066_*.bin variants) easily saturates 48 connections — pool exhaustion produces `QueuePool limit ... connection timed out` on **other** endpoints (firmware list, project tree). Operator-visible: SBOM polls return cleanly; project sidebar fails to load.
- **Severity:** **HIGH** (the d32d197 22000x speedup precedent is exactly this pattern — the perf bomb that surfaced after a 202+polling conversion increased polling cadence)
- **Maps to Rule:** Rule #51 .iv (DB pool headroom) + Rule #33 .a (idempotency contract on simultaneous endpoints)
- **Mitigation:** (a) Frontend polling combiner — when BOTH sbom_status AND vuln_scan_status need polling, batch into a single `/sbom/composite-status` endpoint that returns both in one query. (b) Pre-flight 400 from `/sbom/vulnerabilities/scan` if `sbom_status IN ('queued', 'running')` rather than relying on operator coordination. (c) Pool bump to 20+30=50 if (a) is deferred. (d) Front-end button gating: disable "Scan for Vulnerabilities" while `sbom_status === 'queued' || 'running'`.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_sbom_dual_polling_pool_headroom():
      # Synthesize 5 simultaneous SBOM generate-then-scan operator sessions
      # against the live DB; assert no pool timeout and < 80% pool utilization
      tasks = [drive_sbom_then_scan(fw_id) for fw_id in fws[:5]]
      await asyncio.gather(*tasks)  # legit gather: each owns its own session
      pool_stats = engine.pool.status()
      assert pool_stats.checked_out < 32  # < 80% of 40
  ```

### §SC5-NEW-SBOM-δ: Upload-stage reaper reaps a running row mid-extraction

- **Setup:** Proposal B wires an upload_stage orphan reaper in `main.py` lifespan (analog to vuln_scan reaper at `main.py:200-242`). It flips rows in `upload_stage IN ('detecting','extracting','analyzing')` to `upload_stage='failed'`. **CRITICAL CAVEAT** — the existing _run_upload_post_processing_background runs detached via `asyncio.create_task` from `routers/firmware.py:170` (per Scout A's reconstruction). If a backend hot-reload during dev (uvicorn `--reload` flag was historically used) restarts the process while the task is running on a 16 GB Illumisite upload, the reaper fires DURING extraction — the row flips to `failed` but the `asyncio.create_task` from BEFORE the restart isn't actually cancelled (in dev `--reload` doesn't kill subprocess subtasks cleanly).
- **Trigger:** Backend restart (intentional rebuild, OOM kill, or `docker compose restart backend`) while ANY upload is mid-extraction. Production case: an operator uploads a 16 GB image, immediately runs the Rule #8 rebuild from a parallel agent (typical Citadel multi-agent flow), the rebuild kills the container.
- **Outcome (un-mitigated):** Row flips to `upload_stage='failed'`. Operator sees "Upload failed" on the polling endpoint. **HOWEVER** — if the rebuild took <30s and the container came back up before the original task's docker write completed, the original task's database update CAN race the reaper. Worst case: the in-progress task writes `upload_stage='extracting'` → reaper writes `failed` → in-progress task writes `analyzing` → reaper sees nothing to reap because state is `analyzing` → task writes `ready` → row is `ready` but operator already saw `failed` and re-uploaded. NOW two firmware rows exist for the same operator intent.
- **Severity:** **MEDIUM** (developer/operator concurrent restart is the only realistic trigger; production restart is brief enough that the original task is already dead from sigterm)
- **Maps to Rule:** Rule #51 .i + Rule #33 .a (idempotency under restart)
- **Mitigation:** (a) The reaper must also CANCEL the asyncio.create_task — but `asyncio.create_task(...)` at line 170 is GC'd, so there's no handle. Fix: track task handles in a module-level `_UPLOAD_TASKS: dict[uuid, asyncio.Task] = {}` registry, the reaper iterates this dict and `.cancel()` each before the SQL UPDATE. (b) The reaper SQL adds `started_at < NOW() - INTERVAL '5 minutes'` so it only reaps rows that ARE genuinely abandoned — a fresh post-restart row whose task is just spinning up is NOT reaped.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_upload_reaper_does_not_kill_fresh_running_rows():
      fw = create_firmware_in_stage("extracting", started_at=datetime.now() - timedelta(seconds=10))
      run_upload_reaper()
      db_session.refresh(fw)
      assert fw.upload_stage == "extracting"  # too fresh; should NOT reap
      fw.upload_stage_started_at = datetime.now() - timedelta(minutes=10)
      db_session.commit()
      run_upload_reaper()
      db_session.refresh(fw)
      assert fw.upload_stage == "failed"  # stale; SHOULD reap
  ```

### §SC5-NEW-SBOM-ε: 409-loop trap on misconfigured upload_stage reaper

- **Setup:** Proposal B's upload_stage reaper has no `WHERE started_at <` clause (the naive shape that mirrors the vuln_scan reaper which does NOT have this guard because vuln_scan's started_at is set FROM the background runner BEFORE any work — see `routers/sbom.py:454-455`). For upload_stage, the situation is reversed: `upload_stage='detecting'` is set by `firmware_service.upload_bytes_only` at the very moment of intake (before the task even spawns) — Scout A line 17-19 confirms.
- **Trigger:** Backend restarts (production rebuild) at exactly the moment an upload finishes intake. Reaper fires, flips row to `failed`. The detached background task that was just about to start finds `firmware.upload_stage='failed'` — its `where(Firmware.id == firmware_id, Firmware.upload_stage.in_(...))` filter has nothing to update; task silently exits. Operator clicks "Re-upload" → POST creates a NEW firmware row → original row sits at `upload_stage='failed'` forever with `original_filename='X.zip'`, new row has same filename, status='ready'. **Foreign-key cascade dangling reference:** any analysis_cache rows that may have been written by an interrupted detector for the original firmware orphan dangling rows.
- **Outcome (un-mitigated):** Two firmware rows per upload, half of them dangling. Storage doubles. Project list cluttered with `failed` rows the operator has no UI affordance to delete.
- **Severity:** **MEDIUM** (cleanup operationally painful but not data-loss-critical)
- **Maps to Rule:** Rule #51 .iii (orphan-reaper + state-machine timing)
- **Mitigation:** Upload reaper uses `WHERE upload_stage IN ('detecting','extracting','analyzing') AND upload_stage_started_at < NOW() - INTERVAL '15 minutes'`. The 15-minute grace exceeds the post-process pipeline's worst-case for the 16 GB tarball cohort.
- **Gate-canary test (Rule #46):** As §SC5-NEW-SBOM-δ.

### §SC5-NEW-SBOM-ζ: bare_metal walker fires before chip_catalog.yaml loaded

- **Setup:** Proposal C registers `auto_bare_metal_audit_firmware_safe` in `walker_registry.py`'s `_load_walker_safe_runners()` (currently absent per Scout A line 65-95 enumeration). The function lives at `bare_metal_walker.py:656` and consumes `chip_catalog.yaml` for closed-Literal validation (Rule #52 first instance per CLAUDE.md). `walker_registry.WALKER_AUTO_TRIGGERS = get_walker_auto_triggers()` is built EAGERLY at module-import time (`walker_registry.py:182`). The chip_catalog uses `MtimeCachedYamlLoader` per Rule #52 worked example.
- **Trigger:** Backend cold start; first upload arrives before the chip_catalog mtime-cache is warm (the cache is lazy — populates on first `chip_catalog.get_manifest_for_signal(...)` call).
- **Outcome (un-mitigated):** First firmware upload triggers `_run_hardware_firmware_detection_safe` → walker fan-out → bare_metal walker calls into chip_catalog → catalog loader walks `data/chip_families/**/*.yaml` synchronously. If the data directory has 40+ files, the catalog walk takes ~200ms inside the asyncio event loop (Rule #5 violation if not run_in_executor'd). For the FIRST upload after restart, all 26 walkers + chip_catalog cold-load + Vol3 cold-import all happen on a single asyncio.create_task call chain. **Symptom: 5-second stall on the first upload polling endpoint after every backend restart.**
- **Severity:** **LOW-MEDIUM** (one-time cold-start cost; not user-facing in steady state)
- **Maps to Rule:** Rule #5 (executor wrapping for filesystem I/O) + Rule #52 (closed-grammar manifest loader contract)
- **Mitigation:** Backend lifespan startup (post-reaper) does a single `chip_catalog._warm_cache()` call inside `loop.run_in_executor(...)` so the FIRST upload doesn't pay the catalog walk cost. Symmetrical to the DBX bundle probe at `main.py:244-249`.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_chip_catalog_warmed_on_lifespan_start():
      # After lifespan startup, the chip_catalog cache must be populated.
      async with lifespan(app):
          from app.services.chip_catalog import _CACHE
          assert _CACHE is not None and len(_CACHE) > 0
  ```

### §SC5-NEW-SBOM-η: Walker fan-out cascades on non-HW firmware (gate removal)

- **Setup:** Proposal D removes `unpack.py:106 if count <= 0: return`. The fan-out at lines 145-154 now runs for every firmware regardless of `hardware_firmware_blob` count. Per Scout C, 6 firmware uploaded in the last 5 days have `hw_blob_count=0` (24967.hex + 4 f28066 variants + PowerPack EGIA + Bootloader_7.7.1.hex + coredx-wolfssl + Q17AX-03.SDM + GS724Tv6 minimal). With the gate removed AND `auto_bare_metal_audit_firmware_safe` registered (Proposal C), each firmware fan-out is 27 walkers.
- **Trigger:** Operator triage workflow: drops 5 f28066_*.bin variants in rapid succession (~10s apart, typical UI-paced upload).
- **Outcome (un-mitigated):** 5 firmware × 27 walkers = **135 walker tasks**, each opening its own `async_session_factory()` per Rule #39 .safe semantics (`walker_registry.py:11-13`). The DB pool is 40 (post-58a6f54). Of 135 simultaneous requests, ~95 timeout immediately on `pool.acquire(timeout=10)` → each walker's outer try/except swallows + logs (`unpack.py:147-154`). **Operator-visible:** silently broken walkers; `*_walk_status` columns stay `idle` (Rule #39 .safe contract: walkers DO NOT mutate status on failure). Operator believes the upload succeeded; trigger MCP later finds no data to backfill from because the walkers DID run but errored.
- **Severity:** **CRITICAL** (silent walker failure under operator-typical load — the EXACT symptom Scout C observed but mis-attributed to the gate)
- **Maps to Rule:** Rule #51 .iv (DB pool headroom) + Rule #5 (concurrency control on cascading async)
- **Mitigation:** (a) Per-firmware walker fan-out is bounded by `asyncio.Semaphore(N=4)` declared in `walker_registry.py` module scope; safe-runners acquire/release. (b) Pool sized for the headroom: peak walker count × N=4 × concurrent firmware. For the f28066 cohort, that's 27×4=108 connections AT MOST regardless of how many firmware spawn — pool 50+25=75 covers it. (c) Walker safe-runners EARLY-EXIT cheaply if `get_detection_roots(firmware)` returns `[]` — they shouldn't open a session at all if no work exists.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_walker_fanout_bounded_concurrency_under_burst():
      # Burst-upload 5 firmware in quick succession; assert peak DB connections < pool size
      tasks = [upload_firmware(name=f"f28066_{i}.bin") for i in range(5)]
      with monitor_pool_peak() as monitor:
          await asyncio.gather(*tasks)
      assert monitor.peak_acquired < 40
  ```

### §SC5-NEW-SBOM-θ: Gate removal triggers DB connection pool detonation (CRITICAL escalation)

- **Setup:** Same as §SC5-NEW-SBOM-η but stronger formulation. Wave-1 Scout C's recommendation #3 says "Removing it (or restructuring to `if count > 0: build_driver_firmware_graph()` then ALWAYS proceed to walker fan-out) instantly unblocks 22+ walkers." If literally removed without other mitigation, Scout C's recommendation is INCOMPLETE — the gate WAS protective beyond its stated purpose.
- **Trigger:** Same as η + add the OPERATIONAL trigger: the operator runs the Phase E test from Scout D's recommendation #3 ("Before any deeper investigation, rebuild the frontend image and confirm the regression reproduces"). The rebuild kicks off; a queued upload from another agent stream lands during the 30s rebuild gap (typical for multi-agent Citadel campaign).
- **Outcome (un-mitigated):** Same as η + the rebuild's worker reconnection bumps the pool ceiling momentarily; the first walker fan-out post-rebuild over-allocates connections. **Cascade across the whole backend** — security_audit, attack_surface, uefi_scan, yara_scan all running on the same pool now starve. The Wave-1 Scout C observation "ZERO walker-emitted findings" + "windows_registry_extracts = 0 cluster-wide" is now the **EXPECTED** state for every new upload, not the fixable state.
- **Severity:** **CRITICAL** (any "let's just remove the gate" PR ships a cascade-fail regression)
- **Maps to Rule:** Rule #51 (full invariant sweep on a state-machine boundary change)
- **Mitigation:** Same as η, plus: the gate-removal commit MUST include the Semaphore + the pool bump + the safe-runner early-exit in a SINGLE Rule #25 single-slice atomic commit. Splitting these across commits leaves an intermediate state where the gate is gone but the protection isn't in place — bisect lands on a broken commit.
- **Gate-canary test (Rule #46):** As η, plus a META-CANARY that runs `pytest backend/tests/test_walker_fanout_pool.py` BEFORE accepting the gate-removal commit.

### §SC5-NEW-SBOM-ι: 0-HW-blob walker rows pollute `*_walk_status` semantics

- **Setup:** Proposal D removes the gate. Walker safe-runners run on a 0-HW-blob firmware (24967.hex case from Scout C deep-dive). Each safe-runner per Rule #39 contract DOES NOT mutate status (line 15 of `walker_registry.py` docstring), so the column stays `idle`. **But** if a walker INTERNALLY stamps a result aggregate to a JSONB column to mark "we ran and found nothing" (per Rule #35c discipline), the column write IS a state transition observers care about.
- **Trigger:** Operator runs trigger MCP tool against the 24967.hex case: `trigger_appcompat_walk(firmware_id)`. Per Rule #39 .a, the tool 409s if status is `queued` or `running`. If the auto-fired walker (Proposal D) wrote a JSONB result but left status=idle, the operator's MCP tool succeeds, re-runs the walker, double-writes the JSONB. Result aggregator math (e.g., `total_artefacts: 0` becomes `total_artefacts: 0` again, but `walked_at` timestamp drifts).
- **Outcome (un-mitigated):** Double-write of zero-result JSONB. Minor data hygiene; operator metrics now show "walked twice" with consistent zero results. The bigger issue: if the walker EMITS findings on zero-result (e.g., "no driver found = potentially trusted environment" → finding emitted), the trigger MCP tool re-emits the same finding → Rule #35b dedup violation if Finding-table UniqueConstraint isn't present. Per Scout A, `sbom_vulnerabilities` has no UniqueConstraint; same likely true for several walker-output tables.
- **Severity:** **LOW** (data hygiene only, no operator-visible failure)
- **Maps to Rule:** Rule #35c (JSONB normaliser) + Rule #44 cross-firmware lookup (which would surface duplicate-walked rows)
- **Mitigation:** Walker safe-runners check for existing `walked_at` JSONB stamp; if present + recent, return early without re-emitting findings. The trigger MCP tool ALSO checks staleness and refuses to re-run within a 5-minute window unless `force=True`.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_walker_idempotent_on_zero_hw_blob_firmware():
      fw = create_firmware_with_hw_blob_count(0)  # bare-metal scenario
      await auto_appcompat_walk_firmware_safe(fw.id)
      jsonb_v1 = fw.appcompat_walk_result
      await auto_appcompat_walk_firmware_safe(fw.id)  # second fire
      assert fw.appcompat_walk_result == jsonb_v1  # idempotent; no drift
  ```

### §SC5-NEW-SBOM-κ: Frontend rebuild ships extractErrorMessage that breaks on legacy 4xx

- **Setup:** Proposal E rebuilds the frontend image to close the 27-hour stale-bundle drift. The rebuild includes commit `87a2574 feat(file-formats): cut-over` plus any subsequent commits up to HEAD. Per Scout D line 99-101, `extractErrorMessage` at `utils/error.ts:12-22` reads `data.hint` → `data.detail` → `data.error`. This handles SlowAPI 429 (`data.error`), FastAPI HTTPException (`data.detail`), and Rule #51 structured 429 (`data.hint`).
- **Trigger:** Operator hits an endpoint that returns a 400 from a non-FastAPI source — e.g., the SlowAPI `default_limits=["100/minute"]` default tier limit (rate_limit.py:82). The response is a SlowAPI 429 with `{detail: "100 per 1 minute", error: ...}` shape. The frontend reads `data.hint` first (undefined for SlowAPI default tier — only the wairz custom handler at `rate_limit.py:121-232` sets hint) → falls back to `data.detail` = "100 per 1 minute" — operator sees raw SlowAPI string, not the helpful structured message.
- **Outcome (un-mitigated):** Operator sees "100 per 1 minute" as the toast on the SBOM page. They have no idea what they did wrong. The Rule #51 .iii defect from CLAUDE.md (the user-facing 429 message family) is partially regressed for the DEFAULT tier path.
- **Severity:** **LOW** (cosmetic / operator-confusion; not a functional break)
- **Maps to Rule:** Rule #51 .iii (frontend 429 handler completeness)
- **Mitigation:** The custom handler at `rate_limit.py:121-232` is wired as the global RateLimitExceeded handler for ALL tiers including the default. Verify in `main.py` that `app.state.limiter = limiter` AND `app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)`. The Wave-2 γ yardstick should confirm.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_default_tier_429_has_structured_body():
      # Hammer an endpoint that ONLY has the default tier (no explicit @limiter.limit)
      for _ in range(101):
          response = await client.get("/api/v1/projects/.../cheap-endpoint")
      assert response.status_code == 429
      body = response.json()
      assert "hint" in body  # custom handler ran for default tier too
      assert "tier" in body
  ```

### §SC5-NEW-SBOM-λ: Polling cadence trips its own 30/hour budget

- **Setup:** Proposal E aligns Rule #29 timeouts AND maintains 202+polling. The frontend polls every 2s on `/sbom/vulnerabilities/scan/status` (Scout A line 7-8). If the operator opens the SBOM page TWO TIMES (two browser tabs) and the scan is in `running` state, both tabs poll independently.
- **Trigger:** Operator opens SBOM tab → starts scan → opens a second tab to compare findings against a Notion doc → both tabs poll the GET status endpoint every 2s.
- **Outcome (un-mitigated):** GET `/sbom/vulnerabilities/scan/status` is NOT rate-limited (per Scout A's enumeration of `_EXPECTED_TIERS`, only the POST endpoints are tier'd). 2 tabs × 1 poll / 2s = 1 req/s = 3600/hour. That's WAY under any rate-limit budget for GET. BUT: the GET hits `_resolve_firmware` which queries the DB; 3600/hour × 1 DB query/req = 1 query/sec sustained per operator. For a 30-minute scan, 1800 DB queries hit just for polling. **Aggregated across 3 concurrent operators, 5400 queries** — observable in `pg_stat_statements` as the top query. Not a regression NOW but a latent perf concern; if the d32d197 22000x speedup didn't fix this exact query, the polling cadence detonates again.
- **Severity:** **LOW** (perf-only; no semantic break)
- **Maps to Rule:** Rule #29 (timeout/cadence alignment) + Rule #51 .iv (DB pool headroom under polling)
- **Mitigation:** Frontend polling backoff — start at 2s, double to 4s/8s/16s up to 32s if `status` doesn't change. The polling resumes 2s cadence on user-visible page-focus events. Visibility-API-gated: when the tab is hidden, polling stops entirely.
- **Gate-canary test (Rule #46):**
  ```typescript
  it("polling backs off when status is unchanged", async () => {
    const poll = makePollLoop(firmwareId);
    await poll.poll(); // 2s
    await poll.poll(); // 4s
    await poll.poll(); // 8s
    expect(poll.currentInterval).toBeGreaterThan(2000);
  });
  ```

### §SC5-NEW-SBOM-μ: Grype DELETE-then-INSERT lacks transactional atomicity

- **Setup:** Proposal F fixes `scan_with_grype` to DELETE existing rows before INSERT on `force_rescan=True` (Wave-1 finding #6 at Scout A line 162-164). The fix shape mirrors the SBOM router's `force_rescan` delete at `routers/sbom.py:144-147`.
- **Trigger:** Mid-scan, the Grype subprocess fails (binary missing, OOM in worker container, malformed CDX input from a recently-corrupted SBOM). The DELETE has committed; the INSERT loop fails partway.
- **Outcome (un-mitigated):** `sbom_vulnerabilities` for the firmware is now **EMPTY** (the DELETE landed). Polling endpoint reads `vuln_scan_status='failed'` and `0 vulnerabilities` — operator sees "scan failed, all your prior vulnerabilities erased." This is a **DATA LOSS** failure mode that didn't exist pre-fix (where Grype path simply doubled rows).
- **Severity:** **HIGH** (data loss under failure path)
- **Maps to Rule:** Rule #32 (transaction semantics in wairz session config) + Rule #33 .b (result aggregate persisted on same transaction as state)
- **Mitigation:** The DELETE + INSERT MUST be wrapped in a single transaction. `services/grype_service.py:60-265` already uses the caller's `db: AsyncSession` — the fix is to NOT commit between DELETE and INSERT. The outer caller (`_run_vuln_scan_background` at `routers/sbom.py:478`) calls `await db.commit()` ONCE at the end. If the Grype subprocess fails between DELETE and INSERT, the rollback at `routers/sbom.py:497` rolls back the DELETE too — prior rows survive.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_grype_failure_rolls_back_delete():
      # Pre-populate sbom_vulnerabilities with 5 rows
      seed_vulns(firmware_id, n=5)
      # Mock Grype subprocess to fail
      with mock.patch("subprocess._popen_args", side_effect=RuntimeError):
          await scan_with_grype(firmware_id, project_id, db, force_rescan=True)
      # Original 5 rows must still exist (DELETE rolled back)
      assert db.scalar(select(func.count(SbomVulnerability.id))) == 5
  ```

### §SC5-NEW-SBOM-ν: force_rescan API contract drifts between sync and 202+polling paths

- **Setup:** Proposal F + Proposal A jointly: `/sbom/generate` becomes 202+polling AND its `force_rescan` query param now traverses the 202 boundary. Today (per `routers/sbom.py:117-119`) `force_rescan=False` is the default; the endpoint reads it directly in the request handler. After 202+polling conversion, `force_rescan` must be passed to `_run_sbom_generate_background(firmware_id, force_rescan)`. The router's 409 idempotency check currently doesn't gate on `force_rescan` — but with the fix, two concurrent POSTs with different `force_rescan` values (one True, one False) could 409 the second one even though the first WOULDN'T have done work the second wanted done.
- **Trigger:** Operator clicks "Generate SBOM" (force_rescan=false) → sees cached results → realizes they need a fresh scan → immediately clicks "Force Regenerate SBOM" (force_rescan=true) before the first POST's 200 returns.
- **Outcome (un-mitigated):** Second POST sees `sbom_status='running'` (because first is mid-flight, but the first was returning a cached result — actually a sync no-op), 409s. Operator stuck waiting for a scan that returned cached and doesn't repeat. UI-state divergence.
- **Severity:** **MEDIUM** (operator-visible "second click does nothing" mystery)
- **Maps to Rule:** Rule #33 .a (idempotency contract precision) + Rule #47 (consumer-hook enumeration of force_rescan parameter)
- **Mitigation:** The 409 check considers `force_rescan` — if `force_rescan=True` is requested while `sbom_status='running'` with the IN-FLIGHT row having force_rescan=False, the new request CANCELS the cheap one and starts the expensive one. Mechanically: extend `firmware.sbom_status` writes to include `firmware.sbom_force_rescan: bool` so the 409 check is `(sbom_status, sbom_force_rescan)`-aware. OR: the cached-result path doesn't transition to `running` at all — return 200 immediately from `routers/sbom.py:134-140`. Cached return path stays synchronous; only the actual-work path goes 202.
- **Gate-canary test (Rule #46):**
  ```python
  async def test_sbom_force_rescan_supersedes_running_cached_no_op():
      # First POST with cached results returns 200 (no state change)
      response = await client.post(...?force_rescan=false)
      assert response.status_code == 200
      assert response.json()["cached"] is True
      # Second POST with force_rescan=True should NOT 409
      response = await client.post(...?force_rescan=true)
      assert response.status_code == 202
  ```

### §SC5-NEW-SBOM-ο: FK fix propagates to silent consumer breakage

- **Setup:** Proposal G unblocks `make_live_db()` FK breakage. Per opening baseline, the actual fix is likely to rename `memory_dump_image` (singular) to `memory_dump_images` (plural) OR fix the FK declaration in `volatility_injection_records`. Rule #47 enumeration on the table-rename: every consumer that references the table by name needs migration.
- **Trigger:** Migration ships with new table name; consumers continue to reference old name.
- **Outcome (un-mitigated):** Per Scout C line 119-128, `memory_dump_image` is currently empty (0 rows cluster-wide) — there are no production rows to migrate. BUT: 4 tools likely reference the table by string. Per grep on the codebase from Scout E's persona enumerator — `memory_image_enumerator.py:auto_memory_image_enumeration_safe` writes to it; `windows_info_walker.py` reads it; `vol3_runner.py` reads it; `windows_processes_walker.py` reads it. If the fix renames the model but misses one of the consumers, the consumer silently reads zero rows from the new table (because the orm relationship is unchanged but the consumer queries a stale alias).
- **Severity:** **LOW** (the bug is already silent — consumers read 0 rows pre-fix; fix doesn't worsen things; future writes will populate correctly)
- **Maps to Rule:** Rule #47 (consumer-hook enumeration on table-rename)
- **Mitigation:** Rule #47 mechanical: `grep -rn 'memory_dump_image\|MemoryDumpImage\|memory_dump_images' backend/` and enumerate each match in the migration PR.
- **Gate-canary test (Rule #46):**
  ```python
  def test_memory_dump_table_consumers_resolved():
      from app.models import MemoryDumpImage  # canonical
      from app.services.windows_info_walker import auto_windows_info_walk_firmware_safe
      src = inspect.getsource(auto_windows_info_walk_firmware_safe)
      assert "memory_dump_images" not in src or "MemoryDumpImage" in src  # uses model, not string
  ```

### §SC5-NEW-SBOM-π: Live canaries silently skipped for HOW LONG?

- **Setup:** Per opening baseline, 12 live-canary tests across 4 test files have been failing due to the FK breakage. The breakage was discovered "today" (2026-05-21).
- **Trigger:** Read git blame on the FK declaration `volatility_injection_records.memory_image_id`.
- **Outcome (un-mitigated):** Per Scout B enumeration of the 30-day commit window, the λ.α memory walker phase shipped in commits `89b6f0f` / `5d2169d` / `166df66` / `d357938` — all 2026-05-13 to 2026-05-14. The FK was authored at λ.α.B (memory image enumerator) commit ~`5d2169d`. **The make_live_db FK has been broken for ~7-8 days.** During this window, every Rule #35b live-canary in the SBOM/vuln-scan/finding-emit subsystem was SILENTLY SKIPPED — the metadata-load fails at fixture setup, so no per-test assertion is even attempted. The 180 passing mock tests provided ZERO value-flow validation.
- **Severity:** **HIGH** (test-layer blind spot for 7-8 days; explains why the SBOM/vuln-scan regressions weren't caught in CI)
- **Maps to Rule:** Rule #35b (mocks vs live canaries) + Rule #46 (verification mechanism canary — the live-canary itself needs a canary that proves it ran)
- **Mitigation:** (a) Lifespan startup adds a "test-suite metadata-load smoke" check that imports `tests._live_db` and asserts `make_live_db()` succeeds against a tmp_path DB. (b) CI workflow adds `pytest --collect-only` step that ASSERTS the live-canary tests are collected and ran (not silently skipped). (c) The opening-baseline's 12-failure list is itself the canary that re-running the test suite after fix verifies.
- **Gate-canary test (Rule #46):**
  ```python
  def test_live_canary_metadata_loads_cleanly():
      # If this test passes, make_live_db works. If it fails, the FK is broken again.
      from tests._live_db import make_live_db
      with make_live_db() as db:
          assert db is not None
  ```

## Companion Failure Mode Cascade

If Wave-2 ships proposals A+D+G but skips B+C (and proposals E/F land partially), the worst-case operator session is:

1. Operator uploads a 5-firmware bare-metal triage cohort (f28066_*.bin × 5).
2. Upload pipeline runs the 202+polling path; each row hits `upload_stage='ready'` cleanly. **§SC5-NEW-SBOM-ε absent**: B not landed, reaper not present, but no restart happens.
3. `_run_hardware_firmware_detection_safe` fires per firmware. The gate is gone (D landed), so each firmware fires 26 walkers (C NOT landed, so bare_metal walker not registered).
4. **§SC5-NEW-SBOM-θ fires:** 5×26=130 walker tasks against pool 40. ~90 walker tasks fail silently.
5. Operator opens SbomPage for f28066_otp_16bit.bin. Clicks "Generate SBOM". The page polls.
6. **§SC5-NEW-SBOM-γ fires:** Dual generate+scan polling halves the pool budget; operator's project sidebar fails to refresh (pool exhausted).
7. **§SC5-NEW-SBOM-π absent (G landed):** Live canaries ran in CI before merge. But the live canaries don't test pool-saturation scenarios; the cascade is undetected in CI.
8. **§SC5-NEW-SBOM-μ fires:** Operator hits `force_rescan=True` on a Grype scan; Grype OOMs on the synthesised CDX; DELETE landed, INSERT failed, sbom_vulnerabilities cleared.
9. Operator's full triage cohort is now: 4 walker-empty firmware (silent §SC5-NEW-SBOM-θ), 1 firmware with cleared vulnerabilities (§SC5-NEW-SBOM-μ), project sidebar broken (§SC5-NEW-SBOM-γ).
10. **Operator perceives the regression got WORSE after the fix.** Files a critical bug. The fix gets reverted; we're back to the original state. The whole sweep is for nothing.

**To prevent this cascade, every fix proposal MUST ship with its Rule #46 gate-canary AND the canaries must be live-run against a representative production-shaped fixture corpus before merge.**

## Pre-Cutover Robustness Checklist

| Fix Proposal | Required Gate-Canaries Before Merge |
|---|---|
| **A** (sbom_status + 202+polling generate) | Canary §SC5-NEW-SBOM-α (NULL handling); §SC5-NEW-SBOM-β (no gather); §SC5-NEW-SBOM-γ (dual-polling pool); §SC5-NEW-SBOM-ν (force_rescan contract) |
| **B** (upload_stage reaper) | Canary §SC5-NEW-SBOM-δ (fresh row not reaped); §SC5-NEW-SBOM-ε (15-min grace) |
| **C** (bare_metal walker registration) | Canary §SC5-NEW-SBOM-ζ (catalog warm); cross-firmware MCP tool per Rule #44; orphan reaper for `bare_metal_audit_status` |
| **D** (gate removal) | Canary §SC5-NEW-SBOM-η (semaphore bound); §SC5-NEW-SBOM-θ (pool detonation); §SC5-NEW-SBOM-ι (zero-blob idempotency); MUST be a Rule #25 single-slice commit |
| **E** (frontend rebuild + Rule #29) | Canary §SC5-NEW-SBOM-κ (default-tier 429 structured); §SC5-NEW-SBOM-λ (polling backoff); rebuild verification via `docker compose images frontend` Date check |
| **F** (grype force_rescan) | Canary §SC5-NEW-SBOM-μ (transactional rollback); §SC5-NEW-SBOM-ν (force_rescan precedence) |
| **G** (make_live_db FK) | Canary §SC5-NEW-SBOM-ο (consumer-rename enumeration); §SC5-NEW-SBOM-π (live-canary smoke first) |

## Recommendations for W2-α + W2-γ

1. **Ship G first.** Per §SC5-NEW-SBOM-π, the live-canary blind spot is the deepest pre-existing harm. Until G ships, no other gate-canary in this report can be trusted to actually catch regressions. **Order: G → run all 12 currently-failing live canaries → confirm they pass post-fix → only THEN proceed to A-F.**

2. **Bundle D + E + F + B with semaphore+pool+15-min-grace in a single Rule #25 single-slice atomic commit.** This is the cross-stack alignment commit per Rule #48 Shape-1. Splitting D from the semaphore is a §SC5-NEW-SBOM-θ trap.

3. **Defer A to a separate session.** The 202+polling conversion of `/sbom/generate` is genuinely a Rule #33 conversion with all the Rule #51 invariant-sweep companions (tier review, orphan reaper, DB pool, frontend 429 handler, polling backoff). Treating it as a quick add-column is the same shape as the 8f54a24 → f6dbc7b 11-day latent-defect window. **A standalone session focused on the SBOM generate 202+polling conversion is warranted**, with cross-stack alignment commits per Rule #48.

4. **Add a Rule #46 META-CANARY for the proposed `auto_sbom_safe` and `auto_vuln_scan_safe` walker registrations** if Wave-1 / W2-α proposes adding them. Per Scout A line 67 and Scout E line 11, the current architecture is operator-driven; auto-firing SBOM/vuln-scan changes the operator's mental model and inherits all 7 Rule #51 companion failure modes.

5. **For W2-γ (Rule #28 yardstick):** Re-measure the actual LOC of the sweep commits before sizing the session budget. The proposal touches `routers/sbom.py` (1300+ LOC), `models/firmware.py` (1000+ LOC), `main.py` (300+ LOC), `walker_registry.py` (190 LOC), `grype_service.py` (265 LOC), plus 12 test files. Per Rule #28's +14-22% drift observation, expect the actual diff to land 1.2× the estimate. Budget accordingly.

6. **Critical observation for W2-α convergence:** The Wave-1 reports collectively identify ~10 root causes; **this Wave-2 β report identifies 12 new attacks at the seams**. The fix surface area is therefore ~22 distinct concerns, not 10. A single-session ship-all-fixes approach is not advisable. **Recommend the do-them-all pattern: 3-4 parallel scout-implementers, each owning a disjoint subset of the 22 concerns, with the W2-γ yardstick coordinating the merge order.**
