# Wave-2 β — Cross-Feature Blow-It-Up (S2)

> Investigation date: 2026-05-21 (Session 2, second pass)
> Persona: BLOW-IT-UP — find attacks at SEAMS between Wave-1's individually
> validated fixes. Predecessor: Session 1's `wave2-beta-blowup.md` catalogued
> 12 §SC5-NEW-SBOM-α..π attacks (1 mitigated, 11 deferred); Session 2's Scout C
> catalogued 11 NEW §SC5-NEW-SBOM-S2-α..λ at single-fix boundaries. This
> report finds 7 NEW attacks at the COMBINATORIAL SEAMS Wave-1 individually
> validated as safe but combinatorially break.
> Methodology per `feedback_wave2_cross_feature_methodology.md` memory entry —
> Wave-2 W2-β cross-feature attack stage on top of Wave-1's single-axis output.

## Executive Summary

Wave-1 + Scout C have catalogued the single-fix attack surface comprehensively;
the seams BETWEEN fixes carry residual cross-feature risk that nobody saw
individually. **The highest-severity NEW seam attack is §SC5-NEW-SBOM-S2-SEAM-A
(HIGH): Fix #1's new `_run_sbom_generate_background` task is currently
spawned INSIDE the request handler before the row commit reaches the worker's
DB session, but the new `_post_process_pipeline` Rule #9 also fires
`_run_hardware_firmware_detection_safe` via a BARE `asyncio.create_task` at
`backend/app/services/firmware_service.py:818` — not via
`_spawn_background_task`. The Wave-1 scout-D-required broader sweep MUST
extend the helper TO this site, not just to the 4 router sites Scout C
enumerated.** **Fix #11 (walker reaper sweep) as proposed in Scout E Option B
needs hardening BEFORE shipping** — Scout C's §SC5-NEW-SBOM-S2-γ catches the
sbom_status/vuln_scan_status drop but Scout E's recommended `WALKER_REAPER_CONFIGS`
ALSO doesn't cover the 3 partial-coverage non-walker columns (`authenticode_chain_status`,
`dotnet_decompile_status`, `windows_update_diff_status`) that Scout E itself
identifies at lines 21-23 of `wave1-scout-E-state-machine.md`. **7 NEW seam attacks
catalogued**; confidence HIGH on attack mechanics; MEDIUM on combinatorial
likelihood (each requires 2+ Wave-1 fixes to land together, which is the
session-end shape).

## NEW §SC5-NEW-SBOM-S2-SEAM Attack Catalog

### §SC5-NEW-SBOM-S2-SEAM-A: Broader create_task sweep × _post_process_pipeline's NON-router create_task site

- **Seam:** Scout C's create_task width-canary discipline (§SC5-NEW-SBOM-S2-κ)
  × Scout A's `_post_process_pipeline` walker-bridge fix (line 818 of
  `backend/app/services/firmware_service.py`).
- **Setup:** Scout C's §SC5-NEW-SBOM-S2-κ catalogues 5 router sites that need
  `_spawn_background_task` migration (`firmware.py:175,297,436,441`,
  `fuzzing.py:143`, `hardware_firmware.py:654,750`). Scout B's recommendation
  #5 explicitly says "move `_spawn_background_task` to `app/utils/background.py`
  as a shared utility." Scout C's grep canary `grep -n "asyncio.create_task"
  backend/app/routers/*.py` deliberately SCOPES to `routers/`. **But the
  6th site is in `services/firmware_service.py:818`** — a `asyncio.create_task(
  _run_hardware_firmware_detection_safe(...))` that fires AFTER
  `_post_process_pipeline` commits `upload_stage='ready'`. The walker fan-out
  runs detached for 30-180s (26 walkers, sequential per Rule #7). On worker
  GC pressure, the task is reclaimed mid-run.
- **Trigger:** Operator uploads 5 firmware in a 30-second burst (operator-typical
  triage workflow). The 5 `_post_process_pipeline` runners complete and each
  spawns a detached `_run_hardware_firmware_detection_safe`. Total live RSS
  during the burst exceeds the worker's ~6 GB cap; GC fires; one of the 5
  detached tasks is collected.
- **Outcome (un-mitigated):** That firmware's walker fan-out vanishes
  mid-run; `*_walk_status` columns remain `idle` (Rule #39 .safe semantics —
  the safe-runners don't mutate status); operator opens the firmware page and
  sees BCD/EVTX/Prefetch/SRUM all `idle` while the OTHER 4 firmware show
  `completed`. **Silent walker-vanishing** — no failed row, no error, just
  4-of-5 firmware fully walked and the 5th mysteriously empty. The Scout C
  §SC5-NEW-SBOM-S2-κ canary (grep restricted to routers) would PASS.
- **Severity:** **HIGH** (silent data-completeness regression on a multi-firmware
  triage burst — the operator-typical workflow)
- **Mitigation:** Scout B's recommendation extended — move `_spawn_background_task`
  to `app/utils/background.py` AND grep the WIDER pattern `grep -rn
  "asyncio\.create_task" backend/app/ --include="*.py" | grep -v "test_" | grep
  -v "subprocess" | grep -v "_spawn_background_task"` (covers services AND
  routers — Rule #31 width-canary). The 6th site at
  `firmware_service.py:818` MUST be migrated in the same Session 2 sweep
  commit. Verify via `git grep "asyncio.create_task" backend/app/` returns
  ONLY documented exceptions (terminal WS handlers, fire-and-forget cleanup
  helpers explicitly noqa'd).
- **Gate-canary (Rule #46):**
  ```python
  def test_no_bare_create_task_outside_terminal_handlers():
      """The complement to §SC5-NEW-SBOM-S2-κ: cover services + routers.
      
      Rule #31 width-canary — Scout C's grep was scoped to routers/ which
      misses _post_process_pipeline at services/firmware_service.py:818.
      """
      from pathlib import Path
      import re
      forbidden = []
      for path in Path("backend/app").rglob("*.py"):
          # Skip allowlisted exception files
          if any(seg in str(path) for seg in ("terminal", "test_", "/tests/")):
              continue
          src = path.read_text()
          # Find bare asyncio.create_task that doesn't have noqa right above
          for m in re.finditer(r"asyncio\.create_task\(", src):
              ctx_start = max(0, m.start() - 300)
              ctx = src[ctx_start:m.start()]
              if "_spawn_background_task" not in ctx and "# noqa: BARE_CREATE_TASK" not in ctx:
                  forbidden.append(f"{path}:{src[:m.start()].count(chr(10)) + 1}")
      assert not forbidden, f"Bare create_task outside helper: {forbidden}"
  ```

### §SC5-NEW-SBOM-S2-SEAM-B: Fix #11 size-lock META-CANARY × non-walker partial-coverage columns

- **Seam:** Scout E's Fix #11 Option B `WALKER_REAPER_CONFIGS` dict
  (`backend/app/workers/walker_registry.py` — proposed) × Scout E's own
  partial-coverage column enumeration at lines 21-23 of
  `wave1-scout-E-state-machine.md` (`authenticode_chain_status`,
  `dotnet_decompile_status`, `windows_update_diff_status`).
- **Setup:** Scout E recommends Option B (centralised dict in walker_registry.py)
  with a Rule #46 META-CANARY at line 282 asserting
  `len(WALKER_REAPER_CONFIGS) == len(WALKER_AUTO_TRIGGERS) == 26`. The
  META-CANARY's size-lock IS structural — every walker auto-trigger MUST have
  a matching reaper config. Scout E ALSO acknowledges (line 271, "Extending
  Option B to authenticode_chain + windows_update_diff + dotnet_decompile")
  that 3 non-walker columns share the same shape but explicitly DEFERS them
  to Session 3 ("Fix #11's scope is the 22 walkers; the other 3 columns are
  a Session 3 follow-up").
- **Trigger:** Fix #11 ships in Session 2 with the size-lock META-CANARY
  PASSING (22/22 walker columns reaped). Session 3 starts on the
  `authenticode_chain_status` reaper but the developer adds it to the SAME
  `WALKER_REAPER_CONFIGS` dict (intuitive — that's where the reaper
  derivations live). The size-lock META-CANARY now FAILS:
  `len(WALKER_REAPER_CONFIGS) == 23` but `len(WALKER_AUTO_TRIGGERS) == 22`.
  Developer "fixes" the META-CANARY by changing the expected count to 23.
  Now adding ANOTHER non-walker column (e.g. `cab_extraction_status` shipped
  by a future Session 4 feature) silently drops out of the reaper because
  the META-CANARY no longer encodes the structural invariant.
- **Outcome (un-mitigated):** Scout E's structural invariant ("every walker
  has a reaper") is silently weakened to "the dict has SOME entries." The
  Rule #46 META-CANARY is now load-bearing in name only. Future state-machine
  columns silently miss reaping; orphan-row symptom regresses to the
  Session 1 baseline.
- **Severity:** **MEDIUM** (it takes 2 sessions of drift for the failure to
  manifest, but the META-CANARY itself is what should have prevented it)
- **Mitigation:** Fix #11 SPLITS the reaper dict by axis from day-1:
  `WALKER_REAPER_CONFIGS` (22 entries; size-locked against
  `WALKER_AUTO_TRIGGERS` length) AND `STATE_MACHINE_REAPER_CONFIGS`
  (a separate dict in `app/services/reaper_configs.py` per Scout E line 271,
  starting EMPTY with explicit comment "add authenticode_chain_status here
  in Session 3 per Rule #47"). The size-lock META-CANARY asserts BOTH
  dicts' invariants separately. Scout E's "future follow-up" framing is
  structurally insufficient; the SPLIT must be authored in Session 2 even
  if the second dict starts empty. Rule #46 META-CANARY pattern: the absent
  thing has its own gate, even when it's currently empty.
- **Gate-canary (Rule #46):**
  ```python
  def test_walker_reaper_configs_size_locked_against_auto_triggers():
      from app.workers.walker_registry import WALKER_AUTO_TRIGGERS
      from app.workers.walker_registry import WALKER_REAPER_CONFIGS
      assert len(WALKER_REAPER_CONFIGS) == len(WALKER_AUTO_TRIGGERS), (
          "Drift: every walker auto-trigger MUST have a reaper config. "
          "ADD-ONLY this dict from walker_registry; non-walker columns "
          "(authenticode_chain, dotnet_decompile, windows_update_diff) "
          "ride STATE_MACHINE_REAPER_CONFIGS in app/services/reaper_configs.py."
      )
  
  def test_state_machine_reaper_dict_separate_from_walker():
      from app.services.reaper_configs import STATE_MACHINE_REAPER_CONFIGS
      from app.workers.walker_registry import WALKER_REAPER_CONFIGS
      walker_cols = {cfg.status_column for cfg in WALKER_REAPER_CONFIGS.values()}
      state_cols = set(STATE_MACHINE_REAPER_CONFIGS.keys())
      assert not (walker_cols & state_cols), (
          "Drift: a column may NOT appear in both dicts. "
          "Walker columns flow via auto-trigger registration; "
          "state-machine columns flow via explicit POST endpoints."
      )
  ```

### §SC5-NEW-SBOM-S2-SEAM-C: Fix #9 catalog re-classify × Fix #1 sbom_supported_for_format reads STALE pre-upload classification

- **Seam:** Scout A's Fix #9 recommendation (call `classify_firmware()` +
  consult catalog's `extraction_capability` AT post-process time) × Scout D's
  `sbom_supported_for_format` field (derived from `format_catalog.get_manifest(
  detected_format).has_sbom_strategy`).
- **Setup:** Scout D's Mandatory UX change #5 requires a banner driven by
  `firmware.extraction_capability` + `firmware.detected_format` read from a
  new `useFirmwareDetail` hook. The backend determines `sbom_supported_for_format`
  EITHER (a) at upload time (in `_post_process_pipeline` line 570 — single
  `detect_format()` call), OR (b) at SBOM-generate request time (re-derived
  via catalog lookup), OR (c) at both (re-derived twice with potential drift).
  Scout D doesn't specify WHICH layer derives it. Scout A's Fix #9 candidate
  shape replaces the hardcoded IF-ELIF chain with a catalog-driven dispatch
  using `EXTRACTION_CAPABILITY[detected]`. **Two reads of the same `detected`
  value:** one at `firmware_service.py:570` (upload time, before extraction);
  one at SBOM-generate request time (after extraction may have completed and
  COULD have re-stamped `firmware.detected_format` if Fix #9 includes
  re-classification).
- **Trigger:** Operator uploads a `firmware.zip` whose contents are a
  Linux rootfs. Upload-time `detect_format()` returns `zip_archive` (the
  outer container — at `firmware_service.py:570`). The pipeline expands the
  ZIP to `extracted/` and finds a rootfs; Fix #9 (if it includes re-classify)
  stamps `firmware.detected_format = "linux_firmware_blob"`. **Operator
  opens the SBOM page IMMEDIATELY** — the page polls `upload-status`, sees
  `detected_format='zip_archive'` (because the row was loaded BEFORE the
  re-classify commit landed) OR sees `linux_firmware_blob` (after). If the
  frontend caches the FIRST seen value via React state, the operator sees
  "Detected format: zip_archive — extraction capability: full" banner even
  though the row is now `linux_firmware_blob` (which has a different SBOM
  strategy applicability). Operator clicks "Generate SBOM" — the backend
  re-reads firmware in the new request handler, sees `linux_firmware_blob`,
  and dispatches the LINUX SBOM strategies. Banner says ZIP; backend
  generates LINUX SBOM. UX desync.
- **Outcome (un-mitigated):** Operator's mental model says "wairz thinks
  this is a ZIP, so I expect zero-or-few components", sees 200 components
  (the rootfs SBOM), distrusts the result. Worse: if Scout A's Fix #9
  pivots `_post_process_pipeline` to leave `detected_format=zip_archive`
  (no re-classify) but extracts to a Linux rootfs, the banner is correct
  but the SBOM result is "200 components from a ZIP", which is even more
  confusing.
- **Severity:** **MEDIUM** (UX desync; not a data-integrity issue; operator
  can refresh to resync)
- **Mitigation:** Fix #9's design MUST pin one of two contracts:
  (a) `firmware.detected_format` is the OUTER-CONTAINER format always, not
  the inner extracted format — Scout D's banner reads it directly; the
  SBOM-generate logic reads `firmware.extracted_path` to dispatch
  partition-aware strategies (today's behavior). OR (b)
  `firmware.detected_format` is re-stamped to the INNER rootfs format
  after extraction succeeds; Scout D's banner reads it; the SBOM-generate
  logic dispatches against the INNER format. The Pydantic Literal
  `DetectedFormat` already enumerates BOTH — `ZIP_ARCHIVE` and
  `LINUX_FIRMWARE_BLOB` are distinct values; pick one semantic and stick
  with it. Scout D + Scout A must converge on (a) for backward compatibility.
- **Gate-canary (Rule #46):**
  ```python
  async def test_detected_format_pinned_to_outer_container():
      """Fix #9 + Fix #1 alignment — detected_format describes the upload,
      not the inner extracted shape. SBOM dispatch reads extracted_path /
      detection_roots, NOT detected_format.
      """
      fw = create_firmware_with_zip_containing_linux_rootfs()
      await _post_process_pipeline(db, fw, update_stage=True)
      assert fw.detected_format == "zip_archive"  # OUTER, not LINUX_FIRMWARE_BLOB
      assert "extracted" in fw.extracted_path
  ```

### §SC5-NEW-SBOM-S2-SEAM-D: Fix #9 unknown-format fall-through × Fix #1 force_rescan idempotency

- **Seam:** Scout A Assumption #1 (`_post_process_pipeline` extension matching
  is HARDCODED) × Scout D's Mandatory UX change #4 (force-regenerate gating)
  × Scout E's Rule #33 .a 409 idempotency check for sbom_status.
- **Setup:** Scout D's "Force-Regenerate" gating disables the button while
  `sbom_status in ('queued','running')`. But for an UNKNOWN-format firmware
  (Scout C §SC5-NEW-SBOM-S2-α), the SBOM /generate runner short-circuits
  with `sbom_status='completed'` and `components=0`. Operator's force-regen
  click immediately succeeds → another 0-component pass. **Now extend with
  Fix #9's unknown-format fall-through**: Fix #9 may decide to TRY
  `unpack_firmware_job` on unknown formats (Scout A's Rule #52 candidate
  shape calls this "extraction_capability=unknown → fall through to unblob").
  The job runs in the background, takes 5-30 minutes, mutates
  `firmware.extracted_path` upon success. **During those 30 minutes,
  `sbom_status` stays at `completed`** (from the FIRST generate run that
  saw empty extracted_path).
- **Trigger:** Operator uploads unknown-format firmware → first auto-gen
  produces 0 components → operator triggers Fix #9-style unblob-fallback
  (perhaps via a Scout D-style "Try Generic Strategy" button). Unblob job
  enqueues; runs 8 minutes; succeeds; produces a rich extracted_path.
  Operator clicks "Generate SBOM" again. The 409 idempotency check sees
  `sbom_status='completed'` (NOT in `queued`/`running`), allows the POST.
  But the cached 0-component result is returned (Fix #1's force_rescan=False
  path returns cached if `count > 0`, but with `count=0` and `force_rescan=False`
  the runner re-runs from scratch — UNLESS the runner short-circuits on
  `sbom_status='completed'`). **The contract is ambiguous**: does
  `sbom_status='completed'` mean "the last run completed successfully" OR
  "the components are still valid for the CURRENT extracted_path"?
- **Outcome (un-mitigated):** If "completed = result is current," the
  newly-extracted firmware shows 0 components forever until the operator
  clicks force_rescan. The Scout D button-gating doesn't help because
  `sbom_status` is `completed`, not `queued`/`running`. If "completed =
  last run completed," the runner re-runs; but then `sbom_components` rows
  count is 0, and the force_rescan-only DELETE never fires, leaving inconsistent
  state if some partial rows survived a prior crash.
- **Severity:** **HIGH** (sbom_status semantics are ambiguous across the
  fixes; operator sees stale 0-component result after the firmware has
  been re-extracted)
- **Mitigation:** Fix #1's `sbom_status` semantics must be pinned: "completed
  means the run completed and reflects the firmware's STATE-AT-THE-TIME-OF-RUN."
  Whenever `firmware.extracted_path` changes (Fix #9 re-extracts it), reset
  `sbom_status='idle'` AND `sbom_finished_at=None` AND clear `sbom_components`
  rows. The reset is a single UPDATE statement that Fix #9 fires alongside
  the extracted_path assignment. The Rule #47 consumer-hook enumeration
  applies — every code path that mutates `firmware.extracted_path` ALSO
  resets the downstream `sbom_status` AND `vuln_scan_status` to `idle`.
- **Gate-canary (Rule #46):**
  ```python
  async def test_extracted_path_change_resets_sbom_status():
      fw = create_firmware(detected_format='unknown',
                            extracted_path=None,
                            sbom_status='completed')
      # Operator triggers Fix #9 fall-through unblob
      await _run_unpack_background(fw.id)
      db_session.refresh(fw)
      # SBOM status MUST reset because the underlying firmware changed
      assert fw.sbom_status == 'idle'
      assert fw.vuln_scan_status == 'idle'
  ```

### §SC5-NEW-SBOM-S2-SEAM-E: Frontend rebuild × SECURITY_SCAN_TIMEOUT removal × harness rule auto-frontend-long-op-no-explicit-timeout

- **Seam:** Scout D's section "SECURITY_SCAN_TIMEOUT post-conversion"
  (drop the 600s override from `generateSbom`) × `.claude/harness.json`
  rule `auto-frontend-long-op-no-explicit-timeout` × Rule #26 frontend
  rebuild discipline.
- **Setup:** Scout D requires removing the `timeout: SECURITY_SCAN_TIMEOUT`
  override at `frontend/src/api/sbom.ts:38`. Today the
  `auto-frontend-long-op-no-explicit-timeout` harness rule INSISTS on the
  presence of the timeout override (it flags any 202-ack endpoint missing
  the override). Scout D claims "/generate is in the verb allowlist; if the
  conversion REMOVES the `timeout: SECURITY_SCAN_TIMEOUT` line, the regex
  no longer matches anyway."
- **Trigger:** Session 2 lands the conversion (drops the timeout override).
  Harness rule fires AGAIN because the rule's regex matches the absence-of
  -timeout in a verb-allowlist endpoint? OR the verb allowlist itself is
  managed elsewhere? Either way, the harness developer trusts Scout D's
  claim without empirical verification. **The rebuild succeeds** (`docker
  compose up -d --build frontend`); the harness rule fires ONCE on the
  next commit affecting `sbom.ts`; a future developer reads the harness
  rule as a stale flag and silently adds the `timeout: SECURITY_SCAN_TIMEOUT`
  back in (because the harness keeps flagging it). The 30s default axios
  floor regresses to 600s.
- **Outcome (un-mitigated):** The 600s override on a 202-ack endpoint is
  Rule #29 derivation discipline violation — the ack drops to sub-second
  so the timeout is structurally wrong. A failed-to-ack background launch
  blocks the operator's tab for 600s (10 minutes!) on what should be a
  sub-second connection-refused. Combined with §SC5-NEW-SBOM-S2-λ
  (polling DB pool exhaustion), 10 minutes of failed-ack delay × N tabs
  becomes a 100% browser hang.
- **Severity:** **MEDIUM** (regression-via-harness-confusion; not directly
  exploitable but very confusing to debug — exactly the Rule #21 failure
  mode where docs + harness + rule drift apart)
- **Mitigation:** Fix #1's conversion commit (a) drops the
  `timeout: SECURITY_SCAN_TIMEOUT` override at sbom.ts:38, (b) ADDS an
  inline comment `// Rule #29 derivation: 202+polling ack is sub-second;
  no override needed.` (matches the vuln-scan comment shape at sbom.ts:82-86),
  (c) updates `.claude/harness.json` rule's verb-allowlist to EXPLICITLY
  list `/generate` as a 202+polling endpoint so the rule doesn't fire on
  the absence. The harness rule's MATCHING-AGAINST-FILES list must
  explicitly enumerate Session 2's converted endpoint; trusting "the regex
  no longer matches" is the Rule #17 silent-CLI-exit analog — verify the
  harness flag-fire count drops to 0 post-conversion (canary the harness).
- **Gate-canary (Rule #46):**
  ```python
  def test_sbom_generate_has_no_timeout_override():
      """Verify Session 2's conversion correctly removed SECURITY_SCAN_TIMEOUT
      from generateSbom AND added the Rule #29 derivation comment.
      """
      src = Path("frontend/src/api/sbom.ts").read_text()
      assert "SECURITY_SCAN_TIMEOUT" not in src.split("export const generateSbom")[1].split("export const ")[0]
      # The Rule #29 comment exists nearby
      gen_chunk = src.split("export const generateSbom")[1][:500]
      assert "Rule #29" in gen_chunk or "sub-second" in gen_chunk
  ```

### §SC5-NEW-SBOM-S2-SEAM-F: Fix #11 reaper × Fix #1 background runner race during lifespan startup

- **Seam:** Scout E Fix #11 reaper loop at lifespan startup (sweep WALKER + 5
  existing state-machine reapers — `device_dump`, `cve_match`, `vuln_scan`,
  `upload_stage`, `bare_metal_audit` per Scout E line 27) × Scout E Fix #1's
  new `sbom_status` reaper (NO grace window — line 130-156 of
  `wave1-scout-E-state-machine.md`).
- **Setup:** Scout E's Fix #1 design says the sbom-generate reaper has NO
  grace window because "the work is in-process, 30-120s typical, fully
  bounded by the 409 dedup check" (line 138). But the timing assumption
  doesn't survive the broader Session 2 sweep — Fix #11 ALSO runs at
  lifespan startup, and the lifespan startup is a single sequential
  pass. The current order is: (1) device-dump reaper, (2) cve-match
  reaper, (3) vuln-scan reaper, (4) upload_stage reaper (15-min grace),
  (5) bare-metal-audit reaper (no grace). Fix #1 ADDS a 6th reaper for
  `sbom_status`. Fix #11 ADDS a 7th block iterating 22 walker reapers.
  Each reaper opens its own `async_session_factory()` session (lines 136,
  175, 219, 276, 325 in main.py), runs a single UPDATE, commits, closes.
  Total cumulative DB-connection allocations at lifespan startup: 5 + 1 +
  22 = **28 sequential session-open/commit/close cycles**.
- **Trigger:** Backend restarts during a high-load triage session. PostgreSQL's
  prepared-statement cache invalidates; each new session pays the round-trip
  cost. With pool min=5 (current config), and lifespan startup happening
  BEFORE the pool is "warmed up" by application use, the 28 sequential
  cycles can cumulatively take 3-15 seconds. **During this window, the
  backend is NOT accepting requests** (uvicorn's lifespan is BLOCKING).
- **Outcome (un-mitigated):** Operators see a 5-15 second blackout after
  every backend restart. The Scout D auto-resume polling kicks in at 2s
  intervals — each tab issues 3-7 failed polls before the backend comes
  up. The failed polls all retry. When the backend DOES come up, the
  polling burst hits 50-100 concurrent SELECTs against an unwarmed pool;
  the pool fills; the firmware-list endpoint times out for new operators.
  The 5-15 second startup blackout cascades into a 30-60 second user-visible
  slowdown.
- **Severity:** **MEDIUM** (operator-visible slowdown at restart;
  cosmetic-only after the burst dies down)
- **Mitigation:** Consolidate the 28 sequential reapers into a SINGLE
  session opened once with a single transaction. Each UPDATE flushes
  but the COMMIT happens once at the end:
  ```python
  async with async_session_factory() as db:
      for reaper_func in ALL_REAPERS:
          await reaper_func(db)  # runs an UPDATE; uses session
      await db.commit()  # ONE commit
  ```
  Scout E's Option B already moves toward this shape via the unified loop;
  the cross-cutting consolidation across all 7 reaper blocks completes the
  pattern. The Rule #46 META-CANARY measures lifespan startup time and
  asserts <2s on a representative DB fixture.
- **Gate-canary (Rule #46):**
  ```python
  async def test_lifespan_startup_reapers_complete_under_2s():
      """Session 2's combined reaper sweep must not blackout the backend.
      
      Combined 28-reaper-call lifespan path must run in a single
      AsyncSession + single commit. Reference: Scout E Option B + the
      W2-β cross-feature §SC5-NEW-SBOM-S2-SEAM-F.
      """
      from app.main import lifespan
      from app.main import app
      import time
      start = time.monotonic()
      async with lifespan(app):
          pass
      elapsed = time.monotonic() - start
      assert elapsed < 2.0, f"lifespan startup took {elapsed:.2f}s — reaper consolidation needed"
  ```

### §SC5-NEW-SBOM-S2-SEAM-G: Walker un-gating × Fix #9 unblob fallback × cascade on 0-HW-blob unknown firmware

- **Seam:** Session 1 Fix #3 (walker fan-out un-gating — every
  `_run_hardware_firmware_detection_safe` fires 26 walkers regardless of
  HW-blob count) × Scout A Fix #9 candidate (post-process invokes
  `unpack_firmware()` for unknown-format firmware) × Scout C §SC5-NEW-SBOM-S2-ζ
  (archive-bomb depth bounding) × Scout E new sbom_status state machine.
- **Setup:** Session 1's Fix #3 un-gated walker fan-out: even 0-HW-blob
  firmware fire all 26 walkers. Scout A's Fix #9 candidate makes
  `_post_process_pipeline` fall through to `unpack_firmware()` for unknown
  formats. The combined behavior: operator uploads unknown firmware →
  Fix #9 spawns `unpack_firmware_job` → 5-30 minutes pass → unblob succeeds
  → `extracted_path` populates → `_run_hardware_firmware_detection_safe`
  fires → 26 walkers fan out. **NOW combine with Scout C §SC5-NEW-SBOM-S2-ζ
  (archive-bomb)**: the unknown-format firmware was a depth-50 zip-bomb.
  Unblob produces 100,000 files at depth 50. The 26 walkers each
  `scandir()` the tree (each walker via Rule #16
  `get_detection_roots(firmware)`).
- **Trigger:** 26 walkers × scandir over 100,000 files × depth 50 ≈
  worst-case ~2.6 million `stat()` calls. The walker DB sessions
  (`async_session_factory()` per Rule #39 .safe each) accumulate connection
  references; the sequential walker dispatch per `_fire_walker_auto_triggers`
  (firmware_service.py:825-839) means worst-case 26 × wall-time-per-walker.
  Operator's typical 5-firmware burst now creates 5 × 26 = 130 sequential
  walker invocations, each scanning 100,000 files.
- **Outcome (un-mitigated):** Worker container CPU pegs at 100% for
  hours; Scout C §SC5-NEW-SBOM-S2-ζ catalogues the inode exhaustion
  separately, but the WALKER fan-out cost on inflated-extraction firmware
  is the additional cost vector that Scout C didn't combine. Polling
  endpoints time out; the operator-typical workflow (poll every 2s on
  `sbom_status`) sees `running → running → running → ...` for hours.
  Operator force-restarts the backend; the §SC5-NEW-SBOM-S2-SEAM-F
  reaper-consolidation cost cascades.
- **Severity:** **HIGH** (zip-bomb upload → 6+ hour worker CPU peg →
  cascade restart)
- **Mitigation:** Fix #9 includes a hard cap on the extracted tree size
  BEFORE walker fan-out fires: if `find <extracted_path> | wc -l > 50000`
  OR `du -s <extracted_path> > 50 GB`, mark the firmware with
  `device_metadata.extraction_oversized=True` AND SKIP the walker fan-out
  AND set every `*_walk_status='skipped'` (NEW state — must extend Pydantic
  Literal AND DB CHECK per Rule #25 single-slice exception #2). The
  Scout C §SC5-NEW-SBOM-S2-ζ bound (unblob `--depth 10
  --max-extraction-bytes`) is the FIRST gate; the walker-fan-out skip is
  the SECOND gate.
- **Gate-canary (Rule #46):**
  ```python
  async def test_oversized_extraction_skips_walker_fanout():
      fw = create_firmware_with_oversized_extraction(file_count=100_000)
      await _run_hardware_firmware_detection_safe(fw.id, fw.extracted_path)
      db_session.refresh(fw)
      # Walkers MUST NOT have fired
      assert fw.bcd_walk_status == 'skipped'
      assert fw.evtx_walk_status == 'skipped'
      assert fw.device_metadata.get("extraction_oversized") is True
  ```

## Companion Failure Mode Cascade

If Session 2 ships Fix #1 + Fix #6 + Fix #9 (minimum scope per Scout B) + Fix #11
+ broader create_task sweep, but ONLY mitigates the Scout C §SC5-NEW-SBOM-S2-α..λ
attacks and SKIPS the 7 NEW SEAM attacks above, the worst-case operator session
goes like this:

1. **Operator triage burst:** 5 unknown-format firmware uploaded in 30 seconds
   (operator-typical triage workflow for vendor disclosure batches).
2. **§SC5-NEW-SBOM-S2-SEAM-A fires:** broader create_task sweep covered the 5
   router sites but missed `_post_process_pipeline:818`. Under GC pressure,
   1 of 5 firmware loses its detached walker fan-out.
3. **§SC5-NEW-SBOM-S2-SEAM-G fires:** the 4 surviving firmware were
   zip-bombs (operator was triaging a disclosure batch from an untrusted
   vendor). Fix #9 invokes unblob; unblob lacks the depth cap (§SC5-NEW-SBOM-S2-ζ
   unmitigated); 4 worker containers peg CPU.
4. **§SC5-NEW-SBOM-S2-SEAM-C fires:** operator opens SbomPage. Banner says
   "Detected format: zip_archive — extraction capability: full" (the OUTER
   container). The SBOM result shows 200 components from the inner Linux
   rootfs (extracted by Fix #9 unblob). Operator distrusts the result —
   "is this for the ZIP or the rootfs?"
5. **§SC5-NEW-SBOM-S2-SEAM-D fires:** operator clicks "Generate SBOM" again
   to force a re-derivation. `sbom_status='completed'` from a prior 0-component
   run; the 409 check allows the POST; runner regenerates against the CURRENT
   extracted_path; result is 200 components but components rows aren't
   cleared from a prior failed run; inconsistent UI state.
6. **§SC5-NEW-SBOM-S2-SEAM-E fires:** harness rule
   `auto-frontend-long-op-no-explicit-timeout` continues to flag sbom.ts:38
   for the absence of timeout override; future developer adds it back; 30s
   floor regresses to 600s; operator hangs on next failed-ack.
7. **§SC5-NEW-SBOM-S2-SEAM-F fires:** operator restarts the backend to
   escape the CPU peg. Lifespan startup runs 28 sequential reaper cycles
   (consolidated to 1 session in Fix #11 but each block STILL opens its own
   session per Scout E's Option B as currently designed); 5-15 second
   backend blackout cascades into 30-60 second user-visible slowdown.
8. **§SC5-NEW-SBOM-S2-SEAM-B fires:** 3 weeks later, a Session 4 developer
   adds `cab_extraction_status` to the wrong dict; the size-lock META-CANARY
   was weakened in Session 3 (`==23` not `== len(WALKER_AUTO_TRIGGERS)`);
   the cab_extraction reaper silently doesn't fire; orphan rows resume.
9. **Operator perceives Session 2 made things WORSE.** The Scout C+D
   §SC5-NEW-SBOM-S2-α..λ canaries all PASSED in CI. The seam attacks were
   never individually tested.
10. **Files a critical bug.** Fix sweep gets reverted; we're back to the
    Session 1 baseline.

The cross-feature critique stage (W2-β) exists precisely to catch this
cascade BEFORE shipping. Each seam attack is individually low-likelihood;
together they're the failure mode of large surface-area sessions.

## Pre-Cutover Robustness Checklist

| Session 2 Fix | Required Gate-Canaries BEFORE Merge (Wave-1 + NEW W2-β SEAM) |
|---|---|
| **Fix #1** (SBOM /generate 202+polling + sbom_status) | Scout C §SC5-NEW-SBOM-S2-α (unknown-format graceful-degrade) + §SC5-NEW-SBOM-S2-β (memory-bound 30 GB extracted) + §SC5-NEW-SBOM-S2-ι (sbom-vuln race 409) + §SC5-NEW-SBOM-S2-λ (polling backoff) + Scout E Rule #48 5-part alignment + **NEW §SC5-NEW-SBOM-S2-SEAM-C** (detected_format pinned to outer container) + **NEW §SC5-NEW-SBOM-S2-SEAM-D** (extracted_path change resets sbom_status) + **NEW §SC5-NEW-SBOM-S2-SEAM-E** (no SECURITY_SCAN_TIMEOUT override on /generate) |
| **Fix #6** (grype force_rescan transactional) | Scout C §SC5-NEW-SBOM-S2-η (concurrent 409 verification) + Session 1 §SC5-NEW-SBOM-μ (transactional rollback) |
| **Fix #9** (`_post_process_pipeline` unblob fallback for non-shortcut formats) | Scout C §SC5-NEW-SBOM-S2-ε (polyglot precedence) + §SC5-NEW-SBOM-S2-ζ (archive-bomb bounded recursion) + **NEW §SC5-NEW-SBOM-S2-SEAM-C** (detected_format semantic) + **NEW §SC5-NEW-SBOM-S2-SEAM-G** (oversized-extraction walker-fanout skip) |
| **Fix #11** (walker reaper sweep) | Scout C §SC5-NEW-SBOM-S2-γ (state-machine + walker split — TWO axes) + §SC5-NEW-SBOM-S2-θ (operator-supplied walker state-set discipline) + **NEW §SC5-NEW-SBOM-S2-SEAM-B** (size-lock META-CANARY structural completeness) + **NEW §SC5-NEW-SBOM-S2-SEAM-F** (consolidated lifespan startup < 2s) |
| **Broader create_task sweep** | Scout C §SC5-NEW-SBOM-S2-κ (router width-canary) + **NEW §SC5-NEW-SBOM-S2-SEAM-A** (services width-canary covers `_post_process_pipeline:818`) |
| **Frontend rebuild** | Existing Rule #26 + harness rule + Scout D's section "SECURITY_SCAN_TIMEOUT post-conversion" + **NEW §SC5-NEW-SBOM-S2-SEAM-E** (harness rule allowlist updated in same commit) |
| **NEW closed-grammar surfaces** (deferred to Session 3+ per Scout B Rule-of-Four candidate) | Scout C §SC5-NEW-SBOM-S2-δ (path-cross-check + extra:forbid + closed Literals + Rule #46 META-CANARY) — not in Session 2 scope but the framework gates ALL future Rule #52 instances |

## Recommendations for W2-α / W2-γ

1. **W2-α convergence MUST resolve §SC5-NEW-SBOM-S2-SEAM-C semantic pin
   IN THIS SESSION.** Pick: `detected_format` describes the outer
   container (today's behavior, backward-compatible) OR pivots to the
   inner extracted shape (cleaner but breaking). Scout A's Fix #9
   candidate is silent on this — W2-α picks one and documents the
   choice in the conversion commit message. **Recommended: (a) outer
   container — backward compatible; document it as Rule #47 consumer-hook
   contract.**

2. **W2-α MUST require §SC5-NEW-SBOM-S2-SEAM-D's mitigation in Fix #9's
   contract.** The Rule #47 enumeration — every code path that mutates
   `firmware.extracted_path` MUST also reset downstream `sbom_status` +
   `vuln_scan_status` to `idle` AND clear `sbom_components` rows.
   Without this, Fix #9's unblob-fall-through silently strands stale SBOM
   results. Apply also to Fix #9's REPROCESSING path (operator clicks
   "Reprocess" — same shape).

3. **W2-α MUST split Fix #11's reaper dict by axis from day-1**
   (§SC5-NEW-SBOM-S2-SEAM-B). Scout E's "future follow-up" framing is
   structurally insufficient. The `STATE_MACHINE_REAPER_CONFIGS` dict
   ships EMPTY but EXISTS in Session 2 with the size-lock META-CANARY
   already enforcing the separation invariant. Session 3 can populate it
   incrementally without weakening the gate.

4. **W2-α MUST extend §SC5-NEW-SBOM-S2-SEAM-A's width-canary to
   `backend/app/services/firmware_service.py:818`** specifically.
   The router-scoped grep Scout C proposed misses this site. Run BOTH
   greps as part of the broader create_task sweep:
   ```
   grep -rn 'asyncio\.create_task' backend/app/routers/   # Scout C scope
   grep -rn 'asyncio\.create_task' backend/app/services/  # SEAM-A extension
   ```
   Migrate `firmware_service.py:818` to `_spawn_background_task` (which
   per Scout B recommendation #5 lives in `app/utils/background.py` as
   a shared utility).

5. **W2-γ Rule #28 yardstick re-measure with SEAM attacks included.**
   Scout C estimated +1170 LOC for Session 2 (Fix #1 +300 + Fix #9 +140 +
   Fix #11 +220 + Fix #6 +90 + create_task sweep +80 + tests). The
   7 NEW SEAM attack mitigations add:
   - SEAM-A: +20 LOC (extend create_task sweep + canary)
   - SEAM-B: +40 LOC (split reaper dict + canary + comment) 
   - SEAM-C: +15 LOC (pinned semantic + canary)
   - SEAM-D: +40 LOC (Rule #47 hook on extracted_path mutation + canary)
   - SEAM-E: +20 LOC (harness rule update + comment + canary)
   - SEAM-F: +30 LOC (lifespan reaper consolidation + canary)
   - SEAM-G: +60 LOC (oversized-extraction gate + new 'skipped' literal +
     Rule #25 single-slice cross-stack alignment commit)
   - **Net: +225 LOC across 7 SEAM mitigations = +1395 net LOC total**
   Drift-adjusted total ~1395 net LOC; +20% above Scout C's estimate;
   pushes Session 2 to the W2-γ envelope ceiling. **W2-γ should reaffirm
   SINGLE-SESSION-FEASIBLE only if Fix #6's force_rescan and Fix #9's
   unblob fall-through ship in CO-COMMITTED minimum-viable form** —
   the cross-stack alignment commit for SEAM-G (`*_walk_status='skipped'`
   new literal) is a Rule #48 5-part single-slice that must NOT be split.

6. **W2-α should explicitly require the move of `_spawn_background_task`
   to `app/utils/background.py`** (Scout C recommendation #5) AND CONFIRM
   that the new module uses **lazy import + frozen-set semantics** to avoid
   import-order race: `_BACKGROUND_TASKS: set[asyncio.Task] = set()` at
   module scope is shared across all importers IF the import happens at
   the same module load — but if router A imports `_spawn_background_task`
   before router B's module loads, the set IS shared (Python's module
   cache). The risk is `_spawn_background_task` being defined multiple
   times across routers from copy-paste; consolidation eliminates that
   risk. Verify via canary that ALL routers import from the same module
   (no per-router redefinition).

7. **For W2-β future iteration: cross-feature the SEAM attacks against
   the Rule #52 closed-grammar refactor candidates (Scout B).** The
   Fix #9 extraction-strategy refactor (Scout B's Rule-of-Four candidate)
   would CONVERGE the SEAM-C semantic question by making
   `extraction_capability` the YAML-declared dispatch key (operator-facing
   Pydantic Literal — `full`/`partial`/`none`/`unknown` — closed). The
   SEAM-D reset-on-extracted_path-mutation would be a YAML
   `post_extraction.next_actions` declaration (closed Literal —
   `reset_sbom_status`/`reset_vuln_scan_status`/...). The SEAM-G
   oversized-extraction skip becomes a YAML `resource_limits.max_files`
   declaration. **Five of the seven SEAM attacks dissolve into the
   closed-grammar refactor when it ships.** This is the structural
   argument for prioritizing the Rule-of-Four candidate AFTER ICS
   Session 2 closes Rule-of-Three.

## Cross-References

| # | Path | Lines | Purpose |
|---|---|---|---|
| 1 | `backend/app/routers/sbom.py` | 25-37 | `_spawn_background_task` — Session 1 Fix #8 GC guard |
| 2 | `backend/app/routers/sbom.py` | 142-252 | Current synchronous `/generate` — Fix #1 conversion target |
| 3 | `backend/app/routers/sbom.py` | 449-547 | `_run_vuln_scan_background` — Fix #1 reference shape |
| 4 | `backend/app/routers/sbom.py` | 549-620 | `/vulnerabilities/scan` 202+polling — Fix #1 template |
| 5 | `backend/app/services/firmware_service.py` | 544-822 | `_post_process_pipeline` — Fix #9 target |
| 6 | `backend/app/services/firmware_service.py` | 818 | **SEAM-A:** bare create_task missed by Scout C's router-scoped grep |
| 7 | `backend/app/services/firmware_service.py` | 825-839 | `_fire_walker_auto_triggers` — SEAM-G walker fan-out point |
| 8 | `backend/app/services/grype_service.py` | 60-265 | `scan_with_grype` — Fix #6 transactional fix target |
| 9 | `backend/app/services/grype_service.py` | 160-165 | **Confirmed** unconditional DELETE — Fix #6 must add force_rescan gating |
| 10 | `backend/app/services/sbom/service.py` | 239-301 | `generate_sbom` — sync executor entry |
| 11 | `backend/app/main.py` | 123-348 | Lifespan reapers (5 inlined) — SEAM-F consolidation target |
| 12 | `backend/app/workers/walker_registry.py` | 101-158 | `WALKER_AUTO_TRIGGERS` — Fix #11 + SEAM-B target |
| 13 | `backend/app/workers/walker_registry.py` | 193 | Eager `WALKER_AUTO_TRIGGERS` cache list |
| 14 | `backend/app/services/format_detection.py` | 95-134 | `_build_capability_tables` — SEAM-C source-of-truth |
| 15 | `backend/app/services/format_detection.py` | 187-190 | `EXTRACTION_CAPABILITY, CAPABILITY_NOTES` import-time snapshot |
| 16 | `backend/app/schemas/firmware.py` | 231-260 | `FirmwareUploadStatusResponse` — SEAM-C interface |
| 17 | `backend/app/models/firmware.py` | 113-966 | 22 walker `*_walk_status` columns + 3 partial-coverage (`authenticode_chain_status`, `dotnet_decompile_status`, `windows_update_diff_status`) |
| 18 | `frontend/src/api/sbom.ts` | 28-42 | `generateSbom` — SEAM-E timeout-removal target |
| 19 | `frontend/src/api/sbom.ts` | 82-86 | vuln-scan no-timeout comment — SEAM-E template |
| 20 | `frontend/src/api/timeouts.ts` | 43 | `SECURITY_SCAN_TIMEOUT=600_000` — drop from `generateSbom`, keep for `exportSbom` |
| 21 | `.claude/harness.json` | 170-174 | `auto-frontend-long-op-no-explicit-timeout` rule — SEAM-E coordination |
| 22 | `.planning/research/sbom-vuln-scan-session2-2026-05-21/wave1-scout-A-architecture.md` | 70-156 | 9 hardcoded format-assumption audits — SEAM-G + closed-grammar refactor scope |
| 23 | `.planning/research/sbom-vuln-scan-session2-2026-05-21/wave1-scout-C-redteam.md` | 41-568 | 11 §SC5-NEW-SBOM-S2-α..λ single-fix attacks |
| 24 | `.planning/research/sbom-vuln-scan-session2-2026-05-21/wave1-scout-D-operator-ux.md` | 128-143 | Mandatory UX changes table — SEAM-C + SEAM-E inputs |
| 25 | `.planning/research/sbom-vuln-scan-session2-2026-05-21/wave1-scout-E-state-machine.md` | 21-23 | 3 partial-coverage non-walker columns — SEAM-B input |
| 26 | `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave2-beta-blowup.md` | 12-279 | Session 1 W2-β §SC5-NEW-SBOM-α..π precedent |
