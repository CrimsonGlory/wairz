# Wave-2 α — Convergence Synthesis (ALPHA persona)

> Investigation date: 2026-05-21
> Synthesizes: 5 Wave-1 scout reports (A/B/C/D/E) + opening baseline
> Branch tip at synthesis time: `4ecaa5b` (main)
> User-stated symptom: "SBOM generation + vulnerability scanning appear to have regressed"

## Executive Summary

The operator-reported "SBOM + vuln-scan regressed" symptom is **the visible surface of a deeper walker-orchestration collapse**, not a defect in the SBOM or vuln-scan endpoints themselves. Scout C's live-DB probe confirms cluster-wide zeros across 4 walker artefact tables since 2026-05-12, falsely-complete `upload_stage='ready'` masking the regression, and one bare_metal_audit row stuck `queued` for 6 days (Scout C lines 14-20, 67-73, 219-232). The TOP THREE convergent root causes are: **(1) `unpack.py:106` early-exit gate `if count <= 0: return` short-circuits ALL 25+ walkers when HW-blob detection yields zero rows** (Scout C lines 16, 87-89, 138-140, 162-166; Scout B sealed-finding line 215; Scout A line 195); **(2) `auto_bare_metal_audit_firmware_safe` unregistered in `walker_registry.py`** despite shipping with its Rule #39 triplet on 2026-05-19 (Scout C lines 15, 140-144, 268-272; Scout E line 137); **(3) the upload-pipeline path skips full unpack so the SBOM/vuln-scan surface sees sparse extraction trees for non-Android, non-tarball uploads** (Scout A lines 172-173, line 31; Scout B lines 36-39). The shipping order is: rebuild frontend image first (cheap; Scout D's 27-hour stale-bundle audit), then ship the walker fan-out un-gating + bare_metal registration in one Rule #25 per-piece sub-task chain (highest-impact single fix per Scout C line 165), then expand orphan reaper coverage to ALL walker `*_walk_status` columns plus `bare_metal_audit_status` + `upload_stage` (Scout E #3-4, Scout B sealed-finding-2, Scout D Conclusion 2). The work is **MEDIUM-confidence single-session feasible** if scoped to the top-3 fixes; the deferred items (Rule #44 cross-firmware lookup for bare_metal walker, frontend escape-hatch button for stuck-running rows, SBOM-generate Rule #33 conversion or tier re-tier) ship in follow-up sessions.

## Wave-1 Cross-Reference Matrix

| Finding | Scout A | Scout B | Scout C | Scout D | Scout E | Cross-confirmed? |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| SBOM + vuln-scan NEVER in WALKER_AUTO_TRIGGERS (not Rule #47 orphan) | A:Exec/9 | B:Exec/14 | implicit | — | E:Exec/11, E:101-137 | YES (3 scouts) |
| `_post_process_pipeline` skips full unpack for generic ZIPs → sparse SBOM | A:172-173 | B:36-39 | — | — | E:140-148 | YES (3 scouts) |
| `unpack.py:106 if count<=0: return` gates all walker fan-out | A:191 | B:203 | C:16, 87-89, 138-140 | — | — | YES (3 scouts) |
| `auto_bare_metal_audit_firmware_safe` unregistered | — | — | C:15, 140-144, 268-272 | — | E:137 | PARTIAL (2 scouts, Scout C is definitive) |
| `vuln_scan_status` orphan reaper PRESENT (`3d2454b` shipped) | A:145, 214 | B:99-108 | C:131-133 | D:43, 106 | E:36, 74-77, 162-166 | YES (5 scouts) |
| `upload_stage` orphan reaper MISSING in main.py | A:142 (implicit) | B:38, 193, 207 | C:38 (all rows 'ready') | — | E:34, 70-78, 167-170 | YES (4 scouts) |
| `bare_metal_audit_status` orphan reaper MISSING | — | — | C:67-73, 134 | — | E:39, 171-174 | YES (2 scouts) |
| All 22 walker `*_walk_status` lack orphan reapers | — | — | C:141, 164 | — | E:78, 162-174 | YES (2 scouts) |
| Frontend bundle 27h stale | A:227 (not flagged) | — | — | D:84, 110-115 | — | UNIQUE (Scout D) |
| `POST /sbom/generate` is sync but tiered as 202+polling | A:166 | — | — | D:69, 131 | E:11, 38, 156-160 | YES (3 scouts) |
| `_run_vuln_scan_background` task lacks strong reference (GC risk) | — | — | — | D:78 | — | UNIQUE (Scout D) |
| `scan_with_grype` ignores `force_rescan` → row doubling | A:164 | — | — | — | — | UNIQUE (Scout A) |
| `SbomComponent` UniqueConstraint with no ON CONFLICT | A:162 | — | — | — | — | UNIQUE (Scout A) |
| 12 LiveCanary tests blocked by FK breakage (`memory_dump_image`) | — | — | implicit | — | — | UNIQUE (baseline) |
| Pre-2026-05-12 firmware (incl `0977b260` 2026-05-01) sparse SBOM, no walker output | — | — | C:Exec/20, 188 | — | — | UNIQUE (Scout C) |
| TMS320 row stuck `bare_metal_audit_status='queued'` 6 days | — | — | C:67-73, 134, 219-232 | — | — | UNIQUE (Scout C) |
| `unpack_stage` column NULL for ALL 25 rows (deprecated by `upload_stage`) | — | — | C:41-46 | — | — | UNIQUE (Scout C) |
| Wave-1 missed direct-grep of `auto_bare_metal_audit_*` in walker_registry import block | — | — | C:140-141, 253-255 | — | E:137 | RESOLVED |

## Contradictions Resolved

### Contradiction 1: "Earliest regression date" — Scout B says 2026-05-07; Scout C says 2026-05-01

- **Evidence weight:**
  - Scout B identifies `847eae9` + `8f54a24` (both 2026-05-07) as the suspect-commit chain (Scout B lines 25-56) for the Rule #47 + Rule #51 worked examples.
  - Scout C identifies `0977b260` (usb-stick-developer.zip, 2026-05-01) as the **earliest firmware row with zero walker output** (Scout C line 20, 188).
- **Resolution:** Both are correct but answer DIFFERENT questions.
  - Scout B's date is the **earliest commit that introduced regression-shape**: 2026-05-07 is when the upload-pipeline 202+polling refactor landed an invisible orphan, and the vuln-scan 202+polling refactor landed Rule #51 companion-failure-mode gaps.
  - Scout C's date is the **earliest firmware row that demonstrably failed**: `0977b260` was uploaded BEFORE the `847eae9` regression introduction, so its zero-walker-output is a SEPARATE pre-existing condition — likely from the `count <= 0` gate at `unpack.py:106` having always existed.
- **Implication:** The walker fan-out gate (Scout C primary finding) is OLDER than the 2026-05-07 commit chain — it predates the regression window entirely. The 2026-05-07 commits introduced FRESH regressions (upload-orphan + vuln-scan rate-limit + reaper-missing), all of which have been addressed (`5f3d195`, `12955a6`, `f6dbc7b`, `3d2454b`). The CURRENT operator-visible symptom is the LATENT walker-gate problem that the recent fixes did not address. **Translation:** "the operator-reported regression" is plural — at least two distinct breaks coexist.

### Contradiction 2: "Is SBOM auto-triggered today?" — Scout A says NO (always operator-driven); Scout E says NO (no auto runner exists) — but the operator implies an expectation that it would auto-fire

- **Evidence weight:**
  - Scout A line 9: "SBOM generation + vulnerability scanning subsystems in wairz are user-driven, not auto-triggered."
  - Scout E lines 11, 101-137: WALKER_AUTO_TRIGGERS lists 32 walker safe-runners. ZERO are `auto_sbom_*` or `auto_vuln_scan_*`. Direct grep `auto_sbom|auto_vuln` returns ZERO matches.
- **Resolution:** No contradiction between A and E — they agree. The implied contradiction with the operator's expectation is that **the operator may believe SBOM auto-runs after upload**, but architecturally it does NOT. This is an OPERATOR-MODEL mismatch, not a code regression.
- **Implication:** A subset of the "regression" symptom is **expectation drift** — the operator may have been seeing SBOM rows accumulate from older uploads (when Syft was being run as part of their manual workflow) and now sees nothing because: (a) the new uploads from 2026-05-12+ have no extracted-path-eligible content that an operator-triggered Syft can analyze (Scout C); OR (b) the operator must explicitly press "Generate SBOM" + "Scan Vulnerabilities" buttons that they expect to fire automatically. Wave-2 β/γ should design whether the FIX SHAPE is (i) ship an `auto_sbom_safe` + `auto_vuln_scan_safe` registry entry, OR (ii) educate the operator that these are explicit POSTs, OR (iii) auto-fire only on certain detected formats.

### Contradiction 3: "Is the regression a backend defect or a frontend defect?" — Scout A/B/C/E suggest backend; Scout D says "mixed-but-frontend-dominant"

- **Evidence weight:**
  - Scout C demonstrates the backend walker fan-out is broken at the DB level (cluster-wide zero rows in `windows_registry_extracts`, etc., across 25+ firmware since 2026-05-12).
  - Scout D demonstrates the frontend image is 27 hours stale and the running bundle does not include the most recent `frontend/src/` commit (`87a2574`).
- **Resolution:** Both contributory; the BACKEND defect dominates the surface symptom (cluster-wide empty tables cannot be explained by a stale frontend), but the FRONTEND defect is the cheapest confounder to eliminate before deeper diagnosis.
- **Implication:** Ship the frontend rebuild FIRST (per Scout D Conclusion 3) so the regression's true shape is unambiguous, THEN address the backend walker gate (per Scout C Conclusion 3).

### Contradiction 4: "Is `_fire_walker_auto_triggers` live or dead code?" — Scout A says it's the helper called from `_post_process_pipeline`; Scout B says it's dead code only called by tests

- **Evidence weight:**
  - Scout A line 192-193 (cross-index): `firmware_service.py:825-858 — _fire_walker_auto_triggers (unused, called by tests)`.
  - Scout B line 78-82: explicit verification — "the `_fire_walker_auto_triggers` helper is dead code. Only test_walker_auto_trigger_bridge.py calls it."
- **Resolution:** No contradiction — Scout A and Scout B agree on close reading. The PRODUCTION upload path calls `_post_process_pipeline → _run_hardware_firmware_detection_safe → walker_registry.get_walker_auto_triggers()` (Scout C confirms via line 273-275). `_fire_walker_auto_triggers` is a test bridge helper that is NOT in the production hot path.
- **Implication:** Scout B's surfacing is structurally important — there is a duplicate / dead helper at `firmware_service.py:825-858` that could be either (a) wired into production as a Rule #47-discipline single-source-of-truth, (b) deleted as dead code per Rule #42 simplification. This is a Rule #19 evidence-first cleanup, NOT a regression source.

## Convergent Findings (HIGH-confidence root causes)

### Root cause #1 — `unpack.py:106 if count <= 0: return` gate skips walker fan-out for low-detection firmware

- **Evidence:** Scout C lines 16, 87-89, 138-140, 162-166; Scout B line 203 (cross-ref); Scout A line 195 (cross-index). Scout C verified cluster-wide on real DB: 6 firmware with HW-blob count=0 (24967.hex, TMS320F28066, three f28066_*.bin variants, Bootloader_7.7.1.hex, PowerPack EGIA, target-ld) all have `*_walk_status = idle` across all 22 walkers despite being valid analysis targets.
- **Operator symptom:** Scout C deep-dive on 24967.hex (line 77-91) — operator uploads a real Intel HEX firmware with detected RTOS (uC/OS-II) + ARMhf arch, sees ONLY 1 generic security_audit finding + 0 walker activity. **The most likely "SBOM regressed" symptom** since bare-metal targets are the firmware-class that LACK driver/PE/EVTX artefacts but should still get bare_metal walker output.
- **Earliest manifest date:** Cannot be pinned to a specific commit because the gate appears to predate the 30-day window. Scout C line 188 shows `0977b260` (2026-05-01) already had walker_status_count ≤ 1.
- **Fix shape:** Restructure `backend/app/workers/unpack.py:106` from `if count <= 0: return` to either (a) `if count > 0: build_driver_firmware_graph()` then ALWAYS proceed to walker fan-out, OR (b) move the walker dispatch BEFORE the count check. Each walker's `get_detection_roots()` filter (Rule #16) is the proper place to decide whether work exists per Scout C line 166.
- **Estimated LOC + commits:** 10-25 LOC across `backend/app/workers/unpack.py:74-154`. One Rule #25 per-piece commit. Must include a regression test that uploads a zero-HW-blob firmware and asserts at least one walker safe-runner is invoked.

### Root cause #2 — `auto_bare_metal_audit_firmware_safe` not registered in WALKER_AUTO_TRIGGERS

- **Evidence:** Scout C lines 15, 140-144, 268-272 (verified `walker_registry._load_walker_safe_runners()` does NOT import the bare_metal safe-runner despite it existing at `bare_metal_walker.py:656` and being exported in `__all__`). Scout E line 137 confirms (`grep auto_bare_metal` returns the function but registry does not list it). Phase 2 wiring promised in commit `5ee22c1` was never shipped.
- **Operator symptom:** Bare-metal MCU firmware (TMS320, C28x, STM32) upload completes with `upload_stage='ready'` but `bare_metal_audit_status='idle'` indefinitely. The TMS320 stuck-queued row at `78ad638b` (Scout C line 219-232) is the canary — operator manually triggered via MCP, the OUTER state-machine wrapper failed (Rule #51 reaper gap), and the row is now poisoned and reports completion via the JSONB `result` payload but the status column never advanced.
- **Earliest manifest date:** Bare-metal walker shipped 2026-05-19 (Scout C line 15). Every bare-metal firmware uploaded since (5 candidates per Scout C) is affected.
- **Fix shape:** Two-commit chain:
  1. Add `auto_bare_metal_audit_firmware_safe` to `walker_registry._load_walker_safe_runners()` per Rule #44 + Rule #47 discipline (1 import + 1 list entry).
  2. Add `lookup_bare_metal_audit_across_firmwares` MCP tool per Rule #44 (cross-firmware aggregation; ~50 LOC new tool handler + registry entry in `register_bare_metal_tools(registry)`).
- **Estimated LOC + commits:** ~60 LOC across 2 commits.

### Root cause #3 — Orphan reaper coverage missing for 28+ state-machine columns

- **Evidence:** Scout E lines 70-78 + lines 162-174 — only 3 columns have reapers (`device_dump_session.status`, `cve_match_status`, `vuln_scan_status`). Scout C line 134 + lines 219-232 confirms via the TMS320 stuck-queued row (`bare_metal_audit_status` 6 days). Scout B line 193 + 207 explicitly notes `upload_stage` reaper missing.
- **Operator symptom:** Rows orphaned mid-execution stay in `queued`/`running` indefinitely. The operator hits 409 on subsequent re-triggers (Scout D Symptom-409 line 76). The frontend has no escape hatch (Scout D Conclusion 2). The TMS320 6-day stuck row is the worked example.
- **Earliest manifest date:** Generally latent; surfaces only when a runner crashes / GC'd / backend restarted mid-execution. TMS320 stuck since 2026-05-19 per Scout C line 73.
- **Fix shape:** Extend `backend/app/main.py:200-242` lifespan reaper block by:
  - Generating the reaper list from `walker_registry.WALKER_AUTO_TRIGGERS` so future walkers inherit coverage automatically (Scout C Conclusion 3 recommendation; Rule #47 consumer-hook-enumeration partner).
  - Add explicit reapers for `bare_metal_audit_status`, `upload_stage`, `authenticode_chain_status`, `dotnet_decompile_status`, `windows_update_diff_status`, all 22 `*_walk_status` columns (Scout E line 78, 162-174).
- **Estimated LOC + commits:** ~80 LOC in a single per-piece commit (Rule #25). Add a Rule #46 meta-canary that synthesizes a stuck row and confirms the reaper would flip it on a simulated lifespan startup.

### Root cause #4 (LOWER but convergent) — Frontend bundle 27 hours stale

- **Evidence:** Scout D lines 84, 110-115 (verified `docker compose images frontend` reports image created 2026-05-18T11:33:30Z; last commit touching `frontend/src/` was 2026-05-19 14:20:19). Per Rule #26 + the `auto-frontend-rebuild-not-restart` harness rule.
- **Operator symptom:** Operator sees behavior from older bundle even after backend was rebuilt. Could mask or amplify the apparent regression. Scout D Conclusion 3 marks this as "the most likely operator-visible regression" specifically because it's the cheapest single eliminator.
- **Earliest manifest date:** 2026-05-19 14:20 — moment the bundle drift started.
- **Fix shape:** `docker compose up -d --build frontend` (single command).
- **Estimated LOC + commits:** 0 LOC; environment-only.

## Divergent / Lower-Confidence Findings

| Finding | Confidence | Action |
|---|---|---|
| `_run_vuln_scan_background` GC risk from no strong task ref (Scout D:78) | MEDIUM | INVESTIGATE — verify in Wave-2 β whether `asyncio.create_task` returns are captured; if not, file as a Rule #51 partner pattern. |
| `scan_with_grype` ignores `force_rescan` → row doubling (Scout A:164) | MEDIUM | INVESTIGATE — confirm by inserting/SELECTing on `sbom_vulnerabilities` after a forced rescan. Could explain the 6.7M row count in production (Scout C:97). |
| `SbomComponent` UniqueConstraint without ON CONFLICT (Scout A:162) | LOW | DEFER — pre-existing race; surfaces only on operator-induced sequence; no evidence of mass operator-visible breaks. Out of regression-fix scope. |
| RTOS injection block at `sbom.py:165-198` swallows JSON parse errors silently (Scout A:178) | LOW | DEFER — file as backlog. |
| 600 s `SECURITY_SCAN_TIMEOUT` under-spec per Rule #29 1.2× math (Scout D:91) | LOW | DEFER — predates window. |
| `_fire_walker_auto_triggers` is dead code (Scout A/B confirmed) | LOW | DEFER — file as Rule #42 cleanup ticket. |
| 12 LiveCanary tests blocked by `memory_dump_image` FK breakage (baseline) | HIGH | **MUST FIX BEFORE ANY VALUE-FLOW CLAIM** — without these tests, value-flow regressions in SBOM/vuln-scan persistence will slip through CI silently per Rule #35b. Baseline observation lines 51-65. |
| 9 of 32 walker columns lack Pydantic Literal mirror (Scout E:180) | LOW | DEFER — Rule #33 .c housekeeping; not a regression suspect. |
| `_post_process_pipeline` does not run unpack for generic ZIP (Scout A:172) | MEDIUM | INVESTIGATE — Scout A's framing as "the most likely shape of the operator's regression" is plausible but the live-DB cluster-wide-zero pattern (Scout C) suggests a deeper systemic issue not specific to generic-ZIP. Wave-2 β should grep for which firmware are post-`5f3d195` (2026-05-12+) and check their `extracted_path`. |
| `enrichment.py` directly mutates `metadata` JSONB bypassing `_stamp_*` helper (Scout B:131) | LOW | DEFER — Rule #35c discipline-skip; sample with `SELECT DISTINCT jsonb_typeof(metadata->'schema_version') FROM sbom_components`. |
| `_components_with_vuln_counts_stmt` 22000× perf hot-fix (Scout B:58-69) | RESOLVED | Already fixed via `d32d197`. Verify operator's image is ≥ 2026-05-15 18:31 UTC. |

## Fix Scope + Shipping Order

### Fix #1 — Frontend rebuild (cheapest possible eliminator)

- **Rule(s) applied:** Rule #26 (frontend rebuild not restart).
- **Files touched:** None; environment-only.
- **Commit shape:** No commit. `docker compose up -d --build frontend`.
- **Pre-flight gates required:** Verify `docker compose images frontend` shows `Created > 2026-05-19 14:20`. Run a curl against `http://localhost:3000/assets/index-*.js` and grep for the most recent commit's compiled output.
- **Risk of NOT shipping:** Operator continues to see behavior from the stale bundle; any frontend-side regression observation is contaminated. Cheapest single action.

### Fix #2 — Unblock LiveCanary tests by repairing `memory_dump_image` FK

- **Rule(s) applied:** Rule #35b (mocks vs live canaries); baseline opening finding.
- **Files touched:** `backend/app/models/memory_dump.py` (likely the model is `MemoryDumpImage` but referenced as `memory_dump_image` in volatility FK); `backend/app/models/volatility.py`. Either rename the FK target or rename the table. Verify alembic migration history.
- **Commit shape:** Single Rule #25 commit. Add a Rule #46 META-CANARY confirming `make_live_db()` instantiates metadata.
- **Pre-flight gates required:** Run all 12 blocked tests post-fix; confirm pass.
- **Risk of NOT shipping:** Cannot trust any SBOM/vuln-scan/finding-emit value-flow regression detection in CI. **All other fixes ship blind** without this gate restored.

### Fix #3 — Walker fan-out un-gating (highest-impact single fix)

- **Rule(s) applied:** Rule #16 (detection roots — each walker decides its own work); Rule #47 (consumer-hook enumeration — every walker downstream of the gate is a consumer).
- **Files touched:** `backend/app/workers/unpack.py:74-154` (specifically line 106 early-exit).
- **Commit shape:** Rule #25 single-piece. Add regression test that uploads a zero-HW-blob firmware and asserts at least one walker safe-runner runs.
- **Pre-flight gates required:**
  - Rule #11 import smoke after rebuild.
  - Rule #35b live canary on a representative bare-metal firmware (24967.hex shape).
  - Rule #46 META-CANARY confirming the un-gated dispatch produces at least one walker `*_walk_status` transition.
- **Risk of NOT shipping:** Cluster-wide zero walker output continues; bare-metal targets and other low-blob firmware silently fail analysis.

### Fix #4 — Bare-metal walker registration (Rule #47 + Rule #44 pair)

- **Rule(s) applied:** Rule #47 (consumer-hook enumeration); Rule #44 (cross-firmware MCP tool mandatory at walker's `.E` commit).
- **Files touched:**
  - `backend/app/workers/walker_registry.py:_load_walker_safe_runners` (1 import + 1 list entry).
  - `backend/app/ai/tools/bare_metal.py` (add `lookup_bare_metal_audit_across_firmwares` MCP tool).
  - Test file under `backend/tests/` for the cross-firmware query.
- **Commit shape:** Two Rule #25 per-piece commits OR one Rule #48 Shape-1 commit if the registry change pairs with a single META-CANARY in `test_walker_registry.py`.
- **Pre-flight gates required:** Rule #11 import smoke; Rule #35b live canary against the stuck `78ad638b` TMS320 row to confirm un-poisoning.
- **Risk of NOT shipping:** Bare-metal firmware uploads continue to land with `bare_metal_audit_status='idle'` regardless of detection.

### Fix #5 — Orphan reaper expansion (Rule #51 systematic completion)

- **Rule(s) applied:** Rule #51 (Rule #33 conversion mandates reaper companion); Rule #47 (consumer-hook enumeration); Rule #46 (META-CANARY).
- **Files touched:** `backend/app/main.py:200-242` lifespan block expansion. Optional: refactor to derive reaper list from `walker_registry.WALKER_AUTO_TRIGGERS` for future-proofing.
- **Commit shape:** Single Rule #25 commit. Include test that synthesizes a stuck row and asserts the reaper flips it on a simulated lifespan startup (Rule #46 META-CANARY).
- **Pre-flight gates required:** Verify TMS320 stuck row is recovered post-reaper (or document why it's NOT — the JSONB `result` payload at line 226-229 of Scout C suggests the row's inner runner DID complete; recovery may need a manual SQL update separately).
- **Risk of NOT shipping:** Any future GC-induced orphan stays in `running` indefinitely; operator sees 409 forever; no escape hatch.

### Fix #6 (DEFERRED) — SBOM-generate Rule #33 conversion OR tier re-tier

- **Rule(s) applied:** Rule #33 (sync → 202+polling 4-bullet contract); Rule #51 (tier re-eval at conversion).
- **Files touched:** `backend/app/routers/sbom.py:115-225` (the endpoint); `backend/app/models/firmware.py` (new `sbom_status` column + migration); `backend/app/schemas/sbom.py` (new `SbomStatus` Literal); `frontend/src/pages/SbomPage.tsx:128-144` (handleGenerate polling).
- **Commit shape:** Rule #48 Shape-1 cross-stack alignment commit chain (DB CHECK + Pydantic Literal + frontend mirror; ~5 commits per Rule #33 contract).
- **Pre-flight gates required:** Substantial — Rule #33 .a/.b/.c/.d all four bullets need to ship together; Rule #51 tier re-eval; Rule #47 consumer-hook sweep.
- **Risk of NOT shipping:** SBOM generate continues to hold uvicorn worker + DB connection for 30-120 s per call; under 30/hour budget operator can starve DB pool (Scout D line 131). DEFER unless operator confirms this is the actual regression they're observing.

## Shipping Order (Cheapest → Most-Impactful)

1. **Frontend rebuild** — `docker compose up -d --build frontend`. Zero LOC, ~30 s wall time. Eliminates the stale-bundle confounder before any other diagnosis.
2. **LiveCanary FK repair** — `memory_dump_image` → correct table reference. ~5-15 LOC + 1 migration; enables Rule #35b discipline for the rest of the campaign.
3. **Walker fan-out un-gating** — `unpack.py:106` restructure. ~10-25 LOC + 1 regression test. **Single highest-impact fix per Scout C Conclusion 3.**
4. **Bare-metal walker registration + Rule #44 MCP tool** — `walker_registry.py` + `ai/tools/bare_metal.py`. ~60 LOC across 2 commits.
5. **Orphan reaper expansion** — `main.py` lifespan block + Rule #46 META-CANARY. ~80 LOC + 1 test commit.
6. **(Deferred to next session)** — SBOM-generate Rule #33 conversion. Substantial work; only ship if operator confirms this is the observed bottleneck.

Estimated single-session feasibility for items 1-5: **MEDIUM-confidence YES**, scoped to ~150-200 LOC across 5-6 Rule #25 per-piece commits + 1 Rule #8 rebuild at the end. Each commit is independently revertable per Rule #25 bisect-clean discipline.

## Gaps for W2-β + W2-γ

1. **W2-β cross-feature attack: walker-gate × Rule #44 cross-firmware tools.** If the walker fan-out un-gating ships, will the existing 22 walker safe-runners handle low-blob firmware correctly, OR will they assume HW-blob presence and crash on the no-blob path? Each walker's `get_detection_roots()` contract (Rule #16) is the gate; verify by reading each walker's pre-flight.
2. **W2-β cross-feature attack: orphan reaper coverage × walker auto-trigger registration order.** If reapers are derived from `walker_registry.WALKER_AUTO_TRIGGERS`, what happens if a walker safe-runner is added to the registry BUT not migrated for its status column? The reaper would fire on a non-existent column and crash lifespan startup. Need a Rule #46 META-CANARY for the registry-derives-reaper-list flow.
3. **W2-β cross-feature attack: SBOM-generate sync × `TIER_A_LIGHT_ACK` × DB pool 40-conn ceiling.** Scout B (line 69) + Scout D (line 131) + Scout E (line 158) all surface this. Under heavy operator iteration, the sync `/sbom/generate` holds a DB connection for 30-120s × 30/hour = up to 3000 connection-seconds per hour. With pool=40, this is ~12 % saturation in single-operator steady state. What's the multi-operator multiplier? Does grype-mode (default) vs NVD-mode change the math?
4. **W2-γ yardstick: which firmware ARE producing walker output?** Scout C identifies 3 firmware with `linux_systemd_units` rows (RespArray, target-ld, 8312-RespArray) — all pre-2026-05-05. Was there a regression between 2026-05-05 and 2026-05-12 that changed the systemd walker's detection-root contract? Cross-check against the recent `e2f8333` adaptive nested-archive recursion gate commit (Scout B line 135).
5. **W2-γ yardstick: what does the operator's actual workflow LOOK like today?** All 5 Wave-1 scouts assumed the operator's symptom is "I clicked Generate SBOM and got nothing", but the operator's actual prompt was vague ("regressed"). W2-γ should ask: (a) was the regression discovered via operator-eyes inspection of the UI? (b) via an MCP tool returning empty? (c) via a downstream CVE-match producing zero rows? Each branch points to a different root-cause subset.

## What Each Scout Missed

- **Scout A missed:** the live-DB ground truth that walker output is CLUSTER-WIDE ZERO (Scout C's primary finding). Scout A's framing of "the operator's regression is likely the upload-pipeline sparse-extraction path" (Scout A line 172-173) is plausible but secondary to the systemic walker-gate failure. Scout A correctly identified the WALKER_AUTO_TRIGGERS structure but did not probe whether the walker dispatcher itself is being short-circuited.
- **Scout B missed:** the `unpack.py:106 if count <= 0: return` gate being pre-existing (not introduced by a regression commit in the 30-day window). Scout B's suspect-commit ranking is well-evidenced but the actual highest-impact fix (Scout C's gate removal) is for an OLDER defect that no commit in the window introduced.
- **Scout C missed:** the frontend stale-bundle confounder (Scout D's primary surface concern). Scout C's live-DB ground truth is otherwise extraordinarily complete; the omission is only that Scout C did not cross-check whether the operator's actual UI session might be reflecting cached frontend state.
- **Scout D missed:** the live-DB ground truth that the operator's PERCEIVED stuck-spinner / 409 / empty-table symptoms are downstream of the BACKEND walker-gate failure, not frontend defects. Scout D's symptom catalog is comprehensive but inverts the root-cause priority (frontend-dominant → backend-dominant once Scout C's DB probe lands).
- **Scout E missed:** the bare_metal_audit_status orphan reaper gap that Scout C surfaced via the stuck TMS320 row (Scout C line 67-73, 134, 219-232). Scout E line 39 correctly notes the column has no reaper but does NOT cross-check with the LIVE DB to confirm a real stuck row exists. Scout E also missed Scout A/B's framing of `_fire_walker_auto_triggers` as dead code in the production hot path.

## Recommendation to Parent

**Ship in order: (1) frontend rebuild → (2) LiveCanary FK repair → (3) walker fan-out un-gating → (4) bare-metal registration + Rule #44 MCP tool → (5) orphan reaper expansion.** Defer SBOM-generate Rule #33 conversion to a follow-up session pending operator confirmation that this is the observed symptom. Bisect-clean-feasible per Rule #25 — each commit is independently revertable. Estimated **single session** for items 1-5 if scoped tightly (~150-200 LOC across 5-6 commits + 1 Rule #8 rebuild). Confidence MEDIUM: the convergent evidence is strong on root causes #1-#3, but the operator's actual symptom-vector remains under-specified — W2-γ should clarify whether the regression they observed is "empty walker tables" (Scout C primary), "stuck spinner on Vuln Scan button" (Scout D primary), "SBOM generation returns empty for new uploads" (Scout A primary), or some combination. Ship the cheapest deterministic fixes first to avoid wasted work on the wrong root cause.
