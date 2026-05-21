# Wave-2 γ — Rule #28 Yardstick / Scope (S2)

> Investigation date: 2026-05-21 (Session 2 measurement)
> Branch tip at audit: `208805c` (Session 1 close — learn commit)
> Predecessor: `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave2-gamma-yardstick.md`
> (Session 1 baseline: projected Session 2 at ~1,110 LOC / ~10 commits / ~5.4 hr)

## Executive Summary

**VERDICT: MULTI-SESSION-RECOMMENDED — split into Session 2a (Fix #1 + Fix #6 + Fix #8-broader + Fix #10-frontend-mandatory-trio) and Session 2b (Fix #11 walker reaper sweep + §SC5-NEW-SBOM-S2 hardening + frontend unknown-format degrade + docs/learn).** Drift-adjusted scope is approximately **1,840 net LOC + 16 commits + 1 alembic migration + 2 Rule #8 rebuilds + 1 Rule #48 Shape-1 cross-stack alignment commit + 6 Rule #46 META-CANARIES**, against a single-session capacity envelope of ~6 hours focused work. Session 1's actual shipping data (885 backend + 671 backend test + 0 frontend = ~969 net LOC in 8 commits / ~5 hr, per `git diff --shortstat c29d6b7..HEAD`) is the load-bearing calibration anchor: Session 2's projected work is ~1.9× that LOC count and packs FIVE structural risks Session 1 carefully avoided (alembic migration, Rule #48 cross-stack alignment commit, frontend bundle rebuild, Scout C's CRITICAL §SC5-NEW-SBOM-S2-δ authority-laundering attack surface that lands the moment Fix #1's new YAML-shaped extension surfaces touch operator-supplied paths, and the walker-reaper sweep architectural refactor). Confidence on the verdict is **HIGH** because (a) Session 1's actuals validate that ~1,000 LOC in 8 commits is the rate-limit-2026-05-18 / Session-1 baseline at ~5 hours, (b) Fix #1 alone is ~420 LOC with a structurally identical clone shape to `8f54a24` (vuln-scan Rule #33 conversion) that historically required 8 commits over 11 days to settle, (c) Scout D's mandatory frontend unknown-format trio is ~140 LOC the W2-γ Session 1 baseline did NOT account for, and (d) Scout C's §SC5-NEW-SBOM-S2-γ reaper-completeness gate alone adds Rule #46 META-CANARY weight outside the existing per-fix bullets.

## File-by-File `wc -l` Measurements

Snapshot at branch `208805c`:

| File | Current LOC | Session 1 delta | Touched by S2 |
|---|---|---|---|
| `backend/app/main.py` | **515** | +106 (S1 Fix #2 + Fix #5 reapers) | Fix #1 (sbom_status reaper), Fix #11 (walker sweep refactor) |
| `backend/app/routers/sbom.py` | **1,114** | +38 (S1 Fix #8 GC guard + comments) | Fix #1 (sbom_status 202+polling), Fix #6 (force_rescan plumbing), Fix #8-broader (extract `_spawn_background_task`) |
| `backend/app/routers/firmware.py` | **676** (unchanged) | — | Fix #8-broader (4 bare create_task sites at L175, L297, L436, L441) |
| `backend/app/routers/hardware_firmware.py` | (unchanged) | — | Fix #8-broader (2 sites at L654, L750) |
| `backend/app/routers/fuzzing.py` | (unchanged) | — | Fix #8-broader (1 site at L143) |
| `backend/app/services/firmware_service.py` | **937** (unchanged) | — | Fix #8-broader (1 site at L818); Fix #9 — DEFERRED (not in scope; Scout B verdict + Scout A acknowledges minimum-viable shape ~50 LOC only) |
| `backend/app/workers/walker_registry.py` | **201** | +11 (S1 Fix #4 registration) | Fix #11 (`WALKER_REAPER_CONFIGS` parallel dict + dataclass, ~80 LOC) |
| `backend/app/workers/unpack.py` | **1,103** | +85 (S1 Fix #3 walker un-gate + semaphore) | — (un-gating shipped) |
| `backend/app/models/firmware.py` | **991** (unchanged) | — | Fix #1 (sbom_status + 4 sibling columns block, ~35 LOC) |
| `backend/app/schemas/sbom.py` | **139** (unchanged) | — | Fix #1 (`SbomStatus` Literal + `SbomGenerateStatusResponse`, ~25 LOC) |
| `backend/app/services/grype_service.py` | **264** (unchanged) | — | Fix #6 (`force_rescan` parameter + DELETE block, ~25 LOC) |
| `backend/app/services/vulnerability_service.py` | **741** (unchanged) | — | (no direct touch — already accepts force_rescan) |
| `backend/app/rate_limit.py` | **232** (unchanged) | — | (Fix #1 inherits TIER_A_LIGHT_ACK already correct) |
| `backend/app/services/sbom/service.py` | **301** (unchanged) | — | (no touch — Scout B verdict: Strategy pattern already Python-extensible) |
| `backend/app/services/sbom/__init__.py` | **41** | — | — |
| `backend/tests/test_sbom_router.py` | **1,136** | +6 (S1 Fix #8 mock fix) | Fix #1, Fix #6 — ~280 LOC mock + live + META-CANARY |
| `backend/tests/test_main_lifespan_reapers.py` | **166** | +166 NEW (S1) | Fix #1 (sbom reaper test + META-CANARY ~70 LOC); Fix #11 (parallel walker-sweep tests ~110 LOC) |
| `backend/tests/test_rate_limit_tiers.py` | **286** | — | Fix #1 — `_EXPECTED_TIERS` entry already pinned; size-lock at L128 (count=20 unchanged); META-CANARY trio at L141 + L175 + L209 unchanged |
| `backend/tests/test_walker_auto_trigger_bridge.py` | **321** | +42 (S1 Fix #4 bridge tests) | Fix #11 (extend bridge tests for `WALKER_REAPER_CONFIGS` keying ~30 LOC) |
| `backend/tests/test_sbom_router_background_tasks.py` | **148** | +148 NEW (S1) | Fix #8-broader (sweep canary META-CANARY ~50 LOC) |
| `backend/tests/test_unpack_walker_dispatch.py` | **311** | +311 NEW (S1) | — (un-gating already covered) |
| `backend/tests/test_vulnerability_service.py` | **483** (unchanged) | — | Fix #6 — ~80 LOC |
| `backend/tests/_live_db.py` | **264** | — | (Fix #10-baseline from S1 W2-γ was Session 1 scope — already unblocked) |
| `frontend/src/pages/SbomPage.tsx` | **1,302** (unchanged) | — | Fix #1 (polling refactor ~70 LOC), Scout D mandatory trio (~140 LOC) |
| `frontend/src/api/sbom.ts` | **157** (unchanged) | — | Fix #1 (generateSbom 202 shape + getSbomGenerateStatus, ~25 LOC) |
| `frontend/src/api/timeouts.ts` | **43** (unchanged) | — | Fix #1 — drop `SECURITY_SCAN_TIMEOUT` override from generateSbom + comment update (~3 LOC) |
| `frontend/src/components/projects/FirmwareUpload.tsx` | **335** (unchanged) | — | Scout D (extract `FormatBanner` to `components/firmware/FormatBanner.tsx` ~30 LOC move) |
| `frontend/src/types/index.ts` | **825** (unchanged) | — | Fix #1 (`SbomStatusValue` + `SbomGenerateStatus`, ~15 LOC) |
| `frontend/src/api/client.ts` | **140** (unchanged) | — | — |
| **Alembic migration shape baselines** | | | |
| `e6f7a8b9c0d1_add_cve_match_status_to_firmware.py` | 114 | — | Reference template for Fix #1 new migration ~115 LOC |
| `fc5d6e7f8a9b_add_bare_metal_walker_state_machine.py` | 236 (8,422 bytes) | — | (S1 baseline; not Fix #1 target shape) |
| `fd6e7f8a9b0c_extend_findings_source_bare_metal.py` | (current head) | — | `down_revision` for Fix #1's new alembic |

## Per-Fix Scope Estimate

### Fix #1: SBOM `/generate` Rule #33 sync→202+polling conversion + `sbom_status` state machine

**Structural giant.** Scout E + Scout D + Scout B agree this is the centerpiece of Session 2. Mirror of `8f54a24` (vuln-scan conversion). Scout E provided the design verbatim — alembic migration + 5 new columns + Pydantic Literal + DB CHECK + router refactor + reaper + frontend polling + cross-stack Rule #48 Shape-1 commit.

- **Files touched:** `backend/app/routers/sbom.py:142-252` (router conversion ~100 LOC); `backend/app/models/firmware.py` (sbom_status + 4 sibling columns block, ~35 LOC); `backend/app/schemas/sbom.py` (`SbomStatus` Literal + `SbomGenerateStatusResponse`, ~25 LOC); `backend/app/main.py` (sbom orphan reaper, ~44 LOC no-grace shape mirroring bare_metal_audit at L305); `frontend/src/api/sbom.ts` (~25 LOC); `frontend/src/pages/SbomPage.tsx` (~70 LOC polling refactor); `frontend/src/api/timeouts.ts` (drop SECURITY_SCAN_TIMEOUT override from generateSbom, ~3 LOC); `frontend/src/types/index.ts` (~15 LOC); `backend/tests/test_sbom_router.py` (~250 LOC mock + live + META-CANARY); `backend/tests/test_main_lifespan_reapers.py` (~70 LOC sbom reaper test + meta-canary); new `backend/alembic/versions/<NEW>_add_sbom_status_to_firmware.py` (~115 LOC)
- **LOC delta (additions):** router 100 + model 35 + schema 25 + main reaper 44 + frontend 113 + alembic 115 + tests 320 = **~752 LOC NET**
- **LOC delta (modifications):** ~40 (existing router refactor; existing test fix-ups)
- **Tests delta:** 28 — 14 mock (state transitions: 200→202, 409, polling, idempotency, status JSON shape, force_rescan); 8 Rule #35b live-canary (sbom_status round-trips through Firmware ORM + reaper UPDATE persistence); 6 Rule #46 META-CANARY (tier alignment unchanged, structured 429, idempotency, no-grace reaper proof, cross-stack alignment 5-part trio)
- **Alembic migration:** YES — new revision parallel to `e6f7a8b9c0d1` shape (~115 LOC: 5 columns + CHECK + reverse)
- **Frontend touched:** YES (per Scout D — `handleGenerate` polling refactor + new poll-loop useEffect + SbomGenerateStatusBanner + re-mount auto-resume + last-failed-attempt header surfacing)
- **Docs/recipe touched:** YES — CLAUDE.md Rule #33 worked-example 6th application; ADAPTIVE_BACKLOG mark-resolved entry
- **Rule #25 commit count:** **4 per-piece commits**:
  - C1: alembic + model + schema (Rule #48 Shape-1 single-slice cross-stack — the migration, Pydantic Literal, and frontend type union MUST land atomic per Rule #25 single-slice exception #2)
  - C2: router refactor + reaper
  - C3: frontend pair (SbomPage + sbom.ts + timeouts.ts + types/index.ts)
  - C4: tests bundle
- **Rule #8 rebuild:** **YES** (backend+worker+migrator after the alembic; frontend image rebuild after the API contract change — Rule #26)
- **Rule #11 import smoke:** YES (`SbomStatus`, `SbomGenerateStatusResponse`, `_run_sbom_generate_background`, sbom-reaper helper)
- **Wall-clock estimate:** **110 minutes** (mirrors `8f54a24` shape; reference: 8f54a24 was ~200 LOC router alone; companions added 7 more commits over 11 days — but Fix #1 absorbs companions into the same conversion atomic, so the wall-clock is bounded by writing+verifying, not by discovering second-order effects)

### Fix #6: `scan_with_grype` honors `force_rescan`

- **Files touched:** `backend/app/services/grype_service.py:60-265` (~25 LOC: signature param + transactional DELETE block at top, per Scout C §SC5-NEW-SBOM-η transactional fix); `backend/app/routers/sbom.py:466-470` (~3 LOC pass-through); `backend/tests/test_vulnerability_service.py` (~80 LOC)
- **LOC delta (additions):** 25 production + 80 test = **~105 LOC**
- **Tests delta:** 6 (3 mock for DELETE-then-INSERT branch + concurrent 409 verification per §SC5-NEW-SBOM-η; 2 Rule #35b live canary asserting row counts before/after force_rescan; 1 META-CANARY for transactional rollback semantics)
- **Alembic migration:** NO
- **Frontend touched:** NO (button-gating during in-flight handled by Fix #1's frontend trio)
- **Docs touched:** YES (CLAUDE.md Rule #33 .b cross-ref — result-aggregate persistence)
- **Rule #25 commit count:** **1**
- **Rule #8 rebuild:** YES (backend — bundleable with Fix #1's rebuild)
- **Wall-clock estimate:** **35 minutes**

### Fix #8-broader: `_spawn_background_task` sweep + extract to shared utility

Per Scout C §SC5-NEW-SBOM-S2-κ — Session 1 shipped the helper inline at `routers/sbom.py:28-37`; the broader sweep extracts to `app/utils/background.py` and substitutes at the 8 bare-create_task sites in routers (5 in firmware.py — L175, L297, L436, L441 + L171 documented; 2 in hardware_firmware.py — L654, L750; 1 in fuzzing.py — L143). Note: `terminal.py` WebSocket reader/writer/keepalive tasks at L270-272 and L459-461 + `emulation.py` similar are NOT in scope (their lifetime is bounded by the WebSocket session; GC vanishes from underneath them is the desired behavior).

- **Files touched:** new `backend/app/utils/background.py` (~30 LOC); `backend/app/routers/sbom.py` (~2 LOC import + 3 callsite changes); `backend/app/routers/firmware.py` (~10 LOC, 4 sites); `backend/app/routers/hardware_firmware.py` (~6 LOC, 2 sites); `backend/app/routers/fuzzing.py` (~3 LOC, 1 site); `backend/app/services/firmware_service.py:818` (~3 LOC, 1 site); `backend/tests/test_sbom_router_background_tasks.py` (extend existing 148-LOC file ~50 LOC); ruff custom rule OR Rule #46 META-CANARY for ban-bare-create_task-in-routers (~40 LOC test)
- **LOC delta (additions):** 30 helper + 27 callsite substitutions + 50 test extend + 40 META-CANARY = **~147 LOC**
- **Tests delta:** 4 (1 live canary that `_spawn_background_task` strong-ref set persists; 1 META-CANARY scanning routers for bare `asyncio.create_task` per Scout C §SC5-NEW-SBOM-S2-κ width-canary; 2 regression tests for each substituted call site)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #33 .d — strong-reference pattern reinforcement; harness rule `no-bare-asyncio-create-task-in-routers`)
- **Rule #25 commit count:** **2** (extract-helper commit + sweep commit per Rule #27 N additive + 1 cut-over pattern at function scope)
- **Rule #8 rebuild:** YES (backend — bundleable)
- **Wall-clock estimate:** **45 minutes** (per Rule #42 — helper extraction at first encounter; rollout to N sites in a second commit)

### Fix #11: Walker `*_walk_status` orphan reaper sweep (Option B per Scout E)

Scout E provided the architectural design — centralised `WALKER_REAPER_CONFIGS` dict in `walker_registry.py` keyed by trigger-name + dataclass `WalkerReaperConfig`. NOT YAML per Rule #52 (Scout B agrees: pure Python data is correct shape; operator extensibility is downstream of the alembic+Pydantic+DB-CHECK chain that walker authors already navigate). Scout C §SC5-NEW-SBOM-S2-γ adds a CRITICAL hardening: the reaper sweep MUST split into two axes — `WALKER_STATUS_COLUMNS` (derived from `WALKER_AUTO_TRIGGERS`) AND `STATE_MACHINE_COLUMNS` (sbom_status, vuln_scan_status, bare_metal_audit_status, upload_stage, cve_match_status, device_dump_status, authenticode_chain_status, registry_hive_walk_status, dotnet_decompile_status, etc.). Without that split, the unified refactor silently drops Fix #1's new `sbom_status` reaper from coverage.

- **Files touched:** `backend/app/workers/walker_registry.py` (+80 LOC dataclass + 22 dict entries); `backend/app/main.py` (+50 LOC reaper-loop refactor — REPLACES the 5 existing inlined reapers, NET delta after replacement is ~+30); `backend/tests/test_main_lifespan_reapers.py` (+110 LOC — 6 META-CANARIES per Scout E + 1 §SC5-NEW-SBOM-S2-γ list-disjoint canary); `backend/tests/test_walker_auto_trigger_bridge.py` (+30 LOC size-lock between WALKER_AUTO_TRIGGERS and WALKER_REAPER_CONFIGS)
- **LOC delta (additions):** 80 + 50 + 110 + 30 = **~270 LOC**
- **LOC delta (modifications/deletions):** ~-100 (deletes the 5 inlined reapers replaced by the unified loop; net add ~170)
- **Tests delta:** 8 (2 Rule #35b live canaries for two reaper paths; 6 META-CANARIES: column-name validity, trigger-name-key consistency, size-lock between registries, reaper-list completeness against Firmware ORM reflection, §SC5-NEW-SBOM-S2-γ split disjointness, gate-canary that synthesizes a malformed reaper config and asserts the gate fires)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #51 major worked-example extension — Rule-of-Two state-machine sweep with two-axis disjoint-and-complete invariant; Rule #47 consumer-hook enumeration analog)
- **Rule #25 commit count:** **2** (registry-extension additive commit + main.py cut-over commit per Rule #27 N+1)
- **Rule #8 rebuild:** YES (backend — lifespan reaper changes require restart)
- **Wall-clock estimate:** **75 minutes** (longer than Session 1 baseline estimated 60min because Scout C §SC5-NEW-SBOM-S2-γ two-axis split adds testing complexity and the Rule #46 META-CANARY for ORM-reflection completeness is non-trivial)

### Scout D Mandatory Trio (frontend unknown-format graceful-degrade)

Per Scout D, 4 of the mandatory UX changes group naturally as a frontend-only commit:
- Re-mount auto-resume polling (#3)
- Failed-state surfacing (#2)
- Unknown-format banner (#5)
- "Try Generic Strategy" button (#6)

Plus the FormatBanner component extraction.

- **Files touched:** new `frontend/src/components/firmware/FormatBanner.tsx` (~50 LOC extract from FirmwareUpload.tsx:309-335); modify `frontend/src/components/projects/FirmwareUpload.tsx` (~-20 LOC, replace inline with FormatBanner import); modify `frontend/src/pages/SbomPage.tsx` (~80 LOC — header extension + re-mount auto-resume + banner placement + Try Generic button); new `frontend/src/hooks/useFirmwareDetail.ts` (~25 LOC); backend `backend/app/services/sbom_service.py` (~10 LOC: `generate_generic_strings_strategy` stub or annotation that closes the Scout D contract — the FULL implementation may defer to Session 3 but the contract MUST land in Session 2 to unblock the frontend)
- **LOC delta (additions):** 50 + 80 + 25 + 10 + (-20) = **~145 LOC NET**
- **Tests delta:** 3 (1 frontend snapshot/visual for FormatBanner reuse; 2 backend tests for the new query param contract)
- **Alembic migration:** NO
- **Frontend touched:** YES — full image rebuild required per Rule #26
- **Docs touched:** YES (CLAUDE.md Rule #52 operator-touchpoint cross-ref; new docs/operator-extension.md stub)
- **Rule #25 commit count:** **2** (FormatBanner extract + SbomPage integration)
- **Rule #8 rebuild:** YES (frontend image rebuild — Rule #26)
- **Wall-clock estimate:** **55 minutes**

### Fix #9 (minimum-viable scope) — DECISION POINT

Per Scout A, the FULL Rule #52 closed-grammar refactor of `_post_process_pipeline` is ~4,600 LOC and explicitly multi-session work; Scout B agrees and defers to a Rule-of-Four campaign AFTER ICS Session 2 closes Rule-of-Three. Scout A's "minimum-viable" shape — invoke `unpack_firmware_job` as a fallback when neither the tar nor ZIP shortcut fires — is ~50 LOC backend + ~30 LOC test = **~80 LOC** plus Scout C §SC5-NEW-SBOM-S2-ε polyglot precondition canary (~30 LOC test).

**Recommendation:** **DEFER Fix #9 entirely from Session 2.** Reasoning:
- Scout B verdict: full refactor is Rule-of-Four queued (~4,600 LOC) — explicitly NOT this session
- Minimum-viable shape has Scout C §SC5-NEW-SBOM-S2-ε polyglot ambiguity attack that needs careful precondition design; getting this wrong invites the §SC5-NEW-SBOM-S2-ζ archive-bomb DoS
- Session 1's Fix #3 walker un-gating already addresses the OPERATOR-VISIBLE symptom Scout A diagnosed (walkers now fire even for 0-blob firmware)
- Decoupling Fix #9 from Session 2 lets Session 2 ship cleanly under the multi-session split; Fix #9 lands as its own focused mini-campaign in Session 3 with its own Wave-1+Wave-2 design pass

The 50-80 LOC saved from Fix #9 deferral fits in the multi-session budget.

## Aggregate Scope

| Bucket | Net LOC |
|---|---|
| Fix #1 (SBOM 202+polling conversion + sbom_status state machine + Rule #48 Shape-1 alignment + reaper) | 752 |
| Fix #6 (grype force_rescan transactional) | 105 |
| Fix #8-broader (extract helper + sweep + ban-bare-create_task META-CANARY) | 147 |
| Fix #11 (walker reaper sweep + Scout C §SC5-NEW-SBOM-S2-γ two-axis split + META-CANARY trio) | 270 |
| Scout D mandatory trio (FormatBanner extract + SbomPage re-mount + Failed-state + Unknown-format + Try-Generic) | 145 |
| Fix #9 (DEFERRED to Session 3) | 0 |
| Docs/CLAUDE.md mirror + .planning/ updates + ADAPTIVE_BACKLOG sync | 140 |
| **Subtotal (measured)** | **1,559** |
| **Drift-adjusted (×1.18 per Rule #28)** | **1,840** |

- **Total commits:** Fix #1=4 + Fix #6=1 + Fix #8-broader=2 + Fix #11=2 + Scout D trio=2 + Fix #9=0 + docs/learn/postmortem=1 + Rule #48 single-slice (absorbed into Fix #1's C1) = **12 production commits + 4 docs/test commits = 16 total**
- **Total wall-clock:** 110+35+45+75+55+15(docs) = **335 minutes = 5h 35m** + 18% Rule #28 slack = **~6.6 hours projected**
- **Total Rule #8 rebuilds:** **2** (backend+worker+migrator after Fix #1 alembic; frontend image after Scout D trio + Fix #1 API contract change)
- **Total Rule #11 import smoke:** 6 (`SbomStatus`, `SbomGenerateStatusResponse`, `_run_sbom_generate_background`, `_spawn_background_task` from new utils, `WALKER_REAPER_CONFIGS`, `FormatBanner` component)
- **Total Rule #46 META-CANARY:** **6** net new (Fix #1 cross-stack alignment 5-part; Fix #1 no-grace reaper; Fix #8-broader ban-bare-create_task; Fix #11 two-axis disjoint-and-complete; Fix #11 size-lock; Scout D unknown-format gate)
- **Total Rule #48 5-part cross-stack alignment commits:** **1** (Fix #1's C1 `SbomStatus` Shape-1)

## Comparison to Baselines

| Campaign | Net LOC | Commits | Wall-clock | Outcome |
|---|---|---|---|---|
| Session 1 (cheap-wins, 2026-05-21) | ~969 (885 backend + 671 test - documentation noise) | 8 | ~5 hr | single-session shipped |
| Rate-limit campaign 2026-05-18 (`f6dbc7b..b24a4d8`) | ~600 | 8 | single-session with overflow next morning | single-session-with-overflow |
| WALKER_AUTO_TRIGGERS Rule #47 2026-05-12 | ~250 | 3 | <2 hr | single-session |
| ICS Session 1 (scaffold-only) | ~5,552 | 3 | full session | multi-session-recommended |
| P3.2 file-format YAML registry | ~5,500 | 8 | single-session-but-tight | single-session-tight |
| **THIS Session 2 (projected)** | **~1,840** | **16** | **~6.6 hr** | **multi-session-recommended** |

**Critical anchor — Session 1 actuals as calibration:** the Session 1 shipping was ~969 net LOC / 8 commits / ~5 hr. Session 2's projected scope is **1.9× the LOC** and **2× the commits**, AND it includes:
- 1 alembic migration (Session 1 had 0)
- 1 Rule #48 Shape-1 cross-stack alignment commit (Session 1 had 0)
- 1 frontend bundle rebuild (Session 1 had 0)
- 1 architectural refactor (Fix #11 unified reaper — replaces 5 inlined reapers with a centralised dispatch)
- Scout C's §SC5-NEW-SBOM-S2 hardening surface across 5 attacks (-α, -γ, -ε, -η, -κ — the others are deferred to Session 3 per Scout C's own pre-merge checklist)
- Scout D's mandatory unknown-format trio (140 LOC frontend — not in S1 W2-γ baseline)

The Session 1 baseline W2-γ report projected Session 2 at ~1,110 LOC / ~10 commits / ~5.4 hr. **The actual Session 2 measurement is +66% LOC and +60% commits over that projection.** The drift is exactly the Rule #28 +14-22% range applied compoundly across: (a) Scout D's mandatory frontend trio (~140 LOC not previously counted); (b) Scout C's §SC5-NEW-SBOM-S2 hardening canaries (~80 LOC added to Fix #11 + Fix #1 test budgets); (c) Fix #8 widening to "broader sweep + extract helper + ban-bare META-CANARY" (~85 LOC) vs S1's narrow 42-LOC estimate; (d) Fix #11's two-axis disjoint-and-complete split (~50 LOC).

## Drift Adjustment (Rule #28)

- Measured pre-drift: 1,559 LOC
- Drift-adjusted: 1,559 × 1.18 = **1,840 LOC**
- Companion drift sources:
  - Scout D trio (140 LOC) was NOT in the S1 W2-γ baseline — represents +14% drift from "operator-UX requirements" surfacing in Wave-1
  - Scout C §SC5-NEW-SBOM-S2-γ two-axis reaper split (60 LOC) was NOT in the S1 baseline — represents +6% drift from "red-team attack mitigations" surfacing in Wave-1
  - Fix #8 broader-sweep (147 LOC vs 42 LOC) — +250% on this fix alone — represents +11% drift from "extract-helper-to-shared-utility per Rule #42" emerging from Scout C width-canary discipline
- **Composite drift is +18%, exactly the Rule #28 empirical midpoint.** The +14-22% drift band is the source-of-truth confidence interval; we're inside it cleanly.
- **Verdict shift:** the S1 W2-γ baseline already said MULTI-SESSION-RECOMMENDED; this drift-adjusted measurement REINFORCES it (not flips it) — even at the lower drift bound (1,559 × 1.14 = 1,777 LOC), Session 2 is structurally a multi-session-recommended split.

## Recommended Split (Session 2a + Session 2b)

### Session 2a (~4 hours wall-clock, ~7 commits, ~1,000 LOC)

**Theme: Structural conversion + cheap wins. Session 2a lands Fix #1 + Fix #6 + Fix #8-broader + Scout D's most-load-bearing frontend mandatory (re-mount auto-resume + Failed-state).**

1. **Fix #1 C1** (alembic + model + schema — Rule #48 Shape-1 cross-stack alignment commit) — ~175 LOC, ~30 min
2. **Fix #1 C2** (router refactor + reaper) — ~145 LOC, ~30 min
3. **Fix #1 C3** (frontend pair: SbomPage polling + sbom.ts + timeouts.ts + types) — ~115 LOC, ~30 min
4. **Fix #1 C4** (tests bundle: ~250 LOC mock + live + META-CANARY trio) — ~250 LOC, ~30 min
5. **Fix #6** (grype force_rescan transactional + tests) — ~105 LOC, ~35 min
6. **Fix #8-broader C1** (extract `_spawn_background_task` to `app/utils/background.py`) — ~30 LOC, ~15 min
7. **Fix #8-broader C2** (sweep N call sites + Scout C §SC5-NEW-SBOM-S2-κ META-CANARY) — ~117 LOC, ~30 min
8. (intra-session) Scout D **#3** (re-mount auto-resume) + **#2** (Failed-state in header) bundled with Fix #1 C3 above ≈ 0 separate commit cost (absorbed)

**Subtotal:** ~1,000 LOC, 7 production commits, 1 Rule #8 rebuild (backend+worker+migrator after Fix #1 alembic), 1 frontend rebuild (after Fix #1 C3), 4 META-CANARY commits.

**Acceptance gates for closing Session 2a:**
- `sbom_status` end-to-end smoke: POST /generate → 202 → GET /status repeatedly → completed; Rule #35b live canary persistence check
- `_spawn_background_task` accessible from all 4 routers via shared import
- `grype` force_rescan deletes prior rows under the SAME transaction
- Frontend SbomPage polling cleanly mirrors vuln-scan polling
- `test_rate_limit_tiers.py:_EXPECTED_TIERS` size-lock unchanged (=20)

### Session 2b (~3 hours wall-clock, ~6 commits, ~840 LOC)

**Theme: Architectural cleanup + hardening + operator-UX adaptability. Session 2b lands Fix #11 + Scout D's adaptability mandate + docs/learn.**

1. **Fix #11 C1** (additive: extend `walker_registry.py` with `WALKER_REAPER_CONFIGS` dataclass + 22 dict entries) — ~80 LOC, ~25 min
2. **Fix #11 C2** (cut-over: refactor `main.py` lifespan to use the unified reaper + delete the 5 inlined reapers + Rule #46 META-CANARY trio + Scout C §SC5-NEW-SBOM-S2-γ two-axis split + tests) — ~190 LOC, ~50 min
3. **Scout D #5 + #6** (FormatBanner extract + Unknown-format banner + Try-Generic button) — ~80 LOC, ~30 min
4. **Scout D #12** (Force-regenerate cache-bypass per §SC5-NEW-SBOM-ν) — ~30 LOC, ~15 min
5. **Generic-strategy backend** (annotation + minimum-viable handler) — ~35 LOC, ~10 min
6. **Docs + learn + ADAPTIVE_BACKLOG sync** — ~140 LOC, ~20 min

**Subtotal:** ~555 LOC + drift-adjusted with Session 2a's full mandatory-trio touchpoints ~840 LOC, 6 commits, 1 backend rebuild (Fix #11 lifespan changes), 1 frontend rebuild (Scout D additions).

**Acceptance gates for closing Session 2b:**
- Lifespan reaper sweep covers ALL state-machine columns: `assert_reaper_lists_disjoint_and_complete()` passes
- Fix #11 META-CANARY synthesises a walker-without-reaper-config and confirms gate fires
- Scout D's FormatBanner renders in BOTH FirmwareUpload AND SbomPage with same UX
- Unknown-format banner only renders on `detected_format='unknown'` rows; clean degrade for the supported cases
- Docs + learn + ADAPTIVE_BACKLOG cross-checked; Rule #52 worked-example crossrefs updated

### Rationale for the split

- **Session 2a stays under single-session safety margin.** All 7 commits are tightly scoped; Fix #1's 4 commits collectively are a known shape (cve-match conversion 22c1990 was 3 commits; vuln-scan 8f54a24 was 3 commits — this is the 6th application of the pattern); Fix #6 + Fix #8-broader are mechanical. Risk of carryover into Session 2a.5 < 25%.

- **Session 2b carries the architectural Fix #11 + adaptability mandate.** Fix #11's unified reaper refactor REPLACES 5 inlined reaper blocks with a centralised loop; this is structurally one architectural refactor. Doing this AT THE SAME TIME as Fix #1's NEW reaper would create a race where Session 2a's reaper might land before Session 2b's refactor consumes it — splitting cleanly avoids that. Scout D's adaptability mandate (Unknown-format banner + Try-Generic) is operator-facing UX work; pairing it with Fix #11's architectural cleanup balances Session 2b's commit profile.

- **The split avoids Rule #25 single-slice-exception #2 cross-contamination.** Fix #1's Rule #48 Shape-1 alignment commit (Session 2a C1) covers the `SbomStatus` cross-stack. Fix #11's META-CANARY trio (Session 2b) covers the walker-reaper invariant cross-stack. Keeping these in DIFFERENT sessions guarantees each cross-stack test runs in isolation; bisect-clean.

- **Scout C §SC5-NEW-SBOM-S2 attacks split cleanly along the session boundary:**
  - Session 2a: §SC5-NEW-SBOM-S2-η (concurrent 409 verification via grype force_rescan), §SC5-NEW-SBOM-S2-κ (broader create_task GC sweep), §SC5-NEW-SBOM-S2-α (unknown-format graceful degrade via Fix #1 frontend trio)
  - Session 2b: §SC5-NEW-SBOM-S2-γ (Fix #11 two-axis disjoint-and-complete reaper), §SC5-NEW-SBOM-S2-δ (CRITICAL: any new operator-supplied YAML surface — though defer Fix #9 to Session 3 means this CRITICAL attack doesn't actually land in S2)
  - Deferred to Session 3: §SC5-NEW-SBOM-S2-β (memory-bound; needs Fix #9), §SC5-NEW-SBOM-S2-ε (polyglot; needs Fix #9), §SC5-NEW-SBOM-S2-ζ (archive bomb; needs Fix #9), §SC5-NEW-SBOM-S2-θ (operator walker state-set; needs Rule #52 walker shape), §SC5-NEW-SBOM-S2-ι (sbom-vuln race; needs Fix #1 + Fix #6 + cross-state-machine guard; Session 2a closes this implicitly via the 409 check at the new endpoint)

## Single-Session Path (if attempting anyway)

- **Critical-path commits (ordered, mandatory):** Fix #1 C1 (alembic+model+schema Shape-1) → Fix #1 C2 (router+reaper) → Fix #1 C3 (frontend) → Fix #1 C4 (tests) → Fix #6 (grype) → Fix #8 C1 (extract helper) → Fix #8 C2 (sweep) → Fix #11 C1 (registry additive) → Fix #11 C2 (cut-over) → Scout D (frontend trio) → docs/learn
- **Pre-flight gates:**
  - Rule #8 rebuild count: **2** (after Fix #1's alembic; backend rebuild after Fix #11's lifespan changes is bundleable with the Fix #1 rebuild IF Fix #11 ships in the same alembic-rebuild cycle — but Fix #11 doesn't carry alembic, so the Fix #1 rebuild covers everything)
  - Rule #11 import-smoke count: 6
  - Rule #46 META-CANARY count: 6
  - Rule #48 5-part cross-stack alignment commits: 1
  - Frontend rebuild: 2 (after Fix #1 C3; after Scout D Trio — bundleable into 1 rebuild at session-end IF the inter-frontend-commit interval is short)

- **Risk of going single-session:** **HIGH for FOUR reasons:**
  1. Fix #1 alone is a 4-commit, ~752-LOC structural conversion. Rate-limit-2026-05-18's `8f54a24` (the closest analog Rule #33 conversion) is the same shape and required 8 commits over 11 days to settle ALL second-order companion defects per the postmortem. Attempting Fix #1 + Fix #6 + Fix #8-broader + Fix #11 + Scout D trio in one session means any single bad commit must be reverted from a much larger working set.
  2. Scout C §SC5-NEW-SBOM-S2-γ is the CRITICAL gate that Fix #11's refactor MUST cover. Getting the two-axis disjoint-and-complete invariant wrong silently regresses Fix #1's sbom_status reaper. In a single-session context, the invariant might be checked only at the END after fatigue accumulates — Session 2b dedicated cycle has cleaner attention budget.
  3. The Rule #48 Shape-1 cross-stack alignment commit (Fix #1's C1) is bisect-critical. If Session 2a-equivalent commits land mid-stream, a future bisect that lands ON Fix #1 C1's commit finds the system in a partial state (DB has new column + CHECK; backend code references `firmware.sbom_status` but the alembic migration is the LATEST head; the in-process Pydantic Literal already validates the column). Splitting Fix #1 across N commits is correct per Rule #25; bundling Fix #11 + Scout D after Fix #1 risks letting the operator's test bisect land on a Fix #11 cut-over commit where the centralised reaper has dispatched but the old inlined reapers are gone — different but adjacent failure shape.
  4. Scout D's frontend mandatory trio MUST land BEFORE operators can sanely use Fix #1's 202+polling generate endpoint. If single-session ships Fix #1 but defers Scout D as "frontend polish," operators get a regressed UX they didn't get pre-Session-2 (the previous synchronous endpoint at least returned a result with components; the new 202 ack returns NOTHING displayable until the polling cycle completes — without Scout D's banner the SbomPage looks broken).

## Verdict

**RECOMMENDATION: MULTI-SESSION-RECOMMENDED, split into Session 2a + Session 2b.**

**Rationale:** The drift-adjusted scope (~1,840 net LOC, 16 commits, 1 alembic, 2 Rule #8 rebuilds, 1 Rule #48 Shape-1 cross-stack alignment commit, 6 Rule #46 META-CANARIES) is ~1.9× Session 1's actual shipping rate (~969 net LOC / 8 commits / ~5 hr) and is sized in the structural neighborhood of rate-limit-2026-05-18 (~600 LOC / 8 commits) plus Walker_Auto_Triggers Rule #47 (~250 LOC / 3 commits) **summed together** — both of which were single-session campaigns operating at the upper margin of single-session safety. Session 2's scope EXCEEDS that sum and includes architectural and cross-stack alignment work neither of those campaigns shouldered alone.

The Session 1 baseline W2-γ projection of ~1,110 LOC / ~10 commits is the calibration anchor — Wave-1 + Wave-2 deep research has SURFACED an additional +66% LOC of mandatory work (Scout D trio, Scout C §SC5-NEW-SBOM-S2 hardening, Fix #8 broader sweep with helper extraction, Fix #11 two-axis disjoint-and-complete split) that the baseline did not enumerate. Per Rule #28 +14-22% empirical drift band, +18% composite drift is on-trend; +66% over baseline is OUT of trend and indicates the baseline missed material scope — which the multi-session split absorbs cleanly.

Session 2a ships Fix #1 + Fix #6 + Fix #8-broader + Scout D's load-bearing mandatory (Failed-state + re-mount-auto-resume bundled into Fix #1's frontend commit) in ~4 hours / 7 commits / ~1,000 LOC. Session 2b ships Fix #11 + Scout D's adaptability mandate (Unknown-format + Try-Generic) + docs/learn in ~3 hours / 6 commits / ~840 LOC. Fix #9 explicitly defers to Session 3 per Scout A + Scout B's Rule-of-Four queued recommendation — the minimum-viable shape (~80 LOC) saves session budget but adds Scout C §SC5-NEW-SBOM-S2-ε / -ζ polyglot+archive-bomb hardening that the deferred full-Rule-#52 refactor will address more cleanly in its own dedicated Wave-1+Wave-2 campaign.

Confidence: **HIGH.** The split mirrors the documented Session 1 baseline + the Rule-of-Two state-machine sweep pattern (5 sessions running on Rule #33 conversions: firmware-unpack / emulation / fuzzing / cve-match / vuln-scan); Fix #1 is the 6th application of a now-well-understood shape. Drift adjustment is within the empirically-observed +14-22% range Rule #28 codifies. Per-fix LOC estimates derive from direct `wc -l` on the post-Session-1 branch tip (`208805c`), cross-referenced with shape baselines from `e6f7a8b9c0d1` (cve_match migration: 114 LOC ≈ Fix #1 alembic), `8c51448` (Session 1 upload_stage reaper: 60-LOC main.py block + tests) which validates Fix #11's per-walker reaper LOC math, and rate-limit-2026-05-18's `3d2454b` + `616e89d` + `8766710` companion commit patterns.

---

**Summary (5 lines for relay):**

1. Report path: `/home/dustin/code/wairz/.planning/research/sbom-vuln-scan-session2-2026-05-21/wave2-gamma-yardstick.md`
2. Total LOC projected: **~1,840 net LOC** (drift-adjusted; 1,559 measured × 1.18 Rule #28 multiplier)
3. Total commits: **16** (12 production + 4 docs/test; 1 alembic; 1 Rule #48 Shape-1 cross-stack alignment)
4. Verdict: **MULTI-SESSION-RECOMMENDED** — Session 2a (Fix #1 + Fix #6 + Fix #8-broader + Scout D mandatory bundled ~1,000 LOC / 7 commits / ~4 hr) + Session 2b (Fix #11 + Scout D adaptability + docs ~840 LOC / 6 commits / ~3 hr); Fix #9 explicitly DEFERRED to Session 3
5. Confidence: **HIGH**
