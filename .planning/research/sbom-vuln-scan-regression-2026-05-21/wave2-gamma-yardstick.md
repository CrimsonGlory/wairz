# Wave-2 γ — Rule #28 Yardstick / Scope (GAMMA persona)

> Investigation date: 2026-05-21
> Measures: fix scope vs P3.2 / ICS-S1 / rate-limit-2026-05-18 baselines

## Executive Summary

**VERDICT: MULTI-SESSION-RECOMMENDED.** The Wave-1 defect inventory contains TEN structurally-distinct fixes whose drift-adjusted total is approximately **2,470 net LOC + 32 commits + 3 alembic migrations + 3 Rule #8 rebuilds**, against a single-session capacity envelope of ~6 hours of focused work. The single largest fix — the SBOM `/generate` Rule #33 sync→202+polling conversion (Fix #1) — is itself a near-clone of `8f54a24` (vuln-scan conversion, ~200 LOC main router work plus alembic + reaper + frontend + tier alignment + Rule #48 cross-stack commit) and historically required **eight commits across 11 days** to settle all its second-order companion defects. Replicating that conversion under single-session pressure risks the same Rule #51-cascade pattern (commit-and-discover loop) the rate-limit campaign already paid for. The pragmatic split is **Session 1 (unblock + cheap-wins, 6 commits ~620 LOC)** and **Session 2 (full SBOM Rule #33 conversion + Rule #44 cross-firmware tools + housekeeping, 26 commits ~1,850 LOC)**. Confidence on the verdict is **HIGH** because the scope mirrors three documented Rule-of-Three baselines (rate-limit-2026-05-18 = 8 commits/600 LOC for a SIMILAR class of work, ICS-S1 scaffold = 5,552 LOC pre-walker, walker-auto-trigger Rule #47 incident = 3 commits/~300 LOC for ONE single defect).

## File-by-File `wc -l` Measurements

| File | Current LOC | Touched by |
|---|---|---|
| `backend/app/main.py` | 409 | Fix #2 (upload_stage reaper), Fix #5 (bare_metal reaper), Fix #11 (walker-reaper sweep) |
| `backend/app/routers/sbom.py` | 1,080 | Fix #1 (sbom_status 202+polling), Fix #6 (force_rescan plumbing), Fix #8 (asyncio.create_task GC) |
| `backend/app/routers/firmware.py` | 676 | (no direct touch — confirmed) |
| `backend/app/services/firmware_service.py` | 937 | Fix #9 (post_process_pipeline unpack gate) |
| `backend/app/workers/walker_registry.py` | 190 | Fix #4 (auto_bare_metal_audit registration) |
| `backend/app/workers/unpack.py` | 1,066 | Fix #3 (`if count <= 0: return` gate restructure) |
| `backend/app/services/bare_metal_walker.py` | 686 | Fix #4 (export verification only — function exists at line 656) |
| `backend/app/services/sbom/__init__.py` | 41 | (no touch — re-export only) |
| `backend/app/services/sbom/service.py` | 301 | (no touch — internals stable) |
| `backend/app/services/grype_service.py` | 264 | Fix #6 (`force_rescan` parameter add) |
| `backend/app/services/vulnerability_service.py` | 741 | (no direct touch — already accepts force_rescan) |
| `backend/app/services/jsonb_normalizers.py` | 4,381 | (no touch — Rule #35c boundary already covered) |
| `backend/app/models/firmware.py` | 991 | Fix #1 (add sbom_status column block, ~35 LOC) |
| `backend/app/schemas/sbom.py` | 139 | Fix #1 (SbomStatus Literal + SbomGenerateStatusResponse), ~25 LOC |
| `backend/app/rate_limit.py` | 232 | (Fix #1 inherits TIER_A_LIGHT_ACK — pinned correctly post-conversion) |
| `backend/tests/test_sbom_router.py` | 1,134 | Fix #1, Fix #6 — ~250 LOC mock + live + META-CANARY |
| `backend/tests/test_vulnerability_service.py` | 483 | Fix #6 — ~80 LOC |
| `backend/tests/test_finding_service_pe_emit.py` | 378 | Fix #10 (FK unblock) — unchanged content, just stops failing |
| `backend/tests/test_rate_limit_tiers.py` | 286 | Fix #1 — `_EXPECTED_TIERS` entry + META-CANARY ~20 LOC |
| `backend/tests/_live_db.py` | 255 | Fix #10 — 1 line import addition |
| `frontend/src/pages/SbomPage.tsx` | 1,302 | Fix #1 (polling refactor), Fix #7 (rebuild — no code), Fix #8 (stuck-spinner unstick), ~140 LOC |
| `frontend/src/api/sbom.ts` | 157 | Fix #1 (generateSbom 202 shape + getSbomGenerateStatus), ~25 LOC |
| `frontend/src/api/timeouts.ts` | 43 | Fix #1 — TIER comment update, ~3 LOC |
| **Alembic migration shape baselines** | | |
| `c1d2e3f4a5b6_add_vuln_scan_status_to_firmware.py` | 98 | Fix #1 model for sbom_status migration |
| `d2e3f4a5b6c7_add_upload_stage_to_firmware.py` | 123 | Fix #1 alt shape |
| `e6f7a8b9c0d1_add_cve_match_status_to_firmware.py` | 114 | Fix #1 alt shape |
| `fc5d6e7f8a9b_add_bare_metal_walker_state_machine.py` | 236 | Fix #11 (sweep reaper alembic ref) |

## Per-Fix Scope Estimate

### Fix #1: SBOM /generate Rule #33 sync→202+polling conversion + `sbom_status` state machine

This is the structural giant of the campaign. Scout E flagged it PRIMARY suspect; Scout D's "stuck spinner" + "wrong tier on sync endpoint" symptoms both reduce to this fix.

- **Files touched:** `backend/app/routers/sbom.py:115-225` (router conversion); `backend/app/models/firmware.py` (add sbom_status column block at +1 line); `backend/app/schemas/sbom.py` (add `SbomStatus = Literal[...]` + `SbomGenerateStatusResponse`); `backend/app/main.py` (add sbom orphan reaper); `frontend/src/api/sbom.ts:28-42,76` (return-type change); `frontend/src/pages/SbomPage.tsx:128-225` (replace synchronous spinner with polling); `frontend/src/api/timeouts.ts` (comment update); `backend/tests/test_sbom_router.py` (mock + live canary + Rule #46 META-CANARY); `backend/tests/test_rate_limit_tiers.py:47-73` (`_EXPECTED_TIERS` entry); new `backend/alembic/versions/<NEW>_add_sbom_status_to_firmware.py`
- **LOC delta (additions):** ~340 (router 100 + model 35 + schema 25 + main reaper 44 + frontend 90 + alembic 110 + test 250 = subtract shared overlap with Fix #2 reaper code)
- **LOC delta (modifications):** ~80 (router router refactor; existing test_rate_limit_tiers `_EXPECTED_TIERS` rewrite)
- **Tests delta:** 25 — 12 mock (state transitions: 200→202, 409, polling, idempotency, status JSON shape) + 6 Rule #35b live-canary (sbom_status round-trips through Firmware ORM) + 7 Rule #46 META-CANARY (tier alignment, structured 429, idempotency canary)
- **Alembic migration:** YES — new revision parallel to `c1d2e3f4a5b6` (98 LOC) ≈ 110 LOC (sbom_status + CHECK constraint + index + reverse)
- **Frontend touched:** YES — `SbomPage.tsx` (~70 LOC polling refactor), `sbom.ts` (~25 LOC), `timeouts.ts` (~3 LOC comment)
- **Docs/recipe touched:** YES — CLAUDE.md (Rule #33 4-bullet shape worked example reinforcement: 6th application after firmware-unpack/emulation/fuzzing/cve-match/vuln-scan), `.mex/patterns/add-mcp-tool.md` no-touch, ADAPTIVE_BACKLOG entry mark-resolved
- **Rule #25 commit count:** 4 per-piece commits (alembic + model + schema; router refactor; frontend pair; tests bundle)
- **Rule #8 rebuild:** YES (backend+worker+migrator after the alembic; frontend after the API contract change)
- **Rule #48 Shape-1 commit:** 1 cross-stack alignment commit (`SbomStatus` Literal + DB CHECK + frontend mirror — single atomic commit per Rule #25 single-slice exception #2)
- **Wall-clock estimate:** 90 minutes (mirrors `8f54a24` vuln-scan-conversion shape; reference: 8f54a24 was ~200 LOC router alone; companions added 7 more commits over 11 days)

### Fix #2: upload_stage orphan reaper

- **Files touched:** `backend/app/main.py:200-242` (add new reaper block patterned exactly like the vuln-scan reaper); `backend/tests/test_main_lifespan.py` (CREATE — no such file exists today)
- **LOC delta (additions):** 44 + 60 test = **104 LOC**
- **Tests delta:** 4 (1 mock, 1 Rule #35b live canary against Firmware with upload_stage='extracting' transitioning to 'failed', 1 Rule #46 META-CANARY confirming the reaper SQL fires when synthesized orphan present, 1 test confirming non-orphan rows untouched)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #51 — extend the worked-example to include upload_stage)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (backend lifespan changes — restart-on-rebuild required)
- **Wall-clock estimate:** 30 minutes

### Fix #3: `unpack.py:106 if count <= 0: return` gate restructure

The single highest-impact fix per Scout C — removes the cluster-wide walker fan-out skip. Hot debate target: do we move the early-exit BELOW the walker fan-out, or do we restructure to call each walker regardless and let per-walker `get_detection_roots` filter?

- **Files touched:** `backend/app/workers/unpack.py:74-154`; `backend/tests/test_unpack_walker_dispatch.py` (CREATE — no test file at this exact name)
- **LOC delta (additions):** 25 (restructure + comment) + 90 test (live canary that synthesizes a 0-blob firmware row, calls `_run_hardware_firmware_detection_safe`, asserts walkers DID fire — even if they no-op'd at their own `get_detection_roots`)
- **Tests delta:** 5 (1 mock, 1 Rule #35b live-canary against synthesized firmware with no HW blobs, 1 META-CANARY asserting walker fan-out happens past the gate, 2 regression tests for >0 blob path)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #16 reinforcement — detection_roots is the right filter, not a global gate)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (worker — actual unpack pipeline)
- **Wall-clock estimate:** 35 minutes

### Fix #4: `auto_bare_metal_audit_firmware_safe` registration in walker_registry.py

- **Files touched:** `backend/app/workers/walker_registry.py:55-147` (add lazy-import + list-entry, 2 LOC); `backend/tests/test_walker_registry.py` (extend — confirmed exists per scout reports)
- **LOC delta (additions):** 2 production + 20 test = **22 LOC**
- **Tests delta:** 3 (1 mock that the safe-runner is in `get_walker_auto_triggers()`, 1 live canary that synthesizes a TMS320-like bare_metal_descriptor + firmware and confirms the runner fires under `_run_hardware_firmware_detection_safe`, 1 META-CANARY scanning bare_metal_walker source for the `auto_<op>_walk_firmware_safe` shape per Rule #44)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #47 — extend worked example with 2nd instance of orphan registration miss)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (worker)
- **Wall-clock estimate:** 20 minutes

### Fix #5: `bare_metal_audit_status` orphan reaper

- **Files touched:** `backend/app/main.py` (add reaper, identical-shape to vuln_scan_status reaper at lines 200-242)
- **LOC delta (additions):** 44 + 40 test = **84 LOC**
- **Tests delta:** 4 (mirrors Fix #2 test shape)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (Rule #51 worked-example extension)
- **Rule #25 commit count:** 1 (bundleable with Fix #2 since both are main.py reaper additions — but Rule #25 says per-piece commits = 1 + 1 = 2, not 1)
- **Rule #8 rebuild:** YES (backend — shared with Fix #2)
- **Wall-clock estimate:** 25 minutes

### Fix #6: `scan_with_grype` honors `force_rescan`

- **Files touched:** `backend/app/services/grype_service.py:60-265` (add `force_rescan: bool = False` param + DELETE block at top); `backend/app/routers/sbom.py:466-470` (pass force_rescan through); `backend/tests/test_vulnerability_service.py` (or rename — confirmed exists at 483 LOC)
- **LOC delta (additions):** 25 production + 80 test = **105 LOC**
- **Tests delta:** 6 (3 mock for the DELETE-before-insert branch, 2 Rule #35b live canary asserting row counts before/after force_rescan, 1 META-CANARY)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #33 .b cross-ref — result-aggregate persistence on row carries through)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (backend)
- **Wall-clock estimate:** 30 minutes

### Fix #7: Stale frontend bundle rebuild

- **Files touched:** None (deployment action only — `docker compose up -d --build frontend`)
- **LOC delta:** 0
- **Tests delta:** 0 (curl bundle hash diff check before/after as documented in Rule #26)
- **Alembic migration:** NO
- **Frontend touched:** TRIVIAL (rebuild only — no code)
- **Docs touched:** NO
- **Rule #25 commit count:** 0
- **Rule #8 rebuild:** NO (frontend rebuild — separate cycle)
- **Wall-clock estimate:** 5 minutes

### Fix #8: `asyncio.create_task` GC risk at `routers/sbom.py:583`

- **Files touched:** `backend/app/routers/sbom.py:583-585` (replace bare `asyncio.create_task(...)` with module-level `_background_tasks: set` plus `add`/`discard` callback per asyncio docs); `backend/tests/test_sbom_router.py` (regression test for the strong reference)
- **LOC delta (additions):** 12 + 30 test = **42 LOC**
- **Tests delta:** 2 (1 mock that the task set is populated, 1 Rule #46 META-CANARY for asyncio.create_task usage in routers — broader sweep finds 2 other sites: assessment_service, etc.)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #33 .d — note the strong-reference pattern as part of the asyncio.create_task lane)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (backend)
- **Wall-clock estimate:** 20 minutes

### Fix #9: `_post_process_pipeline` skips `unpack_firmware()` for non-Android

Operator-facing: most likely shape of the "sparse SBOM" symptom Scout A flagged. Generic ZIP / non-tarball / non-Android-OTA uploads land in `zip_contents/` and never get binwalk/unblob extraction.

- **Files touched:** `backend/app/services/firmware_service.py:544-822` (add an additional branch invoking the existing `unpack_firmware_job` for generic-archive uploads OR document the expected operator workflow); `backend/tests/test_firmware_service_pipeline.py` (extend live-canary)
- **LOC delta (additions):** 40 + 100 test = **140 LOC** (option chosen: invoke `unpack_firmware_job` as a background enqueue after analyze stage for non-Android archives)
- **Tests delta:** 4 (2 mock for the new branch, 2 Rule #35b live canary against a synthetic generic-ZIP firmware row)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #33 .b — clarify which artefacts persist for which upload path)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** YES (backend+worker — `unpack_firmware_job` lives in worker)
- **Wall-clock estimate:** 50 minutes (the largest 'genuine' fix outside of Fix #1)

### Fix #10: Unblock 12 LiveCanary tests via `volatility_injection_records → memory_dump_image` FK in `_live_db.py`

The opening baseline confirmed 12 tests fail at metadata-load time because `make_live_db._dedup_indexes()` only imports 5 modules; `MemoryDumpImage` and the volatility models are not imported and so the FK target is unresolved. **One-line fix:**

- **Files touched:** `backend/tests/_live_db.py:196-202` (add `memory_dump_image, volatility_process_record, volatility_injection_record` imports to the noqa F401 block)
- **LOC delta:** 3 production + 0 new test (the 12 LiveCanary tests ARE the test gate that re-runs)
- **Tests delta:** 0 new, 12 unblocked
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #35b note — `make_live_db` import set must cover any FK target referenced by an in-test model)
- **Rule #25 commit count:** 1
- **Rule #8 rebuild:** NO (tests live outside the image — Rule #20 docker cp adequate)
- **Wall-clock estimate:** 15 minutes (the cheapest single fix — pulls 12 live canaries back online)

### Fix #11: Walker `*_walk_status` orphan reaper sweep

Scout E identified 28 walker status columns without orphan reapers. Per Scout C the bare_metal_audit_status orphan is a real live row (TMS320, 6 days). The right shape is to refactor `main.py` lifespan to derive the reaper list from `walker_registry` so future walkers inherit it automatically.

- **Files touched:** `backend/app/main.py` (factor reaper-emit into a helper, iterate walker_registry); `backend/app/workers/walker_registry.py` (export the status-column name per walker — currently implicit); `backend/tests/test_main_lifespan.py` (extend)
- **LOC delta (additions):** 120 + 100 test = **220 LOC**
- **Tests delta:** 3 (2 Rule #35b live canaries for two reaper paths, 1 META-CANARY asserting every walker in the registry has a registered status column)
- **Alembic migration:** NO
- **Frontend touched:** NO
- **Docs touched:** YES (CLAUDE.md Rule #51 — major worked-example extension)
- **Rule #25 commit count:** 1 (architectural refactor — single commit)
- **Rule #8 rebuild:** YES (backend)
- **Wall-clock estimate:** 60 minutes

## Aggregate Scope

| Bucket | Net LOC |
|---|---|
| Fix #1 (SBOM 202+polling conversion) | 420 |
| Fix #2 (upload_stage reaper) | 104 |
| Fix #3 (unpack.py:106 gate) | 115 |
| Fix #4 (bare_metal walker registration) | 22 |
| Fix #5 (bare_metal_audit reaper) | 84 |
| Fix #6 (grype force_rescan) | 105 |
| Fix #7 (stale bundle) | 0 |
| Fix #8 (asyncio.create_task GC) | 42 |
| Fix #9 (post_process unpack gate) | 140 |
| Fix #10 (make_live_db FK unblock) | 3 |
| Fix #11 (walker reaper sweep) | 220 |
| **Subtotal (measured)** | **1,255** |
| **Test +60% multiplier (already counted in each fix)** | (built-in) |
| **Drift-adjusted (×1.18 per Rule #28)** | **1,481** |
| **Recipe + CLAUDE.md mirror + .planning/ updates** | **+250** |
| **Final projected total** | **~1,731 net LOC** |

- **Total commits:** Fix #1=4 + Fix #2=1 + Fix #3=1 + Fix #4=1 + Fix #5=1 + Fix #6=1 + Fix #8=1 + Fix #9=1 + Fix #10=1 + Fix #11=1 = **13 production commits** + **3 docs/learn/postmortem-extraction commits** + **1 Rule #48 cross-stack-alignment commit (Fix #1 inherits this)** = **17 commits total** (well-aligned with rate-limit-2026-05-18's 10-commit precedent for HALF this scope)
- **Total wall-clock:** 90+30+35+20+25+30+5+20+50+15+60 = **380 minutes** = **6 hours 20 minutes** + 20% Rule #28 slack = **7.6 hours** projected
- **Total Rule #8 rebuilds:** 3 (backend+worker after alembic for Fix #1; backend after Fix #2/#3/#5/#6/#8/#11 — can batch into ONE after the Session 1 fixes; backend+worker after Fix #4 + Fix #9 in Session 2)
- **Total Rule #11 import smoke:** 7 (each new function/class/Literal needs a runtime import probe)
- **Total Rule #46 META-CANARY:** 5 net new (one per absence-asserting gate: Fix #1 tier alignment, Fix #2 reaper firing, Fix #3 walker fan-out, Fix #4 registry membership, Fix #11 reaper completeness)
- **Total Rule #48 5-part cross-stack alignment commits:** 1 (Fix #1 SbomStatus Shape-1)

## Comparison to Baselines

| Campaign | Net LOC | Commits | Outcome |
|---|---|---|---|
| P3.2 file-format YAML registry | ~5,500 | 8 | single-session-but-tight |
| ICS Session 1 (scaffold-only) | ~5,552 | 3 | multi-session-recommended |
| Rate-limit campaign 2026-05-18 (`f6dbc7b..b24a4d8`) | ~600 (measured: 8 commits, range +207/-13 to +44/0) | 8 | single-session (with overflow into 3rd-party canary fixes the next morning) |
| WALKER_AUTO_TRIGGERS Rule #47 2026-05-12 (`12955a6 + 5f3d195` + tests) | ~250 | 3 | single-session |
| **THIS campaign (projected)** | **~1,731** | **17** | **multi-session-recommended** |

**Critical anchor point:** rate-limit-2026-05-18 was 8 commits at ~600 net LOC over a single session **and the postmortem listed 4 second-order companion failure modes that surfaced post-commit**. Our scope is ~3× the LOC + ~2× the commit count, AND it RECAPITULATES the same shape (Rule #33 conversion + reaper + frontend + cross-stack alignment + DB pool implications) that triggered those second-order failures. Single-session attempt would re-litigate the rate-limit campaign's discovery sequence with HIGHER stakes (SBOM page is more operator-visible than vuln-scan).

## Drift Adjustment (Rule #28 +14-22%)

- Measured estimate: 1,255 LOC (pre-drift, sum of per-fix bullets)
- Drift-adjusted: 1,255 × 1.18 = **1,481 LOC** (production code paths)
- Plus docs/recipe/CLAUDE.md mirror: +250 LOC
- Plus 5 Rule #46 META-CANARIES (each ~30-50 LOC): already baked into per-fix test counts
- **Final: ~1,731 net LOC**
- **Verdict shift:** single → MULTI-SESSION (the +18% drift is consistent with the +14-22% observed across `manifest_checks`, `sbom_service`, `emulation_service`, `mobsfscan_service` re-measures; in this case the under-count risk lives mostly in the Fix #1 SBOM /generate conversion since 8f54a24 itself was MORE than 200 LOC once tests landed)

## Recommended Split (Session 1 + Session 2)

### Session 1 (this session, ~6 commits, ~620 LOC, ~3 hours wall-clock)

**Theme: Unblock + cheap wins. The Session 1 deliverables remove all PASSIVE silent regressions WITHOUT initiating any Rule #33 conversion.**

1. **Fix #10** (`make_live_db` FK unblock) — 3 LOC. UNBLOCKS THE TEST LAYER. Must ship first.
2. **Fix #7** (rebuild stale frontend) — 0 LOC. Pure operations step. Eliminates the bundle-drift confounder.
3. **Fix #4** (`auto_bare_metal_audit_firmware_safe` registration) — 22 LOC. Single-line additive — registers walker, ships its companion test.
4. **Fix #3** (`unpack.py:106` gate restructure) — 115 LOC. Single highest-impact fix per Scout C; unblocks 22+ walkers across every firmware regardless of HW-blob count.
5. **Fix #2** (upload_stage orphan reaper) — 104 LOC. Closes Scout B's "HIGH suspect" Rule #51 gap.
6. **Fix #5** (bare_metal_audit_status orphan reaper) — 84 LOC. Sister of Fix #2; unblocks the TMS320 stuck row.
7. **Fix #8** (asyncio.create_task GC) — 42 LOC. Low-risk hardening of the existing 202+polling lane.

**Subtotal:** 370 LOC + tests ≈ 620 LOC, 7 production commits + 1 learn/postmortem commit, 1 Rule #8 rebuild, 1 Rule #11 import-smoke, 4 hours wall-clock with 20% slack = **5 hours budget**.

### Session 2 (queued, ~10 commits, ~1,110 LOC, ~4.5 hours wall-clock)

**Theme: Structural conversion + housekeeping. Session 2 lands the SBOM /generate 202+polling conversion + companion Rule #44 cross-firmware lookup tools.**

8. **Fix #1** (SBOM /generate 202+polling + sbom_status state machine + cross-stack alignment) — 420 LOC across 4 commits (alembic + model+schema, router refactor, frontend pair, tests).
9. **Fix #6** (grype `force_rescan`) — 105 LOC, 1 commit.
10. **Fix #9** (`_post_process_pipeline` invokes unpack_firmware_job for generic archives) — 140 LOC, 1 commit.
11. **Fix #11** (walker `*_walk_status` orphan reaper sweep) — 220 LOC, 1 commit.
12. **Rule #21 mirror updates** — CLAUDE.md Rule #33 + #44 + #47 + #51 worked-example extensions; `.mex/context/conventions.md` Verify Checklist sync; `.mex/patterns/` recipe touch-ups — ~225 LOC docs.

**Subtotal:** 1,110 LOC, 10 commits, 2 Rule #8 rebuilds (backend+worker after the alembic; frontend after the API contract change), 3 Rule #46 META-CANARIES, 1 Rule #48 cross-stack alignment commit, ~4.5 hours wall-clock = **5.4 hours budget**.

### Rationale

- **Session 1 stays unambiguously below the single-session capacity.** All 7 fixes are mechanically straightforward (mostly additive). Zero state-machine refactors. Zero alembic migrations. Each fix has a clear, narrow scope test. Risk of carry-over into a Session 1.5 is < 20%.
- **Session 2 carries the structural conversion (SBOM /generate Rule #33).** Mirror of rate-limit-2026-05-18: conversion-plus-companions naturally takes a full session. Session 2 also handles the cross-firmware sweep (Rule #44/#51 housekeeping) since Fix #11 is the architectural pair to Fix #1's sbom_status reaper.
- **The split avoids Rule #25 single-slice-exception #2 cross-contamination.** Fix #1's `SbomStatus` Literal + DB CHECK + frontend mirror MUST be in one commit (Rule #25 Shape-1). Putting that in Session 1 would crowd a tight session and require the alembic chain to interleave with low-risk Session 1 fixes. Session 2 owns the cross-stack alignment surface in isolation.

## Single-Session Path (if attempting anyway)

- **Critical-path commits (ordered):** Fix #10 (unblock test layer) → Fix #1 alembic + Rule #48 Shape-1 commit (sbom_status block + Pydantic Literal + frontend mirror) → Fix #1 router refactor + Fix #6 grype param-add + Fix #1 frontend → Fix #1 tests → Fix #2 + Fix #5 reaper pair → Fix #11 walker reaper sweep → Fix #3 unpack gate → Fix #4 bare_metal registration → Fix #9 post_process pipeline gate → Fix #8 asyncio.create_task → Fix #7 frontend rebuild → docs/learn commit.
- **Pre-flight gates:**
  - Rule #8 rebuild count: 4 (after alembic; after model class change for Fix #1 status field per Rule #20; after Fix #11; after Fix #4)
  - Rule #11 import-smoke count: 7 (each new exportable symbol — `SbomStatus`, `SbomGenerateStatusResponse`, the new reaper functions, etc.)
  - Rule #46 META-CANARY count: 5
  - Rule #48 5-part cross-stack alignment commits: 1 (sbom_status)
- **Risk of going single-session:** The Fix #1 SBOM /generate Rule #33 conversion is structurally identical to `8f54a24` which the postmortem `postmortem-ratelimit-citadel-sweep-2026-05-18.md` shows surfaced 8 second-order companion defects across an 11-day discovery window. Doing this conversion AT THE SAME TIME as Fix #2/#5/#11 (3 reaper additions) AT THE SAME TIME as Fix #3/#9 (2 walker-orchestration structural fixes) AT THE SAME TIME as Fix #4/#6/#8 (3 hardening fixes) means a single bad alembic migration or a single Rule #51 invariant miss requires reverting a much larger surface to recover. The single-session worst case is a half-committed conversion + 4 hours sunk and the operator's regression unaddressed. Recommend AGAINST single-session.

## Verdict

**RECOMMENDATION: MULTI-SESSION-RECOMMENDED**

**Rationale:** The drift-adjusted scope (~1,731 net LOC, 17 commits, 3 Rule #8 rebuilds, 1 Rule #48 cross-stack alignment commit) is ~3× the rate-limit-2026-05-18 baseline (the closest analog: a Rule #33-conversion-induced regression sweep that took 8 commits / 600 LOC in a single session, plus 4 second-order companion defects discovered post-commit). The structural Rule #33 conversion of `/sbom/generate` (Fix #1) is itself a 4-commit, ~420-LOC unit that historically requires a full session of attention to settle; trying to land it ALONGSIDE the other 9 fixes risks the same commit-and-discover cascade that the 2026-05-18 sweep had to relitigate. Session 1 ships 7 high-value/low-risk fixes (~620 LOC, ~5 hours budget) that unblock the test layer + close all passive reaper/walker gaps + eliminate Scout C's "operator sees nothing happen" symptom; Session 2 (~1,110 LOC, ~5.4 hours) carries the SBOM /generate conversion + walker-reaper sweep + housekeeping. The ICS Session 1 precedent (2026-05-20 postmortem) is the operative analog: when γ's scope measurement exceeded a single session, splitting into a scaffold-first session + walker-and-activation session preserved bisect-clean state and prevented half-done damage.

Confidence: **HIGH.** Scope mirrors three documented Rule-of-Three baselines (rate-limit/walker-Rule#47/ICS-S1). Drift adjustment is within the empirically-observed +14-22% range Rule #28 codifies. Per-fix LOC estimates derive from direct `wc -l` measurement of the files each fix touches, cross-referenced with shape baselines from `c1d2e3f4a5b6` (vuln_scan_status migration: 98 LOC), `e6f7a8b9c0d1` (cve_match_status migration: 114 LOC), `d2e3f4a5b6c7` (upload_stage migration: 123 LOC), and the rate-limit campaign commits `3d2454b` (vuln-scan reaper: 44 LOC), `616e89d` (structured 429: 109+10 LOC), `8766710` (TIER_A_HEAVY add: 11 LOC across 3 files).
