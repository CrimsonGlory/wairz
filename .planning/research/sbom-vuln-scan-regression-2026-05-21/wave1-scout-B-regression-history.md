# Wave-1 Scout B — Git Regression History (REGRESSION-HISTORY persona)

> Investigation date: 2026-05-21
> Window: 30 days back from 2026-05-20 (2026-04-20 → 2026-05-20)
> Operator-reported symptom: SBOM generation + vulnerability scanning "appear to have regressed", no specific repro
> Scope: identify every commit that touched the SBOM/vuln-scan surface, score for Rule #47 consumer-hook-enumeration risk

## Executive Summary

The highest-risk window is **2026-05-07 (commits `8f54a24` + `847eae9`)** when BOTH the vuln-scan AND the upload pipeline were converted to Rule #33 202+polling within ~5 hours of each other. The upload conversion landed an INVISIBLE refactor-orphan that took FIVE DAYS to discover — every uploaded firmware silently skipped ALL 22 walker auto-triggers AND HW-firmware detection (Rule #47 worked example, fixed `12955a6` + `5f3d195` on 2026-05-12). The vuln-scan conversion landed a SECOND latent invariant break: rate-limit tier left at `TIER_A_HEAVY = "5/hour"` from the sync era, which silently throttled operators for ELEVEN DAYS until the 2026-05-18 sweep (`f6dbc7b` + `3d2454b`). The 2026-05-15 hot-fix `d32d197` (firmware-scope vuln-count subquery, 22000x speedup) is the third Rule #33 dependent invariant break — POSITIVE evidence the SBOM polling endpoints ARE the operator-facing surface most fragile to recent changes. There is **NO SBOM auto-trigger and NO vuln-scan auto-trigger** in `WALKER_AUTO_TRIGGERS` today, so the "operator says SBOM regressed" symptom most likely reduces to (a) operator-initiated `POST /sbom/generate` finds the SBOM machinery broken on a class of firmware shaped by recent upload-pipeline / extraction changes; OR (b) `POST /sbom/vulnerabilities/scan` is still mis-behaving in a way the 2026-05-18 sweep didn't catch. Confidence: HIGH for the suspect-commit ranking; MEDIUM for the "which symptom" attribution without a Scout C repro.

## Methodology

I walked the git log with six independent queries (suspect-path / walker-registry / alembic / rate-limit / keyword grep / recent commits — all 30-day window). For each commit touching `backend/app/services/sbom/`, `backend/app/routers/sbom.py`, `backend/app/services/firmware_service.py`, `backend/app/workers/walker_registry.py`, or `backend/app/routers/findings.py`, I ran `git show --stat <sha>` + targeted `git show <sha> -- <file>` to read the commit body + diff hunks. I cross-referenced against 30+ postmortems under `.planning/postmortems/` and re-verified the WALKER_AUTO_TRIGGERS chain in the working tree as of HEAD (`backend/app/workers/unpack.py:74` + `backend/app/services/firmware_service.py:825`).

Scoring rubric for "suspect":
- **Rule #47 risk** (consumer-hook enumeration): state-machine column added/refactored without grep-walking every consumer? +3.
- **Rule #51 risk** (rate-limit tier alignment): Rule #33 conversion without tier re-eval? +2.
- **Touches a 202+polling state column for SBOM/vuln-scan/firmware/CVE-match**: +2.
- **Has a documented postmortem identifying a defect we know about**: +1 (well-understood) or +2 (incompletely resolved).
- **Diff size > 200 LOC on a critical service**: +1.

## Suspect Commits — Ranked

### SHA `847eae9` — `refactor(firmware): convert upload to 202+polling per Rule #33` (2026-05-07)

- **Files changed:** Top of stack across firmware_service.py + routers/firmware.py + schemas/firmware.py + models/firmware.py + alembic migration (upload_stage column).
- **Net delta:** large additive (new background runner + state-machine column).
- **Postmortem:** Rule #47 incident documented in CLAUDE.md (Rule #47 worked example). Companion bridge fix in `5f3d195` per `5f3d195` commit body.
- **Suspect for:**
  - [x] **WALKER_AUTO_TRIGGERS orphan (Rule #47)** — confirmed historical impact.
  - [x] State machine refactor without consumer sweep (5-day silent regression on ALL uploads).
  - [x] Background-task removal / arq → asyncio.create_task swap (`_run_upload_post_processing_background` is a new asyncio.create_task lane).
- **Diff Highlights:**
  - `backend/app/routers/firmware.py:130` — `@router.post("", response_model=FirmwareUploadStatusResponse, status_code=202)` replaced the sync 201.
  - The detached `_run_upload_post_processing_background` runs detecting → extracting → analyzing → ready, but the post-`ready` hook `_run_hardware_firmware_detection_safe` was ONLY fired if `firmware.extracted_path` was non-NULL.
  - Generic-ZIP branch did NOT set `extracted_path` — every Windows boot CD / multi-file medical firmware bundle silently skipped the walker chain.
  - `upload_stage` state-machine column has NO ORPHAN REAPER in `backend/app/main.py` today. Verified at HEAD: `main.py` reapers cover `device_dump_status` + `cve_match_status` + `vuln_scan_status`, but NOT `upload_stage`. If the upload background runner crashes, the row sits in `detecting`/`extracting`/`analyzing` forever; operator cannot retry, and the firmware never reaches the state where SBOM generation could succeed.
- **Severity:** **HIGH** — proven 5-day silent regression in May 2026; the `upload_stage` orphan-reaper gap is STILL present today.

### SHA `8f54a24` — `refactor(sbom): convert vuln scan to 202+polling per Rule #33` (2026-05-07)

- **Files changed:** `backend/app/routers/sbom.py` + alembic migration `c1d2e3f4a5b6_ck_firmware_vuln_scan_status` + models/firmware.py.
- **Net delta:** ~200 LOC additive on the SBOM router.
- **Postmortem:** `postmortem-ratelimit-citadel-sweep-2026-05-18.md` ("What Broke #1, #2") — Rule #51 cascade.
- **Suspect for:**
  - [x] **State machine refactor without consumer sweep** — confirmed: missed rate-limit tier re-eval (caught 11 days later, `f6dbc7b`).
  - [x] **Rate-limit re-tier without orphan-reaper update (Rule #51)** — confirmed: `vuln_scan_status` orphan reaper was missed at conversion time, added 11 days later in `3d2454b`.
  - [x] Background-task removal / arq → asyncio.create_task swap.
- **Diff Highlights:**
  - `backend/app/routers/sbom.py:418` — `_run_vuln_scan_background(firmware_id, project_id, force_rescan)` — new detached runner with own `async_session_factory()` session.
  - `backend/app/routers/sbom.py:584` — `asyncio.create_task(_run_vuln_scan_background(...))` per Rule #33 (d) rubric.
  - **Critical gap at commit time:** `@limiter.limit(TIER_A_HEAVY)` (5/hour sync-shape) carried over from pre-conversion; sub-second ack now meant ANY operator hitting the button 6 times in an hour saw a 429. Operator-facing UX defect for ELEVEN DAYS until commit `f6dbc7b`.
  - **Critical gap at commit time:** lifespan startup hook had NO branch for `vuln_scan_status` reaper — would have surfaced the next time backend crashed mid-scan. Caught proactively at `3d2454b`.
  - **The transition itself succeeded** — pytest results in the commit body show the conversion worked end-to-end.
- **Severity:** **HIGH** — two latent invariant breaks that survived for ~2 weeks. The completed sweep at `f6dbc7b..b24a4d8` (2026-05-18) addressed both, but the fix exposed THIRD-ORDER defects: the rate-limit body shape was broken (`69ed1dd` follow-up), structured 429 handler had `tier="unknown"` (`afa23a9` follow-up), and the DB pool was undersized for the new tier (`58a6f54` follow-up).

### SHA `d32d197` — `fix(sbom): firmware-scope the vuln-count subquery — 22000x speedup` (2026-05-15)

- **Files changed:** `backend/app/routers/sbom.py` (1 line + test).
- **Net delta:** 1 production line + ~80 LOC test.
- **Postmortem:** none filed separately; documented in the commit body.
- **Suspect for:**
  - [x] **OTHER**: pre-existing perf bomb that surfaced AFTER vuln-scan 202+polling tripped polling cadence × pool exhaustion.
- **Diff Highlights:**
  - `backend/app/routers/sbom.py:_components_with_vuln_counts_stmt` — added `.where(SbomVulnerability.firmware_id == firmware_id)` to the subquery. Pre-fix every SBOM page render parallel-seq-scanned the FULL 7.5M-row `sbom_vulnerabilities` table.
  - After 4 polls (2 sec cadence × 4 = 8 sec window) at 7050 ms per call, the SQLAlchemy connection pool (size=10 + overflow=20 = 30 max) was exhausted; every endpoint returned `QueuePool limit ... connection timed out`. From the operator's perspective: "session timeout on scanning SBOM for vuln".
  - **22000x speedup measured live on DS1**. Index `ix_sbom_vulnerabilities_firmware_id` already existed; just needed to be reached.
- **Severity:** **MEDIUM** — already fixed and verified live, BUT this is the smoking-gun shape for the operator's symptom: SBOM/vuln-scan polling cascade causing operator-visible "regression". If a SIMILAR un-firmware-scoped query lurks elsewhere in the SBOM surface, the same shape would silently re-emerge on a new state-machine column or new SBOM aggregator.

### SHA `5f3d195` — `feat(services): wire walker auto-triggers into upload pipeline (Shape A bridge)` (2026-05-12)

- **Files changed:** `backend/app/services/firmware_service.py` (+ test bridge file).
- **Net delta:** ~80 LOC.
- **Postmortem:** None as a separate file; CLAUDE.md Rule #47 commit body is the canonical record.
- **Suspect for:**
  - [x] **WALKER_AUTO_TRIGGERS orphan fix** — confirmed: bridges the 847eae9 refactor-orphan.
  - [x] Defines `_fire_walker_auto_triggers(firmware_id)` but the production upload pipeline does NOT call it directly. The chain is `_post_process_pipeline → _run_hardware_firmware_detection_safe → get_walker_auto_triggers()` — but `_fire_walker_auto_triggers` is ONLY called by the live-canary test (no production caller as of HEAD per `grep -rn "_fire_walker_auto_triggers" backend/app/`).
- **Diff Highlights:**
  - `backend/app/services/firmware_service.py:684-698` — sets `firmware.extracted_path = zip_root` for the generic-ZIP branch (the bug from 847eae9).
  - `backend/app/services/firmware_service.py:733-742` — calls `_run_hardware_firmware_detection_safe` only if `firmware.extracted_path` is set. Same comment block notes the HW detection runner dispatches the walker registry internally.
  - `backend/app/services/firmware_service.py:825-857` — new orphan helper `_fire_walker_auto_triggers`. **DEAD CODE in production.** Only test_walker_auto_trigger_bridge.py calls it.
- **Severity:** **MEDIUM** — the bridge fix IS in place, BUT (i) the `_fire_walker_auto_triggers` helper is dead code, (ii) the upload pipeline still depends on `_run_hardware_firmware_detection_safe`'s `count > 0` precondition before firing walkers — if detection finds zero blobs, ALL 22 walkers skip too. Firmware with no detectable HW components but operator-facing SBOM expectations could silently land in this state.

### SHA `12955a6` — `feat(workers): factor walker auto-trigger registry into shared module` (2026-05-12)

- **Files changed:** new file `backend/app/workers/walker_registry.py` + `backend/app/workers/unpack.py`.
- **Net delta:** 157 LOC new module + refactor of unpack.py walker-fire block.
- **Postmortem:** None as a separate file; Rule #47 worked example.
- **Suspect for:**
  - [x] WALKER_AUTO_TRIGGERS orphan fix — partner to 5f3d195.
- **Diff Highlights:**
  - `backend/app/workers/walker_registry.py:1-187` — new registry shape `WALKER_AUTO_TRIGGERS = list[WalkerSafeRunner]` with 22 walker safe-runners.
  - Lazy-import via `_load_walker_safe_runners()` to keep cold-import cost off non-walker callers.
  - `backend/app/workers/unpack.py:140-152` — `_run_hardware_firmware_detection_safe` now iterates the registry instead of 3 inline try-blocks.
- **Severity:** **LOW-MEDIUM** — successful refactor; the orphan fix landed cleanly; 5 subsequent walker additions (λ.α.B / λ.α.D / λ.β.B / λ.γ.B / memory enumerator at d357938/166df66/5d2169d/89b6f0f) all extended the registry per Rule #47 discipline.

### SHA `3d2454b` — `feat(backend): orphan reaper for vuln_scan_status on lifespan startup` (2026-05-18)

- **Files changed:** `backend/app/main.py`.
- **Net delta:** 44 LOC.
- **Postmortem:** `postmortem-ratelimit-citadel-sweep-2026-05-18.md` ("What Broke #2").
- **Suspect for:**
  - [x] State machine refactor without consumer sweep — RETROACTIVE FIX to 8f54a24's gap.
- **Diff Highlights:**
  - `backend/app/main.py:202-224` — UPDATE Firmware SET `vuln_scan_status='failed'` WHERE `vuln_scan_status IN ('queued','running')` on lifespan startup.
  - Verified at HEAD that this reaper IS in main.py today (line 222).
- **Severity:** **LOW** — fix verified in place, the orphan reaper is now in main.py at HEAD.

### SHA `f6dbc7b` — `fix(rate-limit): split TIER_A_HEAVY by cost shape — 30/hour for 202+polling endpoints` (2026-05-18)

- **Files changed:** `backend/app/rate_limit.py` + `backend/app/routers/sbom.py` + others.
- **Net delta:** ~150 LOC.
- **Postmortem:** `postmortem-ratelimit-citadel-sweep-2026-05-18.md` (entire postmortem).
- **Suspect for:**
  - [x] **Rate-limit re-tier (Rule #51 worked example)**.
- **Diff Highlights:**
  - New tier `TIER_A_LIGHT_ACK = "30/hour"` for 202+polling endpoints.
  - `backend/app/routers/sbom.py:116` + `:527` — `@limiter.limit(TIER_A_LIGHT_ACK)` on SBOM generate + vuln-scan endpoints. Verified at HEAD.
- **Severity:** **LOW** — fix verified in place. However, the followup `afa23a9` (tier reverse-map bug) demonstrates that even THIS fix shipped with a latent bug — operator-visible `tier="unknown"` in 429 responses until the same-day canary caught it.

### SHA `9fcd2b9` + `1acbff2` — JSONB normaliser pair (2026-05-06)

- **Files changed:** new `backend/app/services/jsonb_normalizers.py` + 13 + 7 consumer modules.
- **Net delta:** ~600 LOC across both commits.
- **Postmortem:** None as standalone postmortems.
- **Suspect for:**
  - [x] **OTHER**: JSONB shape sweep — Rule #35c. Risk: any consumer that wasn't migrated reads raw JSONB and could break on the new `schema_version` stamp.
- **Diff Highlights:**
  - `9fcd2b9` covers `firmware.device_metadata` (13 readers) + `_stamp_firmware_device_metadata` writes schema_version=1.
  - `1acbff2` covers `sbom_components.metadata` (1 reader) + `hardware_firmware_blobs.metadata` (5 readers). SBOM enrichment writes to `sbom_components.metadata` via `comp.metadata["enrichment_source"] = ...` style at `backend/app/services/sbom/enrichment.py:171,186,196,210,220,237,251,258`.
  - Verified at HEAD: SBOM service `enrichment.py` does NOT use the `_stamp_sbom_components_metadata` helper at write sites; it mutates `.metadata` directly. The schema_version may or may not survive depending on whether the dict pre-existed.
- **Severity:** **MEDIUM** — boundary-normaliser sweep tends to be silent until it surfaces. SBOM enrichment mutating `.metadata` without going through the stamp helper is a Rule #35c discipline-skip.

### SHA `e2f8333` — `feat(unpack): adaptive nested-archive recursion gate for tarball shortcut` (2026-05-15)

- **Files changed:** `backend/app/services/firmware_service.py` + `backend/app/workers/unpack_common.py` + test.
- **Net delta:** ~150 LOC.
- **Postmortem:** None standalone. Documented in commit body and `postmortem-hw-firmware-tegra-activation-2026-05-15.md`.
- **Suspect for:**
  - [x] **OTHER**: changed extraction logic; could shift which firmware reach the SBOM-eligible state.
- **Diff Highlights:**
  - Adds `_is_archive_dense_layout()` + recursion logic to the tarball shortcut.
  - Could change which firmware end up with detectable HW blobs vs. don't — and SBOM generation depends on the extraction tree shape.
- **Severity:** **LOW** — additive feature with paired tests; unlikely to be the regression source, but in the change window.

### SHA `7dc21fe` — `feat(unpack-audit): fire promotion task post-unpack + plug confidence drop` (2026-05-04, just outside 30-day window but immediately relevant)

- **Files changed:** `backend/app/services/finding_service.py` + `backend/app/workers/arq_worker.py` + `backend/app/routers/firmware.py`.
- **Net delta:** ~50 LOC.
- **Postmortem:** None standalone.
- **Suspect for:**
  - [x] **OTHER**: fixes a pre-existing `confidence` drop in `FindingService.create`. Pre-fix, all unpack_audit findings persisted with `confidence=NULL`.
- **Severity:** **LOW** — already fixed; included for completeness.

### SHA `b284ba8` — `fix(services): add missing 'from datetime import datetime' to finding_service.py — backend startup regression from κ.B.D` (2026-05-12)

- **Files changed:** `backend/app/services/finding_service.py`.
- **Net delta:** 1 line.
- **Postmortem:** `postmortem-followup-2026-05-12-structured.md` references this style.
- **Suspect for:**
  - [x] **OTHER**: backend was in 53-restart loop until this fix. Confirms Rule #11 (post-rebuild import smoke) was bypassed in the κ.B.D sub-agent stream.
- **Severity:** **LOW** — already fixed. Notable for the post-commit reinforcement of import-smoke discipline.

## Non-Suspect Commits in Window

Doc-only / test-only / unrelated commits (truncated):
- `c7a6106` (2026-05-15) — YAML hot-reload, no state-machine touch.
- `7730915` / `5398f16` / `51db3c8` / `6bc1c1d` (hw-fw Reviewer findings) — schema gates + CVE pins; do not touch SBOM/vuln-scan state.
- `89b6f0f` / `5d2169d` / `166df66` / `d357938` — memory-forensic walkers; correctly extend WALKER_AUTO_TRIGGERS per Rule #47.
- `4ecaa5b` / `23974ea` / `4c028fc` (file-format ICS protocol housekeeping) — orthogonal.
- All `feat(findings):` cross-stack alignment commits — Rule #48 Shape-1 commits; correctly bundle DB CHECK + Pydantic Literal + frontend mirror.

## Postmortems Surveyed

- `postmortem-ratelimit-citadel-sweep-2026-05-18.md` — Rule #51 promotion + 8 latent defects from 8f54a24 conversion. Key takeaway: when Rule #33 conversion lands, tier + reaper + frontend 429 handler + DB pool headroom are ALL invariants that need explicit sweep.
- `postmortem-followup-2026-05-12-structured.md` — Rule #11 reinforcement after κ.B.D's NameError loop. Key takeaway: sub-agent verification must import the actual service module changed.
- `postmortem-feature-extraction-integrity-2026-04-17.md` — Rule #16 (`get_detection_roots`) origin; SBOM walks depend on this helper.
- `postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md` — F-FORENSIC-10 gate + advisory_id dedup; affects CVE matcher coverage.
- `postmortem-feature-hw-firmware-phase2-enrichment-2026-04-17.md` — origin of `sbom_components.metadata` enrichment writes.
- `postmortem-ics-protocol-session1-2026-05-20.md` — most recent campaign; entirely orthogonal to SBOM surface.

## Bisect Targets

If Scout C confirms the operator's symptom narrows to one of:

1. **"Uploaded firmware shows upload_stage=ready but has 0 sbom_components"** → bisect `847eae9..5f3d195` (2026-05-07 → 2026-05-12); the Rule #47 worked example proves this is the failure mode 847eae9 introduced. Any firmware uploaded BETWEEN those dates is suspect for the original orphan; backfill script at `scripts/walker-results-backfill.sh` (`2321ebe`) may have left stragglers.

2. **"POST /sbom/vulnerabilities/scan returns 429"** → no bisect needed; `f6dbc7b` + `afa23a9` are the fix chain. Operator must rebuild backend image (verify `docker compose images backend` Date is ≥ 2026-05-18 14:00 UTC).

3. **"SBOM page hangs / 'session timeout'"** → no bisect needed; `d32d197` is the fix. Verify operator's backend image is ≥ 2026-05-15 18:31 UTC. **Confirm `SbomVulnerability.firmware_id` filter is present in `_components_with_vuln_counts_stmt` at routers/sbom.py:46**.

4. **"upload row stuck in detecting/extracting/analyzing forever"** → NEW BUG; the `upload_stage` state-machine column has NO orphan reaper in main.py at HEAD (verified). Bisect not required — write the reaper.

5. **"Generic-ZIP firmware (Windows boot CD, multi-file medical) shows 0 walkers ran"** → no bisect; `5f3d195` fixed this for new uploads. Operator may need to manually re-trigger walks via `trigger_*_walk` MCP tools on old rows.

6. **"SBOM generation produces wrong CPE / cpe_confidence"** → bisect against `9fcd2b9` + `1acbff2` (the JSONB normaliser sweep), checking whether `comp.metadata["enrichment_source"]` writes still survive the stamp behaviour.

## Cross-References

1. `backend/app/services/firmware_service.py:825` — `_fire_walker_auto_triggers` defined but dead code (only test calls).
2. `backend/app/workers/unpack.py:74-152` — `_run_hardware_firmware_detection_safe` — the actual walker dispatcher.
3. `backend/app/workers/unpack.py:128` — `count > 0` precondition: walkers skip if 0 HW blobs detected.
4. `backend/app/routers/sbom.py:584` — `asyncio.create_task(_run_vuln_scan_background(...))`.
5. `backend/app/routers/sbom.py:46` — `_components_with_vuln_counts_stmt` (the d32d197 hot-fix site).
6. `backend/app/main.py:202-224` — `vuln_scan_status` orphan reaper (3d2454b).
7. `backend/app/main.py` — NO `upload_stage` orphan reaper. Verified at HEAD.
8. `backend/app/workers/walker_registry.py:1-187` — central walker registry; no SBOM/vuln-scan auto-runners present (intentional per architecture).
9. `backend/app/services/sbom/enrichment.py:171,186,196,210,220,237,251,258` — direct `.metadata` writes that bypass `_stamp_sbom_components_metadata`.
10. `backend/app/routers/sbom.py:116` + `:527` — `@limiter.limit(TIER_A_LIGHT_ACK)` (verified at HEAD — fix is in place).

## Sealed Findings

- **HIGH-confidence claim:** the SBOM/vuln-scan code path has been the subject of THREE distinct Rule #33-conversion-induced regressions in the last 30 days (847eae9 Rule #47, 8f54a24 Rule #51, d32d197 perf cascade). The pattern strongly suggests a fourth latent invariant break remains unobserved.
- **MEDIUM-confidence claim:** the `upload_stage` orphan-reaper gap (no entry in `main.py` lifespan) is the most likely undiscovered candidate. Mechanically identical to the gap `3d2454b` closed for `vuln_scan_status`.
- **MEDIUM-confidence claim:** Operator may be seeing a downstream-of-847eae9 effect. If their firmware was uploaded between 2026-05-07 and 2026-05-12 (the 5-day window), `walker-results-backfill.sh` may have left a class of rows with `extracted_path=NULL` but `upload_stage='ready'` — invisible to a re-trigger because the trigger MCP tool checks `extracted_path` via `get_detection_roots`. Scout C should query `SELECT id, upload_stage, extracted_path, sbom_generated_at FROM firmware WHERE upload_stage = 'ready' AND extracted_path IS NULL` to enumerate.
- **LOW-confidence claim:** the `enrichment.py` direct-`.metadata`-mutation pattern may or may not strip the schema_version stamp. Worth a single SQL probe: `SELECT DISTINCT jsonb_typeof(metadata->'schema_version') FROM sbom_components`.
