# Wave-1 Scout D — Operator UX for Adaptable Ingest + 202+polling (S2)

> Investigation date: 2026-05-21
> Scope: enumerate operator-visible states + UX affordances for Session 2's
> SBOM `/generate` Rule #33 sync→202+polling conversion + force_rescan
> contract + walker fan-out un-gating + multi-format ingest mandate.
> Authored as a one-shot read of the frontend / backend code paths;
> backend rate-limit + walker registry context retrieved live.
> Successor to Session 1's `wave1-scout-D-operator-ux.md` (which closed
> stuck-spinner + GC + stale-bundle on the vuln-scan path).

## Executive Summary

Session 2's top UX risk is **the SBOM-generate spinner regressing the operator's mental model of "synchronous = instant feedback" — but with a force_rescan double-click trap that didn't exist in the sync world**. The current `handleGenerate` (`SbomPage.tsx:128-144`) sets `setGenerating(true)` BEFORE the POST, awaits the 600s-timeout-bounded synchronous response, then re-renders with components. Post-conversion the POST returns sub-second with `sbom_status="queued"` and the frontend must (a) poll a new `/sbom/generate/status` endpoint every 2s, (b) gate `Force Regenerate` while in-flight to avoid §SC5-NEW-SBOM-ν trap, (c) handle 409-on-conflict gracefully (same shape as vuln-scan's existing handling), and (d) survive page navigation mid-run via re-mount polling. The adaptability mandate ("we won't be the only ones ingesting files") adds three NEW operator-visible states that don't exist today: **Unknown-format** (today: empty page with no explanation), **Multi-format** (today: collapses into the single firmware row's SBOM), and **Generating-stuck** (today: no escape hatch). Unknown-format graceful-degradation is **MANDATORY** — the upload pipeline already exposes `detected_format` + `extraction_capability` through `FirmwareUploadStatus` (`types/index.ts:48-63`), but the SBOM page consumes NONE of this; it ploughs ahead into Generate-SBOM and surfaces a 0-component result instead of "this format isn't supported for SBOM extraction yet — operator-supplied parser? try generic strategy?". Frontend rebuild **REQUIRED** at session close because (a) `SbomPage.tsx` ships a new poll-loop for the new status endpoint, (b) `sbom.ts` API client return type changes from `SbomGenerateResponse` to `SbomGenerateStatus`, (c) new `SbomGenerateStatusBanner` component renders the queued/running/completed lifecycle. Confidence HIGH that the conversion is right-shaped per the existing vuln-scan precedent; the four mandatory UX adjustments below carry zero novel design risk.

## Operator Journey for Session 2 Conversion

Step by step for the SBOM /generate flow post-conversion, with frontend file:line + backend endpoint at each step. References the firmware-unpack precedent (the canonical 202+polling shape in wairz).

1. **Operator opens SBOM tab for a `upload_stage='ready'` firmware.** Route `/projects/{pid}/sbom` → `SbomPage` mount (`frontend/src/pages/SbomPage.tsx:67`). `loadData()` at `:89-107` runs `getSbomComponents()` + `getVulnerabilitySummary()` in parallel; if no components yet, `summary.total_components===0` → page shows "Generate an SBOM to identify firmware components" with a `Generate SBOM` button.

2. **Operator clicks Generate SBOM.** `handleGenerate(false)` at `SbomPage.tsx:128-144`. POST to `/api/v1/projects/{pid}/sbom/generate?force_rescan=false&firmware_id={fid}`. **Pre-conversion:** synchronous return after up-to-600s of executor work; the entire `Loader2` spinner spans this. **Post-conversion (Session 2):** POST returns 202 sub-second with `sbom_status="queued"`. Backend handler at `backend/app/routers/sbom.py:142-252` becomes a Rule #33-shaped contract: 409 if already `queued|running`, persist status flip, fire `_spawn_background_task(_run_sbom_generate_background(firmware.id, force_rescan))` (mirrors the GC-safe `vuln_scan` task spawned at `:616`), return 202.

3. **Frontend transitions to Generating state.** New polling effect mirrors the existing vuln-scan loop at `SbomPage.tsx:190-225`. Cadence 2s. Each tick calls a new `getSbomGenerateStatus()` API helper in `sbom.ts` → `GET /api/v1/projects/{pid}/sbom/generate/status?firmware_id={fid}`. Backend returns `SbomGenerateStatus` whose shape mirrors `VulnerabilityScanStatus` (`types/index.ts:376-383`): `{firmware_id, status, started_at, finished_at, error, summary}` where `summary` is `{total_components, components_by_type}` only when `status==="completed"`.

4. **Backend completes the generation.** `_run_sbom_generate_background` writes 70-2000+ `sbom_components` rows incrementally, then flips `sbom_status="completed"`. The poll picks up the completion on the next 2s tick, calls `reloadAfterGenerateCompleted()` (new helper paralleling `reloadAfterScanCompleted` at `:150-160`) to fetch components + summary + vulnerabilities, then `setGenerating(false)`.

5. **Operator next clicks Scan for Vulnerabilities.** Existing path — `handleScan()` at `SbomPage.tsx:162-185` already correctly handles 202+polling via the existing vuln-scan implementation (Session 1 shipped `_spawn_background_task` GC guard at `routers/sbom.py:616`). No changes needed for this step.

6. **Operator navigates away mid-generate.** `useEffect` cleanup at `SbomPage.tsx:221-224` clears the polling interval + sets `cancelled=true`. **Critical:** the BACKEND row stays in `sbom_status="running"` — the work continues independent of the page lifecycle, exactly mirroring firmware-unpack precedent. **On re-mount,** the polling effect must re-derive `generating` state from the persisted status (Mandatory UX change #3 below).

7. **Operator hits Force Regenerate while generating is in-flight.** Today: re-fires `handleGenerate(true)` which sets `setGenerating(true)` redundantly + fires a second POST. Post-conversion: the second POST hits the 409 idempotency gate at `routers/sbom.py` (analogous to `:592`) and the frontend should respond as the vuln-scan handler does (line 174-183) — silently fall through to polling because the existing job IS the work the operator wanted. **BUT** force_rescan semantics differ from a regular Generate; if the in-flight job was `force_rescan=false` (cached return) and the operator wanted `force_rescan=true`, the 409 lies (§SC5-NEW-SBOM-ν from Session 1 W2-β). Mandatory UX change #4 below.

## State Catalog

| State | Operator sees | Frontend file:line | Backend trigger | Mandatory? |
|---|---|---|---|---|
| Idle | "Generate an SBOM to identify firmware components" — empty page with a Generate SBOM button | `SbomPage.tsx:302-307` (header line) + `:352-357` (button) | `sbom_status='idle'` (default per migration); 0 sbom_components rows | YES (no change from today) |
| Generating (active) | "Generating SBOM..." button label; animated `Loader2`; new BANNER below header showing `started_at` + a short "this can take several minutes; navigate away and we'll keep working" tooltip-cite | NEW polling effect after `SbomPage.tsx:225`; new `SbomGenerateStatusBanner` component | `sbom_status='queued'` then `'running'`; row owns its own session per Rule #39 inner runner | YES — without this, regression vs today |
| Generating-stuck (>30 min) | Banner upgrades to amber: "Generation has been running for X minutes; this is longer than expected. Try the Reset button below or check container logs." | NEW banner above existing UI; soft escape hatch button at `SbomPage.tsx:?` | `sbom_status='running'` + `EXTRACT(EPOCH FROM NOW() - sbom_started_at) > 1800` | NICE-TO-HAVE (defer to Session 3 unless Session 2 ships the lifespan reaper for `sbom_status` per Fix #11 sweep) |
| Completed | Components list renders; summary cards show counts; Last scanned timestamp at `:305-306`; Regenerate button | `SbomPage.tsx:295-308` (header); `:441-451` (components tab); existing summary cards at `:362-389` | `sbom_status='completed'`; `sbom_finished_at` populated; sbom_components rows present | YES (zero changes vs today) |
| Failed | Red toast with `extractErrorMessage(status.error, 'SBOM generation failed')`; page returns to Idle layout with Generate SBOM button re-enabled; LAST attempted timestamp at `:305-306` shows "last attempt FAILED at X" | NEW: extend `:305-306` to render `sbom_status==='failed'` distinctly with last-error excerpt | `sbom_status='failed'` + `sbom_error` JSONB | YES — without this, operator sees "Generate SBOM" button with no hint that the last attempt failed (regression vs the current toast-on-throw) |
| Re-generating (force_rescan) | Same as Generating + "Force regenerate — replacing cached results" annotation; the existing component list dims to 50% opacity rather than disappearing (visual continuity) | `SbomPage.tsx:344-349` (button label change); NEW dim treatment on `:441-451` | `sbom_status` flips queued→running with `sbom_force_rescan=true` flag (NEW column per W2-β §SC5-NEW-SBOM-ν, OR commit-message-level convention without column) | YES — without this, operator's force-regenerate click looks identical to first-generate, breaking their mental model |
| Unknown-format | Banner above the Generate SBOM button: "Detected format: vbox-ovf — SBOM extraction not available for this format. Components shown below come from operator-supplied parsers / generic strategy." with a `Try Generic Strategy` button (calls Generate with `strategy=generic` query param OR a documented "I don't see your format" link to the operator-supplied YAML registry per Rule #52) | NEW: extend SbomPage header `:295-308` to read `firmware.extraction_capability` + `firmware.detected_format` from a new `useFirmwareDetail` hook | New backend response field `sbom_supported_for_format: bool` derived from `format_catalog.get_manifest(detected_format).has_sbom_strategy` | YES — without this, unknown-format uploads silently produce 0-component SBOMs; this is the adaptability mandate's MOST VISIBLE operator-touchpoint |
| Multi-format | Per-partition sub-tabs under the main Components / Vulnerabilities tabs at `:425-439`: `Android OTA`, `Linux rootfs`, `UEFI`, `Aggregated`. Default tab = `Aggregated`. Per-tab counts; per-tab "Generate SBOM for this partition" affordance if a partition is un-scanned | NEW: extend `TabButton` row at `:425-439`; partition detection from `firmware.device_metadata.detection_roots` (Rule #16 helper) | New: `sbom_components.detection_root_id` column (FK to a new `firmware_detection_roots` table) OR `detection_root: str` denormalised column | NICE-TO-HAVE — Session 2 ships per-firmware SBOM as today; partition-aware UX is deferred to Session 3+. Current state is functional for single-partition firmware (the dominant case) |

## 202+polling UX Specifics

### Polling cadence

2-second interval throughout, matching the firmware-unpack precedent (`ProjectDetailPage.tsx:87-90` `setInterval(refreshProject, 5000)` — wait, that's 5s; SbomPage's vuln-scan polling at `:220` uses 2s; the firmware-upload `getFirmwareUploadStatus` polls every 2s per `firmware.ts:62` docstring). **For SBOM /generate: use 2s** to align with the existing SbomPage vuln-scan poll (re-uses the same `useEffect` shape — easier mental model + same backoff future-work hooks).

### Cancel affordance (Rule #33 .a idempotency)

Rule #33 .a stipulates idempotent POSTs with 409-on-conflict; it does NOT mandate an explicit cancel endpoint. The existing wairz precedent does NOT expose cancel for any 202+polling endpoint (firmware-unpack has no cancel; vuln-scan has no cancel; cve-match has no cancel). **Recommend: NO Cancel button** for the SBOM-generate path. Rationale: SBOM generation is bounded (~3-5 min on 16 GB firmware; subprocess-free; <600s budget); a Cancel button adds (a) a new endpoint surface, (b) cancellation-mid-write race conditions (Rule #7 partner), (c) operator confusion when the row stays at `running` for 2-3s after Cancel (the work is interruptible only at executor-yield-points). Instead: surface the "you may navigate away; we'll keep going" assurance text in the Generating banner. Session 1 / Session 2 deferred Cancel to Session 3+ if operator demand surfaces.

### Backoff behavior (Rule #29 + §SC5-NEW-SBOM-λ)

Session 1's W2-β catalogued §SC5-NEW-SBOM-λ: the polling cadence trips its own DB load budget when an operator opens two browser tabs simultaneously (1 req/s × 2 tabs × N firmware = N req/s sustained against `_resolve_firmware`). **Mandatory:** the SBOM-generate poll uses the same fixed 2s cadence as today's vuln-scan; **DEFERRED:** smart backoff (2→4→8→16→32 on unchanged status) + Visibility-API gating (pause when `document.hidden`) is queued for Session 3 along with the unified `composite-status` endpoint W2-β proposed.

### Page navigation: what happens if operator leaves the page mid-scan?

The `useEffect` cleanup at `SbomPage.tsx:221-224` clears the interval + sets `cancelled=true` — local state goes away. **The backend row STAYS at `sbom_status='running'`**. When the operator returns to the SBOM page (re-mount), the `loadData()` call at `:109-112` does not yet read `firmware.sbom_status` — it only reads components + summary. **Mandatory UX change #3:** extend `loadData()` to read the firmware row's `sbom_status` and, if `queued|running`, auto-set `generating=true` to resume the polling display. This mirrors the firmware-unpack precedent at `ProjectDetailPage.tsx:68-90` where `isUnpacking = project?.status === 'unpacking'` derives polling-active from persisted state, not local React state.

### Multi-tab coherence

Two browser tabs on the same SBOM page both poll independently — they observe the same transitions but emit duplicate work. The custom 429 handler at `client.ts:109-124` will throttle if either tab exceeds rate limit on the GET (it's not currently tier-limited, but the SlowAPI default `100/minute` per `rate_limit.py:82` covers it). **Acceptable for Session 2.** Future improvement: a BroadcastChannel-based de-duplicator that elects one tab as "polling primary" and broadcasts status. Defer.

## Rule #29 + Rule #51 Frontend Audit

### `SECURITY_SCAN_TIMEOUT` post-conversion

Today `generateSbom` in `sbom.ts:38` overrides axios to `timeout: SECURITY_SCAN_TIMEOUT=600_000` ms (`timeouts.ts:43`). Post-conversion **the 600s override must be REMOVED** — the 202 ack is sub-second, identical to the vuln-scan post-conversion at `sbom.ts:88-101` (no timeout override; default 30s axios floor applies; see the inline comment at `sbom.ts:82-86` that documents exactly this). The new `getSbomGenerateStatus` GET endpoint also inherits the 30s default. **Verification:** the harness rule `auto-frontend-long-op-no-explicit-timeout` (`.claude/harness.json:170-174`) will NOT fire on the post-conversion code because `/generate` is in the verb allowlist; if the conversion REMOVES the `timeout: SECURITY_SCAN_TIMEOUT` line, the regex no longer matches anyway. Run the harness canary before merge: `grep -n "/generate.*timeout" frontend/src/api/sbom.ts` should return 0 hits.

The export endpoint at `sbom.ts:66-80` STAYS synchronous with the 600s override — exports are operator-driven file generations bounded by the SBOM size, not the firmware size, and live behind a `<a href download>`-pattern that does NOT poll. No change for `exportSbom`.

### Tier re-evaluation (Rule #51 .ii core)

The current `/sbom/generate` is decorated `@limiter.limit(TIER_A_LIGHT_ACK)` (`routers/sbom.py:143`) which is 30/hour — **MIS-TIERED for a synchronous endpoint** per Session 1 W2-α + Rule #51 .ii. Post-conversion the tier becomes CORRECT (30/hour is right for a 202+polling endpoint where the ack is sub-second). **No tier change needed** in the conversion commit; the existing tier is already the right shape. **Important:** Session 1 documented this as a CURRENT defect that the conversion FIXES; the conversion is the cure, not a separate tier-edit. Verify in the cross-stack alignment test: `backend/tests/test_rate_limit_tiers.py:_EXPECTED_TIERS` should already pin `/sbom/generate` to `TIER_A_LIGHT_ACK` (if not, that's a Session 2 Rule #48 Shape-1 commit).

### 429 handling for the new polling endpoint

The new `GET /sbom/generate/status` endpoint is **NOT rate-limited** (the existing `GET /sbom/vulnerabilities/scan/status` at `:623-639` carries no `@limiter.limit` decorator). The default SlowAPI `100/minute` per-IP limit at `rate_limit.py:82` applies — exceeded only by an aggressively-polling automation, not by a human operator with one tab. The frontend's 429 handler at `client.ts:109-124` already correctly reads structured 429 bodies + Retry-After. **No frontend changes needed for 429 on the new endpoint.**

### `extractErrorMessage` compatibility

The new status endpoint's error shape is `VulnerabilityScanStatus.error: string | null` (mirrored to `SbomGenerateStatus.error: string | null`). The `extractErrorMessage` helper at `utils/error.ts:12-22` reads `data.hint → data.detail → data.error` in priority order — but the polling response's `error` field is NOT inside an axios error wrapper; it's inside the SUCCESS `200 OK` body. So `extractErrorMessage(status.error, 'SBOM generation failed')` is NOT correct (the helper expects an axios `err` shape with `response.data`). Instead: directly toast `toast.error(status.error || 'SBOM generation failed')` per the vuln-scan precedent at `SbomPage.tsx:207`. **The harness rule `auto-frontend-fake-scan-failed-error`** at `.claude/harness.json:164-167` does NOT fire on this pattern; the existing vuln-scan code is the precedent.

## Unknown-Format UX Design

### Today's behaviour

Operator uploads a firmware whose format wairz doesn't recognize (per `format_catalog.py` lookup against the post-Rule-#52 closed YAML registry). The upload pipeline produces a `FirmwareUploadStatus` with `detected_format='unknown'` (or `null`) + `extraction_capability='none'`. The FirmwareUpload component at `frontend/src/components/projects/FirmwareUpload.tsx:309-335` renders a `FormatBanner` with amber styling: "No native extractor — detected format: unknown" + the `capability_note` from `format_detection.py:CAPABILITY_NOTES`. Operator clicks through to the SBOM page — `loadData()` shows zero components, page says "Generate an SBOM to identify firmware components", operator clicks Generate — backend runs `SbomService.generate_sbom()` against the `extracted_path` which is sparse (no rootfs, no APK manifest, no PE imports), returns 0-5 components, page renders "components: 0" silently. **The operator has no signal that Generate-SBOM is structurally not going to help for this format.**

### Recommended new behaviour

Treat "unknown format / no native extractor" as a FIRST-CLASS SBOM page state, surfaced BEFORE the operator clicks Generate. Three layers:

1. **Banner above the Generate SBOM button.** Inherits the existing `FormatBanner` shape from `FirmwareUpload.tsx:309-335` (component reuse — extract `FormatBanner` to `frontend/src/components/firmware/FormatBanner.tsx` so both pages share it). Text: "Detected format: `<vbox-ovf | macho | unknown>`. SBOM extraction is not available for this format yet. You can: (1) supply a parser YAML via the [operator-extension registry](Rule #52 link); (2) try the generic strategy below (low confidence)."

2. **Generate SBOM button rebrands to "Try Generic Strategy"** for unsupported formats. Click POSTs `/api/v1/projects/{pid}/sbom/generate?firmware_id={fid}&strategy=generic` (new query param; backend dispatches to `SbomService.generate_generic_strings_strategy()` which runs binwalk-string-extraction + ELF-SONAME + Python-package heuristics across ALL extracted files regardless of detected format).

3. **Operator-supplied parser hand-off.** A link from the banner to a new docs page documenting Rule #52's adaptable extension surface: "Don't see your format? Add a YAML under `data/file_formats/<vendor>/<format>.yaml` per the closed-grammar registry (CLAUDE.md Rule #52). Restart the backend; your format will be detected on the next upload." This is the operator-touchpoint for the adaptability mandate.

### API surface needed

Two changes:

(a) **Extend `SbomGenerateStatus` response** (or the new `SbomPageStatus` if Session 2 introduces a wider state-aggregating endpoint) with three new fields:

```typescript
interface SbomGenerateStatus {
  // ... existing ...
  detected_format: string | null         // from firmware.detected_format
  extraction_capability: 'full' | 'partial' | 'none' | null  // from firmware.extraction_capability
  sbom_supported_for_format: boolean     // NEW: from format_catalog.get_manifest(...).has_sbom_strategy
}
```

(b) **Add `strategy` query param** to `POST /sbom/generate`: `strategy: Literal['auto', 'generic']` with `auto` default. Auto dispatches by detected format; `generic` runs the everything-everywhere strings + ELF SONAME + package-heuristic path regardless. The Pydantic Literal closes the grammar per Rule #52.

Both changes are additive — no breaking changes to existing callers. Both ship in the same Session 2 commit chain. Frontend reads the new fields in the new `useFirmwareDetail` hook + renders the conditional banner.

### Mandatory vs nice-to-have

The BANNER + button rebrand are **MANDATORY for Session 2** because (a) without them, the adaptability mandate's flagship surface (operator uploads "weird" firmware) silently fails — exactly the regression-shape Session 1 was investigating; (b) the cost is ~80 LOC frontend + ~30 LOC backend + extract `FormatBanner` to a shared component (~10 LOC move). The operator-supplied parser docs link is **NICE-TO-HAVE** — defer until Session 3 ships the docs page itself.

## Mandatory vs Nice-to-Have

| Change | Classification | Justification |
|---|---|---|
| 1. SBOM /generate 202+polling state machine in frontend (mirror vuln-scan loop) | MANDATORY | Otherwise SBOM generate breaks under any backend takeover that doesn't return synchronously |
| 2. Failed-state surfacing in SBOM header (last-attempt timestamp + error excerpt) | MANDATORY | Today's UI only shows error on the failed-click moment via toast; after a page refresh, the operator has no way to know the last generate FAILED — regression vs current toast-on-throw |
| 3. Re-mount auto-resume polling (derive `generating` from persisted `sbom_status`) | MANDATORY | Otherwise navigating away + back leaves the operator at "Generate SBOM" button while the backend is still working — UX desync vs firmware-unpack precedent |
| 4. Force-regenerate gating during in-flight generate (disable button while `sbom_status='queued'|'running'` unless explicit override) | MANDATORY | Closes §SC5-NEW-SBOM-ν (force_rescan double-click trap). Without it: operator's second click 409s, frontend silently falls through to polling, operator sees the cached-result complete and believes their force-regenerate was honored — but the cached result IS the cached result, fresh scan was never run |
| 5. Unknown-format banner above Generate SBOM (extract FormatBanner to shared component) | MANDATORY | Adaptability mandate's flagship surface; without it, the new closed-grammar YAML registry (Rule #52) has no operator-discoverable path |
| 6. `Try Generic Strategy` button for unsupported formats | MANDATORY | Pairs with #5; without it the banner is informational only and operator has no remediation action |
| 7. Generating-stuck (>30 min) escape hatch button ("Reset") | NICE-TO-HAVE | Defers to Session 3. The Session 1 lifespan reaper for `sbom_status` (if Session 2 ships the Fix #11 walker-reaper sweep) covers backend-restart-induced orphans; in-session orphans depend on `_spawn_background_task` GC-guard which Session 1 already shipped for vuln-scan and Session 2 will extend to SBOM-generate. **Defer the in-page Reset button until operator demand surfaces.** |
| 8. Multi-format per-partition tabs | NICE-TO-HAVE | Session 2 ships per-firmware SBOM as today (the dominant case). Per-partition is operator-requested when they have a multi-OS tarball; defer until that ask lands. |
| 9. Polling backoff (2→4→8→16→32s on unchanged status) + Visibility-API gating | NICE-TO-HAVE | §SC5-NEW-SBOM-λ catalogues the cost (1 req/s/tab/firmware sustained); the harm is measurable in pg_stat_statements but not operator-visible. Defer to Session 3 alongside the `composite-status` unified endpoint. |
| 10. Cancel button | DEFERRED | No wairz 202+polling endpoint exposes Cancel today; SBOM generate completion is bounded; demand has not surfaced. |
| 11. Multi-tab BroadcastChannel de-duplicator | DEFERRED | Operator-typical workflow is single-tab; harm is duplicate polling, not data corruption. Defer indefinitely. |
| 12. Force-regenerate "supersedes cached no-op" path (§SC5-NEW-SBOM-ν proper fix) | MANDATORY-LITE | The 409 silently swallows a force_rescan=True click against a cached-result no-op. Two options: (a) backend at `routers/sbom.py:142-167` returns 200-with-cached if `force_rescan=false` AND `status` not in `('queued','running')` (current sync path); 202+queued ONLY when force_rescan=true OR no cached result. This shape makes the FAST path stay sync-200 and the SLOW path go 202+polling. Operator's force-regenerate click then ALWAYS produces a 202 even if cache exists. **Recommend this shape for Session 2.** |

## Cross-References

Frontend:

1. `frontend/src/pages/SbomPage.tsx:67` — page mount
2. `frontend/src/pages/SbomPage.tsx:89-107` — `loadData()` w/ swallowed-error `.catch(() => [])` (still present; not changed by Session 2)
3. `frontend/src/pages/SbomPage.tsx:128-144` — `handleGenerate` — TARGET for 202+polling conversion
4. `frontend/src/pages/SbomPage.tsx:162-185` — `handleScan` — REFERENCE for the conversion shape (vuln-scan precedent shipped Session 1)
5. `frontend/src/pages/SbomPage.tsx:190-225` — vuln-scan polling effect — TEMPLATE for the new SBOM-generate poll
6. `frontend/src/pages/SbomPage.tsx:295-308` — header — NEEDS extension for `detected_format` banner + last-failed-attempt
7. `frontend/src/pages/SbomPage.tsx:341-357` — Generate / Regenerate buttons — NEED in-flight disable + "Try Generic Strategy" variant
8. `frontend/src/api/sbom.ts:28-42` — `generateSbom` — TARGET for 202 return type change + drop `SECURITY_SCAN_TIMEOUT` override
9. `frontend/src/api/sbom.ts:82-86` — vuln-scan no-timeout precedent comment — APPLIES to generate post-conversion
10. `frontend/src/api/sbom.ts:103-112` — `getVulnerabilityScanStatus` — TEMPLATE for new `getSbomGenerateStatus`
11. `frontend/src/api/timeouts.ts:43` — `SECURITY_SCAN_TIMEOUT=600_000` — DROP from `generateSbom`, KEEP for `exportSbom`
12. `frontend/src/api/client.ts:109-124` — 429 handler — UNCHANGED, applies cleanly to new endpoint
13. `frontend/src/utils/error.ts:12-22` — `extractErrorMessage` — UNCHANGED, used for 409 path only (polling error reads `status.error` directly)
14. `frontend/src/components/projects/FirmwareUpload.tsx:309-335` — `FormatBanner` — EXTRACT to shared `frontend/src/components/firmware/FormatBanner.tsx`
15. `frontend/src/components/projects/FirmwareUpload.tsx:170-183` — phase state machine — REFERENCE for the Generating/Failed/Completed state pattern
16. `frontend/src/api/firmware.ts:63-71` — `getFirmwareUploadStatus` — REFERENCE for the polling helper shape
17. `frontend/src/types/index.ts:48-63` — `FirmwareUploadStatus` — REFERENCE shape for the new `SbomGenerateStatus`
18. `frontend/src/types/index.ts:369-383` — `VulnScanStatusValue` + `VulnerabilityScanStatus` — TEMPLATE for `SbomGenerateStatusValue` + `SbomGenerateStatus`
19. `frontend/src/pages/ProjectDetailPage.tsx:68-90` — `isUnpacking` + polling effect — REFERENCE for re-mount auto-resume pattern

Backend:

20. `backend/app/routers/sbom.py:142-252` — `/generate` — TARGET for 202+polling conversion
21. `backend/app/routers/sbom.py:449-547` — `_run_vuln_scan_background` — TEMPLATE for the new `_run_sbom_generate_background`
22. `backend/app/routers/sbom.py:592-596` — vuln-scan 409 idempotency — TEMPLATE for SBOM /generate 409
23. `backend/app/routers/sbom.py:616-619` — `_spawn_background_task` GC guard — REUSE for SBOM /generate
24. `backend/app/routers/sbom.py:623-639` — `GET /vulnerabilities/scan/status` — TEMPLATE for `GET /generate/status`
25. `backend/app/rate_limit.py:85-87` — `TIER_A_LIGHT_ACK="30/hour"` — UNCHANGED, already correct for the post-conversion endpoint
26. `backend/app/main.py:200-242` — lifespan reaper (vuln-scan) — REFERENCE for the new `sbom_status` reaper Fix #11 sweep
27. `backend/app/services/format_catalog.py` — Rule #52 closed-grammar registry — SOURCE OF TRUTH for `sbom_supported_for_format` derivation
28. `backend/app/schemas/sbom.py` — Pydantic models — NEW `SbomGenerateStatusResponse` + extend `SbomGenerateStatus` with `detected_format` + `extraction_capability` + `sbom_supported_for_format`
29. `backend/app/services/sbom_service.py` — `generate_sbom` — ADD `generate_generic_strings_strategy` method for the `strategy=generic` query param path
30. `.claude/harness.json:158-161` — `auto-frontend-rebuild-not-restart` — VERIFIES the post-Session-2 rebuild happens via `docker compose up -d --build frontend`
