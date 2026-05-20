# Wave-1 Scout D — Operator UX (OPERATOR-UX persona)

> Investigation date: 2026-05-21
> Scope: Enumerate the SPECIFIC operator-visible symptoms of "SBOM + vuln-scan regressed"
> Authored from a one-shot read of the frontend code paths + backend cross-checks; no UI repro available (Playwright present but no browsing harness wired).

## Executive Summary

The most likely operator-visible symptom, given the current code on `main`, is a **"Generate SBOM" press that the operator perceives as broken or stuck even though the backend produces components correctly** — specifically a synchronous `generateSbom(...)` call (`SbomPage.tsx:133`) that holds the spinner for up to ~10 minutes against a 16 GB firmware, with no in-flight progress feedback and no 202+polling shape. A close second is a **"Vulnerability scan" press that returns the BUTTON to the unscanned state on a 409** because `handleScan` silently swallows 409 (intending to fall through to polling) but `scanning` was set to `true` BEFORE the POST — if the underlying job is dead (orphaned + reaper missed), the polling loop sees `status==='failed'` only when the reaper actually ran; if the reaper didn't fire because the backend wasn't restarted, the loop polls a row in `running` state indefinitely while no work happens, producing a permanent "Scanning..." spinner that never resolves. The third-highest likelihood is a **"Generate SBOM" rate-limit 429 trip after 30 attempts/hour** with a wrong tier (`TIER_A_LIGHT_ACK`) for a SYNCHRONOUS endpoint — the rate-limit math was tuned for 202+polling, but `/sbom/generate` is still synchronous and holds the uvicorn worker for the full run, so the operator can starve the worker pool while staying under the rate limit. The split between backend vs frontend root cause is **mixed-but-frontend-dominant**: the backend `/sbom/generate` endpoint contract is incorrect (sync work under a 202+polling rate-limit tier), but the OBSERVED symptoms are all in how the frontend reads / fails to read / mishandles the resulting state. The harness rules `auto-frontend-fake-scan-failed-error` and `auto-frontend-rebuild-not-restart` do NOT fire on the current code paths — `extractErrorMessage(err, ...)` is wired correctly everywhere; the frontend image was rebuilt 2026-05-18 11:33 (after the most recent `frontend/src/` commit at 2026-05-19 14:20 — STALE-BUNDLE EVIDENCE PRESENT, see Stale Bundle Audit below).

## Operator Journey Reconstruction

The journey below walks the click sequence with frontend file:line and backend file:line at each step.

1. **Upload firmware.** Operator drops a zip / image onto the upload control on `ProjectDetailPage` → frontend POSTs `/api/v1/projects/{pid}/firmware` (multipart). The backend persists the row in `upload_stage='uploading'`, then transitions through `detecting → extracting → analyzing → ready` via `_post_process_pipeline` in `backend/app/services/firmware_service.py`. Frontend polls every 2s. **Not in our scope; assumed healthy.**

2. **Frontend reaches `upload_stage='ready'`.** Operator navigates to the SBOM tab — route `/projects/{pid}/sbom` → `SbomPage` at `frontend/src/pages/SbomPage.tsx:67`.

3. **Page mount + initial load.** `loadData()` (`SbomPage.tsx:89-107`) fires `getSbomComponents()` + `getVulnerabilitySummary()` in parallel via `Promise.all([...].catch(...) => [] / null)`. If components exist, `useVulnerabilityStore.loadVulnerabilities(...)` runs as well. **Failure mode:** both `.catch(() => [])` and `.catch(() => null)` SWALLOW the error — a 401 / 403 / 500 / 404 path returns empty silently. The page renders "Generate an SBOM to identify firmware components" with NO error toast.

4. **Operator clicks "Generate SBOM".** `handleGenerate(false)` runs at `SbomPage.tsx:128-144`. This calls `generateSbom(projectId, false, fwId)` at `sbom.ts:28-42`, which is **synchronous** — `apiClient.post('/sbom/generate', null, { timeout: SECURITY_SCAN_TIMEOUT=600_000 })`. Backend handler at `backend/app/routers/sbom.py:115-225` runs the SBOM generation INLINE under the request (no 202+polling), with `loop.run_in_executor(None, service.generate_sbom)` inside. Latency for a 16 GB image: minutes. Frontend spins the `Loader2` icon for the duration; if it exceeds 600s, the axios 30s default is overridden so the request itself doesn't time out, but the operator gets **no progress feedback** and no opportunity to cancel.

5. **Operator clicks "Scan for Vulnerabilities".** `handleScan(false)` at `SbomPage.tsx:162-185`. This calls `runVulnerabilityScan(projectId, false, fwId)` at `sbom.ts:88-101`. Backend at `backend/app/routers/sbom.py:522-586` returns **202 immediately** with `vuln_scan_status='queued'`. Frontend `setScanning(true)` runs BEFORE the POST resolves (line 164), and the polling `useEffect` at lines 190-225 fires on the `scanning` change. The poll calls `getVulnerabilityScanStatus(...)` every 2 s.

6. **Polling loop checks status.** On `status==='completed'` the page calls `reloadAfterScanCompleted()` (line 150-160) which re-pulls components + summary + vulnerabilities, then `setScanning(false)`. On `status==='failed'`, a toast with `status.error || 'Vulnerability scan failed'` fires and `setScanning(false)`. **Transient errors during polling are SWALLOWED via `console.warn` (line 213)**.

7. **Rendering vulns.** Once `vulnerabilities.length > 0`, the table virtualizes via `VirtualizedVulnTable` (`SbomPage.tsx:1202+`). The store at `vulnerabilityStore.ts:73+` caps `VULN_PAGE_SIZE=100`, with a `Load More` button at `hasMore`. Bulk operations cap concurrency at `BULK_RESOLVE_CONCURRENCY=5`.

## Symptom Catalog

### Symptom: Empty table when results should exist

- **What operator sees:** Empty SBOM with "Generate an SBOM to identify firmware components" or empty Vulnerabilities tab with "No vulnerabilities found. Run a scan first."
- **Source code:** `SbomPage.tsx:89-107` (`loadData()` with `.catch(() => [])` swallow); `vulnerabilityStore.ts:89` (`.catch(() => [])` in `loadVulnerabilities`); `SbomPage.tsx:1148-1151` ("No vulnerabilities found"); backend `routers/sbom.py:228-245` (`list_sbom_components`) and `routers/sbom.py:608-664` (`list_vulnerabilities`).
- **How verifiable:** `curl -H "X-API-Key: ..." http://localhost:8000/api/v1/projects/{pid}/sbom?firmware_id={fid}` — if it returns `{ items: [...], total: N }` but the UI shows zero, the frontend swallowed an error or the response shape changed.
- **Likelihood:** **MEDIUM.** The `.catch(() => [])` pattern at three sites means ANY API-side failure — 401 from rotated API key, 403 from middleware, 500 from a DB error, 404 from a deleted firmware — produces the "no data" UI with no toast. The error-toast path lives in the axios interceptor at `client.ts:84-138` and DOES fire for 401/403/429/5xx — so the operator will see a toast, but the table state will be empty AND the page will say "Generate an SBOM" misleadingly. The `.catch()` swallows don't suppress the interceptor toast; they just prevent the page from re-throwing.

### Symptom: Stuck spinner that never resolves

- **What operator sees:** "Scanning..." button label, animated spinner, no completion ever.
- **Source code:** `SbomPage.tsx:190-225` (polling loop). The loop has NO maximum iteration count, NO timeout, NO stop condition other than `status === 'completed'` or `status === 'failed'`. If the backend row sits at `running` forever (orphaned task, crashed worker, deadlock), the spinner spins forever.
- **How verifiable:** `psql wairz -c "SELECT id, vuln_scan_status, vuln_scan_started_at, vuln_scan_error FROM firmware WHERE vuln_scan_status='running'"` — if a row has been in `running` for >10 minutes with no progress, this is the symptom.
- **Likelihood:** **HIGH** in failure scenarios. The orphan reaper at `main.py:200-242` only runs on backend startup; if the backend has been up since BEFORE the orphan was created (e.g., a session was killed mid-scan), the reaper never reaped that row and it sits permanently in `running`. The frontend has no escape hatch other than navigating away — which abandons the poll loop but leaves the DB row untouched. **A subsequent POST returns 409 "vuln-scan already running"** until something else cleans the row.

### Symptom: Frontend timeout firing before backend completes

- **What operator sees:** "Request timed out" toast (`client.ts:91-99`), "SBOM generation failed" toast (from `extractErrorMessage`), but the backend continues and produces components correctly.
- **Source code:** `client.ts:91` (`error.code === 'ECONNABORTED'`); `client.ts:6` (`timeout: 30_000` default); `sbom.ts:38` (`timeout: SECURITY_SCAN_TIMEOUT=600_000` override for `generateSbom`); `timeouts.ts:43` (`SECURITY_SCAN_TIMEOUT = 600_000`).
- **How verifiable:** Watch the backend log after the operator's "Generate SBOM" timeout toast; if `INFO ... POST /generate -> 200` appears AFTER the toast fires, the timeout was premature.
- **Likelihood:** **LOW for SBOM generate** — 600s ceiling matches `mobsfscan.pipeline._PIPELINE_BUDGET_SECONDS=600` per `timeouts.ts:43` comment. SBOM generation is bounded by `service.generate_sbom()` walking the extracted tree synchronously; even a 16 GB image typically completes in ~3-5 minutes. **NEAR-ZERO for vuln-scan** — the 202+polling pattern makes the POST sub-second per `routers/sbom.py:583` (`asyncio.create_task(...)`); the default 30s axios floor is more than enough. **MEDIUM for SBOM export** — the same 600s override applies (`sbom.ts:76`), and exporting a CycloneDX VEX document for a large SBOM with thousands of vulns could realistically exceed it.

### Symptom: Fake "Scan failed" error displayed when backend actually succeeded

- **What operator sees:** Toast "SBOM generation failed", "Vulnerability scan failed to start", "Security audit failed", etc., while the backend log shows a clean `200 OK`.
- **Source code:** `SbomPage.tsx:140`, `:181`, `:207`; `SecurityScanPage.tsx:123`, `:145`, `:193`. All use `extractErrorMessage(e, 'fallback')` correctly. The `extractErrorMessage` helper at `utils/error.ts:12-22` reads `data.hint` → `data.detail` → `data.error` in that order, covering FastAPI HTTPException AND SlowAPI 429.
- **How verifiable:** Grep `frontend/src/` for `errors: ['Scan failed'` — 0 hits in current code (harness rule `auto-frontend-fake-scan-failed-error` is not firing).
- **Likelihood:** **LOW** — the helper is wired correctly at every call site I checked. The only way this re-emerges is if a new endpoint without a `timeout:` override is added and times out at 30s while the backend continues; `extractErrorMessage` on the `ECONNABORTED` AxiosError returns `err.message = 'timeout of 30000ms exceeded'`, which the user reads as "Scan failed". Risk is **specifically for `vulhunt_scan_firmware` via `runTool`** at `SecurityScanPage.tsx:185-198` — that path goes through `runTool` (`api/tools.ts`) which would need its own timeout override if not present.

### Symptom: Wrong CVE attribution (rows show but wrong content)

- **What operator sees:** A CVE row attributes a kernel-CVE to a userspace binary, or a vendor narrowing didn't fire so an over-attribution shows.
- **Source code:** Frontend simply renders what the backend returns. `cve_matcher.py` in the backend (`backend/app/services/hardware_firmware/cve_matcher.py`) is the source of truth; it's outside Scout D's persona but in scope for Scout C / A.
- **How verifiable:** Click into a row; if the description is for a kernel vuln but the component is "openssl", the attribution is wrong; SQL: `SELECT cve_id, component.name FROM sbom_vulnerabilities v JOIN sbom_components c ON v.component_id = c.id WHERE v.firmware_id = '...'`.
- **Likelihood:** **OUT OF SCOPE for UX** but operator-visible. Defer to Scout B / C analysis.

### Symptom: 429 toast firing constantly even after cooldown should have elapsed

- **What operator sees:** "Rate limit reached" toast every few seconds despite waiting; pages can't operate.
- **Source code:** `client.ts:109-124` reads `Retry-After` header (parsed as integer seconds), falls back to 60s, sets `_rateLimitedUntilMs` for `isRateLimited()` checks. The toast is deduped via `toastOnce('rateLimit', ...)` with a 10s dedupe window. Rate limit constants at `rate_limit.py:85-87`: `TIER_A_HEAVY=5/hour`, `TIER_A_LIGHT_ACK=30/hour`. SBOM `/generate` rides `TIER_A_LIGHT_ACK` (30/hour) at `routers/sbom.py:116`; `/vulnerabilities/scan` rides the same at `:527`.
- **How verifiable:** `curl -H "X-API-Key: ..." -X POST http://localhost:8000/api/v1/projects/{pid}/sbom/generate?firmware_id={fid}` 31 times — the 31st should return 429 with `data.tier='TIER_A_LIGHT_ACK'` per Rule #51 structured-body contract.
- **Likelihood:** **MEDIUM-LOW** because the cooldown logic is correct. The risk is that `/sbom/generate` is still SYNCHRONOUS but rides the 30/hour tier intended for 202+polling — see Conclusions. A heavy-use operator can hit 30 in an hour with a single firmware (force_rescan + iterative tweaks of detection), and the 429 cooldown DOES work — but they'll be locked out for an hour from re-generating.

### Symptom: 409 returned and treated as "already running" but the actual job is dead (Rule #51 orphan reaper)

- **What operator sees:** Click "Rescan Vulnerabilities" → button greys → spinner spins → eventually `setScanning(false)` from a `status==='failed'` path (if the reaper ran), OR spinner spins forever (if it didn't). Bad scenario: subsequent POSTs return 409 forever.
- **Source code:** `SbomPage.tsx:174-183` — the 409 path checks `err.response?.status === 409`, prints `console.error` if not 409, but on 409 it FALLS THROUGH to the polling loop without showing any UI. Backend at `routers/sbom.py:565-569` raises 409 if `status in ('queued', 'running')`. The orphan reaper at `main.py:200-242` ONLY runs in the lifespan startup hook, so a row orphaned mid-session (worker died, network blip, container restart) without a backend restart stays orphaned.
- **How verifiable:** `psql wairz -c "SELECT id, vuln_scan_status, EXTRACT(EPOCH FROM (NOW() - vuln_scan_started_at)) as age_sec FROM firmware WHERE vuln_scan_status IN ('queued','running')"` — any row with `age_sec > 600` is suspect. Then `curl -X POST http://localhost:8000/api/v1/projects/{pid}/sbom/vulnerabilities/scan?firmware_id={fid}` — should return 409.
- **Likelihood:** **HIGH in this codebase**. The orphan reaper is startup-only; the row can be orphaned by (a) `_run_vuln_scan_background` task being garbage-collected before completion (Python `asyncio.create_task` has no strong reference — `routers/sbom.py:583` does NOT save the task handle), (b) backend restart without the reaper (which DOES handle this case per `main.py:200-242`), (c) DB connection drop mid-scan. There is no in-session reaper. **The asyncio.create_task GC risk is the most concerning** — without a strong reference, the task can be silently collected; the row stays at `running` with no work happening.

### Symptom: Stale bundle (`auto-frontend-rebuild-not-restart`)

- **What operator sees:** A backend response shape change (e.g., the 202+polling vuln-scan conversion landed 2026-05-18) doesn't take effect; the old bundle still does the old sync POST; the operator gets an unexpected behavior delta.
- **Source code:** Harness rule at `.claude/harness.json:158-161` flags `docker compose restart frontend` in any doc; the actual deployment must use `docker compose up -d --build frontend`.
- **How verifiable:** `docker compose images frontend` returns `wairz-frontend:latest` created `2026-05-18T11:33:30Z`. `git log -1 --format='%ci' -- frontend/src/` returns `2026-05-19 14:20:19`. **The most recent `frontend/src/` commit is 27 hours newer than the running frontend image.** This means the running frontend is missing one commit's worth of changes — specifically `87a2574 feat(file-formats): cut-over` (which touched format detection but possibly nothing UI-visible, but cannot be verified without diffing the bundle hash against a fresh build).
- **Likelihood:** **HIGH that there is stale bundle drift; UNCERTAIN that it's the regression source.** The drift confirms the operator's running frontend is from before the file-formats cut-over but AFTER all 2026-05-18 rate-limit work landed. If the regression is something only the file-formats cut-over changed, this is the source; if not, this is a contributing factor that should be rebuilt out of the picture before deeper investigation.

## Frontend Timeout Alignment Audit (Rule #29)

- `SECURITY_SCAN_TIMEOUT = 600_000` ms at `frontend/src/api/timeouts.ts:43`.
- Backend ceiling: `backend/app/services/mobsfscan/pipeline.py:103` `_PIPELINE_BUDGET_SECONDS = 600`.
- Aligned per Rule #29 math: `frontend_ms >= backend_s * 1200` → `600_000 >= 600 * 1200 = 720_000`. **THIS IS UNDER-SPEC by 17%.** The frontend value is 600_000, the math says it should be 720_000. Per the inline comment at `timeouts.ts:6-7`, `×1.2 for network + JSON-serialization grace` requires the frontend value to exceed the backend's by 20%, not equal it. The current value is exactly equal in ratio, missing the grace. This is **NOT new** — it predates the regression window — but it is a latent symptom-generator: a backend run that genuinely takes 599s plus 30s of JSON serialization will trip the frontend timeout while the backend continues.
- However, this matters ONLY for the synchronous `/sbom/generate` endpoint (still sync) and `/sbom/export` (still sync). The vuln-scan path is now 202+polling and inherits the default 30s — that's correct.
- For Grype: `config.py:58` `grype_timeout: int = 120`. `grype_service.py:136-138` uses `asyncio.wait_for(proc.communicate(), timeout=settings.grype_timeout)`. If Grype is the backend chosen, the entire vuln-scan completes in <120s of work, well inside any frontend ceiling.

## extractErrorMessage Audit (`auto-frontend-fake-scan-failed-error`)

- File: `frontend/src/utils/error.ts:12-22`.
- Does it read `data.detail`? **YES** (line 17).
- Does it read `data.error`? **YES** (line 18).
- Does it correctly distinguish a 4xx with body from a 5xx? **NO — and intentionally so.** The helper extracts a STRING from any axios error with a `response.data` object; it does not branch on the status code. This is correct for the helper's purpose (return a string for a toast) — the axios interceptor at `client.ts:84+` handles status-code-specific behavior (auth toast, rate-limit toast, server-error toast) BEFORE the rejection bubbles up to the per-call `.catch()` where `extractErrorMessage` is invoked. Per Rule #51, the helper also reads `data.hint` (line 16) which the backend's `custom_rate_limit_exceeded_handler` (per `main.py` per `client.ts:117` comment) populates with an operator-friendly string.
- Verdict: **HELPER IS CORRECT.** The harness rule `auto-frontend-fake-scan-failed-error` does NOT fire on any current code path.

## 429 + 409 Handling Audit (Rule #51 partners)

- **429 handler (interceptor):** `client.ts:109-124`. Reads `error.response.headers?.['retry-after']`, parses as integer seconds, falls back to 60s if missing/unparseable. Sets `_rateLimitedUntilMs = Date.now() + retryAfterSec * 1000` (line 116). The cooldown is global per Rule #51 — `isRateLimited()`, `rateLimitedUntil()`, `rateLimitRemainingMs()` are EXPORTED for pages to gate redundant POSTs. **No page in scope (SbomPage, SecurityScanPage, FindingsPage) currently imports these.** A 429-locked operator pressing "Generate SBOM" 5 times in 30 seconds will fire 5 POSTs that the backend will all 429 — wasteful but harmless. Rate-limit toast is deduped to one every 10 s via `toastOnce('rateLimit', ...)` at line 124. **Acceptable but not optimal.**
- **409 handler (per-page):** `SbomPage.tsx:174-183`. Checks `err.response?.status === 409`, falls through to polling (no UI surfaced). **No 409 dead-row recovery path.** If the row is `running` but no work is happening, the user has no recourse from the UI. The orphan reaper at `main.py:200-242` runs on STARTUP only.
- **Verdict:** Per Rule #51 the structured-body 429 contract is in place and read correctly. The 409 handling is INCOMPLETE — no in-session reaper, no UI escape hatch, no "force unstick" button. This pairs with the stuck-spinner symptom above.

## Stale Bundle Audit (`auto-frontend-rebuild-not-restart`)

- Last frontend image rebuild: `2026-05-18T11:33:30Z` (from `docker image inspect wairz-frontend:latest --format='{{.Created}}'`).
- Last commit touching `frontend/src/`: `2026-05-19 14:20:19 -0600` (commit `87a2574 feat(file-formats): cut-over`).
- **Drift: 27 hours.** The running bundle is missing one commit's worth of frontend changes. The bundle hash served at `http://localhost:3000/` is `/assets/index-B6evRwGs.js` — this is from the `2026-05-18` build. If the file-formats cut-over commit changed anything user-visible in the SBOM/vuln-scan paths, that change is not running.
- Container is reported `Up 2 days (healthy)`. Per Rule #26, `docker compose restart frontend` reuses the stale image; only `docker compose up -d --build frontend` would rebuild. **No evidence in the docker state that a rebuild ran after `87a2574`.**
- **Recommendation:** Before any deeper investigation, rebuild the frontend image and confirm the regression reproduces — this is the cheapest single action that eliminates the stale-bundle confounder.

## Browser / Playwright Repro Attempt

Playwright 1.60.0 is installed (`npx playwright --version` returned `Version 1.60.0`), but no browser harness is wired in this scout session. The frontend container is up and responding 200 at `http://localhost:3000/`; the backend at `:8000` returns 404 to a bare `/api/v1/health` GET (typical — that endpoint may not exist). To complete a real browser repro, the operator can:

1. Open `http://localhost:3000/` in a browser with API key configured (`localStorage.setItem('wairz.apiKey', '<key>')`).
2. Navigate to a project with a `ready` firmware.
3. Click the SBOM tab.
4. Open browser DevTools → Network.
5. Click "Generate SBOM"; observe the request to `/api/v1/projects/{pid}/sbom/generate?force_rescan=false&firmware_id={fid}` — watch latency, status code, response body.
6. Click "Scan for Vulnerabilities"; observe the 202 from `/sbom/vulnerabilities/scan`, then watch the 2s-interval polls to `/sbom/vulnerabilities/scan/status` until `completed` or `failed`.
7. If "Scanning..." spinner never resolves: SQL inspect `firmware.vuln_scan_status` for the firmware_id; if `running` for >10 min, the orphan-row symptom is confirmed.

## Conclusions for Wave-2 Convergence

1. **The SBOM `/generate` endpoint is mis-tiered.** It rides `TIER_A_LIGHT_ACK=30/hour` (intended for 202+polling), but the endpoint is still SYNCHRONOUS and holds the uvicorn worker for the full duration. Either convert `/sbom/generate` to 202+polling (Rule #33) and keep the tier, OR move it to `TIER_A_HEAVY=5/hour` and document the sync ceiling. This is a Rule #51 invariant-drift companion failure mode — exactly what Rule #51 was promoted to surface.

2. **The vuln-scan polling loop has no escape hatch.** The orphan reaper at `main.py:200-242` is STARTUP-only; an asyncio.create_task GC risk at `routers/sbom.py:583` (no strong task reference) can orphan a row mid-session. The frontend has no "unstick" / "force unstick" / "abort" button — the operator can navigate away but the row stays at `running`. Wave-2 should consider an in-session periodic reaper (Rule #51 "companion failure modes that frequently coexist") + a frontend "Reset scan" affordance gated on `status === 'running'` and `age > N minutes`.

3. **The most likely operator-visible regression is stale-bundle.** The running frontend image is 27 hours older than the most recent `frontend/src/` commit. Before any deeper diagnosis, rebuild the frontend image (`docker compose up -d --build frontend`) and confirm the regression reproduces. If it doesn't, the stale bundle WAS the regression.

4. **The 600s `SECURITY_SCAN_TIMEOUT` is under-spec per Rule #29's 1.2× grace factor.** It should be 720_000 ms to match the backend's `_PIPELINE_BUDGET_SECONDS=600` × 1.2 grace. Not a regression source (predates the window) but a latent symptom-generator that should be corrected alongside any vuln-scan / SBOM-gen / security-audit work.

5. **The .catch swallows in `loadData()` and the store hide real backend failures.** If the regression is on the backend side (a Pydantic schema mismatch returning 500, a `firmware_id` resolution returning 404 because of a recent firmware-paths change, etc.), the SBOM page will show "Generate an SBOM" with no toast guiding the operator to the real cause. Wave-2 should review whether these `.catch(() => [])` patterns should at least toast on 5xx — the axios interceptor already does the work, but the page-level state is wrong (showing the "no SBOM yet" UI when really the backend errored).
