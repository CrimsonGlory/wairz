# Fleet Discovery Brief — Emulation + Fuzzing 202+Polling (Wave 1)

Session: `emulation-fuzzing-202-polling-2026-04-20`
Wave: 1 (both streams single wave, no discovery-relay needed downstream)

## Stream α — emulation (5 commits, merged to main)
Branch: `feat/stream-alpha-emulation-202-2026-04-20` → merged at `6956aaa` parent `41d8e72`
Commits: 2439365, c5d2f74, e34c803, 6eb0dec, 5c183e7
Files (+674/-133, 10 files):
- `backend/app/services/emulation/service.py` — split `start_session` into `create_pending_session` + `spawn_session_background`
- `backend/app/routers/emulation.py` — `POST /emulation/start` now `status_code=202`; arq `enqueue_job("spawn_emulation_session_job")` with asyncio.create_task fallback; terminal WS handler now gates on `status in ("running", "ready")` (rejects with code 4004 otherwise)
- `backend/app/workers/arq_worker.py` — new `spawn_emulation_session_job` registration (scope expansion beyond declared brief but required)
- `backend/alembic/versions/c3f8a1b9e4d2_widen_emulation_session_status_check.py` — widened CHECK constraint to `{created, pending, starting, booting, running, ready, stopping, stopped, error}` (was 6 values; migration surfaced at integration-probe time when first `POST /start` returned 500)
- Frontend: `types/index.ts`, `pages/EmulationPage.tsx`, 3× components under `components/emulation/`

### Discoveries (α)
- **DB CHECK constraint surfaced at runtime, not typecheck.** Adding a new status enum value required an alembic migration; pydantic+SQLAlchemy types allowed the literal but the CHECK on `emulation_sessions.status` rejected the insert. Caught by real `docker cp` + `POST` integration probe (Rule #20). The migration was commit 5 of 5, written AFTER service/router/frontend were in place.
- **Terminal-WS two-layer gate.** Service-layer `_await_ready` probes for `/tmp/.standalone_mode` (standalone-binary user mode) or `/firmware` (chroot user mode) before flipping to `ready`; system-mode reuses the existing `await_system_startup` which waits for `/tmp/qemu-serial.sock`. Router-layer WS handler rejects `pending|booting` with WS code 4004. No race possible — the frontend cannot reach the WS before the service has confirmed container liveness.
- **arq job name:** `spawn_emulation_session_job`. Signature: `session_id, firmware_id, kernel_name, init_path, pre_init_script, stub_profile`. If arq pool unavailable, falls back to `asyncio.create_task(_spawn_background(...))`.
- **FirmAE system emulation (`POST /emulation/system`) was out of scope.** Uses its own `SystemEmulationService` with existing polling via `system_emulation_stage`. Rule #29 closure here applies ONLY to the `/emulation/start` flow (user-mode + system-mode QEMU via `EmulationService.start_session`). FirmAE's own 1800s alignment is orthogonal; flag for a follow-up if it ever re-surfaces.
- **Pre-existing test `backend/tests/test_emulation_auth.py` fails on main AND α branch with 401.** Unrelated — API key middleware added elsewhere; test fixtures don't set the header. Not regressed by this stream. Noted for the backend-pytest-unstable-tests campaign to investigate.

## Stream β — fuzzing (4 commits, merged to main)
Branch: `feat/stream-beta-fuzzing-202-2026-04-20` → merged at `6956aaa` (conflict-resolved)
Commits: caf2370, df30015, b5b4402, a909937
Files (+158/-16, 7 files):
- `backend/app/services/fuzzing_service.py` — `start_campaign` is now a fast-path (flip row to `queued`, return); new `_spawn_campaign_container` holds container-spawn logic for the background task; `_count_active_campaigns` and `cleanup_orphans` updated for `queued`
- `backend/app/routers/fuzzing.py` — `POST /fuzzing/campaigns/{id}/start` now `status_code=202`; new `_run_campaign_spawn_background` (own DB session); scheduled via `asyncio.create_task`
- Frontend: `types/index.ts` (added `queued` to `FuzzingStatus` union), `pages/FuzzingPage.tsx` (poll every 2 s while queued, 10 s otherwise; `hasRunningCampaign` matches `running||queued`), 2× components under `components/fuzzing/` (exhaustive `Record<FuzzingStatus, ...>` lookups per Rule #9)

### Discoveries (β)
- **`queued` status added despite brief suggesting it wasn't needed.** Campaign pre-flight listed existing values as `queued|running|crashed|completed` but the tree actually had `created|running|crashed|completed` — `queued` was the natural marker for "row exists, container spawn scheduled but not started." Backend enum is VARCHAR(20) with no SQL-level CHECK constraint, so no alembic migration was required (contrast with α which had a CHECK to widen).
- **`cleanup_orphans` now reconciles `queued` rows without `container_id`** — arq cron runs every 30 min; any stranded queued rows (worker crashed between `queued` flip and container spawn) are marked `error` on first cron pass. Graceful backward-compat: pre-refactor `created → running` transitions in flight at merge time are unaffected.
- **No real AFL++ integration run attempted** (per mission brief). Class import + method-shape smoke checked clean via `docker cp` into running container; full 202→running→completed requires a real firmware + campaign setup for merge-session smoke.

## Cross-stream overlap matrix

| File | α | β | Merge outcome |
|---|---|---|---|
| `CLAUDE.md` | Flipped emulation row to FIXED | Flipped fuzzing row to FIXED | Merge conflict resolved manually (combined both FIXED notes in Rule #29) |
| `frontend/src/types/index.ts` | Added emulation `pending/booting` enum members | Added `queued` to `FuzzingStatus` | Auto-merged cleanly (disjoint enum types) |
| All other files | α-only | β-only | — |

No cross-stream commit sweeps (Rule #23 worktree discipline held). α wrote `backend/app/workers/arq_worker.py` outside declared scope for arq job registration — accepted as necessary; β's scope was strictly within its declared file list.

## Acceptance gate results

- [x] `grep 'DEFERRED' CLAUDE.md | grep -E 'emulation|fuzzing'` → 0 hits
- [x] `grep 'asyncio.create_task\|enqueue_job' backend/app/routers/{emulation,fuzzing}.py` → ≥1 match each (multiple in emulation for arq+fallback path)
- [x] `grep 'timeout:' frontend/src/api/{emulation,fuzzing}.ts` → NO long override on `startEmulation`/`startCampaign` (defaults to 30s; other long-op overrides `NETWORK_CAPTURE_TIMEOUT`, `FUZZING_ANALYSIS_TIMEOUT` remain and are legitimate)
- [x] `npx tsc -b --force` from frontend → exit 0 (after Rule-17 canary confirmed tool is live)
- [x] Rule #21 mex mirror updated (commit `d83095f`)
- [ ] Rule #8 + #26 rebuild: IN PROGRESS in background (shell b0s1f2nyt)
- [ ] Full real-boot smoke (emulation `pending→booting→ready` + fuzzing `queued→running`) on real firmware: merge-session integration

## Follow-ups for next session

1. **After Rule #8/26 rebuild finishes**, smoke `POST /emulation/start` + `POST /fuzzing/campaigns/{id}/start` on real firmware; confirm status transitions and terminal WS attach.
2. **`SECURITY_SCAN_TIMEOUT=600_000` is redeclared in 8 files** (noted in Rule #29 body) — consolidate to `frontend/src/api/timeouts.ts` in a future cleanup.
3. **FirmAE `POST /emulation/system` timeout alignment** — orthogonal to this campaign; evaluate if Rule #29 audit should re-open for it.
4. **test_emulation_auth.py 401 failure** — feed into the backend-pytest-unstable-tests campaign (Session +2 per seed).
