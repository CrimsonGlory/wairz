---
title: "Firmware upload UX: surface post-write stages (hash / extract / detect) instead of silent 100%"
status: pending
priority: high
target: backend/app/routers/firmware.py + backend/app/services/firmware_service.py + frontend upload UI
discovered: 2026-05-07
discovered_by: Illumisite 16 GB upload session — user observed UI shows "Uploading firmware... 100%" while backend silently runs ~5+ min of post-write work
---

## Problem

For large firmware uploads (≥1 GB), the user sees `Uploading firmware... 100%` once bytes finish streaming, then waits silently for ~minutes-to-tens-of-minutes while the upload endpoint runs heavy post-write work without any progress feedback. The user cannot tell whether:

- The backend is still working (which it is — 100% CPU sustained)
- It has hung
- An error occurred and the page is stale

Concrete observation (2026-05-07): A ~7.6 GB compressed ZIP (~16 GB Illumisite uncompressed) hit `POST /projects/{id}/firmware`. Bytes finished writing to disk at 17:30 UTC. Backend was still running at 17:32 UTC, no DB row, no log output. UI showed no change from "100%". User had no signal whether to wait or panic.

## Root cause

`backend/app/services/firmware_service.py:upload()` (and the router at `backend/app/routers/firmware.py:80 upload_firmware`) does ALL of these inside one synchronous request handler:

1. Stream bytes to disk (chunked, hash builds progressively) — visible to browser as upload progress
2. SHA256 hexdigest finalisation
3. Duplicate-row dedup query
4. **Tar/zip extraction** (`_extract_tar`, line 398, via `run_in_executor`) — for 16 GB this is 5+ minutes of CPU
5. `widen_read_perms` on the extraction dir
6. `_compute_roots_sync` filesystem detection
7. Architecture / endianness detection
8. OS info extraction
9. Kernel path detection
10. (After commit) HW-firmware detection task via `asyncio.create_task`

Steps 4-9 happen **before** the endpoint returns 201. The browser's progress bar only tracks step 1 (byte upload). Steps 2-9 are invisible.

## Acceptance Criteria

Two-layer fix per Rule #33 202+polling precedent (cve-match, emulation, fuzzing, vuln-scan):

- [ ] **Backend**: split the upload endpoint into a fast ack + background runner.
  - `POST /projects/{id}/firmware` returns 202 with the firmware row populated through step 3 (bytes, hash, dedup) only.  Add `upload_stage` column on `firmware` (Literal["uploading", "extracting", "detecting", "ready", "failed"]) with CHECK constraint per Rule #33 (c), default `'uploading'`. While step 1 is in flight the row doesn't exist yet — frontend keeps progress on the multipart stream.
  - On bytes-done, transition to `'extracting'`, persist row, return 202. Continue to steps 4-9 in `asyncio.create_task` (matching Rule #33 (d) rubric — in-process work + DB-incremental progress + restart-friendly).
  - Background runner updates `upload_stage` at each transition + populates `extraction_dir`, `extracted_path`, `architecture`, `os_info`, `kernel_path`, then sets `'ready'`.
  - On error: rollback, persist `'failed'` + error text on a fresh session.
- [ ] **Frontend**: poll `GET /firmware/{id}` every 2s while `upload_stage in ("extracting", "detecting")`, render stage label + spinner. Mirror the `EmulationPage` / `FuzzingPage` polling pattern.
  - UI labels: "Uploading bytes" (during multipart), "Computing hash" (brief), "Extracting archive (X.X GB)" (longest), "Detecting filesystem", "Ready". Each stage gets a distinct icon + text.
  - On `failed`: show `toast.error(error)` + the upload row stays visible with "Retry" affordance.
- [ ] **Tests**: `backend/tests/test_firmware_router.py` already exists (Phase 1). Add `TestUploadStageRule33` covering the new state machine + 409 idempotency on re-upload of in-flight firmware + CHECK constraint enforcement (Rule #35b live canary).
- [ ] **Migration**: alembic revision adding `upload_stage` column + CHECK constraint, defaulting existing rows to `'ready'` (they're done by definition). Chains off current head.
- [ ] **Acceptance smoke**: Re-upload a ≥1 GB firmware while watching `firmware_id` polling — UI must show stage transitions, NOT 100% silence.

## Cross-step

This is a **Rule #33 202+polling conversion**, exact pattern match to the cve-match (commit `22c1990` 2026-04-25) and vuln-scan (commits `a255a8b..61e814b` 2026-05-07) precedents. Reuses the same structural template:
- Status column with Literal + CHECK
- 202 ack with current row state
- 409 conflict on re-trigger while in-flight
- asyncio.create_task background runner with own AsyncSession via `async_session_factory`
- Outer try guard + fresh session for failure-write path
- `[-2000:]` traceback truncation
- Rule #11 backstop after column addition (class-shape change per Rule #20)

Per-commit shape per Rule #25:
- (i) `feat(firmware): add upload_stage column + CHECK constraint`
- (ii) `refactor(firmware): split upload to 202+polling per Rule #33`
- (iii) `feat(frontend/firmware): poll upload status with stage labels`
- (iv) `test(firmware_router): Rule #33 upload-stage state machine + CHECK canary`

## Out of Scope

- The ALREADY-async unpack worker (separate from upload) is fine and stays untouched. This intake is only about the upload-handler phase.
- Resumable uploads via chunked PUT / Range headers — separate intake; this addresses the post-bytes UX gap, not the during-bytes one.

## Provenance

Surfaced 2026-05-07 during the Illumisite 16 GB upload session. User feedback verbatim: "the bigger finding is that user needs to be provided better understanding of status and progress during this step". Companion to the Rule #33 + Rule #29 architectural pattern shipped for vuln-scan earlier the same session.
