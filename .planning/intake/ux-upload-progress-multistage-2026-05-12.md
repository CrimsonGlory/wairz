---
title: Upload progress UI — multi-stage indicator for browser→nginx→backend→hash→202 journey
opened: 2026-05-12
status: ready-to-ship (research-fleet synthesized; Shape 1 is ~15 LOC frontend-only)
priority: medium (operator UX paper-cut; observed during 8+ GB ILLUMISITE upload 2026-05-12)
discovered_during: Windows-firmware-test-plan execution (post-κ); operator observed "Uploading firmware..." stuck at 100% for 5+ minutes during 8+ GB Medtronic firmware upload
estimated_effort: ~15 LOC, 1 file, 1 commit, ~15-30 min wall (Shape 1 — recommended)
parent: post-κ smoke-test feedback
research_fleet_outputs:
  - scout 1 — industry UX survey (consensus 4-stage stepper + ARIA discipline)
  - scout 2 — wairz integration architecture (existing upload_stage poll + 3-phase UI inventory)
  - scout 3 — minimum-effective-change estimate (Shape 1 ~15 LOC frontend-only)
---

# UX upload progress — multi-stage indicator

## Problem (verified)

The wairz firmware-upload UI shows "Uploading firmware..." with a progress bar at 100%
for multi-minute windows during large-file uploads. Operator stares at static "100%
Uploading firmware..." for 5+ minutes and reasonably concludes the system is hung.

**Observed 2026-05-12** during Medtronic ILLUMISITE upload (8+ GB Windows firmware
ZIP). Browser progress bar hit 100% while backend was still streaming bytes + hashing
SHA256 inline (`upload_bytes_only` at `backend/app/services/firmware_service.py:298-405`).
DB row not created until SHA256 done + dedup checked + INSERT committed; 202 not
returned until then.

## Root cause (Scout 3 diagnosis)

The "100% upload" is the BROWSER→nginx leg only (axios `onUploadProgress`). The
backend's inline `upload_bytes_only` then:

1. Reads body chunks from `UploadFile` (~8 KB at a time)
2. Updates `sha256_hash.update(chunk)` per chunk (inline; not in executor)
3. Writes chunks to disk via `aiofiles.open(...)`
4. Dedup SELECT against existing SHA256
5. INSERTs the firmware row at `upload_stage='detecting'`
6. `await self.db.commit()`
7. Returns 202

For a 16 GB upload, steps 1-3 take 120-180s wall AFTER the browser thinks it's "done"
(steps 4-6 add <1s). The post-202 polling at `getFirmwareUploadStatus` already covers
`detecting → extracting → analyzing → ready` perfectly — the gap is ONLY between
`onUploadProgress=100%` and the axios response promise resolving.

**Important finding:** the `UploadStage` Literal at `backend/app/schemas/firmware.py:10`,
the DB CHECK constraint `ck_firmware_upload_stage` at alembic revision
`d2e3f4a5b6c7`, and the TypeScript `UploadStage` union at `frontend/src/types/index.ts:32`
**already include `'uploading'` and `'hashing'`** — backend just never writes them.
Rule #25 cross-stack alignment is satisfied; the slot is ready for future Shape-3
escalation without an alembic migration.

## Research-fleet synthesis

### Scout 1 (UX industry survey) — converged pattern
- **Single persistent surface** with a 4-stage labeled stepper: **Upload → Server-receiving → Hashing → Unpack/Process** (not a modal that auto-closes at 100%).
- Each completed stage shows a **permanent checkmark badge** — operators can see "your bytes are safe" even if a later stage fails.
- **Indeterminate** spinner OR new-denominator for the server legs; never a "fake" sub-100% percent on uncountable work.
- **ARIA live region `polite` (NOT assertive)** wrapping the stage label + percent; `aria-atomic="true"`; throttle announcements to once per stage transition or per 5-10% delta. Stepper uses `<ol>` with `aria-current="step"`.
- **Error states preserve completed-stage checkmarks** — never collapse the whole journey to one red bar (precedent: GitHub LFS GH008, YouTube "processing abandoned").
- Precedent shapes: YouTube ("Processing... (resolution)" with per-resolution ETA), Hugging Face (tri-counter, no fake percent), Google Drive (dedicated Uploads screen — contrarian non-blocking alternate worth considering as Shape-4 future).

### Scout 2 (architecture audit) — existing infra inventory
- `/api/v1/firmware/{id}/upload-status` polling endpoint already exists (`backend/app/routers/firmware.py:179-198`).
- `FirmwareUpload.tsx:43-218` already has 3-phase UI (`uploading / processing / done`) with 2s polling via `setInterval`.
- `STAGE_LABELS` Record at `FirmwareUpload.tsx:28-36` renders the polled stage as human-readable text.
- Existing SSE infra at `app/services/event_service.py` + `app/routers/events.py` + `frontend/src/hooks/useEventStream.ts` if Shape 2 is ever chosen.
- The `upload_bytes_only` background-extraction refactor shipped at commit `847eae9` (intake `firmware-upload-progress-visibility-2026-05-07`) closed the post-202 gap — only the pre-202 hash+save window remains visible-but-unlabeled.

### Scout 3 (minimum-effective-change) — ranked shapes

| Shape | LOC | Files | Alembic | Rule #25 | Time-to-ship | Recommendation |
|---|---|---|---|---|---|---|
| **1 — Browser 2-tick copy fix** | ~15 | 1 (`FirmwareUpload.tsx`) | none | none (no Literal change) | **~15-30 min** | ✅ **SHIP** |
| 2 — Backend SSE pre-202 phase channel | ~150-200 | 5-7 | none | n/a | ~3-5 hr | future-escalation candidate (only if Shape 1 + Shape-1+backend-write-'hashing' insufficient) |
| 3 — Pre-flight handshake + extend stage enum | ~250-350 | 8-10 | YES — extend `ck_firmware_upload_stage` AND Pydantic AND TS — Rule #25 single-slice | YES single-slice commit | ~6-10 hr | over-engineered; not recommended |

## Decision — Shape 1 (browser-only ~15 LOC)

### Mechanics

In `frontend/src/components/projects/FirmwareUpload.tsx`:

1. Add a `'finalizing'` phase to the `phase` state union (currently `'uploading' | 'processing' | 'done'`).
2. Add `useEffect([uploadProgress, phase])` that triggers `setPhase('finalizing')` when `uploadProgress >= 100 && phase === 'uploading'`.
3. In the `phase === 'uploading'` JSX branch (currently at lines 192-201), split into:
   - **While `uploadProgress < 100`** — current behavior: `<Progress value={uploadProgress} />` + "Uploading firmware..." + `{uploadProgress}%`.
   - **At `uploadProgress >= 100`** — replaced by the `'finalizing'` branch (next step).
4. Add a new `phase === 'finalizing'` JSX branch — indeterminate spinner + "Server received upload — finalizing (hashing + deduplicating)..."  + permanent ✓ "Uploaded N MB" checkmark above the spinner.
5. When the axios POST resolves (202 lands), the existing `setPhase('processing')` runs and the polling pass takes over with `STAGE_LABELS`-driven copy.

ARIA: wrap the spinner + label in `<div role="status" aria-live="polite" aria-atomic="true">`.

### Acceptance criteria

1. **Browser at 100%** transitions visibly: progress bar removed, indeterminate spinner appears, copy flips to "Server received upload — finalizing..." within <1s.
2. **Completed-upload checkmark** with the uploaded byte count is visible above the spinner ("Uploaded 8.21 GB ✓").
3. **When 202 arrives**, transition flows to `'processing'` phase with `STAGE_LABELS` copy — no flicker, no regression.
4. **Error state** (axios rejects post-100%): finalizing phase exits to error state with the "Uploaded N GB ✓" checkmark PRESERVED (server got the bytes; just couldn't process) + clear failure copy + Retry affordance.
5. **Existing 202+polling for `unpack_stage`** unchanged.
6. **Accessibility**: screen-reader announces "Stage 2 of 4: Server received upload, finalizing..." once on transition (not repeatedly).

### Testing strategy (3 layers)

- **Unit**: extend (or create) `FirmwareUpload.test.tsx` — mock `apiUploadFirmware` to return a deferred promise; assert `onProgress(100)` triggers the `'finalizing'` phase before the 202 resolves.
- **Integration**: existing `backend/tests/test_firmware_router.py::test_upload_returns_202_with_upload_stage_detecting` (Rule #35b live-canary) needs NO change.
- **Browser smoke**: upload a 100-MB synthetic file via `citadel:qa` against `/projects/{id}` — observe spinner reaches 100%, transitions through "Server is finalizing..." → "Detecting format" → "Extracting archive" → "Analyzing filesystem" → "Ready".

### Wairz-specific gotchas (forewarned)

- **Rule #26 frontend rebuild required** — `docker compose up -d --build frontend` (NOT restart). Image rebuild ~1-3 min on this hardware.
- **Rule #24 canary** — mandatory `( cd frontend && npx tsc -b --force )` before pushing.
- **Rule #29 axios timeout** — no change needed. `UPLOAD_TIMEOUT = 600_000` (10 min) already covers the pre-202 hash+save window per backend math (600s × 1200 = matches).
- **Rule #25 cross-stack alignment** — no Literal change in Shape 1 = no alignment surface touched. If Shape 3 ever ships, the alignment is ALREADY satisfied (uploading/hashing in all three surfaces).

## Future escalation path (when/if Shape 1 isn't enough)

**Shape 1+ (~30 LOC, 2 files, 0 alembic):** when operators want stage names instead of "finalizing", add a single backend write inside `upload_bytes_only`:

1. At line 298 entry: `firmware.upload_stage = 'hashing'` + `await self.db.flush()`. (Requires a row already EXISTING — chicken/egg.)

Actually the cleanest escalation: **split `upload_bytes_only` into pre-hash and post-hash phases**, INSERT the row at `upload_stage='receiving'` BEFORE the chunk loop (using a placeholder SHA, or skipping dedup until post-hash), then UPDATE to `'hashing'` during the loop, then UPDATE to `'detecting'` + commit + return 202. This requires moving the dedup SELECT to AFTER the hash; the conflict is now an UPDATE-then-409 path instead of pre-INSERT 409, but the operator experience is fully visible.

This is ~30-50 LOC and still no alembic (the values are already in the CHECK constraint). Reserved for a future session.

**Shape 2 (SSE pre-202 phase channel):** real-time event-stream from backend during hash. Existing SSE infra at `event_service.py` is reusable. ~150-200 LOC. Only justified if Shape 1+ proves insufficient AND operators are doing huge uploads frequently enough that per-byte progress matters.

**Shape 4 (Google-Drive-style dedicated Uploads screen):** non-blocking persistent surface for power users running multi-GB jobs. Reserved as a UX-direction question for future operator interviews — DOES wairz's audience prefer modal-blocking or non-blocking upload flows?

## Companion intakes / cross-references

- κ.A through κ.E walker postmortems (`unpack_stage` polling is the backbone — Shape 1 doesn't touch it).
- Rule #29 axios timeout discipline — `UPLOAD_TIMEOUT=600_000` already correct.
- Rule #25 cross-stack alignment — `UploadStage` Literal already aligned; no work needed.
- Rule #26 frontend rebuild — single `docker compose up -d --build frontend` post-ship.
- Rule #24 mandatory tsc canary — `npx tsc -b --force` before push (per Rule #41 concurrency-cancel mitigation, run a broader local-side gate at session-boundary commit).

## Sub-task ladder (single-stream, single-commit)

This is a 1-commit ship per Rule #25 single-slice. NOT a multi-commit walker.

**υ.A** (or whatever stream name — single ship): `feat(ui): finalizing phase for firmware upload — close the 100%-stuck-at-100% UX gap`
- File: `frontend/src/components/projects/FirmwareUpload.tsx`
- LOC delta: ~15
- Tests: ~20 LOC in `FirmwareUpload.test.tsx`
- Frontend rebuild: `docker compose up -d --build frontend` (Rule #26)
- Rule #24 canary: `( cd frontend && npx tsc -b --force )` pre-push

## Open questions for operator interview (defer)

1. For multi-GB uploads (>5 GB), do operators want a "go grab coffee, I'll ping you" non-blocking surface (Shape 4) OR keep the modal flow?
2. Should the `'finalizing'` copy include an ETA based on byte-count rate (e.g. "Server finalizing... ~2 min estimated")? Estimation requires backend-side rate measurement; not in Shape 1 scope.
3. Should the upload modal be DISMISSIBLE while finalizing — i.e. operator can navigate away and the upload continues in the background? This is a Shape-4 question (concurrent uploads + UI persistence) — defer.
