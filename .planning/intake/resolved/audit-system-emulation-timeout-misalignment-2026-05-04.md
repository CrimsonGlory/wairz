---
title: "System-emulation Rule #29 timeout misalignment — 60s backend vs 30s axios default"
status: pending
priority: high
target: backend/app/routers/emulation.py + frontend/src/api/emulation.ts (OR convert to 202+polling per Rule #33)
---

## Description

`POST /emulation/system` does ~60s of synchronous work (30s `_wait_for_shim` + 30s `httpx.post('/start')`) inside the request handler. The matching frontend call at `frontend/src/api/emulation.ts:147` uses no `timeout:` override — it falls back to the 30s axios default. Result: every valid system-emulation start that takes >30s presents to the user as "system emulation start failed", while the backend continues happily.

**Evidence:** Stream B (F-B-03). Width-canary applied — this is the only timeout-misalignment in the routers layer (the rest of `frontend/src/api/*.ts` long-op endpoints carry explicit overrides).

**Companion to CLAUDE.md Rule #29** (`frontend_ms ≥ backend_s × 1200`) and Rule #33 (the 4-bullet 202+polling design contract).

## Acceptance Criteria

Two fix paths — pick one:

**Path A (stop-gap, single-commit):**
- [ ] Add `timeout: 90_000` (75s × 1.2 grace) to the axios call at `frontend/src/api/emulation.ts:147` with an inline comment citing the backend ceiling: `// matches POST /emulation/system handler ceiling 60s + 25% grace per Rule #29`.
- [ ] Tier the constant if reusable: add `SYSTEM_EMULATION_START_TIMEOUT = 90_000` to `frontend/src/api/emulation.ts`.

**Path B (preferred, ships with Rule #33 compliance):**
- [ ] Convert `POST /emulation/system` to 202+polling per Rule #33 4-bullet contract: idempotent POST + 409 conflict on already-running, persist boot-progress on the same row, status column with Pydantic Literal AND DB CHECK constraint, asyncio.create_task vs arq decision (likely arq — Docker spawn + worker resource).
- [ ] Migration to widen `ck_emulation_sessions_status` if a new transient state is needed.
- [ ] Frontend uses default 30s axios + 2s polling per the firmware-unpack precedent.

## Out of Scope

- Other emulation modes (user-mode is already 202+polling per the 2026-04-20 Wave-1 α refactor).

## Cross-step

Path A: 1 frontend commit. Path B: 3 commits per Rule #25 (DB migration / router-and-frontend pair / closure).

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-b-routers-2026-05-04.md` finding F-B-03.
