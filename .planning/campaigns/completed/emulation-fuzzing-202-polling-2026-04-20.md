---
Status: completed
Direction: Convert POST /emulation/start and POST /fuzzing/campaigns/{id}/start from blocking-return to 202-accepted + job-status polling. Rule #29 identified these two misalignments as DEFERRED (pending the protocol change); synchronous ceilings of 1800s and 7200s are impractical to align at the frontend — firmware-unpack's 202+polling pattern is the template.
Created: 2026-04-19
Created_in: session 480666ce (strategic research post wairz-intake-sweep-2026-04-19 close)
Type: build
Baseline HEAD: ea5f1c7 (backend pytest CI workflow shipped)
Estimated Sessions: 1-2
Actual Sessions: 1
Completed: 2026-04-20
Completed_in: session b3a3b580 (/fleet two-stream single-wave; α emulation + β fuzzing; merged at 41d8e72 + 6956aaa; Rule #21 mex mirror at d83095f)
Orchestrator: /fleet (2 parallel streams, isolated worktrees per Rule #23)
Daemon: optional (small campaign — single-session likely)
---

## Pre-flight audit — 2026-04-20 (session 5321d5a1)

Two prep concerns raised by research-fleet dispatch scan (202+polling readiness
agent); both resolved as no-ops per Rule #19:

1. **`frontend/src/components/ProjectRouteGuard.tsx` status-filter audit** —
   Component only resets project-scoped Zustand stores on `projectId` change;
   carries no status-list filter. Adding `starting` to a filter array is a
   non-op; no code change required.
2. **E2E start-endpoint timeout audit** —
   `frontend/tests/e2e/emulation-workflow.spec.ts` exercises UI smoke only
   (tab render, button presence). No test invokes `startEmulation()` /
   `startCampaign()`. `grep -r "startEmulation\|startCampaign" frontend/tests/e2e/`
   → 0 matches. No fuzzing E2E spec exists (`fuzz*.spec.ts` → 0 files). No
   stall-at-30s risk in existing suite.

**Verdict:** Campaign is dispatch-ready. No prep commit needed. Status flipped
`queued → ready`. Dispatch via `/fleet 2 streams` per the stream plan below.
Terminal-WS race (emulation α) is the only in-stream technical risk —
`routers/emulation.py:829-831` must transition `starting → running` on a
container health-check (ping socat socket / shell responsiveness), not on
spawn-completion, so the frontend terminal connect doesn't race a still-
booting container.


# Campaign: Emulation + Fuzzing "202 + Polling" Refactor

## Motivation — Rule #29 deferrals

CLAUDE.md Rule #29 (frontend↔backend timeout alignment) adopted 2026-04-19 in
commit `732d82f`. Rule body names TWO DEFERRED misalignments requiring a
protocol change rather than a simple axios timeout bump:

| Endpoint | Frontend (axios) | Backend | Gap | Status |
|---|---|---|---|---|
| `POST /emulation/start` | default 30 s (`frontend/src/api/emulation.ts:15-26`, no `timeout:` option) | `config.py:30 firmae_timeout=1800` | 60× | DEFERRED — 202+polling required |
| `POST /fuzzing/campaigns/{id}/start` | default 30 s (`frontend/src/api/fuzzing.ts:48-56`, no `timeout:` option) | `config.py:38 fuzzing_timeout_minutes=120` (= 7200 s) | 240× | DEFERRED — 202+polling required |

Rule #29 also notes: `Chrome's XHR/fetch hard cap is ~300s; nginx
proxy_read_timeout defaults to 60s; AWS ALB idle-timeout defaults to 60s
(max 4000s); Cloudflare origin-response defaults to 100s`. Even if we wanted
to raise the axios timeout to 1800s/7200s, any deployment behind a reverse
proxy would break silently at the proxy's ceiling. 202+polling is the only
shape that survives real-world deployment topology.

## Template — firmware unpack (already in-tree)

`backend/app/routers/firmware.py:139` is the canonical wairz example:

```python
@router.post("/{firmware_id}/unpack", response_model=FirmwareDetailResponse, status_code=202)
async def unpack_firmware(...):
    # Dispatch background work; return 202 immediately with initial state
    asyncio.create_task(_run_unpack(...))
    # (arq worker queue used when available — see firmware.py:30)
    return firmware_detail  # frontend polls /firmware/{id} every 2s for status change
```

Frontend polling: `EmulationPage`, `FuzzingPage`, and `ProjectDetailPage`
all already use `useEffect` + `setInterval` for long-running ops (per
CLAUDE.md "Conventions — Frontend" section). The polling skeleton is not
new work — extending it to emulation/fuzzing start endpoints is.

## Phases

| # | Stream | Description | Files | Est. Commits |
|---|--------|-------------|-------|--------------|
| 1α | emulation | Convert `POST /emulation/start` to 202. Split synchronous `EmulationService.start_session` body into `_spawn_async` (detached via `asyncio.create_task`) and add a job-status row (or reuse `emulation_session.status` transitions: `pending → booting → ready`). WebSocket terminal at `routers/emulation.py:829` must continue to work once `status=ready`. Frontend `api/emulation.ts:15` returns initial session row; `EmulationPage` polls `/emulation/{id}/status` until `ready`, then activates the terminal. | backend: `routers/emulation.py`, `services/emulation/service.py`; frontend: `api/emulation.ts`, `pages/EmulationPage.tsx` | 3-5 |
| 1β | fuzzing | Convert `POST /fuzzing/campaigns/{id}/start` to 202. Refactor container-spinup code path to `asyncio.create_task`. Campaign status rows already carry `status: queued\|running\|crashed\|completed` — reuse. Frontend `api/fuzzing.ts:48` returns campaign row with `status=queued`; `FuzzingPage` polls `/fuzzing/campaigns/{id}` every 2 s until status changes. | backend: `routers/fuzzing.py`, `services/fuzzing_service.py`; frontend: `api/fuzzing.ts`, `pages/FuzzingPage.tsx` | 3-5 |

**Two streams, disjoint file sets** — Fleet-parallelizable. Run each in a
`.worktrees/stream-{α,β}` worktree per Rule #23 (worktree discipline).

## End Conditions

| # | Condition | Type |
|---|-----------|------|
| 1α | `curl -sX POST http://localhost:8000/api/v1/projects/{pid}/emulation/start` returns `202` with initial session row (status != `ready`) | command_passes |
| 1α | `GET /api/v1/projects/{pid}/emulation/{sid}/status` transitions `pending → booting → ready` within 1800 s on a real kernel | command_passes |
| 1α | `grep -n 'timeout:' frontend/src/api/emulation.ts` — `startEmulation` has NO `timeout:` option OR uses the default 30 s (the POST is fast again) | source_check |
| 1α | `EmulationPage` terminal WebSocket connects successfully after the polling loop sees `status=ready` | visual_verify |
| 1β | `curl -sX POST http://localhost:8000/api/v1/projects/{pid}/fuzzing/campaigns/{cid}/start` returns `202` with campaign row `status=queued` | command_passes |
| 1β | Campaign `status=running` appears in DB within 120 s of start call | command_passes |
| 1β | `FuzzingPage` displays real-time status without frontend timing out | visual_verify |
| both | `docker compose exec backend /app/.venv/bin/python -m pytest tests/test_emulation*.py tests/test_fuzzing*.py` clean | command_passes |
| both | `grep -n 'asyncio.create_task' backend/app/routers/emulation.py backend/app/routers/fuzzing.py` — ≥ 1 hit per file | source_check |
| both | Rule #29 audit re-run: `grep -n 'firmae_timeout\|fuzzing_timeout_minutes' backend/` — both still present as the async ceiling, but no synchronous endpoint blocks on them | source_check |

## Risks

1. **WebSocket terminal at `routers/emulation.py:829-831`** — must not break when `/start` becomes async. The terminal connects AFTER `status=ready`; stream α MUST NOT race the terminal connect against the booting container.
2. **`fuzzing_service.py` is 1107 LOC** — Rule #27 split candidate. RESIST combining the 202+polling refactor with a split in the same session. Split separately (if at all) — see strategic-research candidate #5.
3. **arq worker vs. `asyncio.create_task` fallback** — firmware unpack uses arq when available (`routers/firmware.py:30`). Match that pattern — don't hard-code `asyncio.create_task` alone.
4. **Frontend route-guard drift** — `ProjectRouteGuard` may need to handle a `status=booting` state on navigation; check before shipping α.
5. **E2E test cover** — existing Playwright specs under `frontend/tests/e2e/` may assume synchronous `/start`. Audit + update specs in-stream.

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-04-19 | Queue as Fleet (2 streams), NOT /archon | Two truly-disjoint subsystems (emulation, fuzzing). No cross-stream dependencies. Fleet's wave mechanics are overkill — single wave of 2 parallel streams suffices. |
| 2026-04-19 | Do NOT combine with fuzzing_service split | Scope creep risk. Rule #27 discipline says structural splits ship independently of behaviour changes. |
| 2026-04-19 | Reuse existing status-enum on both sides | emulation_session.status and fuzzing_campaign.status already exist with ~4 values each. Adding a new `pending` or `booting` value is a trivial alembic migration; creating a separate jobs table is over-engineering. |
| 2026-04-19 | Do NOT ship until after a real system-mode boot is observed through the new flow | Rule #11 runtime smoke — import checks pass when a method references a missing constant. Full boot on a real image is the only trustworthy verification for this class of change. |

## Pickup

Session start: confirm `baseline HEAD: ea5f1c7` is still green (Rule #17 canary
+ backend-tests workflow passes). Create two worktrees:

```
git worktree add .worktrees/stream-alpha -b feat/stream-alpha-emulation-202-$(date +%Y-%m-%d)
git worktree add .worktrees/stream-beta  -b feat/stream-beta-fuzzing-202-$(date +%Y-%m-%d)
```

Dispatch two sub-agents, one per worktree, briefed with:
- This campaign file
- CLAUDE.md Rule #29 (timeout alignment + 202+polling guidance)
- CLAUDE.md Rule #23 (worktree discipline — MUST use the path, not just checkout)
- CLAUDE.md Rule #25 (one commit per sub-task, per-commit grep)
- `backend/app/routers/firmware.py:139` as the template

Merge order: α first (emulation terminal must still connect), then β.
Rule #8 rebuild after merge. End-condition audit before closing.
