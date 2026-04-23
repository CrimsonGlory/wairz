---
title: "Next-session seed — 202+polling fleet, then CI-unblock fleet (deep-researched)"
status: proposed
priority: high
format: ouroboros-seed-v1
author: session-5321d5a1-research-fleet
created: 2026-04-20T00:00:00Z
target_session: next
baseline_head: 5d75bca  # campaign: flip 202+polling queued→ready after pre-flight Rule-19 audit
previous_seed: seed-next-session-2026-04-19.md (option-a-completed 2026-04-18)
research_method: 4-scout parallel Explore fleet (ROI scan, CI triage, 202+polling readiness, Ouroboros fit)
---

# Next-session seed — post-intake-sweep continuation (deep-researched)

> Read order for the incoming Citadel session:
>   1. This file (proposed scope + scout findings)
>   2. `.planning/campaigns/emulation-fuzzing-202-polling.md` (ready to dispatch)
>   3. `.planning/intake/backend-pytest-unstable-tests.md` (triage-front-loaded)
>   4. User confirms → `/fleet`

## Summary — 4 scouts agree

- **Pick the 202+polling campaign next**, not a random intake. Campaign is
  `status: ready` as of baseline `5d75bca` (pre-flight Rule #19 audits both
  closed no-op: ProjectRouteGuard has no status filter; E2E specs don't
  invoke the start endpoints).
- **Then pick up `backend-pytest-unstable-tests`**, but re-measure first —
  scout B found the intake's `test_cache_module.py` diagnosis is imprecise;
  failures appear to be real product bugs (commit-vs-flush discipline per
  Rule #3), not test bugs.
- **Ouroboros stays dormant** — scout D confirmed no current backlog item
  genuinely needs Socratic interview / evolutionary loop. Every queued item
  has a tight spec. Memory preference unchanged.
- **Anti-picks:** `feature-latte-llm-taint-analysis` already shipped
  (session 435cb5c2); `device-acquisition-v2` blocked on hardware.

---

## Session plan — 3 sessions deep

### Session +1 (next) — `/fleet` 202+polling campaign (1 session, 2 streams)

**Orchestrator:** `citadel:fleet` — 2 parallel streams in isolated
worktrees per Rule #23. Prompts MUST include
`git worktree add .worktrees/stream-{name} -b feat/stream-{name}-2026-04-20`
verbatim.

**Stream α — emulation** (higher risk, merge first)
- Files: `backend/app/routers/emulation.py`, `backend/app/services/emulation/service.py`,
  `frontend/src/api/emulation.ts`, `frontend/src/pages/EmulationPage.tsx`
- Convert `POST /emulation/start` to return 202 immediately with `status="starting"`,
  dispatch Docker spawn via `_get_arq_pool()` fallback to `asyncio.create_task`
  (template: `backend/app/routers/firmware.py:139`).
- **Terminal-WS race mitigation:** `starting → running` transition must gate
  on a container health-check (ping socat socket, verify shell responsive) —
  NOT on spawn-completion. The WebSocket at `routers/emulation.py:829-831`
  already checks `status != "running"` before accepting, so the health-check
  gate prevents a racing terminal connect.
- Frontend polling infrastructure already exists at `EmulationPage.tsx:167`
  (5s setInterval + SSE). Just change the POST handler from blocking-complete
  to 202-with-initial-state; existing polling refreshes the terminal state.
- Acceptance: `curl -X POST /api/v1/projects/{id}/emulation/start` → HTTP 202
  within 1s regardless of container spawn time; status endpoint transitions
  `starting → running` only after shell health-check; terminal connect after
  polling reports `running` succeeds first try.

**Stream β — fuzzing** (lower risk, merge second)
- Files: `backend/app/routers/fuzzing.py`, `backend/app/services/fuzzing_service.py`,
  `frontend/src/api/fuzzing.ts`, `frontend/src/pages/FuzzingPage.tsx`
- Convert `POST /fuzzing/campaigns/{id}/start` to return 202 with `status="running"`
  (enum transition `created → running` per
  `alembic/versions/54c8864f... add_enum_check_constraints.py` line 66), dispatch
  AFL++ container.run() via background task.
- No terminal race (fuzzing has no WS terminal).
- Frontend polling exists at `FuzzingPage.tsx:102` (10s setInterval + SSE
  fallback).
- Acceptance: `curl -X POST /api/v1/projects/{id}/fuzzing/campaigns/{id}/start`
  → HTTP 202 within 1s; `GET /fuzzing/campaigns/{id}` transitions through
  status states correctly; crashes still get collected.

**Shared deliverable — timeout alignment post-merge**
- Remove deferred-misalignment rows from CLAUDE.md Rule #29 (the "emulation
  user-mode" and "fuzzing campaign" DEFERRED entries).
- Add Rule #29 mirror update in `.mex/context/conventions.md` Verify Checklist
  (Rule #21 co-update discipline).
- No new axios timeout constants needed — 30s default suffices for POST now
  that it's 202.

**Stream disjointness (Rule #23):**
| Stream | Backend files | Frontend files |
|---|---|---|
| α | `routers/emulation.py`, `services/emulation/*` | `api/emulation.ts`, `pages/EmulationPage.tsx` |
| β | `routers/fuzzing.py`, `services/fuzzing_service.py` | `api/fuzzing.ts`, `pages/FuzzingPage.tsx` |
| shared (read-only) | `config.py`, `models/emulation_session.py`, `models/fuzzing.py` |

No write conflicts. Safe parallel.

**Estimated time:** 4-5 hours end-to-end, fleet-parallelizable to 2-3 hours
wall-clock. Single session.

---

### Session +2 — `/fleet` backend-pytest-unstable-tests (3 streams, 2-3 sessions total) — **COMPLETED 2026-04-23** (single session)

**Status:** +1+2-completed. Merged SHAs: α 01182fc · β 50d1bc1 · γ c53800c · rename 2fae870.
Fleet session: `.planning/fleet/session-backend-pytest-unstable-2026-04-23.md`.
Intake moved to `.planning/intake/resolved/backend-pytest-unstable-tests.md`.



**Pre-flight (do first in session +2, before dispatch):**

1. **Rule #19 re-measure of `test_cache_module.py`.** Intake claims 2 failures
   are test-bug patterns (MagicMock auto-attr, UUID-str SQL rendering). Scout B
   found both tests are structurally correct — failures likely indicate the
   service-under-test is calling `db.commit()` when it should `db.flush()`
   (CLAUDE.md Rule #3 violation). If confirmed, this is a product bug, not a
   test bug — the fix lives in the service, and the test gets to stay as-is.
2. **Fixture audit for MobSF baselines.** Scout B identified
   `tests/fixtures/mobsf_baselines/` as a blocker risk — if baseline JSON
   files were generated against a now-outdated `ManifestFinding` schema, the
   entire Android cluster (5 files) fails before triage begins. Verify:
   ```
   docker compose exec -T backend /app/.venv/bin/python -c "
   from app.schemas.findings import ManifestFinding
   import json, pathlib
   for f in pathlib.Path('tests/fixtures/mobsf_baselines').glob('*.json'):
       data = json.loads(f.read_text())
       # compare data[0].keys() vs ManifestFinding field names
       print(f.name, set(data[0].keys()) if data else 'empty')
   "
   ```
3. **Canary frontend typecheck** (Rule #17 + #24):
   `echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force); rm frontend/src/__canary.ts`

**Stream α — Android/MobSF cluster** (5 files, ~55 failures estimated)
- `test_mobsf_baseline_comparison.py`, `test_mobsf_parity.py`,
  `test_diva_manifest_scan.py`, `test_ovaa_manifest.py`,
  `test_false_positive_rate.py`
- Domain: manifest scanning against vulnerable APKs (DIVA, InsecureBank, OVAA);
  baseline parity + false-positive rate assertions.
- Common failure class: stale fixture JSON + patch targets for the service
  split (many MobSF checks moved during Phase 5 refactor).
- Commit cadence: one file per commit per Rule #25; final commit removes
  the 5 `--ignore=` lines from `.github/workflows/backend-tests.yml`.

**Stream β — Hardware/Firmware cluster** (5 files, ~68 failures estimated)
- `test_hardware_firmware_classifier_patterns.py`,
  `test_hardware_firmware_parsers.py`,
  `test_hardware_firmware_router.py`,
  `test_bytecode_analysis.py`, `test_synthetic_apk_fixtures.py`
- Domain: firmware format detection, parser registry, bytecode pattern
  matching, router endpoints, synthetic APK mocks.
- Likely bugs: parser registry completeness, vendor pattern YAML loads.
- Preserve `test_symlink_to_outside_is_rejected` contract (security Rule #1).

**Stream γ — Data/Schema + Emulation-auth cluster** (5 files, ~66 failures)
- `test_cache_module.py` (real product bug per pre-flight —
  service-level fix),
- `test_fp_rate_computation.py`, `test_scan_harness.py`,
  `test_zip_bomb_prevention.py`, `test_emulation_auth.py`
- Commit shape: cache-module is likely 1 code fix + 0 test changes; others
  per-file.

**Acceptance (session-wide):**
- `grep -c '\-\-ignore=' .github/workflows/backend-tests.yml` → 0
- `docker compose exec backend /app/.venv/bin/python -m pytest tests/ --tb=no -q` → 0 failures
- Workflow job name changes from `"Pytest (Backend, Stable Subset)"` to
  `"Pytest (Backend)"`.

**Estimated time:** 3 sessions (5.5-8 hours total), fleet-parallelizable
to 2 sessions if all three streams land in one day.

---

### Session +3 (and +4 if pytest spills) — follow-up intake drain — **COMPLETED 2026-04-23** (verified, not executed)

**Status:** +3-completed. Rule #19 verification at session 0801ca27 close confirmed all recommended
intakes had already landed via unrelated work: cache-module-extraction-and-ttl (`cleanup_older_than`
in worker), frontend-firmware-hook-dedup (`useFirmwareList.ts`), data-pagination-list-endpoints
(`schemas/pagination.py`), data-constraints-and-backpop, infra-cleanup-migration-and-observability,
security-docker-socket-proxy — all marked completed + artifacts verified. No dispatch needed.

See `.planning/intake/seed-next-session-2026-04-24.md` for next-session continuation options.

After the two big campaigns, the remaining high-leverage intakes:

| Intake | Leverage | Complexity | Ready? |
|---|---|---|---|
| `backend-cache-module-extraction-and-ttl` | unblocks 2 downstream refactors | 1 session | ready |
| `data-pagination-list-endpoints` | frontend hook-dedup unblocks this | 1 session | ready |
| `frontend-firmware-hook-dedup` | 10 callers (grep confirms 10 not 9 per intake) | 1 session | ready |
| `data-constraints-and-backpop` | schema hygiene | 1 session | re-measure first (Rule #19) |
| `infra-cleanup-migration-and-observability` | compose / quotas | 1-2 sessions | ready |
| `security-docker-socket-proxy` | narrow host access surface | 1-2 sessions | ready |

**Suggested order:** `backend-cache-module-extraction-and-ttl` →
`frontend-firmware-hook-dedup` → `data-pagination-list-endpoints`
(cache and pagination enable several later intakes; frontend dedup is
small + fast).

**Do NOT pick up without re-measuring (Rule #19):**
- `data-schema-drift-findings-firmware-cra` — count the actual drift
  rows first; may be a no-op.
- `feature-android-hardware-firmware-detection` — flag says completed
  2026-04-19 per scout D; skip unless user explicitly re-confirms scope.

**Ouroboros trigger (deferred):** when a greenfield feature with genuine
discovery risk enters the intake (e.g. "ML-based malware classifier",
"automated exploit synthesis from crash reproducers"), route through
`/ouroboros:interview` → `/ouroboros:seed` → `/citadel:archon` hybrid.
Until then, Citadel autopilot/fleet/archon handles every queued item.

---

## Verification gates (apply to every session)

Per CLAUDE.md discipline:

**Before any dispatch:**
- [ ] Rule #17 canary: `tsc -b --force` on a known-bad canary file.
  Expect FAIL before trusting a later PASS.
- [ ] Rule #24: use `npx tsc -b --force`, never `tsc --noEmit`.
- [ ] Rule #19: re-measure any intake count that guides scope.

**In each fleet stream prompt:**
- [ ] `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-YYYY-MM-DD`
      followed by `cd .worktrees/stream-{name}` before ANY file write.
      Symlink `frontend/node_modules` from main checkout to avoid 2 GB
      reinstall. (Rule #23)
- [ ] Per-commit discipline: one sub-task per commit (Rule #25).
      Class-shape rebuild (Rule #8) runs ONCE at stream end, not per commit.

**At session close:**
- [ ] `docker compose up -d --build backend worker` (Rule #8) + full
      pytest via `/app/.venv/bin/python -m pytest`.
- [ ] Frontend rebuild if `frontend/src/**` touched
      (Rule #26: `docker compose up -d --build frontend`, not restart).
- [ ] Rule #21: if any rule graduates, mirror into
      `.mex/context/conventions.md` in the same commit.

---

## Scout telemetry

4 Explore-agent scouts dispatched 2026-04-20 session 5321d5a1:

| Scout | Angle | Verdict |
|---|---|---|
| ROI scan | Which intake next? | 202+polling campaign > backend-pytest > cache-module extraction |
| CI triage | `backend-pytest-unstable-tests` deep-read | 3-stream fleet viable; cache_module diagnosis is wrong; MobSF fixtures are the only blocker risk |
| 202+polling readiness | Is the campaign ready? | Yes — both audits clean (doc'd in campaign file at `5d75bca`); 1 prep commit landed |
| Ouroboros fit | When should Ouroboros run? | Not for any current backlog; memory preference confirmed |

## First action for the next session

```text
1. Read this file.
2. Read .planning/campaigns/emulation-fuzzing-202-polling.md in full
   (it has the stream-level task decomposition, DB migration plan,
   and merge order).
3. Ask user:
     (a) "Dispatch /fleet 202+polling now? [y/n]"
     (b) "After 202+polling: pytest-unstable-tests or intake drain? [p/i]"
4. Route:
     y → /fleet with the 2 stream prompts from the campaign file
         (copy verbatim; ensure worktree command in each prompt)
     p → after +1 completes, /fleet pytest-unstable-tests with the
         3 cluster prompts from this seed
     i → /autopilot walk the intake drain order above
5. End-of-session: update this seed's "status" to
   "+1-completed" / "+1+2-completed" etc. + link the merged SHAs.
```

## Risk + rollback

- 202+polling campaign is additive (new status transitions + background
  dispatch); rollback by reverting the two merge commits.
- pytest-unstable-tests: each file-commit is independent; `git revert` per
  file if any fix turns out wrong.
- Baseline rollback: `5d75bca` (this seed's baseline) is the durable
  pre-dispatch state.
- DPCS10 canary (260 blobs, 27 hw-firmware CVEs) remains the live-verify
  gate after each session close.
