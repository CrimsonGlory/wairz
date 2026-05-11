---
title: "Wairz Master Plan (historical reference)"
status: reference
type: reference
priority: low
---

> **Status note 2026-04-21 (Rule-19 audit):** Retyped `status: reference` so the
> `/do` intake scanner stops listing this as actionable work. This is a
> historical planning/context document, not a task-list intake. Current campaign
> pickup lives in `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`; per-task
> intakes live as siblings of this file.
>
> **DO NOT use the item lists in this file as actionable intake selection.**
> Verify EACH named item against current code / alembic / closed campaigns
> BEFORE proposing it as work — see Rule #19 (evidence-first) and Rule #31
> (broaden the grep when narrow returns 0).  Spot-checks performed
> 2026-05-12 found roughly half the listed items already shipped without
> updates to this file:
>
> - `data-analysis-cache-operation-varchar-fix` — DONE in alembic
>   `1f6c72decc84_widen_analysis_cache_operation_to_512.py`; model is
>   `String(512)` at `backend/app/models/analysis_cache.py:26`.
> - `alembic-chain-broken` — DONE; intake at
>   `.planning/intake/alembic-chain-broken-2026-05-07.md` is
>   status:resolved.
> - `security-fuzzing-shell-injection` — appears closed (no `shell=True`
>   matches in `fuzzing_service.py` 2026-05-12); needs deeper grep before
>   re-queueing as actionable.
> - `backend-cwe-checker-session-fix` — no commit/flush violations match
>   the Rule #3 anti-pattern on 2026-05-12; likely closed.
>
> For actionable work, scan `.planning/intake/*.md` for `status: pending`
> entries directly; pick the freshest by `discovered` date.

# Wairz Master Plan

> Created: 2026-04-01
> Last refresh: 2026-04-18 (session 53c9c5ff — DPCS10 extraction fix + HW firmware usability + /learn re-runs)
> Resume with: read `.planning/intake/seed-next-session-2026-04-19.md` first

---

## ⚠ For the next session

**Primary pickup file:** `.planning/intake/seed-next-session-2026-04-19.md`

That seed has three scope options (short / medium / large) with verifiable
end-conditions and Citadel orchestrator hints.  The sections below are
historical context, not current state.

**Session handoff:** `.planning/knowledge/handoff-2026-04-18-session-end.md`
captures what just shipped, open threads, and system state as of
2026-04-18 22:06.

---

## Session 53c9c5ff recap (2026-04-18)

What shipped:

1. **DPCS10 extraction bomb fix** — user-data partition skip + super.img raw
   cleanup + bomb-check reorder.  77/77 tests, 3 CLAUDE.md rule updates.
2. **Detection-roots container promotion** — latent 24h-old regression from
   the extraction-integrity campaign fixed; DPCS10 recovered 246 → 260 blobs.
3. **Hardware Firmware page overhaul via citadel:autopilot** — 13 items across
   P0/P1/P2 tiers + blob download endpoint with realpath sandbox.
4. **Knowledge base updates** — CLAUDE.md rules 17 + 18, Monitor preset
   cheat-sheet, 1 harness quality rule adopted (was pending since 4/17).
5. **4× `/learn` re-runs** — captured 24h-later deltas including legacy
   null-tier CVE rows, phase-integration regression discipline, the
   "pending-rule drift" meta-pattern.

What's uncommitted: 27 files, +3478/-407 lines, all on branch `clean-history`.

---

## Remaining high-level roadmap (session-agnostic)

Categories and representative items, not ranked within each:

### Security (4 items)
- `security-auth-hardening`
- `security-fuzzing-shell-injection`  (double-shell-injection in fuzzing service)
- `security-android-unpack-hardening` (OTA + ZIP extraction paths)
- `security-docker-socket-proxy`       (narrow host access)

### Data / schema (4 items)
- `data-analysis-cache-operation-varchar-fix` (rule 15 — VARCHAR 100 → 512)
- `data-schema-drift-findings-firmware-cra`
- `data-constraints-and-backpop`
- `data-pagination-list-endpoints`
- **Legacy null-tier CVE backfill** (new — surfaced 2026-04-18, not yet queued as its own intake file)

### Backend architecture (3 items)
- `backend-service-decomposition`          (god-class refactor)
- `backend-private-api-and-circular-imports`
- `backend-cwe-checker-session-fix`
- `backend-cache-module-extraction-and-ttl`

### Frontend (3 items)
- `frontend-api-client-hardening`      (auth, API_BASE, bulk ops)
- `frontend-code-splitting-and-virtualization`
- `frontend-firmware-hook-dedup`       (useFirmwareList — 9 duplicate fetches)
- `frontend-store-isolation-and-types`

### Feature growth (2 items)
- `feature-android-hardware-firmware-detection`  (Modem/TEE/Wi-Fi/GPU/DSP/Drivers)
- `feature-latte-llm-taint-analysis`             (two MCP tools)
- `apk-scan-deep-linking`

### Infrastructure (3 items)
- `infra-secrets-and-auth-defaults`
- `infra-cleanup-migration-and-observability`
- `infra-volumes-quotas-and-backup`

### Meta / bundle
- `quick-wins-bundle`  (30 min each, high payoff — overlaps with
  options A subset above)

---

## Confirmed completed campaigns (do NOT re-queue)

- feature-extraction-integrity (5 phases + post-merge follow-up in this session)
- feature-hw-firmware-phase2-enrichment
- feature-hw-firmware-usability-overhaul (this session's autopilot run)
- feature-classifier-patterns-mcu-kernel
- feature-android-hardware-firmware-detection (PARTIAL — deeper expansion queued)

## Hardware-blocked

- Device Acquisition v2 Phase 10 — needs physical MediaTek device in BROM mode.

---

## Project health (as of 2026-04-18 22:06)

| Metric | State |
|---|---|
| Backend / worker / frontend | all healthy |
| Uncommitted change set | 27 files, +3478/-407 |
| Backend affected-suite pytest | 77/77 ✓ |
| Frontend tsc -b | clean (canaried) |
| DB: DPCS10 blob count | 260 (26 hw-firmware CVEs surfaced) |
| Harness quality rules | 15 custom + 2 built-in |
| CLAUDE.md learned rules | 18 (rules 17 + 18 added this session) |
| Open intake items | ~24 pending + new seed |

## Resume protocol

```
1. Read .planning/knowledge/handoff-2026-04-18-session-end.md
2. Read .planning/intake/seed-next-session-2026-04-19.md
3. Ask user which scope option (A / B / C)
4. Route:
     A → /autopilot  (per-item)
     B → /archon     (security-hardening campaign)
     C → /archon     (feature expansion campaign)
5. Before any builds — canary tsc per CLAUDE.md rule 17
6. After every edit — rule 8: rebuild backend + worker together
```
