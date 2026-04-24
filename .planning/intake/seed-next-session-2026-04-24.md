---
title: "Next-session seed — post-pytest-unblock, P3-circular-imports carve-out or queue-empty maintenance"
status: "+C-completed +A-completed (session 5eefecb0, 2026-04-24) +A-prime-completed (session f2f9060c, 2026-04-24: fuzzing_service + emulation/ pair)"
priority: medium
format: citadel-seed-v1
author: session-0801ca27-fleet+learn
created: 2026-04-23T22:30:00Z
target_session: next
baseline_head: d5f2734  # campaign: close backend-pytest-unstable-tests — 15 files un-ignored, full CI green
previous_seed: seed-next-session-2026-04-20.md (+1+2+3 all completed 2026-04-23)
research_method: /learn extraction from fleet session backend-pytest-unstable-2026-04-23
---

# Next-session seed — post-pytest-unblock

> Read order for the incoming Citadel session:
>   1. This file (context + carve-out options)
>   2. `.planning/fleet/session-backend-pytest-unstable-2026-04-23.md` (what just shipped)
>   3. `.planning/knowledge/backend-pytest-unstable-2026-04-23-{patterns,antipatterns}.md` (freshly extracted)
>   4. `.planning/intake/backend-private-api-and-circular-imports.md` (the remaining partial)

## Summary — intake queue is genuinely empty

Post-Session +1 (202+polling fleet), +2 (pytest-unblock fleet), +3 (intake drain)
the pending queue is drained. Rule #19 verification at session 0801ca27 close:

| Intake | Claim | Verified |
|---|---|---|
| backend-cache-module-extraction-and-ttl | completed | ✓ `cleanup_older_than` in worker (`backend/app/workers/arq_worker.py:715`) |
| frontend-firmware-hook-dedup | completed | ✓ `frontend/src/hooks/useFirmwareList.ts` present |
| data-pagination-list-endpoints | completed | ✓ `backend/app/schemas/pagination.py` present |
| backend-private-api-and-circular-imports | partial | ✓ P1 (0 `_scan_*` refs in assessment_service); P2 (0 emulation_service imports in kernel_service); P3 deferred |

No pending intake is eligible for autopilot. Ouroboros stays dormant (no
greenfield feature with discovery risk in backlog).

## Option matrix for the next session

### Option A — carve out the P3 circular-imports sub-problem (RECOMMENDED if you want to keep moving)

The partial intake's Phase 3 is open-ended (37 function-local imports across
13 services). Per the intake's OWN guidance, "cap the scope to specific service
pairs per PR, not 'all of them'." Pick ONE cycle pair and ship a single-session
fix:

**Best candidates (by cycle density × fix clarity):**
| Pair | Function-local imports | Likely shared extract point | Scope |
|---|---|---|---|
| `security_audit_service` ↔ `assessment_service` | 9 + 5 = 14 | existing `security_audit_service.run_scan_subset` | Medium — add 3-5 more scanners to SCANNERS dict; update assessment_service callers |
| `emulation_service` ↔ `fuzzing_service` | 6 + 4 = 10 | new `emulation_constants` symbol? | Medium — may need to extract shared interfaces |
| `assessment_service` ↔ `mobsfscan_service` | 9 + ? | mobsfscan already has `mobsfscan/` subpackage post-Phase 5 | Small — might just be imports that predate the split |

Route: `/marshal backend-private-api-p3-carveout-{pair-slug}` with a scoped prompt
covering ONE pair only. Success = all function-local imports in that pair
promoted to top-level + tests still green.

### Option B — new intake from operational pressure (RECOMMENDED if a real problem has surfaced)

Intake queue is empty, which means the next work item should come from USER
context (something broke, something felt slow, something was painful). Do NOT
manufacture work. Ask the user what's painful; write a new intake; then process.

### Option C — write knowledge-promotion candidates into CLAUDE.md / .mex (maintenance)

`/learn` just extracted 7 successful patterns + 6 anti-patterns + 3 new harness
rules from the pytest-unblock fleet. Some are worth promoting from
`.planning/knowledge/` into durable docs:

- **Promote to CLAUDE.md Rule #30 (candidate):** "For mock patches targeting
  third-party symbols lazy-imported inside service function bodies, patch the
  SOURCE module, not the service module." Evidence: 3 streams found 8+ stale
  patches across α/β/γ. Harness rule
  `auto-pytest-mock-patch-androguard-at-service` catches the narrow case.
- **Promote to `.mex/context/conventions.md` Verify Checklist:** "After a fleet
  session, verify `git diff --name-only` for each stream is disjoint from other
  streams' scope (zero cross-sweeps). Rule #23 evidence-matrix line:
  — 5 of 6 consecutive fleet successes under explicit `git worktree add` discipline."
- **Candidate for CLAUDE.md note (NOT a rule):** "Backend container has no
  bind mount — tests enter the container via `docker cp`. For test-only iteration
  use the 5s docker-cp + exec pattern (Rule #20); for service-code changes,
  rebuild at stream end (Rule #8)." Currently only documented in the session
  files.

Route: one-off edits in a single session; ~30 min total. Low excitement but
high longevity — these rules encode genuine project truths.

### Option D — architecture-review-2026-04-16 re-scan

`.planning/intake/architecture-review-2026-04-16.md` is marked `reference` (not
actionable as-is) but may contain sub-items that have newly become actionable
after 1-2 weeks of shipping. Re-scan before assuming it's dead. Skip if nothing
new surfaces.

## First action for the next session

```text
1. Read this file.
2. Read .planning/knowledge/backend-pytest-unstable-2026-04-23-{patterns,antipatterns}.md
3. Ask user:
     (a) "Intake queue is empty. Four routes: A carve out P3 circular imports
          (1 service pair), B wait for new operational pressure, C promote
          freshly-extracted knowledge to CLAUDE.md/.mex, D re-scan the
          architecture-review intake. Which? [a/b/c/d/n=none]"
4. Route:
     a → ask WHICH pair; /marshal with scoped prompt
     b → reply "OK — flag when a pain surfaces"; end session
     c → /marshal "promote learn findings to CLAUDE.md + .mex/context/conventions.md"
     d → /research on .planning/intake/architecture-review-2026-04-16.md for newly-actionable items
     n → end session cleanly
5. End-of-session: update this seed's "status" to "+A-completed" / "+C-completed" etc.
```

## Baseline + rollback

Baseline `d5f2734` (this seed's baseline) is the durable pre-P3 state. Any
Option A carve-out creates per-service-pair commits that `git revert` per
commit. Option C is pure doc edits — `git revert` the single commit.

## Risk

- **Temptation to fabricate work:** intake queue being empty is a GOOD state.
  Resist inventing campaigns "because autopilot ran dry." Maintenance options
  (C) are legitimate; manufactured features are not.
- **Option A scope creep:** the P3 intake explicitly warns "can grow — cap
  scope to specific service pairs per PR, not 'all of them'." If a candidate
  pair has more imports than anticipated mid-session, STOP after that pair —
  don't chain into a second pair in the same session.

## Scout telemetry

None for this seed — `/learn` + user-intent drove creation, not parallel Explore
scouts. Session 0801ca27 did the whole CI-unblock fleet (15 test files → 0
`--ignore=`) and then wrote this seed as the natural handoff.
