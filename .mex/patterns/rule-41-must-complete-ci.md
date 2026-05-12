---
name: rule-41-must-complete-ci
description: Pick the right Rule #41 must-complete mitigation mechanism for a new or existing CI workflow — per-commit duplicate, nightly cron, or accept-the-gap — based on the workflow's cost profile and trigger surface.
triggers:
  - "Rule #41"
  - "must-complete"
  - "cancel-in-progress"
  - "concurrency-cancel"
  - "ci masking"
  - "F823"
  - "boundary commit"
edges:
  - target: context/conventions.md
    condition: for the Rule #40 (F823) and Rule #41 (concurrency-cancel masking) text
  - target: patterns/docker-rebuild-backend-worker.md
    condition: when the new workflow involves docker compose build + container exec patterns
last_updated: 2026-05-12
---

# Rule #41 Must-Complete CI Mitigation — Mechanism Selection

## Context

CLAUDE.md Rule #41 documents the threat: GitHub Actions
`concurrency.cancel-in-progress: true` saves runner minutes during
sustained per-piece-cadence pushes (Pattern P5) but DELAYS defect
detection at boundary commits, because each intermediate CI run is
cancelled by the next push.  The async-cleanup-2026-05-11 campaign
discovered a Rule #40 F823 bug in `emulation.py:2627` that had sat
in main for weeks because every prior Lint run had been
concurrency-cancelled within 1-3 seconds.

The mitigation is a "must-complete" sibling job — a parallel job that
runs IDENTICAL coverage to the cancellable job but under its own
per-commit-sha concurrency group with `cancel-in-progress: false`,
so each commit's run completes regardless of subsequent push cadence.

This pattern doc captures the DECISION TREE: which mechanism for which
workflow's cost profile.  CLAUDE.md Rule #41 says WHY; this doc says
WHICH MECHANISM and WHEN.

## Decision Tree

```
Does the workflow have a `push` trigger to main?
├── NO → mechanism (d) ACCEPT-THE-GAP
│        (PR-only workflows have no main-branch latency surface)
│
└── YES → How long is one run end-to-end?
          ├── ≤2 min  → mechanism (a) PER-COMMIT MUST-COMPLETE DUPLICATE
          │             (cheap; fast feedback; close every commit boundary)
          │
          └── >2 min  → mechanism (b) NIGHTLY CRON + DISPATCH
                        (per-commit cost too high; <24h latency acceptable
                         for the defect class — tests / integration / etc.)
```

**Avoid mechanism (c) time-bucketed concurrency.**  GitHub Actions
evaluates the `concurrency.group` key at workflow-start time from
`github.*` context only — there's no `${{ schedule.bucket }}` or
`${{ format('YYYY-MM-DD-HH', now()) }}` primitive.  Concurrency runs
BEFORE any job step that could mint a bucket key, so time-bucketing
isn't statically expressible.  Every attempt collapses to (a) (every
commit unique → no bucketing) or (b) (manual cron).  Drop it.

## Mechanism (a) — Per-commit must-complete duplicate

**Use when:** workflow is push-triggered AND one run is ≤2 min (e.g.
lint, fast typecheck, static analysis).

**Shape:** add a NEW job to the same workflow file with identical
coverage steps and a job-level concurrency override:

```yaml
  <job-name>-must-complete:
    name: <Job> must-complete (Rule #41)
    runs-on: ubuntu-latest
    timeout-minutes: 10
    concurrency:
      group: <job-name>-must-complete-${{ github.ref }}-${{ github.sha }}
      cancel-in-progress: false

    steps:
      # ... mirror of the cancellable sibling's steps ...
```

The `${{ github.sha }}` in the group key ensures each commit gets its
OWN group — no two commit-runs can share a group, so none can cancel
another.  `cancel-in-progress: false` is belt-and-suspenders.

The cancellable sibling job is UNCHANGED — it still provides fast
feedback under the workflow-level `cancel-in-progress: true`.  The new
job is the slow safety net.  When the cancellable sibling shows
`cancelled` (GitHub Actions renders this as a red-X identical to
`failure`), treat THIS job's conclusion as authoritative.

**Worked examples in wairz:**
- `lint.yml` `lint-backend-must-complete` (commit `fae88ad`, 2026-05-12)
- `lint.yml` `typecheck-frontend-must-complete` (commit `20f1cc0`, 2026-05-12) — added after 517d613 revealed the typecheck-frontend surface was vulnerable to the same masking.

**Cost:** ~$0.001 per push (1 min runner × $0.008/min commercial; free
for public repos).  Across a 60-commit campaign: ~$0.06.  Negligible.

## Mechanism (b) — Nightly cron + workflow_dispatch

**Use when:** workflow is push-triggered AND one run is >2 min (e.g.
integration tests, docker-build + pytest, e2e).

**Shape:** add `schedule:` to triggers, add `if:` filters that route
push/PR runs to the cancellable job and schedule/dispatch runs to a
new must-complete job:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
    paths: [ ... ]
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * *'    # 06:00 UTC daily — Rule #41 must-complete

jobs:
  <fast-job>:
    name: <Fast Job> (Rule #41: push/PR-only)
    if: github.event_name == 'push' || github.event_name == 'pull_request'
    # ... existing steps unchanged ...

  <fast-job>-must-complete:
    name: <Fast Job> must-complete (Rule #41, nightly)
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    timeout-minutes: 45
    concurrency:
      group: <fast-job>-must-complete-${{ github.run_id }}
      cancel-in-progress: false
    steps:
      # ... mirror of the fast job's steps ...
      # Consider removing --maxfail / fail-fast flags so the nightly
      # surfaces EVERY regression rather than stopping at the Nth.
```

Trigger routing after this shape:
- push / PR → fast cancellable job only
- schedule (nightly) → must-complete only
- workflow_dispatch → must-complete (manual on-demand uncancellable)

**Worked example in wairz:**
- `backend-tests.yml` `pytest-must-complete` (commit `d8a075b`, 2026-05-12) — pytest job is ~8-10 min per run; per-commit must-complete would cost ~$15-20/day commercial vs ~$0.07/day for nightly.

**Cost:** ~$0.07/day (1 nightly run × ~10 min × $0.008/min commercial).
~$2/month.  Sustainable.

**Latency:** ≤24 hours from regression introduction to surfacing.
Acceptable for the defect class (integration / test regressions are
typically less time-sensitive than syntactic-lint regressions like
F823 which need ~1-commit latency).

**Empirical validation status (as of 2026-05-12T00:52Z):** PENDING.
The first scheduled `pytest-must-complete` cron run fires
**2026-05-13 06:00 UTC** (~29h from this writeup).  After that fire
window passes, run:

```bash
gh run list --workflow=backend-tests.yml --limit 10 --json \
  event,conclusion,createdAt,headSha \
  | jq '.[] | select(.event=="schedule")'
```

Outcomes:
- `conclusion: "success"` → declare mechanism (b) validated; replace
  this section with the observed run-id + a final empirical-cost note.
- `conclusion: "failure"` AND failure precedes the pytest step (setup
  fail, missing secret, env mismatch) → tune the setup steps in
  `.github/workflows/backend-tests.yml` to match the `pytest` job's
  setup exactly (mirror env vars, postgres init, redis init, uv lock
  cadence).  Then re-trigger via `gh workflow run backend-tests.yml`
  and re-verify.
- `conclusion: "failure"` AND failure is in pytest itself → real test
  regression introduced between commit `d8a075b` and now.  Triage as a
  normal red-test debugging task; mechanism (b) is working as intended.

## Mechanism (d) — Accept-the-gap (document, don't mitigate)

**Use when:** workflow is PR-only (no push trigger).  The Rule #41
main-branch masking risk does not apply — PR runs can be cancelled by
a force-push within the SAME PR, but the worst case is "re-run the PR
check," not "latent defect rides into main."

**Shape:** add a docs comment near the existing `concurrency:` block:

```yaml
# CLAUDE.md Rule #41 note: this workflow is PR-only (no `push` trigger),
# so workflow-level `cancel-in-progress: true` does NOT expose the main-
# branch masking risk.  If a future change adds a `push` trigger, add a
# must-complete sibling per the mechanism (a) or (b) recipe in
# `.mex/patterns/rule-41-must-complete-ci.md` depending on run cost.
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

**Worked example in wairz:**
- `e2e-tests.yml` (commit `d8a075b`, 2026-05-12) — PR-only + workflow_dispatch.

**Cost:** zero.

## Verify

After adding a must-complete sibling (mechanism a or b):

1. Push a small change (e.g. a comment in the workflow file).  Within
   30 seconds, push a SECOND small change.
2. Check `gh run list --repo <repo> --workflow=<file>.yml --limit 4`:
   - The cancellable sibling on commit 1 should be `cancelled`.
   - The must-complete sibling on commit 1 should be `completed: success`.
3. Drill into the must-complete sibling's run via `gh run view <id>`
   and confirm every step's `conclusion: success`.

If the must-complete sibling ALSO shows `cancelled`, the concurrency
override didn't take.  Most likely cause: missing `${{ github.sha }}`
in the group key (two commits share a group).  Re-read the YAML.

## Anti-patterns

1. **Mechanism (a) on a >5-min job** — runner cost escalates fast
   (~$0.04 × 25 commits/day × 30 days = $30/month per workflow).  Use
   mechanism (b) instead.

2. **Sharing a composite action between cancellable + must-complete
   siblings to "reduce duplication"** — the must-complete sibling's
   safety property (latent-defect-detection guarantee) must hold
   under EVERY invocation path.  A shared composite action centralises
   the steps but introduces an indirection that future refactors might
   silently break.  Duplicate the steps verbatim; keep each
   must-complete job standalone-auditable.

3. **`concurrency.group: <static-string>` (no `${{ github.sha }}`)** —
   all commits share one group; the must-complete is no better than
   the cancellable.  Always include sha (mechanism a) or run_id
   (mechanism b).

4. **Time-bucketed concurrency keys (mechanism c)** — GitHub Actions
   evaluates concurrency before any step can mint a bucket key; the
   pattern doesn't compose.  Don't go down this rabbit hole.

5. **Treating `cancelled` and `failure` as different alert levels in
   CI dashboards** — the GitHub UI renders both with a red X.  The
   must-complete sibling exists precisely BECAUSE `cancelled` is
   structurally indistinguishable from "didn't get a chance to fail."

## Debug

**Must-complete sibling never appears in the run history**

Most likely: the `if:` clause is wrong.  Re-read.  For mechanism (a)
there should be NO `if:` (the job runs on every trigger).  For
mechanism (b) the `if:` should match exactly the trigger event you
want it to fire on.

**Must-complete sibling appears but its conclusion is `skipped`**

The `if:` clause evaluated false on this trigger.  Check the trigger
event via `gh run view <id>` — does it match what the `if:` expects?

**Must-complete sibling appears but its conclusion is `cancelled`**

The job-level concurrency override didn't take.  Possible causes:
- Group key missing `${{ github.sha }}` or `${{ github.run_id }}`,
  causing multiple runs to share a group.
- Workflow-level concurrency block is doing something the job-level
  block can't override (rare; usually job-level wins).
- The `concurrency` block has a typo and YAML parses but GHA silently
  ignores it.  Validate via `python3 -c "import yaml; print(yaml.safe_load(open('FILE')))"`.

## Companion CLAUDE.md rules

- Rule #25 (per-sub-task commits) — ship the must-complete extension
  as its own commit, not bundled with unrelated work.
- Rule #40 (function-local imports MUST sit at top of function body) —
  the canonical defect class that Rule #41 mitigation surfaces.
- Rule #17 (silent-CLI-exit canary) — a `cancelled` CI conclusion is
  the CI-side analog of the silent-exit pattern.
