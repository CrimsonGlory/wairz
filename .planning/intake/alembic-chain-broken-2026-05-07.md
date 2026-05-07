---
title: "Repair broken alembic revision chain (5 dangling parents, 5 disconnected heads)"
status: pending
priority: high
target: backend/alembic/versions/
discovered: 2026-05-07
discovered_by: vuln-scan-timeout-fix session (Phase 2 blocker)
---

## Problem

`docker compose up -d --build frontend` triggered a recreate of the
`migrator` container, which exited 1 with `KeyError: '89007f64cfb0'`
during alembic graph construction. The migrator service is now blocking
backend startup via the `service_completed_successfully` dependency
in `docker-compose.yml`. Backend can be coaxed up via `--no-deps backend`,
but **alembic itself cannot enumerate the graph** — `alembic current`,
`alembic upgrade head`, and any new migration file all fail with the
same KeyError.

## Evidence

Production DB is stamped at `b0c1a2d3e4f5` (device_dump_sessions) — the
schema reflects every migration up through device dumps as having run
successfully at some point in history. The Python migration files,
however, contain a corrupt revision graph:

**5 dangling parents** (referenced by `down_revision` but no migration
file declares the matching `revision`):

```
89007f64cfb0  ← referenced by e3b1a4f97c5d_drop_emulation_sessions_pid
8da8627326d4  ← reference TBD
a3b4c5d6e7f8  ← reference TBD
b7d3f1a2c4e5  ← reference TBD
c2d3e4f5a6b7  ← reference TBD
```

**5 disconnected heads** (revisions with no descendants — alembic
expects exactly one head unless a `merge` revision exists):

```
81f49fd099f5  add_firmware_id_to_findings
b5c6d7e8f9a0  add_system_emulation_columns
c4d5e6f7a8b9  add_logs_to_emulation_sessions
d9b2e3f5a6c7  add_blob_id_to_sbom_vulnerabilities
e3b1a4f97c5d  drop_emulation_sessions_pid (also dangling-parented)
```

The current production head `b0c1a2d3e4f5` is itself reachable from
none of the actual ancestors, since `a8f3d2c1e9b4` (its parent) is
parented by `e3b1a4f97c5d` which is parented by the missing
`89007f64cfb0`.

## Suspected root cause

Commit `2fd0380` (May 5, "fix(models): drop dead emulation_sessions.pid
column") introduced `e3b1a4f97c5d_drop_emulation_sessions_pid.py` with
the comment "chained off `89007f64cfb0` (status-check-constraints head)"
— but the actual status-check-constraints migration is
`54c8864fbe0c_add_enum_check_constraints.py`. The author appears to have
hallucinated the revision id from memory rather than reading the
existing graph. Subsequent migrations (`a8f3d2c1e9b4`, `b0c1a2d3e4f5`)
chained off `e3b1a4f97c5d` and inherited the breakage.

The other dangling parents (8da8627326d4, a3b4c5d6e7f8, b7d3f1a2c4e5,
c2d3e4f5a6b7) likely have similar root causes — IDs invented rather
than referenced from existing files. Worth re-examining each of the 5
heads to see if any branches were meant to be merged via an
`alembic merge` revision that never landed.

## Proposed repair

Two-stage:

1. **Re-stitch the missing parents.** For each dangling parent, identify
   what migration it was MEANT to point to (likely an existing head at
   the time the broken migration was authored — `git log` around the
   commit that introduced the broken revision) and update the
   `down_revision` in-place. Specifically `e3b1a4f97c5d`'s
   `down_revision = "89007f64cfb0"` should become
   `down_revision = "54c8864fbe0c"` per the author's commit message
   intent.

2. **Add a `merge` revision** consolidating the 5 heads into one. Create
   `<new_id>_merge_post_audit_quick_wins.py` with `down_revision` as a
   tuple of all 5 heads. This becomes the new single head and lets
   future migrations chain cleanly.

After the repair, the production DB should already be in the merged
state schema-wise; verify and `alembic stamp` if any column is missing.
A migrator container restart should then `alembic upgrade head` cleanly
to the new merge revision.

## Why this is high priority

- **Blocks vuln-scan-timeout fix Phase 2** (this session). The Rule #33
  202+polling conversion needs a migration to add 4 columns +
  CHECK constraint to `firmware`. The migration cannot be applied while
  alembic is unusable.
- **Blocks every future migration**. No new alembic-driven schema work
  can ship until the graph is repaired.
- **Latent silent failure mode in CI/fresh deploys.** The
  `service_completed_successfully` migrator gate fails fresh installs
  immediately. Existing production DBs survive on stamped state but
  cannot evolve.

## Acceptance criteria

1. `docker compose exec migrator <wairz-migrator-1>` exits 0.
2. `alembic current` lists exactly one head.
3. `alembic upgrade head` is a no-op against the production DB
   (stamped state already matches).
4. A new test migration (`alembic revision -m "smoke"`) generates with
   a single resolved `down_revision`.
