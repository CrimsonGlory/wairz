---
title: "Repair broken alembic revision chain (1 dangling parent, single 1-line fix)"
status: resolved
priority: high
target: backend/alembic/versions/
discovered: 2026-05-07
resolved: 2026-05-07
discovered_by: vuln-scan-timeout-fix session (Phase 2 blocker)
resolved_by: deep-research session (post-investigation correction)
resolution_commit: TBD
---

## Resolution (2026-05-07)

**The original intake overstated the problem 5×.** Deep investigation showed:

- **1 dangling parent**, not 5. Only `e3b1a4f97c5d_drop_emulation_sessions_pid.py` had a broken `down_revision = "89007f64cfb0"` (no migration file defines that revision). Other suggested dangling parents (`8da8627326d4`, `a3b4c5d6e7f8`, `b7d3f1a2c4e5`, `c2d3e4f5a6b7`) ARE all valid revisions defined by their respective migration files.
- **Effective heads at the time of repair: 1**, not 5. `b0c1a2d3e4f5` is the single production-stamped head; `d8e9c4b5f7a2` was a transient sibling (the file added 2h before `e3b1a4f97c5d` and was the head AT AUTHORING TIME of the broken migration).
- **Corrected target was `d8e9c4b5f7a2`, not `54c8864fbe0c`.** The original intake suggested fixing `e3b1a4f97c5d.down_revision` to `54c8864fbe0c` based on the commit message's "(status-check-constraints head)" phrasing. Tracing the commit timeline shows the actual head when commit `2fd0380` was authored (2026-05-05 07:29:58) was `d8e9c4b5f7a2` (added 2h prior in commit `5d11c50`). Production DB schema confirms this linearization (firmware has `cve_match_status` from `e6f7a8b9c0d1`; fuzzing_campaigns CHECK includes 'queued' from `d8e9c4b5f7a2`; both are downstream of `54c8864fbe0c`). Setting `down_revision = "54c8864fbe0c"` would have created a fork at `54c8864fbe0c` requiring a separate `merge` revision; setting it to `d8e9c4b5f7a2` makes the chain linear with no merge needed.

**Fix:** 1-character change in 1 file:

```diff
-down_revision: Union[str, None] = "89007f64cfb0"
+down_revision: Union[str, None] = "d8e9c4b5f7a2"
```

**Verification (all 4 acceptance criteria met):**
- `alembic current` → `b0c1a2d3e4f5 (head)` ✓
- `alembic heads` → `b0c1a2d3e4f5 (head)` (single head, no merge required) ✓
- `alembic upgrade head` → no-op (stamp already matches) ✓
- `alembic revision -m "smoke"` → generated cleanly with ID `98dcf99aef46`, single resolved `down_revision` (deleted post-test) ✓

**Migrator container** still serves the pre-fix image (built before the edit) and will exit 0 after its next `--build` rebuild. The Phase 2 backend+worker rebuild (Rule #8) naturally rebakes the migrator image in the same compose-up cycle.

**Lesson** (filed for post-campaign knowledge extraction):

When an intake describes a problem in terms of a count ("5 dangling parents"), the count itself deserves Rule #19 evidence-first verification before scoping the repair. The original intake was authored mid-blocker by a panicking diagnostic — it conflated parse failures (regex too loose, picked up docstring text) with genuine graph corruption and ALSO conflated the chain-of-revisions topology (where downstream revs naturally have unique parents at authoring time but not after merges). A 30-second `comm -23 all_downs.txt all_revs.txt` against a clean grep ran the truth in seconds.

---

## Original Problem (preserved for record — see Resolution above for what was actually wrong)

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
