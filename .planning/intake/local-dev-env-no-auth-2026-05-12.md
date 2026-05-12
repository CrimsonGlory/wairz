---
intake_id: local-dev-env-no-auth-2026-05-12
title: Local-dev .env must set WAIRZ_ALLOW_NO_AUTH=true OR API_KEY=<value> — backend lifespan check has been silently blocking rebuilds for 118 restart cycles
status: open
opened: 2026-05-12
parent_postmortem: .planning/postmortems/postmortem-windows-coverage-godmode-eta-2026-05-11.md (continuation closure What Broke #8 + antipattern #8)
priority: low-to-medium (doesn't block development; surfaces only on rebuild + only on the backend container; worker stays healthy regardless)
estimated_effort: 30-60 min (doc-only changes + .env.example update + a single integration test against lifespan startup)
---

# Local-dev .env requires WAIRZ_ALLOW_NO_AUTH=true OR API_KEY=<value>

## Symptom

After any Rule #8 `docker compose up -d --build backend worker migrator` rebuild, the backend container enters a restart loop. `docker compose ps` shows `wairz-backend-1 Restarting (3) <Ns> ago`. `docker compose logs backend` reveals:

```
ERROR: api_key is required. Set API_KEY in .env or WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.
```

`docker inspect wairz-backend-1 --format '{{.RestartCount}}'` reported **118** at the 2026-05-12 closure of Phase η — meaning the issue has persisted across many sessions and many rebuild attempts.

## Why it stayed silent for 118 cycles

- Worker container does NOT run the same lifespan check; worker remains `Up <X> hours (healthy)` while backend restart-loops.
- Per-session tier-1 tests run against host `.venv` (not container) per the validated cadence — so test pass/fail signal doesn't surface the failing container.
- Per-session Rule #11 import smoke has targeted the WORKER container (which is healthy) rather than the BACKEND (which is the one that exposes the check). Multiple sessions' postmortems show "Rule #11 import smoke OK" while the backend was silently restart-looping.

## Root cause

`/home/dustin/code/wairz/.env` (1557 bytes, dated 2026-04-19) does NOT contain either `API_KEY=<value>` OR `WAIRZ_ALLOW_NO_AUTH=true`. The Citadel `external-action-gate.js` hook blocks AI agents from reading `.env` directly (secrets), so the issue has been invisible to the orchestrators that would otherwise notice and prompt the operator to add the missing line.

`app/main.py:68-74` is the enforcing check:

```python
if not settings.api_key and not settings.allow_no_auth:
    print(
        "ERROR: api_key is required. Set API_KEY in .env or "
        "WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.",
        file=sys.stderr,
    )
    sys.exit(1)
```

The check is CORRECT — it prevents production deployments from accidentally running without auth — but the dev-host `.env` requires operator action that hasn't happened.

## Scope (this intake)

**In scope:**

1. Update `/home/dustin/code/wairz/.env.example` to make the `WAIRZ_ALLOW_NO_AUTH=true` line MORE OBVIOUS for local-only dev (current state: the file may or may not document this — verify). Add a leading comment block:

   ```
   # ── REQUIRED for local-only single-user deployments ──────────────────
   # Set EXACTLY ONE of the following:
   #   WAIRZ_ALLOW_NO_AUTH=true   ← recommended for local development
   #   API_KEY=<your-secret>       ← production / multi-user deployments
   #
   # If neither is set, the backend container exits 1 at startup with:
   #   "ERROR: api_key is required. Set API_KEY in .env or
   #    WAIRZ_ALLOW_NO_AUTH=true for local-only deployments."
   # ─────────────────────────────────────────────────────────────────────
   WAIRZ_ALLOW_NO_AUTH=true
   # API_KEY=
   ```

2. Add a `docs/dev-setup.md` checklist OR extend the existing `README.md` "Getting Started" section to surface the requirement BEFORE the first `docker compose up -d` invocation.

3. Optional: improve the error message in `app/main.py:68-74` to include a more distinctive exit code (e.g. `sys.exit(78)` — `EX_CONFIG` from `/usr/include/sysexits.h` — so `docker compose ps` failures can be programmatically distinguished from other startup errors).

4. Optional: add a `.mex/patterns/post-rebuild-health-check.md` recipe that says "after Rule #8 rebuild, run `docker inspect wairz-backend-1 --format '{{.RestartCount}}'` and flag suspiciously-high counts (e.g. ≥5) as a session-end recommendation."

5. Optional: add a `.claude/harness.json` `qualityRules.custom` entry that fires on Archon's post-rebuild verification if the backend container is in a restart loop — surfaces the issue to subsequent sessions without requiring AI to read `.env`.

**Out of scope:**

- Backend code change to the lifespan check itself — the check is correct.
- Modifying `.env` directly (Citadel external-action-gate.js blocks AI from touching it; operator action).
- Any production-deployment auth changes.

## Acceptance

- `.env.example` makes the `WAIRZ_ALLOW_NO_AUTH=true` requirement obvious (or `API_KEY=<value>`) for local dev.
- `docs/dev-setup.md` (or equivalent) has a "First-time setup" checklist that includes the `.env` requirement.
- Operator can rebuild backend cleanly after following the checklist.
- Optional: `.mex/patterns/post-rebuild-health-check.md` exists with the `docker inspect ... RestartCount` discipline.

## References

- Postmortem `What Broke #8`: `.planning/postmortems/postmortem-windows-coverage-godmode-eta-2026-05-11.md`
- Antipattern #8: `.planning/knowledge/windows-coverage-godmode-eta-2026-05-11-antipatterns.md`
- Backend lifespan check: `backend/app/main.py:68-74`
- CLAUDE.md Rule #8 (backend rebuild discipline)
- Citadel external-action-gate.js: blocks AI from reading `.env`
