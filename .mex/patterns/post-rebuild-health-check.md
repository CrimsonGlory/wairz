---
name: post-rebuild-health-check
description: After any Rule #8 backend+worker+migrator rebuild, probe the backend container's restart count BEFORE trusting the rebuild — `docker compose ps` "Up" status is not sufficient because a config-exit-loop renders as Restarting with rising count. Catches the local-dev-env-no-auth-2026-05-12 failure mode (backend restart-looped 118 times across sessions because the worker stayed healthy and only the backend container ran the lifespan auth check).
triggers:
  - "rebuild"
  - "docker compose up -d --build backend"
  - "RestartCount"
  - "restart loop"
  - "wairz-backend-1 Restarting"
  - "exit 78"
  - "EX_CONFIG"
edges:
  - target: context/conventions.md
    condition: for the Rule #8 (rebuild backend+worker+migrator together) text
  - target: patterns/docker-rebuild-backend-worker.md
    condition: when issuing the rebuild command itself
  - target: patterns/rule-41-must-complete-ci.md
    condition: when CI verification is the next step (separate concern, but adjacent in the verification chain)
last_updated: 2026-05-12
---

# Post-rebuild health check

## Context

CLAUDE.md Rule #8 says rebuild `backend worker migrator` together
after any Python / dependency / migration change. The rebuild emits
`up -d` output that LOOKS successful — containers are created,
postgres + redis come up, the migrator (rightly) exits 0.

But success at `docker compose up -d` time is NOT the same as
backend-actually-running. The backend container runs a lifespan auth
check at `app/main.py:68-76` that exits **78** (`EX_CONFIG`) if neither
`API_KEY` nor `WAIRZ_ALLOW_NO_AUTH=true` is set in `.env`. Docker
restarts the container, fails again, restarts, fails again — a
restart loop. The worker does NOT run this check and stays "Up
(healthy)" so the standard health-of-stack signal (worker uptime,
test suite green) is preserved. The backend can restart-loop
indefinitely without any other surface fail.

Session-close 2026-05-12 documented `wairz-backend-1` at
**`{{.RestartCount}}` = 118** — the issue had persisted across 5+
sessions because every rebuild was confirmed by "containers up" /
"worker healthy" / "tier-1 tests pass" without probing the backend's
restart count.

This pattern is the discipline that closes that loop.

## Steps

After any `docker compose up -d --build backend worker migrator`
invocation (Rule #8), and BEFORE declaring rebuild success:

```bash
# 1. Probe restart count — should NOT be climbing.
docker inspect wairz-backend-1 --format '{{.RestartCount}}'

# 2. Sanity-check ps state — should say "Up <N>s", not "Restarting".
docker compose ps backend

# 3. Tail logs — should NOT contain "ERROR: api_key" or any line
#    followed by a Python traceback.
docker compose logs --tail 20 backend

# 4. Health endpoint — should return 200.
curl -fsS http://localhost:8000/api/v1/health
```

If step 1 returns a non-zero number AND that number is climbing
across two probes a few seconds apart, the container is in a
restart loop. The most likely cause is exit code 78 (EX_CONFIG —
auth misconfig). Re-read the logs from step 3 and apply the operator
diff at `.planning/intake/local-dev-env-no-auth-2026-05-12-OPERATOR-DIFF.md`.

If step 4 fails with `Connection refused`, the container is not yet
listening — give it ~10s for uvicorn to bind, then retry. If still
refused, return to step 3 and inspect the full log.

## Verify

The rebuild is genuinely complete when ALL of:

- `docker inspect wairz-backend-1 --format '{{.RestartCount}}'` is
  stable across two probes 10s apart.
- `docker compose ps backend` shows `Up <N>s` (not `Restarting`).
- `curl -fsS http://localhost:8000/api/v1/health` returns `{"status":"healthy"}`.
- `docker compose logs --tail 20 backend` shows the normal
  `Uvicorn running on http://0.0.0.0:8000` boot line and no traceback.

Optional but recommended: also probe `wairz-worker-1` and the
`wairz-migrator-1` exit code:

```bash
docker compose ps worker
docker inspect wairz-migrator-1 --format '{{.State.ExitCode}}'  # should be 0
```

## Anti-patterns

1. **Trusting "containers up" output from `docker compose up -d`.**
   That output reports the CREATE-AND-START phase, not the
   STAYS-RUNNING phase. A container that creates successfully then
   exits 78 a second later is still reported as "started" in the
   compose-up output.

2. **Trusting worker health as a proxy for backend health.** The
   worker does not run the lifespan auth check. A healthy worker
   with a restart-looping backend is a real and frequent local-dev
   state.

3. **Skipping the `RestartCount` probe because tier-1 tests pass.**
   Tier-1 tests run against the HOST `.venv`, not the container.
   They cannot detect the backend container's runtime state. (See
   CLAUDE.md "Required Validation Commands" — tier-1 unit tests
   verify code correctness; health probes verify deploy correctness.
   Both are required after Rule #8 rebuilds.)

4. **Mistaking `wairz-backend-1 Restarting (78) <N>s ago` for a
   transient retry.** Docker's default restart policy keeps the
   container alive indefinitely; the `(78)` IS the exit code, not a
   countdown. If the count keeps climbing, the loop is persistent.

5. **Reading exit code as "unknown error" because the message is
   `Restarting (78) <N>s ago`.** Exit 78 is `EX_CONFIG` per
   `/usr/include/sysexits.h` ("configuration error"). This is a
   distinct, semantically-typed exit — not a generic crash.

## Debug

**`docker inspect` returns the wrong container name**

Compose names the container `<project>-backend-1` based on the
project name (directory). Verify with `docker compose ps --format
'table {{.Service}}\t{{.Name}}\t{{.Status}}'` or use
`docker compose ps -q backend | head -1 | xargs docker inspect ...`.

**Health endpoint returns 401 instead of 200**

The backend started successfully BUT auth is enforced and the curl
didn't include the API key. Either set `WAIRZ_ALLOW_NO_AUTH=true`
for local dev (and re-up) or send the key: `curl -H 'X-API-Key:
<value>' http://localhost:8000/api/v1/health`.

**RestartCount stays 0 but ps shows "Exited (78)"**

The compose `restart:` policy is set to `no` (or unset). Set it to
`unless-stopped` in docker-compose.yml for development, then
re-up. Or interpret `Exited (78)` as a one-shot fail rather than a
loop — same root cause (auth misconfig), same fix.

## Companion CLAUDE.md rules

- Rule #8 (rebuild backend+worker+migrator together) — what to do
  BEFORE this check.
- Rule #20 (docker cp + alembic vs rebuild — class-shape changes
  still need restart) — when the post-rebuild check applies vs when
  fast-iteration suffices.
- Rule #19 (evidence-first) — the RestartCount probe is the
  evidence; "Up <N>s" without the probe is intent, not truth.

## Origin

Promoted 2026-05-12 from the 118-restart-cycle incident
documented at `.planning/intake/local-dev-env-no-auth-2026-05-12.md`
("Why it stayed silent for 118 cycles" section). Recipe authored
in-band with the intake's doc/code closure.
