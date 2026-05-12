---
title: Operator paste-apply diff for `.env.example` and local `.env`
parent_intake: local-dev-env-no-auth-2026-05-12.md
status: operator-action-required
opened: 2026-05-12
---

# Operator paste-apply diff (`.env.example` + local `.env`)

Citadel `protect-files.js` + `external-action-gate.js` block AI from
reading or editing any path matching `.env*` — including `.env.example`.
This file documents the exact changes the operator should paste-apply
to close the 118-restart-cycle documentation gap.

The docs / code path (README.md + docs/getting-started/installation.md +
backend/app/main.py exit code 78) has already been updated by AI in
the same intake-closure commit set; only the two files below require
operator action.

## File 1 — `/home/dustin/code/wairz/.env.example`

Find the AUTHENTICATION block (search for `API_KEY=` or `WAIRZ_ALLOW_NO_AUTH=`).
**Replace it with**, or add **at the top of the file** if the block doesn't
yet exist:

```env
# ────────────────────────────────────────────────────────────────────────
# REQUIRED for the backend container to start
# ────────────────────────────────────────────────────────────────────────
# Set EXACTLY ONE of the following:
#   WAIRZ_ALLOW_NO_AUTH=true   ← recommended for local-only single-user dev
#   API_KEY=<your-secret>       ← production / multi-user / LAN-exposed
#
# If neither is set, the backend container will exit with code 78
# (EX_CONFIG) and docker compose ps will show `Restarting (78)`:
#   ERROR: api_key is required. Set API_KEY in .env or
#   WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.
#
# See docs/getting-started/installation.md "Required .env edits before
# first boot" for the full table of when to use each.
# ────────────────────────────────────────────────────────────────────────
WAIRZ_ALLOW_NO_AUTH=true
# API_KEY=

```

## File 2 — `/home/dustin/code/wairz/.env`

Add **one** of the following lines if NEITHER is already present:

```env
WAIRZ_ALLOW_NO_AUTH=true
```

— OR —

```env
API_KEY=<a-strong-random-key-from-openssl-rand-hex-32>
```

Then bring backend back up:

```bash
docker compose up -d backend
docker inspect wairz-backend-1 --format '{{.RestartCount}}'   # should stop climbing
docker compose ps backend                                      # should show "running"
docker compose logs --tail 5 backend                           # should NOT contain "ERROR: api_key"
```

## Verification

After the changes:

1. `docker inspect wairz-backend-1 --format '{{.RestartCount}}'` should
   stay constant (no longer climbing) — the count documented at session
   close was 118; resetting requires `docker compose down && up -d` if
   the operator wants a clean slate.
2. `curl -fsS http://localhost:8000/api/v1/health` returns `{"status":"healthy"}`.
3. The frontend (`http://localhost:3000`) loads without 401s.

## Origin

- Parent intake: `.planning/intake/local-dev-env-no-auth-2026-05-12.md`
- Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-eta-2026-05-11.md`
  "What Broke #8" + antipattern #8
- Backend code: `backend/app/main.py:68-76` (exit code refined 1 → 78 in this intake's commit set)
- AI-blocked due to: Citadel hooks `hooks_src/protect-files.js` +
  `hooks_src/external-action-gate.js` matching `.env*` patterns
