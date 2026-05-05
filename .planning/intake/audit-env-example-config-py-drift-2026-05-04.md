---
title: ".env.example ↔ config.py 22-field drift — incl. allow_no_auth security flag + STORAGE_ROOT mismatch + FIRMAE_DB_PASSWORD dead config"
status: blocked
priority: high
target: .env.example + backend/app/config.py + docker-compose.yml + emulation/scripts/start-system-mode.sh
---

## BLOCKED — autopilot 2026-05-05

`.env.example` is protected by Citadel's `external-action-gate.js`
hook — every read/write is blocked as a "secrets access" event. The
hook is correct (it can't distinguish `.env` from `.env.example` by
filename pattern alone). Closing this intake requires either:
(a) operator-driven session that bypasses the hook for the example
file, or
(b) modifying the hook's regex to whitelist `.env.example` (and any
other `.env.*.example` paths).

Resuming this intake requires picking either path. Marked
`status: blocked` rather than left as `pending` so autopilot scans
correctly skip it.

## Description

Stream H measured **22 settings present in `backend/app/config.py` but missing from `.env.example`**, including the `allow_no_auth` security flag (an operator with bad defaults can ship an unauthenticated backend). Other notable drifts:

- **`STORAGE_ROOT` value mismatch** between `config.py` default and `.env.example` for non-Docker dev workflows.
- **`FIRMAE_DB_PASSWORD` dead config trap** (Stream H F-H-15): required by `docker-compose.yml` for the system-emulation service but never read by the entrypoint script — the actual DB password is the constant `firmadyne` hardcoded in `firmadyne/firmadyne` superuser config. Operators who change `FIRMAE_DB_PASSWORD` get silent "auth failed" with no indication that the var has no effect.
- Entire emulation block missing from `.env.example` (operator can't tune emulation timeouts without hunting through code).

**Evidence:** Stream H (F-H-05, F-H-15).

## Acceptance Criteria

- [ ] `.env.example` adds the 22 missing settings with sensible defaults and inline comments documenting each.
- [ ] **CRITICAL — `allow_no_auth`:** ship default `false` with a comment block explicitly warning that setting `true` removes the API-key gate. If wairz has any "demo mode" path that needs `true`, document the threat model inline.
- [ ] **`STORAGE_ROOT`:** unify the value across `config.py`, `.env.example`, and the developer setup docs. Pick the Docker-friendly default; document the override for non-Docker.
- [ ] **`FIRMAE_DB_PASSWORD`:** either (a) plumb it into the entrypoint script so it ACTUALLY sets the firmadyne user's password OR (b) remove it from `docker-compose.yml` and document that the DB password is fixed. (a) is preferred for operator hygiene.
- [ ] CI gate: a pytest test that diffs `config.py` `Settings` field names against `.env.example` keys, fails on divergence.
- [ ] Backend rebuild per Rule #8 (Settings is `@lru_cache`'d — Rule #20 class-shape, restart-after-cp insufficient if Settings adds fields).

## Out of Scope

- Migrating to a typed env-loader library (e.g. `pydantic-settings` SecretStr for sensitive fields) — current pydantic-settings already handles validation; the gap is documentation, not implementation.

## Cross-step

Per Rule #25, ship in 3 commits: `.env.example` sync / FIRMAE_DB_PASSWORD wire-up or removal / CI gate.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-h-infra-2026-05-04.md` findings F-H-05, F-H-15.
