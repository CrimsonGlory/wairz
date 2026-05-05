---
title: "Rate-limit coverage gap — only 2/156 endpoints have @limiter.limit(); expensive POSTs unguarded"
status: pending
priority: high
target: backend/app/routers/{security_audit,sbom,hardware_firmware,fuzzing,emulation}.py
---

## Description

Audit measured 2 of 156 endpoints carry `@limiter.limit()`. Specifically, the expensive long-op POSTs are unrate-limited:
- `POST /security/audit` (mobsfscan ~10 min)
- `POST /sbom/generate` (Ghidra-heavy)
- `POST /hardware-firmware/cve-match` (10 min)
- `POST /fuzzing/campaigns/{id}/start` (Docker spawn)
- `POST /emulation/start`, `POST /emulation/system` (Docker spawn)

One authenticated client looping these endpoints can DoS the backend (uvicorn workers blocked) and the worker pool (arq queue saturated). Even the existing in-memory state for emulation/fuzzing won't gracefully degrade — the system will simply queue indefinitely.

**Evidence:** Stream B (F-B-07). Width-canary on `@limiter.limit` returned 2 hits; broader `slowapi|RateLimit|Throttle` returned the same 2 + 1 import — no shadow-rate-limit framework.

## Acceptance Criteria

- [ ] Tier the POSTs by cost and apply per-tier rate limits via `slowapi`:
  - **Tier-A (10-min jobs):** `5/hour` per API key — `/security/audit`, `/sbom/generate`, `/hardware-firmware/cve-match`
  - **Tier-B (Docker spawn):** `20/hour` per API key — `/fuzzing/campaigns/{id}/start`, `/emulation/start`, `/emulation/system`
  - **Tier-C (general POSTs):** `100/hour` per API key — everything else not listed
  - Document the tier mapping in `backend/app/middleware/rate_limit.py` (new) or the existing limiter setup.
- [ ] 429 responses include `Retry-After` header.
- [ ] Tests: hit the limit on a tier-A endpoint 6 times; assert 6th returns 429 with Retry-After.
- [ ] Backend rebuild per Rule #8.

## Out of Scope

- Per-IP rate limiting in addition to per-API-key (relevant only for unauth endpoints; current threat model is authed clients).
- Cluster-wide rate limit via Redis-backed slowapi store (single-backend deployment is fine with in-memory; document the assumption).

## Cross-step

Single commit `feat(rate-limit): tier expensive POSTs per API key`. Per Rule #25 if the per-router placement is significant work, split into 2 commits (middleware + per-route decorators).

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-b-routers-2026-05-04.md` finding F-B-07.
