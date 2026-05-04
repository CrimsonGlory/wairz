---
title: "Quick Wins Bundle (30 min each, high payoff)"
status: completed
closed_at: 2026-04-19
closed_in: session 480666ce — Q4 shipped as commit a7bfe47
original_partial_at: 2026-04-18
original_partial_in: session 59045370 autopilot wave-2
shipped: Q1-Q17 (all 17 items)
Q4_final: |
  Commit a7bfe47 refactor(ghidra_service): drop GhidraAnalysisCache singleton.
  Intake's original premise ("get_analysis_cache returns a stateless wrapper")
  was incorrect — the class held real concurrency state (_analysis_locks dict +
  asyncio.Lock) guarding "one Ghidra run per binary SHA." Refactor re-homed the
  state to module scope with lazy-constructed lock (avoids module-import-time
  event-loop issue), and migrated 22 call sites across 5 files (binary.py,
  comparison.py, taint_llm.py, routers/analysis.py, comparison_service.py).
  Rule #8 rebuild + Rule #11 smoke passed; 172/172 MCP tools still register.
priority: medium
target: multiple
---

## Problem

Small, high-value fixes that don't individually warrant an intake item but together materially improve the codebase. Group them into one PR done in a single session.

## The List

### Backend

**Q1. Remove bare `Exception` from tuple `except` in sbom_service**
- File: `backend/app/services/sbom_service.py:645`
- Change: `except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):` → `except (subprocess.TimeoutExpired, json.JSONDecodeError):`
- Rationale: bare `Exception` in the tuple swallows every error; the explicit types are what we want

**Q2. Add debug logging to silent PURL fallback**
- File: `backend/app/services/sbom_service.py:577`
- Change: Add `logger.debug("PackageURL construction failed for %s: %s", name, exc, exc_info=True)` before the fallback `return f"pkg:{pkg_type}/{name}@{version}"`
- Rationale: silent fallback hides malformed-data patterns

**Q3. Add debug logging to SONAME parse failures**
- File: `backend/app/services/sbom_service.py:1783`
- Similar: add `logger.debug(...)` before returning None

**Q4. Drop `_analysis_cache` module-level singleton in ghidra_service**
- File: `backend/app/services/ghidra_service.py:695`
- `get_analysis_cache()` returns a stateless wrapper; export the functions directly instead
- After `backend-cache-module-extraction-and-ttl.md` lands, this becomes straightforward

**Q5. Remove duplicate `entrypoint:` in docker-compose.dev.yml**
- File: `docker-compose.dev.yml:14` (dead override at line 14, overridden at line 20)
- Delete line 14

**Q6. Remove `env_file: .env` from frontend service**
- File: `docker-compose.yml:253`
- Frontend is static nginx; doesn't need backend secrets at runtime (also addressed in `infra-secrets-and-auth-defaults.md`, but minimal enough to do here if that hasn't landed)

**Q7. Delete stub `claude-triage.yml`**
- File: `.github/workflows/claude-triage.yml`
- Currently just echoes a message — misleading telemetry
- Delete or replace with real content

**Q8. Pin vulhunt to a digest instead of :latest**
- File: `docker-compose.yml:206`
- Change: `image: ghcr.io/vulhunt-re/vulhunt:latest` → `image: ghcr.io/vulhunt-re/vulhunt@sha256:<digest>` (look up current digest)

**Q9. Exclude tests/ from backend/.dockerignore**
- File: `backend/.dockerignore`
- Add: `tests/`, `alembic/versions/__pycache__`, `*.log`
- Reduces image size + avoids shipping test fixtures (APK files) into production

**Q10. Add concurrency guards to CI workflows**
- Files: `.github/workflows/lint.yml`, `.github/workflows/e2e-tests.yml`
- Add:
  ```yaml
  concurrency:
    group: ${{ github.workflow }}-${{ github.ref }}
    cancel-in-progress: true
  ```

**Q11. Remove unused `/` from middleware EXEMPT_PATHS**
- File: `backend/app/middleware/auth.py:18`
- No handler registered for `/` — cosmetic cleanup

### Frontend

**Q12. Replace `useVulnerabilityStore()` with selector in SbomPage**
- File: `frontend/src/pages/SbomPage.tsx:77`
- Change: `const vulnStore = useVulnerabilityStore()` → individual selectors:
  ```typescript
  const vulns = useVulnerabilityStore((s) => s.vulnerabilities)
  const updateVuln = useVulnerabilityStore((s) => s.update)
  // etc
  ```
- Payoff: eliminates full-page re-renders on every store field change

**Q13. Move STATUS_VARIANT into statusConfig.ts**
- File: `frontend/src/pages/ProjectDetailPage.tsx:25`
- Move the `STATUS_VARIANT` map into `frontend/src/constants/statusConfig.ts` alongside existing maps
- Rationale: unifies CLAUDE.md rule #9 enforcement — one grep to find all exhaustive Record maps

**Q14. Fix hard-coded `/api/v1/...` in SecurityScanPage VulHunt EventSource**
- File: `frontend/src/pages/SecurityScanPage.tsx:129`
- Change: `new EventSource(\`/api/v1/projects/${projectId}/events?types=vulhunt\`)` → use `apiUrl()` helper (defined in `frontend-api-client-hardening.md`) or inline `${API_BASE}`
- If that intake hasn't landed, inline the prefix:
  ```typescript
  const API_BASE = import.meta.env.VITE_API_URL || ''
  new EventSource(`${API_BASE}/api/v1/projects/${projectId}/events?types=vulhunt`)
  ```

**Q15. Add EventSource double-click guard in handleVulhunt**
- File: `frontend/src/pages/SecurityScanPage.tsx` `handleVulhunt`
- Add at top:
  ```typescript
  if (vulhuntEventSourceRef.current) return  // already running
  ```

**Q16. Remove import React pollution**
- File: `frontend/src/pages/SbomPage.tsx:114`
- Change: `const ref = React.useRef(...)` → `import { useRef } from 'react'; const ref = useRef(...)`
- Small consistency win

### Data

**Q17. Fix remaining `Record<string, unknown>` in device types**
- File: `frontend/src/types/device.ts:26, 50`
- `Record<string, any>` → proper typed interfaces
- Addressed more thoroughly in `frontend-store-isolation-and-types.md`; do here if that hasn't landed

## Files (all the files above)

Combined touch: ~15 files across backend, frontend, CI configs.

## Acceptance Criteria

- [ ] Each item has been committed (one commit per logical group is fine)
- [ ] `npx tsc --noEmit` in frontend passes
- [ ] `docker compose config` validates
- [ ] `docker compose up -d --build backend worker frontend` starts clean
- [ ] Existing E2E tests still pass

## Risks

- The CLAUDE.md rule #1 rebuild cycle applies — rebuild backend and worker after any backend change
- Removing `env_file: .env` from frontend may break something that was undocumented — verify `docker compose config frontend` env list before/after
- Pinning vulhunt to digest means you must manually update the pin periodically; document in README

## Rollback

- Each change is a separate commit; `git revert` any individual one
- No DB changes, no destructive ops

## References

- Synthesized from all 5 architecture reviews — the "Quick Wins" sections of each
