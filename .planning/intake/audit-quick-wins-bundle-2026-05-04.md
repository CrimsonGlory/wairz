---
title: "Audit quick-wins bundle 2026-05-04 — 14 medium/low items"
status: in-progress
priority: medium
target: (multiple files; see per-item)
---

## Progress — autopilot 2026-05-05

| Item | Status | Note |
|---|---|---|
| M-1 | ✅ shipped | Created `frontend/src/api/timeouts.ts` canonical module; eliminated 9 redeclarations across 8 API files. Typecheck clean. |
| M-5 | ⊘ skipped | Audit contradiction: Stream G F-G-05 says "remove (no-op)"; audit-summary.md counter-finding says refresh-after-flush is load-bearing for `onupdate=func.now()`. Verified Finding model line 50: `updated_at` uses `onupdate=func.now()` — refresh is required. Per Rule #19 evidence-first, the production refresh and test assertion are correct as-is. |
| M-7 | ✅ already shipped | Commit b7250c7 (recent) — skip reason now points to `test_diva_manifest_scan.py` and `test_insecurebankv2_manifest.py` (existing files), no longer references nonexistent `test_manifest_checks_signing.py`. |
| M-14 | ✅ shipped 2026-05-05 | docker-compose.yml clamav healthcheck `["CMD", "clamdcheck"]` → `["CMD", "clamdscan", "--ping=1"]`. `clamdcheck` (no .sh) is not on PATH in clamav/clamav:latest; `clamdscan --ping=1` (clamav ≥0.103) actually pings clamd over the socket and exits non-zero on unresponsive daemon, which is a stronger liveness check than the audit-recommended `--version` (binary-exists only). YAML validated via `docker compose --profile clamav config`. |
| M-2..M-4, M-6, M-8..M-13 | pending | Pick up opportunistically. |

## Description

Bundle of 14 medium/low-severity items from the 2026-05-04 codebase audit. Each is a small fix that doesn't justify a full intake but is worth picking up opportunistically. Order is loose; pick whichever fits the current session.

## Items

### M-1. Frontend SECURITY_SCAN_TIMEOUT consolidation (Rule #29)
- **Source:** Stream F F-F-04
- **Scope:** Consolidate the value `600_000` redeclared in 9 files / 12 sites to a single canonical `frontend/src/api/timeouts.ts` import.
- **Why:** Drift risk — backend `_PIPELINE_BUDGET_SECONDS` change won't propagate.

### M-2. Frontend silent error swallowing (Rule #22 follow-up)
- **Source:** Stream E F-E-09/F-E-10/F-E-11
- **Scope:** `FindingsPage.tsx:59,83,97`, `SbomPage.tsx:135,159,198`, `FirmwareMetadataCard.tsx:29`, `BinaryTabs.tsx:72`, `ComparisonPage.tsx:91` — add `extractErrorMessage` + toast.
- **Why:** 422/4xx-other failures invisible to the user.

### M-3. Virtualized lists migrate magic `calc(100vh - Npx)` to `useRef + ResizeObserver`
- **Source:** Stream E F-E-03/F-E-04
- **Scope:** Highest-risk site is `SbomPage.tsx:1204` (bare `calc(100vh - 420px)`, no `min(cap, …)` ceiling). 7 other sites less urgent.
- **Why:** Pattern broke FindingsList in the recent layout pass; SbomPage is the next regression candidate.

### M-4. Inline BaseModel sprawl — move 19 inline classes to `app/schemas/` (Rule #12)
- **Source:** Stream B F-B-02
- **Why:** Project convention; forward-reference issues.

### M-5. Test asserts Rule #32 anti-pattern
- **Source:** Stream G F-G-05
- **Scope:** `backend/tests/test_finding_service.py:253` — remove `assert_awaited_once()` on `db.refresh`. Codifies a no-op given `expire_on_commit=False`.

### M-6. Yara test mutates `@lru_cache` get_settings (Rule #20 risk)
- **Source:** Stream G F-G-06
- **Scope:** `backend/tests/test_yara_service.py:34-36` — patch the Settings instance correctly OR clear the cache between tests.

### M-7. Skip refs nonexistent file
- **Source:** Stream G F-G-12
- **Scope:** `backend/tests/test_mobsf_parity.py:1104` skip references `test_manifest_checks_signing.py` which does not exist. Either create the file (if the skip is gating real coverage) or remove the skip and the comment.

### M-8. Worker + vulhunt no healthcheck
- **Source:** Stream H F-H-04
- **Why:** Both can hang silently; healthcheck would surface to compose `unless-stopped` policy.

### M-9. CORS over-permissive
- **Source:** Stream B F-B-10
- **Why:** Default to localhost-only; ALLOWED_ORIGINS env var for production.

### M-10. Backend root entrypoint + Frontend nginx as root
- **Source:** Stream H F-H-01, F-H-02
- **Why:** Container privilege; switch to non-root user in both Dockerfiles. Rule out file-permission regressions on the firmware data volume.

### M-11. datetime.utcnow() drift (9 call sites + 12 ORM columns naive/aware mix)
- **Source:** Stream C F-C-03
- **Scope:** `datetime.utcnow()` is deprecated in py3.12+, breaks in py3.13. Migrate to `datetime.now(timezone.utc)` for call sites; ORM columns to `DateTime(timezone=True)` + `server_default=func.now()`.

### M-12. port_forwards/discovered_services type drift (dict typed, list written)
- **Source:** Stream C F-C-07
- **Scope:** ORM `Mapped[dict | None]` vs runtime `list[dict]` — fix the type annotation and the consumer access patterns.

### M-13. EmulationSession dead columns (`pid`, `kernel_used`)
- **Source:** Stream C F-C-08
- **Scope:** Read-only never-written columns. Either drop via migration OR plumb the writes if the columns SHOULD be populated.

### M-14. broken `clamdcheck` healthcheck on `clamav:latest`
- **Source:** Stream H F-H-08
- **Scope:** healthcheck command `clamdcheck` is not present in the `clamav:latest` image; replace with `clamdscan --version` or pin to a known-good image tag.

## Acceptance Criteria

- [ ] Each item completed has a dedicated commit per Rule #25 ("medium" doesn't mean "bundle into one big commit").
- [ ] Each commit references this intake file's M-N anchor in the commit body.
- [ ] On completion, mark this intake `status: completed` in the frontmatter and move to `.planning/intake/resolved/`.

## Cross-step

This is a pick-up-as-you-go bundle. Autopilot picks one item per session; archon can sweep multiple if a session has spare context.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery files across all 9 streams (citations per item).
