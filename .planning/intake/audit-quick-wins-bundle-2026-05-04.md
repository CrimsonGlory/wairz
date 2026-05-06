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
| M-6 | ✅ shipped 2026-05-05 | `test_yara_service.py::test_raises_on_empty_rules_dir` rewritten to use `monkeypatch.setenv("YARA_FORGE_DIR", ...)` + `get_settings.cache_clear()` (in try/finally), eliminating the Rule #20 anti-pattern of mutating the cached singleton via `setattr`. Verified the env override + cache_clear path produces the expected `ValueError` via direct Python (backend image doesn't ship pytest). Commit 79281b8. |
| M-7 | ✅ already shipped | Commit b7250c7 (recent) — skip reason now points to `test_diva_manifest_scan.py` and `test_insecurebankv2_manifest.py` (existing files), no longer references nonexistent `test_manifest_checks_signing.py`. |
| M-9 | ✅ shipped 2026-05-05 | `backend/app/main.py` CORS narrowed: `allow_methods=["GET","POST","PATCH","PUT","DELETE"]` (matches the only verbs used in routers — grep'd `@router\.(get\|post\|patch\|put\|delete)`), `allow_headers=["Content-Type","X-API-Key"]` (matches the only custom headers the frontend sends; Starlette auto-adds Accept/Accept-Language/Content-Language). Verified preflight against the running backend returns 200 with the narrowed lists. Default origin remains localhost-only (`["http://localhost:3000","http://127.0.0.1:3000"]`); `cors_origins` env var still overrides for prod. Commit faa1c70. |
| M-13 | ◐ partial 2026-05-05 | `pid` dropped — alembic revision `e3b1a4f97c5d_drop_emulation_sessions_pid.py`, model field removed, dead `Integer` import removed, `test_emulation_auth.py:40` MagicMock attribute removed. Live SELECT smoke confirms the column is gone from the running DB and the loaded model. `kernel_used` NOT dropped: it has a real read site at `backend/app/ai/tools/emulation.py:2763` and a schema field at `app/schemas/emulation.py:148`. The right close for `kernel_used` is to plumb the write (`system_emulation_service` should record which kernel image FirmAE selected per architecture), which is a separate intake item — defer. |
| M-14 | ✅ shipped 2026-05-05 | docker-compose.yml clamav healthcheck `["CMD", "clamdcheck"]` → `["CMD", "clamdscan", "--ping=1"]`. `clamdcheck` (no .sh) is not on PATH in clamav/clamav:latest; `clamdscan --ping=1` (clamav ≥0.103) actually pings clamd over the socket and exits non-zero on unresponsive daemon, which is a stronger liveness check than the audit-recommended `--version` (binary-exists only). YAML validated via `docker compose --profile clamav config`. |
| M-8 | ◐ partial 2026-05-05 | Worker healthcheck added: `[".venv/bin/arq", "--check", "app.workers.arq_worker.WorkerSettings"]`. Stronger than the audit-recommended `pgrep arq` because `arq --check` issues a Redis heartbeat round-trip — verifies process alive AND Redis reachable AND heartbeat fresh. Live-validated: container reports `Status=healthy, ExitCode=0` with output `Health check successful: ... j_complete=0 ...`. Vulhunt healthcheck NOT added: upstream image is Chainguard distroless (`ls /` and `which sh` both fail; only `vulhunt-ce` binary on PATH; `vulhunt-ce` exposes scan/mcp/btp/ba2 subcommands but no `health`). A docker healthcheck has to run inside the target container, so there is no in-image probe we can call without modifying the upstream image. Documented the constraint inline in compose. Future fix would require either upstreaming a `vulhunt-ce health` subcommand or shipping a side-car ambassador on the same network — out of scope for an audit close-out. |
| M-12 | ✅ shipped 2026-05-05 | 3 type annotations changed from `Mapped[dict \| None]` → `Mapped[list[dict] \| None]` across `emulation_session.port_forwards`, `emulation_session.discovered_services`, `emulation_preset.port_forwards`. Rule #19 evidence-first: `SELECT jsonb_typeof(port_forwards) FROM emulation_sessions WHERE port_forwards IS NOT NULL` → 4 rows all `array`, 0 dict; no migration needed. `nvram_state` left as `Mapped[dict \| None]` per F-C-07 (consumers use dict semantics correctly). Validated via Rule #11 import smoke (annotations resolve as `Mapped[list[dict] \| None]` in the running backend) and Rule #35b live canary (real ORM round-trip on 2 production rows shows `type=list, value=[]`). Rule #8 backend+worker rebuild done; both report healthy post-rebuild. Commit `14a5124`. |
| M-2 | ✅ shipped 2026-05-05 | Split into 2 commits per Rule #25. (a) F-E-09 refactor (commit `0a7b845`): replaced inline `(err as { response?... })?.response?.data?.detail` casts with `extractErrorMessage(err, fallback)` at `ComparisonPage.tsx:91`, `FirmwareMetadataCard.tsx:29`, `BinaryTabs.tsx:71` (504/timeout special-case preserved verbatim — only the else-branch fallback uses the helper). (b) F-E-10 + F-E-11 silent-catch toasts (commit `f825a53`): added `toast.error(extractErrorMessage(err, '<op>'))` to 6 silent catches at `FindingsPage.tsx:59,84,99` (fetch/update/delete) and `SbomPage.tsx:135,160,200` (generate/scan/export), keeping the existing `console.error` breadcrumb. The axios interceptor at `client.ts:68-104` already toasts for network/401/403/5xx; this fix closes the 4xx-other gap (400/404/409/422). Rule #24 mandatory canary fired this session (exit=2 on planted type error) before any "0 errors" output was trusted; Rule #26 frontend rebuild done. |
| M-3 | ◐ partial 2026-05-05 | Highest-risk site `SbomPage.tsx` `VirtualizedVulnTable` shipped (commit `baadedb`). `style={{ height: 'calc(100vh - 420px)' }}` → runtime-measured `style={{ height: listHeight }}` where `listHeight = max(300, window.innerHeight - rect.top - 32)`. Re-runs on `window.resize` + `ResizeObserver` of the parent element (filter expansion / bulk-action panel toggles grow above this element without changing its own size, so observing the element directly wouldn't fire — observe the parent instead). Adapted from FindingsList.tsx:57 sibling pattern; adjusted for SbomPage's non-flex `space-y-4` parent chain. Frontend rebuild done; container healthy. The 7 lower-risk `calc(100vh - Npx)` sites elsewhere remain — defer to a future opportunistic pick or a M-3-residual intake (each is a one-line change but the regression risk is far lower since they have proper `min(cap, …)` ceilings the SbomPage site lacked). |
| M-4 | ✅ shipped 2026-05-05 | 19 inline `class XResponse(BaseModel)` definitions across 3 routers moved to `app/schemas/` per Rule #12. Split into 3 commits per Rule #25, one per router. (a) Commit `1bd4a12` — 4 classes from `routers/tools.py` to new `schemas/tools.py` (ToolRunRequest/Response, ToolInfo, ToolListResponse). (b) Commit `621b43e` — 6 classes from `routers/apk_scan.py` extending existing `schemas/apk_scan.py` (Sast* family + SourceFile* viewer). (c) Commit `b6d7925` — 9 classes from `routers/security_audit.py` to new `schemas/security_audit.py` (SecurityScan/Uefi/Yara/Clam/Vt/UpdateMechanism×2/Abusech/KnownGood). Width-canary applied (Rule #31): narrow `^class .*(BaseModel):` and broader `class .*BaseModel` agree at 19 across 3 files; post-move both grep variants return 0. Pre-move external-reference grep returned 0 — no test or service imports any of the moved classes by name from the router module, so the move is purely local with zero cascading import updates. Rule #11 import smoke: each new schema module + each router module imports cleanly, route counts unchanged (tools=2, apk=5, security=8). Rule #35b live canary: representative models instantiate, validate, serialize correctly including the cross-class `UpdateMechanismResponse(mechanisms=[UpdateMechanismDetail(...)])` reference and `SastFindingResponse.model_validate(obj, from_attributes=True)`. Rule #24 frontend tsc canary fired (exit=2 on planted error) before any "0 errors" was trusted; post-move tsc -b --force exit=0. Rule #8 backend+worker rebuild done. |
| M-11 | ✅ shipped 2026-05-05 | datetime.utcnow() drift fixed across 10 call sites + 25 ORM columns. Width-canary discovered intake under-counted both: "9 call sites" vs actual 10 (the +1 was `test_cache_module.py`); "12 ORM columns" vs actual 25 (+108% — Rule #28 instance). Split into 2 coupled commits per Rule #25, with Part B (migration) landed FIRST since asyncpg raises `DataError: can't subtract offset-naive and offset-aware datetimes` when assigning a tz-aware datetime to a TIMESTAMP WITHOUT TIME ZONE column (verified via canary against `cve_match_started_at` pre-migration). (a) Commit `476ce55` Part B — 11 model files updated to `DateTime(timezone=True)`; alembic revision `a8f3d2c1e9b4` runs `ALTER COLUMN <col> TYPE TIMESTAMP WITH TIME ZONE USING <col> AT TIME ZONE 'UTC'` for all 25 columns (analysis_cache, attack_surface_entries, conversations×2, cra_assessments×2, cra_requirement_results×2, documents, findings×2, firmware×3, projects×2, sbom_vulnerabilities, security_reviews×4, review_agents×4). Migration applied via Rule #20 fast iteration; sample SELECT against `information_schema.columns` confirms `data_type=timestamp with time zone` for 5 sampled columns. (b) Commit `1cfb354` Part A — 10 call sites: `vuln.resolved_at` ×2, analysis-cache TTL cutoff, cve-match started/finished/fail-finished ×3, firmware retention cutoff, CRA assessed_at ×2, cache test cutoff. Rule #11 import smoke + Rule #35b live canary (Finding insert/refresh confirms `created_at.tzinfo == UTC` post-rebuild). Rule #24 frontend tsc canary exit=0. Rule #8 backend+worker rebuild done. |
| M-10 | pending | Pick up opportunistically. |

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
