---
name: router
description: Session bootstrap and navigation hub. Read at the start of every session before any task. Contains project state, routing table, and behavioural contract.
edges:
  - target: context/architecture.md
    condition: when working on system design, integrations, or understanding how components connect
  - target: context/stack.md
    condition: when working with specific technologies, libraries, or making tech decisions
  - target: context/conventions.md
    condition: when writing new code, reviewing code, or unsure about project patterns
  - target: context/decisions.md
    condition: when making architectural choices or understanding why something is built a certain way
  - target: context/setup.md
    condition: when setting up the dev environment or running the project for the first time
  - target: context/mcp-tools.md
    condition: when adding, modifying, or debugging MCP tool handlers
  - target: patterns/INDEX.md
    condition: when starting a task — check the pattern index for a matching pattern file
last_updated: 2026-04-24
---

# Session Bootstrap

If you haven't already read `AGENTS.md`, read it now — it contains the project identity, non-negotiables, and commands.

Then read this file fully before doing anything else in this session.

## Current Project State

**Working:**
- MCP server (`wairz-mcp`) with 65+ tools across 19 categories (filesystem, binary, security, sbom, emulation, fuzzing, android, android_bytecode, android_sast, uart, uefi, vulhunt, attack_surface, cwe_checker, comparison, documents, network, reporting, strings).
- Firmware upload + unpacking pipeline (binwalk3 + unblob, multi-partition, SquashFS/JFFS2/UBIFS/CramFS/ext/CPIO/Intel HEX).
- React 19 SPA with pages for Projects, ProjectDetail, Explore (file tree + Monaco viewer), ComponentMap (ReactFlow graph), Emulation, Fuzzing, SBOM, Findings, SecurityScan, SecurityTools, Comparison, DeviceAcquisition, Help.
- Standalone APK upload + classification (recent commit 370b312).
- Docker socket-based sidecar launch for QEMU emulation, AFL++ fuzzing, FirmAE system-mode.
- Host-side UART bridge (port 9999) and device acquisition bridge (port 9998).
- Redis-backed arq job queue + SSE event bus (polling fallback if Redis is down).
- 31 learned rules codified in CLAUDE.md, surfaced in `context/conventions.md` Verify Checklist (recent additions: #27 N+1 cut-over refactor shape, #28 re-measure LOC before scoping, #29 axios-timeout derivation, #30 mock-patch-lazy-imports-at-source, #31 grep-width-canary — sessions b56eb487/7e8dd7c3/0801ca27/3d9d854e, 2026-04-21 through 2026-04-24).
- Backend + frontend host ports bound to 127.0.0.1 by default (A.1 mitigation, session 59045370 commit 10872d6). Override file `docker-compose.override.yml` (gitignored) re-exposes them on 0.0.0.0 alongside a dev API_KEY for operator browser access.
- **B.1 shipped (session 698549d4 commit 3d8aa10):** `APIKeyASGIMiddleware` covers http + websocket scopes. `/ws` terminal + `/{session_id}/terminal` emulation proxy both require `X-API-Key` header OR `api_key` query param; close code 4401 on auth fail. Frontend carries the key via per-request axios interceptor + query param on WS URLs. nginx index.html has explicit `Cache-Control: no-cache`; `/assets/*` has `immutable`. Dockerfile `ARG VITE_API_KEY` bakes the key into the static bundle at build time. B.1.a/b/c (require-api-key gate, slowapi rate limit, streaming upload-size) still pending.
- Postgres + FirmAE passwords parameterized via env vars with backward-compatible defaults (session 59045370 commit 906cfe2).
- `analysis_cache.operation` widened to VARCHAR(512) via alembic 1f6c72decc84 (session 59045370 commit e3053b6).
- Binwalk3 escape-symlink artifact cleanup in the unpack fallback chain (session 59045370 commit 90ed79c) — prevents the "extraction succeeded but only a symlink exists" bug that surfaced on the PowerPack firmware.
- `MAX_STANDALONE_BINARY_MB = 512` (session 59045370 commit ad29b23) — raises the bare-metal-as-standalone-binary cap from the old hardcoded 10 MB so 268 MB medical firmware (PowerPack) and typical automotive/IoT raw blobs analyse as standalone binaries. Env-overridable.
- `useFirmwareList` hook + projectStore action invalidation (session 59045370 commit 97c7c7a) — 10 pages migrated; dedup'd the multi-caller `listFirmware` pattern.
- `cwe_checker` AsyncSession-safety fix (session 59045370 commit b9f625a) — serialised batch; AST-based async-subprocess linter wired into `lint.yml`.
- `/health/deep` endpoint (db + redis + docker socket + storage) — session 59045370 commit 3d14736.

**Recently shipped (post-2026-04-19 session cluster):**
- Docker socket proxy (`wairz-docker-proxy-1`), volume quotas + pg-backup sidecar (2440150/51770af/5f08db1/50a9ca6/3f60398). Storage quotas → 507 pre-upload, cleanup/reconcile crons in arq.
- Shared cache module extraction: `app.services._cache` + migration of ghidra/cwe/jadx/mobsfscan/firmware_metadata/apk_scan/component_map/save_code_cleanup cache access (d100595 → 909101c). `kernel_service↔emulation_service` circular import broken (68ecb64).
- Frontend store isolation + `ProjectRouteGuard` project-id guards (72ec063, 9bcf379).
- Frontend store device-type tightening (rolled into same cluster).
- Pagination envelopes on `/projects`, `/findings`, `/attack-surface`, and others (session 435cb5c2 Stream Beta; frontend `unwrap(data)` helper in 3063283; Rule #26 born from stale-bundle incident 2cb2cca).
- Page-envelope `useFirmwareList` hook migration for 10 frontend pages (97c7c7a).
- **Phase 5 god-class decomposition: 5 consecutive clean splits shipped** (sessions b56eb487 2026-04-21, 7e8dd7c3 2026-04-22 — Rule #27 N additive + 1 cut-over shape proven): `manifest_checks` (2589 LOC Mixin), `security_audit_service` (1258 LOC module), `sbom_service` (2412 LOC, 14-strategy Strategy pattern), `emulation_service` (1664 LOC), `mobsfscan_service` (1539 LOC) — 34 additive + 5 cut-over commits, 0 reverts, 0 cross-stream sweeps.
- **202+polling fleet** (session 2026-04-20, Rule #29 evidence) — emulation + fuzzing long-op endpoints converted from synchronous (30s axios timeout vs 1800-7200s backend) to 202 ack + 2s polling, matching firmware-unpack precedent. Backend-frontend timeout derivation rule (#29) extracted.
- **Pytest-unblock fleet** (session 0801ca27 2026-04-23, commit d5f2734) — 15 backend test files un-ignored and shipped green; +620 tests unlocked once Rule #30 mock-patch targeting was corrected. Rule #30 + harness rule `auto-pytest-mock-patch-androguard-at-service` extracted.
- **P3 circular-imports carve-outs** (sessions 5eefecb0 / f2f9060c / f2f9060c-cont, 2026-04-24) — assessment_service (11 promotions, fc384bb), fuzzing_service + emulation/ pair (9 promotions, 7d349c3/d1a8701/77a5908), mobsfscan/ pair (3 promotions, b213795/ff111d2). Runtime function-local `from app.*` residual: 40→37 across 18 files. `firmware_service.py` (14 remaining) explicitly deferred — cross-layer latent-cycle risk, per-call audit required.
- arq cron for orphan emulation/fuzzing container reaping — `cleanup_emulation_expired` + `cleanup_fuzzing_orphans` in `backend/app/workers/arq_worker.py:424,452` (infra-cleanup-migration-and-observability intake closed).
- B.1.a require-API-key gate (`asgi_auth.py`) + B.1.b slowapi rate limit (`rate_limit.py`) + B.1.c streaming upload-size check (`firmware.py:56-66 _check_upload_size` + `firmware_service.py:287-332` mid-transfer MAX_UPLOAD_SIZE_MB enforcement) — full `security-auth-hardening` intake closed.
- 4th + 5th P3 carve-outs: `security_audit/hash_lookups.py` (5 → 0 runtime, commit 404f66d) + `wairz_runner.py` (2 → 0 real runtime body-imports, commit 781a30e) — session 3d9d854e. Runtime residual via `ast.walk` (authoritative, replaces grep-based count): **33 across 16 files** (was 35/17 pre-session).
- 6th P3 carve-out: `firmware_service.py` (14 → 0 runtime body-imports, commit 5e2cb18) — session 78f772bd, executed against the per-call de-risk audit committed by 3d9d854e (commit 8e99ec4). Promotions span `firmware_paths` + 4 `workers/` modules (safe_extract, unpack, unpack_common, unpack_linux). Rule #30 audit held with zero surprises; no class-shape change. Runtime residual via `ast.walk` (unique-line): **18 across 15 files** (was 33/16). Rule #19 stop point reached — diminishing returns on remaining single-digit candidates; pause unless user directs further.
- 7th/8th/9th P3 carve-outs: `clamav_service.py` (2 → 0, commit 8f9d261), `attack_surface_service.py` (2 → 0, commit 4bd491b), `hardware_firmware/cve_matcher.py` (2 → 0, commit 9a26c1a) — session aa8b4a17 (2026-04-24), user-directed continuation past the session-78f772bd Rule #19 recommendation ("burn down risk first"). Risk-ordered execution (lowest blast-radius first). Rule #30 reverse-check (test patches) + Rule #30 source-audit (pure-leaf targets) + Rule #31 width-canary + Rule #11 import-smoke (backend+worker+blast-radius) all green. `import clamd` intentionally retained lazy per Rule #30 caveat (a). Runtime residual via `ast.walk` (unique-line): **12 across 12 files, flat 1-per-file distribution** (was 18/15). Rule #19 stop-point stronger than ever — remaining P3 thread recommended CLOSE in the intake log unless a concrete cycle-pressure event (failed CI import, circular-import ImportError, cold-start regression) surfaces.

**Not yet built (per intake queue):**
- (None. `backend-private-api-and-circular-imports` P3 thread closed by session aa8b4a17 on 2026-04-24 — structural 1-per-file floor reached. Architecture-review-2026-04-16 intake queue: all 20 items + item 0 completed. No partial or deferred intakes remain.)

**Known issues:**
- (Queue is clean. Next work item comes from operational pressure, not the backlog. 12 residual function-body `app.*` imports remain across `backend/app/services/` (1 each: `abusech_service`, `binary_analysis_service`, `comparison_service`, `device_service`, `hardware_firmware/classifier`, `hardware_firmware/graph`, `qiling_service`, `sbom/enrichment`, `sbom/strategies/syft_strategy`, `security_audit/network`, `virustotal_service`, `yara_service`) — dormant, re-open only on concrete cycle-pressure per Rule #19.)

## Routing Table

Load the relevant file based on the current task. Always load `context/architecture.md` first if not already in context this session.

| Task type | Load |
|-----------|------|
| Understanding how the system works | `context/architecture.md` |
| Working with a specific technology | `context/stack.md` |
| Writing or reviewing code | `context/conventions.md` |
| Making a design decision | `context/decisions.md` |
| Setting up or running the project | `context/setup.md` |
| Adding or debugging an MCP tool | `context/mcp-tools.md` |
| Any specific task | Check `patterns/INDEX.md` for a matching pattern |

## Behavioural Contract

For every task, follow this loop:

1. **CONTEXT** — Load the relevant context file(s) from the routing table above. Check `patterns/INDEX.md` for a matching pattern. If one exists, follow it. Narrate what you load: "Loading architecture context..."
2. **BUILD** — Do the work. If a pattern exists, follow its Steps. If you are about to deviate from an established pattern, say so before writing any code — state the deviation and why.
3. **VERIFY** — Load `context/conventions.md` and run the Verify Checklist item by item. State each item and whether the output passes. Do not summarise — enumerate explicitly.
4. **DEBUG** — If verification fails or something breaks, check `patterns/INDEX.md` for a debug pattern. Follow it. Fix the issue and re-run VERIFY.
5. **GROW** — After completing the task:
   - If no pattern exists for this task type, create one in `patterns/` using the format in `patterns/README.md`. Add it to `patterns/INDEX.md`. Flag it: "Created `patterns/<name>.md` from this session."
   - If a pattern exists but you deviated from it or discovered a new gotcha, update it with what you learned.
   - If any `context/` file is now out of date because of this work, update it surgically — do not rewrite entire files.
   - Update the "Current Project State" section above if the work was significant.
