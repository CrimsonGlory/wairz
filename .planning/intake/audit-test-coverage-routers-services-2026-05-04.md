---
title: "Test coverage backfill — 24/27 routers + 31 services have NO test importing them"
status: in-progress
priority: high
target: backend/tests/test_<router_or_service>.py (multiple new files)
phase_1_complete: 2026-05-06
---

## Phase 1 closeout — autopilot 2026-05-06

**Phase 1 shipped (5 commits, ~2,300 LOC of tests + 1 pattern recipe + CLAUDE.md mandate):**

- `e05f50e` test(security_audit): HTTP-layer + Rule #35b live-canary coverage (10 cases, +616 LOC including shared `tests/_live_db.py` helper)
- `f7b2029` test(firmware): upload + 202+polling unpack guards + Rule #35b live-canary (9 cases, +429 LOC)
- `23b6b03` test(terminal): WebSocket auth + Rule #34b appendApiKey regression coverage (10 cases, +380 LOC across 3 layers — middleware ASGI tests, TestClient WebSocket smoke, live canary)
- `df4403a` test(vulnerability_service): F-A-06 confidence-bypass live-canary backstop (37 cases, +490 LOC)
- `bd927b5` test(ghidra_service): cache round-trip + Rule #29 cache-hit live-canary (28 cases, +437 LOC)
- `707973a` docs(testing): mandate router-level test for every new router (CLAUDE.md + .mex/context/conventions.md mirror per Rule #21)
- `73417c6` docs(mex): add add-router-test pattern recipe (.mex/patterns/add-router-test.md + INDEX.md entry)

**Total: 94 test cases, all passing.** Verified via `pytest tests/test_security_audit_router.py tests/test_firmware_router.py tests/test_terminal_router.py tests/test_vulnerability_service.py tests/test_ghidra_service.py`.

**Validation:** Rule #24 tsc canary passed (`echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force)` → expected error TS2322; rm canary; rerun on real codebase → tsc exit=0). Rule #11 backstop satisfied via `docker compose exec` round-trips for each test file before commit.

**Key innovations for Phase 2 to inherit:**

1. `tests/_live_db.py` — JSONB/ARRAY/UUID PG-only types compile to SQLite via `@compiles(..., "sqlite")` shims; bind/result processors serialize list/dict via `json.dumps`/`loads`. The duplicate `ix_firmware_project_id` (declared on column AND in `__table_args__`) is stripped by `_dedup_indexes` at fixture-setup time.
2. **Patch lazy-imported symbols at the SOURCE module** (Rule #30) — `app.routers.X.get_detection_roots` is a silent no-op; `app.services.firmware_paths.get_detection_roots` works. Same for `app.config.get_settings` when imported inside an endpoint body.
3. **TestClient(app) WITHOUT `with`** for WebSocket tests — the FastAPI lifespan does production-DB writes (orphan-row reaper) that race against the test fixture and surface as "another operation is in progress" asyncpg errors.
4. **Redirect-then-cat for pytest output** in `docker compose exec -T` — the wrapper truncates long traceback streams mid-flight; redirecting to a tmpfile inside the container, then `cat`ing it back, captures the full output.

**Phase 2 remaining (deferred, NOT blocked):**

- 21 untested routers (sbom, apk_scan, comparison, compliance, component_map, cra_compliance, device, documents, events, export_import, files, findings, fuzzing, health, kernels, projects, tools, uart, attack_surface, analysis — all already verified in audit-2026-05-04 F-G-03)
- 26 untested services (cra_compliance_service, system_emulation_service, assessment_service, etc. — see audit findings for full list, triage by `LOC × external_input_surface` per intake brief)
- Triage: route via citadel:archon for multi-session campaign decomposition.

---

## Brief — autopilot 2026-05-05

**Scope:** Large (multi-session campaign). Phase 1 alone is ~5 commits (~600 LOC of tests).

**Phase 1 (P0 security-sensitive):**
- `test_security_audit_router.py` — security_audit.py (1046 LOC, no router-level tests)
- `test_firmware_router.py` — firmware.py upload + 202+polling status path (546 LOC)
- `test_terminal_router.py` — terminal.py WebSocket auth (477 LOC, Rule #34b appendApiKey regression test)
- `test_vulnerability_service.py` — covers confidence-bypass fix (Rule #35b discipline)
- `test_ghidra_service.py` — covers cache + timeout paths

**Phase 2:** remaining 21 routers + 26 services, triage by `LOC × external_input_surface`.

**Approach per test file:**
1. Use Rule #35b live-canary: at least ONE test per file does a real ORM round-trip + SELECT to verify persisted state.
2. Mirror the `test_hardware_firmware_router.py` shape (existing exemplar).
3. For WebSocket auth tests: assert appendApiKey URL paths get 200 and bare-URL paths get 401 (Rule #34b regression).

**Quality gates:**
- Rule #11 backstop runtime smoke on each new test file.
- Rule #24 mandatory tsc canary per session.
- Test files must import the actual router/service module — no pure-mock tests (Rule #35b).

**Companion ask:**
- Update CLAUDE.md "Testing and Validation Policy" to mandate router-level test for any new router.
- Add to `.mex/patterns/INDEX.md` as `add-router-test` recipe.

**Deferral reason — autopilot:** Multi-session by intake design. Phase 1 alone is ~5 hours of focused test-writing. Better suited to a dedicated test-coverage push with archon orchestration.

## Description

Audit measured the coverage shape:

**Router tests (Stream G F-G-03):** Only 3 of 27 routers have direct HTTP-layer tests via `from app.routers.X`:
- ✅ Tested: `deps`, `emulation`, `hardware_firmware`
- ❌ Untested: 24 routers including `security_audit.py` (1046 LOC), `apk_scan.py` (939 LOC), `sbom.py` (851 LOC), `firmware.py` (546 LOC, the 202+poll upload path), `terminal.py` (477 LOC, WebSocket auth)

**Service tests (Stream G F-G-04):** 31 services have no test importing them. Top-LOC untested:
- `cra_compliance_service` (833)
- `system_emulation_service` (771)
- `assessment_service` (770)
- `vulnerability_service` (733)
- `ghidra_service` (685)

**Risk concentration:**
- `security_audit.py` is 1046 LOC of security-sensitive code with no router-level tests.
- `vulnerability_service` is one of the 5 confidence-bypass paths flagged by Stream A — adding tests here covers the Rule #35b fix at the same time.
- `terminal.py` is the WebSocket auth path; `appendApiKey` discipline (Rule #34b) needs a regression test.

## Acceptance Criteria

- [ ] **Phase 1 — security-sensitive backfill (P0):** add HTTP-layer tests for `security_audit`, `firmware` (upload + 202+polling status), `terminal` (WebSocket auth). Service-layer tests for `vulnerability_service` (covers confidence-bypass fix), `ghidra_service`.
- [ ] **Phase 2 — long-tail backfill:** remaining 21 untested routers + 26 untested services. Triage by LOC × external-input-surface.
- [ ] Each new test file uses Rule #35b live-canary discipline: at least ONE test per file does a round-trip through the real ORM + a SELECT to verify persisted state, not just `mock.assert_called`.
- [ ] Update CLAUDE.md "Testing and Validation Policy" to mandate router-level test for any new router; add to `.mex/patterns/INDEX.md` as `add-router-test` recipe.

## Out of Scope

- Test coverage tooling (`pytest-cov` enabling) — flagged in Stream G, separate intake if needed.

## Cross-step

This is a multi-session campaign. Decompose per Rule #25: one commit per new test file. Phase 1 alone is ~5 commits.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-g-tests-2026-05-04.md` findings F-G-03, F-G-04.
