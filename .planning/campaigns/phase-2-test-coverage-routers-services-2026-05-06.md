---
title: "Phase 2 — test coverage backfill (21 routers + 26 services)"
slug: phase-2-test-coverage-routers-services-2026-05-06
status: in-progress
created: 2026-05-06
direction: |
  Pick up Phase 2 of audit-test-coverage-routers-services-2026-05-04. Phase 1
  (5 files, 94 cases, commits e05f50e..8180219) shipped 2026-05-06 with the
  inheritable patterns: tests/_live_db.py shim, lazy-import patch discipline
  per Rule #30, TestClient(app) without `with` for WebSocket tests, redirect-
  then-cat for pytest output. Phase 2 backfills 21 untested routers + ~30
  untested services. Triage by LOC × external_input_surface — start with the
  largest external-input surfaces first.

  Each test file MUST mirror test_hardware_firmware_router.py + follow
  .mex/patterns/add-router-test.md, ship a Rule #35b live-canary via
  tests/_live_db.make_live_db, and land as a per-file commit (Rule #25).

  Decompose into waves (3-5 files each); pause between waves for review.
  Skip files that won't yield a meaningful canary — flag in campaign log.
estimated_sessions: 8
baseline_typecheck_errors: 0
parent_intake: .planning/intake/audit-test-coverage-routers-services-2026-05-04.md
---

## Active Context

**Mode:** wave-4-shipped — paused for user review before Wave 5
**Current Wave:** 4 ✅ COMPLETE (5 test files + Wave 3 close-out)
**Next Wave:** 5 (projects, health, kernels, export_import, component_map, compliance routers — 6 small files 57-130 LOC) — final router wave; service waves come after

**Wave 1 commits (clean-history):**
- `d8f1e14` test(sbom_router): 16 cases, +744 LOC
- `4a6357f` fix(apk_scan): _cache import bug uncovered by Phase 2 backfill
- `fdd549f` test(apk_scan_router): 13 cases, +655 LOC
- `3f31957` test(cra_compliance_service): 26 cases, +607 LOC
- `0c71262` test(system_emulation_service): 16 cases, +533 LOC
- `49a6d34` test(assessment_service): 14 cases, +422 LOC
- `13ae303` chore(campaign): close Wave 1

**Wave 2 commits (clean-history):**
- `dcedd33` test(analysis_router): 14 cases, +579 LOC
- `1d4feed` test(tools_router): 8 cases, +404 LOC
- `b576d8e` test(emulation_router): 14 cases, +568 LOC
- `55bf86d` test(androguard_service): 36 cases, +398 LOC (Rule #30 hot zone)
- `080c10d` test(live_db): harden shim against bare-string JSONB server_default round-trips
- `2febcc0` test(fuzzing_service): 18 cases, +553 LOC

**Wave 2 totals: 90 tests across 5 files + 1 infrastructure improvement = 6 commits.**

**Wave 3 commits (clean-history):**
- `1ca2bcf` test(fuzzing_router): 13 cases, +591 LOC (Rule #33 fast-path canary)
- `ae990cb` test(comparison_router): 9 cases, +420 LOC (cross-project boundary canary)
- `022554a` test(files_router): 11 cases, +400 LOC (real-bytes download canary)
- `45e7772` test(attack_surface_router): 5 cases, +409 LOC (F-A-06 confidence backstop)
- `bcadb28` test(cra_compliance_router): 7 cases, +343 LOC (cross-project boundary canary, paired with Wave 1 service tests)

**Wave 3 totals: 45 tests across 5 files = 5 commits. (Wave 3 was the smallest wave by LOC since the targets were 219-252 LOC; canaries focused on cross-project boundaries — recurring theme — and the F-A-06 confidence-bypass backstop.)**

**Wave 4 commits (clean-history):**
- `a538079` test(uart_router): 15 cases, +436 LOC (bridge proxy error matrix + UARTSession canary)
- `8e2387a` test(documents_router): 7 cases, +350 LOC (cross-project boundary + note canary)
- `8a2ed8b` test(device_router): 11 cases, +321 LOC (Rule #33a 409 idempotency canary)
- `ab79069` test(findings_router): 8 cases, +370 LOC (cross-project boundary + finding-create canary)
- `b11b172` test(events_router): 7 cases, +283 LOC (SSE channel selection + cleanup contract)

**Wave 4 totals: 48 tests across 5 files = 5 commits. (Wave 4 was the smallest by LOC across the campaign so far — targets 144-217 LOC; canaries leaned on already-validated patterns.)**
**Cumulative Phase 2 totals: 268 tests + 1 production bug fix + 1 shim hardening = 23 commits across 4 waves.**

## Phase End Conditions

| Phase | Files (per-commit, Rule #25) | End condition (machine-verifiable) |
|---|---|---|
| Wave 1 | sbom router, apk_scan router, cra_compliance_service, system_emulation_service, assessment_service | `ls backend/tests/test_sbom_router.py test_apk_scan_router.py test_cra_compliance_service.py test_system_emulation_service.py test_assessment_service.py` all exist; each commit message starts `test(...)` (Rule #25); pytest exits 0 for each file |
| Wave 2 | emulation router, fuzzing_service, androguard_service, analysis router, tools router | per-file existence + pytest 0 |
| Wave 3 | fuzzing router, comparison router, files router, attack_surface router, cra_compliance router | per-file existence + pytest 0 |
| Wave 4 | uart router, documents router, device router, findings router, events router | per-file existence + pytest 0 |
| Wave 5 | projects router, health router, kernels router, export_import router, component_map router, compliance router | per-file existence + pytest 0 |
| Wave 6 | component_map_service, pcap_analysis_service, jadx_service, import_service, binary_analysis_service | per-file existence + pytest 0 |
| Wave 7 | firmware_metadata_service, compliance_service, kernel_service, report_service, selinux_service | per-file existence + pytest 0 |
| Wave 8+ | remaining services (cpe_dictionary, abusech, cwe_checker, document, qiling, grype, uart, virustotal, sysroot, clamav, hashlookup, event, emulation_preset, analysis, dependency_track) — triage and skip pure-config files (e.g. emulation_constants) | per-file existence + pytest 0 |

## Inheritable Patterns (from Phase 1, MUST apply to every Wave 2 file)

1. **`tests/_live_db.py` shim** — JSONB/ARRAY/UUID PG-only types compile to SQLite via `@compiles(..., "sqlite")` shims; bind/result processors serialize list/dict via json. The duplicate `ix_firmware_project_id` is stripped by `_dedup_indexes` at fixture-setup time. Use `async with make_live_db() as db:` (NOT `async for ... break`).

2. **Patch lazy-imported symbols at the SOURCE module** (Rule #30) — `patch("app.routers.X.get_detection_roots")` is a silent no-op when the router does `from app.services.firmware_paths import get_detection_roots` INSIDE a function body. Always grep first: `grep -n "^from [^#]*import.*\bY\b" backend/app/routers/<router>.py` — if the match is indented, patch the source module.

3. **TestClient(app) WITHOUT `with`** for WebSocket tests — FastAPI lifespan does production-DB writes that race against the test fixture.

4. **Redirect-then-cat for pytest output** in `docker compose exec -T` — `> /tmp/out.txt 2>&1; cat /tmp/out.txt | tail -50`.

5. **Autouse fixtures**: `_disable_api_key_auth`, `_disable_rate_limit`, `_cleanup_overrides`.

6. **Rule #35b live-canary**: at least ONE test per file does a real ORM round-trip + SELECT to verify persisted state — not just `mock.assert_called`.

7. **Per-file commit (Rule #25)**: one commit per test file with the message form `test(<module>): <one-line summary> (N cases, +M LOC)`.

## Triage — Untested Inventory (verified 2026-05-06)

### Routers (21 untested, by LOC desc)

| Router | LOC | Wave | Notes |
|---|---:|---:|---|
| emulation | 966 | 2 | Largest router. Includes WebSocket terminal endpoint, multiple status endpoints. |
| apk_scan | 877 | 1 | Manifest + bytecode + SAST scan endpoints. Mostly POST, project/firmware-scoped. |
| sbom | 858 | 1 | Generate, list, export, vuln scan, push-to-DT. Includes 5/hour rate limit. |
| analysis | 316 | 2 | Ghidra/radare2 analysis dispatch. |
| tools | 263 | 2 | Tool registry surface. |
| fuzzing | 252 | 3 | 202+polling pattern (fuzzing_service campaign start). |
| comparison | 251 | 3 | Diff endpoints. |
| files | 244 | 3 | File-list + read endpoints. Sandbox-sensitive. |
| attack_surface | 228 | 3 | Detect input vectors. |
| cra_compliance | 219 | 3 | Generate + persist CRA assessments. |
| uart | 217 | 4 | UART bridge proxy. |
| documents | 202 | 4 | CRUD on documents. |
| device | 185 | 4 | Device-bridge proxy. |
| findings | 157 | 4 | CRUD on findings. |
| events | 144 | 4 | Event log endpoints. |
| projects | 130 | 5 | Project CRUD. |
| health | 119 | 5 | Health probes. |
| kernels | 104 | 5 | Kernel CRUD. |
| export_import | 100 | 5 | Project export/import. |
| component_map | 88 | 5 | Component graph. |
| compliance | 57 | 5 | ETSI EN 303 645 surface (small). |

### Services (untested, by LOC desc — top picks)

| Service | LOC | Wave | Notes |
|---|---:|---:|---|
| fuzzing_service | 1196 | 2 | 202+polling job dispatch. |
| androguard_service | 902 | 2 | Lazy-imports androguard — Rule #30 source-patch territory. |
| cra_compliance_service | 839 | 1 | Maps findings to 20 CRA Annex I requirements. |
| system_emulation_service | 772 | 1 | Docker SDK + httpx to FirmAE shim. |
| assessment_service | 770 | 1 | Multi-phase orchestrator (security_audit + sbom + selinux + vuln). |
| component_map_service | 701 | 6 | |
| pcap_analysis_service | 594 | 6 | |
| jadx_service | 592 | 6 | Lazy-imports jadx; Rule #30. |
| import_service | 586 | 6 | Project re-import. |
| binary_analysis_service | 556 | 6 | Lazy-imports lief. |
| firmware_metadata_service | 481 | 7 | |
| compliance_service | 481 | 7 | ETSI mapping. |
| kernel_service | 381 | 7 | |
| report_service | 365 | 7 | |
| selinux_service | 355 | 7 | |
| cpe_dictionary_service | 355 | 8 | |
| abusech_service | 326 | 8 | External API. |
| cwe_checker_service | 318 | 8 | External tool. |
| document_service | 317 | 8 | |
| qiling_service | 279 | 8 | |
| grype_service | 265 | 9 | External tool. |
| uart_service | 254 | 9 | TCP bridge protocol. |
| virustotal_service | 224 | 9 | External API. |
| sysroot_service | 207 | 9 | |
| clamav_service | 174 | 9 | External tool. |
| hashlookup_service | 142 | 10 | External API. |
| event_service | 135 | 10 | Pub/sub. |
| emulation_preset_service | 88 | 10 | |
| analysis_service | 83 | 10 | Likely thin coordinator — verify worth canarying. |
| dependency_track_service | 61 | 10 | External API client — verify worth canarying. |
| emulation_constants | 153 | SKIP | Pure constants — flag in log, don't ship pure-mock test. |

## Feature Ledger

| Wave | File | Commit | Cases | LOC | Live-canary fields verified |
|---|---|---|---:|---:|---|
| 1 | tests/test_sbom_router.py | d8f1e14 | 16 | 744 | SbomComponent: name/version/type/cpe/purl/supplier/detection_source/detection_confidence/file_paths/metadata_/firmware_id; None-coalescence path |
| 1 | backend/app/routers/apk_scan.py (FIX) | 4a6357f | — | 2 | bytecode endpoint NameError on `_cache` — promoted import inline |
| 1 | tests/test_apk_scan_router.py | fdd549f | 13 | 655 | Finding (manifest persist): title/severity/confidence/source/firmware_id/cwe_ids/file_path/description |
| 1 | tests/test_cra_compliance_service.py | 3f31957 | 26 | 607 | CraAssessment + 20 CraRequirementResult rows; status transitions on auto_populate (high→fail, low→partial, no-findings→pass, not_automatable→not_tested); recalc summary on update_requirement |
| 1 | tests/test_system_emulation_service.py | 0c71262 | 16 | 533 | EmulationSession: mode/architecture/container_id/status/started_at/system_emulation_stage; stop short-circuit (status=stopped, stopped_at) |
| 1 | tests/test_assessment_service.py | 49a6d34 | 14 | 422 | Finding via _create_finding: source="security_review"/firmware_id/project_id/title/severity/evidence/file_path/line_number/cwe_ids; orchestration shape (skip + error + success branches) |
| 2 | tests/test_analysis_router.py | dcedd33 | 14 | 579 | analysis_cache.result JSONB round-trip via /cleaned-code (cleaned_code field unwrap) |
| 2 | tests/test_tools_router.py | 1d4feed | 8 | 404 | ToolContext: project_id/firmware_id/extracted_path/extraction_dir/detection_roots all carry from resolved Firmware row into the registered tool handler's context |
| 2 | tests/test_emulation_router.py | b576d8e | 14 | 568 | EmulationPreset: name/mode/binary_path/arguments/architecture/stub_profile + JSONB port_forwards; EmulationSession (POST /start): firmware_id/mode/status='pending'/binary_path/arguments/architecture/JSONB port_forwards |
| 2 | tests/test_androguard_service.py | 55bf86d | 36 | 398 | analyze_apk dict shape: package/version_*/min_sdk/target_sdk/permissions(sorted)/activities/main_activity/is_signed/signatures (Rule #35b applied to non-persistent dict-shape contract) |
| 2 | tests/_live_db.py (HARDENING) | 080c10d | — | 73 | JSONB→TEXT DDL + tolerant json_deserializer eliminates double-decode on bare-string server_defaults |
| 2 | tests/test_fuzzing_service.py | 2febcc0 | 18 | 553 | FuzzingCampaign: project_id/firmware_id/binary_path/status='created' + merged JSONB config dict; start_campaign Rule #33 fast-path flips to status='queued' + clears error_message |
| 3 | tests/test_fuzzing_router.py | 1ca2bcf | 13 | 591 | FuzzingCampaign via POST /campaigns: binary_path + JSONB config from request fields; POST /start (Rule #33): status='queued' COMMITTED before 202 ack so background task sees it |
| 3 | tests/test_comparison_router.py | ae990cb | 9 | 420 | Cross-project boundary on _get_firmware: real Firmware in project A → 404 via project B's URL (security canary) |
| 3 | tests/test_files_router.py | 022554a | 11 | 400 | /download streams real on-disk file bytes through real FileService; Content-Disposition includes basename |
| 3 | tests/test_attack_surface_router.py | 45e7772 | 5 | 409 | Finding via POST /scan: confidence='medium' (F-A-06 backstop) + source='attack_surface' + firmware_id; AttackSurfaceEntry JSONB dangerous_imports + input_categories |
| 3 | tests/test_cra_compliance_router.py | bcadb28 | 7 | 343 | Cross-project boundary on GET /assessments/{id}: real CraAssessment in project A → 404 via project B's URL; correct project A → 200 with eager-loaded 20 requirement_results |
| 4 | tests/test_uart_router.py | a538079 | 15 | 436 | UARTSession via POST /connect: device_path/baudrate(230400 non-default)/status='connected'/connected_at all round-trip through DB |
| 4 | tests/test_documents_router.py | 8e2387a | 7 | 350 | Document via POST /notes: project_id + original_filename(derived from title) + content_type + file_size round-trip |
| 4 | tests/test_device_router.py | 8a2ed8b | 11 | 321 | Rule #33a idempotency: 409 with existing dump_id when active dump exists; start_dump asserted NOT called |
| 4 | tests/test_findings_router.py | ab79069 | 8 | 370 | Finding via POST /findings (real FindingService.create): title/severity/confidence/source/file_path/line_number/cwe_ids/evidence all round-trip |
| 4 | tests/test_events_router.py | b11b172 | 7 | 283 | SSE channel selection: types=unpacking,fuzzing → SUBSCRIBE only those 2 (NOT all 6); pubsub.unsubscribe + aclose called on disconnect |

## Decision Log

- **2026-05-06: Wave shape = 5 files** (matches Phase 1 cadence). Per-file commits (Rule #25). Pause at end of each wave for review per user directive.
- **2026-05-06: Serial in-place commits, NOT parallel worktrees.** Each test file is independent (writes only `backend/tests/test_<X>.py`); serial avoids Rule #23 worktree complexity and the test-author benefits from full container access for Rule #11 smoke runs.
- **2026-05-06: Skip `emulation_constants.py` from canary scope.** Pure constants module (153 LOC of port lists, magic numbers) — no service surface to live-canary.
- **2026-05-06: Latent bug surfaced — `apk_scan.py` bytecode endpoint had `_cache` undefined.** Fixed in commit 4a6357f, separate from the test commit (Rule #25 spirit — independently revertable). The bytecode endpoint had zero router-level test coverage before Phase 2, so the bug shipped silently — exactly the Phase-2-justifies-itself outcome the audit predicted.
- **2026-05-06: SQLite + JSONB server_default = `"'[]'"` workaround.** EmulationSession.port_forwards uses `server_default="'[]'"` (bare-string SQL DEFAULT). When SQLAlchemy round-trips that through SQLite's native JSON column type, the dialect-level JSON processor double-decodes against `tests/_live_db.py`'s bind/result shim and bombs with "Expecting value: line 1 column 1 (char 0)" at flush time. Sbom + cra_compliance JSONB columns use `server_default=text("'{}'")` (text-expression form) and don't hit this. **Workaround applied:** every test EmulationSession constructor passes `port_forwards=[]` explicitly. **Future hardening candidate:** shim JSONB → TEXT (instead of JSON) in `_live_db.py` to eliminate the gotcha entirely. Documented in commit 0c71262 message.
- **2026-05-06: Inverse Rule #30 case documented.** assessment_service.py imports `get_detection_roots` at MODULE scope (line 26). Patching the SOURCE module (`app.services.firmware_paths.get_detection_roots`) is a silent no-op — the consumer module already holds its own local reference. Patch the CONSUMER module instead. Mirror of the standard Rule #30 case (lazy-imported symbols → patch source) but in reverse: top-level `from X import Y` makes `Y` a CONSUMER-module attribute, not a SOURCE-module one. Documented in test_assessment_service.py:200.
- **2026-05-06 (Wave 2): _live_db.py shim hardened.** Wave 1's port_forwards workaround was a band-aid. Wave 2 hit FuzzingCampaign.config + .stats with the same `server_default="'{}'"` shape and the workaround would have spread. Permanent fix shipped as commit 080c10d: (a) render JSONB / ARRAY as TEXT in DDL (was JSON) so SQLite's dialect-level JSON processor doesn't fire on top of our shim; (b) pass a tolerant `json_deserializer` to the engine that strips outer single-quotes (the SQL-string-literal artefact) and falls back gracefully on parse failure. Validated against 276 tests in 15.68s — no regressions. Eliminates the gotcha for all current and future bare-string JSONB server_defaults.
- **2026-05-06 (Wave 2): Wave 2 commit shape (5 tests + 1 infra) instead of 5 tests.** The shim hardening surfaced mid-wave (during fuzzing service canary). Per Rule #25 spirit (per-file commit, independently revertable), shipped the hardening as its own commit (080c10d) BEFORE the fuzzing test commit (2febcc0). Two-line commit message ordering captures the dependency: shim change first, test that depends on it second.
- **2026-05-06 (Wave 2): Rule #30 source-patch confirmed for androguard.** test_androguard_service.py is the cleanest expression of Rule #30 — every Androguard symbol is lazy-imported INSIDE function bodies (lines 508, 523, 640, 861, 891). Patches MUST hit the SOURCE module (`androguard.misc.AnalyzeAPK`, `androguard.core.apk.APK`). Phase 1's pytest-unblock fleet (session 0801ca27, 2026-04-23) showed +620 tests unlocked once patch targets were corrected — same lesson applied here proactively.
- **2026-05-06 (Wave 3): Cross-project security boundary is a recurring canary pattern.** Three Wave 3 files canary the same shape (Firmware in project A → 404 via project B URL, CraAssessment same shape, EmulationSession same shape covered in Wave 2 emulation_router). The pattern is generic: any router with `<X>.project_id != project_id → 404` is a security boundary that mock tests trivially defeat (any UUID matches). Real-DB canary discipline catches the inverse: an unintentional comparison-operator flip (`==` → `!=`, or removing the check entirely) would silently leak rows to wrong-project URLs. Future router waves should default-canary this shape.
- **2026-05-06 (Wave 3): F-A-06 confidence-bypass backstop generalised.** Wave 3's test_attack_surface_router.py canaries the explicit `confidence="medium"` kwarg added by Stream A (audit-2026-05-04). The pattern recurs across persistence sites (Wave 1 vulnerability_service, Wave 1 attack_surface_router, Wave 1 apk_scan_router, Wave 1 assessment_service). Every site that constructs `Finding(...)` directly (not via `FindingService.create()`) needs an explicit confidence canary; the audit cited 5 such sites. Wave 3 closes the attack_surface site; Wave 1 covered the apk_scan and assessment_service sites; Wave 1 closed the vulnerability_service site. Remaining sites (if any) will be flagged in subsequent wave triage.

## Continuation State

**Next session pick-up:**
- Read this campaign file's Active Context + Feature Ledger.
- If Wave 1 shipped: review the user's go-ahead signal, then start Wave 2.
- If Wave 1 partial: resume from the next un-committed file in the wave.

**Per-wave kickoff:**
1. Read the target router/service file in full.
2. Identify lazy-imported symbols (Rule #30 grep).
3. Author `backend/tests/test_<X>.py` mirroring `test_hardware_firmware_router.py` + Phase 1 exemplars.
4. Run `docker cp` + `docker compose exec -T backend ... pytest tests/test_<X>.py -v > /tmp/out.txt 2>&1; cat /tmp/out.txt | tail -50` until green.
5. Commit per-file with `test(<module>): <summary> (N cases, +M LOC)`.

**checkpoint-wave-1: shipped** (commits d8f1e14..49a6d34, 5 test files + 1 fix, 85 cases all passing)
**checkpoint-wave-2: shipped** (commits dcedd33..2febcc0, 5 test files + 1 shim hardening, 90 cases all passing; cumulative 175 tests across waves 1+2)
**checkpoint-wave-3: shipped** (commits 1ca2bcf..bcadb28, 5 test files, 45 cases all passing in 4.04s combined; cumulative 220 tests across waves 1+2+3)
**checkpoint-wave-4: shipped** (commits a538079..b11b172, 5 test files, 48 cases all passing in 3.97s combined; cumulative 268 tests across waves 1-4)
**checkpoint-wave-5: pending** (will set after Wave 5 starts — final router wave)
