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

**Mode:** WAVE 9 SHIPPED — pause for review per user directive
**Current Wave:** 9 ✅ COMPLETE — fourth service wave (4 substantive + 1 skip)
**Next Wave:** 10 (services — remaining 3 of 26 audit-cited services to triage by LOC desc) when user gives go-ahead

**Wave 9 commits (clean-history):**
- `010d022` test(grype_service): 25 cases, +780 LOC (inverse-Rule-30; SbomVuln + Finding live-canary; F-A-06 confidence backstop)
- `0e34255` test(uart_service): 26 cases, +727 LOC (inverse-Rule-30; UARTSession ORM live-canary; bridge-unreachable disconnect regression backstop)
- `dc3feb1` test(sysroot_service): 39 cases, +420 LOC (pure-stdlib lookup tables; ARMv7 second-linker fallback canary)
- `48f0a2a` test(clamav_service): 21 cases, +538 LOC (Rule #30 SOURCE-patch via sys.modules; multiscan→fallback two-pass canary)

**Wave 9 totals: 111 tests across 4 files + 1 documented skip (virustotal_service) = 4 commits.**

**Cumulative across Waves 1-9: 860 tests across 38 files + multiple infra/fix commits = 49 commits.**

Audit citation: services covered = **23 of 26** (was 19/26 after Wave 8). Remaining 3 services for Wave 10 triage; if all 3 prove SKIP-worthy under Rule #19, Phase 2 services may close at Wave 9.

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

**Wave 5 commits (clean-history):**
- `18fbf74` test(projects_router): 5 cases, +234 LOC (create-project canary persists 2 default docs)
- `64bc3e0` test(health_router): 7 cases, +298 LOC (shallow + deep + ready probe parity)
- `72a7c38` test(kernels_router): 7 cases, +240 LOC (architecture whitelist)
- `90f2310` test(export_import_router): 7 cases, +215 LOC (ZIP streaming + import validation)
- `7b57ac5` test(component_map_router): 4 cases, +283 LOC (cache hit/miss + empty-graph no-cache)
- `be70ef0` test(compliance_router): 3 cases, +168 LOC (FINAL ROUTER WAVE — ETSI boundaries)

**Wave 5 totals: 33 tests across 6 files = 6 commits.**
**🎉 ROUTER HALF OF PHASE 2 COMPLETE — all 21 untested routers (audit F-G-03) now have HTTP-layer coverage.**

**Wave 6 commits (clean-history) — first service wave (top-5 by LOC):**
- `e3e6a6c` test(component_map_service): graph builder + Phase 3b partition prefix (56 cases, +543 LOC)
- `a8487af` test(pcap_analysis_service): scapy pipeline + 13 insecure-protocol rules (31 cases, +449 LOC)
- `114c249` test(jadx_service): subprocess CLI + cache hit/miss contract (18 cases, +452 LOC)
- `5196448` test(import_service): archive validation + remapped-UUID round-trip (14 cases, +414 LOC)
- `7ae2358` test(binary_analysis_service): Rule #30 hot zone — lief/pefile/cpu_rec SOURCE-patch (23 cases, +540 LOC)

**Wave 6 totals: 142 tests across 5 files all passing in 5.82s combined; 5 commits, +2,398 LOC of test code (production code unchanged).**

**Wave 7 commits (clean-history) — second service wave (next-5 by LOC):**
- `a5c1862` test(firmware_metadata_service): U-Boot/MTD/binwalk parser + cache canary (35 cases, +815 LOC) — Rule #35c JSONB hot zone with schema_version pop-and-assert
- `bffca93` test(compliance_service): ETSI EN 303 645 mapping + cross-project canary (31 cases, +627 LOC) — pure-logic service, recurring cross-project boundary canary
- `7edc860` test(kernel_service): filesystem kernel mgmt + SSRF + lifecycle canary (61 cases, +734 LOC) — full upload→initrd→list→get→delete cycle
- `f753a6f` test(report_service): markdown/HTML/PDF report rendering + Rule 30 weasyprint (29 cases, +619 LOC) — XSS canary on project.name AND firmware.original_filename; Rule #30 SOURCE-patch via sys.modules
- `8f8847e` test(selinux_service): policy walker + Rule 30 setools source-patch (32 cases, +727 LOC) — realistic Android tree fixture; explicit hasattr-sentinel against future inverse-Rule-30 drift

**Wave 7 totals: 188 tests across 5 files all passing in <2s combined per file; 5 commits, +3,522 LOC of test code (production code unchanged).**
**Cumulative Phase 2 totals: 631 tests + 1 production bug fix + 1 shim hardening = 40 commits across 7 waves.**

**Wave 7 full-suite smoke (suite-green wave-end gate):** `2605 passed / 6 skipped / 1 xfailed / 0 failed in 68.05s` (host-side) — was 2417 before Wave 7, +188 = exact match against the 5 wave files. No regression in any prior test file.

**Wave 8 commits (clean-history) — third service wave (next-5 by LOC, 4 substantive + 1 documented skip):**
- `d5d9d98` test(document_service): upload + note + create + read_text_content + Rule #30 pypdf source-patch (32 cases, +630 LOC)
- `258a08b` test(cwe_checker_service): docker sidecar wrapper + Rule 29 cache HIT/MISS contract (25 cases, +610 LOC)
- `96f192c` test(cpe_dictionary_service): NVD index + Redis cache + Rule #30 rapidfuzz source-patch (32 cases, +685 LOC)
- `1607606` test(qiling_service): format/arch mapping + subprocess parse + Rule #30 lazy analyze_binary source-patch (29 cases, +615 LOC)
- SKIP: `abusech_service` (326 LOC) — pure httpx external API client, no DB persistence/cache/non-stdlib lazy imports beyond `get_settings`. Documented as a no-op skip per Rule #19 evidence-first discipline (parallels the `emulation_constants` skip precedent at the 2026-05-06 Decision Log entry). Adding a pure-mock test for an external API call would verify only "httpx.AsyncClient.post was called" — the precise failure mode that Rule #35b live-canary discipline rejects. The 4 dataclass result types + 4 individual lookup functions + 1 enrich_iocs aggregator are entirely covered by black-box integration tests when ABUSECH_AUTH_KEY is configured.

**Wave 8 totals: 118 tests across 4 files + 1 documented skip = 4 commits, +2,540 LOC of test code (production code unchanged). All 118 cases pass in <5s combined per file.**

**Wave 8 full-suite smoke (suite-green wave-end gate):** `2723 passed / 6 skipped / 1 xfailed / 0 failed in 64.48s` (Docker container, `--ignore=tests/tests` to bypass a stale nested-directory artefact from prior `docker cp` invocations — see Decision Log 2026-05-07 entry below). Was 2605 before Wave 8, +118 = exact match against the 4 wave files (32+25+32+29). No regression in any prior test file.

**Cumulative Phase 2 totals: 749 tests + 1 production bug fix + 1 shim hardening = 44 commits across 8 waves.**

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
| 5 | tests/test_projects_router.py | 18fbf74 | 5 | 234 | POST / persists Project + WAIRZ.md + SCRATCHPAD.md (2 default Documents); a regression dropping one create_note call would silently break new-project bootstrap |
| 5 | tests/test_health_router.py | 64bc3e0 | 7 | 298 | All 4 deep-probe checks (db/redis/docker/storage) reported in body; per-component failure surfaces 503 with degraded status; /ready alias parity |
| 5 | tests/test_kernels_router.py | 72a7c38 | 7 | 240 | architecture whitelist (z80 → 400); empty file 400; service ValueError 400; happy path 201 |
| 5 | tests/test_export_import_router.py | 90f2310 | 7 | 215 | export streams ZIP with sanitized Content-Disposition (NO slashes); import accepts .wairz AND .zip; wrong extension rejected with helpful detail |
| 5 | tests/test_component_map_router.py | 7b57ac5 | 4 | 283 | cache-hit short-circuit (ComponentMapService NOT constructed); empty graph NOT cached (no stale-empty trap); non-empty IS cached |
| 5 | tests/test_compliance_router.py | be70ef0 | 3 | 168 | project + cross-project firmware_id boundaries on ETSI report endpoint |
| 6 | tests/test_component_map_service.py | e3e6a6c | 56 | 543 | ComponentNode (id/label/type/path/size/metadata.endianness/bits) + ComponentEdge (executes/configures) round-trip from real on-disk firmware tree; Phase 3b partition prefix; Rule #30 inverse case (CONSUMER patch on ELFFile) |
| 6 | tests/test_pcap_analysis_service.py | a8487af | 31 | 449 | PcapAnalysis from real wrpcap → PcapReader pipeline: total_packets exact, protocol_breakdown counts (Telnet=3 / HTTP=2 / DNS=2 / ICMP=1), every InsecureProtocolFinding (severity/port/packet_count/evidence), DnsQuery (domain/query_type/resolved_ips); MAX_PACKETS cap canary; Rule #30 inverse-case CONSUMER patch on PcapReader proven |
| 6 | tests/test_jadx_service.py | 114c249 | 18 | 452 | AnalysisCache rows: jadx_decompilation sentinel + jadx_source_tree + jadx_source:Main.java + jadx_all_sources; binary_sha256 lookup key; sentinel.status='complete' / jadx_returncode=0 / stats.total_source_files=1 round-trip; Rule #29 cache-HIT contract (call_count==1 after second call); Rule #30 source-patch on shutil.which |
| 6 | tests/test_import_service.py | 5196448 | 14 | 414 | Round-trip via real .wairz archive → ImportService → SELECT 7 ORM rows; UUID remapping (project/firmware/finding/document/preset/sbom_component all NEW); Finding.confidence 'medium' + None round-trip (F-A-06 width-canary on import path); Firmware storage_path + extracted_path use NEW IDs; FuzzingCampaign.status 'running'→'stopped' coercion; SBOM component FK remap |
| 6 | tests/test_binary_analysis_service.py | 7ae2358 | 23 | 540 | analyze_binary on /bin/ls (real x86_64 PIE ELF): format/arch/endianness/bits/is_static=False/is_pie=True/interpreter/libc-in-deps/entry_point all asserted; mocked-LIEF value-flow on _analyze_elf_lief (ARM dynamic / MIPS→mipsel coercion / static x86_64); check_pe_protections decodes all 6 DllCharacteristics flags via mocked pefile; cpu_rec source-patch + heuristic fallback; **Rule #30 hot zone documented** (3 lazy-imports, dedicated TestRule30LiefSourcePatch class) |
| 7 | tests/test_firmware_metadata_service.py | a5c1862 | 35 | 815 | Real on-disk firmware (uImage header + env block + mtdparts=) → scan_firmware_image → AnalysisCache row keyed by (firmware_id, op='firmware_metadata', binary_sha256 IS NULL); triage-pattern-#4 pop-and-assert on schema_version stamp (Rule #35c); 5-field payload round-trip through JSONB; cache-HIT contract (call_count==1 across 2 scans) — regression backstop for cache-key drift; Rule #30 inverse-consumer-patch class on `_cache.get_cached` |
| 7 | tests/test_compliance_service.py | bffca93 | 31 | 627 | 4 Findings across 2 Projects + 3 Firmware → generate_report walks real ORM; provision counts (pass/fail/partial/not_tested) sum to 13; cross-project boundary canary (project B's CWE-798 finding NEVER appears in project A's provision-1); firmware_id filter strict-subset canary; empty-project = 9 pass + 4 not_tested; created_at DESC ordering |
| 7 | tests/test_kernel_service.py | 7edc860 | 61 | 734 | Filesystem-as-DB lifecycle: upload kernel + initrd → list_kernels round-trip (architecture/description/uploaded_at/file_size/has_initrd) → get/find_kernel_for_arch → delete (binary AND sidecar removed atomically); SSRF matrix (private/loopback/link-local IPs rejected; gaierror; non-http(s); too-long URL); download_kernel happy path with real uImage bytes + HTTP error matrix (404 / size cap / empty / invalid format / RequestError) |
| 7 | tests/test_report_service.py | f753a6f | 29 | 619 | Real Project + Firmware + 4 Findings (severity tier × 4) → generate_markdown_report and generate_html_report contain every persisted field VALUE (project name/desc, sha256, original_filename, file_size as MB, every finding.title/cve_ids/cwe_ids/file_path:line_number/description/evidence); severity-section ordering canary (critical→info); XSS escaping canary on project.name AND firmware.original_filename; Rule #30 SOURCE-patch on weasyprint via sys.modules injection (verifies HTML(string=<rendered>).write_pdf() chain) |
| 7 | tests/test_selinux_service.py | 8f8847e | 32 | 727 | Realistic Android extracted tree (5 partitions, build.prop, plat_sepolicy.cil + vendor_sepolicy.cil + precompiled_sepolicy + odm policy.conf) → analyze_policy() end-to-end: typepermissive dedup across files, cil_stats counts (4 type / 2 allow / 1 neverallow / 1 transition / 3 typepermissive), enforcement source resolution (ro.boot.selinux precedence over ro.build.selinux), policy_files discovery (.cil + .conf + sepolicy/precompiled_sepolicy by exact filename); Rule #30 SOURCE-patch on lazy `import setools` via sys.modules + hasattr-sentinel against future top-level promotion |
| 8 | tests/test_document_service.py | d5d9d98 | 32 | 839 | Document filesystem-as-DB: real UploadFile fixture → upload → SELECT row asserts every persisted field (project_id/original_filename/content_type/file_size/sha256/description/storage_path); on-disk file contents match uploaded bytes; storage_path strictly contained under project documents dir (no traversal escape); update-in-place exempts count cap (regression backstop for "save WAIRZ.md after 20 docs"); delete is atomic (row + on-disk file in one operation, tolerates orphan); pypdf SOURCE-patch via sys.modules — full PDF round-trip from on-disk bytes → mocked PdfReader.pages → joined extracted text |
| 8 | tests/test_cwe_checker_service.py | 258a08b | 25 | 866 | Docker sidecar value-flow: real analysis_cache round-trip via _save_to_cache + _get_cached_result; happy path runs containers.run with image/command/volumes/network_mode=none/platform=linux/amd64/mem_limit verified against mock; ContainerError + ImageNotFound + RuntimeError exception matrix; --partial flag propagation for selective CWE checks; Rule #29 cache-MISS → cache-HIT contract via counting fake docker (call_count==1 stays 1 across 2 calls — regression on cache key drift fails LOUDLY); Rule #30 hasattr-sentinel against future top-level docker import |
| 8 | tests/test_cpe_dictionary_service.py | 96f192c | 32 | 829 | NVD CPE index value-flow: serialize/deserialize round-trip preserves dict + tuple shape; lookup_exact case-insensitive; rapidfuzz lazy-import via sys.modules SOURCE-patch (canary uses spy that asserts candidates lowercased BEFORE process.extract + score 92.0 → confidence 0.92 conversion); ImportError fallback (sys.meta_path blocker — wairz container does NOT install rapidfuzz) returns []; Redis HIT short-circuits httpx; Redis MISS schedules background download via asyncio.create_task; _download_and_cache happy path mocks 1 page of NVD JSON, populates index for 2 valid CPEs, skips wildcard product / malformed CPE / empty cpeName; result-dedup across candidate variants (same vendor+product emitted at most once) |
| 8 | tests/test_qiling_service.py | 1607606 | 29 | 691 | Format/arch → ostype/rootfs mapping table sanity (PE/Mach-O/ELF combinations; macho/aarch64 routes to arm64_ios); check_rootfs_status Windows DLL count gate; full subprocess JSON → QilingResult value-flow with multi-line stdout (debug log lines + final JSON line) verifies the split('\\n')[-1] parser; every QilingResult field including memory_errors / syscall_trace populated; subprocess timeout=inner+10s grace; dataclass default_factory isolation regression-backstop; Rule #30 SOURCE-patch on lazy `from app.services.binary_analysis_service import analyze_binary` (auto-detect path) + hasattr-sentinel against future top-level promotion of analyze_binary / qiling / QL_VERBOSE |
| 9 | tests/test_grype_service.py | 010d022 | 25 | 780 | Subprocess-driven vuln scanner with TOP-level ORM imports (inverse-Rule-30): SQLite live-canary seeds 2 SbomComponents → scan_with_grype runs full pipeline → SELECTs 2 SbomVulnerability rows + 1 Finding (F-A-06 confidence='high' backstop); CycloneDX 1.5 specVersion verified; vendor-mismatch filter (Grype vendor=cisco vs component CPE vendor=openssl → SKIP); error matrix (returncode 2 / timeout / malformed JSON); medium-only severity → NO Finding; delete-then-insert replaces stale CVEs |
| 9 | tests/test_uart_service.py | 0e34255 | 26 | 727 | Bridge proxy + UARTSession ORM live-canary: connect persists row with status/baudrate/transcript_path; bridge protocol verified by capturing JSON request bytes (newline terminator); single-active-session ValueError; **bridge-unreachable disconnect STILL marks row closed** (regression backstop); _bridge_request error matrix (open_connection failure → ConnectionError; empty response → ConnectionError; ok=False → ValueError); multi-step lifecycle live-canary (connect → send_command → disconnect) |
| 9 | tests/test_sysroot_service.py | dc3feb1 | 39 | 420 | Pure-stdlib lookup helper: SYSROOT_ARCH_MAP (x86 → i386 multiarch convention); DYNAMIC_LINKER_NAMES (ARMv7 covers BOTH armhf + soft-float); CORE_LIBS baseline; check_dependencies three modes (exact + versioned-symlink prefix-match libc-2.31.so↔libc.so.6 + theoretical); check_sysroot_in_container two-step exec_run gate with **ARMv7 second-linker fallback canary**; list_sysroot_contents stdout-decoding |
| 9 | tests/test_clamav_service.py | 48f0a2a | 21 | 538 | Lazy `import clamd` SOURCE-patch via sys.modules: check_available ping=PONG / WAT / raises matrix; **scan_directory two-pass canary — multiscan→fallback to per-file cd.scan()** (regression backstop for clamd container restart mid-batch; tracks scan_calls list); fallback per-file exception captured without aborting batch; both-failed → single error sentinel; max_files cap + non-regular-file (S_ISREG) skip + oversized-file (>100 MB) skip |

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

- **2026-05-06 (Wave 6): Inverse-Rule-30 case generalises beyond assessment_service.** Three of the five Wave 6 services exhibit the inverse-Rule-30 shape: `component_map_service.py` imports `elftools.elf.elffile.ELFFile` at module scope; `pcap_analysis_service.py` imports every scapy symbol (`PcapReader`, `IP`, `TCP`, `UDP`, `DNS`, `Raw`, `ARP`, `ICMP`, `DNSQR`) at module scope; `import_service.py` imports its full ORM model surface at module scope. For all three, patches MUST hit the CONSUMER module — `app.services.<X>.<Symbol>` — not the SOURCE. Per the Wave 1 documentation in `test_assessment_service.py:200`, the test_pcap_analysis_service.py adds a dedicated `TestRule30InverseConsumerPatch` class proving the consumer patch is the correct target. **Distribution observed in Wave 6: 3 inverse-case + 2 source-case = 5/5 services. The campaign now has reference exemplars for both shapes.** The Rule #30 wording in CLAUDE.md may benefit from a follow-up "Inverse Rule #30" sub-rule covering module-scope imports, but Wave 6 documents the pattern in-line for now.

- **2026-05-06 (Wave 6): Real-binary canary stronger than synthetic ELF.** `test_binary_analysis_service.py` initially used synthetic ELF byte fixtures (`_build_real_elf` helper writing a minimal ELF header). LIEF parsed them but `binary.header.machine_type` returned a raw int instead of the `lief.ELF.ARCH` enum, so the architecture map miss returned `None`. Switched to `/bin/ls` from the container — a real x86_64 PIE ELF with libselinux/libcap/libc deps + /lib64/ld-linux-x86-64.so.2 interpreter. Every field in `analyze_binary`'s result dict round-trips against actual production attributes. Companion lesson to Rule #35b: when the canary requires real binary parsing, use a real binary in the test environment rather than a synthetic fixture — synthetic fixtures pass syntactically but fail value-flow assertions because parsers don't recognise their malformed enums. Filed as a candidate Rule for the post-campaign knowledge extraction.

- **2026-05-06 (Wave 6): LIEF arch-map autouse-prime fixture.** `_LIEF_ELF_ARCH_MAP` and `_LIEF_PE_ARCH_MAP` are module-level dicts that start EMPTY at import (line 16-17) and lazy-populate via `_ensure_lief()`. Test `test_second_call_short_circuits` legitimately sets `_lief_loaded=True` to exercise the short-circuit branch — but if that runs before any test that calls `analyze_binary`, the maps are empty and `architecture` returns None. Solution: an autouse fixture (`_prime_lief_maps`) that resets `_lief_loaded=False`, clears both maps, and re-runs `_ensure_lief()` before each test. Pattern applies to any service with module-level lazy-init state that tests can inadvertently corrupt. Documented in test_binary_analysis_service.py:160.

- **2026-05-07 (Wave 7): Wave 7 distribution = 3 inverse-Rule-30 + 2 source-patch (matches Wave 6 exactly).** firmware_metadata_service / compliance_service / kernel_service all import their dependencies at MODULE scope → CONSUMER-module patch shape; report_service / selinux_service both lazy-import (`weasyprint` at line 362, `setools` at line 283) → SOURCE-module patch via `patch.dict(sys.modules, {"<lib>": fake})`. The 3-inverse + 2-source split persisted across both service waves with zero outliers — strong evidence the pattern is the natural distribution and not a sampling artifact. Future waves should NOT assume a particular distribution; grep the imports per Rule #30 mechanical check before authoring each test.

- **2026-05-07 (Wave 7): `sys.modules` injection is the canonical Rule #30 SOURCE-patch for lazy-imported third-party modules.** Wave 6 jadx used `patch.object(jadx_service, "get_settings", ...)` for its lazy-imported `shutil.which`; Wave 7 introduces a stronger pattern for full-module replacement: `with patch.dict(sys.modules, {"weasyprint": fake_weasyprint})` and `{"setools": fake_setools}`. The `import weasyprint` / `import setools` inside the function body resolves through `sys.modules` first, so the fake module is picked up cleanly. **Companion sentinel test** documented in test_selinux_service.py:`TestRule30SetoolsSourcePatch.test_consumer_module_has_no_setools_attribute` — explicit `not hasattr(slx_mod, "setools")` assertion that catches a future refactor promoting the import to top-level (which would flip the patch shape to inverse-Rule-30 and silently break the existing patches). The sentinel pattern generalises: any test using sys.modules-injection should pair it with a hasattr-sentinel that fails LOUDLY when the consumer module grows the symbol.

- **2026-05-07 (Wave 7): Triage-pattern-#4 schema_version pop-and-assert applied prophylactically to JSONB-stamped cache rows.** `firmware_metadata_service.scan_firmware_image` writes through `_cache.store_cached`, which calls `_stamp_analysis_cache_result` (jsonb_normalizers.py:134). Tests asserting on the persisted `result` dict use `persisted = dict(row.result); stamp = persisted.pop("schema_version"); assert stamp == ANALYSIS_CACHE_RESULT_SCHEMA_VERSION` — the pattern from the test-maintenance-triage Group A fix. When the schema bumps to 2, the assertion fails with a specific stamp-mismatch signal rather than a confusing 5-field structural diff. Audit consumers across the codebase have to walk concurrently, but the test side is now already future-proof. Applies to: any test asserting on a JSONB column wrapped in a stamper helper.

- **2026-05-07 (Wave 7): Pre-existing tests audit — no new triage candidates surfaced.** Full-suite smoke (Wave 7) returned 2605 passed / 6 skipped / 1 xfailed / 0 failed in 68.05s. Delta vs the 2417-passed baseline (post-Wave-6 triage cleanup at commit a607908) is exactly +188 = 35+31+61+29+32 — accounting for every Wave 7 test with no regression in any prior-wave file. The triage-pattern-#1 (full-suite as wave-end gate) discipline is paying off: a clean delta confirms no new drift was introduced AND no pre-existing drift surfaced from the new test files. Wave 8 starts from a clean 2605-pass baseline.

- **2026-05-07 (Wave 8): abusech_service skipped per Rule #19 evidence-first.** abusech_service.py (326 LOC) is a pure httpx external API client across 4 services (MalwareBazaar / ThreatFox / URLhaus / YARAify). Mechanical Rule #30 grep confirmed: `httpx` is the only external dependency, top-level imported (line 18); no DB persistence, no cache, no lazy-imported third-party libs (only the consistent `from app.config import get_settings` per-call lazy-init for the auth key — that pattern is already canaried in 5+ Wave 1-7 service files). Authoring a pure-mock test for an external API call would verify only "httpx.AsyncClient.post was called with the right URL" — exactly the value-flow gap that Rule #35b live-canary discipline rejects (the response shape is dictated by the abuse.ch API, not by any code we wrote). The 4 dataclass result types (MalwareBazaarResult / ThreatFoxResult / URLhausResult / YARAifyResult) are passed-through wrappers; their value-flow is "JSON dict → dataclass field" which mock tests CAN verify but adds zero canary-strength against production drift. Skip parallels the `emulation_constants` precedent (Decision Log 2026-05-06): pure-coordinator surfaces with no persistence/cache/lazy-import are documented no-op skips, not silent gaps.

- **2026-05-07 (Wave 8): Distribution = 4 SOURCE-patch + 0 inverse-Rule-30 (different from Waves 6+7 split).** Wave 6 + Wave 7 each shipped 3-inverse-Rule-30 + 2-source-patch. Wave 8 shipped 4 SOURCE-patch services (pypdf in document_service, docker in cwe_checker_service, rapidfuzz in cpe_dictionary_service, analyze_binary in qiling_service) — none of the substantive 4 files exhibit the inverse-Rule-30 module-scope-import shape. The pattern: smaller services (279-355 LOC, all in Wave 8) tend toward MORE lazy imports (defer cold-import cost; optional dependencies; subprocess/external-tool boundaries) while the larger services (>500 LOC, predominant in Waves 6+7) tend toward MODULE-scope imports (the cold-import cost is amortised across many surfaces). NOT a new rule — just an observation that distribution drifts with service size + complexity. The Rule #30 mechanical grep before authoring each test caught this in 4/4 Wave 8 files; Rule #30 discipline holds regardless of distribution.

- **2026-05-07 (Wave 8): `sys.modules`-injection + hasattr-sentinel pattern is the canonical Wave 7+8 SOURCE-patch shape.** Every Wave 8 file uses `patch.dict(sys.modules, {"<libname>": fake_module})` for full-module replacement (pypdf / rapidfuzz / qiling-via-analyze_binary's source module) AND pairs it with a `TestRule30...SourcePatch` class containing `assert not hasattr(<consumer_module>, "<libname>")`. The sentinel makes refactor drift LOUD: if a future PR moves the import to module-scope (e.g. to simplify testing or to remove the cold-import cost), the hasattr assertion fails immediately, signalling the patches must migrate to the inverse-Rule-30 shape (`patch.object(consumer_mod, "<libname>", ...)`). 4 Wave 8 files all use this pattern (document_service / cwe_checker_service / cpe_dictionary_service / qiling_service). Cumulative across Waves 6+7+8: 7 SOURCE-patch services (jadx + binary_analysis from Wave 6; report + selinux from Wave 7; document + cwe_checker + cpe_dictionary + qiling from Wave 8) — pattern is durable.

- **2026-05-07 (Wave 8): Stale `/app/tests/tests/` directory in the backend container — environmental cleanup, not a regression.** Wave 8 full-suite smoke initially reported 27 failures from `/app/tests/tests/test_*.py` paths. Investigation (path inspection + file count): the stale dir contains 87 test files copied via `docker cp host/path/test.py <container>:/app/tests/test_X.py` from prior sessions where the host CWD apparently included a `tests/` prefix (e.g. running `docker cp` from inside `backend/`). The copied files landed in `/app/tests/tests/` instead of `/app/tests/` and were never cleaned up. They contain stale code that no longer matches current production imports — failures are NOT real regressions in any current test file. Cleaned up via `docker compose exec backend rm -rf /app/tests/tests`. Wave-end smoke re-run with `--ignore=tests/tests` returned 2723 passed / 0 failed (118 = exact Wave 8 delta over the 2605 Wave-7-baseline). The `docker cp` invocations during Wave 8 itself used the host-relative `backend/tests/test_*.py` path, which lands in `/app/tests/test_*.py` correctly — the stale dir is from BEFORE this session. Companion lesson: when running `docker cp` during a long campaign, audit the destination occasionally to catch path-prefix drift; safer for future waves to use `docker cp <host-absolute>:test_X.py <container>:/app/tests/test_X.py` (already done in Wave 8 commands). No production code changes; no test changes; no campaign-state implications beyond this Decision Log entry.

- **2026-05-07 (Wave 8): Recurring fuzzy-match value-flow canary pattern documented.** test_cpe_dictionary_service.py introduces a new live-canary shape — verifying the candidate-generation logic + score-conversion logic via a SPY function inside the fake rapidfuzz module. The spy: (a) appends each candidate to a list at extract-call time so the test can assert lowercased-input invariant; (b) returns a fixed score so the test can assert score 92.0 → confidence 0.92 (i.e. division by 100, not 1000 or 10); (c) the value flows back through the index dict so the test can assert (vendor, product, cpe23) round-trip. This shape generalises to ANY service that lazy-imports a scoring/parsing library (rapidfuzz, fuzzywuzzy, scipy.stats, sklearn) and does value-flow over its return shape. Worth promoting to a future CLAUDE.md sub-rule of #35b: "spy-fake at the SOURCE module + fixed deterministic return value" enables value-flow assertions that mock-only tests cannot make. Filed for post-campaign knowledge extraction.

- **2026-05-08 (Wave 9): virustotal_service skipped per Rule #19 evidence-first — mirrors abusech_service precedent.** virustotal_service.py (224 LOC) is a pure httpx-based external API client (VirusTotal v3 hash-lookup endpoint). Mechanical Rule #30 grep: ONLY top-level third-party import is httpx; the lazy `from app.config import get_settings` at line 44 is the per-call settings access pattern already canaried in 6+ Wave 1-8 service files. NO DB persistence (returns dataclass VTResult, never persists), NO cache. Authoring a pure-mock test would verify only "httpx.AsyncClient.get was called with X-VT-API-Key header" — exactly the value-flow gap that Rule #35b live-canary discipline rejects (VT response shape is dictated by the VirusTotal API, not by any code we wrote; the dataclass field-mapping is straightforward `data["attributes"]["last_analysis_stats"]["malicious"] → detection_count` which mock tests CAN verify but adds zero canary-strength against production drift). Skip parallels Wave 8's abusech_service decision (Decision Log 2026-05-07) and Wave 1's emulation_constants decision (2026-05-06). The hash-computation + ELF/PE filewalk in `collect_binary_hashes` has SOME canary value (priority order libs > executables > others) but mirrors the file-collection logic already canaried in clamav_service's scan_directory tests this same wave — duplicating it without persistence/cache wraparound adds no marginal canary strength.

- **2026-05-08 (Wave 9): Distribution = 2 inverse-Rule-30 + 1 SOURCE-patch + 1 pure-stdlib (different from both Wave 6+7's 3+2 and Wave 8's 4+0).** grype_service + uart_service have TOP-level imports of asyncio + ORM models → inverse-Rule-30 shape (CONSUMER-module patches). clamav_service has lazy `import clamd` (lines 39 + 51) → Rule #30 SOURCE-patch via sys.modules. sysroot_service has only stdlib imports (logging/os/typing.Any) → no patching needed for third-party deps; tests provide a MagicMock container directly. The Wave-1-through-9 cumulative pattern: distribution drift across waves continues to confirm that the Rule #30 mechanical grep BEFORE authoring each test is the only durable check — every wave has surprised on at least one file vs the predicted distribution. Wave 9's pre-authoring prediction was "smaller services → more lazy imports → SOURCE-patch predominant"; ACTUAL was 1 SOURCE / 2 INVERSE / 1 NEITHER. The intuition (smaller-LOC → more-lazy) does NOT hold reliably; ORM-persistence presence is a stronger predictor (services that write to the DB tend toward TOP-level ORM imports → inverse-Rule-30).

- **2026-05-08 (Wave 9): Two-pass pipeline canary pattern documented.** clamav_service.scan_directory has a two-pass shape (multiscan → per-file fallback) that mock-only tests cannot differentiate without explicit canary on the second-pass code path. test_clamav_service.py's `test_multiscan_raises_falls_back_to_per_file_scan` tracks a scan_calls list inside the fake clamd socket to verify the fallback uses `cd.scan()` not `cd.multiscan()` — a regression where someone swaps the method in the except branch (Python's catch-all `except Exception:` is wide enough to mask this) would silently return clean results. The pattern generalises to any service with a primary-then-fallback dispatch shape: capture call-order in a list inside the mock and assert on the sequence post-execution. Likely future applications: any HTTP retry logic with method swap, any subprocess fallback (POSIX → Windows path), Redis-MISS → DB-read fallback in cache layers.

- **2026-05-08 (Wave 9): Pre-existing failures NOT attributable to Wave 9.** Full-suite smoke surfaced 12 failures: 11 in `test_status_check_constraint_alignment.py` (alembic constraint references — caused by the post-Wave-8 `bd4dff9 fix(alembic): repair revision chain` and `a255a8b feat(sbom): add vuln scan status columns + CHECK constraint` commits introducing new constraint names that the alignment test's allowlist hasn't been updated for); 1 in `test_rate_limit_tiers.py` (looking for `@router.post("/vulnerabilities/scan"` which was renamed during the post-Wave-8 `8f54a24 refactor(sbom): convert vuln scan to 202+polling per Rule #33`). Verified by running ONLY the 4 Wave 9 test files in isolation — 111/111 pass cleanly. Wave 9 contributes +111 cases / 0 regressions. The 12 pre-existing failures are independent of this campaign and belong to whichever future session closes the audit-2026-05-04 vuln-scan migration intake; they do NOT block Wave 9 close.

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
**checkpoint-wave-5: shipped** — **ROUTER HALF COMPLETE** (commits 18fbf74..be70ef0, 6 test files, 33 cases all passing in 3.41s combined; cumulative 301 tests across waves 1-5; all 21 audit-cited untested routers now covered)
**checkpoint-wave-6: shipped** — first service wave (commits e3e6a6c..7ae2358, 5 test files, 142 cases all passing in 5.82s combined; cumulative 443 tests across waves 1-6; top-5 services by LOC × value-flow surface now have full live-canary coverage). Distribution: 3 inverse-Rule-30 services (component_map / pcap_analysis / import) + 2 source-patch services (jadx + binary_analysis). Pause for review per user directive.
**checkpoint-wave-7: shipped** — second service wave (commits a5c1862..8f8847e, 5 test files, 188 cases all passing; cumulative 631 tests across waves 1-7; firmware_metadata + compliance + kernel + report + selinux services now have full live-canary coverage). Distribution: 3 inverse-Rule-30 services (firmware_metadata / compliance / kernel) + 2 source-patch services (report / selinux) — exact match to Wave 6 distribution. Full-suite smoke 2605 passed / 6 skipped / 1 xfailed / 0 failed in 68.05s — exactly +188 over baseline. Pause for review per user directive.
**checkpoint-wave-8: shipped** — third service wave (commits d5d9d98..1607606, 4 substantive test files + 1 documented skip, 118 cases all passing; cumulative 749 tests across waves 1-8; document + cwe_checker + cpe_dictionary + qiling services now have full live-canary coverage; abusech_service skipped per Rule #19 — pure httpx external client with no persistence/cache/non-stdlib lazy imports). Distribution: 4 SOURCE-patch services (pypdf / docker / rapidfuzz / analyze_binary) + 0 inverse-Rule-30 — different from Waves 6+7's 3+2 split because Wave 8 covers smaller services (279-355 LOC) that tend toward more lazy imports. Full-suite smoke 2723 passed / 6 skipped / 1 xfailed / 0 failed in 64.48s (Docker container, --ignore=tests/tests bypassing a stale nested-dir artefact from prior `docker cp` invocations — cleaned up at wave-end) — exactly +118 over baseline. Audit citation: services covered = 19 of 26 (was 15/26 after Wave 7). Pause for review per user directive.
**checkpoint-wave-9: shipped** — fourth service wave (commits 010d022..48f0a2a, 4 substantive test files + 1 documented skip, 111 cases all passing in 3.63s isolated; cumulative 860 tests across waves 1-9; grype + uart + sysroot + clamav services now have full live-canary coverage; virustotal_service skipped per Rule #19 — pure httpx external client mirroring abusech precedent). Distribution: 2 inverse-Rule-30 (grype + uart, both have TOP-level ORM imports) + 1 SOURCE-patch (clamav, lazy `import clamd` × 2 sites) + 1 pure-stdlib (sysroot, no third-party deps). Pre-authoring prediction "smaller LOC → more SOURCE-patch" did NOT hold; ORM-persistence-presence proved the stronger predictor for inverse-Rule-30 shape. Full-suite smoke 2827 passed + 12 PRE-EXISTING failures + 6 skipped + 1 xfailed in 80.49s; the 12 failures are from post-Wave-8 alembic chain repair (`bd4dff9`) + sbom 202+polling refactor (`8f54a24`) + new vuln_scan CHECK constraint (`a255a8b`), all UNRELATED to Wave 9 — verified by running ONLY the 4 Wave 9 files (111/111 pass cleanly). Audit citation: services covered = 23 of 26 (was 19/26 after Wave 8). Pause for review per user directive.
