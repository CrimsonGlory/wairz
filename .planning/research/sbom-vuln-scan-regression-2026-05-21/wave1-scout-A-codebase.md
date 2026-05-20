# Wave-1 Scout A — Codebase Current State (CODEBASE persona)

> Investigation date: 2026-05-21
> Scope: Reconstruct end-to-end SBOM + vuln-scan flow today
> Branch tip: `4ecaa5b` (main); baseline for Rule #47 cross-ref: `847eae9`

## Executive Summary

The SBOM generation + vulnerability scanning subsystems in wairz are **user-driven, not auto-triggered**. POST `/sbom/generate` and POST `/sbom/vulnerabilities/scan` are the only entry points — there is NO post-extraction hook that fires either pipeline. **The `WALKER_AUTO_TRIGGERS` registry at `backend/app/workers/walker_registry.py:100-147` does NOT include `sbom` or `vuln_scan`** — it covers 22 forensic walkers (registry hives, EVTX, AppCompat, BCD, DPAPI, EFS, ESP, ETL, journald, persistence, LNK, MBR/VBR, MFT, prefetch, scheduled_task, SDB, SRUM, systemd, USN journal, WMI, container, plus three λ memory-image walkers). Neither `_post_process_pipeline` (`backend/app/services/firmware_service.py:544-822`) nor `_run_hardware_firmware_detection_safe` (`backend/app/workers/unpack.py:74-154`) calls `SbomService.generate_sbom()` or `scan_with_grype()`. **This is NOT a Rule #47 orphan** — SBOM/vuln-scan never had auto-trigger registration; they have always been operator-initiated via the SBOM page. **The actual regression risk vector is therefore in (a) the user-driven endpoints themselves, (b) the data they read (which IS produced by extraction/walker pipelines), (c) cve_matcher's curated-tier YAML matching, or (d) the frontend render of the data.** The HARDEST suspect surface is the recent rate-limit tier split (`f6dbc7b`) + frontend changes that may interact with the polling loop, plus the SbomComponent UniqueConstraint that has no `ON CONFLICT` handling.

## End-to-End Flow Reconstruction

### 1. Upload → Unpack

Two distinct paths exist today, BOTH terminate at `_run_hardware_firmware_detection_safe`:

**Upload path (Rule #33 202+polling)** — `backend/app/routers/firmware.py:133-176`:
- `POST /api/v1/projects/{project_id}/firmware` → `upload_bytes_only` (writes bytes + creates Firmware row in `upload_stage='detecting'`) → `asyncio.create_task(_run_upload_post_processing_background(firmware.id))` → returns 202.
- `_run_upload_post_processing_background` at `firmware_service.py:875-937` opens its own AsyncSession and calls `_post_process_pipeline(db, row, update_stage=True)`.

**Unpack path (legacy + arq)** — `backend/app/routers/firmware.py:251-301`:
- `POST /api/v1/projects/{project_id}/firmware/{firmware_id}/unpack` → arq `unpack_firmware_job` OR `_run_unpack_background` → full unblob/binwalk extraction → at line 440-445 fires `_run_hardware_firmware_detection_safe`.

State transitions on the upload path: `detecting` → `extracting` → `analyzing` → `ready` | `failed` (`firmware_service.py:566,581,778,807,926`). Polling endpoint at `routers/firmware.py:179-198`.

### 2. _post_process_pipeline

`backend/app/services/firmware_service.py:544-822`. Body sequence:
- Format detection via `detect_format()` (line 570).
- Tarball shortcut (`is_tar` check at line 589, full extract via `tarfile.extractall`).
- ZIP shortcut: rootfs ZIP vs Android OTA vs generic ZIP (lines 663-759). Generic ZIP extracts to `zip_contents/` and assigns `firmware.extracted_path = zip_root` (line 754 — this is the 2026-05-18 walker-bridge fix).
- Architecture / endian / OS detection + `populate_detection_roots(firmware)` (line 797).
- Final stage `ready` at line 807 + commit.
- **At line 818-822: `asyncio.create_task(_run_hardware_firmware_detection_safe(firmware.id, firmware.extracted_path))`** — this is the ONLY post-pipeline trigger. There is NO SBOM or vuln-scan call.

The pipeline does NOT call `unpack_firmware()` (binwalk/unblob extraction). Format-specific deep extraction only runs when the operator clicks "Unpack" → POST `/unpack` → arq job. The upload path handles tarballs and ZIPs only.

### 3. WALKER_AUTO_TRIGGERS Registry

`backend/app/workers/walker_registry.py:100-147` — full enumeration:
1. `registry_auto_walk` (γ.4)
2. `auto_extract_drivers_safe` (γ.5)
3. `evtx_auto_walk` (ε.1.b.4)
4. `auto_appcompat_walk_firmware_safe` (κ.B)
5. `auto_bcd_walk_firmware_safe` (θ.A)
6. `auto_dpapi_walk_firmware_safe` (κ.D)
7. `auto_efs_walk_firmware_safe` (ι.D)
8. `auto_esp_walk_firmware_safe` (θ.C)
9. `auto_etl_walk_firmware_safe` (ι.C)
10. `auto_lnk_walk_firmware_safe` (η.C)
11. `auto_mbr_vbr_walk_firmware_safe` (θ.B)
12. `auto_memory_image_enumeration_safe` (λ.α.B)
13. `auto_windows_info_walk_firmware_safe` (λ.α.D)
14. `auto_windows_processes_walk_firmware_safe` (λ.β)
15. `auto_windows_injection_walk_firmware_safe` (λ.γ)
16. `auto_mft_walk_firmware_safe` (η.A)
17. `prefetch_auto_walk` (ζ.2)
18. `auto_scheduled_task_walk_firmware_safe` (η.E)
19. `auto_sdb_walk_firmware_safe` (θ.D)
20. `srum_auto_walk` (ζ.3)
21. `auto_usnjrnl_walk_firmware_safe` (κ.E)
22. `auto_wmi_walk_firmware_safe` (η.C — note name shared with LNK in registry comments)
23. `auto_container_walk_firmware_safe` (ι.E)
24. `auto_journald_walk_firmware_safe` (ι.A)
25. `auto_linux_persistence_walk_firmware_safe` (κ.C)
26. `auto_systemd_walk_firmware_safe` (ι.B)

**No `auto_sbom_generate` or `auto_vuln_scan` entries — never have been.** The cve_matcher / hw-fw flow is also not in this registry (it's operator-driven via `POST /hardware-firmware/cve-match`).

### 4. SBOM Generation Job

There is no `_sbom_generate_job` (no arq job). Only the synchronous `POST /api/v1/projects/{project_id}/sbom/generate` endpoint at `backend/app/routers/sbom.py:115-225`:
- Decorated `@limiter.limit(TIER_A_LIGHT_ACK)` (30/hour, changed from `TIER_A_HEAVY` in commit `f6dbc7b` 2026-05-18).
- If `force_rescan=False` and existing rows exist → return cached.
- If `force_rescan=True` → `delete(SbomComponent).where(firmware_id == ...)` (line 144).
- Calls `get_detection_roots(firmware, db=db)` (line 153) to populate JSONB cache.
- `SbomService(firmware=firmware)` constructor (line 154; service.py:87-138 resolves `_detection_roots` from `device_metadata['detection_roots']` JSONB cache OR falls back to `firmware.extracted_path`).
- `await loop.run_in_executor(None, service.generate_sbom)` (line 157) — runs all 12 strategies sync (Syft + Dpkg + Opkg + Python + Kernel + FirmwareMarkers + BusyBox + CLibrary + Gcc + SoFiles + BinaryStrings + Android per `service.py:68-85`).
- RTOS injection block at lines 165-198 (parses `firmware.os_info` JSON → adds operating-system + companion component dicts).
- Per-component DB insert at lines 201-215 (no `ON CONFLICT` handling — relies on `force_rescan` delete).
- Returns components with vuln counts (line 220 → composite query `_components_with_vuln_counts_stmt`).

**`SbomService.generate_sbom()`** at `services/sbom/service.py:239-301` iterates `_STRATEGY_CLASSES` then runs `annotate_service_risks` + `enrich_cpes` post-processors. Returns list of dicts.

### 5. Vulnerability Scanning Job

Similarly no arq job; only the 202+polling `POST /sbom/vulnerabilities/scan` at `backend/app/routers/sbom.py:522-586`:
- Decorated `@limiter.limit(TIER_A_LIGHT_ACK)` (changed from TIER_A_HEAVY in `f6dbc7b`).
- 400 if no SBOM components exist for firmware (line 560-563).
- 409 if `vuln_scan_status` already `queued` or `running` (line 565-569).
- Flips to `queued` + commit → `asyncio.create_task(_run_vuln_scan_background(firmware.id, project_id, force_rescan))`.

**Background runner `_run_vuln_scan_background`** at `routers/sbom.py:418-519`:
- Flips status `queued → running` (line 454).
- Reads `settings.vulnerability_backend` (default `"grype"` per `config.py:56`); calls `grype_available()` (PATH lookup for grype binary).
- If grype available → `scan_with_grype(firmware_id, project_id, db)` (`services/grype_service.py:60-265`).
- Else → `VulnerabilityService(db).scan_components(firmware_id, project_id, force_rescan)` (NVD-API path, `services/vulnerability_service.py:60-144`).
- Flips status `running → completed` or `running → failed` (with traceback) on a fresh AsyncSession.

**`scan_with_grype`** at `services/grype_service.py:60-265`:
- Loads all `SbomComponent` rows (line 78).
- Writes CycloneDX 1.5 SBOM to a NamedTemporaryFile (line 116).
- `await asyncio.create_subprocess_exec("grype", f"sbom:{sbom_path}", "-o", "json", "--quiet", ...)` with `timeout=settings.grype_timeout` (120 s default).
- Parses Grype JSON → inserts `SbomVulnerability` rows (line 213-222) with `match_tier=None`.
- If `critical+high > 0`, emits ONE `Finding(source="sbom_scan")` per scan (lines 229-253). Confidence + firmware_id explicit per Rule #35b/F-A-06.

**`VulnerabilityService.scan_components`** at `services/vulnerability_service.py:60-144`:
- Per-component NVD HTTP query via `_query_nvd_for_component`, rate-limited at `RATE_LIMIT_NO_KEY=1.7s` or `RATE_LIMIT_WITH_KEY=0.17s` based on `NVD_API_KEY` env (line 22-24).
- `force_rescan=True` → deletes existing `Finding(source="sbom_scan")` + `SbomVulnerability` rows (line 82-92).
- `_create_findings_from_vulns` at line 287-399 groups vulns by component, only emits findings for critical/high or 3+ medium (line 339).
- One Finding per qualifying component; links each `SbomVulnerability.finding_id` back to the new Finding.

### 6. Findings Emit

The CVE-bearing flow (`scan_with_grype` line 236 + `vulnerability_service._create_findings_from_vulns` line 365) constructs `Finding(...)` directly with `source="sbom_scan"` rather than going through `FindingService.create()`. Direct construction is gated by the Rule #35b/F-A-06 discipline (explicit `confidence` + `firmware_id` in every call). The `Finding` row then propagates through:
- `POST /api/v1/projects/{project_id}/findings` (`routers/findings.py:33-42`) for operator-created findings.
- `Finding.firmware_id` filter at `vulnerability_service.py:5662` for list queries.

`FindingService.create()` at `services/finding_service.py:5619-5642` writes `firmware_id`, `confidence`, `source`, `component_id` etc. unchanged from the `FindingCreate` payload. **finding_service.py is 7904 LOC** (started growing significantly per commits κ.B-κ.E).

### 7. Frontend Render

`frontend/src/pages/SbomPage.tsx` (single page covering both components AND vulnerabilities):
- Polls `getSbomComponents` + `getVulnerabilitySummary` on mount (line 89-107).
- "Generate SBOM" → `generateSbom(projectId, force, fwId)` with `timeout: SECURITY_SCAN_TIMEOUT` (600_000 ms).
- "Run scan" → `runVulnerabilityScan(...)` (no timeout override — `_run_vuln_scan_background` returns 202 sub-second per `sbom.ts:82-101`).
- Polling effect at line 190-225 (`useEffect` with 2 s `setInterval`) on `vuln_scan_status`. Status `completed` → reload data + `setScanning(false)`. Status `failed` → toast.error + stop.
- 409 conflict on scan POST is benignly absorbed (line 174-184) — falls through to polling.

`frontend/src/pages/SecurityScanPage.tsx` is a DIFFERENT page (covers security audit + YARA + attack-surface tabs, NOT SBOM). Audit goes to `runSecurityAudit` → `/security/audit` (synchronous, TIER_A_HEAVY).

`frontend/src/api/sbom.ts`:
- All 7 SBOM endpoints declare `timeout: SECURITY_SCAN_TIMEOUT` on long-ops, default 30 s axios floor on `runVulnerabilityScan` (correct — 202 ack).
- `unwrap()` helper at line 24-26 handles both `Page<T>` envelope AND legacy `T[]` shapes for backward compatibility.

`frontend/src/utils/error.ts` `extractErrorMessage` at lines 12-22 handles `resp.data.hint` (SlowAPI structured) → `resp.data.detail` (FastAPI HTTPException) → `resp.data.error` (SlowAPI 429 raw). Correct.

## Consumer Hook Enumeration (Rule #47)

For `sbom_status` (does not exist in firmware model — UNCLEAR; defer to Scout C):

Mid-read: there is no `firmware.sbom_status` column. The Firmware model at `backend/app/models/firmware.py:21-100+` has `unpack_stage`, `cve_match_status`, `vuln_scan_status`, `upload_stage`, `authenticode_chain_status`, `registry_hive_walk_status`, `dotnet_decompile_status`, plus many more per-walker `*_walk_status` — **but NO `sbom_status`**. SBOM generation has no row-level state column; existence of `SbomComponent` rows IS the state.

For `vuln_scan_status`:
- WIRED — `backend/app/main.py:202-242` orphan reaper (added per scout 2 audit 2026-05-18).
- WIRED — `backend/app/routers/sbom.py:454,487,508,565,571` state transitions + 409 guard.
- WIRED — `backend/app/schemas/sbom.py:108` Pydantic Literal + migration `c1d2e3f4a5b6` DB CHECK constraint.
- WIRED — frontend polling at `SbomPage.tsx:190-225` reads via `getVulnerabilityScanStatus`.

For `sbom_components` table (model `backend/app/models/sbom.py:21-62`):
- WRITERS: `routers/sbom.py:202-215` (operator-triggered generate); `services/assessment_service.py:340-353` (assessment-service comprehensive scan triggered from `routers/cra_compliance.py`).
- READERS: `routers/sbom.py:62-77,228-272,355-368,524-560,612,627,651-654,747-784`; `routers/hardware_firmware.py:122-220,964-972`; `services/sbom/service.py:31-49`; `services/grype_service.py:77-79`; `services/vulnerability_service.py:18,73,89,103`; `services/export_service.py:92,335,355`; `services/import_service.py:471`; `ai/tools/sbom.py:43,476`; `ai/tools/hardware_firmware.py:471,747,822`.
- WIRED to current pipeline at the read sites; WIRED at the write sites (both grypge and operator-driven generate use the table normally).

For `sbom_vulnerabilities` table (model `backend/app/models/sbom.py:65-129`):
- WRITERS: `services/grype_service.py:213-222`; `services/vulnerability_service.py` (NVD path via `_query_nvd_for_component` insert sequence); `services/hardware_firmware/cve_matcher.py:903+` (curated tier matcher writes via `match_firmware_cves` at line 902).
- READERS: `routers/sbom.py:62-77,265-272,370-380,624-654`; `routers/hardware_firmware.py:122-220,964-972`; `services/hardware_firmware/hbom_export.py:16`; `services/hardware_firmware/cve_matcher.py:26,909,938`; `services/grype_service.py:213-222`; `services/vulnerability_service.py:73,89`; `services/export_service.py:93,361,500`.
- NO UniqueConstraint on `sbom_vulnerabilities` (verified — only Indexes at lines 123-129); dedup is application-side via `existing` set at `cve_matcher.py:938-989`.

## Suspect Findings

1. **`SbomComponent` UniqueConstraint** (`models/sbom.py:55-61`) on `(firmware_id, name, version, cpe)` — `routers/sbom.py:202-217` writes WITHOUT `ON CONFLICT DO NOTHING`. If anything inserts duplicate rows between the `force_rescan` delete and the new inserts (e.g., the RTOS injection block at line 165-198 collides with a real Syft detection that also produced an `operating-system` row with the same name+version), `db.flush()` raises `IntegrityError`. The route returns 500 ("Failed to generate SBOM"). NOT a Rule #47 orphan, but a pre-existing race.

2. **`scan_with_grype` ignores `force_rescan`** — `services/grype_service.py:60` signature has only `(firmware_id, project_id, db)`. The router at `routers/sbom.py:466-470` passes `firmware_id, project_id, db` to grype without `force_rescan`. The NVD path at line 471-477 DOES pass `force_rescan`, and `VulnerabilityService.scan_components` deletes prior rows on rescan. Grype path leaves prior rows in place AND inserts new ones — every `force_rescan=True` against grype DOUBLES the row count, eventually saturating page-render queries (the 7.5M-row corruption noted in `routers/sbom.py:53-60`).

3. **Rate-limit tier flip from TIER_A_HEAVY → TIER_A_LIGHT_ACK** (commit `f6dbc7b` 2026-05-18, per Rule #51) — increases the per-IP rate from 5/hour to 30/hour. An operator iterating against `generate_sbom` + `scan_vulnerabilities` may now ALSO trip:
   - The DB pool 40-conn ceiling under fast polling (`routers/sbom.py:53-60` PERF FIX documents the 30-conn pool exhaustion at 4 polls).
   - Concurrent background tasks vs the single-uvicorn 4-GB-RAM container.

4. **`auto-frontend-fake-scan-failed-error` harness rule** — `.claude/harness.json:164-168` exists to flag hardcoded `'Scan failed'` strings in catch blocks. The `SbomPage.handleScan` at line 162-185 + `handleGenerate` at line 128-144 correctly use `extractErrorMessage`. No regression there.

5. **`_post_process_pipeline` does NOT run unpack** — for ZIP uploads, the operator must STILL click "Unpack" to run binwalk/unblob OR the operator's firmware must qualify for the tarball/rootfs-ZIP shortcut paths. Generic ZIPs land in `zip_contents/` only. If `extracted_path` is the `zip_contents/` directory but no rootfs was found, `_run_hardware_firmware_detection_safe` walks `detection_roots` finds no qualifying content, and 22 walkers no-op — the SBOM generation will then find few/no components even after a successful upload-status=ready. **This is the most likely shape of the operator's regression**: upload-only path produces sparse SBOM compared to a full unpack.

6. **`FindingService.create` does not gate `firmware_id`** — `services/finding_service.py:5619-5642` writes `firmware_id=data.firmware_id` from the request body. The Rule #35b/F-A-06 audit fix is enforced for callers OUTSIDE `FindingService.create` (lines 365-391 `vulnerability_service.py`; lines 236-251 `grype_service.py`). The MCP `add_finding` tool's behavior on `firmware_id` is UNCLEAR; defer to Scout C/E if MCP-source findings start showing NULL firmware_id.

7. **No `db.refresh(...)` no-op** in SBOM router after the `update_vulnerability` PATCH at `routers/sbom.py:700` — Rule #32 says it's a no-op since `expire_on_commit=False`. Cosmetic, not a regression.

8. **`generate_sbom` uses 100 LOC of RTOS injection** (lines 161-198) inline in the router rather than a service helper — if `os_info` parse fails the `except Exception: pass` at line 198 silently swallows the error. **Could explain RTOS components missing from SBOM** when `firmware.os_info` is malformed JSON.

## Open Questions for Wave-2

- Did the recent commits between `847eae9` and tip touch any auto-trigger code path that previously fired SBOM/vuln-scan auto-runs? Scout B (git history) should diff.
- Are there phantom rows in production DB with `vuln_scan_status='queued'` from a pre-reaper backend restart? Scout C should check `SELECT vuln_scan_status, COUNT(*) FROM firmware GROUP BY 1`.
- Does the operator's specific firmware have `device_metadata.detection_roots` populated, and does the SBOM service actually pick it up? Scout C should `SELECT id, jsonb_typeof(device_metadata->'detection_roots') FROM firmware`.
- What was the prior expected behavior? The user said "regressed" — without a known baseline shape, the regression dimension is unclear. Scout E should walk through prior commits / scenarios.
- Does the new `_post_process_pipeline` upload path produce `extracted_path` for the operator's recent uploads, or is it leaving them NULL? Scout C should `SELECT extracted_path, extraction_dir, upload_stage FROM firmware WHERE created_at > '2026-05-15' ORDER BY created_at DESC`.

## File-line Refs Cross-Index

1. `backend/app/services/firmware_service.py:544-822` — `_post_process_pipeline`
2. `backend/app/services/firmware_service.py:818-822` — auto-trigger `_run_hardware_firmware_detection_safe`
3. `backend/app/services/firmware_service.py:825-858` — `_fire_walker_auto_triggers` (unused, called by tests)
4. `backend/app/services/firmware_service.py:875-937` — `_run_upload_post_processing_background`
5. `backend/app/workers/walker_registry.py:100-147` — 26-walker registry (no SBOM/vuln)
6. `backend/app/workers/unpack.py:74-154` — `_run_hardware_firmware_detection_safe` + walker dispatch
7. `backend/app/routers/firmware.py:133-176` — POST upload (202+polling)
8. `backend/app/routers/firmware.py:251-301` — POST unpack (arq path)
9. `backend/app/routers/sbom.py:115-225` — POST sbom/generate
10. `backend/app/routers/sbom.py:418-519` — `_run_vuln_scan_background`
11. `backend/app/routers/sbom.py:522-586` — POST sbom/vulnerabilities/scan (202+polling)
12. `backend/app/routers/sbom.py:62-77` — `_components_with_vuln_counts_stmt` (PERF FIX 2026-05-18)
13. `backend/app/services/sbom/service.py:239-301` — `SbomService.generate_sbom`
14. `backend/app/services/sbom/service.py:87-138` — `SbomService.__init__` (detection_roots resolution)
15. `backend/app/services/sbom/service.py:68-85` — 12 strategy classes
16. `backend/app/services/grype_service.py:60-265` — `scan_with_grype` (no force_rescan)
17. `backend/app/services/grype_service.py:236-253` — direct `Finding(source="sbom_scan")` construction
18. `backend/app/services/vulnerability_service.py:60-144` — `VulnerabilityService.scan_components` (NVD)
19. `backend/app/services/vulnerability_service.py:287-399` — `_create_findings_from_vulns` grouping
20. `backend/app/services/hardware_firmware/cve_matcher.py:902-989` — `match_firmware_cves` dedup
21. `backend/app/services/finding_service.py:5619-5642` — `FindingService.create`
22. `backend/app/models/firmware.py:50-99` — status columns (no `sbom_status`; vuln/cve/auth/registry/dotnet)
23. `backend/app/models/sbom.py:21-62` — SbomComponent + UniqueConstraint (firmware_id, name, version, cpe)
24. `backend/app/models/sbom.py:65-129` — SbomVulnerability (no UniqueConstraint)
25. `backend/app/main.py:200-242` — vuln_scan orphan reaper
26. `backend/app/rate_limit.py:85-87` — TIER_A_HEAVY 5/hour, TIER_A_LIGHT_ACK 30/hour
27. `frontend/src/pages/SbomPage.tsx:128-144,162-225` — handleGenerate + handleScan + polling
28. `frontend/src/api/sbom.ts:28-101` — generateSbom + runVulnerabilityScan + polling
29. `frontend/src/utils/error.ts:12-22` — `extractErrorMessage` (SlowAPI hint → detail → error fallback)
30. `backend/app/services/firmware_paths.py:840+` — `get_detection_roots` (JSONB cache)
