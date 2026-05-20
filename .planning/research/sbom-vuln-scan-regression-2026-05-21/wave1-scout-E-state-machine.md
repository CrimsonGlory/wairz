# Wave-1 Scout E — State-Machine Audit (STATE-MACHINE persona)

> Investigation date: 2026-05-21
> Scope: All Rule #33 .a state machines on `firmware` table + their Rule #51 companions

## Executive Summary

The investigation surfaced **one structural Rule #33 gap and one Rule #51 companion gap**, both bearing directly on the SBOM/vuln-scan regression hypothesis:

1. **SBOM generation has NO state machine.** Despite shipping under `TIER_A_LIGHT_ACK` and being tested by `_EXPECTED_TIERS`, the `POST /sbom/generate` endpoint is **strictly synchronous** — there is no `sbom_status` column on `firmware`, no Pydantic `SbomStatus` Literal, no orphan reaper, no idempotency 409, no 202 status code. The endpoint blocks the request thread for ~30-120 s on Syft execution. This is structurally inconsistent with vuln-scan (which IS 202+polling per Rule #33) and with the 30/hour `TIER_A_LIGHT_ACK` tier, which the rate_limit.py docstring justifies on the assumption that the work is "detached background … sub-second ACK". Under load, the request thread + DB connection are held during the entire Syft run.
2. **WALKER_AUTO_TRIGGERS does NOT include any sbom or vuln_scan auto-trigger.** Post-extraction the worker fires 32 walker safe-runners but neither `auto_sbom_safe` nor `auto_vuln_scan_safe` exists in the registry. SBOM and vuln scan are operator-triggered only; they do not autonomously run after firmware upload like the Windows/Linux artefact walkers do. If the operator expected them to be auto-fired (or a recent refactor broke an auto-fire that previously existed), this is the regression surface.
3. **Three state-machine columns have orphan reapers in `main.py` lifespan** — `device_dump_session.status` (lines 123-158), `firmware.cve_match_status` (lines 160-198), `firmware.vuln_scan_status` (lines 200-242). **Twenty-eight other state-machine columns have NO orphan reaper** — including every walker `*_walk_status` and the new `upload_stage` from the Rule #47 worked example. None of those columns owe an idempotency 409 today (their auto-triggers are unconditional fire-and-forget per Rule #39), so the reaper omission is structurally tolerated, but a future trigger MCP tool that adds an idempotency-409 to any of those state machines would inherit the same Rule #51 (i) gap.
4. Confidence: **HIGH** for the SBOM-no-state-machine + WALKER_AUTO_TRIGGERS-no-sbom-or-vuln-scan finding. The structural gap is the most likely Rule #51 .a/.c shape underlying any "scan won't run / scan stuck idle" regression.

## Methodology

Enumerated state-machine columns by combining three sources: (a) `firmware` model grep for `_status: Mapped[str]` and `_stage: Mapped[str]`; (b) alembic migration grep for `op.create_check_constraint` patterns named `ck_firmware_*_status` or `ck_firmware_*_stage`; (c) Pydantic schema grep for `WalkStatus|Status|Stage = Literal[`. For each column the report cross-references all four sources plus the corresponding `main.py` reaper presence, router rate-limit tier, `_EXPECTED_TIERS` pin entry, and Rule #33 4-bullet contract status.

Commands run (raw output in Appendix):

```bash
grep -n "_walk_status\|_status: Mapped\|_stage: Mapped" backend/app/models/firmware.py
grep -n "sa.CheckConstraint\|op.create_check_constraint" backend/alembic/versions/*.py | grep -iE "status|stage"
grep -rn "WalkStatus\s*=\s*Literal\|Status\s*=\s*Literal" backend/app/schemas/
grep -n "reaper\|reap_\|orphan\|asynccontextmanager\|lifespan" backend/app/main.py
grep -rn "TIER_A_HEAVY\|TIER_A_LIGHT_ACK\|TIER_B_DOCKER\|TIER_C_DEFAULT" backend/app/routers/
grep -A 50 "_EXPECTED_TIERS\s*=" backend/tests/test_rate_limit_tiers.py
```

## State-Machine Column Matrix

| Column | DB CHECK (revision) | Pydantic Literal | Orphan reaper | POST endpoint tier | _EXPECTED_TIERS pinned | Rule #33 4-bullet contract |
|---|---|---|---|---|---|---|
| `upload_stage` | YES `ck_firmware_upload_stage` (`d2e3f4a5b6c7`:110-114) | YES `UploadStage` (schemas/firmware.py:10-18) | **MISSING** | n/a (set by `upload_bytes_only` — no operator-fire POST) | n/a | partial — (a) no operator 409 (upload IS the trigger); (b) yes — pipeline writes to `firmware` row; (c) yes; (d) `asyncio.create_task` |
| `vuln_scan_status` | YES `ck_firmware_vuln_scan_status` (`c1d2e3f4a5b6`:86-90) | YES `VulnScanStatus` (schemas/sbom.py:108) | YES (main.py:200-242) | `TIER_A_LIGHT_ACK` (sbom.py:527) | YES (test_rate_limit_tiers.py:53) | YES — (a) 409 sbom.py:565-569; (b) `sbom_vulnerabilities` rows are the result; (c) yes; (d) `asyncio.create_task` sbom.py:583-585 |
| `cve_match_status` | YES `ck_firmware_cve_match_status` (`e6f7a8b9c0d1`:101) | YES `CveMatchStatus` (schemas/hardware_firmware.py:90) | YES (main.py:160-198) | `TIER_A_HEAVY` (hardware_firmware.py:612) | YES (test_rate_limit_tiers.py:49) | YES — canonical reference implementation |
| `device_dump_session.status` (NOT on firmware) | YES `ck_device_dump_session_status` | YES `DumpStatus` (schemas/device.py:61) | YES (main.py:123-158) | `TIER_A_HEAVY` (device.py:102) | YES (test_rate_limit_tiers.py:51) | YES |
| **NO `sbom_status`** | **NONE** | **NONE** | **NONE** | `TIER_A_LIGHT_ACK` (sbom.py:116) on synchronous POST/generate | YES (test_rate_limit_tiers.py:52) **but tier mismatched to shape** | **NO** — endpoint is synchronous, returns 200 with body, no Rule #33 contract at all |
| `bare_metal_audit_status` | YES `ck_firmware_bare_metal_audit_status` (`fc5d6e7f8a9b`) | NO (no `BareMetalAuditStatus` Literal found) | NO | n/a (no operator POST yet — Phase 2 only ships `/bare-metal-hint`) | bare-metal-hint endpoint pinned at `TIER_A_LIGHT_ACK` (test_rate_limit_tiers.py:60) | partial — state machine is fired by walker auto-trigger, not operator POST |
| `authenticode_chain_status` | YES (b2a3c4d5e6f7:77) | YES `AuthenticodeChainStatus` (schemas/hardware_firmware.py:144) | NO | `TIER_A_LIGHT_ACK` (hardware_firmware.py:707) | YES (test_rate_limit_tiers.py:54) | partial — 409 + 202 yes; reaper missing |
| `dotnet_decompile_status` | YES (d1e2f3a4b5c6:100) | YES `DotnetDecompileStatus` (schemas/hardware_firmware.py:235) | NO | n/a (no explicit POST endpoint surfaced in this audit) | n/a | partial |
| `windows_update_diff_status` | YES (d3a4b5c6d7e8:100) | YES `WindowsUpdateDiffStatus` (schemas/hardware_firmware.py:247) | NO | n/a | n/a | partial |
| `registry_hive_walk_status` | YES (c8d9e0f1a2b3:92) | YES `RegistryHiveWalkStatus` (schemas/hardware_firmware.py:203) | NO | n/a (trigger MCP only) | n/a | partial |
| `evtx_walk_status` | YES (e0a1b2c3d4e5:106) | YES `EvtxWalkStatus` (schemas/hardware_firmware.py:262) | NO | n/a | n/a | partial |
| `scheduled_task_walk_status` | YES (f9a0b1c2d3e4:94) | YES `ScheduledTaskWalkStatus` (schemas/firmware.py:27) | NO | n/a | n/a | partial |
| `lnk_walk_status` | YES (c2e3f4a5b6d7:93) | YES `LnkWalkStatus` (schemas/firmware.py:37) | NO | n/a | n/a | partial |
| `mft_walk_status` | YES (2a4b3c5d6e7f:94) | YES `MftWalkStatus` (schemas/firmware.py:47) | NO | n/a | n/a | partial |
| `bcd_walk_status` | YES (2a5b3c4d5e6f:94) | YES `BcdWalkStatus` (schemas/firmware.py:57) | NO | n/a | n/a | partial |
| `wmi_walk_status` | YES (5d8e6f9c0a2b:94) | YES `WmiWalkStatus` (schemas/firmware.py:68) | NO | n/a | n/a | partial |
| `esp_walk_status` | YES (8b9c0d1e2f3a:92) | YES `EspWalkStatus` (schemas/firmware.py:79) | NO | n/a | n/a | partial |
| `mbr_vbr_walk_status` | YES (bc0d1e2f3a4b:97) | YES `MbrVbrWalkStatus` (schemas/firmware.py:102) | NO | n/a | n/a | partial |
| `sdb_walk_status` | YES (bc1d2e3f4a5b:94) | YES `SdbWalkStatus` (schemas/firmware.py:126) | NO | n/a | n/a | partial |
| `journald_walk_status` | YES (fb3a4b5c6d7e:99) | YES `JournaldWalkStatus` (schemas/firmware.py:138) | NO | n/a | n/a | partial |
| `systemd_walk_status` | YES (aabbccddee02:104) | YES `SystemdWalkStatus` (schemas/firmware.py:150) | NO | n/a | n/a | partial |
| `etl_walk_status` | YES (aabbccddee05:104) | YES `EtlWalkStatus` (schemas/firmware.py:161) | NO | n/a | n/a | partial |
| `efs_walk_status` | YES (aabbccddee08:105) | YES `EfsWalkStatus` (schemas/firmware.py:174) | NO | n/a | n/a | partial |
| `container_walk_status` | YES (aabbccddee0b:112) | YES `ContainerWalkStatus` (schemas/firmware.py:187) | NO | n/a | n/a | partial |
| `appcompat_walk_status` | YES (aabbccddee0e:102) | NO | NO | n/a | n/a | partial |
| `persistence_walk_status` | YES (aabbccddee11:106) | NO | NO | n/a | n/a | partial |
| `dpapi_walk_status` | YES (aabbccddee14:103) | NO | NO | n/a | n/a | partial |
| `usnjrnl_walk_status` | YES (aabbccddee17:101) | NO | NO | n/a | n/a | partial |
| `memory_dump_walk_status` | YES (bdf2a3b4c5d6:102) | NO | NO | n/a | n/a | partial |
| `windows_info_walk_status` | YES (c5f6a7b8c9d0:120) | NO | NO | n/a | n/a | partial |
| `windows_processes_walk_status` | YES (d6e7f8a9b0c2:175) | NO | NO | n/a | n/a | partial |
| `windows_injection_walk_status` | YES (d8e9f0a1b2c4:128) | NO | NO | n/a | n/a | partial |
| `prefetch_walk_status` | YES (b4c5d6e7f8a9:92) | NO | NO | n/a | n/a | partial |
| `srum_walk_status` | YES (d6e7f8a9b0c1:91) | NO | NO | n/a | n/a | partial |
| `ics_protocol_walk_status` | **NOT SHIPPED YET** (catalog skeleton present at `app/services/ics_protocol_catalog/__init__.py:21`; walker module path referenced but not implemented) | NONE | n/a | n/a | n/a | n/a — Session 2 work |

## Orphan Reaper Lifespan Audit (`backend/app/main.py`)

Three reapers are wired in the `@asynccontextmanager async def lifespan(app)` body (main.py:57-324):

1. **Device-dump reaper** (main.py:123-158): flips `device_dump_session.status` from `("queued", "running")` → `"failed"` with `error="Backend restarted; runner state lost"`. Comment cites Rule #33 + F-A-01 audit-2026-05-04 closure. Updates `finished_at` to `datetime.now(UTC)`.
2. **cve-match reaper** (main.py:160-198): flips `firmware.cve_match_status` from `("queued", "running")` → `"failed"` with the same error message. Comment notes "the device-dump and cve-match reapers existed but vuln-scan was missed when the row's state machine was added" — historical evidence that the reaper sweep was an after-the-fact catch-up.
3. **vuln-scan reaper** (main.py:200-242): flips `firmware.vuln_scan_status` from `("queued", "running")` → `"failed"` with the same error message. Comment explicitly cites the 2026-05-18 audit (Scout 2's f6dbc7b findings) that surfaced this gap originally; this is the only reaper added under Rule #51 .b explicit-companion-sweep discipline. Cleanup is STARTUP-only — no cron is wired because the in-process `asyncio.create_task` runner ALWAYS dies on backend restart.

No other state-machine column has an orphan reaper. The `bare_metal_audit_status`, `authenticode_chain_status`, `dotnet_decompile_status`, `windows_update_diff_status`, `upload_stage`, and 22 walker `*_walk_status` columns rely on (a) walker safe-runners NOT mutating the column (Rule #39 .safe semantics — they leave status at `idle`) and (b) walker trigger MCP tools not being on the runtime hot path. This works today because no operator-facing POST currently uses an idempotency-409 against these columns.

## Rate-Limit Tier Audit

**Tier constants** (rate_limit.py:84-88):

```
TIER_A_HEAVY     = "5/hour"     # synchronous OR ≥5-min ack-bound runs
TIER_A_LIGHT_ACK = "30/hour"    # 202+polling, ≤2 min detached work
TIER_B_DOCKER    = "20/hour"    # Docker-spawn jobs
TIER_C_DEFAULT   = "100/minute" # implicit default
```

**`_EXPECTED_TIERS`** (test_rate_limit_tiers.py:47-73): **20 entries**, size-locked at `test_expected_tiers_count_size_locked` (test_rate_limit_tiers.py:128-138). Tier name attribution by source: 4× `TIER_B_DOCKER`, 4× `TIER_A_LIGHT_ACK`, 12× `TIER_A_HEAVY`. The pinned entries include 8 ratelimit-scout1-added entries from 2026-05-19 (3× apk_scan + 5× comparison + 1× attack_surface).

**META-CANARY trio** (Rule #46): present at test_rate_limit_tiers.py:141-198 covering (a) wrong-tier-decorator synthesis (`test_meta_canary_wrong_tier_decorator_detected`); (b) missing-endpoint synthesis (`test_meta_canary_missing_endpoint_detected`); (c) the dynamic 429 body shape `test_dynamic_429_response_shape_on_unpack` (lines 208-286) hits POST /firmware/.../unpack 6 times and asserts structured body keys `{detail, error, tier, retry_after_seconds, hint}` + Retry-After header. Both META-CANARIES use `_check_tier_alignment` against a tmp_path synthesized router file, so a regression that breaks the regex would FAIL the canary BEFORE it silently passes.

**`POST /sbom/generate` tier mismatch:**

The endpoint is decorated `@limiter.limit(TIER_A_LIGHT_ACK)` (sbom.py:116) and pinned in `_EXPECTED_TIERS` as TIER_A_LIGHT_ACK (test_rate_limit_tiers.py:52). The rate_limit.py docstring (lines 42-51) justifies TIER_A_LIGHT_ACK as "202+polling endpoints whose ACK is sub-second and whose detached background work completes in ≤2 min". But `generate_sbom` (sbom.py:117-225) is **synchronous** — it awaits the Syft executor (`await loop.run_in_executor(None, service.generate_sbom)` at sbom.py:157) inside the request handler and returns 200 with the full `SbomGenerateResponse` body. The Syft run is documented as 30-120 s wall time. This violates the TIER_A_LIGHT_ACK derivation contract (Rule #51 .ii) — the work shape is synchronous heavy, not light-ack. The correct tier would be `TIER_A_HEAVY` (5/hour) OR the endpoint should be converted to 202+polling so the LIGHT_ACK tier matches.

## WALKER_AUTO_TRIGGERS Registry Contents

Source: `backend/app/workers/walker_registry.py:100-147`. **32 registered safe-runners** (Phase γ → λ):

```
Phase γ:
  - registry_auto_walk        (registry_hive_walker)
  - auto_extract_drivers_safe (driver_extractor)
  - evtx_auto_walk            (evtx_service)

Windows artefact walkers:
  - auto_appcompat_walk_firmware_safe
  - auto_bcd_walk_firmware_safe
  - auto_dpapi_walk_firmware_safe
  - auto_efs_walk_firmware_safe
  - auto_esp_walk_firmware_safe
  - auto_etl_walk_firmware_safe
  - auto_lnk_walk_firmware_safe
  - auto_mbr_vbr_walk_firmware_safe
  - auto_memory_image_enumeration_safe                  (λ.α.B)
  - auto_windows_info_walk_firmware_safe                (λ.α.D)
  - auto_windows_processes_walk_firmware_safe           (λ.β)
  - auto_windows_injection_walk_firmware_safe           (λ.γ)
  - auto_mft_walk_firmware_safe
  - prefetch_auto_walk                                  (ζ.2)
  - auto_scheduled_task_walk_firmware_safe
  - auto_sdb_walk_firmware_safe
  - srum_auto_walk                                      (ζ.3)
  - auto_usnjrnl_walk_firmware_safe
  - auto_wmi_walk_firmware_safe

Cross-platform / Linux artefact walkers:
  - auto_container_walk_firmware_safe
  - auto_journald_walk_firmware_safe
  - auto_linux_persistence_walk_firmware_safe
  - auto_systemd_walk_firmware_safe
```

**ABSENT from the registry: any `auto_sbom_*_safe` runner, any `auto_vuln_scan_*_safe` runner, any `auto_bare_metal_audit_*_safe` runner.** A direct grep for `auto_sbom`, `auto_vuln`, `sbom_auto`, `vuln_auto` across the entire `backend/` tree returns ZERO matches.

## `_post_process_pipeline` Audit

Source: `backend/app/services/firmware_service.py:544-822`. Fires after a firmware upload completes successfully (and also is the inline path for the legacy synchronous `FirmwareService.upload`):

- Stage `detecting` (line 565-577): detect format via `detect_format(storage_path)`.
- Stage `extracting` (lines 580-774): tarball / ZIP / Android-OTA / rootfs-ZIP / generic-ZIP shortcut paths; fallback to leaving `storage_path` untouched.
- Stage `analyzing` (lines 777-803): arch / endian / OS / kernel detection via `detect_architecture`, `detect_os_info`, `detect_kernel`, `populate_detection_roots`.
- Stage `ready` terminal (lines 805-822): commits `upload_stage = "ready"`, then fires `asyncio.create_task(_run_hardware_firmware_detection_safe(firmware.id, firmware.extracted_path))`. **The HW-detection runner then calls every walker safe-runner in `WALKER_AUTO_TRIGGERS`** (firmware_service.py:817-822, mirror at workers/unpack.py:145-154).

**Neither `auto_sbom_*` nor `auto_vuln_scan_*` is fired anywhere in `_post_process_pipeline`.** Firmware upload terminates at `upload_stage = "ready"` with HW detection + walker fan-out as the only background work; SBOM and vuln scan remain operator-triggered only.

`_fire_walker_auto_triggers(firmware_id)` (firmware_service.py:825-858) is the thin orchestrator that iterates `walker_registry.get_walker_auto_triggers()` sequentially with per-runner try/except per Rule #7 (never gather'd on a shared session).

## Rule #51 Companion Failure Mode Audit

For each suspect column:

**`sbom_status` (DOES NOT EXIST):**
- (i) Orphan reaper: N/A — column doesn't exist.
- (ii) Tier alignment: **DRIFT** — `POST /sbom/generate` is synchronous (sbom.py:117-225) but rides `TIER_A_LIGHT_ACK`. The tier's docstring contract requires 202+polling shape; this endpoint returns 200 with the full SBOM body.
- (iii) Frontend 429 body shape: structured per `custom_rate_limit_exceeded_handler` (rate_limit.py:121-232) — applies uniformly to ALL rate-limited endpoints.
- (iv) Structured 429 + Retry-After: PRESENT (rate_limit.py:170-232) — RFC-7231 §7.1.3 Retry-After is set on every 429, regardless of which endpoint produced it.

**`vuln_scan_status`:**
- (i) Orphan reaper: PRESENT (main.py:200-242).
- (ii) Tier alignment: ALIGNED — `TIER_A_LIGHT_ACK` matches the 202+polling shape; runtime ack is sub-second (sbom.py:571 → asyncio.create_task → 202 return).
- (iii)/(iv): same as above.

**`upload_stage`:**
- (i) Orphan reaper: MISSING — but the column has no operator POST that 409s on `("queued", "running")`. The `upload_bytes_only` upload IS the trigger; a backend restart mid-extraction leaves the row in `("detecting", "extracting", "analyzing")` indefinitely. **The HW-detection + walker fan-out does NOT fire** if the row was midway through extraction at restart — the operator must POST `/{firmware_id}/unpack` (`TIER_A_HEAVY`) to recover. A second-order regression candidate.
- (ii)-(iv) n/a.

**`bare_metal_audit_status`:**
- (i) Orphan reaper: MISSING — but no operator POST 409s on this column today.
- (ii) Tier alignment: bare-metal-hint endpoint pinned correctly at `TIER_A_LIGHT_ACK` (test_rate_limit_tiers.py:60).

## Suspect Conclusions

1. **PRIMARY SUSPECT** — SBOM generation has no Rule #33 state machine. Tier-shape drift (`TIER_A_LIGHT_ACK` decorating a synchronous endpoint) violates Rule #51 .ii on a Rule #33 conversion that **never happened**. Symptoms: SBOM endpoint blocks the request thread + DB connection for 30-120 s under Syft; under iterative operator load (30/hour budget), the DB pool can starve other endpoints. Look for `QueuePool timeout` log lines.
2. **SECONDARY SUSPECT** — WALKER_AUTO_TRIGGERS includes NO sbom or vuln-scan auto-trigger. If a recent refactor REMOVED an auto-trigger (e.g. before/after the Rule #47 worked-example #1 fix at `12955a6 + 5f3d195`), the SBOM/vuln-scan no-fire symptom is direct. The bare-metal walker auto-trigger went through `_post_process_pipeline` correctly; SBOM/vuln-scan never did.
3. **TERTIARY** — `upload_stage` has no orphan reaper. A backend restart mid-extraction leaves the row in `("detecting", "extracting", "analyzing")` until the operator POSTs `/unpack` (TIER_A_HEAVY tier). Frontend polling on `upload_stage` will display "stuck" forever; the row's HW-detection + walker fan-out never fires.
4. **HOUSEKEEPING** — 9 of 32 walker columns (`appcompat`, `persistence`, `dpapi`, `usnjrnl`, `memory_dump`, `windows_info`, `windows_processes`, `windows_injection`, `prefetch`, `srum`) HAVE DB CHECK constraints but NO Pydantic Literal mirror. Rule #33 .c says BOTH a Literal AND a CHECK; these are CHECK-only. Not a regression suspect, but a Rule #33 .c housekeeping gap worth filing for κ-batch closure.
5. **NEEDS SHIPPING** — `ics_protocol_walk_status` is referenced in `app/services/ics_protocol_catalog/__init__.py:21` but the walker module + state machine column + alembic migration are NOT YET shipped per the ICS Session 1 postmortem; Session 2 will add. Today this column does not exist.

## Raw Output Appendix

**Status columns on `firmware` model** (verbatim, model.py line numbers):

```
50:  cve_match_status
63:  vuln_scan_status
76:  upload_stage
89:  authenticode_chain_status
113: registry_hive_walk_status
137: dotnet_decompile_status
163: windows_update_diff_status
190: evtx_walk_status
212: prefetch_walk_status
233: srum_walk_status
255: scheduled_task_walk_status
282: lnk_walk_status
310: mft_walk_status
339: bcd_walk_status
372: journald_walk_status
403: systemd_walk_status
443: etl_walk_status
487: efs_walk_status
530: container_walk_status
573: appcompat_walk_status
616: persistence_walk_status
666: dpapi_walk_status
710: usnjrnl_walk_status
738: bare_metal_audit_status
766: wmi_walk_status
795: esp_walk_status
827: mbr_vbr_walk_status
856: sdb_walk_status
881: memory_dump_walk_status
909: windows_info_walk_status
937: windows_processes_walk_status
966: windows_injection_walk_status
```

**Tier constants (rate_limit.py:84-88):**
```
TIER_A_HEAVY = "5/hour"
TIER_A_LIGHT_ACK = "30/hour"
TIER_B_DOCKER = "20/hour"
TIER_C_DEFAULT = "100/minute"
```

**`_EXPECTED_TIERS` size-lock:**
```
test_rate_limit_tiers.py:135-138 asserts len(_EXPECTED_TIERS) == 20
```

**Reapers in main.py lifespan:**
```
main.py:123-158  device-dump reaper       (device_dump_session.status)
main.py:160-198  cve-match reaper         (firmware.cve_match_status)
main.py:200-242  vuln-scan reaper         (firmware.vuln_scan_status)
```

**WALKER_AUTO_TRIGGERS count = 32 entries.** `grep -c auto_` on walker_registry.py:100-147 returns 32 distinct safe-runner identifiers across all phases γ through λ.

**SBOM/vuln-scan auto-trigger search:**
```
grep -rn "auto_sbom\|auto_vuln\|sbom_auto\|vuln_auto" backend/
# → ZERO matches
```

**`POST /sbom/generate` shape:**
```
sbom.py:115-225  decorated TIER_A_LIGHT_ACK; returns SbomGenerateResponse (no 202 status_code)
sbom.py:157      await loop.run_in_executor(None, service.generate_sbom)  ← synchronous wait inside handler
```

**ICS protocol walker status:**
```
grep -rn "ics_protocol_walk_status\|ics_protocol_walker" backend/
# → only catalog skeleton reference at ics_protocol_catalog/__init__.py:21
# → no model column, no alembic migration, no walker module, no Pydantic Literal
```
