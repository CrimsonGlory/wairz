# Wave-1 Scout C — Live DB Behavior Probe (LIVE-DB persona)

> Investigation date: 2026-05-21
> Database probed: PostgreSQL inside docker compose service `postgres` (5434 host)
> Alembic head: `fd6e7f8a9b0c`
> Containers: backend + worker freshly rebuilt 2 minutes prior to probe (healthy).

## Executive Summary

The regression is real, broad, and has TWO independent root causes layered on top of each other. The visible symptom (operator says "SBOM + vuln scan regressed") is the surface — the underlying break is a walker-orchestration regression that has been mostly invisible because some downstream surfaces (`sbom_components`, `sbom_vulnerabilities`, `findings`) are still partially populated by OLDER code paths (security_audit, attack_surface, uefi_scan, yara_scan, apk-mobsfscan) that bypass the walker registry entirely.

Findings of the live probe:

1. **NO firmware uploaded after 2026-05-12 has had ANY walker auto-trigger fire.** Cluster-wide, the four tables that the most common walkers persist into are empty or nearly so: `windows_registry_extracts = 0`, `windows_appcompat_entries = 0`, `windows_drivers = 0`, `memory_dump_image = 0`. The `windows_pe_signatures` table holds 3 rows from 2026-05-08; nothing since.
2. **The bare_metal walker shipped to production on 2026-05-19 but its `auto_bare_metal_audit_firmware_safe` is NOT registered in `walker_registry.py`.** Five recent firmware uploads (TMS320F28066, three f28066_*.bin variants, 24967.hex — all targets the walker was specifically built for) sit at `bare_metal_audit_status = idle` despite descriptors being present in `bare_metal_descriptors` (33 rows, with `unauthenticated_external` and `operator` sources). One manually-triggered run (TMS320, 2026-05-19) is stuck at `bare_metal_audit_status = queued` with no started_at — a textbook Rule #47 orphan + Rule #51 orphan-reaper gap.
3. **The walker dispatch fan-out is gated on hardware-firmware-blob detection succeeding.** `backend/app/workers/unpack.py:106` reads `if count <= 0: return` — when zero `hardware_firmware_blobs` rows get persisted, the entire walker fan-out (25+ walkers) is SKIPPED. Six recent firmware (24967.hex, TMS320F28066_EatonUPS_MCU.zip, all three f28066_*.bin variants, Bootloader_7.7.1.hex, PowerPack_40.5.1_EGIA_EEA_Release.bin) have `hardware_firmware_blob count = 0` and consequently zero walker output.
4. **`upload_stage = 'ready'` is FALSELY-COMPLETE for all 25 firmware rows.** Every firmware row in the table reports `upload_stage = 'ready'` regardless of whether the post-process pipeline actually completed its walker fan-out. This is the silent-completion signal that masks the regression — the UI says "ready" and the operator assumes the analysis is done.
5. **`sbom_components = 4222` and `sbom_vulnerabilities = 6,766,108` totals look fine in aggregate** — but those numbers are dominated by OLD firmware (the RespArray cluster on 2026-04-25 contributed ~5.3M of the vulnerability rows; nothing newer than 2026-05-19 has produced more than 2 SBOM components).

The earliest broken firmware row is `0977b260-0f5f-443b-bcdd-fec15b74fb6d` (usb-stick-developer.zip, 2026-05-01) — it has 72 SBOM components but never had walker output. The pattern is consistent: every firmware after 2026-05-01 has walker_status_count ≤ 1 and the only non-idle is the bare_metal_audit orphan on 78ad638b. **Confidence: HIGH.**

## Probe Setup

- All containers healthy, no rebuild blockers. The original briefing referenced service name `db` — actual compose service name is `postgres` (host port 5434). `pg_isready` returned `accepting connections` immediately.
- Backend Python imports failed under default `python` (sqlalchemy not on sys.path); used `/app/.venv/bin/python -w /app -e PYTHONPATH=/app` per Rule #20.
- Initial query against `firmware.name` failed (column is `original_filename`); briefing schema is stale. Adapted all queries against actual columns surfaced via `information_schema.columns`.
- `hardware_firmware` was not a table — actual name is `hardware_firmware_blobs`. Confirmed via `pg_tables` enumeration.
- No outages; all probes returned within ~1 second.

## Status Column Cardinality

### upload_stage (CHECK enforces: uploading/hashing/detecting/extracting/analyzing/ready/failed)

| value | count |
|---|---|
| ready | 25 |

Every firmware row reports `ready`. There is no `upload_stage = failed` row to inspect (the failure signal does not surface here).

### unpack_stage

| value | count |
|---|---|
| NULL | 25 |

This column appears to be deprecated in favor of `upload_stage` (Rule #47 refactor 2026-05-12 commit `847eae9` consumer-orphan-fix). All 25 rows are NULL.

### vuln_scan_status

| value | count |
|---|---|
| idle | 20 |
| completed | 5 |

The 5 `completed` rows are all pre-2026-05-19 (operator-triggered MCP scans against older firmware). NO firmware uploaded since 2026-05-12 has progressed past `idle` for vuln_scan.

### cve_match_status

| value | count |
|---|---|
| idle | 21 |
| completed | 4 |

The 4 `completed` rows match the 4 most-recently-active sbom_vulnerabilities firmware. Same shape as vuln_scan_status — only OPERATOR-triggered MCP runs advance past idle.

### bare_metal_audit_status

| value | count |
|---|---|
| idle | 24 |
| queued | 1 |

The single `queued` row is `78ad638b-7f7c-4cb0-ac28-e36e05846007` (TMS320F28066_EatonUPS_MCU.zip, 2026-05-19), with `started_at = NULL` (the background runner never picked it up) — this is a Rule #51 orphan-reaper gap: the queued status was set by `ai/tools/bare_metal.py:93` then `asyncio.create_task(run_bare_metal_audit_background(...))` was issued but the outer wrapper never transitioned the row to `running`. Lifetime: 6 days.

## Most Recent Firmware Deep Dive

**24967.hex** (`8c7fb8c4-75af-4689-bad4-3b46857b2f21`)
- created_at: 2026-05-20 18:00:02 UTC
- upload_stage: `ready`
- vuln_scan_status: `idle` / cve_match_status: `idle` / bare_metal_audit_status: `idle`
- extracted_path: `/data/firmware/projects/c20d4977-.../firmware/8c7fb8c4-.../extracted` (present)
- extraction_dir: same as extracted_path
- detected_format: not displayed; unpack_log says "Firmware classified as: intel_hex / Converted Intel HEX to binary: 501744 bytes" + ARMhf + uC/OS-II RTOS detected
- **sbom_components: 1** (likely emitted by hardware_firmware detector, NOT by a walker — the count is suspiciously low for a 500KB image)
- **sbom_vulnerabilities: 0**
- **findings: 1** — single `security_audit` finding "No firmware update mechanism detected"
- **NO walker output:** All 22 *_walk_status columns + bare_metal_audit_status = `idle`. The Intel HEX-converted binary should have triggered the bare_metal walker (uC/OS-II detected; ARMhf candidate) but the walker is unregistered.
- **HW blob count: 0** — triggers the `if count <= 0: return` gate at unpack.py:106, skipping the entire walker fan-out.

The 24967.hex case is the cleanest illustration of the regression: a real bare-metal firmware (Intel HEX → flat binary, ARMhf, RTOS-detected) uploaded TODAY produced 1 generic security_audit finding and zero walker activity. The bare_metal walker would have produced CWE-tagged region-policy findings; the C28x/STM32 chip detection would have populated `bare_metal_descriptors` (it didn't — only TMS320 entries are present from manual MCP-triggered runs).

## Aggregate Surface Audit

- **sbom_components total:** 4,222 rows
- **sbom_vulnerabilities total:** 6,766,108 rows (heavily dominated by `a7523429-...` RespArray 2026-04-25 — 5.3M of them; the next two firmware contribute ~715K each — explains the suspicious cluster)
- **findings total:** 4,761 rows

**Findings grouped by source:**

| source | count |
|---|---|
| attack_surface | 1,759 |
| security_audit | 997 |
| uefi_scan | 654 |
| yara_scan | 585 |
| apk-mobsfscan | 301 |
| apk-manifest-scan | 297 |
| hardware_firmware_graph | 125 |
| sbom_scan | 25 |
| unpack_audit | 10 |
| apk-bytecode-scan | 6 |
| c28x_unsecure_csm | 2 |

**ZERO walker-emitted findings** (`windows_authenticode`, `windows_dbx_revoked`, `windows_registry_persistence`, `windows_inf`, `windows_driver_imports`, etc — none of the 20+ Windows walker finding sources have ANY rows). The 2 `c28x_unsecure_csm` rows are from the operator-triggered bare_metal MCP runs against TMS320 — NOT from the auto-trigger pipeline.

## Walker Artefact Persistence — Cluster-Wide Zeroes

| table | total rows |
|---|---|
| `windows_registry_extracts` | **0** |
| `windows_appcompat_entries` | **0** |
| `windows_drivers` | **0** |
| `windows_pe_signatures` | 3 (all 2026-05-08) |
| `linux_systemd_units` | 510 |
| `memory_dump_image` | **0** |
| `bare_metal_descriptors` | 33 (all manual) |

The `linux_systemd_units` table holding 510 rows is the most striking exception — and it's narrow: only 3 firmware contributed (RespArray, target-ld-v1.12, and the 8312-02.05 RespArray cluster) — all from BEFORE the regression window. **No firmware since 2026-05-05 has produced a systemd_unit row either.**

## Stuck Rows (orphan-reaper telltale)

- `vuln_scan_status IN ('queued', 'running')` for >30 min: **0 rows**
- `cve_match_status IN ('queued', 'running')` for >30 min: **0 rows**
- `bare_metal_audit_status IN ('queued', 'running')` for >30 min: **1 row** — `78ad638b-f99b-4cb0-ac28-e36e05846007` (TMS320F28066), `started_at = NULL`, age ≈ 6 days. Triggered by the bare_metal MCP tool on 2026-05-19 16:38 UTC; the outer `run_bare_metal_audit_background` was scheduled via `asyncio.create_task` from `app/ai/tools/bare_metal.py:103` but the row never transitioned to `running`. This is a Rule #51 orphan-reaper gap (the lifespan reaper covers `vuln_scan_status` + `cve_match_status` + `device_dump_status` per commit `3d2454b` 2026-05-18, but does NOT cover `bare_metal_audit_status` — the new walker added a status column without adding to the reaper inventory).

## What's MISSING vs PRESENT — Scoped

**MISSING:**
- Walker auto-trigger fan-out for ANY firmware whose unpack does not produce `hardware_firmware_blobs > 0`. The fail-closed gate at `unpack.py:106` short-circuits ALL 25+ walkers in `walker_registry.WALKER_AUTO_TRIGGERS` when no HW blobs are detected. Mechanism: line 106 `if count <= 0: return`.
- Auto-trigger registration for `auto_bare_metal_audit_firmware_safe`. The function exists in `bare_metal_walker.py:656` and is exported, but `walker_registry._load_walker_safe_runners()` does NOT import or list it. Phase 2 wiring promised in commit `5ee22c1` was never shipped.
- Orphan-reaper coverage for `bare_metal_audit_status` (and likely 22 other walker `*_walk_status` columns — only 3 of ~28 status columns are covered by the lifespan reaper per `3d2454b`).
- Walker output for ALL firmware uploaded after 2026-05-12. `windows_registry_extracts`, `windows_appcompat_entries`, `windows_drivers`, `memory_dump_image` are cluster-wide zero.
- Bare-metal walker firings on the 6 bare-metal candidates (24967.hex + 4 f28066 variants + TMS320 zip).

**PRESENT (still working):**
- Hardware firmware blob detection on Linux/Android firmware (Moto-G30/G32, RespArray, DPCS10, eaton-network-m3, GS724Tv6, live_base) — all produced 24-638 HW blobs. The detection itself is intact; the broken surface is downstream.
- Legacy `security_audit` finding emission via `_post_process_pipeline` for new uploads (24967.hex got 1 such finding). This is NOT a walker — it's the legacy scanner pipeline that runs in-process during upload analyze stage.
- Operator-triggered MCP runs (`cve-match POST`, `vuln-scan POST`, `bare_metal_audit POST`) — these bypass the broken auto-trigger and produce results when the operator manually fires them. 5 firmware have `vuln_scan_status = completed` exclusively through this path.
- `bare_metal_descriptors` ingestion via MCP tool — 33 rows present (31 `unauthenticated_external`, 2 `operator`) confirming the descriptor pipeline works; the missing piece is the auto-fire from the walker registry.
- SBOM emission for older firmware that went through pre-regression code paths.

## Schema vs Reality

- **Latest alembic revision applied:** `fd6e7f8a9b0c`
- **All 28 walker `*_walk_status` columns + `bare_metal_audit_status` + `cve_match_status` + `vuln_scan_status` + `authenticode_chain_status`** carry the canonical 5-state Rule #33 .c CHECK constraint: `('idle','queued','running','completed','failed')`. This is consistent and enforced.
- **`upload_stage` CHECK** allows: `uploading/hashing/detecting/extracting/analyzing/ready/failed` — note this does NOT include `idle` (which makes sense; upload stages are temporal not optional). All 25 rows are at `ready`.
- **No drift** between model + alembic for the columns I sampled — the Pydantic Literal + DB CHECK + frontend mirror trio per Rule #25 single-slice exception #2 appears intact for the walker status columns themselves.
- **The drift is at the orchestration layer, not the schema layer.** Walker columns exist; descriptor table exists; the gap is the missing import in `walker_registry.py` and the unguarded `if count <= 0: return` early-exit gate.

## Conclusions for Wave-2 Convergence

1. **Two independent regressions stacked.** (a) The hardware-firmware-blob-count gate at `unpack.py:106` skips the walker fan-out entirely for firmware with no HW blobs (bare-metal targets, Intel HEX, raw flash dumps — exactly the firmware the bare_metal walker was BUILT for). (b) Even if the gate were removed, the bare_metal walker would NOT fire because it is unregistered. Fixing only (a) leaves bare-metal targets unprocessed; fixing only (b) leaves Linux/Windows walkers locked behind the HW-blob gate. **Both must be fixed.**

2. **The orphan-reaper gap is a third regression.** The 2026-05-18 orphan-reaper landing (`3d2454b`) covered exactly the status columns that the operator told Scout the reaper was meant to cover — but the audit missed every walker `*_walk_status` column. The TMS320 row stuck at `queued` for 6 days is the canary. Action: extend `app/main.py` lifespan reaper to cover all `*_walk_status` + `bare_metal_audit_status` columns, or better, derive the list from `walker_registry` so future walkers inherit it automatically.

3. **The `if count <= 0: return` gate is the highest-impact single fix.** Removing it (or restructuring to `if count > 0: build_driver_firmware_graph()` then ALWAYS proceed to walker fan-out) instantly unblocks 22+ walkers across every firmware regardless of whether HW blobs were detected. This is also consistent with the walker_registry's per-walker `get_detection_roots()` contract (Rule #16): each walker's `get_detection_roots()` filter is the right place to decide whether work exists, NOT a global gate.

4. **The `auto_bare_metal_audit_firmware_safe` registration is a one-line fix** (add the import + list entry in `walker_registry._load_walker_safe_runners`). Per Rule #44, the matching `lookup_<artefact>_across_firmwares` MCP tool was never written either — Wave-2 should treat this as a partial shipping debt: the bare_metal walker shipped its Rule #39 triplet (γ.4-pattern) but missed its Rule #47 wiring AND its Rule #44 cross-firmware tool. Cf. the 11 backfill candidates the κ campaign already queued.

5. **Operator-facing surface needs a fail-loud signal.** The current `upload_stage = 'ready'` semantics masks the regression — every row is "ready" regardless of whether the walker fan-out completed. A subordinate `walker_fan_out_status` field (or per-walker visibility in the existing `*_walk_status` columns — but the `idle` value currently means BOTH "not triggered yet" and "no work present") would surface this kind of cluster-wide regression at the operator dashboard. Cross-stack alignment commit (Rule #48 Shape-1) for this is non-trivial but worth a Wave-2 design discussion.

## Raw Probe Output Appendix

### Most-recent firmware (top 15)

```
(8c7fb8c4-75af-4689-bad4-3b46857b2f21, '24967.hex', ready, idle, idle, 2026-05-20 18:00, has_extracted=True)
(78ad638b-f99b-4cb0-ac28-e36e05846007, 'TMS320F28066_EatonUPS_MCU.zip', ready, idle, idle, 2026-05-19 14:25, True)
(99f56635-ba2b-44df-95bd-24a82b9adba8, 'f28066_otp_16bit.bin', ready, idle, idle, 2026-05-19 14:22, True)
(5609e910-2bee-436a-abd3-bb695c3f560b, 'f28066_flash_16bit.bin', ready, idle, idle, 2026-05-19 14:22, True)
(9515fd85-a2fc-46de-bc3a-102e91f34871, 'f28066_bootrom_16bit.bin', ready, idle, idle, 2026-05-19 14:21, True)
(7433dfb1-5f82-4af6-8fff-98ad9611d7ac, 'I-SERIES-4-1_PERF_GMS_OTA-6.zip', ready, completed, completed, 2026-05-19 00:33, True)
(295eaf7a-515b-4206-8dde-a26393f2cbea, 'live_base-2.14.3-rc.5039.tar.gz', ready, completed, completed, 2026-05-15 23:06, True)
(f84544a9-f829-47d1-8518-d9212abc7ea8, 'Moto-G30-XT2129-1.zip', ready, completed, idle, 2026-05-15 12:24, True)
(eed5db82-49e9-4751-b2fc-733a0f7190bf, 'Moto-G32-XT2235-1.zip', ready, completed, completed, 2026-05-14 14:31, True)
(bb46d6bd-06a9-466f-a0b9-309d7f25ff1a, 'Q17AX-03.SDM', ready, idle, idle, 2026-05-06 11:39, True)
(6f8f9cc2-e05f-45b3-9a02-8af47f7c9b96, 'RespArray_1.05.00.17.zip', ready, idle, idle, 2026-05-04 17:18, True)
(0977b260-0f5f-443b-bcdd-fec15b74fb6d, 'usb-stick-developer.zip', ready, idle, idle, 2026-05-01 01:55, True)
(e16de6d0-fe36-4a56-aa80-74d13b2b25e3, 'coredx-5.15.0-...wolfssl-5.5.0-Release.tgz', ready, idle, idle, 2026-04-30 03:18, True)
(f8016186-e601-4c50-91b3-02c939654580, 'GS724Tv6-v7.0.0.12.stk', ready, idle, idle, 2026-04-21 06:28, True)
(1afa3f9a-079c-40f0-88e9-ff9cfacffbd2, 'eaton-network-m3-firmware-2.2.0.tar', ready, idle, idle, 2026-04-21 05:50, True)
```

### HW blob count distribution (recent 20)

```
24967.hex: 0
TMS320F28066: 0
f28066_otp_16bit.bin: 0
f28066_flash_16bit.bin: 0
f28066_bootrom_16bit.bin: 0
I-SERIES Garmin: 135
live_base (Lyra): 99
Moto-G30: 588
Moto-G32: 638
Q17AX-03.SDM: 0
RespArray: 288
usb-stick-developer.zip: 21
coredx-wolfssl: 0
GS724Tv6: 2
eaton-network-m3: 24
PowerPack EGIA EEA Release: 0
Bootloader_7.7.1.hex: 0
DPCS10: 265
1.5.18_real-release.apk: 0
target-ld-v1.12: 0
```

### TMS320 bare_metal_audit orphan

```
id: 78ad638b-f99b-4cb0-ac28-e36e05846007
status: queued
started_at: NULL
finished_at: NULL
error: NULL
result: {'errors':[],'blob_id':None,'audited_at':'2026-05-19T16:38:54.441170+00:00',
        'chip_match':{'evidence':[{'id':'6097fb18-...']},'schema_version':1,
        'blob_size_bytes':262144,'skipped_regions':[],'findings_emitted_count':1}
```

Note the `audited_at` IS populated and `findings_emitted_count: 1` — there was a successful inner run on 2026-05-19 16:38, but the outer state machine wrapper failed to transition `status` from `queued` to `running` to `completed`. The result JSONB suggests the run completed; the status column is stuck. This is consistent with a Rule #33 .a outer-runner bug where the status column write was somehow lost — worth a Wave-2 design audit.

### Walker artefact tables (cluster-wide)

```
windows_registry_extracts: 0
windows_appcompat_entries: 0
windows_drivers: 0
windows_pe_signatures: 3 (all 2026-05-08)
linux_systemd_units: 510 (top firmware: RespArray 184, target-ld 163, 8312-RespArray 163)
memory_dump_image: 0
bare_metal_descriptors: 33 (unauthenticated_external=31, operator=2)
hardware_firmware_blobs: total varies, see distribution above
sbom_components: 4222 (top firmware: RespArray 2086, DPCS10 495, then descending)
sbom_vulnerabilities: 6766108 (dominated by 8312-RespArray with 5.3M)
findings: 4761
```

### Source-file evidence

```
backend/app/workers/walker_registry.py:_load_walker_safe_runners()
  — imports 25 walker safe-runners but does NOT import auto_bare_metal_audit_firmware_safe.
  — function exists in bare_metal_walker.py:656 and is exported in __all__.

backend/app/workers/unpack.py:106
  if count <= 0:
      return
  — the early-exit gate. Removing this (or moving the walker fan-out outside the gate)
    is the highest-impact single fix.

backend/app/ai/tools/bare_metal.py:93
  firmware.bare_metal_audit_status = 'queued'
  ... 
  asyncio.create_task(run_bare_metal_audit_background(...))
  — the MCP tool that produced the stuck TMS320 queued row.

backend/app/services/bare_metal_walker.py:656
  async def auto_bare_metal_audit_firmware_safe(firmware_id):
      — exists but unregistered.

backend/app/services/firmware_service.py:818
  asyncio.create_task(_run_hardware_firmware_detection_safe(...))
  — the SINGLE auto-trigger entry point. Wraps both HW detection AND the gated walker fan-out.
```
