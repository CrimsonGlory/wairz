---
title: Windows coverage test checklist — η + θ + ι + κ end-to-end verification
opened: 2026-05-12
status: ready-to-execute (after κ close + backend+frontend rebuilds)
scope: |
  Concrete tests for the Windows artifact-walker portfolio shipped across
  η + θ + ι + κ (so far). Covers MCP / REST / UI / cross-firmware
  aggregation. User-driven (operator uploads a real Windows firmware and
  walks through the checklist).
---

# Windows coverage test checklist

## Scope (24 Windows walkers shipped, ~75 MCP tools touch Windows artefacts)

| Phase | Walker | ORM | MCP category | FindingSource(s) |
|---|---|---|---|---|
| γ.4 | Registry hives | `windows_registry_extract` | `windows_registry` | `windows_registry_persistence` |
| ε.1.b | EVTX | `windows_evtx_event` | `windows_event_log` | `windows_sysmon_proc_create`, `windows_logon_success/failure` |
| ζ.1 | Amcache | (extends γ.4 walks) | (uses registry tools) | `windows_amcache_install` |
| ζ.2 | Prefetch | `windows_prefetch_record` | `windows_prefetch` | `windows_prefetch_execution` |
| ζ.3 | SRUM | `windows_srum_record` | `windows_srum` | `windows_srum_network_activity`, `windows_srum_application_runtime` |
| η.A | NTFS $MFT | `windows_mft_record` | `windows_mft` | `windows_mft_ads_hidden_content`, `windows_mft_timestomping` |
| η.B | Scheduled Tasks | `windows_scheduled_task` | `windows_scheduled_task` | `windows_scheduled_task_persistence` |
| η.C | LNK files | `windows_lnk_record` | `windows_lnk` | `windows_lnk_abnormal_target` |
| η.D | BYOVD LOLDrivers | (extends driver scan) | (uses hardware_firmware) | `windows_byovd_driver` |
| η.E | PowerShell EID4104 | (extends ε EVTX) | (uses windows_event_log) | `windows_powershell_script_block` |
| θ.A | BCD store | `windows_bcd_entry` | `windows_bcd` | `windows_bcd_suspicious_path`, `windows_bcd_testsigning_enabled` |
| θ.B | WMI persistence | `windows_wmi_event` | `windows_wmi` | `windows_wmi_persistence` |
| θ.C | UEFI ESP `.efi` | `windows_esp_entry` | `windows_esp` | `windows_esp_unsigned`, `windows_esp_dbx_revoked` |
| θ.D | Shim .sdb | `windows_sdb_entry` | `windows_sdb` | `windows_sdb_inject_dll`, `windows_sdb_redirect_exe`, `windows_sdb_custom_shim` |
| θ.E | MBR/VBR | `windows_mbr_vbr_sector` | `windows_mbr_vbr` | `windows_mbr_bootkit`, `windows_vbr_anomaly` |
| ι.C | ETL | `windows_etl_event` | `windows_etl` | `windows_etl_kernel_proc_after_clear`, `_provider_disabled`, `_unusual_provider`, `_non_microsoft_in_diagtrack` |
| ι.D | EFS DDF/DRF | `windows_efs_encrypted_file` | `windows_efs` | `windows_efs_orphaned_drf`, `_unusual_recovery_agent`, `_domain_admin_in_ddf`, `_large_drf` |
| κ.B | AppCompat/Shimcache | `windows_appcompat_entry` | `windows_appcompat` | `windows_appcompat_suspicious_path`, `_temp_execution`, `_recent_baseline` |
| κ.D | DPAPI master keys | `windows_dpapi_master_key` | `windows_dpapi` | `windows_dpapi_*` (TBD per κ.D commit) |
| κ.E | UsnJrnl $J | `windows_usnjrnl_entry` | `windows_usnjrnl` | `windows_usnjrnl_*` (TBD per κ.E commit) |

## Phase 0 — Prerequisites (run BEFORE uploading any firmware)

```bash
# All services healthy?
docker compose ps

# Backend alembic head matches code?
docker compose exec -T backend /app/.venv/bin/alembic heads
# Expected: aabbccddee0c (or higher post-κ.B/D/E)

# Backend image current with MCP tool count?
docker compose exec -T backend find /app/app/ai/tools -name '*.py' -exec grep -c 'registry\.register' {} \; 2>/dev/null | awk '{s+=$1}END{print "MCP image total:",s}'
# Expected: matches `find /home/dustin/code/wairz/backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'`
# After κ ships: ~290 (281 baseline + κ.A 1 + κ.B 5 + κ.C ~5 + κ.D 5 + κ.E 5)

# Frontend served bundle has latest unwrap shim?
curl -fsS http://localhost:3000/ | head -20
# (no smoke beyond "200 ok and serves index")

# REST /health
curl -fsS http://localhost:8000/api/v1/health
# Expected: {"status":"healthy"}
```

## Phase 1 — Upload a Windows firmware

UI: `http://localhost:3000` → New Project → Upload firmware. The firmware must contain
Windows artefacts (registry hives, EVTX, MFT/NTFS, ESP, BCD, etc.). Good candidates:

- **Windows IoT Core firmware** (`*.ffu`)
- **Surface / Surface Pro firmware bundles** (often contain ESP `.efi` chains)
- **Captured device images** with the Windows partition extracted (`.vhd`, `.vhdx`, `.raw`)
- **Last-resort synthetic:** mount a Windows VM, `tar -cf windows-fs.tar /` from inside, upload

Note the project ID + firmware ID after upload — used in later steps. Watch the
unpack progress poll cycle in the UI (Rule #29 202+polling shape from γ).

Wait for unpack to finish (`firmware.status` flips `unpacking → unpacked`).

## Phase 2 — Auto-trigger verification

Post-unpack, all Windows walkers auto-fire via the Rule #39 safe runner registration
in `backend/app/workers/unpack.py`. Verify each walker's status column flipped to
"running" or "completed":

```bash
# Replace <fw-id> with the firmware UUID
FW=<fw-id>
docker compose exec -T postgres psql -U wairz -d wairz -c "
SELECT
  registry_walk_status, evtx_walk_status, prefetch_walk_status, srum_walk_status,
  mft_walk_status, scheduled_task_walk_status, lnk_walk_status,
  bcd_walk_status, wmi_walk_status, esp_walk_status, sdb_walk_status, mbr_vbr_walk_status,
  etl_walk_status, efs_walk_status,
  appcompat_walk_status, dpapi_walk_status, usnjrnl_walk_status
FROM firmware WHERE id = '$FW';
"
# Expected: most columns 'completed' or 'running' (walks fire async); 'idle' = walker
#   didn't find a relevant artefact (e.g. no ESP partition = esp_walk_status idle).
#   'failed' = real bug — read `*_error` column.
```

## Phase 3 — Per-walker MCP smoke (via Claude Code MCP integration)

Open Claude Code with the wairz MCP server connected. For each Windows walker
category, run the following MCP commands:

### Registry (γ.4)
```
list_registry_extracts firmware_id=<FW>
lookup_registry_value path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" firmware_id=<FW>
```

### EVTX (ε.1.b + η.E)
```
list_events firmware_id=<FW> channel="Security" event_id=4624 limit=10
search_events firmware_id=<FW> query="powershell" limit=10
```

### Prefetch / SRUM / Amcache (ζ)
```
list_prefetch firmware_id=<FW> limit=20
list_srum firmware_id=<FW> record_type=network_data_usage limit=20
list_amcache firmware_id=<FW> limit=10
```

### MFT / Scheduled Tasks / LNK / BYOVD (η)
```
list_mft_records firmware_id=<FW> filter="ads_present" limit=10
list_scheduled_tasks firmware_id=<FW> limit=20
list_lnk_records firmware_id=<FW> limit=20
list_byovd_drivers firmware_id=<FW>
```

### BCD / WMI / ESP / SDB / MBR-VBR (θ)
```
list_bcd_entries firmware_id=<FW>
list_wmi_events firmware_id=<FW>
list_esp_entries firmware_id=<FW>
list_sdb_entries firmware_id=<FW>
list_mbr_vbr_sectors firmware_id=<FW>
```

### ι (Windows portion: ETL + EFS)
```
list_etl_events firmware_id=<FW> limit=20
list_etl_anomalies firmware_id=<FW>
list_efs_encrypted_files firmware_id=<FW> limit=20
list_efs_anomalies firmware_id=<FW>
```

### κ (post-shipping)
```
list_appcompat_entries firmware_id=<FW> limit=20
list_dpapi_master_keys firmware_id=<FW>
list_usnjrnl_entries firmware_id=<FW> limit=20
```

### Cross-firmware aggregation tools (Rule #44 — only useful with ≥2 firmware uploaded)
```
lookup_etl_event_across_firmwares query="<provider-guid>" project_id=<PROJECT>
lookup_efs_encrypted_file_across_firmwares query="<filename>" project_id=<PROJECT>
lookup_appcompat_entry_across_firmwares query="<path>" project_id=<PROJECT>
lookup_journald_entry_across_firmwares query="<message>" project_id=<PROJECT>   # κ.A — Linux but cross-firmware
```

## Phase 4 — UI verification

Navigate to:
- `http://localhost:3000/projects/<PROJECT_ID>/firmware/<FW_ID>` — firmware detail page
- `http://localhost:3000/projects/<PROJECT_ID>/findings` — findings list

Expected UI behaviour:
- **Findings list** renders ALL emitted Windows finding sources (visible in the source filter dropdown). After κ ships, expect `windows_appcompat_*`, `windows_dpapi_*`, `windows_usnjrnl_*` to appear with proper icons + severity colours (Rule #25 cross-stack alignment ensures `FINDING_SOURCE_CONFIG` has entries for each).
- **No console errors** — open DevTools → Console. Specifically watch for `TypeError: ... .map is not a function` (would indicate stale frontend bundle from before unwrap shim was added — Rule #26 regression).
- **Source filter dropdown** shows all known sources. After κ ships, the count should match `WindowsFindingSource Literal` value count (currently 38; +3 from κ.B AppCompat + ~3 from κ.D DPAPI + ~3 from κ.E UsnJrnl = ~47 expected at κ close).

## Phase 5 — Findings table sanity

```bash
docker compose exec -T postgres psql -U wairz -d wairz -c "
SELECT source, confidence, COUNT(*)
FROM findings
WHERE firmware_id = '$FW' AND source LIKE 'windows_%'
GROUP BY source, confidence
ORDER BY source, confidence;
"
```

Expected: rows for the Windows source values the walks emitted. Confidence values
should be HIGH / MEDIUM / LOW per the heuristics documented in
`backend/app/schemas/finding.py` for each `WindowsFindingSource` Literal entry.

If a walker COMPLETED but emitted ZERO rows for a finding source it's documented to
emit, that's a bug — investigate via:
```bash
docker compose exec -T backend cat /app/logs/finding_service.log | grep "emit_<walker>_findings_from_walk"
```

## Phase 6 — Negative tests

```bash
# 1. Trigger re-walk while a walk is running → expect 409 Conflict
curl -sS -X POST -H "X-API-Key: $API_KEY" \
  "http://localhost:8000/api/v1/firmware/$FW/etl-walk"
# Expected: 409 if etl_walk_status already in ('queued', 'running'); 202 if idle.

# 2. Non-existent firmware → 404
curl -sS -H "X-API-Key: $API_KEY" \
  "http://localhost:8000/api/v1/firmware/00000000-0000-0000-0000-000000000000/etl-walk-status"
# Expected: 404

# 3. Wrong-shape JSONB → walker should NOT crash (Rule #35c boundary normalisers)
#    (no direct test; the normalisers + tests in test_jsonb_normalizers.py cover this)
```

## Phase 7 — Performance + log sanity

```bash
# Check backend logs for ASYNC240 warnings, blocking-call traces, OR exceptions during walks
docker compose logs backend --tail 200 2>&1 | grep -E "ASYNC|Traceback|Exception|FATAL"
# Expected: empty (none) — Rule #5 + #29 + #43 noqa rationale discipline closes these.

# Check worker logs for the same
docker compose logs worker --tail 200 2>&1 | grep -E "Traceback|Exception|FATAL"

# Backend Tests CI status (mechanism (b) cron — Rule #41)
gh run list --workflow=backend-tests.yml --limit 10 --json event,conclusion,createdAt,headSha | jq '[.[] | select(.event=="schedule")] | .[0]'
```

## Acceptance criteria

A successful Windows-coverage test PASS:

1. All Windows walker `*_walk_status` columns reach `completed` (or remain `idle` if no
   relevant artefact found) within 5 minutes of unpack-complete; ZERO `failed` states.
2. All 5 phase-3 MCP smoke commands return JSON (not error) for every walker category
   whose `*_walk_status` is `completed`.
3. Cross-firmware aggregation tools (Rule #44) return aggregated rows when ≥2 firmware
   uploaded with overlap.
4. Findings table contains rows for every `WindowsFindingSource` Literal value covered
   by the firmware's artefacts.
5. Frontend findings page renders all sources with proper icons / colours / severity
   badges; ZERO console errors.
6. Negative tests (409 / 404) return correct HTTP codes.
7. Backend + worker logs contain ZERO unexpected Traceback / Exception entries during
   the test run.

## Companion intake

After completing this checklist, file follow-ups (if any) at
`.planning/intake/test-followup-windows-2026-05-12.md` with concrete repro steps.
