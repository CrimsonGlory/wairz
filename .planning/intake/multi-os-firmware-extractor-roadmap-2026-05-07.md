---
title: "Multi-OS firmware extractor roadmap — Acronis .tibx, QNX .ifs, WIM, eCos / FreeRTOS / Zephyr / VxWorks"
status: in-progress
priority: medium
target: backend/app/workers/unpack_*.py (new per-format) + backend/app/services/format_detection.py (companion intake) + backend/app/services/extraction_pipeline.py (new dispatch layer)
discovered: 2026-05-07
discovered_by: Illumisite 16 GB upload session + user clarification that wairz scope is multi-OS, not Linux-only
progress_2026_05_07_session2: |
  Phase 1 (dispatch infrastructure) shipped: extraction_pipeline.py + extraction_strategies.py + unpack_no_handler.py + router/arq cut-over (commits 8b01723..502efbb, 6 commits, 20 tests).
  Phase 2 handler 1 (ISO 9660 via 7z) shipped: ISO_9660 capability PARTIAL→FULL (commits a4bea55..a340e24, 4 commits, 10 tests).
  Phase 2 handler 2 (WIM via wimlib-imagex) shipped: WIM_ARCHIVE capability NONE→FULL (commits 9a0a7cc..f866b2d, 5 commits, 11 tests; backend Dockerfile gained `wimtools` apt install).
  Phase 2 handler 3 (Windows installer ISO recursive — composes ISO 9660 + WIM) shipped: WINDOWS_INSTALLER_ISO capability PARTIAL→FULL (commits 9a5c500..f2423f3, 4 commits, 17 tests).
  Capability snapshot: 8 of 12 detected formats now FULL (66.7% coverage). Remaining NONE: ACRONIS_BACKUP (deferred — documentation-as-mitigation per prior session decision; no public magic), QNX_IFS (research-pending; new intake task #9), UNKNOWN (intentional — fallback to monolith). Remaining PARTIAL: PE_EXECUTABLE (binary-analysis enhancement, different shape from extraction handlers; deferred to a binary-analysis-focused session).
remaining_2026_05_07_session2: |
  - Phase 2 handler 4 (PE_EXECUTABLE deep): binary analysis enhancement — LIEF imports/exports/.NET tables. Different shape (extends binary_analysis_service.py + ai/tools/binary.py); not an extraction worker. ~1 week. File as separate intake when picked up.
  - Phase 2 handler 5 (QNX_IFS): research-only dispatch in-flight as task #9 of session 2026-05-07-session2. QNX SDK licensing + community alternatives (dumpifs port, ifsdump). Refined Go/No-Go intake to follow.
  - Phase 2 handler 6 (ACRONIS_BACKUP): deferred per prior session's documentation-as-mitigation decision. Re-open when an open-source .tibx extractor lands.
  - Phase 3 (RTOS): unchanged — demand-driven; existing rtos_blob path covers some FreeRTOS/eCos/Zephyr/VxWorks via classify_firmware fast paths.
---

## Problem

Wairz is positioned as a multi-OS firmware analysis platform (Linux + QNX + other RTOS + Windows targets), but the current extraction pipeline is centered on unblob (which covers Linux blobs: squashfs, cramfs, jffs2, ext, U-Boot, kernels, initramfs) plus the Android side (jadx + androguard). Non-Linux / non-Android firmware lands but cannot be analyzed past surface-level magic detection.

Concrete observations from the audit-2026-05-04 corpus + the 2026-05-07 Illumisite session:

| Format | Encountered in | Current support | Gap |
|---|---|---|---|
| Linux squashfs/cramfs/jffs/ext + U-Boot | Most consumer routers, OpenWrt | Full (unblob) | — |
| Android APK | DPCS10, RespArray | Full (jadx + androguard) | — |
| Acronis `.tibx` | **Illumisite 1.2 (medical device)** | None | High priority — medical-device installers commonly use this |
| Windows Imaging Format `.wim` | WinPE installers | Surface only (zipfile sees the wim as a file) | Medium — covers a lot of medical/industrial recovery USBs |
| QNX `.ifs` Image File System | (referenced by user as in-scope) | None | Medium — QNX is common in automotive, medical, defense |
| Windows installer ISO + bootmgr | Industrial devices, medical recovery USBs | Partial (zipfile sees the layout) | Medium |
| eCos / FreeRTOS / Zephyr / VxWorks images | (referenced as "other RTOS") | None | Low-medium — varies by vendor |

## Why this is medium-priority (not high)

This is strategic / scope-expansion work, not bug-fix or operator-blocker work:

- The 2026-05-07 Illumisite case has a **workaround** (extract `.tibx` via Acronis True Image externally, re-upload the resulting filesystem). The companion intake `firmware-format-detection-preflight-2026-05-07` makes that workaround visible to users.
- Adding handlers for proprietary formats (Acronis especially) is RE work. Each handler is its own multi-week effort. Sequencing matters: pick handlers based on observed workload demand, not theoretical completeness.
- The architectural changes (extraction pipeline dispatch layer, per-format unpack workers) are substantial — multi-session campaign work.

## Proposed staging

**Phase 1 — pipeline architecture** (foundational, ships first):
1. `format_detection.py` (companion intake `firmware-format-detection-preflight-2026-05-07`) — produces `DetectedFormat` per upload.
2. `extraction_pipeline.py` (new) — dispatches to per-format unpack workers based on `DetectedFormat`. Currently routes everything to `unpack_firmware_job` (the unblob worker); after this refactor, routes android_apk to a new APK pipeline, leaves linux_firmware_blob on unblob, and surfaces "no handler for this format" gracefully for the rest.
3. Per-format worker registration via a strategy table in `app/workers/extraction_strategies.py`.

**Phase 2 — handler additions, prioritized by workload demand**:
- `wim_archive` handler (Windows Imaging Format) — wimlib + 7zip; covers WinPE + Windows installer images; ~1 week of integration work.
- `acronis_backup` handler — research community `.tibx` extractors; if none usable, defer with documented workaround; ~unknown effort, possibly multi-week if RE work needed.
- `qnx_ifs` handler — QNX SDK has tools but proprietary licensing; community tools may exist; ~1-2 weeks scoping.
- `pe_executable` deep analysis — already partially covered via radare2 / Ghidra paths; gap is the Windows-specific PE shape (imports table, debug symbols, .NET metadata). ~1 week to extend existing analysis tools.
- `iso_9660` generic — `7z` or libisoburn; trivial; covers a broad workload of "I have an ISO, what's in it?". ~2 days.

**Phase 3 — RTOS targets, demand-driven**:
- `ecos`, `freertos`, `zephyr`, `vxworks` — each is a research project. Pick handlers based on which RTOS the user base actually encounters.

## Acceptance Criteria

This intake is **strategic / planning** — closure means having a concrete roadmap, not implementing every handler. Specifically:

- [ ] Phase 1 architecture (extraction pipeline dispatch + format detection + per-format strategy registration) shipped.
- [ ] Roadmap table maintained in `.mex/context/architecture.md` listing each format + current support level + planned effort.
- [ ] Each Phase 2 handler addition gets its own intake when picked up.
- [ ] Document the workarounds clearly in user-facing docs for formats that don't yet have native handlers.

## Out of Scope

- Implementing every Phase 2/3 handler in one campaign — too big.
- Reverse-engineering proprietary formats with no community tooling — separate scoping intake per format.

## Provenance

User correction 2026-05-07: "we also need to support windows and other OS's so saying wairz only supports linux is a lie... it supports qnx and other rtos, etc..." The Illumisite case is the immediate trigger; this intake captures the broader strategic scope so future format-coverage decisions land against a known roadmap rather than ad-hoc requests.
