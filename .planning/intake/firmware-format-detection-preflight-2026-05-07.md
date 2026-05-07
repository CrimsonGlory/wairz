---
title: "Firmware format detection pre-flight: surface unsupported-by-current-extractors content before user clicks Unpack"
status: pending
priority: high
target: backend/app/services/firmware_service.py + backend/app/services/format_detection.py (new) + backend/app/models/firmware.py + frontend/src/pages/FirmwarePage.tsx (or wherever the Unpack button lives)
discovered: 2026-05-07
discovered_by: Illumisite 16 GB upload session — uploaded firmware turned out to be a WinPE recovery USB containing 15.6 GB of proprietary Acronis .tibx archives; unblob has nothing to extract; user only learned this AFTER spending 10+ minutes on upload
---

## Problem

A user uploads firmware → bytes land → user clicks "Unpack" → backend runs unblob → unblob produces a near-empty extraction tree because the upload was an unsupported format → user is confused about whether something failed.

Concrete observation (2026-05-07): A 16 GB "Illumisite 1.2 Product Image" upload turned out to be a WinPE recovery USB ISO whose payload was 15.6 GB of split Acronis True Image `.tibx` archives. The wairz extraction pipeline (centered on unblob for Linux blobs) has no Acronis handler. unblob would have run, found a few Microsoft PE binaries, left the .tibx untouched, and returned an essentially-empty result. From the user's perspective: "I uploaded firmware and unpack failed."

The format mismatch was diagnosable from the upload-time directory listing (autorun.inf, bootmgr.efi, sources/boot.wim, Archive(1).tibx) — but no signal was surfaced to the user pre-Unpack.

## Why this is high priority

1. **Wairz is multi-OS** (Linux, QNX, RTOS, Windows targets). Different OSes need different extractors. Currently unblob covers Linux blobs; jadx + androguard cover Android; nothing covers Windows installers, Acronis backups, QNX `.ifs`, etc. Users uploading non-Linux firmware are silently hitting the gap.
2. **The cost of the gap is asymmetric**: the user invests minutes-to-hours in upload + retry + investigation before realizing the format isn't covered. A pre-flight detection step that runs in seconds at upload time saves all of that.
3. **The fix is ADDITIVE** — we're not removing extraction support, we're surfacing what we already know we can/can't do.

## Acceptance Criteria

- [ ] **New service `app/services/format_detection.py`** with a magic-byte detector that runs at upload time, returning a `DetectedFormat` enum/literal:
  - `linux_firmware_blob` — squashfs, cramfs, jffs2, ext2/3/4, U-Boot, kernel images, initramfs (handled by unblob)
  - `android_apk` — `.apk` zip with AndroidManifest.xml (handled by jadx + androguard)
  - `windows_installer_iso` — bootmgr.efi + sources/boot.wim or Microsoft PE bootloader signature
  - `acronis_backup` — `.tibx` files OR Acronis volume header
  - `qnx_ifs` — QNX Image File System magic
  - `pe_executable` — single PE/PE+ binary
  - `wim_archive` — Windows Imaging Format (`MSWIM\0\0\0` magic)
  - `iso_9660` — generic ISO (CD001 at 0x8001)
  - `tar_archive` — POSIX tar
  - `zip_archive` — generic ZIP (already detected; classify as "unknown payload" if contents don't match a more specific shape)
  - `unknown` — none of the above
- [ ] **New `firmware.detected_format` column** (`Mapped[str | None]`) — nullable, populated by upload-time detection. NO CHECK constraint (the value list will evolve fast as new formats are added). Migration chains off current head.
- [ ] **Per-format `extraction_capability` flag** (in code, not in DB) keyed by `DetectedFormat`:
  - `full` — wairz has a working extractor (linux_firmware_blob, android_apk, tar_archive, zip_archive)
  - `partial` — wairz can extract some surface (windows_installer_iso → boot.wim, pe_executable → strings + symbols, iso_9660 → file listing)
  - `none` — proprietary or unsupported (acronis_backup, qnx_ifs (until handler), wim_archive (until handler), unknown)
- [ ] **Frontend pre-flight banner** on the firmware detail page:
  - `full`: no banner (default behavior)
  - `partial`: yellow info banner — "Detected format: Windows Installer ISO. Wairz will extract the WinPE bootloader + boot.wim contents but cannot read the deeper installer payload. [Learn more]"
  - `none`: red warning banner — "Detected format: Acronis True Image backup. Wairz cannot extract this proprietary format. To analyze the contained device filesystem, use Acronis True Image (or community .tibx tooling) externally first, then re-upload the resulting filesystem image. [Learn more]"
- [ ] The "Unpack" button stays enabled regardless — user might want to attempt extraction anyway (defensive). Banner is informational, not blocking.
- [ ] Tests: per Rule #25 — `backend/tests/test_format_detection.py` covering each `DetectedFormat` value with a real magic-byte fixture; `backend/tests/test_firmware_router.py` extension covering the upload-time detection round-trip.

## Out of Scope

- Actually adding extractors for unsupported formats (Acronis, QNX, WIM) — separate intakes per format.
- Recursive format detection inside an unpacked tree — this intake is upload-time-only.
- Format-detection-driven workflow routing (e.g. "android.apk → run apk_scan automatically") — separate intake.

## Cross-step

Single-session work. Suggested commit shape per Rule #25:
- (i) `feat(firmware): detected_format column + magic-byte detection service`
- (ii) `feat(frontend/firmware): pre-flight banner for partial / unsupported formats`
- (iii) `test(format_detection): magic-byte coverage + upload-time round-trip`

## Related intakes

- `firmware-upload-progress-visibility-2026-05-07` — companion UX fix for the silent-100% gap. Could be bundled if both ship in the same session.
- (TODO) `wairz-multi-os-firmware-extractor-roadmap` — strategic intake for adding Acronis / QNX / WIM extractors.

## Provenance

Surfaced 2026-05-07 during the Illumisite analysis session. The user's reaction to the empty unpack on a WinPE+Acronis image was: "we also need to support windows and other OS's so saying wairz only supports linux is a lie... it supports qnx and other rtos, etc..." The pre-flight banner makes the multi-OS scope visible to operators while honest about what each format's extraction capability currently is.
