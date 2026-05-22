---
intake_id: android-image-sbom-coverage-gap-2026-05-22
title: SBOM strategies miss Android system images — Moto G32 / Elo Tablet produce 2 components from real Android rootfs
status: open
opened: 2026-05-22
parent: postmortem-over-constraint-sweep-2026-05-22 (cross-project sweep follow-up)
priority: medium
estimated_effort: 1-2 sessions (deep Android-shape investigation + new strategy + tests)
---

# Android image SBOM coverage gap

## Problem statement

After the 2026-05-22 SBOM completeness sweep, the cross-project retro-fix landed correct `extracted_path` + complete detection_roots for every candidate firmware. But two Android system images (Moto G32 + Elo Tablet) still produce only 2 SBOM components each, despite having full Android rootfs trees on disk.

| Firmware | Project | Size | Components | Sources | Path shape |
|---|---|---|---|---|---|
| `eed5db82` Moto G32 | DS1 Moto G32 | 2.8 GB | 2 | binary_strings | `.../super.img_recovered_extract/sparsechunk_5/partition_0_ext4` |
| `7433dfb1` Elo Tablet | DS1 Elo Tablet | 1.8 GB | 2 | binary_strings, library_soname | `.../payload.bin_extract/.../gzip.uncompressed_extract` |
| `1165fe74` Horizon Tablet App | Horizon Tablet App | 137 MB | 0 | (none) | `.../extracted/` (just the bare .apk file) |

For comparison, the same-project `f84544a9` Moto G30 (similar Android OTA shape) produces **147 components from 7 sources** — proves AndroidStrategy + others CAN work on Android, but something about Moto G32 / Elo Tablet's specific layout is defeating them.

## Surface evidence

After the sweep:
- Strict-probe `find_filesystem_root_strict` correctly located the Android rootfs (`init + system + bin/apex` markers detected, priority=20).
- Detection_roots populated with 64 entries (Moto G32) / 3489 entries (Elo Tablet).
- `syft_enabled=True`, `syft binary = /usr/local/bin/syft`, `syft_timeout=120`.
- After `_do_sbom_generate(force_rescan=True)`, only `binary_strings` (and `library_soname` on Elo) fired.

Notably: syft DID fire on the L4T BSP (28 components from `.deb` archives via syft's deb cataloger) and on ACM target-ld (281 syft components). So syft itself works. It just doesn't find Linux-style package metadata in Android system images.

## Likely root causes (to investigate)

1. **Syft against Android system images returns ~0 components.** Android doesn't use dpkg/apt/yum/pip/npm/gem/rust-crate — syft's catalogers don't match its filesystem layout. The `binary` cataloger might detect a few system binaries by their embedded version strings, but the bulk of "components" in an Android image are: APKs, native shared libraries (`/system/lib*/*.so`), framework JARs, vendor HALs. Syft has no Android cataloger.

2. **AndroidStrategy isn't firing OR is producing 0 components.** Read `backend/app/services/sbom/strategies/android_strategy.py`. It probably parses `build.prop`, `init.rc`, `AndroidManifest.xml`. On the Moto G32 path, the strict-probe landed at `partition_0_ext4/` which has `acct/, apex/, bin/, system/, ...` — `build.prop` should be at `partition_0_ext4/build.prop` or `partition_0_ext4/system/build.prop`. Verify which path AndroidStrategy walks and confirm the build.prop is at that path.

3. **APK files not unzipped on disk.** For the Horizon APK case, the extracted dir literally has only `1.5.18_real-release_3195.apk` — the apk wasn't unzipped. APKs ARE zip archives; the unpack pipeline should treat .apk as zip + extract to expose `AndroidManifest.xml`, `classes.dex`, `lib/`, `assets/`. Without that, AndroidStrategy has nothing to walk.

4. **Detection_roots include too many low-signal paths.** 3489 detection_roots for Elo Tablet means strategies iterate 3489 paths, most empty or fragmented. Per-root strategy invocation overhead may explode time-to-completion, AND some strategies may have per-root caps that get exhausted before reaching real content.

5. **Per-strategy timeout exceeded silently.** SbomService swallows per-strategy exceptions. If syft on a 1.8 GB tree exceeds its 120s timeout, the error is logged but the SBOM continues without those components.

## Proposed investigation plan (next session)

1. **Read AndroidStrategy + understand its predicates.** Walk the actual Moto G32 / Elo Tablet rootfs and verify `build.prop` exists at AndroidStrategy's expected path. If not, fix the path.

2. **Add an APK strategy.** For each `*.apk` file in detection_roots (or in `priv-app/`, `system_app/`, `vendor_app/`), parse the APK as a zip, read `AndroidManifest.xml` for `package`, `versionCode`, `versionName`. Emit IdentifiedComponent with `type="application"`, `purl=pkg:apk/<package>@<versionName>`, etc. Compare with Syft's APK cataloger first — if Syft already handles this, the gap may be that Syft isn't running.

3. **Add an Android .so strategy.** Walk `system/lib*/*.so` + `vendor/lib*/*.so` for component identification via `ldconfig` / soname / DT_SONAME parsing. Already exists as `library_soname` source for Elo Tablet (1 component) — probably under-firing.

4. **Trigger APK auto-unzip in the upload pipeline.** When the uploaded file is `.apk` (a zip), the tar/zip shortcut at `firmware_service._post_process_pipeline` should unzip it into `extracted/<apk-name>/` so AndroidStrategy can walk it. Compare with the existing `zip_contents/` extraction for generic zips.

5. **Add a regression test fixture for Android super.img** in `backend/tests/test_sbom_service_android.py` (or wherever Android tests live) covering:
   - APK unzip → AndroidManifest parsed
   - super.img / partition_N_ext4 layout → build.prop parsed at the right path
   - Syft on the same tree (sanity baseline)

## Out of scope

- The non-Android cases already fixed by the 2026-05-22 sweep (L4T BSP, ACM target-ld).
- MCU / bare-metal firmware (Eaton TMS320F28066, Signia, Illumisite, CRM .SDM, .hex) — these are MCU firmware blobs, no packaging metadata; 0 SBOM components is correct.
- Raw binary blobs (PowerPack .bin) — also correctly produce 0 components.

## Related files

- `backend/app/services/sbom/strategies/android_strategy.py`
- `backend/app/services/sbom/strategies/syft_strategy.py` (for the syft-cataloger-coverage angle)
- `backend/app/services/firmware_service.py:_post_process_pipeline` (for the APK auto-unzip)
- `backend/app/workers/unpack_common.py` (for the unpack pipeline)
- `.planning/postmortems/postmortem-over-constraint-sweep-2026-05-22.md` (parent postmortem)
- `scripts/retro-fix-sbom.py` (audit script used to surface this gap)
