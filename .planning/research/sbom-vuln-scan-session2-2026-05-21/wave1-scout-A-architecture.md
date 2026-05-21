# Wave-1 Scout A — Architecture + Format-Assumption Audit (S2)

> Investigation date: 2026-05-21 (Session 2 continuation)
> Operator's Rule #52 mandate: don't hardcode strict formats — adaptable / versatile / flexible / resilient
> Branch tip at audit: `4b949d4` (Session 1 close)
> Scope: trace upload → unpack → SBOM emit → vuln-scan flow + enumerate every hardcoded format assumption that would block Rule #52 adaptability

## Executive Summary

The upload → SBOM → vuln-scan flow has **two genuinely independent extraction pipelines**: a fast `_post_process_pipeline` at upload time (tarball + ZIP shortcuts only, no binwalk / unblob, no plugins) and a heavy `unpack_firmware_job` at operator click (full unblob → binwalk → standalone-binary fallback, no shortcuts). The classification surface in between (`classify_firmware`, `_post_process_pipeline`'s branch tree, `unpack.py` Stage 1) is **partially Rule #52-aware** — the file-format YAML catalog (Rule #52 worked example #2) is consulted in `classify_firmware` but BYPASSED entirely in `_post_process_pipeline` and in `unpack.py`'s Stage 1 fast-path tree (lines 413-827). The biggest hardcoded gap is `_post_process_pipeline:589-754` — it inspects `raw_filename.lower().endswith(".tar.gz" / ".tar" / ".zip" / ...)` and `zipfile.is_zipfile()` directly with NO catalog consultation, then branches on three private heuristics (`_is_android_firmware_zip`, `_zip_contains_rootfs`, `_extract_firmware_from_zip`) all of which duplicate `classify_firmware`'s own logic in a less-extensible form. The SBOM `_STRATEGY_CLASSES` tuple at `sbom/service.py:68-85` is a **hardcoded Python class registry** — not YAML-driven, not pluggable. **Fix #9's correct Rule #52 shape is to delete the `_post_process_pipeline` ZIP/tar branching ENTIRELY and replace it with: `(a)` call `classify_firmware()` to get the format_id; `(b)` look up the resolved manifest's `pre_upload.extraction_capability`; `(c)` if `full`, enqueue `unpack_firmware_job`; if `partial` (PE / VHDX), enqueue a partial extractor; if `none`, leave as a single binary. The Stage 1 fast-paths in `unpack.py` also factor into the same dispatch — the YAML manifest's `output.classifier_format` IS the dispatch key.**

## End-to-End Flow Reconstruction (post-Session-1)

### 1. Upload → classify (which file-format detection fires?)

**Two distinct format-detection layers exist today:**

- **(a) `format_detection.detect_format(path)`** at `backend/app/services/format_detection.py:193`, called once at upload from `_post_process_pipeline:570`. Returns a `DetectedFormat` enum (20 values + `UNKNOWN` at lines 67-86). **AS OF P3.1.h this route is catalog-driven** — `_catalog_resolve(head, path, size)` at `format_detection.py:268-282` consults the YAML catalog and reads each manifest's `pre_upload.detected_format` field. `_LEGACY_BRIDGE_DETECT` at line 289 is a graceful-degrade path used only if the catalog fails to load (Rule #34 boundary-normaliser parallel). **This is the cleanest Rule #52-aligned surface in the system.** The detected_format is written to `firmware.detected_format` and surfaces in the upload-status response (`firmware.py:115-130`); the frontend uses it to show "extraction capability" badges.

- **(b) `classify_firmware(firmware_path)`** at `backend/app/workers/unpack_common.py:1452-1629`. Called from `unpack.py:407` (Stage 1 dispatch in `_unpack_firmware_inner`). Returns a **legacy free-form string** ("android_ota" / "intel_hex" / "uefi_firmware" / "rtos_blob" / "linux_blob" / `f"{rtos_name}_elf"`). P3.1.h cut-over routes through the catalog at lines 1531-1567, but lines 1469-1523 are a **pre-catalog ZIP-bridge that hardcodes Android marker sets in Python**, and lines 1571-1629 are **legacy bridges that the catalog can't yet express** (Android sparse magic, UEFI inner-ZIP, partition_dump_tar, linux_rootfs_tar, ELF + RTOS dispatch, Intel HEX, MZ→PE, RTOS in raw blobs). The `_catalog_to_classify_str` helper at line 1632 explicitly OPTS OUT for 8 format_ids (`zip_archive`, `tar_archive`, `iso_9660`, `windows_installer_iso`, `uefi_firmware`, `partition_dump_tar`, `rootfs_tar`, `linux_elf`, `intel_hex`, `pe_binary`, `rtos_blob`) — these route to the legacy bridge instead.

Conclusion: **two independent detection paths** — pre-upload (catalog-aware, deterministic) and unpack-time (catalog + legacy hybrid). The pre-upload path is good. The unpack-time path is the next Rule #52 target.

### 2. Unpack branching (`_post_process_pipeline` decision tree)

`backend/app/services/firmware_service.py:544-822`. Body sequence:

1. **L566-577 — detecting stage.** Calls `detect_format(storage_path)`. **NO branching on the result** — the detected_format is just stamped on the row. The subsequent extraction branches IGNORE this value.
2. **L580-660 — Tarball shortcut.** Triggered by `raw_filename.lower().endswith((".tar.gz", ".tar", ".tgz", ".tar.bz2", ".tar.xz"))` AND `tarfile.is_tarfile(storage_path)`. This is **HARDCODED EXTENSION MATCHING** — does not consult the catalog's tar_archive manifest. Calls `tarfile.extractall(filter=_firmware_tar_filter)` (with archive-dense recursion via `_is_archive_dense_layout` + `_recursive_extract_nested`).
3. **L662-759 — ZIP shortcut.** Triggered by `raw_filename.lower().endswith(".zip")` AND `zipfile.is_zipfile(storage_path)`. **THEN branches on three private heuristics — none catalog-aware:**
   - `_is_android_firmware_zip(storage_path)` at `firmware_service.py:121-152` — duplicates the Android-marker logic in `classify_firmware:1478-1497` AND in `format_detection.py:392-419`. **Three independent copies of the same heuristic.**
   - `_zip_contains_rootfs(storage_path)` at `firmware_service.py:78-118` — rootfs-marker count heuristic with hardcoded `{"etc", "usr", "bin", "lib", "sbin"}` set.
   - `_extract_firmware_from_zip(storage_path, firmware_dir)` at `firmware_service.py:155-234` — generic ZIP extraction to `zip_contents/`.
4. **L781-803 — analyzing stage.** Architecture / endian / OS detection + `populate_detection_roots(firmware)`.
5. **L805-822 — ready terminal.** Fires `_run_hardware_firmware_detection_safe(firmware.id, firmware.extracted_path)` which fans out to all 26 walkers (Session 1 Fix #3 un-gated this).

**Critical observation: `_post_process_pipeline` NEVER calls `unpack_firmware()` (the binwalk/unblob entry point at `unpack.py:300`).** It handles only tar + ZIP. For anything else — raw ELF, PE binaries, Intel HEX, Android sparse, Android boot, UEFI, partition dump tar, MSU/MSI/MSIX/CAB/VHDX/WIM/PSF/Acronis/QNX/Awinic/Mediatek/Samsung/Tegra — the upload finishes with `extracted_path=NULL` or `extracted_path=zip_contents/` and the operator MUST click "Unpack" to run the full extraction. **This is Fix #9.**

### 3. SBOM strategy selection

`backend/app/services/sbom/service.py:68-85` declares the strategy registry as a **hardcoded tuple of Python classes**:

```python
_STRATEGY_CLASSES: tuple[type[SbomStrategy], ...] = (
    DpkgStrategy, OpkgStrategy, PythonPackagesStrategy,
    KernelStrategy, FirmwareMarkersStrategy,
    BusyBoxStrategy, CLibraryStrategy, GccStrategy,
    SoFilesStrategy, BinaryStringsStrategy,
    AndroidStrategy,
)
```

`SyftStrategy` runs once at the top (`service.py:248-253`); the 11 curated strategies run per-partition (lines 257-268). Order matters: Syft emits medium-confidence; curated strategies override. **There is NO per-format dispatch** — every strategy runs on every firmware. Each strategy decides on its own whether to fire (e.g. `DpkgStrategy` checks for `/var/lib/dpkg/status`; `AndroidStrategy` checks for `system/build.prop`). This is **resilient but inefficient** — an MSI-extracted firmware runs the Android+dpkg+opkg walkers fruitlessly.

The shape is a **class-hierarchy registry, NOT YAML-driven**. Adding a new strategy is a Python edit: write the class, add it to the tuple. Operator extensibility = zero.

### 4. Vuln-scan path (Grype / NVD / curated-tier flow)

`backend/app/routers/sbom.py:445-547` (`_run_vuln_scan_background`):

1. Reads `settings.vulnerability_backend` (`config.py:56`, default `"grype"`).
2. If `grype_available()` (PATH lookup at `services/grype_service.py:50`) and backend is grype → `scan_with_grype(firmware_id, project_id, db)` at `services/grype_service.py:60-265`.
3. Else → `VulnerabilityService(db).scan_components(firmware_id, project_id, force_rescan)` at `services/vulnerability_service.py:60-144` (NVD HTTP path).
4. Curated-tier matcher is INDEPENDENT — `cve_matcher.match_firmware_cves` at `services/hardware_firmware/cve_matcher.py:902` fires from the hw-fw cve-match path (`/api/v1/projects/{p}/hardware-firmware/cve-match`), NOT from `/sbom/vulnerabilities/scan`.

`scan_with_grype` writes a CycloneDX 1.5 SBOM to a NamedTemporaryFile (`grype_service.py:116`), invokes `grype sbom:<path> -o json --quiet` (line 159), parses JSON, inserts `SbomVulnerability` rows with `match_tier=None`. **No format-specific branching — Grype handles every ecosystem itself.** Same for NVD path: per-component CPE lookup. The vuln-scan layer is **format-agnostic by design** — it consumes SBOM components, not raw firmware. This layer is fine for Rule #52; it inherits whatever the SBOM strategies emit.

## Format-Assumption Audit

### Assumption #1 (DOMINANT): `_post_process_pipeline` extension-string matching at `firmware_service.py:589` + `:667`

- **What it assumes:** A file is a tar iff its filename ends in `.tar.gz` / `.tar` / `.tgz` / `.tar.bz2` / `.tar.xz`. A file is a ZIP iff its filename ends in `.zip`. Files with other extensions never get the upload-time shortcut and ALWAYS require an explicit operator-driven `/unpack` step.
- **Where it lives:** `firmware_service.py:589` (`is_tar = raw_filename.lower().endswith(...)`); `firmware_service.py:666-669` (`is_zip = raw_filename.lower().endswith(".zip") and zipfile.is_zipfile(storage_path)`).
- **Adaptable today?** NO. Even renaming a `.tar.gz` to `.firmware` defeats the path. An operator's "we have a new container format" needs Python edits to this file.
- **Rule #52 refactor shape:** Replace lines 580-759 with a single catalog-driven dispatch. The catalog already declares `output.classifier_format` AND `pre_upload.extraction_capability` per manifest. The shape:

  ```python
  detected = detect_format(storage_path)
  capability = EXTRACTION_CAPABILITY.get(detected, ExtractionCapability.NONE)
  if capability == ExtractionCapability.FULL:
      # Enqueue unpack_firmware_job (matches Fix #9)
  elif capability == ExtractionCapability.PARTIAL:
      # Partial extractor (PE → strings, VHDX → mount, MSI → tables)
  # else: leave as standalone binary; downstream uses storage_path directly
  ```

  This eliminates the three-way hardcoded shortcut tree AND fixes Fix #9 at the same time.

### Assumption #2: `_is_android_firmware_zip` triplicated heuristic at three independent call sites

- **What it assumes:** Android-OTA detection is "any of (a) payload.bin, (b) META-INF/com/google/android/*, (c) 2+ known partition images present in ZIP".
- **Where it lives:** Three independent copies:
  - `backend/app/services/firmware_service.py:121-152` (`_is_android_firmware_zip`)
  - `backend/app/workers/unpack_common.py:1478-1497` (inline in `classify_firmware`)
  - `backend/app/services/format_detection.py:392-419` (legacy bridge)
  - Plus the YAML manifest at `backend/app/services/file_format_catalog/data/file_formats/_system/android_ota.yaml:23-48` (zip_markers signal).
- **Adaptable today?** PARTIALLY. The YAML manifest IS the single source of truth in P3.1.h, but two Python copies are still live, each branching on inputs the YAML can't yet describe (zip_markers + dispatch.by_zip_inner_file would cover this — but the bridges don't use the catalog).
- **Rule #52 refactor shape:** Delete the two Python heuristics; route through `classify_firmware()` which now consults the catalog. The android_ota.yaml manifest's `zip_markers` signals (with `inner_min_count: 2`) already encode the rule. The frontend just sees `detected_format=android_ota` and the dispatch flows from there.

### Assumption #3: `unpack.py` Stage 1 hardcoded fw_type branch tree at lines 413-827

- **What it assumes:** Each format has a Python-coded fast path: `android_apk` copies the APK as-is (`unpack.py:413-429`); `uefi_firmware` calls `run_uefi_extraction` (lines 431-471); `intel_hex` converts to binary + runs `detect_rtos` (lines 474-597); `*_elf` / `rtos_blob` copies + analyses (lines 599-650); `elf_binary` / `pe_binary` copies + `analyze_binary` (lines 652-684); `android_ota` / `android_sparse` / `android_boot` / `android_scatter` runs `_extract_android_ota` (lines 686-736); `partition_dump_tar` (lines 738-779); `linux_rootfs_tar` (lines 780-828).
- **Where it lives:** `backend/app/workers/unpack.py:413-828` — 8 `if fw_type == ...` branches plus `fw_type.endswith("_elf")` dispatch.
- **Adaptable today?** NO. Adding a new format = adding a new branch (Python edit + tests + rebuild). The YAML catalog can declare the format, but the EXTRACTION POLICY is hardcoded.
- **Rule #52 refactor shape:** This is the **second Rule #52 candidate after Fix #9 lands**. Each fast-path branch becomes an `extraction_strategy` declaration in the YAML manifest:

  ```yaml
  # in linux_elf.yaml
  extraction:
    strategy: copy_as_binary  # closed Literal
    post_processing: [analyze_binary, detect_rtos_companions]
  ```

  The dispatch table `EXTRACTION_STRATEGIES: dict[<strategy_literal>, Callable]` becomes a closed `Literal` plus a Python-side strategy registry (mirrors `SIGNAL_EVALUATORS` shape exactly). Adding `windows_msu` extraction becomes ship-a-YAML-plus-write-the-strategy-handler, not edit `unpack.py`. **Same shape Rule #52 worked example #1 (bare-metal MCU) uses for policy evaluators.**

### Assumption #4: SBOM `_STRATEGY_CLASSES` hardcoded tuple at `sbom/service.py:68-85`

- **What it assumes:** Exactly these 11 strategies fire on every firmware. Order is significant (Syft first for breadth; curated overrides).
- **Where it lives:** `backend/app/services/sbom/service.py:68-85`.
- **Adaptable today?** NO. Adding e.g. an "RPM database" strategy requires writing the Python class AND editing this tuple. The user's mandate — "we won't be the only ones ingesting files" — implies the next-N strategies (Yocto BitBake bb files, Buildroot defconfigs, OpenBMC `subordinate-meta` lists, Snap packages, AppImage AppDir, Flatpak refs, vendor-specific SBOM imports) might come from partners, not the wairz core team.
- **Rule #52 refactor shape:** Convert to a YAML strategy registry. Each strategy ships a YAML manifest declaring `detection_signal` (path glob + magic bytes), `cost_class` (cheap / medium / expensive), `output_schema` (closed Literal), plus a Python implementation registered via `register_sbom_strategy(name, cls)`. Operator overlays add new strategies; wairz core ships the canonical ones in `_system/sbom_strategies/`. **Mirror Rule #52 worked example #2 (file_format_catalog/plugins).**

### Assumption #5: `format_detection._LEGACY_BRIDGE_DETECT` hardcoded magic-byte tree at `format_detection.py:289-380`

- **What it assumes:** When the catalog fails to load (boundary-normaliser parallel — Rule #34 graceful-degrade), fall back to a Python-coded magic-byte tree covering 25+ formats.
- **Where it lives:** `backend/app/services/format_detection.py:289-380`.
- **Adaptable today?** Acceptable — this is a FALLBACK path, not the canonical one. The canonical path IS catalog-driven (lines 268-282).
- **Rule #52 refactor shape:** Leave it; this is Rule #34 emergency-fallback discipline. Document that it's an emergency path; the Rule #46 META-CANARY `test_extraction_capability_catalog_derived_not_hardcoded` already enforces the canonical path is catalog-derived (`format_detection.py:13-15` comment).

### Assumption #6: Vendor-AES decryption key triple heuristic at `unpack.py:887-939`

- **What it assumes:** Some vendor firmware (EDAN MPM RespArray case) ships AES-CBC ciphertext archives with the key + iv hardcoded in an update shell script inside a recovery rootfs. The heuristic `_detect_openssl_key_triples` looks for OpenSSL-shaped key triples in shell scripts.
- **Where it lives:** `backend/app/workers/unpack.py:887-939` + helper at `backend/app/workers/unpack_common.py` (`_detect_openssl_key_triples`, `_decrypt_vendor_encrypted_archives`).
- **Adaptable today?** PARTIALLY — works for OpenSSL-shaped key triples in shell scripts. Doesn't cover key derivation, asymmetric, or non-OpenSSL encryption.
- **Rule #52 refactor shape:** Move to a vendor-key-extraction plugin family. Each vendor (EDAN, Acronis, Samsung, Tegra, …) gets a YAML manifest declaring detection signals + a registered Python plugin (`register_vendor_decryption(name, cls)`). Operator adds a new vendor without core edits. **Mirror file_format_catalog plugins shape — closed Literal `vendor_decryption_kind` + open plugin registry.**

### Assumption #7: Partition-name hardcoded sets at `unpack_common.py:1731-1733` (`_is_partition_dump_tar`)

- **What it assumes:** Qualcomm EDL dumps have `aboot, rpm, tz, hyp, modem, sbl1` partitions; MTKClient has `lk, tee, preloader, md1img, spmfw, sspm`; generic has `boot, recovery, system, vendor, super, vbmeta, dtbo`.
- **Where it lives:** `backend/app/workers/unpack_common.py:1731-1733` hardcoded sets.
- **Adaptable today?** NO. New vendor (e.g. Rockchip, Allwinner, Spreadtrum) needs a Python edit to add markers.
- **Rule #52 refactor shape:** YAML manifest `partition_dump_tar.yaml` declaring vendor partition sets as a closed-grammar `PartitionMarkers` block + closed `vendor: Literal["qualcomm", "mediatek", "generic"]` + free-string vendor-extensions slot (Rule #52 worked example #2's "free-string taxonomy" precedent, mirrors `rtos_family` shape).

### Assumption #8: Android partition-sibling hardcoded set at `unpack.py:67-71`

- **What it assumes:** `_ANDROID_PARTITION_SIBLINGS` = `{vendor, system, odm, product, system_ext, boot, vendor_boot, init_boot, modem, firmware}`. Used by `_pick_detection_root` (unpack.py:74-90) for multi-partition layouts.
- **Where it lives:** `backend/app/workers/unpack.py:67-71`.
- **Adaptable today?** NO. New Android partition names (Pixel's `pvmfw`, future `pkvm`, custom OEM partitions) need a Python edit.
- **Rule #52 refactor shape:** Same as #7 — YAML declaration + free-string taxonomy with optional vendor extensions.

### Assumption #9: Rootfs marker hardcoded set at `unpack_common.py:113-117` (`_ROOTFS_MARKER_DIRS`)

- **What it assumes:** A directory is a rootfs if it contains ≥2 of `{bin, etc, usr, lib, lib64, var, sbin, dev, proc, sys, tmp, boot, root, home, opt, media, mnt, run, system, vendor, product, system_ext, apex, data}`.
- **Where it lives:** `backend/app/workers/unpack_common.py:113-117` + duplicated logic in `firmware_service.py:86` (`rootfs_markers = {"etc", "usr", "bin", "lib", "sbin"}`).
- **Adaptable today?** PARTIALLY — works for Linux + Android. Doesn't cover QNX / VxWorks / IoT-specific rootfs shapes.
- **Rule #52 refactor shape:** Move to YAML — operator-extensible per-OS rootfs definition. Closed Literal `rootfs_family: Linux | Android | QNX | VxWorks | custom` with each family declaring its marker set.

## File-Format Catalog Integration

**Current wiring:**
- `format_detection.detect_format` consults the catalog (`format_detection.py:268-282`).
- `unpack_common.classify_firmware` consults the catalog (`unpack_common.py:1531-1567`).
- These are the ONLY two integration points.

**Gaps (format decisions that BYPASS the catalog):**
- `_post_process_pipeline:589-759` — entire tar/ZIP shortcut tree.
- `unpack.py:413-828` — entire Stage 1 fast-path dispatch.
- `unpack.py:67-71` — `_ANDROID_PARTITION_SIBLINGS`.
- `unpack_common.py:113-117` — `_ROOTFS_MARKER_DIRS`.
- `unpack_common.py:1731-1733` — partition-dump-tar vendor sets.
- `unpack_common.py:1722` — `_is_partition_dump_tar` (tarfile.is_tarfile + name heuristic).
- `unpack_common.py:1715` — `_is_rootfs_tar` (similar).
- `firmware_service.py:78-118` — `_zip_contains_rootfs`.
- `firmware_service.py:121-152` — `_is_android_firmware_zip`.
- `sbom/service.py:68-85` — `_STRATEGY_CLASSES`.
- `sbom/strategies/syft_strategy.py:23-37` — `_SYFT_TYPE_MAP` (hardcoded Syft type → wairz type mapping).
- `vulnerability_service.py` — backend selector (`grype` vs `nvd`) hardcoded in config; could be a plugin registry.

**Integration score: ~25%.** The catalog is consulted for pre-upload labelling and classification but BYPASSED for every downstream extraction-policy decision.

## SBOM Strategy Registry Shape

- **How does sbom_service decide which strategy fires?** ALL 11 strategies fire on EVERY firmware. Each strategy gates itself on internal heuristics (e.g. `DpkgStrategy` checks for `var/lib/dpkg/status`; `AndroidStrategy` checks for `system/build.prop`).
- **Shape:** Class hierarchy. `SbomStrategy` ABC at `sbom/strategies/base.py:44-73` with single `run(ctx)` method. Subclasses share helpers via the ABC. The tuple of strategy CLASSES is hardcoded.
- **NOT YAML-driven.** Each strategy ships a Python module + class + import in `sbom/service.py:31-49` + entry in `_STRATEGY_CLASSES`.
- **Adaptability score: 3/10.** The base class IS clean (Rule #27 N+1 cut-over from the 2412-LOC monolith in session 7e8dd7c3). But operator extension requires Python edits in 3 places + a Docker rebuild. Mirrors the pre-Rule-#52 bare-metal MCU surface (before commit `f0bbb1f..ffcfc73`).

## Adaptability Gap Surface (Rule #52 candidates)

Top 5 places where a closed-grammar Rule #52 refactor would land, ranked by operator-extensibility leverage:

### Candidate #1 (FIX #9 + Rule #52 INSTANCE #3): `_post_process_pipeline` extraction dispatch

- **File:line:** `firmware_service.py:580-759`
- **Scope:** ~250 LOC delete + ~140 LOC new dispatch + new YAML field `output.upload_extraction_action: Literal["shortcut_tar" | "shortcut_zip_rootfs" | "shortcut_generic_zip" | "enqueue_unpack_firmware_job" | "single_binary"]`
- **Rule #52 instance #:** Would become **Rule #52 instance #3** (Rule-of-Three DURABLE BEYOND DEBATE) — promotes the rule per the bare-metal + file-format precedents.
- **Sequencing:** Ship Fix #9 first (Session 2 HIGH priority `sbom-regr-session2:Fix-9`) as a minimum-viable "if `_post_process_pipeline` can't extract directly, enqueue `unpack_firmware_job`". Then in Session 3 or later, factor the YAML field once the bare-bones path is live.

### Candidate #2: `unpack.py` Stage 1 dispatch (`fw_type == "..."` tree)

- **File:line:** `unpack.py:413-828`
- **Scope:** ~410 LOC refactor — each fast-path branch becomes a YAML-declared `extraction_strategy` with a closed Literal + registered Python handler. The `EXTRACTION_STRATEGIES: dict[<literal>, Callable]` dispatch table mirrors `SIGNAL_EVALUATORS` shape.
- **Rule #52 instance #:** Would become **Rule #52 instance #4** if shipped after Fix #9.
- **Sequencing:** Session 4+ or later. Big enough that it needs its own Wave-1+Wave-2 design pass.

### Candidate #3: SBOM `_STRATEGY_CLASSES` registry

- **File:line:** `sbom/service.py:68-85` + `sbom/__init__.py` re-exports
- **Scope:** ~80 LOC refactor — convert tuple to YAML registry mirroring `PLUGIN_REGISTRY` in `file_format_catalog/resolver.py:716-758`. Closed `cost_class` + `applicable_format_ids` per strategy. `freeze_sbom_strategy_registry()` post-startup.
- **Rule #52 instance #:** Would become **Rule #52 instance #5** (DURABLE BEYOND DEBATE strongly reinforced) — third application of the closed-grammar + Python plugin escape hatch + frozen registry pattern.
- **Sequencing:** Can ship independently of #1 / #2. Operator-extensible SBOM strategies (vendor partners shipping "scan our proprietary format for our components") is the user's literal "we won't be the only ones ingesting files" mandate.

### Candidate #4: Partition / rootfs marker sets

- **File:line:** `unpack.py:67-71`, `unpack_common.py:113-117`, `unpack_common.py:1731-1733`
- **Scope:** ~50 LOC — small but high-frequency operator-extension request shape ("we have a new vendor with new partition names"). Closed `rootfs_family` Literal + free-string vendor taxonomy + YAML override capability.
- **Sequencing:** Can ship as a small standalone refactor any time after Fix #9 lands.

### Candidate #5: Vendor-AES decryption registry

- **File:line:** `unpack.py:887-939` + `unpack_common.py` (`_detect_openssl_key_triples`)
- **Scope:** ~120 LOC — vendor-specific key-extraction plugin family. Mirrors Rule #36 BYO-binary discipline (vendor-supplied parsers in hardened side-containers) for vendor-supplied DECRYPTION code. Plugin-registry shape but with **stricter** sandboxing (Rule #36 Exception 3 — vendor-supplied parsers in network=none cap-drop containers).
- **Sequencing:** Long-tail Rule #52 application. Holds until a 2nd vendor needs custom decryption.

## Cross-Index of File:Line Refs (top 30)

| # | Path | Lines | What |
|---|---|---|---|
| 1 | `backend/app/services/firmware_service.py` | 544-822 | `_post_process_pipeline` — upload-time extraction dispatch |
| 2 | `backend/app/services/firmware_service.py` | 121-152 | `_is_android_firmware_zip` — duplicated Android-OTA heuristic |
| 3 | `backend/app/services/firmware_service.py` | 78-118 | `_zip_contains_rootfs` — hardcoded rootfs markers |
| 4 | `backend/app/services/firmware_service.py` | 155-234 | `_extract_firmware_from_zip` — generic ZIP → `zip_contents/` |
| 5 | `backend/app/services/firmware_service.py` | 875-937 | `_run_upload_post_processing_background` — Rule #33 runner |
| 6 | `backend/app/services/format_detection.py` | 193-282 | `detect_format` — catalog-aware (P3.1.h) |
| 7 | `backend/app/services/format_detection.py` | 289-380 | `_LEGACY_BRIDGE_DETECT` — fallback magic-byte tree |
| 8 | `backend/app/services/format_detection.py` | 67-86 | `DetectedFormat` enum (20 values) |
| 9 | `backend/app/workers/unpack_common.py` | 1452-1629 | `classify_firmware` — catalog + legacy bridge hybrid |
| 10 | `backend/app/workers/unpack_common.py` | 1632-1653 | `_catalog_to_classify_str` — bridge opt-out list |
| 11 | `backend/app/workers/unpack_common.py` | 1731-1733 | Partition-dump-tar hardcoded vendor sets |
| 12 | `backend/app/workers/unpack_common.py` | 113-117 | `_ROOTFS_MARKER_DIRS` |
| 13 | `backend/app/workers/unpack.py` | 67-71 | `_ANDROID_PARTITION_SIBLINGS` |
| 14 | `backend/app/workers/unpack.py` | 413-429 | Stage 1: `android_apk` fast path |
| 15 | `backend/app/workers/unpack.py` | 431-471 | Stage 1: `uefi_firmware` fast path |
| 16 | `backend/app/workers/unpack.py` | 474-597 | Stage 1: `intel_hex` fast path + RTOS detect |
| 17 | `backend/app/workers/unpack.py` | 599-650 | Stage 1: `*_elf` / `rtos_blob` fast path |
| 18 | `backend/app/workers/unpack.py` | 652-684 | Stage 1: `elf_binary` / `pe_binary` fast path |
| 19 | `backend/app/workers/unpack.py` | 686-736 | Stage 1: `android_ota` / `android_sparse` / `android_boot` / `android_scatter` |
| 20 | `backend/app/workers/unpack.py` | 738-779 | Stage 1: `partition_dump_tar` |
| 21 | `backend/app/workers/unpack.py` | 780-828 | Stage 1: `linux_rootfs_tar` |
| 22 | `backend/app/workers/unpack.py` | 829-1011 | Stage 2: unblob → binwalk3 fallback chain |
| 23 | `backend/app/workers/unpack.py` | 887-939 | Vendor-AES auto-decrypt |
| 24 | `backend/app/workers/unpack.py` | 93-191 | `_run_hardware_firmware_detection_safe` (walker fan-out) |
| 25 | `backend/app/services/sbom/service.py` | 68-85 | `_STRATEGY_CLASSES` hardcoded tuple |
| 26 | `backend/app/services/sbom/service.py` | 239-301 | `generate_sbom` — coordinator |
| 27 | `backend/app/services/sbom/strategies/base.py` | 24-73 | `SbomStrategy` ABC + `StrategyContext` |
| 28 | `backend/app/services/sbom/strategies/syft_strategy.py` | 23-37 | `_SYFT_TYPE_MAP` hardcoded |
| 29 | `backend/app/services/file_format_catalog/resolver.py` | 716-758 | `PLUGIN_REGISTRY` + `register_matcher` (Rule #52 reference shape) |
| 30 | `backend/app/services/file_format_catalog/__init__.py` | 1-53 | Catalog public API |

## Open Questions for Wave-2

1. **W2-α convergence:** If Fix #9 reshapes to "look at `detected_format` + call `unpack_firmware_job` when catalog says extraction_capability=full", does that single change implicitly cover ALL operator's adaptability mandate? Or is the full Rule #52 instance #3 (closed-grammar `upload_extraction_action`) needed in the same session?
2. **W2-β cross-feature blow-up:** What's the cross-feature attack at `_post_process_pipeline` (catalog-driven) AND `unpack.py` Stage 1 (hardcoded) running on the same firmware? Specifically — if an upload's `detected_format=android_ota` causes `_post_process_pipeline` to enqueue `unpack_firmware_job`, and Stage 1 then ALSO sees `fw_type=android_ota`, can they race or double-extract? (W2-β §SC5-NEW-SBOM-? attack target.)
3. **W2-β cross-feature attack #2:** If an operator's vendor-overlay YAML declares a new format (e.g. `acme_firmware_v3`), `classify_firmware` returns it, but `unpack.py:413-828` has NO branch — current behavior falls through to Stage 2 unblob/binwalk. Is that ACCEPTABLE Rule #52 graceful-degrade, or does it need an `unknown_strategy → fall through to unblob` explicit declaration?
4. **W2-γ Rule #28 yardstick on instance #3:** If Fix #9's minimum-viable shape is ~140 LOC + the full Rule #52 instance #3 is ~390 LOC including YAML schema extension + cross-stack alignment, does this fit in Session 2 alongside Fix #1 (420 LOC) + Fix #6 (105 LOC) + Fix #11 (220 LOC)? Or is Rule #52 instance #3 a Session 3 punt?
5. **SBOM strategy registry timing:** Should the SBOM strategy registry refactor (candidate #3) ship in Session 2 alongside Fix #1's SBOM /generate Rule #33 conversion? They touch the same file (`sbom/service.py`); one bundled refactor might be cheaper than two.
6. **Operator partner shape:** What's the *concrete* operator/partner extension we're optimising for? "Vendor partner ships their own SBOM strategy" vs "Operator overlays a new firmware format YAML" vs "Operator overlays a new vendor partition naming convention" — different Rule #52 instances solve different needs. Wave-2 should ground in a concrete worked-example partner scenario.
7. **Plugin signing / trust:** The file-format catalog has a `manifest_source` precedence ladder (`_system > core > operator > attested_external > unauthenticated_external`). Does the SBOM strategy registry need the same? Today there's no operator/external strategy AT ALL — the trust dimension is implicit. Wave-2 should decide whether to bake in trust precedence from instance #3 onwards.
