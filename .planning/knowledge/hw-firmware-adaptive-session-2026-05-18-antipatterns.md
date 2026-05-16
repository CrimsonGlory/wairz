# Anti-patterns: HW-Firmware Adaptability Session 2026-05-18

> Extracted: 2026-05-18
> Campaign: ad-hoc Citadel-driven session
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md`

## Failed Patterns

### 1. Implementing a parser from a prompt's offset/format claim without source verification
- **What was done:** The user prompt's TARGET 2 spec said "4-byte project ID at offset 8 (LE uint32)" for the Realtek BT parser. Implementing verbatim would have read `fw_version` (the legitimate uint32 at offset 8 per btrtl.h) and hashed its bits as project_id into a chipset map producing nonsense classifications.
- **Failure mode:** Every Realtek BT blob the parser would ever see would misclassify; downstream UI + CVE matcher would surface incorrect chipset attribution.
- **Evidence:** Scout C's deep research report cited the canonical upstream Linux source (`drivers/bluetooth/btrtl.h`) showing offset 8 is `__le32 fw_version` (v1) or `__u8 fw_version[8]` (v2); project_id is in trailing TLV records reverse-scanned from file tail (opcode=0, length=1, data=PID).
- **How to avoid:** Per-prompt-claim source verification at IMPLEMENTATION time, not at review time. When a prompt or design doc makes an offset / magic / format claim, fetch the authoritative source FIRST (upstream kernel for kernel-driver formats; vendor SDK for vendor-specific formats; RFC for protocol formats). Cost ~5 min via parallel scout dispatch; value: design correction at zero post-hoc rework. Generalises Pattern #3 from 2026-05-17 (reviewer-claim verification via web-fetch) to the prompt/scout/spec stage.

### 2. JSONB write-then-overwrite — `firmware.device_metadata = _stamp(new_dict)` clobbers prior keys
- **What was done:** `firmware_service.py:761` did `firmware.device_metadata = _stamp_firmware_device_metadata({"extraction_diagnostics": extraction_diagnostics})` — replacing the FULL dict with a 1-key dict. Pre-existing bug; the `nested_extract` sub-key (added in commit `e2f8333`) made it reachable on the upload happy path.
- **Failure mode:** Concurrent upload-time writes (`detection_roots` written upstream + `extraction_diagnostics` written by this path) clobber each other. The `nested_extract` sub-key would silently lose any prior `detection_roots` writes.
- **Evidence:** Reviewer A B1-HIGH finding cited `firmware_paths.py:787-791` as the correct merge-then-stamp pattern (load via `_normalize_*`, dict-copy, set key, stamp).
- **How to avoid:** When writing to ANY JSONB column, mirror the merge-then-stamp pattern: `existing = _normalize_X(getattr(obj, "field", None)); merged = dict(existing); merged["new_key"] = ...; obj.field = _stamp_X(merged)`. Never assign a fresh dict directly. Per CLAUDE.md Rule #35c, this is the contract. Mechanical detection: `grep -rn "device_metadata = " backend/app/` should return zero hits that AREN'T preceded by a `_normalize_*` call.

### 3. Filename-only attribution for production-signed bootloaders that have content fingerprints
- **What was done:** TARGET 3b shipped 24 NVIDIA Tegra/L4T classifier patterns as FILENAME-ONLY regex matches. No content-evidence parser (analogous to bt_firmware_banner.py for BT firmware) was authored — `bpmp.bin` is matched by filename only, not by `\x7fELF` magic + Tegra-specific header bytes; `tos-trusty.img` by filename, not by NVIDIA wrapper signature; `tegra*-dtb` by filename, not by FDT magic.
- **Failure mode:** A vendor-modified Tegra blob with an operator-customised filename (or operator-renamed during ingestion) classifies as `category=other`. The user's "we won't be the only ones ingesting" framing predicts external uploaders WILL produce such cases.
- **Evidence:** Reviewer A C1-MEDIUM + Reviewer C TEG-1 findings. The wairz precedent (bt_firmware_banner.py) exists specifically because filename-only heuristics produced the BTFM→Broadcom misattribution incident on 2026-05-15.
- **How to avoid:** When shipping classifier patterns for a new vendor family, queue a follow-up content-evidence parser commit. For Tegra: `parsers/tegra_blob.py` reading ELF magic for bpmp/spe/adsp; FDT magic for *.dtb; NVIDIA wrapper header for tos*.img / mb1*.bin; Android boot.img magic for ds1-boot.img. Defer the parser to its own commit but DON'T defer it indefinitely — the antipattern from BTFM exists specifically because filename-only attribution shipped without follow-through.

### 4. Threshold-tuning without measuring across the broader corpus scale
- **What was done:** Initial `_is_archive_dense_layout` shipped with `min_archive_size_bytes = 10 * 1024 * 1024` (10 MB). Right-sized for the DS1-class incident (Tegra TX2 archive 2.38 GB + L4T 279 MB) but biased against IoT/embedded firmware (ESP32 packages 4-8 MB; Nordic SoftDevice updates ~1.5 MB; a vendor wrapping a 9 MB firmware in a tarball would FAIL the gate).
- **Failure mode:** A whole class of legitimate vendor-wrapper layouts that ship small firmware in tarballs would have escaped the recursion gate — same failure shape as the original DS1 incident but for smaller-scale corpus.
- **Evidence:** Reviewer A B4-MEDIUM finding. The user's "we won't be the only ones ingesting" framing predicts the corpus will skew across many vendor sizes.
- **How to avoid:** When tuning a threshold based on a single-case-class incident, measure against the BROADER corpus before locking the default. For the recursion gate: a 1 MB default still suppresses stray-tarball false-fires (the failure mode the threshold protects against) while opening the gate for IoT/embedded firmware. The right discipline is "measure both failure modes; pick the threshold that catches both."

### 5. Top-level-only archive density scan misses vendor `payloads/`-style subdir wrappers
- **What was done:** Initial `_is_archive_dense_layout` only inspected the top level. A vendor wrapping firmware as `outer.tar.gz` → `payloads/foo.tar.gz` + `payloads/bar.tar.gz` would: outer extracts → top-level has 1 subdir + 0 files → gate sees 0 archives at top level → returns False → no recursion.
- **Failure mode:** External uploaders wrapping inner archives in subdirs (`payloads/`, `firmware/`, `images/`, `bootloader/`) would replicate the DS1-class failure for their layouts.
- **Evidence:** Reviewer C REC-1-HIGH finding.
- **How to avoid:** When a gate inspects a candidate root for "is this archive-dense?", probe ONE LEVEL DEEP when the top-level has zero files AND ≤N subdirs. The `_probe_subdirs_for_archive_density` helper bounded to N=8 subdirs gives adaptive subdir-wrapper detection without arbitrary recursion cost. The discipline: "if the top-level looks sparse, look one level down".

### 6. Vendor proactive seed limited to 4 entries — operator uploads from 20+ vendors title-case
- **What was done:** Initial `_VendorTable` in-tree defaults seeded display strings for 4 vendors (qualcomm/mediatek/nvidia/realtek). `firmware_patterns.yaml` already names 20+ vendor prefixes (allwinner, rockchip, marvell, espressif, lattice, xilinx, renesas, stmicro, nordic, microchip, infineon, ti, broadcom, intel, etc.).
- **Failure mode:** Operator uploads from those vendors surface as title-cased fallbacks (e.g. `vendor=allwinner` → display="Allwinner" rather than "Allwinner Technology"). UI looks sloppy; SBOM CycloneDX VEX export inherits the bad display.
- **Evidence:** Reviewer C CC-1-HIGH finding. The user's "we won't be the only ones ingesting" framing predicts external uploads from all major chip vendors.
- **How to avoid:** Proactive seeding for the union of vendors named in `firmware_patterns.yaml`'s `vendor:` field + the obvious major chip vendors. Zero behaviour change (display strings only). 12 minutes of typing prevents 20+ future operator-visible "vendor=foo → display='Foo'" sloppy outputs.

### 7. CVE pin schema accepts family-only entries — disclosure-batch antipattern at the schema layer
- **What was done:** `_parse_banner_cve_pin` validated "at least one match condition required" — but `family` ALONE counted as a match condition. A future operator writing `family: realtek_bt + cves: [CVE-2024-48290, ...]` (RTL8762E SDK CVEs per NVD CPE) would fire those CVEs against ALL 17 chipsets in `bt_realtek_project_ids.yaml`.
- **Failure mode:** The disclosure-batch antipattern wairz had hit 3 sessions in a row (BTFM 2026-05-15, CVE-2021-28139 on 2026-05-16, CVE-2021-34147/31609/31612 on 2026-05-17) would replicate at the bt_banner_cve_pins.yaml layer for any operator-authored family-only pin. NVD CPE for the RTL8762E CVEs lists ONLY RTL8762E BLE SDK — applying to RTL8761B / 8852A / etc would be wrong attribution.
- **Evidence:** Reviewer B F-FORENSIC-10 CRITICAL finding via NVD CPE verification on CVE-2024-48290.
- **How to avoid:** Schema-time validation: when `family:` is set in a pin, REQUIRE at least one of `codename_in / chipset_target_in / banner_match / build_date_before / build_id_lt / signed_eq` ALSO present. Loud rejection at YAML load time + keep-previous-state contract means a bad pin falls back to the prior valid YAML. The narrowing requirement IS the antipattern-prevention.

### 8. Curated CVE matcher tier fired on LOW-confidence soft-evidence vendor matches
- **What was done:** The Realtek BT parser's soft-fallback path emits `vendor=realtek, confidence=low` when it finds any `[Rr]ealte[ck]` ASCII pattern in a head window (necessary for vendor-modified BT blobs that don't carry canonical magic). But `_match_curated` in cve_matcher.py did NOT gate on `detection_confidence`.
- **Failure mode:** A kernel module or Android image containing "Realtek Inc." in a string table would receive curated Realtek CVE attribution. Future `vendor: realtek` curated entries would inherit attribution on every blob that softly mentions Realtek.
- **Evidence:** Reviewer B F-FORENSIC-11 HIGH finding. NVD CPE verification on CVE-2024-48290 (RTL8762E SDK only) shows the surface where soft-evidence + curated tier would produce real false positives.
- **How to avoid:** Confidence floor in the curated matcher: skip blobs with `detection_confidence == "low"`. DEBUG-log for audit. Complements the F-FORENSIC-10 schema gate: F-FORENSIC-11 gates BLOB EVIDENCE quality, F-FORENSIC-10 gates PIN AUTHOR-INTENT quality.

### 9. Trusting Scout reports without per-CVE NVD CPE verification
- **What was done:** Scout A's research report on Tegra/L4T R32.3.1 listed CVE-2019-5680 (Selfblow) as a "Tegra R32.x baseline CVE" + noted DS1's 2019-12-09 build timestamp was "8 days before JetPack 4.3 release (2019-12-17)" — implying R32.3.1 was vulnerable. Scout A conflated R32.3.1 (the dot-release with Selfblow fix) with R32.3 (the JetPack 4.3 base release that pre-dated the fix).
- **Failure mode:** If a future curated `vendor: nvidia` YAML entry shipped CVE-2019-5680 per Scout A's report, every R32.3.1+ Tegra firmware (the FIXED versions) would receive false-positive Selfblow attribution. Plus the CPE list for CVE-2019-5680 is TX1-only — DS1 is TX2, so the CVE doesn't apply regardless.
- **Evidence:** Reviewer B F-FORENSIC-03 CRITICAL finding via direct NVD CPE fetch on CVE-2019-5680 (caps at R32.2, TX1 only).
- **How to avoid:** Per-CVE NVD CPE verification is a RECURSIVE discipline that applies to BOTH reviewer reports AND scout reports. The 2026-05-15..17 sessions established the discipline for reviewer findings; 2026-05-18 extends it to scout findings. Cost: ~30 sec per CVE via WebFetch; carries zero risk; eliminates the "trust-the-research-blindly" failure mode at every layer of the research-to-curation pipeline.

### 10. Generic utility class shipped under a domain subpackage
- **What was done:** `MtimeCachedYamlLoader[T]` shipped at `backend/app/services/hardware_firmware/_yaml_cache.py`. The class is generic over `T` + already imported by `cve_matcher.py` via a sibling-cross-subpackage path; future YAML surfaces beyond hw-firmware will inherit the loader pattern.
- **Failure mode:** Module location signals scope to future authors. A loader living under `hardware_firmware/` artificially constrains its visible-adoption surface — a developer needing hot-reload for a totally different YAML (e.g. credential-pattern overrides) wouldn't naturally find it. Long-term: 1-2 sessions out, parallel re-implementations would emerge.
- **Evidence:** Reviewer A A1-HIGH finding.
- **How to avoid:** When authoring a new generic primitive inside a domain subpackage, ask: "is this class parameterized by T, or does its docstring name future-uses beyond the immediate domain?". If yes, place it in `app/utils/` (mirroring `sandbox.py` / `truncation.py` / `pagination.py`) so codebase-wide adoption is invited rather than gated.

## Cross-Cutting Anti-pattern Themes

1. **"Specs are candidates, not truth."** The user prompt's project_id-at-offset-8 claim + Scout A's CVE-2019-5680 R32.3.1 claim were both incorrect. The discipline countermeasure is mechanical: every byte-offset claim → fetch the upstream source; every CVE-attribution claim → fetch the NVD CPE list. Cost trivial; protection unbounded.

2. **"Pre-existing bugs become reachable when new code routes through them."** `firmware_service.py:761`'s device_metadata overwrite pre-dated this session but was rarely-fired (only on extraction failures). The e2f8333 commit's `nested_extract` sub-key made it reachable on the upload happy path. Future commits adding new fields to existing structures should mechanically check the write-then-stamp pattern at the WRITE site before adding the new field.

3. **"Threshold defaults need cross-corpus measurement, not single-incident calibration."** The 10 MB min_archive_size was right for DS1 but wrong for IoT. When a threshold is added, name the failure mode it protects against AND the boundary case it might exclude — and verify both empirically before committing.

4. **"Adaptability surfaces need subdir + sidecar + negative-rootfs handling, not just file-count."** Top-level-only scans are tempting but miss vendor `payloads/` wrappers. Count-weighted alternatives miss bytes-asymmetric layouts. Negative-rootfs guards short-circuit cleanly for canonical cases. All three combined ARE the adaptability discipline — none alone is sufficient.

5. **"Generic primitives + domain placement = adoption tax."** Cross-subpackage imports work but artificially constrain visibility. Place generic things in generic locations.

6. **"Schema layers are the right place to enforce no-disclosure-batch."** A runtime matcher that rejects bad pins is fine, but a schema layer that REJECTS bad pins at YAML load time is louder + earlier in the operator's edit-test cycle. Defense at two layers (schema + matcher) is durable.

7. **"Soft-evidence vendor matches need confidence floors at every CVE attribution tier."** A parser that emits LOW confidence on partial evidence is a feature (preserves operator value); a CVE matcher that fires curated CVEs on LOW-confidence matches is a bug (pollutes attribution). The two design choices need to interact via explicit gates.

8. **"Multi-persona review is durable beyond debate."** Three consecutive sessions (2026-05-15, -16, -17, -18) have shipped CVE-attribution failure modes that the multi-persona pattern caught. Cost is ~5-10 min per session via parallel Citadel agent dispatch. Value: catches structural bug classes that single-axis review misses.
