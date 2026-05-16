# Postmortem: Hardware-Firmware Adaptability Session — 2026-05-18

> Date: 2026-05-18 (continuation of 2026-05-17 BT YAML externalization session)
> Campaign: ad-hoc Citadel-driven session shipping 2026-05-17 recommendations #5 (YAML hot-reload) + #6 (Realtek BT) + mid-session pivot to TARGET 3 (recursive nested-archive gate + Tegra/L4T classifier patterns) after user-raised DS1 ingestion incident.
> Duration: ~7 hours (commit c7a6106 → 51db3c8)
> Outcome: completed; 6 commits across 3 H2-leverage targets + 1 mid-session adaptability pivot triggered by user direction "we won't be the only ones ingesting files" + 2 reviewer-fix commits applying findings from the 3-parallel multi-persona Citadel review (arch + forensic + adaptability).

## Summary

The session opened against two queued recommendations from yesterday's
postmortem: **TARGET 1 — YAML hot-reload across the 5 extension
surfaces** (~1-2 hours) and **TARGET 2 — Realtek BT family parser**
(~3 hours). Mid-session the user raised an adaptability concern
("we won't be the only ones ingesting files into the tool... don't
hard-code strict formats"), and a specific instance: project
`d360f8f5-6b60-4951-bc1f-01a6a190eecf` (DS1) had uploaded
`live_base-2.14.3-rc.5039.tar.gz` (2.64 GB), and the wairz pipeline
classified 6 top-level files (2 nested archives + 4 sidecars) as
"the rootfs" and stopped — 0 firmware blobs detected because both
inner Tegra TX2 + L4T BSP archives stayed packed.

This triggered a mid-session pivot to **TARGET 3** (split into TARGET
3a — recursive nested-archive gate, and TARGET 3b — NVIDIA Tegra/L4T
classifier patterns) so the DS1 case + its broader class of failures
(external uploaders nesting firmware in vendor wrappers) become the
session's first-class concerns.

Three parallel Citadel deep-research scouts ran during initial
implementation: Scout A (Tegra/L4T firmware structure), Scout B
(recursive-unpack heuristics + binwalk/unblob design), Scout C
(Realtek BT corpus + critical correction to the user's prompt — see
"What Broke" #1). All three returned comprehensive reports cited in
the commit messages.

Three parallel multi-persona reviewers ran post-implementation: Reviewer
A (architecture), Reviewer B (forensic-domain — NVD CPE verification),
Reviewer C (adaptability). Reviewer A surfaced 2 HIGH severity findings
(yaml_cache module location + device_metadata overwrite bug); Reviewer
C surfaced 2 HIGH severity findings (subdirectory probing gap +
vendor proactive seed). Reviewer B is still running at write time.

End-of-session corpus verification:
- **G32 + G30 + DPCS10×3**: 54 CVE-2021-30348 rows (matches 2026-05-17
  baseline; no regression from the multi-fixup chain). Zero
  wrong-attribution CVE rows (28139/34147/31609/31612).
- **DS1 (post-recursion gate)**: 124 firmware-like files visible
  (was 6); 117 classified as `vendor=nvidia` (55 DTBs + 28 bootloader
  + 13 MCU + 9 TEE + 7 other + 3 camera + 2 DSP). 7 unclassified
  (operator-customised filenames).
- **YAML hot-reload demonstrated live**: edited
  `bt_qca_codenames.yaml` in the running container, the next
  `get_qca_codename_map()` call returned the new entry within one
  invocation (5→6 codenames). Restored cleanly.
- **No Realtek BT firmware in current corpus** — Realtek parser
  ships forward-prepared for future uploads (documented absence per
  user prompt instruction).

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | c7a6106 | `feat(hw-fw): YAML mtime-checked hot-reload across all 5 surfaces` | New generic `MtimeCachedYamlLoader` + 5 surfaces wired (vendor_prefixes / firmware_patterns / bt_qca_codenames / bt_banner_cve_pins / known_firmware) + 17 tests |
| 2 | e2f8333 | `feat(unpack): adaptive nested-archive recursion gate for tarball shortcut` | `_is_archive_dense_layout` bytes-weighted + sidecar-aware + negative-rootfs-guarded gate + wired into firmware_service.py tarball shortcut + 13 tests |
| 3 | 3000a9e | `feat(hw-fw): NVIDIA Tegra/L4T classifier patterns + fixed Realtek BT basename match` | 24 new patterns covering Jetson Linux R32+ payload (BPMP/MB1/MB2/cboot/TOS-trusty/MCE/MTS/SPE/ADSP/camera-RTCPU/etc) + fixed latent broken `^rtl_bt\/...` pattern + 62 tests |
| 4 | 5f40eb2 | `feat(hw-fw): Realtek BT family parser + bt_realtek_project_ids.yaml` | 4th BT family parser + 17-chipset YAML (6th hot-reloadable surface) + Realtek dispatch in BtFirmwareBannerParser + 42 tests |
| 5 | 7730915 | `fix(hw-fw): multi-persona reviewer findings on adaptability session` | Reviewer A A1+B1+B4 + Reviewer C REC-1+CC-1 (yaml_cache moved to app/utils/; device_metadata merge-not-overwrite; min_archive_size 10MB→1MB; subdir probing; 24 vendor display defaults) |
| 6 | 51db3c8 | `fix(hw-fw): Reviewer B forensic findings — CVE-attribution schema gates` | F-FORENSIC-10 CRITICAL (bt_banner_cve_pins.yaml schema gate: family-only pins rejected) + F-FORENSIC-11 HIGH (curated_yaml tier skips low-confidence blobs) + 4 paired-canary tests per Rule #46 |

6 commits. 0 reverts. Each independently revertable per Rule #25.

## What Broke

### 1. Initial prompt incorrectly claimed Realtek project_id at offset 8 (CRITICAL — Scout C 2026-05-18 catch)

- **What happened:** The user prompt's TARGET 2 spec said "4-byte project ID at offset 8 (LE uint32)". Implementing this verbatim would have produced a parser that read `fw_version` (a uint32 field that legitimately sits at offset 8 per upstream btrtl.h) and treated it as project_id. Every Realtek blob would have hashed `0x06b30000`-like values into a chipset map producing nonsense classifications.
- **Caught by:** Citadel research Scout C cross-referencing the upstream Linux btrtl.c + btrtl.h source against the prompt's claim.
- **Impact prevented:** A whole-parser misclassification on EVERY Realtek BT blob the parser would ever see. Operator-facing UI + downstream CVE matchers would have shown "RTL chipset=X" for X derived from fw_version bits.
- **Fix:** Scout C's correction shipped in commit `5f40eb2` — the parser scans head for magic ("Realtech" v1 / "RTBTCore" v2), parses fw_version at offset 8 (NOT project_id), and reverse-scans the FILE TAIL for the `(opcode=0, length=1, data=PID)` TLV record that ACTUALLY carries project_id. The fix mirrors btrtl.c's own discovery method.
- **Lesson:** Pattern #3 from 2026-05-17 (independent reviewer-claim verification via web-fetch) generalises to "independent prompt-claim verification before implementation" — when a prompt makes an offset / format claim, fetching the authoritative source (upstream kernel for kernel-driver formats) catches errors BEFORE they ship. Cost ~5 min via Scout dispatch; value: an entire parser shape correction.

### 2. firmware_service.py:761 `device_metadata` write-then-overwrite (HIGH — Reviewer A 2026-05-18)

- **What happened:** `firmware.device_metadata = _stamp_firmware_device_metadata({"extraction_diagnostics": extraction_diagnostics})` replaces the FULL device_metadata dict rather than merging. Pre-existing bug; the new `extraction_diagnostics["nested_extract"]` sub-key (added in commit `e2f8333`) made it reachable on the upload happy path (was previously only triggered on extraction failures, a rarer path).
- **Caught by:** Reviewer A architecture review cross-referenced `firmware_paths.py:787-791` which correctly does merge-then-stamp.
- **Impact:** Concurrent upload-time writes (e.g. `detection_roots` written by upstream + `extraction_diagnostics` written by this path) could clobber each other; the `nested_extract` sub-key would silently lose `detection_roots` in the same window.
- **Fix:** Commit `7730915` mirrored the proven merge-then-stamp pattern: load existing via `_normalize_firmware_device_metadata`, dict-copy, set the new key, stamp.

### 3. `_is_archive_dense_layout` 10 MB threshold ruled out small-vendor IoT firmware (MEDIUM — Reviewer A 2026-05-18)

- **What happened:** Initial `min_archive_size_bytes=10 MB` was right-sized for the DS1-class incident (Tegra archives are 2.38 GB + 279 MB) but biased the gate against the broader IoT/embedded corpus the user signalled wairz must serve. ESP32 packages typically ship 4-8 MB; Nordic SoftDevice updates ~1.5 MB; a vendor wrapping a 9 MB firmware in a tarball would FAIL the gate.
- **Caught by:** Reviewer A noting "embedded medical/IoT firmware skews small."
- **Fix:** Threshold lowered to 1 MB in commit `7730915`. The 1 MB floor still suppresses stray-tarball-in-config-dir false-fires while opening for the broader corpus.

### 4. Subdirectory probing missing — vendor wrappers using `payloads/` / `images/` slip through (HIGH — Reviewer C 2026-05-18)

- **What happened:** `_is_archive_dense_layout` only inspected the top level. A vendor wrapping firmware as `outer.tar.gz` → `payloads/foo.tar.gz` + `payloads/bar.tar.gz` would: outer extracts → `find_filesystem_root` picks the dir (entry-count fallback) → top-level has 1 subdir (`payloads/`) + 0 files → gate sees 0 archives at top level → returns False → no recursion.
- **Caught by:** Reviewer C adaptability review.
- **Impact prevented:** A whole class of external-uploader layouts that would have replicated the DS1 failure for vendors wrapping inner archives in subdirs.
- **Fix:** Commit `7730915` added `_probe_subdirs_for_archive_density()` — when top-level has zero files AND ≤8 subdirs, probes each at depth-1 with the same density test. Bounded by subdir-count cap so adversarial inputs can't blow up the probe.

### 5. `_yaml_cache.py` lived in wrong subpackage (HIGH — Reviewer A 2026-05-18)

- **What happened:** The new generic `MtimeCachedYamlLoader[T]` was placed at `backend/app/services/hardware_firmware/_yaml_cache.py`. The class has zero hw-firmware semantics — already imported by `cve_matcher.py` via a cross-subpackage path. The user's "we won't be the only ones ingesting" framing predicted this class would be reused beyond hw-firmware.
- **Caught by:** Reviewer A architecture review.
- **Fix:** Commit `7730915` moved to `backend/app/utils/yaml_cache.py` (mirroring the `sandbox.py` / `truncation.py` / `pagination.py` siblings). 3 importers updated.

### 6. Vendor proactive seed stopped at 4 entries — operator uploads from Allwinner/Rockchip/Marvell/etc would title-case (HIGH — Reviewer C 2026-05-18)

- **What happened:** Initial `_VendorTable` defaults seeded display strings for 4 vendors (qualcomm/mediatek/nvidia/realtek). The `firmware_patterns.yaml` already names 20+ vendor prefixes; operator uploads from those vendors would surface as title-cased fallbacks (e.g. `allwinner` → display="Allwinner" rather than "Allwinner Technology").
- **Fix:** Commit `7730915` expanded to 28 entries covering Allwinner / Rockchip / Marvell / Espressif / Lattice / Xilinx / Renesas / STMicro / Nordic / Microchip / Infineon / TI / Amd / etc. Zero behaviour change (display strings only).

### 7. `bt_banner_cve_pins.yaml` accepted family-only pins — operators could fire RTL8762E SDK CVEs against ALL 17 Realtek chipsets (CRITICAL — Reviewer B 2026-05-18)

- **What happened:** `_parse_banner_cve_pin` validated "at least one match condition required" — but `family` ALONE counted as a match condition. A future operator writing `family: realtek_bt + cves: [CVE-2024-48290, ...]` (RTL8762E SDK CVEs per NVD) would fire those CVEs against ALL 17 chipsets in `bt_realtek_project_ids.yaml`. Disclosure-batch antipattern at the schema layer — wairz had hit this 3 times (BTFM 2026-05-15, CVE-2021-28139 on 2026-05-16, CVE-2021-34147/31609/31612 on 2026-05-17).
- **Caught by:** Reviewer B forensic-domain review (Citadel multi-persona dispatch), cross-referenced against NVD CPE for CVE-2024-48290 + CVE-2025-44526/31/59.
- **Fix:** Commit `51db3c8` — `_parse_banner_cve_pin` now REJECTS pins where `family:` is set AND no other narrowing condition (`codename_in / chipset_target_in / banner_match / build_date_before / build_id_lt / signed_eq`) is present. Loud rejection at YAML load time + keep-previous-state contract means a bad pin falls back to the prior valid YAML.

### 8. Curated-tier CVE matcher fired on LOW-confidence blobs — Realtek soft-fallback could trigger curated attribution from any "Realtek" ASCII string (HIGH — Reviewer B 2026-05-18)

- **What happened:** The Realtek BT parser's soft-fallback path emits `vendor=realtek, confidence=low` when it finds any `[Rr]ealte[ck]` ASCII pattern in a head window — necessary for vendor-modified BT blobs that don't carry canonical magic. But `_match_curated` in cve_matcher.py did NOT gate on `detection_confidence`, so a kernel module or Android image containing "Realtek Inc." in a string table would receive curated Realtek CVE attribution.
- **Caught by:** Reviewer B forensic-domain review.
- **Fix:** Commit `51db3c8` — `_match_curated` now skips blobs with `detection_confidence == "low"`, DEBUG-logged for audit. Pairs with #7 at two complementary layers: schema gate (author intent) + matcher gate (blob evidence).

### 9. Scout A's CVE-2019-5680 (Selfblow) attribution was incorrect — DS1 R32.3.1 is the FIRST FIXED version (CRITICAL — Reviewer B 2026-05-18 catch)

- **What happened:** Scout A's research report listed CVE-2019-5680 (Selfblow) as a "Tegra R32.x baseline CVE" and noted the DS1 firmware's 2019-12-09 build timestamp was "8 days before JetPack 4.3 release (2019-12-17)" — implying R32.3.1 was vulnerable. Scout A conflated R32.3.1 (the dot-release with Selfblow fix) with R32.3 (the JetPack 4.3 base).
- **Caught by:** Reviewer B forensic-domain review via direct NVD CPE fetch on CVE-2019-5680: CPE caps at R32.2, with `o:nvidia:jetson_tx1_firmware:*<R32.2` (TX1 only — DS1 is TX2; ALSO out-of-CPE).
- **Impact prevented:** If a future curated `vendor: nvidia` YAML entry shipped CVE-2019-5680 against L4T R32.3.1+ targets per Scout A's report, every R32.3.1+ Tegra firmware (the FIXED versions) would receive false-positive Selfblow attribution.
- **Lesson:** Scout reports + reviewer reports BOTH need per-CVE NVD-CPE verification. The discipline from 2026-05-15..17 (Reviewer B catches CVE attribution errors) extends to forward-research from Scouts. Reviewer B 2026-05-18 caught Scout A's error before any curated YAML entry shipped — the per-CVE NVD-fetch step is load-bearing across the full research-to-curation pipeline.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| User direction interjection mid-session | Pivoted scope to surface a structural adaptability gap (DS1) that the planned targets wouldn't have addressed | 1 | A full session's work shipping while the DS1-class failure mode persisted indefinitely |
| Parallel scout dispatch (3 in parallel) before implementation | Scout C caught the prompt's offset-8 project_id claim was incorrect per upstream btrtl.h; Scouts A + B provided authoritative spec input for Tegra + recursive-unpack design before code was written | 1 critical correction + 2 spec validations | A whole-parser misclassification on every future Realtek blob; less-rigorous implementation on TARGET 3 |
| Multi-persona reviewer dispatch (3 in parallel) | Reviewer A: 2 HIGH (yaml_cache location + device_metadata overwrite) + 6 MEDIUM + 4 LOW. Reviewer C: 2 HIGH (subdir probing + vendor seed) + 6 MEDIUM + 6 LOW. Reviewer B: 2 CRITICAL (family-only pin schema gate + Scout A CVE-2019-5680 misattribution) + 3 HIGH (low-confidence curated tier + TOS provenance bundling) + 6 MEDIUM + 5 LOW. | 6 HIGH/CRITICAL + 18 MEDIUM + 15 LOW | A pre-existing JSONB clobber bug + a class of subdir-wrapper failures + future-author module-location confusion + a recursive disclosure-batch antipattern at the schema layer + a Scout-derived CVE misattribution before it shipped |
| YAML hot-reload's "keep previous on malformed" contract | Live demonstration: malformed-YAML mutation triggered the WARN log + kept previous state; restored cleanly. Proves the safety contract works under real edits | 1 | Operators' YAML iteration would otherwise produce silent regress-to-defaults state |
| Rule #25 per-piece commits | 5 commits, each independently revertable. Reviewer fixes (`7730915`) are bisect-clean against the 4 features | 1 | Multi-issue commit-mash where reverting one finding rolls back unrelated improvements |
| End-to-end corpus verification | 54 BRAKTOOTH rows post-Rule-#8 rebuild matches the 2026-05-17 baseline; zero wrong-attribution CVE rows; DS1 went 6→124 firmware-like files post-recursion | 1 | Shipping with a regression on the 2026-05-17 fix chain undetected |
| Tests-as-canary discipline (Rule #46) | The hot-reload "concurrent accessors don't see torn state" test caught a non-atomic-writer issue early; the structural-validation-failure-keeps-previous test caught the empty-doc edge case | 2 | Two subtle correctness gaps in the loader's contract |
| Rule #20 docker cp + restart for fast iteration | ~6 cycles of code-edit → docker cp → live smoke test. Each saved ~3-5 min of full rebuild | 6 | ~20-30 min total session time |
| Rule #8 rebuild + Rule #11 import smoke post-rebuild | Confirmed backend + worker healthy with the new code; smoke tested all 6 hot-reload surfaces + Realtek chipset table + Tegra patterns | 1 | Stale-image debugging confusion |

## Scope Analysis

- **Planned (user prompt):** Ship TARGET 1 (YAML hot-reload, ~1-2 hrs) + TARGET 2 (Realtek BT parser, ~3 hrs). Multi-persona review. Per-piece Rule #25 commits.
- **Mid-session pivot (user direction):** Add TARGET 3 (recursive nested-archive gate + Tegra classifier patterns) to address the d360f8f5 DS1 incident + the broader external-uploader adaptability concern.
- **Built:** 5 commits across 13 files (~3,900 net-new lines): TARGET 1 (1543 LOC + 17 tests), TARGET 3a recursive gate (579 LOC + 13 tests), TARGET 3b Tegra patterns (496 LOC + 62 tests), TARGET 2 Realtek BT (1271 LOC + 42 tests + new YAML), reviewer-fix (115 LOC).
- **Drift:** NONE on user-stated asks. The mid-session pivot was explicitly user-directed. Multi-persona review executed (3 parallel reviewers via Citadel agent dispatch). Reviewer A + C findings of HIGH severity applied in commit 7730915; Reviewer B findings pending at write time. Rule #8 rebuild ran cleanly post-fixup. Final corpus verification confirmed zero regression + massive DS1 recovery (6→124 files visible).

## Patterns

1. **Mid-session user-direction pivots can be absorbed by the per-piece commit discipline without churning previous work.** Initial scope had 2 targets; user added TARGET 3 mid-session. Both committed sets shipped cleanly — Rule #25 per-piece commits let the new direction inherit the same pattern instead of forcing a scope merge. 4 feature + 1 fix is a clean shape.

2. **Pre-implementation scout dispatch + per-claim source verification.** Scout C corrected the prompt's offset-8 claim against btrtl.h. Yesterday's pattern #3 (independent reviewer-claim verification via web-fetch) extends here to "independent prompt-claim verification" — when a user prompt or design doc makes an offset / format claim, fetching the authoritative source catches errors at zero cost compared to post-hoc correction.

3. **Adaptability framing operationalised: bytes-weighted + sidecar-aware + negative-rootfs-guarded gate.** Scout B's research produced a concrete gate shape that's vendor-agnostic. Compared to the "hard-code vendor allowlists" antipattern, the gate fires on DS1's Tegra wrap, Samsung Odin's nested tar.md5, generic OTA bundles — without naming any vendor.

4. **Multi-persona review caught structural bugs that pre-dated the session.** Reviewer A's B1 finding (`firmware_service.py:761` device_metadata overwrite) was pre-existing, but the e2f8333 commit's new `nested_extract` sub-key made it reachable on the happy path. The fix shipped same-session.

5. **Confidence-ladder design for adaptability.** The Realtek parser ships a HIGH/MEDIUM/LOW confidence ladder rather than a binary accept/reject — operator-modified blobs surface as `vendor=realtek/confidence=medium-or-low` rather than disappearing into `unclassified`. Same shape works for the Tegra classifier (high-confidence canonical names + medium-confidence operator customisations like `ds1-boot.img`).

6. **YAML hot-reload's "keep previous on malformed" is operator-friendly under iteration.** Demonstrated live: when a typo was introduced mid-edit, the loader logged WARN + kept the previously-loaded state, restored cleanly when the typo was fixed. Eliminates the silent-regress-to-defaults failure mode that would have made YAML iteration painful.

7. **Sub-suffix bytes-weighting (vs file-count weighting) is the load-bearing decision in `_is_archive_dense_layout`.** DS1 was 2 archives + 4 sidecars by COUNT (33% archive) but ~100% archive by BYTES (sidecars were ~600 bytes). The bytes-weighted denominator + sidecar exclusion caught it. Count-weighted alternative would have failed silently.

8. **Module location signals scope.** Reviewer A's A1 (move `_yaml_cache.py` from hw-firmware/ to utils/) reframes the class from "hw-firmware-specific helper" to "generic infrastructure usable across the codebase". The user's "we won't be the only ones ingesting files" predicts this primitive will see many more consumers — placing it under `app/utils/` invites that adoption.

## Recommendations Carried Forward

1. **`list_extension_points` MCP tool** (Reviewer C CC-3 + HOT-1 + HOT-2 closed together) — ~90 LOC; returns per-YAML `{path, last_load_ts, entries, reload_count, last_warning}` + parser-format → handler map + `_BT_PARSER_FAMILIES`. Highest single-investment leverage per Reviewer C.
2. **Tegra content-evidence parser `parsers/tegra_blob.py`** (Reviewer A C1 + Reviewer C TEG-1) — mirrors `bt_firmware_banner.py` for BPMP / TOS / MB1 / cboot. Reads ELF magic + Tegra header bytes; emits `vendor=nvidia` from content even on operator-modified filenames. ~300 LOC.
3. **Tegra CVE pins in known_firmware.yaml** (Reviewer A C2) — pending Reviewer B per-NVD-CPE verification for CVE-2019-5680 / CVE-2021-1111 / CVE-2021-34372..34397 / CVE-2022-42269..42270. Antipattern-prevention discipline from 2026-05-15..17 sessions applies.
4. **Tier A archive-suffix additions** (Reviewer C REC-2) — `.7z` / `.tar.zst` / `.zst` / `.deb`. Requires Dockerfile apt deps + small `_extract_single_archive` cases. Closes a large class of vendor packaging shapes today's recursion gate misses. ~50 LOC + Dockerfile.
5. **`extraction_strategy` enum** (Reviewer C CC-2) — replace `extracted_via_shortcut: bool` with `Literal["shortcut_clean", "shortcut_recursed", "unblob"]` so downstream consumers can distinguish a trusted shortcut from a recursed-shortcut from a fallback.
6. **`conftest.py` `loader_with_tmp_yaml` fixture helper** (Reviewer C CC-4) — 8-line wrapper around the monkeypatch+cache_clear scaffolding that all future operator-extension tests will need. Forward-looking adaptability multiplier.
7. **`patterns_loader.py` Rule #28 watch** (Reviewer A A4) — file is at 1437 LOC, below the 1500 trigger. Next growth: extract Realtek block to `realtek_chipsets.py` per Rule #27 N+1 shape.
8. **Realtek `bt_banner_cve_pins.yaml` worked example** (Reviewer C RTL-3) — ship a commented-out example pin under `family: realtek_bt` with the Scout C antipattern preamble inline (no BLUFFS/BIAS/KNOB to chipsets; no RTL8762E SDK CVEs to other chipsets).
9. **Docs file `docs/features/extending-firmware-patterns.md` update** (Reviewer C HOT-3 + CC-5) — add Surface 6 (Realtek) + refresh the 4→6 hot-reloadable YAMLs table. Rule #21 companion-file-sync.
10. **`RealtekChipsetEntry.extra: dict` field** (Reviewer C RTL-2) — operator-supplied freeform metadata pass-through. Small change with adaptability multiplier.

## Remaining Work

- Recommendations 1-10 above: ~12-18 hours total.
- Backfill: NONE needed. Zero wrong-CVE rows pre-rebuild; the recursion gate is a forward-only addition that doesn't affect existing classifications.
- Reviewer B's findings (currently running) will be appended to this postmortem when complete.
- DS1 firmware row currently shows `blobs_detected: 0` because the unpack ran BEFORE the recursion gate shipped. A re-trigger would need to either (a) reset the firmware row state + invoke `/unpack` again, OR (b) wait for the operator to re-upload. Either path is documented for the operator; the new code shape is in place.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 6 (4 feat + 2 fix) |
| Files changed (cumulative) | 15 (3 new utility/YAML + 12 modified) |
| Lines added | ~4,070 net-new |
| Reverts | 0 |
| New tests | 138 (17 hot-reload + 13 nested-extract + 62 Tegra + 42 Realtek + 4 Reviewer-B schema gates) |
| Total hw-firmware test count | 348 passing (was 210 pre-session, +138 net) |
| New YAML schemas | 1 (`bt_realtek_project_ids.yaml`) |
| New classifier patterns | 24 NVIDIA Tegra/L4T + 2 Realtek BT corrected |
| New hot-reloadable surfaces | 1 (Realtek BT — 6th surface total) |
| Reviewer scouts (pre-implementation, parallel) | 3 (Tegra + recursive-unpack + Realtek) |
| Reviewer findings applied this session | 4 HIGH (Reviewer A A1 + B1 + B4 + Reviewer C REC-1 + CC-1) + B4 MEDIUM |
| Reviewer findings deferred to follow-up | ~16 (Reviewer A 6 MED + 4 LOW; Reviewer C 6 MED + 4 LOW; Reviewer B pending) |
| Tier 0 BRAKTOOTH rows (G32 / G30 / DPCS10×3) | 26 / 22 / 2-each = 54 (matches 2026-05-17 baseline) |
| Wrong-attribution CVE rows | 0 (post-rebuild confirmed) |
| DS1 firmware-like file count | 6 → 124 (+118) after recursion |
| DS1 NVIDIA classification count | 0 → 117 (+117) with Tegra patterns |
| Backend + worker rebuilds | 1 (post-fixup; verified via Rule #11 import smoke) |
| Rule #20 fast-iteration docker cp cycles | ~10 |
| Live YAML hot-reload demonstrations | 2 (CMC→ZZZ codename add + restore; malformed-edit → keeps-previous WARN) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md`
- Yesterday's postmortem: `.planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md`
- 2026-05-16 BT banner parser: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`
- 2026-05-15 BTFM correction: `.planning/postmortems/postmortem-btfm-correction-and-corpus-2026-05-15.md`

---HANDOFF---
- Postmortem: hw-firmware-adaptive-session-2026-05-18
- Document: .planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md
- Failures documented: 9 (1 CRITICAL prompt-incorrect Realtek project_id offset caught pre-implementation by Scout C + 1 CRITICAL family-only pin schema gap caught by Reviewer B + 1 CRITICAL Scout A CVE-2019-5680 misattribution caught by Reviewer B + 2 HIGH device_metadata overwrite + yaml_cache location + 2 HIGH subdir probing gap + vendor seed gap + 1 HIGH low-confidence curated tier + 1 MEDIUM 10 MB threshold)
- Safety catches: 9 (user direction mid-session interjection + pre-implementation scouts × 3 + multi-persona reviewers × 3 with NVD per-CVE verification × 8 + live YAML hot-reload contract + Rule #25 per-piece commits + end-to-end corpus verification + tests-as-canary × 4 (Rule #46 paired canaries for both new Reviewer B gates) + Rule #20 fast-iter cycles × 10 + Rule #8 rebuild + Rule #11 import smoke)
- Recommendations: 10 carried forward (list_extension_points MCP, Tegra content-evidence parser, Tegra CVE pins pending per-CVE NVD-CPE per Reviewer B recipe, Tier A archive suffixes, extraction_strategy enum, conftest fixture helper, Rule #28 watch, Realtek YAML worked example, docs refresh, RealtekChipsetEntry.extra)
- Critical Scout C catch: Realtek BT firmware project_id is NOT at offset 8 per upstream btrtl.h — offset 8 is fw_version (uint32 LE v1) or ASCII fw_version[8] (v2); project_id is encoded as trailing TLV records (opcode=0, length=1, data=PID) and must be reverse-scanned from file tail. Per-prompt-claim source verification caught the design error BEFORE the parser shipped.
- Critical Reviewer B catches: (a) bt_banner_cve_pins.yaml accepted family-only pins (RTL8762E SDK CVE disclosure-batch antipattern vector) — schema gate added (b) Scout A's CVE-2019-5680 Selfblow attribution to R32.3.1 was wrong (R32.3.1 is the FIX) — caught via direct NVD CPE fetch before any curated entry shipped (c) curated_yaml tier accepted low-confidence soft-fallback blob matches — confidence floor added
- Adaptability deltas shipped: YAML hot-reload (5 surfaces) + nested-archive recursion gate (bytes-weighted, sidecar-aware, negative-rootfs-guarded, subdir-probing) + NVIDIA Tegra/L4T classifier patterns (24 new) + Realtek BT family parser (4th BT family) + 28-vendor proactive display seed + cross-vendor architecture (yaml_cache moved to app/utils/ for codebase-wide reuse) + 2 schema gates against future disclosure-batch antipatterns (F-FORENSIC-10 + F-FORENSIC-11)
- DS1 d360f8f5 impact: 6 firmware-like files → 124 files visible (+118); 0 NVIDIA blobs classified → 117 classified (+117); 7 unclassified remain (operator-customised names)
---

Run `/learn hw-firmware-adaptive-session-2026-05-18` to extract patterns into the knowledge base.
