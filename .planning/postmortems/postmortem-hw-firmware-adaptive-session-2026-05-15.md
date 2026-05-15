# Postmortem: Hardware-Firmware Adaptive Detection Session 2026-05-15

> Date: 2026-05-15
> Campaign: ad-hoc systematic-debugging session (no campaign file)
> Duration: ~8 hours (commit 94df63c → 04ebfab)
> Outcome: completed (1 prong queued — see "Remaining Work")

## Summary

User invoked `/citadel:systematic-debugging` on two Motorola firmware projects (DS1 Moto-G32, Moto-G30) reporting that hardware-firmware detection "missed the Qualcomm radio" and CVE matching produced "only 3 CVEs on Bluetooth". Session shipped 8 commits restoring correct attribution and lifting coverage from 3→36 distinct CVEs (G32) and 0→53 (G30), while correcting a foundational misattribution introduced yesterday (BTFM.bin classified as Broadcom — actually Qualcomm-Atheros). Two detailed phase-level postmortems exist; this document is the unified session view with cross-cutting findings.

## What Broke

### 1. Categorization sink — 517/611 (89%) Qualcomm blobs in `category=other`
- **What happened:** `classifier.py:_category_from_qcom_name` was a hardcoded prefix if-chain. Files in `radio.img_extract/` with carrier-config names (`att_usa_volte.mbn`, etc.), WLAN split chunks (`bdwlan.b0X`), and RFNV calibration data fell through to `return "other"`.
- **Caught by:** User noticed UI underrepresented Qualcomm/Modem (showed 24 of 312 qcom blobs).
- **Cost:** ~75 min trace + design + implementation.
- **Fix:** Commit `94df63c` — YAML-driven `path_contexts:` section + `_apply_path_context` refinement step. 11 path rules covering radio.img / RFNV / EFS / FSG / BTFM / dspso.bin / bdwlan / Adreno splits / carrier-config / bootloader-ELF.
- **Infrastructure created:** Path-context schema in firmware_patterns.yaml; `PathContextMatch` dataclass + `match_path_context()` loader; 13 new tests pinning the refinement + rescue semantics.

### 2. CVE matcher chipset_regex strict-mode produced 0 Qualcomm matches
- **What happened:** Strict-mode gate `if chipset_re and not blob_chipset: continue` rejected every Qualcomm blob — `chipset_target` is populated on 1/611 qualcomm blobs.
- **Caught by:** DB query `SELECT chipset_target, COUNT(*) FROM hardware_firmware_blobs GROUP BY 1` during Phase 2 hypothesis verification.
- **Cost:** ~95 min audit + matcher refactor + YAML expansion.
- **Fix:** Commit `bacb660` — soft chipset_regex (NULL target → match with confidence downgrade) + optional `category_regex` + 12 new Qualcomm advisory entries.
- **Infrastructure created:** 7 new cve_matcher tests; advisory_id YAML key + defensive `[:20]` truncation; YAML schema validation in `_load_known_firmware` (Reviewer A H1).

### 3. Worker container had stale `detector.py` missing yesterday's NUL sanitizers
- **What happened:** Re-detection canary failed with `CharacterNotInRepertoireError: 0x00` on Qualcomm ELF segment metadata (`qc_image_version_string` with embedded NULs).
- **Caught by:** SQLAlchemy bulk INSERT raised the IntegrityError immediately.
- **Cost:** ~10 min trace.
- **Fix:** `docker cp detector.py` (Rule #20 fast iteration) + Rule #8 rebuild at session end.
- **Infrastructure created:** None — yesterday's `_sanitize_text`/`_sanitize_jsonb` was the right code; the issue was image staleness.

### 4. Super.img content (5+ GB per chunk) unwalked despite passing extraction
- **What happened:** Unblob recognized Android super.img sparsechunks and expanded each independently into 7.58-10.3 GB `raw.image` files (mostly zero-padded). The original chunks were consumed; existing `_concatenate_sparsechunks` doesn't apply. Result: 99% of Android system/vendor/product content invisible to detection.
- **Caught by:** Scout C's research agent during the deep-research phase identified the gap.
- **Cost:** ~90 min design + implementation + bug-fix iteration.
- **Fix:** Commit `218013d` — `_recover_sparsechunk_extracts` mmap-scans each raw.image for EROFS/ext4 magic, carves partitions, debugfs-extracts each into a walkable rootfs. Wired into `unpack.py` post-unblob path.
- **Infrastructure created:** 282 lines in `unpack_android.py` + 30 lines in `unpack.py`. Uses existing `_scan_super_partitions_layout_sync` + `_carve_partition_to_tmp_sync` + `_try_extract_partition` helpers.

### 5. Foundational BTFM→Broadcom misattribution (CRITICAL)
- **What happened:** Yesterday's commit `f6bdc4e` ("add Broadcom Bluetooth patterns BTFM.bin") classified BTFM.bin contents as `vendor=broadcom`. Content evidence (banner strings `BTFM.CMC.x.y.z-QCACHROMZ-1` + `Patch Release PF=WCN3950ROM=` + zero broadcom/brcm/bluez/wiced strings) proves it's Qualcomm-Atheros Rome family. The misattribution propagated into my path_context AND through to the BleedingTooth CVE family producing 54 false-positive sb_vuln rows per firmware.
- **Caught by:** User-supplied third-party content-evidence audit. None of the 4 multi-persona Citadel reviewers caught it — they all deferred to the prior commit's attribution.
- **Cost:** ~75 min trace + correction + new legitimate CVE coverage authoring.
- **Fix:** Commit `3d8d018` (BTFM patterns → qualcomm; BleedingTooth narrowed to kernel_module advisory) + commit `ed7642e` (legitimate BRAKTOOTH cluster + WCN3950 WLAN firmware CVE-2023-28581 + spec-level BT advisories KNOB/BLUFFS/BIAS/BLURtooth + FragAttacks).
- **Infrastructure created:** Verbose YAML header documenting the content-evidence chain so future authors don't repeat the mistake; advisory_id schema validation; BRAKTOOTH/WCN-family CVE families.

### 6. Sparsechunk recovery cap tuned to G32 (10 GB) rejected G30 (10.3 GB)
- **What happened:** Initial Fix C `_MAX_RAW_BYTES = 10 GB` cap fit Moto-G32's 7.58 GB raw.images. G30 ships 10.3 GB raw.images (larger super.img) and was rejected with "size outside bounds".
- **Caught by:** Live verification on a second device exposed the limit.
- **Cost:** ~5 min.
- **Fix:** Commit `c25ceeb` — cap bumped to 20 GB. TODO marker added for env-var configurability (`WAIRZ_RECOVERY_MAX_GB`).
- **Infrastructure created:** None — single-value tweak.

### 7. Reviewer-identified cross-vendor CVE duplicates (Reviewer B P0)
- **What happened:** Three CVEs I added in commit bacb660 cross-attributed wrong vendors: CVE-2024-20040 listed under Qualcomm FastConnect (actually MediaTek WLAN); CVE-2024-20011/20009/20007 listed under Qualcomm vdec (MediaTek vdec cluster); CVE-2024-43047 duplicated between Snapdragon modem cluster and FastRPC entries.
- **Caught by:** Citadel forensic-domain reviewer cross-referencing CVE list against ASB attribution.
- **Cost:** ~5 min.
- **Fix:** Commit `3d8d018` removed CVE-2024-20040 from FastConnect, reshaped Qualcomm vdec to advisory-only, reshaped FastRPC to advisory-only (CVE retained in canonical modem cluster).
- **Infrastructure created:** None — YAML correction.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Yesterday's postmortem corpus | Both projects' identity + prior sweep history were one Read away | 1 | Hours of re-tracing the same ground |
| DB partition-origin × category SQL | Surfaced the 517-blob mismatch in one query | 2 | Hours of grep-tracing classifier.py |
| chipset_target population query | Revealed 1/611 chipset_target populated (the fix B foundation) | 1 | Would have shipped chipset_regex Fix B that still produced 0 matches |
| Pre-existing CVE matcher tests | 2 tests asserted OLD strict-chipset semantics; both surfaced as expected failures on the new soft mode | 2 | Silent behavior drift across versions |
| Bulk INSERT NUL rejection | Caught stale worker image before any blob row landed corrupt | 1 | Detected staleness vs. silent partial-failure |
| Live canary against G32 + G30 | Caught the 10 GB sparsechunk cap mismatch (G30 raw.image is 10.3 GB) | 1 | Would have shipped Fix C usable only on G32 |
| 4 parallel multi-persona reviewers | Reviewer A (arch — ReDoS, advisory_id collision); Reviewer B (forensic — cross-vendor CVE duplicates, automotive SA gap); Reviewer C (corpus — re-detect candidates); Reviewer D (adaptability — 9 long-term issues queued) | 4 | Single-thread review would have shipped commits 4-7 with H1+H2+M1+M5+P0×3+P5 latent |
| User content-evidence audit | Caught the foundational BTFM→Broadcom misattribution none of the 4 reviewers spotted | 1 | 108 measured false-positive sb_vuln rows × ∞ future QCA-shipping devices |

## Scope Analysis

- **Planned (user prompt):** "deep research thinking and troubleshooting to enhance this feature... don't hard code strict formats... be more adaptable/versatile/flexible/resilient... only pops for 3 CVEs on Bluetooth... missed the Qualcomm radio on the G32". Plus follow-up directive "using deep research and deep review / thinking across all relevant expert personas using citadel on this. full plan, full execute, don't wait for me you got this" + "blow it up at each step and across steps refine and converge".
- **Built:** 8 commits across 11 files (~2,012 net-new lines): path-context classifier + CVE-matcher soft chipset + super.img sparsechunk recovery + BTFM correction + legitimate QCA Rome/WCN coverage + reviewer hardening + cap bump + 2 phase-level postmortems.
- **Drift:** **NONE on user-stated asks.** Both explicit complaints (Qualcomm radio + 3-CVE Bluetooth) resolved. Both implicit directives (multi-persona review, adaptability) executed. ONE prong queued as follow-up by design (BT banner-string parser — see Recommendations).

## Patterns

1. **Multi-persona Citadel review pays for itself but doesn't catch foundational-attribution errors.** Four reviewers caught HIGH/MEDIUM-priority technical issues + a third-party-team content audit caught the foundational error. The two review types are complementary, not substitutes.

2. **DB-grounded hypothesis verification beats grep-grounded.** Three SQL queries in Phase 2 (vendor×category breakdown, partition-origin × category, chipset_target population stats) produced surgical root-cause statements in ~10 min. Same conclusions via code-tracing would have taken hours and missed the 1/611 chipset_target finding entirely.

3. **Filename-only attribution is unreliable for vendor classification.** Yesterday's BTFM→Broadcom error came from filename heuristic alone. Content-evidence verification (banner strings + magic bytes + string-search for the supposed vendor token) is the durable counterweight. Future BT-firmware classifiers should bake content sniffing into the YAML pattern shape OR ship a banner-parsing parser (recommendation #1).

4. **YAML-driven schemas outperform hardcoded if-chains for user adaptability.** Replacing `_category_from_qcom_name`'s 17-line prefix chain with the path_contexts YAML section gives future operators a single file to extend — no Python change, no rebuild for runtime YAML loading (though `_PATH_CONTEXTS` is module-level cached; hot-reload is recommendation #5).

5. **Soft + Strict matcher modes give "absent evidence" different semantics from "negative evidence".** Pre-fix, chipset_regex with NULL target was rejection. Post-fix, NULL is "match with confidence downgrade" and rejection reserved for "populated AND mismatched". Directly transferable to any matcher combining positive (filename) + corroborating (chipset/version) signals.

6. **Per-piece commits + Rule #25 discipline made the rebuild + re-verify loop crisp.** 8 commits, each independently revertable. The BTFM correction could revert as its own atomic operation without losing the path-context or super.img work. Bisect-clean.

7. **Caps tuned to a single test device fail on the second device.** G32-sized 10 GB cap rejected G30's 10.3 GB raw.images. Pattern: when picking caps, look at corpus distribution + 2-3× safety margin, not the device in front of you.

## Recommendations

1. **Add a BT firmware banner-string parser** (highest-leverage follow-up). Reads first 4 KB of `.tlv`/`.ver`/`.hcd` files, extracts `BTFM.<codename>.x.y.z-<build>-<rom>-N` patterns, populates `blob.version` + `blob.chipset_target` + `metadata.bt_fw_banner`. Drives Tier 0 parser-detected version-pin matching (highest-confidence CVE attribution) and prevents future filename-only mis-attributions.

2. **vendor_regex field on `_match_curated`** so spec-level BT advisories (KNOB/BLUFFS/BIAS/BLURtooth) can apply to ANY bluetooth blob regardless of vendor token. Currently they only fire on `vendor=unknown`.

3. **Bluedroid/Fluoride path_context + CVE family** for `/system/lib*/libbluetooth*.so` etc. — CVE-2023-45866 HID injection, CVE-2023-40129 + 35673 Fluoride GATT RCEs. Legitimate Android host-stack CVEs that complement firmware-side coverage. Per the user-provided BT-vuln-analysis.

4. **wpa_supplicant path_context + CVE family** for `/vendor/bin/hw/wpa_supplicant` — CVE-2023-52160 PEAP bypass + Dragonblood cluster. Per the user-provided WiFi-vuln-analysis.

5. **YAML hot-reload** — replace module-level `_PATTERNS` compile-at-import with mtime-checked lazy load. Reviewer D #2. Eliminates restart-to-pick-up-YAML-changes friction.

6. **Recovery handler registry** — Scout C's adaptability proposal. Generalize Fix C's super.img recovery into a YAML-driven dispatch table for boot.img / vendor_boot.img / dtbo.img / future container formats (Yocto swupdate, etc.).

7. **Extensibility documentation** — Reviewer D #3. `docs/extending-firmware-patterns.md` + example YAML stanzas for Apple, OpenWrt, Yocto, medical devices.

8. **Carrier-config + super.img recovery audit on DPCS10 trio** — verify whether Fix C surfaces additional content on MediaTek firmware (likely no; MediaTek uses scatter-zip not Android sparsechunk format).

## Remaining Work

- BT banner parser (rec #1): estimated 4-6 hours.
- vendor_regex matcher field (rec #2): ~1 hour.
- Bluedroid + wpa_supplicant CVE families (rec #3, #4): ~3 hours each.
- YAML hot-reload (rec #5): ~2 hours.
- Recovery handler registry (rec #6): ~3 hours.
- Docs (rec #7): ~3 hours.
- Total: ~17-20 hours queued.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 8 (6 code + 2 postmortem) |
| Files changed | 11 |
| Lines added | 2,012 net-new (excluding generated) |
| Lines removed | 66 |
| Reverts | 0 |
| New tests | 20 (13 classifier + 7 matcher) |
| Updated tests | 2 (reflecting new soft-chipset semantics) |
| New YAML entries | 11 path_contexts + 14 CVE families |
| False-positive sb_vuln rows eliminated | 108 measured (BleedingTooth × QCA BT blobs) |
| Legitimate CVE entries added | 30+ (BRAKTOOTH, WCN WLAN, Spectra, modem 2024-25, Adreno, FastConnect, vdec, SLPI, QSEE, FragAttacks, BT spec advisories) |
| Parallel research scouts (round 1) | 3 (path-context design + CVE coverage audit + super.img recovery) |
| Parallel multi-persona reviewers (round 2) | 4 (arch + forensic + corpus + adaptability) |
| Additional research scout (BTFM correction) | 1 (QCA WCN BT CVE research) |
| Total parallel agents | 8 across 3 dispatch rounds |
| G32 blob delta | 331 → 638 (+93%) |
| G32 CVE delta | 3 → 36 (-3 false BleedingTooth + 36 legitimate) |
| G30 blob delta | 286 → 588 (+106%) |
| G30 CVE delta | 0 → 53 |
| DPCS10 trio CVE delta | +4% to +∞ (one was first-time matched) |
| Rule #8 rebuilds | 2 (mid-session + end-session) |
| Rule #20 fast-iteration docker cp cycles | ~10 |

## Documents

- Phase 1 detailed postmortem: `.planning/postmortems/postmortem-ds1-moto-g32-hardware-firmware-adaptive-detect-2026-05-15.md` (commits 94df63c → 218013d — first half)
- Phase 2 detailed postmortem: `.planning/postmortems/postmortem-btfm-correction-and-corpus-2026-05-15.md` (commits 218013d → 04ebfab — second half, BTFM correction)
- Yesterday's postmortem: `.planning/postmortems/postmortem-ds1-moto-g32-zero-blobs-2026-05-14.md` (the 0→331 recovery this session built on top of)

---HANDOFF---
- Postmortem: hw-firmware-adaptive-session-2026-05-15
- Document: .planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-15.md
- Failures documented: 7 (5 fixed + 2 procedural — image staleness + cap-tuning)
- Safety catches: 8 (postmortem corpus + DB queries × 2 + pre-existing tests + INSERT NUL + live canary + multi-persona review + user content audit)
- Recommendations: 8 (BT banner parser, vendor_regex, Bluedroid path_context, wpa_supplicant path_context, hot-reload, recovery registry, docs, DPCS10 super.img audit)
---

Run `/learn hw-firmware-adaptive-session-2026-05-15` to extract patterns into the knowledge base.
