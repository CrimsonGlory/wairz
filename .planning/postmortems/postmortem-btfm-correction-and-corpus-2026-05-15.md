# Postmortem: BTFM misattribution correction + corpus impact 2026-05-15

> Date: 2026-05-15 (continuation of postmortem-ds1-moto-g32-hardware-firmware-adaptive-detect-2026-05-15)
> Trigger: user-supplied third-party content-evidence audit identified yesterday's BTFM→Broadcom attribution as a triple false-positive
> Duration: ~4 hours additional (commits 218013d → c25ceeb)
> Outcome: completed; all reviewer findings applied + foundational attribution error corrected

## Summary

After the first half of today's session (commits 94df63c, bacb660, 218013d) shipped path-context classification + CVE coverage expansion + super.img recovery for the Moto-G32 + Moto-G30, the user provided a content-evidence audit from a third-party team proving that yesterday's commit `f6bdc4e` had misattributed BTFM.bin to Broadcom — it's actually Qualcomm-Atheros Rome family. The wrong attribution propagated into today's path-context YAML AND through to the BleedingTooth CVE family which produced **3 false-positive CVE matches × 18 BTFM blobs = 54 false-positive sb_vuln rows** per firmware.

Second half of the session corrected the attribution and shipped the LEGITIMATE QCA-side CVE coverage that should replace it. Plus reviewer findings from a multi-persona Citadel review (arch + forensic + corpus + adaptability) were applied throughout.

## Final commit chain (this session)

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | 94df63c | `feat(classifier): YAML-driven path-context refinement + rescue` | 11 path_contexts entries; rescues 517 qualcomm/other → modem/audio/dsp/wifi |
| 2 | bacb660 | `feat(cve-matcher): soft chipset_regex + category_regex + Qualcomm coverage` | Soft chipset on NULL target; 12 new QC entries (Snapdragon modem 2024-2025, Hexagon Achilles+FastRPC, Adreno 2025 0-days, FastConnect, Spectra, vdec, SLPI, QSEE, advisories) |
| 3 | 9045a2f | `docs(postmortem): adaptive hardware-firmware detection 2026-05-15` | v1 of this session's postmortem |
| 4 | 218013d | `feat(unpack): super.img sparsechunk post-unblob partition recovery` | Carves embedded ext4/erofs from unblob's expanded sparsechunks; rescued 5 partitions × ~17.6 GB on G32 |
| 5 | 3d8d018 | `fix(classifier+cve): BTFM is QCA Rome (not Broadcom) + reviewer hardening` | Core BTFM correction + Reviewer A H1/H2/M1/M5 hardening + Reviewer B P0 (3 cross-vendor CVE-duplicate fixes) + P5 (SA prefix for automotive Snapdragon) |
| 6 | ed7642e | `feat(cve): legitimate QCA Rome BT + WCN WLAN firmware CVE coverage` | BRAKTOOTH cluster (CVE-2021-28139/34147/31609/31612) + WCN3950/3990 WLAN firmware (CVE-2023-28581) + spec-level BT advisories (KNOB/BLUFFS/BIAS/BLURtooth) + FragAttacks WLAN |
| 7 | c25ceeb | `fix(unpack): bump sparsechunk raw.image cap from 10 GB → 20 GB` | G30 ships 10.3 GB raw.image (vs G32's 7.58 GB) — initial cap rejected G30. Adaptability fix. |

7 commits total. 0 reverts. Each is independently revertable per Rule #25.

## Final corpus state (post all commits + rebuild)

| Firmware | Blobs | Curated CVEs | Tier-4 Kernel CPE | Total Distinct | Rows |
|---|---:|---:|---:|---:|---:|
| Moto-G32 (eed5db82) | **638** | **36** | 0 | **36** | 4,466 |
| Moto-G30 (f84544a9) | **588** | **53** | 0 | **53** | 3,903 |
| DPCS10 260403 (efea8619) | 258 | **492** | 785 | **1,246** | 177,493 |
| DPCS10 260413 (188c5b24) | 260 | **517** | 785 | **1,271** | 178,219 |
| DPCS10 260414 (0ed279d8) | 260 | **517** | 785 | **1,271** | 178,219 |

### Deltas vs. yesterday's postmortem state

| Firmware | Yesterday | Today (post all) | Δ blobs | Δ CVEs |
|---|---|---|---|---|
| G32 | 331 / 3 | 638 / 36 | +93% | +1100% |
| G30 | 286 / 0 | 588 / 53 | +106% | ∞ |
| DPCS10 260403 | 258 / 1193 | 258 / 1246 | 0 | +4.4% |
| DPCS10 260413 | 260 / 1220 | 260 / 1271 | 0 | +4.2% |
| DPCS10 260414 | 260 / 0 | 260 / 1271 | 0 | first-time coverage |

The DPCS10 deltas are smaller because:
- DPCS10s are MediaTek (no Qualcomm chips); the QC-side expansion doesn't apply.
- Soft chipset_regex DOES fire MediaTek entries that previously rejected on NULL chipset_target, surfacing ~50 new CVEs per DPCS10.
- 0ed279d8 was newly-detected (idle); first cve-match run.

## Key false-positives REMOVED

The BleedingTooth cluster (CVE-2020-12351/12352/24490) NO LONGER fires on QCA Rome / WCN BT firmware. Pre-correction, these 3 CVE IDs × 18 BTFM blobs per firmware = 54 false-positive sb_vuln rows on G32 + 54 on G30 + however many on any future QCA-shipping device. **Total false-positive sb_vuln rows eliminated: 108 measured + ∞ future.**

Additional cross-vendor CVE-attribution fixes (Reviewer B P0):
- CVE-2024-20040: removed from Qualcomm FastConnect entry (it's MediaTek WLAN per ASB Apr 2024).
- CVE-2024-20011/20009/20007: removed from Qualcomm vdec entry (MediaTek vdec cluster).
- CVE-2024-43047: removed from Qualcomm FastRPC entry (duplicates the Snapdragon modem cluster's authoritative listing).

## Key false-positives ADDED (legitimate coverage)

NEW Qualcomm Rome / WCN-family firmware CVE entries that now correctly fire on QCA blobs:
- **BRAKTOOTH cluster**: CVE-2021-28139 (RCE CVSS 8.8), CVE-2021-34147, CVE-2021-31609, CVE-2021-31612. ASSET Group / SUTD disclosure 2021.
- **CVE-2023-28581**: WCN3950/WCN3990 WLAN firmware memory corruption (CRITICAL CVSS 8.1). QSB Sept 2023.
- **Advisory clusters**: ADVISORY-QC-BT-FW, ADVISORY-QC-WLAN-FW.
- **Spec-level**: ADVISORY-BT-KNOB, BLUFFS, BIAS, BLURtooth (vendor-agnostic — limited to vendor=unknown bluetooth blobs for now; vendor_regex follow-up queued).
- **FragAttacks WLAN**: CVE-2020-24586/24587/24588 for WCN3xx0/6xx0 WLAN blobs pre-July-2021.

## Patterns and antipatterns (for `.planning/knowledge/`)

### Pattern: third-party content-evidence audit as a sanity check on filename-based heuristics
The user provided a comprehensive on-disk content audit (banner strings, header magic bytes, ext2 fs inspection) that found and corrected a single-character-of-evidence error in yesterday's commit. **Pattern**: when authoring filename-based vendor patterns, IMMEDIATELY check at least one file's content (e.g. `xxd` first 64 bytes + `strings | grep vendor_token`) to verify the attribution; don't trust filenames alone. The third-party team's `BTFM.CMC.x.y.z-QCACHROMZ-1` banner check would have caught yesterday's error pre-commit.

### Antipattern: hardcoded caps tuned to a single test device
The initial Fix C `_MAX_RAW_BYTES = 10 GB` cap fit Moto-G32 but excluded Moto-G30 (10.3 GB raw.images). Caught only by re-running on a different device. **Antipattern**: pick caps based on a known-corpus distribution + 2-3× safety margin, not on the single device you tested against. **Fix**: bump to 20 GB; add TODO marker for env-var-driven configurability.

### Pattern: multi-persona Citadel review catches different failure modes
Four parallel reviewers (arch + forensic + corpus + adaptability) each found a distinct class of issue:
- Arch (A): ReDoS regex, advisory_id collision, suffix-hint sandbox-escape (not applicable in my design).
- Forensic (B): cross-vendor CVE mis-attributions (CVE-2024-20040, vdec cluster, CVE-2024-43047), missing automotive (SA) chipset coverage.
- Corpus (C): re-detection candidates corpus-wide.
- Adaptability (D): Apple/OpenWrt/medical/Yocto blind spots, hot-reload gap, docs gap.
None of the four would have surfaced ALL the others' findings independently — the parallel-persona review is load-bearing.

### Antipattern: foundational attribution errors propagate through multi-layer review
The BTFM→Broadcom misattribution from yesterday's commit f6bdc4e was NOT caught by any of the 4 reviewers because they all DEFERRED to the prior commit's attribution. The user's "blow it up at each step" directive is the corrective: don't take prior attributions as load-bearing without independent content-evidence verification. This is a different class of bug than the cross-vendor CVE-duplicate Reviewer B caught — that was a forensic-domain-spotting issue; the BTFM error was a foundational-evidence-not-checked issue.

## Recommendations carried forward

1. **Banner-string parser for BT firmware** — add a parser format that reads the first 4 KB of any .tlv/.ver/.hcd file, extracts the version banner string (`BTFM.<codename>.x.y.z-<build>-<rom>-N`), and populates `blob.version` + `blob.chipset_target` + `metadata.bt_fw_banner` from it. Would drive Tier 0 parser-detected version-pin matching (highest-confidence CVE attribution shape) and prevent future filename-only mis-attributions. Single new file in `backend/app/services/hardware_firmware/parsers/`.

2. **vendor_regex field on `_match_curated`** — would let the spec-level BT advisories (KNOB/BLUFFS/BIAS/BLURtooth) apply to any bluetooth blob regardless of vendor. Currently they only match vendor=unknown.

3. **Bluedroid/Fluoride path_context + CVE family** — add `/system/lib*/libbluetooth*.so` path_context (vendor=aosp, category=bluetooth) + CVE entries for CVE-2023-45866 (HID injection), CVE-2023-40129 (Fluoride GATT RCE), CVE-2023-35673. These are the legitimate Android host-stack CVEs that complement (not duplicate) the firmware-side coverage.

4. **wpa_supplicant path_context + CVE family** — add `/vendor/bin/hw/wpa_supplicant` and `/usr/sbin/wpa_supplicant` path_contexts + CVE-2023-52160 (PEAP bypass) + Dragonblood entries. Per the user's analysis, this is the highest-leverage WiFi attack surface on these devices.

5. **YAML hot-reload** — Reviewer D #2. Replace module-level `_PATTERNS` compile with mtime-checked lazy load. Eliminates restart-to-pick-up-YAML-changes friction.

6. **Recovery handler registry** — Scout C's adaptability proposal. Generalise Fix C's super.img recovery into a YAML-driven dispatch table for boot.img / vendor_boot.img / dtbo.img / future container formats.

7. **Documentation** — Reviewer D #3. `docs/extending-firmware-patterns.md` + example YAML stanzas for Apple, OpenWrt, Yocto, medical devices. Reduce support burden + signal adaptability commitment.

8. **DPCS10 super.img recovery audit** — DPCS10 firmware (MediaTek) may or may not ship in sparsechunks. Verify whether Fix C surfaces additional content there (likely no — MediaTek uses scatter-zip not sparsechunks).

## Numbers

| Metric | Value |
|---|---|
| Commits in this session | 7 (5 fixes + 1 docs + 1 cap bump) |
| Reverts | 0 |
| Files changed | 9 (5 source + 2 yaml + 1 test + 1 doc) |
| Lines added | ~1,800 |
| New YAML entries | 11 path_contexts + 14 CVE families |
| False-positive CVE rows removed | 108 (54 G32 + 54 G30 BleedingTooth) |
| Legitimate CVE entries added | 30+ across BRAKTOOTH, WCN WLAN, Spectra, modem 2024-25, Adreno, FastConnect, vdec, SLPI, QSEE, FragAttacks, BT spec advisories |
| Multi-persona reviewers | 4 (arch + forensic + corpus + adaptability) + 3 scouts (path-context + CVE coverage + super.img) |
| Parallel research agents total | 7 across 2 dispatch rounds |
| Reviewer findings applied | H1+H2+M1+M5 (4 from Arch) + P0a+P0b+P0c+P0d (4 from Forensic) + P5 (1 from Forensic) + BTFM correction (from user) |
| Reviewer findings deferred | M3 (YAML schema validation), M4 (Fix C timeout audit), L1-L5 (low-priority), all Reviewer D long-term adaptability items |
| Corpus firmwares verified end-to-end | 5 (G32, G30, DPCS10 × 3) |
| Rule #8 rebuilds | 1 (mid-session) |
| Rule #20 fast-iteration docker cp cycles | ~10 |

---HANDOFF---
- Postmortem: btfm-correction-and-corpus-2026-05-15
- Document: .planning/postmortems/postmortem-btfm-correction-and-corpus-2026-05-15.md
- Commits: 94df63c, bacb660, 9045a2f, 218013d, 3d8d018, ed7642e, c25ceeb
- False-positives eliminated: 108 measured (BleedingTooth × QCA BT blobs)
- Legitimate CVE entries added: 30+
- Reviewer findings applied: 9 (4 Arch HIGH/MED + 4 Forensic P0 + 1 P5)
- Recommendations carried forward: 8 (BT banner parser, vendor_regex, Bluedroid path_context, wpa_supplicant path_context, hot-reload, recovery registry, docs, DPCS10 super.img audit)
---
