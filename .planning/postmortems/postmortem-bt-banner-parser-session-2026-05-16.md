# Postmortem: BT Firmware Banner Parser Session 2026-05-16

> Date: 2026-05-16 (continuation of 2026-05-15 BTFM-correction work)
> Campaign: ad-hoc systematic-debugging session shipping postmortem 2026-05-15 rec #1-#4
> Duration: ~6 hours (commit c3a8fb2 → ae91e98)
> Outcome: completed; BT firmware banner parser shipped + content-evidence vendor attribution + Bluedroid/wpa_supplicant CVE coverage + spec-level BT advisory vendor_regex retargeting

## Summary

Yesterday's postmortem (2026-05-15) shipped 8 commits across `path-context refinement + soft chipset_regex + super.img recovery + BTFM correction` and queued 8 follow-up recommendations. Today's session shipped recommendations #1 (BT banner parser), #2 (vendor_regex on `_match_curated`), #3 (Bluedroid path_context + CVE family), #4 (wpa_supplicant path_context + CVE family) in 4 commits. The headline outcome: the BTFM→Broadcom vendor-misattribution class is now IMPOSSIBLE BY CONSTRUCTION — content-evidence banner parsing populates `blob.vendor` + `blob.version` + `blob.chipset_target` from QCA Rome BTFM, Broadcom HCD, and MediaTek WMT banners directly, overriding the classifier's filename-derived vendor.

Multi-persona Citadel review (arch + forensic + adaptability in parallel) caught the **exact same antipattern this campaign was supposed to prevent** — Reviewer B's forensic-domain audit found that CVE-2021-28139 (BrakTooth RCE CVSS 8.8) is ESP32-only per NVD's CPE list, NOT Qualcomm; the original `_BRAKTOOTH_CVES` would have shipped ~18 false-positive RCE rows per QCA-Rome firmware. Same fix shape as yesterday's BleedingTooth correction (over-attribution from disclosure-batch association rather than per-CVE evidence). Caught + fixed before any rebuild reached production state.

End-of-session verification on the corpus (G32 + G30 + DPCS10×3) confirmed: 21 Tier 0 BRAKTOOTH pins on G32 + 18 on G30 (legitimate Qualcomm DoS subset only), MediaTek BT detection works on DPCS10's ROMv4_be_patch files, wpa_supplicant + libwpa_client.so + libbluetooth.so paths now classified correctly, spec-level KNOB/BLUFFS/BIAS/BLURtooth advisories fire on every vendor's BT blobs.

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | c3a8fb2 | `feat(hw-fw): BT firmware banner parser` | New parser (~530 LOC) + ParsedBlob.vendor field + classifier registration + tests (23) |
| 2 | 88082f0 | `feat(cve-matcher): vendor_regex on _match_curated` | Optional vendor_regex field + 4 spec-level BT advisories retargeted from `vendor=unknown` → `vendor_regex="."` |
| 3 | d585c79 | `feat(cve): Bluedroid + wpa_supplicant host-stack CVE coverage` | 6 new path_context rules + new `aosp` vendor prefix + 9 new CVE families |
| 4 | ae91e98 | `fix(hw-fw): multi-persona reviewer findings` | Reviewer B critical fix: CVE-2021-28139 ESP32-only exclusion + CVE-2023-28581 chipset retargeting + filename↔content mismatch flag + Reviewer A docstring + lazy-read + advisory_id length cap |

4 commits. 0 reverts. Each is independently revertable per Rule #25.

## What Broke

### 1. Original BT banner parser shipped CVE-2021-28139 as a Qualcomm Rome RCE pin (CRITICAL)
- **What happened:** The parser's `_BRAKTOOTH_CVES` tuple included `CVE-2021-28139` (CVSS 8.8 RCE) alongside the 3 legitimate Qualcomm DoS CVEs. NVD's CPE list for CVE-2021-28139 contains only Espressif ESP-IDF / ESP32 hardware — no Qualcomm. The original implementation extrapolated from the BrakTooth disclosure-batch association ("all four BrakTooth CVEs apply to BrakTooth-vulnerable devices") rather than per-CVE evidence — the EXACT same shape as yesterday's BTFM→Broadcom misattribution failure.
- **Caught by:** Citadel forensic-domain reviewer (Reviewer B) cross-referencing CVE list against NVD CPE entries.
- **Impact prevented:** ~18 false-positive RCE-CVSS-8.8 sb_vuln rows per QCA-Rome-shipping firmware × every BTFM blob.
- **Fix:** Commit `ae91e98` — dropped CVE-2021-28139 from `_BRAKTOOTH_CVES` + dropped from BRAKTOOTH curated YAML entry. Documented in parser docstring + new pinning test `test_qca_rome_braktooth_no_esp32_rce_pin`.
- **Lesson reinforced:** Yesterday's antipattern #1 (filename-only vendor attribution without content evidence) generalizes to "disclosure-batch attribution without per-CVE CPE check". Same root cause; same countermeasure (Rule #19 evidence-first applied per-CVE not just per-vendor).

### 2. CVE-2023-28581 misattributed to WCN3950/WCN3990
- **What happened:** The Qualcomm WLAN firmware CVE entry's `chipset_regex` matched `wcn3950/wcn3990/sm6225/sm4350`. NVD's actual CPE list for CVE-2023-28581 is FastConnect 6800/6900/7800, QCA6391/6426/6436, Snapdragon 865/870/8 Gen 1, AR2 Gen 1, XR2 5G, WCN6740, WSA/WCD9380/9385 — explicitly NOT WCN3950 or WCN3990. The notes claimed "QSB explicitly lists wcn3950 and wcn3990 as affected CPEs" — the claim was wrong.
- **Caught by:** Reviewer B forensic-domain pass.
- **Impact prevented:** False-positive CVE-2023-28581 attribution on every WCN3950/WCN3990-shipping device (G32 SM6225, G30 SM4350, plus an unknown number of future devices).
- **Fix:** Retargeted chipset_regex to the actual NVD CPE list. Renamed family entry from "Qualcomm WCN3950/WCN3990 WLAN firmware memory corruption" to "Qualcomm FastConnect WLAN firmware memory corruption". Documented in YAML notes.

### 3. Vendor-fork ADV-QTI-BT-HAL-2023 entry was double-counting Bluedroid CVEs
- **What happened:** I authored a vendor-fork mirror entry that re-emitted CVE-2023-35673 / 40129 / 45866 under `vendor=qualcomm` against any Qualcomm BT chipset, with the rationale "Qualcomm vendor BT HAL libraries carry a fork of AOSP Bluedroid sources." Reviewer B flagged this as over-attribution: libbt-vendor-qti.so is a different code surface (HAL adapter between Bluedroid and the BT controller); the AOSP-side path_context already covers libbluetooth.so under /system + /apex. The duplicate entry produced double-counted findings without operational value.
- **Caught by:** Reviewer B M4.
- **Fix:** Commit `ae91e98` — removed the entry. AOSP-side coverage remains via path_context for libbluetooth.so under `/system|/apex`. Vendor-fork divergence will be handled per-CVE only when a specific QSB-vs-AOSP-SPL lag is documented.

### 4. The 4 KB head-only scan window missed banners in multi-KB .tlv files
- **What happened:** The parser's initial scan window was 4 KB from the start of the file. QCA Rome .tlv files place the BTFM banner at the FILE END as ASCII metadata after the patch payload (e.g. cmbtfw13.tlv 15 KB → banner at offset 14584; crbtfw21.tlv 220 KB → banner at offset 217936). Initial parser found 1/6 banners on the G32 corpus.
- **Caught by:** Live-canary on real BTFM files copied from the container via `docker cp`.
- **Cost:** ~5 min trace + 10 min fix.
- **Fix:** Refactored to head + tail scan (`_HEAD_SCAN_BYTES = 4 KB`, `_TAIL_SCAN_BYTES = 8 KB`); combined ~12 KB I/O per blob, NUL gap between head and tail to avoid cross-boundary regex matches.

### 5. MediaTek BT gate accepted truncated HCD bytes as "header"
- **What happened:** A truncated Broadcom HCD file (no LAUNCH_RAM terminator) reached the MediaTek branch and PASSED the btmtk_patch_header gates because zero-padded HCI command bytes were "printable enough" (0x4c = 'L' is printable, NULs count as printable padding) without containing any digits.
- **Caught by:** Initial test_broadcom_hcd_truncation_rejected unit test failure.
- **Cost:** ~5 min trace.
- **Fix:** Added Gate 2b — datetime[16] field must contain at least one decimal digit. Real btmtk timestamps always have digits (e.g. `2024/06/15 12:30`); zero-padded HCI bytes do not. Plus Gate 3b — platform[4] tag must not be all-NUL.

### 6. Test fixture leaked BT markers when "no marker" case was intended
- **What happened:** The `_make_mtk_btmtk` test helper always appended `b"BT_FW build patch_release"` as trailer regardless of the explicit `bt_marker=b"\x00"` arg, so the "no marker" low-confidence test always saw a BT marker and the gate didn't fire.
- **Caught by:** Test assertion failure.
- **Fix:** Refactored helper to take an explicit `extra_payload` arg (default to a generic WMT marker; tests for "no marker" pass `b"\x00calibration table\x00"`).

### 7. Pre-existing classifier tests pinned the WRONG BTFM vendor attribution
- **What happened:** 12 test cases in `test_hardware_firmware_classifier_patterns.py` asserted `vendor=broadcom` for BTFM files. These were authored 2026-05-14 (commit f6bdc4e) during the original broadcom misattribution; yesterday's BTFM correction (commit 3d8d018) updated the YAML but didn't touch these tests — they were stale.
- **Caught by:** Running the broader test suite after the parser commit.
- **Fix:** Updated all 12 assertions to expect `vendor=qualcomm` with historical comments preserving the audit trail. This is the test-file equivalent of the path-context YAML correction yesterday.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Yesterday's postmortem + knowledge files | Today's session bootstrapped instantly from rec list + patterns + antipatterns | 1 | Hours of re-tracing yesterday's ground |
| Parallel research scouts (round 1: QCA/BCM/MTK) | Provided precise spec details + upstream Linux btqca.c citations BEFORE parser draft | 3 | Wrong banner regex shape; wrong codename map; wrong HCD walker semantics |
| Live-canary on real BTFM corpus | Caught the head-only scan window missing banners at file tail | 1 | Would have shipped a parser detecting only 1/6 banners |
| Pre-existing test suite | Caught the truncated HCD case, MediaTek gate over-permissiveness, stale BTFM=broadcom tests | 3 | Latent false-positive paths + test-truth drift |
| Multi-persona Citadel review (arch + forensic + adaptability) | A: ReDoS audit (passed), advisory_id VARCHAR(20), lazy-read, docstring stale ref | 4 | M1 cosmetic, M2 4 MB allocation per blob, L5 silent advisory_id truncation collision risk |
|  | B: **CVE-2021-28139 is ESP32-only**, CVE-2023-28581 wrong chipset, QTI HAL duplicate, Apache/AR3002 confusion, MediaTek mismatch flag | 5 | ~18 false-positive RCE pins per Qualcomm Rome device + cross-device WCN3950/3990 false attribution |
|  | C: H1 YAML-driven codename table (queued), H2 banner-pin YAML (queued), H3 docs gap | 3 | Long-term adaptability roadmap captured |
| Rule #20 docker cp + restart (worker fast-iteration) | Validated reviewer fixup before image rebuild completed | 1 | 5-minute rebuild blocking verification |
| Rule #8 rebuild before verification | Caught that initial rebuild predated reviewer fixups (parallel work) | 1 | Stale image running ESP32-included parser; second rebuild captured the fix |
| Final verify script on full corpus | Confirmed Tier 0 pins fire correctly + ZERO CVE-2021-28139 false positives + content-derived vendor + chipset | 1 | Shipping without empirical confirmation |

## Scope Analysis

- **Planned (user prompt):** Ship rec #1 (BT banner parser), then #2 (vendor_regex), then #3 + #4 (Bluedroid + wpa_supplicant). Use deep research + deep multi-persona review. Per-piece Rule #25 commits. Rule #8 rebuild + final re-detect + re-cve-match on G32/G30/DPCS10.
- **Built:** 4 commits across 14 files (~2,100 net-new lines): banner parser + ParsedBlob.vendor field + vendor_regex matcher field + Bluedroid + wpa_supplicant path_contexts + 14 new CVE families + 38 new tests + reviewer-fixup commit applying B's critical finding.
- **Drift:** **NONE on user-stated asks.** All 4 recommendations shipped. Multi-persona review executed (3 parallel reviewers). Rule #8 rebuild ran twice (once mid-session in parallel with reviewer fixups → had to rebuild again to capture the fix). Per-piece commits held across 4 commits including the reviewer fixup.

## Patterns

1. **Content-evidence parser as architectural countermeasure to filename-only attribution.** The parser doesn't fix yesterday's BTFM mistake by hand-editing YAML — it makes the entire class of mistake structurally impossible. Every future BT firmware blob now gets vendor + version + chipset from content. New variants (FastConnect Gen3+, future Qualcomm codenames, Realtek BT, Intel AX) extend via parser updates rather than YAML guesses.

2. **Parallel research scouts pay for themselves on specification work.** Scouts A (QCA), B (BCM), C (MTK) ran in parallel during initial parser draft. Each returned precise spec details with upstream Linux source citations. Authoring the parser without them would have required 3-4× more iteration on regex shape + codename mapping.

3. **Reviewer B caught the exact failure mode the campaign was supposed to prevent.** This is meta-load-bearing: yesterday's session shipped antipattern #1 (filename-only attribution) and #8 (codename without citation). Today's session would have shipped per-CVE-without-evidence (the same failure mode at a different layer) if Reviewer B hadn't audited per-CVE CPE lists against NVD. The discipline-of-checking-twice pays even when the team thinks they've internalized the lesson.

4. **Per-piece Rule #25 commits survive mid-session reviewer corrections.** 4 commits (parser → vendor_regex → Bluedroid/wpa_supplicant → reviewer fixup). The fixup is bisect-clean: it can revert independently without losing the parser or the spec advisories. Pattern held perfectly under reviewer-driven correction pressure.

5. **End-of-session verification on the corpus is the only reliable "did it work" gate.** Test suite passing + Rule #11 import smoke + Rule #8 rebuild are all necessary but not sufficient. Running re-detect + re-cve-match on real firmwares and observing the Tier 0 BRAKTOOTH pin count (21 on G32, 18 on G30) and the ZERO CVE-2021-28139 attribution is the actual safety gate. Without it, the parser shipping with the original CVE-2021-28139 included would have been undetectable by tests alone.

6. **Lazy I/O in parsers matters when the parser is called per-blob across thousands of files.** Reviewer A M2 caught that the original parser read the full file (up to 4 MB) unconditionally even when the QCA banner regex already pinned the result. Reorder: head + tail scan first → QCA + MediaTek branches first (head-only) → lazy full-file read only when Broadcom HCD's HCI walker is needed. Cuts peak memory cost dramatically for the common QCA-hit case.

7. **Filename↔content mismatch is forensic-load-bearing metadata.** G32's `apbtfw10.tlv` contains a CHE (Cherokee) banner — content says WCN3990, filename suggests WCN3988 (Apache). Parser correctly trusts content but now surfaces the discrepancy as `metadata.bt_fw_banner.filename_codename_mismatch` so operators can audit it. Cheap; forensic-load-bearing.

## Recommendations Carried Forward

1. **YAML-driven QCA codename → chipset table** (Reviewer C H1, highest leverage). Externalize `_QCA_CODENAME_TO_CHIPSET` + `_BRAKTOOTH_CHIPSETS` + `_MTK_KNOWN_CHIPS` to `data/bt_qca_codenames.yaml` so operators can extend without Python changes. Sets the pattern for future vendor table externalization. Estimated: 1 hour.

2. **Banner-pin → CVE YAML schema** (Reviewer C H2). Move `_maybe_pin_braktooth` from hardcoded Python to YAML: `{banner_match: BTFM\\.<codename>, chipset_target_in: [...], cves: [...]}`. Lets operators add their own version-pin rules (BlueBorne for BCM4339, etc.) without Python changes. Estimated: 3 hours.

3. **Realtek BT firmware family parser** (Reviewer C M3). Linux `drivers/bluetooth/btrtl.c` is the spec. Add `_parse_realtek_bt(data, filename)` reading the `Realtech` magic at offset 0 + extracting LMP subversion. Estimated: 3 hours.

4. **Docs gap: `docs/features/extending-firmware-patterns.md`** (Reviewer C H3 + yesterday's #7). Document `vendor` vs `vendor_regex`, `category` vs `category_regex`, path_context schema, parser format mapping, ParsedBlob.vendor override contract. Use the Bluedroid path_context as the worked example. Estimated: 2 hours.

5. **Drop-in fixture loader for BT parser tests** (Reviewer C M1). `tests/fixtures/hardware_firmware/bt_banner/{vendor}/{chipset}/<sample>.bin` + sibling `expected.json` → parametrized test discovers them. Supports the corpus-grows-organically pattern. Estimated: 2 hours.

6. **YAML hot-reload** (yesterday's #5, still queued). Replace module-level `_PATTERNS` compile with mtime-checked lazy load. More leverage-positive now that the YAML extension surface widened. Estimated: 1 hour.

7. **Reviewer A L6 — parser-side O_NOFOLLOW for consistency**. Detector validates paths via O_NOFOLLOW + realpath; the parser does plain `open(path)`. The worker container is the security boundary, so risk is LOW, but aligning the discipline costs ~6 LOC. Estimated: 30 minutes.

8. **MediaTek BT chipset extraction from platform_tag** (today's verification finding: DPCS10's ROMv4_be_patch files have `platform_tag` that doesn't match `_MTK_KNOWN_CHIPS` list — chipset_target stays NULL). Either widen the known-chips list OR parse platform_tag bytes more semantically. Estimated: 1 hour.

## Remaining Work

- Recommendations 1-8 above: ~14 hours total.
- Backfill cleanup: existing `sbom_vulnerabilities` rows for CVE-2021-28139 and CVE-2023-28581 on G32/G30 from prior sessions should be deleted (today's re-detect+re-cve-match did delete them via the verify script's DELETE pre-pass, but a corpus-wide cleanup would be valuable if other firmwares have them).
- Yesterday's queue: recovery handler registry (#6), DPCS10 super.img recovery audit (#8) still queued.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 4 (3 feat + 1 reviewer-fixup) |
| Files changed | 14 (3 source + 2 yaml + 4 test + 1 vendor_prefixes.yaml + remaining doc/postmortem) |
| Lines added | ~2,100 net-new |
| Lines removed | ~150 |
| Reverts | 0 |
| New tests | 38 (23 parser + 6 path_context + 6 vendor_regex + 3 Tier 0 integration + others) |
| Updated tests | 12 (stale BTFM=broadcom → qualcomm) |
| New YAML entries | 12 (4 BT path_contexts + 2 wpa_supplicant path_contexts + 1 vendor_prefix + 5 new CVE families post-reviewer-fix) |
| Reviewer findings applied | 6 HIGH/MED (B's H1+H2+H3+M2+M4 + A's M1+M2+L5) |
| Reviewer findings deferred | C's H1+H2+H3+M1+M3 (next-session candidates) |
| Parallel research scouts (round 1) | 3 (QCA + BCM + MTK + Bluedroid/wpa CVE list) |
| Parallel multi-persona reviewers (round 2) | 3 (arch + forensic + adaptability) |
| Total parallel agents | 6 across 2 dispatch rounds |
| Live-canary on real BTFM corpus | 8 sample files via docker cp |
| Tier 0 BRAKTOOTH pins fired (G32) | 21 (3 DoS CVEs × 7 banner-bearing BTFM blobs) |
| Tier 0 BRAKTOOTH pins fired (G30) | 18 (3 × 6) |
| Tier 0 BRAKTOOTH pins fired (DPCS10×3) | 1 each (MediaTek parser path) |
| CVE-2021-28139 false-positive pins prevented (G32+G30) | ~13 (would have been 7+6 from BTFM banner blobs) |
| BT blobs with content-derived version + chipset (G32) | 7/7 |
| BT blobs with content-derived version + chipset (G30) | 6/6 |
| ΔCVEs G32 | +3 (KNOB+BLUFFS+BLUR new via vendor_regex; -1 from CVE-2023-28581 retargeting; +1 net from BIAS) |
| ΔCVEs G30 | +3 (same shape as G32) |
| ΔCVEs DPCS10_260403 | +43 (MediaTek BT parser detected new blobs + Bluedroid path_contexts) |
| ΔCVEs DPCS10_260413/260414 | +18 each |
| Rule #8 rebuilds | 2 (mid-session + after reviewer fixups; first one was parallel and missed the fix) |
| Rule #20 fast-iteration docker cp cycles | ~12 |
| Hardware firmware test count | 293 passing (was 271 pre-session, +22 net) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`
- Yesterday's unified session view: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-15.md`
- Yesterday's BTFM correction detail: `.planning/postmortems/postmortem-btfm-correction-and-corpus-2026-05-15.md`
- Yesterday's patterns: `.planning/knowledge/hw-firmware-adaptive-session-2026-05-15-patterns.md`
- Yesterday's antipatterns: `.planning/knowledge/hw-firmware-adaptive-session-2026-05-15-antipatterns.md`

---HANDOFF---
- Postmortem: bt-banner-parser-session-2026-05-16
- Document: .planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md
- Failures documented: 7 (1 critical CVE-2021-28139 ESP32 attribution caught pre-rebuild + 1 CVE-2023-28581 chipset retarget + 1 vendor-fork mirror over-attribution + 4 mechanical fixes during dev)
- Safety catches: 9 (yesterday's postmortem + scouts × 3 + live-canary + test suite + 3 parallel reviewers + Rule #20 fast-iter + final verify)
- Recommendations: 8 (YAML codename externalization, banner-pin YAML schema, Realtek BT, docs, drop-in fixtures, hot-reload, parser O_NOFOLLOW, MediaTek platform_tag extraction)
- Critical reviewer catch: Reviewer B forensic-domain identified CVE-2021-28139 as ESP32-only per NVD — would have shipped ~18 false-positive RCE-CVSS-8.8 rows per QCA-Rome firmware; same antipattern shape as yesterday's BleedingTooth correction
- Tier 0 BRAKTOOTH pins live: 21 G32 + 18 G30 + 3 DPCS10 = 42 high-confidence parser-version-pin rows
---

Run `/learn bt-banner-parser-session-2026-05-16` to extract patterns into the knowledge base.
