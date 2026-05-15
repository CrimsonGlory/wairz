# Anti-patterns: BT Firmware Banner Parser Session

> Extracted: 2026-05-16
> Campaign: ad-hoc systematic-debugging session shipping yesterday's recs #1-#4
> Postmortem: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`

## Failed Patterns

### 1. Disclosure-batch attribution without per-CVE evidence check
- **What was done:** The parser's `_BRAKTOOTH_CVES` tuple originally included `CVE-2021-28139` alongside the 3 Qualcomm DoS CVEs. Reasoning: the BrakTooth ASSET disclosure batch contained all four CVEs across multiple chip vendors (Cypress, Intel, Qualcomm, ESP32, TI), so any device "in the BrakTooth target list" gets pinned with all four.
- **Failure mode:** CVE-2021-28139 is ESP-IDF / ESP32 hardware ONLY per NVD's CPE list — no Qualcomm CPE. Pinning it on every QCA-Rome BT firmware blob would have shipped ~18 false-positive RCE-CVSS-8.8 sb_vuln rows per QCA-Rome device × every future QCA-shipping firmware. The fresh-false-positive count would have approximately MATCHED yesterday's BleedingTooth misattribution count (54 rows per firmware) before correction.
- **Evidence:** Reviewer B forensic-domain audit cross-referencing NVD CVE-2021-28139's CPE list against the parser's `_BRAKTOOTH_CHIPSETS` set. Caught BEFORE Rule #8 rebuild captured the bug.
- **How to avoid:** Per-CVE attribution requires per-CVE evidence — NEVER batch-attribute a disclosure's CVE cluster to a single vendor without checking each CVE's NVD CPE entry independently. Same shape as yesterday's antipattern #1 (filename-only vendor attribution) and #8 (codename without citation) — generalises to "claim-based attribution without per-claim source check". Countermeasure: when authoring a Tier 0 pinning rule, paste the NVD URL into the comment for EACH CVE.

### 2. Hardcoded scan window mismatched real-world banner location
- **What was done:** Initial parser used `_SCAN_BYTES = 4 * 1024` reading the FIRST 4 KB of the file. The assumption was "banners live in headers, headers live at file start."
- **Failure mode:** QCA Rome .tlv files place the BTFM banner at the FILE END as ASCII metadata after the patch payload (e.g. cmbtfw13.tlv 15 KB → banner at offset 14584; crbtfw21.tlv 220 KB → banner at offset 217936). Initial parser found 1/6 banners on the G32 corpus.
- **Evidence:** Live-canary verification — running the parser against real BTFM files. The .ver companion files (33 bytes) parsed correctly (banner fits in first 33 bytes); all .tlv files returned family=unknown.
- **How to avoid:** Before fixing a scan window size, verify the byte offset of the target signal in real corpus files. Use `python -c "with open(f) as fh: print(fh.read().find(b'TARGET_TAG'))"` against 3-5 representative samples. The QCA Rome convention is "patch payload at start, ASCII metadata at end" — a banner-parser convention worth documenting explicitly.

### 3. Test fixture defaults bypassed the "negative case" they were meant to exercise
- **What was done:** `_make_mtk_btmtk` test helper had a default trailer `b"BT_FW build patch_release"` appended to every fixture regardless of the explicit `bt_marker=b"\x00"` argument. The "header passes but no BT marker → low confidence" test always saw the BT_FW marker and the low-confidence gate never fired.
- **Failure mode:** Initial test pass reported "all 23 tests passed" but two cases (`test_broadcom_hcd_truncation_rejected`, `test_mediatek_bt_header_only_no_marker_is_low_confidence`) were inadvertently testing the OPPOSITE of what they claimed to assert.
- **Evidence:** Refactoring the helper to make trailer explicit revealed the bug; tests started failing correctly.
- **How to avoid:** When a test fixture's name implies a negative case ("no_marker", "truncated", "empty"), the helper should NOT have any default that pre-fills the absent property. Make the no-X case carry an explicit `extra_payload=b""` rather than relying on a default-trailer that the helper appends regardless.

### 4. Parallel rebuild + reviewer fixup ran on stale image
- **What was done:** Triggered Rule #8 backend+worker rebuild in the background AFTER the initial 3 feature commits, then applied reviewer findings as a 4th commit. The rebuild captured the first 3 commits' state, not the 4th. Verifying the rebuilt container's `_BRAKTOOTH_CVES` still showed CVE-2021-28139 included.
- **Failure mode:** The first rebuild was effectively useless for end-of-session verification because it predated the critical reviewer fix. Required a second rebuild to capture the fix, plus a Rule #20 docker cp + worker restart to validate the fix BEFORE the second rebuild completed.
- **Evidence:** Initial post-rebuild Rule #11 import smoke showed `CVE-2021-28139 excluded: False` despite the fix being committed to git.
- **How to avoid:** When work is in flight AND a rebuild is required, either (a) wait for all in-flight commits to land before rebuild OR (b) use Rule #20 fast-iteration (docker cp + restart) to validate intermediate state before the rebuild completes. The 5-minute rebuild cycle is too slow for the "reviewer-found-critical-issue → fix → verify" loop; Rule #20 fills that gap.

### 5. Vendor-fork mirror entry duplicated AOSP-side CVE attribution without divergence
- **What was done:** Authored ADV-QTI-BT-HAL-2023 entry under `vendor: qualcomm + chipset_regex: ".*"` that re-emitted CVE-2023-35673 / 40129 / 45866 (the Bluedroid 2023 cluster) on every Qualcomm BT blob. Rationale: "libbt-vendor-qti.so is a vendor-fork of Bluedroid; CVEs transfer at vendor patch cadence."
- **Failure mode:** Double-counting. AOSP-side path_context already classifies libbluetooth.so / bluetooth.default.so as vendor=aosp + category=bluetooth, and the Bluedroid CVE entries fire there. libbt-vendor-qti.so is a DIFFERENT code surface (HAL adapter between Bluedroid and the BT controller — it doesn't contain the GATT vulnerable code paths). The duplicate entry produced findings without operational value (operators couldn't act on "vendor BT HAL has CVE-2023-40129" any differently from "AOSP BT has CVE-2023-40129").
- **Evidence:** Reviewer B M4 forensic-domain audit.
- **How to avoid:** When tempted to mirror CVEs under a vendor-fork attribution, ask: "does this fork's code surface actually contain the vulnerable code path?" If yes, fire the CVE. If no, the fork is a transport layer and the CVE belongs only on the upstream-vendor attribution. Vendor-fork divergence becomes worth a separate entry ONLY when a specific QSB-vs-AOSP-SPL patch-lag is documented (e.g. "QSB 2024-03 omitted CVE-X fix that AOSP 2024-02 SPL shipped").

### 6. Family-name approximation for chipset attribution
- **What was done:** The CVE-2023-28581 YAML entry used `chipset_regex: "(?i)^(wcn3[0-9]{3}|wcn39[0-9]{2}|sm6225|sm4350).*"` claiming "QSB explicitly lists wcn3950 and wcn3990 as affected CPEs". NVD's actual CPE list contains FastConnect 6800/6900/7800, QCA6391/6426/6436, Snapdragon 865/870/8 Gen 1, AR2 Gen 1, XR2 5G, WCN6740, WSA/WCD9380/9385 — explicitly NOT WCN3950 or WCN3990.
- **Failure mode:** Same shape as antipattern #1 — claim-based attribution without source check. The previous author saw "WCN" + "WLAN" in QSB and extrapolated to all WCN3xxx family chips. Real CPE attribution is per-chip-model not per-family-name.
- **Evidence:** Reviewer B H2 forensic-domain audit cross-referencing NVD CPE list.
- **How to avoid:** When authoring a chipset_regex for a specific CVE, copy the NVD CPE list into the YAML notes verbatim (or the QSB CPE list URL). The chipset_regex should match exactly the chipsets in the cited list — no family-name extrapolation. If the family-name approximation is intentional (operator wants "any WCN3xxx WLAN firmware as advisory shape"), use a separate `advisory_id` entry that's clearly labeled as approximate.

### 7. Apache codename docstring conflated with AR3002 legacy
- **What was done:** Parser docstring at module-level + codename map comment said "APA → Apache → WCN3988 / AR3002 legacy". The conflation muddles two different generations of Atheros BT silicon: WCN3988 is a 2018+ UART-attached chip using the modern TLV-rampatch format with BTFM banners; AR3002/AR3012 are 2010-era USB-attached BT dongles using ath3k.ko + per-chip OTP firmware that does NOT carry BTFM banners.
- **Failure mode:** Future maintainer reading the docstring might assume "Apache codename means we support AR3002 USB firmware too" and try to wire it into the parser, encountering a completely different file format. Or worse, ship code that assumes AR3002 firmware behaves like WCN3988 — different code path entirely.
- **Evidence:** Reviewer B H3 forensic-domain finding.
- **How to avoid:** When codename mappings span generations of silicon, document the GENERATION explicitly. "APA → Apache codename → WCN3988 UART (Fairphone 4)" is clear; "Apache → WCN3988 / AR3002 legacy" is ambiguous. The bracket between codename and chip family should match exactly the kernel driver's switch statement (`btqca.c case QCA_WCN3988`).

### 8. MediaTek BT detection gate accepted truncated HCD bytes as "printable ASCII"
- **What was done:** The 32-byte btmtk_patch_header gate originally required only that datetime[16] be "mostly printable" (≥12/16 bytes printable per ASCII range + NUL padding). Zero-padded HCI command bytes (0x4c='L' printable, 0xfc non-printable, 0x18 non-printable, NULs printable) accidentally passed the gate when they followed the WRITE_RAM opcode.
- **Failure mode:** A truncated Broadcom HCD file that failed the HCI walker would route to the MediaTek branch and incorrectly emit family=mediatek_bt with confidence=low. Real bug — caught by `test_broadcom_hcd_truncation_rejected`.
- **Evidence:** Test failure on the truncation-rejection unit test.
- **How to avoid:** Gates that distinguish "ASCII text" from "binary that happens to contain printable bytes" should require structural evidence specific to the text shape. For datetime strings: require at least one decimal digit (every real timestamp has digits like 2024 or HH:MM). For chip-model tags: require at least one printable non-NUL byte (binary padding is all-NUL; real strings have non-NUL content).

## Cross-Cutting Anti-pattern Themes

1. **"Source-citation laziness" generalises across the campaign.** Yesterday's #1 (filename-only vendor attribution), #8 (codename without citation), today's #1 (disclosure-batch CVE attribution), #6 (family-name chipset approximation), #7 (codename generation conflation) all share the shape "made a claim without checking the authoritative source". The countermeasure is mechanical: every CVE pin's comment must include the NVD URL, every codename mapping's comment must include the upstream Linux source path + commit, every chipset attribution's comment must include the QSB or NVD CPE list. Cheap; preventive.

2. **"Default-trailer leakage" in test fixtures** (#3) mirrors the broader "negative-case-bypass" failure mode from yesterday (gates that fire silently when they're not supposed to). Test fixtures whose negative cases require the helper to be EXPLICIT about absence are robust; fixtures that default to present-with-fallback bypass the negative case.

3. **"Stale rebuild" vs "Rule #20 fast iteration"** (#4) — when work is in flight AND a rebuild is in progress, the rebuild captures whatever state existed at rebuild-start time. The mismatch between "I shipped the fix" (git history) and "the running image reflects the fix" (container state) is structurally invisible without a Rule #11 import-smoke check post-rebuild. Always re-verify after a Rule #8 rebuild even if the test suite passed pre-rebuild — particularly when reviewer findings landed during the rebuild window.

4. **"Over-attribution" vs "right-shape attribution"** (#5, #6) — when in doubt about whether a CVE applies, the right answer is usually NOT to fire it on the broadest possible scope. The fork-mirror entry (#5) and the family-name chipset_regex (#6) both shipped "fire on everything that looks vaguely like the affected device" attribution; the correct shape is "fire only on the documented set, document the documented set inline". Same lesson at two different layers.

5. **"Reviewer-mode self-checking"** — Reviewer B's catch of CVE-2021-28139 is itself reproducible: the original author (this session) and yesterday's session author (different session) both internalized "be evidence-first" and STILL shipped per-CVE-attribution-without-evidence. The Rule #19 discipline is a habit that requires external enforcement (a different reviewer mode, ideally with NVD-fetch tooling) — internal "I'll be careful" doesn't hold under deadline pressure or batch authoring. Mechanical detection: any CVE pin authored without a citation-bearing comment is a candidate for re-review.
