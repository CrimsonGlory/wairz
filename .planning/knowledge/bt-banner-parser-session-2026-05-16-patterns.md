# Patterns: BT Firmware Banner Parser Session

> Extracted: 2026-05-16
> Campaign: ad-hoc systematic-debugging session shipping yesterday's recs #1-#4
> Postmortem: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`

## Successful Patterns

### 1. Content-evidence parser as architectural countermeasure to filename-only attribution
- **Description:** Instead of patching each new BTFM/HCD/WMT pattern in YAML, ship a parser that reads the actual banner / magic / struct shape from file content and populates `ParsedBlob.vendor` + `version` + `chipset_target` directly. Detector then overrides `Classification.vendor` with `ParsedBlob.vendor` when set. The entire "filename-only-misattribution" failure class becomes structurally impossible.
- **Evidence:** Commit `c3a8fb2`; ~530 LOC parser + 23 tests. Live-canary on G32 corpus: 6/6 .tlv/.ver files now report vendor=qualcomm + version=banner + chipset from content. Two yesterday's-failure-mode cases (BleedingTooth, BTFM vendor) prevented by construction going forward.
- **Applies when:** Any classification dimension (vendor / chipset / version / signed-status) where filename signals are inherently lossy AND content signals are extractable from a bounded read window. The architecture is: classifier produces a tentative Classification (filename-driven) → parser produces a ParsedBlob (content-driven) → detector picks content over filename when both signals exist.

### 2. Parallel research scouts before specification work
- **Description:** Before authoring the parser, dispatched 3 parallel research agents — Scout A (QCA Rome BTFM banner format), Scout B (Broadcom HCD HCI command stream), Scout C (MediaTek WMT btmtk_patch_header + Bluedroid/wpa_supplicant CVE lists). Each returned a precise spec with upstream Linux source citations (btqca.c, btbcm.c, btmtk.c) in ~3-4 minutes.
- **Evidence:** Session research notes; parser regex shape + codename map + HCI walker semantics all came from the scout outputs. Each scout produced precise file:line citations that authoring-in-isolation would have required 3-4× more iteration to derive.
- **Applies when:** Authoring code that depends on multiple parallel specs (file format A + file format B + CVE attribution). Sequential research adds dependencies; parallel research compresses the spec-gathering phase.

### 3. Live-canary on real corpus files during parser development
- **Description:** After initial parser draft, copied 8 sample BTFM files (cmbtfw13.tlv, .ver, apbtfw10.tlv, crbtfw11/20/21.tlv, cmnv13.bin, apnv10.bin) from the container to host /tmp via `docker cp` and ran the parser directly. Caught the head-only scan window missing tail banners (1/6 hit rate) before the parser shipped.
- **Evidence:** First canary returned only `cmbtfw13.ver` (33 bytes, banner in first 33 bytes); all .tlv files (>15 KB) returned family=unknown. Investigation: BTFM banner sits at file END not start. Fix: head + tail scan combined.
- **Applies when:** Authoring a parser whose synthetic unit-test fixtures may not match the byte layout of real-world files. Test fixtures are necessarily synthetic (small, controlled); the corpus has organic structure (variable size, banner-at-end conventions, padding). A live-canary catches the layout mismatch synthetic tests can't.

### 4. Multi-persona Citadel review (arch + forensic + adaptability in parallel)
- **Description:** After per-piece commits landed, dispatched 3 parallel Citadel reviewer agents: arch + forensic-domain + adaptability. Each found distinct issues. Forensic (B) caught the **exact same antipattern this campaign was supposed to prevent** — CVE-2021-28139 is ESP32-only per NVD, not Qualcomm.
- **Evidence:** Today's session multi-persona review. Reviewer B found 4 high/medium findings; A found 3 medium + 4 low; C identified 3 high-priority next-session candidates. Single-thread review would have shipped CVE-2021-28139 latent as ~18 false-positive RCE pins per QCA-Rome device.
- **Applies when:** Any commit batch that adds CVE attribution OR security-sensitive classification (vendor/chipset attribution downstream of which the matcher fires). The forensic-domain reviewer with NVD-checking discipline is load-bearing per-CVE.

### 5. Reviewer fixup commit (per Rule #25 single-slice) stays bisect-clean
- **Description:** After 3 feature commits (c3a8fb2 / 88082f0 / d585c79) shipped, applied reviewer findings as a single fixup commit (ae91e98). The fixup commit is independently revertable — could revert without losing the parser or the spec advisories. The 4-commit chain remains bisect-clean.
- **Evidence:** Commit log c3a8fb2 → ae91e98; 0 reverts; clean bisect lanes between feature additions and the reviewer-driven correction.
- **Applies when:** Any commit batch where reviewer-driven corrections arrive AFTER the initial commits ship. The fixup commit is a Rule #25 single-slice in itself — it carries multiple reviewer findings but all of them are correction-shaped, not new-feature-shaped, so the alignment-test discipline (Rule #25 single-slice exception #2) applies: bundle correction-shape changes that target the SAME commit-batch's surface in one atomic commit.

### 6. End-of-session verification on the corpus is the only reliable "did it work" gate
- **Description:** After Rule #8 rebuild, ran a verify script that DELETEs existing rows + re-detects + re-cve-matches on the full corpus (G32 + G30 + DPCS10×3), then prints before/after deltas. Confirmed: Tier 0 BRAKTOOTH pins fired correctly (21 G32 / 18 G30), ZERO CVE-2021-28139 attribution, MediaTek BT detection works on DPCS10 ROMv4 files, spec-level advisories fire on every vendor's BT blobs.
- **Evidence:** Verify script output; CVE counts before/after match the expected deltas. Without this verification, the parser shipping with the original CVE-2021-28139 included would have been undetectable by unit tests alone (mocks verify "function called"; live data verifies "what gets persisted").
- **Applies when:** Any session shipping classification + matcher changes whose downstream effect is "more CVE rows in the DB". Unit tests verify dispatch shape; only re-running the full pipeline on real firmware verifies the actual CVE attribution.

### 7. Lazy I/O in parsers when called per-blob across thousands of files
- **Description:** Reviewer A M2 caught that the original parser read the full file (up to 4 MB) unconditionally even when the QCA banner regex already pinned the result. Refactored: head + tail scan FIRST → QCA + MediaTek branches FIRST (head-only) → lazy full-file read only when Broadcom HCD's HCI walker is needed. Cuts peak memory cost dramatically for the common QCA-hit case.
- **Evidence:** Commit `ae91e98` parser refactor. With 19+ BTFM blobs per Qualcomm firmware × thousands of firmwares in a future production load, the unconditional 4 MB read is a real allocation footprint difference.
- **Applies when:** Any parser called from inside a per-file walk loop. Order branches by "head-only cheap-evaluation" first, "needs-full-file" last. The walk-cost-amortization difference compounds across the corpus.

### 8. Filename↔content mismatch flag as forensic-load-bearing metadata
- **Description:** G32's `apbtfw10.tlv` contains a CHE (Cherokee) banner — content says WCN3990, filename suggests WCN3988 (Apache). Parser correctly trusts content (Rule #19) and now ALSO surfaces the discrepancy as `metadata.bt_fw_banner.filename_codename_mismatch = {filename_codename: "APA", content_codename: "CHE"}`. Cheap; forensic-load-bearing.
- **Evidence:** Reviewer B M2 finding + new test `test_qca_rome_filename_content_mismatch_flagged`. Real-world reproducible against the G32 corpus.
- **Applies when:** Any classification step that trusts one signal over another. Surface the discrepancy as metadata so future forensic audits can audit it without re-reading parser source.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Parser overrides Classification.vendor when content-derived vendor is set | Yesterday's antipattern #1 (filename-only attribution) explicitly traded as the lesson; structural fix is content > filename when both exist. | Worked. Live-canary verified vendor=qualcomm on every BTFM file regardless of filename. |
| Head + tail scan windows (4 KB + 8 KB) rather than full-file scan | QCA Rome .tlv files place banner at file END; HCD/MediaTek place metadata at file START. Combined ~12 KB I/O covers both. Bounded; cheap. | Worked. All 6 G32 .tlv/.ver files parsed correctly. |
| BRAKTOOTH Tier 0 pin fires `_BRAKTOOTH_DoS_CLUSTER` (3 CVEs) not the full 4 | Reviewer B forensic audit: CVE-2021-28139 is ESP32-only per NVD's CPE list. Including would replicate yesterday's failure mode. | Worked. Live-canary verified 21 Tier 0 pins on G32 (3 CVEs × 7 banner-bearing blobs); ZERO CVE-2021-28139 attribution. |
| `vendor_regex` as optional alternative to `vendor` (not replacement) | Backward compat with all existing curated entries that use `vendor`; new spec-level advisories opt into `vendor_regex` explicitly. | Worked. 4 spec-level BT advisories retargeted; all other entries unchanged. |
| Removed ADV-QTI-BT-HAL-2023 vendor-fork mirror entry entirely | Reviewer B M4: duplicate-Bluedroid-CVE-attribution under vendor=qualcomm without operational value. AOSP-side path_context already covers libbluetooth.so. | Worked. Inverted test asserts Qualcomm BT blobs do NOT inherit Bluedroid CVEs. |
| CVE-2023-28581 retargeted from WCN3xx0 to actual NVD CPE list (FastConnect/QCA64xx) | Reviewer B H2: NVD CPE list does not contain WCN3950 or WCN3990 despite the YAML's previous claim "QSB explicitly lists wcn3950 and wcn3990". | Worked. G32 (SM6225) + G30 (SM4350) correctly fall out of scope; future devices with actually-affected chipsets get correct attribution. |
| Documentation of negative-case (NV calibration .bin) returns family=unknown | Negative case is informative — operator can verify "yes the parser saw this file and decided no banner present" instead of inferring from absence of metadata. | Worked. cmnv13.bin / apnv10.bin correctly return family=unknown. |
| Defer Reviewer C H1 (YAML codename externalization) + H2 (banner-pin YAML) to next session | Single-hour each; cleanly self-contained. Today's session focused on shipping the four queued recs. | Carried forward as the highest-leverage next-session candidates. |

## Patterns Cross-Referenced Across Sessions

This session's patterns reinforce/extend prior:
- Yesterday's pattern "filename evidence beats path evidence for vendor when both exist" — today extends to "content evidence beats filename evidence" by mechanical construction (the parser).
- Yesterday's pattern "multi-persona Citadel review catches different failure modes" — today's review caught the SAME class of mistake (filename-only attribution / disclosure-batch attribution) at a different code layer. The discipline applies recursively.
- Rule #19 (evidence-first) — today's application is per-CVE not just per-vendor: every CVE pin requires NVD CPE check, every codename mapping requires upstream-source citation, every chipset attribution requires evidence beyond family-name approximation.
- Rule #25 (per-piece commits) — held across 4 commits including a multi-reviewer correction-shape fixup. Robust pattern.
- Rule #46 (canary discipline) — today's "end-of-session verification on the corpus" is the Rule #46 analog for CVE pipelines: the unit test verifies dispatch shape, the live verification verifies the actual persisted CVE attribution. Both are necessary.
