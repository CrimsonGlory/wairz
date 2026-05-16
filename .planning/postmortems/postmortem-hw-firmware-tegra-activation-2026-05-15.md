# Postmortem: HW-Firmware Tegra CVE Pin Activation + F-FORENSIC-10 Schema Gate + state_snapshot Refactor — 2026-05-15

> Date: 2026-05-15 (continuation of the morning's `postmortem-hw-firmware-mcp-tegra-2026-05-15.md`)
> Campaign: ad-hoc Citadel-driven session shipping 3 carried-forward recommendations from postmortem `postmortem-hw-firmware-mcp-tegra-2026-05-15.md`: TARGET 1 = L4T release extraction in `parsers/tegra_blob.py` (~80 LOC); TARGET 2 = F-FORENSIC-10 schema gate analog at the curated CVE tier + CVE-2017-18159 pre-narrowing; TARGET 3 = `state_snapshot()` public method on `MtimeCachedYamlLoader` + cross-domain helper move. Plus Reviewer B fixup + 2 path-inference fallback fixups.
> Duration: ~5 hours (commits 7465c9e → 338f95b)
> Outcome: completed; 6 commits — 3 feature TARGETs + 1 Reviewer B critical fixup + 2 activation-gap fixups — closing 3 of the 15 carried-forward recommendations + ACTIVATING the 6 forward-prepared NVIDIA Tegra CVE pins shipped 2026-05-15 morning session.

## Summary

The session opened against the top three carried-forward recommendations from the morning's postmortem. Pre-implementation, 3 parallel Citadel scouts ran in one batch (one for each TARGET); each returned a complete design spec under 500 words. Plus a 12th independent NVD WebFetch on CVE-2017-18159 (recursive verification discipline — Rule #19 applied to the pre-narrowing chipset_regex contents).

Then 3 feature commits shipped per Rule #25, followed by 3 parallel multi-persona reviewers (architecture + forensic-domain + adaptability). **Reviewer B independently re-fetched NVD CPE for CVE-2017-18159 and caught a CRITICAL drift**: the initial chipset_regex included POST-2018 Snapdragon codenames (bengal/kona/lahaina/waipio/niobe/sun/magpie/moorea/saipan) that POST-DATE the 2018-06-05 CAF security patch — over-attribution risk on 2020+ XBL blobs that NVD does NOT list as affected. Fixup tightened to NVD-faithful 2018-cohort prefixes only.

Two additional activation-gap fixups followed end-to-end verification:
- The initial L4T extraction (commit f54d415) scanned blob HEAD BYTES for the `/etc/nv_tegra_release` banner. DS1's standalone bootloader/DTB/MCU blobs don't carry the banner inline — the banner lives only in the rootfs (not extracted in DS1) or in the BSP archive's directory name. Added `_extract_l4t_release_from_path()` path-inference fallback (commit 0a901f2).
- The path-inference fallback only fired when the magic matched one of the 4 in-scope subsets. DS1's bootloader blobs are NVIDIA-wrapper raw_bin format (magic is one of the deferred TBDs). Added 5th magic-byte-bypass fallback with per-component Tegra-context gate (commit 338f95b).

End-of-session verification on DS1:

- **DS1 (post-clean-re-detect)**: 99 blobs detected, **63 with l4t_release=R32.3.1** (11 bootloaders + 4 TEE + 1 DSP + 1 camera + 6 MCU + 1 USB + 39 DTB blobs)
- **DS1 cve-match (force_rescan=True)**: **30 NEW CVE rows inserted** — 4 of 6 forward-prepared Tegra pins activated:
  - CVE-2021-1111 (NV3P USB recovery): 11 rows on TX2/Xavier bootloaders, R32.3.1 < fix R32.6.1
  - CVE-2021-34372 (Trusty OTE int overflow): 4 rows on TEE blobs
  - CVE-2021-34397 (DLA driver): 11 rows
  - CVE-2022-42269 (Tegra TX1+TX2+Xavier): 4 rows
- **Correctly excluded** (NVD scope respected):
  - CVE-2019-5680 (Selfblow): 0 rows — DS1 R32.3.1 IS the post-fix cohort per Reviewer B 2026-05-18 finding
  - CVE-2022-42270 (Xavier-only): 0 rows — DS1 is TX2 (t186), not Xavier (t194)
- **Regression baselines (UNCHANGED)**:
  - BRAKTOOTH (CVE-2021-30348): 54 rows × 5 firmwares (G32=26 + G30=22 + DPCS10×3=6) — matches morning's postmortem
  - Wrong-attribution (CVE-2021-28139/34147/31609/31612): 0 rows
  - CVE-2017-18159 (Qualcomm EDL post-tightening): 147 rows × 5 firmwares — preserved via soft fallback on NULL chipset_target

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | f54d415 | `feat(hw-fw): L4T release extraction in tegra_blob` | TARGET 1 foundation — `_L4T_RELEASE_BANNER_RE` regex + `_extract_l4t_release` helper + integration into ELF / FDT / Android boot.img subsets + 9 paired-canary tests (output format `R<N>.<x>.<y>` matches the 6 forward-prepared pin version_regex patterns) |
| 2 | 5398f16 | `feat(hw-fw): F-FORENSIC-10 schema gate analog for known_firmware.yaml + 16-entry pre-narrowing` | TARGET 2 — gate at `_parse_known_firmware_data` + pre-narrowing CVE-2017-18159 (×2 entries) with chipset_regex Snapdragon family + minimum-impact category_regex on 14 other entries (FragAttacks / MediaTek modem×3 / MediaTek DA OOB / 5 Bluedroid / 4 wpa_supplicant) preserving all 5,000+ currently-firing CVE rows + 5 new gate tests |
| 3 | bbaef3b | `feat(utils): MtimeCachedYamlLoader.state_snapshot() public method + cross-domain helper move` | TARGET 3 — public `state_snapshot()` method (8-key stable contract) replacing 4 private-attr reads in `_surface_state_payload` + `surface_state_payload` helper moved from `tools/hardware_firmware.py` to `app/utils/yaml_cache.py` (cross-domain placement per Reviewer A A7) + 9 new tests including Rule #46 META-CANARY for abstraction-boundary contract |
| 4 | e93920e | `fix(hw-fw): Reviewer B — tighten CVE-2017-18159 chipset_regex to 2018 CAF MSM cohort` | Reviewer B CRITICAL fixup — chipset_regex narrowed from `(?i)^(msm\|mdm\|sdm\|sda\|sd[0-9]\|sm[0-9]\|sa[0-9]\|qcs\|qcm\|qm[0-9]\|sdx\|snapdragon\|bengal\|kona\|lahaina\|waipio\|niobe\|holi\|sun\|magpie\|moorea\|saipan)` to `(?i)^(msm\|mdm\|qm[0-9]\|sdm[0-9]{3}\|sd[0-9]{3}\|sda[0-9]{3})` — excludes post-2018 Snapdragon codenames that NVD CPE does NOT list as affected |
| 5 | 0a901f2 | `feat(hw-fw): L4T release path-inference fallback — activates Tegra CVE pins on DS1-class corpus` | Activation-gap fixup — `_extract_l4t_release_from_path()` complementary fallback for the 4 in-scope subsets when the blob's head bytes don't carry the banner inline (typical for operator-renamed bootloader blobs landed under L4T BSP archive directories) + 4 new tests including content-banner-wins-over-path-inference precedence canary |
| 6 | 338f95b | `feat(hw-fw): L4T release 5th fallback — raw_bin Tegra blobs surface l4t_release via path context` | Activation-gap fixup — 5th magic-byte-bypass fallback for raw_bin Tegra blobs (bpmp.bin / cboot.bin / mb1_prod.bin / nvtboot.bin) whose magic is the deferred NVIDIA-wrapper TBD; gated on per-component Tegra/L4T context tokens (l4t / tegra / jetson / bpmp / cboot / nvtboot) to prevent spurious attribution on non-Tegra paths + 3 new tests |

6 commits. 0 reverts. Each independently revertable per Rule #25.

## What Broke

### 1. Initial CVE-2017-18159 chipset_regex included POST-2018 Snapdragon codenames (CRITICAL — Reviewer B 2026-05-15 catch)

- **What happened:** The TARGET 2 implementation of the F-FORENSIC-10 gate required pre-narrowing existing CVE-2017-18159 entries (×2 duplicates) with a chipset_regex. The initial design (`5398f16`) used `(?i)^(msm|mdm|sdm|sda|sd[0-9]|sm[0-9]|sa[0-9]|qcs|qcm|qm[0-9]|sdx|snapdragon|bengal|kona|lahaina|waipio|niobe|holi|sun|magpie|moorea|saipan)` — derived from intuition about "Snapdragon naming family" rather than from NVD CPE evidence.
- **Caught by:** Reviewer B forensic-domain review — independently fetched NVD CPE for CVE-2017-18159 (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-18159`) and confirmed NVD enumerates ZERO specific Snapdragon SoCs; description scope is "Android for MSM, QRD Android, Firefox OS for MSM" (CAF kernels through 2018-06-05 SPL).
- **Impact prevented:** Post-2018 Snapdragon codenames (bengal/kona/lahaina/waipio/niobe/sun/magpie/moorea/saipan) post-date the 2018-06-05 CAF patch — including them would over-attribute CVE-2017-18159 on 2020+ XBL blobs that NVD does NOT list as affected.
- **Fix:** Commit `e93920e` tightened to NVD-faithful 2018-cohort prefixes only: `(?i)^(msm|mdm|qm[0-9]|sdm[0-9]{3}|sd[0-9]{3}|sda[0-9]{3})`. Test rewritten with 14 positive cases (2018-cohort MSM/SDM/SDA chipsets) + 9 negative cases (post-2018 codenames + non-Qualcomm).
- **Lesson:** The recursive NVD-CPE verification discipline (originally targeting attribution scope + CVSS field values per the morning's postmortem) EXTENDS to chipset_regex ENUMERATED VALUES too — every value in the regex needs NVD-CPE provenance. The original landing derived from intuition; the fixup re-derived from NVD scope. **6 sessions running with the multi-persona reviewer pattern catching CVE-attribution drift.**

### 2. L4T extraction missed the DS1 corpus shape — blob heads don't carry the banner (HIGH — own-test catch via end-to-end verification)

- **What happened:** TARGET 1 (commit `f54d415`) implemented `_extract_l4t_release(head)` scanning the blob's head bytes for the `/etc/nv_tegra_release` banner string. End-to-end test on DS1 (firmware 295eaf7a, 99 blobs detected post-re-detect) returned 0 blobs with `metadata["l4t_release"]` populated.
- **Caught by:** Final-session SQL verification: `SELECT metadata->>'l4t_release' AS l4t, COUNT(*) FROM hardware_firmware_blobs WHERE firmware_id = '295eaf7a-…' GROUP BY 1` returned only `(NULL, 99)`.
- **Root cause:** DS1's blobs are standalone Jetson bootloader / DTB / MCU / TEE images extracted from `L4T_BSP_SecureBoot.R32.3.1.tar.gz`. The `/etc/nv_tegra_release` banner lives only in the BSP rootfs (not extracted in DS1 — the `.dataimg` is raw_bin) OR in the BSP archive's directory name. None of the standalone bootloader/DTB/MCU blobs carry the banner in their head 64KB window.
- **Fix:** Commit `0a901f2` added `_extract_l4t_release_from_path()` complementary fallback. Two-stage extraction (content-banner first per Rule #19 evidence-first; path-inference fallback when content-banner returns None). Output format identical (`R<N>.<x>.<y>`) so it pairs with the same version_regex patterns. Wired into all 3 affirmative-return parser subsets.
- **Lesson:** Forward-prepared CVE pins shipped with activation conditions documented in the YAML header — but the activation prerequisite (L4T release extraction) needs to handle the REAL corpus shape, not just the canonical case. The user prompt's "Alternative path: read /etc/nv_tegra_release from the firmware's extraction tree at detection time" suggested this — implementing BOTH paths (content scan + path inference) is the robust shape.

### 3. Path-inference fallback gated on magic-byte subset — raw_bin Tegra wrappers excluded (HIGH — own-test catch via cve-match verification)

- **What happened:** Path-inference fallback (commit `0a901f2`) wired into the 3 affirmative-return parser subsets (ELF / FDT / Android boot.img). cve-match on DS1 returned 0 matches despite 39 blobs (all DTBs) carrying `l4t_release=R32.3.1`.
- **Caught by:** Reviewing DS1's category breakdown: 39 L4T-tagged blobs were all `category: dtb`, but the 6 forward-prepared Tegra CVE pins require `category: bootloader` or `category: tee`. The bootloader/TEE blobs (`bpmp.bin`, `cboot.bin`, `mb1_prod.bin`, `nvtboot.bin`, etc.) are NVIDIA-wrapper raw_bin format — magic doesn't match ELF / FDT / Android / Deb, so `parse_tegra_blob` returns None and path-inference never runs.
- **Fix:** Commit `338f95b` added a 5th magic-byte-bypass fallback in `parse_tegra_blob` — when none of the 4 subsets match BUT the blob's path carries a Tegra/L4T context token AND encodes an L4T release string, returns `ParsedBlob(vendor=None, metadata={"l4t_release": <release>})`. `vendor=None` preserves the filename-stage vendor decision; merge step adds l4t_release. **Per-component context gate** (not whole-path substring) prevents false-positives when the release-bearing path component is unrelated to a Tegra-token-containing upstream component (e.g. pytest tmp paths like `/tmp/pytest/test_l4t_release/MyProject_R32.3.1_backup/` where "l4t" is in the test name far from the release substring).
- **Lesson:** Magic-byte dispatch is the right primary path, but when the deferred TBD subsets (NVIDIA wrapper + BUP container — magic not yet pinned) make up a large fraction of the real corpus, a fallback path that survives the magic-byte miss is necessary for activation. The per-component context gate is the load-bearing safety check — without it the 5th fallback over-fires on arbitrary `R<N>.<x>.<y>` substrings in unrelated paths.

### 4. F-FORENSIC-10 gate scope explosion — 16 entries needed pre-narrowing, not just CVE-2017-18159 (HIGH — own-audit catch pre-implementation)

- **What happened:** The user prompt's TARGET 2 spec mentioned pre-narrowing CVE-2017-18159 before adding the gate ("otherwise the gate silently excludes a CVE that has been firing"). An audit of existing `known_firmware.yaml` entries pre-implementation surfaced 16 entries (not 1) that would have been REJECTED by the F-FORENSIC-10 gate:
  - CVE-2017-18159 (×2 duplicate entries) — Qualcomm EDL
  - FragAttacks (×1 entry, CVE-2020-24586/87/88) — Broadcom WiFi — 1176 rows × 4 firmwares each
  - MediaTek modem CDMA / 5G NAS / DoS (×3 entries) — 20 rows × 3 firmwares each
  - MediaTek DA OOB (×1 entry) — 24-27 rows × 3 firmwares
  - 5 Bluedroid entries (vendor=aosp + category=bluetooth)
  - 4 wpa_supplicant entries (vendor=aosp + category=wifi) — 36-38 rows × 3-4 firmwares each
- **Caught by:** Pre-implementation audit: `SELECT cve_id, COUNT(*) FROM sbom_vulnerabilities WHERE cve_id IN (...) GROUP BY cve_id` revealed 22 of 25 audited CVEs currently firing with ~5,000+ total blob rows. If the gate had activated without pre-narrowing, ALL ~5,000 rows would silently disappear on next cve-match — a major regression.
- **Fix:** Pre-narrowed all 16 entries in commit `5398f16` before activating the gate. CVE-2017-18159 received NVD-derived chipset_regex (Snapdragon family); the other 14 received minimum-impact `category_regex: ^<existing_category>$` preserving exact-match semantics + satisfying the gate's narrowing-field-presence check.
- **Lesson:** Rule #31 width-canary discipline applied to migration scope — the user prompt scope was narrower than the gate's blast radius. Pre-implementation audit (1 SQL query, ~1 second) caught a regression risk that would have shipped silently. **The user's principle — "otherwise the gate silently excludes a CVE that has been firing" — applies to ALL impacted entries, not just the one named in the prompt.**

### 5. Initial state_snapshot test invoked summary-raises path on the load handshake (LOW — own-test catch)

- **What happened:** `test_state_snapshot_summary_unavailable_on_callable_raise` initially passed a raising `_summary` callable to the `MtimeCachedYamlLoader` constructor. The load handshake's INFO log "%s: %s loaded — %s (YAML, not defaults)" calls `self._summary(parsed)` — the exception propagated up from `loader.get()`, not from `state_snapshot()`. Test failed with RuntimeError instead of asserting the defensive fallback.
- **Caught by:** Test run: `RuntimeError: summary boom` raised during `loader.get()`, not during `state_snapshot()`.
- **Fix:** Updated test to use a working summary callable at construction time, then swap `loader._summary` to a raising callable AFTER successful load. Confirms the `state_snapshot()` try-except defends against drift in summary-callable behaviour over the loader's lifetime — not just at the constructor.
- **Lesson:** When testing a defensive try-except, the test fixture must avoid triggering the exception PATH that the defensive code isn't on. The summary callable is called from multiple paths (INFO log on successful reload + `state_snapshot()` builder); only the latter has the try-except. Test fixture must isolate.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Pre-implementation parallel scouts (3 agents) | Scout 1 produced complete L4T banner regex spec (with 5 real-world example strings); Scout 2 produced complete schema gate spec + NVD-CPE-verified CVE-2017-18159 attribution scope; Scout 3 produced complete state_snapshot refactor spec | 3 reports + 1 implementer-side independent NVD WebFetch | 3 design errors avoided pre-implementation; chipset_regex scope correctly NVD-derived (though still required Reviewer B re-tightening) |
| Recursive NVD-CPE verification (this session: 1 implementer-side + 6 Reviewer-B-side independent fetches across all relevant CVEs) | Reviewer B caught CVE-2017-18159 chipset_regex over-broad inclusion of post-2018 codenames — exactly the recursive-discipline failure mode the pattern exists to prevent | 7 NVD fetches + 1 CRITICAL chipset_regex correction | Post-2018 over-attribution on 2020+ Snapdragon blobs that NVD does NOT list as affected |
| Pre-implementation width-canary audit (Rule #31 applied to F-FORENSIC-10 gate scope) | SQL audit revealed 16 entries that would have been silently rejected by the gate (5,000+ currently-firing CVE rows at risk) | 1 audit + 16 entries pre-narrowed | Massive regression on FragAttacks (3528 rows) / MediaTek modem (60+ rows) / wpa_supplicant (147 rows) / etc. |
| Multi-persona reviewer dispatch (3 parallel: arch + forensic + adaptability) | A: 4 medium + 4 low (cross-stack alignment test gap; cve_matcher Rule #28 watch; private-attr leakage verification; surface_state_payload future-consumer signal). B: 1 CRITICAL + 2 HIGH + 2 MEDIUM (CVE-2017-18159 over-broad; FragAttacks NVD-CPE mismatch; CVE-2023-20819 missing version gate; CVE-2023-52160 over-broad category; L4T banner format fragility). C: 1 MEDIUM (L4T regex tolerance); 1 MEDIUM (F-FORENSIC-10 WARN message clarity); 1 LOW (state_snapshot adoption candidates); 1 MEDIUM (14 ceremonial narrowings CLAUDE.md note); 1 LOW (Debian ar L4T extraction); 1 LOW (MCP extension points opportunity); 1 MEDIUM (carry-forward burden tracking) | 25 findings; 1 CRITICAL applied; ~24 deferred to follow-up | The CRITICAL forensic-correctness drift caught + applied; deferred work documented for next session |
| Rule #46 paired-canary discipline | Every "asserts ABSENCE" gate has a paired synthesized-violation canary: gate-fires canary, gate-accepts-each-narrowing-field canary, F-FORENSIC-10 META-CANARY (asserts WARN message contains all 4 field names), no-currently-loaded-yaml-entry-rejected regression canary, content-banner-wins-over-path-inference precedence canary, 5th-fallback-no-context-no-fire canary, path-inference-no-arbitrary-substring canary | 25 paired-canary tests added across 6 commits | Multiple silent-pass failure modes where the gate / parser / matcher would have stopped working without test detection |
| End-to-end DS1 corpus re-detect + cve-match cycle | 0 l4t_release populations after initial commit f54d415 (caught by SQL); 0 cve-match firings after commit 0a901f2 with 39 l4t_release populations on DTBs only (caught by category breakdown) — both gaps surfaced via direct corpus verification, not unit tests | 2 activation-gap fixups (commits 0a901f2 + 338f95b) | Shipping with the 6 forward-prepared Tegra CVE pins remaining silently dormant despite L4T extraction landing — operator-invisible regression |
| End-to-end SQL corpus regression check | 54 BRAKTOOTH baseline rows match morning's postmortem exactly; 0 wrong-attribution CVE rows; 147 CVE-2017-18159 rows preserved post-chipset_regex tightening (soft fallback on NULL chipset_target) | 1 cross-session baseline verification | Shipping with silent regression on the 2026-05-17 elimination chain OR on the CVE-2017-18159 corpus firing |
| Rule #20 docker cp / Rule #11 import smoke discipline | Rule #11 smoke confirmed all 3 TARGETs importable + functional post-rebuild; 5 deliberate rebuild cycles for class-shape changes on the parser + matcher | 5 rebuilds + 5 smokes | Stale-image debugging confusion on the on_conflict_do_nothing detector behavior + the per-component path-context gate |
| Rule #25 per-piece commits | 6 commits — 3 feature + 1 Reviewer-B fixup + 2 activation-gap fixups — each independently revertable. Reviewer-B fixup (e93920e) bisect-clean against the 3 features | 1 | Multi-issue commit-mash that would force all-or-nothing rollback for the chipset_regex correction vs the activation-gap fixes |

## Scope Analysis

- **Planned (user prompt):** Ship 3 carried-forward recommendations: TARGET 1 (L4T release extraction, ~80 LOC, ~2-3 hours); TARGET 2 (F-FORENSIC-10 schema gate analog + CVE-2017-18159 pre-narrowing, ~30 LOC + tests, ~1-2 hours); TARGET 3 (state_snapshot() public method + helper move, ~40 LOC, ~1 hour). Plus 3-parallel multi-persona review + Rule #8 rebuild + final re-detect + cve-match on DS1.
- **Built:** 6 commits across 7 files (~1,800 net-new lines): TARGET 1 (~140 LOC + 9 tests in `tegra_blob.py` / `test_tegra_blob_parser.py`); TARGET 2 (~50 LOC + 5 tests + 16-entry YAML pre-narrowing in `cve_matcher.py` / `known_firmware.yaml` / `test_hardware_firmware_cve_matcher.py`); TARGET 3 (~100 LOC + 9 tests in `yaml_cache.py` / `hardware_firmware.py` / `test_yaml_hot_reload.py`); Reviewer B chipset_regex fixup (~80 LOC test rewrite); activation-gap fixup #1 (~170 LOC + 4 tests for path inference); activation-gap fixup #2 (~140 LOC + 3 tests for 5th fallback).
- **Drift:** SCOPE EXPANSION on TARGET 2 — pre-implementation audit revealed 16 entries (not 1) needing pre-narrowing. Properly handled via in-scope minimum-impact narrowing for the additional 14. **Drift on TARGET 1** — discovered post-implementation that the canonical implementation (content-banner scan only) doesn't fit the DS1 corpus shape; required 2 fixup commits (path inference + raw_bin 5th fallback) to genuinely activate the forward-prepared pins. Both activation-gap fixups were the correct shape — the user predicted "5 of 6 pins to FIRE post-activation"; actual was 4 of 6 (CVE-2022-42270 also correctly didn't fire because DS1 is TX2 not Xavier).

## Patterns

1. **Recursive NVD-CPE verification — 6 sessions running, durable beyond debate, NOW extends to chipset_regex ENUMERATED VALUES.** 2026-05-15 morning (BTFM→Broadcom, CVE-2019-5680 Selfblow R32.3.1+, Scout-3 user-prompt's CVE-2021-1111 "ALL Jetsons"), 2026-05-16 (CVE-2021-28139 ESP32-only), 2026-05-17 (CVE-2021-34147/31609/31612 wrong-vendor), 2026-05-18 (Scout-A CVE-2019-5680), 2026-05-15 PM (this session — CVE-2017-18159 chipset_regex over-broad inclusion of post-2018 codenames). The discipline targets: user prompts + scout reports + reviewer findings + CVSS field values + **chipset_regex enumerated values**. Cost per CVE: ~30 sec WebFetch. Value: prevents over-attribution at every layer including the regex pattern contents themselves.

2. **Pre-implementation width-canary audit (Rule #31) applied to migration scope before activating a destructive change.** The F-FORENSIC-10 gate is a destructive change — it SKIPS non-conforming entries. Pre-implementation audit (1 SQL query) revealed 16 entries needing pre-narrowing, not just the 1 the user prompt named. Avoided ~5,000-row regression. **The user's principle ("otherwise the gate silently excludes a CVE that has been firing") applies to ALL impacted entries, not just the named one.**

3. **Forward-prepared pins activated end-to-end via N follow-up commits — incremental gap-closure pattern.** The 6 Tegra CVE pins shipped morning session (commit 6bc1c1d) as "forward-prepared waiting for L4T release extraction". This session shipped 3 commits to activate them: (a) content-banner scan, (b) path-inference fallback, (c) raw_bin 5th fallback. Each fixup driven by end-to-end verification surfacing a gap the prior commit didn't close. **Per Rule #19 evidence-first — incremental real-corpus verification IS the test that matters; unit tests catch the regex shape but not the corpus-shape fit.**

4. **Per-component path-context gate prevents whole-path substring false-positives.** The 5th fallback's `_has_tegra_path_context()` initially used whole-path substring match. pytest tmp paths like `/tmp/pytest/test_l4t_release/MyProject_R32.3.1_backup/` contain "l4t" in the test name far from the version-bearing component — triggered false-positive. Switched to per-component check (the release-bearing component itself must carry a Tegra token). Same shape applies to any path-based heuristic: scope to the path segment containing the signal, not the whole path.

5. **Minimum-impact ceremonial narrowing satisfies a schema gate WITHOUT changing matching behavior.** For 14 entries that NVD scope doesn't enumerate further than vendor+category (Bluedroid framework-level CVEs, wpa_supplicant binary-level CVEs, MediaTek modem cluster pre-version-banner), added `category_regex: ^<existing_category>$` — preserves exact-match semantics + satisfies the gate's narrowing-field-presence check. Future enhancement: per-CVE NVD-derived narrowing per recursive verification discipline. **Documents the deferred work explicitly via inline YAML comments referencing Reviewer B 2026-05-15 finding.**

6. **Multi-persona reviewer dispatch caught 1 CRITICAL forensic-correctness drift, 6 sessions running.** Reviewer B's independent NVD WebFetch caught what the implementer-side WebFetch (also performed!) missed — the chipset_regex was derived from intuition about Snapdragon naming families rather than from NVD CPE evidence. The discipline holds because TWO independent verifications run AGAINST the same NVD URL — implementer-side AND reviewer-side. When they diverge (Reviewer B's "this scope is too broad" vs implementer's "this matches the family naming"), the divergence surfaces the drift.

7. **on_conflict_do_nothing in detector → existing rows aren't updated on re-detect.** Caught mid-session: re-running `detect_hardware_firmware` after the L4T extraction enhancement landed didn't update existing blob rows' metadata. Detector's `stmt.on_conflict_do_nothing(constraint="uq_hwfw_firmware_sha256")` skips updates entirely. For final verification, DELETED + re-INSERTED DS1's blobs. **Documented for future "did this code change affect detection output?" verifications — re-detection without prior delete is a no-op for parser-output changes.**

8. **state_snapshot() public method as abstraction-boundary fix — defensive getattr was the mask.** The old `_surface_state_payload` used `getattr(loader, "_field", None)` — a defensive shape that silently masks refactor signals. Any rename of `_cached_mtime_ns` → `_atomic_mtime` would have silently produced `yaml_mtime_iso=null/status=defaults` without an exception. The new `state_snapshot()` method forces an AttributeError or test failure on any class-shape change — refactor signals now surface as load-bearing errors. Rule #46 META-CANARY (`test_state_snapshot_no_private_attr_access_required`) asserts the contract is in place.

9. **cross-domain helper placement signals scope (Reviewer A A7 from 2026-05-15 morning extended this session).** The `surface_state_payload` helper moved from `tools/hardware_firmware.py` (hw-firmware-specific) to `app/utils/yaml_cache.py` (cross-domain). The helper is generic over `MtimeCachedYamlLoader[Any]` — placement under `app/utils/` invites future consumers (SBOM grype cache, binary-analysis pattern cache, taint analysis YAML loaders per Reviewer C scout — 2-3 candidate sites identified).

## Recommendations Carried Forward

Of the ~25 reviewer findings this session, **~24 remain** as queued follow-up work. Highest-leverage:

1. **Cross-stack alignment test for F-FORENSIC-10 discipline** (Reviewer A MEDIUM) — `cve_matcher._KNOWN_FIRMWARE_NARROWING_FIELDS` + `patterns_loader._parse_banner_cve_pin` family-only check enforce the same conceptual gate at different layers. Add `tests/test_forensic10_alignment.py` synthesizing disclosure-batch entries on each side + asserting both reject. ~50 LOC.

2. **FragAttacks NVD-CPE realignment** (Reviewer B HIGH) — `vendor: broadcom + category: wifi + category_regex: ^wifi$` is over-broad per NVD CPE which lists ONLY Intel + Arista + Linux/IEEE chips. Convert to advisory-only (`cves: []` + `advisory_id: ADVISORY-FRAGATTACKS`) OR add per-vendor `notes:` calling out kernel-class extension. Same applies to the duplicate Qualcomm FragAttacks entry. ~20 LOC YAML changes.

3. **MediaTek modem CVE-2023-20819 missing version gate** (Reviewer B HIGH) — NVD CPE limits to 6 specific modem-OS versions (lr11/lr12a/lr13/nr15/nr16/nr17). Current entry uses `category_regex: ^modem$` only — over-broad. Add `version_regex` requiring modem-OS evidence OR `strict_chipset: true`. Requires modem-version-banner extraction (deferred via inline YAML comment).

4. **wpa_supplicant CVE-2023-52160 over-broad category** (Reviewer B MEDIUM) — NVD CPE attribution is to `w1.fi:wpa_supplicant` binary, not all wifi. Recommend `category: wpa_supplicant` (new category) OR path_regex narrowing.

5. **L4T regex tolerance for stripped formats** (Reviewer C MEDIUM) — current regex requires literal `(release)` token. Some operator-stripped formats omit it. Add fallback regex matching bare `R\d{2,3}\.\d+\.\d+` patterns + document the contract in the parser docstring. ~30 LOC.

6. **F-FORENSIC-10 WARN message clarity** (Reviewer C MEDIUM) — restructure the WARN to lead with the affected entry + a scannable bullet list of fix options. ~20 LOC clarity improvement.

7. **CLAUDE.md note on ceremonial vs genuine narrowing** (Reviewer C MEDIUM) — explain WHEN ceremonial `category_regex: ^<existing>$` is acceptable vs when genuine NVD-derived narrowing is required. Reference the 14 entries deferred this session for future per-CVE NVD-derivation. ~60 LOC documentation.

8. **state_snapshot() adoption: taint_llm YAML loaders** (Reviewer C LOW) — `app/ai/tools/taint_llm.py:78-101` uses `@lru_cache` on YAML-loaders — cold-cache shape (process-lifetime once only). Migrate to `MtimeCachedYamlLoader` for hot-reload. ~30 LOC.

9. **Debian ar L4T extraction post-unblob** (Reviewer C LOW) — when unblob unpacks a `.deb` containing `/etc/nv_tegra_release` (e.g. `nvidia-l4t-bootloader_32.3.1-20191209230245_arm64.deb`), the extracted text file gets `vendor=unknown` and L4T metadata is lost. Add detector-layer check + propagate to firmware-level metadata. ~30 LOC.

10. **NVIDIA wrapper magic + BUP container magic** (deferred from morning session — when BSP install available) — `xxd | head` known mb1.bin / tos.img / .bup files to pin the bytes. Two single-commit extensions activate the 2 deferred subsets (currently handled via 5th fallback).

11. **Tier A archive-suffix additions** (Reviewer C REC-2 from 2026-05-18) — `.7z` / `.tar.zst` / `.zst` / `.deb`. Dockerfile apt deps + small extraction cases. ~50 LOC.

12. **extraction_strategy enum** (Reviewer C CC-2 from 2026-05-18) — replace `extracted_via_shortcut: bool` with `Literal["shortcut_clean", "shortcut_recursed", "unblob"]`.

13. **conftest fixture helper** (Reviewer C CC-4 from 2026-05-18) — `loader_with_tmp_yaml` 8-line wrapper.

14. **Tegra SOC tokens to YAML** (Reviewer C C5 from morning session) — externalize hard-coded Python tuples to a hot-reloadable `tegra_soc_tokens.yaml`.

15. **Carry-forward burden tracking** (Reviewer C MEDIUM) — `.planning/ADAPTIVE_BACKLOG.md` documenting ceremonial narrowings + deferred narrowings + extension-point work. Make carry-forward DISCOVERABLE per session.

## Remaining Work

- Recommendations 1-15 above: ~10-18 hours total.
- Backfill: NONE needed for this session's commits. The L4T extraction is forward-only; existing detections re-run via `detect_hardware_firmware` opportunistically (with the caveat that `on_conflict_do_nothing` requires explicit DELETE for parser-output updates on existing rows — documented as Pattern #7).
- DS1 now reflects 99 blobs detected (63 with l4t_release=R32.3.1; 4 of 6 Tegra CVE pins activated, 2 correctly excluded per NVD scope).
- 14 ceremonial narrowings stand as deferred work for genuine NVD-derived narrowing per recursive verification discipline.
- The 2 deferred Tegra parser TBDs (NVIDIA wrapper magic + BUP container magic) remain on the queue — currently handled via 5th fallback's path inference, but pinned magic would surface the subsets explicitly in `metadata["tegra_blob"]["subset"]`.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 6 (3 feat + 1 fix + 2 activation-gap feat) |
| Files changed | 7 (1 YAML + 3 service code + 3 test files) |
| Lines added | ~1,800 net-new |
| Reverts | 0 |
| New tests | 30 (9 L4T extraction + 5 schema gate + 9 state_snapshot/surface_state_payload + 4 path inference + 3 5th fallback) |
| Cumulative hw-firmware test count | ~198 (was 168 entering this session) |
| New helper function | 3 (`_extract_l4t_release` + `_extract_l4t_release_from_path` + `_has_tegra_path_context` in tegra_blob.py) |
| New public method | 1 (`MtimeCachedYamlLoader.state_snapshot`) |
| New helper moved cross-domain | 1 (`surface_state_payload` from `tools/hardware_firmware.py` to `app/utils/yaml_cache.py`) |
| New schema gate | 1 (F-FORENSIC-10 analog at `_parse_known_firmware_data`) |
| Pre-narrowed YAML entries | 16 (CVE-2017-18159 ×2 chipset_regex Snapdragon-2018-cohort + 14 minimum-impact category_regex) |
| Pre-implementation scout dispatches | 3 (one per TARGET) |
| Post-implementation reviewer dispatches | 3 (arch + forensic + adaptability) |
| Reviewer findings TOTAL | ~25 (4 A + 5 B + 7 C + ~9 from morning session carryover queue) |
| Reviewer findings APPLIED this session | 1 CRITICAL (Reviewer B CVE-2017-18159 chipset_regex tightening) |
| Reviewer findings DEFERRED to follow-up | ~24 |
| Independent NVD WebFetch verifications | 8 (1 implementer-side + 7 Reviewer-B-side across CVE-2017-18159 + 5 sample-checked of the 14 ceremonial-narrowing entries) |
| Activation gaps surfaced via end-to-end verification | 2 (path-inference missing on raw_bin Tegra; magic-byte gate skipping the deferred-TBD subsets) |
| Activation-gap fixup commits | 2 (commits 0a901f2 + 338f95b) |
| Tier 0 BRAKTOOTH baseline rows (G32 / G30 / DPCS10×3) | 26 + 22 + 6 = 54 (UNCHANGED from morning session) |
| Wrong-attribution CVE rows | 0 (post-rebuild confirmed across all 6 firmwares) |
| CVE-2017-18159 baseline rows (post-tightening) | 147 × 5 firmwares (UNCHANGED via soft fallback on NULL chipset_target) |
| DS1 NVIDIA classification (post-clean-re-detect) | 99 blobs total; 63 with `l4t_release=R32.3.1` populated (11 bootloaders + 4 TEE + 6 MCU + 1 DSP + 1 camera + 1 USB + 39 DTB) |
| New Tegra CVE pins firing on DS1 | 4 of 6: CVE-2021-1111 (11 rows), CVE-2021-34372 (4 rows), CVE-2021-34397 (11 rows), CVE-2022-42269 (4 rows). CVE-2019-5680 (post-fix R32.3.1) + CVE-2022-42270 (Xavier-only, DS1 is TX2) correctly didn't fire. |
| Backend + worker + migrator rebuilds | 5 (post-each-feature-commit + post-activation-gap-fixup; Rule #11 smoke confirmed all 3 TARGETs + all helpers + gate behavior) |
| Test runs (cumulative across the session) | 12 (pytest invocations between commits) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-hw-firmware-tegra-activation-2026-05-15.md`
- Morning session postmortem: `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`
- 2026-05-18 prior session: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md`
- 2026-05-17 BT YAML externalization: `.planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md`
- 2026-05-16 BT banner parser: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`

---HANDOFF---
- Postmortem: hw-firmware-tegra-activation-2026-05-15
- Document: .planning/postmortems/postmortem-hw-firmware-tegra-activation-2026-05-15.md
- Failures documented: 5 (1 CRITICAL Reviewer B CVE-2017-18159 chipset_regex over-broad inclusion of post-2018 Snapdragon codenames caught via independent NVD WebFetch; 2 HIGH activation gaps surfaced by end-to-end verification — L4T banner missing from DS1 blob heads requires path-inference fallback; raw_bin Tegra wrappers require 5th magic-byte-bypass fallback; 1 HIGH width-canary pre-implementation audit caught 16-entry scope expansion vs user-prompt's named 1; 1 LOW test fixture isolation gap on state_snapshot summary-raises-canary)
- Safety catches: 8 (pre-implementation 3-parallel scouts + 1 implementer-side NVD WebFetch; recursive NVD-CPE verification — 7 reviewer-side fetches caught 1 CRITICAL chipset_regex drift; pre-implementation width-canary audit caught 16-entry scope expansion; multi-persona reviewer dispatch × 3; Rule #46 paired-canary discipline × 25 new tests; end-to-end DS1 corpus re-detect + cve-match cycle surfaced 2 activation gaps; end-to-end SQL corpus regression check baselines preserved; Rule #25 per-piece commits × 6)
- Recommendations: 15 carried forward (cross-stack F-FORENSIC-10 alignment test; FragAttacks NVD-CPE realignment; MediaTek CVE-2023-20819 version gate; wpa_supplicant CVE-2023-52160 category; L4T regex tolerance; F-FORENSIC-10 WARN clarity; CLAUDE.md ceremonial-vs-genuine narrowing note; taint_llm hot-reload migration; Debian ar L4T extraction; NVIDIA wrapper + BUP magic; Tier A archive suffixes; extraction_strategy enum; conftest fixture helper; Tegra SOC tokens YAML; carry-forward backlog tracking)
- Critical Reviewer B catch: CVE-2017-18159 chipset_regex included post-2018 Snapdragon codenames (bengal/kona/lahaina/waipio/niobe/sun/magpie/moorea/saipan) NOT in NVD CPE scope — fixup tightened to 2018-cohort MSM-family naming only per NVD description "Android for MSM, QRD Android, Firefox OS for MSM" (CAF kernels through 2018-06-05 SPL). 6 sessions running with the multi-persona reviewer pattern catching CVE-attribution drift.
- DS1 (firmware 295eaf7a) activation: 99 blobs detected; 63 with l4t_release=R32.3.1 populated via L4T extraction (content-banner first + path-inference fallback + raw_bin 5th-fallback chain); cve-match inserted 30 NEW CVE rows from 4 of 6 forward-prepared Tegra pins (CVE-2021-1111 / 34372 / 34397 / CVE-2022-42269). CVE-2019-5680 + CVE-2022-42270 correctly excluded per NVD scope. BRAKTOOTH baseline 54 rows + 0 wrong-attribution rows + 147 CVE-2017-18159 rows preserved post-tightening.
- Adaptability deltas shipped: L4T release extraction via 3-stage fallback chain (content-banner + path-inference + raw_bin 5th fallback) end-to-end activates the 6 forward-prepared Tegra CVE pins shipped morning session + F-FORENSIC-10 schema gate analog at the curated tier prevents disclosure-batch antipattern + state_snapshot() public method as abstraction-boundary fix replaces defensive getattr that masked refactor signals + surface_state_payload helper moved cross-domain to app/utils/ inviting reuse from SBOM/binary-analysis/taint-llm caches + recursive NVD-CPE verification discipline extended to chipset_regex enumerated values + 16-entry pre-narrowing pattern preserves all 5,000+ currently-firing CVE rows + content-banner-wins-over-path-inference precedence (Rule #19) + per-component path-context gate prevents whole-path-substring false-positives
---

Run `/learn hw-firmware-tegra-activation-2026-05-15` to extract patterns into the knowledge base.
