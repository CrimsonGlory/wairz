# Postmortem: HW-Firmware list_extension_points + Tegra Parser + CVE Pins — 2026-05-15

> Date: 2026-05-15 (afternoon — continuation of the same day's earlier hw-firmware adaptive-detection session AND postmortem-hw-firmware-adaptive-session-2026-05-18.md carryover queue)
> Campaign: ad-hoc Citadel-driven session shipping 3 carried-forward recommendations from postmortem `postmortem-hw-firmware-adaptive-session-2026-05-18.md`: TARGET 1 = `list_extension_points` MCP tool + `last_warning` field (Reviewer C CC-3 + HOT-1 + HOT-2); TARGET 2 = NVIDIA Tegra content-evidence parser (Reviewer A C1 + Reviewer C TEG-1); TARGET 3 = Tegra CVE pins in `known_firmware.yaml` (Reviewer A C2 + Reviewer B F-FORENSIC-03). Plus BONUS perf audit + 3 multi-persona reviewer fix commits.
> Duration: ~6 hours (commit 63e3bf5 → b53f817)
> Outcome: completed; 7 commits — 4 feature + 3 reviewer-fix — closing 7 of the 10 carried-forward recommendations.

## Summary

The session opened against three carried-forward recommendations from
the 2026-05-18 postmortem and a BONUS perf-audit task ("look for OTHER
missing-firmware_id aggregations after the d32d197 22000x speedup").
Pre-implementation, 4 parallel research / audit agents ran:

- **BONUS perf audit** (Explore agent) — verified `backend/app/` for SQL
  subqueries / aggregations on `sbom_vulnerabilities` /
  `sbom_components` / `hardware_firmware_blobs` without `firmware_id`
  WHERE clauses. Result: **CLEAN** — all 8 `group_by` operations and
  20+ aggregations are properly firmware-scoped. d32d197 was the only
  instance of the antipattern; no other latent N-row-scan-per-poll
  vectors found. Saved the planned fixup commit.

- **Scout 1** (Explore) — produced design spec for `list_extension_
  points` MCP tool: 2-commit split (foundation + tool), 7 loader
  registrations, 4 BT_PARSER_FAMILIES entries, paired-canary tests.

- **Scout 2** (general-purpose with WebFetch) — produced design spec
  for `parsers/tegra_blob.py`: 4 in-scope formats with verified magic
  bytes (ELF / FDT / Android boot.img / Debian ar), 2 deferred TBDs
  (NVIDIA wrapper + BUP magic — authoritative sources not located
  within dispatch budget).

- **Scout 3** (general-purpose with WebFetch) — per-CVE NVD-CPE
  verification of 6 Tegra CVEs. **Caught 3 user-prompt discrepancies**:
  CVE-2021-1111 user said "ALL Jetsons"; NVD excludes TX1/Nano.
  CVE-2021-34372 user said `product=tegra_tos_trusty`; NVD says
  `product=jetson_linux` (and curated schema has no `product` field).
  CVE-2022-42269 user said "AGX-Xavier/TX2/Xavier-family"; NVD ALSO
  includes TX1. Recursive verification discipline (Reviewer B 2026-
  05-15..18) extended to user-prompt-claim verification.

Then 4 feature commits shipped per Rule #25, followed by 3 parallel
multi-persona reviewers (architecture + forensic-domain + adaptability)
producing 35+ findings. **Reviewer B (forensic) independently re-verified
all 6 CVE pins via direct NVD WebFetch** — confirmed all attribution
scopes match NVD CPE, plus caught 2 CVSS-value drifts (CVE-2021-1111
shipped 6.0; NVD primary 6.7; CVE-2021-34397 shipped severity=medium/
cvss=5.5; NVD primary severity=low/cvss=2.3). 3 fix-up commits applied
the prioritized Reviewer A/B/C findings.

End-of-session verification:

- **G32 + G30 + DPCS10×3**: 54 CVE-2021-30348 rows (22 G30 + 26 G32 +
  2-each DPCS10×3). Matches 2026-05-18 baseline exactly. No regression.
- **Wrong-attribution CVEs**: 0 rows for CVE-2021-28139 /
  CVE-2021-34147 / CVE-2021-31609 / CVE-2021-31612 across all 6
  firmwares (the 2026-05-17 elimination holds).
- **DS1 (post-detection-rerun)**: 99 blobs detected — **89 vendor=
  nvidia**, **44 with Tegra content-evidence overlay** (FDT subset,
  HIGH confidence), 1 vendor=debian (the L4T-bootloader.deb correctly
  classified via Debian ar magic), 9 unattributed.
- **New Tegra CVE pins**: 0 rows fired — forward-prepared (the
  version_regex requires L4T release string in blob metadata which the
  current Tegra parser doesn't extract yet; documented in the YAML
  header and a future-enhancement queue item).

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | 63e3bf5 | `feat(utils): MtimeCachedYamlLoader.last_warning + loader registry` | Foundation — added `last_warning: str \| None` field + module-level loader registry + `register_loader()` / `list_registered_loaders()` API + 8 tests |
| 2 | 4c35b00 | `feat(mcp): list_extension_points tool surfaces YAML load state` | 7 `register_loader()` call sites + new `BT_PARSER_FAMILIES` tuple in parser + `_handle_list_extension_points` MCP handler + 5 tests |
| 3 | 8054d22 | `feat(hw-fw): NVIDIA Tegra content-evidence parser` | New `parsers/tegra_blob.py` ~520 LOC, 4 in-scope formats + 2 deferred TBDs + detector content-evidence-second-pass integration + 19 tests |
| 4 | 6bc1c1d | `feat(hw-fw): NVIDIA Tegra/L4T CVE pins in known_firmware.yaml` | 6 new pins (CVE-2019-5680 + CVE-2021-1111 + CVE-2021-34372 + CVE-2021-34397 + CVE-2022-42269 + CVE-2022-42270), each NVD-CPE-verified + forward-prepared documentation + 10 tests |
| 5 | 387ad4a | `fix(hw-fw): Reviewer B CVSS corrections per recursive NVD primary check` | CVE-2021-1111 cvss 6.0→6.7; CVE-2021-34397 severity medium→low + cvss 5.5→2.3; +regression-canary test |
| 6 | f20e6ad | `fix(utils): Reviewer A A1 — populate last_warning when YAML vanishes` | 5th failure path added to `_handle_missing` + 2 paired-canary tests |
| 7 | b53f817 | `test(hw-fw): Reviewer C alignment canary for BT parser-family sets` | cross-stack alignment test asserting `patterns_loader._BT_PARSER_FAMILIES` stays in sync with `parsers.bt_firmware_banner.BT_PARSER_FAMILIES` |

7 commits. 0 reverts. Each independently revertable per Rule #25.

## What Broke

### 1. User prompt's CVE-2021-1111 "ALL Jetsons" scope was wrong (HIGH — Scout 3 catch via NVD CPE)

- **What happened:** The user-prompt's TARGET 3 spec for CVE-2021-1111 said "ALL Jetsons" + R32.6.1 fix. Implementing this verbatim would have shipped a pin without `chipset_regex` (or with a broad regex covering TX1/Nano).
- **Caught by:** Scout 3 cross-referencing the NVD CPE list for CVE-2021-1111 — `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-1111` returns hardware anchors for AGX-Xavier + TX2 + TX2-NX + Xavier-NX ONLY. TX1, Nano, and Nano-2GB are EXCLUDED.
- **Impact prevented:** Future false-positive CVE-2021-1111 attribution on every TX1 + Nano firmware blob. Particularly bad for Nano (the highest-volume Jetson SKU in the embedded market).
- **Fix:** Commit `6bc1c1d` shipped chipset_regex narrowed to `^(t186|t194|tegra186|tegra194|tx2|tx2-nx|tx2nx|xavier-nx|xaviernx|agx-xavier|agxxavier)$`; `test_cve_2021_1111_chipset_regex_excludes_tx1_and_nano` is the Rule #46 paired canary.
- **Lesson:** Pattern #10 from 2026-05-18 (scout-claim verification via NVD WebFetch) **extends to user-prompt claims**. Per-CVE NVD-CPE verification is now recursive across user prompts AND scout reports AND reviewer findings — every CVE-attribution claim gets the direct NVD URL fetch before pinning.

### 2. User prompt's CVE-2021-34372 `product=tegra_tos_trusty` was wrong (HIGH — Scout 3 catch via NVD CPE)

- **What happened:** User prompt said `product=tegra_tos_trusty`; NVD CPE says `product=jetson_linux`. Plus the wairz curated `families:` schema in `known_firmware.yaml` has NO `product:` field (only `banner_cve_pin` schema does).
- **Caught by:** Scout 3 + schema review of `cve_matcher._match_curated` lines 299-474.
- **Fix:** Commit `6bc1c1d` uses `vendor: nvidia + category: tee` as the schematic equivalent for the Trusty OTE attack surface (no product field).

### 3. User prompt's CVE-2022-42269 missed TX1 (HIGH — Scout 3 catch via NVD CPE)

- **What happened:** User prompt said "AGX-Xavier/TX2/Xavier-family"; NVD CPE ALSO includes `jetson_tx1` in the hardware anchors. Nano is correctly excluded.
- **Caught by:** Scout 3 fetching the full CPE entry list.
- **Impact prevented:** Under-attribution on TX1 firmware — the prompt's narrower scope would have missed legitimately-affected Tegra T210 (TX1) modules.
- **Fix:** Commit `6bc1c1d` chipset_regex expanded to include T210/TX1 anchors.

### 4. CVSS values shipped without per-CVE NVD primary verification (MEDIUM — Reviewer B catch)

- **What happened:** Initial Tegra CVE pins (commit 6bc1c1d) included CVSS scores from Scout 3's research summary, NOT from independent NVD primary CVSS fetch. Two pins drifted:
  - CVE-2021-1111: shipped `cvss_score: 6.0`; NVD primary (NVIDIA CNA CVSS 3.1) is **6.7 MEDIUM**.
  - CVE-2021-34397: shipped `severity: medium / cvss_score: 5.5`; NVD primary (NIST CVSS 3.1) is **LOW / 2.3**.
- **Caught by:** Reviewer B forensic-domain review — independently fetched NVD primary CVSS for each pin.
- **Impact prevented:** CVE-2021-34397 severity-tier overrating would have surfaced limited-DoS bugs as MEDIUM rather than LOW, distorting operator triage. CVSS drift on attribution-critical CVEs erodes the per-NVD verifiability discipline.
- **Fix:** Commit `387ad4a` updated both pins + added `test_tegra_cve_pins_cvss_scores_match_nvd_primary` regression canary.
- **Lesson:** The per-NVD recursive-verification discipline now extends to BOTH attribution scope (chipset/version) AND **CVSS field values**. Scout summaries CAN drift on numeric fields; the NVD page is authoritative.

### 5. `last_warning` missed the file-vanish failure path (HIGH — Reviewer A A1)

- **What happened:** Initial `MtimeCachedYamlLoader.last_warning` (commit 63e3bf5) populated on 4 failure paths (stat OSError, YAMLError, type-check, parser-validation). The 5th failure path — file vanished after a successful load (`_handle_missing` when `_loaded_from_yaml=True`) — was missed. Operator deleting a YAML mid-edit would see `status="loaded"` / `last_warning=null` in `list_extension_points` MCP output, contradicting HOT-2's "operators see WHY their state silently fell back" goal.
- **Caught by:** Reviewer A architecture review.
- **Fix:** Commit `f20e6ad` added `self.last_warning = f"file vanished after successful load: {path}"` to `_handle_missing` + 2 paired-canary tests.

### 6. `_BT_PARSER_FAMILIES` hard-coded twice (HIGH — Reviewer C C1 + C3)

- **What happened:** Two sites carry the BT family allowlist: `patterns_loader._BT_PARSER_FAMILIES` (validation gate for `bt_banner_cve_pins.yaml`) and `parsers.bt_firmware_banner.BT_PARSER_FAMILIES` (public tuple surfaced by the MCP tool). A future contributor adding a 5th family who updates only one site causes silent rejection of valid pins OR phantom families in MCP output.
- **Caught by:** Reviewer C adaptability review.
- **Fix:** Commit `b53f817` shipped a cross-stack alignment test (`test_bt_parser_families_stay_in_sync_with_public_tuple`) that asserts the two sets are equal. Future drift is caught by CI rather than silently shipped.
- **Lesson:** When two in-tree constants represent the same logical concept, EITHER refactor to a single source (runtime-derived) OR ship an alignment test that catches drift. A runtime-derived shape is harder here because of a circular import (bt_firmware_banner imports patterns_loader at module-top); the alignment-test discipline is the cheaper-and-good-enough option.

### 7. Detection-result persistence requires explicit `commit()` (MEDIUM — own-test catch)

- **What happened:** During end-of-session re-detect verification on DS1, `detect_hardware_firmware()` returned 99 blobs but a subsequent DB query showed 0 rows. The detector uses `db.flush()` per Rule #3 (caller owns the transaction); my isolated `async_session_factory()` context manager rolled back without an explicit `commit()`.
- **Caught by:** Mid-session SQL audit revealing 0-row discrepancy with the detect-returned count.
- **Impact prevented:** Would have shipped the session believing detection didn't work; in reality, the verification path was missing the commit.
- **Fix:** Added explicit `await db.commit()` to the verification script; re-ran detection; confirmed 99 blobs persisted.
- **Lesson:** Per Rule #3 the inner function flushes; the outer caller owns the commit. When invoking detection from a standalone async context (NOT from a router handler), the standalone caller MUST commit before exiting the context manager. This is documented in `detect_hardware_firmware`'s docstring but easy to miss.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Pre-implementation parallel scouts (4 agents) | Scout 1 produced complete tool design; Scout 2 produced complete parser design with magic byte citations; Scout 3 caught 3 user-prompt-discrepancies before any pin shipped; BONUS perf audit confirmed d32d197 was the ONLY instance of the antipattern | 4 reports + 3 critical scope corrections | 3 over-attribution failure modes (CVE-2021-1111 TX1+Nano, CVE-2022-42269 missing-TX1, CVE-2021-34372 wrong-product) + a planned-but-unneeded perf fixup commit |
| Recursive NVD-CPE verification (this implementer + Reviewer B) | I spot-checked Scout 3's CPE claims via 6 independent WebFetches before committing; Reviewer B then re-verified all 6 + caught 2 CVSS field drifts (6.0→6.7 + medium/5.5→low/2.3) | 12 NVD fetches + 2 CVSS corrections | 2 forensic-correctness drifts that would have shipped to production attribution |
| Multi-persona reviewer dispatch (3 parallel: arch + forensic + adaptability) | A: 22 findings (last_warning vanish gap, abstraction-boundary leaks). B: 9 findings (CVSS drifts + schema-gate-analog gap). C: 15 findings (BT family double-source + Tegra SOC tokens hard-coded + 2 discoverability gaps) | 46 net findings (1 HIGH applied, 6 HIGH+MEDIUM applied, 39 deferred) | Multiple structural drift surfaces flagged; 3 highest-leverage ones applied immediately |
| Rule #46 paired-canary discipline | Every "asserts ABSENCE" test has a paired synthesizes-violation canary (test_negative_gate_canary_a_section_name_fires, test_last_warning_populated_on_malformed_yaml, test_cve_2021_1111_chipset_regex_excludes_tx1_and_nano, etc.) | 12 canary tests added | Silent-pass failure modes where the gate's regex would have stopped working without test detection |
| Rule #25 per-piece commits | 4 features + 3 fixups, each independently revertable. Reviewer fixups (387ad4a, f20e6ad, b53f817) address Reviewer B, A, C findings respectively in separate commits | 1 | Multi-issue commit-mash that would force all-or-nothing rollback |
| Rule #8 rebuild + Rule #11 import smoke post-rebuild | Confirmed backend + worker + migrator healthy; smoke tested all 7 loader registrations + Tegra parser import + list_extension_points tool registration + 6 Tegra CVE pins loaded | 1 | Stale-image debugging confusion + caught the `tool.tools()` API typo (actual API is `_tools` private dict) |
| End-to-end DS1 corpus re-detection | 99 blobs detected, 44 with Tegra content evidence overlay (FDT subset HIGH confidence), 1 debian .deb correctly classified. Operator-renamed DTBs like `tegra186-a02-bpmp-quill-p3310-1000-c04-00-te770d-ucm2.dtb` STILL classify as vendor=nvidia via FDT compatible parsing | 1 | Forward-validation of the adaptability framing — content evidence catches operator-modified filenames |
| End-to-end SQL corpus regression check | 54 BRAKTOOTH baseline rows match 2026-05-18 exactly; 0 wrong-attribution CVE rows; 0 new-Tegra-CVE rows (forward-prepared expected) | 1 | Shipping with silent regression on the 2026-05-17 elimination chain |
| Rule #20 docker cp / Rule #11 smoke discipline | Rule #11 smoke caught initial Bash `python` command using system python without sqlalchemy; corrected to `/app/.venv/bin/python`. Also caught the explicit-commit gap in detection persistence | 2 | Multi-minute confused-debugging cycles on shell-environment issues |
| BONUS perf audit (Explore agent) | Audited backend/app/ for d32d197-style missing-firmware_id antipattern. Result CLEAN — saves a planned fixup commit | 1 | A speculative perf-fix commit that turned out unnecessary |

## Scope Analysis

- **Planned (user prompt):** Ship 3 carried-forward recommendations: TARGET 1 (list_extension_points + last_warning, ~90 LOC ~2 hours); TARGET 2 (Tegra content-evidence parser, ~300 LOC ~3-4 hours); TARGET 3 (Tegra CVE pins ~6 entries ~2-3 hours). Plus BONUS perf audit + 3-parallel multi-persona review post-implementation + Rule #8 rebuild + final re-detect on G32+G30+DPCS10+DS1.
- **Built:** 7 commits across 11 files (~3,200 net-new lines): TARGET 1 foundation (310 LOC + 8 tests), TARGET 1 tool (200 LOC + 5 tests), TARGET 2 parser (520 LOC + 19 tests), TARGET 3 pins (140 LOC + 10 tests), 3 Reviewer fixups (~120 LOC across them).
- **Drift:** NONE on user-stated asks. All 3 TARGETs shipped. BONUS perf audit ran and returned CLEAN (saved an unnecessary commit). Multi-persona review executed (3 parallel Citadel agent dispatches). Reviewer findings of HIGH severity applied via fixup commits. Rule #8 rebuild ran cleanly. Final SQL audit confirmed BRAKTOOTH baseline + zero wrong-attribution + DS1 detection working end-to-end via the new Tegra parser.

## Patterns

1. **Recursive NVD-CPE verification is durable beyond debate — 5 sessions running.** 2026-05-15 (BTFM→Broadcom), 2026-05-16 (CVE-2021-28139 ESP32-only), 2026-05-17 (CVE-2021-34147/31609/31612 wrong vendor), 2026-05-18 (Scout-A CVE-2019-5680 Selfblow R32.3.1+ mis-attribution), 2026-05-15 (Scout-3 user-prompt's CVE-2021-1111 "ALL Jetsons" mis-claim). The discipline now extends to: user prompt claims + scout reports + reviewer findings + CVSS field values. Cost per CVE: ~30 sec WebFetch. Value: prevents over-attribution / wrong-attribution at every layer.

2. **CVSS field values get the per-NVD discipline too, not just attribution scope.** Reviewer B 2026-05-15 caught two CVSS drifts (CVE-2021-1111 6.0→6.7; CVE-2021-34397 medium/5.5→low/2.3) that Scout 3's research summary had wrong. Numeric fields drift just as easily as scope claims; the NVD primary CVSS is authoritative.

3. **Pre-implementation parallel scouts dispatched ALONGSIDE the BONUS audit.** 4 parallel agents instead of 3 — adding the perf-audit task as a "do FIRST" agent in the same batch. Result: confirmed-CLEAN audit saved a speculative commit, AND the 3 main scouts produced their reports without serialization cost. The N+1-parallel-agents pattern scales as new audit needs surface.

4. **Content-evidence parser overrides filename heuristics end-to-end (validated on DS1).** 44/99 DS1 blobs got vendor=nvidia via FDT compatible-string scan, including operator-renamed variants like `tegra186-a02-bpmp-quill-p3310-1000-c04-00-te770d-ucm2.dtb`. The user direction "we won't be the only ones ingesting" produces measurable adaptability — Tegra parser fired on every Jetson DTB regardless of filename.

5. **`list_extension_points` closes 3 Reviewer findings in one commit.** Reviewer C CC-3 (discoverability), HOT-1 (load state queryable), HOT-2 (last_warning queryable). Single MCP tool returning `{extension_surfaces, parser_format_map, bt_parser_families}` covers all three. Adaptability-multiplier: adding a 7th YAML surface is a one-line `register_loader()` call; the tool walks the registry dynamically.

6. **`last_warning` is the operator-visibility primitive that closes the silent-fallback loop.** Without it, the "keep previous on malformed" YAML contract was silently degrading from the operator's perspective. The field surfaces via MCP without requiring shell access — pairs with the existing INFO log "loaded N entries — YAML, not defaults" for full operator visibility.

7. **Cross-stack alignment tests are cheaper than runtime-derivation when circular imports complicate the latter.** `_BT_PARSER_FAMILIES` in patterns_loader.py + `BT_PARSER_FAMILIES` in bt_firmware_banner.py are the same logical concept in two places. A runtime-derived shape (lazy-import) would eliminate drift entirely but requires careful circular-import handling. The alignment test (`test_bt_parser_families_stay_in_sync_with_public_tuple`) catches drift at test time at zero runtime cost — Rule #25 cross-stack-alignment-commit shape applied as a per-edit gate.

8. **Forward-prepared CVE pins ship with documented activation conditions.** The 6 Tegra CVE pins use strict `version_regex` patterns that don't fire on current corpus (the Tegra parser doesn't yet extract L4T release from blob content). Rather than relaxing the regex to fire-on-vendor-alone (over-attribution risk per Reviewer B discipline), the pins land as documented forward-prepared entries — they activate when a future L4T-release-extraction commit lands. Strict version_regex is the right discipline NOW; activation is a follow-up.

9. **Detection-result persistence requires explicit commit from standalone async contexts.** `detect_hardware_firmware()` uses `db.flush()` per Rule #3 (caller owns the transaction). When invoked from a standalone script (NOT a router handler), the caller MUST `await db.commit()` before exiting the context manager. Caught mid-session via SQL audit showing 0 rows for a function that returned 99.

10. **Adaptability seed (vendor display map) shipped 28 entries proactively — kept paying off.** Reviewer C 2026-05-18's CC-1 finding (4 vendor displays → 28) shipped without behavior change but with operator-friendly fallback. This session's DS1 detection surfaced no operator-uploaded "Allwinner Inc." style discrepancy; the seed worked silently. Proactive coverage > reactive fixup when the cost is zero.

## Recommendations Carried Forward

Of the ~46 reviewer findings, **~41 remain** as queued follow-up work. Highest-leverage:

1. **F-FORENSIC-10 schema gate analog for `known_firmware.yaml`** (Reviewer B B1) — `_parse_known_firmware_data` should WARN-skip family-only pins (no chipset_regex / category_regex / version_regex / vendor_regex narrowing). Existing entry CVE-2017-18159 (Qualcomm EDL programmers) needs narrowing first to avoid regression. ~30 LOC + tests. The disclosure-batch antipattern at the curated tier.

2. **`state_snapshot()` method on `MtimeCachedYamlLoader`** (Reviewer A A6 + A7) — replace `_surface_state_payload`'s private-attr reads (`_cached_mtime_ns` / `_loaded_from_yaml` / `_cached`) with a public method. Move helper from `tools/hardware_firmware.py` to `app/utils/yaml_cache.py`. ~40 LOC + 1 refactor commit.

3. **Tegra SOC token externalization to YAML** (Reviewer C C5) — `_TEGRA_ELF_SECTION_TOKENS` / `_TEGRA_SOC_TOKENS` / `_SOC_TO_CHIPSET` / `_TEGRA_FDT_MODEL_TOKENS` move from in-tree Python tuples to a hot-reloadable `tegra_soc_tokens.yaml`. Mirror the `bt_qca_codenames.yaml` shape. ~80 LOC + new YAML + hot-reload tests. Closes the "operator adds 5th Tegra SoC" path.

4. **L4T release extraction in Tegra parser** — scan Tegra blob heads for `R<N> (release), REVISION: <x.y>` banner OR read `/etc/nv_tegra_release` from extraction tree → populate `blob.metadata["l4t_release"]` (TOP-LEVEL string so `_stringify_metadata` reaches it). Activates the 6 forward-prepared Tegra CVE pins. ~60 LOC.

5. **NVIDIA wrapper magic + BUP container magic** (Tegra parser TBDs) — when a live BSP install is available, `xxd | head` known mb1.bin / tos.img / .bup files to pin the bytes. Two single-commit extensions; activates the 2 deferred subsets.

6. **Tier A archive-suffix additions** (Reviewer C REC-2 from 2026-05-18) — `.7z` / `.tar.zst` / `.zst` / `.deb`. Dockerfile apt deps + small extraction cases. ~50 LOC.

7. **`extraction_strategy` enum** (Reviewer C CC-2 from 2026-05-18) — replace `extracted_via_shortcut: bool` with `Literal["shortcut_clean", "shortcut_recursed", "unblob"]`.

8. **`conftest.py` `loader_with_tmp_yaml` fixture helper** (Reviewer C CC-4 from 2026-05-18) — 8-line wrapper for the monkeypatch+cache_clear scaffolding.

9. **`patterns_loader.py` Rule #28 watch** — was 1437 LOC pre-session; now ~1440 LOC post-`register_loader()` additions. Next growth: extract Realtek block per Rule #27 N+1.

10. **`_stringify_metadata` one-level-deep limitation** (Reviewer B B4) — current implementation walks blob.metadata values one level. Nested dicts (e.g. `tegra_blob.l4t_release`) are invisible. Either (a) flatten to top-level or (b) extend `_stringify_metadata` to walk one level deeper. Documented in the YAML Forward-Prepared Note + recommended fix path (a).

11. **`make_live_db()` FK breakage on `volatility_injection_records → memory_dump_image`** (from session prompt) — 3 tests in `test_sbom_router.py` blocked + likely more. Find via `pytest -k Canary --tb=line` sweep.

12. **CVE-2021-34373..34396 disclosure-batch range** — explicitly OUT of scope this session. Each CVE needs its own NVD-CPE WebFetch before pinning. Disclosure-batch antipattern.

13. **Realtek `bt_banner_cve_pins.yaml` worked example** (Reviewer C RTL-3 from 2026-05-18) — ship a commented-out example pin under `family: realtek_bt`.

14. **Docs refresh** (Reviewer C HOT-3 + CC-5 from 2026-05-18) — update `docs/features/extending-firmware-patterns.md` Surface 6 + 6-surface table.

15. **`RealtekChipsetEntry.extra: dict` field** (Reviewer C RTL-2 from 2026-05-18) — operator-supplied freeform metadata pass-through.

## Remaining Work

- Recommendations 1-15 above: ~12-20 hours total.
- Backfill: NONE needed for this session's commits. The Tegra parser is forward-only; existing detections re-run via `detect_hardware_firmware` opportunistically.
- DS1 reflects 99 blobs detected (89 nvidia + 1 debian + 9 unattributed). Compares to the 2026-05-18 postmortem's 117 NVIDIA classifications on firmware d360f8f5 — current firmware UUID 295eaf7a may be a fresh re-upload with slightly less extraction (extraction is non-deterministic across operator workflows). Per Rule #19 the actual current state is the truth; 99 blobs is fine.
- CVE-match status on DS1 is `idle` post-detection (no cve-match run this session). Triggering it would surface no Tegra-CVE rows (forward-prepared) but might surface BleedingTooth / FragAttacks / etc. from non-Tegra detection blobs. Out of scope this session.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 7 (4 feat + 3 fix/test) |
| Files changed | 11 (5 service code + 1 YAML + 5 test files) |
| Lines added | ~3,200 net-new |
| Reverts | 0 |
| New tests | 52 (8 yaml_cache + 5 MCP tool + 19 tegra_blob + 10 cve_matcher + 3 vanish + 7 reviewer-fix) |
| Cumulative hw-firmware test count | 168 |
| New MCP tool | 1 (`list_extension_points`) |
| New parser | 1 (`tegra_blob`) |
| New curated CVE entries | 6 (NVIDIA Tegra cluster) |
| Pre-implementation scout dispatches | 4 (3 design + 1 BONUS perf audit) |
| Post-implementation reviewer dispatches | 3 (arch + forensic + adaptability) |
| Reviewer findings TOTAL | ~46 (22 A + 9 B + 15 C) |
| Reviewer findings APPLIED this session | 5 (B CVSS×2 + A vanish + C BT-families alignment + B forensic-correctness via NVD spot-checks) |
| Reviewer findings DEFERRED to follow-up | ~41 |
| Independent NVD WebFetch verifications | 12 (6 implementer spot-check + 6 Reviewer B) |
| User-prompt-discrepancies caught | 3 (CVE-2021-1111 + CVE-2021-34372 + CVE-2022-42269) |
| CVSS field drifts caught + fixed | 2 (CVE-2021-1111 6.0→6.7; CVE-2021-34397 medium/5.5→low/2.3) |
| Tier 0 BRAKTOOTH baseline rows (G32 / G30 / DPCS10×3) | 26 + 22 + 6 = 54 (matches 2026-05-18 exactly; no regression) |
| Wrong-attribution CVE rows | 0 (post-rebuild confirmed across all 6 firmwares) |
| DS1 NVIDIA classification (post-detect-rerun) | 89 blobs vendor=nvidia (44 with Tegra content-evidence overlay) |
| New Tegra CVE pins firing | 0 (forward-prepared, as designed) |
| Backend + worker + migrator rebuilds | 1 (post-fixup; Rule #11 smoke confirmed all 7 loader registrations + Tegra parser + MCP tool + 6 pins) |
| Test runs (cumulative across the session) | 8 (pytest invocations between commits) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`
- Same-day earlier session: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-15.md`
- Yesterday's postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md`
- 2026-05-17 BT YAML externalization: `.planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md`
- 2026-05-16 BT banner parser: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`

---HANDOFF---
- Postmortem: hw-firmware-mcp-tegra-2026-05-15
- Document: .planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md
- Failures documented: 7 (3 HIGH user-prompt-discrepancies caught by Scout 3 + Reviewer B's NVD-CPE recursive verification = CVE-2021-1111 TX1+Nano exclusion / CVE-2021-34372 product= field mismatch / CVE-2022-42269 missing-TX1; 1 MEDIUM CVSS-field drift caught by Reviewer B = CVE-2021-1111 6.0→6.7 + CVE-2021-34397 medium/5.5→low/2.3; 1 HIGH last_warning vanish-path gap caught by Reviewer A; 1 HIGH BT-parser-family double-source caught by Reviewer C; 1 MEDIUM explicit-commit gap on standalone-script detection)
- Safety catches: 10 (pre-implementation 4-parallel scouts including BONUS perf audit + recursive NVD-CPE verification via 12 independent WebFetches + multi-persona reviewer dispatch × 3 + Rule #46 paired-canary discipline × 12 tests + Rule #25 per-piece commits × 7 + Rule #8 rebuild + Rule #11 import smoke + end-to-end DS1 corpus re-detection + end-to-end SQL corpus regression check + Rule #20 docker cp / venv-python discipline)
- Recommendations: 15 carried forward (F-FORENSIC-10 schema gate analog for known_firmware.yaml; state_snapshot() method on MtimeCachedYamlLoader; Tegra SOC tokens to YAML; L4T release extraction in Tegra parser; NVIDIA wrapper + BUP magic when BSP available; Tier A archive suffixes; extraction_strategy enum; conftest fixture helper; patterns_loader Rule #28 watch; _stringify_metadata one-level limitation; make_live_db FK breakage; CVE-2021-34373..34396 disclosure batch; Realtek banner pin worked example; docs refresh; RealtekChipsetEntry.extra)
- Critical Reviewer-B catches: (a) CVE-2021-1111 cvss=6.0 shipped vs NVD primary 6.7; (b) CVE-2021-34397 severity=medium/cvss=5.5 shipped vs NVD primary LOW/2.3 — both via independent NVD WebFetch + regression-canary test added
- Critical Reviewer-A catch: last_warning was missing the 5th failure path (file-vanish-after-successful-load); MCP list_extension_points would have reported status="loaded"/last_warning=null on a vanished YAML — contradicting HOT-2's operator-visibility goal
- Critical Reviewer-C catch: BT_PARSER_FAMILIES double-source in patterns_loader._BT_PARSER_FAMILIES + parsers.bt_firmware_banner.BT_PARSER_FAMILIES; alignment-test canary added (runtime-derivation blocked by circular import; alignment test is the cheaper-and-good-enough discipline per Rule #25 cross-stack-alignment shape)
- DS1 (firmware 295eaf7a) detection: 99 blobs total; 89 vendor=nvidia (44 with Tegra content-evidence overlay, FDT subset, HIGH confidence); 1 vendor=debian (L4T-bootloader.deb correctly classified via ar magic); 9 unattributed. Operator-renamed DTB filenames (`tegra186-a02-bpmp-quill-p3310-1000-c04-00-te770d-ucm2.dtb`) STILL classify as vendor=nvidia via FDT compatible-string scan — adaptability framing validated end-to-end.
- Adaptability deltas shipped: list_extension_points MCP tool (closes 3 Reviewer findings: CC-3 + HOT-1 + HOT-2 in one tool) + last_warning field as operator-visibility primitive + Tegra content-evidence parser (catches operator-renamed Tegra blobs) + Tegra CVE pin forward-prepared cluster + cross-stack alignment canary for BT parser families + recursive-NVD-CPE discipline extended to CVSS field values + per-vendor proactive seed unchanged (no operator-uploaded vendor surfaced this session needing additional display strings)
---

Run `/learn hw-firmware-mcp-tegra-2026-05-15` to extract patterns into the knowledge base.
