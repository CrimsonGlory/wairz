# Patterns: HW-Firmware list_extension_points + Tegra Parser + CVE Pins — 2026-05-15

> Extracted: 2026-05-15
> Campaign: ad-hoc Citadel-driven session shipping 3 carried-forward recommendations from postmortem 2026-05-18
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`

## Successful Patterns

### 1. Recursive NVD-CPE verification extends to user-prompt claims
- **Description:** The 2026-05-18 session established that scout reports get per-CVE NVD verification (Pattern #10). This session EXTENDED the discipline to user-prompt CVE claims — every byte of the user's TARGET 3 spec was treated as a candidate to verify against NVD. Scout 3 caught 3 user-prompt discrepancies (CVE-2021-1111 "ALL Jetsons" was wrong; CVE-2021-34372 product= was wrong; CVE-2022-42269 missing TX1). Reviewer B then re-verified all 6 pins independently and caught 2 CVSS-field drifts.
- **Evidence:** 12 independent NVD WebFetches across this session (6 implementer spot-check + 6 Reviewer B); 3 user-prompt discrepancies + 2 CVSS drifts caught. Cost ~3 minutes total; value: 5 forensic-correctness drifts that would have shipped to production attribution.
- **Applies when:** Any session pinning CVE attributions. The recursive-verification discipline is now durable beyond debate (5 sessions running: BTFM→Broadcom 2026-05-15, CVE-2021-28139 ESP32-only 2026-05-16, CVE-2021-34147/31609/31612 wrong-vendor 2026-05-17, CVE-2019-5680 Selfblow R32.3.1+ 2026-05-18, user-prompt CVE-2021-1111 ALL-Jetsons 2026-05-15-PM). Discipline targets: user prompts + scout reports + reviewer findings + CVSS field values + vendor advisories + LLM summaries. NVD CPE list + NVD primary CVSS score are the authoritative sources; everything else is a candidate.

### 2. CVSS field values get the per-NVD discipline alongside attribution scope
- **Description:** Reviewer B 2026-05-15 caught two CVSS drifts (CVE-2021-1111 cvss=6.0 shipped vs NVD primary 6.7; CVE-2021-34397 severity=medium/cvss=5.5 shipped vs NVD primary LOW/2.3) that Scout 3's research summary had wrong. CVSS-field accuracy matters for operator triage — severity-tier overrating distorts which findings get attention first. The per-NVD primary-fetch discipline applies to ALL numeric fields, not just the attribution scope.
- **Evidence:** Commit `387ad4a` shipped the corrections + `test_tegra_cve_pins_cvss_scores_match_nvd_primary` regression-canary test that fails fast on any future CVSS drift.
- **Applies when:** Any session pinning CVE attribution with severity/CVSS. The NVD page's "CVSS V3 Metrics" section is the primary source; scout reports often summarize the value but can drift by 0.7+ points.

### 3. Pre-implementation N+1-parallel-agents pattern (3 design scouts + 1 BONUS audit)
- **Description:** Previous sessions ran 3 parallel scouts. This session added a BONUS perf-audit agent in the SAME parallel batch (4 agents total). The audit confirmed the d32d197 perf hot-fix antipattern doesn't exist elsewhere in `backend/app/` (clean!), AND the 3 main scouts produced their design specs without serialization cost. The N+1 pattern scales as new audit/verification needs surface mid-campaign.
- **Evidence:** Single Bash batch of 4 Agent dispatches + 1 path-survey ran in parallel; all 4 agents returned cleanly within ~6 minutes wall-clock. BONUS audit returned CLEAN, saving a planned perf-fixup commit.
- **Applies when:** Any session where multiple independent research / audit tasks can be ordered for the same wave. Adding a new agent to an existing parallel batch is zero marginal cost as long as the task surface is independent. The pattern scales — N+1 → N+2 → N+3 as the campaign-shape grows.

### 4. Content-evidence parser end-to-end validation on a real operator-modified corpus
- **Description:** The Tegra content-evidence parser shipped 4 in-scope formats (ELF + FDT + Android boot.img + Debian ar). End-to-end validation on DS1 confirmed 44/99 blobs got vendor=nvidia via FDT compatible-string scan, INCLUDING operator-renamed variants like `tegra186-a02-bpmp-quill-p3310-1000-c04-00-te770d-ucm2.dtb`. The user direction "we won't be the only ones ingesting" produced MEASURABLE adaptability — content evidence catches operator-modified filenames.
- **Evidence:** Live DS1 re-detection on firmware UUID 295eaf7a returned 99 blobs (89 vendor=nvidia, 44 with `metadata->'tegra_blob'->>'subset'='fdt'` + `confidence='high'`, 1 vendor=debian for the L4T bootloader .deb). Real Tegra DTB filenames like `tegra186-quill-p3310-1000-c03-00-base.dtb` AND modified variants `DS1.2-jetson-tx2-cot.tegraflash.tar.gz_extracted/tegra186-a02-...` BOTH classified correctly.
- **Applies when:** Adding any new content-evidence parser. Validate on a real firmware corpus (NOT synthetic fixtures only) — operator-modified inputs surface edge cases that synthetic tests miss. The "feed real data through the parser + SQL-query the result" is a Rule #35b live-canary specifically for new parser shipments.

### 5. Single MCP tool closing multiple Reviewer findings via dynamic enumeration
- **Description:** `list_extension_points` MCP tool closes 3 deferred Reviewer C findings in ONE commit: CC-3 (discoverability) + HOT-1 (load state queryable) + HOT-2 (last_warning queryable). The tool returns `{extension_surfaces, parser_format_map, bt_parser_families}` from a global yaml_cache registry + PARSER_REGISTRY walk + the `BT_PARSER_FAMILIES` public tuple — adding a 7th YAML surface is a one-line `register_loader()` call; the tool surfaces it dynamically without code changes.
- **Evidence:** Commit `4c35b00` shipped 7 `register_loader()` call sites + the MCP handler. The tool's output is generated dynamically at call time from registry state — no hard-coded surface list anywhere.
- **Applies when:** Any operator-extension surface where multiple Reviewer findings cluster around discoverability + load-state + error-visibility. A single dynamic-enumeration tool closes all three together at lower cost than three separate tools.

### 6. `last_warning` field as operator-visibility primitive for "keep previous" contracts
- **Description:** `MtimeCachedYamlLoader.last_warning: str | None` populates on every failed reload path (5 total: stat OSError + YAMLError + type-check + parser-validation + file-vanish) with a one-line "<ExceptionType>: <message>" string. Clears on successful reload + `cache_clear()`. Surfaced via `list_extension_points` MCP tool — operators see WHY their YAML state silently fell back to the previous valid load WITHOUT shell access.
- **Evidence:** Commit `63e3bf5` shipped the foundation + 8 tests. Commit `f20e6ad` (Reviewer A A1 fix) added the 5th failure path (file-vanish). End-to-end test confirms malformed-YAML → last_warning populated; valid restore → last_warning cleared.
- **Applies when:** Any cache-on-write data file with a "keep previous on malformed" contract. The field surfaces the silent-fallback state to operators at near-zero implementation cost. Pairs with the existing per-load INFO log for full visibility.

### 7. Cross-stack alignment tests are cheaper than runtime-derivation when circular imports complicate the latter
- **Description:** `_BT_PARSER_FAMILIES` in `patterns_loader.py` (YAML validation gate) + `BT_PARSER_FAMILIES` in `parsers.bt_firmware_banner.py` (public tuple surfaced by MCP) are the same logical concept in two places. A runtime-derived shape (lazy-import) would eliminate drift entirely but requires careful circular-import handling (bt_firmware_banner imports patterns_loader at module-top for codename/pin/chipset accessors). The alignment-test discipline catches drift at test time at zero runtime cost — pin-test-CI fail with clear remediation hint.
- **Evidence:** Commit `b53f817` shipped `test_bt_parser_families_stay_in_sync_with_public_tuple` asserting `PL._BT_PARSER_FAMILIES == frozenset(f["family"] for f in BT_PARSER_FAMILIES)`. The MCP-tool side of the equation ALREADY uses single-source (imports from bt_firmware_banner at function-body top) — the canary covers the validation-gate side.
- **Applies when:** Any two in-tree constants representing the same logical concept where runtime-derivation is blocked by import structure. Rule #25 cross-stack-alignment-commit shape applied as a per-edit gate — drift is caught at CI before it reaches production.

### 8. Forward-prepared CVE pins ship with documented activation conditions
- **Description:** The 6 Tegra CVE pins use strict `version_regex` patterns that don't fire on the current corpus (the Tegra parser doesn't yet extract L4T release from blob content). Rather than relaxing to fire-on-vendor-alone (over-attribution risk per Reviewer B discipline), the pins land as DOCUMENTED forward-prepared entries — they activate when a future L4T-release-extraction commit lands. The YAML header carries an explicit "Forward-Prepared Note" explaining the activation condition. Strict version_regex is the right discipline NOW; activation is a follow-up.
- **Evidence:** Commit `6bc1c1d` shipped the 6 pins; end-of-session DS1 detection confirmed 0 rows fired (as designed). The notes field in each pin cites the NVD URL; the section header documents the activation path and the L4T-release-extraction prerequisite.
- **Applies when:** Any CVE attribution where the version-discriminator data isn't yet extracted from blob content. Better to ship strict-but-currently-silent than relaxed-and-over-attributing. The forward-prepared documentation is the operator-visible contract.

### 9. Detection-result persistence requires explicit commit from standalone async contexts
- **Description:** `detect_hardware_firmware()` uses `db.flush()` per Rule #3 (caller owns the transaction). When invoked from a standalone script (NOT a router handler), the caller MUST `await db.commit()` before exiting the context manager. The SQLAlchemy AsyncSession's `async with` context auto-rolls-back on exit without commit.
- **Evidence:** Caught mid-session — DS1 re-detection returned 99 blobs but SQL query showed 0 rows. Adding `await db.commit()` to the standalone script + re-running confirmed persistence.
- **Applies when:** Any one-off async script invoking flush-using functions. Documented in `detect_hardware_firmware`'s docstring; the discipline is "if you're outside a router, you commit". Pairs with Rule #3 (flush vs commit semantics) — both edges of the same contract.

### 10. Adaptability seed maps keep paying off invisibly
- **Description:** The 28-entry vendor display map shipped 2026-05-18 (Reviewer C CC-1 fix) added proactive coverage for 24 vendors beyond the initial 4. This session's DS1 detection surfaced no operator-uploaded "Allwinner Inc."-style discrepancy — the seed map worked silently. Proactive coverage > reactive fixup when the cost is zero (display strings only, no behavior change).
- **Evidence:** No bug surfaced in this session's DS1 detection requiring additional vendor displays. The 2026-05-18 seed worked.
- **Applies when:** Any data-only proactive coverage (display strings, fallback values, default registrations) where zero behavior changes. Ship broad-as-reasonable upfront; reactive narrowing is cheaper than reactive widening.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| `last_warning` as a simple `str \| None` field, not a structured object | Operator visibility goal is "one line message I can read in MCP output". Structured objects (timestamp + exception class + line number) over-engineer the surface. | Worked. 5 populating sites + 2 clearing sites; ~120 LOC total. |
| Two-commit split for TARGET 1 (foundation + tool) | Per Rule #25, registering loaders is a separate slice from adding the tool. Foundation must land first so the tool has something to walk. | Worked. Bisect-clean against either commit. |
| Single-commit ship for TARGET 2 (parser + detector integration + tests) | Per Rule #25 cross-stack-alignment exception, the parser + integration + tests are jointly the slice that makes the test pass. Splitting would leave bisect on a half-functional state. | Worked. 19 tests pass; 82/82 detector+parsers+tegra regression check clean. |
| Forward-prepared Tegra CVE pins with strict version_regex (vs relaxed firing) | Strict version_regex doesn't fire on current corpus (forensic correctness — no false positives). Relaxing would over-attribute (Reviewer B discipline). Activation deferred to a future L4T-release-extraction commit. | Worked. 0 rows fired post-rebuild; pin shape documents activation conditions clearly. |
| BT_PARSER_FAMILIES alignment test rather than runtime-derivation | Runtime-derivation blocked by circular import; alignment test catches drift at CI. Cheaper-and-good-enough. | Worked. Single test, ~25 LOC + clear remediation hint when drift detected. |
| 4 reviewer-fix candidates → apply 3 (B-CVSS + A-vanish + C-alignment) | Schema-gate analog (B1) requires pre-narrowing existing CVE-2017-18159 entry to avoid regression — deferred to a follow-up commit. The 3 applied are highest-leverage at zero-regression cost. | Worked. Per Rule #25, 3 fixup commits one-per-persona; schema-gate deferred without losing forensic discipline (NVD-CPE recursive verification is still applied at the per-CVE level). |
| Explicit `db.commit()` for standalone-script detection | The flush-vs-commit semantics put commit-ownership on the caller. Standalone scripts ARE the caller. | Worked. End-to-end DS1 detection persisted 99 blobs after the explicit-commit addition. |
| Cite NVD URLs in CVE-pin notes field | Verifiability discipline — operators auditing a pin can re-verify against NVD without leaving the YAML. Mirrors the H2 yaml extension guide's per-load INFO log + last_warning surface visibility-by-default goal. | Worked. `test_tegra_cve_pins_carry_nvd_url_reference` asserts every Tegra pin notes field contains the NVD URL. |

## Patterns Cross-Referenced Across Sessions

This session's patterns extend prior:

- **2026-05-18 Pattern #10** (Scout-claim verification via NVD WebFetch) → **extended to user-prompt-claim verification** AND **CVSS field value verification**. Now durable across 5 sessions; the discipline is recursive across user prompts + scout reports + reviewer findings + CVSS values. Per Rule #19 evidence-first, NVD primary CPE + CVSS are the authoritative sources; everything else is a candidate.
- **2026-05-18 Pattern #2** (Multi-persona reviewer dispatch) → applied at the 5th consecutive session with 0 reverts. Cost: ~5-10 min per session; value: 5 forensic-correctness drifts caught this session that would have shipped to production. Reviewer B's discipline scaled to CVSS-field-numeric verification, not just attribution-scope verification.
- **2026-05-18 Pattern #6** (YAML hot-reload "keep previous on malformed") → extended to operator-visibility via `last_warning`. Pattern #6 was about graceful-degrade silence; this session's `last_warning` is the audit-trail for that silence — operators see WHY the state silently fell back.
- **2026-05-18 Pattern #7** (Schema gates at TWO layers) → applied to the BT_PARSER_FAMILIES alignment between patterns_loader.py validation gate + bt_firmware_banner.py public tuple. Schema-time alignment via cross-stack-test (not runtime-derivation due to circular-import constraint) is the cheaper-and-good-enough variant.
- **2026-05-18 Pattern #9** (Cross-vendor architecture — generic primitives in app/utils/) → reinforced. The `MtimeCachedYamlLoader.last_warning` + `register_loader` + `list_registered_loaders` extensions all live in `app/utils/yaml_cache.py` (not in hw-firmware subpackage), inviting cross-domain adoption. New consumers (SBOM metadata cache, future binary-analysis pattern cache) can adopt the loader + registry without touching hw-firmware code.
- **Rule #25 (per-piece commits)** — applied at session-of-7 (4 feat + 3 fix) all bisect-clean. The 3 reviewer-fix commits (one per persona) demonstrate the Rule #25 fixup-shape — separate fixup commits for separate findings, not bundled.
- **Rule #46 (paired-canary discipline)** → applied to 12 new tests across this session. Every "asserts ABSENCE" gate has a synthesized-violation canary. The new pattern: paired canaries for FORENSIC corrections (test_tegra_cve_pins_cvss_scores_match_nvd_primary) as well as for structural gates.
- **Rule #19 (evidence-first)** → extended to CVSS field values and to user-prompt-claim verification. NVD primary is the truth; everything else is a candidate.
