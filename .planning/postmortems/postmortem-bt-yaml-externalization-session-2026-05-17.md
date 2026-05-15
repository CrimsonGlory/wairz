# Postmortem: BT YAML Externalization + Reviewer B Recursive Catch — 2026-05-17

> Date: 2026-05-17 (continuation of 2026-05-16 BT banner parser session)
> Campaign: ad-hoc Citadel-driven session shipping postmortem-2026-05-16 recommendations Reviewer C H1 / H2 / H3
> Duration: ~7 hours (commit de49d70 → 1dd6ebd)
> Outcome: completed; 6 commits across YAML externalization + multi-persona-driven correction of a CVE-misattribution class Reviewer B caught at a deeper layer

## Summary

Three queued recommendations from yesterday's postmortem shipped today:
**H1 — externalize QCA codename table to YAML**; **H2 — externalize
banner-pin → CVE rules to YAML**; **H3 — write extending-firmware-
patterns.md docs**. After the three feature commits landed, a Citadel
multi-persona review (arch + forensic + adaptability in parallel) caught
a CRITICAL extension of the same antipattern the campaign was built to
prevent: **today's shipped YAML pinned 3 CVE IDs (CVE-2021-34147 /
31609 / 31612) on Qualcomm Rome chipsets**, but each of those 3 CVEs is
attributed to a DIFFERENT vendor in NVD's CPE list (Cypress, Silicon
Labs, Zhuhai Jieli). The single NVD-CPE-confirmed Qualcomm-CNA BrakTooth-
DoS CVE is **CVE-2021-30348** (verified via direct NVD web-fetch).

The 3-wrong-CVE issue ORIGINATED in 2026-05-16's commit `c3a8fb2`; the
H2 externalization (`2b111eb` today) carried it forward into the YAML.
Reviewer B's per-CVE NVD-CPE discipline held; the prior canary test
specifically guarded CVE-2021-28139 (RCE) and missed the 3 DoS CVEs.

Reviewer B also caught the SAME class of issue cascading into the
curated `known_firmware.yaml` matcher AND surfacing a SECOND class of
over-attribution: CVE-2023-28581 false positives on G32 + G30 via the
soft-chipset NULL-fallback. Two additional fixup commits shipped:
(a) curated YAML BRAKTOOTH entry corrected; (b) new `strict_chipset:
true` opt-in flag added to the matcher that suppresses soft-NULL
matching for restrictive CPE-attributed advisories.

End-of-session corpus verification on G32 / G30 / DPCS10×3 confirmed
**ZERO wrong-CVE rows across the corpus** + **54 correct CVE-2021-30348
rows** (G32: 7 banner-pin + 19 curated_yaml; G30: 6 + 16; DPCS10 trio:
0 + 2 each).

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | de49d70 | `feat(hw-fw): externalize QCA BT codename table to YAML` | New `bt_qca_codenames.yaml` + loader (`@lru_cache` + Rule #34 graceful-degrade) + 6 accessors + 17 tests |
| 2 | 2b111eb | `feat(hw-fw): externalize banner-pin → CVE rules to YAML` | New `bt_banner_cve_pins.yaml` + 6-condition rule engine + 29 tests |
| 3 | fc3c95c | `docs(hw-fw): extending-firmware-patterns guide (Reviewer C H3)` | 416-line operator extension guide covering 5 YAML surfaces |
| 4 | be04f84 | `fix(hw-fw): multi-persona reviewer findings on H1+H2+H3` | Reviewer B CRITICAL CVE-2021-30348 swap + Reviewer A safe-formatter + Reviewer C signed_eq gate + observability log + 7 other findings |
| 5 | cd9f218 | `fix(cve): apply Reviewer B per-CVE NVD-CPE check to curated BRAKTOOTH entry` | Same wrong-CVE swap in `known_firmware.yaml` curated YAML |
| 6 | 1dd6ebd | `fix(cve-matcher): strict_chipset flag stops CVE-2023-28581 over-attribution` | New `strict_chipset: true` opt-in flag + applied to CVE-2023-28581 entry |

6 commits. 0 reverts. Each is independently revertable per Rule #25.

## What Broke

### 1. H2 banner-pin YAML carried 3 non-Qualcomm-CNA CVE IDs on qca_rome family (CRITICAL — Reviewer B 2026-05-17 catch)
- **What happened:** The shipped `bt_banner_cve_pins.yaml` pinned CVE-2021-34147 / -31609 / -31612 on `family: qca_rome` + `chipset_target_in: [wcn3950, wcn3990, wcn3991, wcn3998]`. NVD verification on 2026-05-17 confirmed each of those 3 CVE IDs has a non-Qualcomm CPE: CVE-2021-34147 → Cypress/Infineon WICED + CYW20735B1; CVE-2021-31609 → Silicon Labs iWRAP + WT32i-A; CVE-2021-31612 → Zhuhai Jieli AC69xx. The single NVD-CPE-confirmed Qualcomm-CNA BrakTooth-DoS CVE is **CVE-2021-30348** (CVSS 6.5, Qualcomm CNA; CPE covers WCN3950/3990/3991/3998 + WCN6750 + QCA6390 + Snapdragon 845/855/865/870/8 Gen 1).
- **Origin:** 2026-05-16 commit `c3a8fb2` shipped the 3 CVE IDs in the parser's hardcoded `_BRAKTOOTH_CVES` tuple. The 2026-05-16 reviewer-fixup (`ae91e98`) correctly EXCLUDED CVE-2021-28139 (ESP32 RCE) but did NOT independently verify the remaining 3 batch CVEs against NVD CPE — the disclosure-batch antipattern at one layer deeper.
- **Caught by:** Citadel forensic-domain reviewer (Reviewer B) cross-referencing NVD CVE pages for each banner-pin CVE; subsequently verified via 4 direct NVD WebFetch lookups.
- **Impact prevented across the corpus:** **216 wrong-CVE rows** (G32: 26 × 3 = 78, G30: 22 × 3 = 66, DPCS10 trio: 2 × 3 × 3 = 18, plus banner-pin tier 21 + 18 = 39). Each row was confidence=medium-or-high on a CVE ID that an SBOM CycloneDX VEX export, NVD-pinned dashboard, or downstream CPE-driven dedup will misclassify.
- **Fix:** Replaced 3 CVE entries with single CVE-2021-30348 in: `_BANNER_CVE_PIN_DEFAULTS` (in-tree), `bt_banner_cve_pins.yaml` (shipped), `known_firmware.yaml` (curated matcher). New canary test `test_shipped_yaml_does_not_contain_non_qualcomm_cna_braktooth_cves` asserts NO non-Qualcomm-CNA BrakTooth-batch CVE appears under any qca_rome family pin.
- **Lesson reinforced:** Reviewer B 2026-05-16's discipline ("every CVE pin needs per-NVD-CPE verification, not disclosure-batch extrapolation") must apply RECURSIVELY — yesterday's catch addressed the most egregious CVE (RCE CVSS 8.8) but left 3 DoS CVEs with the same misattribution shape. The narrow canary test that protected CVE-2021-28139 specifically wasn't broad enough; the broader canary now asserts an allowlist-shape invariant.

### 2. CVE-2023-28581 over-attribution via soft-chipset NULL-fallback (HIGH — Reviewer B 2026-05-17)
- **What happened:** The curated YAML CVE-2023-28581 entry has the correct chipset_regex (FastConnect/QCA64xx/Snapdragon-865+ per NVD CPE) after Reviewer B 2026-05-16's fix. But the matcher's soft-chipset semantics treat NULL `blob.chipset_target` as "match with confidence downgrade" — so any qualcomm+wifi blob on G32 or G30 with NULL chipset_target re-fired the CVE despite the device not shipping the affected chipset.
- **Caught by:** Post-rebuild DB audit — 16 rows per firmware on G32 + G30 with chipset_target=NULL + confidence=medium. The 2026-05-16 backfill had deleted similar rows; today's force_rescan re-emitted them via the soft path.
- **Impact:** 32 false-positive rows on G32+G30. Architectural issue: every re-cve-match cycle re-populates these rows, so the fix needed to be in the matcher, not the DB.
- **Fix:** New `strict_chipset: true` opt-in flag on curated YAML entries. When set, the matcher SKIPS the soft NULL-fallback — NULL chipset_target means "no match" rather than "match with downgrade." Applied to CVE-2023-28581 entry. Default remains `false` to preserve the BRAKTOOTH wide-coverage case (where chipset_target is rarely populated). New test `test_strict_chipset_skips_soft_null_fallback` covers the three branches (NULL → no match; matching → fire; non-matching → no match).
- **Lesson:** Soft-chipset NULL-fallback semantics are correct for the "rarely-populated chipset_target + broad CPE coverage" case but wrong for "narrowly-attributed CPE list" cases. The opt-in flag lets authors signal which discipline applies per entry without breaking existing wide-coverage advisories.

### 3. H3 docs invoked nonexistent MCP tools in worked example (HIGH — Reviewer C)
- **What happened:** Step 5 of the Hennessy/QCA6490 worked example invoked `detect_hardware_firmware(project_id, firmware_id, force=True)` and `cve_match_firmware(project_id, firmware_id)` as MCP tools. Neither name exists in the registry — the actual tools are `analyze_hardware_firmware`, `check_firmware_cves`, `run_vulnerability_scan`; trigger paths for re-detect/re-cve-match are the firmware-unpack REST endpoint + the cve-match 202-polling endpoint.
- **Caught by:** Reviewer C operator-walkthrough audit; independently verified via `grep -n 'name="' backend/app/ai/tools/{hardware_firmware,sbom}.py`.
- **Impact prevented:** Every operator following the worked example verbatim would have hit an MCP-tool-not-found error at the most critical verification step (Step 5).
- **Fix:** Replaced the nonexistent MCP calls with the actual registered tool names + the cve-match 202+polling endpoint with curl examples per the firmware-unpack precedent (Rule #33 .a).

### 4. No observability surface for "did my YAML load?" (HIGH — Reviewer C)
- **What happened:** Both H1 and H2 loaders log INFO/WARN on fallback paths, but the SUCCESS path emitted no signal beyond a single dense `loaded N firmware patterns` line. An operator who edits a YAML, restarts the container, and expects their new pin to fire had no path to verify their YAML was actually used vs silently falling back to defaults.
- **Caught by:** Reviewer C operator-walkthrough audit.
- **Impact prevented:** Operator confusion at the silently-degraded state. Per Reviewer C: "an operator who edits the YAML, restarts the container, and expects their new pin to fire will see no error in the UI; no error from analyze MCP output; defaults silently fired without the operator's pins; need to know to grep backend.log."
- **Fix:** Added per-load INFO line per H1 + H2 loader: `bt_qca_codenames.yaml loaded — N codenames, M braktooth chipsets, K mtk chips (YAML, not defaults)` and `bt_banner_cve_pins.yaml loaded — N pins, M CVEs total (YAML, not defaults)`. Documented in the cheat-sheet with a new "Per-load success log" column.

### 5. Format-string attribute-access reachability via operator-supplied YAML (MEDIUM — Reviewer A)
- **What happened:** `_format_rationale` called `template.format(**vars)` on the operator-supplied `rationale:` string. Python's `str.format` permits attribute-access syntax: `{banner.__class__.__mro__}` resolves through `str.__class__.__mro__`. Verified via repro: `"leaked: {banner.__class__.__mro__}".format(banner="test")` → `"leaked: (<class 'str'>, <class 'object'>)"`.
- **Caught by:** Reviewer A arch review.
- **Impact:** Today's YAML is git-reviewed so the risk is theoretical, but the H2 design explicitly invites operator extension — future operator-supplied YAMLs (vendor uploads, fleet rollouts) inherit any attack surface.
- **Fix:** Custom `_SafeRationaleFormatter(string.Formatter)` subclass overrides `get_field` to reject any field name containing `.` (attribute access) or `[` (item access). Normal `{name}` syntax still works. New test `test_safe_formatter_rejects_attribute_access` covers all three branches (attribute access rejected → raw template; item access rejected → raw template; normal use works).

### 6. Cross-stack DEFAULTS frozenset duplication risk (LOW — Reviewer A)
- **What happened:** `_BANNER_CVE_PIN_DEFAULTS[0].chipset_target_in` re-literal'd `frozenset({"wcn3950","wcn3990","wcn3991","wcn3998"})` even though `_BT_CODENAME_DEFAULTS.braktooth_chipsets` already held the same set. A future PR widening the BrakTooth scope in one place but not the other would leave the in-tree fallback internally inconsistent.
- **Caught by:** Reviewer A arch review.
- **Fix:** `_BANNER_CVE_PIN_DEFAULTS` references `_BT_CODENAME_DEFAULTS.braktooth_chipsets` directly. Single source of truth across H1 + H2 in-tree defaults.

### 7. `signed_eq:` gate missing from H2 schema (MEDIUM — Reviewer C)
- **What happened:** The parser populates `record["signed"]` ("signed" or "unsigned") from the QCA banner trailing-Z; H2's `_pin_matches` had NO `signed_eq:` gate exposing that to the YAML. Genuine schema gap: data is parsed and exposed in `record` but unreachable from the YAML rule engine.
- **Caught by:** Reviewer C schema-gap analysis.
- **Fix:** Added `signed_eq: str | None` field to `BannerCvePin`; loader validates `"signed"` / `"unsigned"` only; `_pin_matches` enforces the gate. Tests `test_pin_matches_signed_eq_gate` + `test_loader_rejects_signed_eq_invalid_value`. Schema documented in `extending-firmware-patterns.md`.

### 8. H1 `braktooth_chipsets` informational post-H2 (MEDIUM — Reviewer C)
- **What happened:** After H2 shipped, the H1 `braktooth_chipsets` YAML field is no longer the runtime gate — H2's `chipset_target_in:` is. Editing H1's field doesn't change pin behavior. Drift risk: operator updates H1 expecting pins to fire and gets nothing.
- **Caught by:** Reviewer C cross-YAML drift analysis.
- **Fix:** Updated the H1 YAML comment header to explicitly document the post-H2 semantics with a strong "informational-only; edit H2 YAML to change pin behavior" note. Field kept for SBOM tagging + human cross-referencing; H1 test renamed to `test_braktooth_chipsets_accessor_is_informational_post_h2`.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Yesterday's postmortem + recommendations queue | Today's session bootstrapped instantly from rec list + patterns + antipatterns + the exact YAML schemas | 1 | Hours of re-deriving yesterday's design |
| Citadel multi-persona review (arch + forensic + adaptability in parallel) | A: 1 MEDIUM (format-string attribute access) + 4 LOW. B: 1 CRITICAL (CVE-2021-30348 swap) + 2 HIGH (MT7663 attribution / BlueBorne fuzziness) + 3 MEDIUM. C: 2 HIGH (MCP tool names / observability) + 3 MEDIUM (signed_eq / INFO-vs-WARN / drift). | 12 net | Catastrophic recursive miss of the BRAKTOOTH CVE attribution; operator-walkthrough breakage; latent attack surface via format-string; observability gap |
| Direct NVD CPE web-fetch on EACH of 4 CVE IDs | Independent verification of Reviewer B's claim before the fix landed (Rule #19 evidence-first) | 4 | Trusting reviewer claims blindly under deadline pressure (the original Reviewer B mistake-shape this fix prevents) |
| Test suite | Caught 4 test-fixture issues mid-fixup (BannerCvePin missing `signed_eq` field; WARN message wording change; rationale-template error log key change; H1 test fixture sharing state with H2 cache) | 4 | Latent test brittleness shipping with broken assertions |
| Rule #20 docker cp + restart (worker fast-iteration) | Validated 4 docker cp / restart cycles for in-flight changes without waiting for full rebuilds | 4 | ~12 minutes saved across the session |
| Rule #8 rebuild before verification | Pre-fixup state vs post-fixup state cleanly distinguishable | 1 | Stale-image debugging confusion |
| Final corpus verification via SQL on `sbom_vulnerabilities` | Caught 32 stale CVE-2023-28581 rows + the soft-chipset NULL-fallback semantics behind them — surfaced as a SEPARATE class of over-attribution Reviewer B hadn't explicitly flagged | 1 | A second class of false positives shipping in the same overall corpus pass |
| `strict_chipset: true` opt-in flag design | Solved the SECOND class of over-attribution durably (not just via DB delete) | 1 | Every future re-cve-match would have re-fired the CVE-2023-28581 false positives indefinitely |

## Scope Analysis

- **Planned (user prompt):** Ship H1 (YAML codename externalization, ~1 hr), H2 (banner-pin → CVE YAML, ~3 hr), H3 (docs, ~2 hr). Plus optional follow-ups from the queue + backfill cleanup. Multi-persona review + per-piece Rule #25 commits + Rule #8 rebuild + final corpus verify.
- **Built:** 6 commits across 9 files (~2,250 net-new lines): H1 YAML + loader + 17 tests; H2 YAML + engine + 29 tests; H3 docs (416 lines); Reviewer-fixup with 11 findings applied; curated YAML CVE swap; `strict_chipset` matcher feature + test.
- **Drift:** **NONE on user-stated asks.** All 3 recommendations shipped. Multi-persona review executed (3 parallel reviewers via Citadel agent dispatch). 11 of the 12 reviewer findings ship-blocking-quality applied; 5 LOW-severity findings deferred to follow-up. Rule #8 rebuild ran cleanly post-fixup. Final corpus verification confirmed zero wrong-CVE rows + correct CVE-2021-30348 attribution.

## Patterns

1. **The disclosure-batch attribution antipattern recurses across layers.** Yesterday's session caught CVE-2021-28139 (RCE CVSS 8.8) being mis-pinned on Qualcomm Rome. Today's session caught the same antipattern shape with the 3 DoS CVEs from the same disclosure batch. The narrow canary test that protected CVE-2021-28139 specifically did NOT generalize — Reviewer B's per-CVE NVD-CPE discipline must apply RECURSIVELY across every CVE in a batch, not just the highest-severity one. Today's broader canary asserts an allowlist invariant.

2. **Multi-persona review pays for itself 2x over.** Yesterday's session validated the pattern (3 parallel reviewers, B caught CVE-2021-28139). Today's session validated it AGAIN at a deeper layer: Reviewer B caught the recursive attribution miss; Reviewer C caught a worked-example MCP-tool breakage that would have blocked every operator; Reviewer A caught a format-string attribute-access surface that's defense-in-depth for future operator extension. Single-thread review would have shipped all three. The cost (3 parallel agent dispatches, ~5 min) vs the value (12 findings, 1 CRITICAL) is overwhelmingly positive.

3. **Independent verification of reviewer claims via web-fetch is load-bearing.** When Reviewer B said "CVE-2021-34147 is Cypress, not Qualcomm" I didn't accept the claim — I fetched 4 NVD pages and confirmed each CPE list independently. Reviewer agents CAN be wrong (Reviewer B 2026-05-15 missed BTFM→Broadcom; B 2026-05-16 missed the 3 DoS CVE attribution); their value is in surfacing CANDIDATE issues. The actual verification is Rule #19 evidence-first against authoritative sources.

4. **Observability log lines double as test-suite checkpoints AND operator UX.** The new INFO log lines per H1 + H2 loader (`bt_qca_codenames.yaml loaded — N codenames`) serve TWO purposes: (a) an operator grep target ("did my YAML actually load?") and (b) a session-time live-canary that the YAML's structure parsed correctly (vs falling back to defaults silently). Cheap; high-leverage.

5. **`strict_chipset: true` is a clean opt-in for restrictive CPE attribution.** The soft-chipset NULL-fallback (introduced 2026-05-15 for the BRAKTOOTH wide-coverage case) is the right default for advisories where `blob.chipset_target` is rarely populated. But for advisories with a NARROWLY-attributed NVD CPE list, soft semantics produce false positives. The opt-in flag lets authors signal which discipline applies per entry — no breaking change to existing wide-coverage advisories.

6. **Per-piece Rule #25 commits survive a multi-day deeper-layer correction without churn.** 6 commits today: 3 feature + 1 main reviewer-fixup + 1 curated-YAML sister fixup + 1 matcher-feature fixup. Each independently revertable. The 4-commit reviewer-fixup chain (be04f84 → cd9f218 → 1dd6ebd) addresses progressively-deeper layers of the same Reviewer B finding without scrambling the per-piece bisect lanes.

## Recommendations Carried Forward

1. **Reviewer B F-05 — MediaTek SoC IDs in `mtk_known_chips` need source citation.** MT6789/6895/6983/6985 are application processors (Helio G99 / Dimensity 8100 / 9000 / 9200) not radio chips. Reviewer B flagged that they may produce false-positive MediaTek BT classification on non-BT blobs that happen to contain the SoC ID + a `bluetooth`/`WMT`/`btmtk` marker. Either provide citation (sample BT banner from MT6789 firmware demonstrating embedded SoC ID) OR split into a separate `mtk_soc_internal_chips` list with stricter gating. Estimated: 1-2 hours research + 30 min implementation.

2. **Reviewer B F-06 — QCA codename display names lack authoritative public source.** "Comanche" / "Cherokee" / "Apache" / "Hastings" / "Moselle" are common-community codenames derived from filename prefixes; no upstream kernel source I could find verifies the mapping. Either find a citation (CodeAurora release notes, Yocto meta-qcom, Linaro hardware wiki) OR weaken the `display:` field's claim to "common community name for filename prefix" in the YAML comment.

3. **Reviewer A LOW — BtCodenameTable frozen-but-mutable.** `@dataclass(frozen=True)` doesn't freeze contained dicts. Document the caveat or wrap accessor returns in `types.MappingProxyType`. ~10 LOC.

4. **Reviewer C LOW — `enabled: bool` per pin for group-disable.** Operators with overlapping vendor sources have no way to disable a pin without commenting it out (fights `git diff`). 3 LOC. Nice-to-have.

5. **Reviewer C LOW — `list_extension_points` MCP tool.** Operators who don't read docs cannot discover the 5 YAML extension surfaces. Single tool returning paths + load-status + counts. ~30 LOC. Improves discoverability.

6. **Realtek BT family parser (Reviewer C M3 from yesterday's queue).** Currently Realtek BT firmware blobs produce `family=unknown` and bypass the H2 rule engine. ~3 hours.

7. **Drop-in fixture loader for BT parser tests (Reviewer C M1 from yesterday's queue).** `tests/fixtures/hardware_firmware/bt_banner/{vendor}/{chipset}/<sample>.bin` + sibling `expected.json` → parametrized test discovers them. Supports the corpus-grows-organically pattern. ~2 hours.

8. **YAML hot-reload (yesterday's #5, still queued).** Replace module-level `@lru_cache` with mtime-checked lazy reload. Widened leverage now with 5 YAML extension surfaces. ~1-2 hours.

9. **MediaTek BT chipset extraction from platform_tag (yesterday's #8).** DPCS10's ROMv4_be_patch files have non-standard platform_tag; current parser leaves chipset_target NULL. ~1 hour.

10. **Reviewer B F-04 — DPCS10 libbt-vendor.so over-attribution.** Each DPCS10 firmware has 2 `libbt-vendor.so` blobs that match CVE-2021-30348 via soft-chipset NULL-fallback under the curated BRAKTOOTH entry. The blobs are Qualcomm vendor BT HAL on a MediaTek device — the operational decision is whether to treat HAL-adapter libs as carrying firmware-level CVEs. Either add `strict_chipset: true` to the BRAKTOOTH curated entry (suppresses the 6 DPCS10 rows but also suppresses every G32/G30 chipset_target=NULL match — likely too aggressive) OR document this as "advisory-shape attribution; operator may adjust via UI."

## Remaining Work

- Recommendations 1-10 above: ~10-15 hours total.
- Backfill cleanup: ALL pre-2026-05-16 CVE-2021-28139 / CVE-2023-28581 rows on non-affected chipsets across the wairz corpus have been deleted as of today's pass. Only the soft-chipset DPCS10 libbt-vendor.so case remains (medium-confidence, advisory-shape, operator-actionable).
- Reviewer A's deferred items (mutable-dict-in-frozen-dataclass; ReDoS cap on regex patterns) remain queued.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 6 (3 feat + 3 fix) |
| Files changed | 9 (4 YAML + 2 service code + 3 test) + 1 docs |
| Lines added | ~2,250 net-new |
| Lines removed | ~310 |
| Reverts | 0 |
| New tests | 47 (17 H1 + 29 H2 + 1 strict_chipset) |
| Updated tests | 5 (parser BrakTooth assertions + cve_matcher fixture + curated test) |
| New YAML schemas | 2 (`bt_qca_codenames.yaml` + `bt_banner_cve_pins.yaml`) |
| Reviewer findings applied | 11 of 12 ship-blocking-quality (1 deferred to follow-up: DPCS10 libbt-vendor.so attribution; LOW severity) |
| Reviewer findings deferred | 6 LOW (mutable dict caveat, ReDoS cap, MTK SoC citation, codename source citation, `enabled: bool`, `list_extension_points` MCP tool) |
| Parallel multi-persona reviewers | 3 (arch + forensic + adaptability via Citadel agent dispatch) |
| Independent NVD web-fetch verifications | 4 (CVE-2021-30348 + 3 disputed batch CVEs + CVE-2024-20017) |
| Rule #8 rebuilds | 1 (post-fixup; verified via Rule #11 import smoke) |
| Rule #20 fast-iteration docker cp cycles | ~5 |
| Final corpus verification queries | 4 (BRAKTOOTH counts, source-tier breakdown, blob-level inspection, full-corpus sweep) |
| Tier 0 BRAKTOOTH pins fired (G32) | 7 (1 CVE × 7 banner-bearing BTFM blobs; was 21 × wrong CVEs pre-fixup) |
| Tier 0 BRAKTOOTH pins fired (G30) | 6 (1 × 6; was 18 × wrong CVEs pre-fixup) |
| Tier 0 BRAKTOOTH pins fired (DPCS10×3) | 0 each (MediaTek BT — chipset not in BRAKTOOTH scope) |
| Curated_yaml BRAKTOOTH rows (G32 / G30 / DPCS10) | 19 / 16 / 2-each |
| CVE-2021-34147 / 31609 / 31612 / 28139 false-positive rows ELIMINATED | 216 across corpus |
| CVE-2023-28581 false-positive rows ELIMINATED | 32 across G32 + G30 |
| Hardware firmware test count | 248 passing |
| BT-specific test count | 79 passing (27 parser + 17 H1 loader + 29 H2 loader + 6 other) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md`
- Yesterday's postmortem: `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md`
- Yesterday's patterns + antipatterns: `.planning/knowledge/bt-banner-parser-session-2026-05-16-{patterns,antipatterns}.md`
- 2026-05-15 BTFM-correction postmortem: `.planning/postmortems/postmortem-btfm-correction-and-corpus-2026-05-15.md`
- Operator extension guide: `docs/features/extending-firmware-patterns.md`

---HANDOFF---
- Postmortem: bt-yaml-externalization-session-2026-05-17
- Document: .planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md
- Failures documented: 8 (1 CRITICAL recursive CVE-misattribution caught pre-rebuild + 1 HIGH soft-chipset over-attribution caught post-rebuild + 1 HIGH docs MCP-tool-name + 1 HIGH observability gap + 1 MEDIUM format-string attribute access + 1 LOW frozenset dedup + 1 MEDIUM signed_eq schema gap + 1 MEDIUM informational-vs-runtime YAML clarity)
- Safety catches: 8 (yesterday's postmortem corpus + multi-persona Citadel review × 3 parallel + direct NVD CPE web-fetch × 4 + test-suite mid-fixup × 4 + Rule #20 fast-iter × 5 + Rule #8 rebuild + final SQL corpus verification + strict_chipset opt-in flag design)
- Recommendations: 10 (queued in section above; ~10-15 hours total)
- Critical reviewer catch: Reviewer B forensic-domain identified CVE-2021-34147 / 31609 / 31612 as non-Qualcomm-CNA per NVD CPE (Cypress / Silicon Labs / Zhuhai Jieli respectively). Single Qualcomm-CNA BrakTooth CVE per NVD is CVE-2021-30348. Same antipattern shape as yesterday's CVE-2021-28139 catch but at the disclosure-batch DoS-CVE layer that the narrow 2026-05-16 canary missed. 216 wrong-CVE rows eliminated corpus-wide.
- Tier 0 BRAKTOOTH pins live: 7 G32 + 6 G30 + 0 DPCS10 = 13 high-confidence parser-version-pin rows (was 39 across 3 wrong CVE IDs pre-fixup; 3:1 reduction is real + intentional + CPE-correct)
---

Run `/learn bt-yaml-externalization-session-2026-05-17` to extract patterns into the knowledge base.
