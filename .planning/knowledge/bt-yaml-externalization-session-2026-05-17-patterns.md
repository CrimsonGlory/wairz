# Patterns: BT YAML Externalization Session 2026-05-17

> Extracted: 2026-05-17
> Campaign: ad-hoc systematic-debugging session shipping 2026-05-16 recommendations H1/H2/H3
> Postmortem: `.planning/postmortems/postmortem-bt-yaml-externalization-session-2026-05-17.md`

## Successful Patterns

### 1. Parallel multi-persona Citadel review caught the recursive layer of the prior session's antipattern
- **Description:** Three parallel Citadel reviewers (arch + forensic-domain + adaptability) ran after H1+H2+H3 shipped via parallel `Agent` tool dispatches. The forensic-domain reviewer caught CVE-2021-34147 / -31609 / -31612 as NON-Qualcomm-CNA-attributed per NVD CPE — a deeper layer of the SAME antipattern yesterday's session was supposed to prevent. The 2026-05-16 reviewer-fixup excised CVE-2021-28139 (RCE CVSS 8.8) specifically but didn't independently re-verify the remaining 3 DoS batch CVEs against NVD CPE.
- **Evidence:** Reviewer B's report quoted NVD CPE lists for each disputed CVE; subsequent direct NVD web-fetch verified each claim. Result: 216 wrong-CVE rows eliminated corpus-wide across 5 firmwares (G32 78, G30 66, DPCS10 trio 18, plus banner-pin tier 21 + 18 = 39).
- **Applies when:** Any commit batch that adds CVE attribution OR security-sensitive classification downstream of which a matcher fires. Two sessions in a row now ship CVE-attribution failure modes that the multi-persona pattern caught and a single-thread review would have missed. Multi-persona review is now durable beyond debate.

### 2. Independent reviewer-claim verification via web-fetch is Rule #19 evidence-first applied to agent output
- **Description:** When Reviewer B claimed "CVE-2021-34147 is Cypress per NVD, not Qualcomm," I didn't accept the claim — I fetched 4 NVD pages directly and verified each CPE list independently. Reviewer agents can be wrong (2026-05-15 missed BTFM→Broadcom; 2026-05-16 missed the DoS CVE attribution); their value is in surfacing candidate issues. The actual verification is Rule #19 evidence-first against authoritative sources.
- **Evidence:** 4 NVD WebFetch calls produced authoritative CPE strings for CVE-2021-34147 (Cypress WICED + CYW20735B1), -31609 (Silicon Labs iWRAP + WT32i-A), -31612 (Zhuhai Jieli AC69xx), -30348 (Qualcomm + WCN3950/3990/3991/3998/6750 + QCA6390). The corrected CVE-2021-30348 was the SINGLE Qualcomm-CNA BrakTooth CVE.
- **Applies when:** Any reviewer claim that drives a CRITICAL or HIGH-severity correction. Cost is ~30 seconds per CVE; carries zero risk; eliminates trust-the-agent-blindly failure modes.

### 3. `strict_chipset: true` opt-in flag preserves backward compat for the soft-chipset default case
- **Description:** When post-rebuild verification surfaced 32 CVE-2023-28581 false positives on G32 + G30 via the soft-chipset NULL-fallback, the cleanest durable fix was a new YAML field `strict_chipset: true` that opts OUT of the soft-NULL branch for restrictive CPE-attributed advisories. Default remains `false` (preserves BRAKTOOTH wide-coverage). Applied to CVE-2023-28581; framework available for any future restrictive entry.
- **Evidence:** 5 LOC in `_match_curated` + 1 YAML field + 1 new test (`test_strict_chipset_skips_soft_null_fallback`). Eliminates the 32 false-positive class durably (not just via DB delete) — every future re-cve-match no longer re-fires them.
- **Applies when:** Solving a class of over/under-attribution where the SAME matcher field needs different semantics across entries. Opt-in flags > forced-flip global defaults when the default has legitimate use cases.

### 4. Per-loader startup INFO log as observability + live-canary together
- **Description:** Added one INFO line per H1 + H2 YAML loader on the SUCCESS branch: `bt_qca_codenames.yaml loaded — 5 codenames, 4 braktooth chipsets, 18 mtk chips (YAML, not defaults)`. Doubles as (a) operator grep target ("did my YAML load?") and (b) live-canary that the YAML's structure parsed correctly. The fallback paths already had INFO/WARN; the success path now also signals positively.
- **Evidence:** Reviewer C 2026-05-17 finding — "operator cannot tell if YAML loaded vs defaults silently fired." Verified working via docker compose restart + python smoke: both loaders emit the expected line with counts that match expectations.
- **Applies when:** Any data loader where operator-edited input file MIGHT silently fall back to defaults. The positive-side log line is the SINGLE most operator-friendly improvement for these surfaces.

### 5. Allowlist-shape canary tests beat narrow CVE-ID-specific guards
- **Description:** Yesterday's session shipped `test_shipped_yaml_does_not_contain_cve_2021_28139` — a hardcoded CVE-ID-specific canary. That test PASSED today (CVE-2021-28139 still wasn't in the YAML) but missed the SAME antipattern shape on the 3 DoS CVEs from the same disclosure batch. Today's replacement canary asserts a BROADER invariant: "no non-Qualcomm-CNA CVE appears under any qca_rome family pin," with an explicit allowlist of the four batch-attributed CVEs.
- **Evidence:** New `test_shipped_yaml_does_not_contain_non_qualcomm_cna_braktooth_cves` enumerates the 4 non-Qualcomm batch CVEs as a frozen set and asserts disjoint from the YAML's qca_rome pin contents. If a future PR adds any of the 4 IDs OR another non-Qualcomm-CNA CVE under qca_rome, the canary fails LOUD.
- **Applies when:** Authoring any canary test (Rule #46). The narrow form ("X is absent") catches THE specific X; the broad form ("no member of {X, Y, Z, ...} is present") catches the failure class. Prefer the broad form when the failure class is generalizable.

### 6. End-to-end corpus verification surfaces issues unit tests can't
- **Description:** After all 6 commits + Rule #8 rebuild, SQL queries against `sbom_vulnerabilities` revealed: (a) the H2 fix worked end-to-end via parser_version_pin tier; (b) the curated_yaml tier was still emitting the wrong 3 CVE IDs (caught BEFORE moving to next-step verification); (c) CVE-2023-28581 was re-firing via soft-chipset NULL-fallback (NEW class of issue not flagged by unit tests). Each finding led to a separate fixup commit.
- **Evidence:** 4 SQL audit queries + 1 detection re-run + 1 cve-match re-run. Final state: 0 wrong-CVE rows; 54 correct CVE-2021-30348 rows across the 5 corpus firmwares; all from the post-fixup code path.
- **Applies when:** Any session shipping classification + matcher + persistence changes. Unit tests verify dispatch shape; only the corpus end-to-end verification surfaces the cross-layer interactions (parser writes → matcher reads → DB persists → DB read by SQL).

### 7. Per-piece Rule #25 commits survive deeper-layer corrections
- **Description:** 6 commits today: 3 feature (de49d70 H1, 2b111eb H2, fc3c95c H3) + 3 fixup (be04f84 main reviewer-fixup, cd9f218 curated-YAML sister, 1dd6ebd matcher feature). Each independently revertable. The 3-fixup chain addresses progressively-deeper layers of the same Reviewer B finding (parser-pin YAML → curated YAML → matcher soft-chipset semantics) without scrambling per-piece bisect lanes.
- **Evidence:** 0 reverts; clean bisect-clean chain; each commit message documents the prior-session-reference + cross-references the previous fixup.
- **Applies when:** Any session where reviewer corrections discover deeper-layer issues mid-session. The natural urge is to amend or squash; per-piece preserves the audit trail of "what was caught when" which is exactly what makes future sessions cheaper to debug.

### 8. Test-factory function avoids per-field-addition test refactors
- **Description:** When the H2 fixup added a `signed_eq` field to `BannerCvePin`, every existing test that constructed a `BannerCvePin` started failing on the new required field. Rather than updating each test, introduced a `_make_pin(**overrides) → BannerCvePin` factory with all match-condition defaults set to None. Tests now construct pins as `_make_pin(family="qca_rome")` — adding a new field tomorrow only requires updating the factory's default dict.
- **Evidence:** 9 test-construction sites simplified from 7-line BannerCvePin instantiations to 1-line `_make_pin(...)` calls. The dataclass shape can extend without N-test-line edits.
- **Applies when:** Any dataclass constructed in N tests where the dataclass shape is likely to grow. Trades 5 LOC of factory code for N-line-per-field-addition future edits.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Replace 3 BRAKTOOTH CVE IDs with single CVE-2021-30348 | Per-NVD-CPE verification: CVE-2021-34147/31609/31612 are NOT Qualcomm-CNA per NVD CPE; CVE-2021-30348 is the single Qualcomm-CNA BrakTooth CVE (CVSS 6.5, CPE WCN3950/3990/3991/3998 + WCN6750 + QCA6390 + Snapdragon 845/855/865/870/8 Gen 1) | Worked. Corpus verification: 216 wrong-CVE rows eliminated; 54 correct CVE-2021-30348 rows across 5 firmwares. |
| Add `strict_chipset: true` opt-in flag rather than flipping the soft-chipset global default | The soft-chipset NULL-fallback is correct for BRAKTOOTH wide-coverage (chipset_target rarely populated). Restrictive CPE-attributed entries (CVE-2023-28581) need different semantics. Opt-in flag preserves backward compat. | Worked. CVE-2023-28581 false positives eliminated durably (every future re-cve-match no longer re-fires them). |
| Switch `_format_rationale` to `_SafeRationaleFormatter` rather than `string.Template.safe_substitute` | Operator YAMLs already use `{name}` syntax. Custom Formatter subclass rejecting `.` and `[` keeps the existing template syntax while preventing attribute/item access. | Worked. New test `test_safe_formatter_rejects_attribute_access` covers both attack vectors + normal usage. |
| Keep `_QCA_FILENAME_PREFIX_TO_CODENAME` Python-side (NOT externalized) | The filename↔content mismatch flag is forensic-load-bearing (Reviewer B M2 2026-05-16); a small bespoke map keeps the link auditable + cross-references the content parser cleanly. | Worked. H3 docs explicitly call out the caveat: extending H1 YAML alone (without parser edit) silently loses mismatch metadata. |
| H1's `braktooth_chipsets` field kept post-H2 as informational-only | Removal would break the H1 public accessor + tests. Keep + document strongly as "informational; runtime gate is H2's chipset_target_in." | Worked. Test renamed to `test_braktooth_chipsets_accessor_is_informational_post_h2`. Drift risk documented in YAML header. |
| All-or-nothing YAML structural-validation fallback for H1+H2 (one bad entry → entire YAML rejected, defaults fire) | For high-leverage files like H2 pin engine, partial-load semantics are subtle — "my pin doesn't appear" is easier to diagnose than "my pin appears but with a silently-dropped field." Classifier YAML uses per-entry-skip because one bad regex among thousands shouldn't kill classification. | Worked. The asymmetry is documented explicitly in the cheat-sheet table. |
| Reject `build_id_lt: 0` as a likely-unfilled sentinel at load time | A real build_id is always >= 0 so the gate would never fire. Loud-on-likely-mistake matches the rest of the H2 loader's strict-validation discipline. Operators with a legitimate build_id=0 special-case can combine with another gate (e.g. chipset_target_in). | Worked. New test asserts both branches (bare → reject; with-other-gate → accept). |

## Patterns Cross-Referenced Across Sessions

This session's patterns reinforce and extend prior:

- **Yesterday's pattern "multi-persona Citadel review caught the exact same antipattern this campaign was supposed to prevent"** — today's session validated it AGAIN at a deeper layer: the campaign's premise was "make filename-only / disclosure-batch attribution impossible by construction"; the H2 externalization SHIPPED the disclosure-batch attribution latent in 3 CVE IDs; the multi-persona review caught it again. The discipline applies RECURSIVELY across batch CVEs, not just the highest-severity one.

- **Yesterday's pattern "end-of-session verification on the corpus is the only reliable did-it-work gate"** — today's corpus verification surfaced TWO additional classes of issue (curated-YAML cascade + soft-chipset over-attribution). Unit tests passing + the H1+H2 reviewer-fixup commit did NOT mean shipping-quality; the SQL audit against `sbom_vulnerabilities` was the actual gate.

- **Rule #19 (evidence-first) extends to reviewer-claim verification.** When reviewer agents surface a CRITICAL or HIGH finding, fetch the authoritative source (NVD, vendor advisory) BEFORE acting. The spec describes intent, the DB describes truth, the AUTHORITATIVE SOURCE describes the discipline reviewers MUST be measured against.

- **Rule #25 (per-piece commits) holds under multi-layer reviewer-driven correction.** 6 commits, 3 fixup commits addressing progressively-deeper layers. Each independently revertable. The shape pattern of 2026-05-16 (3 feature + 1 reviewer-fixup) extended cleanly to today's (3 feature + 3 fixup) without losing bisect-cleanliness.

- **Rule #46 (canary discipline) generalizes from "narrow X-absent" to "allowlist-shape invariant."** Yesterday's canary protected CVE-2021-28139 specifically; today's canary protects "no non-Qualcomm-CNA BrakTooth-batch CVE present" — the broader invariant. When the narrow canary can be defeated by a slight variation of the same antipattern, broaden to the allowlist form.

- **Rule #34 (graceful-degrade Rule-of-N) applied at both H1 + H2 layers.** Both new loaders ship with in-tree DEFAULTS that mirror the shipped YAML; missing or malformed YAML logs INFO/WARN + falls back. The SUCCESS-path INFO log (added in the fixup) is the natural Rule #34 partner: "what got loaded, with how many entries, from where."
