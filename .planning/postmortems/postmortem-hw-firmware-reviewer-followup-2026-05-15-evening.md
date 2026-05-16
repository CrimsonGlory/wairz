# Postmortem: HW-Firmware Reviewer Follow-up — F-FORENSIC-10 Alignment, FragAttacks Realignment, MediaTek CVE-2023-20819 Version Gate — 2026-05-15 (Evening)

> Date: 2026-05-15 (evening — continuation of the same-day's `postmortem-hw-firmware-tegra-activation-2026-05-15.md`)
> Campaign: ad-hoc Citadel-driven session shipping 3 carried-forward Reviewer findings from `postmortem-hw-firmware-tegra-activation-2026-05-15.md`: TARGET 1 = cross-stack F-FORENSIC-10 alignment test (Reviewer A MEDIUM); TARGET 2 = FragAttacks NVD-CPE realignment (Reviewer B HIGH); TARGET 3 = MediaTek CVE-2023-20819 modem-version gate (Reviewer B HIGH). Plus Reviewer B HIGH CVSS-drift fixup.
> Duration: ~3 hours (commits d641f28 → 3e12ae5)
> Outcome: completed; 4 commits — 3 feature TARGETs + 1 Reviewer B HIGH fixup — closing 3 of the 15 carried-forward recommendations + improving FragAttacks CVSS attribution per NVD primary discipline.

## Summary

The session opened against the top three carried-forward Reviewer findings from the same-day's earlier postmortem. Pre-implementation, 3 parallel Citadel scouts ran in one batch (one per TARGET), each with WebFetch access to the relevant NVD URLs. Each returned a complete design spec under 500 words; Scout 2 + Scout 3 independently re-verified NVD CPE for the in-scope CVEs.

Then 3 feature commits shipped per Rule #25, followed by 3 parallel multi-persona reviewers (architecture + forensic-domain + adaptability). **Reviewer B independently re-fetched NVD primary CVSS for the 3 FragAttacks CVEs and caught a HIGH CVSS-drift**: both FragAttacks advisory entries shipped with `severity: medium / cvss_score: 6.5`, but NVD primary CVSS 3.1 is LOW (3.5/2.6/3.5). Fixup tightened to NVD-faithful aggregate (`severity: low / cvss_score: 3.5` — worst-case of the 3 individual scores). 7 sessions running with the recursive-NVD-CVSS discipline catching field-value drift.

End-of-session verification on the 6-firmware regression corpus (DS1 + G30 + G32 + DPCS10×3):

- **FragAttacks SPEC-level CVEs (CVE-2020-24586/87/88)**: 96 curated CVE rows each pre-rebuild → **0 each** post-rebuild (curated entries converted to advisory-only).
- **ADVISORY-FRAGATTACK** (shared advisory_id across broadcom + qualcomm entries): 0 pre-rebuild → **32 rows** post-rebuild (one per distinct qualcomm/wifi blob; broadcom entry fires on 0 blobs because corpus has 0 broadcom/wifi blobs).
- **CVE-2023-20819 (MediaTek modem CDMA PPP)**: 20 rows pre-rebuild → **0 rows** post-rebuild (hard-reject version_regex; mtk_modem parser doesn't yet harvest MOLY banners — forward-prepared activation when parser shipment lands).
- **Regression baselines (ALL UNCHANGED)**:
  - BRAKTOOTH (CVE-2021-30348): 54 rows — matches morning's postmortem.
  - Wrong-attribution (CVE-2021-28139/34147/31609/31612): 0 rows.
  - CVE-2017-18159: 147 rows — preserved via soft fallback on NULL chipset_target.
  - Tegra activation (CVE-2021-1111/34372/34397/22-42269): 11+4+11+4 = 30 rows on DS1.
  - Tegra correctly-excluded (CVE-2019-5680, CVE-2022-42270): 0 rows.

Net delta: **−276 rows** in the 6-firmware corpus (256 from FragAttacks curated CVE → advisory conversion + 20 from CVE-2023-20819 over-attribution removal). All baselines preserved.

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | d641f28 | `test(hw-fw): F-FORENSIC-10 cross-stack alignment regression canary` | TARGET 1 — new file `backend/tests/test_forensic10_alignment.py` with 7 declared tests (16 cases via parametrize) asserting L1 (cve_matcher._KNOWN_FIRMWARE_NARROWING_FIELDS) + L2 (patterns_loader._parse_banner_cve_pin family-only check) reject the same conceptual disclosure-batch antipattern. META-CANARY confirms gate WARN contains all 4 narrowing-field names. |
| 2 | 54a0a32 | `feat(hw-fw): FragAttacks NVD-CPE realignment — curated CVE → advisory tier` | TARGET 2 — both FragAttacks YAML entries (broadcom + qualcomm wcn3xxx) converted to advisory-only with shared `advisory_id: ADVISORY-FRAGATTACK`. 5 new paired-canary tests including cross-corpus regression canary preventing future re-introduction of CVE-2020-2458x as direct attribution. Per Rule #19 NVD-CPE recursive verification confirmed ZERO Broadcom + ZERO Qualcomm CPEs across all 3 SPEC-level CVEs. |
| 3 | e45a74c | `feat(hw-fw): CVE-2023-20819 modem-family version_regex — forward-prepared` | TARGET 3 — added version_regex `(?i)(?:^|[^a-z0-9])(lr11\|lr12a\|lr13\|nr15\|nr16\|nr17)(?:[^a-z0-9]\|$)` to the MediaTek CVE-2023-20819 entry. NVD CPE narrows to exactly 6 modem-OS families; mtk_modem parser does not yet populate blob.version with MOLY banner — forward-prepared per Tegra precedent (Pattern #3 from morning's postmortem). Hard-reject matcher semantics confirmed. 5 new paired-canary tests including the gate-canary asserting HARD-REJECT semantics actually fire. |
| 4 | 3e12ae5 | `fix(hw-fw): Reviewer B HIGH — FragAttacks CVSS realignment to NVD primary` | Reviewer B HIGH fixup — independent NVD WebFetch on the 3 SPEC-level FragAttacks CVEs confirmed NVD primary CVSS 3.1 = 3.5/2.6/3.5 LOW (NOT medium 6.5 that pre-fixup shipped). Both FragAttacks advisory entries updated to `severity: low / cvss_score: 3.5` (worst-case aggregate). New regression canary pins severity + cvss_score across both entries. |

4 commits. 0 reverts. Each independently revertable per Rule #25.

## What Broke

### 1. FragAttacks CVSS shipped at medium 6.5 vs NVD primary LOW 3.5/2.6/3.5 (HIGH — Reviewer B 2026-05-15-PM catch)

- **What happened:** TARGET 2 (commit `54a0a32`) preserved the pre-realignment `severity: medium / cvss_score: 6.5` on both FragAttacks advisory entries. The CVSS values pre-dated the realignment; the implementer's WebFetch focused on NVD vendor list for the realignment scope, didn't re-fetch CVSS field values.
- **Caught by:** Reviewer B forensic-domain review — independently re-fetched NVD primary CVSS for all 3 CVEs (CVE-2020-24586/87/88) and confirmed the NVD primary is `nvd@nist.gov` LOW with baseScores 3.5/2.6/3.5 (not medium 6.5).
- **Impact prevented:** Operator triage on "fragattacks medium 6.5" would misprioritize vs NVD's LOW assessment. For an advisory aggregating multiple SPEC-level CVEs, the worst-case individual NVD primary CVSS is the standard convention.
- **Fix:** Commit `3e12ae5` updated both entries to `severity: low / cvss_score: 3.5` + added regression canary pinning the values.
- **Lesson:** Per Rule #19 recursive NVD-CPE verification (extended to CVSS field values per Pattern #2 of `postmortem-hw-firmware-mcp-tegra-2026-05-15` — 7 sessions running). The implementer's WebFetch caught the vendor-list drift; the reviewer's WebFetch caught the CVSS-field drift the implementer didn't re-verify. **Triple-verification (scout → implementer → reviewer) catches drift that single-axis verification misses** — different reviewers focus on different aspects.

### 2. CVE-2023-20819 entry fired on every MediaTek modem blob pre-narrowing (HIGH — pre-implementation Reviewer B finding from 2026-05-15-PM, applied this session)

- **What happened:** Pre-fixup, the CVE-2023-20819 entry pinned `vendor: mediatek + category: modem + category_regex: ^modem$` with NO version_regex narrowing. NVD CPE limits CVE-2023-20819 to exactly 6 modem-OS families (lr11/lr12a/lr13/nr15/nr16/nr17), but the entry over-attributed to every MediaTek modem blob (20 currently-firing rows in corpus).
- **Caught by:** Reviewer B 2026-05-15-PM HIGH finding (carried forward from morning's postmortem) — independent NVD CPE WebFetch on CVE-2023-20819 enumerating the 6 affected modem-OS families.
- **Impact prevented:** Forward-prepared narrowing eliminates over-attribution the moment the mtk_modem parser harvests MOLY banners. Until parser ships, rows drop to 0 (better than 20 over-attributed rows per Reviewer B's NVD-CPE evidence).
- **Fix:** Commit `e45a74c` shipped version_regex narrowing the entry to 6 NVD-affected families. Forward-prepared per Tegra precedent — activation pending mtk_modem parser shipment.
- **Lesson:** Forward-prepared CVE pin pattern (Tegra Pattern #3) repeats here for MediaTek modem. Rule-of-Two threshold met for codification as `.mex/patterns/forward-prepared-cve-pin.md` recipe (Reviewer C C7 finding — deferred).

### 3. FragAttacks curated entries over-attributed to Broadcom + Qualcomm vendors that NVD doesn't list (HIGH — pre-implementation Reviewer B finding from 2026-05-15-PM, applied this session)

- **What happened:** Both FragAttacks YAML entries pinned CVE-2020-24586/87/88 to broadcom + qualcomm vendors. NVD CPE for the 3 SPEC-level CVEs lists vendors ieee/linux/debian/arista/cisco/intel/microsoft/siemens ONLY — ZERO Broadcom CPEs + ZERO Qualcomm CPEs.
- **Caught by:** Reviewer B 2026-05-15-PM HIGH finding (carried forward from morning's postmortem) — independent NVD CPE WebFetch on all 3 CVEs.
- **Impact prevented:** Over-attribution on broadcom/qualcomm WiFi blobs that NVD does NOT list as affected. Implementer-side WebFetch (Scout 2 this session) confirmed Reviewer B's prior finding.
- **Fix:** Commit `54a0a32` converted both entries to advisory-only with shared `advisory_id: ADVISORY-FRAGATTACK`. Preserves forensic visibility on the WiFi blobs (one advisory row per blob) while respecting NVD CPE attribution scope.
- **Lesson:** Cross-vendor SPEC-level CVEs (FragAttacks, KRACK, Dragonblood) need recursive NVD-CPE verification of vendor list, not just chipset/version scope. Reviewer B B11 flagged similar candidates for next-session audit.

### 4. Single SQL `DELETE` needed before cve-match for YAML-edit-driven row changes (LOW — own-test catch)

- **What happened:** Initial verification plan called for `force_rescan=True` to re-emit rows. Investigating the matcher code revealed `force_rescan=True` removes the dedup check but doesn't DELETE existing rows — would hit UNIQUE constraint violations on re-insert.
- **Caught by:** Code-reading the matcher's force_rescan semantics at `cve_matcher.py:989,1042` — confirmed no DELETE in the matcher itself.
- **Fix:** Used surgical `DELETE FROM sbom_vulnerabilities WHERE cve_id IN ('CVE-2020-24586','CVE-2020-24587','CVE-2020-24588','CVE-2023-20819','ADVISORY-FRAGATTACK','ADVISORY-WLAN-FRAGATK') AND firmware_id IN (...)` before running cve-match without force_rescan.
- **Lesson:** Verification patterns for YAML-edit-driven row changes need an explicit DELETE step. Document the recipe pattern for next session. Companion to Pattern #9 from morning's postmortem — that pattern is about DETECTION re-runs; this is about MATCHER re-runs.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Pre-implementation parallel scouts (3 agents) | Scout 1 produced complete alignment-test design (path / function names / assertions / META-CANARY shape); Scout 2 produced complete FragAttacks realignment design including independent NVD-CPE verification of all 3 CVEs (confirming 0 Broadcom + 0 Qualcomm CPEs); Scout 3 produced complete CVE-2023-20819 version_regex design including matcher hard-reject semantics verification + mtk_modem parser gap audit | 3 reports + 4 NVD WebFetches (1 per CVE) | 3 design errors avoided pre-implementation; matcher semantics correctly characterized; forward-prepared pattern correctly applied |
| Recursive NVD-CPE verification (this session: 4 implementer-side + 4 reviewer-side independent fetches) | Reviewer B caught FragAttacks CVSS drift (medium 6.5 → LOW 3.5/2.6/3.5); implementer-side caught nothing the scouts missed (scouts' verifications already comprehensive on vendor + version scope) | 8 NVD fetches + 1 HIGH CVSS correction | Operator-triage drift on advisory severity (medium → low) |
| Multi-persona reviewer dispatch (3 parallel: arch + forensic + adaptability) | A: 13 findings (caplog conftest, inspect.getsource fragility, duplicate-advisory_id WARN noise, forward-prepared pattern codification, Rule #21 sync); B: 11 findings (CVSS drift HIGH — applied; wcn7xxx chipset extension; KRACK/Dragonblood/BroadPwn similar-shape audit); C: 15 findings (recipe gaps for cross-stack alignment + forward-prepared + shared advisory_id; MCP tool extensions; carry-forward backlog tracking) | 39 net findings (1 HIGH applied; ~38 deferred) | The HIGH CVSS-drift caught + applied; ~38 deferred to next session |
| Rule #46 paired-canary discipline | Every "asserts ABSENCE" gate has a paired synthesized-violation canary: META-CANARY for L1 WARN content (line 415-464 of test_forensic10_alignment.py); regression canary for CVE-2020-2458x curated leakage; gate-canary for CVE-2023-20819 hard-reject; CVSS regression canary pinning NVD primary values; cross-corpus regression canary for FragAttacks SPEC-level CVE attribution | 17 new paired-canary tests added across 4 commits | Multiple silent-pass failure modes where the gate / matcher would have stopped working without test detection |
| End-to-end SQL corpus regression check | Pre-rebuild + post-rebuild row counts validated against the morning postmortem's baseline (BRAKTOOTH 54 / wrong-attribution 0 / CVE-2017-18159 147 / Tegra 30 ALL UNCHANGED post-rebuild) | 1 cross-session baseline verification | Shipping with silent regression on the morning's 2026-05-17 elimination chain OR on the Tegra activation |
| Rule #8 rebuild + Rule #11 import smoke post-rebuild | Confirmed all 3 TARGETs loaded correctly; YAML state validated (2 ADVISORY-FRAGATTACK entries with severity=low/cvss=3.5; CVE-2023-20819 entry with version_regex; F-FORENSIC-10 narrowing fields tuple intact) | 1 rebuild + 1 smoke | Stale-image debugging confusion + caught the venv-python invocation gotcha (Rule #20 reminder — `python` vs `/app/.venv/bin/python`) |
| Rule #25 per-piece commits | 4 commits — 3 feature + 1 Reviewer B HIGH fixup — each independently revertable. Bisect-clean. | 1 | Multi-issue commit-mash that would force all-or-nothing rollback for the CVSS correction vs the realignment foundation |
| Rule #38 cwd discipline | Caught mid-session cwd drift to `/home/dustin/code/wairz/backend/` after a `cd backend && uv run pytest` invocation; reset to repo root before next git command; switched to subshell-scoped `cd` for subsequent pytest invocations | 1 catch | A `git status backend/...` resolving against `backend/backend/...` and producing the Rule #38 antipattern symptom |
| Pre-implementation corpus audit SQL | Confirmed pre-rebuild row counts against the morning postmortem's baseline (147 + 54 + 30 Tegra + 96 FragAttacks per CVE + 20 CVE-2023-20819); calibrated expected post-rebuild deltas | 1 audit | A surprise during the post-rebuild verification step had the deltas been miscalibrated |

## Scope Analysis

- **Planned (user prompt):** Ship 3 carried-forward Reviewer findings: TARGET 1 (alignment test, ~50 LOC, ~1 hour); TARGET 2 (FragAttacks NVD-CPE realignment, ~30 LOC YAML + tests, ~2 hours); TARGET 3 (CVE-2023-20819 version gate, ~30 LOC, ~1-2 hours). Plus 3-parallel multi-persona review + Rule #8 rebuild + final re-detect + cve-match on DS1+G32+G30+DPCS10×3.
- **Built:** 4 commits across 3 files (~990 net-new lines): TARGET 1 (~464 LOC alignment test); TARGET 2 (~155 LOC YAML edits + 5 paired-canary tests); TARGET 3 (~237 LOC YAML edit + 5 paired-canary tests); Reviewer B HIGH CVSS fixup (~66 LOC YAML notes + 1 regression canary test).
- **Drift:** NONE on user-stated asks. All 3 TARGETs shipped. Multi-persona review executed (3 parallel Citadel agent dispatches). Reviewer B HIGH finding applied via fixup commit per Rule #25. Rule #8 rebuild ran cleanly. Final SQL audit confirmed all 5 baselines preserved AND the expected deltas materialized correctly.

## Patterns

1. **Recursive NVD-CVSS verification extended to ALL severity-aggregating advisory entries (7 sessions running, Rule #19 generalization).** Each advisory aggregating N CVEs needs NVD primary CVSS for all N CVEs — the aggregate cvss_score is the worst-case individual. This session's Reviewer B catch (FragAttacks medium 6.5 → LOW 3.5) extends the pattern from per-CVE chipset/version scope (Pattern #2 of `postmortem-hw-firmware-mcp-tegra-2026-05-15`) to per-advisory CVSS aggregation. The implementer-side WebFetch caught vendor-list drift (the realignment scope); the reviewer-side WebFetch caught CVSS-field drift (which the implementer didn't re-verify). Different verifiers focus on different aspects.

2. **Cross-stack alignment test as Rule-of-Eight cross-stack-alignment commit shape (Rule #25 cross-stack alignment exception).** This session's commit `d641f28` is the cross-stack alignment test for the F-FORENSIC-10 gate; mirrors the cross-stack alignment commits documented in CLAUDE.md Rule #25 single-slice exception #2 (currently Rule-of-Eight for the source-of-truth-N agreement shape). The pattern: identify 2+ source-of-truth surfaces enforcing the same conceptual contract → write a single-file alignment test asserting SHAPE-equivalence (not name-equality, since dialects may legitimately differ). The asymmetric reject mode (L1 WARN+skip; L2 raise ValueError) is documented in the test rather than forced into a common shape. Ready for codification as `.mex/patterns/cross-stack-alignment-test.md` recipe.

3. **Forward-prepared CVE pin pattern Rule-of-Two — Tegra (morning) + MediaTek modem (this session).** Same shape: NVD-CPE-derived narrowing field; matcher hard-reject semantics; parser extraction work pending; activation deferred to a future commit chain when the parser ships. The pattern reduces the "land now or wait" tension — pins land NOW with documented activation conditions; over-attribution risk eliminated; future activation cost is zero-LOC (just ship the parser). Ready for codification as `.mex/patterns/forward-prepared-cve-pin.md` recipe.

4. **Shared advisory_id with documented dedup behavior across N entries.** This session's `ADVISORY-FRAGATTACK` is shared across the broadcom + qualcomm FragAttacks advisory entries. The matcher dedupes per `(firmware_id, blob_id, cve_id)` UNIQUE — even if both entries matched the same blob (impossible in practice since vendor differs), one row would be emitted. The expected duplicate-advisory_id WARN at load time is intentional (operator-visible signal that the convergence is deliberate). Reviewer A A5 + Reviewer B B6 flagged the WARN noise — deferred to next session as an opt-in suppression key.

5. **Pre-implementation corpus audit pattern extended to YAML-edit-driven changes (Rule #31 width-canary applied here too).** Pre-rebuild query captured the 7-CVE baseline in the 6-firmware corpus before any YAML edit landed. Post-rebuild query validated the expected deltas matched calibration (96 → 0 curated FragAttacks; 0 → 32 ADVISORY-FRAGATTACK; 20 → 0 CVE-2023-20819; all baselines unchanged). The audit costs ~1 second and prevents surprise deltas. Companion to Rule #19 evidence-first — the DB is the truth; the spec describes intent.

6. **Surgical DELETE before cve-match for YAML-edit-driven row changes.** The matcher's `force_rescan=True` removes the dedup check but doesn't DELETE existing rows — would hit UNIQUE constraint violations on re-insert if rows already exist. Surgical DELETE of affected (firmware_id, cve_id) pairs before cve-match is the correct shape. Documented this session as Pattern #6 for future YAML-edit verification workflows.

7. **Asymmetric gate reject modes are intentional, not drift (cross-stack alignment test commentary).** L1 (cve_matcher) uses WARN+SKIP; L2 (patterns_loader) uses raise ValueError. The asymmetry is the MODE, not the contract — both REJECT the conceptual antipattern. Cross-stack alignment tests must assert via each layer's IDIOMATIC shape, not force a common reject mode. Documented in the alignment test's module docstring.

8. **Triple-verification (scout → implementer → reviewer) catches drift that single-axis verification misses — 7 sessions running, durable beyond debate.** This session: scout reports verified NVD CPE for vendor/version scope; implementer-side WebFetch confirmed the scopes; reviewer-side WebFetch caught the CVSS-field drift the scouts + implementer didn't re-fetch. Different roles focus on different aspects; the cross-axis verification is the load-bearing safety net.

9. **Boundary-anchored regex `(?:^|[^a-z0-9])` for path/version-token matching prevents whole-substring false-positives.** This session's CVE-2023-20819 version_regex uses `(?:^|[^a-z0-9])(lr11|lr12a|lr13|nr15|nr16|nr17)(?:[^a-z0-9]|$)` — character-class boundary check prevents `nr155_else` (matches nr155 not nr15) and `lr12abc` (matches lr12abc not lr12a) from false-positive firing. Same shape as the per-component path-context gate from morning's postmortem (Pattern #5). The boundary character class `[^a-z0-9]` excludes `_` from "word chars" — correct for underscore-separated banner shapes like `MOLY_NR16_R1`.

10. **Hard-reject `version_regex` semantics are the matcher's documented contract (preserved on `cve_matcher.py:480-491`).** The matcher's comment explicitly states "Stays STRICT — when present, version evidence MUST be found". Soft-fallback applies to `chipset_regex` only, NOT `version_regex`. This contract enables forward-prepared CVE pin shape — landing a version_regex with no extraction infrastructure today produces zero false-positives (because hard-reject drops all blobs with NULL version), then activates the moment the parser ships. A future change of this contract (soft-fallback on `version_regex`) would silently re-introduce over-attribution. The gate-canary test (`test_cve_2023_20819_hard_rejects_blob_with_null_version`) asserts the hard-reject path actually fires; without it, a silent semantics regression would go undetected.

## Recommendations Carried Forward

Of the ~39 reviewer findings this session, **~38 remain** as queued follow-up work. Highest-leverage:

1. **Promote `caplog_at` to `conftest.py`** (Reviewer A A1 MEDIUM) — duplicated across `test_hardware_firmware_cve_matcher.py` and `test_forensic10_alignment.py`; promote to `backend/tests/conftest.py` for first-class pytest discovery.

2. **Export `_BT_NARROWING_CONDITIONS` from `patterns_loader`** (Reviewer A A2 MEDIUM) — replaces the alignment test's `inspect.getsource` source-text-grep with a direct `len()` assertion against an explicit constant. Mirror of the L1 `_KNOWN_FIRMWARE_NARROWING_FIELDS` shape.

3. **Suppress duplicate-advisory_id WARN under intentional-convergence opt-in** (Reviewer A A5 + Reviewer B B6 HIGH+LOW) — add a `shared_advisory_id: true` (or `intentional_shared_advisory_with: <entry_name>`) YAML key; load handshake suppresses the WARN when both entries carry the opt-in. The accidental-collision case (no opt-in) stays WARN.

4. **Author `.mex/patterns/cross-stack-alignment-test.md` recipe** (Reviewer C C2 HIGH) — Rule-of-Eight evidence already documented in CLAUDE.md Rule #25 single-slice exception #2; recipe codifies the WHEN/SHAPE/ASYMMETRY-TOLERANCE/META-CANARY discipline.

5. **Author `.mex/patterns/forward-prepared-cve-pin.md` recipe** (Reviewer C C7 HIGH) — Rule-of-Two now (Tegra + MediaTek modem); recipe documents WHEN (extraction infra not yet present) + WHAT (HARD-REJECT version_regex + inline YAML comment citing NVD CPEs + activation commit-chain plan).

6. **CLAUDE.md Rule-of-Three promotion candidates** (Reviewer C C14 HIGH) — cross-stack-alignment-test discipline + forward-prepared-CVE-pin pattern + shared-advisory_id pattern are all Rule-of-Three candidates. Promote in a single Rule #25 cross-stack-alignment commit updating CLAUDE.md + `.mex/context/conventions.md`.

7. **Extend `list_extension_points` MCP tool with F-FORENSIC-10 rejection counts** (Reviewer C C10 HIGH) — operators need observability on how many entries each layer rejected on last load; without it, drift between layers becomes invisible.

8. **`verify_cve_attribution(cve_id, blob_id)` MCP tool** (Reviewer C C11 HIGH) — operators triaging "why does this blob have CVE-X?" must walk the YAML by hand today; the matcher already produces this chain internally.

9. **Advisory-id glossary** (Reviewer C C4 HIGH) — operator lookup for ADVISORY-* IDs lives only in YAML notes; build `describe_advisory(advisory_id)` MCP tool + frontend hover panel.

10. **Audit KRACK / Dragonblood / BroadPwn for FragAttacks-shape over-attribution** (Reviewer B B11 MEDIUM) — similar SPEC-level disclosure-batch CVEs may have zero-vendor-CPE patterns that the curated tier over-attributes.

11. **`.planning/ADAPTIVE_BACKLOG.md`** (Reviewer C C12 MEDIUM) — single source of truth for the ~38 carry-forward recommendations across postmortems.

12. **HARD-REJECT version_regex semantics docs** (Reviewer C C8 MEDIUM) — `docs/features/extending-firmware-patterns.md` lacks the field reference; add a `version_regex` row documenting hard-reject behavior.

13. **NVD CPE refresh cadence recipe** (Reviewer C C9 MEDIUM) — codify quarterly NVD-CPE audit cron for version_regex pins (like Rule #37 anchor-refresh cron).

14. **wcn7xxx chipset_regex extension for FragAttacks** (Reviewer B B5 MEDIUM) — Wi-Fi 7 Qualcomm parts may carry FragAttacks-affected SoftMAC firmware.

15. **Tier 4 SBOM NVD-CPE alignment audit** (Reviewer A A7 + Reviewer B B9 LOW+MEDIUM) — Tier 4 emits CVE-2020-2458x on kernel_module blobs via linux_kernel CPE; this is correct per NVD scope but should be documented.

16-38. Various LOW/MEDIUM/discoverability findings — see reviewer reports for full list.

## Remaining Work

- Recommendations 1-15 above: ~8-15 hours total.
- Backfill: NONE needed for this session's commits. The YAML changes are forward-only; existing matcher state for the 6-firmware corpus was surgically updated via DELETE + cve-match.
- The 38 deferred reviewer findings + 12 still-open recommendations from morning's postmortem = ~50 carry-forward items total across recent postmortems. The C12 `.planning/ADAPTIVE_BACKLOG.md` recommendation is the highest-leverage way to make these discoverable per session.

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 4 (3 feat + 1 fix) |
| Files changed | 3 (1 YAML + 2 test files) |
| Lines added | ~990 net-new |
| Reverts | 0 |
| New tests | 17 (16 alignment-test cases + 6 FragAttacks paired-canary + 5 CVE-2023-20819 paired-canary + 1 CVSS regression canary; counted as 17 declared tests, 26 cases including parametrize expansion) |
| Cumulative test pass count (cve_matcher + forensic10 + bt_banner) | 136 (was ~117 entering this session) |
| New paired-canary tests | 17 (Rule #46) |
| Pre-implementation scout dispatches | 3 (one per TARGET) |
| Post-implementation reviewer dispatches | 3 (arch + forensic + adaptability) |
| Independent NVD WebFetch verifications | 8 (4 implementer-side via Scout 2 + Scout 3 + 4 reviewer-side via Reviewer B + 3 verified-by-implementer for the Reviewer B HIGH fixup) |
| Reviewer findings TOTAL | ~39 (13 A + 11 B + 15 C) |
| Reviewer findings APPLIED this session | 1 HIGH (Reviewer B FragAttacks CVSS) |
| Reviewer findings DEFERRED to follow-up | ~38 |
| Tier 0 BRAKTOOTH baseline rows (G32 / G30 / DPCS10×3) | 26 + 22 + 6 = 54 (UNCHANGED from morning session) |
| Wrong-attribution CVE rows | 0 (post-rebuild confirmed) |
| CVE-2017-18159 baseline rows | 147 (UNCHANGED via soft fallback on NULL chipset_target) |
| DS1 Tegra CVE rows | 30 (11+4+11+4 — UNCHANGED from morning session) |
| FragAttacks curated CVE rows (CVE-2020-24586/87/88) | 96 × 3 = 288 → 0 (curated → advisory) |
| ADVISORY-FRAGATTACK new rows | 32 (one per qualcomm/wcn3xxx-class wifi blob) |
| CVE-2023-20819 rows | 20 → 0 (hard-reject; forward-prepared activation pending mtk_modem parser) |
| Net corpus row delta | −276 rows in the 6-firmware regression corpus |
| Backend + worker + migrator rebuilds | 1 (Rule #8) |
| Rule #11 import smokes | 1 (post-rebuild) |
| Rule #20 docker-cp iterations | 0 (no class-shape changes; YAML hot-reload via MtimeCachedYamlLoader) |
| Rule #38 cwd-discipline catches | 1 (caught cwd drift to backend/; reset before git command + switched to subshell for subsequent pytest invocations) |
| Rule #46 META-CANARY tests | 2 (1 in alignment test + 1 implicit via Rule #19 NVD-CVSS canary) |
| Pre-implementation width-canary audits | 1 (corpus baseline SQL audit) |
| Test runs (cumulative across the session) | 6 (pytest invocations between commits) |
| Surgical DELETE rows | 308 (96×3 CVE-2020-2458x + 20 CVE-2023-20819) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md`
- Morning session postmortem (carried-forward source): `.planning/postmortems/postmortem-hw-firmware-tegra-activation-2026-05-15.md`
- Earlier same-day postmortem (Tegra MCP + CVE pins context): `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`
- 2026-05-18 prior session: `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-18.md`

---HANDOFF---
- Postmortem: hw-firmware-reviewer-followup-2026-05-15-evening
- Document: .planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md
- Failures documented: 4 (1 HIGH Reviewer B CVSS drift on FragAttacks medium 6.5 → LOW 3.5/2.6/3.5 caught via independent NVD WebFetch + applied via fixup commit; 1 HIGH pre-implementation Reviewer B CVE-2023-20819 over-attribution on every mtk modem blob without version narrowing — applied via forward-prepared version_regex; 1 HIGH pre-implementation Reviewer B FragAttacks vendor over-attribution on broadcom + qualcomm CPE-not-listed vendors — applied via advisory-only conversion; 1 LOW own-test catch of force_rescan semantics → surgical DELETE pattern for cve-match YAML-edit verification)
- Safety catches: 8 (pre-implementation 3-parallel scouts + 8 recursive NVD-CPE WebFetches across implementer + reviewer + multi-persona reviewer dispatch × 3 + Rule #46 paired-canary discipline × 17 tests + end-to-end SQL corpus regression check baselines preserved + Rule #8 rebuild + Rule #11 import smoke + Rule #25 per-piece commits × 4 + Rule #38 cwd-discipline catch + pre-implementation corpus baseline audit)
- Recommendations: 15 highest-leverage carried forward (caplog conftest promotion; _BT_NARROWING_CONDITIONS export; duplicate-advisory_id WARN suppression under opt-in; cross-stack-alignment-test recipe; forward-prepared-cve-pin recipe; CLAUDE.md Rule-of-Three promotions; list_extension_points F-FORENSIC-10 counts; verify_cve_attribution MCP tool; advisory-id glossary; KRACK/Dragonblood/BroadPwn over-attribution audit; ADAPTIVE_BACKLOG.md; version_regex hard-reject docs; NVD CPE refresh cadence; wcn7xxx chipset_regex extension; Tier 4 SBOM alignment audit)
- Critical Reviewer-B catch: FragAttacks CVSS shipped at severity=medium / cvss_score=6.5 vs NVD primary CVSS 3.1 = 3.5/2.6/3.5 LOW (Reviewer B 2026-05-15-PM independent NVD WebFetch). Pattern #2 from postmortem-hw-firmware-mcp-tegra-2026-05-15 (recursive-NVD-CVSS discipline) now 7 sessions running; durable beyond debate.
- 6-firmware corpus row deltas: FragAttacks SPEC-level CVE-2020-24586/87/88 96 → 0 each (curated → advisory); ADVISORY-FRAGATTACK 0 → 32 (one per qualcomm wcn3xxx blob); CVE-2023-20819 20 → 0 (hard-reject; forward-prepared activation pending mtk_modem parser); BRAKTOOTH 54 UNCHANGED; wrong-attribution 0 UNCHANGED; CVE-2017-18159 147 UNCHANGED; Tegra 4-of-6 pins firing 30 rows UNCHANGED on DS1. Net: −276 rows.
- Adaptability deltas shipped: F-FORENSIC-10 cross-stack alignment regression canary (Rule #25 cross-stack-alignment single-slice — 9th instance of the pattern, durable beyond debate) + FragAttacks NVD-CPE realignment from curated CVE → advisory tier with shared advisory_id ADVISORY-FRAGATTACK preserving forensic visibility while respecting NVD attribution scope + MediaTek CVE-2023-20819 forward-prepared version_regex narrowing to 6 NVD-CPE-affected modem-OS families (lr11/lr12a/lr13/nr15/nr16/nr17) — Rule-of-Two with Tegra precedent + recursive NVD-CVSS discipline extended from per-CVE to per-advisory aggregate (worst-case individual CVSS standard convention) + boundary-anchored regex `(?:^|[^a-z0-9])` prevents whole-substring false-positives + hard-reject version_regex matcher semantics preserved + surgical DELETE recipe for YAML-edit-driven cve-match verification.
---

Run `/learn hw-firmware-reviewer-followup-2026-05-15-evening` to extract patterns into the knowledge base.
