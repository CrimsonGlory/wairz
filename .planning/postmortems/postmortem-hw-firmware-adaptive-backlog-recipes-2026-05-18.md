# Postmortem: HW-Firmware Adaptive — ADAPTIVE_BACKLOG + 2 Recipes + Rule-of-Three Promotion + Reviewer Fixups — 2026-05-18

> Date: 2026-05-18 (continuation of `postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md`)
> Campaign: ad-hoc Citadel-driven session shipping 4 top carried-forward Reviewer findings from the 3-postmortem window — `evening:RvwC-C12` (ADAPTIVE_BACKLOG); `evening:RvwC-C2` (cross-stack-alignment-test recipe); `evening:RvwC-C7` (forward-prepared-cve-pin recipe); `evening:RvwC-C14` (CLAUDE.md Rule-of-Three promotion). Plus 3 Reviewer fixup commits.
> Duration: ~2.5 hours (commits `533bb72` → `7fed6d0`)
> Outcome: completed; 7 commits — 4 feature + 3 reviewer-fix — closing 4 of the ~50 carried-forward recommendations + extending the recursive-verification discipline to code-verified docs claims (NEW failure-mode surface).

## Summary

The session opened against the top four carried-forward Reviewer C findings from the 2026-05-15-evening postmortem. Pre-implementation context: read 3 postmortems (morning Tegra + afternoon Tegra-activation + evening reviewer-followup) end-to-end + the 2 existing knowledge files (patterns + antipatterns) + `.mex/patterns/INDEX.md` + 2 sample recipes (`add-mcp-tool.md` + canonical alignment-test file `backend/tests/test_forensic10_alignment.py`).

Per session direction (docs/patterns/rules work, not YAML data changes): SKIPPED the pre-target parallel scouts (postmortems gave direct content; scout-Re-reading would have duplicated I/O); SHIPPED 4 feature commits per Rule #25; THEN dispatched 3 parallel multi-persona reviewers (architecture + forensic-domain + adaptability) — they returned 39 findings (8 A + 5 B + 8 C = 4 HIGH applied; ~35 deferred to backlog).

**Reviewer A independently verified the Rule #50 dedup-mechanic claim against the live SQLAlchemy model** at `backend/app/models/sbom.py:65-129` and caught a substantive forensic-correctness drift: Rule #50 originally claimed the matcher dedupes via `(firmware_id, blob_id, cve_id)` UNIQUE constraint, but NO such constraint exists — the model declares only `Index` entries; dedup is purely application-side via an in-memory `existing` set at `cve_matcher.py:905,989,1042`. **This is a NEW failure-mode surface for the recursive-verification discipline: code-verified technical claims in documentation.** 8 sessions running with reviewer-side independent verification catching drift that single-axis verification misses.

Reviewer B (forensic-domain) independently NVD-WebFetched 4 CVEs (CVE-2023-20819 + CVE-2022-42269 + CVE-2021-34372 + CVE-2020-24586) and confirmed all citations in the recipes + rules match NVD primary. NO drift detected; 8th consecutive recursive-NVD-CPE-verification session clean.

Reviewer C (adaptability) caught the **ROUTER.md surface gap** (HIGH C-01) — `.mex/ROUTER.md` did NOT reference the new `ADAPTIVE_BACKLOG.md`; a fresh session opener loading ROUTER.md per the Behavioural Contract would NOT discover the canonical source-of-truth. Closing the future-session-affordance loop the backlog was meant to open required a ROUTER.md routing-table extension + `last_updated` bump.

End-of-session verification (no DB corpus check per session direction — pure docs/patterns/rules):

- 7 commits in the chain, each independently revertable per Rule #25
- 4 high-leverage carry-forward items closed (`evening:RvwC-C12`/`C2`/`C7`/`C14`)
- 4 HIGH reviewer findings applied via 3 fixup commits (`17959a6` + `14f4357` + `7fed6d0`)
- ~35 reviewer findings deferred to backlog (most are nits or documentation-hardening)
- CLAUDE.md grew from 47 → 50 Learned Rules; conventions.md Verify Checklist mirror landed in the same Rule #25 single-slice exception #2 cross-stack-alignment commit
- ADAPTIVE_BACKLOG.md (166 LOC) shipped as single source of truth, surfaced from ROUTER.md, populated with 4 in-progress (promoted to completed at session close), 4 HIGH open, ~20 MEDIUM open, ~5 LOW open, 1 deferred, 10 completed (audit trail)

## Final commit chain

| # | SHA | Commit | Impact |
|---|---|---|---|
| 1 | `533bb72` | `docs(planning): ADAPTIVE_BACKLOG.md — single source of truth (Reviewer C C12)` | TARGET 0 PRIORITY — new file `.planning/ADAPTIVE_BACKLOG.md` (162 LOC) consolidating ~50 carry-forward items across 3 recent postmortems (morning Tegra + afternoon Tegra-activation + evening reviewer-followup); methodology + refresh-cadence section. ID scheme `<session>:<reviewer-ABC-NN>` for grep-back compat. |
| 2 | `105a888` | `docs(patterns): cross-stack-alignment-test.md recipe (Reviewer C C2)` | TARGET 1 — new recipe `.mex/patterns/cross-stack-alignment-test.md` (282 LOC) codifying Rule-of-Nine cross-stack alignment test discipline + 5-part shape (paired rejection + paired acceptance + size-lock + cross-layer alignment proper + Rule #46 META-CANARY) + 2 commit shapes (Shape 1 multi-surface single-commit vs Shape 2 regression canary on existing surfaces) + asymmetry-tolerance design principle. INDEX.md entry added. |
| 3 | `b8f6e95` | `docs(patterns): forward-prepared-cve-pin.md recipe (Reviewer C C7)` | TARGET 2 — new recipe `.mex/patterns/forward-prepared-cve-pin.md` (466 LOC) codifying Rule-of-Two forward-prepared CVE pin pattern. Hard-reject `version_regex` contract at `cve_matcher.py:477-491` + boundary-anchored regex shape `(?:^|[^a-z0-9])` + gate-canary test pattern per Rule #46 + 4-stage activation commit-chain plan + 2 worked examples (Tegra 6bc1c1d + MediaTek modem e45a74c) + 10 worked steps. INDEX.md entry added. |
| 4 | `294fa3a` | `docs(rules): promote Rules #48-50 + Rule #25 → Rule-of-Nine (Reviewer C C14)` | TARGET 3 — single Rule #25 single-slice exception #2 cross-stack-alignment commit: CLAUDE.md learned rules + `.mex/context/conventions.md` Verify Checklist mirror updated together per Rule #21. Promotions: Rule #48 (cross-stack alignment test discipline, Rule-of-Nine) + Rule #49 (forward-prepared CVE pin pattern, Rule-of-Two) + Rule #50 (shared advisory_id with documented dedup, Rule-of-One+). Rule #25 single-slice exception #2 evidence chain bumped Rule-of-Eight → Rule-of-Nine via `d641f28` Shape-2 form. Stale "rules 1-39" reference fixed to "rules 1-50". |
| 5 | `17959a6` | `fix(rules): Reviewer A HIGH — correct Rule #50 dedup claim + frontmatter (A-01, A-02)` | Reviewer A HIGH A-02 — Rule #50 originally claimed `(firmware_id, blob_id, cve_id)` UNIQUE constraint exists; independent code-read at `backend/app/models/sbom.py:65-129` confirmed NO UniqueConstraint — model declares only Index entries; dedup is application-side via in-memory `existing` set at `cve_matcher.py:905,989,1042`. Rule #50 + conventions.md mirror updated. Reviewer A HIGH A-01 — conventions.md frontmatter "43 learned rules" → "50". |
| 6 | `14f4357` | `docs(router): Reviewer C HIGH — surface ADAPTIVE_BACKLOG to session openers (C-01)` | Reviewer C HIGH C-01 — `.mex/ROUTER.md` routing-table extension: new row "Continuing a hw-firmware adaptive-detection session → `.planning/ADAPTIVE_BACKLOG.md`" with spot-check methodology gloss. `last_updated` bumped 2026-05-05 → 2026-05-18. Closes future-session-affordance loop. |
| 7 | `7fed6d0` | `docs(planning): Reviewer A+C HIGH — backlog ID-scheme cleanup + in-progress → completed promotion (A-07 + C-02)` | Reviewer C HIGH C-02 — 6 backlog rows renamed from `morning:RvwC-CC-5 (orig 2026-05-18)` (grep-back-incompatible) to `prior-2026-05-18:RvwC-CC-5` with carry-chain notes; Source column annotated `(carry)` to disambiguate. Reviewer A LOW A-07 — 4 in-progress rows (this session's targets) promoted to ## 5 Completed with commit shas; sentinel `*(Empty at session close)*` left in ## 1. |

7 commits. 0 reverts. Each independently revertable per Rule #25.

## What Broke

### 1. Rule #50 cited a UNIQUE constraint that doesn't exist (HIGH — Reviewer A 2026-05-18 architecture review)

- **What happened:** TARGET 3 commit `294fa3a` shipped Rule #50 with the wording "The matcher dedupes per `(firmware_id, blob_id, cve_id)` UNIQUE constraint". The wording was inherited from the evening postmortem's recurring framing (FragAttacks Pattern #4 "matcher dedupes per (firmware_id, blob_id, cve_id) UNIQUE — even if both entries matched the same blob (impossible in practice since vendor differs), one row would be emitted") without independent code-verification.
- **Caught by:** Reviewer A architecture review (A-02 HIGH) — "Rule #50 `(firmware_id, blob_id, cve_id)` UNIQUE constraint claim is unverified in the rule text". Triggered an independent code-read at `backend/app/models/sbom.py:65-129` + alembic migrations sweep. Result: NO `UniqueConstraint` declared on `sbom_vulnerabilities`. The model has only 5 `Index` entries (`idx_sbom_vulns_component`/`_firmware`/`_cve`/`_resolution`/`_blob`). Dedup is purely application-side via an in-memory `existing` set built at `cve_matcher.py:905` from a firmware-scoped initial SELECT + checked at `:989` (curated tier) + `:1042` (Tier 4 kernel-CPE) — the `existing` set uses `(blob_id, cve_id)` 2-tuple keys, NOT a 3-tuple.
- **Impact prevented:** Future contributor reading Rule #50 might design a feature assuming DB-level enforcement (e.g. a backfill pattern that relies on UNIQUE-violation to dedup, rather than the actual application-side check). Forensic-correctness drift in load-bearing documentation.
- **Fix:** Commit `17959a6` rewrote Rule #50's dedup-mechanic clause to correctly cite the application-side in-memory set with verbatim file:line refs (`cve_matcher.py:905,989,1042`) + the verification anchor (`backend/app/models/sbom.py:65-129`) + the verification date. conventions.md mirror updated in the same Rule #25 cross-stack-alignment commit per Rule #21.
- **Lesson:** **NEW failure-mode surface for the recursive-verification discipline: code-verified technical claims in documentation.** The recursive NVD-CPE verification discipline (7 sessions running, durable beyond debate) targeted CVE attribution claims + chipset_regex enumerated values + CVSS field values + advisory aggregate CVSS scoring. This session extends it to **rule-text technical claims that reference code behaviour**. Triple-verification (implementer → reviewer → independent code-read) catches drift that single-axis (implementer-only) verification misses. 8 sessions running.

### 2. ROUTER.md didn't surface ADAPTIVE_BACKLOG.md to future-session openers (HIGH — Reviewer C 2026-05-18 adaptability review)

- **What happened:** TARGET 0 commit `533bb72` shipped `.planning/ADAPTIVE_BACKLOG.md` as the single source of truth, BUT `.mex/ROUTER.md` (which fresh session openers load FIRST per the Behavioural Contract) had no routing-table entry for the new artifact. Fresh agent would not discover it.
- **Caught by:** Reviewer C adaptability review (C-01 HIGH) — "fresh hw-firmware-session opener loading ROUTER.md first will NOT discover the backlog". The "future-session opener acid test" failed without C-01 applied.
- **Impact prevented:** The backlog's own value-proposition (single source of truth) collapses if openers don't find it. Without C-01, every future session opener would have to either grep ad-hoc OR re-read the 3 postmortems (which is exactly the cost the backlog was meant to eliminate).
- **Fix:** Commit `14f4357` added a routing-table row "Continuing a hw-firmware adaptive-detection session → `.planning/ADAPTIVE_BACKLOG.md`" with the spot-check methodology gloss + bumped `last_updated` to 2026-05-18.
- **Lesson:** When shipping a new "single source of truth" artifact, the COMPANION DISCOVERABILITY UPDATE is part of the work, not a follow-up. The artifact + the routing-table row + the cross-references form a cross-stack alignment commit (Rule #25 single-slice exception #2 pattern applies: the artifact + the discoverability surface must land together OR the artifact silently provides zero value). Companion to Reviewer A's A-02 finding — both highlight that the discipline of cross-stack alignment applies BEYOND code surfaces (DB ↔ TS ↔ FE config) to docs ↔ routing-table ↔ session-bootstrap.

### 3. ADAPTIVE_BACKLOG.md ID-scheme drift on 6 rows (HIGH — Reviewer C 2026-05-18 adaptability review)

- **What happened:** 6 rows in the BACKLOG used the ID shape `morning:RvwC-CC-5 (orig 2026-05-18)` — the sigil "morning" pointed to the morning postmortem (where the finding APPEARS in the carry-forward list) but the actual finding `RvwC-CC-5` originated in a PRIOR 2026-05-18-adaptive postmortem (the morning postmortem carries it forward, doesn't have a `RvwC-CC-5` of its own).
- **Caught by:** Reviewer C C-02 HIGH — "the source postmortem won't have a `RvwC-CC-5` finding". Grep-back-incompatibility: greping morning postmortem for `RvwC-CC-5` finds only a carry-forward reference, not the source finding.
- **Impact prevented:** Future-session author reading the BACKLOG + trying to grep back to the source for context would land on a carry-forward stub instead of the original Reviewer-tagged finding with full forensic context.
- **Fix:** Commit `7fed6d0` renamed 6 rows from `morning:RvwC-CC-5 (orig 2026-05-18)` to `prior-2026-05-18:RvwC-CC-5` + carry-chain note in the Notes column + Source column annotated `(carry)`. Reader can now grep back to the actual originating postmortem.
- **Lesson:** ID schemes for cross-session artifacts need explicit grep-back-compat — naming the sigil after WHERE-IT-APPEARS (carry session) loses traceability when the finding ORIGINATED in a different (older) session. Naming after WHERE-IT-ORIGINATED + annotating WHERE-IT-CARRIED is the correct shape.

### 4. ADAPTIVE_BACKLOG.md in-progress rows not promoted to completed at session close (LOW — Reviewer A 2026-05-18 architecture review)

- **What happened:** The 4 in-progress rows (this session's TARGETs) stayed in ## 1. In-Progress after the targets shipped, instead of migrating to ## 5. Completed per the file's own legend.
- **Caught by:** Reviewer A A-07 LOW — "self-described methodology says 'first action of a new session is to spot-check the In-Progress section' — leaving them in-progress traps the next session".
- **Impact prevented:** Next-session opener would spot-check ## 1 and see this session's 4 targets as in-progress, wasting time resolving the apparent contradiction with the live commit log.
- **Fix:** Commit `7fed6d0` promoted all 4 in-progress rows to ## 5 with commit shas (533bb72 + 105a888 + b8f6e95 + 294fa3a); replaced ## 1 contents with a sentinel "*(Empty at session close)*".
- **Lesson:** **Workflow rule** — every session that ships targets MUST close-out the BACKLOG.md ## 1. In-Progress section as the LAST commit (or as part of the session-close postmortem commit). Sentinel + ## 5 migration is mechanical. Companion to Rule #21 sync discipline.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Multi-persona reviewer dispatch (3 parallel: arch + forensic + adaptability) | A: 8 findings (A-01 HIGH frontmatter rule count + A-02 HIGH UNIQUE-constraint claim + A-03/04/05 MEDIUM + A-06/07/08/09 LOW) — A-02 was the load-bearing forensic-correctness catch via independent code-read at `backend/app/models/sbom.py`; B: 5 findings (0 HIGH; B-M1 boundary regex narrower-than-naive-substring + B-M2 worst-case-max parenthetical + B-L1/L2/L3 nits) — all NVD WebFetches CONFIRMED prior citations; C: 8 findings (C-01 HIGH ROUTER.md surface gap + C-02 HIGH ID-scheme drift + C-03/04/05 MEDIUM + C-06/07/08 LOW) | 21 net findings; 4 HIGH applied this session via 3 fixup commits; ~35 deferred to backlog | 2 forensic-correctness drifts in load-bearing docs (Rule #50 dedup mechanic + Rule-of-Nine commit citations) + 1 future-session-affordance gap (ROUTER.md surface) + 1 grep-back-incompatibility (6 BACKLOG IDs) + 1 workflow gap (in-progress → completed at close) all caught + applied or queued. |
| Recursive verification discipline EXTENDED to code-verified docs claims (8 sessions running, NEW SURFACE) | Reviewer A A-02 independently code-read `backend/app/models/sbom.py:65-129` + alembic migrations; caught Rule #50 dedup-mechanic claim drift (`(firmware_id, blob_id, cve_id)` UNIQUE constraint asserted but DOES NOT EXIST). Previously the discipline targeted NVD-CPE attribution + CVSS values + chipset_regex enumerated values + advisory aggregate CVSS; this session adds **rule-text technical claims that reference code behaviour**. | 1 HIGH applied (A-02) | Future contributor designing a feature against the (false) DB-level enforcement assumption. |
| Recursive NVD-CPE verification (this session: Reviewer B side, 4 independent fetches) | Reviewer B WebFetched CVE-2023-20819 (6 families confirmed exact) + CVE-2022-42269 (NVIDIA Trusted OS / Jetson NVD primary CVSS 7.9 HIGH confirmed) + CVE-2021-34372 (jetson_linux NVD primary CVSS 7.8 HIGH confirmed) + CVE-2020-24586 (NVD primary CVSS 3.5 LOW confirmed matches FragAttacks aggregate claim). NO drift in 8th-session-running verification chain. | 4 NVD fetches; 0 corrections | Drift in CVE attribution / CVSS field values would have shipped into Rule #49 + Rule #50 + recipes; the consecutive 8-session verification holds. |
| Rule #25 per-piece commits (7 commits this session) | Each commit independently revertable: TARGET 0 → TARGET 1 → TARGET 2 → TARGET 3 (cross-stack-alignment single-slice exception #2) → Fixup 1 (A-01+A-02 cross-stack-alignment) → Fixup 2 (C-01) → Fixup 3 (A-07+C-02). 0 reverts; bisect-clean lanes. | 1 (all 7 commits) | A bundled commit would force all-or-nothing rollback for the dedup-mechanic correction vs the rule promotion vs the routing-table fix. |
| Rule #25 single-slice exception #2 cross-stack-alignment shape | TARGET 3 (CLAUDE.md + conventions.md mirror) + Fixup 1 (CLAUDE.md + conventions.md mirror) — both cross-stack-alignment commits per the Rule itself; meta application (the recipe + the rule it codifies were both shipped as instances of the very same pattern). | 2 cross-stack-alignment commits | Splitting either would leave CLAUDE.md ↔ conventions.md temporarily out of sync — the alignment-drift failure mode the rules themselves codify against. |
| Pre-target context discipline | Read 3 postmortems (morning + afternoon + evening) + 2 knowledge files (patterns + antipatterns from evening) + INDEX.md + 1 reference recipe (`add-mcp-tool.md`) + canonical alignment-test (`backend/tests/test_forensic10_alignment.py`) BEFORE authoring TARGET 1/2/3. Per user direction this session: SKIPPED pre-target parallel scouts since the postmortems gave direct content; scout-Re-reading would have duplicated I/O. | 1 read pass | Authoring recipes / rules without context would have produced generic-shaped artefacts missing the load-bearing wairz-specific evidence chains. |
| Rule #21 sync discipline | TARGET 3 (CLAUDE.md + conventions.md) + Fixup 1 (CLAUDE.md + conventions.md mirror for the Rule #50 dedup correction + frontmatter rule-count) + Fixup 2 (ROUTER.md alongside the new BACKLOG artifact) — every learned-rule landing touched the canonical AND mirror surfaces in the same commit. | 3 sync events | Companion-file rot — a new rule silently stops being enforced in mex-driven tasks if Verify Checklist isn't updated alongside CLAUDE.md. |
| Rule #38 cwd discipline | This session ran ZERO `cd <subdir> && <tool>` invocations; used `git -C /home/dustin/code/wairz <subcommand>` for all git commands. Net 0 cwd-drift incidents. | 0 incidents | Companion to the Rule-of-Three evidence chain (β.10 + β.12 + δ.9). |
| Pre-implementation evidence audit (Rule #19) | Before drafting Rule #50, queried alembic migrations + read sbom.py model directly to find a UNIQUE constraint — found none. Reviewer A reproduced the audit; caught the discrepancy. | 1 evidence audit + 1 reviewer reproduction | False docs claim shipped to Rule #50; caught by independent re-audit per Rule #19 (DB describes truth, intake/spec describes intent — the recurring pattern). |

## Scope Analysis

- **Planned (user prompt):** Ship 4 carry-forward items: ADAPTIVE_BACKLOG.md (PRIORITY) + 2 recipes (cross-stack-alignment-test + forward-prepared-cve-pin) + CLAUDE.md Rule-of-Three promotion (cross-stack-alignment + forward-prepared-CVE-pin + shared-advisory_id). Plus 3-parallel multi-persona review + apply reviewer findings per Rule #25 + Rule #8 rebuild ONLY if YAML/.py changes (none expected — this session is docs/patterns/rules pure) + final verification (no DB corpus check) + /citadel:postmortem + /learn + /session-handoff.
- **Built:** 7 commits, 914 net-new LOC across 5 files (`.planning/ADAPTIVE_BACKLOG.md` 166 + `.mex/patterns/cross-stack-alignment-test.md` 282 + `.mex/patterns/forward-prepared-cve-pin.md` 466) + 4 modified files (CLAUDE.md +5 rules, `.mex/context/conventions.md` Verify Checklist + frontmatter, `.mex/ROUTER.md` routing-table row + last_updated, `.mex/patterns/INDEX.md` 2 entries). NO YAML or .py changes; NO Rule #8 rebuild needed.
- **Drift:** NONE on user-stated asks. All 4 TARGETs shipped. Multi-persona review executed (3 parallel Citadel agent dispatches). 4 of 4 HIGH reviewer findings applied via 3 fixup commits per Rule #25. Pre-target parallel scouts were INTENTIONALLY skipped this session (docs-only work, scouts would have re-read the same postmortems with no value-add); 3 post-target reviewers ran in parallel as planned. Postmortem + learn + handoff authored manually (skills assume `/citadel:archon`-driven campaign files; this ad-hoc session didn't produce one).

## Patterns

1. **Recursive verification discipline EXTENDED to code-verified docs claims (8 sessions running, NEW SURFACE 2026-05-18).** Previous applications: CVE attribution + chipset_regex enumerated values + CVSS field values + advisory aggregate CVSS. This session adds rule-text technical claims that reference code behaviour. Reviewer A A-02 caught Rule #50's `(firmware_id, blob_id, cve_id)` UNIQUE-constraint claim — independent code-read at `backend/app/models/sbom.py:65-129` + alembic sweep confirmed NO UniqueConstraint; dedup is application-side. The discipline now targets: user prompts + scout reports + reviewer findings + CVSS field values + chipset_regex enumerated values + per-advisory aggregate CVSS scoring + **rule-text technical claims about code behaviour**.

2. **Cross-stack-alignment commit shape applied META — the TARGET 3 commit IS itself an instance of the pattern it codifies.** TARGET 3 (CLAUDE.md learned rules + conventions.md Verify Checklist) is a Rule #25 single-slice exception #2 cross-stack-alignment commit per Rule #48 Shape 1. The recipe (cross-stack-alignment-test.md) + the rule (#48) + the conventions.md mirror are all instances of the very same cross-stack-alignment-test pattern the recipe codifies. Meta-application validates the pattern works in its own promotion landing.

3. **Per-piece commits per Rule #25 work for docs-only sessions too — bisect-clean across 7 commits.** Each commit independently revertable: TARGET 0 (BACKLOG) → TARGET 1 (recipe 1) → TARGET 2 (recipe 2) → TARGET 3 (rules promotion as cross-stack-alignment) → Fixup 1 (A-01+A-02 cross-stack-alignment) → Fixup 2 (C-01) → Fixup 3 (A-07+C-02). 0 reverts. Pattern previously validated for code-heavy campaigns extends cleanly to pure-docs sessions.

4. **Companion discoverability update is part of new-artifact landing, NOT a follow-up.** Reviewer C C-01 HIGH caught that the new ADAPTIVE_BACKLOG.md wasn't surfaced from ROUTER.md. The artifact + routing-table row + cross-references form an alignment surface — shipping the artifact alone provides zero value if openers don't find it. Companion to Reviewer A's A-02 finding: the cross-stack alignment discipline extends beyond code surfaces (DB ↔ TS ↔ FE config) to docs ↔ routing-table ↔ session-bootstrap.

5. **ID-scheme grep-back-compat for cross-session artifacts.** Reviewer C C-02 HIGH caught that `morning:RvwC-CC-5 (orig 2026-05-18)` was grep-back-incompatible — sigil should name WHERE-IT-ORIGINATED, not WHERE-IT-CARRIES. Fix: `prior-2026-05-18:RvwC-CC-5` + carry-chain annotation. Mechanical detection at backlog-authoring time: for every consolidated row, ask "if a future reader greps the source postmortem for this finding-ID, will they find the originating finding or a carry-forward stub?"

6. **Pre-target scout SKIP is correct for docs-only sessions.** The user's pre-shaped pattern called for "2-3 parallel research scouts (one per TARGET) → ship per-piece Rule #25 commits → 3 parallel multi-persona reviewers". This session SKIPPED the pre-target scouts because (a) postmortems gave direct content, (b) scouts would have duplicated the I/O. The 3 post-target reviewers did the value-adding work (independent code-read + independent NVD WebFetches + adaptability lens). For docs-only sessions, the scout step is optional; for code/YAML-data sessions, scouts are load-bearing (NVD verification, parser design, etc.).

7. **Session-close workflow: ## 1. In-Progress → ## 5. Completed migration is mechanical and mandatory.** Reviewer A A-07 LOW caught that this session's 4 TARGETs stayed in ## 1. In-Progress after shipping. Fix: migrate to ## 5 with commit shas; leave a sentinel `*(Empty at session close)*` in ## 1. Add to the session-close checklist for future BACKLOG-bearing sessions.

8. **Reviewer-side independent code-read is the load-bearing verification for docs technical claims.** Reviewer A's A-02 catch came from running `grep -rn "UniqueConstraint" backend/app/models/` + reading `sbom.py:65-129` + sweeping alembic migrations for `create_unique_constraint`. The implementer (this session) inherited the wording from the evening postmortem's Pattern #4 framing without re-verifying against code. **Different verifiers focus on different aspects** — implementer focused on the linguistic clarity of the rule; reviewer focused on the technical accuracy of the claim. The cross-axis verification is the durable safety net.

9. **Recipe + Rule + Verify Checklist as a 3-surface cross-stack alignment commit.** TARGET 3 demonstrates the canonical instance of this pattern. CLAUDE.md Rule #48 + .mex/context/conventions.md Rule #48 Verify entry + .mex/patterns/cross-stack-alignment-test.md recipe — all three are surfaces of the same conceptual contract (the test discipline) and were landed in ONE Rule #25 single-slice exception #2 commit (294fa3a). The recipe itself was shipped in a prior commit (105a888) — so TARGET 3 is technically a 2-surface alignment commit (CLAUDE.md + conventions.md), with the recipe as a separate prior commit. Future Rule #48 instances could ship as 3-surface single-commit shape if the recipe lands alongside.

10. **Width-canary on grep-derived consumer counts applies to ID schemes too.** Reviewer C's C-02 catch was effectively a width-canary failure — the original `morning:RvwC-CC-5 (orig 2026-05-18)` scheme grep'd to ZERO source-postmortem-finding hits for the bare ID `RvwC-CC-5` (the morning postmortem has no such finding; it carries it forward). Reviewer C ran the canary mentally; the renamed `prior-2026-05-18:RvwC-CC-5` greps to the actual origin. Rule #31 width-canary discipline applies to ID schemes for cross-session artifacts.

## Recommendations Carried Forward

Of the ~21 net reviewer findings this session, **~17 remain** as queued follow-up work. Highest-leverage (per Reviewer A/B/C MEDIUM findings):

1. **Stable anchor markers for `cve_matcher.py:477-491` line citations** (Reviewer A A-03 MEDIUM) — the line range is referenced 7× across CLAUDE.md Rule #49 + Rule #50 + forward-prepared recipe + Rule #50 fixup. Per Rule #28 the file grows +14-22% historically; one matcher refactor invalidates every cite. Wrap the contract block with `# CVE-MATCHER-VERSION-REGEX-CONTRACT-START` / `-END` comment pair + reference by anchor name. Queue as `2026-05-18:RvwA-A03`.

2. **Recipe Rule-of-Nine table duplicates CLAUDE.md Rule #25** (Reviewer A A-04 MEDIUM) — `.mex/patterns/cross-stack-alignment-test.md:255-273` duplicates CLAUDE.md Rule #25's worked-example list; the rule already lists all 9. Replace the recipe's table with a one-liner pointer to "CLAUDE.md Rule #25 single-slice exception #2". Queue as `2026-05-18:RvwA-A04`.

3. **`edges → patterns/INDEX.md` is novel to new recipes** (Reviewer A A-05 MEDIUM) — none of the 7 pre-existing recipes declare INDEX.md as a graph edge. Either drop the INDEX.md edge from both new recipes OR add it retroactively to the other 7. Queue as `2026-05-18:RvwA-A05`.

4. **Forward-prepared recipe missing `## Debug` section** (Reviewer A A-06 LOW) — most large recipes (`add-mcp-tool.md`, `inner-outer-safe-runner.md`, `add-router-test.md`) include a `## Debug` section; `forward-prepared-cve-pin.md` doesn't. Add for shape conformance. Queue as `2026-05-18:RvwA-A06`.

5. **Boundary regex narrower-than-naive-substring callout** (Reviewer B B-M1 MEDIUM) — the recipe's boundary-anchored regex `(?:^|[^a-z0-9])(...)(?:[^a-z0-9]|$)` correctly rejects `nr155_else` AND ALSO rejects `lr11a` (variant where family is followed by hex char). The recipe should call out this "narrower-than-naive-substring" trade-off explicitly. Queue as `2026-05-18:RvwB-B-M1`.

6. **Rule #50 worst-case-max parenthetical** (Reviewer B B-M2 MEDIUM) — Rule #50 wording "advisory's `cvss_score` is the worst-case individual" is correct (worst-case = highest severity = highest score) but adding `(= max(individual scores))` parenthetical would harden against future drift. Queue as `2026-05-18:RvwB-B-M2`.

7. **Recipe verify checkbox cite for `evening:RvwA-A2`** (Reviewer C C-03 MEDIUM) — recipe's verify checkbox says "explicit `_<LAYER>_NARROWING_FIELDS` constant OR a documented `inspect.getsource` follow-up flagged in ADAPTIVE_BACKLOG.md if not yet promoted." A fresh implementer doesn't know what `evening:RvwA-A2` resolves to without grep. Add the explicit ID + one-line gloss. Queue as `2026-05-18:RvwC-C-03`.

8. **INDEX.md trigger keywords too dense for plain-language search** (Reviewer C C-04 MEDIUM) — both new recipe rows have Rule-citing trigger words rather than operator-facing colloquial phrasing. Extend recipe `triggers:` YAML list with "pin before parser ready" / "CVE not yet extractable" / "land CVE today activate later". Queue as `2026-05-18:RvwC-C-04`.

9. **Cross-domain applicability section in cross-stack-alignment-test recipe** (Reviewer C C-05 MEDIUM) — the recipe's pattern applies WAY beyond hw-firmware (backend↔frontend, parser↔loader, etc.). Add an explicit "Cross-domain applicability" section noting the recipe is NOT hw-firmware-scoped. Queue as `2026-05-18:RvwC-C-05`.

10. **Date-completed column in ADAPTIVE_BACKLOG ## 5** (Reviewer C C-06 LOW) — completed rows can be archived after 60 days per §6, but no rows currently have a date column making the cutoff query expensive. Add a `Date completed` column. Queue as `2026-05-18:RvwC-C-06`.

11. **Reciprocal edge in cross-stack-alignment-test.md → forward-prepared-cve-pin.md** (Reviewer C C-07 LOW) — `forward-prepared-cve-pin.md` edges to cross-stack-alignment-test.md (line 14-15) but the reciprocal edge is missing. Add for symmetry. Queue as `2026-05-18:RvwC-C-07`.

12. **Sub-heading breakup of long Rule #48-50 conventions.md entries** (Reviewer C C-08 LOW) — lines 196-198 are extremely long single-line bullets (~3.5 KB each). Convert to `### Rule #N sub-heading` shape for grep-friendliness. Queue as `2026-05-18:RvwC-C-08`.

13. **Line-range citation consistency `477-491` vs `480-491` vs `~480-491`** (Reviewer B B-L1 + B-L2 LOW) — standardise across all references. Companion to A-03 stable-anchor-markers. Queue as `2026-05-18:RvwB-B-L1`.

14. **NVD-66-chipset-CPEs claim should be NVD-timestamped** (Reviewer B B-L3 LOW) — the "66 hardware chipset CPEs (MT2731..MT8798)" claim in forward-prepared-cve-pin.md and the YAML comment should anchor to a specific NVD timestamp. Queue as `2026-05-18:RvwB-B-L3`.

15-17. Various LOW / NIT items — see reviewer reports (Reviewer A 9 findings + Reviewer B 5 findings + Reviewer C 8 findings = 22 net findings, 4 HIGH applied + ~18 deferred).

## Remaining Work

- Recommendations 1-14 above: ~6-10 hours total queued in ADAPTIVE_BACKLOG.md.
- Backfill: NONE needed for this session's commits. Pure docs/patterns/rules — no YAML data changes; existing matcher state preserved; no DB corpus check needed.
- The 4 deferred reviewer findings + ~38 still-open recommendations from the prior 3 postmortems = ~50 carry-forward items total. Now indexed in `.planning/ADAPTIVE_BACKLOG.md` per `evening:RvwC-C12` (completed this session).

## Numbers

| Metric | Value |
|--------|-------|
| Commits | 7 (4 feat + 3 fix) |
| Files changed | 7 (`.planning/ADAPTIVE_BACKLOG.md` new + 2 recipes new + CLAUDE.md modified + `.mex/context/conventions.md` modified + `.mex/ROUTER.md` modified + `.mex/patterns/INDEX.md` modified) |
| Lines added | 925 net-new |
| Reverts | 0 |
| New CLAUDE.md learned rules | 3 (Rules #48, #49, #50) |
| CLAUDE.md learned rules total | 50 (was 47) |
| `.mex/context/conventions.md` Verify Checklist entries | 50 (was 47 by content count; was 43 by stale frontmatter) |
| New `.mex/patterns/` recipes | 2 (cross-stack-alignment-test + forward-prepared-cve-pin) |
| `.mex/patterns/` recipe count | 15 (was 13) |
| ADAPTIVE_BACKLOG.md items | 39 unique (1 in-progress at peak → 0 at close + 4 HIGH open + ~20 MEDIUM open + ~5 LOW open + 1 deferred + 10 completed) |
| Pre-target parallel scout dispatches | 0 (intentionally skipped per docs-only session direction) |
| Post-target reviewer dispatches | 3 (arch + forensic + adaptability) |
| Reviewer findings TOTAL | ~21 net (8 A + 5 B + 8 C) |
| Reviewer findings APPLIED this session | 4 HIGH (A-01 + A-02 + C-01 + C-02 + A-07 in 3 fixup commits) |
| Reviewer findings DEFERRED to follow-up | ~17 |
| Independent NVD WebFetch verifications (Reviewer B) | 4 (CVE-2023-20819 + CVE-2022-42269 + CVE-2021-34372 + CVE-2020-24586) — all CONFIRMED no drift |
| Independent code-read verifications (Reviewer A + this session) | 2 (`sbom.py:65-129` UNIQUE-constraint audit + alembic migrations sweep) |
| Recursive-verification-discipline sessions running | 8 (extended this session to rule-text technical claims about code behaviour) |
| Cross-stack-alignment-commit instances this session | 2 (TARGET 3 + Fixup 1 — both touch CLAUDE.md + conventions.md mirror) |
| Rule #25 per-piece commits | 7 (all this session) |
| Rule #8 rebuilds | 0 (pure docs; no YAML or .py changes) |
| Rule #11 import smokes | 0 (no class-shape changes) |
| Rule #38 cwd-drift incidents | 0 (used `git -C ...` for all git commands) |
| Final SQL audit | SKIPPED per session direction (pure docs; no DB corpus changes) |

## Documents

- This postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-backlog-recipes-2026-05-18.md`
- Patterns extracted: `.planning/knowledge/hw-firmware-adaptive-backlog-recipes-2026-05-18-patterns.md`
- Antipatterns extracted: `.planning/knowledge/hw-firmware-adaptive-backlog-recipes-2026-05-18-antipatterns.md`
- Prior 2026-05-15-evening postmortem: `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md`
- Prior 2026-05-15-afternoon postmortem: `.planning/postmortems/postmortem-hw-firmware-tegra-activation-2026-05-15.md`
- Prior 2026-05-15-morning postmortem: `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`
- The single source of truth for carry-forward items: `.planning/ADAPTIVE_BACKLOG.md`

---HANDOFF---
- Postmortem: hw-firmware-adaptive-backlog-recipes-2026-05-18
- Document: .planning/postmortems/postmortem-hw-firmware-adaptive-backlog-recipes-2026-05-18.md
- Failures documented: 4 (1 HIGH Reviewer A A-02 forensic-correctness drift on Rule #50 dedup-mechanic claim — Rule asserted `(firmware_id, blob_id, cve_id)` UNIQUE constraint exists but model declares only Index entries; dedup is application-side via `existing` set at `cve_matcher.py:905,989,1042` — fixup commit `17959a6` corrects + 1 HIGH Reviewer C C-01 future-session-affordance gap: ROUTER.md didn't surface new ADAPTIVE_BACKLOG.md to fresh openers — fixup commit `14f4357` adds routing-table row + 1 HIGH Reviewer C C-02 ID-scheme grep-back-incompatibility on 6 backlog rows — fixup commit `7fed6d0` renames to `prior-2026-05-18:RvwC-XX` + 1 LOW Reviewer A A-07 workflow gap: ADAPTIVE_BACKLOG ## 1. In-Progress not promoted to ## 5. Completed at session close — same fixup commit `7fed6d0` migrates + sentinel)
- Safety catches: 8 (multi-persona reviewer dispatch × 3 [arch + forensic + adaptability — 21 net findings, 4 HIGH applied] + recursive verification discipline EXTENDED to code-verified docs claims [NEW failure-mode surface 2026-05-18: rule-text technical claims about code behaviour; 8 sessions running] + recursive NVD-CPE verification × 4 fetches CONFIRMED [Reviewer B; consecutive-session-count 8] + Rule #25 per-piece commits × 7 [bisect-clean; 0 reverts] + Rule #25 single-slice exception #2 cross-stack-alignment shape × 2 instances [TARGET 3 + Fixup 1 both touched CLAUDE.md ↔ conventions.md mirror] + pre-target context discipline [read 3 postmortems + 2 knowledge files + INDEX + reference recipe BEFORE authoring] + Rule #21 sync discipline × 3 events + Rule #38 cwd discipline net 0 incidents)
- Recommendations: 14 highest-leverage carried forward (cve_matcher.py anchor markers for line-range citations + recipe Rule-of-Nine table dedup vs CLAUDE.md Rule #25 + edges → INDEX.md normalisation across recipes + forward-prepared recipe ## Debug section + boundary-regex narrower-than-naive-substring callout + Rule #50 worst-case-max parenthetical + recipe verify-checkbox `evening:RvwA-A2` cite + INDEX.md plain-language triggers + cross-domain applicability section + date-completed column in BACKLOG ## 5 + reciprocal edge in cross-stack-alignment-test → forward-prepared-cve-pin + sub-heading breakup of long conventions.md entries + line-range citation consistency + NVD-66-chipset-CPEs timestamp anchor)
- Critical Reviewer-A catch: Rule #50 dedup-mechanic claim — independent code-read at `backend/app/models/sbom.py:65-129` revealed NO `UniqueConstraint` on `sbom_vulnerabilities`; matcher dedupes via in-memory `existing` set at `cve_matcher.py:905,989,1042` keyed by `(blob_id, cve_id)` 2-tuple; `firmware_id` is implicit per-invocation. **NEW failure-mode surface: rule-text technical claims that reference code behaviour now require independent code-read verification.** Recursive-verification discipline now 8 sessions running.
- No DB corpus changes this session (pure docs/patterns/rules); regression baselines preserved by construction (no YAML or .py changes); Rule #8 rebuild skipped.
- Adaptability deltas shipped: ADAPTIVE_BACKLOG.md as single source of truth for ~50 carry-forward items across 3 recent postmortems + cross-stack-alignment-test recipe codifying Rule-of-Nine 5-part test shape + 2 commit shapes (Shape 1 multi-surface single-commit vs Shape 2 regression canary on existing surfaces) + asymmetry-tolerance design principle + forward-prepared-cve-pin recipe codifying Rule-of-Two HARD-REJECT version_regex pattern + boundary-anchored regex shape + activation commit-chain plan + CLAUDE.md Rules #48 (cross-stack alignment test discipline Rule-of-Nine) + #49 (forward-prepared CVE pin Rule-of-Two) + #50 (shared advisory_id with documented dedup Rule-of-One+) promoted + Rule #25 single-slice exception #2 evidence chain bumped Rule-of-Eight → Rule-of-Nine via d641f28 Shape-2 form + .mex/ROUTER.md routing-table extension surfacing ADAPTIVE_BACKLOG to future-session openers + ID-scheme grep-back-compat refinement for cross-session backlog items + workflow rule "## 1. In-Progress → ## 5. Completed at session close" applied + recursive-verification discipline extended to code-verified docs claims (8 sessions running).
---

Run `/learn hw-firmware-adaptive-backlog-recipes-2026-05-18` to extract patterns into the knowledge base.
