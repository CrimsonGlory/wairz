# Patterns: HW-Firmware Adaptive — ADAPTIVE_BACKLOG + 2 Recipes + Rule-of-Three Promotion + Reviewer Fixups — 2026-05-18

> Extracted: 2026-05-18
> Campaign: ad-hoc Citadel-driven session shipping 4 top carried-forward Reviewer findings + 3 Reviewer fixups
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-backlog-recipes-2026-05-18.md`

## Successful Patterns

### 1. Recursive verification discipline EXTENDED to code-verified docs claims (8 sessions running, NEW FAILURE-MODE SURFACE)

- **Description:** The recursive NVD-CPE verification discipline (7 sessions running prior to this one) previously targeted CVE attribution claims + chipset_regex enumerated values + CVSS field values + per-advisory aggregate CVSS scoring. This session extends it to **rule-text technical claims that reference code behaviour**. When a learned rule asserts a code-level fact (e.g. "the matcher dedupes per `(firmware_id, blob_id, cve_id)` UNIQUE constraint"), the reviewer MUST independently code-read the asserted source-of-truth (model file + alembic migrations) before accepting.
- **Evidence:** This session's Reviewer A A-02 HIGH catch — Rule #50 claimed `(firmware_id, blob_id, cve_id)` UNIQUE constraint exists on `sbom_vulnerabilities`; independent code-read at `backend/app/models/sbom.py:65-129` + alembic migrations sweep confirmed NO UniqueConstraint — model declares only 5 `Index` entries; dedup is purely application-side via in-memory `existing` set at `cve_matcher.py:905,989,1042`. Fixup commit `17959a6` corrected the rule + conventions.md mirror.
- **Applies when:** Any session promoting a learned rule whose body asserts a code-level fact (a constraint, an API contract, a control-flow shape, a class-attribute presence/absence). The reviewer (Reviewer A architecture or Reviewer B forensic-domain depending on whose lens fits) MUST independently grep + read the source-of-truth file. The implementer's WebFetch / code-read alone is insufficient — same triple-verification logic as recursive NVD-CPE verification (scout → implementer → reviewer catches drift single-axis misses).

### 2. Cross-stack-alignment commit shape applied META — the promotion landing IS itself an instance of the pattern it codifies

- **Description:** TARGET 3 this session shipped 3 new CLAUDE.md learned rules (Rules #48 + #49 + #50). Rule #48 codifies the cross-stack-alignment test discipline as a learned rule. The TARGET 3 commit `294fa3a` IS itself a Rule #25 single-slice exception #2 cross-stack-alignment commit (CLAUDE.md learned rules + `.mex/context/conventions.md` Verify Checklist mirror landed together because Rule #21 enforces sync). The Rule #48 recipe at `.mex/patterns/cross-stack-alignment-test.md` (shipped in prior commit `105a888`) describes the pattern; the TARGET 3 commit applies it. Meta-application validates the pattern works in its own promotion landing.
- **Evidence:** Commit `294fa3a` touches 2 files (CLAUDE.md + conventions.md mirror); Fixup 1 `17959a6` also touches these 2 files as a second cross-stack-alignment commit. Both commits follow Rule #25 single-slice exception #2 — splitting would leave the surfaces temporarily out of sync (the alignment-drift failure mode the rules themselves codify against).
- **Applies when:** Promoting a new learned rule from `.mex/patterns/` or `.planning/knowledge/` extraction into CLAUDE.md. Always touches CLAUDE.md + conventions.md Verify Checklist mirror together per Rule #21. Future Rule #48 instances could ship as 3-surface single-commit shape if the recipe lands alongside (when not previously shipped).

### 3. Per-piece commits per Rule #25 work for docs-only sessions too — bisect-clean across 7 commits

- **Description:** Rule #25 per-piece commits were originally validated for code-heavy campaigns (Phase 5 god-class decomposition, Windows-coverage chain, async-cleanup). This session validates the discipline extends cleanly to pure-docs sessions (BACKLOG + 2 recipes + rules promotion + 3 reviewer fixups). Each commit independently revertable; 0 reverts; bisect-clean across 7 commits.
- **Evidence:** Session commits: 533bb72 (TARGET 0 BACKLOG) → 105a888 (TARGET 1 recipe 1) → b8f6e95 (TARGET 2 recipe 2) → 294fa3a (TARGET 3 rules promotion as cross-stack-alignment) → 17959a6 (Fixup 1 A-01+A-02 cross-stack-alignment) → 14f4357 (Fixup 2 C-01) → 7fed6d0 (Fixup 3 A-07+C-02). Each commit's diff scope is single-surface or naturally-paired-surfaces; revert any single commit and the chain stays valid for the others.
- **Applies when:** Any session shipping ≥3 independently-verifiable docs artifacts (recipes, learned rules, backlog updates, postmortems). Don't bundle just because "they're all docs" — per-piece commits make per-finding rollback possible (e.g. if Rule #50's dedup-mechanic correction needs to be reverted later, the recipe shipments aren't affected).

### 4. Companion discoverability update is part of new-artifact landing, NOT a follow-up

- **Description:** When shipping a new "single source of truth" artifact (ADAPTIVE_BACKLOG.md this session), the discoverability surface that fresh agents use to find it (ROUTER.md routing table this session) MUST be updated in the same session — not a follow-up. The artifact + routing-table row + cross-references form a cross-stack alignment surface; shipping the artifact alone provides zero value if openers don't find it.
- **Evidence:** Reviewer C C-01 HIGH this session caught that ADAPTIVE_BACKLOG.md was not surfaced from ROUTER.md. The backlog's own value-proposition (single source of truth) collapses if openers don't discover it. Fixup commit `14f4357` added the routing-table row + last_updated bump. Without it, every future session opener would have to either grep ad-hoc OR re-read 3 postmortems — exactly the cost the backlog was meant to eliminate.
- **Applies when:** Shipping any new artifact intended as a session-opener resource. Mechanical check: "if a fresh agent loads ROUTER.md per the Behavioural Contract, will they find this new artifact via the routing table?" If no, the ROUTER.md update is part of the landing commit.

### 5. ID-scheme grep-back-compat for cross-session artifacts

- **Description:** Backlog items consolidated across N postmortems need ID schemes that name WHERE-THE-FINDING-ORIGINATED, not WHERE-IT-CARRIES. The original `morning:RvwC-CC-5 (orig 2026-05-18)` shape was grep-back-incompatible — greping the morning postmortem for `RvwC-CC-5` finds only a carry-forward stub, not the originating Reviewer-tagged finding. The corrected shape `prior-2026-05-18:RvwC-CC-5` + carry-chain Notes column annotation greps back to the actual source.
- **Evidence:** Reviewer C C-02 HIGH this session caught the grep-back-incompatibility on 6 rows. Fixup commit `7fed6d0` renamed all 6 + added carry-chain notes. Mechanical detection at backlog-authoring time: for every consolidated row, ask "if a future reader greps the source postmortem (named in the Source column) for this finding-ID, will they find the originating finding or a carry-forward stub?"
- **Applies when:** Authoring or extending any cross-session consolidated artifact (backlog, knowledge files, issue trackers) where finding-IDs originated in different sessions. Width-canary the IDs by mentally greping back from the consolidated view to the source.

### 6. Pre-target scout SKIP is correct for docs-only sessions

- **Description:** The Citadel pre-shaped pattern (7 sessions running per evening postmortem's Pattern #9) calls for "2-3 parallel research scouts (one per TARGET) → ship per-piece Rule #25 commits → 3 parallel multi-persona reviewers". This session SKIPPED the pre-target scouts because (a) the 3 source postmortems gave direct content for the 2 recipes + the rule promotions, (b) scouts would have duplicated the I/O the implementer was already doing. The 3 post-target reviewers did the value-adding work (independent code-read for Reviewer A, independent NVD WebFetches for Reviewer B, adaptability lens for Reviewer C).
- **Evidence:** This session's 4 HIGH reviewer findings (A-01 + A-02 + C-01 + C-02) all came from the POST-target review phase; ZERO would have been caught by pre-target scouts because the targets were documentation artifacts, not data/code with external verification needs. Forensic-domain Reviewer B WebFetched 4 CVEs and CONFIRMED all citations — pre-target scout WebFetches would have duplicated this work for no value-add.
- **Applies when:** Docs-only sessions where the source material is already in postmortems / knowledge files / existing recipes. SKIP pre-target scouts; DON'T skip post-target reviewers. For code/YAML-data sessions (e.g. the morning Tegra session shipping new CVE pins), pre-target scouts ARE load-bearing — they verify NVD CPE before the implementer commits.

### 7. Session-close workflow: `## 1. In-Progress → ## 5. Completed` migration is mechanical and mandatory

- **Description:** Every session that ships items from `## 1. In-Progress` of the BACKLOG MUST close-out as the LAST commit (or as part of the session-close postmortem commit): promote each in-flight row to `## 5. Completed` with commit shas; replace `## 1.` contents with a sentinel `*(Empty at session close)*`. The methodology section of the BACKLOG explicitly says "first action of a new session is to spot-check the In-Progress section against the live commit log" — leaving rows in-progress traps the next session.
- **Evidence:** Reviewer A A-07 LOW this session caught that the 4 in-progress rows (TARGETs C12 + C2 + C7 + C14) stayed in `## 1.` after shipping. Fixup commit `7fed6d0` promoted them to `## 5.` with the 4 commit shas + sentinel.
- **Applies when:** Every session that touches `.planning/ADAPTIVE_BACKLOG.md`. Mechanical: add the `## 1. → ## 5.` migration to the session-close checklist.

### 8. Reviewer-side independent code-read is the load-bearing verification for docs technical claims

- **Description:** When a learned rule's text makes a technical claim about code behaviour (constraint, contract, control-flow, class-shape), the reviewer (Reviewer A architecture or Reviewer B forensic-domain depending on the claim's nature) MUST independently grep + read the source-of-truth code BEFORE accepting the wording. The implementer's claim is the FIRST verification; the reviewer's independent code-read is the SECOND. Different verifiers focus on different aspects — implementer on linguistic clarity, reviewer on technical accuracy.
- **Evidence:** Reviewer A A-02 catch came from running `grep -rn "UniqueConstraint" backend/app/models/` + reading `sbom.py:65-129` + sweeping alembic migrations for `create_unique_constraint`. The implementer (this session) inherited the wording from the evening postmortem's Pattern #4 framing without re-verifying against code. The cross-axis verification is the durable safety net.
- **Applies when:** Any session promoting a learned rule that asserts a code-level fact. Companion to the recursive NVD-CPE verification discipline (Reviewer B's analog for external API claims) — Reviewer A is the analog for internal code claims.

### 9. Recipe + Rule + Verify Checklist as a 3-surface alignment system

- **Description:** A learned-rule promotion lands across 3 surfaces: CLAUDE.md (Rule body) + `.mex/context/conventions.md` (Verify Checklist mirror per Rule #21) + `.mex/patterns/<recipe>.md` (operator-facing recipe). The 3 surfaces enforce the same conceptual contract (the discipline being codified); future drift across them is a Rule #48 cross-stack-alignment-test concern. This session's TARGET 3 demonstrates the canonical 3-surface alignment.
- **Evidence:** Rule #48 (CLAUDE.md) + Rule #48 Verify entry (conventions.md) + `.mex/patterns/cross-stack-alignment-test.md` recipe. Same shape for Rule #49 + `.mex/patterns/forward-prepared-cve-pin.md`. The recipe was shipped in a separate commit (105a888) since TARGET 1 ran before TARGET 3; future promotions could land the recipe alongside the rule as a 3-surface single-commit shape.
- **Applies when:** Promoting a learned rule that has (or should have) an operator-facing recipe. Mechanical: ship recipe → rule → conventions.md mirror; if recipe doesn't exist yet, author it first as a separate commit, then promote the rule.

### 10. Asymmetry tolerance — design principle, not a bug (cross-stack-alignment-test recipe codification)

- **Description:** When cross-stack alignment tests assert pairwise agreement across N source-of-truth surfaces, the reject MODE may legitimately differ per layer (curated-tier WARN+skip vs BT-loader raise ValueError). DON'T force a common mode; assert via each layer's idiomatic shape (`_caplog_at(<logger>)` for WARN-mode; `pytest.raises(ValueError, match=...)` for raise-mode). Name-equality across dialects is a FALSE alignment — the dialects may legitimately use different vocabulary; the contract is SHAPE-equivalence.
- **Evidence:** Codified as part of Rule #48 + the cross-stack-alignment-test recipe. The canonical instance (`backend/tests/test_forensic10_alignment.py`, commit `d641f28`) documents asymmetry in the module docstring explicitly — a future reader doesn't "normalise" the asymmetry into a brittle common-mode assertion.
- **Applies when:** Authoring any cross-stack alignment test where the multiple layers enforce the same conceptual contract via different mechanisms. Document the asymmetry in the test module docstring as a design principle.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Skip pre-target parallel scouts | Docs-only session; source material already in postmortems + knowledge files; scout I/O would duplicate implementer's reading | Worked. 0 catches missed; post-target reviewers caught all 4 HIGH findings. Saved ~3 minutes of scout dispatch + return. |
| Author postmortem + patterns + antipatterns manually instead of invoking /citadel:postmortem + /learn skills | Skills assume `/citadel:archon`-driven campaign files; this ad-hoc session didn't produce one. Manual authorship follows the established pattern from `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md` shape exactly. | Worked. Postmortem + patterns + antipatterns shipped as 3 separate files following the evening session's naming convention. |
| Promote Rule #50 at Rule-of-One+ instead of waiting for Rule-of-Two | User direction explicit; the FragAttacks instance is the canonical Rule-of-One; KRACK/Dragonblood/BroadPwn audits queued as future Rule-of-N candidates in ADAPTIVE_BACKLOG. Rule-of-One promotion precedent set by Rule #40 (mechanical rigor) and Rule #47 ("promotable to Rule-of-Two on next instance"). | Worked. Rule #50 shipped with explicit Rule-of-One+ annotation + promotable-to-Rule-of-Two condition documented. |
| Single Rule #25 single-slice exception #2 cross-stack-alignment commit for CLAUDE.md + conventions.md | The 2 files are source-of-truth mirrors enforced by Rule #21; splitting would leave them temporarily out of sync. | Worked. Both files updated atomically in commit `294fa3a`. Fixup 1 `17959a6` followed the same shape for the A-01+A-02 corrections. |
| `prior-2026-05-18:` sigil prefix for backlog items originating in older postmortems | Reviewer C C-02 caught grep-back-incompatibility of `morning:RvwC-CC-5 (orig 2026-05-18)` shape. Renamed to use originating-session sigil for grep-back-compat. | Worked. 6 rows renamed; carry-chain Notes column annotations added. |
| Sentinel `*(Empty at session close)*` in `## 1. In-Progress` | Per Reviewer A A-07 + BACKLOG methodology section. Without sentinel, the next-session opener can't distinguish "this session is closed-out" from "this session hasn't started yet". | Worked. Sentinel + ## 5 migration applied in fixup commit `7fed6d0`. |

## Patterns Cross-Referenced Across Sessions

This session's patterns extend prior:

- **Evening session Pattern #9 (Triple-verification scout → implementer → reviewer)** → **Pattern #1 + Pattern #8 this session**. The discipline now extends to rule-text technical claims about code behaviour (Reviewer A A-02 catch is the 1st instance of this new failure-mode surface). 8 sessions running.
- **Evening session Pattern #2 (Cross-stack alignment test as Rule-of-Nine commit shape)** → **TARGET 1 recipe codifies this discipline + Rule #48 promotes it**. The meta-application (TARGET 3 IS a cross-stack-alignment commit per the rule it codifies) validates the pattern works in its own landing.
- **Evening session Pattern #3 (Forward-prepared CVE pin Rule-of-Two)** → **TARGET 2 recipe codifies this pattern + Rule #49 promotes it**. The recipe provides operator-facing steps for future Rule-of-Three+ instances (KRACK / Dragonblood / BroadPwn audit candidates queued in ADAPTIVE_BACKLOG).
- **Evening session Pattern #4 (Shared advisory_id with documented dedup)** → **Rule #50 promotion + corrected dedup-mechanic claim**. The corrected wording — application-side `existing` set at `cve_matcher.py:905,989,1042`, NOT DB-level UniqueConstraint — is the load-bearing technical accuracy that the docs MUST reflect.
- **Rule #25 cross-stack-alignment-commit shape** → **Rule-of-Nine now** (this session bumps Rule-of-Eight → Rule-of-Nine via d641f28 Shape-2 form). The pattern is durable beyond debate; the 2-surface single-commit shape applied twice this session.
- **Rule #46 paired-canary discipline** → applied to the 2 recipes' verify checkboxes + gate-canary requirement for forward-prepared CVE pins. The discipline is durable across recipe-codification too.
- **Rule #38 cwd-discipline** → 0 incidents this session; all git commands used `git -C /home/dustin/code/wairz <subcommand>`. The discipline holds.
- **8 sessions running with multi-persona reviewer pattern catching CVE-attribution + CVSS drift + (NEW) docs technical claims** — 2026-05-15 morning (CVE-2017-18159 chipset_regex), 2026-05-15 AM (CVE-2021-1111 CVSS 6.0→6.7), 2026-05-15 morning (CVE-2019-5680 R32.3.1+), 2026-05-16, 2026-05-17, 2026-05-18 prior, 2026-05-15 PM (FragAttacks CVSS), and now 2026-05-18 (Rule #50 dedup-mechanic claim — NEW failure-mode surface). Durable beyond debate.
