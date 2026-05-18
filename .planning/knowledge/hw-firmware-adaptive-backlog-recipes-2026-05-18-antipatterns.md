# Anti-patterns: HW-Firmware Adaptive — ADAPTIVE_BACKLOG + 2 Recipes + Rule-of-Three Promotion + Reviewer Fixups — 2026-05-18

> Extracted: 2026-05-18
> Campaign: ad-hoc Citadel-driven session shipping 4 top carried-forward Reviewer findings + 3 Reviewer fixups
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-adaptive-backlog-recipes-2026-05-18.md`

## Failed Patterns

### 1. Inheriting docs technical claims from postmortem framings without independent code-verification

- **What was done:** Rule #50 (TARGET 3 commit `294fa3a`) inherited the dedup-mechanic claim "matcher dedupes per `(firmware_id, blob_id, cve_id)` UNIQUE constraint" from the evening postmortem's recurring framing ("FragAttacks Pattern #4 — matcher dedupes per (firmware_id, blob_id, cve_id) UNIQUE — even if both entries matched the same blob (impossible in practice since vendor differs), one row would be emitted"). The wording was textually consistent with the postmortem's narrative but technically inaccurate.
- **Failure mode:** Forensic-correctness drift in load-bearing documentation. A future contributor reading Rule #50 might design a feature assuming DB-level enforcement (e.g. backfill that relies on UNIQUE-violation to dedup, rather than the actual application-side check) and the feature would silently misbehave on rollback / concurrent insert scenarios.
- **Evidence:** Reviewer A A-02 HIGH this session — independent code-read at `backend/app/models/sbom.py:65-129` + `grep -rn "UniqueConstraint\|create_unique_constraint" backend/alembic/versions/` revealed NO UniqueConstraint on `sbom_vulnerabilities`; the model declares only 5 `Index` entries. Dedup is purely application-side via in-memory `existing` set at `cve_matcher.py:905,989,1042`. Fixup commit `17959a6` corrected Rule #50 + conventions.md mirror.
- **How to avoid:** When a learned rule's body makes a technical claim about code behaviour (constraint, contract, control-flow, class-shape), the IMPLEMENTER (rule-promotion author) MUST independently grep + read the source-of-truth code BEFORE writing the wording — don't inherit from prior postmortems' framings. The REVIEWER then re-runs the code-read as a triple-verification step (same shape as recursive NVD-CPE verification — different verifiers focus on different aspects). 8 sessions running with this discipline; this session extends it to docs technical claims.

### 2. Shipping a "single source of truth" artifact without updating the discoverability surface

- **What was done:** TARGET 0 commit `533bb72` shipped `.planning/ADAPTIVE_BACKLOG.md` as the canonical source-of-truth artifact for ~50 carry-forward items across 3 recent postmortems. BUT `.mex/ROUTER.md` (which fresh session openers load FIRST per the Behavioural Contract) had no routing-table entry for the new artifact. Fresh agent loading ROUTER.md would not discover it.
- **Failure mode:** The artifact's own value-proposition (single source of truth) collapses if openers don't find it. Without the discoverability update, every future session opener would have to either grep ad-hoc OR re-read 3 postmortems — exactly the cost the backlog was meant to eliminate.
- **Evidence:** Reviewer C C-01 HIGH this session — "fresh hw-firmware-session opener loading ROUTER.md first per the Behavioural Contract will NOT discover the backlog". Future-session opener acid test FAILED without C-01. Fixup commit `14f4357` added the routing-table row + bumped `last_updated`.
- **How to avoid:** When shipping any new artifact intended as a session-opener resource, the COMPANION DISCOVERABILITY UPDATE is part of the work, not a follow-up. Mechanical check: "if a fresh agent loads ROUTER.md per the Behavioural Contract, will they find this new artifact via the routing table?" If no, the ROUTER.md update is part of the landing commit. Companion to Reviewer A's A-02 finding: the cross-stack alignment discipline extends BEYOND code surfaces (DB ↔ TS ↔ FE config) to docs ↔ routing-table ↔ session-bootstrap.

### 3. ID schemes that name where-the-finding-CARRIES instead of where-it-ORIGINATED

- **What was done:** Initial ADAPTIVE_BACKLOG.md used 6 rows with ID shape `morning:RvwC-CC-5 (orig 2026-05-18)`. The sigil "morning" pointed to the morning postmortem (where the finding APPEARS in the carry-forward list); the parenthetical "(orig 2026-05-18)" noted the originating session. But the bare finding-ID `RvwC-CC-5` only exists in the originating session — greping the morning postmortem for `RvwC-CC-5` finds only a carry-forward stub, not the original Reviewer-tagged finding.
- **Failure mode:** Future-session author reading the BACKLOG + trying to grep back to the source for context would land on a carry-forward stub instead of the original Reviewer-tagged finding with full forensic context. Grep-back-incompatibility silently degrades the BACKLOG's utility.
- **Evidence:** Reviewer C C-02 HIGH this session — "the source postmortem won't have a `RvwC-CC-5` finding". Fixup commit `7fed6d0` renamed 6 rows to `prior-2026-05-18:RvwC-CC-5` shape + Source column annotated `(carry)` + carry-chain in Notes column.
- **How to avoid:** ID schemes for cross-session consolidated artifacts MUST name where-the-finding-ORIGINATED (not where-it-carries). Width-canary the IDs at backlog-authoring time: for every consolidated row, ask "if a future reader greps the source postmortem (named in the Source column) for this finding-ID, will they find the originating finding or a carry-forward stub?" If stub, the sigil is wrong.

### 4. Leaving `## 1. In-Progress` populated at session close

- **What was done:** TARGET 0 commit `533bb72` shipped ADAPTIVE_BACKLOG.md with 4 in-progress rows (this session's TARGETs C12 + C2 + C7 + C14). After all 4 TARGETs shipped via commits 105a888 + b8f6e95 + 294fa3a + 17959a6, the 4 in-progress rows stayed in `## 1. In-Progress` instead of migrating to `## 5. Completed`.
- **Failure mode:** Next-session opener would spot-check `## 1.` per the BACKLOG's own methodology section + see the 4 targets as in-progress, wasting time resolving the apparent contradiction with the live commit log.
- **Evidence:** Reviewer A A-07 LOW this session — "self-described methodology says 'first action of a new session is to spot-check the In-Progress section' — leaving them in-progress traps the next session". Fixup commit `7fed6d0` promoted all 4 in-progress rows to `## 5.` with commit shas + sentinel `*(Empty at session close)*` left in `## 1.`.
- **How to avoid:** Every session that ships TARGETs from BACKLOG MUST close-out as the LAST commit (or as part of the session-close postmortem commit): promote each in-flight row to `## 5. Completed` with commit shas; replace `## 1.` contents with a sentinel `*(Empty at session close)*`. Add to the session-close checklist as a mechanical workflow rule.

### 5. Invoking /citadel:postmortem + /learn for an ad-hoc session without a campaign file

- **What was done:** Per user direction, the session's close-out was supposed to invoke /citadel:postmortem + /learn + /session-handoff skills. These skills assume `/citadel:archon`-driven campaign files (which this ad-hoc session didn't produce — it ran directly from a user prompt without an Archon campaign).
- **Failure mode:** The skills would either error out (missing campaign file) or produce incomplete output (no telemetry / no feature ledger to read). For an ad-hoc session, manual authorship of postmortem + patterns + antipatterns following the established pattern from `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md` is more reliable.
- **Evidence:** Postmortem files for prior 2026-05-15 sessions were authored manually following the same shape; this session followed the established pattern.
- **How to avoid:** For ad-hoc Citadel-driven sessions (not /citadel:archon campaigns), author the postmortem + patterns + antipatterns manually following the established `.planning/postmortems/postmortem-<topic>-<date>.md` + `.planning/knowledge/<topic>-<date>-{patterns,antipatterns}.md` triplet convention. The /citadel:postmortem + /learn skills are valuable for /citadel:archon-driven multi-session campaigns where the campaign file + telemetry log + feature ledger exist as inputs.

## Cross-Cutting Anti-pattern Themes

1. **"Docs technical claims need code-verification, not just postmortem-inheritance."** This session's Rule #50 dedup-mechanic drift was caused by inheriting the wording from the evening postmortem's Pattern #4 framing without re-verifying against code. The recursive-verification discipline now targets BOTH external API claims (NVD-CPE/CVSS) AND internal code claims (constraints, contracts, control-flow). 8 sessions running.

2. **"Discoverability surface IS part of the artifact landing."** New "single source of truth" artifacts need their routing-table / cross-reference surface updated in the SAME commit (or same session). Don't ship an artifact and assume openers will find it — the meta-pattern is identical to Rule #25 single-slice exception #2 (cross-stack alignment surfaces must land together).

3. **"ID schemes for cross-session artifacts MUST be grep-back-compat."** Width-canary the IDs by mentally greping back from the consolidated view to the source. If the bare finding-ID isn't present in the source postmortem (only a carry-forward stub), the sigil is wrong — rename to the originating session.

4. **"Session-close workflow includes BACKLOG.md `## 1. → ## 5.` migration."** Every session that ships TARGETs from BACKLOG MUST close-out as the LAST commit or part of the session-close postmortem commit. Sentinel + migration is mechanical. Companion to Rule #21 sync discipline.

5. **"Manual authorship beats skill invocation for ad-hoc sessions."** /citadel:postmortem + /learn skills assume /citadel:archon campaign files; ad-hoc Citadel-driven sessions (direct user-prompt-driven) author manually following the established convention. Future improvement: make the skills detect missing campaign file gracefully + offer manual-template-fill mode.

6. **"Pre-target scouts are OPTIONAL for docs-only sessions, MANDATORY for code/YAML-data sessions."** The Citadel pre-shaped pattern's value-add varies by session type: docs-only sessions can skip scouts (source material already in postmortems); code/YAML-data sessions can't (NVD WebFetch + parser-shape verification are load-bearing pre-implementation).

7. **"Cross-stack alignment commits apply to docs surfaces too."** Rule #25 single-slice exception #2 was originally codified for code-heavy commits (DB CHECK + TS union + FE config). This session demonstrates the discipline applies equally to CLAUDE.md learned rules + conventions.md Verify Checklist mirror. The conceptual contract (sync per Rule #21) is the same; only the surface types differ.

8. **"Reviewer-side independent verification is the load-bearing safety net for forensic correctness."** Whether the claim is external (NVD CPE — Reviewer B) or internal (code behaviour — Reviewer A), the implementer's verification alone is insufficient. The triple-verification pattern (implementer's claim + reviewer's independent verification + final code/code-read alignment) is the durable discipline.
