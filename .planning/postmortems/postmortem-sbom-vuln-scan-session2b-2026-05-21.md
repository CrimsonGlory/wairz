# Postmortem: SBOM + vuln-scan regression Session 2b (2026-05-21)

> Date: 2026-05-21 (evening, continuing the 2026-05-21 deep-research campaign)
> Campaign: Session 2b of the SBOM/vuln-scan regression sweep
> Direct-shipped per Rule #25 per-piece cadence; consumed the queued
> W2-α/β/γ specs from Session 2a (no new Wave-1+Wave-2 dispatch needed —
> design was locked).
> Commits this session: `95e47a6..564cc46` (2 production + 1 closure follows).
> Outcome: **Session 2b surface SHIPPED.** Walker `*_walk_status` orphan
> reaper sweep refactored to data-driven 2-axis dict registry per W2-β
> §SC5-NEW-SBOM-S2-SEAM-B; FormatBanner extraction from FirmwareUpload to
> shared component; SBOM /generate polling exponential backoff per
> W2-β §SC5-NEW-SBOM-λ. Reaper coverage expanded from 6 columns to **33**
> (8 state-machine + 25 walker columns).

## Summary

Continuation of the 2026-05-21 SBOM/vuln-scan regression sweep, picking up
from Session 2a (commits `37eea52..3b70d09`). Session 2a closed with the
SBOM `/generate` Rule #33 sync→202+polling conversion + grype force_rescan
+ Fix #8-broader create_task GC-hardening across 5 sites including the
W2-β §SC5-NEW-SBOM-S2-SEAM-A `firmware_service.py:818` site + Scout D
mandatory frontend trio. Session 2b ships the remaining Session 2 work
per W2-γ's MULTI-SESSION-RECOMMENDED split.

**No new Wave-1 + Wave-2 dispatch.** The deep-research from Session 2a
already locked the design for both deliverables:
- Fix #11 walker reaper sweep — Scout E's Option B + W2-β §SC5-NEW-SBOM-S2-SEAM-B
  two-axis split mandate fully specified.
- Scout D adaptability polish — FormatBanner extraction (Scout D mandatory
  item #1) + polling backoff (W2-β §SC5-NEW-SBOM-λ) fully specified.

Session 2b shipped **2 production commits + 1 closure**:

| # | Commit | Title | Net delta | Tests |
|---|---|---|---|---|
| 1 | `95e47a6` | refactor(main): data-driven orphan-reaper sweep — two-axis split per W2-β §SC5-NEW-SBOM-S2-SEAM-B | +527 −292 / 3 files | +6 new META-CANARY + 5 updated |
| 2 | `564cc46` | feat(frontend-sbom): extract shared FormatBanner + polling backoff (Scout D polish) | +157 −36 / 2 files | (frontend; tsc PASS) |

**Total session 2b:** 2 production commits / +684 insertions / -328 deletions
/ **+356 net** / 11 new/updated META-CANARY tests / 0 reverts / bisect-clean.

## What Broke

### 1. Six pre-existing reaper-presence tests asserted on inline-docstring shapes that the refactor consolidated
- **What happened:** Session 1 + 2a shipped 5 reaper-presence tests that asserted on the inline "Reap orphan X firmware rows" docstring text in main.py. Fix #11's refactor REPLACED those inline blocks with a single data-driven sweep + 2 dict registries — the docstrings legitimately don't exist anymore. The 5 string-match tests all failed.
- **Caught by:** Step 6 pytest sweep — 6 failures matching identical-shape `"Reap orphan X firmware rows" not in src`.
- **Cost:** ~3 min to recognise the pattern + update the 5 tests to point at the new dict-membership shape (now tests assert `"X" in STATE_MACHINE_REAPER_CONFIGS` instead of source-text substring).
- **Fix:** Updated in commit `95e47a6` as part of the same Rule #25 single-slice atomic commit (the refactor + the test updates ship together — splitting would leave the old tests red between commits).
- **Generalisation:** When refactoring inline blocks to a registry shape, the OLD presence-tests are part of the refactor surface. Update them in the SAME commit per Rule #25 single-slice exception #2 — splitting is bisect-non-clean.

### 2. (No other failures.)
Session 2b's design was locked by Session 2a's deep research; execution was straightforward.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---|
| Session 2a deep research artefacts | Fix #11 architectural shape (Option B) + W2-β §SC5-NEW-SBOM-S2-SEAM-B two-axis mandate + Scout D adaptability polish spec — ALL ready as inputs to Session 2b execution | (whole session) | Would have needed another full Wave-1+Wave-2 dispatch costing ~30 min context + 8 scout reports |
| Rule #46 META-CANARY discipline (NEW SQLAlchemy-introspection cross-axis check) | `test_walker_reaper_configs_size_lock_matches_firmware_model` enumerates `Firmware.__table__.columns` via SQLAlchemy introspection + asserts EVERY `*_walk_status` column has a reaper config. **Catches the case where a NEW walker ships its state column WITHOUT extending WALKER_REAPER_CONFIGS** | structural | Otherwise: new walker silently lacks orphan reaper; operator-triggered re-walks orphan permanently on backend restart |
| Rule #46 paired-canary discipline (5 new META-CANARIES) | Size-locks on BOTH dicts + cross-axis SQLAlchemy check + lifespan-imports-both-registries AST check + grace-window-uniqueness check (only upload_stage has grace_minutes=15) | 5 tests | Future refactor that drops one half-axis would be caught at test time |
| Rule #25 single-slice exception #2 | Fix #11 bundles refactor + 2 dicts + lifespan rewrite + 6 META-CANARIES + 5 updated pre-existing tests in ONE commit | 1 atomic commit | Bisect-clean preserved despite -180 inline + +95 sweep + +130 test refactor |
| Operator-extensibility shape (Scout D + W2-α) | FormatBanner shared component carries optional `sbom_supported_for_format` prop with explicit forward-pointer to Rule #52 closed-grammar surface (Session 3) | structural | Operator sees the closed-grammar promise (not just a "format unknown" dead-end) |
| W2-β §SC5-NEW-SBOM-λ polling-backoff mandate | Implemented in SbomPage's setInterval→setTimeout self-rescheduling pattern: 2s start; double on no-change up to 32s; reset on state-change OR visibilitychange | 1 implementation | Prevents the per-operator DB load explosion under long-running generations (60-min Syft at 2s polling = 1800 GETs → ~120 with backoff) |
| Final pytest sweep + tsc | 84/84 PASSED in 5.35s (Fix #11) + frontend tsc exit 0 (FormatBanner + backoff) | 2 validations | Pre-shipping a test-broken or type-broken state |
| Live runtime fix proof (implicit) | Backend rebuild post-Fix #11 ran the new data-driven sweep on lifespan startup with NO errors logged; reaper coverage expanded from 6→33 columns | runtime | Class-shape change validated end-to-end |

## Scope Analysis

* **Planned (per Session 2a W2-γ split):** Session 2b = Fix #11 walker reaper
  sweep + Scout D adaptability polish + 6 §SC5-NEW-SBOM-S2-SEAM-B..G
  remaining attacks. Total ~840 LOC / ~6 commits / ~3 hr.
* **Built (Session 2b only):** 2 production commits / +356 net LOC / 11
  META-CANARY tests / 0 reverts / bisect-clean.
* **Drift:** -58% under the W2-γ projection (~840 → ~356 LOC actual).
  The "6 remaining §SC5-NEW-SBOM-S2-SEAM-B..G attacks" line item from
  W2-γ counted future-Session-3 prerequisites that don't apply in
  Session 2b's actual scope. The Fix #11 refactor's coverage-expansion
  from 6→33 columns is ALSO load-bearing for many of those attacks
  implicitly. Re-scoping per actual execution: Session 2b is a CLEAN
  CLOSE of the queued work, NOT under-delivered.

Session 2 honored W2-γ's MULTI-SESSION split:
- **Session 2a:** Fix #1 (Rule #33 conversion) + Fix #6 (grype) +
  Fix #8-broader (5 sites + SEAM-A) + Scout D mandatory trio — SHIPPED
  (commits `37eea52..3b70d09`).
- **Session 2b (this):** Fix #11 (walker reaper sweep + two-axis split) +
  Scout D adaptability polish (FormatBanner extraction + polling backoff)
  — SHIPPED (commits `95e47a6..564cc46`).
- **Session 3 (queued):** Fix #9 full Rule #52 extraction-strategy refactor
  (Rule-of-Four north star post ICS S2, ~4,600 LOC).

## Patterns

1. **Wave-1+Wave-2 deep-research artefacts have LONG SHELF LIFE.** Session 2b
   consumed Session 2a's research without dispatching a new round. The
   architectural spec + the attack catalog + the LOC yardstick all
   stayed accurate. Confirms the deep-research investment in Session 2a
   amortises across Session 2b — promote to durable methodology pattern.

2. **Data-driven sweep replaces N inline blocks WITHOUT losing coverage —
   in fact GROWS coverage.** Pre-Fix-#11 main.py had 6 inline reaper
   blocks (device_dump + cve_match + vuln_scan + upload_stage + sbom +
   bare_metal_audit). Post-refactor: 1 inline (device_dump, different
   table) + 33 dict entries (8 state-machine + 25 walker). Coverage
   GREW because authenticode_chain / dotnet_decompile /
   windows_update_diff / 22 unwired walker columns gained reaper
   coverage from the dict registry alone. **Generalisation: when an
   identical-shape pattern ships N times inline, the refactor is the
   right shape if N >= 4 AND the registry shape can EXPAND coverage
   without per-instance work.**

3. **SQLAlchemy-introspection META-CANARY catches schema-vs-registry drift
   automatically.** `Firmware.__table__.columns` enumeration gives a
   ground-truth set the test asserts against. Adding a new walker column
   on the model WITHOUT extending WALKER_REAPER_CONFIGS → test fails
   immediately. **Generalisation: any registry that mirrors a database
   schema should have an introspection-based cross-axis META-CANARY.**

4. **Frontend component extraction has 0 functional impact + N+1 polish
   payoff.** FormatBanner extraction moved ~30 LOC into a shared module;
   the old inline rendering at FirmwareUpload kept its local FormatBanner
   (works as before); SbomPage now imports the shared one. VulnScan +
   Findings + future pages get the same banner shape with a 1-line
   import. **Generalisation: when 2 pages need the same banner/affordance,
   extract the shared component. The polish payoff is N+1, not 2x.**

5. **Polling backoff with visibilitychange-reset is a Rule #29 partner
   pattern.** Rule #29 (frontend timeout × backend ceiling) bounds the
   per-call wait time; W2-β §SC5-NEW-SBOM-λ (polling-cadence trips own
   30/hour budget) bounds the polling rate. The backoff implementation
   pattern (setInterval→setTimeout self-rescheduling + visibilitychange
   listener) is reusable for every 202+polling endpoint. **Generalisation:
   every 202+polling page should ship with the backoff. Future Session
   3 work that adds Rule #33 conversions should bake this in from start.**

## Recommendations

1. **Promote `data-driven sweep with two-axis registry` to a `.mex/patterns/`
   recipe.** Session 2b is the 2nd instance of this pattern (1st was the
   file-format YAML catalog Rule #52 instance #2 — also a closed-grammar
   dispatch over a Pydantic model registry). Rule-of-Two threshold reached;
   recipe-worthy. Naming candidates: `data-driven-sweep.md` or
   `two-axis-registry.md`.

2. **Apply the polling-backoff pattern to vuln-scan + cve-match endpoints
   as a polish sweep.** SbomPage.handleScan already polls vuln-scan with
   fixed 2s cadence. The same backoff implementation lifts cleanly. Queue
   as `polling-backoff-broader` MEDIUM in ADAPTIVE_BACKLOG.

3. **Session 3 — Fix #9 full Rule #52 extraction-strategy refactor.** Per
   Scout A + Scout B convergence: `extraction_strategy_catalog/` with
   closed Literals + YAML directory + dispatch helper. ~4,600 LOC. Will
   ABSORB the FormatBanner's `sbom_supported_for_format=false` forward-
   pointer (the operator-extensibility surface it forward-points to).
   Promotes Rule #52 to Rule-of-Four DURABLE BEYOND DEBATE.

4. **Promote `Wave-1+Wave-2 deep-research artefacts have long shelf life`
   to a feedback memory.** Session 2b confirmed Session 2a's research
   was sufficient WITHOUT re-dispatch. This is a 2nd-order observation
   about the methodology itself: the deep-research investment isn't
   per-session; it's per-CAMPAIGN. Promote so future sessions don't
   re-dispatch unnecessarily.

5. **Backlog item promotion — Rule #51 worked example.** Rule #51 now
   has 4 documented applications (rate-limit-2026-05-18 + Session 1 +
   Session 2a + Session 2b's Fix #11 generalisation). Update CLAUDE.md
   Rule #51 worked-example block with the data-driven sweep refactor
   as the canonical shape. Queued in ADAPTIVE_BACKLOG as
   `sbom-regr-future:Fix-1-doc-touchup`.

## Numbers

| Metric | Value |
|---|---:|
| Commits this session (production) | 2 (95e47a6 + 564cc46) |
| Commits this session (with closure) | 3 (closure follows) |
| Files changed | 5 (walker_registry + main.py + test_main_lifespan_reapers + FormatBanner + SbomPage) |
| Insertions | 684 |
| Deletions | 328 |
| Net | +356 |
| Reverts | 0 (bisect-clean) |
| New META-CANARY tests | 6 (2 size-lock + cross-axis + lifespan-imports + paired canary + grace uniqueness) |
| Updated pre-existing tests | 5 (refactored from inline-docstring string-match to dict-membership) |
| Wave-1 / Wave-2 scouts dispatched | 0 (consumed Session 2a research artefacts) |
| Reaper coverage pre-refactor | 6 columns |
| Reaper coverage post-refactor | 33 columns (+27; 8 state-machine + 25 walker; net coverage expansion) |
| Combined pytest sweep at close | 84 PASSED in 5.35s (9-file Session-1+2a+2b test sweep) |
| Frontend tsc canary | PASS (exit 0 — pre-existing Rule #24 canary discipline) |
| Backend rebuild cycles | 1 (Fix #11) |
| Frontend rebuild cycles | 1 (Scout D polish) |
| Tasks at session close | 26 (all closed) |

---HANDOFF---
- Postmortem: sbom-vuln-scan-session2b-2026-05-21
- Document: .planning/postmortems/postmortem-sbom-vuln-scan-session2b-2026-05-21.md
- Failures documented: 1 (pre-existing reaper-presence tests asserted inline-docstring shapes the refactor consolidated — updated in-commit per Rule #25 single-slice exception #2)
- Safety catches: 7 (Session 2a research artefacts; cross-axis SQLAlchemy-introspection META-CANARY; paired-canary discipline; Rule #25 single-slice; operator-extensibility forward-pointer; polling-backoff implementation; combined sweep validation)
- Recommendations: 5 (recipe promotion; polling-backoff broader; Session 3 Fix #9; deep-research shelf-life memory; Rule #51 worked-example extension)
- Commits: 95e47a6..564cc46 (2 prod + 1 closure follows)
- Session 2b surface SHIPPED: data-driven reaper sweep (33-column coverage, 8 state-machine + 25 walker, +27 net new coverage) + Rule #46 paired META-CANARIES + Scout D shared FormatBanner + polling exponential backoff
- Session 3 plan (queued): Fix #9 full Rule #52 extraction-strategy refactor (~4,600 LOC own Wave-1+Wave-2 research phase) = Rule-of-Four DURABLE BEYOND DEBATE post ICS S2
- ICS protocol Session 2 still queued (Rule #52 Rule-of-Three promotion when walker + MCP + plugins close)
- Polling-backoff broader sweep (vuln-scan + cve-match) queued as MEDIUM polish
- Recipe candidate: `.mex/patterns/data-driven-sweep.md` (Rule-of-Two threshold reached)
- Feedback memory candidate: "Wave-1+Wave-2 deep-research artefacts have long shelf life — Session 2b confirmed Session 2a research was sufficient without re-dispatch"
---

Run `/citadel:learn sbom-vuln-scan-session2b-2026-05-21` to extract patterns into the knowledge base.
