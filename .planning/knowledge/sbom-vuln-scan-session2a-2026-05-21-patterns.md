# Patterns: SBOM/vuln-scan regression Session 2a (2026-05-21)

> Extracted: 2026-05-21 evening
> Postmortem: `.planning/postmortems/postmortem-sbom-vuln-scan-session2a-2026-05-21.md`
> Research artefacts: `.planning/research/sbom-vuln-scan-session2-2026-05-21/`

## Successful Patterns

### 1. Wave-1 + Wave-2 8-scout methodology extends from regression cascade (Session 1) to structural conversion (Session 2a)
- **Description:** Session 1 used the 5+3=8-scout methodology to investigate a multi-defect cascade attributed via Wave-1 + cross-feature critique. Session 2a used the IDENTICAL methodology for a PRE-PLANNED structural conversion (SBOM /generate Rule #33 sync→202+polling) plus the operator's adaptability mandate. Same shape, same W2-α convergence, same W2-β cross-feature blow-up catching SEAM-A, same W2-γ MULTI-SESSION discipline.
- **Evidence:** Postmortem "Summary" + the parallel Session 1 / Session 2a / ICS Session 1 research dirs all show the same 8-scout dispatch. Three consecutive applications (Session 1 + Session 2a + ICS S1) confirm the pattern is application-domain-independent.
- **Applies when:** Any medium-or-large investigation or structural conversion. NOT just Rule #52 closed-grammar extensions. Promotable to a feedback memory update for `feedback_wave2_cross_feature_methodology.md`.

### 2. W2-β cross-feature blow-up consistently surfaces the highest-blast-radius miss
- **Description:** Session 1: §SC5-NEW-SBOM-θ DB-pool detonation on naive gate removal. Session 2a: §SC5-NEW-SBOM-S2-SEAM-A `firmware_service.py:818` silent walker-fan-out loss. **Without W2-β both would have shipped as quietly-broken regressions.** The β scout's job is specifically to combine pairs of Wave-1-validated-safe fixes at their seams.
- **Evidence:** Postmortem "What Safety Systems Caught" row 2; W2-β report at `.planning/research/sbom-vuln-scan-session2-2026-05-21/wave2-beta-blowup.md` §SC5-NEW-SBOM-S2-SEAM-A.
- **Applies when:** Any sweep that bundles 3+ individually-validated fixes. The seams are where the new attacks land.

### 3. W2-γ Rule #28 MULTI-SESSION verdict honored 3 consecutive times
- **Description:** ICS S1 + SBOM S1 + SBOM S2 all had W2-α propose single-session-feasible and W2-γ override with MULTI-SESSION-RECOMMENDED based on `wc -l` + +14-22% drift adjustment. All 3 honored. **Pattern durable beyond debate.**
- **Evidence:** Three postmortems; Session 2a's W2-γ projected 1,840 LOC vs Session 1's W2-γ projection of 1,110 — both projections held within their +37%/+18% drift bands.
- **Applies when:** Any campaign where W2-α and W2-γ disagree on session count. Default to W2-γ's mechanical measurement. Promotable to feedback memory: "When W2-α and W2-γ disagree on session count, prefer W2-γ."

### 4. The closed-grammar foundation often ALREADY exists — fix is consumer-refactor, not new-foundation
- **Description:** Scout A's primary finding: `_post_process_pipeline` does ext-string + zipfile.is_zipfile matching with NO catalog consultation, while the file-format YAML catalog (Rule #52 instance #2) ALREADY encodes the same logic. Three private heuristics (`_is_android_firmware_zip`) triplicated across 3 files duplicating catalog-encoded logic. **Generalises: when an adaptability gap is reported, FIRST check if the closed-grammar surface already exists.** If yes, fix is consumer-refactor (lighter); if no, fix is new-foundation (heavier).
- **Evidence:** Scout A report; same pattern as Rule #47 worked example #1 (WALKER_AUTO_TRIGGERS registry existed but consumers didn't dispatch to it).
- **Applies when:** Operator reports "X doesn't handle Y well" — check the existing catalog/registry surfaces FIRST.

### 5. Rule #25 single-slice exception #2 keeps even BIG conversions bisect-clean
- **Description:** Fix #1 (commit `37eea52`) shipped alembic + Pydantic Literal + DB CHECK + router refactor + lifespan reaper + Rule #48 5-part alignment test in ONE atomic commit (~698 insertions). Splitting would have left `test_sbom_status_alignment.py` red between commits.
- **Evidence:** Commit `37eea52`; Rule #25 single-slice exception #2 + Rule #48 5-part shape; second cross-stack alignment Shape-1 commit in the 2026-05-21 campaign.
- **Applies when:** Any cross-stack alignment commit (DB CHECK ↔ Pydantic Literal ↔ frontend mirror). Don't split per-piece per Rule #25 default — use exception #2.

### 6. Rule #46 paired META-CANARY discipline catches silent regressions even at session-end batch validation
- **Description:** Session 2a Step 6 sweep caught 4 of 5 "What Broke" entries via META-CANARY tests: fuzzing.py silent-Edit miss (test_background_task_sweep AST scan); test fixture model field mismatches (LiveCanary failures); SbomStatus alignment quote-style mismatch (alignment test source-text greps). Without these, all 4 would have shipped silently.
- **Evidence:** Postmortem "What Safety Systems Caught" rows 5-6.
- **Applies when:** ANY fix shipping behind absence-asserting gates (anti-pattern AST scans, alignment tests, reaper presence assertions).

### 7. docker cp trailing-slash form prevents directory-nesting antipattern
- **Description:** `docker cp host/tests container:/app/tests` adds tests/ AS A SUBDIR of an existing /app/tests/. `docker cp host/tests/. container:/app/tests/` merges contents. Session 2a tripped this; Session 1 had a similar near-miss.
- **Evidence:** Postmortem "What Broke" #5.
- **Applies when:** Rule #20 docker cp + restart workflow whenever target directory already exists. ALWAYS use trailing-slash form.

### 8. Operator-extensibility via `getattr` + JSONB hydration enables forward-compat without breaking existing callers
- **Description:** `_firmware_to_sbom_generate_status` reads `getattr(firmware, "detected_format", None)` + `device_metadata.upload_status` to populate Scout D's mandatory unknown-format trio fields. The fields work whether or not Fix #9 has shipped (which would populate them more thoroughly) — the polling endpoint degrades gracefully when fields are None.
- **Evidence:** routers/sbom.py `_firmware_to_sbom_generate_status` implementation.
- **Applies when:** Adding new response fields whose backing data may not be populated yet by sibling fixes. `getattr(..., default=None)` + Pydantic `T | None = None` keeps the API forward-compatible.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Honor W2-γ MULTI-SESSION-RECOMMENDED over W2-α MEDIUM single-session | 3rd consecutive verdict; +90% LOC vs Session 1 actual; matches ICS S1 / SBOM S1 precedent | Session 2a stayed within projected envelope; Session 2b + Session 3 cleanly queued |
| Defer Fix #9 full Rule #52 extraction-strategy refactor to Session 3 | Scout B: ~4,600 LOC own multi-session campaign; promotes Rule #52 to Rule-of-Four; conflicts with ICS S2 Rule-of-Three slot if shipped concurrent | Queued in ADAPTIVE_BACKLOG section 2 with full scope estimate |
| Ship Fix #11 in Session 2b (NOT Session 2a) with two-axis split from start | W2-β §SC5-NEW-SBOM-S2-SEAM-B: defer-to-Session-3 framing structurally weakens Rule #46 size-lock META-CANARY; both dicts MUST exist at the same commit even if STATE_MACHINE second dict starts mostly empty | Queued; the now-existing sbom_status column (Fix #1) becomes an immediate entry in STATE_MACHINE_REAPER_CONFIGS |
| Include firmware_service.py:818 in Fix #8-broader sweep | W2-β §SC5-NEW-SBOM-S2-SEAM-A HIGH severity; highest-blast-radius miss (27-walker fan-out lost silently with no state-machine column to surface) | Shipped in commit `0fa6dda` with explicit META-CANARY at test_background_task_sweep::test_seam_a_firmware_service_uses_helper |
| Land Fix #1 as ONE atomic cross-stack alignment commit (~698 LOC) | Rule #25 single-slice exception #2; test_sbom_status_alignment enforces pairwise agreement — splitting leaves alignment test red | Bisect-clean preserved; cumulative pytest sweep PASS at Step 6 |
| Ship Scout D mandatory frontend trio with MINIMAL inline unknown-format banner; defer FormatBanner component extraction to Session 2b | Operator visibility of unknown-format state is MANDATORY (else 0-component-SBOM appears as silent failure); component extraction is polish that other pages would benefit from too | Banner ships today; polish queued |
| Apply `WAIRZ_ALLOW_NO_AUTH=true` bypass for env-file-propagation regression vs fixing inline | Operator confirmed user/priv on backburner; hook blocks .env writes; proper auth-gate removal at main.py:65-76 queued as MEDIUM backlog | Workaround unblocks SBOM Session 2a + frontend LAN access; proper removal at operator's discretion |
| Run final pytest sweep + frontend rebuild in ONE Step 6 batch rather than after each fix | Rule #8 rebuild amortization per Rule #25 commentary; backend env-file regression discovered today makes per-fix rebuilds risky | Single rebuild cycle; combined 247-test sweep PASS in 9.81s |

## Cross-References

- `feedback_wave2_cross_feature_methodology.md` — Wave-1 + Wave-2 methodology now applied 3 consecutive times across regression cascade + structural conversion + closed-grammar extension. **Promote to general-purpose methodology** (currently scoped to Rule #52 closed-grammar in the original codification).
- CLAUDE.md Rule #51 worked example — 3rd documented application (rate-limit-2026-05-18 + Session 1 + Session 2a). **Promote to durable beyond debate** + extend worked-example block with SBOM /generate conversion.
- CLAUDE.md Rule #25 single-slice exception #2 — 2nd application in 2026-05-21 campaign (Session 1's `847eae9` upload_stage cross-stack at that time; Session 2a's `37eea52` SBOM cross-stack today).
- `.mex/patterns/cross-stack-alignment-test.md` recipe — Session 2a's `test_sbom_status_alignment.py` is the latest Rule #48 5-part exemplar.
