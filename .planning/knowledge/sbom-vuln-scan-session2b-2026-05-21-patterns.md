# Patterns: SBOM/vuln-scan regression Session 2b (2026-05-21)

> Extracted: 2026-05-21 evening
> Postmortem: `.planning/postmortems/postmortem-sbom-vuln-scan-session2b-2026-05-21.md`

## Successful Patterns

### 1. Wave-1+Wave-2 deep-research artefacts have long shelf life
- **Description:** Session 2b consumed Session 2a's research artefacts WITHOUT re-dispatching a new Wave-1+Wave-2 round. The architectural spec (Fix #11 Option B + W2-β §SC5-NEW-SBOM-S2-SEAM-B two-axis mandate), the attack catalog, and the LOC yardstick all stayed accurate. **Confirms the deep-research investment is per-CAMPAIGN, not per-session.**
- **Evidence:** Zero scout dispatches; 2 production commits + 1 closure shipped in Session 2b. The research artefacts from Session 2a (W2-α convergence, W2-β blow-up, W2-γ yardstick) were sufficient.
- **Applies when:** Multi-session campaigns where Session N's design is locked by Session N-1's research. Don't re-dispatch unless the scope materially changes.

### 2. Data-driven sweep with two-axis registry — Rule-of-Two pattern emerging
- **Description:** Fix #11 consolidates 6 inline reaper blocks (180 LOC of identical-shape try/SQL/except) into a data-driven sweep over 2 dict registries (STATE_MACHINE_REAPER_CONFIGS × WALKER_REAPER_CONFIGS, both consuming a shared WalkerReaperConfig frozen dataclass). Coverage GREW from 6 columns to 33 (+27) because the registry shape can include columns that weren't worth an inline block. **2nd instance of two-axis dispatch over a Pydantic/dataclass registry** (1st: file-format YAML catalog Rule #52 instance #2). Rule-of-Two threshold reached.
- **Evidence:** Commit `95e47a6`; -180 LOC inline removed + 235 LOC registry + 95 LOC sweep + 130 LOC META-CANARIES = +280 net for +27 columns of new coverage.
- **Applies when:** N identical-shape inline blocks where N >= 4 AND the registry shape can EXPAND coverage without per-instance work.

### 3. SQLAlchemy-introspection META-CANARY catches schema-vs-registry drift automatically
- **Description:** `test_walker_reaper_configs_size_lock_matches_firmware_model` enumerates `Firmware.__table__.columns` via SQLAlchemy + asserts every `*_walk_status` column has a WALKER_REAPER_CONFIGS entry. **Adding a new walker column on the model WITHOUT extending the registry → test fails immediately.** The cross-axis check is a stronger discipline than per-instance size-lock.
- **Evidence:** `tests/test_main_lifespan_reapers.py::test_walker_reaper_configs_size_lock_matches_firmware_model`.
- **Applies when:** Any registry that mirrors a database schema. The introspection-based cross-axis META-CANARY is the right shape; pure dict-size assertions are weaker.

### 4. Frontend component extraction has 0 functional impact + N+1 polish payoff
- **Description:** FormatBanner extraction moved ~30 LOC into a shared module; old inline rendering kept (works as before); SbomPage now imports the shared one. VulnScan + Findings + future pages get the same banner shape with 1-line import.
- **Evidence:** Commit `564cc46`; `frontend/src/components/firmware/FormatBanner.tsx` is the new shared module.
- **Applies when:** ≥2 pages need the same UI affordance. Don't refactor for 1 page; do refactor for 2+.

### 5. Polling backoff with visibilitychange-reset is a Rule #29 partner pattern
- **Description:** Rule #29 (frontend timeout × backend ceiling) bounds per-call wait time; W2-β §SC5-NEW-SBOM-λ (polling-cadence trips own 30/hour budget) bounds polling rate. Implementation: setInterval→setTimeout self-rescheduling, 2s→4/8/16/32s upper-clamp, reset on (a) any state transition OR (b) `document.visibilitychange` tab-becomes-visible event. Bounds a 60-min Syft job at 2s polling from 1800 GETs to ~120.
- **Evidence:** SbomPage.tsx polling effect post-commit `564cc46`.
- **Applies when:** Every 202+polling page. Reusable across vuln-scan / cve-match / firmware-unpack / emulation polling. Queued as `polling-backoff-broader` MEDIUM.

### 6. Rule #25 single-slice exception #2 covers refactor + tests in same commit
- **Description:** Fix #11 ships refactor (-180 inline) + 2 dict registries (+235) + lifespan rewrite (+95) + 6 NEW META-CANARIES + 5 UPDATED pre-existing tests (~130 LOC) in ONE commit. Splitting would leave the old tests RED between commits (they asserted on inline-docstring shapes that the refactor consolidated).
- **Evidence:** Commit `95e47a6` (3 files, +527 / -292).
- **Applies when:** Any refactor that obsoletes pre-existing tests. Update tests in same commit per Rule #25 single-slice exception #2.

### 7. Net-coverage-EXPANDING refactor is structurally superior to inline-pattern-N
- **Description:** Pre-Fix-#11 had 6 reaper blocks (cve_match + vuln_scan + sbom + bare_metal_audit + upload_stage + device_dump). Post-refactor: 1 inline (device_dump, different table) + 33 dict entries. Coverage GREW because authenticode_chain / dotnet_decompile / windows_update_diff / 22 unwired walker columns were "implicit deferred" inline-cost-too-high entries that now ship for free. **The refactor is the right time to extend coverage — adding 27 inline blocks would have been the wrong move at any prior point.**
- **Evidence:** Postmortem "Scope Analysis" + coverage counts.
- **Applies when:** Refactoring an inline pattern; check if the registry shape unlocks deferred coverage.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Don't dispatch new Wave-1+Wave-2 for Session 2b | Session 2a's research artefacts locked the design; re-dispatch would cost ~30 min context + 8 scout reports for zero added value | 2 production commits + 1 closure shipped efficiently |
| Update 5 pre-existing reaper-presence tests in the SAME commit as Fix #11 refactor | Rule #25 single-slice exception #2; splitting would leave tests red between commits | Bisect-clean preserved |
| Ship coverage expansion (6→33 columns) inside the refactor commit, NOT as a follow-up | Adding the missing 27 columns is what the registry shape was BUILT FOR; deferring them would have left the refactor pointless | +27 columns of orphan-reaper coverage shipped today |
| Keep device_dump_session reaper INLINE (not in the dict registry) | Different table (DeviceDumpSession not Firmware); special-cased shape; not worth the dict overhead for one-off | Cleaner registry shape; explicit comment in main.py |
| Extract FormatBanner to `components/firmware/` (not `components/sbom/`) | Component is firmware-domain (format detection); applies to multiple pages (SbomPage, future VulnScan, Findings); not SBOM-specific | Future pages adopt with 1-line import |
| Add `sbom_supported_for_format` forward-pointer to Rule #52 closed-grammar surface in FormatBanner copy | Operator's Rule #52 mandate ("we won't be the only ones ingesting files") — explicit operator-visible signal that YAML-extensibility is coming | Sets up Session 3's extraction-strategy catalog story |
| Polling-backoff implementation as setInterval→setTimeout self-rescheduling (not setInterval with conditional rate) | Self-rescheduling avoids the "fire 5 ticks while one is pending" trap; cleaner shape; matches firmware-unpack precedent at ProjectDetailPage | Reusable pattern; queued for broader sweep |

## Cross-References

- `feedback_wave2_cross_feature_methodology.md` — Session 2b's "no re-dispatch" outcome confirms artefact shelf-life. **Promote to feedback memory:** "Wave-1+Wave-2 deep-research artefacts have long shelf life — Session 2b confirmed Session 2a research was sufficient without re-dispatch."
- `.mex/patterns/cross-stack-alignment-test.md` — Session 2b's introspection-based META-CANARY is a sibling pattern (cross-axis schema/registry alignment). Update recipe to note the SQLAlchemy `__table__.columns` enumeration trick as a stronger discipline than dict-size assertions.
- CLAUDE.md Rule #51 worked example — 4th documented application (rate-limit-2026-05-18 + Session 1 + Session 2a + Session 2b). **Promote** the worked-example block to include the data-driven sweep refactor as the durable shape for any Rule #51 .i-style "reaper companion" coverage when N >= 4 inline blocks accumulate.
- New recipe candidate: `.mex/patterns/data-driven-sweep.md` (Rule-of-Two threshold reached: file-format YAML catalog + Fix #11 walker reaper sweep).
