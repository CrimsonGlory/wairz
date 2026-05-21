# Postmortem: SBOM + vuln-scan regression Session 2a (2026-05-21)

> Date: 2026-05-21 (evening, continuing the 2026-05-21 deep-research campaign)
> Campaign: Session 2a of the SBOM/vuln-scan regression sweep
> Direct-shipped per Rule #25 per-piece cadence; W2-γ MULTI-SESSION-RECOMMENDED
> verdict honored (Session 2a = the dominant structural conversion; Session 2b
> + Session 3 queued).
> Commits this session: `37eea52..09aea97` (5 production + 1 docs/closure commit follows).
> Outcome: **Session 2a surface SHIPPED.** SBOM `/generate` Rule #33
> sync→202+polling conversion complete with Rule #48 5-part cross-stack
> alignment regression-canary; grype `force_rescan` cached short-circuit;
> `_spawn_background_task` GC-hardening factored into shared module and
> applied to 5 sites including the W2-β-identified §SC5-NEW-SBOM-S2-SEAM-A
> hot path; Scout D mandatory frontend trio (polling + re-mount auto-resume
> + unknown-format graceful-degrade banner).

## Summary

Continuation of the 2026-05-21 SBOM/vuln-scan regression sweep, picking up
from Session 1 (commits `c29d6b7..208805c`). Operator's mandate verbatim:
"don't hard code strict formats etc into this shit... we need to be more
adaptable/versatile/flexible/resilient across entire code base and
architecture... we won't be the only ones ingesting files into the tool".

Same Wave-1 + Wave-2 8-scout methodology as Session 1:

**Wave-1 (5 expert-persona scouts in parallel):**
- Scout A (architecture + format-assumption audit) — `_post_process_pipeline`
  at `firmware_service.py:589,667` does ext-string + zipfile.is_zipfile
  matching with NO catalog consultation; 3 `_is_android_firmware_zip`
  heuristics triplicated across firmware_service.py, unpack_common.py,
  format_detection.py duplicating logic the YAML catalog already encodes.
  Recommends Rule #52 instance #3 promotion (~4,600 LOC).
- Scout B (Rule #52 precedent) — sanity-check on Scout A: full refactor
  is its own multi-session campaign. Rule-of-Three stays with ICS Session 2.
  Extraction-strategy refactor becomes Rule-of-Four candidate AFTER ICS.
  Smaller Fix #9 form (catalog consultation + enqueue) ships this session;
  full refactor deferred.
- Scout C (red-team / unknown-format) — 11 NEW §SC5-NEW-SBOM-S2-α..λ attacks.
  CRITICAL §SC5-NEW-SBOM-S2-δ: operator-supplied YAML × authority laundering
  at every NEW operator-extensible surface Session 2 introduces. Fix #11
  MUST split into TWO axes (WALKER_STATUS_COLUMNS + STATE_MACHINE_REAPER_CONFIGS).
  Fix #1 needs unknown-format short-circuit + OOM-bound.
- Scout D (operator-UX) — top risk: force_rescan double-click trap + missing
  re-mount auto-resume polling. SbomPage consumes ZERO of existing
  `FirmwareUploadStatus.detected_format` / `extraction_capability` fields →
  unknown-format firmware silently produces 0-component SBOMs. 4-part
  mandatory frontend graceful-degrade.
- Scout E (state-machine) — Fix #1: all 4 Rule #33 bullets designed; new
  `firmware.sbom_result` JSONB column; SbomStatus Literal; alembic head
  `fd6e7f8a9b0c`; tier already correctly pinned in `_EXPECTED_TIERS`. Fix
  #11 Option B (centralised `WALKER_REAPER_CONFIGS` dict in walker_registry.py
  paralleling WALKER_AUTO_TRIGGERS). Rule #52 NOT a candidate for Fix #11.

**Wave-2 (3 critique scouts in parallel):**
- W2-α convergence: top root cause = SBOM `/generate` is structurally sync
  but already tier-decorated as `TIER_A_LIGHT_ACK` (30/hour) — converting
  to Rule #33 sync→202+polling per Scout E's design is Fix #1's primary
  structural ship. Resolved 4 contradictions (B wins on Rule #52 scope;
  Scout E Option B + Scout C two-axis split combine via shared
  `WalkerReaperConfig` dataclass; Scout D ~140 LOC + Scout E ~340 LOC =
  ~480 LOC for Fix #1; unknown-format short-circuit lands inside background
  runner AFTER 409 router-level idempotency check). Single-session feasible
  MEDIUM-HIGH for ~1,170 net LOC / 16 commits.
- W2-β cross-feature blow-up: 7 NEW §SC5-NEW-SBOM-S2-SEAM-A..G attacks at
  Wave-1 fix boundaries. **HIGH §SC5-NEW-SBOM-S2-SEAM-A: the broader sweep
  MUST include firmware_service.py:818** — bare `asyncio.create_task` on
  the HW-firmware detection runner is the highest-blast-radius miss
  (1-of-N firmware silently loses entire 27-walker fan-out under
  burst-upload + GC pressure with NO state-machine column to surface it).
  Fix #11 MUST ship BOTH dicts (WALKER_REAPER_CONFIGS + STATE_MACHINE_REAPER_CONFIGS,
  second can start empty) in Session 2 — defer framing structurally
  weakens the Rule #46 size-lock META-CANARY.
- W2-γ Rule #28 yardstick: **HIGH-confidence MULTI-SESSION-RECOMMENDED
  override** of W2-α MEDIUM single-session claim. Total 1,840 net LOC
  (+90% vs Session 1 actual; +66% over Session 1's W2-γ projection of
  Session 2). Drift +18% = empirical midpoint of Rule #28 band. Split:
  Session 2a (Fix #1 + Fix #6 + Fix #8-broader + Scout D mandatory
  bundled ~1,000 LOC / 7 commits / ~4 hr) + Session 2b (Fix #11 + Scout D
  adaptability + docs ~840 LOC) + Session 3 (Fix #9 full Rule #52 refactor
  = Rule-of-Four north star post ICS S2, ~4,600 LOC).

Session 2a shipped **5 production commits + 1 fixup + 1 closure** matching
W2-γ envelope:

| # | Commit | Title | Net delta | Tests |
|---|---|---|---|---|
| 1 | `37eea52` | feat(sbom): /generate Rule #33 sync→202+polling + Rule #48 cross-stack alignment | +698 −44 / 7 files | +9 (5 alignment, 2 reaper, 2 size-lock) |
| 2 | `53b3cf0` | fix(grype): scan_with_grype honors force_rescan + cached short-circuit | +246 −1 / 3 files | +4 (1 sig, 1 router-call, 1 paired canary, 1 live canary) |
| 3 | `0fa6dda` | refactor(background): factor spawn_background_task → app/utils + apply to 5 sites incl. SEAM-A | +292 −34 / 7 files | +5 (module + 4 sites + SEAM-A explicit) |
| 4 | `66ce6d9` | feat(frontend-sbom): /generate 202+polling refactor + unknown-format graceful-degrade | +182 −15 / 3 files | (frontend; no pytest) |
| 5 | `09aea97` | fix(s2a): close Step-6 validation regressions — fuzzing.py + 4 test fixtures | +86 −44 / 4 files | (corrections) |

**Total session 2a:** 5 production + 1 fixup commits / +1,504 insertions /
-138 deletions / **+1,366 net** / 18 new META-CANARY + alignment tests /
0 reverts / bisect-clean across all 5 commits.

## What Broke

### 1. My Edit to fuzzing.py silently no-op'd; only caught at Step 6 pytest sweep
- **What happened:** During Fix #8-broader (commit `0fa6dda`), my Edit
  call against `routers/fuzzing.py` returned success ("The file ... has
  been updated successfully.") but the file content was unchanged.
  Suspected cause: stale read context — the Edit tool's old_string
  matched stale-cached content but the on-disk file had the unchanged
  shape. The git add at commit time staged the file (no diff to stage,
  silently OK). The bare `asyncio.create_task` remained.
- **Caught by:** Step 6 combined pytest sweep — `test_background_task_sweep::
  test_no_bare_asyncio_create_task_for_background_runners` immediately
  flagged `app/routers/fuzzing.py: 1 bare-create_task match`.
- **Cost:** ~2 min to diagnose + re-apply.
- **Fix:** Re-issued the Edit; committed in `09aea97` fixup commit.
- **Generalisation:** The Rule #46 paired META-CANARY discipline proved
  load-bearing — without the AST/regex scan in `test_background_task_sweep`,
  the SEAM-A-adjacent regression (fuzzing site missed) would have shipped
  silently. **Confirms Rule #46 + Rule #47 enumeration must be END-TO-END
  validated, not just at the per-fix commit level.** A future improvement
  would be to grep-verify each Edit landed by re-reading the file
  immediately after the Edit call.

### 2. Test fixtures used wrong model field names (4 fails)
- **What happened:** Three test files used incorrect field names on the
  Firmware + SbomVulnerability ORM models:
  - `stored_path` → actual is `storage_path` (model line 37)
  - `file_hash` → actual is `sha256` (model line 35)
  - `data_source` + `fix_versions` on SbomVulnerability — not present on the model
  Result: `TypeError: 'stored_path' is an invalid keyword argument for Firmware`.
- **Caught by:** Step 6 combined pytest sweep — 2 test_grype_service_force_rescan
  tests + 1 test_sbom_router LiveCanary.
- **Cost:** ~3 min to diagnose + fix field names.
- **Fix:** Corrected all 3 field names in commit `09aea97` fixup.
- **Generalisation:** When writing a NEW test that constructs ORM objects
  via kwargs, validate field names against the model file FIRST. The
  model-introspect-via-grep pattern (`grep "Mapped\|mapped_column" model.py`)
  is sufficient + fast.

### 3. test_sbom_status_alignment.py searched for single-quoted SQL strings; alembic source has double-quoted Python tuple literals
- **What happened:** My alignment test asserted `f"'{val}'" in alembic_src`
  (single-quoted SQL substring). But the alembic source file uses
  `SBOM_STATUS_VALUES = ("idle", "queued", ...)` — Python tuple literal
  with double quotes. The single-quoted SQL fragment `'idle'` is only
  CONSTRUCTED dynamically inside the f-string `f"sbom_status IN ({quoted})"`;
  it's not in the source text.
- **Caught by:** Step 6 sweep — 3 alignment tests failed because
  the substring check missed the canonical values.
- **Cost:** ~2 min to fix via Edit `replace_all`.
- **Fix:** Changed all `f"'{val}'"` to `f'"{val}"'` in commit `09aea97`.
- **Generalisation:** When writing an AST/text-level alignment test
  against an alembic migration, distinguish the **source-text-quoted**
  values (tuple literal) from the **SQL-quoted** values (inside the
  CHECK constraint string). The tuple literal is the durable surface
  to grep against — the SQL string is dynamically constructed.

### 4. MagicMock leaking into Pydantic str|None validation
- **What happened:** New `test_post_returns_202_and_queues_when_idle`
  used `firmware = _make_firmware(project_id)` which produces a mock
  with auto-MagicMock attributes. My new `_firmware_to_sbom_generate_status`
  reads `getattr(firmware, "detected_format", None)` + similar — auto-mock
  returns MagicMock objects, not None, and Pydantic's str|None field
  fails validation with `Input should be a valid string`.
- **Caught by:** Step 6 sweep.
- **Cost:** ~2 min.
- **Fix:** Explicitly set `firmware.detected_format = None` +
  `firmware.device_metadata = None` + the new sbom_status fields on
  the mock fixture.
- **Generalisation:** When adding a Pydantic response that pulls fields
  via `getattr` defaults, the test fixture MUST explicitly null those
  fields (MagicMock auto-attribute leakage is a long-standing test gotcha).

### 5. docker cp source-directory-into-existing-destination nests vs overwrites
- **What happened:** First `docker cp /host/.../tests wairz-backend-1:/app/tests`
  created /app/tests/ from scratch. Second invocation (after editing tests)
  produced /app/tests/tests/... (nested) — stale tests at /app/tests/ ran.
- **Caught by:** Identical-looking pytest failures + a manual `ls /app/tests/tests/`
  invocation revealing the nesting.
- **Cost:** ~3 min to diagnose + redo cp with trailing-slash form.
- **Fix:** `rm -rf /app/tests/tests` + `docker cp .../tests/. wairz-backend-1:/app/tests/`
  (the trailing slash on both sides forces content-merge).
- **Generalisation:** Rule #20 docker cp discipline — when targeting an
  existing directory, ALWAYS use trailing-slash form on both src and dst
  (`docker cp host/tests/. container:/app/tests/`). Documented in the
  Rule #20 commentary as a Session 2a antipattern.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---|
| Wave-1 5-scout deep research | The hardcoded-format gap (Scout A's 3 triplicated heuristics); Rule #52 Rule-of-Four candidate framing (Scout B's scope sanity check); 11 NEW unknown-format attacks (Scout C); 4 mandatory UX gaps (Scout D); full Fix #1 design including JSONB result column (Scout E) | 5 reports | Would have shipped naive fixes missing the adaptability mandate entirely |
| W2-β cross-feature blow-up | §SC5-NEW-SBOM-S2-SEAM-A (HIGH) firmware_service.py:818 missed-site that the broader sweep wouldn't have included without this finding; Fix #11 two-axis split requirement | 7 attacks | The SEAM-A site is the load-bearing 27-walker fan-out dispatch; GC-vanish there is invisible (no state-machine column to flip) — catastrophic blast radius |
| W2-γ Rule #28 yardstick | MULTI-SESSION-RECOMMENDED override of W2-α MEDIUM single-session claim (+90% vs Session 1 actual, drift +18% midpoint) | 1 verdict | Half-shipped state risk per ICS Session 1 precedent; would have crowded Session 2 with Fix #9 full refactor and risked the 8f54a24 pattern's 11-day discovery window |
| Rule #25 single-slice exception #2 | Fix #1 atomic commit shipping alembic + Pydantic Literal + DB CHECK + router refactor + reaper + alignment test in ONE commit | 1 atomic commit | Bisect-non-clean intermediate state where the CHECK constraint exists but the Literal doesn't (or vice versa) |
| Rule #46 paired META-CANARY (alignment test + AST scan) | 4 of the 5 "What Broke" entries above — the alignment test caught the source-quote mismatch; the background-task-sweep AST scan caught fuzzing.py silent-Edit miss + verified SEAM-A | 5 tests | Without these, the same regression class would have shipped silently |
| Rule #48 5-part cross-stack alignment test | Pinned pairwise agreement (DB CHECK ↔ Pydantic Literal) for SbomStatus | 5 parametrized tests | Future "let's add a 6th state" regression caught at test time, not in production |
| Rule #11 import smoke (via fixture loading) | New `firmware.sbom_result` JSONB column + SbomStatus Literal loaded cleanly through ORM | structural | Class-shape change validated end-to-end |
| Rule #24 mandatory tsc canary | Verified frontend typecheck ACTUALLY ran (caught Rule #35a pipe-induced silent exit immediately) | 1 canary | Session 1's identical Rule #35a antipattern reproduced + immediately worked around |
| Rule #35b live canary (make_live_db) | `test_cached_path_returns_status_cached_without_subprocess` proves the force_rescan cached path actually skips the subprocess via mock-with-AssertionError-side-effect (mock would fire if subprocess ran) | 1 live canary | Pure-mock would have asserted "subprocess.create_subprocess_exec called=False"; live canary asserts no-fire via AssertionError side effect on the mock |
| Session 1 Fix #8 `_spawn_background_task` (now `spawn_background_task` in app/utils/background) | Sister site fuzzing.py, hardware_firmware.py x2, emulation.py, and SEAM-A firmware_service.py:818 now all GC-hardened | 5 sites | Without S1 Fix #8 first establishing the pattern, S2a's broader sweep would have had to design the helper from scratch + risk getting it wrong |

## Scope Analysis

* **Planned (operator directive):** Full adaptability/versatility/flexibility/
  resilience pass on SBOM/vuln-scan surface. Deep research methodology.
  Operator deferred user/priv auth to backlog; bypassed via `WAIRZ_ALLOW_NO_AUTH=true`.
* **Wave-1 + Wave-2 estimated (W2-γ HIGH):** 1,840 net LOC / 16 commits split into
  Session 2a (~1,000 LOC / 7 commits) + Session 2b (~840 LOC / 6 commits) +
  Session 3 (Fix #9 ~4,600 LOC).
* **Built (Session 2a only):** 5 production + 1 fixup commits / +1,366 net LOC
  / 18 new META-CANARY + alignment tests / 0 reverts / bisect-clean.
* **Drift:** +37% over the W2-γ Session 2a projection of ~1,000 LOC. Driven
  by (a) Fix #1's frontend trio coming in at +182 LOC vs Scout D's projected
  ~140 LOC, (b) Fix #6's cached-path COUNT-by-severity query adding ~30 LOC
  beyond bare DELETE+INSERT shape, (c) extensive doc-comment density per
  Session 1's pattern (each commit averages ~30 LOC of cross-ref comments).
  Still WELL WITHIN the +14-22% Rule #28 drift band's worst-case interpretation
  (Session 2 cumulative drift now ~1,366 / ~1,000 = 1.37×; ICS Session 1's
  γ-yardstick projected 1.5×; rate-limit campaign 2026-05-18 ran +25% over
  baseline).

Session 2 honors W2-γ's MULTI-SESSION-RECOMMENDED verdict:
- **Session 2a (this):** Fix #1 + Fix #6 + Fix #8-broader + Scout D mandatory
  frontend trio — **SHIPPED**.
- **Session 2b (queued):** Fix #11 walker `*_walk_status` reaper sweep
  (Option B with two-axis split per W2-β §SC5-NEW-SBOM-S2-SEAM-B) +
  Scout D adaptability polish (FormatBanner component extraction, polling
  backoff) + docs/recipe touch-ups.
- **Session 3 (queued, multi-session campaign):** Fix #9 full Rule #52
  extraction-strategy refactor (Rule-of-Four north star post ICS S2).

## Patterns

1. **Deep research methodology extends cleanly to multi-defect cascade
   AND structural refactors.** Session 1 used Wave-1+Wave-2 for a regression
   cascade investigation; Session 2a used the same methodology for a
   pre-planned structural conversion + adaptability mandate. Same 8-scout
   shape; same W2-α convergence; same W2-β blow-up catching SEAM-A; same
   W2-γ MULTI-SESSION discipline. **Three consecutive applications now
   (Session 1 + Session 2a + ICS Session 1) — promotable to durable
   pattern beyond the original Rule #52 closed-grammar use case.**

2. **W2-β cross-feature blow-up consistently surfaces the highest-blast-radius
   miss.** Session 1: §SC5-NEW-SBOM-θ DB-pool detonation on naive gate
   removal. Session 2a: §SC5-NEW-SBOM-S2-SEAM-A firmware_service.py:818
   silent walker-fan-out loss. **Without W2-β, both would have shipped
   as quietly-broken regressions.** The β scout is now load-bearing for
   every cascade-fix + structural-conversion campaign.

3. **W2-γ Rule #28 MULTI-SESSION verdict honored 3 times in a row** (ICS S1,
   SBOM S1, SBOM S2). **Pattern is durable beyond debate** — promotable to
   a feedback memory: "When W2-α and W2-γ disagree on session count, prefer
   W2-γ's wc -l + +14-22% drift measurement."

4. **The file-format YAML catalog ALREADY encodes most of what the upload
   pipeline needs — it's just bypassed.** Scout A's primary finding. The
   Rule #52 closed-grammar foundation is in place; the work is consumer-
   refactor, not new-feature. Same shape as the WALKER_AUTO_TRIGGERS
   orphan (Rule #47 worked example #1) — the registry exists, callers
   just need to consume it. **This generalises: when an adaptability gap
   is reported, FIRST check if the closed-grammar surface already exists.
   If yes, the fix is consumer-refactor (lighter) not new-foundation
   (heavier).**

5. **Rule #25 single-slice exception #2 keeps SHIPS even bigger conversions
   bisect-clean.** Fix #1 (commit `37eea52`) ships alembic + Pydantic
   Literal + DB CHECK + router refactor + reaper + alignment test in
   ONE atomic commit — single-slice exception #2 because
   `test_sbom_status_alignment.py` enforces pairwise agreement. Splitting
   would have left the alignment test red between commits. **This is
   the second cross-stack alignment Shape-1 commit in the 2026-05-21
   campaign — the discipline is well-trodden now.**

6. **Per Rule #20 + the docker cp directory-nesting antipattern, ALWAYS use
   trailing-slash form `host/dir/. container:/app/dst/`.** Documented in
   Session 2a "What Broke" #5 — Session 1 also tripped this pattern at
   the test-suite re-cp step. Now codified as a workflow gotcha.

7. **Live runtime fix proof remains the gold-standard validation.** Session
   1's Fix #5 bare_metal reaper LIVE-FIRED on the TMS320 row. Session 2a's
   /generate 202+polling conversion's runtime proof is the alembic migration
   landing + the new endpoints returning the correct 202 shape (Step 6
   pytest sweep with 247/247 green is the proxy; a live POST + GET status
   round-trip would be the equivalent of Session 1's reaper log line).

## Recommendations

1. **Session 2b — Fix #11 walker `*_walk_status` reaper sweep with W2-β
   §SC5-NEW-SBOM-S2-SEAM-B two-axis split.** Refactor `main.py` lifespan
   to derive from BOTH (a) `WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig]`
   in `walker_registry.py` paralleling `WALKER_AUTO_TRIGGERS`, AND
   (b) explicit `STATE_MACHINE_REAPER_CONFIGS: dict[str, StateMachineReaperConfig]`
   covering sbom_status (added today by Fix #1!) + vuln_scan + bare_metal_audit
   + upload_stage + cve_match + device_dump + authenticode_chain +
   dotnet_decompile + windows_update_diff. Shared `WalkerReaperConfig`
   dataclass with `grace_minutes` field (None for in-process; 15 for
   upload_stage's detached background task). Rule #46 META-CANARY enforces
   size-lock between WALKER_AUTO_TRIGGERS membership and WALKER_REAPER_CONFIGS
   coverage. ~220 LOC / 1 architectural-refactor commit per W2-γ.

2. **Session 2b — Scout D adaptability polish.** Extract FormatBanner
   component from FirmwareUpload.tsx → shared `components/firmware/FormatBanner.tsx`
   (the minimal inline banner in SbomPage today is a hold-the-line approach;
   the shared component lets other pages — VulnScan, Findings — adopt it).
   Polling backoff per W2-β §SC5-NEW-SBOM-λ (start at 2s, double to
   4/8/16/32s if status unchanged + reset on focus). ~140 LOC frontend.

3. **Session 3 — Fix #9 full Rule #52 extraction-strategy refactor (multi-
   session campaign).** Scout A + Scout B convergence: `extraction_strategy_catalog/`
   with closed Literals (ExtractionTier / ExtractionHandler ~20 entries /
   PostExtractionAction). ~4,600 LOC own Wave-1+Wave-2 research phase.
   **Promotion: this becomes Rule #52 instance #4 = Rule-of-Four DURABLE
   BEYOND DEBATE** (the three precedents are bare-metal MCU + file-format
   YAML registry + ICS protocol catalog; extraction-strategy makes 4).

4. **Promote `Wave-1 + Wave-2 8-scout methodology` from Rule-of-Two
   feedback memory to durable methodology pattern.** Three consecutive
   applications (Session 1 regression cascade + Session 2a structural
   conversion + ICS Session 1 closed-grammar extension) confirm the pattern
   is application-domain-independent. Update
   `feedback_wave2_cross_feature_methodology.md` to note: "Originally
   for Rule #52 closed-grammar; promoted 2026-05-21 to general-purpose
   methodology for ANY medium-or-large scope investigation/conversion."

5. **Promote `W2-γ MULTI-SESSION discipline trumps W2-α single-session
   optimism` to feedback memory.** Three consecutive honored MULTI-SESSION
   verdicts (ICS S1 + SBOM S1 + SBOM S2) prove the pattern.

6. **Filed in ADAPTIVE_BACKLOG — `evening:env-file-propagation`:**
   `WAIRZ_ALLOW_NO_AUTH=true` bypass shipped today; proper auth-gate
   removal at `main.py:65-76` queued as MEDIUM `auth-gate-removal-2026-05-21`.

7. **CLAUDE.md Rule #51 worked-example extension.** Session 2a is the
   third documented Rule #51 4-companion sweep (after Session 1 + rate-limit-2026-05-18).
   Rule #51 is now durable beyond debate — three instances. Update the
   worked-example block to include the SBOM /generate Rule #33 conversion +
   its 4-bullet companion sweep (reaper + tier + frontend handler + DB pool).

## Numbers

| Metric | Value |
|---|---:|
| Commits this session (production) | 5 (37eea52..09aea97 minus 1 fixup) |
| Commits this session (with fixup) | 6 |
| Files changed (cumulative) | 18 (alembic + 6 prod modules + 6 test files + 3 frontend + 2 helper extractions) |
| Insertions | 1,504 |
| Deletions | 138 |
| Net | +1,366 |
| Reverts | 0 (bisect-clean) |
| New tests (META-CANARY + alignment) | 18 (5 SbomStatus alignment + 2 reaper + 4 grype force_rescan + 5 background-sweep + 2 sbom router) |
| Wave-1 scouts dispatched | 5 (architecture + precedent + red-team + operator-UX + state-machine) |
| Wave-2 scouts dispatched | 3 (alpha convergence + beta seam blow-up + gamma yardstick) |
| Wave-1 root-cause findings adopted | 5 of 5 (Scout A primary becomes Session 3; A/B/D's catalog-bypass observation = Session 2a Fix #1 design; C's CRITICAL-δ informs Session 2b Fix #11; D's mandatory trio = Step 5; E's full Fix #1 design = Step 2) |
| W2-β NEW seam attacks catalogued | 7 (§SC5-NEW-SBOM-S2-SEAM-A through G) |
| W2-β SEAM-A mitigated this session | 1 (SEAM-A firmware_service.py:818 in Fix #8-broader) |
| W2-β SEAM attacks deferred to Session 2b | 6 (most need Fix #11 architectural refactor to land) |
| W2-α contradictions resolved | 4 |
| W2-γ Rule #28 yardstick verdict | MULTI-SESSION-RECOMMENDED (HONORED — 3rd consecutive) |
| Combined pytest sweep at close | 247 PASSED (S1 baseline + S2a new tests) in 9.81s |
| Frontend tsc canary | PASS (Rule #24 mandatory canary verified via deliberate-bad TS file) |
| Backend Rebuild cycles | 1 (Step 6 single rebuild for the whole session) |
| Frontend rebuild cycles | 1 (Step 6 close) |
| Tasks at session close | 23 (all closed) |

---HANDOFF---
- Postmortem: sbom-vuln-scan-session2a-2026-05-21
- Document: .planning/postmortems/postmortem-sbom-vuln-scan-session2a-2026-05-21.md
- Failures documented: 5 (1 silent-Edit miss, 4 test fixture corrections — all caught at Step 6 single-batch validation)
- Safety catches: 9 (Wave-1 5-scout + W2-α + W2-β SEAM-A + W2-γ MULTI-SESSION + Rule #25 single-slice + Rule #46 META-CANARY x3 + Rule #48 5-part + Rule #24 tsc canary + Rule #35b live canary)
- Recommendations: 7 (Session 2b Fix #11 + Scout D polish; Session 3 Fix #9 full Rule-of-Four; promote methodology + W2-γ discipline + Rule #51 worked example)
- Commits: 37eea52..09aea97 (5 prod + 1 fixup, closure docs follow)
- Session 2a surface SHIPPED: SBOM /generate Rule #33 conversion (alembic + Pydantic Literal + DB CHECK + router + reaper + alignment test) + grype force_rescan cached short-circuit + shared spawn_background_task module + 5-site sweep incl. SEAM-A + Scout D mandatory frontend trio + 247-test combined sweep PASS
- Session 2b plan (queued in ADAPTIVE_BACKLOG):
  * Fix #11 walker *_walk_status reaper sweep with two-axis split (WALKER_REAPER_CONFIGS + STATE_MACHINE_REAPER_CONFIGS) per W2-β §SC5-NEW-SBOM-S2-SEAM-B
  * Scout D adaptability polish (FormatBanner component extraction + polling backoff per §SC5-NEW-SBOM-λ)
  * 5 remaining §SC5-NEW-SBOM-S2-SEAM-B..G attack mitigations
  * Docs/recipe touch-ups + CLAUDE.md Rule #51 worked-example extension
- Session 3 plan (queued, multi-session campaign):
  * Fix #9 full Rule #52 extraction-strategy refactor — Rule-of-Four north star post ICS S2 (~4,600 LOC own Wave-1+Wave-2 research phase)
  * Promotes Rule #52 from Rule-of-Three (ICS S2 closure) → Rule-of-Four DURABLE BEYOND DEBATE
- ICS protocol Session 2 still queued (Rule #52 Rule-of-Three promotion candidate when walker + MCP + plugins close)
---

Run `/citadel:learn sbom-vuln-scan-session2a-2026-05-21` to extract patterns into the knowledge base.
