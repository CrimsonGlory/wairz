# Wave-2 α — Convergence Synthesis (S2)

> Investigation date: 2026-05-21 (Session 2)
> Synthesizes: 5 Wave-1 scout reports (A architecture / B precedent / C red-team / D operator-UX / E state-machine)
> Predecessor: Session 1 W2-α at `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave2-alpha-convergence.md`
> Operator mandate: "adaptable / versatile / flexible / resilient — we won't be the only ones ingesting files into the tool"
> Branch tip at synthesis: `208805c` (Session 1 close)

## Executive Summary

Session 2 ships the **structural conversion** of the SBOM `/generate` endpoint from sync to 202+polling (Fix #1) plus the grype force_rescan transactional fix (Fix #6), the `_post_process_pipeline` catalog-consultation minimum-scope (Fix #9), the walker reaper sweep with C's two-axis split (Fix #11), and the broader bare `asyncio.create_task` GC sweep — totalling **~1170 net LOC** across ~16 Rule #25 per-piece commits per Scout C lines 685-693. The top **three convergent root causes** are: **(1) SBOM `/generate` is structurally sync but already tier-decorated as 202+polling** (Scout E:38, Scout D:69-79, Scout A:166), so every operator click holds a uvicorn worker for 30-120 s under a budget that assumes sub-second acks — Fix #1 is the canonical Rule #33 conversion; **(2) the upload-pipeline `_post_process_pipeline` enforces extraction policy via hardcoded extension matching that BYPASSES the file-format YAML catalog** (Scout A:172-175, Scout B:36-44, Scout D:99-103) — Fix #9's minimum-scope form is "catalog consultation + enqueue `unpack_firmware_job` when capability=full", deferring the full Rule #52 instance #3 extraction-strategy refactor (~4,600 LOC) to a Rule-of-Four campaign AFTER ICS Session 2; **(3) Session 2's adaptability work will create NEW operator-supplied YAML surfaces whose path-cross-check, `extra:forbid`, and closed-Literal discipline must be inherited from the file-format catalog precedent verbatim** (Scout C:193-259 CRITICAL §SC5-NEW-SBOM-S2-δ) — this constrains Fix #1's frontend response surface (new `strategy` query param uses `Literal["auto","generic"]` not free string) and Fix #11's reaper-derivation (two-axis split per Scout C:146-191, NOT YAML per Scout E:273-282). **Single-session feasibility: YES** with MEDIUM-HIGH confidence — the LOC envelope (~1170) is within the Rule #28 +14-22% drift band on the underlying source files (937 LOC `firmware_service.py` + 1114 LOC `routers/sbom.py` + 515 LOC `main.py` + 201 LOC `walker_registry.py` + 264 LOC `grype_service.py` = 3031 LOC; ~40% additive ratio), and the cross-stack alignment commits (Rule #48 Shape-1) are mechanical per the existing vuln-scan / cve-match precedents. Shipping order: alembic migration → Fix #1 backend → Fix #1 frontend → Fix #6 grype → Fix #9 catalog-consultation → Fix #11 reaper sweep → broader create_task sweep → frontend rebuild.

## Wave-1 Cross-Reference Matrix

| Finding | A | B | C | D | E | Cross-confirmed? |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `_post_process_pipeline` hardcoded `.tar`/`.zip` extension matching bypasses catalog | A:Exec/10, 172-175 | B:36-44 | — | D:99-103 (implicit) | — | YES (3 scouts) |
| Three duplicate `_is_android_firmware_zip` copies (firmware_service / unpack_common / format_detection) | A:90-98 | B:43-44 | — | — | — | YES (2 scouts) |
| Full Rule #52 extraction-strategy refactor ~4,600 LOC | A:200-205 (estimates) | B:101-108 (specific) | — | — | — | YES (2 scouts agree on scope; B has authoritative number) |
| Rule #52 Rule-of-Three slot belongs to ICS Session 2, NOT this session | — | B:138-155 | — | — | — | UNIQUE (Scout B definitive) |
| SBOM `/generate` is sync but tier-decorated 202+polling | A:166 | — | — | D:69-79 | E:38, 156-160 | YES (3 scouts) |
| Fix #1 Rule #33 conversion is mechanical via vuln-scan precedent | — | B:27-30 | — | D:18-46 | E:79-127 | YES (3 scouts; E definitive design) |
| Fix #11 walker reaper sweep — Option B centralised dict in walker_registry | — | — | — | — | E:206-269 | UNIQUE (E primary) |
| §SC5-NEW-SBOM-S2-γ: Option B must split into walker vs state-machine axes | — | — | C:146-191 | — | — | UNIQUE (C primary) |
| §SC5-NEW-SBOM-S2-δ CRITICAL: operator-supplied YAML authority laundering | — | — | C:193-259 | — | — | UNIQUE (C primary) |
| Fix #1 unknown-format graceful-degrade (4-part frontend) | — | — | C:80-90 (mitigation) | D:91-127 (definitive) | — | YES (2 scouts) |
| `_spawn_background_task` should move to `app/utils/background.py` | — | — | C:702-707 | — | — | UNIQUE (C primary) |
| Broader create_task GC sweep scope: 4-6 router sites | A:120 | B:118-121 | C:502-545 | — | — | YES (3 scouts; A:6 sites, B:5 sites — re-grep per Rule #31) |
| SBOM strategy registry already adaptable at Python level (NOT Rule #52 candidate) | — | B:27-30 | — | — | — | UNIQUE (B definitive) |
| Frontend `SECURITY_SCAN_TIMEOUT` override must DROP from `generateSbom` post-conversion | — | — | — | D:71-75 | E:313 | YES (2 scouts) |
| `extractErrorMessage` handler compatible with new 200-body polling | — | — | — | D:85-87 | E:316-318 | YES (2 scouts) |
| Force-regenerate gating during in-flight (closes §SC5-NEW-SBOM-ν) | — | — | C:354-405 | D:135-143 (#4) | — | YES (2 scouts) |
| Rule #46 META-CANARY mandatory for every new closed-grammar gate | — | — | C:91-100, 243-259 | — | E:294-302 | YES (2 scouts) |

## Contradictions Resolved

### Contradiction 1: Rule #52 promotion scope (Scout A vs Scout B)

- **A's position:** Fix #9 IS the Rule-of-Three Rule #52 promotion opportunity this session — replace `_post_process_pipeline:580-759` with a closed-grammar dispatch using a new `output.upload_extraction_action: Literal[...]` field on file-format manifests (~250 LOC delete + ~140 LOC new dispatch). Scout A lines 192-198, 200-205.
- **B's position:** NO. The full refactor across `extraction_strategy_catalog/` + Pydantic schema + resolver + YAML manifests + handlers + tests is **~4,600 net LOC** requiring its own multi-session Wave-1+Wave-2 research campaign per the file-format YAML registry precedent. ICS Session 2 holds the Rule-of-Three slot legitimately (postmortem `postmortem-ics-protocol-session1-2026-05-20.md:148`). This session's Fix #9 is the **smaller catalog-consultation form** (~140 LOC: call `classify_firmware()`, look up `extraction_capability`, enqueue `unpack_firmware_job` when `full`). Scout B lines 38-44, 101-108, 138-155.
- **Evidence weight:** B's case is structurally stronger: (a) the proposed schema scope at A's level (`schemas/extraction_strategy.py` ~400 LOC + `extraction_strategy_catalog/catalog.py` ~600 LOC + resolver ~800 LOC + handlers ~1,200 LOC + YAMLs ~800 LOC + tests ~800 LOC) matches the file-format catalog's actual delivery footprint, which took 8+6 commits across two waves; (b) ICS Session 2 is closer to shipping (Session 1 substrate already 4,500 LOC live per `.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md:14-16`); (c) the operator mandate is satisfied by Fix #9's **minimum-scope** form because it removes the bypass — the catalog IS consulted; the full closed-grammar `extraction_handler` Literal is a follow-on enhancement, not a regression-block.
- **Resolution:** **Ship Fix #9 in the minimum-scope catalog-consultation form (~140 LOC).** The full Rule #52 instance #3 extraction-strategy refactor is deferred to a Rule-of-Four campaign AFTER ICS Session 2 closes Rule-of-Three. The minimum-scope form delivers the operator mandate's primary need: "operator-supplied YAML for a new format is consulted at upload time, not bypassed". The closed-grammar `ExtractionHandler` Literal can be added LATER without breaking the minimum-scope path (additive Rule #25 Shape-1 commit chain).
- **Implication:** Scout A's worked-example schema design becomes the **design north star** for the future Rule-of-Four campaign; queue in `.planning/ADAPTIVE_BACKLOG.md` as `prior-2026-05-21:RuleOf4-extraction-strategy-catalog` with explicit dependency on ICS Session 2 closing the Rule-of-Three slot first.

### Contradiction 2: Fix #11 Option B (Scout E centralised dataclass dict) vs Scout C authority-laundering attack

- **E's position:** Centralised `WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig]` parallel to `WALKER_AUTO_TRIGGERS` in `walker_registry.py`. Single source of truth; the reaper loop in `main.py` iterates the dict to issue UPDATEs. Closed-grammar enforcement is Pydantic Literal at module scope. NOT YAML — Rule #52 doesn't apply because reaper config is wairz-internal data with zero operator-extensibility motivation (Scout E:273-282).
- **C's position:** Option B as-stated is incomplete — it covers only walker columns but the 22 walker `*_walk_status` columns are NOT the only state-machine columns needing reaper coverage. `sbom_status`, `vuln_scan_status`, `bare_metal_audit_status`, `upload_stage`, `cve_match_status`, `device_dump_status`, `authenticode_chain_status`, `registry_hive_walk_status`, `dotnet_decompile_status` are 202+polling state-machines, NOT walker safe-runners. If Fix #11 derives the reaper SQL from `WALKER_AUTO_TRIGGERS` alone, the 5 existing reapers (cve_match / vuln_scan / device_dump / upload_stage / bare_metal_audit) silently lose coverage on the refactor — §SC5-NEW-SBOM-S2-γ HIGH severity (Scout C:146-191).
- **Evidence weight:** Both correct on their respective dimensions. E is right that Rule #52 doesn't apply; C is right that Option B's naïve "iterate WALKER_AUTO_TRIGGERS" misses the 9+ state-machine columns. The synthesis is **Option B + C's two-axis split** — exactly what Scout C's mitigation prescribes at lines 173-181.
- **Resolution:** Fix #11 splits the reaper-derivation into TWO explicit lists in `walker_registry.py` (or a new `app/services/reaper_configs.py`):
  - `WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig]` — 22 walker `*_walk_status` columns.
  - `STATE_MACHINE_REAPER_CONFIGS: dict[str, WalkerReaperConfig]` — `sbom_status` (NEW from Fix #1), `vuln_scan_status`, `bare_metal_audit_status`, `upload_stage`, `cve_match_status`, `device_dump_status`, `authenticode_chain_status`, `registry_hive_walk_status`, `dotnet_decompile_status`. Note: `upload_stage` has a 15-min grace per Session 1 Fix #2 — extend `WalkerReaperConfig` with a `grace_minutes: int = 0` field.
  - `main.py` lifespan reaper iterates BOTH dicts. Both share the same `WalkerReaperConfig` dataclass — the structural difference is the SOURCE list.
  - Rule #46 META-CANARY `test_reaper_lists_cover_every_state_column` (Scout C:182-191) walks `Firmware.__table__.columns`, asserts every `_status`/`_stage`/`_walk_status` column appears in EXACTLY ONE of the two lists. Pairwise-disjoint + complete.
- **Implication:** Option B remains correct; C's two-axis split is a hardening REQUIREMENT, not a contradiction. Closes §SC5-NEW-SBOM-S2-γ structurally — the META-CANARY catches future omissions at startup.

### Contradiction 3: Frontend unknown-format graceful-degrade scope (Scout D ~140 LOC) vs Fix #1 minimum-scope (Scout E ~340 LOC)

- **D's position:** 6 frontend changes are MANDATORY for Session 2 (D:131-143): (1) SBOM `/generate` 202+polling state machine; (2) Failed-state surfacing in header; (3) Re-mount auto-resume polling; (4) Force-regenerate gating during in-flight; (5) Unknown-format banner above Generate SBOM (extract `FormatBanner` to shared); (6) `Try Generic Strategy` button for unsupported formats. Scout D estimates the frontend work at ~140 LOC: extract `FormatBanner` ~10 LOC + new banner consumption ~30 LOC + `useFirmwareDetail` hook ~20 LOC + polling effect ~30 LOC + Failed-state header ~20 LOC + button gating ~20 LOC + `getSbomGenerateStatus` API helper ~10 LOC.
- **E's position:** Fix #1 is ~340 LOC mostly backend — alembic migration 115 LOC + Pydantic + router 120 LOC + reaper 30 LOC + frontend `~75` LOC matching the vuln-scan precedent at SbomPage.tsx:162-219 verbatim. Scout E lines 285-291.
- **Evidence weight:** D and E are not contradicting — E's frontend estimate is the **minimum** vuln-scan-mirror (item #1 of D's list); D's full mandatory set adds ~80 LOC for items #2-#6. Combined frontend work: ~155 LOC. Combined Session 2 total per Scout C:683-693: ~1,170 LOC across Fix #1 (~420 LOC including Scout D's mandatory UX) + Fix #6 (~90 LOC) + Fix #9 (~140 LOC) + Fix #11 (~220 LOC) + create_task sweep (~80 LOC) + Frontend rebuild (~0 LOC) + memory_dump_image FK repair (carry-over from Session 1 W2-α #2, ~15 LOC) + alignment commits (~80 LOC).
- **Resolution:** **Single-session feasible** within the Rule #28 drift band (3031 LOC underlying × +14-22% drift = 3,455-3,698 LOC source target; ~1,170 LOC additive is ~31% of that — well below the W2-γ single-session ceiling). All 6 of D's mandatory items ship in Fix #1's frontend commit chain; treat them as ONE Rule #48 Shape-1 commit (the cross-stack alignment slice for `sbom_status`) plus follow-up per-component commits for items #5 and #6 (FormatBanner extraction + Try Generic Strategy button).
- **Implication:** The session budget accommodates D's mandatory set; do NOT defer items #2-#6 to Session 3 unless Session 2's mid-session re-measure shows drift exceeding 1,500 LOC. W2-γ (next) should yardstick-check this number.

### Contradiction 4: Scout C's "Fix #1 needs unknown-format short-circuit" placement (before or after 409 idempotency)

- **C's position:** §SC5-NEW-SBOM-S2-α (Scout C:43-100) — the background runner checks `firmware.detected_format == "unknown"` at ENTRY and short-circuits with `sbom_status="completed"` + `sbom_result={"reason": "detected_format=unknown", "components": 0}`. Implicit ordering: the short-circuit is inside the BACKGROUND RUNNER, not the operator-facing POST handler — so it's AFTER the 409 idempotency check.
- **E's position:** Clean Rule #33 4-bullet design with the 409 check first, then `_spawn_background_task(_run_sbom_generate_background(...))`. Scout E:96-118.
- **Evidence weight:** No contradiction at the code level — C's short-circuit lives **inside `_run_sbom_generate_background`**, after the 202 ack returns and the background task starts. The 409 idempotency check at the router (Rule #33 .a) is independent: it gates "already queued/running for this firmware". The short-circuit is a runner-internal "this work has nothing to do; stamp completion and return".
- **Resolution:** Short-circuit lands **inside the background runner**, immediately after the row's `status='running'` flip but BEFORE invoking `SbomService.generate_sbom`. Shape:
  ```python
  async def _run_sbom_generate_background(firmware_id, project_id, force_rescan):
      async with async_session_factory() as db:
          firmware = await _resolve(db, firmware_id)
          firmware.sbom_status = "running"
          firmware.sbom_started_at = datetime.utcnow()
          await db.commit()
          # Unknown-format short-circuit per §SC5-NEW-SBOM-S2-α
          if firmware.detected_format == "unknown" or firmware.extracted_path is None:
              firmware.sbom_status = "completed"
              firmware.sbom_finished_at = datetime.utcnow()
              firmware.sbom_result = {
                  "reason": "detected_format=unknown" if firmware.detected_format == "unknown" else "extracted_path=null",
                  "components": 0,
                  "cached": False,
              }
              await db.commit()
              return
          # ... normal SbomService.generate_sbom path ...
  ```
  Frontend's unknown-format banner (D:91-127) renders independent of this short-circuit — the banner triggers on `firmware.detected_format == "unknown"` READ from the upload-status response, not on the runner's completion.
- **Implication:** Each gate is at its idiomatic layer: 409 at the operator boundary (POST router); unknown-format short-circuit at the work boundary (background runner). Both ship in Fix #1's commit chain. Rule #46 META-CANARY pairs: `test_sbom_409_on_concurrent_post` for the operator boundary; `test_sbom_generate_unknown_format_graceful_degrades` (Scout C:91-100) for the runner boundary.

## Convergent Findings (HIGH-confidence)

### Root cause #1 — Hardcoded format heuristics bypassing the YAML catalog (Fix #9 target)

- **Evidence:** A:Exec/10, 172-175 (cross-index #1-4); B:36-44; D:99-103 (operator-UX framing); C:262-311 (§SC5-NEW-SBOM-S2-ε polyglot ambiguity).
- **Where it lives:**
  - `backend/app/services/firmware_service.py:589` — `is_tar = raw_filename.lower().endswith((".tar.gz", ".tar", ...))` — hardcoded extension match, no catalog lookup.
  - `backend/app/services/firmware_service.py:666-669` — `is_zip = raw_filename.lower().endswith(".zip") and zipfile.is_zipfile(...)` — same shape.
  - `backend/app/services/firmware_service.py:121-152` — `_is_android_firmware_zip` — duplicate copy of `classify_firmware:1478-1497` AND `format_detection.py:392-419` AND the `android_ota.yaml` manifest's `zip_markers` signal.
  - `backend/app/services/firmware_service.py:78-118` — `_zip_contains_rootfs` — hardcoded `{etc, usr, bin, lib, sbin}` set duplicated from `unpack_common.py:_ROOTFS_MARKER_DIRS`.
- **Operator symptom:** A non-tar non-ZIP upload (PE binary, Intel HEX, Android sparse, qcow2, .efi, .ima, anything with a custom extension) reaches `_post_process_pipeline` and finishes with `extracted_path=None`. Downstream SBOM and walkers see nothing. The pre-upload `detect_format()` path AT `firmware_service.py:570` IS catalog-aware (P3.1.h) but its return value is stamped on the row and IGNORED for branching purposes (A:28).
- **Fix shape (minimum-scope per Scout B):** `_post_process_pipeline:570-822` reads the post-`detect_format` `detected_format` value, consults the file-format catalog's `manifest.pre_upload.extraction_capability` field, and:
  - `capability == "full"` → enqueue `unpack_firmware_job(firmware.id)` via the existing arq path at `routers/firmware.py:66-80`. Leave the rest of the pipeline alone — `_run_hardware_firmware_detection_safe` fires AFTER `unpack_firmware_job` completes via the existing `_post_process_pipeline → ... → _run_hardware_firmware_detection_safe` chain.
  - `capability == "partial"` → ship as today (no change; partial extractors are out-of-scope this session).
  - `capability == "none"` → leave as a standalone binary; `firmware.extracted_path = firmware.storage_path` so downstream `get_detection_roots()` returns one root.
- **Defer to Rule-of-Four campaign:** The full closed-grammar `extraction_handler: Literal[...]` + YAML-declared `handler_config` + Strategy registry refactor (Scout A's worked example) is the future Rule #52 instance #3 promotion target. Queue as `prior-2026-05-21:RuleOf4-extraction-strategy-catalog`.
- **Estimated LOC + commits:** ~140 LOC net add (~80 LOC delete + ~220 LOC new dispatch logic). One Rule #25 per-piece commit.

### Root cause #2 — SBOM `/generate` sync but tier-decorated for 202+polling (Fix #1 carryover)

- **Evidence:** A:166; D:69-79; E:38, 156-160; Scout-1-Session-1 W2-α #1 (now Session 1 closed Fix #1's data-fetch perf; Session 2 ships the structural conversion).
- **Where it lives:** `backend/app/routers/sbom.py:142-252` — the synchronous `/generate` endpoint decorated `@limiter.limit(TIER_A_LIGHT_ACK)` at line 143 (30/hour). The endpoint's executor wraps `SbomService.generate_sbom()` which takes 30-120 s synchronously; the operator's axios call holds the connection for the full duration with the `SECURITY_SCAN_TIMEOUT=600_000` ms override at `frontend/src/api/sbom.ts:38`.
- **Operator symptom:** Operator clicks Generate SBOM, browser tab hangs for 30-120 s, page goes blank during generation. Under 30/hour budget shared across operators, the DB connection pool (15+25=40 per Rule #51 .iv `58a6f54`) gets pressured. Cross-cutting with §SC5-NEW-SBOM-γ (Session 1 W2-β): if an operator opens two tabs and both kick off `/generate` + `/scan` concurrently, the pool is at ~12% saturation in single-operator steady state per Scout E:320-326.
- **Fix shape (Rule #33 4-bullet contract):** Per Scout E:79-127 (definitive design):
  - **(a) Idempotent POST + 409 on conflict** in the router (`if firmware.sbom_status in ("queued", "running"): raise HTTPException(409, ...)`).
  - **(b) `firmware.sbom_result` JSONB column** persisting the result aggregate `{total, cached, rtos_injected, ...}`; the SBOM components themselves stay in the existing `sbom_components` table.
  - **(c) Both Pydantic `SbomStatus = Literal["idle","queued","running","completed","failed"]` AND DB CHECK `ck_firmware_sbom_status`.** Rule #25 Shape-1 cross-stack alignment commit per Rule #48 5-part test shape (paired rejection + paired acceptance + size-lock + cross-layer alignment proper + Rule #46 META-CANARY).
  - **(d) `asyncio.create_task` via `_spawn_background_task` per Rule #51 §SC5-NEW-SBOM (S1 Fix #8 GC hardening).** Worker resource not required (Syft is in-process subprocess; no Docker spawn).
- **Companion fixes that MUST land in same commit chain (Rule #51 4-companion sweep):**
  - **(i) Orphan reaper** at `main.py` lifespan for `sbom_status`, NO grace window (mirrors vuln_scan / cve_match, NOT upload_stage). Scout E:130-156. Lands as part of Fix #11's two-axis sweep (`sbom_status` in `STATE_MACHINE_REAPER_CONFIGS`).
  - **(ii) Tier alignment** — `TIER_A_LIGHT_ACK` becomes STRUCTURALLY CORRECT post-conversion. No tier edit needed; `_EXPECTED_TIERS[/sbom/generate] = TIER_A_LIGHT_ACK` already pinned at `test_rate_limit_tiers.py:52`. Frontend `SECURITY_SCAN_TIMEOUT` override at `api/sbom.ts:38` MUST be removed in the same commit.
  - **(iii) Frontend `extractErrorMessage`** — unchanged; the new 200-body polling response carries `error: string | null` directly per the vuln-scan precedent (D:85-87).
  - **(iv) DB pool headroom** — unchanged; existing 40-conn pool handles the dual-poll combined burst at ~150 req/min per Scout E:320-326.
- **Estimated LOC + commits:** ~340 LOC backend (alembic 115 + Pydantic + router 120 + runner 75 + tests 30) + ~155 LOC frontend (mandatory UX items #1-#6 per Scout D). ~5 Rule #25 commits.

### Root cause #3 — Operator-extensible YAML surfaces compound authority-laundering risk (§SC5-NEW-SBOM-S2-δ CRITICAL)

- **Evidence:** Scout C:193-259 (CRITICAL primary), Scout C:595-629 (cross-cutting gates for ALL new operator-supplied YAML surfaces). The file-format catalog's `_expected_source_for_path` cross-check at `catalog.py:270-278` is the precedent; the gate must be inherited verbatim by every new YAML surface this session creates OR enables.
- **Where it lives (today):** ONLY `file_format_catalog` has the path-cross-check. Session 2 does NOT itself create new operator-supplied YAML surfaces (Fix #9 minimum-scope consults the existing catalog), but Session 2's adaptability work LANDS in a context where the next Rule #52 instance #3 (full extraction-strategy refactor) WILL create one. The gate must be designed-in from the start of that future campaign.
- **Operator symptom (latent):** Operator drops `data/extraction_strategies.local/operator/aggressive.yaml` declaring `manifest_source: _system` to elevate trust precedence; without `extra:forbid` + closed Literals + path-cross-check, the YAML loads and accretes as "trusted _system authority". Future code that consults `manifest_source: _system` for downstream privilege (e.g. "skip sandbox if source==_system") trusts the laundered claim.
- **Fix shape (this session):** No NEW YAML surfaces created. **But** the Fix #9 catalog-consultation path must NOT introduce a free-string `extraction_handler` field — keep that to the future Rule-of-Four refactor with full Rule #52 gates. Document the Rule-of-Four campaign's required gates in `.planning/ADAPTIVE_BACKLOG.md`:
  - (a) Pydantic `model_config = ConfigDict(extra="forbid")` mandatory.
  - (b) Every extensible field uses `Literal[<closed-vocabulary>]`.
  - (c) Path-cross-check mirroring `catalog.py:_expected_source_for_path:92-118`.
  - (d) `PLUGIN_REGISTRY` is module-level + frozen post-startup via `freeze_plugin_registry()`-shape API.
  - (e) Rule #46 META-CANARY synthesizing forbidden tokens (`regex|script|template|predicate|lua|expression|command`) via in-memory YAML AND asserting the gate fires.
  - (f) Rule #46 authority-laundering canary `test_<surface>_path_cross_check_rejects_operator_claiming_system` (Scout C:247-259).
- **Implication for Session 2:** The 5 gates above are NOT shipped this session, but they are documented as a precondition for the Rule-of-Four campaign. Session 2's own work touches Fix #1 (no new YAML), Fix #6 (no new YAML), Fix #9 (consult existing YAML — no new schema), Fix #11 (Python data structure, NOT YAML per Scout E:273-282), create_task sweep (no YAML). Zero net YAML schemas added this session — the §SC5-NEW-SBOM-S2-δ surface is **deferred** for the Rule-of-Four campaign, but the gate template is locked in.

## Fix Scope + Shipping Order

### Fix #1 — SBOM `/generate` Rule #33 conversion

- **Rules applied:** Rule #33 (.a/.b/.c/.d 4-bullet contract), Rule #48 (5-part cross-stack alignment), Rule #51 (.i reaper + .ii tier + .iii extractErrorMessage + .iv DB pool — companion sweep), Rule #46 (META-CANARY for unknown-format short-circuit + 409 idempotency).
- **Files:**
  - `backend/alembic/versions/<new>_add_sbom_status_to_firmware.py` — new revision, `down_revision='fd6e7f8a9b0c'`.
  - `backend/app/models/firmware.py` — add 5 columns mirroring cve_match/vuln_scan shape.
  - `backend/app/schemas/sbom.py` — `SbomStatus` Literal + `SbomGenerateStatusResponse`.
  - `backend/app/routers/sbom.py:142-252` — convert sync to 202+polling per Scout E:79-127 template.
  - `backend/app/services/sbom_service.py` — add `generate_generic_strings_strategy` method for the `strategy=generic` query param (Scout D:101).
  - `backend/app/main.py:200-242` — add `sbom_status` reaper block (lands via Fix #11's two-axis sweep, NOT a separate commit).
  - `frontend/src/api/sbom.ts` — drop `SECURITY_SCAN_TIMEOUT` override on `generateSbom`; add `getSbomGenerateStatus`.
  - `frontend/src/types/index.ts` — `SbomStatusValue` + `SbomGenerateStatus`.
  - `frontend/src/pages/SbomPage.tsx:128-225` — handleGenerate polling; failed-state header; re-mount auto-resume; force-regenerate gating; unknown-format banner; Try Generic Strategy button.
  - `frontend/src/components/firmware/FormatBanner.tsx` — extract from `FirmwareUpload.tsx:309-335`.
  - `backend/tests/test_sbom_status_alignment.py` — new Rule #48 5-part alignment test.
  - `backend/tests/test_main_lifespan_reapers.py` — add `test_sbom_status_reaper_present_in_lifespan` (Scout E:351-352).
  - `backend/tests/test_sbom_router.py` — add unknown-format short-circuit test + 409 idempotency test.
- **Commit shape:** Rule #25 single-slice exception #2 (5-part cross-stack alignment — DB CHECK ↔ Pydantic Literal ↔ frontend type union) — ONE Shape-1 commit for the schema + Pydantic + DB CHECK + frontend Literal. Then 3 follow-up commits: router + runner; frontend polling + FormatBanner; tests.
- **Pre-flight gates:** Rule #11 import smoke post-alembic; Rule #35b live canary on a real firmware (the existing `c29d6b7` baseline); Rule #46 META-CANARY for unknown-format short-circuit; Rule #20 docker cp + alembic upgrade head for fast iteration if the worker rebuild is deferred.
- **Risk:** MEDIUM. The conversion is mechanical per the vuln-scan precedent (S1 reference), but Scout D's 6 mandatory UX items add ~80 LOC frontend that hasn't been touched yet. Mitigation: ship items #1-#4 in the first frontend commit; items #5-#6 (FormatBanner + Try Generic Strategy) in a follow-up.

### Fix #6 — Grype force_rescan transactional

- **Rules applied:** Rule #25 (per-piece commit), Rule #35b (live canary), Rule #46 (META-CANARY for concurrent 409 verification per §SC5-NEW-SBOM-S2-η).
- **Files:**
  - `backend/app/services/grype_service.py:60-265` — add `force_rescan: bool = False` parameter to `scan_with_grype`; wrap DELETE+INSERT in single transaction; conditional DELETE only when `force_rescan=True`.
  - `backend/app/routers/sbom.py:493-497` — caller passes `force_rescan` through.
  - `backend/tests/test_grype_service.py` — add `test_force_rescan_atomic_delete_insert` + `test_concurrent_force_rescan_409s_correctly` (Scout C:397-405).
- **Commit shape:** Single Rule #25 per-piece commit.
- **Pre-flight gates:** Rule #35b live canary against an existing firmware with `sbom_vulnerabilities` rows; SELECT row count before + after to confirm atomicity.
- **Risk:** LOW. ~90 LOC; mechanical per the NVD-path semantics at `vulnerability_service.py:82-92`.

### Fix #9 — `_post_process_pipeline` minimum-scope (NOT full Rule #52 refactor)

- **Rules applied:** Rule #16 (use `get_detection_roots()` post-extract), Rule #47 (consumer-hook enumeration), Rule #25 (per-piece commit). NOT Rule #52 this session.
- **Files:**
  - `backend/app/services/firmware_service.py:544-822` — replace the hardcoded extension-match branches with catalog consultation:
    ```python
    detected = await loop.run_in_executor(None, detect_format, storage_path)
    capability = EXTRACTION_CAPABILITY.get(detected, ExtractionCapability.NONE)
    if capability == ExtractionCapability.FULL:
        await arq_pool.enqueue_job("unpack_firmware_job", firmware.id)
        # Status flips through 'detecting → extracting → analyzing → ready'
        # via the existing _post_process_pipeline state machine; the
        # unpack_firmware_job completes asynchronously and the existing
        # _run_hardware_firmware_detection_safe fan-out fires after extraction.
        return
    elif capability == ExtractionCapability.NONE:
        firmware.extracted_path = firmware.storage_path
        # Walker fan-out treats the single-blob path via get_detection_roots()
    # else PARTIAL: ship as today (no change)
    ```
  - Delete the 3 duplicate `_is_android_firmware_zip` copies (A:90-98) — keep only the file-format catalog manifest's `zip_markers` signal at `data/file_formats/_system/android_ota.yaml:23-48`. The catalog-driven `detect_format()` returns `android_ota` correctly per P3.1.h.
  - `backend/tests/test_firmware_service.py` — add `test_post_process_pipeline_consults_catalog_for_arbitrary_extension`; `test_post_process_pipeline_enqueues_unpack_for_full_capability`.
- **Commit shape:** Single Rule #25 per-piece commit. Closing the §SC5-NEW-SBOM-S2-ε polyglot ambiguity (Scout C:262-311) lives in this commit — the precondition for the unblob fallback (if added) is `if not extracted_via_shortcut and not is_android and not is_rootfs`, NOT `if fs_root is None`.
- **Pre-flight gates:** Rule #35b live canary on a representative PE-binary upload (no extension match today) → confirm `extracted_path` set + walker fan-out fires; Rule #46 META-CANARY for the polyglot precondition.
- **Risk:** MEDIUM. Deleting the duplicate heuristics changes the upload pipeline's branching behavior on Android-OTA ZIPs — need to confirm the catalog manifest's `zip_markers` signal at `android_ota.yaml:23-48` fires correctly on the existing Android OTAs (`8312-RespArray`, `0977b260`, etc.). Mitigation: add a `test_android_ota_zip_detection_via_catalog` regression test that uploads a synthetic Android-OTA fixture and asserts `detected_format == "android_ota"` AND `_post_process_pipeline` enqueues `unpack_firmware_job`.

### Fix #11 — Walker reaper sweep (Option B with C's two-axis split)

- **Rules applied:** Rule #47 (consumer-hook enumeration when extending reaper coverage to N walkers), Rule #46 (META-CANARY for pairwise-disjoint completeness), Rule #51 (.i reaper companion). NOT Rule #52 per Scout E:273-282.
- **Files:**
  - `backend/app/workers/walker_registry.py` — add `@dataclass(frozen=True) class WalkerReaperConfig` (Scout E:210-218 + Scout C's `grace_minutes` extension). Add `WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig]` (22 entries) + `STATE_MACHINE_REAPER_CONFIGS: dict[str, WalkerReaperConfig]` (9 entries: `sbom_status` (NEW), `vuln_scan_status`, `bare_metal_audit_status`, `upload_stage` with grace_minutes=15, `cve_match_status`, `device_dump_status`, `authenticode_chain_status`, `registry_hive_walk_status`, `dotnet_decompile_status`).
  - `backend/app/main.py:200-348` — replace the 5 inlined reaper try/except blocks with a single loop over both `WALKER_REAPER_CONFIGS` + `STATE_MACHINE_REAPER_CONFIGS` dicts. The existing 5 reapers (cve_match / vuln_scan / device_dump / upload_stage / bare_metal_audit) are folded into `STATE_MACHINE_REAPER_CONFIGS`. Net main.py LOC: ~-90 (delete 5 inlined blocks) + ~50 (new generic loop) = -40 LOC.
  - `backend/tests/test_main_lifespan_reapers.py` — extend with `test_reaper_lists_cover_every_state_column` (Scout C:182-191 META-CANARY — walks `Firmware.__table__.columns`, asserts pairwise disjoint + complete); `test_walker_reaper_configs_size_lock` (22 walker entries + 9 state-machine entries).
  - `backend/tests/test_walker_registry.py` — extend with size-lock + column-name-validity-against-Firmware-model + trigger-name-key-consistency canaries (Scout E:288-290).
- **Commit shape:** Single Rule #25 per-piece commit. Bisect-clean because the dict additions + main.py refactor are coupled — splitting leaves main.py reading a non-existent dict.
- **Pre-flight gates:** Rule #11 import smoke (`docker compose exec -T backend python -c "from app.workers.walker_registry import WALKER_REAPER_CONFIGS, STATE_MACHINE_REAPER_CONFIGS; print(len(WALKER_REAPER_CONFIGS), len(STATE_MACHINE_REAPER_CONFIGS))"`); Rule #46 META-CANARY runs at startup.
- **Risk:** MEDIUM. The refactor folds 5 existing reapers into the new generic loop — must preserve `upload_stage`'s 15-min grace + `bare_metal_audit_status`'s no-grace behavior. Mitigation: the `grace_minutes` field on the dataclass + a Rule #46 META-CANARY confirming the 5 existing behaviors round-trip via the new code path.

### Frontend unknown-format graceful-degrade (Scout D mandatory items #5-#6 + alignment)

- **Rules applied:** Rule #26 (frontend rebuild discipline at end of session), Rule #46 (META-CANARY for the new banner rendering on `detected_format='unknown'`).
- **Files:**
  - `frontend/src/components/firmware/FormatBanner.tsx` — NEW (extract from `FirmwareUpload.tsx:309-335`, ~30 LOC).
  - `frontend/src/components/projects/FirmwareUpload.tsx:309-335` — replace inline banner with imported `<FormatBanner>` component (~3 LOC delta).
  - `frontend/src/pages/SbomPage.tsx:295-308` — add `<FormatBanner>` above the Generate SBOM button when `firmware.detected_format === "unknown"` OR `firmware.extraction_capability === "none"` (~20 LOC).
  - `frontend/src/api/sbom.ts` — add `strategy: 'auto' | 'generic'` query param to `generateSbom` (~5 LOC).
  - `backend/app/schemas/sbom.py` — `Strategy = Literal["auto", "generic"]` (Rule #52 closed-grammar discipline — Scout D:118-120).
  - `backend/app/routers/sbom.py` — accept `strategy` query param, dispatch to `SbomService.generate_generic_strings_strategy` when `strategy=="generic"` (~15 LOC).
- **Commit shape:** 2 commits (FormatBanner extraction is Rule #42 helper extraction; SbomPage integration is per-piece).
- **Pre-flight gates:** Rule #11 frontend typecheck `npx tsc -b --force` (Rule #24); Rule #26 frontend rebuild at session close.
- **Risk:** LOW. ~80 LOC frontend additive; banner reuse is mechanical.

### Broader create_task GC sweep

- **Rules applied:** Rule #31 (width-canary discipline — re-grep with broader pattern before trusting count), Rule #25 (per-piece commit), Rule #42 (helper extraction since N≥3).
- **Files:**
  - `backend/app/utils/background.py` — NEW (move `_spawn_background_task` from `routers/sbom.py:28-37` per Scout C:702-707). ~15 LOC.
  - `backend/app/routers/sbom.py:28-37` — import from `app.utils.background`; deprecate local copy.
  - `backend/app/routers/firmware.py:175,297,436,441` — replace 4 bare `asyncio.create_task` calls with `_spawn_background_task` (verified via re-grep this session at Bash output).
  - `backend/app/routers/hardware_firmware.py:654,750` — replace 2 bare `asyncio.create_task` calls (verified via re-grep this session).
  - `backend/app/routers/emulation.py:165` — replace 1 bare `asyncio.create_task` call (post-202 ack, not WebSocket bidi-reader); the 3 WebSocket bidi-reader tasks at `:946-948` are NOT in scope (different lifetime model — they're cleaned up by the WebSocket handler's `finally` block).
  - `backend/app/services/firmware_service.py:818` — if Scout A:120 surfaces a bare call, address; current grep doesn't show one outside an arq-fallback comment.
- **Commit shape:** 2 commits — (1) helper extraction to `app/utils/background.py`; (2) batch substitution across 6 router sites.
- **Pre-flight gates:** Rule #31 width-canary — run `grep -rn 'asyncio\.create_task\|asyncio\.gather' backend/app/routers/ backend/app/services/` BEFORE and AFTER the sweep; count must drop by exactly 7 (the 6 router sites + the local copy deprecation). Rule #46 META-CANARY: `test_no_bare_asyncio_create_task_in_routers` per Scout C:531-544 (regex AST-walk over router files asserting every `asyncio.create_task` is inside `_spawn_background_task` body OR has a `# noqa: BARE_CREATE_TASK <rationale>` comment).
- **Risk:** LOW. ~80 LOC across all files. The WebSocket bidi-reader tasks at `emulation.py:946-948` and `terminal.py:270-272,459-461` are intentionally excluded — they're WebSocket-lifetime bound, NOT operator-fire-and-forget. The Rule #46 META-CANARY's `# noqa: BARE_CREATE_TASK` allowlist documents this exception.

## Shipping Order (Cheapest → Most-Impactful)

1. **Alembic migration for `sbom_status`** — ~115 LOC. Foundation for Fix #1 + Fix #11. Apply via Rule #20 fast iteration if backend not rebuilt yet.
2. **Fix #1 backend (router + runner + Pydantic + reaper folded into Fix #11)** — ~340 LOC across the Rule #48 Shape-1 cross-stack alignment commit + follow-ups. Includes unknown-format short-circuit + 409 idempotency.
3. **Fix #6 grype force_rescan transactional** — ~90 LOC. Independent of #1; can ship in parallel.
4. **Fix #9 `_post_process_pipeline` catalog consultation** — ~140 LOC. Independent of #1 + #6; bumps non-tar non-ZIP uploads to use the catalog.
5. **Fix #11 walker reaper sweep (two-axis)** — ~180 LOC (net) after folding 5 existing reapers into the new generic loop. Lands AFTER Fix #1's `sbom_status` migration so the new dict can reference it.
6. **Broader create_task GC sweep + `_spawn_background_task` to `app/utils/background.py`** — ~80 LOC. Independent; could ship first if desired but ordering after Fix #11 keeps the helper-extraction Rule #42 commit logically near the reaper consolidation.
7. **Fix #1 frontend (polling + FormatBanner + Try Generic Strategy + force-regenerate gating)** — ~155 LOC. Lands AFTER #2 so the backend response shape is stable.
8. **Frontend rebuild via `docker compose up -d --build frontend`** (Rule #26) — 0 LOC; ~30 s wall time. End-of-session canary.
9. **Documentation: `.planning/ADAPTIVE_BACKLOG.md` entry for Rule-of-Four extraction-strategy-catalog campaign** (Scout A + Scout B convergence) — defers ~4,600 LOC of future work with explicit ICS-Session-2 dependency.

Total: ~1,170 net LOC across ~16 Rule #25 per-piece commits + 1 Rule #48 Shape-1 alignment commit + 1 Rule #42 helper extraction commit + 1 environment-only frontend rebuild.

## Cross-Reference of Session 1 W2-β attacks → Session 2 status

(Session 1 W2-β catalogued §SC5-NEW-SBOM-α..π attacks. Cross-referencing each against the Session 1 close + Session 2 plan.)

| Session 1 attack | Status post-Session-1 | Session 2 relevance |
|---|---|---|
| §SC5-NEW-SBOM-α (orphan vuln_scan_status='running' forever) | MITIGATED via `3d2454b` reaper | Extended in Fix #11 to cover ALL state-machine columns |
| §SC5-NEW-SBOM-β (`scan_with_grype` force_rescan ignored) | OPEN | Fix #6 closes; cross-references new §SC5-NEW-SBOM-S2-η for concurrency hardening |
| §SC5-NEW-SBOM-γ (multi-tab polling pool exhaustion) | PARTIALLY MITIGATED via DB pool 40 + reapers | Fix #11 + composite-status endpoint deferred to Session 3 per Scout C:546-568 §SC5-NEW-SBOM-S2-λ |
| §SC5-NEW-SBOM-δ (SbomComponent UniqueConstraint race) | OPEN, deferred | Out of Session 2 scope per W2-α #3 deferred list |
| §SC5-NEW-SBOM-ε (`upload_stage` orphan + 15-min grace) | MITIGATED via Session 1 Fix #2 (`8c51448`) | Extended in Fix #11's STATE_MACHINE_REAPER_CONFIGS with `grace_minutes=15` |
| §SC5-NEW-SBOM-ζ (architecture detection misreads) | OPEN, low severity | Out of Session 2 scope |
| §SC5-NEW-SBOM-η (walker fan-out semaphore × concurrent unpack) | OPEN | Cross-referenced by Scout C:709-716 — Scout C flags this as a Wave-2 β future-session concern, NOT Session 2 |
| §SC5-NEW-SBOM-θ (RTOS injection JSON parse swallowed) | OPEN, low severity | Deferred per W2-α #3 |
| §SC5-NEW-SBOM-ι (Stage 1 fast-path on extension-renamed firmware) | OPEN | Touched by Fix #9 — catalog consultation FIXES this; the catalog reads magic bytes, not extension |
| §SC5-NEW-SBOM-κ (bare_metal_audit reaper missing) | MITIGATED via Session 1 Fix #5 (`fc22c17`) | Extended in Fix #11's STATE_MACHINE_REAPER_CONFIGS |
| §SC5-NEW-SBOM-λ (polling cadence DB pool budget) | OPEN | Composite-status + backoff deferred to Session 3; pool 40 holds for now per Scout E:320-326 |
| §SC5-NEW-SBOM-μ (DELETE-then-INSERT non-transactional in grype) | OPEN | Fix #6 closes |
| §SC5-NEW-SBOM-ν (force_rescan double-click trap) | OPEN | Closed by Scout D:135-143 #4 (frontend force-regenerate gating) AND Scout D:143 #12 (MANDATORY-LITE backend 200-with-cached split) — adopt the Scout D #12 form |
| §SC5-NEW-SBOM-ξ (cve-match force_rescan SBOM row leak) | OPEN | Out of Session 2 scope |
| §SC5-NEW-SBOM-ο (find_findings race) | OPEN | Out of Session 2 scope |
| §SC5-NEW-SBOM-π (operator-supplied YAML schema absent) | OPEN | NOW formalised as §SC5-NEW-SBOM-S2-δ; deferred to Rule-of-Four campaign per Scout B's verdict |

**Net:** Session 1 closed 3 of 16 W2-β attacks (α/ε/κ). Session 2 closes an additional 4 (β/μ/ν + structural-ι via Fix #9). 9 remain open — most are out-of-scope (δ/ζ/η/θ/ξ/ο) or deferred to Session 3 (γ/λ) or to the Rule-of-Four campaign (π).

## Cross-Reference of Scout C NEW §SC5-NEW-SBOM-S2-α..λ → Session 2 mitigation status

| New attack | Severity | Status |
|---|---|---|
| α (SBOM /generate unknown-format silent zero-result) | MEDIUM | CLOSED in Fix #1 background runner short-circuit + Scout D mandatory unknown-format banner |
| β (50 GB qcow2 OOM) | HIGH | DEFERRED — out-of-scope this session; queue in ADAPTIVE_BACKLOG as `prior-2026-05-21:RvwC-S2-β` |
| γ (Fix #11 reaper-derive drops sbom_status) | HIGH | CLOSED via Fix #11 two-axis split + Rule #46 META-CANARY |
| δ (operator-supplied YAML authority laundering) | CRITICAL | DEFERRED — applies to Rule-of-Four campaign; documented in ADAPTIVE_BACKLOG with gate template |
| ε (polyglot ZIP × qcow2 strategy ambiguity) | HIGH | PARTIALLY CLOSED in Fix #9 — minimum-scope catalog-consultation reduces the surface; full closure requires Rule-of-Four `extraction_strategy: Literal[...]` |
| ζ (nested archive bomb × Fix #9 unblob fallback) | HIGH | DEFERRED — Fix #9 minimum-scope does NOT add unblob fallback; bomb mitigation queued for Rule-of-Four |
| η (concurrent operators × force_rescan transaction lock cascade) | MEDIUM | CLOSED in Fix #6 + frontend button gating per Scout D #4 |
| θ (Fix #11 reaper × operator-supplied future walker `partial` state) | MEDIUM | DEFERRED — applies to future operator-walker registration; documented |
| ι (grype force_rescan × SBOM regen race) | HIGH | CLOSED via Fix #1 .a precondition `if firmware.sbom_status in ('queued','running'): 409` on vuln-scan POST AND frontend disabled-button gating |
| κ (broader create_task sweep misses fuzzing.py:143) | MEDIUM | CLOSED via Rule #31 width-canary discipline in the sweep commit + Rule #46 META-CANARY |
| λ (dual sbom+vuln-scan polling DB pool exhaustion) | HIGH | PARTIALLY CLOSED — pool 40 holds for current operator load; composite-status endpoint + backoff queued for Session 3 |

## Gaps for W2-β + W2-γ

1. **W2-β cross-feature:** What's the attack at `_post_process_pipeline` (catalog-consulted) AND `unpack.py` Stage 1 (still hardcoded fw_type IF-ELIF) running on the same firmware? If the upload path enqueues `unpack_firmware_job` and Stage 1 then ALSO sees the catalog-derived `fw_type`, can they race? (Scout A:262-263 raised this; W2-β should produce a worked attack.)
2. **W2-β:** Is there a cross-feature attack between `STATE_MACHINE_REAPER_CONFIGS` and `WALKER_REAPER_CONFIGS` where a column name appears in BOTH? The Rule #46 META-CANARY asserts pairwise disjoint — what's the failure mode if a column is accidentally duplicated in a follow-up commit?
3. **W2-γ Rule #28 yardstick:** Combined LOC budget ~1,170 net. Re-measure `routers/sbom.py` (1114 LOC current — could drift 14-22% by end of session); `firmware_service.py` (937 LOC current); `main.py` (515 LOC). Fix #1 alone adds ~115 alembic + ~200 router + ~75 frontend = 390 LOC on top of `routers/sbom.py`; check this doesn't push the file past 1500 LOC requiring a Rule #27 split.
4. **W2-γ:** Does Session 2's combined work hit the Rule #51 mid-session re-evaluation tier-change requirement? `TIER_A_LIGHT_ACK` stays correct for the post-conversion `/sbom/generate`; the new `GET /sbom/generate/status` polling endpoint inherits the SlowAPI default `100/minute` per Scout D:81-83. Verify in `test_rate_limit_tiers._EXPECTED_TIERS`.
5. **W2-γ:** The unknown-format short-circuit path in `_run_sbom_generate_background` adds a code path the existing test suite doesn't exercise. Confirm Scout C:91-100's Rule #46 META-CANARY is reproducible via `make_live_db()` fixture with a real `Firmware` row having `detected_format='unknown'`.
6. **W2-γ:** The Rule #20 fast-iteration window for the alembic migration — confirm the migrator + worker + backend rebuild chain triggers correctly when Fix #1's migration lands. Rule #8 `migrator + worker + backend` three-way rebuild is mandatory.

## What Each Scout Missed

- **Scout A missed:** the structural distinction between Fix #9 minimum-scope (catalog-consultation only) and the full Rule #52 instance #3 refactor (closed-grammar `extraction_handler` Literal + handler-config sub-models + plugin registry). A's worked-example schema design IS the future Rule-of-Four campaign's design north star, but A conflated the two scopes into a single Session 2 deliverable. Scout B correctly separated them.
- **Scout B missed:** Scout C's §SC5-NEW-SBOM-S2-δ CRITICAL authority-laundering attack, which applies BEYOND just file-format catalog — it applies to every future operator-supplied YAML surface (including the Rule-of-Four campaign B endorsed). The gate-template documentation in ADAPTIVE_BACKLOG IS load-bearing for that campaign.
- **Scout C missed:** the existing 5 inlined reapers (cve_match / vuln_scan / device_dump / upload_stage / bare_metal_audit) at `main.py:160-348`. C's two-axis split is structurally correct, but the concrete refactor folds those 5 INTO the new `STATE_MACHINE_REAPER_CONFIGS` dict — a net deletion + addition, not pure addition. Scout E's design accounts for this (E:286-287).
- **Scout D missed:** the bare `asyncio.create_task` sweep scope (Scout A counted 5-6 sites; this session's verification grep found 6 in `routers/firmware.py` + `routers/hardware_firmware.py` + 1 in `routers/emulation.py:165` = 7 sites total). D's frontend-dominant analysis missed the backend sweep dimension.
- **Scout E missed:** Scout D's mandatory UX items #5-#6 (FormatBanner extraction + Try Generic Strategy button) cost ~80 LOC frontend that E's ~75 LOC frontend estimate excluded. The combined Fix #1 frontend is ~155 LOC, not ~75 LOC. E also missed Scout C's §SC5-NEW-SBOM-S2-γ requirement to split Option B into TWO axes — E's design is Option B walker-only, which is incomplete.

## Recommendation to Parent

Ship in this order: alembic migration (Rule #20 fast-iteration) → Fix #1 cross-stack alignment commit (Rule #48 Shape-1) → Fix #1 backend router + runner → Fix #6 grype force_rescan transactional → Fix #9 catalog consultation → Fix #11 two-axis reaper sweep → broader create_task sweep + `_spawn_background_task` to `app/utils/background.py` → Fix #1 frontend (polling + FormatBanner + Try Generic Strategy + force-regenerate gating) → `docker compose up -d --build frontend` (Rule #26). **Single-session feasible: YES** with MEDIUM-HIGH confidence — ~1,170 net LOC across ~16 Rule #25 per-piece commits, well within the Rule #28 +14-22% drift band on the underlying 3,031 LOC of source. Defer the full Rule #52 instance #3 extraction-strategy refactor (~4,600 LOC) to a Rule-of-Four campaign AFTER ICS Session 2 closes Rule-of-Three. Bisect-clean per Rule #25 — each commit is independently revertable. Confidence MEDIUM-HIGH: the Rule #33 conversion is mechanical per the vuln-scan precedent; the two-axis reaper split is novel but mechanically simple; Scout C's CRITICAL §SC5-NEW-SBOM-S2-δ is structurally deferred (no new YAML surfaces shipped this session) so its CRITICAL severity drops to "design-locked for the future campaign". The Rule #46 META-CANARIES paired with every closed-grammar gate (alignment, two-axis disjoint+complete, unknown-format short-circuit, no-bare-asyncio-create-task) are the single most important hardening — they ensure the gates fire when synthesised violations are tested, preventing the Rule #17 / Rule #45 / Rule #46 silent-success failure mode that has accumulated through this campaign's prior sessions.
