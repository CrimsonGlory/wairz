# Patterns: Windows-Coverage God-Mode Phase η (2026-05-11 + 2026-05-12 continuation)

> Extracted: 2026-05-11 (initial); extended 2026-05-12 (η.A + η.D closure)
> Campaign: `.planning/campaigns/windows-coverage-godmode-eta-2026-05-11.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-eta-2026-05-11.md`
> Outcome: **closed** — 5 of 5 streams shipped across 2 sessions (η.B + η.C + η.E on 2026-05-11; η.A + η.D on 2026-05-12)

## Successful Patterns

### 1. 3-scout research-fleet pre-pass with diverging lenses produces higher-confidence scope

- **Description:** Before scope decision on a multi-stream campaign with 13+ candidate items, dispatch 3 parallel research scouts (each ~3 min wall) with DIFFERENT analytical lenses: (A) OSS lib survey for tooling availability + license + maintenance, (B) Persona-E adversary completionist refresh for what 2024-2025 tradecraft surfaces in the artifact set, (C) Competitive RE platform parity for what KAPE/Plaso/Velociraptor/FACT cover that we don't. Synthesize convergence (≥2 scouts agree) + cheap-mention (1 scout flags + mechanical evidence supports) + single-lens HIGH (1 scout strongly recommends + LOW integration risk).
- **Evidence:** Phase 0 of this session — `.planning/research/eta-scope-2026-05-11/scout-{1,2,3}*.md`. Scout 2+3 converged on "Scheduled Task XML" (→ η.B); Scout 3 alone flagged LNK files (→ η.C); Scout 3's cheap-mention "PowerShell EID 4103/4104 in evtx_service.py" verified via mechanical grep that EIDs were NOT currently tagged (→ η.E). Synthesis selected 5 candidates spanning all 3 lenses; ZERO scope-mismatch surprises during execution.
- **Applies when:** Multi-stream campaign with 5+ candidate items where each candidate has different stakeholders / integration complexity / value profile. NOT applicable to single-stream tasks (use single-scout or direct execution).

### 2. Single-sub-agent dispatch per stream for Pattern P4 walker recipe

- **Description:** Archon decomposes the campaign into N streams; for each stream, dispatch a SINGLE general-purpose Agent sub-agent SERIALLY with comprehensive context (campaign file pointer + intake pointer + recipe shape file references + per-stream sub-task list + alembic ID hints + validation checklist + per-piece push strategy + HANDOFF format). Sub-agent operates directly on main (no worktree needed for serial dispatch); commits per-piece per Rule #25; pushes direct to main per Pattern P5; returns HANDOFF with all SHAs + bugs-encountered + recommendations to next sub-agent.
- **Evidence:** η.B sub-agent (~26 min wall, 5 commits, 41 tests, 3 MCP tools) + η.C sub-agent (~29 min wall, 6 commits, 41 tests, 3 MCP tools). Both completed end-to-end including direct-push without Archon mid-stream intervention. Faster than serial in-foreground execution (would have been ~45-60 min each due to context churn) AND safer than parallel worktree dispatch (which has cross-stack alignment file conflicts on `finding.py` Literal + `finding_service.py` classifier dict + frontend `types/index.ts` + alembic chain).
- **Applies when:** A walker stream that follows the established Pattern P4 recipe (table + status + walker triplet + alignment + MCP tools = 5-6 commits). NOT applicable to genuinely-novel architectural work (use Archon-foreground execution with full visibility) or to truly-parallelizable file-disjoint streams (use Rule #23 worktree dispatch).
- **Recipe extracted:** Sub-agent prompt structure includes (a) repo state at dispatch (HEAD, alembic head, tool count, container state), (b) goal + scope per campaign tracker section, (c) recipe shape file references (most-recent precedents), (d) prior sub-agent's HANDOFF recommendations, (e) validation checklist (pytest + ruff + tsc + alembic + Rule #11 smoke + tool count), (f) operating rules durable for every step (Rules #25/#38/#35a/#43 etc), (g) per-piece push strategy (Pattern P5), (h) HANDOFF format expected back.

### 3. Cross-stack alignment commit shape (Rule #25 single-slice exception #2) is durable beyond debate — Rule-of-Thirteen (post η.D.D)

- **Description:** Each new finding source value ships as ONE atomic commit touching: (a) alembic CHECK extension migration with `_NEW_SOURCE_VALUES` tuple + import-able by alignment test, (b) backend Pydantic Literal extension in `app/schemas/finding.py`, (c) backend module-level `_SOURCE_<NAME>: WindowsFindingSource = "<value>"` constant + classifier helper + emit method (or extension to existing emit method) in `app/services/finding_service.py`, (d) frontend `FindingSource` union extension in `frontend/src/types/index.ts`, (e) frontend `FINDING_SOURCE_CONFIG` dict entry in `frontend/src/constants/statusConfig.ts`, plus tier-1 classifier tests. Single ATOMIC commit. The `test_finding_source_alignment.py` STRICT pairwise test (DB CHECK ↔ FE union ↔ FE config) enforces zero-baseline-tolerance drift — splitting the commit would leave the test RED between commits.
- **Evidence:** Rule-of-Thirteen now: 7079b4d (2026-05-06 base) + ee2abd9 β.12a + f70c2e1 γ.7 + 20ea228 δ.8 + 5466644 ε.1.b.4 + da71afa ζ.1 + a6be708 ζ.2.C + 04a3c55 ζ.3.C → Rule-of-Eight; ac98e55 η.E + e149dcf η.B.D + fd7cd23 η.C.D (2026-05-11) → Rule-of-Eleven; 66bd8d6 η.A.D + e0403f5 η.D.D (2026-05-12) → Rule-of-Thirteen. The ATOMIC-commit shape ran 5 times across the 2 sessions by 5 different agents (Archon directly + η.B + η.C + η.A + η.D sub-agents) without coordination friction; each invocation kept alignment tests green pairwise.
- **Applies when:** Adding a new value to `WindowsFindingSource` Literal that needs DB CHECK extension AND frontend UI rendering. The recipe location should be promoted to `.mex/patterns/cross-stack-finding-source-alignment.md` (this is one of the postmortem's recommendations).

### 4. Rule #20 docker cp + alembic upgrade head iteration deferring Rule #8 rebuild to end-of-session

- **Description:** During an Archon-orchestrated session that ships N alembic migrations across multiple streams, apply each migration via Rule #20 `docker cp <new>.py wairz-backend-1:/app/alembic/versions/...` + `docker compose exec backend alembic upgrade head` — fast (~30 sec/migration) versus full rebuild (~3-5 min). Defer the Rule #8 backend+worker+migrator rebuild to end-of-session (single rebuild closes the loop). Run Rule #11 import smoke against the rebuilt container as the cut-over verification step.
- **Evidence:** This session shipped 6 alembic migrations (e7f8a9b0c1d2 + f8a9b0c1d2e3 + f9a0b1c2d3e4 + a0b1c2d3e4f5 + b1d2e3f4a5c6 + c2e3f4a5b6d7 + a7b8c9d0e1f2 — wait that's 7 chained). All applied iteratively via Rule #20 without rebuild between iterations. End-of-session Rule #8 rebuild + Rule #11 import smoke confirmed all 3 walker triplets + LnkParse3 dep import cleanly in rebuilt container. Saved ~25 minutes vs per-migration-rebuild.
- **Applies when:** Multi-migration session with stable on-disk class shape (no Rule #20 caveat-class-shape changes that would need restart even within Rule #20 path). NOT applicable when: (a) single-migration session (just rebuild once), (b) any migration adds a new model field that's read by an `@lru_cache`'d singleton (Rule #20 caveat — needs restart at minimum, full rebuild safer).
- **Companion:** η.C sub-agent's observation that container drifts from host-side new modules after stacked Rule #20 iterations — workaround: docker cp the OTHER stream's model+service+schema files alongside your migration on each iteration, OR rely on tier-1 tests against host .venv (the validated cadence this session). End-of-session rebuild closes the loop.

### 5. Tier-1 tests against host `.venv` catch sub-agent bugs BEFORE commit

- **Description:** When a sub-agent implements new code, run targeted pytest against the HOST `.venv` (not the container) BEFORE committing. The host venv has the new code on-disk; tier-1 unit tests on the new functions surface bugs at sub-agent time, not post-merge. Container-side validation can defer to end-of-session via Rule #20 / Rule #8 closure.
- **Evidence:** This session caught 3 bugs PRE-COMMIT via tier-1 tests:
  1. η.B `\b-enc\b` regex word-boundary failure → caught by `test_classifier_detects_encoded_powershell_in_action`
  2. η.C `\b\[char\[\]\]\(` regex word-boundary failure → caught by classifier unit test
  3. η.C JSONB datetime serialization (LnkParse3 returns `datetime` objects asyncpg rejects) → caught by walker tier-1 test against `tiny.lnk` fixture
- **Applies when:** New classifier / parser / walker code where input shape is well-defined enough to write synthetic fixture tests. NOT applicable when input shape is genuinely unknown until real-firmware contact (those are Rule #35b live canaries — also valuable but slower feedback).

### 6. Rule #39 inner/outer/safe runner triplet recipe — Rule-of-Eight (post η.A.C)

- **Description:** Every walker that owns a Rule #33 .a state machine ships as the canonical 3-function triplet: `_do_<op>_run(db, firmware_id) -> dict` (INNER pure-logic; uses `get_detection_roots(firmware)`; called by tier-1 tests via `make_live_db()`); `run_<op>_background(firmware_id) -> None` (OUTER state-machine wrapper owning idle/queued/running/completed/failed transitions); `auto_<op>_walk_firmware_safe(firmware_id) -> None` (UNPACK-POST-DETECTION HOOK; swallows exceptions; doesn't mutate firmware status). Recipe: `.mex/patterns/inner-outer-safe-runner.md`.
- **Evidence:** Rule-of-Eight now: γ.4 (registry_hive_walker, Rule-of-One implicit) + δ.5 (windows_update_diff_service) + ε.1.b.3 (evtx_service walker) + ζ.2.B (prefetch_walker) + ζ.3.B (srum_walker) → Rule-of-Five; η.B.C (scheduled_task_walker, 2026-05-11) + η.C.C (lnk_walker, 2026-05-11) → Rule-of-Seven; η.A.C (mft_walker, 2026-05-12) → Rule-of-Eight. Recipe is the canonical Wave-1 shape for any new walker in wairz; under-30-minutes-per-walker via single-sub-agent dispatch.
- **Applies when:** Any new firmware-walking service that produces persisted records + finding emission. The triplet shape is mechanical and reproducible.

### 7. Pre-allocated alembic chain order for serial sub-agent dispatch

- **Description:** When N sub-agents will run SERIALLY (not parallel) and each adds M migrations, communicate the serialization order in the per-sub-agent prompt: "your migrations chain after the previous sub-agent's tail (most-recent head)". Sub-agent uses the `.mex/patterns/add-alembic-migration.md` recipe to pick fresh IDs. For TRULY parallel dispatch, pre-allocate IDs at decomposition time + tell each sub-agent their assigned IDs.
- **Evidence:** This session: η.E (1 mig) → η.B (3 migs) → η.C (3 migs); each sub-agent picked fresh IDs after grep-verifying freshness against the 73-revision tree. Zero alembic chain divergence; zero merge conflicts on `versions/`.
- **Applies when:** Sub-agent dispatch with new alembic migrations. SERIAL dispatch: tell each sub-agent the current head + recipe; PARALLEL dispatch: pre-allocate IDs to avoid chain divergence at merge time.

### 8. Pattern P5 per-piece direct-push to main + Rule #41 must-complete CI cadence

- **Description:** Each per-piece commit (per Rule #25) is pushed directly to main via `git push origin main`. Rule #41 mechanism (a) lint-per-commit must-complete sibling guarantees Lint runs to completion on every commit boundary regardless of subsequent push cadence. Rule #41 mechanism (b) backend-tests nightly cron at 06:00 UTC catches deeper regressions ≤24h.
- **Evidence:** This session: 14 phase code commits + 2 planning commits = 16 pushes; ALL Lint runs SUCCESS within ~1 minute of each push; Backend Tests cancelled-on-intermediate per `concurrency.cancel-in-progress` is the EXPECTED Pattern P5 + Rule #41 mechanism (b) handoff. Zero Lint failures observed.
- **Applies when:** Trusted environment (≥20 sessions per `.claude/harness.json`) with per-piece commit discipline. The cadence is healthy and durable.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | NTFS-only `$MFT` in η.A; defer `$UsnJrnl` + `$LogFile` to θ | Single-walker scope per η stream keeps Pattern P4 1-day-per-walker cadence; the other two NTFS files have distinct ORM tables + finding shapes warranting own phase letters | η.A scope is bounded and pre-decomposed for next session; θ inherits a clear prerequisite |
| 2 | Scheduled Task XML walker uses `defusedxml.ElementTree` (not raw stdlib `xml`) | Pattern P3 from ζ campaign — defusedxml swap pattern; XXE protection on untrusted input | η.B.C ships with defusedxml import + safe parser; tier-1 tests pass |
| 3 | LNK walker adds `LnkParse3>=1.5` to pyproject.toml | The 2026-05-07 intake's TODO never landed; CONFIRMED via grep → 0 hits; closing this debt is part of η.C scope | η.C.0 ships LnkParse3==1.6.0 dep; pure Python; no native build deps |
| 4 | BYOVD anchor follows Rule #37 offline-trust-anchor discipline (deferred) | Network-time fetch defeats worker security boundary; rate-limit / attacker-MITM / reproducibility risks; bundle JSON + SHA256 + URL sidecars + quarterly cron | Pre-decomposed in campaign tracker η.D section; deferred to next session |
| 5 | PowerShell EID extension uses ONE Literal value (`windows_powershell_script_block`) for both 4103/4104 | The Literal describes the FINDING (a PowerShell script-block was logged), not the event-id taxonomy; sub-EID metadata into the finding's evidence/details rather than separate Literal values | η.E shipped with one Literal value + heuristic-driven confidence (4103→LOW, 4104 plain→MEDIUM, 4104+obfuscation→HIGH); 12 tier-1 tests pass |
| 6 | Ship 3 cheapest streams (η.B + η.C + η.E) THIS session; defer 2 larger (η.A + η.D) to next session | Hot-start avoidance per `feedback_do_them_all_pattern.md`; smaller streams ship via single-sub-agent dispatch in ~25-30 min each; larger streams (NTFS walker + Rule #37 anchor work) get fresh-context next session | 3 streams shipped (12 phase code commits); 2 streams pre-decomposed in campaign tracker with end conditions |
| 7 | Per-piece direct-push to main (Pattern P5) | Trust = trusted (≥184 sessions); Rule #41 must-complete CI mitigations healthy; per-piece preserves bisect-clean per Rule #25 | 14 phase commits direct-pushed; all Lint CI green per-piece; zero force-pushes; zero amends |
| 8 | η.E reuses ε's `emit_evtx_findings_from_walk` method (no new walker, no new MCP tool category) | PowerShell EID classification is annotation extension on existing EVTX walker — no new persistence-store category warranted; sub-EID branch in existing per-record loop is the cleanest shape | η.E ships as ONE atomic alignment commit (no walker, no MCP tools, just classifier + emit extension); 12 tier-1 tests pass |
| 9 | WMI persistence + Boot chain artefacts + Volatility 3 + Shim .sdb + EFS + EVT + ETL + hibernate.sys deferred to a θ campaign letter | Each is its own multi-stream effort warranting its own phase; η stays a horizontal-expansion phase across smaller-scoped artefact walkers | θ scope pre-allocated in intake's "Out of scope" section; ready for next campaign cycle |

## Companion patterns (cross-references)

- **Recipe location for cross-stack alignment** — should be promoted to `.mex/patterns/cross-stack-finding-source-alignment.md` per postmortem recommendation 2.
- **Recipe location for single-sub-agent-per-stream Archon dispatch** — should be documented as a follow-up to `feedback_do_them_all_pattern.md` per postmortem recommendation 3.
- **Recipe location for inner/outer/safe runner triplet** — already exists at `.mex/patterns/inner-outer-safe-runner.md`; Rule-of-Five → Rule-of-Eight extension.
- **Recipe location for Rule #41 must-complete CI mitigation** — already exists at `.mex/patterns/rule-41-must-complete-ci.md`; mechanism (b) empirical validation deferred to 2026-05-13 06:00 UTC nightly cron.

## Additions from 2026-05-12 continuation session (η.A + η.D closure)

### 9. Pre-flight research-scout-corrects-intake-assumptions before sub-agent dispatch — Rule-of-Two

- **Description:** Before dispatching a single-sub-agent for a stream that depends on a NEW external library or NEW bundled artifact, run a focused ≤10-min research scout to verify: (a) license (intake may name a license that's stale), (b) API shape (the intake's pseudocode may be wrong against the real library), (c) bundle size / schema if applicable. The scout's findings get embedded VERBATIM in the sub-agent prompt so the agent doesn't need to re-research, saving wall time and reducing speculation-based errors.
- **Evidence:** 2026-05-12 continuation session ran 2 parallel scouts for η.A + η.D streams:
  - **dissect.ntfs scout** corrected intake's "MIT" license claim to AGPL-3.0-or-later (compatible with wairz AGPL but flagged); provided canonical inner-runner skeleton against GitHub HEAD; identified that `record.full_path()` can raise on orphans; confirmed `dissect.cstruct` + `dissect.util` transitive deps are pure-Python.
  - **LOLDrivers scout** corrected intake's "5-10 MB" bundle size to **29.8 MB** (3-6x larger); verified Apache-2.0 license with redistribution permitted (LICENSE + NOTICE sidecars required); flagged schema field drift (`CVE` vs `CVEs` key + 23-records flat/nested hash anomaly) requiring Rule #35c normalizer; provided 7 recommended bundle fields.
  - All 3 corrections landed BEFORE the sub-agents committed.
- **Applies when:** Sub-agent dispatch for a stream that integrates with a new external library, bundle, or vendor-provided dataset. The "scout corrects intake" pattern works because intakes are written months ahead and external libraries / bundles evolve.
- **Rule-of-Two:** Both scouts (one each for η.A + η.D) returned material corrections. Pattern is durable; promote to a `.mex/patterns/pre-dispatch-library-scout.md` recipe in a future learn pass.

### 10. Mock-at-source per Rule #30 when fixture generation requires unavailable system deps

- **Description:** When tier-1 walker tests need a synthetic fixture file (e.g. NTFS volume, registry hive, raw disk image) but the host environment lacks the tooling to generate one (sudo + ntfs-3g + loop-mount NOT available; `mkfs.ntfs` not installed; etc.), DON'T skip the tier-1 tests. Instead, apply Rule #30 patch-target discipline: mock the parser library at the SOURCE module (`patch("dissect.ntfs.NTFS")`) and have the mock yield fixture-shaped `MftRecord`-like objects. The walker code is exercised; the parser library's correctness is its own concern.
- **Evidence:** η.A.C (`mft_walker.py`) hit this exactly: synthesizing an NTFS volume requires sudo + ntfs-3g + loop-mount on the dev host. Agent applied Rule #30: `patch("dissect.ntfs.NTFS")` returned a context-managed fake whose `mft.segments()` yielded hand-authored fixture-records with the expected $STD_INFO / $FILE_NAME / $DATA shape. 31 walker tests landed clean. Future campaign can add a pre-built `tiny.ntfs.dd` fixture under `backend/tests/fixtures/windows/` for real-parsing integration tests; the mock-at-source tests remain useful for fast feedback regardless.
- **Applies when:** Walker / parser code where the upstream library requires a non-trivial input artifact AND the dev host can't generate one cheaply. NOT applicable to libraries that take pure-Python data structures as input (mock isn't needed there).
- **Rule-of-One** for the NTFS case; reinforces Rule #30 patch-target discipline as a general technique.

### 11. Bundle SHA256 pin verified post-push round-trip (large-file Rule #37 worked example)

- **Description:** When committing a large external bundle (>1 MB) to git per Rule #37 offline-trust-anchor discipline, verify the SHA256 pin survives the full git transport: commit → push → fetch on origin → re-verify locally. Confirms the bundle hasn't been line-ending-normalized, truncated, or otherwise mutated by git in transit.
- **Evidence:** η.D's `backend/ms-anchors/loldrivers.json` is **29.79 MB** — significantly larger than β.10's `dbxupdate.bin` (24 KB). η.D sub-agent ran `( cd backend/ms-anchors && sha256sum -c loldrivers.json.sha256 ); ec=$?` post-push and verified ec=0. Bundle SHA256 `ddda516c90150069d1ca8b8a6151f53adadfd5608534a0e95265574792b81fec` matched commit → push → re-verify. Rule #37 flow handles 30 MB bundles cleanly.
- **Applies when:** Any Rule #37 bundle larger than ~1 MB. For sub-MB bundles, the post-push verification is over-engineering. For >1 MB, the verification is cheap insurance.
- **Rule-of-Two now for Rule #37 worked examples** — β.4 (signify TRUSTED_CERTIFICATE_STORE, package-shipped) + β.10 (`dbxupdate.bin`, 24 KB raw) + η.D (`loldrivers.json`, 29.79 MB raw) = 3 worked examples. The pattern is durable across small-and-large bundles.
