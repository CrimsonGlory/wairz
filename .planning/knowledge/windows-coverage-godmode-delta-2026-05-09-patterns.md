# Patterns: Windows-Coverage God-Mode δ (2026-05-09)

> Extracted: 2026-05-09
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase δ section)
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-delta-2026-05-09.md`
> Branch: `feat/windows-phase-delta-2026-05-09`
> Commits in scope: `1fbdaab..1f09179` (δ.1 through δ.9)
> Status: 9 sub-tasks completed; campaign Phase δ CLOSED (Phase ε deferred per PRD)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta11-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta12-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta14-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-gamma-2026-05-09-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the δ-delta learnings.

## Successful Patterns

### 1. Real-PE canary skip-tier discipline generalises to .NET + KB-diff (Rule-of-Three durable)

- **Description:** β.14a Pattern #1 / γ.9 Pattern #1 (3-tier real-
  artefact canary: tier-1 always-runs against synthetic data + tier-2/3
  skip-unless-fixture) generalises a third time to .NET single-file
  bundles + KB-vs-KB diff:
  - **Tier 1 (always runs)** — synthetic .NET PE (mocked dnfile/pefile)
    + synthetic two-package KB pair on disk. Drives the FULL δ pipeline
    (δ.4 argv discipline → δ.5 inner runner UPSERT path → δ.6 R2R
    classifier → δ.8 emit hook). Mocks dnfile + pefile at the source
    module per Rule #30 to keep tier-1 deterministic.
  - **Tier 2 (skip-unless `WAIRZ_TEST_REAL_DOTNET_BUNDLE`)** — real
    .NET 8 single-file bundle driven through `classify_r2r_stomp_findings`
    with NO dnfile mock. Asserts well-shaped output without crashing.
  - **Tier 3 (skip-unless `WAIRZ_TEST_KB_DIFF_FIXTURE`)** — real
    (older_kb, newer_kb) extracted package pair driven through
    `_do_diff_run` with FS-walk fallback. Asserts ≥1 DLL diff row.
- **Evidence:** δ.9 commit `1f09179`,
  `backend/tests/test_dotnet_update_diff_real_firmware.py`. 7 tests:
  5 tier-1 (always pass) + 2 tier-2/3 (skip-unless env-var fixture).
  β.14a (5 tests, 3p+2s) + γ.9 (4 tests, 2p+2s) + δ.9 (7 tests, 5p+2s)
  = **Rule-of-Three confirmed; pattern is durable.**
- **Applies when:** Any Rule #35b real-artefact canary across forensic
  pipelines where tier-1 host artifacts can exercise the cumulative
  surface and tier-2/3 fixtures need operator provisioning. **Promote
  to `.mex/patterns/real-firmware-skip-tier-canary.md` recipe** — three
  applications across two phases is enough evidence.

### 2. Inner-vs-outer runner split for live canary testing

- **Description:** Background runners that own a Rule #33 .a state
  machine via `async_session_factory()` (e.g.
  `decompile_firmware_background`, `run_windows_update_diff_background`)
  cannot run against the live test DB from the host pytest sweep — the
  factory's connection string resolves Docker hostnames (`postgres`)
  that don't resolve outside the container network. The fix shape:
  expose an INNER runner that accepts a `db` arg + does the actual
  work; the OUTER wrapper owns the state machine + uses
  `async_session_factory()`. Tests target the inner runner with the
  live test DB; the outer wrapper is exercised in the running container.
- **Evidence:** δ.5 `windows_update_diff_service._do_diff_run(db,
  firmware_id)` called by both
  `_run_windows_update_diff_background` (factory wrapper) and the
  δ.9 tier-1 canary `test_tier1_synthetic_update_diff_persists_dll_rows`.
  Same shape as γ.4's `auto_walk_firmware(fw.id, db)` (the inner runner
  accepts the db; auto_walk_firmware_safe wraps it). Caught the failure
  mode on first canary run via `socket.gaierror`; refactored in
  ~3 minutes; no commit-level rework.
- **Applies when:** Authoring any Rule #35b live canary against a
  service that uses `async_session_factory()`. Mechanical heuristic:
  if the service runner takes only `firmware_id` (no `db` param), look
  for an inner function that takes `db` + factor the canary against it.
  If no inner runner exists, the service was structured for production
  dispatch only — refactor to expose one (single-line addition; no
  caller changes). Promotable to a CLAUDE.md rule once a third
  occurrence shows up.

### 3. Rule #36 forbidden-argv0-token gate as the no-execute test gate

- **Description:** Rule #36 (no-execute discipline) requires that
  subprocess argv[0] resolve to a trusted, image-shipped binary —
  never to a runtime that would execute the input file. δ.4 codifies
  this as a public function `assert_no_execute_argv(argv: list[str])`
  + a frozen tuple `FORBIDDEN_ARGV0_TOKENS = ("wine", "mono", "dotnet",
  "cscript", "wscript", "powershell", "pwsh")`. The function checks
  `os.path.basename(argv[0]).lower()` against the tuple — catches
  bare names AND path-prefixed forms (`/usr/bin/dotnet`). Tests
  parametrize over every forbidden token + path-prefixed variant
  (12 cases × 7 tokens) → every runtime + variant rejected.
- **Evidence:** δ.4 commit `96bae6e`,
  `backend/app/services/dotnet_decompile_service.py:411-440` +
  `backend/tests/test_dotnet_decompile_service.py:73-100`. The
  function is also re-importable from the (future) trigger router for
  defense-in-depth re-validation before enqueuing.
- **Applies when:** Any new worker that invokes a third-party CLI tool
  via subprocess against extracted artefacts. The forbidden-token
  tuple should be EXTENDED (not duplicated) when new runtimes need
  guarding (e.g. add `node` if a future worker shells out to a JS
  runtime). Pattern generalizes Rule #36 from "spec" to "automated
  test gate"; first concrete codification of the rule.

### 4. JSONB consumer-count threshold + schema_version + stamp helper (γ + δ = Rule-of-Six)

- **Description:** Rule #35c JSONB normalizer + stamp + schema_version
  discipline applied uniformly across δ to 3 new tree-shaped JSONB
  columns:
  - `windows_update_packages.update_metadata` (δ.1): manifest +
    supersedence (both directions) + applicability + file BOM with
    SHA256.
  - `firmware.dotnet_decompile_result` (δ.2): per-firmware decompile
    aggregate (counts + per-bundle output paths + by-arch histogram).
  - `firmware.windows_update_diff_result` (δ.3): per-firmware diff
    aggregate (per-type counts + by-KB-pair histogram).
  Each shipped with normalizer (None-preserving defensive coercion) +
  stamp helper (idempotent schema_version) + ≥10 tests covering
  canonical / None / wrong-type / idempotency.
- **Evidence:** δ.1 commit `1fbdaab`, δ.2 commit `cf6b6be`, δ.3 commit
  `390d2e5`. Plus γ.1+γ.2+γ.3 (3 columns) for a Rule-of-Six durable
  application. Cumulatively across the campaign: 6 windows-coverage
  JSONB normalizers shipped (3 in γ + 3 in δ); 12+ pre-existing
  normalizers extended. Pattern is mature beyond the "rule-of-three"
  bar.
- **Applies when:** Adding any tree-shaped JSONB column with ≥3
  consumer files (δ's were 3+ each: writer + ≥1 MCP reader + ≥1 FE
  reader + ≥1 classifier reader). Reference recipe is
  `.mex/patterns/add-jsonb-column.md`.

### 5. Per-table Pydantic Literal ↔ DB CHECK alignment test extension (Rule-of-Two now)

- **Description:** γ.2 introduced
  `test_windows_check_literal_alignment.py` with 2 pairs (γ.1
  walk_status + γ.2 signing_tier). δ extends to 4 pairs by appending:
  `(WindowsUpdatePackageType, ck_windows_update_packages_type)` (δ.1)
  + `(WindowsUpdateDllDiffType, ck_windows_update_dll_diffs_type)`
  (δ.5). Future per-table tri-state additions append to the `_PAIRS`
  tuple — no test helper duplication needed.
- **Evidence:** δ.1 commit `1fbdaab` + δ.5 commit `92e0514`. Test
  passes 4/4 against rebuilt env; would have failed if any pair drifted
  between Literal and CheckConstraint allowlist.
- **Applies when:** Adding any per-table tri-state column with a
  matching Pydantic Literal. The `_PAIRS` tuple-extension shape is
  durable (γ.2 first application + γ.2 + δ.1 + δ.5 four applications =
  Rule-of-Two for the EXTENSION discipline; Rule-of-Four for the
  underlying pattern).

### 6. Rule #25 single-slice exception #2 — Rule-of-Four now (durable beyond doubt)

- **Description:** δ.8 bundled the alembic migration extending
  `ck_findings_source` + Pydantic `WindowsFindingSource` Literal
  extension + finding_service constants + `emit_r2r_stomp_findings_from_decompile`
  + frontend `FindingSource` union extension + `FINDING_SOURCE_CONFIG`
  entries + 2 FE skeleton pages + App.tsx route registration in ONE
  commit, per Rule #25 single-slice exception #2 (cross-stack alignment
  tests require pairwise agreement; splitting leaves the alignment
  test RED between commits and breaks bisect-clean lanes).
- **Evidence:** δ.8 commit `20ea228`. The
  `test_finding_source_alignment.py` tests (3/3) pass on the bundled
  commit and would have been RED if any of the 4 surfaces had been
  split off. **Rule-of-Four now**: `7079b4d` (2026-05-06) + `ee2abd9`
  (β.12a) + `f70c2e1` (γ.7) + `20ea228` (δ.8). Pattern is durable
  beyond doubt.
- **Applies when:** Any cross-stack enum extension where
  `test_finding_source_alignment.py` (or analog) enforces pairwise
  agreement across DB CHECK ↔ FE union ↔ FE config. Bundle in one
  commit. Bisect-clean is preserved.

### 7. Rule #33 .d arq vs asyncio.create_task split (codified application)

- **Description:** Rule #33 .d (dispatch rubric) was applied
  successfully in 4 places across δ:
  - **arq dispatch** for δ.4 `decompile_dotnet_bundle_job` (worker-only
    resource — gated dotnet-sdk-8.0 + ilspycmd lives in the worker
    container only; Docker spawn = arq).
  - **asyncio.create_task** for δ.5
    `_run_windows_update_diff_background` (in-process pure-Python
    diff + per-DLL incremental DB persistence is the durable state).
  - δ.7's `trigger_dotnet_decompile` MCP tool implements both
    dispatchers — tries arq first via `arq.create_pool`, falls back to
    `asyncio.create_task` when arq is unavailable. This dual-dispatch
    pattern matches the existing `spawn_emulation_session_job` shape.
- **Evidence:** δ.4 commit `96bae6e` (arq registration in
  WorkerSettings.functions), δ.5 commit `92e0514`
  (asyncio.create_task entry), δ.7 commit `5645c05` (trigger fallback).
- **Applies when:** Any new 202+poll background work. Apply the
  rubric mechanically: (i) worker-only resource? → arq; (ii) survives
  backend restarts via Redis-queue durability? → arq; (iii) needs
  scheduled/cron triggering? → arq. Otherwise asyncio.create_task is
  the right shape (in-process work + per-row durable state +
  fire-and-observe-via-status sufficient).

### 8. Rule #19 evidence-first probe before new third-party library code

- **Description:** Pre-δ.4 + pre-δ.6 ran the explicit dependency-
  availability probe `uv run python -c "import dnfile, dncil, capa"`
  before authoring any code that imports them. The probe found all
  three were MISSING from the host venv (despite being in the worker
  container via the existing flare-capa pip3 install at Dockerfile
  line 251). Caught the gap BEFORE writing the code; added them to
  pyproject.toml + ran `uv sync` as the first action of δ.4.
- **Evidence:** δ.4 commit `96bae6e` (pyproject.toml additions of
  dnfile + dncil + flare-capa; commit message documents the probe).
  Without the probe, δ.4 service code would have been written, then
  failed at host pytest time with `ModuleNotFoundError`, then required
  a second commit to add the deps — a Rule #2 violation.
- **Applies when:** ANY new feature that imports a third-party library
  not previously used in the codebase. Cost: 1-second `uv run python
  -c "import X, Y, Z"`. Benefit: eliminates "code written → tests fail
  → realize deps missing → second commit" loop. Generalises γ.4's
  regipy probe pattern to a multi-package check.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | Branch δ off γ tip (`8437ae3`) NOT main | γ infrastructure is required for δ; main is 5 weeks stale relative to clean-history. Same lesson as γ's branch-off-main correction. | Correct on first attempt; no mid-session clarification needed (γ kickoff already documented the topology) |
| 2 | δ.5 dedicated `windows_update_dll_diffs` table (not JSONB on firmware) | Restart recovery via natural-key UPSERT (`firmware_id, dll_path`) is cleaner than JSONB array merge; per-DLL filter queries scale better than JSONB containment ops | Matches δ.5 background runner contract; UPSERT path verified in tier-1 canary |
| 3 | δ.4 dotnet-sdk gated `INCLUDE_DOTNET=1` (default off) | Backend image stays slim; operators opt in for the +200 MB ilspycmd worker delta. PSF gating (α D1) precedent | Default container builds work without ilspycmd; service degrades gracefully (firmware status → failed with clear message) |
| 4 | δ.6 service-only (NO finding emit yet) — emit hook + ck_findings_source extension co-located in δ.8 | Per-Rule #25 exception #2 — the alignment slice extending DB CHECK + Pydantic Literal + FE union + FE config + emit method is single-slice; splitting would leave the alignment test RED between commits | δ.6 ships pure-detection; δ.8 wires the emit + extends the allowlist atomically. Bisect-clean preserved. |
| 5 | δ.7 windows_storage tools surface paths + sizes only (no deep parsing) | Deep ESEDB extraction needs `libesedb-utils` apt package not yet in Dockerfile. Tools detect availability + degrade gracefully (clear "library not installed — Dockerfile delta needed" message). PRD goal "VHDX/BCD/ESEDB inspectable" met at the path-discovery level. | Tools functional today; deeper parsing tracked as δ-postmortem follow-up #5 (libesedb Dockerfile delta). |
| 6 | δ.6 R2R-stomp Tier 1 + Tier 2 SHIPPED; Tier 3 + Tier 4 documented but deferred | Tier 3 byte-level prologue compare needs ~50 LOC + native disasm engine integration; Tier 4 needs custom capa-rules. Wait until tier-2 fixture provisioning surfaces real divergence patterns before designing the rule set. | δ.6 ships practical detection; deeper tiers are post-δ follow-ups (postmortem rec #6). |
| 7 | Per-DLL UPSERT batch size = 100 | Smaller = more DB round-trips + smaller transaction recovery boundary; bigger = fewer round-trips but larger rollback cost. 100 = aggregate sweet spot matching γ.4's hive-walk batch shape. | Tier-1 canary verifies the batch path; production tuning happens post-fixture-provisioning. |
| 8 | Inner-runner exposed for testability (δ.5 `_do_diff_run`) | Live-canary tests can't use `async_session_factory()` (Docker DNS only); inner runner accepts `db` directly. γ.4 `auto_walk_firmware` precedent. | Tier-1 canary uses inner runner; outer wrapper exercised in container-runtime smoke. |
| 9 | δ.7 trigger_dotnet_decompile dual-dispatch (arq with asyncio.create_task fallback) | arq enqueue may fail if Redis is unreachable (deployment with arq disabled, e.g. minimal CI). Falling back to asyncio.create_task keeps the trigger functional in degraded environments. Same shape as `spawn_emulation_session_job`. | Trigger works in both environments; tested at registry-shape level (δ.9 tier-1 canary). |

## Cross-references back into existing knowledge

- **Pattern #1 (real-PE skip-tier canary)** is the THIRD application
  of β.14a Pattern #1 — Rule-of-Three confirmed; PROMOTE to
  `.mex/patterns/real-firmware-skip-tier-canary.md` recipe.
- **Pattern #2 (inner-vs-outer runner split)** is novel within this
  codebase as an explicit pattern. γ.4's `auto_walk_firmware(fw.id, db)`
  was the implicit precedent; δ.5 codifies the discipline. Promotable
  to a CLAUDE.md rule on the third independent occurrence.
- **Pattern #3 (Rule #36 forbidden-argv0 gate)** is the FIRST concrete
  test-gate codification of Rule #36. Generalises the spec to an
  automated check that fires at test time. Future workers can `from
  app.services.dotnet_decompile_service import assert_no_execute_argv,
  FORBIDDEN_ARGV0_TOKENS` and re-use directly.
- **Pattern #4 (JSONB consumer-count threshold)** is the SIXTH
  application of Rule #35c since it was codified at audit-2026-05-04.
  Pattern is mature beyond the rule-of-three bar.
- **Pattern #5 (per-table alignment-test extension)** is Rule-of-Two
  for the extension discipline (γ.2 first + δ.1+δ.5). Pattern is
  durable; future per-table tri-state additions append to `_PAIRS`.
- **Pattern #6 (Rule #25 single-slice exception #2)** is now
  Rule-of-Four (`7079b4d` + `ee2abd9` β.12a + `f70c2e1` γ.7 +
  `20ea228` δ.8). Pattern is durable beyond doubt. Codified in
  CLAUDE.md Rule #25.
- **Pattern #7 (Rule #33 .d dispatch split)** is the FIRST rigorous
  application of the dispatch rubric in a single phase across both
  paths. Future phases applying both arq AND asyncio.create_task in
  one campaign should follow the δ split.
- **Pattern #8 (Rule #19 multi-package import probe)** generalises
  the γ.4 single-package regipy probe to a multi-package check.
  Discipline is durable; the cost is 1 second per probe.
- **Rule #25 per-sub-task commits** is now **Rule-of-Twelve across
  the windows-coverage campaign** (α 12 + β 14 + γ 9 + δ 9 = 44
  commits, 0 reverts). Pattern is durable beyond reasonable doubt.
- **Rule #35a pipe-trap reproducibility** — δ.9 used the file-redirect
  + capture-before-tail discipline for the Rule #24 tsc canary.
  Codified rule + canary discipline both held.
- **Rule #35b live canary** is now applied across γ + δ to ~37 new
  live canaries (γ added 13 + δ added 18). Cumulative ~111 live
  canaries across α + β + γ + δ.
- **Rule #36 no-execute discipline** — δ extends the rule from
  installer custom actions (α.2) + Authenticode (β.4) + registry
  (γ.4) + driver INF/CAT (γ.5) to .NET single-file bundles (δ.4
  ilspycmd reads PE+metadata as data) + capa-on-IL (δ.6 reads IL
  bytes via flare-capa). The forbidden-argv0 tuple is the new
  instance-of-the-rule.
- **Rule #37 offline-trust-anchor discipline** — δ.4's
  `dotnet tool install` runs at IMAGE BUILD TIME (not scan time);
  the canonical `packages-microsoft-prod.deb` is from Microsoft's
  repo, equivalent in trust to apt's debian:slim trust anchors. No
  scan-time fetch added. Discipline holds.
- **Rule #38 absolute-path bash discipline** — δ caught one mid-flow
  CWD drift instance (after `cd backend && uv run`) and corrected
  with explicit `cd /home/...wairz` reset before any git invocation.
  Validates the discipline rather than violating it. Net 0 incidents
  in the commit log.
