# Patterns: Windows-Coverage God-Mode γ (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase γ section)
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-gamma-2026-05-09.md`
> Branch: `feat/windows-phase-gamma-2026-05-09`
> Commits in scope: `e3e94cc..8437ae3` (γ.1 through γ.9)
> Status: 9 sub-tasks completed; campaign Phase γ CLOSED (Phase δ pending)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta11-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta12-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta14-2026-05-08-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the γ-delta learnings.

## Successful Patterns

### 1. Real-PE canary skip-tier discipline generalises to registry + drivers

- **Description:** β.14a Pattern #1 (real-PE canary 3-tier discipline:
  tier-1 always-runs against host data + tier-2/3 skip-unless-fixture)
  generalises cleanly to other forensic-pipeline canaries. γ.9 applied
  the same shape to registry hives + driver CATs:
  - **Tier 1 (always runs)** — synthetic regf-magic fixture + INF/CAT
    triplet on disk. Drives the FULL γ pipeline (γ.4 walker → γ.5
    extractor → γ.8 emit). Mocks regipy at the source module per
    Rule #30 to keep tier-1 deterministic without dragging a real hive
    into the repo.
  - **Tier 2 (skip-unless `WAIRZ_TEST_REAL_HIVE`)** — real Win11
    SOFTWARE/SYSTEM hive driven through `walk_hive_path` with NO
    regipy mock. Asserts the regipy parse succeeds + the persistence
    classifier emits ≥1 draft.
  - **Tier 3 (skip-unless `WAIRZ_TEST_SIGNED_CAT`)** — real Microsoft-
    signed `.cat` driven through `classify_cat_signing_tier` with NO
    mock. Asserts catalog_signed=True + signing_tier in any
    Microsoft-anchored bucket.
- **Evidence:** γ.9 commit `8437ae3`,
  `backend/tests/test_registry_driver_real_firmware.py`. 4 tests:
  2 tier-1 (full-pipeline + empty-root sanity, both always pass) +
  2 tier-2/3 (skip-unless env-var fixture). β.14a precedent
  (5 tests, 3p + 2s) + γ.9 (4 tests, 2p + 2s) = Rule-of-Two.
- **Applies when:** Any Rule #35b real-artefact canary across
  forensic pipelines where tier-1 host artifacts can exercise the
  cumulative surface and tier-2/3 fixtures need operator
  provisioning. Pattern is durable now — promotable to a
  `.mex/patterns/real-firmware-skip-tier-canary.md` recipe on the
  third application (Phase δ R2R-stomping detection canary is the
  natural next test ground).

### 2. Per-table tri-state Literal+CHECK alignment test

- **Description:** New test shape introduced in γ.2:
  `test_windows_check_literal_alignment.py` parses each model's
  `__table_args__` for `CheckConstraint(name=...)` IN-list values,
  compares against the matching Pydantic Literal's `typing.get_args()`,
  and fails on drift. Single test file co-locates verification across
  multiple (Literal, CheckConstraint) pairs via a `_PAIRS` tuple —
  future tri-state columns append to the tuple instead of copying the
  test helper.
- **Evidence:** γ.2 commit `0c12ede`. Two pairs covered at γ shipping:
  `(WindowsDriverSigningTier, ck_windows_drivers_signing_tier)` and
  `(WindowsRegistryExtractWalkStatus, ck_windows_registry_extracts_
  walk_status)`. Both pass.
- **Applies when:** Any per-table tri-state column (NOT firmware-row
  status columns — those don't carry ORM-level CheckConstraints).
  Distinct from `test_finding_source_alignment.py` which is a
  cross-stack agreement test (DB ↔ FE union ↔ FE config) over a
  central allowlist; this one is single-stack (Pydantic Literal ↔
  ORM CheckConstraint) for per-table columns. Companion to the
  cross-stack alignment test rather than a replacement.

### 3. Library-API surface-shape probe before classifier code

- **Description:** Rule #19 evidence-first applied to library APIs:
  before writing γ.4 walker code, ran a 30-second `inspect.getsource`
  + `attr.fields` probe of `regipy.registry.RegistryHive.recurse_subkeys`
  to confirm the yield shape (`Subkey` attr-class with
  `{subkey_name, path, timestamp, values_count, values, actual_path}`,
  values being `attr.asdict(Value)` dicts of
  `{name, value, value_type, is_corrupted}` when `as_json=True`).
  Same probe for `signify.pkcs7.SignedData.from_envelope` before
  γ.5 classifier — confirmed `signer_infos` + `verify(...)` shape.
  Both probes informed the classifier dataclass shape + test
  assertions on first draft; zero re-design iteration.
- **Evidence:** γ.4 + γ.5 sessions — probes ran before either
  worker module was written. Walker test fixture (`_FakeSubkey`
  attr-shaped class) matched real regipy yield shape on first
  attempt; classifier test mocks (`_FakeCert` with `subject` attr)
  matched signify cert shape on first attempt.
- **Applies when:** Any new third-party library integration where
  the data-flow shape isn't obvious from the library's README. Cost:
  ~30 seconds of `python -c "import inspect; print(inspect.getsource(...))"`
  or `dir(cls); attr.fields(cls)`. Benefit: classifier code grounded
  in real surface area; test fixtures match yields on first try.
  Generalises β.14a Pattern #5 (real-artefact verdict probe) from
  "probe pipeline output" to "probe library input" — same Rule #19
  spirit applied to a different surface. Rule-of-Two now (β.14a
  pattern + γ.4/γ.5 application).

### 4. Tree-shaped JSONB normalizer + schema_version + stamp helper (3-application mass)

- **Description:** Rule #35c JSONB normalizer + stamp + schema_version
  discipline applied uniformly across γ to 3 new tree-shaped JSONB
  columns:
  - `windows_registry_extracts.parsed_tree` (γ.1): nested
    subkey list with key/value counts, walk-completion flags,
    error list.
  - `windows_drivers.inf_metadata` (γ.2): version block +
    manufacturer block + models list + strings table + errors.
  - `firmware.registry_hive_walk_result` (γ.3): aggregate run
    summary with `by_hive_type` + `by_walk_status` histograms.
  Each shipped with normalizer (defensive against None/wrong-type
  → empty canonical) + stamp helper (idempotent schema_version
  injection) + ≥10 tests covering canonical / None / wrong-type /
  idempotency.
- **Evidence:** γ.1 commit `e3e94cc`, γ.2 commit `0c12ede`, γ.3
  commit `183a2e8`. 35 normalizer tests added across the three
  columns; all pass.
- **Applies when:** Adding any tree-shaped JSONB column with ≥3
  consumer files (γ's were 4+ each: worker/writer + MCP/reader +
  FE/reader + classifier/reader). Pattern is durable; reference
  shape is `.mex/patterns/add-jsonb-column.md` from earlier
  campaigns.

### 5. Lazy-import third-party in service module + patch-at-source-module in test (Rule #30 application)

- **Description:** γ.4 + γ.5 service modules import third-party
  libraries (regipy, signify) FUNCTION-LOCALLY rather than at module
  scope, per Rule #30 (cold-import cost + optional-dependency
  partition). Tests patch the SOURCE module (`regipy.registry.
  RegistryHive`, `signify.pkcs7.SignedData`) rather than the
  consumer's namespace, per Rule #30 corollary — patching the
  consumer's namespace is a silent no-op for lazy-imported names.
- **Evidence:** γ.4 walker imports `from regipy.registry import
  RegistryHive` inside `walk_hive_path` (function body); tests
  patch `regipy.registry.RegistryHive`. γ.5 classifier imports
  `from signify.pkcs7 import SignedData` inside
  `classify_cat_signing_tier`; tests patch `signify.pkcs7.
  SignedData` (would patch — current tests use defensive default
  for unparseable bytes). All 31 walker tests + 33 extractor tests
  pass.
- **Applies when:** Any third-party library whose cold import is
  non-trivial OR optional. The pattern is durable now (Rule #30
  established + γ.4/γ.5 reapplied + audit-2026-05-04 androguard
  family already codified in harness rule
  `auto-pytest-mock-patch-androguard-at-service`).

### 6. Auto-walk-on-unpack hook reuses existing post-extraction safety helper

- **Description:** γ.4 + γ.5 each add ONE call to
  `unpack._run_hardware_firmware_detection_safe` (after detection +
  graph build complete) — a fire-and-forget call to the new
  `auto_walk_firmware_safe` / `auto_extract_drivers_safe` entry
  points. Each entry point owns its own AsyncSession via
  `async_session_factory()`, swallows exceptions, logs. Same shape
  as the existing detection + graph calls; minimal new
  orchestration; one chained `try/except` block per hook.
- **Evidence:** γ.4 commit `3161a70` `unpack.py:120-132` (+12 LOC);
  γ.5 commit `be167cd` `unpack.py:134-146` (+13 LOC). Both hooks
  fire on every firmware unpack post-detection without per-format
  conditionals; respects detection_roots discipline (Rule #16) so
  scatter-zip + multi-partition firmware get walked uniformly.
- **Applies when:** Any new "scan extracted tree for X" worker
  that should run automatically after every unpack. Reuses the
  existing safety-helper pattern instead of inventing a new
  orchestration layer. Phase δ R2R-stomping detection +
  windows-update-diff workers can apply the same shape.

### 7. Rule #25 single-slice exception #2 — Rule-of-Three now

- **Description:** γ.7 bundled the alembic migration extending
  `ck_findings_source` + frontend `FindingSource` union extension +
  frontend `FINDING_SOURCE_CONFIG` mirror in ONE commit, per Rule
  #25 single-slice exception #2 (cross-stack alignment tests
  require pairwise agreement; splitting leaves the alignment test
  RED between commits and breaks bisect-clean lanes).
- **Evidence:** γ.7 commit `f70c2e1`. The
  `test_finding_source_alignment.py` tests (3/3) pass on the
  bundled commit and would have been RED if any of the three
  surfaces had been split off. Rule-of-Three now: `7079b4d`
  (2026-05-06) + `ee2abd9` (β.12a) + `f70c2e1` (γ.7). Pattern is
  durable.
- **Applies when:** Any cross-stack enum extension where
  `test_finding_source_alignment.py` (or analog) enforces pairwise
  agreement. Bundle in one commit. Bisect-clean is preserved.

### 8. CWD-drift bash discipline (Rule #38) — Rule-of-Three clean

- **Description:** Rule #38 absolute-path bash discipline held
  100% clean across γ — every `git` invocation used `git -C
  /home/dustin/code/wairz`; every cwd-sensitive tool wrapped in a
  subshell `( cd backend && uv run ... )`. ~50+ Bash invocations
  in this session, zero CWD-drift incidents.
- **Evidence:** γ session bash log — all `git status` / `git add`
  / `git commit` calls used `git -C ...`; uv invocations used
  subshell scoping or absolute paths.
- **Applies when:** Every Bash invocation in this codebase. Rule
  is durable (β.14 first clean session under codified rule + γ
  second clean session = Rule-of-Three counting β.10/β.12 as the
  inciting incidents).

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | Branch γ off β tip (`feat/windows-coverage-godmode-2026-05-07`) NOT main | β infrastructure (WindowsFindingSource Literal, ck_findings_source CHECK extension, authenticode chain runner, WindowsPESignature model, etc.) is required for γ; main is 5 weeks stale | Correct on first attempt; user mid-session clarification ("our main is clean-history") confirmed the active mainline; γ branch topologically equivalent to `clean-history + α + β + γ` |
| 2 | regipy over pyhivex for hive walking | Pure-Python read-only library; matches Rule #5 sync-then-executor without C-extension ABI surprises; more mature for read-only walks per the kickoff prompt design constraint | Installed cleanly via `uv sync`; first probe + test passes |
| 3 | String-pattern heuristic for CAT signing-tier (no full chain walking) | γ.5 is integration only per kickoff prompt; full chain walking (EKU / CRL / OCSP) is out of scope | Tier-3 fixture provisioning will surface real verdicts to refine the heuristic; documented heuristic limitations in module docstring |
| 4 | Skeleton FE pages without REST integration | γ.7 single-slice alignment slice already large (3 surfaces); REST surface deferred to follow-up commit; pages link to MCP-tool reference for today's functionality | Pages compile + render; REST endpoints are clean follow-up scope; no scope creep on γ.7 |
| 5 | `asyncio.create_task` for registry walk dispatch | In-process pure-Python work + per-hive INSERTs are durable + restart recovery via UniqueConstraint | Matches Rule #33 .d rubric exactly; γ.6 trigger MCP tool captures task per the β.14a Pattern #2 deterministic-test shape |
| 6 | Per-table Literal+CHECK alignment test (γ.2) | Co-locates verification with the new tri-state column; reuses test pattern; future tri-state columns append to `_PAIRS` | New durable test shape established; covers γ.2 signing_tier + γ.1 walk_status on first commit |
| 7 | Auto-walk + auto-extract hooks fire from `_run_hardware_firmware_detection_safe` | Already runs on every unpack post-detection; γ hooks reuse the existing post-extraction safety helper instead of inventing new orchestration | Minimal new orchestration (~25 LOC across γ.4+γ.5); same fire-and-forget shape as existing helpers; no per-format conditionals |
| 8 | Bundle 4 FE skeleton pages + alignment + route registration in single γ.7 commit | Pages depend on FindingSource + FINDING_SOURCE_CONFIG additions; co-located by topic; alignment slice itself is the must-bundle per Rule #25 exception #2 | One coherent commit at the cross-stack boundary; bisect-clean alignment maintained |
| 9 | Defer REST endpoints + full FE data integration to follow-up | γ.7 scope already at upper bound; γ.6 MCP tools provide full functionality today via Claude Code/Desktop; REST is additive | Phase γ closed cleanly at 9 commits; REST endpoints + FE hydration are well-scoped follow-up tickets |

## Cross-references back into existing knowledge

- **Pattern #1 (real-PE canary skip-tier)** is the second application
  of β.14a Pattern #1. Rule-of-Two — durable. Promotable to a
  `.mex/patterns/real-firmware-skip-tier-canary.md` recipe on the
  third application (Phase δ R2R-stomping is the natural next).
- **Pattern #2 (per-table Literal+CHECK alignment test)** is novel
  to this codebase. Distinct from `test_finding_source_alignment.py`
  (cross-stack DB↔FE alignment) — covers single-stack
  Pydantic↔ORM-CheckConstraint alignment for per-table tri-state
  columns. Future per-table tri-state additions append to `_PAIRS`.
- **Pattern #3 (library-API surface-shape probe)** generalises
  β.14a Pattern #5 from "probe pipeline output" to "probe library
  input". Same Rule #19 spirit; different surface. Rule-of-Two now.
- **Pattern #4 (tree-shaped JSONB normalizer)** applies the existing
  Rule #35c discipline (codified at audit-2026-05-04 + α.1) to
  3 new γ columns uniformly. Pattern is mature.
- **Pattern #5 (lazy-import + patch-at-source)** reapplies Rule #30
  (already codified, with a specific harness rule for the androguard
  family). γ.4/γ.5 generalises the discipline to regipy + signify;
  no new harness rule needed (the lesson is the rule).
- **Pattern #6 (post-extraction safety helper extension)** is a new
  durable shape — γ.4 + γ.5 each added one ~13-LOC fire-and-forget
  hook to the existing helper. Phase δ workers (R2R-stomping +
  update-diff) can append the same shape.
- **Pattern #7 (Rule #25 single-slice exception #2)** is now Rule-
  of-Three (`7079b4d` + `ee2abd9` β.12a + `f70c2e1` γ.7). Pattern
  is durable. Codified in CLAUDE.md Rule #25.
- **Pattern #8 (Rule #38 absolute-path discipline)** is Rule-of-Two
  for clean sessions under the codified rule (β.14 + γ). Discipline
  is durable.
- **Rule #25 per-sub-task commits** is now Rule-of-Eleven across
  the windows-coverage campaign (α 12 + β 14 + γ 9 = 35 commits, 0
  reverts). Pattern is durable beyond doubt.
- **Rule #35a pipe-trap reproducibility** — γ.7 was the second
  catch-via-canary (audit-2026-05-04 was the first). Codified rule
  + canary discipline both held; the recurrence was caught in
  seconds. Rule-of-Two — see anti-patterns file for the failure
  mode + new harness rule candidate.
- **Rule #35b live canary** is now Rule-of-Eleven across the campaign.
  γ added 13 new live canaries (4 in walker + 3 in extractor + 4
  in finding emit + 2 in tier-1 canary). Cumulative ~93 live
  canaries across α + β + γ.
- **Rule #36 no-execute discipline** — γ extends the no-execute
  rule from installer custom actions (α.2 MSI/MSU) and Authenticode
  signature parsing (β.4) to registry hives (γ.4 reads via regipy,
  never invokes regedit/.reg apply) and driver INF/CAT files (γ.5
  parses INF as text, validates CAT as PKCS#7, never invokes
  rundll32/.inf install). Pattern is mature; codified rule held
  uniformly.
- **Rule #37 offline-trust-anchor discipline** — γ.5 reuses the
  β.10 DBX bundle infrastructure + signify's TRUSTED_CERTIFICATE_STORE
  (which is itself bundled by signify, not fetched at scan time).
  No new offline-anchor work in γ.
