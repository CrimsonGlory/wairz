# Patterns: Windows-Coverage God-Mode β.8 + β.9 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta8-beta9-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `70274c3` (β.8 background runner + 202+poll endpoints), `8247153` (β.9 windows_pe_signature MCP tools)
> Status: 2 sub-tasks completed; campaign as a whole IN PROGRESS (β.10-β.14 remain)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md` (β.5-β.6 delta)
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md` (β.7 delta + α.3 cleanup)

Patterns already captured there are not re-stated; this file captures
only the β.8/β.9-delta learnings.

## Successful Patterns

### 1. DIRECT_MAPPED-as-frozenset moves the verdict↔ORM contract from a test literal to a runner-owned single source of truth

- **Description:** β.5/β.6/β.7 each grew the drift-detector's `direct_mapped`
  literal in `test_authenticode_service.py:test_verdict_maps_to_windows_pe_signature_columns`.
  β.8 promoted the literal to a `DIRECT_MAPPED: frozenset[str]` at
  module scope in the runner module
  (`app/services/authenticode_chain_runner.py`). The runner uses it for the
  row-construction site (`WindowsPESignature(**{k: v for k, v in
  asdict(verdict).items() if k in DIRECT_MAPPED}, blob_id=blob.id)`) AND
  the drift-detector test imports the SAME constant. A `frozenset`
  (not `set`) prevents accidental `.add()`-style mutation in either
  consumer.
- **Evidence:** β.8 commit `70274c3`. The drift-detector test passed
  unchanged after the refactor; β.9's MCP tools rely on the same
  field set indirectly through the verdict spread. Test
  `test_direct_mapped_is_frozen` enforces the immutability contract
  (mutation attempts raise `AttributeError`).
- **Applies when:** Any value-set whose source is a literal in a test
  file AND a literal in production code, where the two MUST stay in
  sync. Generalised: when the third repetition appears (Rule of
  Three), promote to a single source of truth in the production
  module + import in the test. The frozenset (vs plain set) is
  load-bearing — sets in Python are mutable and `set | other_set`
  produces a new set, but `frozen.add()` raises, so accidental
  mutation in either consumer fails fast at write time, not at the
  next drift-detector run.

### 2. Cve-match precedent reduces 202+poll work to ~5 minutes of design

- **Description:** β.8's outer runner + 202+poll endpoint pair
  was structurally identical to `_run_cve_match_background` +
  `POST /cve-match` + `GET /cve-match/status` in
  `routers/hardware_firmware.py`. Same session ownership pattern
  (own `AsyncSession` via `async_session_factory()` in `async with`),
  same status transitions (queued → running → completed/failed),
  same idempotent POST + 409 + 2 s polling shape, same outer-guard +
  inner-try + fresh-session-on-failure structure. Total β.8 design
  time was ~5 minutes of "do exactly what cve-match did, replace
  cve_match with authenticode_chain". The Rule #33 contract makes
  this work durable across operations: cve-match (in-process, DB-
  persisted), authenticode-chain (in-process, DB-persisted), fuzzing
  (Docker spawn delegated), emulation (arq job).
- **Evidence:** β.8 commit `70274c3` lifts the structure verbatim
  from `routers/hardware_firmware.py:486-646`. Five 202+poll
  applications now in tree (firmware unpacking, emulation, fuzzing,
  cve-match, authenticode-chain); zero rework cycles on β.8's
  endpoint pair.
- **Applies when:** Adding a new long-running operation (>100s
  ceiling) that needs detached execution with status polling. The
  mechanical recipe: (a) check the status-column migration mirrors
  the cve-match shape (5 columns: `_status` String(20) with CHECK,
  `_started_at`, `_finished_at`, `_error` Text, `_result` JSONB
  optional); (b) write `_run_<op>_background(id)` mirroring
  `_run_cve_match_background`; (c) write `POST /<op>` with 409 on
  in-flight + `asyncio.create_task` schedule; (d) write `GET
  /<op>/status` mirroring `get_cve_match_status`. The recipe is
  worth promoting to `.mex/patterns/add-202-polling-windows-op.md`
  (PRD already calls for it but hadn't been authored).

### 3. MCP-category-as-thin-service-wrapper for verdict-bearing operations

- **Description:** β.9's 6 tools each follow the same shape: input
  validation + `context.resolve_path()` (Rule #1) + `loop.run_in_executor(None, sync_fn, args)` (Rule #5) + JSON-render-or-explicit-error.
  `verify_authenticode` is 7 LOC of handler body. `detect_pe_arch_view`
  is 6 LOC. The DB-read tools (`list_signatures`,
  `get_signature_chain`) are ~30 LOC each (SELECT + result shaping).
  Total tool LOC is ~170; the rest of the file is registration
  metadata + JSON-shaping helpers. The shape mirrors α.4
  `windows_archive` exactly — same registry pattern, same
  `_truncate(_OUTPUT_CAP_BYTES)` Rule #29 cap, same stub-context
  test infrastructure.
- **Evidence:** β.9 commit `8247153`. Tool registry growth
  178 → 184 (exactly the 6 PRD-named tools); 22 unit tests cover
  every tool's missing-file / null-return / JSON-shape / error path.
  Zero rework; ~30 minute end-to-end implementation time including
  tests.
- **Applies when:** Surfacing a service-layer verdict to the MCP
  layer. The mechanical rule: each tool is one of three shapes —
  (a) **service wrapper**: `path → service(path) → JSON`; (b)
  **DB read**: `params → select(Model).where(...).filter(...) →
  JSON`; (c) **mutation**: `params → service(params) → context.db.flush()
  → status string`. Don't mix shapes in one tool. The α.4 +
  β.9 + future Phase γ/δ MCP categories should each be
  decomposable into these three shapes.

### 4. Two-shape MCP category — service wrappers + DB-reads — completes the operator workflow

- **Description:** The PRD listed 4 explicit β.9 tool names
  (`verify_authenticode`, `decode_rich_header`, `scan_dbx_revocation`,
  `detect_pe_arch_view`) — all service wrappers. Without DB-read
  tools, the category would be write-only-via-async-runner: the
  operator could trigger β.8's runner via `POST /authenticode-chain`
  but couldn't see the results without a frontend. Adding
  `list_signatures` + `get_signature_chain` (DB-read tools that
  consume β.8's persisted rows) closes the loop: operator runs the
  background job → polls status → uses MCP to read individual rows
  or list summaries. Both reads JOIN `WindowsPESignature` →
  `HardwareFirmwareBlob` to filter by the active firmware_id (from
  the ToolContext); both return JSON the operator can copy-paste
  into a finding.
- **Evidence:** β.9 commit `8247153`. PRD said "6 tools incl. {4
  named}" — the "incl." correctly implied more tools; the read
  tools were the natural completion. The β.9 commit message
  documents this as positive scope drift (Rule #19 evidence-first:
  the PRD's "incl." is evidence the operator-workflow needed
  completion, not minimisation).
- **Applies when:** A verdict-bearing service generates persistent
  rows that another part of the system writes (background runner)
  but the MCP layer is the operator's only read path until the
  frontend ships. Pair every batch-writer with at least one DB-read
  tool that surfaces a single row + at least one DB-read tool that
  surfaces a list view. The list view needs filter + offset
  pagination (50/page) per Rule #29's 30 KB output cap. Companion
  to Phase γ/δ work: every new batch-writer MCP category should
  ship with at least 2 DB-read companions until the frontend
  catches up.

### 5. Pre-coding grep on the iteration target column (Rule #19 evidence-first applied to data layout)

- **Description:** β.8 design constraint #6 explicitly named the
  evidence-first sweep: "read app/services/firmware_paths.py
  (get_detection_roots) + app/models/hardware_firmware.py BEFORE
  writing iteration code — confirm exactly which column carries the
  PE-on-disk path. Don't assume; grep." The grep
  (`grep -rn 'blob_path' backend/app/services/hardware_firmware/`)
  confirmed `blob_path` is set from `entry.path` in the detector's
  `_walk_and_classify` (line 160), which is an absolute path from
  `os.scandir`. An assumption-based iteration that joined
  `extracted_path + blob.blob_path` (a tempting mental model since
  many ORM relations carry relative paths) would have produced
  invalid paths and `verify_pe_file` would have reported
  "PE file not found" for every blob.
- **Evidence:** β.8 implementation went directly from grep result
  to `path = blob.blob_path` (no join, no resolve). All 16 runner
  tests passed first try after the substring-collision fixture bug
  was fixed; zero "wait, why is the path wrong" debug cycles.
- **Applies when:** Any new code that iterates an ORM relation +
  reads the file at a column-stored path. The 30-second grep beats
  the 5-minute "why does the file not exist" debug loop. Companion
  to Rule #19 (evidence-first remediation) and Rule #31 (broadest-
  reasonable grep width) — both are about cheap empirical checks
  before the code is written.

### 6. The Rule #35a pipe-trap reproduces even when you know about it

- **Description:** Rule #35a (a) — `cmd | tail; rc=$?` captures
  `tail`'s exit, not `cmd`'s — was documented in CLAUDE.md before
  this session. β.8's first pytest validation invocation reproduced
  the trap exactly: `pytest ... 2>&1 | tail -80; rc=$?; echo
  "pytest_rc=$rc"` printed `pytest_rc=0` despite the visible
  "1 failed" in the tail output. Caught by reading the visible
  pytest summary line, NOT by the captured exit code. Recovery was
  immediate (~30 sec): switched to file-redirect (`cmd > /tmp/x;
  rc=$?; tail -30 /tmp/x`) for every subsequent pytest invocation
  in both β.8 and β.9.
- **Evidence:** β.8 session transcript shows the trap-and-recovery
  sequence at the first runner-test validation; subsequent 5+
  pytest invocations all used file-redirect cleanly with
  `real_pytest_rc` consistent with visible summary.
- **Applies when:** Any validation step where exit code is the
  success criterion. The durable lesson is mechanical: **when
  capturing $?, don't pipe**. The Rule #35a discipline is correct;
  the trap fires when you're focused on something else (test
  fixture bug here, type error elsewhere, build failure, etc.).
  Treat "I know about Rule #35a" as not equivalent to "I never
  trip Rule #35a"; muscle-memory of the file-redirect pattern is
  the durable response.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | DIRECT_MAPPED frozenset in runner module (not test) | Single source of truth as the Rule of Three iteration repeats; frozenset prevents accidental mutation in either consumer | β.8 ships clean; drift-detector test passes after refactor; future Phase γ/δ verdict additions surface in exactly one place |
| 2 | β.8 runner in service module (`services/authenticode_chain_runner.py`) not router | Cve-match has runner in router but heavy work in service; β.8 separates more aggressively because the runner IS the heavy work (no separate matcher service to call) | One module is the natural unit; the router becomes thin (just session management + 202 ack); aligned with cve-match's matcher/router split spirit |
| 3 | Per-PE flush (not batch flush) in `verify_firmware_pe_chain` | Partial progress survives a session-level abort mid-run; large PE counts (Win11 ISO has 1000+) avoid memory pressure with batch | Test `test_verify_firmware_pe_chain_idempotent_on_rerun` confirms re-run cleanly DELETEs prior rows + re-inserts; per-PE flush + outer rollback semantics work cleanly |
| 4 | Re-run idempotency via DELETE WHERE blob_id IN (firmware's blobs) | The CASCADE on `WindowsPESignature.blob_id → hardware_firmware_blobs.id` doesn't help on re-run because the blobs themselves persist; explicit DELETE keeps the per-firmware row set fresh | Two consecutive runs produce N rows, not 2N; `test_verify_firmware_pe_chain_idempotent_on_rerun` enforces |
| 5 | MZ-magic pre-filter before verify_pe_file | Existing `hardware_firmware/classifier.py` doesn't classify PEs (no "pe" format in the FORMATS set), so most blobs are ELF/MBN/DTB content where verify_pe_file would waste signify cycles. The pre-filter keeps the runner cheap on real-world firmware | Per-PE iteration time is dominated by signify; non-PE skip is a 2-byte read + branch. β.8's empty-firmware test confirms the histogram pre-seeds correctly when no PE rows exist |
| 6 | β.9 ships 6 tools (4 service wrappers + 2 DB reads) per PRD's "incl." framing | Without DB reads the category is write-only-via-async-runner; the operator workflow needs read tools until the frontend ships | β.9 ships clean with `list_signatures` (filtered + paginated) + `get_signature_chain` (basename match); 6 Rule #35b live canaries enforce the read shape |
| 7 | `get_signature_chain` matches by basename, not full path | Absolute blob_paths in the DB are post-extraction filesystem paths that may not match the operator's virtualised firmware-tree view; basename match is the durable correspondence | `test_get_signature_chain_full_path_falls_back_to_basename` confirms a virtualised path also resolves; `test_get_signature_chain_matches_by_basename` confirms direct basename input works |
| 8 | β.9 wraps β.4-β.7 services in MCP without re-implementing | Service-layer logic is the durable contract; MCP is the operator-facing thin layer; duplication would create two divergence surfaces | All 6 β.9 tools are wrapper-shaped; ~170 LOC of tool body across 6 tools |

## Cross-references back into existing knowledge

- **Pattern #2 (verdict-field mirror)** is now Rule of Four (β.5/β.6/β.7
  + β.8's frozenset promotion). The single-source-of-truth refactor at
  the fourth iteration is the natural evolution. **β.5/β.6 postmortem
  rec #1** (promote to `.mex/patterns/add-pe-verdict-field.md`) is now
  reinforced by this session — should ship with the recipe before β.10
  starts.
- **Rule #33 4-bullet contract** (idempotent POST + 409, persisted
  result, Pydantic Literal + DB CHECK, asyncio vs arq rubric) holds
  cleanly for β.8. Five applications now in tree.
- **Rule #35a pipe-trap recovery** reproduced once, recovered cleanly
  via file-redirect. The discipline is durable; the muscle memory
  needs occasional reinforcement.
- **Rule #35b live canary** caught a test-fixture bug at fixture-design
  time, not at production time. Pattern is durable across every β-phase
  application; β.8 + β.9 added 12 new live canaries (6 in each).
- **Rule #19 evidence-first** applied to a data layout question (which
  column carries the PE-on-disk path) instead of a remediation
  condition. Same discipline; different surface. Promote to a more
  general formulation: "evidence-first applies to ANY pre-coding
  question whose answer is in the source tree".
