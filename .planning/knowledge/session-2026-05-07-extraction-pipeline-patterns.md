# Patterns: 2026-05-07 multi-OS extraction pipeline campaign

> Extracted: 2026-05-07
> Source: 19 commits between `d9b6c4a` (baseline) and `f2423f3` (HEAD) on
> branch `clean-history`. 4 archon dispatches, 0 reverts, 0 regressions, +58 tests.
> Phase 1 ships dispatch infrastructure (strategy registry + sentinel worker +
> pipeline). Phase 2 ships the first three handlers (ISO 9660 via 7z, WIM via
> wimlib-imagex, Windows installer ISO via recursive composition).

## Successful Patterns

### 1. Strategy registry as single source of truth + capability-map alignment invariant

The `STRATEGIES` dict in `backend/app/workers/extraction_strategies.py` is the
ONE place that maps `DetectedFormat` → worker callable. The
`EXTRACTION_CAPABILITY` map (authored manually, surfaces user-visible status)
is kept in lockstep with the registry via a test asserting that FULL formats
have NO `CAPABILITY_NOTES` entry while PARTIAL/NONE formats do. When a handler
ships, both files update in the same per-handler commit group — a registry
edit without a capability bump fails the alignment test on the next pytest run.

- **Description:** Two parallel structures (machine-dispatch registry + human-
  readable capability map) stay coherent because a test enforces the invariant
  ("FULL ⇔ no notes; PARTIAL/NONE ⇔ has notes") rather than relying on
  discipline alone.
- **Where applied:** Commits `8db9916` (registry creation),
  `502efbb` (capability cross-reference doc), `a340e24` / `f866b2d` /
  `f2423f3` (per-handler capability bumps).
- **Mechanical detection / how to apply next time:** When adding a new
  DetectedFormat or new handler, edit BOTH `extraction_strategies.py` AND
  `extraction_capability.py` in the same commit. The
  `test_capability_notes_only_for_partial_or_none` invariant fails fast if
  either side drifts.
- **Companion to:** Rule #19 (evidence-first — the test is a structural
  evidence gate); Rule #25 (per-sub-task commits — registry + capability bumps
  ship as adjacent commits in the handler group).

### 2. Per-handler 4-commit shape (Rule #25 applied at the handler level)

Every Phase 2 handler shipped as exactly four commits: (a) worker module
additive (no caller wired yet), (b) strategy registration cut-over (registry
edit), (c) capability bump + note removal, (d) test file. Each commit is
independently revertable; the cut-over commit (b) is the single point at
which dispatch behavior changes.

- **Description:** A miniature applied form of Rule #27's "N additive + 1
  cut-over" — additive worker file, additive test, atomic registration cut.
  Bisect-clean; partial-revert clean.
- **Where applied:** ISO 9660 (`a4bea55..a340e24`), WIM
  (`9a0a7cc..f866b2d`), Windows installer ISO (`9a5c500..f2423f3`).
  WIM added a 5th commit for the Dockerfile change (apt-get wimtools), which
  preceded the worker module — a justified deviation since the worker can't
  even be smoke-tested without the binary present.
- **Mechanical detection / how to apply next time:** When opening a handler
  PR, expect 4 commits (5 if a Dockerfile change is needed). A bundled
  "feat(extraction): add X handler" omnibus is the anti-shape — split it.
- **Companion to:** Rule #25 (per-sub-task commits); Rule #27 (additive +
  cut-over for refactors of any size).

### 3. Live canary via real-tool round-trip (Rule #35b applied to subprocess workers)

Each handler test creates fixture data on disk, captures it INTO the target
format using the real CLI tool (`mkisofs` / `xorrisofs` / `wimlib-imagex
capture`), then passes the resulting artifact through the worker and walks
the extracted tree to confirm round-trip integrity. Tests skip gracefully
via `pytest.skip` when the host lacks the tool; the in-container path runs
cleanly because the Dockerfile installs the dep.

- **Description:** Mock-only tests verify "subprocess.run was called with
  these args" — they cannot catch a wrong flag, a wrong working directory,
  or a sasquatch-style FATAL-mid-stream silent failure. The real-tool
  round-trip is the live canary that catches value-flow bugs.
- **Where applied:** `backend/tests/test_unpack_iso9660.py`,
  `backend/tests/test_unpack_wim.py`,
  `backend/tests/test_unpack_windows_installer_iso.py` (commits `a340e24`,
  `f866b2d`, `f2423f3`).
- **Mechanical detection / how to apply next time:** Every new subprocess-
  driven worker test gets a `_make_<format>_fixture()` helper that uses the
  real authoring tool. Pure-mock tests are insufficient — add the canary in
  the same commit as the worker test file.
- **Companion to:** Rule #35b (mocks vs live canaries — value flow needs a
  real round-trip); Rule #11 (post-split runtime smoke — same shape:
  py_compile says nothing about runtime); Rule #34a (sasquatch FATAL was
  the original "subprocess succeeded but data is wrong" lesson).

### 4. Recursive dispatch composition for nested formats

The Windows installer ISO worker (`backend/app/workers/unpack_windows_installer_iso.py`)
extracts the outer ISO via the ISO 9660 handler, then walks the result for
`sources/install.wim` / `boot.wim` and invokes the WIM handler on each.
Inner extractions pass `progress_callback=None` (caller owns progress);
inner failures are logged but do NOT fail the outer extraction (degraded
success). Inner artifacts land as siblings beside the source
(`sources/install.wim` → `sources/install.wim_extracted/`) so
`get_detection_roots(firmware)` (Rule #16) discovers them on its scan.

- **Description:** Outer-format strategy invokes inner-format strategies as
  function calls — no re-entry through the dispatcher, no shared state, each
  inner call returns its own `UnpackResult` that the outer worker logs and
  proceeds.
- **Where applied:** Commit `f2423f3` (Windows installer ISO worker +
  registration + test).
- **Mechanical detection / how to apply next time:** When a format is a
  container of other supported formats, compose at the worker level (not at
  the dispatcher level). Layout the inner extractions as siblings so
  detection_roots picks them up automatically.
- **Companion to:** Rule #16 (always use `get_detection_roots()` for
  filesystem walks); Rule #27 ("N additive + 1 cut-over" — the inner
  handlers existed before composition shipped, so the outer is purely
  additive).

### 5. Container dependency verification before Dockerfile change

Before adding `wimtools` to the backend Dockerfile, the dispatch ran
`docker compose exec -T backend which wimlib-imagex` to confirm the binary
was NOT already present. This is a Rule #19 evidence-first gate — the
Dockerfile change costs a Rule #8 backend+worker rebuild (~3-5 min); if the
tool is already there (transitively pulled by an existing apt package), the
rebuild is wasted.

- **Description:** `which <tool>` / `dpkg -l | grep <pkg>` inside the
  running container BEFORE editing the Dockerfile. Cost: 1 second. Saves: a
  potentially-wasted rebuild cycle.
- **Where applied:** Commit `9a0a7cc` (Dockerfile install of wimtools) was
  preceded by the verification step in the WIM handler dispatch.
- **Mechanical detection / how to apply next time:** Any apt-get install
  Dockerfile diff is a candidate. Run the `which` probe first; only edit
  the Dockerfile if the probe fails.
- **Companion to:** Rule #19 (evidence-first); Rule #8 (worker+backend
  rebuild discipline — minimize the rebuild count).

### 6. Lockstep strategy-table test in test_extraction_pipeline.py

For every new handler, `test_extraction_pipeline.py` gains a focused test
asserting `STRATEGIES[DetectedFormat.X] is unpack_x`. This is a compile-
time guard against the registry-edit + worker-rename drifting silently —
a typo in either side fails the test before pytest even runs the worker.

- **Description:** A single-line identity test per handler that fails fast
  on any registry typo or worker rename, independent of the worker's
  internal logic.
- **Where applied:** Commit `87be59e` (initial registry tests),
  `a340e24` / `f866b2d` / `f2423f3` (per-handler additions).
- **Mechanical detection / how to apply next time:** When registering a
  handler in `STRATEGIES`, add the matching `is`-identity test in the same
  commit as the registration cut-over.
- **Companion to:** Rule #35a (router-level test discipline — same shape:
  every router gets a test file; here, every handler gets an identity test).

### 7. Sub-second pivot of stale parametrize lists during cut-overs

When a handler is registered, the `test_no_handler_formats_route_to_unpack_no_handler`
parametrize list (which previously listed that format as routing to the
sentinel worker) MUST drop the format. The lockstep tests in pattern #6
fail with the WRONG reason if the parametrize isn't updated — the test
becomes both a coverage gate and a forcing function for the cleanup.

- **Description:** Parametrized lists naming "still-unsupported formats"
  rot when handlers ship. The remaining canonical "still NONE" target
  (acronis_backup) is the safe parametrize occupant for tests that need a
  no-handler format.
- **Where applied:** Each Phase 2 handler commit group dropped its format
  from the parametrize and shifted assertions onto `acronis_backup`.
- **Mechanical detection / how to apply next time:** Grep
  `parametrize.*DetectedFormat\.` in `test_extraction_pipeline.py` when
  shipping a handler; any list mentioning the new format must be edited.
- **Companion to:** Rule #31 (broad-grep before trusting scope counts —
  same shape: stale parametrize is a hidden scope item the narrow grep
  misses).

## Key Decisions Made

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Strategy registry over `if/elif` dispatch ladder in `firmware.py` | Open-closed; per-handler isolation; testable | 6 commits, 0 follow-up refactors |
| Sentinel `unpack_no_handler` worker for unsupported formats | Uniform call shape (always returns `UnpackResult`); explicit "we saw it, can't handle it" UX | Closes the silent-failure mode for unknown formats |
| WIM via `wimlib-imagex` rather than `7z` | 7z handles WIM but loses metadata + symlinks; wimlib is the canonical tool | Round-trip fixture test confirmed metadata preservation |
| Recursive composition over flattening for Windows installer ISO | Each inner handler is independently testable; outer worker is < 100 LOC | Phase 2 handler 3 shipped in 4 commits matching the per-handler shape |
| Sequential archon dispatches (NOT parallel) | Each phase depends on the previous registry state; cross-stream sweep risk per Rule #23 | 0 cross-stream sweeps across 4 dispatches |

## Cross-Reference

- Prior session patterns: `.planning/knowledge/session-2026-05-07-multi-fix-illumisite-patterns.md`
- Strategic roadmap: `.planning/intake/multi-os-firmware-extractor-roadmap-2026-05-07.md`
- Format detection precedent: commit `35a754f` (magic-byte detection that
  feeds DetectedFormat into the dispatcher)
