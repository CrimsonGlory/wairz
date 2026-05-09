# Patterns: Windows-Coverage God-Mode β.7 + α.3 cleanup (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta7-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `14425e6` (β.7), `869e8ec` (α.3 cleanup)
> Status: 1 sub-task + 1 follow-up cleanup completed; campaign as a whole IN PROGRESS (β.8+ remain)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α-phase + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md` (β.5-β.6 delta)

Patterns already captured there are not re-stated; this file captures
only the β.7-delta learnings.

## Successful Patterns

### 1. Pattern #2 (verdict-field mirror) accommodates scalar-column ORM targets cleanly

- **Description:** β.5 + β.6 mapped each `dict | None` service result onto
  a single JSONB column (`arch_view`, `rich_header_json`) with a Rule
  #35c normalizer triplet. β.7's target was different — the existing
  ORM columns are scalar (`dbx_revoked: bool`, `dbx_revocation_kb:
  String(32)`), not JSONB. Pattern #4 (verdict ↔ ORM column 1:1)
  resolved the tension cleanly: the service still returns `dict |
  None`, but `_verify_with_open_file` decomposes the dict into TWO
  scalar verdict fields. No JSONB normalizer needed (Rule #35c is
  JSONB-specific). The drift-detector simply grew `direct_mapped` by
  `{dbx_revoked, dbx_revocation_kb}`.
- **Evidence:** β.7 commit `14425e6`. Decision documented in the commit
  message body: "Pattern #2 (β.5/β.6 service shape mirror): returns
  `dict | None`. The verdict-decomposition into the two scalar columns
  happens in `_verify_with_open_file` per Pattern #4 (verdict ↔ ORM
  column 1:1). No new JSONB column → no Rule #35c normalizer triplet."
  All 35 authenticode tests + 23 dbx tests pass; drift-detector enforces
  the new `direct_mapped` set.
- **Applies when:** Adding a verdict-derivable field whose target ORM
  column is scalar (not JSONB). The mechanical rule: service returns
  rich `dict | None` for internal use + future extensibility; verdict
  fields shape to ORM columns; `direct_mapped` grows by every field
  the verdict adds. The Pattern #2 template still holds — the service-
  side dict is preserved; only the verdict→column mapping shape
  differs from the JSONB case. **The Rule of Three is satisfied: β.5
  (JSONB) + β.6 (JSONB) + β.7 (scalar) all follow Pattern #2 with
  Pattern #4 as the column-shape decision boundary.** Worth promoting
  to a `.mex/patterns/add-pe-verdict-field.md` recipe with both shapes.

### 2. Module-level mtime cache for batch-verifying multiple PEs against one bundle

- **Description:** A firmware containing 1000 PE binaries triggers 1000
  Authenticode verifications, each calling `match_dbx_revocation`.
  Without caching, the 500 KB DBX bundle would be parsed 1000 times
  (~50 ms each = 50 seconds wasted). β.7's `_BUNDLE_CACHE` stores
  `(path_str, mtime, parsed_data)`; subsequent calls hit the cache as
  long as the bundle hasn't changed on disk. `reset_bundle_cache()` is
  exposed for tests + the β.10 cron-refresh path.
- **Evidence:** β.7 commit `14425e6`,
  `backend/app/services/dbx_service.py:_load_bundle`. Test
  `test_match_dbx_revocation_caches_parsed_bundle` verifies the cache
  hit produces identical parsed data on the second call.
- **Applies when:** Any service that parses a moderately-large external
  artifact and is called repeatedly against the same artifact within
  one process lifetime. The mtime gate is the durable invalidation
  signal — content-hash would be safer but ~10× more expensive on
  every call. mtime + path together close the realistic stale-data
  window; the β.10 cron explicitly resets the cache after refresh.

### 3. Curated-allowlist test-relaxation pattern for genuinely-correct exceptions

- **Description:** The α.3 follow-up — `test_capability_notes_only_for_partial_or_none`
  was failing because `WINDOWS_DRIVER_PACKAGE` legitimately needs an
  operator-hint note despite being FULL-capability. Two relaxation
  approaches: (a) drop the note (loses real UX value), (b) relax the
  test (loses the hygiene check). The chosen path: add a curated
  `operator_hint_full_exceptions` allowlist set in the test body, with
  the assertion message instructing future contributors to add to the
  set explicitly. Hygiene check survives; legitimate exception is
  documented; future drift requires conscious allowlist update.
- **Evidence:** α.3 cleanup commit `869e8ec`,
  `backend/tests/test_format_detection.py:239-263`. Test then passed.
- **Applies when:** A unit test asserts a clean invariant that
  legitimately admits a small number of exceptions. Pure relaxation
  loses the invariant's value entirely; per-case allowlists keep the
  invariant strong while documenting the exceptions inline. The
  message in the assertion teaches future contributors the right
  decision. Companion to Rule #19 (evidence-first): the exception is
  documented because the EVIDENCE — the operator-hint use case for
  WINDOWS_DRIVER_PACKAGE — supported it.

### 4. Pre-commit Rule #19 evidence sweep on multi-option design decisions

- **Description:** β.7's design-constraint #1 explicitly named two
  options: split scalar columns vs single dbx_match JSONB. Before
  writing code, the decision was made by reading the existing
  schema (columns already exist + indexed), Pattern #4 ("verdict ↔
  ORM 1:1"), and Rule #35c (JSONB-only normalizer pattern). The
  result: keep existing columns; no migration; no normalizer triplet.
  Documented in the commit message body. **Cost: ~2 minutes; the
  alternative (write code, hit migration churn, retrofit) would
  have been ~30 minutes.**
- **Evidence:** β.7 commit `14425e6` body — explicit "Design discipline"
  section with the decision and rationale. Migration history checked
  via `git log --oneline alembic/versions/` confirmed columns exist
  since `b1a2c3d4e5f6` (β.2).
- **Applies when:** Any design constraint that names multiple options
  with "decide before coding" framing. The cheap path is the
  evidence sweep — read the existing schema, the existing patterns,
  the existing tests. The decision often becomes obvious once the
  evidence is on the table. Companion to Rule #19 (evidence-first
  before remediation code) and Pattern #7 (REPL-validation before
  library use) — both are about lowering the cost of decisions
  through cheap empirical checks.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | Keep existing scalar columns (dbx_revoked + dbx_revocation_kb); no new dbx_match JSONB | Migration already exists; columns are indexed for the rollup query path; Pattern #4 verdict↔column 1:1 means verdict gets two scalar fields; Rule #35c is JSONB-specific so no normalizer triplet needed; the dict richness lives in the service for future extensibility | β.7 ships cleanly with zero migration churn; verdict + drift-detector work uniformly; β.10 (real bundle provisioning) doesn't need a schema change either |
| 2 | DBX matching happens INSIDE `_verify_with_open_file` (not at top of `verify_pe_file`) | DBX matching needs the leaf serial which only signify provides; calling matcher pre-signify would force a separate cert-extraction path; defaults (False/None) are the truthful "no DBX information" semantic for the 3 outer-error paths | All 6 plumbing tests pass cleanly; Pattern #1 four-way satisfied via dataclass defaults + explicit population in the inner verdict construction |
| 3 | Phase β.7 baseline always emits dbx_revocation_kb=None even on a true match | The dbxupdate.bin format itself doesn't embed KB strings; β.10's side-car JSON is the planned source of KB metadata; fabricating KB strings would be Rule #19 violation (no evidence) | β.7 ships with a guard test (`test_match_dbx_revocation_revocation_kb_is_none_in_phase_beta_7`) that fails if a future change accidentally fabricates a KB string before β.10 plumbs the side-car |
| 4 | _MAX_ENTRIES = 50_000 for DBX bundle parsing | 2026-era Microsoft bundles carry ~5000 entries; 50_000 is well above any plausible legitimate maximum; β.6 _MAX_ENTRIES=1000 was tuned for ~80-entry RICH headers (10× plausible-max); same 10× discipline applied here | Sanity bound documented inline; `test_parse_bundle_bytes_caps_at_max_entries` enforces the cap; bundle parsing stays bounded under malformed inputs |
| 5 | Bundle-path resolution: explicit > env (DBX_BUNDLE_PATH) > None | Tests pass an explicit path; production uses env (β.10 will set it); when neither is set, function returns None gracefully (β.10 deferral semantic — every PE ships dbx_revoked=False = truthful "no DBX info") | β.7 codes against env-or-explicit; tests cover all three paths; β.10 needs only an env-var update + cron-refresh script |
| 6 | α.3 follow-up uses curated allowlist (one entry: WINDOWS_DRIVER_PACKAGE) instead of dropping the assertion | Hygiene check still has real value (catches accidental note-on-FULL clutter); the legitimate exception is documented inline; future contributors see the discipline via the assertion message | 37 format_detection tests pass; the pre-existing α.3 inconsistency that surfaced in β.5/β.6 postmortem rec #1 is closed |

## Cross-references back into existing knowledge

- **Pattern #4 (verdict ↔ ORM column 1:1)** is the load-bearing rule for β.7's scalar-column path. Worth re-reading at every β/γ/δ verdict-extension step.
- **β.5/β.6 Pattern #2 (verdict-field-mirror discipline)** still holds; the dict-vs-scalar shape variation is accommodated by Pattern #4 without breaking the template.
- **Pattern #7 (REPL-validation)** ran cleanly 3× in β.7 — pattern is now habitual. The cost-amortisation observation (probes get faster as the operator gets more practiced) is the durable lesson.
- **Rule #35a (real-exit-code capture)** continues to backstop pytest exit codes — caught both fixture bugs immediately because the real `2 failed, 21 passed` exit was honest.
