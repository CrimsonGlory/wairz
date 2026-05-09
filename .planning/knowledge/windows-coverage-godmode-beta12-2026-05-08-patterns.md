# Patterns: Windows-Coverage God-Mode β.12 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta12-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `ee2abd9` (β.12a alembic CHECK + frontend mirror), `b67f062` (β.12b Pydantic Literal + emit helper), `d2aad74` (β.12c runner wiring)
> Status: 3 sub-tasks completed; campaign IN PROGRESS (β.14 cut-over remains)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta11-2026-05-08-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the β.12-delta learnings.

## Successful Patterns

### 1. Rule #21 mirror bundling for DB ↔ frontend ↔ config tri-aligned enums

- **Description:** When a DB CHECK constraint, a frontend TypeScript
  union, AND a frontend config object are GUARDED by a cross-stack
  alignment test (here: `test_finding_source_alignment.py` enforces
  `ck_findings_source` ↔ `FindingSource` union ↔ `FINDING_SOURCE_CONFIG`
  keys agree pairwise), splitting the CHECK extension from the frontend
  mirror into separate commits leaves the alignment test RED between
  commits. Rule #25's "default to per-sub-task commits but bundle when
  genuinely single-slice" applies — the alembic + frontend updates are
  mechanically inseparable. Bundle in one commit; document the bundling
  in the commit message.
- **Evidence:** β.12a commit `ee2abd9`. Three files in one commit:
  `backend/alembic/versions/c5b6a7d8e9f0_extend_findings_source_windows_verdicts.py`
  + `frontend/src/types/index.ts` (FindingSource union) +
  `frontend/src/constants/statusConfig.ts` (FINDING_SOURCE_CONFIG +
  ShieldCheck import). Precedent: `61b147189fcf_close_findings_source_drift.py`
  did the same DB+frontend bundle for the prior 6-source closure.
  Post-commit: `uv run pytest tests/test_finding_source_alignment.py`
  3/3 pass; bisect-clean (the commit is atomic — reverting it cleanly
  restores prior state).
- **Applies when:** Adding ANY value to a DB enum / CHECK / Literal /
  TypeScript union / Record-keyed config when 2+ of these surfaces
  exist for the same concept and an alignment test enforces agreement.
  Mechanical heuristic: if `grep -rn "<enum_name>" backend/ frontend/`
  surfaces 3+ source-of-truth definitions, the addition is single-slice
  and belongs in one commit. Companion to Rule #25 (per-sub-task
  commits — the "single slice exception" clause) and Rule #21 (mirror
  discipline — the "out-of-sync state rots fast" warning). Rule-of-Two
  with `61b147189fcf` precedent; promotable to a one-line addition to
  Rule #25's "Exception" sentence next time CLAUDE.md is edited.

### 2. Narrow boundary Literal + free-string field — Rule #33 .c "where the typo gate goes" subtlety

- **Description:** Rule #33 .c says "every new source value gets BOTH
  a Pydantic Literal AND a DB CHECK constraint". The naïve read is
  "tighten `FindingCreate.source: str` to `Literal[...]`" — but that
  breaks every caller passing a different source string (here: 18
  legacy sources, dozens of call sites). The right shape is a NARROW
  Literal at the new boundary (typed module-level constants used by
  the new helper), keeping the existing free-string field permissive.
  The DB CHECK catches legacy-caller drift; the narrow Literal catches
  typos at the new helper's definition site.
- **Evidence:** β.12b commit `b67f062`. `app/schemas/finding.py` adds
  `WindowsFindingSource = Literal["windows_authenticode",
  "windows_dbx_revoked"]`. `app/services/finding_service.py` defines
  `_SOURCE_AUTHENTICODE: WindowsFindingSource = "windows_authenticode"`
  (and the dbx companion). The `_PEFindingDraft.source: WindowsFindingSource`
  field carries the typo gate end-to-end. `FindingCreate.source: str`
  is unchanged — legacy callers passing
  `source="security_audit"` / `source="sbom_scan"` / etc. continue
  to work.
- **Applies when:** Adding NEW enum values to a string-typed schema
  field where (a) many legacy callers pass other values, (b) a DB
  CHECK constraint already enforces the full allowlist, (c) the new
  helper has a small, well-bounded set of values it emits. Mechanical
  discipline: the narrow Literal lives at the helper's boundary
  (function param annotation OR typed module constants OR
  `_PEFindingDraft.source` style frozen dataclass). The free-string
  field on the Pydantic schema stays permissive. Rule-of-One in this
  campaign — pattern is new; promote to Rule-of-Two on the next
  similar enum extension. Companion to Rule #33 .c (the rule)
  generalised: "Pydantic Literal at the typo-gate, NOT necessarily
  on the schema field itself".

### 3. Pure-classifier + service-method split for emit-from-verdict helpers

- **Description:** When a helper converts a verdict tuple (or any
  non-DB input) into 0–N persisted rows, split the work into:
  (a) a PURE function `classify_X(...) -> list[_DraftDataclass]`
  consuming primitive args + returning frozen dataclasses, no DB
  access; (b) a SERVICE method `emit_X(...)` that calls the pure
  classifier + iterates the drafts + persists each via the existing
  `create()` path. The classifier is unit-testable without a DB
  fixture; the service method is integration-testable via Rule #35b
  live canary. Both surfaces test ~10x faster than a single combined
  test that requires a DB session for every verdict matrix corner.
- **Evidence:** β.12b commit `b67f062`.
  `classify_pe_verdict_findings(blob_path, signed, chain_status,
  dbx_revoked, leaf_serial, signer_subject, dbx_revocation_kb) ->
  list[_PEFindingDraft]` is pure. `FindingService.emit_pe_signature_findings`
  consumes the classifier output + persists each draft via `self.create()`.
  Test split: 10 classifier tests (no DB; ~0.1 s total) + 4 live-canary
  tests (full ORM round-trip; ~1 s total). Total: 14 tests in 1.15 s.
- **Applies when:** ANY service helper that converts a non-DB input
  into 0–N persisted rows — verdict-to-finding (β.12), audit-to-finding
  (`unpack_audit_service`), CVE-match-to-finding, future
  fuzzing-crash-to-finding, etc. The mechanical signature: pure
  function returns `list[_DraftFrozenDataclass]`; service method
  iterates + persists. Companion to Rule #35b (live canary
  discipline — the live canary IS the service method's contract test).
  Rule-of-Two now: `unpack_audit_service.py:_extract_aes_key_findings`
  + `_extract_extraction_diagnostic_findings` shipped this shape under
  audit-2026-05-04; β.12b reproduces it for the verdict-to-finding case.

### 4. Self-contained derive-from-DB to preserve test signatures

- **Description:** When a function needs a NEW piece of context (here:
  `project_id` for the FindingService.create() path) but the function's
  signature is referenced by N existing test callers, prefer a
  function-local SELECT that derives the new context from a value the
  function already takes (here: SELECT firmware to read project_id),
  rather than adding a new parameter that breaks every existing caller.
  Cost: one extra SELECT per call. Benefit: zero existing tests need
  updating; the change is purely additive in the call graph.
- **Evidence:** β.12c commit `d2aad74`. `verify_firmware_pe_chain`
  signature stayed `(firmware_id: uuid.UUID, db: AsyncSession) ->
  dict[str, Any]`. The new `project_id` came from
  `(await db.execute(select(Firmware).where(...))).scalar_one_or_none()`
  inside the function body. All 14 pre-existing callers
  (`test_authenticode_chain_runner.py:228, 298, 329, 369, 398, 439,
  494, 538` etc.) continued to work without modification. The new
  per-PE work was additive only.
- **Applies when:** Adding context to an existing function whose
  signature is widely-referenced. Heuristic: if the function takes
  any value that's a DB row's primary key or foreign key, the
  function CAN derive related context via a single SELECT — and the
  cost (one query per call) is small relative to the testing-friction
  cost of a signature change. Companion to Rule #25 (per-sub-task
  commits — keeping signatures stable preserves bisect-clean lanes
  across the campaign). Rule-of-Two within this codebase:
  `cve_match.background_runner` + β.12c both apply this pattern.

### 5. DELETE-scope canary for re-run idempotency

- **Description:** When extending a runner's re-run idempotency from
  table A (here: `WindowsPESignature`) to also cover table B (here:
  `Finding` rows scoped to `source IN _RUNNER_FINDING_SOURCES`), ship
  a Rule #35b canary that pre-seeds an UNRELATED row in table B
  (e.g. a `source='manual'` Finding for the same firmware) and
  asserts the re-run does NOT delete it. Without this canary, a
  DELETE statement that's accidentally too-broad (e.g. forgetting
  the `source IN ...` clause) would silently nuke operator-tagged
  Findings on every authenticode-chain re-run — and a single-firmware
  test wouldn't catch it because there's nothing to compare against.
- **Evidence:** β.12c commit `d2aad74`,
  `test_runner_does_not_delete_unrelated_findings_on_rerun` in
  `test_authenticode_chain_runner.py`. Pre-seeds a `source='manual'`
  Finding on the same firmware → runs `verify_firmware_pe_chain` →
  asserts the manual Finding's `id` survives. Companion canary
  `test_runner_findings_idempotent_on_rerun` confirms windows_*
  Findings DO get DELETE-then-re-emitted.
- **Applies when:** Any service that scopes a DELETE by a subset of
  (table_columns) to enforce re-run idempotency on a SHARED table.
  Mechanical discipline: the test pre-seeds an unrelated row matching
  the OUTER scope (firmware_id) but NOT matching the INNER filter
  (source IN runner_sources); asserts the unrelated row survives.
  Generalisable from `Finding` to any shared table: SBOM
  vulnerabilities, analysis_cache, etc. Companion to Rule #35b
  (live canary — same shape: the canary catches a security/
  data-loss boundary that's invisible from a single-row unit test).

### 6. Additive-JSONB-field at unchanged schema_version

- **Description:** When extending a JSONB column's canonical shape
  with a new ADDITIVE key (here: `findings_emitted: int` on
  `firmware.authenticode_chain_result`), keep the schema_version
  unchanged. Readers should use `payload.get("findings_emitted", 0)`
  for legacy pre-extension rows; the default value is the
  semantic-zero for the new field. Bumping schema_version to 2 would
  imply a breaking change AND require every legacy row to be re-run
  before consumers can trust the new shape. Additive is purely
  forward-compatible.
- **Evidence:** β.12c commit `d2aad74`. `jsonb_normalizers.py` updated
  the canonical-shape comment to document `findings_emitted` as
  optional + added the "readers should use `payload.get(...)`" line.
  `FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION = 1` unchanged.
  Existing test `test_firmware_authenticode_chain_result_schema_version_constant`
  passes without modification. Future readers (frontend StatCards,
  PE-Hardening detail pages) opt in to rendering the new field via
  `result.findings_emitted ?? 0`.
- **Applies when:** Adding a new key to an existing JSONB-shape dict
  where (a) the new key has a sensible default, (b) all readers can
  tolerate its absence, (c) no existing readers depend on the
  field-list being closed. Mechanical discipline: update the canonical
  shape comment to document the field as optional + the default;
  schema_version stays the same. Companion to Rule #35c (JSONB
  normalizer discipline — additive fields are explicitly allowed
  without bumping the version). Rule-of-Three across this codebase:
  `windows_pe_signatures.arch_view` (β.5 added optional secondary
  arch fields), `windows_pe_signatures.rich_header_json` (β.6 added
  optional cluster_md5), and now `firmware.authenticode_chain_result`
  (β.12c added findings_emitted) — all kept schema_version=1 with
  additive extensions.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | β.12a bundle alembic + frontend mirror in 1 commit (not 2) | `test_finding_source_alignment.py` enforces strict DB ↔ FE agreement; splitting leaves alignment test RED between commits | 1 atomic commit; alignment test passes; bisect-clean revert restores both surfaces |
| 2 | `WindowsFindingSource` is a NARROW Literal (only β.12 emitted sources), not a globally-typed `FindingSource` Literal | Tightening `FindingCreate.source: str` would break all 18 legacy callers; narrow Literal at the helper boundary catches β.12-emit typos without disturbing legacy paths | DB CHECK enforces the full 20-source allowlist; narrow Literal catches helper-side typos at definition time; no caller updates needed |
| 3 | `verify_firmware_pe_chain` derives project_id internally via SELECT, not a new parameter | 14 existing test callers use the `(firmware_id, db)` signature; a new parameter would force a sweep update for purely-additive new behavior | All existing tests passed without change; new behavior was purely additive |
| 4 | Idempotency by DELETE-then-emit (not UPSERT or status-toggle) | Mirrors the existing `WindowsPESignature` re-run pattern; keeps the runner's mental model consistent across both row types; Findings table has no natural unique key for upsert | Re-run produces deterministic row counts; cross-source isolation canary confirms the DELETE scope is correct |
| 5 | Pure classifier + service method split for emit-from-verdict | Classifier is testable ~10x faster (no DB); 10 corner-case unit tests + 4 live canaries instead of 14 live-canaries | Test suite runs in 1.15 s for the whole 14-test file; fast iteration during development |
| 6 | `findings_emitted` is additive at schema_version=1 | Purely-additive forward-compatible field; bumping version implies breaking change + legacy-row migration | Existing schema-version test passes unchanged; readers opt in via `payload.get("findings_emitted", 0)` |
| 7 | Per-PE flush (sig + findings) on the same db.flush() | Atomic-emission contract — sigs and findings land or rollback together; mid-run abort can't leave sig-without-finding orphan rows | `test_runner_emits_findings_atomically_with_signatures` confirms both row sets present after one commit |
| 8 | DELETE prior windows_* findings BEFORE the per-PE loop, in the same transaction as the WindowsPESignature DELETE | Mirrors β.8's existing idempotency discipline; keeps both row sets in lockstep on re-run | Idempotency canary confirms 2-run end state has 1 sig + 2 findings, not 2 sigs + 4 findings |
| 9 | Frontend rebuild deferred to next frontend-touching commit (β.14 candidate) | β.11 patterns #3 — one rebuild covers multiple additive frontend commits; β.12a's mirror is purely-additive (lazy-loaded `FINDING_SOURCE_CONFIG` entries) and β.14 will likely touch frontend | Avoid a rebuild cycle for a purely-additive bundle change; β.14 will fold the rebuild |

## Cross-references back into existing knowledge

- **Pattern #1 (Rule #21 mirror bundling)** is Rule-of-Two within this
  codebase: `61b147189fcf` (close findings source drift, 2026-05-06)
  + β.12a (extend findings source for windows verdicts, 2026-05-08).
  Both bundled DB CHECK + frontend mirror in one commit because of
  `test_finding_source_alignment.py`. Rule #25's "default to split,
  bundle when single-slice" exception clause covers this; promotable
  to a one-line addition next time CLAUDE.md edits land.

- **Pattern #2 (narrow boundary Literal + free-string field)**
  refines Rule #33 .c. The rule says "every new source value gets
  BOTH a Pydantic Literal AND a DB CHECK". The naïve read tightens
  the schema field to a Literal; the right read is "Literal at the
  typo-gate, schema field stays permissive". β.12b is the worked
  example.

- **Pattern #3 (pure-classifier + service-method split)** is now
  Rule-of-Two: `unpack_audit_service` (audit-2026-05-04) +
  β.12b's `classify_pe_verdict_findings` + `emit_pe_signature_findings`.
  Pattern is durable; suggest a `.mex/patterns/emit-from-verdict.md`
  recipe on the third application.

- **Pattern #4 (self-contained derive-from-DB)** is now Rule-of-Two:
  `cve_match.background_runner` + β.12c's `verify_firmware_pe_chain`.
  Pattern is durable.

- **Pattern #5 (DELETE-scope canary)** is the security-boundary
  test pattern from β.11 (cross-firmware isolation canary)
  generalised to data-loss boundaries within a single firmware. Both
  protect invariants invisible from single-row unit tests.

- **Pattern #6 (additive JSONB at unchanged schema_version)** is
  Rule-of-Three within this codebase: `arch_view` (β.5),
  `rich_header_json` (β.6), `authenticode_chain_result` (β.12c).
  Pattern is durable; no formulation needed beyond the Rule #35c
  normalizer discipline.

- **Rule #25 per-sub-task commits** held under back-to-back
  execution AGAIN — β.12 shipped 3 commits, just as β.10 + β.13
  shipped 2, β.8 + β.9 shipped 2, β.11 shipped 3, β.5/β.6/β.7 each
  shipped 1 in their own sessions. Pattern is now Rule-of-Nine
  across the campaign (β.5/β.6/β.7/β.8/β.9/β.10/β.11/β.12/β.13).
  The discipline is durable; no new infrastructure needed.

- **Rule #35a pipe-trap reproducibility** stayed clean this session
  — file-redirect muscle memory held throughout β.12. Rule-of-Four
  across the campaign (β.8 + β.9 + β.10 sibling + β.11) without a
  fifth in β.12. Discipline maturing.

- **Rule #35b live canary** is now Rule-of-Nine across the campaign.
  Cumulative ~75 live canaries across β.4 through β.12 (β.12 added
  4 new live canaries in `test_finding_service_pe_emit.py` + 8 new
  in `test_authenticode_chain_runner.py`). Discipline durable.
