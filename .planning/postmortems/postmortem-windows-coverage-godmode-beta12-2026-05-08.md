# Postmortem: windows-coverage-godmode β.12

> Date: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Duration: ~50 min wall-clock (kickoff prompt → β.12c rebuild + Rule #11 smoke)
> Outcome: completed (3 sub-tasks shipped — β.12a/β.12b/β.12c; campaign as a whole still IN PROGRESS — β.14 cut-over remains)

## Summary

Shipped Phase β.12 (Findings extension) as 3 focused Rule #25 commits.
β.12a (`ee2abd9`) extended the `ck_findings_source` CHECK constraint
with `windows_authenticode` + `windows_dbx_revoked` via alembic
revision `c5b6a7d8e9f0`, bundled with the matching frontend
`FindingSource` union + `FINDING_SOURCE_CONFIG` mirror per Rule #21
(precedent: `61b147189fcf` did the same DB+frontend bundle for the
prior 6-source closure; bundling is forced by
`test_finding_source_alignment.py` which enforces strict pairwise
agreement). β.12b (`b67f062`) added the `WindowsFindingSource`
Pydantic Literal + a pure `classify_pe_verdict_findings` classifier +
the `FindingService.emit_pe_signature_findings` service method, with
the severity map from the kickoff brief: chain `revoked` /
`never_valid` → high (windows_authenticode); `unknown` & signed=True
→ medium (windows_authenticode); `valid_at_signing` / `valid_now` →
no Finding; `dbx_revoked=True` → critical (windows_dbx_revoked);
chain-revoked AND DBX-revoked → 2 rows. 14 tests landed (10
classifier-matrix + 4 Rule #35b live canaries). β.12c (`d2aad74`)
wired the helper into `verify_firmware_pe_chain` with self-contained
project_id derivation, scoped DELETE-then-emit idempotency for prior
windows_* findings, atomic per-PE flush of (signature, findings),
and `findings_emitted` plumbed through the aggregate JSONB. 8 new
live canaries (revoked-chain emission, DBX emission, double-revoked
2-row emission, clean-PE 0-row, idempotent re-run, manual-finding-
survives, atomic-with-signatures, aggregate-count). Total: +1217 LOC
across 9 files; 273-test sweep across finding/runner/normalizer
surfaces stays clean; zero reverts; zero rework cycles.

## What Broke

### 1. CWD drift after `cd backend && uv run pytest` compound

- **What happened:** `cd backend && uv run pytest tests/test_finding_service_pe_emit.py` was issued as a Bash-tool compound. The `cd` left the shell's working directory inside `/home/dustin/code/wairz/backend/`. A subsequent `git status --short backend/...` resolved the relative path against `/home/dustin/code/wairz/backend/backend/`, returning `warning: could not open directory 'backend/backend/'` + `fatal: ambiguous argument`.
- **Caught by:** Self-recognition reading the visible error message. β.10 antipattern #3 (CWD drift) had already documented this exact failure mode.
- **Cost:** ~10 sec — switched to absolute paths (`git -C /home/dustin/code/wairz status --short backend/...`) for all subsequent git invocations. No data lost; no rework needed beyond the recovery.
- **Fix:** Absolute-path discipline + `git -C <repo>` for git invocations. The β.10 antipattern's recommended subshell form `( cd X && ... )` would have been the alternative; absolute paths are simpler when the repo path is known.
- **Infrastructure created:** None. β.10's antipattern #3 already documents this; β.12 is the second occurrence. Rule-of-Two now; pattern is durable. Worth a one-line addition in the next CLAUDE.md edit: "Bash tool: prefer absolute paths over `cd X && ...` compounds; the system instructions explicitly recommend this".

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|------------------|
| Rule #19 evidence-first | Read existing Finding model + Pydantic schema + finding_service + alembic CHECK history + AuthenticodeVerdict shape + WindowsPESignature columns + `_live_db` helper + alignment-test contract BEFORE writing any new code; live DB audit `SELECT source, COUNT(*) FROM findings` confirmed zero existing windows_* rows ⇒ "extend CHECK" path, no defensive backfill | 1 | Migration shape would have been wrong (or defensively over-engineered) without the live-DB audit; alignment-test contract surfaced the frontend mirror requirement BEFORE writing the alembic migration commit; helper boundary design (narrow Literal vs global enum) surfaced from reading the 18 existing FindingSource callers |
| Rule #21 mirror discipline | `test_finding_source_alignment.py` enforces DB CHECK ↔ frontend FindingSource union ↔ FINDING_SOURCE_CONFIG keys agree; surfaced the bundling requirement for β.12a; precedent `61b147189fcf` documented the same shape | 1 | Splitting alembic + frontend into 2 commits would have left the alignment test RED for one commit; bisect would have hit the inconsistent state; bundling per Rule #25's "single-slice exception" kept the test green throughout |
| Rule #24 typecheck canary | One-shot canary verified `npx tsc -b --force` actually catches errors (canary produced TS2322 with exit 2) before trusting any "0 errors" output on real code | 1 | A silent-pass scenario (tsc cache short-circuit) would have shipped untyped frontend code; canary made the verification trustworthy across all 3 sub-tasks |
| Rule #25 per-sub-task commits | β.12a (alembic + frontend mirror) / β.12b (Pydantic + service helper) / β.12c (runner wiring) each shipped as a separate focused commit | 3 | A bundled "feat(β.12): full findings extension" commit would have meant one revert surface for three semantically-independent slices; bisect-clean lanes preserved (e.g. an issue with the runner-side DELETE scope doesn't force an alembic revert) |
| Rule #33 .c (Pydantic Literal + DB CHECK) | β.12a's CHECK extension + β.12b's `WindowsFindingSource` Literal (narrow, at the helper boundary) — both gates ship together so direct-SQL writes (cron / manual / partial-rollback) AND API-boundary typos are both caught | 1 | A CHECK-only path would have allowed "windows_authenitcode" typos to slip through tests; a Literal-only path would have allowed direct-SQL drift; the dual gate catches both |
| Rule #35a pipe-trap | Stayed clean throughout — every `cmd; rc=$?` invocation used the file-redirect pattern (`pytest ... > /tmp/p.out 2>&1; rc=$?; tail /tmp/p.out`) | 0 near-misses | Discipline maturing — Rule-of-Four across the campaign without a fifth in β.12. β.10/β.11 muscle-memory held |
| Rule #35b live canaries | 12 new live-canary tests across β.12b + β.12c — full ORM round-trips via `tests._live_db.make_live_db` seeding Project + Firmware + (sometimes) HardwareFirmwareBlob + SELECT-back of every column the helper / runner explicitly sets | 12 | Mock-only tests would have verified call-shape but not value-flow; the live canaries caught a potential `confidence=None` propagation bug that audit-2026-05-04 F-A-06 documented (β.12b's `Confidence.high` is now explicitly verified end-to-end by the live canary) |
| Cross-source-cleanup canary | `test_runner_does_not_delete_unrelated_findings_on_rerun` pre-seeds a `source='manual'` Finding on the same firmware and asserts the runner's re-run DOES NOT delete it | 1 | A DELETE without source-scope clause would have nuked every Finding on the firmware on every authenticode-chain re-run, silently destroying operator triage notes; the canary makes the data-loss boundary explicit |
| Rule #20 docker cp + alembic upgrade | Migration applied via `docker cp` of the alembic file + `alembic upgrade head` via container exec for β.12a (~30 s); full backend+worker rebuild deferred to after β.12c per Rule #27 cut-over discipline (1 rebuild covers all 3 commits) | 1 | A full rebuild per migration would have cost 3× the build time; Rule #20 fast iteration kept the loop tight without sacrificing correctness |
| Rule #11 import smoke | Post-rebuild import smoke imported every β.12 surface (`WindowsFindingSource`, `classify_pe_verdict_findings`, `_RUNNER_FINDING_SOURCES`, `verify_firmware_pe_chain`, `run_authenticode_chain_background`) inside the rebuilt container; asserted `_RUNNER_FINDING_SOURCES == {_SOURCE_AUTHENTICODE, _SOURCE_DBX_REVOKED}` (consistency invariant); ran the classifier on 3 corner cases | 1 | A stale-container scenario where the rebuild didn't actually pick up the new code would have surfaced as ImportError or AttributeError; the smoke confirmed the code-of-record matches the container's live state |
| DBX bundle lifespan probe | β.10's startup probe still logs `DBX bundle ready: path=/opt/wairz/dbxupdate.bin size=24053 mtime=...` after the rebuild | 1 | A regression that broke the DBX bundle COPY in the Dockerfile would have surfaced via the probe; β.12's rebuild confirmed β.10's invariant still holds |

## Scope Analysis

- **Planned (per kickoff prompt):** Ship 3 focused commits — β.12a alembic
  CHECK extension, β.12b Pydantic Literal + emit-from-verdict helper,
  β.12c runner wiring. Design constraints: Rule #19 evidence-first read
  of Finding model / schema / service / alignment-test contract; Rule
  #19 live-DB audit of existing source values; Rule #25 per-sub-task
  commits; Rule #33 .c (DB CHECK + Pydantic Literal); Rule #35b live
  canary per sub-task; Rule #20 fast iteration for the migration;
  severity-map evidence-first reading of existing Severity / Confidence
  enums; Rule #35a (a) file-redirect discipline.
- **Built:** 3 commits — β.12a (alembic migration `c5b6a7d8e9f0` + frontend
  FindingSource union + FINDING_SOURCE_CONFIG mirror, 1 commit per
  Rule #21 bundling) + β.12b (`WindowsFindingSource` Literal in
  schema + `classify_pe_verdict_findings` pure classifier + evidence-
  format helpers + `FindingService.emit_pe_signature_findings` method
  + 14 tests) + β.12c (runner wiring with self-contained project_id
  derivation, scoped DELETE-then-emit idempotency, atomic per-PE
  flush, `findings_emitted` aggregate plumbing, JSONB normalizer
  canonical-shape doc update, 8 new live canaries).
  - β.12a: 114 LOC alembic migration + 5 LOC frontend (FindingSource
    union + FINDING_SOURCE_CONFIG entries + ShieldCheck import).
  - β.12b: 10 LOC schema + 230 LOC service + 381 LOC tests = 621 LOC.
  - β.12c: 92 LOC runner + 7 LOC normalizer doc + 381 LOC tests = 480
    LOC.
- **Drift:** Zero scope drift. Kickoff prompt's 3-sub-task plan held
  exactly; no scope expansion beyond the design constraints. β.11's
  positive +1 commit drift (Rule #19 surfaced missing backend
  endpoints) had no analog in β.12 — every backend artefact β.12
  needed (Finding model, FindingService, AuthenticodeVerdict,
  authenticode_chain_runner) was already in tree from β.4–β.10.

## Patterns

- **Rule #21 mirror bundling for tri-aligned enums (DB ↔ FE union ↔
  config).** When `test_finding_source_alignment.py` enforces strict
  pairwise agreement across DB CHECK, FE TypeScript union, and FE
  config object keys, splitting the CHECK extension from the frontend
  mirror leaves the alignment test RED between commits. Rule #25's
  "default to per-sub-task commits but bundle when single-slice"
  exception clause covers this. β.12a is the second worked example
  after `61b147189fcf` — Rule-of-Two; pattern is durable. **Action:**
  Promote a one-line addition to Rule #25's "Exception" clause in the
  next CLAUDE.md edit: "When a cross-stack alignment test enforces
  pairwise agreement across N surfaces, the multi-surface change is
  single-slice — bundle in one commit". Bundle with the next rule-
  promotion commit per Rule #25 per-sub-task discipline.

- **Narrow boundary Literal + free-string field for Rule #33 .c.**
  The naïve read of Rule #33 .c is "tighten the schema field to a
  Literal". The right read is "Literal at the typo gate, schema
  field stays permissive". β.12b's `WindowsFindingSource` covers
  only the new sources; `FindingCreate.source: str` stays unchanged.
  The DB CHECK enforces the full allowlist; the narrow Literal
  catches β.12-emit typos at definition time. Pattern is new
  (Rule-of-One) within this codebase; promotable to a clarification
  on Rule #33 .c text in the next CLAUDE.md edit.

- **Pure-classifier + service-method split for emit-from-verdict
  helpers.** β.12b's `classify_pe_verdict_findings` (pure, no DB)
  + `FindingService.emit_pe_signature_findings` (service method,
  iterates drafts + persists) is now Rule-of-Two with
  `unpack_audit_service`'s emit helpers (audit-2026-05-04). Test
  surface splits cleanly: 10 classifier corner-case unit tests
  (~0.1 s) + 4 live canaries (~1 s) = 14 tests in 1.15 s.
  **Action:** Promote to a `.mex/patterns/emit-from-verdict.md`
  recipe on the third application (likely β.14 cut-over or future
  γ work).

- **Self-contained derive-from-DB to preserve test signatures.**
  β.12c's `verify_firmware_pe_chain` derives `project_id` from a
  function-local SELECT rather than adding a new parameter that
  would force a 14-test sweep. Rule-of-Two within this codebase
  (cve_match.background_runner is the precedent). Pattern is durable
  and aligns with Rule #25's bisect-clean discipline — keeping
  signatures stable preserves the per-commit revert surface.

- **DELETE-scope canary for re-run idempotency on shared tables.**
  β.12c's `test_runner_does_not_delete_unrelated_findings_on_rerun`
  pre-seeds an unrelated-source Finding + asserts re-run survives
  it. The discipline generalises beyond Findings to ANY shared
  table where a runner needs scoped DELETE-then-emit idempotency
  (sbom_vulnerabilities, analysis_cache, future tables). **Action:**
  No new infrastructure — the canary IS the durable mitigation. Add
  a one-line note to `.mex/patterns/INDEX.md` on the next pattern-
  index edit: "DELETE-scope canary: pre-seed unrelated-scope row;
  assert re-run survives".

- **Additive JSONB at unchanged schema_version.** β.12c's
  `findings_emitted` is purely-additive on
  `firmware.authenticode_chain_result`; readers use
  `payload.get("findings_emitted", 0)` for legacy rows;
  schema_version stays at 1. Rule-of-Three within this codebase
  (arch_view β.5, rich_header_json β.6, authenticode_chain_result
  β.12c) — pattern is durable; no formulation needed beyond the
  Rule #35c normalizer discipline.

- **Rule #25 per-sub-task commits is now Rule-of-Nine across this
  campaign.** β.5/β.6/β.7/β.8/β.9/β.10/β.11/β.12/β.13 each shipped
  per-sub-task commits with no `--no-verify` and no `--amend`. The
  discipline is durable; no new infrastructure needed.

- **Rule #35b live canary is now Rule-of-Nine across this campaign.**
  β.12 added 12 new live canaries (4 in `test_finding_service_pe_emit.py`
  + 8 in `test_authenticode_chain_runner.py`). Cumulative ~75 live
  canaries across β.4 through β.12. Discipline is durable.

- **CWD drift recurrence (Rule-of-Two).** β.10 antipattern #3 was
  the first; β.12 reproduced once during the post-test git-status
  sweep. Recovery via absolute paths (`git -C /home/dustin/code/wairz`)
  was instant. **Action:** Worth a one-line CLAUDE.md addition next
  edit: "Bash-tool: prefer absolute paths; `cd` compounds leak into
  subsequent commands". Companion to the system-instructions guidance
  that's already in place.

## Recommendations

1. **β.14 cut-over in a fresh session** — domain shifts to the
   final integration: real Win11 ISO upload, end-to-end
   `POST /authenticode-chain` → poll → SELECT both sigs and
   findings, frontend rebuild for FINDING_SOURCE_CONFIG entries,
   manual UI verification of windows_authenticode / windows_dbx_revoked
   badges in FindingsList. β.12's Python context doesn't help β.14's
   integration testing — fresh session keeps cache warm for the new
   focus.

2. **Bundle the deferred frontend rebuild with β.14.** β.12a's
   `FINDING_SOURCE_CONFIG` mirror is in the commit but no live
   bundle has been built; β.11 patterns #3 says "one rebuild covers
   multiple additive frontend commits" and β.14 will likely touch
   frontend. Combining the rebuild into β.14 saves a cycle. Pre-
   rebuild, the live UI shows windows_* findings as the manual /
   default badge; post-rebuild, the proper Authenticode + DBX
   Revoked badges render.

3. **Promote 3 candidate rule additions in the next CLAUDE.md
   edit, bundled per Rule #25.** (a) Rule #25 single-slice exception
   for cross-stack alignment tests (worked examples: `61b147189fcf`
   + β.12a). (b) Rule #33 .c clarification: "Pydantic Literal at the
   typo gate, NOT necessarily on the permissive schema field"
   (worked example: β.12b's `WindowsFindingSource`). (c) Bash-tool
   absolute-path discipline (β.10 + β.12 incidents). All three are
   sub-clauses of existing rules and follow the Rule #36/#37
   "worked-example-first" promotion shape.

4. **Activate the deferred Rule #35b real-firmware canary set in
   β.14.** Per the β.10 + β.11 postmortem rec #2 chain: every β-phase
   sub-task to date has shipped with synthetic / fixture-only
   verdict tests. β.12 added 12 live canaries against in-memory
   SQLite seeded fixtures. β.14 should ship with at least one real-
   firmware run: a Win11 ISO upload → `POST /authenticode-chain`
   → poll completion → assert (a) WindowsPESignature row count > 0,
   (b) Finding row count for windows_* sources > 0, (c) chain status
   histogram non-empty, (d) at least one PE chains cleanly to MS
   Authenticode roots (real signify + bundled DBX cooperation).

5. **Optional sidebar entry for /findings filtered by windows_*
   sources.** Currently FindingsList shows all sources mixed; an
   operator looking specifically at PE-hardening verdicts filters
   manually. A sidebar entry "Windows Verdicts" linking to
   `/findings?source=windows_authenticode,windows_dbx_revoked` would
   surface the new sources directly. Out of β.12 scope; worth doing
   in β.14 as a small additive frontend commit alongside the
   rebuild.

## Numbers

| Metric | Value |
|--------|-------|
| Sub-tasks planned (this session) | 3 (β.12a alembic + frontend mirror; β.12b Pydantic + service helper; β.12c runner wiring) |
| Sub-tasks completed | 3 |
| Commits | 3 (`ee2abd9` β.12a, `b67f062` β.12b, `d2aad74` β.12c) |
| Files added | 3 (alembic migration, test_finding_service_pe_emit.py, β.12 patterns + antipatterns + postmortem files) |
| Files modified | 6 (backend: schemas/finding.py, services/finding_service.py, services/authenticode_chain_runner.py, services/jsonb_normalizers.py, tests/test_authenticode_chain_runner.py; frontend: types/index.ts, constants/statusConfig.ts) |
| Total LOC delta | +1217 / -3 (β.12a +118; β.12b +621; β.12c +480) |
| Tests added | 22 (10 classifier-matrix + 4 emit-helper live canaries in β.12b; 8 runner live canaries in β.12c) |
| Tests passing (sweep) | 273 / 273 across test_finding_service / test_finding_service_pe_emit / test_finding_source_alignment / test_finding_confidence_propagation / test_findings_router / test_authenticode_service / test_jsonb_normalizers / test_authenticode_chain_runner (no regression) |
| Reverts | 0 |
| Rework cycles | 0 |
| Circuit breaker trips | 1 (CWD-drift `git status backend/backend/` failure; recovered via absolute paths; consecutive-failure counter advanced to 2 then reset on next-clean call) |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rule #11 import smoke runs | 1 (post-rebuild; imported every β.12 surface + classifier 3-corner case + runner-source consistency invariant) |
| Rule #20 docker cp iterations | 1 (β.12a alembic file + alembic upgrade head; pre-rebuild) |
| Rule #20 / Rule #8 backend+worker rebuild cycles | 1 (after β.12c per Rule #27 cut-over discipline) |
| Rule #25 commits | 3 (one per sub-task, all bisect-clean) |
| Rule #19 evidence-first applications | 4 (Finding model + Pydantic schema + finding_service.create() path; live-DB audit of existing source values; ck_findings_source CHECK history; AuthenticodeVerdict shape + WindowsPESignature columns + _live_db helper + alignment-test contract) |
| Rule #21 mirror bundle commits | 1 (β.12a alembic + frontend mirror in one commit) |
| Rule #33 .c (CHECK + Literal) gate ships | 1 (DB CHECK in β.12a, narrow Literal in β.12b — both ship together) |
| Rule #35a `cmd; rc=$?` patterns | ~20 (pytest, tsc, alembic, docker compose, psql) |
| Rule #35a near-miss recoveries | 0 (file-redirect discipline held throughout) |
| Rule #35b live canaries added | 12 (4 in test_finding_service_pe_emit + 8 in test_authenticode_chain_runner β.12c additions) |
| CWD drift recoveries | 1 (post-test git-status sweep; recovered via `git -C /home/dustin/code/wairz`) |
| Tool registry growth | +0 (no new MCP tools — β.12 is service + runner + DB) |
| Discipline slips | 0 (no `--no-verify`; no `--amend`; bare `git commit -m` per β-phase precedent now Rule-of-Nine) |

---HANDOFF---
- Postmortem: windows-coverage-godmode β.12
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-beta12-2026-05-08.md
- Failures documented: 1 (CWD drift recurrence; recovered instantly via absolute paths)
- Safety catches: 11 (Rule #19 × 4 evidence-first reads + 1 live-DB audit; Rule #21 mirror bundling; Rule #24 typecheck canary; Rule #25 commits × 3; Rule #33 .c dual gate; Rule #35a discipline; Rule #35b live canary × 12; cross-source-cleanup canary; Rule #20 docker cp + Rule #8 rebuild + Rule #11 smoke; DBX bundle lifespan probe survives rebuild)
- Recommendations: 5
---

Run `/learn windows-coverage-godmode-beta12` to extract patterns into the knowledge base.
