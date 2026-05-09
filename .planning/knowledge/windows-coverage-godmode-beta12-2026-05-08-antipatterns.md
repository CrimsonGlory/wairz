# Anti-Patterns: Windows-Coverage God-Mode β.12 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta12-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `ee2abd9` (β.12a), `b67f062` (β.12b), `d2aad74` (β.12c)
> Status: 3 sub-tasks completed; campaign IN PROGRESS (β.14 cut-over remains)

This is an incremental extraction layered on top of the previous β.X
antipatterns files. Patterns already captured there are not re-stated;
this file captures only the β.12-delta failure modes.

## Anti-Patterns

### 1. Tightening a free-string schema field to a Literal alongside a CHECK extension

- **Description:** Rule #33 .c says "every new source value gets
  BOTH a Pydantic Literal AND a DB CHECK constraint". The natural
  reflex is to tighten `FindingCreate.source: str` to
  `Literal["manual", "security_audit", ..., "windows_authenticode",
  "windows_dbx_revoked"]` — promoting the existing free-string field
  to an enum. The trap: 18 legacy sources × dozens of caller sites
  across `services/`, `routers/`, `ai/tools/`. Tightening forces an
  N-file sweep AND breaks any caller that constructs `FindingCreate`
  with `source=...` from a runtime-derived string (e.g. operator-
  tagged sources, dynamic adapter outputs). Worse, the tightening
  doesn't actually help — the typo gate the rule wants is at the
  WRITE site (where the source string becomes a constant), not at
  the schema field.
- **Detection:** When extending a CHECK / enum / Literal-shaped
  invariant: count the existing call sites for the schema field.
  If `grep -rn "FindingCreate(" backend/app/ | wc -l` exceeds 10
  AND the existing field is `str` (not already a Literal), the
  tightening is high-cost and low-value. Prefer a NARROW Literal at
  the new helper's boundary.
- **Mitigation:** Add a NARROW Literal capturing only the new
  values: `WindowsFindingSource = Literal["windows_authenticode",
  "windows_dbx_revoked"]`. Use it as the type of module-level
  constants (`_SOURCE_AUTHENTICODE: WindowsFindingSource =
  "windows_authenticode"`) so the typo gate fires at definition
  time. Use it as the source field type on the helper's draft
  dataclass (`_PEFindingDraft.source: WindowsFindingSource`). The
  permissive `FindingCreate.source: str` field stays unchanged;
  legacy callers continue to work; the DB CHECK enforces the
  full allowlist as the safety floor.

### 2. Adding a new parameter to a widely-referenced function signature for purely-additive new behavior

- **Description:** When `verify_firmware_pe_chain` needs a new piece
  of context (`project_id` for the FindingService.create() path),
  the natural reflex is to add a parameter:
  `verify_firmware_pe_chain(firmware_id, project_id, db)`. The trap:
  14 existing test callers use the `(firmware_id, db)` signature.
  Adding the parameter forces a 14-file edit sweep AND introduces a
  cross-cut concern (every caller now has to know how to derive
  project_id, which is firmware-derived state). Worse, the parameter
  is REDUNDANT — the function already takes firmware_id, and
  project_id is reachable via `firmware.project_id` from one SELECT.
- **Detection:** When tempted to add a parameter to an existing
  function: check if (a) the new context is reachable from a value
  the function already takes (typically via a SELECT or a method
  call), and (b) the function has 5+ existing test callers. If both
  hold, the function-local SELECT is the right shape — the cost is
  one extra query per call, the benefit is zero caller updates.
- **Mitigation:** Function-local SELECT to derive the new context.
  β.12c added `fw = (await db.execute(select(Firmware).where(...))).
  scalar_one_or_none(); project_id = fw.project_id` inside the
  function body. All 14 existing test callers continued to work
  unchanged. New behavior was purely additive in the call graph.

### 3. DELETE without source-scope clause leaks data-loss across uninvolved sources

- **Description:** When extending a runner's re-run idempotency from
  one table to another (β.12c extended WindowsPESignature DELETE to
  Finding DELETE for re-run idempotency), the natural reflex is to
  scope the DELETE by `firmware_id` only:
  `delete(Finding).where(Finding.firmware_id == firmware_id)`. The
  trap: this nukes EVERY Finding on the firmware — including
  operator-tagged manual findings, security_audit findings,
  sbom_scan findings, etc. — every time the authenticode chain
  re-runs. The operator's triage notes silently disappear. The bug
  is invisible from a single-firmware single-source unit test
  because the test only seeds windows_* findings.
- **Detection:** When writing a DELETE in a runner's idempotency
  path: list the OTHER sources / consumers that write to the same
  table for the same scope. If the table has 5+ legitimate writers
  (Finding has 18 source values), the DELETE almost certainly needs
  a multi-column scope filter beyond the obvious `<scope_fk>` clause.
  Mechanical heuristic: the DELETE scope should match exactly what
  the runner WRITES — no narrower, no broader.
- **Mitigation:** Scope by `(firmware_id, source IN
  _RUNNER_FINDING_SOURCES)`. Ship a Rule #35b cross-source canary
  that pre-seeds an UNRELATED-source row on the same scope and
  asserts the re-run does NOT delete it. β.12c worked example:
  `test_runner_does_not_delete_unrelated_findings_on_rerun` seeds a
  `source='manual'` Finding + asserts it survives the runner's
  re-run.

### 4. Bumping schema_version on additive JSONB extensions

- **Description:** When adding a new key to a JSONB shape protected
  by a Rule #35c normalizer, the natural reflex is to bump
  `<TABLE>_<COL>_SCHEMA_VERSION` from 1 to 2 to "signal the change".
  The trap: a version bump implies a BREAKING change AND requires
  every legacy row to be re-run / re-stamped before consumers can
  trust the new shape. Additive fields are forward-compatible —
  legacy readers tolerate the absence; new readers default-handle
  the missing key. Bumping the version creates a false sense of
  obligation to migrate existing data.
- **Detection:** When extending a JSONB shape: ask whether existing
  consumers can tolerate the new key's ABSENCE on legacy rows. If
  yes (e.g. via `payload.get("new_key", default)`), the change is
  ADDITIVE; schema_version stays unchanged. If no (e.g. the new key
  is required for correct rendering), it's a breaking change and
  schema_version bumps + a backfill migration is needed.
- **Mitigation:** Document additive fields explicitly in the
  canonical-shape comment: "Optional for legacy pre-β.12 rows;
  readers should use `payload.get('findings_emitted', 0)`". Keep
  the schema_version constant unchanged. Existing
  `<schema>_version_constant` test passes without modification.
  β.12c worked example: `firmware.authenticode_chain_result` gained
  `findings_emitted` at schema_version=1.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (tightening free-string schema)** is the
  inverse of Pattern #2 (narrow boundary Literal + free-string
  field). The two reinforce each other — the negative formulation
  surfaces the trap, the positive formulation provides the
  mitigation.

- **Anti-pattern #2 (new-parameter for additive context)** is the
  inverse of Pattern #4 (self-contained derive-from-DB). Same
  shape — extend an existing function without breaking its
  signature contract.

- **Anti-pattern #3 (DELETE without source-scope)** is the
  inverse of Pattern #5 (DELETE-scope canary). The canary IS the
  durable mitigation; the source-scope clause in the DELETE is the
  proximate fix. Companion to β.11 anti-pattern #4 (naked
  WHERE id) — both are scope-discipline lessons for shared tables.

- **Anti-pattern #4 (bumping schema_version on additive)** is the
  inverse of Pattern #6 (additive JSONB at unchanged
  schema_version). Same shape — purely-additive doesn't break
  forward compatibility.
