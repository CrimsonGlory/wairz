# Anti-Patterns: Windows-Coverage God-Mode β.11 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta11-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `7d6b0a3` (β.11a), `ad6ed75` (β.11b), `939b17f` (β.11c)
> Status: 3 sub-tasks completed; campaign IN PROGRESS (β.12 + β.14 remain)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the β.11-delta anti-patterns.

## Anti-Patterns

### 1. Trusting user-prompt assumptions about backend state without grepping

- **Description:** A user-supplied prompt or PRD says "GET on the X
  resource is sub-second" or "the existing /api/v1/foo endpoint
  returns Y" — and the natural reflex is to start writing the
  consuming code (frontend page, MCP tool, integration test)
  immediately. The trap: backend artefacts the prompt assumes can
  be missing, renamed, or shaped differently. β.11's user prompt
  said "GET on the persisted WindowsPESignature rows is also sub-
  second" — implying REST endpoints exist. They didn't. Without
  evidence-first grep, the natural failure mode is: write the
  frontend page → rebuild → load page → 404 on every API call →
  back-trace to find the missing endpoint → 30+ min of
  diagnostic loop.
- **Detection:** When reading a user prompt or PRD, enumerate every
  BACKEND-FACT it assumes (endpoint paths, function signatures,
  schema fields, env vars, file paths). For each, run a focused
  grep: `grep -rn "endpoint-path\|symbol-name" backend/app/`. If
  the grep returns empty AND the dependent code would invoke the
  artefact at runtime, the prompt under-counts scope. Fix the scope
  before writing dependent code.
- **Mitigation:** Rule #19 evidence-first generalised to user-prompt
  assumptions. Mechanical discipline:
  (a) Enumerate every backend-fact the prompt depends on (typically
  3–10 items in a moderate-scope prompt).
  (b) Grep each one with the broadest reasonable pattern (Rule #31
  width discipline).
  (c) For each gap, decide: is this an INTENTIONAL prompt assumption
  to be flagged back to the user, or a SCOPE EXPANSION the dependent
  code requires? β.11 was the latter — the user clearly wanted the
  pages to work, so adding the missing endpoints was the correct
  response.
  (d) Document the scope reframe in the first commit's message + the
  postmortem. Don't silently absorb scope expansion.
  Cost: ~5 min upfront grep; saves 30+ min of "why does it 404" debug
  loop. Companion to Rule #22 (grep all sites first for multi-file
  migrations) and Rule #31 (broadest-reasonable grep width for
  scope-count audits).

### 2. Including JSONB payloads in list-endpoint response shape

- **Description:** When designing a `GET /<resource>` list endpoint
  for a table with JSONB columns, the natural reflex is to return
  the FULL row shape including JSONB payloads — copy-paste the
  detail-shape Pydantic schema as the list-shape. The trap: list
  responses fan out across hundreds of rows for verdict-bearing
  tables (Win11 23H2 ISO has ~1000 PEs after extraction); a
  10KB-per-row JSONB column produces a 10MB list response, which
  serialises slowly + ships excess bandwidth + bloats the React
  state tree. The operator drills into one row at a time anyway —
  the list-call JSONB cost has no proportional benefit.
- **Detection:** When designing a list endpoint Pydantic schema,
  check (a) the table has JSONB columns, (b) the column would
  appear in the table-row UI as PRESENCE INFO ("yes / no"), not
  as full-payload render. If both, the JSONB column belongs on
  the detail shape with a derived presence flag on the list shape.
  Mechanical heuristic: if the list rendering uses
  `arch_view_present ? 'bimorphic' : '—'`, the column belongs only
  on detail.
- **Mitigation:** Two Pydantic schemas (Summary + Detail). The
  Summary explicitly drops JSONB columns and adds boolean
  `<col>_present` flags computed from `value is not None`. The
  Detail carries every column. Two router endpoints
  (`GET /<resource>` returns Summary[]; `GET /<resource>/{id}`
  returns Detail). Rule #35b live canary asserts the split is
  contractual: `assert "<jsonb_col>" not in list_row_dict`. β.11a
  worked example: `WindowsPESignatureSummary` (presence flags) vs
  `WindowsPESignatureDetail` (full payloads).

### 3. Per-frontend-commit rebuild for additive lazy chunks

- **Description:** Rule #26 says any change under `frontend/src/**`
  requires `docker compose up -d --build frontend`. The naive read
  is "rebuild after EVERY frontend commit" — but this adds 2-3 min
  of rebuild time per commit for sequential additive work where
  each commit is independently verifiable via typecheck +
  chunk-content inspection. β.11b + β.11c are additive lazy chunks
  (each adds a new route + page that was unreachable in the
  previous commit); a per-commit rebuild adds two rebuilds for no
  observable user-facing effect.
- **Detection:** After committing N sequential frontend changes,
  check if (a) each commit is Rule #25-shape independently
  revertable; (b) commits are additive (new lazy chunks, not
  edits to a shared component) — `git diff <prev>..<this> --stat`
  shows only added files or only additive edits to App.tsx;
  (c) typecheck passes individually. If all three, ONE rebuild
  after the LAST commit covers the chain.
- **Mitigation:** Single `docker compose up -d --build frontend`
  after the last additive commit. Verify via bundle hash refresh
  + chunk-content inspection (`grep -oE 'expected-string-A|expected-string-B'
  /tmp/chunk.js | sort -u`). Don't elide the rebuild — Rule #26
  still requires the image rebuild before the runtime sees the
  new bundle. Per-commit rebuild remains the correct discipline
  when commits modify a shared component or change runtime
  behaviour for existing routes (e.g. a Sidebar.tsx edit affects
  every page).

### 4. Naked WHERE id == :id without firmware-scoping AND-clause

- **Description:** A `GET /<resource>/{id}` endpoint that
  retrieves a per-firmware-scoped row by primary key looks naturally
  written as
  `select(Resource).where(Resource.id == resource_id)`. The trap:
  this allows id-guess exfiltration across firmware in the same
  project. Any authenticated user with project access can iterate
  resource UUIDs and pull rows scoped to other firmware uploads —
  bypassing the firmware-resolver dependency that the route LOOKS
  like it scopes through.
- **Detection:** When writing a per-firmware-scoped GET-by-id
  endpoint, the WHERE clause MUST AND-combine the resource id with
  a firmware-scoping predicate that joins through the route's
  resolved firmware: `where(Resource.id == :id, ParentTable.firmware_id
  == firmware.id)`. Mechanical check: every `GET /<x>/{id}` whose
  prefix includes `{project_id}` and whose dependency stack
  includes `_resolve_firmware` MUST have at least 2 predicates in
  its WHERE clause when the resource is per-firmware-scoped.
- **Mitigation:** AND-clause the firmware-scoping predicate into
  the WHERE clause: `select(Resource, ParentTable.path)
  .join(ParentTable, ParentTable.id == Resource.parent_id)
  .where(Resource.id == resource_id,
  ParentTable.firmware_id == firmware.id)`. Ship a Rule #35b
  cross-firmware isolation canary: seed 2 firmwares (A + B) in the
  same project, override the resolved firmware to A, ask for B's
  resource id, assert 404. β.11a worked example:
  `test_get_signature_belonging_to_other_firmware_returns_404`
  enforces the boundary.

### 5. Premature shared-module extraction for 2-consumer display metadata

- **Description:** When PeHardeningPage and AuthenticodeDetailPage
  both render `WindowsPEChainStatus` enum values, the natural reflex
  is "extract `CHAIN_STATUS_META` to `frontend/src/utils/peChainStatus.ts`
  so the two pages share the source of truth". The trap: at 2
  consumers the abstraction adds an import surface for ~30 LOC
  each, locks in a single render scale (badge size / icon size)
  that the two pages render at DIFFERENT scales (list-row badge
  vs hero badge), and creates a refactor cost when the third
  consumer (Phase γ driver-detail page, perhaps) wants a different
  meta shape (driver-tier instead of chain-status). Three similar
  lines of inline copy beats a premature shared module.
- **Detection:** When tempted to extract metadata to a shared
  module, count consumers. If <= 2, keep inline. If >= 3, promote
  per Rule of Three. Companion check: do the consumers render at
  the SAME scale + use the SAME icon set? If they diverge (β.11
  case: badge in list vs hero in detail), the extraction is
  premature even at 2 consumers.
- **Mitigation:** Inline copies stay aligned via Rule #9
  exhaustiveness (Record<UnionType,...>) — TypeScript compile
  catches drift between the two copies if either omits a chain_status
  value. Promote to a shared module only when (a) >= 3 consumers,
  AND (b) all consumers render at the same scale + use the same
  icon set, AND (c) the extracted shape doesn't add render-scale
  parameters to its API (which signal the abstraction is
  premature). Companion to Rule of Three (the meta-rule) and
  CLAUDE.md "Code Size and Structure: don't add speculative
  abstractions — three similar lines beats a premature helper".

## Cross-references back into existing knowledge

- **Anti-pattern #1 (trusting user-prompt assumptions)** generalises
  the existing Rule #19 + Rule #22 + Rule #31 evidence-first /
  scope-counting / grep-width discipline to a NEW source of
  scope under-counting: the user prompt itself. Worth a Rule #19
  sub-clause promotion in the next CLAUDE.md edit.

- **Anti-pattern #2 (JSONB in list endpoint)** is the negative
  formulation of pattern #2 (list-vs-detail split). The two
  reinforce each other; either side is a valid teaching surface
  depending on which mistake an operator is about to make.

- **Anti-pattern #3 (per-commit rebuild)** is the negative
  formulation of pattern #3 (one-rebuild-covers-multiple). Both
  apply only when commits are additive lazy chunks; for shared-
  component edits, the per-commit rebuild remains the correct
  discipline (Rule #26's intent).

- **Anti-pattern #4 (naked WHERE id)** is the negative formulation
  of pattern #4 (cross-firmware isolation canary). The
  test-canary IS the durable mitigation; the AND-clause in the
  router is the proximate fix.

- **Anti-pattern #5 (premature shared module)** reinforces the
  existing CLAUDE.md "Code Size and Structure" + Rule of Three
  discipline. β.11 is the third application of the rule across
  this campaign (β.5/β.6 inlined `_decoder_helpers` rather than
  extracting; β.10 inlined `_strip_authenticated_variable_wrapper`
  in dbx_service rather than promoting to shared parser util;
  β.11 inlined CHAIN_STATUS_META in both consumer pages). The
  pattern is durable; no new formulation needed.
