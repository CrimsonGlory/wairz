# Patterns: Windows-Coverage God-Mode β.11 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta11-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `7d6b0a3` (β.11a backend pe-signatures REST), `ad6ed75` (β.11b PeHardeningPage + API client + WindowsHubPage link), `939b17f` (β.11c AuthenticodeDetailPage)
> Status: 3 sub-tasks completed; campaign IN PROGRESS (β.12 + β.14 remain)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the β.11-delta learnings.

## Successful Patterns

### 1. Rule #19 evidence-first applies to user-prompt assumptions about backend state

- **Description:** When a user prompt or campaign brief makes an
  assumption about backend artefacts ("GET on the persisted
  WindowsPESignature rows is also sub-second" — implying REST
  endpoints exist), grep the codebase BEFORE writing code that depends
  on those artefacts. The 5-second
  `grep -rn "WindowsPESignature\|pe-signature" backend/app/routers/`
  surfaces missing endpoints / wrong field names / different return
  shapes that would otherwise produce 404s, AttributeErrors, or
  shape-mismatch bugs at first use. β.11 found that β.9 had only
  shipped MCP tools for `WindowsPESignature` access, never REST
  endpoints; the user prompt assumed REST endpoints existed; the grep
  surfaced the gap and reframed the commit shape from "2 frontend"
  to "1 backend + 2 frontend = 3 commits" upfront.
- **Evidence:** β.11a commit `7d6b0a3`. Postmortem section "What
  Broke #1": single grep returned empty for the assumed backend
  endpoints; 10 min of upfront scope-rework saved 30+ min of
  post-frontend-build "why does the page 404" debugging.
- **Applies when:** Any user prompt or PRD that assumes backend
  state — endpoint existence, function signatures, schema shape,
  config presence, environment variables, file paths. Mechanical
  discipline: enumerate every BACKEND-FACT the prompt depends on,
  grep each one, document deltas BEFORE writing dependent code.
  Generalises from "spec describes intent; data describes truth"
  (Rule #19 original) to "spec describes intent; codebase describes
  reality". Companion to Rule #22's "grep all sites first" for
  multi-file migrations and Rule #31's "broadest-reasonable grep
  width" for scope-count audits. Promotion candidate: a one-line
  Rule #19 sub-clause "evidence-first applies to user-prompt
  assumptions too" — bundle with the next CLAUDE.md edit per Rule
  #25 per-sub-task discipline.

### 2. List-vs-detail JSONB split for verdict-bearing rows

- **Description:** When a table has both compact-scan columns
  (signed / chain_status / signer / leaf_serial — small, indexed,
  scanned 50+ at a time) AND heavy JSONB payloads (chain_json /
  arch_view / rich_header_json — variable-size, single-row drill-in),
  ship two endpoint shapes: a paginated LIST endpoint that returns
  compact summaries with PRESENCE FLAGS for the JSONB columns
  (`arch_view_present: bool`, `rich_header_present: bool`), and a
  per-row DETAIL endpoint that returns the full JSONB payload. The
  list-endpoint cost stays ~constant per row regardless of how big
  the JSONB columns get; the detail endpoint pays the serialisation
  cost only for one row at a time when the operator drills in.
  Mirrors the existing `HardwareFirmwareBlobResponse` (compact list)
  vs the per-blob detail in HardwareFirmwarePage; β.11a applies the
  same shape to `WindowsPESignatureSummary` vs
  `WindowsPESignatureDetail`.
- **Evidence:** β.11a commit `7d6b0a3`. The list-shape Pydantic
  schema explicitly drops `chain_json` / `arch_view` /
  `rich_header_json` and adds `arch_view_present` /
  `rich_header_present` boolean derived flags. The detail shape
  carries every column. Live-canary test
  `test_list_and_get_pe_signature_round_trip` asserts
  `assert "chain_json" not in row` on the list response and
  `assert detail["chain_json"] == {...}` on the detail response —
  the split is part of the contract, not an accidental optimisation.
- **Applies when:** Any new ORM table with N <= 10 small columns +
  M >= 1 JSONB columns where (a) the list shape will be rendered as
  a per-row table view, and (b) the JSONB columns are operator
  drill-in fields, not always-displayed metadata. The mechanical
  discipline: 2 Pydantic schemas (Summary + Detail), 2 router
  endpoints (`GET /<resource>` + `GET /<resource>/{id}`), the
  list response's row schema explicitly omits JSONB columns and
  carries `<jsonb_col>_present: bool` flags. Companion to Rule #29
  (axios timeout discipline — list endpoint must stay sub-second
  even at 1000+ rows) and the existing `HardwareFirmwareBlobResponse`
  precedent. Worth a `.mex/patterns/INDEX.md` recipe for "add
  list+detail endpoints for a JSONB-bearing table" alongside the
  existing add-router-test recipe.

### 3. One-rebuild-covers-multiple-frontend-commits when commits are additive lazy chunks

- **Description:** When two or more frontend commits each ship a
  new lazy-loaded route + page + (optional) shared API client
  additions, a single `docker compose up -d --build frontend` after
  the LAST commit covers all of them. The intermediate commits don't
  need their own rebuild because (a) they don't change runtime
  behaviour for users on existing routes, and (b) typecheck +
  chunk-content inspection on the final bundle verifies all
  contributions in one cycle. Rule #26's discipline ("any change
  under frontend/src/** requires `docker compose up -d --build
  frontend`") still applies — the rebuild MUST happen — but the
  rebuild can serve multiple commits.
- **Evidence:** β.11b + β.11c shipped under one rebuild
  (`bbcb673d76…` image). Bundle hash `index-nVdBG55s.js` refreshed
  cleanly; lazy chunks `PeHardeningPage-C5X95bqK.js` (14868 B) and
  `AuthenticodeDetailPage-Dld5Xiby.js` (11508 B) both contain
  expected strings (`PE Hardening Dashboard`, `authenticode-chain`,
  `chain_status`, `Authenticode chain`, `RICH header`, `Bimorphic`,
  `signer_subject`). Companion API client chunk
  `hardwareFirmware-D6erNDAQ.js` carries all four new endpoint
  paths.
- **Applies when:** Sequential frontend commits that are (a) each
  Rule #25-shape independently revertable; (b) additive (new lazy
  chunks, not edits to a shared component); (c) typecheck-clean
  individually. Not applicable when commits modify a shared
  component or change runtime behaviour for existing routes — there
  the per-commit rebuild discipline is the safer path. Pattern is
  now Rule-of-Two: β.10 + β.13 used one backend rebuild for two
  commits; β.11 reproduces on the frontend.

### 4. Cross-firmware isolation canary at the JOIN boundary

- **Description:** When a per-firmware-scoped resource is retrievable
  by id (e.g. `GET /pe-signatures/{signature_id}`), the database
  JOIN that scopes the resource to the resolved firmware MUST be
  exercised by a test that seeds TWO firmwares (A + B) and asks for
  firmware B's resource id while resolved to firmware A — expecting
  404, not the row. Without this canary, a missing AND-clause on
  the JOIN allows cross-firmware id-guess exfiltration: any
  authenticated user with access to project P can iterate
  `pe-signature` UUIDs and pull rows from any firmware in P. The
  canary is mechanically cheap (~30 LOC) and protects a security
  boundary that's invisible from a single-firmware unit test.
- **Evidence:** β.11a's `test_get_signature_belonging_to_other_
  firmware_returns_404` seeds Project + 2 Firmwares + 1 blob on
  fw_b + 1 signature on fw_b's blob through `make_live_db`,
  overrides the resolved firmware to fw_a, and asserts the GET
  returns 404. The router's
  `where(WindowsPESignature.id == signature_id,
  HardwareFirmwareBlob.firmware_id == firmware.id)` AND-clause is
  the durable gate; the test makes the gate explicit and
  regression-resistant.
- **Applies when:** Any new per-firmware-scoped GET-by-id endpoint
  (Phase γ `windows_drivers/{driver_id}`,
  `windows_registry_extracts/{extract_id}`, etc.). Mechanical
  discipline: every such endpoint ships with a 2-firmware
  isolation canary in its test file. Companion to Rule #1
  (sandbox path-traversal prevention — same shape: a security
  boundary made explicit through the test, not just the
  implementation) and the existing
  `test_symlink_to_outside_is_rejected` precedent in the
  hardware-firmware router tests.

### 5. `Record<UnionType, Meta>` exhaustiveness with `?? FALLBACK` defense at lookup sites

- **Description:** When a TypeScript page renders a backend enum
  (here: `WindowsPEChainStatus = 'valid_at_signing' | 'valid_now' |
  'revoked' | 'never_valid' | 'unknown'`), declare a single
  `Record<UnionType, MetaShape>` that maps every value to its
  display metadata (label / description / badgeClass / icon /
  priority). At every lookup site, use the `?? CHAIN_STATUS_META.unknown`
  fallback so a backend deploy that adds a new enum value (without
  a frontend deploy) renders as "unknown" rather than crashing
  React with a blank page. Rule #9 codifies this; β.11b + β.11c
  apply it consistently across both new pages.
- **Evidence:** β.11b `PeHardeningPage.tsx:CHAIN_STATUS_META` +
  β.11c `AuthenticodeDetailPage.tsx:CHAIN_STATUS_META` (kept
  inline rather than extracted to a shared module — see anti-pattern
  #1 below). Both pages: `const meta = CHAIN_STATUS_META[status]
  ?? CHAIN_STATUS_META.unknown`. The TypeScript `Record<>` type
  guarantees every union member has an entry at compile time;
  the `??` fallback guarantees runtime resilience to backend
  drift.
- **Applies when:** Any TypeScript page rendering a backend
  string-enum or `Literal[...]` union. Companion to Rule #9 (the
  rule itself) and to the existing
  `frontend/src/types/firmware.ts:DETECTION_SOURCE_META` precedent.
  No new infrastructure — the discipline IS Rule #9.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | β.11a backend REST endpoints land BEFORE β.11b/β.11c frontend | Rule #19 evidence-first surfaced missing endpoints; user prompt assumed they existed; frontend pages would 404 without them | 3 clean Rule #25 commits in dependency order; bisect-clean lanes preserved |
| 2 | List endpoint returns presence flags (arch_view_present / rich_header_present), not the JSONB payload itself | Cost-saving for table fan-out (Win11 ISO ~1000 PEs × ~10KB JSONB = 10MB list response); operator drills into detail for one row at a time | Live-canary asserts the split is contractual (`assert "arch_view" not in list_row`); detail endpoint returns the JSONB payloads cleanly |
| 3 | Detail endpoint JOINs HardwareFirmwareBlob.firmware_id == resolved_firmware.id (cross-firmware isolation) | A naked WHERE id == signature_id allows id-guess exfiltration across firmware in the same project; the AND-clause makes the security boundary explicit | Cross-firmware isolation canary in test file; a regression of the AND-clause flips the canary red |
| 4 | Single `docker compose up -d --build frontend` covers β.11b + β.11c, not per-commit | Both frontend commits are additive lazy chunks; intermediate rebuild has no observable user-facing effect; chunk-content inspection on final bundle verifies both | One rebuild cycle (~30 sec); both chunks confirmed to contain expected strings |
| 5 | CHAIN_STATUS_META kept inline in both PeHardeningPage AND AuthenticodeDetailPage, NOT extracted to a shared module | Two consumers; differ in icon size + render scale (badge vs hero); shared module would add an import surface for ~30 LOC each. Promote on third consumer per Rule of Three | Inline copies stay aligned; no premature shared-module abstraction; β.12 / β.14 work doesn't touch the meta map |
| 6 | RICH header detail render is a structured table (not just JSON) | Operators want to scan toolchain entries quickly (comp_id × build_number × product_id × instances); raw JSON view is also available behind a collapsible | Detail page reads cleanly for operators familiar with RICH header analysis; JSON fallback for any RICH shape variant the structured render doesn't handle |
| 7 | Aggregate cards source from `firmware.authenticode_chain_result` JSONB, not a separate aggregate-recompute query | β.8's runner persists the aggregate atomically with the row writes; reading from `authenticode_chain_result` survives a page reload (operator's last-run summary doesn't disappear on F5) | PeHardeningPage's StatCard array renders correctly even before the user clicks "Run authenticode chain" — shows the last persisted aggregate or zeroes |
| 8 | Per-PE table click-through targets `/pe-hardening/{signature_id}`, not `/pe-hardening/{blob_id}` | Signature row id is the natural primary key for the detail view; a single blob has at most one signature row but the URL signature_id is what the API expects | Frontend URL matches backend route shape; detail page receives signature_id directly via useParams |
| 9 | "Run authenticode chain" button polls every 2s with a 30-min deadline | Mirrors HardwareFirmwarePage's cve-match polling; 2s strikes a balance between responsiveness and DB-read pressure; 30-min deadline well past expected ~1-3 min Win11 ISO walk | UX is consistent across the campaign's 202+poll surfaces (cve-match, fuzzing, emulation, authenticode-chain) |

## Cross-references back into existing knowledge

- **Pattern #1 (Rule #19 evidence-first generalised to user-prompt
  assumptions)** is the FOURTH application of Rule #19 to a different
  problem shape (DB conditions / source-tree iteration columns /
  third-party binary formats / user-prompt backend assumptions).
  The pattern's generalisation is durable — Rule #19 is "the data
  describes truth; the spec/intake/prompt describes intent; check
  the data first". Worth a one-line addition to Rule #19's "How to
  apply" section in the next CLAUDE.md edit.

- **Pattern #2 (list-vs-detail JSONB split)** is Rule-of-Two within
  this codebase: HardwareFirmwarePage's blob list (compact response)
  vs blob detail endpoint (full metadata) was the first; β.11a's
  pe-signature list vs detail is the second. Worth promoting to a
  `.mex/patterns/add-list-detail-jsonb-endpoints.md` recipe when
  Phase γ's `windows_drivers` or `windows_registry_extracts`
  reproduces the shape (Rule of Three).

- **Pattern #3 (one-rebuild-covers-multiple-frontend-commits)**
  generalises β.10's backend-rebuild-covers-two-commits to the
  frontend. The shape doesn't depend on backend-vs-frontend — it
  depends on commit additivity. Pattern is now Rule-of-Two; durable.

- **Pattern #4 (cross-firmware isolation canary)** is the second
  durable security-boundary canary in the campaign after β.7's DBX
  shape-detection fixture pair. Both protect security boundaries
  invisible from single-fixture unit tests. Worth a generalised
  formulation: "every per-resource-scoped GET-by-id endpoint ships
  with a 2-resource isolation canary".

- **Pattern #5 (Record<> + ?? fallback)** is the durable Rule #9
  worked example. β.11 reinforced it across two new pages. No new
  formulation needed.

- **Rule #25 per-sub-task commits** held under back-to-back
  execution AGAIN — β.11 shipped 3 commits, just as β.10 + β.13
  shipped 2, β.8 + β.9 shipped 2, and β.5/β.6/β.7 shipped 1 each
  in their own sessions. Pattern is now Rule-of-Eight across the
  campaign (β.5/β.6/β.7/β.8/β.9/β.10/β.11/β.13). The discipline is
  durable; no new infrastructure needed.

- **Rule #35a pipe-trap reproducibility** is Rule-of-Four within
  this campaign (β.8 + β.9 + β.10 sibling variant + β.11 reproduced
  pattern (a)). The lesson reinforces: knowing about Rule #35a
  doesn't prevent it; muscle memory of the file-redirect pattern is
  the durable response. No new infrastructure.

- **Rule #35b live canary** is Rule-of-Eight across the campaign.
  Cumulative ~50 live canaries across β.4 through β.11. Discipline
  is durable; pattern doesn't need additional enforcement.
