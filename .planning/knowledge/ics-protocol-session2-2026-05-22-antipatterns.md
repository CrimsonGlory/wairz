# Anti-patterns: ICS Protocol Catalog — Session 2

> Extracted: 2026-05-22
> Campaign: direct-shipped (no campaign file); kickoff at
> `.planning/research/ics-protocol-session2-2026-05-22/SESSION-2-KICKOFF.md`
> Postmortem: `.planning/postmortems/postmortem-ics-protocol-session2-2026-05-22.md`

## Failed Patterns

### 1. Alembic revision ID collision via casual hex picking
- **What was done:** Picked `e7f8a9b0c1d2` as alembic revision ID without
  grepping versions/ directory first. The same ID existed at
  `e7f8a9b0c1d2_extend_findings_source_powershell.py`.
- **Failure mode:** `alembic upgrade head` raised "Multiple head
  revisions are present for given argument 'head'" — both revisions
  shared the same ID; the chain was bifurcated.
- **Evidence:** Phase 1.A first-attempt fail; immediate alembic load
  error.
- **How to avoid:** Before picking an alembic revision ID, grep
  `backend/alembic/versions/*.py` for the candidate:
  `grep -h "^revision: " backend/alembic/versions/*.py | grep <id>`.
  If any hit returned, pick a different ID. Renamed to
  `1c52a4b5c6d7` (mnemonic "1c5 = ICS Session 2") on retry.

### 2. `//` line comment with apostrophe inside FINDING_SOURCE_CONFIG body
- **What was done:** Phase 2 added a 5-line `//` comment block inside
  the `FINDING_SOURCE_CONFIG` object literal in
  `frontend/src/constants/statusConfig.ts`. The comment contained
  `"Network's existing hues"` (apostrophe).
- **Failure mode:** `test_finding_source_alignment._balanced_object_body`
  parser doesn't handle `//` line comments. It saw the apostrophe as
  an unmatched string-open and emitted "unbalanced braces" error.
  Worse: even after rephrasing to avoid the apostrophe, the parser
  treated the 5-line comment block as part of the buf — the next
  comma's regex-match started at the comment's `/` char and missed
  the actual `ics_modbus_tcp_detected` key, causing
  `test_finding_source_config_is_exhaustive` to flag the key as
  missing from FINDING_SOURCE_CONFIG.
- **Evidence:** Host-side alignment test failure with "unbalanced
  braces" then "ics_modbus_tcp_detected missing".
- **How to avoid:** Do NOT add `//` line comments inside the
  `FINDING_SOURCE_CONFIG` object body. Either: (a) put comments
  outside the map literal; (b) refactor the alignment test's
  `_balanced_object_body` parser to handle JS comments (would
  require a real JS parser, not regex); (c) accept the constraint
  and write self-explanatory entry names. Fix: removed the comment
  block; the entry names + Network icon are self-explanatory.

### 3. Cross-protocol matrix tests written before per-protocol split
- **What was done:** Initially wrote all DNP3 + S7Comm + cross-protocol
  matrix tests in a single file
  `test_ics_protocol_dnp3_s7comm_e2e.py`. Per Rule #25 per-piece, Phase
  5 was supposed to split into 5.A (DNP3) + 5.B (S7Comm).
- **Failure mode:** Cross-protocol matrix tests require BOTH YAMLs
  present. If 5.A's tests live in the dnp3-s7comm file, then either
  (a) 5.A's commit lands without the matrix tests (incomplete) OR
  (b) the matrix tests reference s7comm YAML that doesn't exist yet
  (broken in commit 5.A; only green after 5.B).
- **Evidence:** Discovered during commit splitting between 5.A + 5.B.
- **How to avoid:** When per-protocol Rule #25 commits include
  cross-protocol matrix tests, the matrix tests belong with the LAST
  YAML to land. Split the test file: `test_ics_protocol_dnp3_e2e.py`
  carries dnp3-only tests (ships in 5.A); `test_ics_protocol_dnp3_s7comm_e2e.py`
  carries s7comm-only + matrix tests (ships in 5.B). This way 5.A is
  bisect-clean (no broken cross-protocol references) and 5.B
  introduces the matrix once both YAMLs exist.

### 4. Pipe-induced silent exit on Rule #24 canary (Rule #35a recurrence)
- **What was done:** First Rule #24 canary attempt used
  `npx tsc -b --force 2>&1 | tail -5; canary_exit=$?` to capture exit
  code while piping output through `tail`.
- **Failure mode:** Bash's `$?` after a pipeline returns the LAST
  command's exit code (i.e. `tail`), NOT the pipeline's first
  command. The pipe-induced silent-exit attack (Rule #35a) caught
  before but the lesson didn't immediately stick at canary-writing
  time. Exit code reported as 0 despite tsc emitting a real TS2322
  error.
- **Evidence:** Phase 2 Rule #24 canary print: `canary exit: 0 (should
  be NON-zero)` — the bracket comment self-flagged the impossibility.
- **How to avoid:** Per Rule #35a — when capturing an exit code, NEVER
  pipe. Either: (a) run command without pipe, capture `$?` directly;
  (b) use `set -o pipefail` explicitly; (c) capture with
  `${PIPESTATUS[0]}` after the pipeline. Re-ran canary without pipe;
  got expected exit 2. **Rule #35a is durable; the canary at canary-
  writing time is a recurring failure surface — be vigilant.**

## Companion Notes

**All 4 anti-patterns were caught at design/test time** with 0
production impact. No reverts, no operator-visible regressions.
Validates the W2-β + Rule #46 paired META-CANARY discipline + Rule
#25 per-piece commit cadence (catches issues before they accumulate).

**Anti-pattern severity distribution:** 4 LOW (all dev-time
mechanical mistakes; mechanical-canary catches all 4 within minutes).
No HIGH or CRITICAL anti-patterns surfaced in this session — the
W2-β + Wave-1 C catalog of 19 §SC5-NEW-ICS-S2 attacks were all
addressed by inline mitigations rather than learn-from-failure
incidents.

**Rule #21 backfill action item:** file_format_catalog uses the
bare-dict shape; same §SC5-NEW-ICS-S2-α attack surface exists
there. Backfill to MappingProxyType + closure-capture hardening
is queued in Phase 6 postmortem recommendations as a Rule #21
mirror sweep.
