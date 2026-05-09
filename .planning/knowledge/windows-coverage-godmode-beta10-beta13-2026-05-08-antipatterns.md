# Anti-patterns: Windows-Coverage God-Mode β.10 + β.13 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta10-beta13-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`

This is an incremental extraction layered on top of the previous β.X
antipatterns files. Patterns already captured there are not re-stated;
this file captures only the β.10/β.13-delta failure modes.

## Failed Patterns

### 1. `set -e` × `cmd; rc=$?` exit-trap (sibling of Rule #35a's pipe-trap)

- **What was done:** First draft of `scripts/refresh-ms-roots.sh` had
  `set -eu` at the top and used the canonical Rule #35a pattern
  `cmd > /tmp/x; rc=$?; if [ "$rc" -ne 0 ]; then …` after `curl` and
  `docker compose build`.
- **Failure mode:** Under `set -e`, `cmd` exiting non-zero causes the
  script to exit IMMEDIATELY at the cmd line — the `rc=$?` and the
  if-block NEVER run. The error-handling branch (the entire reason for
  capturing the exit code) would never fire. In the script's specific
  case, the curl failure path would die silently with no operator-facing
  message; cron would log just curl's stderr without the operator
  workflow.
- **Evidence:** β.10 commit `856b640`,
  `scripts/refresh-ms-roots.sh:104-115` (the corrected `cmd ... ||
  RC=$?` form). Caught in self-review during `bash -n` syntax check
  + reading the script back end-to-end before committing. Postmortem
  section "What Broke #2".
- **How to avoid:** When using `set -e` AND wanting to capture an
  exit code, use `cmd ... || rc=$?` (or `if ! cmd; then …`). The `||`
  form is treated as the LHS of a successful compound statement, so
  set -e doesn't trigger; rc captures the failed exit code; the
  if-block runs. The Rule #35a (a) pipe-trap and the set-e-trap are
  siblings — both intercept the exit code before `$?` reads it.
  Both are mitigated with explicit `|| rc=$?` or file-redirect
  inspection.
- **Detection:** Static check — in shell scripts containing both
  `set -e` (or `set -eu` / `set -euo pipefail`) and `rc=$?`, every
  occurrence of `rc=$?` MUST be preceded on the previous line by a
  command form ending with `|| rc=$?` OR be inside an `if cmd; then`
  block (where set -e doesn't apply to the conditional). Could be
  expressed as a static-analysis pass; harness rule candidate is
  borderline (regex would have FP rate on legitimate set-e + rc
  combos in different scope).

### 2. β.7 parser was format-blind for the canonical Microsoft asset

- **What was done:** β.7 implemented `dbx_service._parse_bundle_bytes`
  walking `EFI_SIGNATURE_LIST` from offset 0 of the bundle. The
  docstring said "A real `dbxupdate.bin` carries one or more
  `EFI_SIGNATURE_LIST` structures back-to-back" — implying the bare
  format was canonical. β.7 tested against in-memory builders that
  produce the bare shape, which is the synthetic shape β.10's
  generator-script also emits.
- **Failure mode:** Real Microsoft `DBXUpdate.bin` (the bundle ENV var
  `DBX_BUNDLE_PATH` was originally meant to point to) carries an outer
  3337-byte `EFI_VARIABLE_AUTHENTICATION_2` wrapper before the
  EFI_SIGNATURE_LIST array. β.7's parser reads those 3337 bytes as a
  malformed signature list, hits the "stop on malformed" guard
  immediately, and returns `entries_scanned=0`. Every PE the worker
  scans gets `dbx_revoked=False` regardless of actual revocation
  status — silent degradation, not a hard failure.
- **Evidence:** β.10 commit `856b640`. Discovered via the Pattern #1
  Rule #19 evidence-first probe BEFORE writing parser-extension code:
  `xxd dbxupdate.bin | head` decoded bytes 0..15 as EFI_TIME
  (year=2010 = Microsoft signing-cert validity-start), bytes 16..23
  as WIN_CERTIFICATE (dwLength=3321, wType=0x0EF1).
  `EFI_CERT_X509_GUID first offset = 0` returned EMPTY +
  `EFI_CERT_SHA256_GUID first offset = 3337` (= wrapper size exactly).
- **How to avoid:** When designing a parser for a third-party binary
  format, work against a REAL instance of the asset, not just
  synthetic fixtures. The synthetic-fixture-only path is fine for unit
  tests of internal parser logic, but the parser's TOP-LEVEL contract
  (what shape does the on-disk file have?) must be verified against
  the canonical asset. β.7 could have caught this if it had bundled a
  test instance of the real Microsoft DBX in its commit; β.10's
  evidence-first probe at the bundling step is the late-but-still-
  effective backstop.
- **Detection:** No reliable static check; the issue is a missing
  evidence-first probe at design time. Discipline-level: Rule #19
  generalised to "third-party binary format verification before
  parser commit". This antipattern's mechanical tell during code
  review: a parser docstring that says "A real X carries Y" without
  citing how Y was empirically verified is a candidate for
  evidence-first probe.

### 3. CWD drift after `cd backend/ms-anchors && …` compound

- **What was done:** `cd backend/ms-anchors && curl … && sha256sum
  dbxupdate.bin.tmp` was issued as a Bash-tool compound command. The
  `cd` left the shell's working directory inside `backend/ms-anchors/`
  for subsequent unrelated commands.
- **Failure mode:** The next Bash invocation that used a relative
  `backend/...` path failed with "No such file or directory" because
  the path was now resolved against `/home/dustin/code/wairz/
  backend/ms-anchors/backend/...`. Recovery cost ~30 seconds of
  re-orientation + switching to absolute paths.
- **Evidence:** Session transcript shows the recovery sequence:
  `pwd` → recognise CWD drift → switch to absolute paths
  (`/home/dustin/code/wairz/...`) for all subsequent commands.
- **How to avoid:** Either (a) prefer absolute paths over `cd` when
  using the Bash tool — the system instructions explicitly recommend
  this ("Try to maintain your current working directory throughout
  the session by using absolute paths"); or (b) use a subshell to
  scope the `cd`: `( cd backend/ms-anchors && do_thing )` so the cd
  doesn't leak. The subshell form is the durable mitigation when
  cd IS necessary.
- **Detection:** Bash-tool-level antipattern; no source-file regex
  catches it. Self-discipline: when issuing `cd X && ...`, the
  subshell form `( cd X && ... )` is preferred unless persistent
  CWD change is the explicit intent.

## How to avoid (cross-cutting)

- **For Anti-pattern #1:** muscle-memory of the `cmd ... || rc=$?` form
  in shell scripts under `set -e`; treat "I know about Rule #35a" as
  not equivalent to "I never trip Rule #35a"; the set-e-trap is the
  same trap with a different mechanism. Worth a one-line addition to
  Rule #35a's "How to apply" in the next CLAUDE.md editing session
  (β.13 was already focused on Rule #36 + #37 promotion per Rule #25).
- **For Anti-pattern #2:** Rule #19 evidence-first generalised to
  "format verification before parser commit". The discipline:
  download the canonical asset; parse it locally with the existing
  tooling; if entries == 0 OR shape doesn't match, run `xxd | head` +
  struct-decode of the first 64-128 bytes BEFORE writing parser
  code. Captured as Pattern #1 in `windows-coverage-godmode-beta10-beta13-2026-05-08-patterns.md`.
- **For Anti-pattern #3:** prefer absolute paths in Bash-tool
  invocations; use subshell `( cd X && ... )` form when cd is necessary.
  Generalises the system instruction's "maintain current working
  directory" guidance.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (set-e × cmd-rc trap)** is a sibling of CLAUDE.md
  Rule #35a (a) (pipe-induced exit-trap). Both intercept exit codes
  before `$?` can read them; both are mitigated with the same
  explicit-capture form. Add to Rule #35a's "How to apply" list as
  the second known exit-trap mechanism.
- **Anti-pattern #2 (parser-blind-to-canonical-format)** would have
  shipped silently if not for Pattern #1 (Rule #19 evidence-first
  generalised to format verification). The two patterns are
  inversely-paired: one is the failure mode, the other is the
  prevention. Companion to the original Rule #19 (DB-condition
  measurement before backfill code).
- **Anti-pattern #3 (CWD drift)** generalises the system instruction's
  "maintain CWD via absolute paths" guidance. The `( cd X && ... )`
  subshell form is the durable mitigation when cd IS necessary.
