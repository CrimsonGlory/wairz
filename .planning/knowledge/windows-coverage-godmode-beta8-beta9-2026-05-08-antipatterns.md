# Anti-patterns: Windows-Coverage God-Mode β.8 + β.9 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta8-beta9-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`

This is an incremental extraction layered on:
- `windows-coverage-godmode-2026-05-07-antipatterns.md` (α + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-antipatterns.md` (β.5-β.6)
- `windows-coverage-godmode-beta7-2026-05-08-antipatterns.md` (β.7 + α.3)

Patterns already captured there are not re-stated; this file captures
only the β.8/β.9-delta failures.

## Failed Patterns

### 1. Substring-collision in test-fixture discriminator names

- **What was done:** β.8's first attempt at
  `test_verify_firmware_pe_chain_persists_one_row_per_pe` used filenames
  `signed.exe` and `unsigned.dll`, then branched the fake_verify with
  `if "signed" in path:` to return signed-vs-unsigned verdicts. The
  substring `"signed"` matches BOTH filenames (the literal `"signed"` is
  inside `"unsigned.dll"`), so both PEs took the signed branch and the
  test asserted 2 signed rows when it expected 1.
- **Failure mode:** When fixture names share a substring with a branch
  predicate, the predicate is wrong for at least one fixture. The test
  passed at the `db.add.call_count == 2` shape but failed at the
  value-flow assertion (`len([r for r in rows if r.signed is True]) ==
  1`). A mock-only test would have shipped the bug silently — both
  rows DID get added; the bug was that they had the wrong verdict.
- **Evidence:** β.8 commit `70274c3` post-test-fixture-rename. Test
  re-run cycle ~1 minute. The bug surfaced at the SELECT-back-and-
  count phase of the live canary (Rule #35b), which is exactly the
  layer mocks structurally cannot catch.
- **How to avoid:** Two complementary disciplines: (a) **never use
  substring matchers for fixture discrimination when the fixture
  names share substrings**. Use `endswith()`, exact filename match,
  or unrelated discriminator names (e.g. `trusted.exe` vs
  `vendor.dll` — no shared substrings). (b) **The Rule #35b live
  canary IS the durable backstop**. Mocks verify dispatch shape
  ("X was called twice"); live canaries verify value flow ("X was
  called twice with the right args AND the persisted rows have the
  right values"). When designing fixtures for a value-flow test,
  either pick non-overlapping discriminators OR use a more robust
  predicate (`endswith` instead of `in`). Both fixes are cheap; the
  combination eliminates this failure mode.

### 2. Pipe-induced false `pytest_rc=0` — Rule #35a (a) reproduced once

- **What was done:** First pytest validation in β.8 used
  `docker compose exec ... pytest tests/test_authenticode_chain_runner.py
  -v --tb=short 2>&1 | tail -80; rc=$?; echo "pytest_rc=$rc"`. Output
  showed `1 failed, 15 passed` AND `pytest_rc=0` simultaneously, which
  is impossible if pytest's exit reflects the failure.
- **Failure mode:** Bash pipes implicitly subshell. `$?` after a
  pipeline reflects the LAST command (`tail`), not the first
  (`pytest`). The Bash tool does NOT enable `set -o pipefail`. This
  IS Rule #35a (a) — already documented in CLAUDE.md from session
  2026-05-04. Knowing about the rule did not prevent the trap;
  muscle memory had drifted.
- **Evidence:** β.8 session transcript: first invocation showed the
  contradictory output; same response switched all subsequent pytest
  runs to file-redirect (`cmd > /tmp/runner-test.out 2>&1; rc=$?;
  tail -30 /tmp/runner-test.out`). Five+ subsequent invocations
  passed cleanly with `real_pytest_rc=0` corresponding to actual
  pytest success.
- **How to avoid:** **When capturing $?, don't pipe.** The three
  options remain (a) direct `cmd; rc=$?` with no pipe; (b)
  `set -o pipefail` explicitly + `${PIPESTATUS[0]}`; (c)
  `cmd > /tmp/out; rc=$?; tail -10 /tmp/out`. The third is the
  cleanest for the typical "I want to see the tail of the output AND
  the exit code" workflow. **The lesson here isn't "learn Rule #35a"
  (already known) — it's that knowing the rule doesn't prevent the
  trap when you're focused on something else (test fixture bug,
  type error, etc.). The durable response is muscle memory: type
  `> /tmp/x; rc=$?` reflexively, not `| tail; rc=$?`**. No new
  infrastructure needed; Rule #35a (a) IS the rule.

## Notes — failures considered but not captured

- **No DRY-violation tipping point on parser plumbing in β.8.** β.5/β.6
  antipatterns noted the four-path verdict plumbing was at ~12 lines of
  redundancy by β.6 + projecting β.7 might push it over. β.7 stayed
  bounded (dbx fields default to scalar False/None — no replication
  needed). β.8 added NO new four-path plumbing; the `verify_pe_file`
  contract was stable. The DRY watch is still appropriate but β.8 +
  β.9 didn't trip it.

- **β.9's positive scope drift is documented in the commit message,
  not flagged as a failure.** PRD said "6 tools incl. {4 named}";
  β.9 shipped 4 named + 2 DB-read companions. The "incl." framing
  was correctly read as "more than 4 tools"; the operator-workflow
  argument for read tools is sound (write-only-via-async-runner is
  not a complete category). Documented in the postmortem's Scope
  Analysis as positive drift, not as a deviation.

- **The β.5/β.6 antipattern about deferred live canary applies
  symmetrically to β.8 + β.9.** Both ship with mock-only tests +
  Rule #35b live canaries against SQLite-shimmed ORM. Real-PE
  canary work is gated on β.10 bundle provisioning + β.14 cut-over.
  Per the β.7 antipattern note, this is documented deferral, not
  failure.

- **`test_authenticode_service.py` modification was non-trivial but
  shipped as part of the β.8 commit, not a separate cleanup.** The
  drift-detector test was refactored to import DIRECT_MAPPED from
  the runner. Per Rule #25, this could have been argued as a
  separate "test cleanup" commit, but the test's behavior change is
  load-bearing on the β.8 contract (single source of truth) — so
  bundling it into the β.8 commit is correct. The test commit
  message section in `70274c3` documents the refactor.
