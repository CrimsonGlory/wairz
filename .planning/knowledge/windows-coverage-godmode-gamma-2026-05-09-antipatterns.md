# Anti-Patterns: Windows-Coverage God-Mode γ (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase γ section)
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-gamma-2026-05-09.md`
> Branch: `feat/windows-phase-gamma-2026-05-09`
> Commits in scope: `e3e94cc..8437ae3` (γ.1 through γ.9)
> Status: 9 sub-tasks completed; campaign Phase γ CLOSED (Phase δ pending)

This is an incremental extraction layered on top of the previous γ-X
antipatterns files. Patterns already captured there are not re-stated;
this file captures only the γ-delta failure modes.

## Anti-Patterns

### 1. Pipe-trap exit-code obfuscation in shell verification — Rule-of-Two now

- **Description:** Ran the Rule #24 mandatory tsc canary as
  `npx tsc -b --force 2>&1 | tail -10; echo "EXIT=$?"`. Output
  contained `error TS2322: ...` AND `EXIT=0` simultaneously — an
  impossible combination if the exit code reflected tsc. The pipe
  subshelled the pipeline; `$?` after the pipeline reflects `tail`'s
  exit (always 0 unless the input stream errored), not tsc's. Bash
  tool does NOT enable `pipefail` by default. **This is the second
  occurrence of the audit-2026-05-04 lesson** — Rule #35a codified
  it; the recurrence was caught in seconds via the canary discipline
  itself ("error TS2322 + exit=0 simultaneously is impossible").
- **Detection:** Run any verification command DIRECTLY (no pipe) when
  capturing the exit code:
  ```sh
  cmd; ec=$?; tail -10 /tmp/cmd.log; echo "REAL EXIT=$ec"
  ```
  OR redirect to a file and read separately:
  ```sh
  cmd > /tmp/cmd.log 2>&1; ec=$?; tail -10 /tmp/cmd.log
  ```
  OR enable `set -o pipefail` explicitly + capture `${PIPESTATUS[0]}`
  after the pipeline. **Mechanical canary**: any time you see
  `error|FAILED|Traceback` in the output AND `EXIT=0` together, the
  exit code is wrong; re-run without the pipe.
- **Mitigation:** Codified rule (CLAUDE.md Rule #35a) + canary
  discipline + new harness rule
  `auto-pipe-trap-exit-code-after-tail-head` (added in this γ.9
  knowledge extraction) — flags `\| (tail|head|grep|sed|awk|cut|tee)
  .*; *echo .*\$\?` as the suspect shape. Cost is one extra
  redirection per verification; benefit is correct exit-code
  capture, no false-pass on a real failure.

### 2. "Branch off main" ambiguity when local main is stale relative to active mainline

- **Description:** γ kickoff prompt said "fresh branch off main:
  feat/windows-phase-gamma-2026-05-09". Local `main` is 5 weeks
  stale (commit `e2fd35e` from 2026-04-02); the actual mainline
  is `clean-history` (commit `5d9a404` from 2026-05-07, 705
  commits ahead of `main`). The β branch sits directly on top of
  `clean-history`. Branching γ "off main" literally would have lost
  all β infrastructure (WindowsFindingSource Literal,
  ck_findings_source CHECK extension, authenticode chain runner,
  WindowsPESignature model) — γ work depends on it.
- **Detection:** Any kickoff prompt mentioning "branch off main"
  in a multi-branch workflow needs a pre-branch sanity check:
  ```sh
  git -C <repo> log -1 main
  git -C <repo> log -1 <other-likely-mainline-branches>
  git -C <repo> merge-base main <prior-phase-branch>
  ```
  If `main` is older than the prior phase branch's parent, branching
  literally from `main` will drop the prior phase. Confirm with the
  user OR branch from the prior phase tip.
- **Mitigation:** Documented branch topology in the user-facing
  reply BEFORE making the first commit; user confirmed mid-session.
  Going forward — kickoff prompts should say "off the active
  mainline" or "off the prior phase's branch tip" explicitly to
  avoid the ambiguity. Cost: ~3 minutes of evidence-gathering;
  benefit: correct branch base, zero rework.

### 3. `async for db in make_live_db()` — wrong API form

- **Description:** First draft of `tests/test_registry_hive_walker.py`
  used `async for db in make_live_db():` per a stale recollection
  of the pattern. The actual API is `async with make_live_db() as
  db:` — `make_live_db` is decorated with `@asynccontextmanager`
  (returns `_AsyncGeneratorContextManager`), not an async generator
  yielding sessions. **Already had a harness rule for this pattern
  from a prior incident** (`auto-windows-coverage-2026-05-07-async-
  for-make-live-db`); rule didn't fire here because the test file
  was newly created and the rule fires on edit-time inspection.
- **Detection:** **pytest at fixture setup** — failed all 3 live-
  canary tests with `TypeError: 'async for' requires an object with
  __aiter__ method, got _AsyncGeneratorContextManager`. Loud +
  immediate.
- **Mitigation:** Rewrote each live-canary test to wrap its body in
  `async with make_live_db() as db:` per the
  `test_windows_pe_signature_tools.py` precedent. Future fix —
  add a `.mex/patterns/use-live-db.md` recipe so the pattern is
  visible to fresh agents at task-start time, not just at test-
  failure time. The existing harness rule provides edit-time
  enforcement once the file is being modified; the recipe doc
  covers the file-creation case.

### 4. Container has no pytest — production-only image

- **Description:** Attempted `docker compose exec -T backend
  /app/.venv/bin/pytest tests/...` for the γ.9 cut-over verification.
  The backend container is a production-only image with no pytest
  installed and no `tests/` directory mounted. `OCI runtime exec
  failed: ... stat /app/.venv/bin/pytest: no such file or directory`.
- **Detection:** **Docker exec** — failed loudly on first attempt.
- **Mitigation:** Pivoted to host-side pytest sweep (323 tests pass
  against the same source tree via the project's editable install)
  + in-container Rule #11 import smoke (model + service + tool-
  registry imports against the rebuilt container's runtime). This
  is the canonical β-precedent verification path; my expectation
  was wrong, not the infrastructure. Documented the canonical
  shape inline in the γ.9 commit message for future reference.
  No future fix needed — this is the deliberate Dockerfile
  partition (production-only image; tests run against the host
  venv).

### 5. Edit tool requires Read in same conversation turn — not just visible-in-context

- **Description:** Twice during the session, ran `Edit` against a
  file (`backend/app/models/__init__.py` and `backend/pyproject.toml`)
  without first calling `Read` on it in this conversation turn. The
  file content was visible from earlier `Bash cat` output, but the
  Edit tool's safety contract requires a Read in the conversation
  history. Edit failed with `File has not been read yet. Read it
  first before writing to it.`
- **Detection:** **Edit tool guardrail** — returned the error
  message immediately; no edit was applied.
- **Mitigation:** Read then Edit on retry. ~10 seconds per occurrence.
  Future fix — internalize that "Bash cat output" doesn't satisfy
  the Edit-tool's Read-first contract. Cheaper to Read the file
  once before any edit than to discover the gate at edit time.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (pipe-trap exit-code obfuscation)** is the second
  occurrence of the audit-2026-05-04 Rule #35a lesson. Codified rule
  + canary discipline both held — the recurrence was caught in
  seconds. Rule-of-Two now; promotable to a CI grep on the third
  application. Harness rule
  `auto-pipe-trap-exit-code-after-tail-head` added in this
  knowledge extraction to flag the syntactic shape at edit time.
- **Anti-pattern #2 (branch ambiguity)** is novel within this
  codebase. Mitigation is a kickoff-prompt template clarification
  (documentation-only), not a harness rule — kickoff prompts live
  outside the source tree.
- **Anti-pattern #3 (async-for vs async-with)** is a re-discovery
  of an already-codified pattern. The harness rule
  `auto-windows-coverage-2026-05-07-async-for-make-live-db` exists;
  it didn't fire here because the test file was newly created.
  Mitigation is a `.mex/patterns/use-live-db.md` recipe (forward-
  looking documentation for new test file creation, complementing
  the existing edit-time harness rule).
- **Anti-pattern #4 (container has no pytest)** is a re-confirmation
  of the production-only Dockerfile partition. The canonical
  verification path (host-side pytest + in-container import smoke)
  is documented in CLAUDE.md Rule #11 + Rule #8; the mistake was
  trying to bypass it. No new infrastructure needed.
- **Anti-pattern #5 (Edit tool Read-first)** is a tool-contract
  reminder. Not a harness rule (the Edit tool itself is the
  enforcement). Cheap fix going forward — Read before any first
  Edit on a file in a session.

All five anti-patterns share a common shape: **assuming a contract
without verifying it in the current scope**. #1 assumed `$?` would
reflect the first command of the pipe; #2 assumed `main` was the
active mainline; #3 assumed `make_live_db` was an async-iterator;
#4 assumed the container had pytest; #5 assumed prior Bash output
satisfied the Edit-tool Read contract. This is the test-authoring
counterpart to Rule #19's spec-vs-DB-truth discipline applied to
**tool contracts** rather than **data shapes**. The mechanical
mitigation in every case: **probe the contract once before relying
on it** — `cmd; ec=$?` for exit codes, `git log` for branch
freshness, `inspect.signature` for API forms, `ls /app/.venv/bin`
for tool availability, `Read` before `Edit`.
