---
name: increase-coverage
description: >-
  Reads current_coverage.txt at the repo root, picks a random file among the
  5 lowest-covered backend modules, adds unit/integration tests to raise its
  coverage, then rewrites that file's row (Stmts/Miss/Cover/Missing) and the
  TOTAL line to reflect the real post-test numbers. Use when asked to
  "increase coverage", "improve test coverage", or to work through
  current_coverage.txt.
---

# Increase Coverage

Picks one under-tested backend module out of the worst 5 in
`current_coverage.txt`, writes tests that exercise its uncovered lines, and
updates the report file with the measured (not guessed) result.

## Steps

### 1. Read the report and pick a target

Read `current_coverage.txt` from the repo root. Parse the table body
(skip the header, the `----` separator rows, and the `TOTAL` line).
Sort rows by `Cover` ascending, take the 5 lowest, and pick one at random.
Tell the user which file was picked and its current Stmts/Miss/Cover before
doing anything else.

Skip a candidate and re-roll from the remaining bottom-5 if the file is
already at or near 100%, is a `__init__.py` with 0 statements, or is a
thin CLI/worker entrypoint that's already flagged elsewhere as
intentionally untested (e.g. genuinely requires a live Docker/QEMU
environment with no unit-testable seam) — note the skip reason.

### 2. Read the target file and its existing test file

Read the full source of the picked `app/...py` file, paying particular
attention to the `Missing` column's line ranges — those are the uncovered
branches/functions to target. Then check whether
`backend/tests/test_<module>.py` already exists (grep
`backend/tests/` for the module name) — extend it if so, otherwise create
a new one following the existing test file conventions in that directory
(fixtures, `make_live_db`, mocking patterns per CLAUDE.md Rule #30/#35b).

### 3. Write tests for the uncovered lines

Add unit tests (mock-based, fast) for pure logic branches, and at least one
integration/live-canary test (per CLAUDE.md Rule #35b) if the file touches
persistence or a service boundary already covered by that pattern elsewhere
in the test suite. Follow CLAUDE.md's testing conventions:

- Don't test scenarios that can't happen; don't add defensive code to make
  a line "coverable" if it isn't reachable in real use.
- Where a branch is truly unreachable in practice (e.g. a defensive
  `except` for a stdlib guarantee, or an `else` branch that mirrors an
  exhaustive enum already checked elsewhere), it is acceptable to mark it
  `# pragma: no cover` **only** for that specific line/block, with a short
  comment saying why it doesn't make sense to cover. Do not scatter
  `pragma: no cover` broadly to cheaply inflate the number — every use
  must be a genuine edge case, not a shortcut around writing a test.
- Prefer the smallest set of tests that closes the real gaps in `Missing`,
  not maximal test count.

### 4. Run the full backend suite with coverage to get real numbers

Coverage numbers must reflect the whole suite, not just the new test file,
because other tests may already partially exercise the same module (and
the TOTAL line depends on the whole run). Use the same invocation as
`.github/workflows/backend-tests.yml` / CLAUDE.md Rule #1a (always via
`docker compose -f docker-compose.yml -f docker-compose.dev.yml`):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T -w /app \
  -e PYTHONPATH=/app backend /app/.venv/bin/python -m pytest tests/ \
  -v --tb=short --cov=app --cov-report=

docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T -w /app \
  backend /app/.venv/bin/python -m coverage report -m
```

If pytest/pytest-cov aren't installed in the running container yet (fresh
container, no prior CI-style install), install them first:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend \
  /app/.venv/bin/pip install --quiet pytest pytest-asyncio pytest-cov
```

Confirm the new tests actually pass and that the target file's `Cover`
percentage in this fresh report increased versus the value recorded in
`current_coverage.txt` before you started. If it didn't move, the tests
aren't exercising the intended lines — go back to step 3.

### 5. Update `current_coverage.txt` via `scripts/update_current_coverage.py`

Do not hand-edit `current_coverage.txt`. Use
`scripts/update_current_coverage.py` — it derives statement counts from
`coverage.parser.PythonParser` (matching what `coverage.py` itself
reports) instead of trusting hand-typed numbers, and enforces a lock so
concurrent runs don't corrupt the file.

From the freshly measured `coverage report -m` output, find the picked
file's row and its `Missing` column (a line-range spec like
`12-14, 40, 88-91`, or empty if fully covered). Then run:

```bash
python3 scripts/update_current_coverage.py \
  --replace-file-missing backend/app/<path>.py "<missing-spec-from-report>" \
  --write
```

`--replace-file-missing` recomputes that row's `Miss` and `Cover` from the
given line spec (empty string clears Missing entirely, i.e. fully
covered) — the script computes `Miss`/`Cover`, never type them by hand.

The `TOTAL` row is recomputed automatically from the sum of all
non-outdated rows in the file, so no separate TOTAL edit is needed unless
the freshly measured suite-wide `coverage report -m` TOTAL diverges from
that sum (e.g. files outside the scanned set changed). If it diverges,
pass the report's real totals explicitly:

```bash
python3 scripts/update_current_coverage.py \
  --replace-file-missing backend/app/<path>.py "<missing-spec>" \
  --baseline-stmts <TOTAL Stmts from report> \
  --baseline-miss <TOTAL Miss from report> \
  --write
```

If this run added a brand-new test file that isn't yet a row in
`current_coverage.txt`, add it in the same invocation with
`--add-test-file backend/tests/test_<module>.py` (statement count is
derived automatically; miss defaults to 0 since test files are expected
to be fully exercised by their own execution).

Run without `--write` first to preview the diff (it prints the full
table to stdout), confirm the picked file's row and TOTAL look right,
then re-run with `--write` to persist. Leave every other row untouched —
this skill's job is scoped to the one file it changed; the script does
not regenerate rows it wasn't told to touch.

### 6. Lint

Run the `/lint` skill's backend checks (Ruff, Bandit, async-subprocess
gate) against the new/changed test file and, if it was touched, the
target module — per CLAUDE.md Rule #53. Fix any findings before
committing; don't commit a change lint hasn't passed on.

### 7. Commit

Commit the new/updated test file and the updated `current_coverage.txt`
together in one commit (don't ask the user first — committing is part of
this skill's job, per the user's explicit instruction that this skill
should always commit its work). Stage only the specific files this run
touched (the test file + `current_coverage.txt`) — never `git add -A`.
Write a commit message describing which file's coverage was raised and
the before/after `Cover` percentage, e.g.:

```
test(fuzzing): cover app/ai/tools/fuzzing.py MCP tool handlers (6% → 96%)
```

Do not push — committing locally is as far as this skill goes unless the
user separately asks for a push.

### 8. Report

Summarize: which file was picked (and why, if others were skipped), what
tests were added and why, the before/after Stmts/Miss/Cover for that file
and for TOTAL, any `pragma: no cover` lines added with justification, the
lint result, the commit hash, and what was/wasn't validated (per
CLAUDE.md's Handoff Summary Format).
