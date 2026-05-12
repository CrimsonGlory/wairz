# Antipatterns — windows-coverage-godmode θ.D SDB walker (2026-05-12)

Antipatterns SURFACED but caught early, plus discipline reminders documented for future precedent-reuse.

## A1 — Assuming SQLite `make_live_db` enforces FK ON DELETE CASCADE

**Symptom:** A `test_sdb_entry_cascade_delete_with_firmware` test that deleted a `Firmware` row and asserted that the associated `WindowsSdbEntry` rows were also removed (because the alembic migration declares `ondelete="CASCADE"` on the FK). The test failed with `assert 1 == 0` because the SQLite shim does NOT enforce FK cascades by default.

**Root cause:** SQLite's default mode treats `ON DELETE CASCADE` as a no-op unless `PRAGMA foreign_keys = ON` is set on each connection. The `make_live_db` SQLite shim does not set this pragma; production Postgres DOES enforce the cascade.

**Caught by:** pytest at test runtime (~30 seconds debugging).

**Fix:** replaced the test with `test_sdb_entry_multiple_per_firmware_persist_independently` which tests the same kind of multi-row shape without depending on cascade semantics. The cascade IS enforced in production Postgres via the alembic migration's `ForeignKey("firmware.id", ondelete="CASCADE")` clause.

**Lesson:** the `make_live_db` SQLite shim is for column-shape validation and value-flow round-trip tests, NOT for behavioral tests that depend on Postgres-specific features (FK cascades, triggers, partial indexes, generated columns, etc.). When a test would depend on a Postgres-specific behavior, either:
1. Replace the test with one that exercises the same code path without that dependency (this session's choice).
2. Add `PRAGMA foreign_keys = ON` to the `make_live_db` setup (heavier change; defer unless cascades are critical to the test).
3. Move the test to a Postgres-backed integration suite (separate `tests/integration/` dir; doesn't run on host venv).

**Precedent check:** `test_mbr_vbr_models.py` and `test_esp_models.py` do NOT include cascade tests either, consistent with this limitation. Add a docstring note when documenting an SQLite-incompatible behavior so future precedent-reuse doesn't re-encounter it.

## A2 — Rule #35a pipe-induced silent exit code on the Rule #24 tsc canary

**Symptom:** `echo 'const x: number = "nope";' > __canary.ts && cd frontend && npx tsc -b --force 2>&1 | tail -10; rc=$?; echo "exit: $rc"` printed the type error AND `exit: 0` together, which is impossible if tsc actually exited non-zero. The pipe to `tail` discards tsc's exit status and reports `tail`'s exit (0).

**Caught by:** Rule #35a discipline. Re-ran without the pipe; got `exit=2` as expected.

**Cost:** ~5 seconds.

**Lesson:** the Rule #24 canary itself is vulnerable to the Rule #35a pipe-induced silent-exit pattern. The canary's job is to validate that tsc actually fails on a known-bad input; if the canary always reports 0 due to a pipe, it gives false confidence. **Mechanical rule:** the Rule #24 canary command should NEVER use a pipe — run `npx tsc -b --force; rc=$?` directly. If you need to truncate output, redirect to a file: `npx tsc -b --force > /tmp/out 2>&1; rc=$?; tail -5 /tmp/out`.

**Same pattern observed in θ.E** — Rule #35a + Rule #24 interaction is durable across 2+ streams. Documented in θ.E postmortem #2; reinforced here in θ.D.

## A3 — Ruff I001 import-order error on freshly-authored vendor test file

**Symptom:** `ruff check --no-cache backend/tests/test_python_sdb_vendor.py` reported `I001 Import block is un-sorted or un-formatted` — the imported names within `from third_party.python_sdb import (...)` were listed alphabetically with classes before constants, but ruff's import-sorter wanted constants before classes (alphabetical by name, no case-folding).

**Caught by:** Antipattern A6 ruff `--no-cache` per-piece discipline.

**Cost:** ~5 seconds (`ruff check --fix` auto-fixed).

**Lesson:** ruff's import sort order is stricter than human-aesthetic preferences. Always run `ruff check --fix` on freshly-authored test files before committing to avoid this mechanical fix. The Antipattern A6 discipline (per-piece `ruff check --no-cache`) catches this; the fix is non-semantic; production code is unchanged.

## A4 — Worker test file's `from third_party.python_sdb import` requires special handling because the package is under `backend/third_party/`

**Symptom (NOT encountered, but documented for future precedent-reuse):** New contributors might write `from backend.third_party.python_sdb import ...` because the file lives at `backend/third_party/python_sdb/`. This will fail at runtime because pytest's `rootdir` is `backend/` (per `pyproject.toml`); the correct import path is `from third_party.python_sdb import ...`.

**Lesson:** the wairz `backend/` directory is configured as a package root via `pyproject.toml`'s pytest config. Imports from `third_party/` should use the `third_party.<pkg>` form (no leading `backend.`). Mirror the `from third_party.pywmi_persistence_finder import ...` form documented in θ.B's WMI walker.

**Precedent check:** `backend/app/services/wmi_walker.py:167` does `from third_party.pywmi_persistence_finder import (...)`. The pattern is consistent across the codebase. Document in the vendor's ATTRIBUTION.md if there's ambiguity.

## A5 — Counting confidence on cleanup vs feature streams should be different

**Observation:** θ.D shipped with 0 reverts, 0 cross-stream sweeps, 0 critical bugs, 1 minor test rewrite (A1 above). The session was extremely clean. **The mechanical observation** is that θ.D is a 5th-application of the Pattern P1 cadence; **the qualitative observation** is that this is a CHEAP campaign because we built on top of 4 prior precedents.

**Lesson for future planning:** when proposing a 5th+ application of a well-established pattern, set the "expected wall-time" at ~30-40 min, NOT the original first-application's 2.5h. The original Phase α designs should be scoped at 2-3h (significant design work); the Nth application of the same pattern should be scoped at 30-40 min (mechanical translation). Set realistic expectations upfront so cycle-time forecasts are accurate.

**Counter-warning:** if the Nth-application starts taking 1h+, something is wrong — the precedent isn't being reused mechanically. Stop and investigate. Common causes:
- The current stream introduces a new technical challenge (e.g. binary format parsing) not present in prior precedents.
- The schema design is genuinely different (e.g. SDB needs `app_name` + `app_exe` + 7-state shim_class enum that prior walkers don't have).
- The precedent's assumptions don't hold (e.g. cascade-delete works in some shim but not the current one).

In θ.D, the schema design WAS genuinely different (more columns than θ.E) AND a vendor sub-task was added AND the cascade-delete test had to be rewritten. The wall time was 35 min — within the expected 30-40 min envelope for the Nth-application.
