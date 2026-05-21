# Anti-patterns: SBOM/vuln-scan regression Session 2a (2026-05-21)

> Extracted: 2026-05-21 evening
> Postmortem: `.planning/postmortems/postmortem-sbom-vuln-scan-session2a-2026-05-21.md`

## Failed Patterns

### 1. Edit tool silent no-op on stale read context
- **What was done:** During Fix #8-broader sweep, issued an Edit against `routers/fuzzing.py` to replace bare `asyncio.create_task` with the shared helper. Edit returned success.
- **Failure mode:** On-disk file was NOT updated. `git status` showed no staged change; `git add` was a no-op; commit happened with fuzzing.py at pre-Edit state. Only caught at Step 6 when `test_background_task_sweep::test_no_bare_asyncio_create_task_for_background_runners` flagged the surviving bare-create_task.
- **Evidence:** Postmortem "What Broke" #1. Commit `09aea97` re-applied the fix.
- **How to avoid:** After every Edit against a file in a multi-file sweep, immediately re-read the relevant line to confirm the change landed. The discipline costs ~2 seconds per edit; saves the discovery cost at batch-validation time. Alternative: rely on the Rule #46 META-CANARY (which is what caught it here — proof the canary discipline is load-bearing for sweeps).

### 2. Test fixture used wrong ORM field names (3 distinct fails)
- **What was done:** Wrote new Firmware + SbomVulnerability fixture kwargs guessing field names: `stored_path` (actual: `storage_path`), `file_hash` (actual: `sha256`), `data_source` + `fix_versions` (not on model).
- **Failure mode:** `TypeError: 'stored_path' is an invalid keyword argument for Firmware`. Caught at Step 6 pytest sweep.
- **Evidence:** Postmortem "What Broke" #2. Commit `09aea97` corrected.
- **How to avoid:** Before constructing ORM objects via kwargs in a NEW test, run `grep -E "Mapped|mapped_column" backend/app/models/<file>.py` to enumerate actual field names. Cost ~5 seconds; eliminates a recurring class of test-writing errors.

### 3. AST/text alignment test searched wrong quote-style
- **What was done:** Wrote `test_sbom_status_alignment.py` asserting `f"'{val}'"` in alembic source (single-quoted SQL fragment).
- **Failure mode:** Alembic source uses Python tuple literal `SBOM_STATUS_VALUES = ("idle", "queued", ...)` (double-quoted). The single-quoted SQL `'idle'` only appears in dynamically-constructed f-strings, NOT in the source text. Three alignment tests failed.
- **Evidence:** Postmortem "What Broke" #3. Commit `09aea97` `replace_all` corrected.
- **How to avoid:** When writing source-text greps against alembic migrations, distinguish (a) Python literal values (tuple at module scope, typically double-quoted), (b) SQL string fragments inside f-strings (single-quoted, but constructed dynamically). Grep against the tuple literal — that's the durable surface.

### 4. MagicMock attribute leakage into Pydantic str|None validation
- **What was done:** Used `_make_firmware()` factory which produces a MagicMock with auto-attributes. New endpoint reads `getattr(firmware, "detected_format", None)` — MagicMock returns a MagicMock for the attribute, not None.
- **Failure mode:** Pydantic `SbomGenerateStatusResponse.detected_format: str | None` validation fails with `Input should be a valid string [type=string_type, input_value=<MagicMock>]`.
- **Evidence:** Postmortem "What Broke" #4. Commit `09aea97` explicitly set `firmware.detected_format = None` + `firmware.device_metadata = None`.
- **How to avoid:** Long-standing test gotcha — when an endpoint reads `getattr` defaults on a mock fixture, explicitly null those attributes on the mock or the auto-attribute MagicMock leak will fail Pydantic validation. Document in any new endpoint-test scaffolding pattern.

### 5. docker cp directory-into-existing-destination nests instead of merging
- **What was done:** `docker cp /host/.../tests wairz-backend-1:/app/tests` after `/app/tests/` already existed.
- **Failure mode:** Source `tests/` added AS A SUBDIRECTORY: `/app/tests/tests/...`. Stale tests at `/app/tests/` ran; my new tests at `/app/tests/tests/` were ignored. Pytest output looked identical to the pre-cp state.
- **Evidence:** Postmortem "What Broke" #5. Fix: `rm -rf /app/tests/tests` + `docker cp .../tests/. wairz-backend-1:/app/tests/` (trailing-slash form forces content-merge).
- **How to avoid:** Rule #20 docker cp + restart workflow MUST use trailing-slash form for both src and dst whenever target dir already exists. Add to Rule #20's commentary: `docker cp host/<dir>/. container:/app/<dir>/` is the safe shape.

### 6. Pipe-induced silent exit recapitulated during Rule #24 canary
- **What was done:** Ran Rule #24 tsc canary via `npx tsc 2>&1 | tail -5; echo exit=$?` — got `exit=0` even on a known-bad TS file with a type error.
- **Failure mode:** Per Rule #35a, the pipe consumed tsc's actual exit code; `$?` captured `tail`'s exit (always 0). Identical to Session 1's catch. Documented antipattern repeating.
- **Evidence:** Step 5 frontend validation; Postmortem implicit in the canary verification.
- **How to avoid:** Always capture exit code BEFORE piping: `cmd > /tmp/out 2>&1; ec=$?; tail -3 /tmp/out`. OR use `set -o pipefail; cmd | tail -5`. The pattern was already documented in Session 1 anti-patterns — recurring proves it's a deeply-trained habit that requires explicit per-invocation discipline.

### 7. Auto-mock leaks AND wrong field names both surface at SAME pytest run
- **What was done:** Two test-fixture corrections were needed in distinct files. The same Step 6 sweep surfaced both as test failures.
- **Failure mode:** Initial diagnosis blamed the same root cause for both ("test fixture wrong") which delayed fix triage by ~2 minutes.
- **Evidence:** Postmortem "What Broke" #2 + #4.
- **How to avoid:** When N test failures all match a similar error template ("invalid keyword argument" / "validation error"), treat each as a DISTINCT diagnostic problem. Group by failing TEST not by ERROR template — the same template can hide N different bugs.
