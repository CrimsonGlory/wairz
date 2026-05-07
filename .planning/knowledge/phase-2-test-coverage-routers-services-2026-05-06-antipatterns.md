# Anti-patterns: Phase 2 Test Coverage Backfill — Through Wave 7

> Extracted: 2026-05-07 (initial — Waves 1-5)
> Last updated: 2026-05-07 (Wave 6 — entry 7; Wave 7 — entries 8-9)
> Campaign: .planning/campaigns/phase-2-test-coverage-routers-services-2026-05-06.md

## Failed Patterns

### 1. Bare-string JSONB `server_default` round-trips through SQLite double-decoder
- **What was done:** Wrote tests that called `make_live_db()` against models with `server_default="'[]'"` or `server_default="'{}'"` (bare-string SQL DEFAULT) on JSONB columns.
- **Failure mode:** `JSONDecodeError: Expecting value: line 1 column 1 (char 0)` at flush time. The SQLite dialect's JSON processor at sqlite/base.py:1045 wraps SQLAlchemy's `json_deserializer` (sqltypes.py:2820) on top of the column-type-level result processor. Combined with `_live_db.py`'s explicit JSONB.bind/result_processor, the round-trip produced a double-decode chain that bombed on bare-string defaults.
- **Evidence:** Wave 1 EmulationSession.port_forwards (worked around with explicit `port_forwards=[]` in 14 test sites). Wave 2 FuzzingCampaign.config + .stats hit the SAME shape; the workaround would have spread.
- **How to avoid:** Hardened in commit `080c10d`: render JSONB / ARRAY as TEXT in SQLite DDL (NOT JSON, which triggers the dialect-level processor), AND pass a tolerant `json_deserializer` to the engine that strips outer single-quotes (the SQL-string-literal artefact). Future tests don't need per-construct workarounds. Production-side: prefer `server_default=text("'[]'")` over `server_default="'[]'"` (text() expression avoids the issue entirely).

### 2. aiosqlite + `onupdate=func.now()` triggers sync refresh during Pydantic serialization
- **What was done:** PATCH-happy-path canary on `test_projects_router.py` seeded a real Project, called PATCH, expected 200 with the updated row.
- **Failure mode:** `MissingGreenlet: greenlet_spawn has not been called; can't call await_only() here.` Pydantic's response serialization is synchronous; SQLAlchemy detects that `updated_at` is "expired" after the flush (because of `onupdate=func.now()`) and tries to lazy-load — which requires async greenlet context the FastAPI test client doesn't provide on aiosqlite.
- **Evidence:** Multiple attempts to set `updated_at` explicitly didn't help; the `onupdate` trigger fires on the actual UPDATE regardless. Production runs PostgreSQL where the refresh path IS greenlet-safe.
- **How to avoid:** Skip live-canary on PATCH happy paths whose response model includes `onupdate=func.now()` columns. The router's PATCH body (`model_dump(exclude_unset=True)` + setattr) is trivial enough that the 404-boundary test plus a separate live-canary on a different operation (POST/create) covers the realistic failure modes. Documented in test_projects_router.py:223.

### 3. Schema field-name mismatches (5 incidents)
- **What was done:** Drafted test request bodies using "obvious" field names from Docker SDK, generic JSON, or guessed conventions.
- **Failure mode:** 422 Unprocessable Entity at runtime; FastAPI rejects the body because Pydantic field names don't match.
- **Evidence:**
  - PortForward: tested with `{"host_port": 8080, "guest_port": 80, "protocol": "tcp"}` — schema actually uses `{"host": 8080, "guest": 80}` (no protocol). Two test sites needed fix-up.
  - KernelResponse: mocked with `{"size_bytes": 5_000_000}` — schema uses `file_size` AND requires `uploaded_at`.
  - FindingStatus: tried `{"status": "resolved"}` — enum values are `open/confirmed/false_positive/fixed`.
  - DeviceBridgeStatus: mocked with `{"reachable": True, "host": "...", "port": 9998}` — schema uses `connected`/`bridge_host`/`bridge_port`/`error`.
- **How to avoid:** Before authoring a test request body, grep the schema file (`grep -A 10 "class XRequest\|class XResponse" backend/app/schemas/<name>.py`). Cheaper than the 422 round-trip.

### 4. Lexicographic-ordering trap on auto-generated string IDs
- **What was done:** Used `select(Finding).order_by(Finding.title)` then asserted `persisted[0].title == "[M3] Allow Backup"` (assuming numeric ordering would match check_id).
- **Failure mode:** `[M14]` < `[M3]` lexicographically (character-by-character: `[`, `M`, `1` vs `[`, `M`, `3` — at position 2, `1` < `3` so `[M14...]` sorts first). Test failed with `expected '[M3] Allow Backup', got '[M14] Cleartext Traffic'`.
- **Evidence:** test_apk_scan_router.py canary on first run.
- **How to avoid:** Use title-keyed dict access (`{f.title: f for f in persisted}`) instead of positional `order_by` + index when assertions span two specific rows. Order-independent assertions are stronger AND avoid the lexicographic trap.

### 5. Lazy-imported `_cache` shipped without import in `apk_scan` bytecode endpoint
- **What was done:** Production code path that referenced `_cache.get_cached(...)` in the bytecode endpoint without importing `_cache` first. The manifest endpoint right above it imported `_cache` inside its OWN function body (`from app.services import _cache` at line 247), but Python function-scope imports don't propagate to other functions in the same module.
- **Failure mode:** `NameError: name '_cache' is not defined` on every call to the bytecode endpoint. The bug would have shipped silently to any user who ran an APK bytecode scan.
- **Evidence:** Surfaced when the new test `test_apk_scan_router.py::TestBytecodeScanHappyPath` first attempted to call the endpoint. Fix landed in commit `4a6357f` (separate from the test commit `fdd549f` per Rule #25).
- **How to avoid:** Test backfills CATCH this — the goal IS to catch latent bugs that shipped without coverage. The meta-lesson: when a router has multiple endpoints that lazy-import the same dependency in some endpoints but not others, the inconsistent ones are silent timebombs. Mechanical detection: `grep -A 5 "from app\." backend/app/routers/<name>.py | grep -c "    from"` per endpoint, then audit any endpoint that DOESN'T appear.

### 6. Wave-3-Wave-4 schema gotchas indicate triage is rule, not exception
- **What was done:** Multiple waves shipped tests that initially failed because the test author guessed at field names instead of reading the schema first.
- **Failure mode:** Each gotcha costs ~1-2 round-trips through `docker cp` + `pytest` (~30 seconds + cognitive context switch).
- **Evidence:** 5 incidents across waves 2-4 (PortForward × 2, KernelResponse, FindingStatus, DeviceBridgeStatus).
- **How to avoid:** Add `grep -A 10 "class.*Request\|class.*Response" backend/app/schemas/<name>.py` to the per-router test-authoring checklist. Cost: 1 second. Saved per incident: ~30-60 seconds + redirection cost.

### 7. Synthetic binary fixtures fail live-canary value flow silently
- **What was done:** Built minimal ELF/PE byte fixtures in test_binary_analysis_service.py initial draft — just enough header bytes (e_ident + e_type + e_machine struct) to pass `_classify_file`'s magic-byte check, written to `tmp_path` and fed to `analyze_binary`.
- **Failure mode:** `_classify_file` accepts the magic bytes (correctly identifies as ELF), but LIEF rejects the malformed program/section headers downstream and reports `binary.header.machine_type` as a raw `int` instead of a `lief.ELF.ARCH` enum. The arch-map lookup `_LIEF_ELF_ARCH_MAP.get(binary.header.machine_type)` returns `None`, every architecture-dependent assertion silently fails (test author sees `assert architecture == 'arm'` fail with `assert None == 'arm'` and assumes the test expectation is wrong, not the fixture).
- **Evidence:** 6 of 23 tests in the initial test_binary_analysis_service.py draft. Same anti-pattern applies to PE fixtures (pefile rejects minimal PE32 with no rich relocations) and Mach-O. Mechanical signature: a test asserts on `architecture`/`endianness`/`bits` after parsing a `tmp_path`-created binary file; if the test fails with `None` on what should be a "happy path", check whether the fixture is a real binary or synthetic bytes.
- **How to avoid:** Use real binaries from the test container (`/bin/ls` for x86_64 ELF; see Pattern #10). LIEF returns proper enums, the arch-map lookup succeeds, and value-flow assertions fire correctly. Synthetic bytes are appropriate ONLY for testing the magic-byte classifier itself (`_classify_file`); any test that exercises post-classification value flow MUST use a real binary.

### 8. Tight coupling between test inputs and validator branch order (Wave 7)
- **What was done:** Wrote 4 negative-path tests for `_validate_kernel_name` (kernel_service.py) using inputs `..hidden`, `../etc/passwd`, `../bad`, `../etc/passwd` and asserting `pytest.raises(ValueError, match="must not contain")`. The validator's branch order is empty → dot-prefix → slash/backslash/dotdot → regex; ALL 4 inputs trip the dot-prefix branch FIRST (because `..hidden`, `../etc/passwd`, etc. all start with `.`), which raises "must not start with '.'" — never reaching the "must not contain" branch.
- **Failure mode:** 4 tests fail with `Regex pattern did not match. Expected regex: 'must not contain'. Actual message: "Kernel name must not start with '.'"`. Confusing because the inputs LOOK like they would test path traversal; in fact they all test dot-prefix.
- **Evidence:** test_kernel_service.py first iteration (4 of 61 tests). Caught immediately because pytest's regex match shows the actual message; cost ~30 seconds of triage + 4 single-line edits.
- **How to avoid:** Before writing negative tests for a multi-branch validator, READ the validator's branch order (1 second). Construct one input per branch, with each input designed to ONLY match its target branch (no leading dot for the `..` test; no `..` for the `/` test; etc.). Generalises pattern #6 in the patterns file (schema-check before authoring): the principle is "read the production code BEFORE constructing the test inputs that depend on it".

### 9. Counting raw `<` characters in escaped-HTML output without accounting for surrounding tags (Wave 7)
- **What was done:** test_report_service.test_html_special_chars_escaped_in_label asserted `html.count("<") == 1` to prove the escaped label content didn't contain a raw `<`, expecting "only the opening `<span>` tag has a raw `<`."
- **Failure mode:** The full output is `<span ...>&lt;script&gt;</span>` — the closing `</span>` ALSO contains a raw `<`, so the count is 2, not 1. Test failed with `assert 2 == 1`.
- **Evidence:** test_report_service.py first iteration (1 of 29 tests). Caught immediately on first run.
- **How to avoid:** When asserting on the absence of unescaped content, prefer NEGATIVE assertions over count assertions: `assert "<script>" not in html` is tighter, more readable, and harder to misread than `html.count("<") == 1`. The count assertion has to walk through "what raw `<` characters appear and how many" mentally; the negative assertion just says "the dangerous string MUST NOT be there." Generalises: prefer `not in` over `count() == N` whenever the goal is "this dangerous substring is absent".
