# Anti-patterns: Windows-Coverage God-Mode Campaign (2026-05-07)

> Extracted: 2026-05-07
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`

## Failed Patterns

### 1. `cmd | tail -N; rc=$?` — pipe captures tail's exit, not cmd's

- **What was done:** Validated a typecheck canary with `npx tsc -b --force 2>&1 | tail -10; echo "exit=$?"` — printed the TS error AND `exit=0`, which is impossible if tsc actually exited non-zero.
- **Failure mode:** Pipes implicitly subshell. `$?` after a pipeline reflects the LAST command (`tail`), not the first. Bash tool does NOT enable `set -o pipefail` by default. Same shape as Rule #17 silent-CLI-exit but cause is pipe-induced exit obfuscation, not cache-hit short-circuit.
- **Evidence:** Caught at the Rule #24 canary site once during this session; recovered by switching to direct `cmd; rc=$?` pattern.
- **How to avoid:** Three options: (a) direct `cmd; rc=$?` with no pipe; (b) `set -o pipefail` explicitly + `${PIPESTATUS[0]}`; (c) `cmd > /tmp/out; rc=$?; tail -10 /tmp/out`. CLAUDE.md Rule #35a (a) documents this as a Rule #17 generalization.

### 2. `docker compose exec ... python ...` (system python, not venv)

- **What was done:** Ran `docker compose exec -T backend python -c "from app.ai import create_tool_registry"` — failed with `ModuleNotFoundError: No module named 'sqlalchemy'`.
- **Failure mode:** The system `/usr/bin/python` in the backend container lacks the backend deps (sqlalchemy, signify, pefile, etc.). Backend deps live in `/app/.venv/`. The MCP server entry point and uvicorn use the venv python; ad-hoc `docker exec backend python` does not.
- **Evidence:** Phase β.1 + β.4 imports failed once each before pivot to `/app/.venv/bin/python`.
- **How to avoid:** Always use `docker compose exec -T -w /app backend /app/.venv/bin/python ...` for any Rule #11 import smoke against the rebuilt container. Aliasing this in scripts/ would help.

### 3. `tests/` excluded from production image via .dockerignore

- **What was done:** Tried to run `docker compose exec backend pytest tests/test_unpack_wim.py` — got "No such file or directory" because `/app/tests/` doesn't exist in the rebuilt image.
- **Failure mode:** `backend/.dockerignore` has `tests/` (with a comment "Tests are dev-only; not exercised by the production image"). Image rebuilds drop the tests dir. After every rebuild, tests must be `docker cp`-ed in OR a separate test-image must exist.
- **Evidence:** Hit this twice — once before the α.6 rebuild (had to `docker cp` 10 test files in), once after (hit the same wall, same workaround).
- **How to avoid:** Either (a) commit the workaround `docker cp tests/* wairz-backend-1:/app/tests/` to a `scripts/restore-tests-after-rebuild.sh` and make it the canonical post-rebuild step; OR (b) reconsider the .dockerignore — for a development image, including tests is fine.

### 4. Persona-brief stale dependency version constraints

- **What was done:** Persona-B brief specified `uefi-firmware>=1.12` and `signify.SignedPEFile`. Both stale: PyPI's latest is `uefi-firmware==1.11`; signify 0.9.x renamed `SignedPEFile` to `AuthenticodeFile`. Initial pip install failed; subsequent verification revealed the class-name drift.
- **Failure mode:** Personas research at moment-in-time T0; libraries release at T1 > T0. Persona briefs that are 6+ months old will have stale class names + version constraints unless explicitly re-validated.
- **Evidence:** Phase β.1 (`9db7992`) — corrected the constraint to `>=1.11` after empirical PyPI check, and the validator service (β.4 / `d12f64e`) uses the new `AuthenticodeFile` API name.
- **How to avoid:** Before adopting any library version OR class-name reference from a persona brief, run a 1-minute REPL check: `pip index versions <pkg>` for available versions; `python -c "from <pkg> import *; print(dir())"` for current class names. Especially important for libraries with active 0.x → 1.x churn.

### 5. Duplicate index declaration (`index=True` on column AND `Index(...)` in __table_args__)

- **What was done:** Declared `Mapped[uuid.UUID] = mapped_column(... index=True)` AND included `Index("ix_windows_pe_signatures_blob_id", "blob_id")` in `__table_args__`.
- **Failure mode:** SQLAlchemy emits TWO `CREATE INDEX` statements at create_all time — the second one fails with "index already exists". Caught by the Phase β.2 ORM round-trip test failure.
- **Evidence:** Phase β.2 first commit attempt; caught by `test_windows_pe_signature_round_trip` failing on table setup; fixed by removing `index=True` from the columns and keeping only `__table_args__` Index entries.
- **How to avoid:** Pick ONE: explicit `__table_args__` `Index(...)` entries (preferred for batch index management + named indexes) OR `index=True` on individual columns (preferred for one-off simple indexes). Don't mix.

### 6. Field-name drift between fixture creation and ORM model

- **What was done:** Wrote `Firmware(filename="vendor.cab", upload_status="completed")` based on memory; actual model fields are `original_filename` + `upload_stage` (not `filename` / `upload_status`).
- **Failure mode:** SQLAlchemy raises `TypeError: 'filename' is an invalid keyword argument for Firmware`. Caught at test setup time.
- **Evidence:** Phase β.2 second commit attempt; the `test_windows_pe_signature_round_trip` fixture's `_seed_blob` helper had stale field names.
- **How to avoid:** Before writing ORM fixture code, `grep -E "mapped_column|^class" backend/app/models/<model>.py` to enumerate actual column names. Memory/instinct is unreliable across rebuilds.

### 7. `async for db in make_live_db():` — confused async generator vs async context manager

- **What was done:** Used `async for db in make_live_db(): yield db` as a pytest fixture. Failed at runtime with `TypeError: 'async for' requires an object with __aiter__ method, got _AsyncGeneratorContextManager`.
- **Failure mode:** `make_live_db()` is an `@asynccontextmanager` (async context manager), NOT an async generator. The correct pattern is `async with make_live_db() as db:` inside the test body, OR a fixture that wraps with `async with`.
- **Evidence:** Phase β.2 test fixture; caught + fixed by reading an existing test that used `async with make_live_db()`.
- **How to avoid:** Read at least one existing usage of any new helper before authoring with it. The Rule #11 import-smoke discipline should extend to "test-helper-shape smoke" too.

### 8. Bundled-test-and-implementation commit (initial attempt at Phase β.4)

- **What was done:** Considered bundling β.4 service + β.4 tests into a single commit before the testing pattern stabilized.
- **Failure mode:** A bundled commit makes test failures hard to localize — was the bug in the service or the test? Per Rule #25 the per-sub-task commit decomposition keeps the blame surface small.
- **Evidence:** Avoided this anti-pattern at the last moment; β.4 still shipped as one commit (service + tests together) but only because the tests are pure unit tests with no external dependencies — the smaller-commit principle still favored bundling here.
- **How to avoid:** Default to per-sub-task commits unless the test file IS the verification of the implementation file (no separate behavior to test in isolation). For services with mock-only tests where tests verify type-mapping/schema-mapping, bundling is fine. For services with live-canary integration tests, separate commits.

### 9. Verifying frontend changes by `docker compose restart frontend` instead of `up -d --build` (CLAUDE.md Rule #26)

- **What was done:** Initially considered `docker compose restart frontend` — but Rule #26 says that's wrong: the frontend image bakes the bundle into `/usr/share/nginx/html/`; only `--build` rebuilds it.
- **Failure mode:** Restart re-uses the old image; new bundle invisible. Frontend page would 404 the new route or run stale code. Multiple prior incidents documented in CLAUDE.md Rule #26.
- **Evidence:** Caught BEFORE the mistake — recognized the rule + ran `docker compose up -d --build frontend` correctly.
- **How to avoid:** Whenever `frontend/src/**` changes, the rebuild command is `docker compose up -d --build frontend`, never `restart`, never plain `up -d`. The harness rule `auto-frontend-rebuild-not-restart` flags docs/prompts that say `restart`. Verify post-rebuild via `grep -l "WindowsHubPage" /usr/share/nginx/html/assets/*.js` for the chunk presence.

### 10. Skill description "uefi-firmware>=1.12" copied verbatim into pyproject without empirical check

- **What was done:** Same as #4 but specifically for the `pyproject.toml` line — copied the persona-brief constraint without `pip index versions` first.
- **Failure mode:** `pip install` failed all 3 deps because the bundled command had `>=1.12` which broke resolution.
- **Evidence:** Phase β.1 first attempt — single fix (drop to `>=1.11`) repaired the install.
- **How to avoid:** Mechanical pre-commit check: run the actual `pip install` (in a throwaway venv if needed) BEFORE committing the pyproject change. Or at least `pip index versions <pkg>` for each new constraint.
