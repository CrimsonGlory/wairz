---
name: conventions
description: How code is written in Wairz — naming, file structure, async patterns, MCP handler rules, schema/model discipline, and the verify checklist derived from 34 learned rules. Load when writing new code or reviewing existing code.
triggers:
  - "convention"
  - "pattern"
  - "naming"
  - "style"
  - "how should I"
  - "what's the right way"
  - "verify"
edges:
  - target: context/architecture.md
    condition: when a convention depends on understanding the system structure (services vs routers vs tools)
  - target: context/stack.md
    condition: when a convention is tied to a specific library's idioms (SQLAlchemy, arq, Zustand)
  - target: context/mcp-tools.md
    condition: when the work touches MCP tool handlers, registry, or ToolContext
  - target: patterns/INDEX.md
    condition: when starting a common task — a pattern likely encodes these conventions
last_updated: 2026-04-30
---

# Conventions

## Naming

- **Python modules:** `snake_case.py` (`finding_service.py`, `cwe_checker_service.py`). Service files end in `_service.py`, router files named after the resource (`projects.py`, `firmware.py`).
- **Classes:** `PascalCase`. SQLAlchemy models singular (`Project`, `Firmware`, `Finding`). Pydantic schemas suffixed by role: `ProjectCreate`, `ProjectResponse`, `ProjectListResponse`, `ProjectUpdate`.
- **DB tables/columns:** plural snake_case tables (`projects`, `firmware`, `analysis_cache`), snake_case columns (`created_at`, `updated_at`, `project_id`). UUID PKs with `default=uuid.uuid4` AND `server_default=func.gen_random_uuid()` (dual default is mandatory).
- **Router endpoint functions:** suffix with `_endpoint` when they share a conceptual name with an imported service function (Learned Rule #10). E.g. `run_clamav_scan_endpoint` in router, `run_clamav_scan` in service.
- **MCP tool names:** lowercase snake_case verbs (`list_directory`, `decompile_function`, `check_known_cves`). Register via `registry.register(name=..., description=..., input_schema=..., handler=...)`.
- **Frontend files:** Pages `PascalCasePage.tsx` (e.g. `ProjectsPage.tsx`, `EmulationPage.tsx`). API clients `camelCase.ts` in `src/api/` (`projects.ts`, `apkScan.ts`, `componentMap.ts`). Stores `camelCaseStore.ts`.
- **TypeScript types:** exhaustive `Record<UnionType, Config>` maps must include every backend enum value (Learned Rule #9). Add `?? fallback` as defense in depth.

## Structure

- **Routers are thin.** Business logic lives in `app/services/<name>_service.py`. Routers import schemas from `app/schemas/`, call a service, return the Pydantic model. Never define Pydantic models inline in a router file (Learned Rule #12).
- **MCP tool handlers live under `app/ai/tools/<category>.py`.** Each category file exposes a `register_<category>_tools(registry)` function that is called from `app/ai/__init__.py::create_tool_registry`. A new category file MUST be imported + registered there, otherwise the tool is invisible.
- **ToolContext provides: `project_id`, `firmware_id`, `extracted_path`, `db` (AsyncSession), `resolve_path(path)`.** Always use `context.resolve_path()` — it calls `validate_path()` from `app/utils/sandbox.py`. Never `os.path.join(extracted_path, user_input)` directly.
- **Background work goes through arq,** not `asyncio.create_task()` detached from the request. Unpacking the initial firmware upload is the exception — it uses `asyncio.create_task()` because the endpoint returns 202 and the frontend polls.
- **Pydantic response schemas use `from_attributes=True`** (v2 replacement for `orm_mode`) when mapped directly from ORM rows.
- **Alembic migrations** auto-run on worker container start via the entrypoint `alembic upgrade head && exec arq ...`. Generate with `docker compose exec backend alembic revision --autogenerate -m "msg"`.
- **Frontend pages poll long-running operations** with `useEffect + setInterval` every 2s until status transitions. See `EmulationPage`, `FuzzingPage`, `ProjectDetailPage` for the canonical pattern.
- **Frontend API calls** go through `src/api/<resource>.ts` which wraps the single Axios instance in `src/api/client.ts`. Pages never construct Axios calls directly.

## Patterns

### MCP tool handler — `flush()`, never `commit()`

The outer MCP dispatch in `mcp_server.py` owns the transaction. Tool handlers write with `flush()` so changes are visible intra-session but roll back on exception.

```python
# Correct
async def _handle_add_finding(input: dict, context: ToolContext) -> str:
    finding = Finding(project_id=context.project_id, **input)
    context.db.add(finding)
    await context.db.flush()
    return f"Created finding {finding.id}"

# Wrong — commits break transaction ownership and bypass rollback
await context.db.commit()
```

### Async DB access — never `gather()` coroutines sharing a session

`AsyncSession` is NOT safe for concurrent coroutine access (Learned Rule #7). Sequential `await` or fresh session per task.

```python
# Correct — sequential
result_a = await service_a(db, ...)
result_b = await service_b(db, ...)

# Correct — independent sessions
async def worker(args):
    async with async_session_factory() as db:
        ...
await asyncio.gather(worker(a), worker(b))

# Wrong — shared session in gather, silent state corruption
await asyncio.gather(service_a(db, ...), service_b(db, ...))
```

### Sync filesystem I/O — offload to executor (Learned Rule #5)

Firmware may have 10K+ files; sync os.walk blocks the event loop.

```python
loop = asyncio.get_running_loop()
result = await loop.run_in_executor(None, sync_scan_fn, extracted_path)
```

Use `app/utils/sandbox.py::safe_walk` when walking firmware — plain `os.walk` skips symlinks that firmware relies on (`/bin → /usr/bin`).

### New Python dependency — update `pyproject.toml` in the same commit (Learned Rule #2)

Then verify in Docker: `docker compose exec backend python -c "import <module>"`. A missing dependency only surfaces on container rebuild.

## Verify Checklist

Derived from CLAUDE.md Learned Rules (canonical source).  When a
new rule lands in CLAUDE.md, update this checklist in the same
commit (Learned Rule #21).

Before presenting any code change:

- [ ] **Sandbox:** every new file read uses `context.resolve_path()` (MCP tools) or `validate_path()` (services). No `os.path.join(extracted_path, x)` without validation. REST endpoints serving filesystem paths `realpath` BOTH sides before comparison (Learned Rule #1, extended for the hw-firmware symlink-escape test shape).
- [ ] **DB transactions:** MCP tool handlers use `context.db.flush()`, not `commit()`. No `asyncio.gather()` on coroutines sharing a session (Learned Rules #3, #7).
- [ ] **Blocking I/O:** any sync filesystem walk or CPU-bound loop inside an async handler is wrapped in `run_in_executor` (Learned Rule #5).
- [ ] **Schema/model parity:** Pydantic response schema fields match the ORM model fields exactly (Learned Rule #4). No stray or missing columns.
- [ ] **Router naming:** router functions that share a name with an imported service are suffixed `_endpoint` (Learned Rule #10).
- [ ] **MCP tool registration:** new tool category files are imported AND called in `backend/app/ai/__init__.py::create_tool_registry`.
- [ ] **Dependencies:** `pyproject.toml` updated for any new import; `docker compose exec backend python -c "import X"` passes (Learned Rule #2).
- [ ] **Rebuild parity:** after backend code change, rebuild BOTH `backend` and `worker` (`docker compose up -d --build backend worker`). Never just one (Learned Rule #8).
- [ ] **Frontend Record<> exhaustiveness:** if a backend enum/source value was added, grep `Record<{TypeName},` across `frontend/src/` and add the new key, plus `?? fallback` at lookup sites (Learned Rule #9).
- [ ] **Inline Pydantic models:** none in router files — all schemas live in `app/schemas/` (Learned Rule #12).
- [ ] **Detection roots:** filesystem walks across extracted firmware use `get_detection_roots(firmware)`, never `firmware.extracted_path` alone (Learned Rule #16). Post-relocation Android scatter containers holding raw `.img` files at top level are themselves detection roots (Learned Rule #18).
- [ ] **Silent CLI exits:** any verification step whose success criterion is "exit 0" is canaried with a known-bad input before trusted (Learned Rule #17). Especially `tsc -b` and incremental linters.
- [ ] **Android heuristics:** platform-signing detection uses the 3-tier manifest heuristic, not certificate negation (Learned Rule #13). `priv-app` paths matched as `system/priv-app` etc., not bare name (Learned Rule #14).
- [ ] **Varchar widths:** columns storing composite keys that may exceed 100 chars (JADX class names, mangled symbols, decompile cache keys) use VARCHAR(512). Migration file width matches the ORM model width — do not rely on model-only changes (Learned Rule #15).
- [ ] **File splits:** after splitting a large file, module-level constants referenced by moved methods are verified with a runtime import call, not just `py_compile` (Learned Rule #11).
- [ ] **CLI upgrades:** before swapping an external CLI major version (binwalk v2→v3 etc.), grep every flag used and verify each exists in the new `--help` (Learned Rule #6).
- [ ] **Evidence-first remediation:** before writing backfill / cleanup / migration code for "legacy rows like X", measure the condition with a SQL `COUNT(*)` or `grep` — if zero, close with a doc note, not dormant code (Learned Rule #19).
- [ ] **Docker cp iteration:** when validating a single-file change against a stale running container (no dev bind mount), `docker cp` + in-container tool + `PYTHONPATH=/app` + `-w /app` is a <30 s iteration path. Still rebuild backend+worker before trusting for the next session. **Class-shape exception:** if the diff adds/removes/renames a field on a pydantic `BaseSettings`, `@dataclass`, SQLAlchemy model, or any class cached via `@lru_cache` or module-level singleton, `docker cp` alone is insufficient — the running process holds the OLD class reference. `docker compose restart <service>` after `docker cp` (fast boot + no image change) OR full `docker compose up -d --build backend worker` rebuild. Mechanical tell: diff adds a field in a class definition → restart required (Learned Rule #20).
- [ ] **Cross-scaffold sync:** when a rule is added to or changed in CLAUDE.md's Learned Rules list, update this Verify Checklist AND any affected `.mex/patterns/*.md` in the same commit (Learned Rule #21).
- [ ] **Multi-file migration:** for N>1 find/replace tasks, (a) grep ALL call sites before designing the replacement — the full map informs whether to centralise at a store/service layer or do per-site edits, and catches intake scope miscounts; (b) typecheck after every 1-2 file edits so errors localise to the most recent change; (c) run the intake's acceptance grep at the end (`grep 'oldPattern(' → 0 hits; grep 'newPattern' → N hits`) as both completion check and miscount detector (Learned Rule #22).
- [ ] **Parallel-dispatch worktree isolation:** every Fleet-style parallel agent runs `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-{YYYY-MM-DD}` and operates inside that path — NOT just `git checkout -b`. Wave-3 evidence: β proactive worktree → 0 sweeps in 4 commits; α+γ on `checkout -b` only → 4 sweeps in 14 commits, all recovered via cherry-pick + reflog. The harness `isolation: "worktree"` + `worktreePath: "ok"` sentinel is a no-op at the working-tree level. Symlink `frontend/node_modules` from main checkout into the worktree to skip the 2 GB npm-install. `.worktrees/` is in `.gitignore`. Fallbacks (declining safety): (a) `git checkout -b feat/stream-…` — accepts ~50% sweep rate; (b) aggressive top-directory file-disjointness across streams, accept attribution noise. Strict `git add <paths>` discipline alone is NOT sufficient (Learned Rule #23, refined by Wave-3). Harness rule `auto-fleet-worktree-requires-worktree-add` flags fleet/dispatch prompts that omit `git worktree add`.
- [ ] **Frontend typecheck command:** `npx tsc -b --force` ONLY — `--noEmit` exits 0 silently under the project-references tsconfig shape (Learned Rule #24). Canary `echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force); rm …` once per session before trusting any "0 errors" output. `.claude/harness.json:6` `typecheck.command` is now `npx tsc -b --force` (resolved by Citadel protect-files append-only exception).
- [ ] **Multi-sub-task commits:** intakes / features with ≥3 independently-verifiable sub-tasks commit each sub-task separately, not bundled — alembic chains one-per-revision, schema+service+router one-per-layer, frontend virtualisation one-per-page; Rule-8 class-shape rebuild once at end of stream (Learned Rule #25).
- [ ] **Frontend image rebuild:** after any change under `frontend/src/` (including merged PRs pulled in), run `docker compose up -d --build frontend` — `restart` and `up -d` alone reuse the baked-in `/usr/share/nginx/html/dist` and ship the STALE bundle (Learned Rule #26). Mechanical tell: `docker compose images frontend` CreatedAt vs `git log --format='%ci' -1 -- frontend/` — if commit is newer, rebuild. Fix verification: served bundle must contain `Array.isArray(a)?a:(a==null?void 0:a.items` (the compiled `unwrap`). Harness rule `auto-frontend-rebuild-not-restart` flags `docker compose restart frontend` in docs/prompts. Session 93a4948d incident: `.planning/knowledge/incident-frontend-stale-bundle-2026-04-19.md`.
- [ ] **God-class split shape:** when decomposing a ≥1000 LOC file into a subpackage, use the "N additive + 1 cut-over" pattern — commits 1..(N-1) pure-additive (new topic files; monolith unchanged; callers still hit the monolith; local `python3 -m py_compile` only, no rebuild), commit N is the atomic cut-over (delete monolith + update ≤5 callers in-place OR keep a `from app.services.new_pkg import *` shim for >5). Rule #8 rebuild + Rule #11 runtime smoke run ONCE after commit N (Learned Rule #27). Individual topic extracts become bisect-clean and revertable without losing later work. Validated 5× across sessions b56eb487 + 7e8dd7c3 (manifest_checks, security_audit, sbom, emulation, mobsfscan). Re-grep callers IN the cut-over commit — intakes regularly under-count (α's sbom split found a 5th lazy-import). Dead abstractions from intake specs (e.g. a placeholder strategy file for code that never existed) are skipped per Learned Rule #19.
- [ ] **LOC re-measure before scheduling a refactor:** intakes drift uniformly +14-22% between write-time and refactor-time (Learned Rule #28). Observed at 5 Phase 5 targets: `manifest_checks` 2263→2589, `security_audit` 1036→1258, `sbom` 2073→2412, `emulation` 1454→1664, `mobsfscan` 1328→1539. Run `wc -l <target>` as the first step before committing to a refactor; rescope to a partial split or defer entirely if the re-measured value exceeds single-session capacity. A half-split state across sessions is worse than 0% or 100%. Companion to Rule #19 — evidence-first applies to intake-size claims too.
- [ ] **Frontend↔backend timeout alignment:** when adding (or touching) any long-op API call, the axios timeout MUST derive from the backend work ceiling via `frontend_ms = backend_s × 1200` (×1000 ms + ×1.2 grace) — not from an aesthetic round number (Learned Rule #29). (1) grep `backend/app/` for the authoritative timeout (`config.py` `ghidra_timeout`/`jadx_timeout`/`firmae_timeout`/`fuzzing_timeout_minutes`; service-level `subprocess.run(..., timeout=N)` / `asyncio.wait_for(..., timeout=N)` / `_PIPELINE_BUDGET_SECONDS` / `_DEFAULT_TIMEOUT`); (2) compute the formula; (3) pick the tier constant whose value ≥ that number — current tiers: `RADARE2_ANALYSIS_TIMEOUT=150_000` (from `binary.py:1637 communicate(timeout=120)` × 1.25); `GHIDRA_ANALYSIS_TIMEOUT=360_000` (from `config.py:24 ghidra_timeout=300` × 1.2); `HASH_SCAN_TIMEOUT=300_000`; `DEVICE_BRIDGE_TIMEOUT=300_000`; `SECURITY_SCAN_TIMEOUT=600_000`; (4) if no matching tier exists, add one in the file that owns the operation with an inline comment citing the backend source; (5) if `frontend_ms > 100_000` AND the deployment path has any reverse proxy (nginx/ALB/Cloudflare default ceilings ~60-100s), convert to 202+polling pattern instead (precedents: firmware unpacking `routers/firmware.py:139`; emulation start `routers/emulation.py` (2026-04-20 Fleet Wave-1 α); fuzzing campaign start `routers/fuzzing.py` (2026-04-20 Fleet Wave-1 β) — all use `asyncio.create_task` or arq `enqueue_job` + status-column polling every 2 s). Backend-side counter-requirement: every `subprocess.run` / `asyncio.create_subprocess_exec` / `asyncio.wait_for` MUST declare an explicit timeout — bare `wait_for(coro)` without the timeout param is undefined behaviour. Harness rules `auto-frontend-long-op-no-explicit-timeout` + `auto-frontend-multipart-no-explicit-timeout` enforce PRESENCE; Rule #29 adds DERIVATION discipline on top.
- [ ] **Mock patch target for lazy-imported third-party symbols:** before `patch("app.services.X_service.Y")` where Y is a third-party name, `grep -n "^from [^#]*import.*\bY\b\|^import .*\bY\b" backend/app/services/X_service.py` — if the matching import is indented (inside a function body), the symbol is lazy-imported and the patch is a silent no-op; patch the SOURCE module instead (`androguard.core.apk.APK`, `androguard.misc.AnalyzeAPK`, `androguard.core.dex.DEX`, `androguard.core.analysis.analysis.Analysis`, etc. — not `app.services.androguard_service.APK`). Triple-independent discovery in 2026-04-23 pytest-unblock fleet unlocked +620 tests (session 0801ca27, 1086 → 1706 passing). Narrow-case harness rule `patch\s*\(\s*["\']app\.services\.\w+_service\.(APK|AnalyzeAPK|DEX|dx)` enforces the androguard family; Learned Rule #30 generalises. Do NOT promote the lazy import "to simplify testing" without first ruling out optional-dep / LGPL licensing / latent-cycle reasons; if promotion IS correct, run a runtime import smoke (Rule #11) before trusting the change (Learned Rule #30).
- [ ] **Grep-derived scope counts canaried with broader pattern:** any number that feeds into scope ("N residuals remain", "M call sites to migrate", "K files still have X") derived from a grep MUST be re-run under a broader variant of the same concept; if the two counts disagree, use the broader count and investigate the delta (it is hidden scope, not false positives). "Broadest reasonable" has an objective saturation bound — keep widening until the counter stops climbing. Saturation tells in wairz: Python function-local `app.*` imports — `^\s+from app\.` is widest (50 repo-wide; `import app.`, relative imports, `importlib.import_module` all return 0 beyond that); frontend module imports — `^import ` is widest (698; `require(`, `await import(` return 0). Worst observed failure mode: `security_audit/hash_lookups.py` narrow=0 → widened=5 (appears *clean* under the narrow pattern; has 5 residuals in reality). 6 incidents across 2 weeks; miss rate has run +1 to 7×. Applies to residual audits, intake/seed verification (extends Rule #19 to grep-counts), migration scoping (extends Rule #22 with width), cut-over re-greps (extends Rule #27's "intakes under-count"). Companion to Rule #17 (silent-CLI-exit canary). One extra grep ≈ 1 s cost; no harness rule — the width-canary discipline IS the rule (Learned Rule #31).
- [ ] **No `db.refresh(obj)` after `db.commit()`:** wairz's session factory at `backend/app/database.py:24` sets `expire_on_commit=False`, so commit does NOT expire attributes — the in-memory state stays valid and `await db.refresh(obj)` is a no-op (~1-2 ms wasted SELECT round-trip per call). Detection grep: `grep -A2 "await db\.commit()" backend/app/routers/*.py backend/app/services/*.py | grep -B1 "await db\.refresh"`. External tutorials/docs that pair `commit + refresh` assume the SQLAlchemy default `expire_on_commit=True` and DO NOT apply here. If a row genuinely needs re-read (rare — typically when another process may have updated it), use an explicit `await db.execute(select(Model).where(Model.id == id))` rather than `refresh()` (Learned Rule #32). Originally caught in session 76fd9c3a (2026-04-25) cve-match POST handler review; shipped as-is to avoid a Rule #8 rebuild for a cosmetic improvement.
- [ ] **202+polling endpoint design contract:** when converting a long-op endpoint per Rule #29, ALL FOUR contract bullets apply (Learned Rule #33). **(a) Idempotent POST + 409-on-conflict in the router** — `if row.status in ("queued", "running"): raise HTTPException(409, ...)` BEFORE any state mutation, NOT inside a service-layer `ValueError`. **(b) Persist the result aggregate on the same row** — nullable JSONB column on the resource row (e.g. `firmware.cve_match_result`); survives restart + page reload; no separate result-GET endpoint. **(c) Pydantic `Literal` + DB CHECK constraint** — both for the new status column. `op.create_check_constraint("ck_<table>_<col>", ...)` mirrors revision `54c8864fbe0c` / `e6f7a8b9c0d1`. **(d) `asyncio.create_task` vs arq rubric** — arq if work coordinates with worker-only resources (Docker spawn, Ghidra) OR needs restart-survival OR scheduled triggering; `asyncio.create_task` if work runs in-process AND incrementally DB-persists state AND row-status observation is sufficient. Current applications: cve-match (`22c1990`) / fuzzing (`df30015`) → asyncio.create_task; emulation (`c5d2f74`) / firmware-unpack (`routers/firmware.py:139`) → arq. Reference recipe: see CLAUDE.md Rule #33. Frontend: `useEffect + setInterval` polling every 2 s on `/<op>/status` until terminal status; default 30 s axios floor is correct (ack is sub-second).
- [ ] **unblob `--no-sandbox` + browser-download api_key:** two co-discovered defects in session b266f17e (2026-04-30) (Learned Rule #34). (a) `backend/app/workers/unpack_common.py:730` invokes `unblob` — the args list MUST include `--no-sandbox`. unblob's Landlock sandbox induces EXDEV on sasquatch's hardlink creation, FATAL-aborting squashfs extraction with thousands of 0-byte files. Worker container is the security boundary; Landlock is redundant. Mechanical audit: combined two-condition test — `find <ep> -type f -size 0 -not -path '*/dev/*' -not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/var/run/*' -not -path '*/var/log/wtmp*' -not -path '*/var/log/utmp*' -not -path '*/var/log/lastlog*' -not -path '*/var/log/btmp*' | wc -l` AND `find <ep> -type f -links +1 | wc -l` (a healthy Linux rootfs has hundreds-to-thousands of hardlinks; sandbox-killed extract has 0). Naïve `-size 0` count over-flags small embedded firmwares with legitimate device nodes (GS724Tv6 NetGear false-positive: 58 zero-byte / 124 total = 46.8% all legitimate `/dev/*` + log placeholders); re-trigger via arq `unpack_firmware_job` after clearing `extracted_path` / `extraction_dir` / `device_metadata.detection_roots` and resetting `project.status`. (b) Any URL handed to `<a href download>`, `<img src>`, `window.open()`, or `window.location.href` MUST be wrapped with `appendApiKey(url)` — the `X-API-Key` header from the axios interceptor only applies to axios/fetch-issued requests. Browser-issued requests (anchor clicks, navigations, element src/href) bypass the interceptor and hit the API-key middleware with no credential, returning 401. Detection grep: `grep -RIn "href={[^}]*[Dd]ownload\|window\.open\|window\.location\.href\s*=" frontend/src/ | grep -v "appendApiKey"` must be zero. Existing precedents using `appendApiKey`: WebSocket URLs in `src/api/terminal.ts` and `src/api/emulation.ts:93`. **Cross-cutting lesson:** a single user-reported symptom often masks two unrelated bugs hitting the same UX surface — verify each sub-symptom independently before assuming common cause.
- [ ] **Verification-artefact canaries:** three failure modes from session 2026-05-04 (`unpack_audit_service` implementation) where an artefact reported "passed" but masked a real bug (Learned Rule #35). Meta-lesson: when a verification mechanism reports "passed", ask which CONTRACT it actually checked — and probe with a deliberate canary if the contract is weaker than assumed. (a) **Pipe-induced silent exit (Rule #17 sub-case):** `cmd | tail -N; echo "exit=$?"` reports `tail`'s exit, not `cmd`'s — the first Rule #24 canary printed `error TS2322` AND `exit=0` together because the pipe subshelled the pipeline. When capturing an exit code, run the command directly (`cmd; ec=$?`), use `set -o pipefail`, or read `${PIPESTATUS[0]}`. The Bash tool does NOT enable `pipefail` by default. (b) **Mock-vs-live canary:** mock unit tests verify "X was called", not "X was called WITH the right args" — 17 mock tests asserting `mock_db.add.call_count == 4` passed cleanly while the persisted Finding rows had `confidence=None` because the bug lived inside `FindingService.create()`'s `Finding(...)` constructor and the mock replaced the session, not the service (commit `7dc21fe` fix). After mock unit tests pass, run the new code ONCE against an actual production row and SELECT the persisted row to inspect every field the service explicitly sets. Cost: ~1 s; eliminates value-flow bugs mocks structurally cannot catch. Companion to Rule #11. (c) **JSONB schema-drift normalization:** `firmware.device_metadata['vendor_decryption']` has two production shapes (canonical `list[dict]` + legacy single `dict` with `blobs: list[str]`) coexisting in the same table; new consumer `unpack_audit_service._extract_aes_key_findings` raised `AttributeError: 'str' object has no attribute 'get'` on backfill against firmware `5b7735cd-…`. When introducing a new JSONB shape, either (i) add a `schema_version` key from day one or (ii) normalise at every consumer boundary via a dedicated `_normalize_<field>` function. Reference: `backend/app/services/unpack_audit_service.py:104` `_normalize_vendor_decryption` (commit `057ea67`) accepts list, dict-with-blobs, and unparseable inputs idempotently. Audit grep before introducing a JSONB consumer: `grep -rn 'device_metadata\[.<key>.\]\|device_metadata\.get(.<key>.' backend/app/` — every hit is a normalisation candidate. Companion to Rule #19 (measure shapes via `SELECT jsonb_typeof(device_metadata->'<key>') FROM firmware GROUP BY 1;` before assuming uniformity).
