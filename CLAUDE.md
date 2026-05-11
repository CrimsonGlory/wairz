# CLAUDE.md — Wairz Codebase Guide

This file is for AI agents (Claude Code, etc.) working on the Wairz codebase. It describes the architecture, conventions, and patterns you need to follow when making changes.

**What is Wairz?** An open-source, browser-based firmware reverse engineering and security assessment platform. Users upload firmware, the tool unpacks it, and provides a unified interface for filesystem exploration, binary analysis, emulation, fuzzing, and security assessment — augmented by an AI assistant connected via MCP (Model Context Protocol). See `README.md` for user-facing documentation.

---

## Architecture Overview

```
Claude Code / Claude Desktop
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  172 tools      │     │  Services: firmware, file,         │
│                 │     │  analysis, emulation, fuzzing,     │
│  Entry point:   │     │  sbom, uart, finding, export...    │
│  wairz-mcp CLI  │     │                                    │
└─────────────────┘     │  Ghidra headless · QEMU · AFL++    │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  Redis       │
│  (Frontend)  │    │              │              │
└──────────────┘    └──────────────┴──────────────┘

Host machine (optional):
  wairz-uart-bridge.py ←─ TCP:9999 ─→ Docker backend
```

- **Frontend:** React 19 + Vite + TypeScript, shadcn/ui + Tailwind, Monaco Editor, ReactFlow, xterm.js, Zustand
- **Backend:** Python 3.12 + FastAPI (async), SQLAlchemy 2.0 (async) + Alembic, pydantic-settings
- **MCP Server:** `wairz-mcp` CLI entry point (`app.mcp_server:main`), stdio transport, 172 tools across 21 categories
- **Database:** PostgreSQL 16 (JSONB for analysis cache)
- **Containers:** Docker Compose — backend, postgres, redis, emulation (QEMU), fuzzing (AFL++)

---

## Directory Structure

```
wairz/
├── backend/
│   ├── pyproject.toml           # Entry point: wairz-mcp
│   ├── alembic/versions/        # Database migrations (auto-run on container start)
│   └── app/
│       ├── main.py              # FastAPI app + router registration
│       ├── config.py            # Settings via pydantic-settings
│       ├── database.py          # Async engine, session factory, get_db dependency
│       ├── mcp_server.py        # MCP server with dynamic project switching
│       ├── models/              # SQLAlchemy ORM models
│       ├── schemas/             # Pydantic request/response schemas
│       ├── routers/             # FastAPI REST endpoint routers
│       ├── services/            # Business logic layer
│       ├── workers/             # Background tasks (firmware unpacking)
│       ├── ai/
│       │   ├── __init__.py      # Tool registry factory — registers all tool categories
│       │   ├── tool_registry.py # ToolContext + ToolRegistry framework
│       │   ├── system_prompt.py # MCP system prompt for Claude
│       │   └── tools/           # Tool handlers by category
│       └── utils/
│           ├── sandbox.py       # Path traversal prevention (CRITICAL)
│           └── truncation.py    # Output truncation (30KB max)
├── frontend/
│   └── src/
│       ├── pages/               # Route pages, registered in App.tsx
│       ├── components/          # UI components organized by feature
│       ├── api/                 # Axios API client functions
│       ├── stores/              # Zustand state management
│       └── types/               # TypeScript type definitions
├── ghidra/
│   ├── Dockerfile
│   └── scripts/                 # Custom Java analysis scripts for headless Ghidra
├── emulation/
│   ├── Dockerfile               # QEMU + kernels (ARM, MIPS, MIPSel, AArch64)
│   └── scripts/                 # start-user-mode.sh, start-system-mode.sh, serial-exec.sh
├── fuzzing/
│   └── Dockerfile               # AFL++ with QEMU mode
└── scripts/
    └── wairz-uart-bridge.py     # Host-side serial bridge (standalone, pyserial only)
```

---

## How to Add Things

### Adding a New MCP Tool

1. Create or edit a handler in `backend/app/ai/tools/<category>.py`:
   ```python
   async def _handle_my_tool(input: dict, context: ToolContext) -> str:
       # Available on context: project_id, firmware_id, extracted_path, db
       path = context.resolve_path(input.get("path", "/"))  # validates against sandbox
       # ... do work ...
       return "result string (max 30KB, truncated automatically)"
   ```
2. Register in the same file's `register_<category>_tools(registry)` function:
   ```python
   registry.register(name="my_tool", description="...", input_schema={...}, handler=_handle_my_tool)
   ```
3. If it's a new category file, import and call `register_<category>_tools(registry)` in `backend/app/ai/__init__.py`.

### Adding a New REST Endpoint

1. Create router: `backend/app/routers/<name>.py`
   ```python
   router = APIRouter(prefix="/api/v1/projects/{project_id}/<name>", tags=["<name>"])
   ```
2. Register in `backend/app/main.py`: `app.include_router(<name>.router)`
3. Create Pydantic schemas in `backend/app/schemas/<name>.py` (use `from_attributes=True` for ORM compatibility)
4. Create service in `backend/app/services/<name>_service.py`

### Adding a Database Table

1. Create model in `backend/app/models/<name>.py`:
   - Use SQLAlchemy `Mapped`/`mapped_column` style
   - UUID primary key with dual defaults: `default=uuid.uuid4` + `server_default=func.gen_random_uuid()`
   - Foreign keys with `cascade="all, delete-orphan"` on relationships
2. Create Alembic migration: `alembic revision --autogenerate -m "description"`
3. Migrations run automatically on container startup
4. **Every JSONB column** gets a boundary normaliser in `backend/app/services/jsonb_normalizers.py` (Rule #35c). Add `_normalize_<table>_<column>(value: Any) -> <canonical>`; if the column is read by ≥3 consumer files, also add a `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant + `_stamp_<table>_<column>(payload)` writer helper. Route every consumer access through these — `_normalize_*` at read sites, `_stamp_*` at write sites. Add a test in `backend/tests/test_jsonb_normalizers.py` covering canonical pass-through, defensive coercion (`None` / wrong-type), and idempotency.

### Adding a Frontend Page

1. Create page component in `frontend/src/pages/<Name>Page.tsx`
2. Register route in `frontend/src/App.tsx`
3. Create API client functions in `frontend/src/api/<name>.ts`
4. Use Zustand stores (`frontend/src/stores/`) for shared state
5. UI components from shadcn/ui + Tailwind

---

## Critical Rules

### Security

1. **Path traversal prevention is mandatory.** Every file access must be validated via `app/utils/sandbox.py` (`os.path.realpath()` + prefix check against the extracted root). The MCP `ToolContext.resolve_path()` method handles this — always use it. REST endpoints that serve filesystem paths (e.g. `GET /hardware-firmware/{blob_id}/download`) must also `realpath` BOTH sides before comparison so symlinks placed inside the sandbox that point outside are rejected. See `test_symlink_to_outside_is_rejected` in `test_hardware_firmware_router.py` for the canonical test shape.
2. **Never execute firmware binaries on the host.** Emulation runs inside an isolated QEMU Docker container. Fuzzing runs inside an isolated AFL++ Docker container. Both have resource limits (memory, CPU).
3. **No API keys stored in the backend.** The Anthropic API key is user-provided via their Claude Code/Desktop configuration and never touches Wairz.

### Performance

1. **Cache Ghidra decompilations** — each run takes 30-120s. Cached by binary hash + function name in the `analysis_cache` table.
2. **Cache radare2 analysis** — `aaa` can take 10-30s. LRU session caching in the analysis service.
3. **Lazy-load the file tree** — firmware can have 10K+ files. Load children on expand, never the full tree at once.
4. **Truncate MCP tool outputs** — keep under 30KB (`app/utils/truncation.py`). Large outputs break MCP clients.
5. **Firmware unpacking is non-blocking** — the unpack endpoint returns 202 and runs `asyncio.create_task()`. The frontend polls every 2s until status changes from "unpacking".

### Conventions

- **Backend:** Async everywhere (SQLAlchemy async sessions, `asyncio.create_subprocess_exec` for subprocesses). Use `async_session_factory` from `database.py` for DB access outside request context (e.g., background tasks).
- **Frontend:** Zustand for state, API functions in `src/api/`, pages poll with `useEffect` + `setInterval` for long-running operations (see EmulationPage, FuzzingPage, ProjectDetailPage for the pattern).
- **Docker:** Backend has access to Docker socket for managing emulation/fuzzing containers. Emulation containers run on an internal `emulation_net` network.

### Standing Operating Principles

These are operating principles, not forensic incidents. They apply to every change. The Learned Rules below give the specific incidents these principles were derived from — cross-references like (Rule #N) point there.

#### Agent Work Loop

For every code change:

1. Read the relevant files before editing.
2. Identify the root cause before implementing a fix.
3. Prefer the smallest clean change that fixes the root cause.
4. Preserve existing behavior unless the task explicitly requires a behavior change.
5. Check nearby related code paths for the same failure pattern.
6. Add or update tests for new behavior, changed behavior, and reproducible bug fixes.
7. Run the validation commands below before handoff.
8. Summarize what changed, why, what was validated, and what was not.

Do not paper over bugs with arbitrary sleeps, magic pixel offsets, excessive z-index values, broad exception swallowing, disabled tests, or undocumented behavior changes.

#### Testing and Validation Policy

Add or update tests when the change introduces or modifies:

- New behavior, changed behavior, or a bug fix whose failure can be reproduced in isolation.
- Security-sensitive logic — sandbox path validation, API-key handling, browser-issued URLs, auth middleware, signed-archive trust paths.
- API contract or persistence — REST endpoints, Pydantic schemas, ORM models, alembic migrations, JSONB shape, status-column transitions.
- Async / background flows — arq jobs, `asyncio.create_task` detached work, 202+polling endpoints, worker coordination.
- UI behavior — routes, polling, loading/error/empty states, optimistic updates, layout containment, keyboard navigation.

**Every new router gets a router-level test file.** Adding a new file under `backend/app/routers/` means adding a matching `backend/tests/test_<router>.py` in the same PR. The test must (a) import the router module by path (`from app.routers.<name>`), (b) cover at least the validation branches (404 / 400 / 409 paths) plus one happy-path response-schema assertion, and (c) include at least one Rule #35b live-canary that round-trips through the real ORM via `tests._live_db.make_live_db` and SELECTs the persisted row. Pure-mock files are insufficient — the audit-2026-05-04 F-G-03 finding measured 24/27 routers untested at the HTTP layer; mocks structurally cannot catch the value-flow regressions (cf. F-A-06 confidence-bypass) the live-canary discipline backstops. Recipe: `.mex/patterns/add-router-test.md`.

**Mocks vs live canaries (Rule #35b).** Mock unit tests verify dispatch shape ("X was called"), not value flow ("X was called with the right args AND the persisted row reflects them"). When persistence or service behavior matters, after the mocks pass, run the new code once against a real production row (or a freshly-created fixture row through the real ORM / service path) and SELECT the row to inspect the fields the service explicitly sets. Mocks are fine for boundary contracts; live canaries are required for value flow.

Do not delete, weaken, or skip tests to make a suite pass unless the test is demonstrably wrong AND the reason is documented in the commit message.

#### Required Validation Commands

Run the smallest reliable validation set that proves the change.

**Backend:**

- Targeted `pytest backend/tests/test_<module>.py -v` for the changed module or behavior.
- Broader pytest when the change touches shared services, models, schemas, migrations, workers, MCP tool dispatch, or security-sensitive code.
- For migration / model changes: apply via Rule #20 fast iteration (`docker cp` + `alembic upgrade head` via container exec) OR full `docker compose up -d --build backend worker` rebuild.

**Frontend:**

- `npx tsc -b --force` from `frontend/` (NEVER `--noEmit` — Rule #24).
- Mandatory Rule #24 canary once per session before trusting any "0 errors" output.
- After any change under `frontend/src/`: `docker compose up -d --build frontend` (NOT `restart` — Rule #26).

**Targeted pytest is INSUFFICIENT** when the change touches: class shape (fields added/removed/renamed on a Pydantic model, dataclass, SQLAlchemy ORM, or `@lru_cache`'d settings); lazy imports (function-body `from <lib> import …` per Rule #30); module-scope constants; cached singletons; alembic migrations; or runtime import paths after a file split. In those cases the Rule #11 backstop applies — run a runtime import smoke (`docker compose exec -T backend python -c "from app.X import Y; print('ok')"`) AND apply the Rule #20 class-shape consideration (restart after `docker cp`, OR full rebuild).

If a validation command cannot be run, say exactly why and provide the next-best validation performed. Do not claim a test, lint, typecheck, build, browser check, or Docker smoke passed unless the result was actually observed.

#### UI Layout, Overlap, and Responsive

When fixing UI overlap, clipping, stacking, scrolling, or positioning:

- Look for systemic causes first — fixed heights, absolute positioning, missing flex/grid constraints, unsafe overflow, incorrect stacking contexts, components unaware of shared reserved space.
- Do not fix overlap by only increasing `z-index` unless stacking order is genuinely the root cause.
- Do not fix overlap with arbitrary pixel offsets unless the offset comes from a real layout token, measured element, or shared spacing contract.
- Examine related regions together — headers, sidebars, drawers, modals, popovers, tooltips, floating buttons, terminal containers, Monaco panels, xterm.js, tables, scroll regions.
- Verify narrow / medium / wide viewports AND light / dark mode where supported.
- Verify keyboard focus, tab order, accessible names, and visible focus states for changed interactive controls.
- Prefer layouts that reserve or negotiate space naturally over fragile positional patches.

When Playwright / `citadel:qa` / `citadel:live-preview` is available, use it. When it isn't, document the manual viewport checks performed (which sizes, which themes) in the commit message or HANDOFF block.

#### Code Size and Structure

- Don't add unrelated responsibilities to an already-large file.
- Don't add speculative abstractions — three similar lines beats a premature helper.
- For files ≥1500 LOC that need a refactor, follow Rules #27 (N additive + 1 cut-over) and #28 (`wc -l` re-measure before scoping).

#### Handoff Summary Format

At the end of every task, report:

- **Root cause:**
- **Changes made:**
- **Files changed:**
- **Tests / validation run:**
- **Tests / validation not run:**
- **Remaining risks or follow-ups:**

Cross-reference: `/citadel:session-handoff` produces a fuller HANDOFF block for cross-session context transfer; the 6-field summary above is the in-task / per-feature shape that pairs with it. Keep both formats aligned — when one changes, update the other.

Do not claim a test, build, typecheck, browser check, or Docker smoke passed unless it was actually run and the result was observed.

### Learned Rules (from `.planning/knowledge/`)

These rules were extracted from recurring bugs and failures across 30+ development sessions:

1. **Use `docker compose up -d` not `restart` after code changes.** `restart` reuses the old container image. `up -d` recreates it with the new build. This mistake has caused false "it works locally" debugging in multiple sessions.
2. **Add new Python dependencies to `pyproject.toml` immediately.** Code that imports a new package must update `pyproject.toml` in the same commit. Verify in Docker: `docker compose exec backend python -c "import <module>"`.
3. **Use `flush()` not `commit()` in MCP tool handlers.** The outer MCP dispatch in `mcp_server.py` owns the transaction. Tool handlers should use `context.db.flush()` so writes are visible within the session but rollback works on exceptions.
4. **Match Pydantic response schemas to ORM model fields exactly.** When adding a new backend service for an existing MCP endpoint, read the response schema first and construct the return dict to match. Schema/model mismatches cause silent 500 errors.
5. **Wrap sync filesystem I/O in `run_in_executor()` inside async handlers.** Large firmware (10K+ files) stalls the uvicorn event loop. CPU-bound or filesystem-heavy operations must use `await loop.run_in_executor(None, sync_fn, args)`.
6. **Verify CLI tool flags when upgrading versions.** Before swapping any CLI tool (e.g., binwalk v2→v3), grep the codebase for ALL flags used and verify each exists in the new version's `--help`. Test with real data.
7. **Never `asyncio.gather()` on coroutines sharing a SQLAlchemy `AsyncSession`.** `AsyncSession` is not safe for concurrent coroutine access. Gather'd coroutines that share a session cause state corruption, lost writes, or runtime exceptions. Use sequential `await` calls, or create independent sessions per task via `async_session_factory()`.
8. **Rebuild `worker` AND `migrator` whenever you rebuild `backend`.** They share the same Dockerfile, codebase, and alembic versions tree. A stale worker image causes Alembic migration failures (worker can't find new revisions) and silently blocks ALL background jobs (unpack, Ghidra, vuln scan). The migrator init container also boots from the same Dockerfile — when it starts first using a stale image (compose dependency ordering), it can't find new revisions and exits 255 with `Can't locate revision identified by 'XXX'`, blocking backend + worker startup with `service migrator didn't complete successfully: exit 255`. Use `docker compose up -d --build backend worker migrator`, never just `backend` alone. **Originally Rule-of-One in δ.5** (postmortem `windows-coverage-godmode-delta-2026-05-09`, antipattern #2 + "What Broke" #5): ran `docker compose build --pull backend worker` for the δ cut-over, then `up -d` failed because the migrator started first using its OLD image and couldn't find revision `d5a6b7c8d9e0`. Pre-emptively codified the migrator extension here to avoid recurrence in ε rather than waiting for a Rule-of-Two — all three containers share the failure mode, so the rule shape is the same. Mechanical tell: any Dockerfile change OR any new `backend/alembic/versions/*.py` requires the three-way rebuild. Companion: post-rebuild `docker compose ps` to confirm all expected services are running — δ.9 also caught a frontend container that exited during the failed-migrator cascade (antipattern #6); a `docker compose up -d frontend` recovered it in ~10 s.
9. **When adding new backend enum/source values, update all frontend `Record<Type, ...>` lookups.** TypeScript `Record<UnionType, Config>` maps are exhaustive — a new backend value not present in the map returns `undefined`, crashing React with a blank page. Grep for `Record<{TypeName},` across the frontend before deploying. Add `?? fallback` to strict lookups as defense in depth.
10. **Never name a router endpoint function the same as an imported service function.** Python silently rebinds the name: the `def` at module scope overwrites the import. Callers of the "service function" get the router function instead, with completely wrong parameter types. Convention: suffix router functions with `_endpoint` (e.g., `run_clamav_scan_endpoint`) when they share a conceptual name with a service import.
11. **After splitting a large file, verify all module-level constants are accessible.** `py_compile` and import checks pass even when a method references a constant that was left in the original file. The `NameError` only surfaces at runtime when the method is actually called. Always run an API call or integration test against the split code before deploying.
12. **Pydantic response models go in `schemas/`, not in routers.** 9/10 Wairz routers import models from `app/schemas/`. Defining models inline in router files causes forward reference issues and violates the project convention.
13. **For Android firmware analysis, detect platform signing via manifest heuristics, not certificate negation.** Equating "not debug-signed AND in priv-app" with "platform-signed" is a false equivalence. Use the 3-tier heuristic in `_has_signature_or_system_protection()`: declared signatureOrSystem permissions, requested platform-only permissions, system shared UIDs.
14. **When checking firmware paths, match partition prefixes, not bare directory names.** `"priv-app" in path.split(os.sep)` matches too broadly. Check `system/priv-app`, `product/priv-app`, `vendor/priv-app`, `system_ext/priv-app` as partition/directory pairs. Use `is_priv_app_path()` from `_android_helpers.py`.
15. **When reusing DB columns for new data types, verify value lengths.** Java class names with inner classes and synthetic lambdas (`$$ExternalSyntheticLambda0`) commonly reach 150+ characters. The `analysis_cache.operation` column needed VARCHAR(512), not VARCHAR(100), for JADX cache keys.
16. **When walking a Firmware extraction, always use `get_detection_roots(firmware)`, never `firmware.extracted_path` alone.** The `extracted_path` column stores ONE rootfs the unpacker chose; scatter-zip uploads, multi-archive medical firmware, and nested unblob output produce sibling directories that `extracted_path` misses entirely. Helper in `app/services/firmware_paths.py` returns the complete list, cached in `device_metadata["detection_roots"]` JSONB. Per-binary flows (emulation/fuzzing/sandbox) may still use `extracted_path` since they need a single binary path — filesystem walks must use the helper. Originally uncovered by the DPCS10 Android bug (md1dsp.img invisible) and reproduced on the RespArray ZIP (0 blobs before fix, 11+ after).
17. **Canary a silent CLI exit before trusting it.** `tsc -b`, incremental build tools, and some linters exit 0 with no output when their cache says nothing changed — indistinguishable from "didn't run at all." If a non-trivial change produced zero output, feed the tool a known-bad input (e.g. write a one-line TS file with `const x: number = "str"` and re-run). If the canary ALSO passes silently, the tool is not actually checking. Applies to any verification step whose success criterion is "exit 0."
18. **After an Android scatter extraction, the extraction container itself is a detection root when it holds raw images at top level.** `_relocate_scatter_subdirs` moves `.img`/`.bin` files from `extracted/<version>/` into `extracted/`. `firmware_paths._compute_roots_sync` only scans SUBDIRECTORIES of the container for qualifying children; top-level files would be invisible to detection unless the container itself is promoted. The fix in `_compute_roots_sync` uses `_dir_has_raw_image(container)` (strict extension list, non-recursive) so the container is added only when it genuinely holds firmware blobs. Regression uncovered by DPCS10 upload 0ed279d8 losing 14 MTK blobs (lk / tee / gz / preloader / scp / sspm / spmfw / md1dsp / modem / cam_vpu×3 / dtbo). See `test_post_relocation_layout_includes_container` and `test_linux_rootfs_only_container_not_included` in `test_firmware_paths.py` for the contract.
19. **Evidence-first before writing remediation code.** When an intake, seed, or spec prescribes a backfill / cleanup / migration for "legacy rows that look like X", measure the condition first — a single SQL `COUNT(*)` or `grep` usually settles it in one second. If the count is zero, close the thread with a documented no-op; don't write a dormant utility "for safety." Spec-driven coding against a condition that's already been silently resolved produces dead abstractions that rot into maintenance burden. Originally applied to the A.3 null-tier CVE backfill seed item — spec said 2,918 null-tier rows/firmware; live DB showed 0; fix was a doc note, not 50 LOC. The discipline is: the spec describes intent, the DB describes truth — trust the DB.
20. **When iterating a single-file change against a stale running container, use `docker cp` + in-container tool, not a full rebuild — BUT class-shape changes still need a process restart.** A running backend/worker container with no dev bind mount (typical: containers from a previous session) won't see host-side new files. If the change is a single file added under an existing mount point — e.g. a new alembic migration at `backend/alembic/versions/NNNN_*.py` — copy it in with `docker cp host/path.py <container>:/app/…/path.py` and run the tool via `docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/<tool>`. `PYTHONPATH=/app` + `-w /app` are both required for alembic to import `app.database`. This turns a 3–5 min rebuild (CLAUDE.md rule #8) into a <30 s iteration. Still rebuild backend+worker before trusting for the next session — the `docker cp` is for validation speed, not durable state. **Exception:** when the diff adds, removes, or renames a field on a class whose instances are cached in memory — pydantic `BaseSettings` behind `@lru_cache`'d `get_settings()`, `@dataclass` singletons, SQLAlchemy models registered in the session metadata, or any module-level singleton — the running process still holds the OLD class reference. Subsequent imports resolve to the cached instance with the old shape; `docker cp` alone does nothing. Symptom: `AttributeError: 'Settings' object has no attribute '<new_field>'` on first use of the new field. Fix: `docker compose restart <service>` after `docker cp` (if the service boots in <30 s and no image-layer change is needed), OR commit to the full `docker compose up -d --build backend worker` rebuild. Mechanical tell: if the diff adds/removes/renames a field in a class definition, assume a restart is needed even for a one-file change.
21. **When a rule is added to or changed in this Learned Rules list, update the mirror in `.mex/context/conventions.md` Verify Checklist in the same commit.** The two live in parallel (this list is canonical for rule content; the checklist is the task-time gate derived from it). Out-of-sync state rots fast — new rules silently stop being enforced in mex-driven tasks, and agents following only `.mex/ROUTER.md` miss the newest guidance. Applies to changes in rule wording, numbering, or status (e.g. a rule that graduates to a hook-enforced quality rule and no longer needs manual verification). Companion lesson: the same sync discipline applies to `.mex/ROUTER.md`'s "Current Project State" — a resolved issue listed there becomes a trap for the next session.
22. **For multi-file find/replace migrations: grep all sites first, typecheck every 1–2 edits, use the intake's acceptance grep as the completion check.** Three-part discipline, all three bullets applied to every N>1 migration. Grepping every occurrence BEFORE designing the replacement informs the design — if 6/10 call sites live in one file, centralising at a store/service layer cuts 6 per-site edits to 1 `invalidateFoo()` call. The full grep also catches under-counted intake scope (useFirmwareList intake said "9 pages"; grep found 10 — HardwareFirmwarePage was missed). Incremental typecheck after every 1–2 file edits localises each error to the most recent change; a single-commit sweep of N files produces an N-error tsc output needing bisection, for near-zero cost savings. Running the intake's acceptance grep at the end (`grep 'oldPattern(' → 0 hits; grep 'newPattern' → N hits`) doubles as both scope verification and miscount detection. Applies to: Zustand store refactors, API client renames, type widening (`any`→`unknown`), any "migrate N callers to the new helper" task.
23. **For parallel agent dispatch (Citadel Fleet / `Agent` tool with `isolation: "worktree"` or similar harnesses), `git worktree add <path> -b <branch>` + operating IN that path is the only mitigation that holds; `git checkout -b` alone is NOT sufficient.** Wave-3 evidence (session 198243b8) confirmed and refined the original Wave-1+2 finding: β created `git worktree add .worktrees/stream-beta -b feat/stream-beta-2026-04-19` proactively before any file write and had **0 cross-stream commit sweeps in 4 commits**; α used `git checkout -b` only and had **2 sweeps before** running `git worktree add` mid-session (then 0 sweeps after); γ stayed in the main checkout under per-branch discipline and absorbed **2 sweeps in 6 commits** (recovered via cherry-pick + reflog-replay, ~10–15 min cost each). The original session 435cb5c2 cross-sweep catalogue (Alpha→Gamma f614c43, Delta→Zeta e8548fd, Zeta-attributed-to-Delta) reproduced the same pattern under `checkout -b`-only discipline. The `isolation: "worktree"` parameter + `worktreePath: "ok"` sentinel from the Fleet harness are STILL no-ops at the working-tree level — the harness should be fixed to issue real `git worktree add` per stream; until then, sub-agent prompts MUST include the explicit worktree command. **Effective dispatch shape (use verbatim):** `git worktree add .worktrees/stream-{name} -b feat/stream-{name}-{YYYY-MM-DD}` followed by `cd .worktrees/stream-{name}` for all writes/commits. Symlink `frontend/node_modules` from the main checkout into the worktree to avoid a 2 GB npm-install. Add `.worktrees/` to `.gitignore` (already done). **Fallbacks, in declining order of safety:** (a) `git checkout -b feat/stream-{name}-{YYYY-MM-DD}` BEFORE any file write — accepts ~50% sweep rate, recovery via cherry-pick + `git reset --hard {baseline} && git reflog`; (b) design waves for AGGRESSIVE top-directory-level file-disjointness (backend/models/ vs backend/routers/ vs frontend/pages/ — truly separate subtrees) and accept commit-attribution noise. Strict `git add <specific-paths>` discipline alone is NOT sufficient — Wave-2 prompts used it uniformly and still failed 2 of 3 streams, because the shared on-disk checkout exposes unstaged changes from OTHER streams to `git add`. See `.planning/knowledge/wairz-intake-sweep-wave12-antipatterns.md` anti-pattern #1 and `wairz-intake-sweep-wave3-antipatterns.md` anti-pattern #1 for the full evidence matrix. The harness rule `auto-fleet-worktree-requires-worktree-add` (in `.claude/harness.json` qualityRules.custom) flags fleet/dispatch prompts that say `git checkout -b feat/` without an accompanying `git worktree add`.
24. **For frontend typecheck in wairz, use `npx tsc -b --force` — never `tsc --noEmit`.** The `frontend/tsconfig.json` uses `"files": []` + project `"references"`; `--noEmit` has no files to check in the root project and exits 0 without descending into the referenced projects. This is a Rule 17 silent-CLI-exit instance — discovered via canary in session 435cb5c2 Wave 1 Stream Gamma after Gamma's first "0 errors" typecheck appeared to pass despite known type problems. The `-b --force` variant invokes all referenced projects and catches errors. Package.json `"typecheck"` scripts, any harness `typecheck.command` config, CI workflows, and agent-prompt verification steps must use `-b --force`. Mandatory Rule-17 canary once per session before trusting any "0 errors" output: `echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force); rm frontend/src/__canary.ts` — expect the command to fail with a type error before it's trusted for real use. The stale `"command": "npx tsc --noEmit"` entry in `.claude/harness.json:6` was the known companion defect; resolved by the protect-files append-only exception (Citadel `hooks_src/protect-files.js`) — `harness.json:6` now reads `npx tsc -b --force`.
25. **When implementing an intake or feature with ≥3 independently-verifiable sub-tasks, commit each sub-task as its own commit — not a bundled "feat(X): all of Y" omnibus.** Session 435cb5c2 shipped Alpha's 7 data-migration sub-tasks (D1/D2/D3/I1/I2/I3/I4) as 8 commits, Delta's 3 infra sections (O1 cron / O2 migrator / O3 observability) as 7 commits, Beta's pagination as 5 one-per-endpoint-family commits. Individual `git revert <sha>` per sub-task works cleanly; a bundled commit forces all-or-nothing rollback and scrambles `git bisect`. Also: cross-stream commit sweeps (Rule 23 anti-pattern) damage LESS when per-commit surface is small — a mixed sub-task commit contains at most one slice of mis-attributed work. Natural splits: alembic chains = one commit per revision file; schema+service+router changes on the same feature = one commit per layer; frontend virtualisation across N pages = one commit per page. Rule-8 class-shape rebuild runs ONCE at the end of the stream, not per commit. Exception: a single-atomic-change task (one-line bug fix, single flag flip) is one commit; "sub-task" means a genuinely independently-verifiable slice with its own acceptance grep or smoke check. **Single-slice exception #2 — cross-stack alignment tests.** When a cross-stack alignment test enforces pairwise agreement across N source-of-truth surfaces (e.g. `test_finding_source_alignment.py` enforcing DB CHECK ↔ frontend TypeScript union ↔ frontend `FINDING_SOURCE_CONFIG` keys agree pairwise), the multi-surface change is genuinely single-slice — bundle in one commit. Splitting leaves the alignment test RED between commits and breaks bisect-clean lanes. Worked examples: `7079b4d` (alembic `61b147189fcf_close_findings_source_drift.py` + `frontend/src/types/index.ts` `FindingSource` union + `frontend/src/constants/statusConfig.ts` `FINDING_SOURCE_CONFIG` mirror, 2026-05-06) and `ee2abd9` (β.12a alembic `c5b6a7d8e9f0_extend_findings_source_windows_verdicts.py` + same frontend mirror, 2026-05-08) — both bundled DB CHECK extension + frontend mirror in one atomic commit because `test_finding_source_alignment.py` enforces strict pairwise agreement. Mechanical heuristic: if `grep -rn "<enum_name>" backend/ frontend/` surfaces 3+ source-of-truth definitions AND a test enforces their agreement, the multi-surface addition is single-slice. **Rule-of-Eight now** — `7079b4d` (2026-05-06 baseline) + `ee2abd9` β.12a (windows_authenticode + windows_dbx_revoked) + `f70c2e1` γ.7 (windows_registry_persistence + windows_inf + windows_driver_imports) + `20ea228` δ.8 (windows_r2r_stomp + windows_il_capa) + `5466644` ε.1.b.4 (windows_sysmon_proc_create + windows_logon_success + windows_logon_failure) + `da71afa` ζ.1 (windows_amcache_install) + `a6be708` ζ.2.C (windows_prefetch_execution) + `04a3c55` ζ.3.C (windows_srum_network_activity + windows_srum_application_runtime). Pattern is durable beyond debate; the multi-surface single-commit shape is the default for any cross-stack alignment commit going forward.

26. **When `frontend/src/**` changes, the frontend image must be rebuilt — `docker compose up -d --build frontend`, not `restart` and not `up -d` alone.** The frontend container serves a Vite-built `dist/` baked into the image at `/usr/share/nginx/html/`; there is no bind mount, so nginx keeps serving the stale bundle until the image layer is rebuilt. Symptom: runtime `TypeError: <var>.map is not a function` (or similar shape mismatch) thrown from components whose *source code* correctly unwraps the new backend response — the shipped bundle is pre-change. Originally manifested in session 93a4948d: backend Stream Beta (session 435cb5c2) added Page-envelope pagination to `GET /api/v1/projects` → `{items, total, offset, limit}`; Stream Zeta (commit `3063283`) added the frontend `unwrap(data)` helper; but the frontend container image was built at 14:40 UTC *before* `3063283` landed at 17:14 UTC and never rebuilt — so the live bundle returned the raw envelope to `projectStore.fetchProjects`, and `Sidebar`'s `projects.map(...)` threw. Mechanical tell: after any `git pull` / branch switch / commit that modifies a file under `frontend/src/`, compare `docker compose images frontend` `CreatedAt` with `git log --format='%ci' -1 -- frontend/` — if the commit is newer than the image, rebuild. `docker compose restart frontend` does NOT help; it reuses the existing image. Companion to Rule #8 (backend+worker rebuild discipline). Fix verification: curl the served HTML for the bundle hash, then `grep -oE 'Array\.isArray\([a-z]\)\?[a-z]:\([a-z]==null\?void 0:[a-z]\.items' <bundle.js>` must match (the compiled `unwrap`); zero matches = stale build. The harness rule `auto-frontend-rebuild-not-restart` (in `.claude/harness.json` qualityRules.custom) flags docs/prompts that say `docker compose restart frontend`.

27. **When splitting a large single-file class or module (≥1000 LOC) into a subpackage, use the "N additive + 1 cut-over" shape.** Commits 1..(N-1) add new files without changing existing imports or behaviour (callers still hit the monolith; the new files are dead code in the running system). Commit N is the atomic cut-over that either (a) deletes the monolith and updates ≤5 call sites in-place, or (b) replaces the monolith with a one-line `from app.services.new_pkg import *` shim (>5 call sites). Class-shape changes (Mixin→composition, inheritance chain edits) happen in commit N as well, with thin forwarders added in the host class for each method still called via `self._check_*`. The Rule #8 rebuild + Rule #11 runtime smoke run ONCE after commit N, not per commit. Individual topic extracts become revertable in isolation without losing later work — bisect-clean. Originally validated on `manifest_checks` (2589 LOC Mixin, 8 commits) and `security_audit_service` (1258 LOC module, 8 commits) in session b56eb487 (2026-04-21); extended to `sbom_service` (2412 LOC, 9 commits, Strategy pattern with 14 strategies), `emulation_service` (1664 LOC, 7 commits, cron-registration preserved), and `mobsfscan_service` (1539 LOC, 5 commits) in session 7e8dd7c3 (2026-04-22). **5 consecutive clean shippings across 2 sessions — 34 additive + 5 cut-over commits, 0 reverts, 0 cross-stream sweeps (under Rule #23 worktree discipline). The pattern is durable.** Under-counted caller audits surface at cut-over time — α's sbom split found a 5th lazy-import caller the intake missed; re-grep in the cut-over commit, update in-place, adjust the commit message. For Strategy-pattern splits specifically, dead-abstractions in the intake (e.g. an `rpm_strategy.py` the monolith never implemented) are dropped per Rule #19 — don't create placeholder files for conditions that aren't present.

28. **Before starting any refactor whose scope is predicated on a specific LOC count in an intake / spec, re-measure with `wc -l` first.** Observed drift at 5 Phase 5 targets was consistently +14% to +22% over intake measurement: `manifest_checks` 2263→2589 (+14%), `security_audit_service` 1036→1258 (+22%), `sbom_service` 2073→2412 (+16%), `emulation_service` 1454→1664 (+14%), `mobsfscan_service` 1328→1539 (+16%). Intakes age; files grow at a uniform 14-22% rate between when the intake is written and when the refactor runs. If the re-measured target exceeds a single-session capacity budget, rescope to a partial split (one or two topic extractions only) or defer the whole refactor rather than risk a half-done state (CLAUDE.md Rule #11 penalty: the class-shape change costs a Rule #8 rebuild; a half-split state between sessions is much worse than a 0% or 100% split). Companion to Rule #19 — evidence-first applies to intake-size claims too. Re-measure takes 1 second (`wc -l <file>`); carries zero cost; eliminates 14-22% scope surprises.

29. **Frontend axios timeouts derive from the backend work-ceiling plus 20% grace, not from aesthetics — and any synchronous tier >100s is unsafe behind a reverse proxy.** The axios floor is `timeout: 30_000` in `frontend/src/api/client.ts:6` (axios's native default is `0` = unlimited — the wairz-specific 30s override forces fail-fast for unflagged CRUD calls). Every long-op endpoint MUST declare an upward override whose value satisfies `frontend_ms ≥ backend_s × 1200`, i.e. **backend declared timeout in seconds × 1200 = frontend timeout in milliseconds** (the ×1200 factor bakes in ×1000 for ms-conversion and ×1.2 for network + JSON-serialization grace). Backend side: uvicorn has NO per-request max (only `--timeout-keep-alive=5s` governing idle *between* requests), so the authoritative ceiling is whatever `config.py` / `asyncio.wait_for(..., timeout=N)` / `subprocess.run(..., timeout=N)` declares in the service. Sources: [axios request config](https://axios-http.com/docs/req_config) (`default is 0 (no timeout)`); [uvicorn settings](https://www.uvicorn.org/settings/). Current tiered constants in-tree (by decreasing speed): `RADARE2_ANALYSIS_TIMEOUT=150_000` (radare2 `aaa` — matches `backend/app/ai/tools/binary.py:1637` `communicate(timeout=120)` × 1.25); `GHIDRA_ANALYSIS_TIMEOUT=360_000` (Ghidra headless — matches `config.py:24 ghidra_timeout=300` × 1.2); `HASH_SCAN_TIMEOUT=300_000` / `DEVICE_BRIDGE_TIMEOUT=300_000` (hash lookups, device ingest); `SECURITY_SCAN_TIMEOUT=600_000` (security audit, SBOM, yara, vuln scan — backend `mobsfscan` pipeline `_PIPELINE_BUDGET_SECONDS=600` × 1.0 — this is the outer synchronous ceiling). Each tier constant MUST (a) live in the API file that owns the operation (`analysis.ts` owns Ghidra/radare2; `findings.ts` owns security-scan; `device.ts` owns device-bridge), (b) carry an inline comment citing the backend source (e.g. `// matches config.py:24 ghidra_timeout=300 × 1.2 grace`), (c) NOT be duplicated across files — a call in another file uses `import { SECURITY_SCAN_TIMEOUT } from './findings'` rather than re-declaring. **Ceiling caveats from the upstream ecosystem** (session 7e8dd7c3 research): Chrome's XHR/fetch hard cap is ~300s; nginx `proxy_read_timeout` defaults to 60s; AWS ALB idle-timeout defaults to 60s (max 4000s); Cloudflare origin-response defaults to 100s (524 error past that, Enterprise-only raise). wairz currently deploys same-origin (frontend → backend directly, no proxy), so the 600s tier works — but ANY deployment behind a reverse proxy MUST either tune the proxy's `proxy_read_timeout` ≥ the frontend tier OR convert the endpoint to the 202+polling pattern (precedent: firmware unpacking returns 202 and the frontend polls every 2s; `asyncio.create_task()` runs the work detached and posts to `analysis_cache`). Mechanical author check when adding a long-op endpoint: (1) grep the backend service for `timeout=`, `GHIDRA_TIMEOUT`, `BUDGET_SECONDS`, `asyncio.wait_for` to find the authoritative ceiling; (2) compute `frontend_ms = backend_s * 1200`; (3) pick the tier constant whose value ≥ that number; (4) if none exists, add one in the owning API file with a derivation-citing comment; (5) if `frontend_ms > 100_000` AND any proxy sits on the deployment path, use 202+polling instead. **Backend counter-requirement:** every `subprocess.run`, `asyncio.create_subprocess_exec`, and `asyncio.wait_for` in a service MUST declare an explicit timeout — bare `wait_for(coro)` without a timeout param is undefined behaviour, and the alignment math collapses. 4 critical misalignments found in session 7e8dd7c3 backend-timeout-audit: **Ghidra decompile** frontend 180s vs backend 300s (FIXED — 360s this session, commit a183e22); **radare2** frontend 90s vs backend 120s (FIXED — 150s, same commit); **emulation user-mode** frontend 300s vs backend `config.py:30 firmae_timeout=1800` (FIXED — 202+polling refactor shipped on Fleet Wave 1 Stream α 2026-04-20 branch `feat/stream-alpha-emulation-202-2026-04-20`; `POST /emulation/start` returns 202 with `status="pending"`, the detached `EmulationService.spawn_session_background` runs the Docker work via arq job `spawn_emulation_session_job` (fallback `asyncio.create_task`), transitions the row through `pending → booting → ready` on a real health probe (user-mode: `/tmp/.standalone_mode` or `/firmware` readable; system-mode: `/tmp/qemu-serial.sock` appeared via `await_system_startup`), terminal WS in `routers/emulation.py` now gates on `status in ("running", "ready")`; frontend `startEmulation` inherits the `apiClient` default 30 s via `frontend/src/api/emulation.ts` and the `EmulationPage` auto-attaches the terminal when polling flips to `ready`); **fuzzing campaign** frontend 600s vs backend `config.py:38 fuzzing_timeout_minutes=120` (7200s) (FIXED — 2026-04-20 Wave 1 Stream β branch `feat/stream-beta-fuzzing-202-2026-04-20`: `POST /fuzzing/campaigns/{id}/start` now returns 202 with `status="queued"` and schedules the container spawn via `asyncio.create_task(_run_campaign_spawn_background)`; frontend `FuzzingPage` polls every 2 s while any row is queued, matching the firmware-unpack precedent — the frontend `startCampaign` no longer needs a long timeout override and the default 30 s axios floor is now correct for the 202 ack). Drift consolidation shipped 2026-05-05 (audit-2026-05-04 quick-wins M-1): `frontend/src/api/timeouts.ts` is now the single canonical home for all 5 tier constants (`RADARE2_ANALYSIS_TIMEOUT`, `GHIDRA_ANALYSIS_TIMEOUT`, `HASH_SCAN_TIMEOUT`, `DEVICE_BRIDGE_TIMEOUT`, `SECURITY_SCAN_TIMEOUT`); 9 redeclarations across 8 API files were replaced with `import { ... } from './timeouts'`. Harness rules `auto-frontend-long-op-no-explicit-timeout` and `auto-frontend-multipart-no-explicit-timeout` enforce PRESENCE of the `timeout:` option; this rule adds the DERIVATION discipline on top — the harness catches missing overrides, the rule ensures the override value actually aligns with the backend.

30. **For mock patches targeting a third-party symbol that a service LAZY-imports inside a function body, patch the SOURCE module — never the service module.** `unittest.mock.patch(target)` resolves `target` against the module object at patch-setup time and rebinds the attribute on that module; if the symbol was never bound at module scope (because the service does `from <lib> import Symbol` INSIDE a function body, not at the top), the patch is a silent no-op — the real symbol runs against whatever fake inputs the test supplied, typically producing a downstream `FileNotFoundError` or a shape mismatch that looks like a service bug. Mechanical check before writing ANY `patch("app.services.X_service.Y")` where Y is a third-party name: `grep -n "^from [^#]*import.*\bY\b\|^import .*\bY\b" backend/app/services/X_service.py`. If the match is indented (inside a function body), the symbol is lazy-imported — patch the SOURCE module instead: `patch("androguard.core.apk.APK")`, `patch("androguard.misc.AnalyzeAPK")`, `patch("androguard.core.dex.DEX")`, `patch("androguard.core.analysis.analysis.Analysis")`, etc. Originally surfaced as three independent discoveries in session 0801ca27 pytest-unblock fleet (2026-04-23): α retargeted 6 `androguard.core.apk.APK` patches; β retargeted 1 `androguard.misc.AnalyzeAPK` patch; γ retargeted the orchestrator's `androguard.core.apk.APK` patch. Same-session test-count delta: **+620 tests unlocked** once patch targets were corrected (1086 → 1706 passing). Narrow-case harness rule `patch\s*\(\s*["\']app\.services\.\w+_service\.(APK|AnalyzeAPK|DEX|dx)` enforces the androguard family specifically; Rule #30 generalises to any third-party symbol. **Companion guidance — DO NOT promote the lazy import "to simplify testing" before reading WHY it's lazy.** Legitimate reasons for function-body imports include: (a) optional / slow dependency (androguard cold-import is ~500 ms; loading it at startup penalises non-Android code paths); (b) GPL / LGPL licensing partition (binding the dep at app-level module scope leaks it across the whole import graph); (c) genuine circular-import avoidance that Phase 5 hasn't caught yet. Only promote when none of these apply. Conversely, when the lazy-import is a RELIC of pre-Phase-5 cycles that Rule #23 worktree + Phase 5 decomposition have since removed, promoting to top-level IS the correct cleanup (and the patch target then legitimately becomes `app.services.X_service.Y`). Companion to Rule #11: after any lazy→top-level promotion, a runtime import smoke (`docker compose exec -T backend python -c "from app.services.X_service import Y"`) is mandatory before trusting the change — `py_compile` alone won't catch a Rule #20 class-shape cached singleton.

31. **Before trusting any grep-derived scope count, re-run with the broadest-reasonable pattern and compare — narrow regexes silently under-count, and the miss rate has run +1 to 7× across 6 wairz incidents in 2 weeks.** A grep returning "N hits" is a Rule-17-analog silent-success risk: "found N" is indistinguishable from "the grep wasn't looking at the full concept" unless you canary it. Mechanical discipline: (1) write the narrow pattern that catches the primary syntactic form; (2) write a broader variant that covers every syntactic form of the same concept; (3) run both; compare. Agreement → trust the count. Divergence → use the broader count AND investigate the delta — it is hidden scope, not false positives. **"Broadest reasonable" has an objective saturation bound: keep widening until the counter stops climbing.** Measured saturation points in wairz: **Python function-local `app.*` imports** — `^\s+from app\.` is widest (50 repo-wide); adding `import app\.`, relative-import, or `importlib.import_module` returns 0 new. **Frontend module imports** — `^import ` is widest (698); `require(`, `await import(` both return 0. Narrow-side failure modes observed: (a) `^\s+from app\.(services\|ai\|models\|schemas)\.` returned 18 (missed every `app.utils.*` + `app.database.*` — 32 hits invisible); (b) `firmware_service.py` narrow=2 vs widened=14 (12 hidden, 7× miss); (c) `security_audit/hash_lookups.py` narrow=**0** vs widened=5 (appeared *clean* under the narrow pattern — worst failure mode). Evidence across sessions:

    | Session | Concept | Narrow | Broader | Outcome |
    |---|---|---|---|---|
    | f2f9060c (2026-04-24) | `firmware_service.py` residual imports | 2 | 14 | caught end-of-session; scope would have blown up if picked blind |
    | 5eefecb0 (2026-04-24) | `assessment_service` function-local delta | N | N+model+cross-layer | caught at extraction time, Rule #11 smoke flagged it |
    | strategic-next-steps (2026-04-19) | `get_analysis_cache()` call sites | 18 (agent) | 22 (grep) | Rule #22 caught pre-edit |
    | wave1-close (2026-04-22) | sbom split lazy-import callers | intake N | N+1 at cut-over | Rule #27 cut-over re-grep caught it |
    | useFirmwareList (Rule #22 base) | pages using the hook | 9 | 10 | HardwareFirmwarePage was missed |
    | frontend-axios sweep (2026-04-22) | missing-timeout sites | N (old regex) | N+M | regression fix re-scoped on re-grep |

    Applies to: residual-count audits (this session's P3 carve-out ranking), intake/seed scope verification (Rule #19 extended to grep-derived counts), multi-file migration scoping (Rule #22's "grep all sites" + width discipline), cut-over caller re-greps (Rule #27's "intakes regularly under-count" observation). Companion to Rule #17 (silent-CLI-exit canary) — both are about distinguishing "tool confirmed nothing" from "tool wasn't looking." Cost is one extra grep (~1 s); carries zero risk; eliminates a recurring source of mid-session scope surprises. No harness rule candidate — any auto-flag on "narrow-looking" regexes would fire on legitimate targeted greps and produce noise. The durable form IS the width-canary discipline in this rule.

32. **In wairz, `await db.refresh(obj)` after `await db.commit()` is a no-op — skip it.** wairz's session factory at `backend/app/database.py:24` sets `expire_on_commit=False`, so attributes are NOT expired by commit and remain populated in memory. The `db.refresh(obj)` call issues a redundant SELECT round-trip that returns the same values already in scope (~1-2 ms wasted per call; negligible perf impact, but the redundancy obscures intent and signals a misunderstanding of the session config). The SQLAlchemy default is `expire_on_commit=True` where the refresh IS load-bearing — wairz overrides this to `False` everywhere, so external tutorials/docs that pair commit+refresh DO NOT apply to this codebase. Mechanical detection: `grep -A2 "await db\.commit()" backend/app/routers/*.py backend/app/services/*.py | grep -B1 "await db\.refresh"` — every match is suspicious. If a session DOES need expiry behavior (rare — typically when a separate process may have updated the row), use an explicit re-SELECT against `Model.id` rather than relying on `refresh()`. Originally surfaced in session 76fd9c3a (2026-04-25) cve-match POST handler review — the `db.refresh(firmware)` after `db.commit()` was a no-op caught post-smoke; shipped as-is to avoid a Rule #8 rebuild for a cosmetic improvement, flagged for a future cleanup sweep.

33. **A 202+polling endpoint conversion (per Rule #29) follows a 4-bullet design contract — apply ALL FOUR before shipping.** Rule #29 establishes WHEN to convert (frontend timeout > 100s with reverse proxy on the path, OR backend ceiling > axios floor and the work is genuinely async-friendly); this rule establishes WHAT a correct conversion looks like, generalised from 4 shipped applications: firmware unpacking (`backend/app/routers/firmware.py:139`, original precedent), emulation (`c5d2f74`, 2026-04-20 Fleet Wave-1 α), fuzzing (`df30015`, 2026-04-20 Fleet Wave-1 β), cve-match (`22c1990`, 2026-04-25 session 76fd9c3a).

    **(a) Idempotent POST + 409-on-conflict in the router (not the service).** The handler MUST check `if row.status in ("queued", "running"): raise HTTPException(409, f"<op> already {row.status}")` BEFORE any state mutation. 409 is RFC 9110's "conflict with current resource state" — clients distinguish it from 400 (validation error) reliably. Putting the check at the API surface (not buried in a service-layer `ValueError` like emulation's `create_pending_session` or fuzzing's `start_campaign` did originally) makes the contract visible and the response explicit. Anti-patterns: returning 200 with the in-flight status (frontend can't distinguish "started new" from "found existing"); returning 400 (loses conflict semantics); silently re-using the existing job (frontend's `started_at` watcher gets stale data).

    **(b) Persist the result aggregate on the same row used for status — not Redis, not in-process memory.** Add a nullable JSONB column (e.g. `firmware.cve_match_result`) that stores the same dict the synchronous endpoint used to return. Frontend renders the last-known-result directly from the row on page reload; no separate `GET /<op>-result` round-trip needed. Cost: one nullable JSONB column. Benefit: survives backend restart AND survives a page reload. Anti-pattern: storing the result in Redis or process memory (lost on restart; user wonders what their last run produced after F5).

    **(c) New status column gets BOTH a Pydantic `Literal` AND a DB CHECK constraint.** Migration adds `op.create_check_constraint("ck_<table>_<col>", "<table>", "<col> IN ('idle', 'queued', 'running', 'completed', 'failed')")`. Schema declares `Status = Literal["idle", "queued", "running", "completed", "failed"]`. The `Literal` catches LLM/dev typos at the API boundary; the CHECK catches direct-SQL writes (cron scripts, manual fixes, ORM rollbacks under partial-failure paths). Both gates are cheap; ship both. Mirrors `ck_emulation_sessions_status` / `ck_fuzzing_campaigns_status` (revision `54c8864fbe0c`) and `ck_firmware_cve_match_status` (revision `e6f7a8b9c0d1`). **Subtlety on the typo-gate location for free-string fields with N legacy callers.** When the schema field is ALREADY `str` with N legacy values flowing through it (e.g. `FindingCreate.source: str` carrying 18 source-tag values across services / routers / MCP tool handlers), tightening the field to `Literal[<full-allowlist>]` forces an N-file caller sweep AND breaks any caller passing a runtime-derived string (operator-tagged sources, dynamic adapter outputs). The right shape is a NARROW Literal at the new HELPER's boundary — not at the schema field — so the typo-gate fires at the new helper's definition site without disturbing legacy paths. The DB CHECK enforces the full allowlist as the safety floor; the narrow Literal catches new-helper typos at compile / load time. Worked example: `b67f062` (β.12b `WindowsFindingSource = Literal["windows_authenticode", "windows_dbx_revoked"]`) — used by the helper's `_PEFindingDraft.source` field, the typed module-level constants `_SOURCE_AUTHENTICODE: WindowsFindingSource = "windows_authenticode"` / `_SOURCE_DBX_REVOKED: WindowsFindingSource = "windows_dbx_revoked"`, and the helper's emit signature; `FindingCreate.source: str` is unchanged so the 18 legacy callers continue to work. The DB CHECK constraint `ck_findings_source` (extended in β.12a `c5b6a7d8e9f0`) enforces the full 20-source allowlist as the safety floor.

    **(d) `asyncio.create_task` vs arq decision rubric.** Use **arq** if (i) the work coordinates with worker-only resources (Docker container spawn, long-form Ghidra), OR (ii) work survives backend restarts via durable Redis-queue state, OR (iii) work needs scheduled/cron triggering. Use **asyncio.create_task** if (i) work runs entirely in-process, AND (ii) intermediate state is incrementally persisted to the DB by the work itself (so a mid-run crash is recoverable via re-run dedup), AND (iii) "fire and observe via row-status" is sufficient. Current applications: cve-match → asyncio.create_task (in-process matcher with per-batch `db.flush()`); emulation → arq (Docker spawn = worker resource); fuzzing → asyncio.create_task (Docker spawn delegated to a separate already-arq path); firmware-unpack → arq (long-running, multi-stage, restart-survival valuable). Anti-pattern: defaulting to arq "for durability" without applying the rubric — adds worker job + registration churn + Rule #8 rebuild cost for no semantic gain when the work is already DB-persisted.

    **Reference shape** (background runner owns its own AsyncSession via `async_session_factory`; outer guard catches anything; failure persistence on a fresh session because the inner one rolled back):

    ```python
    async def _run_<op>_background(<id>: uuid.UUID, *args) -> None:
        try:
            async with async_session_factory() as db:
                row = (await db.execute(select(Model).where(Model.id == <id>))).scalar_one_or_none()
                if row is None: return
                row.status = "running"; row.started_at = datetime.utcnow()
                await db.commit()
                try:
                    result = await do_work(...)
                    row.status = "completed"; row.finished_at = datetime.utcnow()
                    row.result = result.model_dump()
                    await db.commit()
                except Exception as exc:
                    await db.rollback()
                    err = "\n".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-2000:]
                    async with async_session_factory() as fail_db:
                        fail_row = (await fail_db.execute(select(Model).where(Model.id == <id>))).scalar_one_or_none()
                        if fail_row is not None:
                            fail_row.status = "failed"; fail_row.error = err
                            await fail_db.commit()
                    logger.exception("...")
        except Exception:
            logger.exception("unrecoverable")  # outer guard

    @router.post("/<op>", response_model=StatusResponse, status_code=202)
    async def run_<op>(...) -> StatusResponse:
        if row.status in ("queued", "running"):
            raise HTTPException(409, f"<op> already {row.status}")
        row.status = "queued"
        row.started_at = None; row.finished_at = None; row.error = None; row.result = None
        await db.commit()  # background task's fresh session must see this
        asyncio.create_task(_run_<op>_background(row.id, ...))  # OR arq enqueue per (d)
        return _row_to_status(row)

    @router.get("/<op>/status", response_model=StatusResponse)
    async def get_<op>_status(...) -> StatusResponse:
        return _row_to_status(row)
    ```

    Frontend pairs this with `useEffect + setInterval` polling every 2 s on `/<op>/status` until `status in ("completed", "failed")`, matching the firmware-unpack precedent. The axios timeout drops to the default 30 s floor (no override needed) since the ack is sub-second per (a). Companion to Rule #29 (when), Rule #25 (per-sub-task commits — typically ships in 3 commits: DB migration / router-and-frontend pair / intake closure), Rule #11 (post-rebuild import smoke after the new ORM fields land), Rule #32 (skip the no-op `db.refresh(row)` after commit). Originally extracted from session 76fd9c3a (2026-04-25) cve-match closer; validates against 4 prior shipped applications.

34. **Run `unblob` with `--no-sandbox` (and any browser-initiated download URL must carry the API key as a query param).** Two co-discovered defects from session b266f17e (2026-04-30) on a single user-reported "files appear 0B and won't download" symptom — the bugs were independent but presented as one. (a) **unblob's Landlock sandbox induces EXDEV on `link()`** when sasquatch creates hardlinks during squashfs extraction. sasquatch FATAL-aborts mid-stream; `creat()`'d-but-unfilled files remain 0 bytes. Affects every Linux rootfs squashfs (typically thousands of hardlinks for `/bin/busybox` symlinks, library symlinks, etc.). Mechanical tell: the on-disk extracted tree has >25% zero-byte regular files **AND** zero hardlinks **AND** the zero-byte set is dominated by binaries/libraries (not device nodes). Refined audit grep that excludes legitimate empty-file paths: `find <ep> -type f -size 0 -not -path '*/dev/*' -not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/var/run/*' -not -path '*/var/log/wtmp*' -not -path '*/var/log/utmp*' -not -path '*/var/log/lastlog*' -not -path '*/var/log/btmp*' | wc -l` paired with `find <ep> -type f -links +1 | wc -l` (a healthy Linux rootfs has hundreds-to-thousands of hardlinks; a sandbox-killed extract has 0). Naïve `-size 0` count over-flags small embedded firmwares (GS724Tv6 NetGear: 58 zero-byte = 100% legitimate device nodes + log placeholders out of 124 total). The two-condition test (real-file zeros AND hardlink count) cleanly distinguishes broken vs minimal-but-correct. The fix is `--no-sandbox` on the unblob CLI invocation in `backend/app/workers/unpack_common.py:730`; the worker container is the actual security boundary (`docker compose.yml` constrains mounts), so Landlock is redundant defense-in-depth. Sasquatch decoded-stderr signature (base64-decoded from unblob's `ExtractCommandFailedReport`): `create_inode: failed to create hardlink, because Invalid cross-device link` then `FATAL ERROR`. Repro/verify: `unblob --no-sandbox --extract-dir /tmp/out <sq>` produces N-fold more non-zero files than the sandboxed run on the same input. Audit existing extractions: `find /data/firmware/projects/*/firmware/*/extracted -type f -size 0 | wc -l` per firmware row; >25% zero-byte rate ⇒ broken extraction, re-trigger unpack via arq `unpack_firmware_job` after clearing `extracted_path` / `extraction_dir` / `device_metadata.detection_roots` and resetting `project.status`. (b) **`<a href={url} download>` anchor clicks don't carry custom HTTP headers.** wairz's auth is API-key via `X-API-Key` header (axios interceptor at `frontend/src/api/client.ts:37`), with `api_key=<key>` query-param fallback used for WebSockets via the existing `appendApiKey(url)` helper. The download URL helpers `getFileDownloadUrl` (`frontend/src/api/files.ts`) and `getDocumentDownloadUrl` (`frontend/src/api/documents.ts`) returned bare URLs without `appendApiKey()`, so every browser-initiated download to an authed backend hit `401 Missing or invalid API key` from `app/middleware/asgi_auth.py`. Generalised rule: any URL passed into a `<a href download>`, `<img src>`, `window.open()`, `window.location.href = ...`, or anywhere else the BROWSER (not axios) issues the request must wrap with `appendApiKey()`. The `X-API-Key` header path applies to fetch/axios calls only — anything that produces a navigation, anchor click, or HTML element src/href is browser-issued and bypasses the interceptor. Mechanical detection: `grep -RIn "href={[^}]*[Dd]ownload\|window\.open\|window\.location\.href\s*=" frontend/src/ | grep -v "appendApiKey"` should be zero. The query-param leak into uvicorn access logs is the same tradeoff already accepted for the WebSocket terminal/emulation paths; documented in `frontend/src/api/client.ts:25`. **Cross-cutting lesson:** a single user report ("symptom X") frequently masks two unrelated bugs hitting the same UX surface — the file viewer's "0B + can't download" looked like one bug (e.g. symlink-handling regression) and was actually two: backend extraction corruption + frontend download auth. Always verify each sub-symptom independently — testing a non-zero file's download path in this session distinguished the auth bug from the extraction bug. Companion to Rule #11 (test split changes don't surface bugs that only appear at runtime — same shape: each sub-symptom needs its own test).

35. **Verification artefacts can lie — exit codes, mock assertions, and JSONB shape assumptions all need a canary probe.** Three independent verification-discipline failures from session 2026-05-04 (`unpack_audit_service` implementation, commits `877f83e..057ea67`), each masked by an artefact that LOOKED like success. The unifying meta-lesson: when a verification mechanism reports "passed", ask which CONTRACT it actually checked — and probe with a deliberate canary if the contract is weaker than you assumed.

    (a) **`cmd | tail -N; echo "exit=$?"` reports `tail`'s exit, not `cmd`'s** — sub-case of Rule #17, pipe-induced. The first Rule #24 canary attempt `npx tsc -b --force 2>&1 | tail -5; echo "exit=$?"` printed the type error AND `exit=0` together, which is impossible if tsc actually exited non-zero. Pipes implicitly subshell; `$?` after a pipeline reflects the LAST command (`tail`), not the first (`tsc`). The Bash tool does NOT enable `set -o pipefail` by default. **How to apply:** when capturing an exit code, run the command directly (`cmd; ec=$?`); if you must pipe for output, use `set -o pipefail` explicitly, capture with `${PIPESTATUS[0]}` after the pipeline, or split into `cmd > /tmp/out; ec=$?; tail -5 /tmp/out`. The clean replacement for the canary above is `npx tsc -b --force; echo "real tsc exit=$?"` (no pipe). Generalises Rule #17 to a SECOND silent-exit mechanism: cache-hit short-circuit (Rule #17 original) AND pipe-induced exit obfuscation (this rule). Companion to Rule #24's mandatory tsc canary — both rely on a verifiable exit code; both are useless if the exit code is intercepted en route.

    (b) **Mock unit tests verify "X was called", not "X was called WITH the right args".** 17 mock-based tests passed cleanly asserting `mock_db.add.call_count == 4`. The C3 live canary against firmware `6f8f9cc2-…` immediately surfaced `confidence=None` in persisted Finding rows; the bug lived inside `FindingService.create()`'s body — the `Finding(...)` constructor was called WITHOUT `confidence=data.confidence.value`. The mock replaced the SESSION (not the FindingService), so tests never observed constructor arguments. Pre-existing 2-line bug masked for months because no other scanner explicitly emits confidence. Fix landed in commit `7dc21fe` in-band with the C3 wiring. **How to apply:** after mock unit tests pass, run the new code ONCE against an actual production row (or a freshly-created fixture row that goes through the real ORM/service path), then SELECT the persisted row and inspect every field the service explicitly sets — not just call counts. Mocks verify the contract you wrote; live canaries verify the contract the called code actually has. Companion to Rule #11 (post-split runtime smoke — same shape: `py_compile` says passes, runtime says otherwise) and Rule #19 (evidence-first — same shape: spec describes intent, the DB describes truth). Cost is ~1 second on a real row; eliminates value-flow bugs that mocks structurally cannot catch. Stronger formulations of the mock test (e.g. `mock_db.add.assert_called_with(Finding(confidence='high', ...))` via a captor) catch SOME of these but not all — a captor still trusts the helper to forward args, which is exactly what was broken here. The live canary is the only fully-general check.

    (c) **JSONB without a `schema_version` discriminator forces every consumer to normalize at the boundary.** `firmware.device_metadata['vendor_decryption']` exists in two production shapes — canonical `list[dict]` (modern unpack worker output, `unpack_common.py:451`) and legacy `dict` with `blobs: list[str]` (pre-list-shape rows or hand-authored). Both variants coexist in the same table. New consumer `unpack_audit_service._extract_aes_key_findings` ran the canonical access pattern `[entry.get(...) for entry in audit]`; the legacy shape raised `AttributeError: 'str' object has no attribute 'get'` when the backfill hit firmware `5b7735cd-…`. **How to apply:** when introducing a new JSONB shape, EITHER (i) add a `schema_version` key from day one so consumers can discriminate via `match meta.get("schema_version", 1):`, OR (ii) commit each consumer to normalising at the boundary via a dedicated `_normalize_<field>(value: <canonical> | <legacy> | None) -> <canonical>` function. Boundary-normalisation is durable — old data accumulates indefinitely; consumers come and go; an alembic migration to rewrite JSONB across hundreds of rows is heavier than a 15-line normaliser, AND the migration doesn't help the NEXT shape variant. Reference shape: `_normalize_vendor_decryption` at `backend/app/services/unpack_audit_service.py:104` (commit `057ea67`) accepts list, dict-with-blobs, and unparseable inputs idempotently. Audit grep when introducing a new JSONB consumer: `grep -rn 'device_metadata\[.<key>.\]\|device_metadata\.get(.<key>.' backend/app/` — every hit is a normalisation candidate. Companion to Rule #19 (evidence-first: measure existing data shapes with `SELECT jsonb_typeof(device_metadata->'<key>') FROM firmware GROUP BY 1;` BEFORE assuming uniformity) and Rule #6 (CLI-flag verification — same generalised lesson: never assume the surface; measure with real data). Backfill-as-discovery (Pattern #6 of `unpack-audit-findings-2026-05-04-patterns.md`) is the natural canary — running the new consumer against ALL qualifying production rows surfaces shape drift as a diagnostic exception, not silent skip.

36. **No-execute discipline for installer custom actions, package install scripts, and bundled co-installer DLLs.** Wairz is a forensic extraction + analysis platform — it parses Windows installer / package archives (MSI / MSIX / MSU / DriverPackage / .NET bundles / future Linux .deb postinst hooks) for static-analysis purposes. The artifacts these archives carry — MSI Custom Action rows (CA table: VBScript / JScript / EXE / DLL invocations), MSIX `desktop:Extension` install scripts, MSU `_manifest.cab` post-install hooks, DriverPackage co-installer DLLs (per the INF `[ClassInstall32]` / `[CoInstaller]` sections), .NET single-file bundle entry points — MUST be surfaced to the operator as **data**, never invoked. The worker is the security boundary; running attacker-controlled installer code inside the worker container would defeat the boundary even if a Docker escape didn't follow.

    **Mechanical rule:** extracted artifacts may be written to the firmware tree and read by analysis tools (signify / pefile / radare2 / Ghidra / ilspycmd / asn1crypto). They MUST NOT be passed to any process-spawn primitive that would invoke them: `subprocess.run`, `subprocess.Popen`, `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell`, `os.system`, `os.execvp`, `runpy.run_path`, `importlib.import_module(<path-derived>)`, `eval`, `exec`, etc. CALLING signify/pefile to PARSE a PE is fine (signify reads the file; it does not transfer control to the PE). CALLING `wine /path/to/CustomAction.exe` is the rule violation.

    **Detection grep when authoring an unpacker for a new installer format:** for every extracted file path that lives inside the unpacker's emit set, no code path in the worker should pass it as `argv[0]` to a spawn primitive. Repo-wide audit: `grep -rn 'subprocess\.\(run\|Popen\|call\|check_output\|check_call\)\|asyncio\.create_subprocess_\(exec\|shell\)\|os\.\(system\|execvp\|execve\|spawnvp\)' backend/app/workers/unpack_*.py` — every hit must have its `argv[0]` resolve to a TRUSTED binary that's part of the wairz worker image (cabextract, msiextract, 7z, qemu-img, etc.), NEVER an extracted artifact path. `argv[1+]` carrying an extracted path as a filename to one of those trusted binaries is fine — `cabextract <unsafe.cab>` reads the cab as data, doesn't execute it.

    **Test gate:** every `unpack_<format>.py` whose archive may carry executable hooks ships a test that scans `result.unpack_log` AND the extracted tree for forbidden-token combinations. α's `test_unpack_msi.py::test_msi_no_custom_action_execution` is the canonical shape — assert `"CustomActionType" in unpack_log → custom actions surfaced as data` AND `assert no `wine` / `mono` / `dotnet` / `cscript` / `wscript` invocation in any spawn list`. The test is cheap (string scan over the unpack_log) and protects against a future contributor adding "convenience" execution.

    **Exceptions (must be EXPLICITLY documented in the unpacker docstring):**
    - **Trusted, image-shipped binaries operating on extracted artifacts AS DATA** are allowed — e.g. `qemu-img convert -f vhdx -O raw <extracted.vhdx> <out.raw>` is image-shipped qemu-img reading the vhdx as data. Same shape: `signify` reading a PE; `ilspycmd` reading a .NET DLL.
    - **Sandboxed analysis environments** (Qiling user-mode emulation, FirmAE system-mode emulation, AFL++ fuzzing) DO invoke extracted binaries — but inside heavily-isolated Docker containers with documented security boundaries (CLAUDE.md "Security #2"). These run under explicit user opt-in via the emulation/fuzzing routers, never as a side effect of unpacking.

    **Worked examples:**
    - α.2 (`508feca`) — `unpack_msi` extracts MSI tables via `msiextract`; CustomAction rows are surfaced into `unpack_log` for operator review; never invoked. Test gate: `test_msi_no_custom_action_execution`.
    - α.2.4 (`8086c32`) — `unpack_msu` chains MSU → CAB-of-CABs via `cabextract`; PSF stub detected for separate side-container handling (β.X), never composed-and-executed inline.
    - α.2.6 (`8516fa2`) — `unpack_driver_package` extracts INF + SYS + CAT triplet; INF is parsed for metadata but never `rundll32`'d; SYS/CAT are passed to signify for chain validation, not loaded.
    - α.2.7 (`b9d124d`) — `unpack_vhdx` runs `qemu-img convert` (trusted, image-shipped) to convert VHDX → raw; the raw image is then walked by NTFS parsers, never booted.

    **Companion to Rule #19** (evidence-first — the rule applies to security boundaries too: read the unpack_log + spawn list before assuming an unpacker is execute-clean) and **Rule #29** (timeout discipline — a CustomAction.exe that DID get executed would block the worker indefinitely without a timeout; the no-execute rule prevents the failure mode at the source). Promoted from α-phase precedent (Phase α.2.x worked examples) at the end of Phase β.10, codifying what the campaign already practiced.

37. **Offline-trust-anchor discipline for cert roots / DBX / vendor PEM bundles.** Trust anchors used to verify signed firmware artifacts (Microsoft Authenticode root chain, UEFI Secure Boot DBX revocation list, vendor PEM bundles, certificate transparency anchors, OCSP responder caches if/when adopted) MUST be baked into the worker / backend image at **build** time — they MUST NOT be fetched from the network at **scan** time, even with caching.

    **Why scan-time fetches are the wrong shape:**
    - Air-gapped / offline-deployed wairz instances break — every scan needs network egress to a moving target.
    - Microsoft / GitHub / Mozilla / vendor CDNs rate-limit; a burst-scanning operator hits 429s mid-firmware and DBX matching silently degrades for some PEs but not others.
    - A network attacker positioned between the worker and the upstream can swap the trust anchor (Microsoft's root → an attacker root) and every PE in the firmware suddenly chains-and-validates against attacker-controlled trust. TLS to GitHub helps but isn't sufficient — the URL itself becomes attacker-influenced if DNS or BGP is in play.
    - Cache invalidation adds complexity to every scan path that didn't need it.
    - Reproducibility: two scans of the same PE against the same wairz image must produce the same verdict; a network fetch makes the verdict a function of "what Microsoft was serving when this scan ran".

    **Why build-time bundling is the right shape:**
    - The image is a stable, hashable artifact; SHA256 of the bundled file is verified at build via `sha256sum -c`; corrupted commit OR Microsoft publishing a new revision both fail the build loudly.
    - Refresh is a deliberate, out-of-band operation (host-side cron) that exits non-zero on drift; the operator reviews + commits + rebuilds.
    - Every scan against the same image yields the same verdict.
    - The worker container has **zero** network egress requirement for trust-anchor purposes (egress is reserved for genuinely-network-bound features: NVD CVE lookup, vulhunt MCP, etc., all already documented).

    **Mechanical rule (when adding a new trust-anchor source):**
    - Anchor binary lives in `backend/ms-anchors/` (or an analogous build-time-asset directory: `backend/vendor-anchors/`, `backend/ct-anchors/`, etc.) with three sidecars: `<anchor>.sha256` (sha256sum-format pin), `<anchor>.url` (single-line canonical source), and a directory-level `README.md` documenting the refresh process.
    - Dockerfile delta: `COPY` the anchors directory + `RUN sha256sum -c <anchor>.sha256` + place at a known runtime path (`/opt/wairz/<anchor>`) + chmod 0444 + chown wairz.
    - docker-compose.yml: set the env var the consuming service reads (e.g. `DBX_BUNDLE_PATH=/opt/wairz/dbxupdate.bin`) on BOTH backend AND worker.
    - Service reads ONLY from the in-image path. If the file is missing OR malformed OR oversized, log a WARNING and degrade GRACEFULLY — return the truthful "no trust info available" verdict (e.g. `dbx_revoked=False` with `bundle_entries=0` flagged in logs), NOT a fabricated answer (e.g. `revoked=True` because "we don't know" is not the same as "we know it's revoked").
    - Backend lifespan startup probe: log presence + size + mtime so operators can confirm the bundle survived the build / cron-refresh schedule held. Anything other than "ready: size=N mtime=…" is a cron-alert candidate.
    - Refresh handled by a host-side cron script (`scripts/refresh-<anchor>.sh` shape) that: (1) downloads the live artifact atomically (`.tmp` + rename per Rule #19 atomic-write discipline), (2) computes SHA256, (3) compares against the pinned hash, (4) exits non-zero on drift, (5) supports `--apply` for auto-pin-update + `--rebuild` for `docker compose build --no-cache --pull worker backend`. Quarterly schedule for slow-moving anchors (DBX, MS roots); monthly for faster (CT logs).

    **Wrapper-format discovery is part of the bundling work.** When the canonical artifact carries an outer authentication wrapper (Microsoft DBXUpdate.bin's 3337-byte EFI_VARIABLE_AUTHENTICATION_2; Microsoft authroot.stl's PKCS#7 envelope; Mozilla certdata.txt's Mozilla-format wrapper), the parser MUST be extended to detect + strip the wrapper at load time. Synthetic test fixtures that use the bare format pass through unchanged via shape-detecting heuristics — wairz does NOT verify the wrapper's PKCS#7 signature (the SHA256 pin is the integrity check; we trust the build-time download). Bare β.7 dbx_service was wrapper-blind; β.10 added `_strip_authenticated_variable_wrapper` with year-range + wType==0x0EF1 detection.

    **Detection grep when reviewing a security-sensitive service:** `grep -rn 'curl\|wget\|httpx\|requests\.\(get\|post\)\|aiohttp\|urllib\.' backend/app/services/<security-related>/` — if any matches resolve to cert-bundle URLs, vendor root URLs, DBX URLs, or CRL/OCSP responders called at scan time, the rule is being broken.

    **Worked examples:**
    - β.4 (`d12f64e`) — Microsoft Authenticode roots: signify ships TRUSTED_CERTIFICATE_STORE inside its package; wairz consumes via signify's API. (Signify being a Python package IS the build-time bundle.)
    - β.10 (`856b640`) — UEFI Secure Boot DBX: `backend/ms-anchors/dbxupdate.bin` (24,053 bytes pinned by SHA256), Dockerfile COPY + sha256sum -c, /opt/wairz/dbxupdate.bin, DBX_BUNDLE_PATH env var on backend+worker, `scripts/refresh-ms-roots.sh` quarterly cron. EFI_VARIABLE_AUTHENTICATION_2 wrapper-strip extension caught the format-mismatch before it shipped a non-functional bundle.

    **Companion to Rule #36** (no-execute — same shape: the worker is the security boundary, and operations that defeat it from a different angle (executing untrusted code OR fetching untrusted trust anchors) are equally forbidden), **Rule #19** (evidence-first — the wrapper-format discovery in β.10 came from `xxd dbxupdate.bin | head` BEFORE writing parser code, not after a bug report), and **Rule #25** (per-sub-task commits — bundle + Dockerfile + cron + tests is one atomic Rule #25 commit; the rebuild runs once after). Promoted at the end of Phase β.10, codifying what β.4 + β.10 already practice.

38. **Bash tool: prefer absolute paths and `git -C <repo>` over `cd X && ...` compounds.** The Bash tool's working directory IS persisted across calls (per the Bash-tool docstring: "the working directory persists between commands, but shell state does not"), so `cd backend && uv run pytest tests/foo.py` leaves the shell in `/home/dustin/code/wairz/backend/` for the NEXT call; a subsequent `git status backend/...` resolves the relative argument against `/home/dustin/code/wairz/backend/backend/`, returning `warning: could not open directory 'backend/backend/'` + `fatal: ambiguous argument`. The system instructions already recommend this discipline (system-prompt Bash section: "Try to maintain your current working directory throughout the session by using absolute paths and avoiding usage of `cd`. … never prepend `cd <current-directory>` to a `git` command"); this rule is the wairz-specific reinforcement with worked-example incidents. **How to apply:** for git invocations use `git -C /home/dustin/code/wairz <subcommand>` rather than `cd /home/dustin/code/wairz && git <subcommand>` (the former matches the system prompt's explicit guidance on `git` compounds AND avoids the permission-prompt trip). For `uv run pytest` / `npx tsc -b --force` / `alembic upgrade head` and other tools that need a specific cwd, use a subshell `( cd backend && uv run pytest ... )` form so the `cd` is scoped to the parens and doesn't leak into the next call. **Worked examples:** β.10 antipattern #3 (`.planning/knowledge/windows-coverage-godmode-beta10-beta13-2026-05-08-antipatterns.md`) — originally caught (Rule-of-One). β.12 postmortem "What Broke" #1 (`.planning/postmortems/postmortem-windows-coverage-godmode-beta12-2026-05-08.md`) — CWD drift after `cd backend && uv run pytest tests/test_finding_service_pe_emit.py`; recovered via absolute paths (`git -C /home/dustin/code/wairz status --short backend/...`) — Rule-of-Two. δ.9 antipattern #5 (`.planning/knowledge/windows-coverage-godmode-delta-2026-05-09-antipatterns.md`) — caught mid-flow via `pwd` self-inspection after a `cd /home/dustin/code/wairz/backend && uv run python -c "..."` invocation drifted the cwd; reset with explicit `cd /home/dustin/code/wairz` BEFORE any git command resolved against `/backend/backend/...`. Net 0 incidents in the commit log; the catch validates the discipline rather than violating it. Discipline is durable now (Rule-of-Three across γ + δ clean sessions); future occurrences should be flagged as a regression rather than a fresh discovery. **Catch-and-correct mid-flow:** if a `cd <subdir> && <tool>` invocation has already drifted the cwd (e.g. you went into `backend/` for an alembic ID enumeration or a uv subprocess), the very next Bash invocation should be either `cd /home/dustin/code/wairz` or use absolute-path forms for everything that follows. Mechanical self-check: `pwd` costs ~1 second; the alternative (a git command resolving against `backend/backend/...`) costs ~30 seconds to recover and produces a confusing `fatal: ambiguous argument` error trail. Subshell form `( cd backend && uv run pytest ... )` scopes the cd to the parens and prevents the drift entirely — prefer this shape over a bare `cd backend && uv run ...`. Companion to Rule #20 (docker cp + alembic — same family of bash-discipline reminders for the wairz iteration loop) and Rule #35a (pipe-induced silent exit — both rules cover bash-tool invocation hygiene that's invisible until you trip it).

39. **Background runners that own a Rule #33 .a state machine ship as an inner/outer/safe runner triplet.** Three independent functions per service module — each with a distinct caller, a distinct session-ownership shape, and a distinct failure semantics:

    - `_do_<op>_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict` — **INNER pure-logic orchestrator.** Accepts `db` from the caller. Resolves detection roots via `get_detection_roots(firmware)` (Rule #16). Walks + parses + aggregates the artefact in question. Returns the result dict UNSTAMPED (caller stamps via `_stamp_<table>_<column>(payload)` per Rule #35c). Does NOT mutate row.status. Does NOT call `commit()` (the OUTER caller owns the transaction). This is the function tier-1 tests call via `make_live_db()` — single round-trip; deterministic; no Docker DNS dependency.

    - `run_<op>_background(firmware_id: uuid.UUID) -> None` — **OUTER state-machine wrapper.** Owns the 5-state Rule #33 .a transitions (`idle → queued → running → completed | failed`) via `async_session_factory()`. Calls inner. Outer guard catches anything that escapes (`except Exception` at the top level + `logger.exception("unrecoverable")`). Failure persistence on a FRESH session because the inner session rolled back on the exception. This is the function the router endpoint enqueues via `asyncio.create_task` or arq job dispatch.

    - `auto_<op>_firmware_safe(firmware_id: uuid.UUID) -> None` — **UNPACK-POST-DETECTION HOOK.** Owns own session via `async_session_factory()`. Swallows exceptions silently (`logger.exception` + return). Stamps the result aggregate so operators can see the walk happened, but **DOES NOT mutate the firmware status field** — leaves it `idle` so a manual re-trigger via the trigger MCP tool works without 409 conflict (Rule #33 .a). Called from `app/workers/unpack.py` after detection roots are computed; never blocks unpack on failure.

    **Rule-of-Five precedents:**
    - γ.4 (commit `3161a70`, 2026-05-08) — `registry_hive_walker.py` — IMPLICIT first application; the three runners were authored organically without naming the pattern.
    - δ.5 (commit `8b3c4d5`, 2026-05-09 — actual SHA on δ branch) — `windows_update_diff_service.py` — first EXPLICIT codification with the function-name discipline.
    - ε.1.b.3 (commit `c0e4979`, 2026-05-10) — `evtx_service.py` — second EXPLICIT codification confirming the shape.
    - ζ.2.B (commit `f076808`, 2026-05-10) — `prefetch_walker.py` — fourth application; recipe applied without deviation.
    - ζ.3.B (commit `661355c`, 2026-05-10) — `srum_walker.py` — fifth application; recipe applied without deviation. Same-day authoring as ζ.2.B confirmed the recipe is now under-1-day per walker.

    **Pitfall — DO NOT call the outer wrapper from tier-1 tests.** `run_<op>_background` opens its own `async_session_factory()` session; under the dev-host pytest environment (no Docker container, no resolvable `db:5432`), this raises `socket.gaierror: [Errno -2] Name or service not known`. Tier-1 tests MUST call the INNER runner with a `make_live_db()`-provided session. Outer + safe wrappers are validated via integration tests against a real container OR via mocks of the session factory.

    **Companions:** Rule #33 .a (state-machine ownership), Rule #35b (live canaries against the inner runner), Rule #16 (detection roots inside the inner runner), Rule #11 (post-rebuild import smoke for the new triplet — verify all three exports), Rule #19 (probe library API shape before drafting the inner walker — `inspect.getsource` on the parser entry-point catches yield-shape surprises in seconds). Recipe: `.mex/patterns/inner-outer-safe-runner.md`. Promoted from γ.4 + δ.5 + ε.1.b.3 Rule-of-Three at the end of the windows-coverage-godmode housekeeping campaign (2026-05-10); reinforced to Rule-of-Five by ζ.2.B + ζ.3.B same-session same-day applications.

40. **Function-local imports MUST sit at the top of the function body, BEFORE any reference to the imported name.** Python's local-binding rule promotes ANY in-function `import X` (or `from X import Y`) to a function-scope local for the WHOLE function body — so a reference to X BEFORE the import line raises `UnboundLocalError` at runtime (ruff: F823 "local variable used before assignment"). The bug is silent until (i) the codepath is actually exercised AND (ii) the surrounding lint workflow runs to completion past that line. Mechanical detection: ruff F823 catches it; LLMs frequently emit this shape when refactoring (a "move-and-leave-old-import" mid-function pattern). The fix is purely positional — move the import to the first statement of the function body. Equivalent rule under nested blocks (`if`/`try`/`for`): the import binds to the enclosing FUNCTION scope, not the block, so placement inside a nested block still affects the whole function's name resolution — keep the import at the very top of the function. **Worked example:** `app/ai/tools/emulation.py:2627` `_handle_emulate_with_qiling()` had `import asyncio` inside the function body AFTER first reference to `asyncio.create_subprocess_exec`. Surfaced in commit `cae7547` (async-cleanup-2026-05-11 Phase E.8) when concurrency-cancel finally let a Lint run reach that codepath; sat latent in main for weeks before that. Fixed in `6376d8d` (Phase D.39) by moving the `import asyncio` to top-of-function. **Companions:** Rule #11 (split-file constants — runtime smoke before trusting that imports resolve), Rule #30 (lazy-import patch targets — function-body imports complicate `unittest.mock.patch` resolution; if the function-body placement is itself legitimate per Rule #30's optional-dep / licensing / cycle reasons, the rule still requires top-of-function placement so F823 doesn't fire). Promoted on Rule-of-One strength of mechanical rigor rather than recurrence — the failure mode is universally Pythonic and the fix is a single-line positional move. Promotion date: 2026-05-12 (async-cleanup-2026-05-11 Phase H).

41. **Per-piece direct-push CI with `concurrency: cancel-in-progress` saves runner minutes but DELAYS defect detection at boundary commits — schedule consolidation pauses.** Pattern P5 (per-piece direct-push) plus GitHub Actions' `concurrency.cancel-in-progress: true` cancels each intermediate commit's CI within seconds of the next push. Saves ~30+ Backend Tests runs across a 60-commit campaign. Cost: a latent bug whose first surface is at byte N of file F may sit undetected for arbitrarily long if no commit happens to be "last" long enough for CI to reach that codepath. The BOUNDARY commit (the one before a session-end pause or before CI completes uninterrupted) is the one that surfaces accumulated defects. **Mitigations** (apply when sustained per-piece cadence > 5-10 commits): (a) schedule a "consolidation pause" every 5-10 commits — the NEXT commit waits for CI to complete on the previous before pushing (cost: 5-10 min idle; benefit: defects surface within 10 commits rather than 60); (b) run a broader local-side gate before any session-boundary commit — `( cd backend && uv run ruff check --no-cache . )` with NO `--select` filter (full ruleset) catches latent debt the active campaign isn't supposed to fix but might surface; (c) watch `gh run list` for `conclusion: cancelled` on Lint runs — that's a signal CI did not reach the lint codepath that might surface a defect. **Rule-of-Two evidence:** parent campaign `windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-09` documented P5 as a success pattern (P5 in `.planning/knowledge/windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-09-patterns.md`); async-cleanup-2026-05-11 documented its antipattern surface — F823 in `emulation.py:2627` masked across ~30 cancelled Lint runs (Rule #40 incident). The success/antipattern pairing is the full rule shape. **Companions:** Rule #25 per-sub-task commits (enables the cadence that triggers concurrency-cancel), Rule #40 (the specific failure mode masked by concurrency-cancel in 2026-05-12), Rule #17 (silent-CLI-exit canary — same family: a `cancelled` CI conclusion is structurally indistinguishable from "didn't get a chance to run" without explicit attention). Promotion date: 2026-05-12 (async-cleanup-2026-05-11 Phase H).

42. **Helper extraction during multi-file sweeps — when 3+ files share the same N-call sync sequence, extract a helper at first encounter then roll out to the rest.** Shape: a per-file fix sweep reveals the SAME repeated 3+-call pattern across N similar files. The right move is not to write N duplicate fixes — it is to extract a helper at the FIRST encounter, then roll out the helper to the remaining N-1 files in a batched commit. The campaign output is DURABLE CODE (the helper), not just lint-quiet decoration; future similar files use the helper by default, preventing the same shape from accreting again. **Mechanical detection during a sweep:** when you find yourself writing the SAME executor wrap / SAME noqa rationale / SAME try-except / SAME 3-call sequence in the 2ND file, STOP and grep for the pattern across all in-scope files. If it appears in 3+, extract — the saving is N-1 future patches plus the durable factorization. **Boundary — don't over-generalize.** The helper should be specific to its caller pattern (`reset_extraction_dir_sync` is for unpack workers' extraction-dir reset, NOT "any rmtree+makedirs anywhere"). Generic helpers that try to cover too many shapes become unwieldy parameter-bags. The right scope is: same N+ caller files, same pre-/post- conditions, same failure semantics. **Rule-of-Two evidence:** (a) Phase 2 of `feature-extraction-integrity` (commit `ceade9a`) — `get_detection_roots(firmware)` extracted from scatter-zip + multi-archive walk logic; subsequently codified as Rule #16. (b) async-cleanup-2026-05-11 D.34 (`821762a`) — `reset_extraction_dir_sync(extraction_dir)` in `app/workers/unpack_common.py:17` combining `os.path.exists` + `shutil.rmtree` + `os.makedirs` into ONE sync function suitable for a single executor hop (Rule #5 minimum-hop discipline); rolled out to 6 unpack workers in D.35 (`a07ed26`) + 1 late-discovery in D.37 (`a0ef530`). **Companions:** Rule #25 per-sub-task commits — the helper extraction + rollout is one commit per helper-batch (the rollout-of-N commit is genuinely independently revertable because it's pure call-site substitution); Rule #5 (the helper enforces minimum-hop executor wrapping at the call site); Rule #27 (additive-then-cut-over for file-level decomposition — Rule #42 operates at the function level, Rule #27 at the module level). Promotion date: 2026-05-12 (async-cleanup-2026-05-11 Phase H).

43. **Per-line `# noqa: <CODE> — <rationale>` is the correct closure for lint rules that fire on syntactic matches semantically safe in the calling context — required rationale categories must apply.** When a lint rule's syntactic match is semantically safe (the code looks like a violation but is provably bounded / pure / contract-required), the right closure is per-line noqa with a rationale comment, NOT executor wrap, NOT module-level suppression, NOT rule suppression at the project level. The rationale comment turns the suppression into a TYPED DECLARATION of why-this-is-fine that future code review can verify. **Required format** — `# noqa: <CODE> — <one-line rationale>` with the em-dash and a one-line explanation. NEVER bare `# noqa: <CODE>` (Decision D4 explicit prohibition; without rationale, future maintainers cannot tell whether the suppression is legitimate or accumulated tech debt) and NEVER multi-line (the rationale must fit in one comment to remain greppable). **The 4 rationale categories that authorize a noqa:** (1) **Single pre-flight stat before a sync subprocess** — `# noqa: ASYNC240 — pre-flight stat before bounded sync subprocess`. The subprocess itself is wrapped per Rule #29; the stat is bounded to one call per request and doesn't justify a separate executor hop. (2) **Pure-string path math** — `# noqa: ASYNC240 — pure-string path math; no filesystem I/O`. `os.path.relpath` / `.join` / `.basename` / `.dirname` / `.splitext` / `.normpath` / `.expanduser` / `Path(...).name` / `.parent` / `.suffix` / `.parts` touch nothing on disk; ruff matches them uniformly with the I/O-touching siblings. (3) **Bounded loop over detection roots** (Rule #16 partner) — `# noqa: ASYNC240 — bounded loop over ≤3 detection roots`. `os.path.realpath` / `.stat` inside a `for root in get_detection_roots(firmware)` loop is bounded by the detection-root count (typically 1-3); the overhead of executor-wrapping each iteration exceeds the win. (4) **Caller-supplied `timeout=` parameter** (Rule #29 contract) — `# noqa: ASYNC109 — caller-supplied timeout per Rule #29 contract`. When an async function exposes `timeout=` as a per-call override plumbed through to a `wait_for` / `subprocess` with explicit value, the param is intentional and the ASYNC109 firing is a false positive at the API boundary. **Why categories?** Code review can ASK "which category does this fit?" — if none, the fix is wrong (executor wrap, refactor, or different shape needed). The rule is forward-protective: future review can REJECT a noqa-with-rationale that doesn't match a category, preventing rationale-prose drift into accumulated tech-debt theatre. **Rule-of-One evidence within this campaign:** async-cleanup-2026-05-11 D.38 (`735d054`) — 19 hits across 16 app/ files closed via categories 2/3/4; Phase E (E.1-E.9, 9 commits, ~80 total noqa lines) — test fixtures + path math via categories 1/2. Decision D4 was originally test-files-only; this rule formalizes its app/ extension as a durable principle. **Companions:** Rule #5 (executor wrap for unbounded blocking I/O — Rule #43 covers the bounded case, Rule #5 covers the unbounded case; they're complementary, not exclusive); Rule #29 (timeout discipline — category 4 implements the contract); Rule #16 (detection roots — category 3 implements the bounded-loop partner). Promotion date: 2026-05-12 (async-cleanup-2026-05-11 Phase H).

---

## Companion scaffold: `.mex/`

`.mex/` is a forward-looking task-navigation graph + recipe book that sits alongside this file. CLAUDE.md is canonical for learned rules and the top-level project reference; `.mex/` is the navigation layer you hit when starting a *specific* task. Roles:

- `.mex/ROUTER.md` — session bootstrap + routing table ("what file do I load for task X?"). Auto-maintained "Current Project State" section replaces re-discovering state on each session.
- `.mex/context/{architecture,stack,conventions,decisions,mcp-tools}.md` — dense, YAML-fronted context files with `triggers` + `edges` for graph navigation. The Verify Checklist in `conventions.md` is the task-time gate derived from rules 1–39 above.
- `.mex/patterns/INDEX.md` + `patterns/*.md` — recipes ("add mcp tool", "add rest endpoint", "docker rebuild backend+worker") with Context / Steps / Gotchas / Verify / Debug sections. These are authored upfront; `.planning/knowledge/*-patterns.md` are extracted post-hoc. Both exist.

Orchestration sits in Citadel (skills, harness hooks, campaigns). mex sits in version-controlled docs. The two talk through CLAUDE.md (canonical rules) and `.planning/knowledge/` (extracted patterns) — no shared state that drifts silently.

---

## MCP Server

Entry point: `wairz-mcp = "app.mcp_server:main"` (defined in `pyproject.toml`)

The server uses a mutable `ProjectState` dataclass so all project context (project_id, firmware_id, extracted_path) can be switched dynamically via the `switch_project` tool without restarting the MCP process.

### Tool Categories (172 across 21 categories)

Source-of-truth count: `find backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'` → 172.

| Category | File | Count | Notes |
|----------|------|------:|-------|
| Project | `tools/filesystem.py` | 3 | `get_project_info`, `switch_project`, `list_projects` |
| Filesystem | `tools/filesystem.py` | 8 | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| Strings | `tools/strings.py` | 5 | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials`, plus expanded variants |
| Binary | `tools/binary.py` | 23 | radare2 + Ghidra-backed: list/disassemble/decompile/xrefs/protections/dataflow/stack-layout/global-layout/cross-binary-dataflow |
| Security | `tools/security.py` | 36 | CVE lookup, config audit, SetUID, init scripts, perms, certificates, kernel hardening, YARA, CWE, etc. |
| SBOM | `tools/sbom.py` | 9 | generate/list components/CVE check/vuln scan + adjusters |
| Emulation | `tools/emulation.py` | 25 | user-mode + system-mode (FirmAE) + Qiling: start/exec/stop/status/logs/services/troubleshoot/crash-dump/gdb/presets/networking |
| Fuzzing | `tools/fuzzing.py` | 9 | target analysis, dictionary, seed corpus, harness gen, campaign start/status/stop, crash triage, diagnose |
| Comparison | `tools/comparison.py` | 4 | list versions, diff firmware/binary/decompilation |
| UART | `tools/uart.py` | 8 | connect, send command/break/raw, read, disconnect, status, transcript |
| Reporting | `tools/reporting.py` | 6 | add/list/update finding, read project instructions/documents |
| Android | `tools/android.py` | 4 | analyze APK, permissions, signatures, manifest scan |
| Android Bytecode | `tools/android_bytecode.py` | 1 | `scan_apk_bytecode` |
| Android SAST | `tools/android_sast.py` | 1 | `scan_apk_sast` |
| Code | `tools/documents.py` | 6 | code-cleanup save + document management |
| Hardware Firmware | `tools/hardware_firmware.py` | 7 | list/analyze blobs, drivers, CVEs, unsigned, HBOM export, DTB extract |
| CWE Checker | `tools/cwe_checker.py` | 3 | status, check binary, check firmware |
| Vulhunt | `tools/vulhunt.py` | 3 | scan binary, scan firmware, check availability |
| Attack Surface | `tools/attack_surface.py` | 2 | detect input vectors, analyze binary attack surface |
| Network | `tools/network.py` | 5 | pcap analyze, protocol breakdown, insecure protocols, DNS queries, conversations |
| UEFI | `tools/uefi.py` | 5 | list firmware volumes, list/identify/read UEFI modules, extract NVRAM |
| Taint LLM | `tools/taint_llm.py` | 2 | scan taint analysis, deep-dive taint analysis |

---

## UART Bridge Architecture

The bridge runs on the host (not in Docker) because USB serial adapters can't easily pass through to containers.

**How it works:**
- **Host:** `scripts/wairz-uart-bridge.py` is a standalone TCP server (only requires pyserial). It listens on TCP 9999 and proxies serial I/O.
- **Docker:** `uart_service.py` in the backend container connects to the bridge via `host.docker.internal:9999`
- **Protocol:** Newline-delimited JSON, request/response matched by `id` field
- **Important:** The bridge does NOT take a serial device path or baudrate on its command line. Those are specified by the MCP `uart_connect` tool at connection time.

**Starting the bridge:**
```bash
python3 scripts/wairz-uart-bridge.py --bind 0.0.0.0 --port 9999
```
The bridge will print "UART bridge listening on ..." when ready. It waits for connection commands from the backend.

**Connecting via MCP:** Call `uart_connect` with the `device_path` (e.g., `/dev/ttyUSB0`) and `baudrate` (e.g., 115200). The backend sends these to the bridge, which opens the serial port.

**Common setup issues (Bridge unreachable):**
1. `UART_BRIDGE_HOST` in `.env` must be `host.docker.internal` (NOT `localhost` — `localhost` inside Docker refers to the container, not the host)
2. An iptables rule is required to allow Docker bridge traffic to reach the host:
   ```bash
   sudo iptables -I INPUT -i docker0 -p tcp --dport 9999 -j ACCEPT
   ```
3. After changing `.env`, restart the backend: `docker compose restart backend`
4. After restarting the backend, reconnect MCP (e.g., `/mcp` in Claude Code)

---

## Device Acquisition Bridge

Similar to the UART bridge, the device bridge runs on the host to access ADB-connected Android devices.

**How it works:**
- **Host:** `scripts/wairz-device-bridge.py` is a standalone TCP server (only requires `adb` on PATH). Listens on TCP 9998.
- **Docker:** `device_service.py` connects to the bridge via `host.docker.internal:9998`
- **Protocol:** Same as UART bridge — newline-delimited JSON, request/response matched by `id` field
- **Commands:** `list_devices`, `get_device_info`, `dump_partition`, `dump_all`, `get_dump_status`, `cancel_dump`, `resume_dump`
- **Frontend:** 4-step wizard at `/projects/{id}/device` — Connect → Select Device → Dump Progress → Summary/Import

**Starting the bridge:**
```bash
python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998
```

**Mock mode (for development without a real device):**
```bash
python3 scripts/wairz-device-bridge.py --mock --port 9998
```

**Setup (same pattern as UART bridge):**
1. `DEVICE_BRIDGE_HOST` in `.env` must be `host.docker.internal`
2. iptables rule: `sudo iptables -I INPUT -i docker0 -p tcp --dport 9998 -j ACCEPT`
3. Restart backend after `.env` changes

---

## Environment Variables

See `.env.example` for defaults. Key variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (asyncpg) |
| `REDIS_URL` | Redis connection string |
| `POSTGRES_HOST_PORT` | Host-side port for PostgreSQL (default 5432, change if port conflicts) |
| `REDIS_HOST_PORT` | Host-side port for Redis (default 6379, change if port conflicts) |
| `DOCKER_GID` | Docker socket GID for container access (run `stat -c %g /var/run/docker.sock`) |
| `STORAGE_ROOT` | Where firmware files are stored on disk |
| `MAX_UPLOAD_SIZE_MB` | Maximum firmware upload size (default 2048) |
| `MAX_TOOL_OUTPUT_KB` | MCP tool output truncation limit (default 30) |
| `GHIDRA_PATH` / `GHIDRA_SCRIPTS_PATH` | Ghidra headless installation paths |
| `GHIDRA_TIMEOUT` | Decompilation timeout in seconds (default 300 per `config.py:24 ghidra_timeout`; frontend `GHIDRA_ANALYSIS_TIMEOUT` = 360_000 ms per Rule #29) |
| `EMULATION_IMAGE` / `EMULATION_NETWORK` | Docker image and network for QEMU containers |
| `FUZZING_IMAGE` / `FUZZING_TIMEOUT_MINUTES` | Docker image and timeout for AFL++ containers |
| `UART_BRIDGE_HOST` / `UART_BRIDGE_PORT` | Host-side UART bridge connection |
| `DEVICE_BRIDGE_HOST` / `DEVICE_BRIDGE_PORT` | Host-side device acquisition bridge (default: host.docker.internal:9998) |
| `NVD_API_KEY` | Optional, for higher NVD rate limits during CVE scanning |

---

## Testing Firmware

Good images for development and testing:

- **OpenWrt** (MIPS, ARM) — well-structured embedded Linux with lots of components
- **DD-WRT** — similar to OpenWrt
- **DVRF** (Damn Vulnerable Router Firmware) — intentionally vulnerable, great for security tool testing

---

## Citadel Harness

This project uses the [Citadel](https://github.com/SethGammon/Citadel) agent
orchestration harness. Configuration is in `.claude/harness.json`.
