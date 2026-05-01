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
│  65+ tools      │     │  Services: firmware, file,         │
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
- **MCP Server:** `wairz-mcp` CLI entry point (`app.mcp_server:main`), stdio transport, 65+ tools
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

### Learned Rules (from `.planning/knowledge/`)

These rules were extracted from recurring bugs and failures across 30+ development sessions:

1. **Use `docker compose up -d` not `restart` after code changes.** `restart` reuses the old container image. `up -d` recreates it with the new build. This mistake has caused false "it works locally" debugging in multiple sessions.
2. **Add new Python dependencies to `pyproject.toml` immediately.** Code that imports a new package must update `pyproject.toml` in the same commit. Verify in Docker: `docker compose exec backend python -c "import <module>"`.
3. **Use `flush()` not `commit()` in MCP tool handlers.** The outer MCP dispatch in `mcp_server.py` owns the transaction. Tool handlers should use `context.db.flush()` so writes are visible within the session but rollback works on exceptions.
4. **Match Pydantic response schemas to ORM model fields exactly.** When adding a new backend service for an existing MCP endpoint, read the response schema first and construct the return dict to match. Schema/model mismatches cause silent 500 errors.
5. **Wrap sync filesystem I/O in `run_in_executor()` inside async handlers.** Large firmware (10K+ files) stalls the uvicorn event loop. CPU-bound or filesystem-heavy operations must use `await loop.run_in_executor(None, sync_fn, args)`.
6. **Verify CLI tool flags when upgrading versions.** Before swapping any CLI tool (e.g., binwalk v2→v3), grep the codebase for ALL flags used and verify each exists in the new version's `--help`. Test with real data.
7. **Never `asyncio.gather()` on coroutines sharing a SQLAlchemy `AsyncSession`.** `AsyncSession` is not safe for concurrent coroutine access. Gather'd coroutines that share a session cause state corruption, lost writes, or runtime exceptions. Use sequential `await` calls, or create independent sessions per task via `async_session_factory()`.
8. **Rebuild `worker` whenever you rebuild `backend`.** They share the same Dockerfile and codebase. A stale worker image causes Alembic migration failures (worker can't find new revisions) and silently blocks ALL background jobs (unpack, Ghidra, vuln scan). Use `docker compose up -d --build backend worker`, never just `backend` alone.
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
25. **When implementing an intake or feature with ≥3 independently-verifiable sub-tasks, commit each sub-task as its own commit — not a bundled "feat(X): all of Y" omnibus.** Session 435cb5c2 shipped Alpha's 7 data-migration sub-tasks (D1/D2/D3/I1/I2/I3/I4) as 8 commits, Delta's 3 infra sections (O1 cron / O2 migrator / O3 observability) as 7 commits, Beta's pagination as 5 one-per-endpoint-family commits. Individual `git revert <sha>` per sub-task works cleanly; a bundled commit forces all-or-nothing rollback and scrambles `git bisect`. Also: cross-stream commit sweeps (Rule 23 anti-pattern) damage LESS when per-commit surface is small — a mixed sub-task commit contains at most one slice of mis-attributed work. Natural splits: alembic chains = one commit per revision file; schema+service+router changes on the same feature = one commit per layer; frontend virtualisation across N pages = one commit per page. Rule-8 class-shape rebuild runs ONCE at the end of the stream, not per commit. Exception: a single-atomic-change task (one-line bug fix, single flag flip) is one commit; "sub-task" means a genuinely independently-verifiable slice with its own acceptance grep or smoke check.

26. **When `frontend/src/**` changes, the frontend image must be rebuilt — `docker compose up -d --build frontend`, not `restart` and not `up -d` alone.** The frontend container serves a Vite-built `dist/` baked into the image at `/usr/share/nginx/html/`; there is no bind mount, so nginx keeps serving the stale bundle until the image layer is rebuilt. Symptom: runtime `TypeError: <var>.map is not a function` (or similar shape mismatch) thrown from components whose *source code* correctly unwraps the new backend response — the shipped bundle is pre-change. Originally manifested in session 93a4948d: backend Stream Beta (session 435cb5c2) added Page-envelope pagination to `GET /api/v1/projects` → `{items, total, offset, limit}`; Stream Zeta (commit `3063283`) added the frontend `unwrap(data)` helper; but the frontend container image was built at 14:40 UTC *before* `3063283` landed at 17:14 UTC and never rebuilt — so the live bundle returned the raw envelope to `projectStore.fetchProjects`, and `Sidebar`'s `projects.map(...)` threw. Mechanical tell: after any `git pull` / branch switch / commit that modifies a file under `frontend/src/`, compare `docker compose images frontend` `CreatedAt` with `git log --format='%ci' -1 -- frontend/` — if the commit is newer than the image, rebuild. `docker compose restart frontend` does NOT help; it reuses the existing image. Companion to Rule #8 (backend+worker rebuild discipline). Fix verification: curl the served HTML for the bundle hash, then `grep -oE 'Array\.isArray\([a-z]\)\?[a-z]:\([a-z]==null\?void 0:[a-z]\.items' <bundle.js>` must match (the compiled `unwrap`); zero matches = stale build. The harness rule `auto-frontend-rebuild-not-restart` (in `.claude/harness.json` qualityRules.custom) flags docs/prompts that say `docker compose restart frontend`.

27. **When splitting a large single-file class or module (≥1000 LOC) into a subpackage, use the "N additive + 1 cut-over" shape.** Commits 1..(N-1) add new files without changing existing imports or behaviour (callers still hit the monolith; the new files are dead code in the running system). Commit N is the atomic cut-over that either (a) deletes the monolith and updates ≤5 call sites in-place, or (b) replaces the monolith with a one-line `from app.services.new_pkg import *` shim (>5 call sites). Class-shape changes (Mixin→composition, inheritance chain edits) happen in commit N as well, with thin forwarders added in the host class for each method still called via `self._check_*`. The Rule #8 rebuild + Rule #11 runtime smoke run ONCE after commit N, not per commit. Individual topic extracts become revertable in isolation without losing later work — bisect-clean. Originally validated on `manifest_checks` (2589 LOC Mixin, 8 commits) and `security_audit_service` (1258 LOC module, 8 commits) in session b56eb487 (2026-04-21); extended to `sbom_service` (2412 LOC, 9 commits, Strategy pattern with 14 strategies), `emulation_service` (1664 LOC, 7 commits, cron-registration preserved), and `mobsfscan_service` (1539 LOC, 5 commits) in session 7e8dd7c3 (2026-04-22). **5 consecutive clean shippings across 2 sessions — 34 additive + 5 cut-over commits, 0 reverts, 0 cross-stream sweeps (under Rule #23 worktree discipline). The pattern is durable.** Under-counted caller audits surface at cut-over time — α's sbom split found a 5th lazy-import caller the intake missed; re-grep in the cut-over commit, update in-place, adjust the commit message. For Strategy-pattern splits specifically, dead-abstractions in the intake (e.g. an `rpm_strategy.py` the monolith never implemented) are dropped per Rule #19 — don't create placeholder files for conditions that aren't present.

28. **Before starting any refactor whose scope is predicated on a specific LOC count in an intake / spec, re-measure with `wc -l` first.** Observed drift at 5 Phase 5 targets was consistently +14% to +22% over intake measurement: `manifest_checks` 2263→2589 (+14%), `security_audit_service` 1036→1258 (+22%), `sbom_service` 2073→2412 (+16%), `emulation_service` 1454→1664 (+14%), `mobsfscan_service` 1328→1539 (+16%). Intakes age; files grow at a uniform 14-22% rate between when the intake is written and when the refactor runs. If the re-measured target exceeds a single-session capacity budget, rescope to a partial split (one or two topic extractions only) or defer the whole refactor rather than risk a half-done state (CLAUDE.md Rule #11 penalty: the class-shape change costs a Rule #8 rebuild; a half-split state between sessions is much worse than a 0% or 100% split). Companion to Rule #19 — evidence-first applies to intake-size claims too. Re-measure takes 1 second (`wc -l <file>`); carries zero cost; eliminates 14-22% scope surprises.

29. **Frontend axios timeouts derive from the backend work-ceiling plus 20% grace, not from aesthetics — and any synchronous tier >100s is unsafe behind a reverse proxy.** The axios floor is `timeout: 30_000` in `frontend/src/api/client.ts:6` (axios's native default is `0` = unlimited — the wairz-specific 30s override forces fail-fast for unflagged CRUD calls). Every long-op endpoint MUST declare an upward override whose value satisfies `frontend_ms ≥ backend_s × 1200`, i.e. **backend declared timeout in seconds × 1200 = frontend timeout in milliseconds** (the ×1200 factor bakes in ×1000 for ms-conversion and ×1.2 for network + JSON-serialization grace). Backend side: uvicorn has NO per-request max (only `--timeout-keep-alive=5s` governing idle *between* requests), so the authoritative ceiling is whatever `config.py` / `asyncio.wait_for(..., timeout=N)` / `subprocess.run(..., timeout=N)` declares in the service. Sources: [axios request config](https://axios-http.com/docs/req_config) (`default is 0 (no timeout)`); [uvicorn settings](https://www.uvicorn.org/settings/). Current tiered constants in-tree (by decreasing speed): `RADARE2_ANALYSIS_TIMEOUT=150_000` (radare2 `aaa` — matches `backend/app/ai/tools/binary.py:1637` `communicate(timeout=120)` × 1.25); `GHIDRA_ANALYSIS_TIMEOUT=360_000` (Ghidra headless — matches `config.py:24 ghidra_timeout=300` × 1.2); `HASH_SCAN_TIMEOUT=300_000` / `DEVICE_BRIDGE_TIMEOUT=300_000` (hash lookups, device ingest); `SECURITY_SCAN_TIMEOUT=600_000` (security audit, SBOM, yara, vuln scan — backend `mobsfscan` pipeline `_PIPELINE_BUDGET_SECONDS=600` × 1.0 — this is the outer synchronous ceiling). Each tier constant MUST (a) live in the API file that owns the operation (`analysis.ts` owns Ghidra/radare2; `findings.ts` owns security-scan; `device.ts` owns device-bridge), (b) carry an inline comment citing the backend source (e.g. `// matches config.py:24 ghidra_timeout=300 × 1.2 grace`), (c) NOT be duplicated across files — a call in another file uses `import { SECURITY_SCAN_TIMEOUT } from './findings'` rather than re-declaring. **Ceiling caveats from the upstream ecosystem** (session 7e8dd7c3 research): Chrome's XHR/fetch hard cap is ~300s; nginx `proxy_read_timeout` defaults to 60s; AWS ALB idle-timeout defaults to 60s (max 4000s); Cloudflare origin-response defaults to 100s (524 error past that, Enterprise-only raise). wairz currently deploys same-origin (frontend → backend directly, no proxy), so the 600s tier works — but ANY deployment behind a reverse proxy MUST either tune the proxy's `proxy_read_timeout` ≥ the frontend tier OR convert the endpoint to the 202+polling pattern (precedent: firmware unpacking returns 202 and the frontend polls every 2s; `asyncio.create_task()` runs the work detached and posts to `analysis_cache`). Mechanical author check when adding a long-op endpoint: (1) grep the backend service for `timeout=`, `GHIDRA_TIMEOUT`, `BUDGET_SECONDS`, `asyncio.wait_for` to find the authoritative ceiling; (2) compute `frontend_ms = backend_s * 1200`; (3) pick the tier constant whose value ≥ that number; (4) if none exists, add one in the owning API file with a derivation-citing comment; (5) if `frontend_ms > 100_000` AND any proxy sits on the deployment path, use 202+polling instead. **Backend counter-requirement:** every `subprocess.run`, `asyncio.create_subprocess_exec`, and `asyncio.wait_for` in a service MUST declare an explicit timeout — bare `wait_for(coro)` without a timeout param is undefined behaviour, and the alignment math collapses. 4 critical misalignments found in session 7e8dd7c3 backend-timeout-audit: **Ghidra decompile** frontend 180s vs backend 300s (FIXED — 360s this session, commit a183e22); **radare2** frontend 90s vs backend 120s (FIXED — 150s, same commit); **emulation user-mode** frontend 300s vs backend `config.py:30 firmae_timeout=1800` (FIXED — 202+polling refactor shipped on Fleet Wave 1 Stream α 2026-04-20 branch `feat/stream-alpha-emulation-202-2026-04-20`; `POST /emulation/start` returns 202 with `status="pending"`, the detached `EmulationService.spawn_session_background` runs the Docker work via arq job `spawn_emulation_session_job` (fallback `asyncio.create_task`), transitions the row through `pending → booting → ready` on a real health probe (user-mode: `/tmp/.standalone_mode` or `/firmware` readable; system-mode: `/tmp/qemu-serial.sock` appeared via `await_system_startup`), terminal WS in `routers/emulation.py` now gates on `status in ("running", "ready")`; frontend `startEmulation` inherits the `apiClient` default 30 s via `frontend/src/api/emulation.ts` and the `EmulationPage` auto-attaches the terminal when polling flips to `ready`); **fuzzing campaign** frontend 600s vs backend `config.py:38 fuzzing_timeout_minutes=120` (7200s) (FIXED — 2026-04-20 Wave 1 Stream β branch `feat/stream-beta-fuzzing-202-2026-04-20`: `POST /fuzzing/campaigns/{id}/start` now returns 202 with `status="queued"` and schedules the container spawn via `asyncio.create_task(_run_campaign_spawn_background)`; frontend `FuzzingPage` polls every 2 s while any row is queued, matching the firmware-unpack precedent — the frontend `startCampaign` no longer needs a long timeout override and the default 30 s axios floor is now correct for the 202 ack). Drift risk: `SECURITY_SCAN_TIMEOUT=600_000` is currently redeclared verbatim in 8 files (no canonical owner); next refactor should consolidate to `frontend/src/api/timeouts.ts`. Harness rules `auto-frontend-long-op-no-explicit-timeout` and `auto-frontend-multipart-no-explicit-timeout` enforce PRESENCE of the `timeout:` option; this rule adds the DERIVATION discipline on top — the harness catches missing overrides, the rule ensures the override value actually aligns with the backend.

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

    **(c) New status column gets BOTH a Pydantic `Literal` AND a DB CHECK constraint.** Migration adds `op.create_check_constraint("ck_<table>_<col>", "<table>", "<col> IN ('idle', 'queued', 'running', 'completed', 'failed')")`. Schema declares `Status = Literal["idle", "queued", "running", "completed", "failed"]`. The `Literal` catches LLM/dev typos at the API boundary; the CHECK catches direct-SQL writes (cron scripts, manual fixes, ORM rollbacks under partial-failure paths). Both gates are cheap; ship both. Mirrors `ck_emulation_sessions_status` / `ck_fuzzing_campaigns_status` (revision `54c8864fbe0c`) and `ck_firmware_cve_match_status` (revision `e6f7a8b9c0d1`).

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

---

## Companion scaffold: `.mex/`

`.mex/` is a forward-looking task-navigation graph + recipe book that sits alongside this file. CLAUDE.md is canonical for learned rules and the top-level project reference; `.mex/` is the navigation layer you hit when starting a *specific* task. Roles:

- `.mex/ROUTER.md` — session bootstrap + routing table ("what file do I load for task X?"). Auto-maintained "Current Project State" section replaces re-discovering state on each session.
- `.mex/context/{architecture,stack,conventions,decisions,mcp-tools}.md` — dense, YAML-fronted context files with `triggers` + `edges` for graph navigation. The Verify Checklist in `conventions.md` is the task-time gate derived from rules 1–29 above.
- `.mex/patterns/INDEX.md` + `patterns/*.md` — recipes ("add mcp tool", "add rest endpoint", "docker rebuild backend+worker") with Context / Steps / Gotchas / Verify / Debug sections. These are authored upfront; `.planning/knowledge/*-patterns.md` are extracted post-hoc. Both exist.

Orchestration sits in Citadel (skills, harness hooks, campaigns). mex sits in version-controlled docs. The two talk through CLAUDE.md (canonical rules) and `.planning/knowledge/` (extracted patterns) — no shared state that drifts silently.

---

## MCP Server

Entry point: `wairz-mcp = "app.mcp_server:main"` (defined in `pyproject.toml`)

The server uses a mutable `ProjectState` dataclass so all project context (project_id, firmware_id, extracted_path) can be switched dynamically via the `switch_project` tool without restarting the MCP process.

### Tool Categories (65+)

| Category | File | Tools |
|----------|------|-------|
| Project | `tools/filesystem.py` | `get_project_info`, `switch_project`, `list_projects` |
| Filesystem | `tools/filesystem.py` | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| Strings | `tools/strings.py` | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials` |
| Binary | `tools/binary.py` | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `check_binary_protections`, `check_all_binary_protections`, `find_string_refs`, `resolve_import`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `trace_dataflow`, `cross_binary_dataflow` |
| Security | `tools/security.py` | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate`, `check_kernel_hardening`, `scan_with_yara` |
| SBOM | `tools/sbom.py` | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan` |
| Emulation | `tools/emulation.py` | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `enumerate_emulation_services`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset` |
| Fuzzing | `tools/fuzzing.py` | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash`, `diagnose_fuzzing_campaign` |
| Comparison | `tools/comparison.py` | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| UART | `tools/uart.py` | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| Reporting | `tools/reporting.py` | `add_finding`, `list_findings`, `update_finding`, `read_project_instructions`, `list_project_documents`, `read_project_document` |
| Android | `tools/android.py` | `analyze_apk`, `list_apk_permissions`, `check_apk_signatures`, `scan_apk_manifest` |
| Android Bytecode | `tools/android_bytecode.py` | `scan_apk_bytecode` |
| Android SAST | `tools/android_sast.py` | `scan_apk_sast` |
| Code | `tools/documents.py` | `save_code_cleanup` |

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
