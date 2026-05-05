---
name: architecture
description: How the major pieces of Wairz connect and flow — MCP server, FastAPI backend, React SPA, worker, and the Docker sidecars (QEMU, AFL++, Ghidra, ClamAV, vulhunt). Load when working on system design, integrations, or understanding how components interact.
triggers:
  - "architecture"
  - "system design"
  - "how does X connect to Y"
  - "integration"
  - "flow"
  - "mcp"
  - "sidecar"
edges:
  - target: context/stack.md
    condition: when specific technology details (library, framework, version) are needed
  - target: context/decisions.md
    condition: when understanding why the architecture is structured this way
  - target: context/mcp-tools.md
    condition: when adding or debugging MCP tool handlers, registry, or project switching
  - target: patterns/INDEX.md
    condition: when starting any task — check for a matching pattern first
last_updated: 2026-04-17
---

# Architecture

## System Overview

An MCP-compatible AI client (Claude Code/Desktop, Cursor, OpenCode, etc.) launches the `wairz-mcp` CLI over stdio. That process holds a mutable `ProjectState` (project_id, firmware_id, extracted_path) and dispatches 172 analysis tools across 21 categories against the same PostgreSQL database the FastAPI backend writes to. The React SPA talks to FastAPI at `/api/v1/...`; long-running work (firmware unpacking, Ghidra decompilation, vuln scans, fuzzing orchestration) is enqueued on Redis (arq) and consumed by the `worker` container. Emulation and fuzzing launch child Docker containers on the `wairz_emulation_net` network via the Docker socket mounted into backend/worker. UART and Android device access happen through two host-side TCP bridges (`wairz-uart-bridge.py:9999`, `wairz-device-bridge.py:9998`) reached via `host.docker.internal`. Analysis results (decompilations, APK scans, radare2 output) are cached in the `analysis_cache` JSONB table to avoid rerunning 30-120s operations.

## Key Components

- **`wairz-mcp` (backend/app/mcp_server.py)** — stdio MCP server with a mutable `ProjectState` dataclass so `switch_project` can swap active project/firmware without restarting. Owns the outer DB transaction; tool handlers only `flush()`.
- **FastAPI app (backend/app/main.py)** — registers routers under `/api/v1/projects/{project_id}/...`. Middleware stack: CORS → `APIKeyMiddleware`. Lifespan boots Redis event bus + CPE dictionary.
- **Tool Registry (backend/app/ai/tool_registry.py + ai/__init__.py)** — each tool category (`filesystem`, `binary`, `security`, `sbom`, `emulation`, `fuzzing`, `android`, `uart`, `uefi`, `vulhunt`, `comparison`, `cwe_checker`, ...) registers via `register_<category>_tools(registry)`. Handlers receive a `ToolContext` with `project_id`, `firmware_id`, `extracted_path`, `db`, and `resolve_path()`.
- **Services layer (backend/app/services/*.py)** — business logic. Routers are thin; services call Ghidra headless, radare2, binwalk3/unblob, docker SDK, etc. Async throughout.
- **Worker (backend/app/workers/arq_worker.py)** — consumes arq jobs for unpack (`unpack.py`, `unpack_linux.py`, `unpack_android.py`), Ghidra, vulnerability scan. Shares the backend Dockerfile and image; both must be rebuilt together.
- **React SPA (frontend/src/)** — pages under `src/pages/`, Axios clients in `src/api/`, Zustand stores (`projectStore`, `explorerStore`, `vulnerabilityStore`). Long-running ops use `useEffect + setInterval` polling (2s) until status transitions; SSE event bus provides push updates where available.
- **Sidecar containers** — `emulation` (QEMU multi-arch kernels), `fuzzing` (AFL++ QEMU mode), `system-emulation` (FirmAE, narrowed cap-set: `NET_ADMIN + SYS_ADMIN + MKNOD + /dev/net/tun`; was `privileged: true` until audit-2026-05-04 F-H-03), `vulhunt` (MCP-over-HTTP on 8080), `clamav` (optional profile). All mount `firmware_data` read-only.

## External Dependencies

- **PostgreSQL 16** — single source of truth. JSONB columns in `analysis_cache` (cache key = binary sha256 + operation name, operation VARCHAR(512) — JADX class names are long). Migrations auto-apply on worker/backend boot via Alembic.
- **Redis 7** — arq job queue and SSE event bus. If Redis is down, backend still boots but drops to polling only (see `main.py` lifespan warning).
- **Docker socket** — mounted into backend and worker (`/var/run/docker.sock`). Required for launching emulation/fuzzing sidecars. `DOCKER_GID` must match the host socket group.
- **Ghidra headless** — installed at `/opt/ghidra` in the backend image; custom Java scripts mounted read-only from `./ghidra/scripts:/opt/ghidra_scripts`. Each decompilation is 30-120s → always cache.
- **NVD API** — CVE dictionary + CPE enrichment for SBOM/vulnerability scan. Optional `NVD_API_KEY` raises rate limits.
- **Host-side bridges** — `wairz-uart-bridge.py` (pyserial) and `wairz-device-bridge.py` (adb) run on the host, not in Docker, because USB passthrough is unreliable. Protocol is newline-delimited JSON with id correlation. Requires iptables rule `INPUT -i docker0 -p tcp --dport {9998,9999} -j ACCEPT`.
- **MCP clients (external)** — Claude Code/Desktop, Cursor, OpenCode, Gemini CLI, Codex, VS Code Copilot, Windsurf. The Anthropic API key is user-provided in the client config; Wairz never stores it.

## What Does NOT Exist Here

- No in-process binary execution. Every QEMU/AFL++ run happens in a separate container with memory/PID limits set in `docker-compose.yml`.
- No backend-stored LLM API keys. Wairz is the MCP server — the client's AI credentials stay in the client.
- No ORM-less database access. Every query goes through SQLAlchemy 2.0 async sessions; raw SQL is not used outside Alembic migrations.
- No direct filesystem reads of firmware from route handlers. All file access funnels through `app/utils/sandbox.py` + `safe_walk` to handle symlink escapes in firmware rootfs.
- No frontend state outside Zustand + component-local state. No Redux, no Context for cross-page state.
- No authentication service beyond the single `APIKeyMiddleware` (env-configured). Multi-user/SSO is out of scope.
