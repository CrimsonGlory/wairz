# Pattern Index

Lookup table for all pattern files in this directory. Check here before starting any task — if a pattern exists, follow it.

| Pattern | Use when |
|---------|----------|
| [add-frontend-page.md](add-frontend-page.md) | Adding a new React page, Zustand store, or API client under `/projects/:projectId/...` |
| [add-mcp-tool.md](add-mcp-tool.md) | Adding a new MCP tool handler to the Wairz registry (`backend/app/ai/tools/*.py`) |
| [add-rest-endpoint.md](add-rest-endpoint.md) | Adding a new FastAPI route under `/api/v1/projects/{project_id}/...` with service + schema |
| [debug-mcp-tool-failure.md](debug-mcp-tool-failure.md) | MCP tool invisible, returning empty, corrupting protocol, or leaving stale DB state |
| [docker-rebuild-backend-worker.md](docker-rebuild-backend-worker.md) | Rebuilding backend + worker together after any Python / dependency / migration change |
| [layout-containment.md](layout-containment.md) | Split-pane page layout, sidebar form controls, long content, floating action docking — preventing pane bleed and overlap |
| [add-jsonb-column.md](add-jsonb-column.md) | Adding a new JSONB column to any model — normaliser + schema_version discipline (Rule #35c) |
| [add-router-test.md](add-router-test.md) | Adding a router-level test file (HTTP / WebSocket layer + Rule #35b live-canary) for any new or existing FastAPI router |
| [inner-outer-safe-runner.md](inner-outer-safe-runner.md) | Authoring a Rule #33 .a state-machine background runner — `_do_<op>_run` (inner) + `run_<op>_background` (outer) + `auto_<op>_firmware_safe` (unpack hook) triplet (Rule #39) |
| [add-alembic-migration.md](add-alembic-migration.md) | Authoring an alembic migration — revision-ID collision pre-check + table-creator / column-adder / check-extender shape selection + Rule #20 fast-iteration apply path |
| [real-firmware-skip-tier-canary.md](real-firmware-skip-tier-canary.md) | Authoring a 3-tier real-firmware end-to-end canary for a forensic-format pipeline — tier-1 always runs against synthetic data with mocks; tier-2/3 skip-unless an env-var fixture is provided (Rule-of-Three across β.14a + γ.9 + δ.9) |
