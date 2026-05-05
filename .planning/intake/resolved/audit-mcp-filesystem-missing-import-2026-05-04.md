---
title: "MCP filesystem.py missing `from sqlalchemy import select` — 2 tools NameError on first call"
status: pending
priority: critical
target: backend/app/ai/tools/filesystem.py
---

## Description

`backend/app/ai/tools/filesystem.py` references `select(...)` at lines 307 and 393 (inside `_handle_get_firmware_metadata` and `_handle_extract_bootloader_env`) but never imports it. Both MCP tools raise `NameError: name 'select' is not defined` on first invocation. Likely a Rule #11 footprint — these handlers were extracted from a parent module during a Phase 5 split but the relevant import was left behind.

`py_compile` and import-time checks pass because the unbound name is inside a function body — only runtime invocation triggers it.

**Evidence:** Stream D (F-D-01) caught via runtime trace canary on the registered tool surface.

**Companion to CLAUDE.md Rule #11** — after splitting a large file, runtime smoke is mandatory. This bug exists because the post-split smoke wasn't run on these specific MCP tools.

## Acceptance Criteria

- [ ] `from sqlalchemy import select` added to `backend/app/ai/tools/filesystem.py` imports.
- [ ] Test: `backend/tests/test_filesystem_tools.py` — invoke `_handle_get_firmware_metadata` and `_handle_extract_bootloader_env` against a fixture firmware row, assert no exception.
- [ ] Live canary (Rule #35b): run the MCP tool against a real firmware row in dev DB, confirm tool returns valid metadata.
- [ ] Backend rebuild per Rule #8 (no model change but the fix touches the tool registry import graph; safe to run via `docker cp` for fast iteration first per Rule #20).

## Out of Scope

- Wider grep for other Rule #11 split-residual import gaps in MCP tool files (covered separately by `audit-mcp-detection-roots-rule16-2026-05-04.md` and the test-coverage intake).

## Cross-step

Single commit `fix(mcp): add missing select import in filesystem tools (Rule #11)`. One-line change.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-d-mcp-2026-05-04.md` finding F-D-01.
