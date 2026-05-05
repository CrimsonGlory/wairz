---
title: "MCP security.py extract_kernel_config auto-search TypeError — keyword-only arg passed positionally"
status: pending
priority: critical
target: backend/app/ai/tools/security.py:1191
---

## Description

`backend/app/ai/tools/security.py:1191` calls `safe_walk(extracted_root, extracted_root)` with a second positional argument, but the second parameter of `safe_walk` is keyword-only. Result: `TypeError: safe_walk() takes 1 positional argument but 2 were given` whenever the `extract_kernel_config` MCP tool runs in auto-search mode (no explicit kernel-image path provided).

**Evidence:** Stream D (F-D-02). Caught via the tool-registry runtime trace.

**Companion to CLAUDE.md Rule #11** (post-split runtime smoke) — this is another Phase-5-split residual that compiled but doesn't run.

## Acceptance Criteria

- [ ] Fix the call site: replace positional with keyword (`safe_walk(extracted_root, sandbox_root=extracted_root)`) OR remove the duplicate arg if `safe_walk` defaults to the same root.
- [ ] Test: `backend/tests/test_security_tools.py::test_extract_kernel_config_auto_search` — invoke the tool against a fixture firmware with a kernel image at the standard path, assert no exception.
- [ ] Live canary on a real firmware row.

## Out of Scope

- Refactoring `safe_walk` to accept positional `sandbox_root` (changes API surface; out of band).

## Cross-step

Single commit `fix(mcp-security): pass safe_walk sandbox_root by keyword (Rule #11)`. One-line.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-d-mcp-2026-05-04.md` finding F-D-02.
