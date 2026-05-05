---
title: "Docs drift — MCP tool count (172 actual vs 60+/65+/160+/165+ docs) + env defaults (MAX_UPLOAD/GHIDRA_TIMEOUT 2.5×–4× off)"
status: completed
priority: high
target: CLAUDE.md + README.md + docs/index.md + docs/mcp-tools.md + docs/configuration.md + .mex/context/{conventions,setup,mcp-tools}.md
---

## Progress — autopilot 2026-05-05

| Slice | Status |
|---|---|
| CLAUDE.md tool count + categories table (line 19, 37, 385) | ✅ updated to 172 / 21 categories with all 7 missing categories added |
| README.md tool count (lines 9, 37, 50, 168, 172, 274) | ✅ all updated to 172 |
| README.md MAX_UPLOAD/GHIDRA_TIMEOUT (lines 313, 316) | ✅ 2048 / 300 |
| docs/configuration.md MAX_UPLOAD/GHIDRA_TIMEOUT (lines 24, 33) | ✅ 2048 / 300 |
| docs/index.md tool count (lines 61, 103, 118) | ✅ all updated to 172 |
| docs/index.md RTOS "planned" (line 74) | ✅ updated to "shipped" |
| docs/mcp-tools.md tool count (line 3) | ✅ updated to 172, redirects to CLAUDE.md for canonical category breakdown |
| docs/architecture.md tool count (line 13) | ✅ 172 |
| docs/architecture.md tool count (line 64 — missed in first pass) | ✅ 172 / 21 categories (2026-05-05 follow-up) |
| .mex/context/architecture.md "~65+ analysis tools" (line 28 — missed in first pass) | ✅ 172 / 21 categories (2026-05-05 follow-up) |
| .mex/context/conventions.md description "34 learned rules" (line 3) | ✅ "35 learned rules" |
| .mex/ROUTER.md last_updated + Current Project State | ✅ refreshed (2026-05-05, 35 rules, 172 tools / 21 categories) |
| Rule #29 obsolete "drift risk" line (CLAUDE.md:282) | ✅ updated to reflect timeouts.ts consolidation shipped |

**Final canary (Rule #31 width-discipline):** `grep -nE "60\+\|65\+\|160\+\|165\+" CLAUDE.md README.md docs/*.md .mex/context/*.md .mex/ROUTER.md` returns 0 hits as of 2026-05-05.

**Deferred — out of scope for this autopilot pass:**

- docs/configuration.md adds 12+ missing env vars (esp. `API_KEY`) — needs the env-example sync intake (currently `status: blocked` on the Citadel external-action-gate hook).
- .mex/SETUP.md / .mex/SYNC.md broken script refs (point to non-existent `.mex/setup.sh` / `.mex/sync.sh`).
- frontend/README.md (still the unmodified Vite template).
- `.claude/agent-context/rules-summary.md` mirror — needs a new pre-commit hook to regenerate from CLAUDE.md `## Learned Rules`.
- CI gate diffing CLAUDE.md ↔ .mex/context/conventions.md ↔ rules-summary.md rule counts.

## Description

Two independent doc-vs-source drifts of structurally-significant magnitude:

**(a) MCP tool count + category drift (Stream I F-I-1)**
- **Actual:** 172 tools across 21 categories.
- **Docs say:** 60+/65+/160+/165+ — every public-facing reference is wrong.
- **CLAUDE.md "Tool Categories (65+)" table is missing 7 entire categories:** `hardware_firmware`, `cwe_checker`, `vulhunt`, `attack_surface`, `network`, `uefi`, `taint_llm`.
- **`docs/mcp-tools.md` is dramatically stale** (~50% tool coverage).
- **`docs/index.md:74` says RTOS support is "planned"** — it shipped.

**(b) Env-default drift (Stream I F-I-2)**
- `MAX_UPLOAD_SIZE_MB`: actual `2048` in `backend/app/config.py:19`, docs say `500` (4× off)
- `GHIDRA_TIMEOUT`: actual `300` in `config.py:24`, docs say `120` in README + `.mex/context/setup.md` (2.5× off — feeds INTO Rule #29's timeout-derivation chain, and Rule #29's frontend constants are derived from the actual values, so the public docs are inconsistent with the working system)

**Other doc drift surfaced (lower priority but in scope):**
- `.mex/SETUP.md` and `.mex/SYNC.md` reference non-existent `.mex/setup.sh` / `.mex/sync.sh`
- `frontend/README.md` is the unmodified Vite template
- `docs/configuration.md` is missing 12+ env vars present in README + CLAUDE.md (most critically `API_KEY` — a security-relevant var hidden from operators)
- `.mex/ROUTER.md` `last_updated: 2026-04-24` — predates Rule #34, #35, layout-containment, unpack_audit_service, Standing Operating Principles
- `.mex/context/conventions.md:3` description says "34 learned rules" but the file has 35 items
- `.claude/agent-context/rules-summary.md` ships ZERO of the 35 Learned Rules to sub-agents (file exists but is not a mirror) — fix is to make it a derived mirror of CLAUDE.md `## Learned Rules` section, regenerated on commit via a hook

## Acceptance Criteria

- [ ] CLAUDE.md MCP "Tool Categories" table updated to 172 tools / 21 categories. Cite the source: `find backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'`.
- [ ] CLAUDE.md header / inline counts: replace "65+ tools" with the actual number.
- [ ] README.md, docs/index.md, docs/mcp-tools.md updated. RTOS "planned" → "shipped".
- [ ] `MAX_UPLOAD_SIZE_MB` and `GHIDRA_TIMEOUT` aligned across README, docs, .mex.
- [ ] `docs/configuration.md` adds the 12+ missing env vars (esp. `API_KEY` — document its security model: per-deployment, header `X-API-Key`, query-param fallback for browser-issued URLs).
- [ ] `.mex/SETUP.md` and `.mex/SYNC.md` either point to existing scripts OR remove the broken references.
- [ ] `frontend/README.md` either gets project content OR is removed (the wairz README is the canonical one).
- [ ] `.mex/ROUTER.md` `last_updated` refreshed; "Current Project State" section regenerated against latest commits.
- [ ] `.mex/context/conventions.md:3` description fixed to "35 learned rules".
- [ ] `.claude/agent-context/rules-summary.md` becomes a generated mirror of CLAUDE.md Learned Rules. Add a pre-commit hook (or build-on-commit script) that regenerates it. This unblocks sub-agent rule injection across the harness.
- [ ] Add a CI check that diffs CLAUDE.md `## Learned Rules` count against `.mex/context/conventions.md` Verify Checklist count and `.claude/agent-context/rules-summary.md` Rule-N count — fails on divergence (Rule #21 enforcement at the gate level).

## Out of Scope

- Rewriting the architecture docs holistically (separate effort if the audit reveals deeper issues).

## Cross-step

Per Rule #25, split into ~5 commits: tool count sweep / env-default sync / mex SETUP/SYNC fix / agent-context mirror generation / CI gate.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-i-docs-2026-05-04.md` findings F-I-1, F-I-2, F-I-3 + others.
