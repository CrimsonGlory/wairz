---
title: "Systemic Rule #35c violation — 19/20 JSONB columns lack schema_version + normaliser helpers"
status: resolved
resolved_date: 2026-05-06
resolved_session: jsonb-normaliser-sweep
resolved_commits: 9fcd2b9..9ff6d9c
priority: high
target: backend/app/models/*.py + backend/app/services/jsonb_normalizers.py + each consumer
---

## Resolution — 2026-05-06

**Outcome:** All 20 unprotected JSONB columns now have boundary normalisers in
`backend/app/services/jsonb_normalizers.py` (the inventory miscounted by 1 — 20,
not 19). 12 columns also got `schema_version` discriminators (≥3 consumer
files). 8 are normaliser-only. 119 pytest cases. Doc updates landed in
CLAUDE.md "Adding a Database Table", `.mex/patterns/INDEX.md` (new pattern
`add-jsonb-column.md`), and `.mex/context/conventions.md` Verify Checklist
(Rule #35c sub-bullet (c)).

**14 commits:**

- `9fcd2b9` firmware.device_metadata (foundation + 13-consumer column)
- `f859cb3` conversations.messages
- `c7915f5` analysis_cache.result
- `fea5e68` firmware.binary_info
- `fd73c00` firmware.cve_match_result
- `e03b688` fuzzing.{config,stats} (bundled — atomic write)
- `4bf11c0` emulation_sessions.port_forwards
- `567044d` emulation_sessions.discovered_services (also fixes 4bf11c0 import nit)
- `55565b8` emulation_sessions.nvram_state
- `c6f8c09` emulation_presets.port_forwards
- `a291dac` attack_surface_entries × 3 (bundled — atomic write)
- `1acbff2` sbom_components.metadata + hardware_firmware_blobs.metadata
- `7cfff99` cra_requirement_results × 4 (bundled — homogeneous list[str])
- `9ff6d9c` docs(jsonb): require boundary normaliser on every new JSONB column

**Inventory:** `.planning/research/jsonb-shape-inventory-2026-05-04.md` —
all 22 JSONB columns, strategy per column, prod shape variance measured via
`SELECT jsonb_typeof(<col>) FROM <table> GROUP BY 1` (no divergence at
column level).

**Knowledge captured:**
- `.planning/knowledge/jsonb-normaliser-sweep-2026-05-06-patterns.md`
- `.planning/knowledge/jsonb-normaliser-sweep-2026-05-06-antipatterns.md`

**Phase-2 deferred (none).** The intake projected Phase-1 (top 3) as a
session, with Phase-2 (remaining 16) deferred. Actual completion was all
20 columns in this single session because shared infrastructure (one
central module) made per-column commits cheap.

---

## Brief — autopilot 2026-05-05

**Scope:** Large (multi-session sweep, 19 columns × ~15 LOC normaliser each = ~3 commits per column = ~57 commits). Per Rule #25 each column ships as its own commit.

**Approach (Phase-1 recommended):**
1. Pick top 3 highest-risk columns: `device_metadata`, `Conversation.messages`, `analysis_cache.result`.
2. For each: SELECT `jsonb_typeof(<col>)` GROUP BY 1 in production to measure shape variance.
3. Write `_normalize_<col>(value: ...) -> <canonical>` per the precedent at `backend/app/services/unpack_audit_service.py:104` (Rule #35c canonical example).
4. Replace every consumer access with the normaliser call.
5. Add parameterised tests covering all known variants.

**Quality gates:**
- Width-canary grep for every consumer access pattern (Rule #31).
- Backfill-as-discovery: run consumer against ALL qualifying production rows; surface shape drift as diagnostic exception.
- Update CLAUDE.md "Adding a Database Table" + .mex/patterns/INDEX.md to require schema_version on new JSONB columns going forward.

**Risks:**
- Phase-2 (remaining 16 columns) accumulates risk over multi-session timeline; defer until pattern proven.
- Normalisers must be idempotent — a normalised value passed back through must equal itself.

**Deferral reason — autopilot:** Genuinely multi-session (19 columns × per-column commit). Phase-1 (top 3 highest-risk) alone would consume a session. Better suited to a dedicated archon-driven campaign with Phase-1 / Phase-2 split.

## Description

CLAUDE.md Rule #35c (extracted 2026-05-04 from the `vendor_decryption` shape-drift incident) requires: every new JSONB column gets EITHER a `schema_version` discriminator OR a dedicated boundary-normalisation helper. Audit measured **19/20 JSONB columns lack both** — only `_normalize_vendor_decryption` exists in the codebase.

The risk repeats on every new JSONB consumer: legacy/canonical shape divergence accumulates indefinitely, and a dict-vs-list shape drift produces `AttributeError` deep inside a service the consumer doesn't own. The cost of the rule is ~15 lines per column; the cost of NOT doing it is the unpack-audit incident (5/4) replayed for each consumer.

**Evidence:** Stream C (F-C-02, F-C-13). Width-canary: `grep -rn "schema_version" backend/app/models/` returns 0 hits across all 20 JSONB columns.

**High-risk targets (large surface area + active consumer count):**
- `Conversation.messages` (F-C-13) — AI conversation history; future LLM features will multiply consumers
- `Firmware.device_metadata` — already has the partial `_normalize_vendor_decryption` precedent, can be the canonical model
- `analysis_cache.result` — multi-tool consumer (Ghidra, radare2, mobsfscan) writes, multiple readers
- Any column with a `jsonb_typeof` divergence in production data

## Acceptance Criteria

- [ ] Audit each of the 19 JSONB columns. For each: SELECT `jsonb_typeof(<col>)` GROUP BY 1 against production data to measure existing shape divergence. Document in a per-column inventory file (e.g. `.planning/research/jsonb-shape-inventory-2026-05-04.md`).
- [ ] For each column with multi-shape data: write a `_normalize_<col>(value: <canonical> | <legacy> | None) -> <canonical>` helper, place it in the owning service module. Replace every consumer access (`device_metadata['<key>']`, `.get('<key>')`) with `_normalize_<col>(...)`.
- [ ] For each NEW JSONB column going forward: include `schema_version: int` from day one. Update CLAUDE.md "Adding a Database Table" section and `.mex/patterns/INDEX.md` to document this requirement.
- [ ] Tests: per consumer, add a parameterised test fixture covering all known shape variants (canonical, legacy, malformed). Backfill-as-discovery pattern (Pattern #6 from `unpack-audit-findings-2026-05-04-patterns.md`) is preferred — run the consumer against ALL qualifying production rows in dev to surface shape drift as a diagnostic exception.

## Out of Scope

- Schema migrations to rewrite legacy JSONB rows to canonical shape (heavier than the 15-line normaliser; only do this if a normaliser proves insufficient for some perf-critical consumer).

## Cross-step

This is a multi-session sweep. Decompose into one commit per column (Rule #25). Or pick the top 3 highest-risk columns first (`device_metadata`, `Conversation.messages`, `analysis_cache.result`) and ship as a Phase-1; defer the rest as a Phase-2 intake.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-c-models-2026-05-04.md` findings F-C-02, F-C-13.
