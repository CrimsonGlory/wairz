---
title: "Feature: LATTE-Style LLM Binary Taint Analysis (Two MCP Tools)"
status: completed
priority: high
target: backend/app/ai/tools/, backend/app/ai/__init__.py
depends_on: none
estimated_sessions: 1-2
source: Ouroboros interview seed_61966b02ef35 (2026-04-17) + Citadel research-fleet-wairz-next-campaigns
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 435cb5c2 Stream
> Epsilon across 3 commits (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Phase 6 history). Live audit verified:
> - YAML sink + source dictionaries: commit `cbeb8fd`
>   (`backend/app/ai/tools/_taint_sinks.yaml`, `_taint_sources.yaml`).
> - Both MCP tools implemented: commit `c434959`. `backend/app/ai/tools/taint_llm.py`
>   exists (32763 bytes); handlers at line 504 (`_handle_scan_taint_analysis`) and
>   line 624 (`_handle_deep_dive_taint_analysis`); registration at lines 798 and 853.
> - Registered in `create_tool_registry`: commit `180c25f`
>   (`backend/app/ai/__init__.py:19` imports `register_taint_llm_tools`, line 48
>   calls it).
> - Unit tests: commit `06b80b8` (YAML loaders, ranking, confidence gate, prompts).
> This intake is retained for historical reference; further changes go in new intakes.

## Overview

Build two MCP tools that use Claude (the already-connected MCP client) as the LLM reasoning engine for LATTE-style binary taint analysis. No Anthropic API keys on the backend, no new pip dependencies.

This closes the gap between "Wairz classifies 1000s of binaries" and "Wairz tells you which functions are suspicious." Today Dustin must open Ghidra per-function manually; these tools automate the scan/triage loop while preserving offline mode.

The two-tool split:

1. **`scan_taint_analysis`** — fast, binary-wide. Pre-filters thousands of functions by dangerous-sink callers and call-graph weight, then composes a structured prompt that returns a ranked list of `{function, offset, CWE, confidence, one-line rationale}`. Accepts `min_confidence` (low|medium|high) so the same tool serves quick-scan and exhaustive-audit.
2. **`deep_dive_taint_analysis`** — per-function. Takes one function, returns the full source→sink taint path with quoted decompiled lines as evidence for each propagation step.

## Why now

- **Wairz strength × AI frontier fit:** Wairz already has 65+ MCP tools including `decompile_function`, `xrefs_to`, `list_imports`, `trace_dataflow`, `find_callers`. LATTE-style taint is pure prompt engineering on top of existing plumbing — no new services, no new models.
- **Market gap:** GhidraMCP / binary_ninja_mcp / pyghidra-mcp expose decomp to LLMs but none ship LATTE-style structured taint analysis. Wairz would be the first OSS MCP taint tool using Claude.
- **Unblocks user workflow:** Dustin's current pain is manual Ghidra-per-function. Tool #1 picks targets; tool #2 drills in.

## Approach

### Phase 1 — scan_taint_analysis (single session)

**Pre-filter pipeline** (the hard part):
1. Read binary's import table via existing `list_imports`.
2. Filter imports to dangerous sink set: `strcpy`, `strncpy`, `sprintf`, `snprintf`, `gets`, `system`, `popen`, `execve`, `memcpy`, `scanf`, `recv`, `read`, `open`, `mktemp`, etc. (configurable YAML).
3. For each dangerous sink, find callers via existing `find_callers` — these are the candidate functions.
4. Rank by call-graph weight: (a) how many sinks the function touches, (b) how many callers the function has (high centrality = higher impact if vulnerable), (c) whether user-input sources (`recv`, `read`, `getenv`, `fgets`) are reachable from entry.
5. Apply `min_confidence` threshold: low = keep all; medium = require ≥2 sinks OR ≥1 user-input source; high = require both + reachability analysis via existing `trace_dataflow`.

**Prompt composition:**
- Decompile each candidate via existing cached `decompile_function`.
- Structure: `{binary_info}` + `{candidate list with decompiled bodies}` + `{sink inventory}` + `{instruction: rank, assign CWE, justify in one line}`.
- Stay under 30KB output truncation limit — batch if necessary.

**Tool returns:** structured prompt string; Claude Code client analyzes, returns findings.

### Phase 2 — deep_dive_taint_analysis (single session or concurrent)

**Inputs:** `function_name` + `binary_path` (via ToolContext).

**Slice builder:**
1. Decompile target function.
2. Walk `xrefs_to` and `xrefs_from` 2 hops in each direction to build a local call graph.
3. Identify source candidates (user-input sinks called upstream) + sink candidates (dangerous functions called downstream).
4. Compose prompt structured as: 4-stage chain-of-thought matching LATTE paper (sink-id → source-id → dataflow → CWE classification). For each stage, provide quoted decompiled lines as anchors.

**Tool returns:** structured prompt string with anchored source lines; Claude reasons and produces the full chain.

### Cross-phase

- Cache composed prompts in `analysis_cache` by `(binary_sha256, function_name, min_confidence)` so re-scans are free.
- Tests: fixture with DVRF-style planted-bug binary + unit tests asserting filter ordering + prompt structure. Integration test asserting 80% recall target.
- No frontend changes — the tools are MCP-only. Future phases can add UI after the tools stabilize.

## Data model

None new. Reuse existing `analysis_cache` table (VARCHAR(512) operation field — CLAUDE.md rule 15).

## File layout

```
backend/app/ai/tools/
  taint_llm.py                            (new, ~450 LOC — two tool handlers)
  _taint_sinks.yaml                       (new, ~80 lines — dangerous sink list)
  _taint_sources.yaml                     (new, ~40 lines — user-input source list)

backend/app/ai/__init__.py                (register new tool category)

backend/tests/fixtures/taint/
  dvrf_planted_bugs_sample.c              (optional — DVRF reference)
  taint_planted_bugs.elf                  (prebuilt DVRF binary fixture)

backend/tests/test_taint_llm.py           (new, ~300 LOC — filter + prompt tests)
```

## New dependencies

**Zero.** Research-fleet scout confirmed backend has zero `anthropic` SDK imports; all 65+ existing MCP tools return strings. This one follows the same pattern.

## Acceptance criteria

### Phase 1 (scan)
- [ ] `scan_taint_analysis` registered; appears in MCP tool list.
- [ ] Accepts `binary_path`, `min_confidence` (low|medium|high, default medium), optional `max_candidates` (default 50).
- [ ] Pre-filter pipeline documented; unit tests assert ordering is stable for a golden fixture.
- [ ] Returns a structured prompt string under 30KB.
- [ ] DVRF baseline: flagged ≥80% of planted bugs at `min_confidence=low` on a reference DVRF binary.

### Phase 2 (deep-dive)
- [ ] `deep_dive_taint_analysis` registered; accepts `binary_path` + `function_name`.
- [ ] Returns 4-stage chain-of-thought prompt (sink-id → source-id → dataflow → CWE) with quoted decompiled lines per stage.
- [ ] DVRF golden bug: produces a fully verified taint chain with every intermediate step defensible against the decompiled code.

### Cross-phase
- [ ] Real firmware qualitative spot-check: Dustin picks one binary from recent work; Claude's analysis is reasonable and non-hallucinated.
- [ ] No regression in existing 192/192 hw-firmware tests.
- [ ] Ruff clean on new code.
- [ ] Prompt cache hits observable via `analysis_cache` queries.

## Risks

1. **Hallucination:** Claude reports CVE-style finding that doesn't exist. Mitigation: require quoted decompiled lines in every chain step; unit test asserts the prompt FORCES quoting ("you must copy 3+ consecutive lines from the decompiled code for each step").
2. **Scale blow-up:** Binaries with 10K functions × 5K-token decompilations = runaway prompts. Mitigation: pre-filter hard cap (`max_candidates=50`) + batching.
3. **Consistency:** Same function analyzed twice → different reports. Mitigation: cache in `analysis_cache`; use `low_temperature`-leaning prompt structure.
4. **DVRF binary availability:** 80% recall target requires a DVRF binary with KNOWN planted bugs. If unavailable, fallback: build a minimal fixture with 5 classic CWE patterns (CWE-78, CWE-120, CWE-134, CWE-787, CWE-190) and use it as the quantitative gate.
5. **Overlap with `trace_dataflow` MCP tool:** existing tool does static dataflow. Positioning: `trace_dataflow` = fast, deterministic, low recall. `scan_taint_analysis` = slower, LLM-augmented, high recall. Document the split in both tool descriptions.

## Extensibility

Same architecture handles:
- **Source code taint** for extracted source trees (treat code files like decompiled output).
- **Multi-binary taint** via existing `cross_binary_dataflow` MCP tool as upstream slicer.
- **Custom CWE focus** via optional `focus_cwe` parameter (e.g., only CWE-78).
- **Golden-bug regression suite:** if the scanner regresses (e.g., after a prompt change), the DVRF unit test catches it.

## References

- **Research brief:** `.planning/research/fleet-wairz-next-campaigns/latte-llm-taint.md` (1,546 words, 22 citations).
- **Ouroboros seed:** `seed_61966b02ef35`, session `interview_20260417_164140`. Serialized YAML at `.planning/research/fleet-wairz-next-campaigns/seed-latte-llm-taint.yaml`.
- **LATTE paper:** arXiv 2310.08275v4 (TOSEM 2025). No public code; prompt structure extracted from paper HTML.

## Campaign tracking

Recommended:
- Campaign file: `.planning/campaigns/feature-latte-llm-taint-analysis.md`
- 2 phases, estimated 1-2 sessions.
- Launch via `/archon feature-latte-llm-taint-analysis`.
- Depends on: `feature-hw-firmware-phase2-enrichment` (completed at a102004) — the decompile/xrefs/imports tools used as building blocks are unchanged.
