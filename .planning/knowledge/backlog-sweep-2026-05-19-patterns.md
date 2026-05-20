# Patterns: backlog sweep — P3.3.a + 5 HIGH backlog items (2026-05-19)

> Extracted: 2026-05-20
> Campaign: continuation-of-P3.2 backlog sweep (no campaign file; direct-shipped per Rule #25)
> Postmortem: .planning/postmortems/postmortem-backlog-sweep-2026-05-19.md

## Successful Patterns

### 1. HIGH backlog items closed in priority order WITHOUT scout dispatch
- **Description:** When ADAPTIVE_BACKLOG.md HIGH items already carry a description + LOC estimate + rationale (Reviewer-tagged at finding time), they constitute the convergence-doc-style implementation contract. Direct ship-per-piece — no Wave-1/Wave-2 research needed.
- **Evidence:** 5 backlog items (RvwA-A5+B6, RvwC-C10, scout1, RvwC-C4, RvwC-C11) shipped in <2 hours total at session-end. Total +717 LOC against the postmortem's ~230 LOC pre-estimate (modestly higher due to per-tool META-CANARY discipline).
- **Applies when:** The backlog item carries (a) scoped LOC estimate, (b) rationale, (c) reviewer-tagged source, (d) clear acceptance criteria. Items without all 4 still need a scout pass.

### 2. Schema-driven extension of existing tools beats new tool authoring
- **Description:** Extending an existing MCP tool's payload (e.g. add `load_rejections` to `list_extension_points`) is cheaper than authoring a new MCP tool when the new data fits the existing tool's role. Inherits existing test scaffolding, tool registration, frontend wiring.
- **Evidence:** C10 (`load_rejections` extension to `list_extension_points`) shipped in 49 LOC vs C4 (new `describe_advisory` tool) at 148 LOC + C11 (new `verify_cve_attribution` tool) at 280 LOC. The per-tool authoring cost dominates over the per-payload-extension cost.
- **Applies when:** New observability data fits within an existing tool's scope (e.g. extending an `info`-style tool with new fields, not creating a new `info_v2` tool). Don't extend when the role differs.

### 3. Per-tool MCP test shape — 4-test baseline
- **Description:** Each new MCP tool ships with at least 4 tests: (1) positive case (mock or real data shows the tool works); (2) no-match / empty path; (3) schema-error path (missing required input); (4) edge case (invalid UUID / hostile input / wrong-format).
- **Evidence:** C4 (describe_advisory) shipped 3 tests; C11 (verify_cve_attribution) shipped 4 tests. The 4-test shape is now Rule-of-Two for MCP tool authoring.
- **Applies when:** Authoring any new MCP tool via `registry.register(...)` in `app/ai/tools/<category>.py`. Promote to `.mex/patterns/add-mcp-tool.md` if not already.

### 4. Rule #21 cross-scaffold sync as the closure commit
- **Description:** When a session ships N backlog items, the FINAL commit updates ADAPTIVE_BACKLOG.md to move shipped items to the Completed section + downgrade related deferrals. Without this commit, the next-session opener loads stale "Open" rows for items already shipped.
- **Evidence:** Commit `e7824cf` closed 5 backlog items + downgraded the frontend hover panel + scout1-remaining-58 to LOW. Closure commit is ~13 lines but load-bearing for cross-session navigation.
- **Applies when:** Any session that ships ≥1 ADAPTIVE_BACKLOG.md item. The closure commit should be the LAST commit before the session-handoff.

### 5. Module-level counter dict + accessor for cross-session observability
- **Description:** When operators need visibility into "how many entries each gate rejected on last load", a per-load counter dict (reset at parse start) + public accessor + MCP-tool surfacing closes the loop. Cheaper than per-log search.
- **Evidence:** C10 `_LAST_LOAD_REJECTIONS` dict in `cve_matcher.py` tracking 4 categories (advisory_missing_advisory_id / advisory_id_too_long / advisory_id_duplicate_warn / f_forensic_10_no_narrowing). Surfaced via `get_known_firmware_load_rejections()` accessor + `load_rejections` MCP payload key.
- **Applies when:** Any closed-grammar validator that emits WARN logs but doesn't track the count. Add the counter dict + accessor + MCP surfacing in the same Rule #25 commit.

### 6. Opt-in YAML key for intentional convergence
- **Description:** When multiple YAML entries SHARE a discriminator value (advisory_id, dispatch case, etc.) intentionally — not by accident — the right closure is an opt-in flag (`shared_advisory_id: true`) that suppresses the default WARN. Asymmetric opt-in (only one entry declares) STILL WARNs — defense against silent collision-via-typo.
- **Evidence:** Rule #50 (FragAttacks shared advisory_id) — RvwA-A5+B6. The 3-test shape (both-opt-in suppressed; asymmetric opt-in WARNs; pre-flag backward-compat) generalizes to any "two YAML entries intentionally share a discriminator" case.
- **Applies when:** Operators authoring SPEC-level disclosure-batch CVEs that legitimately span multiple vendor entries (FragAttacks, KRACK, Dragonblood, BroadPwn). Pre-flag YAMLs keep working — backward-compat preserved.

### 7. The "alternative lanes" kickoff-prompt framing
- **Description:** Phase kickoff prompts should preserve a fallback-direction list ("alternative lanes if user prefers smaller scope"). When the user says "continue forward" after the main phase closes, the alternative-lane structure makes the next slice unambiguous.
- **Evidence:** P3.2 kickoff explicitly mentioned ADAPTIVE_BACKLOG.md §2 HIGH evening + §3.0 rate-limit follow-ups. The 5-item backlog sweep proceeded without re-deriving scope from postmortems.
- **Applies when:** Drafting a kickoff prompt for the next session's opener. Include 2-3 alternative lanes ranked by size + value.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Ship P3.3.a (shim deletion) ALONGSIDE backlog items | P3.2.e parity-snapshot conversion unblocked deletion; kickoff prompt item #6 explicitly listed it | shipped `4c028fc`; -700 net LOC |
| Use sync `TIER_A_HEAVY` for all 9 scout1 endpoints | Per Rule #51: sync CPU-bound work = TIER_A_HEAVY (5/hour); future P3.x may convert to 202+polling | shipped `3677f1c`; `_EXPECTED_TIERS` 11→20 |
| `verify_cve_attribution` returns YAML entry's `cves` list | Operator sees WHICH CVE family was matched; cheaper than re-querying describe_advisory | shipped `7420279`; cves added to matching_yaml_entry dict |
| Ship 5 backlog items without Wave-1/Wave-2 scout dispatch | ADAPTIVE_BACKLOG.md entries already carry convergence-doc-style implementation contract | 7 commits in <2 hours; 0 reverts |
| Cross-scaffold sync as the final commit | Rule #21 + Rule #47 consumer-hook enumeration | shipped `e7824cf`; ADAPTIVE_BACKLOG.md updated |
