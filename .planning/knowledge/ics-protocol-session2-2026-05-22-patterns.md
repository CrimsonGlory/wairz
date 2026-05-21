# Patterns: ICS Protocol Catalog — Session 2

> Extracted: 2026-05-22
> Campaign: direct-shipped (no campaign file); kickoff at
> `.planning/research/ics-protocol-session2-2026-05-22/SESSION-2-KICKOFF.md`
> Postmortem: `.planning/postmortems/postmortem-ics-protocol-session2-2026-05-22.md`
> Promotion: CLAUDE.md Rule #52 → **Rule-of-Three DURABLE BEYOND DEBATE**

## Successful Patterns

### 1. Wave-1 + Wave-2 cross-feature critique now Rule-of-Four
- **Description:** 5 single-axis Wave-1 expert-persona scouts
  (architecture / adjacency / red-team / operator-UX / state-machine
  precedence) dispatched in parallel; followed by 3 Wave-2 critique
  scouts (W2-α convergence + W2-β cross-feature blow-it-up + W2-γ
  Rule #28 yardstick). W2-β's "blow-it-up stage" surfaced 10 NEW
  §SC5-NEW-ICS-S2-α..κ attacks across Phase 1-6 feature seams that
  Wave-1 single-axis scouts architecturally couldn't see.
- **Evidence:** P3.1 (5 attacks) + P3.2 (3 attacks) + ICS S1 (6 attacks)
  + ICS S2 (10 attacks) = 24 cross-feature attacks across 4 applications.
  Promotes feedback memory to Rule-of-Four.
- **Applies when:** Any Rule #52 closed-grammar extension surface or
  ANY large multi-phase feature where pair-wise feature interactions
  matter.

### 2. MappingProxyType + closure-capture HARDENING for plugin freeze
- **Description:** Plugin registry uses TWO mechanisms together —
  (a) private mutable `_PLUGIN_REGISTRY` dict with public
  `PLUGIN_REGISTRY = MappingProxyType(_PLUGIN_REGISTRY)` read-only
  view, prevents `PLUGIN_REGISTRY[x] = y` direct mutation;
  (b) `_PLUGIN_REGISTRY_FROZEN: bool` flag flipped at lifespan
  startup so `register_matcher` raises post-freeze;
  (c) `_closure_capture_check` rejects matchers with AsyncSession /
  Settings / ContextVar / ToolContext in `__closure__`.
- **Evidence:** Closes W2-β §SC5-NEW-ICS-S2-α (module-level attribute
  shadow — the scariest unmitigated Session 1 W2-β attack) +
  §SC5-NEW-ICS-S2-ζ (request-scope leak via closure capture).
  Test_plugin_registry_is_mappingproxytype_read_only +
  test_mappingproxytype_gate_actually_blocks_direct_dict_write paired
  META-CANARY confirms the gate fires on synthetic violations.
- **Applies when:** ANY plugin registry needing freeze-after-startup
  semantics. **File-format catalog uses the bare-dict shape — backfill
  pending as Rule #21 mirror sweep.**

### 3. DUAL reaper registration for walker columns with .b result JSONB
- **Description:** ICS column `ics_protocol_walk_status` lives in
  BOTH `STATE_MACHINE_REAPER_CONFIGS` (8→9; operator-triggered +
  result JSONB shape) AND `WALKER_REAPER_CONFIGS` (25→26; suffix
  match). Reaper sweep applies both passes; second pass is a no-op
  (~1 ms) on a row already reaped by the first.
- **Evidence:** Scout E identified the suffix-introspection
  cross-check at `test_walker_reaper_configs_size_lock_matches_firmware_model:
  67-99` enforces every `*_walk_status` column to be registered in
  WALKER regardless of state-machine semantics. Exclusion-list
  alternative erodes the cross-axis guarantee.
- **Applies when:** Any new walker column carries both
  `_walk_status` suffix AND Rule #33 .b result JSONB (matching
  bare_metal_audit precedent).

### 4. Snapshot-pin at INNER entry for hot-reloadable catalogs
- **Description:** Walker INNER `_do_*_walk` reads
  `snapshot = catalog.get_snapshot()` ONCE at function entry; passes
  same snapshot to every resolver call. Reads exit snapshot at
  function end; stamps `consistency_warning` when entry_id !=
  exit_id. Downstream consumers gate attribution on
  `consistency_warning is None`.
- **Evidence:** Closes W2-β §SC5-NEW-ICS-S2-β (mid-walk catalog
  hot-reload tears classification — 90s walker scan + concurrent
  YAML edit produces heterogeneous JSONB results CVE matcher
  trusts). test_walker_detects_mid_walk_snapshot_drift +
  test_walker_no_drift_when_snapshot_stable paired META-CANARY.
- **Applies when:** Any walker consuming a hot-reloadable
  YAML/JSON catalog with mtime-cached snapshots.

### 5. Rule #35c sister-provenance gate for descriptor-route trust
- **Description:** JSONB stamp helper writes `provenance: "walker"`
  alongside `schema_version`. Downstream consumers (CVE matcher,
  cross-firmware lookup) gate attribution on
  `result.provenance == "walker"`. Hostile pre-seed of
  `provenance: "descriptor"` is OVERWRITTEN by stamp helper.
- **Evidence:** Closes W2-β §SC5-NEW-ICS-S2-1 (descriptor route
  pre-seeds `protocol_family_counts={"s7comm": 1}` causing false
  Siemens-CVE attribution on non-Siemens firmware).
  test_stamp_firmware_ics_protocol_walk_result_enforces_provenance_walker
  + test_..._overwrites_hostile_provenance paired META-CANARY.
- **Applies when:** ANY future descriptor-route ingest path
  (operator-pushed JSONB pre-seed) for walker result columns.

### 6. Cross-firmware MCP tool multi-gate filter pipeline
- **Description:** Rule #44 cross-firmware lookup applies FOUR gates
  per row before counting toward `match_count` or
  `supply_chain_signal`:
  (a) SQL filter `ics_protocol_walk_status = 'completed' AND
  result IS NOT NULL` (W2-β §SC5-NEW-ICS-S2-3);
  (b) Python `schema_version == 1` (§SC5-NEW-ICS-S2-ι legacy-rows);
  (c) Python `provenance == "walker"` (§SC5-NEW-ICS-S2-1);
  (d) Python absence of `consistency_warning` (§SC5-NEW-ICS-S2-β).
  AND: `supply_chain_signal` only fires when `match_count >= 2 AND
  manifest_sources_seen has _system|core` (§SC5-NEW-ICS-S2-γ I30
  curated-only).
- **Evidence:** 5 META-CANARIES across the Rule #44 lookup tool
  test suite — paired exhaustive coverage of each gate.
- **Applies when:** ANY Rule #44 cross-firmware tool reading JSONB
  walker result columns (linux_systemd / journald / etc. should
  audit/backfill).

### 7. Closed-grammar walker emit with allowlist gate
- **Description:** Walker module derives
  `_ALLOWED_<FAMILY>_FINDING_SOURCES =
  frozenset(get_args(<FindingSourceLiteral>))` as SINGLE SOURCE OF
  TRUTH; walker inner checks `source in allowlist` before
  `FindingService.create`. Unmapped families silently skip emit
  rather than raising 422.
- **Evidence:** Closes W2-β §SC5-NEW-ICS-S2-η (future YAML
  extension adds a new protocol_family without DB CHECK extension →
  silent FastAPI 422). Walker test
  `test_walker_ics_finding_source_allowlist_matches_pydantic_literal`
  enforces drift = 0.
- **Applies when:** Walker emits findings using a closed-Literal
  source-set + the DB CHECK is the safety floor.

### 8. Per-piece Rule #25 commit chain at scale (10 commits / 0 reverts)
- **Description:** Phase 1 split into 4 commits (alembic+ORM /
  normaliser / triplet / registry+reaper) per Scout B + Scout E
  recommendation. Each commit individually revertable; tests pass
  before next commit starts. Phase 2 single-slice cross-stack
  alignment per Rule #25 single-slice exception #2. Phase 3 single
  commit (MCP tools + tests bundled). Phase 4 single Rule #25
  Shape-1 atomic (plugin + freeze + lifespan + tests). Phase 5 split
  per-protocol (DNP3 + S7Comm). Phase 6 docs atomic.
- **Evidence:** 10 commits, 0 reverts, bisect-clean across all,
  980/980 test sweep green throughout.
- **Applies when:** Any multi-phase Rule #52 closed-grammar
  extension; the per-piece + single-slice exception mix is durable.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DUAL reaper (STATE_MACHINE + WALKER) | Scout E's suffix-introspection check at `test_walker_reaper_configs_size_lock_matches_firmware_model:67-99` enforces every *_walk_status column in WALKER; exclusion-list erodes the cross-axis guarantee | Worked — 980 tests green |
| Scout B template-copy projection over Scout A's higher estimate | Heavy template-copy (~60-70% mechanical s/bare_metal/ics/) compresses per-LOC pace; W2-γ measured 5,569 midpoint matched Session 1 actual within 0.3% | Worked — actual 4,529 LOC came in -19% under midpoint |
| Sub-route `/projects/{id}/ics-protocols` over tab-on-FirmwareDetailPage | No FirmwareDetailPage exists in wairz; sub-route mirrors FindingsPage/SbomPage precedent | Adopted but DEFERRED — frontend page is future-session work |
| Plugin freeze in lifespan AFTER catalog warmup BEFORE yield | Freeze MUST be set before any request can reach a register_matcher; catalog warmup must complete first so YAML's plugin.name references resolve | Worked — Rule #46 META-CANARY confirms textual ordering |
| MappingProxyType HARDENING over bare-dict freeze | W2-β confirmed bare freeze NOT iron-clad against module-level attribute shadow; MappingProxyType + closure-capture is the durable shape | Worked — paired META-CANARY confirms direct write raises TypeError |
| DEFER REST router + frontend page | W2-γ marked HTTP endpoint optional; MCP-only access sufficient for v0 | Worked — kept session scope at 10 commits within W2-γ budget |
| DEFER file_format_catalog backfill to MappingProxyType | Rule #21 mirror sweep is heavier than session budget allows; documented in postmortem as follow-up | Pending — queued in postmortem recommendations |
| Per-protocol Rule #25 split for Phase 5 (5.A DNP3 / 5.B S7Comm) | Cross-protocol matrix tests require both YAMLs; restructured tests so matrix lands in 5.B | Worked — bisect-clean, both protocols independently revertable |

## Companion Notes

**Operator session pace:** 10 commits / 4,529 net LOC / 80 new tests
/ 0 reverts / bisect-clean / 980-test broader sweep all green.
Slightly under W2-γ midpoint projection (-19%) due to template-copy
discipline. Sustained-pace estimate: ~450 LOC/commit, 9 commits/session
under per-piece Rule #25 discipline.

**Rule #52 Rule-of-Three durability:** Three applications now
(bare-metal MCU 2026-05-19 + file-format YAML registry 2026-05-19 +
ICS protocol catalog 2026-05-20/22) share IDENTICAL architectural
shape: closed-grammar Pydantic Literals + free-string output
taxonomy + plugin escape hatch + walker dispatch + Rule #44 cross-
firmware tool + Rule #46 paired META-CANARIES + Wave-1+Wave-2
methodology. Rule-of-Three DURABLE BEYOND DEBATE locks the shape
as the durable template for any future closed-grammar surface.
