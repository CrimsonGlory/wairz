# ICS Protocol Catalog — Session 2 Kickoff Brief

> Status: PLANNED (next session)
> Source: queued from 2026-05-20 Session 1 closure + 2026-05-21 SBOM
> regression sweep closure (Sessions 1 + 2a + 2b shipped; ICS S2 is the
> next-priority queued work).
> Purpose: complete the Rule #52 instance #3 surface (walker + ORM +
> alembic + DB CHECK + JSONB normaliser + orphan reaper + MCP tools +
> bundled plugins + remaining 2 protocols). Promotes CLAUDE.md Rule #52
> from Rule-of-Two to **Rule-of-Three DURABLE BEYOND DEBATE**.

## Operator Direction Verbatim

From the 2026-05-21 SBOM regression directive opener:

> "When the SBOM + vuln-scan surfaces are GREEN again, resume ICS protocol
> Session 2 (queued in .planning/postmortems/postmortem-ics-protocol-
> session1-2026-05-20.md Session-2 plan) — that work will promote
> CLAUDE.md Rule #52 from Rule-of-Two to Rule-of-Three DURABLE BEYOND
> DEBATE when the walker + MCP tools + bundled plugins close."

SBOM is now green (Session 2b closed 2026-05-21 evening — commits
`c29d6b7..df0f548`). ICS S2 is the queued next-priority work.

## Session 1 Surface Already Shipped

Per `.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md`:

- Commits `0dabbd6..1d0d0a9` (3 ICS commits / +5,552 net LOC / 114 tests)
- Schema: 11 closed Literals + 5 Pydantic sub-models + IcsProtocolManifest +
  IcsProtocolMatch + IcsDeprecation
- Catalog: mtime-cached `MtimeCachedYamlLoader` + I1/I2/I4 cross-feature gates
  (placeholder for I3/I5/I6/I7) + path cross-check (W2-β §SC5-NEW-ICS-4
  authority laundering mitigation) + graceful-degrade
- Resolver: closed dispatch over 5 IcsSignalKind values (3 active:
  magic_bytes + string_in_binary + function_code_set; 2 stub:
  port_signature + library_symbol)
- v0 YAML: 1 production manifest (`_system/modbus_tcp.yaml`)
- 17 paired Rule #46 META-CANARIES (11 closed-Literal exhaustive + 3
  dispatch-table exhaustive + 3 anti-hardcode AST)

## Session 2 Scope (Per Session 1 W2-γ + Postmortem Recommendations)

### Phase 1: Walker + ORM + State Machine (~2,200 LOC per Session 1 W2-γ)

Per CLAUDE.md Rule #39 inner/outer/safe runner triplet pattern (worked
examples: BCD walker `3161a70`, windows_update_diff `8b3c4d5`, evtx
`c0e4979`, prefetch `f076808`, srum `661355c`):

- `backend/app/services/ics_protocol_walker.py` (NEW):
  - `_do_ics_protocol_walk(db, firmware_id) -> dict` — INNER pure-logic
    orchestrator. Calls `resolve_all()` (the Session 1 resolver) against
    every binary in `get_detection_roots(firmware)` per Rule #16; returns
    result-aggregate dict UNSTAMPED.
  - `run_ics_protocol_walk_background(firmware_id) -> None` — OUTER
    state-machine wrapper. Owns own `async_session_factory()`. Cycles
    `idle → queued → running → completed | failed`. Stamps result
    aggregate per Rule #33 .b. Outer guard catches anything.
  - `auto_ics_protocol_walk_firmware_safe(firmware_id) -> None` — UNPACK-
    POST-DETECTION HOOK. Swallows exceptions silently. Stamps result but
    does NOT mutate `ics_protocol_walk_status` (Rule #39 .safe semantics).

- `backend/app/models/firmware.py`:
  - Add columns: `ics_protocol_walk_status` Mapped[str] NOT NULL
    DEFAULT 'idle' + `ics_protocol_walk_started_at` + `_finished_at` +
    `_error` + `ics_protocol_walk_result` JSONB

- `backend/alembic/versions/<NEW>_add_ics_protocol_walk_to_firmware.py`
  (NEW): adds 5 columns + CHECK constraint
  `ck_firmware_ics_protocol_walk_status`. Mirrors Session 2a's
  `feab18c9d201_add_sbom_status_to_firmware.py` shape exactly.
  `down_revision` = current alembic head at session start (run
  `ls backend/alembic/versions/ | sort | tail -1` to confirm).

- `backend/app/services/jsonb_normalizers.py`:
  - Per CLAUDE.md `Adding a Database Table` discipline: add
    `_normalize_firmware_ics_protocol_walk_result(value)` boundary
    normaliser + `ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION = 1` constant +
    `_stamp_firmware_ics_protocol_walk_result(payload)` writer helper.

- `backend/app/main.py`:
  - Extend `STATE_MACHINE_REAPER_CONFIGS` (in
    `walker_registry.py`) with `ics_protocol_walk_status` entry.
    Rule #46 META-CANARY in `test_main_lifespan_reapers.py` size-locks
    grow from 8 → 9 (state machine) — single-edit update.
  - Reaper sweep then picks it up automatically via the data-driven
    Session 2b Fix #11 sweep.

- `backend/app/workers/walker_registry.py`:
  - Add `auto_ics_protocol_walk_firmware_safe` to `_load_walker_safe_runners()`
    + the registry list entry (alphabetical position).
  - Extend `WALKER_REAPER_CONFIGS` (in same file) with the
    `ics_protocol_walk_status` config (the walker shipping here is
    operator-triggered via the MCP tool too, so reaper coverage is
    load-bearing; mirrors the bare_metal_audit pattern).
  - **However**: per the CURRENT Session 2b dict shape, `ics_protocol_walk_status`
    could go in EITHER STATE_MACHINE_REAPER_CONFIGS or WALKER_REAPER_CONFIGS.
    The bare_metal_audit precedent puts the operator-triggered state-machine
    column in STATE_MACHINE (because it has matching Rule #33 .b result
    JSONB). ICS protocol walker mirrors this — operator-triggered via
    `trigger_ics_protocol_walk` MCP tool + `ics_protocol_walk_result` JSONB
    on Firmware. Recommend: put it in STATE_MACHINE_REAPER_CONFIGS (Session
    2b size-lock becomes 9).
  - Rule #46 META-CANARY in `test_main_lifespan_reapers.py`:
    update the size-lock assertion from 8 → 9.

- `backend/app/services/firmware_service.py`:
  - Extend `_post_process_pipeline._fire_walker_auto_triggers` to call
    `auto_ics_protocol_walk_firmware_safe` (per Session 1 Fix #4
    walker_registry-derived dispatch).

- Test scaffolding (Session 1 precedent):
  - `backend/tests/test_ics_protocol_walker.py` — Rule #39 triplet tests
    (inner against `make_live_db()`, outer + safe via mocks of session
    factory)
  - Rule #46 META-CANARY suite extension

### Phase 2: Walker Auto-Trigger + Finding-Source Cross-Stack Alignment (~480 LOC)

Per CLAUDE.md Rule #25 Shape-1 single-slice atomic commit:

- `backend/alembic/versions/<NEW>_extend_findings_source_ics_protocol.py`:
  Extend `ck_findings_source` CHECK constraint to include new
  `IcsProtocolFindingSource` values (e.g. `ics_modbus_tcp_detected`,
  `ics_dnp3_detected`, `ics_s7comm_detected`).
- `backend/app/schemas/finding.py`:
  Add `IcsProtocolFindingSource = Literal[...]` + extend `FindingSource`
  union if separately typed.
- `frontend/src/types/index.ts`:
  Mirror the new finding sources in the `FindingSource` union.
- `frontend/src/constants/statusConfig.ts`:
  Add entries to `FINDING_SOURCE_CONFIG` map (icon + description).
- `backend/tests/test_finding_source_alignment.py`:
  Extend with new ICS source value rows.

Per Rule #25 single-slice exception #2: all 5 files ship in ONE atomic
commit because `test_finding_source_alignment.py` enforces pairwise
agreement across all 4 surfaces (DB CHECK + Pydantic Literal + frontend
Union + frontend Config map). Splitting leaves the alignment test red
between commits — bisect-non-clean.

### Phase 3: MCP Tools (~1,100 LOC per Session 1 W2-γ)

Per CLAUDE.md Rule #44 mandatory `lookup_*_across_firmwares`:

- `backend/app/ai/tools/ics_protocol.py` (NEW): new MCP tool category.
  Minimum 4 tools:
  - `trigger_ics_protocol_walk(firmware_id)` — operator-trigger MCP per
    Rule #33 .a 5-state column
  - `list_ics_protocols(firmware_id)` — returns detected protocols for
    one firmware
  - `lookup_ics_protocol_across_firmwares(query)` — Rule #44 MANDATORY
    cross-firmware aggregation (groups by firmware; emits
    `match_count` + `supply_chain_signal` per
    `lookup_systemd_unit_across_firmwares` precedent in
    `linux_systemd.py:437,772`)
  - `describe_ics_protocol_anomalies(firmware_id)` — operator-UX surface
    for the unusual matches

- `backend/app/ai/__init__.py`: import + call `register_ics_protocol_tools(registry)`.

### Phase 4: Bundled Plugin + W2-β §SC5-NEW-ICS-7 Hot-Reload Mitigation (~500 LOC)

Per Session 1 W2-β findings + Rule #52 instance #2 (file-format catalog)
HYBRID plugin precedent:

- `backend/app/services/ics_protocol_catalog/plugins/string_scanner.py`
  (NEW): bundled string-scanner plugin implementing the
  `IcsProtocolMatcherProto` from Session 1's schema. Specific to
  artefacts that need free-string library-symbol scans (e.g. detecting
  the literal byte sequence `LibModbus` in a binary).
- `backend/app/services/ics_protocol_catalog/__init__.py`:
  Add `register_matcher` / `freeze_plugin_registry` per
  W2-β §SC5-NEW-ICS-7 hot-reload mitigation. The plugin registry MUST
  be FROZEN post-startup (`freeze_plugin_registry()` called in
  `main.py:lifespan` after the catalog loads). Hot-reload of YAML
  manifests at runtime is allowed; plugin registration at runtime is
  NOT — closes the §SC5-NEW-ICS-7 hot-reload × plugin attack vector.
- Rule #46 META-CANARY: paired synthesize-and-assert canary confirming
  `register_matcher()` raises if called post-freeze.

### Phase 5: DNP3 + S7Comm YAMLs (~300 LOC × 2 = 600 LOC YAML + tests)

Per CLAUDE.md Rule #25 Shape-1 (cross-stack alignment per protocol):

- `backend/app/services/ics_protocol_catalog/data/ics_protocols/_system/dnp3.yaml`:
  3-signal `combine=all_required` (transport TCP/UDP port 20000 +
  function code allowlist + magic_bytes start sentinel). Mirrors Session
  1's `modbus_tcp.yaml` shape.
- `backend/app/services/ics_protocol_catalog/data/ics_protocols/_system/s7comm.yaml`:
  3-signal `combine=all_required` (TCP port 102 + COTP framing magic +
  function code allowlist).
- Test scaffolding: 5-10 e2e tests per YAML.

### Phase 6: CLAUDE.md Rule #52 Rule-of-Three Promotion (~200 LOC docs)

Per CLAUDE.md Rule #25 single-slice exception #2 + Rule #21 mirror:

- Update CLAUDE.md Rule #52 worked-example block to add ICS protocol
  catalog as instance #3 (Rule-of-Three DURABLE BEYOND DEBATE).
- Mirror update in `.mex/context/conventions.md` per Rule #21.
- Promote `.mex/patterns/add-signal-kind.md` recipe per Session 1
  Recommendation #7 (Rule-of-Three threshold reached:
  P3.2.b TextFormatConstraint + P3.x SubstringInHeadConstraint +
  Session 1 IcsStringInBinaryConstraint/IcsFunctionCodeSetConstraint).

## Estimated Scope (Per Session 1 W2-γ Projection)

Per `wave2-gamma-yardstick.md` in `.planning/research/ics-protocol-2026-05-20/`:

> Session 2 ships the walker + walker MCP tools + bundled plugins + 2
> more protocols (DNP3 + S7Comm) + Rule #52 Rule-of-Three promotion +
> recipe promotion. ~3,000 LOC.

W2-γ Session 1 broke this down:
- Walker (Rule #39 triplet): ~2,200 LOC
- Auto-trigger + Rule #25 Shape-1 alignment: ~480 LOC
- MCP tools: ~1,100 LOC
- Bundled plugin + I16 hot-reload mitigation: ~500 LOC
- DNP3 + S7Comm YAMLs + tests: ~600 LOC
- CLAUDE.md + recipe promotion: ~200 LOC

**Total projected: ~5,080 LOC raw + Rule #28 +14-22% drift = ~6,000 LOC
adjusted.** Larger than Session 1's actual 5,552. May need a Session 2a + 2b
split per the SBOM precedent — W2-γ in the next session will arbitrate.

## Wave-1 + Wave-2 Dispatch Plan (Run At Next-Session Start)

Per `feedback_wave2_cross_feature_methodology.md` Rule-of-N proven across
- Rule #52 P3.1 (file-format YAML registry Wave-1+Wave-2)
- Rule #52 P3.2 (file-format catalog refinements)
- ICS Session 1 (3 ICS commits + Rule #52 instance #3 scaffold)
- SBOM Session 1 (regression cascade — methodology extension)
- SBOM Session 2a (structural conversion — methodology extension)
- SBOM Session 2b (consumed Session 2a artefacts — confirms shelf-life)

Dispatch 5 Wave-1 single-axis scouts + 3 Wave-2 critique scouts in parallel
at start of ICS S2:

### Wave-1 (5 scouts):

- **Scout A — Architecture / current state**: read every ICS-S1-shipped
  artefact. Reconstruct the end-to-end flow from upload → detection →
  resolver → walker (this session's NEW). Identify integration points
  with `_post_process_pipeline._fire_walker_auto_triggers` (Session 1
  Fix #4 of the SBOM sweep). Map against bare_metal_walker.py +
  registry_hive_walker.py as Rule #39 triplet exemplars. Identify the
  `STATE_MACHINE_REAPER_CONFIGS` vs `WALKER_REAPER_CONFIGS` placement
  decision (per Session 2b Fix #11 design).

- **Scout B — Adjacency / precedent**: read bare_metal_walker (Rule #52
  instance #1 walker) + sbom_status conversion (Session 2a Fix #1
  precedent for the alembic + Pydantic + DB CHECK + frontend mirror
  pattern). Identify which Phase-1-Phase-6 deliverables can share
  helpers vs need their own.

- **Scout C — Red-team / adversarial**: extend Session 1's
  §SC5-NEW-ICS-5..10 attack catalog. Apply W2-β cross-feature blow-up
  to the seams: walker × hot-reload × MCP tool × YAML extension. Per
  Session 2 SBOM regression W2-β: every NEW operator-extensible YAML
  surface needs path-cross-check authority laundering protection (the
  `_system/` source-of-truth gate). ICS S2 ships bundled string-scanner
  plugin — verify the Session 1 `freeze_plugin_registry()` plan ships
  in this session's Phase 4.

- **Scout D — Operator-UX**: what does the operator see for an
  ICS-protocol-detected firmware? New "ICS Protocols" tab on the
  Firmware Detail page? Cross-firmware lookup page wired to the
  Rule #44 mandatory `lookup_ics_protocol_across_firmwares` MCP tool?
  Polling shape for `trigger_ics_protocol_walk` (use the Session 2b
  `usePollingBackoff` hook).

- **Scout E — Rule #51 partner / state machine**: design the
  `ics_protocol_walk_status` column's full Rule #33 4-bullet contract.
  Wire into the Session 2b two-axis reaper sweep
  (`STATE_MACHINE_REAPER_CONFIGS` extension from 8 → 9 entries). Verify
  rate-limit tier assignment (TIER_A_LIGHT_ACK 30/hour matches operator-
  triggered MCP polling cadence).

### Wave-2 (3 scouts, after Wave-1 returns):

- **W2-α convergence**: synthesize 5 Wave-1 reports; pick 1-3 root
  causes for the multi-phase scope; resolve contradictions; produce
  shipping order; mandatory: confirm Phase 4 plugin-freeze ships in
  this session (NOT deferred — was W2-β CRITICAL in Session 1).

- **W2-β cross-feature blow-up**: combine pairs of Phase-1..6
  deliverables at their seams. Specific attack scenarios to enumerate:
  - Phase 1 walker × Phase 4 plugin × hot-reload registry
  - Phase 3 cross-firmware MCP tool × multi-tenant scope leak
  - Phase 5 protocol YAML × authority laundering at `_system/` path
  - Phase 6 recipe promotion × silent regression on the Rule #52
    Rule-of-Three claim

- **W2-γ Rule #28 yardstick**: `wc -l` measure of every file Phase
  1-6 will touch. Apply Rule #28 +14-22% drift. Verdict: SINGLE-SESSION
  vs MULTI-SESSION (Session 2a + Session 2b split per SBOM precedent).
  Given ICS S1's ~5,552 LOC scaffold + this session's projected
  ~6,000 LOC adjusted, MULTI-SESSION is likely. W2-γ arbitrates.

## Reading List (Pre-Dispatch)

Required reading before dispatching the 5 Wave-1 scouts:

- `.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md`
  — full Session 1 narrative + Session 2 plan
- `.planning/research/ics-protocol-2026-05-20/wave2-*.md` — Session 1's
  Wave-2 reports (W2-α convergence resolution + W2-β attack catalog +
  W2-γ yardstick projecting Session 2 scope)
- `.planning/knowledge/file-format-yaml-registry-p32-2026-05-19-patterns.md`
  — Rule #52 instance #2 closed-grammar pattern reference
- `.planning/knowledge/bare-metal-mcu-rule52-phase1-phase2-2026-05-19-patterns.md`
  — Rule #52 instance #1 closed-grammar pattern reference
- `.planning/knowledge/sbom-vuln-scan-session2a-2026-05-21-patterns.md`
  — Session 2a's Rule #25 single-slice + cross-stack alignment + 202+polling
  conversion patterns
- `.planning/knowledge/sbom-vuln-scan-session2b-2026-05-21-patterns.md`
  — Session 2b's data-driven sweep + two-axis registry + introspection-based
  META-CANARY patterns
- CLAUDE.md Rule #52 worked-example block (currently Rule-of-Two)
- CLAUDE.md Rule #44 (mandatory cross-firmware MCP tool)
- CLAUDE.md Rule #39 (inner/outer/safe runner triplet)
- CLAUDE.md Rule #25 single-slice exception #2 + Rule #48 5-part shape

## Recommended Pre-Flight (Operator)

1. `docker compose ps` — confirm backend + worker + frontend healthy
   post-Session-2b commits + Phase A1/A2.
2. `docker compose up -d --build backend worker migrator` — Rule #8
   baseline rebuild to pick up the auth-gate removal + allow_no_auth
   default flip.
3. `docker cp backend/tests wairz-backend-1:/app/tests && docker compose
   exec backend uv run pytest tests/test_main_lifespan_auth_gate.py
   tests/test_main_lifespan_reapers.py tests/test_sbom_status_alignment.py
   tests/test_background_task_sweep.py -q --tb=line` — baseline confirm
   all 2026-05-21-shipped META-CANARIES still green.

## Suggested Next-Session Kickoff Prompt (Copy/Paste)

```
ICS protocol catalog Session 2 — kickoff per the queued plan at
.planning/research/ics-protocol-session2-2026-05-22/SESSION-2-KICKOFF.md
and the originating Session 1 postmortem at
.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md.

Operator's directive (from 2026-05-21 SBOM regression sweep opener):
"resume ICS protocol Session 2 — that work will promote CLAUDE.md
Rule #52 from Rule-of-Two to Rule-of-Three DURABLE BEYOND DEBATE
when the walker + MCP tools + bundled plugins close."

Use Wave-1 + Wave-2 deep research methodology per
feedback_wave2_cross_feature_methodology.md. Dispatch 5 Wave-1
single-axis scouts + 3 Wave-2 critique scouts in parallel.

PRE-FLIGHT:
1. docker compose -f /home/dustin/code/wairz/docker-compose.yml ps
2. docker compose up -d --build backend worker migrator
3. docker cp backend/tests wairz-backend-1:/app/tests
4. docker compose exec -T -w /app backend uv run pytest \
     tests/test_main_lifespan_auth_gate.py \
     tests/test_main_lifespan_reapers.py \
     tests/test_sbom_status_alignment.py \
     tests/test_background_task_sweep.py \
     -q --tb=line
   (Baseline: confirm 2026-05-21-shipped META-CANARIES still green.)

WAVE-1 DISPATCH (5 scouts in parallel — each ~2500 word structured
report saved to .planning/research/ics-protocol-session2-2026-05-22/
wave1-scout-{A,B,C,D,E}-{persona}.md):

  Scout A — Architecture / current state. Reconstruct end-to-end
    flow upload → detection → resolver → walker. Identify
    STATE_MACHINE_REAPER_CONFIGS vs WALKER_REAPER_CONFIGS placement
    for ics_protocol_walk_status (recommend STATE_MACHINE per
    bare_metal_audit precedent).

  Scout B — Adjacency / precedent. Read bare_metal_walker (Rule #52
    instance #1) + sbom_status conversion (Session 2a Fix #1 precedent).
    Identify shareable helpers across Phases 1-6.

  Scout C — Red-team / adversarial. Extend Session 1 §SC5-NEW-ICS-5..10
    catalog. Apply W2-β cross-feature blow-up: walker × hot-reload ×
    MCP tool × YAML extension. Verify freeze_plugin_registry() ships
    in this session's Phase 4.

  Scout D — Operator-UX. New ICS Protocols tab on Firmware Detail
    page; cross-firmware lookup wired to lookup_ics_protocol_across_firmwares;
    polling shape for trigger_ics_protocol_walk via Session 2b
    usePollingBackoff hook.

  Scout E — Rule #51 state-machine + reaper coverage extension. Wire
    ics_protocol_walk_status into Session 2b's two-axis reaper sweep
    (STATE_MACHINE_REAPER_CONFIGS 8 → 9 entries). Confirm tier
    alignment (TIER_A_LIGHT_ACK 30/hour).

WAVE-2 DISPATCH (3 scouts after Wave-1 returns):
  W2-α convergence; W2-β cross-feature blow-up (especially Phase
    4 plugin-freeze CRITICAL); W2-γ Rule #28 yardstick (likely
    MULTI-SESSION — projected ~6,000 LOC adjusted).

EXECUTE per Rule #25 per-piece commits; Rule #48 5-part for
cross-stack alignment; Rule #46 paired META-CANARIES; postmortem +
/citadel:learn at close. Promote Rule #52 worked-example block to
Rule-of-Three DURABLE BEYOND DEBATE in CLAUDE.md when full surface
ships.
```

## Tracking Status

- **PLANNED**: this brief (Session 2b Phase B closure, 2026-05-21)
- **QUEUED**: Session 2 dispatch on next-session start
- **EXECUTION-START-CONDITION**: SBOM/vuln-scan surfaces GREEN (✅ confirmed
  Session 2b closure 2026-05-21 evening; Phase A1+A2 polish closed
  2026-05-21 same evening)
- **NEXT-ACTION-OWNER**: operator (pick up at next session start)

When this work ships, mark complete in ADAPTIVE_BACKLOG section 5 with
the final commit chain SHA range + the Rule #52 Rule-of-Three promotion
worked-example block diff.
