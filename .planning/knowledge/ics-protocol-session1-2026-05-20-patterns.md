# Patterns: ICS Protocol Catalog — Session 1 (2026-05-20)

> Extracted: 2026-05-20
> Campaign: (no campaign file — direct-shipped per Rule #25 per-piece cadence)
> Postmortem: .planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md
> Commits: 0dabbd6..91bf4e5 (4 commits — 3 ICS commits + closure)
> Research artefacts: .planning/research/ics-protocol-2026-05-20/

## Successful Patterns

### 1. Wave-1 + Wave-2 methodology — Rule-of-Two for Rule #52 extensions
- **Description:** When tackling a Rule #52 third-application surface, dispatch 5 Wave-1 expert-persona scouts (architecture / adjacency / red-team / operator-UX / precedence) in parallel + 3 Wave-2 critique scouts (alpha convergence / beta cross-feature blow-it-up / gamma Rule #28 yardstick) in parallel after Wave-1 returns. 8 scouts total. Each scout returns ~1500-3000 words of structured findings.
- **Evidence:** P3.1 (Phase 3.1 file-format YAML) + P3.2 (Phase 3.2 closure) + this session = Rule-of-Three for the methodology itself. Documented in `feedback_wave2_cross_feature_methodology.md`.
- **Applies when:** Tackling a Rule #52 third-application or higher surface; user explicitly invokes "deep research + Citadel" framing; greenfield architectural decision with multiple acceptable shapes.

### 2. W2-γ Rule #28 yardstick CATCHES Wave-1 over-estimates BEFORE shipping
- **Description:** Wave-1 Scout A's intuitive LOC estimates routinely undershoot reality by 1.5-3×. The Wave-2 γ yardstick scout runs `wc -l` on REFERENCE files (file_format.py, file_format_catalog/*, walker examples, MCP tool examples) and applies Rule #28 +14-22% drift adjustment. Verdict: SINGLE-SESSION-FEASIBLE? or MULTI-SESSION-RECOMMENDED?
- **Evidence:** This session — Scout A said 1.5× P3.2 (~4000 LOC); W2-γ measured ~3.8× P3.2 (~10,300 LOC). HONORED gamma's verdict → multi-session split → Session 1 = ~4500 LOC scaffold; Session 2 = walker + activation.
- **Applies when:** Any Wave-1 estimate that touches >2× P3.2 baseline; before writing the first line of code; load-bearing for multi-session campaigns.

### 3. Multi-session FOUNDATION-first split
- **Description:** When W2-γ verdict is MULTI-SESSION-RECOMMENDED, Session 1 ships the FOUNDATION (schema + catalog + resolver + 1 minimal end-to-end YAML) without activating the consumer surface (walker + MCP tools). Session 2 wires the consumer + ships remaining YAMLs + promotes Rule #52 to Rule-of-Three. The foundation is DEAD CODE in production per Rule #27 N-additive + 1-cutover, but THOROUGHLY TESTED.
- **Evidence:** Session 1 shipped 3 commits / +5,552 net LOC / 114 tests, all green; Session 2 starts on solid ground vs greenfield.
- **Applies when:** Large Rule #52 surface where W2-γ says multi-session; the foundation can be tested end-to-end without the walker.

### 4. Sub-model + symmetric-reject + extra='forbid' + Rule #46 anti-hardcode AST canary — Rule-of-Three now
- **Description:** Adding a new closed-grammar signal kind to a Rule #52 catalog follows an identical 4-element pattern across 3 instances:
    1. Sub-model with closed Literal sub-fields + `extra='forbid'` + own model_validator
    2. DetectionSignal `<kind>_constraint: Constraint | None` field
    3. DetectionSignal `_check_kind_fields` validator branch with REQUIRED-when-kind + SYMMETRIC-REJECT (constraint set on wrong kind = mis-author error)
    4. Evaluator at `_eval_<kind>` consuming ONLY the constraint's declared fields; Rule #46 paired anti-hardcode AST canary forbids hardcoded byte literals in the evaluator body
- **Evidence:** 3 applications:
    - P3.2.b TextFormatConstraint (file-format catalog)
    - P3.x SubstringInHeadConstraint (file-format catalog, 2026-05-20 morning)
    - Session 1 IcsStringInBinaryConstraint + IcsFunctionCodeSetConstraint (this session)
- **Applies when:** Extending any Rule #52 closed-grammar catalog with a new signal kind. **Promote to `.mex/patterns/add-signal-kind.md` recipe.**

### 5. Closed-grammar Pydantic Literals + free-string taxonomy + sibling subpackage = durable Rule #52 shape
- **Description:** Each Rule #52 application uses the same architectural template:
    - `data/<surface>/<vendor>/<entry>.yaml` (operator-extensible)
    - 5-source ManifestSource Literal (_system / core / operator / attested_external / unauthenticated_external)
    - mtime-cached YAML loader with hot-reload
    - closed dispatch table with Rule #46 paired exhaustive canaries
    - sibling subpackage isolation (separate resolver per catalog)
    - HYBRID plugin escape hatch (deferred to follow-on sessions for sub-Rule-#52 surfaces)
- **Evidence:** Three Rule #52 applications now (bare-metal MCU/DSP / file-format YAML registry / ICS protocol catalog). **Promotes Rule #52 to Rule-of-Three DURABLE BEYOND DEBATE when Session 2 closes.**
- **Applies when:** Any future adaptable-extension surface; the durable template is established.

### 6. Multi-protocol-per-binary cardinality (resolve_all vs file_format resolve)
- **Description:** Some Rule #52 surfaces have 1:N cardinality (one binary → N detections), some have 1:1 (one blob → one format). When the surface is 1:N, the resolver MUST return `list[Match]` (e.g. `resolve_all()`), NOT a single match. This is a CARDINALITY decision driven by the operator-facing reality, not a design choice.
- **Evidence:** file_format = single-format-per-blob (`FormatMatch`); ICS = multi-protocol-per-binary (`list[IcsProtocolMatch]`). Wave-1 Scout A observed: an HMI binary can speak Modbus + OPC-UA + DNP3 simultaneously.
- **Applies when:** Designing a new Rule #52 catalog; ask the operator-UX scout for cardinality before writing the resolver.

### 7. `combine: all_required` discipline is the operator-UX answer to W2-β §SC5-NEW combine-mode-permissive attacks
- **Description:** W2-β surfaces attacks where weak signals composed via `combine: any` allow single-signal hits (banner-only / port-only) to fire false positives. The mitigation is BY-CONSTRUCTION: ship v0 YAMLs with `combine: all_required` that force co-occurrence of multiple signal kinds. The v0 Modbus YAML uses banner + port + function-code table (3 signals all_required).
- **Evidence:** W2-β §SC5-NEW-ICS-2 (combine-mode permissive composition attack). The v0 Modbus YAML's 4 e2e test cases verify that banner-only / port-only / function-codes-only DO NOT match.
- **Applies when:** Any new closed-grammar catalog YAML — default to combine=all_required for operator-tier manifests; require explicit justification + W2-β review for combine=any.

### 8. Path cross-check at catalog load (W2-β §SC5-NEW authority-laundering mitigation)
- **Description:** When loading an operator-supplied YAML, cross-check the DECLARED `manifest_source` against the ON-DISK path tier. If operator drops a file at `.local/hostile.yaml` declaring `manifest_source: _system`, REJECT with a structured WARN. Prevents authority laundering.
- **Evidence:** Mirror of file_format_catalog `_expected_source_for_path`; this session implemented `_expected_source_for_path` + `_expected_source_for_overlay_path` + path-tier WARN logging.
- **Applies when:** Any Rule #52 catalog with operator overlay support. 3 e2e test cases verify the cross-check.

### 9. Closed dispatch tables + Rule #46 PAIRED META-CANARIES on every exhaustive
- **Description:** Every closed-Literal → Python-dispatch table (SIGNAL_EVALUATORS, _SIGNAL_COST_CLASS, _SOURCE_PRECEDENCE, _TIER_RANK, etc.) ships with TWO META-CANARIES:
    1. Exhaustive — declared values == wired values
    2. Paired gate-canary — synthesize a missing entry, assert exhaustive REJECTS
- **Evidence:** This session shipped 3 paired exhaustive canaries (SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS + _SOURCE_PRECEDENCE) + 11 paired closed-Literal canaries + 2 paired anti-hardcode AST canaries = 16 paired tests total.
- **Applies when:** Every dispatch table in a Rule #52 catalog. **Rule #46 §gate-canary-requirement is mandatory** — exhaustive without paired gate-canary is a silent-pass risk per the substring_in_head session's lessons.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Lane B.3 ICS protocol decoders (over USB descriptors / JTAG TAP / decoder families / vendor adapters) | Highest operator leverage for OT/ICS firmware RE; substantially different abstraction from chip-family + file-format; substantially absent in wairz today | Greenfield surface; 3 commits / 5,552 net / 114 tests / 0 reverts |
| Dispatch Wave-1 + Wave-2 methodology (8 scouts) | User's "deep research + Citadel" framing; mirrors P3.1/P3.2 Rule-of-Two methodology | 8 scout reports surface 4 §SC5-NEW-ICS attacks Wave-1 missed; W2-γ catches over-ambitious sizing |
| HONOR W2-γ MULTI-SESSION-RECOMMENDED verdict | Scout A's estimate was 2-3× too low; cramming everything would leave half-shipped state worse than 0% or 100% (Rule #28's worst-case clause) | Session 1 = scaffold (this); Session 2 = walker + activation + Rule-of-Three promotion |
| Sibling subpackage at `ics_protocol_catalog/` (not extending file_format_catalog) | File-format = single-format-per-blob; ICS = multi-protocol-per-binary; different cardinality + different signal grammar + cross-catalog hijack attack surface | Clean isolation; resolver returns `list[IcsProtocolMatch]`; no cross-catalog signal kind sharing |
| v0 = 3 protocols narrowed to 1 in Session 1 (Modbus only) | W2-γ scope budget; ship FOUNDATION proof-of-concept; DNP3 + S7Comm queued for Session 2 as Rule #25 Shape-1 commits | 1 YAML / 11 e2e tests / clean end-to-end resolution |
| Defer plugins entirely to Session 2 | W2-β §SC5-NEW-ICS-7 hot-reload × freeze_plugin_registry attack requires plugins to be exploitable; ship the I16 mitigation alongside the first plugin in Session 2 | port_signature + library_symbol shipped as STUB evaluators (return False) so exhaustive canary stays green; functional in Session 2 |
| combine=all_required in v0 Modbus YAML | W2-β §SC5-NEW-ICS-2 combine-mode permissive composition mitigation by-construction | Banner-only / port-only / FC-only blobs explicitly rejected by 4 e2e tests |
| `_SOURCE_PRECEDENCE` mirror of file_format_catalog verbatim | Same 5-source authority hierarchy; same vendor-authority derivation (`derive_vendor_authority`); same path cross-check pattern | 5/5 closed-Literal coverage; 3 W2-β §SC5-NEW-ICS-1/4 mitigations applied |

## Followup Carry-Forwards (Session 2 plan)

1. **Walker (Rule #39 triplet)** — `ics_protocol_walker.py` with `_do_ics_protocol_walk` / `run_ics_protocol_walk_background` / `auto_ics_protocol_walk_firmware_safe`
2. **ORM + alembic + DB CHECK + state machine** — 5 columns on firmware (status + started_at + finished_at + error + result JSONB) + Rule #51 orphan reaper
3. **Rule #35c JSONB normaliser + stamp + SCHEMA_VERSION** for `ics_protocol_walk_result`
4. **Walker auto-trigger registry** — add to `walker_registry.py` per Rule #47 worked-example #1
5. **Finding-source Rule #25 Shape-1 cross-stack alignment** — DB CHECK + Pydantic Literal + frontend FindingSource union + FINDING_SOURCE_CONFIG mirror + Rule #48 5-part alignment test
6. **MCP tool category** — `app/ai/tools/ics_protocol.py` with `trigger_*` + `list_*` + `lookup_*_across_firmwares` (Rule #44 mandatory) + `describe_ics_protocol_anomalies`
7. **Bundled string-scanner plugin + W2-β §SC5-NEW-ICS-7 I16 hot-reload mitigation** — applicability cross-check at YAML-load every hot-reload, not at plugin-register
8. **DNP3 + S7Comm v0 YAMLs** — 2 additional Rule #25 Shape-1 commits
9. **CLAUDE.md Rule #52 Rule-of-Three promotion** — append worked-example #3 to Rule #52 table when full surface ships
10. **Promote `.mex/patterns/add-signal-kind.md` recipe** — Rule-of-Three threshold reached after Session 2 ships
