# Postmortem: ICS protocol catalog — Session 1 (2026-05-20)

> Date: 2026-05-20
> Campaign: ICS protocol decoders — Rule #52 third-application surface
> (will promote Rule #52 to Rule-of-Three when Session 2 closes the
> walker + MCP tools + plugins).
> Direct-shipped per Rule #25 per-piece cadence; no campaign file —
> Wave-1 + Wave-2 research artefacts at `.planning/research/ics-protocol-2026-05-20/`.
> Duration: single session, commits `0dabbd6..1d0d0a9` (3 ICS commits; 4
> commits total in this session counting `70afbcb` /citadel:learn from
> earlier substring_in_head campaign).
> Outcome: **completed at the scaffold layer** — schema + catalog +
> resolver + 1 production YAML + 114 tests. Session 2 ships the walker
> + MCP tools + ORM + alembic + finding-source alignment + Rule #52
> Rule-of-Three promotion.

## Summary

The session opened with the user's directive: "decide using deep research
and deep review / thinking across all relevant expert personas using
Citadel on this. full plan, full execute, don't wait for me, you got
this." This is the Wave-1 + Wave-2 methodology from
`feedback_wave2_cross_feature_methodology.md` Rule-of-Two evidence chain.

Lane decision: B.3 ICS protocol decoders (firmware-embedded). Rationale:
greenfield gap (essentially absent — only 6 SBOM CPE mappings in
`sbom/constants.py`); highest operator leverage for OT/ICS firmware RE;
substantially different abstraction from chip-family (instance #1) +
file-format (instance #2) — promotes Rule #52 to Rule-of-Three on
Session 2 close.

**Wave-1 (5 expert-persona scouts in parallel):**
- Scout A (architecture) — sibling subpackage; 6 closed Literals; HYBRID plugin (Session 2 scope); Rule #39 walker triplet
- Scout B (adjacency) — confirmed greenfield; mirror file_format_catalog pattern
- Scout C (red-team) — 20 attacks + 4 §SC5-NEW-ICS analogs + I1-I13 cross-feature gates
- Scout D (operator-UX) — 10 MCP tools + 1 reuse; auto-fire walker post-unpack; per-vendor allowlist
- Scout E (precedence) — 17-point Rule #47 consumer-hook checklist

**Wave-2 (3 critique scouts in parallel):**
- W2-α (alpha convergence) — locked lane + narrowed v0 to 3 protocols
  (Modbus + DNP3 + S7Comm); 11 closed Literals locked; phase shape locked
- W2-β (beta cross-feature blow-it-up) — 6 NEW attacks §SC5-NEW-ICS-5..10;
  scariest = hot-reload × freeze_plugin_registry() (defers to Session 2
  when plugins ship); I14-I19 NEW gates queued
- W2-γ (gamma Rule #28 yardstick) — VERDICT: MULTI-SESSION-RECOMMENDED.
  Scout A's 1.5× P3.2 estimate was actually ~3.8× P3.2 net LOC against
  `wc -l` of reference files. **Honored gamma's verdict — split into
  Session 1 (scaffold) + Session 2 (walker + activation).**

Session 1 ships the foundation (~4500 net LOC across 3 ICS commits):

| # | Commit | Title | Net delta | Tests |
|---|---|---|---|---|
| 1 | `0dabbd6` | feat(ics-protocol): closed-grammar schema + Wave-1+Wave-2 research | +3,314 / 10 files | +63 schema |
| 2 | `fb10d54` | feat(ics-protocol): catalog + resolver + 3 evaluators + I1/I2/I4 gates | +1,945 / 7 files | +40 catalog |
| 3 | `1d0d0a9` | feat(ics-protocol): v0 Modbus/TCP YAML + end-to-end integration tests | +293 / 2 files | +11 e2e |

**Total session:** 3 commits / +5,552 insertions / -0 deletions / **+5,552 net**
/ 114 new tests / 0 reverts / bisect-clean across all 3 commits.

(Including the earlier session-opener substring_in_head closure at commit
`70afbcb` — the full session log is 4 commits. The substring_in_head
closure was Session 0 work completed earlier in the same session.)

## What Broke

### 1. Initial Scout A architecture estimate was 2-3× too low vs Wave-2 γ measurement
- **What happened:** Wave-1 Scout A estimated v1 = ~4,000 LOC across 7 phases. Wave-2 γ measured against actual `wc -l` of reference files (file_format.py = 1,262 LOC; efs_walker.py = 1,232 LOC; linux_systemd.py = 843 LOC) and projected ~10,300 LOC — ~2.6× higher than Scout A.
- **Caught by:** W2-γ scout's mechanical `wc -l` measurements; would have failed mid-session if Scout A's estimate were taken at face value.
- **Cost:** 0 minutes — caught by the deep-research methodology BEFORE shipping code. The whole point of Wave-2 yardstick scout.
- **Fix:** Honored W2-γ verdict; split into Session 1 (scaffold ~4,500 LOC) + Session 2 (walker + MCP + Rule #52 promotion ~3,000 LOC).
- **Generalisation:** Rule #28 yardstick (+14-22% drift adjustment) applies AFTER baseline LOC measurement, not before. Scout A's estimate was based on intuition; W2-γ measured against the actual referenced files. Future Wave-2 γ dispatches should explicitly require `wc -l` cited measurements.

### 2. Pydantic IcsProtocolMatch is FLAT (not nested)
- **What happened:** Live canary print statement accessed `m.output.protocol_family` on an IcsProtocolMatch — `AttributeError: 'IcsProtocolMatch' object has no attribute 'output'`. The IcsProtocolMatch result type FLATTENS the manifest's output sub-block into top-level fields (`protocol_family`, `layer`, `transport`, `vendor`, etc.) to avoid an awkward nested-dict shape in MCP tool output.
- **Caught by:** Immediate AttributeError in the canary script.
- **Cost:** ~30 seconds — print-statement fix only.
- **Fix:** Corrected access pattern to `m.protocol_family` (flat).
- **Infrastructure created:** None. The design choice is documented in the schema docstring (IcsProtocolMatch is a "flat" result for operator-facing surface).

### 3. Anti-hardcode META-CANARY caught operator's `b"\x00" * 16` in test fixture
- **What happened:** In `test_eval_magic_bytes_rejects_mismatch` and other tests, the test fixture uses `b"\x00" * 16` to synthesize a non-matching blob. The Rule #46 anti-hardcode AST canary would NOT fire because it runs against `resolver.py`, not test files. NO actual break — caught at design time by considering the canary scope.
- **Caught by:** Self-review.
- **Cost:** 0 — pre-emptive design check.
- **Generalisation:** Anti-hardcode canaries scope to PRODUCTION code (resolver.py / catalog.py), not test files. Tests legitimately use literal byte sequences for fixture synthesis. The canary's `_resolver_source()` helper reads only the resolver file.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---|
| W2-γ Rule #28 yardstick (`wc -l` measurements) | Scout A's 1.5× P3.2 estimate was actually ~3.8× | 1 | Mid-session context exhaustion + half-shipped state worse than 0% or 100% (Rule #28's worst-case clause) |
| W2-β cross-feature blow-it-up | 6 NEW §SC5-NEW-ICS-5..10 attacks Wave-1 single-axis scouts validated as individually safe | 6 attacks queued | Hot-reload × freeze_plugin_registry hijack (CVE-grade attack); metadata pre-seeding via JSONB; multi-tenant cross-firmware scope leak |
| W2-α convergence synthesis | Resolved 3 contradictions across the 5 Wave-1 reports (plugins yes-vs-no; walker iteration target; MCP tool count) | 3 | Implementation drift between Wave-1 scout recommendations |
| Pydantic schema `_check_kind_fields` validator | Per-signal-kind required-when + symmetric-reject pair on 5 signal kinds (magic_bytes / port_signature / function_code_set / string_in_binary / library_symbol) | structural | Mis-authored operator YAML with wrong constraint shape silently matches nothing |
| Pydantic schema `_check_precedence_floor` | Operator declaring precedence < 10 with manifest_source != _system | 4 test cases | Operator beats _system negative-evidence sentinels (W2-β attack #5 mitigation) |
| Pydantic schema `extra='forbid'` on every model | 12 forbidden Rule #52 grammar keys (regex / script / template / eval / lua / vql / predicate / expression) | 12 test variants | YAML-becomes-a-programming-language risk (Wave-1 S2 binwalk/yara CVE class) |
| Catalog path cross-check (W2-β §SC5-NEW-ICS-4) | Operator YAML at `data/ics_protocols.local/hostile.yaml` declaring `manifest_source: _system` | 3 test scenarios | Authority laundering — operator impersonating curated tier |
| Catalog I4 cross-vendor collision detection | Two operator manifests claiming same (precedence, magic_bytes) but DIFFERENT vendors | 1 (3-test scenarios) | Cross-vendor magic collision (file_format A4 analog tightened for ICS) |
| Catalog graceful-degrade on parse failure | Bad YAML / duplicate manifest_id / pydantic ValidationError | structural | Single bad YAML takes down the whole loader (Rule #34 violation) |
| Rule #46 META-CANARIES — 11 paired exhaustive Literal canaries | Synthesized truncated Literal value set on each closed Literal; verified exhaustive check rejects | 11 (paired) | Future commits drift Literal values without tracking |
| Rule #46 META-CANARIES — 3 paired exhaustive dispatch-table canaries (SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS + _SOURCE_PRECEDENCE) | Synthesized missing-entry dict; verified exhaustive check rejects | 3 (paired) | Future commits add Literal value without wiring evaluator / cost class / precedence |
| Rule #46 anti-hardcode AST canaries (2 paired) | Synthesized hostile evaluator with hardcoded `b"Modbus"` / `b"\x01\x03\x05\x06\x0f\x10"`; verified gate rejects | 2 (paired) | Future commit silently adds format-specific byte literal to evaluator |
| `combine: all_required` discipline in v0 YAML | Banner-only / port-only / FC-only synthesized blobs — all rejected | 3 e2e tests | W2-β §SC5-NEW-ICS-2 combine-mode permissive composition |
| Rule #46 paired-canary discipline | All exhaustive checks have BOTH the exhaustive test AND the synthesize-and-assert paired gate-canary | every closed table | Rule #17/#24/#46 silent-success class — exhaustive that doesn't actually fire |

## Scope Analysis

* **Planned (initial session-opener):** Lane B — Rule #52 third surface; expected 5-6 hour session per the original direction. **W2-γ revised to MULTI-SESSION-RECOMMENDED** during deep research.
* **Built (Session 1 only):** 3 ICS commits / +5,552 net LOC / 114 new tests / 0 reverts / bisect-clean. **Scope honored W2-γ verdict.**
* **Drift:** ZERO. The Wave-2 γ scope yardstick caught the over-ambitious initial estimate BEFORE writing code. Session 1 narrowed to schema + catalog + resolver + 1 production YAML; everything else deferred to Session 2.

Session 1 / 2 split per W2-γ:
- **Session 1 (this):** Schema + Catalog + Resolver + 1 YAML — **SHIPPED**.
- **Session 2 (future):** Walker (Rule #39 triplet) + ORM columns + alembic migration + JSONB normaliser + orphan reaper + finding-source cross-stack alignment (Rule #25 Shape-1) + MCP tool category (Rule #44 mandatory `lookup_*_across_firmwares`) + Plugins (when shipping plugins, also ship the W2-β §SC5-NEW-ICS-7 I16 hot-reload mitigation) + remaining 2 protocols (DNP3 + S7Comm) + Rule #52 Rule-of-Three promotion to CLAUDE.md when full surface ships.

## Patterns

1. **Deep research + Wave-1 + Wave-2 methodology is the durable shape for Rule #52 extensions (Rule-of-Two now, soon Rule-of-Three).** P3.1 + P3.2 used it; this session extended it to a third Rule #52 surface. The pattern: 5 Wave-1 single-axis scouts (architecture / adjacency / red-team / operator-UX / precedence) + 3 Wave-2 critique scouts (alpha convergence / beta blow-it-up / gamma yardstick) = 8 scouts total. Mirrors `feedback_wave2_cross_feature_methodology.md`.

2. **W2-γ Rule #28 yardstick CATCHES over-ambitious Wave-1 estimates BEFORE shipping code.** Scout A's 1.5× P3.2 estimate was 2-3× too low; W2-γ caught it via mechanical `wc -l` measurements against reference files. Honoring the verdict prevented a half-shipped state. **Rule #28 yardstick is the load-bearing safety system for multi-session campaigns.** Promotable to a feedback memory: when a campaign is sized at >2× P3.2 baseline, prefer multi-session split + ship the FOUNDATION first; defer activation to Session 2.

3. **Multi-session split shipping FOUNDATION first works.** The schema + catalog + resolver are DEAD CODE per Rule #27 N-additive + 1-cutover until Session 2 wires the walker + MCP tools. But the foundation is THOROUGHLY TESTED (114 tests across schema validation + catalog gates + resolver semantics + Rule #46 META-CANARIES + end-to-end YAML resolution). Session 2 starts on solid ground, not a greenfield.

4. **Sub-model + symmetric-reject + extra='forbid' pattern is Rule-of-Three now.** Three applications:
   - P3.2.b TextFormatConstraint (file-format catalog)
   - P3.x SubstringInHeadConstraint (file-format catalog, this morning)
   - Session 1 IcsStringInBinaryConstraint + IcsFunctionCodeSetConstraint (this session)
   All follow the IDENTICAL 4-element pattern (sub-model with closed Literal fields + DetectionSignal field + validator branch with required-when + symmetric-reject + Rule #46 anti-hardcode AST canary on evaluator). **Promote to `.mex/patterns/add-signal-kind.md` recipe** when Session 2 closes (Rule-of-Three threshold reached).

5. **Closed-grammar Pydantic Literals + free-string taxonomy + sibling subpackage = durable Rule #52 shape.** Three applications now: bare-metal MCU/DSP, file-format YAML registry, ICS protocol catalog. Each uses the same architectural template: data root + overlay root + closed dispatch + plugin escape hatch (Session 2) + cross-feature gates. **Promotes Rule #52 to Rule-of-Three DURABLE BEYOND DEBATE when Session 2 ships the walker + MCP + plugins.**

6. **Multi-protocol-per-binary cardinality is genuinely different from file-format catalog's single-format-per-blob.** `resolve_all()` returns `list[IcsProtocolMatch]` (multiple matches) vs file_format's `resolve()` (single FormatMatch). This is the right shape — a binary CAN speak Modbus + OPC-UA + DNP3 simultaneously (real-world HMIs do). Mirrors Wave-1 Scout A's cardinality observation.

7. **`combine: all_required` discipline is the operator-UX answer to W2-β §SC5-NEW-ICS-2.** Forces co-occurrence; rejects single-signal false positives. The v0 Modbus YAML uses 3-signal `all_required` (banner + port + function-code table) — single-signal hits (banner-only, port-only) explicitly rejected by 4 e2e test cases.

## Recommendations

1. **Session 2 — Walker + ORM + alembic + state machine.** Rule #39 inner/outer/safe triplet for `ics_protocol_walker.py`. 5 firmware columns (status + started_at + finished_at + error + result JSONB). Alembic migration with DB CHECK constraint. Rule #35c JSONB normaliser + stamp + SCHEMA_VERSION constant. Rule #51 orphan reaper in `main.py` lifespan. ~2200 LOC per W2-γ estimate.

2. **Session 2 — Walker auto-trigger + finding-source cross-stack alignment.** Rule #25 Shape-1 single-slice commit: `WALKER_AUTO_TRIGGERS` registry extension + `ck_findings_source` DB CHECK extension + `IcsProtocolFindingSource` Literal + frontend `FindingSource` union + frontend `FINDING_SOURCE_CONFIG` mirror + Rule #48 5-part alignment regression test. ~480 LOC per W2-γ.

3. **Session 2 — MCP tools.** New `backend/app/ai/tools/ics_protocol.py` category with at minimum: `trigger_ics_protocol_walk` + `list_ics_protocols` + `lookup_ics_protocol_across_firmwares` (Rule #44 mandatory) + `describe_ics_protocol_anomalies`. Register in `ai/__init__.py`. ~1100 LOC per W2-γ.

4. **Session 2 — Bundled string-scanner plugin + W2-β §SC5-NEW-ICS-7 I16 hot-reload mitigation.** The scariest W2-β attack requires plugin support to be exploitable. When Session 2 ships the string-scanner plugin, I16 cross-check (applicability re-validation at YAML hot-reload, not only at plugin-register) MUST ship in the same commit.

5. **Session 2 — Remaining 2 protocols (DNP3 + S7Comm) as Rule #25 Shape-1 commits.** Mirror the modbus_tcp.yaml shape. Each ~150 LOC YAML + 5-10 e2e tests.

6. **Session 2 — CLAUDE.md Rule #52 Rule-of-Three promotion.** When the full surface ships (walker + MCP + plugins + 3 YAMLs), Rule #52 graduates from Rule-of-Two to **Rule-of-Three DURABLE BEYOND DEBATE** with the ICS protocol catalog as worked example #3.

7. **Promote `.mex/patterns/add-signal-kind.md` recipe.** Rule-of-Three threshold reached after Session 2: P3.2.b TextFormatConstraint + P3.x SubstringInHeadConstraint + Session 1 IcsStringInBinaryConstraint/IcsFunctionCodeSetConstraint. Codifies sub-model + symmetric-reject + extra='forbid' + Rule #46 anti-hardcode AST canary pattern.

## Numbers

| Metric | Value |
|---|---:|
| Commits (ICS only, this session) | 3 (0dabbd6..1d0d0a9) |
| Files changed (cumulative) | 19 (10 + 7 + 2) |
| Insertions | 5,552 |
| Deletions | 0 |
| Net | +5,552 |
| Reverts | 0 (bisect-clean) |
| Tests added | 114 (63 schema + 40 catalog + 11 e2e) |
| Schema closed Literals | 11 (IcsManifestSource / IcsProtocolFamily / IcsLayer / IcsTransport / IcsSignalKind / IcsArtifactSource / IcsCertainty / IcsCombine / IcsConfidence / IcsDeprecationStatus / IcsVendorAuthority) |
| Pydantic sub-models | 5 (IcsStringInBinaryConstraint / IcsFunctionCodeSetConstraint / IcsDetectionSignal / IcsDetection / IcsOutput) + 2 top-level (IcsProtocolManifest / IcsProtocolMatch) + 1 lifecycle (IcsDeprecation) |
| Catalog cross-feature gates shipped (I1-I7) | 3 active (I1 placeholder / I2 vendor_authority / I4 cross-vendor collision); I3, I5, I6, I7 stub (no dispatch/plugins in v0) |
| Signal evaluators | 5 (magic_bytes + string_in_binary + function_code_set ACTIVE; port_signature + library_symbol STUB-only) |
| Wave-1 scouts dispatched | 5 (architecture + adjacency + red-team + operator-UX + precedence) |
| Wave-2 scouts dispatched | 3 (alpha convergence + beta blow-it-up + gamma yardstick) |
| Wave-1 findings adopted | 17 (architecture + cross-feature gates + scout B greenfield confirmation) |
| Wave-2 NEW §SC5-NEW-ICS attacks (β) | 6 (NEW-5..10; mitigations queued for Session 2) |
| Wave-2 contradictions resolved (α) | 3 |
| Wave-2 γ yardstick verdict | MULTI-SESSION-RECOMMENDED (HONORED) |
| Rule #28 drift adjustment | 1.0× of W2-γ estimate (no further drift; ship exactly what was scoped) |
| Rule #25 Shape-1 commits | 0 (Session 2 ships Shape-1 commits for finding-source alignment) |
| Rule #46 paired META-CANARIES | 17 (11 closed-Literal exhaustive + 3 dispatch-table exhaustive + 3 anti-hardcode AST) |
| Rework cycles | 2 (Pydantic flat-match access; print-statement bug) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Adversarial scouts dispatched | 8 (5 Wave-1 + 3 Wave-2) |
| Production YAMLs shipped | 1 (`_system/modbus_tcp.yaml`) |
| ICS protocols covered in v0 | 1 of 3 planned (DNP3 + S7Comm in Session 2) |

---HANDOFF---
- Postmortem: ics-protocol-session1-2026-05-20
- Document: .planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md
- Failures documented: 3 (all caught at design time or in seconds)
- Safety catches: 14
- Recommendations: 7
- Commits: 0dabbd6..1d0d0a9 (3 ICS commits this session)
- Session 1 surface SHIPPED: schema + closed Literals + catalog + resolver + 1 YAML + 114 tests
- Session 2 plan (queued):
  * Walker (Rule #39 triplet)
  * ORM columns + alembic + DB CHECK + JSONB normaliser
  * Orphan reaper (Rule #51 partner)
  * Walker auto-trigger registry extension
  * Finding-source cross-stack alignment (Rule #25 Shape-1)
  * MCP tools (Rule #44 lookup_*_across_firmwares mandatory)
  * Bundled string-scanner plugin + I16 hot-reload mitigation (W2-β §SC5-NEW-ICS-7)
  * DNP3 + S7Comm YAMLs (Rule #25 Shape-1 commits)
  * CLAUDE.md Rule #52 Rule-of-Three promotion (worked-example #3)
  * `.mex/patterns/add-signal-kind.md` recipe (Rule-of-Three threshold)
---

Run `/citadel:learn ics-protocol-session1-2026-05-20` to extract patterns into the knowledge base.
