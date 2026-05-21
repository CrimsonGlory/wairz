# Postmortem: ICS protocol catalog — Session 2 (2026-05-22)

> Date: 2026-05-22
> Campaign: ICS protocol decoders — Rule #52 third-application surface
> closure. Session 2 ships the walker + ORM + alembic + JSONB normaliser
> + MCP tools + bundled plugin + plugin freeze + 2 more protocol YAMLs +
> Rule #52 **Rule-of-Three DURABLE BEYOND DEBATE** promotion.
> Direct-shipped per Rule #25 per-piece cadence; no campaign file —
> Wave-1 + Wave-2 research artefacts at
> `.planning/research/ics-protocol-session2-2026-05-22/`.
> Duration: single session, 10 commits `0de1eba..cabb298` (Phase 1.A
> through Phase 5.B; Phase 6 docs lands as the final commit after this
> postmortem).
> Outcome: **completed at the full-surface layer — Rule-of-Three
> promotion ships in Phase 6**.

## Summary

The session opened with the operator's directive: "resume ICS protocol
Session 2 — that work will promote CLAUDE.md Rule #52 from Rule-of-Two
to Rule-of-Three DURABLE BEYOND DEBATE when the walker + MCP tools +
bundled plugins close." Pre-staged kickoff brief at
`.planning/research/ics-protocol-session2-2026-05-22/SESSION-2-KICKOFF.md`
specified Wave-1 + Wave-2 dispatch + Phase 1-6 commit chain.

**Wave-1 (5 expert-persona scouts in parallel — `.planning/research/
ics-protocol-session2-2026-05-22/wave1-*`):**
- Scout A (architecture) — Session 1 shipped 1,906 LOC of
  dead-code-until-S2 scaffolding; S2 wires the Rule #39 triplet +
  STATE_MACHINE_REAPER_CONFIGS 8→9; projected ~4,710-5,490 LOC.
- Scout B (adjacency) — 60-70% template-copy from bare_metal_walker +
  file_format_catalog + Session 2a feab18c9d201 alembic mirror;
  projected ~3,500-4,000 LOC adjusted; 5 genuinely-fresh surfaces.
- Scout C (red-team) — 10 NEW §SC5-NEW-ICS-S2-* attacks at Phase 1-6
  surfaces; 3 CRITICAL (walker JSONB pre-seed × CVE matcher; plugin
  freeze × `__getattr__` shadow; cross-firmware × failed-row leak).
- Scout D (operator-UX) — recommended `/projects/{id}/ics-protocols`
  sub-route (no FirmwareDetailPage exists in wairz); ~950 LOC
  frontend; TIER_A_LIGHT_ACK 30/hour.
- Scout E (state machine) — DUAL REGISTRATION required
  (STATE_MACHINE_REAPER_CONFIGS 8→9 AND WALKER_REAPER_CONFIGS 25→26)
  because the suffix-introspection cross-check at
  `test_walker_reaper_configs_size_lock_matches_firmware_model:67-99`
  forces every `*_walk_status` column into WALKER.

**Wave-2 (3 critique scouts in parallel — `wave2-*`):**
- W2-α convergence — 11-commit chain locked; DUAL reaper resolved;
  Scout B's template-copy projection wins; Scout D's sub-route
  supersedes kickoff's "tab" terminology; plugin freeze in lifespan
  AFTER catalog warmup BEFORE yield.
- W2-β cross-feature blow-up — **10 NEW §SC5-NEW-ICS-S2-α..κ attacks**
  beyond Wave-1 C's catalog. Scariest: **§SC5-NEW-ICS-S2-α** — bare
  `freeze_plugin_registry()` IS NOT iron-clad against module-level
  attribute-shadow attack. Mitigation: MappingProxyType wrap +
  closure-capture check.
- W2-γ Rule #28 yardstick — **VERDICT: SINGLE-SESSION (80% confidence)**
  — projected 5,569 LOC midpoint matches Session 1's shipped 5,552 LOC
  within 0.3%. 11 commits projected; 3 Rule #8 rebuilds.

**Session 2 shipped (~3,958 net LOC across 10 commits + Phase 6 docs):**

| # | Commit | Title | Net delta | Tests |
|---|---|---|---|---|
| 1 | `0de1eba` | feat: walker state machine columns + alembic (Phase 1.A) | +165 / 2 files | DB CHECK |
| 2 | `7c6405f` | feat: Rule #35c normaliser + provenance gate (Phase 1.B) | +224 / 2 files | +6 jsonb |
| 3 | `bad86ee` | feat: Rule #39 triplet + Pydantic Literal + Rule #45/46 (Phase 1.C) | +921 / 3 files | +9 walker |
| 4 | `2dc77a1` | feat: walker_registry + DUAL reaper + size-lock (Phase 1.D) | +48 net / 3 files | +0 (size-lock edits) |
| 5 | `cf6db33` | feat: finding-source cross-stack alignment (Phase 2) | +322 / 6 files | +2 walker alignment |
| 6 | `56bf14e` | feat: 4 MCP tools incl. Rule #44 cross-firmware (Phase 3) | +1124 / 3 files | +12 mcp |
| 7 | `960500f` | feat: plugin freeze HARDENED + bundled string_scanner (Phase 4) | +664 / 6 files | +13 plugin |
| 8 | `8a6f5b5` | feat: DNP3 production YAML (Phase 5.A) | +214 / 2 files | +5 dnp3 e2e |
| 9 | `cabb298` | feat: S7Comm + cross-protocol matrix (Phase 5.B) | +276 / 2 files | +7 s7comm/matrix |
| 10 | (next) | docs: Rule #52 Rule-of-Three promotion + recipe (Phase 6) | +~750 / 4 files | +0 (docs) |

**Total Session 2:** 9 commits / +3,958 net LOC / +80 new tests /
**0 reverts** / bisect-clean across all 9 commits / DB CHECK constraints
applied + verified via psql.

## What Broke

### 1. Alembic revision ID collision (`e7f8a9b0c1d2`)
- **What happened:** First-attempt alembic file used revision ID
  `e7f8a9b0c1d2` which collided with the existing
  `e7f8a9b0c1d2_extend_findings_source_powershell.py`. `alembic
  upgrade head` failed with "Multiple head revisions are present".
- **Caught by:** Immediate alembic error before any tests ran.
- **Cost:** ~2 minutes — rename + re-`docker cp` + retry.
- **Fix:** Renamed to `1c52a4b5c6d7` (mnemonic "1c5 = ICS Session 2").
- **Generalisation:** Before picking an alembic revision ID, grep
  the versions directory for the candidate ID with
  `grep -h "^revision: " backend/alembic/versions/*.py | grep <id>`.
  Not codified as a rule (one-off; mechanical-canary on alembic
  load catches it cheaply).

### 2. statusConfig.ts parser confused by apostrophe in code comment
- **What happened:** Phase 2 added a multi-line `//` comment block
  containing the apostrophe in "Network's existing hues". The
  `_balanced_object_body` parser in `test_finding_source_alignment.py`
  doesn't handle JS comments; it saw the apostrophe as an unmatched
  string-open and emitted "unbalanced braces" error.
- **Caught by:** Alignment test on host.
- **Cost:** ~2 minutes — rephrase comment to avoid apostrophe.
- **Fix:** Removed the comment block entirely (the new entries are
  self-explanatory by name).
- **Generalisation:** When editing `frontend/src/constants/statusConfig.ts`
  near the `FINDING_SOURCE_CONFIG` map, avoid `//` line comments WITHIN
  the map body — the alignment test's parser treats them as part of
  the buf and corrupts key extraction. Alternative: keep comments
  outside the map literal, or rewrite the parser. Documented in this
  postmortem; no rule needed (cheap to avoid).

### 3. Phase 5 cross-protocol test ordered before s7comm.yaml landed
- **What happened:** Initially wrote all DNP3 + S7Comm + cross-protocol
  matrix tests in a single file `test_ics_protocol_dnp3_s7comm_e2e.py`.
  Per Rule #25 per-piece, split into 5.A (DNP3 only) + 5.B (S7Comm +
  cross-protocol matrix). The matrix tests require BOTH YAMLs present;
  splitting cleanly required moving them to 5.B's test file.
- **Caught by:** Self-review during commit splitting.
- **Cost:** ~3 minutes — restructured test files.
- **Generalisation:** When per-protocol Rule #25 commits include
  cross-protocol matrix tests, the matrix tests belong with the LAST
  YAML to land. Not codified as a rule (case-specific).

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---:|
| W2-β cross-feature blow-it-up | 10 NEW §SC5-NEW-ICS-S2-α..κ attacks beyond Wave-1 | 10 | Plugin freeze module-level shadow (CRITICAL); mid-walk snapshot tear; cross-firmware × failed-row leak; etc. |
| W2-α convergence DUAL reaper resolution | Scout A's STATE_MACHINE-only recommendation would have broken the `test_walker_reaper_configs_size_lock_matches_firmware_model` suffix-introspection check | 1 | Half-shipped state at Phase 1 commit 4 — Rule #28 worst-case clause prevented |
| W2-γ Rule #28 yardstick | Confirmed SINGLE-SESSION feasibility (80% confidence, 5,569 LOC midpoint matched within 0.3% of Session 1 actual) | 1 | Honored — single-session ship achieved |
| Rule #46 paired META-CANARIES (Phase 1.C walker source no-execute scan) | Confirms gate fires on synthetic subprocess.run + asyncio.create_subprocess_exec + .decrypt() patterns | 1 paired | Rule #17 silent-pass class on the walker no-execute gate |
| Rule #46 META-CANARY (Phase 1.B sister-provenance) | Stamp helper enforces `provenance: "walker"` even on hostile pre-seed `provenance: "descriptor"` | 1 paired | W2-β §SC5-NEW-ICS-S2-1 — descriptor route CVE attribution attack closed |
| Rule #46 META-CANARY (Phase 1.C snapshot drift detection) | Mocked drifting catalog at entry/exit; INNER stamps `consistency_warning` when entry ≠ exit | 1 paired | W2-β §SC5-NEW-ICS-S2-β — mid-walk hot-reload tear closed |
| Rule #46 META-CANARY (Phase 1.C stale JSONB clear) | INNER clears stale `ics_protocol_walk_result` at entry | 1 | W2-β §SC5-NEW-ICS-S2-δ — partial JSONB on retry closed |
| Rule #46 META-CANARY (Phase 4 MappingProxyType) | Direct write to PLUGIN_REGISTRY raises TypeError "mappingproxy" | 1 paired | W2-β §SC5-NEW-ICS-S2-α CRITICAL — module-level attribute shadow closed |
| Rule #46 META-CANARY (Phase 4 closure-capture) | Synthesized matcher with AsyncSession in `__closure__` → ValueError | 1 paired | W2-β §SC5-NEW-ICS-S2-ζ — request-scope leak closed |
| Rule #46 META-CANARY (Phase 4 main.py lifespan-wire) | Confirms register_default_plugins called BEFORE yield textually | 1 | Plugin freeze not bypassed by ordering bug |
| Rule #25 single-slice exception #2 (Phase 2 cross-stack alignment) | DB CHECK + Pydantic Literal + frontend Union + Config mirror all ship atomically | 1 commit | Bisect-non-clean gap between commits closed |
| Rule #44 cross-firmware MCP tool gates (Phase 3) | Status='completed' + schema_version=1 + curated-tier only `supply_chain_signal` | 3 tests | W2-β §SC5-NEW-ICS-S2-3/γ/ι — failed-row/legacy-row/noise-signal leaks closed |
| §SC5-NEW-ICS-S2-ε project-scope filter (Phase 3) | Operator-A in P1 can't trigger walker against firmware in P2 | 1 test | Tenancy audit-log integrity defect closed |
| Cross-protocol matrix tests (Phase 5.B) | Modbus-shaped blob does not cross-match dnp3/s7comm; multi-protocol blob matches all 3 | 4 e2e tests | Cross-protocol disjointness contract enforced |

## Scope Analysis

- **Planned (Session 2 kickoff):** Rule #52 instance #3 — walker + ORM
  + alembic + MCP + plugins + 2 protocols + Rule-of-Three promotion.
  W2-γ projected 5,569 LOC midpoint; SINGLE-SESSION verdict.
- **Built (Session 2):** 9 commits / +3,958 net LOC / 80 new tests /
  0 reverts / bisect-clean. Phase 6 docs adds ~750 LOC.
- **Drift:** -29% under W2-γ midpoint (3,958 actual vs 5,569 projected).
  Scout B's template-copy discipline (~60-70% mechanical s/foo/ics/)
  delivered exactly as projected.

## Patterns

1. **Wave-1 + Wave-2 methodology is now Rule-of-Four** (P3.1 + P3.2 +
   ICS S1 + ICS S2). W2-β surfaced 10 NEW cross-feature attacks Wave-1
   architecturally couldn't see; 3 of them CRITICAL (plugin module-
   level shadow; mid-walk snapshot tear; cross-firmware × failed-row).
   Per `feedback_wave2_cross_feature_methodology.md`, this is the
   durable methodology for Rule #52 closed-grammar extensions.

2. **MappingProxyType + closure-capture HARDENING is the durable plugin
   freeze shape.** Session 1 W2-β identified bare `freeze_plugin_registry()`
   as the scariest unmitigated attack; Session 2 W2-β confirmed the bare
   shape IS NOT IRON-CLAD against module-level attribute shadow. The
   hardened pair (MappingProxyType view + private mutable + closure-
   capture rejection) closes both attack vectors. **file_format_catalog
   has the bare shape — backfill to MappingProxyType is queued as a
   Rule #21 mirror sweep (Phase 6 deferred follow-up).**

3. **DUAL reaper registration is mandatory for any walker column with
   ALSO state-machine semantics.** Scout E's discovery (the
   suffix-introspection check at
   `test_walker_reaper_configs_size_lock_matches_firmware_model:67-99`
   forces every `*_walk_status` column into WALKER) means columns that
   ALSO carry Rule #33 .b result JSONB (matching bare_metal_audit's
   precedent) need DUAL entries. Cost: ~1 ms extra sweep at startup
   per row; benefit: introspection guarantee holds; alternative
   (exclusion-list) erodes the cross-axis guarantee.

4. **Rule #25 Shape-1 per-phase commit chain works at scale.** Phase
   1 split into 4 commits (alembic+ORM / normaliser / triplet / registry+
   reaper) per Scout B + Scout E recommendation — every commit is
   individually revertable, every commit's tests pass before the next
   commit starts. 0 reverts across 9 commits validates the discipline.

5. **Closed-grammar walker emit with allowlist gate is the durable
   shape for finding-source cross-stack alignment.** Phase 2 ships
   `_ALLOWED_ICS_FINDING_SOURCES = frozenset(get_args(IcsProtocolFindingSource))`
   as the SINGLE SOURCE OF TRUTH; walker checks `source in allowlist`
   before emit; downstream Pydantic Literal + DB CHECK + frontend
   mirror all derive from the same allowlist. New protocol YAMLs that
   declare unmapped families silently skip emit instead of raising
   422 at FindingService.create.

6. **Cross-protocol disjointness matrix tests are mandatory for
   multi-protocol catalogs.** Phase 5.B ships 4 matrix tests proving
   Modbus + DNP3 + S7Comm don't cross-match despite FC overlap on
   0x01-0x06. Without these, a single-signal false positive in any
   protocol's YAML could silently leak across protocols under
   `combine: all_required` if a future commit weakens the discipline.

## Recommendations

1. **Backfill MappingProxyType + closure-capture hardening to
   file_format_catalog (Rule #21 mirror sweep — Phase 6 deferred
   follow-up).** The file-format precedent uses the bare-dict shape;
   the same §SC5-NEW-ICS-S2-α attack surface exists there. Ship as
   one commit: rename `PLUGIN_REGISTRY` → `_PLUGIN_REGISTRY` + export
   `PLUGIN_REGISTRY = MappingProxyType(...)` + closure-capture gate +
   Rule #46 paired META-CANARIES.

2. **Optional Phase 7 — REST router + frontend page.** Per W2-γ's
   "HTTP endpoint optional" note, the REST endpoint exposing
   `trigger_ics_protocol_walk` + the frontend `/projects/{id}/ics-protocols`
   sub-route (Scout D recommendation) ship as a future session. MCP
   access is sufficient for the v0 ship.

3. **Optional Phase 8 — AST plugin-source pre-import scan.** W2-β
   listed this as a NICE-TO-HAVE secondary defense beyond
   MappingProxyType. Deferred because MappingProxyType + closure-
   capture + freeze sentinel collectively are sufficient; AST scan
   would add a third layer for plugin module source validation.

4. **Promote `feedback_wave2_cross_feature_methodology.md` to
   Rule-of-Four.** ICS Session 2 is the 4th application of the
   Wave-1 + Wave-2 methodology (P3.1 + P3.2 + ICS S1 + ICS S2). The
   pattern is now durable; update the memory's evidence section.

5. **Run /citadel:learn ics-protocol-session2-2026-05-22.** Extract
   patterns into `.planning/knowledge/` per the postmortem close
   discipline.

## Numbers

| Metric | Value |
|---|---:|
| Commits (Phase 1-5, this session) | 9 (0de1eba..cabb298) |
| Files changed (cumulative) | ~30 unique |
| Insertions | ~3,958 |
| Deletions | ~23 (mostly size-lock updates 25→26, 8→9) |
| Net | +3,935 |
| Reverts | 0 (bisect-clean) |
| Tests added | ~80 (1.A:0 + 1.B:6 + 1.C:9 + 1.D:3 + 2:2 + 3:12 + 4:13 + 5.A:5 + 5.B:7 + plugin smoke 23) |
| Wave-1 scouts dispatched | 5 (architecture / adjacency / red-team / operator-UX / state machine) |
| Wave-2 scouts dispatched | 3 (alpha convergence / beta blow-it-up / gamma yardstick) |
| Wave-1 findings adopted | 17 (Scout A integration risks + Scout B template-copy + Scout C 9 attacks + Scout D UX + Scout E dual reaper) |
| Wave-2 NEW §SC5-NEW-ICS-S2 attacks | 10 (α..κ — 3 CRITICAL, 2 HIGH, 4 MEDIUM, 1 LOW) |
| Wave-2 contradictions resolved (α) | 4 (reaper placement / LOC projection / frontend surface / plugin freeze timing) |
| W2-γ yardstick verdict | SINGLE-SESSION-RECOMMENDED (80% confidence) — HONORED |
| Rule #28 drift adjustment | -29% under midpoint (3,958 actual vs 5,569 projected) |
| Rule #25 Shape-1 commits | 2 (Phase 2 alignment + Phase 4 plugin-with-freeze atomic) |
| Rule #46 paired META-CANARIES | ~80 (cumulative across all phases) |
| Rule #8 rebuilds | 2 (Phase 1 close + Phase 4 close) |
| Rework cycles | 3 (alembic ID collision; statusConfig apostrophe parser; cross-protocol test split) |
| Production YAMLs shipped | 3 cumulative — modbus_tcp (S1) + dnp3 (5.A) + s7comm (5.B) |
| ICS protocols covered v0 | 3 of 5 IcsProtocolFamily Literal values (modbus_tcp + dnp3 + s7comm; modbus_rtu + unknown_ics are forward-prepared) |
| MCP tools registered | 4 (trigger / list / lookup_across_firmwares Rule #44 / describe_anomalies) |
| MCP registry size | 335 (was 331; +4 ICS) |
| Walker auto-trigger registry size | 28 (was 27; +1 ICS) |
| STATE_MACHINE_REAPER_CONFIGS size | 9 (was 8) |
| WALKER_REAPER_CONFIGS size | 26 (was 25) |
| **Rule #52 promotion** | **Rule-of-Two → Rule-of-Three DURABLE BEYOND DEBATE** (lands in Phase 6 final commit) |

---HANDOFF---
- Postmortem: ics-protocol-session2-2026-05-22
- Document: .planning/postmortems/postmortem-ics-protocol-session2-2026-05-22.md
- Failures documented: 3 (all caught at design time or in minutes; 0 production impact)
- Safety catches: 14 systems, ~30 individual catches across Phase 1-5
- Recommendations: 5 (4 are future-session follow-ups; 1 ships in Phase 6 closing commit)
- Commits: 0de1eba..cabb298 (9 ICS Phase 1-5 commits + Phase 6 docs as 10th)
- Session 2 surface SHIPPED:
  * Phase 1: walker triplet + ORM + alembic + JSONB normaliser + DUAL reaper
  * Phase 2: finding-source Rule #25 Shape-1 cross-stack alignment
  * Phase 3: 4 MCP tools incl. Rule #44 cross-firmware
  * Phase 4: plugin infrastructure + bundled string_scanner + W2-β §SC5-NEW-ICS-S2-α HARDENED freeze
  * Phase 5: DNP3 + S7Comm production YAMLs + cross-protocol disjointness matrix
- Session 2 Phase 6 (in-progress at this writing — ships with postmortem):
  * CLAUDE.md Rule #52 worked-example block extension (ICS as instance #3)
  * Rule-of-Two → Rule-of-Three DURABLE BEYOND DEBATE promotion
  * .mex/context/conventions.md Verify Checklist mirror per Rule #21
  * .mex/patterns/add-signal-kind.md recipe (Rule-of-Three threshold)
  * This postmortem
  * /citadel:learn ics-protocol-session2-2026-05-22 extraction (next-step)
  * ADAPTIVE_BACKLOG section 5 sync (next-step)
---

Run `/citadel:learn ics-protocol-session2-2026-05-22` to extract patterns into the knowledge base.
