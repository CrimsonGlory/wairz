# Wave-2 Gamma — Rule #28 Scope Yardstick — ICS Protocol Decoder v0 (2026-05-20)

**Verdict (lead): MULTI-SESSION RECOMMENDED (2 sessions).** A single-session ship is feasible only with aggressive narrowing (3 protocols, defer plugins to v1, ship 2 of 5 MCP tools). Scope drift risk + Rule #25 per-piece-commit discipline collapse at 4-6h pushes the prudent split to **Session 1 = Phases A+B+D (scaffold) / Session 2 = Phases C+E+F+G (YAMLs + alignment + MCP + close)**.

---

## 1. `wc -l` measurements (canonical, Rule #31 width-canary applied)

### Reference files (already shipped — Wave-1 Scout A's templates)

| File | Actual LOC | Scout A estimate | Drift |
|---|---:|---:|---:|
| `backend/app/schemas/file_format.py` | **1262** | "~600 LOC" | **+110%** ⚠ |
| `backend/app/services/file_format_catalog/catalog.py` | **604** | (part of "~1200 LOC catalog package") | — |
| `backend/app/services/file_format_catalog/resolver.py` | **1008** | (part of "~1200 LOC catalog package") | catalog+resolver = **1612 LOC**; **+34%** over A's 1200 |
| `backend/app/services/file_format_catalog/plugins/rtos_detection_default.py` | **113** | "~600 LOC" for 3 plugins | thin shim — A's 600 estimate is realistic for 3 substantive plugins |
| `backend/app/services/efs_walker.py` (Rule #39 triplet) | **1232** | "~800 LOC" | **+54%** ⚠ |
| `backend/app/services/srum_walker.py` (Rule #39 triplet) | **790** | "~800 LOC" | **-1%** (matches) |
| `backend/app/ai/tools/linux_systemd.py` (Rule #44 precedent) | **843** | "~600 LOC" | **+41%** ⚠ |
| `backend/app/ai/tools/bare_metal.py` (operator-descriptor) | **326** | — | (smaller analog) |
| `backend/app/schemas/chip_family.py` (Rule #52 worked example #1) | **512** | — | (Pydantic-heavy reference) |
| `backend/app/services/bare_metal_walker.py` (Rule #52 #1 walker) | **686** | — | (Rule #39 triplet at ~700 LOC) |

### Supporting consumer-hook surfaces (Scout E enumeration)

| File | Actual LOC |
|---|---:|
| `backend/app/services/jsonb_normalizers.py` | **4381** (mega-file; this is a single function addition) |
| `backend/app/workers/walker_registry.py` | **190** (one-line addition + import) |
| `backend/app/models/firmware.py` | **991** (5-column addition) |
| `backend/app/schemas/firmware.py` | **359** (Literal addition) |
| `backend/app/schemas/finding.py` | **649** (Literal addition for Rule #25 Shape-1) |
| `backend/app/services/hardware_firmware/cve_matcher.py` | **1128** (1-field addition to `_KNOWN_FIRMWARE_NARROWING_FIELDS`) |
| `backend/app/main.py` (orphan reapers) | **409** (mirror of 4 existing reapers at lines 155/195/239) |
| `backend/app/services/firmware_service.py` (pipeline) | **937** (no change required per Scout E) |
| `backend/app/ai/__init__.py` (32nd register call) | **113** (2-line edit) |

### Existing _system YAMLs (representative samples)

| Manifest | LOC |
|---|---:|
| `windows_driver_package.yaml` | 39 |
| `linux_squashfs.yaml` | 35 |
| `motorola_srec.yaml` | 59 |
| `windows_psf.yaml` | 44 |
| `android_ota.yaml` | 56 |
| `acronis_backup.yaml` (vendor) | 45 |
| `kinibi_mclf.yaml` (vendor) | 30 |
| `linux_zimage.yaml` (vendor) | 31 |
| **Sample average** | **~42 LOC per manifest** |

49 total file-format manifests in catalog.

### Test reference files

| File | Actual LOC |
|---|---:|
| `test_finding_source_alignment.py` (Rule #48 5-part) | **402** |
| `test_efs_walker.py` (Rule #45+#46 paired-canary battery) | **887** |
| `test_srum_walker.py` (lighter walker test) | **232** |
| `test_file_format_schema.py` | **750** |
| `test_file_format_catalog.py` | **985** |
| `test_file_format_sort_tier.py` | **547** |
| `test_bare_metal_walker.py` | **340** |

### Reference alembic migrations

| Migration | LOC |
|---|---:|
| `fc5d6e7f8a9b_add_bare_metal_walker_state_machine.py` | **236** |
| `fd6e7f8a9b0c_extend_findings_source_bare_metal.py` | **155** |
| `fb3a4b5c6d7e_add_journald_walk_status.py` | **117** |
| `fb4c5d6e7f8a_extend_findings_source_linux_journald.py` | **205** |

---

## 2. Per-phase LOC + commit + test estimates (Rule #28 +20% drift applied)

I apply the **high end of Rule #28's +14-22% drift band (+20%)** because the deep-research scout estimates compress into "~600 LOC" round numbers that frequently undercount the closed-grammar Pydantic shape (file_format.py = 1262 LOC vs Scout A's 600 estimate = +110% drift — empirical signal that Scout A under-counted by half).

### Phase A — Schema + closed Literals + catalog scaffold

- **Schema** (`backend/app/schemas/ics_protocol.py`): 6 new closed Literals + 7 Pydantic models with `extra="forbid"` + 5-tier `_check_cross_field_invariants` model_validator + IcsCertainty floor. **Reference file_format.py = 1262 LOC; the ICS schema needs ~70-75% of that surface** (no Refinement, no TextFormatConstraint, no DispatchKind — but +IcsCertainty + IcsTransportPort closed allowlist + per-signal-kind validators) → **~900 LOC** (Scout A's 600 +50%).
- **Catalog scaffold** (`backend/app/services/ics_protocol_catalog/__init__.py` + `catalog.py`): mtime-cached YAML loader. Reference catalog.py = 604 LOC; ICS analog needs all 5 ManifestSource ranks + cross-feature validators I1-I13 BUT 8 of those mirror file_format's A1-A9 with substitution. **~700 LOC**.
- **Tests**: schema unit tests (test_ics_protocol_schema.py, mirror test_file_format_schema.py at 750 LOC) → **~600 LOC** with closed-grammar acceptance battery + Rule #46 paired canaries.

**Phase A estimate: ~2200 net LOC / 1 commit / ~35 new tests / RISK = MEDIUM (closed-Literal exhaustiveness drift is the main hazard).**

### Phase B — Resolver + 3 bundled plugins + cross-feature gates I1-I13

This is the **HEAVIEST phase by far** (Scout C flagged 13 cross-feature gates; Scout A flagged 3 plugins; Scout E flagged I10-I13 as ICS-specific NEW additions). Resolver.py reference = **1008 LOC**.

- **Resolver** (`backend/app/services/ics_protocol_catalog/resolver.py`): cost-sorted resolver + 8 closed `SIGNAL_EVALUATORS` (magic_bytes / port_signature / function_code_set / string_in_binary / oid_or_object_type / library_symbol / config_file_path / always_matches) + `IcsDetectionContext` plugin-cache + `freeze_plugin_registry()`. **~900 LOC** (resolver is the load-bearing piece — port-signature evaluator + function-code-set bitmap evaluator are new).
- **Plugin protocol + 3 bundled plugins** (`plugins/ics_string_scanner_default.py`, `ics_elf_symtab_default.py`, `ics_pe_imports_default.py`). Scout A estimates ~200 LOC each = 600 LOC total; realistic for a meaningful PE-imports scanner (lief/pefile-based) is **~700 LOC** with shared base class.
- **Cross-feature gates I1-I13** (13 catalog-load validators). Reference: file_format A1-A9 cumulative ~400 LOC in catalog.py. Adding 13 gates with stricter REJECT semantics for ICS (Scout C tightening) → **~500 LOC** in catalog.py body.
- **Tests**: resolver per-evaluator + 13 cross-feature gate canaries + paired META-CANARIES per Rule #46 (M1-M8 mirror + 5 new) → **~900 LOC** spread across test_ics_protocol_resolver.py + test_ics_protocol_catalog.py.

**Phase B estimate: ~3000 net LOC / 1 commit / ~50 new tests / RISK = HIGH ⚠.** This phase alone exceeds the P3.2.b commit (+866) by 3.5×. **Strong candidate for splitting into B.1 (resolver + plugin protocol) and B.2 (3 bundled plugins + 13 gates).**

### Phase C — v0 YAMLs + corpus fixtures

3-protocol v0 (per Wave-2 narrowing): Modbus/TCP + DNP3 + S7Comm. Each ~50 LOC YAML (richer than file-format avg 42 LOC because ICS YAMLs carry function-code tables + port arrays + library SONAME lists).

- 3 YAMLs × ~60 LOC each = **180 LOC** YAML data.
- Corpus fixtures (3 small ELF blobs containing known protocol-name strings + function-code tables for the resolver to detect) = **~100 LOC** Python fixture builders.
- Tests verifying each YAML's manifest loads + detects against its fixture = **~250 LOC**.

**Phase C estimate: ~530 LOC / 1 commit / ~15 new tests / RISK = LOW (parallel to P3.2.b shipping Intel HEX + SREC YAMLs at +866 net LOC including evaluator).**

### Phase D — Walker + ORM + alembic + state machine + JSONB normaliser + orphan reaper

This phase wires Scout E's 17 consumer hooks (sans the cross-stack alignment portion which lives in Phase E).

- **Walker triplet** (`backend/app/services/ics_protocol_walker.py`): Rule #39 inner/outer/safe. Reference efs_walker.py = 1232 LOC; srum_walker.py = 790 LOC; bare_metal_walker.py = 686 LOC. **ICS walker mid-range at ~900 LOC** (filtered walk set per Scout A = ELF/PE binary subset; not every blob; plugin-cache invalidation + per-binary detection orchestration).
- **Alembic migration** (state-machine columns): mirror `fc5d6e7f8a9b` at 236 LOC → **~250 LOC**.
- **JSONB normaliser** in `jsonb_normalizers.py`: ~120 LOC addition (Scout E sketched the canonical shape).
- **firmware ORM extension**: 5-column mapped_column addition → **~30 LOC**.
- **schemas/firmware.py** `IcsProtocolWalkStatus` Literal: **5 LOC**.
- **main.py orphan reaper**: ~50 LOC mirror of existing reapers at lines 155/195/239.
- **Tests**: test_ics_protocol_walker.py (mirror test_efs_walker.py at 887 LOC) → **~700 LOC** with Rule #45 no-decrypt + Rule #46 META-CANARY + paired canary + Rule #35b live canary.
- **Tests**: test_jsonb_normalizers.py extension (~80 LOC for the 3-canary battery).

**Phase D estimate: ~2200 net LOC / 1 commit / ~40 new tests / RISK = MEDIUM-HIGH (orphan reaper miss is the Rule #51 catch; live canary is non-trivial — needs real ELF blob through async_session_factory).**

### Phase E — Walker auto-trigger + finding-source cross-stack alignment (Rule #25 Shape-1)

This is the single-slice exception #2 commit (Rule #25 + Rule #48 5-part alignment test).

- `walker_registry.py` 1-line addition + import = **~10 LOC**.
- alembic finding-source extension: mirror `fd6e7f8a9b0c` at 155 LOC → **~170 LOC**.
- `schemas/finding.py` `IcsProtocolFindingSource = Literal[...]` (Scout A enumerated 7 sources; closer to 12 with all certainty tiers and supply-chain shapes) = **~30 LOC**.
- `frontend/src/types/index.ts` FindingSource union extension: **~15 LOC**.
- `frontend/src/constants/statusConfig.ts` FINDING_SOURCE_CONFIG mirror: **~50 LOC**.
- `tests/test_finding_source_alignment.py` Rule #48 5-part canary (mirror at 402 LOC) → **~200 LOC** extension.

**Phase E estimate: ~480 LOC / 1 commit (Rule #25 Shape-1 atomic) / ~15 new tests / RISK = LOW-MEDIUM (well-trodden by Rule #25 Rule-of-Nine).**

### Phase F — MCP tools (Rule #44 cross-firmware mandatory)

- `ai/tools/ics_protocol.py` NEW category with Tier-1 mandatory (5 tools) + selected Tier-2 (4 tools) per Scout D. Reference linux_systemd.py = 843 LOC. **ICS analog: ~700 LOC** (smaller because most filter dimensions reuse the protocol_family Literal + the cross-firmware SQL shape is the same template).
- `ai/__init__.py` 2-line edit.
- Tests for each tool handler + cross-firmware SQL canary: **~400 LOC**.

**Phase F estimate: ~1100 LOC / 1 commit / ~25 new tests / RISK = MEDIUM (Rule #44 contract; cross-firmware SQL JOIN pattern is shared).**

### Phase G — Postmortem + /citadel:learn + Rule #52 promotion to Rule-of-Three

- Postmortem markdown (mirror P3.2 at ~260 lines): **~280 LOC** documentation.
- `/citadel:learn` extraction into `.planning/knowledge/`: **~200 LOC** patterns + antipatterns docs.
- `CLAUDE.md` Rule #52 extension (worked-example #3 paragraph + Rule-of-Three lock): **~120 LOC**.
- `.mex/context/conventions.md` Verify Checklist mirror: **~10 LOC**.
- `.mex/patterns/add-ics-protocol-decoder.md` recipe: **~250 LOC**.

**Phase G estimate: ~860 LOC / 1 commit / 0 new tests / RISK = LOW (documentation; no code changes).**

---

## 3. Total scope estimate + ratio against P3.2 baseline

| Phase | Net LOC | Commits | Tests | Risk |
|---|---:|---:|---:|---|
| A — Schema + scaffold | ~2200 | 1 | ~35 | MEDIUM |
| B — Resolver + plugins + gates | ~3000 | 1 (split candidate → 2) | ~50 | **HIGH ⚠** |
| C — v0 YAMLs + fixtures | ~530 | 1 | ~15 | LOW |
| D — Walker + ORM + alembic + reaper | ~2200 | 1 | ~40 | MEDIUM-HIGH |
| E — Auto-trigger + Rule #25 Shape-1 | ~480 | 1 | ~15 | LOW-MEDIUM |
| F — MCP tools | ~1100 | 1 | ~25 | MEDIUM |
| G — Postmortem + Rule #52 promotion | ~860 | 1 | 0 | LOW |
| **TOTAL** | **~10370 LOC** | **7 (8 if B splits)** | **~180 tests** | — |

### Comparison against P3.2 baseline

| Metric | P3.2 actual | ICS v0 estimate | Ratio |
|---|---:|---:|---:|
| Commits | 6 | 7-8 | **1.17-1.33×** |
| Net LOC | +2,689 | ~+10,300 | **3.83×** ⚠ |
| Insertions | +2,876 | ~+10,500 | **3.65×** ⚠ |
| New tests | 87 | ~180 | **2.07×** |
| Cross-feature gates | 4 NEW (A6/A7/A8/A9) | 13 (I1-I13 with 4 NEW: I10-I13) | **3.25×** |
| Wave-2 scouts | 8 (5+3) | 8 (5+3) — same | 1× |

**Scout A's 1.5× P3.2 estimate is too low.** Actual measured = **~3.8× P3.2 net LOC** (driven primarily by file_format.py being 2× Scout A's expectation AND walker triplet being ~900 LOC mid-range). Even applying Rule #28's +20% drift backwards to compress, the floor is **~3.0× P3.2** — well over single-session capacity.

---

## 4. Single-session feasibility analysis

**P3.2 took 6 commits / +2689 / 87 tests / ~5 hours** in a single session under exactly this methodology (deep research + Wave-1+Wave-2 + Rule #25 per-piece + Rule #46 paired canaries).

**ICS v0 at 3.8× P3.2 LOC volume** = ~19 hours of equivalent throughput at the same per-LOC pace. Even with optimistic per-LOC speedup from the durable Rule #52 pattern (P3.2 was Rule-of-Two confirmation; ICS would be Rule-of-Three with all the infrastructure already in place — Rule #39 triplet shape, Rule #25 Shape-1 alignment, Rule #46 paired-canary recipe), the realistic compression is **~50% per-LOC pace** = **~9-10 hours**.

**Conclusion: NOT single-session feasible at the 4-6h target window with full v0 scope.**

### Narrowing options (single-session paths)

If single-session is required, three narrowing options preserve the Rule #52 Rule-of-Three promotion:

1. **Defer Phase B plugins to v1** — ship Phase A + Phase B-resolver-only (no bundled plugins; `_check_plugin_namespace_disjointness` gate ships dormant) + Phase C with 2 protocols (Modbus + DNP3) + Phase D + Phase E + Phase F with 4 MCP tools (cross-firmware + per-firmware list + trigger + walk_status) + Phase G. **Estimated drop: -1400 LOC, -25 tests** → still ~9000 LOC / 7 commits. Marginal.
2. **v0 = 3 protocols, narrow Phase B gates to I1-I9 mirror only (defer I10-I13 to v1)** — drops the ICS-specific NEW gates. Risk: Scout C's §SC5-NEW-ICS-1 (dispatch-chain authority) is one of the I-NEW gates; without it, the CVE-attribution drift threat is uncaptured at load-time. **NOT RECOMMENDED** — Scout C's evidence is strong that I10-I13 must ship in v0.
3. **v0 = 2 protocols (Modbus + DNP3 only) + 3 plugins + all I1-I13** — preserves the security floor; drops one protocol YAML + ~60 LOC. **Marginal savings (~3%); does not change feasibility verdict.**

None of the three options closes the >4× P3.2-LOC gap to single-session feasibility.

---

## 5. Multi-session recommendation (RECOMMENDED PATH)

**2-session split with explicit handoff via `/citadel:session-handoff`:**

### Session 1 (4-6h target window): **Scaffold + Walker**

- Phase A — Schema + closed Literals + catalog scaffold (1 commit, ~2200 LOC)
- Phase B — Resolver + 3 plugins + I1-I13 gates (1 commit, ~3000 LOC) **— or split B.1/B.2 if needed**
- Phase D — Walker + ORM + alembic + JSONB normaliser + orphan reaper (1 commit, ~2200 LOC)

**Session 1 total: ~7400 LOC / 3 commits (4 if B splits) / ~125 tests / ~5h.** This is **~2.75× P3.2** — still ambitious but achievable given the Phase B+D codepaths reuse Rule #52 worked-example #2 (file_format) shape directly. Walker at Phase D ships dormant — no auto-trigger wiring yet.

### Session 2 (3-4h target window): **YAMLs + Alignment + MCP + Close**

- Phase C — v0 YAMLs + corpus fixtures (1 commit, ~530 LOC)
- Phase E — Walker auto-trigger + Rule #25 Shape-1 cross-stack alignment (1 commit, ~480 LOC)
- Phase F — MCP tools (1 commit, ~1100 LOC)
- Phase G — Postmortem + /citadel:learn + Rule #52 Rule-of-Three promotion (1 commit, ~860 LOC)

**Session 2 total: ~2970 LOC / 4 commits / ~55 tests / ~3-4h.** This is **~1.1× P3.2** — well within single-session budget.

**Handoff state at session-1 close:** Walker exists, walker_registry.py NOT updated (Rule #47 explicit defer — session 2 ships the auto-trigger commit), catalog loads YAMLs but corpus is empty, MCP tools un-registered. All shipped commits remain bisect-clean per Rule #25. The 7400-LOC scaffold + walker is a meaningful artefact even if session 2 is delayed — the v1 catalog is dormant-but-correct.

---

## 6. High-variance risk callouts

### Phase B — HIGHEST risk (Rule #25 per-piece-commit attention)

- **3 closed-grammar plugins + 13 cross-feature gates + 8 signal evaluators** = the largest single commit in any wairz campaign to date (P3.2.c at +1017 was the prior record; B is projected at ~+3000).
- **Strong candidate for Rule #25 split into B.1 + B.2** where B.1 = resolver + evaluators + plugin protocol (the file_format-mirror pieces) and B.2 = 3 bundled plugins + I1-I13 gates (the ICS-NEW pieces). Each remains bisect-clean.
- **Scout C's §SC5-NEW-ICS attacks #1-#4 require the gates to be present and tested with paired META-CANARIES at commit time** — deferring any gate to a follow-up commit creates a security window where the catalog loads operator YAMLs without the attack mitigation.
- **Recommendation: split B if commit exceeds +2000 LOC at compose-time; Rule #25 single-slice exception #2 does NOT apply** (no cross-stack alignment in B — the 13 gates are all internal to the catalog package).

### Phase D — second-highest risk (Rule #51 orphan reaper miss)

- Rule #47 worked-example #1 (the `ics_protocol_walk_status` walker auto-trigger registration) MUST land in Phase E, NOT Phase D. The temptation to wire it in D is the orphan-walker failure mode.
- **Rule #51 orphan reaper** is the second known foot-gun — easy to forget mid-phase. Recommend the Phase D commit checklist explicitly enumerate "main.py orphan reaper added at line ~240 mirror" as a gate.

### Phase E — single-slice exception #2 commit (Rule #25 + Rule #48)

- 5 surfaces in one commit (DB CHECK + Pydantic Literal + frontend union + FINDING_SOURCE_CONFIG + alignment test) — Rule #25 Rule-of-Nine precedent supports this exactly; risk is LOW once Phases A-D are landed.

---

## 7. Rule #28 +20% drift adjustment (final)

Applied throughout. Specifically:

- Schema (file_format.py 1262 LOC vs Scout A "600" = ground-truth +110% drift); used +50% over A's 600 = 900 LOC for ICS schema.
- Walker (efs_walker 1232 LOC vs Scout A "800" = +54% drift); used 900 LOC mid-range between efs/srum/bare_metal.
- MCP tool (linux_systemd 843 LOC vs Scout A "600" = +41% drift); used 700 LOC.
- All test files inflated +25% over their direct mirrors to absorb the additional META-CANARY surface called out in the P3.2 postmortem (60+ canaries vs P3.1's 28 projected).

**Final verdict: MULTI-SESSION-RECOMMENDED (2 sessions), with Session 1 = scaffold + walker dormant and Session 2 = activate + close + Rule #52 Rule-of-Three promotion.**
