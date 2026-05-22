---
intake_id: architecture-health-audit-2026-05-22
title: Wairz architecture-health audit — 5-scout cross-cutting review of session-day findings
status: open
opened: 2026-05-22
trigger: operator directive "based on all of the issues found in this session you should deep analyze review entire architecture for things like this"
priority: high
estimated_effort: 3-5 sessions (or fleet-decompose into parallel streams)
---

# Wairz Architecture-Health Audit (2026-05-22)

## Provenance

Today's debugging chain (commits `89b87d3..47ecadb..afb7ea9..0c1234` — over-constraint sweep + SBOM completeness + CVE pin batch + standalone APK + 5+ vulnerabilities-list fixes) surfaced 22+ individual issues. Operator observed the meta-pattern was being missed: "based on all of the issues found in this session you should deep analyze review entire architecture for things like this".

5-scout parallel architecture review fired. Findings below organize the symptoms into seven structural classes (P1-P7), each with recommendations.

## Patterns

### P1 — Parallel write-pipelines, single read-pipeline INNER JOIN
(Rule-of-Six confirmed across 3 fixed today + 5 found in audit)

The same table is populated by TWO write paths with **mutually-exclusive FKs** (e.g. `component_id XOR blob_id`); a read endpoint joins to only one FK with INNER JOIN, silently dropping every row from the other path.

**Confirmed bugs:**
1. `47ecadb` (today) — `routers/sbom.py:944` vulnerabilities list. **FIXED.**
2. `routers/sbom.py:575` — VEX export INNER JOIN. **FIXED today (commit pending).**
3. `ai/tools/sbom.py:710` — MCP `list_vulnerabilities`. **FIXED today.**
4. `ai/tools/sbom.py:844` — MCP VEX export. **FIXED today.**
5. `vulnerability_service.py:300` — `_create_findings_from_vulns` — biggest impact: zero auto-Findings for blob-CVE projects. **FIXED today.**
6. `bare_metal.py:195` — cross-firmware aggregation MCP tool drops findings after firmware deletion. **MEDIUM, deferred.**

**Cross-cutting recommendation:**
- **Ruff/AST lint rule `no-inner-join-on-nullable-fk`** — walk `sqlalchemy.select(...).join(<right>, <Left>.<col> == <right>.id)` and fail when `<col>` is `Mapped[T | None]` (nullable). 5 of 5 confirmed bugs would be caught at lint time.
- **Pydantic schema marker** — when a response carries two `Optional[uuid.UUID]` FK fields documented as mutually exclusive (cf. `SbomVulnerabilityResponse.component_id` + `blob_id`), assert at construction time that at least one is populated.
- **Rule #46 META-CANARY for XOR-FK tables** — fixture writes one row via path A + one via path B; every read endpoint must return COUNT=2, not 1. Mirrors Rule #35b live-canary on the read side.

### P2 — Vocabulary drift between curated YAML and detector
(7 confirmed drift surfaces)

YAML pins reference enum values the runtime never emits, or vice versa. Three-way comparison results:

| Surface | Pins-only (non-firing) | Detector-only (no pins) |
|---|---|---|
| Blob `category` | `kernel_module` (3 pins) | `dtb`, `display`, `fingerprint`, `nfc`, `other`, `sensor`, `touchpad`, `usb` (8) |
| Blob `vendor` | `samsung` (≥1 pin) | `awinic, bosch, cirrus, edan, elan, fingerprint-cards, focaltech, goodix, himax, invensense, nordic, nxp, realtek, sensortek, silead, synaptics, ti` (17) |
| `detection_source` (SBOM strategy) | (none) | backend emits **20**; frontend Literal declares **5**. **15-value drift.** |
| `severity` | `unknown` emitted by 3 sites; not in frontend Severity Literal |
| `match_tier` | stale docstring lists `chipset_cpe, nvd_freetext` (never emitted) |

**Cross-cutting recommendation:**
- **`test_blob_category_alignment.py`** — Rule #48 5-part shape: assert `classifier.py:CATEGORIES ⊇ {pins ∪ patterns}`. Paired META-CANARY: synthesize a `category=does_not_exist` pin, confirm the matcher's curated-tier loader rejects (currently WARN-only — should be raise per Rule #45).
- **`test_detection_source_alignment.py`** — Rule #48 Shape-2 regression canary asserting backend-emitted strings ⊆ frontend `DetectionSource` Literal. Would fire RED today.
- Coerce `severity = "unknown"` to `"info"` at backend boundary OR extend frontend Severity Literal to include "unknown".

### P3 — Operator-initiated workflows that don't auto-chain
(2 HIGH severity gaps confirmed)

`upload_stage → unpack_stage → hw-firmware-detection → walker fan-out` is fully chained via `WALKER_AUTO_TRIGGERS` registry (Rule #47). But `sbom_status → vuln_scan_status` and `hw-firmware-detection → cve_match_status` are NOT chained — operators must click separate buttons.

**Operator symptom (exactly the user's report today):** "SBOM has 28 components, but vulnerabilities list shows 0 unless I click 'Scan for Vulnerabilities'".

**Recommended chain additions:**

| Source | Target | Cost | Rationale |
|---|---|---|---|
| `_run_sbom_generate_background` end (when total_components > 0) | `_run_vuln_scan_background` | 30-60s (Grype offline DB, image-bundled) | The user's exact symptom |
| `_run_hardware_firmware_detection_safe` end (when blobs > 0) | `_run_cve_match_background` | 1-7 min (curated YAML, local CPE) | Same shape as walker auto-trigger |
| Walker batch end (per-firmware) | `CRAComplianceService.auto_populate` (IF assessment exists) | sub-second (DB join) | Keeps CRA current |

**Cross-cutting recommendation:**
- **New `POST_EXTRACTION_CHAIN` registry** at `backend/app/workers/walker_registry.py` alongside `WALKER_AUTO_TRIGGERS` — list of `(predicate, runner_id)` tuples respecting Rule #33 .a 409-idempotency at each step. Operator can disable globally via env var. Walker triplet (Rule #39 .safe) stays at status='idle'; the new chain flips status='queued'→'completed' on Rule #33 runners.

### P4 — Silent caps without operator-visible truncation notice
(11 HIGH severity + 8 MEDIUM unsurfaced)

Three conventions coexist in code: (a) good template with `+N more` sentinel (~60%), (b) header-only count disclosure (~25%), (c) silent (~15%). Today's session fixed 5 instances; audit found ~14 more.

**Worst:** `assessment_service.py:497` — Semgrep findings silently truncated to 50 in PERSISTENT STORAGE (not just display). Operator sees 50 findings; DB never received the other N-50.

**Other HIGH severity (file:line):**
- `models/sbom.py:34` — `sbom_components.version VARCHAR(100)` — Qualcomm banners overflow (Rule #15 family; bridge truncates with "..." today, model should widen to 512)
- `ai/tools/network.py:195,321` — pcap conversations silently `[:50]`, `[:30]`
- `ai/tools/fuzzing.py:823,839` — crashes + campaigns lists silently `[:30]`
- `ai/tools/security.py:591,597,3534,3604,3643` — perms + VT detections silently capped
- `ai/tools/emulation.py:2705` — memory_errors silently `[:30]`
- `ai/tools/uefi.py:438,460` — modules/NVRAM header-only disclosure (HP/Dell UEFI dumps have 800+ modules)

**Cross-cutting recommendation:**
- Add `backend/app/utils/truncation.py::truncate_with_notice(items, cap, label)` helper returning `(slice, marker_str)`. Mechanically convert 14 silent sites.
- **Harness rule `auto-slice-without-sentinel`** at `.claude/harness.json` — regex `\bfor\s+\w+\s+in\s+\w+\[:\d+\]:` flagged when next 8 lines lack `if len(\w+) > \d+`.
- **Rule #15 column-overflow audit step at PR time** — `SELECT MAX(LENGTH(column)) FROM table` for new VARCHAR(N) columns; assert MAX < N × 0.7.

### P5 — Strategy coverage gaps (firmware shape × SBOM strategy matrix)
(8+ shapes with 0 coverage)

49 firmware shapes declared via `file_format_catalog`; 8+ have ZERO SBOM strategy AND ZERO curated CVE pins:

- **Windows installer family** (MSI, MSIX, MSU, CAB, DriverPackage, VHDX, InstallerISO, PSF, WIM) — extraction works; SBOM strategy + pins NONE. Operator uploads a 600 MB Windows driver bundle, sees 0 components.
- **QNX IFS** — partial extraction; no strategy + no pins (real-world target: Medtronic / BlackBerry firmware).
- **Acronis backup** — partial extraction (BYOB tibxread); no UI surfacing of "BYOB-required" state.
- **UEFI firmware** — DBX/Authenticode walkers exist (Rule #37); no `category: uefi` curated pins.
- **`linux_elf` standalone** — strategies all gate on `/bin /lib /usr` tree.

**Forward-prepared CVE pins still blocked:**
- **MediaTek CVE-2023-20819** — blocked on `mtk_modem` parser emitting MOLY banner (~50 LOC fix).
- **Tegra CVE-2021-34373..34391 cluster** — comment says "FORWARD-PREPARED" but banner extraction shipped (commit `1c2dee5`-era). **Action**: re-run cve-match on Jetson corpus, confirm CVEs fire today, update comment block (Rule #21 sync gap).

**Cross-cutting recommendation:**
- **`backend/tests/test_sbom_strategy_coverage_matrix.py`** — Rule #46 META-CANARY parametrized over file_format YAML entries. Per shape: `(min_components, strategies_fired, zero_by_design_flag, expected_pin_categories)`. Forces every new shape to declare expected coverage AT PR TIME, not session-3-months-later operator complaint.
- UI must distinguish "0 components, walked nothing" (bug) from "0 components by design — bare-metal MCU / RTOS opaque" (correct, surfaced).

### P6 — Frontend exhaustive `Record<Type, Config>` drift (Rule #9)
(2 surfaces confirmed drift; 1 well-policed)

Per CLAUDE.md Rule #9, frontend `Record<EnumType, Config>` lookups return `undefined` when backend adds new enum values.

| Surface | State |
|---|---|
| `FindingSource` (DB CHECK + Literal + FINDING_SOURCE_CONFIG) | ✓ Clean — 92 values agree pairwise via `test_finding_source_alignment.py` |
| `DetectionSource` (backend emits 20, frontend declares 5) | ✗ 15-value drift, no alignment test |
| `Severity` ("unknown" emitted by 3 sites, not in Literal) | ✗ Coercion gap at backend boundary |
| `MatchTier` (backend emits 3, docstring claims 5, frontend displays string verbatim) | ✗ No closed enum; latent risk |

**Cross-cutting recommendation:** add 3 Rule #48 5-part cross-stack alignment tests mirroring the well-working `test_finding_source_alignment.py`.

### P7 — Forward-prepared pins blocked on parser features (Rule #49)
Audit found:
- ~24 Tegra/L4T CVE pins forward-prepared on banner extraction (most fire today; comment stale per P5)
- 1 MediaTek modem CVE blocked on MOLY banner parser
- 3 `category: kernel_module` pins structurally non-firing (P2 vocabulary drift)

Recommendation: when a parser ships a new banner extraction, Rule #21 companion-file sync MUST include "re-validate all forward-prepared pins for this parser; update comment blocks; SELECT sbom_vulnerabilities to confirm fire."

## Priorities for ship sequence

### Immediate (this week)
1. **The 4 INNER JOIN bugs** — shipped today in this commit.
2. **`category: kernel_module` to `category: kernel` migration** for the 3 remaining pins, OR ship the classifier alignment to emit `kernel_module` for `.ko` blobs.
3. **`severity = "unknown"` coercion** — backend boundary fix.

### Short-term (next 2 sessions)
4. **POST_EXTRACTION_CHAIN registry** — close the SBOM→vuln_scan + HW-detection→cve_match auto-chain gaps.
5. **`sbom_components.version` widen to VARCHAR(512)** + alembic migration + Rule #15 family extension.
6. **`test_detection_source_alignment.py` + `test_blob_category_alignment.py`** — Rule #48 5-part cross-stack alignment tests.

### Medium-term (campaign-scale)
7. **`test_sbom_strategy_coverage_matrix.py`** — forces every firmware shape to declare expected coverage.
8. **Windows installer family SBOM strategies + curated CVE pins** — 8 shapes, ~5 sessions each (research + strategy + pins + tests).
9. **`no-inner-join-on-nullable-fk` ruff/AST lint rule** — prevent future P1 regressions.
10. **Tegra CVE-2021-34373..34391 cluster** — re-validate firing; update YAML comment block.

### Long-term (architecture refactor)
11. **Unified `truncate_with_notice` helper** + harness rule for silent `[:N]` slices.
12. **CRA compliance auto-update** on walker batch completion (low cost, high UX).
13. **APK Scan + StandaloneApkStrategy unification** — currently two paths for APK analysis (findings vs SBOM); consider merging.

## Cross-cutting wins

If we ship the alignment-test family (P2/P6) + the lint rule (P1) + the truncation harness rule (P4) + the coverage matrix (P5), the WHOLE class of bugs from today is preventable at PR time. Today's debugging chain (operator → me one at a time) is the slow, painful version. The fast version is automated structural enforcement.

## Files produced by this audit (scout reports)

5 Citadel scout reports captured in this session (output verbatim above this intake). Each is ~600-1100 words of evidence + recommendation.
