# Adaptive Detection Backlog

> Single source of truth for carry-forward items from the recent hardware-firmware
> adaptive-detection postmortems. Walked + deduplicated from three 2026-05-15
> sessions, then extended each session as items ship or new ones surface.
>
> **Sources walked for the 2026-05-18 consolidation:**
> - `morning`  — `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`
>                (commit chain `63e3bf5..b53f817` — `list_extension_points` MCP tool +
>                Tegra content-evidence parser + 6 forward-prepared Tegra CVE pins;
>                15 recs carried)
> - `afternoon` — `.planning/postmortems/postmortem-hw-firmware-tegra-activation-2026-05-15.md`
>                (commit chain `f54d415..338f95b` — L4T release extraction activating
>                4-of-6 Tegra pins + F-FORENSIC-10 schema gate analog + `state_snapshot()`;
>                15 recs carried)
> - `evening`  — `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md`
>                (commit chain `d641f28..3e12ae5` — F-FORENSIC-10 alignment regression
>                canary + FragAttacks NVD-CPE realignment + CVE-2023-20819
>                forward-prepared version_regex + Reviewer B HIGH CVSS fixup;
>                ~38 reviewer findings + 15 highest-leverage recs carried)
>
> **Status legend.**
> - `open`         — queued, not yet started, no in-flight commits.
> - `in-progress`  — actively shipping this session (linked commits noted in the row).
> - `completed`    — shipped in a prior session's commit chain (sha noted).
> - `deferred`     — deliberately punted with explicit rationale (NOT "open we just haven't
>                    gotten to" — these are scope-bound decisions to NOT ship).
>
> **ID scheme.** `<source-session>:<reviewer-ABC-NN>` namespaces each item to its
> original reviewer finding, so this file's reader can grep back to the source
> postmortem's `## Recommendations Carried Forward` section for full context.
> Duplicates across sessions are consolidated into the EARLIEST surfacing entry +
> additional source-session sigil; later-session re-mentions appear as
> `also: <later-session>:<reviewer-ABC-NN>` in the Notes column.
>
> **Last updated:** 2026-05-20 morning (P3.x `substring_in_head` signal kind — 1 commit closes the P3.2 postmortem Rec #2 deferral: windows_installer_iso + iso_9660 bridge cleanup via new closed-grammar `SubstringInHeadConstraint` sub-model; Rule #25 Shape-1 single-slice cross-stack alignment; 34 new tests including 4 paired Rule #46 gate-canaries for previously-unpaired exhaustive META-CANARIES). Prior 2026-05-19 update: file-format YAML registry Phase 3.2 + Phase 3.3.a — 15 commits `34d0689..7420279` closing all P3.1 deferrals + 5 ADAPTIVE_BACKLOG.md items: RvwA-A5+B6, RvwC-C10, scout1, RvwC-C4, RvwC-C11. CLAUDE.md Rule #52 promoted Rule-of-One → Rule-of-Two DURABLE BEYOND DEBATE; Wave-1+Wave-2 cross-feature critique methodology promoted to feedback memory.

---

## 1. In-Progress (this session — 2026-05-18 docs/patterns/rules cycle)

*(Empty at session close — all 4 in-flight items shipped and promoted to section 5 below.)*

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| _none — see section 5 for this session's completions_ |

---

## 2. Open — HIGH severity (operator-visibility + forensic-correctness)

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
<!-- SHIPPED 2026-05-19 — see Completed section: RvwA-A5+B6, RvwC-C10, RvwC-C4, RvwC-C11 -->
<!-- Frontend hover panel for RvwC-C4 deferred to future UI session. -->
| `evening:RvwC-C4-frontend` | LOW | evening 2026-05-18 → P3.x | Frontend hover panel for advisory_id glossary (calls `describe_advisory` MCP tool) | ~40 LOC frontend | Backend MCP tool shipped 2026-05-19 (`f1669c3`); frontend UI hover panel deferred. |

---

## 3. Open — MEDIUM severity

### 3.0 Rate-limit campaign deferred items (2026-05-18)

These are explicit punts from the rate-limit Citadel review (commits
`f6dbc7b..b24a4d8` + Rule #51 promotion `4616501`). Each was identified
by one of the 5 expert-persona scouts but scoped OUT of the
shipping batch to limit blast radius. Documented rationale in commit
chain + Rule #51 worked-example evidence.

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `ratelimit-2026-05-18:scout1-xff` | MEDIUM | scout1-security | X-Forwarded-For extraction in `rate_limit.py` `get_remote_address` callback | ~30 LOC + tests | Per-IP keying via slowapi default `get_remote_address` reads the immediate-peer IP. Behind a TLS-terminating reverse proxy (nginx / ALB / Cloudflare), all clients collapse to the proxy IP. Add `X-Forwarded-For`-aware callback gated by a `TRUST_FORWARDED_FOR` config flag (default `False`; operator opts in when deploying behind a trusted proxy). Out of scope for the f6dbc7b campaign because it's a DEPLOYMENT-shape change, not a same-deployment fix. |
<!-- SHIPPED 2026-05-19:3677f1c — see Completed section. -->
<!-- Remaining 58 unlimited endpoints from scout1's 68-endpoint audit are deferred to future rate-limit sessions. -->
| `ratelimit-2026-05-19:scout1-remaining-58` | LOW | scout1-security audit → P3.x | Sweep remaining ~58 unlimited POST endpoints from scout1's 2026-05-18 audit | scope TBD | Lower priority than the first 9 (apk_scan + comparison + attack_surface). Endpoints to audit: SBOM uploads, finding mutations, project CRUD, etc. — most are operator-CRUD shapes that don't need TIER_A_HEAVY (CRUD = TIER_C_DEFAULT 100/minute or unrestricted). Re-grep needed before scoping. |
| `ratelimit-2026-05-18:scout2-cleanup-task` | MEDIUM | scout1-security | Emulation container cleanup background task (GC containers older than `emulation_timeout_minutes`) | ~80 LOC + test | TIER_B_DOCKER 20/hour bounds spawn rate but doesn't reap zombies. Operator runs 20 emulation sessions and forgets to stop → containers accumulate over days. Add an arq cron-style task to delete containers older than the configured timeout. Out of scope for this campaign (separate feature, not 429 UX). |
| `ratelimit-2026-05-18:scout2-prometheus` | MEDIUM | scout2-infra + scout5-obs | Custom Prometheus metrics for rate-limit hits + background-task queue depth | ~50 LOC | The `event_type=rate_limit_exceeded` structured log (commit 616e89d) covers operator log-shipper greppability. A Prometheus counter `rate_limit_exceeded_total{endpoint, tier}` + gauge `vuln_scan_tasks_active` would enable dashboards. Out of scope: the existing prometheus-fastapi-instrumentator gives request-count + status-code metrics today; rate-limit hits show up as 429 there. Dedicated counters wait for Prometheus integration becoming first-class. |
| `ratelimit-2026-05-18:scout3-useratelimitedmutation` | MEDIUM | scout3-frontend-ux | Refactor pages to `useRateLimitedMutation` hook with Retry-After countdown + button disable | ~150 LOC | The C2 axios interceptor (commit ca5a64f) sets a module-scope `_rateLimitedUntilMs` + exports `isRateLimited()` / `rateLimitRemainingMs()`. A reusable hook would: (a) wrap the POST, (b) read the cooldown timestamp, (c) disable the button + show "Try again in Ns" countdown, (d) auto-re-enable when cooldown clears. Refactoring 5 pages (SbomPage / SecurityScanPage / HardwareFirmwarePage / EmulationPage / FuzzingPage). Out of scope: works correctly with the existing pages via the axios global toast; the hook is polish. |
| `ratelimit-2026-05-18:scout5-rate-limit-endpoint` | LOW | scout5-obs | `/api/v1/rate-limit-status` GET endpoint returning per-IP remaining budget per tier | ~40 LOC + frontend integration | Lets the frontend pro-actively show "X/30 scans left this hour" instead of waiting for the 429 round-trip. Cute UX win, low priority — operators rarely run multi-scan sequences that benefit from foreknowledge. |

### 3.a Refactor / documentation hygiene

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `evening:RvwA-A1` | MEDIUM | evening | Promote `caplog_at` to `backend/tests/conftest.py` | ~15 LOC + remove duplicates | Duplicated across `test_hardware_firmware_cve_matcher.py` and `test_forensic10_alignment.py`. First-class pytest discovery via conftest. |
| `evening:RvwA-A2` | MEDIUM | evening | Export `_BT_NARROWING_CONDITIONS` from `patterns_loader` | ~10 LOC + replace inspect.getsource grep | Replaces `test_forensic10_alignment.py`'s `inspect.getsource(_parse_banner_cve_pin)` source-text-grep with `len(_BT_NARROWING_CONDITIONS) == 6` against an explicit constant. Mirrors the L1 `_KNOWN_FIRMWARE_NARROWING_FIELDS` shape. |
| `evening:RvwC-C8` | MEDIUM | evening | HARD-REJECT `version_regex` semantics docs | ~30 LOC | `docs/features/extending-firmware-patterns.md` lacks the field reference; add a row documenting hard-reject behaviour per `cve_matcher.py:480-491`. Supports adoption of the forward-prepared-CVE-pin recipe. |
| `evening:RvwC-C9` | MEDIUM | evening | NVD CPE refresh cadence recipe | ~30 LOC | Codify quarterly NVD-CPE audit cron for `version_regex` pins (analog of Rule #37 anchor-refresh cron). |
| `afternoon:RvwC-MED-clar` | MEDIUM | afternoon | F-FORENSIC-10 WARN message clarity | ~20 LOC clarity | Restructure the WARN to lead with the affected entry + a scannable bullet list of fix options. Operators currently scan a single-line message. |
| `afternoon:RvwC-MED-ceremonial-note` | MEDIUM | afternoon | CLAUDE.md note on ceremonial vs genuine narrowing | ~60 LOC documentation | Explain WHEN ceremonial `category_regex: ^<existing>$` is acceptable (gate-satisfying placeholder) vs WHEN genuine NVD-derived narrowing is required. Reference the 14 entries deferred for per-CVE NVD derivation. |
| `prior-2026-05-18:RvwC-CC-5` | MEDIUM | morning (carry) | Docs refresh — `docs/features/extending-firmware-patterns.md` Surface 6 + 6-surface table | ~40 LOC | Originally Reviewer C CC-5 in `postmortem-hw-firmware-adaptive-session-2026-05-18.md` (prior-adaptive session); carried via morning's `## Recommendations Carried Forward`. Re-aligns operator docs with the post-`list_extension_points` reality. |
| `morning:Rule-#28-watch` | MEDIUM | morning | `patterns_loader.py` Rule #28 watch — re-measure before next refactor | ~1 hr re-measure + scope decision | Was 1437 LOC pre-morning; ~1440 LOC post-`register_loader()` additions. Per Rule #28 intakes drift +14-22% — re-measure before scoping a refactor. Next growth: extract Realtek block per Rule #27 N+1. |

### 3.b Adaptability + content-evidence extension

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `morning+afternoon:RvwC-C5` | MEDIUM | morning, afternoon | Tegra SOC token externalization to YAML | ~80 LOC + new YAML + hot-reload tests | `_TEGRA_ELF_SECTION_TOKENS` / `_TEGRA_SOC_TOKENS` / `_SOC_TO_CHIPSET` / `_TEGRA_FDT_MODEL_TOKENS` move from in-tree Python tuples to a hot-reloadable `tegra_soc_tokens.yaml` (mirror `bt_qca_codenames.yaml` shape). Closes the "operator adds 5th Tegra SoC" path. |
| `morning+afternoon:Tegra-TBDs` | MEDIUM | morning, afternoon | NVIDIA wrapper magic + BUP container magic — Tegra parser deferred TBDs | ~30 LOC × 2 + tests | When a live BSP install is available, `xxd | head` known `mb1.bin` / `tos.img` / `.bup` files to pin the bytes. Currently handled via 5th-fallback path-context gate; pinned magic would surface the subsets explicitly in `metadata["tegra_blob"]["subset"]`. |
| `morning:RvwB-B4 (2026-05-15)` | MEDIUM | morning | `_stringify_metadata` one-level-deep limitation | ~30 LOC | Current implementation walks `blob.metadata` values one level. Nested dicts (e.g. `tegra_blob.l4t_release`) are invisible. Either (a) flatten to top-level or (b) extend `_stringify_metadata` to walk one level deeper. Documented in the YAML Forward-Prepared Note + recommended fix path (a) — top-level promotion. |
| `evening:RvwB-B5` | MEDIUM | evening | `wcn7xxx` chipset_regex extension for FragAttacks | ~10 LOC YAML + 1 test | Wi-Fi 7 Qualcomm parts may carry FragAttacks-affected SoftMAC firmware. Currently the qualcomm FragAttacks advisory entry matches wcn3xxx/6xxx; extending to wcn7xxx is a per-NVD-CPE refresh task. |
| `evening:RvwA-A7 + RvwB-B9` | LOW+MEDIUM | evening | Tier 4 SBOM NVD-CPE alignment audit | ~20 LOC docs | Tier 4 emits CVE-2020-2458x on kernel_module blobs via `linux_kernel` CPE — correct per NVD scope but should be documented to avoid future "looks like FragAttacks over-attribution" confusion. |
| `afternoon:RvwB-MED-52160` | MEDIUM | afternoon | wpa_supplicant CVE-2023-52160 over-broad category | ~10 LOC YAML | NVD CPE attribution is to `w1.fi:wpa_supplicant` binary, not all WiFi. Recommend `category: wpa_supplicant` (new category) OR path_regex narrowing. |
| `afternoon:RvwC-MED-l4t-tolerance` | MEDIUM | afternoon | L4T regex tolerance for stripped formats | ~30 LOC | Current regex requires literal `(release)` token. Some operator-stripped formats omit it. Add fallback regex matching bare `R\d{2,3}\.\d+\.\d+` patterns + document the contract in the parser docstring. |
| `evening:RvwB-B11` | MEDIUM | evening | Audit KRACK / Dragonblood / BroadPwn for FragAttacks-shape over-attribution | ~1-2 hr per disclosure + NVD WebFetch | Similar SPEC-level disclosure-batch CVEs may have zero-vendor-CPE patterns that the curated tier over-attributes. Each disclosure needs its own NVD CPE walk + scoping decision (advisory-only vs per-vendor narrow). |

### 3.c Infrastructure / scaffolding

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `prior-2026-05-18:RvwC-REC-2` | MEDIUM | morning, afternoon (carry) | Tier A archive-suffix additions — `.7z` / `.tar.zst` / `.zst` / `.deb` | ~50 LOC + Dockerfile apt deps | Originally Reviewer C REC-2 in prior-adaptive 2026-05-18 session; carried via morning + afternoon postmortems' carry-forward lists. Small extraction cases. Validates Tier A's adaptability claim. |
| `prior-2026-05-18:RvwC-CC-2` | MEDIUM | morning, afternoon (carry) | `extraction_strategy` enum | ~30 LOC + alembic migration | Originally Reviewer C CC-2 in prior-adaptive 2026-05-18 session; carried via morning + afternoon postmortems. Replace `extracted_via_shortcut: bool` with `Literal["shortcut_clean", "shortcut_recursed", "unblob"]`. Improves operator observability. |
| `prior-2026-05-18:RvwC-CC-4` | MEDIUM | morning, afternoon (carry) | `conftest.py` `loader_with_tmp_yaml` fixture helper | ~15 LOC | Originally Reviewer C CC-4 in prior-adaptive 2026-05-18 session; carried via morning + afternoon postmortems. 8-line wrapper for the `monkeypatch+cache_clear` scaffolding currently duplicated across YAML-cache tests. |
| `morning:RvwC-make_live_db-FK` | MEDIUM | morning | `make_live_db()` FK breakage on `volatility_injection_records → memory_dump_image` | ~30 LOC + canary sweep | 3 tests in `test_sbom_router.py` blocked + likely more. Find via `pytest -k Canary --tb=line` sweep. |
| `prior-2026-05-18:RvwC-RTL-3` | LOW | morning (carry) | Realtek `bt_banner_cve_pins.yaml` worked example | ~15 LOC YAML | Originally Reviewer C RTL-3 in prior-adaptive 2026-05-18 session; carried via morning postmortem. Ship a commented-out example pin under `family: realtek_bt`. Pairs with the parser's existing realtek_bt support. |
| `prior-2026-05-18:RvwC-RTL-2` | LOW | morning (carry) | `RealtekChipsetEntry.extra: dict` field | ~10 LOC schema | Originally Reviewer C RTL-2 in prior-adaptive 2026-05-18 session; carried via morning postmortem. Operator-supplied freeform metadata pass-through. |
| `afternoon:RvwC-LOW-taint-llm` | LOW | afternoon | `state_snapshot()` adoption: taint_llm YAML loaders | ~30 LOC | `app/ai/tools/taint_llm.py:78-101` uses `@lru_cache` on YAML loaders — cold-cache shape (process-lifetime once only). Migrate to `MtimeCachedYamlLoader` for hot-reload. |
| `afternoon:RvwC-LOW-debian-l4t` | LOW | afternoon | Debian ar L4T extraction post-unblob | ~30 LOC | When unblob unpacks a `.deb` containing `/etc/nv_tegra_release` (e.g. `nvidia-l4t-bootloader_32.3.1-20191209230245_arm64.deb`), the extracted text file gets `vendor=unknown` and L4T metadata is lost. Add detector-layer check + propagate to firmware-level metadata. |

---

## 4. Deferred (scope-bound — DO NOT ship blindly; documented rationale)

| ID | Severity | Source | Item | Rationale |
|----|---------|--------|------|-----------|
| `morning:CVE-2021-34373..34396` | (deferred) | morning | CVE-2021-34373..34396 disclosure-batch range — 24 NVIDIA Tegra CVEs | Per Pattern #1 of `postmortem-hw-firmware-mcp-tegra-2026-05-15` (recursive NVD-CPE verification): EACH CVE requires its own NVD-CPE WebFetch + per-Tegra-SoC narrowing before pinning. Disclosure-batch antipattern at the curated tier. Not a single bulk-import. Future scout-driven sessions can pick subsets (e.g. by SoC family) for verifiable shipment. |

---

## 5. Completed (recent shipped work — kept for audit trail)

| ID | Severity | Source | Item | Shipped in | Notes |
|----|---------|--------|------|-----------|-------|
| `p3x:substring_in_head` | HIGH | P3.2 postmortem Rec #2 → 2026-05-20 | `substring_in_head` signal kind — closes the windows_installer_iso + iso_9660 bridge case | `2026-05-20:dcebd1c` (1 commit) | Rule #25 Shape-1 single-slice: new `SubstringInHeadConstraint` Pydantic sub-model (5 fields, 16-needle cap, 64-byte-per-needle cap) + `SubstringInHeadCombine` Literal + `DetectionSignalKind` += `substring_in_head` + `_eval_substring_in_head` evaluator + `_SIGNAL_COST_CLASS` entry (cost 2; same I/O class as magic_bytes) + `SIGNAL_EVALUATORS` dispatch entry + `windows_installer_iso.yaml` adopts new signal (bootmgr / sources/boot.wim / sources\\boot.wim needles; case_sensitive=false; combine=any) + `format_detection.py` drops both `iso_9660` + `windows_installer_iso` from `_CATALOG_NEEDS_DISAMBIGUATION` + deletes the bootmgr substring upgrade block in `_legacy_bridge_detect`. Corpus fixture `windows_installer_iso.head` regenerated with bootmgr at offset 0x100 + CD001 at 0x8001; parity test `_HEAD_BYTES_INSUFFICIENT` drops `windows_installer_iso`. New test file `test_substring_in_head_evaluator.py` (34 tests: positive/negative eval + case-sensitivity + combine=any/all + min_count + search_offset/length + schema validation + catalog round-trip + Rule #46 paired META-CANARY for SIGNAL_EVALUATORS exhaustive + _SIGNAL_COST_CLASS exhaustive + DISPATCH_EVALUATORS exhaustive + anti-hardcode AST-walk + 4 new paired gate-canaries that the pre-edit codebase was missing per Rule #46 §gate-canary-requirement). 433/434 pytest sweep green (1 skipped is pre-existing); Rule #11 import smoke + Rule #35b live canary via running backend confirm: bootmgr-bearing ISO → windows_installer_iso, bare CD001 ISO → iso_9660. |
| `file-format-yaml-registry-p32` | HIGH | continuation-of-P3.1 → 2026-05-19 evening | Phase 3.2: closed-grammar sort_tier + precedence-flip + TextFormatConstraint + RTOS plugin HYBRID + A6/A7/A8/A9 gates + parity-JSON-snapshot + Rule #52 Rule-of-Two promotion + P3.3.a legacy shim deletion | `2026-05-19: 34d0689..4c028fc` (P3.2.a..f + P3.3.a, 7 commits) + `229578a + 0038698` (postmortem + /citadel:learn) | 15 commits closing all P3.1 deferrals end-to-end. CLAUDE.md Rule #52 promoted Rule-of-One → Rule-of-Two DURABLE BEYOND DEBATE (bare-metal MCU/DSP + file-format YAML registry). 60+ paired META-CANARIES; 3 NEW §SC5 analogs caught by W2-β cross-feature critique (dispatch-chain authority laundering → A6; TextFormatConstraint high-collision → A8; RTOS plugin family namespace collision → A7). 383/383 in-scope pytest sweep green. Patterns extracted to `.planning/knowledge/file-format-yaml-registry-p32-2026-05-19-{patterns,antipatterns}.md`. Postmortem at `.planning/postmortems/postmortem-file-format-yaml-registry-p32-2026-05-19.md`. Methodology: Wave-1 + Wave-2 cross-feature critique separation promoted to feedback memory `feedback_wave2_cross_feature_methodology.md`. |
| `evening:RvwA-A5 + RvwB-B6` | HIGH | evening 2026-05-18 → 2026-05-19 | Suppress duplicate-`advisory_id` WARN under intentional-convergence opt-in (`shared_advisory_id: true` YAML key) | `2026-05-19:23974ea` | 3 new tests in `test_hardware_firmware_cve_matcher.py` (both-opt-in suppressed; asymmetric opt-in WARNs; pre-flag backward-compat). Both FragAttacks YAML entries (broadcom + qualcomm wcn3xxx) now declare the flag. |
| `evening:RvwC-C10` | HIGH | evening 2026-05-18 → 2026-05-19 | Extend `list_extension_points` MCP tool with F-FORENSIC-10 rejection counts per layer | `2026-05-19:4ecaa5b` | Module-level `_LAST_LOAD_REJECTIONS` dict in `cve_matcher.py` tracking 4 categories (advisory_missing_advisory_id / advisory_id_too_long / advisory_id_duplicate_warn / f_forensic_10_no_narrowing); accessor `get_known_firmware_load_rejections()`; surfaced in MCP tool payload under `load_rejections.curated_known_firmware`. |
| `ratelimit-2026-05-18:scout1-apk-comparison-tiers` | MEDIUM | 2026-05-18 scout1 → 2026-05-19 | TIER_A_HEAVY rate-limit on 9 expensive sync POST endpoints (3 apk_scan + 5 comparison + 1 attack_surface) | `2026-05-19:3677f1c` | Per Rule #51 tier-decision rubric: sync CPU-bound work = TIER_A_HEAVY (5/hour). `_EXPECTED_TIERS` size-locked at 20 (was 11). |
| `evening:RvwC-C4` | HIGH | evening 2026-05-18 → 2026-05-19 | `describe_advisory(advisory_id)` MCP tool | `2026-05-19:f1669c3` | Operator queries `ADVISORY-*` ID; tool returns matching `known_firmware.yaml` entries with full payload (name + vendor + category + narrowing fields + severity + cvss + notes + `shared_advisory_id` flag). Top-level `is_shared: bool` = `True` iff all matching entries declared the opt-in. Frontend hover panel deferred. |
| `evening:RvwC-C11` | HIGH | evening 2026-05-18 → 2026-05-19 | `verify_cve_attribution(cve_id, blob_id)` MCP tool — walk matcher's attribution chain | `2026-05-19:7420279` | Returns `match_tier` + `match_confidence` + blob context (vendor/category/format/chipset/version) + matching `known_firmware.yaml` entry (for curated/advisory tiers). Closes the operator-visibility loop on "why does this blob have CVE-X?". |
| `ratelimit-2026-05-18:campaign` | HIGH | operator-report (DS1 429) + Citadel 5-scout review | Rate-limit tier split + structured 429 handler + frontend UX + DB pool headroom + orphan reaper + new rate limits + dynamic test + Rule #51 promotion | `2026-05-18: f6dbc7b → 69ed1dd → ca5a64f → 616e89d → 3d2454b → 58a6f54 → 8766710 → afa23a9 → b24a4d8 → 4616501` (10 commits) | 9-commit per-Rule-#25 sweep across backend (tier split / structured handler / pool / orphan reaper / 2 new decorated endpoints / test trio) + frontend (extractErrorMessage / axios interceptor) + docs (Rule #51 + conventions.md mirror per Rule #21). Verified end-to-end: Rule #11 import smoke + Rule #35b live canary (POST DS1 vuln-scan → 202; POST /firmware/{id}/unpack 6× → 5×409 + 1×429 with structured body `tier=TIER_A_HEAVY`, `retry_after_seconds=3600`, `Retry-After: 3600`); Rule #46 META-CANARY trio in `test_rate_limit_tiers.py` (6 tests, all PASS). Companion failure modes Rule #51 documents: orphan reaper / frontend 429 handler / structured body / pool headroom. Rule #20 caveat: backend was iterated via `docker cp + restart`; next session should rebuild backend for durable state via `docker compose up -d --build backend worker`. |
| `evening:RvwC-C12` | MEDIUM | evening → consolidation-2026-05-18 | `.planning/ADAPTIVE_BACKLOG.md` — single source of truth | `2026-05-18:533bb72` | Walked + deduplicated ~50 items across morning + afternoon + evening 2026-05-15 postmortems. PRIORITY per user direction. |
| `evening:RvwC-C2` | HIGH | evening → consolidation-2026-05-18 | `.mex/patterns/cross-stack-alignment-test.md` recipe | `2026-05-18:105a888` | Rule-of-Nine durable beyond debate; recipe codifies 5-part test shape + 2 commit shapes + asymmetry tolerance. |
| `evening:RvwC-C7` | HIGH | evening → consolidation-2026-05-18 | `.mex/patterns/forward-prepared-cve-pin.md` recipe | `2026-05-18:b8f6e95` | Rule-of-Two pattern; HARD-REJECT version_regex contract at `cve_matcher.py:477-491`; activation commit-chain plan. |
| `evening:RvwC-C14` | HIGH | evening → consolidation-2026-05-18 | CLAUDE.md Rules #48-50 promotion + Rule #25 Rule-of-Eight → Rule-of-Nine | `2026-05-18:294fa3a` (CLAUDE.md + conventions.md mirror per Rule #21) + Reviewer A HIGH fixup `2026-05-18:17959a6` (correct Rule #50 dedup-mechanic claim — NO DB UniqueConstraint exists, app-side `existing`-set lookup at `cve_matcher.py:905,989,1042`) | Single Rule #25 cross-stack-alignment commit shape per Rule #48 Shape 1. |
| `evening:RvwC-C01` | HIGH | (this session's reviewer C-01) | `.mex/ROUTER.md` routing-table row + last_updated bump → ADAPTIVE_BACKLOG surfaced to future-session openers | `2026-05-18:14f4357` | Closed the future-session-affordance loop. Fresh session opener loading ROUTER.md per Behavioural Contract now discovers the backlog. |
| `morning:RvwB-B1 (F-FORENSIC-10 gate)` | HIGH | morning → afternoon | F-FORENSIC-10 schema gate analog for `known_firmware.yaml` + 16-entry pre-narrowing | `afternoon:5398f16` | Pre-implementation width-canary audit caught 16-entry scope vs user-prompt's named 1 (Rule #31 applied to YAML edits). |
| `morning:RvwA-A6 + A7 (state_snapshot)` | HIGH | morning → afternoon | `state_snapshot()` public method on `MtimeCachedYamlLoader` + cross-domain helper move | `afternoon:bbaef3b` | Abstraction-boundary fix replacing defensive `getattr` reads that masked refactor signals. |
| `morning:L4T-extraction` | HIGH | morning → afternoon | L4T release extraction in Tegra parser (3-stage: content-banner + path-inference + raw_bin 5th fallback) | `afternoon:f54d415 + 0a901f2 + 338f95b` | Activated 4-of-6 forward-prepared Tegra CVE pins on DS1; 63/99 blobs got `l4t_release=R32.3.1`. |
| `afternoon:RvwA-MED-alignment-test` | MEDIUM | afternoon → evening | Cross-stack F-FORENSIC-10 alignment regression canary | `evening:d641f28` | New file `backend/tests/test_forensic10_alignment.py` (7 declared tests, 16 cases via parametrize) — adds Rule-of-Nine instance to CLAUDE.md Rule #25 single-slice exception #2. |
| `afternoon:RvwB-HIGH-fragattacks` | HIGH | afternoon → evening | FragAttacks NVD-CPE realignment — curated CVE → advisory tier | `evening:54a0a32 + 3e12ae5` | Shared `advisory_id: ADVISORY-FRAGATTACK` across broadcom + qualcomm entries; preserved forensic visibility (32 advisory rows on qualcomm wcn3xxx blobs) while respecting NVD CPE attribution scope (0 broadcom + 0 qualcomm CPEs across 3 SPEC-level CVEs). Reviewer B HIGH CVSS fixup (medium 6.5 → NVD primary LOW 3.5) shipped as separate commit. |
| `afternoon:RvwB-HIGH-cve-2023-20819` | HIGH | afternoon → evening | MediaTek CVE-2023-20819 forward-prepared `version_regex` narrowing | `evening:e45a74c` | Narrowed to 6 NVD-CPE-affected modem-OS families (`lr11/lr12a/lr13/nr15/nr16/nr17`); hard-reject on NULL version produces 0 rows today; activates when mtk_modem parser ships MOLY banner extraction. Rule-of-Two pattern (Tegra `6bc1c1d` is the other instance). |
| `morning:Tegra-CVE-pins` | HIGH | morning | 6 NVIDIA Tegra/L4T CVE pins (CVE-2019-5680 + CVE-2021-1111 + CVE-2021-34372 + CVE-2021-34397 + CVE-2022-42269 + CVE-2022-42270) | `morning:6bc1c1d + afternoon:387ad4a + e93920e` | Forward-prepared cluster with NVD-CPE-derived chipset_regex + version_regex narrowing. Reviewer B CVSS fixup (`387ad4a` — 6.0→6.7 + medium/5.5→low/2.3) + chipset_regex tightening (`e93920e` — exclude post-2018 codenames). 4 of 6 fired on DS1 post-L4T-activation (afternoon session); 2 correctly excluded per NVD scope (CVE-2019-5680 R32.3.1+ post-fix; CVE-2022-42270 Xavier-only). |
| `morning:list_extension_points + last_warning` | HIGH | morning | `list_extension_points` MCP tool + `last_warning` field + loader registry | `morning:63e3bf5 + 4c35b00 + f20e6ad` | Closed 3 Reviewer findings in one tool (CC-3 + HOT-1 + HOT-2); Reviewer A A1 vanish-path follow-up shipped same-day. |
| `morning:Tegra-content-evidence-parser` | HIGH | morning | NVIDIA Tegra content-evidence parser (`parsers/tegra_blob.py`) | `morning:8054d22` | ~520 LOC, 4 in-scope formats (ELF / FDT / Android boot.img / Debian ar) + 2 deferred TBDs. Validated end-to-end: 44/99 DS1 blobs got `vendor=nvidia` via FDT compatible-string scan including operator-renamed variants. |
| `morning:BT-parser-families-alignment` | HIGH | morning | Cross-stack alignment test for BT parser families | `morning:b53f817` | `patterns_loader._BT_PARSER_FAMILIES` ↔ `parsers.bt_firmware_banner.BT_PARSER_FAMILIES`. First explicit Rule #25 cross-stack-alignment-commit shape in the hw-firmware area (which then matured into evening's F-FORENSIC-10 alignment + this session's recipe). |

---

## 6. Methodology + refresh cadence

**Walking the postmortems.** Each postmortem's `## Recommendations Carried Forward`
section is the canonical source. Items are reviewer-tagged at finding time (Reviewer
A architecture / Reviewer B forensic-domain / Reviewer C adaptability) with a severity
band; this file preserves the tag + adds session-source sigil + status.

**Adding a new item.** When a postmortem lands with a new recommendation, the
postmortem author (or the next-session opener) appends a row to the appropriate
severity section. Use the established `<session>:<reviewer-ABC-NN>` ID scheme.

**Marking complete.** When a session ships an item, move the row to section 5 with
the commit SHA(s). Keep the audit trail (do NOT delete completed rows in the immediate
3-session window — the recent history makes Rule-of-N pattern surfacing easier).

**Pruning.** Completed rows older than ~60 days can be archived to a separate
`ADAPTIVE_BACKLOG_ARCHIVE.md` if the file grows past ~500 lines. Until then, in-place
is fine and the grep stays cheap.

**Refresh cadence.** Per `evening:RvwC-C12` operator expectation, this file is the
**single source of truth** — every hw-firmware session opener should grep it BEFORE
re-reading multiple postmortems. The first action of a new session is to spot-check
this file's `## 1. In-Progress` section against the live commit log; stale rows there
mean a prior session shipped without updating, and the corrective edit goes in the
opening commit.

**Cross-references.**
- CLAUDE.md Learned Rules: source-of-truth for the discipline this backlog operationalises.
- `.mex/context/conventions.md` Verify Checklist: per-task gate derived from CLAUDE.md.
- `.mex/patterns/INDEX.md`: recipes that close common items (e.g. `add-mcp-tool.md`
  closes most of section 2's MCP-tool items in ~30 min each).
- `.planning/knowledge/*-patterns.md` + `*-antipatterns.md`: extracted patterns
  from completed work; useful when scoping a new item against historical precedent.
