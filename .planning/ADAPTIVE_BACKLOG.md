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
> **Last updated:** 2026-05-18 (consolidation pass per evening:RvwC-C12).

---

## 1. In-Progress (this session — 2026-05-18 docs/patterns/rules cycle)

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `evening:RvwC-C12` | MEDIUM | evening | `.planning/ADAPTIVE_BACKLOG.md` — single source of truth for ~50 carry-forward items across recent postmortems | ~10 min, ~150 LOC markdown | **PRIORITY** per user direction; this file. |
| `evening:RvwC-C2` | HIGH | evening | `.mex/patterns/cross-stack-alignment-test.md` recipe — codify Rule-of-Nine cross-stack alignment discipline | ~30 min, ~120 LOC | TARGET 1 this session; rule-of-Nine durable beyond debate (CLAUDE.md Rule #25 single-slice exception #2 has 8 + evening's `d641f28` = 9). |
| `evening:RvwC-C7` | HIGH | evening | `.mex/patterns/forward-prepared-cve-pin.md` recipe — Rule-of-Two pattern with HARD-REJECT version_regex | ~30 min, ~100 LOC | TARGET 2 this session; Rule-of-Two evidence (Tegra `6bc1c1d` morning + MediaTek modem `e45a74c` evening). |
| `evening:RvwC-C14` | HIGH | evening | CLAUDE.md Rule-of-Three promotion — cross-stack-alignment + forward-prepared-CVE-pin + shared-advisory_id | ~1-2 hr, ~80 LOC | TARGET 3 this session; single Rule #25 cross-stack-alignment commit updating CLAUDE.md + `.mex/context/conventions.md` Verify Checklist per Rule #21. |

---

## 2. Open — HIGH severity (operator-visibility + forensic-correctness)

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `evening:RvwA-A5 + RvwB-B6` | HIGH | evening | Suppress duplicate-`advisory_id` WARN under intentional-convergence opt-in (`shared_advisory_id: true` YAML key) | ~30 LOC YAML schema + 2 tests | Today the FragAttacks shared `ADVISORY-FRAGATTACK` produces a WARN at load — trains operators to ignore it, masking accidental collisions. Add opt-in key + load handshake suppression. |
| `evening:RvwC-C10` | HIGH | evening | Extend `list_extension_points` MCP tool with F-FORENSIC-10 rejection counts per layer | ~40 LOC + 1 test | Operators need observability on "how many entries each layer rejected on last load"; without it, drift between layers becomes invisible to MCP clients. |
| `evening:RvwC-C11` | HIGH | evening | `verify_cve_attribution(cve_id, blob_id)` MCP tool — walk the matcher's attribution chain | ~80 LOC + tests | Operators triaging "why does this blob have CVE-X?" walk YAML by hand today; the matcher already produces this chain internally — surfacing it as a tool closes the operator loop. |
| `evening:RvwC-C4` | HIGH | evening | Advisory-id glossary — `describe_advisory(advisory_id)` MCP tool + frontend hover panel | ~60 LOC | Operator lookup for `ADVISORY-*` IDs lives only in YAML notes today. |

---

## 3. Open — MEDIUM severity

### 3.a Refactor / documentation hygiene

| ID | Severity | Source | Item | Effort | Notes |
|----|---------|--------|------|--------|-------|
| `evening:RvwA-A1` | MEDIUM | evening | Promote `caplog_at` to `backend/tests/conftest.py` | ~15 LOC + remove duplicates | Duplicated across `test_hardware_firmware_cve_matcher.py` and `test_forensic10_alignment.py`. First-class pytest discovery via conftest. |
| `evening:RvwA-A2` | MEDIUM | evening | Export `_BT_NARROWING_CONDITIONS` from `patterns_loader` | ~10 LOC + replace inspect.getsource grep | Replaces `test_forensic10_alignment.py`'s `inspect.getsource(_parse_banner_cve_pin)` source-text-grep with `len(_BT_NARROWING_CONDITIONS) == 6` against an explicit constant. Mirrors the L1 `_KNOWN_FIRMWARE_NARROWING_FIELDS` shape. |
| `evening:RvwC-C8` | MEDIUM | evening | HARD-REJECT `version_regex` semantics docs | ~30 LOC | `docs/features/extending-firmware-patterns.md` lacks the field reference; add a row documenting hard-reject behaviour per `cve_matcher.py:480-491`. Supports adoption of the forward-prepared-CVE-pin recipe. |
| `evening:RvwC-C9` | MEDIUM | evening | NVD CPE refresh cadence recipe | ~30 LOC | Codify quarterly NVD-CPE audit cron for `version_regex` pins (analog of Rule #37 anchor-refresh cron). |
| `afternoon:RvwC-MED-clar` | MEDIUM | afternoon | F-FORENSIC-10 WARN message clarity | ~20 LOC clarity | Restructure the WARN to lead with the affected entry + a scannable bullet list of fix options. Operators currently scan a single-line message. |
| `afternoon:RvwC-MED-ceremonial-note` | MEDIUM | afternoon | CLAUDE.md note on ceremonial vs genuine narrowing | ~60 LOC documentation | Explain WHEN ceremonial `category_regex: ^<existing>$` is acceptable (gate-satisfying placeholder) vs WHEN genuine NVD-derived narrowing is required. Reference the 14 entries deferred for per-CVE NVD derivation. |
| `morning:RvwC-CC-5 (orig 2026-05-18)` | MEDIUM | morning | Docs refresh — `docs/features/extending-firmware-patterns.md` Surface 6 + 6-surface table | ~40 LOC | Re-aligns operator docs with the post-`list_extension_points` reality. |
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
| `morning+afternoon:RvwC-REC-2 (orig 2026-05-18)` | MEDIUM | morning, afternoon | Tier A archive-suffix additions — `.7z` / `.tar.zst` / `.zst` / `.deb` | ~50 LOC + Dockerfile apt deps | Small extraction cases. Validates Tier A's adaptability claim. |
| `morning+afternoon:RvwC-CC-2 (orig 2026-05-18)` | MEDIUM | morning, afternoon | `extraction_strategy` enum | ~30 LOC + alembic migration | Replace `extracted_via_shortcut: bool` with `Literal["shortcut_clean", "shortcut_recursed", "unblob"]`. Improves operator observability. |
| `morning+afternoon:RvwC-CC-4 (orig 2026-05-18)` | MEDIUM | morning, afternoon | `conftest.py` `loader_with_tmp_yaml` fixture helper | ~15 LOC | 8-line wrapper for the `monkeypatch+cache_clear` scaffolding currently duplicated across YAML-cache tests. |
| `morning:RvwC-make_live_db-FK` | MEDIUM | morning | `make_live_db()` FK breakage on `volatility_injection_records → memory_dump_image` | ~30 LOC + canary sweep | 3 tests in `test_sbom_router.py` blocked + likely more. Find via `pytest -k Canary --tb=line` sweep. |
| `morning:RvwC-RTL-3 (orig 2026-05-18)` | LOW | morning | Realtek `bt_banner_cve_pins.yaml` worked example | ~15 LOC YAML | Ship a commented-out example pin under `family: realtek_bt`. Pairs with the parser's existing realtek_bt support. |
| `morning:RvwC-RTL-2 (orig 2026-05-18)` | LOW | morning | `RealtekChipsetEntry.extra: dict` field | ~10 LOC schema | Operator-supplied freeform metadata pass-through. |
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
