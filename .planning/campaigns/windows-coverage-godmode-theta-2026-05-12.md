---
campaign_id: windows-coverage-godmode-theta-2026-05-12
title: Phase θ — Windows-coverage horizontal expansion (Wave 3, post-η continuation)
status: brief-only (kickoff scoped; first stream not yet dispatched)
opened: 2026-05-12
parent_campaign: windows-coverage-godmode-eta-2026-05-11 (archived in completed/)
research_fleet_outputs:
  - .planning/research-fleet/theta-scout1-oss-lib-survey.md
  - .planning/research-fleet/theta-scout2-persona-e-adversary.md
  - .planning/research-fleet/theta-scout3-competitive-parity.md
---

# Phase θ — Windows-coverage horizontal expansion

## Context

Phase η (windows-coverage-godmode-eta-2026-05-11) shipped **5 streams**
across 2 sessions / 31 commits / 212 tier-1 tests / 10 MCP tools / 6
WindowsFindingSource Literal values: η.A NTFS $MFT walker, η.B
scheduled-tasks walker, η.C LNK walker, η.D BYOVD LOLDrivers
fingerprinting, η.E PowerShell EID4104 annotation.

Phase θ picks the next horizontal expansion from the 8 deferred-to-θ
candidates left at η closure. A 3-scout research-fleet pre-pass was
dispatched 2026-05-12T00:55Z and converged within 4 minutes.

## Scout convergence

| # | Candidate | Scout 1 (OSS lib) | Scout 2 (Persona-E adversary) | Scout 3 (Competitive parity) | Convergence |
|---|---|---|---|---|---|
| 1 | WMI persistence (OBJECTS.DATA + INDEX.BTR) | MEDIUM/medium — python-cim archived 2024, vendor PyWMIPersistenceFinder ~200 LOC | **HIGH #1** | **HIGH #1** | **STRONG (2/3 #1)** — implementation flag |
| 2 | Boot chain (BCD + MBR/VBR + ESP `.efi`) | **HIGH #1 small** — BCD zero new dep (regipy already in pyproject) | HIGH #3 | **HIGH #2** | **STRONG (3/3 HIGH)** |
| 3 | Volatility 3 integration | DEFER (architectural — new top-level data type) | HIGH but defer to ι | LOW (out-of-lane) | **STRONG DEFER** |
| 4 | Shim .sdb | MEDIUM #3 — fork-and-vendor python-sdb (5y stale) | MEDIUM #4 | MEDIUM #3 (ship-or-defer-to-ι) | MEDIUM — solid 3rd if capacity |
| 5 | EFS DDF/DRF | MEDIUM — depends on dissect.ntfs raw-attr API | LOW-MEDIUM (PoC-only) | LOW | DEFER |
| 6 | EVT pre-Vista | MEDIUM #2 — libevt-python fresh, libyal pattern | LOW-MEDIUM (niche) | LOW (negligible) | DEFER (S1 outlier; niche audience) |
| 7 | ETL | LOW — etl-parser 6y stale | **HIGH #2** (2024-25 anti-forensic blind spot) | LOW (out-of-lane) | DEFER (S2 outlier; format complexity vs prevalence) |
| 8 | hibernate.sys | DEFER (architectural — paired w/ Volatility 3) | MEDIUM-HIGH (paired) | LOW | **STRONG DEFER (paired with #3)** |

## Convergent picks (θ ships)

### θ.A — BCD store walker (highest confidence)

- **Why first:** 3/3 scouts HIGH. Zero new dep (`regipy>=4.0,<5` is
  already in `backend/pyproject.toml` from η). BCD is REGF format
  (Microsoft Open Specs + libguestfs precedent), parseable by regipy
  out of the box.
- **Adversary lens:** T1542.003 bootkit-adjacent — BlackLotus,
  Bootkitty (Nov 2024 ESET), CosmicStrand, MoonBounce.
- **Competitive lens:** EZTools = no parser; CHIPSEC = UEFI-only;
  Volatility = memory-only. Wairz uniquely closes the OSS static-
  analysis gap for the BCD layer.
- **Shape (Rule #39 inner/outer/safe runner triplet):**
  - `backend/app/services/bcd_walker.py`:
    - `_do_bcd_walk(db, firmware_id) -> dict` (inner pure-logic)
    - `run_bcd_walk_background(firmware_id) -> None` (outer Rule #33 .a state machine)
    - `auto_bcd_walk_firmware_safe(firmware_id) -> None` (unpack hook)
  - `backend/app/models/windows_bcd_entries.py` (ORM + alembic migration)
  - `backend/app/services/jsonb_normalizers.py` (per Rule #35c)
  - `backend/app/ai/tools/windows_bcd.py` (~3 MCP tools — list, lookup, summarize)
  - Frontend `FindingSource` Literal extension via β.12b narrow-helper-Literal pattern (Rule #25 single-slice exception #2)
- **Detection focus (per Scout 2 #3 + Scout 3 #2):**
  - Unsigned bootloader hash in BCD entries
  - Unexpected `path` element (boot path overrides)
  - Suspicious `description` strings
  - Anomalous boot order / hidden entries
  - Test-signing flag (`{globalsettings} testsigning=Yes`)
- **Phase α.2.7 / β.4 / β.10 / η.D Rule #37 trust anchors apply** —
  cross-reference BCD-referenced bootloader hashes against the
  existing Authenticode chain + DBX revocation list.
- **Estimated effort:** 4-6 hours wall (single stream, Pattern P5
  per-piece direct-push, Rule #25 ~6-7 commits).
- **Phase end conditions:** see `## Phase end conditions` table below.

### θ.B — WMI persistence walker (high adversary value)

- **Why second:** Scout 2 + Scout 3 both #1 by adversary breadth +
  competitive gap. Scout 1 flags implementation discipline — vendor
  ~200 LOC PyWMIPersistenceFinder per Rule #36 no-execute, NOT the
  full python-cim archived dep.
- **Adversary lens:** T1546.003 — APT29, APT32, Turla, FIN7,
  ransomware affiliates. In every modern APT playbook.
- **Competitive lens:** EZTools = no parser; flare-wmi unmaintained
  since 2018; MCP-exposed cross-firmware aggregation
  (`lookup_wmi_persistence`) is a wairz-only capability.
- **Shape:**
  - `backend/app/services/wmi_walker.py` — Rule #39 triplet over
    `OBJECTS.DATA` + `INDEX.BTR` + `MAPPING{1,2,3}.MAP` (vendor a
    keyword-search shape, not full repository parser).
  - `backend/third_party/pywmi_persistence_finder/` — vendored from
    David Pany's WMI_Forensics with Rule #37 attribution.
  - `backend/app/models/windows_wmi_events.py`.
  - `backend/app/ai/tools/windows_wmi.py` — ~3 MCP tools.
  - Detection: `__EventFilter` + `__EventConsumer`
    (`CommandLineEventConsumer` / `ActiveScriptEventConsumer`) +
    `__FilterToConsumerBinding` triples.
- **Estimated effort:** 6-8 hours wall (single stream + vendor-in
  scaffolding + Rule #36 no-execute test gate).
- **Vendor-in discipline:** Rule #36 — files extracted from
  OBJECTS.DATA via WMI parser must NEVER be passed to a process-spawn
  primitive. `ActiveScriptEventConsumer` ScriptText surfaces as
  finding `details`, not executed via `wscript`/`cscript`. Test gate
  per α.2.x precedent.

### θ.C — ESP `.efi` PE chain correlation (small wiring)

- **Why third:** Scout 1 — most of this is wiring on existing
  primitives. `signify>=0.7` + `pefile` already validate Authenticode
  for arbitrary PE. `tools/uefi.py` already enumerates UEFI volumes.
  This stream wires the boot-chain glue: walk ESP, validate every
  `.efi` against signify+DBX, flag unsigned/expired/revoked.
- **Adversary lens (Scout 2 #3 + Scout 3 #2 boot chain):** Same as
  θ.A — BlackLotus, MoonBounce, CosmicStrand, Bootkitty.
- **Shape:**
  - `backend/app/services/esp_walker.py` — Rule #39 triplet over the
    EFI System Partition (FAT32). Locate via dissect-style partition
    walk; for each `.efi` PE32+ file: signify Authenticode validate,
    DBX revocation check, cross-reference β.4/β.10 trust anchors.
  - `backend/app/models/windows_esp_entries.py`.
  - `backend/app/ai/tools/windows_esp.py` — ~2 MCP tools (list,
    summarize-chain).
- **Estimated effort:** 2-4 hours wall — mostly wiring. Most of the
  parsing primitives are already shipped; θ.C is the integration.

## Optional streams (capacity-dependent)

### θ.D — Shim .sdb walker (T1546.011)

- All 3 scouts MEDIUM. Solid 3rd-or-4th pick if Phase θ has
  capacity. Fork-and-vendor python-sdb (5y stale, no PyPI tag) per
  Rule #36 no-execute discipline. ~5-7 hours wall.
- **Defer rule:** if θ.A + θ.B + θ.C cumulative wall time approaches
  16 hours, ship Shim .sdb in Phase ι instead.

### θ.E — MBR/VBR boot-sector walker

- Scout 1 sub-candidate (b) — small. Pair with θ.A BCD work for a
  "complete boot-chain" trifecta with θ.C ESP. Vendor (or 100-LOC
  inline) MBR parser; reference ANSSI bootcode_parser signatures (5y
  stale but format-stable). ~2-3 hours wall.
- **Defer rule:** ship after θ.C if capacity allows; else Phase ι.

## Deferred to Phase ι (next campaign letter)

- **Volatility 3 + hibernate.sys (paired)** — architectural
  prerequisite (memory-dump upload as new top-level data type).
  Scout 2 honourable mention: "would rank above #2 and #3 if paired,
  but the engineering scope exceeds the other six candidates
  combined." Its own campaign.
- **EFS DDF/DRF** — needs `dissect.ntfs` raw-attribute API
  verification first; rare in firmware uploads; partial-implementation
  (parse-but-no-decrypt) is forensically weak.
- **EVT pre-Vista** — clean implementation per Scout 1 but niche
  audience (XP-embedded medical/ICS only). Scout 2/3 both defer.
- **ETL** — Scout 2 sees real adversary value (2024-25 surviving-
  cleanup blind spot), but Scout 1 (6y-stale upstream + partial
  format coverage) and Scout 3 (out-of-firmware-lane) outvote. Revisit
  in Phase ι if a fresh maintained ETL parser emerges.

## Decision Log

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | 3-scout research-fleet pre-pass (OSS / persona-E / competitive) | Same shape as η; convergent ranking across 3 lenses gives higher-confidence pick than single-lens | All 3 scouts returned in ~4 minutes wall; convergence on BCD (3/3) and WMI (2/3 #1) clean |
| 2 | θ ships 3 core streams (θ.A BCD + θ.B WMI + θ.C ESP); 2 optional (θ.D SDB + θ.E MBR/VBR); 5 deferred to ι | Pattern P5 per-piece direct-push works best on convergent picks; η pattern was 5 streams horizontal; θ shrinks to 3 core because Volatility/hiberfil architectural-prereq pair dominates the rest of the deferred list | 3-core / 2-optional / 5-deferred shape matches scout convergence cleanly |
| 3 | θ.A FIRST (not WMI) despite WMI's #1 adversary lens | BCD has zero new dep (regipy already in tree) and SMALLEST complexity; lowest-risk first stream per Pattern P5 best-practice — start with the most reproducible build | θ.A is the kickoff stream for the next session |
| 4 | WMI walker is a vendor-in (~200 LOC PyWMIPersistenceFinder), NOT a full python-cim adoption | python-cim archived 2024; format is bounded to keyword-search persistence detection (T1546.003); a 200-LOC vendor under Rule #36 no-execute discipline is right-sized | θ.B uses a custom-sized vendor shape, not a heavy dep |
| 5 | Defer Volatility 3 + hibernate.sys as a paired Phase ι campaign | Both share the same architectural prerequisite (memory-dump upload as new data type — new model, router family, MCP category, ~5-10 streams); pairing in ι gives a focused campaign vs. half-shipped in θ | Volatility + hibernate flagged for ι kickoff scope |
| 6 | Per-piece direct-push to main (Pattern P5), Trust=trusted | Same as η; Rule #41 must-complete CI mitigations healthy (per-commit lint + nightly backend-tests cron with empirical validation 2026-05-13 06:00 UTC pending) | Direct-push authorized for θ; no worktree-merge step |

## Phase end conditions

| Phase | Condition Type | Condition |
|---|---|---|
| θ.A | command_passes | `( cd backend && uv run pytest tests/test_bcd_walker.py tests/test_bcd_models.py -v )` exits 0 |
| θ.A | metric_threshold | MCP tool count ≥ 239 (was 236 post-η; +3 for `windows_bcd` category) |
| θ.A | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| θ.A | file_exists | `backend/app/services/bcd_walker.py` |
| θ.A | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase θ.A' \| wc -l` ≥ 5 |
| θ.B | command_passes | `( cd backend && uv run pytest tests/test_wmi_walker.py tests/test_wmi_models.py -v )` exits 0 |
| θ.B | metric_threshold | MCP tool count ≥ 242 (after θ.A + θ.B cumulative; +6 from η baseline) |
| θ.B | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| θ.B | file_exists | `backend/app/services/wmi_walker.py` AND `backend/third_party/pywmi_persistence_finder/__init__.py` |
| θ.B | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase θ.B' \| wc -l` ≥ 6 |
| θ.C | command_passes | `( cd backend && uv run pytest tests/test_esp_walker.py tests/test_esp_models.py -v )` exits 0 |
| θ.C | metric_threshold | MCP tool count ≥ 244 (after θ.A + θ.B + θ.C cumulative; +8 from η baseline) |
| θ.C | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| θ.C | file_exists | `backend/app/services/esp_walker.py` |
| θ.C | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase θ.C' \| wc -l` ≥ 4 |

## Operating Rules (durable across θ)

Same set as η:

- **Rule #38** absolute paths (`git -C /home/dustin/code/wairz` + subshell-scoped `( cd backend && ... )`).
- **Rule #35a** exit-code-before-pipe (`cmd; ec=$?` BEFORE any pipe).
- **Rule #25** per-piece commits + single-slice exception #2 cross-stack alignment (Rule-of-Thirteen post-η.D.D; θ.A applications take it to Rule-of-Fourteen et seq).
- **Rule #39** inner/outer/safe runner triplet (Rule-of-Eight post-η.A.C; θ.A is Rule-of-Nine).
- **Rule #41** must-complete CI mitigation (lint per-commit + backend-tests nightly cron) — first empirical cron run 2026-05-13 06:00 UTC pending; verify per `.mex/patterns/rule-41-must-complete-ci.md` after that.
- **Rule #43** per-line noqa rationale with 4 categories (em-dash format).
- **Rule #37** offline-trust-anchor for any new bundled artifact (β.4 signify + β.10 dbxupdate.bin + η.D loldrivers.json are precedents; θ may NOT require new anchors — verify per-stream).
- **Antipatterns A6 / A8 / A9 / A10** as documented in η postmortem.
- **Pattern P5** per-piece direct-push to main.

## Kickoff sequence (next session)

1. **Cron empirical (Item #1 from η closeout):** If 2026-05-13 06:00 UTC has passed, run `gh run list --workflow=backend-tests.yml --limit 10 --json event,conclusion,createdAt,headSha | jq '.[] | select(.event=="schedule")'` and update `.mex/patterns/rule-41-must-complete-ci.md` per the empirical-validation-status section. ~60 seconds.
2. **θ.A BCD walker kickoff** — single-sub-agent-per-stream dispatch with Pattern P5 per-piece direct-push. The validated η.A NTFS-MFT walker is the closest precedent: same dep-set (dissect.ntfs + regipy), same Rule #39 triplet, same JSONB-normaliser pattern, same MCP-tool category shape, same DB CHECK constraint extension.
3. After θ.A merges (or via the same agent in continuation): θ.B WMI walker (depends on θ.A being green to avoid alembic ID collisions per A10).
4. After θ.B: θ.C ESP `.efi` correlation (smallest stream; mostly wiring).
5. Optional θ.D Shim .sdb + θ.E MBR/VBR if session capacity allows.
6. End-of-campaign: postmortem + patterns/antipatterns extraction.

## References

- **Parent campaign:** `.planning/campaigns/completed/windows-coverage-godmode-eta-2026-05-11.md`
- **Scout outputs:**
  - `.planning/research-fleet/theta-scout1-oss-lib-survey.md`
  - `.planning/research-fleet/theta-scout2-persona-e-adversary.md`
  - `.planning/research-fleet/theta-scout3-competitive-parity.md`
- **Patterns referenced:** `.mex/patterns/inner-outer-safe-runner.md` (Rule #39), `.mex/patterns/add-alembic-migration.md`, `.mex/patterns/rule-41-must-complete-ci.md`, `.mex/patterns/add-jsonb-column.md`, `.mex/patterns/add-mcp-tool.md`, `.mex/patterns/add-router-test.md`.
- **CLAUDE.md rules driving design:** #25, #29.a (Rule #33.a state machine), #35c (JSONB normalisers), #36 (no-execute), #37 (offline-trust-anchor), #38 (absolute paths), #39 (runner triplet), #41 (must-complete CI), #43 (noqa rationale).
