---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
title: Phase κ — coverage god-mode adjacency batch (Rule #44 backfill + Linux persistence + DPAPI + UsnJrnl)
status: brief-only (kickoff scoped; first stream not yet dispatched)
opened: 2026-05-12
parent_campaign: windows-coverage-godmode-iota-2026-05-12 (archived in completed/)
research_fleet_outputs:
  - .planning/research-fleet/kappa-scout1-vol3-competitive-correction.md
  - .planning/research-fleet/kappa-scout2-adjacency-portfolio.md
  - .planning/research-fleet/kappa-scout3-vol3-architectural-cost.md
scope_evolution: |
  κ is a SINGLE-SESSION ADJACENCY BATCH that consolidates ι's deferred
  cross-firmware backfill candidate (journald) with 4 new coverage picks
  surfaced by κ Scout 2's portfolio audit. Vol3 (memory forensics) is
  deferred to a SEPARATE multi-session campaign codenamed λ /
  "memory-forensic-godmode-α" — Scout 1 corrected the iota brief's
  premature Vol3 defer (MemProcFS does NOT have MCP; the wedge is open)
  and Scout 3 quantified Vol3 as 8 streams across 2-3 sessions, which
  doesn't fit the single-session capacity κ is sized for.

  The campaign filename retains the "windows-coverage-godmode" prefix for
  series continuity. κ is the 10th Greek-letter campaign and the second
  cross-platform expansion (after ι Linux launch).
---

# Phase κ — coverage god-mode adjacency batch

## Context

Phase ι (`windows-coverage-godmode-iota-2026-05-12`, completed) shipped **5 streams in
1 day** across 39 commits / 2 mid-campaign cleanups / full campaign postmortem /
`/citadel:learn` extraction / session-close: ι.A Linux journald walker, ι.B Linux
systemd persistence, ι.C Windows ETL via `dissect.etl`, ι.D Windows EFS DDF/DRF
parse-only metadata walker, ι.E Linux container runtime artefacts.

**ι deferred:** journald cross-firmware aggregation MCP tool (HANDOFF item #2 — ι.A.E
shipped per-firmware only; 4 of 5 ι walkers caught the Rule #44 pattern but ι.A
preceded the pattern's codification).

**Baseline at κ kickoff (HEAD 44a86b9):**
- alembic head: `aabbccddee0c` (ι.E.D extend_findings_source_linux_container)
- MCP tool count: 281 (η+θ+ι joint baseline)
- WindowsFindingSource Literal: 38 values (κ scout verification — brief said 35; 38 is canonical from `app/schemas/finding.py`)
- LinuxFindingSource Literal: 15 values (NEW family from ι)
- Rule #39 walker triplet: Rule-of-Nineteen (ζ.2.B + ζ.3.B confirmed; ι extends further)
- Rule #25 cross-stack alignment: Rule-of-Twenty-Three (ι close codified)
- Rule #37 offline-trust-anchor worked examples: 3 (β.4 signify + β.10 dbx + η.D loldrivers)
- Rule #44 cross-firmware-aggregation: Rule-of-Four DURABLE (ι.B/C/D/E shipped; ι.A backfill = this campaign's κ.A)
- Rule #45 parse-only metadata walker: Rule-of-One (ι.D EFS); κ.D DPAPI matures to Rule-of-Two
- 56 custom quality rules in `.claude/harness.json`; session counter 189 (190 mid-session)
- wairz license: AGPL-3.0-or-later

## Scout convergence

| # | Question | Scout 1 (Vol3 competitive) | Scout 2 (Adjacency portfolio) | Scout 3 (Vol3 architectural cost) | Synthesis |
|---|---|---|---|---|---|
| 1 | Does Vol3 deserve κ slot? | **GO** — wedge open, diff 8/10, maintenance LOW | (out of scope — adjacency lens) | **NEEDS 2-3 SESSIONS, clean-fit** | **DEFER to λ multi-session**, but as separate campaign |
| 2 | Is the iota brief's MemProcFS-MCP-blocks-Vol3 claim true? | **NO — false positive**; MemProcFS v5.17 (Feb 2026) has no MCP. iota Scout 3 was misled by `skywork.ai` secondary source | — | — | **Correction lands; wedge is open** |
| 3 | Is the brief's 5-candidate adjacency slate optimal? | — | **NEAR-OPTIMAL, needs 2 swaps**: drop auditd + WMI refactor; add AppCompat/Shimcache + UsnJrnl | — | **Refined slate ships** |
| 4 | How many Rule #44 backfill targets remain? | — | **12 viable** across η/θ/ι walkers (journald + 11 others); each ~1 stream | — | journald (κ.A) is highest-priority (explicit deferral); 11 others queued for κ.X+1 |
| 5 | Vol3 data type shape? | — | — | **Subordinate to Firmware** (82 import sites for Firmware; parallel would cost 15-20 router parallels) | Recorded for λ kickoff |
| 6 | Vol3 plugin granularity? | — | — | **Per plugin-family** (windows_processes covers pslist/pstree/psscan/cmdline) | Recorded for λ kickoff |

## Cross-lens summary

All three scouts converge on the same κ shape: **adjacency batch this session, Vol3
as separate multi-session campaign**. Disagreements were minimal — Scout 2 swapped 2
of the brief's 5 candidates, but the swaps are LATERAL (still adjacency-pick shape,
not strategic-direction change). Scout 1's competitive correction REINFORCES the case
for doing Vol3 properly via λ with its own research-fleet pre-pass (rather than
opening Vol3 mid-session with insufficient prep).

The brief's option (c) hybrid lands EXACTLY as recommended, with Scout 2's slate refinement.

## Decision

**Option (c) hybrid, refined slate.** This session ships κ.A through κ.E (5 streams,
~2.5 h agent-wall on Pattern P1 single-sub-agent cadence). λ (memory-forensic-godmode-α)
opens in a future session with its own 3-scout research-fleet pre-pass (Vol3 library
probe + ISF download dry-run + plugin-API stability).

**Rule promotions expected in κ:**
- Rule #44 cross-firmware-aggregation: Rule-of-Four → Rule-of-Five (κ.A backfill)
- Rule #45 parse-only metadata walker: Rule-of-One → Rule-of-Two (κ.D DPAPI), promoting to **durable beyond debate**
- Pattern P1 single-sub-agent + precedent reuse: Rule-of-Ten → Rule-of-Fifteen (κ.A–E)

## Convergent picks (κ ships)

### κ.A — journald cross-firmware aggregation MCP tool

- **Why first:** Explicit ι.A.E deferral; matures Rule #44 to Rule-of-Five; smallest
  stream (~15-20 min); precedent reuse is exact (ι.B/C/D/E shipped the same shape).
- **Adversary lens:** T1070.002 (Clear Linux/Mac System Logs) — cross-firmware
  aggregation surfaces same log-clear marker across firmware corpus; supply-chain or
  threat-actor cohort indicator.
- **OSS library:** None new — uses existing `linux_journald.py` MCP tool category +
  existing `LinuxJournaldEntry` ORM.
- **Shape:** Single MCP tool addition `lookup_journald_entry_across_firmwares` in
  `backend/app/ai/tools/linux_journald.py`, mirroring ι.B/C/D/E shape.
- **Sub-task ladder:** Single commit (no Rule #25 single-slice triggered — no DB
  CHECK / frontend mirror change).

### κ.B — AppCompat/Shimcache walker

- **Why second:** regipy already in tree (no new dep); T1106 (Native API) +
  T1059.001 (PowerShell) execution-evidence (Shimcache = "what executed AND when");
  highest adversary value of N-candidates per Scout 2.
- **Adversary lens:** T1106 execution-evidence; T1070.005 (Indicator Removal: Network
  Share Connection Removal) defensive bypass — Shimcache survives executable deletion.
- **Competitive lens:** EZTools' AppCompatCacheParser is the closest competitor (CLI,
  no MCP). Plaso / Volatility have parsers. **wairz wedge: MCP-callable +
  cross-firmware aggregation from Day 1** (Rule #44 by default).
- **OSS library:** `regipy` (existing — used by γ.4 registry walker), parses SYSTEM
  hive `ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache` value.
- **Shape:** Full Rule #39 walker triplet + Rule #16 detection_roots integration +
  Rule #25 cross-stack alignment + Rule #44 cross-firmware aggregation built in from
  start (5 MCP tools: list + lookup + lookup_across_firmwares + status + trigger).
- **Sub-task ladder (mirrors ι sub-task shape, ~5 commits):**
  - **κ.B.A** — `WindowsAppCompatEntry` ORM + alembic migration + jsonb normalisers
  - **κ.B.B** — 5-column 202+poll status set on `Firmware` (`appcompat_walk_status`,
    `_started_at`, `_finished_at`, `_error`, `_result`)
  - **κ.B.C** — Rule #39 walker triplet (`appcompat_walker.py`)
  - **κ.B.D** — `WindowsFindingSource` Literal extension + DB CHECK + FE mirror +
    emit hook (`emit_appcompat_findings_from_walk`) — ONE commit (Rule #25 exception #2)
  - **κ.B.E** — `windows_appcompat` MCP tool category — 5 tools

### κ.C — Linux persistence triplet bundled (bash_history + crontab + ld.so.preload)

- **Why third:** Three text-format Linux persistence artefacts under ONE walker
  (Pattern P1 single-stream multi-artefact precedent — see γ.4 registry walking
  multiple hive types). Completes Linux persistence stack alongside ι.A journald +
  ι.B systemd.
- **Adversary lens:** T1059.004 (Unix Shell — bash_history), T1053.003 (Cron),
  T1574.006 (LD_PRELOAD). Real-world: Quasar Linux QLNX (May 2026), HiatusRAT (2024),
  FIRESTARTER CISA/NCSC 2026.
- **Competitive lens:** Velociraptor `Linux.Sys.BashLogins` + `Linux.Sys.Crontab`
  artefacts; chkrootkit detects some `ld.so.preload` hijacks. **wairz wedge: combined
  artefact view + cross-firmware aggregation** ("same ld.so.preload across N
  firmware → supply-chain cohort").
- **OSS library:** stdlib only — bash_history is plain text (newline-delimited),
  crontab is RFC-equivalent text format (with `@reboot`, `* * * * *` syntax),
  ld.so.preload is one-line-per-binary path list.
- **Shape:** Rule #39 walker triplet in `linux_persistence_walker.py` emitting to
  three sibling tables (`linux_bash_history_entries`, `linux_cron_jobs`,
  `linux_ld_preload_entries`) — multi-table emit per Scout 2's Pattern-P1
  multi-artefact precedent.
- **Sub-task ladder (~5-6 commits):**
  - **κ.C.A** — 3 ORM tables + 1 alembic migration (single migration for all 3 tables —
    same JSONB normaliser file shared)
  - **κ.C.B** — single 5-column 202+poll status set (`persistence_walk_*`)
  - **κ.C.C** — Rule #39 walker triplet (3 sub-parsers, single triplet shell)
  - **κ.C.D** — `LinuxFindingSource` Literal extension (3 sources:
    `linux_bash_history_clear`, `linux_cron_suspicious_command`,
    `linux_ld_preload_hijack`) + DB CHECK + FE mirror + emit hook — ONE commit
  - **κ.C.E** — `linux_persistence` MCP tool category — 5 tools (list per artefact +
    aggregate `lookup_persistence_across_firmwares`)

### κ.D — DPAPI master-key parse-only metadata walker

- **Why fourth:** Matures Rule #45 parse-only-metadata walker pattern from
  Rule-of-One (ι.D EFS) to **Rule-of-Two — DURABLE BEYOND DEBATE**. Directly mirrors
  ι.D shape (parse metadata only, NEVER decrypt). High adversary value: T1555.004
  (Credentials from Password Stores: Windows Credential Manager) + T1003 (OS
  Credential Dumping) reconnaissance.
- **Adversary lens:** T1555.004 (DPAPI Credential Manager), T1003 (OS Credential
  Dumping). Real-world: every Windows credential-theft TTP touches DPAPI master keys.
  Parse-only surfaces master-key METADATA (GUID, flags, creator SID, last-modified)
  without ever attempting decryption — Rule #36 no-execute + Rule #45 no-decrypt
  enforced via test gate (`test_dpapi_walker_no_decrypt`).
- **Competitive lens:** `impacket.dpapi` (live-decrypt CLI), `SharpDPAPI`
  (offensive). **wairz wedge: parse-only metadata + cross-firmware aggregation** —
  "same master-key GUID across N firmware → user-account-reused indicator."
- **OSS library:** stdlib `struct` parsing on the master-key file format (well-known
  shape; can clean-room from `SharpDPAPI` reference docs). Optionally
  `impacket.dpapi` METADATA-ONLY paths (FlagMasterKey blob parse without
  CryptUnprotectData call).
- **Shape:** Rule #39 walker triplet in `dpapi_walker.py`. PARSE-ONLY discipline
  enforced via `test_dpapi_walker_no_decrypt` (Rule #36 EXTENSION + Rule #45
  pattern): `tokenize`-based AST scan for forbidden tokens (`decrypt`, `DPAPI`
  decrypt entry-points, `CryptUnprotectData`, `cryptography.fernet`,
  `impacket.dpapi.MasterKey.decrypt`).
- **Sub-task ladder (~5 commits):**
  - **κ.D.A** — `WindowsDpapiMasterKey` ORM + alembic + jsonb normalisers
  - **κ.D.B** — 5-column `dpapi_walk_*` status set
  - **κ.D.C** — Rule #39 walker triplet (parse-only, with `test_dpapi_walker_no_decrypt` Rule #36 EXTENSION gate)
  - **κ.D.D** — `WindowsFindingSource` Literal extension (e.g.
    `windows_dpapi_orphaned_masterkey`, `windows_dpapi_admin_creator_sid`,
    `windows_dpapi_large_masterkey`) + DB CHECK + FE mirror + emit hook — ONE commit
  - **κ.D.E** — `windows_dpapi` MCP tool category — 5 tools

### κ.E — UsnJrnl $J change-log walker

- **Why fifth:** `dissect.ntfs` already in tree from η.A MFT walker (zero new dep);
  T1070.001 (Clear Windows Event Logs) anti-forensics analog at the filesystem layer
  — UsnJrnl $J retains file-change history adversaries often miss when cleaning
  filesystem traces; pairs naturally with MFT walker for "what changed AND when AND
  who" timeline reconstruction.
- **Adversary lens:** T1070.004 (File Deletion — adversary deletes a payload, but the
  $J change-log retains the create+delete pair with timestamps), T1070.001 supporting
  evidence at the filesystem layer.
- **Competitive lens:** EZTools' MFTECmd has UsnJrnl support (CLI). Plaso parses $J
  via `j_l_log` parser. **wairz wedge: MCP-callable + cross-firmware aggregation
  built-in.**
- **OSS library:** `dissect.ntfs` (existing) — `$Extend/$UsnJrnl:$J` ADS parsing via
  `dissect.ntfs.usnjrnl` module.
- **Shape:** Full Rule #39 triplet + Rule #44 cross-firmware aggregation by default.
- **Sub-task ladder (~5 commits):** Mirrors κ.B shape exactly.

## Rule promotions expected at κ close

| Rule | Pre-κ status | Post-κ status | Promoted by |
|---|---|---|---|
| #44 cross-firmware aggregation | Rule-of-Four DURABLE BEYOND DEBATE | Rule-of-Five (with explicit backfill demonstration) | κ.A journald backfill |
| #45 parse-only metadata walker | Rule-of-One | **Rule-of-Two — DURABLE** | κ.D DPAPI extends ι.D EFS shape |
| Pattern P1 single-sub-agent | Rule-of-Ten | Rule-of-Fifteen | κ.A–E |
| Pattern P5 per-piece direct-push | Trust=trusted (189 sessions) | Unchanged — continues | κ ships per-piece |
| Pattern P7 trust-but-verify | Rule-of-Six | Rule-of-Eleven (with κ.A–E as 5 new orchestrator gates) | Per-stream verification |

## Operating discipline (κ-specific)

- **All Antipatterns A7 + A8 enforcement in dispatch prompts.** Specifically: every
  sub-agent prompt MUST include `( cd backend && uv run ruff check --no-cache
  <changed-files> )` (A7) AND post-migration verification
  `docker compose exec backend /app/.venv/bin/alembic heads | grep <expected-id>` (A8).
- **Rule #36 + Rule #45 test gate for κ.D.** The DPAPI walker test gate scans the
  walker source via `tokenize` for forbidden decrypt tokens — verify the gate fires
  on a synthetic violation BEFORE trusting it (Rule #17 silent-CLI canary equivalent).
- **Per-piece commits per Rule #25.** Each .A/.B/.C/.D/.E commit is one Rule #25
  slice; .D is the Rule #25 exception #2 cross-stack alignment single-slice.
- **Rule #8 three-way rebuild after each walker stream's last commit** (ORM changes
  require backend+worker+migrator). Single rebuild per stream, not per commit.
- **Pattern P5 per-piece direct-push.** Each commit goes directly to origin/main.
  No PR overhead.

## End-of-campaign expectations

Per the session brief:
- Per-stream postmortem + patterns/antipatterns after EACH κ stream ships
  (`.planning/postmortems/postmortem-windows-coverage-godmode-kappa-<stream>-2026-05-12.md`)
- Full campaign postmortem after κ.E ships
  (`.planning/postmortems/postmortem-windows-coverage-godmode-kappa-2026-05-12.md`)
- `/citadel:learn` auto-runs after campaign postmortem
- `/citadel:session-handoff` at session close
- λ (memory-forensic-godmode-α Vol3) kickoff intake stub written at
  `.planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md` for next
  session

## Total estimated wall

- 5 streams × ~30 min agent-wall on Pattern P1 = ~2.5 h agent
- Per-stream verification gate (Pattern P7 ~7 commands × 5 streams) = ~15 min orchestrator
- Per-stream postmortems = ~30 min
- Campaign close (postmortem + learn + handoff + λ intake) = ~30 min

**Total: ~3.75 h orchestrator + agent wall.** Fits comfortably within a single-session
budget if dispatched sequentially with no parallelism (Pattern P1 discipline).
