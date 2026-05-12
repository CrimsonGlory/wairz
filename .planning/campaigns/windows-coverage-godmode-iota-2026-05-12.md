---
campaign_id: windows-coverage-godmode-iota-2026-05-12
title: Phase ι — coverage god-mode cross-platform expansion (Linux launch + Windows finishing)
status: brief-only (kickoff scoped; first stream not yet dispatched)
opened: 2026-05-12
parent_campaign: windows-coverage-godmode-theta-2026-05-12 (archived in completed/)
research_fleet_outputs:
  - .planning/research-fleet/iota-scout1-oss-lib-survey.md
  - .planning/research-fleet/iota-scout2-persona-e-adversary.md
  - .planning/research-fleet/iota-scout3-competitive-parity.md
scope_evolution: |
  ι is the FIRST CROSS-PLATFORM coverage campaign — Scouts 2 + 3 both
  converge HIGH on Linux journald + systemd persistence as the top
  pick, breaking the Windows-only η + θ pattern. The campaign filename
  retains the "windows-coverage-godmode" prefix for series continuity
  but the scope evolves to "wairz cross-platform forensic coverage."
---

# Phase ι — coverage god-mode cross-platform expansion

## Context

Phase η (`windows-coverage-godmode-eta-2026-05-11`, completed) shipped
**5 streams** across 2 sessions / 31 commits / 212 tier-1 tests / 10
MCP tools / 6 WindowsFindingSource Literal values: η.A NTFS $MFT
walker, η.B scheduled-tasks walker, η.C LNK walker, η.D BYOVD
LOLDrivers fingerprinting, η.E PowerShell EID4104 annotation.

Phase θ (`windows-coverage-godmode-theta-2026-05-12`, completed) shipped
**5 streams** in 1 session — **matching η's count in HALF the wall
time** — across 33 phase commits / ~464 tier-1 tests / 16 MCP tools /
8 WindowsFindingSource Literal values / 15 alembic revisions: θ.A BCD
store, θ.B WMI persistence, θ.C ESP `.efi` chain, θ.E MBR/VBR sectors,
θ.D Shim .sdb. **Boot-chain trifecta** (BCD + ESP + MBR/VBR + SDB)
operational; cross-firmware fingerprint MCP tools wired for all four
boot artefacts.

**Baseline at ι kickoff (HEAD 6fd7692):**
- alembic head: `cd1e2f3a4b5c`
- MCP tool count: 252 (η+θ joint baseline)
- WindowsFindingSource Literal: 27 values; `_SOURCE_*` constants: 30
- Rule #39 walker triplet: Rule-of-Thirteen (campaign-progression)
- Rule #25 cross-stack alignment: Rule-of-Eighteen (campaign-progression)
- Rule #37 offline-trust-anchor worked examples: 3 (β.4 signify + β.10 dbx + η.D loldrivers)
- 56 custom quality rules in `.claude/harness.json`
- wairz license: **AGPL-3.0-or-later** (confirmed in `backend/pyproject.toml`) — `dissect.*` family (AGPL) is the natural license-aligned choice.

Phase ι picks the next horizontal expansion from the 5 deferred-from-θ
candidates plus adjacency picks surfaced by the research-fleet pre-pass
dispatched 2026-05-12T14:01Z (3 parallel scouts, ~4.7 min agent-wall
each, converged within 16 min wall total).

## Scout convergence

| # | Candidate | Scout 1 (OSS lib) | Scout 2 (Persona-E adversary) | Scout 3 (Competitive parity) | Convergence |
|---|---|---|---|---|---|
| 1 | Volatility 3 + hibernate.sys PAIRED | DEFER (5-6 stream multi-session campaign of its own) | **HIGH #1** (all 4 adversary tiers) | DEFER (**MemProcFS already ships MCP** — eliminates wairz's differentiation wedge) | **2/3 DEFER** |
| 2 | EFS DDF/DRF | **MEDIUM SHIP #2** (`dissect.ntfs` API verified via `mft_walker.py:256` — `LOGGED_UTILITY_STREAM` 0x100 exposed) | DEFER (SafeBreach 2020 PoC still the headline 6y later; not in 2024-26 Akamai/Dragos top-N TTPs) | **MEDIUM-LOW SHIP #2** (NTFSTool is closest competitor, CLI-only, no LLM integration) | **2/3 SHIP** |
| 3 | EVT pre-Vista | LOW filler (libevt-python fresh, libyal pattern) | DEFER (niche; FrostyGoop uses Modbus, not legacy event logs) | DEFER (**LOW #4** in synthesis; XP-embedded ICS only) | **3/3 DEFER** |
| 4 | ETL | **MEDIUM-HIGH SHIP #1** — **DRAMATIC REVERSAL** from θ. New finding: `dissect.etl` (Fox-IT, AGPL-3.0, v3.14 released 2025-11-20) is the maintained OSS pick θ Scout 1 didn't find | **HIGH SHIP #2** — FortiGuard case: `AutoLogger-Diagtrack-Listener.etl` retained kernel process-trace evidence AFTER adversary cleared EVTX | DEFER (audience-lane mismatch; offline ETL in firmware is rare) | **2/3 SHIP** (Scout 3 contrary on audience, not library readiness) |
| 5 | Linux journald + systemd persistence | κ recommendation (NOT ι top-3) — Kaitai parser ready, but Scout 1 ranks ι by single-lib readiness, not strategic value | **HIGH SHIP #3** (APT36 Transparent Tribe Aug 2025, FIRESTARTER CISA/NCSC 2026, Quasar Linux QLNX May 2026 — 7 persistence mechanisms) | **HIGH SHIP #1** ("must-have for credibility"; wairz's dominant audience is Linux firmware; η+θ accidentally created a Linux-coverage debt) | **2/3 SHIP #1 strategic** |
| 6 | Container runtime (runc + OCI + Docker layers) | (not in top picks) | HM for κ (4 critical 2025 CVEs; adversary persona narrower than #5) | **MEDIUM SHIP #3** (Trivy/Syft/Grype focus on CVE+SBOM, not provenance + cross-firmware aggregation) | **1/3 SHIP** (Scout 2 says defer-to-κ; Scout 3 says ship; Scout 1 silent) |
| 7 | WMI dissect.cim refactor (Rule #27) | MEDIUM honourable mention (Fox-IT `dissect.cim` replaces archived Mandiant python-cim) | — | — | **1/3 HM** (refactor candidate, not new walker) |
| 8 | macOS (FSEvents, plists, TCC, kext) | REJECTED out of scope per README | (covered in adjacency search) | (not in top) | **3/3 DEFER** (out of wairz audience) |

## Cross-lens disagreement (worth surfacing)

Three significant disagreements emerged:

**1. Volatility 3 + hibernate.sys** — Scout 2 says HIGH #1, Scouts 1 +
3 say DEFER. Scout 3's MemProcFS MCP finding is decisive:
[`skywork.ai`](https://skywork.ai/skypage/en/unlocking-system-internals-memprocfs-mcp-server/1980472180219695104)
documents Ulf Frisk's MemProcFS shipping an MCP server in 2026 —
**wairz's "first OSS memory-forensic tool with MCP" wedge is gone**.
Combined with Scout 1's "architectural prerequisite is a 5-6 stream
multi-session campaign of its own" — defer to κ or later, revisit
after MemProcFS adoption is observed.

**2. ETL** — Scouts 1 + 2 say SHIP, Scout 3 says DEFER. Scout 3's
"audience mismatch" reasoning is weakest of the three: ETL files DO
appear in Windows firmware images (`C:\Windows\System32\WDI\LogFiles\*.etl`,
`C:\Windows\System32\winevt\Logs\*.etl`), and Scout 2's FortiGuard
case demonstrates real adversary forensic value. Scout 1's `dissect.etl`
finding (NEW since θ — that scout had no good OSS option) makes the
integration newly cheap. **Ship as ι.C; track Scout 3's audience
concern post-stream by measuring how many firmware uploads contain
`.etl` files.**

**3. Linux journald + systemd** — Scout 1 says "κ not ι"; Scouts 2 + 3
say "ι top pick." Scout 1's reasoning is library-readiness ranking,
not strategic value (it confirms journald has a Kaitai parser —
Apache-2.0, pure-Python, parses offline). Scouts 2 + 3 weigh strategic
value (Scout 2: most diversified coverage uplift; Scout 3: "the η+θ
Windows-coverage trifecta accidentally inverted the audience map").
**Resolve in favour of Scouts 2 + 3 — ship as ι.A.**

## Convergent picks (ι ships)

### ι.A — Linux journald walker (highest strategic value)

- **Why first:** 2/3 scouts rank HIGH; specifically, Scout 3 rates
  "**must-have for credibility**" (wairz's dominant audience is Linux
  firmware — OpenWrt, DD-WRT, vendor IoT — analysed at ≥Windows rate;
  the η + θ Windows-focused stretch created a structural portfolio
  debt). Scout 2 rates HIGH adversary value (APT36, FIRESTARTER,
  Quasar Linux QLNX 2024-26). **First Linux walker in wairz —
  campaign-defining milestone.**
- **Adversary lens:** T1070.002 (Clear Linux/Mac System Logs), T1562.012
  (Disable or Modify Linux Audit System), T1547 (Boot or Logon
  Autostart — Linux variants), T1543.002 (Systemd Service).
- **Competitive lens:** Velociraptor `Linux.Forensics.Journal` artifact
  is the closest OSS competitor (live-query shape, not offline-image-from-firmware
  triage). Plaso has a journald parser. EZTools is Windows-only.
  **wairz uniquely offers static-firmware-image MCP-callable
  cross-firmware aggregation for Linux persistence stack.**
- **OSS library:** `dissect.journal` (Fox-IT, AGPL-3.0) IF available
  AND maintained — verify per-stream via `pip show dissect-journal`
  during sub-task A.A. Fallback: Kaitai-generated parser (Apache-2.0,
  pure-Python) per Scout 1's recommendation. Tertiary fallback:
  vendor-in from `systemd-journal-remote` C reference docs (clean-room
  per Pattern P3 if needed).
- **Shape (Rule #39 inner/outer/safe runner triplet + Rule #16
  detection-roots adapted for Linux firmware):**
  - `backend/app/services/journald_walker.py`:
    - `_do_journald_walk(db, firmware_id) -> dict` (inner pure-logic)
    - `run_journald_walk_background(firmware_id) -> None` (outer Rule #33 .a state machine)
    - `auto_journald_walk_firmware_safe(firmware_id) -> None` (unpack hook)
  - `backend/app/models/linux_journald_entries.py` (ORM + alembic migration)
  - `backend/app/services/jsonb_normalizers.py` (per Rule #35c)
  - `backend/app/ai/tools/linux_journald.py` (~3 MCP tools: `list_journald_entries`,
    `lookup_journald_entry`, `search_journald_messages`, plus
    `trigger_journald_walk` + `journald_walk_status`)
- **New `LinuxFindingSource` Literal:** Introduce `LinuxFindingSource =
  Literal["linux_journald_log_clear", "linux_journald_kernel_anomaly",
  ...]` as a sibling of `WindowsFindingSource`. **Cross-stack
  alignment extension** (Rule #25 single-slice exception #2): DB CHECK
  `ck_findings_source` extension + frontend `FindingSource` union
  extension + `FINDING_SOURCE_CONFIG` extension all bundled in one
  commit per the established pattern (Rule-of-Eighteen → Rule-of-Nineteen).
- **Sub-task ladder (mirrors θ pattern, ~5 commits):**
  - **ι.A.A** — `LinuxJournaldEntry` ORM + alembic migration + jsonb normalisers
  - **ι.A.B** — 5-column 202+poll status set on `Firmware`
    (`journald_walk_status`, `journald_walk_started_at`,
    `journald_walk_finished_at`, `journald_walk_error`,
    `journald_walk_result`) per Rule #33 .a state machine + Rule #29 timeout discipline
  - **ι.A.C** — Rule #39 walker triplet (`journald_walker.py`) — inner/outer/safe
  - **ι.A.D** — `LinuxFindingSource` Literal + DB CHECK extension + FE union + FE config
    in **ONE COMMIT** per Rule #25 exception #2 (cross-stack alignment)
  - **ι.A.E** — `windows_journald` MCP tool category — at least 3 tools (`list`, `lookup`, `trigger` + `walk_status`)
- **Risk surface:**
  - **Detection-root semantics for Linux firmware.** `get_detection_roots(firmware)`
    handles scatter-zip + multi-archive at the helper level (Rule #16);
    Linux firmware (OpenWrt squashfs, DD-WRT ext2/3, vendor cramfs)
    is already supported by the unpacker. Validate by spot-check
    against a recent OpenWrt firmware upload (`SELECT id, project_id, extracted_path,
    device_metadata->'detection_roots' FROM firmware WHERE
    device_metadata->>'type' = 'linux' LIMIT 5;`) at sub-task A.C kick-off.
  - **journald binary log format stability.** Microsoft-doc-equivalent
    is upstream systemd-journal's `journal/journal-def.h` — stable
    since systemd v1.10 (2010). Format risk LOW.
  - **Rule #36 no-execute:** journald is a binary log; no execution
    primitive risk. Test gate: `test_journald_walker_no_execute`
    pattern (Rule-of-N propagation).
  - **Rule #37 trust-anchor:** N/A — no cert / DBX / vendor PEM
    bundle for journald. Worked examples remain at 3 (β.4 + β.10 + η.D).

### ι.B — systemd unit file persistence walker

- **Why second:** Pairs naturally with ι.A as the "Linux persistence
  stack" (Scout 2: "PAIRED — first Linux walker pair in wairz's
  Windows-heavy η+θ portfolio"). Where journald is the activity log,
  systemd unit files are the persistence vector — surface unit files
  with suspicious `ExecStart=`, `WantedBy=multi-user.target`, paths
  under `/tmp/*`, `/dev/shm/*`, etc.
- **Adversary lens:** T1543.002 (Systemd Service), T1547.013 (XDG
  Autostart Entries) when paired with desktop firmware. Real-world:
  APT36 (Aug 2025), HiatusRAT (2024), Quasar Linux QLNX (May 2026).
- **Competitive lens:** Velociraptor has artefact-level coverage
  (`Linux.Sys.Services`); Plaso has a parser. **wairz adds the
  cross-firmware fingerprint MCP tool** — `lookup_systemd_unit` over
  the firmware corpus to find the same unit name + ExecStart across
  multiple targets (supply-chain indicator).
- **OSS library:** Pure stdlib — `.service` / `.timer` / `.target`
  files are INI-format text. Python's `configparser` is sufficient.
  **Zero new dep.** Possibly augment with `defusedxml` (already in
  tree) for any malformed-XML edge cases (rare).
- **Shape:** Same Rule #39 triplet as ι.A.
- **Sub-task ladder:** ι.B.A through ι.B.E mirror ι.A's shape.

### ι.C — ETL via `dissect.etl`

- **Why third:** Scout 1's dramatic finding — `dissect.etl` (Fox-IT,
  AGPL-3.0, v3.14 released 2025-11-20) is fresh + maintained, directly
  sibling to `dissect.ntfs` already in wairz. Scout 2 ranks HIGH for
  adversary value (FortiGuard's `AutoLogger-Diagtrack-Listener.etl`
  case demonstrating kernel process-trace evidence retention POST-EVTX-clear).
- **Adversary lens:** T1070.001 (Clear Windows Event Logs — ETL is
  the "second-pass" log surface adversaries forget to clear),
  T1562.002 (Disable Windows Event Logging — ETW manifest providers).
- **Competitive lens:** Scout 3 says "audience mismatch" — verify
  post-stream by measuring `.etl` file prevalence in firmware uploads.
  If <5% of Windows firmware contains `.etl` files, Scout 3's
  audience concern is validated; if >20%, Scout 2's adversary case
  carries. Hypothesis to test.
- **OSS library:** `dissect.etl` — AGPL-3.0, pip-installable, Fox-IT
  maintained, py3-none-any. Same Linux/wairz fit as `dissect.ntfs`.
  License is AGPL-3.0 == wairz AGPL-3.0 — full compatibility.
- **Shape:** Same Rule #39 triplet pattern.
- **Sub-task ladder:** ι.C.A through ι.C.E mirror θ.A shape.
- **Rule #19 evidence-first probe:** before ι.C.A dispatch, `pip install
  dissect.etl && python -c "from dissect.etl.etl import ETL; print(ETL.__doc__)"`
  to verify the public API surface; catch any yield-shape surprises
  before the walker stream starts (η.A precedent).

### ι.D — EFS DDF/DRF metadata walker (parse-only)

- **Why fourth:** 2/3 scouts ship (Scouts 1 + 3); Scout 2 says defer
  (PoC-only threat). Scout 1's API verification (`mft_walker.py:256`
  + `mft_walker.py:266` confirm dissect.ntfs exposes raw-attribute
  access for `LOGGED_UTILITY_STREAM` 0x100) makes the integration
  newly cheap. Scope: surface **who can decrypt** (DDF user list + DRF
  recovery agent list) — NEVER the FEK or plaintext (Rule #36
  no-execute discipline applies to decrypt primitives too).
- **Adversary lens:** T1486 (Data Encrypted for Impact — ransomware
  variant when used at scale); T1564.001 (Hide Artifacts: Hidden Files
  and Directories — insider variant).
- **Competitive lens:** EZTools has genuine $EFS gap (no parser);
  NTFSTool is closest free competitor (CLI-only, no LLM integration).
  **wairz adds MCP-callable cross-firmware aggregation** — find files
  encrypted-by-the-same-recovery-agent across multiple firmware images
  (insider-threat or supply-chain indicator).
- **OSS library:** `dissect.ntfs>=3.10` already in wairz (η.A baseline).
  Walker uses existing `_safe_attribute_value` helper to read raw
  `LOGGED_UTILITY_STREAM` attribute, then wairz-side `asn1crypto`
  parsing of the DDF/DRF blob structure (already in deps).
  **Zero new dep.**
- **Shape:** Same Rule #39 triplet. Walker extends η.A's NTFS-MFT
  pattern with attribute-specific filtering.
- **Sub-task ladder:** ι.D.A through ι.D.E mirror η.A's shape.

## Defer picks

### Volatility 3 + hibernate.sys PAIRED — STRONG DEFER (2/3)

- **Why deferred:** Scout 1: 5-6 stream multi-session campaign of its
  own (memory-dump as new top-level data type alongside Firmware; new
  model, new router family, new MCP category, new upload flow).
  Scout 3: **MemProcFS already ships MCP** (Ulf Frisk, 2026) —
  wairz's "first OSS memory-forensic tool with MCP" wedge is gone;
  defer until wairz can re-establish a differentiation angle (e.g.
  Vol3 + hibernate + cross-firmware-correlated artefacts, where the
  cross-correlation is the wedge).
- **What changes the calculus:** revisit at κ or later if (a) MemProcFS
  MCP adoption stalls (unlikely; it's already shipped), (b) wairz
  identifies a differentiation angle beyond raw MCP-on-memory (e.g.
  Vol3 plugin orchestration coupled to wairz's existing artefact
  surfaces — "find memory-resident decryptor for the BCD-anomaly
  bootkit detected in firmware X"), or (c) a higher-priority pick
  in κ deferral list exhausts.

### Container runtime forensics (runc + OCI + Docker layers) — DEFER to κ

- **Why deferred:** Scout 2 explicitly classes as κ candidate
  ("adversary persona currently narrower than option A"); Scout 3
  ranks #3 ship but with "modest engineering cost" caveat; Scout 1
  silent. 4 critical 2025 CVEs (3 runc + Docker CVE-2025-9074) make
  this a rising trend, but persona breadth is narrower than ι.A Linux
  mirror. Carry into κ.

### EVT pre-Vista — 3/3 DEFER

- **Why deferred:** Niche audience (legacy XP/Server 2003 firmware
  only). All three scouts agree LOW priority. Could ship as
  guaranteed-clean filler if session capacity surplus emerges, but
  not in the top-3 prioritisation.

### macOS coverage — out of wairz scope

- **Why deferred:** README explicitly scopes wairz to Linux + Windows
  firmware. Adding macOS coverage requires expanding the README
  product definition first. Not a Phase ι concern.

## Recommended Phase ι execution sequence

Per Pattern P1 Rule-of-Five floor (~25-35 min agent-wall per stream;
CI-bounded by lint must-complete cadence per Rule #41 mechanism a),
the validated single-session capacity is **4-5 streams**. Plan:

| Order | Stream | Convergence | Risk | Estimated agent-wall |
|---|---|---|---|---:|
| 1 | **ι.A — Linux journald walker** | Strongest (2/3 SHIP, Scout 3 "must-have for credibility") | First Linux walker — detection-root spot-check needed at sub-task A.C | ~40 min (first-stream precedent set) |
| 2 | **ι.B — systemd unit file persistence walker** | Pairs with ι.A | Lower (zero new dep, INI text format) | ~30 min |
| 3 | **ι.C — ETL via dissect.etl** | 2/3 SHIP (Scout 3 contrary on audience) | Library API verification gate (Rule #19) | ~30 min |
| 4 | **ι.D — EFS DDF/DRF metadata walker** | 2/3 SHIP | Reuses η.A NTFS shape; lowest novelty | ~25 min |
| 5 (if capacity) | ι.E — EVT pre-Vista filler OR auditd walker OR bash_history/cron triplet | — | — | ~20-30 min |

**Total estimated agent-wall:** ~125-155 min (4 streams) to ~155-185
min (5 streams). At Pattern P1's ~25-30 min floor compounding from
stream 1, the actual wall time will likely run slightly below
estimate per Antipattern A6 inversion (estimates DISCOUNTED 50-75%
apply to brief-as-written; actual cadence often beats brief).

**Pattern P1 re-verification:** First ι stream (ι.A) will extend the
Rule-of-Five chain to Rule-of-Six (η.A → θ.A precedent chain + ι.A
new application). Document in ι.A postmortem.

## Operating rules for ι

Inherits from η + θ (CLAUDE.md authoritative):

- **Rule #16 detection-roots** — `get_detection_roots(firmware)` for any walker filesystem traversal
- **Rule #25 single-slice exception #2 cross-stack alignment** — DB CHECK + FE union + FE config in ONE commit
- **Rule #29 timeout discipline** — frontend axios + backend `wait_for` paired with explicit timeouts
- **Rule #33 .a state machine** — `idle → queued → running → completed | failed` for any 202+poll walker
- **Rule #35c jsonb_normalizers** — per JSONB column boundary normaliser + schema_version stamp (≥3 consumers)
- **Rule #36 no-execute** — no spawn primitive on extracted artefacts; test gate per walker
- **Rule #37 offline-trust-anchor** — IF a stream needs a new anchor (Vol3 ISF would, none of the ι top-4 do)
- **Rule #38 absolute paths** — `git -C /home/dustin/code/wairz` + subshell-scoped `( cd backend && ... )`
- **Rule #39 inner/outer/safe runner triplet** — every walker stream; chain extends to Rule-of-Fourteen at ι.A
- **Rule #41 must-complete CI** — mechanism (a) lint per-commit sibling + mechanism (b) nightly backend-tests cron; validated this session
- **Rule #43 per-line noqa rationale** — 4 categories with em-dash format

**Patterns durable:**

- **Pattern P1 single-sub-agent + precedent reuse** — Rule-of-Five extending to Rule-of-Six at ι.A
- **Pattern P3 vendor-in decision tree** — verbatim fork vs clean-room; apply if ι stream needs new vendor (none expected in ι.A-D)
- **Pattern P5 per-piece direct-push to main** — Trust=trusted; concurrency-cancel-aware
- **Pattern P7 trust-but-verify orchestrator gate** — ~7 verification commands per sub-agent return

**Antipatterns to remember:**

- A1 verify CI claims independently — don't trust the brief's "CI green" without `gh run list`
- A3 run `date -u` at session-open — brief dates drift between sessions
- A4 trust `duration_ms` not self-reported wall — sub-agent self-reports inflate
- A6 discount brief estimates 50-75% for streams 2+ — Pattern P1 compounding makes actual cadence faster than written

## Risks + open questions

1. **First Linux walker (ι.A) detection-root semantics.** Verify
   `get_detection_roots(firmware)` returns sensible paths for Linux
   firmware (OpenWrt squashfs, DD-WRT ext2/3, vendor cramfs) BEFORE
   dispatching ι.A.C inner-runner work. Spot-check via DB query at
   ι.A.A kick-off.

2. **`dissect.journal` availability.** Verify `pip show dissect-journal`
   before ι.A.A dispatch. If unavailable, fall back to Kaitai-generated
   parser (Scout 1's secondary recommendation) — pure-Python, Apache-2.0,
   parses offline.

3. **Scout 3's audience-mismatch concern for ETL (ι.C).** Hypothesis to
   test post-stream: measure `.etl` file prevalence in firmware uploads.
   `SELECT COUNT(*) FROM firmware WHERE device_metadata->'detection_roots'
   IS NOT NULL` paired with `find <root> -name '*.etl' | wc -l`
   sampling. If <5%, Scout 3's concern validated and ι.C value is
   bounded; if >20%, ship as scoped.

4. **Vol3 deferral revisit timing.** Track MemProcFS MCP adoption +
   wairz's differentiation angle reassessment in κ planning. Don't
   "drop" Vol3 — defer with a re-evaluation trigger.

5. **LinuxFindingSource Literal naming.** Introduces a new
   parallel-to-WindowsFindingSource type. Verify the FE `FindingSource`
   union accepts both Windows + Linux sources without breaking the
   pairwise-agreement test in `test_finding_source_alignment.py` —
   the test currently only enforces WindowsFindingSource alignment;
   extend the test to also enforce LinuxFindingSource at ι.A.D.

6. **OPERATOR-DIFF carryover.** `.planning/intake/local-dev-env-no-auth-2026-05-12-OPERATOR-DIFF.md`
   is durability-only — runtime already healthy (backend 13h uptime,
   RestartCount=0, `API_KEY=...` set in `.env`). Not blocking any ι
   work.

## Sources

Research-fleet outputs (full text in `.planning/research-fleet/`):
- [iota-scout1-oss-lib-survey.md](../research-fleet/iota-scout1-oss-lib-survey.md) (3678 words; ETL dramatic reversal, EFS API verified)
- [iota-scout2-persona-e-adversary.md](../research-fleet/iota-scout2-persona-e-adversary.md) (4152 words, 88 source URLs; APT36/FIRESTARTER/Quasar Linux QLNX evidence)
- [iota-scout3-competitive-parity.md](../research-fleet/iota-scout3-competitive-parity.md) (4650 words, 44 source URLs; MemProcFS-MCP-already-shipping erodes Vol3 wedge)

External:
- [`dissect.etl` (Fox-IT, AGPL-3.0)](https://github.com/fox-it/dissect.etl) — ETL Scout 1 reversal
- [`dissect.cim` (Fox-IT)](https://github.com/fox-it/dissect.cim) — WMI refactor adjacency
- [Volatility 3 (VSL, py3-none-any wheel)](https://github.com/volatilityfoundation/volatility3) — deferred
- [MemProcFS MCP Server](https://skywork.ai/skypage/en/unlocking-system-internals-memprocfs-mcp-server/1980472180219695104) — Vol3 wedge erosion evidence
- [Velociraptor Linux.Forensics.Journal](https://docs.velociraptor.app/artifact_references/pages/linux.forensics.journal/) — Linux competitive baseline
- [Hunting for Persistence in Linux (Pberba)](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/) — Linux walker scoping reference
- [Elastic Security Labs persistence primer](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) — Linux persistence taxonomy
- [JPCERTCC/Windows-Symbol-Tables](https://github.com/JPCERTCC/Windows-Symbol-Tables) — Vol3 ISF bundle (deferred trust-anchor source for κ)
