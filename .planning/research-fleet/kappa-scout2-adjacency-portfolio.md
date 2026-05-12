---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
scout: 2
angle: adjacency-pick portfolio audit (validate/revise brief's 5 candidates + surface alternates)
opened: 2026-05-12
duration_ms: 144776
total_tokens: 126187
tool_uses: 32
---

# κ Scout 2 — Adjacency-pick portfolio audit

**Headline finding:** Brief's 5-candidate slate is **NEAR-OPTIMAL but needs one swap**.
Drop `auditd` (defer to a later Linux audit-trail campaign) and `WMI dissect.cim
refactor` (Rule #27 refactor, different work shape, breaks Pattern P1 cadence).
Substitute **AppCompat/Shimcache** (regipy already in-tree) and **UsnJrnl $J** (dissect.ntfs
already in-tree). Also surfaces **12 viable Rule #44 backfill candidates** across η/θ/ι.

---

## Brief candidates table

| # | Brief Candidate | Confirmed | Evidence | Streams |
|---|---|---|---|---|
| 1 | journald cross-firmware backfill | **Y** | `linux_journald.py` has 5 per-fw tools (`list/lookup/search/status/trigger`) but ZERO `*_across_firmwares` (explicitly deferred in ι postmortem HANDOFF #2; Rule #44 backfill). | **1** |
| 2 | auditd binary log walker | **Y** | No service/tool files exist for auditd; `auditd-tools` (PyPI 0.0.3) thin — clean-room over `audit-parse` format spec viable; Linux persistence-stack triplet partner (journald + systemd + auditd). | **1** |
| 3 | WMI `dissect.cim` refactor | **Y, but** | `wmi_walker.py` uses vendored PyWMIPersistenceFinder (`backend/third_party/pywmi_persistence_finder/`); `dissect.cim` v3.13 confirmed on PyPI (released 2024-04-11). Rule #27 refactor — DIFFERENT work shape (not new walker). Slower precedent reuse. | **1-2** |
| 4 | bash_history/cron/ld.so.preload triplet | **Y, but caveat** | Zero existing code (`grep -lE 'cron\|bash_history\|ld.so.preload' backend/` empty for walker-shape). Three text-format Linux persistence artefacts. Risk: text-format parsing is too cheap → may bundle into 1 stream as 3 sub-tasks vs 3 streams. | **1 (bundled)** |
| 5 | DPAPI master keys (Rule #45 parse-only metadata adjacent) | **Y** | Zero DPAPI code in tree (`grep -rln 'DPAPI' backend/` returns only EFS-walker references). Directly extends ι.D EFS DDF/DRF "parse-only metadata walker" Rule-of-One precedent; `dissect.cim` family has none for DPAPI but `impacket.dpapi` available. | **1** |

## Rule #44 backfill candidates

Mechanical grep confirmed: only ι.B/C/D/E walkers (4 of 17) have `lookup_*_across_firmwares`.
Backfill targets (each ~1 stream, ~15-25 min agent-wall on ι.B-E precedent):

- `linux_journald.py` (ι.A — explicit deferral, HANDOFF #2)
- `windows_event_log.py` (ε EVTX) — currently `search_events` is per-fw only
- `windows_mft.py` (η.A) — `search_mft_records` per-fw only
- `windows_lnk.py` (η.C) — `search_lnk_records` per-fw only
- `windows_scheduled_task.py` (η.B) — per-fw only
- `windows_prefetch.py` (ζ.2) — per-fw only
- `windows_srum.py` (ζ.3) — per-fw only
- `windows_registry.py` (γ.4) — per-fw only
- `windows_bcd.py / wmi.py / esp.py / mbr_vbr.py / sdb.py` (θ.A-E) — HAVE θ-era `lookup_<topic>` BUT name pattern shifted; could rename or already-fit
- `windows_efs.py` ALREADY has it (ι.D) — skip

**12 viable Rule #44 backfill candidates.** Each backfill is a 1-stream, ~15-25 min,
zero-new-dep, low-risk slot.

## New adjacency candidates (beyond brief's 5)

| # | Candidate | Streams | Rule #39 fit | Lib dep | Risk |
|---|---|---:|---|---|---|
| N1 | **AppCompat/Shimcache** (registry SYSTEM hive parse — execution evidence) | 1 | YES (regipy already in tree) | regipy (existing) | LOW |
| N2 | **UsnJrnl $J change log walker** | 1-2 | YES (dissect.ntfs already in tree for $J record) | dissect.ntfs (existing) | LOW-MED |
| N3 | **BAM/DAM** (Background/Desktop Activity Moderator registry walker) | 1 | YES (regipy reuse, SYSTEM hive sub-key) | regipy (existing) | LOW |
| N4 | **UserAssist** (NTUSER.DAT registry — GUI execution evidence) | 1 | YES (regipy ROT-13 decode) | regipy (existing) | LOW |
| N5 | **Linux crontab + ld.so.preload + bash_history triplet bundled** (refined #4) | 1 | YES (text-format → fits triplet) | stdlib only | LOW |
| N6 | **Android Doze/AppStandby walker** (system service dumpsys — Android lacks coverage parity) | 2 | YES (clean-room dumpsys-stub parser) | androguard (existing) | MED (Android dumpsys is text format) |

## Top 5 recommended for κ.X

Ranked by: (a) Rule #39 precedent fit, (b) zero-new-dep preference, (c) stream-count
fit ~30 min each, (d) coverage gain.

1. **κ.A — journald cross-firmware backfill** (ι.A.E completion; brief #1) — explicit
   HANDOFF carryover; 15-20 min; zero new dep; smallest follow-up.
2. **κ.B — AppCompat/Shimcache** (N1) — regipy reuse; T1106 execution-evidence; high
   adversary value (LotL execution residue); fits Rule #39 triplet exactly; Windows
   portfolio addition.
3. **κ.C — bash_history + crontab + ld.so.preload bundled Linux persistence triplet**
   (brief #4 refined as 1 bundled stream; 3 text-format sub-tasks under one walker
   `linux_persistence_walker`) — completes Linux persistence stack alongside
   journald/systemd; fits Pattern P1 single-stream multi-artefact precedent.
4. **κ.D — DPAPI master-key parse-only metadata walker** (brief #5) — directly extends
   ι.D Rule #45 parse-only-metadata Rule-of-One to Rule-of-Two; promotes Rule #45 to
   durable; ~25-30 min via parse-only file walk (`Master Key Container` GUID + flags
   only — never decrypt).
5. **κ.E — UsnJrnl $J change-log walker** (N2) — `dissect.ntfs` already in tree from
   η.A MFT; T1070.001 anti-forensics evidence; complements MFT walker; ~25-30 min.

**Skip from brief:** auditd (#2) — defer to a later Linux campaign; clean-room over
format spec is ~30-40 min and the value compounds better paired with a Linux audit-trail
campaign. WMI dissect.cim refactor (#3) — Rule #27 refactor, different work shape,
doesn't fit adjacency batch cadence.

## Closing assessment

The brief's 5-candidate slate is NEAR-OPTIMAL but needs one swap. Recommended revision:
keep candidates 1, 4 (bundled), 5; SWAP candidate 2 (auditd) → AppCompat/Shimcache (N1)
as a Windows regipy-reuse stream that better fits the ~30 min cadence and matures the
Rule #44 + Rule #45 promotion to Rule-of-Two; SWAP candidate 3 (WMI refactor) →
UsnJrnl (N2) because the refactor is a different work shape and would break Pattern P1
single-sub-agent precedent reuse. Optional 6th if capacity holds: pair κ.A
journald-backfill with one additional Rule #44 backfill (windows_event_log or
windows_mft) to mature the cross-firmware backfill pattern to Rule-of-Two within κ.
