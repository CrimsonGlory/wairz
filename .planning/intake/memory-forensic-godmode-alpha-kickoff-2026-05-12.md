---
title: λ campaign kickoff — memory-forensic-godmode α (Vol3 + Windows hibernate)
opened: 2026-05-12
status: kickoff-pending-research-fleet (next session)
parent: windows-coverage-godmode-kappa-2026-05-12.md (κ close)
series_pivot: |
  λ launches the "memory-forensic-godmode" series — a NEW series codename
  separate from "windows-coverage-godmode" (α through κ). Memory forensics
  is a distinct horizontal expansion (not artefact-walker addition) and
  deserves its own series naming. The Greek-letter ladder resets to α for
  the new series.

  Codename: memory-forensic-godmode-α (the "α" is a fresh start, not a
  continuation of κ → λ in the windows-coverage series).
---

# λ campaign kickoff — memory-forensic-godmode α

## Strategic context (from κ scouts)

**κ Scout 1 finding (corrected from iota):** MemProcFS does NOT have MCP integration
as of v5.17 (Feb 2026). The iota brief's "MemProcFS shipped MCP" claim was a false
positive from a third-party aggregator (`skywork.ai`). **wairz is still first-to-
market for MCP-exposed memory forensics.** Differentiation 8/10, maintenance risk
LOW for Vol3 dependency, ISF bundle bake-in viable per Rule #37.

**κ Scout 3 finding:** Vol3 is a CLEAN FIT for wairz patterns:
- Memory dumps slot as Rule #16 detection_roots-discoverable artefacts (`.raw`,
  `.dmp`, `.vmem`, `.lime`, `.mem`, `.crash`)
- Vol3 plugins map to Rule #33 .a state machines
- ISF bundle (~1.5 GB compressed) fits Rule #37 build-time anchor pattern
- Vol3's pure-parser nature satisfies Rule #36 no-execute trivially
- **Data type: SUBORDINATE to Firmware** (82 import sites for Firmware; parallel
  top-level would cost 15-20 router parallels)
- **Plugin orchestration: ONE walker per plugin-family** (windows_processes covers
  pslist/pstree/psscan/cmdline; windows_network covers netstat/netscan)
- **8 streams to Vol3-READY, 2-3 sessions** estimated

## Pre-flight research-fleet (next session opens with this)

Dispatch 3 parallel scouts BEFORE writing the λ campaign brief:

1. **Scout 1 — Vol3 library probe.** Verify Vol3 v2.28+ Python API surface; probe
   `dissect.vol3` if exists OR `volatility3` official package; check Python 3.12
   compatibility (wairz backend); verify CLI invocation shape; probe one plugin
   end-to-end (`windows.info` against a tiny test memory image — sub-agent
   synthesizes a 1MB memory blob fixture).
2. **Scout 2 — ISF bundle download dry-run.** Run `scripts/refresh-vol3-symbols.sh
   --probe-only` (TO BE WRITTEN — sub-agent writes the probe-only mode); verify
   `downloads.volatilityfoundation.org/volatility3/symbols/` is reachable + sane;
   measure compressed bundle size; verify SHA256 pinning works; estimate refresh
   cadence.
3. **Scout 3 — Plugin API stability + plugin-family taxonomy.** Audit Vol3's
   plugin namespace: enumerate `windows.*` and `linux.*` plugin families;
   identify which 5 families to ship as the FIRST κ walkers (windows_processes,
   windows_network, windows_injection, windows_persistence, linux_processes per
   Scout 3 of κ); probe plugin argument shapes; recommend one-walker-per-family
   mapping.

## Architectural prerequisites (λ.α core, first session)

Per κ Scout 3's 8-stream breakdown:

- **λ.α.A** — ORM `memory_dump_image` (FK firmware_id, image_path, magic detected,
  kernel_hint, size, ISF profile guess) + alembic migration. Mirrors
  `windows_mft_records` / `linux_journald_entries` shape.
- **λ.α.B** — `memory_image_paths.py` helper (Rule #16 detection_roots-style
  enumeration for memory-dump file extensions) + Rule #39 inner/outer/safe
  triplet that enumerates+stamps memory_image rows. Auto-trigger registration in
  `app/workers/unpack.py` (4-line precedent).
- **λ.α.C** — Vol3 Dockerfile gate (`ARG INCLUDE_VOL3=1` → vol3 + symbol bundle
  COPY + sha256 verify). Pattern mirror: existing `ARG INCLUDE_DOTNET=1` for
  dotnet-runtime-8.0 + ilspycmd.
- **λ.α.D** — `vol3_runner.py` service: containerized `volatility3 -f <image>
  -p <symbols> <plugin>` subprocess wrapper with Rule #29 timeout +
  Rule #33 .a state machine. **First Vol3 plugin invoked: `windows.info`** —
  confirms parsable kernel + bakes ISF profile into the image row.

## Subsequent λ session(s) (post-α infrastructure)

- **λ.β** — `windows_processes` walker family (pslist/pstree/psscan/cmdline →
  one walker, multi-table emit to `volatility_process_records`). First plugin
  family.
- **λ.γ** — VolatilityFindingSource Literal + DB CHECK extension + frontend
  mirror + 2 first sources (`vol3_unlinked_process`, `vol3_hollow_process`) —
  Rule #25 single-slice cross-stack commit.
- **λ.δ** — MCP tool category `backend/app/ai/tools/volatility.py` with first
  4-5 tools (status, list-processes, list-anomalies, get-process-tree,
  trigger-walk).
- **λ.ε onwards** — Additional plugin families per scout-3 taxonomy:
  windows_network, windows_injection, windows_persistence, linux_processes.

## λ session 1 deliverables (estimated 4 streams)

Per Scout 3 estimate: Session 1 ships streams 1-4 (ORM + paths + unpack hook +
Docker gate). Each session ends at a green Rule #8 rebuild + Rule #11 smoke +
cross-stack alignment test passing.

## Rule #37 ISF bundle bake-in plan

Add `backend/vol3-symbols/` directory pattern:
- `backend/vol3-symbols/windows/`, `linux/`, `mac/` subdirectories
- `backend/vol3-symbols/SHA256SUMS` pinned
- `backend/vol3-symbols/README.md` documenting refresh process
- `scripts/refresh-vol3-symbols.sh` — quarterly cadence (matches DBX), atomic-write,
  `--apply` flag for auto-pin-update, `--rebuild` for compose --no-cache build
- Dockerfile: `COPY` directory under `ARG INCLUDE_VOL3=1` gate + `sha256sum -c`
  + `/opt/wairz/vol3-symbols/` runtime path
- docker-compose.yml: `VOL3_SYMBOLS_PATH=/opt/wairz/vol3-symbols` env on backend + worker

Image size impact: ~1.5 GB compressed bundle. Same gate pattern as
`INCLUDE_DOTNET=1` (existing precedent).

## Companion intakes to file from κ close

- `.planning/intake/ι-D-efs-test-gate-whitespace-tolerance-backfill-2026-05-12.md`
  — Apply κ.D's whitespace-tolerant regex fix to the ι.D EFS
  `test_walker_no_decrypt` gate. 1-line fix, ~5 min wall. Can ship as a κ.X
  carve-out OR be the first commit of λ.
- `.planning/intake/rule-44-backfill-11-walkers-2026-05-12.md` — Per κ scout 2's
  audit, 11 more Rule #44 cross-firmware-aggregation backfill candidates remain
  across η/θ/pre-ι walkers. Each is a single-commit MCP tool addition. Could
  ship as a single κ.X session OR distributed across λ idle slots.

## Code/architecture decisions to lock at λ kickoff

1. Vol3 invocation shape: subprocess wrapper vs Python API integration?
   (Subprocess is safer per Rule #29 timeout; Python API may have stability
   issues with long-running plugins. Default: subprocess.)
2. Memory dump auto-detection vs user-trigger only? (Default: auto-detect on
   unpack for files >100MB matching `.raw|.dmp|.vmem|.lime|.mem|.crash`;
   surface in firmware UI.)
3. ISF bundle storage: in worker image OR sidecar volume?
   (Default: in worker image — atomic versioning + reproducibility; ~1.5 GB
   image growth.)

## Forward signal

λ should NOT open in the same session as κ closes. κ produced 4 new walker
families + Rule #45 promotion + Rule-of-Three canary discipline — context for
the next session is rich. λ deserves its own clean session with the 3-scout
research-fleet running fresh.

Open λ when:
1. κ close fully shipped (campaign postmortem + /citadel:learn + session-handoff)
2. Operator manually tests Windows κ outputs via the test plan at
   `.planning/intake/windows-coverage-test-plan-2026-05-12.md`
3. Operator confirms ready for λ kickoff

Estimated session count for λ: 2-3 sessions to Vol3-READY-with-first-MCP-tool.
