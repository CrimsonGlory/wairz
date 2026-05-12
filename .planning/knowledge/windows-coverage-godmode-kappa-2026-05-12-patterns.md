---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
extraction_type: patterns (success modes worth carrying forward)
opened: 2026-05-12
---

# Phase κ — successful patterns

## P1 — Pattern P1 single-sub-agent + precedent reuse (Rule-of-Fifteen — decimal+5)

Each κ stream dispatched as ONE sub-agent prompt referencing prior streams as
precedent. Sub-agent inherits the walker triplet shape + Rule #25 single-slice
shape + Rule #44 cross-firmware tool shape directly. **Compounding effect** —
later streams need less prompt overhead because more in-tree precedent exists.
ZERO sub-agent retries needed across 5 streams. Continues from ι.A-E (5 streams)
at the same per-stream wall (~26-38 min).

**When to apply:** any new walker stream in this codebase. Read 2-3 most-recent
precedent walker files (e.g. κ.B reads ι.D + γ.4; κ.C reads κ.B + ι.B + γ.4)
before designing.

## P2 — Pattern P5 per-piece direct-push to main

21 stream commits + 5 per-stream postmortem commits + ancillary commits — all
direct-pushed to origin/main. ZERO ff-merge conflicts. Each commit individually
revertable per Rule #25.

**Key invariant:** worktree branches merge to main via `git -C
/home/dustin/code/wairz merge --ff-only feat/stream-kappa-X-2026-05-12` from the
PRIMARY checkout (not from inside the worktree, because main is already checked
out in the primary checkout and `git merge` on a checked-out-elsewhere branch
fails). All 5 sub-agents internalized this pattern.

## P3 — Worktree isolation per Rule #23 effective dispatch shape

All 5 streams used `git worktree add .worktrees/stream-kappa-X -b
feat/stream-kappa-X-2026-05-12`. Sub-agents symlinked `.venv` and
`frontend/node_modules` from the primary checkout (saves 2-5 min of venv
recreate). ZERO cross-stream commit sweeps detected.

**Mechanical detection:** any sub-agent prompt that uses `git checkout -b` alone
(without `git worktree add`) is a Rule #23 violation. The κ campaign reinforced
this discipline is mature.

## P4 — Pattern P7 trust-but-verify orchestrator gate (Rule-of-Eleven)

After EACH sub-agent return, orchestrator runs 6-7 independent verification
commands:
1. `git -C <repo> pull origin main; git log --oneline -8`
2. `git -C <repo> log --stat <prev-head>..HEAD --format='%h %s'`
3. `find backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'`
4. `awk '/^WindowsFindingSource = Literal\[/,/^\]/' backend/app/schemas/finding.py | grep -E '^\\s*\"windows' | wc -l`
5. Frontend cross-stack evidence: `grep -c "<source>" frontend/src/types/index.ts frontend/src/constants/statusConfig.ts`
6. `( cd backend && uv run ruff check --no-cache <files> )` — Antipattern A7
7. `gh run list --workflow=lint.yml --limit 5 --json conclusion,headSha | jq ...` — Antipattern A1

Total verification overhead: ~75 min across the 5 streams. ZERO antipattern
recurrence. Pattern P7 must NOT be skipped (ι.C/D antipattern A1 incidents were
the original cost driver).

## P5 — Cross-firmware aggregation at walker-stream time (codified as Rule #44 — Rule-of-Nine DURABLE BEYOND DEBATE)

Every walker MCP category ships ONE `lookup_<artefact>_across_firmwares` tool in
the .E commit. Shape: SQL `JOIN firmware ON Artefact.firmware_id = firmware.id`
+ group-by-firmware bucket + match_count + supply_chain_signal flag.

**Rule-of-Nine evidence:** ι.B/C/D/E + κ.A/B/C/D/E. The pattern is mechanical
and universal. wairz's primary competitive wedge vs EZTools/Plaso/Velociraptor.

**Retroactive applicability proven (κ.A backfill):** walkers shipped before Rule
#44 codification can have the cross-firmware tool added as a single follow-up
commit. 11 backfill candidates remain (windows_event_log, windows_mft,
windows_lnk, windows_scheduled_task, windows_prefetch, windows_srum,
windows_registry, plus θ.A/B/C/E walkers).

## P6 — Parse-only metadata walker discipline (codified as Rule #45 — Rule-of-Two DURABLE BEYOND DEBATE)

Security-sensitive walkers (DPAPI, EFS, future BitLocker/PGP/TPM/cert-stores)
surface METADATA only. NEVER decrypt. Rule #36 EXTENSION test gate via
`tokenize`-based forbidden-token scan, paired with synthetic-violation canary
per Rule #46.

**Worked examples:**
- ι.D EFS walker (`backend/app/services/efs_walker.py` + `test_efs_walker.py`)
- κ.D DPAPI walker (`backend/app/services/dpapi_walker.py` +
  `test_dpapi_walker.py` with whitespace-tolerant regex + canary)

## P7 — Canary discipline for "asserts absence" verification mechanisms (codified as Rule #46 — Rule-of-Four)

ALL gates that say "no forbidden tokens / no type errors / no failed tests" MUST
be paired with a canary test in the same file that synthesises a violation IN
MEMORY and confirms the gate REJECTS it.

**Rule-of-Four evidence chain:**
1. Rule #17 — `tsc -b` cache short-circuit
2. Rule #24 — `tsc --noEmit` empty-files no-check
3. κ.D test-gate tokenize-whitespace gap (regex `\.decrypt\(` failed against `obj . decrypt (`)
4. κ.E meta-canary — Rule #24 invocation caught Rule #35a pipe-induced silent exit

**Mechanical authoring:** write synthetic-violation constructor FIRST; ensure
synthetic round-trips through gate's preprocessing (string-join, tokenize,
AST-walk, JSON-load); a synthetic the gate strips out is itself a bug —
finding it pre-ships saves regressions.

## P8 — Multi-artefact single-walker FAN-OUT variant (Rule-of-Four)

One walker (`linux_persistence_walker.py`) emitting to THREE SIBLING ORM tables
(`linux_bash_history_entries` / `linux_cron_jobs` / `linux_ld_preload_entries`)
under a SHARED Rule #33 .a status state-machine. Distinct from γ.4 + ι.B
(single ORM with discriminator column).

**Apply when:** artefacts are conceptually grouped (Linux persistence) but
structurally distinct (commands vs schedule-specs vs library-paths).

**Don't apply when:** artefacts share the same column shape — use 1 ORM with
discriminator (γ.4 pattern).

## P9 — Rule #19 evidence-first probe of library API at stream-start

κ.E sub-agent probed `dissect.ntfs.c_ntfs` for `USN_REASON_*` constants before
writing code — found only `USN_PAGE_SIZE` exported. Sub-agent defined explicit
local constants matching MS-FSCC §2.3 bit table instead of relying on absent
library symbols. **Saved a debug cycle.**

**Mechanical authoring:** any unfamiliar library API gets `inspect.getsource()`
or `dir()` probed before code-write. Especially: dissect.* families,
specialized parsers, version-sensitive APIs.

## P10 — Pre-flight pattern observation for Pattern P1 transfer

Sub-agents writing the SAME N-file change (e.g. 3 ORM files for κ.C) benefit
from a pre-flight grep audit BEFORE editing. κ.B + κ.C sub-agents both ran
`grep` audits against precedent files BEFORE starting edits. Rule #22 + Rule #31
discipline applied to stream-time work, not just intake-time.

## Forward — patterns that extend to λ

- P1/P5/P7/Rule #23 are durable; carry to λ.α directly
- Rule #44 cross-firmware tool ships in λ's first MCP tool category (λ.δ at
  Vol3 plugin family level)
- Rule #45 parse-only metadata discipline applies to λ's first plugin family
  if any handles credential/key material (e.g. windows.hashdump — but that's
  intentional decrypt; falls OUTSIDE Rule #45's parse-only scope; treat as
  intentional Rule #36 violation with explicit operator opt-in)
- Rule #46 canary discipline applies to any λ verification mechanism
