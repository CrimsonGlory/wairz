---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
scout: 3
angle: Vol3 architectural cost estimate (informs whether κ should be Vol3 or adjacency)
opened: 2026-05-12
duration_ms: 97005
total_tokens: 109214
tool_uses: 21
---

# κ Scout 3 — Vol3 architectural cost estimate

**Headline finding:** Vol3 is a CLEAN FIT for wairz patterns — memory dumps slot as
Rule #16 detection_roots-discoverable artefacts; Vol3 plugins as Rule #33 .a state
machines; ISF bundle as Rule #37 build-time anchor; pure-parser nature satisfies
Rule #36 trivially. **8 streams to Vol3-READY, 2-3 sessions, subordinate-to-Firmware
data-type shape.**

---

## DATA TYPE DECISION

**Subordinate to Firmware** (memory dump as sibling artefact under existing Firmware
row, not a parallel top-level type).

**Justification:** 82 files import `app.models.firmware`; `Firmware` references appear
in 20 routers and saturate `routers/firmware.py` (108 hits), `hardware_firmware.py`
(89), `apk_scan.py` (74), `security_audit.py` (52). A parallel `MemoryDump` top-level
type would force a "MemoryDump as parent of Findings + as sibling-of-Firmware-for-Projects"
rewire across ~15-20 routers/services to mirror finding-emit / project-membership /
export / device-bridge / MCP-context patterns.

Subordinate fits because Vol3 needs (a) detection_roots-style enumeration of `.raw` /
`.dmp` / `.vmem` / `.lime` files inside the firmware extracted tree, and (b)
per-image-file walk-status columns — both already match the walker pattern shape exactly.

## INFRA STREAM COUNT TO MEMORYDUMP-READY

**3 streams** for the foundation (ORM + worker + walker triplet skeleton + first finding):

1. ORM table `memory_dump_image` (per-image-file row: FK firmware_id, image_path, magic,
   kernel_hint, size, ISF profile guess) + alembic migration. Mirrors
   `windows_mft_records` / `linux_journald_entries` shape.
2. `memory_image_paths.py` helper (returns list[str] of `.raw` / `.dmp` / `.vmem` /
   `.lime` / `.mem` / `.crash` candidates under detection_roots) + Rule #39
   inner/outer/safe runner triplet that just enumerates+stamps memory_image rows.
   Auto-trigger wiring in `app/workers/unpack.py` (lines ~130-162 precedent — 4-line
   registration block).
3. First Vol3-orchestrator stream: containerized `volatility3 -f <image> windows.info`
   to confirm a parsable kernel + bake the ISF profile into the image row. Pure
   read-only Rule #36 — Vol3 reads memory bytes AS DATA. Triplet pattern continues.

## VOL3 PLUGIN STREAM SHAPE

**One walker triplet per plugin-family**, not per plugin. Family granularity mirrors
the existing wairz pattern (one walker for "registry hives" covers all 5 standard hive
types; one for "EVTX" covers all `.evtx` files):

- `windows_processes` (pslist/pstree/psscan/cmdline → one walker, multi-table emit)
- `windows_network` (netstat/netscan)
- `windows_injection` (malfind/hollowfind/ldrmodules)
- `windows_persistence` (svcscan/registry-from-memory)
- `linux_processes` (psaux/pslist/proc_maps)

Each family is one Rule #39 triplet emitting per-family rows (e.g.
`volatility_process_records`). Per-plugin shape (~50 walkers) would explode the
Firmware ORM column count beyond reason; family shape fits the 18 walker-status-column
precedent.

## ISF BUNDLE BAKE-IN

**NEEDS-REFRESH-CRON** (Rule #37-compliant, ~1.5-3 GB total bundle).

Vol3 ISFs ship with the volatility3 PyPI package as a thin set (~5 Windows kernels) but
real coverage requires the [volatilityfoundation/symbols](https://github.com/volatilityfoundation/symbols) bundle:

- Windows ISFs ~80-150 MB compressed (~500-800 MB uncompressed across ~3000 Windows
  kernel builds)
- Linux ISFs ~10-50 MB per distro family (banner-strings indexed)
- Mac ISFs ~5-20 MB

Realistic wairz-coverage bake: ~1.5 GB compressed (Windows-full + Linux-major-distros +
Mac-recent).

**Precedent supports this:** `backend/ms-anchors/` is already 29 MB (dbxupdate.bin +
loldrivers.json). Add `backend/vol3-symbols/` with `scripts/refresh-vol3-symbols.sh`
(quarterly, SHA256-pinned, atomic-write per Rule #37) + Dockerfile `COPY` +
`VOL3_SYMBOLS_PATH=/opt/wairz/vol3-symbols` env on backend+worker.

Refresh source: `https://downloads.volatilityfoundation.org/volatility3/symbols/`.

Worker image grows ~1.5 GB — large but precedented (`dotnet-runtime-8.0` + `ilspycmd`
lives behind `ARG INCLUDE_DOTNET=1` gate; same gate pattern applies as
`INCLUDE_VOL3=1`).

## TOTAL STREAMS TO VOL3-READY

**8 streams** (infra + first MCP tool flowing through the triplet):

1. ORM + alembic for `memory_dump_image` + `volatility_process_record` (cross-stack
   alignment commit per Rule #25 single-slice).
2. `memory_image_paths.py` + Rule #39 triplet for image enumeration.
3. unpack.py auto-trigger registration + integration test.
4. Vol3 Dockerfile gate (`ARG INCLUDE_VOL3=1` → vol3 + symbol bundle COPY + sha256
   verify).
5. `vol3_runner.py` service: containerized `volatility3 -f <image> -p <symbols>
   <plugin>` subprocess wrapper with Rule #29 timeout + Rule #33 .a state machine on
   `memory_dump_image.<plugin>_status`.
6. First plugin family — `windows_processes` walker triplet
   (`vol3_processes_walker.py`) calling pslist/pstree/psscan/cmdline + per-row emit to
   `volatility_process_records`.
7. Finding emit source extension: `VolatilityFindingSource` Literal + DB CHECK
   extension + frontend mirror + 2 first sources (`vol3_unlinked_process`,
   `vol3_hollow_process`) — Rule #25 single-slice cross-stack commit.
8. MCP tool category `backend/app/ai/tools/volatility.py` with first 4-5 tools
   (status, list-processes, list-anomalies, get-process-tree, trigger-walk).

## VERDICT

**VOL3 NEEDS 2-3 SESSIONS.**

Single-session capacity is ~5 streams × 30 min (per harness baseline); 8 streams puts
κ over the ~2.5 h wall. The Dockerfile gate + ISF bundle bake (stream 4) is itself a
Rule #8 three-way rebuild that consumes ~5-10 min and forces serialization against
other infra streams (no parallelization).

**Realistic shape:**
- Session 1 ships streams 1-4 (ORM + paths + unpack hook + Docker gate)
- Session 2 ships streams 5-6 (vol3_runner + first family walker)
- Session 3 ships streams 7-8 (finding source + MCP tools)

Each session ends at a green Rule #8 rebuild + Rule #11 smoke + cross-stack alignment
test passing.

## FIT ASSESSMENT

Vol3 is a **clean fit** for wairz patterns — memory dumps slot in as Rule #16
detection_roots-discoverable artefacts, Vol3 plugin invocations slot in as Rule #33 .a
state-machined 202+polling endpoints, ISF bundle slots in as Rule #37 build-time-baked
refresh-cron anchor, and Vol3's pure-parser nature satisfies Rule #36 no-execute
trivially (memory dumps are bytes; Vol3 never re-executes process state).

## Key file references

- `backend/app/models/firmware.py:1-673` (18 walker-status column blocks confirm the
  family pattern)
- `backend/app/services/firmware_paths.py:1-535` (detection_roots template)
- `backend/app/services/journald_walker.py:899,1029,1111` (Rule #39 triplet entry
  points)
- `backend/app/workers/unpack.py:129-162` (4-line auto-trigger registration pattern)
- `backend/ms-anchors/` (Rule #37 build-time anchor precedent, 29 MB)
- `backend/app/services/finding_service.py:48-120` (cross-stack source enum precedent,
  ~14 windows + 8 linux constants)
- `backend/app/main.py:296-321` (router include shape — vol3 router would be one new
  include)
