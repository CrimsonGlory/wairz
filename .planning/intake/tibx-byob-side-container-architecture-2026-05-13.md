---
title: tibx BYOB-SC (bring-your-own-binary side-container) architecture
opened: 2026-05-13
status: scoped-ready-for-next-session
priority: high
estimated_streams: 4 (per Rule #25)
estimated_sessions: 1-2 (depending on side-container Docker complexity)
parent_research: .planning/research/tibx-deep-2026-05-13/
---

# tibx BYOB-SC implementation intake

## Context

`.tibx` (Acronis Archive3) is the wrapper format for the Medtronic ILLUMISITE
Windows recovery payload (and an unmeasured set of other Advantech /
Kontron / OEM-bundled industrial-medical Windows recovery images per λ
Scout 1's η-scope work). The actual Windows update content — NTFS volume,
registry hives, EVTX logs, Authenticode-signed PE files, BCD store, USN
journal — lives inside ``Archive(1).tibx`` + continuation slices. Without
.tibx extraction, every wairz Windows walker (registry / EVTX / prefetch /
AppCompat / BCD / DPAPI / MFT / USN / SRUM / scheduled-tasks / LNK / WMI)
no-ops on these uploads.

## Why this is now ready to ship

The 2026-05-13 deep-research (`tibx-deep-2026-05-13/scout-{a,b,c}-*.md`)
locked the architecture. **Key findings:**

- **Scout A:** No OSS .tibx parser exists or is foreseeable (multi-year RE
  effort + moving-target risk). Writing one is not justified by N=1
  current operator demand. HOLD on parser-library work.
- **Scout C:** Acronis ships `tibxread`, a Linux-native CLI tool that
  reads .tibx files and writes raw disk bytes to stdout. `tibxread get
  content --loc <dir> --arc <master.tibx> --backup <id> --disk 1` is the
  invocation contract.
- **EULA:** Acronis EULA §2 prohibits redistribution. Wairz cannot bundle
  the binary in any Docker image.
- **BYOB-SC architecture** (Scout C verdict): operator installs Acronis
  Cyber Protection Agent for Linux on the host once; wairz ships a
  hardened side-container (`tibx-extractor`) with no Acronis bundled;
  operator points `WAIRZ_TIBX_AGENT_PATH` at the host install; container
  bind-mounts the binary read-only. Mirrors UART-bridge / device-bridge
  precedent.
- **Scout B:** wairz integration surface is 80% wired (`DetectedFormat.
  ACRONIS_BACKUP` exists; strategy registry has the slot;
  `unpack_no_handler` is the current stub). Implementation is mechanical
  once the side-container is ready.

## Streams (per Rule #25 per-piece commits)

### Stream 1 — Side-container scaffolding

- `tibx-extractor/Dockerfile` — Alpine-base, sh + small toolset, NO
  Acronis bundled (operator-supplied at runtime via bind mount).
- `tibx-extractor/entrypoint.sh` — validate args, sanity-check that
  /opt/acronis bind mount is non-empty, invoke tibxread with stdout
  redirect to /work/disk.raw.
- `docker-compose.yml` — new `tibx-extractor` service definition with
  the hardening profile from Scout C §3:
  - `read_only: true`, `tmpfs: /tmp:size=64M`
  - `security_opt: no-new-privileges:true`
  - `cap_drop: ALL`
  - `network_mode: none`
  - `user: 65534:65534` (nobody:nogroup)
  - `pids_limit: 64`, `cpus: "2.0"`, `memory: 2048M`
  - Volumes:
    - `${WAIRZ_TIBX_AGENT_PATH:-/dev/null}:/opt/acronis:ro` (operator BYO)
    - `firmware_data:/data/firmware:ro` (customer data RO)
    - `tibx_work:/work` (named volume, write-able output sink)
  - `profiles: ["build"]` to keep idle wairz deployments slim.
- Named volume `tibx_work` declared in docker-compose.yml.
- New `.env.example` entry for `WAIRZ_TIBX_AGENT_PATH` documenting the
  required Acronis install path on the host.

### Stream 2 — Worker module (`unpack_tibx.py`)

Mirror `backend/app/workers/unpack_vhdx.py` (305 LOC, 7-step body):

1. Async `_report` callback wrapper.
2. `extraction_dir` derivation + reset via `reset_extraction_dir_sync`
   (Rule #5 minimum-hop).
3. Magic-byte probe — ARCH at offset 8 for master, slice-naming check
   for continuations. Reject continuations with operator guidance
   pointing at the master.
4. Side-container probe — Docker SDK call (via docker-proxy ambassador
   at `docker-compose.yml:39-74`) to verify `WAIRZ_TIBX_AGENT_PATH` is
   bind-mounted in the extractor container. Fail fast (<2s) with clear
   "configure `WAIRZ_TIBX_AGENT_PATH`" error if the operator hasn't
   set up Acronis.
5. Disk-space check — 1× the .tibx total size (raw expands fully).
6. Main extraction: `client.containers.run(image="wairz-tibx-extractor",
   command=["/opt/acronis/usr/lib/Acronis/BackupAndRecovery/tibxread",
   "get", "content", "--loc", "/data/firmware/<rel-dir>", "--arc",
   "<basename>.tibx", "--backup", "<recovery_point_id>", "--disk", "1"],
   detach=True, ...)`. Timeout: 1200s (Rule #29 — bigger than Ghidra
   tier because 4×4 GB extractions can take 10-20 min). The
   `--backup` recovery-point-id is discoverable via `tibxread list
   backups`; if missing, default to the first one.
7. Post-conversion analysis + result population: `disk.raw` exists,
   detection roots fire, walkers iterate. Same shape as VHDX.

### Stream 3 — Integration cross-stack

- `backend/app/workers/extraction_strategies.py:83` —
  `DetectedFormat.ACRONIS_BACKUP: unpack_tibx` (was: `unpack_no_handler`).
- `backend/app/services/format_detection.py:123` —
  `DetectedFormat.ACRONIS_BACKUP: ExtractionCapability.PARTIAL` (was:
  `NONE`). PARTIAL because BYOB-dependent.
- `backend/app/services/format_detection.py:144-148` —
  `CAPABILITY_NOTES[ACRONIS_BACKUP]` updated to describe the BYOB-SC
  setup (already updated in commit ~2026-05-13 detection-refinement
  but text will need a "now extractable via BYOB" prefix).
- Tests:
  - `backend/tests/test_unpack_tibx.py` — mirror
    `test_unpack_vhdx.py` (7 tests: magic reject, missing-binary,
    side-container missing, extractor-step failure, timeout, happy
    path, progress).
  - `backend/tests/test_extraction_pipeline.py:288-330` — migrate
    `test_unpack_no_handler_acronis_backup` + cousin to a different
    `ExtractionCapability.NONE` format (deferred until one is added)
    OR delete + replace with `unpack_no_handler`-direct unit tests.
  - `backend/tests/test_firmware_router.py:533-555` — update
    `test_capability_banner_for_acronis_backup` to assert the new
    capability + note.

### Stream 4 — CLAUDE.md Rule #36 amendment (Rule #21 sync)

Scout C surfaced a Rule #36 nuance: vendor-supplied parser binaries
operating on customer data AS DATA inside an ISOLATED SIDE-CONTAINER
are different from the original "don't execute installer custom
actions" incidents. The exception is parallel to the existing
`qemu-img convert` / `signify` / `ilspycmd` exceptions but adds the
"moved out of worker for sandbox strength" qualifier.

Proposed Rule #36 Exception 3:
> Vendor-supplied trusted parser binaries running INSIDE A HARDENED
> SIDE-CONTAINER (separate from the worker; `read_only`,
> `network_mode: none`, `cap_drop: ALL`, non-root, resource-limited,
> operator-supplied via bind-mount per BYO discipline) that consume
> customer data AS DATA are an explicit Rule #36 exception. The
> security boundary is the side-container's network/capability
> isolation; the wairz worker only consumes the side-container's
> output bytes. Precedent: `tibxread` inside `tibx-extractor`
> (Phase λ.μ — to be implemented). Companion to Rule #21 — update
> CLAUDE.md AND `.mex/context/conventions.md` in the same commit.

## Open questions for the implementer

1. **Multi-disk TIBX.** The Medtronic sample's metadata may carry
   multiple disks (Disk 1, Disk 2, ...). `tibxread` takes `--disk N`
   per invocation. Should wairz iterate all disks automatically (per
   `tibxread list content`) or surface a manual disk-selection UI?
   Default: iterate all; emit each as `extraction_dir/disk-N.raw`.
2. **Encrypted TIBX.** Acronis backups can be AES-256 encrypted with
   an operator-supplied password. `tibxread` accepts `--password`.
   How does wairz plumb the password? Per-firmware setting in the
   project UI? Env var? Defer encryption support to a separate
   stream.
3. **`WAIRZ_TIBX_AGENT_PATH` location.** Operator UI surface (project
   settings) or env var only (.env.example)? Default: env var only
   for first ship; project-UI plumbing in a follow-up.
4. **Recovery-point ID discovery.** `tibxread get content` requires
   `--backup <recovery_point_id>`. The ID is discoverable via
   `tibxread list backups` JSON output. wairz needs to run that
   first, parse the JSON, pick the most recent (or all) recovery
   points, then iterate `get content` per point.

## Companion items (NOT in this intake — track separately)

1. **`.planning/intake/acronis-recovery-pe-walker-validation-2026-05-13.md`**
   — verify that wairz's existing `unpack_iso9660` + `unpack_wim`
   handlers produce useful walker findings on the Acronis Recovery PE
   ISO that ships alongside the .tibx (for the ILLUMISITE case, the
   `sources/boot.wim` file). 1-session smoke test; no new code.

## Time estimate

3-4 commits, 1-2 sessions. Bulk of the work is the side-container
Dockerfile + docker-compose service definition + Docker SDK plumbing
in the worker. Tests + integration are mechanical once the side-
container is healthy.

## Pre-requisites

- A host machine with Acronis Cyber Protection Agent for Linux
  installed (for end-to-end testing). The 30-day free trial works.
  Without this, the implementation can SHIP cleanly (graceful-degrade
  error message when `WAIRZ_TIBX_AGENT_PATH` is empty) but cannot be
  fully tested.

## Cross-references

- `.planning/research/tibx-deep-2026-05-13/scout-a-format-deep-research.md`
- `.planning/research/tibx-deep-2026-05-13/scout-b-wairz-integration.md`
- `.planning/research/tibx-deep-2026-05-13/scout-c-sandboxed-extraction.md`
- `.planning/research-fleet/tibx-support-research-brief-2026-05-12.md` (prior HOLD verdict, now superseded)
- CLAUDE.md Rule #36 (no-execute discipline)
- CLAUDE.md Rule #37 (offline-trust-anchor discipline) — partially
  relevant: tibxread runs from a bind mount, not bundled, but the
  isolation discipline carries forward.
- `backend/app/workers/unpack_vhdx.py` — template for unpack_tibx
- `docker-compose.yml:324-392` — emulation/fuzzing side-container precedent
