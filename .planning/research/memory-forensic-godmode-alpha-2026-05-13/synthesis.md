---
title: λ campaign synthesis — memory-forensic-godmode α
date: 2026-05-13
status: locked
inputs:
  - scout-1-vol3-library-probe.md
  - scout-2-isf-bundle-dry-run.md
  - scout-3-plugin-taxonomy.md
parent_intake: .planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md
---

# λ.α synthesis — decisions locked from 3-scout pre-pass

## 1. Decisions locked

| Decision | Outcome | Source |
|---|---|---|
| Vol3 version pin | `volatility3==2.28.0[full]` (PyPI 2026-04-30) | S1 §1 |
| Python 3.12 compat | Supported — issues #1105, #1220 both fixed at 2.28.0 | S1 §2 |
| Invocation shape | **Subprocess** (Rule #29 timeout + Rule #36 audit + process isolation + heap reclaim) | S1 §5 |
| CLI baseline | `vol --offline -q -f <img> -s /opt/wairz/vol3-symbols -o <tmp> --cache-path <tmp>/cache -l <tmp>/vol.log -r jsonl <plugin>` | S1 §4, S3 §4 |
| Renderer | `jsonl` (stream-parsable) | S1 §4 |
| First plugin to wire | `windows.info` (1 requirement, 22-row output, ideal acceptance test) | S1 §6 |
| Memory dump type | **Subordinate to Firmware** (FK firmware_id; 82 import sites = parallel-top-level costs prohibitive) | κ Scout 3 + intake |
| Auto-detect threshold | Files >100 MB matching `.raw|.dmp|.vmem|.lime|.mem|.crash` | intake §3 default |
| ISF bundle source | **GitHub release** `volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/` (NOT downloads.volatilityfoundation.org — stale; canonical content byte-identical) | S2 §1 |
| Total compressed | **~885 MiB** (windows 800 MiB + mac 81 MiB + linux 2.8 MiB) — revise intake's "~1.5 GB" estimate **DOWN** | S2 §2 |
| SHA256 pinning | Use upstream `SHA256SUMS` aggregate (published; no GPG) — acceptable per Rule #37 (parity with LOLDrivers) | S2 §3 |
| Refresh cadence | Quarterly (matches DBX + LOLDrivers cron) | S2 §4 |
| Dockerfile gate | `ARG INCLUDE_VOL3=0` (opt-in; mirrors `INCLUDE_DOTNET=1` precedent) | S2 §7 + intake |

## 2. Critical risks surfaced

### 2.1 Deprecation deadline 2026-06-07 — must wire to `windows.malware.*` paths (S3)

12 top-level Windows plugins are deprecation wrappers scheduled for removal:
`hollowprocesses`, `malfind`, `ldrmodules`, `processghosting`, `psxview`,
`drivermodule`, `direct_system_calls`, `indirect_system_calls`,
`unhooked_system_calls`, `suspicious_threads`, `skeleton_key_check`, `svcdiff`.

**Mitigation:** λ.γ `windows_injection_walker` MUST wire to `windows.malware.malfind`
/ `windows.malware.hollowprocesses` / etc. Linter-grep at λ.γ commit time:
`grep -rn 'windows\.\(hollowprocesses\|malfind\|ldrmodules\|processghosting\|psxview\)' backend/`
must return 0.

### 2.2 Vol3 runtime symbol-server fetch — must pass `--offline` (S2)

Without `--offline`, Vol3 reaches out to `msdl.microsoft.com/download/symbols`
AND `downloads.volatilityfoundation.org/volatility3/symbols/` at scan time.
Defeats Rule #37 + leaks scan metadata externally. **MUST PASS `--offline`** in
every vol3_runner.py subprocess invocation. Test gate: λ.α.D's runner test
asserts `--offline` is in the argv.

### 2.3 GitHub release URLs are 302 → time-limited Azure signed URLs (S2)

`https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip`
redirects to `objects.githubusercontent.com/...?se=<expiry>&...`. Refresh script
must follow redirects in ONE curl invocation; never cache the Location header.

### 2.4 Credentials family deferred (S3)

`hashdump`, `lsadump`, `cachedump`, `truecrypt` plugins ARE genuine credential
extraction — Rule #45 (parse-only metadata walker) requires explicit operator
sign-off before wrapping. **DEFERRED beyond λ.α/β/γ/δ.** Document explicitly
in λ.δ MCP-tool intake.

## 3. First-session deliverables (streams 1-4)

Per intake λ.α.A-D. Per-stream Rule #25 commits, Rule #8 rebuild ONCE at the
end of the session.

### 3.1 λ.α.A — ORM `memory_dump_image` + alembic migration

- Model file `backend/app/models/memory_dump_image.py` mirrors
  `windows_prefetch_record.py` shape.
- Columns: `id` (UUID PK), `firmware_id` (FK CASCADE), `image_path` (str(1024)),
  `image_filename` (str(256)), `file_size` (BigInt), `magic_detected`
  (str(48)), `os_family` (str(32)) — values `windows` / `linux` / `mac` /
  `unknown`, `kernel_hint` (str(255) nullable), `isf_profile_guess` (str(64)
  nullable), `last_walked_at` (DateTime nullable), `created_at` (DateTime
  server_default now).
- Indexes: `(firmware_id, image_filename)` + `(firmware_id, os_family)`.
- Alembic migration revises from current head `aabbccddee18`.

### 3.2 λ.α.B — `memory_image_paths.py` helper + Rule #39 walker triplet

- `backend/app/services/memory_image_paths.py`:
  - `MEMORY_IMAGE_EXTENSIONS` constant: `(.raw, .dmp, .vmem, .lime, .mem, .crash)`
  - `MIN_MEMORY_IMAGE_BYTES = 100 * 1024 * 1024` (100 MB)
  - `_enumerate_memory_image_candidates(roots) -> Iterator[(path, size)]`
  - `_sniff_memory_image_magic(path) -> str` (magic-byte head probe)
- `backend/app/services/memory_image_enumerator.py` (Rule #39 triplet):
  - `_do_memory_image_enumeration(db, firmware_id) -> dict` (inner — pure logic, returns aggregate)
  - `run_memory_image_enumeration_background(firmware_id) -> None` (outer — state-machine wrapper)
  - `auto_memory_image_enumeration_safe(firmware_id) -> None` (safe — unpack-hook entry)
- Register in `walker_registry.py` BEHIND a Rule #37 + ARG gate-aware flag —
  the enumerator runs regardless of `INCLUDE_VOL3` (it just records dump
  presence + metadata; doesn't invoke vol3 itself).
- ORM JSONB stamp on `firmware.memory_dump_walk_result` — new column added in
  the migration above.

### 3.3 λ.α.C — Dockerfile `ARG INCLUDE_VOL3=0` gate

- Default OFF (`0`) — the Vol3 walker family is opt-in until enough is wired
  for it to be useful. Once λ.β + λ.δ ship MCP tools + first walker, flip default ON.
- `RUN if [ "$INCLUDE_VOL3" = "1" ]; then uv pip install --no-cache-dir 'volatility3==2.28.0[full]'; fi`
- ISF bundle COPY + sha256sum -c inside the SAME gate. Source: per S2,
  `backend/vol3-symbols/` host directory + sha256 sidecar.
- docker-compose.yml: `VOL3_SYMBOLS_PATH=/opt/wairz/vol3-symbols` env on
  backend + worker. Reader code degrades gracefully if absent.

### 3.4 λ.α.D — `vol3_runner.py` service (Rule #33 .a state machine + Rule #29 timeout)

- `backend/app/services/vol3_runner.py`:
  - Subprocess wrapper. Argv builder defaults to `--offline` + `-r jsonl` +
    `-s $VOL3_SYMBOLS_PATH`.
  - `VOL3_PLUGIN_TIMEOUT_SECONDS = 600` (matches `mobsfscan` pipeline; allows
    `unhooked_system_calls`-class O(N²) plugins to complete on multi-GB images).
  - Returns `{records: list[dict], plugin: str, image_path: str, elapsed_s: float, exit_code: int, stderr_tail: str}`.
  - First plugin invoked: `windows.info` against the first
    `memory_dump_image` per firmware (acceptance test).
- Each plugin invocation is one subprocess + one Rule #33 .a state row on
  the per-image table. λ.α.D ships the runner skeleton + the windows.info
  driver only; other plugins ship in λ.β onwards.

## 4. Defer to λ.β+ (NOT in this session)

- `windows_processes_walker` (λ.β) — full Rule #39 walker around pslist/psscan/pstree/cmdline.
- `VolatilityFindingSource` Literal + DB CHECK + frontend mirror + 2 first sources (λ.γ).
- `windows_injection_walker` against `windows.malware.*` (λ.γ + λ.ε).
- MCP tool category `tools/volatility.py` (λ.δ).
- Networking / persistence / linux_processes walker families (λ.ε onwards).

## 5. Companion-intake spillover

Per intake §"Companion intakes to file from κ close":

- `ι-D-efs-test-gate-whitespace-tolerance-backfill-2026-05-12.md` — apply κ.D's
  whitespace-tolerant regex fix to the ι.D EFS gate. Ships as Item #3 carve-out
  if capacity remains.
- `rule-44-backfill-11-walkers-2026-05-12.md` — 11 more cross-firmware MCP tools.
  Distributable across λ idle slots.

## 6. Reference card

| What | Where |
|---|---|
| Vol3 pinned version | `volatility3==2.28.0[full]` |
| Symbol bundle URL prefix | `https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/` |
| ISF runtime path | `/opt/wairz/vol3-symbols` |
| CLI baseline | `vol --offline -q -f X -s Y -o T --cache-path T/cache -l T/log -r jsonl P` |
| Subprocess timeout | 600s (`VOL3_PLUGIN_TIMEOUT_SECONDS`) |
| Auto-detect minimum size | 100 MB |
| Auto-detect extensions | `.raw|.dmp|.vmem|.lime|.mem|.crash` |
| First plugin | `windows.info` |
| API interface gate | `framework.require_interface_version(2, 0, 0)` |

DONE — proceed to implementation streams α.A → α.D.
