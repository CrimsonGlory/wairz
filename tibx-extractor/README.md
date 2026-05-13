# wairz tibx-extractor side-container

Hardened Alpine sandbox that runs Acronis `tibxread` against a customer-
supplied `.tibx` file and writes the recovered disk bytes to the
`tibx_work` named volume. The wairz worker spawns this container
ephemerally per upload and reads `/work/disk.raw` afterward.

## Operator setup

1. **Install Acronis Cyber Protection Agent for Linux** on the build host.
   30-day free trial available at
   <https://www.acronis.com/en-us/products/cyber-protect/>. The agent
   installs `tibxread` under `/usr/lib/Acronis/BackupAndRecovery/`
   (canonical install path; sub-paths may apply per release).

2. **Set `WAIRZ_TIBX_AGENT_PATH`** in your `.env` to the parent
   directory of the `tibxread` binary:

   ```
   WAIRZ_TIBX_AGENT_PATH=/usr/lib/Acronis/BackupAndRecovery
   ```

   Default is `/dev/null` (no bind, worker fails fast with actionable error).

3. **Rebuild the worker + tibx-extractor**:

   ```
   docker compose --profile build build worker tibx-extractor
   ```

4. **Verify** by uploading a Medtronic-class `.tibx`-bundle firmware ZIP.
   The worker will spawn `wairz-tibx-extractor` per `.tibx` master file
   and the disk image will materialise in the firmware's `extraction_dir`.

## Architecture

Per CLAUDE.md Rule #36 Exception 3 (sandboxed vendor parser binaries
operating on customer data AS DATA inside an isolated side-container).
The container ships EMPTY (no Acronis binary baked in); the operator-
installed Acronis directory is bind-mounted read-only at `/opt/acronis`
at runtime. Hardening:

- `read_only: true` rootfs; `/tmp` is tmpfs (64 MB, noexec)
- `network_mode: none` — no egress at all
- `cap_drop: ALL` + `no-new-privileges:true`
- Non-root user (`65534:65534` = `nobody:nogroup`)
- `pids_limit: 64`, `memory: 2 GiB`, `cpus: 2.0`
- `firmware_data:/data/firmware:ro` (read-only customer data)
- `tibx_work:/work` (write-only output sink; named volume, NOT host bind)

## Why BYOB (Bring Your Own Binary)

Acronis EULA was reviewed by the wairz operator (2026-05-13) and deemed
compatible with the BYOB shipping pattern — operator installs Acronis
themselves, wairz never redistributes the binary. The side-container
itself ships with no Acronis content; the runtime bind mount supplies it.
This sidesteps redistribution review for downstream wairz packagers and
mirrors the existing UART-bridge + device-bridge precedent.

## Side-container lifecycle

Per upload, the wairz worker (`backend/app/workers/unpack_tibx.py`):

1. Detects `.tibx` master file (magic-byte ARCH at offset 8 OR `.tibx`
   extension).
2. Pre-flight: `containers.run(image='wairz-tibx-extractor', command=
   ['--help'], detach=False)` — confirms the side-container image exists
   AND the bind mount is non-empty (entrypoint exits 2 if Acronis missing).
3. `containers.run` with the actual `tibxread get content` argv,
   `detach=True`, `auto_remove=False`. The container writes
   `disk.raw` to `/work` (the `tibx_work` named volume).
4. `wait` with Rule #29 timeout (default 1200 s = 20 min for a 4×4 GB
   `.tibx` set). Capture stderr via `container.logs(stderr=True,
   stdout=False)`.
5. Read `/var/lib/wairz/tibx_work/disk.raw` from the worker side (same
   named volume), copy into the firmware's `extraction_dir/disk.raw`.
6. Set `result.extracted_path = extraction_dir` so the existing
   NTFS/registry/EVTX walker chain picks up the recovered NTFS volume
   transparently (same pattern as `unpack_vhdx`).
7. `container.remove(force=True)` cleanup.

## Failure modes

| Exit | Meaning | Worker response |
|---:|---|---|
| 0 | `disk.raw` populated | success path |
| 2 | tibxread binary not found | `result.error="configure WAIRZ_TIBX_AGENT_PATH"`; firmware row → `failed` |
| 3 | `/work` not writable | `result.error="tibx_work volume unhealthy"`; rebuild required |
| 4 | bad argv | bug — file an issue |
| N | tibxread native failure | passthrough; stderr lands in `unpack_log` |

## Cross-references

- `.planning/research/tibx-deep-2026-05-13/scout-c-sandboxed-extraction.md`
  — architectural rationale
- `.planning/intake/tibx-byob-side-container-architecture-2026-05-13.md`
  — original implementation intake
- CLAUDE.md Rule #36 — no-execute baseline (Exception 3 added in this phase)
- `docker-compose.yml` — service definition + named-volume wiring
- `backend/app/workers/unpack_tibx.py` — worker that spawns this container
