---
title: Scout C — Sandboxed-extraction architecture for `.tibx` support
date: 2026-05-13
scout: C (infrastructure / security-architecture)
brief: tibx-support-research-brief-2026-05-12.md
verdict: GO via BYO-binary side-container (BYOB-SC); HOLD on bundled-binary or Wine paths
---

# Scout C — Sandboxed-extraction architecture for `.tibx`

## TL;DR — recommended architecture

**Bring-your-own-binary side-container (BYOB-SC).** Wairz ships an
empty hardened `tibx-extractor` Docker service definition; the
operator installs Acronis Cyber Protection Agent for Linux on the
host, points `WAIRZ_TIBX_AGENT_PATH` at the host installation, and the
side-container bind-mounts that directory read-only at runtime. Wairz
itself never redistributes any Acronis binary — sidesteps the EULA's
hard prohibition on redistribution outright. The side-container is
the security boundary; the wairz worker only consumes its `disk.raw`
output. Rule #36 is preserved with a new explicit exception class:
*vendor-supplied parser binaries operating on customer data **as
data** inside an isolated side-container, mirroring qemu-img and
signify in the worker tier but moved out for sandboxing strength*.

If the operator has not installed Acronis, the side-container starts
healthy but the unpack worker emits a clear "configure
`WAIRZ_TIBX_AGENT_PATH` or use Acronis Recovery + VHDX export" error
and the firmware row's `upload_stage` transitions to `failed` with an
actionable message. This matches the existing `unblob --no-sandbox`
graceful degradation pattern (Rule #34).

## 1. Acronis Linux CLI availability

**Canonical tool: `tibxread`** (not `acrocmd`, not `trueimagecmd`).
The Acronis docs describe it as a "tool for manual check of the
backed-up disk integrity" with these four commands: `list backups`,
`list content`, `get content`, `calculate hash`.[^tibxread] Most
relevant to wairz: **`tibxread get content` writes raw disk bytes to
stdout from a local-path location URI** — exactly the shape wairz
needs (TIBX → disk.raw → existing NTFS/registry/EVTX walker chain
takes over transparently, mirroring `unpack_vhdx.py`'s contract).

Example invocation (per Acronis docs):

```
tibxread get content --loc=/var/tmp --arc=backup.tibx \
    --backup=<RECOVERY_POINT_ID> --disk=1
# → raw disk bytes on stdout
```

The tool ships **bundled with Agent for Linux** (
`Cyber_Protection_Agent_for_Linux_x86_64.bin` installer; deployed
under `/usr/lib/Acronis/BackupAndRecovery/`), Agent for Windows, and
Agent for Mac.[^agentpath] It is not distributed as a standalone
binary. Acronis does ship a 30-day free trial of Cyber Protection
that includes the Linux agent, plus a fully-featured commercial
edition; the OEM editions bundled by Kingston/Crucial/WD/Advantech do
not include the Linux agent.

**Licensing: redistribution is forbidden.** The Acronis EULA Section 2
explicitly states the operator agrees not to "sublicense, lease,
rent, loan, transfer, or distribute the Software, or any portion …
to any third party," and the EULA does not carve out "internal use,"
"open-source bundling," or "self-license-provided shipping."[^eula]
**Wairz cannot ship the Acronis binary in a Docker image.** This
single constraint eliminates Path 1 (bundled binary) entirely.

## 2. Wine-based approach — discarded

Wine could in principle run the Windows Acronis CLI inside a side-
container, sidestepping the Linux-agent dependency. **Discarded for
three reasons:**

1. **Storage stability.** Acronis True Image performs sector-level
   disk operations against virtual block devices it constructs from
   the TIBX bitmap. Wine's lag on storage / block-device / file-handle
   semantics is well documented; Acronis themselves recommend the
   Linux bootable rescue media over Wine for any Linux-side
   operation.[^wineacronis] Silent corruption risk on a sector
   pipeline is unacceptable — silently truncating a `disk.raw` halfway
   through is the worst possible failure mode (Rule #17 class —
   indistinguishable from success without forensic-grade verification
   per recovery point).

2. **Image weight.** Wine + .NET + mono brings the side-container to
   1.5–2 GB on top of the Acronis binary itself. Rule #36's no-execute
   discipline scales: bigger attack surface inside the sandboxed
   container is still attack surface.

3. **Redistribution is still a problem.** Wine sidesteps the Linux-
   agent dependency but does not sidestep the EULA. Whether wairz
   ships the *Windows* Acronis binary inside Docker, or the *Linux*
   one, the EULA's redistribution prohibition applies identically.

## 3. Container security boundary design (BYOB-SC)

Mirrors the existing `emulation` (QEMU) + `fuzzing` (AFL++) + `system-
emulation` (FirmAE) side-container precedents in
`docker-compose.yml:324-392`. Hardening sourced from the Docker
Security cheat sheet,[^docker-sec] OWASP container security
guidance,[^owasp-docker] and the Tecnativa docker-socket-proxy
pattern wairz already uses.

**Service definition (proposed delta in `docker-compose.yml`):**

```yaml
tibx-extractor:
  profiles: ["build"]
  build:
    context: ./tibx-extractor
    dockerfile: Dockerfile
  image: wairz-tibx-extractor
  read_only: true
  tmpfs:
    - /tmp:size=64M,mode=1777,noexec,nosuid,nodev
  security_opt:
    - no-new-privileges:true
    - seccomp=unconfined   # tibxread needs ioctl variety; tighten later
  cap_drop:
    - ALL
  network_mode: none
  pids_limit: 64
  user: "65534:65534"   # nobody:nogroup — non-root
  volumes:
    # Operator-supplied Acronis install — read-only at runtime
    - ${WAIRZ_TIBX_AGENT_PATH:-/dev/null}:/opt/acronis:ro
    # Customer firmware data — read-only
    - firmware_data:/data/firmware:ro
    # Output sink — write-only via worker put_archive (no host bind)
    - tibx_work:/work
  deploy:
    resources:
      limits:
        memory: 2048M
        pids: 128
        cpus: "2.0"
```

**Hardening rationale, line by line:**

- **`read_only: true` + tmpfs**: tibxread writes nothing to its rootfs;
  scratch space lives in 64 MB tmpfs. Even if tibxread is compromised,
  the rootfs is non-writable. Matches OWASP-D-21 (immutable
  containers).[^owasp-docker]
- **`security_opt: no-new-privileges`**: prevents setuid escalation,
  which is the standard escape path from a confined non-root
  process.[^raesene-nnp]
- **`cap_drop: ALL`**: tibxread is a userspace reader — no kernel
  capabilities needed. Drop everything; add nothing back.
- **`network_mode: none`**: tibxread takes a local-path URI and writes
  to stdout. Zero network egress. Network-isolated container cannot
  be a C2 staging post even if compromised; cannot leak TIBX content
  to attacker-controlled DNS / HTTP.
- **`user: 65534:65534`**: explicit non-root. wairz worker tier
  already runs as `wairz:wairz` (`backend/Dockerfile`); the
  extractor's nobody:nogroup is a deeper drop.
- **`pids_limit: 64`** + `cpus: "2.0"` + `memory: 2048M`: bounded fork
  bomb / runaway. Single TIBX extraction is single-process; 64 PIDs
  is generous.
- **`/opt/acronis:ro`**: operator's host-installed Acronis directory
  mounted read-only — tibxread cannot self-modify or write back to
  the host installation.
- **`firmware_data:/data/firmware:ro`**: customer's `.tibx` files
  visible read-only. Even an unbounded tibxread bug cannot scribble
  on other firmware data.
- **`tibx_work:/work`** as a named volume scoped to this service
  alone — output `disk.raw` lands here, worker reads it after the
  extractor exits. Not a host bind mount, so cannot escape the
  sandbox via path traversal.

**Worker-to-extractor API.** Mirror the existing emulation pattern
(`backend/app/services/emulation/docker_ops.py`): the worker uses the
Docker SDK against the `docker-proxy` ambassador (already in
`docker-compose.yml:39-74`, narrow CONTAINERS+POST+EXEC privileges).
Worker `run` spec:

```python
container = client.containers.run(
    image="wairz-tibx-extractor",
    command=[
        "/opt/acronis/usr/lib/Acronis/BackupAndRecovery/tibxread",
        "get", "content",
        "--loc", "/data/firmware/<project>/<firmware>",
        "--arc", "<basename>.tibx",
        "--backup", "<recovery_point_id>",
        "--disk", "1",
    ],
    detach=True,
    stdout=True,  # capture to /work/disk.raw via shell redirect
    auto_remove=False,  # we read logs + exit code first
)
```

Output via `container.logs(stdout=True, stream=False)` to capture stdout
(the raw disk bytes), written to the named volume's `/work/disk.raw`
via a wrapping `sh -c 'tibxread get content … > /work/disk.raw'`. The
worker then reads `/work/disk.raw` from the same named volume (also
mounted into the worker) and copies into the firmware's
`extraction_dir/disk.raw`. Same shape as `unpack_vhdx.py`'s
qemu-img output contract, just one Docker hop further out.

**Failure / timeout / hang.** Per Rule #29 the side-container call
sits in the 600 s tier (matches `_QEMU_IMG_CONVERT_TIMEOUT_SECONDS` in
`unpack_vhdx.py:52`); 4 GB TIBX → 4 GB disk.raw is comparable IO
workload. Past the timeout, `container.kill()` + `container.remove()`
takes ~1 s; the worker emits an `unpack_log` failure and the
firmware row's `upload_stage` transitions to `failed`. Idempotent
retry is safe because the side-container is stateless. The named
volume `/work` is `rmtree`'d before the next attempt.

## 4. Bring-your-own-binary architecture — the picked path

**Configuration switch:** `WAIRZ_TIBX_AGENT_PATH` env var in `.env`,
default unset. When unset, the `tibx-extractor` service skips the
bind mount (defaults to `/dev/null`, which Docker accepts as a stub
"file"). The wairz unpack worker detects the missing binary by
`exec`-ing `/opt/acronis/usr/lib/Acronis/BackupAndRecovery/tibxread
--version` first; on `FileNotFoundError` it emits:

```
TIBX extraction requires Acronis Cyber Protection Agent for Linux.

Wairz cannot redistribute the Acronis binary (EULA §2 prohibits
redistribution). Install Acronis on the host machine, then set:

    WAIRZ_TIBX_AGENT_PATH=/   # host root, OR a narrower path
                              # containing /usr/lib/Acronis

in .env and rebuild via `docker compose up -d --build tibx-extractor`.

Alternative: boot Acronis Recovery Media against the .tibx in a
separate VM, export VHDX, re-upload to wairz.
```

This is the canonical Rule #34-class failure path: missing optional
dependency → clear actionable error, no silent crash.

**Operator workflow on first encounter:** identical to the existing
UART-bridge / device-bridge bring-your-own pattern documented in
CLAUDE.md ("UART Bridge Architecture" + "Device Acquisition Bridge"
sections). Operator installs Acronis once, sets one env var,
rebuilds one container. Subsequent firmware uploads work
transparently.

**Mount layout.** Acronis Agent for Linux installs under several host
directories (`/usr/lib/Acronis/`, `/var/lib/Acronis/`, `/etc/Acronis/`,
`/opt/acronis/`, `/var/log/Acronis/`). For tibxread specifically only
`/usr/lib/Acronis/BackupAndRecovery/` matters — but tibxread may
shared-link against libraries elsewhere in `/usr/lib/Acronis/`. Pick
the broadest sensible mount: `${WAIRZ_TIBX_AGENT_PATH}:/opt/acronis:ro`
where the operator points at `/` (full host root, RO) or `/usr/lib`
(narrower). Document both options; default to full-root mount with a
note that operators in shared environments may narrow it.

## 5. Rule #36 reinterpretation

Rule #36 (no-execute) was authored against **installer custom
actions** — attacker-supplied code that wants to run **against
customer data** inside the worker. The MSI / MSU / driver-package
unpackers extract those CAs to disk and surface them to the operator
as data; they never invoke `wine CustomAction.exe`. Customer data is
untrusted; the unpacker reads it as bytes.

**The Acronis CLI is a different shape:**

- **Vendor binary** (Acronis, supplied by operator's existing licensed
  install) — *trusted*.
- **Customer data** (`.tibx` files inside the firmware tree) — still
  *untrusted*.
- **Operation:** the vendor binary **reads** the customer data as
  data and **emits** disk bytes; it does not transfer control to
  customer-supplied code.

This is the **same shape** as Rule #36's existing documented
exceptions: `qemu-img convert -f vhdx -O raw` (qemu-img is a trusted
image-shipped binary reading the VHDX as data), `signify` (trusted,
reads PE files as data for chain validation), `ilspycmd` (trusted,
reads .NET DLLs as data for decompilation). The shape is preserved.

**Two differences from the existing exceptions, both addressed by the
side-container design:**

1. **The binary is not image-shipped.** Operator-supplied via host
   bind mount. Provenance is the operator's existing Acronis license;
   wairz never sees it during build. The trust model is unchanged
   from the operator-trust-the-tools axiom wairz already relies on
   (operators trust radare2, Ghidra, AFL++).
2. **The binary is closed-source.** Unlike qemu-img / signify /
   ilspycmd, wairz cannot audit Acronis source. The
   **side-container with `cap_drop: ALL` + `network_mode: none` +
   `read_only` + tmpfs scratch** is the architectural answer to this:
   we don't need to trust the binary's *behavior*, only the kernel's
   ability to confine it. The side-container is the security
   boundary; the wairz worker only consumes its bytes.

**Proposed amendment to Rule #36** (text for CLAUDE.md, not applied in
this scout — Rule #21 sync discipline):

> **Exception 3 — Trusted vendor parser binaries in isolated side-
> containers operating on customer data AS DATA.** When a vendor-
> supplied parser binary (e.g. Acronis `tibxread`, future commercial
> CAD/EDA parsers, future closed-source partition tools) reads
> customer-controlled bytes and emits derivative bytes (raw disk
> image, decompiled output, structural metadata), and the binary
> cannot be redistributed (vendor EULA forbids), wairz MAY invoke it
> inside a hardened side-container that meets ALL of the following:
> `read_only: true` rootfs, tmpfs scratch with noexec/nosuid/nodev,
> `network_mode: none`, `cap_drop: ALL`, `security_opt: no-new-
> privileges`, non-root user, pids/cpu/memory limits per Rule #29,
> operator-supplied binary via read-only host bind mount, output
> consumed by the worker via a named volume only. The wairz worker
> remains the security boundary; the side-container is itself
> sandboxed.

This amendment preserves Rule #36's letter (no execution against
customer data **inside the worker**) and its spirit (the worker is
the security boundary; defense-in-depth applies elsewhere).

## 6. Operator UX

Per the 2026-05-12 upload-stage pipeline (`upload_stage`:
`detecting → extracting → analyzing → ready`,
`backend/app/services/firmware_service.py:549-747`), TIBX fits inside
`extracting` natively. The upload flow becomes:

| Stage | Time (Medtronic 4×4GB TIBX, modern x86_64) | Operator sees |
|---|---|---|
| upload | 30-90s (HTTP POST + dedup) | progress bar |
| detecting | <2s (magic check) | "Detecting format…" |
| **extracting** | **8-20 min** (4 × tibxread invocations) | "Extracting Acronis backup (1 of 4)…" |
| analyzing | 1-3 min (arch/OS/kernel) | "Analyzing…" |
| ready | — | NTFS / registry / EVTX walkers fire automatically (Rule #47) |

**8-20 minutes** is well outside the 30s axios floor and the 100s
reverse-proxy ceiling (Rule #29 caveat), but **firmware unpack is
already 202+polling** (per `routers/firmware.py:139` precedent and the
`upload_stage` polling endpoint at `routers/firmware.py:179-198`).
TIBX inherits this transparently — no new long-op endpoint needed.

**Progress reporting.** The unpack worker calls a `progress_callback`
during extraction (existing contract in
`backend/app/workers/unpack_*.py`); for TIBX, the worker emits
"Extracting recovery point N of M" before each tibxread invocation,
plus byte-progress if tibxread supports `--progress` (per Acronis
docs the `get content` and `calculate hash` subcommands accept
`--progress`).[^tibxread] Frontend polls `upload_stage` every 2 s and
re-renders.

**First-time operator without Acronis installed.** Upload → detecting
→ extracting (fails immediately, <2 s) → failed, with the clear
error message above. No silent hang; no progress bar stuck at 30%.

## Architecture decision matrix

| Path | Legal? | Stable? | Sandbox strength | Operator burden | Recommended |
|---|---|---|---|---|---|
| Bundle Acronis in Docker image | NO (EULA §2) | yes | strong | low | NO |
| Wine + bundled Windows binary | NO (EULA §2) + stability risk | medium | strong | low | NO |
| Wine + BYO Windows binary | yes | medium (storage flakiness) | strong | medium | NO (stability) |
| **BYO Linux binary + hardened side-container** | **yes** | **high** | **strong** | **medium** | **YES** |
| Detection-only stub (no extraction) | yes | n/a | n/a | high (manual VHDX export) | fallback only |

## Recommended cut shape

If the user approves GO on BYOB-SC, the implementation cuts as
follows (3-4 streams under Rule #25 per-sub-task commit discipline,
matching Rule #27's "N additive + 1 cut-over" if a class-shape
refactor lands; Rule #39 inner/outer/safe-runner pattern for the
worker side):

1. **Stream A — side-container Dockerfile + compose service**
   (`tibx-extractor/Dockerfile`, ~30 LOC; compose delta ~25 LOC; env
   var documentation; refresh of `.env.example`). No backend code.
2. **Stream B — `unpack_tibx.py` worker** (~250 LOC; mirrors
   `unpack_vhdx.py` shape; container.run via docker-proxy;
   recovery-point enumeration via `tibxread list backups`; per-disk
   extraction loop; Rule #29 timeout + Rule #34 missing-binary
   graceful fail; named-volume copy into firmware extraction_dir).
3. **Stream C — strategy registration + magic detection** (single
   line in `extraction_strategies.STRATEGIES`; magic-byte detector in
   `format_detection.py` — pending Scout A's magic-byte finding).
4. **Stream D — Rule #36 amendment** (CLAUDE.md + `.mex/context/
   conventions.md` mirror per Rule #21; one commit covering both
   files atomically per Rule #25's "single-slice cross-stack
   alignment" exception).

Tests: standard `backend/tests/test_unpack_tibx.py` with a synthetic
fixture (cannot redistribute a real Acronis-encrypted sample — would
inherit the same EULA problem); mock the docker.containers.run call
and assert command shape per Rule #35.b mock discipline; live canary
gated on `WAIRZ_TIBX_AGENT_PATH` being set on the developer host. The
Rule #46 canary requirement applies: a test gate that asserts
"command never invokes anything outside `/opt/acronis/`" needs a
paired canary synthesizing a violation to confirm it fires.

## Open questions for the user

1. **Magic-byte detection.** Scout A's task. Without a magic byte
   wairz cannot detect `.tibx` automatically; the worker would fall
   back to extension-based detection (acceptable, but less robust
   against renamed files).
2. **Multi-disk TIBX.** Scout A's task. tibxread `--disk=N` selects
   one disk per invocation. If a `.tibx` contains multiple disks,
   the worker loops; each becomes a separate `disk_N.raw`. The
   wairz walker chain handles multi-disk firmware already (Rule
   #16 `get_detection_roots`).
3. **Encrypted TIBX.** Some `.tibx` are AES-encrypted with a
   user-supplied password. `tibxread get content --password
   <pw>` accepts it; wairz would need a per-firmware-row optional
   password field (DB migration, schema, API). Not in the MVP cut.
4. **`WAIRZ_TIBX_AGENT_PATH` UX.** Should the frontend's project-
   settings page expose this as a configurable field, or stay env-
   var-only? Recommend env-var-only for the MVP (mirrors the UART /
   device bridge pattern; configurable knobs that affect Docker
   service definitions don't belong in the per-project settings
   layer).

[^tibxread]: [The tool "tibxread" for getting the backed-up data — Acronis Cyber Protection docs](https://dl.managed-protection.com/u/cyberprotect/help/15/user/en-US/tool-tibxread-for-getting-backed-up-data.html)
[^agentpath]: [Acronis Cyber Protect 15: Linux components, services, and processes](https://kb.acronis.com/content/67276)
[^eula]: [Acronis End User License Agreement, Section 2](https://www.acronis.com/en/support/eula/)
[^wineacronis]: [Acronis True Image: unsupported CPU and operating systems](https://kb.acronis.com/content/62562); [Acronis TrueImage for my Linux partition? — Acronis Forum](https://forum.acronis.com/forum/acronis-true-image-2018-forum/acronis-trueimage-my-linux-partition)
[^docker-sec]: [Docker Security — OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
[^owasp-docker]: [Define services in Docker Compose — security_opt, cap_drop, read_only, tmpfs](https://docs.docker.com/reference/compose-file/services/)
[^raesene-nnp]: [Docker Capabilities and no-new-privileges — raesene blog 2019](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)

## Sources

- [tibxread tool documentation (Cyber Protection 15)](https://dl.managed-protection.com/u/cyberprotect/help/15/user/en-US/tool-tibxread-for-getting-backed-up-data.html)
- [tibxread tool documentation (Cyber Protection 21.03)](https://dl.managed-protection.com/u/baas/help/21.03/user/en-US/tool-tibxread-for-getting-backed-up-data.html)
- [Acronis Linux components, services, processes (kb.acronis.com/content/67276)](https://kb.acronis.com/content/67276)
- [Acronis End User License Agreement](https://www.acronis.com/en/support/eula/)
- [Acronis True Image unsupported OS — kb.acronis.com/content/62562](https://kb.acronis.com/content/62562)
- [Installing protection agents in Linux — Acronis docs](https://www.acronis.com/en/support/documentation/CyberProtectionService/installing-agents-linux.html)
- [Docker Security cheat sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Define services in Docker Compose — reference](https://docs.docker.com/reference/compose-file/services/)
- [Docker Capabilities and no-new-privileges — raesene 2019](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)
- [Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [Tecnativa docker-socket-proxy (wairz uses)](https://github.com/Tecnativa/docker-socket-proxy)
- [Acronis True Image free 30-day trial (Linux agent)](https://www.acronis.com/en/products/true-image/trial/)
- [Acronis Cyber Protect: Installation files](https://care.acronis.com/s/article/71847-Acronis-Cyber-Protect-Links-to-download-installation-files)
- [Support for OEM Versions of Acronis Products — kb.acronis.com/content/2201](https://kb.acronis.com/content/2201)
- [How to Personalize Unattended Acronis Agent Installation on Linux](https://www.acronis.com/en/blog/posts/how-to-personalize-unattended-acronis-agent-installation-on-linux/)
- [wairz `docker-compose.yml` — emulation / fuzzing / system-emulation side-container precedents](file:///home/dustin/code/wairz/docker-compose.yml)
- [wairz `backend/app/workers/unpack_vhdx.py` — closest worker precedent (TIBX→disk.raw mirrors VHDX→disk.raw)](file:///home/dustin/code/wairz/backend/app/workers/unpack_vhdx.py)
- [wairz `backend/app/services/emulation/docker_ops.py` — Docker SDK worker-side container pattern](file:///home/dustin/code/wairz/backend/app/services/emulation/docker_ops.py)
- [wairz CLAUDE.md Rule #36 (no-execute) and the qemu-img / signify exceptions](file:///home/dustin/code/wairz/CLAUDE.md)
