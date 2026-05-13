---
title: tibx alternative-extraction synthesis (post-BYOB-scratch)
date: 2026-05-13
status: locked
inputs:
  - scout-x-qemu-recovery-pe.md (VERDICT: HOLD pending 2 probes; technically viable)
  - scout-y-wine-acrocmd.md (VERDICT: NO-GO; Wine cannot satisfy 4-layer dep chain)
  - scout-z-format-re-and-frameworks.md (VERDICT: no new OSS path since 2026-05-12)
supersedes_intake: .planning/intake/tibx-byob-side-container-architecture-2026-05-13.md
---

# Synthesis — alternative .tibx extraction paths

## TL;DR — single recommended path

**QEMU-boot the customer's own Acronis Recovery PE inside a wairz side-container.**

The customer's ILLUMISITE upload already carries the full Acronis Recovery PE
extracted at `extracted_boot_wim/`. Booting that PE inside QEMU (mirroring
the existing `system-emulation` FirmAE pattern) gives `acrocmd.exe` the
exact execution context Acronis designed for: full kernel drivers
(`snapapi.sys`, `tdpcl.sys`, `aimas.sys`) loaded, `mms.exe` supervisor
running, registered runtime state intact. This bypasses the
`Archive3_GetDefaultPcsProcess` wall the BYOB path hit AND uses ONLY
binaries the customer already shipped — zero Acronis-redistribution
concern on wairz's side.

## Scout matrix

| Path | Verdict | Why | Cost |
|---|---|---|---|
| **X — QEMU + Recovery PE boot** | **HOLD pending 2 probes** | Technically viable. acrocmd runs in its designed PE-based bootable-media context. Mirrors existing FirmAE/emulation/fuzzing side-container pattern. KB 45856 / 16994 / Cyber Protect 15 CLI Reference confirm the workflow. | 12-16 h dev (2 sessions); ~30 min operator probes first |
| Y — Wine + extracted acrocmd.exe | **NO-GO** | acrocmd is a client to MMS; MMS needs kernel drivers (`snapapi.sys`); Wine has zero kernel-driver support. Same `Archive3_GetDefaultPcsProcess BUG` wall as the BYOB-Linux-Agent path. Zero Wine AppDB entries; zero GitHub successes; community confirmed failure. | — (path closed) |
| Z — Format RE + dissect refresh | **No new OSS path since 2026-05-12** | dissect.archive v1.8 confirmed empty for Acronis. DFRWS/USENIX/NDSS/S&P/arxiv 2024-2026 zero papers. Russian/Chinese forums zero RE. Ghidra-RE of tibxread ~80 h; clean-room parser 6-12 months. Justified only on 2nd operator encounter. | 80h-12mo (deferred until N≥2) |

## Why X works where BYOB failed

The BYOB path hit `Archive3_GetDefaultPcsProcess BUG` because tibxread (and
acrocmd) are CLIENTS to the Acronis Agent's pcs_process supervisor. The
supervisor's "registered runtime state" is populated by the agent's
INSTALL + REGISTRATION flow — NOT just by starting the binary.

Inside a real Recovery PE boot, the Acronis-managed Windows-PE runtime
(boot.wim's `startnet.cmd` typical flow) initializes that registry as
part of the PE startup sequence. The PE was DESIGNED for offline rescue
— so the registration step it does on boot doesn't require cloud
connectivity. acrocmd inside a properly-booted PE finds its supervisor
and works.

Wine can't replicate this because (a) the supervisor needs kernel
drivers Wine doesn't load, and (b) the PE's startup-time registration
flow is what produces the runtime-state files acrocmd expects.

## Three risks Scout X flagged (all probe-resolvable)

1. **License/activation OEM-dependent.** Strong indirect evidence
   (Kingston/Crucial/WD OEM pattern; Acronis docs "recovery always free
   in bootable media") that ILLUMISITE's 2019-era OEM Recovery PE works
   fully offline, but unverified for this specific firmware.
2. **PE may refuse to boot with `-net none`.** QEMU command line denies
   any NIC; if the PE startup checks for one, NO-GO. Most rescue PEs
   tolerate no-NIC, but verification needed.
3. **PE defaults to interactive GUI.** Automation requires injecting
   a `startnet.cmd` script that runs acrocmd unattended. WIM mutation
   via `wimupdate` on a SCRATCH copy of boot.wim (customer's firmware
   bytes never touched on disk). Documented technique; ~50 LOC.

## Operator probes (~30 min total, NO new code)

### Probe #1 — Boot the Recovery PE in QEMU with no network

```bash
# From the host, pointing at the customer's already-extracted PE:
qemu-system-x86_64 \
    -enable-kvm -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/path/to/scratch_ovmf_vars.fd \
    -drive if=ide,format=raw,file=/path/to/scratch_pe.iso,media=cdrom \
    -drive if=ide,format=qcow2,file=/tmp/target.qcow2 \
    -net none \
    -display gtk \
    -serial stdio
```

Build `scratch_pe.iso` via `xorriso -as mkisofs` from the
`extracted_boot_wim/` tree (operator does this once; wairz worker
automates if probe passes).

**Pass criteria:** PE boots to a Windows-PE shell (CMD prompt), no
visible "phone home" attempts, no license/activation dialog blocks
acrocmd.

### Probe #2 — acrocmd help works in the PE

From the WinPE shell:

```cmd
acrocmd help recover
```

**Pass criteria:** Non-empty help text emitted, no "license required"
dialog, no MMS connection failures (MMS should auto-start under PE).

## Implementation skeleton (if probes pass)

Mirrors the existing `system-emulation/Dockerfile` pattern:

### Stream 1 — `tibx-recovery-emulator` side-container

- `tibx-recovery-emulator/Dockerfile`:
  - Base: `ubuntu:22.04`
  - Install: `qemu-system-x86`, `ovmf` (UEFI firmware), `wimtools` (WIM
    mutation), `xorriso` (ISO build), `python3-flask` (HTTP shim for
    worker→container API)
  - Bundle: a `startnet.cmd` template that auto-runs acrocmd with
    operator-provided args
  - Image size: ~700 MB
- `tibx-recovery-emulator/entrypoint.py` (Flask shim):
  - `POST /extract` → builds scratch PE ISO with mutated `startnet.cmd`,
    spawns `qemu-system-x86_64`, waits for completion via `-serial`
    pipe, returns disk.raw path
- `docker-compose.yml`: new service `tibx-recovery-emulator`,
  `profiles: ["build"]`, full hardening (`network_mode: none`,
  `read_only: true`, `cap_drop: ALL`, non-root, resource limits)
- New named volume `tibx_recovery_work` for the disk.raw output

### Stream 2 — `unpack_tibx.py` worker

Mirrors the reverted unpack_tibx but with QEMU side-container
invocation instead of Docker-exec'd tibxread:

1. Validate master slice (ARCH magic at offset 8) — same as before
2. POST to side-container's `/extract` endpoint with:
   - Recovery PE path (read-only bind)
   - `.tibx` master path + continuation slice paths (read-only bind)
   - acrocmd argv:
     `recover disk --loc=/data --arc='Archive(1)' --disk=1 --target_disk=2 --service=mms`
3. Wait with Rule #29 timeout (1800 s — bigger than tibxread since QEMU adds boot+restore overhead)
4. Read `/var/lib/wairz/tibx_recovery_work/disk.raw` (named volume bind on worker)
5. Copy into `extraction_dir/disk.raw`
6. Set `result.extracted_path = extraction_dir` — existing NTFS walker chain takes over

### Stream 3 — Capability + tests + Rule #36 amendment

- `format_detection.py`: capability `NONE → PARTIAL` (PARTIAL because
  it depends on the customer's upload having a recovery PE)
- `CAPABILITY_NOTES[ACRONIS_BACKUP]`: update to describe the new
  recovery-PE-driven workflow ("if the upload includes an Acronis
  Recovery PE in `sources/boot.wim`, wairz can extract the .tibx via
  QEMU; otherwise operator must install Acronis Linux Agent")
- `test_unpack_tibx.py`: mock-Docker-SDK tests for the worker
- CLAUDE.md Rule #36 Exception 3: "vendor-supplied parser binaries
  RUNNING INSIDE A FULL OS EMULATION (QEMU + customer-provided OS
  image) as the operator's-own-data restoration flow". Same
  Rule-of-Two precedent class as the BYOB exception we previously
  drafted, but stronger isolation (full VM vs hardened userspace
  container).

## Key technical gotchas captured by scouts

- **WinPE is virtio-blind** — use `-drive if=ide` for input/output
  volumes; `if=virtio` causes `INACCESSIBLE_BOOT_DEVICE`.
- **TIBX cannot be mounted as a virtual disk** (KB 63425) — full
  restore is the only Acronis-supported shape. wairz output is
  `disk.raw`, not a live-mount.
- **4-file ILLUMISITE chain is ONE chained backup** — master
  `Archive(1).tibx` + slices `-0001/-0002/-0003`. acrocmd discovers
  the slices automatically; we pass only the master `--arc`.
- **OVMF non-secboot variant** works for the unsigned Acronis PE;
  if the PE is Secure Boot signed, switch to `OVMF.secboot.fd` +
  MS UEFI CA enrolment.
- **acrocmd command syntax** (canonical, per Scout Y bonus +
  Scout X confirmation):
  ```
  acrocmd recover disk --loc=<dir-of-tibx> \
                       --arc='Archive(1)' \
                       --disk=1 \
                       --target_disk=<N> \
                       --service=mms
  ```
  Note: no `--target_disk=file:...` form; target is a virtual disk
  number, hence the secondary QEMU drive.

## Recommended priority (no-Acronis-cloud-account paths only)

1. **(30 min, operator)** Probe #1 + Probe #2 — manual QEMU boot to
   resolve the 3 risks Scout X flagged.
2. **(2 sessions, ~16 h dev)** If probes pass: ship the
   `tibx-recovery-emulator` side-container + `unpack_tibx.py` worker
   + capability flip + tests + Rule #36 amendment.
3. **(Shippable today, no Acronis)** From Scout Z's recommendation:
   - Recovery-PE walker validation against the EXISTING boot.wim
     extraction. Already done this session (commits 5c19490 + 78f7c6b)
     — 322 driver packages + 9 BCD entries + 1 WMI binding + 3
     signed-valid EFI files + 2 findings stamped on ILLUMISITE.
4. **(Deferred indefinitely)** Format RE — only justified at 2nd
   operator encounter with `.tibx` in a non-recovery-PE-bundled upload.

## What's NOT in scope here

- **No format reverse engineering.** Scout Z confirms 80h-12mo cost;
  justification floor is N≥2 operator encounters.
- **No Wine attempt.** Scout Y NO-GO is unambiguous; kernel-driver
  dependency is non-negotiable.
- **No Acronis cloud / account creation.** User explicitly scratched
  the BYOB-Linux-Agent path; the QEMU approach uses ONLY the
  customer's own binaries from THEIR own upload.

## Suggested first action

**Operator runs Probe #1 + Probe #2** on a workstation with QEMU + KVM.
~30 min wall-clock. Result determines whether the implementation
streams are worth spinning up.

If the operator wants wairz to attempt Probe #1 instead (the host
has Docker; QEMU could run inside a one-off Docker container against
the existing ILLUMISITE files; no host-system changes needed), the
probe is feasible from this environment but should be explicitly
authorised.

DONE — synthesis locked.
