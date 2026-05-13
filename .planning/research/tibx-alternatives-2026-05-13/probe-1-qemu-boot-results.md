---
title: Probe #1 result — QEMU-boot Acronis Recovery PE
date: 2026-05-13
status: PARTIAL-GO (bootx64.efi loads; BCD/volume-GUID layout needs fix)
---

# Probe #1 result — QEMU-boot Acronis Recovery PE (ILLUMISITE)

## TL;DR

**Partial GO.** The customer's Acronis Recovery PE bootloader (`bootx64.efi`)
DOES execute in QEMU + OVMF + `-net none`. The Windows Boot Manager then
fails on a BCD-path/volume-GUID layout mismatch (`0xc000000e`) — a
well-known issue when packaging WinPE boot files into a non-Microsoft-
prepared FAT/ISO container. **Solvable in implementation** via either
(a) a proper UEFI hybrid ISO with embedded `efisys.bin`-style EFI El
Torito boot image, or (b) BCD edit via `hivex`/`chntpw` to point at
our volume GUID. Estimated +2-4h on top of Scout X's 12-16h estimate.

## What we verified

✅ **Customer's PE files are complete + present.** All Boot/, EFI/,
   sources/boot.wim, bootmgr.efi, autorun.* survive the unpack pipeline.

✅ **OVMF UEFI firmware detects a FAT-formatted disk** (FS0 in EFI shell).
   First attempt with an ISO failed — UEFI's auto-boot only looks at
   registered Boot#### variables, not `/EFI/Boot/bootx64.efi`. Second
   attempt with a partition-less FAT32 disk image succeeded.

✅ **`startup.nsh` chain-load works.** Added a one-line `startup.nsh`
   that runs `\EFI\Boot\bootx64.efi`; OVMF EFI shell auto-runs it
   after the 5s timeout, and bootx64.efi loads successfully.

✅ **`-net none` does NOT prevent the PE from starting.** No NIC-related
   pre-boot check failed. (Recovery PE booted with no NIC present.)

✅ **No license/activation dialog at boot time.** The boot proceeded to
   Windows Boot Manager without a "license required" gate.

## What we did NOT verify

❌ **Windows Boot Manager → boot.wim load.** WBM loaded but failed
   immediately with `\EFI\Microsoft\Boot\BCD : 0xc000000e` — "BCD
   missing or contains errors". The BCD file IS in the FAT image (262 KB
   at the expected path), but the BCD's internal references (device GUID,
   partition UUID, volume serial) don't match our FAT volume's actual
   metadata.

❌ **acrocmd-in-PE help/recover.** Couldn't reach the WinPE shell to
   probe Probe #2's `acrocmd help recover` because WBM never handed
   control to boot.wim.

## Root cause of the BCD failure (hypothesis)

Microsoft WinPE ISOs / USB sticks are typically prepared by Microsoft's
`MakeWinPEMedia` tool, which:

1. Builds a FAT32 partition with a specific volume serial
2. Writes a BCD whose boot entry's `device` element references that
   volume by GUID
3. Optionally includes `efisys.bin` (a pre-formatted EFI FAT image)
   embedded as the El Torito boot record on the ISO

Our naive "format FAT, mcopy everything" approach skipped step (2) —
the BCD that landed in our FAT references some volume GUID from when
the customer originally prepared the recovery media, not our volume.

## Three fixes (in increasing engineering cost)

### Fix A — Build a UEFI hybrid ISO with embedded EFI El Torito image
~4-6 h. xorriso `-eltorito-alt-boot -e EFI.IMG -no-emul-boot` shape.
EFI.IMG is a small FAT image (16-64 MB) containing just `EFI/Boot/
bootx64.efi` + `EFI/Microsoft/Boot/{BCD,bootmgfw.efi}`. The BCD inside
EFI.IMG must reference the OUTER ISO (UDF/CDFS) by `ramdisk()`
descriptor rather than by volume GUID. This is the structurally
correct way to mimic Microsoft's WinPE ISO layout.

### Fix B — Live-edit the BCD to point at our FAT volume
~2-3 h. Use `hivex` / `hivexsh` to open the BCD as a Windows registry
hive (BCD is REGF format). Find the boot entry's `device` element +
its `BootDevice` element, replace with a `boot()` or `partition(0,1,
<our-volume-guid>)` descriptor. Tools: `hivexsh -w bcd_path`. Companion
strategy: read the current FAT volume's UUID via `dumpe2fs`/`tune2fs`
or compute from VFAT header, then update BCD to match.

### Fix C — Skip OVMF; use SeaBIOS legacy boot path
~1-2 h. The PE includes `Boot/bootmgr` (legacy BIOS) AND
`Boot/bootfix.bin`. SeaBIOS-mode QEMU with `-boot c` from a partitioned
FAT disk with the right MBR boot sector might bypass the UEFI BCD path
entirely. Worth trying as a quick win — but loses UEFI Secure Boot
parity with how Microsoft tests the PE.

## Recommendation

**Proceed with Scout X's full implementation path; budget +4-6 h on top of
the 12-16 h estimate for Fix A.** The probe proved the fundamentals
work; the BCD/volume layout is engineering, not architecture.

Decision points if engaging implementation:

1. Build a proper UEFI ESP image (Fix A) inside the `tibx-recovery-emulator`
   side-container's entrypoint per-upload — the customer's PE files
   move into a synthesized EFI.IMG at extract time.
2. Inject `startnet.cmd` mutation via `wimupdate` on a scratch copy of
   `sources/boot.wim` to run `acrocmd recover disk --loc=... --arc=...
   --target_disk=2 --service=mms > X:\probe.txt && wpeutil shutdown`.
3. Capture WinPE output via a small FAT scratch disk + Linux post-mount
   read of `probe.txt`. (Required because WinPE doesn't redirect to
   COM by default — modifying boot.wim's `system32\winpeshl.ini` could
   redirect, but is more work than the scratch-disk file path.)

## Operational artifacts cleaned up

- `tibx-probe` Docker image removed
- `wairz_tibx_work` named volume removed (was leftover from the
  reverted BYOB-SC commit)
- `/tmp/tibx-probe/` host scratch dir removed
- No persistent host-side changes

## Time spent

~45 minutes wall-clock. Three probe attempts:

1. ISO with El Torito alt-boot only → UEFI auto-search failed; dropped
   to EFI Internal Shell.
2. FAT32 partition-less disk image without `startup.nsh` → same.
3. FAT32 + `startup.nsh` chain → bootx64.efi loaded, WBM started, BCD
   failed.

## Decision the user should make

A. **Proceed with implementation** (Fix A — UEFI hybrid ISO; ~16-22 h
   total across 2-3 sessions). Probe confirms the fundamentals work.
B. **Defer** until 2nd operator encounter with `.tibx` to justify the
   investment.
C. **Pivot to Acronis Linux Agent install** path (the previously-
   scratched BYOB approach) — operator one-time setup is faster than
   re-engineering the UEFI ISO layout, IF the operator is willing to
   create an Acronis account.

My recommendation: **A** if the user has Acronis-bundled medical/
industrial firmware coming in (i.e. N≥2 expectation); **B** otherwise.
