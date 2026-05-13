---
title: Probe #2 result — BCD hivex/byte patch (Fix B) does NOT bypass 0xc000000e
date: 2026-05-13
status: NO-GO on Fix B; Fix A (proper UEFI hybrid ISO via Microsoft ADK) is the only remaining path
relates_to: probe-1-qemu-boot-results.md
---

# Probe #2 result — Fix B (BCD edit) cannot get past `0xc000000e`

## TL;DR

**Fix B (live-edit BCD via hivex / byte-patch) FAILED.** After patching
all four PARTITION-type (5) device descriptors → BOOT-type (6) in the
extracted BCD, Windows Boot Manager STILL halts with
`0xc000000e` "BCD missing or contains errors".

This eliminates the cheaper of the three fixes Scout X proposed. The
remaining path is **Fix A** — build a proper Microsoft-WinPE-ISO-style
UEFI hybrid ISO with embedded `efisys.bin` FAT image, OR use
Microsoft's `MakeWinPEMedia` (which requires a Windows host).

## What I tried

1. **hivex-targeted patch:** opened BCD as a registry hive (it IS a
   REGF file), located the SDI Device Options object
   `{7619dcc8-fafe-11d9-b411-000476eba25f}` Element `31000003`
   (RamdiskDevice). Changed device type DWORD at offset 16 from
   `05 00 00 00` (PARTITION) to `06 00 00 00` (BOOT). committed.
   Result: same `0xc000000e`.
2. **Broader hivex patch:** also targeted OS Loader
   `{7619dcc9-fafe-11d9-b411-000476eba25f}` Elements `11000001`
   (ApplicationDevice) + `21000001` (OSDevice). Found the outer
   bytes at offset 16 are already `00 00 00 00` (placeholder — uses
   child GUID reference), so nothing to patch there. The "real"
   PARTITION reference is inside the SDI Device Options object,
   already patched in step 1.
3. **Brute-force byte-level patch:** scanned the entire BCD file
   for `05 00 00 00` followed by a reasonable length DWORD. Found
   4 occurrences; replaced all with `06 00 00 00`. Rebuilt FAT
   image with patched BCD at both `\Boot\BCD` AND `\EFI\Microsoft\
   Boot\BCD`. Fresh OVMF_VARS. Result: same `0xc000000e`.

## Why Fix B is insufficient

Microsoft's BCD device descriptors are NOT just a single type field.
The full structure includes:

- Parent GUID (16 bytes)
- DeviceType (4 bytes)
- Flags (4 bytes)
- Length (4 bytes)
- Type-specific payload (PARTITION: signature+offset; RAMDISK: source
  device descriptor + path)
- Potentially: signed/hashed integrity check across the whole hive

Even if every PARTITION-type field flips correctly, the BCD's internal
GUID cross-references + (suspected) integrity hashes can mismatch.
Windows Boot Manager's `BcdLib` parser validates these holistically.

The 4 type-5 → type-6 patches likely DID break the integrity checks,
which is what now triggers `0xc000000e` instead of an unknown-device
error. We're trading one error for another.

## What Fix A (UEFI hybrid ISO) requires

The structurally-correct approach mimics Microsoft's WinPE ISO layout:

1. Build a small FAT image (~16 MB) containing:
   - `efi\boot\bootx64.efi` (UEFI loader)
   - `efi\microsoft\boot\BCD` (a Microsoft-PE-style BCD — built by
     Microsoft tooling, not synthesized)
2. Embed that FAT image as the El Torito boot record in an ISO9660
   hybrid that ALSO carries:
   - The rest of the PE files (boot.wim, sources, etc.) at the ISO
     root
3. Attach the ISO as a CDROM device to QEMU; UEFI auto-finds the El
   Torito boot record + loads the EFI FAT image.

The catch: **synthesizing a working BCD from scratch on Linux is the
hard part.** Microsoft's BCD library is closed-source; reverse-
engineered libraries (libbcd, etc.) exist but are incomplete /
research-grade. The only reliable way to produce a valid Microsoft
PE BCD is to use Microsoft's tools (`bcdedit`, `MakeWinPEMedia`,
`oscdimg`) — which require Windows.

## Strategic implications

Three viable architecture branches:

### Branch 1 — Require Windows host for PE-ISO construction

wairz ships a SCRIPT that operators run on a Windows host once:
```
PS> MakeWinPEMedia /ISO <customer-PE-dir> <output.iso>
```
The operator uploads the resulting `.iso` to wairz; wairz boots it in
QEMU; acrocmd runs against the .tibx. Same EULA exposure as the
Acronis-bundled-binary path (zero — operator owns their own PE and
Microsoft tooling).

**Cost:** ~2h of script-authoring + docs. **Operator burden:** must
have a Windows machine accessible for one-time PE-to-ISO conversion.

### Branch 2 — Pre-built Microsoft WinPE base image

wairz ships a generic UEFI-bootable Microsoft WinPE ISO (built once
by wairz developers using Microsoft ADK on a Windows machine). For
each upload, wairz INJECTS the Acronis Recovery binaries from the
customer's boot.wim into the generic ISO's `[Program Files]` location
+ writes a startup.cmd that runs acrocmd. The generic Microsoft BCD
+ bootmgr + efisys.bin layout is what makes the boot work.

**Cost:** ~4-6h to build the generic WinPE ISO recipe + the
per-upload injection logic. **Operator burden:** zero (wairz ships
the generic PE). **Licensing risk:** Microsoft WinPE is part of ADK
and has redistribution restrictions; wairz may need to either
(a) build the WinPE ISO per-operator using Microsoft tooling they
provide, OR (b) bundle only the Microsoft-signed bootmgr+efisys
binaries without the WinPE OS itself (operator's customer-supplied
boot.wim becomes the OS payload).

### Branch 3 — Accept .tibx as opaque, deepen non-Acronis paths

Per Scout Z's recommendation: ship the recovery-PE walker findings
we already have (322 driver packages + 9 BCD entries + WMI binding
+ EFI files in DB), accept the .tibx-encrypted payload as out of
reach. Defer .tibx parsing until either (a) a second operator
encounter justifies the investment, OR (b) an OSS dissect plugin
emerges (Fox-IT dissect.archive is the most likely place — currently
empty, no PR in flight).

## Decision matrix update

| Branch | Cost | Operator burden | Risk | Recommendation |
|---|---|---|---|---|
| 1 — Windows host for ISO build | ~2h | One-time Windows step per operator | Low | **VIABLE** |
| 2 — Pre-built Microsoft PE base | ~6h | Zero | Microsoft-WinPE-licensing review needed | **VIABLE pending licensing** |
| 3 — Accept opacity | 0h | Zero | Lose the .tibx payload | **Default if 1/2 won't ship** |

## What's NOT on the table anymore

- Fix B (BCD edit on Linux) — this probe disproved it. Removed from
  the path list. Even byte-patching all PARTITION descriptors did
  not bypass `0xc000000e`.
- BYOB-Linux-Agent (the reverted approach) — operator scratched.
- Wine + acrocmd.exe — Scout Y NO-GO.
- Format reverse engineering — Scout Z multi-month estimate; out of
  scope.
- QEMU + Linux Acronis Agent — Acronis EULA requires registration
  even in container deployments.

## What I recommend

**Default to Branch 3 (accept opacity).** Operator's value-realised
so far this session is substantial:

- 322 driver packages detected (boot.wim WinSxS)
- 1 SYSTEM hive in the DB
- 9 BCD entries parsed
- 1 WMI binding
- 3 signed-valid EFI files (bootmgr.efi, bootmgfw.efi, memtest.efi)
- 2 security findings (high-sev update mechanism + info CIRCL hash)
- ~50 MCP tools queryable against this corpus

The .tibx-side payload represents the FULL Windows installation, which
would multiply the artefact count, but the recovery PE walker
findings already represent the Acronis-managed components that are
the most forensically interesting class (Acronis is the unique
adversary surface for this firmware; the embedded Windows is
generic).

If a 2nd Acronis-bundled firmware lands (Advantech/Kontron/Kingston/
WD OEM medical/industrial), revisit Branch 1 or 2. Until then, the
ROI on .tibx parsing doesn't justify the engineering investment.

## Probe artifacts cleaned up

- `tibx-probe2` Docker image removed
- `/tmp/tibx-probe2/` host scratch dir removed
- Dangling `backend/tests/test_unpack_tibx.py` (orphaned by the 9428b5f revert) deleted
- No persistent host state changes
- No Acronis binaries downloaded, no Acronis cloud accounts touched

## Time spent on probes #1 + #2

~90 minutes wall-clock total across both probes. Three distinct boot
attempts (no startup.nsh; FAT no-startup.nsh; FAT + startup.nsh +
unpatched BCD), two BCD patches (hivex-targeted, byte-level), plus
recovery PE structure analysis via hivex. Clean exit; no leftover
state.
