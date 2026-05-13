---
title: Scout Y — Wine-run Acronis Windows binaries for .tibx extraction
opened: 2026-05-13
status: scout-deliverable
author: scout-y (wine-acrocmd)
relates_to: postmortem-tibx-byob-extraction-attempt-2026-05-13.md
verdict: NO-GO (HOLD for QEMU recovery PE — Scout X)
---

# Scout Y — Wine-run acrocmd.exe — VERDICT: NO-GO

## TL;DR

**NO-GO.** Wine cannot run `acrocmd.exe` from the customer's ILLUMISITE recovery PE because:

1. **`acrocmd.exe` is a CLIENT-ONLY tool** talking to `mms.exe` (Acronis Managed Machine Service). Per [Acronis KB 26419](https://kb.acronis.com/content/26419) + [KB 71361](https://care.acronis.com/s/article/71361), `acrocmd` fails with "Failed to establish local connection" when MMS isn't running.
2. **MMS depends on registered runtime state** populated only by a real Acronis Agent install — the same failure mode the Linux side hit in the prior session (postmortem 2026-05-13, `Archive3_GetDefaultPcsProcess BUG` SIGABRT). Extracting the binaries from a WinPE image and starting them in a Wine prefix won't populate the install-time registration MMS reads at startup.
3. **MMS requires Acronis kernel-mode drivers** (`snapapi.sys`, `tdpcl.sys`, `aimas.sys`). Wine has **no kernel driver support** — `ntoskrnl.exe:ZwLoadDriver` returns "failed to create driver" for every `.sys` load ([WineHQ forum thread 35861](https://forum.winehq.org/viewtopic.php?t=35861)). Architectural limit, not missing feature.
4. **Empirical record**: "Neither Acronis nor EaseUs run on Wine successfully" ([Linux Mint Forums 254311](https://forums.linuxmint.com/viewtopic.php?t=254311&start=20)). No Wine AppDB rating for any Acronis True Image version. No GitHub project for "acrocmd wine" (verified 2026-05-13).

**Recommended alternative:** Scout X (QEMU + boot the customer's recovery PE as a Windows-on-QEMU VM with the FULL Acronis kernel-mode driver stack + MMS + acrocmd already wired up). Matches Acronis's supported execution context exactly. Image size (~4 GB recovery PE + QEMU + kernel) is comparable to a Wine + .NET side-container with vastly higher success probability.

---

## 1. Wine compatibility evidence

**Wine AppDB:** The query for "Acronis" returned no usable content (Anubis bot-protection 403). Search-engine queries for "Acronis True Image" Wine AppDB ratings returned **zero direct AppDB entries** across all version years. Software with known compatibility (Notepad++, 7-Zip, Photoshop, MS Office) surface their pages directly. The absence is itself evidence: Acronis is not a popular Wine target, and the little community testing that exists has been negative.

**Community reports:** [Linux Mint Forums thread 254311](https://forums.linuxmint.com/viewtopic.php?t=254311&start=20) — verbatim verdict: "Neither Acronis nor EaseUs run on wine successfully." The same thread reports Goodsync runs cleanly under Wine, so the author had a working Wine setup and was reporting a specific Acronis-class failure.

**Wine + kernel drivers:** [WineHQ forum thread 35861](https://forum.winehq.org/viewtopic.php?t=35861) documents `ntoskrnl:ZwLoadDriver failed to create driver` — the universal failure mode for any Windows app that ships a `.sys` driver. [WineHQ kernel-modules wiki](https://wiki.winehq.org/Wine_Developer's_Guide/Kernel_modules) makes Wine's official position explicit: Wine implements `ntoskrnl.exe` user-mode side just enough for some user-mode apps that LINK against it; it does not run `.sys` kernel drivers. Wine runs in userspace, and Linux's kernel will not load Windows kernel drivers regardless of what Wine sends. No workaround exists.

**VSS:** Wine's `vssapi.dll` stub is incomplete, but VSS isn't strictly needed for the **restore** path (only for live backup creation) — so the restore-to-raw-file is theoretically Wine's friendliest possible Acronis use. Still requires Archive3 parser → MMS → kernel driver → install-time registration. Wine cannot satisfy any link past the first.

---

## 2. acrocmd command shape for unattended .tibx restore

From the [Acronis Cyber Backup 12.5 Command-Line Reference PDF](http://dl.acronis.com/u/pdf/AcronisCyberBackup_12.5_cmdlineref_en-US.pdf) and [Cyber Protect 15 reference](https://www.acronis.com/en/support/documentation/AcronisCyberProtect_15_Command_Line_Reference/), the canonical syntax IF acrocmd worked under Wine would be:

```cmd
acrocmd.exe recover disk --loc="C:\extracted" --arc="Archive(1)" \
  --disk=1 --target_disk=2 --service=mms --log="C:\tmp\restore.log"
```

`--target_disk` takes a numeric Windows disk index. **No documented `--target_disk=file:...` form exists** — restoring to a `.raw` file requires exposing a sparse file via `losetup -P` then mapping it into the Wine prefix's `dosdevices/`, an additional fragile layer.

[Acronis Forum "list content no results"](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-list-content-no-results): even `acrocmd list content --loc=... --arc=...` requires a working MMS connection ("Failed to establish local connection" per KB 26419).

## 3. Cloud-activation independence

Acronis bootable rescue media DOES run offline — per [Acronis SCS bootable media KB](https://support.acronisscs.com/hc/en-us/articles/9935618576787), "Without the license keys, the media will only be capable of recovery." But that's acrocmd running INSIDE the recovery PE where MMS is already running with drivers loaded. The constraint is about LICENSE, not runtime state. The runtime state (registered MMS, loaded `.sys` drivers) is provided by the PE bootstrap — exactly what Wine cannot replicate.

## 4. Sandbox boundaries (if it worked)

The side-container shape would be `network_mode: none`, `cap_drop: ALL`, non-root user, `read_only: true` rootfs, tmpfs for Wine prefix scratch space (~4 GB), customer Acronis binaries via read-only bind mount, output via writable bind mount or named volume. Dockerfile would install Wine + winetricks + `dotnet48` + `vcrun2019` + `corefonts` + `Xvfb`. Image size ~1.5 GB before customer binaries (which bind-mount at runtime, no redistribution). The shape mirrors the side-container reverted in commit `23cb720`. None of this matters because Wine cannot satisfy `acrocmd.exe`'s runtime preconditions.

---

## 5. Failure modes if we tried anyway

1. **MMS startup failure.** `mms.exe` tries `LoadDriver("snapapi.sys")`; Wine's `ntoskrnl` returns `ZwLoadDriver failed`; `mms.exe` aborts. **`acrocmd.exe` then fails with "Failed to establish local connection" matching KB 26419.** Best case: clean failure. Worst case: silent abort.
2. **Registration state missing.** `mms.exe` consults a registered process registry (Windows analog of `Archive3_GetDefaultPcsProcess`). A Wine prefix that didn't run the Acronis installer has a missing registration entry. Symptom: `mms.exe` aborts on startup, or `acrocmd.exe` connects but receives "no archive parser available".
3. **Cloud phone-home.** `network_mode: none` blocks activation retries but adds startup latency hangs.
4. **GUI dialog dependency.** Some `acrocmd.exe` operations pop dialogs. Need `Xvfb` (+50 MB) or `WINEDLLOVERRIDES` for builtin user32.
5. **WinPE-specific bug ABR-117132.** Per [Acronis forum](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-problem-recovery-media), `acrocmd` in WinPE already fails to browse some archives in Acronis's own environment. Wine layered on top inherits this PLUS every Wine-related issue.

---

## 6. Existing work mined

- **GitHub** ("acrocmd wine", "Acronis True Image Wine"): zero repos, zero forks, zero issues.
- **DFRWS / USENIX Security 2024-2026**: zero papers on Wine-based Acronis extraction. The forensic community uses (a) Acronis's native Linux Agent, or (b) Acronis Windows binaries inside a real Windows VM (QEMU/KVM). Both avoid Wine impedance mismatch.
- **Forensic Focus / Reddit /r/computerforensics**: zero threads. "Open .tibx without Acronis" reliably gets the answer "use Acronis's free trial in a Windows VM" (Scout X's path).

---

## 7. Alternative: Wine64-only with explicit DLL search path

This is the cleaner-on-paper attempt: don't try to boot the recovery PE, don't run MMS, just point `wine64` at `acrocmd.exe` with `WINEDLLPATH=/opt/acronis-customer` and hope `acrocmd.exe` exposes a CLI mode that doesn't need MMS.

**It doesn't.** Per the Acronis service architecture, `acrocmd.exe` is purely a CLI front-end that translates command-line arguments into RPC calls to MMS. There's no "standalone mode" — every operation goes through MMS. This is confirmed by multiple Acronis KB articles describing the "Failed to establish local connection" error when MMS isn't running on the same host.

The architectural shape `acrocmd.exe → MMS RPC → AcronisAgentCore → snapapi.sys → Archive3 parser` is fixed. Removing any layer makes the chain non-functional.

---

## 8. Implementation skeleton — DO NOT BUILD

Skeleton retained only to make the NO-GO concrete. A working build would chain `wineboot --init` → `winetricks -q dotnet48 vcrun2019 corefonts` → `Xvfb :99` → `wine /opt/acronis-customer/acrocmd.exe recover disk --loc=/input --arc='Archive(1)' ...`. The chain fails at MMS startup before the Acronis Archive3 parser ever loads, so the Dockerfile + worker module would just be elaborate scaffolding for a guaranteed-failing entrypoint.

## 9. Risk + time estimate

- **Realistic**: 1 week of Dockerfile + Wine prefix scaffolding, hitting MMS-startup or kernel-driver-load failure within day 1 of integration testing. Same NO-GO reached experimentally that's already reached analytically here.
- **Pessimistic**: Wine produces partial output that silently corrupts the .tibx parse → garbage `disk.raw` → 2 weeks to discover against a known-good reference. **Rule #36 worker-boundary concern** (closed-source vendor code with unknown failure modes), AMPLIFIED by Wine.

**Don't invest.** Spend the same week on Scout X (QEMU + recovery PE) with vastly higher success probability.

## 10. What this scout DID NOT do

- **Did not run an empirical Wine probe against the customer's `acrocmd.exe`.** This scout's container has empty `/data/firmware/` (verified), and the analytical evidence is unambiguous. **If empirical confirmation is wanted**: extract `acrocmd.exe` + `mms.exe` + DLLs into a clean Wine prefix, try `wine acrocmd.exe help` (expect "Failed to establish local connection"), try `wine mms.exe --service` (expect kernel driver load error). ~2 hours.
- **Did not check the customer's upload for Linux-side acrocmd**. The recovery PE is Windows-side per the prior session (boot.wim + Acronis WinPE plugin). No Linux binaries in the upload.
- **Did not redistribute Acronis binaries.** Per the user's EULA affirmation, the would-be container bind-mounts the customer's upload read-only — no redistribution.

## 11. Recommendation

**NO-GO on Wine + acrocmd.exe.** The architectural-dependency chain (acrocmd.exe → MMS → kernel driver → registered runtime state) cannot be satisfied by Wine. Empirical evidence from community reports + Wine's own kernel-driver-support stance confirms this analytically.

**GO on Scout X path** (QEMU + customer recovery PE). The recovery PE is self-contained — it ships its own Windows kernel + Acronis kernel drivers + MMS supervisor + registered runtime state. Booting it as a QEMU VM with the customer's `.tibx` files attached as a virtual disk lets `acrocmd.exe` run in EXACTLY the execution context Acronis designed for it. Image-size cost (~5 GB QEMU + recovery PE working set) is comparable to a Wine + .NET side-container. Security boundary is stronger (QEMU VM is a harder isolation than a Wine prefix). And critically: there's a clear "did it work" / "did it fail" verdict based on whether MMS comes up and `acrocmd recover disk` completes, with no Wine impedance to debug.

**FALLBACK if Scout X also says NO-GO:** the operator-side `Cyber_Protect_Agent_for_Linux_x86_64.bin` install path from the prior postmortem remains the documented escape. It's a one-time operator action and produces a working tibxread on the host that the existing wairz BYOB-SC side-container picks up cleanly.

---

## Sources

- [WineHQ kernel modules wiki](https://wiki.winehq.org/Wine_Developer's_Guide/Kernel_modules) — Wine cannot load `.sys` kernel drivers.
- [WineHQ forum thread 35861 — ntoskrnl ZwLoadDriver failure](https://forum.winehq.org/viewtopic.php?t=35861) — canonical Wine + Windows kernel driver failure thread.
- [Linux Mint Forums thread 254311](https://forums.linuxmint.com/viewtopic.php?t=254311&start=20) — "Neither Acronis nor EaseUs run on wine successfully."
- [Acronis KB 26419 — Services not running / Failed to establish local connection](https://kb.acronis.com/content/26419) — acrocmd → MMS dependency.
- [Acronis KB 71361 — Agent Core Service corrupted config](https://care.acronis.com/s/article/71361) — MMS startup state requirements.
- [Acronis KB 60085 — Cyber Backup 12.5 Windows services and processes](https://kb.acronis.com/content/60085) — mms.exe service architecture.
- [Acronis SCS KB 9935618576787 — Creating Bootable Media](https://support.acronisscs.com/hc/en-us/articles/9935618576787) — offline-recovery licensing.
- [Acronis Cyber Backup 12.5 Command-Line Reference (PDF)](http://dl.acronis.com/u/pdf/AcronisCyberBackup_12.5_cmdlineref_en-US.pdf) — acrocmd command syntax.
- [Acronis forum — acrocmd Problem in Recovery Media](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-problem-recovery-media) — WinPE-specific bug ABR-117132.
- [Acronis forum — acrocmd list content no results](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-list-content-no-results) — local connection failure mode.
- [Acronis KB 1537 — Bootable Media](https://kb.acronis.com/content/1537) — Linux-based vs WinPE-based bootable media.
- [Acronis Cyber Protect 15 — Adding Acronis Plug-in to WinPE](https://www.acronis.com/en-us/support/documentation/AcronisCyberProtect_15/adding-plug-in-to-winpe.html) — Acronis Plug-in is a modification of Acronis Backup Agent.
- [Acronis KB 62490 — SnapAPI kernel module not loaded](https://care.acronis.com/s/article/62490) — kernel driver dependency confirmed.
- [GitHub `dennisss/acronis-tib`](https://github.com/dennisss/acronis-tib) — only OSS parser; no .tibx support.
- [Winetricks documentation](https://github.com/Winetricks/winetricks) — unattended Wine prefix setup for the would-be-implementation.
- [wairz internal postmortem 2026-05-13](../../postmortems/postmortem-tibx-byob-extraction-attempt-2026-05-13.md) — Linux-side equivalent failure (`Archive3_GetDefaultPcsProcess BUG`).
- [wairz internal Scout A research 2026-05-13](../tibx-deep-2026-05-13/scout-a-format-deep-research.md) — format-level evidence base.
