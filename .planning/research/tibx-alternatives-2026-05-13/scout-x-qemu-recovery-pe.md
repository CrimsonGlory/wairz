---
title: Scout X — QEMU-boot Acronis Recovery PE for .tibx extraction
date: 2026-05-13
status: research-draft
verdict: HOLD (viable in principle, two operator-side probes resolve GO / NO-GO in ~30 min)
relates_to:
  - .planning/research/tibx-deep-2026-05-13/scout-c-sandboxed-extraction.md
  - .planning/postmortems/postmortem-tibx-byob-extraction-attempt-2026-05-13.md
  - .planning/intake/tibx-byob-side-container-architecture-2026-05-13.md
---

# Scout X — Boot the Acronis Recovery PE inside QEMU to drive .tibx extraction

## Verdict: HOLD pending two probes

This approach is **technically viable in principle** and is meaningfully different from the BYOB path that hit the `Archive3_GetDefaultPcsProcess` wall (postmortem 2026-05-13). Booting a Recovery PE inside QEMU to drive `.tibx` restore is the standard Acronis-documented workflow for restoring `.tibx` to a virtual disk: [KB content/45856](https://kb.acronis.com/content/45856) documents recovery-into-VMs as a first-class flow and [KB content/16994](https://kb.acronis.com/content/16994) documents Acronis recovery inside KVM. The technical building blocks — QEMU + OVMF UEFI booting WinPE x64 from `boot.wim`, `acrocmd` shipped in PE-based bootable media per the [Acronis Cyber Protect 15 Command-Line Reference](https://dl.acronis.com/u/pdf/AcronisCyberProtect_15_Command_Line_Reference_en-US.pdf) ("This utility is also available in 64-bit Linux-based bootable media and in PE-based bootable media") — are all documented and individually well-trodden.

**Why HOLD rather than GO:** three unverified-but-resolvable risks, all answerable by ~30 minutes of operator-side probing:

1. **License / activation behaviour is OEM-dependent.** Acronis docs are explicit that "only recovery is available in bootable media" and that recovery remains available even after license expiry ([KB limitoftrial](https://kb.acronis.com/limitoftrial); cross-confirmed across Kingston/Crucial/WD OEM user guides — e.g. [Kingston ATI 2023 OEM guide](https://media.kingston.com/support/pdf/ATI2023OEM_userguide_en-US.pdf): "even if the fully functional product functions become unavailable after the trial period without activation, the recovery function remains available"). ILLUMISITE is an OEM-Acronis bundle (True-Image-2019-era based on `agent.exe` / `TrueImage.exe` filenames), so this pattern should apply — but it's unverified for this specific firmware.
2. **The PE may phone home for license validation on boot.** Newer Cyber Protect Cloud media "register the bootable media in the Cyber Protection service on booting up" ([KB content/59611](https://kb.acronis.com/content/59611)). ILLUMISITE predates Cyber Protect Cloud, so risk is lower — but unverified. Mitigation: `-net none` denies the PE any network, full stop.
3. **Customer Recovery PE → unknown automation surface.** Acronis-bundled Recovery PE ships with the TrueImage GUI as the default startup target, designed for **interactive** rescue use. Driving it unattended requires either replacing `startnet.cmd` in the WIM (well-trodden but constitutes WIM mutation in a scratch copy), or scripting GUI keystrokes via serial console (fragile). Forum evidence ([Acronis Forum — ACROCMD Problem in Recovery Media](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-problem-recovery-media); [Forum — best practice tibx-to-VHD via bootable media](https://forum.acronis.com/forum/acronis-backup-cloud-forum/there-best-practice-guide-recover-physical-machine-backup-tibx-file-vhd-bootable-media)) confirms `acrocmd` lives inside PE media, but its license-check behaviour from inside the PE is unverified.

**Two probes resolve GO/NO-GO** (operator runs these once against the ILLUMISITE Recovery PE; total ~30 min):

- **Probe #1 — manually boot the customer Recovery PE in QEMU.** `qemu-system-x86_64 -enable-kvm -m 4096 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd -drive if=pflash,format=raw,file=/work/OVMF_VARS.fd -drive file=acronis_recovery.iso,media=cdrom -drive file=blank.raw,if=ide,format=raw -net none -nographic`. **Pass:** PE boots to TrueImage GUI without a license-key prompt; GUI sees `.tibx` files; restore-to-target completes; shutdown clean.
- **Probe #2 — open a WinPE shell, run `acrocmd help recover` and `acrocmd help mount`.** **Pass:** non-empty help; no license/activation gate.

If both pass → GO; the code spec below ships in ~12–16 hours. If either fails → NO-GO; Scout Y (header reverse-engineering) and Scout Z (Acronis Cloud direct API) become the only paths.

---

## 1. QEMU command line

Sources: [Baeldung — Booting From UEFI in QEMU](https://www.baeldung.com/linux/qemu-uefi-boot), [QEMU ELI5 — UEFI, BIOS & OVMF (Tuna Cici / Medium)](https://medium.com/@tunacici7/qemu-eli5-part-6-uefi-bios-ovmf-7919facf7e31):

```bash
qemu-system-x86_64 \
  -enable-kvm -cpu host -smp 4 -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/work/OVMF_VARS.fd \
  -drive file=/input/acronis_recovery.iso,media=cdrom,readonly=on \
  -drive file=/input/tibx_volume.raw,if=ide,format=raw,readonly=on \
  -drive file=/output/disk.raw,if=ide,format=raw \
  -boot order=d \
  -net none -nographic \
  -serial unix:/work/serial.sock,server,nowait \
  -monitor unix:/work/monitor.sock,server,nowait
```

**Design decisions:**

- **`if=ide` for the input/output volumes (not virtio).** WinPE is virtio-blind by default; using virtio-block triggers `INACCESSIBLE_BOOT_DEVICE`-class faults ([Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5598163/inaccessible-boot-device-after-winpe-installed-win)). IDE/SATA always works for PE. The ~30% performance loss vs virtio is acceptable for a ~10-min one-shot.
- **`-net none`.** Forces offline operation. The strongest single defence against cloud activation. If the PE refuses to boot or hangs without a NIC, Probe #1 fails and we know the approach is NO-GO.
- **OVMF_VARS per-VM copy.** Vanilla `/usr/share/OVMF/OVMF_VARS.fd` is the template; copy it per VM so UEFI variable writes don't pollute the template. The Recovery PE's `bootmgr.efi` → `EFI/Boot/bootx64.efi` chain works with stock OVMF.
- **Memory 4 GB.** WinPE needs 1–1.5 GB; TrueImage adds ~1 GB during restore. 4 GB is comfortable.
- **`-cdrom` for ISO, `-boot order=d`.** PE boots from CD; restore writes to the second IDE disk; first IDE disk presents the `.tibx` files.
- **Secure Boot disabled by default** (non-`secboot` OVMF_CODE variant). If the customer PE is Secure-Boot-signed and refuses to run, swap to `OVMF_CODE.secboot.fd` and enrol the Microsoft UEFI CA into a fresh `OVMF_VARS.secboot.fd` per [openSUSE wiki](https://en.opensuse.org/openSUSE:UEFI_Secure_boot_using_qemu-kvm). One-time ~30-min plumbing.
- **`/dev/kvm` required.** Without KVM, TCG runs at ~10× slower (4 GB restore in ~60 min instead of ~6 min). Gracefully degrade per Rule #34 if `/dev/kvm` is absent.

**Input volume prep:** package the four `.tibx` files into a FAT32 raw image (~20 GB sparse): `dd of=tibx_volume.raw bs=1M count=20000 conv=sparse && mkfs.fat -F 32 tibx_volume.raw && mcopy -i tibx_volume.raw Archive*.tibx ::`. **Output volume prep:** `qemu-img create -f raw /output/disk.raw 50G` (sparse; sized at expected source-disk capacity).

## 2. acrocmd.exe automation

**Path A — `startnet.cmd` mutation (preferred).** WinPE's `\Windows\System32\startnet.cmd` auto-runs at boot ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wpeinit-and-startnetcmd-using-winpe-startup-scripts)). Replace its default body with:

```cmd
wpeinit
"X:\Program Files\Acronis\BackupAndRecovery\acrocmd.exe" ^
    recover disk --loc=E:\ --arc=Archive(1).tibx --backup=last ^
    --disk=1 --target_disk=Disk2 --progress --log=Y:\acrocmd.log
shutdown /s /t 0
```

The `acrocmd recover disk` flag set (`--loc`, `--arc`, `--backup`, `--disk`, `--target_disk`, `--password`, `--progress`) is confirmed in the [CLI Reference](https://dl.acronis.com/u/pdf/AcronisCyberProtect_15_Command_Line_Reference_en-US.pdf) and forum example ([acroncmd null syntax example](https://forum.acronis.com/forum/acronis-backup-117-former-acronis-backup-recovery-115/acroncmd-recover-disk-optional-value)): same syntax works for `.tib` and `.tibx`. Injection via Linux-friendly `wimtools`: `wimmountrw boot.wim 1 /mnt && cp startnet.cmd /mnt/Windows/System32/ && wimunmount --commit /mnt && xorriso -as mkisofs -o new.iso ...`. Modification happens in tmpfs scratch inside the side-container; **on-disk customer firmware never touched**.

**Path B — `autounattend.xml`: rejected.** Targets `setup.exe` install flow, not post-init commands ([4sysops](https://4sysops.com/archives/automate-windows-setup-from-winpe-using-autounattendxml/)). Wrong hook for Acronis PE.

**Path C — serial-console GUI keystroke driver: last-resort fallback.** Fragile under TrueImage version drift; invoke only if A blocked.

**Mount-only mode: not available.** Per [KB 63425](https://kb.acronis.com/content/63425), **TIBX cannot be mounted as a virtual disk** (a feature lost in the tib→tibx transition). Full restore is the only Acronis-supported shape. ILLUMISITE's 4 `.tibx` files form ONE chained backup (master `Archive(1).tibx` + slices `-0001`/`-0002`/`-0003` per [Sherweb KA-03624](https://helpdesk.sherweb.com/en-US/knowledge-base/articles/KA-03624) and [KB 64744](https://care.acronis.com/s/article/64744-Acronis-Cyber-Protect-Cloud-version-12-backup-format-archive3)); `acrocmd` is pointed at the master and restores the whole chain into ONE `disk.raw`.

## 3. Cloud-activation independence

Confidence ladder:

- **High** — recovery is always free in Acronis bootable media even on expired/no license (OEM user guides cross-confirm).
- **Medium** — OEM Recovery PE typically has the license baked into the WIM. ILLUMISITE is an OEM bundle, True-Image-2019-era, predating Cyber Protect Cloud. Pattern should apply.
- **Low-but-real** — a 2019-era TrueImage PE may still want to "phone home for license validation" on first boot. `-net none` denies the call. If the PE refuses to boot without a NIC, NO-GO.

Verdict: likely YES for ILLUMISITE specifically; Probe #1 resolves in 15 min.

## 4. Implementation skeleton (assuming GO)

Mirror `system-emulation/` (FirmAE) side-container pattern. New service: `tibx-recovery-emulator`.

```
wairz/
├── tibx-recovery-emulator/                # NEW; sibling to system-emulation/
│   ├── Dockerfile                         # ubuntu:22.04 + qemu-system-x86 + ovmf + wimtools + xorriso + flask  (~700 MB)
│   ├── entrypoint.sh                      # boots Flask on :5001
│   ├── shim/
│   │   ├── app.py                         # POST /restore → orchestrate → return /output/disk.raw
│   │   └── orchestrator.py                # extract ISO → mutate startnet.cmd → xorriso new ISO →
│   │                                      #   mkfs.fat32 input volume → qemu launch → poll serial for shutdown
│   └── patches/startnet.cmd.template
backend/app/workers/unpack_tibx_qemu.py    # NEW worker: POST to shim, poll, docker-cp /output/disk.raw out
backend/app/services/extraction_strategies.py  # ACRONIS_TIBX_QEMU strategy entry
docker-compose.yml                          # tibx-recovery-emulator service; --device /dev/kvm; --network=none;
                                            #   --read-only --tmpfs /work:size=2g --tmpfs /output:size=64g;
                                            #   --cap-drop=ALL --security-opt=no-new-privileges
.env.example                                # TIBX_RECOVERY_EMULATOR_IMAGE, _HOST
```

**Worker module shape** (~150 LOC): POST input refs to `tibx-recovery-emulator:5001/restore`; shim does the WIM mutation + xorriso + qemu launch + waits for VM shutdown; emits `/output/disk.raw`; worker `docker cp` it back to the firmware's `extracted/` dir; existing NTFS walker chain takes over.

**Rule #36 / #33 fit:** the worker container does NOT execute Acronis binaries. It only delegates to a strictly-isolated side-container (no network, read-only rootfs, cap-drop ALL) — same threat shape as the FirmAE / AFL++ pattern (CLAUDE.md Security #2). Within precedent.

## 5. Time + complexity

| Phase | Time | Notes |
|------:|-----:|-------|
| Probes #1 + #2 (operator) | 30 min | resolves GO/NO-GO |
| Dockerfile + Flask shim | ~5 h | low complexity |
| WIM mutation orchestrator | ~5 h | well-trodden tooling (`wimtools` + `xorriso`); error-prone glue |
| Worker + strategy entry | ~3 h | mirrors patterns |
| End-to-end test against ILLUMISITE | ~1 session | medium |
| **Total to ship** | **12–16 h, 2 sessions** | post-probes |
| Per-upload runtime | 10–20 min | `-enable-kvm` required; without KVM ~60 min |

Comparable to the BYOB estimate but eliminates "operator installs Acronis Agent." Replaces it with "operator runs Probes #1+#2 once" — far smaller commitment.

## 6. Top risks (consolidated)

| # | Risk | Mitigation | Verdict |
|---|------|------------|---------|
| 1 | PE refuses to run in QEMU (hardware-presence check) | Try `-cpu host` vs `qemu64`; try `-machine pc` (BIOS) | Resolves Probe #1 |
| 2 | PE phones home; `-net none` causes hang | If hang, NO-GO | Resolves Probe #1 |
| 3 | Secure Boot rejection | OVMF secboot + MS UEFI CA enrolment | +30 min, not blocking |
| 4 | acrocmd license-check inside PE | Path C (GUI driver) fallback | Resolves Probe #2 |
| 5 | `startnet.cmd` mutation is forbidden by license terms | Path C fallback; or interactive-only mode (no automation) | Reduces value, doesn't kill |
| 6 | `/dev/kvm` unavailable on host | Rule #34 graceful fail; document `/dev/kvm` requirement | Standard |
| 7 | `.tibx` chain detection (which is master?) | Sherweb KA-03624 documents naming convention; unsuffixed = master | Algorithmic |

## 7. If NO-GO — scout-y / scout-z scope

- **Scout Y — header reverse-engineering.** Probe `xxd Archive(1).tibx | head -100` first (per scout-a-format-deep-research.md). If compression magic is recognizable (LZ4/zlib/zstd), 200–400 LOC of Python could parse the unencrypted-OEM case. Best-case high-leverage; worst-case multi-week dead end if AES-encrypted ([Elcomsoft analysis](https://blog.elcomsoft.com/2022/01/targeting-backup-encryption-acronis-macrium-and-veeam/) confirms AES is user-optional; OEM medical-device images usually unencrypted).
- **Scout Z — Acronis Cloud direct API.** If operator has Cyber Protect Cloud credentials, download `.tibx` as pre-restored disk image via Acronis' REST API. Eliminates wairz-side parsing entirely. Operationally heaviest path (operator must have cloud account + active license + the .tibx must be uploadable to cloud), but technically simplest from wairz's side. Worth a 1-h scope check on Acronis Cloud's REST docs.

Per [github.com/dennisss/acronis-tib](https://github.com/dennisss/acronis-tib) the only public OSS parser is `.tib`-only (Archive2); no `.tibx` parser exists in the wild. Scout Y is genuine net-new RE work.

## Sources

- Acronis CLI / format docs: [CLI Reference (PDF)](https://dl.acronis.com/u/pdf/AcronisCyberProtect_15_Command_Line_Reference_en-US.pdf), [Backup 11.7 HTML mirror](https://usermanual.wiki/acronis/Backup117cmdlinerefen.3003000281/html), [KB 64744 archive3 format](https://care.acronis.com/s/article/64744-Acronis-Cyber-Protect-Cloud-version-12-backup-format-archive3), [KB 63425 tibx limitations](https://kb.acronis.com/content/63425), [KB 59611 WinPE bootable media](https://kb.acronis.com/content/59611), [KB 45856 recovery into VM](https://kb.acronis.com/content/45856), [KB 16994 KVM recovery](https://kb.acronis.com/content/16994), [KB limitoftrial](https://kb.acronis.com/limitoftrial), [Sherweb KA-03624](https://helpdesk.sherweb.com/en-US/knowledge-base/articles/KA-03624), [Kingston ATI 2023 OEM guide (PDF)](https://media.kingston.com/support/pdf/ATI2023OEM_userguide_en-US.pdf).
- QEMU / UEFI: [Baeldung UEFI in QEMU](https://www.baeldung.com/linux/qemu-uefi-boot), [QEMU ELI5 OVMF](https://medium.com/@tunacici7/qemu-eli5-part-6-uefi-bios-ovmf-7919facf7e31), [openSUSE Secure Boot in qemu-kvm](https://en.opensuse.org/openSUSE:UEFI_Secure_boot_using_qemu-kvm), [Microsoft Q&A WinPE virtio INACCESSIBLE_BOOT_DEVICE](https://learn.microsoft.com/en-us/answers/questions/5598163/inaccessible-boot-device-after-winpe-installed-win).
- WinPE automation: [Microsoft Learn — Wpeinit and Startnet.cmd](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wpeinit-and-startnetcmd-using-winpe-startup-scripts), [4sysops autounattend.xml from WinPE](https://4sysops.com/archives/automate-windows-setup-from-winpe-using-autounattendxml/).
- Community evidence: [Forum acrocmd in Recovery Media](https://forum.acronis.com/forum/acronis-backup-12/acrocmd-problem-recovery-media), [Forum tibx-to-VHD via bootable media](https://forum.acronis.com/forum/acronis-backup-cloud-forum/there-best-practice-guide-recover-physical-machine-backup-tibx-file-vhd-bootable-media), [Forum acroncmd syntax example](https://forum.acronis.com/forum/acronis-backup-117-former-acronis-backup-recovery-115/acroncmd-recover-disk-optional-value).
- Format ecosystem: [dennisss/acronis-tib OSS .tib parser](https://github.com/dennisss/acronis-tib) (confirms no .tibx parser exists), [Elcomsoft on .tibx encryption](https://blog.elcomsoft.com/2022/01/targeting-backup-encryption-acronis-macrium-and-veeam/).
