---
title: Acronis `.tibx` deep research — fresh look post-HOLD
opened: 2026-05-13
status: scout-deliverable
author: scout-a (format-deep)
override: user-requested fresh deep research, prior brief was HOLD
---

# .tibx Deep Research — Scout A (Format Deep Research)

## TL;DR

**Confirmed: NO native OSS extraction path exists. The HOLD verdict from 2026-05-12 stands at the parser-library level — nothing new since then.** But the user is right that there ARE viable paths that the prior brief under-explored. The strongest is a **sandboxed-side-container** approach using either (a) the `acrocmd` / `archive_io_ctl` CLI from Acronis Cyber Protect 15 Linux Agent (commercial bundling — **EULA-blocking**), or (b) operator-host-install mode where wairz only ships a thin client. **Practical recommendation: ship the recovery-PE walker + detection-only stub immediately (no Rule #36 hazard, real operator value); defer mounting/extraction until N≥2 operator encounters re-justify the heavier path.**

Concrete file paths and a deferred-but-sketched side-container architecture below.

---

## 1. Format reversibility — 2026-05-13 update

**No new OSS parser has emerged.** Verified across multiple angles:

- **`dennisss/acronis-tib`** ([GitHub](https://github.com/dennisss/acronis-tib)) — still the only public Acronis parser. 13 commits, master branch hasn't moved since pre-2020. README explicitly targets four format variants: Windows ≤2012, 2013-2014, ≥2015, Mac OS — **no mention of `.tibx` or "Archive3" anywhere**. README "Reverse Engineering TODOs" list: "Encryption", "Most of the Windows format spec", "Some parts of the Mac spec" — even `.tib` is incomplete; `.tibx` is not on the roadmap.
- **GitHub `tibx` org** — empty placeholder account, 0 public repos, 3 stars on other projects. Not a parser source.
- **`libtibx` / `tibx-parser` / `python-tibx` / `tibxtract`** — none exist (verified via web search). No academic papers at DFRWS USA 2024, DFRWS USA 2025, DFRWS EU 2025, USENIX Security 2024-2026, or arxiv naming `.tibx`. No reverse-engineering threads on Forensic Focus, Reddit /r/computerforensics, Stack Overflow, or Hex-Rays forum since 2026-05-12.
- **TIBX Converter SaaS** ([convert.guru/tibx-converter](https://convert.guru/tibx-converter)) — closed third-party converter to VHD/ISO/ZIP. AGPL-incompatible (no source); cannot bundle.
- **OSF Mount (PassMark)** ([OSForensics tools](https://www.osforensics.com/tools/mount-disk-images.html)) — freeware on Windows, closed-source, no `.tibx` driver. No Linux port.
- **PassMark, [eathealthy365 "Definitive Guide"](https://eathealthy365.com/your-definitive-guide-to-opening-extracting-tib-files/), and Ask Leo all converge on the same statement (2024-2025 sources):** "For modern .tibx files, the answer is a firm no. The .tibx format is proprietary and encrypted, and only Acronis software can reliably parse it. There are no legitimate, safe, third-party free tools."

### Magic bytes — best evidence so far

- `.tib` (Archive2) magic: `CE 24 B9 A2 20 00 00 00` (documented in `dennisss/acronis-tib` source comments + multiple forensic file-signature references)
- `.tibx` (Archive3) magic: **No public documentation. Confirmed via [Wikipedia file-signatures list](https://en.wikipedia.org/wiki/List_of_file_signatures) absence, [Gary Kessler's file signatures table](https://www.garykessler.net/library/file_sigs.html) absence, and no PR to the `magika` ML magic-byte classifier addressing tibx.** Operator-side hex inspection of the Medtronic samples is the next mandatory verification step — likely a custom Acronis Archive3 envelope (16 or 32 byte fixed header) followed by container-encrypted slice metadata. **Recommend: spend 30 minutes with `xxd Archive(1).tibx | head -100` and `xxd Archive(1)-0001.tibx | head -100` to record the actual magic + first 256 bytes; this is companion intake #1 from the prior brief.** Until that's run, all parser strategy is speculative.

### What the Acronis KB *does* document

From [Acronis KB 64744 — Version 12 backup format (archive3)](https://care.acronis.com/s/article/64744-Acronis-Cyber-Protect-Cloud-version-12-backup-format-archive3) and [Sherweb KB Large Scale Recovery format 12](https://helpdesk.sherweb.com/en/support/solutions/articles/67000676979-acronis-large-scale-recovery-backup-format-12):

- **Naming convention:** `[Machine Name]-[Plan ID]-[Unique ID]A.tibx` for the first slice. Multi-slice continuations are `-0001.tibx`, `-0002.tibx`, etc. **This confirms Archive(1).tibx is the master/index and Archive(1)-0001.tibx through -0003.tibx are payload slices.**
- **"Meta information of the backup archive is stored in the first archive's slice."** This is the critical signal — `Archive(1).tibx` contains the chain manifest; the numbered files are slice payload. Any extraction path MUST process the master first.
- **Built-in dedup** — blocks identical to ones already present aren't re-stored. This means slice files are NOT independent; you cannot extract `-0001.tibx` standalone.
- **Compression + optional encryption** — undocumented format. Archive3 dropped Archive2's MD5-hashed password scheme for an undisclosed hardened scheme (likely AES-256-GCM or similar).
- **Schemes:** "always incremental" (one .tibx contains the full + all incrementals via dedup; what the Medtronic operator likely has) OR "multi-full" (one .tibx per backup chain).

### Verdict on writing our own parser

**Same as 2026-05-12: multi-month libyal-tier RE effort, moving target (Acronis ships major format updates ~yearly), no realistic path to handle encryption variants reliably.** Single-operator N=1 demand doesn't justify the investment. **NO-GO on writing a parser from scratch.**

---

## 2. Acronis Recovery PE deconstruction

The Medtronic ILLUMISITE image is a Windows recovery payload wrapping `acronis_recovery.iso` + the 4×~4 GB `.tibx` files. Per [Acronis KB 1537 — Bootable Media](https://kb.acronis.com/content/1537) and [Acronis Cyber Protect Cloud — WinPE-based bootable media](https://kb.acronis.com/content/59611), the bootable media comes in two flavors:

- **Linux-based bootable media** — based on a custom Linux rootfs with Acronis Linux drivers + the Acronis Linux Agent (`trueimagecmd` / `acrocmd`).
- **WinPE-based bootable media** — based on WinPE with the Acronis WinPE plugin injected.

**What wairz can do TODAY against this ISO without violating Rule #36:**

1. **`unpack_iso9660.py` already handles the outer ISO** ([backend/app/workers/unpack_iso9660.py](backend/app/workers/unpack_iso9660.py:1) exists). Walks the ISO9660 filesystem, extracts `boot.wim` / `sources/`.
2. **`unpack_wim.py` walks `boot.wim`** ([backend/app/workers/unpack_wim.py](backend/app/workers/unpack_wim.py:1) exists). Extracts the WinPE rootfs.
3. **The existing Windows-coverage walker chain (γ.4 registry, ε.1.b.3 EVTX, ι.B systemd, κ.A journald, κ.D DPAPI, etc.) inspects the WinPE rootfs.** Walker findings: registry hives, signed Acronis binaries, ClassInstall32 driver INF entries from the Acronis volume snapshot driver, EVTX logs if any, DPAPI master keys from the WinPE registry.

This is essentially **free operator value** — the recovery PE itself is a security-interesting artifact (signed kernel-mode driver, signed boot binaries, Acronis private signing CA chain visible to the chain-validation walker). Per [companion intake #3 from the prior brief](#) this is "likely shippable today." **Strong recommendation: ship this in parallel with whatever .tibx decision happens.**

**Identifying the .tibx parser binary:** Acronis ships its volume snapshot driver as `snapapi.sys` / `tdpcl.sys` / `aimas.sys`; the `.tibx` decoder lives in `mms.exe` / `mmsd.exe` / `tih_image.dll` / `aciso.exe` on the WinPE side, and on Linux is `mms` daemon under `/opt/acronis/`. No publicly-documented IDA database, no Ghidra script ported to it. **Reversing the parser is a multi-month forensics effort and is NOT differentiated from writing our own parser — same cost, same risk, same moving target.**

**Running the Acronis binary statically — Rule #36 analysis:** "Static analysis" of a binary means reading bytes for inspection (pefile, signify, Ghidra, radare2) — that's fine. "Running the binary against attacker-controlled input" is the no-execute boundary. **Running `wine /opt/acronis/mms /path/to/Archive(1).tibx` inside the worker container DOES violate Rule #36** even with sandboxing — the binary is closed-source vendor code processing untrusted bytes; we don't have visibility into what it does on parsing failure (file write? network call? memory corruption that escapes the sandbox?). The argument "but Docker is the security boundary" does NOT save us here — Rule #36 is explicitly about the worker container being the boundary, and we're proposing to compromise the boundary from inside.

**The only Rule #36-compliant way to involve the Acronis binary at all** is the side-container path discussed in §3 below — which is structurally different from the worker container.

---

## 3. Mount-style extraction via FUSE / side-container

This is where the user's override is most productive. The forensic mount pattern (FUSE driver → `disk.raw` block device → existing wairz walker chain) is the right shape — but no FUSE driver for `.tibx` exists. So the question becomes: can we run the Acronis CLI in a HEAVILY-isolated separate container that the wairz worker treats as an opaque extraction service?

### 3a. Architecture sketch (side-container)

```
┌────────────────────────────────────────────────────────────────────┐
│  wairz worker container (no Acronis binary, Rule #36 maintained)   │
│                                                                     │
│   app/workers/unpack_tibx.py                                         │
│       ↓ asyncio.create_subprocess_exec                              │
│       ↓                                                              │
│   docker exec wairz-acronis-extractor /opt/acronis/acrocmd \         │
│       recover disk                                                   │
│       --loc=/input/Archive(1).tibx                                   │
│       --target_disk=raw                                              │
│       --output=/output/disk.raw                                      │
└─────────────────────────────────────┬──────────────────────────────┘
                                       │ docker socket via wairz_extraction_net
                                       │
┌──────────────────────────────────────▼──────────────────────────────┐
│  wairz-acronis-extractor container (separate image, no network)      │
│                                                                       │
│   - Acronis Cyber Protect 15 Linux Agent (acrocmd + mms + libs)       │
│   - read-only bind mount: <firmware>/extracted/ → /input/             │
│   - tmpfs:        /output (size-capped 16 GB)                         │
│   - network:      "none" (no DNS, no inet)                            │
│   - cap_drop:     ALL                                                 │
│   - no-new-privileges, seccomp=runtime/default                        │
│   - read_only root, no /var/run/docker.sock                           │
└───────────────────────────────────────────────────────────────────────┘
```

**Rule #36 argument for why this isn't a violation:**

- The Acronis CLI runs in its **own container** — NOT the wairz worker. The worker only orchestrates via `docker exec` against a known-named sibling.
- The extractor container has **no network**, **no Docker socket**, **cap_drop=ALL**, **read-only root**, **tmpfs output** — strictly tighter than the worker's profile.
- The Acronis binary processes **read-only mounted bytes** from the firmware tree; the only thing that escapes is the produced `disk.raw` on tmpfs, which the worker reads back through the bind mount.
- If the Acronis binary misbehaves (file-write to `/etc`, network call, crash, kernel exploit attempt) — it's contained to a sibling container with no privileges and no escape surface.

**This is the same shape as wairz already uses for emulation and fuzzing** (per [CLAUDE.md security #2](#)): "Emulation runs inside an isolated QEMU Docker container. Fuzzing runs inside an isolated AFL++ Docker container. Both have resource limits." The .tibx extractor would be the third sibling-container pattern.

**Why this DOESN'T ship today: the EULA.**

### 3b. Acronis EULA — the blocking issue

Per the [Acronis EULA](https://www.acronis.com/en-us/support/eula.html):

> "You agree not to sublicense, lease, rent, loan, transfer, or distribute the Software, or any portion thereof, to any third party."
>
> "You may not make commercial use of the Software or Service, including but not limited to selling or distributing the Software and/or Service to any third party."
>
> "[Cannot] use or permit the Software to be used to perform services for third parties, whether on a service bureau or time sharing basis or otherwise, without the express written authorization of the licensor."

wairz is AGPL-licensed software intended for use by third parties — operators self-hosting the platform. **Bundling the Acronis Linux Agent in a wairz Docker image and distributing that image violates redistribution clauses.** Even shipping a `Dockerfile.acronis-extractor` that downloads the Acronis installer at build time has the same issue — wairz would be a "service bureau" performing services for third parties using Acronis software.

**The only EULA-compliant variant is "BYO Acronis":**

- Wairz ships **detection + a thin client** (`unpack_tibx.py` that recognizes the format).
- Wairz documents how the operator builds the side-container image **on their own host** using their own Acronis license.
- Wairz documents an env-var contract: `ACRONIS_EXTRACTOR_IMAGE=<operator-built-image-name>`.
- The operator runs `acronis-cyber-protect-installer.bin` themselves on the host, builds the sidecar image, and points wairz at it.
- If `ACRONIS_EXTRACTOR_IMAGE` is unset, `unpack_tibx.py` falls back to the detection-only stub.

This is **functionally equivalent to the UART/Device bridge precedent** (per [CLAUDE.md UART Bridge Architecture](#)): the bridge runs on the host because the host has the special access (USB serial / ADB / proprietary CLI), and wairz connects to it. The wairz repo ships the protocol + a thin client; the operator provides the access.

### 3c. Concrete file paths if this gets greenlit

```
backend/app/workers/unpack_tibx.py              # Thin client; subprocess exec into sidecar
backend/app/services/tibx_extractor_service.py  # Side-container orchestration (docker.from_env())
docker/tibx-extractor/                          # Sidecar build context (operator-built)
    README.md                                   # "BYO Acronis" build instructions
    Dockerfile.template                         # Operator fills in Acronis installer URL/path
    entrypoint.sh                               # acrocmd invocation
.env.example                                    # ACRONIS_EXTRACTOR_IMAGE = "" (unset by default)
```

**Stream count if greenlit (Rule #25 per-piece):**
1. Detection + stub (`unpack_tibx.py` emits operator guidance message; no extraction)
2. Sidecar protocol design (Rule #33 .a 202+polling shape for the multi-GB extraction)
3. Sidecar Dockerfile template + README ("BYO Acronis" build instructions)
4. Wairz-side orchestration service (`tibx_extractor_service.py` + Rule #39 inner/outer/safe runner triplet)
5. Tests against synthetic .tibx fixture (`mock_extractor_image` for CI)
6. Documentation + intake closure

**Estimated time:** 4-6 sessions if a real `.tibx` testbed is available; closer to 10-12 if working blind.

---

## 4. Commercial tool licensing — alternate angles

### 4a. Acronis OEM license vs Cyber Protect 15 license

The Medtronic image likely ships with an **OEM-bundled** Acronis True Image (per Kingston/WD/SanDisk precedent in the prior brief). [Acronis True Image OEM datasheet](http://dl.acronis.com/u/pdf/oem_datasheet.pdf) confirms the OEM SKU. The OEM EULA is more restrictive than the trial (no redistribution, no service bureau, tied to a specific hardware vendor's product line). **OEM cannot be used as the "BYO operator license" path** unless the operator happens to also own the hardware tied to the OEM bundle. Most wairz operators won't.

### 4b. Cyber Protect 15 trial — 30 days, fully featured

Per [Acronis KB 67083 — How to start a trial version](https://care.acronis.com/s/article/67083-Acronis-Cyber-Protect-15-How-to-start-a-trial-version): 30-day trial, all features, **trial can only be installed once per machine** (machine-fingerprint binding). This means the operator can stand up a `wairz-acronis-extractor` sidecar with the trial agent for short-term forensic work but **cannot put it into a persistent production pipeline** without buying a license. Functional for ad-hoc Medtronic-style cases (single-incident response), not for ongoing scanning.

### 4c. `acrocmd` / `archive_io_ctl` on Linux

Confirmed via [Acronis Cyber Protect 15 Command Line Reference](https://www.acronis.com/en/support/documentation/AcronisCyberProtect_15_Command_Line_Reference/) and [Acronis KB 67276 — Linux components](https://kb.acronis.com/content/67276):

- `/usr/sbin/acrocmd` — CLI for backup/restore. Runs against locally-installed agent.
- `archive_io_ctl` — lower-level tool for cloud upload/download of `.tibx` archives. Also runs against locally-installed agent.
- `/usr/sbin/universal_restore` — Linux recovery launcher.

The Linux agent installs as `.bin` (auto-detects distro: `.deb`-style on Debian/Ubuntu, `.rpm`-style on RHEL/CentOS, custom for SUSE). Requires kernel headers, GCC, Make, Perl at install time. The agent then provides `acrocmd` recovery commands that operate on `.tibx` archives.

**Linux agent is what powers the side-container path.** The actual mount/recovery code is identical regardless of OS — but Linux is preferred over `wine`-on-WinPE for our sandboxing model.

---

## 5. Brute-force header analysis viability

**Reserving judgment until the operator dumps Medtronic Archive(1).tibx headers.** Two scenarios:

- **Best case:** Medtronic uses Acronis OEM "no encryption" mode (some OEM vendors disable encryption to keep recovery one-click; Medtronic is a medical device vendor, encrypted recovery would block field service). If unencrypted, the slice payload may contain recognizable LZ4 / zlib / zstd block headers at predictable offsets after a fixed header. This would make a custom parser tractable — `.tibx` envelope strip → identify compression family by magic at payload offset → decompress block-by-block → reassemble disk image. Maybe 200-400 LOC of Python if everything aligns.
- **Worst case:** AES-256-GCM with key derived from PBKDF2 over a vendor-specific salt + boot machine SID. Completely opaque to byte-level analysis. Requires Acronis binary to derive the key.

**This is the single highest-leverage probe** — operator runs `xxd Archive(1).tibx | head -50` and we know within 5 minutes which scenario we're in. **Strong recommendation: this comes BEFORE any code work.**

If Best Case: write a custom parser, 6-10 sessions.
If Worst Case: fall back to side-container OR detection-only.

---

## 6. Per-volume cross-reference

**Confirmed:** Per [Acronis KB 64744](https://care.acronis.com/s/article/64744-Acronis-Cyber-Protect-Cloud-version-12-backup-format-archive3): naming convention is `[Machine Name]-[Plan ID]-[Unique ID]A.tibx` (or `Archive(1).tibx` in Cyber Protect Home Office) for the master/first slice; `-0001.tibx`, `-0002.tibx`, etc. for continuation slices.

**"Meta information of the backup archive is stored in the first archive's slice"** — extraction strategy MUST start with `Archive(1).tibx`. The numbered files are dedup'd payload and CANNOT be extracted standalone.

**Practical implication for wairz:** the format detector should recognize the master-vs-continuation distinction. Right now [backend/app/services/format_detection.py:344-345](backend/app/services/format_detection.py:344) treats all `.tibx` extensions identically as `ACRONIS_BACKUP` and routes to `unpack_no_handler`. The improvement (low-cost, ship in any case): add a "tibx_chain_member" subtype that recognizes `-NNNN.tibx` naming and surfaces "this is a continuation slice; the master is `<basename>.tibx`" in the operator-facing unpack_log. Doesn't unblock extraction but gives the operator the right diagnostic.

---

## 7. Recommended operator action — even if extraction stays HOLD

The prior brief listed companion intakes. Re-ranking them with this fresh look:

| Priority | Intake | Cost | Value |
|---|---|---|---|
| **1 (do today)** | **Header measurement** — `xxd Archive(1).tibx \| head -100` from Medtronic samples | 30 min | Decides parser feasibility (best/worst case); informs everything else |
| **2 (do today)** | **Acronis Recovery PE ISO walker** — `unpack_iso9660` already routes `acronis_recovery.iso`; verify it produces the WinPE tree + Acronis driver findings on the Medtronic sample | 1 stream | Free operator value (signed binaries, kernel-mode driver findings, INF analysis) regardless of `.tibx` decision |
| **3 (do today)** | **Detection-only stub upgrade** — extend `unpack_no_handler` to recognize `Archive(N).tibx` vs `Archive(N)-XXXX.tibx`; emit specific operator guidance (path to dennisss tool for `.tib`, BYO-Acronis link for `.tibx`, link to brute-force header investigation if magic looks decompressable) | 1 stream | Closes silent-failure UX gap; sets up for any future extraction path |
| **4 (defer)** | **Sidecar BYO-Acronis architecture** — full side-container path from §3 | 4-6 streams | Only justified if N≥2 operator encounters; EULA constraints make this an opt-in path even when shipped |
| **5 (defer)** | **Custom parser if Best Case** — 6-10 stream RE effort if header probe reveals unencrypted Acronis Archive3 | 6-10 streams | Only viable if header analysis shows recognizable compression magic at predictable offsets |

---

## Final verdict

**Reaffirm HOLD on writing-our-own-parser. Reaffirm HOLD on bundling Acronis CLI (EULA-blocking).**

**REVERSE the HOLD on three companion items that can ship today regardless of `.tibx` extraction:**

1. **Recovery PE ISO walker validation** — the outer ISO is already supported; verify wairz produces useful walker findings on the Medtronic sample's `acronis_recovery.iso`. Likely already works; 1-session smoke test.
2. **Detection-only stub upgrade** — distinguish master vs continuation slices; emit specific operator guidance per file class. 1 stream.
3. **Header measurement (operator-side)** — gates everything else. 30 min of operator time + 30 min of analysis. Decides Best/Worst case for any future custom-parser path.

**Defer-but-design** the sidecar BYO-Acronis architecture (§3a/§3c). Don't build it speculatively; build it the moment a second operator encounter (or a paying customer with an Acronis license they're willing to BYO) materializes.

**For the user's current Medtronic ILLUMISITE specifically:** The fastest, EULA-compliant, Rule #36-compliant path is to **install Acronis Cyber Protect 15 trial on a sacrificial VM** (host VM, not wairz worker container), use `acrocmd recover disk` to extract `disk.raw`, then upload that disk image to wairz as a normal firmware blob (wairz's NTFS / registry / EVTX / DPAPI / κ-walker chain runs on it transparently). This is the same 30-min workflow the prior brief noted but **explicitly stated as the right answer given Rule #36 + EULA constraints**, not as a workaround.

---

## Sources

- [GitHub: dennisss/acronis-tib](https://github.com/dennisss/acronis-tib) — sole OSS parser, `.tib`-only, 13 commits, pre-2020
- [Acronis KB 64744 — Version 12 backup format (archive3)](https://care.acronis.com/s/article/64744-Acronis-Cyber-Protect-Cloud-version-12-backup-format-archive3) — naming convention, dedup, meta-in-first-slice
- [Sherweb KB — Large Scale Recovery format 12](https://helpdesk.sherweb.com/en/support/solutions/articles/67000676979-acronis-large-scale-recovery-backup-format-12) — `archive_io_ctl`, multi-slice download workflow
- [Acronis KB 63498 — TIBX backup format FAQ](https://kb.acronis.com/content/63498) — `.tibx` introduction, replaces `.tib`
- [Acronis KB 63441 — tib and tibx backup format usage](https://care.acronis.com/s/article/63441-Acronis-True-Image-2020-and-2021-tib-and-tibx-backup-format-usage)
- [Acronis KB 63444 — tibx backups in local storage](https://kb.acronis.com/content/63444)
- [Acronis KB 63227 — Do not delete .TIB or .TIBX files outside Acronis](https://care.acronis.com/s/article/63227-Acronis-True-Image-Do-not-delete-TIB-or-TIBX-files-outside-of-Acronis-True-Image)
- [Acronis Cyber Protect 15 Command Line Reference](https://www.acronis.com/en/support/documentation/AcronisCyberProtect_15_Command_Line_Reference/) — `acrocmd` syntax
- [Acronis KB 67276 — Cyber Protect 15 Linux components](https://care.acronis.com/s/article/67276-Acronis-Cyber-Protect-15-Linux-components-services-and-processes)
- [Acronis KB 1537 — Acronis Bootable Media (Linux-based)](https://kb.acronis.com/content/1537)
- [Acronis KB 59611 — Cyber Protect Cloud WinPE-based bootable media](https://kb.acronis.com/content/59611)
- [Acronis EULA (en-us)](https://www.acronis.com/en-us/support/eula.html) — redistribution + service-bureau prohibitions
- [Acronis Trial Limitations KB 2768](https://care.acronis.com/s/article/2768-Trial-version-limitations-of-Acronis-products) — 30-day trial, single-machine install
- [Acronis True Image OEM datasheet](http://dl.acronis.com/u/pdf/oem_datasheet.pdf) — OEM SKU posture
- [Kingston Acronis True Image OEM User Guide 2023](https://media.kingston.com/support/pdf/ATI2023OEM_userguide_en-US.pdf)
- [Wikipedia: List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) — `.tibx` magic NOT listed
- [Gary Kessler file signatures table](https://www.garykessler.net/library/file_sigs.html) — `.tibx` magic NOT listed
- [convert.guru TIBX Converter (closed SaaS)](https://convert.guru/tibx-converter) — AGPL-incompatible
- [OSF Mount (PassMark, Windows-only, closed)](https://www.osforensics.com/tools/mount-disk-images.html)
- [Ask Leo — How do I read my Acronis backup data on a computer without Acronis?](https://askleo.com/how_do_i_read_my_acronis_backup_data_on_a_computer_without_acronis/) — confirms no third-party `.tibx` tools
- [eathealthy365 Definitive Guide to Opening TIB Files (2024)](https://eathealthy365.com/your-definitive-guide-to-opening-extracting-tib-files/) — confirms .tibx proprietary + encrypted
- Existing wairz scaffolding: [backend/app/services/format_detection.py:344-345](backend/app/services/format_detection.py:344), [backend/app/workers/unpack_no_handler.py:17](backend/app/workers/unpack_no_handler.py:17), [backend/app/workers/extraction_strategies.py:83](backend/app/workers/extraction_strategies.py:83), [backend/app/workers/unpack_iso9660.py](backend/app/workers/unpack_iso9660.py:1), [backend/app/workers/unpack_wim.py](backend/app/workers/unpack_wim.py:1)
- [QEMU FUSE block-export pattern (vhdx→raw precedent)](https://www.qemu.org/2021/08/22/fuse-blkexport/) — wairz `unpack_vhdx.py` precedent for sidecar-style extraction
- [DFRWS USA 2024 program](https://dfrws.org/conferences/dfrws-usa-2024/), [DFRWS EU 2025](https://dfrws.org/conferences/dfrws-eu-2025/), [DFRWS USA 2025](https://dfrws.org/conferences/dfrws-usa-2025/) — no `.tibx` papers
