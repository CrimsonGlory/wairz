---
title: Acronis True Image .tibx backup format support — research-fleet brief
opened: 2026-05-12 (filed late-night UTC)
status: research-fleet-pending-scope-decision
---

# Acronis True Image `.tibx` Backup Format Support — Research Brief

**Trigger:** 15.57 GB Medtronic ILLUMISITE Windows recovery ISO; actual disk content sits inside 4 × ~4 GB `.tibx` files. NTFS / registry / EVTX / κ-walker payload is locked behind the wrapper.

## 1 — `.tibx` format reversibility (forensics SME)

`.tibx` is Acronis Archive3 (True Image 2020+, succeeds `.tib`/Archive2). Per Acronis KB: proprietary, undocumented, compressed, optional AES-256 (Archive3 dropped Archive2's MD5-hashed password for an undisclosed hardened scheme). Metadata in-archive; incrementals auto-merge into base files.

| Tool | Format | Verdict |
|---|---|---|
| `dennisss/acronis-tib` (MIT, TS, 13 commits, "WIP") | `.tib` only | **Cannot handle `.tibx`** |
| `libacronis` / `python-tibx` / `tibx-tools` | — | **None exist** |
| OSF Mount (PassMark), TIBX Converter SaaS | `.tibx` partial | Closed — AGPL-incompatible |
| unblob / binwalk / 7-zip | — | No magic handler |
| Acronis True Image trial | `.tibx` full | Violates Rule #36 |

Acronis recovery PE uses closed `aciso`/`mms` blobs — no extractable parser surface. Writing one ourselves: libyal-tier multi-year (encryption + version churn). Legacy `.tib` magic is `CE 24 B9 A2 20 00 00 00`; no public `.tibx` magic documented.

## 2 — Strategic value (forensics analyst)

**Prevalence:** Acronis True Image OEM ships bundled with Kingston, WD, SanDisk, Crucial, Seagate, **Advantech** (industrial/medical embedded). Medtronic ILLUMISITE = first confirmed wairz operator encounter; no public catalog of medical vendors using Acronis. Plausible silent adjacencies: Advantech/Kontron/Kingston-bundled Windows recovery (medical, factory automation, kiosk/POS, defense) — unmeasured.

**Operator workaround today:** Windows VM + Acronis trial + manual VHDX export + re-upload. ~30 min, requires Windows licensing, breaks AGPL self-host promise.

**Competitive wedge:** Plaso, Velociraptor, MemProcFS, EZTools, KAPE, Autopsy — **none parse `.tibx`**. Genuine differentiation IF demand exists; demand floor is N=1.

**Maintenance burden:** Acronis ships major updates yearly; format cycled `.tib`→`.tibx` in 2020; next-gen plausible 2027-2028. A RE'd parser chases a moving target with silent-corruption risk per version bump (Rule #17/#35a class).

## 3 — wairz integration cost (architecture)

**Placement:** `backend/app/workers/unpack_tibx.py`, registered via `extraction_strategies.STRATEGIES[DetectedFormat.ACRONIS_TIBX] = unpack_tibx`. Output contract identical to `unpack_vhdx.py`: `.tibx` → `extraction_dir/disk.raw`, then existing NTFS/registry/EVTX walker chain takes over transparently.

**Paths (rank-ordered):**
1. **NO-GO blocker:** no AGPL-compatible `.tibx` parser exists. Writing one is multi-month libyal-tier RE. Wrapping Acronis CLI violates Rule #36 AND license.
2. **Fallback:** wrap `dennisss/acronis-tib` for legacy `.tib`; emit clear "tibx unsupported, use Acronis Recovery + re-upload" for `.tibx`. Doesn't solve Medtronic.
3. **Rule #39 walker triplet** applies IF parser exists; ~3 streams. Moot until parser exists.

**Rule #36 hard line:** running vendor decoder code from a closed proprietary stack inside the worker defeats the security boundary.

---

## Verdict

**HOLD — soft NO-GO at current intake strength.** No AGPL-compatible `.tibx` parser exists; only OSS tool (`dennisss/acronis-tib`) is `.tib`-only and incomplete; writing one from scratch is multi-month RE chasing a moving target. Strategic-value floor: **N=1 (Medtronic)**. **Revisit trigger:** (a) 2+ additional `.tibx` operator encounters in different device families, OR (b) credible OSS `.tibx` reader with encryption support emerges.

## Recommended scope shape if GO

- **Unpacker extension** (not new walker family) — slot into existing `unpack_<format>.py` convention; downstream NTFS/registry/EVTX walkers reused unchanged.
- **Stream count:** 3 if parser library appears (wrap + detect + tests); 8-12 if writing parser ourselves (RE + decompression + crypto + metadata + chain-walk + tests + Dockerfile + integration).
- **First-session deliverable:** measurement-first stub (companion #1) — confirm magic, measure shape on Medtronic sample, decide with data not speculation (Rule #19).

## Companion intakes

1. **`tibx-magic-and-shape-measurement-2026-05-12`** — 1-2 hour `xxd` investigation of Medtronic samples; identify magic, decompress headers, measure layout. **Recommended even under HOLD.**
2. **`legacy-tib-support-via-dennisss-acronis-tib-2026-05-12`** — separate intake for `.tib` (Archive2); lower priority, mostly out of distribution by 2026.
3. **`acronis-recovery-pe-iso-walker-2026-05-12`** — outer recovery ISO is ISO9660 + WinPE (already supported by `unpack_iso9660.py` + `unpack_wim.py`). Even without `.tibx`, wairz can walk boot.wim, Acronis driver payload, recovery scripts, signed Acronis binaries. **Likely shippable today** — verify operator's current view of the Medtronic upload.
4. **`detection-only-tibx-no-extraction-2026-05-12`** — MVP shim: detect magic, emit `unpack_log` message with operator workflow. Closes silent-failure UX gap. ~1 stream.

Sources:
- [dennisss/acronis-tib GitHub repo](https://github.com/dennisss/acronis-tib)
- [Acronis KB 63498 — TIBX backup format FAQ](https://kb.acronis.com/content/63498)
- [Acronis KB 63441 — tib and tibx backup format usage](https://care.acronis.com/s/article/63441-Acronis-True-Image-2020-and-2021-tib-and-tibx-backup-format-usage)
- [Acronis KB 73032 — Switching from TIB to TIBX](https://care.acronis.com/s/article/73032-Acronis-Cyber-Protect-Home-Office-Switching-from-TIB-Archive2-to-TIBX-Archive3-backup-format)
- [Acronis Forum — mount tibx file](https://forum.acronis.com/forum/acronis-true-image-2020-forum/mount-tibx-file)
- [Acronis Forum — extracting from a .tibx](https://forum.acronis.com/forum/acronis-true-image-2019-forum/extracting-tibx)
- [FileInfo.com — .tibx file extension](https://fileinfo.com/extension/tibx)
- [Acronis Cyber Protect Home Office on Wikipedia](https://en.wikipedia.org/wiki/Acronis_Cyber_Protect_Home_Office)
- [Acronis True Image OEM datasheet](http://dl.acronis.com/u/pdf/oem_datasheet.pdf)
- [Awesome Forensics — DFIR tool catalog (no .tibx)](https://cugu.github.io/awesome-forensics/)
- [Kali Linux Tools — xmount (FUSE disk-image mounter, no .tibx)](https://www.kali.org/tools/xmount/)
- [Kingston Acronis True Image OEM User Guide 2023](https://media.kingston.com/support/pdf/ATI2023OEM_userguide_en-US.pdf)
- [Acronis True Image 2025 User Guide for Windows](https://dl.acronis.com/u/pdf/ATI2025_userguidewindows_en-US.pdf)
- [Medtronic ILLUMISITE product page](https://www.medtronic.com/covidien/en-us/products/interventional-lung-solutions/illumisite-platform.html)
- [QEMU FUSE block-export (vhdx→raw precedent)](https://www.qemu.org/2021/08/22/fuse-blkexport/)
