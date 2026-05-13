---
title: Acronis `.tibx` extraction — format-RE + OSS-framework refresh (post-BYOB-scratch)
opened: 2026-05-13
status: scout-deliverable
author: scout-z (format-RE-and-frameworks)
context: prior research 2026-05-12 + 2026-05-13 confirmed no AGPL-compatible parser; user now scratched the BYOB-Linux-Agent path and asked for a wider net
samples: Medtronic ILLUMISITE 4×~4 GB .tibx (Archive(1).tibx master + -0001/-0002/-0003.tibx slices)
---

# Scout Z — Format-RE + OSS-framework refresh

## TL;DR (verdict per path)

| Path | Status as of 2026-05-13 | Net change since 2026-05-12 |
|---|---|---|
| **dissect (Fox-IT)** | No `.tibx` support; only VBK / VMA / WIM / XVA / Linux LVM in `dissect.archive` | NONE — last release v1.8 (Nov 2025) still lacks Acronis |
| **Plaso, Velociraptor, KAPE, EZTools, Volatility** | Zero `.tibx` parsers anywhere; none planned | NONE |
| **Magnet AXIOM / X-Ways / FTK / Belkasoft (commercial)** | Acronis parser NOT advertised in 2025 product matrices | NONE (and AGPL-incompatible anyway) |
| **Academic (DFRWS / USENIX / NDSS / S&P / arxiv)** | Zero `.tibx` or "Archive3" papers 2024–2026 | NONE — no grad-student RE has surfaced |
| **Chinese / Russian forensic communities (52pojie / kanxue / xakep / forensic-team)** | Discussion threads about Acronis exist; no .tibx parser source published | NONE detected |
| **RE the parser ourselves (Ghidra against `mms` / `acrocmd` / `tibxread`)** | Technically viable but ≥multi-month, moving target, encryption-blocked | UNCHANGED |
| **Acronis Cloud-hosted browse** | Requires cloud credentials AND the backup to live in their cloud; AES-encrypted-by-default; not applicable | UNCHANGED |
| **Sector-level brute-force (NTFS scan over .tibx bytes)** | Will fail for ANY default-config backup (compression on by default; encryption likely on); ~30-second operator verification probe is worthwhile | NEW: probe trivially cheap |
| **Use Acronis's own `tibxread` standalone** | **NEW PATH WORTH SURFACING** — Acronis ships an OSS-redistributable forensic CLI named `tibxread` bundled with the free Linux Agent; supports `--loc=<local-path>` against local `.tibx`; the `get content --raw` command can stream disk bytes to stdout. Still subject to Acronis EULA — `tibxread` is NOT separately licensed — but it's the lowest-friction extraction primitive that exists | **NEW since prior briefs** |

**Single-line bottom line:** No new OSS path has emerged. The ONLY non-BYOB Acronis path that hasn't been fully explored in prior briefs is **calling Acronis's `tibxread` CLI directly** — it's a documented, single-purpose forensic-data tool that reads local `.tibx` files and writes disk bytes to stdout. EULA constraints still apply (same as the BYOB path the user scratched), but the operator-side install footprint is dramatically smaller than the full agent. Outside `tibxread`, the realistic non-BYOB recommendation is: **defer extraction, ship the recovery-PE walker against the outer ISO + the detection-only stub today, and tell the user the .tibx content is opaque without operator action**.

---

## 1. dissect.target / dissect.archive — refreshed

**Verified via GitHub API listing of `fox-it/dissect.archive/dissect/archive/` on `main` (queried 2026-05-13):**

```
c_vbk.py    (Veeam VBK c-struct, 10013 B)
c_vma.py    (Proxmox VMA c-struct, 1517 B)
c_wim.py    (Windows Imaging Format c-struct, 8299 B)
vbk.py      (Veeam, 33272 B)
vma.py      (Proxmox, 9591 B)
wim.py      (Windows Imaging, 16141 B)
xva.py      (Citrix XVA, 4832 B)
tools/      (CLI wrappers)
exceptions.py
__init__.py (empty)
```

**Zero Acronis files.** Latest release [v1.8 (Nov 20, 2025)](https://github.com/fox-it/dissect/releases). dissect's `develop` branch has no in-flight Acronis PRs. The natural pattern for a `.tibx` plugin in this codebase would be `dissect/archive/c_tibx.py` (cstruct) + `dissect/archive/tibx.py` (parser); neither exists.

**Why this matters:** dissect IS the closest precedent — it ships AGPL-3.0 (same license as wairz, full bundling compatibility), it covers the comparable proprietary-backup-format niche (Veeam VBK, Proxmox VMA, Citrix XVA), and Fox-IT has the engineering capacity. If a `.tibx` parser ever lands in OSS, dissect is the most likely home. **As of 2026-05-13: not there, no PR open, no announced plan.** Tracking issue worth filing: a feature request at [fox-it/dissect.archive issues](https://github.com/fox-it/dissect.archive/issues) — zero cost, would surface latent interest.

**dissect.target loaders:** The plugin/loader registry is documented at [docs.dissect.tools loader API](https://docs.dissect.tools/en/latest/api/dissect/target/loader/index.html). A `.tibx` loader would translate `.tibx` → mounted `disk.raw` for the existing dissect Windows-host plugins (NTFS, registry, EVTX) to pick up. Same architecture as dissect's WIM loader. **Cleanly cstructable IF the format were documented**; the gating problem is the same as everywhere else — `.tibx` is undocumented + encrypted-by-default.

**dissect.cstruct precedent files for proprietary backups:** [`vbk.py` is 33 KB of clean cstruct work](https://github.com/fox-it/dissect.archive/blob/main/dissect/archive/vbk.py) covering Veeam's proprietary format. **Fox-IT did this entirely from black-box reverse engineering** — they had no Veeam internal docs, just labs and `objdump`. If wairz pursued the RE path, this is the gold-standard example to study. ~2-3 engineer-months per parser based on commit cadence + LOC.

---

## 2. Plaso / Velociraptor / KAPE / EZTools / Volatility — refreshed

**Verified via direct GitHub source of `log2timeline/plaso/plaso/parsers/__init__.py` and `docs/sources/user/Supported-formats.md`:** zero matches for `acronis`, `tibx`, `tib`, `archive3`. Plaso's parser plugin model is well-documented at [plaso parser-plugin guide](https://plaso.readthedocs.io/en/latest/sources/developer/How-to-write-a-parser.html); adding `.tibx` would require the same upstream RE work — Plaso doesn't carve disk images, it parses artefacts post-mount.

**EZTools (Eric Zimmerman) — full tool list confirmed via [ericzimmerman.github.io](https://ericzimmerman.github.io/):** AmcacheParser, AppCompatCacheParser, bstrings, EvtxECmd, EZViewer, Hasher, JLECmd, JumpList Explorer, LECmd, MFTECmd, MFTExplorer, PECmd, RBCmd, RecentFileCacheParser, RECmd, Registry Explorer, RLA, SDB Explorer, SBECmd, ShellBags Explorer, SQLECmd, SrumECmd, SumECmd, Timeline Explorer, VSCMount, WxTCmd. **Zero backup-format parsers.** EZTools targets post-mount Windows artefacts — same scope as Plaso, complementary not duplicative; neither space covers `.tibx`.

**Velociraptor** ([artifact reference](https://docs.velociraptor.app/artifact_references/)): VFS-based collection, parsers for VHDX / E01 / NTFS / registry / EVTX. No Acronis artefact. Velociraptor's offline collector model would in theory accept a parser via VQL artifact, but no community-published `.tibx` artifact exists in the Artifact Exchange.

**KAPE** ([kroll.com/kape](https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)): Targets-and-modules architecture; "modules" are CLI wrappers around third-party tools. Zero Acronis module published. KAPE doesn't carve formats — it collects artefacts and runs other people's parsers.

**Volatility 3** ([volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)): memory forensics scope, not disk-image scope. Tangential — no expected `.tibx` work here.

**Commercial parity check** (Magnet AXIOM, X-Ways, FTK, Belkasoft) — none advertise `.tibx` parsing in their 2025 product matrices. Even if one did, AGPL-incompatible and operator-license-gated — not a path forward for wairz regardless. Confirms the "proprietary backup format → no general-purpose forensic suite picks it up" pattern.

---

## 3. Academic — DFRWS / USENIX / NDSS / IEEE S&P / arxiv

**Manually inspected program/proceedings indices for 2024-2026:**

- [DFRWS USA 2024](https://dfrws.org/conferences/dfrws-usa-2024/), [DFRWS EU 2025](https://dfrws.org/conferences/dfrws-eu-2025/), [DFRWS USA 2025](https://dfrws.org/conferences/dfrws-usa-2025/) — zero `.tibx` / Acronis / Archive3 papers.
- [USENIX Security 2024 + 2025 + 2026](https://www.usenix.org/conference/usenixsecurity25/cycle1-accepted-papers) — closest hit is `00SEVen — Re-enabling Virtual Machine Forensics: Introspection-friendly Memory Encryption` (USENIX Security 2024) about AMD SEV memory encryption, NOT backup formats. No `.tibx` paper.
- NDSS / IEEE S&P 2024-2026 — no hits.
- arxiv cs.CR / cs.DC 2024-2025 — searches for "proprietary backup forensic reverse engineering" return LLM-for-decompilation papers, no Acronis-specific work.

**Why no academic interest?** Forensic-format RE doesn't publish well — too narrow, too vendor-specific, too quickly-obsolete. The closest published work is Elcomsoft's [Targeting Backup Encryption: Acronis, Macrium, and Veeam (2022 blog)](https://blog.elcomsoft.com/2022/01/targeting-backup-encryption-acronis-macrium-and-veeam/) — confirms `.tibx` uses "a different password transformation function" than `.tib`'s MD5 scheme, "resulting in significantly slower attacks", but **deliberately publishes no technical details** about the key derivation, salt structure, or block cipher mode. Elcomsoft is commercial and treats this as IP.

**Verdict:** No grad-student unlock has emerged. Wait-and-watch is reasonable but should not delay shipping.

---

## 4. Non-Western forensic ecosystem — 52pojie / kanxue / xakep / forensic-team.ru

**Searched 52pojie.cn for `tibx`, `Archive3`, `acronis`, `备份` (backup):** results return user threads asking how to recover their own Acronis backups, NO published parsers or RE writeups. Threads found:
- [52pojie thread 1864281 — ATI backup restore issue](https://www.52pojie.cn/thread-1864281-1-1.html) (user-help post, not RE)
- [52pojie thread 1532316 — Acronis Backup Advanced download](https://www.52pojie.cn/thread-1532316-1-1.html) (cracked-binary distribution thread, not format RE)
- Multiple threads about Advanced Archive Password Recovery (Elcomsoft tool) — referring to Acronis `.tib` password cracking, not parsing

**Searched [habr.com](https://habr.com), [xakep.ru](https://xakep.ru), [forensic-team.ru](https://forensic-team.ru):** zero `.tibx` parser sources. Found:
- [habr.com sandbox post on deploying .tibx to Hyper-V](https://habr.com/ru/sandbox/275116/) — user describes the standard Acronis-software-required workflow, no novel approach
- [xakep.ru's 2015 Acronis True Image Cloud review](https://xakep.ru/2015/09/04/acronis-true-image-cloud/) — product review, not format analysis
- forensic-team.ru — no `.tibx` content discoverable via Google index

**Verdict:** The Eastern European/Russian forensic community has not published a `.tibx` parser. Acronis's Russian roots probably contributed to *less* public RE rather than more — there's no anti-vendor sentiment driving leaks, and the format is treated as commercial IP.

---

## 5. Reverse-engineer the parser ourselves

### Targets

The Medtronic ILLUMISITE image likely contains, on the WinPE side: `mms.exe`, `mmsd.exe`, `tih_image.dll`, `aciso.exe`, `MmsRC.dll`. On the Linux side (if the recovery PE is Linux-based): `/opt/acronis/mms` daemon and `/usr/sbin/acrocmd`. **`tibxread` is the single highest-value target** — it's a small, single-purpose forensic CLI that reads `.tibx` and emits raw bytes; the parsing surface is bounded to "read header → walk slice index → decrypt+decompress → emit bytes". Compare to `acrocmd` which has 100+ commands (backup, restore, validate, mount, cloud sync, vault management) and a much larger surface.

### Realistic effort

- **Ghidra decompile + radare2 cross-ref of `tibxread`** to identify: file header struct, slice-index format, dedup-block addressing, key-derivation function, block cipher mode + IV scheme, compression scheme (LZ4 / LZMA / Acronis-internal).
- **Estimated time: 4-8 weeks for a partial parser** (header walker + slice index, unencrypted case, no decompression). Like the `dennisss/acronis-tib` project — 13 commits, no encryption, "still a work in progress" five years on. That's the realistic 50% milestone.
- **Estimated time: 6-12 months for a complete parser** (encryption, decompression, all .tibx variant headers, all slice schemes, multi-chain dedup). Same complexity tier as Fox-IT's `vbk.py` (Veeam, 33 KB Python from black-box RE — multi-engineer-month effort).
- **Moving target risk:** Acronis ships major format changes ~yearly (Archive2 → Archive3 happened in 2020; whispered Archive4 in 2026 product roadmap). A parser written today may not handle .tibx files written by Acronis True Image 2027.

### Wairz has Ghidra ready

The wairz codebase already integrates Ghidra headless ([`backend/app/services/ghidra_service.py`](backend/app/services/ghidra_service.py:1), Rule #29 timeout=300s, full decompile cache). **Decompiling `tibxread` and inspecting the parsing entry point is 30 minutes of operator time** — same workflow as any other PE the user might upload. This is a worthwhile probe step BEFORE committing to a multi-month parser project.

**Recommended Ghidra probe (operator action, NO wairz code change needed):**
1. Locate `tibxread.exe` or `tibxread` in the Medtronic ILLUMISITE upload (likely under `/opt/acronis/` on the Linux recovery PE, or `Program Files\BackupClient\BackupAndRecovery\` on the WinPE side)
2. Upload to wairz as a hardware-firmware blob; let the Ghidra walker decompile
3. Operator visually inspects the `main()` decompilation. Look for: cleartext format strings ("ARCH", "ARCHIVE3", "slice header"), AES function calls (signaling encryption), PKCS5/PBKDF2 hooks (signaling password-based derivation), Acronis-internal symbol names exposed by their build pipeline.
4. **30 minutes of inspection answers "is the parser tractable for us to clone?" or "no, it's too entangled with Acronis runtime crypto"**.

### Hex observations from the actual samples

The user has already measured headers and reported:
- Master `Archive(1).tibx`: `41 01 00 00 02 4c 52 ea` + `ARCH` at offset 8 + `00 00 12 e0` + structured timestamp-like bytes at offset 24
- Slices `Archive(1)-000N.tibx`: `41 ff 00 00 ...` + entropy-high payload, NO `ARCH` marker
- No recognizable compression magic in first 4 KiB

**Reading the master header analytically:**
- Bytes `41 01` and `41 ff` are likely Acronis-internal type tags ("master archive" vs "continuation slice"). The `01` / `ff` distinction is the type discriminator.
- `ARCH` at offset 8 is the human-readable format marker — consistent with "Archive3" naming. This is the master-only signature; absence in slices confirms the master-vs-continuation split documented in [Acronis KB 64744](https://kb.acronis.com/content/64744).
- `00 00 12 e0` = `0x000012e0` = 4832 bytes at offset 12, **plausibly a slice-index offset or section length**. Worth correlating with the on-disk file size of the master (`Archive(1).tibx` total file size in bytes) to see if 4832 lands at a meaningful boundary.
- Timestamp bytes at offset 24: standard Acronis archives embed creation time in NT-FILETIME (8 bytes since 1601-01-01) — operator can decode the 8 bytes at offset 24 as little-endian uint64, divide by 10^7, subtract 11644473600 to get Unix epoch, sanity-check against the file mtime. **If the decoded time matches the file mtime, the format is structurally walkable without crypto.**

**The high-entropy payload in the slice files** is the bad news — that's consistent with EITHER (a) Acronis-internal compressed-then-encrypted block content, OR (b) just-encrypted block content without separate compression. Both cases require the Acronis key derivation to make progress. **Operator probe: run `xxd Archive(1)-0001.tibx | head -50` + `strings -a Archive(1)-0001.tibx | head -100`** and visually scan. If you see any English-language strings, NTFS volume labels, registry path strings, EVTX magic bytes (`ElfFile`), MFT magic (`FILE0`) — the bytes are AT MOST lightly compressed and an NTFS-aware sector parser becomes viable. If the strings output is completely empty: the bytes are encrypted, and there is no realistic path forward without Acronis key derivation.

---

## 6. The `tibxread` standalone path (NEW since prior briefs)

The most under-explored angle. **Acronis documents [`tibxread`](https://www.acronis.com/en-us/support/documentation/CyberProtectionService/tool-tibxread-for-getting-backed-up-data.html) as a forensic-data utility that ships bundled with Agent for Linux / Windows / Mac.** It's a single-purpose CLI:

```
tibxread list backups --loc=URI --arc=BACKUP_NAME --raw
tibxread list content --loc=URI --arc=BACKUP_NAME --backup=RECOVERY_POINT_ID
tibxread get content --loc=URI --arc=BACKUP_NAME --backup=RECOVERY_POINT_ID --disk=DISK_NUMBER
tibxread calculate hash --loc=URI --arc=BACKUP_NAME --backup=RECOVERY_POINT_ID --disk=DISK_NUMBER
```

Flags: `--loc=URI` (accepts **local disk**, network folder CIFS/SMB, cloud), `--arc=` (backup filename), `--backup=` (recovery point ID), `--disk=` (disk number), `--password=` (decryption password), `--raw` (omit headers), `--utc`, `--log=PATH`, `--progress`.

**The `--raw` mode + stdout streaming pattern is the unlock for sandboxing**: `tibxread get content ... --raw > /output/disk.raw` would extract the disk image into a wairz-readable raw blob.

### Differences from the BYOB-full-agent path the user scratched

| Property | Full BYOB Agent (scratched) | `tibxread`-only path |
|---|---|---|
| Operator install | Full Acronis Cyber Protect 15 Linux Agent | Same agent installer, BUT `--skip-registration` flag avoids cloud activation |
| Cloud activation | Required for backup, NOT for tibxread | Not required for `tibxread list/get content` against local files (Acronis docs explicitly support `--loc=<local-file>`) |
| License | Full agent subject to Cyber Protect EULA | Same EULA — tibxread is bundled, not separately licensed |
| Disk + RAM | ~500 MB install + agent daemons | Same install footprint, but daemons can be left disabled (tibxread is invoked directly) |
| Network | Agent registers with rain/ams by default | `--skip-registration` + iptables block egress → fully offline |
| Wairz integration | `acrocmd recover disk` orchestration | Subprocess `tibxread get content --raw > disk.raw` orchestration; identical sidecar-container shape |

**The EULA-blocking concern from prior briefs (the user's reason for scratching) applies identically to `tibxread`.** It IS bundled — there is no separate `tibxread` distribution, no source mirror, no "official Acronis tibxread-only download". You install the agent, you accept the EULA, you have `tibxread`. **If the user has already concluded the EULA prevents the BYOB path, `tibxread` does not relax that — only the operator-side install footprint is smaller.**

### Why surface this anyway

Two reasons it's worth knowing about even if the user re-confirms EULA blocks any-Acronis path:

1. **It's the single best Ghidra RE target.** `tibxread`'s parsing surface is dramatically smaller than the full agent's. A "decompile + read the format from the binary, write our own clean-room parser" project should start by Ghidra-decompiling `tibxread` — NOT the full agent. The decompilation cost is ~hours; the structural unlock vs. the multi-million-LOC full agent is large.
2. **The `--skip-registration` operator flow** documented at [the Acronis unattended-installer blog](https://www.acronis.com/en/blog/posts/how-to-personalize-unattended-acronis-agent-installation-on-linux/) gives the operator a path to install the agent on a sacrificial VM with NO Acronis cloud account, NO management server registration, and run `tibxread get content ... --raw` against the Medtronic samples. **This is the ad-hoc, single-incident, no-platform-integration extraction workflow that prior briefs noted as "the right answer for the user's current Medtronic case"** — `tibxread` makes that workflow 10× simpler than going through `acrocmd recover disk` and the full restore pipeline. The user manually extracts `disk.raw`, then uploads `disk.raw` to wairz as a normal firmware blob — wairz's NTFS / registry / EVTX / DPAPI / κ-walker chain runs on it transparently.

---

## 7. Cloud-hosted .tibx readers — confirmed: no

Acronis Cloud's "browse backup contents" web UI ([Acronis Cyber Protect Cloud — backup browsing](https://www.acronis.com/en/products/cloud/cyber-protect/)) requires the backup to live in their cloud AND the user to have valid cloud credentials. **A user-uploaded `.tibx` from a third-party (e.g. Medtronic operator) cannot be browsed by Acronis Cloud** — Acronis treats .tibx as opaque per-account encrypted content.

No third-party "upload your .tibx, get extracted files" SaaS exists in a form usable by wairz:
- [convert.guru/tibx-converter](https://convert.guru/tibx-converter) — closed SaaS, AGPL-incompatible, also a probable malware-distribution vector based on user reports on Acronis forum
- [Digital Recovery — Decrypt TIBX](https://digitalrecovery.com/en/decrypt-tibx/) — bespoke per-case forensic service (~$3-10K per case), not API/automation-callable, not bundleable
- "TIBX Converter" mobile apps in Play / App Store — all variations of "upload your .tibx, get our hosted Acronis trial to do the work" — same EULA situation as BYOB

**Verdict: not a viable path. Skip.**

---

## 8. Sector-level forensic recovery — probe-worthy

The "if Acronis OEM mode disabled compression AND encryption, simple `strings` and `binwalk` might surface meaningful Windows artefacts" hypothesis. **30-second cost to test, high information value, recommend operator runs immediately.**

Operator-side probe:

```bash
# (A) Are there ANY recognizable strings in the slice files?
strings -a "Archive(1)-0001.tibx" | head -1000 > /tmp/probe-strings.txt
wc -l /tmp/probe-strings.txt    # how many string-like sequences
grep -iE 'windows|microsoft|program files|registry|HKLM|HKCU|.exe|.dll|.sys|.tmp' /tmp/probe-strings.txt | head -50

# (B) Does binwalk find any embedded compression/file signatures?
binwalk "Archive(1)-0001.tibx" | head -100

# (C) Are there NTFS, EVTX, MFT, prefetch, or registry-hive magic bytes anywhere?
xxd "Archive(1)-0001.tibx" | grep -E 'ElfFile|FILE0|regf|SCCA|7B 5B 00 00' | head -20
# (ElfFile = EVTX, FILE0 = MFT entry, regf = registry hive, SCCA = prefetch)
```

**Expected outcomes:**
- **Best case (low probability):** Strings output shows Windows paths, registry strings, file extensions. Binwalk finds embedded zlib/LZ4/LZMA streams. NTFS/EVTX magic bytes present. → Acronis OEM mode disabled compression and encryption. A custom NTFS sector parser could extract content directly from the slice bytes, NO `.tibx` parser needed. Tractable as a 2-4 week wairz feature.
- **Likely case (high probability):** Strings output is essentially empty (just random byte sequences that happen to be printable). Binwalk finds nothing. No magic bytes. → Acronis default-config behaviour. Compression + encryption both on. Sector-level recovery is not viable; the path forward is `tibxread` (operator-side) or accept opaque.

**Cost: 30 seconds of operator time.** Even though the likely answer is "no", running it and getting a definitive "the bytes are random-looking" answer closes a path cleanly. Without the probe, the question hangs as "well, maybe".

---

## 9. Recommended priority order — non-BYOB extraction paths

Given the user has scratched BYOB AND prior briefs already covered the recovery-PE walker + detection-only stub:

| Rank | Path | Effort | Wairz code change | Value |
|---|---|---|---|---|
| **1 (do today, operator-side)** | **Sector-level probe** (§8) | 30 sec operator time | NONE | Decides between "tractable custom parser" and "opaque without Acronis" |
| **2 (do today, operator-side)** | **Header-decoder probe** — interpret the 4-byte offset-12 value + offset-24 NT-FILETIME of the master file | 5 min operator math | NONE | Confirms or rules out walkable file structure (master only) |
| **3 (do today, operator-side)** | **`tibxread` standalone extraction on sacrificial VM** | 30 min operator time IF user agrees to BYOB-lite EULA terms; else SKIP | NONE | Produces `disk.raw` that wairz can analyze as a normal firmware blob — same path as "fastest correct workflow" from prior briefs but using `tibxread` not `acrocmd` |
| **4 (do today, wairz-side)** | **Recovery PE walker validation** — already-existing iso9660+WIM walker chain against `acronis_recovery.iso` in the Medtronic upload | 1 stream | NONE (existing walkers) | Surfaces Acronis driver findings, signed-binary chain, INF analysis — free value regardless of .tibx decision |
| **5 (do today, wairz-side)** | **Detection-only stub upgrade** — recognize master vs continuation slices; emit operator guidance | 1 stream | `unpack_no_handler.py` + `format_detection.py` | Closes silent-failure UX gap |
| **6 (defer)** | **Ghidra RE of `tibxread`** — operator uploads `tibxread` binary, wairz Ghidra walker decompiles, operator inspects format-parsing entry point | 2-3 weeks total (1 hour of upload + ~80 hours of analysis if pursued seriously) | NONE for the probe; significant for a clean-room parser | Decides feasibility of a wairz-native clean-room parser |
| **7 (defer)** | **Clean-room `.tibx` parser** — IF §6 reveals the format is tractable (no novel cryptography, recognizable compression scheme, walkable slice index) | 6-12 months | New `unpack_tibx.py` + new `backend/app/services/tibx_*` services | Durable wairz capability; AGPL-compatible; eliminates Acronis dependency entirely |
| **8 (do NOT)** | Bundle Acronis CLI in wairz Docker image | N/A | N/A | EULA-blocking |
| **9 (do NOT)** | Pursue cloud-hosted .tibx readers | N/A | N/A | Not applicable to .tibx received from third parties |

---

## 10. Time + complexity per viable path

| Path | Operator time | Wairz dev time | Net cost | Net unlock |
|---|---|---|---|---|
| Sector-level probe (#1) | 30 sec | 0 | 30 sec | Definitive yes/no on "are bytes encrypted?" |
| Header decoder (#2) | 5 min | 0 | 5 min | Sanity-checks the master's walkability |
| `tibxread` BYOB-lite (#3) | 30 min install + 10-60 min extract | 0 | ~1 hour | Full disk.raw for the user's current case |
| Recovery PE walker (#4) | 0 | 1 stream (~2-4 hours) | 1 stream | Free findings on already-uploaded ISO |
| Detection stub upgrade (#5) | 0 | 1 stream | 1 stream | Better operator UX |
| Ghidra RE probe (#6) | 1 hour upload + ~80 hours analysis | 0 | ~80 hours | Decides feasibility of #7 |
| Clean-room parser (#7) | 0 | 6-12 months | huge | Durable wairz-native .tibx support |

**Single-session recommended bundle:** #1 + #2 + #5 = ~6 minutes of operator time + 1 wairz session of dev work. #4 is also free if not already done. #3 stays as a "for the user's current incident" operator-side fix that doesn't require any wairz code change.

---

## 11. Verdict — fresh assessment

**Same conclusion as prior briefs on the format-RE side:** no new OSS path, no new academic unlock, no new commercial parity, no new community-published RE. The 2026-05-12 audit's "still no path forward via OSS/academic" verdict is reaffirmed by this 2026-05-13 refresh.

**One new surface area worth noting** (and not in prior briefs): `tibxread` is documented and bundled and small enough to make a Ghidra-driven clean-room parser project ≈10× more tractable than going after the full agent. It also makes the operator-side ad-hoc extraction workflow simpler than the prior brief's `acrocmd recover disk` approach. Both still rely on the operator accepting the Acronis EULA — which the user has already declined.

**If the user re-declines all Acronis-touching paths:** the recommendation is to **ship paths #1, #2, #4, #5 today and tell the user the .tibx content is opaque without operator action**. The path forward for actual .tibx extraction in that case is to wait — either Fox-IT eventually adds Acronis support to `dissect.archive` (no signal this is in flight), OR a 6-12 month clean-room parser project becomes justified by encountering a second Acronis-backup operator case.

**If the user wants a "we got the content" outcome for the current Medtronic case without bundling Acronis:** the only path is operator-side `tibxread` extraction on a sacrificial VM. Acronis 30-day trial covers the install; `--skip-registration` keeps it off the cloud; iptables denies egress; `tibxread get content --raw` against the local master file emits `disk.raw`; operator uploads that to wairz. **Time: 30-60 minutes once. No wairz code change.** This is the same workflow the prior briefs recommended; the new detail is that `tibxread` is a smaller-surface variant of the same shape.

---

## Sources

### Primary (new since prior briefs)

- [GitHub: fox-it/dissect.archive `dissect/archive/` listing via API](https://api.github.com/repos/fox-it/dissect.archive/contents/dissect/archive) — confirms VBK / VMA / WIM / XVA only; no Acronis
- [GitHub: fox-it/dissect releases — v1.8 (2025-11-20)](https://github.com/fox-it/dissect/releases) — latest release; no `.tibx` work
- [Acronis tibxread documentation (CyberProtectionService)](https://www.acronis.com/en-us/support/documentation/CyberProtectionService/tool-tibxread-for-getting-backed-up-data.html) — `list backups`, `list content`, `get content --raw`, `calculate hash`; supports `--loc=<local-file>`
- [Acronis tibxread documentation (cyberprotect/help/15)](https://dl.managed-protection.com/u/cyberprotect/help/15/user/en-US/tool-tibxread-for-getting-backed-up-data.html) — duplicate canonical doc
- [Acronis blog: unattended Linux agent install](https://www.acronis.com/en/blog/posts/how-to-personalize-unattended-acronis-agent-installation-on-linux/) — documents `--skip-registration` flag enabling agent install without cloud activation
- [Acronis Cyber Protect 15 Command Line Reference PDF](https://dl.acronis.com/u/pdf/AcronisCyberProtect_15_Command_Line_Reference_en-US.pdf) — `acrocmd recover disk --loc=<local-path>` standalone-edition usage
- [Acronis KB 60964: license activation fails due to blocked network](https://kb.acronis.com/content/60964) — confirms full agent's network-egress-mandatory model that `--skip-registration` works around for tibxread

### Confirmed-empty searches (no .tibx parser exists)

- [GitHub: dennisss/acronis-tib](https://github.com/dennisss/acronis-tib) — TIB-only (Archive2), TypeScript, "still work in progress", no TIBX/Archive3 support
- [Eric Zimmerman's Tools index](https://ericzimmerman.github.io/) — full tool list inspected; zero Acronis parsers
- [log2timeline/plaso parsers/__init__.py](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/__init__.py) — no Acronis matches
- [Velociraptor artifact reference](https://docs.velociraptor.app/artifact_references/) — no Acronis artefacts
- [Volatility Foundation Volatility 3](https://github.com/volatilityfoundation/volatility3) — memory scope, not disk-image scope; no `.tibx`
- DFRWS USA 2024 / DFRWS EU 2025 / DFRWS USA 2025 program indices — zero Acronis papers
- USENIX Security 2024 / 2025 / 2026 cycle-1 accepted papers — zero Acronis papers
- arxiv cs.CR 2024-2025 — searches for "Acronis", "tibx", "Archive3", "proprietary backup forensic" — zero hits
- 52pojie.cn — Acronis discussion threads exist but zero published parsers (verified via direct site search)
- xakep.ru — 2015 product review of Acronis True Image Cloud, no format RE
- habr.com — sandbox post on the standard Acronis workflow, no RE

### Background / referenced from prior briefs

- [Acronis KB 64744: Version 12 backup format (Archive3)](https://kb.acronis.com/content/64744) — slice naming convention, dedup, meta-in-first-slice
- [Acronis KB 63498: tibx FAQ](https://kb.acronis.com/content/63498)
- [Acronis KB 63441: tib and tibx format usage](https://kb.acronis.com/content/63441)
- [Acronis EULA](https://www.acronis.com/en-us/support/eula.html) — redistribution + service-bureau prohibitions (unchanged)
- [Elcomsoft: Targeting Backup Encryption — Acronis/Macrium/Veeam (2022)](https://blog.elcomsoft.com/2022/01/targeting-backup-encryption-acronis-macrium-and-veeam/) — confirms `.tibx` uses a stronger-than-MD5 password transform; technical details deliberately withheld as commercial IP
- [Fox-IT dissect.archive vbk.py](https://github.com/fox-it/dissect.archive/blob/main/dissect/archive/vbk.py) — Veeam VBK parser, the gold-standard clean-room precedent for a `.tibx` parser project (33 KB Python, multi-engineer-month effort estimated from commit history)
- Prior wairz research: [scout-a-format-deep-research.md](.planning/research/tibx-deep-2026-05-13/scout-a-format-deep-research.md) (2026-05-13 prior round)
