---
title: "QNX .ifs extraction tooling research — Go/No-Go assessment"
status: research-complete
priority: medium
discovered: 2026-05-07
type: research
session: 2026-05-07-session2
---

## Summary (TL;DR)

- **Recommendation: Go-with-caveats.** Ship a `unpack_qnx_ifs` handler at PARTIAL capability, wrapping `jtang613/qnx_dumpers` (`ifsdump`) — the only candidate with a clean-room implementation, an explicit MIT license header, and an active 2025 release.
- **Primary tool choice:** `jtang613/qnx_dumpers/ifsdump` (MIT, C, build via `gcc + zlib + liblzo2 + libucl`, no QNX SDK dependency, no proprietary header lineage). Listing AND extraction supported; LZO/UCL/zlib decompression covered. Build inside the existing worker container; do NOT bring in the QNX SDP.
- **Biggest unknown / risk:** `jtang613/qnx_dumpers` has only 8 stars, one contributor, three commits (May–June 2025) and no test corpus or CI. Format-coverage breadth is unverified against real QNX firmware variants (BMW HU, automotive head units, medical). Mitigation: gate the handler at PARTIAL, ship listing-first, fall back to `unpack_no_handler` on any non-zero exit. Two backup paths exist (`ReverseEngDotDev/dump_hbcifs` for HBCIFS-wrapped vehicle firmware; `ttepatti/dumpifs-linux` as a derivative-of-QNX-source last resort if the clean-room tool fails on a real image — but the second path is *legally* a redistribution risk and should NOT ship in the worker image).

## Decision matrix

| Option | Tool | License | Completeness | Confidence | Recommendation |
|---|---|---|---|---|---|
| **A — Recommended** | `jtang613/qnx_dumpers/ifsdump` | MIT (explicit header) | List + Extract (LZO/UCL/zlib) | Medium | Ship as PARTIAL handler; log failures; fall back to `unpack_no_handler` |
| B — Backup for HBCIFS | `ReverseEngDotDev/dump_hbcifs` | None declared (forked from askac/dumpifs which carries the proprietary `$QNXLicenseC$` header) | List + Extract incl. multi-section vehicle firmware | Low (license risk) | Do NOT ship; cite as workaround in PARTIAL-failure path docs only |
| C — Reference impl | `ttepatti/dumpifs-linux` | None declared; carries `$QNXLicenseC$` proprietary header verbatim | Full extraction (matches QNX dumpifs) | Low (license-blocked) | Do NOT ship; users may run on host as documented workaround |
| D — Reference impl | `askac/dumpifs` | None declared; carries `$QNXLicenseC$` proprietary header verbatim | Full extraction | Low (license-blocked) | Do NOT ship; same workaround note as C |
| E — Defer | unblob plugin (custom handler) | MIT | Would need authoring (no public QNX-IFS handler exists) | Low (cost: weeks) | Defer; revisit if open-source QNX-IFS handler appears upstream |
| F — Defer | binwalk 3.x | MIT | Magic-byte detection only; no parser | High (incomplete) | Already deferred; binwalk's QNX-IFS support has been a stale issue (#840) since March 2025 |
| G — Defer | QNX SDP `dumpifs` | Non-Commercial (NC) restrictive; no commercial redistribution | Full | High (license-blocked for OSS) | Do NOT ship; a public-OSS project shipping NC-licensed binaries in a public Docker image is inconsistent with the NC license terms |
| H — No-Go | Document workaround | n/a | n/a | High | Acceptable fallback if Option A fails on real-world test corpus |

## Q1: Format documentation

**Public spec from QNX/Blackberry: PARTIAL.** QNX publishes user-facing docs for `mount_ifs`, `mkifs`, and `dumpifs` (covering CLI usage, runtime semantics, and high-level structure — startup header → optional compressed body → image header → directory + file data → trailer), but does NOT publish a byte-level field-by-field spec for the on-disk format. ([QNX 8.0 mount_ifs](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mount_ifs.html), [QNX 6.5 dumpifs](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_utilities/d/dumpifs.html)) — accessed 2026-05-07, high confidence.

**Magic bytes (already in `format_detection.py:211`):** the optional startup header begins with `0xeb7eff7e` (LE) or `0x00ff7eeb` (byte-swapped). The startup header is 256 bytes and contains compression info, boot params, image entry point, and a checksum. The image header that follows the optional decompressed body has the signature `imagefs` (7 bytes ASCII) per the openqnx source.

**Independent reverse-engineered specs (high confidence):**
- `jtang613/qnx_dumpers` README documents the IFS layout in detail: `boot_info_s` (QSSL_F3S signature for EFS, separate ImageFS structures), unit info, extent chains, directory entries with `first`/`next` pointer chains, file-data extents, compression block headers (`iwlyfmbp` signature for compressed file blocks). ([README](https://github.com/jtang613/qnx_dumpers/blob/master/README.md)) — accessed 2026-05-07, medium-high confidence (single-author research, no peer review).
- `ReverseEngDotDev/dump_hbcifs` source includes `startup.h`, `image.h`, `hbcifs.h`, `hdr.h`, `elf.h`, `elftypes.h` — full header definitions for the layered format (HBCIFS wrapper + IFS + ELF executables). ([repo tree](https://github.com/ReverseEngDotDev/dump_hbcifs)) — accessed 2026-05-07, high confidence on shape, low on origin (dump_hbcifs is forked from `askac/dumpifs` which carries the proprietary openqnx header verbatim, so its struct definitions plausibly trace back to leaked QNX SDP source).
- `vocho/openqnx` mirror at `trunk/utils/m/mkxfs/dumpifs/dumpifs.c` is the canonical authoritative source — but it carries a "must obtain a written license" notice that excludes it from clean-room redistribution. ([dumpifs.c](https://github.com/vocho/openqnx/blob/master/trunk/utils/m/mkxfs/dumpifs/dumpifs.c)) — accessed 2026-05-07, high confidence.

**Verdict:** the format is well-documented enough to reverse-engineer cleanly (jtang613 demonstrates this); QNX has not published a formal byte-level spec but the practical layout is public via dumpifs source + community write-ups (Karamba, HAKSTUFF).

## Q2: Open-source extraction tools

### Candidate A — `jtang613/qnx_dumpers/ifsdump` (RECOMMENDED)

| Field | Value |
|---|---|
| Exists / active | Yes; latest commit 2025-06-29; only 3 commits total (initial 2025-05-26, structure-output 2025-05-27, ifsdump-added 2025-06-29) |
| License | **MIT (explicit C-source header: `Author: Jason Tang / License: MIT`)** — but no `LICENSE` file at repo root (license is per-source-file). Recommend bundling a `LICENSE` copy when packaging in wairz. |
| Completeness | List-only mode (`-l`); full extraction (`-x`); selective file extraction by name; preserves directory structure |
| Compression | LZO + UCL + zlib (the three codecs documented for IFS/EFS) |
| Language / deps | C; `-lz -llzo2 -lucl`; standard build with `gcc + Makefile` |
| Recent stable release | No tagged releases. Master branch only. Version 2.0 stamp in README (June 2025). |
| Source: README | [README.md](https://github.com/jtang613/qnx_dumpers/blob/master/README.md) accessed 2026-05-07, high confidence |
| Source: license header | [ifsdump.c first 50 lines](https://github.com/jtang613/qnx_dumpers/blob/master/ifsdump.c) accessed 2026-05-07, high confidence |
| Stars / contributors | 8 / 1 (jtang613 sole contributor) — narrow ecosystem |
| Heritage | Author claims "Based on research of QNX IFS filesystem structures." No QNX-attribution lines in source. Treated as clean-room. |

### Candidate B — `ReverseEngDotDev/dump_hbcifs`

| Field | Value |
|---|---|
| Exists / active | Yes; latest commit 2024-03-18 (≈14 months stale at research time) |
| License | **None declared at repo root or in C++ source headers.** README explicitly states "based on https://github.com/askac/dumpifs" — and `askac/dumpifs` is a verbatim fork of openqnx's proprietary-licensed dumpifs.c. |
| Completeness | Full extraction including multi-section vehicle firmware (HBCIFS wrapper around IFS-pre-boot/IFS-boot/IFS-rootfs) |
| Compression | LZO + UCL (deflate-via-LZO/UCL) |
| Language / deps | C++; `liblzo + libucl + openssl-dev (MD5)`; CMake build |
| Stars / contributors | 22 / single primary maintainer |
| Source: [README](https://github.com/ReverseEngDotDev/dump_hbcifs#readme) | accessed 2026-05-07, high confidence |
| Heritage red flag | Forked from askac/dumpifs which carries the proprietary `$QNXLicenseC$` header verbatim. dump_hbcifs's `dump_hbcifs.cpp` does NOT carry the proprietary header in its `main` file — but the supporting `startup.h`, `image.h`, etc. likely contain QNX-derived struct definitions. **Legally ambiguous.** |

### Candidate C — `ttepatti/dumpifs-linux`

| Field | Value |
|---|---|
| Exists / active | Yes; latest commit 2024-03-02 (≈26 months stale) |
| License | **None declared.** Source files (`dumpifs.c`) carry the proprietary `$QNXLicenseC$` header verbatim — "You must obtain a written license from and pay applicable license fees to QNX Software Systems before you may reproduce, modify or distribute this software." |
| Completeness | Full extraction (it IS the QNX dumpifs, lightly patched to compile on Linux without QNX SDP) |
| Compression | LZO + UCL (matches QNX dumpifs) |
| Language / deps | C; `liblzo2-dev + libucl-dev`; pre-built x86-64 ELF binary in repo + Makefile |
| Stars / contributors | 3 / forked from `askac/dumpifs` via `sickcodes` |
| Source: [README](https://github.com/ttepatti/dumpifs-linux#readme), [dumpifs.c header](https://github.com/ttepatti/dumpifs-linux/blob/master/dumpifs.c) | accessed 2026-05-07, high confidence |
| Heritage | Direct openqnx descendant. Recommended workaround for users to run on the host, NOT bundled into wairz worker. |

### Candidate D — `askac/dumpifs`

| Field | Value |
|---|---|
| Exists / active | Yes; latest commit 2022-01-16 (≈4 years stale) |
| License | **None declared.** Same proprietary `$QNXLicenseC$` header as Candidate C. |
| Completeness | Full extraction |
| Stars | 64 (highest in the candidate set, but stars ≠ recency) |
| Source: [repo](https://github.com/askac/dumpifs) | accessed 2026-05-07, high confidence |
| Verdict | Direct openqnx fork. Same legal posture as Candidate C — NOT shippable. |

### Candidate E — unblob plugin

`unblob` is the firmware extraction layer wairz already uses (`backend/app/workers/unpack_common.py`). Status:
- **No public QNX IFS filesystem handler exists.** unblob's filesystem handler directory contains only btrfs, cramfs, ext, fat, iso9660, jffs2, minix, ntfs, romfs, squashfs, ubi, ufs, yaffs, plus android. ([handlers/filesystem](https://github.com/onekey-sec/unblob/tree/main/python/unblob/handlers/filesystem)) — accessed 2026-05-07, high confidence.
- **QNX deflate compression IS supported** (`handlers/compression/qnx_deflate.py`) — added in late 2025 per the ONEKEY blog. ([ONEKEY post](https://www.onekey.com/resource/latest-developments-in-unblob-new-formats-smarter-extraction-and-a-more-hardened-release-pipeline)) — accessed 2026-05-07, high confidence.
- The unblob blog's "QNX image filesystem (IFS v4)" reference points to **private/proprietary** ONEKEY handlers, not the open-source release.
- **Implication:** unblob will detect the QNX deflate compression block and decompress it, but won't reconstruct the IFS filesystem structure. Authoring an unblob plugin from scratch would duplicate the work in Candidate A; cleaner to wrap the existing CLI tool.

### Candidate F — binwalk 3.x

- Only magic-byte detection for QNX IFS; no filesystem parser. ([Issue #840 — open since 2025-03-14](https://github.com/ReFirmLabs/binwalk/issues/840)) — accessed 2026-05-07, high confidence.
- Stale issue, no upstream commitment to add extraction. Not viable.

### Candidate G — `ReFirmLabs/qnx6-extractor`

- **Wrong format.** Targets QNX4/QNX6 native filesystems (different from IFS). Listed only for completeness; not relevant to the wairz `QNX_IFS` detection bucket.

## Q3: QNX SDK licensing

**The current QNX licensing landscape (as of 2026-05-07):**

1. **QNX Free Non-Commercial License (announced Nov 2024, available Jan 2025).** Hobbyists, students, and academic users can download QNX SDP 8.0 at no cost. Restrictions: no commercial redistribution, no use in safety-critical or "high-risk" applications, no AWS-external cloud deployment. ([QNX Everywhere](https://www.qnx.com/products/everywhere/), [Hackster summary](https://www.hackster.io/news/blackberry-s-qnx-seeks-hobbyists-and-makers-with-free-non-commercial-license-raspberry-pi-image-7c53320cac11), [HN thread](https://news.ycombinator.com/item?id=42079460)) — accessed 2026-05-07, high confidence.
2. **The Non-Commercial License explicitly forbids redistribution.** Per the [BB QNX Development License (Non-Commercial Class) PDF](https://support7.qnx.com/download/download/51624/BB_QNX_Development_License_Non-Commercial_License_Class_v6_2024-11-1.pdf) — though the rendered PDF text was not extractable in this session, [the official QNX page](https://www.qnx.com/products/everywhere/) and the [community summary](https://www.hackster.io/news/blackberry-s-qnx-seeks-hobbyists-and-makers-with-free-non-commercial-license-raspberry-pi-image-7c53320cac11) state explicitly: "Commercial redistribution and distribution are not permitted under the non-commercial license." This rules out shipping `dumpifs` from the SDP into a public Docker image even for a non-commercial OSS project, because the act of pushing the image to a public registry IS redistribution. Confidence: high (multiple corroborating sources).
3. **The 2007 QNX source release is NOT Apache 2.0.** Despite QNX's [Open Source License Agreements page](https://www.qnx.com/legal/licensing/open_source.html) prominently mentioning Apache 2.0, the per-file headers in the `vocho/openqnx` mirror (which is the lineage of `askac/dumpifs` → `ttepatti/dumpifs-linux` → `ReverseEngDotDev/dump_hbcifs`) carry a much more restrictive `$QNXLicenseC$` header — "You must obtain a written license from and pay applicable license fees" — dated 2007. ([dumpifs.c](https://github.com/vocho/openqnx/blob/master/trunk/utils/m/mkxfs/dumpifs/dumpifs.c)) The Apache 2.0 release applied to the Neutrino kernel and base C library; the userland utilities (including dumpifs) were under a separate, restrictive license. Confidence: high (verified by inspecting the source header directly).
4. **No commercial redistribution rights for QNX-derived dumpifs source under any current license channel.** A wairz Docker image that bundles `ttepatti/dumpifs-linux` or `askac/dumpifs` (or any descendant carrying the `$QNXLicenseC$` header) is technically a license violation, even though those repos exist publicly on GitHub. The legal risk is non-zero: BlackBerry/QNX has historically pursued license-enforcement actions, and shipping a derived binary in a public Docker registry is the most visible form of redistribution.

**Net:** Only Option A (`jtang613/qnx_dumpers`) is legally clean for an OSS project. The author claims clean-room implementation based on format research, the source carries an MIT header, and there are no `$QNXLicenseC$` traces. Best practice when packaging: vendor the source into the worker image's build stage (compile from source), copy the LICENSE info into wairz's `THIRD_PARTY_NOTICES.md`, and pin to a specific commit SHA so an upstream license change can't surprise the project.

## Q4: Real-world QNX firmware

**Where QNX shows up in the wild:**

- **Automotive infotainment.** BMW HU NBT EVO (BMW's pre-2018 head units) ran QNX 6.5.0 — the [HAKSTUFF blog walkthrough](https://www.hakstuff.net/blog/extracting-qnx-ifs-partitions) (accessed 2026-05-07) explicitly extracts a BMW IFS via `dumpifs-folderized.sh` and finds passwd/shadow files, vehicle processor binaries, and network config. Audi A5/S5 owners' forum [thread](https://www.a5oc.com/threads/extracting-ifs-root-ifs-image-file-solved.177873/) describes manually extracting `ifs-root.ifs` from the MMI (Multi Media Interface) head unit. Both are first-party-supplier firmware (Harman/Becker, Continental) often distributed as multi-section HBCIFS-wrapped IFS — Candidate A covers the IFS layer, Candidate B covers the HBCIFS wrapper.
- **Other automotive.** Ford Sync 3 (some variants), various Tier-1-supplier head units, and ADAS modules. Less publicly documented; analyst writeups are sparse.
- **Medical.** Some medical-imaging consoles and patient monitors use QNX. wairz's existing testing has touched MTK/Android/Linux firmware but not (yet) reported a medical QNX upload.
- **Defense and aerospace.** Highly regulated, unlikely to surface as a wairz user upload.
- **Industrial.** Some PLCs and controller HMIs use QNX. Niche.

**Form on-disk:**
- Bare `.ifs` files (rarely uploaded directly by users — usually pulled out of larger update packages by other tools first).
- HBCIFS-wrapped multi-section vehicle firmware (`pre-boot.ifs + boot.ifs + root.ifs` concatenated under a Harman/Becker container).
- Embedded inside larger update bundles — `tar`/`zip`/proprietary updaters that wairz's existing recursive unblob unwraps. The QNX_IFS detection in `format_detection.py:211` matches on the startup-header magic, so as long as unblob exposes the `.ifs` blob to the format-detection layer, the new handler will be invoked.

**Real-world expectation for wairz users:** automotive RE researchers (especially the BMW/Audi/Ford head-unit hobbyist community) are a substantial slice of demand for QNX support. Medical and defense users are unlikely to upload but a portion of platform-claim credibility is delivered by SUPPORTING the format even if the upload volume stays low.

## Q5: Minimal viable scope

**Smallest useful extraction (PARTIAL):** list archive contents only.
- Run `ifsdump -l <input>` (or equivalent listing flag) to capture the file inventory; persist to `device_metadata['qnx_ifs_listing']` JSONB.
- Capability label: `PARTIAL` — same shape as wairz already uses for "we detected the format and surfaced metadata but didn't reconstruct a browseable filesystem."
- Cost: ~1 day (handler stub + listing parse + tests).

**Recommended scope (FULL):** list + extract.
- Run `ifsdump -x -d <output_dir> <input>` to reconstruct the filesystem under `extracted_path`.
- Detection roots already recognise the unpacked tree per Rule #16/#18 (no extra wiring needed if the directory layout matches Linux rootfs conventions, which IFS does).
- Capability label: `FULL`.
- Cost: ~2-3 days (handler + tests + a first real-firmware canary). The marginal effort over PARTIAL is small because `ifsdump -x` is a one-flag-flip from `-l`.
- Risk: jtang613/qnx_dumpers is unproven against real-world IFS variants. Ship `PARTIAL` first, gather upload telemetry over 2 weeks, promote to `FULL` once the listing path proves robust.

**Strategy-registry slot (mirror the iso9660 shape):**

```python
# backend/app/workers/extraction_strategies.py
DetectedFormat.QNX_IFS: unpack_qnx_ifs,  # Phase 2 handler 4 — ifsdump (jtang613/qnx_dumpers)
```

Handler module shape (mirroring `unpack_iso9660.py`):
- `backend/app/workers/unpack_qnx_ifs.py`: `async def unpack_qnx_ifs(firmware: Firmware, db: AsyncSession) -> UnpackResult` — `await asyncio.create_subprocess_exec("ifsdump", "-x", "-d", out_dir, ifs_path)`, capture stderr, persist listing into `device_metadata`, return.
- Worker Dockerfile additions: `apt-get install -y liblzo2-dev libucl-dev zlib1g-dev` + a build stage that vendors `jtang613/qnx_dumpers` at a pinned SHA, runs `make`, and copies `ifsdump` into `/usr/local/bin`.
- Tests: `backend/tests/test_unpack_qnx_ifs.py` covering happy path (small fixture IFS), corrupted-input rejection, listing-only mode, and a Rule #35b live-canary against a real BMW HU image if available.

**Build-time integration cost:** the Dockerfile delta is small (3 libs + 1 build stage); no QNX SDP bring-in is required since jtang613 is self-contained. Estimate: 4-6 hours for the Docker plumbing + 8-12 hours for the handler/tests = roughly 1.5-2 dev days for FULL capability.

## Go / No-Go

**Recommendation: Go-with-caveats.**

If Go (recommended path):
- **Tool choice:** `jtang613/qnx_dumpers/ifsdump`, vendored at a pinned commit SHA (initial pin: `master @ 2025-06-29`).
- **License:** MIT (per source-file header). Add a `LICENSE.qnx_dumpers` copy to the wairz repo at `backend/third_party/qnx_dumpers/LICENSE.MIT` and reference in `THIRD_PARTY_NOTICES.md`.
- **Estimated effort:** 1.5-2 dev days for FULL capability; 0.5-1 dev day for PARTIAL-only first iteration.
- **Phasing recommendation:** ship PARTIAL first (listing only); promote to FULL after ≥1 successful real-firmware canary. Mirrors the cautious shape used for the WIM and Windows installer ISO handlers.
- **Risks:**
  - **Format-coverage breadth unverified.** jtang613/qnx_dumpers has no public test corpus. Real-world IFS variants (different QNX versions, vendor-specific extensions, HBCIFS wrappers) may not parse cleanly. Mitigation: treat any non-zero exit as a soft-fail; persist the error and fall back to `unpack_no_handler` so the unpack pipeline doesn't block.
  - **HBCIFS-wrapped vehicle firmware.** Won't be handled by ifsdump alone. If a BMW/Harman image with HBCIFS shows up, the handler will fail. Mitigation: document the workaround (run `dump_hbcifs` on the host); revisit shipping a HBCIFS pre-stripper if upload telemetry shows demand. Do NOT ship `dump_hbcifs` in the worker image (license risk).
  - **Upstream tool abandonment.** Single-author, small-star-count repo. Mitigation: vendor at a pinned SHA, fork into the wairz GitHub org if upstream goes silent.
  - **License surprise.** Source carries MIT in headers but no top-level LICENSE file. Mitigation: confirm with author via GitHub issue, or include a clear "MIT, per source-file headers" attribution in `THIRD_PARTY_NOTICES.md`.
- **Integration shape:** mirror `backend/app/workers/unpack_iso9660.py`; register in `backend/app/workers/extraction_strategies.py:67` (replacing the current `unpack_no_handler` line). Use the Rule #33 PARTIAL-capability pattern (listing → metadata) for the first cut.

If No-Go (defer):
- **Document workaround:** in `backend/app/workers/unpack_no_handler.py`'s rejection-message path, point users at `jtang613/qnx_dumpers` and `ttepatti/dumpifs-linux` to run on their own host before re-uploading the extracted filesystem as a tarball.
- **Re-open trigger:** any one of (a) a wairz user reports a QNX firmware upload that fails to extract, (b) jtang613/qnx_dumpers gains a tagged stable release + test corpus, (c) unblob ships a public QNX IFS filesystem handler upstream.

## Sources

- [QNX 8.0 mount_ifs documentation](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mount_ifs.html) — accessed 2026-05-07 — high confidence — establishes that QNX provides user-facing CLI docs but no byte-level format spec
- [QNX 6.5 dumpifs documentation](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_utilities/d/dumpifs.html) — accessed 2026-05-07 — high confidence — CLI reference confirming `-x`, `-d`, `-l` flag semantics
- [QNX Everywhere — Free Non-Commercial license](https://www.qnx.com/products/everywhere/) — accessed 2026-05-07 — high confidence — current QNX free-tier landscape
- [BlackBerry's QNX Seeks Hobbyists, Hackster](https://www.hackster.io/news/blackberry-s-qnx-seeks-hobbyists-and-makers-with-free-non-commercial-license-raspberry-pi-image-7c53320cac11) — accessed 2026-05-07 — high confidence — cross-reference for the NC license terms including explicit "no commercial redistribution"
- [HN: QNX is now free for anything non-commercial (2024)](https://news.ycombinator.com/item?id=42079460) — accessed 2026-05-07 — high confidence — community reception + precedent of two prior QNX "rug pulls"
- [QNX Open Source License Agreements](https://www.qnx.com/legal/licensing/open_source.html) — accessed 2026-05-07 — high confidence — Apache 2.0 release applied to kernel + base C library, NOT userland tools like dumpifs
- [vocho/openqnx mirror — dumpifs.c](https://github.com/vocho/openqnx/blob/master/trunk/utils/m/mkxfs/dumpifs/dumpifs.c) — accessed 2026-05-07 — high confidence — proves dumpifs source carries the proprietary `$QNXLicenseC$` "must obtain a written license" header
- [vocho/openqnx repo metadata](https://github.com/vocho/openqnx) — accessed 2026-05-07 — high confidence — confirms last push 2015-11, no LICENSE/COPYING file at root
- [jtang613/qnx_dumpers repo + README + ifsdump.c header](https://github.com/jtang613/qnx_dumpers) — accessed 2026-05-07 — high confidence on license claim (MIT in source header); medium confidence on coverage breadth (no public test corpus, sole maintainer)
- [ReverseEngDotDev/dump_hbcifs README](https://github.com/ReverseEngDotDev/dump_hbcifs) — accessed 2026-05-07 — high confidence on capability (HBCIFS multi-section vehicle firmware); low confidence on license clarity (no LICENSE, parent fork carries proprietary header)
- [ttepatti/dumpifs-linux README + dumpifs.c](https://github.com/ttepatti/dumpifs-linux) — accessed 2026-05-07 — high confidence — direct openqnx descendant carrying the proprietary `$QNXLicenseC$` header verbatim
- [askac/dumpifs README](https://github.com/askac/dumpifs) — accessed 2026-05-07 — high confidence — same proprietary lineage as ttepatti/dumpifs-linux
- [onekey-sec/unblob handlers tree](https://github.com/onekey-sec/unblob/tree/main/python/unblob/handlers) — accessed 2026-05-07 — high confidence — confirms NO public QNX IFS filesystem handler in unblob; only `compression/qnx_deflate.py`
- [unblob — supported formats](https://unblob.org/formats/) — accessed 2026-05-07 — high confidence — only QNX deflate is publicly supported
- [ONEKEY blog: latest unblob developments](https://www.onekey.com/resource/latest-developments-in-unblob-new-formats-smarter-extraction-and-a-more-hardened-release-pipeline) — accessed 2026-05-07 — high confidence — confirms QNX IFS filesystem support exists only in "private" ONEKEY handlers, not the OSS release
- [ReFirmLabs/binwalk Issue #840 — QNX4/QNX6 detection](https://github.com/ReFirmLabs/binwalk/issues/840) — accessed 2026-05-07 — high confidence — open issue since 2025-03-14, no upstream extraction commitment
- [Karamba Security — Extracting QNX IFS](https://karambasecurity.com/blog/2017-10-19-extracting-the-content-of-a-qnx-ifs-image) — accessed 2026-05-07 — medium confidence — 2017 walkthrough; demonstrates the listing-then-extract workflow that the wairz handler can mirror
- [HAKSTUFF — Extracting QNX IFS Partitions](https://www.hakstuff.net/blog/extracting-qnx-ifs-partitions) — accessed 2026-05-07 — high confidence — establishes BMW HU NBT EVO QNX 6.5.0 as a real-world target and recommends the dumpifs-linux fork
- [Audi A5 forum — Extracting ifs-root.ifs](https://www.a5oc.com/threads/extracting-ifs-root-ifs-image-file-solved.177873/) — accessed 2026-05-07 — medium confidence — community evidence of Audi MMI head-unit RE demand
- [BB QNX Development License Non-Commercial PDF](https://support7.qnx.com/download/download/51624/BB_QNX_Development_License_Non-Commercial_License_Class_v6_2024-11-1.pdf) — accessed 2026-05-07 — low confidence — PDF text not extractable in this session; license terms confirmed via Hackster + QNX Everywhere page cross-reference instead
