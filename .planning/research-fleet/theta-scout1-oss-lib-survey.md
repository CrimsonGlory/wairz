# Phase θ Scout 1 — OSS Library Survey

**Date:** 2026-05-12
**Scout:** 1 of 3 (research-fleet pre-pass)
**Lens:** OSS Python library availability + Linux/wairz fit + integration complexity
**Time budget:** 8 minutes wall
**Method:** WebSearch/WebFetch + local pyproject.toml audit

**Wairz dep-set already present (η baseline):** `regipy>=4.0,<5`, `python-evtx>=0.8`, `windowsprefetch>=4.0.3`, `libesedb-python>=20240420`, `dissect.ntfs>=3.10`, `signify>=0.7`, `uefi-firmware>=1.11`, `lief>=0.15.0`, `pefile>=2024.8`, `dnfile>=0.18`, `flare-capa>=9.4`, `LnkParse3>=1.5`, `defusedxml>=0.7.1`, `asn1crypto>=1.5`.

---

### 1. WMI persistence (T1546.003)
- **OSS lib**: `python-cim` (https://github.com/mandiant/flare-wmi/tree/master/python-cim) — Apache-2.0
- **Maintenance**: **dead** — repo archived 2024-07-06 by FireEye/Mandiant; last commit 2018-07-23 by Ballenthin. PyPI package `python-cim` exists per documentation reference (`pip install python-cim`) but PyPI page failed to load during scout (likely 404 — `pip` page error is identical to the python-sdb page error, consistent with PyPI-not-existing). Companion: David Pany's `WMI_Forensics/PyWMIPersistenceFinder.py` is a single 200-LOC keyword-search script over OBJECTS.DATA — public-domain shape, copy-vendor candidate, NOT a dep.
- **Throughput / scale**: O(OBJECTS.DATA size); typical Windows host = 30-200 MB. Pure-Python full parse measured at ~minutes per repository in literature.
- **Linux/wairz fit**: fits in arq worker — OBJECTS.DATA + INDEX.BTR + MAPPING{1,2,3}.MAP are raw files extractable from any NTFS image via existing dissect.ntfs walker (η.A precedent).
- **Integration complexity**: **medium**. python-cim is archived; preferred path is vendor PyWMIPersistenceFinder.py (~200 LOC, Apache-2.0-equivalent) directly into wairz under Rule #36 no-execute discipline. Keyword-search shape (not full repository parse) covers T1546.003 detection without taking on a dead C-extension-free dep that would carry forward maintenance risk.
- **Rating**: **MEDIUM**
- **One-sentence rationale**: PyWMIPersistenceFinder keyword-search vendor-in is a 1-day stream (single inner/outer/safe runner per Rule #39, FilterToConsumerBinding/EventConsumer/EventFilter regex match against OBJECTS.DATA), but the archived upstream forces Rule #19 evidence-first justification ("no maintained alternative, format is documented, scope is bounded to persistence keywords").

### 2. Boot chain artefacts (sub-candidates)
- **OSS lib**:
  - (a) BCD store: `regipy>=4.0,<5` (already in wairz!) — REGF format per Microsoft + Richard W.M. Jones libguestfs blog confirmation; regipy parses any REGF-header hive. No BCD-specific plugin in regipy but the value tree is walkable.
  - (b) MBR/VBR: `ANSSI-FR/bootcode_parser` (https://github.com/ANSSI-FR/bootcode_parser) — GPL-3.0, "maintenance mode" (no PyPI distribution, requires `construct` + `capstone` which wairz has via `capstone>=5.0.0`).
  - (c) ESP `.efi`: subsumed by existing `signify>=0.7` + `pefile` — PE32+ format, Authenticode validation chain already wired in β.4.
- **Maintenance**: regipy **fresh** (v6.2.1 released 2026-01-22); bootcode_parser **stale** (maintenance-mode); signify/pefile **fresh**.
- **Throughput / scale**: BCD <2 MB hive parses in <100 ms via regipy; MBR/VBR are 512-byte sectors (O(1)); ESP `.efi` files are PE32+, signify scan <50 ms per file.
- **Linux/wairz fit**: all three fit existing arq worker shape. BCD hive is at `\boot\BCD` (or `EFI\Microsoft\Boot\BCD` on UEFI systems) — dissect.ntfs walker locates trivially. MBR is sector 0 of the disk image; VBR is sector 0 of the NTFS partition. ESP `.efi` files live on the FAT32 EFI System Partition.
- **Integration complexity**: **small** — (a) BCD: zero new dep, write a regipy-driven walker analogous to η.A.D registry persistence. (b) MBR/VBR: vendor bootcode_parser (or write minimal MBR parser <100 LOC; ANSSI signature whitelist is the value-add but is 5 years stale). (c) ESP `.efi`: pure wiring on existing signify+pefile to walk EFI partition and surface unsigned/expired entries.
- **Rating**: **HIGH** (sub-candidate (a) BCD; specifically a Phase θ pick)
- **One-sentence rationale**: BCD is the high-ROI sub-candidate — zero new dep (regipy already in tree), well-documented REGF format, T1542.003 bootkit-adjacent coverage extending the η.A registry-persistence pattern; sub-candidate (b) MBR/VBR is a follow-up that can vendor bootcode_parser later; sub-candidate (c) ESP signature chain is mostly already covered by β.4 signify wiring and is a small extension.

### 3. Volatility 3 integration
- **OSS lib**: `volatility3>=2.28.0` (https://pypi.org/project/volatility3/) — VSL (Volatility Software License, OSI-compatible-but-custom)
- **Maintenance**: **fresh** — v2.28.0 released 2026-04-30 by Volatility Foundation; active commit cadence.
- **Throughput / scale**: O(memory-dump-size); 4-32 GB typical; plugin invocations are minutes each (heavy reflection + symbol-table lookups).
- **Linux/wairz fit**: pure Python (py3-none-any wheel, 1.4 MB) + no C extensions; **BUT** prerequisite is a memory-dump upload type that wairz does NOT have. Firmware != memory dump in wairz's data model. Need new `MemoryDump` model, new upload flow, new "unpack" hook (= "load profile + run trivial pslist"), new MCP tool category. Volatility 3's input-stream abstraction works on raw, dmp, vmem, lime; hibernation needs hibr2bin pre-process (see candidate 8).
- **Integration complexity**: **large** — architectural change (new firmware-sibling data type, new router family, new MCP category). Re-uses arq worker shape but every other layer is greenfield. Conservative estimate: 5-10 streams, multi-session campaign of its own.
- **Rating**: **DEFER**
- **One-sentence rationale**: dep itself is healthy and pip-installable, but the architectural prerequisite (memory-dump upload as a new top-level data type) is a campaign on its own — not a Phase θ single-stream pick.

### 4. Shim .sdb (T1546.011)
- **OSS lib**: `python-sdb` (https://github.com/williballenthin/python-sdb) — Apache-2.0
- **Maintenance**: **stale** — last commit 2021-01-26 by Ballenthin (5 years inactive); no PyPI release page successfully resolved during scout (`No releases published` on GitHub). Python 3 compatibility per scripts directory; no formal tag.
- **Throughput / scale**: O(file-size); typical .sdb files are 20-500 KB; parse in milliseconds.
- **Linux/wairz fit**: pure Python; fits arq worker; .sdb files live at `C:\Windows\AppPatch\*.sdb` and `C:\Windows\System32\AppPatch\*.sdb` — straightforward dissect.ntfs walk to enumerate, then per-file sdb_dump.
- **Integration complexity**: **medium** — fork-and-vendor python-sdb into `backend/third_party/python_sdb/` per Rule #36-style discipline (no execute; read-only parse); alternatively pin git+https URL in pyproject.toml. Stale upstream means future format drift is on wairz to maintain — but the SDB format hasn't materially changed since XP, so risk is bounded. New inner/outer/safe runner per Rule #39, persistence walker pattern matches η.A.D registry persistence.
- **Rating**: **MEDIUM**
- **One-sentence rationale**: SDB is a high-value persistence vector (T1546.011 used in real campaigns — Latentbot, ShadowPad), the parser exists and is pure-Python, but 5-year-old stale upstream + no PyPI tag forces fork-and-vendor; otherwise a clean Phase θ single-stream pick.

### 5. EFS DDF/DRF (T1486-adjacent)
- **OSS lib**: `dissect.ntfs>=3.10` (already in wairz!) is the access mechanism, but per documentation scout, **no $EFS / $LOGGED_UTILITY_STREAM (attribute 0x100) parser exposed** in the public API. Underlying primitive (raw attribute read by ID) likely available; DDF/DRF blob structure parsing would be wairz-side code over `cryptography` (already in deps) for the DPAPI/RSA unwrap.
- **Maintenance**: dissect.ntfs **fresh** (active fox-it maintenance).
- **Throughput / scale**: O(N files-with-EFS-attribute); typical Windows hosts have <100 encrypted files; raw attribute read is microseconds, DDF parse is microseconds.
- **Linux/wairz fit**: fits arq worker. Reads $EFS attribute (0x100) raw bytes, parses DDF/DRF (Microsoft-documented structure: user SID, public key thumbprint, RSA-encrypted FEK), surfaces as "encrypted file inventory" finding (T1486 insider-threat indicator).
- **Integration complexity**: **medium-to-large** — DDF/DRF binary layout is documented but parsing is wairz-side; need to verify whether dissect.ntfs exposes raw attribute-by-ID read for type 0x100 (probable, since the lower-level `MFT` class typically exposes raw attribute iteration). Cryptographic decode (RSA unwrap) is OUT of scope per Rule #36 — we surface metadata only (who can decrypt, which recovery agent), never the FEK or plaintext.
- **Rating**: **MEDIUM**
- **One-sentence rationale**: high-signal coverage (insider-threat + ransomware-adjacent) and the dep is already in tree, but inner-loop work depends on confirming dissect.ntfs raw-attribute exposure and writing the wairz-side DDF/DRF struct parser — 2-day single-stream rather than 1-day.

### 6. EVT (pre-Vista event logs)
- **OSS lib**: `libevt-python` (https://pypi.org/project/libevt-python/) — LGPL-3.0-or-later, latest 20240421 (released 2024-04-21)
- **Maintenance**: **fresh** — Joachim Metz / libyal organization actively releases; consistent with `libesedb-python` discipline already in wairz.
- **Throughput / scale**: O(file-size); typical XP/2003 .evt files are 0.5-10 MB; parse in seconds.
- **Linux/wairz fit**: fits arq worker, same C-extension build shape as `libesedb-python` (already in tree — proven Dockerfile pattern). Python bindings (pyevt) work on Linux against extracted .evt files.
- **Integration complexity**: **small** — add `libevt-python>=20240421` to pyproject.toml; mirror η.A or pre-η EVTX walker shape (`evtx_service.py` precedent in ε.1.b.3, commit c0e4979); new inner/outer/safe runner per Rule #39.
- **Rating**: **MEDIUM** (LOW-MEDIUM)
- **One-sentence rationale**: technically clean and cheap (small dep, libyal pattern already in tree), but coverage gap is for **legacy XP/2003 firmware only** — wairz user base is unlikely to hit pre-Vista images often, so ROI is bounded; if Phase θ has slack capacity, EVT is a low-risk fill-in; otherwise defer.

### 7. ETL (Event Tracing for Windows)
- **OSS lib**: `etl-parser` (https://github.com/airbus-cert/etl-parser, https://pypi.org/project/etl-parser/) — Apache-2.0
- **Maintenance**: **dead** — last release v1.0.1 in **2020-07-23** (~6 years inactive); README explicitly notes WPP support not implemented.
- **Throughput / scale**: O(file-size); ETL files are typically 10-500 MB; pure-Python parse is slow (literature suggests minutes for large kernel logs).
- **Linux/wairz fit**: pure Python 3, fits arq worker.
- **Integration complexity**: **medium** — single dep, but partial format coverage (TraceLogging + manifest providers + MOF kernel logs; **no WPP**) means a chunk of real-world ETL files won't decode. PyETW (FireEye) is Windows-only ETW collection, not offline ETL parsing — does NOT apply.
- **Rating**: **LOW**
- **One-sentence rationale**: 6-year-stale upstream + partial format coverage + bounded forensic value (ETL on disk is rare relative to EVTX; usually ephemeral telemetry) makes this a low-priority pick versus the WMI/BCD/SDB/EFS options.

### 8. hibernate.sys
- **OSS lib**: `MagnetForensics/Hibr2Bin` (https://github.com/MagnetForensics/Hibr2Bin) — GPL-3.0, C++; Volatility 3 plugins for hibernation address-space.
- **Maintenance**: Hibr2Bin C++ code last open-sourced 2017; "supports Win8+" but literature notes incomplete decompression. Volatility 3 hibernation address-space is part of the actively-maintained Vol3.
- **Throughput / scale**: O(hibernation-file-size); typical 2-16 GB compressed; decompression + analysis = significant CPU and disk.
- **Linux/wairz fit**: Hibr2Bin needs Linux build (C++; possible but not pip-installable; GPL-3.0 license incompatible with Apache-2.0 conservative shape). Volatility 3 hiber address-space works on Linux but is downstream of candidate 3's architectural prerequisite.
- **Integration complexity**: **large** — same prerequisite as candidate 3 (memory-dump-flavored upload type for wairz); Hibr2Bin pre-process step adds C++ build dep + GPL-3.0 license complication for the worker image.
- **Rating**: **DEFER**
- **One-sentence rationale**: honestly subsumed by Volatility 3 candidate 3 — the architectural prerequisite is the same memory-dump upload flow, hibernation analysis is just one more Volatility plugin invocation; not a standalone Phase θ pick.

---

## Synthesis — Top 3 ranked for Phase θ single-stream pick

Sweet spot: **MEDIUM-or-better rating** AND **small-or-medium complexity**. Ranking:

1. **#2(a) BCD store via existing regipy** — **HIGH**, **small complexity**. Zero new dep (regipy is already in pyproject.toml from η). BCD format == REGF == regipy already parses. T1542.003 bootkit-adjacent coverage extends η.A.D registry-persistence pattern using the SAME library and SAME inner/outer/safe runner shape (Rule #39 recipe is mature). Path: dissect.ntfs walker locates BCD store on system partition → regipy parses → enumerate boot entries → surface anomalous entries (unsigned bootloader hash, unexpected `path` element, suspicious `description` strings). **Estimated single stream, 4-6 hours wall, perfectly fits Phase θ's η-precedent cadence.** Sub-candidates (b) MBR/VBR and (c) ESP .efi chain are natural follow-up streams that could be bundled in the same campaign if capacity allows, but BCD alone is the high-confidence pick.

2. **#6 EVT (pre-Vista) via libevt-python** — **MEDIUM**, **small complexity**. Single new dep (`libevt-python>=20240421`), mirrors `libesedb-python` build pattern already in Docker image. Coverage value is bounded (legacy firmware only) but the implementation is the LOWEST-risk option on the board — fresh upstream, established libyal pattern, established walker shape (clone evtx_service.py to evt_service.py + adapt 5-state machine). **Estimated single stream, 3-5 hours wall.** Use this if Phase θ wants a guaranteed-clean shippable stream; pair with #1 BCD for a 2-stream Phase θ.

3. **#4 SDB shim database via fork-and-vendor python-sdb** — **MEDIUM**, **medium complexity**. T1546.011 persistence (real-campaign value: Latentbot, ShadowPad, FIN7 use sdbinst-based shimming). python-sdb is pure-Python, stale upstream (2021), no PyPI tag — forces vendor-in OR git+https pin. Format is XP-era stable (no drift risk). Walker shape mirrors η.A.D. **Estimated single stream, 5-7 hours wall** (extra time on vendor-in scaffolding + Rule #36 no-execute-discipline test gate). Use this as the third stream if Phase θ wants a 3-stream wave like η.

**Honorable mentions (deliberately ranked LOW for Phase θ):**
- #1 WMI (medium complexity, valuable but archived upstream — vendor a 200-LOC keyword-search shape rather than the full python-cim repository parser; OK for Phase ι, not Phase θ's clean shape).
- #5 EFS DDF/DRF (medium-to-large complexity, requires dissect.ntfs raw-attribute API verification + wairz-side struct parser — schedule for Phase ι once a regression-test fixture is identified).
- #3 Volatility 3 and #8 hibernate.sys (both DEFER — share an architectural prerequisite that's a campaign on its own).
- #7 ETL (LOW — 6-year stale upstream + partial format coverage).

**Recommended Phase θ shape:** Wave-1 single stream on **#1 BCD** (highest confidence, zero new dep, η-pattern continuity). If session has surplus capacity, add **#6 EVT** as Wave-2 (independent stream, no shared file paths with BCD, safe per Rule #23 worktree discipline). Defer **#4 SDB** to Phase ι unless Phase θ is given multi-session scope.

---

## Sources

- https://github.com/mandiant/flare-wmi
- https://github.com/davidpany/WMI_Forensics
- https://github.com/williballenthin/python-sdb
- https://github.com/williballenthin/python-cim (404 — archived parent flare-wmi/python-cim)
- https://github.com/volatilityfoundation/volatility3
- https://pypi.org/project/volatility3/
- https://github.com/libyal/libevt
- https://pypi.org/project/libevt-python/
- https://github.com/airbus-cert/etl-parser
- https://github.com/ANSSI-FR/bootcode_parser
- https://github.com/MagnetForensics/Hibr2Bin
- https://github.com/mkorman90/regipy
- https://github.com/fox-it/dissect.ntfs
- https://docs.dissect.tools/en/latest/projects/dissect.ntfs/
- https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics
- https://rwmj.wordpress.com/2010/04/03/use-hivex-to-unpack-a-windows-boot-configuration-data-bcd-hive/
- http://ntfs.com/attribute-encrypted-files.htm
- https://attack.mitre.org/techniques/T1542/003/
- /home/dustin/code/wairz/backend/pyproject.toml (local audit — η-baseline dep set)
