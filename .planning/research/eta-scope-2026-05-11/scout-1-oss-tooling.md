# Scout 1 — OSS Tooling Survey for η Candidate Set

Date: 2026-05-11. Scope: Python-first, license, maintenance, API stability, deps for the 7 η candidates. Worker is Python 3.12 in the wairz worker container.

---

## 1. Memory dump triage / Volatility integration

- **Library:** `volatility3` (volatilityfoundation/volatility3)
- **License:** Volatility Software License (VSL) v1.0 — custom permissive (BSD-style derived; not OSI-listed but explicitly grants commercial use). Watch-out: not Apache 2.0 as the candidate brief assumed; need legal review for the asymmetry, but the license is explicitly permissive and used by commercial DFIR vendors.
- **Last release:** v2.28.0 on 2026-04-30 (active; v2.27.0 on 2026-01-29). 4.1k stars.
- **Status:** Production. Pure Python (99.9%); pip-installable; Python 3.8+. Optional `[full]` extras for yara/capstone.
- **Plugin coverage:** All requested Windows plugins shipped in core: `windows.pslist`, `windows.pstree`, `windows.dlllist`, `windows.registry.hivelist`, `windows.hashdump`, `windows.malfind`, `windows.vadinfo`. Mimikatz lives in `community3`.
- **Alternative — `memprocfs` (UlfFrisk):** v5.17 on 2026-02-22, 4.1k stars, AGPL-3.0 (license blocker for closed deployments; OK for wairz which is open-source). Native CPython C extension (Linux+Windows wheels). Faster than vol3 for live mem; for static images vol3 wins on plugin breadth.
- **Alternative — Rekall (google/rekall):** **DEAD.** Officially archived; GRR migrated off it.
- **Recommendation:** USE `volatility3`. Use-as-a-library API is documented at volatility3.readthedocs.io.

## 2. ETL (Event Trace Log) parsing

- **Library A:** `etl-parser` (airbus-cert/etl-parser) — Apache 2.0, pure Python, no system deps. Last release v1.0.1 on 2020-07-23 (8 commits total). **STALE — 5+ years no release.** Observer-pattern API: `IEtlFileObserver.on_event_record(event)` with `event.parse_tracelogging()` / `event.parse_etw()`. Handles MOF kernel + Tracelogging; WPP marked future work.
- **Library B (PREFERRED):** `dissect.etl` (fox-it/dissect.etl) — AGPL-3.0, Python 99.1%, last release v3.14 on 2025-11-20 (active), pip-installable via `pip install dissect.etl`. Part of Fox-IT/NCC Group's Dissect framework. 5 stars only (Dissect modules are individually small but the umbrella has ~1k+).
- **License caveat:** Both Apache (etl-parser, stale) and AGPL (dissect.etl, active). Wairz is open-source so AGPL is fine for the worker, but flag it for downstream.
- **Recommendation:** USE `dissect.etl` — actively maintained, same-org cohort with other Dissect modules already candidate for #3, #4, #6. FALLBACK to `etl-parser` if the AGPL is a problem (license review needed).

## 3. hibernate.sys decompression

- **Library A:** `pyxca` (jborean93/pyxca) — MIT, 3 stars, 12 commits, **EXPERIMENTAL** (author's own warning). NOT pure Python (Cython + C, requires GCC). Implements MS-XCA Xpress+Huffman; doesn't claim hibernation use specifically — would need wrapper code to navigate hiberfil.sys's PO_MEMORY_IMAGE header + compressed Xpress block arrays.
- **Library B (PREFERRED):** Use `volatility3` directly — vol3 has a hibernation layer that handles xpress-huffman natively for memory acquisition (same loader API as raw/lime/vmem). Existing GitHub issue #692 confirms Win10+ hiberfil.sys support is in develop. Avoids re-solving the decompression problem.
- **Library C:** `Hibr2Bin` (MagnetForensics) — C++ CLI tool, no Python binding, build-and-shell-out shape only.
- **Recommendation:** SKIP standalone Python lib; FOLD into Volatility 3 integration (#1). If standalone parsing is needed, the cleanest path is `dissect.target` (#7-adjacent) for header inspection + a vol3 layer for actual decompression.

## 4. EVT (legacy pre-Vista Event Log)

- **Library:** `libyal/libevt` with `libevt-python` PyPI package
- **License:** LGPL-3.0 (dual GPL-3.0). Acceptable for wairz worker; flag for vendor analysis.
- **Last commit:** Repo has 355 commits total; libyal libraries get periodic batched releases. PyPI listing exists.
- **Stars:** 60. Status: alpha but PRODUCTION-USED across the libyal forensic tool ecosystem (plaso, dfvfs).
- **Pip install:** YES — `pip install libevt-python` ships pre-compiled wheels for Linux (manylinux), macOS, Windows. (Confirmed via libbde-python and libfsntfs-python sister packages — same publishing pattern.) No need to compile from C.
- **Recommendation:** USE `libevt-python` from PyPI. Mature; small surface; libyal's binding pattern is consistent with `pyfsntfs` / `pyregf` already implicitly required for #6.

## 5. BitLocker FVEK detection-only

- **Library:** `libyal/libbde` with `libbde-python` PyPI package
- **License:** LGPL-3.0/GPL-3.0 dual.
- **Last release:** PyPI 2024-05-02; 250 stars; 340 commits. Stable cadence (not abandoned, batched releases).
- **Pip install:** YES — wheels for Python 3.8–3.12 across Linux (manylinux), macOS 12+, Windows x86/x64.
- **Detection-only API:** `pybde.volume()` open call against the volume header succeeds and exposes `volume.encryption_method`, `volume.is_locked`, `volume.creation_time` WITHOUT requiring keys. Reading sectors requires the key, but the verdict ("encrypted volume detected, AES-XTS, vendor-key required") needs only the header read. This is the cleanest Python-native path.
- **Alternative — `dislocker`:** C tool with no maintained Python binding.
- **Recommendation:** USE `libbde-python`. Clean header-only API matches the "detection without recovery" verdict shape exactly.

## 6. EFS DDF/DRF cert-key matching

- **CRITICAL FINDING — `libfsntfs` explicitly does NOT support EFS.** README lists "Encrypted File System (EFS)" under "Unsupported NTFS format features." Affects both C lib and `pyfsntfs`/`libfsntfs-python` Python binding. Latest release was 2025-10-28 (active project, but EFS won't appear soon).
- **Alternative — `pytsk3` (py4n6/pytsk):** Mature SleuthKit Python binding (production; ntfsdump/ntfsfind built on it; ~150 GB/hour MFT parse rate). pytsk3 EXPOSES the `$EFS` named alternate-data-stream as a regular ADS — extraction works via the `/path/file:$EFS` syntax pattern that ntfsdump uses for `$J`. The DDF/DRF parsing inside the `$EFS` ADS payload is then bespoke — there is NO turnkey Python lib that decodes the DDF/DRF cert-key structure. Microsoft documents the structure (Encrypted File System Wikipedia + ntfs.com $EFS Attribute reference); a custom parser at ~200-400 LOC would be needed.
- **Recommendation:** USE `pytsk3` for ADS extraction + write a custom DDF/DRF parser. This is the highest-effort candidate of the 7. License: pytsk3 is Apache 2.0 (clean). Risk: bespoke parser needs careful spec adherence.

## 7. Shim engine `.sdb` parsing

- **Library:** `python-sdb` (williballenthin/python-sdb)
- **License:** Apache 2.0 — cleanest in the set.
- **Stars:** 109. 31 commits. Pure Python 100%, no native deps.
- **Maintenance status:** Last meaningful commit appears older (Will Ballenthin's libraries are stable and rarely revised because the underlying Microsoft format hasn't changed). Format is essentially frozen; "stale" here is not a defect.
- **Output:** XML-formatted dump with INDEXES / DATABASE / STRINGTABLE sections. SHIM elements (name + DLL), EXE elements (matching files + shim refs), STRINGTABLE references. Shape directly maps to MITRE ATT&CK T1546.011 detection (look for non-Microsoft SHIM entries against EXE matchers).
- **Recommendation:** USE `python-sdb`. Tiny surface, Apache-licensed, format-stable.

---

## Summary — Lowest integration risk (top 3 of 7)

1. **#7 Shim engine `.sdb`** — `python-sdb`: Apache 2.0, pure Python, 100 LOC integration tier, format frozen. Drop-in.
2. **#5 BitLocker detection-only** — `libbde-python`: pre-built wheels on PyPI, header-only API matches verdict shape, no key handling needed.
3. **#1 Volatility 3** — actively maintained (last release 11 days ago), pip-install, all requested Windows plugins shipped. Library API documented. Largest surface but most production-proven.

Honorable mention: **#4 EVT (`libevt-python`)** is also low-risk (libyal pattern, pip wheels) but the legacy EVT format applies only to pre-Vista firmware which may be lower-priority for wairz's current Windows-coverage emphasis.

Highest risk: **#6 EFS** (no turnkey lib, bespoke DDF/DRF parser needed) and **#3 hibernate.sys** (best path is folding into Volatility, not a standalone lib — meaning #3 isn't really a separate η item, it's a sub-feature of #1).

DONE.
