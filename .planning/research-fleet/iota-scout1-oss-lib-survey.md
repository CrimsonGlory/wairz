# Phase ι Scout 1 — OSS Library Survey

**Date:** 2026-05-12
**Scout:** 1 of 3 (research-fleet pre-pass)
**Lens:** OSS Python library availability + Linux/wairz fit + integration complexity
**Time budget:** ~30 minutes wall
**Method:** WebSearch / WebFetch + local `pyproject.toml` audit + `backend/app/services/` walk

**Wairz dep-set already present (η + θ baseline):**
`regipy>=4.0,<5`, `python-evtx>=0.8`, `windowsprefetch>=4.0.3`, `libesedb-python>=20240420`,
`dissect.ntfs>=3.10`, `signify>=0.7`, `uefi-firmware>=1.11`, `lief>=0.15.0`, `pefile>=2024.8`,
`dnfile>=0.18`, `dncil>=1.0`, `flare-capa>=9.4`, `LnkParse3>=1.5`, `defusedxml>=0.7.1`,
`asn1crypto>=1.5`, `cryptography>=43`, `yara-python>=4.5`, `capstone>=5.0`, `pyelftools>=0.31`.

**Walker baseline (15 streams shipped η + θ):** `mft_walker.py`, `authenticode_*.py`,
`dbx_service.py`, `lnk_walker.py`, `registry_hive_walker.py`, `evtx_service.py`,
`prefetch_walker.py`, `srum_walker.py`, `bcd_walker.py`, `wmi_walker.py`, `esp_walker.py`,
`mbr_vbr_walker.py`, `sdb_walker.py`. Amcache emit lives inside `finding_service.py` (no dedicated walker file — Phase ζ.1).

**Dissect-family precedent in tree.** wairz already uses AGPL-3.0-licensed Fox-IT
`dissect.ntfs` (with transitive `dissect.cstruct` + `dissect.util`) — license + maintenance
+ pure-Python-no-C-extension shape are validated in production. Any sibling
`dissect.<format>` package inherits the same proven fit.

---

### 1. Volatility 3 + hibernate.sys PAIRED (memory-dump greenfield)

- **OSS lib (Vol3):** `volatility3` (https://pypi.org/project/volatility3/) — VSL (Volatility
  Software License v1.0), pure Python `py3-none-any` wheel (1.4 MB), no C extensions,
  Python >=3.8.
- **Latest release:** v2.28.0 on **2026-04-30** — actively maintained by the Volatility
  Foundation; commit cadence verified in θ scout 1 still holds two weeks later.
- **OSS lib (hibernation):** **subsumed by Volatility 3 itself.** As of recent releases, Vol3 ships
  `windows.hibernation.Info` and `windows.hibernation.Dump` plugins supporting both the
  "old" (XP→Win7) and "new" (Win8→Win11) hiberfil.sys formats including Xpress LZ77 +
  LZ77+Huffman compression on Windows 22H2. **Hibr2Bin C++/GPL-3.0 dep is NO LONGER
  NEEDED** — this is a material change from the θ analysis. Hibernation decompression
  becomes "one more Volatility plugin invocation," not a separate vendor-in.
- **ISF symbol tables — Rule #37 trust-anchor concern (HIGH).** Vol3 does NOT bundle
  Windows kernel symbol tables; by default it downloads them from Microsoft at scan time
  (https://msdl.microsoft.com via `WINDOWS_SYMBOL_URL`). This is a **direct Rule #37
  violation in the default configuration** — scan-time network fetch from a moving CDN.
  The fix: bundle `JPCERTCC/Windows-Symbol-Tables`
  (https://github.com/JPCERTCC/Windows-Symbol-Tables) ISF JSON.GZ files into
  `backend/ms-anchors/volatility3-windows-isf/` with SHA256 pins, COPY into the worker
  image at `/opt/wairz/volatility3-symbols/`, set `VOLATILITY3_SYMBOLS_PATH` env var, and
  refresh quarterly via `scripts/refresh-vol3-isf.sh`. Mirrors β.10 DBX precedent exactly.
- **Throughput / scale:** O(memory-dump-size); 4–32 GB typical; plugin invocations are
  minutes each (pslist, malfind, dlllist, hibernation.Dump). Some plugins are O(n²) in
  process count for cross-reference walks.
- **Linux/wairz fit:** pure Python — fits arq worker image directly. Vol3's input-stream
  abstraction handles `.raw`, `.dmp`, `.vmem`, `.lime`, `.hiberfil.sys` natively (post-
  hibernation-plugin landing). NO new system binary; NO Docker socket bypass; NO
  privileged ops.
- **Integration complexity:** **LARGE — architectural change confirmed from θ analysis,
  refined here.** Memory-dump is a fundamentally different data type from Firmware:
  - New `MemoryDump` ORM model (probably sibling of `Firmware`, not nested)
  - New upload + (lightweight) "unpack" router family (the equivalent of unpack for
    memory is "load symbol table + run pslist as the smoke probe")
  - New MCP tool category (`memory.py` — plugin invocation tools mirroring the existing
    `analysis.py` shape: `mem_pslist`, `mem_malfind`, `mem_dlllist`, `mem_hibernation_dump`)
  - New finding sources (`memory_malfind_injected`, `memory_hidden_process`, etc.)
  - Per Pattern P3 multi-stream decomposition: ι.A.1 MemoryDump model + upload +
    minimal router (~1 stream); ι.A.2 Volatility 3 dep + worker integration + ISF
    bundle per Rule #37 (~1 stream); ι.A.3 MCP tool category for top 5 plugins
    (~1 stream); ι.A.4 hibernation conversion as a unpack-time pre-process (~1 stream);
    ι.A.5+ findings emit + frontend page (~1-2 streams). Conservative estimate:
    **5–6 streams, multi-session campaign of its own.**
- **Rule #36 no-execute compat:** Vol3 plugins read the memory dump AS DATA — no
  process spawn, no kernel module load, no exec primitive. **Pure-data parse, fully
  compatible.** Test gate (per α.2 MSI precedent): scan unpack_log + service code paths
  for any `subprocess` invocation against extracted-binary paths.
- **License:** VSL is OSI-compatible-but-custom (https://www.volatilityfoundation.org/license/vsl-v1.0).
  Wairz is AGPL-3.0 (per the `dissect.ntfs` pyproject.toml note). VSL+AGPL compatibility
  requires a real read — VSL is more permissive than GPL but has unusual indemnification
  clauses; **needs legal sign-off before adopting** (one of the few candidates where
  licensing is genuinely a blocker, not a formality).
- **Rating:** **DEFER** (unchanged from θ).
- **One-sentence rationale:** Vol3 itself is healthier than θ Scout 1 thought (native
  hibernation support removed the Hibr2Bin/GPL complication entirely), but the
  architectural prerequisite — memory-dump as a new top-level data type sibling to
  Firmware — is still a 5–6 stream multi-session campaign of its own, and the Rule #37
  ISF bundle work is a non-trivial sub-piece even before any plugin lands.

### 2. EFS DDF/DRF (T1486-adjacent, T1564.001 stealth)

- **OSS lib:** `dissect.ntfs>=3.10` (already in tree, used by `mft_walker.py`) provides
  the access mechanism via `dissect.ntfs.c_ntfs.ATTRIBUTE_TYPE_CODE`. **Confirmed during
  this scout:** ATTRIBUTE_TYPE_CODE enumerates LOGGED_UTILITY_STREAM (0x100), and
  wairz's existing `_safe_attribute_value` helper at `mft_walker.py:236` already does
  raw attribute access via `record.attributes[ATTRIBUTE_TYPE_CODE.<NAME>]`. The exact
  same shape extends to LOGGED_UTILITY_STREAM.
- **Maintenance:** `dissect.ntfs` is **fresh** (active fox-it/NCC Group maintenance,
  versions 3.10+ in 2025–2026).
- **EFS struct parser — NO turnkey OSS:** confirmed via search — the DDF/DRF binary
  layout is Microsoft-documented but no Python library implements it. The parsing is
  wairz-side struct work over `dissect.cstruct` (transitive dep of dissect.ntfs — wairz
  already has it). DDF/DRF contains: user SID, certificate thumbprint, RSA-encrypted
  FEK, recovery-agent thumbprints. Per Rule #36, wairz surfaces ONLY metadata (who can
  decrypt, which recovery agents) — NEVER the FEK or plaintext.
- **Throughput / scale:** O(N files-with-EFS-attribute); typical Windows host <100
  encrypted files; per-record parse is microseconds (extends the MFT walker's existing
  segment iteration).
- **Linux/wairz fit:** fits arq worker — extends `mft_walker.py` with a sibling
  `_extract_efs_attribute_data` function reading attribute type 0x100, OR ships as a
  separate `efs_walker.py` consuming the MFT walker's output as input. The latter is
  cleaner: the MFT walker already iterates allocated segments; an `efs_walker.py` filters
  to those with attribute 0x100 and parses the DDF/DRF blob.
- **Integration complexity:** **MEDIUM** (refined down from θ's "medium-to-large" —
  dissect.ntfs API access was the unknown; this scout confirmed it via reading
  `mft_walker.py:256` + `mft_walker.py:266`).
  - One new walker per Rule #39 (`efs_walker.py` with `_do_efs_walk` inner +
    `run_efs_walk_background` outer + `auto_efs_walk_firmware_safe` unpack hook)
  - New `windows_efs_encrypted_file` finding source per Rule #25 single-slice
    exception #2 (DB CHECK + frontend Literal + FINDING_SOURCE_CONFIG in one commit)
  - DDF/DRF struct via `dissect.cstruct` (Rule #19 evidence-first: probe the layout
    against a real EFS-encrypted file from a test fixture before committing the
    parser — Microsoft docs are accurate but the field-ordering subtleties bite)
  - **Genuine risk: no easily-available test fixture.** Forensic EFS-encrypted test
    files are not commonly distributed; may need to manufacture one in a Windows VM
    to validate the parser, OR find one in DFIR teaching repositories
    (e.g. `digitalcorpora.org`). This is the ONE concrete blocker.
- **Rule #36 no-execute compat:** **FULLY COMPATIBLE.** DDF/DRF parser reads bytes
  as data; no RSA decrypt attempt (the FEK is encrypted with a private key we don't
  have access to); no recovery-agent invocation.
- **Rule #37 trust-anchor:** N/A — no cert roots / DBX bundle needed; the certificate
  thumbprints in DDF/DRF are surfaced AS-IS for operator correlation.
- **License:** dissect.ntfs is AGPL-3.0 (already accepted); wairz-side struct parser is
  wairz's own AGPL code. No new license complication.
- **Rating:** **HIGH** (medium-complexity Phase ι single-stream pick).
- **One-sentence rationale:** dissect.ntfs API access for attribute 0x100 is confirmed via
  existing `mft_walker.py` pattern; this is now a clean Rule #39 triplet on a confirmed
  API surface, with the only real risk being the test-fixture-availability question
  (mitigation: manufacture one in a Windows VM or vendor a forensic-teaching sample).

### 3. EVT pre-Vista event logs (T1070.001-adjacent for legacy hosts)

- **OSS lib:** `libevt-python` (https://pypi.org/project/libevt-python/) —
  LGPL-3.0-or-later, version **20240421** (released 2024-04-21).
- **Maintenance:** **stale-fresh** — Joachim Metz / libyal organization releases on an
  approximately-yearly cadence; 20240421 is the latest; previous was 2024-02-03. **NO
  2025 or 2026 release** as of this scout. This is a libyal pattern (slow but
  reliable) — `libesedb-python` follows the same shape and is in production in wairz.
  Treat as fresh-by-libyal-standards but flag the no-2025-release pattern as a
  watch-but-not-blocker signal.
- **Throughput / scale:** O(file-size); typical XP/2003 .evt files are 0.5–10 MB; parse
  in seconds. Drastically smaller than EVTX (typically 100–500 MB Security log).
- **Linux/wairz fit:** fits arq worker, **same C-extension build shape as
  libesedb-python** (already in tree at line 125 of `pyproject.toml` — Dockerfile build
  pattern proven). Python bindings (`pyevt`) work on Linux against extracted .evt files.
- **Integration complexity:** **SMALL** (unchanged from θ).
  - Single new dep (`libevt-python>=20240421`)
  - Mirrors `evtx_service.py` shape (commit c0e4979) almost exactly — same Rule #33 .a
    state machine, same Rule #39 triplet, same finding-source pattern
  - Could literally start by `cp evtx_service.py evt_service.py` and adapt
- **Rule #36 no-execute compat:** **FULLY COMPATIBLE** — pyevt reads .evt binary as
  data; no replay primitive.
- **Rule #37 trust-anchor:** N/A.
- **License:** LGPL-3.0-or-later, AGPL-compatible.
- **Persona re-evaluation for ι:** θ Scout 1 rated this MEDIUM (LOW-MEDIUM) given
  bounded XP/Server 2003 ROI. For ι, persona analysis is unchanged — the user base for
  wairz forensic-analysis is primarily on modern Windows (Vista+/EVTX) targets. **However,
  ι has a unique strength θ lacked**: the slot opens just after θ wrapped 5 streams in
  one session under the mature recipe — the EVT walker would ship in ~3-4 hours wall and
  carry near-zero risk. **If ι has slack capacity after ranking picks #1-#3, EVT is the
  guaranteed-clean shippable**: small dep, libyal pattern already in tree, walker shape
  is a near-verbatim copy of evtx_service.py.
- **Rating:** **MEDIUM** (held from θ; promoted-in-priority-ranking if ι has slack
  capacity — see Synthesis).
- **One-sentence rationale:** Lowest-risk option on the board (libyal precedent in tree
  + walker shape mirror of ε.1.b.3 evtx) but bounded by legacy-XP user-base limit;
  guaranteed-clean shippable for any ι session with surplus capacity.

### 4. ETL (Event Tracing for Windows logs)

- **OSS lib — DRAMATICALLY DIFFERENT FROM θ ANALYSIS:** `dissect.etl`
  (https://pypi.org/project/dissect.etl/, https://github.com/fox-it/dissect.etl) —
  AGPL-3.0, **pure Python, no C extensions**, Fox-IT / NCC Group.
- **Maintenance:** **fresh** — latest release v3.14 on **2025-11-20** (was v3.11 in
  March 2025); active commit cadence. **This is a complete reversal of the θ analysis,
  which concluded ETL had only the 6-year-stale `airbus-cert/etl-parser`** — that
  conclusion missed the Fox-IT dissect.etl that landed in 2024+. `dissect.etl` is a
  direct sibling of the `dissect.ntfs` already in wairz; same org, same license, same
  build shape.
- **Throughput / scale:** O(file-size); ETL files typically 10–500 MB; pure-Python
  parse is likely faster than the airbus-cert/etl-parser baseline because dissect.cstruct
  is heavily optimized.
- **Linux/wairz fit:** fits arq worker. Pure Python (99.1% per repo language
  breakdown), no native build deps, ships as part of the dissect family. WPP support
  unconfirmed from scout WebFetch (PyPI page failed to load) — would need to read the
  dissect.etl docs at `docs.dissect.tools/en/stable/projects/dissect.etl/` to verify
  scope. Treat as "covers at least the same scope as airbus-cert/etl-parser" — the
  partial-format coverage caveat may still apply, but the maintenance situation is
  fundamentally different.
- **Integration complexity:** **SMALL** (downgraded from θ's "medium").
  - Single new dep (`dissect.etl`)
  - Same dissect.ntfs precedent for build + import
  - Rule #39 walker triplet shape (mirror of `evtx_service.py`)
  - **One concrete risk:** WPP format support unconfirmed — if firmware images contain
    primarily WPP-format ETL files (relatively rare; WPP is mostly debug-trace, not
    forensic logging), partial coverage may force a "WPP unsupported, skip" emit
    rather than full parse. Mitigate via Rule #19 evidence-first probe against a
    fixture ETL file before drafting the inner walker.
- **Rule #36 no-execute compat:** **FULLY COMPATIBLE** — reads bytes as data.
- **Rule #37 trust-anchor:** N/A.
- **License:** AGPL-3.0 (matches dissect.ntfs + wairz baseline).
- **Rating:** **MEDIUM-HIGH** (PROMOTED from θ's LOW).
- **One-sentence rationale:** θ Scout 1 missed `dissect.etl` (Fox-IT, AGPL-3.0, pure
  Python, Nov 2025 release) and saw only the 6-year-stale airbus-cert/etl-parser — the
  Fox-IT package is a clean, in-family pick that drops integration complexity from
  "medium" to "small" and is now genuinely Phase-ι-shippable.

### 5. NEW adjacency pick A — WMI via `dissect.cim` (T1546.003)

- **OSS lib:** `dissect.cim` (https://pypi.org/project/dissect.cim/,
  https://github.com/fox-it/dissect.cim) — AGPL-3.0, pure Python, Fox-IT.
- **Maintenance:** active (Fox-IT dissect family release cadence). PyPI page failed to
  load during scout (intermittent error message) — needs a second verification before
  taking this as a Phase ι pick. GitHub repo confirms existence + commits.
- **What it replaces:** θ Scout 1's analysis of WMI relied on `python-cim`
  (mandiant/flare-wmi) — **archived 2024-07-06, last commit 2018-07-23**. The Fox-IT
  dissect.cim is a direct replacement, actively maintained, same license/family shape
  as the dissect.ntfs/dissect.etl already in tree.
- **Throughput / scale:** O(OBJECTS.DATA size); 30–200 MB typical; dissect-family
  parsing is fast (pure Python over cstruct).
- **Linux/wairz fit:** fits arq worker. OBJECTS.DATA + INDEX.BTR + MAPPING{1,2,3}.MAP
  are raw files extractable from any NTFS image via existing dissect.ntfs walker (η.A
  precedent). Note: **wairz already has a `wmi_walker.py` shipped in θ** — this
  candidate is "should we REPLACE the archived python-cim path with dissect.cim?", not
  "should we add WMI coverage?". Likely the existing wmi_walker.py used a different
  approach (PyWMIPersistenceFinder keyword vendor-in per θ Scout 1's recommendation),
  and the dissect.cim option opens a richer full-repository parse for follow-up work.
- **Integration complexity:** **SMALL-MEDIUM** (depends on whether ι treats this as a
  parallel walker or a refactor of θ's wmi_walker.py).
  - Single new dep
  - If parallel: new walker shape (e.g. `cim_walker.py` for full-repository parse vs
    existing wmi_walker.py for keyword-targeted persistence)
  - If refactor: cut-over commit per Rule #27 — replaces existing wmi_walker.py's
    parser with dissect.cim while keeping the same finding-source key
- **Rule #36 no-execute compat:** **FULLY COMPATIBLE**.
- **Rule #37 trust-anchor:** N/A.
- **License:** AGPL-3.0.
- **Rating:** **MEDIUM** (depends on θ's wmi_walker.py current shape).
- **One-sentence rationale:** Replaces the archived/dead `python-cim` upstream with the
  fresh Fox-IT `dissect.cim`, in the same family already in tree — either a
  parallel walker for full-repository forensic parse OR a Rule #27 refactor of θ's
  existing wmi_walker.py; needs a read of the existing walker before scoping.

### 6. NEW adjacency pick B — Linux journald binary logs

- **OSS lib:** Kaitai Struct-generated parser via `kaitaistruct` (Apache-2.0) —
  https://formats.kaitai.io/systemd_journal/python.html — pure Python, no C extensions.
  Fallback: `systemd/python-systemd` (LGPL-2.1) — requires running systemd daemon, NOT
  suitable for offline forensic parsing.
- **Maintenance:** Kaitai Struct itself is **fresh** (active Apache-2.0 project,
  formats library actively maintained); the systemd_journal Kaitai spec is community-
  contributed and updates infrequently but the format is stable. **Caveat:** the
  Kaitai-generated Python parser is "minimum viable" — covers the documented
  on-disk format but does NOT include the systemd live-API niceties.
- **Throughput / scale:** O(journal-file-size); journal files are typically 1–500 MB;
  parse should be fast.
- **Linux/wairz fit:** fits arq worker. Journal files live at `/var/log/journal/<machine-id>/*.journal`
  on extracted Linux rootfs — the unpack worker's existing rootfs walk already surfaces
  them. Note: wairz's primary customer focus is Windows-forensic per the η/θ campaign
  direction, but Linux firmware (router/IoT) is also a significant use case (existing
  `unpack_linux.py` worker shape). **This is the natural Linux-mirror to η/θ's
  Windows-event-log coverage** — EVTX on Windows, journald on Linux, EVT on legacy
  Windows. Symmetry argument.
- **Integration complexity:** **MEDIUM**.
  - One new dep (`kaitaistruct` + the generated parser module — typically committed
    in-tree as a vendor-in since the Kaitai-generated code is ~500 LOC per format)
  - Rule #39 walker triplet (e.g. `journald_walker.py`)
  - Inner walker iterates entries, surfaces fields (_BOOT_ID, _MACHINE_ID, _SYSTEMD_UNIT,
    MESSAGE, _PID, _UID, _CMDLINE, _COMM, _AUDIT_*)
  - New finding sources for high-signal events: `linux_journald_suspicious_systemd_unit`,
    `linux_journald_auth_failure`, `linux_journald_sudo_invocation`, etc.
- **Rule #36 no-execute compat:** **FULLY COMPATIBLE** — reads journal binary as data.
- **Rule #37 trust-anchor:** N/A.
- **License:** Apache-2.0 (parser library) — fully compatible.
- **Rating:** **MEDIUM-HIGH** (Linux symmetry to η/θ).
- **One-sentence rationale:** Natural Linux-mirror to the Windows event-log coverage
  ζ.1+ shipped, fits the existing unpack_linux.py rootfs walk, no license
  complications, parses on-disk format without needing a live systemd daemon (the
  fatal flaw with python-systemd) — clean Phase ι single-stream pick.

### 7. NEW adjacency pick C — macOS FSEvents (rejected, evidence below)

- **OSS lib:** `FSEventsParser` (https://github.com/dlcowen/FSEventsParser) — David
  Cowen, license unspecified (script-style, no LICENSE file visible).
- **Maintenance:** stale (last release ~2018-2020); community forks for "3SLD" format
  support (e.g. mac4n6/FSEventsParser, nicoleibrahim/FSEventsParser).
- **wairz fit consideration:** macOS firmware analysis is **out of scope for wairz**
  per the README + CLAUDE.md (no Apple platform mentioned in the architectures or
  supported firmware types). Adding macOS support is a persona shift, not an
  adjacency pick.
- **Rating:** **DEFER** (out of wairz scope).
- **One-sentence rationale:** macOS firmware/forensic analysis is a persona-shift
  campaign, not an ι single-stream pick; defer indefinitely unless wairz adopts
  Apple-platform support as a strategic direction.

---

## Synthesis — Ranked picks for Phase ι

Sweet spot: **MEDIUM-HIGH-or-better rating** AND **small-or-medium complexity** AND
**clean license** AND **wairz persona fit**.

### Top 3 picks for Phase ι (in order)

**1. ETL via `dissect.etl` (Fox-IT, AGPL-3.0, v3.14 / 2025-11-20)** — HIGH-priority,
SMALL complexity.
- **Estimated stream count:** **1 stream**, single session.
- **Estimated agent-wall time:** **3–5 hours wall** (Pattern P1 Rule-of-Five baseline:
  25–35 min × ~8 sub-tasks = ~4 hours; matches the evtx_service.py shape).
- **Sub-task ladder shape:** **Re-uses η/θ Rule #39 triplet** — copy `evtx_service.py`
  → `etl_service.py`, swap python-evtx for dissect.etl, adapt finding-source enum +
  Rule #25 single-slice cross-stack alignment commit, write the inner walker over the
  dissect.etl parse-iterator, ship.
- **Single biggest risk:** **Rule #19 evidence-first probe needed** for WPP format
  coverage — if firmware images contain primarily WPP-format ETL (relatively rare
  but possible for kernel-trace dumps), partial parse may degrade. Mitigation: run
  the inner walker against a real ETL fixture before drafting the emit path; degrade
  gracefully with "WPP unsupported, surfacing manifest+TraceLogging only" rather than
  fatal-erroring.
- **Why first:** Lowest-risk PROMOTION from θ's LOW rating once `dissect.etl` is on the
  radar; biggest delta-in-wairz-coverage (currently NO ETL parse path at all); same
  Fox-IT family already in tree (dissect.ntfs precedent validates the build shape);
  AGPL-3.0 matches wairz baseline; θ Scout 1 missed this candidate entirely and ι
  catches it as the highest-leverage closure.

**2. EFS DDF/DRF via existing `dissect.ntfs` + `dissect.cstruct`** — HIGH-priority,
MEDIUM complexity.
- **Estimated stream count:** **1 stream** (could be 2 if WMI dissect.cim refactor is
  bundled — see pick #3).
- **Estimated agent-wall time:** **5–7 hours wall** (Pattern P1: extends the mft_walker
  attribute-access shape; +2 hours for the DDF/DRF struct parser per Rule #19
  evidence-first probe against a real EFS-encrypted fixture).
- **Sub-task ladder shape:** **Re-uses η/θ Rule #39 triplet** — `efs_walker.py` as a
  sibling of `mft_walker.py`, consumes the MFT walker's segment iteration as input,
  filters to attribute 0x100, parses DDF/DRF via `dissect.cstruct`, surfaces user-SID
  + cert-thumbprint + recovery-agent metadata as Findings. Rule #25 single-slice
  cross-stack alignment commit for the new `windows_efs_encrypted_file` source.
- **Single biggest risk:** **Test-fixture availability** — forensic EFS-encrypted
  test files are not commonly distributed. Mitigation: manufacture one in a Windows
  VM (cipher /e on a small file) and check into `backend/tests/fixtures/` — or vendor
  a teaching sample from digitalcorpora.org. **NOT a Rule #36 risk** (no decryption
  attempted) and **NOT a Rule #37 risk** (no cert bundle needed).
- **Why second:** Insider-threat / T1486 ransomware-adjacent forensic signal is high-
  value; dissect.ntfs API access for attribute 0x100 is confirmed via existing
  `mft_walker.py:266` pattern; the DDF/DRF struct parser is the new work but bounded
  and Microsoft-documented; clean Phase ι single-stream pick once the fixture
  question is settled.

**3. ETL plus EFS plus a third "fast guaranteed-clean" filler** —
  recommended filler is **EVT pre-Vista via `libevt-python`** (Rule of "guaranteed
  shippable lowest-risk").
- **Estimated stream count:** **1 stream** (3–4 hours wall).
- **Sub-task ladder shape:** **Direct verbatim mirror of evtx_service.py** — `cp
  evtx_service.py evt_service.py; sed -i 's/evtx/evt/g; s/python-evtx/libevt-python/g'`
  as the starting point, then adapt the iterator API differences. Mature recipe; near-
  zero risk.
- **Single biggest risk:** **bounded coverage** — only legacy XP/Server-2003 firmware
  benefits. If ι has slack capacity after picks #1 + #2, ship this as the safety-net
  third stream; if not, defer to a future phase.

### Top 2 to DEFER

**1. Volatility 3 + memory dump as a new data type** — DEFER (unchanged from θ).
- Architectural change requiring new ORM model, new upload flow, new MCP category, new
  finding sources. 5–6 stream multi-session campaign of its own. Hibernation is now
  free via Vol3 native plugins (delta from θ scout 1), but the data-type prerequisite
  is unchanged. **Recommend: kick off as Phase μ** or its own campaign post-ι.

**2. macOS / FSEvents / Quarantine** — DEFER (out of wairz scope).
- Persona shift, not adjacency pick. Reconsider only if wairz adopts macOS firmware
  analysis as a strategic direction.

### Honorable mentions (deliberately not in top 3)

- **WMI dissect.cim refactor** (#5 above): MEDIUM-rated but depends on whether θ's
  shipped `wmi_walker.py` used PyWMIPersistenceFinder vendor-in (per θ Scout 1's
  recommendation) or some other shape. Quick read of wmi_walker.py would clarify; if
  the current walker is keyword-vendor-in, a follow-up Phase ι stream could ADD a
  full-repository dissect.cim walker as a sibling. Not in top 3 because Rule #19
  evidence-first hasn't been done on the existing walker.
- **Linux journald binary parse** (#6 above): MEDIUM-HIGH but persona-shifts from
  Windows-forensic to Linux-mirror. Strong candidate for a Phase κ kickoff after the
  Phase ι Windows-stretch closes; not first-priority for ι itself.

### Recommended Phase ι shape

**Wave 1 — two parallel streams under Rule #23 worktree discipline:**
- **Stream α:** ETL via `dissect.etl` (~4 hours wall)
- **Stream β:** EFS DDF/DRF via existing dissect.ntfs (~6 hours wall)

**Wave 2 (if capacity):** EVT pre-Vista via `libevt-python` as a guaranteed-clean
single-stream (~3 hours wall).

Worktree paths per Rule #23: `.worktrees/stream-iota-etl-2026-05-12` +
`.worktrees/stream-iota-efs-2026-05-12`. Branch names: `feat/stream-iota-etl-2026-05-12` +
`feat/stream-iota-efs-2026-05-12`. Symlink `frontend/node_modules` from main checkout
into each worktree to avoid the 2 GB npm-install penalty.

Each stream ships under the mature recipe: Rule #39 inner/outer/safe runner triplet,
Rule #33 .a 5-state machine, Rule #25 single-slice exception #2 cross-stack alignment
for the new finding source, Rule #36 no-execute test gate (per α.2 MSI precedent),
Rule #11 post-rebuild import smoke for the new ORM/imports.

---

## Sources

- https://pypi.org/project/volatility3/
- https://github.com/volatilityfoundation/volatility3
- https://github.com/JPCERTCC/Windows-Symbol-Tables
- https://blogs.jpcert.or.jp/en/2021/09/volatility3_offline.html
- https://github.com/fox-it/dissect.etl
- https://pypi.org/project/dissect.etl/
- https://docs.dissect.tools/en/stable/projects/dissect.etl/index.html
- https://github.com/fox-it/dissect.ntfs
- https://docs.dissect.tools/en/stable/api/dissect/ntfs/c_ntfs/
- https://flatcap.github.io/linux-ntfs/ntfs/attributes/logged_utility_stream.html
- http://ntfs.com/attribute-encrypted-files.htm
- https://github.com/fox-it/dissect.cim
- https://pypi.org/project/dissect.cim/
- https://github.com/libyal/libevt
- https://pypi.org/project/libevt-python/
- https://github.com/airbus-cert/etl-parser  *(superseded by dissect.etl)*
- https://github.com/m96-chan/PyETWkit  *(Windows-only, NOT applicable to wairz Linux worker)*
- https://formats.kaitai.io/systemd_journal/python.html
- https://github.com/systemd/python-systemd  *(needs live daemon, NOT applicable to offline forensic)*
- https://github.com/dlcowen/FSEventsParser  *(macOS, out of wairz scope)*
- https://www.volatilityfoundation.org/license/vsl-v1.0
- /home/dustin/code/wairz/backend/pyproject.toml  *(local audit — η + θ baseline)*
- /home/dustin/code/wairz/backend/app/services/mft_walker.py  *(confirmed dissect.ntfs ATTRIBUTE_TYPE_CODE access pattern for EFS extension)*
- /home/dustin/code/wairz/backend/app/services/  *(confirmed 14 walker services + finding_service amcache emit shipped η + θ)*
- /home/dustin/code/wairz/.planning/research-fleet/theta-scout1-oss-lib-survey.md  *(precedent)*
