# Scout 3 — Competitive RE-Platform Gap Analysis (Phase η scope)

Date: 2026-05-11. Author: Scout 3 (research-fleet, parent campaign `windows-coverage-godmode`). Wairz baseline: Phases α-ζ shipped; 226 MCP tools across 21 categories; Windows tool surface lives at `backend/app/ai/tools/windows_*.py` (10 modules covering archive, dotnet, driver, event_log, pe_signature, prefetch, registry, srum, storage, update). Models at `backend/app/models/windows_*.py` (driver, update_package, pe_signature, registry_extract, srum_record, prefetch_record, update_dll_diff, event_record).

## Per-platform competitive scan

**FACT_core (fkie-cad).** Plugin-driven (`src/plugins/analysis/`); 100+ analyzers but **Linux-firmware-centric**. Strong overlap with wairz on `cwe_checker`, `software_components`, `binwalk`, YARA, `crypto_material`, exploit-mitigation. Windows-specific surface is THIN: `pe_file` magic + section parse, no Authenticode chain, no DBX, no RICH, no WHQL, no ARM64EC. **Wairz is AHEAD on Windows-specific PE analysis** (β.4-β.13 + γ Authenticode/DBX/RICH/ARM64EC + WHQL classification). FACT advantages wairz lacks: comparison UI for cross-firmware diff is more polished; YARA-rule corpus (`signature` plugin) larger; QEMU-based init detection (S121) not mirrored by wairz. Not a Windows-RE threat to wairz.

**EMBA (e-m-b-a/emba).** Bash-driven, Linux-focused. S09 binary version detection / S12 checksec / S120 cwe-checker — wairz has equivalents (`security_audit`, `cwe_checker_service`). Windows binary support is incidental ("scripts, APKs, Windows binaries also processed") with no dedicated PE/Authenticode/registry path. Not a Windows-RE competitor.

**Binwalk Pro / refirm-labs.** Commercial; public feature list emphasizes binary similarity/hash matching, CVE correlation, SBOM. Wairz's `grype_service` + `cve_*` tools + `sbom/` strategy modules cover this. Their Windows angle = generic PE — not differentiated.

**Detective / IntelliEval.** Both effectively dormant in 2025-2026 OSS; no recent commits worth tracking.

**Eclypsium + Binarly REsearch.** Closed-source platforms; relevant for "table-stakes" benchmarking. Eclypsium 4.2 (2026): Automata AI binary analysis, Asset Profile Verification, network-edge-device focus, GenAI-stack integrity. Binarly: firmware supply-chain memory-corruption hunting, BMC/UEFI-heavy. Both prioritize: (a) signature-chain integrity, (b) revoked-cert/DBX matching, (c) component-version → CVE rollup, (d) cross-device deviation-from-baseline. Wairz covers a/b/c via β.4-β.10; (d) baseline-deviation is NOT shipped.

**Velociraptor (Rapid7).** Endpoint live-collection. `Windows.Forensics.Usn` (USN journal carving), `Windows.NTFS.MFT`, `Windows.Forensics.Lnk`, `Windows.Forensics.PSReadline`, `Windows.Forensics.Prefetch`, `Windows.Forensics.SAM`, `Windows.Registry.NTUser`, JumpLists, RecycleBin all shipped as artifact YAML. Wairz's static-extraction equivalent covers Prefetch+SRUM+Amcache+Registry+EVTX; **GAPS = MFT, USN, LNK, JumpList, RecycleBin, browser, scheduled-tasks, WMI, PowerShell-event-IDs**.

**KAPE (Kroll/EricZimmerman).** The de facto target inventory. `KapeFiles` repo defines targets via `.tkape` files; `!SANS_triage` + `KapeTriage` compounds set the table-stakes baseline: $MFT / $LogFile / $UsnJrnl / Registry hives / Event Logs / Prefetch / Amcache / Tasks / RecycleBin / LNK / JumpLists / Browsers / WMI repository / PowerShell logs / SRUM / Shimcache. Wairz currently covers ~60% of the KapeTriage compound by artifact category.

**Plaso / Log2Timeline.** Parser inventory (per `Parsers-and-plugins.md`): `lnk`, `prefetch`, `winreg`, `winjob` (Tasks .job/.xml), `usnjrnl`, `webhist` (browser), `olecf` (incl. JumpList CustomDestinations), `pe`, `winfirewall`, `setupapi`, plus `automatic_destinations` registry plugin. Wairz lacks: lnk, winjob, usnjrnl, webhist, olecf-JumpList, automatic_destinations.

## Per-gap evaluation (1-9)

**1. WMI repository (OBJECTS.DATA).** KAPE collects via `WMI.tkape`; Plaso has no first-class parser but the OSS `python-cim` (David Cowen / Mandiant) library is the standard. Persistence-relevant (WMI event consumers = stealthy persistence; FIN7/APT33 favored). Table-stakes? **YES (forensic)** but **NICHE for firmware-RE platform** — most firmware images ship pristine WMI. **Effort: M** (~250 LOC walker + finding emitter + tier-1 tests; `python-cim` is mature). **Persona-D priority: MED** — high differentiation vs FACT/EMBA, low-frequency value vs MFT/LNK.

**2. NTFS $MFT / $UsnJrnl / $LogFile parsing.** Plaso `usnjrnl` parser, Velociraptor first-class, KAPE !SANS_triage core. **TABLE STAKES — non-negotiable** for any 2025-2026 windows-forensic platform. OSS libraries: `analyzeMFT` (David Kovar, mature), `dissect.ntfs` (Fox-IT, modern + actively maintained, MIT). Wairz already extracts NTFS volumes via `unpack_vhdx` → raw image → NTFS walk is LOW additional cost since the disk image is in-tree. **Effort: L** (3 walkers — MFT/USN/LogFile — but `dissect.ntfs` collapses much of it; ~600-900 LOC across walker + 3 ORM tables + finding emit; reuses inner/outer/safe Rule #39 triplet). **Persona-D priority: HIGH** — without MFT, wairz cannot claim parity with Velociraptor/KAPE/Plaso for offline forensic triage. The VHDX → NTFS pipeline (β.7) makes this the natural next phase.

**3. Recycle Bin (`$Recycle.Bin\$I*` + `$R*`).** KAPE collects; small, well-defined format; Plaso `recycle_bin` parser. Deleted-file forensics + user-attribution per SID. **Table-stakes for forensic, OPTIONAL for firmware-RE** (most firmware images empty here). **Effort: S** (~150 LOC; format is tiny — `$I*` = 544 bytes fixed). **Persona-D priority: LOW** — easy win but rare in firmware-context use cases.

**4. LNK file parsing.** KAPE+Plaso both. CLAUDE.md mentions `LnkParse3` aspirationally but **`grep -rln "lnk\|LnkParse" backend/app/` returned ZERO matches** — NOT integrated. Living-off-the-land detection (LNK as initial-access dropper, e.g. Qakbot/IcedID); MAC times, target-path, working-dir. **Table-stakes — YES.** **Effort: S** (`LnkParse3` PyPI package, ~200 LOC walker + findings + tests). **Persona-D priority: HIGH** — small effort, strong KAPE/Plaso parity signal, supports the "tampered installer carries LNK with abnormal target" finding shape that Persona-D cares about.

**5. Jump List parsing (AutomaticDestinations + CustomDestinations).** OLECF wrapper holding embedded LNK streams. Plaso `olecf_automatic_destinations` plugin. Evidence-of-execution + per-app history. **Table-stakes for forensic, MARGINAL for firmware-RE.** **Effort: M** (~300 LOC; OLECF parsing via `olefile` + LNK parsing via the same lib chosen for #4). **Persona-D priority: LOW-MED** — pairs naturally with #4 once that lib is in-tree; standalone weak.

**6. Browser artifact extraction (Chrome/Edge/Firefox).** SQLite history/cookies/downloads, IE/Edge `WebCacheV01.dat` (ESE). Plaso has `webhist` parser family. Massive surface; wairz can lean on existing `python-evtx`-style ecosystem (Chromium = SQLite, FF = SQLite, IE/Edge legacy = `dissect.esedb` / `python-libesedb`). **Table-stakes for forensic, LOW for firmware-RE** — most firmware images don't have browsers. Exception: enterprise-laptop full-disk images. **Effort: L** (3-4 walkers + ESE parser dep). **Persona-D priority: LOW** — wrong fit for a firmware-RE platform's persona-D positioning.

**7. PowerShell event IDs (4103/4104/4105/4106).** ε already shipped EVTX walker (`evtx_service.py`) and emits persistence findings. **Specific check needed — does ε tag these IDs?** Mechanical scan of `evtx_service.py` for "4104" / "4103" / "ScriptBlock" would settle it; if absent, this is a pure annotation expansion (not a new walker). **Table-stakes — YES for IR/forensic; partially shipped.** **Effort: S** (~50-100 LOC if just adding event-ID-aware finding emit to existing walker; ~250 LOC if adding script-block reassembly across multi-part 4104 events). **Persona-D priority: HIGH** — leverages existing infra, closes a known IR detection gap, completes ε's promised coverage.

**8. Scheduled Task XML parsing (`\Windows\System32\Tasks\`).** XML tasks (Vista+); also legacy binary `.job` files. OSS: `gajos112/Windows-Scheduled-Task-Parser` (XML), `yahoo/winjob` (both formats). Plaso has `winjob` parser. **Table-stakes — YES**; persistence mechanism #1 in 2024-2025 ransomware playbooks (per CrowdStrike/Mandiant reports). **Effort: S-M** (~200 LOC; XML is well-structured; finding shape mirrors registry persistence emit at γ.7). **Persona-D priority: HIGH** — strongest persistence-detection ROI of the 9, fits Rule #39 triplet shape, low-effort/high-value/clean-fit.

**9. Volatility 3 web GUI parity.** Volatility's web GUI offers: tabular plugin output, process-tree visualization, timeline, hex viewer, dump-to-disk-and-re-analyze. Wairz already has Monaco + xterm + ReactFlow; comparable surface area exists. **Not a backend-coverage gap; it's a UX inspiration.** **Effort: VARIABLE** depending on which UX patterns adopted. **Persona-D priority: LOW-DEFER** — UX polish, not coverage; should follow #2/#4/#7/#8 not precede them.

## Wairz coverage NOT under-estimated

For the record: wairz has features many of these platforms LACK — **Authenticode chain validation with real CRL/DBX traversal** (Eclypsium and Binarly do this; FACT/EMBA/Plaso don't), **WHQL signature classification** (commercial-only elsewhere), **ARM64EC/X arch detection** (very recent; almost no OSS coverage), **R2R-stomping detection** (Windows-defender-proprietary in commercial scanners), **Update-DLL-diff** (Binarly does this; nothing OSS), **DBX EFI revocation matching** (Eclypsium yes; OSS no). On **firmware** specifically, wairz outclasses every OSS competitor on Windows installer/package coverage (CAB/MSI/MSIX/MSU/PSF/VHDX) — KAPE doesn't unpack, Plaso doesn't unpack, FACT/EMBA stop at Linux. The gaps below are forensic-artifact gaps, not firmware-analysis gaps.

## Final summary — top 3 for Phase η inclusion

**Recommend in priority order:**

1. **#2 NTFS $MFT / $UsnJrnl / $LogFile (HIGH).** Closes the largest single competitive gap; natural follow-on to β.7 VHDX work (the disk image is already in-tree); enables KAPE/Plaso/Velociraptor parity on offline-triage. `dissect.ntfs` is mature MIT-licensed Python. Largest effort of the three but largest payoff.

2. **#8 Scheduled Tasks XML (HIGH).** Highest ROI per LOC of the 9 candidates. Persistence-detection finding emit is the exact shape γ.7 already ships for registry persistence — Rule #25 single-slice cross-stack alignment commit (DB CHECK + frontend mirror + new walker). Low effort, high IR-relevance.

3. **#4 LNK files (HIGH).** Smallest effort; closes a CLAUDE.md-acknowledged gap (`LnkParse3` was named but never integrated); pairs well with future #5 JumpList work (shared lib). Establishes the LNK-parser dependency that #5 reuses. Strong KAPE/Plaso parity signal.

Honourable mention: **#7 PowerShell event-ID expansion** — depends on whether ε's existing EVTX walker already tags 4103/4104; if not, this is a pure annotation extension, possibly the cheapest win on the list. Run a 1-second grep to settle scope (Rule #19 evidence-first) before sizing.

Defer: #1 WMI (niche for firmware-RE), #3 RecycleBin (low firmware value), #5 JumpList (do AFTER #4), #6 Browser (wrong persona fit), #9 Volatility-UX (not a coverage issue).

Sources:
- [FACT_core repository](https://github.com/fkie-cad/FACT_core)
- [FACT analysis plugins directory](https://github.com/fkie-cad/FACT_core/tree/master/src/plugins/analysis)
- [EMBA repository](https://github.com/e-m-b-a/emba)
- [EMBA feature overview wiki](https://github.com/e-m-b-a/emba/wiki/Feature-overview/13cd33f277f1f5dcc515c947882c5b7d679c3b27)
- [KAPE official page](https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape)
- [KapeFiles community targets/modules](https://github.com/EricZimmerman/KapeFiles)
- [Plaso parsers and plugins documentation](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html)
- [Plaso repository](https://github.com/log2timeline/plaso)
- [Velociraptor USN artifact](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Carving/USN.yaml)
- [Velociraptor USN journal blog](https://docs.velociraptor.app/blog/2020/2020-11-13-the-windows-usn-journal-f0c55c9010e/)
- [Eclypsium 4.2 release](https://eclypsium.com/press-release/eclypsium-release-expanding-network-edge-threat-detection-and-security/)
- [Binarly platform](https://www.binarly.io/)
- [Windows-Scheduled-Task-Parser (gajos112)](https://github.com/gajos112/Windows-Scheduled-Task-Parser)
- [winjob parser (yahoo)](https://github.com/yahoo/winjob)
- [PowerShell event ID 4103/4104 detection guide](https://www.redsecuretech.co.uk/blog/post/event-id-4104-4103-catch-malicious-powershell-scripts/942)
- [Windows Event Log Analysis 2025 cheat sheet](https://thehgtech.com/guides/windows-event-log-analysis.html)

DONE.
