# Scout 2 — Persona-E Adversary Completionist Refresh (Phase η scope)

Date: 2026-05-11
Scope: 2025-2026 threat-actor tradecraft surfacing in Windows firmware/binary/forensic artifacts that wairz currently MISSES.

---

## 1. Vulnerable-signed-driver fingerprinting (BYOVD)

- **Active in 2025-2026?** YES, peak activity. LOLDrivers catalogues 700+ vulnerable signed drivers; Microsoft's Vulnerable Driver Blocklist includes 917 signed 64-bit entries. Adopted across ALL adversary tiers (ransomware, IABs, APTs).
- **Forensic trace:** SYS files persisted on disk in `\Windows\System32\drivers\` or attacker-controlled paths; INF/CAT triplets (already extracted in α.2.6 driver-package unpacker). Hash-matchable against LOLDrivers JSON DB (SHA1/SHA256/Authentihash). Driver-load via Service registry key (Type=1 = kernel driver) cross-references with γ's hive walk.
- **Persona-E priority:** **HIGH**. wairz already extracts driver triplets (α.2.6) and walks Services/registry (γ). This gap is BYOVD-specific hash matching against the LOLDrivers offline DB — one new MS-anchor bundle (`backend/ms-anchors/loldrivers.json` per Rule #37) + a new finding source `windows_byovd_driver`. Direct extension of existing γ + α infrastructure.
- **Notable campaigns:** LockBit/BlackCat ransomware EDR-killers (2024-2025); SCATTERED SPIDER (Qilin partner); 2025 campaign that bypassed MS Vulnerable Driver Blocklist via PE-structure mutation (preserved signature, mutated hash).

## 2. WMI persistence / Subscription artifacts (T1546.003)

- **Active in 2025-2026?** YES. APT29, FIN8, Rancor catalogued; broadly used for fileless persistence. Sysmon EID 19/20/21 = primary detection.
- **Forensic trace:** WMI repository files at `\Windows\System32\wbem\Repository\OBJECTS.DATA` (+ `INDEX.BTR`, `MAPPINGn.MAP`). Stores EventFilter + EventConsumer (CommandLine/ActiveScript) + FilterToConsumerBinding triplets. Mandiant's `python-cim` library parses the CIM repository directly without WMI service.
- **Persona-E priority:** **HIGH**. Major persistence gap — wairz ζ caught Amcache/Prefetch/SRUM but WMI persistence is a different namespace entirely. Mandiant python-cim is the canonical parser; no current wairz coverage. New service `wmi_repository_walker.py` per Rule #39 (inner/outer/safe runner triplet); finding source `windows_wmi_event_subscription`.
- **Notable campaigns:** APT29 (CozyBear) backdoors; FIN8 ShadowSpider variants; commodity Qakbot/IcedID variants 2024-2025.

## 3. Boot chain artefacts (BCD store, BootKit MBR/VBR, Secure Boot policy)

- **Active in 2025-2026?** YES, escalating. CVE-2025-3052 (June 2025 Patch Tuesday) Secure Boot bypass affecting nearly every system trusting "UEFI CA 2011". Bootkitty (first Linux UEFI bootkit, 2024) + LogoFAIL chaining. BlackLotus (CVE-2023-24932) still active in air-gapped/unpatched environments.
- **Forensic trace:** BCD = registry-hive format file at `\Boot\BCD` or `\EFI\Microsoft\Boot\BCD` (parseable via `regipy` already in γ stack). MBR = first 512 bytes of disk image (signature 0x55AA + bootloader code analysis). VBR = first sector of NTFS partition (identifiable IPL bytes vs known-good signatures). EFI System Partition (ESP) = FAT32 with `.efi` PE files (parseable via existing pefile/signify).
- **Persona-E priority:** **HIGH**. wairz γ caught the SecureBoot registry value; this expands to the full boot-chain artifact set. BCD parse via `regipy` (already integrated) is cheap; MBR/VBR signature detection is a 50-LOC walker; ESP `.efi` files chain to Authenticode/DBX (β infrastructure). Three artifact types, one walker module per Rule #39.
- **Notable campaigns:** BlackLotus (Nov 2022 — still observed 2024-2025); MosaicRegressor (Kaspersky 2020 — UEFI implant); Bootkitty (Nov 2024); FinSpy UEFI (2021 — Lazarus); CosmicStrand (2022 — Chinese-attributed).

## 4. Scheduled Task XMLs (T1053.005 on-disk)

- **Active in 2025-2026?** YES. Qakbot uses encoded registry+task chain. Direct XML manipulation in `\Windows\System32\Tasks\` bypasses Task Scheduler service interfaces entirely — popular with sophisticated intrusions.
- **Forensic trace:** XML files in `\Windows\System32\Tasks\` (+ subdirectories). Triggers (LogonTrigger, BootTrigger, TimeTrigger, EventTrigger), Actions (Exec/Path with EncodedCommand patterns), Principal (RunLevel=HighestAvailable). Sister registry tree at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` (already covered by γ's hive walk).
- **Persona-E priority:** **HIGH**. ε's EVTX walker caught 4698-style runtime events; this is the static on-disk definition complement. Pure XML parse (stdlib `xml.etree`); no new dependencies. Cross-references with γ's TaskCache hive entries for completeness. Extremely high signal-to-noise (encoded PowerShell action = near-certain malware).
- **Notable campaigns:** Qakbot 2024 variants; APT29 ScheduledTask backdoors; commodity ransomware (LockBit/Conti family) using `schtasks /create /xml` with hidden temp files.

## 5. Service ImagePath persistence (T1543.003)

- **Active in 2025-2026?** YES. 134+ catalogued threat-actor groups using this technique per MITRE — the most prevalent Windows persistence sub-technique. Industroyer/CrashOverride canonical example.
- **Forensic trace:** `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath` + `ServiceDLL` + `Start` (2 = auto, 1 = boot-driver) + `ObjectName`. ALREADY in γ's registry hive walk scope — γ extracts the SYSTEM hive.
- **Persona-E priority:** **MED**. Not a NEW artifact — γ.4 registry hive walker already reads SYSTEM. Gap is whether γ surfaces the Services subtree as a discrete dataset with anomaly heuristics (auto-start ImagePath outside `%SystemRoot%`, ServiceDLL pointing to user-writable paths, recently-created services with random names). Lower priority because the data is already accessible; this is presentation/heuristics over γ's existing extraction. Could ship as a γ.X follow-up rather than a Phase η headline item.
- **Notable campaigns:** Industroyer/CrashOverride; nearly every commodity RAT (njRAT, QuasarRAT, AsyncRAT); LockBit ransomware persistence stub.

## 6. Amcache + Shimcache joint analysis (T1112 / T1564)

- **Active in 2025-2026?** YES, a CORE forensic correlation in 2024-2025 IR. Cybertriage 2026 article documents the Amcache-vs-Shimcache pivot as primary execution-evidence triangulation.
- **Forensic trace:** Shimcache = `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` (binary blob, parseable via Eric Zimmerman's AppCompatCacheParser format spec; only flushed to registry on shutdown). Amcache = ζ.1 already shipped. Joint analysis surfaces PEs in Amcache (install-history) WITHOUT corresponding Prefetch (ζ.2.B) — possible execution suppression / Prefetch-disabled environment.
- **Persona-E priority:** **HIGH**. ζ.1 + ζ.2.B already shipped means this gap is the CORRELATION layer (Amcache ∩ Shimcache ∩ ¬Prefetch = high-signal IOC). Shimcache parsing is well-documented; binary format is stable. The triangulation finding — "executed but no Prefetch trace" — is novel signal that single-artifact analysis misses. Direct ROI on existing ζ infrastructure.
- **Notable campaigns:** APT41 (uses Prefetch suppression via reg key flip); Volt Typhoon (LOLBin-heavy, leaves Shimcache+Amcache but minimal Prefetch); ransomware groups deleting Prefetch as anti-forensics.

## 7. NTFS file system artifacts ($MFT, $UsnJrnl, $LogFile, ADS)

- **Active in 2025-2026?** YES, but already a deep DFIR specialty (libfsntfs is THE library; analyzeMFT is the MS-DOS-era classic). Less an EVOLVING threat than a permanent gap.
- **Forensic trace:** $MFT (record-per-file metadata, deleted entries recoverable until overwritten), $Extend\$UsnJrnl with $J ADS (change journal — file create/delete/rename timeline), $LogFile (transaction log — operation rollback evidence), arbitrary `$DATA:streamname` ADS (T1564.004 hidden content).
- **Persona-E priority:** **MED**. Big surface (4 sub-artifacts), big payoff, but expensive to ship and overlaps with general filesystem-forensics commercial tools (Autopsy, X-Ways). libfsntfs is in the worker per ε.2 (EVTX) — pyfsntfs Python bindings also available. Recommend SCOPING DOWN to just $MFT walk + ADS enumeration first; defer $UsnJrnl + $LogFile to η+1.
- **Notable campaigns:** APT29 ADS-hidden Cobalt Strike beacons (2024); ransomware $UsnJrnl wipes (LockBit, Conti); APT41 timestomping detectable via $MFT vs $UsnJrnl divergence.

## 8. Memory-resident malware indicators (no memory dump)

- **Active in 2025-2026?** Partially. The artifacts (pagefile.sys, hiberfil.sys, swapfile.sys) are well-known but tooling is fragmented. YARA-over-pagefile is the main 2024-2025 technique.
- **Forensic trace:** `pagefile.sys` (4KB-aligned page-sized chunks, non-sequential — strings + YARA scans only practical), `hiberfil.sys` (compressed RAM snapshot via Volatility Hibr2bin), `swapfile.sys` (Modern App suspended state). Unallocated NTFS clusters (depends on filesystem walk = item #7).
- **Persona-E priority:** **LOW** for Phase η. Compelling but expensive — strings-over-pagefile is naive without memory-forensic context (no process/handle/VAD attribution); proper analysis demands Volatility integration which is a separate MAJOR effort. Defer.
- **Notable campaigns:** Cobalt Strike beacon strings in pagefile (default-config detection); PoshC2 PowerShell snippets in unallocated; Mimikatz LSASS-dump remnants in hiberfil.

---

## SUMMARY — Top 3 highest persona-E priorities for Phase η

1. **Gap #2 — WMI persistence (OBJECTS.DATA walker)** — biggest persistence-gap blind spot vs ζ. APT29/FIN8/Qakbot all use it. Mandiant python-cim is canonical. New service per Rule #39; finding source `windows_wmi_event_subscription`. **One walker = one major adversary tradecraft surface closed.**

2. **Gap #3 — Boot chain artefacts (BCD + MBR/VBR + ESP .efi)** — leverages existing β (Authenticode/DBX) + γ (regipy hives) + α (PE parsers). CVE-2025-3052 currency makes this timely. BlackLotus/Bootkitty/CosmicStrand all leave on-disk traces wairz currently misses. **Maximum reuse of existing infrastructure for high-signal output.**

3. **Gap #1 — BYOVD LOLDrivers fingerprinting** — extends α.2.6 driver-package unpacker + γ Services walk with a hash-match against an offline LOLDrivers bundle (per Rule #37 anchor discipline). EDR-killer detection is the hottest 2025 ransomware pre-stage. **Directly applies wairz's 2 strongest existing patterns (no-execute + offline-trust-anchor).**

Honorable mention: **Gap #6 (Amcache+Shimcache joint analysis)** is genuinely high-signal but is a correlation/heuristics layer over already-shipped data — can be a γ.X follow-up rather than a Phase η headline. Gap #4 (Scheduled Task XMLs) is also high-priority but smaller in scope; could ride along with η as a sub-phase.

Sources:
- [MITRE ATT&CK T1546.003 WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE ATT&CK T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [LOLDrivers Project (MagicSword)](https://www.magicsword.io/blog/loldrivers-malicious-drivers)
- [BYOVD NDSS 2026 Paper](https://www.ndss-symposium.org/wp-content/uploads/2026-s1491-paper.pdf)
- [Bitdefender BYOVD TechZone](https://techzone.bitdefender.com/en/tech-explainers/what-is-bring-your-own-vulnerable-driver--byovd-.html)
- [Cybertriage 2026 Shimcache+Amcache](https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/)
- [Eclypsium Bootkitty/Linux Bootkits](https://eclypsium.com/blog/bootkitty-linux-bootkit/)
- [Eclypsium Bootloaders/Bootkits/SecureBoot](https://eclypsium.com/blog/threat-detection-bootloaders-bootkits-secureboot/)
- [Bleeping Computer CVE-2025-3052 Secure Boot](https://www.bleepingcomputer.com/news/security/new-secure-boot-flaw-lets-attackers-install-bootkit-malware-patch-now/)
- [NTFS forensics wiki](https://forensics.wiki/new_technology_file_system_(ntfs)/)
- [pagefile.sys forensics wiki](https://forensics.wiki/pagefile.sys/)

DONE.
