# Phase θ — Scout 2: Persona-E Adversary Refresh

**Lens:** Persona-E is a fictional advanced-tier offensive adversary representing nation-state + ransomware-affiliate threats. Rank the 8 deferred-to-θ candidates by **adversary-coverage-value** — which artifact, when surfaced by wairz, catches the most diverse + most recent threat activity, weighted by detection-rarity in commercial EDR.

**Scope reminder:** wairz is a Linux-hosted *offline firmware* analysis platform. Candidates are evaluated for what they surface in a *static disk image* extracted from firmware/embedded systems — not live EDR telemetry. The Persona-E coverage value reflects *the artifact's role in adversary persistence/operations*; the rarity dimension reflects *where commercial EDR is structurally blind* (most EDR is live-telemetry-first, weak on offline-disk-from-image triage).

---

### 1. WMI persistence — `__EventFilter`/`__EventConsumer`
- **Primary MITRE ATT&CK technique(s)**: T1546.003 (Windows Management Instrumentation Event Subscription)
- **Notable threat actors / families**: APT29 (Cozy Bear), APT32 (OceanLotus), Turla, FIN7 (Carbanak), Cobalt Strike's WMIPersist module — also widely used by commodity malware including ransomware affiliates
- **Recent incident references**: APT32 multi-year intrusion against Vietnamese human-rights org disclosed August 2024 used scheduled-task + registry persistence alongside WMI patterns; Cyber Triage's 2025 published methodology specifically targets WMI event-consumer triage as a recurring incident-response surface ([Cyber Triage 2025](https://www.cybertriage.com/blog/how-to-investigate-malware-wmi-event-consumers-2025/)); Splunk Security Content keeps active 2025 detections (Sysmon EIDs 19/20/21) confirming the technique remains current
- **Detection rarity in current commercial EDR**: **uncommon** in offline-image triage (most EDR catches it live via Sysmon EID 19/20/21, but offline disk extraction of `OBJECTS.DATA` from `C:\Windows\System32\wbem\Repository\` is not standard EDR output)
- **Adversary-coverage value**: **HIGH**
- **One-sentence rationale**: Persists across nearly every nation-state actor catalogue AND most ransomware playbooks; the WMI repository is a binary blob that survives in firmware images and is rarely parsed offline by commercial tooling.

### 2. Boot chain artefacts — BCD store + MBR/VBR + ESP `.efi` PE chain
- **Primary MITRE ATT&CK technique(s)**: T1542.003 (Bootkit), T1542.001 (System Firmware), T1547.001 (Boot or Logon Autostart - Registry Run Keys variant via BCD)
- **Notable threat actors / families**: BlackLotus, Bootkitty (Linux UEFI, Nov 2024), CosmicStrand, MoonBounce, ESPecter, FinSpy UEFI, LoJax, MosaicRegressor
- **Recent incident references**: Bootkitty disclosed November 2024 (ESET) as the first UEFI bootkit targeting Linux ([ESET](https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/)); Microsoft published a Secure Boot bypass update July 8, 2025 for the BlackLotus-leveraged path (CVE-2023-24932); Binarly's FwHunt scanner ecosystem actively maintained through 2024-2025 for ESP `.efi` triage ([Binarly](https://www.binarly.io/blog/uefi-bootkit-hunting-in-depth-search-for-unique-code-behavior))
- **Detection rarity in current commercial EDR**: **rare** — most commercial EDR runs *after* Windows boots; bootkits operate before EDR is loaded; ESP forensic triage at the offline-image level is a documented blind spot
- **Adversary-coverage value**: **HIGH**
- **One-sentence rationale**: Catches the top tier of nation-state firmware implants (CosmicStrand, MoonBounce) plus growing ransomware/wiper bootkit class; wairz is uniquely positioned because it already handles firmware unpacking and would extend cleanly to ESP `.efi` chain parsing.

### 3. Volatility 3 integration — broad memory-dump triage
- **Primary MITRE ATT&CK technique(s)**: T1055 (Process Injection — all sub-techniques), T1620 (Reflective Code Loading), T1140 (Deobfuscate/Decode Files), T1027.002 (Software Packing)
- **Notable threat actors / families**: Conti/LockBit (in-memory decryptor staging), Cobalt Strike beacon (memory-only by default), APT29 WINELOADER second-stage, fileless commodity malware broadly
- **Recent incident references**: Hybrid Behavioural-Forensic Detection Model paper (2025) reports 90% detection on fileless attacks combining Volatility 3 + Sysmon + ETW vs. 30% disk-only ([MDPI 2025](https://www.mdpi.com/2073-431X/14/11/467)); XGBoost on 900 memory dumps achieved 89% ransomware detection accuracy ([memory forensics ML survey 2025](https://dl.acm.org/doi/10.1145/3764580))
- **Detection rarity in current commercial EDR**: **uncommon** — most EDR has *live* memory introspection but few platforms productionise offline `.dmp`/`.raw`/`hiberfil.sys`/`pagefile.sys` triage; firmware-captured snapshots are even rarer
- **Adversary-coverage value**: **HIGH**
- **One-sentence rationale**: Memory is *the* layer where fileless adversaries live; integrating Vol3 unlocks a research multiplier across every other Windows artefact wairz surfaces (LNK, Prefetch, MFT all become richer with paired memory context).

### 4. Shim `.sdb` — Application Shim persistence
- **Primary MITRE ATT&CK technique(s)**: T1546.011 (Event Triggered Execution: Application Shimming)
- **Notable threat actors / families**: FIN7 (Carbanak) — documented heavy user; APT41; sLoad downloader; TA505 (SDBbot RAT); historical Equation Group
- **Recent incident references**: Sigma detection rules updated through October 2025 indicating active research interest ([SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml)); MITRE T1546.011 page references CISA Eviction Strategies tool active in 2024-2025
- **Detection rarity in current commercial EDR**: **uncommon-to-rare** — `sdbinst.exe` invocations are caught live, but custom `.sdb` files dropped into `%WINDIR%\AppPatch\Custom\` are rarely parsed offline; the binary `.sdb` format itself is underdocumented in mainstream EDR
- **Adversary-coverage value**: **MEDIUM**
- **One-sentence rationale**: Niche but persistent across a recognisable APT/financial-crime cohort; structurally invisible to most disk-image triage because `.sdb` parsing requires a specific Microsoft-format parser most platforms don't ship.

### 5. EFS DDF/DRF — Encrypted File System adversary use
- **Primary MITRE ATT&CK technique(s)**: T1486 (Data Encrypted for Impact — when used by ransomware), T1564.001 (Hide Artifacts: Hidden Files and Directories — insider variants), T1027 (Obfuscated Files)
- **Notable threat actors / families**: SafeBreach Labs PoC ransomware family ("EFS ransomware" research class); no widespread in-the-wild attribution observed; insider-threat case-law references
- **Recent incident references**: BleepingComputer/SafeBreach 2020 PoC remains the primary reference; 2025 Akamai/Dragos ransomware reports do not list EFS-abuse as a top-N family TTP ([Akamai 2025 ransomware trends](https://www.akamai.com/site/en/documents/state-of-the-internet/2025/ransomware-trends-2025.pdf))
- **Detection rarity in current commercial EDR**: **rare** — EFS metadata parsing from offline NTFS is a specialist forensic skill; little commercial tooling triages DDF/DRF certificates offline
- **Adversary-coverage value**: **LOW-to-MEDIUM**
- **One-sentence rationale**: High signal *when* present, but real-world adversary uptake has stayed primarily theoretical/PoC; coverage payoff is narrower than other candidates despite the EDR gap.

### 6. EVT (pre-Vista) — Legacy Windows XP/Server 2003 event logs
- **Primary MITRE ATT&CK technique(s)**: T1070.001 (Indicator Removal: Clear Windows Event Logs), T1562.002 (Disable Windows Event Logging) — same techniques as modern EVTX, on legacy format
- **Notable threat actors / families**: Threats targeting legacy ICS/medical IoT (TRITON, INDUSTROYER variants) often touch XP-era subsystems; ransomware affiliates targeting hospital legacy gear (medical-device manufacturers shipped XP Embedded through 2016 EOL)
- **Recent incident references**: 2025 Dragos Q1 industrial ransomware report (708 incidents) confirms legacy-OS exposure in OT environments; Windows XP Embedded had EOL December 2016 but still ships in fielded medical/ATM devices ([Windows XP Embedded license reference](https://www.elbacom.com/embedded-iot-operating-systems))
- **Detection rarity in current commercial EDR**: **rare** — modern EDR doesn't parse legacy `.evt` format; Windows 10 Event Viewer itself fails on legacy `.evt` files
- **Adversary-coverage value**: **LOW-to-MEDIUM** (HIGH only for wairz's medical/industrial firmware niche)
- **One-sentence rationale**: Unique to wairz's embedded-firmware niche — most modern adversaries don't target XP-era, but the firmware wairz analyses for medical/industrial IoT often runs XP Embedded, making this a niche-but-uncontested gap.

### 7. ETL — Event Tracing for Windows logs
- **Primary MITRE ATT&CK technique(s)**: T1070 (Indicator Removal — adversaries delete ETL traces to cover tracks), T1562.006 (Indicator Blocking — disable ETW providers), T1218 (Living-off-the-land via legitimate ETW consumers)
- **Notable threat actors / families**: Ransomware groups using anti-forensic ETL deletion (documented FortiGuard case 2024); APT actors with ETW bypass capability (Binarly research class); red-team via SilkETW
- **Recent incident references**: FortiGuard Labs disclosed AutoLogger-Diagtrack-Listener.etl as a *surviving* forensic artefact even after adversary cleanup attempts ([FortiGuard 2024-2025](https://www.fortinet.com/blog/threat-research/uncovering-hidden-forensic-evidence-in-windows-mystery-of-autologger)); JPCERT/CC published "ETW Forensics" guidance November 2024 ([JPCERT 2024](https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html)); ElcomSoft published Feb 2026 Windows 10/11 event log forensic analysis ([ElcomSoft 2026](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/))
- **Detection rarity in current commercial EDR**: **rare** — `.etl` parsing is specialist; most commercial EDR consumes ETW *streams* live but does not triage offline `.etl` files from disk images; ETL is structurally a 2024-2025 *discovered-blind-spot* artefact
- **Adversary-coverage value**: **HIGH**
- **One-sentence rationale**: ETL has surfaced as the "surviving telemetry" that catches adversaries *after* they thought they cleaned up — a high-yield, recently-validated coverage gap that aligns directly with anti-forensics-aware nation-state and ransomware TTPs.

### 8. hibernate.sys — Hibernation file memory snapshot
- **Primary MITRE ATT&CK technique(s)**: T1003 (OS Credential Dumping — recovered from snapshotted LSASS), T1555 (Credentials from Password Stores — keys/tokens at hibernate time), T1055 (Process Injection — recoverable from past memory state)
- **Notable threat actors / families**: Indirect coverage — any adversary present at hibernate time leaves trace; particularly valuable against in-memory-only malware (Cobalt Strike beacons, fileless ransomware loaders)
- **Recent incident references**: Magnet Forensics 2024+ hiberfil.sys forensics blog ([Magnet](https://www.magnetforensics.com/blog/when-windows-takes-a-nap-and-leaves-you-evidence-inside-hiberfil-sys/)); arxiv UEFI memory forensics framework Jan 2025 ([arXiv 2501.16962](https://arxiv.org/html/2501.16962v1)); ongoing challenge that Windows 10/11 changed compression algorithms breaking older tools
- **Detection rarity in current commercial EDR**: **rare** — `hiberfil.sys` triage requires decompression to a memory image then Volatility-class analysis; very few commercial EDR platforms do this end-to-end on offline images
- **Adversary-coverage value**: **MEDIUM-to-HIGH**
- **One-sentence rationale**: Direct multiplier for Volatility 3 (candidate #3) — without hiberfil.sys parsing, wairz can't reach the memory state of a powered-off firmware capture; with it, every memory-resident adversary becomes detectable post-hoc.

---

## Synthesis — Top 3 by Adversary-Coverage × Detection-Rarity

The scoring axis is **(adversary breadth × recency-of-relevance) × (commercial-EDR coverage gap for offline-image triage)**. wairz's structural advantage is *offline static firmware analysis* — so artefacts that are well-covered by live EDR but invisible offline still score highly.

### Rank 1: **WMI persistence** (candidate #1) — HIGH × uncommon
Catches the broadest cross-section of named adversaries (APT29, APT32, Turla, FIN7, ransomware affiliates) AND remains current in 2025 detection content. wairz can parse the WMI repository (`OBJECTS.DATA`) from extracted firmware/disk images statically — no live-EDR equivalent needed. Lowest implementation risk (binary CIM format is documented; existing FOSS parsers like `python-cim` exist). Highest **breadth-per-engineering-hour** of the eight candidates.

### Rank 2: **ETL Event Tracing logs** (candidate #7) — HIGH × rare
The 2024-2025 surprise: FortiGuard, JPCERT/CC, and ElcomSoft all independently surfaced ETL files as *surviving anti-forensic cleanup* — meaning adversaries who clear Security/System EVTX logs frequently miss the `.etl` traces. This is a textbook **structural-blind-spot** artefact: present in every modern Windows firmware image, rarely triaged offline, and directly catches the anti-forensics-aware tier of Persona-E (ransomware + APT). Pairs perfectly with the existing η-phase EVTX work.

### Rank 3: **Boot chain artefacts (BCD + ESP `.efi` PE chain)** (candidate #2) — HIGH × rare
Captures the *highest-tier* nation-state implants (CosmicStrand, MoonBounce, BlackLotus, Bootkitty 2024) — implants that fundamentally bypass post-boot EDR by running *before* the OS. wairz is uniquely positioned because it already handles firmware extraction; the marginal cost of parsing ESP contents + BCD store is low relative to the unique coverage gain. The lower runner-up vs ETL is that adversary *prevalence* is narrower (top-tier APT only; ransomware crews rarely deploy bootkits), but the *severity-per-find* is exceptional. Strongly synergistic with the Phase η BYOVD-LOLDrivers work (both target pre-EDR persistence).

**Honourable mentions:**
- **Volatility 3 + hibernate.sys (candidates #3 + #8 together)** would rank above #2 and #3 if treated as a paired investment — memory forensics is a massive multiplier — but the engineering scope is materially larger than the other six candidates combined, so they're better as a Phase-ι standalone campaign.
- **Shim `.sdb`** (#4) ranks fourth — solid niche coverage of FIN7/TA505/APT41, but the adversary cohort is narrower than WMI's.

**De-prioritise:**
- **EFS DDF/DRF** (#5) — the threat hasn't materialised at scale; SafeBreach PoC is still the headline reference five years later.
- **EVT (pre-Vista)** (#6) — only relevant to wairz's medical/ICS legacy-firmware niche; not a portfolio-wide win.

---

## Sources

- [MITRE ATT&CK T1546.003 (WMI Event Subscription)](https://attack.mitre.org/techniques/T1546/003/)
- [Cyber Triage WMI Event Consumer Investigation 2025](https://www.cybertriage.com/blog/how-to-investigate-malware-wmi-event-consumers-2025/)
- [Splunk Security Content WMI Persistence Detection](https://research.splunk.com/endpoint/01d9a0c2-cece-11eb-ab46-acde48001122/)
- [MITRE ATT&CK Group G0050 (APT32/OceanLotus)](https://attack.mitre.org/groups/G0050/)
- [MITRE ATT&CK Group G0016 (APT29)](https://attack.mitre.org/groups/G0016/)
- [APT32 2025 NGO Targeting (Brandefense)](https://brandefense.io/blog/apt32-targeting-ngos-2025/)
- [ESET Bootkitty Analysis (Nov 2024)](https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/)
- [Microsoft CVE-2023-24932 Secure Boot Bypass Guidance (July 2025)](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Binarly UEFI Bootkit Hunting](https://www.binarly.io/blog/uefi-bootkit-hunting-in-depth-search-for-unique-code-behavior)
- [Securelist CosmicStrand UEFI Rootkit](https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/)
- [Securelist MoonBounce](https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/)
- [Rapid7 Hunting UEFI Malware with Velociraptor (Feb 2024)](https://www.rapid7.com/blog/post/2024/02/29/how-to-hunt-for-uefi-malware-using-velociraptor/)
- [arXiv UEFI Memory Forensics Framework (Jan 2025)](https://arxiv.org/html/2501.16962v1)
- [MITRE ATT&CK T1546.011 (Application Shimming)](https://attack.mitre.org/techniques/T1546/011/)
- [SigmaHQ SDB Persistence Detection Rule (Oct 2025)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml)
- [Google Cloud FIN7 Shim Database Persistence](https://cloud.google.com/blog/topics/threat-intelligence/fin7-shim-databases-persistence)
- [BleepingComputer Windows EFS Ransomware Feature](https://www.bleepingcomputer.com/news/security/windows-efs-feature-may-help-ransomware-attackers/)
- [Akamai State of the Internet Ransomware Trends 2025](https://www.akamai.com/site/en/documents/state-of-the-internet/2025/ransomware-trends-2025.pdf)
- [Dragos OT Ransomware Trends Q1 2025](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q1-2025)
- [JPCERT/CC ETW Forensics (Nov 2024)](https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html)
- [FortiGuard AutoLogger DiagTrack ETL Forensic Evidence](https://www.fortinet.com/blog/threat-research/uncovering-hidden-forensic-evidence-in-windows-mystery-of-autologger)
- [ElcomSoft Windows 10/11 Event Log Forensic Analysis (Feb 2026)](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/)
- [Binarly Design Issues of Modern EDRs: Bypassing ETW](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
- [Magnet Forensics hiberfil.sys Forensics](https://www.magnetforensics.com/blog/when-windows-takes-a-nap-and-leaves-you-evidence-inside-hiberfil-sys/)
- [Hiberfil.sys Forensics Wiki](https://forensics.wiki/hiberfil.sys/)
- [MDPI Memory Forensics Fileless Detection 2025](https://www.mdpi.com/2073-431X/14/11/467)
- [ACM Memory Analysis Survey 2025](https://dl.acm.org/doi/10.1145/3764580)
- [Forensics Wiki Windows Event Log (EVT)](https://forensics.wiki/windows_event_log_(evt)/)
- [Windows Embedded & IoT OS Reference](https://www.elbacom.com/embedded-iot-operating-systems)
