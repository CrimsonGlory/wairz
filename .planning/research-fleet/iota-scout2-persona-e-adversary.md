# Phase ι — Scout 2: Persona-E Adversary Refresh

**Lens:** Persona-E is wairz's fictional advanced-tier offensive adversary representing nation-state + ransomware-affiliate threats. Rank the 5 ι candidates (4 carryovers + 1-2 adjacency picks) by **adversary-coverage-value** — which artifact, when surfaced by wairz, catches the most diverse + most recent threat activity, weighted by detection-rarity in commercial EDR.

**Scope reminder:** wairz is a Linux-hosted *offline firmware* analysis platform. Candidates are evaluated for what they surface in a *static disk image* extracted from firmware/embedded systems — not live EDR telemetry. The Persona-E coverage value reflects *the artifact's role in adversary persistence/operations*; the rarity dimension reflects *where commercial EDR is structurally blind* (most EDR is live-telemetry-first, weak on offline-disk-from-image triage).

**Date of research:** 2026-05-12

**Continuity with θ:** Phase η + θ shipped 10 Windows-coverage walker streams (NTFS-MFT, Authenticode, DBX, scheduled-tasks, LNK, registry persistence, Amcache, Prefetch, SRUM, BCD, WMI, ESP, MBR/VBR, SDB). The ι candidates pick up where θ left off — including the θ-scout-2 #3 + #8 recommendation that **Volatility 3 + hibernate.sys be treated as a paired Phase-ι standalone campaign** because the engineering scope is materially larger than the other candidates.

---

### 1. Volatility 3 + hibernate.sys PAIRED — memory-dump as new top-level data type
- **Primary MITRE ATT&CK technique(s)**: T1055 (Process Injection — all sub-techniques: T1055.001 DLL Injection, T1055.002 PE Injection, T1055.004 Asynchronous Procedure Call, T1055.012 Process Hollowing), T1620 (Reflective Code Loading), T1027.002 (Software Packing), T1003.001 (LSASS Memory dump), T1555 (Credentials from Password Stores at hibernate time)
- **Notable threat actors / families**: APT29 (Cozy Bear) — WINELOADER second-stage; APT41 — fileless StealthVector loader; Lazarus / BlueNoroff — Telegram 2 Nim implant (April 2025+ ongoing); Cobalt Strike beacons (memory-only by default, JPCERT/CC published Volatility plugin specifically for in-memory CS detection); Conti/LockBit/ALPHV ransomware (in-memory decryptor staging); Brute Ratel C4; Sliver; commodity fileless loaders (PowerSploit, donut-shellcode, PEzor); Quasar Linux (QLNX, 2026 — 7 distinct persistence mechanisms including LD_PRELOAD); FIRESTARTER backdoor (CISA/NCSC 2026 — APT against Cisco ASA firmware, structurally memory-resident)
- **Recent incident references**:
  - [BlueNoroff Web3 macOS Intrusion Analysis (Huntress, Q4 2025)](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis) — Nim-based memory-resident implant ("Telegram 2") embedded as LaunchDaemon; only retrievable via memory triage post-hoc
  - [Securelist BlueNoroff GhostCall & GhostHire (Q4 2025)](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/) — ongoing operations since April 2025 against crypto/Web3 across India, Turkey, Australia, EU/Asia
  - [Forensicxlab Volatility3 Modern Windows Hibernation file analysis](https://www.forensicxlab.com/blog/hibernation) — current support for Windows 8 x64 through Windows 11 23H2 x64 hibernation files via Volatility 3
  - [JPCERT/CC Volatility Plugin for Detecting Cobalt Strike Beacon](https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html) — actively maintained; CS beacon config extraction from memory remains the most reliable offline detection
  - [MDPI Hybrid Behavioural-Forensic Detection Model (2025)](https://www.mdpi.com/2073-431X/14/11/467) — 90% detection on fileless attacks combining Volatility 3 + Sysmon + ETW vs. 30% disk-only
  - [Magnet Forensics hiberfil.sys Forensics](https://www.magnetforensics.com/blog/when-windows-takes-a-nap-and-leaves-you-evidence-inside-hiberfil-sys/) — historic memory snapshot includes credentials at hibernate time; Mimikatz-against-hiberfil is documented
  - [arXiv UEFI Memory Forensics Framework (Jan 2025)](https://arxiv.org/html/2501.16962v1) — firmware-derived memory triage is a 2025 research-active area
- **Detection rarity in current commercial EDR**: **rare-to-structurally-blind** — most commercial EDR has *live* memory introspection but few platforms productionise offline `.dmp`/`.raw`/`hiberfil.sys`/`pagefile.sys` triage from firmware images; firmware-captured snapshots are exotic. EDR is structurally weak when the system is *powered off* — exactly where wairz operates.
- **Adversary-coverage value**: **HIGH (highest of the 5 candidates)**
- **One-sentence rationale**: Memory is *the* layer where every modern fileless adversary lives — from APT29 WINELOADER to BlueNoroff Telegram 2 to every Cobalt Strike beacon ever cast — and hibernate.sys is the disk-resident memory snapshot that survives power-off; integrating Vol3 + hibernate parser unlocks a **detection multiplier across every other Windows artefact wairz already surfaces** (LNK + Prefetch + MFT all become richer with paired memory context).

### 2. EFS DDF/DRF — Encrypted File System adversary use
- **Primary MITRE ATT&CK technique(s)**: T1486 (Data Encrypted for Impact — ransomware variant), T1564.001 (Hide Artifacts: Hidden Files and Directories — insider variants), T1027 (Obfuscated Files), T1552.004 (Unsecured Credentials: Private Keys — EFS DDF/DRF cert exfil)
- **Notable threat actors / families**: SafeBreach Labs PoC ransomware family ("EFS ransomware" research class, January 2020); no widespread in-the-wild attribution observed in 2024-2026; insider-threat case-law references (employees encrypting departure data); historical APT use of EFS for selective document protection (limited public attribution)
- **Recent incident references**:
  - [SafeBreach EFS Ransomware research](https://www.safebreach.com/blog/efs-ransomware/) — primary reference; 3 AV vendors failed in original 2020 testing
  - [BleepingComputer Windows EFS Ransomware Feature](https://www.bleepingcomputer.com/news/security/windows-efs-feature-may-help-ransomware-attackers/) — still the most-cited public coverage
  - [DarkReading EFS Ransomware Slips by AV Products](https://www.darkreading.com/cyberattacks-data-breaches/efs-ransomware-slips-by-av-products) — same 2020 PoC era
  - [TrendMicro Security Note on EFS Bypass Issues](https://success.trendmicro.com/en-US/solution/KA-0010191) — vendor advisory, but no recent in-the-wild
  - [Elcomsoft Advanced EFS Data Recovery](https://www.elcomsoft.com/aefsdr.html) — actively maintained commercial product, suggests forensic market exists but mostly for legitimate recovery use cases
  - **Notably absent**: Akamai Q3 2025 ransomware trends report, Dragos 2024-2025 ICS ransomware reports — neither lists EFS-abuse as a top-N family TTP, confirming the PoC-only status
- **Detection rarity in current commercial EDR**: **rare** — EFS metadata parsing from offline NTFS is a specialist forensic skill; little commercial tooling triages DDF/DRF certificates offline; the structural gap exists but the *threat utilization* does not match it
- **Adversary-coverage value**: **LOW-to-MEDIUM**
- **One-sentence rationale**: High structural signal *when* present, but real-world adversary uptake has stayed primarily theoretical/PoC through 6+ years since SafeBreach's 2020 disclosure; coverage payoff is narrower than other candidates despite the EDR gap, and modern ransomware affiliates have settled on direct-overwrite encryption (LockBit, ALPHV, Royal) rather than EFS leveraging.

### 3. EVT pre-Vista — Legacy Windows XP/Server 2003 event logs
- **Primary MITRE ATT&CK technique(s)**: T1070.001 (Indicator Removal: Clear Windows Event Logs), T1562.002 (Disable Windows Event Logging) — same techniques as modern EVTX, on legacy format
- **Notable threat actors / families**: FrostyGoop (Dragos disclosure July 2024; Modbus TCP malware; gained access via Mikrotik router pivot; impacted Ukrainian district heating with ENCO controller firmware downgrade — January 2024); TRITON / INDUSTROYER variants (historical, XP-era subsystems touched); ransomware affiliates targeting hospital legacy gear (Windows XP Embedded shipped until December 2016 EOL, still in fielded medical/ATM/POS devices); Volt Typhoon adjacency (CISA / FBI / NSA joint advisory campaign targeting US critical infrastructure, structurally targets legacy systems)
- **Recent incident references**:
  - [The Register on FrostyGoop Ukraine heating attack (July 2024)](https://www.theregister.com/2024/07/23/frostygoop_ics_malware/) — explicitly notes the attacker downgraded ENCO firmware to versions lacking critical monitoring features; legacy attack on legacy gear
  - [Dragos FrostyGoop / BUSTLEBERM analysis (2024)](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology) — primary discovery report
  - [OPSWAT ICS/OT Threat Landscape 2024–2026](https://www.opswat.com/blog/every-ot-breach-has-a-file-in-its-attack-chain-the-ics-ot-threat-landscape-2024-2026) — every OT breach has a file in the attack chain; structurally aligns with offline-firmware-image triage
  - [Cyble Ransomware Threats to Vulnerable ICS](https://cyble.com/blog/ransomware-menace-amplifies-for-vulnerable-industrial-control-systems-heightened-threats-to-critical-infrastructure/) — ICS vulnerability disclosures nearly doubled 2024→2025
  - [Event Log Explorer on POSReady 2009 still supported](https://eventlogxp.com/blog/windows-event-viewer-cannot-read-classic-event-logs-anymore/) — millions of devices still log to legacy `.evt` format
  - [Forensics Wiki EVT format reference](https://forensics.wiki/windows_event_log_(evt)/) — format documentation; Windows 10 Event Viewer itself fails on legacy `.evt` files
- **Detection rarity in current commercial EDR**: **rare-to-structurally-blind** — modern EDR doesn't parse legacy `.evt` format; Windows 10/11 Event Viewer itself cannot open legacy EVT files, requiring specialist tools like Event Log Explorer
- **Adversary-coverage value**: **LOW-to-MEDIUM** (HIGH only for wairz's medical/industrial firmware niche)
- **One-sentence rationale**: Unique to wairz's embedded-firmware niche — most modern adversaries don't target XP-era directly, but the **firmware wairz analyses for medical/industrial IoT often runs XP Embedded** (December 2016 EOL, but still fielded in medical/ATM/POS), making this a niche-but-uncontested gap — and the FrostyGoop January 2024 attack proves nation-state actors *are* still touching legacy OT subsystems in 2024-2025.

### 4. ETL — Event Tracing for Windows logs (re-evaluated from θ)
- **Primary MITRE ATT&CK technique(s)**: T1070 (Indicator Removal — adversaries delete ETL traces to cover tracks), T1562.006 (Indicator Blocking — disable ETW providers), T1218 (Living-off-the-land via legitimate ETW consumers)
- **Notable threat actors / families**: Ransomware groups using anti-forensic ETL deletion (FortiGuard 2024-2025 documented case); APT actors with ETW bypass capability (Binarly research class — "Design Issues of Modern EDRs: Bypassing ETW-based Solutions"); red-team via SilkETW; the broader "EDR-bypass" tier (BlackCat/ALPHV documented disabling Microsoft Defender via ETW patching)
- **Recent incident references**:
  - [FortiGuard AutoLogger DiagTrack ETL Forensic Evidence (2024-2025)](https://www.fortinet.com/blog/threat-research/uncovering-hidden-forensic-evidence-in-windows-mystery-of-autologger) — **the critical finding**: during a ransomware investigation, the `AutoLogger-Diagtrack-Listener.etl` file exposed a kernel process trace stream containing historical records of process launches including command-line arguments, image paths, process and parent PIDs, and user SIDs — *even after* the adversary had removed binaries from disk and cleared standard event logs. FGIR extracted evidence of execution of binaries that had been deleted by the threat actor, including the tool GMER (renamed gomer.exe) and several malicious batch files.
  - [JPCERT/CC ETW Forensics (Nov 2024)](https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html) — formal guide to ETW forensics methodology
  - [ElcomSoft Windows 10/11 Event Log Forensic Analysis (Feb 2026)](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/) — extends Windows 10/11 forensic coverage including ETL
  - [Cyberpress on FortiGuard ETL finding](https://cyberpress.org/windows-telemetry-logs/) — secondary coverage confirming the discovery
  - [Hendry Adrian summary of AutoLogger-Diagtrack-Listener forensics](https://www.hendryadrian.com/uncovering-hidden-forensic-evidence-in-windows-the-mystery-of-autologger-diagtrack-listener-etl/) — additional summary
  - [Binarly Design Issues of Modern EDRs: Bypassing ETW](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions) — adversary side: ETW bypass as EDR-defeat primitive
- **Detection rarity in current commercial EDR**: **rare-to-structurally-blind** — `.etl` parsing is specialist; most commercial EDR consumes ETW *streams* live but does not triage offline `.etl` files from disk images; ETL is structurally a 2024-2026 *discovered-blind-spot* artefact. The structural insight is that **DiagTrack populates ETL files conditionally based on undocumented triggers** — meaning adversaries who think they've cleared logs may have missed a kernel-trace stream still on disk.
- **Adversary-coverage value**: **HIGH**
- **One-sentence rationale**: ETL has surfaced as the "surviving telemetry" that catches adversaries *after* they thought they cleaned up — a high-yield, recently-validated coverage gap that aligns directly with anti-forensics-aware nation-state and ransomware TTPs; carryover from θ where it ranked #2.

### 5. ADJACENCY PICK A — Linux journald + systemd unit file persistence (paired)
- **Primary MITRE ATT&CK technique(s)**: T1543.002 (Create or Modify System Process: Systemd Service), T1070.002 (Indicator Removal: Clear Linux or Mac System Logs — journald binary log clearing/truncation), T1053.003 (Scheduled Task/Job: Cron — co-located persistence), T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking — LD_PRELOAD, often paired with systemd persistence), T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification — `.bashrc` co-persistence)
- **Notable threat actors / families**:
  - **Quasar Linux (QLNX)** — discovered May 2026, uses **seven distinct persistence mechanisms** including LD_PRELOAD, systemd, crontab, init.d scripts, XDG autostart, and `.bashrc` injection; targets software developers ([We Fix PC, May 2026](https://we-fix-pc.com/2026/05/05/new-stealthy-quasar-linux-malware-targets-software-developers/))
  - **Transparent Tribe (APT36)** — Pakistan-linked; August 2025 campaign delivered malicious Linux `.desktop` files disguised as PDFs via spear-phishing; persistence via autostart + cron + systemd abuse; "still going strong" per Elastic Security Labs
  - **FIRESTARTER** — CISA/NCSC joint advisory (2026); APT backdoor against Cisco ASA firmware; structurally Linux-derivative
  - Cryptominer crews using systemd unit files for persistence (broadly attested in 2024-2025 cloud-instance compromises)
  - Ransomware crews pivoting to Linux ESXi targets (broad 2024 Royal, BlackCat, LockBit-Linux variants — many use systemd timers + units for persistence)
- **Recent incident references**:
  - [Elastic Security Labs - Linux Detection Engineering: Sequel on Persistence Mechanisms (2025)](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms) — comprehensive Linux persistence coverage including systemd
  - [SOCRadar Top 10 APT Groups in 2025](https://socradar.io/blog/top-10-apt-groups-in-2025/) — multiple Linux-targeting APT groups documented
  - [CISA FIRESTARTER Backdoor advisory (2026)](https://www.cisa.gov/news-events/analysis-reports/ar26-113a) — Cisco ASA firmware APT
  - [Red Canary ATT&CK T1501 Systemd Service Persistence](https://redcanary.com/blog/threat-detection/attck-t1501-understanding-systemd-service-persistence/) — detection guidance
  - [Forensic Analysis of Linux Journals (Abhiram's Blog)](https://stuxnet999.github.io/dfir/linux-journal-forensics/) — practical journald binary log forensics methodology
  - [PMC Linux APT intrusion detection dataset 2024](https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/) — formal academic dataset for Linux APT detection
  - [Stealthy Quasar Linux malware analysis (May 2026)](https://we-fix-pc.com/2026/05/05/new-stealthy-quasar-linux-malware-targets-software-developers/)
- **Detection rarity in current commercial EDR**: **uncommon-to-rare for offline-image triage** — Linux EDR exists but disk-image-of-Linux-firmware triage is the structural gap; most commercial Linux EDR targets live cloud workloads, not firmware-extracted disk images
- **Adversary-coverage value**: **HIGH (for wairz's firmware-analysis niche specifically — wairz analyses Linux-based firmware MORE than Windows-based firmware on the routing/IoT/embedded side)**
- **One-sentence rationale**: wairz's primary user persona (firmware reverse engineer + security assessor) analyses Linux-based firmware (OpenWrt, DD-WRT, embedded vendors) at the same or higher rate than Windows firmware; surfacing Linux journald binary logs + systemd unit-file persistence catches the entire APT36 / FIRESTARTER / Quasar tier *and* the ESXi-ransomware lateral-pivot tier in a single sweep, with explicit cross-coverage for cron + LD_PRELOAD + `.bashrc` co-persistence (T1546.004 / T1574.006 sub-coverage).

### 6. ADJACENCY PICK B — Container runtime artifacts (runc state JSON + OCI image-spec layers)
- **Primary MITRE ATT&CK technique(s)**: T1610 (Deploy Container — adversary-deployed images on compromised hosts), T1611 (Escape to Host — container escape via runc CVE chain), T1612 (Build Image on Host — adversary-built malicious images at runtime), T1525 (Implant Internal Image — backdoored image layers), T1543 (Create or Modify System Process — container as persistence vehicle)
- **Notable threat actors / families**: Recent runc CVE chain (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 — Sysdig/Orca disclosure November 2025) creates the **adversary opportunity** even though specific in-the-wild attribution remains limited; ransomware crews targeting Kubernetes (TeamTNT historical, plus the LockBit-Linux pivot to container hosts); cryptominers as primary persona (Kinsing, RocketBot, broadly attested 2024-2025); Operation Diceshovel and similar cloud-supply-chain campaigns (broader Unit 42 ELF-malware-targets-cloud research class)
- **Recent incident references**:
  - [Sysdig - New runc vulnerabilities CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 (November 2025)](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities) — three new runc CVEs affecting nearly all runc versions
  - [Orca - New runC Vulnerabilities Expose Docker and Kubernetes](https://orca.security/resources/blog/new-runc-vulnerabilities-allow-container-escape/) — secondary coverage with exploit detail
  - [The Hacker News - Docker CVE-2025-9074 critical container escape (CVSS 9.3, August 2025)](https://thehackernews.com/2025/08/docker-fixes-cve-2025-9074-critical.html) — separate August 2025 critical Docker CVE
  - [Unit 42 Container Breakouts: Escape Techniques in Cloud Environments](https://unit42.paloaltonetworks.com/container-escape-techniques/) — comprehensive escape technique survey
  - [Red Hat Docker Forensics for Containers](https://www.redhat.com/en/blog/docker-forensics-for-containers-how-to-conduct-investigations) — official forensics methodology
  - [CONTAIN4n6 systematic evaluation of container artifacts (Journal of Cloud Computing)](https://journalofcloudcomputing.springeropen.com/articles/10.1186/s13677-022-00303-8) — academic baseline
  - [Unit 42 Evolution of Linux Binaries in Targeted Cloud Operations](https://unit42.paloaltonetworks.com/elf-based-malware-targets-cloud/) — broader cloud-malware landscape
- **Detection rarity in current commercial EDR**: **rare** — container artifact offline-image triage is a specialist forensic skill; most container EDR runs live (Falco, Sysdig Runtime); few platforms can take a static disk image of a host carrying runc state + image cache + layer files and reconstruct what containers were deployed
- **Adversary-coverage value**: **MEDIUM-to-HIGH (rising trend; lower current breadth than option A)**
- **One-sentence rationale**: The container forensics surface is genuinely rising in 2024-2026 with three runc CVEs and one critical Docker CVE shipped in 2025, but the adversary persona is currently narrower than the Linux systemd surface (mostly cryptominer + Kubernetes-pivot crews, less APT-tier than option A) — strong secondary pick but a worse first-of-its-class investment than the broader Linux journald + systemd coverage.

---

## Synthesis — Top 3 by Adversary-Coverage × Detection-Rarity

The scoring axis is **(adversary breadth × recency-of-relevance) × (commercial-EDR coverage gap for offline-image triage)**. wairz's structural advantage is *offline static firmware analysis* — so artefacts that are well-covered by live EDR but invisible offline still score highly.

### Rank 1: **Volatility 3 + hibernate.sys PAIRED** (candidate #1) — HIGH × rare-to-structurally-blind

**Adversary persona-fit:** Catches ALL FOUR adversary tiers:
- **APT** — APT29 WINELOADER, APT41 fileless StealthVector, BlueNoroff Nim implants (April 2025 ongoing), Lazarus broadly
- **Ransomware affiliates** — Conti, LockBit, ALPHV (in-memory decryptor staging; encrypted-key recoverable from memory)
- **Insider-threat / red-team / commodity** — every Cobalt Strike beacon, Brute Ratel, Sliver, PowerSploit-derived loader
- **Supply-chain** — memory-resident second-stages of compromised software update flows (XZ Utils-class incidents leave residue in memory even when the cleanup binary itself is gone)

**MITRE technique mapping wairz would surface:** T1055 (Process Injection — all sub-techniques), T1620 (Reflective Code Loading), T1027.002 (Software Packing), T1003.001 (LSASS Memory dump), T1555 (Credentials from Password Stores). The wairz emitter ranges across **finding-source** `windows_volatility_injection`, `windows_volatility_cobalt_strike_beacon`, `windows_volatility_credential_material`, `windows_hibernate_lsass_artifact`.

**Detection narrative:** "If `hiberfil.sys` is present in firmware at `/Windows/System32/config/` or `/Windows/hiberfil.sys`, wairz decompresses it to a raw memory image, runs Volatility 3 plugins (`pslist`, `malfind`, `cmdline`, `dlllist`, `handles`, `cobaltstrikescan`, `mimikatz`) against it, and emits one finding per detected anomaly — tagged HIGH severity because **memory-resident adversaries are by design invisible to disk-only EDR**, and the firmware image is structurally the only forensic surface that survives the adversary's clean-up after live operation."

**Anti-counter-detection:** Adversary clean-up options are extremely limited — to defeat hibernate-based memory forensics, the adversary must either (a) **prevent hibernation entirely** (requires admin + persistent registry change), (b) **wipe hiberfil.sys** (requires admin + reboot, which itself generates Prefetch/Amcache artifacts wairz already detects), or (c) **encrypt the entire volume with BitLocker** (which then becomes its own indicator). For (a), wairz can detect the registry change via the η registry persistence walker. For (b), wairz detects the post-reboot Prefetch + Amcache. For (c), wairz detects BitLocker volume metadata. **The triple-redundant trace coverage makes this candidate exceptionally hard to counter.**

---

### Rank 2: **ETL Event Tracing logs** (candidate #4) — HIGH × rare-to-structurally-blind

**Adversary persona-fit:** Catches **APT + ransomware affiliates** primarily; weak against pure-fileless threats (those leave less ETL trace). Strongest against the **anti-forensics-aware tier** — the adversary who took the trouble to clear Security/System EVTX logs is exactly the adversary who DIDN'T know to look for `AutoLogger-Diagtrack-Listener.etl`.

**MITRE technique mapping:** T1070 (Indicator Removal — and specifically the failure of T1070.001 to be complete), T1562.006 (Indicator Blocking), T1218 (LOL via legitimate ETW consumers). The wairz emitter ranges across **finding-source** `windows_etl_process_create_residue`, `windows_etl_diagtrack_listener_evidence`, `windows_etl_deleted_binary_artifact`.

**Detection narrative:** "If `C:\Windows\System32\WDI\LogFiles\*.etl` OR `C:\Windows\System32\winevt\Logs\*.etl` OR `C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl` is present in firmware, wairz parses the ETL files for `KernelProcess → ProcessStarted` stream events and emits one finding per **process creation event whose Image path is no longer present on disk** (binary deleted by adversary but ETL retained the trace) — tagged HIGH severity because **the ETL trace is the smoking-gun evidence the adversary thought they removed**, validated against the FortiGuard GMER-renamed-gomer.exe case study."

**Anti-counter-detection:** The adversary's clean-up options are narrow — the FortiGuard finding is that DiagTrack populates ETL files conditionally based on undocumented triggers, so most adversaries don't even know to look for these files. Even sophisticated cleanup (`wevtutil cl Security` + `wevtutil cl System`) leaves AutoLogger ETL files untouched in the documented cases. The adversary would need to know about and explicitly clear `*.etl` in WDI/LogFiles AND AutoLogger AND winevt/Logs to defeat this — and `cipher /w:`-style overwrite of the partition would itself generate detectable artifacts elsewhere. **Carry-over from θ where it ranked #2; the rank holds in ι.**

---

### Rank 3: **Linux journald + systemd unit file persistence PAIRED** (adjacency pick A) — HIGH × uncommon-to-rare

**Adversary persona-fit:** Catches the **APT tier targeting Linux firmware** (APT36 Transparent Tribe August 2025, FIRESTARTER 2026 Cisco ASA, broad ELF-malware-targets-cloud campaigns) + the **ransomware-affiliate tier pivoting to Linux ESXi targets** (LockBit-Linux, ALPHV-Linux, Royal-Linux 2024-2025 variants) + **cryptominer crews** (Kinsing, RocketBot, attested broadly). Crucially, this is the FIRST candidate in the synthesis that maps directly to **wairz's primary use case** — wairz analyses Linux-based firmware (OpenWrt, DD-WRT, vendor router/IoT firmware, embedded device images) at the same or higher rate than Windows-based firmware. The η + θ campaigns shipped 10 Windows-coverage walkers; ι adding a Linux coverage stream is a structural gap-fill for wairz's portfolio that exceeds raw adversary count.

**MITRE technique mapping:** T1543.002 (systemd service persistence), T1070.002 (clear journald binary logs), T1053.003 (cron co-persistence), T1574.006 (LD_PRELOAD shared object hijack), T1546.004 (`.bashrc` injection). The wairz emitter ranges across **finding-source** `linux_systemd_unit_persistence`, `linux_journald_cleared`, `linux_ld_preload_hijack`, `linux_cron_persistence`, `linux_bashrc_injection`.

**Detection narrative:** "If a Linux firmware extraction contains `/etc/systemd/system/*.service` OR `/usr/lib/systemd/system/*.service` OR `/var/log/journal/*/system.journal` OR `/etc/ld.so.preload`, wairz parses each artifact and emits findings for: (a) systemd unit files with `ExecStart=` paths in writable directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/home/*`); (b) journald binary logs with gaps, truncation, or rotation patterns suggesting clearance (T1070.002); (c) `/etc/ld.so.preload` containing user-writable paths or unsigned shared objects (T1574.006 LD_PRELOAD hijack — matches Quasar Linux QLNX 2026); (d) cron entries (`/etc/cron.d/*`, `/var/spool/cron/*`) pointing to writable paths — tagged HIGH severity because **the surface combination matches APT36 + FIRESTARTER + Quasar Linux TTPs verbatim**."

**Anti-counter-detection:** The adversary can shred systemd unit files (`shred -u`) but typically misses the journald binary log evidence of the unit's activation history; conversely, they can clear journald (`journalctl --rotate` + `journalctl --vacuum-time=1s`) but typically leave systemd unit files behind. **The bilateral trace pattern means single-vector cleanup almost always leaves the other vector intact.** Plus, the η-shipped Linux scheduled-task surface gives partial coverage already — adding journald + systemd-unit closes the Linux side to ~80% of the Windows-side coverage wairz already has.

---

### TOP 2 to DEFER

**Defer 1: EFS DDF/DRF (candidate #2) — LOW-to-MEDIUM**
- The structural EDR gap is real, but the threat hasn't materialised at scale; SafeBreach 2020 PoC is still the headline reference six years later.
- 2024-2026 ransomware-trends reports (Akamai, Dragos) do NOT list EFS-abuse as a top-N family TTP.
- Modern ransomware affiliates (LockBit, ALPHV, Royal, Cl0p) have settled on direct-overwrite encryption rather than EFS-leveraging — the threat economics favour the simpler approach.
- Wairz should monitor this surface for 12-18 months for re-evaluation; if any 2026-2027 incident report places EFS DDF/DRF abuse in a top-N TTP, promote to Phase κ.

**Defer 2: EVT pre-Vista (candidate #3) — LOW-to-MEDIUM**
- Niche-but-uncontested gap, but the adversary persona is bounded to ICS/medical/embedded-legacy
- FrostyGoop (January 2024) proves nation-state actors *are* still touching legacy OT subsystems, but FrostyGoop itself uses Modbus over TCP, not Windows event logs — the legacy-EVT surface is incidental to the actual attack vector
- Wairz's existing Phase η EVTX walker handles the modern format; extending to legacy EVT is a 20% implementation cost for ~5% of wairz's firmware corpus (medical/ICS legacy gear)
- Reasonable Phase κ or later candidate if a specific medical/ICS firmware case study justifies the investment

**Honourable mention — Container runtime forensics (adjacency pick B) — MEDIUM-to-HIGH (rising)**
- Genuinely rising trend with 4 critical 2025 CVEs (3 runc + 1 Docker)
- But adversary persona is narrower than Linux systemd (mostly cryptominer + K8s-pivot crews, less APT-tier)
- Strong Phase κ candidate once the runc CVE chain matures into documented in-the-wild attacks
- Pairs naturally with future cloud/container-image expansion of wairz's scope

---

## Final ranking

| Rank | Candidate | Persona-E value | EDR rarity | Implementation notes |
|------|-----------|-----------------|------------|----------------------|
| 1 | Volatility 3 + hibernate.sys PAIRED | HIGH | rare-to-blind | Largest engineering scope but largest detection multiplier; θ-scout-2 #3+#8 carryover |
| 2 | ETL Event Tracing logs | HIGH | rare-to-blind | Carryover from θ rank-2; FortiGuard 2024-2025 evidence remains the highest-quality recency reference |
| 3 | Linux journald + systemd PAIRED (NEW adjacency pick A) | HIGH (esp. for wairz portfolio fit) | uncommon-to-rare | Strategic gap-fill — first Linux walker in wairz Windows-heavy Phase η+θ portfolio; cross-coverage for APT36 + FIRESTARTER + Quasar 2026 |
| 4 (defer) | EFS DDF/DRF | LOW-to-MEDIUM | rare | Threat hasn't materialised; revisit in 12-18 months |
| 5 (defer) | EVT pre-Vista | LOW-to-MEDIUM | rare | Niche; let medical/ICS-specific intake drive promotion |

**Strategic note for the synthesizer:** The ι top-3 covers a balanced threat-axis matrix:
- #1 covers the *memory-resident / fileless* axis (any platform);
- #2 covers the *anti-forensic-aware Windows ransomware/APT* axis;
- #3 covers the *Linux-firmware-resident persistence* axis (closing wairz's biggest portfolio gap).

A Phase-ι campaign that ships all three would yield wairz's most diversified single-phase coverage uplift since the η + θ Windows-side decadrun.

---

## Sources

- [MITRE ATT&CK T1055 (Process Injection)](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1620 (Reflective Code Loading)](https://attack.mitre.org/techniques/T1620/)
- [MITRE ATT&CK T1003.001 (LSASS Memory)](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1543.001 (Launch Agent)](https://attack.mitre.org/techniques/T1543/001/)
- [MITRE ATT&CK T1543.002 (Systemd Service)](https://attack.mitre.org/techniques/T1543/002/)
- [MITRE ATT&CK T1574.006 (Dynamic Linker Hijacking)](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK T1070 (Indicator Removal)](https://attack.mitre.org/techniques/T1070/)
- [Forensicxlab Volatility3 Modern Windows Hibernation file analysis](https://www.forensicxlab.com/blog/hibernation)
- [Magnet Forensics hiberfil.sys Forensics](https://www.magnetforensics.com/blog/when-windows-takes-a-nap-and-leaves-you-evidence-inside-hiberfil-sys/)
- [JPCERT/CC Volatility Plugin for Cobalt Strike](https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html)
- [BlueNoroff Web3 macOS Intrusion (Huntress 2025)](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis)
- [Securelist BlueNoroff GhostCall & GhostHire](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/)
- [MDPI Hybrid Behavioural-Forensic Detection Model 2025](https://www.mdpi.com/2073-431X/14/11/467)
- [arXiv UEFI Memory Forensics Framework (Jan 2025)](https://arxiv.org/html/2501.16962v1)
- [SafeBreach EFS Ransomware research](https://www.safebreach.com/blog/efs-ransomware/)
- [BleepingComputer Windows EFS Ransomware Feature](https://www.bleepingcomputer.com/news/security/windows-efs-feature-may-help-ransomware-attackers/)
- [DarkReading EFS Ransomware Slips by AV Products](https://www.darkreading.com/cyberattacks-data-breaches/efs-ransomware-slips-by-av-products)
- [Elcomsoft Advanced EFS Data Recovery](https://www.elcomsoft.com/aefsdr.html)
- [Forensics Wiki EVT format](https://forensics.wiki/windows_event_log_(evt)/)
- [Event Log Explorer on legacy EVT support](https://eventlogxp.com/blog/windows-event-viewer-cannot-read-classic-event-logs-anymore/)
- [The Register on FrostyGoop](https://www.theregister.com/2024/07/23/frostygoop_ics_malware/)
- [Dragos FrostyGoop / BUSTLEBERM analysis](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology)
- [Hacker News FrostyGoop coverage](https://thehackernews.com/2024/07/new-ics-malware-frostygoop-targeting.html)
- [OPSWAT ICS/OT Threat Landscape 2024–2026](https://www.opswat.com/blog/every-ot-breach-has-a-file-in-its-attack-chain-the-ics-ot-threat-landscape-2024-2026)
- [Cyble Ransomware ICS Threats](https://cyble.com/blog/ransomware-menace-amplifies-for-vulnerable-industrial-control-systems-heightened-threats-to-critical-infrastructure/)
- [FortiGuard AutoLogger DiagTrack ETL Forensic Evidence](https://www.fortinet.com/blog/threat-research/uncovering-hidden-forensic-evidence-in-windows-mystery-of-autologger)
- [JPCERT/CC ETW Forensics (Nov 2024)](https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html)
- [ElcomSoft Windows 10/11 Event Log Forensic Analysis (Feb 2026)](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/)
- [Binarly Design Issues of Modern EDRs: Bypassing ETW](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
- [Cyberpress on FortiGuard ETL finding](https://cyberpress.org/windows-telemetry-logs/)
- [Hendry Adrian summary of AutoLogger-Diagtrack-Listener](https://www.hendryadrian.com/uncovering-hidden-forensic-evidence-in-windows-the-mystery-of-autologger-diagtrack-listener-etl/)
- [Forensic Analysis of Linux Journals (Abhiram's Blog)](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Canary ATT&CK T1501 Systemd Persistence](https://redcanary.com/blog/threat-detection/attck-t1501-understanding-systemd-service-persistence/)
- [Elastic Security Labs Linux Persistence Mechanisms Sequel](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)
- [SOCRadar Top 10 APT Groups 2025](https://socradar.io/blog/top-10-apt-groups-in-2025/)
- [CISA FIRESTARTER Backdoor advisory 2026](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)
- [Quasar Linux malware 2026 analysis](https://we-fix-pc.com/2026/05/05/new-stealthy-quasar-linux-malware-targets-software-developers/)
- [PMC Linux APT detection dataset 2024](https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/)
- [SANS FOR577 Linux Incident Response](https://www.sans.org/cyber-security-courses/linux-threat-hunting-incident-response)
- [Sysdig runc CVE-2025-31133/52565/52881](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities)
- [Orca runC Vulnerabilities](https://orca.security/resources/blog/new-runc-vulnerabilities-allow-container-escape/)
- [Hacker News Docker CVE-2025-9074 critical container escape](https://thehackernews.com/2025/08/docker-fixes-cve-2025-9074-critical.html)
- [Unit 42 Container Breakouts Survey](https://unit42.paloaltonetworks.com/container-escape-techniques/)
- [Red Hat Docker Forensics for Containers](https://www.redhat.com/en/blog/docker-forensics-for-containers-how-to-conduct-investigations)
- [CONTAIN4n6 Journal of Cloud Computing](https://journalofcloudcomputing.springeropen.com/articles/10.1186/s13677-022-00303-8)
- [Unit 42 ELF Malware Targets Cloud](https://unit42.paloaltonetworks.com/elf-based-malware-targets-cloud/)
- [SentinelLabs macOS Threat Tools & Techniques](https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/)
- [Microsoft Security Blog ClickFix macOS Infostealer (May 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/)
- [Securelist BlueNoroff GhostCall & GhostHire detailed](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/)
