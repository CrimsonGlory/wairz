# Phase ι Competitive Parity Research — Scout 3

**Lens:** RE/forensic-platform competitive parity for the 4 θ-deferred candidates + 2 adjacency picks.
**Date:** 2026-05-12
**Author:** Scout 3 (research-fleet wave, parallel to Scouts 1 & 2)
**Wairz baseline (post-θ):** NTFS $MFT, scheduled-tasks, LNK, BYOVD LOLDrivers, PowerShell EID4104, Authenticode/DBX, registry hive walker, EVTX, Amcache, Prefetch, SRUM, BCD, WMI persistence, ESP `.efi` chain, MBR/VBR boot sectors, SDB shim database.

Boot-chain trifecta (BCD + ESP + MBR/VBR + SDB) is operational with cross-firmware fingerprint MCP tools.

---

### 1. Volatility 3 + hibernate.sys PAIRED (memory-dump triage)

- **Coverage by competing platforms** (artifact × tool):

  | Tool | hiberfil.sys decompression | Live memory analysis | Notes |
  |------|---------------------------|---------------------|-------|
  | Volatility 3 | YES (`windows.hibernation` AS, native) | YES (~30+ plugins: pslist, malfind, cmdline, netscan, hivelist, ssdt, callbacks, modscan, hollowfind) | Reference platform; v2.27.0 (Feb 2026) adds windows.amcache, windows.cmdscan, windows.consoles, windows.debugregisters, windows.orphan_kernel_threads, windows.pe_symbols, windows.scheduled_tasks, windows.unhooked_system_calls |
  | MemProcFS (Ulf Frisk) | YES (hibernation file support) | YES (VFS-mounted; live PCILeech, WinPMEM, DumpIt; YARA + timelines) | v4.1+ offline symbols on Linux; closest competitor to Vol3 |
  | Hibr2Bin (Magnet/Comae/MoonSols) | YES (canonical converter) | NO | Stale post-Win8 Huffman variant; multiple forks (MagnetForensics, AddaxSoft, fransla, vysecurity) |
  | KAPE | NO (collects via Target) | NO | Defers analysis to Vol3 |
  | Velociraptor | Collects hiberfil.sys via Target | NO (analysis defers to Vol3) | `Windows.Detection.Bootkits` adjacent |
  | EZTools | NO | NO | Explicitly out-of-scope for EZ suite |
  | Plaso | Processes hiberfil.sys for timelining | Limited | log2timeline 20260427 docs mention hiberfil but defer extraction |
  | FLARE-VM | Bundles Vol3 + Hibr2Bin | YES (via Vol3) | Mandiant-curated bundle |
  | Autopsy | Collects but doesn't decompress | NO | Plugin-via-Vol3 path |

- **Format documentation**: Hibernation file is reverse-engineered (Matthieu Suiche "Sandman" 2008 canonical; Windows 8/Server 2012 introduced Huffman + Xpress variant that broke pre-existing parsers). Volatility 3 maintains the most current implementation. Memory dump formats (raw, crash, ELF core) are public. Vol3 profile system is open-source.
- **Wairz current gap severity**: **Negligible-to-minor for firmware-RE focus** (unchanged from θ scout 3 analysis). Memory dumps are a runtime / IR artifact; hibernation files are captured from powered-on Windows machines. Neither appears in firmware images shipped from a vendor. This is genuinely out-of-audience for wairz.
- **Differentiation opportunity**: The PAIRED hibernate+Vol3 framing in the ι candidate list is more interesting than θ's split treatment — but the differentiation math is unchanged. Vol3 is so dominant that any wairz integration would be a thin wrapper. The ONE differentiation worth highlighting: if wairz integrated Vol3 output INTO its cross-firmware finding aggregation pattern (e.g., correlate memory-resident driver names from a runtime snapshot back to BYOVD LOLDrivers hits in the firmware blob already-shipped in θ), that's novel cross-artifact correlation NO other tool provides. But it requires the user to provide BOTH a firmware AND a memory dump alongside — which breaks the wairz "upload a firmware blob and walk it" model. Companion problem: MemProcFS is positioning hard via its MCP server (skywork.ai page exists already) — wairz would be entering a contested space, not a green-field one.
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Vol3 + MemProcFS already own the space; the format alignment is poor (firmware-on-disk vs runtime-memory); the upload model conflict is structural; and MemProcFS is already shipping MCP integration, eliminating the differentiation wedge.

---

### 2. EFS DDF/DRF (Encrypted File System metadata recovery)

- **Coverage by competing platforms** (artifact × tool):

  | Tool | $EFS attribute 0x100 parsing | DPAPI integration | EFS-decrypt-with-key |
  |------|------------------------------|-------------------|---------------------|
  | NTFSTool (thewhiteninja) | YES (reads $EFS attr; lists DDF/DRF) | YES (exports PKCS12) | YES (with .pfx) |
  | Microsoft `efsinfo`/`cipher` | YES (live-system only) | Indirect | YES (live) |
  | Volatility 3 | Partial via `windows.dpapi` family | YES | NO (route via mimikatz/DPAPIck downstream) |
  | DPAPIck | NO ($EFS itself) | YES (master keys) | Indirect (composed tooling) |
  | mimikatz `dpapi::masterkey` | NO | YES | YES (composed) |
  | Velociraptor | Collects $EFS streams via NTFS artifact; defers analysis | YES via DPAPI artifacts | NO |
  | Plaso | NO first-class EFS plugin | Partial DPAPI in winreg plugin | NO |
  | EZTools | **NO** (gap in EZ suite) | NO direct | NO |
  | KAPE | Collects via Target | Collects DPAPI via Target | NO |
  | Elcomsoft Advanced EFS Data Recovery | YES (commercial) | YES | YES | (closed source $$$)
  | Autopsy | NO native EFS plugin | NO | NO |
  | dissect.ntfs (Fox-IT) | Partial attribute exposure | NO | NO |

- **Format documentation**: Microsoft publishes MS-FSCC for $EFS attribute (0x100) and MS-EFSR for the recovery agent protocol. DDF/DRF binary layout IS in public Microsoft specifications. DPAPI internals were reverse-engineered (Bursztein & Picod) but the keychain is now also partially documented. NTFS.com hosts the canonical layout (0.5K-several-KB attribute, variable DDF/DRF record count).
- **Wairz current gap severity**: **Minor-to-major depending on target**. For consumer/embedded firmware → minor (devices don't ship pre-populated $EFS-protected files). For enterprise endpoint images / supply-chain artifacts / WIM payloads → moderate-to-major. Wairz's typical firmware upload doesn't carry $EFS-protected files; this is an endpoint-forensics-shaped ask. However, with Phase η/θ giving wairz a serious Windows-endpoint reputation, the demographic of submitted samples may shift toward enterprise endpoint disk images where $EFS appears.
- **Differentiation opportunity**: NTFSTool is the closest free competitor and is single-binary CLI; no LLM integration. EZTools has a real gap — surfacing $EFS metadata via wairz's MCP `lookup_efs_ddf` would be unique. BUT: standalone EFS header parsing without decryption is forensically weak; if wairz half-implements (parse + list DDF/DRF user SIDs + no decrypt), the value is "this file is encrypted, here are the user SIDs that can decrypt it" — useful for triage, not for evidence extraction. The DPAPI master-key recovery rabbit hole (requires user creds, SYSTEM keys, optional domain DPAPI, offline LSASS dumps) is a non-trivial follow-on. The differentiation is real for triage but limited for completeness — and the audience hasn't been asking. Cross-firmware aggregation ("this user SID appears as DDF on N firmware images = supply-chain operator account") is a novel insight but requires the user-SID-prevalence dataset to be meaningful.
- **Competitive parity rating**: **MEDIUM-LOW**
- **One-sentence rationale**: Format is public, competitors don't cover it cleanly (especially EZTools), and parse-only is genuinely useful for triage — but firmware uploads rarely carry $EFS-protected files, and a half-implementation without DPAPI decrypt is forensically weak; promote ONLY if endpoint-disk-image audience materializes.

---

### 3. EVT pre-Vista (legacy XP/2003 event logs)

- **Coverage by competing platforms** (artifact × tool):

  | Tool | .evt parsing | Notes |
  |------|--------------|-------|
  | Volatility 3 | YES (`windows.evtlogs` — LEGACY EVT, distinct from EVTX) | First-class legacy parser |
  | Plaso/log2timeline | YES (`winevt` parser) | Used for timelining |
  | python-evt (Ballenthin) | YES | Pure Python; reference impl |
  | libevt (libyal) | YES (alpha-status LGPLv3+) | Has pyevt Python module |
  | EZTools EvtxECmd | NO (EVTX only) | Carvey's `evtwalk`/`evtparse` for legacy EVT (separate) |
  | KAPE | Collects via Target; relies on Plaso/Carvey | Triage-only |
  | Velociraptor | Minimal legacy EVT support | Defers to libyal |
  | Autopsy | Plugin-via-Plaso | Indirect |

- **Format documentation**: Fully public. Microsoft EVT file format (MS-EVEN; binary, fixed-size records, circular buffer of record structures with string-template references in DLLs). Carvey + Ballenthin papers exhaustive. Format requires SYSTEM + SOFTWARE registry hive + multi-language DLL resources for full record decoding.
- **Wairz current gap severity**: **Negligible**. Pre-Vista (XP, Server 2003) targets are vanishing in production firmware. ICS / medical / legacy embedded Windows CE / XP-Embedded systems are the remaining audience — niche but real. Wairz's typical firmware audience (modern routers, embedded Linux, modern Windows IoT) does not encounter .evt files.
- **Differentiation opportunity**: Very narrow. Wairz's ε.1.b EVTX walker could be extended with a legacy-EVT adapter at low engineering cost (.evt format is simpler than EVTX — fixed-size records, no XML, no manifest-template chain). MCP cross-firmware angle: detect XP-embedded firmware via presence of .evt files = supply-chain age indicator. Could surface "this firmware is running an OS that has been EOL for 10+ years" as a Pydantic Literal source value (windows_legacy_evt). The differentiation is the AGE-INDICATOR FRAMING, not the parsing itself.
- **Competitive parity rating**: **LOW** (with a kicker for XP-embedded ICS detection)
- **One-sentence rationale**: Format is fading from production relevance; wairz's audience rarely encounters it; existing EVTX walker covers 99% of value; promote only as a 1-day adapter if XP-embedded ICS targets become a frequent ask.

---

### 4. ETL (Event Tracing for Windows logs)

- **Coverage by competing platforms** (artifact × tool):

  | Tool | ETL container parsing | Provider-manifest resolution | Notes |
  |------|----------------------|------------------------------|-------|
  | PerfView (Microsoft) | YES (canonical; v3.1.30 Feb 2026) | YES | Built on TraceEvent NuGet (Microsoft.Diagnostics.Tracing.TraceEvent) |
  | TraceEvent library | YES | YES | NuGet for .NET; not Python |
  | dissect.etl (Fox-IT) | YES (Python parser for kernel events) | Partial | First-class Python option |
  | etl-parser (forensiclunch) | YES (stale GitHub) | Partial | Long-tail community parser |
  | PyETW | Live ETW collection | YES | Not for offline ETL |
  | etl2pcapng (Microsoft) | YES (network-only ETL → PCAP) | NA | Specialized network captures |
  | EZTools | **NO** | NA | Out-of-scope |
  | Plaso | **NO** first-class ETL parser | NA | Gap |
  | Volatility 3 | **NO** | NA | Gap |
  | Velociraptor | Collects ETL via Target; defers to tracerpt | NA | No first-class parser |
  | KAPE | Collects; defers | NA | Triage-only |
  | Mandiant analysts | Use PerfView GUI | YES | Not a tool |

- **Format documentation**: Microsoft documents ETW providers (XML manifests, publicly registered; `wevtutil gp` enumerates) and the ETL container format (MS-DOCS). The binary container is moderately complex (multi-block, multi-buffer, kernel/user/private logger differentiation). dissect.etl is the only mature open-source Python parser, but it's positioned as a Dissect-framework module rather than a standalone library. Fox-IT's dissect ecosystem includes dissect.regf, dissect.eventlog, dissect.esedb already — wairz could wrap dissect.etl much as θ wraps libsdb / python-sdb.
- **Wairz current gap severity**: **Negligible-to-minor for offline firmware**. ETL is primarily a live-system telemetry stream (AutoLogger configs, DiagTrack). Saved ETL files appear mainly in diagnostic captures (`Windows\System32\WDI\LogFiles`, `Windows\Logs\DPX`, etc.) — these CAN appear in firmware images if vendor shipped diagnostic data with the image, but it's uncommon.
- **Differentiation opportunity**: Substantial IF wairz pivots toward incident-response artifact triage — no OSS tool offers clean offline ETL parsing other than dissect.etl and the stale etl-parser. dissect.etl is the existing reference; wairz would either (a) wrap dissect.etl and add MCP exposure + cross-firmware aggregation, OR (b) re-implement in pure Python from MS-DOCS. Option (a) is the cleaner Rule #19 path. The differentiator: MCP-callable `lookup_etl_providers` exposing which ETW providers logged events across N firmware images would be a category-creating capability — but the audience for this is narrow (ETL is primarily IR / runtime, not firmware static analysis). For firmware-RE this is far outside the core lane.
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Competitors don't cover it well (genuine gap), but ETL rarely appears in firmware-shaped uploads, and dissect.etl already exists as the OSS reference; the parity-gap math says "not worth the engineering" for wairz's audience.

---

### 5. ADJACENCY PICK A — Linux mirror coverage (journald + auditd + bash_history + systemd persistence)

This is the highest-value adjacency candidate by audience-fit. Wairz already ships a Linux unpacker pipeline (binwalk/unblob, ext4/squashfs filesystem extraction); Linux firmware is the dominant upload type today (OpenWrt routers, embedded Linux IoT, medical devices). The Windows-coverage campaign of Phases η+θ inverted the wairz audience focus toward Windows — but the **Linux mirror is the bigger demand** in absolute upload volume, and existing wairz coverage on the Linux side is shallow (filesystem walk + binary analysis; no systemd-persistence, no journald binary parsing, no bash_history correlation).

- **Coverage by competing platforms** (artifact × tool):

  | Tool | journald binary | auditd binary | bash_history | systemd persistence | cron / timers |
  |------|-----------------|---------------|--------------|---------------------|----------------|
  | Velociraptor | YES (`Linux.Forensics.Journal`, `parse_journald()` VQL) | YES (LogTargets) | YES | YES (`Linux.Sys.Services`, `Linux.Detection.Persistence`) | YES |
  | Plaso/log2timeline | Partial (no first-class journald in `--info` as of 20260427; syslog parser only) | YES (audit parser) | YES (bash_history) | Partial | YES |
  | dissect (Fox-IT) | Partial (Linux modules: dissect.extfs, dissect.jffs; no first-class journald yet) | NO | NO | NO | NO |
  | python-systemd | YES (live journal reader) | NO | NO | Live only | NO |
  | Kaitai Struct | YES (formal spec for journald) | NO | NO | NO | NO |
  | Mac-Triage / Aftermath | NA (macOS) | NA | NA | NA | NA |
  | Volatility 3 | NO (live-only via memory) | NO | NO | NO | NO |
  | EZTools | NA (Windows-only) | NA | NA | NA | NA |
  | KAPE | NA (Windows-only, but expanding) | NA | NA | NA | NA |
  | Autopsy | YES (LinuxArtifactsModule) | YES | YES | Partial | YES |
  | Elastic Security Labs | YES (`primer-on-persistence-mechanisms` blog) | YES (Auditbeat) | YES | YES | YES |

- **Format documentation**: journald binary file format is publicly documented (systemd journal-file format spec on freedesktop.org; Kaitai Struct has a formal spec; format gallery hosts Python parsing library). auditd binary log format is documented in the audit-userspace package. bash_history is plain text. systemd .service files are plain text INI-like. Cron tabs are plain text.
- **Wairz current gap severity**: **Major-to-critical**. wairz markets as "browser-based firmware reverse engineering" — Linux IS the dominant firmware audience. Yet wairz has ZERO coverage of journald binary logs (binary forensics is needed; journalctl is live-system only); ZERO coverage of auditd binary logs; ZERO walker for systemd persistence (`/etc/systemd/system/*.service`, `/etc/systemd/system/*.timer`, `~/.config/systemd/user/*`); shallow filesystem walk for `/var/spool/cron/crontabs/*`, `/etc/cron.*`, `/etc/crontab`. The Windows-coverage trifecta (BCD + ESP + MBR/VBR + SDB) is structurally analogous to the Linux trifecta (journald + auditd + systemd-timer/cron) — and the Linux trifecta has MORE addressable firmware volume.
- **Differentiation opportunity**: **Very large.** Velociraptor and Elastic dominate live Linux-endpoint forensics; Autopsy covers post-mortem but at a low level of abstraction. NO competitor offers cross-firmware aggregation across journald log records ("this MESSAGE_ID appears in N firmware images = supply-chain pattern"), and NO competitor offers MCP-callable Linux persistence triage. The wairz pattern (inner/outer/safe runner Rule #39, JSONB normaliser Rule #35c, DB CHECK + Pydantic Literal Rule #33.c, MCP `lookup_<artifact>` cross-firmware aggregation Rule #25 single-slice commits) is DIRECTLY portable from the Windows walkers. systemd persistence is MITRE T1543.002 (Create or Modify System Process: Systemd Service) — high-priority technique with no good OSS firmware-static-analysis coverage. bash_history correlation across firmware images would surface supply-chain operator commands (e.g., "vendor pushed this firmware with `wget http://staging-fileserver.internal/...` baked in"). systemd-timer + cron walker mirrors the Windows scheduled-tasks walker shipped in η.
- **Competitive parity rating**: **HIGH** (highest of all 6 candidates ranked here)
- **One-sentence rationale**: Linux is wairz's dominant audience, the systemd/journald/auditd persistence stack is the structural Linux mirror of the Windows trifecta wairz just shipped, and no competitor offers MCP-callable cross-firmware Linux persistence aggregation — this closes the most strategically important gap in the wairz coverage map.

---

### 6. ADJACENCY PICK B — Container artifact extraction (OCI image-spec + runc state + Docker layer FS)

Container firmware images have become a real upload category (k8s edge appliances, OCI-shipped IoT firmware, container-based router OSes). Wairz currently treats container images as filesystem extracts; there's no first-class OCI walker, no manifest parsing, no layer-diff analysis, no runc state extraction.

- **Coverage by competing platforms** (artifact × tool):

  | Tool | OCI manifest | Layer extraction | Layer diff | runc state | CRIU checkpoints |
  |------|--------------|------------------|------------|------------|------------------|
  | Dive | YES (TUI) | YES | YES | NO | NO |
  | Docker CLI (`save`/`export`/`diff`) | Partial | YES | YES | YES (`docker inspect`) | NO |
  | Podman | YES | YES | YES | YES | YES (via `podman container checkpoint`) |
  | crit (CRIU) | NO | NO | NO | NO | YES (mountpoints, bind mounts, upperDir) |
  | Trivy | YES (vuln scan layers) | YES | NO | NO | NO |
  | Syft / Grype | YES (SBOM per layer) | YES | NO | NO | NO |
  | Velociraptor | Partial (collects via path) | NO | NO | NO | NO |
  | KAPE | NO | NO | NO | NO | NO |
  | Autopsy | NO native | NO | NO | NO | NO |
  | Plaso | NO | NO | NO | NO | NO |
  | Volatility 3 | NO | NO | NO | NO | YES (memory in CRIU checkpoint) |
  | Cyber Triage | Partial | NA | NA | NA | NA |

- **Format documentation**: Fully public. OCI Image Specification (manifest.json, config.json, blobs/sha256/* layout) and OCI Runtime Specification (config.json, hooks, state.json). runc state is JSON. CRIU checkpoints are documented in the CRIU project. Layer tarballs are gzipped tar with diff semantics.
- **Wairz current gap severity**: **Moderate**. Container-image firmware uploads exist today but are a minority of wairz's load. Existing wairz coverage (filesystem walk, binary analysis, SBOM via existing services) gets most of the value already — wairz can already extract a container layer and walk it as a normal filesystem. The GAP is: (a) no manifest-level metadata (no `image_config`, `os/arch`, `created`, `history` walker), (b) no layer-diff cross-firmware analysis ("this layer-digest appears in N firmware images = base-image fingerprint"), (c) no CRIU-checkpoint state extraction (rare in firmware context).
- **Differentiation opportunity**: Moderate. Trivy / Syft / Grype already do per-layer vuln + SBOM analysis — but at a different angle (CVE matching, not forensic walker). Dive is TUI-only, no programmatic access. The wairz pattern would shine on (a) cross-firmware layer-digest aggregation — surfaces base-image reuse across vendor lineups; (b) MCP-callable `lookup_oci_base_image` exposing "which OCI base image variants appear across uploaded firmware". The persona-driven angle is real: an OCI-shipped router firmware where vendor uses a stale Alpine base would surface as "this firmware uses Alpine 3.14 which has N CVEs". But existing wairz CVE matching already does most of this; the differentiation is incremental, not category-creating.
- **Competitive parity rating**: **MEDIUM**
- **One-sentence rationale**: Real gap (no OSS forensic tool does cross-firmware container-image layer-digest aggregation with MCP exposure), but existing wairz filesystem-walk + SBOM coverage gets most of the value already, and the audience is a minority of uploads — promote if container-OS firmware uploads become a frequent ask.

---

## Synthesis

### Ranking ALL 6 candidates (4 carryovers + 2 adjacency picks)

By competitive-parity-gap × differentiation-opportunity × audience-fit:

| Rank | Candidate | Parity Rating | Audience Fit | Differentiation | Verdict |
|------|-----------|---------------|--------------|-----------------|---------|
| 1 | Linux mirror (journald + auditd + bash_history + systemd persistence) | **HIGH** | DOMINANT (Linux is wairz's biggest audience) | Category-creating (cross-firmware journald aggregation, MCP-callable Linux persistence) | **SHIP ι.1 — must-have for credibility** |
| 2 | EFS DDF/DRF | **MEDIUM-LOW** | Minor-to-moderate (rises if endpoint-disk-image uploads grow) | Real (EZTools gap, MCP triage exposure) | **SHIP ι.2 (lite) — endpoint completeness** |
| 3 | Container artifact extraction (OCI + runc + layer FS) | **MEDIUM** | Minority but growing | Modest (incremental over Trivy/Syft) | **SHIP ι.3 (manifest+layer-diff only)** |
| 4 | EVT pre-Vista (legacy XP/2003) | **LOW** | Niche (ICS/medical/CE only) | Narrow (1-day EVTX-walker adapter) | DEFER — promote if XP-embedded targets surge |
| 5 | ETL Event Tracing | **LOW** | Minor for firmware | Substantial (dissect.etl is the only Python option) | DEFER — wrong audience lane |
| 6 | Volatility 3 + hibernate.sys PAIRED | **LOW** | Out-of-audience (runtime not firmware) | Tiny (Vol3 + MemProcFS already dominant, MemProcFS shipping MCP) | DEFER indefinitely |

### Top 3 picks for Phase ι by competitive value

**1. ι.A = Linux mirror coverage (journald + auditd + bash_history + systemd persistence)** — **SHIP**

- **Which competitors support it, and what they MISS**: Velociraptor has `Linux.Forensics.Journal` and `Linux.Detection.Persistence` artifacts but is a LIVE-endpoint tool (requires running agent on target); it does NOT do offline firmware-image triage. Plaso has partial journald support (no first-class plugin as of 20260427 release); does NOT do cross-firmware aggregation. Autopsy has Linux artifact module; no MCP, no LLM, no aggregation. Elastic Security Labs has the conceptual coverage but it's a SaaS endpoint product, not a firmware-RE platform. **The gap wairz fills**: NO competitor offers offline static-analysis-of-firmware-images for the Linux persistence stack (journald binary parser + auditd binary + systemd-timer/cron walker + bash_history correlation) with MCP-callable cross-firmware aggregation.
- **Wairz's specific differentiator**: (a) MCP tools `lookup_journald_messages`, `lookup_systemd_persistence`, `lookup_cron_persistence`, `lookup_bash_history` exposing aggregated findings across N firmware images; (b) DB CHECK constraint + Pydantic Literal + frontend union all aligned per Rule #25 single-slice; (c) reuse of inner/outer/safe runner triplet (Rule #39) means each walker ships in 3-5 commits per Rule #25; (d) Linux-host firmware is wairz's DOMINANT upload audience.
- **Verdict**: **Must-have for credibility.** Without it, wairz is structurally behind its own audience expectation — the platform was MARKETED as a Linux firmware RE tool but has shallow Linux persistence coverage; the Windows trifecta of Phases η+θ accidentally inverted the audience map, and ι.A corrects it.

**2. ι.B = EFS DDF/DRF metadata parser (lite — parse-only, no DPAPI decrypt)** — **SHIP**

- **Which competitors support it, and what they MISS**: NTFSTool is the closest free competitor (parses $EFS, exports PKCS12, can decrypt with .pfx) — but is single-binary CLI with no LLM integration. Microsoft `efsinfo`/`cipher` is live-system only. Volatility 3 has partial DPAPI but not $EFS. EZTools has NO coverage (gap). Elcomsoft is commercial closed-source. **The gap wairz fills**: EZTools has a genuine EFS gap; wairz becomes the only OSS LLM-callable EFS-metadata-triage tool, surfacing "this file is encrypted, here are the user SIDs that can decrypt it" as structured findings.
- **Wairz's specific differentiator**: (a) MCP tool `lookup_efs_ddf` with cross-firmware aggregation ("this user SID appears as DDF on N firmware images = supply-chain operator account"); (b) Pydantic Literal for windows source values per Rule #33.c; (c) FOR NOW — parse-only, no decrypt. The DPAPI master-key recovery rabbit hole is explicitly out-of-scope for ι.B and would be a follow-on phase if endpoint-disk-image audience grows; (d) wairz's existing NTFS parser pipeline (η $MFT walker) sets up the $EFS attribute parser at low marginal cost.
- **Verdict**: **Nice-to-have for completeness.** Useful triage value; closes a real EZTools gap; modest engineering cost; promote if endpoint-disk-image audience grows.

**3. ι.C = Container artifact extraction (OCI manifest + layer-digest aggregation)** — **SHIP (scoped lite)**

- **Which competitors support it, and what they MISS**: Trivy, Syft, Grype do per-layer vuln + SBOM analysis (overlap with wairz existing CVE matching). Dive is TUI-only, no programmatic API. Velociraptor / KAPE / Autopsy do not handle OCI images natively. **The gap wairz fills**: NO OSS forensic tool offers cross-firmware layer-digest aggregation with MCP exposure ("this base-image digest appears across N firmware images = vendor reuse fingerprint"); MCP tool `lookup_oci_base_image` is unique.
- **Wairz's specific differentiator**: (a) Cross-firmware layer-digest aggregation (the canonical wairz pattern); (b) MCP-callable manifest metadata (`image_config`, `os/arch`, `created`, `history` entries) surfacing build provenance findings; (c) integration with existing wairz CVE matching to map "base image's CVE-exposed packages" across N images; (d) NOT competing with Trivy/Syft on vuln matching (that's already wairz's existing service); explicitly competing on PROVENANCE + CROSS-FIRMWARE aggregation.
- **Verdict**: **Nice-to-have for completeness.** Real gap, real differentiator, but lower-priority than ι.A; ship as a 3-4 commit Rule #25 sequence (manifest walker + layer-digest walker + MCP tool + cross-stack alignment).

### Top 2 picks to DEFER

**1. Volatility 3 + hibernate.sys PAIRED (#1)** — **DEFER indefinitely**

- **Why defer**: Out-of-audience (runtime/IR artifact, not firmware artifact). Vol3 + MemProcFS already dominate the space; MemProcFS is already shipping an MCP server (skywork.ai page exists). Wairz would be entering contested space with structural upload-model conflict — wairz expects "upload firmware blob", Vol3 expects "upload memory dump". Adding hibernate.sys parsing only routes back to Vol3, which routes to MemProcFS, which has MCP already. The differentiation wedge collapses.
- **When to revisit**: If wairz pivots toward incident-response artifact triage as a strategic direction. Not on the current roadmap.

**2. ETL (#4)** — **DEFER**

- **Why defer**: Audience-lane mismatch. ETL is primarily a live-system telemetry stream; offline ETL files appear rarely in firmware images. dissect.etl exists as the OSS reference (Fox-IT) — wairz would be wrapping it, not creating. The MCP-callable angle is interesting but the audience for cross-firmware ETL aggregation is narrow. Engineering cost is moderate-to-high (ETL container is multi-block multi-buffer kernel/user/private logger; provider-manifest resolution requires registry hive cross-reference).
- **When to revisit**: If a specific user request surfaces (e.g., diagnostic-capture-in-firmware analysis for medical/ICS targets), OR if wairz pivots toward IR artifact triage.

### Wairz-leads-the-field highlight

**ι.A (Linux mirror) is the standout — it's the highest-value gap by every dimension wairz cares about**: dominant audience, no competitor offers offline firmware-image static analysis with cross-firmware MCP aggregation for the Linux persistence stack, the engineering pattern (inner/outer/safe runner + JSONB normaliser + DB CHECK alignment) is fully repeatable from η+θ. The Phases η+θ Windows-coverage campaign accidentally created a Linux-coverage debt; ι.A pays it down. Without ι.A wairz is structurally behind its own audience expectation. With ι.A wairz becomes the only OSS platform that can statically analyze BOTH Windows AND Linux firmware-image persistence stacks through an LLM-callable interface — a category-creating coverage map.

### Recommended Phase ι scope

**ι.A = Linux mirror coverage** (~3 sub-phases, ~12-15 commits per Rule #25):
- **ι.A.1 = journald binary log walker** (parse-only; Kaitai Struct spec available; MCP `lookup_journald_messages` cross-firmware)
- **ι.A.2 = systemd persistence walker** (.service / .timer / .socket / .path files; MCP `lookup_systemd_persistence`; MITRE T1543.002 mapping)
- **ι.A.3 = bash_history + cron + auditd walker** (combined trifecta; MCP `lookup_linux_persistence`; cross-firmware operator-account fingerprint aggregation)

**ι.B = EFS DDF/DRF metadata walker** (parse-only, no DPAPI decrypt; ~3-4 commits per Rule #25):
- Reuses η $MFT walker for $EFS attribute access
- MCP `lookup_efs_ddf` with user-SID cross-firmware aggregation

**ι.C = OCI container artifact walker** (manifest + layer-digest; ~3-4 commits per Rule #25):
- Manifest walker (image_config, os/arch, history)
- Layer-digest cross-firmware aggregation
- MCP `lookup_oci_base_image`

**Expected outcome:** wairz becomes the only OSS firmware platform with end-to-end Windows + Linux + container static-analysis coverage through an LLM-callable interface, with cross-firmware persistence + provenance aggregation that no competitor offers. The Linux mirror closes the dominant-audience credibility gap; EFS and OCI close completeness gaps that endpoint-disk-image and container-firmware audiences need.

---

## Sources

- [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
- [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html)
- [Volatility Foundation](https://volatilityfoundation.org/the-volatility-framework/)
- [MagnetForensics Hibr2Bin GitHub](https://github.com/MagnetForensics/Hibr2Bin)
- [Decompressing hiberfil.sys Win8+ (Ponder The Bits)](https://ponderthebits.com/2017/07/decompressing-and-extracting-artifacts-from-windows-8-server-2012-hibernation-files/)
- [MemProcFS GitHub (Ulf Frisk)](https://github.com/ufrisk/MemProcFS)
- [MemProcFS MCP Server (skywork.ai)](https://skywork.ai/skypage/en/unlocking-system-internals-memprocfs-mcp-server/1980472180219695104)
- [NTFSTool GitHub](https://github.com/thewhiteninja/ntfstool)
- [$EFS Attribute (NTFS.com)](http://ntfs.com/attribute-encrypted-files.htm)
- [EFS Internals (NTFS.com)](https://www.ntfs.com/internals-encrypted-files.htm)
- [Advanced EFS Data Recovery (Elcomsoft)](https://www.elcomsoft.com/aefsdr.html)
- [SANS GIAC EFS Forensic Analysis paper](https://www.giac.org/paper/gcfe/4010/forensic-analysis-encrypting-file-system/141180)
- [libevt GitHub (libyal)](https://github.com/libyal/libevt)
- [python-evt GitHub (Ballenthin)](https://github.com/williballenthin/python-evt)
- [Kaitai Windows EVT spec](https://formats.kaitai.io/windows_evt_log/python.html)
- [PerfView GitHub (Microsoft)](https://github.com/microsoft/perfview)
- [dissect.etl GitHub (Fox-IT)](https://github.com/fox-it/dissect.etl)
- [PerfView TraceEvent Library docs](https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventLibrary.md)
- [systemd-journal Kaitai spec](https://formats.kaitai.io/systemd_journal/python.html)
- [python-systemd GitHub](https://github.com/systemd/python-systemd)
- [Velociraptor Linux.Forensics.Journal](https://docs.velociraptor.app/artifact_references/pages/linux.forensics.journal/)
- [Velociraptor Artifact Reference](https://docs.velociraptor.app/artifact_references/)
- [Forensic Analysis of Linux Journals (Abhiram)](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Hunting for Persistence in Linux Part 3 (Pberba)](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/)
- [Hunting for Persistence in Linux Part 1 (Active Countermeasures)](https://www.activecountermeasures.com/hunting-for-persistence-in-linux-part-1-auditd-sysmon-osquery-and-webshells/)
- [Elastic Security Labs persistence primer](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)
- [dissect framework GitHub (Fox-IT)](https://github.com/fox-it/dissect)
- [dissect.evidence GitHub (Fox-IT)](https://github.com/fox-it/dissect.evidence)
- [MacPersistenceChecker GitHub](https://github.com/Pinperepette/MacPersistenceChecker)
- [Mac-Triage GitHub](https://github.com/a1l4m/Mac-Triage)
- [Aftermath GitHub (Jamf)](https://github.com/jamf/aftermath)
- [Aftermath Jamf docs](https://trusted.jamf.com/docs/aftermath-incident-response-macos)
- [Velociraptor MacOS.Forensics.FSEvents](https://docs.velociraptor.app/artifact_references/pages/macos.forensics.fsevents/)
- [Velociraptor Linux.Forensics.Targets](https://docs.velociraptor.app/exchange/artifacts/pages/linux.forensics.targets/)
- [OCI Image and Runtime Specifications (OneUptime)](https://oneuptime.com/blog/post/2026-02-08-how-to-understand-oci-image-and-runtime-specifications/view)
- [Container Forensics (DeepWiki)](https://deepwiki.com/vonderchild/digital-forensics-lab/5.2-container-forensics)
- [OCI Image Specification (Quarkslab)](https://blog.quarkslab.com/digging-into-the-oci-image-specification.html)
- [Docker Forensics Threat Hunting (Khanna)](https://medium.com/@deepanshu_khanna/docker-forensics-threat-hunting-like-a-pro-inside-containers-525d776cd8cf)
- [ConPoint Container Checkpoints (ACM)](https://dl.acm.org/doi/fullHtml/10.1145/3664476.3670895)
- [Plaso Supported Formats](https://plaso.readthedocs.io/en/latest/sources/Supported-formats.html)
- [Plaso Parsers and Plugins](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html)
- [Reviewing macOS Unified Logs (Google Cloud)](https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/)
- [Swisscom ArtifactCollectionMatrix](https://github.com/swisscom/ArtifactCollectionMatrix)
