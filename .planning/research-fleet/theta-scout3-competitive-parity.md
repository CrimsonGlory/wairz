# Phase θ Competitive Parity Research — Scout 3

**Lens:** RE/forensic-platform competitive parity for the 8 θ-deferred Windows-artefact candidates.
**Date:** 2026-05-11
**Author:** Scout 3 (research-fleet wave, parallel to Scouts 1 & 2)
**Wairz baseline (post-η):** NTFS $MFT, scheduled-tasks, LNK, BYOVD LOLDrivers, PowerShell EID4104, Authenticode/DBX, registry hive walker, EVTX, Amcache, Prefetch, SRUM.

---

### 1. WMI persistence (OBJECTS.DATA + INDEX.BTR + MAPPINGn.MAP)

- **Coverage by competing platforms**:
  - **EZTools** — no dedicated WMI repository parser (gap in the EZ suite).
  - **FireEye/Mandiant flare-wmi** (PyWMIPersistenceFinder, WMI-Parser) — public Python tools; the de-facto reference parser.
  - **Volatility 3** — `windows.registry.userassist` etc., but WMI repo parsing lives in the `windows.cmdline`-adjacent community plugins (`wmi_persistence` plugin from FireEye).
  - **Velociraptor** — `Windows.Persistence.PermanentWMIEvents` artifact (queries live WMI namespaces, not OBJECTS.DATA directly).
  - **KAPE** — collects the repo files via Target; relies on flare-wmi / external parser for analysis.
  - **Plaso** — `winevtx` / `winreg` plugins, but no first-class OBJECTS.DATA plugin.
- **Format documentation**: Reverse-engineered only. Mandiant's "There's something about WMI" whitepaper (2015) + flare-wmi source remain the authoritative reference. Microsoft does not publish CIM repository internals.
- **Wairz current gap severity**: **Major**. WMI persistence (T1546.003) is one of the most common modern fileless persistence techniques (ASEC, FIN7, APT29). Without it wairz misses a top-5 MITRE Enterprise persistence sub-technique on Windows firmware.
- **Differentiation opportunity**: NO competitor exposes OBJECTS.DATA parsing through an MCP/LLM interface. Wairz could ship `lookup_wmi_persistence` + cross-firmware aggregation (same `__EventConsumer` name across N firmware images = supply-chain indicator). flare-wmi is CLI-only and unmaintained since 2018.
- **Competitive parity rating**: **HIGH**
- **One-sentence rationale**: Closes a major persistence-coverage gap that even EZTools doesn't address, and the underdeveloped competitive landscape leaves room for wairz to lead on MCP-integrated WMI triage.

---

### 2. Boot chain artefacts (BCD store + MBR/VBR + ESP `.efi`)

- **Coverage by competing platforms**:
  - **EZTools** — no BCD parser; some MBR/VBR awareness in MFTECmd boot-sector handling.
  - **Microsoft `bcdedit`** — first-party but live-system only.
  - **Volatility 3** — limited; memory-resident BCD via `windows.registry.hivelist` but not offline ESP `.efi` parsing.
  - **UEFITool / chipsec** — ESP `.efi` extraction + analysis (chipsec is the de-facto Linux toolchain).
  - **Velociraptor** — `Windows.Detection.Bootkits` family; limited offline parsing.
  - **Wairz already has** UEFI module enumeration via `tools/uefi.py` (5 tools — list firmware volumes, modules, extract NVRAM).
  - **CHIPSEC** (Intel) — best-in-class for SMM / bootkit / UEFI analysis but no PE-level integration with non-UEFI Windows boot chain.
- **Format documentation**: Fully public — BCD is a registry hive (Microsoft Open Specifications), MBR/VBR documented in NT volume format spec, EFI executables are PE32+ (UEFI spec public).
- **Wairz current gap severity**: **Major**. Wairz already understands UEFI volumes (η framework) and signed PE chains (β.4 Authenticode + β.10 DBX). The BCD-store + ESP-cross-reference walker is the missing tier-1 boot-chain glue. Bootkit detection (BlackLotus, MoonBounce, FinFisher Vault7) lives in this gap.
- **Differentiation opportunity**: Wairz UNIQUELY combines BYOVD LOLDrivers signal + DBX revocation + Authenticode trust chain + UEFI volume parser. Adding BCD + ESP closes the loop: "is this firmware's boot chain consistent end-to-end?" — a question no other open-source tool answers in ONE query. CHIPSEC is UEFI-only; EZTools is OS-only; Velociraptor is detection-only; Wairz could be analysis-first.
- **Competitive parity rating**: **HIGH**
- **One-sentence rationale**: Existing UEFI + Authenticode + DBX + driver coverage means wairz is two artefacts away from being the only OSS platform that can statically analyze the complete UEFI-to-Windows-userland boot chain.

---

### 3. Volatility 3 integration (memory-dump triage)

- **Coverage by competing platforms**:
  - **Volatility 3** — IS the reference; 100+ Windows plugins (pslist, malfind, cmdline, netscan, hivelist, ssdt, callbacks, modscan, hollowfind).
  - **Rekall** (Google fork) — deprecated since 2020; volatility 3 absorbed momentum.
  - **MemProcFS** (Ulf Frisk) — alternative VFS-mounted memory analysis.
  - **Velociraptor** — collects memory dumps but defers analysis to Volatility.
  - **FLARE-VM** — bundles Volatility for malware analysis.
  - **KAPE** — collects but doesn't analyze memory.
- **Format documentation**: Memory dump formats (raw, crash, hibernation) are public; Volatility's profile system is open-source.
- **Wairz current gap severity**: **Negligible-to-minor** for FIRMWARE-RE focus. Memory dumps are a runtime/IR artefact, not a firmware artefact. Wairz is a firmware reverse-engineering platform — memory analysis is genuinely out-of-scope unless wairz pivots to live-IR.
- **Differentiation opportunity**: Limited. Volatility 3 is so dominant that any wairz integration would be a thin wrapper. The ONE differentiation: if wairz integrated Volatility output INTO its cross-firmware finding aggregation (e.g., correlate memory-resident driver names from a running snapshot back to BYOVD LOLDrivers hits in the firmware blob), that's novel — but it requires the user to ALSO provide a memory dump alongside firmware, which breaks the wairz upload model.
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Volatility 3 owns the space, the format alignment is poor (firmware-on-disk vs runtime-memory), and this would dilute wairz's firmware-static-analysis focus.

---

### 4. Shim .sdb (Application Shim, T1546.011)

- **Coverage by competing platforms**:
  - **EZTools** — SDBexplorer (Eric Zimmerman) parses .sdb directly; AppCompatCacheParser handles registry side.
  - **Microsoft `sdbinst`** + Compatibility Administrator — first-party but live-system.
  - **Mandiant `python-sdb`** — Python parser, public on GitHub (willi-ballenthin).
  - **Volatility 3** — no first-class .sdb plugin; AppCompatCache via registry.
  - **Velociraptor** — `Windows.Sys.AppCompatCache` (registry side); .sdb file collection via Target.
  - **KAPE** — collects sysmain.sdb, custom .sdb files; relies on SDBexplorer for analysis.
- **Format documentation**: Reverse-engineered. Mandiant + Jonathan Tomczak ("Shimming for the Win", 2014) papers; python-sdb source is reference impl. Microsoft does not publish the binary .sdb schema.
- **Wairz current gap severity**: **Minor**. Shim DB persistence (T1546.011) is a known APT technique (APT41, Hidden Cobra) but lower-frequency than WMI / Scheduled Tasks. Wairz already covers scheduled tasks + AppCompatCache via Amcache parser.
- **Differentiation opportunity**: Modest. python-sdb is the reference; wairz would re-implement. The MCP-integration angle (lookup_shim_database with cross-firmware aggregation) is interesting but the artefact's prevalence is lower than WMI.
- **Competitive parity rating**: **MEDIUM**
- **One-sentence rationale**: Closes a real (T1546.011) gap and EZTools covers it well, but the gap is narrower than WMI or boot-chain — solid second-tier addition.

---

### 5. EFS DDF/DRF (Encrypted File System)

- **Coverage by competing platforms**:
  - **EZTools** — no dedicated EFS parser (gap).
  - **Microsoft `efsinfo`, `cipher`** — first-party live tools; show DDF (Data Decryption Field) + DRF (Data Recovery Field) header data.
  - **Volatility 3** — `windows.dpapi` family covers DPAPI keys; EFS-specific support is partial.
  - **DPAPIck**, **mimikatz** (`dpapi::masterkey`) — extract DPAPI master keys; downstream EFS decryption requires combined tooling.
  - **Velociraptor** — collects $EFS streams via NTFS artifact; analysis defers to external tools.
  - **Plaso** — no first-class EFS plugin.
- **Format documentation**: Microsoft Open Specs document NTFS $EFS attribute (0x100) + DDF/DRF structures publicly (MS-FSCC, MS-EFSR). DPAPI internals reverse-engineered by Bursztein & Picod.
- **Wairz current gap severity**: **Minor-to-major** depending on target. For consumer/embedded firmware → minor. For enterprise Windows endpoint forensics or supply-chain artefacts containing per-user encrypted data → major. Wairz's typical firmware doesn't carry $EFS-protected files; this is more of an endpoint-forensics ask.
- **Differentiation opportunity**: Limited unless wairz also implements DPAPI master-key recovery — which is a rabbit hole (requires user creds, SYSTEM keys, optional domain DPAPI). Standalone EFS header parsing without decryption is low-value.
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Format is public and competitors don't cover it cleanly, but the artefact appears rarely in firmware-shaped uploads and a half-implementation (parse-but-no-decrypt) is forensically weak.

---

### 6. EVT (pre-Vista event log)

- **Coverage by competing platforms**:
  - **EZTools** — EvtxECmd handles EVTX (post-Vista); separate `evtparse` / `evtwalk` (Harlan Carvey) for legacy EVT.
  - **Volatility 3** — `windows.evtlogs` plugin specifically for the LEGACY EVT format (XP/2003 era).
  - **Plaso/log2timeline** — has `winevt` parser for legacy EVT.
  - **python-evt** (Willi Ballenthin) — public reference parser.
  - **KAPE** — collects .evt files; relies on Plaso/Carvey tooling.
  - **Velociraptor** — minimal legacy EVT support.
- **Format documentation**: Fully public. Microsoft EVT file format (binary, fixed-size records) documented in MS-EVEN; Carvey + Ballenthin papers exhaustive.
- **Wairz current gap severity**: **Negligible**. Pre-Vista (XP, Server 2003) targets are vanishing in production firmware. ICS/medical/legacy embedded Windows CE/XP-Embedded systems are the remaining audience.
- **Differentiation opportunity**: Very narrow. Wairz's ε.1.b EVTX walker could be extended with a legacy-EVT adapter at low cost (format is simpler than EVTX), giving wairz EVT + EVTX parity. The MCP cross-firmware angle: detect XP-embedded firmware via the presence of .evt files = supply-chain age indicator.
- **Competitive parity rating**: **LOW** (with a kicker for XP-embedded ICS detection)
- **One-sentence rationale**: Format is fading from production relevance; wairz's audience is unlikely to encounter it often, and the existing EVTX walker provides 99% of the value.

---

### 7. ETL (Event Tracing for Windows)

- **Coverage by competing platforms**:
  - **Microsoft `tracerpt`, `pktmon`, `netsh trace`, PerfView** — first-party live tools; PerfView is open-source.
  - **EZTools** — NO ETL parser. EvtxECmd is EVTX-only.
  - **Plaso** — no first-class ETL parser.
  - **Velociraptor** — collects ETL files; relies on tracerpt for parsing.
  - **etl2pcapng** (Microsoft) — converts ETL with network captures to PCAP.
  - **Volatility 3** — no ETL support.
  - **mandiant/PerfView analysts** — depend on PerfView GUI.
  - **Sleuth Kit, KAPE** — collect but don't parse.
- **Format documentation**: Microsoft documents ETW providers (manifests are XML, publicly registered) and the ETL container format (MS-DOCS), but the binary container is sufficiently complex that no open-source full-featured ETL parser exists outside Microsoft's libtraceevent equivalents.
- **Wairz current gap severity**: **Negligible-to-minor** for offline firmware. ETL is primarily a live-system telemetry stream. Saved ETL files appear mainly in diagnostic captures (DiagTrack, AutoLogger configs), not in shipping firmware.
- **Differentiation opportunity**: Substantial IF wairz pivots toward incident-response artefact triage — no OSS tool offers good offline ETL parsing. But for firmware-RE this is far outside the core lane.
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Competitors don't cover it well, but the artefact rarely appears in firmware-shaped uploads, so the parity-gap math says "not worth the engineering" for wairz's audience.

---

### 8. hibernate.sys (Windows hibernation file)

- **Coverage by competing platforms**:
  - **Volatility 3** — `hibernation` address space; converts hiberfil.sys → raw via `windows.hibernation`.
  - **Hibr2Bin (Comae/MoonSols/Magnet)** — de-facto conversion tool, now in Magnet RAM Capture suite.
  - **Velociraptor** — collects hiberfil.sys; relies on Volatility for analysis.
  - **FLARE-VM** — bundles Volatility + Hibr2Bin.
  - **EZTools** — no hibernation support (out of scope).
  - **rekall (deprecated)** — had hibernation handling.
  - **Autopsy** — collects but doesn't decompress.
- **Format documentation**: Reverse-engineered. Matthieu Suiche ("Sandman" project, 2008) is the canonical reference; Microsoft does not publish the Xpress-compressed hibernation page-table format.
- **Wairz current gap severity**: **Negligible** for firmware-RE focus. hiberfil.sys is a runtime artefact captured from a powered-on Windows machine; it doesn't appear in firmware images. (Similar to Volatility integration — it's a live/IR artefact, not a firmware artefact.)
- **Differentiation opportunity**: Essentially zero. Even if wairz parsed hiberfil.sys, the downstream analysis is "now you have a memory dump" — which routes back to Volatility 3 (candidate #3, already rated LOW).
- **Competitive parity rating**: **LOW**
- **One-sentence rationale**: Hibernation file is firmware-irrelevant; analyzing it routes back to Volatility, which is already a LOW-priority integration for wairz's focus.

---

## Synthesis

### Top 3 candidates for Phase θ

**Ranked by competitive-parity HIGH/MEDIUM/LOW scoring + audience-fit + wairz-differentiation potential:**

1. **WMI persistence (OBJECTS.DATA)** — **SHIP θ.1**
   - The clearest win. MITRE T1546.003 is in every modern APT playbook (FIN7, APT29, Lazarus). EZTools has NO coverage. flare-wmi is unmaintained since 2018. Wairz already has the four prerequisites: registry hive walker (γ.4), MCP tool framework, JSONB normaliser pattern (Rule #35c), inner/outer/safe runner triplet (Rule #39). Adding `lookup_wmi_persistence` + `_extract_wmi_consumers` walker is a clean 1-week ship. **MCP differentiation is unique** — no competing tool exposes WMI persistence triage through an LLM-callable interface, and cross-firmware aggregation ("this `ActiveScriptEventConsumer` name appears in N firmware images") is a wairz-only capability.

2. **Boot chain artefacts (BCD + MBR/VBR + ESP `.efi`)** — **SHIP θ.2**
   - Wairz is uniquely positioned: η framework (UEFI volumes, BYOVD LOLDrivers, DBX revocation, Authenticode chains) plus β.4/β.10 trust-anchor discipline (Rule #37) means wairz has 80% of the boot-chain primitives already. Adding BCD-store parser (registry-hive shape — γ.4 walker is the template) + MBR/VBR + ESP-`.efi`-correlation produces "is this firmware's boot chain end-to-end consistent?" — a question NO open-source tool answers in one query today. CHIPSEC = UEFI-only; EZTools = OS-only; Volatility = memory-only. **Wairz becomes the only OSS static-analysis platform for the complete UEFI→Windows-userland boot chain.** Bootkit detection (BlackLotus, MoonBounce) lives in this gap.

3. **Shim .sdb (T1546.011)** — **SHIP θ.3 (or defer to ι)**
   - Solid third pick. python-sdb is the existing reference; format is reverse-engineered but stable. Lower-prevalence than WMI but a recognized APT technique. Cost is modest because the inner/outer/safe runner triplet + DB CHECK constraint + Pydantic Literal scaffolding from η.D.E carries over directly. **Acceptable trade-off:** if θ has bandwidth for only TWO, push Shim .sdb to ι and double-down on WMI + Boot-chain depth (e.g., add UEFI-DBX firmware-image cross-reference to the boot-chain walker).

### Wairz-leads-the-field highlight

**WMI persistence + Boot chain are BOTH candidates where wairz can lead the field:**

- **WMI:** Combined with the registry walker (γ.4) and MCP exposure, wairz can produce "rank WMI persistence findings across N firmware images by ActiveScriptEventConsumer name" — a query that today requires a forensic analyst to run flare-wmi N times manually and aggregate by hand. Cross-firmware aggregation through the existing `analysis_cache` JSONB pattern is a category-creating capability.

- **Boot chain:** No other OSS tool combines UEFI-volume parsing + DBX revocation + Authenticode + BYOVD driver detection + (added) BCD + MBR/VBR + ESP `.efi` correlation. The closest commercial analog is Eclypsium / Binarly REFI — both proprietary, $$$. Open-source firmware bootkit-hunting today is a patchwork; wairz could be the unified answer.

### Candidates explicitly to defer or drop

- **Volatility 3 integration (#3), hibernate.sys (#8):** Out of audience-lane (runtime/IR, not firmware). Defer indefinitely unless wairz pivots toward incident-response.
- **EFS DDF/DRF (#5):** Format public; competitor coverage is uniformly weak; but firmware uploads rarely carry $EFS-protected files. Defer unless a specific user request surfaces.
- **EVT (#6):** Fading-relevance format; existing EVTX walker covers 99% of audience need. Defer; can be added as a 1-day adapter to the EVTX walker if XP-embedded ICS targets become a frequent ask.
- **ETL (#7):** Format complexity is high; offline ETL is rare in firmware; competitors don't cover it but the parity-gap math doesn't justify wairz building it. Defer.

### Recommended Phase θ scope

**θ.A = WMI persistence walker** (~5-7 commits per Rule #25, inner/outer/safe runner per Rule #39, JSONB normaliser per Rule #35c, MCP tool `lookup_wmi_persistence` per η.D.F precedent).

**θ.B = Boot-chain walker triplet** — three sub-phases:
- **θ.B.1 = BCD-store parser** (registry hive shape, reuse γ.4 walker)
- **θ.B.2 = MBR/VBR parser** (binary structure, simple)
- **θ.B.3 = ESP `.efi` correlation** (cross-reference η UEFI volume tools + β.4 Authenticode chain)

**θ.C = Shim .sdb walker** (optional; defer to ι if θ.A + θ.B fill the campaign).

**Expected outcome:** wairz becomes the only OSS firmware platform with end-to-end Windows boot-chain static analysis (θ.B) AND the only platform exposing WMI persistence triage through an LLM-callable interface (θ.A). Both are category-creating, not parity-closing.
