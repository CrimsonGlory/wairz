import uuid
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel

# Per CLAUDE.md Rule #33 .c — Pydantic Literal for the verdict-bearing
# Windows sources β.12 + γ.8 emit. Used at the call boundary inside
# ``FindingService.emit_pe_signature_findings`` (β.12c authenticode
# chain runner) and ``FindingService.emit_registry_findings_from_walk``
# / ``emit_driver_findings_from_extract`` (γ.8) so the source-string
# constants are typo-checked at construction time. The DB-side
# enforcement is the matching ``ck_findings_source`` CHECK from
# alembic revisions ``c5b6a7d8e9f0`` (β.12a, +authenticode/+dbx) and
# ``c9d0e1f2a3b4`` (γ.7, +registry_persistence/+inf/+driver_imports).
WindowsFindingSource = Literal[
    "windows_authenticode",
    "windows_dbx_revoked",
    "windows_registry_persistence",
    "windows_inf",
    "windows_driver_imports",
    # Phase δ.8 — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by:
    # - δ.6 R2R-stomping classifier → Finding rows for review.
    # - Future capa-on-IL emitter → capability badges per .NET assembly.
    "windows_r2r_stomp",
    "windows_il_capa",
    # Phase ε.1.b.4 — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the EVTX walk emit hook
    # (``finding_service.emit_evtx_findings_from_walk``) for the
    # forensic-timeline trio (Persona-E #4):
    # - Sysmon EID 1 (process create) → windows_sysmon_proc_create.
    # - Security EID 4624 (logon success) → windows_logon_success.
    # - Security EID 4625 (logon failure) → windows_logon_failure.
    "windows_sysmon_proc_create",
    "windows_logon_success",
    "windows_logon_failure",
    # Phase ζ.1 — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the Amcache finding-emit
    # hook (``finding_service.emit_amcache_findings_from_walk``) for
    # InventoryApplicationFile entries on parsed AmCache.hve registry
    # extracts (γ.4 already walks the hive; ζ.1 layers Finding emission
    # on top without a new walker — Persona-E program-installation
    # history, LOW confidence baseline; threat-feed correlation defers
    # to a future ζ.X phase).
    "windows_amcache_install",
    # Phase ζ.2.C — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the Prefetch finding-emit
    # hook (``finding_service.emit_prefetch_findings_from_walk``) for
    # every ``WindowsPrefetchRecord`` row produced by the ζ.2.B walker —
    # Persona-E application-execution history. LOW confidence baseline;
    # threat-feed correlation (file path / executable hash) deferred to
    # a future ζ.X phase. Companion to windows_amcache_install (also
    # installation/execution-history baseline at LOW).
    "windows_prefetch_execution",
    # Phase ζ.3.C — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the SRUM finding-emit
    # hook (``finding_service.emit_srum_findings_from_walk``) for the
    # network_data_usage / network_connectivity (network_activity) and
    # application_resource_usage (application_runtime) record types
    # produced by the ζ.3.B walker — Persona-E ~30-60 day per-app
    # network + runtime history. LOW confidence baseline; threat-feed
    # correlation is deferred to a future ζ.X phase. Companions to
    # windows_amcache_install + windows_prefetch_execution (all program-
    # history baselines at LOW).
    "windows_srum_network_activity",
    "windows_srum_application_runtime",
    # Phase η.E — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by η.E's extension to ε's
    # ``emit_evtx_findings_from_walk`` per-record loop, branching on
    # PowerShell EIDs 4103 (Module/Pipeline) and 4104 (ScriptBlock) —
    # Persona-E LOLBin / fileless-execution detection. Confidence
    # tier mapping is heuristic-driven:
    # - LOW (Confidence.low) — EID 4103 module-load events.
    # - MEDIUM (Confidence.medium) — EID 4104 plain ScriptBlock events.
    # - HIGH (Confidence.high) — EID 4104 with obfuscation indicators
    #   (base64 / EncodedCommand / -enc / Invoke-Expression /
    #   FromBase64String / `[char]` arrays).
    # Per intake D5, ONE Literal value covers the 4103/4104 EID pair
    # (the EID-specific metadata goes into the finding's evidence
    # rather than into separate Literal values per EID). 4105/4106
    # (Pipeline state-change) are NOISE — not emitted.
    "windows_powershell_script_block",
    # Phase η.B.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_scheduled_task_findings_from_walk`` for every
    # ``WindowsScheduledTask`` row produced by the η.B.C walker.
    # Confidence tier mapping is heuristic-driven:
    # - HIGH (Confidence.high) — Action contains encoded-PowerShell
    #   pattern (Qakbot signature: ``-EncodedCommand`` / ``-enc`` /
    #   ``FromBase64String`` / ``Invoke-Expression`` / ``[char[]]`` /
    #   ``DownloadString`` / ``IEX``).
    # - MEDIUM (Confidence.medium) — RunLevel=HighestAvailable AND
    #   non-system Author (Author NOT prefixed by "Microsoft").
    # - LOW (Confidence.low) — baseline review-candidate row.
    # Per intake style: ONE Literal value covers all 3 tiers (tier
    # metadata into the finding's confidence + evidence rather than
    # separate Literal values per tier).
    "windows_scheduled_task_persistence",
    # Phase η.C.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_lnk_findings_from_walk`` for every ``WindowsLnkRecord``
    # row produced by the η.C.C walker whose target / arguments shape
    # matches T1547.009 Shortcut Modification persistence indicators.
    # Confidence tier mapping is heuristic-driven:
    # - HIGH (Confidence.high) — target is a known script-host binary
    #   (cmd / cscript / wscript / powershell / pwsh / mshta / regsvr32
    #   / rundll32) AND arguments contain encoded-PowerShell pattern
    #   (Qakbot signature: ``-EncodedCommand`` / ``-enc`` /
    #   ``FromBase64String`` / ``Invoke-Expression`` / ``[char[]]`` /
    #   ``DownloadString`` / ``IEX``).
    # - MEDIUM (Confidence.medium) — target_path is non-Microsoft
    #   (NOT under \\Windows\\, %SystemRoot%, %windir%, C:\\Program Files\\
    #   Microsoft *, C:\\ProgramData\\Microsoft\\, etc.).
    # - LOW (Confidence.low) — baseline review-candidate row.
    # Per intake style: ONE Literal value covers all 3 tiers.
    "windows_lnk_abnormal_target",
    # Phase η.A.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_mft_findings_from_walk`` for every ``WindowsMftRecord`` row
    # produced by the η.A.C walker whose ads_streams + timestamp shape
    # matches MITRE ATT&CK persistence + anti-forensics indicators.
    #
    # windows_mft_ads_hidden_content — named ADS stream with size > 1 KB
    # (excludes benign Zone.Identifier MOTW tag at ~100 B). Confidence
    # tier mapping is heuristic-driven:
    # - HIGH (Confidence.high) — ADS size > 16 KB. ProcessHollower /
    #   Pegasus / generic AV-evasion drop pattern.
    # - MEDIUM (Confidence.medium) — ADS size 1 KB – 16 KB.
    #
    # windows_mft_timestomping — $SI mtime < $FN mtime. T1070.006
    # Indicator Removal: Timestomp. Confidence tier mapping:
    # - MEDIUM (Confidence.medium) — single timestomp pair detected.
    # - HIGH (Confidence.high) — ALL FOUR $SI timestamps older than
    #   ALL FOUR $FN timestamps. timestomp.exe rewrites the full tuple.
    "windows_mft_ads_hidden_content",
    "windows_mft_timestomping",
    # Phase η.D.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_byovd_findings_from_driver`` for every Windows driver blob
    # whose SHA256 (or Authenticode hash) matches a LOLDrivers record
    # (``magicsword-io/LOLDrivers``, Apache-2.0, bundled per Rule #37
    # at backend/ms-anchors/loldrivers.json). The lookup pipeline lives
    # in ``app.services.loldrivers_lookup_service.lookup_driver_byovd``.
    #
    # windows_byovd_driver — Bring-Your-Own-Vulnerable-Driver fingerprint.
    # Confidence tier mapping is heuristic-driven by category + CVE:
    # - HIGH (Confidence.high) — category=``malicious``, OR category=
    #   ``vulnerable driver`` AND ≥1 CVE association. The malicious case
    #   is unambiguous compromise; the CVE-associated case carries
    #   public-known-exploit weight beyond stale-driver flag.
    # - MEDIUM (Confidence.medium) — category=``vulnerable driver`` with
    #   no CVE association. Surfaces stale-driver BYOVD risk without
    #   over-triaging legitimate-but-stale embedded firmware.
    # Per intake style: ONE Literal value covers all tiers.
    "windows_byovd_driver",
    # Phase θ.A.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_bcd_findings_from_walk`` for every ``WindowsBcdEntry`` row
    # produced by the θ.A.C walker whose anomaly_flags shape matches
    # T1542.003 Pre-OS Boot: Bootkit indicators (BlackLotus, Bootkitty,
    # CosmicStrand, MoonBounce).
    #
    # windows_bcd_suspicious_path — image_path NOT under any Microsoft-
    # vetted prefix (Windows\\, Boot\\, EFI\\Microsoft\\). Confidence
    # tier mapping is heuristic-driven:
    # - HIGH (Confidence.high) — suspicious_path AND
    #   (non_microsoft_description OR testsigning_enabled). Strong
    #   bootkit signal.
    # - MEDIUM (Confidence.medium) — suspicious_path alone. Could be a
    #   legitimate non-Microsoft OS; operator triages by description.
    #
    # windows_bcd_testsigning_enabled — BCD element 0x16000010 set
    # (TestSigning=True). Confidence tier mapping:
    # - HIGH (Confidence.high) — testsigning_enabled AND
    #   (no_integrity_checks OR nx_disabled). Multiple policy bits
    #   flipped is the canonical BYOVD-precursor shape.
    # - MEDIUM (Confidence.medium) — testsigning_enabled alone. Could
    #   be developer / driver-debug context.
    "windows_bcd_suspicious_path",
    "windows_bcd_testsigning_enabled",
    # Phase θ.B.E — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_wmi_findings_from_walk`` for every non-benign
    # ``WindowsWmiEvent`` row produced by the θ.B.D walker whose
    # anomaly_flags shape matches T1546.003 Event-Triggered
    # Execution: WMI Event Subscription persistence indicators.
    #
    # windows_wmi_persistence — WMI FilterToConsumerBinding (the
    # T1546.003 canonical persistence shape). Confidence tier mapping
    # is heuristic-driven:
    # - HIGH (Confidence.high) — consumer_type=ActiveScriptEvent
    #   Consumer (in-process VBScript/JScript — highest-impact),
    #   OR consumer_payload carries encoded-PowerShell signature
    #   (Qakbot tradecraft: -EncodedCommand / -enc / FromBase64String
    #   / Invoke-Expression / [char[]] / DownloadString / IEX).
    # - MEDIUM (Confidence.medium) — consumer_type=CommandLineEvent
    #   Consumer AND consumer_payload references a known script-host
    #   binary (wscript / cscript / powershell / pwsh / mshta /
    #   rundll32 / regsvr32). LOLBin-via-WMI shape.
    # - LOW (Confidence.low) — baseline review-candidate row (any
    #   non-benign FilterToConsumerBinding deserves operator
    #   attention).
    # Per intake style: ONE Literal value covers all 3 tiers (tier
    # metadata into the finding's confidence + evidence rather than
    # separate Literal values per tier).
    "windows_wmi_persistence",
    # Phase θ.C.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_esp_findings_from_walk`` for every ``WindowsEspEntry``
    # row produced by the θ.C.C walker whose authenticode_state
    # matches T1542.003 Pre-OS Boot: Bootkit indicators (BlackLotus,
    # MoonBounce, CosmicStrand, Bootkitty).
    #
    # windows_esp_unsigned — `.efi` file with authenticode_state=
    # unsigned. Confidence tier mapping is heuristic-driven:
    # - HIGH (Confidence.high) — unsigned `.efi` AND
    #   is_known_bootloader_path (EFI/Boot/bootx64.efi,
    #   EFI/Microsoft/Boot/bootmgfw.efi, etc.). Strong bootkit
    #   signal — replacing a canonical OS bootloader with an
    #   unsigned binary is the BlackLotus / Bootkitty canonical
    #   shape.
    # - MEDIUM (Confidence.medium) — unsigned `.efi` AND
    #   is_vendor_path (EFI/<vendor>/...). Could be non-standard
    #   signed-via-shim layout OR legitimate vendor utility;
    #   operator triages.
    #
    # windows_esp_dbx_revoked — `.efi` file with authenticode_state=
    # signed_revoked (chain validates but β.10 DBX revocation list
    # carries the leaf certificate / file hash). Confidence tier:
    # - HIGH (Confidence.high) — DBX-revoked. Microsoft has
    #   explicitly revoked this bootloader; under Secure Boot
    #   enforcement the binary would fail at load time. The
    #   revocation is the authoritative signal regardless of path.
    "windows_esp_unsigned",
    "windows_esp_dbx_revoked",
    # Phase θ.E.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_mbr_vbr_findings_from_walk`` for every
    # ``WindowsMbrVbrSector`` row produced by the θ.E.C walker whose
    # known_bootkit_match or anomaly_flags shape matches T1542.003
    # Pre-OS Boot: Bootkit indicators at the BIOS / legacy boot layer
    # (TDL4 / Olmasco / Mebroot / Petya / BlackEnergy). Completes the
    # boot-chain trifecta with windows_bcd_* (OS-stage) + windows_esp_*
    # (UEFI pre-bootmgr).
    #
    # windows_mbr_bootkit — MBR with known_bootkit_match populated.
    # Confidence tier mapping:
    # - HIGH (Confidence.high) — known_bootkit_match populated (named
    #   bootkit fingerprint hit: TDL4 / Petya / Mebroot / etc.).
    #   Direct adversary deployment evidence.
    #
    # windows_vbr_anomaly — VBR with known_bootkit_match OR
    # (bootcode_signature_match=NULL AND >=2 anomaly flags). Tier:
    # - HIGH (Confidence.high) — known_bootkit_match populated (named
    #   VBR bootkit — Mebroot/Olmasco VBR variants).
    # - MEDIUM (Confidence.medium) — bootcode_signature_match=NULL AND
    #   >=2 anomaly flags raised (modified VBR; supply-chain candidate).
    "windows_mbr_bootkit",
    "windows_vbr_anomaly",
    # Phase θ.D.E — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by
    # ``emit_sdb_findings_from_walk`` for every ``WindowsSdbEntry``
    # row produced by the θ.D.D walker whose sdb_kind/shim_class
    # combination matches T1546.011 Application Shimming indicators
    # (APT41 / FIN7 / Carbanak / ransomware affiliates plant custom
    # .sdb shims under Windows/AppPatch/Custom/<exe>.sdb).
    # Closes the windows-coverage-godmode θ campaign at 5-of-5
    # walker streams (θ.A BCD + θ.B WMI + θ.C ESP + θ.E MBR/VBR +
    # θ.D SDB).
    #
    # windows_sdb_inject_dll — custom-path .sdb with shim_class=
    # InjectDll. Confidence tier mapping:
    # - HIGH (Confidence.high) — direct DLL-injection primitive in
    #   attacker-controllable directory; T1546.011 signal.
    #
    # windows_sdb_redirect_exe — custom-path .sdb with shim_class=
    # RedirectEXE. Confidence tier:
    # - HIGH (Confidence.high) — replaces executed binary entirely.
    #
    # windows_sdb_custom_shim — any custom-path .sdb that doesn't
    # match the two HIGH classifiers but still warrants review.
    # Confidence tier:
    # - MEDIUM (Confidence.medium) — Custom-path AND
    #   (shim_class=GetCommandLineW OR RedirectShortcut OR
    #   has_command_line).
    # - LOW (Confidence.low) — Custom-path baseline.
    "windows_sdb_inject_dll",
    "windows_sdb_redirect_exe",
    "windows_sdb_custom_shim",
    # Phase ι.C.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the ETL walk emit hook
    # (``finding_service.emit_etl_findings_from_walk``) per Persona-E
    # ETW post-compromise surface — adversaries who clear EVTX often
    # forget to clear ETL (FortiGuard 2024 IR case; Microsoft DART
    # disclosures; Russinovich ProcMon-author blog).
    #
    # windows_etl_kernel_proc_after_clear — Kernel process events
    #   retained in ETL after Security.evtx clear marker (correlated
    #   via firmware.evtx_walk_result.log_clear_count). T1070.001
    #   (Clear Windows Event Logs) post-clear evidence trail. Persona-E
    #   HIGH — the canonical "adversary missed the ETL" tradecraft.
    #
    # windows_etl_provider_disabled — Logger-session-end event from a
    #   session-control provider (EventLog / Logger / Trace-Control).
    #   T1562.002 (Disable Windows Event Logging) supporting indicator.
    #   Persona-E HIGH.
    #
    # windows_etl_unusual_provider — Provider GUID not in known
    #   Microsoft set AND name doesn't match Microsoft-* / Windows-*
    #   prefix. T1574 (Hijack Execution Flow — providers) candidate.
    #   Persona-E MEDIUM.
    #
    # windows_etl_non_microsoft_in_diagtrack — Third-party provider
    #   inside AutoLogger-Diagtrack-Listener session (Microsoft-only
    #   by design). Strong T1574 indicator. Persona-E HIGH.
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
    # Phase ι.D.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the EFS finding-emit
    # hook (``finding_service.emit_efs_findings_from_walk``) for the
    # ι.D.C walker output. SECOND ι Windows source-family extension
    # (FIRST was ι.C.D ETL). PARSE-ONLY surface — the walker NEVER
    # decrypts the FEK, NEVER invokes DPAPI; these findings flag
    # METADATA anomalies only.
    #
    # windows_efs_orphaned_drf — file has DRF recovery agents but no
    #   DDF user entries (encrypted-via-recovery-only). T1564.001
    #   (Hidden Files and Directories — insider stealth) — the file
    #   owner can't decrypt their own file, but the recovery agent can.
    #   Persona-E HIGH.
    #
    # windows_efs_unusual_recovery_agent — DRF entry has a SID outside
    #   the standard Windows EFS Recovery family (S-1-5-21-*,
    #   S-1-5-32-544, S-1-5-18). T1564.001 supporting indicator —
    #   non-standard recovery agents may be backdoor keys. Persona-E
    #   MEDIUM.
    #
    # windows_efs_domain_admin_in_ddf — DDF user entry has a SID
    #   matching a Windows admin RID pattern (RID 500/512/519 — Built-in
    #   Administrator, Domain Admins, Enterprise Admins). T1078.002
    #   (Domain Accounts) — could be legitimate admin pre-staging OR
    #   privileged compromise indicator. Persona-E MEDIUM.
    #
    # windows_efs_large_drf — file has >2 recovery agents in DRF.
    #   Unusual EFS configuration; supply-chain or vendor-default
    #   indicator. Persona-E LOW baseline review.
    "windows_efs_orphaned_drf",
    "windows_efs_unusual_recovery_agent",
    "windows_efs_domain_admin_in_ddf",
    "windows_efs_large_drf",
    # Phase κ.B.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the AppCompat finding-
    # emit hook (``finding_service.emit_appcompat_findings_from_walk``)
    # for the κ.B.C walker output. PARSE-ONLY surface — the walker
    # NEVER invokes any extracted binary; these findings flag
    # EXECUTION-EVIDENCE METADATA anomalies only.
    #
    # windows_appcompat_suspicious_path — file_path under canonical
    #   adversary-staging directories (\Users\Public\, \Windows\Temp\,
    #   \AppData\Local\Temp\, \ProgramData\Microsoft\Windows\Caches\,
    #   C:\Temp\). T1106 (Native API) / T1059 (Command and Scripting
    #   Interpreter) — Persona-E HIGH.
    #
    # windows_appcompat_temp_execution — file_path ends in .tmp or
    #   .dat (extension hiding). T1036 Masquerading — Persona-E MEDIUM.
    #
    # windows_appcompat_recent_baseline — entry near MRU end of
    #   AppCompat (insertion_position low) AND recent last_modified_ts.
    #   Baseline-anomaly review — Persona-E LOW.
    "windows_appcompat_suspicious_path",
    "windows_appcompat_temp_execution",
    "windows_appcompat_recent_baseline",
    # Phase κ.D.D — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the DPAPI finding-emit
    # hook (``finding_service.emit_dpapi_findings_from_walk``) for the
    # κ.D.C walker output. NINTH κ-era cross-stack alignment commit.
    # PARSE-ONLY surface — the walker NEVER decrypts master keys; these
    # findings flag METADATA anomalies only.
    #
    # windows_dpapi_orphaned_masterkey — creator_sid (extracted from
    #   master-key file path) doesn't match any user SID discovered
    #   elsewhere in the firmware. Backdoor key stash indicator
    #   (attacker pre-staged keys for later credential decryption) OR
    #   legacy artefact. Persona-E HIGH.
    #
    # windows_dpapi_admin_creator_sid — creator_sid matches Windows
    #   admin RID pattern (RID 500 / 512 / 519 — Built-in Administrator,
    #   Domain Admins, Enterprise Admins) OR Local System SID
    #   (S-1-5-18). Could be legitimate (admin service-account use) or
    #   compromise indicator. Persona-E MEDIUM.
    #
    # windows_dpapi_large_masterkey — file_size_bytes > 2048. Typical
    #   master-key files are 740-1024 bytes; oversized files may
    #   indicate unusual DPAPI configuration. Persona-E LOW baseline.
    "windows_dpapi_orphaned_masterkey",
    "windows_dpapi_admin_creator_sid",
    "windows_dpapi_large_masterkey",
]


# Phase ι.A.D — FIRST cross-stack-aligned non-Windows source family.
# Linux journald walker emit sources. Sibling of WindowsFindingSource;
# the DB CHECK ck_findings_source (extended via alembic revision
# fb4c5d6e7f8a in ι.A.D) carries values from both families as the
# safety floor. Used at the call boundary inside
# ``FindingService.emit_journald_findings_from_walk`` (ι.A.D emit hook)
# so the source-string constants are typo-checked at construction time.
#
# Mapping to anomaly_flags + adversary technique:
#
# linux_journald_priority_critical — priority <= 2 (emerg/alert/crit).
#   Persona-E LOW baseline; review-candidate row.
#
# linux_journald_oom_killer — message matches kernel OOM-killer.
#   T1499 (Endpoint DoS) collateral signal. Persona-E MEDIUM.
#
# linux_journald_suspicious_unit — _SYSTEMD_UNIT path under writable
#   directory (/tmp, /var/tmp, /dev/shm, /run/shm, /home). T1543.002
#   (Systemd Service from writable). Persona-E HIGH.
#
# linux_journald_log_clear — message matches journalctl --vacuum /
#   --rotate / cleared residue. T1070.002 (Clear Linux System Logs).
#   Persona-E MEDIUM (operator review — could be legitimate
#   rotation).
#
# linux_journald_selinux_denied — message matches SELinux AVC denial.
#   T1562.001 (Disable or Modify Tools — SELinux policy circumvention
#   attempt). Persona-E MEDIUM.
LinuxFindingSource = Literal[
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    # Phase ι.B.D — Linux systemd unit-file walker emit sources
    # (SECOND LINUX source family extension; the LinuxFindingSource
    # umbrella was established by ι.A.D for journald).
    #
    # linux_systemd_suspicious_path — ExecStart= or WorkingDirectory=
    #   under a writable directory (/tmp, /var/tmp, /dev/shm, /run/shm,
    #   /home). T1543.002 (Create or Modify System Process: Systemd
    #   Service from writable). Persona-E HIGH — APT36 / FIRESTARTER /
    #   Quasar QLNX canonical TTP.
    #
    # linux_systemd_obfuscated_exec — ExecStart contains long sh -c
    #   shell command, eval/curl|sh pattern, or base64-encoded blob.
    #   T1027 (Obfuscated Files or Information). Persona-E HIGH.
    #
    # linux_systemd_socket_unusual_port — [Socket] ListenStream= or
    #   ListenDatagram= on a numeric port outside the well-known set.
    #   T1571 (Non-Standard Port). Persona-E MEDIUM.
    #
    # linux_systemd_root_minimal_deps — service runs as User=root (or
    #   unset, default root) AND Requires= is empty. Common rootkit
    #   pattern — no dependency chain means the unit's start order is
    #   unpredictable / it survives target reordering. Persona-E
    #   MEDIUM.
    #
    # linux_systemd_enabled_outside_standard — WantedBy= or RequiredBy=
    #   contains a target outside the standard 17-target set (multi-
    #   user.target, graphical.target, sysinit.target, sockets.target,
    #   etc). Adversary often defines a custom target for staging.
    #   T1543.002 supporting indicator. Persona-E MEDIUM.
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    # Phase ι.E.D — Linux container runtime artefact walker emit sources
    # (THIRD LINUX source family extension; FIFTH ι walker overall).
    #
    # linux_container_privileged_mode — HostConfig.Privileged=true OR
    #   OCI-runtime equivalent. T1610 Deploy Container — privileged
    #   container is a foothold + escalation primitive. Persona-E HIGH.
    #
    # linux_container_dangerous_capability — CapAdd contains SYS_ADMIN
    #   / SYS_PTRACE / SYS_MODULE / DAC_READ_SEARCH / NET_ADMIN /
    #   SETUID / SETGID etc. T1611 Escape to Host. Persona-E HIGH.
    #
    # linux_container_unsafe_host_mount — bind mount source under host
    #   sensitive prefix (/, /etc, /proc, /sys, /dev,
    #   /var/run/docker.sock, /home). T1611 escape pathway. Persona-E HIGH.
    #
    # linux_container_unconfined_security — seccomp=unconfined OR
    #   AppArmorProfile=unconfined. Removes the kernel-syscall filter that
    #   blocks container-escape primitives. Persona-E MEDIUM.
    #
    # linux_container_unknown_registry_image — image_repository not in
    #   the major registry allowlist (docker.io / gcr.io / mcr.microsoft.com
    #   / quay.io / public.ecr.aws / etc). Could be private (legitimate)
    #   or attacker-controlled (compromise). Persona-E MEDIUM baseline.
    "linux_container_privileged_mode",
    "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount",
    "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
    # Phase κ.C.D — Linux persistence-triplet walker emit sources
    # (FOURTH LINUX source family extension; EIGHTH κ-era walker).
    #
    # linux_bash_history_clear — T1070.003 Indicator Removal: Clear
    #   Command History. The act of trying to clear bash_history leaves
    #   the cleanup command (`history -c` / `> ~/.bash_history` / etc)
    #   in the persisted lines below. Persona-E HIGH — adversary
    #   tradecraft signal.
    #
    # linux_cron_suspicious_command — T1053.003 Scheduled Task / Cron
    #   + persistence. Fires when a crontab line combines suspicious
    #   flags (temp_path_command, reboot_persistence + network_egress).
    #   Persona-E MEDIUM baseline.
    #
    # linux_ld_preload_hijack — T1574.006 Hijack Execution Flow:
    #   Dynamic Linker Hijacking. ANY ld.so.preload entry warrants
    #   review; library_path under /tmp/ / /dev/shm/ or unusual
    #   extension elevates to open-and-shut compromise. Persona-E
    #   HIGH.
    "linux_bash_history_clear",
    "linux_cron_suspicious_command",
    "linux_ld_preload_hijack",
]


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class FindingStatus(str, Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    fixed = "fixed"


class FindingCreate(BaseModel):
    title: str
    severity: Severity
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    confidence: Confidence | None = None
    conversation_id: uuid.UUID | None = None
    firmware_id: uuid.UUID | None = None
    source: str = "manual"
    component_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    title: str | None = None
    severity: Severity | None = None
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    confidence: Confidence | None = None
    status: FindingStatus | None = None
    source: str | None = None


class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID | None
    conversation_id: uuid.UUID | None
    title: str
    severity: str
    description: str | None
    evidence: str | None
    file_path: str | None
    line_number: int | None
    cve_ids: list[str] | None
    cwe_ids: list[str] | None
    confidence: str | None
    status: str
    source: str
    component_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
