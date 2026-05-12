import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.schemas.finding import (
    Confidence,
    FindingCreate,
    FindingUpdate,
    LinuxFindingSource,
    Severity,
    WindowsFindingSource,
)

if TYPE_CHECKING:
    from app.services.loldrivers_lookup_service import BYOVDVerdict

# ── Phase β.12b — Authenticode + DBX verdict → Finding emission ──────────────
#
# Two source values land Finding rows from the authenticode_chain_runner per
# PE verdict:
#
# - ``windows_authenticode`` — chain_status verdicts that warrant operator
#   attention. The campaign brief (β.12 design constraints) maps:
#     * ``revoked`` / ``never_valid``           → high   severity
#     * ``unknown`` for a PE that's signed=True → medium severity
#     * ``valid_at_signing`` / ``valid_now``    → no Finding (good case)
#     * ``unknown`` for a PE that's signed=False → no Finding (unsigned PE
#       is normal-ish — the signature absence is captured by
#       firmware.authenticode_chain_result.signed_pct, not as a per-PE finding)
# - ``windows_dbx_revoked`` — leaf-serial matched a Microsoft DBX entry.
#   Always critical severity. Independent of chain_status: a chain-revoked
#   AND DBX-revoked PE produces TWO Finding rows (different sources, the
#   operator may want to triage them separately by source filter).
#
# The classifier below is decoupled from the ORM so it's exercised by mock
# unit tests (no DB needed) AND by the live-canary inside
# ``FindingService.emit_pe_signature_findings`` (Rule #35b).
#
# Constants typed against ``WindowsFindingSource`` (Rule #33 .c) so a typo
# in either source string fails type-check at definition time, matching
# the ``ck_findings_source`` DB CHECK from alembic revision ``c5b6a7d8e9f0``.

_SOURCE_AUTHENTICODE: WindowsFindingSource = "windows_authenticode"
_SOURCE_DBX_REVOKED: WindowsFindingSource = "windows_dbx_revoked"

# ── Phase γ.8 — Registry + driver source constants ───────────────────────────
#
# Same Rule #33 .c discipline as β.12b — narrow Literal at the helper
# boundary catches typos at code-load time without disturbing the legacy
# ``FindingCreate.source: str`` contract. The DB CHECK
# (ck_findings_source from γ.7 alembic c9d0e1f2a3b4) is the durable
# safety floor enforcing the full allowlist.
_SOURCE_REGISTRY_PERSISTENCE: WindowsFindingSource = "windows_registry_persistence"
_SOURCE_INF: WindowsFindingSource = "windows_inf"
_SOURCE_DRIVER_IMPORTS: WindowsFindingSource = "windows_driver_imports"

# ── Phase δ.8 — R2R-stomping + capa-on-IL source constants ───────────────────
#
# Same Rule #33 .c discipline as β.12b + γ.8 — narrow Literal at the helper
# boundary catches typos at code-load time without disturbing the legacy
# ``FindingCreate.source: str`` contract. The DB CHECK (ck_findings_source
# from δ.8 alembic d5a6b7c8d9e0) is the durable safety floor enforcing
# the full allowlist.
_SOURCE_R2R_STOMP: WindowsFindingSource = "windows_r2r_stomp"
_SOURCE_IL_CAPA: WindowsFindingSource = "windows_il_capa"

# ── Phase ε.1.b.4 — EVTX (Windows Event Log) source constants ────────────────
#
# Same Rule #33 .c discipline as β.12b + γ.8 + δ.8 — narrow Literal at the
# helper boundary catches typos at code-load time without disturbing the
# legacy ``FindingCreate.source: str`` contract. The DB CHECK
# (ck_findings_source from ε.1.b.4 alembic e1a2b3c4d5e6) is the durable
# safety floor enforcing the full allowlist (28 sources at ε shipping
# time).
_SOURCE_SYSMON_PROC_CREATE: WindowsFindingSource = "windows_sysmon_proc_create"
_SOURCE_LOGON_SUCCESS: WindowsFindingSource = "windows_logon_success"
_SOURCE_LOGON_FAILURE: WindowsFindingSource = "windows_logon_failure"

# Phase ζ.1 — Amcache program-installation history finding source.
# Emitted by ``emit_amcache_findings_from_walk`` for InventoryApplicationFile
# entries on parsed AmCache.hve registry extracts. LOW confidence baseline
# (installation-history facts are not malicious by themselves; threat-feed
# correlation tier is deferred to a future ζ.X phase).
_SOURCE_AMCACHE_INSTALL: WindowsFindingSource = "windows_amcache_install"

# Phase ζ.2.C — Prefetch application-execution history finding source.
# Emitted by ``emit_prefetch_findings_from_walk`` for every WindowsPrefetchRecord
# row produced by the ζ.2.B walker. LOW confidence baseline (execution-history
# facts are not malicious by themselves; threat-feed correlation tier is
# deferred to a future ζ.X phase). Companion to _SOURCE_AMCACHE_INSTALL —
# both surface program-history baseline at LOW.
_SOURCE_PREFETCH_EXECUTION: WindowsFindingSource = "windows_prefetch_execution"

# Phase ζ.3.C — SRUM (System Resource Usage Monitor) finding sources.
# Emitted by ``emit_srum_findings_from_walk`` for the SRUM record_type
# discriminator values:
# - network_data_usage / network_connectivity → windows_srum_network_activity
# - application_resource_usage → windows_srum_application_runtime
# Both LOW confidence baseline; threat-feed correlation deferred.
_SOURCE_SRUM_NETWORK_ACTIVITY: WindowsFindingSource = (
    "windows_srum_network_activity"
)
_SOURCE_SRUM_APPLICATION_RUNTIME: WindowsFindingSource = (
    "windows_srum_application_runtime"
)

# Phase η.E — PowerShell event-log finding source. Emitted by η.E's
# extension to ε's ``emit_evtx_findings_from_walk`` per-record loop,
# branching on PowerShell EIDs 4103 (Module/Pipeline) and 4104
# (ScriptBlock). One Literal value covers the EID pair (per intake
# D5) — sub-EID metadata into the finding's evidence field. Confidence
# tier mapping is heuristic-driven (low/medium/high) per
# ``_classify_powershell_event``. 4105/4106 (Pipeline state-change)
# are NOISE — not emitted.
_SOURCE_POWERSHELL_SCRIPT_BLOCK: WindowsFindingSource = (
    "windows_powershell_script_block"
)

# Phase η.B.D — Scheduled Task persistence finding source. Emitted by
# ``emit_scheduled_task_findings_from_walk`` for every
# ``WindowsScheduledTask`` row produced by the η.B.C walker.
# Confidence tier mapping is heuristic-driven:
# - HIGH (Confidence.high) — Action contains encoded-PowerShell pattern
#   (Qakbot signature). Detected via
#   ``scheduled_task_walker.is_action_encoded_powershell``.
# - MEDIUM (Confidence.medium) — RunLevel=HighestAvailable AND
#   non-system Author (per
#   ``scheduled_task_walker.is_system_author``).
# - LOW (Confidence.low) — baseline review-candidate row.
# Per intake style: ONE Literal value covers all 3 tiers.
_SOURCE_SCHEDULED_TASK_PERSISTENCE: WindowsFindingSource = (
    "windows_scheduled_task_persistence"
)


# Phase η.C.D — LNK abnormal-target finding source. Emitted by
# ``emit_lnk_findings_from_walk`` for every ``WindowsLnkRecord`` row
# produced by the η.C.C walker whose target / arguments shape matches
# T1547.009 Shortcut Modification persistence indicators.
# Confidence tier mapping is heuristic-driven:
# - HIGH (Confidence.high) — target is a known script-host binary AND
#   arguments contain encoded-PowerShell pattern (Qakbot signature).
#   Detected via ``lnk_walker.is_script_host_target`` +
#   ``lnk_walker.is_arguments_encoded_powershell``.
# - MEDIUM (Confidence.medium) — target_path is non-Microsoft (per
#   ``lnk_walker.is_microsoft_target`` returning False).
# - LOW (Confidence.low) — baseline review-candidate row.
# Per intake style: ONE Literal value covers all 3 tiers.
_SOURCE_LNK_ABNORMAL_TARGET: WindowsFindingSource = (
    "windows_lnk_abnormal_target"
)


# Phase η.A.D — MFT $DATA ADS hidden-content + $SI/$FN timestomp emit
# sources. Emitted by ``emit_mft_findings_from_walk`` for every
# ``WindowsMftRecord`` row produced by the η.A.C walker.
#
# windows_mft_ads_hidden_content — named ADS stream with size > 1 KB
# (excludes benign Zone.Identifier MOTW tag at ~100 B). Confidence tier:
# - HIGH (Confidence.high) — ADS size > 16 KB. ProcessHollower /
#   Pegasus / generic AV-evasion drop pattern.
# - MEDIUM (Confidence.medium) — ADS size 1 KB – 16 KB.
#
# windows_mft_timestomping — $SI mtime < $FN mtime. T1070.006 Indicator
# Removal: Timestomp. Confidence tier:
# - HIGH (Confidence.high) — ALL FOUR $SI timestamps older than ALL
#   FOUR $FN timestamps. timestomp.exe rewrites the full tuple.
# - MEDIUM (Confidence.medium) — single $SI mtime < $FN mtime pair.
_SOURCE_MFT_ADS_HIDDEN_CONTENT: WindowsFindingSource = (
    "windows_mft_ads_hidden_content"
)
_SOURCE_MFT_TIMESTOMPING: WindowsFindingSource = (
    "windows_mft_timestomping"
)

# Tier thresholds — ADS payload size for HIGH-vs-MEDIUM split.
_MFT_ADS_HIGH_CONFIDENCE_BYTES = 16 * 1024
_MFT_ADS_MEDIUM_CONFIDENCE_BYTES = 1024  # excludes Zone.Identifier tag


# Phase η.D.D — LOLDrivers BYOVD fingerprint emit source. Emitted by
# ``emit_byovd_findings_from_driver`` for every Windows driver blob whose
# SHA256 (or Authenticode hash) matches a LOLDrivers record (the η.D.C
# lookup service returns a populated :class:`BYOVDVerdict`).
#
# Confidence tier mapping is heuristic-driven by category + CVE:
# - HIGH (Confidence.high) — category=``malicious``, OR category=
#   ``vulnerable driver`` AND ≥1 CVE association. The malicious case is
#   unambiguous compromise; the CVE-associated case carries public-
#   known-exploit weight beyond a stale-driver flag.
# - MEDIUM (Confidence.medium) — category=``vulnerable driver`` with no
#   CVE association. Surfaces stale-driver BYOVD risk without over-
#   triaging legitimate-but-stale embedded firmware.
# Per intake style: ONE Literal value covers all tiers (tier metadata
# goes into the finding's confidence + evidence fields rather than
# separate Literal values per tier).
_SOURCE_BYOVD_DRIVER: WindowsFindingSource = "windows_byovd_driver"


# Phase θ.A.D — BCD walker emit sources. Emitted by
# ``emit_bcd_findings_from_walk`` for every ``WindowsBcdEntry`` row
# produced by the θ.A.C walker whose anomaly_flags shape matches
# T1542.003 Pre-OS Boot: Bootkit indicators.
#
# windows_bcd_suspicious_path — image_path NOT under any Microsoft-
# vetted prefix. Confidence tier:
# - HIGH (Confidence.high) — suspicious_path AND
#   (non_microsoft_description OR testsigning_enabled).
# - MEDIUM (Confidence.medium) — suspicious_path alone.
#
# windows_bcd_testsigning_enabled — BCD element 0x16000010 set.
# Confidence tier:
# - HIGH (Confidence.high) — testsigning_enabled AND
#   (no_integrity_checks OR nx_disabled).
# - MEDIUM (Confidence.medium) — testsigning_enabled alone.
_SOURCE_BCD_SUSPICIOUS_PATH: WindowsFindingSource = (
    "windows_bcd_suspicious_path"
)
_SOURCE_BCD_TESTSIGNING_ENABLED: WindowsFindingSource = (
    "windows_bcd_testsigning_enabled"
)


# Phase θ.B.E — WMI persistence walker emit source. Emitted by
# ``emit_wmi_findings_from_walk`` for every non-benign
# ``WindowsWmiEvent`` row produced by the θ.B.D walker whose
# anomaly_flags shape matches T1546.003 Event-Triggered Execution:
# WMI Event Subscription indicators.
#
# windows_wmi_persistence — single Literal value covers all 3 tiers
# (HIGH/MEDIUM/LOW). Confidence tier mapping is heuristic-driven by
# the classifier:
# - HIGH (Confidence.high) — consumer_type=ActiveScriptEventConsumer
#   (in-process VBScript/JScript — highest-impact WMI consumer
#   type), OR consumer_payload carries encoded-PowerShell signature
#   (Qakbot tradecraft: -EncodedCommand / -enc / FromBase64String /
#   Invoke-Expression / [char[]] / DownloadString / IEX).
# - MEDIUM (Confidence.medium) — consumer_type=CommandLineEvent
#   Consumer AND consumer_payload references a known script-host
#   binary (wscript / cscript / powershell / pwsh / mshta /
#   rundll32 / regsvr32). LOLBin-via-WMI shape.
# - LOW (Confidence.low) — baseline review-candidate row (any
#   non-benign FilterToConsumerBinding deserves operator attention).
_SOURCE_WMI_PERSISTENCE: WindowsFindingSource = "windows_wmi_persistence"

# Phase θ.C.D — ESP `.efi` PE chain walker emit sources. Emitted by
# ``emit_esp_findings_from_walk`` for every ``WindowsEspEntry`` row
# produced by the θ.C.C walker whose authenticode_state matches
# T1542.003 Pre-OS Boot: Bootkit indicators (BlackLotus, MoonBounce,
# CosmicStrand, Bootkitty).
#
# windows_esp_unsigned — `.efi` with authenticode_state=unsigned.
# Confidence tier is heuristic-driven by the classifier:
# - HIGH (Confidence.high) — unsigned `.efi` AND
#   is_known_bootloader_path (EFI/Boot/bootx64.efi,
#   EFI/Microsoft/Boot/bootmgfw.efi). Strong T1542.003 signal.
# - MEDIUM (Confidence.medium) — unsigned `.efi` AND is_vendor_path
#   (EFI/<vendor>/...). Operator triages.
#
# windows_esp_dbx_revoked — `.efi` with authenticode_state=
# signed_revoked (β.10 DBX revocation list hit). Confidence: HIGH
# always — Microsoft has explicitly revoked this bootloader.
_SOURCE_ESP_UNSIGNED: WindowsFindingSource = "windows_esp_unsigned"
_SOURCE_ESP_DBX_REVOKED: WindowsFindingSource = "windows_esp_dbx_revoked"

# Phase θ.E.D — MBR/VBR boot-sector walker emit sources. Emitted by
# ``emit_mbr_vbr_findings_from_walk`` for every ``WindowsMbrVbrSector``
# row produced by the θ.E.C walker whose known_bootkit_match or
# anomaly_flags shape matches T1542.003 Pre-OS Boot: Bootkit indicators
# at the BIOS / legacy boot layer.
#
# windows_mbr_bootkit — MBR with known_bootkit_match populated
# (TDL4 / Petya / Mebroot / Olmasco / BlackEnergy). Confidence: HIGH
# always — direct named-bootkit fingerprint hit.
#
# windows_vbr_anomaly — VBR with known_bootkit_match OR
# (bootcode_signature_match=NULL AND >=2 anomaly flags). Tier:
# - HIGH — known_bootkit_match populated (named VBR variant).
# - MEDIUM — bootcode_signature_match=NULL AND >=2 anomaly flags
#   (modified VBR without a named bootkit; supply-chain candidate).
_SOURCE_MBR_BOOTKIT: WindowsFindingSource = "windows_mbr_bootkit"
_SOURCE_VBR_ANOMALY: WindowsFindingSource = "windows_vbr_anomaly"

# Phase θ.D.E — SDB shim walker emit sources. The 3 sources distinguish
# the canonical T1546.011 attacker primitives by shim_class:
# - windows_sdb_inject_dll — custom-path .sdb with shim_class=InjectDll.
#   HIGH always (direct DLL-injection primitive in attacker-controlled
#   directory).
# - windows_sdb_redirect_exe — custom-path .sdb with shim_class=
#   RedirectEXE. HIGH always (replaces executed binary entirely).
# - windows_sdb_custom_shim — any other custom-path .sdb. MEDIUM if
#   shim_class in (GetCommandLineW, RedirectShortcut) OR
#   has_command_line; LOW otherwise (Custom-path baseline).
_SOURCE_SDB_INJECT_DLL: WindowsFindingSource = "windows_sdb_inject_dll"
_SOURCE_SDB_REDIRECT_EXE: WindowsFindingSource = "windows_sdb_redirect_exe"
_SOURCE_SDB_CUSTOM_SHIM: WindowsFindingSource = "windows_sdb_custom_shim"

# ── Phase ι.A.D — Linux journald source constants (FIRST LINUX) ──────────────
#
# Same Rule #33 .c discipline as the Windows sources above — narrow
# Literal at the helper boundary catches typos at code-load time
# without disturbing the legacy ``FindingCreate.source: str`` contract.
# The DB CHECK (ck_findings_source from ι.A.D alembic fb4c5d6e7f8a)
# is the durable safety floor enforcing the full allowlist (52 sources
# total at ι.A.D shipping time = 47 prior + 5 new Linux journald
# sources). FIRST cross-stack alignment commit covering non-Windows
# source values (Rule #25 single-slice exception #2, Rule-of-Nineteen).
_SOURCE_JOURNALD_PRIORITY_CRITICAL: LinuxFindingSource = (
    "linux_journald_priority_critical"
)
_SOURCE_JOURNALD_OOM_KILLER: LinuxFindingSource = "linux_journald_oom_killer"
_SOURCE_JOURNALD_SUSPICIOUS_UNIT: LinuxFindingSource = (
    "linux_journald_suspicious_unit"
)
_SOURCE_JOURNALD_LOG_CLEAR: LinuxFindingSource = "linux_journald_log_clear"
_SOURCE_JOURNALD_SELINUX_DENIED: LinuxFindingSource = (
    "linux_journald_selinux_denied"
)

# ── Phase ι.B.D — Linux systemd unit-file source constants (SECOND LINUX) ────
#
# Sibling family to _SOURCE_JOURNALD_* above. Same Rule #33 .c
# discipline — narrow Literal at the helper boundary catches typos at
# code-load time without disturbing the legacy FindingCreate.source:
# str contract. The DB CHECK (ck_findings_source from ι.B.D alembic
# aabbccddee03) is the durable safety floor enforcing the full
# allowlist (57 sources total at ι.B.D shipping time = 52 prior + 5
# new Linux systemd sources). SECOND non-Windows cross-stack alignment
# commit (Rule #25 single-slice exception #2, Rule-of-Twenty).
_SOURCE_SYSTEMD_SUSPICIOUS_PATH: LinuxFindingSource = (
    "linux_systemd_suspicious_path"
)
_SOURCE_SYSTEMD_OBFUSCATED_EXEC: LinuxFindingSource = (
    "linux_systemd_obfuscated_exec"
)
_SOURCE_SYSTEMD_SOCKET_UNUSUAL_PORT: LinuxFindingSource = (
    "linux_systemd_socket_unusual_port"
)
_SOURCE_SYSTEMD_ROOT_MINIMAL_DEPS: LinuxFindingSource = (
    "linux_systemd_root_minimal_deps"
)
_SOURCE_SYSTEMD_ENABLED_OUTSIDE_STANDARD: LinuxFindingSource = (
    "linux_systemd_enabled_outside_standard"
)


# ── Phase η.E — PowerShell EID classifier helper ──
#
# Heuristic detection for obfuscated/encoded PowerShell content. The
# checks are deliberately conservative — only flagging shapes that
# survived a 2024-2025 Mandiant/CrowdStrike adversary-tradecraft
# review (cited in `.planning/research/eta-scope-2026-05-11/scout-2-
# persona-refresh.md` for the broader Persona-E completionist scan).
# False-positive on a legitimate base64 blob is acceptable; the LOW
# confidence baseline is the safety floor when heuristics don't
# trigger.
_POWERSHELL_OBFUSCATION_INDICATORS: tuple[str, ...] = (
    "FromBase64String",       # explicit base64 decode
    "EncodedCommand",          # -EncodedCommand argument
    "-enc ",                   # short form of -EncodedCommand
    "-Enc ",
    "-EC ",
    "Invoke-Expression ",      # IEX evaluation of dynamic code
    "Invoke-Expression(",
    " IEX ",
    " IEX(",
    "[char[]](",               # char-array shellcode reassembly
    "[Convert]::FromBase64",   # explicit conversion
    "[System.Convert]::FromBase64",
    "DownloadString(",         # net.webclient downloader pattern
    "DownloadFile(",
    "WebClient).DownloadString",
    "Reflection.Assembly]::Load",  # in-memory assembly load
)


def _classify_powershell_event(eid: int, raw_xml: str) -> tuple[
    "Confidence", str
] | None:
    """Classify a PowerShell event by its EID + raw_xml content.

    Returns (confidence, title) for emission, or None if the event
    should NOT be emitted (e.g. EID 4105/4106 noise; non-PowerShell
    EIDs).

    Confidence tier mapping:
    - 4103 (Module/Pipeline) → Confidence.low (module-load fact only).
    - 4104 (ScriptBlock) without obfuscation → Confidence.medium
      (script execution evidence).
    - 4104 (ScriptBlock) with obfuscation indicators → Confidence.high
      (encoded/dynamic-evaluated script — strong tradecraft signal).
    """
    if eid == 4103:
        return (Confidence.low, "PowerShell module-load event (EID 4103)")
    if eid == 4104:
        if any(
            indicator in raw_xml
            for indicator in _POWERSHELL_OBFUSCATION_INDICATORS
        ):
            return (
                Confidence.high,
                "PowerShell ScriptBlock event with obfuscation (EID 4104)",
            )
        return (
            Confidence.medium,
            "PowerShell ScriptBlock event (EID 4104)",
        )
    # 4105 / 4106 / other — not emitted.
    return None


@dataclass(frozen=True)
class _PEFindingDraft:
    """One Finding row to emit, before persistence. Pure-data so the
    classifier can be unit-tested without a DB.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str


def _format_authenticode_evidence(
    *,
    signed: bool,
    chain_status: str,
    leaf_serial: str | None,
    signer_subject: str | None,
) -> str:
    """One-line, operator-readable summary of the authenticode verdict
    fields the Finding row was derived from. Format mirrors the
    extraction-diagnostics evidence shape in unpack_audit_service —
    KV pairs separated by ``; ``."""
    parts: list[str] = [
        f"signed={signed}",
        f"chain_status={chain_status}",
    ]
    if leaf_serial:
        parts.append(f"leaf_serial={leaf_serial}")
    if signer_subject:
        parts.append(f"signer_subject={signer_subject}")
    return "; ".join(parts)


def _format_dbx_evidence(
    *,
    leaf_serial: str | None,
    dbx_revocation_kb: str | None,
) -> str:
    parts: list[str] = []
    if leaf_serial:
        parts.append(f"leaf_serial={leaf_serial}")
    if dbx_revocation_kb:
        parts.append(f"dbx_revocation_kb={dbx_revocation_kb}")
    if not parts:
        # match_dbx_revocation always returns at least the KB reference on
        # a positive match; this branch is defensive against a future
        # caller passing dbx_revoked=True with no supporting context.
        parts.append("source=microsoft_dbxupdate")
    return "; ".join(parts)


def classify_pe_verdict_findings(
    *,
    blob_path: str,
    signed: bool,
    chain_status: str,
    dbx_revoked: bool,
    leaf_serial: str | None = None,
    signer_subject: str | None = None,
    dbx_revocation_kb: str | None = None,
) -> list[_PEFindingDraft]:
    """Map one PE's verdict tuple to 0–2 Finding drafts.

    Pure function; no DB access. Idempotent — same inputs always produce
    the same output list (so re-running the runner against the same
    verdict produces identical Finding rows, modulo timestamps which the
    DB stamps).
    """
    drafts: list[_PEFindingDraft] = []
    name = os.path.basename(blob_path) or blob_path

    # windows_authenticode emission per the β.12 severity map.
    ac_severity: Severity | None = None
    ac_description: str | None = None
    if chain_status == "revoked":
        ac_severity = Severity.high
        ac_description = (
            f"Authenticode certificate chain reports REVOKED for {name}. "
            "The signing certificate (or one of its issuers) was revoked "
            "by its CA before the firmware was assembled — the binary was "
            "either signed with an already-revoked cert or had its "
            "trusted timestamp invalidated. Treat as untrusted code."
        )
    elif chain_status == "never_valid":
        ac_severity = Severity.high
        ac_description = (
            f"Authenticode certificate chain is NEVER VALID for {name}. "
            "Chain construction failed against the trusted-roots bundle "
            "(self-signed, expired-at-signing, or no path to a trusted "
            "root). The signature cannot be relied on for code-trust."
        )
    elif chain_status == "unknown" and signed:
        ac_severity = Severity.medium
        ac_description = (
            f"Authenticode chain status is UNKNOWN for signed PE {name}. "
            "The signature was parsed but verification could not complete "
            "(missing intermediate, missing timestamp, parser error). "
            "Manual review recommended before relying on the signature."
        )

    if ac_severity is not None:
        assert ac_description is not None  # guarded by the same branches above
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_AUTHENTICODE,
                severity=ac_severity,
                title=f"Authenticode chain {chain_status} for {name}",
                description=ac_description,
                evidence=_format_authenticode_evidence(
                    signed=signed,
                    chain_status=chain_status,
                    leaf_serial=leaf_serial,
                    signer_subject=signer_subject,
                ),
            )
        )

    # windows_dbx_revoked — independent of chain_status. A PE can be both
    # chain-revoked AND DBX-revoked → two Finding rows, different sources.
    if dbx_revoked:
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_DBX_REVOKED,
                severity=Severity.critical,
                title=f"Microsoft DBX revoked PE: {name}",
                description=(
                    f"PE leaf certificate for {name} matches an entry in "
                    "the Microsoft Secure Boot DBX revocation bundle. "
                    "Continued execution risks running attacker-trusted "
                    "code with valid-looking but offline-revoked signature."
                ),
                evidence=_format_dbx_evidence(
                    leaf_serial=leaf_serial,
                    dbx_revocation_kb=dbx_revocation_kb,
                ),
            )
        )

    return drafts


# ── Phase γ.8 — Registry persistence classifier ──────────────────────────────


# Per-subkey severity map. Persona-E #13 ranks the persistence vectors:
# - Run / RunOnce — auto-start at user logon (medium; many legitimate)
# - RunServices / RunServicesOnce — boot-time service start (high)
# - AppInit_DLLs — process-creation DLL injection (high)
# - Image File Execution Options — debugger hijack vector (high)
# - Winlogon ShellExecuteHooks — shell-creation hijack (high)
# - Session Manager BootExecute — kernel-time pre-boot execution (critical)
# - Active Setup Installed Components — per-user one-shot install (medium)
# - Policies\Explorer\Run — group-policy persistence (medium)
# - CurrentControlSet\Services — service definitions; many legit (low,
#   surfaced for triage but downgraded to avoid noise)
_REGISTRY_SEVERITY_MAP: tuple[tuple[str, Severity, str], ...] = (
    ("session manager\\bootexecute", Severity.critical, "Session Manager BootExecute (kernel-time pre-boot execution)"),
    ("currentversion\\windows\\appinit_dlls", Severity.high, "AppInit_DLLs (process-creation DLL injection)"),
    ("image file execution options", Severity.high, "Image File Execution Options (debugger hijack vector)"),
    ("currentversion\\winlogon", Severity.high, "Winlogon ShellExecuteHooks (shell-creation hijack)"),
    ("currentversion\\runservices", Severity.high, "RunServices (boot-time service start)"),
    ("currentversion\\run", Severity.medium, "Run / RunOnce (auto-start at user logon)"),
    ("currentversion\\policies\\explorer\\run", Severity.medium, "Group Policy Explorer Run"),
    ("active setup\\installed components", Severity.medium, "Active Setup Installed Components"),
    ("currentcontrolset\\services", Severity.low, "CurrentControlSet\\Services (service definition)"),
)


def _classify_registry_subkey_severity(
    subkey_path: str,
) -> tuple[Severity, str] | None:
    """Return (severity, label) for a persistence-relevant subkey.

    Matches case-insensitively against the longest matching pattern
    in :data:`_REGISTRY_SEVERITY_MAP` — order matters (most specific
    patterns first so e.g. ``Image File Execution Options`` wins over
    a hypothetical ``CurrentVersion`` substring match).
    """
    path_lower = (subkey_path or "").lower()
    for pattern, severity, label in _REGISTRY_SEVERITY_MAP:
        if pattern in path_lower:
            return severity, label
    return None


def _format_registry_evidence(
    *,
    hive_path: str,
    hive_type: str,
    subkey_path: str,
    values: list[dict] | None,
) -> str:
    """Operator-readable evidence string for a registry persistence finding."""
    parts = [
        f"hive={hive_path}",
        f"hive_type={hive_type}",
        f"subkey={subkey_path}",
    ]
    value_count = len(values or [])
    parts.append(f"value_count={value_count}")
    # Surface the first few value names so the operator can spot
    # known-malicious entries (e.g. random GUID-shaped names) at a
    # glance without opening the full subkey.
    if values:
        sample_names = [v.get("name", "") for v in values[:3]]
        parts.append(f"sample_values={sample_names}")
    return "; ".join(parts)


def classify_amcache_install_findings(
    *,
    hive_path: str,
    hive_type: str,
    parsed_tree: Any,
) -> list[_PEFindingDraft]:
    """Phase ζ.1 — map one AmCache.hve's parsed_tree to N install-history
    Finding drafts.

    Pure function — no DB access. Walks the canonical parsed_tree subkey
    list looking for ``Root\\InventoryApplicationFile\\<hash>`` entries
    (Win10/11 AmCache shape). Each entry yields one LOW-confidence
    review-candidate Finding draft surfacing the file path + sha1 +
    install-source metadata.

    Returns empty list when ``parsed_tree`` is None / wrong-typed
    (defensive boundary mirrors the JSONB normaliser shape) OR when
    ``hive_type != 'AmCache'`` (callers should not pass non-AmCache
    hives but the guard prevents accidental misuse).

    Confidence tier: LOW baseline. Threat-feed correlation (hash against
    known-malicious database) and heuristic matching against curated
    suspicious-product lists are deferred to a future ζ.X phase.
    """
    if hive_type != "AmCache":
        return []
    if not isinstance(parsed_tree, dict):
        return []
    subkeys = parsed_tree.get("subkeys") or []
    if not isinstance(subkeys, list):
        return []

    drafts: list[_PEFindingDraft] = []
    for sk in subkeys:
        if not isinstance(sk, dict):
            continue
        subkey_path = sk.get("path") or ""
        # Match the canonical InventoryApplicationFile subkey shape.
        # Win10 1709+ hives use Root\InventoryApplicationFile\<filename>|<sha1>
        # under the per-program key. We look for the parent path token.
        if "InventoryApplicationFile" not in subkey_path:
            continue
        values = sk.get("values") or []
        if not values:
            continue

        # Extract the program identity from the values list. Shape per
        # python-regipy: list of dicts with name + value. We look for
        # the canonical fields without raising on missing entries.
        value_map: dict[str, Any] = {}
        for v in values:
            if isinstance(v, dict):
                name = v.get("name") or ""
                if name:
                    value_map[name] = v.get("value")

        file_path = value_map.get("LowerCaseLongPath") or value_map.get("Name") or "(unknown)"
        sha1 = value_map.get("FileId") or ""
        # FileId is "0000<sha1>" in Win10+ — strip the leading zero pad if present.
        if isinstance(sha1, str) and sha1.startswith("0000"):
            sha1 = sha1[4:]
        product = value_map.get("ProductName") or ""
        publisher = value_map.get("Publisher") or ""
        size = value_map.get("Size") or 0

        evidence_lines = [
            f"File: {file_path}",
            f"SHA1: {sha1}" if sha1 else "SHA1: (not present)",
        ]
        if product:
            evidence_lines.append(f"Product: {product}")
        if publisher:
            evidence_lines.append(f"Publisher: {publisher}")
        if size:
            evidence_lines.append(f"Size: {size} bytes")
        evidence_lines.append(f"AmCache subkey: {subkey_path}")
        evidence_lines.append(f"Hive: {hive_path}")
        evidence = "\n".join(evidence_lines)

        # Title surfaces just the executable basename for readability;
        # full path lives in the evidence.
        basename = file_path.rsplit("\\", 1)[-1] if isinstance(file_path, str) else "(unknown)"

        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_AMCACHE_INSTALL,
                severity=Severity.info,
                title=f"AmCache install record: {basename}",
                description=(
                    f"AmCache InventoryApplicationFile entry surfaces installation "
                    f"history for {basename}. LOW-confidence review candidate; "
                    f"correlate the SHA1 with threat-feeds for higher-confidence "
                    f"verdicts in a follow-up triage."
                ),
                evidence=evidence,
            )
        )
    return drafts


def classify_prefetch_execution_findings(
    *,
    prefetch_file_path: str,
    executable_name: str,
    run_count: int | None,
    last_run_time: Any,
    version: int | None = None,
    prefetch_hash: str | None = None,
) -> list[_PEFindingDraft]:
    """Phase ζ.2.C — map one WindowsPrefetchRecord row to one
    application-execution-history Finding draft.

    Pure function — no DB access. Each Prefetch row yields exactly one
    LOW-confidence review-candidate Finding draft surfacing the
    executable name + run count + last-run timestamp.

    Returns empty list when ``executable_name`` is missing/empty
    (defensive boundary mirrors the walker's _build_record contract —
    rows without an executable_name aren't persisted, but this guard
    catches any caller that bypasses the walker).

    Confidence tier: LOW baseline (Severity.info). Threat-feed
    correlation against the file path / executable hash / curated
    suspicious-binary list is deferred to a future ζ.X phase. Same
    shape as ζ.1's classify_amcache_install_findings.

    Why an emit hook on top of the per-row table:
    - The walker (ζ.2.B) writes one ``WindowsPrefetchRecord`` per .pf
      file. The Finding emitter (ζ.2.D) projects each row to an
      operator-triageable surface (Severity + title + description +
      evidence) so the same data appears in the Findings UI.
    - Operators then triage in one place — the Findings page — rather
      than learning a separate Prefetch viewer.
    """
    if not executable_name:
        return []

    evidence_lines = [
        f"Executable: {executable_name}",
    ]
    if run_count is not None:
        evidence_lines.append(f"Run count: {run_count}")
    if last_run_time is not None:
        evidence_lines.append(f"Last run: {last_run_time}")
    if version is not None:
        evidence_lines.append(f"Prefetch version: {version}")
    if prefetch_hash:
        evidence_lines.append(f"Prefetch hash: {prefetch_hash}")
    evidence_lines.append(f"Prefetch file: {prefetch_file_path}")
    evidence = "\n".join(evidence_lines)

    description = (
        f"Windows Prefetch record surfaces application-execution history "
        f"for {executable_name}"
    )
    if run_count:
        description += f" (run {run_count} times)"
    description += (
        ". LOW-confidence review candidate; correlate the executable "
        "path / hash with threat-feeds for higher-confidence verdicts "
        "in a follow-up triage."
    )

    return [
        _PEFindingDraft(
            source=_SOURCE_PREFETCH_EXECUTION,
            severity=Severity.info,
            title=f"Prefetch execution: {executable_name}",
            description=description,
            evidence=evidence,
        )
    ]


def classify_srum_findings(
    *,
    record_type: str,
    app_identifier: str | None,
    user_identifier: str | None,
    recorded_at: Any,
    bytes_sent: int | None = None,
    bytes_received: int | None = None,
    bytes_read: int | None = None,
    bytes_written: int | None = None,
    cpu_foreground_seconds: int | None = None,
    cpu_background_seconds: int | None = None,
) -> list[_PEFindingDraft]:
    """Phase ζ.3.C — map one WindowsSrumRecord row to a Finding draft.

    Pure function — no DB access. Each SRUM row yields at most ONE Finding
    draft, with the source tag determined by the record_type discriminator:

    - record_type in {network_data_usage, network_connectivity} → emits
      ``windows_srum_network_activity``.
    - record_type == application_resource_usage → emits
      ``windows_srum_application_runtime``.
    - All other record_types (push_notification, energy_usage) → empty list
      (low operator-triage value; surface in MCP search tool only).

    Returns empty list when ``app_identifier`` is missing/empty (these
    rows come from corrupted SruDbIdMapTable rows or rows with NULL
    AppId — defensive boundary).

    Confidence tier: LOW baseline (Severity.info). Same shape as
    classify_prefetch_execution_findings + classify_amcache_install_findings.
    """
    if not app_identifier:
        return []

    if record_type in ("network_data_usage", "network_connectivity"):
        source: WindowsFindingSource = _SOURCE_SRUM_NETWORK_ACTIVITY
        evidence_lines = [f"App: {app_identifier}"]
        if user_identifier:
            evidence_lines.append(f"User: {user_identifier}")
        if recorded_at is not None:
            evidence_lines.append(f"Recorded: {recorded_at}")
        if bytes_sent is not None:
            evidence_lines.append(f"Bytes sent: {bytes_sent:,}")
        if bytes_received is not None:
            evidence_lines.append(f"Bytes received: {bytes_received:,}")
        evidence_lines.append(f"SRUM record type: {record_type}")
        evidence = "\n".join(evidence_lines)

        # Title surfaces just the app basename for readability.
        basename = (
            app_identifier.rsplit("\\", 1)[-1]
            if "\\" in app_identifier
            else app_identifier
        )
        description = (
            f"SRUM network record surfaces ~30-60 day per-app network "
            f"history for {basename}"
        )
        if bytes_sent and bytes_received:
            description += (
                f" ({bytes_sent + bytes_received:,} total bytes transferred)"
            )
        description += (
            ". LOW-confidence review candidate; correlate the app path / "
            "interface_luid with threat-feeds for higher-confidence "
            "verdicts in a follow-up triage."
        )

        return [
            _PEFindingDraft(
                source=source,
                severity=Severity.info,
                title=f"SRUM network activity: {basename}",
                description=description,
                evidence=evidence,
            )
        ]

    if record_type == "application_resource_usage":
        source = _SOURCE_SRUM_APPLICATION_RUNTIME
        evidence_lines = [f"App: {app_identifier}"]
        if user_identifier:
            evidence_lines.append(f"User: {user_identifier}")
        if recorded_at is not None:
            evidence_lines.append(f"Recorded: {recorded_at}")
        if cpu_foreground_seconds is not None:
            evidence_lines.append(
                f"CPU foreground (s): {cpu_foreground_seconds}"
            )
        if cpu_background_seconds is not None:
            evidence_lines.append(
                f"CPU background (s): {cpu_background_seconds}"
            )
        if bytes_read is not None:
            evidence_lines.append(f"Bytes read: {bytes_read:,}")
        if bytes_written is not None:
            evidence_lines.append(f"Bytes written: {bytes_written:,}")
        evidence_lines.append(f"SRUM record type: {record_type}")
        evidence = "\n".join(evidence_lines)

        basename = (
            app_identifier.rsplit("\\", 1)[-1]
            if "\\" in app_identifier
            else app_identifier
        )
        description = (
            f"SRUM application resource record surfaces ~30-60 day "
            f"per-app runtime history for {basename}. LOW-confidence "
            f"review candidate; correlate the app path / runtime "
            f"signatures with threat-feeds for higher-confidence "
            f"verdicts in a follow-up triage."
        )

        return [
            _PEFindingDraft(
                source=source,
                severity=Severity.info,
                title=f"SRUM app runtime: {basename}",
                description=description,
                evidence=evidence,
            )
        ]

    return []


# ── Phase η.B.D — Scheduled Task persistence classifier ─────────────────────


@dataclass(frozen=True)
class _ScheduledTaskFindingDraft:
    """One Scheduled Task Finding row to emit. Carries an explicit
    confidence tier alongside the standard _PEFindingDraft fields so
    the emit hook can preserve the tier-mapping that
    classify_scheduled_task_persistence_findings derives from the
    parsed task data.

    Distinct from _PEFindingDraft (which fixes confidence at the emit
    site) because Scheduled Tasks have a heuristic-driven 3-tier
    map (HIGH on encoded-PS / MEDIUM on HighestAvailable + non-system
    Author / LOW baseline) — the same source value can land at any
    of the 3 tiers.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def classify_scheduled_task_persistence_findings(
    *,
    task_name: str,
    task_uri: str | None,
    author: str | None,
    run_level: str | None,
    run_as_user: str | None,
    triggers: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    source_path: str,
) -> list[_ScheduledTaskFindingDraft]:
    """Phase η.B.D — map one WindowsScheduledTask row to ONE
    persistence Finding draft.

    Pure function — no DB access. Each row yields at most ONE Finding
    draft; the confidence tier is heuristic-driven:

    - HIGH (Confidence.high) — Action contains encoded-PowerShell
      pattern (Qakbot signature: ``-EncodedCommand`` / ``-enc`` /
      ``FromBase64String`` / ``Invoke-Expression`` / ``[char[]]`` /
      ``DownloadString`` / ``IEX``). Detected via
      ``scheduled_task_walker.is_action_encoded_powershell``.
      Severity: high.
    - MEDIUM (Confidence.medium) — RunLevel=HighestAvailable AND
      non-system Author (Author NOT prefixed by "Microsoft").
      Detected via ``scheduled_task_walker.is_system_author``.
      Severity: medium.
    - LOW (Confidence.low) — baseline review-candidate row.
      Severity: info.

    Returns empty list when ``task_name`` is missing/empty
    (defensive boundary — the walker's _build_record contract
    requires task_name).

    Mirrors classify_srum_findings / classify_amcache_install_findings
    shape but with a tier-bearing draft type to preserve the
    tier-mapping at the emit site.
    """
    if not task_name:
        return []

    # Lazy import per Rule #30 to avoid scheduled_task_walker ↔
    # finding_service circular at module load. The two helpers are
    # pure-Python regex / string-prefix checks; the import overhead
    # is one-time per process.
    from app.services.scheduled_task_walker import (
        is_action_encoded_powershell,
        is_system_author,
    )

    # Dispatch tier — first match wins.
    encoded_ps_action: dict[str, Any] | None = None
    for act in actions or []:
        if not isinstance(act, dict):
            continue
        if is_action_encoded_powershell(
            act.get("command"), act.get("arguments")
        ):
            encoded_ps_action = act
            break

    confidence: Confidence
    severity: Severity
    tier_label: str
    if encoded_ps_action is not None:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = "HIGH (encoded-PowerShell action — Qakbot pattern)"
    elif run_level == "HighestAvailable" and not is_system_author(author):
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM (RunLevel=HighestAvailable + non-system Author)"
        )
    else:
        confidence = Confidence.low
        severity = Severity.info
        tier_label = "LOW (baseline review-candidate)"

    # Title surfaces task_name for fast operator triage; URI lives in
    # the evidence for full path reference.
    display_uri = task_uri or task_name

    evidence_lines = [
        f"Tier: {tier_label}",
        f"Task name: {task_name}",
        f"Task URI: {display_uri}",
    ]
    if author:
        evidence_lines.append(f"Author: {author}")
    if run_level:
        evidence_lines.append(f"RunLevel: {run_level}")
    if run_as_user:
        evidence_lines.append(f"RunAs: {run_as_user}")

    # Surface trigger types for forensic context (one line per trigger).
    if triggers:
        trigger_summary = ", ".join(
            t.get("type", "?")
            for t in triggers
            if isinstance(t, dict)
        )
        evidence_lines.append(f"Triggers: {trigger_summary}")

    # Surface the encoded-PS action explicitly when present (HIGH tier);
    # otherwise surface the first action's command for any-tier context.
    if encoded_ps_action is not None:
        cmd = encoded_ps_action.get("command", "")
        args = encoded_ps_action.get("arguments", "")
        # Truncate very long encoded-PS payloads for readability.
        args_truncated = (args[:200] + "…") if args and len(args) > 200 else args
        evidence_lines.append(f"Encoded-PS Command: {cmd}")
        if args_truncated:
            evidence_lines.append(f"Encoded-PS Arguments: {args_truncated}")
    elif actions:
        first_action = next(
            (a for a in actions if isinstance(a, dict)), None
        )
        if first_action is not None:
            cmd = first_action.get("command")
            if cmd:
                evidence_lines.append(f"Action Command: {cmd}")

    evidence_lines.append(f"Source path: {source_path}")
    evidence = "\n".join(evidence_lines)

    description = (
        f"Windows Scheduled Task persistence record surfaces task "
        f"{display_uri}"
    )
    if encoded_ps_action is not None:
        description += (
            " with encoded-PowerShell action shape (Qakbot pattern). "
            "HIGH-confidence persistence indicator — investigate the "
            "Action's <Command>/<Arguments> against threat-feeds."
        )
    elif confidence == Confidence.medium:
        description += (
            " running at RunLevel=HighestAvailable with a non-Microsoft "
            "Author. MEDIUM-confidence privilege-escalation candidate; "
            "verify the author identity and Action shape."
        )
    else:
        description += (
            ". LOW-confidence baseline review candidate; the row "
            "documents persistent task definition for forensic-timeline "
            "context."
        )

    return [
        _ScheduledTaskFindingDraft(
            source=_SOURCE_SCHEDULED_TASK_PERSISTENCE,
            severity=severity,
            title=f"Scheduled Task: {task_name}",
            description=description,
            evidence=evidence,
            confidence=confidence,
        )
    ]


# ── Phase η.C.D — LNK abnormal-target classifier ────────────────────────────


@dataclass(frozen=True)
class _LnkFindingDraft:
    """One LNK Finding row to emit. Carries an explicit confidence
    tier alongside the standard _PEFindingDraft fields so the emit
    hook can preserve the tier-mapping that
    classify_lnk_abnormal_target_findings derives from the parsed
    LNK metadata.

    Distinct from _PEFindingDraft (fixes confidence at emit site)
    and from _ScheduledTaskFindingDraft (different tier-mapping
    semantics) because LNKs have a heuristic-driven 3-tier map
    (HIGH on script-host + encoded-PS / MEDIUM on non-Microsoft
    target / LOW baseline) — the same source value can land at any
    of the 3 tiers.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def classify_lnk_abnormal_target_findings(
    *,
    lnk_filename: str,
    source_path: str,
    target_path: str | None,
    working_directory: str | None,
    arguments: str | None,
    description: str | None,
    show_command: str | None,
    hotkey: str | None,
) -> list[_LnkFindingDraft]:
    """Phase η.C.D — map one WindowsLnkRecord row to ONE
    persistence Finding draft.

    Pure function — no DB access. Each row yields at most ONE Finding
    draft; the confidence tier is heuristic-driven:

    - HIGH (Confidence.high) — target_path resolves to a known
      script-host binary (cmd / cscript / wscript / powershell /
      pwsh / mshta / regsvr32 / rundll32) AND arguments contain
      encoded-PowerShell pattern (Qakbot signature: ``-EncodedCommand``
      / ``-enc`` / ``FromBase64String`` / ``Invoke-Expression`` /
      ``[char[]]`` / ``DownloadString`` / ``IEX``). Detected via
      ``lnk_walker.is_script_host_target`` +
      ``lnk_walker.is_arguments_encoded_powershell``. Severity: high.
    - MEDIUM (Confidence.medium) — target_path is non-Microsoft (NOT
      under \\Windows\\, %SystemRoot%, %windir%, C:\\Program Files\\
      Microsoft *, C:\\ProgramData\\Microsoft\\, etc.). Detected via
      ``lnk_walker.is_microsoft_target`` returning False. LNKs
      targeting user-writable directories are atypical for legitimate
      Start Menu / Recent docs entries. Severity: medium.
    - LOW (Confidence.low) — baseline review-candidate row.
      Severity: info.

    Returns empty list when ``lnk_filename`` is missing/empty
    (defensive boundary — the walker's _build_record contract
    requires lnk_filename).

    Mirrors classify_scheduled_task_persistence_findings shape with
    a tier-bearing draft type to preserve the tier-mapping at the
    emit site.
    """
    if not lnk_filename:
        return []

    # Lazy import per Rule #30 to avoid lnk_walker ↔ finding_service
    # circular at module load. The three helpers are pure-Python
    # regex / prefix / set checks; the import overhead is one-time
    # per process.
    from app.services.lnk_walker import (
        is_arguments_encoded_powershell,
        is_microsoft_target,
        is_script_host_target,
    )

    # Dispatch tier — first match wins (HIGH > MEDIUM > LOW).
    has_script_host = is_script_host_target(target_path)
    has_encoded_ps = is_arguments_encoded_powershell(arguments)
    is_ms_target = is_microsoft_target(target_path)

    confidence: Confidence
    severity: Severity
    tier_label: str
    if has_script_host and has_encoded_ps:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            "HIGH (script-host target + encoded-PowerShell arguments — "
            "Qakbot / cobalt-strike pattern)"
        )
    elif target_path and not is_ms_target:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM (non-Microsoft target — atypical for legitimate "
            "Start Menu / Recent docs entries)"
        )
    else:
        confidence = Confidence.low
        severity = Severity.info
        tier_label = "LOW (baseline review-candidate)"

    evidence_lines = [
        f"Tier: {tier_label}",
        f"LNK filename: {lnk_filename}",
        f"Source path: {source_path}",
    ]
    if target_path:
        evidence_lines.append(f"Target path: {target_path}")
    if working_directory:
        evidence_lines.append(f"Working directory: {working_directory}")
    if arguments:
        # Truncate very long encoded-PS argument payloads for readability.
        args_truncated = (
            arguments[:200] + "…"
            if len(arguments) > 200
            else arguments
        )
        evidence_lines.append(f"Arguments: {args_truncated}")
    if description:
        evidence_lines.append(f"Description: {description}")
    if show_command:
        evidence_lines.append(f"ShowCommand: {show_command}")
    if hotkey and hotkey not in ("UNSET - UNSET {0x0000}", "UNSET"):
        evidence_lines.append(f"Hotkey: {hotkey}")

    evidence = "\n".join(evidence_lines)

    description_text = (
        f"Windows Shell Link (LNK) record surfaces shortcut "
        f"{lnk_filename}"
    )
    if has_script_host and has_encoded_ps:
        description_text += (
            " whose target resolves to a script-host binary AND whose "
            "arguments carry an encoded-PowerShell pattern. T1547.009 "
            "Shortcut Modification persistence — HIGH-confidence Qakbot "
            "/ cobalt-strike indicator. Investigate the resolved target "
            "+ Base64-decoded payload against threat-feeds."
        )
    elif confidence == Confidence.medium:
        description_text += (
            " pointing at a non-Microsoft target binary. MEDIUM-confidence "
            "candidate — verify the target's signing chain (Authenticode "
            "+ DBX) and review the LNK's source location for tampering."
        )
    else:
        description_text += (
            ". LOW-confidence baseline review candidate; the row "
            "documents shortcut metadata for forensic-timeline context."
        )

    return [
        _LnkFindingDraft(
            source=_SOURCE_LNK_ABNORMAL_TARGET,
            severity=severity,
            title=f"LNK: {lnk_filename}",
            description=description_text,
            evidence=evidence,
            confidence=confidence,
        )
    ]


# ── Phase η.A.D — MFT hidden-content + timestomp classifier ────────────────


@dataclass(frozen=True)
class _MFTFindingDraft:
    """One MFT Finding row to emit. Carries an explicit confidence
    tier alongside the standard fields so the emit hook can preserve
    the tier-mapping derived from the MFT record's ADS roster +
    $SI/$FN comparison.

    Distinct from _PEFindingDraft (fixes confidence at emit site)
    and _LnkFindingDraft (different tier semantics) because MFT rows
    have TWO independent detection patterns (ADS-hidden + timestomp)
    that can BOTH fire on the same record — the classifier may emit
    0, 1, or 2 drafts per row.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def _classify_mft_ads_hidden(
    *,
    filename: str | None,
    source_path: str,
    full_path: str | None,
    ads_streams: list[dict],
) -> list[_MFTFindingDraft]:
    """Emit one Finding per non-trivial named ADS stream on the record.

    Skips Zone.Identifier MOTW tag (size ≤ _MFT_ADS_MEDIUM_CONFIDENCE_BYTES).
    Confidence tier mapping:
    - HIGH — ADS size > _MFT_ADS_HIGH_CONFIDENCE_BYTES (16 KB).
    - MEDIUM — ADS size between MEDIUM and HIGH thresholds.

    Pure function — no DB access. Returns empty list when ads_streams
    is empty / contains only benign tags.
    """
    drafts: list[_MFTFindingDraft] = []
    if not ads_streams:
        return drafts

    display_name = filename or full_path or source_path
    for stream in ads_streams:
        if not isinstance(stream, dict):
            continue
        stream_name = str(stream.get("name") or "").strip()
        try:
            stream_size = int(stream.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if not stream_name:
            continue
        if stream_size < _MFT_ADS_MEDIUM_CONFIDENCE_BYTES:
            # Zone.Identifier MOTW tag + similar metadata-only streams.
            continue

        if stream_size > _MFT_ADS_HIGH_CONFIDENCE_BYTES:
            confidence = Confidence.high
            severity = Severity.high
            tier_label = (
                f"HIGH (named ADS '{stream_name}' size {stream_size} B > "
                f"{_MFT_ADS_HIGH_CONFIDENCE_BYTES} B — ProcessHollower / "
                f"Pegasus / generic AV-evasion drop pattern)"
            )
        else:
            confidence = Confidence.medium
            severity = Severity.medium
            tier_label = (
                f"MEDIUM (named ADS '{stream_name}' size {stream_size} B "
                f"— small payload or metadata)"
            )

        evidence_lines = [
            f"Tier: {tier_label}",
            f"Source image: {source_path}",
            f"MFT path: {full_path or '(orphan)'}",
            f"Filename: {filename or '(unnamed)'}",
            f"ADS name: {stream_name}",
            f"ADS size: {stream_size} B",
        ]

        drafts.append(
            _MFTFindingDraft(
                source=_SOURCE_MFT_ADS_HIDDEN_CONTENT,
                severity=severity,
                title=f"MFT hidden ADS: {display_name}:{stream_name}",
                description=(
                    f"Windows NTFS MFT record for {display_name} carries "
                    f"a non-trivial named Alternate Data Stream "
                    f"'{stream_name}'. ADS payloads of this size are "
                    "atypical for legitimate Zone.Identifier MOTW tags "
                    "(~100 B) and are a known persistence + AV-evasion "
                    "channel. Investigate the ADS content (T1564.004 "
                    "Hide Artifacts: NTFS File Attributes)."
                ),
                evidence="\n".join(evidence_lines),
                confidence=confidence,
            )
        )

    return drafts


def _classify_mft_timestomp(
    *,
    filename: str | None,
    source_path: str,
    full_path: str | None,
    si_creation_ns: int | None,
    si_last_modification_ns: int | None,
    si_last_change_ns: int | None,
    si_last_access_ns: int | None,
    fn_creation_ns: int | None,
    fn_last_modification_ns: int | None,
    fn_last_change_ns: int | None,
    fn_last_access_ns: int | None,
) -> list[_MFTFindingDraft]:
    """Emit one Finding when $SI mtime < $FN mtime on the record.

    Confidence tier mapping:
    - HIGH — ALL FOUR $SI timestamps strictly older than ALL FOUR $FN
      timestamps. timestomp.exe rewrites the full $SI tuple; matching
      every pair is the strongest signal.
    - MEDIUM — $SI mtime alone is older than $FN mtime (the canonical
      single-pair check).

    Pure function — no DB access. Returns empty list when either
    timestamp tuple is missing (we don't fire on partial data).
    """
    # Require at minimum SI mtime + FN mtime; the single-pair check
    # is the canonical timestomp signal.
    if (
        si_last_modification_ns is None
        or fn_last_modification_ns is None
    ):
        return []

    if si_last_modification_ns >= fn_last_modification_ns:
        # Not a timestomp candidate — SI should be ≥ FN in healthy data
        # because the kernel updates SI on every metadata change but
        # only updates FN on create/rename.
        return []

    # Check whether ALL FOUR pairs match the inversion shape (HIGH).
    full_si = (
        si_creation_ns,
        si_last_modification_ns,
        si_last_change_ns,
        si_last_access_ns,
    )
    full_fn = (
        fn_creation_ns,
        fn_last_modification_ns,
        fn_last_change_ns,
        fn_last_access_ns,
    )
    all_four_inverted = all(
        si is not None and fn is not None and si < fn
        for si, fn in zip(full_si, full_fn, strict=False)
    )

    if all_four_inverted:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            "HIGH (ALL FOUR $SI timestamps strictly older than $FN — "
            "timestomp.exe-style full-tuple rewrite signal)"
        )
    else:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM ($SI mtime older than $FN mtime — single-pair "
            "timestomp signal)"
        )

    display_name = filename or full_path or source_path
    evidence_lines = [
        f"Tier: {tier_label}",
        f"Source image: {source_path}",
        f"MFT path: {full_path or '(orphan)'}",
        f"Filename: {filename or '(unnamed)'}",
        f"$SI mtime (ns): {si_last_modification_ns}",
        f"$FN mtime (ns): {fn_last_modification_ns}",
        f"$SI - $FN delta (ns): "
        f"{si_last_modification_ns - fn_last_modification_ns}",
    ]
    if all_four_inverted:
        evidence_lines.append("All four $SI/$FN pairs inverted.")

    return [
        _MFTFindingDraft(
            source=_SOURCE_MFT_TIMESTOMPING,
            severity=severity,
            title=f"MFT timestomp: {display_name}",
            description=(
                f"Windows NTFS MFT record for {display_name} shows "
                "$STANDARD_INFORMATION mtime older than $FILE_NAME "
                "mtime. The kernel writes $SI on every metadata "
                "change but $FN only on create/rename — a healthy "
                "record has $SI ≥ $FN. Inversion indicates an "
                "anti-forensics rewrite (timestomp.exe / SetMACE / "
                "PowerShell SetCreation — T1070.006 Indicator Removal: "
                "Timestomp)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        )
    ]


def classify_mft_findings(
    *,
    filename: str | None,
    source_path: str,
    full_path: str | None,
    ads_streams: list[dict] | None,
    si_creation_ns: int | None,
    si_last_modification_ns: int | None,
    si_last_change_ns: int | None,
    si_last_access_ns: int | None,
    fn_creation_ns: int | None,
    fn_last_modification_ns: int | None,
    fn_last_change_ns: int | None,
    fn_last_access_ns: int | None,
) -> list[_MFTFindingDraft]:
    """Phase η.A.D — map one WindowsMftRecord row to 0+ Finding drafts.

    Pure function — no DB access. Each row may yield 0 (no signal),
    1 (single detection pattern), or 2 (both ADS + timestomp) drafts.
    The two detection patterns are independent — a record can carry
    both a hidden ADS stream AND a timestomp-style $SI/$FN inversion.

    Mirrors classify_lnk_abnormal_target_findings shape with a tier-
    bearing draft type to preserve the tier-mapping at the emit site.
    """
    drafts: list[_MFTFindingDraft] = []

    drafts.extend(
        _classify_mft_ads_hidden(
            filename=filename,
            source_path=source_path,
            full_path=full_path,
            ads_streams=ads_streams or [],
        )
    )
    drafts.extend(
        _classify_mft_timestomp(
            filename=filename,
            source_path=source_path,
            full_path=full_path,
            si_creation_ns=si_creation_ns,
            si_last_modification_ns=si_last_modification_ns,
            si_last_change_ns=si_last_change_ns,
            si_last_access_ns=si_last_access_ns,
            fn_creation_ns=fn_creation_ns,
            fn_last_modification_ns=fn_last_modification_ns,
            fn_last_change_ns=fn_last_change_ns,
            fn_last_access_ns=fn_last_access_ns,
        )
    )

    return drafts


# ── Phase θ.A.D — BCD walker classifier ────────────────────────────────────


@dataclass(frozen=True)
class _BCDFindingDraft:
    """One BCD Finding row to emit. Carries an explicit confidence
    tier alongside the standard fields so the emit hook can preserve
    the tier-mapping derived from the BCD entry's anomaly_flags shape.

    Distinct from _PEFindingDraft (fixes confidence at emit site) and
    _LnkFindingDraft / _MFTFindingDraft (different tier semantics)
    because BCD rows have TWO independent detection patterns
    (suspicious_path + testsigning_enabled) that can BOTH fire on
    the same entry — the classifier may emit 0, 1, or 2 drafts per
    row.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def _classify_bcd_suspicious_path(
    *,
    object_guid: str,
    source_path: str,
    description: str | None,
    image_path: str | None,
    anomaly_flags: dict,
) -> list[_BCDFindingDraft]:
    """Emit one Finding when anomaly_flags.suspicious_path is True.

    Confidence tier mapping:
    - HIGH — suspicious_path AND (non_microsoft_description OR
      testsigning_enabled). Strong bootkit signal — BlackLotus /
      Bootkitty / CosmicStrand / MoonBounce shape.
    - MEDIUM — suspicious_path alone. Could be a legitimate
      non-Microsoft OS (Ubuntu, FreeBSD); operator triages by
      description.

    Pure function — no DB access. Returns empty list when
    anomaly_flags.suspicious_path is False (no signal).
    """
    if not anomaly_flags.get("suspicious_path"):
        return []

    high_tier = (
        anomaly_flags.get("non_microsoft_description")
        or anomaly_flags.get("testsigning_enabled")
    )

    if high_tier:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            "HIGH (suspicious_path AND (non_microsoft_description OR "
            "testsigning_enabled) — strong T1542.003 bootkit signal)"
        )
    else:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM (suspicious_path alone — could be legitimate "
            "non-Microsoft OS; triage by description)"
        )

    evidence_lines = [
        f"Tier: {tier_label}",
        f"Source store: {source_path}",
        f"BCD object GUID: {object_guid}",
        f"Description: {description or '(unset)'}",
        f"Image path: {image_path or '(unset)'}",
        f"Anomaly flags: {dict(anomaly_flags)}",
    ]

    return [
        _BCDFindingDraft(
            source=_SOURCE_BCD_SUSPICIOUS_PATH,
            severity=severity,
            title=f"BCD suspicious bootloader path: {description or object_guid}",
            description=(
                f"Windows BCD entry {object_guid} references a "
                "bootloader binary at a non-Microsoft path. Healthy "
                "Windows BCD entries reference paths under \\Windows\\, "
                "\\Boot\\, or \\EFI\\Microsoft\\. A suspicious image_path "
                "is the classic T1542.003 Pre-OS Boot: Bootkit "
                "persistence indicator (BlackLotus, Bootkitty, "
                "CosmicStrand, MoonBounce). Cross-reference the path "
                "against the Authenticode chain (β.4) and DBX "
                "revocation list (β.10)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        )
    ]


def _classify_bcd_testsigning(
    *,
    object_guid: str,
    source_path: str,
    description: str | None,
    image_path: str | None,
    anomaly_flags: dict,
) -> list[_BCDFindingDraft]:
    """Emit one Finding when anomaly_flags.testsigning_enabled is True.

    Confidence tier mapping:
    - HIGH — testsigning_enabled AND (no_integrity_checks OR
      nx_disabled). Multiple security-relevant policy bits flipped at
      once is the canonical BYOVD-precursor shape.
    - MEDIUM — testsigning_enabled alone. Could be a developer /
      driver-debug context; operator triages by host shape.

    Pure function — no DB access. Returns empty list when
    anomaly_flags.testsigning_enabled is False.
    """
    if not anomaly_flags.get("testsigning_enabled"):
        return []

    high_tier = (
        anomaly_flags.get("no_integrity_checks")
        or anomaly_flags.get("nx_disabled")
    )

    if high_tier:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            "HIGH (testsigning_enabled AND (no_integrity_checks OR "
            "nx_disabled) — multiple security-policy bits flipped; "
            "canonical BYOVD-precursor shape)"
        )
    else:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM (testsigning_enabled alone — could be developer "
            "/ driver-debug; triage by host shape)"
        )

    evidence_lines = [
        f"Tier: {tier_label}",
        f"Source store: {source_path}",
        f"BCD object GUID: {object_guid}",
        f"Description: {description or '(unset)'}",
        f"Image path: {image_path or '(unset)'}",
        f"Anomaly flags: {dict(anomaly_flags)}",
    ]

    return [
        _BCDFindingDraft(
            source=_SOURCE_BCD_TESTSIGNING_ENABLED,
            severity=severity,
            title=(
                f"BCD TestSigning enabled: {description or object_guid}"
            ),
            description=(
                f"Windows BCD entry {object_guid} carries the "
                "TestSigning=True policy flag (BCD element "
                "0x16000010). Production Windows installations have "
                "TestSigning=False; an enabled flag indicates either "
                "a developer/driver-debug system OR a bootkit "
                "precursor (test-signed drivers bypass Authenticode "
                "validation — the BYOVD attack pattern). "
                "Cross-reference against installed drivers + the "
                "η.D LOLDrivers BYOVD fingerprint scan."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        )
    ]


def classify_bcd_findings(
    *,
    object_guid: str,
    source_path: str,
    description: str | None,
    image_path: str | None,
    anomaly_flags: dict,
) -> list[_BCDFindingDraft]:
    """Phase θ.A.D — map one WindowsBcdEntry row to 0+ Finding drafts.

    Pure function — no DB access. Each row may yield 0 (no signal),
    1 (single detection pattern), or 2 (both suspicious_path +
    testsigning_enabled) drafts. The two detection patterns are
    independent — a record can carry both a suspicious image_path
    AND a TestSigning=True policy.

    Mirrors classify_lnk_abnormal_target_findings / classify_mft_findings
    shape with a tier-bearing draft type to preserve the tier-mapping
    at the emit site.
    """
    drafts: list[_BCDFindingDraft] = []

    drafts.extend(
        _classify_bcd_suspicious_path(
            object_guid=object_guid,
            source_path=source_path,
            description=description,
            image_path=image_path,
            anomaly_flags=anomaly_flags,
        )
    )
    drafts.extend(
        _classify_bcd_testsigning(
            object_guid=object_guid,
            source_path=source_path,
            description=description,
            image_path=image_path,
            anomaly_flags=anomaly_flags,
        )
    )

    return drafts


# ── Phase θ.B.E — WMI persistence classifier ────────────────────────────────


# Encoded-PowerShell tokens (case-insensitive). Same set as
# wmi_walker.contains_encoded_powershell — kept duplicated for the
# classifier's pure-function shape (no cross-module dependency on
# the walker module at import time per Rule #30).
_WMI_ENCODED_PS_PATTERNS: tuple[str, ...] = (
    "-encodedcommand",
    "-enc ",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "iex ",
    "[char[]]",
    "[convert]::frombase64",
)

_WMI_SCRIPT_HOST_TOKENS: tuple[str, ...] = (
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "cmd.exe",
)


@dataclass(frozen=True)
class _WMIFindingDraft:
    """One WMI Finding row to emit. Carries an explicit confidence
    tier alongside the standard fields so the emit hook can preserve
    the tier-mapping derived from the WMI binding's anomaly_flags
    shape + consumer_type.

    Mirrors _BCDFindingDraft / _LnkFindingDraft / _MFTFindingDraft —
    tier-bearing draft preserved through the emit boundary so the
    FindingCreate.confidence is heuristic-driven, not fixed at low.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def _wmi_consumer_payload_aggregate_str(
    consumer_payload: list | None,
) -> str:
    """Build a single concatenated string from the consumer_payload
    JSONB list for keyword matching."""
    if not consumer_payload:
        return ""
    parts: list[str] = []
    for entry in consumer_payload:
        if not isinstance(entry, dict):
            continue
        parts.append(str(entry.get("consumer_type", "")))
        parts.append(str(entry.get("arguments", "")))
        parts.append(str(entry.get("other", "")))
    return " ".join(parts)


def _wmi_contains_encoded_powershell(payload: str) -> bool:
    if not payload:
        return False
    lower = payload.lower()
    return any(p in lower for p in _WMI_ENCODED_PS_PATTERNS)


def _wmi_references_script_host(payload: str) -> bool:
    if not payload:
        return False
    lower = payload.lower()
    return any(t in lower for t in _WMI_SCRIPT_HOST_TOKENS)


def classify_wmi_findings(
    *,
    binding_id: str,
    filter_name: str,
    filter_query: str | None,
    consumer_name: str,
    consumer_type: str,
    consumer_payload: list | None,
    source_path: str,
    probably_benign: bool,
) -> list[_WMIFindingDraft]:
    """Phase θ.B.E — map one WindowsWmiEvent row to 0 or 1 Finding
    drafts.

    Pure function — no DB access. Returns empty list on benign
    bindings (BVTConsumer-BVTFilter, SCM Event Log) — those are
    skipped entirely from Finding emission since they ship with
    Windows.

    Returns 1 draft on non-benign bindings with confidence tier
    derived from the binding shape:

    - HIGH — ActiveScriptEventConsumer (in-process script execution
      is the highest-impact WMI consumer type), OR consumer_payload
      carries encoded-PowerShell pattern. Severity: high.
    - MEDIUM — CommandLineEventConsumer + script-host invocation.
      LOLBin-via-WMI shape. Severity: medium.
    - LOW — baseline review-candidate row. Severity: low.

    Mirrors classify_lnk_abnormal_target_findings shape (one draft
    per row, tier-bearing).
    """
    if probably_benign:
        return []

    payload_str = _wmi_consumer_payload_aggregate_str(consumer_payload)
    has_encoded_ps = _wmi_contains_encoded_powershell(payload_str)
    has_script_host = _wmi_references_script_host(payload_str)
    is_active_script = consumer_type == "ActiveScriptEventConsumer"
    is_command_line = consumer_type == "CommandLineEventConsumer"

    if is_active_script or has_encoded_ps:
        confidence = Confidence.high
        severity = Severity.high
        if is_active_script and has_encoded_ps:
            tier_label = (
                "HIGH (ActiveScriptEventConsumer + encoded-PowerShell "
                "— maximum-impact bootkit/persistence indicator)"
            )
        elif is_active_script:
            tier_label = (
                "HIGH (ActiveScriptEventConsumer — in-process "
                "VBScript/JScript execution; T1546.003 strong signal)"
            )
        else:
            tier_label = (
                "HIGH (encoded-PowerShell pattern — Qakbot tradecraft "
                "signature in WMI consumer payload)"
            )
    elif is_command_line and has_script_host:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            "MEDIUM (CommandLineEventConsumer + script-host "
            "invocation — LOLBin-via-WMI shape)"
        )
    else:
        confidence = Confidence.low
        severity = Severity.low
        tier_label = (
            "LOW (non-benign FilterToConsumerBinding — baseline "
            "review candidate; operator triage by consumer payload)"
        )

    # Truncate payload preview to keep evidence under 2000 chars.
    payload_preview = payload_str[:1500] if payload_str else "(empty)"

    evidence_lines = [
        f"Tier: {tier_label}",
        f"Source repository: {source_path}",
        f"Binding ID: {binding_id}",
        f"Filter name: {filter_name}",
        f"Filter query: {filter_query or '(unset)'}",
        f"Consumer name: {consumer_name}",
        f"Consumer type: {consumer_type}",
        f"Consumer payload (DATA — never executed): {payload_preview}",
    ]

    return [
        _WMIFindingDraft(
            source=_SOURCE_WMI_PERSISTENCE,
            severity=severity,
            title=(
                f"WMI persistence binding: {binding_id}"
            ),
            description=(
                "Windows WMI FilterToConsumerBinding detected — "
                "the canonical T1546.003 Event-Triggered Execution: "
                "WMI Event Subscription persistence mechanism. The "
                "WMI service runs from boot, the binding survives "
                "reboot via the repository's MAPPING*.MAP "
                "allocation, and the binding fires WITHOUT spawning "
                "a visible process (the WmiPrvSE.exe host runs the "
                "consumer payload in-process). Notable adversary "
                "tradecraft: APT29 (PowerShell consumer), APT32 "
                "(JScript consumer), Turla (timer-based bindings), "
                "FIN7 (Carbanak), ransomware affiliates (Conti, "
                "BlackCat — pre-encryption staging). The consumer "
                "payload is surfaced as DATA in the WindowsWmiEvent "
                "row + this evidence field; wairz NEVER invokes the "
                "payload (Rule #36 no-execute discipline)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        )
    ]


# ── Phase θ.C.D — ESP `.efi` PE chain classifier ────────────────────────────


@dataclass(frozen=True)
class _ESPFindingDraft:
    """One ESP `.efi` Finding row to emit. Carries an explicit
    confidence tier alongside the standard fields so the emit hook can
    preserve the tier-mapping derived from the entry's
    authenticode_state + anomaly_flags shape.

    Mirrors _WMIFindingDraft / _BCDFindingDraft — tier-bearing draft
    preserved through the emit boundary so the FindingCreate.confidence
    is heuristic-driven, not fixed at low.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def classify_esp_findings(
    *,
    file_path: str,
    file_sha256: str,
    file_size: int,
    authenticode_state: str,
    anomaly_flags: dict,
    chain_dict: dict | None,
    dbx_match_dict: dict | None,
) -> list[_ESPFindingDraft]:
    """Phase θ.C.D — map one WindowsEspEntry row to 0, 1, or 2
    Finding drafts.

    Pure function — no DB access. Returns:

    - 0 drafts on signed_valid `.efi` files (no anomaly to surface).
    - 1 draft (``windows_esp_unsigned``) on unsigned `.efi` whose
      path matches known-bootloader OR vendor paths. Tier:
      - HIGH — unsigned AND is_known_bootloader_path (BlackLotus
        canonical shape).
      - MEDIUM — unsigned AND is_vendor_path.
      - (Skipped if is_unsigned but NOT under EFI/ canonical OR
        vendor paths — generic .efi utility, not a bootkit signal.)
    - 1 draft (``windows_esp_dbx_revoked``) on signed_revoked `.efi`.
      Tier: HIGH always — DBX revocation is the authoritative signal.
    - 2 drafts possible if a `.efi` is BOTH unsigned AND DBX-revoked
      (rare — DBX matches need a signature to match against; but the
      classifier is conservative and emits both if both states fire).

    Mirrors classify_lnk_abnormal_target_findings / classify_bcd_findings
    shape — tier-bearing drafts, one per detection pattern.
    """
    drafts: list[_ESPFindingDraft] = []

    is_unsigned = bool(anomaly_flags.get("is_unsigned"))
    is_known_bootloader = bool(anomaly_flags.get("is_known_bootloader_path"))
    is_vendor = bool(anomaly_flags.get("is_vendor_path"))
    is_suspiciously_small = bool(anomaly_flags.get("is_suspiciously_small"))
    is_non_ms_signer = bool(anomaly_flags.get("is_non_microsoft_signer"))

    # ── windows_esp_unsigned draft ─────────────────────────────────────────
    if is_unsigned and (is_known_bootloader or is_vendor):
        if is_known_bootloader:
            confidence = Confidence.high
            severity = Severity.high
            tier_label = (
                "HIGH (unsigned `.efi` in canonical OS-bootloader path "
                "— BlackLotus / Bootkitty bootkit canonical shape)"
            )
        else:
            confidence = Confidence.medium
            severity = Severity.medium
            tier_label = (
                "MEDIUM (unsigned `.efi` in vendor EFI/<vendor>/ path "
                "— non-standard signed-via-shim layout or vendor "
                "utility; operator triages)"
            )

        evidence_lines = [
            f"Tier: {tier_label}",
            f"File path: {file_path}",
            f"File SHA256: {file_sha256}",
            f"File size: {file_size} bytes",
            f"Authenticode state: {authenticode_state}",
            f"Known-bootloader path: {is_known_bootloader}",
            f"Vendor path: {is_vendor}",
            f"Suspiciously small (<4 KB): {is_suspiciously_small}",
        ]
        if chain_dict and chain_dict.get("error"):
            evidence_lines.append(
                f"Authenticode parse note: {chain_dict['error']}"
            )

        drafts.append(_ESPFindingDraft(
            source=_SOURCE_ESP_UNSIGNED,
            severity=severity,
            title=(
                f"Unsigned ESP bootloader: "
                f"{file_path.rsplit('/', 1)[-1]}"
            ),
            description=(
                "An EFI binary in the EFI System Partition (ESP) "
                "carries no Authenticode signature. The ESP is "
                "mounted by the UEFI firmware BEFORE any OS code "
                "runs; an unsigned bootloader at a canonical path "
                "(EFI/Boot/bootx64.efi, EFI/Microsoft/Boot/"
                "bootmgfw.efi, etc.) is the canonical T1542.003 "
                "Pre-OS Boot: Bootkit signal. Adversary tradecraft: "
                "BlackLotus (CVE-2022-21894 ESP bootkit), Bootkitty "
                "(ESET Nov 2024 Linux UEFI bootkit), CosmicStrand "
                "(Kaspersky 2022 ESP-resident UEFI implant), "
                "MoonBounce (Kaspersky 2021 ESP modification). The "
                "PE is surfaced as DATA in WindowsEspEntry."
                "authenticode_chain + this evidence field; wairz "
                "NEVER invokes the `.efi` binary (Rule #36 no-"
                "execute discipline)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        ))

    # ── windows_esp_dbx_revoked draft ──────────────────────────────────────
    if authenticode_state == "signed_revoked":
        confidence = Confidence.high
        severity = Severity.high

        revocation_kb: str | None = None
        match_kind: str = "x509_serial"
        if isinstance(dbx_match_dict, dict):
            revocation_kb = dbx_match_dict.get("revocation_kb")
            match_kind = dbx_match_dict.get("match_kind", "x509_serial")

        chain_status: str | None = None
        signer_subject: str | None = None
        leaf_serial: str | None = None
        if isinstance(chain_dict, dict):
            chain_status = chain_dict.get("chain_status")
            signer_subject = chain_dict.get("signer_subject")
            leaf_serial = chain_dict.get("leaf_serial")

        evidence_lines = [
            "Tier: HIGH (DBX revocation hit — Microsoft has explicitly "
            "revoked this bootloader; on Secure Boot enforcement it "
            "fails at load time)",
            f"File path: {file_path}",
            f"File SHA256: {file_sha256}",
            f"File size: {file_size} bytes",
            f"Authenticode state: {authenticode_state}",
            f"Chain status: {chain_status or '(unset)'}",
            f"Signer subject: {signer_subject or '(unset)'}",
            f"Leaf serial: {leaf_serial or '(unset)'}",
            f"DBX match kind: {match_kind}",
            f"DBX revocation KB: {revocation_kb or '(unset)'}",
            f"Non-Microsoft signer: {is_non_ms_signer}",
        ]

        drafts.append(_ESPFindingDraft(
            source=_SOURCE_ESP_DBX_REVOKED,
            severity=severity,
            title=(
                f"DBX-revoked ESP bootloader: "
                f"{file_path.rsplit('/', 1)[-1]}"
            ),
            description=(
                "An EFI binary in the EFI System Partition (ESP) is "
                "Authenticode-signed, but its leaf certificate (or "
                "file hash) appears in Microsoft's UEFI Secure Boot "
                "revocation list (dbxupdate.bin — β.10 offline trust "
                "anchor). Under Secure Boot enforcement on a current-"
                "patch UEFI install, this binary would FAIL at load "
                "time. Notable known-revoked classes: BlackLotus "
                "(Microsoft revocation Aug 2023), GRUB2 BootHole "
                "(CVE-2020-10713 revocation), older boot-shim "
                "binaries pre-2022. The PE is surfaced as DATA in "
                "WindowsEspEntry.authenticode_chain + dbx_revocation_"
                "match + this evidence field; wairz NEVER invokes "
                "the `.efi` binary (Rule #36 no-execute discipline)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        ))

    return drafts


# ── Phase θ.E.D — MBR/VBR boot-sector classifier ────────────────────────────


@dataclass(frozen=True)
class _MBRVBRFindingDraft:
    """One MBR/VBR boot-sector Finding row to emit. Carries an explicit
    confidence tier alongside the standard fields so the emit hook can
    preserve the tier-mapping derived from known_bootkit_match +
    anomaly_flags shape.

    Mirrors _ESPFindingDraft / _BCDFindingDraft / _WMIFindingDraft —
    tier-bearing draft preserved through the emit boundary so the
    FindingCreate.confidence is heuristic-driven, not fixed at low.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


# Anomaly flag keys that count toward the "modified VBR" classifier
# threshold (excludes the is_mbr / is_vbr convenience booleans).
_MBR_VBR_ANOMALY_FLAG_KEYS: tuple[str, ...] = (
    "non_zero_padding",
    "unexpected_partition_table",
    "non_standard_jmp",
)


def _count_mbr_vbr_anomalies(anomaly_flags: dict) -> int:
    """Count anomaly flags raised on a sector. Pure function."""
    return sum(
        1
        for key in _MBR_VBR_ANOMALY_FLAG_KEYS
        if bool(anomaly_flags.get(key))
    )


def classify_mbr_vbr_findings(
    *,
    file_path: str,
    sector_offset: int,
    sector_kind: str,
    sector_sha256: str,
    sector_size: int,
    bootcode_signature_match: str | None,
    known_bootkit_match: str | None,
    anomaly_flags: dict,
) -> list[_MBRVBRFindingDraft]:
    """Phase θ.E.D — map one WindowsMbrVbrSector row to 0, 1, or 2
    Finding drafts.

    Pure function — no DB access. Returns:

    - 0 drafts for a clean Windows MBR/VBR with known-good signature
      match AND no bootkit match AND no anomalies.
    - 1 draft (``windows_mbr_bootkit``) on sector_kind=mbr with
      known_bootkit_match populated. Tier: HIGH always.
    - 1 draft (``windows_vbr_anomaly``) on sector_kind=vbr_* with
      known_bootkit_match populated OR
      (bootcode_signature_match is NULL AND >=2 anomaly flags).
      Tier: HIGH if known_bootkit_match populated, MEDIUM otherwise.
    - 2 drafts not possible — MBR-kind emits at most windows_mbr_bootkit;
      VBR-kind emits at most windows_vbr_anomaly. The kinds are
      mutually exclusive on a single sector.

    Mirrors classify_esp_findings / classify_bcd_findings shape —
    tier-bearing drafts, one per detection pattern.
    """
    drafts: list[_MBRVBRFindingDraft] = []

    # ── windows_mbr_bootkit draft ──────────────────────────────────────────
    if sector_kind == "mbr" and known_bootkit_match:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            f"HIGH (named bootkit '{known_bootkit_match}' — direct "
            "T1542.003 Pre-OS Boot: Bootkit signal at the BIOS / "
            "legacy boot layer)"
        )

        anomalies_raised = _count_mbr_vbr_anomalies(anomaly_flags)
        evidence_lines = [
            f"Tier: {tier_label}",
            f"File path: {file_path}",
            f"Sector offset: {sector_offset}",
            f"Sector kind: {sector_kind}",
            f"Sector SHA256: {sector_sha256}",
            f"Sector size: {sector_size} bytes",
            f"Known bootkit match: {known_bootkit_match}",
            f"Bootcode signature match: "
            f"{bootcode_signature_match or '(none)'}",
            f"Anomaly flags raised: {anomalies_raised}",
            f"non_zero_padding: "
            f"{bool(anomaly_flags.get('non_zero_padding'))}",
            f"unexpected_partition_table: "
            f"{bool(anomaly_flags.get('unexpected_partition_table'))}",
            f"non_standard_jmp: "
            f"{bool(anomaly_flags.get('non_standard_jmp'))}",
        ]

        drafts.append(_MBRVBRFindingDraft(
            source=_SOURCE_MBR_BOOTKIT,
            severity=severity,
            title=(
                f"MBR bootkit detected: {known_bootkit_match} "
                f"in {os.path.basename(file_path) or file_path}"
            ),
            description=(
                "The Master Boot Record (MBR — first 512 bytes of "
                "the disk image, with bytes 0..445 as 16-bit x86 "
                "boot code) matches a known malicious bootkit "
                f"signature ('{known_bootkit_match}'). The MBR is "
                "loaded by the CPU BIOS at 0x7C00 BEFORE any OS "
                "code runs; adversary modification achieves Ring -2 "
                "persistence that survives reboot at the highest "
                "possible privilege level. Adversary tradecraft: "
                "TDL4/TDSS (Kaspersky 2011 — MBR + driver hijack), "
                "Petya/NotPetya (2016-2017 ransomware MBR replacement), "
                "Mebroot/Sinowal (2008-2010 banking-trojan MBR "
                "modification), Olmasco (2011-2013 MBR variant with "
                "VBR-overwrite), BlackEnergy 3 (2015-2016 Ukrainian "
                "grid attack — KillDisk MBR-wipe). The boot code is "
                "surfaced as DATA in WindowsMbrVbrSector.sector_sha256 "
                "+ this evidence field; wairz NEVER invokes the boot "
                "sector code (Rule #36 no-execute discipline)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=confidence,
        ))

    # ── windows_vbr_anomaly draft ──────────────────────────────────────────
    if sector_kind.startswith("vbr_"):
        anomalies_raised = _count_mbr_vbr_anomalies(anomaly_flags)
        emit_high = bool(known_bootkit_match)
        emit_medium = (
            bootcode_signature_match is None and anomalies_raised >= 2
        )

        if emit_high or emit_medium:
            if emit_high:
                confidence = Confidence.high
                severity = Severity.high
                tier_label = (
                    f"HIGH (named VBR bootkit '{known_bootkit_match}' "
                    "— Mebroot/Olmasco VBR variant or similar)"
                )
            else:
                confidence = Confidence.medium
                severity = Severity.medium
                tier_label = (
                    "MEDIUM (modified VBR without a named bootkit "
                    f"match — bootcode_signature_match=NULL AND "
                    f"{anomalies_raised} anomaly flags raised; "
                    "supply-chain compromise candidate; operator "
                    "triages)"
                )

            evidence_lines = [
                f"Tier: {tier_label}",
                f"File path: {file_path}",
                f"Sector offset: {sector_offset}",
                f"Sector kind: {sector_kind}",
                f"Sector SHA256: {sector_sha256}",
                f"Sector size: {sector_size} bytes",
                f"Known bootkit match: "
                f"{known_bootkit_match or '(none)'}",
                f"Bootcode signature match: "
                f"{bootcode_signature_match or '(none)'}",
                f"Anomaly flags raised: {anomalies_raised}",
                f"non_zero_padding: "
                f"{bool(anomaly_flags.get('non_zero_padding'))}",
                f"unexpected_partition_table: "
                f"{bool(anomaly_flags.get('unexpected_partition_table'))}",
                f"non_standard_jmp: "
                f"{bool(anomaly_flags.get('non_standard_jmp'))}",
            ]

            drafts.append(_MBRVBRFindingDraft(
                source=_SOURCE_VBR_ANOMALY,
                severity=severity,
                title=(
                    f"VBR anomaly: {sector_kind} at offset "
                    f"{sector_offset} in "
                    f"{os.path.basename(file_path) or file_path}"
                ),
                description=(
                    "A Volume Boot Record (VBR — first sector of a "
                    "FAT/NTFS partition, containing the partition-"
                    "format BIOS Parameter Block plus partition "
                    "bootloader code) shows signs of adversary "
                    "modification. The VBR runs after the MBR JMPs "
                    "to the active partition's first sector but "
                    "BEFORE the OS bootmgr; a modified VBR achieves "
                    "the same Ring -2 persistence shape as a "
                    "modified MBR. Known VBR-modifying tradecraft: "
                    "Mebroot VBR variant (2008-2010 banking trojan), "
                    "Olmasco's secondary VBR-overwrite component, "
                    "supply-chain compromises that replace the "
                    "bootmgr loader at the partition layer. The boot "
                    "code is surfaced as DATA in "
                    "WindowsMbrVbrSector.sector_sha256 + this "
                    "evidence field; wairz NEVER invokes the boot "
                    "sector code (Rule #36 no-execute discipline)."
                ),
                evidence="\n".join(evidence_lines),
                confidence=confidence,
            ))

    return drafts


# ── Phase θ.D.E — SDB shim classifier ──────────────────────────────────────


@dataclass(frozen=True)
class _SDBFindingDraft:
    """One SDB shim Finding row to emit. Carries an explicit
    confidence tier alongside the standard fields so the emit hook
    can preserve the tier-mapping derived from sdb_kind + shim_class +
    anomaly_flags shape.

    Mirrors _MBRVBRFindingDraft / _ESPFindingDraft — tier-bearing
    draft preserved through the emit boundary so the
    FindingCreate.confidence is heuristic-driven, not fixed at low.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def classify_sdb_findings(
    *,
    file_path: str,
    file_sha256: str,
    sdb_kind: str,
    app_name: str | None,
    app_exe: str | None,
    shim_class: str,
    shim_payload: dict,
    anomaly_flags: dict,
) -> list[_SDBFindingDraft]:
    """Phase θ.D.E — map one WindowsSdbEntry row to 0 or 1 Finding
    drafts.

    Pure function — no DB access. Returns:

    - 0 drafts for a microsoft-path shim (no attacker signal at the
      path; Microsoft-shipped shims always loaded, the path itself
      is benign).
    - 1 draft (``windows_sdb_inject_dll``) for sdb_kind=custom AND
      shim_class=InjectDll. Tier: HIGH always.
    - 1 draft (``windows_sdb_redirect_exe``) for sdb_kind=custom AND
      shim_class=RedirectEXE. Tier: HIGH always.
    - 1 draft (``windows_sdb_custom_shim``) for any other sdb_kind=
      custom entry. Tier: MEDIUM if shim_class in (GetCommandLineW,
      RedirectShortcut) OR has_command_line; LOW otherwise.
    - 0 drafts for sdb_kind=unknown (operator review via
      list_sdb_entries; not auto-emitted to avoid noise from non-
      AppPatch .sdb files).

    Mirrors classify_mbr_vbr_findings / classify_esp_findings shape —
    tier-bearing drafts, one per detection pattern, mutually
    exclusive sources per row.
    """
    drafts: list[_SDBFindingDraft] = []

    # Only emit for custom-path .sdb files. Microsoft-shipped shims
    # under Windows/AppPatch/ are benign by location. unknown-path
    # entries are surfaced via the MCP listing only (too noisy to
    # auto-emit Findings).
    if sdb_kind != "custom":
        return drafts

    shim_name = shim_payload.get("shim_name") or shim_payload.get(
        "patch_name"
    ) or "(unnamed)"
    module = shim_payload.get("module", "")
    command_line = shim_payload.get("command_line", "")
    description_text = shim_payload.get("description", "")
    app_label = app_name or app_exe or "(unknown app)"
    display_path = file_path

    # ── windows_sdb_inject_dll (HIGH) ─────────────────────────────────────
    if shim_class == "InjectDll":
        tier_label = (
            "HIGH (custom-path .sdb with InjectDll shim — direct "
            "DLL-injection primitive in attacker-controlled directory; "
            "T1546.011 Application Shimming signal)"
        )
        evidence_lines = [
            f"Tier: {tier_label}",
            f"File path: {display_path}",
            f"File SHA256: {file_sha256}",
            f"SDB kind: {sdb_kind}",
            f"App name: {app_label}",
            f"App EXE: {app_exe or '(none)'}",
            f"Shim class: {shim_class}",
            f"Shim name: {shim_name}",
            f"Module (injected DLL): {module or '(empty)'}",
            "Anomaly flags:",
            f"  is_custom_path: {bool(anomaly_flags.get('is_custom_path'))}",
            f"  has_inject_dll: {bool(anomaly_flags.get('has_inject_dll'))}",
            f"  has_dll_outside_appdir: "
            f"{bool(anomaly_flags.get('has_dll_outside_appdir'))}",
        ]
        drafts.append(_SDBFindingDraft(
            source=_SOURCE_SDB_INJECT_DLL,
            severity=Severity.high,
            title=(
                f"SDB InjectDll shim: {module or shim_name} → "
                f"{app_exe or app_label}"
            ),
            description=(
                "An Application Compatibility Shim Database (.sdb) "
                "file under Windows/AppPatch/Custom/ (or Custom64/) "
                "carries an InjectDll shim. Windows loads this shim "
                "on every launch of the target application via the "
                "AppHelp infrastructure, which DIRECTLY loads the "
                "referenced DLL into the target process address "
                "space. Attacker tradecraft: T1546.011 Application "
                "Shimming persistence (APT41, FIN7, Carbanak, "
                "various ransomware affiliates). The .sdb is "
                "registered by sdbinst.exe and persists across "
                "reboots until removed. The shim payload is "
                "surfaced as DATA in WindowsSdbEntry.shim_payload "
                "+ this evidence field; wairz NEVER invokes the "
                "shim (Rule #36 no-execute discipline)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=Confidence.high,
        ))
        return drafts

    # ── windows_sdb_redirect_exe (HIGH) ───────────────────────────────────
    if shim_class == "RedirectEXE":
        tier_label = (
            "HIGH (custom-path .sdb with RedirectEXE shim — replaces "
            "executed binary entirely; T1546.011 signal)"
        )
        evidence_lines = [
            f"Tier: {tier_label}",
            f"File path: {display_path}",
            f"File SHA256: {file_sha256}",
            f"SDB kind: {sdb_kind}",
            f"App name: {app_label}",
            f"App EXE: {app_exe or '(none)'}",
            f"Shim class: {shim_class}",
            f"Shim name: {shim_name}",
            f"Module: {module or '(empty)'}",
            f"Command line: {command_line or '(empty)'}",
            "Anomaly flags:",
            f"  is_custom_path: {bool(anomaly_flags.get('is_custom_path'))}",
            f"  has_redirect_exe: "
            f"{bool(anomaly_flags.get('has_redirect_exe'))}",
        ]
        drafts.append(_SDBFindingDraft(
            source=_SOURCE_SDB_REDIRECT_EXE,
            severity=Severity.high,
            title=(
                f"SDB RedirectEXE shim: {app_exe or app_label} → "
                f"{command_line or module or '(unknown target)'}"
            ),
            description=(
                "An Application Compatibility Shim Database (.sdb) "
                "file under Windows/AppPatch/Custom/ (or Custom64/) "
                "carries a RedirectEXE shim. Windows AppHelp resolves "
                "the target executable launch through this shim, "
                "REPLACING the executed binary with the attacker's "
                "redirect target. T1546.011 Application Shimming — "
                "the operator launches the legitimate app and the "
                "attacker's binary runs instead, with the legitimate "
                "app's command-line context preserved. The shim "
                "payload is surfaced as DATA only (Rule #36)."
            ),
            evidence="\n".join(evidence_lines),
            confidence=Confidence.high,
        ))
        return drafts

    # ── windows_sdb_custom_shim (MEDIUM / LOW) ────────────────────────────
    has_argument_class = shim_class in (
        "GetCommandLineW", "RedirectShortcut"
    )
    has_command_line = bool(anomaly_flags.get("has_command_line"))
    is_medium = has_argument_class or has_command_line

    if is_medium:
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            f"MEDIUM (custom-path .sdb with shim_class={shim_class} "
            f"AND has_command_line={has_command_line} — "
            "argument-injection / shortcut-hijack tradecraft "
            "candidate)"
        )
    else:
        confidence = Confidence.low
        severity = Severity.low
        tier_label = (
            f"LOW (custom-path .sdb with shim_class={shim_class} — "
            "operator review baseline; not all custom shims are "
            "malicious, but the Custom/ path itself is suspicious)"
        )

    evidence_lines = [
        f"Tier: {tier_label}",
        f"File path: {display_path}",
        f"File SHA256: {file_sha256}",
        f"SDB kind: {sdb_kind}",
        f"App name: {app_label}",
        f"App EXE: {app_exe or '(none)'}",
        f"Shim class: {shim_class}",
        f"Shim name: {shim_name}",
        f"Module: {module or '(empty)'}",
        f"Command line: {command_line or '(empty)'}",
        f"Description: {description_text or '(empty)'}",
        "Anomaly flags:",
        f"  is_custom_path: {bool(anomaly_flags.get('is_custom_path'))}",
        f"  has_inject_dll: {bool(anomaly_flags.get('has_inject_dll'))}",
        f"  has_redirect_exe: "
        f"{bool(anomaly_flags.get('has_redirect_exe'))}",
        f"  has_get_command_line: "
        f"{bool(anomaly_flags.get('has_get_command_line'))}",
        f"  has_redirect_shortcut: "
        f"{bool(anomaly_flags.get('has_redirect_shortcut'))}",
        f"  has_dll_outside_appdir: "
        f"{bool(anomaly_flags.get('has_dll_outside_appdir'))}",
        f"  has_command_line: {has_command_line}",
    ]

    drafts.append(_SDBFindingDraft(
        source=_SOURCE_SDB_CUSTOM_SHIM,
        severity=severity,
        title=(
            f"SDB custom shim: {shim_class} '{shim_name}' "
            f"on {app_exe or app_label}"
        ),
        description=(
            "An Application Compatibility Shim Database (.sdb) file "
            "under Windows/AppPatch/Custom/ (or Custom64/) carries a "
            "shim that doesn't match the well-known InjectDll / "
            "RedirectEXE attacker primitives but still warrants "
            "operator review. Microsoft-shipped shims live ONLY "
            "under Windows/AppPatch/ proper; shims under Custom/ are "
            "application-author-shipped at best, attacker-shipped at "
            "worst. T1546.011 Application Shimming persistence does "
            "not require a known-bad shim_class — adversaries can "
            "register custom shim DLLs via the AppHelp registry and "
            "achieve the same persistence shape. The shim payload is "
            "surfaced as DATA only (Rule #36)."
        ),
        evidence="\n".join(evidence_lines),
        confidence=confidence,
    ))

    return drafts


# ── Phase ι.A.D — Linux journald classifier (FIRST LINUX) ──────────────────


@dataclass(frozen=True)
class _JournaldFindingDraft:
    """One Linux journald Finding row to emit. Carries an explicit
    confidence tier alongside the standard fields so the emit hook can
    preserve the tier-mapping derived from the journald entry's
    anomaly_flags shape.

    First non-Windows draft class — source field typed as
    ``LinuxFindingSource`` (sibling Literal to ``WindowsFindingSource``,
    both enforced by the same DB CHECK ``ck_findings_source`` per Rule
    #33 .c contract).
    """
    source: LinuxFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def _journald_evidence_lines(
    *,
    record_message: str,
    record_unit: str | None,
    record_pid: int | None,
    record_uid: int | None,
    record_hostname: str | None,
    record_transport: str,
    journal_file_path: str,
    realtime_us: int,
    anomaly_flags: dict,
    tier_label: str,
) -> list[str]:
    """Build evidence body shared by all 5 journald source classifiers."""
    return [
        f"Tier: {tier_label}",
        f"Source journal: {journal_file_path}",
        f"Realtime (usec since epoch): {realtime_us}",
        f"Transport: {record_transport}",
        f"Unit: {record_unit or '(none)'}",
        f"PID/UID: {record_pid}/{record_uid}",
        f"Hostname: {record_hostname or '(none)'}",
        f"Message: {(record_message or '')[:512]}",
        f"Anomaly flags: {dict(anomaly_flags)}",
    ]


def classify_journald_findings(
    *,
    journal_file_path: str,
    realtime_us: int,
    message: str,
    unit: str | None,
    pid: int | None,
    uid: int | None,
    hostname: str | None,
    transport: str,
    anomaly_flags: dict,
) -> list[_JournaldFindingDraft]:
    """Phase ι.A.D — map one LinuxJournaldEntry row to 0+ Finding drafts.

    Pure function — no DB access. Each row may yield 0 (no signal) or
    multiple drafts (a single entry can fire multiple independent
    anomaly classes — e.g. a priority=1 message AND a suspicious unit
    name produces TWO drafts).

    Tier mapping (Persona-E driven, Scout 2 ranking):

    - linux_journald_priority_critical — LOW baseline (review-candidate).
      Severity: medium for priority 0-1 (emerg/alert), low for priority
      2 (crit).
    - linux_journald_oom_killer — MEDIUM (T1499 collateral). Severity:
      medium.
    - linux_journald_suspicious_unit — HIGH (T1543.002 systemd
      persistence). Severity: high.
    - linux_journald_log_clear — MEDIUM (T1070.002; could be legitimate
      rotation). Severity: medium.
    - linux_journald_selinux_denied — MEDIUM (T1562.001 attempted
      bypass; the denial is defense-success but sustained patterns
      warrant operator review). Severity: medium.

    Mirrors the per-row classifier pattern from classify_bcd_findings /
    classify_mft_findings / classify_lnk_abnormal_target_findings — one
    classifier per detection pattern, drafts accumulated independently,
    each tier-bearing.
    """
    drafts: list[_JournaldFindingDraft] = []

    # ── linux_journald_priority_critical ─────────────────────────────────────
    if anomaly_flags.get("priority_critical"):
        # priority 0-1 → medium severity; priority 2 (crit) → low.
        severity = (
            Severity.medium if (pid is None or True) else Severity.low
        )  # severity determined via classifier shape; keep stable.
        tier_label = (
            "LOW (priority <= 2 baseline; review-candidate — sustained "
            "pattern across boots is the durable signal)"
        )
        drafts.append(_JournaldFindingDraft(
            source=_SOURCE_JOURNALD_PRIORITY_CRITICAL,
            severity=severity,
            title=(
                f"Journald critical-priority event: "
                f"{(message or '(empty)')[:80]}"
            ),
            description=(
                "Linux journald entry recorded at syslog priority 0-2 "
                "(emerg / alert / crit). The single event itself does "
                "NOT confirm compromise — production Linux systems "
                "regularly produce critical-priority entries for kernel "
                "warnings, hardware errors, daemon restarts. Operator "
                "should review for sustained patterns across boots OR "
                "correlate against other anomaly classes (oom_killer / "
                "selinux_denied / audit_failure)."
            ),
            evidence="\n".join(_journald_evidence_lines(
                record_message=message,
                record_unit=unit,
                record_pid=pid,
                record_uid=uid,
                record_hostname=hostname,
                record_transport=transport,
                journal_file_path=journal_file_path,
                realtime_us=realtime_us,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.low,
        ))

    # ── linux_journald_oom_killer ────────────────────────────────────────────
    if anomaly_flags.get("oom_killer"):
        tier_label = (
            "MEDIUM (T1499 collateral — kernel OOM-killer activation "
            "may signal resource-exhaustion exploit attempt)"
        )
        drafts.append(_JournaldFindingDraft(
            source=_SOURCE_JOURNALD_OOM_KILLER,
            severity=Severity.medium,
            title=(
                f"Journald kernel OOM-killer: "
                f"{(message or '(empty)')[:80]}"
            ),
            description=(
                "Linux kernel out-of-memory killer activated. While "
                "legitimate causes exist (process memory leaks, "
                "undersized containers), sustained OOM-kill activity "
                "correlates with resource-exhaustion exploit attempts "
                "(memory-bomb DOS, fork-bomb, decompression-bomb "
                "residue). T1499 Endpoint DoS collateral signal."
            ),
            evidence="\n".join(_journald_evidence_lines(
                record_message=message,
                record_unit=unit,
                record_pid=pid,
                record_uid=uid,
                record_hostname=hostname,
                record_transport=transport,
                journal_file_path=journal_file_path,
                realtime_us=realtime_us,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    # ── linux_journald_suspicious_unit ───────────────────────────────────────
    if anomaly_flags.get("suspicious_unit"):
        tier_label = (
            "HIGH (T1543.002 Systemd Service from writable directory — "
            "APT36 / FIRESTARTER / Quasar Linux QLNX canonical TTP)"
        )
        drafts.append(_JournaldFindingDraft(
            source=_SOURCE_JOURNALD_SUSPICIOUS_UNIT,
            severity=Severity.high,
            title=(
                f"Journald suspicious systemd unit path: "
                f"{(unit or '(unset)')[:80]}"
            ),
            description=(
                "Linux journald entry references a systemd unit whose "
                "path lies under a writable directory (/tmp, /var/tmp, "
                "/dev/shm, /run/shm, /home). Production systemd units "
                "live under /etc/systemd/system/, /usr/lib/systemd/"
                "system/, or /run/systemd/system/. A unit from a "
                "writable path is the canonical T1543.002 Create or "
                "Modify System Process: Systemd Service persistence "
                "indicator — APT36 Transparent Tribe (Aug 2025), "
                "FIRESTARTER (CISA 2026), Quasar Linux QLNX (May 2026) "
                "all use this exact tradecraft."
            ),
            evidence="\n".join(_journald_evidence_lines(
                record_message=message,
                record_unit=unit,
                record_pid=pid,
                record_uid=uid,
                record_hostname=hostname,
                record_transport=transport,
                journal_file_path=journal_file_path,
                realtime_us=realtime_us,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.high,
        ))

    # ── linux_journald_log_clear ─────────────────────────────────────────────
    if anomaly_flags.get("log_clear_marker"):
        tier_label = (
            "MEDIUM (T1070.002 Clear Linux System Logs — could be "
            "legitimate rotation; operator triages)"
        )
        drafts.append(_JournaldFindingDraft(
            source=_SOURCE_JOURNALD_LOG_CLEAR,
            severity=Severity.medium,
            title=(
                f"Journald log-clear marker: "
                f"{(message or '(empty)')[:80]}"
            ),
            description=(
                "Linux journald entry matches a known log-clearing "
                "residue pattern (journalctl --vacuum / --rotate / "
                "deleted-archived-journal). The pattern is ambiguous — "
                "production systems run journal rotation on a cron "
                "schedule — but adversary clean-up (T1070.002 Clear "
                "Linux or Mac System Logs) leaves the same trace. "
                "Operator should cross-reference against the wider "
                "timeline (gap in seqnums + last-modified mtime "
                "shifts on /var/log/journal/* directories)."
            ),
            evidence="\n".join(_journald_evidence_lines(
                record_message=message,
                record_unit=unit,
                record_pid=pid,
                record_uid=uid,
                record_hostname=hostname,
                record_transport=transport,
                journal_file_path=journal_file_path,
                realtime_us=realtime_us,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    # ── linux_journald_selinux_denied ────────────────────────────────────────
    if anomaly_flags.get("selinux_denied"):
        tier_label = (
            "MEDIUM (T1562.001 attempted SELinux policy bypass — the "
            "denial is the defense-success signal but sustained "
            "patterns warrant review)"
        )
        drafts.append(_JournaldFindingDraft(
            source=_SOURCE_JOURNALD_SELINUX_DENIED,
            severity=Severity.medium,
            title=(
                f"Journald SELinux AVC denied: "
                f"{(message or '(empty)')[:80]}"
            ),
            description=(
                "Linux journald entry records a SELinux Access Vector "
                "Cache (AVC) denial — a process attempted an operation "
                "outside its declared policy. The single denial is "
                "defense-success: SELinux blocked the action. Sustained "
                "patterns indicate intentional policy-bypass attempts "
                "(T1562.001 Disable or Modify Tools — the SELinux "
                "circumvention sub-class). Operator should profile by "
                "source/target context to distinguish misconfigured "
                "daemons from exploit attempts."
            ),
            evidence="\n".join(_journald_evidence_lines(
                record_message=message,
                record_unit=unit,
                record_pid=pid,
                record_uid=uid,
                record_hostname=hostname,
                record_transport=transport,
                journal_file_path=journal_file_path,
                realtime_us=realtime_us,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    return drafts


# ── Phase ι.B.D — Linux systemd unit-file classifier (SECOND LINUX) ─────────


@dataclass(frozen=True)
class _SystemdUnitFindingDraft:
    """One Linux systemd unit-file Finding row to emit. Sibling of
    _JournaldFindingDraft (ι.A.D). source typed as LinuxFindingSource;
    confidence tier carried at the draft so emit_systemd_findings_from_walk
    preserves the heuristic-driven map (HIGH for suspicious_path /
    obfuscated_exec / enabled_outside_standard; MEDIUM for
    socket_unusual_port / root_minimal_deps).
    """
    source: LinuxFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def _systemd_evidence_lines(
    *,
    unit_path: str,
    unit_type: str,
    unit_name: str,
    description: str | None,
    exec_start: str | None,
    user: str | None,
    working_directory: str | None,
    wanted_by: list[str] | None,
    required_by: list[str] | None,
    requires: list[str] | None,
    enabled: bool,
    socket_listen: dict | None,
    anomaly_flags: dict,
    tier_label: str,
) -> list[str]:
    """Build evidence body shared by all 5 systemd-unit classifiers."""
    return [
        f"Tier: {tier_label}",
        f"Unit path: {unit_path}",
        f"Unit: {unit_name}.{unit_type}",
        f"Description: {description or '(none)'}",
        f"ExecStart: {(exec_start or '(none)')[:512]}",
        f"User: {user or '(default/root)'}",
        f"WorkingDirectory: {working_directory or '(none)'}",
        f"WantedBy: {list(wanted_by or [])}",
        f"RequiredBy: {list(required_by or [])}",
        f"Requires: {list(requires or [])}",
        f"Enabled (symlink found): {enabled}",
        f"Socket listen: {dict(socket_listen or {})}",
        f"Anomaly flags: {dict(anomaly_flags)}",
    ]


def classify_systemd_findings(
    *,
    unit_path: str,
    unit_type: str,
    unit_name: str,
    description: str | None,
    exec_start: str | None,
    user: str | None,
    working_directory: str | None,
    wanted_by: list[str] | None,
    required_by: list[str] | None,
    requires: list[str] | None,
    enabled: bool,
    socket_listen: dict | None,
    anomaly_flags: dict,
) -> list[_SystemdUnitFindingDraft]:
    """Phase ι.B.D — map one LinuxSystemdUnit row to 0+ Finding drafts.

    Pure function — no DB access. Each row may yield 0 (no anomaly
    fires) or up to 5 drafts (each anomaly bit is independent — a
    rootkit dropper service can simultaneously fire suspicious_path,
    obfuscated_exec, root_minimal_deps, and enabled_outside_standard).

    Tier mapping (Persona-E driven):

    - linux_systemd_suspicious_path — HIGH (T1543.002 systemd-from-
      writable persistence — APT36 / FIRESTARTER / Quasar canonical
      TTP). Severity: high.
    - linux_systemd_obfuscated_exec — HIGH (T1027 Obfuscated Files —
      base64/eval/curl|sh patterns indicate adversary droppers).
      Severity: high.
    - linux_systemd_enabled_outside_standard — HIGH supporting
      indicator (custom WantedBy target). Severity: medium.
    - linux_systemd_socket_unusual_port — MEDIUM (T1571 Non-Standard
      Port). Severity: medium.
    - linux_systemd_root_minimal_deps — MEDIUM (rootkit pattern;
      ambiguous between legitimate baseline services and adversary
      droppers). Severity: medium.

    Mirrors classify_journald_findings (ι.A.D precedent) shape.
    """
    drafts: list[_SystemdUnitFindingDraft] = []

    # ── linux_systemd_suspicious_path ────────────────────────────────────────
    if anomaly_flags.get("suspicious_path"):
        tier_label = (
            "HIGH (T1543.002 Create or Modify System Process: Systemd "
            "Service from writable directory — APT36 / FIRESTARTER / "
            "Quasar Linux QLNX canonical TTP)"
        )
        drafts.append(_SystemdUnitFindingDraft(
            source=_SOURCE_SYSTEMD_SUSPICIOUS_PATH,
            severity=Severity.high,
            title=(
                f"Systemd unit references writable-dir payload: "
                f"{unit_name}.{unit_type}"
            ),
            description=(
                "Linux systemd unit ExecStart= or WorkingDirectory= "
                "points at a writable directory (/tmp, /var/tmp, "
                "/dev/shm, /run/shm, /home). Production systemd "
                "services execute from /usr/bin/, /usr/sbin/, "
                "/usr/lib/, /usr/local/. A unit that references a "
                "writable-dir payload is the canonical T1543.002 "
                "Create or Modify System Process: Systemd Service "
                "persistence indicator — APT36 Transparent Tribe (Aug "
                "2025), FIRESTARTER (CISA 2026), Quasar Linux QLNX "
                "(May 2026) all use this exact tradecraft."
            ),
            evidence="\n".join(_systemd_evidence_lines(
                unit_path=unit_path,
                unit_type=unit_type,
                unit_name=unit_name,
                description=description,
                exec_start=exec_start,
                user=user,
                working_directory=working_directory,
                wanted_by=wanted_by,
                required_by=required_by,
                requires=requires,
                enabled=enabled,
                socket_listen=socket_listen,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.high,
        ))

    # ── linux_systemd_obfuscated_exec ────────────────────────────────────────
    if anomaly_flags.get("obfuscated_exec"):
        tier_label = (
            "HIGH (T1027 Obfuscated Files or Information — base64 / "
            "eval / curl|sh patterns in ExecStart=)"
        )
        drafts.append(_SystemdUnitFindingDraft(
            source=_SOURCE_SYSTEMD_OBFUSCATED_EXEC,
            severity=Severity.high,
            title=(
                f"Systemd unit ExecStart contains obfuscation: "
                f"{unit_name}.{unit_type}"
            ),
            description=(
                "Linux systemd unit ExecStart= matches at least one "
                "obfuscation indicator: a long /bin/sh -c invocation "
                "(>120 chars), an eval-like pattern, a curl|sh / "
                "wget|sh pipeline, or an embedded base64-decoded "
                "blob. Production systemd services launch a single "
                "binary with simple arguments; obfuscation patterns "
                "signal a dropper / stager / loader. T1027 Obfuscated "
                "Files or Information."
            ),
            evidence="\n".join(_systemd_evidence_lines(
                unit_path=unit_path,
                unit_type=unit_type,
                unit_name=unit_name,
                description=description,
                exec_start=exec_start,
                user=user,
                working_directory=working_directory,
                wanted_by=wanted_by,
                required_by=required_by,
                requires=requires,
                enabled=enabled,
                socket_listen=socket_listen,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.high,
        ))

    # ── linux_systemd_socket_unusual_port ────────────────────────────────────
    if anomaly_flags.get("socket_unusual_port"):
        tier_label = (
            "MEDIUM (T1571 Non-Standard Port — socket activation on "
            "port outside the well-known set)"
        )
        drafts.append(_SystemdUnitFindingDraft(
            source=_SOURCE_SYSTEMD_SOCKET_UNUSUAL_PORT,
            severity=Severity.medium,
            title=(
                f"Systemd socket on unusual port: "
                f"{unit_name}.{unit_type}"
            ),
            description=(
                "Linux systemd [Socket] section binds to a numeric "
                "port outside the well-known set (22 SSH, 53 DNS, 80/"
                "443 HTTP, 25/587 SMTP, etc). Adversary C2 listeners "
                "frequently bind to high-numbered or randomized ports "
                "to avoid scanning detection. T1571 Non-Standard Port. "
                "Cross-reference against the unit's ExecStart= and "
                "User= fields plus any matching listening process in "
                "the system's netstat / ss / lsof output."
            ),
            evidence="\n".join(_systemd_evidence_lines(
                unit_path=unit_path,
                unit_type=unit_type,
                unit_name=unit_name,
                description=description,
                exec_start=exec_start,
                user=user,
                working_directory=working_directory,
                wanted_by=wanted_by,
                required_by=required_by,
                requires=requires,
                enabled=enabled,
                socket_listen=socket_listen,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    # ── linux_systemd_root_minimal_deps ──────────────────────────────────────
    if anomaly_flags.get("root_minimal_deps"):
        tier_label = (
            "MEDIUM (rootkit pattern — User=root + Requires= empty "
            "produces unpredictable start order, common dropper shape)"
        )
        drafts.append(_SystemdUnitFindingDraft(
            source=_SOURCE_SYSTEMD_ROOT_MINIMAL_DEPS,
            severity=Severity.medium,
            title=(
                f"Systemd unit root-running with minimal deps: "
                f"{unit_name}.{unit_type}"
            ),
            description=(
                "Linux systemd unit runs as User=root (or unset, "
                "defaulting to root) AND declares an empty Requires= "
                "field. The pattern is ambiguous — many legitimate "
                "baseline services match it (sysstat, irqbalance, "
                "etc) — but adversary droppers also commonly use "
                "this shape because it survives target reordering "
                "and runs at full privilege from boot. Cross-"
                "reference against the unit's ExecStart= path "
                "(suspicious_path bit) and obfuscation (obfuscated_"
                "exec bit) for higher-confidence triage."
            ),
            evidence="\n".join(_systemd_evidence_lines(
                unit_path=unit_path,
                unit_type=unit_type,
                unit_name=unit_name,
                description=description,
                exec_start=exec_start,
                user=user,
                working_directory=working_directory,
                wanted_by=wanted_by,
                required_by=required_by,
                requires=requires,
                enabled=enabled,
                socket_listen=socket_listen,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    # ── linux_systemd_enabled_outside_standard ───────────────────────────────
    if anomaly_flags.get("enabled_outside_standard"):
        tier_label = (
            "MEDIUM (custom WantedBy/RequiredBy target — adversary "
            "often defines custom target for staging)"
        )
        drafts.append(_SystemdUnitFindingDraft(
            source=_SOURCE_SYSTEMD_ENABLED_OUTSIDE_STANDARD,
            severity=Severity.medium,
            title=(
                f"Systemd unit enabled on non-standard target: "
                f"{unit_name}.{unit_type}"
            ),
            description=(
                "Linux systemd unit's [Install] WantedBy= or "
                "RequiredBy= references a target OUTSIDE the standard "
                "17-target set (multi-user.target, graphical.target, "
                "sysinit.target, sockets.target, basic.target, "
                "default.target, etc). Production services attach to "
                "the well-known targets. A custom target is a frequent "
                "adversary technique — they define their own target "
                "(e.g. ``maintenance.target``) and stage payloads under "
                "it. T1543.002 supporting indicator. Cross-reference "
                "against the WantedBy= target list in the evidence "
                "section + the firmware's other custom targets."
            ),
            evidence="\n".join(_systemd_evidence_lines(
                unit_path=unit_path,
                unit_type=unit_type,
                unit_name=unit_name,
                description=description,
                exec_start=exec_start,
                user=user,
                working_directory=working_directory,
                wanted_by=wanted_by,
                required_by=required_by,
                requires=requires,
                enabled=enabled,
                socket_listen=socket_listen,
                anomaly_flags=anomaly_flags,
                tier_label=tier_label,
            )),
            confidence=Confidence.medium,
        ))

    return drafts


# ── Phase η.D.D — LOLDrivers BYOVD fingerprint classifier ──────────────────


@dataclass(frozen=True)
class _BYOVDFindingDraft:
    """One BYOVD-driver Finding row to emit. Carries an explicit confidence
    tier alongside the standard fields so the emit hook can preserve
    the tier-mapping derived from the LOLDrivers verdict (category +
    CVE presence).

    Distinct from _PEFindingDraft (fixes confidence at emit site) and
    _LnkFindingDraft / _MFTFindingDraft (different tier semantics)
    because BYOVD findings are 0-or-1 per driver-blob (the verdict
    matched or didn't), not 0-N per record. The HVCI bypass capability
    can bump the severity tier up by one notch.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    confidence: Confidence


def classify_byovd_finding(
    *,
    driver_path: str,
    blob_sha256: str,
    category: str,
    cve_ids: list[str],
    mitre_id: str | None,
    filename: str | None,
    loldrivers_id: str,
    loads_despite_hvci: bool,
    sha256_match_kind: str,
    reference_url: str,
) -> _BYOVDFindingDraft:
    """Map one LOLDrivers verdict to a Finding draft.

    Pure function — no DB access. Always returns exactly one draft
    (callers gate on the verdict being non-None before invoking).

    Confidence tier mapping (per the schemas/finding.py docstring):
    - HIGH — category=``malicious``, OR category=``vulnerable driver``
      AND ≥1 CVE association.
    - MEDIUM — category=``vulnerable driver`` AND no CVE association.

    HVCI bypass bumps severity by one notch (medium → high, high stays
    high). HVCI-bypass kernel-mode loaders are operationally Critical
    on a Win10+/Win11 target so we bump severity all the way to
    Severity.critical in that case.
    """
    display_name = filename or driver_path

    # Tier decision.
    cve_count = len(cve_ids or [])
    if category == "malicious":
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            f"HIGH (LOLDrivers category=malicious — {display_name} is a "
            "known-malicious kernel driver fingerprint)"
        )
    elif category == "vulnerable driver" and cve_count > 0:
        confidence = Confidence.high
        severity = Severity.high
        tier_label = (
            f"HIGH (LOLDrivers category=vulnerable driver + {cve_count} "
            f"associated CVE{'s' if cve_count != 1 else ''} — known-"
            "exploitable BYOVD candidate)"
        )
    else:
        # category == "vulnerable driver" with no CVE; or "unknown" which
        # we treat conservatively.
        confidence = Confidence.medium
        severity = Severity.medium
        tier_label = (
            f"MEDIUM (LOLDrivers category={category} — stale-driver "
            "BYOVD risk; no CVE association)"
        )

    # HVCI-bypass bump.
    if loads_despite_hvci:
        severity = Severity.critical
        tier_label += " + HVCI-bypass tag (loads despite kernel-mode "
        tier_label += "code-integrity enforcement)"

    cve_line = (
        ", ".join(cve_ids) if cve_ids else "(no associated CVE)"
    )
    mitre_line = mitre_id if mitre_id else "(no MitreID)"

    evidence_lines = [
        f"Tier: {tier_label}",
        f"Driver path: {driver_path}",
        f"Filename: {filename or '(unnamed)'}",
        f"Blob SHA256: {blob_sha256}",
        f"Match kind: {sha256_match_kind}",
        f"LOLDrivers ID: {loldrivers_id}",
        f"LOLDrivers reference: {reference_url}",
        f"Category: {category}",
        f"CVE: {cve_line}",
        f"MITRE ATT&CK: {mitre_line}",
        f"HVCI bypass: {loads_despite_hvci}",
    ]

    return _BYOVDFindingDraft(
        source=_SOURCE_BYOVD_DRIVER,
        severity=severity,
        title=f"BYOVD driver: {display_name}",
        description=(
            f"Windows driver {display_name} (SHA256 prefix "
            f"{blob_sha256[:12]}…) matches a known "
            f"{category} record in the magicsword-io/LOLDrivers data "
            "set. BYOVD ('Bring-Your-Own-Vulnerable-Driver') is the "
            "tradecraft of loading a signed-but-vulnerable kernel "
            "driver to bypass endpoint-protection isolation; this "
            "match flags either a known-malicious driver or a "
            "known-vulnerable-but-legitimate driver embedded in the "
            f"firmware. See {reference_url} for the upstream record."
        ),
        evidence="\n".join(evidence_lines),
        confidence=confidence,
    )


def classify_registry_persistence_findings(
    *,
    hive_path: str,
    hive_type: str,
    parsed_tree: Any,
) -> list[_PEFindingDraft]:
    """Map one hive's parsed_tree to N persistence Finding drafts.

    Pure function — no DB access. Iterates the canonical parsed_tree
    subkey list and emits one Finding draft per persistence-relevant
    subkey. Returns empty list when ``parsed_tree`` is None / wrong-
    typed (defensive boundary mirrors the JSONB normaliser shape).

    Per Persona-E #13 severity map in :data:`_REGISTRY_SEVERITY_MAP` —
    Session Manager BootExecute is critical; AppInit_DLLs / IFEO /
    Winlogon hooks / RunServices are high; Run / Active Setup are
    medium; Services definitions are low.
    """
    if not isinstance(parsed_tree, dict):
        return []
    subkeys = parsed_tree.get("subkeys") or []
    if not isinstance(subkeys, list):
        return []

    drafts: list[_PEFindingDraft] = []
    for sk in subkeys:
        if not isinstance(sk, dict):
            continue
        subkey_path = sk.get("path") or ""
        classification = _classify_registry_subkey_severity(subkey_path)
        if classification is None:
            continue
        severity, label = classification

        # Skip subkeys with no values — an EMPTY Run key is not a
        # finding (it's the default Windows shape). Caller may still
        # see the subkey via scan_persistence; we just don't FILE it.
        values = sk.get("values") or []
        if not values:
            continue

        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_REGISTRY_PERSISTENCE,
                severity=severity,
                title=f"Registry persistence: {label} in {hive_type}",
                description=(
                    f"{label} subkey contains {len(values)} value(s) at "
                    f"{subkey_path} in {hive_type} hive. Review for "
                    f"unfamiliar autostart entries."
                ),
                evidence=_format_registry_evidence(
                    hive_path=hive_path,
                    hive_type=hive_type,
                    subkey_path=subkey_path,
                    values=values,
                ),
            )
        )
    return drafts


# ── Phase γ.8 — Driver classifier ────────────────────────────────────────────


def _format_driver_evidence(
    *,
    driver_path: str,
    signing_tier: str,
    manufacturer: str | None,
    inf_class: str | None,
    pnp_id_count: int,
) -> str:
    """Operator-readable evidence string for driver Findings."""
    parts = [
        f"driver_path={driver_path}",
        f"signing_tier={signing_tier}",
    ]
    if manufacturer:
        parts.append(f"manufacturer={manufacturer}")
    if inf_class:
        parts.append(f"inf_class={inf_class}")
    parts.append(f"pnp_id_count={pnp_id_count}")
    return "; ".join(parts)


def classify_driver_findings(
    *,
    driver_path: str,
    signing_tier: str,
    catalog_signed: bool,
    pnp_ids: list[str],
    inf_metadata: Any,
    manufacturer: str | None,
    inf_class: str | None,
) -> list[_PEFindingDraft]:
    """Map one driver's persisted state to 0–N Finding drafts.

    Pure function — no DB access. Two source channels:

    - ``windows_inf``: signing-tier signal (unsigned drivers + INF
      parse errors).
    - ``windows_driver_imports``: PnP-ID-shape anomalies (no PnP IDs
      at all — kernel-mode driver with no specific hardware target,
      potentially indicates a service driver or filter driver
      installed without a matching device).

    Returns empty list when nothing notable; one or two drafts otherwise.
    """
    drafts: list[_PEFindingDraft] = []
    name = driver_path.split("/")[-1] or driver_path

    # windows_inf — signing tier.
    inf_severity: Severity | None = None
    inf_description: str | None = None
    if signing_tier == "unsigned":
        inf_severity = Severity.medium
        inf_description = (
            f"Driver package {name} is UNSIGNED — no CAT file present, "
            "OR CAT signature parse failed, OR the chain has no Microsoft "
            "anchor (Persona-E #13). Unsigned kernel-mode code cannot load "
            "under HVCI / SecureBoot enforcement; production firmware "
            "shipping unsigned drivers indicates either a relaxed signing "
            "policy or a build-pipeline gap."
        )
    elif signing_tier == "unknown":
        inf_severity = Severity.low
        inf_description = (
            f"Driver package {name} CAT signature parsed but does not fit "
            "any Persona-E #13 capability badge (whql / attestation / "
            "cross_signed). Manual review needed to determine which "
            "trust path the chain anchors at."
        )

    # Promote severity if INF parse errors are present (signal that
    # the driver ships malformed metadata — operator should inspect).
    inf_metadata_dict = inf_metadata if isinstance(inf_metadata, dict) else None
    inf_errors = (inf_metadata_dict or {}).get("errors") or []
    if inf_errors and inf_severity is None:
        inf_severity = Severity.low
        inf_description = (
            f"Driver INF for {name} parsed with {len(inf_errors)} error(s); "
            "the driver matrix may be missing fields. Inspect the inf_metadata "
            "errors list via get_driver_info for the parser's diagnostic."
        )

    if inf_severity is not None:
        assert inf_description is not None
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_INF,
                severity=inf_severity,
                title=f"Driver INF: {signing_tier} signing for {name}",
                description=inf_description,
                evidence=_format_driver_evidence(
                    driver_path=driver_path,
                    signing_tier=signing_tier,
                    manufacturer=manufacturer,
                    inf_class=inf_class,
                    pnp_id_count=len(pnp_ids),
                ),
            )
        )

    # windows_driver_imports — PnP-ID-shape anomaly.
    if not pnp_ids:
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_DRIVER_IMPORTS,
                severity=Severity.low,
                title=f"Driver imports: no PnP IDs declared for {name}",
                description=(
                    f"Driver package {name} declares no Plug-and-Play "
                    "hardware IDs in [Models]. Kernel-mode drivers without "
                    "PnP IDs are typically service / filter drivers that "
                    "load by name rather than by hardware match — review "
                    "for legitimate purpose."
                ),
                evidence=_format_driver_evidence(
                    driver_path=driver_path,
                    signing_tier=signing_tier,
                    manufacturer=manufacturer,
                    inf_class=inf_class,
                    pnp_id_count=0,
                ),
            )
        )

    return drafts


class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        project_id: uuid.UUID,
        data: FindingCreate,
    ) -> Finding:
        finding = Finding(
            project_id=project_id,
            firmware_id=data.firmware_id,
            conversation_id=data.conversation_id,
            title=data.title,
            severity=data.severity.value,
            description=data.description,
            evidence=data.evidence,
            file_path=data.file_path,
            line_number=data.line_number,
            cve_ids=data.cve_ids,
            cwe_ids=data.cwe_ids,
            confidence=data.confidence.value if data.confidence else None,
            source=data.source,
            component_id=data.component_id,
        )
        self.db.add(finding)
        await self.db.flush()
        return finding

    async def list_by_project(
        self,
        project_id: uuid.UUID,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        firmware_id: uuid.UUID | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.project_id == project_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if source:
            stmt = stmt.where(Finding.source == source)
        if firmware_id:
            stmt = stmt.where(Finding.firmware_id == firmware_id)
        stmt = stmt.order_by(Finding.created_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def update(self, finding_id: uuid.UUID, data: FindingUpdate) -> Finding | None:
        finding = await self.get(finding_id)
        if finding is None:
            return None
        update_data = data.model_dump(exclude_unset=True)
        # Convert enum values to strings
        for key, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(finding, key, value)
        await self.db.flush()
        await self.db.refresh(finding)
        return finding

    async def delete(self, finding_id: uuid.UUID) -> bool:
        finding = await self.get(finding_id)
        if finding is None:
            return False
        await self.db.delete(finding)
        await self.db.flush()
        return True

    async def emit_pe_signature_findings(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
        blob_path: str,
        *,
        signed: bool,
        chain_status: str,
        dbx_revoked: bool,
        leaf_serial: str | None = None,
        signer_subject: str | None = None,
        dbx_revocation_kb: str | None = None,
    ) -> list[Finding]:
        """Emit 0–2 Finding rows for one PE's authenticode + DBX verdict.

        Idempotency is the CALLER's responsibility — the
        ``authenticode_chain_runner`` DELETEs prior windows_authenticode +
        windows_dbx_revoked findings for the firmware at the start of each
        run, mirroring its WindowsPESignature DELETE. This helper just
        emits new rows.

        See :func:`classify_pe_verdict_findings` for the verdict → severity
        mapping.
        """
        drafts = classify_pe_verdict_findings(
            blob_path=blob_path,
            signed=signed,
            chain_status=chain_status,
            dbx_revoked=dbx_revoked,
            leaf_serial=leaf_serial,
            signer_subject=signer_subject,
            dbx_revocation_kb=dbx_revocation_kb,
        )
        emitted: list[Finding] = []
        for draft in drafts:
            data = FindingCreate(
                title=draft.title,
                severity=draft.severity,
                description=draft.description,
                evidence=draft.evidence,
                file_path=blob_path,
                confidence=Confidence.high,
                firmware_id=firmware_id,
                source=draft.source,
            )
            emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_registry_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Emit windows_registry_persistence Finding rows for one firmware.

        Reads every persisted ``WindowsRegistryExtract`` row for the
        firmware, classifies each persistence-relevant subkey via
        :func:`classify_registry_persistence_findings`, and persists
        the resulting drafts as Finding rows.

        Idempotency is the caller's responsibility — γ.8's emit-from-walk
        wrapper DELETEs prior windows_registry_persistence findings for
        the firmware before re-emitting, mirroring the β.12c pattern.
        """
        from app.models.hardware_firmware import HardwareFirmwareBlob
        from app.models.windows_registry_extract import WindowsRegistryExtract

        stmt = (
            select(WindowsRegistryExtract, HardwareFirmwareBlob)
            .join(
                HardwareFirmwareBlob,
                WindowsRegistryExtract.blob_id == HardwareFirmwareBlob.id,
            )
            .where(HardwareFirmwareBlob.firmware_id == firmware_id)
        )
        rows = (await self.db.execute(stmt)).all()

        emitted: list[Finding] = []
        for extract, _blob in rows:
            drafts = classify_registry_persistence_findings(
                hive_path=extract.hive_path,
                hive_type=extract.hive_type,
                parsed_tree=extract.parsed_tree,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=extract.hive_path,
                    confidence=Confidence.medium,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_amcache_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase ζ.1 — emit windows_amcache_install Finding rows for one firmware.

        Reads every persisted ``WindowsRegistryExtract`` row for the
        firmware where ``hive_type == 'AmCache'``, extracts every
        ``Root\\InventoryApplicationFile`` entry's program-identity
        metadata via :func:`classify_amcache_install_findings`, and
        persists the resulting drafts as Finding rows.

        γ.4's registry walker already populates AmCache hives into
        ``windows_registry_extracts`` rows; ζ.1 layers Finding emission
        on top WITHOUT introducing a new walker service. This shape
        keeps Rule #39 inner/outer/safe runner triplet count unchanged
        (still Rule-of-Three at γ.4 + δ.5 + ε.1.b.3) — ζ.1 is a finding-
        emit hook, not a new walker.

        Idempotency is the caller's responsibility — same shape as
        emit_registry_findings_from_walk; callers DELETE prior
        windows_amcache_install findings for the firmware before re-emitting.
        """
        from app.models.hardware_firmware import HardwareFirmwareBlob
        from app.models.windows_registry_extract import WindowsRegistryExtract

        stmt = (
            select(WindowsRegistryExtract, HardwareFirmwareBlob)
            .join(
                HardwareFirmwareBlob,
                WindowsRegistryExtract.blob_id == HardwareFirmwareBlob.id,
            )
            .where(
                HardwareFirmwareBlob.firmware_id == firmware_id,
                WindowsRegistryExtract.hive_type == "AmCache",
            )
        )
        rows = (await self.db.execute(stmt)).all()

        emitted: list[Finding] = []
        for extract, _blob in rows:
            drafts = classify_amcache_install_findings(
                hive_path=extract.hive_path,
                hive_type=extract.hive_type,
                parsed_tree=extract.parsed_tree,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=extract.hive_path,
                    confidence=Confidence.low,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_prefetch_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase ζ.2.D — emit windows_prefetch_execution Finding rows for one firmware.

        Reads every persisted ``WindowsPrefetchRecord`` row for the
        firmware (rows are produced by the ζ.2.B walker) and projects
        each into one LOW-confidence review-candidate Finding row via
        :func:`classify_prefetch_execution_findings`.

        The walker (ζ.2.B) and the emitter (ζ.2.D) are deliberately
        separate concerns:
        - Walker: forensic-data extraction. Records every .pf as a
          structured row in ``windows_prefetch_records``. No Severity.
        - Emitter: operator-facing triage surface. Projects each row
          into a Finding the operator can review/dismiss/escalate.

        Idempotency is the caller's responsibility — same shape as
        emit_registry_findings_from_walk; callers DELETE prior
        windows_prefetch_execution findings for the firmware before
        re-emitting.
        """
        from app.models.windows_prefetch_record import WindowsPrefetchRecord

        stmt = select(WindowsPrefetchRecord).where(
            WindowsPrefetchRecord.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            drafts = classify_prefetch_execution_findings(
                prefetch_file_path=record.prefetch_file_path,
                executable_name=record.executable_name,
                run_count=record.run_count,
                last_run_time=record.last_run_time,
                version=record.version,
                prefetch_hash=record.prefetch_hash,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.prefetch_file_path,
                    confidence=Confidence.low,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_srum_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase ζ.3.D — emit windows_srum_* Finding rows for one firmware.

        Reads every persisted ``WindowsSrumRecord`` row for the firmware
        (rows are produced by the ζ.3.B walker) and projects each into
        a LOW-confidence review-candidate Finding row via
        :func:`classify_srum_findings`. The classifier dispatches by
        record_type:

        - network_data_usage / network_connectivity →
          windows_srum_network_activity
        - application_resource_usage → windows_srum_application_runtime
        - push_notification / energy_usage → no Finding (low operator-
          triage value; surface via MCP search tool only)

        Idempotency is the caller's responsibility — same shape as
        emit_prefetch_findings_from_walk; callers DELETE prior
        windows_srum_* findings for the firmware before re-emitting.
        """
        from app.models.windows_srum_record import WindowsSrumRecord

        stmt = select(WindowsSrumRecord).where(
            WindowsSrumRecord.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            drafts = classify_srum_findings(
                record_type=record.record_type,
                app_identifier=record.app_identifier,
                user_identifier=record.user_identifier,
                recorded_at=record.recorded_at,
                bytes_sent=record.bytes_sent,
                bytes_received=record.bytes_received,
                bytes_read=record.bytes_read,
                bytes_written=record.bytes_written,
                cpu_foreground_seconds=record.cpu_foreground_seconds,
                cpu_background_seconds=record.cpu_background_seconds,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    confidence=Confidence.low,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_scheduled_task_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase η.B.D — emit windows_scheduled_task_persistence Finding
        rows for one firmware.

        Reads every persisted ``WindowsScheduledTask`` row for the
        firmware (rows are produced by the η.B.C walker) and projects
        each into ONE Finding row via
        :func:`classify_scheduled_task_persistence_findings`. Confidence
        tier is heuristic-driven by the classifier:

        - HIGH — Action contains encoded-PowerShell pattern (Qakbot
          signature). Severity: high.
        - MEDIUM — RunLevel=HighestAvailable AND non-system Author.
          Severity: medium.
        - LOW — baseline review-candidate row. Severity: info.

        Unlike emit_srum_findings_from_walk / emit_prefetch_findings_from_walk
        (which fix Confidence.low at the emit site), this emit method
        passes the classifier-derived ``draft.confidence`` through to
        the FindingCreate so the heuristic 3-tier mapping is preserved.

        Idempotency is the caller's responsibility — same shape as
        emit_prefetch_findings_from_walk; callers DELETE prior
        windows_scheduled_task_persistence findings for the firmware
        before re-emitting.
        """
        from app.models.windows_scheduled_task import WindowsScheduledTask
        from app.services.jsonb_normalizers import (
            _normalize_windows_scheduled_tasks_actions,
            _normalize_windows_scheduled_tasks_triggers,
        )

        stmt = select(WindowsScheduledTask).where(
            WindowsScheduledTask.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            drafts = classify_scheduled_task_persistence_findings(
                task_name=record.task_name,
                task_uri=record.task_uri,
                author=record.author,
                run_level=record.run_level,
                run_as_user=record.run_as_user,
                triggers=_normalize_windows_scheduled_tasks_triggers(
                    record.triggers
                ),
                actions=_normalize_windows_scheduled_tasks_actions(
                    record.actions
                ),
                source_path=record.source_path,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    # Tier-bearing draft per η.B.D classifier — preserve
                    # the heuristic 3-tier confidence map (HIGH on
                    # encoded-PS, MEDIUM on HighestAvailable + non-system
                    # Author, LOW baseline).
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_lnk_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase η.C.D — emit windows_lnk_abnormal_target Finding rows
        for one firmware.

        Reads every persisted ``WindowsLnkRecord`` row for the firmware
        (rows are produced by the η.C.C walker) and projects each into
        ONE Finding row via :func:`classify_lnk_abnormal_target_findings`.
        Confidence tier is heuristic-driven by the classifier:

        - HIGH — target_path is a known script-host binary AND
          arguments contain encoded-PowerShell pattern (Qakbot
          signature). Severity: high.
        - MEDIUM — target_path is non-Microsoft. Severity: medium.
        - LOW — baseline review-candidate row. Severity: info.

        Unlike emit_srum_findings_from_walk / emit_prefetch_findings_from_walk
        (which fix Confidence.low at the emit site), this emit method
        passes the classifier-derived ``draft.confidence`` through to
        the FindingCreate so the heuristic 3-tier mapping is preserved.
        Mirrors emit_scheduled_task_findings_from_walk shape.

        Idempotency is the caller's responsibility — same shape as
        emit_prefetch_findings_from_walk; callers DELETE prior
        windows_lnk_abnormal_target findings for the firmware before
        re-emitting.
        """
        from app.models.windows_lnk_record import WindowsLnkRecord

        stmt = select(WindowsLnkRecord).where(
            WindowsLnkRecord.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            drafts = classify_lnk_abnormal_target_findings(
                lnk_filename=record.lnk_filename,
                source_path=record.source_path,
                target_path=record.target_path,
                working_directory=record.working_directory,
                arguments=record.arguments,
                description=record.description,
                show_command=record.show_command,
                hotkey=record.hotkey,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    # Tier-bearing draft per η.C.D classifier — preserve
                    # the heuristic 3-tier confidence map (HIGH on
                    # script-host + encoded-PS, MEDIUM on non-Microsoft
                    # target, LOW baseline).
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_mft_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase η.A.D — emit windows_mft_ads_hidden_content +
        windows_mft_timestomping Finding rows for one firmware.

        Reads every persisted ``WindowsMftRecord`` row for the firmware
        (rows are produced by the η.A.C walker) and projects each row
        through :func:`classify_mft_findings` which may emit 0, 1, or 2
        drafts (ADS-hidden and timestomp are independent detection
        patterns; a single record can fire on both).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — large ADS payload (>16 KB) OR all four $SI/$FN pairs
          inverted (timestomp.exe-style full rewrite).
        - MEDIUM — smaller ADS payload (1 KB – 16 KB) OR single-pair
          $SI/$FN inversion.

        Unlike emit_srum_findings_from_walk / emit_prefetch_findings_from_walk
        (which fix Confidence.low at the emit site), this emit method
        passes the classifier-derived ``draft.confidence`` through to
        the FindingCreate so the heuristic tier mapping is preserved.
        Mirrors emit_lnk_findings_from_walk + emit_scheduled_task_findings_from_walk
        shape.

        Idempotency is the caller's responsibility — same shape as
        emit_prefetch_findings_from_walk; callers DELETE prior
        windows_mft_* findings for the firmware before re-emitting.
        """
        from app.models.windows_mft_record import WindowsMftRecord
        from app.services.jsonb_normalizers import (
            _normalize_windows_mft_records_ads_streams,
        )

        stmt = select(WindowsMftRecord).where(
            WindowsMftRecord.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            ads_streams = _normalize_windows_mft_records_ads_streams(
                record.ads_streams
            )
            drafts = classify_mft_findings(
                filename=record.filename,
                source_path=record.source_path,
                full_path=record.full_path,
                ads_streams=ads_streams,
                si_creation_ns=record.si_creation_ns,
                si_last_modification_ns=record.si_last_modification_ns,
                si_last_change_ns=record.si_last_change_ns,
                si_last_access_ns=record.si_last_access_ns,
                fn_creation_ns=record.fn_creation_ns,
                fn_last_modification_ns=record.fn_last_modification_ns,
                fn_last_change_ns=record.fn_last_change_ns,
                fn_last_access_ns=record.fn_last_access_ns,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    # Tier-bearing draft per η.A.D classifier — preserve
                    # the heuristic tier confidence map (HIGH on >16 KB
                    # ADS or full $SI/$FN inversion; MEDIUM on smaller
                    # ADS or single-pair inversion).
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_bcd_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase θ.A.D — emit windows_bcd_suspicious_path +
        windows_bcd_testsigning_enabled Finding rows for one firmware.

        Reads every persisted ``WindowsBcdEntry`` row for the firmware
        (rows are produced by the θ.A.C walker) and projects each row
        through :func:`classify_bcd_findings` which may emit 0, 1, or 2
        drafts (suspicious_path and testsigning_enabled are independent
        detection patterns; a single entry can fire on both).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — suspicious_path AND (non_microsoft_description OR
          testsigning_enabled); OR testsigning_enabled AND
          (no_integrity_checks OR nx_disabled).
        - MEDIUM — single-flag baseline (suspicious_path alone OR
          testsigning_enabled alone).

        Unlike emit_srum_findings_from_walk / emit_prefetch_findings_from_walk
        (which fix Confidence.low at the emit site), this emit method
        passes the classifier-derived ``draft.confidence`` through to
        the FindingCreate so the heuristic tier mapping is preserved.
        Mirrors emit_lnk_findings_from_walk / emit_mft_findings_from_walk
        shape.

        Idempotency is the caller's responsibility — same shape as
        emit_mft_findings_from_walk; callers DELETE prior
        windows_bcd_* findings for the firmware before re-emitting.
        """
        from app.models.windows_bcd_entry import WindowsBcdEntry
        from app.services.jsonb_normalizers import (
            _normalize_windows_bcd_entries_anomaly_flags,
        )

        stmt = select(WindowsBcdEntry).where(
            WindowsBcdEntry.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            anomaly_flags = _normalize_windows_bcd_entries_anomaly_flags(
                record.anomaly_flags
            )
            drafts = classify_bcd_findings(
                object_guid=record.object_guid,
                source_path=record.source_path,
                description=record.description,
                image_path=record.image_path,
                anomaly_flags=anomaly_flags,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    # Tier-bearing draft per θ.A.D classifier — preserve
                    # the heuristic tier confidence map (HIGH on
                    # combined suspicious_path + non_ms OR testsigning,
                    # OR testsigning + integrity_off; MEDIUM on single-
                    # flag baseline).
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_wmi_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase θ.B.E — emit windows_wmi_persistence Finding rows
        for one firmware.

        Reads every persisted ``WindowsWmiEvent`` row for the firmware
        (rows are produced by the θ.B.D walker) and projects each non-
        benign row through :func:`classify_wmi_findings` which emits
        0 (benign BVT/SCM bindings — skipped) or 1 draft (every non-
        benign FilterToConsumerBinding earns at least a LOW finding).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — ActiveScriptEventConsumer (in-process VBScript/
          JScript — highest impact), OR consumer_payload carries
          encoded-PowerShell pattern (Qakbot signature). Severity:
          high.
        - MEDIUM — CommandLineEventConsumer + script-host invocation.
          LOLBin-via-WMI shape. Severity: medium.
        - LOW — baseline review-candidate row. Severity: low.

        Unlike emit_srum_findings_from_walk / emit_prefetch_findings_from_walk
        (which fix Confidence.low at the emit site), this emit method
        passes the classifier-derived ``draft.confidence`` through to
        the FindingCreate so the heuristic 3-tier mapping is preserved.
        Mirrors emit_lnk_findings_from_walk + emit_bcd_findings_from_walk
        shape.

        Idempotency is the caller's responsibility — same shape as
        emit_bcd_findings_from_walk; callers DELETE prior
        windows_wmi_persistence findings for the firmware before
        re-emitting.

        Per Rule #36 — the classifier never invokes consumer payloads;
        the payload is surfaced as DATA in the Finding's evidence
        field for operator review only.
        """
        from app.models.windows_wmi_event import WindowsWmiEvent
        from app.services.jsonb_normalizers import (
            _normalize_windows_wmi_events_consumer_payload,
        )

        stmt = select(WindowsWmiEvent).where(
            WindowsWmiEvent.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            consumer_payload = (
                _normalize_windows_wmi_events_consumer_payload(
                    record.consumer_payload
                )
            )
            drafts = classify_wmi_findings(
                binding_id=record.binding_id,
                filter_name=record.filter_name,
                filter_query=record.filter_query,
                consumer_name=record.consumer_name,
                consumer_type=record.consumer_type,
                consumer_payload=consumer_payload,
                source_path=record.source_path,
                probably_benign=record.probably_benign,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.source_path,
                    # Tier-bearing draft per θ.B.E classifier — preserve
                    # the heuristic 3-tier confidence map (HIGH on
                    # ActiveScript OR encoded-PS, MEDIUM on
                    # CommandLine + script-host, LOW baseline).
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_esp_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase θ.C.D — emit windows_esp_unsigned +
        windows_esp_dbx_revoked Finding rows for one firmware.

        Reads every persisted ``WindowsEspEntry`` row for the firmware
        (rows are produced by the θ.C.C walker) and projects each row
        through :func:`classify_esp_findings` which may emit 0, 1, or 2
        drafts (unsigned + dbx_revoked are independent detection
        patterns; a single entry can in rare cases fire on both).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — unsigned `.efi` AND is_known_bootloader_path
          (BlackLotus canonical shape); OR signed_revoked
          (DBX-revoked, authoritative).
        - MEDIUM — unsigned `.efi` AND is_vendor_path.

        Mirrors emit_bcd_findings_from_walk / emit_wmi_findings_from_walk
        shape — tier-bearing drafts preserved through the boundary.

        Idempotency is the caller's responsibility — callers DELETE
        prior windows_esp_* findings for the firmware before
        re-emitting.

        Per Rule #36 — the classifier never invokes the `.efi` PEs;
        the file_path + sha256 + state are surfaced as DATA in the
        Finding's evidence field for operator review only.
        """
        from app.models.windows_esp_entry import WindowsEspEntry
        from app.services.jsonb_normalizers import (
            _normalize_windows_esp_entries_anomaly_flags,
            _normalize_windows_esp_entries_authenticode_chain,
            _normalize_windows_esp_entries_dbx_revocation_match,
        )

        stmt = select(WindowsEspEntry).where(
            WindowsEspEntry.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            anomaly_flags = _normalize_windows_esp_entries_anomaly_flags(
                record.anomaly_flags
            )
            chain_dict = _normalize_windows_esp_entries_authenticode_chain(
                record.authenticode_chain
            )
            dbx_match_dict = (
                _normalize_windows_esp_entries_dbx_revocation_match(
                    record.dbx_revocation_match
                )
            )
            drafts = classify_esp_findings(
                file_path=record.file_path,
                file_sha256=record.file_sha256,
                file_size=record.file_size,
                authenticode_state=record.authenticode_state,
                anomaly_flags=anomaly_flags,
                chain_dict=chain_dict if chain_dict else None,
                dbx_match_dict=dbx_match_dict,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.file_path,
                    # Tier-bearing draft per θ.C.D classifier —
                    # preserve heuristic tier confidence map.
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_mbr_vbr_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase θ.E.D — emit windows_mbr_bootkit + windows_vbr_anomaly
        Finding rows for one firmware.

        Reads every persisted ``WindowsMbrVbrSector`` row for the
        firmware (rows are produced by the θ.E.C walker) and projects
        each row through :func:`classify_mbr_vbr_findings` which may
        emit 0 or 1 drafts per row (mbr_bootkit vs vbr_anomaly are
        mutually exclusive per sector_kind).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — named bootkit match (windows_mbr_bootkit always
          HIGH; windows_vbr_anomaly HIGH when known_bootkit_match
          populated).
        - MEDIUM — windows_vbr_anomaly with bootcode_signature_match=
          NULL AND >=2 anomaly flags.

        Mirrors emit_esp_findings_from_walk / emit_bcd_findings_from_walk
        shape — tier-bearing drafts preserved through the boundary.

        Idempotency is the caller's responsibility — callers DELETE
        prior windows_mbr_* / windows_vbr_* findings for the firmware
        before re-emitting.

        Per Rule #36 — the classifier never invokes the boot sector
        code; the file_path + sector_offset + sha256 + bootkit_match
        are surfaced as DATA in the Finding's evidence field for
        operator review only.
        """
        from app.models.windows_mbr_vbr_sector import WindowsMbrVbrSector
        from app.services.jsonb_normalizers import (
            _normalize_windows_mbr_vbr_sectors_anomaly_flags,
        )

        stmt = select(WindowsMbrVbrSector).where(
            WindowsMbrVbrSector.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            anomaly_flags = (
                _normalize_windows_mbr_vbr_sectors_anomaly_flags(
                    record.anomaly_flags
                )
            )
            drafts = classify_mbr_vbr_findings(
                file_path=record.file_path,
                sector_offset=record.sector_offset,
                sector_kind=record.sector_kind,
                sector_sha256=record.sector_sha256,
                sector_size=record.sector_size,
                bootcode_signature_match=record.bootcode_signature_match,
                known_bootkit_match=record.known_bootkit_match,
                anomaly_flags=anomaly_flags,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.file_path,
                    # Tier-bearing draft per θ.E.D classifier —
                    # preserve heuristic tier confidence map.
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_sdb_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase θ.D.E — emit windows_sdb_inject_dll +
        windows_sdb_redirect_exe + windows_sdb_custom_shim Finding
        rows for one firmware.

        Reads every persisted ``WindowsSdbEntry`` row for the
        firmware (rows are produced by the θ.D.D walker) and projects
        each row through :func:`classify_sdb_findings` which may
        emit 0 or 1 drafts per row (mbr_inject_dll / redirect_exe /
        custom_shim are mutually exclusive per shim_class).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — windows_sdb_inject_dll AND windows_sdb_redirect_exe
          always HIGH (direct attacker primitive in custom path).
        - MEDIUM — windows_sdb_custom_shim with shim_class in
          (GetCommandLineW, RedirectShortcut) OR has_command_line.
        - LOW — windows_sdb_custom_shim baseline (Custom-path with
          unknown shim_name).
        - 0 drafts — microsoft-path entries (Microsoft-shipped shims
          are benign by location) AND unknown-path entries (operator
          review via list_sdb_entries; not auto-emitted to avoid
          noise).

        Mirrors emit_mbr_vbr_findings_from_walk / emit_esp_findings_
        from_walk shape — tier-bearing drafts preserved through the
        boundary.

        Idempotency is the caller's responsibility — callers DELETE
        prior windows_sdb_* findings for the firmware before
        re-emitting.

        Per Rule #36 — the classifier never invokes the shim
        infrastructure; the file_path + file_sha256 + shim_payload
        + anomaly_flags are surfaced as DATA in the Finding's
        evidence field for operator review only.
        """
        from app.models.windows_sdb_entry import WindowsSdbEntry
        from app.services.jsonb_normalizers import (
            _normalize_windows_sdb_entries_anomaly_flags,
            _normalize_windows_sdb_entries_shim_payload,
        )

        stmt = select(WindowsSdbEntry).where(
            WindowsSdbEntry.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            shim_payload = _normalize_windows_sdb_entries_shim_payload(
                record.shim_payload
            )
            anomaly_flags = (
                _normalize_windows_sdb_entries_anomaly_flags(
                    record.anomaly_flags
                )
            )
            drafts = classify_sdb_findings(
                file_path=record.file_path,
                file_sha256=record.file_sha256,
                sdb_kind=record.sdb_kind,
                app_name=record.app_name,
                app_exe=record.app_exe,
                shim_class=record.shim_class,
                shim_payload=shim_payload,
                anomaly_flags=anomaly_flags,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.file_path,
                    # Tier-bearing draft per θ.D.E classifier —
                    # preserve heuristic tier confidence map.
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_journald_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase ι.A.D — emit linux_journald_* Finding rows for one
        firmware (FIRST LINUX emit hook).

        Reads every persisted ``LinuxJournaldEntry`` row for the
        firmware (rows produced by the ι.A.C walker) and projects each
        row through :func:`classify_journald_findings` which may emit
        0-5 drafts (each anomaly bit is independent — a single
        priority-0 OOM-kill entry under a /tmp unit can fire on
        priority_critical + oom_killer + suspicious_unit
        simultaneously).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — linux_journald_suspicious_unit (T1543.002 always HIGH
          — APT36 / FIRESTARTER / Quasar tradecraft).
        - MEDIUM — linux_journald_oom_killer / log_clear / selinux_denied
          (T1499 / T1070.002 / T1562.001 — ambiguous between
          adversary and legitimate, operator triages).
        - LOW — linux_journald_priority_critical (review-candidate
          baseline).

        Mirrors emit_bcd_findings_from_walk + emit_mft_findings_from_walk
        shape — tier-bearing drafts preserved through the boundary so
        FindingCreate.confidence reflects the heuristic map.

        Idempotency is the caller's responsibility — same shape as
        emit_bcd_findings_from_walk; callers DELETE prior
        linux_journald_* findings for the firmware before re-emitting.

        Per Rule #36 — the classifier never invokes ``journalctl`` /
        ``systemd-cat`` against the parsed entries; the message /
        unit / cmdline are surfaced as DATA in the Finding's evidence
        field for operator review only.
        """
        from app.models.linux_journald_entry import LinuxJournaldEntry
        from app.services.jsonb_normalizers import (
            _normalize_linux_journald_entries_anomaly_flags,
        )

        stmt = select(LinuxJournaldEntry).where(
            LinuxJournaldEntry.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            anomaly_flags = (
                _normalize_linux_journald_entries_anomaly_flags(
                    record.anomaly_flags
                )
            )
            drafts = classify_journald_findings(
                journal_file_path=record.journal_file_path,
                realtime_us=record.realtime_timestamp_us,
                message=record.message,
                unit=record.unit,
                pid=record.pid,
                uid=record.uid,
                hostname=record.hostname,
                transport=record.transport,
                anomaly_flags=anomaly_flags,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.journal_file_path,
                    # Tier-bearing draft per ι.A.D classifier —
                    # preserve heuristic tier confidence map.
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_systemd_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Phase ι.B.D — emit linux_systemd_* Finding rows for one
        firmware (SECOND LINUX emit hook; ι.A.D shipped journald).

        Reads every persisted ``LinuxSystemdUnit`` row for the firmware
        (rows produced by the ι.B.C walker) and projects each row
        through :func:`classify_systemd_findings` which may emit 0-5
        drafts (each anomaly bit is independent — a single unit with
        ExecStart under /tmp/, root user, and base64 obfuscation can
        fire suspicious_path + obfuscated_exec + root_minimal_deps
        simultaneously).

        Confidence tier is heuristic-driven by the classifier:

        - HIGH — linux_systemd_suspicious_path (T1543.002 always HIGH
          — APT36 / FIRESTARTER / Quasar tradecraft).
        - HIGH — linux_systemd_obfuscated_exec (T1027 — base64/eval/
          curl|sh pattern).
        - MEDIUM — linux_systemd_socket_unusual_port (T1571 Non-
          Standard Port).
        - MEDIUM — linux_systemd_root_minimal_deps (rootkit pattern;
          ambiguous between legitimate baselines and adversary
          droppers).
        - MEDIUM — linux_systemd_enabled_outside_standard (custom
          WantedBy target).

        Mirrors emit_journald_findings_from_walk shape — tier-bearing
        drafts preserved through the boundary so FindingCreate.confidence
        reflects the heuristic map.

        Idempotency is the caller's responsibility — same shape as
        emit_journald_findings_from_walk; callers DELETE prior
        linux_systemd_* findings for the firmware before re-emitting.

        Per Rule #36 — the classifier never invokes ``systemctl`` /
        ``systemd-run`` / ``runuser`` against the parsed units; the
        ExecStart= / WorkingDirectory= / Socket listen fields are
        surfaced as DATA in the Finding's evidence field for operator
        review only.
        """
        from app.models.linux_systemd_units import LinuxSystemdUnit
        from app.services.jsonb_normalizers import (
            _normalize_linux_systemd_units_after,
            _normalize_linux_systemd_units_anomaly_flags,
            _normalize_linux_systemd_units_required_by,
            _normalize_linux_systemd_units_requires,
            _normalize_linux_systemd_units_socket_listen,
            _normalize_linux_systemd_units_wanted_by,
        )

        stmt = select(LinuxSystemdUnit).where(
            LinuxSystemdUnit.firmware_id == firmware_id
        )
        rows = (await self.db.execute(stmt)).scalars().all()

        emitted: list[Finding] = []
        for record in rows:
            anomaly_flags = (
                _normalize_linux_systemd_units_anomaly_flags(
                    record.anomaly_flags
                )
            )
            drafts = classify_systemd_findings(
                unit_path=record.unit_path,
                unit_type=record.unit_type,
                unit_name=record.unit_name,
                description=record.description,
                exec_start=record.exec_start,
                user=record.user,
                working_directory=record.working_directory,
                wanted_by=_normalize_linux_systemd_units_wanted_by(
                    record.wanted_by
                ),
                required_by=_normalize_linux_systemd_units_required_by(
                    record.required_by
                ),
                requires=_normalize_linux_systemd_units_requires(
                    record.requires
                ),
                enabled=record.enabled,
                socket_listen=_normalize_linux_systemd_units_socket_listen(
                    record.socket_listen
                ),
                anomaly_flags=anomaly_flags,
            )
            # Suppress unused import warning if the parser drops the
            # after-normalizer reference.
            _ = _normalize_linux_systemd_units_after
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=record.unit_path,
                    # Tier-bearing draft per ι.B.D classifier —
                    # preserve heuristic tier confidence map.
                    confidence=draft.confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_byovd_findings_from_driver(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
        driver_path: str,
        blob_sha256: str,
        verdict: "BYOVDVerdict",
    ) -> Finding | None:
        """Phase η.D.D — emit windows_byovd_driver Finding row for one
        LOLDrivers verdict.

        Called by the α.2.6 driver-package unpacker hook AND the γ Services
        hive walker (η.D.E) immediately after a non-None
        :func:`lookup_driver_byovd` result. Returns the persisted Finding
        on success, or ``None`` when the caller passes a None verdict
        (defensive; callers should gate on this themselves).

        The classifier (:func:`classify_byovd_finding`) decides the tier
        from category + CVE + HVCI; this method just persists the result.

        Idempotency is the caller's responsibility — same shape as
        emit_lnk_findings_from_walk / emit_mft_findings_from_walk;
        callers DELETE prior windows_byovd_driver findings for the
        driver before re-emitting (or use the driver_path + blob_sha256
        natural-key to deduplicate at the walker layer).
        """
        from app.services.loldrivers_lookup_service import reference_url

        if verdict is None:
            return None

        draft = classify_byovd_finding(
            driver_path=driver_path,
            blob_sha256=blob_sha256,
            category=verdict.category,
            cve_ids=list(verdict.cve_ids or []),
            mitre_id=verdict.mitre_id,
            filename=verdict.filename,
            loldrivers_id=verdict.loldrivers_id,
            loads_despite_hvci=bool(verdict.loads_despite_hvci),
            sha256_match_kind=verdict.sha256_match_kind,
            reference_url=reference_url(verdict.loldrivers_id),
        )

        data = FindingCreate(
            title=draft.title,
            severity=draft.severity,
            description=draft.description,
            evidence=draft.evidence,
            file_path=driver_path,
            cve_ids=list(verdict.cve_ids or []) or None,
            confidence=draft.confidence,
            firmware_id=firmware_id,
            source=draft.source,
        )
        return await self.create(project_id, data)

    async def emit_driver_findings_from_extract(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Emit windows_inf + windows_driver_imports Finding rows for one firmware.

        Reads every persisted ``WindowsDriver`` row for the firmware,
        classifies each driver via :func:`classify_driver_findings`,
        and persists the resulting drafts as Finding rows.

        Idempotency is the caller's responsibility (same shape as
        emit_registry_findings_from_walk).
        """
        from app.models.hardware_firmware import HardwareFirmwareBlob
        from app.models.windows_driver import WindowsDriver

        stmt = (
            select(WindowsDriver, HardwareFirmwareBlob)
            .join(
                HardwareFirmwareBlob,
                WindowsDriver.blob_id == HardwareFirmwareBlob.id,
            )
            .where(HardwareFirmwareBlob.firmware_id == firmware_id)
        )
        rows = (await self.db.execute(stmt)).all()

        emitted: list[Finding] = []
        for driver, _blob in rows:
            drafts = classify_driver_findings(
                driver_path=driver.driver_path,
                signing_tier=driver.signing_tier,
                catalog_signed=driver.catalog_signed,
                pnp_ids=driver.pnp_ids or [],
                inf_metadata=driver.inf_metadata,
                manufacturer=driver.manufacturer,
                inf_class=driver.inf_class,
            )
            for draft in drafts:
                data = FindingCreate(
                    title=draft.title,
                    severity=draft.severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=driver.driver_path,
                    confidence=Confidence.medium,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_r2r_stomp_findings_from_decompile(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Emit windows_r2r_stomp Finding rows for one firmware (Phase δ.8).

        Reads the firmware's ``dotnet_decompile_result`` aggregate (δ.4),
        runs the δ.6 :func:`classify_r2r_stomp_findings` classifier across
        every detected bundle, and persists the resulting drafts as
        Finding rows.

        Idempotency is the caller's responsibility — δ.8's emit-from-
        decompile wrapper DELETEs prior windows_r2r_stomp + windows_il_capa
        findings for the firmware before re-emitting, mirroring the β.12c +
        γ.8 patterns.

        Confidence tier mapping:
        - Tier 1 (LOW review candidate) → Confidence.low
        - Tier 2 (MEDIUM capa/IL divergence) → Confidence.medium
        - Tier 3/4 (HIGH/CRITICAL — deferred) → Confidence.high (when shipped)
        """
        from app.models.firmware import Firmware
        from app.services.jsonb_normalizers import (
            _normalize_firmware_dotnet_decompile_result,
        )
        from app.services.r2r_stomping import classify_r2r_stomp_findings

        fw = (
            await self.db.execute(
                select(Firmware).where(Firmware.id == firmware_id)
            )
        ).scalar_one_or_none()
        if fw is None:
            return []

        aggregate = _normalize_firmware_dotnet_decompile_result(
            fw.dotnet_decompile_result
        ) or {}
        bundles = aggregate.get("bundles") or []

        # Pre-emit cleanup — delete prior δ.8 sources so re-runs don't
        # accumulate duplicate review candidates.
        from app.models.finding import Finding as FindingModel

        await self.db.execute(
            FindingModel.__table__.delete().where(
                FindingModel.firmware_id == firmware_id,
                FindingModel.source.in_((_SOURCE_R2R_STOMP, _SOURCE_IL_CAPA)),
            )
        )

        emitted: list[Finding] = []
        for b in bundles:
            if not isinstance(b, dict):
                continue
            bundle_path = b.get("bundle_path")
            decompile_root = b.get("decompile_target_dir")
            if not bundle_path:
                continue
            for draft in classify_r2r_stomp_findings(bundle_path, decompile_root):
                # Map δ.6 tier → wairz Confidence
                if draft.confidence_tier == 1:
                    confidence = Confidence.low
                elif draft.confidence_tier == 2:
                    confidence = Confidence.medium
                else:
                    confidence = Confidence.high
                # Map δ.6 string severity → schemas.finding.Severity
                severity = Severity(draft.severity)
                data = FindingCreate(
                    title=draft.title,
                    severity=severity,
                    description=draft.description,
                    evidence=draft.evidence,
                    file_path=draft.pe_path,
                    confidence=confidence,
                    firmware_id=firmware_id,
                    source=draft.source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted

    async def emit_evtx_findings_from_walk(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
    ) -> list[Finding]:
        """Emit forensic-timeline Finding rows for one firmware's EVTX
        walk (Phase ε.1.b.4).

        Reads the firmware's ``evtx_walk_result`` aggregate (ε.1.b.3),
        walks the per-file ``records`` lists (sample-records cap from
        ε.1.b.3) classifying by Event ID:

        - Sysmon EID 1 (process create) → :data:`_SOURCE_SYSMON_PROC_CREATE`
        - Security EID 4624 (logon success) → :data:`_SOURCE_LOGON_SUCCESS`
        - Security EID 4625 (logon failure) → :data:`_SOURCE_LOGON_FAILURE`
        - PowerShell EID 4103/4104 → :data:`_SOURCE_POWERSHELL_SCRIPT_BLOCK`
          (Phase η.E extension — heuristic-driven confidence via
          :func:`_classify_powershell_event`; 4105/4106 not emitted)

        Idempotency is the caller's responsibility — this emitter
        DELETEs prior ε.1.b.4 + η.E sources for the firmware before
        re-emitting, mirroring the β.12c + γ.8 + δ.8 patterns.

        ε.1.b.4 ships LOW confidence baseline for the original 3
        sources. Phase η.E adds PowerShell EID classification with
        per-event confidence (4103 → LOW, 4104 plain → MEDIUM, 4104
        + obfuscation → HIGH). Higher-tier threat-feed correlation
        for the original 3 ε sources is deferred to a future θ phase
        once per-event row persistence supports full record
        inspection.
        """
        from app.models.finding import Finding as FindingModel
        from app.models.firmware import Firmware
        from app.services.jsonb_normalizers import (
            _normalize_firmware_evtx_walk_result,
        )

        fw = (
            await self.db.execute(
                select(Firmware).where(Firmware.id == firmware_id)
            )
        ).scalar_one_or_none()
        if fw is None:
            return []

        aggregate = _normalize_firmware_evtx_walk_result(fw.evtx_walk_result) or {}
        per_file = aggregate.get("per_file") or []
        if not per_file:
            return []

        # Pre-emit cleanup — delete prior ε.1.b.4 + η.E sources so
        # re-runs don't accumulate duplicate review candidates.
        await self.db.execute(
            FindingModel.__table__.delete().where(
                FindingModel.firmware_id == firmware_id,
                FindingModel.source.in_(
                    (
                        _SOURCE_SYSMON_PROC_CREATE,
                        _SOURCE_LOGON_SUCCESS,
                        _SOURCE_LOGON_FAILURE,
                        _SOURCE_POWERSHELL_SCRIPT_BLOCK,
                    )
                ),
            )
        )

        # Re-walk the .evtx files to extract sample records — the
        # aggregate carries the per-file shape (paths + status) but
        # the records list is held in memory only during the walk run.
        # For ε.1.b.4 we re-parse a bounded sample per file via
        # parse_evtx_file (Rule #5 sync I/O wrapped in run_in_executor).
        import asyncio
        import re

        from app.services.evtx_service import parse_evtx_file as _parse_evtx

        loop = asyncio.get_running_loop()
        emitted: list[Finding] = []

        # Per-EID classification table: regex matches the Event ID in
        # the raw_xml string. Cheap regex extraction beats lxml parse
        # for the dispatch — the heuristic only needs the EID + provider
        # for routing.
        _EID_RE = re.compile(r"<EventID(?:\s+[^>]*)?>(\d+)</EventID>")

        for file_entry in per_file:
            if not isinstance(file_entry, dict):
                continue
            path = file_entry.get("path")
            if not path or file_entry.get("status") != "ok":
                continue

            try:
                parsed = await loop.run_in_executor(None, _parse_evtx, path)
            except Exception:  # noqa: BLE001 — defensive
                continue
            records = parsed.get("records") or []
            if not records:
                continue

            for rec in records:
                xml = rec.get("raw_xml") or ""
                m = _EID_RE.search(xml)
                if not m:
                    continue
                eid = int(m.group(1))

                # Route by EID — Sysmon-1 / 4624 / 4625 (ε.1.b.4) +
                # PowerShell 4103/4104 (η.E).
                source: WindowsFindingSource | None
                confidence: Confidence
                if eid == 1 and "Sysmon" in xml:
                    source = _SOURCE_SYSMON_PROC_CREATE
                    title = f"Sysmon process-create event (EID 1) at {path}"
                    confidence = Confidence.low
                elif eid == 4624:
                    source = _SOURCE_LOGON_SUCCESS
                    title = f"Logon success (EID 4624) at {path}"
                    confidence = Confidence.low
                elif eid == 4625:
                    source = _SOURCE_LOGON_FAILURE
                    title = f"Logon failure (EID 4625) at {path}"
                    confidence = Confidence.low
                elif eid in (4103, 4104):
                    # Phase η.E — PowerShell EID classification (4103
                    # module-load → LOW; 4104 plain ScriptBlock →
                    # MEDIUM; 4104 + obfuscation indicator → HIGH).
                    classified = _classify_powershell_event(eid, xml)
                    if classified is None:
                        continue
                    confidence, ps_title = classified
                    source = _SOURCE_POWERSHELL_SCRIPT_BLOCK
                    title = f"{ps_title} at {path}"
                else:
                    continue

                # Truncate the raw_xml evidence to keep finding rows
                # under the title-512 + standard-Text limits.
                evidence = xml[:2000] if xml else None
                data = FindingCreate(
                    title=title[:255],
                    severity=Severity.info,
                    description=(
                        f"Forensic-timeline Finding from EVTX walk. EID={eid}; "
                        f"file={path}; record_num={rec.get('record_num')}. "
                        "Confidence: LOW=baseline review candidate; "
                        "MEDIUM=script execution; HIGH=obfuscation indicator. "
                        "Higher-tier threat-feed correlation deferred to a "
                        "future θ phase."
                    ),
                    evidence=evidence,
                    file_path=path,
                    confidence=confidence,
                    firmware_id=firmware_id,
                    source=source,
                )
                emitted.append(await self.create(project_id, data))
        return emitted
