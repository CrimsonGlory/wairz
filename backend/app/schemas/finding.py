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
