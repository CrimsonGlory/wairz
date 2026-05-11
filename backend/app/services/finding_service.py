import os
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.schemas.finding import (
    Confidence,
    FindingCreate,
    FindingUpdate,
    Severity,
    WindowsFindingSource,
)

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
