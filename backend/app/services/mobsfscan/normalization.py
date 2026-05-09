"""Finding normalization + severity adjustment + rule/path suppressions.

This module is the **post-processing** layer of the mobsfscan pipeline.
The raw :class:`~app.services.mobsfscan.parser.MobsfScanFinding` objects
produced by the CLI runner are transformed into the project's unified
:class:`~app.schemas.finding.FindingCreate`-shaped
:class:`NormalizedFinding` via :func:`normalize_mobsfscan_findings`, which
applies:

- **Rule suppressions** — rules listed in :data:`SUPPRESSED_RULES` are
  dropped entirely (high false-positive rate or redundant with Phase 1
  manifest / Phase 2a bytecode checks).
- **Path suppressions** — findings in library/generated code paths
  (see :data:`SUPPRESSED_PATH_PATTERNS`) are dropped.  Note: path
  suppression happens in the parser layer (raw findings are filtered out
  before they reach the normalizer) but the patterns live here so that
  normalization config lives together.
- **Severity overrides** — :data:`SEVERITY_OVERRIDES` maps rule IDs to
  APK-specific severities (e.g. crypto→high, hardcoded secrets→high).
- **Firmware-context bump** — APKs under ``priv-app/`` get a one-level
  severity bump via :func:`_bump_severity`.
- **Minimum-severity filter** — findings below the requested threshold
  are silently dropped.
- **Deduplication** — findings sharing ``(rule_id, severity, file_path)``
  are collapsed via SHA-256 dedup key.

Cache implication: raw scan results in ``analysis_cache`` are stored
pre-normalization, so a config change here produces a different
normalized output **without** re-running the CLI.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.models.finding import Finding
from app.utils.firmware_context import enrich_description, enrich_evidence

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.services.mobsfscan.parser import MobsfScanResult
    from app.utils.firmware_context import FirmwareContext


# ---------------------------------------------------------------------------
# Rule suppressions & severity overrides
# ---------------------------------------------------------------------------
# These configurations reduce false-positive noise and align mobsfscan
# severity with APK-specific context.  They are applied during the
# normalization step so that cached raw results remain un-filtered (a
# config change triggers a different normalized output without rescan).

#: Rules that are **always suppressed** (high false-positive rate or
#: redundant with Wairz Phase 1 manifest checks / Phase 2a bytecode).
#: Keys are exact mobsfscan ``rule_id`` strings.
SUPPRESSED_RULES: frozenset[str] = frozenset({
    # --- Manifest-level rules already covered by Phase 1 ---
    # Phase 1 androguard_service.py checks allowBackup, debuggable,
    # exported components, NSC cleartext, etc. with firmware-context
    # awareness that mobsfscan lacks.
    "android_manifest_backup",
    "android_manifest_debug",
    "android_exported_component",
    "android_exported_content_provider",
    "android_manifest_cleartext",
    "android_ns_cleartext",
    "android_ns_temp_cert",
    "android_permission_dangerous",

    # --- High false-positive / low-signal rules ---
    # Logging detection: matches all Log.* calls; nearly every app uses
    # android.util.Log — true positives require runtime context (e.g.
    # logging of PII) that static analysis cannot determine.
    "android_logging",
    "android_log_info",

    # IP address regex: fires on localhost (127.0.0.1), link-local,
    # broadcast, and documentation IPs embedded in comments/strings.
    "android_ip_disclosure",
    "android_ip_private",

    # Generic temp file detection: flags File.createTempFile() which is
    # the *correct* way to create temp files on Android (vs. hardcoded
    # paths).  The real risk is not cleaning up — which this rule
    # doesn't check.
    "android_temp_file",

    # URL-in-string detections that match every https:// literal
    # including Google Play, Firebase, and documentation URLs.
    "android_hardcoded_url",

    # Clipboard usage: flags ClipboardManager access.  Nearly all apps
    # interact with the clipboard; the risk is context-dependent.
    "android_clipboard",

    # ADB backup flag: duplicate of android_manifest_backup already
    # handled by Phase 1's allowBackup check (with firmware context).
    "android_adb_backup",
})

#: Rules with **overridden severity** (mobsfscan default → Wairz
#: override).  This aligns scanner output with APK-specific risk:
#: e.g. mobsfscan rates some crypto issues as WARNING (medium) but
#: they are genuinely high-severity for mobile apps handling user data.
#:
#: Format: ``rule_id → target_severity`` where severity is one of
#: "critical", "high", "medium", "low", "info".
SEVERITY_OVERRIDES: dict[str, str] = {
    # --- Crypto: promote to high ---
    # Weak/broken algorithms (DES, RC4, MD5 for integrity) are high
    # risk in mobile apps that handle PII, auth tokens, or payment.
    "android_insecure_random": "high",       # java.util.Random instead of SecureRandom
    "android_weak_crypto_des": "high",       # DES/DESede usage
    "android_weak_crypto_rc4": "high",       # RC4 stream cipher
    "android_ecb_cipher": "high",            # ECB mode (pattern-preserving)
    "android_rsa_no_oaep": "high",           # RSA without OAEP padding
    "android_weak_hash": "high",             # MD5/SHA-1 for integrity

    # --- Hardcoded secrets: promote to high/critical ---
    # Embedded API keys and secrets are always high; private keys are critical.
    "android_hardcoded_secret": "high",
    "android_hardcoded_api_key": "high",
    "android_hardcoded_firebase": "high",
    "android_private_key_hardcoded": "critical",

    # --- SQL injection: promote to high ---
    "android_sql_injection_rawquery": "high",
    "android_sql_injection_content_provider": "high",

    # --- TLS/SSL: keep or promote to high ---
    "android_ssl_pinning_bypass": "high",    # disabled cert pinning
    "android_trust_all_certs": "high",       # TrustManager accepting all
    "android_ssl_hostname_bypass": "high",   # hostname verifier bypass
    "android_custom_trust_manager": "medium",

    # --- WebView: align with risk ---
    "android_webview_js_enabled": "medium",  # JS in WebView (context-dependent)
    "android_webview_file_access": "high",   # file:// access in WebView
    "android_webview_debug": "medium",       # WebView remote debugging

    # --- Sensitive data exposure: demote noise ---
    "android_shared_prefs_world_readable": "high",   # world-readable prefs
    "android_external_storage": "medium",    # writing to SD card (common)
    "android_broadcast_sensitive": "low",    # sending sensitive broadcast

    # --- Runtime: adjust for APK context ---
    "android_root_detection_bypass": "info", # root detection is optional
    "android_emulator_detection": "info",    # emulator detection is optional
    "android_dynamic_dex_loading": "medium", # dynamic loading is suspicious
}

#: File-path patterns that should be excluded from scanning.  Matches
#: in *decompiled* source paths often originate from bundled libraries
#: or generated code where findings are not actionable by the APK author.
SUPPRESSED_PATH_PATTERNS: tuple[str, ...] = (
    # Google/Android support/jetpack libraries — enormous volume, not
    # user code.  Findings here are against the platform, not the app.
    "com/google/android/",
    "androidx/",
    "android/support/",

    # Common third-party SDKs that generate high-volume findings.
    "com/facebook/",
    "com/crashlytics/",
    "com/google/firebase/",
    "com/squareup/okhttp",
    "io/reactivex/",
    "kotlin/",
    "kotlinx/",

    # Auto-generated code (R.java, BuildConfig, databinding).
    "/R$",      # R$style.java, R$layout.java, etc.
    "/R.java",
    "/BuildConfig.java",
    "/databinding/",
)


def _is_suppressed_path(file_path: str) -> bool:
    """Return True if *file_path* matches a suppressed path pattern.

    Uses substring matching against :data:`SUPPRESSED_PATH_PATTERNS`.
    Forward-slash normalisation handles both Unix and Windows-style
    paths from mobsfscan output.
    """
    normalised = file_path.replace("\\", "/")
    return any(pat in normalised for pat in SUPPRESSED_PATH_PATTERNS)


def _apply_severity_override(rule_id: str, base_severity: str) -> str:
    """Return the overridden severity for *rule_id*, or *base_severity*
    if no override is configured.
    """
    return SEVERITY_OVERRIDES.get(rule_id, base_severity)


# ---------------------------------------------------------------------------
# Severity ordering & firmware-context helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

# CWE regex: accept "CWE-123", "cwe-123", "CWE:123", or bare "123"
_CWE_RE = re.compile(r"(?:CWE[-:]?\s*)?(\d+)", re.IGNORECASE)


def _parse_cwe_ids(raw_cwe: str) -> list[str]:
    """Extract structured CWE IDs from mobsfscan's free-form CWE string.

    mobsfscan uses inconsistent formats:
      - ``"CWE-312"``
      - ``"CWE-312, CWE-200"``
      - ``"cwe-312"``
      - ``""`` (empty)

    Returns a list of normalised ``"CWE-NNN"`` strings, deduplicated.
    """
    if not raw_cwe or not raw_cwe.strip():
        return []
    seen: set[str] = set()
    result: list[str] = []
    for m in _CWE_RE.finditer(raw_cwe):
        cwe_id = f"CWE-{m.group(1)}"
        if cwe_id not in seen:
            seen.add(cwe_id)
            result.append(cwe_id)
    return result


def _is_priv_app(apk_rel_path: str) -> bool:
    """Return True if the APK lives under a privileged app directory."""
    parts = apk_rel_path.replace("\\", "/").split("/")
    return "priv-app" in parts


def _bump_severity(severity: str) -> str:
    """Increase severity by one level (for priv-app context bump).

    ``info`` → ``low``, ``low`` → ``medium``, etc.
    ``critical`` stays ``critical``.
    """
    idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 2
    return _SEVERITY_ORDER[max(0, idx - 1)]


def _dedup_key(rule_id: str, severity: str, file_path: str | None) -> str:
    """Produce a stable dedup key for a normalized finding.

    Two findings are duplicates when they share the same rule, severity,
    and file (ignoring line number, since mobsfscan may match the same
    pattern on slightly different lines across re-scans).
    """
    raw = f"{rule_id}|{severity}|{file_path or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Normalized finding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """A mobsfscan finding mapped to the project's Finding schema.

    This is the bridge between :class:`~app.services.mobsfscan.parser.MobsfScanFinding`
    (raw scanner output) and the unified ``findings`` table.  Fields match
    :class:`~app.schemas.finding.FindingCreate` exactly so that persistence
    code can unpack them directly.
    """

    rule_id: str
    title: str
    severity: str  # one of _SEVERITY_ORDER values
    description: str
    evidence: str
    file_path: str | None  # APK path (for findings DB)
    source_file: str | None  # Java/Kotlin source file path from mobsfscan
    line_number: int | None
    cwe_ids: list[str]
    source: str  # always "apk-mobsfscan"
    owasp_mobile: str  # preserved for rich output
    masvs: str  # preserved for rich output
    dedup_hash: str  # SHA-256 dedup key


# ---------------------------------------------------------------------------
# Public API — normalize
# ---------------------------------------------------------------------------

#: The ``source`` value used for mobsfscan-originated findings.
MOBSFSCAN_SOURCE = "apk-mobsfscan"


def normalize_mobsfscan_findings(
    result: MobsfScanResult,
    *,
    apk_rel_path: str = "",
    priv_app_bump: bool = True,
    min_severity: str = "info",
) -> list[NormalizedFinding]:
    """Transform a :class:`MobsfScanResult` into normalized finding objects.

    Parameters
    ----------
    result:
        The raw result returned by :func:`run_mobsfscan`.
    apk_rel_path:
        Path of the APK relative to the firmware extraction root.  Used for
        firmware-context severity adjustments (priv-app bump) and recorded
        as ``file_path`` on each finding.
    priv_app_bump:
        When *True* **and** the APK resides in a privileged-app directory
        (``priv-app/``), severity is bumped up one level.
    min_severity:
        Minimum severity to include.  Findings below this threshold are
        silently dropped.  Defaults to ``"info"`` (keep everything).

    Returns
    -------
    list[NormalizedFinding]
        Deduplicated, filtered, and severity-adjusted findings ready for
        persistence.
    """
    if not result.success or not result.findings:
        return []

    # Resolve min-severity index (lower index = higher severity)
    min_sev_idx = (
        _SEVERITY_ORDER.index(min_severity)
        if min_severity in _SEVERITY_ORDER
        else len(_SEVERITY_ORDER) - 1
    )

    is_priv = priv_app_bump and _is_priv_app(apk_rel_path)

    normalized: list[NormalizedFinding] = []
    seen_hashes: set[str] = set()

    for raw in result.findings:
        # --- severity mapping ---
        # 1. Start with the base mapping (ERROR→high, WARNING→medium, INFO→info)
        severity = raw.normalized_severity
        # 2. Apply APK-specific severity overrides (e.g. crypto→high)
        severity = _apply_severity_override(raw.rule_id, severity)
        # 3. Apply priv-app firmware context bump on top
        if is_priv:
            severity = _bump_severity(severity)

        # --- min-severity filter ---
        sev_idx = (
            _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 2
        )
        if sev_idx > min_sev_idx:
            continue

        # --- CWE extraction ---
        cwe_ids = _parse_cwe_ids(raw.cwe)

        # --- evidence construction ---
        evidence_parts: list[str] = []
        if raw.match_string:
            # Truncate long code matches to keep evidence readable
            snippet = raw.match_string[:500]
            if len(raw.match_string) > 500:
                snippet += " …(truncated)"
            evidence_parts.append(f"Code match:\n{snippet}")
        if raw.file_path:
            evidence_parts.append(f"File: {raw.file_path}")
        if raw.line_number:
            evidence_parts.append(f"Line: {raw.line_number}")
        if raw.owasp_mobile:
            evidence_parts.append(f"OWASP Mobile: {raw.owasp_mobile}")
        if raw.masvs:
            evidence_parts.append(f"MASVS: {raw.masvs}")
        if raw.section and raw.section != "code_analysis":
            evidence_parts.append(f"Section: {raw.section}")
        evidence = "\n".join(evidence_parts) if evidence_parts else raw.match_string

        # --- title construction ---
        title = f"[{raw.rule_id}] {raw.title}"
        # Cap title at 255 chars (DB column limit)
        if len(title) > 255:
            title = title[:252] + "..."

        # --- build normalized finding ---
        resolved_path = apk_rel_path or raw.file_path or None
        # Preserve the Java/Kotlin source file path from mobsfscan
        # (raw.file_path is the decompiled source path, not the APK path)
        source_file = None
        if raw.file_path and raw.file_path.endswith(('.java', '.kt')):
            # Strip temp directory prefix to get relative Java path
            # e.g. "/tmp/mobsfscan_xxx/sources/com/example/Foo.java" -> "com/example/Foo.java"
            fp = raw.file_path
            sources_idx = fp.find('/sources/')
            source_file = fp[sources_idx + len('/sources/'):] if sources_idx >= 0 else os.path.basename(fp)
        dedup_hash = _dedup_key(raw.rule_id, severity, resolved_path)

        nf = NormalizedFinding(
            rule_id=raw.rule_id,
            title=title,
            severity=severity,
            description=raw.description or raw.title,
            evidence=evidence,
            file_path=resolved_path,
            source_file=source_file,
            line_number=raw.line_number if raw.line_number else None,
            cwe_ids=cwe_ids,
            source=MOBSFSCAN_SOURCE,
            owasp_mobile=raw.owasp_mobile,
            masvs=raw.masvs,
            dedup_hash=dedup_hash,
        )

        # --- deduplication ---
        if nf.dedup_hash in seen_hashes:
            continue
        seen_hashes.add(nf.dedup_hash)

        normalized.append(nf)

    return normalized


# ---------------------------------------------------------------------------
# Public API — persist
# ---------------------------------------------------------------------------


async def persist_mobsfscan_findings(
    db: AsyncSession,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None,
    normalized: list[NormalizedFinding],
    *,
    fw_ctx: FirmwareContext | None = None,
) -> int:
    """Write normalized mobsfscan findings to the ``findings`` table.

    Uses ``flush()`` (not ``commit()``) so the caller controls the
    transaction boundary — matching the MCP handler convention.

    When *fw_ctx* is provided, finding descriptions and evidence are
    enriched with firmware metadata (device model, Android version, etc.).

    Parameters
    ----------
    db:
        Async SQLAlchemy session (typically ``context.db`` from MCP tools
        or ``async_session_factory()`` in REST handlers).
    project_id:
        UUID of the project that owns the findings.
    firmware_id:
        UUID of the firmware the APK belongs to (nullable for standalone).
    normalized:
        Output of :func:`normalize_mobsfscan_findings`.
    fw_ctx:
        Optional :class:`FirmwareContext` for enriching finding
        descriptions with device/firmware metadata.

    Returns
    -------
    int
        Number of findings persisted.
    """
    for nf in normalized:
        description = nf.description
        evidence = nf.evidence

        # Enrich with firmware context when available
        if fw_ctx:
            description = enrich_description(description, fw_ctx)
            evidence = enrich_evidence(evidence, fw_ctx)

        # Rule #35b / audit-2026-05-04 F-A-06: confidence + firmware_id
        # MUST be explicit on every Finding() construction outside
        # FindingService.create() to prevent silent NULL persistence.
        # Confidence: mobsfscan rules are regex / AST pattern matchers
        # against decompiled bytecode + manifest XML — high false-positive
        # rate compared to CVE-DB matches; "medium" reflects matcher
        # uncertainty.  Severity remains nf.severity (impact dimension).
        finding = Finding(
            project_id=project_id,
            firmware_id=firmware_id,
            confidence="medium",
            title=nf.title,
            severity=nf.severity,
            description=description,
            evidence=evidence,
            file_path=nf.file_path,
            line_number=nf.line_number,
            cwe_ids=nf.cwe_ids if nf.cwe_ids else None,
            source=nf.source,
        )
        db.add(finding)

    if normalized:
        await db.flush()

    return len(normalized)


def format_mobsfscan_text(
    result: MobsfScanResult,
    normalized: list[NormalizedFinding],
    apk_rel_path: str = "",
    *,
    jadx_elapsed_ms: int = 0,
    total_elapsed_ms: int = 0,
) -> str:
    """Format mobsfscan results as human-readable text for MCP tool output.

    Parameters
    ----------
    result:
        The raw :class:`MobsfScanResult` (used for summary stats).
    normalized:
        Filtered/normalized findings from :func:`normalize_mobsfscan_findings`.
    apk_rel_path:
        Display path for the APK.
    jadx_elapsed_ms:
        Time spent in JADX decompilation (for pipeline timing display).
    total_elapsed_ms:
        Total pipeline wall-clock time (for pipeline timing display).

    Returns
    -------
    str
        Formatted text suitable for MCP tool response (will be truncated
        downstream by ``truncation.py`` if over 30 KB).
    """
    lines: list[str] = []

    # Header
    lines.append("=== mobsfscan Source Code Analysis ===")
    if apk_rel_path:
        lines.append(f"APK: {apk_rel_path}")

    # Pipeline timing
    if total_elapsed_ms:
        lines.append(
            f"Pipeline: {total_elapsed_ms}ms total "
            f"(JADX: {jadx_elapsed_ms}ms, "
            f"mobsfscan: {result.scan_duration_ms}ms)"
        )
    else:
        lines.append(f"Scan duration: {result.scan_duration_ms}ms")

    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Total raw findings: {len(result.findings)}")
    suppressed_total = result.suppressed_rule_count + result.suppressed_path_count
    if suppressed_total:
        lines.append(
            f"Suppressed: {suppressed_total} "
            f"({result.suppressed_rule_count} noisy rules, "
            f"{result.suppressed_path_count} library paths)"
        )
    lines.append(f"Normalized findings: {len(normalized)}")

    # Severity summary
    sev_counts: dict[str, int] = {}
    for nf in normalized:
        sev_counts[nf.severity] = sev_counts.get(nf.severity, 0) + 1
    if sev_counts:
        parts = [f"{sev}: {cnt}" for sev, cnt in sorted(sev_counts.items())]
        lines.append(f"By severity: {', '.join(parts)}")

    lines.append("")

    # Individual findings
    for i, nf in enumerate(normalized, 1):
        lines.append(f"--- Finding {i} [{nf.severity.upper()}] ---")
        lines.append(f"Rule: {nf.rule_id}")
        lines.append(f"Title: {nf.title}")
        lines.append(f"Description: {nf.description}")
        if nf.cwe_ids:
            lines.append(f"CWE: {', '.join(nf.cwe_ids)}")
        if nf.owasp_mobile:
            lines.append(f"OWASP Mobile: {nf.owasp_mobile}")
        if nf.masvs:
            lines.append(f"MASVS: {nf.masvs}")
        if nf.file_path:
            lines.append(f"File: {nf.file_path}")
        if nf.line_number:
            lines.append(f"Line: {nf.line_number}")
        if nf.evidence:
            lines.append(f"Evidence:\n{nf.evidence}")
        lines.append("")

    if not normalized:
        lines.append("No findings above the minimum severity threshold.")

    return "\n".join(lines)
