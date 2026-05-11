"""Async threat-intelligence scanners backed by hash lookups.

Extracted from security_audit_service.py as step 6/8 of the Phase 5 split.
Each scanner returns a list of SecurityFinding objects; all four are
optional and no-op when their upstream service is unavailable or
unconfigured.

- ``run_clamav_scan``: antivirus signature scan via ClamAV.
- ``run_virustotal_scan``: SHA-256 lookup against VirusTotal (requires
  ``VIRUSTOTAL_API_KEY``).
- ``run_abusech_scan``: MalwareBazaar / ThreatFox / YARAify enrichment.
- ``run_known_good_scan``: CIRCL hashlookup (NSRL) known-good
  identification; produces a single informational summary finding.
"""

import asyncio
import logging
import os

from app.config import get_settings
from app.services import abusech_service, clamav_service, hashlookup_service, virustotal_service
from app.services.security_audit._base import SecurityFinding

logger = logging.getLogger(__name__)


async def run_clamav_scan(extracted_root: str) -> list[SecurityFinding]:
    """Scan extracted firmware with ClamAV (async, optional).

    Returns findings for infected files. Returns empty list if
    ClamAV is unavailable.
    """
    available = await clamav_service.check_available()
    if not available:
        logger.info("ClamAV not available — skipping antivirus scan")
        return []

    results = await clamav_service.scan_directory(extracted_root, max_files=500)
    findings: list[SecurityFinding] = []

    for sr in results:
        if sr.infected:
            rel = "/" + os.path.relpath(sr.file_path, extracted_root)  # noqa: ASYNC240 — pure-string path math via os.path.relpath inside scan-result loop; no filesystem I/O
            findings.append(SecurityFinding(
                title=f"Malware detected: {sr.signature}",
                severity="critical",
                description=(
                    f"ClamAV detected malware signature '{sr.signature}' "
                    f"in file {rel}. This file should be quarantined and "
                    f"analyzed further."
                ),
                evidence=f"ClamAV signature: {sr.signature}",
                file_path=rel,
                cwe_ids=["CWE-506"],
            ))

    logger.info("ClamAV scan: %d findings from %d files", len(findings), len(results))
    return findings


async def run_virustotal_scan(extracted_root: str) -> list[SecurityFinding]:
    """Hash-check firmware binaries against VirusTotal (async, optional).

    Returns findings for detected files. Returns empty list if
    VT API key is not configured.
    """
    settings = get_settings()
    if not settings.virustotal_api_key:
        logger.info("VT API key not configured — skipping VirusTotal scan")
        return []

    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 50,
    )
    if not hashes:
        return []

    vt_results = await virustotal_service.batch_check_hashes(hashes)
    findings: list[SecurityFinding] = []

    for vr in vt_results:
        if vr.found and vr.detection_count > 0:
            if vr.detection_count > 10:
                severity = "critical"
            elif vr.detection_count > 5:
                severity = "high"
            elif vr.detection_count > 1:
                severity = "medium"
            else:
                severity = "low"

            top_detections = ", ".join(vr.detections[:5])
            findings.append(SecurityFinding(
                title=f"VirusTotal detection: {vr.file_path} ({vr.detection_count}/{vr.total_engines})",
                severity=severity,
                description=(
                    f"VirusTotal reports {vr.detection_count}/{vr.total_engines} "
                    f"engines flagging this binary. Top detections: {top_detections}"
                ),
                evidence=f"SHA-256: {vr.sha256}\nPermalink: {vr.permalink}",
                file_path=vr.file_path,
                cwe_ids=["CWE-506"],
            ))

    logger.info("VirusTotal scan: %d findings from %d hashes", len(findings), len(hashes))
    return findings


async def run_abusech_scan(extracted_root: str) -> list[SecurityFinding]:
    """Check firmware hashes against abuse.ch services (async, optional).

    Returns findings for known malware (MalwareBazaar), IOC matches
    (ThreatFox), and community YARA matches (YARAify).
    """
    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 30,
    )
    if not hashes:
        return []

    summary = await abusech_service.enrich_iocs(hashes=hashes, max_hashes=30)
    findings: list[SecurityFinding] = []

    for mb in summary.get("malwarebazaar", []):
        findings.append(SecurityFinding(
            title=f"MalwareBazaar: known malware — {mb.signature or 'unknown'}",
            severity="critical",
            description=(
                f"MalwareBazaar identifies this binary as a known malware sample. "
                f"Signature: {mb.signature or 'N/A'}. "
                f"Tags: {', '.join(mb.tags[:5]) if mb.tags else 'none'}. "
                f"First seen: {mb.first_seen or 'unknown'}."
            ),
            evidence=f"SHA-256: {mb.sha256}",
            file_path=mb.file_path,
            cwe_ids=["CWE-506"],
        ))

    for tf in summary.get("threatfox", []):
        findings.append(SecurityFinding(
            title=f"ThreatFox IOC: {tf.malware} ({tf.threat_type})",
            severity="high" if tf.confidence_level >= 75 else "medium",
            description=(
                f"ThreatFox links this IOC to {tf.malware} ({tf.threat_type}). "
                f"Confidence: {tf.confidence_level}%."
            ),
            evidence=f"IOC: {tf.ioc}\nType: {tf.ioc_type}",
            cwe_ids=["CWE-506"],
        ))

    for yf in summary.get("yaraify", []):
        rules = ", ".join(yf.rule_matches[:5])
        findings.append(SecurityFinding(
            title=f"YARAify: community YARA match — {rules}",
            severity="medium",
            description=(
                f"YARAify reports {len(yf.rule_matches)} community YARA rule "
                f"matches for this binary: {rules}."
            ),
            evidence=f"SHA-256: {yf.sha256}",
            file_path=yf.file_path,
            cwe_ids=["CWE-506"],
        ))

    logger.info("abuse.ch scan: %d findings from %d hashes", len(findings), len(hashes))
    return findings


async def run_known_good_scan(extracted_root: str) -> list[SecurityFinding]:
    """Identify known-good files via CIRCL hashlookup (informational).

    Returns informational findings for files identified as known-good.
    These are useful for reducing false positives in other scans.
    """
    loop = asyncio.get_running_loop()
    hashes = await loop.run_in_executor(
        None, virustotal_service.collect_binary_hashes,
        extracted_root, 100,
    )
    if not hashes:
        return []

    results = await hashlookup_service.batch_check_known_good(hashes)
    findings: list[SecurityFinding] = []

    known = [r for r in results if r.known]
    if known:
        # Single summary finding rather than one per file
        file_list = ", ".join(r.file_path for r in known[:20])
        findings.append(SecurityFinding(
            title=f"CIRCL Hashlookup: {len(known)}/{len(results)} binaries are known-good",
            severity="info",
            description=(
                f"{len(known)} of {len(results)} checked binaries are recognized in "
                f"the NSRL known-good database. These can be deprioritized during "
                f"manual analysis. Files: {file_list}"
            ),
            evidence=f"Checked {len(results)} binaries against CIRCL hashlookup.circl.lu",
        ))

    logger.info("CIRCL hashlookup: %d known-good from %d checked", len(known), len(results))
    return findings
