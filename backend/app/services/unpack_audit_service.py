"""Promote unpack-time discoveries to Finding rows.

Reads ``firmware.device_metadata`` structured artifacts written by the
unpack pipeline (``vendor_decryption``, ``extraction_diagnostics``) and
emits Findings with ``source='unpack_audit'``. Idempotent —
DELETE+REPOPULATE per ``(firmware_id, source)`` on every run, so
re-running unpack produces a clean finding state.

Architectural template:
``app.workers.unpack._run_hardware_firmware_detection_safe``. Owns its
own ``AsyncSession`` (Rule #7 — never share a session across coroutine
boundaries). Outer try/except in ``_run_safe`` for fire-and-forget
exception isolation (Rule #33 shape).

Source-tag exclusivity: this service is the sole writer of
``source='unpack_audit'``. Other code paths writing this tag will be
clobbered by the DELETE pass on the next unpack. See intake
``unpack-audit-findings-2026-05-04.md`` for cross-step rationale.

Three findings emitted per recovered AES key triple
``(algo, key_hex, iv_hex)``, deduped — vendor_decryption typically
contains one entry per decrypted archive but all entries cite the same
triple, so we emit ONE F1 + ONE F2 + ONE F3 per triple, not N×3.

  F1 — Hardcoded AES key in update script (CWE-798, CWE-321)
  F2 — Static IV reuse across N AES-CBC ciphertexts (CWE-323, CWE-329)
  F3 — Cleartext key shipped within firmware image (CWE-312, CWE-256)

Plus zero or more info-severity findings for vendor-encrypted archives
that did NOT decrypt (computed as ``len(encrypted) - len(decrypted)``,
NOT non-emptiness of encrypted_archives — extraction_diagnostics is
upload-time and is never updated post-decrypt; falsely treating it as
authoritative would emit "key not recovered" findings on every
successful EDAN-class firmware).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import delete

from app.database import async_session_factory
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.schemas.finding import Confidence, FindingCreate, Severity
from app.services.finding_service import FindingService

logger = logging.getLogger(__name__)

UNPACK_AUDIT_SOURCE = "unpack_audit"


async def _run_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget wrapper. Mirrors ``_run_hardware_firmware_detection_safe``.

    Swallows all exceptions with ``logger.warning(..., exc_info=True)`` so a
    finding-promotion failure never breaks the unpack pipeline.
    """
    try:
        count = await run(firmware_id)
        logger.info(
            "Unpack audit: emitted %d findings for firmware %s",
            count, firmware_id,
        )
    except Exception:
        logger.warning(
            "Unpack audit failed for firmware %s", firmware_id, exc_info=True,
        )


async def run(firmware_id: uuid.UUID) -> int:
    """Read firmware metadata, emit findings. Returns count created.

    Idempotent: DELETEs prior ``unpack_audit`` findings for this firmware
    before INSERTing the new set. Building the new finding list BEFORE
    the DELETE means an extractor exception leaves prior findings intact.
    """
    async with async_session_factory() as db:
        fw = await db.get(Firmware, firmware_id)
        if fw is None:
            return 0

        meta = fw.device_metadata or {}
        new_findings: list[FindingCreate] = []
        new_findings.extend(_extract_aes_key_findings(meta, firmware_id))
        new_findings.extend(_extract_partial_extraction_findings(meta, firmware_id))
        new_findings.extend(_extract_signed_archive_finding(meta, firmware_id))

        await db.execute(delete(Finding).where(
            Finding.firmware_id == firmware_id,
            Finding.source == UNPACK_AUDIT_SOURCE,
        ))

        svc = FindingService(db)
        for finding_data in new_findings:
            await svc.create(fw.project_id, finding_data)

        await db.commit()
        return len(new_findings)


def _normalize_vendor_decryption(audit: Any) -> list[dict]:
    """Accept both schemas in firmware.device_metadata['vendor_decryption']:

    - Canonical (post-unblob worker output): ``list[dict]`` where each
      dict has keys ``algorithm, key_hex, iv_hex, key_source, archive``.
    - Legacy (hand-authored / pre-list-shape rows): a single ``dict``
      with ``algorithm, key_hex, iv_hex, key_source`` plus a ``blobs:
      list[str]`` listing the affected archive paths.

    Returns the canonical list-of-dicts shape. Unparseable inputs
    return an empty list rather than raising — defensive at the
    boundary because real production rows pre-date the canonical
    schema.
    """
    if isinstance(audit, list):
        return [e for e in audit if isinstance(e, dict)]
    if isinstance(audit, dict):
        # Legacy shape — expand 'blobs' to per-archive entries.
        blobs = audit.get("blobs")
        common = {
            k: audit.get(k) for k in ("algorithm", "key_hex", "iv_hex", "key_source")
        }
        if isinstance(blobs, list) and blobs:
            return [{**common, "archive": str(b)} for b in blobs if b]
        # No 'blobs' — treat as a single entry with archive=None.
        return [{**common, "archive": audit.get("archive")}]
    return []


def _extract_aes_key_findings(
    meta: dict[str, Any], firmware_id: uuid.UUID,
) -> list[FindingCreate]:
    """F1+F2+F3 per recovered AES key triple, deduped."""
    audit = _normalize_vendor_decryption(meta.get("vendor_decryption"))
    if not audit:
        return []

    by_triple: dict[tuple[str, str, str], list[dict]] = {}
    for entry in audit:
        algo = entry.get("algorithm", "")
        key_hex = entry.get("key_hex", "")
        iv_hex = entry.get("iv_hex", "")
        if not (algo and key_hex and iv_hex):
            continue
        by_triple.setdefault((algo, key_hex, iv_hex), []).append(entry)

    findings: list[FindingCreate] = []
    for (algo, key_hex, iv_hex), entries in by_triple.items():
        archives = sorted({e.get("archive", "") for e in entries if e.get("archive")})

        # Defensive: take the first parseable file:line citation.
        key_source = ""
        source_file: str | None = None
        source_line: int | None = None
        for e in entries:
            ks = e.get("key_source") or ""
            if ":" in ks:
                fp, _, ln = ks.rpartition(":")
                try:
                    source_line = int(ln)
                    source_file = fp
                    key_source = ks
                    break
                except ValueError:
                    continue
        if not key_source:
            key_source = entries[0].get("key_source", "<unknown>")

        archive_list = "\n".join(f"  - {a}" for a in archives)
        evidence_common = (
            f"algorithm: {algo}\n"
            f"key (hex): {key_hex}\n"
            f"iv (hex):  {iv_hex}\n"
            f"key_source: {key_source}\n"
            f"\n"
            f"Successfully decrypted {len(archives)} archive(s) — verified by "
            f"strict magic-byte gate on plaintext head:\n{archive_list}"
        )

        # F1 — Hardcoded AES key (CWE-798, CWE-321)
        findings.append(FindingCreate(
            firmware_id=firmware_id,
            source=UNPACK_AUDIT_SOURCE,
            severity=Severity.high,
            confidence=Confidence.high,
            title=f"Hardcoded {algo.upper()} key in firmware update script",
            file_path=source_file,
            line_number=source_line,
            cwe_ids=["CWE-798", "CWE-321"],
            evidence=evidence_common,
            description=(
                "An update orchestration script in the firmware ships an "
                f"{algo.upper()} key + IV in plaintext. Anyone with a copy of "
                "any update package for this device family can recover the key, "
                "decrypt all sibling firmware updates, extract proprietary IP, "
                "and produce tampered updates that pass the staging-side "
                "decryption gate. Confidence is high by construction: the key "
                "was used to decrypt sibling archives whose plaintext head "
                "matched the declared archive magic — wrong-key decryption "
                "cannot pass that gate."
            ),
        ))

        # F2 — Static IV reuse (only when 2+ archives share the IV)
        if len(archives) >= 2:
            findings.append(FindingCreate(
                firmware_id=firmware_id,
                source=UNPACK_AUDIT_SOURCE,
                severity=Severity.medium,
                confidence=Confidence.high,
                title=f"Static IV reused across {len(archives)} AES-CBC ciphertexts",
                file_path=source_file,
                line_number=source_line,
                cwe_ids=["CWE-323", "CWE-329"],
                evidence=(
                    f"Same IV {iv_hex} reused under key {key_hex} across:\n"
                    f"{archive_list}\n\n"
                    f"First-block plaintext leakage on identical-prefix archives; "
                    f"cross-update plaintext distinguishability when the same "
                    f"key+IV is reused on partially-modified updates."
                ),
                description=(
                    "AES-CBC requires a fresh, unpredictable IV per encryption. "
                    "Reusing one IV across multiple ciphertexts under the same "
                    "key leaks information about identical plaintext prefixes "
                    "and weakens the security guarantees of the mode."
                ),
            ))

        # F3 — Cleartext key in shipped firmware (CWE-312, CWE-256)
        findings.append(FindingCreate(
            firmware_id=firmware_id,
            source=UNPACK_AUDIT_SOURCE,
            severity=Severity.medium,
            confidence=Confidence.high,
            title="Decryption key shipped in plaintext within firmware image",
            file_path=source_file,
            line_number=source_line,
            cwe_ids=["CWE-312", "CWE-256"],
            evidence=(
                f"Update key {key_hex} (with IV {iv_hex}) is embedded in "
                f"plaintext in {key_source}.\n"
                f"This file ships on every device — physical NAND extraction "
                f"yields the key without reverse engineering."
            ),
            description=(
                "Cryptographic key material stored in cleartext on shipped "
                "firmware images is recoverable by any device-level adversary "
                "and trivially extracted via dump-then-grep. Keys must be "
                "stored in a hardware secure element, derived from a per-device "
                "secret, or omitted from the rootfs and provisioned via a "
                "separate secure channel."
            ),
        ))

    return findings


def _extract_partial_extraction_findings(
    meta: dict[str, Any], firmware_id: uuid.UUID,
) -> list[FindingCreate]:
    """One info finding per vendor-encrypted archive NOT decrypted.

    The gap is computed as ``encrypted_archives \\ vendor_decryption``
    (set difference on basename), NOT ``encrypted_archives`` non-empty.
    extraction_diagnostics is written at upload time and never updated
    after the post-unpack decrypt pass succeeds — relying on
    non-emptiness would falsely emit "key not recovered" on every
    successful EDAN-class firmware (Rule #31 width canary applies).
    """
    diag = meta.get("extraction_diagnostics") or {}
    encrypted = diag.get("encrypted_archives") or []
    decrypted = _normalize_vendor_decryption(meta.get("vendor_decryption"))
    if not encrypted:
        return []

    decrypted_basenames = {
        (e.get("archive") or "").rsplit("/", 1)[-1]
        for e in decrypted
        if e.get("archive")
    }

    findings: list[FindingCreate] = []
    for ea in encrypted:
        ea_path = ea.get("path", "")
        if not ea_path:
            continue
        ea_basename = ea_path.rsplit("/", 1)[-1]
        if ea_basename in decrypted_basenames:
            continue

        vendor = ea.get("vendor", "unknown")
        fmt = ea.get("format", "unknown")
        note = ea.get("note") or f"Vendor-encrypted archive ({vendor}/{fmt})"
        findings.append(FindingCreate(
            firmware_id=firmware_id,
            source=UNPACK_AUDIT_SOURCE,
            severity=Severity.info,
            confidence=Confidence.high,
            title=f"Vendor-encrypted archive not decrypted ({vendor}/{fmt})",
            file_path=ea_path,
            cwe_ids=None,
            evidence=(
                f"Archive: {ea_path}\n"
                f"Size: {ea.get('size_bytes', 0)} bytes\n"
                f"Magic (hex): {ea.get('magic_hex', '<unknown>')}\n"
                f"Format: {fmt}\n"
                f"Vendor: {vendor}\n"
                f"\n"
                f"{note}"
            ),
            description=(
                "Wairz identified this archive as a vendor-encrypted container "
                "but did not recover a decryption key during unpack. The "
                "archive's contents are not visible to downstream scanners "
                "(SBOM, vuln, security audit, MCP filesystem tools). Manual "
                "key recovery — typically Ghidra against the firmware's update "
                "binaries — is required to surface the payload."
            ),
        ))
    return findings


def _extract_signed_archive_finding(
    meta: dict[str, Any], firmware_id: uuid.UUID,
) -> list[FindingCreate]:
    """One info finding when any vendor-signed archive format is detected.

    Surfaces the bootloader-side signature-verification surface to the
    operator without making a security claim — verification itself runs
    on-device and is out of Wairz's measurement scope.
    """
    diag = meta.get("extraction_diagnostics") or {}
    encrypted = diag.get("encrypted_archives") or []
    formats = {ea.get("format") for ea in encrypted if ea.get("format")}
    formats.discard(None)
    if not formats:
        return []
    formats_str = ", ".join(sorted(f for f in formats if f))
    return [FindingCreate(
        firmware_id=firmware_id,
        source=UNPACK_AUDIT_SOURCE,
        severity=Severity.info,
        confidence=Confidence.high,
        title=f"Vendor-signed firmware container detected ({formats_str})",
        cwe_ids=None,
        evidence=(
            f"Detected vendor-signed container format(s): {formats_str}\n"
            f"Bootloader-resident public key verifies update signatures "
            f"on-device. Signature validation is out of Wairz's measurement "
            f"scope — surfaced for operator awareness."
        ),
        description=(
            "Vendor-signed firmware containers carry a public-key signature "
            "that the bootloader verifies before applying an update. This "
            "finding is informational: any signature-validation bypass would "
            "live in the bootloader code path, which Wairz does not directly "
            "instrument. Recommend separate manual review of the bootloader "
            "binary (typically u-boot or vendor-derived) for verification "
            "logic correctness."
        ),
    )]
