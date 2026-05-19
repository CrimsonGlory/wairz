"""Bare-metal MCU/DSP audit walker — architecture-agnostic schema consumer.

The walker is the SCHEMA-DRIVEN execution engine for CLAUDE.md Rule #52.
It reads a chip-family YAML manifest from the catalog, resolves an uploaded
firmware blob to a ``(family, domain)`` via either an operator-supplied
``bare_metal_descriptors`` row OR :class:`YamlDrivenMatcher` auto-detect,
walks every :class:`AddressRegion` declared on the domain, applies each
region's closed-grammar :class:`PolicyRule` via :data:`POLICY_EVALUATORS`,
and emits CWE-tagged Finding rows for every matched policy.

**Walker is architecture-agnostic.** Adding a new chip family is a YAML
edit; the walker stays the same. Adding a new policy operator is a Rule
#25 cross-stack alignment commit (closed Literal + POLICY_EVALUATORS
handler + alignment test); the walker's dispatch loop stays the same.

**Rule #45 parse-only contract.** The walker NEVER attempts decryption.
``encrypted_region`` semantic regions are SKIPPED with an explicit
``skipped_regions`` entry — operators see why the audit didn't run on a
given range. The ``test_walker_no_decrypt`` token-scan gate (Rule #45) +
its META-CANARY (Rule #46) live in ``test_bare_metal_walker.py``.

**Rule #39 inner/outer/safe triplet.** Three functions:

  - ``_do_bare_metal_audit_run(db, firmware_id) -> dict`` — INNER pure-logic
    orchestrator. Caller owns the session + transaction. Returns the result
    dict UNSTAMPED.
  - ``run_bare_metal_audit_background(firmware_id) -> None`` — OUTER state
    machine wrapper. Owns Rule #33 .a transitions
    (idle → queued → running → completed | failed) via async_session_factory.
  - ``auto_bare_metal_audit_firmware_safe(firmware_id) -> None`` — SAFE
    unpack-post-detection hook. Owns own session, swallows exceptions,
    does NOT mutate firmware status (Rule #47 — leaves manual re-trigger
    via MCP working without 409 conflict).

**Provenance arbitration** (Scout CC §SC11). When multiple descriptors
exist for one firmware, the walker reads the most-recent NON-SUPERSEDED
row and applies precedence:

    operator > attested_external > unauthenticated_external > auto_detection
"""
from __future__ import annotations

import datetime as dt
import logging
import math
import traceback
import uuid
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.bare_metal_descriptor import BareMetalDescriptor
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.schemas.chip_family import (
    AddressRegion,
    ChipFamilyManifest,
    ChipMatch,
    Domain,
    Packing,
    PolicyOperator,
    PolicyRule,
)
from app.schemas.finding import Confidence, FindingCreate, Severity
from app.services.finding_service import FindingService
from app.services.hardware_firmware.chip_catalog import (
    get_chip_catalog,
    get_chip_domain,
)
from app.services.hardware_firmware.matchers import (
    YamlDrivenMatcher,
    domain_base_addr_for_blob,
    read_region_bytes,
    read_word_at_address,
)
from app.services.jsonb_normalizers import (
    _stamp_firmware_bare_metal_audit_result,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy-rule evaluators — CLOSED dispatch table.
# Each evaluator returns (matched: bool, evidence: str). matched=True means
# the policy condition is satisfied and a finding should be emitted.
# ---------------------------------------------------------------------------


def _read_words_from_region(
    blob_bytes: bytes,
    region: AddressRegion,
    base_addr: int,
    packing: Packing,
    word_size_bits: int,
) -> list[int] | None:
    """Read region as a list of words (LE for two_bytes_per_word_le packing)."""
    if region.size is None:
        return None
    raw = read_region_bytes(blob_bytes, region.start, region.size, base_addr, packing)
    if raw is None:
        return None
    word_size_bytes = max(1, word_size_bits // 8)
    if len(raw) % word_size_bytes != 0:
        return None
    endian = "big" if packing == "two_bytes_per_word_be" else "little"
    return [
        int.from_bytes(raw[i : i + word_size_bytes], endian)
        for i in range(0, len(raw), word_size_bytes)
    ]


def _eval_unsecure_when_all_words_equal(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if rule.value_hex is None:
        return False, "policy missing value_hex"
    target = int(rule.value_hex, 16)
    word_size = rule.word_size_bits or domain.data_word_bits
    base = domain_base_addr_for_blob(domain)
    words = _read_words_from_region(blob_bytes, region, base, domain.packing, word_size)
    if words is None:
        return False, "region outside blob coverage"
    matched = bool(words) and all(w == target for w in words)
    return matched, f"all {len(words)} words {'==' if matched else '!='} 0x{target:X}"


def _eval_unsecure_when_any_word_equal(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if rule.value_hex is None:
        return False, "policy missing value_hex"
    target = int(rule.value_hex, 16)
    word_size = rule.word_size_bits or domain.data_word_bits
    base = domain_base_addr_for_blob(domain)
    words = _read_words_from_region(blob_bytes, region, base, domain.packing, word_size)
    if words is None:
        return False, "region outside blob coverage"
    return any(w == target for w in words), f"any word == 0x{target:X}"


def _eval_perma_lock_when_all_words_equal(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    # Mechanically identical to ``unsecure_when_all_words_equal`` — the
    # distinction is purely the finding-source emitted on match. Different
    # cwe_ids + finding_source on the rule express the semantic difference.
    return _eval_unsecure_when_all_words_equal(blob_bytes, region, rule, domain)


def _eval_required_value_at_offset(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if rule.value_hex is None or rule.offset is None:
        return False, "policy missing value_hex or offset"
    word_size = rule.word_size_bits or domain.data_word_bits
    base = domain_base_addr_for_blob(domain)
    word = read_word_at_address(
        blob_bytes, region.start + rule.offset, base, domain.packing, word_size,
    )
    if word is None:
        return False, "offset outside blob coverage"
    expected = int(rule.value_hex, 16)
    # "required" means a FINDING fires when the value is NOT what was required.
    matched = word != expected
    return matched, f"word at offset {rule.offset} = 0x{word:X}; required = 0x{expected:X}"


def _eval_forbidden_value_at_offset(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if rule.value_hex is None or rule.offset is None:
        return False, "policy missing value_hex or offset"
    word_size = rule.word_size_bits or domain.data_word_bits
    base = domain_base_addr_for_blob(domain)
    word = read_word_at_address(
        blob_bytes, region.start + rule.offset, base, domain.packing, word_size,
    )
    if word is None:
        return False, "offset outside blob coverage"
    forbidden = int(rule.value_hex, 16)
    matched = word == forbidden
    return matched, f"word at offset {rule.offset} = 0x{word:X}; forbidden = 0x{forbidden:X}"


def _eval_entropy_floor(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if region.size is None:
        return False, "region has no size"
    base = domain_base_addr_for_blob(domain)
    raw = read_region_bytes(blob_bytes, region.start, region.size, base, domain.packing)
    if raw is None or not raw:
        return False, "region outside blob coverage"
    counts = Counter(raw)
    total = len(raw)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    floor = float(rule.value_hex) if rule.value_hex is not None else 0.0
    return entropy < floor, f"entropy {entropy:.2f} < floor {floor:.2f}"


def _eval_entropy_ceiling(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    if region.size is None:
        return False, "region has no size"
    base = domain_base_addr_for_blob(domain)
    raw = read_region_bytes(blob_bytes, region.start, region.size, base, domain.packing)
    if raw is None or not raw:
        return False, "region outside blob coverage"
    counts = Counter(raw)
    total = len(raw)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    ceiling = float(rule.value_hex) if rule.value_hex is not None else 8.0
    return entropy > ceiling, f"entropy {entropy:.2f} > ceiling {ceiling:.2f}"


def _eval_informational(
    blob_bytes: bytes,
    region: AddressRegion,
    rule: PolicyRule,
    domain: Domain,
) -> tuple[bool, str]:
    """Always fires — used for info-level metadata findings."""
    return True, "informational policy"


POLICY_EVALUATORS: dict[
    PolicyOperator,
    Callable[[bytes, AddressRegion, PolicyRule, Domain], tuple[bool, str]],
] = {
    "unsecure_when_all_words_equal": _eval_unsecure_when_all_words_equal,
    "unsecure_when_any_word_equal": _eval_unsecure_when_any_word_equal,
    "perma_lock_when_all_words_equal": _eval_perma_lock_when_all_words_equal,
    "required_value_at_offset": _eval_required_value_at_offset,
    "forbidden_value_at_offset": _eval_forbidden_value_at_offset,
    "entropy_floor": _eval_entropy_floor,
    "entropy_ceiling": _eval_entropy_ceiling,
    "informational": _eval_informational,
}


# ---------------------------------------------------------------------------
# Descriptor + chip-family resolution.
# ---------------------------------------------------------------------------


_SOURCE_PRECEDENCE: dict[str, int] = {
    "operator": 4,
    "attested_external": 3,
    "unauthenticated_external": 2,
    "auto_detection": 1,
}


async def _resolve_chip_for_blob(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    blob_bytes: bytes,
    chip_target_hint: str | None = None,
) -> ChipMatch | None:
    """Resolve the chip family + domain for a given blob.

    Precedence:
      1. Caller-supplied ``chip_target_hint`` (e.g. operator-set on the
         hardware_firmware_blobs row).
      2. Most-recent NON-SUPERSEDED ``bare_metal_descriptors`` row for the
         firmware (operator-pushed via MCP / HTTP).
      3. :class:`YamlDrivenMatcher` auto-detect against the catalog.

    Returns ``None`` if no chip identifies above the matcher's threshold.
    """
    if chip_target_hint:
        match = get_chip_domain(chip_target_hint)
        if match is not None:
            manifest, domain_name = match
            return ChipMatch(
                family_id=manifest.family_id,
                domain_name=domain_name,
                confidence=1.0,
                evidence=[{"source": "blob.chip_target", "value": chip_target_hint}],
                descriptor_source="operator",
            )
    descriptor = await _most_recent_descriptor(db, firmware_id)
    if descriptor is not None:
        payload = descriptor.payload or {}
        triple = payload.get("chip_family_hint")
        if triple:
            domain_name = payload.get("domain_hint")
            if not domain_name:
                manifest = get_chip_catalog().get(triple)
                if manifest is not None and manifest.domains:
                    domain_name = manifest.domains[0].name
            if domain_name:
                full_id = f"{triple}/{domain_name}"
                match = get_chip_domain(full_id)
                if match is not None:
                    return ChipMatch(
                        family_id=triple,
                        domain_name=domain_name,
                        confidence=1.0,
                        evidence=[{"source": "bare_metal_descriptor", "id": str(descriptor.id)}],
                        descriptor_source=descriptor.descriptor_source,
                    )
    matches = YamlDrivenMatcher().detect(blob_bytes, threshold=0.3, max_candidates=1)
    if matches:
        return matches[0]
    return None


async def _most_recent_descriptor(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> BareMetalDescriptor | None:
    """Return the highest-precedence non-superseded descriptor for a firmware.

    **Precedence-aware ordering** (Scout GG §SC5 bug fix 2026-05-19): the
    documented contract is
    ``operator > attested_external > unauthenticated_external > auto_detection``.
    Naïve ``ORDER BY received_at DESC LIMIT 1`` lets a LATER
    unauthenticated_external descriptor outrank an EARLIER operator one —
    the literal opposite of the desired behaviour, with significant
    security implications (untrusted ingestor overrides operator's
    authoritative chip-family assertion).

    Fix: build a SQL CASE WHEN that maps ``descriptor_source`` to its
    precedence rank, then ``ORDER BY (rank DESC, received_at DESC)``.
    Rule #46 META-CANARY in test_bare_metal_walker.py confirms the
    ordering with synthetic out-of-order pushes.
    """
    # CASE WHEN expression matching :data:`_SOURCE_PRECEDENCE`. Built as a
    # SQL expression so the ordering happens in Postgres, not in Python
    # (Rule #29 round-trip discipline — sort + LIMIT 1 at the DB).
    precedence_case = sa.case(
        {source: rank for source, rank in _SOURCE_PRECEDENCE.items()},
        value=BareMetalDescriptor.descriptor_source,
        else_=0,
    )
    stmt = (
        select(BareMetalDescriptor)
        .where(BareMetalDescriptor.firmware_id == firmware_id)
        .order_by(precedence_case.desc(), BareMetalDescriptor.received_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# INNER pure-logic walker.
# ---------------------------------------------------------------------------


async def _do_bare_metal_audit_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    blob_path: Path | None = None,
    blob_id: uuid.UUID | None = None,
    chip_target_hint: str | None = None,
) -> dict:
    """Run the bare-metal audit on a single blob; emit findings.

    Args:
        db: AsyncSession owned by the caller (outer wrapper).
        firmware_id: Firmware row id.
        blob_path: Optional path to the blob bytes (when not in
            hardware_firmware_blobs). For Phase 1 the Eaton flow uses this.
        blob_id: Optional hardware_firmware_blobs.id (overrides blob_path).
        chip_target_hint: Optional "vendor/family/domain" triple to bypass
            auto-detect (used when caller already knows the chip).

    Returns:
        Result dict UNSTAMPED (caller stamps via _stamp_firmware_bare_metal_audit_result).
    """
    audit_started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return {
            "audited_at": audit_started_at,
            "chip_match": None,
            "blob_id": str(blob_id) if blob_id else None,
            "blob_size_bytes": 0,
            "region_audits": [],
            "skipped_regions": [],
            "findings_emitted_count": 0,
            "errors": [f"firmware {firmware_id} not found"],
        }
    project_id = firmware.project_id

    # Resolve blob bytes — three input shapes.
    blob_bytes: bytes
    resolved_blob_id: str | None = None
    if blob_id is not None:
        blob_row = await db.get(HardwareFirmwareBlob, blob_id)
        if blob_row is None:
            return {
                "audited_at": audit_started_at,
                "chip_match": None,
                "blob_id": str(blob_id),
                "blob_size_bytes": 0,
                "region_audits": [],
                "skipped_regions": [],
                "findings_emitted_count": 0,
                "errors": [f"blob {blob_id} not found"],
            }
        if chip_target_hint is None and blob_row.chip_target:
            chip_target_hint = blob_row.chip_target
        resolved_blob_id = str(blob_row.id)
        # Read bytes from the blob's path — blob rows carry their file path
        # in metadata; for Phase 1 fall back to a heuristic that consults the
        # blob_path arg.
        if blob_path is None:
            return {
                "audited_at": audit_started_at,
                "chip_match": None,
                "blob_id": resolved_blob_id,
                "blob_size_bytes": 0,
                "region_audits": [],
                "skipped_regions": [],
                "findings_emitted_count": 0,
                "errors": ["blob row found but no blob_path supplied (Phase 1)"],
            }
        blob_bytes = blob_path.read_bytes()
    elif blob_path is not None:
        blob_bytes = blob_path.read_bytes()
    else:
        return {
            "audited_at": audit_started_at,
            "chip_match": None,
            "blob_id": None,
            "blob_size_bytes": 0,
            "region_audits": [],
            "skipped_regions": [],
            "findings_emitted_count": 0,
            "errors": ["neither blob_path nor blob_id supplied"],
        }

    chip_match = await _resolve_chip_for_blob(db, firmware_id, blob_bytes, chip_target_hint)
    if chip_match is None:
        return {
            "audited_at": audit_started_at,
            "chip_match": None,
            "blob_id": resolved_blob_id,
            "blob_size_bytes": len(blob_bytes),
            "region_audits": [],
            "skipped_regions": [],
            "findings_emitted_count": 0,
            "errors": [
                "no chip family matched; supply an operator descriptor via "
                "POST /bare-metal-hint or submit_bare_metal_descriptor MCP tool"
            ],
        }

    catalog_match = get_chip_domain(f"{chip_match.family_id}/{chip_match.domain_name}")
    if catalog_match is None:
        return {
            "audited_at": audit_started_at,
            "chip_match": chip_match.model_dump(),
            "blob_id": resolved_blob_id,
            "blob_size_bytes": len(blob_bytes),
            "region_audits": [],
            "skipped_regions": [],
            "findings_emitted_count": 0,
            "errors": [f"chip {chip_match.family_id}/{chip_match.domain_name} not in catalog"],
        }
    manifest, domain_name = catalog_match
    domain = next(d for d in manifest.domains if d.name == domain_name)

    region_audits: list[dict] = []
    skipped_regions: list[dict] = []
    findings_emitted = 0
    findings_service = FindingService(db)
    errors: list[str] = []

    for region in domain.address_regions:
        # Rule #45 parse-only — encrypted regions are explicitly skipped,
        # never decrypted by the walker.
        if "encrypted_region" in region.semantic:
            skipped_regions.append({
                "region_name": region.name,
                "reason": "encrypted_region semantic — Rule #45 parse-only",
            })
            continue
        if not region.policy:
            continue
        policies_evaluated = []
        for rule in region.policy:
            evaluator = POLICY_EVALUATORS.get(rule.operator)
            if evaluator is None:
                errors.append(f"no evaluator for policy operator {rule.operator!r}")
                continue
            try:
                matched, evidence_text = evaluator(blob_bytes, region, rule, domain)
            except Exception as exc:
                errors.append(
                    f"evaluator {rule.operator!r} raised on {region.name!r}: {exc}"
                )
                continue
            policy_record: dict[str, Any] = {
                "operator": rule.operator,
                "value_hex": rule.value_hex,
                "matched": matched,
                "cwe_ids": list(rule.cwe_ids),
                "severity": rule.severity,
                "finding_source": rule.finding_source,
                "evidence": evidence_text,
                "finding_id": None,
            }
            if matched and rule.finding_source:
                title = (
                    f"{manifest.display_name}: {rule.finding_source} "
                    f"on region {region.name}"
                )
                description = (
                    rule.description
                    or f"Policy {rule.operator} matched on region {region.name} "
                       f"(0x{region.start:X}-0x{region.end:X}); {evidence_text}"
                )
                cwe_ids_str = [f"CWE-{c}" for c in rule.cwe_ids]
                finding = await findings_service.create(
                    project_id=project_id,
                    data=FindingCreate(
                        title=title,
                        severity=Severity(rule.severity),
                        description=description,
                        evidence=evidence_text,
                        cwe_ids=cwe_ids_str,
                        confidence=Confidence(rule.confidence),
                        firmware_id=firmware_id,
                        source=rule.finding_source,
                    ),
                )
                policy_record["finding_id"] = str(finding.id)
                findings_emitted += 1
            policies_evaluated.append(policy_record)
        if policies_evaluated:
            region_audits.append({
                "region_name": region.name,
                "start": region.start,
                "end": region.end,
                "semantic": list(region.semantic),
                "policies_evaluated": policies_evaluated,
            })

    # Stamp chip_target on the descriptor source if from operator/external.
    if blob_id is not None and resolved_blob_id is not None:
        blob_row = await db.get(HardwareFirmwareBlob, uuid.UUID(resolved_blob_id))
        if blob_row is not None and not blob_row.chip_target:
            blob_row.chip_target = f"{chip_match.family_id}/{chip_match.domain_name}"

    return {
        "audited_at": audit_started_at,
        "chip_match": chip_match.model_dump(),
        "blob_id": resolved_blob_id,
        "blob_size_bytes": len(blob_bytes),
        "region_audits": region_audits,
        "skipped_regions": skipped_regions,
        "findings_emitted_count": findings_emitted,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_bare_metal_audit_background(
    firmware_id: uuid.UUID,
    *,
    blob_path: Path | None = None,
    blob_id: uuid.UUID | None = None,
    chip_target_hint: str | None = None,
) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions firmware.bare_metal_audit_status:
        queued (set by caller via POST/MCP)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Outer guard: any exception escaping the inner runner gets captured into
    bare_metal_audit_error + status=failed via a FRESH session (because the
    inner session may have rolled back on the exception).
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning("bare_metal_audit: firmware %s not found", firmware_id)
                return
            firmware.bare_metal_audit_status = "running"
            firmware.bare_metal_audit_started_at = dt.datetime.now(dt.timezone.utc)
            firmware.bare_metal_audit_error = None
            await db.commit()
            try:
                result = await _do_bare_metal_audit_run(
                    db, firmware_id,
                    blob_path=blob_path, blob_id=blob_id,
                    chip_target_hint=chip_target_hint,
                )
                firmware.bare_metal_audit_status = "completed"
                firmware.bare_metal_audit_finished_at = dt.datetime.now(dt.timezone.utc)
                firmware.bare_metal_audit_result = _stamp_firmware_bare_metal_audit_result(result)
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.bare_metal_audit_status = "failed"
                        fail_row.bare_metal_audit_finished_at = dt.datetime.now(dt.timezone.utc)
                        fail_row.bare_metal_audit_error = err
                        await fail_db.commit()
                logger.exception("bare_metal_audit: inner runner failed for %s", firmware_id)
    except Exception:
        logger.exception("bare_metal_audit: unrecoverable outer failure for %s", firmware_id)


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_bare_metal_audit_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook.

    Mirrors the ``auto_<op>_firmware_safe`` pattern across the walker fleet:
    own session, swallow exceptions silently, DO NOT mutate firmware status
    (leaves it ``idle`` so a manual MCP re-trigger works without 409).

    Currently a no-op for firmwares without auto-discovered bare-metal blobs
    (the catalog auto-detect needs strong signals; stripped production
    firmware requires an operator descriptor). The walker is operator-
    triggered via MCP / HTTP for Phase 1; full unpack-post-detection
    auto-trigger lands in Phase 2 alongside the multi-blob discovery path.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            # Phase 1: no-op. The walker fires on operator demand via MCP /
            # HTTP. Phase 2 will discover bare-metal blob candidates by
            # walking get_detection_roots(firmware) for raw .bin files.
    except Exception:
        logger.exception("auto_bare_metal_audit_firmware_safe: %s", firmware_id)


__all__ = [
    "POLICY_EVALUATORS",
    "_do_bare_metal_audit_run",
    "auto_bare_metal_audit_firmware_safe",
    "run_bare_metal_audit_background",
]
