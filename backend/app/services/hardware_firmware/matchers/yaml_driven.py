"""Default chip matcher — walks the YAML catalog and scores candidates.

For each chip family / domain in the catalog, evaluates the declared
``detection_signals`` against the blob bytes and accumulates a weighted
confidence score. Returns scored candidates above the operator-supplied
threshold.

**Signal evaluators are CLOSED.** Adding a new signal kind requires:

1. A new value on :data:`app.schemas.chip_family.DetectionSignalKind`.
2. A handler in :data:`SIGNAL_EVALUATORS` below.
3. Rule #25 cross-stack alignment commit + Rule #46 META-CANARY.

Operators NEVER provide ``regex`` / ``script`` / ``predicate`` keys via
YAML — every signal flows through a Python evaluator vetted in code review
(Scout CC §SC7 hard cap on YAML expressiveness).
"""
from __future__ import annotations

import logging
import math
from collections import Counter
from collections.abc import Callable

from app.schemas.chip_family import (
    ChipFamilyManifest,
    ChipMatch,
    DetectionSignal,
    DetectionSignalKind,
    Domain,
)
from app.services.hardware_firmware.chip_catalog import get_chip_catalog
from app.services.hardware_firmware.matchers.base import (
    ChipMatcher,
    domain_base_addr_for_blob,
    read_region_bytes,
    read_word_at_address,
    register_matcher,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signal evaluators — one per DetectionSignalKind. Each returns a partial
# score in [0.0, 1.0] (multiplied by the signal's ``weight`` to get the
# contribution to the domain's total confidence) OR a special negative
# value -inf meaning "reject this candidate outright" (used by elf_magic
# to short-circuit ELF-shaped inputs).
# ---------------------------------------------------------------------------


# Sentinel: any signal evaluator returning this value disqualifies the
# domain entirely, bypassing accumulation.
REJECT = float("-inf")

# Sentinel: this signal is not applicable to the current blob (e.g. it
# anchors at an address outside the blob's coverage). The matcher EXCLUDES
# such signals from both the accumulator AND the max_possible normaliser
# — partial dumps (flash-only / boot-ROM-only) don't get penalised for
# signals that target the part they don't contain.
NOT_APPLICABLE = float("nan")


def _is_not_applicable(score: float) -> bool:
    """NaN-safe check for the NOT_APPLICABLE sentinel."""
    return score != score  # only NaN is not equal to itself


def _eval_silicon_id_byte_match(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """Match a specific byte sequence at a specific offset (or anywhere)."""
    if not signal.bytes_hex:
        return 0.0
    try:
        expected = bytes.fromhex(signal.bytes_hex.replace(" ", ""))
    except ValueError:
        logger.warning(
            "silicon_id_byte_match: bytes_hex %r is not valid hex on signal %r",
            signal.bytes_hex, signal.description,
        )
        return 0.0
    if signal.address is not None:
        base = domain_base_addr_for_blob(domain)
        # signal.address is a CHIP-side address; translate via packing
        from app.services.hardware_firmware.matchers.base import (
            address_to_file_offset,
        )
        try:
            offset = address_to_file_offset(signal.address, base, domain.packing)
        except ValueError:
            return 0.0
        if offset + len(expected) > len(blob_bytes):
            return 0.0
        return 1.0 if blob_bytes[offset : offset + len(expected)] == expected else 0.0
    # No anchor — substring search
    return 1.0 if expected in blob_bytes else 0.0


def _eval_reset_vector_at(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """Word at ``signal.address`` looks like a plausible reset / branch.

    Returns NOT_APPLICABLE when the signal's address lies outside the
    blob's coverage (e.g. signal targets a boot-ROM address but the blob
    is a flash-only dump). Partial dumps don't get penalised for absent
    address ranges (Rule #19 evidence-first — observed against stripped
    Eaton production firmware 2026-05-19).
    """
    if signal.address is None:
        return 0.0
    base = domain_base_addr_for_blob(domain)
    word = read_word_at_address(
        blob_bytes, signal.address, base, domain.packing, domain.instruction_word_bits,
    )
    if word is None:
        return NOT_APPLICABLE   # outside blob coverage — don't score
    if word in (0x0000, 0xFFFF, 0xFFFFFFFF):
        return 0.0
    return 1.0


def _eval_vector_table_shape(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """At ``signal.region_name``, look for an N-entry vector ladder.

    Heuristic: read 8 consecutive entries; each non-empty and within the
    expected code-address range → score 1.0. Empty / all-FF entries reduce score.
    """
    if not signal.region_name:
        return 0.0
    region = next(
        (r for r in domain.address_regions if r.name == signal.region_name),
        None,
    )
    if region is None or region.size is None:
        return 0.0
    base = domain_base_addr_for_blob(domain)
    region_bytes = read_region_bytes(
        blob_bytes, region.start, region.size, base, domain.packing,
    )
    if region_bytes is None:
        return NOT_APPLICABLE   # region outside blob coverage
    word_size_bytes = max(1, domain.instruction_word_bits // 8)
    # Sample 16 consecutive words from the start of the region.
    num_words = min(16, len(region_bytes) // word_size_bytes)
    if num_words < 4:
        return 0.0
    plausible = 0
    for i in range(num_words):
        chunk = region_bytes[i * word_size_bytes : (i + 1) * word_size_bytes]
        word = int.from_bytes(chunk, "little")
        if word not in (0x0000, 0xFFFF):
            plausible += 1
    return plausible / num_words


def _eval_string_present(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """Score based on fraction of operator-declared literal strings present.

    Literal substring search in both Latin-1 and UTF-8 forms (covers
    null-terminated C strings + UTF-16 ASCII subset). NO regex.
    """
    if not signal.patterns:
        return 0.0
    hits = 0
    for pat in signal.patterns:
        encoded = pat.encode("latin-1", errors="ignore")
        if encoded and encoded in blob_bytes:
            hits += 1
            continue
        # Try wide-char (UTF-16LE) — common in compiler runtime tables
        wide = pat.encode("utf-16-le", errors="ignore")
        if wide and wide in blob_bytes:
            hits += 1
    return hits / len(signal.patterns) if signal.patterns else 0.0


def _eval_bam_signature(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """NXP SPC58 BAM RCHW signature at start of blob."""
    if not signal.bytes_hex:
        return 0.0
    try:
        expected = bytes.fromhex(signal.bytes_hex.replace(" ", ""))
    except ValueError:
        return 0.0
    if len(blob_bytes) < len(expected):
        return 0.0
    return 1.0 if blob_bytes[: len(expected)] == expected else 0.0


def _eval_boot_header_magic(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """Vendor-specific boot header magic at a fixed offset."""
    if not signal.bytes_hex:
        return 0.0
    try:
        expected = bytes.fromhex(signal.bytes_hex.replace(" ", ""))
    except ValueError:
        return 0.0
    offset = 0
    if signal.address is not None:
        base = domain_base_addr_for_blob(domain)
        from app.services.hardware_firmware.matchers.base import (
            address_to_file_offset,
        )
        try:
            offset = address_to_file_offset(signal.address, base, domain.packing)
        except ValueError:
            return 0.0
    if offset + len(expected) > len(blob_bytes):
        return 0.0
    return 1.0 if blob_bytes[offset : offset + len(expected)] == expected else 0.0


def _eval_elf_magic(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """REJECT-mode signal: if the blob is ELF-shaped, disqualify this candidate.

    Bare-metal flash dumps are not ELFs. An ELF-shaped input means the
    operator uploaded a build artefact, not a chip dump — different
    extraction path (existing ELF parsers handle it).
    """
    elf_magic = b"\x7fELF"
    return REJECT if blob_bytes[:4] == elf_magic else 0.0


def _shannon_entropy(buf: bytes) -> float:
    """Compute Shannon entropy of a byte buffer (bits/byte, range 0–8)."""
    if not buf:
        return 0.0
    counts = Counter(buf)
    total = len(buf)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _eval_entropy_band(
    blob_bytes: bytes,
    signal: DetectionSignal,
    domain: Domain,
) -> float:
    """Score based on whether region (or whole blob) entropy falls in band."""
    if signal.region_name:
        region = next(
            (r for r in domain.address_regions if r.name == signal.region_name),
            None,
        )
        if region is None or region.size is None:
            return 0.0
        base = domain_base_addr_for_blob(domain)
        buf = read_region_bytes(
            blob_bytes, region.start, region.size, base, domain.packing,
        ) or b""
    else:
        buf = blob_bytes
    if not buf:
        return 0.0
    e = _shannon_entropy(buf)
    lo = signal.entropy_min if signal.entropy_min is not None else 0.0
    hi = signal.entropy_max if signal.entropy_max is not None else 8.0
    return 1.0 if lo <= e <= hi else 0.0


SIGNAL_EVALUATORS: dict[
    DetectionSignalKind,
    Callable[[bytes, DetectionSignal, Domain], float],
] = {
    "silicon_id_byte_match": _eval_silicon_id_byte_match,
    "reset_vector_at": _eval_reset_vector_at,
    "vector_table_shape": _eval_vector_table_shape,
    "string_present": _eval_string_present,
    "bam_signature": _eval_bam_signature,
    "boot_header_magic": _eval_boot_header_magic,
    "elf_magic": _eval_elf_magic,
    "entropy_band": _eval_entropy_band,
}


# ---------------------------------------------------------------------------
# YamlDrivenMatcher — the default catalog-walking matcher.
# ---------------------------------------------------------------------------


class YamlDrivenMatcher:
    """Walks the YAML chip catalog and scores every domain.

    Implements the :class:`ChipMatcher` protocol. Registered as
    ``"yaml_driven"`` at module import time.

    Confidence accumulation: each signal contributes ``weight × evaluator_score``
    to the domain total. Confidence is capped at 1.0 (so over-declared
    high-weight signals don't compound past sanity). Domains accumulating
    a :data:`REJECT` from any signal are dropped outright.
    """

    NAME = "yaml_driven"

    def detect(
        self,
        blob_bytes: bytes,
        blob_metadata: dict | None = None,
        *,
        threshold: float = 0.3,
        max_candidates: int = 5,
    ) -> list[ChipMatch]:
        catalog = get_chip_catalog()
        if not catalog:
            return []
        results: list[ChipMatch] = []
        for manifest in catalog.values():
            for domain in manifest.domains:
                match = self._score_domain(manifest, domain, blob_bytes)
                if match is not None and match.confidence >= threshold:
                    results.append(match)
        results.sort(key=lambda m: m.confidence, reverse=True)
        return results[:max_candidates]

    def _score_domain(
        self,
        manifest: ChipFamilyManifest,
        domain: Domain,
        blob_bytes: bytes,
    ) -> ChipMatch | None:
        total_score = 0.0
        max_possible = 0.0
        evidence: list[dict] = []
        for signal in domain.detection_signals:
            evaluator = SIGNAL_EVALUATORS.get(signal.kind)
            if evaluator is None:
                logger.warning(
                    "yaml_driven: no evaluator for signal kind %r (domain %s/%s)",
                    signal.kind, manifest.family_id, domain.name,
                )
                continue
            try:
                partial = evaluator(blob_bytes, signal, domain)
            except Exception as exc:
                logger.warning(
                    "yaml_driven: evaluator %r raised on %s/%s: %s",
                    signal.kind, manifest.family_id, domain.name, exc,
                )
                continue
            if partial == REJECT:
                # Hard reject — domain disqualified
                return None
            if _is_not_applicable(partial):
                # Signal targets a region outside this blob's coverage —
                # exclude from both numerator AND denominator (don't penalise
                # partial dumps for absent address ranges).
                evidence.append({
                    "kind": signal.kind,
                    "weight": signal.weight,
                    "partial_score": "n/a",
                    "contribution": 0.0,
                    "description": signal.description,
                    "skipped": "blob coverage does not include signal target",
                })
                continue
            max_possible += signal.weight
            contribution = signal.weight * partial
            total_score += contribution
            evidence.append({
                "kind": signal.kind,
                "weight": signal.weight,
                "partial_score": partial,
                "contribution": contribution,
                "description": signal.description,
            })
        if max_possible == 0.0:
            return None
        # Normalise to [0.0, 1.0] — confidence is fraction of total possible weight.
        confidence = min(1.0, total_score / max_possible) if max_possible else 0.0
        return ChipMatch(
            family_id=manifest.family_id,
            domain_name=domain.name,
            confidence=confidence,
            evidence=evidence,
            descriptor_source="auto_detection",
        )


_default_matcher: ChipMatcher = YamlDrivenMatcher()


def get_default_matcher() -> ChipMatcher:
    """Return the module-level YamlDrivenMatcher singleton."""
    return _default_matcher


# Register at import time (matches parsers/<vendor>.py idiom)
register_matcher(_default_matcher)


__all__ = [
    "REJECT",
    "SIGNAL_EVALUATORS",
    "YamlDrivenMatcher",
    "get_default_matcher",
]
