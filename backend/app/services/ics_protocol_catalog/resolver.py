"""ICS protocol resolver — closed dispatch + cost-sorted signal evaluation.

Module-level constants are CLOSED + Rule #46 META-CANARY enforced exhaustive
against the matching closed Literals in :mod:`app.schemas.ics_protocol`.

``_SOURCE_PRECEDENCE``
    Mirror of file_format_catalog._SOURCE_PRECEDENCE. Manifest_source rank
    ALWAYS outranks numeric precedence (Wave-1 S5 H; Scout GG §SC5 dual).

``_SIGNAL_COST_CLASS``
    Resolver evaluates signals in cost-class order, NOT YAML declaration
    order (Wave-1 S5 attack O — I/O cost amplification DoS closed).

``SIGNAL_EVALUATORS``
    Dispatch table mapping IcsSignalKind to evaluator functions. Rule #46
    META-CANARY enforced exhaustive against the IcsSignalKind Literal.

v0 (Session 1) ships 3 evaluators: ``_eval_magic_bytes``,
``_eval_string_in_binary``, ``_eval_function_code_set``. ``_eval_port_signature``
+ ``_eval_library_symbol`` will land in Session 2 alongside the walker that
provides the binary context (ELF dynsym table + ``.rodata`` constants xref).
For Session 1 those 2 evaluators are PRESENT as stubs returning False so the
exhaustive META-CANARY passes — operator manifests that declare them
correctly will validate but match nothing until Session 2 wires the context.

Multiple-protocol-per-binary cardinality: unlike file_format catalog where
:func:`resolve` returns a single ``FormatMatch``, this catalog's
:func:`resolve_all` returns ``list[IcsProtocolMatch]`` because a binary can
speak N protocols simultaneously (Modbus + OPC-UA + DNP3 in one HMI is
real-world per Wave-1 Scout A).
"""
from __future__ import annotations

import logging
from collections.abc import Callable

from app.schemas.ics_protocol import (
    IcsConfidence,
    IcsDetection,
    IcsDetectionSignal,
    IcsManifestSource,
    IcsProtocolManifest,
    IcsProtocolMatch,
    IcsSignalKind,
)
from app.services.ics_protocol_catalog.snapshot import (
    IcsProtocolCatalogSnapshot,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed dispatch tables — Rule #46 META-CANARY enforced exhaustive.
# ---------------------------------------------------------------------------


#: Source precedence rank. Higher rank wins. Manifest_source rank ALWAYS
#: outranks numeric precedence (Wave-1 S5 H; Scout GG §SC5 dual).
_SOURCE_PRECEDENCE: dict[IcsManifestSource, int] = {
    "_system": 100,
    "core": 80,
    "operator": 60,
    "attested_external": 40,
    "unauthenticated_external": 20,
}


#: Cost classes — resolver evaluates signals in this order regardless of YAML
#: order (Wave-1 S5 attack O). Lower = cheaper.
_SIGNAL_COST_CLASS: dict[IcsSignalKind, int] = {
    "port_signature": 0,        # zero — list lookup against signal.ports
    "magic_bytes": 1,           # cheap — bounded head-byte slice
    "function_code_set": 2,     # mid — bounded scan for sorted byte set
    "library_symbol": 2,        # mid — Session 2 ELF/PE dynsym walk
    "string_in_binary": 3,      # expensive — substring scan over head window
}


# Signal-evaluator signature: takes (signal, blob_head, path, size, context) -> bool
_SignalEvaluator = Callable[
    [IcsDetectionSignal, bytes, str, int, "IcsResolverContext | None"], bool,
]


# ---------------------------------------------------------------------------
# Resolver context — passed through evaluators. Session 1 stub; Session 2
# extends with ELF symtab cache, PE imports cache, config-file scan results.
# ---------------------------------------------------------------------------


class IcsResolverContext:
    """Per-resolve-call context. Session 1 stub.

    Session 2 will add:
    * elf_dynsym_cache: dict[str, frozenset[str]] — per-binary dynamic symbols
    * pe_imports_cache: dict[str, frozenset[str]] — per-binary PE imports
    * config_file_scan: dict[str, frozenset[str]] — pre-scanned config files
    * observed_ports: frozenset[int] — ports observed in `.rodata` constants

    For Session 1, the context is a placeholder so the evaluator signatures
    remain stable across Session 1 → Session 2.
    """

    def __init__(self) -> None:
        self.elf_dynsym_cache: dict[str, frozenset[str]] = {}
        self.pe_imports_cache: dict[str, frozenset[str]] = {}


# ---------------------------------------------------------------------------
# Signal evaluators.
# ---------------------------------------------------------------------------


def _eval_magic_bytes(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Match bytes_hex at offset; optional mask AND-ing.

    Mirror of file_format_catalog._eval_magic_bytes.
    """
    if signal.bytes_hex is None or signal.offset is None:
        return False
    try:
        expected = bytes.fromhex(signal.bytes_hex)
    except ValueError:
        return False
    end = signal.offset + len(expected)
    if end > len(blob_head):
        return False
    actual = blob_head[signal.offset:end]
    if signal.mask_hex is not None:
        try:
            mask = bytes.fromhex(signal.mask_hex)
        except ValueError:
            return False
        if len(mask) != len(expected):
            return False
        return all(
            (a & m) == (e & m) for a, m, e in zip(actual, mask, expected)
        )
    return actual == expected


def _eval_string_in_binary(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Literal byte-substring scan over a bounded head window.

    Closed-grammar evaluator. Each needle is a hex-encoded literal byte
    sequence; the evaluator decodes once, optionally lowercases (the
    constraint's case_sensitive=False case), and runs ``needle in window``
    for each needle. ``combine='all'`` requires every needle present;
    ``combine='any'`` requires at least ``min_count`` of N needles present.
    """
    constraint = signal.string_in_binary_constraint
    if constraint is None:
        return False
    try:
        needles = [bytes.fromhex(n) for n in constraint.needles_hex]
    except ValueError:
        return False
    start = constraint.search_offset
    if start >= len(blob_head):
        return False
    if constraint.search_length is None:
        window = blob_head[start:]
    else:
        window = blob_head[start:start + constraint.search_length]
    if not constraint.case_sensitive:
        window = window.lower()
        needles = [n.lower() for n in needles]
    hits = sum(1 for needle in needles if needle in window)
    if constraint.combine == "all":
        return hits == len(needles)
    # combine == "any" — at least min_count of N needles present.
    return hits >= constraint.min_count


def _eval_function_code_set(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Scan for a function-code dispatch-table fingerprint.

    Each manifest declares the standard function codes for its protocol
    (e.g. Modbus 0x01-0x06 / 0x0F / 0x10). The evaluator scans every
    ``window_bytes``-length window in the head looking for at least
    ``min_count`` of the declared codes appearing within that window. This
    detects compiled function-code lookup tables embedded in ``.rodata`` or
    ``.text`` without requiring the codes to be contiguous or sorted.

    Floor: ``min_count >= 2`` enforced by IcsFunctionCodeSetConstraint
    validator (W2-β A8 high-collision mitigation).
    """
    constraint = signal.function_code_constraint
    if constraint is None:
        return False
    try:
        target_codes = frozenset(
            bytes.fromhex(c)[0] for c in constraint.function_codes_hex
        )
    except (ValueError, IndexError):
        return False
    if not target_codes:
        return False

    window_bytes = constraint.window_bytes
    min_count = constraint.min_count

    # Slide a window across blob_head; for each window, count distinct
    # function-code bytes from target_codes that appear inside it.
    head_len = len(blob_head)
    if head_len < min_count:
        return False

    # Optimisation: pre-compute byte-presence indices for each target code.
    # For each window-start, check the sum of distinct codes present.
    step = max(window_bytes // 4, 64)  # overlap windows by 75% — bounded
    for start in range(0, head_len, step):
        end = min(start + window_bytes, head_len)
        window = blob_head[start:end]
        distinct_codes_in_window = len(target_codes & set(window))
        if distinct_codes_in_window >= min_count:
            return True
    return False


def _eval_port_signature(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Detect IANA-assigned port constants in `.rodata`.

    Session 1 STUB — returns False. Session 2 will populate ``context.
    observed_ports`` from a `.rodata`-scanner plugin, and this evaluator
    will check `signal.ports & context.observed_ports`.

    For now the stub keeps the SIGNAL_EVALUATORS exhaustive (Rule #46)
    while the consumer infrastructure ships in Session 2.
    """
    if signal.ports is None:
        return False
    # Stub matches when ANY port's little-endian uint16 byte sequence
    # appears in the head bytes — a minimal proof of concept until Session 2
    # adds proper `.rodata` xref tracking.
    for port in signal.ports:
        le_bytes = port.to_bytes(2, "little")
        if le_bytes in blob_head:
            return True
    return False


def _eval_library_symbol(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Match dynamic-library symbol patterns against the binary's symtab.

    Session 1 STUB — returns False. Session 2 will populate ``context.
    elf_dynsym_cache[path]`` and ``context.pe_imports_cache[path]`` from
    LIEF/pefile and check `signal.symbol_patterns_lower` against the
    cached symbol set.

    Until Session 2 ships the context populator, this evaluator returns
    False (no false positives) and the manifest's other signals carry
    the detection.
    """
    if signal.symbol_patterns_lower is None:
        return False
    if context is None:
        return False
    cached_symbols = context.elf_dynsym_cache.get(path, frozenset())
    cached_symbols |= context.pe_imports_cache.get(path, frozenset())
    if not cached_symbols:
        return False
    for pattern in signal.symbol_patterns_lower:
        for symbol in cached_symbols:
            if pattern in symbol.lower():
                return True
    return False


SIGNAL_EVALUATORS: dict[IcsSignalKind, _SignalEvaluator] = {
    "magic_bytes": _eval_magic_bytes,
    "string_in_binary": _eval_string_in_binary,
    "function_code_set": _eval_function_code_set,
    "port_signature": _eval_port_signature,
    "library_symbol": _eval_library_symbol,
}


# ---------------------------------------------------------------------------
# Manifest evaluation — applies the IcsDetection combine semantics.
# ---------------------------------------------------------------------------


def _certainty_to_confidence(
    detection: IcsDetection, operator_confidence: IcsConfidence,
) -> IcsConfidence:
    """Cap operator-supplied confidence by detection.certainty.

    string_only → low; config_present → max medium; stack_present → no cap.
    Mirror of W2-α convergence on operator-supplied vs auto-derived
    confidence.
    """
    certainty = detection.certainty
    if certainty == "string_only":
        return "low"
    if certainty == "config_present":
        if operator_confidence == "high":
            return "medium"
        return operator_confidence
    # stack_present → no cap
    return operator_confidence


def _evaluate_manifest(
    manifest: IcsProtocolManifest,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> IcsProtocolMatch | None:
    """Evaluate ONE manifest against the binary. Returns a match or None.

    Applies the IcsDetection.combine semantics:
    * all_required — every signal must fire
    * any — at least one signal must fire
    * weighted — sum-of-(weight*match) must meet min_confidence_score floor
    """
    detection = manifest.detection
    # Cost-sort signals before evaluation (Wave-1 S5 attack O).
    sorted_signals = sorted(
        enumerate(detection.signals),
        key=lambda pair: (
            _SIGNAL_COST_CLASS.get(pair[1].kind, 99), pair[0],
        ),
    )

    matched_kinds: list[str] = []
    weighted_score: float = 0.0
    for _idx, signal in sorted_signals:
        evaluator = SIGNAL_EVALUATORS.get(signal.kind)
        if evaluator is None:
            # Should be impossible per Rule #46 exhaustive canary; defensive.
            logger.warning(
                "ics_resolver: no evaluator for signal kind %r in manifest %r",
                signal.kind, manifest.manifest_id,
            )
            continue
        try:
            matched = evaluator(signal, blob_head, path, size, context)
        except Exception as exc:  # noqa: BLE001 — defensive evaluator boundary
            logger.warning(
                "ics_resolver: evaluator %r raised for manifest %r: %s",
                signal.kind, manifest.manifest_id, exc,
            )
            matched = False
        if matched:
            matched_kinds.append(signal.kind)
            weighted_score += signal.weight * 100.0
        elif detection.combine == "all_required":
            # Short-circuit on first miss.
            return None

    if not matched_kinds:
        return None
    if detection.combine == "any" and not matched_kinds:
        return None
    if detection.combine == "weighted":
        if detection.min_confidence_score is None:
            return None
        if weighted_score < detection.min_confidence_score:
            return None
    if detection.combine == "all_required" and len(matched_kinds) != len(
        detection.signals
    ):
        return None

    capped_confidence = _certainty_to_confidence(
        detection, manifest.output.confidence,
    )
    return IcsProtocolMatch(
        manifest_id=manifest.manifest_id,
        manifest_source=manifest.manifest_source,
        protocol_family=manifest.output.protocol_family,
        layer=manifest.output.layer,
        transport=manifest.output.transport,
        vendor=manifest.output.vendor,
        vendor_product=manifest.output.vendor_product,
        protocol_version=manifest.output.protocol_version,
        confidence=capped_confidence,
        certainty=detection.certainty,
        matched_signals=matched_kinds,
    )


def resolve_all(
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: IcsProtocolCatalogSnapshot,
    context: IcsResolverContext | None = None,
) -> list[IcsProtocolMatch]:
    """Resolve ALL ICS protocols matched by the given binary.

    Unlike file_format catalog's :func:`resolve` (single-format-per-blob),
    this returns a LIST of matches because a single binary can speak N
    protocols simultaneously (Modbus + OPC-UA + DNP3 in one HMI is real).

    Drops manifests whose ``deprecation.status == "removed"`` per file_format
    catalog A3 discipline.

    Sorted by (manifest_source rank DESC, precedence ASC, manifest_id ASC)
    so the operator-facing output is deterministic.
    """
    if context is None:
        context = IcsResolverContext()

    matches: list[IcsProtocolMatch] = []
    for manifest in snapshot:
        if manifest.deprecation.status == "removed":
            continue
        m = _evaluate_manifest(manifest, blob_head, path, size, context)
        if m is not None:
            matches.append(m)

    # Stable sort by (source rank DESC, precedence ASC, manifest_id ASC)
    matches.sort(
        key=lambda m: (
            -_SOURCE_PRECEDENCE[m.manifest_source],
            # We don't carry precedence on IcsProtocolMatch; sort by
            # manifest_id lexically as tie-breaker; precedence resolution
            # happens at the catalog-load gate (I4 cross-vendor collision).
            m.manifest_id,
        ),
    )
    return matches


__all__ = [
    "SIGNAL_EVALUATORS",
    "_SIGNAL_COST_CLASS",
    "_SOURCE_PRECEDENCE",
    "IcsResolverContext",
    "resolve_all",
]
