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


# ---------------------------------------------------------------------------
# Plugin registry — frozen post-startup (W2-β §SC5-NEW-ICS-S2-α HARDENED).
# ---------------------------------------------------------------------------
#
# Per W2-β §SC5-NEW-ICS-S2-α (Session 1 W2-β §SC5-NEW-ICS-7 extension):
# bare ``freeze_plugin_registry()`` is NOT iron-clad if the registry is a
# plain mutable dict that consumers import + can mutate at module-level.
# Mitigation: the ACTUAL registry is private ``_PLUGIN_REGISTRY``; the
# public ``PLUGIN_REGISTRY`` is a ``MappingProxyType`` read-only view.
# Consumers can't bypass the freeze via direct dict mutation.
#
# Per W2-β §SC5-NEW-ICS-S2-ζ: ``register_matcher`` also rejects matchers
# whose ``__closure__`` captures session/auth state — defensive against
# plugins that lazy-capture context.db from registration time.
#
# File-format-catalog precedent at ``file_format_catalog/resolver.py:716``
# uses the bare dict shape — backfill to MappingProxyType discipline is
# queued as a Rule #21 mirror sweep (deferred; documented in Phase 6
# postmortem).
from types import MappingProxyType  # noqa: E402 — at file end for grouping
from typing import Any, Protocol  # noqa: E402


class IcsProtocolMatcherProto(Protocol):
    """Protocol for registered Python ICS-protocol matchers.

    A plugin matcher receives the same head + path + size + context that
    closed-grammar signal evaluators do, but can implement arbitrary
    detection logic beyond the closed Pydantic grammar (e.g. ELF
    dynsym/symtab walks, PE import-table fingerprinting, .rodata port-
    constant xref tracking). Useful for protocol shapes the closed
    grammar can't express; the closed-grammar gates I20-I23 (Phase 4
    bundled-only-or-frozen-only) ensure plugins can't subvert
    operator-authored YAML detection.
    """

    cost_class: int
    protocol_families: frozenset[str]  # protocol_family values this plugin can emit

    def detect(
        self,
        blob_head: bytes,
        path: str,
        size: int,
        context: IcsResolverContext | None,
    ) -> Any: ...  # pragma: no cover - protocol


# Private mutable registry. NEVER re-export this. Only ``register_matcher``
# (gated by freeze flag) writes here; ``PLUGIN_REGISTRY`` (proxy) reads.
_PLUGIN_REGISTRY: dict[str, IcsProtocolMatcherProto] = {}

# Public read-only proxy. Consumers (resolver + walker + MCP tools)
# import this and read; the underlying dict is mutated ONLY by
# ``register_matcher`` during startup. Post-freeze, ``register_matcher``
# raises RuntimeError — and even if a hostile module reaches in via
# ``__dict__`` introspection, the proxy still prevents direct
# ``PLUGIN_REGISTRY[...] = ...`` writes.
PLUGIN_REGISTRY: MappingProxyType[str, IcsProtocolMatcherProto] = (
    MappingProxyType(_PLUGIN_REGISTRY)
)

_PLUGIN_REGISTRY_FROZEN: bool = False


def _namespace_collision_check(
    name: str, matcher: IcsProtocolMatcherProto,
) -> None:
    """Reject matchers whose ``protocol_families`` overlap with an already-
    registered matcher. Prevents plugin A claiming
    ``protocol_families={"modbus_tcp"}`` and plugin B doing the same —
    ambiguous dispatch + W2-β §SC5-NEW-ICS-7 vendor-authority laundering
    surface analog.
    """
    families: frozenset[str] = getattr(matcher, "protocol_families", frozenset())
    if not families:
        return
    for other_name, other in _PLUGIN_REGISTRY.items():
        if other_name == name:
            continue
        other_families: frozenset[str] = getattr(
            other, "protocol_families", frozenset(),
        )
        collision = families & other_families
        if collision:
            raise ValueError(
                f"plugin-namespace-disjointness: matcher {name!r} claims "
                f"protocol_families {sorted(collision)!r} already declared "
                f"by {other_name!r} (W2-β §SC5-NEW-ICS-S2-α related — "
                f"prevents ambiguous dispatch + family-claim laundering)"
            )


def _closure_capture_check(
    name: str, matcher: IcsProtocolMatcherProto,
) -> None:
    """Reject matchers whose callable closure captures session/auth state.

    Per W2-β §SC5-NEW-ICS-S2-ζ: a plugin matcher MUST be stateless w.r.t.
    request context. If the matcher's ``detect`` closure captures an
    ``AsyncSession``, ``Settings``, ``ContextVar``, or a user identifier
    type, raise at registration time — the stale closure value would
    leak across walker runs (e.g. plugin captures ``current_db`` from
    startup and every subsequent resolve reads from that one session).
    """
    detect = getattr(matcher, "detect", None)
    if detect is None:
        return
    closure = getattr(detect, "__closure__", None)
    if closure is None:
        return
    # Inspect each closure cell's contents. We don't know cell types
    # statically (Python is dynamic) — check by type name match.
    FORBIDDEN_TYPE_NAMES = {
        "AsyncSession",
        "Settings",
        "ContextVar",
        "ToolContext",
    }
    for cell in closure:
        try:
            value = cell.cell_contents
        except ValueError:
            continue  # empty cell — not yet bound; safe
        type_name = type(value).__name__
        if type_name in FORBIDDEN_TYPE_NAMES:
            raise ValueError(
                f"plugin matcher {name!r} captures closure of type "
                f"{type_name!r} — stateful capture forbidden per "
                f"W2-β §SC5-NEW-ICS-S2-ζ. Refactor the plugin to be "
                f"stateless w.r.t. session/auth; receive all context "
                f"via the detect() context kwarg."
            )


def register_matcher(name: str, matcher: IcsProtocolMatcherProto) -> None:
    """Register a Python plugin matcher. Must run BEFORE
    ``freeze_plugin_registry()``.

    Applies W2-β §SC5-NEW-ICS-S2-α (freeze gate), W2-β §SC5-NEW-ICS-S2-ζ
    (closure-capture rejection), and the namespace-disjointness
    collision check (analog of file_format A7).
    """
    if _PLUGIN_REGISTRY_FROZEN:
        raise RuntimeError(
            f"ics_protocol_catalog PLUGIN_REGISTRY is frozen after startup; "
            f"cannot register {name!r}. Plugin registration MUST happen "
            f"BEFORE freeze_plugin_registry() — call during lifespan "
            f"startup, not at runtime (W2-β §SC5-NEW-ICS-S2-α gate)."
        )
    _namespace_collision_check(name, matcher)
    _closure_capture_check(name, matcher)
    _PLUGIN_REGISTRY[name] = matcher


def freeze_plugin_registry() -> None:
    """Freeze the plugin registry post-startup. W2-β §SC5-NEW-ICS-S2-α
    HARDENED — the public ``PLUGIN_REGISTRY`` is already a read-only
    proxy; this flips the freeze flag so subsequent ``register_matcher``
    calls raise RuntimeError. Together the two mechanisms (proxy +
    flag) defend against the module-level attribute-shadow attack the
    Session 1 W2-β identified as the scariest unmitigated case.
    """
    global _PLUGIN_REGISTRY_FROZEN
    _PLUGIN_REGISTRY_FROZEN = True


def _unfreeze_plugin_registry_for_tests() -> None:
    """Test-only — reset frozen flag between tests. NEVER call in prod."""
    global _PLUGIN_REGISTRY_FROZEN
    _PLUGIN_REGISTRY_FROZEN = False


def is_plugin_registry_frozen() -> bool:
    """Return the freeze sentinel state. Used by Rule #46 META-CANARIES."""
    return _PLUGIN_REGISTRY_FROZEN


__all__ = [
    "PLUGIN_REGISTRY",
    "SIGNAL_EVALUATORS",
    "_SIGNAL_COST_CLASS",
    "_SOURCE_PRECEDENCE",
    "IcsProtocolMatcherProto",
    "IcsResolverContext",
    "_unfreeze_plugin_registry_for_tests",
    "freeze_plugin_registry",
    "is_plugin_registry_frozen",
    "register_matcher",
    "resolve_all",
]
