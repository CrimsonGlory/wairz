"""File-format resolver — closed dispatch + cost-sorted signal evaluation.

Module-level constants are CLOSED + Rule #46 META-CANARY enforced exhaustive
against the matching closed Literals in :mod:`app.schemas.file_format`.

``_SOURCE_PRECEDENCE``
    Scout GG §SC5 dual. Manifest_source rank ALWAYS outranks numeric
    precedence (Wave-1 S5 H). Operator at precedence=200 STILL beats
    unauthenticated_external at precedence=50.

``_SIGNAL_COST_CLASS``
    Resolver evaluates signals in cost-class order, NOT YAML declaration
    order (Wave-1 S5 attack O — I/O cost amplification DoS closed).

``PLUGIN_REGISTRY``
    Registered Python plugins. Plugins declare ``cost_class`` +
    ``applicable_format_ids`` (Wave-1 S3 §3). Frozen post-startup per
    W2-beta attack I (TOCTOU between validation and use).
"""
from __future__ import annotations

import logging
import os
import zipfile
from collections.abc import Callable
from io import BytesIO
from typing import Any, Protocol

from app.schemas.file_format import (
    Detection,
    DetectionSignal,
    DetectionSignalKind,
    DispatchKind,
    FileFormatManifest,
    FormatMatch,
    ManifestSource,
    SortTier,
)
from app.services.file_format_catalog.snapshot import FormatCatalogSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed dispatch tables — Rule #46 META-CANARY enforced exhaustive.
# ---------------------------------------------------------------------------


#: Source precedence rank. Higher rank wins. Manifest_source rank ALWAYS
#: outranks numeric precedence (Wave-1 S5 H; Scout GG §SC5 dual).
_SOURCE_PRECEDENCE: dict[ManifestSource, int] = {
    "_system": 100,
    "core": 80,
    "operator": 60,
    "attested_external": 40,
    "unauthenticated_external": 20,
}


#: Sort-tier rank — outermost dimension of the resolver sort key. Ascending
#: sort, so ceiling=0 wins; floor=2 loses. Rule #46 META-CANARY enforces
#: exhaustive coverage against :data:`SortTier`. P3.2.a.
_TIER_RANK: dict[SortTier, int] = {
    "ceiling": 0,
    "general": 1,
    "floor":   2,
}


#: Cost classes — resolver evaluates signals in this order regardless of YAML
#: order (Wave-1 S5 attack O). Lower = cheaper.
_SIGNAL_COST_CLASS: dict[DetectionSignalKind, int] = {
    "always_matches": 0,          # zero — single _system sentinel only
    "filename": 0,
    "path_context": 0,
    "size_range": 0,
    "elf_check": 1,
    "intel_hex_check": 1,
    "pe_check": 1,
    "text_format": 1,
    "magic_bytes": 2,
    "zip_markers": 3,
    "tar_markers": 3,
    "rtos_check": 3,
}


# Signal-evaluator signature: takes (signal, blob_head, path, size) -> bool
_SignalEvaluator = Callable[[DetectionSignal, bytes, str, int], bool]


# ---------------------------------------------------------------------------
# Signal evaluators — production-semantic match for the 80% case.
# Long-tail (text_format / rtos_check) stubbed to return False with a TODO.
# ---------------------------------------------------------------------------


def _eval_filename(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Exact basename match (lowercased) OR extension match."""
    basename = os.path.basename(path).lower()
    if signal.stems_lower:
        if basename in {s.lower() for s in signal.stems_lower}:
            return True
        # Stem-without-extension match too
        stem, _, _ = basename.rpartition(".")
        if stem and stem in {s.lower() for s in signal.stems_lower}:
            return True
    if signal.extensions_lower:
        for ext in signal.extensions_lower:
            if basename.endswith(ext.lower()):
                return True
    return False


def _eval_path_context(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Any substring of the lowercased path matches."""
    if not signal.path_substrings_any_of:
        return False
    p = path.lower()
    return any(sub.lower() in p for sub in signal.path_substrings_any_of)


def _eval_size_range(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Inclusive size band; both bounds optional."""
    if signal.size_min is not None and size < signal.size_min:
        return False
    if signal.size_max is not None and size > signal.size_max:
        return False
    return True


def _eval_elf_check(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """ELF header magic at offset 0."""
    return blob_head[:4] == b"\x7fELF"


def _eval_intel_hex_check(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Intel HEX format — first byte ``:`` then hex digits."""
    if not blob_head or blob_head[:1] != b":":
        return False
    # Sample the next 10 bytes; all must be hex chars
    sample = blob_head[1:11]
    if not sample:
        return False
    hex_chars = set(b"0123456789abcdefABCDEF\r\n")
    return all(b in hex_chars for b in sample)


def _eval_pe_check(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """PE/MZ DOS header magic at offset 0."""
    return blob_head[:2] == b"MZ"


def _eval_text_format(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """SREC / TI-TXT detection. TODO P3.2 wiring."""
    # P3.2 ships srec + ti_txt parsers. Conservative stub today.
    return False


def _eval_magic_bytes(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Match bytes_hex at offset; optional mask AND-ing."""
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


def _eval_zip_markers(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Open as zip and check inner file names.

    Conservative — requires inner_min_count if declared. Uses BytesIO over
    blob_head (limited preview). For full-file zip walks the matcher needs
    file path access; we trust the schema to keep this signal away from
    head-only callers (zip directory is at END of file).
    """
    if not signal.inner_file_names and not signal.inner_basenames:
        return False
    # We need the FULL file for zip inspection — fall back to path read.
    # Heuristic: peek for PK magic in head; if absent, definitely not zip.
    if b"PK\x03\x04" not in blob_head[:128] and b"PK\x05\x06" not in blob_head:
        return False
    try:
        # Try to open the file path if it exists; otherwise the head-byte
        # heuristic alone (PK magic present) returns True.
        if path and os.path.isfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                inner = [n.lower() for n in zf.namelist()]
        else:
            return False
    except (zipfile.BadZipFile, OSError):
        return False
    hits = 0
    needles_full = {n.lower() for n in (signal.inner_file_names or [])}
    needles_base = {n.lower() for n in (signal.inner_basenames or [])}
    for n in inner:
        if n in needles_full:
            hits += 1
        elif os.path.basename(n) in needles_base:
            hits += 1
    min_count = signal.inner_min_count or 1
    return hits >= min_count


def _eval_tar_markers(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """ustar magic at offset 0x101 (Unix tar header)."""
    if len(blob_head) < 0x108:
        return False
    return blob_head[0x101:0x106] == b"ustar"


def _eval_rtos_check(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """RTOS plugin dispatch. TODO P3.2 wiring with PLUGIN_REGISTRY."""
    if signal.rtos_plugin_ref is None:
        return False
    plugin = PLUGIN_REGISTRY.get(signal.rtos_plugin_ref)
    if plugin is None:
        return False
    try:
        result = plugin.detect(blob_head, path, size)
    except Exception as exc:  # noqa: BLE001 — defensive plugin boundary
        logger.warning(
            "rtos_check: plugin %r raised: %s", signal.rtos_plugin_ref, exc,
        )
        return False
    return bool(result)


def _eval_always_matches(
    signal: DetectionSignal, blob_head: bytes, path: str, size: int,
) -> bool:
    """Always returns True. Only the single _system sentinel sets this kind."""
    return True


SIGNAL_EVALUATORS: dict[DetectionSignalKind, _SignalEvaluator] = {
    "filename": _eval_filename,
    "path_context": _eval_path_context,
    "size_range": _eval_size_range,
    "elf_check": _eval_elf_check,
    "intel_hex_check": _eval_intel_hex_check,
    "pe_check": _eval_pe_check,
    "text_format": _eval_text_format,
    "magic_bytes": _eval_magic_bytes,
    "zip_markers": _eval_zip_markers,
    "tar_markers": _eval_tar_markers,
    "rtos_check": _eval_rtos_check,
    "always_matches": _eval_always_matches,
}


# ---------------------------------------------------------------------------
# Dispatch evaluators — closed table per DispatchKind.
# ---------------------------------------------------------------------------


# Returns the format_id to dispatch TO, or None to use the manifest's output.
_DispatchEvaluator = Callable[
    [FileFormatManifest, bytes, str, int, FormatCatalogSnapshot],
    str | None,
]


def _dispatch_by_partition_name(
    manifest: FileFormatManifest,
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: FormatCatalogSnapshot,
) -> str | None:
    """Match the basename (lowercased, sans ext) against dispatch.cases."""
    basename = os.path.basename(path).lower()
    stem, _, _ = basename.rpartition(".")
    key = stem or basename
    target = manifest.dispatch.cases.get(key)
    if target:
        return target
    return manifest.dispatch.default


def _dispatch_by_zip_inner_file(
    manifest: FileFormatManifest,
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: FormatCatalogSnapshot,
) -> str | None:
    """Open zip; look up first inner basename in dispatch.cases."""
    if not path or not os.path.isfile(path):
        return manifest.dispatch.default
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return manifest.dispatch.default
    for n in names:
        basename = os.path.basename(n).lower()
        target = manifest.dispatch.cases.get(basename)
        if target:
            return target
    return manifest.dispatch.default


def _dispatch_by_inner_magic(
    manifest: FileFormatManifest,
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: FormatCatalogSnapshot,
) -> str | None:
    """First N bytes (hex) match a case key. Cases keyed by hex prefix."""
    head_hex = blob_head[:16].hex()
    for case_key, target in manifest.dispatch.cases.items():
        if head_hex.startswith(case_key.lower()):
            return target
    return manifest.dispatch.default


def _dispatch_alias(
    manifest: FileFormatManifest,
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: FormatCatalogSnapshot,
) -> str | None:
    """Alias dispatch — resolve to manifest.alias_of."""
    return manifest.alias_of


def _dispatch_none(
    manifest: FileFormatManifest,
    blob_head: bytes,
    path: str,
    size: int,
    snapshot: FormatCatalogSnapshot,
) -> str | None:
    """No dispatch — emit this manifest's output."""
    return None


DISPATCH_EVALUATORS: dict[DispatchKind, _DispatchEvaluator] = {
    "by_partition_name": _dispatch_by_partition_name,
    "by_zip_inner_file": _dispatch_by_zip_inner_file,
    "by_inner_magic": _dispatch_by_inner_magic,
    "alias": _dispatch_alias,
    "none": _dispatch_none,
}


# ---------------------------------------------------------------------------
# Plugin registry — frozen post-startup (W2-beta attack I).
# ---------------------------------------------------------------------------


class MatcherProto(Protocol):
    """Protocol for registered Python matchers.

    ``cost_class`` is checked by validator A5 (deep-dispatch eager-expensive
    plugin reject). ``applicable_format_ids`` is the plugin-side allowlist
    cross-checked against PluginRef.applicable_format_ids at catalog refresh.
    """

    cost_class: int
    applicable_format_ids: frozenset[str]

    def detect(
        self, blob_head: bytes, path: str, size: int,
    ) -> Any: ...  # pragma: no cover - protocol


PLUGIN_REGISTRY: dict[str, MatcherProto] = {}
_PLUGIN_REGISTRY_FROZEN: bool = False


def register_matcher(name: str, matcher: MatcherProto) -> None:
    """Register a Python plugin. Must run BEFORE freeze_plugin_registry()."""
    if _PLUGIN_REGISTRY_FROZEN:
        raise RuntimeError(
            f"PLUGIN_REGISTRY frozen after startup; cannot register {name!r}"
        )
    PLUGIN_REGISTRY[name] = matcher


def freeze_plugin_registry() -> None:
    """Freeze the plugin registry post-startup (W2-beta attack I)."""
    global _PLUGIN_REGISTRY_FROZEN
    _PLUGIN_REGISTRY_FROZEN = True


def _unfreeze_plugin_registry_for_tests() -> None:
    """Test-only — reset frozen flag between tests. NEVER call in prod."""
    global _PLUGIN_REGISTRY_FROZEN
    _PLUGIN_REGISTRY_FROZEN = False


# ---------------------------------------------------------------------------
# Resolver — collect-then-sort by total-order tuple (Wave-1 S5 B + H).
# ---------------------------------------------------------------------------


def _evaluate_detection(
    detection: Detection, blob_head: bytes, path: str, size: int,
) -> tuple[bool, list[dict], float]:
    """Evaluate detection signals in COST-CLASS order, not declaration order.

    Returns ``(matched, evidence, score)``. Score is the fraction of signals
    that matched in [0, 1.0] under all_required / any; under weighted the
    score is the weight-fraction.

    Wave-1 S5 attack O — short-circuit on first MISS for all_required so
    expensive signals (zip_markers / rtos_check) never run when a cheap
    signal (filename) already disqualifies the manifest.
    """
    # Sort signals by cost class; stable for declaration order tie.
    sorted_signals = sorted(
        enumerate(detection.signals),
        key=lambda pair: (
            _SIGNAL_COST_CLASS.get(pair[1].kind, 99), pair[0],
        ),
    )
    evidence: list[dict] = []
    matched_count = 0
    weighted_sum = 0.0
    weighted_max = 0.0
    for _orig_idx, signal in sorted_signals:
        evaluator = SIGNAL_EVALUATORS.get(signal.kind)
        if evaluator is None:
            evidence.append({
                "kind": signal.kind,
                "match": False,
                "note": "no evaluator registered",
            })
            continue
        try:
            hit = evaluator(signal, blob_head, path, size)
        except Exception as exc:  # noqa: BLE001 — defensive evaluator boundary
            logger.warning(
                "resolver: evaluator %r raised: %s", signal.kind, exc,
            )
            hit = False
        evidence.append({
            "kind": signal.kind,
            "match": hit,
            "cost_class": _SIGNAL_COST_CLASS.get(signal.kind, 99),
        })
        if hit:
            matched_count += 1
            weighted_sum += signal.weight
        weighted_max += signal.weight
        # all_required short-circuit on miss (Wave-1 S5 attack O closure)
        if detection.combine == "all_required" and not hit:
            return False, evidence, 0.0
    total = len(detection.signals)
    if total == 0:
        return False, evidence, 0.0
    if detection.combine == "all_required":
        matched = (matched_count == total)
        score = (matched_count / total) if total else 0.0
    elif detection.combine == "any":
        matched = (matched_count >= 1)
        score = (matched_count / total) if total else 0.0
    else:  # weighted
        score = (weighted_sum / weighted_max) if weighted_max else 0.0
        threshold = (detection.min_confidence_score or 0.0) / 100.0
        matched = score >= threshold
    return matched, evidence, score


def _rule_specificity(manifest: FileFormatManifest) -> int:
    """Rough specificity metric for tie-breaking. Higher = more specific.

    Counts the number of signals + dispatch cases + refinement substrings.
    """
    n = len(manifest.detection.signals)
    n += len(manifest.dispatch.cases)
    if manifest.refinement:
        n += len(manifest.refinement.path_substrings_any_of)
    return n


def _compute_sort_key(manifest: FileFormatManifest) -> tuple:
    """Total-order sort key for resolver candidate ranking. P3.2.a.

    Tuple shape (ascending sort):

        (tier_rank, -source_rank, precedence, -specificity, vendor, basename)

    * **tier_rank** (outermost) — closed-Literal sort-tier policy declared
      per-manifest in YAML (Rule #52). ``ceiling`` (0) wins over ``general``
      (1) wins over ``floor`` (2). Reserved to ``_system`` for ceiling +
      floor via schema validator + loader path cross-check.
    * **-source_rank** — ``_SOURCE_PRECEDENCE`` rank. Scout GG §SC5 dual /
      Wave-1 S5 H: manifest_source rank ALWAYS outranks numeric precedence
      within a tier. Operator at precedence=N STILL beats
      unauthenticated_external at precedence=N (within tier).
    * **precedence** — numeric. **P3.2.a FLIP**: lower precedence wins
      (matches AUTHORING.md author intent across all 47 manifests; S2
      audit found 14 inversions caused by the prior `-precedence` shape).
    * **-specificity** — within tied precedence, more-specific manifest
      (more signals + dispatch cases + refinement substrings) wins.
    * **vendor / basename** — lex tie-break for stable ordering.

    Extracted into a named helper so the Rule #46 META-CANARY can AST-walk
    a single function body (P3.1.c lesson — scope source scanners narrowly).
    """
    tier_rank = _TIER_RANK[manifest.detection.sort_tier]
    source_rank = _SOURCE_PRECEDENCE.get(manifest.manifest_source, 0)
    specificity = _rule_specificity(manifest)
    return (
        tier_rank,                # P3.2.a outermost — closed-Literal tier
        -source_rank,             # within tier: _SOURCE_PRECEDENCE rank desc
        manifest.precedence,      # P3.2.a FLIP — lower precedence wins
        -specificity,             # then specificity desc
        manifest.vendor.lower(),  # lex tie-break
        os.path.basename(manifest.source_path or "").lower(),
    )


def resolve(
    blob_head: bytes,
    path: str,
    size: int,
    *,
    snapshot: FormatCatalogSnapshot | None = None,
) -> FormatMatch | None:
    """Resolve a blob to a format using collect-then-sort + dispatch chain.

    Wave-1 S5 B HIGH stop-the-line: first-match was the bug shape. Collect
    EVERY matching manifest, sort by total-order tuple, return the TOP-1.

    Total-order key is computed by :func:`_compute_sort_key` (P3.2.a — the
    sort-key construction is extracted into a named helper so Rule #46
    META-CANARIES can AST-walk a single function body).

    Dispatch chain is followed up to ``manifest.dispatch.depth_max`` (default 2);
    cycle detection rejects with WARN.
    """
    if snapshot is None:
        snapshot = get_default_snapshot()
    candidates: list[tuple[tuple, FileFormatManifest, list[dict], float]] = []
    for manifest in snapshot.manifests:
        # Skip removed manifests defensively (catalog should already reject).
        if manifest.deprecation.status == "removed":
            continue
        matched, evidence, score = _evaluate_detection(
            manifest.detection, blob_head, path, size,
        )
        if not matched:
            continue
        sort_key = _compute_sort_key(manifest)
        candidates.append((sort_key, manifest, evidence, score))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    _, best, best_evidence, best_score = candidates[0]
    # Follow dispatch chain (depth_max enforced; cycle detection).
    visited: set[str] = set()
    current = best
    depth = 0
    max_depth = best.dispatch.depth_max
    while True:
        if depth >= max_depth:
            break
        kind = current.dispatch.kind
        evaluator = DISPATCH_EVALUATORS.get(kind)
        if evaluator is None:
            break
        if kind == "none":
            break
        target_id = evaluator(current, blob_head, path, size, snapshot)
        if not target_id:
            break
        if target_id in visited:
            logger.warning(
                "resolver: dispatch cycle detected at %s -> %s",
                current.format_id, target_id,
            )
            break
        visited.add(current.format_id)
        target = snapshot.get(target_id)
        if target is None:
            logger.warning(
                "resolver: dispatch target %r not in snapshot (from %s)",
                target_id, current.format_id,
            )
            break
        current = target
        depth += 1
    return FormatMatch(
        format_id=current.format_id,
        confidence_score=best_score * 100.0,
        evidence=best_evidence,
        manifest_source=best.manifest_source,
        source_path=best.source_path or "",
    )


# ---------------------------------------------------------------------------
# Default snapshot accessor — late-binds catalog to avoid circular import.
# ---------------------------------------------------------------------------


def get_default_snapshot() -> FormatCatalogSnapshot:
    """Return the latest default-catalog snapshot.

    Late-bound to avoid circular import; catalog.py imports resolver constants.
    """
    from app.services.file_format_catalog.catalog import (
        get_default_catalog,
    )
    return get_default_catalog().get_snapshot()


__all__ = [
    "DISPATCH_EVALUATORS",
    "MatcherProto",
    "PLUGIN_REGISTRY",
    "SIGNAL_EVALUATORS",
    "_SIGNAL_COST_CLASS",
    "_SOURCE_PRECEDENCE",
    "freeze_plugin_registry",
    "get_default_snapshot",
    "register_matcher",
    "resolve",
]
