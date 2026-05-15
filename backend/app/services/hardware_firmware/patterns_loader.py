"""Data-driven firmware filename classifier.

Loads two YAML files once at import:

* ``data/vendor_prefixes.yaml`` — canonical vendor names, display strings,
  and aliases.  Provides :data:`VENDORS` and :data:`VENDOR_DISPLAY` for UI
  lookups and :func:`resolve_vendor`.
* ``data/firmware_patterns.yaml`` — ordered, first-match-wins list of
  filename regexes mapped to (vendor, product, category, confidence, source,
  format).  See :func:`match`.

The loaders are tolerant — on YAML parse errors or missing files we log a
warning and return empty tables rather than crashing the whole import.  Any
regex that fails to compile is skipped (logged) so one bad entry cannot
break classification for all other patterns.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_DATA_DIR = Path(__file__).parent / "data"
_VENDOR_YAML = _DATA_DIR / "vendor_prefixes.yaml"
_PATTERNS_YAML = _DATA_DIR / "firmware_patterns.yaml"

# Canonical vendor prefixes Wairz ships with — classifier.py reads this set
# (via the legacy ``VENDORS`` import) to gate downstream normalization.  The
# loader always seeds this fallback so classification keeps working even if
# the YAML file goes missing.
_CORE_VENDORS: frozenset[str] = frozenset(
    {
        "qualcomm",
        "mediatek",
        "samsung",
        "broadcom",
        "nvidia",
        "imagination",
        "arm",
        "apple",
        "cypress",
        "unisoc",
        "hisilicon",
        "intel",
        "realtek",
        "unknown",
    }
)


@dataclass
class PatternMatch:
    """Result of matching a filename against firmware_patterns.yaml.

    ``format`` defaults to ``raw_bin`` so callers can always pass it to the
    ``Classification`` dataclass without None-checking.
    """

    vendor: str
    category: str
    product: str | None
    confidence: str  # high | medium | low
    source: str | None = None
    format: str = "raw_bin"


@dataclass
class PathContextMatch:
    """Result of matching a blob's path against firmware_patterns.yaml::path_contexts.

    Used by the classifier as a REFINEMENT step: when filename-stage
    classification returns ``category="other"`` for a blob in a known
    partition tree (radio.img / BTFM.bin / dspso.bin / …), the path-
    context matcher rescues it into a specific category.

    See classifier._classify_by_path_context for the integration point.
    """

    vendor: str  # "unknown" → keep filename-inferred vendor
    category: str
    product: str | None
    confidence: str  # high | medium | low
    priority: int = 0


def _safe_load(path: Path) -> dict:
    """Load a YAML file, returning {} on any error (logged)."""
    if not path.is_file():
        logger.warning("patterns_loader: YAML not found at %s", path)
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:  # pragma: no cover — exercised in tests
        logger.warning("patterns_loader: failed to parse %s: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning(
            "patterns_loader: %s top-level must be a mapping, got %s",
            path,
            type(data).__name__,
        )
        return {}
    return data


def _load_vendors() -> tuple[frozenset[str], dict[str, str], dict[str, str]]:
    """Return (canonical prefixes, alias→canonical, canonical→display).

    Falls back to the hard-coded ``_CORE_VENDORS`` when the YAML is missing
    so the rest of the codebase keeps working.
    """
    data = _safe_load(_VENDOR_YAML)
    entries = data.get("vendors") or []
    if not isinstance(entries, list):
        logger.warning("patterns_loader: 'vendors' must be a list in %s", _VENDOR_YAML)
        entries = []

    canonical: set[str] = set(_CORE_VENDORS)
    display: dict[str, str] = {}
    alias_map: dict[str, str] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        prefix = str(entry.get("prefix") or "").strip().lower()
        if not prefix:
            continue
        canonical.add(prefix)
        disp = entry.get("display")
        if isinstance(disp, str) and disp.strip():
            display[prefix] = disp.strip()
        aliases = entry.get("aliases") or []
        if isinstance(aliases, list):
            for a in aliases:
                a_str = str(a or "").strip().lower()
                if a_str and a_str != prefix:
                    alias_map[a_str] = prefix

    # Seed display for the core vendors if not overridden by the YAML.
    display.setdefault("qualcomm", "Qualcomm Technologies, Inc.")
    display.setdefault("mediatek", "MediaTek Inc.")
    display.setdefault("unknown", "Unknown Vendor")

    return frozenset(canonical), alias_map, display


def _compile_patterns() -> list[tuple[re.Pattern[str], PatternMatch]]:
    """Load and compile firmware_patterns.yaml → [(regex, match-template)]."""
    data = _safe_load(_PATTERNS_YAML)
    raw = data.get("patterns") or []
    if not isinstance(raw, list):
        logger.warning("patterns_loader: 'patterns' must be a list in %s", _PATTERNS_YAML)
        return []

    compiled: list[tuple[re.Pattern[str], PatternMatch]] = []
    skipped = 0
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            skipped += 1
            continue
        pat = entry.get("pattern")
        vendor = entry.get("vendor")
        category = entry.get("category")
        if not (isinstance(pat, str) and isinstance(vendor, str) and isinstance(category, str)):
            logger.warning(
                "patterns_loader: entry #%d missing required field (pattern/vendor/category)", idx
            )
            skipped += 1
            continue
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error as exc:
            logger.warning(
                "patterns_loader: entry #%d pattern %r failed to compile: %s",
                idx,
                pat,
                exc,
            )
            skipped += 1
            continue

        confidence = str(entry.get("confidence") or "medium").strip().lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"

        fmt = entry.get("format")
        fmt_str = str(fmt).strip() if isinstance(fmt, str) and fmt.strip() else "raw_bin"

        product = entry.get("product")
        product_str = str(product).strip() if isinstance(product, str) and product.strip() else None

        source = entry.get("source")
        source_str = str(source).strip() if isinstance(source, str) and source.strip() else None

        compiled.append(
            (
                rx,
                PatternMatch(
                    vendor=vendor.strip().lower(),
                    category=category.strip().lower(),
                    product=product_str,
                    confidence=confidence,
                    source=source_str,
                    format=fmt_str,
                ),
            )
        )

    if skipped:
        logger.info(
            "patterns_loader: loaded %d patterns (%d skipped due to errors)",
            len(compiled),
            skipped,
        )
    else:
        logger.info("patterns_loader: loaded %d firmware patterns", len(compiled))
    return compiled


def _compile_path_contexts() -> list[
    tuple[re.Pattern[str], re.Pattern[str] | None, PathContextMatch]
]:
    """Load + compile ``firmware_patterns.yaml::path_contexts`` entries.

    Returns ``[(path_regex, filename_regex_or_None, PathContextMatch), ...]``
    sorted by descending ``priority`` so the most specific rules fire first.

    Same defensive shape as :func:`_compile_patterns` — invalid entries are
    logged and skipped, never raise. An empty section returns ``[]``; a
    missing section returns ``[]`` (back-compat with older YAML).
    """
    data = _safe_load(_PATTERNS_YAML)
    raw = data.get("path_contexts") or []
    if not isinstance(raw, list):
        logger.warning(
            "patterns_loader: 'path_contexts' must be a list in %s",
            _PATTERNS_YAML,
        )
        return []

    compiled: list[tuple[re.Pattern[str], re.Pattern[str] | None, PathContextMatch]] = []
    skipped = 0
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            skipped += 1
            continue
        path_pat = entry.get("path_pattern")
        vendor = entry.get("vendor")
        category = entry.get("category")
        if not (
            isinstance(path_pat, str)
            and isinstance(vendor, str)
            and isinstance(category, str)
        ):
            logger.warning(
                "patterns_loader: path_contexts entry #%d missing required field "
                "(path_pattern/vendor/category)",
                idx,
            )
            skipped += 1
            continue
        try:
            path_rx = re.compile(path_pat, re.IGNORECASE)
        except re.error as exc:
            logger.warning(
                "patterns_loader: path_contexts entry #%d path_pattern %r "
                "failed to compile: %s",
                idx,
                path_pat,
                exc,
            )
            skipped += 1
            continue

        filename_rx: re.Pattern[str] | None = None
        filename_pat = entry.get("filename_pattern")
        if filename_pat:
            if not isinstance(filename_pat, str):
                logger.warning(
                    "patterns_loader: path_contexts entry #%d filename_pattern "
                    "must be a string",
                    idx,
                )
                skipped += 1
                continue
            try:
                filename_rx = re.compile(filename_pat, re.IGNORECASE)
            except re.error as exc:
                logger.warning(
                    "patterns_loader: path_contexts entry #%d filename_pattern "
                    "%r failed to compile: %s",
                    idx,
                    filename_pat,
                    exc,
                )
                skipped += 1
                continue

        confidence = str(entry.get("confidence") or "medium").strip().lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"

        priority_raw = entry.get("priority", 0)
        try:
            priority = int(priority_raw)
        except (TypeError, ValueError):
            priority = 0

        product = entry.get("product")
        product_str = (
            str(product).strip()
            if isinstance(product, str) and product.strip()
            else None
        )

        compiled.append(
            (
                path_rx,
                filename_rx,
                PathContextMatch(
                    vendor=vendor.strip().lower(),
                    category=category.strip().lower(),
                    product=product_str,
                    confidence=confidence,
                    priority=priority,
                ),
            )
        )

    # Highest priority first so the most specific rule wins. Secondary
    # sort keys (category, vendor, product) ensure deterministic
    # ordering across runs when two rules share the same priority —
    # per Reviewer A M5 (2026-05-15): without the tiebreaker, two
    # priority-tied rules resolve in YAML insertion order, so a future
    # PR appending a new rule in the wrong spot could silently change
    # classification results. Deterministic ordering makes the YAML
    # rewrite robust to author-order accidents.
    compiled.sort(
        key=lambda t: (
            -t[2].priority,
            t[2].category,
            t[2].vendor,
            t[2].product or "",
        )
    )

    if skipped:
        logger.info(
            "patterns_loader: loaded %d path_contexts (%d skipped due to errors)",
            len(compiled),
            skipped,
        )
    else:
        logger.info(
            "patterns_loader: loaded %d path_contexts entries", len(compiled)
        )
    return compiled


# ---------------------------------------------------------------------------
# Module-level tables (loaded once at import time).
# ---------------------------------------------------------------------------
VENDORS, _VENDOR_ALIASES, VENDOR_DISPLAY = _load_vendors()
_PATTERNS: list[tuple[re.Pattern[str], PatternMatch]] = _compile_patterns()
_PATH_CONTEXTS: list[
    tuple[re.Pattern[str], re.Pattern[str] | None, PathContextMatch]
] = _compile_path_contexts()


def resolve_vendor(name: str | None) -> str:
    """Canonicalise a vendor token via the alias map.

    Returns the input lowercased if no alias match is found — callers can
    then check ``name in VENDORS`` themselves.  An empty/None input returns
    ``"unknown"``.
    """
    if not name:
        return "unknown"
    key = name.strip().lower()
    return _VENDOR_ALIASES.get(key, key)


def match(path: str) -> PatternMatch | None:
    """Return the first PatternMatch whose regex matches the basename.

    The matcher is case-insensitive (regexes compiled with ``re.IGNORECASE``)
    and operates on ``os.path.basename(path)`` — full-path matching is *not*
    supported to keep YAML patterns portable across extraction roots.
    """
    if not path:
        return None
    # basename without importing os (cheap split is fine and keeps this
    # module importable before os in some sandbox scenarios).
    base = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not base:
        return None
    for rx, tmpl in _PATTERNS:
        if rx.search(base):
            return tmpl
    return None


def match_path_context(path: str) -> PathContextMatch | None:
    """Return the highest-priority path-context match for ``path``.

    Args:
        path: Full path (any case; the matcher lowercases). Separator MUST
            be ``/`` or ``\\`` — the function normalises both to ``/``.

    Returns ``None`` when no path_contexts entry matches. Path-context rules
    fire ONLY if (a) the lowercased path matches the rule's ``path_pattern``
    AND (b) when present, the basename matches the rule's ``filename_pattern``.

    Use this as a REFINEMENT step in the classifier — see classifier.py
    ``_classify_by_path_context``. Never overrides a non-"other" filename
    classification by contract; the classifier enforces that gate.
    """
    if not path:
        return None
    norm = path.replace("\\", "/").lower()
    base = norm.rsplit("/", 1)[-1] if "/" in norm else norm
    if not base:
        return None
    for path_rx, filename_rx, tmpl in _PATH_CONTEXTS:
        if not path_rx.search(norm):
            continue
        if filename_rx is not None and not filename_rx.search(base):
            continue
        return tmpl
    return None


__all__ = [
    "PathContextMatch",
    "PatternMatch",
    "VENDORS",
    "VENDOR_DISPLAY",
    "match",
    "match_path_context",
    "resolve_vendor",
]
