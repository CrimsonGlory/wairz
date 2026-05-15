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
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_DATA_DIR = Path(__file__).parent / "data"
_VENDOR_YAML = _DATA_DIR / "vendor_prefixes.yaml"
_PATTERNS_YAML = _DATA_DIR / "firmware_patterns.yaml"
_BT_QCA_CODENAMES_YAML = _DATA_DIR / "bt_qca_codenames.yaml"

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
# BT QCA codename table (bt_qca_codenames.yaml) — externalized 2026-05-17.
#
# Owns the QCA Bluetooth codename → chipset map, the BrakTooth-DoS chipset
# scope, and the MediaTek known-chip allowlist. Consumed by
# parsers/bt_firmware_banner.py via the public accessors at the bottom of
# this module. Each accessor reads via @lru_cache so per-call cost is O(1).
#
# Loader contract: on a missing or malformed YAML, log a WARNING and return
# the in-tree ``_BT_CODENAME_DEFAULTS`` so parsing keeps working without
# operator intervention (Rule #34-style graceful degrade).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BtCodenameTable:
    """Loaded view of bt_qca_codenames.yaml.

    Frozen so accessors can return shared instances safely. Field shapes are
    chosen to match the parser's existing consumption (dict[str, str] for
    fast .get / `in` checks; frozenset[str] for chipset membership tests;
    tuple[bytes, ...] for byte-wise ``in data`` membership against raw
    firmware bytes).
    """

    codename_map: dict[str, str] = field(default_factory=dict)
    codename_display: dict[str, str] = field(default_factory=dict)
    codename_also_covers: dict[str, frozenset[str]] = field(default_factory=dict)
    codename_families: dict[str, tuple[str, ...]] = field(default_factory=dict)
    braktooth_chipsets: frozenset[str] = frozenset()
    mtk_known_chips: tuple[bytes, ...] = ()


# In-tree defaults — fallback when bt_qca_codenames.yaml is missing or
# malformed. Mirrors the shipping YAML; keeping these as the literal
# fallback means a future YAML schema regression cannot regress the
# parser to silently lose all QCA codename / MediaTek chip coverage.
# Order MUST be kept in lockstep with the shipped YAML (verified by the
# loader tests).
_BT_CODENAME_DEFAULTS = BtCodenameTable(
    codename_map={
        "CMC": "wcn3950",
        "CHE": "wcn3990",
        "APA": "wcn3988",
        "HAS": "qca6390",
        "MOS": "wcn6750",
    },
    codename_display={
        "CMC": "Comanche",
        "CHE": "Cherokee",
        "APA": "Apache",
        "HAS": "Hastings",
        "MOS": "Moselle",
    },
    codename_also_covers={
        "CHE": frozenset({"wcn3991", "wcn3998"}),
    },
    codename_families={
        "CMC": ("Rome",),
        "CHE": ("Rome",),
        "APA": ("Rome",),
        "HAS": ("FastConnect",),
        "MOS": ("FastConnect",),
    },
    braktooth_chipsets=frozenset({"wcn3950", "wcn3990", "wcn3991", "wcn3998"}),
    mtk_known_chips=(
        b"MT7961", b"MT7921", b"MT7922", b"MT7925", b"MT7902", b"MT7927",
        b"MT7663", b"MT7668", b"MT6620", b"MT6628", b"MT6630", b"MT6632",
        b"MT6635", b"MT6639", b"MT6789", b"MT6895", b"MT6983", b"MT6985",
    ),
)


def _parse_bt_codename_data(data: dict) -> BtCodenameTable:
    """Parse a validated YAML dict into a BtCodenameTable.

    Raises ``ValueError`` on any structural issue; the caller
    (``_load_bt_qca_codenames``) wraps with the graceful-degrade fallback
    to ``_BT_CODENAME_DEFAULTS``. Loud-on-bad-structure here is the right
    shape — we want operators editing the YAML to see the error in the
    backend log, not silently get defaults.
    """
    codenames_raw = data.get("codenames")
    if not isinstance(codenames_raw, list):
        raise ValueError("'codenames' must be a list")

    codename_map: dict[str, str] = {}
    codename_display: dict[str, str] = {}
    codename_also_covers: dict[str, frozenset[str]] = {}
    codename_families: dict[str, tuple[str, ...]] = {}

    for idx, entry in enumerate(codenames_raw):
        if not isinstance(entry, dict):
            raise ValueError(f"codenames[{idx}] must be a mapping, got {type(entry).__name__}")
        codename = entry.get("codename")
        chipset = entry.get("chipset")
        if not (isinstance(codename, str) and codename.strip()):
            raise ValueError(f"codenames[{idx}]: 'codename' missing or empty")
        if not (isinstance(chipset, str) and chipset.strip()):
            raise ValueError(f"codenames[{idx}]: 'chipset' missing or empty")
        cn = codename.strip().upper()
        codename_map[cn] = chipset.strip().lower()

        disp = entry.get("display")
        if isinstance(disp, str) and disp.strip():
            codename_display[cn] = disp.strip()

        also = entry.get("also_covers")
        if isinstance(also, list):
            covers = {
                str(c).strip().lower()
                for c in also
                if isinstance(c, str) and c.strip()
            }
            if covers:
                codename_also_covers[cn] = frozenset(covers)

        fams = entry.get("families")
        if isinstance(fams, list):
            families = tuple(
                str(f).strip() for f in fams if isinstance(f, str) and f.strip()
            )
            if families:
                codename_families[cn] = families

    bt_raw = data.get("braktooth_chipsets")
    if bt_raw is not None and not isinstance(bt_raw, list):
        raise ValueError("'braktooth_chipsets' must be a list")
    braktooth_chipsets = frozenset(
        str(c).strip().lower()
        for c in (bt_raw or [])
        if isinstance(c, str) and c.strip()
    )

    mtk_raw = data.get("mtk_known_chips")
    if mtk_raw is not None and not isinstance(mtk_raw, list):
        raise ValueError("'mtk_known_chips' must be a list")
    mtk_known_chips: list[bytes] = []
    for chip in mtk_raw or []:
        if not isinstance(chip, str) or not chip.strip():
            continue
        try:
            mtk_known_chips.append(chip.strip().encode("ascii"))
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"mtk_known_chips entry {chip!r}: must be ASCII (got {exc})"
            ) from exc

    return BtCodenameTable(
        codename_map=codename_map,
        codename_display=codename_display,
        codename_also_covers=codename_also_covers,
        codename_families=codename_families,
        braktooth_chipsets=braktooth_chipsets,
        mtk_known_chips=tuple(mtk_known_chips),
    )


@lru_cache(maxsize=1)
def _load_bt_qca_codenames() -> BtCodenameTable:
    """Load and validate bt_qca_codenames.yaml.

    Returns the parsed ``BtCodenameTable`` on success; on missing file,
    YAML syntax error, or structural validation failure, returns
    ``_BT_CODENAME_DEFAULTS`` and logs a WARNING.

    Cached via ``functools.lru_cache(maxsize=1)``: per-call cost is O(1)
    after the first invocation. Tests that swap the YAML path MUST call
    ``_load_bt_qca_codenames.cache_clear()`` to reset state.
    """
    data = _safe_load(_BT_QCA_CODENAMES_YAML)
    if not data:
        # _safe_load already logged the issue (missing file or YAML syntax
        # error). Surface the fallback decision at INFO so a stale-default
        # state is visible to operators tailing the backend log.
        logger.info(
            "patterns_loader: using in-tree _BT_CODENAME_DEFAULTS "
            "(bt_qca_codenames.yaml missing or unparseable)"
        )
        return _BT_CODENAME_DEFAULTS
    try:
        return _parse_bt_codename_data(data)
    except (ValueError, TypeError) as exc:
        logger.warning(
            "patterns_loader: bt_qca_codenames.yaml structural validation "
            "failed (%s); falling back to in-tree _BT_CODENAME_DEFAULTS",
            exc,
        )
        return _BT_CODENAME_DEFAULTS


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


# ---------------------------------------------------------------------------
# BT QCA codename accessors. Each call resolves through the lru_cache, so
# repeated lookups are O(1). Callers (parsers/bt_firmware_banner.py) treat
# these as authoritative — the parser carries no parallel in-tree copy.
# ---------------------------------------------------------------------------


def get_qca_codename_map() -> dict[str, str]:
    """3-letter QCA codename (UPPERCASE) → canonical primary chipset (lowercase)."""
    return _load_bt_qca_codenames().codename_map


def get_qca_codename_display() -> dict[str, str]:
    """QCA codename → human-readable display name (e.g. "CMC" → "Comanche")."""
    return _load_bt_qca_codenames().codename_display


def get_qca_also_covers() -> dict[str, frozenset[str]]:
    """QCA codename → additional chipsets the same codename can ship on.

    Example: ``{"CHE": frozenset({"wcn3991", "wcn3998"})}`` — Cherokee
    family covers WCN3990 (primary) + WCN3991 + WCN3998 in the upstream
    Linux kernel switch. Informational; the parser does not currently
    consume this beyond surfacing via metadata.
    """
    return _load_bt_qca_codenames().codename_also_covers


def get_qca_codename_families() -> dict[str, tuple[str, ...]]:
    """QCA codename → generation tag tuples (e.g. ``("Rome",)``, ``("FastConnect",)``).

    Informational; available for future queries like "list all FastConnect
    BT codenames" without re-reading the parser source.
    """
    return _load_bt_qca_codenames().codename_families


def get_braktooth_chipsets() -> frozenset[str]:
    """Chipsets in scope for the ASSET BrakTooth Qualcomm DoS subset.

    CVE-2021-34147 + CVE-2021-31609 + CVE-2021-31612 fire on any blob
    whose ``chipset_target`` falls in this set. CVE-2021-28139 (RCE
    CVSS 8.8) is ESP32-only per NVD and is NOT pinned by this parser
    despite being part of the BrakTooth disclosure batch — see Reviewer
    B finding 2026-05-16.
    """
    return _load_bt_qca_codenames().braktooth_chipsets


def get_mtk_chips() -> tuple[bytes, ...]:
    """MediaTek BT/WiFi chip-ID allowlist for content scanning.

    Returned as ``tuple[bytes, ...]`` because the parser performs byte-wise
    ``in firmware_bytes`` membership tests — encoding once at load time is
    cheaper than encoding on every parser invocation.
    """
    return _load_bt_qca_codenames().mtk_known_chips


__all__ = [
    "BtCodenameTable",
    "PathContextMatch",
    "PatternMatch",
    "VENDORS",
    "VENDOR_DISPLAY",
    "get_braktooth_chipsets",
    "get_mtk_chips",
    "get_qca_also_covers",
    "get_qca_codename_display",
    "get_qca_codename_families",
    "get_qca_codename_map",
    "match",
    "match_path_context",
    "resolve_vendor",
]
