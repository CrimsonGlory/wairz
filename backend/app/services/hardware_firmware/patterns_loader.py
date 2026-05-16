"""Data-driven firmware filename classifier with hot-reloadable YAML backing.

Loads five YAML files that operators may extend at runtime:

* ``data/vendor_prefixes.yaml`` — canonical vendor names, display strings,
  and aliases. Backs :func:`resolve_vendor` + module-level
  :data:`VENDORS` / :data:`VENDOR_DISPLAY` snapshots.
* ``data/firmware_patterns.yaml`` — ordered, first-match-wins list of
  filename regexes mapped to (vendor, product, category, confidence,
  source, format). Backs :func:`match` and :func:`match_path_context`.
* ``data/bt_qca_codenames.yaml`` — QCA Bluetooth codename → chipset map +
  BrakTooth-DoS chipset scope + MediaTek BT known-chip allowlist.
  Backs the six ``get_qca_*`` / ``get_braktooth_chipsets`` / ``get_mtk_chips``
  accessors consumed by parsers/bt_firmware_banner.py.
* ``data/bt_banner_cve_pins.yaml`` — banner-pin → CVE rule engine input.
  Backs :func:`get_banner_cve_pins`.
* (Sibling-module) ``known_firmware.yaml`` — curated CVE-family list
  consumed by ``cve_matcher._load_known_firmware``. Hot-reloaded via the
  same generic ``MtimeCachedYamlLoader`` shape over there.

**Hot-reload contract (2026-05-18):** every accessor checks the file's
``stat().st_mtime_ns`` on every call and reloads atomically when it
changes. Operators edit YAML, save, and the next ``match()`` /
``get_banner_cve_pins()`` / etc. invocation sees the new entries without
a backend restart — pairs with the success-path INFO logs:

    bt_qca_codenames.yaml loaded — 5 codenames ... (YAML, not defaults)
    bt_qca_codenames.yaml reloaded due to mtime change (...)

Malformed reload (YAML syntax error OR structural validation failure)
**keeps the PREVIOUS valid cached value** + emits a WARN log; it does
NOT silently regress to in-tree defaults. The defaults fire only on a
cold start with a missing-or-malformed YAML.

The five loaders share the same machinery (``_yaml_cache.MtimeCachedYamlLoader``)
so adding a sixth surface in the future is a one-class-instance change.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from app.utils.yaml_cache import MtimeCachedYamlLoader, register_loader

logger = logging.getLogger(__name__)


_DATA_DIR = Path(__file__).parent / "data"
_VENDOR_YAML = _DATA_DIR / "vendor_prefixes.yaml"
_PATTERNS_YAML = _DATA_DIR / "firmware_patterns.yaml"
_BT_QCA_CODENAMES_YAML = _DATA_DIR / "bt_qca_codenames.yaml"
_BT_BANNER_CVE_PINS_YAML = _DATA_DIR / "bt_banner_cve_pins.yaml"
_BT_REALTEK_PROJECT_IDS_YAML = _DATA_DIR / "bt_realtek_project_ids.yaml"

# Recognised BT banner parser families. Used by the H2 banner-pin loader
# to validate that ``family:`` entries reference a real parser verdict.
# Sourced from parsers/bt_firmware_banner.py — keep in sync if a new
# family is added there.
_BT_PARSER_FAMILIES: frozenset[str] = frozenset(
    {"qca_rome", "broadcom_hcd", "mediatek_bt", "realtek_bt"}
)

# Canonical vendor prefixes Wairz ships with — classifier.py reads this set
# (via the legacy ``VENDORS`` import) to gate downstream normalization. The
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


# ---------------------------------------------------------------------------
# Public dataclasses returned by accessors.
# ---------------------------------------------------------------------------


@dataclass
class PatternMatch:
    """Result of matching a filename against firmware_patterns.yaml.

    ``format`` defaults to ``raw_bin`` so callers can always pass it to
    the ``Classification`` dataclass without None-checking.
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
    partition tree, the path-context matcher rescues it into a specific
    category. See classifier._classify_by_path_context for the
    integration point.
    """

    vendor: str  # "unknown" → keep filename-inferred vendor
    category: str
    product: str | None
    confidence: str  # high | medium | low
    priority: int = 0


@dataclass(frozen=True)
class _VendorTable:
    """Combined vendor data: canonical set + alias map + display map."""

    canonical: frozenset[str]
    aliases: dict[str, str]
    display: dict[str, str]


# ---------------------------------------------------------------------------
# Parser functions — each takes the raw YAML dict and returns the typed
# value the loader will cache. Raises on structural issues; per-entry
# skips are logged + counted but the whole load succeeds.
# ---------------------------------------------------------------------------


def _parse_vendors_data(raw: dict) -> _VendorTable:
    """Parse vendor_prefixes.yaml into a _VendorTable.

    Always seeds the in-tree ``_CORE_VENDORS`` set so downstream code can
    rely on those being present even if an operator deletes them from
    the YAML. Display map gets a few hard-coded fallbacks for the same
    reason.
    """
    entries = raw.get("vendors") or []
    if not isinstance(entries, list):
        raise ValueError("'vendors' must be a list")

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
    display.setdefault("nvidia", "NVIDIA Corporation")
    display.setdefault("realtek", "Realtek Semiconductor Corp.")
    display.setdefault("unknown", "Unknown Vendor")

    return _VendorTable(
        canonical=frozenset(canonical),
        aliases=alias_map,
        display=display,
    )


_PatternEntry = tuple[re.Pattern[str], PatternMatch]


def _parse_patterns_data(raw: dict) -> list[_PatternEntry]:
    """Parse firmware_patterns.yaml::patterns into compiled regex list.

    Per-entry validation failures (missing field, regex compile error)
    are logged + skipped — the load still succeeds with the other
    entries. Whole-load failure (non-list 'patterns') raises ValueError.
    """
    raw_patterns = raw.get("patterns") or []
    if not isinstance(raw_patterns, list):
        raise ValueError("'patterns' must be a list")

    compiled: list[_PatternEntry] = []
    skipped = 0
    for idx, entry in enumerate(raw_patterns):
        if not isinstance(entry, dict):
            skipped += 1
            continue
        pat = entry.get("pattern")
        vendor = entry.get("vendor")
        category = entry.get("category")
        if not (
            isinstance(pat, str)
            and isinstance(vendor, str)
            and isinstance(category, str)
        ):
            logger.warning(
                "patterns_loader: entry #%d missing required field "
                "(pattern/vendor/category)",
                idx,
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
        fmt_str = (
            str(fmt).strip()
            if isinstance(fmt, str) and fmt.strip()
            else "raw_bin"
        )

        product = entry.get("product")
        product_str = (
            str(product).strip()
            if isinstance(product, str) and product.strip()
            else None
        )

        source = entry.get("source")
        source_str = (
            str(source).strip()
            if isinstance(source, str) and source.strip()
            else None
        )

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
            "patterns_loader: parsed %d patterns (%d skipped due to errors)",
            len(compiled),
            skipped,
        )
    return compiled


_PathContextEntry = tuple[
    re.Pattern[str], re.Pattern[str] | None, PathContextMatch
]


def _parse_path_contexts_data(raw: dict) -> list[_PathContextEntry]:
    """Parse firmware_patterns.yaml::path_contexts into compiled list.

    Returns ``[(path_regex, filename_regex_or_None, PathContextMatch), ...]``
    sorted by descending priority so the most specific rules fire first.
    """
    raw_entries = raw.get("path_contexts") or []
    if not isinstance(raw_entries, list):
        raise ValueError("'path_contexts' must be a list")

    compiled: list[_PathContextEntry] = []
    skipped = 0
    for idx, entry in enumerate(raw_entries):
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
                "patterns_loader: path_contexts entry #%d missing required "
                "field (path_pattern/vendor/category)",
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
                    "patterns_loader: path_contexts entry #%d "
                    "filename_pattern must be a string",
                    idx,
                )
                skipped += 1
                continue
            try:
                filename_rx = re.compile(filename_pat, re.IGNORECASE)
            except re.error as exc:
                logger.warning(
                    "patterns_loader: path_contexts entry #%d "
                    "filename_pattern %r failed to compile: %s",
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
    # sort keys ensure deterministic ordering when priorities tie.
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
            "patterns_loader: parsed %d path_contexts (%d skipped due to errors)",
            len(compiled),
            skipped,
        )
    return compiled


# ---------------------------------------------------------------------------
# BT QCA codename table (bt_qca_codenames.yaml).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BtCodenameTable:
    """Loaded view of bt_qca_codenames.yaml.

    Frozen so accessors can return shared instances safely. Field shapes
    are chosen to match the parser's existing consumption (dict for fast
    .get / `in`; frozenset for chipset membership; tuple[bytes,...] for
    byte-wise ``in data`` membership against raw firmware bytes).
    """

    codename_map: dict[str, str] = field(default_factory=dict)
    codename_display: dict[str, str] = field(default_factory=dict)
    codename_also_covers: dict[str, frozenset[str]] = field(default_factory=dict)
    codename_families: dict[str, tuple[str, ...]] = field(default_factory=dict)
    braktooth_chipsets: frozenset[str] = frozenset()
    mtk_known_chips: tuple[bytes, ...] = ()


# In-tree defaults — fallback when bt_qca_codenames.yaml is missing or
# malformed AND no prior valid load has occurred. Mirrors the shipping
# YAML; keeping these as the literal fallback means a future YAML
# schema regression cannot regress the parser to silently lose all QCA
# codename / MediaTek chip coverage.
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


def _parse_bt_codename_data(raw: dict) -> BtCodenameTable:
    """Parse a validated YAML dict into a BtCodenameTable.

    Raises ``ValueError`` on any structural issue.
    """
    codenames_raw = raw.get("codenames")
    if not isinstance(codenames_raw, list):
        raise ValueError("'codenames' must be a list")

    codename_map: dict[str, str] = {}
    codename_display: dict[str, str] = {}
    codename_also_covers: dict[str, frozenset[str]] = {}
    codename_families: dict[str, tuple[str, ...]] = {}

    for idx, entry in enumerate(codenames_raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"codenames[{idx}] must be a mapping, got {type(entry).__name__}"
            )
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
                str(f).strip()
                for f in fams
                if isinstance(f, str) and f.strip()
            )
            if families:
                codename_families[cn] = families

    bt_raw = raw.get("braktooth_chipsets")
    if bt_raw is not None and not isinstance(bt_raw, list):
        raise ValueError("'braktooth_chipsets' must be a list")
    braktooth_chipsets = frozenset(
        str(c).strip().lower()
        for c in (bt_raw or [])
        if isinstance(c, str) and c.strip()
    )

    mtk_raw = raw.get("mtk_known_chips")
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


# ---------------------------------------------------------------------------
# Realtek BT chipset table (bt_realtek_project_ids.yaml).
#
# project_id → chipset mapping per upstream Linux btrtl.c's ic_id_table[]
# + project_id_to_lmp_subver[]. The project_id itself sits in trailing
# TLV records at the firmware blob's TAIL (opcode=0, length=1, data=PID)
# — NOT at offset 8 as a uint32 (a common misreading; offset 8 is the
# fw_version field per rtl_epatch_header). The parser reads BOTH the
# head (for the "Realtech"/"RTBTCore" magic + fw_version) AND the tail
# (reverse-TLV scan for project_id), then looks up the chipset here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RealtekChipsetEntry:
    """One row from bt_realtek_project_ids.yaml.

    Adaptability note: ``lmp_subver`` / ``hci_rev`` / ``hci_ver`` are
    OPTIONAL — early-family chipsets (RTL8703B project_id=7) ship
    without populated HCI revision metadata. Parser code treats
    missing fields as "no claim", not "no match".
    """

    project_id: int
    chipset: str
    display: str | None
    lmp_subver: int | None
    hci_rev: int | None
    hci_ver: int | None
    bus: str | None
    family: str | None
    filename_fw: str | None
    filename_config: str | None


# In-tree defaults — fallback when bt_realtek_project_ids.yaml is
# missing or malformed AND no prior valid load has occurred. Subset
# of the shipping YAML; the parser still classifies firmware as
# vendor=realtek even when this table is empty (the magic + tail-TLV
# scan stand independent), but the chipset_target field stays None.
_REALTEK_CHIPSET_DEFAULTS: tuple[RealtekChipsetEntry, ...] = (
    RealtekChipsetEntry(
        project_id=9,
        chipset="rtl8723d",
        display="RTL8723D / 8723DS",
        lmp_subver=0x8723,
        hci_rev=0x0d,
        hci_ver=0x08,
        bus="both",
        family="rtl87xx",
        filename_fw="rtl8723d_fw.bin",
        filename_config="rtl8723d_config.bin",
    ),
    RealtekChipsetEntry(
        project_id=14,
        chipset="rtl8761b",
        display="RTL8761B / 8761BTV / 8761BU",
        lmp_subver=0x8761,
        hci_rev=0x0b,
        hci_ver=0x0a,
        bus="both",
        family="rtl87xx",
        filename_fw="rtl8761b_fw.bin",
        filename_config="rtl8761b_config.bin",
    ),
    RealtekChipsetEntry(
        project_id=10,
        chipset="rtl8821c",
        display="RTL8821C / 8821CS",
        lmp_subver=0x8821,
        hci_rev=0x0c,
        hci_ver=0x08,
        bus="both",
        family="rtl87xx",
        filename_fw="rtl8821c_fw.bin",
        filename_config="rtl8821c_config.bin",
    ),
    RealtekChipsetEntry(
        project_id=18,
        chipset="rtl8852a",
        display="RTL8852A (8852AU)",
        lmp_subver=0x8852,
        hci_rev=0x0a,
        hci_ver=0x0b,
        bus="usb",
        family="rtl88xx",
        filename_fw="rtl8852au_fw.bin",
        filename_config="rtl8852au_config.bin",
    ),
    RealtekChipsetEntry(
        project_id=20,
        chipset="rtl8852b",
        display="RTL8852B (8852BU) / 8852BS",
        lmp_subver=0x8852,
        hci_rev=0x0b,
        hci_ver=0x0b,
        bus="both",
        family="rtl88xx",
        filename_fw="rtl8852bu_fw.bin",
        filename_config="rtl8852bu_config.bin",
    ),
    RealtekChipsetEntry(
        project_id=25,
        chipset="rtl8852c",
        display="RTL8852C (8852CU)",
        lmp_subver=0x8852,
        hci_rev=0x0c,
        hci_ver=0x0c,
        bus="usb",
        family="rtl88xx",
        filename_fw="rtl8852cu_fw.bin",
        filename_config="rtl8852cu_config.bin",
    ),
)


def _coerce_hex_int(value: object, field_name: str, idx: int) -> int | None:
    """Coerce YAML scalar → int. Accepts hex strings ("0x8723") AND ints
    AND None. Raises ValueError on any other shape so operator typos
    surface loudly."""
    if value is None:
        return None
    if isinstance(value, bool):
        # PyYAML may parse "yes/no" as bool — reject (int gate is wrong shape).
        raise ValueError(
            f"chipsets[{idx}]: {field_name!r} must be int or 0xHEX string, "
            f"got bool"
        )
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            return int(s, 10)
        except ValueError as exc:
            raise ValueError(
                f"chipsets[{idx}]: {field_name!r} unparseable as int: {value!r}"
            ) from exc
    raise ValueError(
        f"chipsets[{idx}]: {field_name!r} must be int / 0xHEX string / null, "
        f"got {type(value).__name__}"
    )


def _parse_realtek_data(raw: dict) -> tuple[RealtekChipsetEntry, ...]:
    """Parse bt_realtek_project_ids.yaml into a tuple of RealtekChipsetEntry."""
    chipsets_raw = raw.get("chipsets")
    if not isinstance(chipsets_raw, list):
        raise ValueError("'chipsets' must be a list")

    entries: list[RealtekChipsetEntry] = []
    seen_project_ids: set[int] = set()
    for idx, entry in enumerate(chipsets_raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"chipsets[{idx}] must be a mapping, got {type(entry).__name__}"
            )
        pid_raw = entry.get("project_id")
        if not isinstance(pid_raw, int) or isinstance(pid_raw, bool):
            raise ValueError(
                f"chipsets[{idx}]: 'project_id' must be int, got {pid_raw!r}"
            )
        if pid_raw < 0 or pid_raw > 255:
            # btrtl.c project_ids are small ints — anything outside 0-255
            # is almost certainly a typo (fw_version mistakenly placed
            # here).
            raise ValueError(
                f"chipsets[{idx}]: 'project_id' out of range (0-255): {pid_raw}"
            )
        if pid_raw in seen_project_ids:
            raise ValueError(
                f"chipsets[{idx}]: duplicate project_id {pid_raw}"
            )
        seen_project_ids.add(pid_raw)

        chipset = entry.get("chipset")
        if not (isinstance(chipset, str) and chipset.strip()):
            raise ValueError(
                f"chipsets[{idx}]: 'chipset' missing or empty"
            )

        display_raw = entry.get("display")
        display = (
            display_raw.strip()
            if isinstance(display_raw, str) and display_raw.strip()
            else None
        )

        lmp_subver = _coerce_hex_int(
            entry.get("lmp_subver"), "lmp_subver", idx
        )
        hci_rev = _coerce_hex_int(entry.get("hci_rev"), "hci_rev", idx)
        hci_ver = _coerce_hex_int(entry.get("hci_ver"), "hci_ver", idx)

        bus_raw = entry.get("bus")
        bus = (
            bus_raw.strip().lower()
            if isinstance(bus_raw, str) and bus_raw.strip()
            else None
        )
        if bus is not None and bus not in {"usb", "uart", "both"}:
            raise ValueError(
                f"chipsets[{idx}]: 'bus' must be 'usb', 'uart', 'both', "
                f"or null; got {bus_raw!r}"
            )

        family_raw = entry.get("family")
        family = (
            family_raw.strip()
            if isinstance(family_raw, str) and family_raw.strip()
            else None
        )

        filename_fw_raw = entry.get("filename_fw")
        filename_fw = (
            filename_fw_raw.strip()
            if isinstance(filename_fw_raw, str) and filename_fw_raw.strip()
            else None
        )

        filename_config_raw = entry.get("filename_config")
        filename_config = (
            filename_config_raw.strip()
            if isinstance(filename_config_raw, str) and filename_config_raw.strip()
            else None
        )

        entries.append(
            RealtekChipsetEntry(
                project_id=pid_raw,
                chipset=chipset.strip().lower(),
                display=display,
                lmp_subver=lmp_subver,
                hci_rev=hci_rev,
                hci_ver=hci_ver,
                bus=bus,
                family=family,
                filename_fw=filename_fw,
                filename_config=filename_config,
            )
        )

    return tuple(entries)


# ---------------------------------------------------------------------------
# Banner-pin → CVE rules (bt_banner_cve_pins.yaml).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BannerCveEntry:
    """One CVE attached to a banner-pin rule."""

    cve_id: str
    severity: str
    rationale: str
    subcomponent: str = "bluetooth"
    confidence: str = "high"
    reference: str | None = None


@dataclass(frozen=True)
class BannerCvePin:
    """One banner-pin rule loaded from bt_banner_cve_pins.yaml."""

    pin_id: str
    description: str
    family: str | None
    codename_in: frozenset[str] | None
    chipset_target_in: frozenset[str] | None
    banner_re: re.Pattern[str] | None
    build_date_before: date | None
    build_id_lt: int | None
    signed_eq: str | None
    cves: tuple[BannerCveEntry, ...]


# In-tree default — fallback when bt_banner_cve_pins.yaml is missing or
# malformed AND no prior valid load has occurred. Mirrors the shipping
# YAML's first pin (BRAKTOOTH Qualcomm DoS — CVE-2021-30348).
#
# CRITICAL: per Reviewer B 2026-05-16 + 2026-05-17 audits, the ONLY
# correct per-NVD-CPE Qualcomm BrakTooth-DoS CVE is **CVE-2021-30348**
# (CVSS 6.5, Qualcomm CNA). CVE-2021-28139 (ESP32 RCE), CVE-2021-34147
# (Cypress WICED), CVE-2021-31609 (Silicon Labs iWRAP), and CVE-2021-31612
# (Zhuhai Jieli) appear in the ASSET BrakTooth disclosure batch but their
# NVD CPE lists do NOT include Qualcomm chipsets — pinning them under a
# qca_rome family pin would replicate the BTFM→Broadcom misattribution
# class. NEVER add a non-Qualcomm-CNA CVE under a qca_rome family pin
# without an explicit NVD-CPE-verifying citation.
_BANNER_CVE_PIN_DEFAULTS: tuple[BannerCvePin, ...] = (
    BannerCvePin(
        pin_id="qualcomm-braktooth-qca-rome-dos-cve-2021-30348",
        description=(
            "Qualcomm BrakTooth LLM utility-timer DoS (CVE-2021-30348) "
            "on Rome WCN3xx0 BT firmware"
        ),
        family="qca_rome",
        codename_in=None,
        chipset_target_in=_BT_CODENAME_DEFAULTS.braktooth_chipsets,
        banner_re=None,
        build_date_before=None,
        build_id_lt=None,
        signed_eq=None,
        cves=(
            BannerCveEntry(
                cve_id="CVE-2021-30348",
                severity="medium",
                rationale=(
                    "BT firmware banner '{banner}' confirms {chipset_upper} "
                    "(QCA Rome family). Per NVD's CPE list (vendor=qualcomm), "
                    "CVE-2021-30348 is the Qualcomm BrakTooth-class LLM "
                    "utility-timer availability DoS affecting WCN3950/3990/"
                    "3991/3998 (plus WCN6750, QCA6390, and other Snapdragon "
                    "SoCs). Disclosed in the ASSET BrakTooth research "
                    "(Garbelini et al. 2021); CNA=Qualcomm, CVSS 6.5."
                ),
                reference="https://nvd.nist.gov/vuln/detail/CVE-2021-30348",
            ),
        ),
    ),
)


def _parse_banner_cve_pin(idx: int, entry: dict) -> BannerCvePin:
    """Validate + convert a single YAML pin entry into a BannerCvePin."""
    if not isinstance(entry, dict):
        raise ValueError(
            f"pins[{idx}] must be a mapping, got {type(entry).__name__}"
        )

    pin_id = entry.get("id")
    description = entry.get("description")
    if not (isinstance(pin_id, str) and pin_id.strip()):
        raise ValueError(f"pins[{idx}]: 'id' missing or empty")
    if not (isinstance(description, str) and description.strip()):
        raise ValueError(f"pins[{idx}] {pin_id!r}: 'description' missing or empty")

    family = entry.get("family")
    if family is not None:
        if not isinstance(family, str) or family.strip() not in _BT_PARSER_FAMILIES:
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'family' must be one of "
                f"{sorted(_BT_PARSER_FAMILIES)}; got {family!r}"
            )
        family = family.strip()

    codename_in_raw = entry.get("codename_in")
    codename_in: frozenset[str] | None = None
    if codename_in_raw is not None:
        if not isinstance(codename_in_raw, list):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'codename_in' must be a list"
            )
        codename_in = frozenset(
            str(c).strip().upper()
            for c in codename_in_raw
            if isinstance(c, str) and c.strip()
        )

    chipset_in_raw = entry.get("chipset_target_in")
    chipset_target_in: frozenset[str] | None = None
    if chipset_in_raw is not None:
        if not isinstance(chipset_in_raw, list):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'chipset_target_in' must be a list"
            )
        chipset_target_in = frozenset(
            str(c).strip().lower()
            for c in chipset_in_raw
            if isinstance(c, str) and c.strip()
        )

    banner_match_raw = entry.get("banner_match")
    banner_re: re.Pattern[str] | None = None
    if banner_match_raw is not None:
        if not isinstance(banner_match_raw, str):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'banner_match' must be a string regex"
            )
        try:
            banner_re = re.compile(banner_match_raw, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'banner_match' regex compile failed: {exc}"
            ) from exc

    build_date_before: date | None = None
    bdb_raw = entry.get("build_date_before")
    if bdb_raw is not None:
        if isinstance(bdb_raw, date):
            build_date_before = bdb_raw
        elif isinstance(bdb_raw, str):
            try:
                build_date_before = date.fromisoformat(bdb_raw.strip())
            except ValueError as exc:
                raise ValueError(
                    f"pins[{idx}] {pin_id!r}: 'build_date_before' must be "
                    f"YYYY-MM-DD; got {bdb_raw!r} ({exc})"
                ) from exc
        else:
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'build_date_before' must be a "
                f"date or YYYY-MM-DD string; got {type(bdb_raw).__name__}"
            )

    bil_raw = entry.get("build_id_lt")
    build_id_lt: int | None = None
    if bil_raw is not None:
        if isinstance(bil_raw, bool) or not isinstance(bil_raw, int):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'build_id_lt' must be an integer; "
                f"got {type(bil_raw).__name__}"
            )
        build_id_lt = bil_raw
        # Reject the unfilled-placeholder sentinel.
        if (
            bil_raw == 0
            and family is None
            and codename_in is None
            and chipset_target_in is None
            and banner_re is None
            and build_date_before is None
        ):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'build_id_lt: 0' with no other gate "
                "would never fire — likely an unfilled placeholder sentinel"
            )

    signed_eq_raw = entry.get("signed_eq")
    signed_eq: str | None = None
    if signed_eq_raw is not None:
        if not isinstance(signed_eq_raw, str):
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'signed_eq' must be a string; "
                f"got {type(signed_eq_raw).__name__}"
            )
        normalized = signed_eq_raw.strip().lower()
        if normalized not in {"signed", "unsigned"}:
            raise ValueError(
                f"pins[{idx}] {pin_id!r}: 'signed_eq' must be 'signed' or "
                f"'unsigned'; got {signed_eq_raw!r}"
            )
        signed_eq = normalized

    if all(
        cond is None
        for cond in (
            family,
            codename_in,
            chipset_target_in,
            banner_re,
            build_date_before,
            build_id_lt,
            signed_eq,
        )
    ):
        raise ValueError(
            f"pins[{idx}] {pin_id!r}: at least one match condition required "
            "(family / codename_in / chipset_target_in / banner_match / "
            "build_date_before / build_id_lt / signed_eq)"
        )

    # Reviewer B F-FORENSIC-10 CRITICAL 2026-05-18: a pin with ONLY
    # `family:` set (no chipset / codename / banner / version
    # narrowing) replicates the disclosure-batch antipattern. Future
    # operators writing `family: realtek_bt + cves: [CVE-2024-48290,
    # ...]` would fire RTL8762E SDK CVEs across ALL 17 Realtek
    # chipsets per the bt_realtek_project_ids.yaml map — even though
    # NVD CPE limits those CVEs to the RTL8762E variant only. Per
    # Reviewer B 2026-05-15..17 per-CVE NVD-CPE discipline applied
    # at the SCHEMA gate. The narrowing requirement IS the
    # antipattern-prevention.
    family_only = (
        family is not None
        and codename_in is None
        and chipset_target_in is None
        and banner_re is None
        and build_date_before is None
        and build_id_lt is None
        and signed_eq is None
    )
    if family_only:
        raise ValueError(
            f"pins[{idx}] {pin_id!r}: 'family' alone is insufficient — "
            "pins with `family:` set MUST also gate on at least one of "
            "codename_in / chipset_target_in / banner_match / "
            "build_date_before / build_id_lt / signed_eq to prevent "
            "disclosure-batch CVE over-attribution across the family's "
            "full chipset surface (Reviewer B 2026-05-18 invariant)"
        )

    cves_raw = entry.get("cves")
    if not isinstance(cves_raw, list) or not cves_raw:
        raise ValueError(
            f"pins[{idx}] {pin_id!r}: 'cves' must be a non-empty list"
        )
    cves: list[BannerCveEntry] = []
    for cidx, cve in enumerate(cves_raw):
        if not isinstance(cve, dict):
            raise ValueError(
                f"pins[{idx}] {pin_id!r} cves[{cidx}] must be a mapping"
            )
        cve_id = cve.get("id")
        severity = cve.get("severity")
        rationale = cve.get("rationale")
        if not (isinstance(cve_id, str) and cve_id.strip()):
            raise ValueError(
                f"pins[{idx}] {pin_id!r} cves[{cidx}]: 'id' missing or empty"
            )
        if not (isinstance(severity, str) and severity.strip()):
            raise ValueError(
                f"pins[{idx}] {pin_id!r} cves[{cidx}]: 'severity' missing or empty"
            )
        if not (isinstance(rationale, str) and rationale.strip()):
            raise ValueError(
                f"pins[{idx}] {pin_id!r} cves[{cidx}]: 'rationale' missing or empty"
            )
        subcomp = cve.get("subcomponent")
        subcomp_str = (
            subcomp.strip()
            if isinstance(subcomp, str) and subcomp.strip()
            else "bluetooth"
        )
        conf = cve.get("confidence")
        conf_str = (
            conf.strip().lower()
            if isinstance(conf, str) and conf.strip()
            else "high"
        )
        if conf_str not in {"high", "medium", "low"}:
            conf_str = "high"
        ref = cve.get("reference")
        ref_str = (
            ref.strip() if isinstance(ref, str) and ref.strip() else None
        )
        cves.append(
            BannerCveEntry(
                cve_id=cve_id.strip(),
                severity=severity.strip().lower(),
                rationale=rationale.strip(),
                subcomponent=subcomp_str,
                confidence=conf_str,
                reference=ref_str,
            )
        )

    return BannerCvePin(
        pin_id=pin_id.strip(),
        description=description.strip(),
        family=family,
        codename_in=codename_in,
        chipset_target_in=chipset_target_in,
        banner_re=banner_re,
        build_date_before=build_date_before,
        build_id_lt=build_id_lt,
        signed_eq=signed_eq,
        cves=tuple(cves),
    )


def _parse_banner_cve_pin_data(raw: dict) -> tuple[BannerCvePin, ...]:
    """Parse the full bt_banner_cve_pins.yaml dict → tuple of pins."""
    pins_raw = raw.get("pins")
    if not isinstance(pins_raw, list):
        raise ValueError("'pins' must be a list")
    pins: list[BannerCvePin] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(pins_raw):
        pin = _parse_banner_cve_pin(idx, entry)
        if pin.pin_id in seen_ids:
            raise ValueError(f"pins[{idx}]: duplicate id {pin.pin_id!r}")
        seen_ids.add(pin.pin_id)
        pins.append(pin)
    return tuple(pins)


# ---------------------------------------------------------------------------
# Summary callables — produce the human-readable count strings the mtime
# loader uses for its INFO log lines. Each must accept its loader's typed
# value and return a one-line string.
# ---------------------------------------------------------------------------


def _summary_vendors(t: _VendorTable) -> str:
    return (
        f"{len(t.canonical)} canonical vendors, "
        f"{len(t.aliases)} aliases, "
        f"{len(t.display)} display names"
    )


def _summary_patterns(p: list[_PatternEntry]) -> str:
    return f"{len(p)} patterns"


def _summary_path_contexts(p: list[_PathContextEntry]) -> str:
    return f"{len(p)} path_contexts entries"


def _summary_bt_codenames(t: BtCodenameTable) -> str:
    return (
        f"{len(t.codename_map)} codenames, "
        f"{len(t.braktooth_chipsets)} braktooth chipsets, "
        f"{len(t.mtk_known_chips)} mtk chips"
    )


def _summary_banner_pins(p: tuple[BannerCvePin, ...]) -> str:
    return f"{len(p)} pins, {sum(len(pin.cves) for pin in p)} CVEs total"


def _summary_realtek_chipsets(p: tuple[RealtekChipsetEntry, ...]) -> str:
    families: set[str] = {e.family for e in p if e.family}
    return (
        f"{len(p)} chipsets across {len(families)} families "
        f"({', '.join(sorted(families)) or 'none'})"
    )


# ---------------------------------------------------------------------------
# Module-level loader instances.
#
# All five share the MtimeCachedYamlLoader machinery from _yaml_cache.py.
# Each accessor function below delegates to ``.get()`` so an mtime change
# on disk is picked up within a single call.
# ---------------------------------------------------------------------------


# Path resolvers are lambdas that re-read the module-level constants on
# every call. This is load-bearing for test fixtures that
# ``monkeypatch.setattr(PL, '_BT_QCA_CODENAMES_YAML', tmp_path)`` — the
# loader's next ``get()`` sees the swapped path because the resolver
# looks up the module attribute fresh.
import sys as _sys

_this_module = _sys.modules[__name__]


def _resolve_vendor_yaml() -> Path:
    return _this_module._VENDOR_YAML  # type: ignore[attr-defined]


def _resolve_patterns_yaml() -> Path:
    return _this_module._PATTERNS_YAML  # type: ignore[attr-defined]


def _resolve_bt_qca_codenames_yaml() -> Path:
    return _this_module._BT_QCA_CODENAMES_YAML  # type: ignore[attr-defined]


def _resolve_bt_banner_cve_pins_yaml() -> Path:
    return _this_module._BT_BANNER_CVE_PINS_YAML  # type: ignore[attr-defined]


def _resolve_bt_realtek_project_ids_yaml() -> Path:
    return _this_module._BT_REALTEK_PROJECT_IDS_YAML  # type: ignore[attr-defined]


_VENDORS_LOADER: MtimeCachedYamlLoader[_VendorTable] = MtimeCachedYamlLoader(
    path=_resolve_vendor_yaml,
    parser=_parse_vendors_data,
    defaults=_VendorTable(
        canonical=_CORE_VENDORS,
        aliases={},
        # Adaptability seed (Reviewer C CC-1 2026-05-18): proactively
        # seed display names for chip vendors that already appear in
        # firmware_patterns.yaml or are likely operator-upload targets.
        # Each entry is zero-risk — display strings only, no behaviour
        # change. Operators uploading Allwinner / Rockchip / Marvell /
        # Espressif / Lattice / Xilinx etc. firmware get a real
        # display string instead of the title-cased prefix fallback.
        display={
            "qualcomm": "Qualcomm Technologies, Inc.",
            "mediatek": "MediaTek Inc.",
            "nvidia": "NVIDIA Corporation",
            "realtek": "Realtek Semiconductor Corp.",
            "samsung": "Samsung Electronics",
            "broadcom": "Broadcom Inc.",
            "cypress": "Cypress / Infineon Technologies",
            "apple": "Apple Inc.",
            "intel": "Intel Corporation",
            "hisilicon": "HiSilicon (Huawei Technologies)",
            "unisoc": "UNISOC (Spreadtrum)",
            "imagination": "Imagination Technologies",
            "arm": "Arm Limited",
            "ti": "Texas Instruments",
            "espressif": "Espressif Systems",
            "infineon": "Infineon Technologies AG",
            "nordic": "Nordic Semiconductor",
            "microchip": "Microchip Technology / Atmel",
            "allwinner": "Allwinner Technology",
            "rockchip": "Rockchip Electronics",
            "marvell": "Marvell Technology Group",
            "lattice": "Lattice Semiconductor",
            "xilinx": "Xilinx / AMD Adaptive Computing",
            "altera": "Altera / Intel FPGA",
            "renesas": "Renesas Electronics",
            "stmicro": "STMicroelectronics",
            "amd": "Advanced Micro Devices",
            "awinic": "Shanghai Awinic Technology",
            "aosp": "Android Open Source Project",
            "unknown": "Unknown Vendor",
        },
    ),
    name="patterns_loader",
    summary=_summary_vendors,
)

_PATTERNS_LOADER: MtimeCachedYamlLoader[list[_PatternEntry]] = MtimeCachedYamlLoader(
    path=_resolve_patterns_yaml,
    parser=_parse_patterns_data,
    defaults=[],
    name="patterns_loader",
    summary=_summary_patterns,
)

_PATH_CONTEXTS_LOADER: MtimeCachedYamlLoader[list[_PathContextEntry]] = (
    MtimeCachedYamlLoader(
        path=_resolve_patterns_yaml,
        parser=_parse_path_contexts_data,
        defaults=[],
        name="patterns_loader",
        summary=_summary_path_contexts,
    )
)

_BT_CODENAMES_LOADER: MtimeCachedYamlLoader[BtCodenameTable] = MtimeCachedYamlLoader(
    path=_resolve_bt_qca_codenames_yaml,
    parser=_parse_bt_codename_data,
    defaults=_BT_CODENAME_DEFAULTS,
    name="patterns_loader",
    summary=_summary_bt_codenames,
)

_BANNER_CVE_PINS_LOADER: MtimeCachedYamlLoader[tuple[BannerCvePin, ...]] = (
    MtimeCachedYamlLoader(
        path=_resolve_bt_banner_cve_pins_yaml,
        parser=_parse_banner_cve_pin_data,
        defaults=_BANNER_CVE_PIN_DEFAULTS,
        name="patterns_loader",
        summary=_summary_banner_pins,
    )
)

_REALTEK_LOADER: MtimeCachedYamlLoader[tuple[RealtekChipsetEntry, ...]] = (
    MtimeCachedYamlLoader(
        path=_resolve_bt_realtek_project_ids_yaml,
        parser=_parse_realtek_data,
        defaults=_REALTEK_CHIPSET_DEFAULTS,
        name="patterns_loader",
        summary=_summary_realtek_chipsets,
    )
)


# MCP observability — register each loader under a stable kebab-case
# surface name so the ``list_extension_points`` MCP tool can enumerate
# them at call time. Adding a future YAML surface requires only one
# new register_loader() line; the tool itself has no hard-coded list.
register_loader("vendor_prefixes", _VENDORS_LOADER)
register_loader("firmware_patterns", _PATTERNS_LOADER)
register_loader("firmware_patterns_contexts", _PATH_CONTEXTS_LOADER)
register_loader("bt_qca_codenames", _BT_CODENAMES_LOADER)
register_loader("bt_banner_cve_pins", _BANNER_CVE_PINS_LOADER)
register_loader("bt_realtek_project_ids", _REALTEK_LOADER)


# Backward-compat shims for the H1 + H2 unit tests that call
# ``_load_bt_qca_codenames.cache_clear()`` / ``_load_banner_cve_pins.cache_clear()``.
# The names match the previous @lru_cache function shapes so existing
# fixture code migrates without source edits.
_load_bt_qca_codenames = _BT_CODENAMES_LOADER
_load_banner_cve_pins = _BANNER_CVE_PINS_LOADER
_load_realtek_chipsets = _REALTEK_LOADER


def clear_all_caches() -> None:
    """Pytest helper: reset every loader's cache (mtime + cached value).

    Use in tests that swap YAML paths via monkeypatch.setattr against the
    module-level ``_*_YAML`` constants. The reset forces a fresh load
    against whatever path the loaders now point to.
    """
    _VENDORS_LOADER.cache_clear()
    _PATTERNS_LOADER.cache_clear()
    _PATH_CONTEXTS_LOADER.cache_clear()
    _BT_CODENAMES_LOADER.cache_clear()
    _BANNER_CVE_PINS_LOADER.cache_clear()
    _REALTEK_LOADER.cache_clear()


# ---------------------------------------------------------------------------
# Module-level snapshots — captured once at import for backward-compat.
#
# Runtime callers that need hot-reload behaviour MUST use the accessor
# functions (``resolve_vendor`` / ``match`` / ``match_path_context`` /
# ``get_*``) rather than these module-level constants. The constants are
# preserved for downstream code that imports them by name (e.g.
# classifier.py re-exports VENDORS for UI consumers).
# ---------------------------------------------------------------------------
_initial_vendors = _VENDORS_LOADER.get()
VENDORS: frozenset[str] = _initial_vendors.canonical
_VENDOR_ALIASES: dict[str, str] = _initial_vendors.aliases
VENDOR_DISPLAY: dict[str, str] = _initial_vendors.display


# ---------------------------------------------------------------------------
# Accessors — read fresh state on every call so YAML edits land within
# one accessor call. Pair with the per-load INFO logs to give operators
# definitive visibility into "did my YAML edit take effect?".
# ---------------------------------------------------------------------------


def resolve_vendor(name: str | None) -> str:
    """Canonicalise a vendor token via the alias map."""
    if not name:
        return "unknown"
    key = name.strip().lower()
    table = _VENDORS_LOADER.get()
    return table.aliases.get(key, key)


def get_vendors() -> frozenset[str]:
    """Current canonical vendor set (hot-reloaded from vendor_prefixes.yaml)."""
    return _VENDORS_LOADER.get().canonical


def get_vendor_display() -> dict[str, str]:
    """Current vendor → display-name mapping (hot-reloaded)."""
    return _VENDORS_LOADER.get().display


def match(path: str) -> PatternMatch | None:
    """Return the first PatternMatch whose regex matches the basename."""
    if not path:
        return None
    base = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not base:
        return None
    for rx, tmpl in _PATTERNS_LOADER.get():
        if rx.search(base):
            return tmpl
    return None


def match_path_context(path: str) -> PathContextMatch | None:
    """Return the highest-priority path-context match for ``path``."""
    if not path:
        return None
    norm = path.replace("\\", "/").lower()
    base = norm.rsplit("/", 1)[-1] if "/" in norm else norm
    if not base:
        return None
    for path_rx, filename_rx, tmpl in _PATH_CONTEXTS_LOADER.get():
        if not path_rx.search(norm):
            continue
        if filename_rx is not None and not filename_rx.search(base):
            continue
        return tmpl
    return None


def get_qca_codename_map() -> dict[str, str]:
    """3-letter QCA codename (UPPERCASE) → canonical primary chipset (lowercase)."""
    return _BT_CODENAMES_LOADER.get().codename_map


def get_qca_codename_display() -> dict[str, str]:
    """QCA codename → human-readable display name."""
    return _BT_CODENAMES_LOADER.get().codename_display


def get_qca_also_covers() -> dict[str, frozenset[str]]:
    """QCA codename → additional chipsets the same codename can ship on."""
    return _BT_CODENAMES_LOADER.get().codename_also_covers


def get_qca_codename_families() -> dict[str, tuple[str, ...]]:
    """QCA codename → generation tag tuples."""
    return _BT_CODENAMES_LOADER.get().codename_families


def get_braktooth_chipsets() -> frozenset[str]:
    """Chipsets in scope for the ASSET BrakTooth Qualcomm DoS subset."""
    return _BT_CODENAMES_LOADER.get().braktooth_chipsets


def get_mtk_chips() -> tuple[bytes, ...]:
    """MediaTek BT/WiFi chip-ID allowlist for content scanning."""
    return _BT_CODENAMES_LOADER.get().mtk_known_chips


def get_banner_cve_pins() -> tuple[BannerCvePin, ...]:
    """Banner-pin → CVE rule list, parsed + validated from YAML."""
    return _BANNER_CVE_PINS_LOADER.get()


def get_realtek_chipsets() -> tuple[RealtekChipsetEntry, ...]:
    """Realtek BT chipset table (hot-reloaded from bt_realtek_project_ids.yaml).

    Consumed by parsers/bt_firmware_banner.py's `_parse_realtek_bt` to
    map a project_id (read from trailing TLV records in the firmware
    blob) to a chipset / LMP subversion / HCI revision triple. Empty
    or missing YAML falls back to the in-tree `_REALTEK_CHIPSET_DEFAULTS`
    (6 chipsets covering the prompt's named variants RTL8723D / 8761B /
    8821C / 8852A/B/C).
    """
    return _REALTEK_LOADER.get()


def get_realtek_chipset_by_project_id(project_id: int) -> RealtekChipsetEntry | None:
    """Convenience lookup: project_id (small int 0-51 per btrtl.c) → entry.

    Returns None when the project_id is unknown to the current YAML
    (operators can extend without Python changes — edit
    bt_realtek_project_ids.yaml, save; the next parser invocation
    sees the new entry via mtime hot-reload).
    """
    for entry in _REALTEK_LOADER.get():
        if entry.project_id == project_id:
            return entry
    return None


__all__ = [
    "BannerCveEntry",
    "BannerCvePin",
    "BtCodenameTable",
    "PathContextMatch",
    "PatternMatch",
    "RealtekChipsetEntry",
    "VENDORS",
    "VENDOR_DISPLAY",
    "clear_all_caches",
    "get_banner_cve_pins",
    "get_braktooth_chipsets",
    "get_mtk_chips",
    "get_qca_also_covers",
    "get_qca_codename_display",
    "get_qca_codename_families",
    "get_qca_codename_map",
    "get_realtek_chipset_by_project_id",
    "get_realtek_chipsets",
    "get_vendor_display",
    "get_vendors",
    "match",
    "match_path_context",
    "resolve_vendor",
]
