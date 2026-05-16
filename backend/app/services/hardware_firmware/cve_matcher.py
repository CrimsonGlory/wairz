"""Multi-tier CVE matcher for hardware firmware blobs.

Tier 0 — Parser-detected version-pin (high): parsers that can pin a CVE
  from a banner + bulletin (e.g. ``mediatek_geniezone`` flags
  CVE-2025-20707 when the GenieZone banner predates the February 2026
  PSB fix) populate ``blob.metadata_["known_vulnerabilities"]``.  This
  tier projects those records into CveMatch rows so the same persistence,
  UI read, and HBOM export paths apply.  Zero DB cost; per-blob iterable.
Tier 1 — Chipset CPE lookup (high confidence): if blob.chipset_target
  matches a CPE in the NVD dictionary, query by CPE.
Tier 2 — NVD free-text (medium): keyword search on "{vendor} {category}
  firmware" against NVD descriptions, filter by version substring.
Tier 3 — Curated YAML (high, human-vetted): load known_firmware.yaml
  and match each entry against the blob's vendor/category/version/chipset.
Tier 4 — Kernel CPE (medium): read the ``linux-kernel`` SbomComponent
  rows (produced by sbom_service ``_scan_kernel_from_vermagic`` and
  enriched by grype) and mirror their CVEs onto every kernel_module blob
  so each .ko surfaces the kernel-level findings instead of leaving them
  on the component alone.
Tier 5 — Kernel subsystem (high): map ``.ko`` basenames to their upstream
  kernel subsystem path (e.g. ``bluetooth.ko`` -> ``net/bluetooth/``) and
  query the Redis-backed :mod:`kernel_vulns_index` (kernel.org ``vulns.git``
  CNA feed) to produce per-subsystem, version-scoped CVE matches.  Fails
  soft — if the index is not populated, this tier returns ``[]``.

Results land in sbom_vulnerabilities with blob_id set and
match_confidence + match_tier populated.  Idempotent — dedups on
(firmware_id, blob_id, cve_id).
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func, insert, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services.cpe_dictionary_service import get_cpe_dictionary_service
from app.services.hardware_firmware import kernel_vulns_index as kvi
from app.utils.yaml_cache import MtimeCachedYamlLoader
from app.services.jsonb_normalizers import _normalize_hardware_firmware_blobs_metadata

logger = logging.getLogger(__name__)

_YAML_PATH = Path(__file__).parent / "known_firmware.yaml"


@dataclass
class CveMatch:
    """One CVE match against one blob."""

    blob_id: uuid.UUID
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str
    confidence: str  # high | medium | low
    tier: str  # parser_version_pin | chipset_cpe | nvd_freetext | curated_yaml | kernel_cpe | kernel_subsystem


@dataclass
class MatchResult:
    """Return value of :func:`match_firmware_cves`.

    The Tier 4 cartesian (kmod_blobs × kernel_cves) is persisted directly
    via batched SQLAlchemy Core inserts inside the matcher and is NOT
    materialised in :attr:`matches` — for Yocto-style firmware that
    matrix can reach 2.65 M rows and previously OOM'd the backend when
    held as Python ``CveMatch`` instances.  Callers that need the row /
    distinct-CVE counts for Tier 4 should read :attr:`tier4_rows` and
    :attr:`tier4_distinct_cves`.

    For back-compat, ``MatchResult`` proxies ``__iter__`` / ``__len__`` /
    ``__getitem__`` to :attr:`matches`, so existing patterns like
    ``for m in matches:`` and ``len(matches)`` keep working without
    seeing the streamed Tier 4 rows.
    """

    matches: list[CveMatch] = field(default_factory=list)
    tier4_rows: int = 0  # total tier-4 cartesian count seen this run (incl. dedup'd)
    tier4_inserted: int = 0  # NEW tier-4 rows actually persisted this run
    tier4_distinct_cves: frozenset[str] = field(default_factory=frozenset)
    inserted: int = 0  # total new sb_vuln rows persisted across all tiers

    def __iter__(self) -> Iterator[CveMatch]:
        return iter(self.matches)

    def __len__(self) -> int:
        return len(self.matches)

    def __getitem__(self, idx):  # type: ignore[no-untyped-def]
        return self.matches[idx]

    def __bool__(self) -> bool:
        return bool(self.matches) or self.tier4_rows > 0

    def __eq__(self, other: object) -> bool:
        # Back-compat: tests compare ``out == []``.  Treat empty
        # MatchResult as equal to an empty list so the contract holds.
        if isinstance(other, list):
            return self.matches == other and self.tier4_rows == 0
        return NotImplemented


def _parse_known_firmware_data(raw: dict) -> list[dict]:
    """Parse known_firmware.yaml's families list with schema validation.

    Performs the same lightweight WARN-only validation that the legacy
    ``_load_known_firmware`` did:
      - Advisory-only entries (``cves: []`` or missing ``cves``) MUST
        carry an ``advisory_id`` key (Reviewer A H1 2026-05-15).
      - ``advisory_id`` (when present) MUST be ≤20 chars to fit the
        column constraint.

    Malformed entries still load (so a YAML typo doesn't gate every CVE
    match) but the warning surfaces in logs for the operator to fix.

    Hot-reload contract: this parser is the per-load callable handed to
    ``MtimeCachedYamlLoader`` — it runs on first access AND on every
    subsequent disk-mtime-change. Raises only on FATAL whole-load
    issues (top-level 'families' not a list); per-entry issues become
    warnings.
    """
    families = raw.get("families", []) if raw else []
    if not isinstance(families, list):
        raise ValueError("'families' must be a list")

    seen_advisory_ids: set[str] = set()
    for idx, fam in enumerate(families):
        if not isinstance(fam, dict):
            continue
        cves = fam.get("cves") or []
        if not cves:
            adv_id = fam.get("advisory_id")
            if not adv_id:
                logger.warning(
                    "known_firmware.yaml entry #%d (%r) is advisory-only "
                    "(cves: []) but missing advisory_id — synthesized ID "
                    "may collide under VARCHAR(20) truncation",
                    idx,
                    fam.get("name", "<unnamed>"),
                )
            elif isinstance(adv_id, str):
                if len(adv_id) > 20:
                    logger.warning(
                        "known_firmware.yaml entry #%d advisory_id %r "
                        "exceeds VARCHAR(20) cap (length %d)",
                        idx,
                        adv_id,
                        len(adv_id),
                    )
                if adv_id in seen_advisory_ids:
                    logger.warning(
                        "known_firmware.yaml entry #%d duplicate "
                        "advisory_id %r — second entry will be deduped "
                        "by the (firmware_id, blob_id, cve_id) UNIQUE "
                        "constraint",
                        idx,
                        adv_id,
                    )
                seen_advisory_ids.add(adv_id)
    return families


def _summary_known_firmware(families: list[dict]) -> str:
    with_cves = sum(1 for f in families if isinstance(f, dict) and f.get("cves"))
    advisories = len(families) - with_cves
    return f"{len(families)} families ({with_cves} CVE-bearing, {advisories} advisory-only)"


# Hot-reloadable cache: operators editing known_firmware.yaml see new
# entries on the next cve-match cycle without a backend restart. The
# previous-state-keep-on-malformed-reload discipline (matching the H1+H2
# loaders in patterns_loader.py) means a YAML typo doesn't silently
# regress curated CVE matching to in-tree defaults.
#
# Path resolver looks up ``_YAML_PATH`` on the module fresh on every
# call so test fixtures that monkeypatch the constant swap the loader's
# target file without explicit cache_clear.
import sys as _sys

_this_module = _sys.modules[__name__]


def _resolve_yaml_path() -> Path:
    return _this_module._YAML_PATH  # type: ignore[attr-defined]


_KNOWN_FIRMWARE_LOADER: MtimeCachedYamlLoader[list[dict]] = MtimeCachedYamlLoader(
    path=_resolve_yaml_path,
    parser=_parse_known_firmware_data,
    defaults=[],
    name="cve_matcher",
    summary=_summary_known_firmware,
)


def _load_known_firmware() -> list[dict]:
    """Return the current curated CVE families list.

    Hot-reloaded from known_firmware.yaml on every call: stat-checks the
    file's ``st_mtime_ns``, returns cached state if unchanged, atomically
    re-parses if changed. Operators iterating CVE-family edits see new
    rows on the next cve-match invocation without a docker restart.
    """
    return _KNOWN_FIRMWARE_LOADER.get()


# MediaTek's monthly Product Security Bulletins tag every CVE with a
# Subcomponent (geniezone, atf, tinysys, wlan, modem, …). NVD descriptions
# for these CVEs consistently begin "In <subcomponent>, …" — extracting
# that tag lets downstream filtering narrow Tier 3/4 matches from
# vendor-wide to component-scoped. The match itself is not yet enforced;
# this utility exists so a future tightening can flip the switch without
# schema changes.
_SUBCOMPONENT_RE = re.compile(
    r"^In\s+([a-z][a-z0-9_]{1,40})\b",
    re.IGNORECASE,
)


def extract_subcomponent(description: str) -> str | None:
    """Extract a MediaTek-style subcomponent tag from an NVD description.

    Returns the lowercased tag (e.g. ``"geniezone"``, ``"atf"``,
    ``"wlan"``) or ``None`` when the description doesn't follow the
    ``"In <word>, …"`` convention.
    """
    if not description:
        return None
    m = _SUBCOMPONENT_RE.match(description.strip())
    return m.group(1).lower() if m else None


def _stringify_metadata(md: dict) -> list[str]:
    """Return all string values found in metadata (one level deep)."""
    out: list[str] = []
    for v in md.values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def _match_parser_detected(
    blobs: Sequence[HardwareFirmwareBlob],
) -> list[CveMatch]:
    """Tier 0 — CVEs fingerprinted inline by parsers (version-pin).

    Some parsers embed known-vulnerability records directly in
    ``blob.metadata_["known_vulnerabilities"]`` when the banner carries
    enough information to pin a CVE against a vendor bulletin's fixed
    version (e.g. ``mediatek_geniezone`` flags CVE-2025-20707 when the
    GZ banner predates the February 2026 PSB fix).  Each record is
    projected into a :class:`CveMatch` so the same dedup, persistence,
    UI-read, and HBOM export paths apply as the other tiers.

    Record shape (columnar mapping):
        cve_id      → CveMatch.cve_id        (required; skipped if absent)
        severity    → CveMatch.severity      (default "medium")
        confidence  → CveMatch.confidence    (default "high")
        rationale   → CveMatch.description   (default "")
    Unknown keys (``cwe``, ``subcomponent``, ``source``, ``reference``)
    stay in ``blob.metadata_`` and are not columnar.
    """
    matches: list[CveMatch] = []
    for blob in blobs:
        known = _normalize_hardware_firmware_blobs_metadata(blob.metadata_).get("known_vulnerabilities") or []
        if not isinstance(known, list):
            continue
        for v in known:
            if not isinstance(v, dict):
                continue
            cve_id = v.get("cve_id")
            if not cve_id:
                continue
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=cve_id,
                    severity=v.get("severity") or "medium",
                    cvss_score=None,
                    description=v.get("rationale") or "",
                    confidence=v.get("confidence") or "high",
                    tier="parser_version_pin",
                )
            )
    return matches


def _match_curated(
    blob: HardwareFirmwareBlob, families: list[dict]
) -> list[CveMatch]:
    """Tier 3 — curated YAML match.

    Vendor + (category OR category_regex) must match. Optional
    ``chipset_regex`` is **soft**: when ``blob.chipset_target`` is populated,
    the regex MUST match; when it's NULL, the blob still matches but the
    emitted ``CveMatch.confidence`` is downgraded to ``"medium"`` (signaling
    that the match relied on vendor+category alone, not chipset evidence).

    Soft chipset semantics were adopted 2026-05-15 after the Moto-G32 + G30
    audit found ``chipset_target`` populated on only 1 of 611 qualcomm
    blobs — strict mode produced zero qualcomm matches across the corpus
    despite 312 qualcomm blobs and a Bengal SM6225 SoC. The user-facing
    directive was "be more adaptable/versatile/flexible/resilient"; the
    confidence downgrade preserves the strict-mode signal in UI while
    surfacing the advisory-shape match.

    Optional ``category_regex`` lets one entry span related categories
    (e.g. ``"^(audio|dsp|modem)$"`` for chipset-wide subsystem advisories)
    without duplicating the family. When present, takes precedence over
    the exact ``category`` field; otherwise the exact-match path runs.

    Optional ``vendor_regex`` lets one entry span MULTIPLE vendors. When
    present, takes precedence over the exact ``vendor`` field; otherwise
    the exact-match path runs. Added 2026-05-16 after the BTFM correction
    + spec-level BT-advisory authoring (KNOB/BLUFFS/BIAS/BLURtooth) made
    it clear that ``vendor: unknown`` is a poor shape — those attacks
    apply to ANY Bluetooth firmware vendor (Qualcomm, Broadcom, Cypress,
    MediaTek, Realtek, Samsung). Using ``vendor_regex: "."`` matches
    every populated vendor, OR ``vendor_regex: "^(qualcomm|broadcom|
    cypress|mediatek)$"`` scopes to the known-spec-implementing set.
    Per Reviewer C (2026-05-16): keep ``vendor`` AND ``vendor_regex``
    as alternatives, not both — YAML clarity + author-intent precision.
    """
    matches: list[CveMatch] = []
    # Reviewer B F-FORENSIC-11 HIGH 2026-05-18: gate curated-tier
    # attribution on detection_confidence >= medium. A LOW-confidence
    # blob (e.g. Realtek BT parser's soft-fallback path: any
    # `[Rr]ealte[ck]` ASCII in the head window → vendor=realtek,
    # confidence=low) would otherwise produce CVE rows for ANY
    # `vendor: realtek` curated entry — including the RTL8762E SDK
    # CVEs that NVD attributes only to that specific chipset. The
    # confidence floor prevents soft-evidence vendor matches from
    # polluting curated CVE attribution.
    blob_conf = (blob.detection_confidence or "medium").lower()
    if blob_conf == "low":
        logger.debug(
            "cve-match: blob %s skipped curated-tier match "
            "(detection_confidence=low; soft-evidence vendor)",
            blob.id,
        )
        return matches

    blob_vendor = (blob.vendor or "").lower()
    blob_category = (blob.category or "").lower()
    blob_version = blob.version or ""
    blob_chipset = blob.chipset_target or ""
    metadata_values = _stringify_metadata(_normalize_hardware_firmware_blobs_metadata(blob.metadata_))

    for fam in families:
        # Vendor matching — exact OR vendor_regex (one of them required).
        vendor_re = fam.get("vendor_regex")
        if vendor_re:
            # vendor_regex MUST match SOMETHING — empty / null blob.vendor
            # is treated as no-match (avoids spec-level BT advisories
            # accidentally firing on uncategorized blobs).
            if not blob_vendor:
                continue
            if not re.search(vendor_re, blob_vendor, re.IGNORECASE):
                continue
        elif fam.get("vendor", "").lower() != blob_vendor:
            continue

        # Category matching — exact OR category_regex (one of them required).
        cat_re = fam.get("category_regex")
        if cat_re:
            if not re.search(cat_re, blob_category, re.IGNORECASE):
                continue
        elif fam.get("category", "").lower() != blob_category:
            continue

        # Optional chipset regex — SOFT by default: NULL blob.chipset_target
        # → match with confidence downgrade. Populated chipset_target → must
        # match.
        #
        # `strict_chipset: true` opts OUT of the soft fallback (Reviewer B
        # 2026-05-17 finding): for CVEs whose NVD CPE list is narrowly
        # vendor-attributed (e.g. CVE-2023-28581 covers FastConnect 6800/
        # 6900/7800 + QCA6391/6426/6436 + Snapdragon 865/870/8 Gen 1 — NOT
        # the broader Qualcomm BT+WiFi surface), the soft NULL-fallback
        # produces over-attribution on Qualcomm+wifi blobs whose
        # chipset_target is NULL but which clearly ship a different
        # chipset (G32 = WCN3950, G30 = WCN3990 — neither in the CPE list).
        # Use `strict_chipset: true` when the CPE list is RESTRICTIVE
        # enough that uncertainty about chipset_target should mean NO
        # match rather than a downgraded match.
        chipset_soft = False
        chipset_re = fam.get("chipset_regex")
        strict_chipset = bool(fam.get("strict_chipset", False))
        if chipset_re:
            if not blob_chipset:
                if strict_chipset:
                    continue
                chipset_soft = True
            elif not re.search(chipset_re, blob_chipset, re.IGNORECASE):
                continue

        # Optional version regex — match against version OR any metadata value.
        # Stays STRICT — when present, version evidence MUST be found.
        # Authors who want chipset-wide advisories should omit version_regex.
        version_re = fam.get("version_regex")
        if version_re:
            version_ok = False
            if blob_version and re.search(version_re, blob_version, re.IGNORECASE):
                version_ok = True
            else:
                for v in metadata_values:
                    if re.search(version_re, v, re.IGNORECASE):
                        version_ok = True
                        break
            if not version_ok:
                continue

        cves = fam.get("cves", [])
        severity = fam.get("severity", "medium")
        cvss_score = fam.get("cvss_score")
        desc = f"{fam.get('name', '(unnamed)')}: {fam.get('notes', '').strip()}"
        # Confidence: high when all soft gates were either absent or
        # satisfied with positive evidence; medium when a soft chipset
        # match propagated. Explicit "confidence" key on the family
        # overrides (rarely used; falls back to high).
        match_conf = fam.get("confidence") or ("medium" if chipset_soft else "high")

        if not cves:
            # Advisory-only (e.g. kamakiri BROM — no CVE assigned).
            # cve_id column is VARCHAR(20) — clip to fit. Rule #15: when
            # the YAML name is too long, the matcher truncates rather than
            # raising at INSERT time. Authors who need a distinct short tag
            # for collision avoidance can override via the family-level
            # ``advisory_id`` key (max 20 chars including any prefix).
            advisory_id = fam.get("advisory_id")
            if advisory_id:
                cve_id_advisory = str(advisory_id)[:20]
            else:
                raw_name = fam.get("name", "unknown").upper().replace(" ", "-")
                # Strip punctuation that would push past the cap before clip.
                raw_name = re.sub(r"[^A-Z0-9-]", "", raw_name)
                cve_id_advisory = ("ADVISORY-" + raw_name)[:20]
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=cve_id_advisory,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=desc,
                    confidence=match_conf,
                    tier="curated_yaml",
                )
            )
            continue

        for cve_id in cves:
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=desc,
                    confidence=match_conf,
                    tier="curated_yaml",
                )
            )
    return matches


async def _match_chipset_cpe(
    blob: HardwareFirmwareBlob,
) -> list[CveMatch]:
    """Tier 1 — chipset CPE lookup.  Best-effort (returns [] if CPE service unavailable).

    Phase 4 ships this as a stub: even with CPE service loaded, we don't
    yet query NVD for CPE -> CVE (that's a larger separate loop).  Kept as
    a structured stub so Phase 5/6 can extend without touching the matcher
    pipeline shape.
    """
    if not blob.chipset_target:
        return []
    try:
        svc = get_cpe_dictionary_service()
        if not await svc.ensure_loaded():
            return []
        # We validated the CPE path works; actual CPE -> CVE query is
        # deferred to a later phase so Phase 4 remains scoped.
    except Exception:
        logger.debug(
            "CPE dictionary unavailable for tier 1 match", exc_info=True
        )
        return []
    return []


async def _match_nvd_freetext(
    blob: HardwareFirmwareBlob,
) -> list[CveMatch]:
    """Tier 2 — NVD free-text keyword search.

    Current implementation: placeholder.  Real NVD keyword API is rate-
    limited and asynchronous; Phase 4 ships with Tier 3 active and Tiers
    1/2 as stubs that return [].  Users can run the existing SBOM-grype
    pipeline for userspace CVEs; hardware firmware CVEs come from Tier 3
    curated YAML.
    """
    return []


async def _iter_kernel_cve_rows(
    blobs: Sequence[HardwareFirmwareBlob],
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> AsyncIterator[CveMatch]:
    """Yield Tier 4 CveMatch rows one at a time without materialising the matrix.

    Pulls the kernel SbomComponent rows + their SbomVulnerability rows once
    (small, bounded), then yields kmod_blob × cve cross-products one at a
    time.  Memory cost is O(kernel_cves) for the source, not O(kernel_cves
    × kmod_blobs) for the cross-product.  Used both by the back-compat
    list-returning :func:`_match_kernel_cpe` and the streaming-persist
    path in :func:`match_firmware_cves`.
    """
    kmod_blobs = [b for b in blobs if (b.category or "").lower() == "kernel_module"]
    if not kmod_blobs:
        return

    # Locate every linux-kernel SbomComponent for this firmware.  Match on
    # name (case-insensitive) plus a loose "operating-system" type or any
    # detection source beginning with ``kernel_``.
    name_lower = func.lower(SbomComponent.name)
    comp_stmt = select(SbomComponent).where(
        SbomComponent.firmware_id == firmware_id,
        name_lower.in_(("linux-kernel", "linux_kernel", "linux")),
        or_(
            SbomComponent.type == "operating-system",
            SbomComponent.detection_source.like("kernel_%"),
        ),
    )
    components = (await db.execute(comp_stmt)).scalars().all()
    if not components:
        return

    comp_ids = [c.id for c in components]
    vuln_stmt = select(SbomVulnerability).where(
        SbomVulnerability.component_id.in_(comp_ids),
    )
    vulns = (await db.execute(vuln_stmt)).scalars().all()
    if not vulns:
        return

    for vuln in vulns:
        # cvss_score arrives as Decimal off the Numeric column; coerce so
        # downstream consumers see a float | None consistently with the
        # other tiers.
        cvss_score = float(vuln.cvss_score) if vuln.cvss_score is not None else None
        severity = vuln.severity or "unknown"
        description = vuln.description or ""
        # Tier 4 is, by design, the broadest kernel projection: every
        # kernel CVE gets mirrored onto every kernel_module row. That
        # mirror is useful for drill-down but produces a row count of
        # O(CVEs × modules) — 185k+ on Android builds. Flag as "low"
        # confidence so UIs can filter or down-rank these; Tier 5
        # (subsystem-verified) is the authoritative "high" tier.
        for blob in kmod_blobs:
            yield CveMatch(
                blob_id=blob.id,
                cve_id=vuln.cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=description,
                confidence="low",
                tier="kernel_cpe",
            )


async def _match_kernel_cpe(
    blobs: Sequence[HardwareFirmwareBlob],
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[CveMatch]:
    """Tier 4 — mirror linux-kernel component CVEs onto each kernel_module blob.

    Back-compat list-returning wrapper around :func:`_iter_kernel_cve_rows`.
    Production callers should use the async iterator + streaming persist
    in :func:`match_firmware_cves` instead — for large firmware (e.g.
    Yocto-style with 500+ kmods × 5000 kernel CVEs) the materialised list
    is the OOM driver.  This wrapper is kept for unit tests and any
    future ad-hoc tier-4 inspection.
    """
    return [m async for m in _iter_kernel_cve_rows(blobs, firmware_id, db)]


# ---------------------------------------------------------------------------
# Tier 5 — kernel subsystem (kernel.org vulns.git CNA feed)
# ---------------------------------------------------------------------------

# Basename -> upstream kernel subsystem path (with trailing slash).
# Covers ~80% of common Android / OpenWrt / mainline kernel modules.
_KMOD_TO_SUBSYSTEM: dict[str, str] = {
    # Networking — wireless
    "cfg80211": "net/wireless/",
    "mac80211": "net/mac80211/",
    "wlan": "drivers/net/wireless/",
    "ath9k": "drivers/net/wireless/ath/ath9k/",
    "ath9k_common": "drivers/net/wireless/ath/ath9k/",
    "ath9k_htc": "drivers/net/wireless/ath/ath9k/",
    "ath10k_core": "drivers/net/wireless/ath/ath10k/",
    "ath10k_pci": "drivers/net/wireless/ath/ath10k/",
    "ath10k_sdio": "drivers/net/wireless/ath/ath10k/",
    "ath11k": "drivers/net/wireless/ath/ath11k/",
    "ath11k_pci": "drivers/net/wireless/ath/ath11k/",
    "iwlwifi": "drivers/net/wireless/intel/iwlwifi/",
    "iwlmvm": "drivers/net/wireless/intel/iwlwifi/mvm/",
    "rtl8xxxu": "drivers/net/wireless/realtek/rtl8xxxu/",
    "rtw88_core": "drivers/net/wireless/realtek/rtw88/",
    "rtw89_core": "drivers/net/wireless/realtek/rtw89/",
    "brcmfmac": "drivers/net/wireless/broadcom/brcm80211/brcmfmac/",
    "brcmutil": "drivers/net/wireless/broadcom/brcm80211/",
    "bcmdhd": "drivers/net/wireless/broadcom/",
    # Networking — bluetooth
    "bluetooth": "net/bluetooth/",
    "btusb": "drivers/bluetooth/",
    "btbcm": "drivers/bluetooth/",
    "hci_uart": "drivers/bluetooth/",
    # Networking — core / netfilter
    "ipv4": "net/ipv4/",
    "ipv6": "net/ipv6/",
    "nf_tables": "net/netfilter/",
    "nft_ct": "net/netfilter/",
    "nft_chain_nat": "net/netfilter/",
    "nfnetlink": "net/netfilter/",
    "nfc": "net/nfc/",
    # Filesystems
    "exfat": "fs/exfat/",
    "f2fs": "fs/f2fs/",
    "ext4": "fs/ext4/",
    "fuse": "fs/fuse/",
    "btrfs": "fs/btrfs/",
    "overlay": "fs/overlayfs/",
    # Memory / core
    "zsmalloc": "mm/",
    "ksm": "mm/",
    "io_uring": "io_uring/",
    # GPU / DRM / display
    "mali_kbase": "drivers/gpu/arm/",
    "msm_drm": "drivers/gpu/drm/msm/",
    "msm": "drivers/gpu/drm/msm/",
    "hwcomposer": "drivers/gpu/drm/",
    "drm": "drivers/gpu/drm/",
    "drm_kms_helper": "drivers/gpu/drm/",
    # Android / vendor
    "binder_linux": "drivers/android/",
    "ashmem_linux": "drivers/android/",
    # USB / HID
    "usbhid": "drivers/hid/usbhid/",
    "uhid": "drivers/hid/",
    # Audio
    "snd_soc_core": "sound/soc/",
    "snd_usb_audio": "sound/usb/",
}


def _kmod_basename(blob_path: str | None) -> str:
    """Return a normalised module basename suitable for :data:`_KMOD_TO_SUBSYSTEM` lookup.

    Examples::

        "/vendor/lib/modules/bluetooth.ko"            -> "bluetooth"
        "/vendor/lib/modules/mali_kbase_mt6771_r49p0.ko" -> "mali_kbase"
        "/vendor/lib/modules/ath11k_pci.ko"           -> "ath11k_pci"
        "/vendor/lib/modules/nft_ct.ko"               -> "nft_ct"
    """
    if not blob_path:
        return ""
    name = blob_path.rsplit("/", 1)[-1]
    if name.endswith(".ko"):
        name = name[:-3]
    elif name.endswith(".ko.xz") or name.endswith(".ko.gz"):
        name = name.rsplit(".", 2)[0]

    # Anchor-based prefix normalisation.  Collapse vendor / chipset suffixes
    # so "mali_kbase_mt6771_r49p0" -> "mali_kbase", "nft_ct_*" -> "nft_ct".
    # Exact matches short-circuit before anchors so "ath11k_pci" stays intact.
    if name in _KMOD_TO_SUBSYSTEM:
        return name

    anchors = (
        "mali_kbase",
        "bcmdhd",
        "iwlmvm",
        "iwlwifi",
        "brcmfmac",
        "brcmutil",
        "rtw88",
        "rtw89",
    )
    for anchor in anchors:
        if name.startswith(anchor + "_") or name == anchor:
            return anchor
    return name


async def _match_kernel_subsystem(
    blobs: Sequence[HardwareFirmwareBlob],
) -> list[CveMatch]:
    """Tier 5 — per-subsystem kernel CVE attribution from kernel.org vulns.git.

    For each ``kernel_module`` blob:

    1. Normalise the ``.ko`` basename.
    2. Look up its subsystem path via :data:`_KMOD_TO_SUBSYSTEM`.
    3. Read ``metadata.kernel_semver`` (populated by the kmod parser).
    4. Query :mod:`kernel_vulns_index` for subsystem CVEs overlapping that
       kernel version.

    Fails soft — if the index isn't populated, this tier returns ``[]``
    and logs at INFO level.  Never raises.
    """
    kmod_blobs = [b for b in blobs if (b.category or "").lower() == "kernel_module"]
    if not kmod_blobs:
        return []

    # Fast-fail — don't block a CVE match on a cold-cache initial clone.
    try:
        populated = await kvi.is_populated()
    except Exception:  # noqa: BLE001
        logger.debug("Tier 5: kernel_vulns_index unavailable", exc_info=True)
        return []
    if not populated:
        logger.info("Tier 5 skipped: kernel_vulns_index not populated")
        return []

    matches: list[CveMatch] = []
    for blob in kmod_blobs:
        basename = _kmod_basename(blob.blob_path)
        subsystem = _KMOD_TO_SUBSYSTEM.get(basename)
        if not subsystem:
            continue

        kernel_version = _normalize_hardware_firmware_blobs_metadata(blob.metadata_).get("kernel_semver")
        if not kernel_version:
            continue

        try:
            cves = await kvi.lookup(subsystem, kernel_version)
        except Exception:  # noqa: BLE001
            logger.debug(
                "Tier 5 lookup failed for %s (%s @ %s)",
                basename,
                subsystem,
                kernel_version,
                exc_info=True,
            )
            continue

        for cve in cves:
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=cve["cve_id"],
                    severity=cve.get("severity", "medium") or "medium",
                    cvss_score=None,
                    description=cve.get("description") or "",
                    confidence="high",
                    tier="kernel_subsystem",
                )
            )
    return matches


_TIER4_BATCH_SIZE = 5000
"""Tier 4 batch size for the streaming Core INSERT path.

Uses ``db.execute(insert(M), [dicts])`` — asyncpg ``executemany`` —
which AVOIDS PostgreSQL's 32 767 bound-parameter cap (each row is
parameter-bound independently, not packed into one big statement).
A multi-row INSERT (``insert(M).values([dicts])``) would hit the
cap because each row contributes ~11 bound params — including the
Python-default ``id`` UUID — giving a ceiling of ~2 700 rows per
batch, and benchmark on the 2.65 M-row Yocto firmware showed the
multi-row form was no faster than executemany once index-update
cost dominated (5 b-trees × 2.65 M rows = 13 M index writes is the
bulk of the 375 s runtime).  The per-row cost is near-constant; for
work that needs to be faster than ~7 k rows/sec, the right fix is
the 202+polling pattern (Rule #29), not a batch-tuning microoptim.
"""


async def match_firmware_cves(
    firmware_id: uuid.UUID,
    db: AsyncSession,
    force_rescan: bool = False,
) -> MatchResult:
    """Run the multi-tier matcher for all hardware firmware blobs of one firmware.

    - Skips blobs that already have cves in sbom_vulnerabilities unless
      force_rescan=True.
    - Persists tiers 0/1/2/3/5 via ``db.add()`` + final ``db.flush()``.
      Persists tier 4 (the cartesian kmod_blobs × kernel_cves) via
      :func:`sqlalchemy.insert` with batched ``executemany`` —
      bypassing the ORM identity map, which previously held all 2.65 M
      objects in memory and OOM'd the backend container at the bulk
      flush.  Memory cost for tier 4 is now bounded to ~5 000 dicts
      (one batch's worth) regardless of input size.
    - Dedups on (firmware_id, blob_id, cve_id) across all tiers.
    - Returns a :class:`MatchResult` whose ``matches`` list excludes
      tier-4 rows; per-tier-4 stats live on :attr:`MatchResult.tier4_rows`
      and :attr:`MatchResult.tier4_distinct_cves`.
    """
    families = _load_known_firmware()

    # Fetch all blobs for this firmware
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware_id,
    )
    blobs = (await db.execute(stmt)).scalars().all()
    if not blobs:
        return MatchResult()

    # Fetch existing hw-firmware CVEs for dedup key
    existing_stmt = select(
        SbomVulnerability.blob_id,
        SbomVulnerability.cve_id,
    ).where(
        SbomVulnerability.firmware_id == firmware_id,
        SbomVulnerability.blob_id.is_not(None),
    )
    existing = {(r[0], r[1]) for r in (await db.execute(existing_stmt)).all()}

    kmod_count = sum(1 for b in blobs if (b.category or "").lower() == "kernel_module")
    logger.info(
        "cve-match: starting firmware_id=%s blobs=%d kernel_modules=%d existing=%d",
        firmware_id,
        len(blobs),
        kmod_count,
        len(existing),
    )

    all_matches: list[CveMatch] = []
    # Tier 0 — parser-embedded version-pin fingerprints (per-blob metadata;
    # zero DB cost).  Runs before the per-blob Tier 1/2/3 loop so any CVE
    # a parser flagged during detection surfaces even when the curated
    # YAML, NVD keyword search, and CPE dictionary all miss.
    t_start = time.monotonic()
    tier0 = _match_parser_detected(blobs)
    all_matches.extend(tier0)
    logger.info(
        "cve-match: tier-0 parser_detected done in %.2fs (%d matches)",
        time.monotonic() - t_start,
        len(tier0),
    )

    t_start = time.monotonic()
    tier123_count = 0
    for blob in blobs:
        # Tier 3 (always)
        m3 = _match_curated(blob, families)
        all_matches.extend(m3)
        tier123_count += len(m3)
        # Tier 1 / Tier 2 stubs
        m1 = await _match_chipset_cpe(blob)
        all_matches.extend(m1)
        tier123_count += len(m1)
        m2 = await _match_nvd_freetext(blob)
        all_matches.extend(m2)
        tier123_count += len(m2)
    logger.info(
        "cve-match: tier-1/2/3 loop done in %.2fs (%d matches across %d blobs)",
        time.monotonic() - t_start,
        tier123_count,
        len(blobs),
    )

    # Tier 4 — streaming Core insert (per-blob yield → batch → flush →
    # discard).  Replaces the previous "build a 2.65 M-element list,
    # ORM-add each one, then bulk-flush" pattern that exhausted process
    # memory at the flush step.  See cve-match-residual-oom-2026-04-25
    # intake for the diagnostic logs.
    logger.info(
        "cve-match: entering tier-4 streaming persist (kmod_blobs=%d, batch_size=%d)",
        kmod_count,
        _TIER4_BATCH_SIZE,
    )
    t_start = time.monotonic()
    tier4_total = 0  # cartesian count seen, regardless of dedup
    tier4_inserted = 0  # rows actually persisted this run
    tier4_distinct: set[str] = set()
    tier4_batch: list[dict] = []

    async def _flush_tier4_batch() -> None:
        if not tier4_batch:
            return
        # See ``_TIER4_BATCH_SIZE`` doc for the executemany-vs-multi-row
        # tradeoff.  Short version: executemany sidesteps the asyncpg
        # 32 767 bound-param cap and gives equivalent throughput once
        # index-update cost dominates.
        # Pass a shallow copy so the subsequent ``.clear()`` does not
        # mutate the list still referenced by AsyncMock test fixtures
        # (asyncpg itself doesn't care — execute completes before we
        # clear — but tests inspecting call_args_list would see [] post-clear).
        await db.execute(insert(SbomVulnerability), list(tier4_batch))
        await db.flush()
        tier4_batch.clear()

    async for m in _iter_kernel_cve_rows(blobs, firmware_id, db):
        # Count every cartesian projection so the router's
        # kernel_module_rows reflects the total matrix size, matching
        # pre-streaming semantics. Distinct CVE set captures the unique
        # kernel CVEs regardless of dedup status.
        tier4_total += 1
        tier4_distinct.add(m.cve_id)
        if (m.blob_id, m.cve_id) in existing and not force_rescan:
            continue
        tier4_batch.append(
            {
                "component_id": None,
                "firmware_id": firmware_id,
                "blob_id": m.blob_id,
                "cve_id": m.cve_id,
                "severity": m.severity,
                "cvss_score": m.cvss_score,
                "description": m.description,
                "match_confidence": m.confidence,
                "match_tier": m.tier,
                "resolution_status": "open",
            }
        )
        existing.add((m.blob_id, m.cve_id))
        tier4_inserted += 1
        if len(tier4_batch) >= _TIER4_BATCH_SIZE:
            await _flush_tier4_batch()
    await _flush_tier4_batch()
    logger.info(
        "cve-match: tier-4 streamed-persist done in %.2fs "
        "(%d cartesian rows, %d new persisted, %d distinct CVEs)",
        time.monotonic() - t_start,
        tier4_total,
        tier4_inserted,
        len(tier4_distinct),
    )

    # Tier 5 — kernel subsystem (kernel.org vulns.git CNA feed) — small
    # result set (~2 k rows on big firmware), keep ORM add pattern.
    logger.info("cve-match: entering tier-5 _match_kernel_subsystem (kmod_blobs=%d)", kmod_count)
    t_start = time.monotonic()
    tier5 = await _match_kernel_subsystem(blobs)
    logger.info(
        "cve-match: tier-5 done in %.2fs (%d matches)",
        time.monotonic() - t_start,
        len(tier5),
    )
    all_matches.extend(tier5)

    # Persist non-tier-4 matches via the existing ORM pattern.  These
    # tiers stay small (Yocto firmware: tier-0/1/2/3 ≈ 0 ; tier-5 ≈ 2 k)
    # so the identity-map cost is negligible.
    logger.info(
        "cve-match: entering non-tier-4 persist loop (all_matches=%d, existing dedup-keys=%d)",
        len(all_matches),
        len(existing),
    )
    t_start = time.monotonic()
    inserted_other = 0
    for m in all_matches:
        if (m.blob_id, m.cve_id) in existing and not force_rescan:
            continue
        vuln = SbomVulnerability(
            component_id=None,
            firmware_id=firmware_id,
            blob_id=m.blob_id,
            cve_id=m.cve_id,
            severity=m.severity,
            cvss_score=m.cvss_score,
            description=m.description,
            match_confidence=m.confidence,
            match_tier=m.tier,
            resolution_status="open",
        )
        db.add(vuln)
        existing.add((m.blob_id, m.cve_id))
        inserted_other += 1
    logger.info(
        "cve-match: non-tier-4 persist build-loop done in %.2fs (%d new sb_vuln rows queued)",
        time.monotonic() - t_start,
        inserted_other,
    )

    logger.info("cve-match: entering final db.flush() (queued=%d)", inserted_other)
    t_start = time.monotonic()
    await db.flush()
    logger.info(
        "cve-match: final db.flush() done in %.2fs",
        time.monotonic() - t_start,
    )

    inserted_total = inserted_other + tier4_inserted
    logger.info(
        "HW firmware CVE matcher: %d blobs scanned, %d new matches "
        "(%d non-tier-4 + %d tier-4 = %d total persisted; "
        "%d non-tier-4 returned; tier-4 cartesian seen=%d)",
        len(blobs),
        inserted_total,
        inserted_other,
        tier4_inserted,
        inserted_total,
        len(all_matches),
        tier4_total,
    )
    return MatchResult(
        matches=all_matches,
        tier4_rows=tier4_total,
        tier4_inserted=tier4_inserted,
        tier4_distinct_cves=frozenset(tier4_distinct),
        inserted=inserted_total,
    )
