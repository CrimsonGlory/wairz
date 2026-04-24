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
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services.cpe_dictionary_service import CpeDictionaryService
from app.services.hardware_firmware import kernel_vulns_index as kvi

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


def _load_known_firmware() -> list[dict]:
    """Load curated CVE families from YAML.  Cached in module scope."""
    if not _YAML_PATH.is_file():
        logger.warning("known_firmware.yaml missing at %s", _YAML_PATH)
        return []
    try:
        with _YAML_PATH.open("r") as f:
            data = yaml.safe_load(f)
        return data.get("families", []) if data else []
    except yaml.YAMLError as exc:
        logger.error("Failed to parse known_firmware.yaml: %s", exc)
        return []


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
        known = (blob.metadata_ or {}).get("known_vulnerabilities") or []
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
    """Tier 3 — curated YAML match."""
    matches: list[CveMatch] = []
    blob_vendor = (blob.vendor or "").lower()
    blob_category = (blob.category or "").lower()
    blob_version = blob.version or ""
    blob_chipset = blob.chipset_target or ""
    metadata_values = _stringify_metadata(blob.metadata_ or {})

    for fam in families:
        if fam.get("vendor", "").lower() != blob_vendor:
            continue
        if fam.get("category", "").lower() != blob_category:
            continue

        # Optional chipset regex
        chipset_re = fam.get("chipset_regex")
        if chipset_re:
            if not blob_chipset:
                continue
            if not re.search(chipset_re, blob_chipset, re.IGNORECASE):
                continue

        # Optional version regex — match against version OR any metadata value
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

        if not cves:
            # Advisory-only (e.g. kamakiri BROM — no CVE assigned)
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=(
                        "ADVISORY-"
                        + fam.get("name", "unknown").upper().replace(" ", "-")
                    ),
                    severity=severity,
                    cvss_score=cvss_score,
                    description=desc,
                    confidence="high",
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
                    confidence="high",
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
        svc = CpeDictionaryService()
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


async def _match_kernel_cpe(
    blobs: Sequence[HardwareFirmwareBlob],
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[CveMatch]:
    """Tier 4 — mirror linux-kernel component CVEs onto each kernel_module blob.

    Reads ``SbomComponent`` rows flagged as the Linux kernel (by name /
    type / ``kernel_*`` detection source) for this firmware, pulls the
    grype-supplied ``SbomVulnerability`` rows attached to those
    components, and projects a ``CveMatch`` onto every ``kernel_module``
    blob.  The persistence layer in :func:`match_firmware_cves` dedups on
    ``(blob_id, cve_id)``, so callers can safely re-run this tier.
    """
    kmod_blobs = [b for b in blobs if (b.category or "").lower() == "kernel_module"]
    if not kmod_blobs:
        return []

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
        return []

    comp_ids = [c.id for c in components]
    vuln_stmt = select(SbomVulnerability).where(
        SbomVulnerability.component_id.in_(comp_ids),
    )
    vulns = (await db.execute(vuln_stmt)).scalars().all()
    if not vulns:
        return []

    matches: list[CveMatch] = []
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
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=vuln.cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=description,
                    confidence="low",
                    tier="kernel_cpe",
                )
            )
    return matches


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

        kernel_version = (blob.metadata_ or {}).get("kernel_semver")
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


async def match_firmware_cves(
    firmware_id: uuid.UUID,
    db: AsyncSession,
    force_rescan: bool = False,
) -> list[CveMatch]:
    """Run the multi-tier matcher for all hardware firmware blobs of one firmware.

    - Skips blobs that already have cves in sbom_vulnerabilities unless
      force_rescan=True.
    - Persists matches to sbom_vulnerabilities with blob_id + match_tier +
      match_confidence.  Dedups on (firmware_id, blob_id, cve_id).
    """
    families = _load_known_firmware()

    # Fetch all blobs for this firmware
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware_id,
    )
    blobs = (await db.execute(stmt)).scalars().all()
    if not blobs:
        return []

    # Fetch existing hw-firmware CVEs for dedup key
    existing_stmt = select(
        SbomVulnerability.blob_id,
        SbomVulnerability.cve_id,
    ).where(
        SbomVulnerability.firmware_id == firmware_id,
        SbomVulnerability.blob_id.is_not(None),
    )
    existing = {(r[0], r[1]) for r in (await db.execute(existing_stmt)).all()}

    all_matches: list[CveMatch] = []
    # Tier 0 — parser-embedded version-pin fingerprints (per-blob metadata;
    # zero DB cost).  Runs before the per-blob Tier 1/2/3 loop so any CVE
    # a parser flagged during detection surfaces even when the curated
    # YAML, NVD keyword search, and CPE dictionary all miss.
    all_matches.extend(_match_parser_detected(blobs))
    for blob in blobs:
        # Tier 3 (always)
        all_matches.extend(_match_curated(blob, families))
        # Tier 1 / Tier 2 stubs
        all_matches.extend(await _match_chipset_cpe(blob))
        all_matches.extend(await _match_nvd_freetext(blob))

    # Tier 4 — kernel CPE (pulls grype's kernel-component CVEs onto each kmod blob)
    all_matches.extend(await _match_kernel_cpe(blobs, firmware_id, db))

    # Tier 5 — kernel subsystem (kernel.org vulns.git CNA feed)
    all_matches.extend(await _match_kernel_subsystem(blobs))

    # Persist matches
    inserted = 0
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
        inserted += 1

    await db.flush()
    logger.info(
        "HW firmware CVE matcher: %d blobs scanned, %d new matches (%d total)",
        len(blobs),
        inserted,
        len(all_matches),
    )
    return all_matches
