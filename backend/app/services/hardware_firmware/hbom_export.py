"""CycloneDX v1.6 HBOM (Hardware Bill of Materials) exporter.

Builds a CycloneDX v1.6 HBOM from ``HardwareFirmwareBlob`` rows.  For each
detected blob we emit two linked components:

* a ``hardware`` component describing the chip
  (bom-ref = ``chip_<blob.id>``), and
* a ``firmware`` component describing the binary
  (bom-ref = ``fw_<blob.id>``), with ``hashes`` from ``blob_sha256`` and
  properties carrying category / format / partition / chipset / signing
  metadata.

Chip -> firmware is expressed via the top-level ``dependencies`` array
(``provides``: the chip "provides" the firmware) per the HBOM convention.

CVE data (``sbom_vulnerabilities`` rows with ``blob_id`` set) is emitted
in the top-level ``vulnerabilities`` array keyed off the firmware
component bom-refs.

The implementation is pure Python dict building — no shell, no
subprocess, no file I/O.
"""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.services.jsonb_normalizers import _normalize_hardware_firmware_blobs_metadata

# CycloneDX v1.6 severity enum — any value outside this set is coerced to
# "unknown" so downstream consumers validating against the schema don't
# reject the document.
_VALID_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "none",
    "unknown",
}


def _iso_utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with trailing ``Z`` suffix."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _build_hardware_component(blob: HardwareFirmwareBlob) -> dict:
    """Build a CycloneDX v1.6 ``device`` component for a blob.

    Per the CycloneDX 1.6 spec the ``component.type`` enum does not
    include ``"hardware"`` — the canonical type for physical hardware
    is ``"device"``.  The chipset identifier rides in ``properties[]``
    (the spec's ``modelNumber`` field is not part of the generic
    component object); ``manufacturer`` is included only when
    ``blob.vendor`` is populated (None / unknown -> omitted rather
    than stubbed out).
    """
    ref = f"chip_{blob.id}"
    vendor = (blob.vendor or "").strip()
    category = (blob.category or "device").strip()

    # Name: "<vendor> <category>" if we have a vendor, otherwise just the
    # category.  Always human-readable.
    name = f"{vendor} {category}".strip() if vendor else category

    comp: dict = {
        "type": "device",
        "bom-ref": ref,
        "name": name,
    }
    if vendor:
        comp["manufacturer"] = {"name": vendor}
    if blob.chipset_target:
        comp["properties"] = [
            {"name": "hw-firmware:chipset", "value": blob.chipset_target},
        ]
    return comp


def _build_firmware_component(blob: HardwareFirmwareBlob) -> dict:
    """Build a CycloneDX v1.6 ``firmware`` component for a blob.

    ``supplier`` is only emitted when we have a vendor (omitted on
    unknown), matching the ``manufacturer`` rule on the chip component.
    """
    ref = f"fw_{blob.id}"
    basename = os.path.basename(blob.blob_path) or blob.blob_path
    vendor = (blob.vendor or "").strip()

    comp: dict = {
        "type": "firmware",
        "bom-ref": ref,
        "name": basename,
    }
    if blob.version:
        comp["version"] = blob.version
    if vendor:
        comp["supplier"] = {"name": vendor}
    if blob.blob_sha256:
        comp["hashes"] = [
            {"alg": "SHA-256", "content": blob.blob_sha256},
        ]

    # Properties — carry all the firmware-specific metadata the top-level
    # CycloneDX component schema doesn't have a home for.  The
    # ``hw-firmware:`` prefix namespaces these away from other consumers.
    props: list[dict] = []

    def _add_prop(name: str, value: str | None) -> None:
        if value is None or value == "":
            return
        props.append({"name": name, "value": str(value)})

    _add_prop("hw-firmware:category", blob.category)
    _add_prop("hw-firmware:format", blob.format)
    _add_prop("hw-firmware:partition", blob.partition)
    _add_prop("hw-firmware:blob-path", blob.blob_path)
    _add_prop("hw-firmware:signed", blob.signed)
    _add_prop("hw-firmware:signature-algorithm", blob.signature_algorithm)
    _add_prop("hw-firmware:cert-subject", blob.cert_subject)
    _add_prop("hw-firmware:chipset-target", blob.chipset_target)
    _add_prop("hw-firmware:detection-source", blob.detection_source)
    _add_prop("hw-firmware:detection-confidence", blob.detection_confidence)
    _add_prop("hw-firmware:file-size", str(blob.file_size))

    # Flatten top-level string/int metadata into properties too so
    # parser-specific fields (kernel_semver, product, fw_version_raw, ...)
    # survive into the HBOM.
    md = _normalize_hardware_firmware_blobs_metadata(blob.metadata_)
    for key, value in md.items():
        if isinstance(value, (str, int, float, bool)):
            _add_prop(f"hw-firmware:meta:{key}", str(value))

    if props:
        comp["properties"] = props

    return comp


# Tier priority for picking the "best" representative SbomVulnerability
# row when one CVE is matched by multiple tiers.  Higher = more
# specific / more authoritative.  The winning row's description and
# severity become the canonical entry text; non-winning rows still
# contribute their (blob_ref, tier) attribution to the rolled-up
# affects[] and properties.
_TIER_PRIORITY = {
    "parser_version_pin": 4,  # most specific: parser-extracted version pin
    "curated_yaml": 3,         # human-vetted, version+chipset constraints
    "kernel_subsystem": 2,     # kernel.org vulns.git CNA mapping
    "chipset_cpe": 2,          # NVD CPE keyed by chipset
    "nvd_freetext": 1,         # NVD keyword search
    "kernel_cpe": 1,           # grype-projected onto every kmod blob
}


def _rating_from_vuln(vuln: SbomVulnerability) -> dict:
    """Build a single CycloneDX rating dict from one SbomVulnerability row."""
    severity = (vuln.severity or "unknown").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "unknown"
    rating: dict = {"severity": severity}
    if vuln.cvss_score is not None:
        try:
            rating["score"] = float(vuln.cvss_score)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            pass
    if vuln.cvss_vector:
        rating["vector"] = vuln.cvss_vector
        v = vuln.cvss_vector.upper()
        if v.startswith("CVSS:3.1"):
            rating["method"] = "CVSSv31"
        elif v.startswith("CVSS:3"):
            rating["method"] = "CVSSv3"
        elif v.startswith("CVSS:4"):
            rating["method"] = "CVSSv4"
    return rating


def _build_rolled_up_vulnerability(
    cve_id: str,
    rows: list[tuple[SbomVulnerability, str]],
) -> dict:
    """Build ONE CycloneDX v1.6 vulnerability entry for a CVE that may
    affect many components.

    ``rows`` is a list of ``(SbomVulnerability, firmware_bom_ref)``
    tuples representing every persisted match for this ``cve_id``.

    Per CycloneDX 1.6, ``vulnerability.affects[]`` is an ARRAY of
    component refs — that's the canonical way to express "this CVE
    affects N components".  Emitting one entry per (component × CVE)
    row is what bloated the DPCS10 HBOM from ~2 MB to 222 MB; the
    Linux kernel's kernel_cpe tier projects 785 kernel CVEs onto every
    kernel-module blob (~225 of them), producing ~177K duplicate rows
    instead of ~1,200 deduplicated entries.

    Algorithm:
      * Sort rows by (tier_priority desc, cvss_score desc) — the top
        row wins for description / canonical severity.
      * Roll up unique firmware refs into ``affects[]``.
      * Emit unique ratings (deduped by vector+score+severity tuple)
        so multi-source CVSS data survives, but identical ratings
        from kernel_cpe × N blobs collapse to one.
      * Tier provenance lives in properties: comma-joined tier list +
        affected_blob_count for transparency.
    """
    # Sort by tier priority (most specific first), then by CVSS score
    # descending so the highest-severity description wins on ties.
    def _sort_key(row: tuple[SbomVulnerability, str]) -> tuple[int, float]:
        v, _ = row
        priority = _TIER_PRIORITY.get(v.match_tier or "", 0)
        score = float(v.cvss_score or 0)
        return (-priority, -score)

    sorted_rows = sorted(rows, key=_sort_key)
    canonical, _ = sorted_rows[0]

    # Roll up unique firmware refs (preserve sort order from input — the
    # caller passes rows in a deterministic order so the affects[] list
    # is stable across exports of the same DB state).
    seen_refs: set[str] = set()
    affects: list[dict] = []
    for _v, ref in sorted_rows:
        if ref in seen_refs:
            continue
        seen_refs.add(ref)
        affects.append({"ref": ref})

    # Roll up unique ratings.  Two rows with identical (severity, score,
    # vector) collapse — the kernel_cpe tier projects the SAME CVE
    # ratings onto every kmod blob, so without dedup we'd carry 200+
    # identical ratings per entry.
    seen_ratings: set[tuple] = set()
    ratings: list[dict] = []
    for v, _ref in sorted_rows:
        rating = _rating_from_vuln(v)
        rkey = (
            rating.get("severity"),
            rating.get("score"),
            rating.get("vector"),
        )
        if rkey in seen_ratings:
            continue
        seen_ratings.add(rkey)
        ratings.append(rating)

    entry: dict = {
        "id": cve_id,
        "affects": affects,
        "ratings": ratings,
    }
    if canonical.description:
        entry["description"] = canonical.description

    # Tier provenance: comma-joined unique tiers (sorted by priority
    # desc) + affected blob count, so consumers can filter / triage
    # without re-aggregating.
    unique_tiers = sorted(
        {v.match_tier for v, _ in rows if v.match_tier},
        key=lambda t: -_TIER_PRIORITY.get(t, 0),
    )
    props: list[dict] = []
    if unique_tiers:
        props.append({"name": "wairz:match_tiers", "value": ",".join(unique_tiers)})
    if canonical.match_confidence:
        props.append(
            {"name": "wairz:match_confidence", "value": canonical.match_confidence},
        )
    props.append(
        {"name": "wairz:affected_blob_count", "value": str(len(affects))},
    )
    entry["properties"] = props
    return entry


async def build_hbom(
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict:
    """Build a CycloneDX v1.6 HBOM for the given firmware image.

    Returns a JSON-serialisable ``dict``.  Skips firmware-image metadata
    gracefully when the parent ``firmware`` row can't be resolved — the
    rest of the document still validates against CycloneDX v1.6.
    """
    # Parent firmware row (for the metadata.component header).  Optional
    # because the HBOM is still valid without it — we just lose the
    # "firmware-image" root component.
    fw_row = (
        await db.execute(
            select(Firmware).where(Firmware.id == firmware_id),
        )
    ).scalar_one_or_none()

    # Load blobs for this firmware, deterministically ordered so the
    # output is stable for snapshot tests.
    blob_stmt = (
        select(HardwareFirmwareBlob)
        .where(HardwareFirmwareBlob.firmware_id == firmware_id)
        .order_by(
            HardwareFirmwareBlob.category,
            HardwareFirmwareBlob.blob_path,
        )
    )
    blobs = (await db.execute(blob_stmt)).scalars().all()

    # Pre-fetch all hw-firmware vulns in one query and bucket by blob.
    vuln_stmt = (
        select(SbomVulnerability)
        .where(
            SbomVulnerability.firmware_id == firmware_id,
            SbomVulnerability.blob_id.is_not(None),
        )
        .order_by(SbomVulnerability.cve_id)
    )
    vulns = (await db.execute(vuln_stmt)).scalars().all()

    vulns_by_blob: dict[uuid.UUID, list[SbomVulnerability]] = {}
    for v in vulns:
        if v.blob_id is None:
            continue
        vulns_by_blob.setdefault(v.blob_id, []).append(v)

    # ── Build components + dependencies ────────────────────────────────
    components: list[dict] = []
    dependencies: list[dict] = []

    # Group SbomVulnerability rows by cve_id so we can roll up affects[]
    # per CycloneDX 1.6 conventions.  Without this, kernel_cpe tier
    # projects 785 distinct kernel CVEs onto every kernel-module blob
    # (~225 blobs) producing 176K duplicate entries instead of 785.
    rows_by_cve: dict[str, list[tuple[SbomVulnerability, str]]] = {}

    for blob in blobs:
        chip_ref = f"chip_{blob.id}"
        fw_ref = f"fw_{blob.id}"

        components.append(_build_hardware_component(blob))
        components.append(_build_firmware_component(blob))
        dependencies.append({"ref": chip_ref, "provides": [fw_ref]})

        for v in vulns_by_blob.get(blob.id, []):
            rows_by_cve.setdefault(v.cve_id, []).append((v, fw_ref))

    # Emit one vulnerability entry per distinct CVE, deterministically
    # ordered by cve_id so snapshot tests stay stable.
    vuln_entries: list[dict] = [
        _build_rolled_up_vulnerability(cve_id, rows_by_cve[cve_id])
        for cve_id in sorted(rows_by_cve)
    ]

    # ── Assemble the document ──────────────────────────────────────────
    metadata: dict = {
        "timestamp": _iso_utc_now(),
        "tools": [
            {
                "vendor": "Wairz",
                "name": "hardware-firmware-detector",
                "version": "0.1",
            },
        ],
    }
    if fw_row is not None:
        metadata["component"] = {
            "type": "firmware",
            "bom-ref": "firmware-image",
            "name": fw_row.original_filename or str(fw_row.id),
        }
        if fw_row.version_label:
            metadata["component"]["version"] = fw_row.version_label
        if fw_row.sha256:
            metadata["component"]["hashes"] = [
                {"alg": "SHA-256", "content": fw_row.sha256},
            ]

    hbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
    if vuln_entries:
        hbom["vulnerabilities"] = vuln_entries

    return hbom
