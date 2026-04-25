from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HardwareFirmwareBlobResponse(BaseModel):
    """One detected hardware firmware blob."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    firmware_id: uuid.UUID
    blob_path: str
    partition: str | None = None
    blob_sha256: str
    file_size: int
    category: str
    vendor: str | None = None
    format: str
    version: str | None = None
    signed: str = "unknown"
    signature_algorithm: str | None = None
    cert_subject: str | None = None
    chipset_target: str | None = None
    driver_references: list[str] | None = None
    sbom_component_id: uuid.UUID | None = None
    metadata: dict = Field(validation_alias="metadata_", default_factory=dict)
    detection_source: str
    detection_confidence: str = "medium"
    created_at: datetime
    # CVE rollup populated by the list endpoint via a single GROUP BY
    # over sbom_vulnerabilities.  ``cve_count`` excludes ADVISORY-* rows
    # (they're presence flags, not actual CVEs); ``advisory_count``
    # tracks them separately so the UI can badge with the right severity
    # signal.  ``max_severity`` is the highest severity across both CVEs
    # AND advisories so the badge color reflects worst-case risk.
    cve_count: int = 0
    advisory_count: int = 0
    max_severity: str | None = None  # critical | high | medium | low


class HardwareFirmwareListResponse(BaseModel):
    """Paginated list of hardware firmware blobs."""

    blobs: list[HardwareFirmwareBlobResponse]
    total: int


class HardwareFirmwareCveAggregate(BaseModel):
    """Firmware-wide CVE count summary used by the page header.

    Distinct from ``POST /cve-match`` which RUNS the matcher; this is a
    cheap read-only count of what's already persisted in
    ``sbom_vulnerabilities`` so the header badge can render on page load
    without re-running matching every time.
    """

    hw_firmware_cves: int  # distinct CVEs across hw-firmware tiers
    kernel_cves: int        # distinct CVEs from kernel_cpe + kernel_subsystem
    advisory_count: int     # distinct ADVISORY-* presence flags
    last_match_at: datetime | None = None
    # Severity breakdown of ``hw_firmware_cves`` (NOT kernel-tier).
    # Populated so the StatsHeader can render "26 CVEs (1 crit · 24 high
    # · 2 med)" without a second round-trip.
    hw_severity_critical: int = 0
    hw_severity_high: int = 0
    hw_severity_medium: int = 0
    hw_severity_low: int = 0


class CveMatchRunResult(BaseModel):
    """Final-result payload of a cve-match run.

    Carries the same shape the synchronous endpoint used to return; now
    persisted on ``firmware.cve_match_result`` so the frontend can render
    the last-known-result without a follow-up ``/cve-aggregate`` call.
    """

    count: int             # distinct CVE IDs across all tiers
    rows: int              # total persisted rows (kernel cartesian included)
    hw_firmware_cves: int  # distinct hw-firmware tier CVEs
    kernel_cves: int       # distinct kernel-tier CVEs
    kernel_module_rows: int  # cartesian projection rows across kmod blobs


CveMatchStatus = Literal["idle", "queued", "running", "completed", "failed"]


class CveMatchStatusResponse(BaseModel):
    """Status snapshot for the 202+polling cve-match flow.

    Mirrors the firmware-unpack precedent: the POST handler returns this
    with ``status="queued"``; the frontend polls ``GET /cve-match/status``
    every 2 s until ``status`` flips to ``"completed"`` or ``"failed"``.
    """

    model_config = ConfigDict(from_attributes=True)

    firmware_id: uuid.UUID
    status: CveMatchStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    result: CveMatchRunResult | None = None


class HardwareFirmwareCveRow(BaseModel):
    """One distinct CVE in the CVE-centric aggregate view."""

    cve_id: str
    severity: str
    cvss_score: float | None = None
    match_tier: str | None = None
    match_confidence: str | None = None
    description: str | None = None
    affected_blob_count: int
    affected_blob_ids: list[uuid.UUID]
    affected_formats: list[str]  # distinct formats across affected blobs


class HardwareFirmwareCvesResponse(BaseModel):
    cves: list[HardwareFirmwareCveRow]
    total: int


class HardwareFirmwareFilter(BaseModel):
    """Filter criteria for listing hardware firmware blobs."""

    category: str | None = None
    vendor: str | None = None
    signed_only: bool | None = None


# ---------------------------------------------------------------------------
# Phase 3 — driver <-> firmware graph schemas
# ---------------------------------------------------------------------------


class FirmwareEdgeResponse(BaseModel):
    """One edge in the driver <-> firmware graph.

    ``firmware_blob_path`` is ``None`` when the driver requests firmware that
    is not present in the extracted image (an unresolved / missing
    reference).
    """

    model_config = ConfigDict(from_attributes=True)

    driver_path: str
    firmware_name: str
    firmware_blob_path: str | None = None
    source: str  # kmod_modinfo | vmlinux_strings | dtb_firmware_name


class FirmwareEdgesResponse(BaseModel):
    """Response for the ``/component-map/firmware-edges``-style overlay."""

    edges: list[FirmwareEdgeResponse]
    kmod_drivers: int
    dtb_sources: int
    unresolved_count: int


class FirmwareDriverResponse(BaseModel):
    """Driver (kmod / vmlinux / DTB source) with its firmware dependencies."""

    model_config = ConfigDict(from_attributes=True)

    driver_path: str
    format: str  # ko | vmlinux | dtb
    firmware_deps: list[str]  # requested firmware names (both resolved + unresolved)
    firmware_blobs: list[str]  # resolved blob paths
    total: int  # count of firmware_deps


class FirmwareDriversListResponse(BaseModel):
    drivers: list[FirmwareDriverResponse]
    total: int
