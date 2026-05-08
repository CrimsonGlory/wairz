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


# ── Phase β.8 — Authenticode-chain 202+polling schemas ───────────────────────


class AuthenticodeChainAggregate(BaseModel):
    """Final-result payload of one authenticode-chain run.

    Carries the per-firmware histogram + counts produced by walking
    every PE in ``hardware_firmware_blobs``, running signify's
    Authenticode validator + DBX matcher + ARM-arch detector + RICH
    decoder, and persisting one ``WindowsPESignature`` row per PE.
    Persisted on ``firmware.authenticode_chain_result`` JSONB so the
    frontend's last-known-result render survives a session reload
    (mirrors :class:`CveMatchRunResult`).

    The ``schema_version`` key written by
    :func:`_stamp_firmware_authenticode_chain_result` is stripped at
    read time by Pydantic's ``extra='ignore'`` default — the model
    field set is the canonical contract; the JSONB stamp is the
    cross-version dispatch hook (see ``services/jsonb_normalizers.py``).
    """

    model_config = ConfigDict(extra="ignore")

    signed_count: int             # PEs whose verdict signed=True
    signed_pct: float             # signed_count / total_pe_count, [0.0, 1.0]
    unsigned_count: int           # PEs whose verdict signed=False
    dbx_revoked_count: int        # PEs whose leaf serial is in the dbxupdate.bin
    by_chain_status: dict[str, int]  # chain_status histogram (5 buckets)
    run_seconds: float            # wall-clock duration of the run
    total_pe_count: int           # PEs the runner identified (MZ-magic prefilter)
    errors: list[dict[str, str]] = []  # per-PE [{blob_path, error}, ...]


AuthenticodeChainStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]


class AuthenticodeChainStatusResponse(BaseModel):
    """Status snapshot for the 202+polling authenticode-chain flow.

    Mirrors :class:`CveMatchStatusResponse`: POST handler returns this
    with ``status="queued"``; the frontend polls
    ``GET /authenticode-chain/status`` every 2 s until ``status`` flips
    to ``"completed"`` or ``"failed"``.
    """

    model_config = ConfigDict(from_attributes=True)

    firmware_id: uuid.UUID
    status: AuthenticodeChainStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    result: AuthenticodeChainAggregate | None = None


# ── Phase β.11 — Per-PE signature row schemas (REST surface) ─────────────────


# Mirrors the WindowsPESignature.chain_status CHECK constraint values. A
# Pydantic Literal at the API boundary gates writer-side typos; the DB
# CHECK is the durable runtime gate (Rule #33 .c).
WindowsPEChainStatus = Literal[
    "valid_at_signing", "valid_now", "revoked", "never_valid", "unknown",
]


# Mirrors the WindowsDriver.signing_tier CHECK constraint values (Phase γ.2).
# Persona-E #13 capability badge — the tier determines which Windows
# kernel-mode loader will accept the driver (HVCI requires WHQL + EV;
# SecureBoot requires at least cross_signed). Pydantic Literal gates the
# writer side; the DB CHECK is the durable runtime gate (Rule #33 .c).
WindowsDriverSigningTier = Literal[
    "whql", "attestation", "cross_signed", "unsigned", "unknown",
]


# Mirrors the WindowsRegistryExtract.walk_status CHECK constraint values
# (Phase γ.1). Per-hive parse status; aggregate batch-walk status across
# all hives in a firmware lives separately on the firmware row via
# ``firmware.registry_hive_walk_status`` (Phase γ.3).
WindowsRegistryExtractWalkStatus = Literal[
    "completed", "partial", "failed", "skipped",
]


# Mirrors the firmware.registry_hive_walk_status CHECK constraint values
# (Phase γ.3 — alembic ``c8d9e0f1a2b3``). 5-state 202+polling status set
# matching the cve_match / vuln_scan / authenticode_chain pattern. Rule
# #33 .c contract: Pydantic Literal here gates writer-side typos; the
# DB CHECK (in the migration) is the durable runtime gate.
RegistryHiveWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed",
]


# Mirrors the windows_update_packages.package_type CHECK constraint values
# (Phase δ.1 — alembic ``d0e1f2a3b4c5``). Discriminator for detected
# Windows-Update packages: msu = compound CAB-of-CAB, cab_cumulative /
# cab_security / cab_sru / cab_lcu / cab_dotnet = the per-MSU child CABs,
# msi / msix = legacy / modern app installers, unknown = catch-all for
# packages whose manifest didn't surface a recognisable shape. Rule #33
# .c contract — Literal at the writer boundary, DB CHECK in the migration.
WindowsUpdatePackageType = Literal[
    "msu",
    "cab_cumulative",
    "cab_security",
    "cab_sru",
    "cab_lcu",
    "cab_dotnet",
    "msi",
    "msix",
    "unknown",
]


# Mirrors the firmware.dotnet_decompile_status CHECK constraint values
# (Phase δ.2 — alembic ``d1e2f3a4b5c6``). 5-state 202+polling status set
# matching the cve_match / vuln_scan / authenticode_chain /
# registry_hive_walk pattern. Rule #33 .c contract: Pydantic Literal here
# gates writer-side typos; the DB CHECK (in the migration) is the durable
# runtime gate. Rule #33 .d — δ.4 dispatch is **arq** (worker-only
# dotnet-runtime + ilspycmd resource).
DotnetDecompileStatus = Literal[
    "idle", "queued", "running", "completed", "failed",
]


class WindowsPESignatureSummary(BaseModel):
    """Compact per-PE signature row for the PeHardeningPage table.

    Surfaces the columns the operator scans first (signed / chain_status /
    signer_subject / leaf_serial / dbx_revoked) without the heavy JSONB
    payloads (chain_json / arch_view / rich_header_json) — those land on
    :class:`WindowsPESignatureDetail` for the AuthenticodeDetailPage.

    ``blob_path`` joins through HardwareFirmwareBlob so the operator sees
    the firmware-tree path the runner verified, not just the FK uuid.
    ``arch_view_present`` / ``rich_header_present`` are presence flags so
    the table can badge bimorphic / RICH-header rows without paying the
    JSONB serialization cost on every list call.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    blob_id: uuid.UUID
    blob_path: str
    signed: bool
    chain_status: WindowsPEChainStatus
    signer_subject: str | None = None
    signer_issuer: str | None = None
    leaf_serial: str | None = None
    sig_hash_algo: str | None = None
    tsa_authority: str | None = None
    signed_at: datetime | None = None
    dbx_revoked: bool
    dbx_revocation_kb: str | None = None
    arch_view_present: bool
    rich_header_present: bool
    created_at: datetime


class WindowsPESignatureListResponse(BaseModel):
    """Paginated list of per-PE signature rows for one firmware."""

    signatures: list[WindowsPESignatureSummary]
    total: int
    offset: int
    limit: int


class WindowsPESignatureDetail(BaseModel):
    """Full per-PE signature row for the AuthenticodeDetailPage.

    Carries every column the runner persists, including the heavy JSONB
    payloads (``chain_json`` for signify's verification_result tree,
    ``arch_view`` for ARM64EC/X bimorphic detection, ``rich_header_json``
    for the Microsoft toolchain fingerprint). The detail page renders
    each section behind a collapsible region so the operator can drill
    into the chain without overwhelming the layout.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    blob_id: uuid.UUID
    blob_path: str
    signed: bool
    chain_status: WindowsPEChainStatus
    signer_subject: str | None = None
    signer_issuer: str | None = None
    leaf_serial: str | None = None
    sig_hash_algo: str | None = None
    tsa_authority: str | None = None
    signed_at: datetime | None = None
    chain_json: dict | None = None
    dbx_revoked: bool
    dbx_revocation_kb: str | None = None
    rich_header_json: dict | None = None
    arch_view: dict | None = None
    created_at: datetime
    updated_at: datetime


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
