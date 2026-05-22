import uuid
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field


class VulnerabilityResolutionStatus(str, Enum):
    open = "open"
    resolved = "resolved"
    ignored = "ignored"
    false_positive = "false_positive"


class SbomComponentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    firmware_id: uuid.UUID
    name: str
    version: str | None
    type: str
    cpe: str | None
    purl: str | None
    supplier: str | None
    detection_source: str
    detection_confidence: str | None
    file_paths: list[str] | None
    metadata: dict = Field(validation_alias="metadata_", default={})
    vulnerability_count: int = 0
    created_at: datetime

    @computed_field
    @property
    def enrichment_source(self) -> str | None:
        return self.metadata.get("enrichment_source")

    @computed_field
    @property
    def cpe_confidence(self) -> float | None:
        val = self.metadata.get("cpe_confidence")
        return float(val) if val is not None else None


class SbomGenerateResponse(BaseModel):
    components: list[SbomComponentResponse]
    total: int
    cached: bool


# Rule #33 (c): both a Pydantic Literal AND a DB CHECK constraint.
# Mirrors ck_firmware_sbom_status added in alembic revision feab18c9d201
# (Session 2a of the 2026-05-21 SBOM/vuln-scan regression sweep).
# Rule #48 5-part cross-stack alignment: see
# backend/tests/test_sbom_status_alignment.py for the regression-canary
# that pins DB CHECK ↔ Pydantic Literal pairwise agreement.
SbomStatus = Literal["idle", "queued", "running", "completed", "failed"]


class SbomGenerateStatusResponse(BaseModel):
    """Polling-shape response for the 202+polling SBOM /generate flow.

    POST /sbom/generate returns this with status='queued'; the frontend
    polls GET /sbom/generate/status every 2 s (firmware-unpack +
    vuln-scan precedent) until status flips to 'completed' or 'failed'.
    On 'completed', `result` carries the last-known component-count
    aggregate so the page reload renders without a re-COUNT query;
    `summary` is None until 'completed'.

    Per W2-α convergence resolution, the response shape includes
    detected_format + extraction_capability + sbom_supported_for_format
    so Scout D's mandatory frontend graceful-degrade can render the
    correct affordance for unknown-format firmware (added via
    Pydantic-`Field` defaults to keep the schema backward-compatible).
    """
    firmware_id: uuid.UUID
    status: SbomStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    cached: bool = False
    total_components: int | None = None
    detected_format: str | None = None
    extraction_capability: str | None = None
    sbom_supported_for_format: bool | None = None
    model_config = ConfigDict(from_attributes=True)


class SbomVulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    # component_id is None for hardware-firmware-blob-linked vulns
    # (curated YAML tier — Tier 2-5 via cve_matcher). SBOM-component-
    # linked vulns (Tier 1 Grype) have component_id populated.
    component_id: uuid.UUID | None = None
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    description: str | None
    published_date: datetime | None
    finding_id: uuid.UUID | None
    component_name: str | None = None
    component_version: str | None = None
    # Hardware-firmware blob context — populated when the vuln was
    # matched via the curated-YAML pin tier against a blob (no SBOM
    # component link). Mutually exclusive with component_name/version
    # in practice (component_id is None when blob_id is populated).
    blob_id: uuid.UUID | None = None
    blob_path: str | None = None
    match_tier: str | None = None
    match_confidence: str | None = None

    # Resolution fields
    resolution_status: str = "open"
    resolution_justification: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None

    # AI-adjusted severity
    adjusted_cvss_score: float | None = None
    adjusted_severity: str | None = None
    adjustment_rationale: str | None = None

    @computed_field
    @property
    def effective_severity(self) -> str:
        return self.adjusted_severity if self.adjusted_severity else self.severity

    @computed_field
    @property
    def effective_cvss_score(self) -> float | None:
        return self.adjusted_cvss_score if self.adjusted_cvss_score is not None else self.cvss_score


class VulnerabilityUpdateRequest(BaseModel):
    resolution_status: VulnerabilityResolutionStatus | None = None
    resolution_justification: str | None = None


class VulnerabilityScanRequest(BaseModel):
    force_rescan: bool = False


class VulnerabilityScanResponse(BaseModel):
    status: str
    total_components_scanned: int
    total_vulnerabilities_found: int
    findings_created: int
    vulns_by_severity: dict[str, int]


# Rule #33 (c): both a Pydantic Literal AND a DB CHECK constraint.
# Mirrors ck_firmware_vuln_scan_status added in revision c1d2e3f4a5b6.
VulnScanStatus = Literal["idle", "queued", "running", "completed", "failed"]


class VulnerabilityScanStatusResponse(BaseModel):
    """Polling-shape response for the 202+polling vulnerability scan flow.

    POST /sbom/vulnerabilities/scan returns this with status="queued";
    the frontend polls GET /sbom/vulnerabilities/scan/status every 2 s
    until status flips to "completed" or "failed". The summary field is
    built per-request from a count query against sbom_vulnerabilities
    when status == "completed" — the persisted vuln rows ARE the result,
    so no JSONB result column on firmware is required.
    """

    firmware_id: uuid.UUID
    status: VulnScanStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    summary: VulnerabilityScanResponse | None = None
    model_config = ConfigDict(from_attributes=True)


class SbomSummaryResponse(BaseModel):
    total_components: int
    components_by_type: dict[str, int]
    components_with_vulns: int
    total_vulnerabilities: int
    vulns_by_severity: dict[str, int]
    scan_date: datetime | None
    open_count: int = 0
    resolved_count: int = 0
