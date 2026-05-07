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


class SbomVulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    component_id: uuid.UUID
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    description: str | None
    published_date: datetime | None
    finding_id: uuid.UUID | None
    component_name: str | None = None
    component_version: str | None = None

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
