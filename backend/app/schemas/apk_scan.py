"""Pydantic response schemas for APK security scanning endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Phase 1: Manifest scan response schemas
# ---------------------------------------------------------------------------


class ManifestFindingResponse(BaseModel):
    """A single manifest security finding."""
    check_id: str
    title: str
    description: str
    severity: str
    evidence: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    confidence: str = "high"
    suppressed: bool = False
    suppression_reason: str = ""

    model_config = {"from_attributes": True}


class ManifestScanSummary(BaseModel):
    """Summary statistics for a manifest scan."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ConfidenceSummary(BaseModel):
    """Confidence breakdown for scan findings."""
    high: int = 0
    medium: int = 0
    low: int = 0


class FirmwareContextResponse(BaseModel):
    """Firmware metadata context attached to scan responses."""
    device_model: str | None = None
    manufacturer: str | None = None
    android_version: str | None = None
    api_level: int | None = None
    security_patch: str | None = None
    architecture: str | None = None
    partition: str | None = None
    firmware_filename: str | None = None
    bootloader_state: str | None = None
    is_priv_app: bool = False
    is_system_app: bool = False
    is_vendor_app: bool = False

    model_config = {"from_attributes": True}


class ManifestScanResponse(BaseModel):
    """Full response for a manifest security scan."""
    package: str
    findings: list[ManifestFindingResponse] = Field(default_factory=list)
    summary: ManifestScanSummary = Field(default_factory=ManifestScanSummary)
    confidence_summary: ConfidenceSummary = Field(
        default_factory=ConfidenceSummary
    )
    is_priv_app: bool = False
    is_platform_signed: bool = False
    is_debug_signed: bool = False
    severity_reduced: bool = False
    reduced_check_ids: list[str] = Field(default_factory=list)
    suppressed_findings: list[ManifestFindingResponse] = Field(
        default_factory=list
    )
    suppressed_count: int = 0
    suppression_reasons: list[str] = Field(default_factory=list)
    from_cache: bool = False
    elapsed_ms: float | None = None
    error: str | None = None
    firmware_context: FirmwareContextResponse | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Phase 2a: Bytecode scan response schemas
# ---------------------------------------------------------------------------


class BytecodeFindingLocation(BaseModel):
    """A single location where a pattern was detected."""
    caller_class: str | None = None
    caller_method: str | None = None
    target: str | None = None
    string_value: str | None = None
    using_class: str | None = None
    using_method: str | None = None
    dangerous_class: str | None = None

    model_config = {"from_attributes": True}


class BytecodeFindingResponse(BaseModel):
    """A single bytecode security finding."""
    pattern_id: str
    title: str
    description: str
    severity: str
    confidence: str = "high"
    cwe_ids: list[str] = Field(default_factory=list)
    category: str
    locations: list[dict] = Field(default_factory=list)
    total_occurrences: int = 0

    model_config = {"from_attributes": True}


class BytecodeScanSummary(BaseModel):
    """Summary statistics for a bytecode scan."""
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)


class BytecodeScanResponse(BaseModel):
    """Full response for a bytecode scan."""
    package: str
    findings: list[BytecodeFindingResponse] = Field(default_factory=list)
    summary: BytecodeScanSummary = Field(default_factory=BytecodeScanSummary)
    elapsed_seconds: float = 0.0
    dex_count: int = 0
    from_cache: bool = False
    error: str | None = None
    firmware_context: FirmwareContextResponse | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Phase 2b: mobsfscan SAST scan response schemas
# ---------------------------------------------------------------------------


class SastFindingResponse(BaseModel):
    """A single SAST finding from mobsfscan."""
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str | None = None
    source_file: str | None = None  # Java/Kotlin source path for source viewer
    line_number: int | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_mobile: str = ""
    masvs: str = ""

    model_config = {"from_attributes": True}


class SastScanTimingResponse(BaseModel):
    """Pipeline timing breakdown."""
    total_elapsed_ms: int = 0
    jadx_elapsed_ms: int = 0
    mobsfscan_elapsed_ms: int = 0


class SastScanSummary(BaseModel):
    """Summary statistics for a SAST scan."""
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    normalized_findings: int = 0
    persisted_count: int = 0
    suppressed_rule_count: int = 0
    suppressed_path_count: int = 0


class SastScanResponse(BaseModel):
    """Full response for a SAST (jadx+mobsfscan) scan."""
    success: bool = True
    findings: list[SastFindingResponse] = Field(default_factory=list)
    summary: SastScanSummary = Field(default_factory=SastScanSummary)
    timing: SastScanTimingResponse = Field(default_factory=SastScanTimingResponse)
    cached: bool = False
    error: str | None = None
    firmware_context: FirmwareContextResponse | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Decompiled source viewer
# ---------------------------------------------------------------------------


class SourceFileResponse(BaseModel):
    """Decompiled Java/Kotlin source code for a single file."""
    path: str
    source: str
    apk_path: str
    line_count: int


class SourceFileListResponse(BaseModel):
    """List of available decompiled source files for an APK."""
    apk_path: str
    files: list[str]
    total: int
