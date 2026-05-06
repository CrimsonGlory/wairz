"""Pydantic response schemas for automated security scanning endpoints."""

from __future__ import annotations

from pydantic import BaseModel


class SecurityScanResponse(BaseModel):
    status: str
    checks_run: int
    findings_created: int
    total_findings: int
    errors: list[str] = []


class UefiScanResponse(BaseModel):
    status: str
    modules_scanned: int
    findings_created: int
    summary: dict[str, int] = {}
    errors: list[str] = []


class YaraScanResponse(BaseModel):
    status: str
    rules_loaded: int
    files_scanned: int
    files_matched: int
    findings_created: int
    errors: list[str] = []


class ClamScanResponse(BaseModel):
    status: str
    files_scanned: int
    infected_count: int
    infected_files: list[dict] = []
    findings_created: int = 0
    errors: list[str] = []


class VtScanResponse(BaseModel):
    status: str
    binaries_checked: int
    detected_count: int
    detected_files: list[dict] = []
    findings_created: int = 0
    errors: list[str] = []


class UpdateMechanismDetail(BaseModel):
    system: str
    confidence: str
    binaries: list[str] = []
    configs: list[str] = []
    update_urls: list[str] = []
    uses_https: bool | None = None
    has_ab_scheme: bool | None = None
    findings: list[dict] = []


class UpdateMechanismResponse(BaseModel):
    status: str
    mechanisms: list[UpdateMechanismDetail]
    total: int


class AbusechScanResponse(BaseModel):
    status: str
    binaries_checked: int
    malwarebazaar_hits: int = 0
    threatfox_hits: int = 0
    yaraify_hits: int = 0
    findings_created: int = 0
    details: dict = {}
    errors: list[str] = []


class KnownGoodScanResponse(BaseModel):
    status: str
    binaries_checked: int
    known_good_count: int = 0
    unknown_count: int = 0
    known_good_files: list[dict] = []
    errors: list[str] = []
