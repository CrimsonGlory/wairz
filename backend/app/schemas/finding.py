import uuid
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel

# Per CLAUDE.md Rule #33 .c — Pydantic Literal for the verdict-bearing
# Windows sources β.12 + γ.8 emit. Used at the call boundary inside
# ``FindingService.emit_pe_signature_findings`` (β.12c authenticode
# chain runner) and ``FindingService.emit_registry_findings_from_walk``
# / ``emit_driver_findings_from_extract`` (γ.8) so the source-string
# constants are typo-checked at construction time. The DB-side
# enforcement is the matching ``ck_findings_source`` CHECK from
# alembic revisions ``c5b6a7d8e9f0`` (β.12a, +authenticode/+dbx) and
# ``c9d0e1f2a3b4`` (γ.7, +registry_persistence/+inf/+driver_imports).
WindowsFindingSource = Literal[
    "windows_authenticode",
    "windows_dbx_revoked",
    "windows_registry_persistence",
    "windows_inf",
    "windows_driver_imports",
    # Phase δ.8 — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by:
    # - δ.6 R2R-stomping classifier → Finding rows for review.
    # - Future capa-on-IL emitter → capability badges per .NET assembly.
    "windows_r2r_stomp",
    "windows_il_capa",
    # Phase ε.1.b.4 — alignment slice with frontend FindingSource union +
    # FINDING_SOURCE_CONFIG entries. Emitted by the EVTX walk emit hook
    # (``finding_service.emit_evtx_findings_from_walk``) for the
    # forensic-timeline trio (Persona-E #4):
    # - Sysmon EID 1 (process create) → windows_sysmon_proc_create.
    # - Security EID 4624 (logon success) → windows_logon_success.
    # - Security EID 4625 (logon failure) → windows_logon_failure.
    "windows_sysmon_proc_create",
    "windows_logon_success",
    "windows_logon_failure",
]


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class FindingStatus(str, Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    fixed = "fixed"


class FindingCreate(BaseModel):
    title: str
    severity: Severity
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    confidence: Confidence | None = None
    conversation_id: uuid.UUID | None = None
    firmware_id: uuid.UUID | None = None
    source: str = "manual"
    component_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    title: str | None = None
    severity: Severity | None = None
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    confidence: Confidence | None = None
    status: FindingStatus | None = None
    source: str | None = None


class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID | None
    conversation_id: uuid.UUID | None
    title: str
    severity: str
    description: str | None
    evidence: str | None
    file_path: str | None
    line_number: int | None
    cve_ids: list[str] | None
    cwe_ids: list[str] | None
    confidence: str | None
    status: str
    source: str
    component_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
