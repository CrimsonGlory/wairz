import os
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.schemas.finding import (
    Confidence,
    FindingCreate,
    FindingUpdate,
    Severity,
    WindowsFindingSource,
)


# ── Phase β.12b — Authenticode + DBX verdict → Finding emission ──────────────
#
# Two source values land Finding rows from the authenticode_chain_runner per
# PE verdict:
#
# - ``windows_authenticode`` — chain_status verdicts that warrant operator
#   attention. The campaign brief (β.12 design constraints) maps:
#     * ``revoked`` / ``never_valid``           → high   severity
#     * ``unknown`` for a PE that's signed=True → medium severity
#     * ``valid_at_signing`` / ``valid_now``    → no Finding (good case)
#     * ``unknown`` for a PE that's signed=False → no Finding (unsigned PE
#       is normal-ish — the signature absence is captured by
#       firmware.authenticode_chain_result.signed_pct, not as a per-PE finding)
# - ``windows_dbx_revoked`` — leaf-serial matched a Microsoft DBX entry.
#   Always critical severity. Independent of chain_status: a chain-revoked
#   AND DBX-revoked PE produces TWO Finding rows (different sources, the
#   operator may want to triage them separately by source filter).
#
# The classifier below is decoupled from the ORM so it's exercised by mock
# unit tests (no DB needed) AND by the live-canary inside
# ``FindingService.emit_pe_signature_findings`` (Rule #35b).
#
# Constants typed against ``WindowsFindingSource`` (Rule #33 .c) so a typo
# in either source string fails type-check at definition time, matching
# the ``ck_findings_source`` DB CHECK from alembic revision ``c5b6a7d8e9f0``.

_SOURCE_AUTHENTICODE: WindowsFindingSource = "windows_authenticode"
_SOURCE_DBX_REVOKED: WindowsFindingSource = "windows_dbx_revoked"


@dataclass(frozen=True)
class _PEFindingDraft:
    """One Finding row to emit, before persistence. Pure-data so the
    classifier can be unit-tested without a DB.
    """
    source: WindowsFindingSource
    severity: Severity
    title: str
    description: str
    evidence: str


def _format_authenticode_evidence(
    *,
    signed: bool,
    chain_status: str,
    leaf_serial: str | None,
    signer_subject: str | None,
) -> str:
    """One-line, operator-readable summary of the authenticode verdict
    fields the Finding row was derived from. Format mirrors the
    extraction-diagnostics evidence shape in unpack_audit_service —
    KV pairs separated by ``; ``."""
    parts: list[str] = [
        f"signed={signed}",
        f"chain_status={chain_status}",
    ]
    if leaf_serial:
        parts.append(f"leaf_serial={leaf_serial}")
    if signer_subject:
        parts.append(f"signer_subject={signer_subject}")
    return "; ".join(parts)


def _format_dbx_evidence(
    *,
    leaf_serial: str | None,
    dbx_revocation_kb: str | None,
) -> str:
    parts: list[str] = []
    if leaf_serial:
        parts.append(f"leaf_serial={leaf_serial}")
    if dbx_revocation_kb:
        parts.append(f"dbx_revocation_kb={dbx_revocation_kb}")
    if not parts:
        # match_dbx_revocation always returns at least the KB reference on
        # a positive match; this branch is defensive against a future
        # caller passing dbx_revoked=True with no supporting context.
        parts.append("source=microsoft_dbxupdate")
    return "; ".join(parts)


def classify_pe_verdict_findings(
    *,
    blob_path: str,
    signed: bool,
    chain_status: str,
    dbx_revoked: bool,
    leaf_serial: str | None = None,
    signer_subject: str | None = None,
    dbx_revocation_kb: str | None = None,
) -> list[_PEFindingDraft]:
    """Map one PE's verdict tuple to 0–2 Finding drafts.

    Pure function; no DB access. Idempotent — same inputs always produce
    the same output list (so re-running the runner against the same
    verdict produces identical Finding rows, modulo timestamps which the
    DB stamps).
    """
    drafts: list[_PEFindingDraft] = []
    name = os.path.basename(blob_path) or blob_path

    # windows_authenticode emission per the β.12 severity map.
    ac_severity: Severity | None = None
    ac_description: str | None = None
    if chain_status == "revoked":
        ac_severity = Severity.high
        ac_description = (
            f"Authenticode certificate chain reports REVOKED for {name}. "
            "The signing certificate (or one of its issuers) was revoked "
            "by its CA before the firmware was assembled — the binary was "
            "either signed with an already-revoked cert or had its "
            "trusted timestamp invalidated. Treat as untrusted code."
        )
    elif chain_status == "never_valid":
        ac_severity = Severity.high
        ac_description = (
            f"Authenticode certificate chain is NEVER VALID for {name}. "
            "Chain construction failed against the trusted-roots bundle "
            "(self-signed, expired-at-signing, or no path to a trusted "
            "root). The signature cannot be relied on for code-trust."
        )
    elif chain_status == "unknown" and signed:
        ac_severity = Severity.medium
        ac_description = (
            f"Authenticode chain status is UNKNOWN for signed PE {name}. "
            "The signature was parsed but verification could not complete "
            "(missing intermediate, missing timestamp, parser error). "
            "Manual review recommended before relying on the signature."
        )

    if ac_severity is not None:
        assert ac_description is not None  # guarded by the same branches above
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_AUTHENTICODE,
                severity=ac_severity,
                title=f"Authenticode chain {chain_status} for {name}",
                description=ac_description,
                evidence=_format_authenticode_evidence(
                    signed=signed,
                    chain_status=chain_status,
                    leaf_serial=leaf_serial,
                    signer_subject=signer_subject,
                ),
            )
        )

    # windows_dbx_revoked — independent of chain_status. A PE can be both
    # chain-revoked AND DBX-revoked → two Finding rows, different sources.
    if dbx_revoked:
        drafts.append(
            _PEFindingDraft(
                source=_SOURCE_DBX_REVOKED,
                severity=Severity.critical,
                title=f"Microsoft DBX revoked PE: {name}",
                description=(
                    f"PE leaf certificate for {name} matches an entry in "
                    "the Microsoft Secure Boot DBX revocation bundle. "
                    "Continued execution risks running attacker-trusted "
                    "code with valid-looking but offline-revoked signature."
                ),
                evidence=_format_dbx_evidence(
                    leaf_serial=leaf_serial,
                    dbx_revocation_kb=dbx_revocation_kb,
                ),
            )
        )

    return drafts


class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        project_id: uuid.UUID,
        data: FindingCreate,
    ) -> Finding:
        finding = Finding(
            project_id=project_id,
            firmware_id=data.firmware_id,
            conversation_id=data.conversation_id,
            title=data.title,
            severity=data.severity.value,
            description=data.description,
            evidence=data.evidence,
            file_path=data.file_path,
            line_number=data.line_number,
            cve_ids=data.cve_ids,
            cwe_ids=data.cwe_ids,
            confidence=data.confidence.value if data.confidence else None,
            source=data.source,
            component_id=data.component_id,
        )
        self.db.add(finding)
        await self.db.flush()
        return finding

    async def list_by_project(
        self,
        project_id: uuid.UUID,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        firmware_id: uuid.UUID | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.project_id == project_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if source:
            stmt = stmt.where(Finding.source == source)
        if firmware_id:
            stmt = stmt.where(Finding.firmware_id == firmware_id)
        stmt = stmt.order_by(Finding.created_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def update(self, finding_id: uuid.UUID, data: FindingUpdate) -> Finding | None:
        finding = await self.get(finding_id)
        if finding is None:
            return None
        update_data = data.model_dump(exclude_unset=True)
        # Convert enum values to strings
        for key, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(finding, key, value)
        await self.db.flush()
        await self.db.refresh(finding)
        return finding

    async def delete(self, finding_id: uuid.UUID) -> bool:
        finding = await self.get(finding_id)
        if finding is None:
            return False
        await self.db.delete(finding)
        await self.db.flush()
        return True

    async def emit_pe_signature_findings(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
        blob_path: str,
        *,
        signed: bool,
        chain_status: str,
        dbx_revoked: bool,
        leaf_serial: str | None = None,
        signer_subject: str | None = None,
        dbx_revocation_kb: str | None = None,
    ) -> list[Finding]:
        """Emit 0–2 Finding rows for one PE's authenticode + DBX verdict.

        Idempotency is the CALLER's responsibility — the
        ``authenticode_chain_runner`` DELETEs prior windows_authenticode +
        windows_dbx_revoked findings for the firmware at the start of each
        run, mirroring its WindowsPESignature DELETE. This helper just
        emits new rows.

        See :func:`classify_pe_verdict_findings` for the verdict → severity
        mapping.
        """
        drafts = classify_pe_verdict_findings(
            blob_path=blob_path,
            signed=signed,
            chain_status=chain_status,
            dbx_revoked=dbx_revoked,
            leaf_serial=leaf_serial,
            signer_subject=signer_subject,
            dbx_revocation_kb=dbx_revocation_kb,
        )
        emitted: list[Finding] = []
        for draft in drafts:
            data = FindingCreate(
                title=draft.title,
                severity=draft.severity,
                description=draft.description,
                evidence=draft.evidence,
                file_path=blob_path,
                confidence=Confidence.high,
                firmware_id=firmware_id,
                source=draft.source,
            )
            emitted.append(await self.create(project_id, data))
        return emitted
