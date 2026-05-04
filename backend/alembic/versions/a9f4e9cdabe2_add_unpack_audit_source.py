"""add unpack_audit to findings.source CHECK constraint

Revision ID: a9f4e9cdabe2
Revises: e6f7a8b9c0d1
Create Date: 2026-05-04

Adds 'unpack_audit' as a permitted Finding.source value. Used by the
post-unpack background task ``services.unpack_audit_service`` that
promotes ``firmware.device_metadata['vendor_decryption']`` and
``['extraction_diagnostics']`` discoveries to Finding rows.

Mirrors the FINDINGS_SOURCE_VALUES tuple in
``54c8864fbe0c_add_enum_check_constraints.py`` plus 'unpack_audit'.
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'a9f4e9cdabe2'
down_revision: Union[str, None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_SOURCE_VALUES: tuple[str, ...] = (
    "manual",
    "security_audit",
    "yara_scan",
    "attack_surface",
    "sbom_scan",
    "hardware_firmware_graph",
    "apk-manifest-scan",
    "apk-bytecode-scan",
    "apk-mobsfscan",
    "cwe_checker",
    "uefi_scan",
    "clamav_scan",
    "vt_scan",
    "abusech_scan",
    "fuzzing",
    "fuzzing_scan",
    "unpack_audit",
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", _NEW_SOURCE_VALUES),
    )


def downgrade() -> None:
    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(v for v in _NEW_SOURCE_VALUES if v != "unpack_audit")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
