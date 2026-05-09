"""ORM ↔ Pydantic response-schema alignment tests.

Background: CLAUDE.md learned rule #4 — every Pydantic response schema
must match its ORM model's column set. Mismatches cause silent 500s
when `from_attributes=True` serialisation hits a field the ORM doesn't
have, or when a non-nullable DB column surfaces as NULL in a `str` field.

Historical regressions:
- D1 drift (findings.source): ORM said non-null, migration said null,
  Pydantic said `str`. Fixed in alembic bb4acf97d9dd.
- D2 drift (FirmwareDetailResponse): ORM had `extraction_dir` and
  `device_metadata`, response schema only declared `device_metadata`.
  Fixed by adding `extraction_dir` to the response schema.

These tests lock in the contract: a schema may be a SUBSET of the ORM
(not every column needs to be exposed on the API) but must not INVENT
fields that don't exist on the ORM, and must cover the well-known
"must expose" set for each model.
"""
from __future__ import annotations

from app.models import (
    Finding,
    Firmware,
    Project,
)
from app.schemas.finding import FindingResponse
from app.schemas.firmware import FirmwareDetailResponse


def _orm_column_names(model_cls) -> set[str]:
    return set(model_cls.__mapper__.column_attrs.keys())


def _pydantic_field_names(schema_cls) -> set[str]:
    return set(schema_cls.model_fields.keys())


# ── Field inventions (Pydantic field not present on ORM) ──
# Any "invented" field is a bug: `from_attributes=True` can't populate it.


def test_firmware_detail_response_declares_no_invented_fields():
    orm = _orm_column_names(Firmware)
    schema = _pydantic_field_names(FirmwareDetailResponse)
    invented = schema - orm
    assert not invented, (
        f"FirmwareDetailResponse declares fields not on Firmware ORM: {sorted(invented)}"
    )


def test_finding_response_declares_no_invented_fields():
    orm = _orm_column_names(Finding)
    schema = _pydantic_field_names(FindingResponse)
    invented = schema - orm
    assert not invented, (
        f"FindingResponse declares fields not on Finding ORM: {sorted(invented)}"
    )


# ── D2 regression: must-expose fields ──
# Without these assertions, a future refactor could silently drop either
# field again and the frontend would read `undefined` with no 500.


def test_firmware_detail_response_exposes_extraction_dir():
    """D2 regression (rev bb4acf97d9dd companion)."""
    assert "extraction_dir" in _pydantic_field_names(FirmwareDetailResponse)


def test_firmware_detail_response_exposes_device_metadata():
    """D2 regression — FirmwareDetailResponse must include device_metadata."""
    assert "device_metadata" in _pydantic_field_names(FirmwareDetailResponse)


def test_firmware_detail_response_exposes_extracted_path():
    """Pre-existing contract — surfaced in the extraction-integrity audit."""
    assert "extracted_path" in _pydantic_field_names(FirmwareDetailResponse)


# ── D1 regression: findings.source must be non-nullable on ORM ──


def test_findings_source_is_non_nullable_on_orm():
    """After alembic bb4acf97d9dd the DB + ORM agree: source is NOT NULL."""
    col = Finding.__mapper__.column_attrs["source"].columns[0]
    assert col.nullable is False, "Finding.source ORM nullability regressed — see D1"


# ── CRA JSONB retype (D3) ──


def test_cra_requirement_result_jsonb_typed_as_list():
    """D3: CRA JSONB columns retyped from `dict` to `list[str]`.

    Assert via the model class annotations rather than runtime (which is
    `JSONB` either way) — this guards against a silent revert to `dict`.
    """
    from app.models.cra_compliance import CraRequirementResult

    hints = CraRequirementResult.__annotations__
    for col_name in ("finding_ids", "tool_sources", "related_cwes", "related_cves"):
        assert col_name in hints, f"CraRequirementResult.{col_name} vanished"
        type_repr = repr(hints[col_name])
        assert "list" in type_repr, (
            f"CraRequirementResult.{col_name} type hint should be Mapped[list[str]], "
            f"got {type_repr}. See CLAUDE.md rule #4 + D3 intake."
        )


# ── I4 regression: Project must expose cascading child collections ──


def test_project_exposes_backpopulated_collections():
    """I4 regression: Project.emulation_sessions et al. must be queryable
    via `selectinload(Project.xxx)` without raw SQL."""
    orm_rels = set(Project.__mapper__.relationships.keys())
    expected = {
        "firmware",
        "conversations",
        "findings",
        "documents",
        "reviews",
        "emulation_sessions",
        "emulation_presets",
        "uart_sessions",
        "fuzzing_campaigns",
        "attack_surface_entries",
    }
    missing = expected - orm_rels
    assert not missing, (
        f"Project is missing back-populated relationships: {sorted(missing)}. "
        f"Present: {sorted(orm_rels)}"
    )


# ── I1 CHECK allowlist parity with migration ──


def test_check_allowlist_imports_from_migration():
    """Allowlists are module constants in the migration file so external
    code (including this test) can read them. If the import fails, the
    migration was accidentally made private."""
    # Import the migration module by path
    import importlib.util
    import pathlib

    mig_path = (
        pathlib.Path(__file__).parent.parent
        / "alembic"
        / "versions"
        / "54c8864fbe0c_add_enum_check_constraints.py"
    )
    assert mig_path.exists(), (
        "Enum-check migration moved or renamed — update test_schemas.py to match"
    )
    spec = importlib.util.spec_from_file_location("_enum_check_mig", mig_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Spot-check that observed-in-DB source values are in the allowlist.
    must_include = {
        "manual",
        "security_audit",
        "yara_scan",
        "apk-manifest-scan",
        "apk-mobsfscan",
        "apk-bytecode-scan",
    }
    allow = set(mod.FINDINGS_SOURCE_VALUES)
    missing = must_include - allow
    assert not missing, (
        f"Migration FINDINGS_SOURCE_VALUES missing live DB values: {sorted(missing)}"
    )
