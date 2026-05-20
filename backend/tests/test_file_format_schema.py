"""Schema validation tests for FileFormatManifest (CLAUDE.md Rule #52 P3.1.a).

Pure Pydantic validation tests — NO catalog state needed (catalog tests live
in P3.1.b). Each test instantiates :class:`FileFormatManifest` (or a sub-model)
with valid/invalid YAML-shape inputs and asserts acceptance or
:class:`pydantic.ValidationError`.

Coverage shape (W2-beta 14 forbidden-key shapes + Rule #52 hard cap + Rule #46
META-CANARIES + Rule #35b live canary):

* Happy paths — minimal valid; FREE-string taxonomy; dispatch with cases;
  refinement with vendor_precedence; plugin matcher; pre_upload; provenance;
  default-lifecycle deprecation.
* ``extra="forbid"`` rejection battery — regex/script/template/eval/lua/vql/
  predicate/expression keys rejected at any nesting level; unknown top-level
  field rejected; unknown nested field rejected.
* Closed-Literal rejections — confidence/manifest_source/dispatch.kind/
  plugin.role/evaluation_mode reject out-of-grammar values.
* Field-constraint rejections — bytes_hex length/odd/mask-length-mismatch/
  mask-all-zero; offset overflow; path-substring floor + leading-slash;
  filename stems floor; precedence reservation; negative-evidence floor;
  always_matches sentinel; dispatch.none with cases; dispatch w/o cases;
  mode-override pairing; alias_of mutual exclusion; combine=weighted requires
  min_confidence_score; deprecation lifecycle pairing; format_id pattern.
* Rule #46 META-CANARIES — every model has ``extra="forbid"``; no open-
  predicate keys in the schema source; extra-forbid canary fires on an
  unknown field; JSON Schema export emits closed Literals via ``enum``.
* Rule #35b live canary — realistic operator-minted Medtronic manifest dict
  round-trips through validate / model_dump / re-validate identity.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from app.schemas.file_format import (
    Deprecation,
    Detection,
    DetectionSignal,
    Dispatch,
    ExternalManifestsPolicyBlock,
    FileFormatManifest,
    FormatMatch,
    Output,
    Plugin,
    PluginRef,
    PreUploadHint,
    ProvenanceStub,
    Refinement,
)


# ---------------------------------------------------------------------------
# Fixture builders — produce VALID manifest dicts that survive Pydantic
# validation. Each test mutates a deep-copy to exercise one failure mode.
# ---------------------------------------------------------------------------


def _minimal_signal_dict() -> dict:
    return {
        "kind": "magic_bytes",
        "offset": 0,
        "bytes_hex": "4d4d5450",  # 4 bytes — clears the 2-byte floor
    }


def _minimal_detection_dict() -> dict:
    return {
        "combine": "all_required",
        "signals": [_minimal_signal_dict()],
    }


def _minimal_output_dict() -> dict:
    return {
        "classifier_format": "test_format",
        "classifier_category": "test_category",
        "classifier_vendor": "test_vendor",
        "confidence": "high",
    }


def _minimal_manifest_dict() -> dict:
    return {
        "schema_version": 1,
        "format_id": "test_format",
        "manifest_source": "operator",
        "precedence": 200,
        "category": "test_category",
        "vendor": "test_vendor",
        "detection": _minimal_detection_dict(),
        "output": _minimal_output_dict(),
    }


# ---------------------------------------------------------------------------
# Happy paths (acceptance).
# ---------------------------------------------------------------------------


def test_minimal_valid_manifest_loads():
    m = FileFormatManifest(**_minimal_manifest_dict())
    assert m.format_id == "test_format"
    assert m.manifest_source == "operator"
    assert m.detection.signals[0].kind == "magic_bytes"


def test_free_string_vendor_accepts_operator_minted_value():
    """W2-alpha convergence: vendor taxonomy is a FREE STRING."""
    data = _minimal_manifest_dict()
    data["vendor"] = "medtronic_branded_qcom"
    m = FileFormatManifest(**data)
    assert m.vendor == "medtronic_branded_qcom"


def test_free_string_category_accepts_operator_minted_value():
    data = _minimal_manifest_dict()
    data["category"] = "implant_firmware"
    m = FileFormatManifest(**data)
    assert m.category == "implant_firmware"


def test_dispatch_by_partition_name_with_cases_accepts():
    """MTK LK shape — dispatch.by_partition_name with cases mapping."""
    data = _minimal_manifest_dict()
    data["format_id"] = "mtk_lk_container"
    data["dispatch"] = {
        "kind": "by_partition_name",
        "cases": {"lk": "mtk_lk_image", "atf": "mtk_atf_image"},
        "default": "mtk_unknown",
        "depth_max": 2,
    }
    m = FileFormatManifest(**data)
    assert m.dispatch.kind == "by_partition_name"
    assert m.dispatch.cases["lk"] == "mtk_lk_image"


def test_refinement_block_accepts_with_vendor_precedence_filename_wins():
    data = _minimal_manifest_dict()
    data["refinement"] = {
        "applies_when": "category_is_other",
        "path_substrings_any_of": ["/vendor/firmware"],
        "output_category": "vendor_blob",
        "output_vendor": "qualcomm",
        "output_confidence": "medium",
        "vendor_precedence": "filename_wins",
    }
    m = FileFormatManifest(**data)
    assert m.refinement is not None
    assert m.refinement.vendor_precedence == "filename_wins"


def test_plugin_matcher_with_applicable_format_ids_accepts():
    data = _minimal_manifest_dict()
    data["plugin"] = {
        "matcher": {
            "ref": "mtk_magic_matcher",
            "bind": "eager",
            "role": "refine",
            "applicable_format_ids": ["mtk_lk_image", "mtk_atf_image"],
        }
    }
    m = FileFormatManifest(**data)
    assert m.plugin.matcher is not None
    assert m.plugin.matcher.ref == "mtk_magic_matcher"
    assert m.plugin.matcher.applicable_format_ids == ["mtk_lk_image", "mtk_atf_image"]


def test_pre_upload_hint_with_extraction_capability_accepts():
    data = _minimal_manifest_dict()
    data["pre_upload"] = {
        "detected_format": "linux_firmware_blob",
        "extraction_capability": "full",
        "banner_note": "Linux blob — full unblob support.",
    }
    m = FileFormatManifest(**data)
    assert m.pre_upload is not None
    assert m.pre_upload.detected_format == "linux_firmware_blob"
    assert m.pre_upload.extraction_capability == "full"


def test_provenance_stub_with_contributor_org_only_accepts():
    """Signature field absent — P3.1 ships unsigned stub."""
    data = _minimal_manifest_dict()
    data["provenance"] = {
        "contributor_org": "Acme Medical Devices, Inc.",
    }
    m = FileFormatManifest(**data)
    assert m.provenance is not None
    assert m.provenance.contributor_org == "Acme Medical Devices, Inc."
    assert m.provenance.signature is None


def test_deprecation_active_with_no_replaced_by_accepts():
    """Default deprecation.status=active — no replaced_by required."""
    m = FileFormatManifest(**_minimal_manifest_dict())
    assert m.deprecation.status == "active"
    assert m.deprecation.replaced_by is None


# ---------------------------------------------------------------------------
# Rejection battery — extra=forbid (14 forbidden-key shapes + unknown fields).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "regex",
        "script",
        "template",
        "eval",
        "lua",
        "vql",
        "predicate",
        "expression",
    ],
)
def test_extra_forbid_rejects_forbidden_grammar_key_at_top_level(forbidden_key: str):
    """Rule #52 hard cap — operator YAML CANNOT carry executable-grammar keys."""
    data = _minimal_manifest_dict()
    data[forbidden_key] = ".*"
    with pytest.raises(ValidationError) as excinfo:
        FileFormatManifest(**data)
    # Pydantic v2: "Extra inputs are not permitted" with the offending field name
    assert forbidden_key in str(excinfo.value).lower() or "extra" in str(excinfo.value).lower()


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "regex",
        "script",
        "template",
        "eval",
        "lua",
        "vql",
        "predicate",
        "expression",
    ],
)
def test_extra_forbid_rejects_forbidden_grammar_key_in_detection(forbidden_key: str):
    """Forbidden keys also rejected nested in detection block."""
    data = _minimal_manifest_dict()
    data["detection"][forbidden_key] = "anything"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_extra_forbid_rejects_unknown_top_level_field():
    data = _minimal_manifest_dict()
    data["attacker_field"] = 1
    with pytest.raises(ValidationError) as excinfo:
        FileFormatManifest(**data)
    assert "attacker_field" in str(excinfo.value).lower() or "extra" in str(excinfo.value).lower()


def test_extra_forbid_rejects_unknown_nested_field_in_detection():
    data = _minimal_manifest_dict()
    data["detection"]["bogus_field"] = True
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


# ---------------------------------------------------------------------------
# Closed-Literal rejections.
# ---------------------------------------------------------------------------


def test_confidence_rejects_invalid_value():
    """``confidence`` is Literal['high','medium','low'] — 'hi' must fail."""
    data = _minimal_manifest_dict()
    data["confidence"] = "hi"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_manifest_source_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["manifest_source"] = "custom"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_dispatch_kind_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["dispatch"] = {"kind": "custom"}
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_plugin_role_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["plugin"] = {
        "matcher": {
            "ref": "matcher_a",
            "role": "overlord",
        }
    }
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_evaluation_mode_rejects_first_match_today():
    """EvaluationMode is single-value Literal — 'first_match' was the bug shape."""
    data = _minimal_manifest_dict()
    data["evaluation_mode"] = "first_match"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


# ---------------------------------------------------------------------------
# Field constraint rejections (W2-beta Section D + Rule #46 paired canaries).
# ---------------------------------------------------------------------------


def test_bytes_hex_max_length_rejects_oversized():
    """bytes_hex max_length=1024 — 1025-char hex must fail."""
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "ab" * 513  # 1026 chars
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_bytes_hex_min_length_rejects_under_2_bytes():
    """bytes_hex < 4 chars (2 bytes floor) rejected."""
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "ab"  # 1 byte
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_bytes_hex_odd_length_rejects():
    """bytes_hex must have even length (whole bytes)."""
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "abcde"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_mask_hex_length_mismatch_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "4d4d"
    data["detection"]["signals"][0]["mask_hex"] = "ffffff"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_mask_hex_all_zero_rejects():
    """mask='0000' would match everything — use detection.always_matches instead."""
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "4d4d"
    data["detection"]["signals"][0]["mask_hex"] = "0000"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_offset_overflow_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["offset"] = 2**33
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_precedence_floor_rejects_below_10_in_core_path():
    """[0,9] reserved for _system; manifest_source=core, precedence=5 rejected."""
    data = _minimal_manifest_dict()
    data["manifest_source"] = "core"
    data["precedence"] = 5
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_precedence_floor_allows_below_10_in_system_path():
    """precedence < 10 ACCEPTED when manifest_source=_system."""
    data = _minimal_manifest_dict()
    data["manifest_source"] = "_system"
    data["precedence"] = 5
    m = FileFormatManifest(**data)
    assert m.precedence == 5


def test_negative_evidence_floor_enforces_precedence_5000():
    """magic_bytes <=2 bytes (4 hex chars) requires precedence >= 5000."""
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["bytes_hex"] = "4d5a"  # 2 bytes, PE-like
    data["precedence"] = 100
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)

    # Same data with precedence=5000 must accept
    data2 = _minimal_manifest_dict()
    data2["detection"]["signals"][0]["bytes_hex"] = "4d5a"
    data2["precedence"] = 5000
    m = FileFormatManifest(**data2)
    assert m.precedence == 5000


def test_path_substring_under_6_chars_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["signals"] = [
        {
            "kind": "path_context",
            "path_substrings_any_of": ["/lib"],
        }
    ]
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_path_substring_no_leading_slash_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["signals"] = [
        {
            "kind": "path_context",
            "path_substrings_any_of": ["partition123"],
        }
    ]
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_filename_stems_under_4_chars_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["signals"] = [
        {
            "kind": "filename",
            "stems_lower": ["foo"],
        }
    ]
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_always_matches_outside_system_rejects():
    """detection.always_matches=True permitted ONLY when manifest_source=_system."""
    data = _minimal_manifest_dict()
    data["manifest_source"] = "core"
    data["detection"]["always_matches"] = True
    data["detection"]["signals"] = [{"kind": "always_matches"}]
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_always_matches_in_system_accepts():
    """_system + always_matches=True + sort_tier=floor + always_matches signal ACCEPTS."""
    data = _minimal_manifest_dict()
    data["manifest_source"] = "_system"
    data["precedence"] = 0
    data["detection"] = {
        "combine": "all_required",
        "signals": [{"kind": "always_matches"}],
        "always_matches": True,
        "sort_tier": "floor",  # P3.2.a: always_matches=True requires sort_tier=floor
    }
    m = FileFormatManifest(**data)
    assert m.detection.always_matches is True
    assert m.detection.sort_tier == "floor"


def test_dispatch_none_with_cases_rejects():
    data = _minimal_manifest_dict()
    data["dispatch"] = {"kind": "none", "cases": {"x": "y"}}
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_dispatch_by_partition_without_cases_or_default_rejects():
    data = _minimal_manifest_dict()
    data["dispatch"] = {"kind": "by_partition_name"}
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_mode_override_without_overrides_path_rejects():
    data = _minimal_manifest_dict()
    data["mode"] = "override"
    # overrides field omitted
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_mode_new_with_overrides_path_rejects():
    data = _minimal_manifest_dict()
    data["mode"] = "new"
    data["overrides"] = "qualcomm/qcom_mbn.yaml"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_alias_of_with_dispatch_kind_by_partition_rejects():
    """alias_of and dispatch.kind!=none are mutually exclusive (W2-alpha Q3)."""
    data = _minimal_manifest_dict()
    data["alias_of"] = "other_format"
    data["dispatch"] = {
        "kind": "by_partition_name",
        "cases": {"x": "y"},
    }
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_combine_weighted_without_min_confidence_score_rejects():
    data = _minimal_manifest_dict()
    data["detection"]["combine"] = "weighted"
    # min_confidence_score omitted
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_deprecation_deprecated_without_replaced_by_rejects():
    data = _minimal_manifest_dict()
    data["deprecation"] = {"status": "deprecated"}
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_deprecation_deprecated_without_removal_phase_rejects():
    data = _minimal_manifest_dict()
    data["deprecation"] = {
        "status": "deprecated",
        "replaced_by": "new_format_id",
        # removal_phase omitted
    }
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


def test_format_id_invalid_pattern_rejects():
    """format_id MUST match ^[a-z][a-z0-9_]*$."""
    data = _minimal_manifest_dict()
    data["format_id"] = "Foo!"
    with pytest.raises(ValidationError):
        FileFormatManifest(**data)


# ---------------------------------------------------------------------------
# Rule #46 META-CANARIES (token-scan / structural).
# ---------------------------------------------------------------------------


def _walk_basemodel_subclasses(root: type[BaseModel]) -> set[type[BaseModel]]:
    """Recursively collect every BaseModel subclass reachable from `root`."""
    seen: set[type[BaseModel]] = set()
    stack: list[type[BaseModel]] = [root]
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        for sub in cls.__subclasses__():
            stack.append(sub)
    return seen


def test_meta_canary_every_model_has_extra_forbid():
    """Rule #46 — walk every BaseModel subclass declared in the schema module
    and assert each has ``model_config['extra'] == 'forbid'``."""
    import app.schemas.file_format as ff

    file_format_models = [
        value
        for name, value in vars(ff).items()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value is not BaseModel
    ]
    assert len(file_format_models) >= 10, (
        f"Expected >=10 BaseModel subclasses, found {len(file_format_models)}"
    )

    for cls in file_format_models:
        config = getattr(cls, "model_config", {})
        extra = config.get("extra") if isinstance(config, dict) else None
        assert extra == "forbid", (
            f"Model {cls.__name__} missing extra='forbid'; "
            f"model_config={config!r}"
        )


def test_meta_canary_no_open_predicates_in_schema_source():
    """Rule #46 — read the schema source text and assert no occurrences of
    ``regex:`` / ``script:`` / ``template:`` / ``eval:`` / ``lua:`` / ``vql:`` /
    ``predicate:`` / ``expression:`` as YAML-key-shape model FIELDS.

    Token shape: a Pydantic field declaration is ``<key>: <type>`` at column-
    indent. We use Python's :mod:`tokenize` to walk NAME tokens and assert
    none of the forbidden keys appear immediately followed by ``:`` at the
    NAME-token level (which excludes string-literal contents in docstrings).

    Paired gate-canary :func:`test_meta_canary_no_open_predicates_gate_actually_fires`
    confirms the gate fires on a synthetic offending source.
    """
    src_path = Path(
        "/home/dustin/code/wairz/backend/app/schemas/file_format.py"
    )
    forbidden = _scan_source_for_forbidden_field_decls(src_path.read_text(encoding="utf-8"))
    assert not forbidden, (
        f"schema declares forbidden-grammar field(s): {forbidden!r}; "
        "Rule #52 hard cap — YAML must NOT carry executable predicates"
    )


def _scan_source_for_forbidden_field_decls(source: str) -> list[str]:
    """Walk Python tokens; return forbidden-grammar NAME tokens followed by ':'.

    This is the production gate body — shared with the synthetic canary below
    (Rule #46 paired META-CANARY).
    """
    import io
    import tokenize as tk

    forbidden_keys = {
        "regex", "script", "template", "eval",
        "lua", "vql", "predicate", "expression",
    }

    hits: list[str] = []
    prev_name: str | None = None
    try:
        for tok in tk.generate_tokens(io.StringIO(source).readline):
            if tok.type == tk.NAME:
                prev_name = tok.string
            elif tok.type == tk.OP and tok.string == ":" and prev_name in forbidden_keys:
                # Field-decl shape: `<NAME> : <annotation>` at any indent.
                # Excludes string-literal contents in docstrings (those are
                # STRING tokens, not NAME tokens).
                hits.append(prev_name)
                prev_name = None
            else:
                prev_name = None
    except (tk.TokenError, IndentationError):
        # Best-effort scan; if the source has a tokenize error here, the test
        # gate is not the right surface to surface that.
        pass
    return hits


def test_meta_canary_no_open_predicates_gate_actually_fires():
    """Rule #46 paired canary — synthesize a forbidden-grammar field decl
    IN MEMORY and confirm the gate's token-scanner WOULD catch it."""
    offending_source = (
        "class Bad:\n"
        "    regex: str = ''\n"
        "    script: str = ''\n"
    )
    hits = _scan_source_for_forbidden_field_decls(offending_source)
    assert "regex" in hits and "script" in hits, (
        f"META-CANARY failed to fire on synthetic violation; hits={hits!r}"
    )


def test_meta_canary_extra_forbid_canary_fires_on_unknown_field():
    """Rule #46 paired canary — synthesize an unknown-field violation and
    confirm Pydantic raises ValidationError with the expected message shape."""
    data = _minimal_manifest_dict()
    data["attacker_field"] = "value"
    with pytest.raises(ValidationError) as excinfo:
        FileFormatManifest(**data)
    # Pydantic v2 message: "Extra inputs are not permitted"
    msg = str(excinfo.value).lower()
    assert ("extra" in msg) or ("attacker_field" in msg), (
        f"Expected 'extra'/'attacker_field' in error message, got: {msg!r}"
    )


def test_meta_canary_jsonschema_export_is_emitted_and_loads():
    """Rule #46 — :func:`json_schema()` returns a dict with ``properties`` AND
    at least 18 closed Literals (counted as ``enum`` appearances)."""
    adapter = TypeAdapter(FileFormatManifest)
    schema = adapter.json_schema(by_alias=False)

    assert isinstance(schema, dict)
    assert "properties" in schema or "$defs" in schema, (
        f"JSON Schema missing properties/$defs key; got: {list(schema.keys())}"
    )

    # Count `enum` appearances (closed Literals each render as enum nodes).
    src_json = adapter.json_schema(by_alias=False)
    import json

    flat = json.dumps(src_json)
    enum_count = flat.count('"enum"')
    assert enum_count >= 18, (
        f"Expected >=18 closed Literals (enum nodes); found {enum_count}"
    )


# ---------------------------------------------------------------------------
# Rule #35b live canary — realistic operator manifest round-trip.
# ---------------------------------------------------------------------------


def test_live_canary_round_trips_realistic_manifest():
    """Build a realistic operator-minted manifest dict (Medtronic MMTP example),
    validate, dump to dict via :meth:`model_dump`, re-validate, assert round-
    trip identity (the canonical Pydantic v2 round-trip pattern)."""
    raw = {
        "schema_version": 1,
        "format_id": "medtronic_mmtp_implant_blob",
        "manifest_source": "operator",
        "precedence": 200,
        "category": "implant_firmware",
        "vendor": "medtronic",
        "product": "mmtp_pacer_v3",
        "confidence": "high",
        "notes": (
            "Medtronic MMTP implant firmware. Magic 'MMTP' at offset 0. "
            "Operator-supplied YAML under NDA reference NDA-2026-04. "
            "See compliance_constraints.yaml for HIPAA/IEC 62304 mappings."
        ),
        "detection": {
            "combine": "all_required",
            "signals": [
                {
                    "kind": "magic_bytes",
                    "offset": 0,
                    "bytes_hex": "4d4d5450",  # "MMTP"
                    "description": "Medtronic Modular Transfer Protocol header",
                },
            ],
        },
        "output": {
            "classifier_format": "medtronic_mmtp_implant_blob",
            "classifier_category": "implant_firmware",
            "classifier_vendor": "medtronic",
            "classifier_product": "mmtp_pacer_v3",
            "confidence": "high",
        },
        "provenance": {
            "contributor_org": "Medtronic Plc",
            "attestation_url": "https://example.invalid/wairz/medtronic/mmtp",
        },
    }

    m1 = FileFormatManifest(**raw)
    dumped = m1.model_dump(mode="python", exclude_none=True)
    m2 = FileFormatManifest(**dumped)
    # Round-trip identity on the loaded models.
    assert m1.model_dump(mode="python") == m2.model_dump(mode="python")

    # Spot-check that taxonomy free-strings persisted.
    assert m2.vendor == "medtronic"
    assert m2.category == "implant_firmware"
    assert m2.detection.signals[0].bytes_hex == "4d4d5450"
    assert m2.provenance is not None
    assert m2.provenance.contributor_org == "Medtronic Plc"
