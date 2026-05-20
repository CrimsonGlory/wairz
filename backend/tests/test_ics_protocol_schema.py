"""ICS protocol schema tests — closed-grammar Pydantic Literals + cross-field invariants.

Session 1 Commit 1 — Rule #52 third worked-example application.

Coverage:
1. Closed Literal acceptance (all 11 ICS Literals — exhaustive value tests)
2. extra='forbid' rejection on every model
3. Cross-field invariants (precedence floor [0,9] reserved to _system;
   kind ⇔ constraint required-when + symmetric-reject pair)
4. Per-signal-kind field validators (magic_bytes / port_signature /
   function_code_set / string_in_binary / library_symbol)
5. Rule #46 paired META-CANARIES — Literal exhaustive checks +
   synthesize-and-assert canaries confirming gates would catch violations

Session 2 will extend with: Plugin/PluginRef tests, Refinement tests,
Dispatch tests, ProvenanceStub tests, IcsCategory tests when those
sub-models ship.
"""
from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from app.schemas.ics_protocol import (
    IcsArtifactSource,
    IcsCertainty,
    IcsCombine,
    IcsConfidence,
    IcsDeprecationStatus,
    IcsDetection,
    IcsDetectionSignal,
    IcsFunctionCodeSetConstraint,
    IcsLayer,
    IcsManifestSource,
    IcsOutput,
    IcsProtocolFamily,
    IcsProtocolManifest,
    IcsProtocolMatch,
    IcsSignalKind,
    IcsStringInBinaryConstraint,
    IcsTransport,
    IcsVendorAuthority,
)

# ---------------------------------------------------------------------------
# Helpers — build minimal valid manifests
# ---------------------------------------------------------------------------


_MODBUS_NEEDLE = "4d6f64627573"  # "Modbus" — 6 bytes


def _minimal_signal() -> IcsDetectionSignal:
    return IcsDetectionSignal(
        kind="magic_bytes",
        offset=0,
        bytes_hex="00000300",  # arbitrary 4-byte magic
    )


def _minimal_detection() -> IcsDetection:
    return IcsDetection(signals=[_minimal_signal()])


def _minimal_output() -> IcsOutput:
    return IcsOutput(
        protocol_family="modbus_tcp",
        layer="transport",
        transport="tcp",
        vendor="generic",
    )


def _minimal_manifest_dict(
    *,
    manifest_id: str = "test_modbus",
    manifest_source: str = "core",
    precedence: int = 100,
) -> dict:
    return {
        "schema_version": 1,
        "manifest_id": manifest_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "detection": {
            "combine": "all_required",
            "signals": [{
                "kind": "magic_bytes",
                "offset": 0,
                "bytes_hex": "00000300",
            }],
        },
        "output": {
            "protocol_family": "modbus_tcp",
            "layer": "transport",
            "transport": "tcp",
            "vendor": "generic",
        },
    }


# ---------------------------------------------------------------------------
# Top-level manifest acceptance
# ---------------------------------------------------------------------------


def test_minimal_valid_manifest_loads():
    m = IcsProtocolManifest(**_minimal_manifest_dict())
    assert m.manifest_id == "test_modbus"
    assert m.manifest_source == "core"
    assert m.precedence == 100
    assert m.detection.combine == "all_required"
    assert m.detection.certainty == "stack_present"  # default
    assert m.deprecation.status == "active"  # default
    assert m.output.protocol_family == "modbus_tcp"
    assert m.output.confidence == "medium"  # default


def test_minimal_manifest_with_attested_external_loads():
    data = _minimal_manifest_dict(
        manifest_id="partner_dnp3", manifest_source="attested_external",
    )
    m = IcsProtocolManifest(**data)
    assert m.manifest_source == "attested_external"


def test_free_string_vendor_accepts_operator_minted_value():
    data = _minimal_manifest_dict()
    data["output"]["vendor"] = "codesys_3_5"  # operator-minted free string
    m = IcsProtocolManifest(**data)
    assert m.output.vendor == "codesys_3_5"


# ---------------------------------------------------------------------------
# precedence floor [0, 9] RESERVED to _system
# ---------------------------------------------------------------------------


def test_precedence_floor_rejects_below_10_in_core_path():
    data = _minimal_manifest_dict(manifest_source="core", precedence=5)
    with pytest.raises(ValidationError) as exc:
        IcsProtocolManifest(**data)
    assert "precedence" in str(exc.value)
    assert "_system" in str(exc.value)


def test_precedence_floor_accepts_below_10_in_system_path():
    data = _minimal_manifest_dict(manifest_source="_system", precedence=5)
    m = IcsProtocolManifest(**data)
    assert m.precedence == 5


def test_precedence_floor_rejects_below_10_in_operator_path():
    data = _minimal_manifest_dict(manifest_source="operator", precedence=0)
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_precedence_floor_rejects_below_10_in_unauthenticated_external_path():
    data = _minimal_manifest_dict(
        manifest_source="unauthenticated_external", precedence=3,
    )
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


# ---------------------------------------------------------------------------
# extra='forbid' discipline — exhaustive across nested models
# ---------------------------------------------------------------------------


def test_extra_forbid_rejects_unknown_top_level_field():
    data = _minimal_manifest_dict()
    data["unknown_field"] = "bogus"
    with pytest.raises(ValidationError) as exc:
        IcsProtocolManifest(**data)
    assert "unknown_field" in str(exc.value) or "Extra inputs" in str(exc.value)


def test_extra_forbid_rejects_unknown_field_in_detection():
    data = _minimal_manifest_dict()
    data["detection"]["unknown"] = 42
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_extra_forbid_rejects_unknown_field_in_signal():
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["unknown"] = 42
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_extra_forbid_rejects_unknown_field_in_output():
    data = _minimal_manifest_dict()
    data["output"]["unknown"] = 42
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_extra_forbid_rejects_regex_key_at_top_level():
    """Rule #52 closed-grammar: regex / script / template / eval forbidden."""
    for forbidden in ("regex", "script", "template", "eval", "lua",
                       "vql", "predicate", "expression"):
        data = _minimal_manifest_dict()
        data[forbidden] = "bogus_pattern"
        with pytest.raises(ValidationError):
            IcsProtocolManifest(**data)


def test_extra_forbid_rejects_regex_key_in_detection():
    """Rule #52 — depth-2 forbidden-key cover."""
    for forbidden in ("regex", "script", "template", "eval"):
        data = _minimal_manifest_dict()
        data["detection"][forbidden] = "bogus"
        with pytest.raises(ValidationError):
            IcsProtocolManifest(**data)


# ---------------------------------------------------------------------------
# Closed-Literal rejection (per-Literal coverage)
# ---------------------------------------------------------------------------


def test_manifest_source_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["manifest_source"] = "external_unsigned"  # wrong spelling
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_protocol_family_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["output"]["protocol_family"] = "modbus"  # missing _tcp suffix
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_layer_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["output"]["layer"] = "presentation"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_transport_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["output"]["transport"] = "websocket"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_signal_kind_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["detection"]["signals"][0]["kind"] = "yara_rule"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_combine_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["detection"]["combine"] = "first_match"  # forbidden per Wave-1 S5
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_certainty_rejects_invalid_value():
    data = _minimal_manifest_dict()
    data["detection"]["certainty"] = "definite"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


# ---------------------------------------------------------------------------
# Signal-kind ⇔ constraint pairing (required-when + symmetric-reject)
# ---------------------------------------------------------------------------


def test_magic_bytes_signal_requires_bytes_hex_and_offset():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="magic_bytes")
    assert "bytes_hex" in str(exc.value) or "offset" in str(exc.value)


def test_magic_bytes_rejects_under_2_bytes():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="magic_bytes", offset=0, bytes_hex="aa")
    assert "minimum 2 bytes" in str(exc.value) or "min" in str(exc.value).lower()


def test_magic_bytes_rejects_odd_hex_length():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="magic_bytes", offset=0, bytes_hex="aabbc")
    assert "even" in str(exc.value).lower()


def test_magic_bytes_mask_all_zero_rejected():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(
            kind="magic_bytes", offset=0, bytes_hex="abcdef01",
            mask_hex="00000000",
        )
    assert "all-zero" in str(exc.value)


def test_magic_bytes_mask_length_mismatch_rejected():
    with pytest.raises(ValidationError):
        IcsDetectionSignal(
            kind="magic_bytes", offset=0, bytes_hex="abcd",
            mask_hex="abcdef",
        )


def test_port_signature_requires_ports_list():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="port_signature")
    assert "ports" in str(exc.value)


def test_port_signature_rejects_invalid_port_range():
    with pytest.raises(ValidationError):
        IcsDetectionSignal(kind="port_signature", ports=[0])
    with pytest.raises(ValidationError):
        IcsDetectionSignal(kind="port_signature", ports=[70000])


def test_function_code_set_signal_requires_constraint():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="function_code_set")
    assert "function_code_constraint" in str(exc.value)


def test_function_code_set_constraint_on_wrong_kind_symmetric_reject():
    """Constraint set on wrong kind = mis-author error (symmetric reject)."""
    constraint = IcsFunctionCodeSetConstraint(
        function_codes_hex=["01", "03", "05"], min_count=2,
    )
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(
            kind="magic_bytes", offset=0, bytes_hex="0001",
            function_code_constraint=constraint,
        )
    assert "function_code_constraint" in str(exc.value)


def test_function_code_constraint_rejects_single_code():
    """min_length=2 floor — single-byte triggers rejected (W2-β A8 floor)."""
    with pytest.raises(ValidationError):
        IcsFunctionCodeSetConstraint(function_codes_hex=["01"], min_count=1)


def test_function_code_constraint_rejects_min_count_exceeds_codes():
    with pytest.raises(ValidationError) as exc:
        IcsFunctionCodeSetConstraint(
            function_codes_hex=["01", "03"], min_count=5,
        )
    assert "min_count" in str(exc.value)


def test_function_code_constraint_rejects_multibyte_codes():
    with pytest.raises(ValidationError) as exc:
        IcsFunctionCodeSetConstraint(
            function_codes_hex=["0101", "0303"], min_count=2,
        )
    assert "1 byte" in str(exc.value) or "exactly 2 hex" in str(exc.value)


def test_string_in_binary_signal_requires_constraint():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="string_in_binary")
    assert "string_in_binary_constraint" in str(exc.value)


def test_string_in_binary_constraint_on_wrong_kind_symmetric_reject():
    constraint = IcsStringInBinaryConstraint(needles_hex=[_MODBUS_NEEDLE])
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(
            kind="magic_bytes", offset=0, bytes_hex="0001",
            string_in_binary_constraint=constraint,
        )
    assert "string_in_binary_constraint" in str(exc.value)


def test_string_in_binary_rejects_under_2_byte_needle():
    with pytest.raises(ValidationError):
        IcsStringInBinaryConstraint(needles_hex=["aa"])


def test_string_in_binary_rejects_too_many_needles():
    needles = [_MODBUS_NEEDLE] * 17  # 17 > max=16
    with pytest.raises(ValidationError):
        IcsStringInBinaryConstraint(needles_hex=needles)


def test_string_in_binary_rejects_invalid_hex():
    with pytest.raises(ValidationError):
        IcsStringInBinaryConstraint(needles_hex=["zzzz"])


def test_string_in_binary_min_count_above_needle_count_rejected():
    with pytest.raises(ValidationError) as exc:
        IcsStringInBinaryConstraint(needles_hex=[_MODBUS_NEEDLE], min_count=2)
    assert "min_count" in str(exc.value)


def test_library_symbol_signal_requires_symbol_patterns():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(kind="library_symbol")
    assert "symbol_patterns_lower" in str(exc.value)


def test_library_symbol_rejects_under_5_char_pattern():
    with pytest.raises(ValidationError):
        IcsDetectionSignal(kind="library_symbol", symbol_patterns_lower=["mb"])


def test_library_symbol_rejects_uppercase_pattern():
    with pytest.raises(ValidationError) as exc:
        IcsDetectionSignal(
            kind="library_symbol", symbol_patterns_lower=["MODBUS_NEW"],
        )
    assert "lowercased" in str(exc.value)


# ---------------------------------------------------------------------------
# IcsDetection combine semantics
# ---------------------------------------------------------------------------


def test_detection_weighted_requires_min_confidence_score():
    with pytest.raises(ValidationError) as exc:
        IcsDetection(combine="weighted", signals=[_minimal_signal()])
    assert "min_confidence_score" in str(exc.value)


def test_detection_weighted_with_score_accepts():
    d = IcsDetection(
        combine="weighted", signals=[_minimal_signal()],
        min_confidence_score=50.0,
    )
    assert d.combine == "weighted"


def test_detection_max_signals_16():
    """Cap at 16 — Wave-1 S5 cost bound."""
    with pytest.raises(ValidationError):
        IcsDetection(signals=[_minimal_signal()] * 17)


# ---------------------------------------------------------------------------
# Manifest-id pattern
# ---------------------------------------------------------------------------


def test_manifest_id_rejects_uppercase():
    data = _minimal_manifest_dict()
    data["manifest_id"] = "TEST_MODBUS"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_manifest_id_rejects_path_traversal():
    data = _minimal_manifest_dict()
    data["manifest_id"] = "../../etc/passwd"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


def test_manifest_id_rejects_starting_digit():
    data = _minimal_manifest_dict()
    data["manifest_id"] = "1modbus"
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


# ---------------------------------------------------------------------------
# Schema version pinned to 1
# ---------------------------------------------------------------------------


def test_schema_version_must_be_1():
    data = _minimal_manifest_dict()
    data["schema_version"] = 2
    with pytest.raises(ValidationError):
        IcsProtocolManifest(**data)


# ---------------------------------------------------------------------------
# Rule #46 META-CANARY — closed Literal exhaustive checks
# ---------------------------------------------------------------------------


def test_meta_canary_protocol_family_literal_pinned():
    """Rule #46: lock the v0 IcsProtocolFamily Literal at 5 values.
    Adding a value requires Rule #25 Shape-1 cross-stack alignment (DB CHECK
    + frontend Config mirror + alignment test) in the SAME commit."""
    expected = {
        "modbus_tcp", "modbus_rtu", "dnp3", "s7comm", "unknown_ics",
    }
    actual = set(get_args(IcsProtocolFamily))
    assert actual == expected, (
        f"IcsProtocolFamily Literal drift: missing={expected - actual}, "
        f"extra={actual - expected}. Drift requires Rule #25 Shape-1 commit."
    )


def test_meta_canary_protocol_family_literal_pinned_gate_actually_fires():
    """Rule #46 paired canary — synthesize a truncated Literal value set +
    assert the exhaustive check would REJECT it."""
    expected = set(get_args(IcsProtocolFamily))
    truncated = expected - {"dnp3"}  # synthetic drift
    with pytest.raises(AssertionError):
        assert truncated == expected


def test_meta_canary_signal_kind_literal_pinned():
    expected = {
        "magic_bytes", "port_signature", "function_code_set",
        "string_in_binary", "library_symbol",
    }
    actual = set(get_args(IcsSignalKind))
    assert actual == expected, (
        f"IcsSignalKind Literal drift: missing={expected - actual}, "
        f"extra={actual - expected}."
    )


def test_meta_canary_signal_kind_literal_pinned_gate_actually_fires():
    expected = set(get_args(IcsSignalKind))
    truncated = expected - {"magic_bytes"}
    with pytest.raises(AssertionError):
        assert truncated == expected


def test_meta_canary_manifest_source_literal_pinned():
    expected = {
        "_system", "core", "operator", "attested_external",
        "unauthenticated_external",
    }
    actual = set(get_args(IcsManifestSource))
    assert actual == expected


def test_meta_canary_layer_literal_pinned():
    expected = {"application", "transport", "data_link", "session"}
    actual = set(get_args(IcsLayer))
    assert actual == expected


def test_meta_canary_transport_literal_pinned():
    expected = {"tcp", "udp", "ethernet_raw", "serial_rs485", "any"}
    actual = set(get_args(IcsTransport))
    assert actual == expected


def test_meta_canary_artifact_source_literal_pinned():
    expected = {"binary", "config_file", "embedded_blob", "any"}
    actual = set(get_args(IcsArtifactSource))
    assert actual == expected


def test_meta_canary_certainty_literal_pinned():
    expected = {"stack_present", "config_present", "string_only"}
    actual = set(get_args(IcsCertainty))
    assert actual == expected


def test_meta_canary_combine_literal_pinned():
    expected = {"all_required", "any", "weighted"}
    actual = set(get_args(IcsCombine))
    assert actual == expected


def test_meta_canary_confidence_literal_pinned():
    expected = {"high", "medium", "low"}
    actual = set(get_args(IcsConfidence))
    assert actual == expected


def test_meta_canary_deprecation_status_literal_pinned():
    expected = {"active", "deprecated", "removed"}
    actual = set(get_args(IcsDeprecationStatus))
    assert actual == expected


def test_meta_canary_vendor_authority_literal_pinned():
    expected = {"curated", "operator_supplied", "community"}
    actual = set(get_args(IcsVendorAuthority))
    assert actual == expected


# ---------------------------------------------------------------------------
# IcsProtocolMatch result type
# ---------------------------------------------------------------------------


def test_protocol_match_result_type_accepts():
    m = IcsProtocolMatch(
        manifest_id="modbus_tcp",
        manifest_source="_system",
        protocol_family="modbus_tcp",
        layer="transport",
        transport="tcp",
        vendor="generic",
        vendor_product=None,
        protocol_version=None,
        confidence="high",
        certainty="stack_present",
        matched_signals=["magic_bytes", "function_code_set"],
    )
    assert m.protocol_family == "modbus_tcp"
    assert m.matched_signals == ["magic_bytes", "function_code_set"]


def test_protocol_match_extra_forbid():
    with pytest.raises(ValidationError):
        IcsProtocolMatch(
            manifest_id="modbus_tcp",
            manifest_source="_system",
            protocol_family="modbus_tcp",
            layer="transport",
            transport="tcp",
            vendor="generic",
            vendor_product=None,
            protocol_version=None,
            confidence="high",
            certainty="stack_present",
            matched_signals=[],
            unknown="bogus",
        )
