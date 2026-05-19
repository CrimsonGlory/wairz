"""Schema-grammar tests for the bare-metal chip-family manifest.

Acts as the canary that closed-grammar Pydantic Literals + ``extra='forbid'``
actually reject everything they should. Pairs with the walker's
``test_walker_no_decrypt_gate_actually_fires`` per CLAUDE.md Rule #46: every
absence-asserting gate ships with a synthetic-violation canary in the same
file as the gate.

When you extend the schema (add a new ``RegionSemantic`` value, a new
``PolicyOperator``, a new ``Arch``, etc.) per Rule #25 single-slice
cross-stack alignment, add the new value to the happy-path test AND extend
the rejection battery to confirm the OLD vocabulary still rejects the NEW
keyword absent the schema update — Rule #46 META-CANARY discipline.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.chip_family import (
    AddressRegion,
    ChipDescriptor,
    ChipFamilyManifest,
    ChipMatch,
    DetectionSignal,
    Domain,
    GhidraImportParams,
    PolicyRule,
)


# ---------------------------------------------------------------------------
# Happy paths.
# ---------------------------------------------------------------------------


def _build_f28066_manifest() -> ChipFamilyManifest:
    """Reusable F28066 manifest mirroring the catalog YAML's intent."""
    return ChipFamilyManifest(
        schema_version=1,
        vendor="ti",
        family="tms320f28066",
        display_name="TI TMS320F28066 (Piccolo F2806x)",
        domains=[
            Domain(
                name="c28x_core",
                arch="tms320c28x",
                endianness="little",
                instruction_word_bits=16,
                data_word_bits=16,
                address_bus_bits=22,
                packing="two_bytes_per_word_le",
                address_regions=[
                    AddressRegion(
                        name="flash_main",
                        start=0x3D8000,
                        end=0x3F7FF7,
                        access="read-execute",
                        semantic=["flash_code"],
                    ),
                    AddressRegion(
                        name="csm_pwl",
                        start=0x3F7FF8,
                        size=8,
                        access="secret",
                        semantic=["security_password_csm"],
                        policy=[
                            PolicyRule(
                                operator="unsecure_when_all_words_equal",
                                value_hex="FFFF",
                                word_size_bits=16,
                                cwe_ids=[1273, 1191],
                                severity="high",
                                finding_source="c28x_unsecure_csm",
                                description="all-0xFFFF PWL = JTAG unlocked",
                            ),
                        ],
                    ),
                    AddressRegion(
                        name="boot_rom",
                        start=0x3FF000,
                        size=0x1000,
                        access="read-execute",
                        semantic=["boot_rom"],
                    ),
                ],
                ghidra_import_params=GhidraImportParams(
                    processor="TMS320C28x:LE:32:default",
                    base_addr=0x3D8000,
                ),
            ),
        ],
    )


def test_happy_path_f28066_manifest_validates():
    m = _build_f28066_manifest()
    assert m.family_id == "ti/tms320f28066"
    assert m.domain_id("c28x_core") == "ti/tms320f28066/c28x_core"
    assert m.domains[0].address_regions[1].policy[0].cwe_ids == [1273, 1191]


def test_chip_match_serialises():
    cm = ChipMatch(
        family_id="ti/tms320f28066",
        domain_name="c28x_core",
        confidence=0.85,
        evidence=[{"signal": "silicon_id_byte_match", "weight": 0.4, "score": 0.4}],
    )
    assert cm.domain_id == "ti/tms320f28066/c28x_core"
    payload = cm.model_dump()
    assert payload["descriptor_source"] == "auto_detection"


def test_chip_descriptor_roundtrip_with_inline_family():
    """Operator one-off inline manifest (Scout CC §SC14 path) round-trips."""
    inline = _build_f28066_manifest()
    desc = ChipDescriptor(
        firmware_id="78ad638b-f99b-4cb0-ac28-e36e05846007",
        descriptor_source="operator",
        ingestor_id="manual",
        chip_family_hint="ti/tms320f28066",
        inline_chip_family=inline,
    )
    again = ChipDescriptor.model_validate(desc.model_dump())
    assert again.inline_chip_family is not None
    assert again.inline_chip_family.family_id == "ti/tms320f28066"


def test_alias_overlap_permitted():
    """Aliased regions are allowed to overlap their canonical sibling."""
    d = Domain(
        name="d",
        arch="arm-cortex-m",
        endianness="little",
        instruction_word_bits=32,
        data_word_bits=32,
        address_bus_bits=32,
        address_regions=[
            AddressRegion(name="flash_canonical", start=0x08000000, size=0x40000, semantic=["flash_code"]),
            AddressRegion(name="boot_alias", start=0x00000000, size=0x40000, alias_of="flash_canonical"),
        ],
    )
    assert d.address_regions[1].alias_of == "flash_canonical"


def test_region_size_inferred_from_end():
    r = AddressRegion(name="r", start=0x100, end=0x1FF)
    assert r.size == 0x100


def test_region_end_inferred_from_size():
    r = AddressRegion(name="r", start=0x100, size=0x100)
    assert r.end == 0x1FF


# ---------------------------------------------------------------------------
# Rejection battery — schema-grammar canary.
# ---------------------------------------------------------------------------


def test_reject_unknown_semantic():
    with pytest.raises(ValidationError):
        AddressRegion(name="x", start=0, size=1, semantic=["definitely_not_a_real_semantic"])  # type: ignore[arg-type]


def test_reject_extra_key_regex_on_region():
    """Confirms ``extra='forbid'`` rejects operator-attempted DSL keys."""
    with pytest.raises(ValidationError):
        AddressRegion.model_validate({"name": "x", "start": 0, "size": 1, "regex": ".*"})


def test_reject_extra_key_script_on_policy():
    with pytest.raises(ValidationError):
        PolicyRule.model_validate({
            "operator": "unsecure_when_all_words_equal",
            "script": "lambda x: True",
        })


def test_reject_extra_key_expression_on_domain():
    with pytest.raises(ValidationError):
        Domain.model_validate({
            "name": "d", "arch": "msp430", "endianness": "little",
            "instruction_word_bits": 16, "data_word_bits": 16, "address_bus_bits": 16,
            "address_regions": [{"name": "r", "start": 0, "size": 1}],
            "expression": "foo",
        })


def test_reject_unknown_arch():
    with pytest.raises(ValidationError):
        Domain.model_validate({
            "name": "d", "arch": "invented_isa", "endianness": "little",
            "instruction_word_bits": 16, "data_word_bits": 16, "address_bus_bits": 16,
            "address_regions": [{"name": "r", "start": 0, "size": 1}],
        })


def test_reject_unknown_ghidra_processor():
    """Whitelist enforcement — operator YAML cannot name an arbitrary plugin."""
    with pytest.raises(ValidationError):
        GhidraImportParams.model_validate({"processor": "Malicious:PluginName", "base_addr": 0})


def test_reject_region_end_outside_address_bus():
    with pytest.raises(ValidationError):
        Domain(
            name="d", arch="msp430", endianness="little",
            instruction_word_bits=16, data_word_bits=16, address_bus_bits=16,
            address_regions=[AddressRegion(name="r", start=0x20000, size=1)],
        )


def test_reject_overlapping_regions_without_alias_of():
    with pytest.raises(ValidationError):
        Domain(
            name="d", arch="msp430", endianness="little",
            instruction_word_bits=16, data_word_bits=16, address_bus_bits=20,
            address_regions=[
                AddressRegion(name="a", start=0, size=0x100),
                AddressRegion(name="b", start=0x50, size=0x100),
            ],
        )


def test_reject_alias_of_orphan():
    with pytest.raises(ValidationError):
        Domain(
            name="d", arch="msp430", endianness="little",
            instruction_word_bits=16, data_word_bits=16, address_bus_bits=20,
            address_regions=[AddressRegion(name="a", start=0, size=1, alias_of="ghost")],
        )


def test_reject_active_when_dsl_key():
    """active_when is closed-shape — only boot_mode key permitted."""
    with pytest.raises(ValidationError):
        AddressRegion(name="x", start=0, size=1, active_when={"cpu_mode": "foo"})


def test_reject_size_end_disagreement():
    with pytest.raises(ValidationError):
        AddressRegion(name="x", start=0x100, size=0x10, end=0x120)


def test_reject_missing_size_and_end():
    with pytest.raises(ValidationError):
        AddressRegion(name="x", start=0)


def test_reject_duplicate_domain_names():
    with pytest.raises(ValidationError):
        ChipFamilyManifest(
            schema_version=1, vendor="ti", family="f", display_name="F",
            domains=[
                Domain(
                    name="c", arch="msp430", endianness="little",
                    instruction_word_bits=16, data_word_bits=16, address_bus_bits=16,
                    address_regions=[AddressRegion(name="r", start=0, size=1)],
                ),
                Domain(
                    name="c", arch="msp430", endianness="little",
                    instruction_word_bits=16, data_word_bits=16, address_bus_bits=16,
                    address_regions=[AddressRegion(name="r", start=0, size=1)],
                ),
            ],
        )


def test_reject_detection_signal_references_unknown_region():
    with pytest.raises(ValidationError):
        Domain(
            name="d", arch="msp430", endianness="little",
            instruction_word_bits=16, data_word_bits=16, address_bus_bits=20,
            address_regions=[AddressRegion(name="a", start=0, size=1)],
            detection_signals=[
                DetectionSignal(kind="silicon_id_byte_match", weight=0.5, region_name="b_does_not_exist"),
            ],
        )


# ---------------------------------------------------------------------------
# Rule #46 META-CANARY — confirm the closed-grammar gate actually fires.
# Generic shape: synthesize a known-bad YAML payload and confirm the schema
# rejects it. Pairs with the rejection battery above — if the META-CANARY
# ever stops failing (i.e. starts ACCEPTING the synthetic), the gate has
# silently broken.
# ---------------------------------------------------------------------------


def test_meta_canary_unknown_semantic_value_rejected():
    """Rule #46: a synthetic violation MUST be rejected by the gate.

    If this test ever passes by accepting ``definitely_not_a_real_semantic``,
    the closed-Literal gate has silently broken — investigate before merging.
    """
    bad_yaml_dict = {
        "name": "synthetic_canary_region",
        "start": 0,
        "size": 1,
        "semantic": ["definitely_not_a_real_semantic"],
    }
    with pytest.raises(ValidationError) as exc_info:
        AddressRegion.model_validate(bad_yaml_dict)
    # The diagnostic must name the offending value so operators see what to fix.
    assert "definitely_not_a_real_semantic" in str(exc_info.value)


def test_meta_canary_dsl_key_rejected_diagnostic_names_key():
    """Rule #46: rejection diagnostic must name the offending key."""
    bad_yaml_dict = {
        "name": "synthetic_dsl_canary",
        "start": 0,
        "size": 1,
        "lua_predicate": "function(r) return true end",
    }
    with pytest.raises(ValidationError) as exc_info:
        AddressRegion.model_validate(bad_yaml_dict)
    assert "lua_predicate" in str(exc_info.value)
