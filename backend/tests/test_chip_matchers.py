"""Tests for the YAML-driven chip matcher + signal evaluators.

Covers:
  * SIGNAL_EVALUATORS closure (every DetectionSignalKind has a handler)
  * Each evaluator's happy + reject path
  * Address-to-file-offset translation for C28x packing
  * REJECT short-circuit on ELF-shaped inputs
  * End-to-end YamlDrivenMatcher against synthetic + real F28066 dumps
  * Threshold + max_candidates filtering
"""
from __future__ import annotations

import typing

import pytest
import yaml

from app.schemas.chip_family import (
    AddressRegion,
    ChipFamilyManifest,
    DetectionSignal,
    DetectionSignalKind,
    Domain,
)
from app.services.hardware_firmware.chip_catalog import ChipCatalog, get_default_catalog
from app.services.hardware_firmware.matchers import (
    SIGNAL_EVALUATORS,
    YamlDrivenMatcher,
    address_to_file_offset,
    read_region_bytes,
    read_word_at_address,
)
from app.services.hardware_firmware.matchers.yaml_driven import REJECT


# ---------------------------------------------------------------------------
# Closed-grammar guarantee: every DetectionSignalKind has an evaluator.
# Rule #46 META-CANARY shape — confirms the gate that SIGNAL_EVALUATORS is
# the exhaustive dispatch table.
# ---------------------------------------------------------------------------


def test_signal_evaluators_exhaustive():
    """Every DetectionSignalKind Literal value MUST have an evaluator."""
    declared = set(typing.get_args(DetectionSignalKind))
    handled = set(SIGNAL_EVALUATORS.keys())
    missing = declared - handled
    assert not missing, (
        f"DetectionSignalKind values without evaluators in SIGNAL_EVALUATORS: {missing}. "
        f"Adding a new signal kind requires both a schema Literal extension AND a "
        f"handler in matchers/yaml_driven.py (Rule #25 cross-stack alignment + Rule #46)."
    )


# ---------------------------------------------------------------------------
# Address-translation helpers.
# ---------------------------------------------------------------------------


def test_address_translation_byte_addressed():
    """Cortex-M: file_offset = address - base_addr (1:1)."""
    assert address_to_file_offset(0x08001000, 0x08000000, "one_byte_per_address") == 0x1000


def test_address_translation_c28x_word_packing():
    """C28x: each address holds 1 word = 2 host-bytes → file_offset = (addr - base) × 2."""
    assert address_to_file_offset(0x3D8001, 0x3D8000, "two_bytes_per_word_le") == 2
    assert address_to_file_offset(0x3F7FF8, 0x3D8000, "two_bytes_per_word_le") == (0x3F7FF8 - 0x3D8000) * 2


def test_address_translation_below_base_raises():
    with pytest.raises(ValueError):
        address_to_file_offset(0x100, 0x200, "one_byte_per_address")


def test_read_word_at_address_le():
    # Word 0xF983 at C28x address 0x3D8000 → host bytes 0x83 0xF9
    blob = b"\x83\xf9" + b"\x00" * 100
    assert read_word_at_address(blob, 0x3D8000, 0x3D8000, "two_bytes_per_word_le", 16) == 0xF983


def test_read_word_at_address_oob_returns_none():
    blob = b"\x00\x00"
    assert read_word_at_address(blob, 0x3D8100, 0x3D8000, "two_bytes_per_word_le", 16) is None


def test_read_region_bytes_respects_packing():
    blob = b"\x83\xf9\xab\xcd" + b"\x00" * 100
    # Region of 2 words at C28x address 0x3D8000 → 4 host-bytes
    region_bytes = read_region_bytes(blob, 0x3D8000, 2, 0x3D8000, "two_bytes_per_word_le")
    assert region_bytes == b"\x83\xf9\xab\xcd"


# ---------------------------------------------------------------------------
# Per-evaluator unit tests.
# ---------------------------------------------------------------------------


def _build_test_domain(**overrides) -> Domain:
    """Builder for a minimal test domain."""
    defaults = dict(
        name="test_core",
        arch="tms320c28x",
        endianness="little",
        instruction_word_bits=16,
        data_word_bits=16,
        address_bus_bits=22,
        packing="two_bytes_per_word_le",
        address_regions=[
            AddressRegion(name="flash", start=0x3D8000, size=0x20000, semantic=["flash_code"]),
        ],
    )
    defaults.update(overrides)
    return Domain(**defaults)


def test_evaluator_string_present_hits():
    domain = _build_test_domain()
    blob = b"\x00" * 1000 + b"TMS320F28066 Piccolo" + b"\x00" * 1000
    signal = DetectionSignal(
        kind="string_present",
        weight=0.5,
        patterns=["TMS320F28066", "Piccolo", "MissingString"],
    )
    score = SIGNAL_EVALUATORS["string_present"](blob, signal, domain)
    # 2 of 3 patterns hit
    assert abs(score - 2 / 3) < 1e-6


def test_evaluator_string_present_no_hits():
    domain = _build_test_domain()
    blob = b"\x00" * 1000
    signal = DetectionSignal(kind="string_present", weight=0.5, patterns=["NotInBlob"])
    assert SIGNAL_EVALUATORS["string_present"](blob, signal, domain) == 0.0


def test_evaluator_elf_magic_rejects():
    """ELF-shaped blob disqualifies the candidate via REJECT sentinel."""
    domain = _build_test_domain()
    blob = b"\x7fELF" + b"\x00" * 100
    signal = DetectionSignal(kind="elf_magic", weight=1.0, bytes_hex="7F454C46")
    assert SIGNAL_EVALUATORS["elf_magic"](blob, signal, domain) == REJECT


def test_evaluator_elf_magic_passes_on_non_elf():
    domain = _build_test_domain()
    blob = b"\x83\xf9" + b"\x00" * 100  # C28x-shaped first bytes
    signal = DetectionSignal(kind="elf_magic", weight=1.0, bytes_hex="7F454C46")
    assert SIGNAL_EVALUATORS["elf_magic"](blob, signal, domain) == 0.0


def test_evaluator_silicon_id_byte_match_anchored():
    """Anchored byte match — fixed offset matches → score 1.0."""
    domain = _build_test_domain()
    # Translation: byte offset 0 = chip addr 0x3D8000
    blob = b"\xab\xcd\xef" + b"\x00" * 100
    signal = DetectionSignal(
        kind="silicon_id_byte_match",
        weight=0.5,
        address=0x3D8000,
        bytes_hex="ABCDEF",
    )
    assert SIGNAL_EVALUATORS["silicon_id_byte_match"](blob, signal, domain) == 1.0


def test_evaluator_silicon_id_byte_match_substring_search():
    """Unanchored byte match — substring search."""
    domain = _build_test_domain()
    blob = b"\x00" * 500 + b"\xde\xad\xbe\xef" + b"\x00" * 500
    signal = DetectionSignal(
        kind="silicon_id_byte_match", weight=0.5, bytes_hex="DEADBEEF",
    )
    assert SIGNAL_EVALUATORS["silicon_id_byte_match"](blob, signal, domain) == 1.0


def test_evaluator_entropy_band_random_data():
    """High-entropy random buffer matches a [7.0, 8.0] band."""
    domain = _build_test_domain()
    import os
    blob = os.urandom(4096)
    signal = DetectionSignal(kind="entropy_band", weight=1.0, entropy_min=7.0, entropy_max=8.0)
    assert SIGNAL_EVALUATORS["entropy_band"](blob, signal, domain) == 1.0


def test_evaluator_entropy_band_low_entropy_rejects():
    domain = _build_test_domain()
    blob = b"\x00" * 4096  # zero entropy
    signal = DetectionSignal(kind="entropy_band", weight=1.0, entropy_min=7.0, entropy_max=8.0)
    assert SIGNAL_EVALUATORS["entropy_band"](blob, signal, domain) == 0.0


# ---------------------------------------------------------------------------
# YamlDrivenMatcher end-to-end.
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_catalog(tmp_path, monkeypatch):
    """Point the default catalog at tmp_path for an isolated test."""
    cat = ChipCatalog(root_resolver=lambda: tmp_path)
    monkeypatch.setattr(
        "app.services.hardware_firmware.matchers.yaml_driven.get_chip_catalog",
        cat.get_catalog,
    )
    return tmp_path


def _write_test_yaml(path, family: str, patterns: list[str]) -> None:
    manifest = {
        "schema_version": 1,
        "vendor": "test",
        "family": family,
        "display_name": f"Test {family}",
        "domains": [{
            "name": "core",
            "arch": "tms320c28x",
            "endianness": "little",
            "instruction_word_bits": 16,
            "data_word_bits": 16,
            "address_bus_bits": 22,
            "packing": "two_bytes_per_word_le",
            "address_regions": [
                {"name": "flash", "start": 0x3D8000, "size": 0x20000, "semantic": ["flash_code"]},
            ],
            "detection_signals": [
                {"kind": "string_present", "weight": 1.0, "patterns": patterns},
                {"kind": "elf_magic", "weight": 1.0, "bytes_hex": "7F454C46"},
            ],
        }],
    }
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")


def test_matcher_returns_high_confidence_on_strong_match(isolated_catalog):
    _write_test_yaml(isolated_catalog / "f28066.yaml", "f28066", ["TMS320F28066", "Piccolo"])
    blob = b"\x00" * 1000 + b"TMS320F28066 Piccolo F2806x" + b"\x00" * 1000
    results = YamlDrivenMatcher().detect(blob, threshold=0.1)
    assert len(results) == 1
    assert results[0].family_id == "test/f28066"
    assert results[0].confidence > 0.4  # both patterns hit → 1.0/2.0 weights = 0.5
    assert results[0].descriptor_source == "auto_detection"


def test_matcher_returns_empty_on_no_match(isolated_catalog):
    _write_test_yaml(isolated_catalog / "f28066.yaml", "f28066", ["VerySpecificPattern"])
    blob = b"\x00" * 1000
    results = YamlDrivenMatcher().detect(blob, threshold=0.1)
    assert results == []


def test_matcher_rejects_elf_shaped_input(isolated_catalog):
    """ELF-shaped blob disqualifies even when other signals hit."""
    _write_test_yaml(isolated_catalog / "f28066.yaml", "f28066", ["TMS320F28066"])
    blob = b"\x7fELF\x01\x01\x01\x00" + b"TMS320F28066" + b"\x00" * 100
    results = YamlDrivenMatcher().detect(blob, threshold=0.0)
    assert results == []


def test_matcher_returns_multiple_candidates_sorted_by_confidence(isolated_catalog):
    _write_test_yaml(isolated_catalog / "a.yaml", "a_strong", ["TMS320F28066", "Piccolo", "F2806x"])
    _write_test_yaml(isolated_catalog / "b.yaml", "b_weak", ["TMS320F28066", "AlmostNeverHits"])
    blob = b"\x00" * 100 + b"TMS320F28066 Piccolo F2806x" + b"\x00" * 100
    results = YamlDrivenMatcher().detect(blob, threshold=0.1, max_candidates=5)
    assert len(results) == 2
    assert results[0].confidence >= results[1].confidence
    assert results[0].family_id == "test/a_strong"


def test_matcher_respects_threshold(isolated_catalog):
    """Low-confidence match below threshold is filtered out."""
    _write_test_yaml(isolated_catalog / "f.yaml", "weak", ["Only", "Two", "Patterns", "Hit", "OneOfFive"])
    blob = b"\x00" * 100 + b"Only Two" + b"\x00" * 100
    high = YamlDrivenMatcher().detect(blob, threshold=0.9)
    low = YamlDrivenMatcher().detect(blob, threshold=0.1)
    assert high == []
    assert len(low) == 1


def test_matcher_evidence_breakdown_present(isolated_catalog):
    """Each match carries per-signal evidence so operators can audit."""
    _write_test_yaml(isolated_catalog / "f.yaml", "f", ["TMS320F28066"])
    blob = b"\x00" * 100 + b"TMS320F28066" + b"\x00" * 100
    results = YamlDrivenMatcher().detect(blob, threshold=0.1)
    assert len(results) == 1
    evidence = results[0].evidence
    assert len(evidence) >= 1
    string_evidence = next(e for e in evidence if e["kind"] == "string_present")
    assert "weight" in string_evidence
    assert "contribution" in string_evidence


def test_matcher_skips_not_applicable_signals(isolated_catalog):
    """Signals targeting addresses outside blob coverage are excluded.

    Partial dumps (flash-only, boot-ROM-only) get NOT_APPLICABLE for
    signals that reference the part they don't contain — those signals
    are excluded from both numerator AND denominator so confidence
    isn't dragged down (Rule #19 evidence-first — observed against
    stripped Eaton production firmware 2026-05-19).
    """
    manifest = {
        "schema_version": 1,
        "vendor": "test",
        "family": "split",
        "display_name": "Split",
        "domains": [{
            "name": "core",
            "arch": "tms320c28x", "endianness": "little",
            "instruction_word_bits": 16, "data_word_bits": 16, "address_bus_bits": 22,
            "packing": "two_bytes_per_word_le",
            "address_regions": [
                {"name": "flash", "start": 0x3D8000, "size": 0x20000, "semantic": ["flash_code"]},
                {"name": "boot_rom", "start": 0x3FF000, "size": 0x1000, "semantic": ["boot_rom"]},
            ],
            "detection_signals": [
                # This signal targets boot ROM; a flash-only blob has no coverage there
                {"kind": "reset_vector_at", "weight": 0.5, "address": 0x3FFFC0},
                # This always-anchored signal IS in flash coverage
                {"kind": "silicon_id_byte_match", "weight": 0.5, "bytes_hex": "ABCD"},
            ],
        }],
    }
    (isolated_catalog / "split.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    # Flash-sized blob containing the silicon-id pattern but NOT the boot ROM
    blob = b"\xab\xcd" + b"\x00" * (0x40000 - 2)
    results = YamlDrivenMatcher().detect(blob, threshold=0.0)
    assert len(results) == 1
    match = results[0]
    # confidence = silicon_id matches (1.0 × 0.5 weight) / total applicable weight (0.5)
    # = 0.5 / 0.5 = 1.0. The reset_vector_at signal is excluded from BOTH numerator
    # and denominator since the boot ROM address is outside blob coverage.
    assert match.confidence == 1.0
    # Evidence shows the reset_vector_at signal as skipped, not contributing
    reset_evidence = next(e for e in match.evidence if e["kind"] == "reset_vector_at")
    assert reset_evidence.get("skipped"), "reset_vector_at should be marked skipped"
    assert reset_evidence["contribution"] == 0.0


def test_matcher_real_default_catalog_f28066_smoke():
    """Smoke against the SHIPPED F28066 YAML in the default catalog.

    Verifies the production catalog loads cleanly and F28066 scores
    above 0 against a synthetic TI-shaped blob. Real Eaton blob smoke
    happens in P1.12 end-to-end.
    """
    # Don't isolate — use the default catalog (which now includes F28066)
    cat = get_default_catalog()
    cat.cache_clear()
    snapshot = cat.get_catalog()
    if "ti/tms320f28066" not in snapshot:
        pytest.skip("F28066 YAML not present in default catalog")
    # Synthetic blob with TI-shaped strings + a non-zero word at expected reset vector
    blob = bytearray(0x40000)
    blob[0:14] = b"Texas Instruments"[:14]
    blob[100:107] = b"TMS320 "
    blob[200:207] = b"Piccolo"
    blob[300:307] = b"F28066 "
    # Reset vector at C28x 0x3FFFC0 → file offset (0x3FFFC0 - 0x3D8000) * 2 = 0x4FF80
    # — outside the 256K blob we just sized; bump the blob to cover boot ROM range
    # For this smoke we just want strings to fire.
    results = YamlDrivenMatcher().detect(bytes(blob), threshold=0.0)
    f28066_matches = [r for r in results if r.family_id == "ti/tms320f28066"]
    assert f28066_matches, f"F28066 should have at least scored 0 on TI-string-laden blob"
    assert f28066_matches[0].confidence > 0.0
