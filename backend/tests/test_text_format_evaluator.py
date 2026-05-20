"""P3.2.b TextFormatConstraint closed-grammar evaluator tests.

Phase 3.2 commit `b` ships the closed-grammar text_format evaluator:

* New `TextFormatConstraint` Pydantic sub-model (8 fields).
* New `TextFormatCharset` Literal (6 values; W2-α `hex_space_separated`
  added).
* New `TextFormatLineTerminator` + `TextFormatFirstLine` Literals.
* `_eval_text_format` evaluator implementation (replaces P3.1.b stub).
* `_TEXT_FORMAT_CHARSET_BYTES` + `_TEXT_FORMAT_TERMINATORS` exhaustive
  dispatch tables (Rule #46 META-CANARY enforced).
* Two new `_system/` YAMLs: `intel_hex` (updated with constraint
  block) + `motorola_srec`. (TI-TXT deferred — block-header mode needs
  a future `block_header` Literal extension.)
* A8 catalog-load gate: operator text_format with `ascii_printable`
  charset requires precedence >= 5000 (W2-β §SC5-NEW-2 high-collision
  floor).

Wave-1 S4 design + Wave-2 W2-α convergence + W2-β safety floor.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from app.schemas.file_format import (
    Detection,
    DetectionSignal,
    FileFormatManifest,
    TextFormatCharset,
    TextFormatConstraint,
    TextFormatFirstLine,
    TextFormatLineTerminator,
)
from app.services.file_format_catalog import get_default_snapshot
from app.services.file_format_catalog.resolver import (
    _TEXT_FORMAT_CHARSET_BYTES,
    _TEXT_FORMAT_TERMINATORS,
    _eval_text_format,
    resolve,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_INTEL_HEX_4_RECORDS = (
    b":020000040000FA\n"
    b":10000000010203040506070809101112131415161710\n"
    b":10001000181920212223242526272829303132333470\n"
    b":00000001FF\n"
)

_SREC_5_RECORDS = (
    b"S0030000FC\n"
    b"S113000048656C6C6F2C20576F726C642100000000A4\n"
    b"S113001048656C6C6F2C20576F726C6421000000009E\n"
    b"S113002048656C6C6F2C20576F726C642100000000A4\n"
    b"S9030000FC\n"
)


def _ihex_signal() -> DetectionSignal:
    """Build the Intel-HEX signal matching the in-tree _system YAML."""
    return DetectionSignal(
        kind="text_format",
        text_format_constraint=TextFormatConstraint(
            record_start_byte_hex="3a",  # ':'
            charset="hex_mixed",
            line_terminator="any",
            min_line_length=11,
            max_line_length=521,
            first_line_must_match="record_start",
            min_first_block_records=4,
            terminator_record_hex="3a303030303030303146460a",  # `:00000001FF\n`
        ),
    )


def _srec_signal() -> DetectionSignal:
    """Build the SREC signal matching the in-tree _system YAML."""
    return DetectionSignal(
        kind="text_format",
        text_format_constraint=TextFormatConstraint(
            record_start_byte_hex="53",  # 'S'
            charset="hex_mixed",
            line_terminator="any",
            min_line_length=10,
            max_line_length=515,
            first_line_must_match="record_start",
            min_first_block_records=4,
        ),
    )


# ---------------------------------------------------------------------------
# Positive detection — Intel HEX, SREC via direct evaluator + via catalog
# ---------------------------------------------------------------------------


def test_eval_text_format_intel_hex_valid_blob_accepts():
    sig = _ihex_signal()
    assert _eval_text_format(
        sig, _INTEL_HEX_4_RECORDS, "/tmp/test.hex", len(_INTEL_HEX_4_RECORDS),
    ) is True


def test_eval_text_format_srec_valid_blob_accepts():
    sig = _srec_signal()
    assert _eval_text_format(
        sig, _SREC_5_RECORDS, "/tmp/test.srec", len(_SREC_5_RECORDS),
    ) is True


def test_resolve_returns_intel_hex_for_valid_ihex_blob():
    match = resolve(
        _INTEL_HEX_4_RECORDS, "/tmp/firmware.hex", len(_INTEL_HEX_4_RECORDS),
    )
    assert match is not None
    assert match.format_id == "intel_hex"


def test_resolve_returns_motorola_srec_for_valid_srec_blob():
    match = resolve(_SREC_5_RECORDS, "/tmp/firmware.srec", len(_SREC_5_RECORDS))
    assert match is not None
    assert match.format_id == "motorola_srec"


# ---------------------------------------------------------------------------
# Negative tests — corrupted, too short, charset violation
# ---------------------------------------------------------------------------


def test_eval_text_format_non_marker_first_line_rejects():
    sig = _ihex_signal()
    blob = b"hello world\n:020000040000FA\n"
    assert _eval_text_format(sig, blob, "/tmp/x.hex", len(blob)) is False


def test_eval_text_format_too_few_records_rejects():
    sig = _ihex_signal()
    blob = b":020000040000FA\n:10000000010203040506070809101112131415161710\n"
    assert _eval_text_format(sig, blob, "/tmp/x.hex", len(blob)) is False


def test_eval_text_format_charset_violation_rejects():
    sig = _ihex_signal()
    # Insert a non-hex char in the body of a record.
    blob = (
        b":020000040000FA\n"
        b":10000000010203040506070809111213141516XX\n"  # XX is not hex (X not in hex)
        b":10001000181920212223242526272829303132333470\n"
        b":00000001FF\n"
    )
    assert _eval_text_format(sig, blob, "/tmp/x.hex", len(blob)) is False


def test_eval_text_format_corrupted_terminator_record_rejects_when_full_file():
    sig = _ihex_signal()
    # Replace the terminator record with a non-EOF record. With size <= len(blob),
    # the tail scan REQUIRES the terminator to be present.
    blob = (
        b":020000040000FA\n"
        b":10000000010203040506070809101112131415161710\n"
        b":10001000181920212223242526272829303132333470\n"
        b":1000200001020304050607080910111213141516AA\n"  # not the EOF record
    )
    assert _eval_text_format(sig, blob, "/tmp/x.hex", len(blob)) is False


def test_eval_text_format_empty_blob_rejects():
    sig = _ihex_signal()
    assert _eval_text_format(sig, b"", "/tmp/x.hex", 0) is False


def test_eval_text_format_line_too_short_rejects():
    sig = _ihex_signal()
    # min_line_length=11; line `:0FA\n` is 5 chars.
    blob = b":0FA\n:0FA\n:0FA\n:0FA\n"
    assert _eval_text_format(sig, blob, "/tmp/x.hex", len(blob)) is False


def test_resolve_binary_blob_with_hex_ext_falls_through_to_linux_blob():
    """Binary content with .hex extension shouldn't classify as intel_hex —
    text_format evaluator rejects, catalog falls to floor sentinel."""
    blob = b"\x00\xff" * 128
    match = resolve(blob, "/tmp/garbage.hex", len(blob))
    assert match is not None
    assert match.format_id == "linux_blob"


# ---------------------------------------------------------------------------
# Schema validation — required field, mutual exclusion
# ---------------------------------------------------------------------------


def test_schema_rejects_text_format_signal_without_constraint():
    with pytest.raises(ValidationError) as exc:
        DetectionSignal(
            kind="text_format",
            description="bogus — missing constraint",
        )
    assert "text_format_constraint" in str(exc.value)


def test_schema_rejects_text_format_constraint_on_non_text_format_signal():
    """Setting text_format_constraint on a kind other than text_format
    is a typo / leftover — symmetric rejection at parse time."""
    with pytest.raises(ValidationError) as exc:
        DetectionSignal(
            kind="filename",
            extensions_lower=[".hex"],
            text_format_constraint=TextFormatConstraint(
                record_start_byte_hex="3a", charset="hex_mixed",
                min_line_length=11, max_line_length=521,
            ),
        )
    assert "text_format_constraint" in str(exc.value)


def test_schema_rejects_text_format_constraint_with_weak_strength():
    """Constraint-strength floor: min_records<2 + min_line<8 rejected
    (W2-β §SC5-NEW-2 mitigation; the evaluator could match anything)."""
    with pytest.raises(ValidationError) as exc:
        TextFormatConstraint(
            record_start_byte_hex="3a", charset="hex_mixed",
            min_line_length=4, max_line_length=20,
            min_first_block_records=1,
        )
    assert "too weak" in str(exc.value) or "min_first_block_records" in str(exc.value)


def test_schema_rejects_text_format_constraint_with_min_gt_max():
    with pytest.raises(ValidationError) as exc:
        TextFormatConstraint(
            record_start_byte_hex="3a", charset="hex_mixed",
            min_line_length=100, max_line_length=50,
        )
    assert "min_line_length" in str(exc.value)


def _minimal_manifest_dict(
    *,
    format_id: str = "test_fmt",
    manifest_source: str = "core",
    precedence: int = 100,
    text_format_constraint: dict | None = None,
) -> dict:
    if text_format_constraint is None:
        text_format_constraint = {
            "record_start_byte_hex": "3a",
            "charset": "hex_mixed",
            "min_line_length": 11,
            "max_line_length": 521,
        }
    return {
        "format_id": format_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "category": "other",
        "vendor": "test_vendor",
        "confidence": "high",
        "detection": {
            "combine": "all_required",
            "signals": [{
                "kind": "text_format",
                "description": "test text_format",
                "text_format_constraint": text_format_constraint,
            }],
        },
        "output": {
            "classifier_format": format_id,
            "classifier_category": "other",
            "classifier_vendor": "test_vendor",
            "confidence": "high",
        },
    }


# ---------------------------------------------------------------------------
# A8 — high-collision floor (Wave-2 W2-β §SC5-NEW-2)
# ---------------------------------------------------------------------------


def test_a8_operator_ascii_printable_low_precedence_rejected():
    """Operator-supplied text_format with ascii_printable charset +
    precedence<5000 rejected at parse time. Prevents the "operator
    declares effective always_matches without the flag" attack."""
    data = _minimal_manifest_dict(
        manifest_source="operator", precedence=100,
        text_format_constraint={
            "record_start_byte_hex": "20",   # space
            "charset": "ascii_printable",
            "min_line_length": 8,
            "max_line_length": 256,
            "min_first_block_records": 3,
        },
    )
    with pytest.raises(ValidationError) as exc:
        FileFormatManifest(**data)
    assert "ascii_printable" in str(exc.value)
    assert "5000" in str(exc.value)


def test_a8_operator_ascii_printable_high_precedence_accepts():
    """Operator-supplied text_format with ascii_printable + precedence
    >= 5000 (negative-evidence floor) accepts — the high precedence
    documents the operator's awareness of the false-positive cascade."""
    data = _minimal_manifest_dict(
        manifest_source="operator", precedence=5000,
        text_format_constraint={
            "record_start_byte_hex": "20",
            "charset": "ascii_printable",
            "min_line_length": 8,
            "max_line_length": 256,
            "min_first_block_records": 3,
        },
    )
    m = FileFormatManifest(**data)
    assert m.precedence == 5000


def test_a8_system_ascii_printable_accepts_any_precedence():
    """_system source with ascii_printable charset accepts regardless
    of precedence — wairz invariants are trusted to use the permissive
    charset only where appropriate."""
    data = _minimal_manifest_dict(
        format_id="test_system_ascii",
        manifest_source="_system", precedence=8,
        text_format_constraint={
            "record_start_byte_hex": "23",
            "charset": "ascii_printable",
            "min_line_length": 8,
            "max_line_length": 256,
            "min_first_block_records": 3,
        },
    )
    m = FileFormatManifest(**data)
    assert m.detection.signals[0].text_format_constraint.charset == "ascii_printable"


def test_a8_operator_hex_mixed_low_precedence_accepts():
    """Operator-supplied text_format with hex_mixed charset (restrictive)
    accepts at low precedence — discrimination comes from the charset."""
    data = _minimal_manifest_dict(manifest_source="operator", precedence=100)
    m = FileFormatManifest(**data)
    assert m.precedence == 100


# ---------------------------------------------------------------------------
# META-CANARY M5 — _eval_text_format AST-walk: NO hardcoded byte literals
# ---------------------------------------------------------------------------


def _resolver_source() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "file_format_catalog" / "resolver.py"
    ).read_text(encoding="utf-8")


def _ast_find_function(module_src: str, name: str) -> ast.FunctionDef:
    tree = ast.parse(module_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")


def test_meta_canary_text_format_evaluator_uses_declared_constraints_not_hardcoded_m5():
    """Rule #46 anti-hardcode META-CANARY (W2-α + S4 §6.A).

    AST-walk `_eval_text_format` body and assert NO record-start-byte
    literals like b":" / b"S" / b"@" appear — every byte the evaluator
    compares against MUST come from a field on
    :class:`TextFormatConstraint`. The lookup tables
    `_TEXT_FORMAT_CHARSET_BYTES` + `_TEXT_FORMAT_TERMINATORS` are
    module-level (allowed); only function-body literals are forbidden.
    """
    func = _ast_find_function(_resolver_source(), "_eval_text_format")
    # Allowlist: empty bytes b"" and single-byte CR/LF used for
    # splitlines-style terminator stripping (b"\r\n", b"\n", b"\r")
    # are mechanical I/O constants, not format-specific. Forbidden:
    # ANY other byte-literal that could be a hardcoded record_start.
    ALLOWED_BYTE_LITERALS = {b"", b"\n", b"\r", b"\r\n"}
    forbidden: list[bytes] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in ALLOWED_BYTE_LITERALS:
                forbidden.append(node.value)
    assert not forbidden, (
        f"_eval_text_format contains hardcoded byte literals "
        f"{forbidden!r}; every byte comparison MUST go through "
        "signal.text_format_constraint (Rule #52 closed-grammar discipline)"
    )


def test_meta_canary_m5_gate_actually_fires_on_synthetic_violation():
    """Rule #46 paired canary: construct an AST representing a
    `_eval_text_format` body with a hardcoded `b":"` byte literal +
    assert the M5 assertion would REJECT it."""
    hostile_src = '''
def _eval_text_format(signal, blob_head, path, size):
    if blob_head[0:1] == b":":  # HARDCODED — anti-Rule-#52
        return True
    return False
'''
    func = _ast_find_function(hostile_src, "_eval_text_format")
    ALLOWED_BYTE_LITERALS = {b"", b"\n", b"\r", b"\r\n"}
    forbidden = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in ALLOWED_BYTE_LITERALS:
                forbidden.append(node.value)
    # Synthetic must trip the gate — exactly the hardcoded `b":"`.
    assert forbidden == [b":"], f"Expected gate to catch [b':'], got {forbidden}"


# ---------------------------------------------------------------------------
# META-CANARY M6 — text_format_constraint Required-when-kind=text_format
# (already verified by schema rejection tests above; this M6 documents
# the regression-prevention path)
# ---------------------------------------------------------------------------


def test_meta_canary_text_format_charset_table_exhaustive_m6a():
    """Rule #46 — _TEXT_FORMAT_CHARSET_BYTES exhaustive against
    TextFormatCharset Literal."""
    expected = set(get_args(TextFormatCharset))
    actual = set(_TEXT_FORMAT_CHARSET_BYTES.keys())
    assert actual == expected, (
        f"_TEXT_FORMAT_CHARSET_BYTES diverges from TextFormatCharset: "
        f"missing={expected - actual}, extra={actual - expected}"
    )


def test_meta_canary_text_format_terminator_table_exhaustive_m6b():
    """Rule #46 — _TEXT_FORMAT_TERMINATORS exhaustive against
    TextFormatLineTerminator Literal."""
    expected = set(get_args(TextFormatLineTerminator))
    actual = set(_TEXT_FORMAT_TERMINATORS.keys())
    assert actual == expected, (
        f"_TEXT_FORMAT_TERMINATORS diverges from TextFormatLineTerminator: "
        f"missing={expected - actual}, extra={actual - expected}"
    )


def test_meta_canary_charset_table_exhaustive_gate_actually_fires():
    """Rule #46 paired canary: simulate a TextFormatCharset extension
    without a corresponding _TEXT_FORMAT_CHARSET_BYTES update."""
    expected = set(get_args(TextFormatCharset))
    # Synthesized missing-key dict.
    incomplete = {k: v for k, v in _TEXT_FORMAT_CHARSET_BYTES.items()
                  if k != next(iter(expected))}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected
