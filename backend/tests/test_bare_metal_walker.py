"""Tests for the bare-metal MCU/DSP audit walker.

Covers:
  * POLICY_EVALUATORS exhaustive-coverage META-CANARY (Rule #46)
  * Each policy operator's matched + non-matched paths
  * Rule #45 parse-only token-scan gate ``test_walker_no_decrypt`` +
    its META-CANARY ``test_walker_no_decrypt_gate_actually_fires``
  * Rule #39 inner/outer/safe triplet exports
"""
from __future__ import annotations

import io
import tokenize
import typing
from pathlib import Path

import pytest

import app.services.bare_metal_walker as walker_module
from app.schemas.chip_family import (
    AddressRegion,
    Domain,
    GhidraImportParams,
    PolicyOperator,
    PolicyRule,
)
from app.services.bare_metal_walker import POLICY_EVALUATORS

# ---------------------------------------------------------------------------
# Rule #46 META-CANARY: POLICY_EVALUATORS exhaustive.
# ---------------------------------------------------------------------------


def test_policy_evaluators_exhaustive():
    """Every PolicyOperator Literal value MUST have an evaluator.

    Adding a new operator requires a Rule #25 cross-stack alignment commit
    (schema Literal extension + POLICY_EVALUATORS handler + this test
    passing) — if the new operator is added to the schema without a handler,
    this test fails loudly at import time.
    """
    declared = set(typing.get_args(PolicyOperator))
    handled = set(POLICY_EVALUATORS.keys())
    missing = declared - handled
    assert not missing, (
        f"PolicyOperator values without evaluators in POLICY_EVALUATORS: {missing}. "
        f"Adding a new policy operator requires both a schema Literal extension AND "
        f"a handler in bare_metal_walker.POLICY_EVALUATORS (Rule #25 cross-stack "
        f"alignment + Rule #46 META-CANARY)."
    )


# ---------------------------------------------------------------------------
# Rule #45 + Rule #46: parse-only no-decrypt token scan.
# ---------------------------------------------------------------------------


_FORBIDDEN_DECRYPT_TOKENS = (
    r"\.\s*decrypt\s*\(",                       # any obj.decrypt(...)
    r"CryptUnprotectData",                      # Windows DPAPI
    r"cryptography\s*\.\s*fernet",              # cryptography.fernet
    r"Crypto\s*\.\s*Cipher",                    # pycryptodome
    r"impacket\s*\.\s*dpapi",                   # impacket dpapi
    r"pyDes",                                   # pyDes
    r"AES\s*\.\s*new",                          # pycrypto AES
)


def _scan_for_forbidden_tokens(source: str) -> list[str]:
    """Tokenise source, strip comments+strings, return matched forbidden patterns."""
    import re
    tokens = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING, tokenize.FSTRING_START,
                             tokenize.FSTRING_MIDDLE, tokenize.FSTRING_END,
                             tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                             tokenize.DEDENT, tokenize.ENCODING):
                continue
            tokens.append(tok.string)
    except tokenize.TokenizeError:
        pass
    joined = " ".join(tokens)
    matches = []
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        if re.search(pattern, joined):
            matches.append(pattern)
    return matches


def test_walker_no_decrypt():
    """Rule #45 parse-only — walker source MUST NOT contain decrypt entry points.

    Tokenises ``bare_metal_walker.py``, strips comments + string literals,
    asserts the remaining executable tokens contain none of the forbidden
    decryption-API patterns. The walker is the security boundary; if it
    grows a decrypt call, every encrypted_region semantic loses its
    contract.
    """
    source_path = Path(walker_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    matched = _scan_for_forbidden_tokens(source)
    assert not matched, (
        f"bare_metal_walker.py contains forbidden decrypt tokens (Rule #45 violation): "
        f"{matched}. The walker is the security boundary — encrypted_region "
        f"semantic MUST be skipped, NEVER decrypted."
    )


def test_walker_no_decrypt_gate_actually_fires():
    """Rule #46 META-CANARY — confirm the gate WOULD catch a synthetic violation.

    Constructs a fake walker source IN MEMORY that includes a forbidden
    decrypt call, runs the same scanner the real gate uses, asserts it
    fires. Without this canary, the gate might silently fail (regex
    whitespace bug, tokenize strip too aggressive, etc.) and let a real
    violation through (Rule #46 paired-canary discipline).

    Concatenates source lines rather than f-strings — tokenize would strip
    string literals, so an in-string violation wouldn't be detected by the
    real scanner (the canary itself would be a false positive).
    """
    fake_violating_source = "\n".join([
        "def evil_walker():",
        "    obj = SomeClass()",
        "    plaintext = obj.decrypt(ciphertext)",
        "    return plaintext",
    ])
    matched = _scan_for_forbidden_tokens(fake_violating_source)
    assert matched, (
        f"Rule #46 META-CANARY FAILED: the no-decrypt gate did not catch a "
        f"synthetic decrypt() call. The token-strip regex may have changed "
        f"and is no longer matching. Real Rule #45 violations would now pass "
        f"undetected — investigate before merging."
    )


# ---------------------------------------------------------------------------
# Policy-evaluator unit tests.
# ---------------------------------------------------------------------------


def _build_domain() -> Domain:
    return Domain(
        name="test_core",
        arch="tms320c28x",
        endianness="little",
        instruction_word_bits=16,
        data_word_bits=16,
        address_bus_bits=22,
        packing="two_bytes_per_word_le",
        address_regions=[
            AddressRegion(name="csm_pwl", start=0x3F7FF8, size=8, semantic=["security_password_csm"]),
        ],
        ghidra_import_params=GhidraImportParams(
            processor="TMS320C28x:LE:32:default", base_addr=0x3F7FF8,
        ),
    )


def test_unsecure_when_all_words_equal_matches_all_ffff():
    """All-0xFFFF CSM PWL → policy fires (Eaton TMS320F28066 reference)."""
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(
        operator="unsecure_when_all_words_equal",
        value_hex="FFFF", word_size_bits=16,
        cwe_ids=[1273, 1191], severity="high",
        finding_source="c28x_unsecure_csm",
    )
    blob = b"\xff" * 16  # 8 words × 2 bytes, all 0xFFFF
    matched, evidence = POLICY_EVALUATORS["unsecure_when_all_words_equal"](
        blob, region, rule, domain,
    )
    assert matched
    assert "0xFFFF" in evidence


def test_unsecure_when_all_words_equal_not_matched_on_mixed():
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(
        operator="unsecure_when_all_words_equal", value_hex="FFFF",
        word_size_bits=16, severity="high",
    )
    # Half 0xFFFF, half 0x1234
    blob = b"\xff\xff" * 4 + b"\x34\x12" * 4
    matched, _ = POLICY_EVALUATORS["unsecure_when_all_words_equal"](
        blob, region, rule, domain,
    )
    assert not matched


def test_unsecure_when_any_word_equal_matches_one():
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(operator="unsecure_when_any_word_equal", value_hex="DEAD", word_size_bits=16)
    blob = b"\x00\x00" * 4 + b"\xad\xde" + b"\x11\x22" * 3   # one word = 0xDEAD
    matched, _ = POLICY_EVALUATORS["unsecure_when_any_word_equal"](blob, region, rule, domain)
    assert matched


def test_perma_lock_when_all_words_equal_matches_zeros():
    """All-zero CSM PWL → perma-lock policy fires."""
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(
        operator="perma_lock_when_all_words_equal", value_hex="0000",
        word_size_bits=16, cwe_ids=[1191], severity="medium",
        finding_source="c28x_csm_perma_lock",
    )
    blob = b"\x00" * 16
    matched, _ = POLICY_EVALUATORS["perma_lock_when_all_words_equal"](blob, region, rule, domain)
    assert matched


def test_required_value_at_offset():
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(
        operator="required_value_at_offset", value_hex="DEAD",
        offset=0, word_size_bits=16,
    )
    # Offset 0 within csm_pwl is C28x address 0x3F7FF8 — read should be 0x1234, not 0xDEAD
    blob_bytes = bytearray(0x40000)
    word_idx = (0x3F7FF8 - 0x3F7FFF + 8) * 2   # base_addr for this domain is 0x3F7FF8
    blob_bytes[0:2] = (0x1234).to_bytes(2, "little")
    matched, _ = POLICY_EVALUATORS["required_value_at_offset"](
        bytes(blob_bytes), region, rule, domain,
    )
    # "required" semantics: matched=True when value is NOT what was required
    assert matched


def test_forbidden_value_at_offset():
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(
        operator="forbidden_value_at_offset", value_hex="1234",
        offset=0, word_size_bits=16,
    )
    blob_bytes = bytearray(0x40000)
    blob_bytes[0:2] = (0x1234).to_bytes(2, "little")
    matched, _ = POLICY_EVALUATORS["forbidden_value_at_offset"](
        bytes(blob_bytes), region, rule, domain,
    )
    assert matched


def test_informational_always_fires():
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(operator="informational")
    matched, _ = POLICY_EVALUATORS["informational"](b"", region, rule, domain)
    assert matched


def test_region_outside_blob_coverage_does_not_match():
    """Policy on a region the blob doesn't contain → no match (clean skip)."""
    domain = _build_domain()
    region = domain.address_regions[0]
    rule = PolicyRule(operator="unsecure_when_all_words_equal", value_hex="FFFF", word_size_bits=16)
    blob = b""   # zero-length blob
    matched, evidence = POLICY_EVALUATORS["unsecure_when_all_words_equal"](
        blob, region, rule, domain,
    )
    assert not matched
    assert "outside blob coverage" in evidence


# ---------------------------------------------------------------------------
# Rule #39 inner/outer/safe triplet exports.
# ---------------------------------------------------------------------------


def test_walker_triplet_exports():
    """All three Rule #39 entry points exist with the canonical names."""
    assert callable(walker_module._do_bare_metal_audit_run)
    assert callable(walker_module.run_bare_metal_audit_background)
    assert callable(walker_module.auto_bare_metal_audit_firmware_safe)


# ---------------------------------------------------------------------------
# Rule #46 META-CANARY — descriptor precedence ordering.
# Scout GG §SC5 stop-the-line: walker MUST honour
#   operator > attested_external > unauthenticated_external > auto_detection
# even when a lower-precedence descriptor arrives LATER (Scout GG verdict
# MUST — the original `ORDER BY received_at DESC` would let an
# unauthenticated_external descriptor at t=10 outrank an operator
# descriptor at t=5).
# ---------------------------------------------------------------------------


def test_precedence_case_orders_operator_above_external():
    """Static check on the SQL CASE expression — operator > external.

    Compile the ORDER BY expression and confirm the precedence ranks are
    the documented values (Rule #19 evidence-first: the SQL must equal
    what the docstring promises).
    """
    from app.services.bare_metal_walker import _SOURCE_PRECEDENCE
    # Documented contract — must match
    assert _SOURCE_PRECEDENCE == {
        "operator": 4,
        "attested_external": 3,
        "unauthenticated_external": 2,
        "auto_detection": 1,
    }
    # Sorted by precedence rank DESC = the resolution order
    by_rank = sorted(_SOURCE_PRECEDENCE.items(), key=lambda x: x[1], reverse=True)
    assert [source for source, _ in by_rank] == [
        "operator",
        "attested_external",
        "unauthenticated_external",
        "auto_detection",
    ]


def test_meta_canary_sql_uses_precedence_case_not_just_timestamp():
    """Rule #46 META-CANARY — confirm the SQL is precedence-aware.

    Without this canary, a future refactor could silently revert
    ``_most_recent_descriptor`` to ``ORDER BY received_at DESC`` and let
    untrusted ingestors override operator descriptors. Scans the source
    function for the precedence_case construction tokens.
    """
    import inspect
    src = inspect.getsource(walker_module._most_recent_descriptor)
    # Must include the precedence_case construction (Rule #46 — synthetic
    # check on source structure)
    assert "precedence_case" in src, (
        "_most_recent_descriptor SQL must use precedence_case — Scout GG §SC5 "
        "regression. Without the CASE expression, ORDER BY received_at DESC "
        "alone lets unauthenticated_external descriptors outrank operator ones."
    )
    assert "sa.case" in src or "case(" in src
    # The precedence map must be referenced (verifies the source-of-truth
    # dict drives the SQL, not a duplicated literal that could drift)
    assert "_SOURCE_PRECEDENCE" in src
