"""P3.x SubstringInHeadConstraint closed-grammar evaluator tests (2026-05-20).

The 2026-05-20 P3.x slice ships the `substring_in_head` signal kind:

* New `SubstringInHeadConstraint` Pydantic sub-model (5 fields).
* New `SubstringInHeadCombine` Literal (2 values: `any`, `all`).
* New `DetectionSignalKind` Literal value `substring_in_head`.
* `_eval_substring_in_head` evaluator implementation (literal byte
  substring scan over the head window).
* `_SIGNAL_COST_CLASS["substring_in_head"] = 2` (same I/O cost as
  `magic_bytes`).
* `windows_installer_iso.yaml` adopts the new signal (bootmgr +
  sources/boot.wim needles) so the catalog distinguishes installer
  ISOs from bare ISO-9660 without the legacy `_legacy_bridge_detect`
  bootmgr upgrade.
* `iso_9660` + `windows_installer_iso` drop from
  `_CATALOG_NEEDS_DISAMBIGUATION` in `format_detection.py`; the
  bootmgr substring block in `_legacy_bridge_detect` is deleted.

Closes the P3.2 postmortem deferral: "Both `windows_installer_iso`
(bootmgr substring) AND `iso_9660` (CD001 magic at offset 32769; works
today via magic_bytes signal) can drop from
`_CATALOG_NEEDS_DISAMBIGUATION` when a `substring_in_head` signal kind
ships."

Rule #25 Shape-1 single-slice cross-stack alignment commit; Rule #46
paired META-CANARY for SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS exhaustive
(both currently lack their paired gate-canaries — fixed here).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from app.schemas.file_format import (
    DetectionSignal,
    DetectionSignalKind,
    DispatchKind,
    FileFormatManifest,
    SubstringInHeadCombine,
    SubstringInHeadConstraint,
)
from app.services.file_format_catalog.resolver import (
    _SIGNAL_COST_CLASS,
    DISPATCH_EVALUATORS,
    SIGNAL_EVALUATORS,
    _eval_substring_in_head,
    resolve,
)

# ---------------------------------------------------------------------------
# Helpers — build signals + blobs
# ---------------------------------------------------------------------------


_BOOTMGR_HEX = "626f6f746d6772"                                 # 'bootmgr'
_SOURCES_BOOT_WIM_HEX = "736f75726365732f626f6f742e77696d"      # 'sources/boot.wim'
_SOURCES_BACKSLASH_HEX = "736f75726365735c626f6f742e77696d"     # 'sources\\boot.wim'
_CD001 = b"CD001"


def _bootmgr_signal(case_sensitive: bool = False) -> DetectionSignal:
    """Build the windows_installer_iso bootmgr substring signal."""
    return DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[
                _BOOTMGR_HEX,
                _SOURCES_BOOT_WIM_HEX,
                _SOURCES_BACKSLASH_HEX,
            ],
            case_sensitive=case_sensitive,
            combine="any",
            min_count=1,
        ),
    )


def _make_iso_with_bootmgr(bootmgr_text: bytes = b"bootmgr") -> bytes:
    """Build a Windows-installer-ISO-shaped blob: CD001 at 0x8001 + bootmgr."""
    head = bytearray(0x8006)
    head[0x100:0x100 + len(bootmgr_text)] = bootmgr_text
    head[0x8001:0x8006] = _CD001
    return bytes(head)


def _make_bare_iso() -> bytes:
    """Build a bare ISO-9660 blob: CD001 at 0x8001, no bootmgr."""
    head = bytearray(0x8006)
    head[0x8001:0x8006] = _CD001
    return bytes(head)


# ---------------------------------------------------------------------------
# Positive evaluator tests
# ---------------------------------------------------------------------------


def test_eval_substring_in_head_finds_bootmgr_lowercase():
    sig = _bootmgr_signal()
    blob = _make_iso_with_bootmgr(b"bootmgr")
    assert _eval_substring_in_head(sig, blob, "/tmp/win.iso", len(blob)) is True


def test_eval_substring_in_head_finds_bootmgr_uppercase_case_insensitive():
    """case_sensitive=False (default) — 'BOOTMGR' matches the bootmgr needle."""
    sig = _bootmgr_signal(case_sensitive=False)
    blob = _make_iso_with_bootmgr(b"BOOTMGR")
    assert _eval_substring_in_head(sig, blob, "/tmp/win.iso", len(blob)) is True


def test_eval_substring_in_head_finds_sources_boot_wim_alternative():
    """'sources/boot.wim' alone (no bootmgr) — any-combine still matches."""
    sig = _bootmgr_signal()
    head = bytearray(0x8006)
    head[0x500:0x500 + 16] = b"sources/boot.wim"
    head[0x8001:0x8006] = _CD001
    blob = bytes(head)
    assert _eval_substring_in_head(sig, blob, "/tmp/win.iso", len(blob)) is True


def test_eval_substring_in_head_finds_sources_backslash_alternative():
    """'sources\\boot.wim' (Windows path separator) — any-combine matches."""
    sig = _bootmgr_signal()
    head = bytearray(0x8006)
    head[0x500:0x500 + 16] = b"sources\\boot.wim"
    head[0x8001:0x8006] = _CD001
    blob = bytes(head)
    assert _eval_substring_in_head(sig, blob, "/tmp/win.iso", len(blob)) is True


# ---------------------------------------------------------------------------
# Negative evaluator tests
# ---------------------------------------------------------------------------


def test_eval_substring_in_head_rejects_when_no_needle_present():
    """Bare ISO-9660 with no installer markers — bootmgr signal misses."""
    sig = _bootmgr_signal()
    blob = _make_bare_iso()
    assert _eval_substring_in_head(sig, blob, "/tmp/bare.iso", len(blob)) is False


def test_eval_substring_in_head_rejects_case_sensitive_uppercase_when_needle_lowercase():
    """case_sensitive=True + needle 'bootmgr' lowercase + blob 'BOOTMGR' upper
    — strict match misses (case_sensitive flag honored)."""
    sig = _bootmgr_signal(case_sensitive=True)
    blob = _make_iso_with_bootmgr(b"BOOTMGR")
    assert _eval_substring_in_head(sig, blob, "/tmp/win.iso", len(blob)) is False


def test_eval_substring_in_head_rejects_empty_head():
    sig = _bootmgr_signal()
    assert _eval_substring_in_head(sig, b"", "/tmp/x", 0) is False


def test_eval_substring_in_head_rejects_when_needle_outside_search_window():
    """search_length restricts the scan; needle past the window doesn't count."""
    sig = DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX],
            search_offset=0,
            search_length=256,  # bootmgr at 0x100 = 256 — just outside
        ),
    )
    head = bytearray(0x400)
    head[0x100:0x107] = b"bootmgr"
    blob = bytes(head)
    # search_length=256 means window=head[0:256]; bootmgr starts at 0x100=256 — JUST past.
    assert _eval_substring_in_head(sig, blob, "/tmp/x.bin", len(blob)) is False


def test_eval_substring_in_head_search_offset_skips_early_match():
    """search_offset=0x200 skips bootmgr planted at 0x100."""
    sig = DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX],
            search_offset=0x200,
            search_length=None,
        ),
    )
    head = bytearray(0x400)
    head[0x100:0x107] = b"bootmgr"
    blob = bytes(head)
    assert _eval_substring_in_head(sig, blob, "/tmp/x.bin", len(blob)) is False


def test_eval_substring_in_head_search_offset_beyond_blob_rejects():
    """search_offset past the blob size — no possible match."""
    sig = DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX],
            search_offset=0x1000,
        ),
    )
    blob = b"\x00" * 0x100
    assert _eval_substring_in_head(sig, blob, "/tmp/x.bin", len(blob)) is False


# ---------------------------------------------------------------------------
# combine='all' + min_count semantics
# ---------------------------------------------------------------------------


def test_eval_substring_in_head_combine_all_requires_every_needle():
    """combine='all' — both needles must be present; one alone rejects."""
    sig = DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX, _SOURCES_BOOT_WIM_HEX],
            combine="all",
        ),
    )
    head_one_needle = bytearray(0x1000)
    head_one_needle[0x100:0x107] = b"bootmgr"  # bootmgr only
    head_both = bytearray(0x1000)
    head_both[0x100:0x107] = b"bootmgr"
    head_both[0x300:0x310] = b"sources/boot.wim"
    assert _eval_substring_in_head(
        sig, bytes(head_one_needle), "/tmp/x", 0x1000,
    ) is False
    assert _eval_substring_in_head(
        sig, bytes(head_both), "/tmp/x", 0x1000,
    ) is True


def test_eval_substring_in_head_combine_any_min_count_2_of_3():
    """combine='any' + min_count=2 — at least 2 of 3 needles must hit."""
    sig = DetectionSignal(
        kind="substring_in_head",
        substring_in_head_constraint=SubstringInHeadConstraint(
            needles_hex=[
                _BOOTMGR_HEX, _SOURCES_BOOT_WIM_HEX, _SOURCES_BACKSLASH_HEX,
            ],
            combine="any",
            min_count=2,
        ),
    )
    # Only 1 needle — rejects
    head_one = bytearray(0x1000)
    head_one[0x100:0x107] = b"bootmgr"
    assert _eval_substring_in_head(sig, bytes(head_one), "/tmp/x", 0x1000) is False
    # 2 needles — accepts
    head_two = bytearray(0x1000)
    head_two[0x100:0x107] = b"bootmgr"
    head_two[0x300:0x310] = b"sources/boot.wim"
    assert _eval_substring_in_head(sig, bytes(head_two), "/tmp/x", 0x1000) is True


# ---------------------------------------------------------------------------
# Catalog round-trip — windows_installer_iso vs iso_9660
# ---------------------------------------------------------------------------


def test_resolve_returns_windows_installer_iso_for_bootmgr_iso():
    """A CD001 ISO with bootmgr substring resolves to windows_installer_iso
    (precedence 100 < iso_9660's 200 wins post-P3.2.a flip)."""
    blob = _make_iso_with_bootmgr(b"bootmgr")
    match = resolve(blob, "/tmp/win.iso", len(blob))
    assert match is not None
    assert match.format_id == "windows_installer_iso"


def test_resolve_returns_iso_9660_for_bare_iso():
    """A CD001 ISO WITHOUT bootmgr falls through to iso_9660 — the
    windows_installer_iso signal #2 (substring_in_head) doesn't match,
    and combine=all_required rejects it; iso_9660 (CD001 alone) wins."""
    blob = _make_bare_iso()
    match = resolve(blob, "/tmp/bare.iso", len(blob))
    assert match is not None
    assert match.format_id == "iso_9660"


def test_resolve_returns_windows_installer_iso_with_uppercase_bootmgr():
    """Operator-renamed ISO with 'BOOTMGR.EFI' in uppercase still resolves
    via case_sensitive=False — matches the legacy bridge head_lower scan."""
    blob = _make_iso_with_bootmgr(b"BOOTMGR")
    match = resolve(blob, "/tmp/WIN10.iso", len(blob))
    assert match is not None
    assert match.format_id == "windows_installer_iso"


# ---------------------------------------------------------------------------
# Schema validation — required field, mutual exclusion, needles, min_count
# ---------------------------------------------------------------------------


def test_schema_rejects_substring_in_head_signal_without_constraint():
    with pytest.raises(ValidationError) as exc:
        DetectionSignal(
            kind="substring_in_head",
            description="bogus — missing constraint",
        )
    assert "substring_in_head_constraint" in str(exc.value)


def test_schema_rejects_substring_in_head_constraint_on_non_substring_kind():
    """Symmetric reject — constraint set on wrong kind is a typo / leftover."""
    with pytest.raises(ValidationError) as exc:
        DetectionSignal(
            kind="filename",
            extensions_lower=[".iso"],
            substring_in_head_constraint=SubstringInHeadConstraint(
                needles_hex=[_BOOTMGR_HEX],
            ),
        )
    assert "substring_in_head_constraint" in str(exc.value)


def test_schema_rejects_empty_needles_list():
    with pytest.raises(ValidationError):
        SubstringInHeadConstraint(needles_hex=[])


def test_schema_rejects_too_many_needles():
    """16-needle cap (Wave-1 S5 attack O floor)."""
    needles = ["41424344"] * 17  # 17 needles, all 4-hex (2 bytes)
    with pytest.raises(ValidationError):
        SubstringInHeadConstraint(needles_hex=needles)


def test_schema_rejects_needle_below_min_byte_floor():
    """Min 2 bytes per needle — 1-byte needles match too much."""
    with pytest.raises(ValidationError) as exc:
        SubstringInHeadConstraint(needles_hex=["41"])  # 1 byte
    assert "min 2 bytes" in str(exc.value) or "min_length" in str(exc.value).lower()


def test_schema_rejects_needle_above_max_byte_ceiling():
    """Max 64 bytes per needle (128 hex chars)."""
    too_long = "41" * 65  # 65 bytes = 130 hex chars
    with pytest.raises(ValidationError):
        SubstringInHeadConstraint(needles_hex=[too_long])


def test_schema_rejects_odd_length_needle():
    """Hex must be byte-aligned (even number of chars)."""
    with pytest.raises(ValidationError) as exc:
        SubstringInHeadConstraint(needles_hex=["41424"])  # 5 hex chars
    assert "byte-aligned" in str(exc.value) or "odd" in str(exc.value)


def test_schema_rejects_invalid_hex_needle():
    with pytest.raises(ValidationError):
        SubstringInHeadConstraint(needles_hex=["ZZZZ"])  # 'Z' not hex


def test_schema_rejects_min_count_exceeding_needles():
    """min_count=5 with only 2 needles — impossible to satisfy."""
    with pytest.raises(ValidationError) as exc:
        SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX, _SOURCES_BOOT_WIM_HEX],
            min_count=5,
        )
    assert "min_count" in str(exc.value)


def test_schema_extra_forbid_rejects_unknown_constraint_field():
    """Rule #52 closed-grammar — extra='forbid' on the constraint model."""
    with pytest.raises(ValidationError):
        SubstringInHeadConstraint(
            needles_hex=[_BOOTMGR_HEX],
            unknown_field="bogus",  # not in the model
        )


def test_schema_accepts_minimal_valid_constraint():
    """One needle, defaults for everything else, validates cleanly."""
    c = SubstringInHeadConstraint(needles_hex=[_BOOTMGR_HEX])
    assert c.combine == "any"
    assert c.min_count == 1
    assert c.case_sensitive is False
    assert c.search_offset == 0
    assert c.search_length is None


# ---------------------------------------------------------------------------
# Catalog manifest acceptance — operator YAML loads with the new signal
# ---------------------------------------------------------------------------


def _operator_manifest_dict(
    *,
    format_id: str = "test_substr_fmt",
    needles_hex: list[str] | None = None,
    combine: str = "any",
) -> dict:
    return {
        "format_id": format_id,
        "manifest_source": "operator",
        "precedence": 100,
        "category": "other",
        "vendor": "test_vendor",
        "confidence": "high",
        "detection": {
            "combine": "all_required",
            "signals": [{
                "kind": "substring_in_head",
                "description": "test substring",
                "substring_in_head_constraint": {
                    "needles_hex": needles_hex or [_BOOTMGR_HEX],
                    "combine": combine,
                },
            }],
        },
        "output": {
            "classifier_format": format_id,
            "classifier_category": "other",
            "classifier_vendor": "test_vendor",
            "confidence": "high",
        },
    }


def test_operator_manifest_accepts_substring_in_head_signal():
    """Operator-supplied YAML using substring_in_head loads cleanly."""
    data = _operator_manifest_dict()
    m = FileFormatManifest(**data)
    assert m.detection.signals[0].kind == "substring_in_head"
    assert (
        m.detection.signals[0].substring_in_head_constraint.needles_hex
        == [_BOOTMGR_HEX]
    )


# ---------------------------------------------------------------------------
# Rule #46 paired META-CANARY — SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS
# exhaustive against DetectionSignalKind. Both gates exist in
# test_file_format_catalog.py (M1 + extension); this file adds the
# PAIRED GATE-CANARIES that confirm the gates would catch synthetic
# violations.
# ---------------------------------------------------------------------------


def test_meta_canary_signal_evaluators_exhaustive_gate_actually_fires():
    """Rule #46 paired canary — synthesize a SIGNAL_EVALUATORS dict missing
    `substring_in_head` and confirm the exhaustive assertion would REJECT it."""
    expected = set(get_args(DetectionSignalKind))
    # Remove one value to simulate the "added Literal value but forgot
    # to wire the evaluator" failure mode.
    incomplete = {k: v for k, v in SIGNAL_EVALUATORS.items()
                  if k != "substring_in_head"}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected


def test_meta_canary_signal_cost_class_exhaustive():
    """Rule #46 — _SIGNAL_COST_CLASS must be exhaustive against
    DetectionSignalKind. Adding a Literal value without a cost-class
    entry would let the resolver fall back to cost 99 (signal evaluated
    LAST) — silent perf regression. Plug the gate."""
    expected = set(get_args(DetectionSignalKind))
    actual = set(_SIGNAL_COST_CLASS.keys())
    assert actual == expected, (
        f"_SIGNAL_COST_CLASS diverges from DetectionSignalKind: "
        f"missing={expected - actual}, extra={actual - expected}"
    )


def test_meta_canary_signal_cost_class_exhaustive_gate_actually_fires():
    """Rule #46 paired canary — synthesize a _SIGNAL_COST_CLASS dict
    missing `substring_in_head` + confirm the assertion would REJECT it."""
    expected = set(get_args(DetectionSignalKind))
    incomplete = {k: v for k, v in _SIGNAL_COST_CLASS.items()
                  if k != "substring_in_head"}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected


def test_meta_canary_dispatch_evaluators_exhaustive_gate_actually_fires():
    """Rule #46 paired canary — synthesize a DISPATCH_EVALUATORS dict
    missing one entry + confirm the exhaustive assertion REJECTS it.

    Companion to the existing `test_meta_canary_dispatch_evaluators_exhaustive`
    in test_file_format_catalog.py (which lacked its paired canary —
    Rule #46 hygiene fixup as part of this commit)."""
    expected = set(get_args(DispatchKind))
    # Remove one entry to simulate the failure mode.
    one_value = next(iter(DISPATCH_EVALUATORS.keys()))
    incomplete = {k: v for k, v in DISPATCH_EVALUATORS.items()
                  if k != one_value}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected


# ---------------------------------------------------------------------------
# META-CANARY — _eval_substring_in_head AST-walk: NO hardcoded byte literals
# (Rule #46 anti-hardcode — mirrors M5 for text_format)
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


def test_meta_canary_substring_in_head_evaluator_uses_declared_needles_not_hardcoded():
    """Rule #46 anti-hardcode META-CANARY.

    AST-walk `_eval_substring_in_head` body and assert NO format-specific
    byte literals like b"bootmgr" / b"CD001" appear — every byte the
    evaluator searches for MUST come from a needle on
    :class:`SubstringInHeadConstraint`. Generic mechanical bytes (empty,
    CR/LF) are allowed."""
    func = _ast_find_function(_resolver_source(), "_eval_substring_in_head")
    ALLOWED_BYTE_LITERALS = {b"", b"\n", b"\r", b"\r\n"}
    forbidden: list[bytes] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in ALLOWED_BYTE_LITERALS:
                forbidden.append(node.value)
    assert not forbidden, (
        f"_eval_substring_in_head contains hardcoded byte literals "
        f"{forbidden!r}; every byte comparison MUST go through "
        "signal.substring_in_head_constraint.needles_hex "
        "(Rule #52 closed-grammar discipline)"
    )


def test_meta_canary_substring_in_head_evaluator_anti_hardcode_gate_actually_fires():
    """Rule #46 paired canary — synthesize a hostile `_eval_substring_in_head`
    body with `b"bootmgr"` hardcoded + assert the M-NEW assertion REJECTS it."""
    hostile_src = (
        "def _eval_substring_in_head(signal, blob_head, path, size):\n"
        "    if b'\\x62\\x6f\\x6f\\x74\\x6d\\x67\\x72' in blob_head:\n"
        "        return True\n"
        "    return False\n"
    )
    func = _ast_find_function(hostile_src, "_eval_substring_in_head")
    ALLOWED_BYTE_LITERALS = {b"", b"\n", b"\r", b"\r\n"}
    forbidden = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in ALLOWED_BYTE_LITERALS:
                forbidden.append(node.value)
    assert forbidden == [b"bootmgr"], (
        f"Expected gate to catch [b'bootmgr'], got {forbidden}"
    )


# ---------------------------------------------------------------------------
# Combine literal exhaustive
# ---------------------------------------------------------------------------


def test_substring_in_head_combine_literal_values():
    """SubstringInHeadCombine = Literal['any', 'all'] — closed grammar.
    Locks the 2-value enumeration; extending requires Rule #25 Shape-1
    + an _eval_substring_in_head branch update."""
    assert set(get_args(SubstringInHeadCombine)) == {"any", "all"}
