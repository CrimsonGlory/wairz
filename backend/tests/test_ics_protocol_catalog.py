"""ICS protocol catalog + resolver tests — Session 1 Commit 2.

Coverage:
1. Catalog construction + isolated tmp roots
2. Path cross-check (declared manifest_source × on-disk path tier)
3. Manifest-id duplicate detection
4. I4 cross-vendor collision
5. Resolver — magic_bytes / string_in_binary / function_code_set
6. Resolver — combine semantics (all_required / any / weighted)
7. Resolver — multi-protocol-per-binary cardinality (list[match])
8. Certainty cap on confidence
9. Rule #46 META-CANARIES — SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS exhaustive
   + paired gate-canaries
10. Rule #46 anti-hardcode AST canaries for all 3 active evaluators
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import get_args

import pytest
import yaml as pyyaml

from app.schemas.ics_protocol import (
    IcsDetection,
    IcsDetectionSignal,
    IcsFunctionCodeSetConstraint,
    IcsProtocolManifest,
    IcsSignalKind,
    IcsStringInBinaryConstraint,
)
from app.services.ics_protocol_catalog import (
    _SIGNAL_COST_CLASS,
    _SOURCE_PRECEDENCE,
    SIGNAL_EVALUATORS,
    IcsProtocolCatalog,
    IcsResolverContext,
    derive_vendor_authority,
    resolve_all,
)
from app.services.ics_protocol_catalog.catalog import (
    _expected_source_for_overlay_path,
    _expected_source_for_path,
)
from app.services.ics_protocol_catalog.resolver import (
    _eval_function_code_set,
    _eval_magic_bytes,
    _eval_string_in_binary,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pyyaml.safe_dump(data), encoding="utf-8")


def _minimal_manifest_dict(
    *,
    manifest_id: str,
    manifest_source: str = "core",
    precedence: int = 100,
    vendor: str = "generic",
    signals: list[dict] | None = None,
    protocol_family: str = "modbus_tcp",
) -> dict:
    if signals is None:
        signals = [{"kind": "magic_bytes", "offset": 0, "bytes_hex": "abcd"}]
    return {
        "schema_version": 1,
        "manifest_id": manifest_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "detection": {"combine": "all_required", "signals": signals},
        "output": {
            "protocol_family": protocol_family,
            "layer": "transport",
            "transport": "tcp",
            "vendor": vendor,
        },
    }


@pytest.fixture
def catalog(tmp_path: Path) -> IcsProtocolCatalog:
    data_root = tmp_path / "data" / "ics_protocols"
    overlay_root = tmp_path / "data" / "ics_protocols.local"
    data_root.mkdir(parents=True)
    overlay_root.mkdir(parents=True)
    return IcsProtocolCatalog(
        data_root=data_root, overlay_root=overlay_root,
    )


# ---------------------------------------------------------------------------
# Catalog construction + basic loading
# ---------------------------------------------------------------------------


def test_catalog_empty_data_root_returns_empty_snapshot(catalog):
    snap = catalog.get_snapshot()
    assert len(snap) == 0
    assert catalog.last_warning is None


def test_catalog_loads_system_manifest(catalog, tmp_path):
    sys_dir = catalog.data_root / "_system"
    _write_yaml(
        sys_dir / "modbus_tcp.yaml",
        _minimal_manifest_dict(
            manifest_id="modbus_tcp_system",
            manifest_source="_system",
            precedence=5,
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 1
    m = snap.get("modbus_tcp_system")
    assert m is not None
    assert m.manifest_source == "_system"
    assert catalog.last_warning is None


def test_catalog_loads_core_manifest(catalog):
    schneider_dir = catalog.data_root / "schneider"
    _write_yaml(
        schneider_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="schneider_modbus",
            manifest_source="core",
            vendor="schneider",
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 1


def test_catalog_loads_operator_overlay(catalog):
    _write_yaml(
        catalog.overlay_root / "my_modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="my_operator_modbus",
            manifest_source="operator",
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 1
    assert snap.get("my_operator_modbus").manifest_source == "operator"


# ---------------------------------------------------------------------------
# Path cross-check (W2-β §SC5-NEW-ICS-4 mitigation)
# ---------------------------------------------------------------------------


def test_path_cross_check_rejects_system_claim_from_core_path(catalog):
    """An operator drops a `.yaml` under data/ics_protocols/schneider/ but
    declares `manifest_source: _system` — loader REJECTS because path is
    under <vendor>/, not _system/."""
    schneider_dir = catalog.data_root / "schneider"
    _write_yaml(
        schneider_dir / "hostile.yaml",
        _minimal_manifest_dict(
            manifest_id="hostile",
            manifest_source="_system",  # mismatch — path is core/schneider
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 0
    assert catalog.last_warning is not None
    assert "path tier" in catalog.last_warning
    assert "_system" in catalog.last_warning


def test_path_cross_check_rejects_system_claim_from_overlay(catalog):
    """Operator-overlay file declares `manifest_source: _system` — REJECTED."""
    _write_yaml(
        catalog.overlay_root / "hostile.yaml",
        _minimal_manifest_dict(
            manifest_id="hostile_overlay",
            manifest_source="_system",
            precedence=5,
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 0
    assert "path tier" in catalog.last_warning


def test_path_cross_check_rejects_core_claim_from_overlay(catalog):
    """Overlay path = operator; declaring core is a mismatch."""
    _write_yaml(
        catalog.overlay_root / "hostile.yaml",
        _minimal_manifest_dict(
            manifest_id="hostile_core",
            manifest_source="core",
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 0


def test_expected_source_helpers():
    """Direct test of the path-tier helpers."""
    data_root = Path("/tmp/data_root")
    overlay_root = Path("/tmp/overlay_root")
    assert _expected_source_for_path(
        data_root / "_system/modbus.yaml", data_root,
    ) == "_system"
    assert _expected_source_for_path(
        data_root / "schneider/modbus.yaml", data_root,
    ) == "core"
    assert _expected_source_for_overlay_path(
        overlay_root / "modbus.yaml", overlay_root,
    ) == "operator"
    assert _expected_source_for_overlay_path(
        overlay_root / "_attested_external/partner.yaml", overlay_root,
    ) == "attested_external"


# ---------------------------------------------------------------------------
# Duplicate manifest_id rejection
# ---------------------------------------------------------------------------


def test_catalog_rejects_duplicate_manifest_id(catalog):
    sys_dir = catalog.data_root / "_system"
    schneider_dir = catalog.data_root / "schneider"
    _write_yaml(
        sys_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="duplicate_id",
            manifest_source="_system",
            precedence=5,
        ),
    )
    _write_yaml(
        schneider_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="duplicate_id",  # same id, different path
            manifest_source="core",
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 1  # one survives, the other is dropped
    assert catalog.last_warning is not None
    assert "duplicate manifest_id" in catalog.last_warning


# ---------------------------------------------------------------------------
# I4 cross-vendor collision
# ---------------------------------------------------------------------------


def test_i4_cross_vendor_collision_drops_later_manifest(catalog):
    """Two operator manifests claim Modbus magic at the same offset with
    DIFFERENT vendors — I4 drops the later one with a WARN."""
    _write_yaml(
        catalog.overlay_root / "vendor_a_modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="aaa_vendor_a_modbus",
            manifest_source="operator",
            vendor="vendor_a",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    _write_yaml(
        catalog.overlay_root / "vendor_b_modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="bbb_vendor_b_modbus",
            manifest_source="operator",
            vendor="vendor_b",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 1
    assert snap.get("aaa_vendor_a_modbus") is not None  # lex-first survives
    assert snap.get("bbb_vendor_b_modbus") is None
    assert "I4 cross-vendor collision" in catalog.last_warning


def test_i4_does_not_collide_same_vendor_multiple_manifests(catalog):
    """Two manifests with SAME vendor + SAME magic — fine; no I4 collision."""
    _write_yaml(
        catalog.overlay_root / "modbus_a.yaml",
        _minimal_manifest_dict(
            manifest_id="schneider_modbus_a",
            manifest_source="operator",
            vendor="schneider",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    _write_yaml(
        catalog.overlay_root / "modbus_b.yaml",
        _minimal_manifest_dict(
            manifest_id="schneider_modbus_b",
            manifest_source="operator",
            vendor="schneider",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 2  # both kept; same vendor


def test_i4_does_not_collide_different_source_tiers(catalog):
    """Different manifest_source rank — different authority levels, no I4."""
    sys_dir = catalog.data_root / "_system"
    _write_yaml(
        sys_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="system_modbus",
            manifest_source="_system",
            precedence=5,
            vendor="generic",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    _write_yaml(
        catalog.overlay_root / "vendor_modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="vendor_modbus_alias",
            manifest_source="operator",
            vendor="schneider",
            signals=[{
                "kind": "magic_bytes", "offset": 0,
                "bytes_hex": "00000300",
            }],
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 2  # different tier ranks — no collision


# ---------------------------------------------------------------------------
# derive_vendor_authority (I2)
# ---------------------------------------------------------------------------


def test_derive_vendor_authority_per_source():
    for source, expected in [
        ("_system", "curated"),
        ("core", "curated"),
        ("operator", "operator_supplied"),
        ("attested_external", "operator_supplied"),
        ("unauthenticated_external", "community"),
    ]:
        m = IcsProtocolManifest(**_minimal_manifest_dict(
            manifest_id=f"t_{source}", manifest_source=source,
            precedence=5 if source == "_system" else 100,
        ))
        assert derive_vendor_authority(m) == expected


# ---------------------------------------------------------------------------
# Resolver — magic_bytes evaluator
# ---------------------------------------------------------------------------


def test_eval_magic_bytes_matches_at_offset():
    sig = IcsDetectionSignal(
        kind="magic_bytes", offset=4, bytes_hex="abcd1234",
    )
    blob = b"\x00\x00\x00\x00\xab\xcd\x12\x34" + b"\x00" * 8
    assert _eval_magic_bytes(sig, blob, "/tmp/x", len(blob), None) is True


def test_eval_magic_bytes_rejects_mismatch():
    sig = IcsDetectionSignal(
        kind="magic_bytes", offset=0, bytes_hex="abcd1234",
    )
    blob = b"\x00" * 16
    assert _eval_magic_bytes(sig, blob, "/tmp/x", 16, None) is False


def test_eval_magic_bytes_with_mask():
    sig = IcsDetectionSignal(
        kind="magic_bytes", offset=0, bytes_hex="abcd1234",
        mask_hex="ff00ff00",  # only high bytes matter
    )
    blob = b"\xab\x99\x12\x99"
    assert _eval_magic_bytes(sig, blob, "/tmp/x", 4, None) is True


# ---------------------------------------------------------------------------
# Resolver — string_in_binary evaluator
# ---------------------------------------------------------------------------


def test_eval_string_in_binary_lowercase_match():
    constraint = IcsStringInBinaryConstraint(
        needles_hex=["4d6f64627573"],  # "Modbus"
        case_sensitive=False,
    )
    sig = IcsDetectionSignal(
        kind="string_in_binary",
        string_in_binary_constraint=constraint,
    )
    blob = b"\x00" * 100 + b"MODBUS" + b"\x00" * 100
    assert _eval_string_in_binary(sig, blob, "/tmp/x", len(blob), None) is True


def test_eval_string_in_binary_case_sensitive_rejects_mixed_case():
    constraint = IcsStringInBinaryConstraint(
        needles_hex=["4d6f64627573"],  # lowercase "Modbus" in hex
        case_sensitive=True,
    )
    sig = IcsDetectionSignal(
        kind="string_in_binary",
        string_in_binary_constraint=constraint,
    )
    blob = b"\x00" * 50 + b"MODBUS" + b"\x00" * 50
    # Case-sensitive — needle is lowercase "Modbus", blob has uppercase MODBUS
    # The hex 4d6f64627573 IS "Modbus" (M-o-d-b-u-s), so blob "MODBUS" differs
    # at every position 1-5 (uppercase vs lowercase). Strict match fails.
    assert _eval_string_in_binary(sig, blob, "/tmp/x", len(blob), None) is False


def test_eval_string_in_binary_combine_any_min_count_2():
    constraint = IcsStringInBinaryConstraint(
        needles_hex=["6d6f64627573", "646e7033", "73376363"],  # modbus/dnp3/s7cc
        combine="any",
        min_count=2,
    )
    sig = IcsDetectionSignal(
        kind="string_in_binary",
        string_in_binary_constraint=constraint,
    )
    # 1 needle present — rejects
    blob_one = b"modbus stack" + b"\x00" * 100
    assert _eval_string_in_binary(sig, blob_one, "/tmp/x", 100, None) is False
    # 2 needles present — accepts
    blob_two = b"modbus and dnp3 both" + b"\x00" * 100
    assert _eval_string_in_binary(sig, blob_two, "/tmp/x", 100, None) is True


def test_eval_string_in_binary_combine_all_requires_every():
    constraint = IcsStringInBinaryConstraint(
        needles_hex=["6d6f64627573", "646e7033"],  # modbus/dnp3
        combine="all",
    )
    sig = IcsDetectionSignal(
        kind="string_in_binary",
        string_in_binary_constraint=constraint,
    )
    blob_one = b"modbus only" + b"\x00" * 100
    assert _eval_string_in_binary(sig, blob_one, "/tmp/x", 100, None) is False
    blob_both = b"modbus and dnp3" + b"\x00" * 100
    assert _eval_string_in_binary(sig, blob_both, "/tmp/x", 100, None) is True


# ---------------------------------------------------------------------------
# Resolver — function_code_set evaluator
# ---------------------------------------------------------------------------


def test_eval_function_code_set_finds_modbus_codes():
    """Modbus FCs 0x01, 0x03, 0x05 in a single window — matches."""
    constraint = IcsFunctionCodeSetConstraint(
        function_codes_hex=["01", "03", "05", "06", "0f", "10"],
        min_count=3,
        window_bytes=128,
    )
    sig = IcsDetectionSignal(
        kind="function_code_set",
        function_code_constraint=constraint,
    )
    # Plant FCs 0x01, 0x03, 0x05 within a 128-byte window.
    blob = b"\x00" * 64 + b"\x01\x03\x05\x06" + b"\x00" * 1024
    assert _eval_function_code_set(sig, blob, "/tmp/x", len(blob), None) is True


def test_eval_function_code_set_rejects_too_few_codes_in_window():
    constraint = IcsFunctionCodeSetConstraint(
        function_codes_hex=["01", "03", "05", "06"],
        min_count=4,
        window_bytes=64,
    )
    sig = IcsDetectionSignal(
        kind="function_code_set",
        function_code_constraint=constraint,
    )
    # Only 2 FCs visible — rejects.
    blob = b"\xff" * 64 + b"\x01\x03" + b"\xff" * 64
    assert _eval_function_code_set(sig, blob, "/tmp/x", len(blob), None) is False


# ---------------------------------------------------------------------------
# resolve_all — multi-protocol-per-binary cardinality
# ---------------------------------------------------------------------------


def test_resolve_all_returns_multiple_matches_when_present(catalog):
    """A binary speaking BOTH Modbus AND DNP3 — resolver returns 2 matches."""
    sys_dir = catalog.data_root / "_system"
    _write_yaml(
        sys_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="modbus_match",
            manifest_source="_system",
            precedence=5,
            signals=[{
                "kind": "string_in_binary",
                "string_in_binary_constraint": {
                    "needles_hex": ["4d6f64627573"],  # "Modbus"
                    "case_sensitive": False,
                },
            }],
        ),
    )
    _write_yaml(
        sys_dir / "dnp3.yaml",
        _minimal_manifest_dict(
            manifest_id="dnp3_match",
            manifest_source="_system",
            precedence=5,
            protocol_family="dnp3",
            signals=[{
                "kind": "string_in_binary",
                "string_in_binary_constraint": {
                    "needles_hex": ["444e5033"],  # "DNP3"
                    "case_sensitive": False,
                },
            }],
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    assert len(snap) == 2

    blob = b"Modbus and DNP3 both present" + b"\x00" * 100
    matches = resolve_all(blob, "/tmp/multi_proto.bin", len(blob), snap)
    assert len(matches) == 2
    families = {m.protocol_family for m in matches}
    assert families == {"modbus_tcp", "dnp3"}


def test_resolve_all_returns_empty_when_no_match(catalog):
    sys_dir = catalog.data_root / "_system"
    _write_yaml(
        sys_dir / "modbus.yaml",
        _minimal_manifest_dict(
            manifest_id="modbus_only",
            manifest_source="_system",
            precedence=5,
            signals=[{
                "kind": "string_in_binary",
                "string_in_binary_constraint": {
                    "needles_hex": ["4d6f64627573"],
                    "case_sensitive": False,
                },
            }],
        ),
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    blob = b"\x00" * 1024
    matches = resolve_all(blob, "/tmp/empty.bin", 1024, snap)
    assert matches == []


def test_resolve_all_skips_removed_deprecated_manifests(catalog):
    sys_dir = catalog.data_root / "_system"
    _write_yaml(
        sys_dir / "old_modbus.yaml",
        {
            **_minimal_manifest_dict(
                manifest_id="old_modbus",
                manifest_source="_system",
                precedence=5,
                signals=[{
                    "kind": "string_in_binary",
                    "string_in_binary_constraint": {
                        "needles_hex": ["4d6f64627573"],
                        "case_sensitive": False,
                    },
                }],
            ),
            "deprecation": {"status": "removed"},
        },
    )
    catalog.reload()
    snap = catalog.get_snapshot()
    blob = b"Modbus is here" + b"\x00" * 100
    matches = resolve_all(blob, "/tmp/b.bin", len(blob), snap)
    assert matches == []  # removed manifests don't fire


# ---------------------------------------------------------------------------
# Certainty cap on confidence
# ---------------------------------------------------------------------------


def test_certainty_string_only_caps_confidence_at_low(catalog):
    sys_dir = catalog.data_root / "_system"
    data = _minimal_manifest_dict(
        manifest_id="ss_modbus",
        manifest_source="_system",
        precedence=5,
        signals=[{
            "kind": "string_in_binary",
            "string_in_binary_constraint": {
                "needles_hex": ["4d6f64627573"],
                "case_sensitive": False,
            },
        }],
    )
    data["detection"]["certainty"] = "string_only"
    data["output"]["confidence"] = "high"  # Operator-supplied ceiling
    _write_yaml(sys_dir / "ss.yaml", data)
    catalog.reload()
    snap = catalog.get_snapshot()
    blob = b"Modbus is here" + b"\x00" * 100
    matches = resolve_all(blob, "/tmp/b.bin", len(blob), snap)
    assert len(matches) == 1
    # string_only certainty caps confidence to low regardless of operator value.
    assert matches[0].confidence == "low"


def test_certainty_config_present_caps_confidence_at_medium(catalog):
    sys_dir = catalog.data_root / "_system"
    data = _minimal_manifest_dict(
        manifest_id="cp_modbus",
        manifest_source="_system",
        precedence=5,
        signals=[{
            "kind": "string_in_binary",
            "string_in_binary_constraint": {
                "needles_hex": ["4d6f64627573"],
                "case_sensitive": False,
            },
        }],
    )
    data["detection"]["certainty"] = "config_present"
    data["output"]["confidence"] = "high"
    _write_yaml(sys_dir / "cp.yaml", data)
    catalog.reload()
    snap = catalog.get_snapshot()
    blob = b"Modbus is here" + b"\x00" * 100
    matches = resolve_all(blob, "/tmp/b.bin", len(blob), snap)
    assert matches[0].confidence == "medium"


# ---------------------------------------------------------------------------
# Rule #46 META-CANARIES — closed-table exhaustive + paired gate-canaries
# ---------------------------------------------------------------------------


def test_meta_canary_signal_evaluators_exhaustive():
    """Rule #46: every IcsSignalKind has a SIGNAL_EVALUATORS entry."""
    declared = set(get_args(IcsSignalKind))
    wired = set(SIGNAL_EVALUATORS.keys())
    assert declared == wired, (
        f"IcsSignalKind values not wired: {declared - wired}; "
        f"orphan evaluators: {wired - declared}"
    )


def test_meta_canary_signal_evaluators_exhaustive_gate_actually_fires():
    """Paired gate-canary — synthesize a missing entry + assert exhaustive check fails."""
    expected = set(get_args(IcsSignalKind))
    incomplete = {k: v for k, v in SIGNAL_EVALUATORS.items()
                  if k != "magic_bytes"}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected


def test_meta_canary_signal_cost_class_exhaustive():
    declared = set(get_args(IcsSignalKind))
    wired = set(_SIGNAL_COST_CLASS.keys())
    assert declared == wired


def test_meta_canary_signal_cost_class_exhaustive_gate_actually_fires():
    expected = set(get_args(IcsSignalKind))
    incomplete = {k: v for k, v in _SIGNAL_COST_CLASS.items()
                  if k != "string_in_binary"}
    with pytest.raises(AssertionError):
        assert set(incomplete.keys()) == expected


def test_meta_canary_source_precedence_exhaustive():
    from app.schemas.ics_protocol import IcsManifestSource
    declared = set(get_args(IcsManifestSource))
    wired = set(_SOURCE_PRECEDENCE.keys())
    assert declared == wired


def test_meta_canary_source_precedence_exhaustive_gate_actually_fires():
    from app.schemas.ics_protocol import IcsManifestSource
    expected = set(get_args(IcsManifestSource))
    incomplete = {k: v for k, v in _SOURCE_PRECEDENCE.items()
                  if k != "_system"}
    with pytest.raises(AssertionError):
        assert set(incomplete.keys()) == expected


# ---------------------------------------------------------------------------
# Rule #46 — anti-hardcode AST canaries for active evaluators
# ---------------------------------------------------------------------------


def _resolver_source() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "ics_protocol_catalog" / "resolver.py"
    ).read_text(encoding="utf-8")


def _ast_find_function(module_src: str, name: str) -> ast.FunctionDef:
    tree = ast.parse(module_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")


def test_meta_canary_string_in_binary_evaluator_no_hardcoded_bytes():
    """Rule #46 anti-hardcode META-CANARY — _eval_string_in_binary body
    must contain NO format-specific byte literals; every byte the evaluator
    searches for comes from signal.string_in_binary_constraint.needles_hex.
    """
    func = _ast_find_function(_resolver_source(), "_eval_string_in_binary")
    allowed = {b"", b"\n", b"\r", b"\r\n"}
    forbidden: list[bytes] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in allowed:
                forbidden.append(node.value)
    assert not forbidden, (
        f"_eval_string_in_binary contains hardcoded bytes: {forbidden!r}"
    )


def test_meta_canary_string_in_binary_anti_hardcode_gate_actually_fires():
    """Paired canary — synthesize a hostile `_eval_string_in_binary` with
    hardcoded `b"Modbus"` + assert the gate REJECTS it."""
    hostile_src = (
        "def _eval_string_in_binary(signal, blob_head, path, size, context):\n"
        "    if b'\\x4d\\x6f\\x64\\x62\\x75\\x73' in blob_head:\n"
        "        return True\n"
        "    return False\n"
    )
    func = _ast_find_function(hostile_src, "_eval_string_in_binary")
    allowed = {b"", b"\n", b"\r", b"\r\n"}
    forbidden = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in allowed:
                forbidden.append(node.value)
    assert forbidden == [b"Modbus"]


def test_meta_canary_function_code_set_evaluator_no_hardcoded_codes():
    """Rule #46 anti-hardcode — _eval_function_code_set body must not
    contain hardcoded function-code values (every code byte comes from
    constraint.function_codes_hex)."""
    func = _ast_find_function(_resolver_source(), "_eval_function_code_set")
    # Allow empty bytes + CR/LF terminator literals (mechanical I/O); no
    # other byte literals permitted.
    allowed = {b"", b"\n", b"\r", b"\r\n"}
    forbidden = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in allowed:
                forbidden.append(node.value)
    assert not forbidden


def test_meta_canary_function_code_anti_hardcode_gate_actually_fires():
    hostile_src = (
        "def _eval_function_code_set(signal, blob_head, path, size, context):\n"
        "    modbus_codes = b'\\x01\\x03\\x05\\x06\\x0f\\x10'\n"
        "    if all(c in blob_head for c in modbus_codes):\n"
        "        return True\n"
        "    return False\n"
    )
    func = _ast_find_function(hostile_src, "_eval_function_code_set")
    allowed = {b"", b"\n", b"\r", b"\r\n"}
    forbidden = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            if node.value not in allowed:
                forbidden.append(node.value)
    assert forbidden == [b"\x01\x03\x05\x06\x0f\x10"]


# ---------------------------------------------------------------------------
# Hot-reload + snapshot id semantics
# ---------------------------------------------------------------------------


def test_catalog_snapshot_id_stable_across_cosmetic_reloads(catalog):
    sys_dir = catalog.data_root / "_system"
    yaml_path = sys_dir / "modbus.yaml"
    _write_yaml(
        yaml_path,
        _minimal_manifest_dict(
            manifest_id="modbus_stable",
            manifest_source="_system",
            precedence=5,
        ),
    )
    catalog.reload()
    snap_1 = catalog.get_snapshot()
    sid_1 = snap_1.snapshot_id

    # Cosmetic re-write — bump mtime but content unchanged after YAML parse.
    yaml_path.write_text(yaml_path.read_text() + "\n# comment\n")
    catalog.reload()
    snap_2 = catalog.get_snapshot()
    sid_2 = snap_2.snapshot_id

    # Same canonical content → same snapshot_id (Wave-1 S5 K cosmetic-reload).
    assert sid_1 == sid_2


def test_catalog_snapshot_id_flips_on_semantic_change(catalog):
    sys_dir = catalog.data_root / "_system"
    yaml_path = sys_dir / "modbus.yaml"
    _write_yaml(
        yaml_path,
        _minimal_manifest_dict(
            manifest_id="modbus_change",
            manifest_source="_system",
            precedence=5,
        ),
    )
    catalog.reload()
    sid_1 = catalog.get_snapshot().snapshot_id

    # Semantic change — precedence flips.
    _write_yaml(
        yaml_path,
        _minimal_manifest_dict(
            manifest_id="modbus_change",
            manifest_source="_system",
            precedence=7,  # different
        ),
    )
    catalog.reload()
    sid_2 = catalog.get_snapshot().snapshot_id
    assert sid_1 != sid_2


def test_catalog_state_snapshot_keys():
    """state_snapshot() returns operator-visible telemetry keys."""
    cat = IcsProtocolCatalog(
        data_root=Path("/tmp/nonexistent_data_root_does_not_exist_xyz"),
        overlay_root=Path("/tmp/nonexistent_overlay_root_does_not_exist_xyz"),
    )
    state = cat.state_snapshot()
    assert "data_root" in state
    assert "overlay_root" in state
    assert "manifest_count" in state
    assert "snapshot_id" in state
    assert "loaded_at_unix_ns" in state
    assert "last_warning" in state
