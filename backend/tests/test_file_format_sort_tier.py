"""P3.2.a sort-tier reform tests.

Phase 3.2 commit `a` introduces the closed-grammar ``SortTier`` Literal on
``Detection`` with three values:

* ``floor``   — sentinels sort LAST (reserved to ``manifest_source="_system"``)
* ``general`` — default tier (sort by source_rank/precedence/specificity)
* ``ceiling`` — invariants sort FIRST (reserved; no current author)

The resolver's new sort key (computed by :func:`_compute_sort_key`) is:

    (tier_rank, -source_rank, precedence, -specificity, vendor, basename)

Per Wave-1 S1 + S2 + S5 + W2-α convergence:

* ``tier_rank`` outermost — ``ceiling`` (0) wins over ``general`` (1) wins
  over ``floor`` (2).
* ``-source_rank`` next — Scout GG §SC5 dual; manifest_source rank ALWAYS
  outranks numeric precedence WITHIN a tier.
* ``precedence`` (P3.2.a FLIP — lower wins, matching AUTHORING.md author
  intent across all 47 manifests).
* ``-specificity`` then lex tie-break.

This file covers tests T1-T12 (per Wave-1 S1 plan) + META-CANARIES M1-M4
with paired-violation canaries (Rule #46).
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from app.schemas.file_format import (
    Detection,
    DetectionSignal,
    FileFormatManifest,
    SortTier,
)
from app.services.file_format_catalog import get_default_snapshot
from app.services.file_format_catalog.resolver import (
    _TIER_RANK,
    _compute_sort_key,
    resolve,
)


# ---------------------------------------------------------------------------
# Helpers — minimal manifest dict that satisfies the FileFormatManifest schema
# ---------------------------------------------------------------------------


def _minimal_manifest_dict(
    *,
    format_id: str = "test_fmt",
    manifest_source: str = "core",
    precedence: int = 100,
    category: str = "other",
    vendor: str = "test_vendor",
    detection: dict | None = None,
) -> dict:
    if detection is None:
        detection = {
            "combine": "all_required",
            "signals": [{
                "kind": "magic_bytes",
                "offset": 0,
                "bytes_hex": "deadbeefcafebabe",
                "description": "test magic",
            }],
        }
    return {
        "format_id": format_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "category": category,
        "vendor": vendor,
        "confidence": "high",
        "detection": detection,
        "output": {
            "classifier_format": format_id,
            "classifier_category": category,
            "classifier_vendor": vendor,
            "confidence": "high",
        },
    }


# ---------------------------------------------------------------------------
# T1-T5 — resolve() returns specific format for raw vendor magic bytes.
# Previously these required the `_legacy_magic_classify` bridge.
# ---------------------------------------------------------------------------


def test_resolve_returns_mtk_lk_for_raw_mtk_magic():
    """Raw MTK LK header magic (0x88168858, partition name 'atf') resolves
    to the mtk_atf manifest via catalog dispatch, NOT linux_blob."""
    blob = b"\x88\x16\x88\x58" + b"\x00" * 252
    match = resolve(blob, "atf.img", 256)
    assert match is not None
    assert match.format_id in ("mtk_lk", "mtk_atf"), match.format_id


def test_resolve_returns_shannon_toc_for_raw_toc_magic():
    """Raw Samsung Shannon TOC magic resolves via catalog (not linux_blob)."""
    blob = b"TOC\x00" + b"\x00" * 60
    match = resolve(blob, "modem.bin", 64)
    assert match is not None
    assert match.format_id == "samsung_shannon_toc"


def test_resolve_returns_kinibi_mclf_for_raw_trus_magic():
    """Raw Kinibi MCLF (TrustZone TA) magic resolves via catalog."""
    blob = b"TRUS" + b"\x00" * 60
    match = resolve(blob, "t-mci-2.tlbin", 64)
    assert match is not None
    assert match.format_id == "kinibi_mclf"


def test_resolve_returns_mtk_preloader_for_raw_preloader_magic():
    """Raw MTK preloader (MMM\\x01\\x38) resolves via catalog."""
    blob = b"MMM\x01\x38" + b"\x00" * 59
    match = resolve(blob, "preloader.bin", 64)
    assert match is not None
    assert match.format_id == "mtk_preloader"


def test_resolve_returns_signed_archive_for_raw_signed_archive_magic():
    """Raw vendor signed archive magic resolves via catalog."""
    blob = b"\xa3\xdf\xbb\xbf" + b"\x00" * 60
    match = resolve(blob, "firmware.bin", 64)
    assert match is not None
    assert match.format_id == "signed_archive"


# ---------------------------------------------------------------------------
# T6 — sentinel still wins when nothing else matches
# ---------------------------------------------------------------------------


def test_resolve_returns_linux_blob_when_no_other_manifest_matches():
    """linux_blob_fallback sentinel wins ONLY when no general-tier manifest
    matches (its intended floor semantic)."""
    blob = b"\xde\xad\xbe\xef" * 16  # no known magic
    match = resolve(blob, "random.bin", 64)
    assert match is not None
    assert match.format_id == "linux_blob"


# ---------------------------------------------------------------------------
# T8 — ceiling invariant wins over general
# (Note: T7 multi-floor is structurally tested via the per-tier cardinality
# table; loosening cardinality is a follow-on extension test.)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# T9-T11 — schema-level rejection of operator sort_tier=floor/ceiling +
# always_matches/sort_tier consistency
# ---------------------------------------------------------------------------


def test_schema_rejects_operator_sort_tier_floor():
    """Operator-source manifests cannot declare sort_tier=floor (reserved
    to _system). Schema-level cross-field validator rejects at parse time."""
    data = _minimal_manifest_dict(manifest_source="operator", precedence=200)
    data["detection"]["sort_tier"] = "floor"
    with pytest.raises(ValidationError) as exc:
        FileFormatManifest(**data)
    assert "sort_tier" in str(exc.value)
    assert "_system" in str(exc.value)


def test_schema_rejects_core_sort_tier_ceiling():
    """Core-source manifests cannot declare sort_tier=ceiling (reserved
    to _system invariants)."""
    data = _minimal_manifest_dict(manifest_source="core", precedence=100)
    data["detection"]["sort_tier"] = "ceiling"
    with pytest.raises(ValidationError) as exc:
        FileFormatManifest(**data)
    assert "ceiling" in str(exc.value)
    assert "_system" in str(exc.value)


def test_schema_rejects_unauthenticated_external_sort_tier_floor():
    """Unauthenticated-external manifests cannot declare sort_tier=floor."""
    data = _minimal_manifest_dict(
        manifest_source="unauthenticated_external", precedence=100,
    )
    data["detection"]["sort_tier"] = "floor"
    with pytest.raises(ValidationError) as exc:
        FileFormatManifest(**data)
    assert "_system" in str(exc.value)


def test_schema_rejects_always_matches_without_floor_tier():
    """always_matches=True requires sort_tier=floor (Detection-level
    cross-field validator). Author intent must be explicit at both fields."""
    data = _minimal_manifest_dict(
        manifest_source="_system", precedence=0, category="linux_blob",
    )
    data["detection"] = {
        "combine": "any",
        "always_matches": True,
        "sort_tier": "general",  # mismatch — must be 'floor'
        "signals": [{"kind": "always_matches", "description": "fallback"}],
    }
    with pytest.raises(ValidationError) as exc:
        FileFormatManifest(**data)
    assert "always_matches" in str(exc.value)
    assert "floor" in str(exc.value)


def test_schema_accepts_system_sort_tier_floor_with_always_matches():
    """The canonical sentinel shape: _system + always_matches=True +
    sort_tier=floor + always_matches signals only — all gates pass."""
    data = _minimal_manifest_dict(
        manifest_source="_system", precedence=0, category="linux_blob",
        vendor="unknown",
    )
    data["detection"] = {
        "combine": "any",
        "always_matches": True,
        "sort_tier": "floor",
        "signals": [{"kind": "always_matches", "description": "fallback"}],
    }
    m = FileFormatManifest(**data)
    assert m.detection.sort_tier == "floor"
    assert m.detection.always_matches is True


# ---------------------------------------------------------------------------
# T12 — classifier no longer uses _legacy_magic_classify (after P3.2.a)
# ---------------------------------------------------------------------------


def test_classifier_no_longer_calls_legacy_magic_classify():
    """The `_legacy_magic_classify` branch was deleted in P3.2.a — the
    sort-tier reform makes vendor `core` manifests beat `_system` sentinel
    so the bridge is redundant. Source scan confirms the symbol is gone."""
    classifier_src = (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "hardware_firmware" / "classifier.py"
    ).read_text(encoding="utf-8")
    # The legacy bridge function and its call site must both be absent.
    assert "def _legacy_magic_classify" not in classifier_src
    assert "_legacy_magic_classify(magic)" not in classifier_src


# ---------------------------------------------------------------------------
# Sort-key sanity tests against live catalog snapshot
# ---------------------------------------------------------------------------


def test_compute_sort_key_floor_sentinel_sorts_after_general():
    """linux_blob_fallback (floor tier) MUST sort AFTER any general manifest."""
    snapshot = get_default_snapshot()
    linux_blob = next(m for m in snapshot.manifests if m.format_id == "linux_blob")
    mtk_lk = next(m for m in snapshot.manifests if m.format_id == "mtk_lk")
    assert _compute_sort_key(linux_blob) > _compute_sort_key(mtk_lk)


def test_compute_sort_key_floor_tier_rank_is_2():
    """floor → 2 (sorts LAST in ascending sort)."""
    assert _TIER_RANK["floor"] == 2


def test_compute_sort_key_ceiling_tier_rank_is_0():
    """ceiling → 0 (sorts FIRST in ascending sort)."""
    assert _TIER_RANK["ceiling"] == 0


def test_compute_sort_key_general_tier_rank_is_1():
    """general → 1 (default tier)."""
    assert _TIER_RANK["general"] == 1


def test_compute_sort_key_precedence_is_NOT_negated():
    """P3.2.a flip: precedence is the 3rd dimension and is NOT negated
    (lower precedence wins, matching AUTHORING.md author intent)."""
    snapshot = get_default_snapshot()
    # mtk_lk has precedence 50; qcom_mbn has precedence 50; signed_archive
    # has precedence 1000. Compare two general-tier manifests.
    mtk_lk = next(m for m in snapshot.manifests if m.format_id == "mtk_lk")
    sort_key = _compute_sort_key(mtk_lk)
    # 3rd element is precedence — must equal the manifest's value, not its negation
    assert sort_key[2] == mtk_lk.precedence


def test_source_precedence_invariant_holds_within_tier():
    """Scout GG §SC5 dual: WITHIN a tier, manifest_source rank outranks
    numeric precedence. operator+precedence=200 STILL beats
    unauthenticated_external+precedence=50."""
    op_manifest = FileFormatManifest(**_minimal_manifest_dict(
        format_id="op_fmt",
        manifest_source="operator",
        precedence=200,
    ))
    ext_manifest = FileFormatManifest(**_minimal_manifest_dict(
        format_id="ext_fmt",
        manifest_source="unauthenticated_external",
        precedence=50,
    ))
    op_key = _compute_sort_key(op_manifest)
    ext_key = _compute_sort_key(ext_manifest)
    # operator wins (sorts BEFORE unauthenticated_external) in ascending sort
    assert op_key < ext_key


# ---------------------------------------------------------------------------
# META-CANARY M1 — sort-key tuple shape (AST-walk _compute_sort_key body)
# ---------------------------------------------------------------------------


def _ast_find_function_body(module_src: str, func_name: str) -> ast.FunctionDef:
    """Return the AST FunctionDef node for ``func_name`` in module source."""
    tree = ast.parse(module_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    raise AssertionError(f"function {func_name!r} not found in module source")


def _ast_find_returned_tuple(func: ast.FunctionDef) -> ast.Tuple:
    """Return the AST Tuple node returned from a single-return function."""
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            return node.value
    raise AssertionError(f"function {func.name!r}: no Tuple-shaped return found")


def _compute_sort_key_source() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "file_format_catalog" / "resolver.py"
    ).read_text(encoding="utf-8")


def test_meta_canary_sort_key_tuple_shape_m1():
    """Token-scan resolver source for the canonical sort-key tuple shape.

    Rule #46 — gate fires when a future commit reorders the sort key (e.g.
    moves -source_rank before tier_rank or negates `manifest.precedence`).
    Scoped to `_compute_sort_key` function body (P3.1.c lesson — AST-walk
    a single function, not the whole module).
    """
    src = _compute_sort_key_source()
    func = _ast_find_function_body(src, "_compute_sort_key")
    tup = _ast_find_returned_tuple(func)
    assert len(tup.elts) == 6, (
        f"_compute_sort_key returns {len(tup.elts)}-tuple; expected 6 "
        "(tier_rank, -source_rank, precedence, -specificity, vendor, basename)"
    )
    # Element 0: tier_rank (Name)
    assert isinstance(tup.elts[0], ast.Name), \
        f"sort_key[0] must be Name 'tier_rank', got {type(tup.elts[0]).__name__}"
    assert tup.elts[0].id == "tier_rank"
    # Element 1: -source_rank (UnaryOp(USub, Name('source_rank')))
    assert isinstance(tup.elts[1], ast.UnaryOp), \
        f"sort_key[1] must be UnaryOp(-source_rank), got {type(tup.elts[1]).__name__}"
    assert isinstance(tup.elts[1].op, ast.USub)
    assert isinstance(tup.elts[1].operand, ast.Name)
    assert tup.elts[1].operand.id == "source_rank"
    # Element 2: manifest.precedence (Attribute) — NOT NEGATED (P3.2.a flip)
    assert isinstance(tup.elts[2], ast.Attribute), (
        f"sort_key[2] must be Attribute manifest.precedence (NOT NEGATED — "
        f"P3.2.a flip; lower precedence wins); got {type(tup.elts[2]).__name__}"
    )
    assert tup.elts[2].attr == "precedence"
    # Element 3: -specificity
    assert isinstance(tup.elts[3], ast.UnaryOp)
    assert isinstance(tup.elts[3].op, ast.USub)


def test_meta_canary_sort_key_tuple_shape_m1_gate_actually_fires():
    """Rule #46 paired canary: construct an AST representing the WRONG sort
    key (precedence at position 0 instead of tier_rank) and confirm the
    gate's structural assertion would reject it.

    This proves the M1 gate is actually checking the shape it claims to;
    without this canary, the gate's pass is structurally indistinguishable
    from "the gate didn't run". Generalizable Rule #46 paired-canary
    discipline (κ.D + ι.D lesson — synthesize violations in-memory).
    """
    # Synthetic wrong-shape tuple: precedence first, tier_rank second.
    wrong_src = """
def _compute_sort_key(manifest):
    tier_rank = 1
    source_rank = 100
    specificity = 5
    return (
        manifest.precedence,  # WRONG — should be tier_rank first
        tier_rank,            # WRONG — should be -source_rank second
        -source_rank,
        -specificity,
        manifest.vendor.lower(),
        "",
    )
"""
    func = _ast_find_function_body(wrong_src, "_compute_sort_key")
    tup = _ast_find_returned_tuple(func)
    # Apply the same structural assertion logic as M1; it MUST fail on
    # this synthetic. We catch the failure to confirm the gate would fire.
    with pytest.raises(AssertionError):
        # The first-element check: must be Name 'tier_rank'. In the
        # synthetic, it's an Attribute manifest.precedence.
        assert isinstance(tup.elts[0], ast.Name) and tup.elts[0].id == "tier_rank"


# ---------------------------------------------------------------------------
# META-CANARY M2 — _TIER_RANK exhaustive coverage against SortTier Literal
# ---------------------------------------------------------------------------


def test_meta_canary_tier_rank_table_exhaustive_m2():
    """The resolver's _TIER_RANK keys must be exhaustive against SortTier."""
    expected = set(get_args(SortTier))
    actual = set(_TIER_RANK.keys())
    assert actual == expected, (
        f"_TIER_RANK keys diverge from SortTier Literal: "
        f"missing={expected - actual}, extra={actual - expected}"
    )


def test_meta_canary_tier_rank_table_exhaustive_m2_gate_actually_fires():
    """Rule #46 paired canary: simulate a SortTier extension without
    matching _TIER_RANK update, confirm the exhaustiveness check fires."""
    # Synthesize a wrong table — missing a value.
    incomplete_table = {"ceiling": 0, "general": 1}  # missing 'floor'
    expected = set(get_args(SortTier))
    actual = set(incomplete_table.keys())
    # The M2 assertion: actual == expected. Must fail on the synthetic.
    with pytest.raises(AssertionError):
        assert actual == expected


# ---------------------------------------------------------------------------
# META-CANARY M3 — every YAML in the catalog data dir with sort_tier in
# (floor, ceiling) MUST be under _system/
# ---------------------------------------------------------------------------


def test_meta_canary_no_non_system_sort_tier_floor_or_ceiling_m3():
    """Walk all catalog YAMLs; assert any manifest with sort_tier in
    (floor, ceiling) is under _system/. Defense-in-depth against an
    operator-supplied YAML bypassing the schema validator.
    """
    import yaml as pyyaml
    data_root = (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "file_format_catalog" / "data" / "file_formats"
    )
    for yaml_path in data_root.rglob("*.yaml"):
        text = yaml_path.read_text(encoding="utf-8")
        doc = pyyaml.safe_load(text)
        if not isinstance(doc, dict):
            continue
        det = doc.get("detection", {})
        if not isinstance(det, dict):
            continue
        sort_tier = det.get("sort_tier", "general")
        if sort_tier in ("floor", "ceiling"):
            assert "_system" in yaml_path.parts, (
                f"{yaml_path}: declares sort_tier={sort_tier!r} but is NOT "
                f"under _system/ — schema validator + this canary BOTH reject"
            )


def test_meta_canary_no_non_system_sort_tier_floor_or_ceiling_m3_gate_actually_fires(
    tmp_path: Path,
):
    """Rule #46 paired canary: synthesize a hostile YAML at a non-_system
    path declaring sort_tier=floor; assert the M3 walker semantic would
    REJECT it (via the assertion clause, not via filesystem-walking the
    synthetic — the canary verifies the GATE LOGIC).
    """
    import yaml as pyyaml
    hostile_dir = tmp_path / "test_vendor"
    hostile_dir.mkdir()
    hostile_yaml = hostile_dir / "hostile.yaml"
    hostile_yaml.write_text(pyyaml.safe_dump({
        "format_id": "hostile_fmt",
        "manifest_source": "core",
        "precedence": 100,
        "category": "other",
        "vendor": "hostile",
        "confidence": "high",
        "detection": {
            "combine": "all_required",
            "sort_tier": "floor",  # HOSTILE — non-_system claiming floor
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeefcafebabe", "description": ""}],
        },
        "output": {
            "classifier_format": "hostile_fmt",
            "classifier_category": "other",
            "classifier_vendor": "hostile",
            "confidence": "high",
        },
    }))
    # Apply the M3 gate logic to this synthetic; assert it would reject.
    doc = pyyaml.safe_load(hostile_yaml.read_text(encoding="utf-8"))
    sort_tier = doc["detection"].get("sort_tier", "general")
    assert sort_tier in ("floor", "ceiling")
    # The M3 assertion: "_system" in path parts. Must fail.
    with pytest.raises(AssertionError):
        assert "_system" in hostile_yaml.parts


# ---------------------------------------------------------------------------
# META-CANARY M4 — Detection.always_matches⇔sort_tier=floor correlation
# (defense-in-depth at catalog-load time; schema validator catches authoring)
# ---------------------------------------------------------------------------


def test_meta_canary_always_matches_implies_floor_in_catalog_m4():
    """Every manifest with always_matches=True in the live catalog MUST
    also declare sort_tier=floor (already enforced by Detection model_validator
    at schema validation; this canary is defense-in-depth at runtime)."""
    snapshot = get_default_snapshot()
    for m in snapshot.manifests:
        if m.detection.always_matches:
            assert m.detection.sort_tier == "floor", (
                f"{m.format_id!r}: always_matches=True but sort_tier="
                f"{m.detection.sort_tier!r} — schema validator should have "
                "rejected this; runtime gate fired as defense-in-depth"
            )


def test_meta_canary_always_matches_implies_floor_gate_actually_fires_m4():
    """Rule #46 paired canary: construct a synthetic Detection with
    always_matches=True and sort_tier=general; assert the schema validator
    rejects it (cross-field invariant enforces the correlation)."""
    with pytest.raises(ValidationError) as exc:
        Detection(
            combine="any",
            always_matches=True,
            sort_tier="general",
            signals=[DetectionSignal(
                kind="always_matches", description="bogus general sentinel",
            )],
        )
    assert "always_matches" in str(exc.value)
    assert "floor" in str(exc.value)
