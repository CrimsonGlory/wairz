"""P3.1.b catalog loader + frozen snapshot + cost-sorted resolver tests.

Mirrors :mod:`backend.tests.test_chip_catalog` shape — tmp_path fixture, per-file
mtime probes, graceful-degrade assertions.

Coverage:

* Catalog basics — empty/missing root; multi-vendor subdirs; mtime caching;
  reload-on-change; file add/remove; malformed YAML keeps prior; warn-once;
  Pydantic ValidationError preserves prior; empty-yaml rejected.
* Path cross-check (Wave-1 S3 G + W2-alpha Q7) — _system/<x> must declare
  ``manifest_source: _system``; core <vendor>/<x> must declare ``core``;
  overlay must declare ``operator``.
* Cross-feature validators A1-A5 (W2-beta) — mode=override authority;
  vendor_authority derivation from manifest_source not alias_of;
  dispatch target removed rejected; cross-vendor magic collision rejected;
  deep dispatch + eager expensive plugin rejected.
* Resolver Rule #46 META-CANARIES — total-order tuple sort (token-scan);
  collect-then-sort (behavioural); SQL CASE manifest_source (token-scan);
  signal cost-class order (behavioural); SIGNAL_EVALUATORS exhaustive vs
  DetectionSignalKind Literal; DISPATCH_EVALUATORS exhaustive vs DispatchKind;
  plugin registry frozen post-init; only one always_matches manifest allowed;
  linux_blob fallback live canary; PE head live canary.
* Snapshot (Wave-1 S5 D + K) — id changes on semantic edit; id preserved on
  comment-only edit; walker pins snapshot at scan entry.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import get_args

import pytest
import yaml

from app.schemas.file_format import (
    DetectionSignalKind,
    DispatchKind,
    FileFormatManifest,
)
from app.services.file_format_catalog import (
    DISPATCH_EVALUATORS,
    PLUGIN_REGISTRY,
    SIGNAL_EVALUATORS,
    FormatCatalog,
    FormatCatalogSnapshot,
    freeze_plugin_registry,
    register_matcher,
    resolve,
)
from app.services.file_format_catalog.catalog import (
    _AUTHORITY_FROM_SOURCE,
    derive_vendor_authority,
)
from app.services.file_format_catalog.resolver import (
    _PLUGIN_REGISTRY_FROZEN,
    _SIGNAL_COST_CLASS,
    _SOURCE_PRECEDENCE,
    _unfreeze_plugin_registry_for_tests,
)

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _minimal_manifest_dict(
    *,
    format_id: str = "test_fmt",
    manifest_source: str = "_system",
    precedence: int = 0,
    category: str = "linux_blob",
    vendor: str = "unknown",
    confidence: str = "low",
    detection: dict | None = None,
    output: dict | None = None,
    dispatch: dict | None = None,
    deprecation: dict | None = None,
    plugin: dict | None = None,
    mode: str = "new",
    overrides: str | None = None,
    pre_upload: dict | None = None,
    notes: str | None = None,
) -> dict:
    """Minimal valid manifest as a dict."""
    if detection is None:
        # Default: always_matches (only valid for _system / linux_blob).
        # P3.2.a: sort_tier=floor required when always_matches=True.
        if manifest_source == "_system":
            detection = {
                "combine": "any",
                "always_matches": True,
                "sort_tier": "floor",
                "signals": [{"kind": "always_matches", "description": "any"}],
            }
        else:
            detection = {
                "combine": "all_required",
                "signals": [
                    {
                        "kind": "magic_bytes",
                        "offset": 0,
                        "bytes_hex": "deadbeef",
                        "description": "test magic",
                    }
                ],
            }
    if output is None:
        output = {
            "classifier_format": format_id,
            "classifier_category": category,
            "classifier_vendor": vendor,
            "confidence": confidence,
        }
    m: dict = {
        "schema_version": 1,
        "format_id": format_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "category": category,
        "vendor": vendor,
        "confidence": confidence,
        "detection": detection,
        "output": output,
        "mode": mode,
    }
    if overrides is not None:
        m["overrides"] = overrides
    if dispatch is not None:
        m["dispatch"] = dispatch
    if deprecation is not None:
        m["deprecation"] = deprecation
    if plugin is not None:
        m["plugin"] = plugin
    if pre_upload is not None:
        m["pre_upload"] = pre_upload
    if notes is not None:
        m["notes"] = notes
    return m


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


@pytest.fixture
def catalog(tmp_path):
    """Two-root catalog rooted at tmp_path/system and tmp_path/local."""
    system_root = tmp_path / "system"
    local_root = tmp_path / "local"
    system_root.mkdir()
    local_root.mkdir()
    return FormatCatalog(
        root_resolver=lambda: system_root,
        local_root_resolver=lambda: local_root,
    )


@pytest.fixture(autouse=True)
def _reset_plugin_registry():
    """Reset PLUGIN_REGISTRY between tests (frozen-flag + entries)."""
    saved = dict(PLUGIN_REGISTRY)
    _unfreeze_plugin_registry_for_tests()
    PLUGIN_REGISTRY.clear()
    yield
    PLUGIN_REGISTRY.clear()
    PLUGIN_REGISTRY.update(saved)
    _unfreeze_plugin_registry_for_tests()


# ---------------------------------------------------------------------------
# Catalog basics
# ---------------------------------------------------------------------------


def test_empty_root_returns_empty_catalog(catalog):
    assert catalog.get_catalog() == {}
    assert catalog.last_warning is None


def test_missing_root_returns_empty_catalog(tmp_path):
    bogus = tmp_path / "no_such_dir"
    cat = FormatCatalog(root_resolver=lambda: bogus)
    assert cat.get_catalog() == {}


def test_loads_single_valid_yaml(catalog, tmp_path):
    system_root = tmp_path / "system"
    sys_dir = system_root / "_system"
    _write_yaml(
        sys_dir / "linux_blob.yaml",
        _minimal_manifest_dict(format_id="linux_blob"),
    )
    snapshot = catalog.get_catalog()
    assert "linux_blob" in snapshot
    manifest = snapshot["linux_blob"]
    assert isinstance(manifest, FileFormatManifest)
    assert manifest.source_path is not None


def test_multiple_vendor_subdirs(catalog, tmp_path):
    system_root = tmp_path / "system"
    _write_yaml(
        system_root / "qualcomm" / "qcom_mbn.yaml",
        _minimal_manifest_dict(
            format_id="qcom_mbn", manifest_source="core",
            precedence=100, vendor="qualcomm",
        ),
    )
    _write_yaml(
        system_root / "mediatek" / "mtk_lk.yaml",
        _minimal_manifest_dict(
            format_id="mtk_lk", manifest_source="core",
            precedence=100, vendor="mediatek",
            detection={
                "combine": "all_required",
                "signals": [
                    {"kind": "magic_bytes", "offset": 0,
                     "bytes_hex": "cafebabe", "description": "mtk"},
                ],
            },
        ),
    )
    snapshot = catalog.get_catalog()
    assert "qcom_mbn" in snapshot
    assert "mtk_lk" in snapshot


def test_cached_on_unchanged_mtime(catalog, tmp_path):
    system_root = tmp_path / "system"
    _write_yaml(
        system_root / "_system" / "a.yaml",
        _minimal_manifest_dict(format_id="a"),
    )
    catalog.get_catalog()
    initial_reloads = catalog.reload_count
    catalog.get_catalog()
    catalog.get_catalog()
    assert catalog.reload_count == initial_reloads


def test_reloads_on_mtime_change(catalog, tmp_path):
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v1"))
    snapshot1 = catalog.get_catalog()
    assert snapshot1["a"].notes == "v1"

    time.sleep(0.01)
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v2"))
    snapshot2 = catalog.get_catalog()
    assert snapshot2["a"].notes == "v2"


def test_file_deletion_drops_from_catalog(catalog, tmp_path):
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a"))
    assert "a" in catalog.get_catalog()
    path.unlink()
    snapshot = catalog.get_catalog()
    assert snapshot == {}


def test_new_file_appears_in_catalog(catalog, tmp_path):
    system_root = tmp_path / "system"
    # Both manifests use magic_bytes (not always_matches) so the
    # sentinel-cardinality rule doesn't fire.
    _write_yaml(
        system_root / "qualcomm" / "a.yaml",
        _minimal_manifest_dict(
            format_id="a", manifest_source="core", precedence=100,
            vendor="qualcomm",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "deadbeef", "description": "a"}],
            },
        ),
    )
    assert "a" in catalog.get_catalog()
    _write_yaml(
        system_root / "mediatek" / "b.yaml",
        _minimal_manifest_dict(
            format_id="b", manifest_source="core", precedence=100,
            vendor="mediatek",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "cafebabe", "description": "b"}],
            },
        ),
    )
    snapshot = catalog.get_catalog()
    assert "a" in snapshot
    assert "b" in snapshot


def test_malformed_yaml_no_prior_skipped(catalog, tmp_path):
    system_root = tmp_path / "system"
    bad = system_root / "_system" / "bad.yaml"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{this: is: not: valid: yaml", encoding="utf-8")
    snapshot = catalog.get_catalog()
    assert snapshot == {}
    assert catalog.last_warning is not None
    assert "bad.yaml" in catalog.last_warning


def test_malformed_yaml_keeps_prior(catalog, tmp_path):
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a"))
    snapshot1 = catalog.get_catalog()
    assert "a" in snapshot1

    time.sleep(0.01)
    path.write_text("garbage: [unclosed", encoding="utf-8")
    snapshot2 = catalog.get_catalog()
    assert "a" in snapshot2  # prior valid retained
    assert catalog.last_warning is not None


def test_warn_once_per_failed_mtime(catalog, tmp_path):
    system_root = tmp_path / "system"
    bad = system_root / "_system" / "bad.yaml"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{unclosed", encoding="utf-8")
    catalog.get_catalog()
    first_warning = catalog.last_warning
    catalog.get_catalog()
    catalog.get_catalog()
    assert catalog.last_warning == first_warning


def test_pydantic_validation_error_keeps_prior(catalog, tmp_path):
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a"))
    snapshot1 = catalog.get_catalog()
    assert "a" in snapshot1

    bad = _minimal_manifest_dict(format_id="a")
    bad["confidence"] = "totally_bogus"  # Literal violation
    time.sleep(0.01)
    _write_yaml(path, bad)
    snapshot2 = catalog.get_catalog()
    assert "a" in snapshot2
    assert "totally_bogus" in (catalog.last_warning or "")


def test_empty_yaml_file_treated_as_malformed(catalog, tmp_path):
    system_root = tmp_path / "system"
    (system_root / "_system").mkdir()
    (system_root / "_system" / "empty.yaml").write_text("", encoding="utf-8")
    snapshot = catalog.get_catalog()
    assert snapshot == {}
    assert catalog.last_warning is not None


# ---------------------------------------------------------------------------
# Path cross-check (Wave-1 S3 G + W2-alpha Q7)
# ---------------------------------------------------------------------------


def test_path_cross_check_system_yaml_must_declare_system_source(catalog, tmp_path):
    """File at _system/<x>.yaml MUST declare manifest_source: _system."""
    system_root = tmp_path / "system"
    # Put a file in _system/ but declare it as core
    bad = _minimal_manifest_dict(
        format_id="a", manifest_source="core", precedence=100,
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "x"}],
        },
    )
    _write_yaml(system_root / "_system" / "a.yaml", bad)
    snapshot = catalog.get_catalog()
    assert "a" not in snapshot
    assert catalog.last_warning is not None
    assert "path cross-check" in catalog.last_warning


def test_path_cross_check_core_yaml_must_declare_core_source(catalog, tmp_path):
    """File at <vendor>/<x>.yaml MUST declare manifest_source: core."""
    system_root = tmp_path / "system"
    bad = _minimal_manifest_dict(
        format_id="a", manifest_source="operator", precedence=100,
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "x"}],
        },
    )
    _write_yaml(system_root / "qualcomm" / "a.yaml", bad)
    snapshot = catalog.get_catalog()
    assert "a" not in snapshot


def test_path_cross_check_overlay_yaml_must_declare_operator_source(catalog, tmp_path):
    """File at file_formats.local/<x>.yaml MUST declare manifest_source: operator."""
    local_root = tmp_path / "local"
    bad = _minimal_manifest_dict(
        format_id="a", manifest_source="core", precedence=100,
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "x"}],
        },
    )
    _write_yaml(local_root / "custom.yaml", bad)
    snapshot = catalog.get_catalog()
    assert "a" not in snapshot


def test_path_mismatch_rejected_with_last_warning_set(catalog, tmp_path):
    """Verify mismatch flow sets last_warning."""
    system_root = tmp_path / "system"
    bad = _minimal_manifest_dict(
        format_id="a", manifest_source="operator", precedence=100,
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "x"}],
        },
    )
    _write_yaml(system_root / "qualcomm" / "a.yaml", bad)
    catalog.get_catalog()
    assert catalog.last_warning is not None
    assert "operator" in catalog.last_warning


# ---------------------------------------------------------------------------
# Cross-feature validators A1-A5 (W2-beta)
# ---------------------------------------------------------------------------


def test_a1_mode_override_authority_rejects_lower_tier_overriding_higher(
    catalog, tmp_path,
):
    """A1: an `operator` mode=override CANNOT override a `_system` manifest."""
    system_root = tmp_path / "system"
    local_root = tmp_path / "local"
    # First: _system loads pe_binary
    _write_yaml(
        system_root / "_system" / "pe_binary.yaml",
        _minimal_manifest_dict(
            format_id="pe_binary", manifest_source="_system",
            precedence=9000, category="windows_pe",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d5a", "description": "MZ"}],
            },
        ),
    )
    # Then: operator overlay tries to override.
    # precedence MUST be >= 5000 to clear the schema's negative-evidence
    # floor for 2-byte magic; even so, A1 still rejects this manifest
    # because operator's rank (60) < _system's rank (100).
    _write_yaml(
        local_root / "pe_override.yaml",
        _minimal_manifest_dict(
            format_id="pe_binary", manifest_source="operator",
            precedence=5000, category="windows_pe", vendor="custom",
            mode="override", overrides="_system/pe_binary.yaml",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d5a", "description": "MZ"}],
            },
        ),
    )
    snapshot = catalog.get_catalog()
    # _system entry still wins
    assert "pe_binary" in snapshot
    assert snapshot["pe_binary"].manifest_source == "_system"
    # And A1 warning was logged
    assert catalog.last_warning is not None
    assert "A1" in catalog.last_warning


def test_a2_vendor_authority_derived_from_this_manifest_not_alias(catalog, tmp_path):
    """A2: vendor_authority is DERIVED from manifest_source, never alias_of."""
    # Test the derivation function directly + via a catalog with two manifests
    system_root = tmp_path / "system"

    # _system manifest → curated
    sys_dict = _minimal_manifest_dict(
        format_id="primary", manifest_source="_system", precedence=100,
    )
    _write_yaml(system_root / "_system" / "primary.yaml", sys_dict)

    # core manifest aliasing the _system one
    core_dict = _minimal_manifest_dict(
        format_id="aliased", manifest_source="core", precedence=100,
        vendor="qualcomm", category="linux_blob",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "cafebabe", "description": "alias"}],
        },
    )
    core_dict["alias_of"] = "primary"
    _write_yaml(system_root / "qualcomm" / "aliased.yaml", core_dict)
    snapshot = catalog.get_catalog()

    primary = snapshot["primary"]
    aliased = snapshot["aliased"]
    assert derive_vendor_authority(primary) == "curated"
    assert derive_vendor_authority(aliased) == "curated"  # core -> curated

    # If we mark `aliased` as operator, authority MUST become operator_supplied
    # even though it aliases a curated manifest (A2 — no laundering).
    core_dict2 = dict(core_dict)
    core_dict2["manifest_source"] = "operator"
    # Test the function in isolation since path enforces core
    # Build manifest directly
    from app.schemas.file_format import FileFormatManifest as FFM
    op_manifest = FFM.model_validate({**core_dict2, "alias_of": "primary"})
    assert derive_vendor_authority(op_manifest) == "operator_supplied"


def test_a3_dispatch_target_removed_rejected_at_load(catalog, tmp_path):
    """A3: if dispatch.cases targets a removed format, REJECT the dispatcher."""
    system_root = tmp_path / "system"
    # Removed target
    removed = _minimal_manifest_dict(
        format_id="old_fmt", manifest_source="_system", precedence=50,
    )
    removed["deprecation"] = {
        "status": "removed", "replaced_by": "new_fmt", "removal_phase": "P5",
    }
    _write_yaml(system_root / "_system" / "old.yaml", removed)
    # Dispatcher referencing the removed target
    dispatcher = _minimal_manifest_dict(
        format_id="container", manifest_source="core", precedence=100,
        vendor="qualcomm",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "dispatch"}],
        },
        dispatch={
            "kind": "by_partition_name",
            "cases": {"old": "old_fmt"},
        },
    )
    _write_yaml(system_root / "qualcomm" / "container.yaml", dispatcher)
    snapshot = catalog.get_catalog()
    assert "container" not in snapshot
    assert catalog.last_warning is not None
    assert "A3" in catalog.last_warning


def test_a4_cross_vendor_same_precedence_collision_rejected(catalog, tmp_path):
    """A4: same precedence + same magic + DIFFERENT vendor + SAME source → REJECT."""
    system_root = tmp_path / "system"
    qcom = _minimal_manifest_dict(
        format_id="fmt_q", manifest_source="core", precedence=100,
        vendor="qualcomm",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "abcd1234", "description": "qcom magic"}],
        },
    )
    mtk = _minimal_manifest_dict(
        format_id="fmt_m", manifest_source="core", precedence=100,
        vendor="mediatek",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "abcd1234", "description": "mtk magic"}],
        },
    )
    _write_yaml(system_root / "qualcomm" / "fmt_q.yaml", qcom)
    _write_yaml(system_root / "mediatek" / "fmt_m.yaml", mtk)
    snapshot = catalog.get_catalog()
    assert "fmt_q" not in snapshot
    assert "fmt_m" not in snapshot
    assert catalog.last_warning is not None
    assert "A4" in catalog.last_warning


def test_a5_dispatch_depth_max_eager_expensive_plugin_rejected(catalog, tmp_path):
    """A5: depth_max >= 2 + eager expensive plugin in target → REJECT."""
    system_root = tmp_path / "system"

    # Register an expensive plugin
    class ExpensivePlugin:
        cost_class = _SIGNAL_COST_CLASS["magic_bytes"]
        applicable_format_ids = frozenset({"target_fmt"})

        def detect(self, blob_head, path, size):
            return None

    register_matcher("expensive_plugin", ExpensivePlugin())

    # Target manifest uses eager expensive plugin
    target = _minimal_manifest_dict(
        format_id="target_fmt", manifest_source="core", precedence=100,
        vendor="qualcomm",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "cafebabe", "description": "target"}],
        },
        plugin={
            "matcher": {
                "ref": "expensive_plugin",
                "bind": "eager",
                "role": "primary",
            },
        },
    )
    _write_yaml(system_root / "qualcomm" / "target_fmt.yaml", target)

    # Dispatcher with depth_max=2 chains to target
    dispatcher = _minimal_manifest_dict(
        format_id="container", manifest_source="core", precedence=100,
        vendor="mediatek",
        detection={
            "combine": "all_required",
            "signals": [{"kind": "magic_bytes", "offset": 0,
                         "bytes_hex": "deadbeef", "description": "container"}],
        },
        dispatch={
            "kind": "by_partition_name",
            "cases": {"key": "target_fmt"},
            "depth_max": 2,
        },
    )
    _write_yaml(system_root / "mediatek" / "container.yaml", dispatcher)

    snapshot = catalog.get_catalog()
    assert "container" not in snapshot
    assert catalog.last_warning is not None
    assert "A5" in catalog.last_warning


# ---------------------------------------------------------------------------
# Resolver Rule #46 META-CANARIES
# ---------------------------------------------------------------------------


def test_meta_canary_resolver_uses_total_order_tuple_not_filesystem_iteration():
    """Rule #46 META-CANARY: resolver.py source contains _SOURCE_PRECEDENCE
    tuple ordering, not bare filesystem iteration order."""
    resolver_path = Path(__file__).parent.parent / "app" / "services" / \
        "file_format_catalog" / "resolver.py"
    src = resolver_path.read_text(encoding="utf-8")
    assert "_SOURCE_PRECEDENCE" in src
    # The total-order sort_key tuple must reference source_rank
    assert "source_rank" in src
    # First-match is explicitly REJECTED
    assert "candidates.sort" in src
    # No raw filesystem-iteration sort
    assert "ORDER BY received_at" not in src


def test_meta_canary_resolver_collects_all_matches_then_sorts(catalog, tmp_path):
    """Rule #46 META-CANARY (behavioural): even when filesystem iteration
    produces an _operator_supplied_ manifest first, the _system one wins."""
    system_root = tmp_path / "system"
    local_root = tmp_path / "local"
    # Operator overlay magic — high precedence
    _write_yaml(
        local_root / "op_high.yaml",
        _minimal_manifest_dict(
            format_id="op_high", manifest_source="operator",
            precedence=9999, vendor="custom_op", category="windows_pe",
            confidence="low",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d5a", "description": "MZ"}],
            },
        ),
    )
    # _system PE manifest, precedence 9000 — LOWER than operator's 9999.
    _write_yaml(
        system_root / "_system" / "pe.yaml",
        _minimal_manifest_dict(
            format_id="pe_binary", manifest_source="_system",
            precedence=9000, category="windows_pe", confidence="low",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d5a", "description": "MZ"}],
            },
        ),
    )
    snapshot = catalog.get_snapshot()
    blob_head = b"MZ" + b"\x00" * 30
    match = resolve(blob_head, "/tmp/x.exe", 32, snapshot=snapshot)
    assert match is not None
    # _system manifest_source rank (100) outranks operator (60) regardless of
    # the higher precedence value. Scout GG §SC5 dual proven.
    assert match.manifest_source == "_system"
    assert match.format_id == "pe_binary"


def test_meta_canary_sql_uses_manifest_source_case_not_just_precedence():
    """Rule #46 META-CANARY: resolver source has _SOURCE_PRECEDENCE as a
    closed dict, not a free-form numeric-only ordering."""
    resolver_path = Path(__file__).parent.parent / "app" / "services" / \
        "file_format_catalog" / "resolver.py"
    src = resolver_path.read_text(encoding="utf-8")
    # The constant MUST exist and use the closed Literal values
    assert '"_system": 100' in src
    assert '"core": 80' in src
    assert '"operator": 60' in src
    # No ORDER BY received_at-style "first wins" anti-pattern
    assert "first_match" not in src
    assert "ORDER BY received_at" not in src


def test_meta_canary_signal_evaluation_uses_cost_class_order_not_declared(
    catalog, tmp_path,
):
    """Rule #46 META-CANARY (behavioural): magic_bytes signal listed FIRST
    in YAML + filename signal listed last; resolver evaluates filename
    FIRST (cost class 0), short-circuits, and never calls magic_bytes."""
    calls: list[str] = []
    original_filename = SIGNAL_EVALUATORS["filename"]
    original_magic = SIGNAL_EVALUATORS["magic_bytes"]

    def trace_filename(signal, head, path, size):
        calls.append("filename")
        return original_filename(signal, head, path, size)

    def trace_magic(signal, head, path, size):
        calls.append("magic_bytes")
        return original_magic(signal, head, path, size)

    SIGNAL_EVALUATORS["filename"] = trace_filename
    SIGNAL_EVALUATORS["magic_bytes"] = trace_magic
    try:
        system_root = tmp_path / "system"
        # Filename will NOT match (path is /tmp/blob.bin; stem 'blob' not in list)
        manifest_dict = _minimal_manifest_dict(
            format_id="test_fmt", manifest_source="core", precedence=100,
            vendor="qualcomm",
            detection={
                "combine": "all_required",
                "signals": [
                    {"kind": "magic_bytes", "offset": 0,
                     "bytes_hex": "deadbeef", "description": "first in YAML"},
                    {"kind": "filename",
                     "stems_lower": ["nonexistent"],
                     "description": "last in YAML, cost-class 0"},
                ],
            },
        )
        _write_yaml(system_root / "qualcomm" / "test_fmt.yaml", manifest_dict)
        snapshot = catalog.get_snapshot()
        blob_head = b"\xde\xad\xbe\xef" + b"\x00" * 28
        resolve(blob_head, "/tmp/blob.bin", 32, snapshot=snapshot)
        # filename evaluated first (cost class 0); short-circuit on miss;
        # magic_bytes NEVER called despite being listed first in YAML.
        assert calls
        assert calls[0] == "filename"
        assert "magic_bytes" not in calls
    finally:
        SIGNAL_EVALUATORS["filename"] = original_filename
        SIGNAL_EVALUATORS["magic_bytes"] = original_magic


def test_meta_canary_signal_evaluators_exhaustive():
    """Rule #46: every DetectionSignalKind has a SIGNAL_EVALUATORS entry."""
    declared = set(get_args(DetectionSignalKind))
    wired = set(SIGNAL_EVALUATORS.keys())
    assert declared == wired, (
        f"DetectionSignalKind values not wired: {declared - wired}; "
        f"orphan evaluators: {wired - declared}"
    )


def test_meta_canary_dispatch_evaluators_exhaustive():
    """Rule #46: every DispatchKind has a DISPATCH_EVALUATORS entry."""
    declared = set(get_args(DispatchKind))
    wired = set(DISPATCH_EVALUATORS.keys())
    assert declared == wired, (
        f"DispatchKind values not wired: {declared - wired}; "
        f"orphan evaluators: {wired - declared}"
    )


def test_meta_canary_plugin_registry_frozen_after_init_rejects_late_register():
    """Rule #46 (W2-beta attack I): late registration MUST raise."""
    class FakePlugin:
        cost_class = 0
        applicable_format_ids = frozenset()

        def detect(self, head, path, size):
            return None

    register_matcher("ok_before_freeze", FakePlugin())
    freeze_plugin_registry()
    with pytest.raises(RuntimeError, match="frozen"):
        register_matcher("late", FakePlugin())


def test_meta_canary_only_one_always_matches_manifest_allowed(catalog, tmp_path):
    """Per-tier cardinality (P3.2.a): only ONE sort_tier=floor manifest allowed.

    Replaces the prior singleton-always_matches check. The new per-tier table
    in catalog.py caps `floor: 1` and `ceiling: 0` at load time. Loosen via
    Rule #25 Shape-1 when a concrete second-floor use case appears.
    """
    system_root = tmp_path / "system"
    sys_dir = system_root / "_system"
    # First sentinel
    _write_yaml(
        sys_dir / "fallback_a.yaml",
        _minimal_manifest_dict(
            format_id="fallback_a", manifest_source="_system",
            precedence=0, category="linux_blob",
            detection={
                "combine": "any",
                "always_matches": True,
                "sort_tier": "floor",
                "signals": [{"kind": "always_matches", "description": "a"}],
            },
        ),
    )
    # Second sentinel — should be dropped (per-tier cardinality)
    _write_yaml(
        sys_dir / "fallback_b.yaml",
        _minimal_manifest_dict(
            format_id="fallback_b", manifest_source="_system",
            precedence=1, category="linux_blob",
            detection={
                "combine": "any",
                "always_matches": True,
                "sort_tier": "floor",
                "signals": [{"kind": "always_matches", "description": "b"}],
            },
        ),
    )
    snapshot = catalog.get_catalog()
    sentinels = [
        f for f, m in snapshot.items() if m.detection.always_matches
    ]
    assert len(sentinels) == 1
    assert catalog.last_warning is not None
    assert "sort-tier cardinality" in catalog.last_warning


def test_resolver_returns_linux_blob_fallback_when_nothing_else_matches(
    catalog, tmp_path,
):
    """Live canary: bytes that match nothing fall through to linux_blob."""
    system_root = tmp_path / "system"
    sys_dir = system_root / "_system"
    _write_yaml(
        sys_dir / "linux_blob.yaml",
        _minimal_manifest_dict(format_id="linux_blob"),
    )
    snapshot = catalog.get_snapshot()
    # Random noise that matches no specific format
    blob_head = b"\xab\xcd\xef\x01" * 8
    match = resolve(blob_head, "/tmp/random.bin", 32, snapshot=snapshot)
    assert match is not None
    assert match.format_id == "linux_blob"


# ---------------------------------------------------------------------------
# Snapshot (Wave-1 S5 D + S5 K)
# ---------------------------------------------------------------------------


def test_snapshot_id_changes_on_yaml_diff(catalog, tmp_path):
    """Semantic edit → snapshot_id changes."""
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v1"))
    snap1 = catalog.get_snapshot()
    time.sleep(0.01)
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v2"))
    snap2 = catalog.get_snapshot()
    assert snap1.snapshot_id != snap2.snapshot_id


def test_snapshot_id_unchanged_on_comment_only_diff(catalog, tmp_path):
    """Comment-only YAML diff → snapshot_id preserved (Wave-1 S5 K)."""
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    body = yaml.safe_dump(_minimal_manifest_dict(format_id="a", notes="v1"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# original comment\n" + body, encoding="utf-8")
    snap1 = catalog.get_snapshot()
    id1 = snap1.snapshot_id
    time.sleep(0.01)
    # Change ONLY the leading comment — semantic content unchanged
    path.write_text("# DIFFERENT comment text\n" + body, encoding="utf-8")
    catalog.cache_clear()  # force re-parse so mtime change is realised
    snap2 = catalog.get_snapshot()
    assert snap2.snapshot_id == id1


def test_walker_pins_snapshot_at_scan_entry(catalog, tmp_path):
    """Snapshot pinned at scan entry survives mid-scan catalog reloads."""
    system_root = tmp_path / "system"
    path = system_root / "_system" / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v1"))
    snap_at_entry = catalog.get_snapshot()
    initial_id = snap_at_entry.snapshot_id

    # Mid-scan: operator edits YAML
    time.sleep(0.01)
    _write_yaml(path, _minimal_manifest_dict(format_id="a", notes="v2"))
    # Force catalog rebuild
    catalog.get_catalog()

    # Pinned snapshot unchanged
    assert snap_at_entry.snapshot_id == initial_id


# ---------------------------------------------------------------------------
# Live canaries (Rule #35b)
# ---------------------------------------------------------------------------


def test_live_canary_pe_head_resolves_to_pe_binary(catalog, tmp_path):
    """Head bytes MZ -> resolver should pick pe_binary at precedence 9000."""
    system_root = tmp_path / "system"
    sys_dir = system_root / "_system"
    _write_yaml(
        sys_dir / "pe.yaml",
        _minimal_manifest_dict(
            format_id="pe_binary", manifest_source="_system",
            precedence=9000, category="windows_pe", confidence="low",
            detection={
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d5a", "description": "MZ magic"}],
            },
        ),
    )
    _write_yaml(
        sys_dir / "linux_blob.yaml",
        _minimal_manifest_dict(format_id="linux_blob"),
    )
    snapshot = catalog.get_snapshot()
    # MZ\x90\x00 — typical PE/MZ header start
    blob_head = b"MZ\x90\x00" + b"\x00" * 28
    match = resolve(blob_head, "/tmp/setup.exe", 32, snapshot=snapshot)
    assert match is not None
    assert match.format_id == "pe_binary"


def test_live_canary_squashfs_head_resolves_to_some_linux_format(catalog, tmp_path):
    """A blob that looks like squashfs (no specific manifest) → linux_blob."""
    system_root = tmp_path / "system"
    sys_dir = system_root / "_system"
    _write_yaml(
        sys_dir / "linux_blob.yaml",
        _minimal_manifest_dict(format_id="linux_blob"),
    )
    snapshot = catalog.get_snapshot()
    # "hsqs" magic at offset 0 — squashfs LE. Without a squashfs-specific
    # manifest, fallback to linux_blob.
    blob_head = b"hsqs" + b"\x00" * 28
    match = resolve(blob_head, "/tmp/rootfs.squashfs", 32, snapshot=snapshot)
    assert match is not None
    assert match.format_id == "linux_blob"


# ---------------------------------------------------------------------------
# Authority derivation table coverage (A2 mechanical)
# ---------------------------------------------------------------------------


def test_authority_derivation_table_covers_all_manifest_sources():
    """A2 derivation table is exhaustive over ManifestSource Literal."""
    from app.schemas.file_format import ManifestSource
    declared = set(get_args(ManifestSource))
    wired = set(_AUTHORITY_FROM_SOURCE.keys())
    assert declared == wired
