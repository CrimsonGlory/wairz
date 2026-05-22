"""Tests for the ICS protocol catalog plugin infrastructure (Phase 4 —
Rule #52 instance #3, Session 2 2026-05-22).

W2-β §SC5-NEW-ICS-S2-α HARDENED — closes Session 1's scariest unmitigated
attack (W2-β §SC5-NEW-ICS-7 hot-reload × plugin module-level shadow):

1. PLUGIN_REGISTRY public symbol is a ``types.MappingProxyType`` view —
   consumers CANNOT mutate via ``PLUGIN_REGISTRY[x] = y`` (raises
   TypeError 'mappingproxy' object does not support item assignment).
2. ``register_matcher`` checks the freeze sentinel; post-freeze calls
   raise RuntimeError.
3. ``_closure_capture_check`` rejects plugins whose ``detect``
   callable captures session/auth state — W2-β §SC5-NEW-ICS-S2-ζ
   defense against plugins leaking request scope across walker runs.

Rule #46 paired META-CANARY discipline: every gate has a synthesize-
violation test that proves it WOULD fire on a hostile shape; without
this canary, the gate is a Rule #17 silent-success risk.
"""
from __future__ import annotations

import pytest

from app.services.ics_protocol_catalog.resolver import (
    _PLUGIN_REGISTRY,
    PLUGIN_REGISTRY,
    _unfreeze_plugin_registry_for_tests,
    freeze_plugin_registry,
    is_plugin_registry_frozen,
    register_matcher,
)


@pytest.fixture(autouse=True)
def _reset_freeze_state_between_tests():
    """Reset freeze sentinel + clear private registry per test so the
    PLUGIN_REGISTRY state doesn't leak across the suite."""
    _unfreeze_plugin_registry_for_tests()
    _PLUGIN_REGISTRY.clear()
    yield
    _unfreeze_plugin_registry_for_tests()
    _PLUGIN_REGISTRY.clear()


class _StatelessMatcher:
    """Minimal valid matcher — no closure capture, declares
    protocol_families."""

    cost_class: int = 1
    protocol_families: frozenset[str] = frozenset({"modbus_tcp"})

    def detect(self, blob_head, path, size, context):
        return None


# ───────────────────────────────────────────────────────────────────────
# W2-β §SC5-NEW-ICS-S2-α MappingProxyType wrap.
# ───────────────────────────────────────────────────────────────────────


def test_plugin_registry_is_mappingproxytype_read_only():
    """W2-β §SC5-NEW-ICS-S2-α HARDENED — PLUGIN_REGISTRY is a
    read-only ``MappingProxyType`` view. Consumer that attempts
    ``PLUGIN_REGISTRY[x] = y`` MUST raise TypeError.

    Without the proxy wrap, a hostile bundled plugin could rebind via
    module-level ``from app.services.ics_protocol_catalog.resolver import
    PLUGIN_REGISTRY; PLUGIN_REGISTRY["hostile"] = _Matcher()``, fully
    bypassing register_matcher + the freeze gate + namespace check.
    """
    from types import MappingProxyType

    assert isinstance(PLUGIN_REGISTRY, MappingProxyType), (
        f"PLUGIN_REGISTRY MUST be a MappingProxyType view; got "
        f"{type(PLUGIN_REGISTRY).__name__!r}. W2-β §SC5-NEW-ICS-S2-α "
        f"HARDENED contract."
    )

    with pytest.raises(TypeError, match="'mappingproxy' object"):
        PLUGIN_REGISTRY["hostile"] = _StatelessMatcher()  # type: ignore[index]


# ───────────────────────────────────────────────────────────────────────
# Rule #33 .a + W2-β §SC5-NEW-ICS-S2-α freeze gate.
# ───────────────────────────────────────────────────────────────────────


def test_register_matcher_pre_freeze_succeeds():
    """Paired canary — confirms the gate doesn't degenerate to
    'always-reject'. Pre-freeze register_matcher succeeds with a clean
    stateless matcher."""
    assert not is_plugin_registry_frozen()
    register_matcher("modbus_tcp_default", _StatelessMatcher())
    assert "modbus_tcp_default" in PLUGIN_REGISTRY


def test_register_matcher_post_freeze_raises():
    """W2-β §SC5-NEW-ICS-S2-α — post-freeze ``register_matcher`` MUST
    raise RuntimeError. The freeze sentinel + MappingProxyType together
    are the durable HARDENED contract."""
    freeze_plugin_registry()
    assert is_plugin_registry_frozen()
    with pytest.raises(RuntimeError, match="frozen"):
        register_matcher("hostile", _StatelessMatcher())


def test_freeze_does_not_block_existing_lookups():
    """Post-freeze, READS still work — only writes raise."""
    register_matcher("modbus_tcp_default", _StatelessMatcher())
    freeze_plugin_registry()
    # Reads still work
    assert "modbus_tcp_default" in PLUGIN_REGISTRY
    assert PLUGIN_REGISTRY["modbus_tcp_default"] is not None


# ───────────────────────────────────────────────────────────────────────
# W2-β §SC5-NEW-ICS-S2-ζ closure-capture gate.
# ───────────────────────────────────────────────────────────────────────


def test_register_matcher_rejects_async_session_closure_capture():
    """W2-β §SC5-NEW-ICS-S2-ζ — register_matcher MUST reject matchers
    that capture an AsyncSession in their detect callable's closure.

    Synthesized hostile pattern: a matcher created via a factory
    function that closes over the active session at registration
    time. Without the gate, the plugin's detect() would always read
    from the stale closed-over session — leaking session/auth state
    across walker runs.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    # Create a real AsyncSession instance to capture in closure.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    captured_session = AsyncSession(engine)

    def make_hostile_matcher(db):
        class _HostileMatcher:
            cost_class: int = 1
            protocol_families: frozenset[str] = frozenset({"dnp3"})

            def detect(self, blob_head, path, size, context):
                # Captures db via closure → forbidden.
                _ = db
                return None

        return _HostileMatcher()

    hostile = make_hostile_matcher(captured_session)
    with pytest.raises(ValueError, match="closure"):
        register_matcher("hostile_closure", hostile)


def test_register_matcher_accepts_stateless_matcher():
    """Pair canary — stateless matchers (no captured closure) pass the
    closure-capture gate."""
    register_matcher("stateless_ok", _StatelessMatcher())
    assert "stateless_ok" in PLUGIN_REGISTRY


# ───────────────────────────────────────────────────────────────────────
# Namespace-collision gate.
# ───────────────────────────────────────────────────────────────────────


def test_register_matcher_rejects_protocol_family_collision():
    """Two plugins both claiming ``protocol_families={"modbus_tcp"}``
    raises a ValueError so dispatch is unambiguous."""

    class _SecondModbusMatcher:
        cost_class: int = 1
        protocol_families: frozenset[str] = frozenset({"modbus_tcp"})

        def detect(self, blob_head, path, size, context):
            return None

    register_matcher("modbus_first", _StatelessMatcher())
    with pytest.raises(ValueError, match="namespace-disjointness"):
        register_matcher("modbus_second", _SecondModbusMatcher())


# ───────────────────────────────────────────────────────────────────────
# Bundled plugin registration (lifespan integration smoke).
# ───────────────────────────────────────────────────────────────────────


def test_register_default_plugins_registers_string_scanner():
    """register_default_plugins must register the bundled
    StringScannerPlugin under the well-known 'string_scanner' name."""
    from app.services.ics_protocol_catalog.plugins import register_default_plugins

    register_default_plugins(freeze=False)
    assert "string_scanner" in PLUGIN_REGISTRY
    assert is_plugin_registry_frozen() is False


def test_register_default_plugins_freezes_when_requested():
    """register_default_plugins(freeze=True) flips the sentinel."""
    from app.services.ics_protocol_catalog.plugins import register_default_plugins

    register_default_plugins(freeze=True)
    assert is_plugin_registry_frozen() is True
    # Subsequent register_matcher MUST raise
    with pytest.raises(RuntimeError, match="frozen"):
        register_matcher("post_freeze_hostile", _StatelessMatcher())


def test_string_scanner_plugin_detect_returns_hits_on_modbus_signature():
    """Smoke test — the bundled StringScannerPlugin.detect() returns
    hits on a binary containing one of its needle byte sequences."""
    from app.services.ics_protocol_catalog.plugins.string_scanner import (
        StringScannerPlugin,
    )

    plugin = StringScannerPlugin()
    blob_head = b"some prefix bytes...libmodbus..suffix"
    hits = plugin.detect(blob_head, "/bin/modbus_server", len(blob_head), None)
    assert hits is not None
    family_hits = {h["protocol_family"] for h in hits}
    assert "modbus_tcp" in family_hits


def test_string_scanner_plugin_returns_none_on_clean_binary():
    """Smoke test — StringScannerPlugin returns None when no needles
    match (so the resolver skips this matcher's contribution)."""
    from app.services.ics_protocol_catalog.plugins.string_scanner import (
        StringScannerPlugin,
    )

    plugin = StringScannerPlugin()
    blob_head = b"\x00" * 1024  # clean buffer
    assert plugin.detect(blob_head, "/bin/clean", 1024, None) is None


# ───────────────────────────────────────────────────────────────────────
# Lifespan-wire META-CANARY: main.py imports + calls
# register_default_plugins(freeze=True).
# ───────────────────────────────────────────────────────────────────────


def test_main_py_lifespan_imports_and_calls_register_default_plugins():
    """Rule #46 META-CANARY — main.py:lifespan MUST import + call
    register_default_plugins(freeze=True) BEFORE yield. Without the
    call, the freeze sentinel is never flipped and a runtime
    register_matcher could land post-startup, defeating the W2-β
    §SC5-NEW-ICS-S2-α defense.
    """
    from pathlib import Path

    src = Path("/app/app/main.py").read_text() if Path(
        "/app/app/main.py"
    ).exists() else Path(__file__).parent.parent.joinpath(
        "app/main.py"
    ).read_text()

    assert "register_default_plugins" in src, (
        "main.py:lifespan does NOT import register_default_plugins — "
        "the ICS plugin freeze sentinel is never flipped; W2-β "
        "§SC5-NEW-ICS-S2-α defense bypassed."
    )
    assert "freeze=True" in src or "freeze=  True" in src, (
        "main.py:lifespan does NOT call register_default_plugins with "
        "freeze=True — the freeze sentinel is never flipped post-startup."
    )
    # Lifespan call MUST be BEFORE 'yield' textually.
    register_idx = src.find("register_default_plugins")
    yield_idx = src.find("yield")
    assert register_idx > 0 and yield_idx > 0
    assert register_idx < yield_idx, (
        "register_default_plugins MUST be called BEFORE yield in "
        "main.py:lifespan. Order matters — the freeze gate is the "
        "security boundary; calling it after yield exposes a startup-"
        "to-first-request window for matcher hijack."
    )


# ───────────────────────────────────────────────────────────────────────
# Rule #46 PAIRED META-CANARY for the MappingProxyType protection.
# ───────────────────────────────────────────────────────────────────────


def test_mappingproxytype_gate_actually_blocks_direct_dict_write():
    """Rule #46 paired META-CANARY — synthesize a hostile direct write
    against the public PLUGIN_REGISTRY symbol. Confirms the
    MappingProxyType layer actually blocks the §SC5-NEW-ICS-S2-α
    attack pattern.

    Without this canary, the test_plugin_registry_is_mappingproxytype_
    read_only test passes if MappingProxyType type-checks but the
    actual write fails to raise — both checks together prove the
    proxy is load-bearing.
    """
    # Hostile pattern: import public symbol, attempt direct write.
    with pytest.raises(TypeError) as excinfo:
        PLUGIN_REGISTRY["§SC5-NEW-ICS-S2-α-pattern"] = (  # type: ignore[index]
            _StatelessMatcher()
        )
    # The TypeError must specifically mention mappingproxy — otherwise
    # the proxy isn't load-bearing.
    assert "mappingproxy" in str(excinfo.value).lower(), (
        f"Direct write to PLUGIN_REGISTRY raised, but the error "
        f"message does NOT mention 'mappingproxy' — gate may not be "
        f"functioning as expected. Got: {excinfo.value!r}"
    )
