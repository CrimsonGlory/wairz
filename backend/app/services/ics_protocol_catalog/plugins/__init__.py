"""Bundled plugin discovery + registration for the ICS protocol catalog.

CLAUDE.md Rule #52 instance #3 / Phase 4. Wired into ``main.py:lifespan``
AFTER catalog mtime-cache warmup AND BEFORE the FastAPI ``yield`` so
the freeze sentinel is set before any incoming request can reach a
``register_matcher`` call.

Discovery shape (W2-β §SC5-NEW-ICS-S2-α partial mitigation): bundled
plugins are static imports below — NOT dynamic via ``importlib`` against
operator-controlled name strings. The catalog loader's YAML
``plugin.name`` reference (future cross-feature gate I21) MUST resolve
against the frozen registry; unknown names reject the manifest at
YAML-load time.

Hot-reload of YAML at runtime is allowed (operators tune detection
without restart); plugin registration at runtime is NOT — closes the
§SC5-NEW-ICS-7 hot-reload × plugin attack vector that Session 1 W2-β
identified as the scariest unmitigated case.
"""
from __future__ import annotations

import logging

from app.services.ics_protocol_catalog.plugins.string_scanner import (
    StringScannerPlugin,
)
from app.services.ics_protocol_catalog.resolver import (
    freeze_plugin_registry,
    register_matcher,
)

logger = logging.getLogger(__name__)


def register_default_plugins(*, freeze: bool = True) -> None:
    """Register every bundled plugin, then optionally freeze the registry.

    Wired from ``main.py:lifespan`` with ``freeze=True``. Tests can call
    with ``freeze=False`` to register-and-test without locking the
    sentinel for sibling tests.
    """
    register_matcher("string_scanner", StringScannerPlugin())
    if freeze:
        freeze_plugin_registry()
        logger.info(
            "ics_protocol_catalog: plugin registry frozen post-startup "
            "(W2-β §SC5-NEW-ICS-S2-α HARDENED — MappingProxyType view + "
            "freeze sentinel; bundled plugins: string_scanner)"
        )


__all__ = ["register_default_plugins"]
