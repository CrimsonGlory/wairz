"""Bundled RTOS-detection plugin (P3.2.c — Wave-1 S3 HYBRID).

Wraps the legacy :func:`app.services.rtos_detection_service.detect_rtos`
behind the catalog's :class:`MatcherProto` contract. The plugin lives
inside :data:`PLUGIN_REGISTRY` under name ``rtos_detection_default``;
catalog manifests reference it via ``signal.rtos_plugin_ref``.

Flow:
    1. Catalog manifest declares an ``rtos_check`` signal with
       ``rtos_plugin_ref: rtos_detection_default``.
    2. Resolver's :func:`_eval_rtos_check` looks up THIS plugin by name.
    3. Plugin's :meth:`detect` calls the underlying detect_rtos() with
       the on-disk path (NOT the head bytes — the legacy function reads
       its own bounded chunk).
    4. On hit, returns :class:`RtosDetection` (typed dataclass) which the
       resolver stashes on ``_RTOS_DETECTION_CONTEXT`` for the
       ``by_rtos_family`` dispatch evaluator to consume.
    5. Catalog dispatches via ``manifest.dispatch.cases[rtos_family]``
       (operator-extensible — partners drop a YAML in
       ``data/file_formats.local/`` declaring a NEW rtos_family and the
       same dispatch table picks it up).

The ``rtos_families: frozenset[str]`` advertised here is the set
this plugin's legacy detect_rtos can emit — A7 namespace-disjointness
gates against collisions at registration time.
"""
from __future__ import annotations

import logging
from typing import Any

from app.services.file_format_catalog.resolver import (
    PLUGIN_REGISTRY,
    RtosDetection,
    register_matcher,
)

logger = logging.getLogger(__name__)

NAME = "rtos_detection_default"
COST_CLASS = 3  # mid-tier — head read + LIEF parse


class _DefaultRtosMatcher:
    """Bundled RTOS-detection plugin wrapping legacy detect_rtos."""

    name: str = NAME
    cost_class: int = COST_CLASS
    applicable_format_ids: frozenset[str] = frozenset({"rtos_blob"})
    rtos_families: frozenset[str] = frozenset({
        "zephyr",
        "freertos",
        "amazon-freertos",
        "vxworks",
        "threadx",
        "qnx",
        "ucos",
        "ucos-ii",
        "ucos-iii",
        "safertos",
    })

    def detect(
        self, blob_head: bytes, path: str, size: int,
    ) -> Any:
        """Run the legacy 5-tier RTOS scan on ``path``.

        detect_rtos() takes a filesystem PATH (not bytes) and does its
        own bounded read. blob_head is unused at the plugin boundary;
        we keep the MatcherProto contract uniform across plugin shapes.
        """
        if not path:
            return None
        try:
            from app.services.rtos_detection_service import detect_rtos as _d
        except ImportError:
            logger.warning(
                "rtos_detection_default: rtos_detection_service import failed",
                exc_info=True,
            )
            return None
        try:
            result = _d(path)
        except Exception:  # noqa: BLE001 — plugin boundary
            logger.warning(
                "rtos_detection_default: detect_rtos raised for %s",
                path, exc_info=True,
            )
            return None
        if result is None:
            return None
        family = result.get("rtos_name")
        if not family:
            return None
        conf_raw = result.get("confidence", "medium")
        if conf_raw not in ("high", "medium", "low"):
            conf_raw = "medium"
        return RtosDetection(
            rtos_family=family,
            confidence=conf_raw,
            version=result.get("version"),
            metadata=result.get("metadata") or None,
        )


def register() -> None:
    """Register the bundled RTOS plugin (idempotent — safe under reload)."""
    if NAME in PLUGIN_REGISTRY:
        return
    register_matcher(NAME, _DefaultRtosMatcher())


__all__ = ["NAME", "register"]
