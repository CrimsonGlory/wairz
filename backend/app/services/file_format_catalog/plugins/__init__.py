"""File-format catalog plugin package (P3.2.c — Wave-1 S3 HYBRID).

Bundled in-tree plugins register their :class:`MatcherProto` instances
with :data:`PLUGIN_REGISTRY` so the catalog's ``rtos_check`` /
``by_rtos_family`` dispatch can route via the closed-grammar evaluators
without hardcoding family names into a Python ``Literal`` (Rule #52
"don't hardcode strict formats" + user direction 2026-05-19).

Operator out-of-tree plugins (e.g. ``wairz_zephyr_specialised_plugin``)
load via the ``WAIRZ_FORMAT_PLUGIN_PATH`` env var — DEFERRED to P4 per
S3 + S5 + W2-α consensus (untrusted-code-execution requires a Rule #36
Exception 3 side-container).

Registration timing:
    * Backend process: ``app/main.py`` ``lifespan`` calls
      :func:`register_default_plugins` once at startup THEN
      :func:`freeze_plugin_registry` to close the W2-β TOCTOU window.
    * Worker process: TBD — currently the worker imports the catalog
      via :mod:`app.workers.unpack_common` but does not go through
      ``app/main.py``'s lifespan. P3.x will add an arq ``on_startup``
      hook calling the same registration function; until then the worker
      relies on the catalog's default empty-registry behavior (rtos_check
      signals return False; by_rtos_family dispatch falls through to
      ``manifest.dispatch.default``).

Adding an in-tree plugin: drop a module in this package + import + call
its ``register()`` from :func:`register_default_plugins`. Plugins MUST
declare ``rtos_families: frozenset[str]`` (advisory, not closed Literal)
if they emit :class:`RtosDetection`.
"""
from __future__ import annotations

import logging

from app.services.file_format_catalog.plugins.rtos_detection_default import (
    register as _register_rtos_detection_default,
)
from app.services.file_format_catalog.resolver import freeze_plugin_registry

logger = logging.getLogger(__name__)


def register_default_plugins(*, freeze: bool = True) -> None:
    """Register the bundled in-tree plugins. Idempotent; safe to call
    multiple times in test contexts (each plugin's ``register()`` checks
    for prior registration). When ``freeze`` is True, also freeze the
    registry post-registration (W2-β attack I closure)."""
    try:
        _register_rtos_detection_default()
    except Exception:  # noqa: BLE001 — defensive at startup
        logger.warning(
            "register_default_plugins: rtos_detection_default registration "
            "failed; rtos_check signals will return False",
            exc_info=True,
        )
    if freeze:
        freeze_plugin_registry()


__all__ = ["register_default_plugins"]
