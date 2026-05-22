"""File-format manifest catalog — operator-extensible YAML registry.

Phase 3 of CLAUDE.md Rule #52 (schema-driven discipline). Loads YAML
manifests from data/file_formats/ + data/file_formats.local/ via the
chip_catalog mtime-cached pattern (Phase 1+2 precedent).

P3.1.a shipped the schema + JSON Schema export.
P3.1.b (THIS package) ships:
    * catalog loader (catalog.py) — two-root walk, path cross-check,
      cross-feature validators A1-A5 (W2-beta)
    * frozen snapshot (snapshot.py) — Wave-1 S5 D + S5 K closure
    * cost-sorted resolver (resolver.py) — Wave-1 S5 B + H + attack O closure
"""
from __future__ import annotations

from app.schemas.file_format import FileFormatManifest, FormatMatch
from app.services.file_format_catalog.catalog import (
    FormatCatalog,
    derive_vendor_authority,
    get_default_catalog,
    get_format_catalog,
)
from app.services.file_format_catalog.resolver import (
    DISPATCH_EVALUATORS,
    PLUGIN_REGISTRY,
    RTOS_FAMILY_ADVISORY,
    SIGNAL_EVALUATORS,
    RtosDetection,
    freeze_plugin_registry,
    get_default_snapshot,
    register_matcher,
    resolve,
)
from app.services.file_format_catalog.snapshot import FormatCatalogSnapshot

__all__ = [
    "DISPATCH_EVALUATORS",
    "FileFormatManifest",
    "FormatCatalog",
    "FormatCatalogSnapshot",
    "FormatMatch",
    "PLUGIN_REGISTRY",
    "RTOS_FAMILY_ADVISORY",
    "RtosDetection",
    "SIGNAL_EVALUATORS",
    "derive_vendor_authority",
    "freeze_plugin_registry",
    "get_default_catalog",
    "get_default_snapshot",
    "get_format_catalog",
    "register_matcher",
    "resolve",
]
