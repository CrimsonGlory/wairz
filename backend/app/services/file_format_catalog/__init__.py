"""File-format manifest catalog — operator-extensible YAML registry.

Phase 3 of CLAUDE.md Rule #52 (schema-driven discipline). Loads YAML
manifests from data/file_formats/ + data/file_formats.local/ via
MtimeCachedYamlLoader pattern (Phase 1+2 chip_catalog precedent).

P3.1.a (this commit) ships ONLY the schema + JSON Schema export.
P3.1.b ships the loader, frozen snapshot, cost-sorted resolver,
cross-feature validators (A1-A5 from W2-beta Wave-2 critique).
"""
from __future__ import annotations

from app.schemas.file_format import FileFormatManifest, FormatMatch


def get_format_catalog():  # pragma: no cover - placeholder
    """Placeholder — loader ships in P3.1.b."""
    raise NotImplementedError(
        "Format catalog loader lands in commit P3.1.b; "
        "this is the P3.1.a schema-only stub."
    )


__all__ = ["FileFormatManifest", "FormatMatch", "get_format_catalog"]
