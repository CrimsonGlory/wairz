"""Frozen per-scan-run catalog snapshot (Wave-1 S5 D + W2-alpha).

The snapshot is pinned at scan entry and passed down the walker chain;
mid-scan catalog reloads do NOT produce torn classifications. ``snapshot_id``
is a hash of the parsed-AST canonical JSON across all loaded manifests:

* Cosmetic edits (comment-only YAML changes) → mtime bumps, snapshot rebuilt,
  ``snapshot_id`` unchanged because canonical JSON is identical.
* Semantic edits (Pydantic-visible field change) → ``snapshot_id`` flips.

This closes Wave-1 S5 K (endless-cache-thrash from cosmetic-only file saves)
because consumers can short-circuit on ``snapshot_id`` equality.

The snapshot is a :class:`dataclass(frozen=True)` so it's immutable and
hashable; callers pass it down the call stack without defensive copies.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.schemas.file_format import FileFormatManifest


@dataclass(frozen=True)
class FormatCatalogSnapshot:
    """Immutable per-scan-run catalog snapshot.

    Pin at scan entry; pass down the walker chain. Wave-1 S5 D + S5 K.

    Attributes:
        manifests: All loaded manifests, sorted lexically by ``format_id`` so
            iteration order is deterministic across rebuilds (a torn run with
            two slightly-different orderings would otherwise produce non-
            reproducible diff output).
        snapshot_id: ``sha256`` over canonical-JSON (sorted keys, no whitespace)
            of every manifest with ``source_path`` excluded (so the same logical
            content on disk at different tmp_path locations is the same id).
        loaded_at_unix_ns: Loader timestamp for telemetry. NOT part of the hash.
    """

    manifests: tuple[FileFormatManifest, ...]
    snapshot_id: str
    loaded_at_unix_ns: int

    @classmethod
    def from_dict(
        cls,
        by_format_id: dict[str, FileFormatManifest],
        loaded_at_unix_ns: int,
    ) -> FormatCatalogSnapshot:
        """Build a snapshot from a ``format_id → manifest`` mapping."""
        # Sort by format_id so iteration order is stable across rebuilds.
        manifests = tuple(
            sorted(by_format_id.values(), key=lambda m: m.format_id)
        )
        payload = [
            m.model_dump(mode="json", exclude={"source_path"})
            for m in manifests
        ]
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        snapshot_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(
            manifests=manifests,
            snapshot_id=snapshot_id,
            loaded_at_unix_ns=loaded_at_unix_ns,
        )

    def get(self, format_id: str) -> FileFormatManifest | None:
        """Linear scan by ``format_id``. Snapshots are typically small (<200)."""
        for m in self.manifests:
            if m.format_id == format_id:
                return m
        return None

    def __len__(self) -> int:
        return len(self.manifests)

    def __iter__(self):
        return iter(self.manifests)


__all__ = ["FormatCatalogSnapshot"]
