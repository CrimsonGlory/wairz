"""Frozen per-scan-run ICS protocol catalog snapshot.

Mirror of :class:`app.services.file_format_catalog.snapshot.FormatCatalogSnapshot`.
Pinned at scan entry and passed down the walker chain so mid-scan catalog
reloads do NOT produce torn classifications. ``snapshot_id`` is a hash of
parsed-AST canonical JSON across all loaded manifests:

* Cosmetic YAML edits (comment-only) → mtime bumps, snapshot rebuilt,
  ``snapshot_id`` unchanged because canonical JSON is identical.
* Semantic edits (Pydantic-visible field change) → ``snapshot_id`` flips.

The snapshot is a :class:`dataclass(frozen=True)` so it's immutable and
hashable; callers pass it down the call stack without defensive copies.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.schemas.ics_protocol import IcsProtocolManifest


@dataclass(frozen=True)
class IcsProtocolCatalogSnapshot:
    """Immutable per-scan-run ICS protocol catalog snapshot.

    Attributes:
        manifests: All loaded manifests, sorted lexically by ``manifest_id``
            so iteration order is deterministic across rebuilds.
        snapshot_id: ``sha256`` over canonical-JSON (sorted keys, no
            whitespace) of every manifest. ``source_path`` (if added later)
            excluded from hash so identical content at different tmp paths
            produces the same id.
        loaded_at_unix_ns: Loader timestamp for telemetry. NOT part of the
            hash.
    """

    manifests: tuple[IcsProtocolManifest, ...]
    snapshot_id: str
    loaded_at_unix_ns: int

    @classmethod
    def from_dict(
        cls,
        by_manifest_id: dict[str, IcsProtocolManifest],
        loaded_at_unix_ns: int,
    ) -> IcsProtocolCatalogSnapshot:
        """Build a snapshot from a ``manifest_id → manifest`` mapping."""
        manifests = tuple(
            sorted(by_manifest_id.values(), key=lambda m: m.manifest_id)
        )
        payload = [m.model_dump(mode="json") for m in manifests]
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        snapshot_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(
            manifests=manifests,
            snapshot_id=snapshot_id,
            loaded_at_unix_ns=loaded_at_unix_ns,
        )

    def get(self, manifest_id: str) -> IcsProtocolManifest | None:
        """Linear scan by ``manifest_id``. Snapshots are typically small."""
        for m in self.manifests:
            if m.manifest_id == manifest_id:
                return m
        return None

    def by_protocol_family(
        self, protocol_family: str,
    ) -> tuple[IcsProtocolManifest, ...]:
        """Filter snapshot by protocol_family. Closed-Literal-typed at
        the IcsProtocolFamily layer (the manifest's output.protocol_family).
        Returns all manifests detecting the given family."""
        return tuple(
            m for m in self.manifests
            if m.output.protocol_family == protocol_family
        )

    def __len__(self) -> int:
        return len(self.manifests)

    def __iter__(self):
        return iter(self.manifests)


__all__ = ["IcsProtocolCatalogSnapshot"]
