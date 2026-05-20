"""ICS protocol catalog loader.

Mirror of :mod:`app.services.file_format_catalog.catalog`. Walks YAML files
under two roots (canonical + operator overlay), parses each via Pydantic,
exposes ``manifest_id → manifest`` mapping with mtime-based hot-reload and
graceful degradation on parse failure.

Two roots:
    ``data/ics_protocols/``         — in-tree, ``manifest_source`` MUST be
                                       ``_system`` (under ``_system/``) OR
                                       ``core`` (under ``<vendor>/``).
    ``data/ics_protocols.local/``   — operator overlay; ``manifest_source``
                                       MUST be ``operator`` for files in the
                                       root, ``attested_external`` for
                                       anything under ``_attested_external/``.

**Path cross-check** (Wave-1 S3 G analog): the on-disk path tier is the
SOURCE OF TRUTH for ``manifest_source``. Mismatch → REJECT manifest.

**Cross-feature validators I1-I7** (Wave-2 W2-β; analogs of file_format A1-A7):

* **I1** ``mode=override`` × ``manifest_source`` authority parity (mirror A1).
  v0 Session 1: no override mode yet — placeholder check enforces no
  ``override`` keys at any level.
* **I2** ``vendor_authority`` DERIVED from THIS manifest's ``manifest_source``
  (mirror A2). Exposed via :func:`derive_vendor_authority`.
* **I3** ``deprecation.status: removed`` × dispatch reference → REJECT load.
  v0 Session 1: no dispatch; placeholder only.
* **I4** Cross-vendor same-precedence same-magic collision → REJECT unless
  ``manifest_source`` differs (mirror A4). Detects two operator-tier
  manifests both claiming Modbus at the same offset+bytes_hex.
* **I5-I7** dispatch + plugin gates — defer to Session 2 with full surface.

Wave-2 W2-β identified I8-I19 (NEW for ICS) — also defer to Session 2 with
plugins / refinement / dispatch.

Validators emit WARN to ``last_warning`` and SKIP the offending manifest; the
catalog returns the remaining valid manifests so a single bad YAML never
takes down the whole loader (graceful-degrade per Rule #34).
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.schemas.ics_protocol import (
    IcsManifestSource,
    IcsProtocolManifest,
    IcsVendorAuthority,
)
from app.services.ics_protocol_catalog.snapshot import (
    IcsProtocolCatalogSnapshot,
)

logger = logging.getLogger(__name__)


# Per-source vendor-authority map (Rule #52 + W2-β §SC5-NEW-ICS-1 mitigation).
# CVE matcher reads `curated` only; operator-supplied is informational.
_VENDOR_AUTHORITY: dict[IcsManifestSource, IcsVendorAuthority] = {
    "_system": "curated",
    "core": "curated",
    "operator": "operator_supplied",
    "attested_external": "operator_supplied",
    "unauthenticated_external": "community",
}


def derive_vendor_authority(manifest: IcsProtocolManifest) -> IcsVendorAuthority:
    """I2 — vendor authority is DERIVED from this manifest's manifest_source.

    NEVER read from a dispatch chain entry (W2-β §SC5-NEW-ICS-1 mitigation:
    must read terminus, not entry — for v0 there is no dispatch, so this is
    trivially the manifest itself).
    """
    return _VENDOR_AUTHORITY[manifest.manifest_source]


def _expected_source_for_path(yaml_path: Path, data_root: Path) -> IcsManifestSource | None:
    """Compute expected ``manifest_source`` from the on-disk path tier.

    Returns None if the path doesn't match any known tier (loader rejects).
    """
    try:
        rel = yaml_path.relative_to(data_root)
    except ValueError:
        return None
    parts = rel.parts
    if not parts:
        return None
    first = parts[0]
    if first == "_system":
        return "_system"
    if first == "_attested_external":
        return "attested_external"
    if first == "_unauthenticated_external":
        return "unauthenticated_external"
    # Anything else under data/ics_protocols/ is a vendor dir → core
    return "core"


def _expected_source_for_overlay_path(
    yaml_path: Path, overlay_root: Path,
) -> IcsManifestSource | None:
    """Path tier for the operator-overlay directory.

    Files at the overlay root → operator. Under _attested_external/ →
    attested_external. Under _unauthenticated_external/ → unauthenticated.
    """
    try:
        rel = yaml_path.relative_to(overlay_root)
    except ValueError:
        return None
    parts = rel.parts
    if not parts:
        return None
    first = parts[0]
    if first == "_attested_external":
        return "attested_external"
    if first == "_unauthenticated_external":
        return "unauthenticated_external"
    # All other overlay paths → operator
    return "operator"


class IcsProtocolCatalog:
    """Hot-reloadable ICS protocol manifest catalog.

    Walks two data roots (canonical + operator overlay), parses every YAML
    via Pydantic, exposes ``manifest_id → IcsProtocolManifest`` mapping with
    mtime-aware staleness check + reload. Per-file parse failures and per-
    manifest validator rejections are SKIPPED with a structured WARN; the
    catalog never raises from public surface.

    Thread-safe: a single ``threading.RLock`` guards the cached mapping +
    snapshot.

    Attributes:
        last_warning: most-recent WARN message emitted by a load-time validator.
            None if last load was clean.
    """

    _CACHE_REBUILD_DEBOUNCE_NS = 50_000_000  # 50ms

    def __init__(
        self,
        data_root: Path | None = None,
        overlay_root: Path | None = None,
    ) -> None:
        if data_root is None:
            data_root = (
                Path(__file__).resolve().parent
                / "data" / "ics_protocols"
            )
        if overlay_root is None:
            overlay_root = (
                Path(__file__).resolve().parent
                / "data" / "ics_protocols.local"
            )
        self._data_root = data_root
        self._overlay_root = overlay_root
        self._lock = threading.RLock()
        self._cached_by_id: dict[str, IcsProtocolManifest] = {}
        self._cached_snapshot: IcsProtocolCatalogSnapshot | None = None
        self._cached_mtime_signature: tuple[tuple[str, int], ...] | None = None
        self._cache_built_ns: int = 0
        self.last_warning: str | None = None

    @property
    def data_root(self) -> Path:
        return self._data_root

    @property
    def overlay_root(self) -> Path:
        return self._overlay_root

    def _iter_yaml_paths(self) -> list[Path]:
        """Walk both data roots; return YAML files in deterministic order."""
        paths: list[Path] = []
        for root in (self._data_root, self._overlay_root):
            if not root.is_dir():
                continue
            for p in sorted(root.rglob("*.yaml")):
                if p.is_file():
                    paths.append(p)
        return paths

    def _compute_mtime_signature(self) -> tuple[tuple[str, int], ...]:
        """Per-file mtime signature; cache invalidated when any file changes."""
        sig: list[tuple[str, int]] = []
        for p in self._iter_yaml_paths():
            try:
                sig.append((str(p), p.stat().st_mtime_ns))
            except OSError:
                continue
        return tuple(sig)

    def _is_in_data_root(self, p: Path) -> bool:
        try:
            p.relative_to(self._data_root)
            return True
        except ValueError:
            return False

    def _is_in_overlay_root(self, p: Path) -> bool:
        try:
            p.relative_to(self._overlay_root)
            return True
        except ValueError:
            return False

    def _expected_source(self, yaml_path: Path) -> IcsManifestSource | None:
        if self._is_in_data_root(yaml_path):
            return _expected_source_for_path(yaml_path, self._data_root)
        if self._is_in_overlay_root(yaml_path):
            return _expected_source_for_overlay_path(
                yaml_path, self._overlay_root,
            )
        return None

    def _load_one(
        self, yaml_path: Path, warnings: list[str],
    ) -> IcsProtocolManifest | None:
        """Parse one YAML; return manifest or None (skips with WARN).

        Cross-checks declared manifest_source against on-disk path tier
        (Wave-2 §SC5-NEW-ICS-4 mitigation — operator cannot impersonate
        _system by claiming manifest_source: _system from .local/).
        """
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.append(f"{yaml_path}: read error: {exc}")
            return None
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            warnings.append(f"{yaml_path}: yaml parse error: {exc}")
            return None
        if not isinstance(doc, dict):
            warnings.append(f"{yaml_path}: top-level YAML is not a mapping")
            return None
        try:
            manifest = IcsProtocolManifest(**doc)
        except ValidationError as exc:
            warnings.append(
                f"{yaml_path}: pydantic validation: "
                f"{exc.errors(include_url=False)[:3]}"
            )
            return None

        # Path cross-check (W2-β §SC5-NEW-ICS-4 + file_format S3 G analog).
        expected_source = self._expected_source(yaml_path)
        if expected_source is None:
            warnings.append(
                f"{yaml_path}: path not under data_root or overlay_root; SKIPPED"
            )
            return None
        if manifest.manifest_source != expected_source:
            warnings.append(
                f"{yaml_path}: declared manifest_source="
                f"{manifest.manifest_source!r} but path tier expects "
                f"{expected_source!r}; SKIPPED (loader path cross-check)"
            )
            return None

        return manifest

    def _check_i4_cross_vendor_collision(
        self,
        by_id: dict[str, IcsProtocolManifest],
        warnings: list[str],
    ) -> None:
        """I4 — Cross-vendor same-precedence same-magic collision.

        REJECT if two manifests declare same (precedence, signal magic) but
        DIFFERENT vendors at the SAME manifest_source rank. Mirror of
        file_format A4. Drops the LATER (lex-sorted) manifest with a WARN.
        """
        # Build a fingerprint per manifest's magic_bytes signals; group by
        # (manifest_source, precedence, fingerprint); duplicates with
        # different vendors trigger A4 collision.
        fp_to_ids: dict[
            tuple[IcsManifestSource, int, str, int, str], list[str]
        ] = {}
        for manifest in by_id.values():
            for sig in manifest.detection.signals:
                if sig.kind != "magic_bytes":
                    continue
                if sig.bytes_hex is None or sig.offset is None:
                    continue
                fp = (
                    manifest.manifest_source,
                    manifest.precedence,
                    sig.bytes_hex.lower(),
                    sig.offset,
                    manifest.output.vendor,
                )
                # Same-vendor multi-manifest is fine.
                key = fp[:-1]  # drop vendor for collision detection
                fp_to_ids.setdefault(key, []).append(
                    f"{manifest.manifest_id}:{manifest.output.vendor}"
                )

        for key, members in fp_to_ids.items():
            distinct_vendors = {m.split(":", 1)[1] for m in members}
            if len(distinct_vendors) >= 2:
                # I4 collision — drop everything but the lex-first manifest.
                source, precedence, bytes_hex, offset = key
                sorted_members = sorted(members)
                survivor = sorted_members[0]
                drop_ids = [m.split(":", 1)[0] for m in sorted_members[1:]]
                for drop_id in drop_ids:
                    by_id.pop(drop_id, None)
                warnings.append(
                    f"I4 cross-vendor collision: source={source!r} "
                    f"precedence={precedence} magic_bytes@{offset:#x}="
                    f"{bytes_hex!r} declared by {len(distinct_vendors)} "
                    f"vendors ({sorted(distinct_vendors)}); kept "
                    f"{survivor.split(':',1)[0]!r}; dropped {drop_ids!r}"
                )

    def _rebuild_if_stale(self) -> None:
        with self._lock:
            now_ns = time.monotonic_ns()
            if (
                self._cached_snapshot is not None
                and now_ns - self._cache_built_ns
                < self._CACHE_REBUILD_DEBOUNCE_NS
            ):
                return
            new_sig = self._compute_mtime_signature()
            if (
                self._cached_snapshot is not None
                and new_sig == self._cached_mtime_signature
            ):
                self._cache_built_ns = now_ns
                return
            # Rebuild.
            warnings: list[str] = []
            by_id: dict[str, IcsProtocolManifest] = {}
            for yaml_path in self._iter_yaml_paths():
                manifest = self._load_one(yaml_path, warnings)
                if manifest is None:
                    continue
                if manifest.manifest_id in by_id:
                    warnings.append(
                        f"{yaml_path}: duplicate manifest_id "
                        f"{manifest.manifest_id!r}; SKIPPED"
                    )
                    continue
                by_id[manifest.manifest_id] = manifest
            # I4 collision check (post-load — needs full set).
            self._check_i4_cross_vendor_collision(by_id, warnings)
            self._cached_by_id = by_id
            self._cached_snapshot = IcsProtocolCatalogSnapshot.from_dict(
                by_id, loaded_at_unix_ns=time.time_ns(),
            )
            self._cached_mtime_signature = new_sig
            self._cache_built_ns = now_ns
            if warnings:
                self.last_warning = "\n".join(warnings)
                logger.warning(
                    "IcsProtocolCatalog load warnings (%d): %s",
                    len(warnings), self.last_warning,
                )
            else:
                self.last_warning = None

    def get_catalog(self) -> dict[str, IcsProtocolManifest]:
        """Return the current ``manifest_id → manifest`` mapping (rebuilds if stale)."""
        self._rebuild_if_stale()
        return dict(self._cached_by_id)

    def get_snapshot(self) -> IcsProtocolCatalogSnapshot:
        """Return the current frozen snapshot (rebuilds if stale)."""
        self._rebuild_if_stale()
        assert self._cached_snapshot is not None
        return self._cached_snapshot

    def reload(self) -> None:
        """Force a rebuild on the next access; clears the mtime signature."""
        with self._lock:
            self._cached_mtime_signature = None
            self._cached_snapshot = None
            self._cache_built_ns = 0

    def state_snapshot(self) -> dict[str, object]:
        """Operator-visible state snapshot (telemetry/observability).

        Mirror of `MtimeCachedYamlLoader.state_snapshot()` for the ICS surface.
        """
        with self._lock:
            return {
                "data_root": str(self._data_root),
                "overlay_root": str(self._overlay_root),
                "manifest_count": len(self._cached_by_id),
                "snapshot_id": (
                    self._cached_snapshot.snapshot_id
                    if self._cached_snapshot else None
                ),
                "loaded_at_unix_ns": (
                    self._cached_snapshot.loaded_at_unix_ns
                    if self._cached_snapshot else 0
                ),
                "last_warning": self.last_warning,
            }


# Process-wide singleton.
_DEFAULT_CATALOG: IcsProtocolCatalog | None = None
_DEFAULT_CATALOG_LOCK = threading.Lock()


def get_default_catalog() -> IcsProtocolCatalog:
    """Return the process-wide singleton catalog."""
    global _DEFAULT_CATALOG
    if _DEFAULT_CATALOG is not None:
        return _DEFAULT_CATALOG
    with _DEFAULT_CATALOG_LOCK:
        if _DEFAULT_CATALOG is None:
            _DEFAULT_CATALOG = IcsProtocolCatalog()
        return _DEFAULT_CATALOG


def reset_default_catalog() -> None:
    """Reset the singleton (test-only)."""
    global _DEFAULT_CATALOG
    with _DEFAULT_CATALOG_LOCK:
        _DEFAULT_CATALOG = None


__all__ = [
    "IcsProtocolCatalog",
    "derive_vendor_authority",
    "get_default_catalog",
    "reset_default_catalog",
]
