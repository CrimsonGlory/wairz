"""File-format manifest catalog loader (P3.1.b).

Mirrors :class:`app.services.hardware_firmware.chip_catalog.ChipCatalog`:
walks YAML files under two roots (canonical + operator overlay), parses each
via Pydantic, exposes ``format_id → manifest`` mapping with per-file
mtime-based hot-reload, graceful-degrade on parse failure.

Two roots:
    ``data/file_formats/``           — in-tree, ``manifest_source`` MUST be
                                        ``_system`` (under ``_system/``)
                                        OR ``core`` (under ``<vendor>/``).
    ``data/file_formats.local/``     — operator overlay; ``manifest_source``
                                        MUST be ``operator`` for files in
                                        the root, ``attested_external`` for
                                        anything under ``_attested_external/``
                                        (P4 surface; today rejected at load).

**Path cross-check** (Wave-1 S3 G + W2-alpha Q7): the on-disk path tier is
the SOURCE OF TRUTH for ``manifest_source``. Mismatch → REJECT manifest.

**Cross-feature validators A1-A5** (W2-beta) fire at catalog construction:

* **A1** ``mode=override`` × ``manifest_source`` authority: override source's
  rank MUST be >= override target's rank. Prevents external override of
  operator's local override.
* **A2** ``vendor_authority`` DERIVED from THIS manifest's ``manifest_source``;
  never from alias_of. Surfaced via :func:`derive_vendor_authority`.
* **A3** ``dispatch.cases.*`` × ``deprecation.status: removed`` → REJECT load.
* **A4** Cross-vendor same-precedence same-magic collision → REJECT unless
  ``manifest_source`` differs.
* **A5** ``dispatch.depth_max >= 2`` × eager expensive plugin → REJECT.

A1-A5 emit WARN to ``last_warning`` and SKIP the offending manifest; the
catalog returns the remaining valid manifests so a single bad YAML never
takes down the whole loader (graceful-degrade per Rule #34).
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.schemas.file_format import (
    FileFormatManifest,
    ManifestSource,
    VendorAuthority,
)
from app.services.file_format_catalog.resolver import (
    PLUGIN_REGISTRY,
    _SIGNAL_COST_CLASS,
    _SOURCE_PRECEDENCE,
)
from app.services.file_format_catalog.snapshot import FormatCatalogSnapshot

logger = logging.getLogger(__name__)


# Canonical catalog roots. Adjacent to the schema's MtimeCachedYamlLoader pattern.
_DATA_ROOT = Path(__file__).parent / "data" / "file_formats"
_LOCAL_ROOT = Path(__file__).parent / "data" / "file_formats.local"


# manifest_source -> vendor_authority derivation (A2 implementation).
# Wave-1 W2-alpha Q1 + W2-beta A2. NEVER read alias_of target's authority.
_AUTHORITY_FROM_SOURCE: dict[ManifestSource, VendorAuthority] = {
    "_system": "curated",
    "core": "curated",
    "operator": "operator_supplied",
    "attested_external": "external_attested",
    "unauthenticated_external": "operator_supplied",
}


def derive_vendor_authority(manifest: FileFormatManifest) -> VendorAuthority:
    """Derive vendor_authority from THIS manifest's manifest_source (A2)."""
    return _AUTHORITY_FROM_SOURCE[manifest.manifest_source]


# Expensive plugin cost-class threshold for A5.
_EXPENSIVE_COST_CLASS_THRESHOLD = _SIGNAL_COST_CLASS["magic_bytes"]


# -----------------------------------------------------------------------------


def _expected_source_for_path(path: Path, system_root: Path, local_root: Path,
                              ) -> ManifestSource | None:
    """Determine the expected manifest_source from the on-disk path.

    Returns ``None`` if the path is outside both roots (shouldn't happen for
    files the loader picked up via rglob, but defensive).
    """
    try:
        rel_system = path.relative_to(system_root)
    except ValueError:
        rel_system = None
    try:
        rel_local = path.relative_to(local_root)
    except ValueError:
        rel_local = None

    if rel_system is not None:
        parts = rel_system.parts
        if parts and parts[0] == "_system":
            return "_system"
        return "core"
    if rel_local is not None:
        parts = rel_local.parts
        if parts and parts[0] == "_attested_external":
            return "attested_external"
        return "operator"
    return None


class FormatCatalog:
    """Per-file mtime-cached catalog of file-format manifests.

    Thread-safe via ``threading.RLock``. Mirrors ChipCatalog exactly in shape
    (chip_catalog.py:64-205). Adds:

    * **Two roots** — canonical + operator overlay.
    * **Path cross-check** — ``manifest_source`` MUST match on-disk tier.
    * **Cross-feature validators A1-A5** — load-time graph walk over the
      aggregated catalog state; rejects offending manifests with WARN.
    * **Snapshot accessor** — :meth:`get_snapshot` returns the frozen
      ``FormatCatalogSnapshot`` for resolver consumption.
    """

    def __init__(
        self,
        *,
        root_resolver: Callable[[], Path],
        local_root_resolver: Callable[[], Path] | None = None,
    ) -> None:
        self._root_resolver = root_resolver
        self._local_root_resolver = local_root_resolver
        self._lock = threading.RLock()
        # path -> (mtime_ns, manifest) — manifest already has path-cross-check applied
        self._cache: dict[Path, tuple[int, FileFormatManifest]] = {}
        # path -> mtime_ns of last malformed parse (warn-once-per-mtime)
        self._failed_mtime: dict[Path, int] = {}
        # Test instrumentation
        self.stat_count: int = 0
        self.reload_count: int = 0
        self.last_warning: str | None = None
        # Snapshot cache — invalidated when _cache changes
        self._snapshot: FormatCatalogSnapshot | None = None
        self._snapshot_cache_key: tuple = ()

    # ---- public API -------------------------------------------------------

    def get_catalog(self) -> dict[str, FileFormatManifest]:
        """Return ``format_id → manifest`` snapshot of the catalog."""
        with self._lock:
            self.stat_count += 1
            system_root = self._root_resolver()
            local_root = (
                self._local_root_resolver()
                if self._local_root_resolver is not None
                else None
            )
            current_paths: set[Path] = set()
            self._walk_root(system_root, current_paths)
            if local_root is not None:
                self._walk_root(local_root, current_paths)
            # Drop entries whose files vanished
            removed = set(self._cache) - current_paths
            for stale in removed:
                manifest_tup = self._cache.pop(stale, None)
                self._failed_mtime.pop(stale, None)
                if manifest_tup is not None:
                    logger.info(
                        "format_catalog: file removed %s (was %s)",
                        stale, manifest_tup[1].format_id,
                    )
            removed_failed = set(self._failed_mtime) - current_paths
            for stale in removed_failed:
                self._failed_mtime.pop(stale, None)
            # Build the by-format-id dict + run cross-feature validators.
            by_id = self._build_validated_catalog(system_root, local_root)
            return by_id

    def get_format(self, format_id: str) -> FileFormatManifest | None:
        """Convenience lookup by ``format_id``."""
        return self.get_catalog().get(format_id)

    def get_snapshot(self) -> FormatCatalogSnapshot:
        """Return a frozen snapshot of the catalog (Wave-1 S5 D).

        Snapshot id is sha256 of canonical JSON across all manifests with
        ``source_path`` excluded. Comment-only edits preserve snapshot id.
        """
        with self._lock:
            by_id = self.get_catalog()
            # Cache key: (sorted tuple of (format_id, source_path, mtime))
            cache_key = tuple(
                sorted(
                    (m.format_id, m.source_path or "",
                     self._cache.get(Path(m.source_path), (0, None))[0]
                     if m.source_path else 0)
                    for m in by_id.values()
                )
            )
            if self._snapshot is not None and cache_key == self._snapshot_cache_key:
                return self._snapshot
            snapshot = FormatCatalogSnapshot.from_dict(by_id, time.time_ns())
            self._snapshot = snapshot
            self._snapshot_cache_key = cache_key
            return snapshot

    def cache_clear(self) -> None:
        """Forget all cached state. Forces a fresh load on next call."""
        with self._lock:
            self._cache.clear()
            self._failed_mtime.clear()
            self.last_warning = None
            self._snapshot = None
            self._snapshot_cache_key = ()

    # ---- internals --------------------------------------------------------

    def _walk_root(self, root: Path | None, current_paths: set[Path]) -> None:
        """Walk one root; refresh each YAML found. Tolerant of missing dir."""
        if root is None:
            return
        if not root.is_dir():
            return
        for yaml_path in sorted(root.rglob("*.yaml")):
            if not yaml_path.is_file():
                continue
            # Skip hidden / dotfiles
            if yaml_path.name.startswith("."):
                continue
            current_paths.add(yaml_path)
            self._refresh(yaml_path)

    def _refresh(self, path: Path) -> None:
        """Refresh one YAML — try/except keeps prior valid state on failure."""
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError as exc:
            logger.warning("format_catalog: stat failed for %s: %s", path, exc)
            return
        if self._failed_mtime.get(path) == mtime_ns:
            return
        cached = self._cache.get(path)
        if cached is not None and cached[0] == mtime_ns:
            return  # Unchanged since last cache
        try:
            with path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
            if raw is None:
                raise ValueError("empty YAML document")
            manifest = FileFormatManifest.model_validate(raw)
            # Stamp source_path so operators trace runtime back to disk.
            manifest = manifest.model_copy(update={"source_path": str(path)})
            # Path cross-check — manifest_source MUST match on-disk tier.
            system_root = self._root_resolver()
            local_root = (
                self._local_root_resolver()
                if self._local_root_resolver is not None
                else None
            )
            expected = _expected_source_for_path(
                path, system_root, local_root if local_root else Path("/dev/null"),
            )
            if expected is not None and manifest.manifest_source != expected:
                raise ValueError(
                    f"path cross-check: file at {path.name} (tier "
                    f"{expected!r}) declares manifest_source="
                    f"{manifest.manifest_source!r}"
                )
            self._cache[path] = (mtime_ns, manifest)
            self._failed_mtime.pop(path, None)
            self.reload_count += 1
            self._snapshot = None  # invalidate
            if cached is None:
                logger.info(
                    "format_catalog: loaded %s (format %s)",
                    path, manifest.format_id,
                )
            else:
                logger.info(
                    "format_catalog: reloaded %s (format %s, mtime change)",
                    path, manifest.format_id,
                )
            self.last_warning = None
        except (yaml.YAMLError, ValidationError, ValueError) as exc:
            # Pydantic-aware error rendering (matches chip_catalog shape).
            if isinstance(exc, ValidationError):
                parts = []
                for err in exc.errors()[:4]:
                    loc = ".".join(str(p) for p in err.get("loc", ()))
                    inp = err.get("input")
                    inp_short = repr(inp)[:80] if inp is not None else "<missing>"
                    parts.append(f"{loc}={inp_short} ({err.get('msg', '?')})")
                short = "; ".join(parts)[:600]
            else:
                short = str(exc).replace("\n", " | ")[:600]
            msg = f"{type(exc).__name__}: {short}"
            self.last_warning = f"{path}: {msg}"
            self._failed_mtime[path] = mtime_ns
            self._snapshot = None  # invalidate so next call rebuilds
            if cached is not None:
                logger.warning(
                    "format_catalog: malformed %s — keeping prior format %s: %s",
                    path, cached[1].format_id, msg,
                )
            else:
                logger.warning(
                    "format_catalog: malformed %s — no prior, skipping: %s",
                    path, msg,
                )

    def _build_validated_catalog(
        self,
        system_root: Path,
        local_root: Path | None,
    ) -> dict[str, FileFormatManifest]:
        """Build the final ``format_id → manifest`` map under A1-A5 validators.

        Manifests that fail any cross-feature validator are SKIPPED (logged to
        ``last_warning``); the rest pass through. Graceful-degrade per Rule
        #34 — one bad YAML never takes down the whole catalog.
        """
        # Start with everything in _cache by format_id; later entries with the
        # same format_id replace earlier ones IF mode=override and A1 passes.
        # Default (mode=new) duplicate is REJECTED (silent shadow closed).
        by_id: dict[str, FileFormatManifest] = {}
        # First pass: collect by format_id with overlay semantics.
        # Iterate by DESCENDING source rank so higher-tier manifests load
        # first (Scout GG §SC5 dual): _system > core > operator > attested >
        # unauthenticated. Same-rank ties break alphabetically by path. This
        # ensures A1 (override authority) is evaluated against the highest-
        # rank prior entry, and silent-shadow ``mode=new`` duplicates are
        # rejected on the LOWER-rank side rather than the higher.
        def _iter_key(p: Path) -> tuple:
            _, m = self._cache[p]
            return (-_SOURCE_PRECEDENCE.get(m.manifest_source, 0), str(p))
        for path in sorted(self._cache, key=_iter_key):
            _mtime, manifest = self._cache[path]
            existing = by_id.get(manifest.format_id)
            if existing is None:
                by_id[manifest.format_id] = manifest
                continue
            # Duplicate format_id — apply overlay semantics
            if manifest.mode == "new":
                self.last_warning = (
                    f"{path}: duplicate format_id {manifest.format_id!r} "
                    f"with mode=new (already loaded from "
                    f"{existing.source_path}); silent-shadow closed (Wave-1 S5 C)"
                )
                logger.warning("format_catalog: %s", self.last_warning)
                continue
            if manifest.mode == "override":
                # A1: override-source's rank MUST be >= override-target's rank
                src_rank = _SOURCE_PRECEDENCE.get(manifest.manifest_source, 0)
                tgt_rank = _SOURCE_PRECEDENCE.get(existing.manifest_source, 0)
                if src_rank < tgt_rank:
                    self.last_warning = (
                        f"{path}: A1 mode=override rejected — source rank "
                        f"{manifest.manifest_source}({src_rank}) < target rank "
                        f"{existing.manifest_source}({tgt_rank})"
                    )
                    logger.warning("format_catalog: %s", self.last_warning)
                    continue
                by_id[manifest.format_id] = manifest
                continue
            if manifest.mode == "extend":
                # extend semantics are P3.2 — for now treat as override
                by_id[manifest.format_id] = manifest

        # Second pass: A3 — drop manifests whose dispatch references a REMOVED
        # format. Walk every loaded manifest's dispatch targets.
        to_drop: set[str] = set()
        for fmt_id, manifest in by_id.items():
            targets: list[str] = list(manifest.dispatch.cases.values())
            if manifest.dispatch.default:
                targets.append(manifest.dispatch.default)
            for target_id in targets:
                target = by_id.get(target_id)
                if target is None:
                    continue
                if target.deprecation.status == "removed":
                    self.last_warning = (
                        f"{manifest.source_path}: A3 dispatch target "
                        f"{target_id!r} has deprecation.status=removed"
                    )
                    logger.warning("format_catalog: %s", self.last_warning)
                    to_drop.add(fmt_id)
                    break
        for fmt_id in to_drop:
            del by_id[fmt_id]

        # Third pass: A4 — cross-vendor same-precedence same-magic collision.
        # Walk pairs of manifests; flag when (precedence, magic_bytes signal
        # at same offset+bytes) collide across DIFFERENT vendors AND same
        # manifest_source. Different manifest_source is intentional tiering.
        magic_index: dict[tuple[int, int, str], list[str]] = {}
        for fmt_id, manifest in by_id.items():
            for sig in manifest.detection.signals:
                if sig.kind != "magic_bytes":
                    continue
                if sig.offset is None or sig.bytes_hex is None:
                    continue
                key = (manifest.precedence, sig.offset, sig.bytes_hex.lower())
                magic_index.setdefault(key, []).append(fmt_id)
        a4_drop: set[str] = set()
        for key, fmt_ids in magic_index.items():
            if len(fmt_ids) < 2:
                continue
            # Group by (manifest_source, vendor) — collision if 2+ entries with
            # different vendors but SAME manifest_source.
            by_source: dict[str, list[tuple[str, str]]] = {}
            for fid in fmt_ids:
                m = by_id.get(fid)
                if m is None:
                    continue
                by_source.setdefault(m.manifest_source, []).append((fid, m.vendor))
            for source, entries in by_source.items():
                vendors = {v for _, v in entries}
                if len(vendors) >= 2:
                    self.last_warning = (
                        f"A4 cross-vendor collision at precedence={key[0]} "
                        f"offset={key[1]} bytes={key[2]!r}: "
                        f"{[fid for fid, _ in entries]} (source={source})"
                    )
                    logger.warning("format_catalog: %s", self.last_warning)
                    # Drop ALL conflicting entries — operator must reconcile.
                    for fid, _ in entries:
                        a4_drop.add(fid)
        for fmt_id in a4_drop:
            by_id.pop(fmt_id, None)

        # Fourth pass: A5 — dispatch.depth_max >= 2 AND eager expensive plugin
        # in a chained manifest → REJECT.
        a5_drop: set[str] = set()
        for fmt_id, manifest in by_id.items():
            if manifest.dispatch.depth_max < 2:
                continue
            # Walk dispatch targets up to depth_max
            visited: set[str] = set()
            queue: list[tuple[str, int]] = [
                (t, 1) for t in manifest.dispatch.cases.values()
            ]
            if manifest.dispatch.default:
                queue.append((manifest.dispatch.default, 1))
            while queue:
                target_id, depth = queue.pop(0)
                if target_id in visited or depth > manifest.dispatch.depth_max:
                    continue
                visited.add(target_id)
                target = by_id.get(target_id)
                if target is None:
                    continue
                # Check eager + expensive plugin
                if target.plugin.matcher is not None:
                    matcher_ref = target.plugin.matcher
                    if matcher_ref.bind == "eager":
                        plugin = PLUGIN_REGISTRY.get(matcher_ref.ref)
                        if plugin is not None:
                            cost = getattr(plugin, "cost_class", 0)
                            if cost >= _EXPENSIVE_COST_CLASS_THRESHOLD:
                                self.last_warning = (
                                    f"{manifest.source_path}: A5 deep dispatch "
                                    f"(depth_max={manifest.dispatch.depth_max}) "
                                    f"chains eager-expensive plugin "
                                    f"{matcher_ref.ref!r} (cost_class={cost}) "
                                    f"in {target_id!r}; require bind=lazy"
                                )
                                logger.warning(
                                    "format_catalog: %s", self.last_warning,
                                )
                                a5_drop.add(fmt_id)
                                break
                # Queue this target's own dispatch targets
                if target.dispatch.kind != "none":
                    for t in target.dispatch.cases.values():
                        queue.append((t, depth + 1))
                    if target.dispatch.default:
                        queue.append((target.dispatch.default, depth + 1))
        for fmt_id in a5_drop:
            by_id.pop(fmt_id, None)

        # Per-tier cardinality check (P3.2.a — replaces the singleton
        # always_matches check). The schema permits N>=1 manifests per
        # sort_tier so per-failure-class sentinels can be added; the
        # CATALOG-LOAD cardinality table caps the count without a schema
        # reform. Today: floor=1 (linux_blob_fallback ONLY), ceiling=0
        # (no current author; reserved future slot). Loosen via Rule #25
        # Shape-1 commit when a concrete second-floor use case appears.
        _SORT_TIER_MAX_CARDINALITY: dict[str, int] = {
            "floor": 1,
            "ceiling": 0,
        }
        by_tier: dict[str, list[str]] = {}
        for fid, m in by_id.items():
            by_tier.setdefault(m.detection.sort_tier, []).append(fid)
        for tier, max_count in _SORT_TIER_MAX_CARDINALITY.items():
            ids = by_tier.get(tier, [])
            if len(ids) > max_count:
                # Keep the highest-rank manifest_source; drop the rest.
                ranked = sorted(
                    ids,
                    key=lambda fid: (
                        -_SOURCE_PRECEDENCE.get(by_id[fid].manifest_source, 0),
                        by_id[fid].precedence,  # P3.2.a flip: lower wins
                        fid,
                    ),
                )
                for fid in ranked[max_count:]:
                    self.last_warning = (
                        f"sort-tier cardinality: {tier!r} permits at most "
                        f"{max_count}; dropping {fid!r} (kept: "
                        f"{ranked[:max_count]})"
                    )
                    logger.warning("format_catalog: %s", self.last_warning)
                    by_id.pop(fid, None)

        return by_id


# Module-level default catalog instance — tests inject alternate roots via
# monkeypatching or fresh constructor invocation.
_DEFAULT_CATALOG = FormatCatalog(
    root_resolver=lambda: _DATA_ROOT,
    local_root_resolver=lambda: _LOCAL_ROOT,
)


def get_format_catalog() -> dict[str, FileFormatManifest]:
    """Return the current catalog snapshot (auto-refresh on mtime change)."""
    return _DEFAULT_CATALOG.get_catalog()


def get_default_catalog() -> FormatCatalog:
    """Return the module-level catalog instance (for test instrumentation)."""
    return _DEFAULT_CATALOG


__all__ = [
    "FormatCatalog",
    "derive_vendor_authority",
    "get_default_catalog",
    "get_format_catalog",
]
