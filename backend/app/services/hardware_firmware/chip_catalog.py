"""Chip-family catalog loader for bare-metal MCU/DSP firmware analysis.

Walks ``backend/app/services/hardware_firmware/data/chip_families/**/*.yaml``,
parses each via Pydantic against :class:`app.schemas.chip_family.ChipFamilyManifest`,
and exposes the aggregated ``family_id → manifest`` catalog with per-file
mtime-based hot-reload.

**Hot-reload contract** (mirrors :class:`app.utils.yaml_cache.MtimeCachedYamlLoader`):

* Directory is re-walked on EVERY ``get_chip_catalog()`` call (cheap — single
  ``rglob``).
* Each file's ``st_mtime_ns`` is compared against the per-path cache cursor.
* Unchanged file → cached manifest is returned.
* Changed file → re-parse; on success swap atomically + log INFO; on
  Pydantic / YAML failure keep PREVIOUS valid cached value + log WARN ONCE
  per mtime (the failed-mtime cursor is advanced so subsequent calls don't
  re-warn until the operator saves again).
* Deleted file → drops from catalog on next call.
* New file → appears on next call.

**Graceful-degrade** (Rule #34): missing root dir → empty catalog; malformed
YAML at startup with no prior valid cache → skipped + WARN, never raises.
The walker's ``YamlDrivenMatcher`` consumes the catalog snapshot — an empty
catalog means "no chip families matched" not "crash". Operators see this
state via the MCP ``list_chip_families`` tool.

**Adaptability surface** (the user-stated direction 2026-05-19): operators
drop a new YAML at ``data/chip_families/<vendor>/<family>.yaml`` and the
next walker invocation picks it up. No docker restart. No code change. The
schema's closed-Literal grammar (see :mod:`app.schemas.chip_family`) is the
hard cap that keeps the YAML from becoming a programming language.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.schemas.chip_family import ChipFamilyManifest

logger = logging.getLogger(__name__)


# Canonical catalog root. Adjacent to existing patterns_loader YAML data.
_DATA_ROOT = Path(__file__).parent / "data" / "chip_families"


class ChipCatalog:
    """Per-file mtime-cached catalog of chip-family manifests under one root.

    Thread-safe via ``threading.RLock``. Concurrent accessors during a reload
    either see the FULL previous state or the FULL new state, never a torn
    partial.

    Tracks ``stat_count`` and ``reload_count`` for test instrumentation.
    Latest failure message exposed via ``last_warning`` for MCP
    ``list_extension_points``-style observability.
    """

    def __init__(self, *, root_resolver: Callable[[], Path]) -> None:
        self._root_resolver = root_resolver
        self._lock = threading.RLock()
        # path → (mtime_ns, manifest)
        self._cache: dict[Path, tuple[int, ChipFamilyManifest]] = {}
        # path → mtime_ns of last malformed parse (warn-once-per-mtime)
        self._failed_mtime: dict[Path, int] = {}
        # Test instrumentation
        self.stat_count: int = 0
        self.reload_count: int = 0
        self.last_warning: str | None = None

    def get_catalog(self) -> dict[str, ChipFamilyManifest]:
        """Return ``family_id → manifest`` snapshot of the catalog."""
        with self._lock:
            self.stat_count += 1
            root = self._root_resolver()
            if not root.is_dir():
                if self._cache:
                    logger.info("chip_catalog: root %s vanished — dropping %d entries",
                                root, len(self._cache))
                self._cache.clear()
                self._failed_mtime.clear()
                return {}
            current_paths: set[Path] = set()
            for yaml_path in sorted(root.rglob("*.yaml")):
                if not yaml_path.is_file():
                    continue
                current_paths.add(yaml_path)
                self._refresh(yaml_path)
            # Drop entries whose files vanished (operator removed YAML)
            removed = set(self._cache) - current_paths
            for stale in removed:
                manifest = self._cache.pop(stale, (None, None))[1]
                self._failed_mtime.pop(stale, None)
                if manifest is not None:
                    logger.info("chip_catalog: file removed %s (was %s)",
                                stale, manifest.family_id)
            removed_failed = set(self._failed_mtime) - current_paths
            for stale in removed_failed:
                self._failed_mtime.pop(stale, None)
            return {m.family_id: m for _, m in self._cache.values()}

    def get_family(self, family_id: str) -> ChipFamilyManifest | None:
        """Convenience: look up one family by ``vendor/family`` id."""
        return self.get_catalog().get(family_id)

    def get_domain(self, domain_id: str) -> tuple[ChipFamilyManifest, str] | None:
        """Resolve ``vendor/family/domain`` → ``(manifest, domain_name)``.

        Returns ``None`` if the family is missing OR the domain name is not
        declared on the family.
        """
        parts = domain_id.split("/")
        if len(parts) != 3:
            return None
        family_id = f"{parts[0]}/{parts[1]}"
        manifest = self.get_family(family_id)
        if manifest is None:
            return None
        for domain in manifest.domains:
            if domain.name == parts[2]:
                return (manifest, domain.name)
        return None

    def cache_clear(self) -> None:
        """Forget all cached state. Forces a fresh load on next ``get_catalog()``.

        Name matches :meth:`functools.lru_cache.cache_clear` for pytest
        fixtures + matches the convention established by
        :class:`MtimeCachedYamlLoader.cache_clear`.
        """
        with self._lock:
            self._cache.clear()
            self._failed_mtime.clear()
            self.last_warning = None

    def _refresh(self, path: Path) -> None:
        """Refresh one YAML file under the lock. Internal."""
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError as exc:
            logger.warning("chip_catalog: stat failed for %s: %s", path, exc)
            return
        # If previously failed at THIS mtime, skip silently — operator must
        # save the file again to trigger another reload attempt.
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
            manifest = ChipFamilyManifest.model_validate(raw)
            # Stamp provenance — operators can trace runtime back to source file.
            manifest_with_source = manifest.model_copy(update={"source_path": str(path)})
            self._cache[path] = (mtime_ns, manifest_with_source)
            self._failed_mtime.pop(path, None)
            self.reload_count += 1
            if cached is None:
                logger.info(
                    "chip_catalog: loaded %s (family %s, %d domain(s))",
                    path, manifest.family_id, len(manifest.domains),
                )
            else:
                logger.info(
                    "chip_catalog: reloaded %s (family %s, mtime change)",
                    path, manifest.family_id,
                )
            self.last_warning = None
        except (yaml.YAMLError, ValidationError, ValueError) as exc:
            # Pydantic ValidationError lists ALL allowed Literal values before
            # the offending input_value, so the input_value sits past the
            # naive prefix truncation. For Pydantic specifically, extract the
            # structured ``errors()`` list and surface the offending value +
            # field path first, then fall back to flattened-message form.
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
            if cached is not None:
                logger.warning(
                    "chip_catalog: malformed %s — keeping prior family %s: %s",
                    path, cached[1].family_id, msg,
                )
            else:
                logger.warning(
                    "chip_catalog: malformed %s — no prior, skipping: %s",
                    path, msg,
                )


# Module-level default catalog instance. Tests inject alternate roots via
# monkeypatch of ``_DATA_ROOT`` or by constructing a fresh ``ChipCatalog``.
_DEFAULT_CATALOG = ChipCatalog(root_resolver=lambda: _DATA_ROOT)


def get_chip_catalog() -> dict[str, ChipFamilyManifest]:
    """Return the current catalog snapshot (auto-refresh on mtime change)."""
    return _DEFAULT_CATALOG.get_catalog()


def get_chip_family(family_id: str) -> ChipFamilyManifest | None:
    """Look up a chip family by ``vendor/family`` id."""
    return _DEFAULT_CATALOG.get_family(family_id)


def get_chip_domain(domain_id: str) -> tuple[ChipFamilyManifest, str] | None:
    """Look up ``(manifest, domain_name)`` by ``vendor/family/domain`` triple."""
    return _DEFAULT_CATALOG.get_domain(domain_id)


def get_default_catalog() -> ChipCatalog:
    """Return the module-level catalog instance (for test instrumentation)."""
    return _DEFAULT_CATALOG


__all__ = [
    "ChipCatalog",
    "get_chip_catalog",
    "get_chip_family",
    "get_chip_domain",
    "get_default_catalog",
]
