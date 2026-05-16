"""Generic mtime-checked lazy-reload cache for YAML-backed configuration files.

Wraps a single YAML file with a thread-safe accessor that:

* Reads the file once on first access (or returns in-tree defaults if the
  file is missing / unparseable / structurally invalid).
* On every subsequent access, ``stat()``'s the file and compares
  ``st_mtime_ns`` against the cached value:

  * **Unchanged** → returns the cached parsed value (one stat per call).
  * **Changed** → re-reads + re-parses; on success, swaps the cached
    value atomically and logs INFO ``"<name>: <path> reloaded due to
    mtime change (<summary>)"``; on parse / structural failure, **keeps
    the PREVIOUS valid cached value** and logs WARN. The mtime cursor
    is advanced to the malformed file's mtime so subsequent calls don't
    retry on every accessor — the operator must save the file again
    (bumping mtime) to trigger another reload attempt.

* Thread-safe via a ``threading.RLock`` — concurrent accessors during a
  reload either see the FULL previous state or the FULL new state, never
  a torn partial.

Eliminates the docker restart cycle for YAML iteration: operators edit
the YAML, save, and the next analyze / cve-match invocation picks up the
new entries within ONE accessor call. Pairs with the success-path INFO
logs added 2026-05-17 so operators see "loaded N entries — YAML, not
defaults" + "reloaded due to mtime change."

This is an ADAPTABILITY surface, not a magic-byte gate — wairz consumers
should be willing to absorb operator-extended YAML without docker
restarts. The cache layer is intentionally generic so future YAML
surfaces (Tegra classifier extensions, Realtek BT chipset overrides,
arbitrary vendor uploads) can reuse the same machinery.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

import yaml

logger = logging.getLogger(__name__)

T = TypeVar("T")


class MtimeCachedYamlLoader(Generic[T]):
    """Mtime-checked lazy-reload cache for one YAML file → typed value.

    See the module docstring for the full contract.

    Public surface:

    * ``get()`` — returns the current cached value, reloading from disk
      if the file's ``st_mtime_ns`` changed since the previous call.
    * ``cache_clear()`` — pytest-friendly reset; forgets the cached value
      AND the cached mtime, forcing a fresh load on the next ``get()``.
      Name matches ``functools.lru_cache.cache_clear`` so existing
      fixture code (``loader.cache_clear()``) keeps working after the
      lru_cache → mtime cache migration.
    * ``stat_count`` / ``reload_count`` — read-only counters for tests
      that need to verify cached-vs-reloaded behaviour without scraping
      logs. ``stat_count`` increments on every ``get()`` call;
      ``reload_count`` increments only when a successful re-parse swaps
      the cached value.

    The ``defaults`` value is returned whenever the file is missing OR
    unparseable AND no prior valid load has occurred. Once a successful
    load completes, the previous-state is kept under both transient
    failures (read errors, parse errors) AND if the file is later
    deleted — graceful-degrade per Rule #34.
    """

    def __init__(
        self,
        *,
        path: Path | Callable[[], Path],
        parser: Callable[[dict], T],
        defaults: T,
        name: str,
        summary: Callable[[T], str],
    ) -> None:
        # ``path`` accepts either a fixed Path OR a zero-arg callable
        # that returns a Path. The callable form lets test fixtures swap
        # the underlying file via monkeypatch.setattr on a module-level
        # path constant — the loader re-resolves on every get() call so
        # the next .get() sees the new path without explicit cache_clear.
        if callable(path):
            self._path_resolver: Callable[[], Path] = path
        else:
            self._path_resolver = lambda fixed=path: fixed
        self._parser = parser
        self._defaults = defaults
        self._name = name
        self._summary = summary
        self._lock = threading.RLock()
        self._cached: T = defaults
        self._cached_mtime_ns: int | None = None
        # True once we've completed a successful YAML load (vs falling back
        # to defaults). Used to format the INFO log on subsequent reloads
        # and to keep-previous-state on a later vanish.
        self._loaded_from_yaml: bool = False
        # Path the last successful load came from. When the resolver
        # returns a NEW path (test fixture swap), we treat the next load
        # as a fresh first-call so logging shows "loaded — N entries
        # (YAML, not defaults)" not "reloaded due to mtime change".
        self._loaded_path: Path | None = None
        # Once-per-state log suppression flags. Cleared on cache_clear().
        self._warned_missing: bool = False
        self._logged_initial_default: bool = False
        # Counters for test instrumentation.
        self.stat_count: int = 0
        self.reload_count: int = 0
        # Most recent reload-failure message, queryable from the MCP
        # ``list_extension_points`` tool. ``None`` when the last reload
        # succeeded OR no reload has been attempted; populated with a
        # one-line ``"<ExceptionType>: <message>"`` on every failed
        # reload (read error, parse error, structural validation, stat
        # OSError); cleared on a subsequent successful reload + on
        # ``cache_clear()``. Pairs with the "keep previous on malformed"
        # contract so operators see why their YAML edit silently fell
        # back to the previous valid state, without shelling into the
        # container to grep the WARN log.
        self.last_warning: str | None = None

    @property
    def path(self) -> Path:
        return self._path_resolver()

    @property
    def name(self) -> str:
        return self._name

    def get(self) -> T:
        """Return the current cached value; reload-on-disk-change.

        Thread-safe: holds an RLock for the duration of the get() call so
        concurrent accessors during a reload see only the full previous
        or the full new state, never a torn partial.
        """
        with self._lock:
            self.stat_count += 1
            current_path = self._path_resolver()
            # Test-fixture path swap: if the resolver returned a path
            # different from the one we last successfully loaded from,
            # invalidate the cache so the next call re-loads fresh.
            if (
                self._loaded_path is not None
                and current_path != self._loaded_path
            ):
                self._cached_mtime_ns = None
                self._loaded_from_yaml = False
                self._warned_missing = False
                self._logged_initial_default = False
            try:
                mtime_ns = current_path.stat().st_mtime_ns
            except FileNotFoundError:
                return self._handle_missing(current_path)
            except OSError as exc:
                logger.warning(
                    "%s: stat %s failed (%s); using last cached value",
                    self._name,
                    current_path,
                    exc,
                )
                self.last_warning = f"{type(exc).__name__}: {exc}"
                return self._cached

            # File exists. Same-mtime fast path requires that we've
            # already loaded successfully; first-call-after-clear hits
            # the reload branch even if cached_mtime_ns matches by
            # coincidence (cache_clear resets it to None).
            if (
                self._cached_mtime_ns == mtime_ns
                and self._loaded_from_yaml
            ):
                return self._cached

            return self._reload(current_path, mtime_ns)

    def _handle_missing(self, current_path: Path) -> T:
        """File not on disk. Behaviour depends on whether we've ever loaded."""
        if self._loaded_from_yaml:
            # Successful prior load; file vanished. Keep previous state.
            if not self._warned_missing:
                logger.warning(
                    "%s: %s vanished after a successful load — keeping "
                    "previously loaded state (re-add the file to refresh)",
                    self._name,
                    current_path,
                )
                self._warned_missing = True
            # Reviewer A A1 (2026-05-15): file-vanish IS an operator-visible
            # failure path that belongs alongside parse/structural failures
            # in last_warning. Without this, the MCP list_extension_points
            # tool reports status="loaded" / last_warning=null on a vanished
            # YAML — silently contradicting HOT-2's "operators see WHY their
            # state silently fell back" goal.
            self.last_warning = (
                f"file vanished after successful load: {current_path}"
            )
            return self._cached
        # First-call with missing file — use defaults.
        if not self._logged_initial_default:
            logger.info(
                "%s: %s missing — using in-tree defaults (%s)",
                self._name,
                current_path,
                self._summary(self._defaults),
            )
            self._logged_initial_default = True
        return self._cached

    def _reload(self, current_path: Path, mtime_ns: int) -> T:
        """Attempt a fresh load; keep previous on failure."""
        try:
            with current_path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as exc:
            logger.warning(
                "%s: %s failed to read/parse (%s); keeping previously "
                "loaded state",
                self._name,
                current_path,
                exc,
            )
            self.last_warning = f"{type(exc).__name__}: {exc}"
            # Advance the mtime cursor so subsequent accessors don't
            # retry the same broken file on every call — the operator
            # must save the file again (bumping mtime) to retry.
            self._cached_mtime_ns = mtime_ns
            return self._cached

        if raw is None:
            # Empty YAML doc (`---` only) parses to None — treat as an
            # empty mapping for parsers that expect a dict, avoiding a
            # TypeError downstream.
            raw = {}
        if not isinstance(raw, dict):
            logger.warning(
                "%s: %s top-level must be a mapping, got %s; keeping "
                "previously loaded state",
                self._name,
                current_path,
                type(raw).__name__,
            )
            self.last_warning = (
                f"top-level must be a mapping, got {type(raw).__name__}"
            )
            self._cached_mtime_ns = mtime_ns
            return self._cached

        try:
            parsed = self._parser(raw)
        except Exception as exc:  # noqa: BLE001 — parser can raise anything
            logger.warning(
                "%s: %s structural validation failed (%s); keeping "
                "previously loaded state",
                self._name,
                current_path,
                exc,
            )
            self.last_warning = f"{type(exc).__name__}: {exc}"
            self._cached_mtime_ns = mtime_ns
            return self._cached

        # Success — atomic swap of the cached value.
        self.reload_count += 1
        previously_loaded = self._loaded_from_yaml
        self._cached = parsed
        self._cached_mtime_ns = mtime_ns
        self._loaded_from_yaml = True
        self._loaded_path = current_path
        # Reset the missing-warning flag — a successful load means the
        # operator may have restored the file after a deletion.
        self._warned_missing = False
        # Clear last_warning on successful reload so an operator who
        # fixed their malformed YAML sees the warning disappear on the
        # next mtime-triggered reload.
        self.last_warning = None
        if previously_loaded:
            logger.info(
                "%s: %s reloaded due to mtime change (%s)",
                self._name,
                current_path,
                self._summary(parsed),
            )
        else:
            logger.info(
                "%s: %s loaded — %s (YAML, not defaults)",
                self._name,
                current_path,
                self._summary(parsed),
            )
        return self._cached

    def __call__(self) -> T:
        """Allow ``loader()`` as an alias for ``loader.get()``.

        Preserves the call shape ``_load_X()`` from the previous
        ``@lru_cache`` decoration pattern so test fixtures that invoke
        the loader as a function (``PL._load_bt_qca_codenames()``)
        keep working under the mtime-cache migration.
        """
        return self.get()

    def cache_clear(self) -> None:
        """Forget the cached value + mtime; force fresh load on next ``get()``.

        Matches the ``functools.lru_cache.cache_clear`` shape so existing
        pytest fixtures that call ``_loader.cache_clear()`` migrate
        without source edits.
        """
        with self._lock:
            self._cached = self._defaults
            self._cached_mtime_ns = None
            self._loaded_from_yaml = False
            self._warned_missing = False
            self._logged_initial_default = False
            self.stat_count = 0
            self.reload_count = 0
            self.last_warning = None


# Module-level registry of named loaders for MCP discovery.
#
# Consumers (patterns_loader, cve_matcher, future YAML surfaces) call
# ``register_loader(surface_name, loader)`` at import time AFTER the
# loader is instantiated. The MCP ``list_extension_points`` tool walks
# this registry to enumerate currently-active extension surfaces +
# return per-loader load state (path, last_load_ts, entries,
# reload_count, last_warning).
#
# Surface names are kebab-case lowercase per wairz convention
# (``bt_qca_codenames`` / ``firmware_patterns`` / ``known_firmware``).
# Registration is idempotent — re-registering the same surface_name
# replaces the loader reference (typically only happens under pytest
# when modules are reimported).
_yaml_loader_registry: dict[str, MtimeCachedYamlLoader] = {}


def register_loader(surface_name: str, loader: MtimeCachedYamlLoader) -> None:
    """Register ``loader`` under ``surface_name`` for MCP discovery.

    Idempotent — re-registration replaces the prior reference (pytest-
    safe under module reload).
    """
    _yaml_loader_registry[surface_name] = loader


def list_registered_loaders() -> dict[str, MtimeCachedYamlLoader]:
    """Return a snapshot of currently-registered YAML loaders.

    Returns a dict copy so callers can iterate safely without holding
    the registry under mutation from concurrent registrations.
    """
    return dict(_yaml_loader_registry)


__all__ = [
    "MtimeCachedYamlLoader",
    "register_loader",
    "list_registered_loaders",
]
