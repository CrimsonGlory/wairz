"""SBOM service coordinator — runs strategies + post-processing passes.

Thin orchestration layer over the strategy list in
``app.services.sbom.strategies``. Public API is preserved from the
legacy ``app.services.sbom_service.SbomService`` — two construction
modes, one primary entry point (``generate_sbom``), same return shape.

Two construction modes:

1. ``SbomService(extracted_root="/path/to/rootfs")`` — legacy
   single-root mode. Retained for direct callers (tests, MCP tools)
   that don't have a Firmware row handy. The single root is used as
   the sole scan root.
2. ``SbomService(firmware=fw)`` — Phase 3a mode. Resolves all detection
   roots via ``app.services.firmware_paths.get_detection_roots`` so
   sibling partition dirs (scatter zips, raw images) are scanned too.
   The primary root becomes ``self.extracted_root``; additional roots
   surface through the partition loop in ``generate_sbom``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from app.services.jsonb_normalizers import _normalize_firmware_device_metadata
from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.enrichment import enrich_cpes
from app.services.sbom.normalization import ComponentStore
from app.services.sbom.service_risks import annotate_service_risks
from app.services.sbom.strategies.android_strategy import AndroidStrategy
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext
from app.services.sbom.strategies.binary_strings_strategy import (
    BinaryStringsStrategy,
)
from app.services.sbom.strategies.busybox_strategy import BusyBoxStrategy
from app.services.sbom.strategies.c_library_strategy import CLibraryStrategy
from app.services.sbom.strategies.dpkg_strategy import DpkgStrategy
from app.services.sbom.strategies.firmware_markers_strategy import (
    FirmwareMarkersStrategy,
)
from app.services.sbom.strategies.gcc_strategy import GccStrategy
from app.services.sbom.strategies.kernel_strategy import KernelStrategy
from app.services.sbom.strategies.opkg_strategy import OpkgStrategy
from app.services.sbom.strategies.python_packages_strategy import (
    PythonPackagesStrategy,
)
from app.services.sbom.strategies.so_files_strategy import SoFilesStrategy
from app.services.sbom.strategies.syft_strategy import SyftStrategy
from app.utils.sandbox import validate_path

if TYPE_CHECKING:
    from app.models.firmware import Firmware


class SbomService:
    """Identifies software components from an unpacked firmware filesystem.

    Thin coordinator over :class:`ComponentStore` + ordered list of
    :class:`SbomStrategy` instances. Public API (``__init__`` shape,
    ``generate_sbom()``, ``extracted_root`` attribute) matches the
    legacy monolithic ``sbom_service.SbomService`` exactly.
    """

    #: Ordered list of strategy classes. Syft runs first for broad
    #: medium-confidence coverage; curated strategies that override
    #: with high-confidence detections run after.
    _STRATEGY_CLASSES: tuple[type[SbomStrategy], ...] = (
        # Package managers
        DpkgStrategy,
        OpkgStrategy,
        PythonPackagesStrategy,
        # OS / kernel
        KernelStrategy,
        FirmwareMarkersStrategy,
        # Toolchain / core binaries
        BusyBoxStrategy,
        CLibraryStrategy,
        GccStrategy,
        # Libraries + generic binary strings
        SoFilesStrategy,
        BinaryStringsStrategy,
        # Android (walks system/vendor/product directly)
        AndroidStrategy,
    )

    def __init__(
        self,
        extracted_root: str | None = None,
        *,
        firmware: Firmware | None = None,
        detection_roots: list[str] | None = None,
    ):
        # Resolve the list of scan roots once at construction time.
        # Priority: explicit detection_roots → firmware row → extracted_root.
        if detection_roots is None:
            if firmware is not None:
                # Read from JSONB cache synchronously (mirrors the async
                # helper's cache path — the constructor runs in an
                # executor so we can't await here). Stale cache falls
                # back below.
                meta = _normalize_firmware_device_metadata(getattr(firmware, "device_metadata", None))
                cached = meta.get("detection_roots")
                if isinstance(cached, list) and all(
                    isinstance(p, str) and os.path.isdir(p) for p in cached
                ):
                    detection_roots = list(cached)
                else:
                    # No valid cache — caller should have populated via
                    # get_detection_roots before constructing us, but we
                    # fall back to firmware.extracted_path so we don't
                    # crash on a fresh row.
                    fp = getattr(firmware, "extracted_path", None)
                    detection_roots = [fp] if fp else []
            elif extracted_root:
                detection_roots = [extracted_root]
            else:
                detection_roots = []

        # Normalise — realpath every root, drop missing/empty entries.
        self._detection_roots: list[str] = [
            os.path.realpath(r) for r in detection_roots if r and os.path.isdir(r)
        ]

        # Pick the primary root (first entry) so legacy code that reads
        # ``self.extracted_root`` directly keeps working.
        if self._detection_roots:
            self.extracted_root = self._detection_roots[0]
        elif extracted_root:
            # Degraded fallback: single root even if it doesn't exist on
            # disk (e.g. tests that point at a tmp_path that has no content).
            self.extracted_root = os.path.realpath(extracted_root)
            self._detection_roots = [self.extracted_root]
        else:
            self.extracted_root = ""

        # Store owns the dict of components, normalisation, partition context.
        self._store = ComponentStore()

    # ------------------------------------------------------------------
    # Compatibility shims for legacy tests that poke at privates directly.
    # sbom_service.py's tests access ``svc._components`` and call
    # ``svc._parse_build_prop`` / ``svc._parse_android_init_rc``. Keep
    # these names routing into the new module boundaries.
    # ------------------------------------------------------------------

    @property
    def _components(self) -> dict[tuple[str, str | None], IdentifiedComponent]:
        """Backward-compat alias to the underlying component-store dict."""
        return self._store._components

    def _parse_build_prop(self, abs_path: str) -> None:
        """Parse an Android build.prop for test compatibility.

        Routes through :class:`AndroidStrategy` using a synthetic
        ``StrategyContext`` rooted at ``self.extracted_root``.
        """
        ctx = StrategyContext(
            extracted_root=self.extracted_root,
            store=self._store,
            partition_name=None,
        )
        AndroidStrategy()._parse_build_prop(abs_path, ctx)

    def _parse_android_init_rc(self, abs_path: str, rel_dir: str) -> None:
        """Parse a single Android init.rc for test compatibility."""
        ctx = StrategyContext(
            extracted_root=self.extracted_root,
            store=self._store,
            partition_name=None,
        )
        AndroidStrategy._parse_init_rc(abs_path, rel_dir, ctx)

    # ------------------------------------------------------------------
    # Helpers retained from the monolith for direct-caller callers that
    # probe internal paths (none currently, but preserved for parity).
    # ------------------------------------------------------------------

    def _validate(self, path: str) -> str:
        return validate_path(self.extracted_root, path)

    def _abs_path(self, rel_path: str) -> str:
        return os.path.join(self.extracted_root, rel_path.lstrip("/"))

    def _get_all_scan_roots(self) -> list[tuple[str, str | None]]:
        """Return all directories to scan: (path, partition_name | None).

        The primary extracted root is always first (partition_name=None).
        Additional roots come from ``get_detection_roots`` when the
        service was constructed with a ``Firmware`` row, or from the
        legacy sibling heuristic when given a bare ``extracted_root``.
        """
        roots: list[tuple[str, str | None]] = []
        seen_real: set[str] = set()

        primary_real = self.extracted_root
        roots.append((primary_real, None))
        seen_real.add(primary_real)

        # Phase 3a: additional roots from the helper (via __init__).
        for root in self._detection_roots[1:]:
            if root in seen_real:
                continue
            seen_real.add(root)
            partition_name = os.path.basename(root.rstrip("/")) or None
            roots.append((root, partition_name))

        # Legacy sibling heuristic (single-root construction, no Firmware
        # row). Retained so bare ``SbomService("/rootfs/system")``
        # continues to discover sibling /rootfs/vendor, /rootfs/product.
        # When ``_detection_roots`` already has >1 entry we assume the
        # helper already found the siblings.
        if len(self._detection_roots) <= 1 and self.extracted_root:
            parent = os.path.dirname(self.extracted_root)
            primary_name = os.path.basename(self.extracted_root)
            if os.path.basename(parent) in ("rootfs", "partitions", "images"):
                try:
                    for entry in sorted(os.listdir(parent)):
                        sibling_path = os.path.join(parent, entry)
                        if (
                            entry != primary_name
                            and os.path.isdir(sibling_path)
                            and not entry.startswith(".")
                        ):
                            real = os.path.realpath(sibling_path)
                            if real in seen_real:
                                continue
                            seen_real.add(real)
                            roots.append((sibling_path, entry))
                except OSError:
                    pass

        return roots

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def generate_sbom(self) -> list[dict]:
        """Run all identification strategies and return component list.

        Call from a thread executor (sync, CPU-bound). Returns list of
        dicts ready for DB insertion.
        """
        # Syft is run ONCE against the primary root (its internal
        # directory scan finds siblings on its own), then the per-
        # partition strategies iterate each scan root.
        syft_ctx = StrategyContext(
            extracted_root=self.extracted_root,
            store=self._store,
            partition_name=None,
        )
        SyftStrategy().run(syft_ctx)

        # Discover all scan roots for multi-partition firmware and run
        # the curated strategies across each one.
        scan_roots = self._get_all_scan_roots()
        strategies: list[SbomStrategy] = [cls() for cls in self._STRATEGY_CLASSES]

        for scan_root, partition_name in scan_roots:
            self._store.set_partition(partition_name)
            ctx = StrategyContext(
                extracted_root=scan_root,
                store=self._store,
                partition_name=partition_name,
            )
            for strategy in strategies:
                strategy.run(ctx)

        # Clear partition context before post-processing passes run
        self._store.set_partition(None)

        # Service-risk annotation walks the primary root's daemon dirs.
        # (Identical behaviour to the monolith, which only annotated
        # against ``self.extracted_root`` after the partition loop
        # restored the original value.)
        annotate_service_risks(self.extracted_root, self._store)

        # CPE enrichment post-processor — fills in missing CPEs
        enrich_cpes(self._store)

        # Serialise to dicts ready for DB insertion.
        results: list[dict] = []
        for comp in self._store.values():
            metadata = dict(comp.metadata)
            if comp.source_partition:
                metadata["source_partition"] = comp.source_partition
            results.append({
                "name": comp.name,
                "version": comp.version,
                "type": comp.type,
                "cpe": comp.cpe,
                "purl": comp.purl,
                "supplier": comp.supplier,
                "detection_source": comp.detection_source,
                "detection_confidence": comp.detection_confidence,
                "file_paths": comp.file_paths or None,
                "metadata": metadata,
            })

        return results
