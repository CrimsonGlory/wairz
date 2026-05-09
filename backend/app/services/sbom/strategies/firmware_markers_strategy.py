"""Firmware OS fingerprinting via marker files (DD-WRT, buildroot, Yocto).

Checks a handful of well-known marker files that identify the
build-system / distro lineage of an embedded firmware image. Each
detection pulls the version out of the file content when possible.

Previously ``SbomService._scan_firmware_markers`` + the
``FIRMWARE_MARKERS`` constant in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import FIRMWARE_MARKERS, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext


class FirmwareMarkersStrategy(SbomStrategy):
    """Detect distro lineage from marker files not covered by os-release."""

    name = "firmware_markers"

    def run(self, ctx: StrategyContext) -> None:
        for distro_id, marker_paths in FIRMWARE_MARKERS.items():
            for rel_path in marker_paths:
                abs_path = ctx.abs_path(rel_path)
                if not os.path.isfile(abs_path):
                    continue
                try:
                    with open(abs_path, errors="replace") as f:
                        content = f.read(1024).strip()
                except OSError:
                    continue
                if not content:
                    continue

                # Try to extract a version number from the file content
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
                version = (
                    version_match.group(1)
                    if version_match else content[:50]
                )

                comp = IdentifiedComponent(
                    name=distro_id,
                    version=version,
                    type="operating-system",
                    cpe=build_cpe(distro_id, distro_id, version),
                    purl=build_purl(distro_id, version),
                    supplier=distro_id,
                    detection_source="config_file",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={
                        "marker_file": rel_path,
                        "raw_content": content[:200],
                    },
                )
                ctx.store.add(comp)
                break  # Only need one marker per distro
