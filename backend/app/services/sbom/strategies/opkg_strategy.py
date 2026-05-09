"""OpenWrt ``opkg`` package database parser.

Parses one of the opkg status paths (OpenWrt, historical busybox-based
images). Uses the same Debian-style control-block format as dpkg but
WITHOUT the ``Status: ... installed`` gate — opkg only writes installed
packages to status files.

Previously part of ``SbomService._scan_package_managers /
_parse_opkg_status`` in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import os

from app.services.sbom.constants import CPE_VENDOR_MAP, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext
from app.services.sbom.strategies.dpkg_strategy import parse_control_block

_OPKG_STATUS_PATHS = (
    "/usr/lib/opkg/status",
    "/var/lib/opkg/status",
    "/usr/lib/opkg/info",
)


class OpkgStrategy(SbomStrategy):
    """Detect OpenWrt/opkg packages from one of the known status paths."""

    name = "opkg"

    def run(self, ctx: StrategyContext) -> None:
        for rel_path in _OPKG_STATUS_PATHS:
            abs_path = ctx.abs_path(rel_path)
            if os.path.isfile(abs_path):
                self._parse(abs_path, ctx)

    @staticmethod
    def _parse(abs_path: str, ctx: StrategyContext) -> None:
        try:
            with open(abs_path, errors="replace") as f:
                content = f.read()
        except OSError:
            return

        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            fields = parse_control_block(block)
            name = fields.get("package", "").strip()
            version = fields.get("version", "").strip() or None
            if not name:
                continue

            vendor_product = CPE_VENDOR_MAP.get(name.lower())
            cpe = None
            if vendor_product:
                cpe = build_cpe(vendor_product[0], vendor_product[1], version)

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=build_purl(name, version, "opkg"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "opkg",
                },
            )
            ctx.store.add(comp)
