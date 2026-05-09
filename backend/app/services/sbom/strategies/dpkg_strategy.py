"""Debian ``dpkg`` package database parser.

Parses ``/var/lib/dpkg/status`` — a Debian-control-format flat-file
database of installed packages. Only packages whose status contains
``installed`` are emitted as components.

Previously part of ``SbomService._scan_package_managers /
_parse_dpkg_status / _parse_control_block`` in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os

from app.services.sbom.constants import CPE_VENDOR_MAP, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext


def parse_control_block(block: str) -> dict[str, str]:
    """Parse a Debian-style control file block into a dict.

    Continuation lines (leading space/tab) are concatenated to the
    previous field. Field names are lower-cased.
    """
    fields: dict[str, str] = {}
    current_key = ""
    current_val = ""
    for line in block.splitlines():
        if line.startswith((" ", "\t")):
            # Continuation line
            current_val += "\n" + line.strip()
        elif ":" in line:
            # Save previous field
            if current_key:
                fields[current_key.lower()] = current_val
            key, _, val = line.partition(":")
            current_key = key.strip()
            current_val = val.strip()
    if current_key:
        fields[current_key.lower()] = current_val
    return fields


class DpkgStrategy(SbomStrategy):
    """Detect Debian packages from ``/var/lib/dpkg/status``."""

    name = "dpkg"

    def run(self, ctx: StrategyContext) -> None:
        abs_path = ctx.abs_path("/var/lib/dpkg/status")
        if not os.path.isfile(abs_path):
            return
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
            status = fields.get("status", "")
            if not name:
                continue
            # Only include installed packages
            if "installed" not in status.lower():
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
                purl=build_purl(name, version, "deb"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "dpkg",
                },
            )
            ctx.store.add(comp)
