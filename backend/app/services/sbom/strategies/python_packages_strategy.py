"""Python site-packages detector (.dist-info / .egg-info).

Walks common Python site-packages locations under the firmware root and
detects installed packages by parsing PEP 376 ``.dist-info`` and
legacy ``.egg-info`` directories.

Previously ``SbomService._scan_python_packages /
_parse_python_metadata`` in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import glob as _glob
import os

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.purl import build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

_SITE_PACKAGES_GLOBS = (
    "usr/lib/python*/site-packages",
    "usr/lib/python*/dist-packages",
    "usr/local/lib/python*/site-packages",
)


def _parse_python_metadata(meta_file: str) -> tuple[str | None, str | None]:
    """Parse Name and Version from a Python METADATA or PKG-INFO file."""
    if not os.path.isfile(meta_file):
        return None, None
    name = None
    version = None
    try:
        with open(meta_file, errors="replace") as f:
            for line in f:
                if line.startswith("Name:"):
                    name = line[5:].strip().lower()
                elif line.startswith("Version:"):
                    version = line[8:].strip()
                elif line.startswith(" ") or line.startswith("\t"):
                    continue
                elif name and version:
                    break  # Got both, stop reading
    except OSError:
        pass
    return name, version


class PythonPackagesStrategy(SbomStrategy):
    """Detect Python packages from .dist-info and .egg-info directories."""

    name = "python_packages"

    def run(self, ctx: StrategyContext) -> None:
        for pattern in _SITE_PACKAGES_GLOBS:
            full_pattern = os.path.join(ctx.extracted_root, pattern)
            for site_dir in _glob.glob(full_pattern):
                if not os.path.isdir(site_dir):
                    continue
                try:
                    entries = os.listdir(site_dir)
                except OSError:
                    continue
                for entry in entries:
                    self._process_entry(site_dir, entry, ctx)

    @staticmethod
    def _process_entry(site_dir: str, entry: str, ctx: StrategyContext) -> None:
        name: str | None = None
        version: str | None = None
        rel_path = os.path.relpath(
            os.path.join(site_dir, entry), ctx.extracted_root
        )

        if entry.endswith(".dist-info"):
            # PEP 376: name-version.dist-info
            meta_file = os.path.join(site_dir, entry, "METADATA")
            if not os.path.isfile(meta_file):
                meta_file = os.path.join(site_dir, entry, "PKG-INFO")
            name, version = _parse_python_metadata(meta_file)
            if not name:
                # Fallback: parse directory name
                parts = entry[:-len(".dist-info")].rsplit("-", 1)
                name = parts[0].lower().replace("_", "-")
                version = parts[1] if len(parts) > 1 else None

        elif entry.endswith(".egg-info"):
            # setuptools: name-version.egg-info
            meta_path = os.path.join(site_dir, entry)
            if os.path.isdir(meta_path):
                meta_file = os.path.join(meta_path, "PKG-INFO")
            else:
                meta_file = meta_path  # single-file .egg-info
            name, version = _parse_python_metadata(meta_file)
            if not name:
                parts = entry[:-len(".egg-info")].rsplit("-", 1)
                name = parts[0].lower().replace("_", "-")
                version = parts[1] if len(parts) > 1 else None

        if not name or name == "unknown":
            return

        # Skip placeholder entries
        if version == "0.0.0":
            version = None

        comp = IdentifiedComponent(
            name=name,
            version=version,
            type="library",
            cpe=None,  # Python packages rarely have CPEs
            purl=build_purl(name, version, "pypi"),
            supplier=None,
            detection_source="python_package",
            detection_confidence="high",
            file_paths=[f"/{rel_path}"],
            metadata={"source": "python", "ecosystem": "pypi"},
        )
        ctx.store.add(comp)
