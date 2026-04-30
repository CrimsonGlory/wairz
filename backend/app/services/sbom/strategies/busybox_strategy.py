"""Dedicated BusyBox binary scanner.

BusyBox installs as a single binary with hundreds of symlinks, so the
generic binary scanner (which skips symlinks) may miss it depending on
layout. This strategy resolves symlinks explicitly and reads the actual
binary to extract the version string.

Previously ``SbomService._scan_busybox`` in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext
from app.utils.sandbox import safe_walk

# Common locations where the real busybox binary (or a symlink to it)
# lives. /bin/sh is almost always a symlink to busybox on embedded systems.
# Vendor-specific layouts (Wyze: /bin/busybox/bin/busybox) are covered by
# the walk-fallback below.
_CANDIDATES = (
    "/bin/busybox",
    "/bin/busybox.nosuid",
    "/bin/busybox.suid",
    "/usr/bin/busybox",
    "/sbin/busybox",
    "/bin/sh",
    "/bin/busybox/bin/busybox",  # Wyze cameras
    "/bin/busybox/sbin/busybox",
)

_MAX_BUSYBOX_SIZE = 4 * 1024 * 1024  # 4MB


class BusyBoxStrategy(SbomStrategy):
    """Explicitly search for BusyBox; resolve symlinks to read the real binary."""

    name = "busybox"

    def run(self, ctx: StrategyContext) -> None:
        if self._scan_at(ctx, list(_CANDIDATES)):
            return

        # Walk-fallback: search /bin, /sbin, /usr/bin, /usr/sbin for a file
        # literally named "busybox". Catches arbitrary vendor layouts.
        for walk_dir in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
            abs_walk = ctx.abs_path(walk_dir)
            if not os.path.isdir(abs_walk):
                continue
            extra: list[str] = []
            for dirpath, _dirs, files in safe_walk(abs_walk):
                for name in files:
                    if name == "busybox":
                        full = os.path.join(dirpath, name)
                        if os.path.isfile(full) and not os.path.islink(full):
                            rel = "/" + os.path.relpath(full, ctx.extracted_root)
                            extra.append(rel)
            if extra and self._scan_at(ctx, extra):
                return

    def _scan_at(self, ctx: StrategyContext, candidates: list[str]) -> bool:
        """Try each candidate path for a BusyBox banner. Returns True on hit."""
        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = ctx.abs_path(candidate)

            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue

            if not real_path.startswith(ctx.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue

            # BusyBox banners often live deep in rodata (past 256KB);
            # read whole file capped at 4MB.
            try:
                if os.path.getsize(real_path) > _MAX_BUSYBOX_SIZE:
                    continue
                with open(real_path, "rb") as f:
                    data = f.read()
            except OSError:
                continue

            match = re.search(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)", data)
            if match:
                version = match.group(1).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, ctx.extracted_root)

                comp = IdentifiedComponent(
                    name="busybox",
                    version=version,
                    type="application",
                    cpe=build_cpe("busybox", "busybox", version),
                    purl=build_purl("busybox", version),
                    supplier="busybox",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated busybox scan"},
                )
                ctx.store.add(comp)
                return True

        return False
