"""Linux kernel version detection from ``/lib/modules/*`` and ``.ko`` files.

Also parses ``/etc/os-release`` + ``/etc/openwrt_release`` for distro
identification (operating-system components).

Previously ``SbomService._scan_kernel_version /
_scan_kernel_from_vermagic / _parse_os_release`` in the
``sbom_service.py`` monolith.
"""

from __future__ import annotations

import os
import re
import subprocess

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext


class KernelStrategy(SbomStrategy):
    """Detect Linux kernel version + distro identification."""

    name = "kernel"

    def run(self, ctx: StrategyContext) -> None:
        kernel_found = False

        # Check /lib/modules/*/ (standard Linux)
        modules_dir = ctx.abs_path("/lib/modules")
        if os.path.isdir(modules_dir):
            try:
                for entry in os.listdir(modules_dir):
                    entry_path = os.path.join(modules_dir, entry)
                    if os.path.isdir(entry_path) and re.match(r"\d+\.\d+", entry):
                        match = re.match(r"(\d+\.\d+\.\d+)", entry)
                        version = match.group(1) if match else entry
                        comp = IdentifiedComponent(
                            name="linux-kernel",
                            version=version,
                            type="operating-system",
                            cpe=f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*",
                            purl=build_purl("linux", version),
                            supplier="linux",
                            detection_source="kernel_modules",
                            detection_confidence="high",
                            file_paths=[f"/lib/modules/{entry}"],
                            metadata={"full_version": entry},
                        )
                        ctx.store.add(comp)
                        kernel_found = True
                        break
            except OSError:
                pass

        # Fallback: extract kernel version from .ko vermagic strings.
        # Android puts modules in vendor/lib/modules or sibling partitions.
        if not kernel_found:
            kernel_found = self._scan_from_vermagic(ctx)

        # Check /etc/os-release, /etc/openwrt_release for distro info
        for rel_file in ("/etc/os-release", "/etc/openwrt_release"):
            abs_path = ctx.abs_path(rel_file)
            if os.path.isfile(abs_path):
                self._parse_os_release(abs_path, rel_file, ctx)

    @staticmethod
    def _scan_from_vermagic(ctx: StrategyContext) -> bool:
        """Extract kernel version from .ko module vermagic strings.

        Searches the extracted root AND sibling partitions (Android puts
        kernel modules in vendor or other partitions, not the system
        root). Returns True if a kernel version was identified.
        """
        # Search dirs: extracted root + sibling partition dirs
        search_dirs = [ctx.extracted_root]
        parent = os.path.dirname(ctx.extracted_root)
        if os.path.isdir(parent):
            try:
                for entry in os.listdir(parent):
                    sibling = os.path.join(parent, entry)
                    if (
                        os.path.isdir(sibling)
                        and sibling != ctx.extracted_root
                    ):
                        search_dirs.append(sibling)
            except OSError:
                pass

        for search_dir in search_dirs:
            # Find the first .ko file
            ko_path: str | None = None
            for dirpath, _, filenames in os.walk(search_dir):
                for fn in filenames:
                    if fn.endswith(".ko"):
                        ko_path = os.path.join(dirpath, fn)
                        break
                if ko_path:
                    break

            if not ko_path:
                continue

            # Extract vermagic string
            try:
                result = subprocess.run(
                    ["strings", ko_path],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if line.startswith("vermagic="):
                        # vermagic=6.6.102-android15-8-g... SMP preempt ...
                        ver_str = line.split("=", 1)[1].split()[0]
                        match = re.match(r"(\d+\.\d+\.\d+)", ver_str)
                        if match:
                            version = match.group(1)
                            rel_path = ko_path.replace(ctx.extracted_root, "")
                            comp = IdentifiedComponent(
                                name="linux-kernel",
                                version=version,
                                type="operating-system",
                                cpe=f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*",
                                purl=build_purl("linux", version),
                                supplier="linux",
                                detection_source="kernel_vermagic",
                                detection_confidence="high",
                                file_paths=[rel_path],
                                metadata={"full_version": ver_str},
                            )
                            ctx.store.add(comp)
                            return True
            except (subprocess.TimeoutExpired, OSError):
                continue

        return False

    @staticmethod
    def _parse_os_release(
        abs_path: str,
        rel_path: str,
        ctx: StrategyContext,
    ) -> None:
        """Parse os-release or openwrt_release for distro identification."""
        try:
            with open(abs_path, errors="replace") as f:
                content = f.read(4096)
        except OSError:
            return

        fields: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                fields[key.strip()] = val.strip().strip("'\"")

        distro_id = fields.get("ID", fields.get("DISTRIB_ID", "")).lower()
        distro_version = fields.get(
            "VERSION_ID", fields.get("DISTRIB_RELEASE", "")
        )
        distro_name = fields.get(
            "NAME", fields.get("DISTRIB_DESCRIPTION", distro_id)
        )

        if distro_id and distro_version:
            comp = IdentifiedComponent(
                name=distro_id,
                version=distro_version,
                type="operating-system",
                cpe=build_cpe(distro_id, distro_id, distro_version),
                purl=build_purl(distro_id, distro_version),
                supplier=distro_id,
                detection_source="config_file",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"display_name": distro_name},
            )
            ctx.store.add(comp)
