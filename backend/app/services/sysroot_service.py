"""Service for managing pre-built sysroot templates for standalone binary emulation.

Sysroots contain the minimal set of shared libraries (dynamic linker, libc,
libpthread, etc.) needed to run a dynamically-linked binary on a foreign
architecture via QEMU user-mode.

Sysroot templates are stored in the emulation container at /opt/sysroots/<arch>/.
They are built from Debian multiarch packages during the Docker image build.
"""

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Canonical architecture → sysroot directory name in the emulation container
SYSROOT_ARCH_MAP: dict[str, str] = {
    "arm": "arm",
    "aarch64": "aarch64",
    "mips": "mips",
    "mipsel": "mipsel",
    "x86": "i386",
    "x86_64": "x86_64",
}

# Known dynamic linker names per architecture (used for verification)
DYNAMIC_LINKER_NAMES: dict[str, list[str]] = {
    "arm": ["ld-linux-armhf.so.3", "ld-linux.so.3"],
    "aarch64": ["ld-linux-aarch64.so.1"],
    "mips": ["ld.so.1"],
    "mipsel": ["ld.so.1"],
    "x86": ["ld-linux.so.2"],
    "x86_64": ["ld-linux-x86-64.so.2"],
}

# Core libraries that every sysroot should contain
CORE_LIBS: list[str] = [
    "libc.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "libm.so.6",
    "librt.so.1",
    "libgcc_s.so.1",
]

# Container-internal base path for sysroots
SYSROOT_BASE_PATH = "/opt/sysroots"


def get_sysroot_path(architecture: str) -> str | None:
    """Return the container-internal sysroot path for a given architecture.

    Returns None if the architecture is not supported.
    """
    sysroot_name = SYSROOT_ARCH_MAP.get(architecture)
    if not sysroot_name:
        return None
    return f"{SYSROOT_BASE_PATH}/{sysroot_name}"


def get_sysroot_env(architecture: str) -> dict[str, str]:
    """Return environment variables needed for QEMU to use the sysroot.

    Used when starting emulation and fuzzing containers for standalone binaries.
    """
    sysroot = get_sysroot_path(architecture)
    if not sysroot:
        return {}
    return {"QEMU_LD_PREFIX": sysroot}


def check_dependencies(
    architecture: str,
    needed_libs: list[str],
    sysroot_contents: list[str] | None = None,
) -> dict[str, Any]:
    """Check which of the binary's dependencies are available in the sysroot.

    Args:
        architecture: Canonical architecture name (arm, aarch64, mips, etc.)
        needed_libs: List of DT_NEEDED library names from binary analysis.
        sysroot_contents: Optional pre-fetched list of files in the sysroot.
            If None, this returns a theoretical check against known core libs.

    Returns a dict with:
        available: list of libs found in sysroot
        missing: list of libs NOT found in sysroot
        sysroot_path: container path to sysroot
        all_satisfied: bool — True if no missing deps
    """
    sysroot_path = get_sysroot_path(architecture)
    if not sysroot_path:
        return {
            "available": [],
            "missing": needed_libs,
            "sysroot_path": None,
            "all_satisfied": False,
        }

    if sysroot_contents is not None:
        # Check against actual sysroot contents
        available = []
        missing = []
        sysroot_basenames = {os.path.basename(f) for f in sysroot_contents}
        for lib in needed_libs:
            # Check exact name and also versioned symlink patterns
            if lib in sysroot_basenames or any(
                s.startswith(lib.split(".so")[0]) for s in sysroot_basenames
            ):
                available.append(lib)
            else:
                missing.append(lib)
    else:
        # Theoretical check: only core libs + dynamic linker are guaranteed
        known_libs = set(CORE_LIBS)
        for linker_names in DYNAMIC_LINKER_NAMES.get(architecture, []):
            known_libs.add(linker_names)

        available = [lib for lib in needed_libs if lib in known_libs]
        missing = [lib for lib in needed_libs if lib not in known_libs]

    return {
        "available": available,
        "missing": missing,
        "sysroot_path": sysroot_path,
        "all_satisfied": len(missing) == 0,
    }


def list_available_sysroots() -> list[dict[str, str]]:
    """List all supported sysroot architectures.

    Returns a list of dicts with architecture and container path.
    This is a static list — actual availability depends on the Docker image.
    """
    return [
        {"architecture": arch, "sysroot_name": name, "path": f"{SYSROOT_BASE_PATH}/{name}"}
        for arch, name in SYSROOT_ARCH_MAP.items()
    ]


def check_sysroot_in_container(container: Any, architecture: str) -> bool:
    """Check if a sysroot exists in a running Docker container.

    Args:
        container: Docker container object (from docker SDK).
        architecture: Canonical architecture name.

    Returns True if the sysroot directory exists and contains a dynamic linker.
    """
    sysroot_path = get_sysroot_path(architecture)
    if not sysroot_path:
        return False

    try:
        exit_code, _ = container.exec_run(
            ["test", "-d", sysroot_path],
            demux=True,
        )
        if exit_code != 0:
            return False

        # Verify dynamic linker exists
        linker_names = DYNAMIC_LINKER_NAMES.get(architecture, [])
        for linker_name in linker_names:
            exit_code, _ = container.exec_run(
                ["test", "-f", f"{sysroot_path}/lib/{linker_name}"],
                demux=True,
            )
            if exit_code == 0:
                return True

        return False
    except Exception as exc:
        logger.debug("Failed to check sysroot in container: %s", exc)
        return False


def list_sysroot_contents(container: Any, architecture: str) -> list[str]:
    """List the shared libraries available in a sysroot inside a container.

    Returns a list of library filenames (basenames).
    """
    sysroot_path = get_sysroot_path(architecture)
    if not sysroot_path:
        return []

    try:
        exit_code, output = container.exec_run(
            ["find", f"{sysroot_path}/lib", "-name", "*.so*", "-type", "f", "-o", "-type", "l"],
            demux=True,
        )
        if exit_code != 0:
            return []
        stdout = output[0] if isinstance(output, tuple) else output
        if not stdout:
            return []
        return [
            os.path.basename(line.strip())
            for line in stdout.decode(errors="replace").splitlines()
            if line.strip()
        ]
    except Exception as exc:
        logger.debug("Failed to list sysroot contents: %s", exc)
        return []
