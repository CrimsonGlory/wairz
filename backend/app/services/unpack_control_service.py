"""Manual unpack-control service.

Gives a researcher (or the AI agent acting like one) authoritative control over
the firmware fields the rest of Wairz keys off — architecture, the emulation
rootfs (``extracted_path``), and the kernel image — plus an on-demand
re-detection pass. These exist because some firmware genuinely can't be
auto-unpacked correctly:

  - App-only OTAs (e.g. Wyze Chime Pro) ship a kernel + ``/app`` partition but
    no base rootfs — the busybox/init root lives on a separate flash partition
    that isn't in the image. There is nothing for the auto-unpacker to
    "reconstruct", so the agent must carve/assemble a workable root in the
    sandbox and *designate* it.
  - Odd layouts where ELF/uImage detection still misses the architecture.

The carving sandbox (``run_shell``) is where the agent builds things — its
output lands at ``/_carved/...`` and ``/extracted`` is writable for in-place
fixes. This service is how those manual results become authoritative:

    set_architecture  → firmware.architecture / .endianness   (unblocks emu gate)
    set_rootfs        → firmware.extracted_path                (emulation/analysis root)
    set_kernel        → firmware.kernel_path                   (emulation kernel)
    redetect          → re-run detection over the current extraction

All path inputs are virtual firmware paths (``/_carved/myroot``, ``/rootfs``,
``/squashfs-root-0`` …); they are resolved through the same ``FileService``
layer the read tools use and then re-validated to live within the firmware's
own storage tree, so nothing can point Wairz at a path outside the sandbox.
"""

from __future__ import annotations

import os

from app.models.firmware import Firmware
from app.services.file_service import FileService

# Architectures we accept for a manual override. Keys mirror the friendly
# names the unpacker emits and the emulation layer's ARCH_ALIASES targets.
_VALID_ARCHES = frozenset({
    "arm", "aarch64", "mips", "mipsel", "mips64", "x86", "x86_64",
    "ppc", "ppc64", "sh", "sparc", "sparc64", "riscv",
})

# Common aliases an agent/user might pass, normalised to the canonical name.
_ARCH_ALIASES = {
    "arm32": "arm", "armhf": "arm", "armel": "arm", "armv7": "arm",
    "arm64": "aarch64", "armv8": "aarch64",
    "mipsbe": "mips", "mipseb": "mips",
    "mipsle": "mipsel",
    "i386": "x86", "i686": "x86", "x86-64": "x86_64", "amd64": "x86_64",
    "powerpc": "ppc", "powerpc64": "ppc64",
    "risc-v": "riscv", "riscv64": "riscv", "riscv32": "riscv",
}

_VALID_ENDIAN = frozenset({"little", "big"})


class UnpackControlError(ValueError):
    """Raised for invalid manual unpack-control input (bad arch, path, etc.)."""


def _firmware_root(firmware: Firmware) -> str:
    """The on-disk directory that bounds everything for this firmware.

    Every manual path must resolve to somewhere under here — the firmware's
    own ``projects/<pid>/firmware/<fid>/`` directory — so a manual override can
    never point Wairz at another project's data or the host filesystem.
    """
    if not firmware.storage_path:
        raise UnpackControlError("firmware has no storage_path on disk")
    return os.path.realpath(os.path.dirname(firmware.storage_path))


def _carved_path(firmware: Firmware) -> str | None:
    if not firmware.storage_path:
        return None
    return os.path.join(os.path.dirname(firmware.storage_path), "carved")


def _file_service(firmware: Firmware) -> FileService:
    return FileService(
        firmware.extracted_path or "",
        extraction_dir=firmware.extraction_dir,
        carved_path=_carved_path(firmware),
        firmware_path=firmware.storage_path,
    )


def _resolve_within_tree(firmware: Firmware, virtual_path: str) -> str:
    """Resolve a virtual firmware path to a real path inside the firmware tree.

    Combines the FileService virtual-path resolution (which already enforces
    per-namespace sandboxing) with a final realpath prefix check against the
    firmware's own storage directory as defence in depth.
    """
    if not isinstance(virtual_path, str) or not virtual_path.strip():
        raise UnpackControlError("path is required")

    try:
        real = os.path.realpath(_file_service(firmware)._resolve(virtual_path))
    except Exception as exc:  # PathTraversalError, etc.
        raise UnpackControlError(f"could not resolve path '{virtual_path}': {exc}")

    root = _firmware_root(firmware)
    if real != root and not real.startswith(root + os.sep):
        raise UnpackControlError(
            f"path '{virtual_path}' resolves outside the firmware's storage "
            f"tree and was rejected"
        )
    return real


class UnpackControlService:
    """Authoritative, path-validated mutations of firmware unpack metadata."""

    def __init__(self, db) -> None:
        self.db = db

    # ── architecture ────────────────────────────────────────────────────

    async def set_architecture(
        self,
        firmware: Firmware,
        architecture: str,
        endianness: str | None = None,
    ) -> Firmware:
        if not isinstance(architecture, str) or not architecture.strip():
            raise UnpackControlError("architecture is required")
        arch = architecture.strip().lower()
        arch = _ARCH_ALIASES.get(arch, arch)
        if arch not in _VALID_ARCHES:
            raise UnpackControlError(
                f"unsupported architecture '{architecture}'. Valid values: "
                f"{', '.join(sorted(_VALID_ARCHES))}"
            )

        endian = endianness
        if endian is not None:
            endian = endian.strip().lower()
            if endian not in _VALID_ENDIAN:
                raise UnpackControlError(
                    "endianness must be 'little' or 'big'"
                )
        else:
            # mipsel is intrinsically little; otherwise keep any existing value.
            if arch == "mipsel":
                endian = "little"
            else:
                endian = firmware.endianness

        firmware.architecture = arch
        firmware.endianness = endian
        await self.db.flush()
        return firmware

    # ── rootfs ──────────────────────────────────────────────────────────

    async def set_rootfs(self, firmware: Firmware, path: str) -> Firmware:
        real = _resolve_within_tree(firmware, path)
        if not os.path.isdir(real):
            raise UnpackControlError(
                f"path '{path}' is not a directory; the rootfs must be a "
                f"directory containing the filesystem root"
            )
        firmware.extracted_path = real
        # The chosen directory IS the root now, so drop the binwalk-output
        # virtual top level — /rootfs maps straight to this dir. (A stale
        # extraction_dir would make the virtual filesystem surface the wrong
        # tree.)
        firmware.extraction_dir = None
        await self.db.flush()
        return firmware

    # ── kernel ──────────────────────────────────────────────────────────

    async def set_kernel(self, firmware: Firmware, path: str) -> Firmware:
        real = _resolve_within_tree(firmware, path)
        if not os.path.isfile(real):
            raise UnpackControlError(
                f"path '{path}' is not a file; the kernel must be a single "
                f"image file"
            )
        firmware.kernel_path = real
        await self.db.flush()
        return firmware

    # ── re-detect ───────────────────────────────────────────────────────

    async def redetect(
        self,
        firmware: Firmware,
        targets: list[str] | None = None,
    ) -> tuple[Firmware, dict[str, str | None]]:
        """Re-run detection over the firmware's existing extraction.

        ``targets`` selects which fields to refresh — any of ``rootfs``,
        ``arch``, ``kernel``; defaults to all three. Returns the firmware and a
        small report of what each pass found so callers can surface it.
        """
        from app.workers.unpack import (
            detect_architecture,
            detect_architecture_from_uboot,
            detect_kernel,
            find_filesystem_root,
        )

        wanted = set(targets) if targets else {"rootfs", "arch", "kernel"}
        invalid = wanted - {"rootfs", "arch", "kernel"}
        if invalid:
            raise UnpackControlError(
                f"unknown redetect target(s): {', '.join(sorted(invalid))}. "
                f"Valid: rootfs, arch, kernel"
            )

        # Locate the extraction directory: prefer the recorded one, else the
        # canonical extracted/ dir next to the blob.
        extraction_dir = firmware.extraction_dir
        if not extraction_dir or not os.path.isdir(extraction_dir):
            if firmware.storage_path:
                candidate = os.path.join(
                    os.path.dirname(firmware.storage_path), "extracted"
                )
                extraction_dir = candidate if os.path.isdir(candidate) else None
        if not extraction_dir or not os.path.isdir(extraction_dir):
            raise UnpackControlError(
                "no extraction directory found to re-detect from; (re-)unpack "
                "the firmware first or carve a rootfs and use set_rootfs"
            )

        report: dict[str, str | None] = {}

        fs_root = find_filesystem_root(extraction_dir)
        if "rootfs" in wanted:
            if fs_root:
                firmware.extracted_path = os.path.realpath(fs_root)
                fs_root_real = firmware.extracted_path
                extraction_real = os.path.realpath(extraction_dir)
                firmware.extraction_dir = (
                    extraction_real if fs_root_real != extraction_real else None
                )
                report["rootfs"] = firmware.extracted_path
            else:
                report["rootfs"] = None

        # Use the freshly-found (or existing) rootfs as the arch scan target.
        arch_root = fs_root or firmware.extracted_path
        if "arch" in wanted:
            arch = endian = None
            if arch_root and os.path.isdir(arch_root):
                arch, endian = detect_architecture(arch_root)
            if arch is None and firmware.storage_path:
                arch, endian = detect_architecture_from_uboot(firmware.storage_path)
            if arch is not None:
                firmware.architecture = arch
                firmware.endianness = endian
            report["arch"] = (
                f"{arch}/{endian}" if arch else None
            )

        if "kernel" in wanted:
            kernel = detect_kernel(extraction_dir, fs_root or firmware.extracted_path)
            if kernel:
                firmware.kernel_path = os.path.realpath(kernel)
            report["kernel"] = firmware.kernel_path if kernel else None

        await self.db.flush()
        return firmware, report
