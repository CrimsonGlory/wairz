"""User-mode QEMU workflow: binfmt_misc + chroot shell + standalone binaries.

Extracted from ``emulation_service.py`` as step 5/7 of the Phase 5 split.

User-mode QEMU runs a single foreign-arch binary directly on the host
kernel's userspace, using the ``qemu-<arch>-static`` translator. Two
flavours are supported:

- **Firmware rootfs mode**: chroot into ``/firmware`` so every path
  resolves naturally (e.g. ``/bin/sh`` → ``/firmware/bin/sh``). The
  qemu-static binary is copied into the chroot so the kernel's
  binfmt_misc registration can execve it.
- **Standalone binary mode**: the user uploaded a lone ELF; QEMU runs
  directly with ``-L <sysroot>`` for library resolution (dynamic) or
  without (static), and no chroot.

Public surface:

- ``ensure_binfmt_misc`` — privileged short-lived container that
  registers the kernel's binfmt_misc entry for a target arch (idempotent,
  flag-file cached).
- ``setup_user_mode_container`` — post-container-create setup: copy
  qemu-static into the firmware rootfs, set up chroot /proc and /dev
  mounts, OR for standalone binaries, write marker files and chmod.
- ``build_user_shell_cmd`` — return the container-exec command list for
  an interactive QEMU user-mode shell (chroot variant or direct-QEMU
  variant).
"""

import logging
import os

import docker

from app.config import Settings
from app.services.emulation_constants import (
    BINFMT_ENTRIES,
    QEMU_USER_BIN_MAP,
    _HOST_ARCH,
)
from app.services.sysroot_service import get_sysroot_path
from app.utils.docker_client import get_docker_client

logger = logging.getLogger(__name__)


def ensure_binfmt_misc(settings: Settings, arch: str) -> None:
    """Register binfmt_misc for the target architecture if not already present.

    Uses a short-lived privileged Docker container to register the QEMU
    user-mode interpreter with the kernel's binfmt_misc subsystem. The
    ``F`` (fix binary) flag causes the kernel to cache the interpreter's
    file descriptor at registration time, so it works transparently inside
    chroots and containers — any execve() of a foreign-arch ELF is handled
    by the kernel without the binary needing to be accessible from the
    process's mount namespace.

    Docker containers see an empty ``/proc/sys/fs/binfmt_misc`` by default
    (it's not the host's mount), so the privileged container must first
    ``mount -t binfmt_misc`` to access the real kernel entries.

    This is a host-level operation (binfmt_misc is kernel-wide) and
    persists until the host reboots or the entry is explicitly removed.
    A flag file in ``/tmp`` avoids re-running the privileged container
    on every emulation start within the same backend container lifetime.

    Failures are logged as warnings but never raised — user-mode
    emulation still works for the initial shell; only child processes
    would fail with "Exec format error".
    """
    # Skip for the host's native architecture — the kernel handles it
    if arch == _HOST_ARCH:
        logger.debug("Skipping binfmt_misc for native architecture: %s", arch)
        return

    entry = BINFMT_ENTRIES.get(arch)
    if not entry:
        logger.debug("No binfmt_misc entry defined for architecture: %s", arch)
        return

    binfmt_name, registration = entry

    # Check local flag file — avoids running a privileged container on
    # every emulation start. The flag persists within this backend
    # container's lifetime (cleared on container restart).
    flag_file = f"/tmp/.binfmt_registered_{binfmt_name}"
    if os.path.exists(flag_file):
        logger.debug("binfmt_misc already registered (cached): %s", binfmt_name)
        return

    logger.info(
        "Registering binfmt_misc for %s (requires privileged container)...",
        binfmt_name,
    )

    client = get_docker_client()
    try:
        # Run a short-lived privileged container that:
        # 1. Mounts binfmt_misc (Docker containers don't see the host's mount)
        # 2. Checks if the entry already exists (idempotent)
        # 3. Registers if needed
        # Must be privileged because Docker's default seccomp profile blocks
        # writes to /proc/sys even with the SYS_ADMIN capability.
        # The F flag causes the kernel to open /usr/bin/qemu-{arch}-static
        # from within this container's filesystem and cache the fd.
        result = client.containers.run(
            image=settings.emulation_image,
            command=[
                "sh", "-c",
                "mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null; "
                f"if [ -f /proc/sys/fs/binfmt_misc/{binfmt_name} ]; then "
                "echo ALREADY_REGISTERED; "
                "else "
                f"echo '{registration}' > /proc/sys/fs/binfmt_misc/register 2>&1 "
                "&& echo REGISTERED || echo FAILED; "
                "fi",
            ],
            remove=True,
            privileged=True,
        )

        output = result.decode("utf-8", errors="replace").strip()

        if "REGISTERED" in output or "ALREADY_REGISTERED" in output:
            # Create flag file so subsequent calls skip the privileged container
            try:
                with open(flag_file, "w") as f:
                    f.write("1")
            except OSError:
                pass  # Non-critical — just means we'll check again next time
            logger.info("binfmt_misc for %s: %s", binfmt_name, output)
        else:
            logger.warning(
                "binfmt_misc registration for %s returned unexpected output: %s",
                binfmt_name,
                output,
            )
    except Exception as exc:
        logger.warning(
            "Could not register binfmt_misc for %s: %s. "
            "Child processes in user-mode emulation may fail with 'Exec format error'. "
            "To fix manually: docker run --rm --privileged multiarch/qemu-user-static --reset -p yes",
            binfmt_name,
            exc,
        )


def setup_user_mode_container(
    container: "docker.models.containers.Container",
    settings: Settings,
    arch: str,
    is_standalone: bool,
    binary_info: dict | None,
) -> None:
    """Prepare a running container for user-mode emulation.

    Handles both flavours:

    - **Standalone binary**: writes marker files at
      ``/tmp/.standalone_mode``, ``/tmp/.standalone_arch``, and
      ``/tmp/.standalone_static`` so ``exec_command`` and the WebSocket
      terminal route to the non-chroot execution path. Resolves a
      sysroot for dynamic binaries. Chmods binary files so they can be
      executed from the bind mount.
    - **Firmware rootfs**: copies ``qemu-<arch>-static`` into
      ``/firmware/`` (so chroot can find it), creates ``/proc``,
      ``/dev``, ``/tmp``, and ``/sys`` inside the firmware tree, and
      bind-mounts host ``/proc`` and ``/dev`` into them.

    Must run AFTER ``fix_firmware_permissions``. Callers should also have
    already called :func:`ensure_binfmt_misc` for the arch.

    The ``binary_info`` parameter carries ``is_static`` and is only
    consulted when ``is_standalone`` is True.
    """
    qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

    if is_standalone:
        # Standalone binary mode: no chroot, use QEMU directly with
        # -L pointing to the sysroot for library resolution.
        is_static = binary_info.get("is_static", False) if binary_info else False
        sysroot_path = get_sysroot_path(arch) if not is_static else None

        # Mark the container as standalone mode via a flag file
        # so exec_command and the WebSocket terminal know to use
        # the non-chroot execution path.
        container.exec_run([
            "sh", "-c",
            "touch /tmp/.standalone_mode && "
            f"echo '{arch}' > /tmp/.standalone_arch && "
            f"echo '{1 if is_static else 0}' > /tmp/.standalone_static"
        ])

        # Make the binary executable (must run as root since firmware
        # files are owned by root from the bind mount)
        container.exec_run(
            ["sh", "-c", "chmod +x /firmware/* 2>/dev/null || true"],
            user="root",
        )

        if sysroot_path and not is_static:
            logger.info(
                "Standalone binary mode (dynamic): arch=%s sysroot=%s",
                arch, sysroot_path,
            )
        else:
            logger.info(
                "Standalone binary mode (static): arch=%s", arch,
            )
    else:
        # Standard firmware rootfs mode: chroot-based
        container.exec_run([
            "sh", "-c",
            f"cp $(which {qemu_bin}) /firmware/{qemu_bin} && "
            f"chmod +x /firmware/{qemu_bin}"
        ])
        # Ensure /proc and /dev exist for binaries that need them
        container.exec_run([
            "sh", "-c",
            "mkdir -p /firmware/proc /firmware/dev /firmware/tmp /firmware/sys && "
            "mount -t proc proc /firmware/proc 2>/dev/null || true && "
            "mount --bind /dev /firmware/dev 2>/dev/null || true"
        ])
        logger.info(
            "User-mode chroot prepared: copied %s into /firmware/",
            qemu_bin,
        )

    # Silence unused-argument warnings — settings is accepted for future
    # consistency with other setup helpers and is not currently read.
    _ = settings


def build_user_shell_cmd(
    arch: str,
    is_standalone: bool = False,
    binary_path: str | None = None,
    is_static: bool = False,
) -> list[str]:
    """Return the command list for an interactive QEMU user-mode shell.

    For firmware rootfs mode: uses chroot so all firmware paths work
    naturally (e.g., ``/bin/foo`` resolves to ``/firmware/bin/foo``).

    For standalone binary mode: uses QEMU directly with ``-L`` for
    sysroot, running the binary without a chroot.
    """
    qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

    if is_standalone and binary_path:
        # For standalone binaries, run QEMU directly (no chroot).
        # The binary is at /firmware/<binary_name>.
        full_binary = f"/firmware/{binary_path.lstrip('/')}"
        qemu_path = f"/usr/bin/{qemu_bin}"

        if is_static:
            return [qemu_path, full_binary]
        else:
            sysroot = get_sysroot_path(arch) or "/opt/sysroots/arm"
            return [qemu_path, "-L", sysroot, full_binary]

    # Standard firmware rootfs mode
    return ["chroot", "/firmware", f"/{qemu_bin}", "/bin/sh"]
