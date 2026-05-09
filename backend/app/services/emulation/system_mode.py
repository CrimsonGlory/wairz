"""System-mode QEMU workflow: full-OS boot via ``qemu-system-<arch>``.

Extracted from ``emulation_service.py`` as step 6/7 of the Phase 5 split.

System-mode emulation runs the firmware's own kernel (or a pre-built
kernel) under ``qemu-system-<arch>``, which provides a full VM with a
serial console. The flow inside the emulation container is:

1. Copy kernel (+ optional initrd) to well-known paths.
2. Inject the wairz init wrapper into ``/firmware`` (handled by
   :mod:`app.services.emulation.sysroot_mount`).
3. Fire ``/opt/scripts/start-system-mode.sh`` which builds an ext4
   rootfs image, decompresses the kernel if needed, then execs QEMU.
4. Wait briefly for QEMU to come up (serial socket appears) and bail
   out early on obvious failures.

Public surface:

- ``setup_system_mode_container`` — kernel/initrd copy + wrapper
  injection + ``start-system-mode.sh`` launch. Returns normally if
  the startup health probe succeeds (or QEMU is still legitimately
  slow but the container is healthy).
- ``await_system_startup`` — the health probe, factored out so tests
  and callers can reuse it.
"""

import asyncio
import logging

import docker
import docker.errors

from app.models.emulation_session import EmulationSession
from app.services.emulation.docker_ops import (
    copy_file_to_container,
    read_container_qemu_log,
)
from app.services.emulation.sysroot_mount import inject_init_wrapper
from app.services.jsonb_normalizers import _normalize_emulation_sessions_port_forwards

logger = logging.getLogger(__name__)


#: Container-internal path where the kernel will be placed.
CONTAINER_KERNEL_PATH = "/tmp/kernel"

#: Container-internal path where an optional initrd will be placed.
CONTAINER_INITRD_PATH = "/tmp/initrd"


async def setup_system_mode_container(
    container: "docker.models.containers.Container",
    session: EmulationSession,
    kernel_backend_path: str | None,
    initrd_backend_path: str | None,
    init_path: str | None,
    pre_init_script: str | None,
    stub_profile: str,
) -> None:
    """Prepare a running container for system-mode QEMU and launch it.

    Caller must have already:

    - Created the container (bind-mounted or tar-copied firmware into
      ``/firmware``).
    - Called :func:`fix_firmware_permissions` + optionally
      :func:`inject_stub_libraries`.
    - Resolved ``kernel_backend_path`` via
      :func:`app.services.emulation.kernel_selection.find_kernel`.

    On failure (no valid kernel), removes the container and raises
    ``ValueError`` — matching the monolith's behaviour.

    On success, starts the QEMU process via exec_run(detach=True) and
    runs the :func:`await_system_startup` health probe. Raises
    ``RuntimeError`` if QEMU fails to come up cleanly.
    """
    if not kernel_backend_path:
        # No valid kernel available — clean up the container
        container.remove(force=True)
        raise ValueError(
            "System-mode emulation requires a valid kernel, but none was found. "
            "The firmware-extracted kernel (if any) failed validation and no "
            "pre-built kernels are available. Upload a QEMU-compatible kernel "
            "via the Kernel Manager."
        )

    copy_file_to_container(container, kernel_backend_path, CONTAINER_KERNEL_PATH)

    # Copy initrd if available
    initrd_arg = ""
    if initrd_backend_path:
        import os
        if os.path.isfile(initrd_backend_path):
            copy_file_to_container(
                container, initrd_backend_path, CONTAINER_INITRD_PATH,
            )
            initrd_arg = CONTAINER_INITRD_PATH
            logger.info("Copied initrd to container: %s", initrd_backend_path)

    # Inject init wrapper into the firmware rootfs. The wrapper
    # auto-mounts proc/sysfs, configures networking, sets LD_PRELOAD
    # based on stub_profile, sources the optional pre-init script,
    # then execs the original init.
    # This must happen before ext4 image creation in start-system-mode.sh.
    wrapper_init = inject_init_wrapper(
        container,
        init_path=init_path,
        pre_init_script=pre_init_script,
        stub_profile=stub_profile,
    )

    pf_str = ""
    pfs = _normalize_emulation_sessions_port_forwards(session.port_forwards)
    if pfs:
        pf_str = ",".join(
            f"{pf['host']}:{pf['guest']}" for pf in pfs
        )
    cmd = [
        "/opt/scripts/start-system-mode.sh",
        session.architecture or "arm",
        "/firmware",
        CONTAINER_KERNEL_PATH,
        pf_str,
        initrd_arg,
        wrapper_init,
    ]
    container.exec_run(cmd, detach=True)

    # Health check: wait briefly to catch early QEMU failures
    await await_system_startup(container)


async def await_system_startup(
    container: "docker.models.containers.Container",
    timeout: int = 30,
) -> None:
    """Wait briefly after QEMU launch and check for early failures.

    The startup script creates an ext4 rootfs image (takes a few seconds),
    decompresses the kernel if needed, then exec's to QEMU. We need to
    account for this preparation phase where the QEMU process doesn't
    exist yet but the startup script is still running.

    Checks each second whether the startup script or QEMU is still alive.
    If both are gone, reads ``/tmp/qemu-system.log`` and raises with the
    log content so the caller can set error status.
    """
    qemu_was_seen = False

    for i in range(timeout):
        await asyncio.sleep(1)

        # Check if the container itself is still running
        try:
            container.reload()
            if container.status not in ("running", "created"):
                log = read_container_qemu_log(container, quiet=True)
                raise RuntimeError(
                    f"Emulation container exited during startup.\n\n"
                    f"--- QEMU log ---\n{log}"
                )
        except docker.errors.NotFound:
            raise RuntimeError("Emulation container disappeared during startup")

        # Check if either the startup script or QEMU process is alive.
        # During ext4 creation, only the script runs. After exec, only
        # QEMU runs. If neither is found, something failed.
        try:
            result = container.exec_run(
                ["sh", "-c",
                 "pgrep -f 'qemu-system' >/dev/null 2>&1 && echo qemu || "
                 "(pgrep -f 'start-system-mode' >/dev/null 2>&1 && echo script || echo none)"],
            )
            output = result.output.decode("utf-8", errors="replace").strip()

            if output == "qemu":
                qemu_was_seen = True
            elif output == "none":
                if qemu_was_seen:
                    # QEMU was running but now it's gone — it crashed
                    log = read_container_qemu_log(container)
                    raise RuntimeError(
                        f"QEMU process exited during startup.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                elif i > 15:
                    # Neither script nor QEMU found after 15s — something is wrong
                    log = read_container_qemu_log(container)
                    raise RuntimeError(
                        f"Neither startup script nor QEMU found after {i}s.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                # else: still early, script may not have started yet
        except docker.errors.APIError:
            pass  # Container may be in a transient state

        # Check if the serial socket appeared (means QEMU is up and listening)
        try:
            result = container.exec_run(["test", "-S", "/tmp/qemu-serial.sock"])
            if result.exit_code == 0:
                logger.info("QEMU serial socket ready after %ds", i + 1)
                return  # QEMU is healthy
        except docker.errors.APIError:
            pass

    # Timeout without socket, but QEMU is still running — that's OK,
    # it may just be slow (ext4 creation, kernel boot). Let it continue.
    logger.info(
        "QEMU still starting after %ds (no serial socket yet), "
        "continuing in background",
        timeout,
    )
