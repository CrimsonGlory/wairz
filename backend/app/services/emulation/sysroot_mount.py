"""Firmware rootfs preparation — wairz init wrapper generation + injection.

Extracted from ``emulation_service.py`` as step 4/7 of the Phase 5 split.

The wairz init wrapper is a shell script injected into the firmware
rootfs that runs as PID 1 in system-mode emulation. It performs the
shared setup that every firmware needs (mount proc/sysfs/devtmpfs,
configure QEMU user-net interface, set ``LD_PRELOAD`` for stub
libraries) before handing off to the firmware's native init or an
interactive shell.

The module name "sysroot_mount" follows the Phase 5 intake spec; the
actual operations target the firmware root that becomes the ext4 image
mounted by the guest kernel.

Public surface:

- ``generate_init_wrapper`` — pure-string builder; renders the template
  at ``app/templates/wairz_init_wrapper.sh`` with three substitutions.
- ``inject_init_wrapper`` — writes ``/firmware/wairz_init.sh`` (and
  optionally ``/firmware/wairz_pre_init.sh``) into a running container.
  Returns the init_path to pass to ``start-system-mode.sh``.
"""

import logging
import os

import docker

from app.services.emulation.docker_ops import put_file_in_container
from app.utils.log_sanitize import sanitize_for_log

logger = logging.getLogger(__name__)

# Template location: backend/app/templates/wairz_init_wrapper.sh
# __file__ = backend/app/services/emulation/sysroot_mount.py
# dirname (x3) walks up: emulation/ → services/ → app/
_TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "templates", "wairz_init_wrapper.sh",
)

# Locations searched (in order) for a usable POSIX shell inside the
# firmware rootfs when /bin/sh is missing.
SHELL_CANDIDATE_PATHS: tuple[str, ...] = (
    "/bin/sh",
    "/bin/ash",
    "/bin/dash",
    "/bin/bash",
    "/sbin/sh",
    "/usr/bin/sh",
    "/usr/bin/ash",
    "/usr/bin/bash",
    "/bin/busybox",
    "/sbin/busybox",
    "/usr/bin/busybox",
    "/usr/sbin/busybox",
    "/bin/busybox/bin/sh",
    "/bin/busybox/bin/ash",
    "/bin/busybox/bin/busybox",
)


def detect_shell_in_firmware(
    container: "docker.models.containers.Container",
) -> str | None:
    """Find a usable shell inside the firmware rootfs.

    Returns the absolute path of the first matching shell (regular file or
    symlink whose target resolves) under /firmware, with the /firmware prefix
    stripped (i.e., the path the kernel will see after switch_root). Returns
    None if no candidate exists.
    """
    tests = " ".join(
        f'if [ -e /firmware{p} ] && [ ! -d /firmware{p} ]; then '
        f'echo "{p}"; exit 0; fi;'
        for p in SHELL_CANDIDATE_PATHS
    )
    result = container.exec_run(["sh", "-c", tests])
    path = result.output.decode("utf-8", errors="replace").strip()
    return path or None


def ensure_bin_sh(
    container: "docker.models.containers.Container",
    shell_path: str,
) -> None:
    """Make /bin/sh resolve to `shell_path` inside the firmware rootfs.

    If /firmware/bin/sh already exists (symlink or file), do nothing.
    Otherwise create a relative symlink so firmware scripts and the wrapper
    shebang resolve on rootfs layouts that lack /bin/sh.
    """
    if shell_path == "/bin/sh":
        return
    rel_target = os.path.relpath(shell_path, "/bin")
    container.exec_run([
        "sh", "-c",
        "mkdir -p /firmware/bin && "
        "if [ ! -e /firmware/bin/sh ]; then "
        f"ln -s '{rel_target}' /firmware/bin/sh; fi",
    ])


def generate_init_wrapper(
    original_init: str | None = None,
    pre_init_script: str | None = None,
    stub_profile: str = "none",
    shell_path: str = "/bin/sh",
) -> str:
    """Generate a wairz init wrapper script for system-mode emulation.

    The wrapper runs before the firmware's own init and handles:

    - Mounting proc, sysfs, devtmpfs, tmpfs
    - Configuring networking (QEMU user-mode always uses 10.0.2.0/24)
    - Setting ``LD_PRELOAD`` for stub libraries (based on stub_profile)
    - Sourcing an optional pre-init script for firmware-specific setup
    - Executing the firmware's original init or an interactive shell

    ``shell_path`` is the absolute path of the interpreter to put in the
    shebang. Defaults to /bin/sh; callers should pass the result of
    ``detect_shell_in_firmware`` so the wrapper still runs on rootfs
    layouts that lack /bin/sh.
    """
    if original_init:
        exec_line = f'exec {original_init}'
    else:
        exec_line = (
            '# Auto-detect init\n'
            'for candidate in /sbin/init /etc/preinit /sbin/procd /init /linuxrc; do\n'
            '    if [ -x "$candidate" ] || [ -L "$candidate" ]; then\n'
            '        exec "$candidate"\n'
            '    fi\n'
            'done\n'
            '# Fallback to shell\n'
            'echo "[wairz] No init found, dropping to shell"\n'
            'exec /bin/sh'
        )

    pre_init_block = ""
    if pre_init_script:
        pre_init_block = (
            '\n# --- User pre-init script ---\n'
            'if [ -f /wairz_pre_init.sh ]; then\n'
            '    echo "[wairz] Running pre-init script..."\n'
            '    chmod +x /wairz_pre_init.sh\n'
            '    . /wairz_pre_init.sh\n'
            '    echo "[wairz] Pre-init script finished (exit=$?)"\n'
            'fi'
        )

    stub_block = ""
    if stub_profile != "none":
        stub_block = (
            '# Export LD_PRELOAD for stub libraries based on stub_profile setting.\n'
            '# This ensures ALL processes started by the firmware\'s init inherit the stubs.\n'
            '# /etc/ld.so.preload is NOT supported by musl libc -- only the env var works.\n'
            'STUBS=""\n'
            'for f in /opt/stubs/stubs_*.so; do\n'
            '    [ -f "$f" ] && STUBS="$STUBS $f"\n'
            'done\n'
            'STUBS=$(echo "$STUBS" | sed \'s/^ //\')\n'
            'if [ -n "$STUBS" ]; then\n'
            '    export LD_PRELOAD="$STUBS"\n'
            '    echo "[wairz] LD_PRELOAD set: $LD_PRELOAD"\n'
            'else\n'
            '    echo "[wairz] No stub libraries found in /opt/stubs/"\n'
            'fi'
        )

    with open(_TEMPLATE_PATH) as f:
        template = f.read()

    return (
        template
        .replace("@@SHEBANG@@", f"#!{shell_path}")
        .replace("@@PRE_INIT_BLOCK@@", pre_init_block)
        .replace("@@STUB_BLOCK@@", stub_block)
        .replace("@@EXEC_LINE@@", exec_line)
    )


def inject_init_wrapper(
    container: "docker.models.containers.Container",
    init_path: str | None = None,
    pre_init_script: str | None = None,
    stub_profile: str = "none",
) -> str:
    """Inject the wairz init wrapper into the firmware rootfs.

    Writes ``/firmware/wairz_init.sh`` (and optionally
    ``/firmware/wairz_pre_init.sh``) into the container's firmware
    directory. These files will be included in the ext4 rootfs image
    created by ``start-system-mode.sh``.

    Returns the init_path to pass to ``start-system-mode.sh``
    (``"/wairz_init.sh"``).
    """
    # Pick a shebang interpreter that actually exists in the rootfs.
    # Many split-MTD firmwares (camera /app partitions, etc.) lack /bin/sh —
    # the kernel reports the resulting exec failure as if the wrapper itself
    # were missing, panicking with "switch_root: can't execute
    # '/wairz_init.sh': No such file or directory".
    shell_path = detect_shell_in_firmware(container)
    if not shell_path:
        raise RuntimeError(
            "No usable shell found in firmware rootfs. The init wrapper "
            "needs an interpreter for its shebang, but none of the "
            "standard locations (/bin/sh, /bin/busybox, /bin/ash, ...) "
            "exist under /firmware. This rootfs is likely incomplete "
            "(e.g., a /app partition mounted standalone without the "
            "device's separate rootfs partition). Provide a complete "
            "rootfs or use user-mode emulation."
        )
    if shell_path != "/bin/sh":
        ensure_bin_sh(container, shell_path)
        logger.info(
            "Firmware lacks /bin/sh; using %s for wrapper shebang and "
            "symlinked /bin/sh -> %s",
            shell_path, shell_path,
        )

    wrapper = generate_init_wrapper(
        init_path,
        pre_init_script,
        stub_profile=stub_profile,
        shell_path=shell_path,
    )

    # Write scripts into the container using put_archive (avoids
    # heredoc/escaping issues)
    put_file_in_container(container, "/firmware/wairz_init.sh", wrapper)

    # Write the pre-init script if provided
    if pre_init_script:
        put_file_in_container(
            container, "/firmware/wairz_pre_init.sh", pre_init_script,
        )
        logger.info("Injected pre-init script (%d bytes)", len(pre_init_script))

    logger.info(
        "Injected init wrapper (original_init=%s, has_pre_init=%s, shell=%s)",
        sanitize_for_log(init_path or "auto-detect"),
        bool(pre_init_script),
        shell_path,
    )
    return "/wairz_init.sh"
