"""EmulationService — public API orchestrator for QEMU firmware emulation.

Step 7/7 of the Phase 5 split: the monolithic ``emulation_service.py``
module is retired in favour of this subpackage. ``EmulationService``
keeps the same public method surface it had before — all callers that
imported ``from app.services.emulation_service import EmulationService``
are migrated to ``from app.services.emulation import EmulationService``
in the same commit.

The heavy lifting moves to topic modules:

- :mod:`app.services.emulation.docker_ops` — Docker helpers (tar
  streaming, symlink repair, host-path translation, stub injection,
  log retrieval).
- :mod:`app.services.emulation.kernel_selection` — arch-to-kernel
  matching + initrd discovery.
- :mod:`app.services.emulation.sysroot_mount` — wairz init-wrapper
  generation + injection into the firmware rootfs.
- :mod:`app.services.emulation.user_mode` — binfmt_misc + chroot
  shell + standalone-binary setup + command builder.
- :mod:`app.services.emulation.system_mode` — kernel/initrd copy,
  QEMU launch, startup health probe.
"""

import logging
import os
import shlex
from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.services.emulation.docker_ops import (
    copy_dir_to_container,
    fix_firmware_permissions,
    inject_stub_libraries,
    read_container_qemu_log,
    resolve_host_path,
)
from app.services.emulation.kernel_selection import find_initrd, find_kernel
from app.services.emulation.system_mode import setup_system_mode_container
from app.services.emulation.user_mode import (
    build_user_shell_cmd as _build_user_shell_cmd,
)
from app.services.emulation.user_mode import (
    ensure_binfmt_misc,
    setup_user_mode_container,
)
from app.services.emulation_constants import (
    _ANSI_RE,
    _MARKER_RE,
    ARCH_ALIASES,
    QEMU_USER_BIN_MAP,
)
from app.services.emulation_preset_service import EmulationPresetService
from app.services.qiling_service import get_rootfs_path, run_binary_async
from app.services.sysroot_service import get_sysroot_path
from app.utils.docker_client import get_docker_client
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)


class EmulationService:
    """Manages QEMU emulation session lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    # ── Arch / session counting ──

    def _normalize_arch(self, arch: str | None) -> str | None:
        if not arch:
            return None
        return ARCH_ALIASES.get(arch, arch.lower())

    async def _count_active_sessions(self, project_id: UUID) -> int:
        # "pending" and "booting" are the 202-polling intermediate
        # statuses; "starting" and "running" are pre-202 legacy values
        # kept for back-compat; "ready" is the new terminal-attachable
        # status (replacement for "running"). All five count as
        # consuming a concurrency slot.
        result = await self.db.scalar(
            select(func.count(EmulationSession.id)).where(
                EmulationSession.project_id == project_id,
                EmulationSession.status.in_([
                    "created", "pending", "booting",
                    "starting", "running", "ready",
                ]),
            )
        )
        return result or 0

    # ── Session lifecycle ──

    async def create_pending_session(
        self,
        firmware: Firmware,
        mode: str,
        binary_path: str | None = None,
        arguments: str | None = None,
        port_forwards: list[dict] | None = None,
    ) -> EmulationSession:
        """Validate start-request inputs and create a ``pending`` DB row.

        Fast path — runs synchronously inside the request handler. Does
        NO Docker work, NO subprocesses, NO filesystem reads beyond
        what's needed to validate ``binary_path``. Returns in a few
        milliseconds.

        The returned row has ``status="pending"``. Caller is expected to
        schedule :meth:`spawn_session_background` to do the heavy
        lifting. The background task transitions
        ``pending → booting → ready`` (or ``error`` / ``stopped`` for
        Qiling).

        Raises ``ValueError`` for invalid inputs — the router translates
        this into a 400.
        """
        if mode not in ("user", "system"):
            raise ValueError("mode must be 'user' or 'system'")

        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        if mode == "user" and not binary_path:
            raise ValueError("binary_path is required for user-mode emulation")

        # Validate binary_path against extracted root
        if binary_path:
            validate_path(firmware.extracted_path, binary_path)

        # Check concurrent session limit
        active = await self._count_active_sessions(firmware.project_id)
        if active >= self._settings.emulation_max_sessions:
            raise ValueError(
                f"Maximum concurrent sessions ({self._settings.emulation_max_sessions}) reached. "
                "Stop an existing session first."
            )

        arch = self._normalize_arch(firmware.architecture)
        if not arch:
            raise ValueError(
                "Cannot determine firmware architecture. "
                "Architecture detection must complete before emulation."
            )

        session = EmulationSession(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            mode=mode,
            status="pending",
            binary_path=binary_path,
            arguments=arguments,
            architecture=arch,
            port_forwards=port_forwards or [],
        )
        self.db.add(session)
        await self.db.flush()
        return session

    async def spawn_session_background(
        self,
        session_id: UUID,
        firmware_id: UUID,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> None:
        """Heavy-lifting phase of session start. Runs detached.

        Reads the ``pending`` session from its OWN AsyncSession (NOT
        ``self.db`` — the request-scoped session is already closed by
        the time this runs) and transitions its status:

        - ``pending → booting`` once the Docker container is created
          and the arch-specific setup has started.
        - ``booting → ready`` once the health check succeeds
          (user-mode: the /firmware chroot or /tmp/.standalone_mode
          marker is observable; system-mode: the QEMU serial socket
          ``/tmp/qemu-serial.sock`` appears, per
          :func:`system_mode.await_system_startup`).
        - ``booting → error`` on any exception, with the message
          stored in ``error_message``.

        For Qiling (PE/Mach-O binaries, user-mode only), the terminal
        attachment codepath is not used — the background task runs the
        Qiling emulation inline and transitions to ``stopped`` when
        done, matching the pre-202 behaviour.

        This method is designed to be called via ``asyncio.create_task``
        from the router. The caller should NOT await it — the router
        has already returned 202 by that point.
        """
        async with async_session_factory() as db:
            # Re-load the session + firmware using this task's session
            session = await db.scalar(
                select(EmulationSession).where(
                    EmulationSession.id == session_id,
                )
            )
            firmware = await db.scalar(
                select(Firmware).where(Firmware.id == firmware_id)
            )
            if session is None or firmware is None:
                logger.error(
                    "spawn_session_background: session=%s firmware=%s "
                    "not found — cannot spawn",
                    session_id,
                    firmware_id,
                )
                return

            # Detect standalone binary mode: binary_info is only set for
            # standalone binaries (direct ELF/PE upload or extraction
            # fallback), never for firmware with a proper rootfs.
            is_standalone = firmware.binary_info is not None

            # Qiling path — PE/Mach-O run in-process; no Docker, no
            # terminal. Runs to completion inline because Qiling is
            # batch-only; the session ends in status=stopped.
            binary_format = (firmware.binary_info or {}).get("format")
            use_qiling = (
                is_standalone
                and binary_format in ("pe", "macho")
                and session.mode == "user"
            )

            if use_qiling:
                await self._spawn_qiling(
                    db, session, firmware, binary_format,
                )
                return

            # QEMU path (user-mode ELF + system-mode).
            try:
                session.status = "booting"
                session.started_at = datetime.now(timezone.utc)
                await db.commit()

                container_id = await self._start_container(
                    session=session,
                    extracted_path=firmware.extracted_path,
                    kernel_name=kernel_name,
                    firmware_kernel_path=firmware.kernel_path,
                    init_path=init_path,
                    pre_init_script=pre_init_script,
                    stub_profile=stub_profile,
                    is_standalone=is_standalone,
                    binary_info=firmware.binary_info,
                )
                session.container_id = container_id

                # Health check: verify the session is actually bootable
                # before flipping to "ready". System mode's
                # await_system_startup (called inside
                # setup_system_mode_container) already probes the
                # serial socket — if we got here without an exception,
                # system mode is ready. User mode: check the standalone
                # marker file or /firmware directory is readable.
                await self._await_ready(session, container_id)

                session.status = "ready"
                await db.commit()
            except Exception as exc:
                logger.exception("Failed to spawn emulation session %s", session_id)
                session.status = "error"
                session.error_message = str(exc)
                session.stopped_at = datetime.now(timezone.utc)
                try:
                    await db.commit()
                except Exception:
                    await db.rollback()

    async def _spawn_qiling(
        self,
        db: AsyncSession,
        session: EmulationSession,
        firmware: Firmware,
        binary_format: str,
    ) -> None:
        """Run the Qiling in-process emulation and finalise the session.

        Split out for readability. Only called from
        :meth:`spawn_session_background`.
        """
        try:
            abs_binary = os.path.join(
                firmware.extracted_path,
                (session.binary_path or "").lstrip("/"),
            )
            args = shlex.split(session.arguments) if session.arguments else None
            rootfs = get_rootfs_path(binary_format, session.architecture)

            session.mode = "qiling"
            session.status = "booting"
            session.started_at = datetime.now(timezone.utc)
            await db.commit()

            qresult = await run_binary_async(
                binary_path=abs_binary,
                rootfs=rootfs,
                args=args,
                timeout=60,
                trace_syscalls=True,
                binary_format=binary_format,
                architecture=session.architecture,
            )

            output_parts = []
            if qresult.stdout:
                output_parts.append(f"=== STDOUT ===\n{qresult.stdout}")
            if qresult.stderr:
                output_parts.append(f"=== STDERR ===\n{qresult.stderr}")
            if qresult.error:
                output_parts.append(f"=== ERROR ===\n{qresult.error}")
            if qresult.memory_errors:
                output_parts.append(
                    "=== MEMORY ERRORS ===\n" +
                    "\n".join(qresult.memory_errors)
                )
            if qresult.syscall_trace:
                trace = qresult.syscall_trace[:100]
                output_parts.append(
                    f"=== SYSCALL TRACE ({qresult.syscall_count} total) ===\n" +
                    "\n".join(trace)
                )

            session.logs = "\n\n".join(output_parts) if output_parts else "(no output)"
            session.error_message = qresult.error
            session.status = "stopped"
            session.stopped_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as exc:
            logger.exception("Qiling emulation failed")
            session.status = "error"
            session.error_message = str(exc)
            session.stopped_at = datetime.now(timezone.utc)
            try:
                await db.commit()
            except Exception:
                await db.rollback()

    async def _await_ready(
        self,
        session: EmulationSession,
        container_id: str,
    ) -> None:
        """Gate the ``booting → ready`` transition on a real health probe.

        System mode: the inner ``await_system_startup`` check inside
        ``setup_system_mode_container`` already waited for the QEMU
        serial socket to appear; if we returned from ``_start_container``
        without raising, the container is usable. We re-verify the
        container itself is still up.

        User mode: standalone-binary sessions expose a marker file at
        ``/tmp/.standalone_mode``; chroot sessions should have
        ``/firmware/`` readable. Both are fast exec_run probes.

        Raises ``RuntimeError`` if the probe fails — the caller flips
        the session to ``error``.
        """
        import docker
        import docker.errors

        client = get_docker_client()
        try:
            container = client.containers.get(container_id)
        except docker.errors.NotFound:
            raise RuntimeError(
                "Emulation container disappeared before readiness probe",
            )

        container.reload()
        if container.status not in ("running", "created"):
            raise RuntimeError(
                f"Emulation container in unexpected state: {container.status}",
            )

        if session.mode == "user":
            # Either standalone marker OR chroot /firmware dir must be
            # probe-able. The standalone_check runs quickly (single
            # docker API call).
            standalone_probe = container.exec_run(
                ["test", "-f", "/tmp/.standalone_mode"], demux=True,
            )
            chroot_probe = container.exec_run(
                ["test", "-d", "/firmware"], demux=True,
            )
            if (
                standalone_probe.exit_code != 0
                and chroot_probe.exit_code != 0
            ):
                raise RuntimeError(
                    "User-mode container has neither /tmp/.standalone_mode "
                    "nor /firmware — setup did not complete successfully."
                )
        elif session.mode == "system":
            # setup_system_mode_container.await_system_startup already
            # probed /tmp/qemu-serial.sock. No further work needed.
            pass

    async def start_session(
        self,
        firmware: Firmware,
        mode: str,
        binary_path: str | None = None,
        arguments: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationSession:
        """Synchronous full start (back-compat for callers outside the router).

        Exists for MCP tools and tests that want a one-shot
        "return when ready" call. The REST router no longer uses this —
        it calls :meth:`create_pending_session` and schedules
        :meth:`spawn_session_background` to return 202 immediately.

        Behaviour is identical to the pre-202 flow: creates the row,
        boots the container, flips to ``ready`` (was ``running``) on
        success or ``error`` on failure, then returns the final row.
        """
        session = await self.create_pending_session(
            firmware=firmware,
            mode=mode,
            binary_path=binary_path,
            arguments=arguments,
            port_forwards=port_forwards,
        )

        # Run the background work synchronously. We can't just call
        # spawn_session_background directly because that opens its own
        # AsyncSession; instead, inline the work against self.db to
        # preserve the old single-session semantics.
        is_standalone = firmware.binary_info is not None
        binary_format = (firmware.binary_info or {}).get("format")
        use_qiling = (
            is_standalone
            and binary_format in ("pe", "macho")
            and mode == "user"
        )

        if use_qiling:
            await self._spawn_qiling(self.db, session, firmware, binary_format)
            return session

        try:
            session.status = "booting"
            session.started_at = datetime.now(timezone.utc)
            await self.db.flush()

            container_id = await self._start_container(
                session=session,
                extracted_path=firmware.extracted_path,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware.kernel_path,
                init_path=init_path,
                pre_init_script=pre_init_script,
                stub_profile=stub_profile,
                is_standalone=is_standalone,
                binary_info=firmware.binary_info,
            )
            session.container_id = container_id
            await self._await_ready(session, container_id)
            session.status = "ready"
        except Exception as exc:
            logger.exception("Failed to start emulation container")
            session.status = "error"
            session.error_message = str(exc)

        await self.db.flush()
        return session

    async def _start_container(
        self,
        session: EmulationSession,
        extracted_path: str,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
        is_standalone: bool = False,
        binary_info: dict | None = None,
    ) -> str:
        """Spawn a Docker container for this emulation session.

        Thin orchestrator: delegates per-mode setup to
        :mod:`app.services.emulation.user_mode` or
        :mod:`app.services.emulation.system_mode`. Handles the shared
        container-create step (volume vs docker-cp, port bindings,
        common labels).
        """
        client = get_docker_client()
        settings = self._settings

        # Resolve the extracted path to a host path for Docker volume
        # mounts. If None, the data is baked into the backend image
        # (not on a volume), so we'll use docker cp instead of a bind
        # mount.
        real_path = os.path.realpath(extracted_path)
        host_path = resolve_host_path(real_path)
        use_docker_cp = host_path is None

        volumes: dict[str, dict[str, str]] = {}
        if not use_docker_cp:
            volumes[host_path] = {"bind": "/firmware", "mode": "rw"}

        # Build port bindings for system mode
        port_bindings: dict[str, list[dict[str, str]]] = {}
        if session.port_forwards:
            for pf in session.port_forwards:
                host_ = pf.get("host", 0)
                if host_:
                    # QEMU listens on the host port INSIDE the container
                    # (hostfwd=tcp::HOST_PORT-:GUEST_PORT), so Docker
                    # must map the same port on both sides:
                    # host:PORT → container:PORT
                    port_bindings[f"{host_}/tcp"] = [{"HostPort": str(host_)}]

        # Resolve kernel path for system mode (backend-side path)
        kernel_backend_path = None
        initrd_backend_path = None
        if session.mode == "system":
            kernel_backend_path = find_kernel(
                settings,
                session.architecture,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware_kernel_path,
            )
            # Look for companion initrd
            initrd_backend_path = find_initrd(
                kernel_backend_path, kernel_name,
            )
            if initrd_backend_path:
                logger.info("Found initrd: %s", initrd_backend_path)

        common_labels = {
            "wairz.session_id": str(session.id),
            "wairz.project_id": str(session.project_id),
            "wairz.mode": session.mode,
        }

        if use_docker_cp:
            # Create container with "sleep infinity" so we can copy
            # files via SDK.
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                cap_add=["SYS_ADMIN"],
                network_mode="bridge",
                labels=common_labels,
            )

            # Create /firmware dir, then copy the extracted filesystem
            # into it using the Docker SDK's put_archive (accepts a tar
            # stream).
            container.exec_run(["mkdir", "-p", "/firmware"])

            logger.info(
                "Copying firmware to emulation container via tar stream: %s",
                real_path,
            )
            try:
                copy_dir_to_container(container, real_path, "/firmware")
            except Exception as exc:
                container.remove(force=True)
                raise RuntimeError(
                    f"Failed to copy firmware to emulation container: {exc}"
                )

            # Fix permissions — binwalk extraction may lose execute bits.
            fix_firmware_permissions(container)

        else:
            # Standard bind mount — host path is available
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes or None,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                cap_add=["SYS_ADMIN"],
                network_mode="bridge",
                labels=common_labels,
            )

            # Fix permissions — binwalk extraction may lose execute bits.
            fix_firmware_permissions(container)

        # Inject LD_PRELOAD stub libraries into the firmware rootfs.
        # Based on stub_profile, copies the appropriate .so files into
        # /firmware/opt/stubs/ so they end up in the ext4 rootfs for
        # system mode and in the chroot for user mode. The init wrapper
        # handles LD_PRELOAD.
        inject_stub_libraries(container, session.architecture, stub_profile)

        # Per-mode setup: user-mode binfmt_misc + chroot prep, or
        # system-mode kernel copy + QEMU launch + health probe.
        if session.mode == "user":
            arch = session.architecture or "arm"
            ensure_binfmt_misc(settings, arch)
            setup_user_mode_container(
                container,
                settings,
                arch,
                is_standalone,
                binary_info,
            )
        elif session.mode == "system":
            await setup_system_mode_container(
                container=container,
                session=session,
                kernel_backend_path=kernel_backend_path,
                initrd_backend_path=initrd_backend_path,
                init_path=init_path,
                pre_init_script=pre_init_script,
                stub_profile=stub_profile,
            )

        return container.id

    # ── Static forwarder (back-compat for routers/emulation.py) ──

    @staticmethod
    def build_user_shell_cmd(
        arch: str,
        is_standalone: bool = False,
        binary_path: str | None = None,
        is_static: bool = False,
    ) -> list[str]:
        """Forwarder to :func:`user_mode.build_user_shell_cmd`.

        Kept as a class-scoped @staticmethod because
        :mod:`app.routers.emulation` calls it via
        ``EmulationService.build_user_shell_cmd(...)`` (class-access
        form, not instance-access). Updating every call site to the
        free-function form would multiply the cut-over diff without
        benefit.
        """
        return _build_user_shell_cmd(
            arch=arch,
            is_standalone=is_standalone,
            binary_path=binary_path,
            is_static=is_static,
        )

    async def stop_session(self, session_id: UUID) -> EmulationSession:
        """Stop an emulation session and remove its container."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status in ("stopped", "error"):
            return session

        # Stop the Docker container
        if session.container_id:
            try:
                client = get_docker_client()
                container = client.containers.get(session.container_id)
                session.logs = read_container_qemu_log(container, max_bytes=8000)
                container.stop(timeout=5)
                container.remove(force=True)
            except docker.errors.NotFound:
                logger.info(
                    "Container already removed: %s", session.container_id,
                )
            except Exception:
                logger.exception(
                    "Error stopping container: %s", session.container_id,
                )

        session.status = "stopped"
        session.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return session

    async def delete_session(self, session_id: UUID) -> None:
        """Delete a stopped or errored emulation session record."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")
        if session.status in (
            "running", "starting", "pending", "booting", "ready",
        ):
            raise ValueError("Cannot delete an active session — stop it first")
        await self.db.delete(session)
        await self.db.flush()

    async def exec_command(
        self,
        session_id: UUID,
        command: str,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
    ) -> dict:
        """Execute a command inside a running emulation session."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        # Accept both the legacy "running" status and the new 202-polling
        # terminal status "ready" (Commit 1 of the 202+polling refactor —
        # "ready" replaces "running" for sessions that went through the
        # async start path).
        if session.status not in ("running", "ready"):
            raise ValueError(
                f"Session is not running (status: {session.status})",
            )

        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError(
                "Container not found — session may have been terminated",
            )

        # Build exec command.
        # User mode: chroot into /firmware so all firmware paths work
        # naturally. The qemu-static binary was copied into /firmware/
        # during session start.
        # System mode: send command through QEMU's serial console socket.
        #
        # Environment variables are prepended as shell exports so
        # they're available to the command inside the chroot/emulated
        # system.
        env_prefix = ""
        if environment:
            exports = " ".join(
                f"export {shlex.quote(k)}={shlex.quote(v)};"
                for k, v in environment.items()
            )
            env_prefix = exports + " "

        if session.mode == "user":
            arch = session.architecture or "arm"
            qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

            # Check if this is a standalone binary session (marker set
            # in _start_container)
            standalone_check = container.exec_run(
                ["test", "-f", "/tmp/.standalone_mode"], demux=True,
            )
            is_standalone = standalone_check.exit_code == 0

            if is_standalone:
                # Standalone binary mode: run QEMU directly with sysroot
                static_check = container.exec_run(
                    ["cat", "/tmp/.standalone_static"], demux=True,
                )
                is_static = False
                if static_check.exit_code == 0:
                    stdout = static_check.output[0] if isinstance(static_check.output, tuple) else static_check.output
                    is_static = stdout and stdout.strip() == b"1"

                sysroot = get_sysroot_path(arch)
                ld_prefix = (
                    f"QEMU_LD_PREFIX={sysroot} "
                    if sysroot and not is_static else ""
                )

                # Apply shlex.quote to the binary path so filenames
                # with spaces, quotes, or other shell metacharacters
                # don't break the single-shell expansion here.
                # ``command`` is user-supplied exec intent (by design)
                # and is kept as-is.
                quoted_binary = shlex.quote(
                    (session.binary_path or "").lstrip("/"),
                )
                exec_cmd = [
                    "timeout", str(timeout),
                    "sh", "-c",
                    f"{ld_prefix}{env_prefix}/usr/bin/{qemu_bin} /firmware/{quoted_binary} {command}",
                ]
            else:
                # Standard firmware rootfs mode: chroot
                exec_cmd = [
                    "timeout", str(timeout),
                    "chroot", "/firmware",
                    f"/{qemu_bin}", "/bin/sh", "-c", env_prefix + command,
                ]
        else:
            # System mode: use serial-exec.sh to send commands through
            # the QEMU serial console socket with proper output
            # capture. The script wraps the command in unique markers,
            # keeps the socat connection alive until output is
            # captured, and extracts the guest command's stdout and
            # exit code.
            full_cmd = env_prefix + command if env_prefix else command
            exec_cmd = [
                "/opt/scripts/serial-exec.sh",
                full_cmd,
                str(timeout),
            ]

        try:
            exec_result = container.exec_run(exec_cmd, demux=True)

            stdout_bytes = exec_result.output[0] if exec_result.output[0] else b""
            stderr_bytes = exec_result.output[1] if exec_result.output[1] else b""
            exit_code = exec_result.exit_code

            # `timeout` and serial-exec.sh return exit code 124 for
            # timeouts
            timed_out = exit_code == 124

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            # Strip ANSI escape codes and residual markers (safety net
            # for anything serial-exec.sh misses or user-mode terminal
            # output)
            if session.mode == "system":
                stdout_str = _ANSI_RE.sub("", stdout_str)
                stdout_str = _MARKER_RE.sub("", stdout_str)
                stderr_str = _ANSI_RE.sub("", stderr_str)

            # For system mode, the serial-exec.sh script outputs a
            # timeout marker if no response was received from the guest
            if session.mode == "system" and "WAIRZ_SERIAL_TIMEOUT" in stdout_str:
                # Strip the marker and return whatever raw serial
                # output was captured
                stdout_str = stdout_str.replace(
                    "WAIRZ_SERIAL_TIMEOUT\n", "",
                ).strip()
                if not stderr_str:
                    stderr_str = (
                        "No response from serial console within timeout. "
                        "The guest OS may still be booting or no shell is available."
                    )
                timed_out = True

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": exit_code if not timed_out else -1,
                "timed_out": timed_out,
            }

        except Exception as exc:
            raise ValueError(f"Command execution failed: {exc}")

    async def send_ctrl_c(self, session_id: UUID) -> dict:
        """Send Ctrl-C to a running system-mode emulation session.

        This kills any stuck foreground process on the serial console,
        allowing subsequent commands to execute. Only works for
        system-mode sessions (user-mode sessions don't have a serial
        console).
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")
        if session.status not in ("running", "ready"):
            raise ValueError(
                f"Session is not running (status: {session.status})",
            )
        if session.mode != "system":
            raise ValueError(
                "send_ctrl_c is only supported for system-mode sessions",
            )
        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError(
                "Container not found — session may have been terminated",
            )

        # Send Ctrl-C (\x03) followed by a newline to the serial socket
        ctrl_c_cmd = [
            "sh", "-c",
            "printf '\\x03\\n' | socat - UNIX-CONNECT:/tmp/qemu-serial.sock",
        ]
        try:
            exec_result = container.exec_run(ctrl_c_cmd, demux=True)
            stdout = (exec_result.output[0] or b"").decode(
                "utf-8", errors="replace",
            )
            return {
                "success": exec_result.exit_code == 0,
                "message": (
                    "Ctrl-C sent to serial console"
                    if exec_result.exit_code == 0
                    else f"Failed: {stdout}"
                ),
            }
        except Exception as exc:
            raise ValueError(f"Failed to send Ctrl-C: {exc}")

    async def get_status(self, session_id: UUID) -> EmulationSession:
        """Get the status of an emulation session, updating from Docker if running."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        # If session claims to be running or ready, verify with Docker
        if session.status in ("running", "ready") and session.container_id:
            try:
                client = get_docker_client()
                container = client.containers.get(session.container_id)
                if container.status not in ("running", "created"):
                    # Container died — try to read QEMU log for
                    # diagnostics
                    log = read_container_qemu_log(container, quiet=True)
                    session.status = "error"
                    session.error_message = (
                        f"Emulation container exited unexpectedly.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                    session.stopped_at = datetime.now(timezone.utc)
                    await self.db.flush()
                elif session.mode == "system":
                    # Container is running, but check if QEMU process
                    # inside is alive
                    try:
                        check = container.exec_run(
                            ["sh", "-c", "pgrep -f 'qemu-system' >/dev/null 2>&1; echo $?"],
                        )
                        output = check.output.decode("utf-8", errors="replace").strip()
                        if output != "0":
                            log = read_container_qemu_log(container)
                            session.status = "error"
                            session.error_message = (
                                f"QEMU process has exited.\n\n"
                                f"--- QEMU log ---\n{log}"
                            )
                            session.stopped_at = datetime.now(timezone.utc)
                            await self.db.flush()
                    except docker.errors.APIError:
                        pass  # transient Docker error, don't update status
            except docker.errors.NotFound:
                session.status = "stopped"
                session.error_message = "Container no longer exists"
                session.stopped_at = datetime.now(timezone.utc)
                await self.db.flush()
            except Exception:
                logger.exception("Error checking container status")

        return session

    async def list_sessions(
        self, project_id: UUID,
    ) -> list[EmulationSession]:
        """List all emulation sessions for a project."""
        result = await self.db.execute(
            select(EmulationSession)
            .where(EmulationSession.project_id == project_id)
            .order_by(EmulationSession.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_session_logs(self, session_id: UUID) -> str:
        """Read QEMU startup logs from a session's container.

        Works for both running and recently-stopped containers.
        Returns the log text or an explanatory message.
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if not session.container_id:
            # No container — return stored error_message if available
            if session.error_message:
                return session.error_message
            return "No container associated with this session — no logs available."

        try:
            client = get_docker_client()
            container = client.containers.get(session.container_id)
            return read_container_qemu_log(container, max_bytes=8000)
        except docker.errors.NotFound:
            # Container removed — return saved logs or error_message
            if session.logs:
                return session.logs
            if session.error_message:
                return session.error_message
            return "Container has been removed — no logs available."
        except Exception as exc:
            return f"Failed to read logs: {exc}"

    async def cleanup_expired(self) -> int:
        """Stop sessions that have exceeded the timeout.

        Returns count stopped.
        """
        timeout_minutes = self._settings.emulation_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(EmulationSession).where(
                EmulationSession.status.in_(("running", "ready")),
                EmulationSession.started_at.isnot(None),
            )
        )
        sessions = result.scalars().all()
        count = 0

        for session in sessions:
            if session.started_at and session.started_at.timestamp() < cutoff:
                try:
                    await self.stop_session(session.id)
                    count += 1
                except Exception:
                    logger.exception(
                        "Failed to stop expired session: %s", session.id,
                    )

        return count

    # ── Emulation Presets (delegated to EmulationPresetService) ──

    async def create_preset(
        self,
        project_id: UUID,
        name: str,
        mode: str,
        description: str | None = None,
        binary_path: str | None = None,
        arguments: str | None = None,
        architecture: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationPreset:
        """Create a new emulation preset for a project."""
        return await EmulationPresetService(self.db).create_preset(
            project_id=project_id,
            name=name,
            mode=mode,
            description=description,
            binary_path=binary_path,
            arguments=arguments,
            architecture=architecture,
            port_forwards=port_forwards,
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )

    async def list_presets(self, project_id: UUID) -> list[EmulationPreset]:
        """List all emulation presets for a project."""
        return await EmulationPresetService(self.db).list_presets(project_id)

    async def get_preset(self, preset_id: UUID) -> EmulationPreset:
        """Get a single emulation preset by ID."""
        return await EmulationPresetService(self.db).get_preset(preset_id)

    async def update_preset(
        self, preset_id: UUID, updates: dict,
    ) -> EmulationPreset:
        """Update an existing emulation preset."""
        return await EmulationPresetService(self.db).update_preset(
            preset_id, updates,
        )

    async def delete_preset(self, preset_id: UUID) -> None:
        """Delete an emulation preset."""
        await EmulationPresetService(self.db).delete_preset(preset_id)
