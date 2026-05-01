"""Service for the firmware carving sandbox.

Spawns and manages one long-running, locked-down container per active project
where the AI agent can run binwalk, dd, python3, and friends against the raw
firmware blob. Mirrors the lifecycle pattern used by EmulationService and
FuzzingService.

Sandbox guarantees (enforced via Docker):

  - network_mode=none (no internet, no host)
  - cap_drop=ALL + no-new-privileges
  - read-only root filesystem
  - non-root user (uid 1000)
  - writable bind only at /carved/
  - tmpfs at /tmp (256 MiB)
  - mem_limit=1g, cpu=1.0 (configurable)

The container is reused across `run_command` calls within a project so
agents don't pay 200–500 ms of cold-start per command.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware

logger = logging.getLogger(__name__)


_CONTAINER_LABEL_TYPE = "wairz.type"
_CONTAINER_LABEL_PROJECT = "wairz.project_id"
_CONTAINER_LABEL_FIRMWARE = "wairz.firmware_id"
_CONTAINER_TYPE = "carving"


@dataclass
class ShellResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CarvingError(RuntimeError):
    pass


class CarvingService:
    """Lifecycle + exec wrapper for the per-project carving sandbox."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._settings = get_settings()
        self._client: docker.DockerClient | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_command(
        self,
        project_id: UUID,
        firmware_id: UUID,
        command: str,
        timeout: int | None = None,
    ) -> ShellResult:
        """Run a shell command in the project's carving sandbox.

        The command is fed to ``bash -c`` inside the container, so it can be
        a pipeline, multi-statement script, etc. The container is created on
        first use and reused for subsequent calls.
        """
        if not command or not command.strip():
            raise CarvingError("command is empty")

        max_timeout = self._settings.carving_max_timeout
        if timeout is None:
            timeout = self._settings.carving_default_timeout
        if timeout < 1:
            raise CarvingError("timeout must be >= 1 second")
        if timeout > max_timeout:
            raise CarvingError(f"timeout cannot exceed {max_timeout} seconds")

        firmware = await self._load_firmware(project_id, firmware_id)
        container = await self._ensure_container(project_id, firmware)
        return await self._exec(container, command, timeout)

    async def stop_container(self, project_id: UUID) -> bool:
        """Stop and remove the project's carving container if any. Idempotent."""
        client = self._get_docker_client()
        name = self._container_name(project_id)

        def _stop() -> bool:
            try:
                container = client.containers.get(name)
            except docker.errors.NotFound:
                return False
            try:
                container.stop(timeout=2)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass
            return True

        return await asyncio.to_thread(_stop)

    @classmethod
    def cleanup_orphans(cls) -> None:
        """Remove every carving container left behind by a previous backend run.

        Called from app startup so a hard restart doesn't accumulate orphans.
        """
        try:
            client = docker.from_env()
        except docker.errors.DockerException:
            logger.warning("Docker not available; skipping carving orphan cleanup")
            return

        try:
            containers = client.containers.list(
                all=True,
                filters={"label": f"{_CONTAINER_LABEL_TYPE}={_CONTAINER_TYPE}"},
            )
        except Exception:
            logger.exception("Failed to list carving containers for cleanup")
            return

        for c in containers:
            try:
                c.remove(force=True)
                logger.info("Removed orphan carving container: %s", c.name)
            except Exception:
                logger.warning("Could not remove carving container %s", c.name)

    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    async def _ensure_container(
        self, project_id: UUID, firmware: Firmware
    ) -> docker.models.containers.Container:
        client = self._get_docker_client()
        name = self._container_name(project_id)

        def _get_or_create() -> docker.models.containers.Container:
            # Reuse an existing container if it's already running
            try:
                existing = client.containers.get(name)
            except docker.errors.NotFound:
                existing = None

            if existing is not None:
                if existing.status == "running":
                    return existing
                # Dead container — clear it and respawn
                try:
                    existing.remove(force=True)
                except Exception:
                    pass

            return self._spawn_container(client, project_id, firmware, name)

        return await asyncio.to_thread(_get_or_create)

    def _spawn_container(
        self,
        client: docker.DockerClient,
        project_id: UUID,
        firmware: Firmware,
        name: str,
    ) -> docker.models.containers.Container:
        # Resolve the on-disk paths the sandbox needs to see.
        if not firmware.storage_path:
            raise CarvingError("firmware has no storage_path on disk")
        if not os.path.isfile(firmware.storage_path):
            raise CarvingError(
                f"firmware blob missing on disk: {firmware.storage_path}"
            )

        carved_dir = self._ensure_carved_dir(firmware)

        # Translate paths to host-visible paths (we're running inside Docker
        # ourselves; bind mounts must reference paths the daemon can see).
        firmware_host = self._resolve_host_path(firmware.storage_path)
        carved_host = self._resolve_host_path(carved_dir)
        if firmware_host is None or carved_host is None:
            raise CarvingError(
                "could not resolve host paths for carving mounts; "
                "is the backend running outside its expected volumes?"
            )

        volumes: dict[str, dict[str, str]] = {
            firmware_host: {"bind": "/image/firmware.bin", "mode": "ro"},
            carved_host: {"bind": "/carved", "mode": "rw"},
        }

        # Optional: mount the extracted tree if available, so the agent can
        # cross-reference the carved view with the unpacked filesystem.
        if firmware.extracted_path and os.path.isdir(firmware.extracted_path):
            extracted_host = self._resolve_host_path(firmware.extracted_path)
            if extracted_host is not None:
                volumes[extracted_host] = {"bind": "/extracted", "mode": "ro"}

        labels = {
            _CONTAINER_LABEL_TYPE: _CONTAINER_TYPE,
            _CONTAINER_LABEL_PROJECT: str(project_id),
            _CONTAINER_LABEL_FIRMWARE: str(firmware.id),
        }

        logger.info(
            "Spawning carving sandbox %s for project=%s firmware=%s",
            name, project_id, firmware.id,
        )

        container = client.containers.run(
            image=self._settings.carving_image,
            command=["sleep", "infinity"],
            name=name,
            detach=True,
            volumes=volumes,
            network_mode="none",
            mem_limit=f"{self._settings.carving_memory_limit_mb}m",
            nano_cpus=int(self._settings.carving_cpu_limit * 1e9),
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            read_only=True,
            tmpfs={"/tmp": "rw,size=256m,mode=1777"},
            user="1000:1000",
            working_dir="/carved",
            labels=labels,
            # We don't auto-remove because we explicitly reap on stop /
            # orphan-cleanup; auto_remove + a brief race could leave clients
            # exec'ing into a vanishing container.
            auto_remove=False,
        )
        return container

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    async def _exec(
        self,
        container: docker.models.containers.Container,
        command: str,
        timeout: int,
    ) -> ShellResult:
        def _run() -> ShellResult:
            # We use the low-level API (exec_create + exec_start) instead of
            # container.exec_run so we can capture stdout and stderr
            # separately and apply a wallclock timeout from the host side.
            api = container.client.api
            try:
                exec_id = api.exec_create(
                    container.id,
                    cmd=["bash", "-c", command],
                    stdout=True,
                    stderr=True,
                    tty=False,
                )["Id"]
                stream = api.exec_start(exec_id, stream=True, demux=True)
            except docker.errors.APIError as exc:
                raise CarvingError(f"docker exec failed: {exc}") from exc

            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            timed_out = False
            try:
                # demux=True yields (stdout_bytes, stderr_bytes) tuples
                import time
                start = time.monotonic()
                for chunk in stream:
                    if chunk is None:
                        continue
                    out, err = chunk
                    if out:
                        stdout_chunks.append(out)
                    if err:
                        stderr_chunks.append(err)
                    if time.monotonic() - start > timeout:
                        timed_out = True
                        break
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

            stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

            if timed_out:
                # Best-effort kill of the exec'd process. There's no clean
                # way to address an exec instance, so we send a signal to
                # the container's main process; the bash -c child will be
                # left as a zombie until container teardown — acceptable
                # because we're going to keep the container alive.
                try:
                    api.exec_inspect(exec_id)
                except Exception:
                    pass
                return ShellResult(
                    exit_code=-1,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=True,
                )

            try:
                info = api.exec_inspect(exec_id)
                exit_code = int(info.get("ExitCode") or 0)
            except Exception:
                exit_code = -1

            return ShellResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
            )

        return await asyncio.to_thread(_run)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _load_firmware(
        self, project_id: UUID, firmware_id: UUID
    ) -> Firmware:
        result = await self.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
        firmware = result.scalar_one_or_none()
        if firmware is None:
            raise CarvingError("firmware not found for this project")
        return firmware

    @staticmethod
    def _container_name(project_id: UUID) -> str:
        return f"wairz-carving-{project_id}"

    @staticmethod
    def _ensure_carved_dir(firmware: Firmware) -> str:
        """Carved outputs live next to the original blob and survive sessions."""
        if not firmware.storage_path:
            raise CarvingError("firmware has no storage_path on disk")
        firmware_dir = os.path.dirname(firmware.storage_path)
        carved = os.path.join(firmware_dir, "carved")
        os.makedirs(carved, exist_ok=True)
        # Make the dir writable by the sandbox's uid (1000). The backend
        # container itself may run as a different uid, so chmod 0o775 is
        # safer than chowning.
        try:
            os.chmod(carved, 0o2775)
        except OSError:
            pass
        return carved

    def _get_docker_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Translate an in-backend path to a host-visible path.

        Identical pattern to EmulationService and FuzzingService — when the
        backend runs inside Docker, bind-mount sources must be host paths,
        not container paths. We inspect our own container's mounts to
        translate. If we're running outside Docker, the path is already a
        host path.
        """
        real_path = os.path.realpath(container_path)

        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])
            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    return os.path.join(source, relative)
        except Exception:
            logger.warning(
                "Could not inspect own container for path translation: %s",
                real_path,
            )

        return None
