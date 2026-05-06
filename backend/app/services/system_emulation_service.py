"""Service for managing FirmAE-based full system emulation sessions.

Uses Docker SDK to spawn the FirmAE sidecar container and httpx to
communicate with the Flask shim API running inside it.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.services.jsonb_normalizers import _normalize_emulation_sessions_discovered_services
from app.utils.docker_client import get_docker_client

logger = logging.getLogger(__name__)

# Ports the sidecar commonly exposes for firmware services
_COMMON_SERVICE_PORTS = [80, 443, 22, 23, 53, 8080, 8443, 21, 161, 554]


def _write_bytes(path: str, data: bytes) -> None:
    """Write bytes to a file (used via run_in_executor)."""
    with open(path, "wb") as f:
        f.write(data)


class SystemEmulationService:
    """Orchestrates FirmAE sidecar for full system emulation."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        return get_docker_client()

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Translate backend-container path to host path for Docker mounts.

        Same pattern as EmulationService._resolve_host_path.
        """
        real_path = os.path.realpath(container_path)

        if not os.path.exists("/.dockerenv"):
            return real_path

        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            client = self._get_docker_client()
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])

            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    host_path = os.path.join(source, relative)
                    logger.info(
                        "Path translation: %s -> %s (via mount %s -> %s)",
                        real_path, host_path, source, dest,
                    )
                    return host_path
        except Exception:
            logger.warning(
                "Could not resolve host path for %s", real_path, exc_info=True,
            )

        return None

    async def _get_shim_url(self, container_id: str) -> str | None:
        """Get the shim API URL from the sidecar container's network settings."""
        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, self._get_docker_client)
            container = await loop.run_in_executor(
                None, client.containers.get, container_id,
            )
            # Refresh attrs
            await loop.run_in_executor(None, container.reload)

            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            net_name = self._settings.emulation_network

            if net_name in networks:
                ip = networks[net_name].get("IPAddress")
                if ip:
                    return f"http://{ip}:5000"

            # Fallback: try port mapping on host
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
            mapping = ports.get("5000/tcp")
            if mapping:
                host_port = mapping[0]["HostPort"]
                return f"http://127.0.0.1:{host_port}"
        except Exception:
            logger.warning("Could not resolve shim URL for %s", container_id, exc_info=True)

        return None

    async def _count_active_system_sessions(self, project_id: UUID) -> int:
        from sqlalchemy import func
        result = await self.db.scalar(
            select(func.count(EmulationSession.id)).where(
                EmulationSession.project_id == project_id,
                EmulationSession.mode == "system-full",
                EmulationSession.status.in_(["pending", "starting", "running"]),
            )
        )
        return result or 0

    async def start_system_emulation(
        self,
        firmware: Firmware,
        project_id: UUID,
        brand: str = "unknown",
        timeout: int = 600,
    ) -> EmulationSession:
        """Start a FirmAE-based full system emulation session.

        Creates a Docker sidecar container running the FirmAE pipeline,
        then calls the Flask shim to start emulation.
        """
        if not firmware.storage_path:
            raise ValueError("Firmware file not available (no storage_path)")

        # Enforce 1 system session per project
        active = await self._count_active_system_sessions(project_id)
        if active >= 1:
            raise ValueError(
                "A system emulation session is already running for this project. "
                "Stop it before starting a new one."
            )

        # Create DB record
        session = EmulationSession(
            project_id=project_id,
            firmware_id=firmware.id,
            mode="system-full",
            status="pending",
            architecture=firmware.architecture,
            port_forwards=[],
        )
        self.db.add(session)
        await self.db.flush()

        session_id_str = str(session.id)

        # Resolve the firmware file's host path for the Docker bind mount
        storage_root = self._settings.storage_root
        host_storage = self._resolve_host_path(storage_root)
        if not host_storage:
            session.status = "error"
            session.error_message = "Could not resolve storage root to host path for Docker mount"
            await self.db.flush()
            return session

        # Build port bindings: 5000 (shim) + common service ports
        port_bindings: dict[str, None] = {"5000/tcp": None}
        for p in _COMMON_SERVICE_PORTS:
            port_bindings[f"{p}/tcp"] = None

        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, self._get_docker_client)

            # Ensure the emulation network exists
            try:
                await loop.run_in_executor(
                    None,
                    lambda: client.networks.get(self._settings.emulation_network),
                )
            except docker.errors.NotFound:
                await loop.run_in_executor(
                    None,
                    lambda: client.networks.create(
                        self._settings.emulation_network,
                        driver="bridge",
                    ),
                )

            container = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    image=self._settings.system_emulation_image,
                    detach=True,
                    privileged=True,
                    volumes={
                        host_storage: {"bind": "/firmwares", "mode": "ro"},
                    },
                    network=self._settings.emulation_network,
                    mem_limit=self._settings.system_emulation_ram_limit,
                    nano_cpus=int(self._settings.system_emulation_cpu_limit * 1e9),
                    ports=port_bindings,
                    labels={
                        "wairz.system-emulation": session_id_str,
                        "wairz.project": str(project_id),
                    },
                    environment={
                        "SESSION_ID": session_id_str,
                    },
                ),
            )

            session.container_id = container.id
            session.status = "starting"
            session.started_at = datetime.now(timezone.utc)
            await self.db.flush()

            # Wait for shim to become healthy (up to 30s)
            shim_url = await self._wait_for_shim(container.id, timeout=30)
            if not shim_url:
                session.status = "error"
                session.error_message = "FirmAE shim did not become healthy within 30s"
                await self.db.flush()
                return session

            # Compute firmware path relative to the storage root mount
            rel_path = os.path.relpath(firmware.storage_path, storage_root)
            firmware_path_in_container = os.path.join("/firmwares", rel_path)

            # Call shim POST /start
            async with httpx.AsyncClient(timeout=30.0) as http:
                resp = await http.post(
                    f"{shim_url}/start",
                    json={
                        "firmware_path": firmware_path_in_container,
                        "brand": brand,
                        "session_id": session_id_str,
                        "timeout": timeout,
                    },
                )

            if resp.status_code not in (200, 202):
                error_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                session.status = "error"
                session.error_message = error_data.get("error", f"Shim returned HTTP {resp.status_code}")
                await self.db.flush()
                return session

            session.system_emulation_stage = "starting"
            await self.db.flush()

        except Exception as exc:
            logger.exception("Failed to start system emulation container")
            session.status = "error"
            session.error_message = str(exc)
            await self.db.flush()

        return session

    async def _wait_for_shim(self, container_id: str, timeout: int = 30) -> str | None:
        """Poll the shim /health endpoint until it responds or timeout."""
        deadline = asyncio.get_event_loop().time() + timeout

        while asyncio.get_event_loop().time() < deadline:
            shim_url = await self._get_shim_url(container_id)
            if shim_url:
                try:
                    async with httpx.AsyncClient(timeout=5.0) as http:
                        resp = await http.get(f"{shim_url}/health")
                        if resp.status_code == 200:
                            return shim_url
                except (httpx.ConnectError, httpx.ReadTimeout, OSError):
                    pass
            await asyncio.sleep(2)

        return None

    async def poll_system_status(self, session_id: UUID) -> EmulationSession:
        """Poll the FirmAE shim for status and update the DB."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.mode != "system-full":
            raise ValueError("Not a system emulation session")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        if session.status in ("stopped", "error"):
            return session

        shim_url = await self._get_shim_url(session.container_id)
        if not shim_url:
            session.status = "error"
            session.error_message = "Cannot reach FirmAE shim — container may have stopped"
            await self.db.flush()
            return session

        try:
            async with httpx.AsyncClient(timeout=15.0) as http:
                resp = await http.get(
                    f"{shim_url}/status",
                    params={"session_id": str(session_id)},
                )
            if resp.status_code != 200:
                return session

            data = resp.json()

            # Map shim phase to our stage
            phase = data.get("phase", "")
            session.system_emulation_stage = phase

            # Update architecture if detected
            arch = data.get("arch")
            if arch and not session.architecture:
                session.architecture = arch

            # Update guest IPs
            guest_ips = data.get("guest_ips", [])
            if guest_ips:
                session.firmware_ip = guest_ips[0]

            # Map pipeline phase to session status
            is_terminal = data.get("is_terminal", False)
            error = data.get("error")

            if is_terminal and error:
                session.status = "error"
                session.error_message = error
            elif phase in ("running", "checking", "network_check", "web_check"):
                session.status = "running"
            elif phase in ("done",):
                session.status = "running"
            elif phase in ("failed", "timeout"):
                session.status = "error"
                session.error_message = error or f"Pipeline ended in phase: {phase}"
            else:
                # Starting phases
                session.status = "starting"

            await self.db.flush()

        except (httpx.ConnectError, httpx.ReadTimeout) as exc:
            logger.warning("Could not poll shim for session %s: %s", session_id, exc)

        return session

    async def get_firmware_services(self, session_id: UUID) -> list[dict]:
        """Get discovered network services from the FirmAE shim."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        shim_url = await self._get_shim_url(session.container_id)
        if not shim_url:
            raise ValueError("Cannot reach FirmAE shim")

        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                resp = await http.get(
                    f"{shim_url}/ports",
                    params={"session_id": str(session_id)},
                )

            if resp.status_code != 200:
                return _normalize_emulation_sessions_discovered_services(session.discovered_services)

            data = resp.json()
            ports = data.get("ports", [])

            # Map internal ports to dynamic host ports
            loop = asyncio.get_running_loop()
            client = await loop.run_in_executor(None, self._get_docker_client)
            container = await loop.run_in_executor(
                None, client.containers.get, session.container_id,
            )
            await loop.run_in_executor(None, container.reload)

            container_ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})

            services = []
            for port_info in ports:
                port_num = port_info.get("port")
                protocol = port_info.get("protocol", "tcp")
                service_name = port_info.get("service", "unknown")

                host_port = None
                mapping = container_ports.get(f"{port_num}/{protocol}")
                if mapping:
                    host_port = int(mapping[0]["HostPort"])

                url = None
                if service_name in ("http", "https") and host_port:
                    scheme = "https" if port_num == 443 or service_name == "https" else "http"
                    url = f"{scheme}://localhost:{host_port}"

                services.append({
                    "port": port_num,
                    "protocol": protocol,
                    "service": service_name,
                    "host_port": host_port,
                    "url": url,
                })

            # Persist to DB
            session.discovered_services = services
            await self.db.flush()

            return services

        except (httpx.ConnectError, httpx.ReadTimeout) as exc:
            logger.warning("Could not get services for session %s: %s", session_id, exc)
            return _normalize_emulation_sessions_discovered_services(session.discovered_services)

    async def stop_system_emulation(self, session_id: UUID) -> EmulationSession:
        """Stop FirmAE emulation and remove the sidecar container."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if not session.container_id:
            session.status = "stopped"
            session.stopped_at = datetime.now(timezone.utc)
            await self.db.flush()
            return session

        # Try to call shim stop first (graceful)
        shim_url = await self._get_shim_url(session.container_id)
        if shim_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as http:
                    await http.post(
                        f"{shim_url}/stop",
                        json={"session_id": str(session_id)},
                    )
            except Exception:
                logger.debug("Could not call shim /stop — will force remove container")

        # Remove the Docker container
        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, self._get_docker_client)
            container = await loop.run_in_executor(
                None, client.containers.get, session.container_id,
            )
            await loop.run_in_executor(None, lambda: container.remove(force=True))
        except docker.errors.NotFound:
            logger.debug("Container %s already gone", session.container_id)
        except Exception as exc:
            logger.warning("Error removing container %s: %s", session.container_id, exc)

        session.status = "stopped"
        session.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return session

    async def run_command_in_firmware(
        self,
        session_id: UUID,
        command: str,
        timeout: int = 30,
    ) -> dict:
        """Execute a command inside the FirmAE sidecar container.

        Uses Docker exec to run the command inside the sidecar, which has
        access to the running QEMU instance and firmware network.
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        loop = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._get_docker_client)

        try:
            container = await loop.run_in_executor(
                None, client.containers.get, session.container_id,
            )
        except docker.errors.NotFound:
            raise ValueError("Container not found — session may have been stopped")

        # Execute via docker exec
        try:
            exec_result = await loop.run_in_executor(
                None,
                lambda: container.exec_run(
                    ["sh", "-c", command],
                    demux=True,
                    environment={"TERM": "dumb"},
                ),
            )

            stdout_raw, stderr_raw = exec_result.output if isinstance(exec_result.output, tuple) else (exec_result.output, b"")
            stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
            stderr = (stderr_raw or b"").decode("utf-8", errors="replace")

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exec_result.exit_code,
            }
        except Exception as exc:
            return {
                "stdout": "",
                "stderr": str(exc),
                "exit_code": -1,
            }

    async def capture_network_traffic(
        self,
        session_id: UUID,
        duration: int = 10,
        interface: str = "eth0",
    ) -> dict:
        """Capture network traffic from the sidecar using tcpdump.

        Writes a binary pcap file inside the container, copies it out,
        and persists it to the project's pcaps directory on disk.

        Returns a dict with packet_count, pcap_path, size_bytes, and duration.
        """
        import io
        import tarfile

        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.status != "running" or not session.container_id:
            raise ValueError("Session is not running")

        # Clamp duration
        duration = max(1, min(duration, 120))

        loop = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._get_docker_client)
        container = await loop.run_in_executor(
            None, client.containers.get, session.container_id,
        )

        # Run tcpdump with binary pcap output inside the container
        capture_cmd = (
            f"timeout {duration + 5} tcpdump -i {interface} -c 10000 "
            f"-w /tmp/capture.pcap not port 22 2>/dev/null & "
            f"sleep {duration}; kill %1 2>/dev/null; wait 2>/dev/null; true"
        )

        await loop.run_in_executor(
            None,
            lambda: container.exec_run(
                ["sh", "-c", capture_cmd],
                demux=True,
            ),
        )

        # Count packets captured by reading back the pcap
        count_cmd = "tcpdump -r /tmp/capture.pcap 2>/dev/null | wc -l"
        count_result = await loop.run_in_executor(
            None,
            lambda: container.exec_run(["sh", "-c", count_cmd], demux=True),
        )
        stdout_raw = count_result.output[0] if isinstance(count_result.output, tuple) else count_result.output
        try:
            packet_count = int((stdout_raw or b"").decode().strip())
        except (ValueError, AttributeError):
            packet_count = 0

        # Copy the pcap file out of the container via tar archive
        try:
            tar_stream, _stat = await loop.run_in_executor(
                None,
                lambda: container.get_archive("/tmp/capture.pcap"),
            )
        except docker.errors.NotFound:
            raise ValueError("Capture failed — no pcap file produced in container")

        # Extract the pcap bytes from the tar stream
        tar_bytes = b"".join(tar_stream)
        tar_buf = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=tar_buf, mode="r") as tar:
            member = tar.getmembers()[0]
            pcap_data = tar.extractfile(member).read()

        # Save to disk: {storage_root}/projects/{project_id}/pcaps/{session_id}.pcap
        pcaps_dir = os.path.join(
            self._settings.storage_root,
            "projects",
            str(session.project_id),
            "pcaps",
        )
        os.makedirs(pcaps_dir, exist_ok=True)
        pcap_file = os.path.join(pcaps_dir, f"{session_id}.pcap")

        await loop.run_in_executor(
            None,
            lambda: _write_bytes(pcap_file, pcap_data),
        )

        size_bytes = len(pcap_data)

        # Update the session's pcap_path column
        session.pcap_path = pcap_file
        await self.db.flush()

        return {
            "packet_count": packet_count,
            "pcap_path": pcap_file,
            "size_bytes": size_bytes,
            "duration": duration,
        }

    async def get_nvram_state(self, session_id: UUID) -> dict[str, str]:
        """Read NVRAM key-value pairs from the running emulation."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.status != "running" or not session.container_id:
            raise ValueError("Session is not running")

        loop = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._get_docker_client)
        container = await loop.run_in_executor(
            None, client.containers.get, session.container_id,
        )

        # Read NVRAM from FirmAE's libnvram storage
        cmd = (
            "cat /firmadyne/libnvram.override 2>/dev/null; "
            "echo '---SEPARATOR---'; "
            "find /firmadyne/libnvram/ -type f 2>/dev/null | "
            "while read f; do echo \"$(basename $f)=$(cat $f 2>/dev/null)\"; done"
        )

        exec_result = await loop.run_in_executor(
            None,
            lambda: container.exec_run(["sh", "-c", cmd], demux=True),
        )

        stdout_raw = exec_result.output[0] if isinstance(exec_result.output, tuple) else exec_result.output
        output = (stdout_raw or b"").decode("utf-8", errors="replace")

        nvram: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line or line == "---SEPARATOR---":
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                nvram[key.strip()] = value.strip()

        # Persist to DB
        session.nvram_state = nvram
        await self.db.flush()

        return nvram

    async def interact_web_endpoint(
        self,
        session_id: UUID,
        method: str = "GET",
        path: str = "/",
    ) -> dict:
        """Make an HTTP request to the firmware's web interface from the sidecar."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.status != "running" or not session.container_id:
            raise ValueError("Session is not running")

        firmware_ip = session.firmware_ip
        if not firmware_ip:
            raise ValueError(
                "No firmware IP discovered yet. "
                "Poll status first or wait for the pipeline to detect the guest IP."
            )

        loop = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._get_docker_client)
        container = await loop.run_in_executor(
            None, client.containers.get, session.container_id,
        )

        method_upper = method.upper()
        url = f"http://{firmware_ip}{path}"

        # Use curl inside the sidecar (it has network access to the firmware)
        curl_cmd = f"curl -s -S -o /dev/stdout -w '\\n---HTTP_CODE:%{{http_code}}---' -X {method_upper} '{url}' 2>&1"
        cmd = f"timeout 15 {curl_cmd}"

        exec_result = await loop.run_in_executor(
            None,
            lambda: container.exec_run(["sh", "-c", cmd], demux=True),
        )

        stdout_raw = exec_result.output[0] if isinstance(exec_result.output, tuple) else exec_result.output
        output = (stdout_raw or b"").decode("utf-8", errors="replace")

        # Parse HTTP status code from output
        status_code = 0
        body = output
        if "---HTTP_CODE:" in output:
            parts = output.rsplit("---HTTP_CODE:", 1)
            body = parts[0]
            try:
                code_str = parts[1].replace("---", "").strip()
                status_code = int(code_str)
            except (ValueError, IndexError):
                pass

        return {
            "url": url,
            "method": method_upper,
            "status_code": status_code,
            "body": body[:30000],  # Cap body size
        }

    async def get_container_ip(self, container_id: str) -> str | None:
        """Get the container's IP address on the emulation network."""
        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, self._get_docker_client)
            container = await loop.run_in_executor(
                None, client.containers.get, container_id,
            )
            await loop.run_in_executor(None, container.reload)

            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            net = networks.get(self._settings.emulation_network, {})
            return net.get("IPAddress")
        except Exception:
            return None
