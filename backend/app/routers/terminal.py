"""WebSocket terminal — sandboxed shell for firmware filesystem exploration.

Spawns a lightweight Docker container with the firmware directory mounted
read-only, providing an isolated shell. Uses the same container+exec pattern
as the emulation terminal (routers/emulation.py).

Also provides a WebSocket-to-TCP proxy for system emulation port forwarding
(SSH, telnet, etc.) via the FirmAE sidecar container.
"""

import asyncio
import io
import logging
import os
import socket
import tarfile
import uuid

import docker
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.database import async_session_factory
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.models.project import Project
from app.utils.docker_client import get_docker_client

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/terminal",
    tags=["terminal"],
)

# Lightweight image for the terminal shell — pre-pulled at first use
TERMINAL_IMAGE = "alpine:3.19"


def _resolve_host_path(container_path: str) -> str | None:
    """Translate a backend-container path to the host path for Docker mounts.

    Same logic as EmulationService._resolve_host_path — when the backend
    runs inside Docker, volume mounts reference HOST paths.
    """
    real_path = os.path.realpath(container_path)

    if not os.path.exists("/.dockerenv"):
        return real_path

    hostname = os.environ.get("HOSTNAME", "")
    if not hostname:
        return real_path

    try:
        client = get_docker_client()
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
                return host_path
    except Exception:
        logger.warning("Could not resolve host path for %s", real_path, exc_info=True)

    return None


def _copy_dir_to_container(
    container: "docker.models.containers.Container",
    src_path: str,
    dest_path: str,
) -> None:
    """Copy a directory into a container via tar stream (fallback when bind mount unavailable)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(src_path, arcname=".")
    buf.seek(0)
    container.put_archive(dest_path, buf)


@router.websocket("/ws")
async def websocket_terminal(
    websocket: WebSocket,
    project_id: uuid.UUID,
):
    await websocket.accept()

    # Look up project and firmware extracted_path
    async with async_session_factory() as db:
        result = await db.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if not project:
            await websocket.send_json({"type": "error", "data": "Project not found"})
            await websocket.close(code=4004)
            return

        fw_result = await db.execute(
            select(Firmware).where(Firmware.project_id == project_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            await websocket.send_json(
                {"type": "error", "data": "No unpacked firmware found"}
            )
            await websocket.close(code=4004)
            return

        extracted_path = firmware.extracted_path

    if not os.path.isdir(extracted_path):
        await websocket.send_json(
            {"type": "error", "data": "Extracted firmware directory not found on disk"}
        )
        await websocket.close(code=4004)
        return

    # Spawn a sandboxed Docker container
    loop = asyncio.get_running_loop()
    try:
        client = await loop.run_in_executor(None, get_docker_client)
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Docker unavailable: {exc}"})
        await websocket.close(code=4004)
        return

    container = None
    try:
        # Resolve host path for bind mount
        host_path = _resolve_host_path(extracted_path)

        if host_path:
            container = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    TERMINAL_IMAGE,
                    command=["sleep", "infinity"],
                    detach=True,
                    volumes={host_path: {"bind": "/workspace", "mode": "ro"}},
                    working_dir="/workspace",
                    mem_limit="256m",
                    nano_cpus=int(1e9),
                    pids_limit=128,
                    network_mode="none",
                    labels={"wairz.terminal": str(project_id)},
                    auto_remove=True,
                ),
            )
        else:
            # Fallback: create container then copy firmware in
            container = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    TERMINAL_IMAGE,
                    command=["sleep", "infinity"],
                    detach=True,
                    working_dir="/workspace",
                    mem_limit="256m",
                    nano_cpus=int(1e9),
                    pids_limit=128,
                    network_mode="none",
                    labels={"wairz.terminal": str(project_id)},
                    auto_remove=True,
                ),
            )
            await loop.run_in_executor(
                None,
                lambda: _copy_dir_to_container(container, extracted_path, "/workspace"),
            )

    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Failed to start terminal: {exc}"})
        await websocket.close(code=4004)
        if container:
            try:
                container.kill()
            except Exception:
                pass
        return

    # Create an interactive exec instance
    try:
        exec_id = client.api.exec_create(
            container.id,
            ["/bin/sh"],
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
            workdir="/workspace",
        )
        sock = client.api.exec_start(exec_id, socket=True, tty=True)
        raw_sock = sock._sock
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Failed to exec shell: {exc}"})
        await websocket.close(code=4004)
        try:
            container.kill()
        except Exception:
            pass
        return

    await websocket.send_json({
        "type": "output",
        "data": "\r\n  Firmware root: /workspace (read-only, sandboxed)\r\n\r\n",
    })

    async def read_container():
        """Read from container socket and send to WebSocket."""
        try:
            while True:
                data = await loop.run_in_executor(None, raw_sock.recv, 4096)
                if not data:
                    break
                await websocket.send_json({
                    "type": "output",
                    "data": data.decode("utf-8", errors="replace"),
                })
        except OSError:
            pass
        except Exception:
            logger.debug("Container reader stopped", exc_info=True)

    async def write_container():
        """Read from WebSocket and write to container socket."""
        try:
            while True:
                msg = await websocket.receive_json()
                msg_type = msg.get("type")

                if msg_type == "input":
                    input_data = msg.get("data", "")
                    if input_data:
                        await loop.run_in_executor(
                            None, raw_sock.sendall, input_data.encode("utf-8")
                        )

                elif msg_type == "resize":
                    cols = msg.get("cols", 80)
                    rows = msg.get("rows", 24)
                    try:
                        client.api.exec_resize(exec_id, height=rows, width=cols)
                    except Exception:
                        pass

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            pass
        except Exception:
            logger.debug("Container writer stopped", exc_info=True)

    async def keepalive():
        """Send periodic pings to keep the WebSocket alive."""
        try:
            while True:
                await asyncio.sleep(15)
                await websocket.send_json({"type": "ping"})
        except Exception:
            pass

    try:
        reader_task = asyncio.create_task(read_container())
        writer_task = asyncio.create_task(write_container())
        keepalive_task = asyncio.create_task(keepalive())
        done, pending = await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        keepalive_task.cancel()
    finally:
        # Cleanup: close sockets, kill container
        try:
            raw_sock.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        try:
            container.kill()
        except Exception:
            pass
        logger.info("Terminal session ended: project=%s", project_id)


# ── WebSocket TCP Proxy for System Emulation Port Forwarding ──

# This endpoint is on the emulation router's URL space, but we define it
# in this module to keep all WebSocket bridge logic together. The actual
# route is registered via a separate router included in main.py.

system_ws_router = APIRouter(
    prefix="/api/v1/projects/{project_id}/emulation/system",
    tags=["terminal"],
)


@system_ws_router.websocket("/{session_id}/ws/{port}")
async def websocket_tcp_proxy(
    websocket: WebSocket,
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    port: int,
):
    """WebSocket-to-TCP proxy for system emulation port forwarding.

    Bridges xterm.js (WebSocket) to a TCP port (SSH:22, telnet:23, etc.)
    on the FirmAE sidecar container. Looks up the session's container_id,
    resolves the container's IP on emulation_net, then proxies
    WebSocket <-> TCP.

    Protocol (same as firmware terminal):
      - Client sends: { "type": "input", "data": "<bytes>" }
      - Client sends: { "type": "resize", "cols": 80, "rows": 24 }
      - Server sends: { "type": "output", "data": "<text>" }
      - Server sends: { "type": "error", "data": "<message>" }
    """
    await websocket.accept()

    # Validate port range
    if port < 1 or port > 65535:
        await websocket.send_json({"type": "error", "data": "Invalid port number"})
        await websocket.close(code=4004)
        return

    # Look up session and container
    async with async_session_factory() as db:
        result = await db.execute(
            select(EmulationSession).where(
                EmulationSession.id == session_id,
                EmulationSession.project_id == project_id,
            )
        )
        session = result.scalar_one_or_none()
        if not session:
            await websocket.send_json({"type": "error", "data": "Session not found"})
            await websocket.close(code=4004)
            return

        if session.status != "running" or not session.container_id:
            await websocket.send_json(
                {"type": "error", "data": f"Session is not running (status: {session.status})"}
            )
            await websocket.close(code=4004)
            return

        container_id = session.container_id

    # Resolve the container's IP on the emulation network
    from app.config import get_settings

    settings = get_settings()
    loop = asyncio.get_running_loop()

    try:
        client = await loop.run_in_executor(None, get_docker_client)
        container = await loop.run_in_executor(
            None, client.containers.get, container_id,
        )
        await loop.run_in_executor(None, container.reload)
    except docker.errors.NotFound:
        await websocket.send_json({"type": "error", "data": "Container not found"})
        await websocket.close(code=4004)
        return
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Docker error: {exc}"})
        await websocket.close(code=4004)
        return

    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    net_info = networks.get(settings.emulation_network, {})
    container_ip = net_info.get("IPAddress")

    if not container_ip:
        await websocket.send_json(
            {"type": "error", "data": "Could not resolve container IP on emulation network"}
        )
        await websocket.close(code=4004)
        return

    # Connect TCP socket to the container's port
    tcp_sock = None
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(10)
        await loop.run_in_executor(None, tcp_sock.connect, (container_ip, port))
        tcp_sock.setblocking(False)
    except (ConnectionRefusedError, OSError) as exc:
        await websocket.send_json(
            {"type": "error", "data": f"Cannot connect to {container_ip}:{port} — {exc}"}
        )
        await websocket.close(code=4004)
        if tcp_sock:
            tcp_sock.close()
        return

    await websocket.send_json({
        "type": "output",
        "data": f"\r\n  Connected to system emulation port {port} ({container_ip}:{port})\r\n\r\n",
    })

    async def read_tcp():
        """Read from TCP socket and send to WebSocket."""
        try:
            while True:
                data = await loop.sock_recv(tcp_sock, 4096)
                if not data:
                    break
                await websocket.send_json({
                    "type": "output",
                    "data": data.decode("utf-8", errors="replace"),
                })
        except OSError:
            pass
        except Exception:
            logger.debug("TCP reader stopped", exc_info=True)

    async def write_tcp():
        """Read from WebSocket and write to TCP socket."""
        try:
            while True:
                msg = await websocket.receive_json()
                msg_type = msg.get("type")

                if msg_type == "input":
                    input_data = msg.get("data", "")
                    if input_data:
                        await loop.sock_sendall(
                            tcp_sock, input_data.encode("utf-8"),
                        )
                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            pass
        except Exception:
            logger.debug("TCP writer stopped", exc_info=True)

    async def keepalive():
        """Send periodic pings to keep the WebSocket alive."""
        try:
            while True:
                await asyncio.sleep(15)
                await websocket.send_json({"type": "ping"})
        except Exception:
            pass

    try:
        reader_task = asyncio.create_task(read_tcp())
        writer_task = asyncio.create_task(write_tcp())
        keepalive_task = asyncio.create_task(keepalive())
        done, pending = await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        keepalive_task.cancel()
    finally:
        try:
            tcp_sock.close()
        except Exception:
            pass
        logger.info(
            "System emulation TCP proxy ended: project=%s session=%s port=%d",
            project_id, session_id, port,
        )
