"""REST and WebSocket endpoints for firmware emulation sessions."""

import asyncio
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.config import get_settings
from app.database import async_session_factory, get_db
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.rate_limit import TIER_B_DOCKER, limiter
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.emulation import (
    EmulationExecRequest,
    EmulationExecResponse,
    EmulationPresetCreate,
    EmulationPresetResponse,
    EmulationPresetUpdate,
    EmulationSessionResponse,
    EmulationStartRequest,
    FirmwareServiceResponse,
    NetworkCaptureRequest,
    NetworkCaptureResponse,
    NvramResponse,
    PcapAnalysisResponse,
    SystemCommandRequest,
    SystemCommandResponse,
    SystemEmulationStartRequest,
    SystemEmulationStatusResponse,
)
from app.services.emulation import EmulationService
from app.services.pcap_analysis_service import PcapAnalysisService
from app.services.system_emulation_service import SystemEmulationService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/emulation",
    tags=["emulation"],
)


# ---------------------------------------------------------------------------
# arq pool (lazy-initialised, with fallback to asyncio.create_task). Mirrors
# the firmware-unpack precedent in `routers/firmware.py` so emulation start
# benefits from the durable worker queue when arq is configured and falls
# back to in-process background tasks otherwise.
# ---------------------------------------------------------------------------
_arq_pool = None
_arq_unavailable = False


async def _get_arq_pool():
    """Return a shared arq connection pool, or None if arq is unavailable."""
    global _arq_pool, _arq_unavailable
    if _arq_unavailable:
        return None
    if _arq_pool is not None:
        return _arq_pool
    try:
        from arq import create_pool

        from app.workers.arq_worker import get_redis_settings
        _arq_pool = await create_pool(get_redis_settings())
        logger.info(
            "arq pool connected for emulation — background spawn will use the worker queue",
        )
        return _arq_pool
    except Exception:
        _arq_unavailable = True
        logger.warning(
            "arq pool unavailable for emulation — falling back to asyncio.create_task",
        )
        return None


async def _run_spawn_background(
    session_id: uuid.UUID,
    firmware_id: uuid.UUID,
    kernel_name: str | None,
    init_path: str | None,
    pre_init_script: str | None,
    stub_profile: str,
) -> None:
    """Detached fallback runner for emulation session spawn.

    Opens its own AsyncSession and calls EmulationService.spawn_session_background,
    which does the heavy Docker work and transitions the DB row through
    pending → booting → ready (or error).
    """
    async with async_session_factory() as db:
        svc = EmulationService(db)
        await svc.spawn_session_background(
            session_id=session_id,
            firmware_id=firmware_id,
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )


@router.post("/start", response_model=EmulationSessionResponse, status_code=202)
@limiter.limit(TIER_B_DOCKER)
async def start_emulation(
    request: Request,
    project_id: uuid.UUID,
    body: EmulationStartRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Start a new emulation session (user-mode or system-mode).

    Returns 202 Accepted with an initial session row at status="pending".
    The heavy work (Docker container boot, QEMU launch, health probe)
    runs in a background task. Callers must poll
    `GET /emulation/{id}/status` and wait for status="ready" before
    attaching the terminal WebSocket. Mirrors the firmware-unpack
    precedent in `routers/firmware.py`.
    """
    svc = EmulationService(db)

    try:
        session = await svc.create_pending_session(
            firmware=firmware,
            mode=body.mode,
            binary_path=body.binary_path,
            arguments=body.arguments,
            port_forwards=[pf.model_dump() for pf in body.port_forwards],
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    # Commit the pending row before returning, so the background task
    # (which opens its own AsyncSession) can find it.
    await db.commit()

    # Schedule the heavy work — prefer arq worker queue, fall back to
    # in-process asyncio.create_task. Whichever path runs, the detached
    # work transitions the row from pending → booting → ready (or error).
    pool = await _get_arq_pool()
    if pool is not None:
        await pool.enqueue_job(
            "spawn_emulation_session_job",
            session_id=str(session.id),
            firmware_id=str(firmware.id),
            kernel_name=body.kernel_name,
            init_path=body.init_path,
            pre_init_script=body.pre_init_script,
            stub_profile=body.stub_profile or "none",
        )
        logger.info(
            "Enqueued spawn_emulation_session_job for session %s via arq",
            session.id,
        )
    else:
        asyncio.create_task(
            _run_spawn_background(
                session_id=session.id,
                firmware_id=firmware.id,
                kernel_name=body.kernel_name,
                init_path=body.init_path,
                pre_init_script=body.pre_init_script,
                stub_profile=body.stub_profile or "none",
            )
        )

    return session


@router.delete("/{session_id}", status_code=204)
async def delete_session(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a stopped or errored emulation session."""
    # Verify session belongs to this project
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = EmulationService(db)
    try:
        await svc.delete_session(session_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post(
    "/{session_id}/stop",
    response_model=EmulationSessionResponse,
)
async def stop_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop an emulation session."""
    # Verify session belongs to this project
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = EmulationService(db)
    try:
        session = await svc.stop_session(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return session


@router.post(
    "/{session_id}/exec",
    response_model=EmulationExecResponse,
)
async def exec_in_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    request: EmulationExecRequest,
    db: AsyncSession = Depends(get_db),
):
    """Execute a command inside a running emulation session."""
    # Verify session belongs to this project
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = EmulationService(db)
    try:
        exec_result = await svc.exec_command(
            session_id=session_id,
            command=request.command,
            timeout=request.timeout,
            environment=request.environment,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return exec_result


@router.get("/sessions", response_model=list[EmulationSessionResponse])
async def list_sessions(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all emulation sessions for this project.

    Also updates status for any sessions that claim to be running —
    detects dead QEMU processes and captures error logs.
    """
    svc = EmulationService(db)
    sessions = await svc.list_sessions(project_id)
    # Update status for running sessions sequentially
    # (AsyncSession is not safe for concurrent coroutine access).
    # "pending" and "booting" are the 202-polling intermediate states;
    # "ready" replaced "running" for sessions started via the async path.
    for i, session in enumerate(sessions):
        if session.status in (
            "running", "starting", "pending", "booting", "ready",
        ):
            try:
                sessions[i] = await svc.get_status(session.id)
            except Exception:
                continue

    return sessions


@router.get("/{session_id}/status", response_model=EmulationSessionResponse)
async def get_session_status(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status of an emulation session."""
    # Verify session belongs to this project
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = EmulationService(db)
    try:
        session = await svc.get_status(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return session


@router.get("/{session_id}/logs")
async def get_session_logs(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get QEMU startup/error logs for an emulation session."""
    # Verify session belongs to this project
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = EmulationService(db)
    try:
        logs = await svc.get_session_logs(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return {"logs": logs}


# ── Emulation Presets ──


@router.post("/presets", response_model=EmulationPresetResponse, status_code=201)
async def create_preset(
    project_id: uuid.UUID,
    request: EmulationPresetCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new emulation preset."""
    svc = EmulationService(db)
    try:
        preset = await svc.create_preset(
            project_id=project_id,
            name=request.name,
            mode=request.mode,
            description=request.description,
            binary_path=request.binary_path,
            arguments=request.arguments,
            architecture=request.architecture,
            port_forwards=[pf.model_dump() for pf in request.port_forwards],
            kernel_name=request.kernel_name,
            init_path=request.init_path,
            pre_init_script=request.pre_init_script,
            stub_profile=request.stub_profile,
        )
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return preset


@router.get("/presets", response_model=list[EmulationPresetResponse])
async def list_presets(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all emulation presets for this project."""
    svc = EmulationService(db)
    return await svc.list_presets(project_id)


@router.get("/presets/{preset_id}", response_model=EmulationPresetResponse)
async def get_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a single emulation preset."""
    # Verify preset belongs to this project
    result = await db.execute(
        select(EmulationPreset).where(EmulationPreset.id == preset_id)
    )
    preset = result.scalar_one_or_none()
    if not preset or preset.project_id != project_id:
        raise HTTPException(404, "Preset not found")

    return preset


@router.patch("/presets/{preset_id}", response_model=EmulationPresetResponse)
async def update_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    request: EmulationPresetUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an emulation preset."""
    # Verify preset belongs to this project
    result = await db.execute(
        select(EmulationPreset).where(EmulationPreset.id == preset_id)
    )
    preset = result.scalar_one_or_none()
    if not preset or preset.project_id != project_id:
        raise HTTPException(404, "Preset not found")

    svc = EmulationService(db)
    try:
        updates = request.model_dump(exclude_unset=True)
        preset = await svc.update_preset(preset_id, updates)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return preset


@router.delete("/presets/{preset_id}", status_code=204)
async def delete_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete an emulation preset."""
    # Verify preset belongs to this project
    result = await db.execute(
        select(EmulationPreset).where(EmulationPreset.id == preset_id)
    )
    preset = result.scalar_one_or_none()
    if not preset or preset.project_id != project_id:
        raise HTTPException(404, "Preset not found")

    svc = EmulationService(db)
    try:
        await svc.delete_preset(preset_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(404, str(exc))


# ── System Emulation (FirmAE) Endpoints ──


@router.post(
    "/system",
    response_model=SystemEmulationStatusResponse,
    status_code=201,
)
@limiter.limit(TIER_B_DOCKER)
async def start_system_emulation(
    request: Request,
    project_id: uuid.UUID,
    body: SystemEmulationStartRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Start FirmAE full system emulation for the project's firmware."""
    settings = get_settings()
    # Use config timeout unless client explicitly overrides (schema default is 600)
    timeout = body.timeout if body.timeout != 600 else settings.system_emulation_pipeline_timeout
    svc = SystemEmulationService(db)
    try:
        session = await svc.start_system_emulation(
            firmware=firmware,
            project_id=project_id,
            brand=body.brand,
            timeout=timeout,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return session


@router.get(
    "/system/{session_id}",
    response_model=SystemEmulationStatusResponse,
)
async def get_system_emulation_status(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status of a system emulation session (polls FirmAE shim)."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        session = await svc.poll_system_status(session_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return session


@router.get(
    "/system/{session_id}/services",
    response_model=list[FirmwareServiceResponse],
)
async def get_system_emulation_services(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List network services discovered on the running firmware."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        services = await svc.get_firmware_services(session_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return services


@router.delete("/system/{session_id}", status_code=204)
async def stop_system_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop a system emulation session and remove the FirmAE sidecar container."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        await svc.stop_system_emulation(session_id)
        await db.flush()
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post(
    "/system/{session_id}/command",
    response_model=SystemCommandResponse,
)
async def run_command_in_system_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    request: SystemCommandRequest,
    db: AsyncSession = Depends(get_db),
):
    """Execute a command inside the FirmAE sidecar (accesses the running firmware)."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        exec_result = await svc.run_command_in_firmware(
            session_id=session_id,
            command=request.command,
            timeout=request.timeout,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return exec_result


@router.post(
    "/system/{session_id}/capture",
    response_model=NetworkCaptureResponse,
)
async def capture_network_traffic(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    request: NetworkCaptureRequest,
    db: AsyncSession = Depends(get_db),
):
    """Capture network traffic from the FirmAE emulated firmware.

    Returns pcap metadata (packet count, file size). Use the
    GET .../pcap endpoint to download the binary pcap for Wireshark.
    """
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        capture_result = await svc.capture_network_traffic(
            session_id=session_id,
            duration=request.duration,
            interface=request.interface,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return capture_result


@router.get(
    "/system/{session_id}/pcap",
)
async def download_pcap(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Download the captured pcap file for Wireshark analysis."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")
    if not session.pcap_path:
        raise HTTPException(404, "No pcap capture available for this session")

    pcap_file = Path(session.pcap_path)
    if not pcap_file.exists():
        raise HTTPException(404, "Pcap file not found on disk")

    return FileResponse(
        path=str(pcap_file),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"capture_{session_id}.pcap",
    )


@router.get(
    "/system/{session_id}/network-analysis",
    response_model=PcapAnalysisResponse,
)
async def analyze_network_traffic(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Analyze captured network traffic -- protocol breakdown, insecure protocols, DNS."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")
    if not session.pcap_path:
        raise HTTPException(404, "No pcap capture available. Capture traffic first.")

    loop = asyncio.get_running_loop()
    svc = PcapAnalysisService()
    try:
        analysis = await loop.run_in_executor(None, svc.analyze_pcap, session.pcap_path)
    except FileNotFoundError:
        raise HTTPException(404, "Pcap file not found on disk")

    total = analysis.total_packets or 1
    return {
        "total_packets": analysis.total_packets,
        "protocol_breakdown": [
            {"protocol": p, "packet_count": c, "percentage": round(c / total * 100, 1)}
            for p, c in sorted(analysis.protocol_breakdown.items(), key=lambda x: -x[1])
        ],
        "conversations": [
            {
                "src": c.src,
                "src_port": c.src_port,
                "dst": c.dst,
                "dst_port": c.dst_port,
                "protocol": c.protocol,
                "packet_count": c.packet_count,
                "byte_count": c.byte_count,
            }
            for c in analysis.conversations
        ],
        "insecure_findings": [
            {
                "protocol": f.protocol,
                "port": f.port,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "packet_count": f.packet_count,
            }
            for f in analysis.insecure_findings
        ],
        "dns_queries": [
            {
                "domain": q.domain,
                "query_type": q.query_type,
                "resolved_ips": q.resolved_ips,
            }
            for q in analysis.dns_queries
        ],
        "tls_info": [
            {
                "server": t.server,
                "port": t.port,
                "version": t.version,
                "cipher_suites": t.cipher_suites,
            }
            for t in analysis.tls_info
        ],
    }


@router.get(
    "/system/{session_id}/nvram",
    response_model=NvramResponse,
)
async def get_nvram_state(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the NVRAM key-value state from the running firmware."""
    result = await db.execute(
        select(EmulationSession).where(EmulationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session or session.project_id != project_id:
        raise HTTPException(404, "Session not found")

    svc = SystemEmulationService(db)
    try:
        nvram = await svc.get_nvram_state(session_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"nvram": nvram}


@router.websocket("/{session_id}/terminal")
async def websocket_emulation_terminal(
    websocket: WebSocket,
    project_id: uuid.UUID,
    session_id: uuid.UUID,
):
    """WebSocket terminal for interactive access to an emulation session.

    Connects to the Docker container's PTY, forwarding input/output
    using the same protocol as the firmware terminal:
      - Client sends: { "type": "input", "data": "<keystrokes>" }
      - Client sends: { "type": "resize", "cols": 80, "rows": 24 }
      - Server sends: { "type": "output", "data": "<text>" }
      - Server sends: { "type": "error", "data": "<message>" }
    """
    await websocket.accept()

    async with async_session_factory() as db:
        # Validate session
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

        # Gate on the post-health-check "ready" status (new 202-polling
        # flow) OR the legacy "running" status (sessions started via the
        # synchronous start_session path for MCP / tests). Rejecting any
        # other status prevents the terminal-WS race: clients that poll
        # must wait for status="ready" before opening the WS, at which
        # point the container has passed its health probe (user-mode:
        # /firmware or /tmp/.standalone_mode observable; system-mode:
        # /tmp/qemu-serial.sock appeared).
        if session.status not in ("running", "ready") or not session.container_id:
            await websocket.send_json(
                {"type": "error", "data": f"Session is not running (status: {session.status})"}
            )
            await websocket.close(code=4004)
            return

    # Connect to the container's exec instance
    import docker

    from app.utils.docker_client import get_docker_client

    try:
        client = get_docker_client()
        container = client.containers.get(session.container_id)
    except docker.errors.NotFound:
        await websocket.send_json({"type": "error", "data": "Container not found"})
        await websocket.close(code=4004)
        return
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Docker error: {exc}"})
        await websocket.close(code=4004)
        return

    # Build the shell command — for user mode, run through QEMU user-mode
    if session.mode == "user":
        # Check if this is a standalone binary session
        standalone_check = container.exec_run(
            ["test", "-f", "/tmp/.standalone_mode"], demux=True,
        )
        is_standalone = standalone_check.exit_code == 0

        if is_standalone:
            static_check = container.exec_run(
                ["cat", "/tmp/.standalone_static"], demux=True,
            )
            is_static = False
            if static_check.exit_code == 0:
                stdout = static_check.output[0] if isinstance(static_check.output, tuple) else static_check.output
                is_static = stdout and stdout.strip() == b"1"

            shell_cmd = EmulationService.build_user_shell_cmd(
                session.architecture or "arm",
                is_standalone=True,
                binary_path=session.binary_path,
                is_static=is_static,
            )
        else:
            shell_cmd = EmulationService.build_user_shell_cmd(session.architecture or "arm")
    else:
        # System mode: wait for QEMU serial socket, then connect via socat.
        # The start-system-mode.sh script creates an ext4 rootfs image and
        # launches QEMU with serial output on /tmp/qemu-serial.sock.
        # Ext4 creation + QEMU startup can take a while, and the socket file
        # may appear before QEMU is ready to accept connections, so we retry.
        shell_cmd = [
            "sh", "-c",
            # Wait for socket file to appear (up to 120s — ext4 creation can be slow)
            "echo 'Waiting for QEMU to start...'; "
            "for i in $(seq 1 120); do "
            "  [ -S /tmp/qemu-serial.sock ] && break; "
            "  if [ $((i % 10)) -eq 0 ]; then echo \"  still waiting... (${i}s)\"; fi; "
            "  sleep 1; "
            "done; "
            "if [ ! -S /tmp/qemu-serial.sock ]; then "
            "  echo ''; echo 'ERROR: QEMU serial socket not found after 120s.'; "
            "  echo ''; echo '--- QEMU startup log ---'; "
            "  cat /tmp/qemu-system.log 2>/dev/null || echo 'No log file found.'; "
            "  echo ''; echo 'The kernel may not be compatible with this QEMU machine type.'; "
            "  echo 'Try uploading a kernel built for QEMU (e.g., from OpenWrt or Buildroot).'; "
            "  sleep 30; exit 1; "
            "fi; "
            # Retry socat connection (socket file may exist before QEMU is listening)
            "for i in $(seq 1 15); do "
            "  socat -,raw,echo=0 UNIX-CONNECT:/tmp/qemu-serial.sock 2>/dev/null && exit 0; "
            "  sleep 2; "
            "done; "
            # All retries failed — show diagnostics
            "echo ''; echo 'Failed to connect to QEMU serial console.'; "
            "echo ''; echo '--- QEMU startup log ---'; "
            "cat /tmp/qemu-system.log 2>/dev/null || echo 'No log file found.'; "
            "echo ''; echo 'QEMU started but the kernel may have crashed immediately.'; "
            "echo 'Firmware kernels are often incompatible with generic QEMU machine types.'; "
            "echo 'Upload a kernel built for QEMU (e.g., from OpenWrt or Buildroot).'; "
            "sleep 30",
        ]

    # Create an interactive exec instance
    exec_id = client.api.exec_create(
        container.id,
        shell_cmd,
        stdin=True,
        tty=True,
        stdout=True,
        stderr=True,
    )

    sock = client.api.exec_start(exec_id, socket=True, tty=True)
    raw_sock = sock._sock  # Get underlying socket

    await websocket.send_json({
        "type": "output",
        "data": f"\r\n  Emulation terminal ({session.mode} mode, {session.architecture})\r\n\r\n",
    })

    loop = asyncio.get_running_loop()

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
                    # Resize is best-effort — may not work for all exec types
                    cols = msg.get("cols", 80)
                    rows = msg.get("rows", 24)
                    try:
                        client.api.exec_resize(exec_id, height=rows, width=cols)
                    except Exception:
                        pass

                elif msg_type == "ping":
                    # Respond to client-side keepalive pings
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
        try:
            raw_sock.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        logger.info(
            "Emulation terminal ended: project=%s session=%s",
            project_id,
            session_id,
        )
