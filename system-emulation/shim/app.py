"""
FirmAE Flask API Shim

REST API that wraps FirmAE's pipeline for integration with the Wairz backend.
Endpoints: /start, /status, /ports, /stop, /health, /events
"""

import json
import logging
import os
import subprocess
import time
import uuid

from flask import Flask, Response, jsonify, request

from pipeline import PipelineManager, PipelinePhase, PipelineState

logger = logging.getLogger(__name__)

# Only accept firmware paths under these container-mounted roots.
# Keep these as plain string literals so CodeQL path-injection can treat
# them as trusted prefixes at isfile/open sinks (realpath()'d values at
# import time are opaque to the dataflow model).
_ALLOWED_FIRMWARE_ROOTS = (
    "/firmware",
    "/data",
    "/tmp",
)


def _validate_firmware_path(firmware_path: str) -> str:
    """Resolve and require the path to stay under an allowed root.

    Collapses ``..`` and symlinks via ``realpath``, then requires a prefix
    match against container-mounted roots. Symlink-correct at runtime by
    comparing against ``realpath(root)``; callers that need a CodeQL-visible
    barrier should re-check the literal roots next to the path sink.
    """
    if not isinstance(firmware_path, str) or not firmware_path:
        raise ValueError("firmware_path outside allowed roots")
    real = os.path.realpath(firmware_path)
    for root in _ALLOWED_FIRMWARE_ROOTS:
        root_real = os.path.realpath(root)
        if real == root_real or real.startswith(root_real + os.sep):
            return real
    raise ValueError("firmware_path outside allowed roots")



# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_pipeline_manager: PipelineManager | None = None
_event_subscribers: list[dict] = []  # [{session_id, queue}]


def _notify_subscribers(state: PipelineState, phase: PipelinePhase) -> None:
    """Push SSE event to all subscribers watching this session."""
    event_data = json.dumps({
        "session_id": state.session_id,
        "phase": phase.value,
        "arch": state.arch,
        "guest_ips": state.guest_ips,
        "network_reachable": state.network_reachable,
        "web_reachable": state.web_reachable,
        "error": state.error,
        "uptime": round(state.uptime, 1),
    })

    dead = []
    for i, sub in enumerate(_event_subscribers):
        if sub["session_id"] == state.session_id or sub["session_id"] is None:
            try:
                sub["queue"].append(event_data)
            except Exception:
                dead.append(i)

    for i in reversed(dead):
        _event_subscribers.pop(i)


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Configure logging
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    firmae_dir = os.environ.get("FIRMAE_DIR", "/opt/FirmAE")

    global _pipeline_manager
    _pipeline_manager = PipelineManager(
        firmae_dir=firmae_dir,
        on_phase_change=_notify_subscribers,
    )

    # -----------------------------------------------------------------------
    # Error handling
    # -----------------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": str(e.description)}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(409)
    def conflict(e):
        return jsonify({"error": str(e.description)}), 409

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Internal server error")
        return jsonify({"error": "Internal server error"}), 500

    # -----------------------------------------------------------------------
    # POST /start — Start FirmAE pipeline
    # -----------------------------------------------------------------------
    @app.route("/start", methods=["POST"])
    def start_pipeline():
        data = request.get_json(silent=True) or {}

        firmware_path = data.get("firmware_path")
        if not firmware_path:
            return jsonify({"error": "firmware_path is required"}), 400

        try:
            firmware_path = _validate_firmware_path(firmware_path)
        except ValueError:
            return jsonify({"error": "firmware_path outside allowed roots"}), 400

        # Re-assert sandbox barrier at the sink: realpath + explicit literal
        # prefix checks in the same function as isfile. Custom helpers and
        # any()-over-tuple forms are not modelled as CodeQL sanitizers, so
        # the checks are expanded and the sink carries an intentional
        # suppression once the barrier has passed.
        real = os.path.realpath(firmware_path)
        if not (
            real == "/firmware"
            or real.startswith("/firmware/")
            or real == "/data"
            or real.startswith("/data/")
            or real == "/tmp"
            or real.startswith("/tmp/")
        ):
            return jsonify({"error": "firmware_path outside allowed roots"}), 400
        # codeql[py/path-injection] — realpath + literal /firmware|/data|/tmp prefix checked above
        if not os.path.isfile(real):
            return jsonify({"error": "Firmware file not found"}), 400
        firmware_path = real

        session_id = data.get("session_id") or str(uuid.uuid4())
        brand = data.get("brand", "unknown")
        timeout = int(data.get("timeout", 600))

        # Clamp timeout to reasonable bounds
        timeout = max(60, min(timeout, 3600))

        try:
            state = _pipeline_manager.start(
                session_id=session_id,
                firmware_path=firmware_path,
                brand=brand,
                timeout=timeout,
            )
        except ValueError:
            # Do not echo exception text — can leak internal path/state details.
            return jsonify({"error": "Pipeline already running or invalid request"}), 409

        def _log_safe(value: object) -> str:
            return str(value).replace("\r", "\\r").replace("\n", "\\n")

        logger.info(
            "Pipeline started: session=%s firmware=%s brand=%s timeout=%ss",
            _log_safe(session_id),
            _log_safe(firmware_path),
            _log_safe(brand),
            _log_safe(timeout),
        )

        return jsonify({
            "session_id": state.session_id,
            "status": "starting",
            "phase": state.phase.value,
        }), 202

    # -----------------------------------------------------------------------
    # GET /status — Pipeline status
    # -----------------------------------------------------------------------
    @app.route("/status", methods=["GET"])
    def get_status():
        session_id = request.args.get("session_id")

        if session_id:
            state = _pipeline_manager.get_session(session_id)
            if state is None:
                return jsonify({"error": f"Session not found: {session_id}"}), 404
            return jsonify(state.to_dict())

        # Return all sessions
        sessions = {
            sid: s.to_dict()
            for sid, s in _pipeline_manager.sessions.items()
        }
        return jsonify({"sessions": sessions})

    # -----------------------------------------------------------------------
    # GET /ports — Discovered services via nmap
    # -----------------------------------------------------------------------
    @app.route("/ports", methods=["GET"])
    def get_ports():
        session_id = request.args.get("session_id")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        state = _pipeline_manager.get_session(session_id)
        if state is None:
            return jsonify({"error": f"Session not found: {session_id}"}), 404

        if not state.guest_ips:
            return jsonify({
                "session_id": session_id,
                "ports": [],
                "message": "No guest IPs discovered yet",
            })

        ports = []
        for ip in state.guest_ips:
            try:
                # Targeted nmap scan: common embedded device ports
                # (top-1000 is too slow inside QEMU cross-arch emulation)
                result = subprocess.run(
                    [
                        "nmap", "-sT", "-sV",
                        "-p", "21,22,23,25,53,80,443,554,8080,8443,161,179,1883,5060,8883",
                        "--open",
                        "-T5",
                        "--max-retries", "0",
                        "-oX", "-",  # XML output to stdout
                        ip,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                # Parse nmap XML output for open ports
                ports.extend(_parse_nmap_output(result.stdout, ip))

            except subprocess.TimeoutExpired:
                logger.warning("nmap scan timed out for IP %s", ip)
            except OSError as exc:
                logger.error("nmap scan failed for IP %s: %s", ip, exc)

        return jsonify({
            "session_id": session_id,
            "guest_ips": state.guest_ips,
            "ports": ports,
        })

    # -----------------------------------------------------------------------
    # POST /stop — Stop emulation
    # -----------------------------------------------------------------------
    @app.route("/stop", methods=["POST"])
    def stop_pipeline():
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        state = _pipeline_manager.get_session(session_id)
        if state is None:
            return jsonify({"error": f"Session not found: {session_id}"}), 404

        success = _pipeline_manager.stop(session_id)

        return jsonify({
            "session_id": session_id,
            "stopped": success,
            "phase": state.phase.value,
        })

    # -----------------------------------------------------------------------
    # GET /health — Container health check
    # -----------------------------------------------------------------------
    @app.route("/health", methods=["GET"])
    def health_check():
        # Check PostgreSQL
        postgres_ok = False
        try:
            result = subprocess.run(
                ["pg_isready", "-p", os.environ.get("PGPORT", "5432")],
                capture_output=True,
                timeout=5,
            )
            postgres_ok = result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Check FirmAE installation
        firmae_dir = os.environ.get("FIRMAE_DIR", "/opt/FirmAE")
        firmae_ready = os.path.isfile(os.path.join(firmae_dir, "run.sh"))

        status_code = 200 if (postgres_ok and firmae_ready) else 503

        return jsonify({
            "postgres_ok": postgres_ok,
            "firmae_ready": firmae_ready,
            "active_sessions": len([
                s for s in _pipeline_manager.sessions.values()
                if not s.is_terminal
            ]) if _pipeline_manager else 0,
        }), status_code

    # -----------------------------------------------------------------------
    # GET /events — Server-Sent Events stream
    # -----------------------------------------------------------------------
    @app.route("/events", methods=["GET"])
    def event_stream():
        session_id = request.args.get("session_id")  # None = all sessions

        queue: list[str] = []
        subscriber = {"session_id": session_id, "queue": queue}
        _event_subscribers.append(subscriber)

        def generate():
            try:
                # Send initial state if session_id specified
                if session_id:
                    state = _pipeline_manager.get_session(session_id)
                    if state:
                        yield f"data: {json.dumps(state.to_dict())}\n\n"

                while True:
                    if queue:
                        event_data = queue.pop(0)
                        yield f"data: {event_data}\n\n"
                    else:
                        # Send keepalive comment every 15s
                        yield ": keepalive\n\n"
                        time.sleep(1)
            except GeneratorExit:
                pass
            finally:
                if subscriber in _event_subscribers:
                    _event_subscribers.remove(subscriber)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # -----------------------------------------------------------------------
    # GET /output — Raw pipeline output (for debugging)
    # -----------------------------------------------------------------------
    @app.route("/output", methods=["GET"])
    def get_output():
        session_id = request.args.get("session_id")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        last_n = int(request.args.get("lines", 100))
        last_n = max(1, min(last_n, 5000))

        lines = _pipeline_manager.get_output(session_id, last_n=last_n)
        if not lines and session_id not in _pipeline_manager.sessions:
            return jsonify({"error": f"Session not found: {session_id}"}), 404

        return jsonify({
            "session_id": session_id,
            "lines": lines,
            "count": len(lines),
        })

    return app


# ---------------------------------------------------------------------------
# nmap XML parser (lightweight, no lxml dependency)
# ---------------------------------------------------------------------------
def _parse_nmap_output(xml_output: str, target_ip: str) -> list[dict]:
    """Parse nmap XML output to extract open port information."""
    import re

    ports = []

    # Match <port> elements with their state and service info.
    # nmap XML format:
    #   <port protocol="tcp" portid="80">
    #     <state state="open" .../>
    #     <service name="http" product="..." version="..." .../>
    #   </port>
    port_pattern = re.compile(
        r'<port\s+protocol="(\w+)"\s+portid="(\d+)">'
        r'.*?<state\s+state="(\w+)"'
        r'(?:.*?<service\s+name="([^"]*)")?',
        re.DOTALL,
    )

    for match in port_pattern.finditer(xml_output):
        protocol = match.group(1)
        port_num = int(match.group(2))
        state = match.group(3)
        service = match.group(4) or "unknown"

        if state == "open":
            ports.append({
                "ip": target_ip,
                "port": port_num,
                "protocol": protocol,
                "service": service,
                "state": state,
            })

    return ports


# ---------------------------------------------------------------------------
# Direct execution (development)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
