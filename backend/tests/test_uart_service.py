"""Service-layer tests for ``app.services.uart_service``.

Phase 2 Wave 9 file 2 of 4 — backfills service-layer tests for the
UART bridge proxy + DB-record manager (254 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Strong canary surface: this service WRITES to the uart_sessions
table AND speaks a JSON-over-newline TCP protocol with a host-side
bridge process. Mock-only tests would verify "asyncio.open_connection
was called" but NOT "the persisted UARTSession row reflects the
right device_path/baudrate/status/transcript_path". Per Rule #35b,
the live canary opens a real in-memory SQLite session, mocks
``asyncio.open_connection`` with a fake StreamReader/StreamWriter
that round-trips the JSON protocol, runs UARTService methods, then
SELECTs the persisted row to inspect every field.

Rule #30 distribution: ``asyncio``, ``json``, ``select``, and the
ORM model ``UARTSession`` are all TOP-LEVEL imported at module
scope. ``get_settings`` is also TOP-LEVEL. Inverse-Rule-30 shape:
patches MUST hit the CONSUMER module
(``app.services.uart_service.asyncio.open_connection``,
``app.services.uart_service.get_settings``).

Coverage targets:

* ``UARTService.connect`` — happy path: bridge ack returns
  transcript_path; ORM row persisted with status='connected',
  baudrate, device_path, transcript_path; flush makes the row
  SELECT-able within the same session.
* ``UARTService.connect`` — already-active session raises
  ValueError (single-session-per-project invariant).
* ``UARTService.send_command`` — no active session → ValueError;
  happy path: zero-or-negative timeout reads from settings;
  positive timeout passed through; protocol carries command +
  prompt + timeout.
* ``UARTService.read_buffer`` — no active session → ValueError;
  happy path returns the bridge result dict.
* ``UARTService.send_break`` — no active session → ValueError;
  happy path passes through.
* ``UARTService.send_raw`` — no active session → ValueError;
  happy path: hex_mode kwarg propagates.
* ``UARTService.get_status`` — bridge unreachable returns
  graceful payload with bridge_error; session-aware payload
  includes session metadata; no-session bridge-only payload.
* ``UARTService.disconnect`` — no active session → ValueError;
  bridge-unreachable still marks DB row closed (regression
  backstop for "user can't disconnect because bridge is down");
  bridge-reachable disconnect updates status=closed + closed_at.
* ``UARTService.get_transcript`` — no active session →
  ValueError; happy path passes tail_lines.
* ``UARTService.list_sessions`` — returns ordered DESC by
  created_at.
* ``_bridge_request`` — JSON protocol assembly (request encoded
  with newline terminator); bridge ack with ok=True returns the
  parsed response; ok=False raises ValueError; empty line raises
  ConnectionError; OSError on open_connection raises
  ConnectionError.
* **Rule #35b live canary** — full SQLite + fake-bridge
  round-trip: connect → send_command → disconnect; SELECT
  UARTSession row at each stage to verify status transitions
  (connected → closed) and closed_at populated.
* **Rule #30 inverse-consumer-patch class** — sentinels prove
  asyncio + get_settings + UARTSession are bound at module scope
  on the consumer; failure signals a future refactor that flips
  to lazy imports.
"""
from __future__ import annotations

import asyncio as real_asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.project import Project
from app.models.uart_session import UARTSession
from app.services import uart_service as uart_mod
from app.services.uart_service import UARTService

from tests._live_db import make_live_db


# ===========================================================================
# Fake bridge — drop-in replacement for asyncio.open_connection
# ===========================================================================


class _FakeWriter:
    """Captures one JSON request, returns one JSON response."""

    def __init__(self, response: dict, capture: list):
        self._response = response
        self._capture = capture
        self.closed = False

    def write(self, data: bytes) -> None:
        self._capture.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _FakeReader:
    def __init__(self, payload: bytes):
        self._payload = payload
        self._consumed = False

    async def readline(self) -> bytes:
        if self._consumed:
            return b""
        self._consumed = True
        return self._payload


def _patch_bridge(
    response: dict | None = None,
    *,
    open_exc: Exception | None = None,
    empty_line: bool = False,
    capture: list | None = None,
):
    """Return a context-manager that patches ``asyncio.open_connection``
    on the uart_service consumer module. The fake writer's request bytes
    accumulate in ``capture`` if provided.
    """
    if capture is None:
        capture = []

    if open_exc is not None:
        async def _raise(host, port):  # noqa: ARG001
            raise open_exc
        return patch.object(uart_mod.asyncio, "open_connection", side_effect=_raise), capture

    payload = b"" if empty_line else (json.dumps(response or {"ok": True}).encode() + b"\n")

    async def _fake_open(host, port):  # noqa: ARG001
        reader = _FakeReader(payload)
        writer = _FakeWriter(response or {"ok": True}, capture)
        return reader, writer

    return patch.object(uart_mod.asyncio, "open_connection", side_effect=_fake_open), capture


def _settings_mock(host: str = "host.docker.internal", port: int = 9999, timeout: int = 30) -> MagicMock:
    s = MagicMock()
    s.uart_bridge_host = host
    s.uart_bridge_port = port
    s.uart_command_timeout = timeout
    return s


# ===========================================================================
# Fixtures
# ===========================================================================


async def _seed_project_and_firmware(db) -> tuple[Project, Firmware]:
    pid = uuid.uuid4()
    project = Project(id=pid, name="uart-test", status="ready")
    db.add(project)
    await db.flush()
    firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="u" * 64)
    db.add(firmware)
    await db.flush()
    return project, firmware


# ===========================================================================
# UARTService.connect
# ===========================================================================


class TestConnect:
    @pytest.mark.asyncio
    async def test_happy_path_persists_session_row(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)

            response = {
                "ok": True,
                "result": {"transcript_path": "/host/transcripts/abc.log"},
            }
            ctx, capture = _patch_bridge(response)

            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    session = await svc.connect(
                        project_id=project.id,
                        firmware_id=firmware.id,
                        device_path="/dev/ttyUSB0",
                        baudrate=115200,
                    )
            await db.commit()

            # Live-canary: SELECT the persisted row.
            row = (await db.execute(
                select(UARTSession).where(UARTSession.id == session.id)
            )).scalar_one()
            assert row.project_id == project.id
            assert row.firmware_id == firmware.id
            assert row.device_path == "/dev/ttyUSB0"
            assert row.baudrate == 115200
            assert row.status == "connected"
            assert row.transcript_path == "/host/transcripts/abc.log"
            assert row.connected_at is not None
            assert row.closed_at is None

            # Bridge protocol: request was a JSON line ending in \n.
            assert len(capture) == 1
            request_bytes = capture[0]
            assert request_bytes.endswith(b"\n")
            parsed = json.loads(request_bytes.decode().strip())
            assert parsed["method"] == "connect"
            assert parsed["params"]["device"] == "/dev/ttyUSB0"
            assert parsed["params"]["baudrate"] == 115200

    @pytest.mark.asyncio
    async def test_connect_with_existing_active_session_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)

            # Pre-existing connected session.
            existing = UARTSession(
                project_id=project.id,
                firmware_id=firmware.id,
                device_path="/dev/ttyUSB0",
                baudrate=115200,
                status="connected",
                connected_at=datetime.now(timezone.utc),
            )
            db.add(existing)
            await db.flush()

            svc = UARTService(db)
            with pytest.raises(ValueError) as exc_info:
                await svc.connect(
                    project_id=project.id,
                    firmware_id=firmware.id,
                    device_path="/dev/ttyUSB1",
                )
            assert "already has an active UART session" in str(exc_info.value)
            assert "/dev/ttyUSB0" in str(exc_info.value)


# ===========================================================================
# UARTService.send_command
# ===========================================================================


class TestSendCommand:
    @pytest.mark.asyncio
    async def test_no_active_session_raises(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            svc = UARTService(db)
            with pytest.raises(ValueError) as exc:
                await svc.send_command(project.id, "ls")
            assert "No active UART session" in str(exc.value)

    @pytest.mark.asyncio
    async def test_zero_timeout_uses_settings_default(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            response = {"ok": True, "result": {"output": "done\n"}}
            ctx, capture = _patch_bridge(response)

            with patch.object(uart_mod, "get_settings", lambda: _settings_mock(timeout=99)):
                with ctx:
                    svc = UARTService(db)
                    result = await svc.send_command(project.id, "ls", timeout=0)

            assert result == {"output": "done\n"}
            parsed = json.loads(capture[0].decode().strip())
            assert parsed["method"] == "send_command"
            # zero/negative timeout coerced to settings.uart_command_timeout
            assert parsed["params"]["timeout"] == 99
            assert parsed["params"]["command"] == "ls"
            assert parsed["params"]["prompt"] == "# "

    @pytest.mark.asyncio
    async def test_positive_timeout_passes_through(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            ctx, capture = _patch_bridge({"ok": True, "result": {}})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    await svc.send_command(project.id, "uname", timeout=45, prompt="$ ")

            parsed = json.loads(capture[0].decode().strip())
            assert parsed["params"]["timeout"] == 45
            assert parsed["params"]["prompt"] == "$ "


# ===========================================================================
# UARTService.read_buffer / send_break / send_raw
# ===========================================================================


class TestReadBufferBreakRaw:
    @pytest.mark.asyncio
    async def test_read_buffer_no_session_raises(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            svc = UARTService(db)
            with pytest.raises(ValueError):
                await svc.read_buffer(project.id)

    @pytest.mark.asyncio
    async def test_read_buffer_happy_path(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            response = {"ok": True, "result": {"data": "buffered text"}}
            ctx, capture = _patch_bridge(response)
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    result = await svc.read_buffer(project.id, timeout=5)
            assert result == {"data": "buffered text"}
            parsed = json.loads(capture[0].decode().strip())
            assert parsed["method"] == "read"
            assert parsed["params"]["timeout"] == 5

    @pytest.mark.asyncio
    async def test_send_break_no_session_raises(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            svc = UARTService(db)
            with pytest.raises(ValueError):
                await svc.send_break(project.id)

    @pytest.mark.asyncio
    async def test_send_break_happy_path(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            ctx, capture = _patch_bridge({"ok": True, "result": {"sent": True}})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    result = await svc.send_break(project.id)
            assert result == {"sent": True}
            parsed = json.loads(capture[0].decode().strip())
            assert parsed["method"] == "send_break"

    @pytest.mark.asyncio
    async def test_send_raw_propagates_hex_mode(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            ctx, capture = _patch_bridge({"ok": True, "result": {}})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    await svc.send_raw(project.id, "deadbeef", hex_mode=True)
            parsed = json.loads(capture[0].decode().strip())
            assert parsed["method"] == "send_raw"
            assert parsed["params"]["data"] == "deadbeef"
            assert parsed["params"]["hex"] is True


# ===========================================================================
# UARTService.get_status
# ===========================================================================


class TestGetStatus:
    @pytest.mark.asyncio
    async def test_bridge_unreachable_returns_graceful_payload(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            ctx, _ = _patch_bridge(open_exc=OSError("connection refused"))
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    status = await svc.get_status(project.id)
            assert status["connected"] is False
            assert status["bridge_error"] == "Bridge unreachable"
            # No active session → no session sub-object
            assert "session" not in status

    @pytest.mark.asyncio
    async def test_with_session_includes_session_metadata(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            sess = UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            )
            db.add(sess)
            await db.flush()

            response = {
                "ok": True,
                "result": {
                    "connected": True, "device": "/dev/ttyUSB0",
                    "baudrate": 115200, "buffer_bytes": 42,
                    "transcript_path": "/host/x.log",
                },
            }
            ctx, _ = _patch_bridge(response)
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    status = await svc.get_status(project.id)

            assert status["connected"] is True
            assert status["buffer_bytes"] == 42
            assert status["session"]["id"] == str(sess.id)
            assert status["session"]["status"] == "connected"
            assert status["session"]["device_path"] == "/dev/ttyUSB0"
            assert status["session"]["baudrate"] == 115200


# ===========================================================================
# UARTService.disconnect
# ===========================================================================


class TestDisconnect:
    @pytest.mark.asyncio
    async def test_no_active_session_raises(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            svc = UARTService(db)
            with pytest.raises(ValueError):
                await svc.disconnect(project.id)

    @pytest.mark.asyncio
    async def test_bridge_reachable_marks_session_closed(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            sess = UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            )
            db.add(sess)
            await db.flush()

            ctx, _ = _patch_bridge({"ok": True, "result": {}})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    closed = await svc.disconnect(project.id)
            await db.commit()

            row = (await db.execute(
                select(UARTSession).where(UARTSession.id == sess.id)
            )).scalar_one()
            assert closed.id == sess.id
            assert row.status == "closed"
            assert row.closed_at is not None

    @pytest.mark.asyncio
    async def test_bridge_unreachable_still_closes_db_row(self):
        """Regression backstop: user must be able to disconnect even when
        the bridge has crashed / been killed externally."""
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            sess = UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            )
            db.add(sess)
            await db.flush()

            ctx, _ = _patch_bridge(open_exc=OSError("connection refused"))
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    closed = await svc.disconnect(project.id)
            await db.commit()

            row = (await db.execute(
                select(UARTSession).where(UARTSession.id == sess.id)
            )).scalar_one()
            assert row.status == "closed"
            assert row.closed_at is not None
            assert closed.status == "closed"


# ===========================================================================
# UARTService.get_transcript
# ===========================================================================


class TestGetTranscript:
    @pytest.mark.asyncio
    async def test_no_session_raises(self):
        async with make_live_db() as db:
            project, _ = await _seed_project_and_firmware(db)
            svc = UARTService(db)
            with pytest.raises(ValueError):
                await svc.get_transcript(project.id)

    @pytest.mark.asyncio
    async def test_passes_tail_lines(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            db.add(UARTSession(
                project_id=project.id, firmware_id=firmware.id,
                device_path="/dev/ttyUSB0", baudrate=115200,
                status="connected", connected_at=datetime.now(timezone.utc),
            ))
            await db.flush()

            ctx, capture = _patch_bridge({
                "ok": True,
                "result": {"lines": ["a", "b", "c"]},
            })
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    result = await svc.get_transcript(project.id, tail_lines=50)
            assert result == {"lines": ["a", "b", "c"]}
            parsed = json.loads(capture[0].decode().strip())
            assert parsed["method"] == "get_transcript"
            assert parsed["params"]["tail_lines"] == 50


# ===========================================================================
# UARTService.list_sessions
# ===========================================================================


class TestListSessions:
    @pytest.mark.asyncio
    async def test_returns_descending_by_created_at(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)
            # Use explicit created_at offsets — SQLite resolves func.now()
            # at the same microsecond for all 3 rows when seeded in a tight
            # loop, which makes ORDER BY created_at DESC unstable.
            from datetime import timedelta
            base = datetime.now(timezone.utc)
            for i, path in enumerate(("/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2")):
                db.add(UARTSession(
                    project_id=project.id, firmware_id=firmware.id,
                    device_path=path, baudrate=115200,
                    status="closed",
                    connected_at=base,
                    created_at=base + timedelta(seconds=i),
                ))
                await db.flush()

            svc = UARTService(db)
            sessions = await svc.list_sessions(project.id)
            assert len(sessions) == 3
            # ttyUSB2 has the latest created_at → first under DESC.
            paths = [s.device_path for s in sessions]
            assert paths == ["/dev/ttyUSB2", "/dev/ttyUSB1", "/dev/ttyUSB0"]


# ===========================================================================
# _bridge_request — protocol-level error matrix
# ===========================================================================


class TestBridgeRequest:
    @pytest.mark.asyncio
    async def test_open_connection_failure_raises_connection_error(self):
        async with make_live_db() as db:
            ctx, _ = _patch_bridge(open_exc=OSError("network down"))
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    with pytest.raises(ConnectionError) as exc:
                        await svc._bridge_request({"method": "ping", "params": {}})
            assert "Cannot reach UART bridge" in str(exc.value)
            assert "network down" in str(exc.value)

    @pytest.mark.asyncio
    async def test_empty_response_raises_connection_error(self):
        async with make_live_db() as db:
            ctx, _ = _patch_bridge({"ok": True}, empty_line=True)
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    with pytest.raises(ConnectionError) as exc:
                        await svc._bridge_request({"method": "ping", "params": {}})
            assert "without response" in str(exc.value)

    @pytest.mark.asyncio
    async def test_ok_false_raises_value_error(self):
        async with make_live_db() as db:
            ctx, _ = _patch_bridge({"ok": False, "error": "device busy"})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    with pytest.raises(ValueError) as exc:
                        await svc._bridge_request({"method": "ping", "params": {}})
            assert "device busy" in str(exc.value)


# ===========================================================================
# Rule #35b multi-step live canary: connect → send_command → disconnect
# ===========================================================================


class TestFullLifecycleLiveCanary:
    @pytest.mark.asyncio
    async def test_connect_send_disconnect_status_transitions(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_and_firmware(db)

            # Stage 1: connect.
            ctx, _ = _patch_bridge({
                "ok": True,
                "result": {"transcript_path": "/host/uart-1.log"},
            })
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    svc = UARTService(db)
                    session = await svc.connect(
                        project_id=project.id,
                        firmware_id=firmware.id,
                        device_path="/dev/ttyUSB0",
                        baudrate=115200,
                    )
            await db.commit()

            row1 = (await db.execute(
                select(UARTSession).where(UARTSession.id == session.id)
            )).scalar_one()
            assert row1.status == "connected"
            assert row1.transcript_path == "/host/uart-1.log"

            # Stage 2: send a command.
            ctx, _ = _patch_bridge({
                "ok": True, "result": {"output": "Linux"},
            })
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    res = await svc.send_command(project.id, "uname", timeout=10)
            assert res == {"output": "Linux"}

            # Status row is unchanged after send.
            row2 = (await db.execute(
                select(UARTSession).where(UARTSession.id == session.id)
            )).scalar_one()
            assert row2.status == "connected"

            # Stage 3: disconnect.
            ctx, _ = _patch_bridge({"ok": True, "result": {}})
            with patch.object(uart_mod, "get_settings", lambda: _settings_mock()):
                with ctx:
                    closed = await svc.disconnect(project.id)
            await db.commit()

            row3 = (await db.execute(
                select(UARTSession).where(UARTSession.id == session.id)
            )).scalar_one()
            assert row3.status == "closed"
            assert row3.closed_at is not None
            assert closed.id == session.id


# ===========================================================================
# Rule #30 inverse-consumer-patch sentinels
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Document that uart_service binds asyncio + get_settings + UARTSession
    at module scope; patches MUST hit the consumer module.
    """

    def test_consumer_module_binds_asyncio(self):
        assert hasattr(uart_mod, "asyncio")

    def test_consumer_module_binds_get_settings(self):
        # `from app.config import get_settings` at line 16.
        assert hasattr(uart_mod, "get_settings")

    def test_consumer_module_binds_uart_session_orm(self):
        # `from app.models.uart_session import UARTSession` at line 17.
        assert hasattr(uart_mod, "UARTSession")

    def test_consumer_module_binds_select(self):
        assert hasattr(uart_mod, "select")
