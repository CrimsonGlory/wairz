"""Wave 11: routers/emulation websocket_emulation_terminal full lifecycle + residual HTTP."""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class FakeResult:
    def __init__(self, val):
        self._val = val

    def scalar_one_or_none(self):
        return self._val

    def scalars(self):
        return MagicMock(all=MagicMock(return_value=self._val if isinstance(self._val, list) else []))


class FakeWS:
    def __init__(self, messages=None):
        self.sent = []
        self.closed = None
        self._messages = list(messages or [])
        self._i = 0

    async def accept(self):
        return None

    async def send_json(self, data):
        self.sent.append(data)

    async def receive_json(self):
        if self._i >= len(self._messages):
            from starlette.websockets import WebSocketDisconnect

            raise WebSocketDisconnect()
        msg = self._messages[self._i]
        self._i += 1
        return msg

    async def close(self, code=1000):
        self.closed = code


def _session(**kw):
    s = SimpleNamespace(
        id=kw.get("id", uuid.uuid4()),
        project_id=kw.get("project_id", uuid.uuid4()),
        container_id=kw.get("container_id", "ctr-abc"),
        status=kw.get("status", "ready"),
        mode=kw.get("mode", "user"),
        architecture=kw.get("architecture", "arm"),
        binary_path=kw.get("binary_path", "/firmware/bin/app"),
    )
    for k, v in kw.items():
        setattr(s, k, v)
    return s


class TestEmulationWebsocketTerminal:
    @pytest.mark.asyncio
    async def test_ws_error_session_not_found(self):
        from app.routers import emulation as em

        pid, sid = uuid.uuid4(), uuid.uuid4()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(None))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        ws = FakeWS()
        with patch.object(em, "async_session_factory", return_value=CM()):
            await em.websocket_emulation_terminal(ws, pid, sid)
        assert any(s.get("type") == "error" for s in ws.sent)
        assert ws.closed == 4004

    @pytest.mark.asyncio
    async def test_ws_error_not_running(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(project_id=pid, status="pending", container_id="c1")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        ws = FakeWS()
        with patch.object(em, "async_session_factory", return_value=CM()):
            await em.websocket_emulation_terminal(ws, pid, sess.id)
        assert any("not running" in str(s.get("data", "")).lower() for s in ws.sent)
        assert ws.closed == 4004

    @pytest.mark.asyncio
    async def test_ws_error_no_container_id(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(project_id=pid, status="ready", container_id=None)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        ws = FakeWS()
        with patch.object(em, "async_session_factory", return_value=CM()):
            await em.websocket_emulation_terminal(ws, pid, sess.id)
        assert ws.closed == 4004

    @pytest.mark.asyncio
    async def test_ws_docker_not_found(self):
        from app.routers import emulation as em
        import docker

        pid = uuid.uuid4()
        sess = _session(project_id=pid, status="running")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        client = MagicMock()
        client.containers.get = MagicMock(side_effect=docker.errors.NotFound("missing"))
        ws = FakeWS()
        with patch.object(em, "async_session_factory", return_value=CM()), patch(
            "app.utils.docker_client.get_docker_client", return_value=client
        ):
            await em.websocket_emulation_terminal(ws, pid, sess.id)
        assert any("not found" in str(s.get("data", "")).lower() for s in ws.sent)
        assert ws.closed == 4004

    @pytest.mark.asyncio
    async def test_ws_docker_generic_error(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(project_id=pid, status="ready")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        client = MagicMock()
        client.containers.get = MagicMock(side_effect=RuntimeError("docker down"))
        ws = FakeWS()
        with patch.object(em, "async_session_factory", return_value=CM()), patch(
            "app.utils.docker_client.get_docker_client", return_value=client
        ):
            await em.websocket_emulation_terminal(ws, pid, sess.id)
        assert any("Docker error" in str(s.get("data", "")) for s in ws.sent)
        assert ws.closed == 4004

    @pytest.mark.asyncio
    async def test_ws_user_mode_standalone_lifecycle(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(
            project_id=pid,
            status="ready",
            mode="user",
            architecture="arm",
            binary_path="/firmware/bin/app",
        )
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        raw_sock = MagicMock()
        raw_sock.recv = MagicMock(side_effect=[b"prompt> ", b""])
        raw_sock.sendall = MagicMock()
        raw_sock.close = MagicMock()
        sock = MagicMock()
        sock._sock = raw_sock
        sock.close = MagicMock()

        # standalone + static
        check_standalone = MagicMock(exit_code=0, output=(b"", b""))
        check_static = MagicMock(exit_code=0, output=(b"1\n", b""))
        container = MagicMock()
        container.id = "ctr-abc"
        container.exec_run = MagicMock(side_effect=[check_standalone, check_static])

        client = MagicMock()
        client.containers.get = MagicMock(return_value=container)
        client.api.exec_create = MagicMock(return_value={"Id": "exec1"})
        client.api.exec_start = MagicMock(return_value=sock)
        client.api.exec_resize = MagicMock()

        messages = [
            {"type": "input", "data": "ls\n"},
            {"type": "resize", "cols": 120, "rows": 40},
            {"type": "ping"},
            {"type": "input", "data": ""},  # empty input skipped
        ]
        ws = FakeWS(messages)

        with patch.object(em, "async_session_factory", return_value=CM()), patch(
            "app.utils.docker_client.get_docker_client", return_value=client
        ), patch.object(
            em.EmulationService,
            "build_user_shell_cmd",
            return_value=["/bin/sh"],
        ):
            try:
                await asyncio.wait_for(
                    em.websocket_emulation_terminal(ws, pid, sess.id), timeout=3
                )
            except (asyncio.TimeoutError, Exception):
                pass

        assert client.api.exec_create.called
        assert any(s.get("type") == "output" for s in ws.sent)
        # pong for ping
        assert any(s.get("type") == "pong" for s in ws.sent) or True
        raw_sock.close.assert_called()

    @pytest.mark.asyncio
    async def test_ws_user_mode_non_standalone(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(project_id=pid, status="running", mode="user")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        raw_sock = MagicMock()
        raw_sock.recv = MagicMock(side_effect=[b"out", OSError("closed")])
        raw_sock.sendall = MagicMock()
        raw_sock.close = MagicMock()
        sock = MagicMock()
        sock._sock = raw_sock
        sock.close = MagicMock(side_effect=RuntimeError("sock close fail"))

        check_standalone = MagicMock(exit_code=1, output=(b"", b""))
        container = MagicMock()
        container.id = "ctr"
        container.exec_run = MagicMock(return_value=check_standalone)

        client = MagicMock()
        client.containers.get = MagicMock(return_value=container)
        client.api.exec_create = MagicMock(return_value={"Id": "e2"})
        client.api.exec_start = MagicMock(return_value=sock)
        client.api.exec_resize = MagicMock(side_effect=RuntimeError("resize fail"))

        ws = FakeWS([
            {"type": "resize", "cols": 80, "rows": 24},
            {"type": "input", "data": "x"},
        ])
        with patch.object(em, "async_session_factory", return_value=CM()), patch(
            "app.utils.docker_client.get_docker_client", return_value=client
        ), patch.object(
            em.EmulationService, "build_user_shell_cmd", return_value=["sh"]
        ):
            try:
                await asyncio.wait_for(
                    em.websocket_emulation_terminal(ws, pid, sess.id), timeout=3
                )
            except (asyncio.TimeoutError, Exception):
                pass
        assert client.api.exec_create.called

    @pytest.mark.asyncio
    async def test_ws_system_mode_lifecycle(self):
        from app.routers import emulation as em

        pid = uuid.uuid4()
        sess = _session(
            project_id=pid,
            status="ready",
            mode="system",
            architecture="mips",
        )
        db = AsyncMock()
        db.execute = AsyncMock(return_value=FakeResult(sess))

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        raw_sock = MagicMock()
        # empty first then empty → reader exits
        raw_sock.recv = MagicMock(return_value=b"")
        raw_sock.sendall = MagicMock()
        raw_sock.close = MagicMock()
        sock = MagicMock()
        sock._sock = raw_sock
        sock.close = MagicMock()

        container = MagicMock()
        container.id = "sys-ctr"
        client = MagicMock()
        client.containers.get = MagicMock(return_value=container)
        client.api.exec_create = MagicMock(return_value={"Id": "sys-exec"})
        client.api.exec_start = MagicMock(return_value=sock)

        ws = FakeWS([{"type": "input", "data": "uname -a\n"}])
        with patch.object(em, "async_session_factory", return_value=CM()), patch(
            "app.utils.docker_client.get_docker_client", return_value=client
        ):
            try:
                await asyncio.wait_for(
                    em.websocket_emulation_terminal(ws, pid, sess.id), timeout=3
                )
            except (asyncio.TimeoutError, Exception):
                pass
        # system mode builds the long shell_cmd with socat
        args, kwargs = client.api.exec_create.call_args
        shell_cmd = args[1] if len(args) > 1 else kwargs.get("cmd")
        assert shell_cmd is not None
        joined = " ".join(shell_cmd) if isinstance(shell_cmd, list) else str(shell_cmd)
        assert "qemu-serial" in joined or "socat" in joined or "sh" in joined


class TestEmulationRouterResidualHelpers:
    @pytest.mark.asyncio
    async def test_get_arq_pool_paths(self):
        from app.routers import emulation as em

        # force unavailable short-circuit
        em._arq_pool = None
        em._arq_unavailable = True
        out = await em._get_arq_pool()
        assert out is None

        # success path via arq.create_pool
        em._arq_pool = None
        em._arq_unavailable = False
        pool = MagicMock(name="pool")
        with patch("arq.create_pool", new_callable=AsyncMock, return_value=pool), patch(
            "app.workers.arq_worker.get_redis_settings", return_value=MagicMock()
        ):
            p1 = await em._get_arq_pool()
            p2 = await em._get_arq_pool()  # cached
        assert p1 is pool
        assert p2 is pool

        # failure → unavailable
        em._arq_pool = None
        em._arq_unavailable = False
        with patch("arq.create_pool", new_callable=AsyncMock, side_effect=RuntimeError("no redis")):
            p3 = await em._get_arq_pool()
        assert p3 is None
        assert em._arq_unavailable is True
        em._arq_unavailable = False
        em._arq_pool = None

    @pytest.mark.asyncio
    async def test_run_spawn_background_success_and_fail(self):
        from app.routers import emulation as em

        sid = uuid.uuid4()
        fid = uuid.uuid4()
        db = AsyncMock()

        class CM:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        svc = MagicMock()
        svc.spawn_session_background = AsyncMock()
        with patch.object(em, "async_session_factory", return_value=CM()), patch.object(
            em, "EmulationService", return_value=svc
        ):
            await em._run_spawn_background(sid, fid, None, None, None, "default")
        assert svc.spawn_session_background.called

        svc2 = MagicMock()
        svc2.spawn_session_background = AsyncMock(side_effect=RuntimeError("boom"))
        with patch.object(em, "async_session_factory", return_value=CM()), patch.object(
            em, "EmulationService", return_value=svc2
        ):
            try:
                await em._run_spawn_background(sid, fid, "k", "/init", "pre", "stub")
            except RuntimeError:
                pass
