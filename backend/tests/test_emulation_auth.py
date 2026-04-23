"""Tests for emulation router project_id ownership checks.

Every session and preset endpoint that takes a resource ID must verify
that the resource belongs to the project in the URL. These tests confirm
that mismatched project_ids return 404.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(project_id: uuid.UUID, session_id: uuid.UUID) -> MagicMock:
    """Create a mock EmulationSession with the given IDs."""
    session = MagicMock()
    session.id = session_id
    session.project_id = project_id
    session.firmware_id = uuid.uuid4()
    session.mode = "user"
    session.status = "running"
    session.architecture = "arm"
    session.binary_path = "/usr/bin/httpd"
    session.arguments = None
    session.port_forwards = []
    session.container_id = "abc123"
    session.error_message = None
    session.logs = None
    session.started_at = datetime.now(timezone.utc)
    session.stopped_at = None
    session.created_at = datetime.now(timezone.utc)
    session.pid = None
    return session


def _make_preset(project_id: uuid.UUID, preset_id: uuid.UUID) -> MagicMock:
    """Create a mock EmulationPreset with the given IDs."""
    preset = MagicMock()
    preset.id = preset_id
    preset.project_id = project_id
    preset.name = "test-preset"
    preset.description = "A test preset"
    preset.mode = "user"
    preset.binary_path = "/usr/bin/httpd"
    preset.arguments = None
    preset.architecture = "arm"
    preset.port_forwards = []
    preset.kernel_name = None
    preset.init_path = None
    preset.pre_init_script = None
    preset.stub_profile = "none"
    preset.created_at = datetime.now(timezone.utc)
    preset.updated_at = datetime.now(timezone.utc)
    return preset


def _mock_db_execute(return_obj):
    """Create an AsyncMock for db.execute that returns a result with scalar_one_or_none."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = return_obj
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def owner_project_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def other_project_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def session_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def preset_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    """Disable APIKeyASGIMiddleware for this test module.

    When ``settings.api_key`` is falsy the middleware is a no-op
    (see app/middleware/asgi_auth.py lines 59-61). Patching
    ``get_settings`` that the middleware imports makes the test
    environment behave like an unauthenticated dev backend, which
    is the correct shape for endpoint logic tests — the auth layer
    has its own coverage.
    """
    from unittest.mock import MagicMock as _MagicMock

    from app.middleware import asgi_auth as _auth_mod

    fake_settings = _MagicMock()
    fake_settings.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Session ownership tests — mismatched project_id must return 404
# ---------------------------------------------------------------------------

class TestSessionOwnership:
    """Session endpoints must reject requests where the session's project_id
    does not match the URL project_id."""

    @pytest.mark.asyncio
    async def test_delete_session_wrong_project(
        self, client, owner_project_id, other_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        with patch("app.routers.emulation.get_db", return_value=db):
            app.dependency_overrides[__import__("app.database", fromlist=["get_db"]).get_db] = lambda: db
            try:
                resp = await client.delete(
                    f"/api/v1/projects/{other_project_id}/emulation/{session_id}"
                )
                assert resp.status_code == 404
                assert "Session not found" in resp.json()["detail"]
            finally:
                app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_stop_session_wrong_project(
        self, client, owner_project_id, other_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.post(
                f"/api/v1/projects/{other_project_id}/emulation/{session_id}/stop"
            )
            assert resp.status_code == 404
            assert "Session not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_exec_session_wrong_project(
        self, client, owner_project_id, other_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.post(
                f"/api/v1/projects/{other_project_id}/emulation/{session_id}/exec",
                json={"command": "id"},
            )
            assert resp.status_code == 404
            assert "Session not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_status_session_wrong_project(
        self, client, owner_project_id, other_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.get(
                f"/api/v1/projects/{other_project_id}/emulation/{session_id}/status"
            )
            assert resp.status_code == 404
            assert "Session not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logs_session_wrong_project(
        self, client, owner_project_id, other_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.get(
                f"/api/v1/projects/{other_project_id}/emulation/{session_id}/logs"
            )
            assert resp.status_code == 404
            assert "Session not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_delete_session_not_found(
        self, client, other_project_id, session_id
    ):
        """Session that doesn't exist at all returns 404."""
        db = _mock_db_execute(None)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.delete(
                f"/api/v1/projects/{other_project_id}/emulation/{session_id}"
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Session ownership tests — matching project_id (happy path)
# ---------------------------------------------------------------------------

class TestSessionOwnershipHappyPath:
    """Session endpoints should proceed when project_id matches."""

    @pytest.mark.asyncio
    async def test_delete_session_correct_project(
        self, client, owner_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        session.status = "stopped"
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.delete_session = AsyncMock()
                resp = await client.delete(
                    f"/api/v1/projects/{owner_project_id}/emulation/{session_id}"
                )
                assert resp.status_code == 204
                svc_instance.delete_session.assert_called_once_with(session_id)
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_stop_session_correct_project(
        self, client, owner_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        stopped_session = _make_session(owner_project_id, session_id)
        stopped_session.status = "stopped"
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.stop_session = AsyncMock(return_value=stopped_session)
                resp = await client.post(
                    f"/api/v1/projects/{owner_project_id}/emulation/{session_id}/stop"
                )
                assert resp.status_code == 200
                svc_instance.stop_session.assert_called_once_with(session_id)
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_exec_session_correct_project(
        self, client, owner_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        exec_result = MagicMock()
        exec_result.stdout = "uid=0(root)"
        exec_result.stderr = ""
        exec_result.exit_code = 0
        exec_result.timed_out = False

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.exec_command = AsyncMock(return_value=exec_result)
                resp = await client.post(
                    f"/api/v1/projects/{owner_project_id}/emulation/{session_id}/exec",
                    json={"command": "id"},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["stdout"] == "uid=0(root)"
                assert data["exit_code"] == 0
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_status_session_correct_project(
        self, client, owner_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.get_status = AsyncMock(return_value=session)
                resp = await client.get(
                    f"/api/v1/projects/{owner_project_id}/emulation/{session_id}/status"
                )
                assert resp.status_code == 200
                assert resp.json()["id"] == str(session_id)
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logs_session_correct_project(
        self, client, owner_project_id, session_id
    ):
        session = _make_session(owner_project_id, session_id)
        db = _mock_db_execute(session)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.get_session_logs = AsyncMock(return_value="QEMU started OK")
                resp = await client.get(
                    f"/api/v1/projects/{owner_project_id}/emulation/{session_id}/logs"
                )
                assert resp.status_code == 200
                assert resp.json()["logs"] == "QEMU started OK"
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Preset ownership tests — mismatched project_id must return 404
# ---------------------------------------------------------------------------

class TestPresetOwnership:
    """Preset endpoints must reject requests where the preset's project_id
    does not match the URL project_id."""

    @pytest.mark.asyncio
    async def test_get_preset_wrong_project(
        self, client, owner_project_id, other_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.get(
                f"/api/v1/projects/{other_project_id}/emulation/presets/{preset_id}"
            )
            assert resp.status_code == 404
            assert "Preset not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_update_preset_wrong_project(
        self, client, owner_project_id, other_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.patch(
                f"/api/v1/projects/{other_project_id}/emulation/presets/{preset_id}",
                json={"name": "hacked-preset"},
            )
            assert resp.status_code == 404
            assert "Preset not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_delete_preset_wrong_project(
        self, client, owner_project_id, other_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.delete(
                f"/api/v1/projects/{other_project_id}/emulation/presets/{preset_id}"
            )
            assert resp.status_code == 404
            assert "Preset not found" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_get_preset_not_found(
        self, client, other_project_id, preset_id
    ):
        """Preset that doesn't exist returns 404."""
        db = _mock_db_execute(None)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.get(
                f"/api/v1/projects/{other_project_id}/emulation/presets/{preset_id}"
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Preset ownership tests — matching project_id (happy path)
# ---------------------------------------------------------------------------

class TestPresetOwnershipHappyPath:
    """Preset endpoints should proceed when project_id matches."""

    @pytest.mark.asyncio
    async def test_get_preset_correct_project(
        self, client, owner_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            resp = await client.get(
                f"/api/v1/projects/{owner_project_id}/emulation/presets/{preset_id}"
            )
            assert resp.status_code == 200
            assert resp.json()["id"] == str(preset_id)
            assert resp.json()["name"] == "test-preset"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_update_preset_correct_project(
        self, client, owner_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        updated_preset = _make_preset(owner_project_id, preset_id)
        updated_preset.name = "renamed-preset"
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.update_preset = AsyncMock(return_value=updated_preset)
                resp = await client.patch(
                    f"/api/v1/projects/{owner_project_id}/emulation/presets/{preset_id}",
                    json={"name": "renamed-preset"},
                )
                assert resp.status_code == 200
                assert resp.json()["name"] == "renamed-preset"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_delete_preset_correct_project(
        self, client, owner_project_id, preset_id
    ):
        preset = _make_preset(owner_project_id, preset_id)
        db = _mock_db_execute(preset)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: db
        try:
            with patch(
                "app.routers.emulation.EmulationService"
            ) as MockSvc:
                svc_instance = MockSvc.return_value
                svc_instance.delete_preset = AsyncMock()
                resp = await client.delete(
                    f"/api/v1/projects/{owner_project_id}/emulation/presets/{preset_id}"
                )
                assert resp.status_code == 204
                svc_instance.delete_preset.assert_called_once_with(preset_id)
        finally:
            app.dependency_overrides.clear()
