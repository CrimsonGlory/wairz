"""HTTP-layer tests for ``app.routers.ghidra_research``.

Per CLAUDE.md: every new router gets a test file covering:
- Validation branches (400 / 404 / 409)
- Happy-path response-schema assertion
- Rule #35b live canary via make_live_db round-trip
"""
from __future__ import annotations

import io
import uuid
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import get_settings
from app.database import get_db
from app.main import app
from app.models.ghidra_research import GhidraResearchFile
from app.models.project import Project
from app.rate_limit import limiter
from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    prior = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    try:
        yield
    finally:
        limiter.enabled = prior


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.clear()


@pytest.fixture
async def client():
    # Pre-attach X-API-Key so the APIKeyASGIMiddleware gate in
    # app/middleware/asgi_auth.py doesn't return 401 on every request.
    # get_settings() is @lru_cache'd and reads API_KEY from the container env.
    # Also send Host: localhost so origin_host_guard (app/main.py) passes
    # through — it blocks requests with host "test" which is httpx's default.
    api_key = get_settings().api_key or ""
    headers: dict[str, str] = {"Host": "localhost"}
    if api_key:
        headers["X-API-Key"] = api_key
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost", headers=headers,
    ) as c:
        yield c


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


@pytest.fixture
async def project_id(live_db):
    project = Project(
        id=uuid.uuid4(),
        name="Test Project",
        description=None,
        status="active",
    )
    live_db.add(project)
    await live_db.commit()
    return str(project.id)


def _make_fake_db(live_db):
    async def _override():
        yield live_db
    return _override


# ---------------------------------------------------------------------------
# 404 — project not found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_unknown_project_returns_404(client):
    bad_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/projects/{bad_id}/ghidra-research")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 400 — bad extension
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_bad_extension_returns_400(client, live_db, project_id):
    app.dependency_overrides[get_db] = _make_fake_db(live_db)
    resp = await client.post(
        f"/api/v1/projects/{project_id}/ghidra-research",
        files={"file": ("malware.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 409 — double-import conflict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trigger_import_409_when_already_queued(client, live_db, project_id):
    app.dependency_overrides[get_db] = _make_fake_db(live_db)

    # Seed a .gzf record in queued state directly
    file_id = uuid.uuid4()
    record = GhidraResearchFile(
        id=file_id,
        project_id=uuid.UUID(project_id),
        original_filename="research.gzf",
        file_category="ghidra_archive",
        content_type="application/octet-stream",
        file_size=1024,
        sha256="a" * 64,
        storage_path="/tmp/research.gzf",
        import_status="queued",
    )
    live_db.add(record)
    await live_db.commit()

    resp = await client.post(
        f"/api/v1/projects/{project_id}/ghidra-research/{file_id}/import"
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Happy path — upload .py script + response schema
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_python_script_happy_path(client, live_db, project_id, tmp_path):
    app.dependency_overrides[get_db] = _make_fake_db(live_db)

    # Patch storage_root to tmp_path so file writes go to a safe location
    import app.config as _cfg
    orig = _cfg.get_settings
    fake_settings = MagicMock()
    fake_settings.storage_root = str(tmp_path)
    _cfg.get_settings = lambda: fake_settings

    try:
        resp = await client.post(
            f"/api/v1/projects/{project_id}/ghidra-research",
            files={"file": ("analyze.py", io.BytesIO(b"# analysis script"), "text/plain")},
            data={"description": "My analysis script"},
        )
    finally:
        _cfg.get_settings = orig

    assert resp.status_code == 201
    body = resp.json()
    assert body["original_filename"] == "analyze.py"
    assert body["file_category"] == "python_script"
    assert body["import_status"] == "idle"
    assert body["import_result"] is None
    assert "id" in body
    assert "project_id" in body


# ---------------------------------------------------------------------------
# Rule #35b live canary — ORM round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_canary_persists_correct_fields(live_db, project_id):
    """Seed a GhidraResearchFile row directly and verify persisted fields."""
    file_id = uuid.uuid4()
    record = GhidraResearchFile(
        id=file_id,
        project_id=uuid.UUID(project_id),
        original_filename="firmware_analysis.py",
        file_category="python_script",
        content_type="text/plain",
        file_size=512,
        sha256="b" * 64,
        storage_path="/tmp/firmware_analysis.py",
        import_status="idle",
    )
    live_db.add(record)
    await live_db.commit()

    # SELECT and verify all critical fields round-tripped correctly
    result = await live_db.execute(
        select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
    )
    row = result.scalar_one()
    assert row.original_filename == "firmware_analysis.py"
    assert row.file_category == "python_script"
    assert row.import_status == "idle"
    assert row.import_result is None
    assert row.import_error is None
    assert row.sha256 == "b" * 64
    assert row.file_size == 512
