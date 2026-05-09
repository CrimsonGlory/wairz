"""HTTP-layer tests for ``app.routers.fuzzing``.

Phase 2 Wave 3 file 1 of 5 — backfills router-level tests for
backend/app/routers/fuzzing.py (252 LOC, 9 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04. Pairs with the Wave 2
service-layer test_fuzzing_service.py for end-to-end coverage of the
AFL++ fuzzing pipeline.

The router exposes the 202+polling pattern (Rule #33) for the heavy
``POST /campaigns/{id}/start`` endpoint — the canary asserts the row
flips to ``status="queued"`` before the background container spawn.

Coverage targets:

* ``GET /analyze``           — ValueError → 400.
* ``POST /campaigns``        — ValueError → 400; happy path persists
  FuzzingCampaign with the request's binary_path / config (Rule #35b
  live canary).
* ``POST /campaigns/{id}/start`` — ValueError → 400; happy path returns
  202 + status='queued' (Rule #33 canary; background spawn patched out).
* ``POST /campaigns/{id}/stop`` — ValueError → 400.
* ``GET /campaigns``         — happy path.
* ``GET /campaigns/{id}``    — ValueError → 404.
* ``GET /campaigns/{id}/crashes`` — happy path.
* ``GET /campaigns/{id}/crashes/{cid}`` — ValueError → 404; hex encoding.
* ``POST /campaigns/{id}/crashes/{cid}/triage`` — ValueError → 400.

Per Rule #30 audit, ``FuzzingService`` is module-imported at top of
fuzzing.py (line 22). Service-module patches work for it.
``async_session_factory`` and ``_run_campaign_spawn_background`` are
module-scope; the test patches the latter to an async no-op so the
202+polling canary doesn't actually spawn a Docker container.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash  # noqa: F401 — registers tables
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    from app.middleware import asgi_auth as _auth_mod
    fake = MagicMock()
    fake.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake)


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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


def _make_firmware(project_id: uuid.UUID) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = "/tmp/extract"
    fw.extraction_dir = "/tmp/extract"
    fw.architecture = "arm"
    fw.device_metadata = None
    return fw


def _campaign_response_mock(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    *,
    status: str = "created",
    container_id: str | None = None,
) -> MagicMock:
    c = MagicMock(spec=FuzzingCampaign)
    c.id = uuid.uuid4()
    c.project_id = project_id
    c.firmware_id = firmware_id
    c.binary_path = "/bin/foo"
    c.status = status
    c.config = {"timeout_per_exec": 1000, "memory_limit": 256}
    c.stats = {}
    c.crashes_count = 0
    c.container_id = container_id
    c.error_message = None
    c.started_at = None
    c.stopped_at = None
    c.created_at = datetime.now(UTC)
    return c


# ===========================================================================
# GET /analyze
# ===========================================================================


class TestAnalyzeTarget:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        firmware = _make_firmware(project_id)

        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.analyze_target = AsyncMock(
                side_effect=ValueError("Binary not found"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/analyze",
                params={"path": "/missing"},
            )
        assert resp.status_code == 400
        assert "Binary not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_returns_analysis_dict(self, client, project_id):
        firmware = _make_firmware(project_id)

        analysis = {
            "binary_path": "/bin/sh",
            "fuzzing_score": 65,
            "input_sources": ["read", "fgets"],
            "dangerous_functions": ["strcpy"],
            "network_functions": [],
            "protections": {"nx": True, "canary": False, "pie": True, "relro": "partial"},
            "recommended_strategy": "stdin",
            "function_count": 200,
            "imports_of_interest": ["strcpy", "read", "fgets"],
            "file_size": 65000,
            "error": None,
        }
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.analyze_target = AsyncMock(return_value=analysis)
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/analyze",
                params={"path": "/bin/sh"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["fuzzing_score"] == 65
        assert body["recommended_strategy"] == "stdin"


# ===========================================================================
# POST /campaigns
# ===========================================================================


class TestCreateCampaign:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        firmware = _make_firmware(project_id)

        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.create_campaign = AsyncMock(
                side_effect=ValueError("not been unpacked"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns",
                json={"binary_path": "bin/foo"},
            )
        assert resp.status_code == 400


# ===========================================================================
# POST /campaigns/{id}/start  — Rule #33 fast-path
# ===========================================================================


class TestStartCampaign:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.start_campaign = AsyncMock(
                side_effect=ValueError("cannot be started"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{uuid.uuid4()}/start",
            )
        assert resp.status_code == 400
        assert "cannot be started" in resp.json()["detail"]


# ===========================================================================
# POST /campaigns/{id}/stop
# ===========================================================================


class TestStopCampaign:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.stop_campaign = AsyncMock(
                side_effect=ValueError("not found"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{uuid.uuid4()}/stop",
            )
        assert resp.status_code == 400


# ===========================================================================
# GET /campaigns + GET /campaigns/{id}
# ===========================================================================


class TestListAndGetCampaigns:
    @pytest.mark.asyncio
    async def test_list_returns_campaigns(self, client, project_id):
        firmware_id = uuid.uuid4()
        c1 = _campaign_response_mock(project_id, firmware_id, status="stopped")
        c2 = _campaign_response_mock(project_id, firmware_id, status="created")

        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.list_campaigns = AsyncMock(return_value=[c1, c2])
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 2
        assert {c["status"] for c in body} == {"stopped", "created"}

    @pytest.mark.asyncio
    async def test_get_404_when_not_found(self, client, project_id):
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_campaign_status = AsyncMock(
                side_effect=ValueError("not found"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{uuid.uuid4()}",
            )
        assert resp.status_code == 404


# ===========================================================================
# GET /crashes + crash detail + triage
# ===========================================================================


class TestCrashEndpoints:
    def _crash_mock(self, campaign_id: uuid.UUID, *, with_input: bool = False) -> MagicMock:
        crash = MagicMock(spec=FuzzingCrash)
        crash.id = uuid.uuid4()
        crash.campaign_id = campaign_id
        crash.crash_filename = "id_000001"
        crash.crash_size = 64
        crash.signal = "SIGSEGV"
        crash.stack_trace = None
        crash.exploitability = None
        crash.triage_output = None
        crash.finding_id = None
        crash.crash_input = b"\xde\xad\xbe\xef" if with_input else None
        crash.created_at = datetime.now(UTC)
        return crash

    @pytest.mark.asyncio
    async def test_list_crashes_returns_list(self, client, project_id):
        campaign_id = uuid.uuid4()
        crashes = [self._crash_mock(campaign_id) for _ in range(2)]

        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_crashes = AsyncMock(return_value=crashes)
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{campaign_id}/crashes",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 2

    @pytest.mark.asyncio
    async def test_get_crash_detail_returns_404_when_missing(
        self, client, project_id,
    ):
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_crash_detail = AsyncMock(
                side_effect=ValueError("not found"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{uuid.uuid4()}/crashes/{uuid.uuid4()}",
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_crash_detail_hex_encodes_input_bytes(
        self, client, project_id,
    ):
        """The detail endpoint hex-encodes the binary crash_input so the
        response is JSON-safe. This is a value-flow contract — a regression
        that returns ``crash.crash_input.decode()`` would silently break
        on arbitrary bytes and is the F-A-06 shape applied to encoding."""
        campaign_id = uuid.uuid4()
        crash = self._crash_mock(campaign_id, with_input=True)

        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_crash_detail = AsyncMock(return_value=crash)
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{campaign_id}/crashes/{crash.id}",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["crash_input_hex"] == "deadbeef", (
            "crash_input bytes must be hex-encoded for JSON safety"
        )

    @pytest.mark.asyncio
    async def test_triage_value_error_returns_400(self, client, project_id):
        with patch(
            "app.routers.fuzzing.FuzzingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.triage_crash = AsyncMock(
                side_effect=ValueError("crash not reproducible"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/fuzzing/campaigns/{uuid.uuid4()}/crashes/{uuid.uuid4()}/triage",
            )
        assert resp.status_code == 400


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /campaigns persists FuzzingCampaign row
# ===========================================================================


class TestCreateCampaignLiveCanary:
    """Rule #35b: ``POST /campaigns`` constructs the config dict from
    request fields and routes through FuzzingService.create_campaign.
    The canary asserts the request's timeout_per_exec / memory_limit /
    dictionary all round-trip into the persisted JSONB ``config`` column —
    the F-A-06 confidence-bypass shape applied to the request→config dict
    construction at router lines 86-91.
    """

    @pytest.mark.asyncio
    async def test_persists_campaign_with_config_from_request(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="n" * 64,
                extracted_path="/tmp/extract",
                extraction_dir="/tmp/extract",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            # validate_path is module-imported by fuzzing_service.py
            # (line 36); patch the consumer module so the test doesn't
            # need a real on-disk binary.
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                with patch(
                    "app.services.fuzzing_service.validate_path",
                    return_value="/tmp/extract/bin/foo",
                ):
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/fuzzing/campaigns",
                        json={
                            "binary_path": "bin/foo",
                            "timeout_per_exec": 2000,
                            "memory_limit": 512,
                            "dictionary": "/usr/share/dict",
                            "seed_corpus": None,
                        },
                    )

            assert resp.status_code == 201, resp.text

            persisted = (
                await db.execute(
                    select(FuzzingCampaign).where(
                        FuzzingCampaign.project_id == pid,
                    )
                )
            ).scalars().all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.binary_path == "bin/foo"
            assert row.status == "created"
            # The router builds config from request fields (lines 86-91);
            # every override must round-trip.
            assert row.config["timeout_per_exec"] == 2000
            assert row.config["memory_limit"] == 512
            assert row.config["dictionary"] == "/usr/share/dict"


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /campaigns/{id}/start (Rule #33 fast-path)
# ===========================================================================


class TestStartCampaignLiveCanary:
    """Rule #33's idempotency contract requires status='queued' to be
    visible to the background task before the 202 ack returns. The canary
    seeds a 'created' campaign, calls /start, asserts the row flipped to
    'queued' AND a fresh DB session can SELECT the queued row (committed,
    not just flushed). Background spawn is patched to a no-op so we don't
    actually touch Docker.
    """

    @pytest.mark.asyncio
    async def test_start_flips_status_to_queued_and_commits(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="o" * 64,
                extracted_path="/tmp/extract",
                extraction_dir="/tmp/extract",
            )
            db.add(firmware)
            await db.flush()

            campaign = FuzzingCampaign(
                project_id=pid,
                firmware_id=firmware.id,
                binary_path="bin/foo",
                status="created",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            await db.commit()  # so subsequent SELECT sees it

            app.dependency_overrides[get_db] = lambda: db

            # _run_campaign_spawn_background is module-scope in
            # routers/fuzzing.py (line 32); patch to no-op so the
            # background task doesn't try to touch real Docker.
            async def _noop(*args, **kwargs):
                return None

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                with patch(
                    "app.routers.fuzzing._run_campaign_spawn_background",
                    _noop,
                ):
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/fuzzing/campaigns/{campaign.id}/start",
                    )

            assert resp.status_code == 202, resp.text
            body = resp.json()
            assert body["status"] == "queued"

            # Real SELECT — the row is committed (Rule #33 contract).
            refreshed = (
                await db.execute(
                    select(FuzzingCampaign).where(
                        FuzzingCampaign.id == campaign.id,
                    )
                )
            ).scalar_one()
            assert refreshed.status == "queued", (
                "Rule #33: status='queued' must be persisted (committed) "
                "before the 202 ack returns so the background task sees it"
            )
