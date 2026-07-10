"""Honest, explicit coverage for app/routers/fuzzing.py residual branches.

Targets every statement skeptic flagged as still-missing plus crash_input_hex
(238-240). Pure unit tests with mocked FuzzingService — no Docker/AFL++.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.schemas.fuzzing import (
    FuzzingCampaignCreateRequest,
    FuzzingCrashDetailResponse,
)


def _unwrap(fn):
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


def _req() -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("t", 80),
        }
    )


def _campaign(cid: uuid.UUID, pid: uuid.UUID, status: str = "queued"):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=cid,
        project_id=pid,
        firmware_id=uuid.uuid4(),
        binary_path="/bin/target",
        status=status,
        config={},
        stats=None,
        crashes_count=0,
        container_id=None,
        error_message=None,
        started_at=None,
        stopped_at=None,
        created_at=now,
    )


def _crash(crid: uuid.UUID, cid: uuid.UUID, with_input: bool = True):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=crid,
        campaign_id=cid,
        crash_filename="id:000000",
        crash_size=4 if with_input else None,
        signal="SIGSEGV",
        stack_trace="#0 main",
        exploitability="unknown",
        triage_output=None,
        finding_id=None,
        created_at=now,
        crash_input=b"\xde\xad\xbe\xef" if with_input else None,
    )


class TestFuzzingRouterHonest:
    """Explicit endpoint-by-endpoint coverage — no broad try/except swallow."""

    @pytest.mark.asyncio
    async def test_analyze_target_ok_and_value_error(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        fw = SimpleNamespace(id=uuid.uuid4(), project_id=pid)
        db = AsyncMock()
        analysis = SimpleNamespace(
            binary_path="/bin/x",
            fuzzing_score=10,
            input_sources=[],
            dangerous_functions=[],
            network_functions=[],
            protections={},
            recommended_strategy="stdin",
            function_count=1,
            imports_of_interest=[],
            file_size=100,
            error=None,
        )
        svc = MagicMock()
        svc.analyze_target = AsyncMock(
            side_effect=[ValueError("bad path"), analysis]
        )
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.analyze_target(pid, "/missing", fw, db)
            assert ei.value.status_code == 400
            out = await fr.analyze_target(pid, "/bin/x", fw, db)
            assert out is analysis

    @pytest.mark.asyncio
    async def test_create_campaign_ok_and_value_error(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        fw = SimpleNamespace(id=uuid.uuid4(), project_id=pid)
        db = AsyncMock()
        db.flush = AsyncMock()
        cid = uuid.uuid4()
        camp = _campaign(cid, pid, "created")
        body = FuzzingCampaignCreateRequest(binary_path="/bin/x")
        svc = MagicMock()
        svc.create_campaign = AsyncMock(side_effect=[ValueError("nope"), camp])
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.create_campaign(pid, body, fw, db)
            assert ei.value.status_code == 400
            out = await fr.create_campaign(pid, body, fw, db)
            assert out.id == cid
            db.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_start_campaign_ok_value_error_and_spawn(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        db = AsyncMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        camp = _campaign(cid, pid, "queued")
        svc = MagicMock()
        svc.start_campaign = AsyncMock(side_effect=[ValueError("busy"), camp])
        spawn = MagicMock()
        with (
            patch.object(fr, "FuzzingService", return_value=svc),
            patch("app.utils.background.spawn_background_task", spawn),
        ):
            with pytest.raises(HTTPException) as ei:
                await _unwrap(fr.start_campaign)(
                    request=_req(), project_id=pid, campaign_id=cid, db=db
                )
            assert ei.value.status_code == 400
            out = await _unwrap(fr.start_campaign)(
                request=_req(), project_id=pid, campaign_id=cid, db=db
            )
            assert out.status == "queued"
            db.commit.assert_awaited()
            spawn.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_campaign_ok_and_value_error(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        db = AsyncMock()
        db.flush = AsyncMock()
        camp = _campaign(cid, pid, "stopped")
        svc = MagicMock()
        svc.stop_campaign = AsyncMock(side_effect=[ValueError("not running"), camp])
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.stop_campaign(pid, cid, db)
            assert ei.value.status_code == 400
            out = await fr.stop_campaign(pid, cid, db)
            assert out.status == "stopped"

    @pytest.mark.asyncio
    async def test_list_campaigns_running_status_refresh_and_error(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        db = AsyncMock()
        running = _campaign(cid, pid, "running")
        created = _campaign(uuid.uuid4(), pid, "created")
        refreshed = _campaign(cid, pid, "running")
        refreshed.crashes_count = 3
        svc = MagicMock()
        svc.list_campaigns = AsyncMock(return_value=[running, created])
        svc.get_campaign_status = AsyncMock(
            side_effect=[RuntimeError("docker down"), refreshed]
        )
        with patch.object(fr, "FuzzingService", return_value=svc):
            # first call: status refresh raises → continue
            out1 = await fr.list_campaigns(pid, db)
            assert len(out1) == 2
            # second call: refresh succeeds
            svc.list_campaigns = AsyncMock(return_value=[running, created])
            svc.get_campaign_status = AsyncMock(return_value=refreshed)
            out2 = await fr.list_campaigns(pid, db)
            assert out2[0].crashes_count == 3

    @pytest.mark.asyncio
    async def test_get_campaign_ok_and_404(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        db = AsyncMock()
        db.flush = AsyncMock()
        camp = _campaign(cid, pid, "running")
        svc = MagicMock()
        svc.get_campaign_status = AsyncMock(
            side_effect=[ValueError("missing"), camp]
        )
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.get_campaign(pid, cid, db)
            assert ei.value.status_code == 404
            out = await fr.get_campaign(pid, cid, db)
            assert out.id == cid

    @pytest.mark.asyncio
    async def test_list_crashes(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        db = AsyncMock()
        cr = _crash(uuid.uuid4(), cid)
        svc = MagicMock()
        svc.get_crashes = AsyncMock(return_value=[cr])
        with patch.object(fr, "FuzzingService", return_value=svc):
            out = await fr.list_crashes(pid, cid, db)
            assert len(out) == 1

    @pytest.mark.asyncio
    async def test_get_crash_detail_with_and_without_input_and_404(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        crid = uuid.uuid4()
        db = AsyncMock()
        with_input = _crash(crid, cid, with_input=True)
        no_input = _crash(crid, cid, with_input=False)
        svc = MagicMock()
        svc.get_crash_detail = AsyncMock(
            side_effect=[ValueError("gone"), with_input, no_input]
        )
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.get_crash_detail(pid, cid, crid, db)
            assert ei.value.status_code == 404

            # Lines 238-240: hex-encode crash_input when present
            resp = await fr.get_crash_detail(pid, cid, crid, db)
            assert isinstance(resp, FuzzingCrashDetailResponse)
            assert resp.crash_input_hex == "deadbeef"

            # crash_input falsy → skip hex assignment, still return
            resp2 = await fr.get_crash_detail(pid, cid, crid, db)
            assert resp2.crash_input_hex is None

    @pytest.mark.asyncio
    async def test_triage_crash_ok_and_value_error(self):
        from app.routers import fuzzing as fr

        pid = uuid.uuid4()
        cid = uuid.uuid4()
        crid = uuid.uuid4()
        db = AsyncMock()
        db.flush = AsyncMock()
        cr = _crash(crid, cid)
        cr.exploitability = "exploitable"
        svc = MagicMock()
        svc.triage_crash = AsyncMock(side_effect=[ValueError("bad"), cr])
        with patch.object(fr, "FuzzingService", return_value=svc):
            with pytest.raises(HTTPException) as ei:
                await fr.triage_crash(pid, cid, crid, db)
            assert ei.value.status_code == 400
            out = await fr.triage_crash(pid, cid, crid, db)
            assert out.exploitability == "exploitable"
            db.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_campaign_spawn_background_success(self):
        from app.routers import fuzzing as fr

        cid = uuid.uuid4()
        db = AsyncMock()
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        svc = MagicMock()
        svc._spawn_campaign_container = AsyncMock()

        class Sess:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        with (
            patch.object(fr, "async_session_factory", return_value=Sess()),
            patch.object(fr, "FuzzingService", return_value=svc),
        ):
            await fr._run_campaign_spawn_background(cid)
            svc._spawn_campaign_container.assert_awaited_once_with(cid)
            db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_campaign_spawn_background_inner_then_outer(self):
        """Inner except (51-53) + outer except (54-58) both must fire."""
        from app.routers import fuzzing as fr

        cid = uuid.uuid4()
        db = AsyncMock()
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        svc = MagicMock()
        svc._spawn_campaign_container = AsyncMock(
            side_effect=RuntimeError("spawn fail")
        )

        class Sess:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *a):
                return False

        with (
            patch.object(fr, "async_session_factory", return_value=Sess()),
            patch.object(fr, "FuzzingService", return_value=svc),
            patch.object(fr.logger, "exception") as log_exc,
        ):
            # Inner raises → rollback → re-raise → outer catches → log
            await fr._run_campaign_spawn_background(cid)
            db.rollback.assert_awaited()
            log_exc.assert_called()

    @pytest.mark.asyncio
    async def test_run_campaign_spawn_background_session_factory_fail(self):
        """Outer except alone when session factory itself blows up."""
        from app.routers import fuzzing as fr

        cid = uuid.uuid4()

        def boom():
            raise ConnectionError("db down")

        with (
            patch.object(fr, "async_session_factory", side_effect=boom),
            patch.object(fr.logger, "exception") as log_exc,
        ):
            await fr._run_campaign_spawn_background(cid)
            log_exc.assert_called()
