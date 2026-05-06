"""HTTP-layer tests for ``app.routers.attack_surface``.

Phase 2 Wave 3 file 4 of 5 — backfills router-level tests for
backend/app/routers/attack_surface.py (228 LOC, 3 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

The router persists AttackSurfaceEntry rows AND auto-creates Finding
rows for binaries with auto-finding data. **The Finding constructor at
line 160 explicitly sets ``confidence="medium"``** — added by Stream A
during the audit-2026-05-04 confidence-bypass fix (F-A-06). This is
exactly the F-A-06 shape the Rule #35b live canary discipline backstops:
a regression that drops the explicit ``confidence="medium"`` would
silently NULL the column on persisted rows. The canary asserts the
field round-trips via a real ORM SELECT.

Coverage targets:

* ``GET /``         — pagination + min_score filter shape.
* ``POST /scan``    — cached path (returns existing entries with
  cached=True); fresh-scan path persists entries + auto-findings;
  scan exception → 500.
* ``GET /{entry_id}`` — 404 missing.
* ``_build_summary`` — internal helper, reachable through cached path:
  score buckets (critical >= 75, high >= 50, medium >= 25, low <25)
  + top_categories rollup.
* **Rule #35b live canary** — POST /scan persists Finding rows with
  ``confidence="medium"`` AND ``source="attack_surface"`` AND the right
  firmware_id. Mocked scan returns 1 entry with 1 auto-finding; live
  SELECT verifies all three constructor fields landed in the DB.

Per Rule #30: ``scan_attack_surface`` is LAZY-imported INSIDE the
endpoint body (line 106). Patches must hit the SOURCE module
``app.services.attack_surface_service.scan_attack_surface``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.attack_surface import AttackSurfaceEntry  # noqa: F401 — registers
from app.models.finding import Finding
from app.models.firmware import Firmware
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
    fw.device_metadata = None
    return fw


# ===========================================================================
# GET / — pagination
# ===========================================================================


class TestListEntries:
    @pytest.mark.asyncio
    async def test_returns_paginated_entries(
        self, client, project_id, monkeypatch,
    ):
        firmware = _make_firmware(project_id)

        entry = MagicMock(spec=AttackSurfaceEntry)
        entry.id = uuid.uuid4()
        entry.project_id = project_id
        entry.firmware_id = firmware.id
        entry.binary_path = "/usr/bin/sshd"
        entry.binary_name = "sshd"
        entry.architecture = "arm"
        entry.file_size = 100000
        entry.attack_surface_score = 80
        entry.score_breakdown = {"network": 30, "imports": 20, "size": 30}
        entry.is_setuid = False
        entry.is_network_listener = True
        entry.is_cgi_handler = False
        entry.has_dangerous_imports = True
        entry.dangerous_imports = ["strcpy"]
        entry.input_categories = ["network"]
        entry.auto_findings_generated = True
        entry.created_at = datetime.now(timezone.utc)

        async def fake_paginate(db, stmt, offset, limit):  # noqa: ARG001
            return [entry], 1

        monkeypatch.setattr(
            "app.routers.attack_surface.paginate_query", fake_paginate,
        )

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        resp = await client.get(
            f"/api/v1/projects/{project_id}/attack-surface",
            params={"min_score": 50},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["binary_name"] == "sshd"
        assert body["items"][0]["attack_surface_score"] == 80


# ===========================================================================
# POST /scan — cached path
# ===========================================================================


class TestScanCached:
    @pytest.mark.asyncio
    async def test_cached_response_when_entries_exist_no_force(
        self, client, project_id,
    ):
        firmware = _make_firmware(project_id)

        # Mock: scalar count returns >0 → cache hit.
        entry = MagicMock(spec=AttackSurfaceEntry)
        entry.id = uuid.uuid4()
        entry.project_id = project_id
        entry.firmware_id = firmware.id
        entry.binary_path = "/sbin/init"
        entry.binary_name = "init"
        entry.architecture = "arm"
        entry.file_size = 50000
        entry.attack_surface_score = 30
        entry.score_breakdown = {}
        entry.is_setuid = True
        entry.is_network_listener = False
        entry.is_cgi_handler = False
        entry.has_dangerous_imports = False
        entry.dangerous_imports = []
        entry.input_categories = ["filesystem"]
        entry.auto_findings_generated = False
        entry.created_at = datetime.now(timezone.utc)

        cached_result = MagicMock()
        scalars_proxy = MagicMock()
        scalars_proxy.all.return_value = [entry]
        cached_result.scalars.return_value = scalars_proxy

        db = AsyncMock()
        db.scalar = AsyncMock(return_value=1)  # count > 0
        db.execute = AsyncMock(return_value=cached_result)

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/attack-surface/scan",
            json={"force_rescan": False},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cached"] is True
        assert len(body["entries"]) == 1
        # _build_summary score buckets: 30 → medium.
        assert body["summary"]["medium_count"] == 1
        assert body["summary"]["critical_count"] == 0
        assert body["summary"]["top_categories"] == ["filesystem"]


class TestScanError:
    @pytest.mark.asyncio
    async def test_scan_exception_returns_500(self, client, project_id):
        firmware = _make_firmware(project_id)

        db = AsyncMock()
        db.scalar = AsyncMock(return_value=0)  # cache miss → run scan

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        # scan_attack_surface lazy-imported in endpoint body — patch SOURCE.
        with patch(
            "app.services.attack_surface_service.scan_attack_surface",
            side_effect=RuntimeError("scan crashed"),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/attack-surface/scan",
                json={"force_rescan": True},
            )
        assert resp.status_code == 500
        assert "scan failed" in resp.json()["detail"].lower()


# ===========================================================================
# GET /{entry_id}
# ===========================================================================


class TestGetEntry:
    @pytest.mark.asyncio
    async def test_missing_entry_returns_404(self, client, project_id):
        firmware = _make_firmware(project_id)

        result = MagicMock()
        scalars_proxy = MagicMock()
        scalars_proxy.first.return_value = None
        result.scalars.return_value = scalars_proxy

        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/attack-surface/{uuid.uuid4()}",
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"]


# ===========================================================================
# Rule #35b LIVE-CANARY — Finding row with confidence="medium" persisted
# ===========================================================================


class TestScanAutoFindingLiveCanary:
    """Rule #35b: ``POST /scan`` builds Finding rows with
    ``confidence="medium"`` (router line 160) AND ``source="attack_surface"``
    (line 166). This explicit kwarg was added by Stream A's audit-2026-05-04
    F-A-06 confidence-bypass fix — without it the column would silently
    NULL on every persisted row. A mock-only test would assert
    ``db.add.call_count == 2`` and pass; this canary instead seeds a real
    SQLite session, runs the scan with one auto-finding, and SELECTs the
    persisted Finding row to verify confidence + source + firmware_id.
    """

    @pytest.mark.asyncio
    async def test_scan_persists_finding_with_explicit_confidence(
        self, tmp_path: Path,
    ):
        from dataclasses import dataclass, field

        @dataclass
        class _StubScanResult:
            path: str
            name: str
            architecture: str | None
            file_size: int | None
            score: int
            breakdown: dict
            is_setuid: bool
            is_network_listener: bool
            is_cgi_handler: bool
            has_dangerous_imports: bool
            dangerous_imports: list[str]
            input_categories: list[str]
            findings: list[dict] = field(default_factory=list)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="r" * 64,
                extracted_path=str(tmp_path),
                extraction_dir=str(tmp_path),
            )
            db.add(firmware)
            await db.flush()

            stub_results = [_StubScanResult(
                path="/usr/sbin/lighttpd",
                name="lighttpd",
                architecture="arm",
                file_size=200000,
                score=85,
                breakdown={"network": 40, "imports": 30, "size": 15},
                is_setuid=False,
                is_network_listener=True,
                is_cgi_handler=True,
                has_dangerous_imports=True,
                dangerous_imports=["system", "execl"],
                input_categories=["network", "cgi"],
                findings=[{
                    "title": "Network-facing CGI binary with dangerous imports",
                    "severity": "high",
                    "description": "lighttpd loads dangerous libc functions",
                    "file_path": "/usr/sbin/lighttpd",
                    "cwe_ids": ["CWE-78"],
                }],
            )]

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            # Per Rule #30: scan_attack_surface is lazy-imported inside
            # the endpoint body — patch the SOURCE module.
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                with patch(
                    "app.services.attack_surface_service.scan_attack_surface",
                    return_value=stub_results,
                ):
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/attack-surface/scan",
                        json={"force_rescan": True},
                    )

            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["cached"] is False
            assert len(body["entries"]) == 1

            # Real SELECT — Rule #35b. The Finding constructor at
            # router line 160 sets confidence="medium" explicitly; verify
            # it round-tripped (the F-A-06 backstop).
            persisted_findings = (
                await db.execute(
                    select(Finding).where(Finding.project_id == pid),
                )
            ).scalars().all()
            assert len(persisted_findings) == 1, (
                f"expected exactly 1 Finding, got {len(persisted_findings)}"
            )
            finding = persisted_findings[0]
            assert finding.confidence == "medium", (
                "Rule #35b: confidence='medium' must round-trip through "
                "the Finding constructor — F-A-06 confidence-bypass shape"
            )
            assert finding.source == "attack_surface"
            assert finding.firmware_id == firmware.id
            assert finding.title == "Network-facing CGI binary with dangerous imports"
            assert finding.severity == "high"
            assert finding.file_path == "/usr/sbin/lighttpd"
            assert finding.cwe_ids == ["CWE-78"]

            # Also verify the AttackSurfaceEntry row landed correctly.
            persisted_entries = (
                await db.execute(
                    select(AttackSurfaceEntry).where(
                        AttackSurfaceEntry.firmware_id == firmware.id,
                    ),
                )
            ).scalars().all()
            assert len(persisted_entries) == 1
            entry = persisted_entries[0]
            assert entry.binary_name == "lighttpd"
            assert entry.attack_surface_score == 85
            assert entry.has_dangerous_imports is True
            assert entry.dangerous_imports == ["system", "execl"]
            assert entry.input_categories == ["network", "cgi"]
            assert entry.auto_findings_generated is True
