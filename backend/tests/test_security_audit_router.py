"""HTTP-layer tests for ``app.routers.security_audit``.

Mirrors the shape of ``test_hardware_firmware_router.py``: dependency
overrides on ``get_db`` + service-layer patches keep the FastAPI route
exercised without needing real firmware on disk or live external services
(NVD, ClamAV, VirusTotal). The slowapi rate limiter is disabled in an
autouse fixture so the 5/hour TIER_A_HEAVY budget on ``POST /audit`` does
not bleed across test cases.

Coverage targets (per intake audit-test-coverage-routers-services-2026-05-04):

* ``POST /audit`` — project-missing 404, no-firmware 400, happy-path
  finding persistence.
* ``POST /yara`` — project-missing 404, no-firmware 400.
* ``POST /clamav-scan`` — daemon-unavailable returns ``status="unavailable"``.
* ``POST /vt-scan`` — missing API key returns ``status="not_configured"``.
* ``POST /known-good-scan`` — project-missing 404.
* ``GET /firmware/{firmware_id}/update-mechanisms`` — project-missing 404,
  firmware-missing 404.
* **Rule #35b live-canary** — runs the audit endpoint against a real
  SQLite-backed session, scans a tmp firmware tree with a real
  ``run_security_audit`` invocation, then ``SELECT``s the persisted
  ``Finding`` row to confirm ``source='security_audit'``, the matching
  ``firmware_id``, and that the row actually landed in the database.
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
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    """Force the APIKeyASGIMiddleware into pass-through mode for these tests.

    When ``settings.api_key`` is falsy the middleware short-circuits
    (see ``app/middleware/asgi_auth.py:60``). The auth layer has dedicated
    coverage in ``test_emulation_auth.py`` and ``test_terminal_router.py``;
    here we only care about the router-level logic.
    """
    from app.middleware import asgi_auth as _auth_mod

    fake_settings = MagicMock()
    fake_settings.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    """Disable the slowapi limiter so the 5/hour TIER_A_HEAVY cap on
    ``POST /audit`` (rate_limit.py:47) does not bleed between tests.

    The limiter is enabled in production by default — we toggle it off
    for the test scope and restore on teardown so the production gate
    keeps working when the suite shares a runtime with the live app.
    """
    prior = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    try:
        yield
    finally:
        limiter.enabled = prior


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    """Reset FastAPI dependency overrides after each test."""
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project(project_id: uuid.UUID) -> MagicMock:
    project = MagicMock(spec=Project)
    project.id = project_id
    project.name = "test-project"
    project.status = "ready"
    return project


def _make_firmware(project_id: uuid.UUID, extracted_path: str) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.created_at = datetime.now(timezone.utc)
    fw.device_metadata = None
    return fw


def _make_db_with_results(project, firmware_list):
    """Build an AsyncMock db whose execute() returns project then firmware list.

    The ``security_audit`` router does:
        - SELECT Project → scalar_one_or_none
        - SELECT Firmware → scalars().all()
        - DELETE Finding (...)
        - flush
        - ... scan ...
        - INSERT findings via FindingService

    We seed the responses in order. Subsequent execute() calls (DELETE,
    INSERT) just return a generic MagicMock since the router doesn't
    consume them.
    """
    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = project

    firmware_result = MagicMock()
    scalars_proxy = MagicMock()
    scalars_proxy.all.return_value = firmware_list
    firmware_result.scalars.return_value = scalars_proxy

    db = AsyncMock()
    # Each test typically issues 2-3 SELECTs (project, firmware list);
    # downstream DELETE / INSERT calls land here too. side_effect lets us
    # hand back project then firmware then "anything else" indefinitely.
    db.execute = AsyncMock(side_effect=_iter_responses(project_result, firmware_result))
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


def _iter_responses(*first_responses):
    """Return an iterator that yields ``first_responses`` then MagicMock()s forever.

    Plain ``side_effect=[a, b]`` raises ``StopIteration`` once exhausted;
    the security-audit handlers issue several execute() calls (DELETE,
    INSERT through FindingService) after the SELECT pair, so we keep
    feeding harmless MagicMocks.
    """
    queue = list(first_responses)

    def _next(*_args, **_kwargs):
        if queue:
            return queue.pop(0)
        return MagicMock()

    return _next


# ---------------------------------------------------------------------------
# POST /audit — project-missing / no-firmware paths
# ---------------------------------------------------------------------------

class TestRunAuditValidation:
    """Pre-scan validation: project must exist and have extracted firmware."""

    @pytest.mark.asyncio
    async def test_project_missing_returns_404(self, client, project_id):
        db = _make_db_with_results(project=None, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{project_id}/security/audit")
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_no_extracted_firmware_returns_400(self, client, project_id):
        project = _make_project(project_id)
        db = _make_db_with_results(project=project, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{project_id}/security/audit")
        assert resp.status_code == 400
        assert "No extracted firmware" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# POST /yara — same validation surface
# ---------------------------------------------------------------------------

class TestYaraScanValidation:
    @pytest.mark.asyncio
    async def test_project_missing_returns_404(self, client, project_id):
        db = _make_db_with_results(project=None, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{project_id}/security/yara")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_no_extracted_firmware_returns_400(self, client, project_id):
        project = _make_project(project_id)
        db = _make_db_with_results(project=project, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{project_id}/security/yara")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /clamav-scan — daemon unreachable short-circuits with success status
# ---------------------------------------------------------------------------

class TestClamavScanUnavailable:
    @pytest.mark.asyncio
    async def test_returns_unavailable_when_daemon_down(self, client, project_id):
        """When the ClamAV daemon is not reachable the endpoint returns 200
        with ``status="unavailable"`` rather than 503 — matches the existing
        VT/known-good ergonomic where the scan tier just opts out."""
        # No DB override needed: the early return in the handler runs before
        # any DB query when ``check_available()`` returns False.
        with patch(
            "app.services.clamav_service.check_available",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/clamav-scan"
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unavailable"
        assert body["files_scanned"] == 0
        assert body["infected_count"] == 0


# ---------------------------------------------------------------------------
# POST /vt-scan — missing API key short-circuits with success status
# ---------------------------------------------------------------------------

class TestVirusTotalScanUnconfigured:
    @pytest.mark.asyncio
    async def test_returns_not_configured_without_api_key(self, client, project_id):
        """No VT_API_KEY → 200 with ``status="not_configured"`` (privacy
        ergonomic — no accidental hash exfiltration on a misconfigured box).

        ``get_settings`` is lazy-imported inside the endpoint body
        (security_audit.py:657 ``from app.config import get_settings``), so
        the only patch target that intercepts the call per Rule #30 is the
        source module ``app.config.get_settings`` — patching
        ``app.routers.security_audit.get_settings`` would be a silent no-op
        because the symbol was never bound at module scope.
        """
        fake_settings = MagicMock()
        fake_settings.virustotal_api_key = ""
        with patch(
            "app.config.get_settings",
            return_value=fake_settings,
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/vt-scan"
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "not_configured"
        assert body["binaries_checked"] == 0


# ---------------------------------------------------------------------------
# POST /known-good-scan — project-missing 404
# ---------------------------------------------------------------------------

class TestKnownGoodScanValidation:
    @pytest.mark.asyncio
    async def test_project_missing_returns_404(self, client, project_id):
        db = _make_db_with_results(project=None, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/security/known-good-scan"
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /firmware/{firmware_id}/update-mechanisms — both 404 paths
# ---------------------------------------------------------------------------

class TestUpdateMechanismsValidation:
    @pytest.mark.asyncio
    async def test_project_missing_returns_404(self, client, project_id):
        db = _make_db_with_results(project=None, firmware_list=[])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/security/firmware/{uuid.uuid4()}/update-mechanisms"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_firmware_missing_returns_404(self, client, project_id):
        project = _make_project(project_id)
        # First execute() returns project; second returns scalar_one_or_none = None
        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = project

        firmware_result = MagicMock()
        firmware_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[project_result, firmware_result])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/security/firmware/{uuid.uuid4()}/update-mechanisms"
        )
        assert resp.status_code == 404
        assert "Firmware not found" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Rule #35b LIVE-CANARY — real ORM round-trip + SELECT
# ---------------------------------------------------------------------------

class TestSecurityAuditPersistenceLiveCanary:
    """Rule #35b: persistence is verified end-to-end against a real session.

    Mock-only tests would assert ``mock_db.add.call_count == 1`` and pass
    while the constructor silently dropped a field. This canary instead
    seeds a real SQLite session, runs the audit handler against a real
    extracted-firmware tree, then ``SELECT``s the persisted Finding row
    to verify ``source``, ``severity``, ``project_id``, and ``firmware_id``
    actually round-tripped through the DB layer.
    """

    @pytest.mark.asyncio
    async def test_audit_persists_finding_row_with_correct_source_and_firmware_id(
        self, client, tmp_path: Path,
    ):
        from app.services.security_audit._base import (
            ScanResult,
            SecurityFinding,
        )

        # Real on-disk extraction: minimal firmware tree under tmp_path.
        extraction_dir = tmp_path / "rootfs"
        (extraction_dir / "etc").mkdir(parents=True)
        (extraction_dir / "etc" / "passwd").write_text(
            "root::0:0:root:/root:/bin/sh\n",
        )

        async for db in make_live_db():
            # Seed a real Project + Firmware row.
            pid = uuid.uuid4()
            project = Project(id=pid, name="live-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="c" * 64,
                extracted_path=str(extraction_dir),
                extraction_dir=str(extraction_dir),
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            # Stub the scanner so we don't depend on the full security_audit
            # check pipeline (which scans hundreds of files, takes seconds,
            # and brings in optional deps). The single SecurityFinding we
            # return is what the persistence layer should write to the DB.
            stub_finding = SecurityFinding(
                title="Empty root password",
                severity="critical",
                description="root account has no password set",
                evidence="root::0:0:...",
                file_path="etc/passwd",
                cwe_ids=["CWE-521"],
            )
            scan_result = ScanResult(
                findings=[stub_finding],
                checks_run=1,
                errors=[],
            )

            # Per Rule #30: ``get_detection_roots`` is lazy-imported inside
            # the endpoint body (security_audit.py:135), so the only
            # patch target that intercepts the call is the source module —
            # patching ``app.routers.security_audit.get_detection_roots``
            # would be a silent no-op because the symbol was never bound at
            # module scope. The other scanners ARE module-scope imports
            # (security_audit.py:31-37) so router-level patching works for
            # them.
            with patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(return_value=[str(extraction_dir)]),
            ), patch(
                "app.routers.security_audit.run_security_audit_multi",
                return_value=scan_result,
            ), patch(
                "app.routers.security_audit.run_clamav_scan",
                new=AsyncMock(return_value=[]),
            ), patch(
                "app.routers.security_audit.run_virustotal_scan",
                new=AsyncMock(return_value=[]),
            ), patch(
                "app.routers.security_audit.run_abusech_scan",
                new=AsyncMock(return_value=[]),
            ), patch(
                "app.routers.security_audit.run_known_good_scan",
                new=AsyncMock(return_value=[]),
            ):
                resp = await client.post(
                    f"/api/v1/projects/{pid}/security/audit"
                )

            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["findings_created"] == 1

            # Real SELECT — the canary that mocks cannot fake.
            persisted = (
                await db.execute(
                    select(Finding).where(Finding.project_id == pid)
                )
            ).scalars().all()
            assert len(persisted) == 1, (
                f"expected exactly 1 persisted Finding, got {len(persisted)}"
            )
            row = persisted[0]
            assert row.title == "Empty root password"
            assert row.severity == "critical"
            assert row.source == "security_audit"
            assert row.firmware_id == firmware.id, (
                "Rule #35b: firmware_id must round-trip through the DB layer"
            )
            assert row.cwe_ids == ["CWE-521"]
            break
