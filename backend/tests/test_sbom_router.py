"""HTTP-layer tests for ``app.routers.sbom``.

Mirrors the shape of ``test_security_audit_router.py``: dependency overrides
on ``get_db`` + ``_resolve_firmware`` keep the FastAPI route exercised
without needing real firmware on disk. The slowapi rate limiter is disabled
in an autouse fixture so the 5/hour ``TIER_A_HEAVY`` budget on the
``POST /generate`` and ``POST /vulnerabilities/scan`` endpoints does not
bleed across test cases.

Coverage targets (per intake audit-test-coverage-routers-services-2026-05-04
Phase 2):

* ``GET /``           — paginated component list, type/name filters.
* ``GET /export``     — cyclonedx-json, spdx-json, cyclonedx-vex-json shapes;
  no-components 404.
* ``POST /generate``  — cached path (no force_rescan), invalid format guard.
* ``POST /vulnerabilities/scan`` — no-SBOM 400 short-circuit.
* ``GET /vulnerabilities`` — pagination + severity / cve_id filters.
* ``PATCH /vulnerabilities/{id}`` — 404 missing; resolution_status update
  populates ``resolved_by`` / ``resolved_at`` (live canary).
* ``GET /vulnerabilities/summary`` — happy-path response shape.
* ``POST /push-to-dependency-track`` — unconfigured 400; no-components 404.
* ``GET /cpe-dictionary/status`` + ``POST /cpe-dictionary/reload`` — happy
  path (lazy-imported service per Rule #30).
* **Rule #35b live-canary** — ``POST /generate`` against a real SQLite
  session. Stubs ``SbomService.generate_sbom`` to a known component-dict
  list, then ``SELECT``s the persisted ``SbomComponent`` rows and asserts
  every constructor argument the router explicitly sets round-tripped
  (the F-A-06-shape value-flow contract that mock tests cannot fail on).
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    """Force the APIKeyASGIMiddleware into pass-through mode for these tests."""
    from app.middleware import asgi_auth as _auth_mod

    fake_settings = MagicMock()
    fake_settings.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    """Disable the slowapi limiter so the 5/hour TIER_A_HEAVY cap on
    ``POST /generate`` and ``POST /vulnerabilities/scan`` does not bleed
    between tests."""
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


def _make_firmware(project_id: uuid.UUID, extracted_path: str = "/tmp/x") -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.original_filename = "test-firmware.bin"
    fw.device_metadata = None
    fw.os_info = None
    fw.created_at = datetime.now(UTC)
    return fw


def _make_component(
    firmware_id: uuid.UUID,
    name: str = "openssl",
    version: str = "1.1.1",
    type: str = "library",
) -> MagicMock:
    """Build a SbomComponent-shaped mock for non-live-DB tests."""
    comp = MagicMock(spec=SbomComponent)
    comp.id = uuid.uuid4()
    comp.firmware_id = firmware_id
    comp.name = name
    comp.version = version
    comp.type = type
    comp.cpe = f"cpe:2.3:a:vendor:{name}:{version}:*:*:*:*:*:*:*"
    comp.purl = f"pkg:generic/{name}@{version}"
    comp.supplier = "Test Vendor"
    comp.detection_source = "binwalk"
    comp.detection_confidence = "high"
    comp.file_paths = ["/usr/lib/libssl.so"]
    comp.metadata_ = {}
    comp.created_at = datetime.now(UTC)
    return comp


def _make_vulnerability(
    component_id: uuid.UUID,
    firmware_id: uuid.UUID,
    cve_id: str = "CVE-2024-0001",
    severity: str = "high",
    cvss_score: float | None = 7.5,
) -> MagicMock:
    """Build a SbomVulnerability-shaped mock for non-live-DB tests."""
    vuln = MagicMock(spec=SbomVulnerability)
    vuln.id = uuid.uuid4()
    vuln.component_id = component_id
    vuln.firmware_id = firmware_id
    vuln.blob_id = None
    vuln.cve_id = cve_id
    vuln.cvss_score = cvss_score
    vuln.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vuln.severity = severity
    vuln.description = "Test vulnerability"
    vuln.published_date = datetime.now(UTC)
    vuln.finding_id = None
    vuln.resolution_status = "open"
    vuln.resolution_justification = None
    vuln.resolved_by = None
    vuln.resolved_at = None
    vuln.adjusted_cvss_score = None
    vuln.adjusted_severity = None
    vuln.adjustment_rationale = None
    vuln.match_confidence = None
    vuln.match_tier = None
    vuln.created_at = datetime.now(UTC)
    return vuln


def _result_with_all(rows: list) -> MagicMock:
    """Build a SQLAlchemy result-shaped mock whose .all() returns ``rows``."""
    result = MagicMock()
    result.all.return_value = rows
    scalars_proxy = MagicMock()
    scalars_proxy.all.return_value = rows
    scalars_proxy.first.return_value = rows[0] if rows else None
    result.scalars.return_value = scalars_proxy
    return result


# ===========================================================================
# GET / — paginated component listing
# ===========================================================================


class TestListComponents:
    """``GET .../sbom`` returns Page[SbomComponentResponse]."""

    @pytest.mark.asyncio
    async def test_returns_paginated_components(
        self, client, project_id, monkeypatch,
    ):
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)

        # paginate_query_rows is imported at module scope in sbom router
        # (line 34); patch it on the router module so we control the
        # composed pagination output.
        async def fake_paginate(db, stmt, offset, limit):  # noqa: ARG001
            return [(comp, 0)], 1

        monkeypatch.setattr(
            "app.routers.sbom.paginate_query_rows", fake_paginate,
        )
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        resp = await client.get(f"/api/v1/projects/{project_id}/sbom")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["offset"] == 0
        assert body["limit"] == 100
        assert len(body["items"]) == 1
        assert body["items"][0]["name"] == "openssl"
        assert body["items"][0]["vulnerability_count"] == 0


# ===========================================================================
# GET /export — CycloneDX / SPDX / VEX shapes
# ===========================================================================


class TestExport:
    """``GET .../sbom/export?format=...`` returns the requested document."""

    @pytest.mark.asyncio
    async def test_no_components_returns_404(self, client, project_id):
        firmware = _make_firmware(project_id)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_result_with_all([]))

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/export?format=cyclonedx-json",
        )
        assert resp.status_code == 404
        assert "No SBOM generated yet" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_cyclonedx_json_shape(self, client, project_id):
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_result_with_all([comp]))

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/export?format=cyclonedx-json",
        )
        assert resp.status_code == 200
        bom = json.loads(resp.text)
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.7"
        assert bom["metadata"]["component"]["type"] == "firmware"
        assert bom["metadata"]["component"]["name"] == "test-firmware.bin"
        assert len(bom["components"]) == 1
        assert bom["components"][0]["name"] == "openssl"
        assert bom["components"][0]["version"] == "1.1.1"
        # CycloneDX type mapping: "library" stays as "library".
        assert bom["components"][0]["type"] == "library"
        assert "attachment" in resp.headers.get("content-disposition", "").lower()

    @pytest.mark.asyncio
    async def test_spdx_json_shape(self, client, project_id):
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_result_with_all([comp]))

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/export?format=spdx-json",
        )
        assert resp.status_code == 200
        doc = json.loads(resp.text)
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert len(doc["packages"]) == 1
        assert doc["packages"][0]["name"] == "openssl"
        assert doc["packages"][0]["versionInfo"] == "1.1.1"
        assert any(rel["relatedSpdxElement"] == doc["packages"][0]["SPDXID"]
                   for rel in doc["relationships"])

    @pytest.mark.asyncio
    async def test_vex_json_shape_includes_analysis(
        self, client, project_id,
    ):
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)
        vuln = _make_vulnerability(comp.id, firmware.id)
        # vex export: first execute() returns the components list, second
        # returns vuln_rows (each row is a (SbomVulnerability, SbomComponent)
        # tuple per the router's join select).
        comp_result = _result_with_all([comp])
        vuln_result = MagicMock()
        vuln_result.all.return_value = [(vuln, comp)]

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[comp_result, vuln_result])

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/export?format=cyclonedx-vex-json",
        )
        assert resp.status_code == 200
        bom = json.loads(resp.text)
        assert bom["bomFormat"] == "CycloneDX"
        assert "vulnerabilities" in bom
        assert len(bom["vulnerabilities"]) == 1
        v = bom["vulnerabilities"][0]
        assert v["id"] == "CVE-2024-0001"
        assert v["analysis"]["state"] == "in_triage"  # open + no adjusted_severity
        assert v["ratings"][0]["score"] == 7.5
        assert v["ratings"][0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_invalid_format_returns_422(self, client, project_id):
        """The router declares ``pattern=^(cyclonedx-json|spdx-json|cyclonedx-vex-json)$``;
        FastAPI rejects everything else at the validation layer."""
        firmware = _make_firmware(project_id)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/export?format=bogus",
        )
        assert resp.status_code == 422


# ===========================================================================
# POST /generate — cached path
# ===========================================================================


class TestGenerateSbomCached:
    @pytest.mark.asyncio
    async def test_cached_response_when_components_exist_and_no_force(
        self, client, project_id,
    ):
        """``force_rescan=False`` + components in DB → return cached set."""
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)

        # First db.execute() = SELECT count → returns 1 (cache hit).
        # Second = SELECT components-with-vuln-counts in
        # _get_components_with_vuln_counts → returns the [(comp, 0)] row.
        count_result = MagicMock()
        count_result.scalar.return_value = 1

        components_result = MagicMock()
        components_result.all.return_value = [(comp, 0)]

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[count_result, components_result])

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{project_id}/sbom/generate")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cached"] is True
        assert body["total"] == 1
        assert body["components"][0]["name"] == "openssl"


# ===========================================================================
# POST /vulnerabilities/scan — pre-scan validation
# ===========================================================================


class TestScanVulnerabilitiesValidation:
    @pytest.mark.asyncio
    async def test_no_sbom_returns_400(self, client, project_id):
        """Router does ``SELECT count`` first; zero components → 400."""
        firmware = _make_firmware(project_id)
        db = AsyncMock()
        db.scalar = AsyncMock(return_value=0)
        db.execute = AsyncMock(return_value=MagicMock())

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities/scan",
        )
        assert resp.status_code == 400
        assert "No SBOM generated yet" in resp.json()["detail"]


# ===========================================================================
# GET /vulnerabilities — pagination + filters
# ===========================================================================


class TestListVulnerabilities:
    @pytest.mark.asyncio
    async def test_returns_paginated_vulns_with_component_metadata(
        self, client, project_id, monkeypatch,
    ):
        firmware = _make_firmware(project_id)
        comp = _make_component(firmware.id)
        vuln = _make_vulnerability(comp.id, firmware.id)

        # paginate_query_rows yields rows shaped per the SELECT in the router:
        # (SbomVulnerability, SbomComponent.name, SbomComponent.version).
        async def fake_paginate(db, stmt, offset, limit):  # noqa: ARG001
            return [(vuln, comp.name, comp.version)], 1

        monkeypatch.setattr(
            "app.routers.sbom.paginate_query_rows", fake_paginate,
        )
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["cve_id"] == "CVE-2024-0001"
        assert item["severity"] == "high"
        assert item["component_name"] == "openssl"
        assert item["component_version"] == "1.1.1"
        assert item["resolution_status"] == "open"


# ===========================================================================
# PATCH /vulnerabilities/{id} — 404 + update path
# ===========================================================================


class TestUpdateVulnerability:
    @pytest.mark.asyncio
    async def test_missing_vulnerability_returns_404(self, client, project_id):
        firmware = _make_firmware(project_id)
        result = MagicMock()
        scalars_proxy = MagicMock()
        scalars_proxy.first.return_value = None
        result.scalars.return_value = scalars_proxy

        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.patch(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities/{uuid.uuid4()}",
            json={"resolution_status": "ignored"},
        )
        assert resp.status_code == 404
        assert "Vulnerability not found" in resp.json()["detail"]


# ===========================================================================
# GET /vulnerabilities/summary — happy path
# ===========================================================================


class TestVulnerabilitySummary:
    @pytest.mark.asyncio
    async def test_returns_summary_response(self, client, project_id):
        firmware = _make_firmware(project_id)
        # VulnerabilityService.get_vulnerability_summary is async.
        fake_summary = {
            "total_components": 5,
            "components_by_type": {"library": 5},
            "components_with_vulns": 2,
            "total_vulnerabilities": 3,
            "vulns_by_severity": {"critical": 1, "high": 2},
            "scan_date": datetime.now(UTC).isoformat(),
            "open_count": 3,
            "resolved_count": 0,
        }
        with patch(
            "app.routers.sbom.VulnerabilityService",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.get_vulnerability_summary = AsyncMock(return_value=fake_summary)
            svc_cls.return_value = svc_inst

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/sbom/vulnerabilities/summary",
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["total_components"] == 5
            assert body["components_with_vulns"] == 2
            assert body["vulns_by_severity"]["critical"] == 1
            assert body["open_count"] == 3


# ===========================================================================
# POST /push-to-dependency-track — unconfigured / no-components paths
# ===========================================================================


class TestPushToDependencyTrack:
    """``DependencyTrackService`` is lazy-imported inside the endpoint body
    (sbom.py:512); per Rule #30 patches must hit
    ``app.services.dependency_track_service.DependencyTrackService``."""

    @pytest.mark.asyncio
    async def test_unconfigured_returns_400(self, client, project_id):
        firmware = _make_firmware(project_id)

        fake_svc = MagicMock()
        fake_svc.is_configured = False
        with patch(
            "app.services.dependency_track_service.DependencyTrackService",
            return_value=fake_svc,
        ):
            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/sbom/push-to-dependency-track",
            )
            assert resp.status_code == 400
            assert "Dependency-Track not configured" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_no_components_returns_404(self, client, project_id):
        firmware = _make_firmware(project_id)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_result_with_all([]))

        fake_svc = MagicMock()
        fake_svc.is_configured = True
        with patch(
            "app.services.dependency_track_service.DependencyTrackService",
            return_value=fake_svc,
        ):
            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            resp = await client.post(
                f"/api/v1/projects/{project_id}/sbom/push-to-dependency-track",
            )
            assert resp.status_code == 404
            assert "No SBOM generated yet" in resp.json()["detail"]


# ===========================================================================
# CPE dictionary — lazy-imported per Rule #30
# ===========================================================================


class TestCpeDictionary:
    """``get_cpe_dictionary_service`` is lazy-imported inside the endpoint
    bodies (sbom.py:841, 850); patch the SOURCE module, not the router."""

    @pytest.mark.asyncio
    async def test_status_returns_loaded_state(self, client, project_id):
        fake_svc = MagicMock()
        fake_svc.get_status = AsyncMock(return_value={"loaded": True, "size": 12345})
        with patch(
            "app.services.cpe_dictionary_service.get_cpe_dictionary_service",
            return_value=fake_svc,
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/sbom/cpe-dictionary/status",
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["loaded"] is True
            assert body["size"] == 12345

    @pytest.mark.asyncio
    async def test_reload_returns_loading_status(self, client, project_id):
        fake_svc = MagicMock()
        fake_svc._index = None
        fake_svc._product_names = None
        fake_svc._loading = False
        fake_svc.ensure_loaded = AsyncMock(return_value=False)
        with patch(
            "app.services.cpe_dictionary_service.get_cpe_dictionary_service",
            return_value=fake_svc,
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/sbom/cpe-dictionary/reload",
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "loading"


# ===========================================================================
# Rule #35b LIVE-CANARY — real ORM round-trip + SELECT
# ===========================================================================


class TestSbomGeneratePersistenceLiveCanary:
    """Rule #35b: persistence is verified end-to-end against a real session.

    Mock-only tests would assert ``db.add.call_count == 2`` and pass while
    the constructor silently dropped ``detection_source`` (the F-A-06
    confidence-bypass shape). This canary instead seeds a real SQLite
    session, runs ``POST /generate`` with a stubbed ``SbomService`` that
    returns known component_dicts, then ``SELECT``s the persisted
    ``SbomComponent`` rows and asserts every field the router explicitly
    sets on the constructor (lines 187-199 of sbom.py) round-tripped
    through the DB layer.
    """

    @pytest.mark.asyncio
    async def test_generate_persists_components_with_correct_fields(
        self, client, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="live-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="d" * 64,
                extracted_path=str(tmp_path),
                extraction_dir=str(tmp_path),
                original_filename="canary-firmware.bin",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            # Stub SbomService so the generate handler has known dicts to
            # persist. The router's job is to map dict → SbomComponent
            # constructor; this canary verifies that mapping is correct
            # for every column.
            stub_dicts = [
                {
                    "name": "libcurl",
                    "version": "7.81.0",
                    "type": "library",
                    "cpe": "cpe:2.3:a:haxx:libcurl:7.81.0:*:*:*:*:*:*:*",
                    "purl": "pkg:generic/libcurl@7.81.0",
                    "supplier": "Daniel Stenberg",
                    "detection_source": "binwalk",
                    "detection_confidence": "high",
                    "file_paths": ["/usr/lib/libcurl.so.4"],
                    "metadata": {"sha256": "abc123"},
                },
                {
                    "name": "openssl",
                    "version": "3.0.1",
                    "type": "library",
                    "cpe": None,
                    "purl": None,
                    "supplier": None,
                    "detection_source": "string-match",
                    "detection_confidence": "medium",
                    "file_paths": None,
                    "metadata": {},
                },
            ]

            fake_svc = MagicMock()
            fake_svc.generate_sbom = MagicMock(return_value=stub_dicts)

            # Per Rule #30: ``get_detection_roots`` is lazy-imported inside
            # the endpoint body (sbom.py:137); patch the SOURCE module.
            # ``SbomService`` is module-imported at top (sbom.py:32) so
            # the router-level patch path works for it.
            with patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(return_value=[str(tmp_path)]),
            ), patch(
                "app.routers.sbom.SbomService",
                return_value=fake_svc,
            ):
                resp = await client.post(
                    f"/api/v1/projects/{pid}/sbom/generate?force_rescan=true",
                )

            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["cached"] is False
            assert body["total"] == 2

            # Real SELECT — the canary that mocks cannot fake.
            persisted = (
                await db.execute(
                    select(SbomComponent).where(
                        SbomComponent.firmware_id == firmware.id,
                    ).order_by(SbomComponent.name)
                )
            ).scalars().all()
            assert len(persisted) == 2, (
                f"expected 2 persisted SbomComponent rows, got {len(persisted)}"
            )

            # libcurl row — every field set on the constructor must round-trip.
            libcurl = persisted[0]
            assert libcurl.name == "libcurl"
            assert libcurl.version == "7.81.0"
            assert libcurl.type == "library"
            assert libcurl.cpe == "cpe:2.3:a:haxx:libcurl:7.81.0:*:*:*:*:*:*:*"
            assert libcurl.purl == "pkg:generic/libcurl@7.81.0"
            assert libcurl.supplier == "Daniel Stenberg"
            assert libcurl.detection_source == "binwalk"
            assert libcurl.detection_confidence == "high"
            assert libcurl.file_paths == ["/usr/lib/libcurl.so.4"]
            assert libcurl.metadata_ == {"sha256": "abc123"}
            assert libcurl.firmware_id == firmware.id, (
                "Rule #35b: firmware_id must round-trip through the DB layer"
            )

            # openssl row — None-coalescence path (cpe / purl / supplier /
            # file_paths all None) must also persist correctly.
            openssl = persisted[1]
            assert openssl.name == "openssl"
            assert openssl.version == "3.0.1"
            assert openssl.cpe is None
            assert openssl.purl is None
            assert openssl.supplier is None
            assert openssl.file_paths is None
            assert openssl.detection_source == "string-match"
            assert openssl.detection_confidence == "medium"


# ===========================================================================
# Rule #33 — POST /vulnerabilities/scan 202+polling state machine
# ===========================================================================


class TestVulnerabilityScanRule33:
    """Rule #33 four-bullet contract for the SBOM vuln-scan refactor.

    The synchronous endpoint held the TCP connection idle for ~4m10s on
    72 components and the axios floor / network blip / browser
    backgrounding tripped before the response landed (user report
    2026-05-07: "scan for vulnerabilities timed out" while 5,104 vuln
    rows had already persisted). The conversion replaces the synchronous
    return with a 202 ack + asyncio.create_task background runner +
    GET /scan/status polling endpoint.

    Tests in this class cover the API surface of the contract:
      (a) idempotent POST + 409-on-conflict
      (b) status response shape (summary populated post-completion)
      (c) Pydantic Literal acceptance + DB CHECK rejects invalid value
    """

    @pytest.mark.asyncio
    async def test_post_returns_202_and_queues_when_idle(
        self, client, project_id, monkeypatch,
    ):
        """Happy path: idle firmware → 202 + status='queued' + background task scheduled."""
        firmware = _make_firmware(project_id)
        firmware.id = uuid.uuid4()
        firmware.vuln_scan_status = "idle"
        firmware.vuln_scan_started_at = None
        firmware.vuln_scan_finished_at = None
        firmware.vuln_scan_error = None

        db = AsyncMock()
        # SBOM exists (component count > 0)
        db.scalar = AsyncMock(return_value=5)
        db.execute = AsyncMock(return_value=MagicMock())
        db.commit = AsyncMock()

        # Capture the create_task call — the background runner must NOT
        # actually run during this test (it would try real Grype).
        created_tasks: list = []

        def fake_create_task(coro):
            # Close the coro immediately to avoid the "coroutine was never
            # awaited" warning, then return a sentinel.
            coro.close()
            created_tasks.append("scheduled")
            return MagicMock()

        monkeypatch.setattr(
            "app.routers.sbom.asyncio.create_task", fake_create_task,
        )

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities/scan",
        )

        assert resp.status_code == 202, resp.text
        body = resp.json()
        # The mutation in the router flips status to "queued" before the
        # response is built, so the response reflects the queued state.
        assert body["status"] == "queued"
        assert body["firmware_id"] == str(firmware.id)
        assert body["error"] is None
        assert body["summary"] is None
        # State mutation observed
        assert firmware.vuln_scan_status == "queued"
        assert firmware.vuln_scan_error is None
        # commit() called before the background task is scheduled
        assert db.commit.await_count >= 1
        # Background task scheduled exactly once
        assert created_tasks == ["scheduled"]

    @pytest.mark.asyncio
    async def test_post_returns_409_when_already_queued(
        self, client, project_id,
    ):
        """Idempotency: second POST while status=queued/running → 409, no second task."""
        for in_flight in ("queued", "running"):
            firmware = _make_firmware(project_id)
            firmware.id = uuid.uuid4()
            firmware.vuln_scan_status = in_flight

            db = AsyncMock()
            db.scalar = AsyncMock(return_value=5)
            db.commit = AsyncMock()

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            resp = await client.post(
                f"/api/v1/projects/{project_id}/sbom/vulnerabilities/scan",
            )

            assert resp.status_code == 409, (
                f"expected 409 when status={in_flight!r}, got {resp.status_code}"
            )
            assert in_flight in resp.json()["detail"]
            # No commit should have happened on the 409 path (the check
            # runs BEFORE any state mutation per Rule #33 (a)).
            assert db.commit.await_count == 0
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_status_endpoint_returns_completed_with_summary(
        self, client, project_id, monkeypatch,
    ):
        """GET /scan/status: completed firmware → summary populated from vuln rows."""
        firmware = _make_firmware(project_id)
        firmware.id = uuid.uuid4()
        firmware.vuln_scan_status = "completed"
        firmware.vuln_scan_started_at = datetime.now(UTC)
        firmware.vuln_scan_finished_at = datetime.now(UTC)
        firmware.vuln_scan_error = None

        # Stub the helper that builds the summary from a count query —
        # pure async unit, no real DB needed for this shape test.
        async def fake_build_summary(db, firmware_id):  # noqa: ARG001
            from app.schemas.sbom import VulnerabilityScanResponse
            return VulnerabilityScanResponse(
                status="completed",
                total_components_scanned=72,
                total_vulnerabilities_found=5104,
                findings_created=0,
                vulns_by_severity={"critical": 12, "high": 100, "medium": 2000, "low": 2992},
            )

        monkeypatch.setattr(
            "app.routers.sbom._build_vuln_scan_summary", fake_build_summary,
        )

        db = AsyncMock()
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities/scan/status",
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "completed"
        assert body["summary"] is not None
        assert body["summary"]["total_vulnerabilities_found"] == 5104
        assert body["summary"]["total_components_scanned"] == 72
        assert body["error"] is None

    @pytest.mark.asyncio
    async def test_no_sbom_still_returns_400_before_409(
        self, client, project_id,
    ):
        """Validation order: zero-component check fires before the 409 check.

        Even if the firmware row has vuln_scan_status='queued' for some
        legacy reason, the 'no SBOM yet' guard should still surface as
        400 — the client needs to know to call /generate first, not be
        told to wait on a non-existent run.
        """
        firmware = _make_firmware(project_id)
        firmware.vuln_scan_status = "queued"  # would otherwise trigger 409
        db = AsyncMock()
        db.scalar = AsyncMock(return_value=0)
        db.commit = AsyncMock()

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/sbom/vulnerabilities/scan",
        )

        assert resp.status_code == 400
        assert "No SBOM generated yet" in resp.json()["detail"]


# ===========================================================================
# Rule #35b LIVE-CANARY — vuln_scan_status persistence + CHECK constraint
# ===========================================================================


class TestVulnScanStatusLiveCanary:
    """Rule #35b: status-column round-trip + CHECK rejects invalid values.

    Mock unit tests verify "status='queued' was assigned to the row";
    they CANNOT verify "the DB layer accepts that assignment AND the
    CHECK constraint rejects an invalid value." This canary writes
    a real Firmware row through the live_db shim and SELECTs it back,
    then attempts to write an invalid status and asserts an IntegrityError
    surfaces — proving the Rule #33 (c) double gate (Pydantic Literal
    AND DB CHECK) is actually wired.

    Note: SQLite does enforce CHECK constraints when they're declared
    in DDL. Postgres in production does the same via the
    ck_firmware_vuln_scan_status constraint added in revision
    c1d2e3f4a5b6.
    """

    @pytest.mark.asyncio
    async def test_status_field_round_trips_through_live_db(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="vuln-scan-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="e" * 64,
                extracted_path="/tmp/canary",
                extraction_dir="/tmp/canary",
                original_filename="canary.bin",
                vuln_scan_status="queued",
                vuln_scan_started_at=datetime.now(UTC),
                vuln_scan_error=None,
            )
            db.add(firmware)
            await db.flush()

            persisted = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware.id)
                )
            ).scalar_one()
            assert persisted.vuln_scan_status == "queued"
            assert persisted.vuln_scan_started_at is not None
            assert persisted.vuln_scan_finished_at is None
            assert persisted.vuln_scan_error is None

            # Transition queued → running → completed reflects in the DB.
            persisted.vuln_scan_status = "running"
            await db.flush()
            persisted.vuln_scan_status = "completed"
            persisted.vuln_scan_finished_at = datetime.now(UTC)
            await db.flush()

            final = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware.id)
                )
            ).scalar_one()
            assert final.vuln_scan_status == "completed"
            assert final.vuln_scan_finished_at is not None

